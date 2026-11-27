const PARTICIPANT_STATES = ['idle','presenting','acquiring_token','ready','failed_registration','failed_presentation','failed_token','failed_connector_unreachable'];
const participantObject = value => value && typeof value === 'object' && !Array.isArray(value);
const participantText = (value,max=200) => typeof value==='string' && value.length<=max;
const participantDate = value => typeof value==='string' && value.length<=40 && Number.isFinite(Date.parse(value));
const participantId = value => typeof value==='string' && /^[A-Za-z0-9._:-]{1,128}$/.test(value);
function validateParticipantState(value) {
  if(!participantObject(value)||value.mode!=='token'||!PARTICIPANT_STATES.includes(value.state)||!Number.isSafeInteger(value.attempt)||value.attempt<0||!participantText(value.lastErrorCode)||!Array.isArray(value.history)||value.history.length>500) throw new Error('PARTICIPANT_STATE_INVALID');
  const history=value.history.map(item=>{
    if(!participantObject(item)||!PARTICIPANT_STATES.includes(item.state)||!participantText(item.reason)||!participantDate(item.at))throw new Error('PARTICIPANT_STATE_INVALID');
    return {state:item.state,reason:item.reason,at:item.at};
  });
  return {mode:'token',state:value.state,attempt:value.attempt,lastErrorCode:value.lastErrorCode,history};
}
function validateParticipantToken(value,status,ids,expectedSource) {
  if(!expectedSource)throw new Error('PARTICIPANT_TOKEN_CONTRACT_UNCONFIGURED');
  if(!participantObject(value)||value.mode!=='token'||value.source!==expectedSource||!['success','denied','unavailable','error'].includes(value.outcome)||!participantText(value.reasonCode,100)||!value.reasonCode||!participantText(value.explanation,500)||!value.explanation.trim()||!participantDate(value.timestamp)||value.requestId!==ids.requestId||value.correlationId!==ids.correlationId||!participantObject(value.safeData))throw new Error('PARTICIPANT_TOKEN_RESPONSE_INVALID');
  const allowedStatus={success:[200],denied:[401,403],unavailable:[503,504],error:[400,404,405,409,500,502]};
  if(!allowedStatus[value.outcome].includes(status))throw new Error('PARTICIPANT_TOKEN_RESPONSE_INVALID');
  let safeData={};
  if(value.outcome==='success') {
    const kind=value.reasonCode==='RESOURCE_REPORT_RETURNED'?'report':value.reasonCode==='RESOURCE_SUMMARY_RETURNED'?'summary':null;
    const content=kind==='report'?'content':'summary',item=value.safeData[kind];
    if(!kind||!participantObject(item)||Object.keys(item).some(k=>!['id','title',content].includes(k))||!['id','title',content].every(k=>participantText(item[k],500)&&item[k].trim())||Object.keys(value.safeData).some(k=>!['resource','action',kind].includes(k))||value.safeData.resource!=='sample-report'||value.safeData.action!=='read')throw new Error('PARTICIPANT_TOKEN_RESPONSE_INVALID');
    safeData={resource:'sample-report',action:'read',[kind]:{id:item.id,title:item.title,[content]:item[content]}};
  } else if(Object.keys(value.safeData).length)throw new Error('PARTICIPANT_TOKEN_RESPONSE_INVALID');
  return {source:expectedSource,mode:'token',outcome:value.outcome,reasonCode:value.reasonCode,explanation:value.explanation,timestamp:value.timestamp,requestId:value.requestId,correlationId:value.correlationId,safeData,httpStatus:status};
}

const PARTICIPANT_PUBLIC_CA = "-----BEGIN CERTIFICATE-----\nMIIBnzCCAUWgAwIBAgIJANSeX3Sm9HVeMAoGCCqGSM49BAMCMCExHzAdBgNVBAMM\nFkZBQ0lTIGRlbW9uc3RyYXRpb24gQ0EwHhcNMjYxMTA2MTczODQzWhcNMjcwMjA0\nMTczODQzWjAhMR8wHQYDVQQDDBZGQUNJUyBkZW1vbnN0cmF0aW9uIENBMFkwEwYH\nKoZIzj0CAQYIKoZIzj0DAQcDQgAEW5uQidOCWSWGYlsqCI+kPqiPIz8ArAQxYrAY\n9QWwnW7todQ4TYlmDwq6Go9JqQ06Gccp+9JkTkepCwF8CTGL0qNmMGQwEgYDVR0T\nAQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8EBAMCAQYwHQYDVR0OBBYEFPQWHUheUUEv\neHnmNH4m8rnjr7ArMB8GA1UdIwQYMBaAFPQWHUheUUEveHnmNH4m8rnjr7ArMAoG\nCCqGSM49BAMCA0gAMEUCIHroZTIbrFkqHFi5oQrytnQ3pemRJPR0ZsM2V7Mh3kxY\nAiEA609MrK9o3GdnVn9V1wW1lw5wpoDkvXqzqAxwQR4HO7g=\n-----END CERTIFICATE-----\n";
const viewer=msg.req?.facis;
const respond=(participant,state)=>{msg.payload={ok:true,data:{participant,...(state?{state}: {})}};delete msg.headers;delete msg.url;node.send(msg,false);node.done();};
if(!viewer||viewer.scope!=='oidc-review'||!['ztd-operator','ztd-observer'].includes(viewer.role)) {msg.payload={ok:false,error:{code:'UI-NOT-AUTHORISED'}};return msg;}
if(!['participant-state','participant-reset','participant-demo'].includes(msg.type)||(msg.type!=='participant-state'&&viewer.role!=='ztd-operator')) {msg.payload={ok:false,error:{code:'UI-NOT-AUTHORISED'}};return msg;}
if(msg.type==='participant-reset'&&msg.data?.confirmShared!=='yes'){msg.payload={ok:false,error:{code:'PARTICIPANT_RESET_CONFIRMATION_REQUIRED'}};return msg;}
if(context._participantReset){msg.payload={ok:false,error:{code:'PARTICIPANT_RESET_PENDING'}};return msg;}
if(msg.type==='participant-demo' && flow.get('journeyStates')?.[viewer.userId]?.result===null){msg.payload={ok:false,error:{code:'RUN_IN_PROGRESS'}};return msg;}
if(msg.type==='participant-reset')context._participantReset=true;
const read=name=>{const v=env.get(name);return typeof v==='string'?v.trim():'';};
(async()=>{
 let upstreamStatus=null,observation=null;
 try {
  const caPath=read('PARTICIPANT_CA_FILE');const ca=caPath?nodeFS.readFileSync(caPath,'utf8'):PARTICIPANT_PUBLIC_CA;
  const requestId=nodeCrypto.randomUUID(),correlationId=nodeCrypto.randomUUID();
  const op=msg.type.replace('participant-','');
  const expectedSource=read('PARTICIPANT_TOKEN_SOURCE') || 'sample';
  if(op==='demo'&&!expectedSource)throw new Error('PARTICIPANT_TOKEN_CONTRACT_UNCONFIGURED');
  const body=op==='demo'?JSON.stringify({resource:'sample-report',action:'read',requestId,correlationId}):op==='reset'?'{}':null;
  const path=op==='state'?'/state':op==='reset'?'/reset':'/demo';
  const response=await new Promise((resolve,reject)=>{
    let finished=false,req;const finish=(error,value)=>{if(finished)return;finished=true;clearTimeout(timer);error?reject(error):resolve(value);};
    const timer=setTimeout(()=>{finish(new Error('PARTICIPANT_CONNECTION_TIMEOUT'));req?.destroy();},15000);
    req=nodeHTTPS.request('https://160.44.12.245'+path,{method:body?'POST':'GET',ca,rejectUnauthorized:true,headers:{accept:'application/json',...(body?{'content-type':'application/json','content-length':Buffer.byteLength(body)}:{})}},res=>{
      let size=0;const chunks=[];
      res.on('data',chunk=>{size+=chunk.length;if(size>65536){finish(new Error('PARTICIPANT_RESPONSE_TOO_LARGE'));res.destroy();}else chunks.push(chunk);});
      res.on('aborted',()=>finish(new Error('PARTICIPANT_CONNECTION_FAILURE')));
      res.on('error',error=>finish(error));
      res.on('end',()=>{if(finished)return;let json;try{json=JSON.parse(Buffer.concat(chunks).toString('utf8'));}catch{return finish(new Error('PARTICIPANT_RESPONSE_INVALID'));}finish(null,{status:res.statusCode,body:json});});
    });
    req.on('error',error=>finish(new Error(['CERT_HAS_EXPIRED','DEPTH_ZERO_SELF_SIGNED_CERT','SELF_SIGNED_CERT_IN_CHAIN','UNABLE_TO_VERIFY_LEAF_SIGNATURE','UNABLE_TO_GET_ISSUER_CERT_LOCALLY','ERR_TLS_CERT_ALTNAME_INVALID'].includes(error.code)?'PARTICIPANT_TLS_FAILED':'PARTICIPANT_CONNECTION_FAILURE')));
    req.end(body);
  });
  upstreamStatus=response.status;
  if(op==='demo')observation={source:participantText(response.body?.source,100)?response.body.source:null,mode:participantText(response.body?.mode,100)?response.body.mode:null,reasonCode:participantText(response.body?.reasonCode,100)?response.body.reasonCode:null};
  if(op==='state'||op==='reset') {
    if(op==='reset'&&response.status===503&&response.body?.reason==='reset_wait_timeout')return respond({operation:op,ok:false,httpStatus:503,reasonCode:'reset_wait_timeout',transportFailure:false});
    if(response.status!==200)throw new Error('PARTICIPANT_HTTP_FAILURE');
    const snapshot=validateParticipantState(response.body);
    if(op==='reset'&&snapshot.state!=='idle')throw new Error('PARTICIPANT_RESET_RESPONSE_INVALID');
    return respond({operation:op,ok:true,httpStatus:response.status,transportFailure:false,snapshot});
  }
  const result=validateParticipantToken(response.body,response.status,{requestId,correlationId},expectedSource);
  const at=new Date().toISOString(),success=result.outcome==='success';
  const state={ownerId:viewer.userId,runId:requestId,correlationId,scenario:'participant-token',scenarioLabel:'Hosted Participant token path',profile:'Service token scopes',sample:false,fixtureOnly:false,atlasPlan:false,adapterMode:'token',transport:'Participant HTTPS',securitySource:'Participant token response',activeStep:1,terminal:true,result:success?'success':result.outcome==='unavailable'?'unavailable':'failure',terminalStatus:success?'Granted':result.outcome==='unavailable'?'Unavailable':'Refused',outcome:success?'Protected resource returned':result.outcome==='unavailable'?'Participant unavailable':'Protected request refused',reasonCode:result.reasonCode,reason:result.explanation,updatedAt:at,tone:success?'success':'warning',checks:[{id:'token-response',name:'Participant token response',source:'participant-token',kind:'application_response',detail:result.explanation,status:success?'Pass':'Fail',evaluatedAt:at}],policyChecks:[],measurements:[],credential:{type:'Service token',status:'Not independently observed',issuer:'Not returned',validity:'Not returned'},trust:{zone:'Not returned',status:'Not independently observed'},attestation:{method:'Not returned',result:'Not independently observed'},connection:{protocol:'HTTPS',status:'Response received',endpoint:'160.44.12.245',encryption:'TLS verified'},serviceRequest:{...result,status:'completed'},evidence:[{event:'participant.token.response',timestamp:at,detail:result.explanation,data:{...result,blocked:!success,unavailable:result.outcome==='unavailable'}}],events:[{event:'run.completed',timestamp:at,detail:result.reasonCode}]};
  const states=flow.get('journeyStates')||{};states[viewer.userId]=state;flow.set('journeyStates',states);
  respond({operation:'demo',ok:true,transportFailure:false,...result},state);
 } catch(error) {
  const code=/^PARTICIPANT_[A-Z_]+$/.test(error.message)?error.message:'PARTICIPANT_CLIENT_CONFIGURATION_FAILED';
  respond({operation:msg.type.replace('participant-',''),ok:false,transportFailure:['PARTICIPANT_TLS_FAILED','PARTICIPANT_CONNECTION_TIMEOUT','PARTICIPANT_CONNECTION_FAILURE'].includes(code),reasonCode:code,httpStatus:upstreamStatus,...(observation?{contractObservation:observation}:{})});
 } finally {if(msg.type==='participant-reset')context._participantReset=false;}
})();return;
