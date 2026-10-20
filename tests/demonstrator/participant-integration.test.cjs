const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const nodes=JSON.parse(fs.readFileSync(path.join(__dirname,'../../flows/demonstrator/journey_flow.json')));
const code=id=>nodes.find(n=>n.id===id).func;
const run=(id,msg,flow={get:()=>undefined,set:()=>{}},values={})=>new Function('msg','flow','env','Buffer',code(id))(msg,flow,{get:n=>values[n]},Buffer);
const good={requestId:'r1',correlationId:'c1',source:'sample',mode:'sample',outcome:'success',reasonCode:'SAMPLE_RESOURCE_RETURNED',explanation:'Sample report; no authorization was performed.',timestamp:new Date().toISOString(),safeData:{resource:'sample-report',action:'read',report:{id:'report1',title:'Sample report',content:'Sample content'}}};
const response=(body=good,status=200)=>run('journey-validate-response',{payload:JSON.stringify(body),statusCode:status,journeyPending:{requestId:'r1',correlationId:'c1'},headers:{authorization:'secret'},cookies:{a:'secret'},responseCookies:{b:'secret'}});
test('valid application response retains only bounded sample data',()=>{
 const m=response(); assert.equal(m.journeyServiceResult.outcome,'success'); assert.equal(m.journeyServiceResult.transportStatus,200); for(const k of ['payload','headers','cookies','responseCookies']) assert.equal(m[k],undefined);
});
test('mismatched identifiers, live mode, oversized report and false success fail closed',()=>{
 for(const b of [{...good,requestId:'wrong'},{...good,correlationId:'wrong'},{...good,mode:'live'},{...good,safeData:{...good.safeData,report:{...good.safeData.report,content:'x'.repeat(501)}}}]) assert.equal(response(b).journeyServiceResult.reasonCode,'SAMPLE_INVALID_RESPONSE');
 assert.equal(response(good,503).journeyServiceResult.outcome,'error');
});
test('Basic Auth refusal is distinct from simulated authorization denial',()=>{
 assert.equal(response(good,401).journeyServiceResult.reasonCode,'SAMPLE_PARTICIPANT_AUTH_REQUIRED');
 assert.equal(response({...good,outcome:'denied',reasonCode:'SAMPLE_ACCESS_DENIED',safeData:{}},403).journeyServiceResult.outcome,'denied');
});
test('certificate verification defaults on; sample exception is explicit and origin-bound',()=>{
 const vars={JOURNEY_ADAPTER_MODE:'http-sample',JOURNEY_PARTICIPANT_URL:'https://participant.zero-trust.160-44-12-115.sslip.io'};
 assert.equal(run('journey-adapter-config',{},undefined,vars).journeyAdapterConfig.skipTlsVerification,false);
 const configured=run('journey-adapter-config',{},undefined,{...vars,JOURNEY_PARTICIPANT_TLS_SKIP_VERIFY:'true'}).journeyAdapterConfig;
 assert.equal(configured.skipTlsVerification,true); assert.equal(configured.error,null); assert.equal(configured.tlsExceptionUntil,null);
 assert.equal(run('journey-adapter-config',{},undefined,{...vars,JOURNEY_PARTICIPANT_TLS_SKIP_VERIFY:'false'}).journeyAdapterConfig.skipTlsVerification,false);
 assert.equal(run('journey-adapter-config',{},undefined,{...vars,JOURNEY_PARTICIPANT_TLS_SKIP_VERIFY:'true',JOURNEY_PARTICIPANT_URL:'https://other.example'}).journeyAdapterConfig.skipTlsVerification,false);
 assert.equal(run('journey-adapter-config',{},undefined,{...vars,JOURNEY_PARTICIPANT_URL:'https://other.example'}).journeyAdapterConfig.error.code,'JOURNEY_PARTICIPANT_UNCONFIGURED');
});
function harness(){
 const memory=new Map();const flow={get:k=>memory.get(k),set:(k,v)=>memory.set(k,v)};
 const variables=Object.fromEntries(nodes.find(n=>n.id==='module-journey').env.map(e=>[e.name,e.value]));
 function command(type,data,role='ztd-operator',userId='operator1'){
  let msg={type,data,req:{facis:{userId,role,scope:'oidc-review'}}};
  msg=run('journey-adapter-config',msg,flow,variables);msg=run('journey-sample-fixtures',msg,flow);return run('journey-engine',msg,flow);
 }
 return {memory,flow,command};
}
function pending(h){
 const start=h.command('start',{scenario:'atlas-successful-call',commandId:'start1'});let state=start.payload.data.state;
 for(let i=2;i<=5;i++)state=h.command('next',{runId:state.runId,commandId:'next'+i}).payload.data.state;
 const pair=h.command('next',{runId:state.runId,commandId:'next6'});return pair[1];
}
test('operator reaches server-side HTTPS only at final sample step; observer is denied',()=>{
 const h=harness();assert.equal(h.command('start',{scenario:'atlas-successful-call',commandId:'observer'},'ztd-observer').payload.error.code,'UI-NOT-AUTHORISED');
 const msg=pending(h);assert.equal(msg.url,'https://participant.zero-trust.160-44-12-115.sslip.io/demo');assert.equal(msg.followRedirects,false);assert.equal(msg.method,'POST');
 assert.equal(msg.rejectUnauthorized,false);
 const body=JSON.parse(msg.payload);assert.equal(body.requestId,msg.journeyPending.requestId);assert.equal(body.correlationId,msg.journeyPending.correlationId);
 assert.equal(h.memory.get('journeyStates').operator1.result,null);
 msg.payload=JSON.stringify({...good,requestId:body.requestId,correlationId:body.correlationId});msg.statusCode=200;
 run('journey-http-complete',run('journey-validate-response',msg,h.flow),h.flow);
 const state=h.memory.get('journeyStates').operator1;assert.equal(state.result,'success');assert.equal(state.serviceRequest.httpStatus,200);assert.equal(state.securitySource,'fixture-only');assert.equal(state.checks[5].source,'participant-sample');assert.equal(state.fixtureResource,undefined);
});
test('late response after reset cannot resurrect a run; deadline cannot produce success',()=>{
 const h=harness();let msg=pending(h);h.command('reset',{runId:msg.journeyPending.runId,commandId:'reset1'});
 msg.journeyServiceResult={...good,transportStatus:200};assert.equal(run('journey-http-complete',msg,h.flow),null);assert.equal(h.memory.get('journeyStates').operator1,undefined);
 const h2=harness();msg=pending(h2);msg.journeyPending.deadlineAt=Date.now()-1;msg.journeyServiceResult={...good,transportStatus:200};run('journey-http-complete',msg,h2.flow);assert.equal(h2.memory.get('journeyStates').operator1.result,'unavailable');
});

test('a separate observer watches operator progress but cannot mutate or reset it',()=>{
 const h=harness();const start=h.command('start',{scenario:'atlas-successful-call',commandId:'shared-start'});const id=start.payload.data.state.runId;
 let view=h.command('status',{},'ztd-observer','observer1').payload.data.state;assert.equal(view.runId,id);assert.equal(view.activeStep,1);assert.equal(view.ownerId,undefined);
 for(const type of ['start','next','reset']) assert.equal(h.command(type,{runId:id,commandId:'blocked-'+type},'ztd-observer','observer1').payload.error.code,'UI-NOT-AUTHORISED');
 h.command('next',{runId:id,commandId:'shared-next'});view=h.command('status',{},'ztd-observer','observer1').payload.data.state;assert.equal(view.activeStep,2);
 h.command('reset',{runId:id,commandId:'shared-reset'});assert.equal(h.command('status',{},'ztd-observer','observer1').payload.data.state,null);
});
test('P1 refusal reasons and presentation-required variant match supplied scenarios',()=>{
 for(const [scenario,variant,reason,count] of [['atlas-revoked-credential',undefined,'CRED-REVOKED',3],['atlas-wrong-scope','rule-deny','POL-RULE-DENY',4],['atlas-wrong-scope','presentation-required','POL-PRESENTATION-REQUIRED',4]]){
  const h=harness();let state=h.command('start',{scenario,variant,commandId:'start'}).payload.data.state;for(let i=1;i<count&&!state.terminal;i++)state=h.command('next',{runId:state.runId,commandId:'next'+i}).payload.data.state;
  assert.equal(state.terminal,true);assert.equal(state.reasonCode,reason);assert.equal(state.serviceRequest,null);if(variant==='rule-deny')assert.equal(state.ruleId,'data.facis.guard.deny_no_entitlement');
 }
});
test('HTTPS transport is reported for pending, completed and previously persisted sample runs',()=>{
 const h=harness();const msg=pending(h);assert.equal(h.command('status',{}).payload.data.state.transport,'Participant sample HTTPS');
 msg.journeyServiceResult={...good,transportStatus:200};run('journey-http-complete',msg,h.flow);assert.equal(h.command('status',{}).payload.data.state.transport,'Participant sample HTTPS');
 h.memory.get('journeyStates').operator1.transport='fixture';assert.equal(h.command('status',{}).payload.data.state.transport,'Participant sample HTTPS');
});
