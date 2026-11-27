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
