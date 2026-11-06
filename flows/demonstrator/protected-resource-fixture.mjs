// Synthetic service contexts only. These roles/scopes are local test policy,
// not an approved ATLAS role mapping and never a source of live authorization.
const fixtures = {
  reader: {label:'Reader',roles:['resource-reader'],scopes:['read']},
  'reader-detail': {label:'Reader with detail',roles:['resource-reader','resource-detail'],scopes:['read','read:detail']},
  auditor: {label:'Auditor',roles:['resource-auditor'],scopes:['audit']},
  'reader-auditor': {label:'Reader and auditor',roles:['resource-reader','resource-auditor'],scopes:['read','audit']},
  'missing-role': {label:'Missing service role',roles:[],scopes:['read']},
  'unauthorized-role': {label:'Unauthorized service role',roles:['ztd-operator'],scopes:['read']},
  'wrong-scope': {label:'Wrong service scope',roles:['resource-reader'],scopes:['profile:read']},
  'detail-only': {label:'Detail role without reader',roles:['resource-detail'],scopes:['read:detail']},
  revoked: {label:'Revoked credential',roles:['resource-reader'],scopes:['read'],credential:'revoked'},
  invalid: {label:'Invalid credential',roles:['resource-reader'],scopes:['read'],credential:'invalid'},
  expired: {label:'Expired access context',roles:['resource-reader'],scopes:['read'],expired:true},
  'missing-context': {label:'Missing verified context',roles:['resource-reader'],scopes:['read'],verified:false},
  'dependency-unavailable': {label:'Security dependency unavailable',roles:['resource-reader'],scopes:['read'],dependency:false}
};
export const resourceFixtureCatalog = Object.freeze(Object.entries(fixtures).map(([id,value])=>Object.freeze({id,label:value.label})));
export function evaluateFixtureResource(input = {}) {
  const {caseId,requestId,correlationId} = input;
  const base={source:'fixture',mode:'fixture',securitySource:'fixture-only',caseId:typeof caseId==='string'?caseId:null,requestId,correlationId,timestamp:new Date().toISOString(),safeData:{}};
  const refuse=(reasonCode,explanation,status=403)=>({...base,outcome:status===503?'unavailable':'denied',status,reasonCode,explanation});
  if (Object.keys(input).some(k=>!['caseId','requestId','correlationId'].includes(k)) || ![requestId,correlationId].every(id=>typeof id==='string'&&/^[A-Za-z0-9._:-]{1,128}$/.test(id))) return refuse('FIXTURE_INVALID_REQUEST','Fixture input or correlation identifiers are invalid.',400);
  if (!Object.hasOwn(fixtures,caseId)) return refuse('FIXTURE_CASE_UNKNOWN','Select a registered local fixture case.',400);
  const context=fixtures[caseId];
  if (context.dependency===false) return refuse('FIXTURE_SECURITY_UNAVAILABLE','The synthetic security dependency is unavailable; protected content is withheld.',503);
  if (context.verified===false) return refuse('FIXTURE_CONTEXT_REQUIRED','A synthetic verified service context is required.',401);
  if (context.expired) return refuse('FIXTURE_CONTEXT_EXPIRED','The synthetic service access context has expired.',401);
  if (context.credential==='revoked') return refuse('FIXTURE_CREDENTIAL_REVOKED','The synthetic credential has been revoked.');
  if (context.credential==='invalid') return refuse('FIXTURE_CREDENTIAL_INVALID','The synthetic credential is invalid.');
  const reader=context.roles.includes('resource-reader');
  const auditor=context.roles.includes('resource-auditor');
  if (!reader&&!auditor) return refuse('FIXTURE_ROLE_DENIED','No permitted synthetic service role is present.');
  const read=reader&&context.scopes.includes('read');
  const audit=auditor&&context.scopes.includes('audit');
  if (!read&&!audit) return refuse('FIXTURE_SCOPE_DENIED','The synthetic role lacks the required resource scope.');
  const detail=read&&context.roles.includes('resource-detail')&&context.scopes.includes('read:detail');
  const parts=[...(read?['Synthetic report summary.']:[]),...(detail?['Synthetic detailed findings.']:[]),...(audit?['Synthetic audit trail.']:[])];
  return {...base,outcome:'success',status:200,reasonCode:'FIXTURE_RESOURCE_RETURNED',explanation:'Synthetic service rights permit this local fixture response; no live authorization was performed.',safeData:{resource:'sample-report',action:'read',report:{id:'FIXTURE-REPORT-'+caseId,title:'Protected Resource fixture: '+context.label,content:parts.join(' ')}}};
}
