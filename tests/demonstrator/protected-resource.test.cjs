const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const mod=import('../../flows/demonstrator/protected-resource-fixture.mjs');
const ids={requestId:'request-1',correlationId:'correlation-1'};
const expected={reader:'success','reader-detail':'success',auditor:'success','reader-auditor':'success','missing-role':'denied','unauthorized-role':'denied','wrong-scope':'denied','detail-only':'denied',revoked:'denied',invalid:'denied',expired:'denied','missing-context':'denied','dependency-unavailable':'unavailable'};
for(const [caseId,outcome] of Object.entries(expected)) test('Protected Resource local fixture: '+caseId,async()=>{
 const {evaluateFixtureResource}=await mod;const result=evaluateFixtureResource({caseId,...ids});
 assert.equal(result.outcome,outcome);assert.equal(result.mode,'fixture');assert.equal(result.securitySource,'fixture-only');assert.equal(result.correlationId,ids.correlationId);
 if(outcome==='success')assert.ok(result.safeData.report.content);else assert.deepEqual(result.safeData,{});
});
test('different service-right combinations return only their corresponding synthetic content',async()=>{
 const {evaluateFixtureResource:run}=await mod;const call=caseId=>run({caseId,...ids}).safeData.report.content;
 assert.equal(call('reader'),'Synthetic report summary.');assert.equal(call('reader-detail'),'Synthetic report summary. Synthetic detailed findings.');assert.equal(call('auditor'),'Synthetic audit trail.');assert.equal(call('reader-auditor'),'Synthetic report summary. Synthetic audit trail.');
});
test('browser-selected roles, headers or claimed verified context cannot grant content',async()=>{
 const {evaluateFixtureResource:run}=await mod;
 for(const injected of [{roles:['resource-reader']},{verifiedContext:{verified:true,roles:['resource-reader']}},{headers:{'x-role':'resource-reader'}},{role:'ztd-operator'}]){
  const r=run({caseId:'unauthorized-role',...ids,...injected});assert.equal(r.outcome,'denied');assert.deepEqual(r.safeData,{});
 }
 for(const caseId of ['__proto__','constructor','unknown'])assert.equal(run({caseId,...ids}).reasonCode,'FIXTURE_CASE_UNKNOWN');
});
function harness(){
 const dir=path.resolve(__dirname,'../../flows/demonstrator');
 const nodes=JSON.parse(fs.readFileSync(path.join(dir,'journey_flow.json')));
 const combined=JSON.parse(fs.readFileSync(path.join(dir,'current-facis-flows.json')));
 for(const id of ['journey-engine','journey-sample-fixtures']){
  const n=nodes.find(n=>n.id===id);assert.equal(n.func,fs.readFileSync(path.join(dir,id+'.js'),'utf8'));assert.deepEqual(combined.find(n=>n.id===id),n);
 }
 const memory=new Map(),flow={get:k=>memory.get(k),set:(k,v)=>memory.set(k,v)};
 const vars=Object.fromEntries(nodes.find(n=>n.type==='tab').env.map(e=>[e.name,e.value]));
 function command(type,data={},role='ztd-operator',userId='operator1'){
  let msg={type,data,req:{facis:{userId,role,scope:'oidc-review'}}};
  for(const id of ['journey-adapter-config','journey-sample-fixtures','journey-engine']){
   const code=nodes.find(n=>n.id===id).func;msg=new Function('msg','flow','env','Buffer',code)(msg,flow,{get:n=>vars[n]},Buffer);
  }
  return msg;
 }
 return {command,memory};
}
for(const [caseId,outcome] of Object.entries(expected))test('Journey/Evidence records the '+caseId+' fixture outcome without any HTTP request',()=>{
 const h=harness();let r=h.command('start',{scenario:'resource-fixture-'+caseId,commandId:'start'});
 const state=r.payload.data.state;assert.equal(state.adapterMode,'fixture');assert.equal(state.activeStep,1);
 r=h.command('next',{runId:state.runId,commandId:'next',roles:['resource-reader'],verifiedContext:{verified:true}});
 assert.ok(!Array.isArray(r));assert.equal(r.url,undefined);
 const result=r.payload.data.state;assert.equal(result.terminal,true);assert.equal(result.resourceFixtureResult.outcome,outcome);assert.equal(result.serviceRequest,null);
 const evidence=result.evidence.find(e=>e.event==='fixture.resource.decision');assert.ok(evidence);assert.equal(evidence.data.correlationId,result.correlationId);assert.ok(evidence.data.requestId);assert.equal(evidence.data.fixture,true);
 if(outcome==='success')assert.ok(result.fixtureResource.report);else {assert.equal(result.fixtureResource,undefined);assert.deepEqual(evidence.data.safeData,{});assert.equal(evidence.data.blocked,true);assert.ok(['Fail','Unavailable'].includes(result.checks.at(-1).status));}
 assert.equal(h.command('next',{runId:state.runId,commandId:'again'}).payload.error.code,'INVALID_TRANSITION');
});
test('observer sees shared fixture evidence but cannot start or reset a resource scenario',()=>{
 const h=harness();let r=h.command('start',{scenario:'resource-fixture-reader',commandId:'start'});const id=r.payload.data.state.runId;
 h.command('next',{runId:id,commandId:'finish'});
 const view=h.command('status',{},'ztd-observer','observer1');assert.equal(view.payload.data.state.fixtureResource.report.content,'Synthetic report summary.');
 for(const type of ['start','next','reset'])assert.equal(h.command(type,{scenario:'resource-fixture-reader',runId:id,commandId:type+'-observer'},'ztd-observer','observer1').payload.error.code,'UI-NOT-AUTHORISED');
 h.command('reset',{runId:id,commandId:'reset'});assert.equal(h.command('status').payload.data.state,null);
});
