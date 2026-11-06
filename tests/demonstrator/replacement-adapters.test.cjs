const test=require('node:test'),assert=require('node:assert/strict'),http=require('node:http');
const {once}=require('node:events');
const modulePromise=import('../../flows/demonstrator/replacement-adapters.mjs');
const request={requestId:'replacement-request',correlationId:'replacement-correlation',resource:'sample-report',action:'read',scenario:'success'};
async function server(t,role,options={}) {
 const mod=await modulePromise, calls=[];
 const app=http.createServer(async(req,res)=>{
  const chunks=[];for await(const chunk of req)chunks.push(chunk);
  calls.push({url:req.url,requestId:req.headers['x-request-id'],correlationId:req.headers['x-correlation-id']});
  const send=(status,data)=>{res.writeHead(status,{'content-type':'application/json'});res.end(JSON.stringify(data));};
  if(req.url==='/interface')return send(200,{contract:options.badInterface?'unknown/v1':mod.replacementContracts[role],role,mode:'sample',method:'POST',path:'/execute'});
  if(options.delay)await new Promise(r=>setTimeout(r,70));
  if(res.destroyed)return;
  if(options.redirect){res.writeHead(302,{location:'/unexpected'});return res.end();}
  if(options.malformed){res.writeHead(200);return res.end('not json');}
  if(options.large)return send(200,{value:'x'.repeat(70000)});
  let input=JSON.parse(Buffer.concat(chunks).toString());
  let data=role==='participant-backend'?mod.sampleParticipantResponse(input):mod.sampleResourceResponse(input);
  if(options.wrongIds){if(role==='participant-backend')data.request.correlationId='wrong';else data.correlationId='wrong';}
  if(options.refusalLeak){data.outcome='denied';data.safeData={report:{content:'must not escape'}};}
  if(options.liveMode)data.mode='live';
  if(options.refuseParticipant)data.outcome='denied';
  const status=role==='participant-backend'?200:{success:200,denied:403,unavailable:503,error:502}[data.outcome];
  send(options.wrongStatus?200:status,data);
 });
 app.listen(0,'127.0.0.1');await once(app,'listening');
 t.after(async()=>{app.closeAllConnections();await new Promise(resolve=>app.close(resolve));});
 return {calls,config:{kind:'sample-http',role,contract:mod.replacementContracts[role],baseURL:'http://127.0.0.1:'+app.address().port}};
}
async function config(t,pKind,rKind,pOptions={},rOptions={}){
 const mod=await modulePromise;
 const p=await server(t,'participant-backend',pOptions),r=await server(t,'protected-resource',rOptions);
 const pick=(service,kind)=>kind==='mock'?{kind,role:service.config.role,contract:service.config.contract}:service.config;
 return {p,r,config:{participant:pick(p,pKind),resource:pick(r,rKind),timeoutMs:1000},mod};
}
for(const pKind of ['mock','sample-http'])for(const rKind of ['mock','sample-http'])test('replacement matrix: '+pKind+' Participant / '+rKind+' Resource uses the same journey contract',async t=>{
 const f=await config(t,pKind,rKind);const journey=await f.mod.createReplacementJourney(f.config);const result=await journey.run(request);
 assert.equal(result.ok,true);assert.equal(result.securitySource,'fixture-only');assert.equal(result.safeData.report.content,'Synthetic report summary.');
 assert.equal(f.p.calls.filter(c=>c.url==='/execute').length,pKind==='sample-http'?1:0);assert.equal(f.r.calls.filter(c=>c.url==='/execute').length,rKind==='sample-http'?1:0);
 for(const service of [f.p,f.r])for(const c of service.calls.filter(c=>c.url==='/execute')){assert.equal(c.correlationId,request.correlationId);assert.equal(c.requestId,request.requestId);}
 assert.ok(result.events.every(e=>e.mode==='sample'&&e.correlationId===request.correlationId));
});
for(const scenario of ['denied','unavailable','error'])test('sample replacement '+scenario+' returns no protected content',async t=>{
 const f=await config(t,'sample-http','sample-http');const journey=await f.mod.createReplacementJourney(f.config);const r=await journey.run({...request,scenario});assert.equal(r.ok,false);assert.equal(r.outcome,scenario);assert.deepEqual(r.safeData,{});
});
test('both roles reject incompatible configuration before any discovery/execution request',async t=>{
 const f=await config(t,'sample-http','sample-http');
 for(const role of ['participant','resource']){
  await assert.rejects(f.mod.createReplacementJourney({...f.config,[role]:{...f.config[role],contract:'wrong/v1'}}),/REPLACEMENT_INTERFACE_INVALID/);
  await assert.rejects(f.mod.createReplacementJourney({...f.config,[role]:{...f.config[role],kind:'real'}}),/REPLACEMENT_TARGET_NOT_APPROVED/);
 }
 assert.equal(f.p.calls.length,0);assert.equal(f.r.calls.length,0);
});
for(const role of ['participant','resource'])test('incompatible '+role+' sample interface is rejected before a journey executes',async t=>{
 const f=await config(t,'sample-http','sample-http',role==='participant'?{badInterface:true}:{},role==='resource'?{badInterface:true}:{});
 await assert.rejects(f.mod.createReplacementJourney(f.config),/REPLACEMENT_INTERFACE_INVALID/);
 assert.equal(f.p.calls.some(c=>c.url==='/execute'),false);assert.equal(f.r.calls.some(c=>c.url==='/execute'),false);
});
for(const role of ['participant','resource'])test('mismatched '+role+' correlation cannot become a successful replacement',async t=>{
 const f=await config(t,'sample-http','sample-http',role==='participant'?{wrongIds:true}:{},role==='resource'?{wrongIds:true}:{});
 const journey=await f.mod.createReplacementJourney(f.config);const result=await journey.run(request);assert.equal(result.ok,false);assert.deepEqual(result.safeData,{});
 if(role==='participant')assert.equal(f.r.calls.filter(c=>c.url==='/execute').length,0);
});
for(const [option,code] of [['refusalLeak','REPLACEMENT_REFUSAL_LEAK'],['liveMode','REPLACEMENT_RESPONSE_INVALID'],['malformed','REPLACEMENT_RESPONSE_INVALID'],['large','REPLACEMENT_RESPONSE_TOO_LARGE'],['redirect','REPLACEMENT_REDIRECT_REFUSED']])test('resource adapter rejects '+option+' without mock fallback',async t=>{
 const f=await config(t,'mock','sample-http',{}, {[option]:true});const journey=await f.mod.createReplacementJourney(f.config);const result=await journey.run(request);
 assert.equal(result.ok,false);assert.equal(result.reasonCode,code);assert.deepEqual(result.safeData,{});assert.equal(f.r.calls.filter(c=>c.url==='/execute').length,1);
});
test('participant refusal stops before resource and never invokes mock fallback',async t=>{
 const f=await config(t,'sample-http','sample-http',{refuseParticipant:true});const journey=await f.mod.createReplacementJourney(f.config);const r=await journey.run(request);
 assert.equal(r.reasonCode,'REPLACEMENT_PARTICIPANT_REFUSED');assert.equal(f.r.calls.filter(c=>c.url==='/execute').length,0);
});
test('sample timeout fails closed',async t=>{
 const f=await config(t,'mock','sample-http',{}, {delay:true});const journey=await f.mod.createReplacementJourney({...f.config,timeoutMs:30});const result=await journey.run(request);assert.equal(result.reasonCode,'REPLACEMENT_TIMEOUT');assert.deepEqual(result.safeData,{});
});
test('unavailable selected sample service fails instead of silently choosing a mock',async t=>{
 const f=await config(t,'mock','sample-http');const journey=await f.mod.createReplacementJourney(f.config);
 // Close the selected resource after successful interface preflight.
 // Its explicit service endpoint remains the only execution target.
 const old=globalThis.fetch;
 try {globalThis.fetch=async()=>{throw new Error('connection refused');};const result=await journey.run(request);assert.equal(result.reasonCode,'REPLACEMENT_UNAVAILABLE');assert.deepEqual(result.safeData,{});}finally{globalThis.fetch=old;}
});
test('validated configuration is copied and request cannot inject endpoint or viewer roles',async t=>{
 const f=await config(t,'sample-http','sample-http');const journey=await f.mod.createReplacementJourney(f.config);f.config.resource.baseURL='http://unapproved.invalid';assert.equal((await journey.run(request)).ok,true);
 for(const injected of [{roles:['admin']},{endpoint:'http://unapproved.invalid'},{headers:{authorization:'private'}}])await assert.rejects(journey.run({...request,...injected}),/REPLACEMENT_REQUEST_INVALID/);
});
