const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const source = fs.readFileSync(path.join(__dirname, '../../flows/demonstrator/identity-on-start.js'), 'utf8');
const UIAuth = new Function('nodeUrl', 'crypto', 'https', 'node', 'context', 'global', 'Buffer', source + '\nreturn UIAuth;')(require('node:url'), crypto, {}, {warn(){},status(){}}, {}, {set(){}}, Buffer);
const {privateKey, publicKey} = crypto.generateKeyPairSync('rsa', {modulusLength:2048});
const jwk = {...publicKey.export({format:'jwk'}), kid:'component-test', use:'sig', alg:'RS256'};
const enc = v => Buffer.from(JSON.stringify(v)).toString('base64url');
function sign(claims) { const data=enc({alg:'RS256',kid:jwk.kid})+'.'+enc(claims); return data+'.'+crypto.sign('RSA-SHA256',Buffer.from(data),privateKey).toString('base64url'); }
function response() {return {headers:{},statusCode:200,status(n){this.statusCode=n;return this;},set(k,v){this.headers[k]=v;return this;},append(k,v){(this.headers[k]??=[]).push(v);},json(v){this.body=v;return this;},redirect(n,url){this.statusCode=n;this.location=url;},end(){}};}
function fixture(role='ztd-operator') {
 let time=Date.now(); const a=new UIAuth({now:()=>time});
 a.request=async()=>({keys:[jwk]});
 const claims={iss:a.issuer,aud:['ztd-ui'],azp:'ztd-ui',sub:'signed-viewer',preferred_username:'component-persona',sid:'component-session',iat:Math.floor(time/1000),exp:Math.floor(time/1000)+300,realm_access:{roles:role?[role]:[]}};
 a.sessions.set('test-session',{access:sign(claims),subject:claims.sub,username:claims.preferred_username,claims,role,expires:time+300000,created:time,last:time,csrf:'component-csrf',sid:claims.sid,idToken:sign(claims)});
 const req=(type='status',data={})=>({headers:{cookie:'__Secure-facis-ui=test-session',origin:a.origin,'x-facis-csrf':'component-csrf'},body:{type,data},query:{}});
 return {a,claims,req,advance(ms){time+=ms;}};
}
test('identity source uses PKCE S256 and the /dev callback',async()=>{
 const {a,req}=fixture(),r=response();await a.login(req(),r);const q=new URL(r.location).searchParams;
 assert.equal(q.get('client_id'),'ztd-ui');assert.equal(q.get('code_challenge_method'),'S256');assert.equal(q.get('redirect_uri'),a.origin+'/dev/ztd/oidc/callback');assert.equal(q.get('scope'),'openid profile roles');
});
test('operator identity is derived on server and forged role/subject are ignored',async()=>{
 const {a,req}=fixture();let emitted;await a.command(req('start',{role:'forged',userId:'forged',scenario:'atlas-successful-call'}),response(),m=>emitted=m);
 assert.equal(emitted.req.facis.role,'ztd-operator');assert.equal(emitted.req.facis.subject,'signed-viewer');assert.equal(emitted.data.role,undefined);assert.equal(emitted.data.userId,undefined);
});
test('observer can read status but all commands and configuration preview return denied',async()=>{
 const {a,req}=fixture('ztd-observer');let emitted;await a.command(req(),response(),m=>emitted=m);assert.equal(emitted.req.facis.role,'ztd-observer');
 for(const type of ['start','next','reset','config-preview']){const r=response();await a.command(req(type),r,()=>assert.fail('observer mutated state'));assert.equal(r.statusCode,403);assert.equal(r.body.state,'denied');assert.equal(r.body.error.code,type==='config-preview'?'CFG-NOT-AUTHORISED':'UI-NOT-AUTHORISED');}
});
test('signature, issuer, audience and expiry are checked before commands',async()=>{
 const {a,claims}=fixture();await a.verify(sign(claims));
 for(const change of [{iss:'https://invalid.example'},{aud:['another-client']},{exp:0}])await assert.rejects(()=>a.verify(sign({...claims,...change})));
 const parts=sign(claims).split('.');parts[1]=enc({...claims,sub:'forged'});await assert.rejects(()=>a.verify(parts.join('.')));
});
test('missing/conflicting roles and cross-origin commands fail closed',async()=>{
 for(const roles of [[],['ztd-operator','ztd-observer']]){const {a,req,claims}=fixture();a.sessions.get('test-session').access=sign({...claims,realm_access:{roles}});const r=response();await a.command(req('start'),r,()=>assert.fail());assert.equal(r.statusCode,403);}
 const {a,req}=fixture(),q=req('start'),r=response();q.headers.origin='https://invalid.example';await a.command(q,r,()=>assert.fail());assert.equal(r.body.error.code,'CSRF_DENIED');
});
test('expired session is explicit and session status never exposes tokens',async()=>{
 const f=fixture(),r=response();await f.a.status(f.req(),r);assert.equal(r.body.role,'ztd-operator');assert.equal(r.body.access_token,undefined);assert.equal(r.body.refresh_token,undefined);
 f.advance(301000);const expired=response();await f.a.command(f.req('start'),expired,()=>assert.fail());assert.equal(expired.statusCode,401);assert.equal(expired.body.state,'expired');
});
test('logout clears backend session and uses the /dev UI post-logout path',async()=>{
 const {a,req}=fixture(),r=response();await a.logout(req(),r);assert.equal(a.sessions.size,0);assert.equal(new URL(r.location).searchParams.get('post_logout_redirect_uri'),a.origin+'/dev/facis-demo/');assert.match(r.headers['Set-Cookie'][0],/Max-Age=0/);
});
test('access subject is mandatory and must match the ID token subject',async()=>{
 const {a,claims}=fixture();const data={access_token:sign(claims),id_token:sign({...claims,preferred_username:'id-only-name'}),refresh_token:'test-refresh'};
 const s=await a.tokens(data,null);assert.equal(s.subject,claims.sub);assert.equal(s.username,claims.preferred_username);
 const missing={...claims};delete missing.sub;
 await assert.rejects(()=>a.tokens({...data,access_token:sign(missing)},null),{code:'TOKEN_SUB_MISSING'});
 await assert.rejects(()=>a.tokens({...data,id_token:sign({...claims,sub:'different'})},null),{code:'INVALID_IDENTITY_RESPONSE'});
});
test('configuration preview enforces kinds, targets and payloads without live apply',async()=>{
 const {a,req}=fixture();
 const cases=[
 {kind:'trust-zone',target:'zone-b',payload:{zone:'zone-b'}},
 {kind:'measurement',target:'zone-a-gateway',payload:{digest:'sha256:'+'a'.repeat(64)}},
 {kind:'mock-replacement',target:'protected-resource',payload:{adapter:'mock'}},
 {kind:'policy-ref',target:'guard-b',payload:{bundle:'candidate',revision:'1'}}];
 for(const change of cases){const r=response();await a.command(req('config-preview',change),r,()=>assert.fail());assert.equal(r.body.ok,true);assert.equal(r.body.data.applied,false);assert.equal(r.body.data.preview.phase,'preview');if(change.kind==='policy-ref')assert.equal(r.body.data.preview.validation,'awaiting-registry');}
 for(const change of [{participantBackend:'edited'}, {...cases[0],target:'unknown'}, {...cases[0],payload:{zone:'zone-a'}}, {...cases[1],payload:{digest:'sha256:abc'}}, {...cases[2],payload:{adapter:'arbitrary'}}, {...cases[3],payload:{bundle:'candidate',revision:''}}]){const r=response();await a.command(req('config-preview',change),r,()=>assert.fail());assert.equal(r.statusCode,400);assert.equal(r.body.error.code,'CFG-SCHEMA-INVALID');}
 const r=response();await a.command(req('config-preview',{...cases[2],payload:{adapter:'real'}}),r,()=>assert.fail());assert.equal(r.body.error.code,'CFG-REAL-API-UNAVAILABLE');
});

function refreshed(f, changes={}) {
 const claims={...f.claims,iat:Math.floor(f.a.now()/1000),exp:Math.floor(f.a.now()/1000)+300,...changes};
 return {access_token:sign(claims),id_token:sign(claims),refresh_token:'rotated-refresh'};
}
function logoutClaims(f, changes={}) {
 return {iss:f.a.issuer,aud:'ztd-ui',iat:Math.floor(f.a.now()/1000),jti:'logout-once',sid:f.claims.sid,events:{'http://schemas.openid.net/event/backchannel-logout':{}},...changes};
}
test('expired signed token cannot authorize even with a future cached expiry',async()=>{
 const f=fixture();f.advance(301000);f.a.sessions.get('test-session').expires=f.a.now()+300000;
 const r=response();await f.a.command(f.req('start'),r,()=>assert.fail('expired token authorized'));
 assert.equal(r.statusCode,401);assert.equal(r.body.state,'expired');
});
test('near-expiry concurrent requests share one refresh and rotate the refresh token',async()=>{
 const f=fixture();f.a.sessions.get('test-session').refresh='initial-refresh';f.advance(241000);let calls=0;
 f.a.token=async form=>{calls++;assert.deepEqual(form,{grant_type:'refresh_token',refresh_token:'initial-refresh'});return refreshed(f);};
 const sessions=await Promise.all([f.a.session(f.req()),f.a.session(f.req())]);
 assert.equal(calls,1);assert.equal(sessions[0].refresh,'rotated-refresh');assert.equal(sessions[0],sessions[1]);
});
test('refresh failure, reuse, or changed subject/session clears authorization',async()=>{
 for(const mode of ['failure','reuse','subject','sid']){
  const f=fixture();f.a.sessions.get('test-session').refresh='initial-refresh';f.advance(241000);
  f.a.token=async()=>{if(mode==='failure')throw Object.assign(new Error('rejected'),{code:'LOGIN_REJECTED'});const d=refreshed(f,mode==='subject'?{sub:'other'}:mode==='sid'?{sid:'other'}:{});if(mode==='reuse')d.refresh_token='initial-refresh';return d;};
  const r=response();await f.a.command(f.req('start'),r,()=>assert.fail(mode+' authorized'));assert.equal(r.statusCode,401);assert.equal(f.a.sessions.size,0);
 }
});
test('role changes on refresh immediately deny operator commands',async()=>{
 const f=fixture();f.a.sessions.get('test-session').refresh='initial-refresh';f.advance(241000);
 f.a.token=async()=>refreshed(f,{realm_access:{roles:['ztd-observer']}});
 const r=response();await f.a.command(f.req('next'),r,()=>assert.fail('observer authorized'));assert.equal(r.statusCode,403);
});
test('front-channel logout validates issuer and invalidates only matching sessions',async()=>{
 const f=fixture();f.a.sessions.set('other',{...f.a.sessions.get('test-session'),sid:'other-session'});
 let r=response();f.a.frontchannel({query:{iss:'https://invalid.example',sid:f.claims.sid}},r);assert.equal(r.statusCode,400);assert.equal(f.a.sessions.size,2);
 r=response();f.a.frontchannel({query:{iss:f.a.issuer,sid:f.claims.sid}},r);assert.equal(r.statusCode,200);assert.equal(f.a.sessions.has('test-session'),false);assert.equal(f.a.sessions.has('other'),true);
 const denied=response();await f.a.command(f.req('start'),denied,()=>assert.fail());assert.equal(denied.statusCode,401);
});
test('signed back-channel logout handles sid or subject and rejects replay',async()=>{
 for(const subjectOnly of [false,true]){
  const f=fixture();f.a.sessions.set('other',{...f.a.sessions.get('test-session'),subject:'other-user',sid:'other-session'});
  const c=logoutClaims(f,subjectOnly?{sid:undefined,sub:f.claims.sub}:{});const req={body:{logout_token:sign(c)}};
  const r=response();await f.a.backchannel(req,r);assert.equal(r.statusCode,200);assert.equal(f.a.sessions.has('test-session'),false);assert.equal(f.a.sessions.has('other'),true);
  const replay=response();await f.a.backchannel(req,replay);assert.equal(replay.statusCode,400);
  const denied=response();await f.a.command(f.req('start'),denied,()=>assert.fail());assert.equal(denied.statusCode,401);
 }
});
test('invalid logout tokens cannot revoke a session',async()=>{
 for(const changes of [{iss:'https://invalid.example'},{aud:'other'},{events:{'http://schemas.openid.net/event/backchannel-logout':null}},{nonce:'forbidden'},{iat:0},{sid:f=>f}]){
  const f=fixture();const r=response();await f.a.backchannel({body:{logout_token:sign(logoutClaims(f,changes))}},r);assert.equal(r.statusCode,400);assert.equal(f.a.sessions.size,1);
 }
 const f=fixture(),parts=sign(logoutClaims(f)).split('.');parts[1]=enc(logoutClaims(f,{sub:'forged'}));const r=response();await f.a.backchannel({body:{logout_token:parts.join('.')}},r);assert.equal(r.statusCode,400);assert.equal(f.a.sessions.size,1);
});
test('logout during refresh cannot resurrect the UI session',async()=>{
 const f=fixture();f.a.sessions.get('test-session').refresh='initial-refresh';f.advance(241000);let finish,started;
 const entered=new Promise(resolve=>started=resolve);f.a.token=()=>{started();return new Promise(resolve=>finish=resolve);};
 const pending=f.a.session(f.req());await entered;
 f.a.frontchannel({query:{iss:f.a.issuer,sid:f.claims.sid}},response());finish(refreshed(f));
 await assert.rejects(pending,{code:'LOGGED_OUT'});assert.equal(f.a.sessions.size,0);
});
