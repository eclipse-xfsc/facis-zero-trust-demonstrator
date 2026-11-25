'use strict';
// Real Keycloak code + PKCE login, followed by the same UIAuth code ORCE packages.
// No request/token/JWKS override. Credentials and the cross-boundary token stay private.
const fs = require('node:fs');
const path = require('node:path');
const https = require('node:https');
const crypto = require('node:crypto');
const assert = require('node:assert/strict');
const root = path.resolve(__dirname, '../..');
function required(name) { if (!process.env[name]) throw new Error('Missing ' + name); return process.env[name]; }
const response = () => ({
  headers: {}, statusCode: 200,
  set(k,v) { this.headers[k]=v; return this; },
  append(k,v) { (this.headers[k]??=[]).push(v); },
  status(v) { this.statusCode=v; return this; },
  json(v) { this.body=v; }, redirect(s,url) { this.statusCode=s; this.location=url; }, end() {}
});
function browser() {
  const cookies = new Map();
  return (url, body) => new Promise((resolve, reject) => {
    const req = https.request(url, { method: body ? 'POST' : 'GET', timeout: 10000, headers: {
      Cookie: [...cookies].map(([k,v])=>k+'='+v).join('; '),
      ...(body ? { 'Content-Type': 'application/x-www-form-urlencoded' } : {})
    } }, res => {
      for (const c of res.headers['set-cookie'] || []) { const pair=c.split(';')[0], i=pair.indexOf('='); cookies.set(pair.slice(0,i),pair.slice(i+1)); }
      const chunks=[]; let size=0;
      res.on('data', c=> { size+=c.length; if(size>1048576) req.destroy(new Error('Response too large')); else chunks.push(c); });
      res.on('error', reject);
      res.on('end', ()=>resolve({status:res.statusCode, location:res.headers.location, text:Buffer.concat(chunks).toString()}));
    });
    req.on('timeout',()=>req.destroy(new Error('Identity request timed out')));
    req.on('error',()=>reject(new Error('Identity transport failed')));
    if(body) req.write(body.toString()); req.end();
  });
}
async function main() {
  const issuer=required('FACIS_OIDC_ISSUER'), origin=required('FACIS_UI_ORIGIN');
  const recordPath=required('KEYCLOAK_RECORD'), tokenPath=required('KEYCLOAK_GUARD_TOKEN_FILE');
  const events=[];
  const source=fs.readFileSync(path.join(root,'flows/demonstrator/identity-on-start.js'),'utf8');
  const UIAuth=new Function('nodeUrl','crypto','https','node','context','global','Buffer','env',source+'\nreturn UIAuth;')(
    require('node:url'),crypto,https,{status(){},warn(line){ if(line.startsWith('{')) events.push(JSON.parse(line)); }},{},{set(){}},Buffer,{get:n=>process.env[n]});
  const discovery=await browser()(issuer+'/.well-known/openid-configuration');
  assert.equal(discovery.status,200,'Keycloak discovery unavailable');
  assert.equal(JSON.parse(discovery.text).issuer,issuer,'Discovery issuer differs');
  const a=new UIAuth({issuer,origin});
  const records=[];
  async function login(persona, password) {
    const b=browser(), r=response();
    await a.login({headers:{}},r);
    const txCookie=r.headers['Set-Cookie'][0].split(';')[0];
    const form=await b(r.location);
    assert.equal(form.status,200,'Login page unavailable');
    const action=form.text.match(/<form\b[^>]*\baction="([^"]+)"/i)?.[1]?.replaceAll('&amp;','&');
    assert.ok(action,'No login form');
    assert.equal(new URL(action).origin,new URL(issuer).origin,'Foreign login form');
    const signedIn=await b(action,new URLSearchParams({username:persona,password,credentialId:''}));
    assert.equal(signedIn.status,302,'Keycloak login failed');
    // Never include a redirect URI (it contains the code) in an assertion failure.
    const callback=new URL(signedIn.location);
    assert.ok(callback.origin===origin && callback.pathname==='/dev/ztd/oidc/callback','Unexpected callback');
    const done=response();
    await a.callbackHandler({headers:{cookie:txCookie},query:Object.fromEntries(callback.searchParams)},done);
    assert.equal(done.statusCode,303,'Code exchange rejected');
    const cookie=done.headers['Set-Cookie'].find(c=>c.startsWith('__Secure-facis-ui=')).split(';')[0];
    const status=response(); await a.status({headers:{cookie}},status);
    assert.equal(status.statusCode,200,'Session unavailable');
    return {cookie,csrf:status.body.csrf,b};
  }
  async function command(name, session, type, status, reason, emitted) {
    let count=0; const r=response(), before=events.length;
    const req={headers:{cookie:session.cookie,origin,'x-facis-csrf':session.csrf},body:{type,data:{scenario:'atlas-successful-call'}}};
    await a.command(req,r,()=>{count++;});
    assert.equal(r.statusCode,status,name+' status'); assert.equal(count,emitted,name+' dispatch count');
    const event=events[before];
    assert.ok(event && event.correlation_id===r.headers['X-Request-ID'],name+' missing decision');
    assert.equal(event.reason_code,reason,name+' reason');
    assert.equal(event.state,emitted?'allowed':'denied',name+' state');
    records.push({case:name,status,dispatched:count,event});
  }
  const operator=await login('bdd-operator',required('BDD_OPERATOR_PASSWORD'));
  const observer=await login('bdd-observer',required('BDD_OBSERVER_PASSWORD'));
  await command('operator start',operator,'start',200,'UI-AUTHORISED',1);
  await command('observer start',observer,'start',403,'UI-NOT-AUTHORISED',0);
  await command('observer configuration',observer,'config-preview',403,'CFG-NOT-AUTHORISED',0);
  const key=operator.cookie.split('=')[1];
  fs.writeFileSync(tokenPath,a.sessions.get(key).access,{mode:0o600,flag:'wx'});
  const refresh=a.sessions.get(key).refresh;
  const logout=response();
  await a.logout({headers:{cookie:operator.cookie,origin,'x-facis-csrf':operator.csrf}},logout);
  assert.equal(logout.statusCode,303,'Logout did not redirect');
  const ended=await operator.b(logout.location);
  assert.ok([200,302,303].includes(ended.status),'Keycloak logout unavailable');
  await assert.rejects(()=>a.token({grant_type:'refresh_token',refresh_token:refresh}),{code:'LOGIN_REJECTED'});
  await command('logged out operator',operator,'start',401,'LOGGED_OUT',0);
  // Exercise expiry of an actual signed token without delaying the proof five minutes.
  a.now=()=>Date.now()+301000;
  await command('expired observer',observer,'start',401,'EXPIRED',0);
  fs.writeFileSync(recordPath,JSON.stringify({issuer,discovery:true,cases:records},null,2)+'\n');
}
main().catch(()=> { console.error('Keycloak viewer proof failed (credentials and tokens suppressed)'); process.exitCode=1; });
