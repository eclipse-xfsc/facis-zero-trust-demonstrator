'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const crypto=require('node:crypto');
const {sources,sign,fixture,response}=require('./auth-fixture.cjs');

for(const [name,source] of Object.entries(sources)) {
  function boundary(settings={}) {
    const events=[],context={};
    new Function('nodeUrl','crypto','https','node','context','global','Buffer','env',source)(
      require('node:url'),crypto,{}, {warn:line=>{if(line.startsWith('{'))events.push(JSON.parse(line));},status(){}},context,{set(){}},Buffer,{get:n=>settings[n]});
    return {a:context._facisAuth,events};
  }
  test(name+': configured issuer and UI origin control the real PKCE redirect',async()=> {
    const {a}=boundary({FACIS_OIDC_ISSUER:'https://identity.example/realms/facis-ztd',FACIS_UI_ORIGIN:'https://viewer.example'});
    const r=response();await a.login({headers:{}},r);
    const url=new URL(r.location);
    assert.equal(url.origin,'https://identity.example');
    assert.equal(url.searchParams.get('redirect_uri'),'https://viewer.example/dev/ztd/oidc/callback');
    assert.equal(url.searchParams.get('code_challenge_method'),'S256');
    for(const bad of ['http://identity.example/realms/facis-ztd','https://user:pass@identity.example/realms/facis-ztd','https://identity.example/realms/other','https://identity.example/realms/facis-ztd?x=1']) {
      assert.throws(()=>boundary({FACIS_OIDC_ISSUER:bad}),{code:'INVALID_IDENTITY_CONFIG'});
    }
    assert.throws(()=>boundary({FACIS_UI_ORIGIN:'https://viewer.example/path'}),{code:'INVALID_IDENTITY_CONFIG'});
  });
  test(name+': every refused command has a matching recorded decision, with no token or caller header',async()=> {
    const {a,events}=boundary();
    const f=fixture(source); f.session('session-a',{realm_access:{roles:['ztd-observer']}});
    a.sessions=f.a.sessions; a.now=f.a.now; a.request=f.a.request;
    for(const [type,code] of [['start','UI-NOT-AUTHORISED'],['config-preview','CFG-NOT-AUTHORISED']]) {
      const req=f.req(type),r=response(); req.headers['x-request-id']='untrusted-value';
      await a.command(req,r,()=>assert.fail('observer dispatched'));
      const event=events.at(-1);
      assert.equal(r.statusCode,403); assert.equal(event.correlation_id,r.headers['X-Request-ID']);
      assert.equal(event.reason_code,code); assert.equal(event.state,'denied');
      assert.equal(event.action,type); assert.equal(event.event,'ui.authorization');
    }
    const record=JSON.stringify(events);
    assert.ok(!record.includes(a.sessions.get('session-a').access));
    assert.ok(!record.includes('untrusted-value'));
    assert.equal(new Set(events.map(e=>e.correlation_id)).size,events.length);
  });
  test(name+': invalid signature, issuer, audience, expiry and missing session are recorded before dispatch',async()=> {
    for(const [change,code] of [[{iss:'https://other.example'},'INVALID_TOKEN'],[{aud:'other'},'INVALID_TOKEN'],[{exp:1},'EXPIRED'],['signature','INVALID_TOKEN'],['absent','LOGGED_OUT']]) {
      const {a,events}=boundary(), f=fixture(source);f.session();
      a.sessions=f.a.sessions;a.now=f.a.now;a.request=f.a.request;
      if(change==='absent')a.sessions.clear();
      else if(change==='signature') {const parts=a.sessions.get('session-a').access.split('.');parts[1]=Buffer.from(JSON.stringify(f.claims({sub:'forged'}))).toString('base64url');a.sessions.get('session-a').access=parts.join('.');}
      else a.sessions.get('session-a').access=sign(f.claims(change));
      const r=response();await a.command(f.req('start'),r,()=>assert.fail('invalid identity dispatched'));
      assert.equal(r.statusCode,401);assert.equal(events[0].reason_code,code);assert.equal(events[0].state,'denied');
      assert.equal(events[0].correlation_id,r.headers['X-Request-ID']);
    }
  });
  test(name+': operator allow event accompanies the authenticated journey command',async()=> {
    const {a,events}=boundary(),f=fixture(source);f.session();
    a.sessions=f.a.sessions;a.now=f.a.now;a.request=f.a.request;
    const r=response();let dispatched=0;
    await a.command(f.req('start'),r,()=>dispatched++);
    assert.equal(dispatched,1);assert.equal(events[0].state,'allowed');assert.equal(events[0].reason_code,'UI-AUTHORISED');
    assert.equal(events[0].correlation_id,r.headers['X-Request-ID']);
  });
}
