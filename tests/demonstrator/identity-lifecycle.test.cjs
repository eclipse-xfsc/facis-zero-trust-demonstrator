'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const {fixture,response,sign,sources}=require('./auth-fixture.cjs');
const noEmit=()=>assert.fail('Rejected command must not reach the journey engine');

// Exercise both editable source and the code actually imported into ORCE.
for(const [label,source] of Object.entries(sources)) {
  const check=(name,fn)=>test(label+': '+name,()=>fn(fixture(source)));
  check('unauthenticated commands never execute',async f=>{
    for(const type of ['status','start','next','reset','config-preview']) {
      const r=response(); await f.a.command(f.req(type),r,noEmit); assert.equal(r.statusCode,401); assert.equal(r.body.error.code,'LOGGED_OUT');
    }
  });
  check('missing or incorrect CSRF and origin reject mutations and logout',async f=>{
    f.session();
    for(const type of ['start','next','reset','config-preview']) for(const field of ['origin','x-facis-csrf']) for(const value of [undefined,'invalid']) {
      const req=f.req(type); req.headers[field]=value; const r=response(); await f.a.command(req,r,noEmit);
      assert.equal(r.statusCode,403); assert.equal(r.body.error.code,'CSRF_DENIED');
    }
    const req=f.req(); delete req.headers['x-facis-csrf']; const r=response(); await f.a.logout(req,r);
    assert.equal(r.statusCode,403); assert.equal(f.a.sessions.size,1);
  });
  check('valid callback binds nonce, PKCE verifier and creates a secure session; replay fails',async f=>{
    const {transaction,request}=await f.begin(); let exchanges=0;
    f.a.token=async form=>{exchanges++; assert.equal(form.code_verifier,transaction.verifier); assert.equal(form.redirect_uri,f.a.callback); return f.tokens({},transaction.nonce);};
    const r=response(); await f.a.callbackHandler(request,r); assert.equal(r.statusCode,303); assert.equal(r.location,f.a.ui); assert.equal(f.a.sessions.size,1);
    const sessionCookie=r.headers['Set-Cookie'].find(v=>v.startsWith('__Secure-facis-ui='));
    for(const attribute of ['HttpOnly','Secure','SameSite=Lax','Path=/dev/ztd']) assert.ok(sessionCookie.includes(attribute));
    const replay=response(); await f.a.callbackHandler(request,replay); assert.equal(replay.statusCode,400); assert.equal(exchanges,1);
  });
  check('wrong state, expired transaction and wrong issuer fail before token exchange',async f=>{
    for(const fault of ['state','expiry','issuer']) {
      const {request}=await f.begin(); if(fault==='state') request.query.state='wrong'; if(fault==='issuer') request.query.iss='https://invalid.example'; if(fault==='expiry') f.advance(300001);
      f.a.token=async()=>assert.fail('Invalid callback exchanged a code'); const r=response(); await f.a.callbackHandler(request,r); assert.equal(r.statusCode,400);
    }
    assert.equal(f.a.sessions.size,0);
  });
  check('wrong nonce or inconsistent access/ID subjects cannot establish a session',async f=>{
    for(const fault of ['nonce','subject']) {
      const {transaction,request}=await f.begin(); f.a.token=async()=>{
        const tokens=f.tokens({},fault==='nonce'?'wrong':transaction.nonce);
        if(fault==='subject') tokens.access_token=sign(f.claims({sub:'different-subject'})); return tokens;
      };
      const r=response(); await f.a.callbackHandler(request,r); assert.equal(r.statusCode,401); assert.equal(f.a.sessions.size,0);
    }
  });
  check('signed back-channel logout invalidates only matching sessions and rejects replay',async f=>{
    f.session(); f.session('session-b',{sub:'subject-b',sid:'sid-b'});
    const token=sign(f.claims({jti:'logout-once',events:{'http://schemas.openid.net/event/backchannel-logout':{}}}));
    const r=response(); await f.a.backchannel({body:{logout_token:token}},r); assert.equal(r.statusCode,200);
    assert.equal(f.a.sessions.has('session-a'),false); assert.equal(f.a.sessions.has('session-b'),true);
    const denied=response(); await f.a.command(f.req(),denied,noEmit); assert.equal(denied.statusCode,401);
    const replay=response(); await f.a.backchannel({body:{logout_token:token}},replay); assert.equal(replay.statusCode,400);
  });
  check('invalid back-channel events, issuer, nonce and stale token preserve sessions',async f=>{
    f.session();
    const base={jti:'bad-logout',events:{'http://schemas.openid.net/event/backchannel-logout':{}}};
    for(const change of [{events:{}},{iss:'https://invalid.example'},{nonce:'not-permitted'},{iat:Math.floor(1802304000000/1000)-301}]) {
      const r=response(); await f.a.backchannel({body:{logout_token:sign(f.claims({...base,...change}))}},r);
      assert.equal(r.statusCode,400); assert.equal(f.a.sessions.size,1);
    }
  });
  check('front-channel logout checks issuer and isolates the session',async f=>{
    f.session(); f.session('session-b',{sub:'subject-b',sid:'sid-b'});
    const bad=response(); f.a.frontchannel({query:{iss:'https://invalid.example',sid:'sid-a'}},bad); assert.equal(bad.statusCode,400); assert.equal(f.a.sessions.size,2);
    const good=response(); f.a.frontchannel({query:{iss:f.a.issuer,sid:'sid-a'}},good); assert.equal(good.statusCode,200);
    assert.equal(f.a.sessions.has('session-a'),false); assert.equal(f.a.sessions.has('session-b'),true);
  });
  check('concurrent requests share one refresh and use rotated credentials',async f=>{
    f.session(); f.advance(250000); let release; let count=0;
    f.a.token=async form=>{count++; assert.equal(form.grant_type,'refresh_token'); assert.equal(form.refresh_token,'local-refresh'); return new Promise(resolve=>{release=resolve;});};
    const one=f.a.session(f.req()),two=f.a.session(f.req());
    await new Promise(resolve=>setImmediate(resolve)); assert.equal(count,1); release(f.tokens()); await Promise.all([one,two]);
    assert.equal(f.a.sessions.get('session-a').refresh,'rotated-local-refresh'); assert.equal(f.a.refreshes.size,0);
  });
  check('refresh rejection removes the session and refuses the command',async f=>{
    f.session(); f.advance(250000); f.a.token=async()=>{throw Object.assign(new Error('rejected'),{code:'LOGIN_REJECTED'});};
    const r=response(); await f.a.command(f.req(),r,noEmit); assert.equal(r.statusCode,401); assert.equal(f.a.sessions.size,0);
  });
  check('in-flight refresh cannot restore a session removed by logout',async f=>{
    f.session(); f.advance(250000); let release; f.a.token=async()=>new Promise(resolve=>{release=resolve;});
    const pending=assert.rejects(()=>f.a.session(f.req()),{code:'LOGGED_OUT'});
    await new Promise(resolve=>setImmediate(resolve));
    f.a.frontchannel({query:{iss:f.a.issuer,sid:'sid-a'}},response()); release(f.tokens()); await pending; assert.equal(f.a.sessions.size,0);
  });
  check('idle and maximum session lifetime refuse otherwise valid tokens',async f=>{
    for(const boundary of ['idle','maximum']) {
      const s=f.session(); if(boundary==='idle') s.last-=30*60000; else s.created-=8*3600000;
      const r=response(); await f.a.command(f.req(),r,noEmit); assert.equal(r.statusCode,401); assert.equal(r.body.state,'expired');
    }
  });
  check('JWKS provider failure cannot authorize commands',async f=>{
    f.session(); f.a.request=async()=>{throw Object.assign(new Error('offline'),{code:'IDENTITY_PROVIDER_UNAVAILABLE'});};
    const r=response(); await f.a.command(f.req(),r,noEmit); assert.equal(r.statusCode,401);
  });
}
