'use strict';
// Required delivery behavior. Failures remain visible until the implementation is corrected.
const test=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const {fixture,response,sign,root}=require('./auth-fixture.cjs');

test('identity contract: reject an access token without sub despite a valid ID token',async()=>{
  const f=fixture(); const claims=f.claims(); delete claims.sub;
  const tokens={...f.tokens({},'contract-nonce'),access_token:sign(claims)};
  await assert.rejects(()=>f.a.tokens(tokens,'contract-nonce'), 'Missing access-token sub must not be silently supplied from the ID token');
});

// These fields are read-only in the supplied scenario contract, not merely disabled in HTML.
for(const field of ['participantBackend','protectedResource','dns']) {
  test('configuration contract: reject attempted edit to read-only '+field,async()=>{
    const f=fixture(); f.session(); const r=response();
    await f.a.command(f.req('config-preview',{[field]:'unauthorized-change'}),r,()=>assert.fail('Configuration must not execute a journey'));
    assert.ok(r.statusCode>=400 && r.statusCode<500, 'Expected a client error; received '+r.statusCode+' for read-only field '+field);
  });
}

test('UI package: every local script and stylesheet referenced by index.html exists',()=>{
  const dir=path.join(root,'ui/demonstrator/src'); const html=fs.readFileSync(path.join(dir,'index.html'),'utf8');
  const refs=[...html.matchAll(/<(?:script|link)\b[^>]*(?:src|href)=["']([^"']+)["']/gi)].map(m=>m[1]).filter(v=>v.startsWith('./'));
  assert.ok(refs.length>0,'Expected local UI assets');
  const missing=refs.filter(ref=>!fs.existsSync(path.resolve(dir,ref.split(/[?#]/)[0])));
  assert.deepEqual(missing,[],'Missing referenced UI assets: '+missing.join(', '));
});
