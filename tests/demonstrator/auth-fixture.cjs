'use strict';
// Local component harness: real RSA signatures; no network, real accounts or credentials.
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const root = path.resolve(__dirname, '../..');
const standalone = fs.readFileSync(path.join(root, 'flows/demonstrator/identity-on-start.js'), 'utf8');
const nodes = JSON.parse(fs.readFileSync(path.join(root, 'flows/demonstrator/identity_flow.json'), 'utf8'));
const embedded = nodes.find(n => n.id === 'facis-native-identity-engine').initialize;
if (!embedded) throw new Error('Identity flow initialization code not found');
const {privateKey, publicKey} = crypto.generateKeyPairSync('rsa', {modulusLength: 2048});
const jwk = {...publicKey.export({format: 'jwk'}), kid: 'local-regression-key', use: 'sig', alg: 'RS256'};
const enc = value => Buffer.from(JSON.stringify(value)).toString('base64url');
function sign(claims) {
  const data = enc({alg: 'RS256', kid: jwk.kid}) + '.' + enc(claims);
  return data + '.' + crypto.sign('RSA-SHA256', Buffer.from(data), privateKey).toString('base64url');
}
function response() {
  return {headers: {}, statusCode: 200, status(n) {this.statusCode=n; return this;},
    set(k,v) {this.headers[k]=v; return this;}, append(k,v) {(this.headers[k]??=[]).push(v);},
    json(body) {this.body=body; return this;}, redirect(n,url) {this.statusCode=n; this.location=url;}, end() {this.ended=true;}};
}
function fixture(source = standalone) {
  const UIAuth = new Function('nodeUrl','crypto','https','node','context','global','Buffer', source+'\nreturn UIAuth;')(
    require('node:url'), crypto, {request() {throw new Error('Unexpected network request');}}, {warn(){},status(){}}, {}, {set(){}}, Buffer);
  let time = 1802304000000;
  const a = new UIAuth({now: () => time});
  a.request = async url => {if(url !== a.protocol+'/certs') throw new Error('Unexpected request: '+url); return {keys:[jwk]};};
  const claims = (extra = {}) => ({iss:a.issuer,aud:'ztd-ui',azp:'ztd-ui',sub:'subject-a',sid:'sid-a',preferred_username:'test-user',
    iat:Math.floor(time/1000),exp:Math.floor(time/1000)+300,realm_access:{roles:['ztd-operator']},...extra});
  function session(key='session-a', extra={}) {
    const c = claims(extra);
    const s = {access:sign(c),idToken:sign(c),refresh:'local-refresh',subject:c.sub,username:c.preferred_username,claims:c,
      role:c.realm_access.roles[0],sid:c.sid,expires:c.exp*1000,created:time,last:time,csrf:'local-csrf'};
    a.sessions.set(key,s); return s;
  }
  const req = (type='start', data={}, key='session-a') => ({headers:{cookie:'__Secure-facis-ui='+key,origin:a.origin,'x-facis-csrf':'local-csrf'},body:{type,data},query:{}});
  const tokens = (extra = {}, nonce) => ({access_token:sign(claims(extra)),id_token:sign(claims({...extra,...(nonce?{nonce}:{})})),refresh_token:'rotated-local-refresh'});
  async function begin() {
    const r=response(); await a.login({headers:{}},r);
    const cookie=r.headers['Set-Cookie'][0].split(';')[0];
    const transaction=a.transactions.get(cookie.slice(cookie.indexOf('=')+1));
    return {transaction,request:{headers:{cookie},query:{state:transaction.state,code:'local-code',iss:a.issuer}}};
  }
  return {a,claims,session,req,tokens,begin,advance(ms){time+=ms;}};
}
module.exports={fixture,response,sign,sources:{standalone,embedded},root};
