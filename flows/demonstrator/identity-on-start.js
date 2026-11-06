'use strict';
const OidcSearchParams = nodeUrl.URLSearchParams; const OidcURL = nodeUrl.URL;
const ISSUER = 'https://keycloak.85.215.131.155.sslip.io/realms/facis-ztd';
const ORIGIN = 'https://orce.85-215-131-155.sslip.io';
const ROLE_OPERATOR = 'ztd-operator', ROLE_OBSERVER = 'ztd-observer';
const SESSION_COOKIE = '__Secure-facis-ui', TX_COOKIE = '__Secure-facis-oidc';
const err = code => Object.assign(new Error(code), { code });
const random = () => crypto.randomBytes(32).toString('base64url');
const same = (a, b) => typeof a === 'string' && typeof b === 'string' && Buffer.byteLength(a) === Buffer.byteLength(b) && crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
function cookies(req) { const out = {}; for (const part of String(req.headers.cookie || '').split(';')) { const i = part.indexOf('='); if (i > 0) out[part.slice(0, i).trim()] = part.slice(i + 1).trim(); } return out; }
function cookie(res, name, value, maxAge, frame = false) { res.append('Set-Cookie', `${name}=${value}; Path=/dev/ztd; HttpOnly; Secure; SameSite=${frame ? 'None' : 'Lax'}; Max-Age=${maxAge}`); }
function safeHeaders(res) { res.set('Cache-Control', 'no-store'); res.set('Pragma', 'no-cache'); res.set('X-Content-Type-Options', 'nosniff'); res.set('Referrer-Policy', 'no-referrer'); }
function reply(res, status, code, state) { safeHeaders(res); res.status(status).json({ ok: false, error: { code }, ...(state ? { state } : {}) }); }
function role(claims) { const roles = Array.isArray(claims.realm_access?.roles) ? claims.realm_access.roles : []; const op = roles.includes(ROLE_OPERATOR), ob = roles.includes(ROLE_OBSERVER); return op === ob ? null : op ? ROLE_OPERATOR : ROLE_OBSERVER; }
function validateConfigChange(d) {
  const object = v => v && typeof v === 'object' && !Array.isArray(v);
  const exact = (v, keys) => object(v) && Object.keys(v).length === keys.length && keys.every(k => Object.hasOwn(v,k));
  const fail = () => { throw err('CFG-SCHEMA-INVALID'); };
  if (!exact(d,['kind','target','payload'])) fail();
  const targets = {'trust-zone':['zone-a','zone-b'],'policy-ref':['guard-a','guard-b'],measurement:['zone-a-gateway','zone-b-gateway'],'mock-replacement':['participant-backend','protected-resource']};
  if (!Object.hasOwn(targets,d.kind) || !targets[d.kind].includes(d.target)) fail();
  const p=d.payload;
  if (d.kind==='trust-zone' && (!exact(p,['zone']) || p.zone!==d.target)) fail();
  if (d.kind==='measurement' && (!exact(p,['digest']) || typeof p.digest!=='string' || !/^sha256:[0-9a-fA-F]{64}$/.test(p.digest))) fail();
  if (d.kind==='mock-replacement') {
    if (!exact(p,['adapter']) || !['mock','real'].includes(p.adapter)) fail();
    if (p.adapter==='real') throw err('CFG-REAL-API-UNAVAILABLE');
  }
  if (d.kind==='policy-ref' && (!exact(p,['bundle','revision']) || [p.bundle,p.revision].some(v=>typeof v!=='string' || !v.trim() || v.length>200))) fail();
  return {...d, payload:{...p}, validation:d.kind==='policy-ref'?'awaiting-registry':'local-schema-valid', phase:'preview'};
}
class UIAuth {
  constructor(options = {}) {
    this.issuer = options.issuer || ISSUER; this.origin = options.origin || ORIGIN; this.clientId = 'ztd-ui'; this.loginMode = options.loginMode === 'password' ? 'password' : 'pkce'; this.passwordPending = 0; this.loginAttempts = new Map(); this.fetch = options.fetch || null; this.now = options.now || Date.now;
    this.callback = this.origin + '/dev/ztd/oidc/callback'; this.ui = this.origin + '/dev/facis-demo/'; this.postLogout = this.origin + '/dev/facis-demo/';
    this.protocol = this.issuer + '/protocol/openid-connect'; this.sessions = new Map(); this.ended = new Map(); this.transactions = new Map(); this.replays = new Map(); this.keys = null; this.keyAt = 0; this.keyFetch = null; this.refreshes = new Map(); this.limit = 500; this.generation = 0;
  }
  reset() { this.generation += 1; this.sessions.clear(); this.ended.clear(); this.transactions.clear(); this.replays.clear(); }
  cleanup() { const now = this.now(); for (const [k, v] of this.transactions) if (v.expires <= now) this.transactions.delete(k); for (const [k, v] of this.replays) if (v <= now) this.replays.delete(k); for (const [k, v] of this.ended) if (v <= now) this.ended.delete(k); for (const [k, v] of this.sessions) if (now - v.created >= 8 * 3600000 || now - v.last >= 30 * 60000) { this.sessions.delete(k); this.markExpired(k); } }
  markExpired(key) { if (this.ended.size >= this.limit) this.ended.delete(this.ended.keys().next().value); this.ended.set(key, this.now() + 300000); }
  async request(url, options = {}, tokenErrors = false) {
    // Native TLS transport: fixed issuer endpoints, absolute timeout, bounded body; no redirects.
    if (![this.protocol + '/token', this.protocol + '/certs'].includes(url)) throw err('INVALID_IDENTITY_ENDPOINT');
    const data = await new Promise((resolve, reject) => {
      let settled = false; const finish = (e, v) => { if (settled) return; settled = true; clearTimeout(timer); e ? reject(e) : resolve(v); };
      const request = https.request(url, { method: options.method || 'GET', headers: options.headers || {}, rejectUnauthorized: true }, response => {
        let size = 0, parts = []; response.on('data', chunk => { size += chunk.length; if (size > 131072) { finish(err('INVALID_IDENTITY_RESPONSE')); response.destroy(); request.destroy(); } else parts.push(chunk); });
        response.on('error', () => finish(err('IDENTITY_PROVIDER_UNAVAILABLE')));
        response.on('end', () => finish(null, { status: response.statusCode, text: Buffer.concat(parts).toString('utf8') }));
      });
      const timer = setTimeout(() => { finish(err('IDENTITY_PROVIDER_UNAVAILABLE')); request.destroy(); }, 10000);
      request.on('error', () => finish(err('IDENTITY_PROVIDER_UNAVAILABLE')));
      if (options.body) request.write(String(options.body)); request.end();
    });
    if (data.status < 200 || data.status >= 300) {
      if (!tokenErrors) throw err('IDENTITY_PROVIDER_UNAVAILABLE');
      let body; try { body = JSON.parse(data.text); } catch { throw err('INVALID_IDENTITY_RESPONSE'); }
      throw err(data.status >= 500 ? 'IDENTITY_PROVIDER_UNAVAILABLE' : ({ unauthorized_client: 'CLIENT_NOT_ALLOWED', invalid_client: 'CLIENT_NOT_ALLOWED', invalid_grant: 'LOGIN_REJECTED', invalid_scope: 'LOGIN_SCOPE_REJECTED' }[body.error] || 'LOGIN_REJECTED'));
    }
    try { return JSON.parse(data.text); } catch { throw err('INVALID_IDENTITY_RESPONSE'); }
  }
  async jwks(force = false) {
    if (this.keys && !force && this.now() - this.keyAt < 60000) return this.keys;
    if (this.keyFetch) return this.keyFetch;
    this.keyFetch = this.request(this.protocol + '/certs').then(data => { if (!Array.isArray(data.keys) || data.keys.length > 32) throw err('INVALID_JWKS'); this.keys = data.keys; this.keyAt = this.now(); return this.keys; }).finally(() => { this.keyFetch = null; }); return this.keyFetch;
  }
  async verify(token, { nonce = undefined, logout = false, requireSubject = true } = {}) {
    if (typeof token !== 'string' || token.length > 32768) throw err('INVALID_TOKEN'); const parts = token.split('.'); if (parts.length !== 3) throw err('INVALID_TOKEN'); let h, c;
    try { h = JSON.parse(Buffer.from(parts[0], 'base64url')); c = JSON.parse(Buffer.from(parts[1], 'base64url')); } catch { throw err('INVALID_TOKEN'); }
    if (h.alg !== 'RS256' || typeof h.kid !== 'string' || h.crit || !c || Array.isArray(c)) throw err('INVALID_TOKEN');
    let keys = await this.jwks(); let key = keys.find(k => k.kid === h.kid && k.kty === 'RSA' && (!k.alg || k.alg === 'RS256') && (!k.use || k.use === 'sig'));
    if (!key) { keys = await this.jwks(true); key = keys.find(k => k.kid === h.kid && k.kty === 'RSA' && (!k.alg || k.alg === 'RS256') && (!k.use || k.use === 'sig')); }
    if (!key || Buffer.from(key.n || '', 'base64url').length < 256) throw err('INVALID_TOKEN');
    let valid = false; try { valid = crypto.verify('RSA-SHA256', Buffer.from(parts[0] + '.' + parts[1]), crypto.createPublicKey({ key, format: 'jwk' }), Buffer.from(parts[2], 'base64url')); } catch { } if (!valid) throw err('INVALID_TOKEN');
    const now = Math.floor(this.now() / 1000), aud = typeof c.aud === 'string' ? [c.aud] : c.aud;
    if (c.iss !== this.issuer || !Array.isArray(aud) || !aud.includes(this.clientId) || (c.azp && c.azp !== this.clientId) || typeof c.iat !== 'number' || c.iat > now + 30 || (c.nbf && c.nbf > now + 30)) throw err('INVALID_TOKEN');
    if (!logout) { if (typeof c.exp !== 'number' || !Number.isFinite(c.exp)) throw err('TOKEN_EXP_MISSING'); if ((requireSubject || c.sub !== undefined) && (typeof c.sub !== 'string' || !c.sub)) throw err('TOKEN_SUB_MISSING'); if (c.exp <= now) { node.warn('FACIS token timing: remainingSeconds=' + Math.floor(c.exp - now) + ', lifetimeSeconds=' + Math.floor(c.exp - c.iat) + ', runtimeEpochSeconds=' + now + ', issuedAtEpochSeconds=' + c.iat); throw err('EXPIRED'); } }
    if (nonce && !same(nonce, c.nonce)) throw err('INVALID_NONCE');
    if (logout) { const events = c.events; if (now - c.iat > 300 || (c.exp !== undefined && c.exp <= now) || !c.jti || typeof c.jti !== 'string' || c.nonce !== undefined || !events || typeof events !== 'object' || !Object.hasOwn(events, 'http://schemas.openid.net/event/backchannel-logout') || !events['http://schemas.openid.net/event/backchannel-logout'] || typeof events['http://schemas.openid.net/event/backchannel-logout'] !== 'object' || Array.isArray(events['http://schemas.openid.net/event/backchannel-logout']) || (!c.sid && !c.sub)) throw err('INVALID_LOGOUT_TOKEN'); }
    return c;
  }
  async token(form) { return this.request(this.protocol + '/token', { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: new OidcSearchParams({ ...form, client_id: this.clientId }) }, true); }
  async tokens(data, nonce, previous) {
    let access, id; try { access = await this.verify(data.access_token); } catch (e) { node.warn('FACIS login: access token validation failed [' + (['INVALID_TOKEN', 'EXPIRED', 'TOKEN_EXP_MISSING', 'TOKEN_SUB_MISSING', 'INVALID_JWKS', 'IDENTITY_PROVIDER_UNAVAILABLE'].includes(e.code) ? e.code : 'VALIDATION_ERROR') + ']'); throw e; } try { id = await this.verify(data.id_token, { nonce, requireSubject: true }); } catch (e) { node.warn('FACIS login: ID token validation failed [' + (['INVALID_TOKEN', 'EXPIRED', 'TOKEN_EXP_MISSING', 'TOKEN_SUB_MISSING', 'INVALID_NONCE', 'INVALID_JWKS', 'IDENTITY_PROVIDER_UNAVAILABLE'].includes(e.code) ? e.code : 'VALIDATION_ERROR') + ']'); throw e; }
    const username = typeof access.preferred_username === 'string' && access.preferred_username ? access.preferred_username : access.sub;
    if ((access.sub !== id.sub) || (access.sid && id.sid && access.sid !== id.sid) || (previous && (id.sub !== previous.subject || (previous.sid && (id.sid || access.sid) !== previous.sid))) || typeof data.refresh_token !== 'string' || !data.refresh_token || data.refresh_token.length > 32768 || (previous && data.refresh_token === previous.refresh)) throw err('INVALID_IDENTITY_RESPONSE');
    return { access: data.access_token, idToken: data.id_token, refresh: data.refresh_token, claims: { ...access, preferred_username: username }, subject: access.sub, username, sid: id.sid || access.sid, role: role(access), expires: access.exp * 1000 };
  }
  async session(req) {
    this.cleanup(); const key = cookies(req)[SESSION_COOKIE]; let s = this.sessions.get(key); if (!s) throw err(this.ended.has(key) ? 'EXPIRED' : 'LOGGED_OUT');
    if (this.now() >= s.expires) { this.sessions.delete(key); this.markExpired(key); throw err('EXPIRED'); }
    // Revalidate signature, issuer, audience and expiry on every request; never accept browser claims.
    const verifiedAccess = await this.verify(s.access); if (verifiedAccess.sub !== s.subject) throw err('INVALID_IDENTITY_RESPONSE'); s.claims = { ...verifiedAccess, preferred_username: verifiedAccess.preferred_username || verifiedAccess.sub }; s.role = role(verifiedAccess);
    if (s.expires - this.now() < 60000) {
      if (!this.refreshes.has(key)) this.refreshes.set(key, this.token({ grant_type: 'refresh_token', refresh_token: s.refresh }).then(d => this.tokens(d, null, s)).then(updated => { if (!this.sessions.has(key)) throw err('LOGGED_OUT'); Object.assign(s, updated); return s; }).catch(e => { this.sessions.delete(key); throw e; }).finally(() => this.refreshes.delete(key)));
      s = await this.refreshes.get(key);
    }
    if (!this.sessions.has(key)) throw err('LOGGED_OUT'); s.last = this.now(); return s;
  }
  async login(req, res) {
    this.cleanup(); if (this.transactions.size >= this.limit) return reply(res, 503, 'IDENTITY_BUSY');
    const tx = random(), state = random(), nonce = random(), verifier = random(); this.transactions.set(tx, { state, nonce, verifier, expires: this.now() + 300000 }); cookie(res, TX_COOKIE, tx, 300); safeHeaders(res);
    const q = new OidcSearchParams({ client_id: this.clientId, redirect_uri: this.callback, response_type: 'code', scope: 'openid profile roles', state, nonce, code_challenge: crypto.createHash('sha256').update(verifier).digest('base64url'), code_challenge_method: 'S256' }); res.redirect(303, this.protocol + '/auth?' + q);
  }
  async callbackHandler(req, res) {
    const generation = this.generation; const tx = cookies(req)[TX_COOKIE], v = this.transactions.get(tx); this.transactions.delete(tx); cookie(res, TX_COOKIE, '', 0); safeHeaders(res);
    const q = req.query; if (!v || v.expires <= this.now() || !same(v.state, q.state) || typeof q.code !== 'string' || q.code.length > 4096 || (q.iss && q.iss !== this.issuer)) return reply(res, 400, 'INVALID_OIDC_CALLBACK');
    try { this.cleanup(); if (this.sessions.size >= this.limit) throw err('IDENTITY_BUSY'); const data = await this.token({ grant_type: 'authorization_code', code: q.code, redirect_uri: this.callback, code_verifier: v.verifier }); const s = await this.tokens(data, v.nonce); if (generation !== this.generation) throw err('LOGIN_FAILED'); s.created = s.last = this.now(); s.csrf = random(); const key = random(); const old = cookies(req)[SESSION_COOKIE]; this.sessions.delete(old); this.sessions.set(key, s); cookie(res, SESSION_COOKIE, key, 8 * 3600); res.redirect(303, this.ui); } catch (e) { node.warn('FACIS login failed [' + (['CLIENT_NOT_ALLOWED', 'LOGIN_REJECTED', 'LOGIN_SCOPE_REJECTED', 'INVALID_IDENTITY_RESPONSE', 'IDENTITY_PROVIDER_UNAVAILABLE', 'INVALID_TOKEN', 'INVALID_NONCE', 'INVALID_JWKS', 'EXPIRED', 'TOKEN_EXP_MISSING', 'TOKEN_SUB_MISSING', 'IDENTITY_BUSY', 'LOGIN_FAILED'].includes(e.code) ? e.code : 'INTERNAL_ERROR') + ']'); return reply(res, 401, 'LOGIN_FAILED'); }
  }
  async status(req, res) { try { const s = await this.session(req); safeHeaders(res); res.json({ mode: 'oidc', state: s.role ? 'authenticated' : 'denied', username: s.claims.preferred_username, role: s.role, canOperate: s.role === ROLE_OPERATOR, csrf: s.csrf }); } catch (e) { reply(res, e.code === 'IDENTITY_PROVIDER_UNAVAILABLE' ? 503 : 401, e.code || 'IDENTITY_UNAVAILABLE', e.code === 'EXPIRED' ? 'expired' : 'logged out'); } }
  csrf(req, s) { return req.headers.origin === this.origin && same(req.headers['x-facis-csrf'], s.csrf); }
  async command(req, res, emit) {
    let s; try { s = await this.session(req); } catch (e) { return reply(res, 401, e.code || 'IDENTITY_UNAVAILABLE', e.code === 'EXPIRED' ? 'expired' : 'logged out'); }
    const p = req.body; if (!p || typeof p !== 'object' || Array.isArray(p) || !['status', 'start', 'next', 'reset', 'config-preview'].includes(p.type)) return reply(res, 400, 'INVALID_COMMAND');
    if (!this.csrf(req, s)) return reply(res, 403, 'CSRF_DENIED', 'denied');
    if (!s.role || (p.type !== 'status' && s.role !== ROLE_OPERATOR)) return reply(res, 403, p.type === 'config-preview' ? 'CFG-NOT-AUTHORISED' : 'UI-NOT-AUTHORISED', 'denied');
    if (p.type === 'config-preview') {
      let preview; try { preview = validateConfigChange(p.data); } catch (e) { return reply(res, 400, e.code || 'CFG-SCHEMA-INVALID'); }
      safeHeaders(res); return res.json({ ok: true, data: { preview, requested_by: s.claims.preferred_username, applied: false } });
    }
    const data = {}; for (const k of ['commandId', 'runId', 'scenario', 'serviceScenario', 'profile', 'variant', 'credentialToRevoke']) if (p.data?.[k] !== undefined) { if (typeof p.data[k] !== 'string' || p.data[k].length > 120) return reply(res, 400, 'INVALID_COMMAND'); data[k] = p.data[k]; }
    safeHeaders(res); req.facis = { userId: 'oidc-shared-review', subject: s.claims.sub, username: s.claims.preferred_username, role: s.role, scope: 'oidc-review' }; emit({ type: p.type, data, req, res, _facisAuthResponse: true });
  }
  async logout(req, res) {
    let s; try { s = await this.session(req); } catch { cookie(res, SESSION_COOKIE, '', 0); return reply(res, 401, 'LOGGED_OUT', 'logged out'); } if (req.headers.origin !== this.origin || !same(req.headers['x-facis-csrf'] || req.body?.csrf, s.csrf)) return reply(res, 403, 'CSRF_DENIED'); this.sessions.delete(cookies(req)[SESSION_COOKIE]); cookie(res, SESSION_COOKIE, '', 0); safeHeaders(res);
    const q = new OidcSearchParams({ client_id: this.clientId, id_token_hint: s.idToken, post_logout_redirect_uri: this.postLogout }); res.redirect(303, this.protocol + '/logout?' + q);
  }
  async backchannel(req, res) { try { const c = await this.verify(req.body?.logout_token, { logout: true }); this.cleanup(); if (this.replays.has(c.jti) || this.replays.size >= this.limit) throw err('INVALID_LOGOUT_TOKEN'); this.replays.set(c.jti, this.now() + 300000); for (const [key, s] of this.sessions) if ((c.sid ? s.sid === c.sid && (!c.sub || s.subject === c.sub) : s.subject === c.sub)) this.sessions.delete(key); safeHeaders(res); res.status(200).end(); } catch { return reply(res, 400, 'INVALID_LOGOUT_TOKEN'); } }
  frontchannel(req, res) { const { iss, sid } = req.query; safeHeaders(res); res.set('Content-Security-Policy', `default-src 'none'; frame-ancestors ${new OidcURL(this.issuer).origin}`); if (iss !== this.issuer || typeof sid !== 'string' || !sid) return reply(res, 400, 'INVALID_LOGOUT_REQUEST'); for (const [key, s] of this.sessions) if (s.sid === sid) this.sessions.delete(key); cookie(res, SESSION_COOKIE, '', 0); res.status(200).end(); }
}


context._facisAuth = new UIAuth(); global.set('facisUiAuthActive', true); node.status({ fill: 'green', shape: 'dot', text: 'PKCE session boundary' });