const read = name => { const value = env.get(name); return typeof value === 'string' ? value.trim() : ''; };
const requestId = nodeCrypto.randomUUID();
const correlationId = nodeCrypto.randomUUID();
if (read('CONNECTOR_ADAPTER_ENABLED') !== 'true') {
  node.status({fill:'grey',shape:'ring',text:'Disabled: waiting for Connector endpoints'});
  return [{payload:{ok:false,requestId,correlationId,mode:'live',reasonCode:'CONNECTOR_NOT_ENABLED',failedStage:'configuration',events:[]}},null];
}
let deadline;
const AbortSignal = { timeout(ms) {
  const controller = nodeUtil.transferableAbortController();
  deadline = setTimeout(() => controller.abort(), ms);
  return controller.signal;
} };
// Standard Node transports keep TLS verification enabled and never follow redirects.
async function fetch(endpoint, options) {
  const target = new nodeURL.URL(endpoint);
  const transport = target.protocol === 'https:' ? nodeHTTPS : nodeHTTP;
  return await new Promise((resolve,reject) => {
    const request = transport.request(target,{method:options.method,headers:options.headers,signal:options.signal},response => resolve({
      status:response.statusCode,
      ok:response.statusCode >= 200 && response.statusCode < 300,
      headers:{get(name){const value=response.headers[name.toLowerCase()];return Array.isArray(value)?value.join(', '):value||null;}},
      body:response
    }));
    request.on('error',reject);
    request.end(options.body);
  });
}
const { createHash, generateKeyPairSync, randomUUID, sign } = nodeCrypto;
const { URL, URLSearchParams } = nodeURL;

const registrationScope = 'connector:client_registration';
const knownReasons = new Set(['dpop_invalid_proof', 'dpop_replayed', 'dpop_use_nonce', 'dpop_jkt_mismatch', 'dpop_invalid_ath', 'invalid_client', 'invalid_token', 'insufficient_scope', 'registration_rejected', 'invalid_request', 'server_error']);
const b64 = value => Buffer.from(value).toString('base64url');
class AdapterError extends Error {
  constructor(code, stage, status = null) { super(code); this.code = code; this.stage = stage; this.status = status; }
}
const invalid = () => { throw new AdapterError('CONNECTOR_CONFIG_INVALID', 'configuration'); };

// This adapter implements only the 30 September OAuth2 contract. It does not
// implement credential verification, policy decisions or the Connector itself.
function createConnectorAdapter(config) {
  const { tokenURL, registrationURL, protectedURL, registrarClientId, registrarClientSecret, scope, audience, mode = 'live', method = 'GET', timeoutMs = 7000 } = config || {};
  if (!['live', 'local-contract'].includes(mode) || !['GET', 'POST'].includes(method) || !Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 60000) invalid();
  const urls = [tokenURL, registrationURL, protectedURL].map(value => {
    let url; try { url = new URL(value); } catch { invalid(); }
    const loopback = ['127.0.0.1', '[::1]'].includes(url.hostname);
    if (url.username || url.password || url.hash || !(url.protocol === 'https:' || (mode === 'local-contract' && loopback && url.protocol === 'http:'))) invalid();
    return url.href;
  });
  if (new Set(urls).size !== 3) invalid();
  if (![registrarClientId, registrarClientSecret, scope].every(v => typeof v === 'string' && v.trim() && v.length <= 4096)) invalid();
  const scopes = scope.trim().split(/\s+/);
  if (scopes.includes(registrationScope) || scopes.some(s => !/^[\x21\x23-\x5b\x5d-\x7e]+$/.test(s))) invalid();
  if (audience !== undefined && (typeof audience !== 'string' || !audience.trim() || audience.length > 2048)) invalid();
  const [tokenEndpoint, registerEndpoint, resourceEndpoint] = urls;
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const jwk = publicKey.export({ format: 'jwk' });
  let registered;

  function proof(method, endpoint, accessToken, nonce) {
    const uri = new URL(endpoint); uri.search = ''; uri.hash = '';
    const claims = { jti: randomUUID(), htm: method, htu: uri.href, iat: Math.floor(Date.now() / 1000) };
    if (nonce) claims.nonce = nonce;
    if (accessToken) claims.ath = createHash('sha256').update(accessToken).digest('base64url');
    const input = b64(JSON.stringify({ typ: 'dpop+jwt', alg: 'ES256', jwk })) + '.' + b64(JSON.stringify(claims));
    return input + '.' + sign('sha256', Buffer.from(input), { key: privateKey, dsaEncoding: 'ieee-p1363' }).toString('base64url');
  }
  function basic(id, secret) {
    const escape = value => new URLSearchParams({ x: value }).toString().slice(2);
    return 'Basic ' + Buffer.from(escape(id) + ':' + escape(secret)).toString('base64');
  }
  async function request(stage, endpoint, { method = 'POST', body, headers = {}, accessToken, dpop = true }, signal) {
    let nonce;
    for (let attempt = 0; attempt < 2; attempt++) {
      let response, bytes = 0, chunks = [];
      try {
        response = await fetch(endpoint, { method, body, redirect: 'manual', signal, headers: { Accept: 'application/json', ...headers, ...(dpop ? { DPoP: proof(method, endpoint, accessToken, nonce) } : {}) } });
        if (response.body) {
          for await (const chunk of response.body) {
            bytes += chunk.byteLength;
            if (bytes > 65536) throw new AdapterError('CONNECTOR_RESPONSE_TOO_LARGE', stage, response.status);
            chunks.push(chunk);
          }
        }
      } catch (error) {
        if (error instanceof AdapterError) throw error;
        throw new AdapterError(signal.aborted ? 'CONNECTOR_TIMEOUT' : 'CONNECTOR_UNAVAILABLE', stage);
      }
      let data;
      try { data = JSON.parse(Buffer.concat(chunks).toString('utf8')); } catch { data = null; }
      const challenge = [400, 401].includes(response.status) && (data?.error === 'use_dpop_nonce' || data?.reason === 'dpop_use_nonce' || /\berror="use_dpop_nonce"/.test(response.headers.get('www-authenticate') || ''));
      if (dpop && challenge && attempt === 0) {
        const supplied = response.headers.get('dpop-nonce');
        if (supplied && supplied.length <= 1024 && !/[\r\n]/.test(supplied)) { nonce = supplied; continue; }
      }
      if (!response.ok) throw new AdapterError(knownReasons.has(data?.reason) ? data.reason : response.status >= 500 ? 'CONNECTOR_UPSTREAM_FAILURE' : 'CONNECTOR_REQUEST_REFUSED', stage, response.status);
      if (!data || typeof data !== 'object' || Array.isArray(data)) throw new AdapterError('CONNECTOR_INVALID_RESPONSE', stage, response.status);
      return { data, status: response.status };
    }
  }
  function tokenValue(data, stage, requireDPoP) {
    if (typeof data.access_token !== 'string' || !/^[\x21-\x7e]{1,16384}$/.test(data.access_token) || !['DPoP', 'Bearer'].includes(data.token_type) || (requireDPoP && data.token_type !== 'DPoP') || !Number.isFinite(data.expires_in) || data.expires_in <= 0) throw new AdapterError('CONNECTOR_INVALID_TOKEN_RESPONSE', stage);
    if (data.scope !== undefined && (typeof data.scope !== 'string' || scopes.some(s => !data.scope.split(/\s+/).includes(s)))) throw new AdapterError('insufficient_scope', stage);
    return data;
  }
  async function register(signal, trace) {
    const form = new URLSearchParams({ grant_type: 'client_credentials', scope: [registrationScope, ...scopes].join(' '), audience: registerEndpoint });
    const bootstrap = tokenValue((await request('registration-token', tokenEndpoint, { body: form.toString(), headers: { ...trace, Authorization: basic(registrarClientId, registrarClientSecret), 'Content-Type': 'application/x-www-form-urlencoded' } }, signal)).data, 'registration-token', false);
    const metadata = { client_name: 'participant backend', grant_types: ['client_credentials'], token_endpoint_auth_method: 'client_secret_basic', scope: scopes.join(' '), dpop_bound_access_tokens: true };
    const registered = await request('registration', registerEndpoint, { body: JSON.stringify(metadata), headers: { ...trace, Authorization: bootstrap.token_type + ' ' + bootstrap.access_token, 'Content-Type': 'application/json' }, accessToken: bootstrap.access_token, dpop: bootstrap.token_type === 'DPoP' }, signal);
    const value = registered.data;
    if (registered.status !== 201 || ![value.client_id, value.client_secret].every(v => typeof v === 'string' && v.length > 0 && v.length <= 4096) || value.dpop_bound_access_tokens !== true) throw new AdapterError('CONNECTOR_INVALID_REGISTRATION_RESPONSE', 'registration', registered.status);
    return { id: value.client_id, secret: value.client_secret };
  }
  return Object.freeze({
    async run({ requestId, correlationId, payload } = {}) {
      for (const id of [requestId, correlationId]) if (typeof id !== 'string' || !/^[A-Za-z0-9._:-]{1,128}$/.test(id)) throw new AdapterError('CONNECTOR_IDENTIFIER_INVALID', 'configuration');
      let body;
      if (method === 'POST') {
        try { body = JSON.stringify(payload); } catch { throw new AdapterError('CONNECTOR_PAYLOAD_INVALID', 'configuration'); }
        if (!payload || typeof payload !== 'object' || Array.isArray(payload) || Buffer.byteLength(body) > 65536) throw new AdapterError('CONNECTOR_PAYLOAD_INVALID', 'configuration');
      } else if (payload !== undefined) throw new AdapterError('CONNECTOR_PAYLOAD_INVALID', 'configuration');
      const events = [], signal = AbortSignal.timeout(timeoutMs);
      const trace = { 'X-Request-ID': requestId, 'X-Correlation-ID': correlationId };
      const emit = (event, stage, detail = {}) => events.push({ event, stage, requestId, correlationId, mode, timestamp: new Date().toISOString(), ...detail });
      let stage = 'registration';
      try {
        emit('registration.requested', stage);
        // Cache only the generated client credentials, in this server-side instance.
        // Concurrent runs may register independently; no global/session state is shared.
        const client = registered || await register(signal, trace);
        registered = client;
        emit('registration.ready', stage);
        stage = 'token';
        const form = new URLSearchParams({ grant_type: 'client_credentials', scope: scopes.join(' ') });
        if (audience) form.set('audience', audience);
        const token = tokenValue((await request(stage, tokenEndpoint, { body: form.toString(), headers: { ...trace, Authorization: basic(client.id, client.secret), 'Content-Type': 'application/x-www-form-urlencoded' } }, signal)).data, stage, true);
        emit('token.acquired', stage);
        stage = 'protected-call';
        emit('protected.requested', stage);
        const response = await request(stage, resourceEndpoint, { method, body, headers: { Authorization: 'DPoP ' + token.access_token, 'X-Request-ID': requestId, 'X-Correlation-ID': correlationId, ...(method === 'POST' ? { 'Content-Type': 'application/json' } : {}) }, accessToken: token.access_token }, signal);
        emit('protected.responded', stage, { status: response.status });
        return { ok: true, requestId, correlationId, mode, status: response.status, data: response.data, events };
      } catch (error) {
        const failure = error instanceof AdapterError ? error : new AdapterError('CONNECTOR_UNAVAILABLE', stage);
        emit('request.refused', failure.stage, { reasonCode: failure.code, status: failure.status });
        return { ok: false, requestId, correlationId, mode, reasonCode: failure.code, failedStage: failure.stage, status: failure.status, events };
      }
    }
  });
}

try {
  const method = read('CONNECTOR_METHOD') || 'GET';
  const adapter = createConnectorAdapter({
    tokenURL:read('CONNECTOR_TOKEN_URL'),
    registrationURL:read('CONNECTOR_REGISTRATION_URL'),
    protectedURL:read('CONNECTOR_PROTECTED_URL'),
    registrarClientId:read('CONNECTOR_REGISTRAR_CLIENT_ID'),
    registrarClientSecret:read('CONNECTOR_REGISTRAR_CLIENT_SECRET'),
    scope:read('CONNECTOR_SCOPE'),
    audience:read('CONNECTOR_AUDIENCE') || undefined,
    method,mode:'live',timeoutMs:Number(read('CONNECTOR_TIMEOUT_MS') || 7000)
  });
  const result = await adapter.run({requestId,correlationId,...(method === 'POST' ? {payload:msg.payload} : {})});
  node.status({fill:result.ok?'green':'red',shape:'dot',text:result.ok?'Protected response received':result.reasonCode});
  return [{payload:result},result.events.map(event=>({payload:event}))];
} catch (error) {
  const result={ok:false,requestId,correlationId,mode:'live',reasonCode:error instanceof AdapterError?error.code:'CONNECTOR_UNAVAILABLE',failedStage:'configuration',events:[]};
  node.status({fill:'red',shape:'ring',text:result.reasonCode});
  return [{payload:result},null];
} finally { if (deadline) clearTimeout(deadline); }
