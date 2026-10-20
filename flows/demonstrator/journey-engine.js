const CHECK_DEFINITIONS = [
  { id: 'request', name: 'Resource request', detail: 'Participant requests the protected sample resource.' },
  { id: 'initial-refusal', name: 'Initial refusal', detail: 'Request is refused until the required credential is present.' },
  { id: 'credential', name: 'Credential issued and presented', detail: 'OCM W-Stack issues the credential; status and revocation are evaluated.' },
  { id: 'trust-checks', name: 'Trust checks', detail: 'Trust-zone membership, attestation and the mission-data:read permission are evaluated.' },
  { id: 'measurements', name: 'Measurements', detail: 'Local sample TEE and runtime values are compared with sample expected values.' },
  { id: 'final-policy', name: 'Final policy decision', detail: 'The request is retried and the final result is recorded.' }
];

const type = typeof msg.type === 'string' ? msg.type : '';
const data = msg.data && typeof msg.data === 'object' && !Array.isArray(msg.data) ? msg.data : {};
const userId = msg.req && msg.req.facis && msg.req.facis.userId;
const scenarios = msg.journeySampleScenarios || {};
const aliases = msg.journeyScenarioAliases || {};
const adapterConfig = msg.journeyAdapterConfig || { mode: 'fixture' };
const serviceScenarios = ['success', 'denied', 'unavailable', 'error', 'slow'];
const timestamp = () => new Date().toISOString();
const uuid = () => 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (token) => {
  const value = Math.floor(Math.random() * 16);
  return (token === 'x' ? value : ((value & 3) | 8)).toString(16);
});
const replyError = (code, detail) => {
  msg.payload = { ok: false, error: { code, detail } };
  return msg;
};
// Server-side person-role gate in authenticated review mode.
if (true) {
  const viewer = msg.req && msg.req.facis;
  if (!viewer || viewer.scope !== 'oidc-review' || !['ztd-operator','ztd-observer'].includes(viewer.role)) return replyError('UI-NOT-AUTHORISED','denied');
  if (type !== 'status' && viewer.role !== 'ztd-operator') return replyError('UI-NOT-AUTHORISED','denied');
}

const publicState = (state) => {
  if (!state) return null;
  const copy = JSON.parse(JSON.stringify(state));
  if (copy.adapterMode === 'http-sample' && copy.serviceRequest) copy.transport = 'Participant sample HTTPS';
  delete copy.ownerId;
  return copy;
};
const replyState = (state, extra) => {
  msg.payload = {
    ok: true,
    data: Object.assign({
      sample: true,
      fixtureOnly: true,
      atlasCatalog,
      availability: adapterConfig.error ? 'unavailable' : 'available',
      adapterMode: adapterConfig.mode,
      transport: adapterConfig.mode === 'http-sample' ? 'Participant sample HTTPS' : 'fixture',
      protocol: 'journey.sample/v1',
      supportedCommands: ['status', 'start', 'next', 'reset'],
      state: publicState(state)
    }, extra || {})
  };
  return msg;
};
const addEvent = (state, event, detail) => {
  const item = { event, timestamp: timestamp(), detail: detail || '' };
  state.events.push(item);
  state.updatedAt = item.timestamp;
  return item;
};
const addEvidence = (state, event, detail, dataValue) => {
  const item = { event, timestamp: timestamp(), detail: detail || '', data: dataValue || {} };
  state.evidence.push(item);
  state.updatedAt = item.timestamp;
  return item;
};
const clone = (value) => JSON.parse(JSON.stringify(value));
const pendingPolicyChecks = (fixture) => fixture.policyChecks.map((item) => Object.assign({}, item, { detail: 'Not evaluated', status: 'Not evaluated' }));
const revealPolicyChecks = (state, fixture, step) => {
  fixture.policyChecks.forEach((item, index) => {
    if (item.step === step) state.policyChecks[index] = clone(item);
  });
};
const skipLaterSections = (state, failedStep) => {
  if (failedStep < 3) {
    state.credential.status = 'Skipped';
    state.measurements.forEach((item) => { item.actual = 'Skipped'; item.status = 'Skipped'; });
  }
  if (failedStep < 5) {
    state.measurements.forEach((item) => { item.actual = 'Skipped'; item.status = 'Skipped'; });
  }
  if (failedStep < 4) {
    state.permission.status = 'Skipped';
    state.permission.detail = 'Skipped';
    state.trust.status = 'Skipped';
    state.trust.confidence = 'Skipped';
    state.trust.attestation = 'Skipped';
    state.trust.membershipStatus = 'Skipped';
    state.attestation.result = 'Skipped';
    state.attestation.signatureStatus = 'Skipped';
    state.attestation.measurementStatus = 'Skipped';
    state.attestation.timestamp = 'Skipped';
  }
  state.policyChecks.forEach((item) => {
    if (item.status === 'Not evaluated' && item.step > failedStep) { item.status = 'Skipped'; item.detail = 'Skipped'; }
  });
};

// Atlas P1 fixture execution. Events model IF-01 but are never published as live feed evidence.
const atlasFixtures = msg.journeyAtlasFixtures || {};
const atlasCatalog = Object.values(atlasFixtures).map(({ id, label, summary, profile, variants, steps }) => ({ id, label, summary, profile, variants, steps: steps.map(s => modeResourceStep(s, id)) }));
function modeResourceStep(step,id) { return adapterConfig.mode === 'http-sample' && id === 'atlas-successful-call' && step.id === 'resource' ? Object.assign({},step,{name:'Participant sample response',source:'participant-sample',kind:'application_response',detail:'Real sample application response; security steps remain fixtures.'}) : step; }
const atlasSpecFor = (id, variant) => {
  const spec = atlasFixtures[id];
  if (!spec) return null;
  const copy = clone(spec);
  if (variant === 'presentation-required') {
    copy.profile = 'participant-unpresented';
    copy.reasonCode = 'POL-PRESENTATION-REQUIRED';
    copy.reason = 'Fixture guard-b refuses an unpresented credential and supplies a synthetic OID4VP presentation link; no verification, token issuance or channel step occurs.';
    copy.steps.slice(0, 3).forEach(step => { step.skip = true; });
    const last = copy.steps[3];
    last.reasonCode = 'POL-PRESENTATION-REQUIRED';
    last.ruleId = null;
    last.detail = copy.reason;
    copy.presentationLink = 'openid4vp://?request_uri=https%3A%2F%2Fzone-b.example%2Ffixture%2Fpresentation-request';
  }
  return copy;
};
const finishAtlas = (state, spec) => {
  state.terminal = true;
  state.result = spec.result;
  state.terminalStatus = spec.result === 'success' ? 'Granted' : 'Refused';
  state.tone = spec.result === 'success' ? 'success' : 'danger';
  state.outcome = spec.result === 'success' ? 'Fixture resource returned' : 'Fixture request refused';
  state.reasonCode = spec.reasonCode || null;
  state.reason = spec.reason;
  state.failedCheck = spec.result === 'success' ? null : clone(state.checks.find(c => c.status === 'Fail'));
  state.ruleId = spec.steps.find(s => s.ruleId)?.ruleId || null;
  state.presentationLink = spec.presentationLink || null;
  if (spec.result === 'success') state.fixtureResource = { resource: 'sample-report', action: 'read', report: { id: 'FACIS-P1-FIXTURE-REPORT', title: 'FACIS fixture report', content: 'Synthetic resource payload for the Successful call review journey.' } };
  addEvent(state, 'run.completed', state.outcome);
};
const evaluateAtlasStep = (state, spec, index) => {
  const step = spec.steps[index];
  const check = state.checks[index];
  if (step.skip) { check.status = 'Skipped'; check.detail = 'Not executed in presentation-required variant.'; return; }
  const at = timestamp();
  state.activeStep = index + 1;
  check.status = step.state === 'denied' || step.state === 'revoked' || step.state === 'refused' ? 'Fail' : 'Pass';
  check.evaluatedAt = at;
  check.detail = step.detail;
  const eventStates = step.states || [step.state];
  for (const eventState of eventStates) {
    const seq = state.sourceSequences[step.source] || 0;
    state.sourceSequences[step.source] = seq + 1;
    const payload = { state: eventState, detail: step.detail };
    if (step.reasonCode) payload.reason_code = step.reasonCode;
    if (step.ruleId) payload.rule_id = step.ruleId;
    const feedEvent = { run_id: state.runId, correlation_id: state.correlationId, seq, ts: at, source: step.source, kind: step.kind, payload };
    state.fixtureEvents.push(feedEvent);
    addEvidence(state, 'fixture.' + step.kind, step.detail, { fixture: true, blocked: check.status === 'Fail', source: step.source, kind: step.kind, state: eventState, reasonCode: step.reasonCode || null, ruleId: step.ruleId || null, contractEvent: feedEvent, fixtureRefs: step.fixtureRefs || [] });
  }
  addEvent(state, 'step.completed', step.name + ': ' + step.state + ' (fixture-only).');
  if (step.kind === 'credential_event') {
    state.credential.status = step.state === 'revoked' ? 'Revoked (fixture)' : 'Verified (fixture)';
    state.policyChecks[0] = { label: 'Credential verification', detail: step.detail, status: check.status };
  }
  if (step.state === 'issued') state.token = { state: 'issued', scope: 'read', keyBound: true, fixture: true };
  if (step.kind === 'channel_state') {
    state.connection.status = 'Attested (fixture)';
    state.trust.status = 'Fixture channel attested';
    state.attestation.result = 'Fixture channel attested';
    state.policyChecks[1] = { label: 'Attested channel', detail: step.detail, status: 'Pass' };
  }
  if (step.kind === 'decision') {
    state.permission.status = check.status;
    state.permission.detail = step.detail;
    state.policyChecks[2] = { label: 'Guard decision', detail: step.detail, status: check.status };
  }
};
const newAtlasState = (spec, variant, serviceScenario) => {
  const at = timestamp();
  const runId = uuid();
  return {
    sample: true, fixtureOnly: true, atlasPlan: true, fixtureSource: 'docs/scenarios.md + supplied XFSC/contract fixtures',
    adapterMode: adapterConfig.mode, transport: 'fixture', securitySource: 'fixture-only', serviceScenario, serviceRequest: null,
    ownerId: userId, runId, correlationId: uuid(), startedAt: at, updatedAt: at,
    scenario: spec.id, scenarioLabel: spec.label, summary: spec.summary, profile: spec.profile, variant,
    credentialToRevoke: spec.id === 'atlas-revoked-credential' ? spec.credential.id : null,
    seed: spec.id === 'atlas-revoked-credential' ? { fixture: true, statusListIndex: 42, revoked: true, resetRestoresSeed: true } : { fixture: true, revoked: false, resetRestoresSeed: true },
    sourceSequences: {}, fixtureEvents: [], fixtureRefs: spec.fixtureRefs, fixtureArtifacts: spec.fixtureArtifacts,
    tone: 'neutral', activeStep: 0, terminal: false, result: null, terminalStatus: null, reasonCode: null, failedCheck: null,
    outcome: 'Fixture journey in progress', reason: 'Only synthetic fixture results are evaluated.',
    checks: spec.steps.map((original, i) => { const s=modeResourceStep(original,spec.id); return ({ id: s.id, name: s.name, detail: 'Not evaluated', source: s.source, kind: s.kind, reasonCode: s.reasonCode || null, ruleId: s.ruleId || null, expectedState: s.state, status: 'Not evaluated', evaluatedAt: null, number: i + 1 }); }),
    credential: Object.assign(clone(spec.credential), { status: variant === 'presentation-required' ? 'Not presented (fixture)' : 'Not evaluated' }),
    permission: { name: 'read', detail: 'Not evaluated', status: 'Not evaluated' },
    trust: { zone: 'Zone A → Zone B', confidence: 'Not evaluated', attestation: 'Not evaluated', status: 'Not evaluated', membershipStatus: 'Not evaluated' },
    attestation: { method: 'Fixture channel state', result: 'Not evaluated', signatureStatus: 'Not evaluated', measurementStatus: 'Not evaluated', timestamp: 'Not evaluated' },
    connection: { protocol: 'Fixture channel', encryption: 'Not observed', endpoint: 'zone-b.example/resource (fixture)', status: 'Not opened' },
    token: { state: 'Not issued', scope: null, fixture: true }, measurements: [],
    policyChecks: ['Credential verification', 'Attested channel', 'Guard decision'].map(label => ({ label, detail: 'Not evaluated', status: 'Not evaluated' })),
    credentialUnlock: { initialRefusal: false, credentialIssued: false, credentialPresented: false, retrySuccess: false },
    evidence: [], events: [], notExecuted: spec.id === 'atlas-revoked-credential' ? ['Channel not opened', 'Guard not called', 'Resource not called'] : []
  };
};

if (!userId) return replyError('UNAUTHORIZED', 'Verified viewer identity is required for Journey state.');
if (!['status', 'start', 'next', 'reset'].includes(type)) {
  return replyError('UNKNOWN_OPERATION', 'Journey supports status, start, next, and reset.');
}

const states = flow.get('journeyStates') || {};
const histories = flow.get('journeyCommandHistory') || {};
const history = Array.isArray(histories[userId]) ? histories[userId] : [];
// Observer reads the latest shared demonstration without acquiring ownership.
const observed = msg.req.facis.role === 'ztd-observer' && type === 'status';
const observedState = observed ? Object.values(states).filter(state => state && state.sample === true && state.atlasPlan === true && typeof state.ownerId === 'string').sort((a, b) => Date.parse(b.updatedAt) - Date.parse(a.updatedAt))[0] : null;
let current = observed ? (observedState || null) : (states[userId] || null);

if (current && current.serviceRequest && current.serviceRequest.status === 'pending' && typeof current.serviceRequest.deadlineAt === 'number' && Date.now() > current.serviceRequest.deadlineAt) {
  const expiredAt = timestamp();
  const finalCheck = current.checks[current.checks.length - 1];
  finalCheck.status = 'Unavailable';
  finalCheck.evaluatedAt = expiredAt;
  current.result = 'unavailable';
  current.terminal = true;
  current.terminalStatus = 'Unavailable';
  current.reasonCode = 'SAMPLE_FLOW_DEADLINE_EXCEEDED';
  current.outcome = 'Sample service unavailable';
  current.reason = 'No Participant sample HTTPS response arrived before the Journey flow deadline.';
  current.connection.status = 'Unavailable';
  current.failedCheck = { id: 'final-service-request', name: 'Final Participant sample HTTPS request', status: 'Unavailable' };
  current.serviceRequest = Object.assign({}, current.serviceRequest, { status: 'completed', respondedAt: null, expiredAt, httpStatus: null, outcome: 'unavailable', reasonCode: 'SAMPLE_FLOW_DEADLINE_EXCEEDED', explanation: current.reason, safeData: {} });
  addEvidence(current, 'service.deadline.expired', current.reason, { sent: true, blocked: true, unavailable: true, requestId: current.serviceRequest.requestId, correlationId: current.serviceRequest.correlationId, requestedAt: current.serviceRequest.requestedAt, expiredAt, transport: 'Participant sample HTTPS', outcome: 'unavailable', reasonCode: 'SAMPLE_FLOW_DEADLINE_EXCEEDED' });
  addEvent(current, 'run.completed', current.outcome);
  states[current.ownerId] = current;
  flow.set('journeyStates', states);
}
if (type === 'status') return replyState(current);
if (adapterConfig.error) return replyError(adapterConfig.error.code, adapterConfig.error.detail);

const commandId = typeof data.commandId === 'string' ? data.commandId.trim() : '';
if (!commandId || commandId.length > 120) {
  return replyError('VALIDATION_FAILED', 'A commandId of 1 to 120 characters is required.');
}
if (history.includes(commandId)) {
  return replyError('DUPLICATE_COMMAND', 'This Journey command was already processed.');
}
history.push(commandId);
histories[userId] = history.slice(-100);
flow.set('journeyCommandHistory', histories);

if (type === 'start' && atlasFixtures[data.scenario]) {
  if (current && current.result === null) return replyError('RUN_IN_PROGRESS', 'Reset or finish the active Journey before starting another.');
  const definition = atlasFixtures[data.scenario];
  const variant = data.variant === undefined ? (definition.variants.length ? 'rule-deny' : null) : data.variant;
  if ((definition.variants.length && !definition.variants.includes(variant)) || (!definition.variants.length && variant !== null)) return replyError('INVALID_VARIANT', 'Select an allowed variant for this fixture journey.');
  const spec = atlasSpecFor(data.scenario, variant);
  if (data.profile !== undefined && data.profile !== spec.profile) return replyError('INVALID_PROFILE', 'The participant profile does not match this journey variant.');
  if (data.credentialToRevoke !== undefined && (spec.id !== 'atlas-revoked-credential' || data.credentialToRevoke !== spec.credential.id)) return replyError('INVALID_CREDENTIAL', 'Only the selected profile own fixture credential may be revoked.');
  const serviceScenario = typeof data.serviceScenario === 'string' ? data.serviceScenario : 'success';
  if (!serviceScenarios.includes(serviceScenario)) return replyError('INVALID_SERVICE_SCENARIO', 'Unsupported final sample service scenario.');
  current = newAtlasState(spec, variant, serviceScenario);
  if (variant === 'presentation-required') {
    current.fixtureArtifacts = { derivation: { fixture: true, source: 'docs/scenarios.md#wrong-scope', description: 'Synthetic unpresented profile and OID4VP link; no verified credential artifact selected.' } };
    current.notExecuted = ['Credential verification not executed', 'Token not issued', 'Channel not opened', 'Resource not called'];
  }
  addEvent(current, 'run.started', 'Atlas P1 fixture journey started from its selected seed.');
  const initial = variant === 'presentation-required' ? 3 : 0;
  if (initial === 3) for (let i = 0; i < 3; i++) evaluateAtlasStep(current, spec, i);
  evaluateAtlasStep(current, spec, initial);
  if (initial === spec.steps.length - 1) finishAtlas(current, spec);
  states[userId] = current; flow.set('journeyStates', states);
  return replyState(current, { commandId });
}

if (type === 'start') {
  if (current && current.result === null) {
    return replyError('RUN_IN_PROGRESS', 'Reset or finish the active Journey before starting another.');
  }
  const requested = typeof data.scenario === 'string' ? data.scenario : '';
  const scenarioId = aliases[requested] || requested;
  const fixture = scenarios[scenarioId];
  if (!fixture) {
    return replyError('INVALID_SCENARIO', 'Select one of the five registered sample Journey scenarios.');
  }
  const requestedServiceScenario = typeof data.serviceScenario === 'string' ? data.serviceScenario.trim().toLowerCase() : 'success';
  if (!serviceScenarios.includes(requestedServiceScenario)) {
    return replyError('INVALID_SERVICE_SCENARIO', 'Select success, denied, unavailable, error, or slow for the final sample service request.');
  }
  const startedAt = timestamp();
  current = {
    sample: true,
    fixtureSource: 'Journey sample scenario adapter',
    adapterMode: adapterConfig.mode,
    transport: adapterConfig.mode === 'http-sample' ? 'Participant sample HTTPS' : 'fixture',
    serviceScenario: requestedServiceScenario,
    serviceRequest: null,
    ownerId: userId,
    runId: uuid(),
    startedAt,
    updatedAt: startedAt,
    scenario: scenarioId,
    scenarioLabel: fixture.label,
    summary: fixture.summary,
    tone: fixture.tone,
    activeStep: 1,
    terminal: false,
    checks: CHECK_DEFINITIONS.map((check) => Object.assign({}, check, { status: 'Not evaluated', evaluatedAt: null })),
    policyChecks: pendingPolicyChecks(fixture),
    credential: Object.assign(clone(fixture.credential), { status: 'Not evaluated' }),
    measurements: fixture.measurements.map((item) => Object.assign(clone(item), { actual: 'Not evaluated', status: 'Not evaluated' })),
    permission: Object.assign(clone(fixture.permission), { detail: 'Not evaluated', status: 'Not evaluated' }),
    trust: Object.assign(clone(fixture.trust), { confidence: 'Not evaluated', attestation: 'Not evaluated', status: 'Not evaluated', membershipStatus: 'Not evaluated' }),
    attestation: Object.assign(clone(fixture.attestation), { result: 'Not evaluated', signatureStatus: 'Not evaluated', measurementStatus: 'Not evaluated', timestamp: 'Not evaluated' }),
    result: null,
    terminalStatus: null,
    reasonCode: null,
    failedCheck: null,
    outcome: 'Journey in progress',
    reason: 'Flow-owned local sample checks are being evaluated.',
    connection: Object.assign({ status: 'Requested' }, fixture.connection),
    credentialUnlock: { initialRefusal: false, credentialIssued: false, credentialPresented: false, retrySuccess: false },
    evidence: [],
    events: []
  };
  current.checks[0].status = 'Pass';
  current.checks[0].evaluatedAt = startedAt;
  addEvent(current, 'run.started', 'Sample Journey run started.');
  addEvent(current, 'step.completed', 'Resource request formed and sent to policy enforcement.');
  addEvidence(current, 'resource.requested', 'Participant requested the protected sample resource.', { sent: true, blocked: false });
  states[userId] = current;
  flow.set('journeyStates', states);
  return replyState(current, { commandId });
}

if (type === 'reset') {
  if (current) {
    if (typeof data.runId !== 'string' || data.runId !== current.runId) {
      return replyError('STALE_RUN', 'Reset requires the active runId.');
    }
    delete states[userId];
    flow.set('journeyStates', states);
  }
  return replyState(null, { commandId, reset: true });
}

if (!current) return replyError('NO_ACTIVE_RUN', 'Start a Journey before continuing.');
if (typeof data.runId !== 'string' || data.runId !== current.runId) {
  return replyError('STALE_RUN', 'The command runId does not match the active Journey.');
}
if (current.terminal || current.result !== null) {
  return replyError('INVALID_TRANSITION', 'The Journey is already complete.');
}
if (current.serviceRequest && current.serviceRequest.status === 'pending') {
  return replyError('REQUEST_IN_PROGRESS', 'The final Participant sample HTTPS request is still pending.');
}

if (current.atlasPlan) {
  const spec = atlasSpecFor(current.scenario, current.variant);
  if (!spec) return replyError('SCENARIO_UNAVAILABLE', 'The active Atlas fixture is unavailable.');
  const index = current.activeStep;
  if (index >= spec.steps.length) return replyError('INVALID_TRANSITION', 'No later fixture step exists.');
  if (index === spec.steps.length - 1 && spec.result === 'success' && current.adapterMode === 'http-sample') {
    current.activeStep = index + 1;
      const requestId = uuid();
      const correlationId = current.correlationId;
      const requestedAt = timestamp();
      current.checks[current.checks.length - 1].status = 'Pending';
      current.connection.status = 'Pending Participant sample HTTPS';
      current.outcome = 'Local sample HTTP request pending';
      current.reason = 'Waiting for a validated response from the configured Participant sample service.';
      const deadlineAt = Date.now() + adapterConfig.flowDeadlineMs;
      current.transport = 'Participant sample HTTPS';
      current.serviceRequest = { status: 'pending', requestId, correlationId, requestedAt, respondedAt: null, scenario: current.serviceScenario, deadlineAt, source:'sample', mode:'sample', tlsVerification:adapterConfig.skipTlsVerification?'skipped for sample endpoint':'enabled', tlsExceptionUntil:adapterConfig.tlsExceptionUntil };
      addEvidence(current, 'service.requested', 'Final sample-report request sent through Participant sample HTTPS.', { sent: true, blocked: false, requestId, correlationId, requestedAt, transport: 'Participant sample HTTPS' });
      states[userId] = current;
      flow.set('journeyStates', states);
      msg.journeyPending = { ownerId: userId, runId: current.runId, requestId, correlationId, commandId, requestedAt, deadlineAt };
      msg.method = 'POST';
      msg.requestTimeout = adapterConfig.participantTimeoutMs;
      msg.followRedirects = false;
      msg.rejectUnauthorized = !adapterConfig.skipTlsVerification;
      msg.url = adapterConfig.participantUrl.replace(/\/$/, '') + '/demo';
      msg.headers = { 'content-type': 'application/json', accept: 'application/json', 'x-request-id': requestId, 'x-correlation-id': correlationId };
      msg.payload = JSON.stringify({ resource: 'sample-report', action: 'read', scenario: current.serviceScenario, requestId, correlationId });
      const pendingState = publicState(current);
      const responseMsg = Object.assign({}, msg, { payload: { ok: true, data: { sample: true, availability: 'available', adapterMode: 'http-sample', transport: 'Participant sample HTTPS', protocol: 'journey.sample/v1', supportedCommands: ['status', 'start', 'next', 'reset'], state: pendingState, commandId } } });
      delete responseMsg.url; delete responseMsg.method; delete responseMsg.headers; delete responseMsg.requestTimeout;
      return [responseMsg, msg];
  }
  evaluateAtlasStep(current, spec, index);
  if (index === spec.steps.length - 1) finishAtlas(current, spec);
  states[userId] = current; flow.set('journeyStates', states);
  return replyState(current, { commandId });
}

const fixture = scenarios[current.scenario];
if (!fixture) return replyError('SCENARIO_UNAVAILABLE', 'The active sample scenario adapter is unavailable.');
const step = current.activeStep + 1;
if (step > CHECK_DEFINITIONS.length) return replyError('INVALID_TRANSITION', 'No later Journey step exists.');
current.activeStep = step;
const check = current.checks[step - 1];
const failed = fixture.stopStep === step;
check.status = failed ? fixture.failStatus : 'Pass';
check.evaluatedAt = timestamp();

if (step === 2) {
  current.connection.status = failed ? 'Unavailable' : 'Refused';
  if (failed) {
    addEvidence(current, 'connection.unavailable', fixture.reason, { sent: true, blocked: true, unavailable: true });
  } else {
    current.credentialUnlock.initialRefusal = true;
    addEvidence(current, 'access.initially-refused', 'Initial request refused because the required credential is missing.', { sent: true, blocked: true, initialRefusal: true });
  }
}
if (step === 3) {
  current.credential = clone(fixture.credential);
  revealPolicyChecks(current, fixture, 3);
  current.credentialUnlock.credentialIssued = true;
  current.credentialUnlock.credentialPresented = true;
  current.connection.status = failed ? 'Blocked' : 'Verifying';
  addEvidence(current, 'credential.issued', 'OCM W-Stack issued the sample participant credential.', { sample: true });
  addEvidence(current, 'credential.presented', 'The sample credential was presented with the retried request.', { sample: true, credentialStatus: fixture.credential.status });
}
if (step === 4) {
  current.trust = clone(fixture.trust);
  current.attestation = clone(fixture.attestation);
  current.permission = clone(fixture.permission);
  revealPolicyChecks(current, fixture, 4);
  addEvidence(current, 'trust.evaluated', 'Sample trust-zone, attestation and permission checks were evaluated.', { trust: clone(fixture.trust), attestation: clone(fixture.attestation), permission: clone(fixture.permission) });
  if (!failed) current.connection.status = 'Verifying';
}
if (step === 5) {
  current.measurements = clone(fixture.measurements);
  current.attestation.measurementStatus = failed ? 'Fail' : 'Pass';
  current.attestation.result = failed ? 'Measurement failed' : 'Verified';
  revealPolicyChecks(current, fixture, 5);
  addEvidence(current, 'measurements.evaluated', 'Local sample TEE and runtime values were compared with sample expected values.', { measurements: clone(fixture.measurements), signatureStatus: current.attestation.signatureStatus, measurementStatus: current.attestation.measurementStatus });
  if (!failed) current.connection.status = 'Verifying';
}

if (failed) {
  for (let index = step; index < current.checks.length; index += 1) {
    current.checks[index].status = 'Skipped';
    current.checks[index].evaluatedAt = check.evaluatedAt;
  }
  skipLaterSections(current, step);
  current.result = fixture.result;
  current.terminal = true;
  current.terminalStatus = fixture.terminalStatus;
  current.reasonCode = fixture.reasonCode;
  const failedPolicyCheck = fixture.policyChecks.find((item) => item.step === step && item.status === fixture.failStatus);
  current.failedCheck = failedPolicyCheck ? { id: failedPolicyCheck.label.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/(^-|-$)/g, ''), name: failedPolicyCheck.label, status: failedPolicyCheck.status } : { id: check.id, name: check.name, status: check.status };
  current.outcome = fixture.outcome;
  current.reason = fixture.reason;
  current.connection.status = fixture.id === 'service-unavailable' ? 'Unavailable' : 'Blocked';
  addEvent(current, 'check.failed', check.name + ': ' + fixture.reason);
  addEvent(current, 'run.completed', fixture.outcome);
  const failureData = { sent: false, blocked: true, failedCheck: clone(current.failedCheck), reasonCode: current.reasonCode, terminalStatus: current.terminalStatus };
  if (fixture.id === 'measurement-mismatch') failureData.measurements = clone(fixture.measurements);
  if (fixture.id === 'service-unavailable') failureData.unavailable = true;
  addEvidence(current, fixture.id === 'service-unavailable' ? 'decision.unavailable' : 'access.refused', fixture.reason, failureData);
} else {
  if (!(step === CHECK_DEFINITIONS.length && adapterConfig.mode === 'http-sample')) addEvent(current, 'step.completed', check.name + ' passed.');
  if (step === CHECK_DEFINITIONS.length) {
    if (adapterConfig.mode === 'http-sample') {
      const requestId = uuid();
      const correlationId = current.runId;
      const requestedAt = timestamp();
      current.checks[step - 1].status = 'Pending';
      current.connection.status = 'Pending Participant sample HTTPS';
      current.outcome = 'Local sample HTTP request pending';
      current.reason = 'Waiting for a validated response from the configured Participant sample service.';
      const deadlineAt = Date.now() + adapterConfig.flowDeadlineMs;
      current.transport = 'Participant sample HTTPS';
      current.serviceRequest = { status: 'pending', requestId, correlationId, requestedAt, respondedAt: null, scenario: current.serviceScenario, deadlineAt, source:'sample', mode:'sample', tlsVerification:adapterConfig.skipTlsVerification?'skipped for sample endpoint':'enabled', tlsExceptionUntil:adapterConfig.tlsExceptionUntil };
      addEvidence(current, 'service.requested', 'Final sample-report request sent through Participant sample HTTPS.', { sent: true, blocked: false, requestId, correlationId, requestedAt, transport: 'Participant sample HTTPS' });
      states[userId] = current;
      flow.set('journeyStates', states);
      msg.journeyPending = { ownerId: userId, runId: current.runId, requestId, correlationId, commandId, requestedAt, deadlineAt };
      msg.method = 'POST';
      msg.requestTimeout = adapterConfig.participantTimeoutMs;
      msg.followRedirects = false;
      msg.rejectUnauthorized = !adapterConfig.skipTlsVerification;
      msg.url = adapterConfig.participantUrl.replace(/\/$/, '') + '/demo';
      msg.headers = { 'content-type': 'application/json', accept: 'application/json', 'x-request-id': requestId, 'x-correlation-id': correlationId };
      msg.payload = JSON.stringify({ resource: 'sample-report', action: 'read', scenario: current.serviceScenario, requestId, correlationId });
      const pendingState = publicState(current);
      const responseMsg = Object.assign({}, msg, { payload: { ok: true, data: { sample: true, availability: 'available', adapterMode: 'http-sample', transport: 'Participant sample HTTPS', protocol: 'journey.sample/v1', supportedCommands: ['status', 'start', 'next', 'reset'], state: pendingState, commandId } } });
      delete responseMsg.url; delete responseMsg.method; delete responseMsg.headers; delete responseMsg.requestTimeout;
      return [responseMsg, msg];
    }
    current.result = fixture.result;
    current.terminal = true;
    current.terminalStatus = fixture.terminalStatus;
    current.reasonCode = fixture.reasonCode;
    current.failedCheck = null;
    current.outcome = fixture.outcome;
    current.reason = fixture.reason;
    current.connection.status = 'Fixture result';
    current.credentialUnlock.retrySuccess = true;
    addEvidence(current, 'request.retried', 'The fixture request was retried after credential presentation.', { sent: true, blocked: false, transport: 'fixture' });
    addEvidence(current, 'access.granted', fixture.reason, { sent: true, blocked: false, initialRefusalPreserved: current.credentialUnlock.initialRefusal, reasonCode: current.reasonCode, terminalStatus: current.terminalStatus, transport: 'fixture' });
    addEvent(current, 'run.completed', fixture.outcome);
  }
}

states[userId] = current;
flow.set('journeyStates', states);
return replyState(current, { commandId });