import { evaluateFixtureResource } from './protected-resource-fixture.mjs';

const contracts = Object.freeze({
  'participant-backend': 'facis.sample-participant/v1',
  'protected-resource': 'facis.sample-resource/v1'
});
const outcomes = new Set(['success', 'denied', 'unavailable', 'error']);
const keys = (value, names) => value && typeof value === 'object' && !Array.isArray(value) && Object.keys(value).every(k => names.includes(k));
const id = value => typeof value === 'string' && /^[A-Za-z0-9._:-]{1,128}$/.test(value);
class ReplacementError extends Error {
  constructor(code, stage) { super(code); this.code = code; this.stage = stage; }
}
const fail = (code, stage) => { throw new ReplacementError(code, stage); };
function normalizeRequest(input) {
  if (!keys(input, ['requestId','correlationId','resource','action','scenario']) || !id(input.requestId) || !id(input.correlationId) || input.resource !== 'sample-report' || input.action !== 'read' || !['success','denied','unavailable','error'].includes(input.scenario)) fail('REPLACEMENT_REQUEST_INVALID', 'request');
  return {...input};
}
function configuration(value, role) {
  if (!keys(value, ['kind','role','contract','baseURL']) || value.role !== role || value.contract !== contracts[role]) fail('REPLACEMENT_INTERFACE_INVALID', role);
  if (value.kind === 'real') fail('REPLACEMENT_TARGET_NOT_APPROVED', role);
  if (!['mock','sample-http'].includes(value.kind)) fail('REPLACEMENT_KIND_UNSUPPORTED', role);
  if (value.kind === 'mock') { if (value.baseURL !== undefined) fail('REPLACEMENT_CONFIG_INVALID', role); return {...value}; }
  let url; try { url = new URL(value.baseURL); } catch { fail('REPLACEMENT_CONFIG_INVALID', role); }
  // This preparation adapter can only call disposable local sample services.
  if (url.protocol !== 'http:' || !['127.0.0.1','[::1]'].includes(url.hostname) || url.username || url.password || url.search || url.hash || url.pathname !== '/') fail('REPLACEMENT_SAMPLE_ENDPOINT_INVALID', role);
  return {...value, baseURL:url.origin};
}
async function jsonCall(url, method, body, signal, stage, trace = {}) {
  let response, size=0, chunks=[];
  try {
    response = await fetch(url, {method,redirect:'manual',signal,headers:{accept:'application/json',...trace,...(body?{'content-type':'application/json'}:{})},body:body?JSON.stringify(body):undefined});
    if (response.body) for await (const chunk of response.body) { size+=chunk.byteLength; if(size>65536) fail('REPLACEMENT_RESPONSE_TOO_LARGE',stage); chunks.push(chunk); }
  } catch(error) {
    if(error instanceof ReplacementError) throw error;
    fail(signal.aborted?'REPLACEMENT_TIMEOUT':'REPLACEMENT_UNAVAILABLE',stage);
  }
  if (response.status>=300 && response.status<400) fail('REPLACEMENT_REDIRECT_REFUSED',stage);
  let data; try { data=JSON.parse(Buffer.concat(chunks).toString('utf8')); } catch { fail('REPLACEMENT_RESPONSE_INVALID',stage); }
  return {status:response.status,data};
}
function participantResult(data, request) {
  if (!keys(data,['contract','role','mode','outcome','reasonCode','request']) || data.contract!==contracts['participant-backend'] || data.role!=='participant-backend' || data.mode!=='sample') fail('REPLACEMENT_RESPONSE_INVALID','participant-backend');
  if (data.outcome!=='ready') fail('REPLACEMENT_PARTICIPANT_REFUSED','participant-backend');
  const next=normalizeRequest(data.request);
  if (Object.keys(request).some(k=>next[k]!==request[k])) fail('REPLACEMENT_REQUEST_MISMATCH','participant-backend');
  return next;
}
function resourceResult(data, request, status) {
  if (!keys(data,['contract','role','mode','requestId','correlationId','outcome','reasonCode','safeData']) || data.contract!==contracts['protected-resource'] || data.role!=='protected-resource' || data.mode!=='sample' || data.requestId!==request.requestId || data.correlationId!==request.correlationId || !outcomes.has(data.outcome) || !/^[A-Z][A-Z0-9_]{1,79}$/.test(data.reasonCode || '')) fail('REPLACEMENT_RESPONSE_INVALID','protected-resource');
  const expectedStatus={success:200,denied:403,unavailable:503,error:502}[data.outcome];
  if(status!==expectedStatus) fail('REPLACEMENT_STATUS_MISMATCH','protected-resource');
  if(data.outcome==='success') {
    const safe=data.safeData, report=safe?.report;
    if (!keys(safe,['resource','action','report']) || safe.resource!==request.resource || safe.action!==request.action || !keys(report,['id','title','content']) || !['id','title','content'].every(k=>typeof report[k]==='string'&&report[k].trim()&&report[k].length<=500)) fail('REPLACEMENT_RESPONSE_INVALID','protected-resource');
  } else if(!keys(data.safeData,[]) || Object.keys(data.safeData).length) fail('REPLACEMENT_REFUSAL_LEAK','protected-resource');
  return data;
}
export const replacementContracts = contracts;
export function sampleResourceResponse(request) {
  request=normalizeRequest(request);
  const caseId={success:'reader',denied:'unauthorized-role',unavailable:'dependency-unavailable',error:'invalid'}[request.scenario];
  const result=evaluateFixtureResource({caseId,requestId:request.requestId,correlationId:request.correlationId});
  return {contract:contracts['protected-resource'],role:'protected-resource',mode:'sample',requestId:request.requestId,correlationId:request.correlationId,outcome:request.scenario==='error'?'error':result.outcome,reasonCode:request.scenario==='error'?'SAMPLE_REPLACEMENT_ERROR':result.reasonCode,safeData:result.safeData};
}
export function sampleParticipantResponse(request) {
  return {contract:contracts['participant-backend'],role:'participant-backend',mode:'sample',outcome:'ready',request:normalizeRequest(request)};
}
export async function createReplacementJourney(config) {
  if (!keys(config,['participant','resource','timeoutMs'])) fail('REPLACEMENT_CONFIG_INVALID','configuration');
  // Validate both configurations before even preflighting either service.
  const participant=configuration(config.participant,'participant-backend');
  const resource=configuration(config.resource,'protected-resource');
  const timeoutMs=config.timeoutMs ?? 3000;
  if(!Number.isInteger(timeoutMs)||timeoutMs<1||timeoutMs>60000) fail('REPLACEMENT_CONFIG_INVALID','configuration');
  const preflightSignal=AbortSignal.timeout(timeoutMs);
  for(const target of [participant,resource]) if(target.kind==='sample-http') {
    const {status,data}=await jsonCall(target.baseURL+'/interface','GET',undefined,preflightSignal,target.role);
    if(status!==200 || !keys(data,['contract','role','mode','method','path']) || data.contract!==target.contract || data.role!==target.role || data.mode!=='sample' || data.method!=='POST' || data.path!=='/execute') fail('REPLACEMENT_INTERFACE_INVALID',target.role);
  }
  // Copy configuration so a caller cannot redirect validated adapters later.
  return Object.freeze({async run(input) {
    const request=normalizeRequest(input),signal=AbortSignal.timeout(timeoutMs),events=[];
    const trace={'x-request-id':request.requestId,'x-correlation-id':request.correlationId};
    const emit=(event,role,detail={})=>events.push({event,role,mode:'sample',securitySource:'fixture-only',requestId:request.requestId,correlationId:request.correlationId,timestamp:new Date().toISOString(),...detail});
    let stage='participant-backend';
    try {
      emit('replacement.requested',stage,{adapter:participant.kind});
      const prepared=participant.kind==='mock'?{status:200,data:sampleParticipantResponse(request)}:await jsonCall(participant.baseURL+'/execute','POST',request,signal,stage,trace);
      if(prepared.status!==200) fail('REPLACEMENT_PARTICIPANT_REFUSED',stage);
      const forwarded=participantResult(prepared.data,request);
      emit('replacement.prepared',stage,{adapter:participant.kind});stage='protected-resource';
      emit('replacement.requested',stage,{adapter:resource.kind});
      const result=resource.kind==='mock'?{data:sampleResourceResponse(forwarded),status:{success:200,denied:403,unavailable:503,error:502}[forwarded.scenario]}:await jsonCall(resource.baseURL+'/execute','POST',forwarded,signal,stage,trace);
      const checked=resourceResult(result.data,request,result.status);
      emit('replacement.responded',stage,{adapter:resource.kind,outcome:checked.outcome,reasonCode:checked.reasonCode});
      return {ok:checked.outcome==='success',mode:'sample',securitySource:'fixture-only',requestId:request.requestId,correlationId:request.correlationId,outcome:checked.outcome,reasonCode:checked.reasonCode,safeData:checked.safeData,events};
    } catch(error) {
      const reasonCode=error instanceof ReplacementError?error.code:'REPLACEMENT_UNAVAILABLE';
      emit('replacement.refused',stage,{reasonCode});
      return {ok:false,mode:'sample',securitySource:'fixture-only',requestId:request.requestId,correlationId:request.correlationId,outcome:'error',reasonCode,safeData:{},events};
    }
  }});
}
