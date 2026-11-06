delete msg.journeyServiceResult;
const pending = msg.journeyPending;
let parseFailed = false;
const invalid = (detail) => { msg.journeyServiceResult = { outcome: 'error', reasonCode: 'SAMPLE_INVALID_RESPONSE', explanation: detail, timestamp: new Date().toISOString(), safeData: {}, transportStatus: Number(msg.statusCode) || null }; };
let raw = msg.payload;
if (Buffer.isBuffer(raw)) raw = raw.toString('utf8');
if (Number(msg.statusCode)===401) { msg.journeyServiceResult={outcome:'error',reasonCode:'SAMPLE_PARTICIPANT_AUTH_REQUIRED',explanation:'Participant rejected the server-side Basic Auth credential.',timestamp:new Date().toISOString(),safeData:{},transportStatus:401}; }
if (msg.journeyServiceResult) { /* Preserve the safe authentication failure. */ } else if (typeof raw !== 'string' || Buffer.byteLength(raw, 'utf8') === 0 || Buffer.byteLength(raw, 'utf8') > 65536) {
  invalid('The Participant sample service returned an empty or oversized response.');
} else {
  let body;
  try { body = JSON.parse(raw); } catch (_) { parseFailed = true; invalid('The Participant sample service returned malformed JSON.'); }
  if (!parseFailed) {
    if (body === null || typeof body !== 'object' || Array.isArray(body)) {
      invalid('The Participant sample service response must be a JSON object.');
    } else {
      const status = Number(msg.statusCode);
      const statusMatches = (body.outcome === 'success' && status === 200) || (body.outcome === 'denied' && status === 403) || (body.outcome === 'unavailable' && [503, 504].includes(status)) || (body.outcome === 'error' && [400, 404, 405, 502].includes(status));
      const reasons = {
        success: ['SAMPLE_ACCESS_GRANTED', 'SAMPLE_RESOURCE_RETURNED', 'SAMPLE_SLOW_RESOURCE_RETURNED', 'SAMPLE_ALTERNATIVE_RESOURCE_RETURNED', 'SAMPLE_ALTERNATIVE_SLOW_RESOURCE_RETURNED'],
        denied: ['SAMPLE_ACCESS_DENIED'],
        unavailable: ['SAMPLE_DEPENDENCY_UNAVAILABLE', 'SAMPLE_RESOURCE_UNAVAILABLE', 'SAMPLE_REQUEST_TIMEOUT', 'SAMPLE_CONNECTION_FAILURE', 'SAMPLE_ADAPTER_NO_RESPONSE', 'SAMPLE_REQUEST_CANCELLED'],
        error: ['SAMPLE_INVALID_REQUEST', 'SAMPLE_METHOD_NOT_ALLOWED', 'SAMPLE_ADAPTER_ERROR', 'SAMPLE_UNSUPPORTED_SCENARIO', 'SAMPLE_RESOURCE_ERROR', 'SAMPLE_UNKNOWN_SCENARIO', 'SAMPLE_RESOURCE_NOT_FOUND', 'SAMPLE_REQUEST_TOO_LARGE', 'SAMPLE_ADAPTER_FAILURE']
      };
      const validTimestamp = typeof body.timestamp === 'string' && Number.isFinite(Date.parse(body.timestamp));
      const validExplanation = typeof body.explanation === 'string' && body.explanation.trim().length > 0 && body.explanation.length <= 500;
      const validIdentity = pending && body.requestId === pending.requestId && body.correlationId === pending.correlationId;
      const validContract = body.source === 'sample' && body.mode === 'sample' && reasons[body.outcome]?.includes(body.reasonCode) && statusMatches && validTimestamp && validExplanation;
      const data = body.safeData;
      const validDataObject = data !== null && typeof data === 'object' && !Array.isArray(data);
      let validSafeData = false;
      if (validDataObject && body.outcome === 'success') {
        const report = data.report;
        const validReport = report !== null && typeof report === 'object' && !Array.isArray(report) && Object.keys(report).length === 3 && ['id', 'title', 'content'].every((key) => typeof report[key] === 'string' && report[key].trim().length > 0 && report[key].length <= 500);
        validSafeData = Object.keys(data).length === 3 && data.resource === 'sample-report' && data.action === 'read' && validReport;
      } else if (validDataObject && body.outcome !== 'success') {
        validSafeData = Object.keys(data).length === 0;
      }
      if (!validIdentity || !validContract || !validSafeData) {
        invalid('The Participant sample service response did not match the expected identifiers, safe data, or documented sample contract.');
      } else {
        const safeData = body.outcome === 'success' ? { resource: data.resource, action: data.action, report: { id: data.report.id, title: data.report.title, content: data.report.content } } : {};
        msg.journeyServiceResult = { outcome: body.outcome, reasonCode: body.reasonCode, explanation: body.explanation.trim(), timestamp: body.timestamp, safeData, transportStatus: status };
      }
    }
  }
}
if (!msg.journeyServiceResult) invalid('The Participant sample service response could not be validated.');
delete msg.payload;
delete msg.url;
delete msg.headers;
delete msg.responseUrl;
delete msg.cookies; delete msg.responseCookies; delete msg.rejectUnauthorized; delete msg.followRedirects;
return msg;