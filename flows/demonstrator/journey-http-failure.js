msg.journeyServiceResult = { outcome: 'unavailable', reasonCode: 'SAMPLE_CONNECTION_FAILURE', explanation: 'The configured Participant sample service was unavailable.', timestamp: new Date().toISOString(), safeData: {}, transportStatus: null };
delete msg.error;
delete msg.payload;
delete msg.url;
delete msg.headers;
delete msg.cookies; delete msg.responseCookies; delete msg.rejectUnauthorized; delete msg.followRedirects; return msg;