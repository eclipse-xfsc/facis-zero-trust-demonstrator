package atls_test

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/Fraunhofer-AISEC/cmc/attestedtls"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/atls"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/atls/atlstest"
)

var modes = []struct {
	mode           atls.Mode
	cmc            attestedtls.AttestSelect
	server, client bool // which ends present a report
}{
	{atls.ModeMutual, attestedtls.Attest_Mutual, true, true},
	{atls.ModeServer, attestedtls.Attest_Server, true, false},
	{atls.ModeClient, attestedtls.Attest_Client, false, true},
}

func withMode(cfg atls.Config, m atls.Mode) atls.Config { cfg.Mode = m; return cfg }

// ZT-29: a handshake completes in each mode, through the zones' cmcd over gRPC. Only the ends the
// mode names produce a report, only their peers verify one, and an end that attests nothing
// reports its peer as not attested.
func TestHandshakeInEachMode(t *testing.T) {
	for _, m := range modes {
		t.Run(m.mode.String(), func(t *testing.T) {
			f := newFixture(t) // server zone a, client zone b
			cli, srv := pair(t, withMode(f.a.Config(t, f.b), m.mode), withMode(f.b.Config(t, f.a), m.mode))
			want := func(attested bool) atls.Verdict {
				if attested {
					return atls.VerdictSuccess
				}
				return atls.VerdictNotAttested
			}
			for _, end := range []struct {
				name     string
				conn     *atls.Conn
				attested bool
			}{{"client's view of the server", cli, m.server}, {"server's view of the client", srv, m.client}} {
				p := end.conn.Peer()
				if p.Verdict != want(end.attested) || p.AttestedAt.IsZero() == end.attested || p.PeerID == "" || p.ValidUntil.IsZero() ||
					(!end.attested && len(p.Measurements) > 0) {
					t.Errorf("%s: verdict %q, attested at %v, %d measurements, PeerID %q, ValidUntil %v",
						end.name, p.Verdict, p.AttestedAt, len(p.Measurements), p.PeerID, p.ValidUntil)
				}
			}
			calls := func(attested bool) int64 {
				if attested {
					return 1
				}
				return 0
			}
			if attest, verify := f.a.CmcdCalls(); attest != calls(m.server) || verify != calls(m.client) {
				t.Errorf("server's cmcd: %d reports, %d verifications", attest, verify)
			}
			if attest, verify := f.b.CmcdCalls(); attest != calls(m.client) || verify != calls(m.server) {
				t.Errorf("client's cmcd: %d reports, %d verifications", attest, verify)
			}
			if len(cli.Binding()) != 32 || string(cli.Binding()) != string(srv.Binding()) {
				t.Error("the ends disagree on the channel binding")
			}
			exchange(t, cli, srv, "ping in "+m.mode.String())
			exchange(t, srv, cli, "pong")
		})
	}
}

// Two ends configured with different modes are refused at both ends, in each of the six orders.
func TestModesMustMatch(t *testing.T) {
	for _, server := range modes {
		for _, client := range modes {
			if server.mode == client.mode {
				continue
			}
			t.Run(server.mode.String()+" server, "+client.mode.String()+" client", func(t *testing.T) {
				f := newFixture(t)
				ln := listen(t, withMode(f.a.Config(t, f.b), server.mode))
				acc := acceptOne(ln, 15*time.Second)
				_, err := dial(t, ln.Addr().String(), withMode(f.b.Config(t, f.a), client.mode))
				assertRefusal(t, err, atls.ErrAttestModeMismatch)
				assertRefusal(t, (<-acc).err, atls.ErrAttestModeMismatch)
			})
		}
	}
}

// A PeerVerifier on an end that does not attest its peer, and an unknown mode, are configuration
// errors.
func TestModeConfiguration(t *testing.T) {
	f := newFixture(t)
	verifier := atls.PeerVerifierFunc(func(_ context.Context, _ atls.PeerAttestation) error { return nil })
	server := withMode(f.a.Config(t, f.b), atls.ModeServer)
	server.PeerVerifier = verifier
	if _, err := atls.Listen("127.0.0.1:0", server); !errors.Is(err, atls.ErrConfig) {
		t.Errorf("verifier on a server that attests no client: %v", err)
	}
	client := withMode(f.b.Config(t, f.a), atls.ModeClient)
	client.PeerVerifier = verifier
	if _, err := atls.Dial(t.Context(), "127.0.0.1:1", client); !errors.Is(err, atls.ErrConfig) {
		t.Errorf("verifier on a client that attests no server: %v", err)
	}
	if _, err := atls.Listen("127.0.0.1:0", withMode(f.a.Config(t, f.b), atls.Mode(7))); !errors.Is(err, atls.ErrConfig) {
		t.Errorf("unknown mode: %v", err)
	}
}

// ZT-29 and ZT-30 on the wire: the server's request is machine-readable JSON stating its mode;
// its response carries a report exactly when the mode makes the server present one; and what
// the request and the response carry besides the report is smaller than the report.
func TestModeOnTheWire(t *testing.T) {
	for _, m := range modes {
		t.Run(m.mode.String(), func(t *testing.T) {
			f := newFixture(t)
			ln := listen(t, withMode(f.a.Config(t, f.b), m.mode))
			acc := acceptOne(ln, 15*time.Second)
			c := fakeTLSClient(t, ln.Addr().String(), f.b)

			sendMsg(t, c, attestedtls.AtlsHandshakeRequest{Version: atlsVersion, Attest: m.cmc})
			rawReq := recvMsg(t, c)
			var req map[string]json.RawMessage
			if err := json.Unmarshal(rawReq, &req); err != nil {
				t.Fatalf("the request is not JSON: %v", err)
			}
			var stated attestedtls.AttestSelect
			if err := json.Unmarshal(req["attest"], &stated); err != nil || stated != m.cmc {
				t.Fatalf("the request states mode %s (%v), want %s", req["attest"], err, m.cmc)
			}

			var own []byte
			if m.client {
				own = f.b.Report(t, bindNonce(exporter(t, c), f.b.Cert.Certificate[0]))
			}
			sendMsg(t, c, attestedtls.AtlsHandshakeResponse{Version: atlsVersion, Report: own})
			rawResp := recvMsg(t, c)
			var resp attestedtls.AtlsHandshakeResponse
			if err := json.Unmarshal(rawResp, &resp); err != nil {
				t.Fatalf("the response is not JSON: %v", err)
			}
			if (len(resp.Report) > 0) != m.server || resp.Error != "" {
				t.Fatalf("response: %d report bytes, error %q", len(resp.Report), resp.Error)
			}
			sendMsg(t, c, attestedtls.AtlsHandshakeComplete{Version: atlsVersion, Success: true})
			recvMsg(t, c)
			if a := <-acc; a.err != nil {
				t.Fatalf("the server refused the fake client: %v", a.err)
			}

			checkSizes(t, "server", rawReq, own, rawResp, resp.Report)
		})
	}
}

// requestBound and emptyResponseBound bound what a message may carry when no report sets the
// limit: a request no report answers, and a response that presents none (ZT-30's empty report).
const (
	requestBound       = 128
	emptyResponseBound = 64
)

// checkSizes applies the size rule of ZT-29 and ZT-30 to one end's messages: its request against
// the report that answers it, its response besides its report against that report.
func checkSizes(t *testing.T, end string, request, answeringReport, response, ownReport []byte) {
	t.Helper()
	switch {
	case len(answeringReport) > 0 && len(request) >= len(answeringReport):
		t.Errorf("%s: request %d bytes, the report answering it %d bytes", end, len(request), len(answeringReport))
	case len(answeringReport) == 0 && len(request) > requestBound:
		t.Errorf("%s: request %d bytes with no report answering it", end, len(request))
	}
	rest := len(withoutReport(t, response))
	switch {
	case len(ownReport) > 0 && rest >= len(ownReport):
		t.Errorf("%s: response besides its report %d bytes, report %d bytes", end, rest, len(ownReport))
	case len(ownReport) == 0 && rest > emptyResponseBound:
		t.Errorf("%s: a response without a report carries %d bytes", end, rest)
	}
}

// withoutReport is the message with its report member removed, every other member kept.
func withoutReport(t *testing.T, raw []byte) []byte {
	t.Helper()
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("not JSON: %v", err)
	}
	delete(m, "report")
	out, _ := json.Marshal(m)
	return out
}

// ZT-29 and ZT-30 from the client: a real dialer's request states its mode, its response carries
// a report exactly when the mode makes the client present one, and the rest of each message is
// smaller than that report.
func TestClientModeOnTheWire(t *testing.T) {
	for _, m := range modes {
		t.Run(m.mode.String(), func(t *testing.T) {
			f := newFixture(t)
			got := make(chan [3][]byte, 1)
			addr := fakeTLSServer(t, f.a, func(c *tls.Conn) {
				req := recvMsg(t, c)
				sendMsg(t, c, attestedtls.AtlsHandshakeRequest{Version: atlsVersion, Attest: m.cmc})
				resp := recvMsg(t, c)
				// The report this server would answer the client's request with, bound to this
				// session and to the server's certificate.
				var answer []byte
				if m.server {
					answer = f.a.Report(t, bindNonce(exporter(t, c), f.a.Cert.Certificate[0]))
				}
				got <- [3][]byte{req, resp, answer}
				_ = c.Close()
			})
			_, _ = dial(t, addr, withMode(f.b.Config(t, f.a), m.mode))
			var msgs [3][]byte
			select {
			case msgs = <-got:
			case <-time.After(15 * time.Second):
				t.Fatal("the fake server captured no request and response")
			}
			var req map[string]json.RawMessage
			var resp attestedtls.AtlsHandshakeResponse
			if json.Unmarshal(msgs[0], &req) != nil || json.Unmarshal(msgs[1], &resp) != nil {
				t.Fatalf("not JSON: %s / %s", msgs[0], msgs[1])
			}
			var stated attestedtls.AttestSelect
			if raw, ok := req["attest"]; !ok || json.Unmarshal(raw, &stated) != nil || stated != m.cmc {
				t.Fatalf("client request states mode %s, want %s", req["attest"], m.cmc)
			}
			if (len(resp.Report) > 0) != m.client || resp.Error != "" {
				t.Fatalf("client response: %d report bytes, error %q", len(resp.Report), resp.Error)
			}
			checkSizes(t, "client", msgs[0], msgs[2], msgs[1], resp.Report)
		})
	}
}

// Two CMC v0.9.15 limitations of the one-sided modes, pinned so that a CMC change is noticed
// (docs/attested-channel.md, N10 and N11).
func TestOneSidedModeLimitations(t *testing.T) {
	// N10: a report the mode does not ask for is ignored, not refused.
	t.Run("unsolicited report", func(t *testing.T) {
		f := newFixture(t)
		ln := listen(t, withMode(f.a.Config(t, f.b), atls.ModeServer))
		acc := acceptOne(ln, 15*time.Second)
		c := fakeTLSClient(t, ln.Addr().String(), f.b)
		sendMsg(t, c, attestedtls.AtlsHandshakeRequest{Version: atlsVersion, Attest: attestedtls.Attest_Server})
		recvMsg(t, c)
		sendMsg(t, c, attestedtls.AtlsHandshakeResponse{Version: atlsVersion, Report: f.b.Report(t, bindNonce(exporter(t, c), f.b.Cert.Certificate[0]))})
		recvMsg(t, c)
		sendMsg(t, c, attestedtls.AtlsHandshakeComplete{Version: atlsVersion, Success: true})
		recvMsg(t, c)
		a := <-acc
		if a.err != nil || a.conn.Peer().Verdict != atls.VerdictNotAttested {
			t.Fatalf("CMC now treats an unsolicited report differently: %v", a.err)
		}
	})
	// N11: when this end's own report cannot be produced, CMC tells only the peer. An honest peer
	// refuses, and so the channel fails at both ends; a peer that claims success anyway gets it.
	t.Run("own attester down", func(t *testing.T) {
		f := newFixture(t)
		server := withMode(f.a.Config(t, f.b), atls.ModeServer)
		server.CmcdAddr = atlstest.UnreachableCmcd(t)
		ln := listen(t, server)
		acc := acceptOne(ln, 15*time.Second)
		if _, err := dial(t, ln.Addr().String(), withMode(f.b.Config(t, f.a), atls.ModeServer)); err == nil {
			t.Fatal("an honest client accepted a server without a report")
		}
		if a := <-acc; a.err == nil {
			t.Fatal("the server kept a channel its honest client refused")
		}
		acc = acceptOne(ln, 15*time.Second)
		c := fakeTLSClient(t, ln.Addr().String(), f.b)
		sendMsg(t, c, attestedtls.AtlsHandshakeRequest{Version: atlsVersion, Attest: attestedtls.Attest_Server})
		recvMsg(t, c)
		sendMsg(t, c, attestedtls.AtlsHandshakeResponse{Version: atlsVersion})
		resp := recvMsg(t, c)
		sendMsg(t, c, attestedtls.AtlsHandshakeComplete{Version: atlsVersion, Success: true})
		recvMsg(t, c)
		var r attestedtls.AtlsHandshakeResponse
		if err := json.Unmarshal(resp, &r); err != nil || r.Error == "" || len(r.Report) != 0 {
			t.Fatalf("CMC no longer reports its failure to the peer: %s", resp)
		}
		if a := <-acc; a.err != nil {
			t.Fatalf("CMC now refuses on its own failed report: %v", a.err)
		}
	})
}
