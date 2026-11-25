package bdd

import (
	"crypto/tls"
	"encoding/json"
	"strings"
	"testing"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/connectorgateway"
)

func TestGatewayDeciderRequiresRefusalsAndBinding(t *testing.T) {
	events := []connectorgateway.Event{
		{Role: "egress", Decision: "established", Peer: "spiffe://b/gateway", Binding: strings.Repeat("a", 64), TLSVersion: tls.VersionTLS13},
		{Role: "ingress", Decision: "established", Peer: "spiffe://a/gateway", Binding: strings.Repeat("a", 64), TLSVersion: tls.VersionTLS13},
		{Role: "ingress", Decision: "refused", Reason: "atls: peer does not speak attested TLS 1.3"},
		{Role: "ingress", Decision: "refused", Reason: "atls: handshake timed out"},
		{Role: "egress", Decision: "refused", Reason: "atls: handshake timed out"},
	}
	wire := 4096
	decide := func(entries []connectorgateway.Event) error {
		data, err := json.Marshal(map[string]any{"passed": true, "proof": "http-grpc-two-cmcd", "events": entries, "interConnectorTLSBytes": wire})
		if err != nil {
			t.Fatal(err)
		}
		return decideGateway(data)
	}
	if err := decide(events); err != nil {
		t.Fatal(err)
	}
	for i := range events {
		reduced := append([]connectorgateway.Event(nil), events[:i]...)
		reduced = append(reduced, events[i+1:]...)
		if err := decide(reduced); err == nil {
			t.Fatalf("accepted missing event %d", i)
		}
	}
	wire = 0
	if err := decide(events); err == nil {
		t.Fatal("accepted a record without bytes on the inter-connector hop")
	}
	wire = 4096
	events[0].Binding = strings.Repeat("b", 64)
	if err := decide(events); err == nil {
		t.Fatal("accepted mismatched channel bindings")
	}
	if err := decideGateway([]byte(`{"passed":true}`)); err == nil {
		t.Fatal("accepted a bare success flag")
	}
}
