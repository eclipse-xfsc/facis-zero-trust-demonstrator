package trustlist

import "testing"

func TestDIDWebURL(t *testing.T) {
	for did, want := range map[string]string{
		"did:web:tspa.facis.cloud":             "https://tspa.facis.cloud/.well-known/did.json",
		"did:web:127.0.0.1%3A8443":             "https://127.0.0.1:8443/.well-known/did.json",
		"did:web:tspa.facis.cloud:ztd:release": "https://tspa.facis.cloud/ztd/release/did.json",
	} {
		if got, err := didWebURL(did); err != nil || got != want {
			t.Errorf("%s: %s %v", did, got, err)
		}
	}
	for _, bad := range []string{"did:key:z6Mk", "did:web:", "did:web:a%2Fb"} {
		if _, err := didWebURL(bad); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
}

func TestMultihashIsIPFSBase58(t *testing.T) {
	// The multihash of the empty input, as IPFS writes it.
	if got := MultihashSHA256(nil); got != "QmdfTbBqBPQ7VNxZEYEj14VmRuZBkqFbiwReogJgS1zR1n" {
		t.Errorf("got %s", got)
	}
}
