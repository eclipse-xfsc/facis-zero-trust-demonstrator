package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/if03"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/trustlist"
)

// maxTrustDoc bounds every trust document read: the issuer keys file, the pinned trust list and a
// TCR answer.
const maxTrustDoc = trustlist.MaxDoc

// lister says whether TRAIN lists issuer as an active trust service, and until when the listing
// may be relied on (the expiry of the trust-list VC that lists it; zero for a source without one).
// An error is "not known", and the issuer is not trusted until the next refresh says otherwise
// (fail closed).
type lister func(ctx context.Context, issuer string) (ok bool, until time.Time, err error)

// trusted is the credential issuers a presentation may come from: those of keyed (the issuer keys
// file, if03.ParseIssuers' format) that listed reports. An issuer with keys but no listing, or
// whose listing cannot be read, is left out, so its credentials are CRED-ISSUER-UNTRUSTED.
// Each kept issuer's deadline, when its source has one, is in until.
func trusted(ctx context.Context, keyed if03.Issuers, listed lister) (set if03.Issuers, until map[string]time.Time, dropped []string) {
	set, until = if03.Issuers{}, map[string]time.Time{}
	for iss, keys := range keyed {
		ok, deadline, err := listed(ctx, iss)
		if err != nil || !ok {
			dropped = append(dropped, iss)
			continue
		}
		set[iss] = keys
		if !deadline.IsZero() {
			until[iss] = deadline
		}
	}
	return set, until, dropped
}

func readIssuers(path string) (if03.Issuers, error) {
	b, err := readBounded(path)
	if err != nil {
		return nil, err
	}
	return if03.ParseIssuers(b)
}

func readBounded(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	switch {
	case err != nil:
		return nil, errors.New("cannot read the file")
	case len(b) > maxTrustDoc:
		return nil, errors.New("the file is larger than 1 MiB")
	}
	return b, nil
}

// pinnedList is the FIXTURE trust source: a trust list in the JSON form TSPA serves at
// GET /tspa/v1/{framework}/trust-list (docs/tspa-publish-api.md), read from a file at every call.
// Unlike the TCR it verifies neither the trust-list VC's signature nor its hash, and it resolves no
// DNS: it stands in for TRAIN where no TCR is reachable and must never be a zone's trust source of
// record.
func pinnedList(path string) lister {
	return func(_ context.Context, issuer string) (bool, time.Time, error) {
		b, err := readBounded(path)
		if err != nil {
			return false, time.Time{}, err
		}
		var doc any
		if err := json.Unmarshal(b, &doc); err != nil {
			return false, time.Time{}, errors.New("the trust list is not JSON")
		}
		return trustlist.ListsActive(doc, issuer), time.Time{}, nil
	}
}

// tcrList uses the TRAIN Trusted Content Resolver (eclipse-xfsc/train-trust-validator,
// POST /tcr/v1/resolve, docs/tspa-publish-api.md section 4) for what only it does: walking the DNS
// chain from the trust framework pointers to the trust list issuers' DIDs and their trust-list VC
// locations. Its vcVerified is not relied on (it ignores the VC's validity window): the service
// fetches each VC from the resolved location and verifies it itself (trustlist.Verifier), and the issuer
// is listed when a list so verified holds an active service whose ServiceTypeIdentifier is the
// issuer. Any failure leaves the issuer unlisted.
func tcrList(client *http.Client, base string, pointers []string, vcs *trustlist.Verifier) lister {
	endpoint := strings.TrimRight(base, "/") + "/tcr/v1/resolve"
	return func(ctx context.Context, issuer string) (bool, time.Time, error) {
		body, _ := json.Marshal(map[string]any{"issuer": issuer, "trustSchemePointers": pointers})
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
		if err != nil {
			return false, time.Time{}, err
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			return false, time.Time{}, errors.New("tcr unreachable")
		}
		defer func() { _ = resp.Body.Close() }()
		raw, err := io.ReadAll(io.LimitReader(resp.Body, maxTrustDoc+1))
		if err != nil || len(raw) > maxTrustDoc || resp.StatusCode != http.StatusOK {
			return false, time.Time{}, errors.New("tcr answer refused")
		}
		var answer struct {
			ResolvedResults []struct {
				DID         string `json:"did"`
				ResolvedDoc *struct {
					Endpoints []struct {
						VCURI string `json:"vcUri"`
					} `json:"endpoints"`
				} `json:"resolvedDoc"`
			} `json:"resolvedResults"`
		}
		if json.Unmarshal(raw, &answer) != nil {
			return false, time.Time{}, errors.New("tcr answer is not JSON")
		}
		var refused error
		for _, r := range answer.ResolvedResults {
			if r.ResolvedDoc == nil {
				continue
			}
			for _, e := range r.ResolvedDoc.Endpoints {
				list, until, err := vcs.TrustList(ctx, r.DID, e.VCURI)
				if err != nil {
					refused = err
					continue
				}
				if trustlist.ListsActive(list, issuer) {
					return true, until, nil
				}
			}
		}
		return false, time.Time{}, refused
	}
}
