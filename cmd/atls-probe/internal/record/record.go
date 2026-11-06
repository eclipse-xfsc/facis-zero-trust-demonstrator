// Package record is the machine-readable record an atls-probe run leaves behind.
//
// A record holds addresses, certificate fingerprints, the channel binding, verdicts, errors and
// timings. It never holds key material.
package record

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"sync"
	"time"
)

// Schema identifies the record layout.
const Schema = "atls-probe-record/v1"

// Session outcomes.
const (
	OutcomePending     = "pending"      // no handshake finished yet
	OutcomeEstablished = "established"  // an attested channel was returned
	OutcomeRefused     = "refused"      // the handshake was refused
	OutcomeNoPeer      = "no-peer"      // the run ended before any handshake
	OutcomeConfigError = "config-error" // the run never started: invalid flags or material
	OutcomeForwarded   = "forwarded"    // relay: both TLS sessions were up and bytes were copied
	OutcomeNotRelayed  = "not-relayed"  // relay: one of the two TLS sessions failed
)

// How a session ended.
const (
	EndedExchangeComplete = "exchange-complete" // one heartbeat each way, then this end closed
	EndedHoldElapsed      = "hold-elapsed"      // this end closed the channel after --hold
	EndedPeerClosed       = "peer-closed"       // the peer's end of the stream ended (EOF)
	EndedError            = "error"             // a read or write failed
	EndedSignal           = "signal"            // this process was told to stop
	EndedRefused          = "refused"           // no channel: the handshake was refused
)

// Environment is what produced the record.
type Environment struct {
	// Commit is the repository commit the probe was built from; Dirty tells whether the tree
	// had changes on top of it.
	Commit string `json:"commit"`
	Dirty  bool   `json:"dirty"`
	// GoVersion is the Go toolchain the probe was built with.
	GoVersion string `json:"go_version"`
	// CMCVersion is the version of the CMC attested-TLS module linked into the probe.
	CMCVersion string `json:"cmc_version"`
	Platform   string `json:"platform"`
}

// cmcModule is the module path of the CMC attested-TLS library. The probe never imports it; the
// version is read from the build information of the binary.
const cmcModule = "github.com/Fraunhofer-AISEC/cmc"

// NewEnvironment describes the running binary. commit and dirty come from the build (-ldflags);
// when commit is empty the version-control stamp of the Go toolchain is used.
func NewEnvironment(commit string, dirty bool) Environment {
	env := Environment{
		Commit:     commit,
		Dirty:      dirty,
		GoVersion:  runtime.Version(),
		CMCVersion: "unknown",
		Platform:   runtime.GOOS + "/" + runtime.GOARCH,
	}
	info, ok := debug.ReadBuildInfo()
	if !ok {
		if env.Commit == "" {
			env.Commit = "unknown"
		}
		return env
	}
	for _, dep := range info.Deps {
		if dep.Path == cmcModule {
			env.CMCVersion = dep.Version
			if dep.Replace != nil {
				env.CMCVersion = dep.Replace.Path + "@" + dep.Replace.Version + " (replaced)"
			}
		}
	}
	if env.Commit == "" {
		env.Commit = "unknown"
		for _, s := range info.Settings {
			switch s.Key {
			case "vcs.revision":
				env.Commit = s.Value
			case "vcs.modified":
				env.Dirty = s.Value == "true"
			}
		}
	}
	return env
}

// Refusal names why no channel was returned.
type Refusal struct {
	// Sentinel is the name of the wrapper sentinel the refusal matches, for example
	// "ErrBindingMismatch"; empty when the error is not a wrapper refusal.
	Sentinel string `json:"sentinel"`
	Message  string `json:"message"`
}

// IOError is the first read or write failure on an established channel.
type IOError struct {
	// Op is "read" or "write".
	Op      string `json:"op"`
	Message string `json:"message"`
	// Kind is "sentinel" when the error matches a wrapper sentinel, "transport" otherwise. A
	// lost channel (sentinel "ErrChannelLost") names both the sentinel and the transport error
	// it wraps.
	Kind      string `json:"kind"`
	Sentinel  string `json:"sentinel,omitempty"`
	Transport string `json:"transport,omitempty"`

	DetectedAt       string `json:"detected_at"`
	DetectedAtUnixMs int64  `json:"detected_at_unix_ms"`
	// SinceEstablishedMs and SinceLastPeerHeartbeatMs place the failure in the session.
	SinceEstablishedMs       int64 `json:"since_established_ms"`
	SinceLastPeerHeartbeatMs int64 `json:"since_last_peer_heartbeat_ms"`
}

// Measurement is one verified measurement of the peer's evidence.
type Measurement struct {
	Evidence string `json:"evidence"`
	Name     string `json:"name,omitempty"`
	Index    int    `json:"index"`
	Digest   string `json:"digest"`
	HashAlg  string `json:"hash_alg,omitempty"`
}

// Heartbeats counts the application traffic of a held channel.
type Heartbeats struct {
	Sent                 int64  `json:"sent"`
	Received             int64  `json:"received"`
	LastReceivedAt       string `json:"last_received_at,omitempty"`
	LastReceivedAtUnixMs int64  `json:"last_received_at_unix_ms,omitempty"`
	// MaxGapMs is the longest time this end went without a heartbeat from the peer, up to the
	// moment the record was written.
	MaxGapMs int64 `json:"max_gap_ms"`
}

// Session is one handshake attempt and, when it succeeded, the channel that followed.
type Session struct {
	Outcome   string `json:"outcome"`
	LocalAddr string `json:"local_addr,omitempty"`
	PeerAddr  string `json:"peer_addr,omitempty"`

	// HandshakeStartedAt and HandshakeMs are set by the dialing end, which knows when it began.
	HandshakeStartedAt string `json:"handshake_started_at,omitempty"`
	HandshakeMs        int64  `json:"handshake_ms,omitempty"`

	EstablishedAt       string `json:"established_at,omitempty"`
	EstablishedAtUnixMs int64  `json:"established_at_unix_ms,omitempty"`

	// Binding is the RFC 9266 tls-exporter value of the session, hex encoded. Set only when a
	// channel was established.
	Binding      string `json:"binding,omitempty"`
	BindingBytes int    `json:"binding_bytes,omitempty"`

	// PeerFingerprint is the hex SHA-256 of the peer's TLS leaf certificate.
	PeerFingerprint  string        `json:"peer_fingerprint,omitempty"`
	Verdict          string        `json:"verdict,omitempty"`
	AttestedAt       string        `json:"attested_at,omitempty"`
	EvidenceNotAfter string        `json:"evidence_not_after,omitempty"`
	ValidUntil       string        `json:"valid_until,omitempty"`
	Measurements     []Measurement `json:"measurements,omitempty"`

	Refusal         *Refusal `json:"refusal,omitempty"`
	RefusedAt       string   `json:"refused_at,omitempty"`
	RefusedAtUnixMs int64    `json:"refused_at_unix_ms,omitempty"`

	EndedAt       string   `json:"ended_at,omitempty"`
	EndedAtUnixMs int64    `json:"ended_at_unix_ms,omitempty"`
	Ended         string   `json:"ended,omitempty"`
	Error         *IOError `json:"error,omitempty"`

	Heartbeats               Heartbeats `json:"heartbeats"`
	ApplicationBytesSent     int64      `json:"application_bytes_sent"`
	ApplicationBytesReceived int64      `json:"application_bytes_received"`
}

// RelayLeg is one of the relay's two TLS sessions.
type RelayLeg struct {
	LocalAddr string `json:"local_addr,omitempty"`
	PeerAddr  string `json:"peer_addr,omitempty"`
	// PresentedFingerprint and PresentedIdentities describe the certificate the relay showed.
	PresentedFingerprint string   `json:"presented_fingerprint,omitempty"`
	PresentedIdentities  []string `json:"presented_identities,omitempty"`
	// PeerFingerprint and PeerIdentities describe the certificate the relay was shown.
	PeerFingerprint string   `json:"peer_fingerprint,omitempty"`
	PeerIdentities  []string `json:"peer_identities,omitempty"`
	TLSVersion      string   `json:"tls_version,omitempty"`
	// Binding is the RFC 9266 tls-exporter value of this TLS session, hex encoded.
	Binding string `json:"binding,omitempty"`
	Error   string `json:"error,omitempty"`
}

// Relay is what a relay run observed.
type Relay struct {
	UpstreamAddr string `json:"upstream_addr"`
	// Downstream is the TLS session with the dialing end, Upstream the one with the listener.
	Downstream RelayLeg `json:"downstream"`
	Upstream   RelayLeg `json:"upstream"`
	// BindingsDiffer tells that the two TLS sessions have different channel bindings, so a
	// report bound to one cannot verify on the other.
	BindingsDiffer         bool   `json:"bindings_differ"`
	BytesDialerToListener  int64  `json:"bytes_dialer_to_listener"`
	BytesListenerToDialer  int64  `json:"bytes_listener_to_dialer"`
	ForwardingStartedAt    string `json:"forwarding_started_at,omitempty"`
	ForwardingEndedAt      string `json:"forwarding_ended_at,omitempty"`
	ForwardingEndedBecause string `json:"forwarding_ended_because,omitempty"`
}

// Record is the record of one probe run. The fields of Session describe the run's first
// handshake; a listener that takes more than one records the others in FurtherSessions.
type Record struct {
	Schema string `json:"schema"`
	// Mode is the subcommand: "server", "client" or "relay".
	Mode string `json:"mode"`
	// Role is the end of the channel the run played: "listener", "dialer" or
	// "man-in-the-middle".
	Role string `json:"role"`

	// Identity is what this end's own certificate carries; ExpectedPeerIdentity what it
	// requires of the peer.
	Identities           []string `json:"identities,omitempty"`
	CertFingerprint      string   `json:"cert_fingerprint,omitempty"`
	ExpectedPeerIdentity string   `json:"expected_peer_identity,omitempty"`
	CmcdAddr             string   `json:"cmcd_addr,omitempty"`
	ListenAddr           string   `json:"listen_addr,omitempty"`
	ConnectAddr          string   `json:"connect_addr,omitempty"`
	HoldMs               int64    `json:"hold_ms"`
	IntervalMs           int64    `json:"interval_ms"`

	StartedAt       string `json:"started_at"`
	StartedAtUnixMs int64  `json:"started_at_unix_ms"`
	// FinishedAt is set when the run ends in an orderly way. A run that was killed leaves its
	// last snapshot, without FinishedAt.
	FinishedAt string `json:"finished_at,omitempty"`
	ExitCode   *int   `json:"exit_code,omitempty"`
	// ConfigError is set when the run never started.
	ConfigError string `json:"config_error,omitempty"`

	Session
	FurtherSessions []*Session `json:"further_sessions,omitempty"`

	Relay *Relay `json:"relay,omitempty"`

	Environment Environment `json:"environment"`
}

// File is a record bound to the file it is written to. All access goes through Update, so
// concurrent sessions can share it.
type File struct {
	mu       sync.Mutex
	path     string
	rec      Record
	sessions int
}

// Stamp formats t as the records do: RFC 3339 in UTC with nanoseconds, and Unix milliseconds.
func Stamp(t time.Time) (string, int64) {
	return t.UTC().Format(time.RFC3339Nano), t.UnixMilli()
}

// New starts a record for a run of mode in role, to be written to path. An empty path keeps
// the record in memory only.
func New(path, mode, role string, env Environment) *File {
	f := &File{path: path}
	f.rec = Record{Schema: Schema, Mode: mode, Role: role, Environment: env}
	f.rec.Outcome = OutcomePending
	f.rec.StartedAt, f.rec.StartedAtUnixMs = Stamp(time.Now())
	return f
}

// Update changes the record under its lock.
func (f *File) Update(fn func(r *Record)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fn(&f.rec)
}

// NextSession reserves the next session of the record and returns its index: 0 is the record's
// own session, later ones are appended to FurtherSessions.
func (f *File) NextSession() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	i := f.sessions
	f.sessions++
	if i > 0 {
		f.rec.FurtherSessions = append(f.rec.FurtherSessions, &Session{Outcome: OutcomePending})
	}
	return i
}

// Sessions returns how many sessions were reserved.
func (f *File) Sessions() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.sessions
}

// UpdateSession changes session i under the record's lock.
func (f *File) UpdateSession(i int, fn func(s *Session)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if i == 0 {
		fn(&f.rec.Session)
		return
	}
	fn(f.rec.FurtherSessions[i-1])
}

// Snapshot returns a copy of the record's own session.
func (f *File) Snapshot() Session {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.rec.Session
}

// Save writes the record atomically: a reader sees the previous record or the new one, never a
// partial file.
func (f *File) Save() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.path == "" {
		return nil
	}
	data, err := json.MarshalIndent(&f.rec, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal record: %w", err)
	}
	data = append(data, '\n')
	tmp, err := os.CreateTemp(filepath.Dir(f.path), "."+filepath.Base(f.path)+".*")
	if err != nil {
		return fmt.Errorf("write record: %w", err)
	}
	name := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(name)
		return fmt.Errorf("write record: %w", err)
	}
	if err := tmp.Chmod(0o644); err != nil {
		_ = tmp.Close()
		_ = os.Remove(name)
		return fmt.Errorf("write record: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(name)
		return fmt.Errorf("write record: %w", err)
	}
	if err := os.Rename(name, f.path); err != nil {
		_ = os.Remove(name)
		return fmt.Errorf("write record: %w", err)
	}
	return nil
}
