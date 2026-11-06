package atls

// ListenerPeak returns the highest number of concurrent handshakes the listener has run.
func ListenerPeak(l *Listener) int64 { return l.gate.peak.Load() }

// DialPeak returns the highest number of concurrent Dial handshakes, and resets it.
func DialPeak() int64 { return dialGate.peak.Load() }

// ResetDialPeak resets the Dial peak to the current number in flight.
func ResetDialPeak() { dialGate.peak.Store(dialGate.inflight.Load()) }

// Classify exposes the CMC error classifier to the pinning tests.
func Classify(err error) *Error { return fromText(err) }
