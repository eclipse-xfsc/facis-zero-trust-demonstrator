package participant

import "context"

// State is a step of the Participant's start-up on the token path (design D12). Every failure has its
// own state so /state names what went wrong.
type State string

const (
	StateRegistering     State = "registering"
	StatePresenting      State = "presenting"
	StateAcquiringToken  State = "acquiring_token"
	StateReady           State = "ready"
	StateFailedRegister  State = "failed_registration"
	StateFailedPresent   State = "failed_presentation"
	StateFailedToken     State = "failed_token"
	StateFailedConnector State = "failed_connector_unreachable"
)

// Bootstrapper runs the start-up sequence: register with the Connector (registrar credentials from a
// mounted secret), obtain a challenge, present (an IF-03 outcome from the OutcomeSource), and acquire
// a DPoP-bound token. It reports every transition through report. The token path implementation is
// integrated locally; the Participant's lifecycle, /state and /reset build against this interface.
type Bootstrapper interface {
	Run(ctx context.Context, report func(State, string)) (TokenSession, error)
}

// TokenSession makes authenticated calls: it owns the DPoP key and adds a fresh proof per request.
type TokenSession interface {
	Authorize(ctx context.Context, method, url string) (authorization, dpop string, err error)
}
