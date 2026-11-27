package atls_test

// A regression test for finding N4 that runs under the race detector too. The tests that drive
// CMC through its in-process (libapi) backend are in libapi_test.go, which is not compiled under
// the race detector.

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Fraunhofer-AISEC/cmc/cmc"
)

// libapiMu keeps handshakes through CMC's in-process backend of different tests apart: libapi
// re-initialises process-global drivers on every call (finding N4). Tests hold it only while
// CMC is working, not while they wait. Only the in-process backend shares the global driver: the
// stand-in cmcd of every atlstest zone attests with a private sw driver, so handshakes over gRPC
// need no lock (TestStandInCmcdIsolatedFromGlobalDriver).
var libapiMu sync.Mutex

// Finding N4: CMC's in-process backend calls cmc.NewCmc on every call, which re-initialises the
// process-global sw driver from the calling zone's storage, without a lock. A stand-in cmcd that
// generated reports with that global driver could publish one key in a report's collateral and
// sign its evidence with another while an in-process handshake of another fixture ran, and the
// peer refused the report (the intermittent refusal of the parallel tests). Every atlstest zone
// now attests with a private sw driver: re-initialising CMC with two other fixtures'
// configurations in a loop must not disturb a third fixture's handshakes over gRPC.
func TestStandInCmcdIsolatedFromGlobalDriver(t *testing.T) {
	others := []*fixture{newFixture(t), newFixture(t)}
	f := newFixture(t)

	stop := make(chan struct{})
	var reinit sync.WaitGroup
	var reinits atomic.Int64
	reinit.Add(1)
	go func() {
		defer reinit.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			libapiMu.Lock()
			_, err := cmc.NewCmc(others[i%2].a.LibAPIConfig())
			libapiMu.Unlock()
			if err != nil {
				t.Errorf("re-initialise CMC: %v", err)
				return
			}
			reinits.Add(1)
		}
	}()
	defer func() { close(stop); reinit.Wait() }()

	ln := listen(t, f.b.Config(t, f.a))
	cc := f.a.Config(t, f.b)
	const handshakes = 200
	for i := range handshakes {
		acc := acceptOne(ln, 20*time.Second)
		c, err := dial(t, ln.Addr().String(), cc)
		a := <-acc
		if c != nil {
			_ = c.Close()
		}
		if a.conn != nil {
			_ = a.conn.Close()
		}
		if err != nil || a.err != nil {
			t.Fatalf("handshake %d of %d refused while CMC was re-initialised %d times: dial %v, accept %v",
				i+1, handshakes, reinits.Load(), err, a.err)
		}
	}
	if reinits.Load() == 0 {
		t.Fatal("CMC was never re-initialised during the handshakes")
	}
}
