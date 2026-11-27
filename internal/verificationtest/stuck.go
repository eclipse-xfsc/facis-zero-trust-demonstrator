package verificationtest

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/oid4vp"
	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/internal/verificationclient"
)

// Stuck is a holder that takes a request and does not come back, whatever its context says: a
// wallet that never answers. Release lets the calls it holds return, each with an error, and a
// call that arrives afterwards returns at once.
type Stuck struct {
	taken, back atomic.Int32
	entered     chan struct{}
	release     chan struct{}
	released    sync.Once
}

var _ verificationclient.Holder = (*Stuck)(nil)

// StuckHolder returns a Stuck that the test's cleanup releases and waits for, so no call it holds
// outlives the test.
func StuckHolder(t testing.TB) *Stuck {
	t.Helper()
	s := &Stuck{entered: make(chan struct{}, 64), release: make(chan struct{})}
	t.Cleanup(s.Release)
	return s
}

// Present takes the request and returns only after Release.
func (s *Stuck) Present(context.Context, oid4vp.Request) (string, error) {
	s.taken.Add(1)
	select {
	case s.entered <- struct{}{}:
	default:
	}
	<-s.release
	s.back.Add(1)
	return "", errors.New("released by the test")
}

// Taken is the number of requests that have reached the holder.
func (s *Stuck) Taken() int { return int(s.taken.Load()) }

// Entered receives once for each request that reaches the holder.
func (s *Stuck) Entered() <-chan struct{} { return s.entered }

// Release lets every held call return and waits until each has left the holder.
func (s *Stuck) Release() {
	s.released.Do(func() { close(s.release) })
	for s.back.Load() < s.taken.Load() {
		time.Sleep(time.Millisecond)
	}
}
