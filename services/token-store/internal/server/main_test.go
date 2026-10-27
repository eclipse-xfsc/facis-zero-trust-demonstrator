package server

import (
	"os"
	"testing"

	"github.com/eclipse-xfsc/facis-zero-trust-demonstrator/services/token-store/internal/acquire/acquiretest"
)

func TestMain(m *testing.M) {
	code := m.Run()
	acquiretest.Cleanup()
	os.Exit(code)
}
