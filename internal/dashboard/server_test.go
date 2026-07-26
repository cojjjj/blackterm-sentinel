package dashboard

import "testing"

func TestRejectsNonLoopbackAddress(t *testing.T) {
	err := Serve(Options{
		Addr:   "0.0.0.0:0",
		Target: "192.168.1.0/24",
		DBPath: ":memory:",
	})
	if err == nil {
		t.Fatal("expected non-loopback bind to be rejected")
	}
}
