package assets

import (
	"testing"

	"github.com/cojjjj/blackterm-sentinel/internal/model"
)

func TestIdentityKeyPrefersMAC(t *testing.T) {
	host := model.Host{
		IP:  "192.168.50.25",
		MAC: "aa:bb:cc:dd:ee:ff",
	}

	got := IdentityKey(host)
	want := "mac:AA:BB:CC:DD:EE:FF"

	if got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
}

func TestIdentityKeyFallsBackToIP(t *testing.T) {
	host := model.Host{IP: "192.168.50.25"}

	got := IdentityKey(host)
	want := "ip:192.168.50.25"

	if got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
}
