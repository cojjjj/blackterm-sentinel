package discovery

import (
	"context"
	"testing"
	"time"
)

func TestDiscoverICMPLocalhost(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	hosts, err := DiscoverICMP(ctx, []string{"127.0.0.1"}, ICMPOptions{
		Workers: 1,
		Timeout: 500 * time.Millisecond,
		Rate:    10,
	})
	if err != nil {
		t.Fatal(err)
	}

	if len(hosts) != 1 || hosts[0] != "127.0.0.1" {
		t.Fatalf("expected localhost, got %#v", hosts)
	}
}
