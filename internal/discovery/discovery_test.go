package discovery

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestDiscoverFindsListeningHost(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	port := uint16(ln.Addr().(*net.TCPAddr).Port)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	hosts, err := Discover(ctx, []string{"127.0.0.1"}, Options{
		Workers: 2,
		Timeout: 250 * time.Millisecond,
		Rate:    100,
		Ports:   []uint16{port},
	})
	if err != nil {
		t.Fatal(err)
	}

	if len(hosts) != 1 || hosts[0] != "127.0.0.1" {
		t.Fatalf("expected localhost to be discovered, got %#v", hosts)
	}
}
