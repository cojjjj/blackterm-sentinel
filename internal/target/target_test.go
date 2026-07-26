package target

import "testing"

func TestExpandCIDR(t *testing.T) {
	hosts, err := Expand("192.168.1.0/30")
	if err != nil {
		t.Fatal(err)
	}
	if len(hosts) != 2 || hosts[0] != "192.168.1.1" || hosts[1] != "192.168.1.2" {
		t.Fatalf("unexpected hosts: %#v", hosts)
	}
}

func TestExpandSingleIP(t *testing.T) {
	hosts, err := Expand("127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if len(hosts) != 1 || hosts[0] != "127.0.0.1" {
		t.Fatalf("unexpected hosts: %#v", hosts)
	}
}
