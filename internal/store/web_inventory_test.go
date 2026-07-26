package store

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/cojjjj/blackterm-sentinel/internal/model"
)

func TestLatestWebInterfacesReturnsLatestScan(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sentinel-web-inventory.db")

	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	target := "192.168.50.0/24"

	_, err = s.SaveSnapshot(model.Snapshot{
		Target:    target,
		Timestamp: time.Now().Add(-time.Minute),
		Hosts: []model.Host{
			{
				IP: "192.168.50.10",
				Services: []model.Service{
					{Port: 80, Protocol: "tcp", Name: "HTTP"},
				},
			},
		},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}

	_, err = s.SaveSnapshot(model.Snapshot{
		Target:    target,
		Timestamp: time.Now(),
		Hosts: []model.Host{
			{
				IP:       "192.168.50.20",
				Hostname: "router",
				Services: []model.Service{
					{
						Port:     8443,
						Protocol: "tcp",
						Name:     "HTTPS",
						HTTP: &model.HTTPFingerprint{
							Scheme:          "https",
							Title:           "Admin Login",
							LoginIndicators: []string{"login-text"},
						},
					},
				},
			},
		},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}

	web, err := s.LatestWebInterfaces(target)
	if err != nil {
		t.Fatal(err)
	}

	if len(web) != 1 {
		t.Fatalf("expected 1 latest web interface, got %#v", web)
	}

	if web[0].IP != "192.168.50.20" || web[0].Port != 8443 {
		t.Fatalf("unexpected interface: %#v", web[0])
	}
}
