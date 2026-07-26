package store

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/cojjjj/blackterm-sentinel/internal/model"
)

func TestWebInterfacesPrefersLoginSignal(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sentinel-web.db")

	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	snapshot := model.Snapshot{
		Target:    "192.168.50.0/24",
		Timestamp: time.Now(),
		Hosts: []model.Host{
			{
				IP:       "192.168.50.10",
				Hostname: "device",
				Services: []model.Service{
					{
						Port:     443,
						Protocol: "tcp",
						Name:     "HTTPS",
						HTTP: &model.HTTPFingerprint{
							Scheme: "https",
							Title:  "Status",
						},
					},
					{
						Port:     8080,
						Protocol: "tcp",
						Name:     "HTTP",
						HTTP: &model.HTTPFingerprint{
							Scheme:          "http",
							Title:           "Login",
							LoginIndicators: []string{"password-field"},
						},
					},
				},
			},
		},
	}

	if _, err := s.SaveSnapshot(snapshot, nil); err != nil {
		t.Fatal(err)
	}

	web, err := s.WebInterfaces("192.168.50.10")
	if err != nil {
		t.Fatal(err)
	}

	if len(web) != 2 {
		t.Fatalf("expected 2 web interfaces, got %#v", web)
	}

	if web[0].Port != 8080 {
		t.Fatalf("expected login interface first, got %#v", web[0])
	}
}
