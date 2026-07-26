package store

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/cojjjj/blackterm-sentinel/internal/model"
)

func TestDashboardSummary(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dashboard.db")

	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	target := "192.168.1.0/24"

	_, err = s.SaveSnapshot(model.Snapshot{
		Target:    target,
		Timestamp: time.Now(),
		Hosts: []model.Host{
			{
				IP: "192.168.1.10",
				Services: []model.Service{
					{Port: 443, Protocol: "tcp", Name: "HTTPS"},
				},
			},
		},
		Findings: []model.Finding{
			{Severity: "HIGH", Host: "192.168.1.10", Title: "test"},
		},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}

	if err := s.SaveEvents([]model.Event{
		{
			Target: target, Severity: "MEDIUM", Type: "HOST_ADDED",
			Host: "192.168.1.10", Message: "test", CreatedAt: time.Now(),
		},
	}); err != nil {
		t.Fatal(err)
	}

	summary, err := s.DashboardSummary(target)
	if err != nil {
		t.Fatal(err)
	}

	if summary.Assets != 1 || summary.Services != 1 || summary.High != 1 || summary.Events != 1 {
		t.Fatalf("unexpected dashboard summary: %#v", summary)
	}
}
