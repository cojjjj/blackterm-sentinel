package store

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/cojjjj/blackterm-sentinel/internal/model"
)

func TestSaveAndReadEvents(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.db")

	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	now := time.Now()

	err = s.SaveEvents([]model.Event{
		{
			Target:    "192.168.1.0/24",
			Severity:  "MEDIUM",
			Type:      "HOST_ADDED",
			Host:      "192.168.1.50",
			Message:   "New asset discovered",
			CreatedAt: now,
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	events, err := s.RecentEvents("192.168.1.0/24", 10)
	if err != nil {
		t.Fatal(err)
	}

	if len(events) != 1 {
		t.Fatalf("expected 1 event, got %#v", events)
	}

	if events[0].Severity != "MEDIUM" {
		t.Fatalf("unexpected severity: %s", events[0].Severity)
	}
}
