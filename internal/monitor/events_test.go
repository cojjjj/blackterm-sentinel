package monitor

import (
	"testing"
	"time"

	"github.com/cojjjj/blackterm-sentinel/internal/model"
)

func TestEventsFromChanges(t *testing.T) {
	now := time.Now()

	events := EventsFromChanges("192.168.1.0/24", []model.Change{
		{
			Type:       model.HostAdded,
			Host:       "192.168.1.50",
			DetectedAt: now,
		},
		{
			Type:       model.ServiceAdded,
			Host:       "192.168.1.50",
			Port:       8080,
			Protocol:   "tcp",
			Service:    "HTTP",
			DetectedAt: now,
		},
	})

	if len(events) != 2 {
		t.Fatalf("expected 2 events, got %d", len(events))
	}

	if events[0].Severity != "MEDIUM" {
		t.Fatalf("expected MEDIUM host-added severity, got %s", events[0].Severity)
	}

	if events[1].Severity != "MEDIUM" {
		t.Fatalf("expected MEDIUM service-added severity, got %s", events[1].Severity)
	}
}
