package report

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/cojjjj/blackterm-sentinel/internal/model"
)

func TestWatchCycleNoChanges(t *testing.T) {
	var buf bytes.Buffer

	snapshot := model.Snapshot{
		Timestamp: time.Date(2026, 7, 25, 20, 0, 0, 0, time.Local),
		Hosts: []model.Host{
			{
				IP: "192.168.1.10",
				Services: []model.Service{
					{Port: 443, Protocol: "tcp", Name: "HTTPS"},
				},
			},
		},
	}

	WatchCycle(&buf, snapshot, nil, nil, 30*time.Second)

	out := buf.String()
	if !strings.Contains(out, "OK | 1 assets | 1 services | next scan 30s") {
		t.Fatalf("unexpected watch output: %q", out)
	}
}

func TestWatchBaseline(t *testing.T) {
	var buf bytes.Buffer

	snapshot := model.Snapshot{
		Timestamp: time.Now(),
		Hosts: []model.Host{
			{IP: "192.168.1.10"},
			{IP: "192.168.1.11"},
		},
	}

	WatchBaseline(&buf, snapshot)

	if !strings.Contains(buf.String(), "BASELINE ESTABLISHED | 2 assets") {
		t.Fatalf("unexpected baseline output: %q", buf.String())
	}
}

func TestWatchStartShowsNotificationMode(t *testing.T) {
	var buf bytes.Buffer

	WatchStart(
		&buf,
		"192.168.1.0/24",
		30*time.Second,
		true,
		"medium",
	)

	if !strings.Contains(buf.String(), "NOTIFY      enabled (MEDIUM+)") {
		t.Fatalf("unexpected watch start output: %q", buf.String())
	}
}
