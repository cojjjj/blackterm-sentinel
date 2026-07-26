package diff

import (
	"testing"
	"time"

	"github.com/cojjjj/blackterm-sentinel/internal/model"
)

func TestCompareDetectsServiceAddedAndRemoved(t *testing.T) {
	now := time.Now()
	previous := model.Snapshot{Hosts: []model.Host{
		{IP: "192.168.1.10", Services: []model.Service{
			{Port: 22, Protocol: "tcp", Name: "SSH"},
			{Port: 8080, Protocol: "tcp", Name: "HTTP"},
		}},
	}}
	current := model.Snapshot{Hosts: []model.Host{
		{IP: "192.168.1.10", Services: []model.Service{
			{Port: 22, Protocol: "tcp", Name: "SSH"},
			{Port: 3306, Protocol: "tcp", Name: "MySQL"},
		}},
	}}

	changes := Compare(previous, current, now)

	var added, removed bool
	for _, ch := range changes {
		if ch.Type == model.ServiceAdded && ch.Port == 3306 {
			added = true
		}
		if ch.Type == model.ServiceRemoved && ch.Port == 8080 {
			removed = true
		}
	}
	if !added || !removed {
		t.Fatalf("expected added 3306 and removed 8080, got %#v", changes)
	}
}

func TestCompareDetectsHostAdded(t *testing.T) {
	now := time.Now()
	changes := Compare(
		model.Snapshot{},
		model.Snapshot{Hosts: []model.Host{{IP: "10.0.0.5"}}},
		now,
	)
	if len(changes) != 1 || changes[0].Type != model.HostAdded {
		t.Fatalf("expected HOST_ADDED, got %#v", changes)
	}
}
