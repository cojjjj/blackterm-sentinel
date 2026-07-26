package store

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/cojjjj/blackterm-sentinel/internal/model"
)

func TestAssetStateTransitions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sentinel-test.db")

	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	target := "192.168.50.0/24"
	host := model.Host{
		IP:  "192.168.50.25",
		MAC: "AA:BB:CC:DD:EE:FF",
		Services: []model.Service{
			{Port: 443, Protocol: "tcp", Name: "HTTPS"},
		},
	}

	base := time.Date(2026, 7, 25, 20, 0, 0, 0, time.UTC)

	_, err = s.SaveSnapshot(model.Snapshot{
		Target:    target,
		Timestamp: base,
		Hosts:     []model.Host{host},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}

	assets, err := s.Assets(target)
	if err != nil {
		t.Fatal(err)
	}
	if len(assets) != 1 || assets[0].State != model.AssetNew {
		t.Fatalf("expected NEW asset, got %#v", assets)
	}
	if assets[0].DeviceType != "UNKNOWN" {
		t.Fatalf("expected UNKNOWN device type, got %q", assets[0].DeviceType)
	}

	_, err = s.SaveSnapshot(model.Snapshot{
		Target:    target,
		Timestamp: base.Add(time.Minute),
		Hosts:     []model.Host{host},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}

	assets, err = s.Assets(target)
	if err != nil {
		t.Fatal(err)
	}
	if assets[0].State != model.AssetActive {
		t.Fatalf("expected ACTIVE asset, got %#v", assets[0])
	}

	for i := 0; i < 2; i++ {
		_, err = s.SaveSnapshot(model.Snapshot{
			Target:    target,
			Timestamp: base.Add(time.Duration(i+2) * time.Minute),
		}, nil)
		if err != nil {
			t.Fatal(err)
		}
	}

	assets, err = s.Assets(target)
	if err != nil {
		t.Fatal(err)
	}
	if assets[0].State != model.AssetStale {
		t.Fatalf("expected STALE after two misses, got %#v", assets[0])
	}

	_, err = s.SaveSnapshot(model.Snapshot{
		Target:    target,
		Timestamp: base.Add(4 * time.Minute),
	}, nil)
	if err != nil {
		t.Fatal(err)
	}

	assets, err = s.Assets(target)
	if err != nil {
		t.Fatal(err)
	}
	if assets[0].State != model.AssetOffline {
		t.Fatalf("expected OFFLINE after three misses, got %#v", assets[0])
	}
}
