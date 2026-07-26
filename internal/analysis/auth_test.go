package analysis

import (
	"testing"

	"github.com/cojjjj/blackterm-sentinel/internal/model"
)

func TestAuthExposureGenericHTTPIsLow(t *testing.T) {
	hosts := []model.Host{
		{
			IP: "192.168.1.10",
			Services: []model.Service{
				{Port: 80, Protocol: "tcp", Name: "HTTP"},
			},
		},
	}

	findings := AuthExposure(hosts)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %#v", len(findings), findings)
	}

	if findings[0].Severity != "LOW" {
		t.Fatalf("expected LOW severity, got %s", findings[0].Severity)
	}
}

func TestAuthExposureStillFlagsTelnetHigh(t *testing.T) {
	hosts := []model.Host{
		{
			IP: "192.168.1.11",
			Services: []model.Service{
				{Port: 23, Protocol: "tcp", Name: "TELNET"},
			},
		},
	}

	findings := AuthExposure(hosts)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	if findings[0].Severity != "HIGH" {
		t.Fatalf("expected HIGH severity, got %s", findings[0].Severity)
	}
}
