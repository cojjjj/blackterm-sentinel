package analysis

import (
	"testing"
	"time"

	"github.com/cojjjj/blackterm-sentinel/internal/model"
)

func TestFingerprintFindingsPasswordFieldIsHigh(t *testing.T) {
	hosts := []model.Host{
		{
			IP: "192.168.1.50",
			Services: []model.Service{
				{
					Port: 80, Protocol: "tcp", Name: "HTTP",
					HTTP: &model.HTTPFingerprint{
						Scheme:          "http",
						LoginIndicators: []string{"password-field", "login-text"},
					},
				},
			},
		},
	}

	findings := FingerprintFindings(hosts)

	var found bool
	for _, f := range findings {
		if f.Title == "LOGIN SURFACE OVER HTTP" {
			found = true
			if f.Severity != "HIGH" {
				t.Fatalf("expected HIGH severity, got %s", f.Severity)
			}
		}
	}

	if !found {
		t.Fatalf("expected LOGIN SURFACE OVER HTTP finding, got %#v", findings)
	}
}

func TestFingerprintFindingsLoginTextOnlyIsMedium(t *testing.T) {
	hosts := []model.Host{
		{
			IP: "192.168.1.60",
			Services: []model.Service{
				{
					Port: 8080, Protocol: "tcp", Name: "HTTP",
					HTTP: &model.HTTPFingerprint{
						Scheme:          "http",
						LoginIndicators: []string{"login-text"},
					},
				},
			},
		},
	}

	findings := FingerprintFindings(hosts)

	var found bool
	for _, f := range findings {
		if f.Title == "POSSIBLE LOGIN SURFACE OVER HTTP" {
			found = true
			if f.Severity != "MEDIUM" {
				t.Fatalf("expected MEDIUM severity, got %s", f.Severity)
			}
		}
	}

	if !found {
		t.Fatalf("expected POSSIBLE LOGIN SURFACE OVER HTTP finding, got %#v", findings)
	}
}

func TestFingerprintFindingsDetectsExpiringTLS(t *testing.T) {
	hosts := []model.Host{
		{
			IP: "192.168.1.70",
			Services: []model.Service{
				{
					Port: 443, Protocol: "tcp", Name: "HTTPS",
					HTTP: &model.HTTPFingerprint{
						Scheme:  "https",
						Headers: map[string]string{},
					},
					TLS: &model.TLSFingerprint{
						Version:       "TLS 1.2",
						NotAfter:      time.Now().Add(10 * 24 * time.Hour),
						DaysRemaining: 10,
					},
				},
			},
		},
	}

	findings := FingerprintFindings(hosts)

	var expiry bool
	for _, f := range findings {
		if f.Title == "TLS CERTIFICATE EXPIRING SOON" {
			expiry = true
		}
	}
	if !expiry {
		t.Fatalf("expected TLS CERTIFICATE EXPIRING SOON, got %#v", findings)
	}
}
