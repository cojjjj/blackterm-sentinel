package analysis

import (
	"fmt"
	"strings"
	"time"

	"github.com/cojjjj/blackterm-sentinel/internal/model"
)

func FingerprintFindings(hosts []model.Host) []model.Finding {
	var findings []model.Finding

	for _, host := range hosts {
		for _, svc := range host.Services {
			if svc.HTTP != nil {
				findings = append(findings, httpFindings(host, svc)...)
			}
			if svc.TLS != nil {
				findings = append(findings, tlsFindings(host, svc)...)
			}
		}
	}

	return findings
}

func httpFindings(host model.Host, svc model.Service) []model.Finding {
	var findings []model.Finding
	fp := svc.HTTP

	if fp.Scheme == "http" {
		hasPasswordField := contains(fp.LoginIndicators, "password-field")
		hasAuthChallenge := contains(fp.LoginIndicators, "http-401") ||
			contains(fp.LoginIndicators, "www-authenticate")
		hasLoginText := contains(fp.LoginIndicators, "login-text")

		switch {
		case hasPasswordField || hasAuthChallenge:
			findings = append(findings, model.Finding{
				Severity: "HIGH",
				Category: "AUTH_EXPOSURE",
				Host:     host.IP, Port: svc.Port, Protocol: svc.Protocol, Service: svc.Name,
				Title: "LOGIN SURFACE OVER HTTP",
				Detail: fmt.Sprintf(
					"Sentinel observed explicit authentication indicators (%s) on an unencrypted HTTP service.",
					strings.Join(fp.LoginIndicators, ", "),
				),
				Recommendation: "Use HTTPS for login and administrative interfaces and avoid transmitting credentials over plain HTTP.",
			})

		case hasLoginText:
			findings = append(findings, model.Finding{
				Severity: "MEDIUM",
				Category: "AUTH_EXPOSURE",
				Host:     host.IP, Port: svc.Port, Protocol: svc.Protocol, Service: svc.Name,
				Title:          "POSSIBLE LOGIN SURFACE OVER HTTP",
				Detail:         "Sentinel observed login-related page text on an unencrypted HTTP service, but did not confirm a password field or explicit authentication challenge.",
				Recommendation: "Review the interface and use HTTPS if authentication or sensitive administration is present.",
			})
		}
	}

	if fp.Scheme == "https" {
		if _, ok := fp.Headers["Strict-Transport-Security"]; !ok {
			findings = append(findings, model.Finding{
				Severity: "LOW",
				Category: "HTTP_HEADERS",
				Host:     host.IP, Port: svc.Port, Protocol: svc.Protocol, Service: svc.Name,
				Title:          "HSTS NOT OBSERVED",
				Detail:         "The HTTPS response did not include a Strict-Transport-Security header.",
				Recommendation: "Consider enabling HSTS after confirming all access paths are HTTPS-only.",
			})
		}
	}

	if _, ok := fp.Headers["X-Content-Type-Options"]; !ok {
		findings = append(findings, model.Finding{
			Severity: "INFO",
			Category: "HTTP_HEADERS",
			Host:     host.IP, Port: svc.Port, Protocol: svc.Protocol, Service: svc.Name,
			Title:          "X-CONTENT-TYPE-OPTIONS NOT OBSERVED",
			Detail:         "The HTTP response did not include X-Content-Type-Options.",
			Recommendation: "For browser-facing applications, consider setting X-Content-Type-Options: nosniff.",
		})
	}

	return findings
}

func contains(items []string, wanted string) bool {
	for _, item := range items {
		if item == wanted {
			return true
		}
	}
	return false
}

func tlsFindings(host model.Host, svc model.Service) []model.Finding {
	var findings []model.Finding
	fp := svc.TLS

	if fp.DaysRemaining < 0 {
		findings = append(findings, model.Finding{
			Severity: "HIGH",
			Category: "TLS",
			Host:     host.IP, Port: svc.Port, Protocol: svc.Protocol, Service: svc.Name,
			Title:          "TLS CERTIFICATE EXPIRED",
			Detail:         fmt.Sprintf("The observed TLS certificate expired on %s.", fp.NotAfter.Format(time.DateOnly)),
			Recommendation: "Replace or renew the certificate and confirm clients receive the updated chain.",
		})
	} else if fp.DaysRemaining <= 30 {
		findings = append(findings, model.Finding{
			Severity: "MEDIUM",
			Category: "TLS",
			Host:     host.IP, Port: svc.Port, Protocol: svc.Protocol, Service: svc.Name,
			Title:          "TLS CERTIFICATE EXPIRING SOON",
			Detail:         fmt.Sprintf("The observed TLS certificate has about %d days remaining.", fp.DaysRemaining),
			Recommendation: "Plan certificate renewal before expiration.",
		})
	}

	if fp.Version == "TLS 1.0" || fp.Version == "TLS 1.1" {
		findings = append(findings, model.Finding{
			Severity: "HIGH",
			Category: "TLS",
			Host:     host.IP, Port: svc.Port, Protocol: svc.Protocol, Service: svc.Name,
			Title:          "LEGACY TLS VERSION",
			Detail:         fmt.Sprintf("The observed HTTPS connection negotiated %s.", fp.Version),
			Recommendation: "Prefer TLS 1.2 or TLS 1.3 where supported.",
		})
	}

	if fp.SelfSigned {
		findings = append(findings, model.Finding{
			Severity: "INFO",
			Category: "TLS",
			Host:     host.IP, Port: svc.Port, Protocol: svc.Protocol, Service: svc.Name,
			Title:          "SELF-SIGNED TLS CERTIFICATE",
			Detail:         "The observed certificate subject and issuer are identical.",
			Recommendation: "Confirm self-signed trust is intentional and limited to appropriate internal use.",
		})
	}

	return findings
}
