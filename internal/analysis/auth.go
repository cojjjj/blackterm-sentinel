package analysis

import (
	"fmt"
	"strings"

	"github.com/cojjjj/blackterm-sentinel/internal/model"
)

// AuthExposure performs passive analysis using services Sentinel has already
// observed. It does not attempt authentication, guess credentials, intercept
// traffic, or submit passwords.
func AuthExposure(hosts []model.Host) []model.Finding {
	var findings []model.Finding

	for _, host := range hosts {
		for _, svc := range host.Services {
			switch strings.ToUpper(svc.Name) {
			case "TELNET":
				findings = append(findings, finding(
					"HIGH", host, svc,
					"CLEAR-TEXT AUTH PROTOCOL",
					"Telnet does not provide encrypted transport for authentication or session data.",
					"Disable Telnet where possible and use SSH or another encrypted management protocol.",
				))

			case "FTP":
				findings = append(findings, finding(
					"HIGH", host, svc,
					"CLEAR-TEXT CREDENTIAL RISK",
					"Traditional FTP can transmit usernames, passwords, and data without transport encryption.",
					"Prefer SFTP, FTPS, or another encrypted file-transfer mechanism.",
				))

			case "HTTP":
				findings = append(findings, finding(
					"LOW", host, svc,
					"UNENCRYPTED WEB SERVICE",
					"An HTTP service is exposed without TLS. Plain HTTP does not encrypt traffic in transit.",
					"Prefer HTTPS for administrative, authenticated, or sensitive interfaces.",
				))

			case "SMB":
				findings = append(findings, finding(
					"INFO", host, svc,
					"SMB AUTHENTICATION SURFACE",
					"SMB is reachable on the network and may expose an authentication surface depending on host configuration.",
					"Restrict SMB to trusted network segments and review signing, sharing, and authentication policy.",
				))

			case "RDP":
				findings = append(findings, finding(
					"INFO", host, svc,
					"REMOTE LOGIN SURFACE",
					"RDP is reachable and represents an interactive authentication surface.",
					"Restrict access to trusted hosts or VPN paths and use strong authentication controls.",
				))

			case "VNC":
				findings = append(findings, finding(
					"MEDIUM", host, svc,
					"REMOTE DESKTOP AUTH SURFACE",
					"VNC is reachable. Security properties vary by implementation and configuration.",
					"Confirm authentication and encryption are enabled and restrict network exposure.",
				))

			case "DOCKER":
				findings = append(findings, finding(
					"HIGH", host, svc,
					"DOCKER API EXPOSURE",
					"A Docker API endpoint is reachable on the network. Unprotected remote APIs can create serious administrative exposure.",
					"Confirm the endpoint requires appropriate protection and is restricted to trusted management networks.",
				))
			}
		}
	}

	return findings
}

func finding(severity string, host model.Host, svc model.Service, title, detail, recommendation string) model.Finding {
	return model.Finding{
		Severity:       severity,
		Category:       "AUTH_EXPOSURE",
		Host:           host.IP,
		Port:           svc.Port,
		Protocol:       svc.Protocol,
		Service:        svc.Name,
		Title:          title,
		Detail:         detail,
		Recommendation: recommendation,
	}
}

func Summary(findings []model.Finding) string {
	counts := map[string]int{}
	for _, f := range findings {
		counts[f.Severity]++
	}
	return fmt.Sprintf(
		"CRITICAL %d | HIGH %d | MEDIUM %d | LOW %d | INFO %d",
		counts["CRITICAL"], counts["HIGH"], counts["MEDIUM"], counts["LOW"], counts["INFO"],
	)
}
