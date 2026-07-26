package fingerprint

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/cojjjj/blackterm-sentinel/internal/model"
)

var titleRE = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

type HTTPOptions struct {
	Timeout time.Duration
	MaxBody int64
}

func InspectHTTP(ctx context.Context, host string, port uint16, secure bool, opts HTTPOptions) (*model.HTTPFingerprint, *model.TLSFingerprint) {
	if opts.Timeout <= 0 {
		opts.Timeout = 1200 * time.Millisecond
	}
	if opts.MaxBody <= 0 {
		opts.MaxBody = 64 * 1024
	}

	scheme := "http"
	if secure {
		scheme = "https"
	}

	url := fmt.Sprintf("%s://%s", scheme, net.JoinHostPort(host, fmt.Sprintf("%d", port)))

	dialer := &net.Dialer{Timeout: opts.Timeout}
	transport := &http.Transport{
		DialContext: dialer.DialContext,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, // Metadata inspection only; validity is analyzed separately.
			ServerName:         host,
			MinVersion:         tls.VersionTLS10,
		},
		DisableKeepAlives: true,
	}

	client := &http.Client{
		Timeout:   opts.Timeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, nil
	}
	req.Header.Set("User-Agent", "BLACKTERM-Sentinel/0.2")

	resp, err := client.Do(req)
	if err != nil {
		return nil, nil
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, opts.MaxBody))

	httpFP := &model.HTTPFingerprint{
		Scheme:      scheme,
		StatusCode:  resp.StatusCode,
		Status:      resp.Status,
		Server:      resp.Header.Get("Server"),
		ContentType: resp.Header.Get("Content-Type"),
		Headers:     securityHeaders(resp.Header),
	}

	if match := titleRE.FindSubmatch(body); len(match) == 2 {
		httpFP.Title = strings.TrimSpace(htmlSpace(string(match[1])))
		if len(httpFP.Title) > 120 {
			httpFP.Title = httpFP.Title[:120]
		}
	}

	httpFP.LoginIndicators = detectLoginIndicators(resp, body)

	var tlsFP *model.TLSFingerprint
	if secure && resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
		tlsFP = tlsFromState(host, resp.TLS)
	}

	return httpFP, tlsFP
}

func securityHeaders(h http.Header) map[string]string {
	names := []string{
		"Strict-Transport-Security",
		"Content-Security-Policy",
		"X-Content-Type-Options",
		"X-Frame-Options",
		"Referrer-Policy",
		"Permissions-Policy",
	}
	out := map[string]string{}
	for _, name := range names {
		if value := strings.TrimSpace(h.Get(name)); value != "" {
			out[name] = value
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func detectLoginIndicators(resp *http.Response, body []byte) []string {
	lower := strings.ToLower(string(body))
	var indicators []string

	if strings.Contains(lower, `type="password"`) || strings.Contains(lower, `type='password'`) {
		indicators = append(indicators, "password-field")
	}
	if strings.Contains(lower, "sign in") || strings.Contains(lower, "log in") || strings.Contains(lower, "login") {
		indicators = append(indicators, "login-text")
	}
	if resp.StatusCode == http.StatusUnauthorized {
		indicators = append(indicators, "http-401")
	}
	if resp.Header.Get("WWW-Authenticate") != "" {
		indicators = append(indicators, "www-authenticate")
	}
	return unique(indicators)
}

func tlsFromState(host string, state *tls.ConnectionState) *model.TLSFingerprint {
	cert := state.PeerCertificates[0]
	now := time.Now()

	hostnameMatch := cert.VerifyHostname(host) == nil
	selfSigned := cert.Issuer.String() == cert.Subject.String()

	return &model.TLSFingerprint{
		Version:       tlsVersionName(state.Version),
		CipherSuite:   tls.CipherSuiteName(state.CipherSuite),
		Subject:       cert.Subject.String(),
		Issuer:        cert.Issuer.String(),
		DNSNames:      append([]string(nil), cert.DNSNames...),
		NotBefore:     cert.NotBefore,
		NotAfter:      cert.NotAfter,
		DaysRemaining: int(cert.NotAfter.Sub(now).Hours() / 24),
		SelfSigned:    selfSigned,
		HostnameMatch: hostnameMatch,
	}
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("0x%04x", v)
	}
}

func htmlSpace(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

func unique(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, item := range in {
		if !seen[item] {
			seen[item] = true
			out = append(out, item)
		}
	}
	return out
}
