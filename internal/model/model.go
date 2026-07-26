package model

import "time"

type HTTPFingerprint struct {
	Scheme          string            `json:"scheme,omitempty"`
	StatusCode      int               `json:"status_code,omitempty"`
	Status          string            `json:"status,omitempty"`
	Title           string            `json:"title,omitempty"`
	Server          string            `json:"server,omitempty"`
	ContentType     string            `json:"content_type,omitempty"`
	Headers         map[string]string `json:"headers,omitempty"`
	LoginIndicators []string          `json:"login_indicators,omitempty"`
}

type TLSFingerprint struct {
	Version       string    `json:"version,omitempty"`
	CipherSuite   string    `json:"cipher_suite,omitempty"`
	Subject       string    `json:"subject,omitempty"`
	Issuer        string    `json:"issuer,omitempty"`
	DNSNames      []string  `json:"dns_names,omitempty"`
	NotBefore     time.Time `json:"not_before,omitempty"`
	NotAfter      time.Time `json:"not_after,omitempty"`
	DaysRemaining int       `json:"days_remaining,omitempty"`
	SelfSigned    bool      `json:"self_signed,omitempty"`
	HostnameMatch bool      `json:"hostname_match,omitempty"`
}

type Service struct {
	Port     uint16           `json:"port"`
	Protocol string           `json:"protocol"`
	Name     string           `json:"name"`
	Banner   string           `json:"banner,omitempty"`
	HTTP     *HTTPFingerprint `json:"http,omitempty"`
	TLS      *TLSFingerprint  `json:"tls,omitempty"`
}

type Finding struct {
	Severity       string `json:"severity"`
	Category       string `json:"category"`
	Host           string `json:"host"`
	Port           uint16 `json:"port,omitempty"`
	Protocol       string `json:"protocol,omitempty"`
	Service        string `json:"service,omitempty"`
	Title          string `json:"title"`
	Detail         string `json:"detail"`
	Recommendation string `json:"recommendation,omitempty"`
}

type Host struct {
	IP               string    `json:"ip"`
	Hostname         string    `json:"hostname,omitempty"`
	MAC              string    `json:"mac,omitempty"`
	DiscoverySources []string  `json:"discovery_sources,omitempty"`
	Services         []Service `json:"services"`
}

type Snapshot struct {
	ID        int64     `json:"id"`
	Target    string    `json:"target"`
	Interface string    `json:"interface,omitempty"`
	Timestamp time.Time `json:"timestamp"`
	Hosts     []Host    `json:"hosts"`
	Findings  []Finding `json:"findings,omitempty"`
}

type AssetState string

const (
	AssetNew     AssetState = "NEW"
	AssetActive  AssetState = "ACTIVE"
	AssetStale   AssetState = "STALE"
	AssetOffline AssetState = "OFFLINE"
)

type AssetRecord struct {
	IdentityKey      string     `json:"identity_key"`
	DeviceType       string     `json:"device_type,omitempty"`
	Target           string     `json:"target"`
	IP               string     `json:"ip"`
	Hostname         string     `json:"hostname,omitempty"`
	MAC              string     `json:"mac,omitempty"`
	State            AssetState `json:"state"`
	FirstSeen        time.Time  `json:"first_seen"`
	LastSeen         time.Time  `json:"last_seen"`
	ObservationCount int        `json:"observation_count"`
	MissedScans      int        `json:"missed_scans"`
}

type ServiceHistory struct {
	IdentityKey      string    `json:"identity_key"`
	Target           string    `json:"target"`
	IP               string    `json:"ip"`
	Port             uint16    `json:"port"`
	Protocol         string    `json:"protocol"`
	Name             string    `json:"name"`
	Present          bool      `json:"present"`
	FirstSeen        time.Time `json:"first_seen"`
	LastSeen         time.Time `json:"last_seen"`
	ObservationCount int       `json:"observation_count"`
}

type WebInterface struct {
	IP              string   `json:"ip"`
	Hostname        string   `json:"hostname,omitempty"`
	Port            uint16   `json:"port"`
	Scheme          string   `json:"scheme"`
	URL             string   `json:"url"`
	Title           string   `json:"title,omitempty"`
	Server          string   `json:"server,omitempty"`
	Status          string   `json:"status,omitempty"`
	LoginIndicators []string `json:"login_indicators,omitempty"`
}

type MonitoringStatus struct {
	Target     string        `json:"target"`
	Active     bool          `json:"active"`
	Interval   time.Duration `json:"interval"`
	StartedAt  time.Time     `json:"started_at,omitempty"`
	LastScanAt time.Time     `json:"last_scan_at,omitempty"`
}

type DashboardSummary struct {
	Target        string           `json:"target"`
	Assets        int              `json:"assets"`
	ActiveAssets  int              `json:"active_assets"`
	StaleAssets   int              `json:"stale_assets"`
	OfflineAssets int              `json:"offline_assets"`
	Services      int              `json:"services"`
	Findings      int              `json:"findings"`
	Events        int              `json:"events"`
	Critical      int              `json:"critical"`
	High          int              `json:"high"`
	Medium        int              `json:"medium"`
	Low           int              `json:"low"`
	Info          int              `json:"info"`
	LastScanAt    time.Time        `json:"last_scan_at,omitempty"`
	Monitoring    MonitoringStatus `json:"monitoring"`
}

type Event struct {
	ID        int64     `json:"id"`
	Target    string    `json:"target"`
	Severity  string    `json:"severity"`
	Type      string    `json:"type"`
	Host      string    `json:"host,omitempty"`
	Port      uint16    `json:"port,omitempty"`
	Protocol  string    `json:"protocol,omitempty"`
	Service   string    `json:"service,omitempty"`
	Message   string    `json:"message"`
	CreatedAt time.Time `json:"created_at"`
}

type ChangeType string

const (
	HostAdded      ChangeType = "HOST_ADDED"
	HostRemoved    ChangeType = "HOST_REMOVED"
	ServiceAdded   ChangeType = "SERVICE_ADDED"
	ServiceRemoved ChangeType = "SERVICE_REMOVED"
	ServiceChanged ChangeType = "SERVICE_CHANGED"
)

type Change struct {
	Type       ChangeType `json:"type"`
	Host       string     `json:"host"`
	Port       uint16     `json:"port,omitempty"`
	Protocol   string     `json:"protocol,omitempty"`
	Service    string     `json:"service,omitempty"`
	Previous   string     `json:"previous,omitempty"`
	Current    string     `json:"current,omitempty"`
	DetectedAt time.Time  `json:"detected_at"`
}
