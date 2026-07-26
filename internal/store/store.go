package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/cojjjj/blackterm-sentinel/internal/assets"
	"github.com/cojjjj/blackterm-sentinel/internal/model"
	_ "modernc.org/sqlite"
)

const offlineAfterMisses = 3

type Store struct {
	db *sql.DB
}

func Open(path string) (*Store, error) {
	if dir := filepath.Dir(path); dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, fmt.Errorf("create data directory: %w", err)
		}
	}

	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}

	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate() error {
	schema := `
CREATE TABLE IF NOT EXISTS scans (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	target TEXT NOT NULL,
	interface TEXT NOT NULL DEFAULT '',
	created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS hosts (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	scan_id INTEGER NOT NULL,
	ip TEXT NOT NULL,
	hostname TEXT NOT NULL DEFAULT '',
	mac TEXT NOT NULL DEFAULT '',
	discovery_sources TEXT NOT NULL DEFAULT '',
	FOREIGN KEY(scan_id) REFERENCES scans(id)
);
CREATE TABLE IF NOT EXISTS services (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	host_id INTEGER NOT NULL,
	port INTEGER NOT NULL,
	protocol TEXT NOT NULL,
	name TEXT NOT NULL,
	banner TEXT NOT NULL DEFAULT '',
	metadata_json TEXT NOT NULL DEFAULT '',
	FOREIGN KEY(host_id) REFERENCES hosts(id)
);
CREATE TABLE IF NOT EXISTS changes (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	scan_id INTEGER NOT NULL,
	type TEXT NOT NULL,
	host TEXT NOT NULL,
	port INTEGER NOT NULL DEFAULT 0,
	protocol TEXT NOT NULL DEFAULT '',
	service TEXT NOT NULL DEFAULT '',
	previous TEXT NOT NULL DEFAULT '',
	current TEXT NOT NULL DEFAULT '',
	detected_at TEXT NOT NULL,
	FOREIGN KEY(scan_id) REFERENCES scans(id)
);
CREATE TABLE IF NOT EXISTS findings (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	scan_id INTEGER NOT NULL,
	severity TEXT NOT NULL,
	category TEXT NOT NULL,
	host TEXT NOT NULL,
	port INTEGER NOT NULL DEFAULT 0,
	protocol TEXT NOT NULL DEFAULT '',
	service TEXT NOT NULL DEFAULT '',
	title TEXT NOT NULL,
	detail TEXT NOT NULL,
	recommendation TEXT NOT NULL DEFAULT '',
	FOREIGN KEY(scan_id) REFERENCES scans(id)
);
CREATE TABLE IF NOT EXISTS assets (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	target TEXT NOT NULL,
	identity_key TEXT NOT NULL,
	current_ip TEXT NOT NULL,
	hostname TEXT NOT NULL DEFAULT '',
	mac TEXT NOT NULL DEFAULT '',
	device_type TEXT NOT NULL DEFAULT '',
	state TEXT NOT NULL,
	first_seen TEXT NOT NULL,
	last_seen TEXT NOT NULL,
	observation_count INTEGER NOT NULL DEFAULT 1,
	missed_scans INTEGER NOT NULL DEFAULT 0,
	UNIQUE(target, identity_key)
);
CREATE TABLE IF NOT EXISTS service_history (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	target TEXT NOT NULL,
	identity_key TEXT NOT NULL,
	current_ip TEXT NOT NULL,
	port INTEGER NOT NULL,
	protocol TEXT NOT NULL,
	name TEXT NOT NULL,
	present INTEGER NOT NULL DEFAULT 1,
	first_seen TEXT NOT NULL,
	last_seen TEXT NOT NULL,
	observation_count INTEGER NOT NULL DEFAULT 1,
	UNIQUE(target, identity_key, port, protocol)
);
CREATE TABLE IF NOT EXISTS events (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	target TEXT NOT NULL,
	severity TEXT NOT NULL,
	type TEXT NOT NULL,
	host TEXT NOT NULL DEFAULT '',
	port INTEGER NOT NULL DEFAULT 0,
	protocol TEXT NOT NULL DEFAULT '',
	service TEXT NOT NULL DEFAULT '',
	message TEXT NOT NULL,
	created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS monitoring_status (
	target TEXT PRIMARY KEY,
	active INTEGER NOT NULL DEFAULT 0,
	interval_seconds INTEGER NOT NULL DEFAULT 0,
	started_at TEXT NOT NULL DEFAULT '',
	last_scan_at TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target, id);
CREATE INDEX IF NOT EXISTS idx_hosts_scan ON hosts(scan_id);
CREATE INDEX IF NOT EXISTS idx_services_host ON services(host_id);
CREATE INDEX IF NOT EXISTS idx_changes_scan ON changes(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_assets_target ON assets(target, state, last_seen);
CREATE INDEX IF NOT EXISTS idx_service_history_asset ON service_history(target, identity_key, present);
CREATE INDEX IF NOT EXISTS idx_events_target ON events(target, id);
`
	if _, err := s.db.Exec(schema); err != nil {
		return err
	}

	// Safe upgrades from V0.1/V0.2 databases.
	alter := []string{
		`ALTER TABLE scans ADD COLUMN interface TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE hosts ADD COLUMN mac TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE hosts ADD COLUMN discovery_sources TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE services ADD COLUMN metadata_json TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE assets ADD COLUMN device_type TEXT NOT NULL DEFAULT ''`,
	}
	for _, stmt := range alter {
		if _, err := s.db.Exec(stmt); err != nil {
			msg := strings.ToLower(err.Error())
			if strings.Contains(msg, "duplicate column") ||
				strings.Contains(msg, "already exists") {
				continue
			}
		}
	}

	return nil
}

func (s *Store) SaveSnapshot(snapshot model.Snapshot, changes []model.Change) (int64, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	res, err := tx.Exec(
		"INSERT INTO scans(target, interface, created_at) VALUES(?, ?, ?)",
		snapshot.Target,
		snapshot.Interface,
		snapshot.Timestamp.UTC().Format(time.RFC3339Nano),
	)
	if err != nil {
		return 0, err
	}
	scanID, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}

	for _, h := range snapshot.Hosts {
		res, err := tx.Exec(
			"INSERT INTO hosts(scan_id, ip, hostname, mac, discovery_sources) VALUES(?, ?, ?, ?, ?)",
			scanID,
			h.IP,
			h.Hostname,
			h.MAC,
			strings.Join(h.DiscoverySources, ","),
		)
		if err != nil {
			return 0, err
		}
		hostID, err := res.LastInsertId()
		if err != nil {
			return 0, err
		}

		for _, svc := range h.Services {
			metadata, _ := json.Marshal(struct {
				HTTP *model.HTTPFingerprint `json:"http,omitempty"`
				TLS  *model.TLSFingerprint  `json:"tls,omitempty"`
			}{
				HTTP: svc.HTTP,
				TLS:  svc.TLS,
			})

			_, err = tx.Exec(
				"INSERT INTO services(host_id, port, protocol, name, banner, metadata_json) VALUES(?, ?, ?, ?, ?, ?)",
				hostID,
				svc.Port,
				svc.Protocol,
				svc.Name,
				svc.Banner,
				string(metadata),
			)
			if err != nil {
				return 0, err
			}
		}
	}

	for _, ch := range changes {
		_, err := tx.Exec(`
INSERT INTO changes(scan_id, type, host, port, protocol, service, previous, current, detected_at)
VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			scanID,
			ch.Type,
			ch.Host,
			ch.Port,
			ch.Protocol,
			ch.Service,
			ch.Previous,
			ch.Current,
			ch.DetectedAt.UTC().Format(time.RFC3339Nano),
		)
		if err != nil {
			return 0, err
		}
	}

	for _, finding := range snapshot.Findings {
		_, err := tx.Exec(`
INSERT INTO findings(scan_id, severity, category, host, port, protocol, service, title, detail, recommendation)
VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			scanID,
			finding.Severity,
			finding.Category,
			finding.Host,
			finding.Port,
			finding.Protocol,
			finding.Service,
			finding.Title,
			finding.Detail,
			finding.Recommendation,
		)
		if err != nil {
			return 0, err
		}
	}

	if err := updateAssetIntelligence(tx, snapshot); err != nil {
		return 0, err
	}

	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return scanID, nil
}

func updateAssetIntelligence(tx *sql.Tx, snapshot model.Snapshot) error {
	observedAt := snapshot.Timestamp.UTC().Format(time.RFC3339Nano)

	// Every asset belonging to this target gets one missed observation before
	// this scan's observed hosts are refreshed. This prevents a single missing
	// ARP/cache observation from immediately becoming OFFLINE.
	_, err := tx.Exec(`
UPDATE assets
SET missed_scans = missed_scans + 1,
	state = CASE
		WHEN missed_scans + 1 >= ? THEN ?
		ELSE ?
	END
WHERE target = ?`,
		offlineAfterMisses,
		model.AssetOffline,
		model.AssetStale,
		snapshot.Target,
	)
	if err != nil {
		return err
	}

	_, err = tx.Exec(`
UPDATE service_history
SET present = 0
WHERE target = ?`,
		snapshot.Target,
	)
	if err != nil {
		return err
	}

	for _, host := range snapshot.Hosts {
		identity := assets.IdentityKey(host)

		var existed int
		err := tx.QueryRow(
			"SELECT COUNT(1) FROM assets WHERE target = ? AND identity_key = ?",
			snapshot.Target,
			identity,
		).Scan(&existed)
		if err != nil {
			return err
		}

		if existed == 0 {
			_, err = tx.Exec(`
INSERT INTO assets(
	target, identity_key, current_ip, hostname, mac, device_type, state,
	first_seen, last_seen, observation_count, missed_scans
)
VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, 1, 0)`,
				snapshot.Target,
				identity,
				host.IP,
				host.Hostname,
				host.MAC,
				assets.Classify(host.Hostname, host.Services),
				model.AssetNew,
				observedAt,
				observedAt,
			)
		} else {
			_, err = tx.Exec(`
UPDATE assets
SET current_ip = ?,
	hostname = CASE WHEN ? <> '' THEN ? ELSE hostname END,
	mac = CASE WHEN ? <> '' THEN ? ELSE mac END,
	device_type = ?,
	state = ?,
	last_seen = ?,
	observation_count = observation_count + 1,
	missed_scans = 0
WHERE target = ? AND identity_key = ?`,
				host.IP,
				host.Hostname,
				host.Hostname,
				host.MAC,
				host.MAC,
				assets.Classify(host.Hostname, host.Services),
				model.AssetActive,
				observedAt,
				snapshot.Target,
				identity,
			)
		}
		if err != nil {
			return err
		}

		for _, svc := range host.Services {
			_, err = tx.Exec(`
INSERT INTO service_history(
	target, identity_key, current_ip, port, protocol, name,
	present, first_seen, last_seen, observation_count
)
VALUES(?, ?, ?, ?, ?, ?, 1, ?, ?, 1)
ON CONFLICT(target, identity_key, port, protocol)
DO UPDATE SET
	current_ip = excluded.current_ip,
	name = excluded.name,
	present = 1,
	last_seen = excluded.last_seen,
	observation_count = service_history.observation_count + 1`,
				snapshot.Target,
				identity,
				host.IP,
				svc.Port,
				svc.Protocol,
				svc.Name,
				observedAt,
				observedAt,
			)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func (s *Store) LatestSnapshot(target string) (model.Snapshot, bool, error) {
	row := s.db.QueryRow(
		"SELECT id, target, interface, created_at FROM scans WHERE target = ? ORDER BY id DESC LIMIT 1",
		target,
	)

	var snap model.Snapshot
	var created string
	if err := row.Scan(&snap.ID, &snap.Target, &snap.Interface, &created); err != nil {
		if err == sql.ErrNoRows {
			return model.Snapshot{}, false, nil
		}
		return model.Snapshot{}, false, err
	}

	t, err := time.Parse(time.RFC3339Nano, created)
	if err != nil {
		return model.Snapshot{}, false, err
	}
	snap.Timestamp = t

	hosts, err := s.db.Query(`
SELECT id, ip, hostname, mac, discovery_sources
FROM hosts
WHERE scan_id = ?
ORDER BY ip`, snap.ID)
	if err != nil {
		return model.Snapshot{}, false, err
	}
	defer hosts.Close()

	for hosts.Next() {
		var hostID int64
		var h model.Host
		var sources string
		if err := hosts.Scan(&hostID, &h.IP, &h.Hostname, &h.MAC, &sources); err != nil {
			return model.Snapshot{}, false, err
		}
		if sources != "" {
			h.DiscoverySources = strings.Split(sources, ",")
		}

		rows, err := s.db.Query(`
SELECT port, protocol, name, banner, metadata_json
FROM services
WHERE host_id = ?
ORDER BY port`, hostID)
		if err != nil {
			return model.Snapshot{}, false, err
		}

		for rows.Next() {
			var svc model.Service
			var metadata string
			if err := rows.Scan(
				&svc.Port,
				&svc.Protocol,
				&svc.Name,
				&svc.Banner,
				&metadata,
			); err != nil {
				rows.Close()
				return model.Snapshot{}, false, err
			}

			if metadata != "" {
				var decoded struct {
					HTTP *model.HTTPFingerprint `json:"http,omitempty"`
					TLS  *model.TLSFingerprint  `json:"tls,omitempty"`
				}
				if json.Unmarshal([]byte(metadata), &decoded) == nil {
					svc.HTTP = decoded.HTTP
					svc.TLS = decoded.TLS
				}
			}
			h.Services = append(h.Services, svc)
		}

		if err := rows.Err(); err != nil {
			rows.Close()
			return model.Snapshot{}, false, err
		}
		rows.Close()

		snap.Hosts = append(snap.Hosts, h)
	}

	return snap, true, hosts.Err()
}

func (s *Store) ListLatest(limit int) ([]model.Snapshot, error) {
	if limit <= 0 {
		limit = 20
	}

	rows, err := s.db.Query(`
SELECT id, target, interface, created_at
FROM scans
ORDER BY id DESC
LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []model.Snapshot
	for rows.Next() {
		var snap model.Snapshot
		var created string

		if err := rows.Scan(
			&snap.ID,
			&snap.Target,
			&snap.Interface,
			&created,
		); err != nil {
			return nil, err
		}

		snap.Timestamp, _ = time.Parse(time.RFC3339Nano, created)
		out = append(out, snap)
	}
	return out, rows.Err()
}

func (s *Store) RecentChanges(limit int) ([]model.Change, error) {
	if limit <= 0 {
		limit = 50
	}

	rows, err := s.db.Query(`
SELECT type, host, port, protocol, service, previous, current, detected_at
FROM changes
ORDER BY id DESC
LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []model.Change
	for rows.Next() {
		var ch model.Change
		var t, detected string

		if err := rows.Scan(
			&t,
			&ch.Host,
			&ch.Port,
			&ch.Protocol,
			&ch.Service,
			&ch.Previous,
			&ch.Current,
			&detected,
		); err != nil {
			return nil, err
		}

		ch.Type = model.ChangeType(t)
		ch.DetectedAt, _ = time.Parse(time.RFC3339Nano, detected)
		out = append(out, ch)
	}
	return out, rows.Err()
}

func (s *Store) RecentFindings(limit int) ([]model.Finding, error) {
	if limit <= 0 {
		limit = 100
	}

	rows, err := s.db.Query(`
SELECT severity, category, host, port, protocol, service, title, detail, recommendation
FROM findings
ORDER BY id DESC
LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []model.Finding
	for rows.Next() {
		var finding model.Finding
		if err := rows.Scan(
			&finding.Severity,
			&finding.Category,
			&finding.Host,
			&finding.Port,
			&finding.Protocol,
			&finding.Service,
			&finding.Title,
			&finding.Detail,
			&finding.Recommendation,
		); err != nil {
			return nil, err
		}
		out = append(out, finding)
	}
	return out, rows.Err()
}

func (s *Store) Assets(target string) ([]model.AssetRecord, error) {
	var (
		rows *sql.Rows
		err  error
	)

	if strings.TrimSpace(target) == "" {
		rows, err = s.db.Query(`
SELECT target, identity_key, current_ip, hostname, mac, device_type, state,
	first_seen, last_seen, observation_count, missed_scans
FROM assets
ORDER BY target, current_ip`)
	} else {
		rows, err = s.db.Query(`
SELECT target, identity_key, current_ip, hostname, mac, device_type, state,
	first_seen, last_seen, observation_count, missed_scans
FROM assets
WHERE target = ?
ORDER BY current_ip`, target)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []model.AssetRecord
	for rows.Next() {
		var asset model.AssetRecord
		var state, firstSeen, lastSeen string

		if err := rows.Scan(
			&asset.Target,
			&asset.IdentityKey,
			&asset.IP,
			&asset.Hostname,
			&asset.MAC,
			&asset.DeviceType,
			&state,
			&firstSeen,
			&lastSeen,
			&asset.ObservationCount,
			&asset.MissedScans,
		); err != nil {
			return nil, err
		}

		asset.State = model.AssetState(state)
		asset.FirstSeen, _ = time.Parse(time.RFC3339Nano, firstSeen)
		asset.LastSeen, _ = time.Parse(time.RFC3339Nano, lastSeen)
		out = append(out, asset)
	}

	return out, rows.Err()
}

func (s *Store) AssetHistory(query string) ([]model.AssetRecord, []model.ServiceHistory, error) {
	pattern := "%" + strings.TrimSpace(query) + "%"

	rows, err := s.db.Query(`
SELECT target, identity_key, current_ip, hostname, mac, device_type, state,
	first_seen, last_seen, observation_count, missed_scans
FROM assets
WHERE current_ip = ?
	OR mac = ?
	OR hostname LIKE ?
	OR identity_key = ?
ORDER BY last_seen DESC`,
		query,
		strings.ToUpper(query),
		pattern,
		query,
	)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()

	var assetRecords []model.AssetRecord
	var identityKeys []string

	for rows.Next() {
		var asset model.AssetRecord
		var state, firstSeen, lastSeen string

		if err := rows.Scan(
			&asset.Target,
			&asset.IdentityKey,
			&asset.IP,
			&asset.Hostname,
			&asset.MAC,
			&asset.DeviceType,
			&state,
			&firstSeen,
			&lastSeen,
			&asset.ObservationCount,
			&asset.MissedScans,
		); err != nil {
			return nil, nil, err
		}

		asset.State = model.AssetState(state)
		asset.FirstSeen, _ = time.Parse(time.RFC3339Nano, firstSeen)
		asset.LastSeen, _ = time.Parse(time.RFC3339Nano, lastSeen)
		assetRecords = append(assetRecords, asset)
		identityKeys = append(identityKeys, asset.IdentityKey)
	}

	var histories []model.ServiceHistory
	for _, identity := range identityKeys {
		serviceRows, err := s.db.Query(`
SELECT target, identity_key, current_ip, port, protocol, name, present,
	first_seen, last_seen, observation_count
FROM service_history
WHERE identity_key = ?
ORDER BY port`, identity)
		if err != nil {
			return nil, nil, err
		}

		for serviceRows.Next() {
			var history model.ServiceHistory
			var present int
			var firstSeen, lastSeen string

			if err := serviceRows.Scan(
				&history.Target,
				&history.IdentityKey,
				&history.IP,
				&history.Port,
				&history.Protocol,
				&history.Name,
				&present,
				&firstSeen,
				&lastSeen,
				&history.ObservationCount,
			); err != nil {
				serviceRows.Close()
				return nil, nil, err
			}

			history.Present = present == 1
			history.FirstSeen, _ = time.Parse(time.RFC3339Nano, firstSeen)
			history.LastSeen, _ = time.Parse(time.RFC3339Nano, lastSeen)
			histories = append(histories, history)
		}

		if err := serviceRows.Err(); err != nil {
			serviceRows.Close()
			return nil, nil, err
		}
		serviceRows.Close()
	}

	return assetRecords, histories, nil
}

func (s *Store) KnownAssetIPs(target string) ([]string, error) {
	rows, err := s.db.Query(`
SELECT current_ip
FROM assets
WHERE target = ?
	AND state <> ?
ORDER BY current_ip`,
		target,
		model.AssetOffline,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []string
	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err != nil {
			return nil, err
		}
		out = append(out, ip)
	}
	return out, rows.Err()
}

func (s *Store) WebInterfaces(query string) ([]model.WebInterface, error) {
	query = strings.TrimSpace(query)
	if query == "" {
		return nil, fmt.Errorf("device query cannot be empty")
	}

	rows, err := s.db.Query(`
SELECT h.ip, h.hostname, s.port, s.name, s.metadata_json
FROM hosts h
JOIN services s ON s.host_id = h.id
JOIN scans sc ON sc.id = h.scan_id
WHERE sc.id = (
	SELECT MAX(sc2.id)
	FROM scans sc2
	JOIN hosts h2 ON h2.scan_id = sc2.id
	WHERE h2.ip = ?
		OR LOWER(h2.hostname) = LOWER(?)
)
AND (h.ip = ? OR LOWER(h.hostname) = LOWER(?))
AND UPPER(s.name) IN ('HTTP', 'HTTPS')
ORDER BY CASE WHEN UPPER(s.name) = 'HTTPS' THEN 0 ELSE 1 END, s.port`,
		query, query, query, query,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []model.WebInterface

	for rows.Next() {
		var (
			ip       string
			hostname string
			port     uint16
			name     string
			metadata string
		)

		if err := rows.Scan(&ip, &hostname, &port, &name, &metadata); err != nil {
			return nil, err
		}

		scheme := "http"
		if strings.EqualFold(name, "HTTPS") {
			scheme = "https"
		}

		web := model.WebInterface{
			IP:       ip,
			Hostname: hostname,
			Port:     port,
			Scheme:   scheme,
			URL:      fmt.Sprintf("%s://%s:%d/", scheme, ip, port),
		}

		if metadata != "" {
			var decoded struct {
				HTTP *model.HTTPFingerprint `json:"http,omitempty"`
				TLS  *model.TLSFingerprint  `json:"tls,omitempty"`
			}
			if json.Unmarshal([]byte(metadata), &decoded) == nil && decoded.HTTP != nil {
				web.Title = decoded.HTTP.Title
				web.Server = decoded.HTTP.Server
				web.Status = decoded.HTTP.Status
				web.LoginIndicators = append([]string(nil), decoded.HTTP.LoginIndicators...)
			}
		}

		out = append(out, web)
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	// Prefer interfaces with explicit login/auth signals, then HTTPS.
	sort.SliceStable(out, func(i, j int) bool {
		iLogin := len(out[i].LoginIndicators) > 0
		jLogin := len(out[j].LoginIndicators) > 0

		if iLogin != jLogin {
			return iLogin
		}
		if out[i].Scheme != out[j].Scheme {
			return out[i].Scheme == "https"
		}
		return out[i].Port < out[j].Port
	})

	return out, nil
}

func (s *Store) LatestWebInterfaces(target string) ([]model.WebInterface, error) {
	target = strings.TrimSpace(target)

	var (
		scanID int64
		err    error
	)

	if target == "" {
		err = s.db.QueryRow(`
SELECT id
FROM scans
ORDER BY id DESC
LIMIT 1`).Scan(&scanID)
	} else {
		err = s.db.QueryRow(`
SELECT id
FROM scans
WHERE target = ?
ORDER BY id DESC
LIMIT 1`, target).Scan(&scanID)
	}

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}

	rows, err := s.db.Query(`
SELECT h.ip, h.hostname, s.port, s.name, s.metadata_json
FROM hosts h
JOIN services s ON s.host_id = h.id
WHERE h.scan_id = ?
	AND UPPER(s.name) IN ('HTTP', 'HTTPS')
ORDER BY h.ip,
	CASE WHEN UPPER(s.name) = 'HTTPS' THEN 0 ELSE 1 END,
	s.port`, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []model.WebInterface

	for rows.Next() {
		var (
			ip       string
			hostname string
			port     uint16
			name     string
			metadata string
		)

		if err := rows.Scan(&ip, &hostname, &port, &name, &metadata); err != nil {
			return nil, err
		}

		scheme := "http"
		if strings.EqualFold(name, "HTTPS") {
			scheme = "https"
		}

		web := model.WebInterface{
			IP:       ip,
			Hostname: hostname,
			Port:     port,
			Scheme:   scheme,
			URL:      fmt.Sprintf("%s://%s:%d/", scheme, ip, port),
		}

		if metadata != "" {
			var decoded struct {
				HTTP *model.HTTPFingerprint `json:"http,omitempty"`
				TLS  *model.TLSFingerprint  `json:"tls,omitempty"`
			}
			if json.Unmarshal([]byte(metadata), &decoded) == nil && decoded.HTTP != nil {
				web.Title = decoded.HTTP.Title
				web.Server = decoded.HTTP.Server
				web.Status = decoded.HTTP.Status
				web.LoginIndicators = append([]string(nil), decoded.HTTP.LoginIndicators...)
			}
		}

		out = append(out, web)
	}

	return out, rows.Err()
}

func (s *Store) SaveEvents(events []model.Event) error {
	if len(events) == 0 {
		return nil
	}

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	for _, event := range events {
		_, err := tx.Exec(`
INSERT INTO events(target, severity, type, host, port, protocol, service, message, created_at)
VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			event.Target,
			event.Severity,
			event.Type,
			event.Host,
			event.Port,
			event.Protocol,
			event.Service,
			event.Message,
			event.CreatedAt.UTC().Format(time.RFC3339Nano),
		)
		if err != nil {
			return err
		}
	}

	return tx.Commit()
}

func (s *Store) RecentEvents(target string, limit int) ([]model.Event, error) {
	if limit <= 0 {
		limit = 100
	}

	var (
		rows *sql.Rows
		err  error
	)

	if strings.TrimSpace(target) == "" {
		rows, err = s.db.Query(`
SELECT id, target, severity, type, host, port, protocol, service, message, created_at
FROM events
ORDER BY id DESC
LIMIT ?`, limit)
	} else {
		rows, err = s.db.Query(`
SELECT id, target, severity, type, host, port, protocol, service, message, created_at
FROM events
WHERE target = ?
ORDER BY id DESC
LIMIT ?`, target, limit)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []model.Event
	for rows.Next() {
		var event model.Event
		var created string

		if err := rows.Scan(
			&event.ID,
			&event.Target,
			&event.Severity,
			&event.Type,
			&event.Host,
			&event.Port,
			&event.Protocol,
			&event.Service,
			&event.Message,
			&created,
		); err != nil {
			return nil, err
		}

		event.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
		out = append(out, event)
	}

	return out, rows.Err()
}

func (s *Store) SetMonitoringStatus(status model.MonitoringStatus) error {
	started := ""
	lastScan := ""

	if !status.StartedAt.IsZero() {
		started = status.StartedAt.UTC().Format(time.RFC3339Nano)
	}
	if !status.LastScanAt.IsZero() {
		lastScan = status.LastScanAt.UTC().Format(time.RFC3339Nano)
	}

	active := 0
	if status.Active {
		active = 1
	}

	_, err := s.db.Exec(`
INSERT INTO monitoring_status(target, active, interval_seconds, started_at, last_scan_at)
VALUES(?, ?, ?, ?, ?)
ON CONFLICT(target)
DO UPDATE SET
	active = excluded.active,
	interval_seconds = excluded.interval_seconds,
	started_at = CASE
		WHEN excluded.started_at <> '' THEN excluded.started_at
		ELSE monitoring_status.started_at
	END,
	last_scan_at = CASE
		WHEN excluded.last_scan_at <> '' THEN excluded.last_scan_at
		ELSE monitoring_status.last_scan_at
	END`,
		status.Target,
		active,
		int64(status.Interval.Seconds()),
		started,
		lastScan,
	)

	return err
}

func (s *Store) MonitoringStatus(target string) (model.MonitoringStatus, error) {
	status := model.MonitoringStatus{Target: target}

	var (
		active          int
		intervalSeconds int64
		started         string
		lastScan        string
	)

	err := s.db.QueryRow(`
SELECT active, interval_seconds, started_at, last_scan_at
FROM monitoring_status
WHERE target = ?`, target).Scan(
		&active,
		&intervalSeconds,
		&started,
		&lastScan,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return status, nil
		}
		return status, err
	}

	status.Active = active == 1
	status.Interval = time.Duration(intervalSeconds) * time.Second
	if started != "" {
		status.StartedAt, _ = time.Parse(time.RFC3339Nano, started)
	}
	if lastScan != "" {
		status.LastScanAt, _ = time.Parse(time.RFC3339Nano, lastScan)
	}

	return status, nil
}

func (s *Store) DashboardSummary(target string) (model.DashboardSummary, error) {
	summary := model.DashboardSummary{Target: target}

	assets, err := s.Assets(target)
	if err != nil {
		return summary, err
	}

	summary.Assets = len(assets)
	for _, asset := range assets {
		switch asset.State {
		case model.AssetActive, model.AssetNew:
			summary.ActiveAssets++
		case model.AssetStale:
			summary.StaleAssets++
		case model.AssetOffline:
			summary.OfflineAssets++
		}
	}

	snapshot, ok, err := s.LatestSnapshot(target)
	if err != nil {
		return summary, err
	}
	if ok {
		summary.LastScanAt = snapshot.Timestamp
		for _, host := range snapshot.Hosts {
			summary.Services += len(host.Services)
		}
	}

	findings, err := s.RecentFindings(1000)
	if err != nil {
		return summary, err
	}
	for _, finding := range findings {
		switch strings.ToUpper(finding.Severity) {
		case "CRITICAL":
			summary.Critical++
		case "HIGH":
			summary.High++
		case "MEDIUM":
			summary.Medium++
		case "LOW":
			summary.Low++
		case "INFO":
			summary.Info++
		}
	}
	summary.Findings = len(findings)

	events, err := s.RecentEvents(target, 1000)
	if err != nil {
		return summary, err
	}
	summary.Events = len(events)

	monitoring, err := s.MonitoringStatus(target)
	if err != nil {
		return summary, err
	}
	summary.Monitoring = monitoring

	return summary, nil
}
