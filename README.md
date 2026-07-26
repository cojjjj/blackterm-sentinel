# 🛰️ BLACKTERM // SENTINEL

**NETWORK STATE INTELLIGENCE**

> Observe the network.  
> Remember the baseline.  
> Detect the change.

Sentinel is a defensive, Go-based network visibility engine for networks and systems you own or are explicitly authorized to test.

V0.1 focuses on a simple loop:

**Discover → Inspect → Snapshot → Compare → Report**

It is intentionally not an exploitation framework and not designed to bypass authorization boundaries.

## What V0.1 does

- Accepts a single IPv4 address or IPv4 CIDR
- Concurrent TCP connect scanning with a bounded worker pool
- Rate limiting and connection timeouts
- Common service-name fingerprinting by port
- SQLite snapshot persistence
- Baseline comparison
- Host/service added and removed detection
- Terminal reports
- JSON output
- Graceful cancellation with Ctrl+C
- Unit tests for CIDR expansion and change detection

## Requirements

- Go 1.22+
- No C compiler is required. Sentinel uses a pure-Go SQLite driver.

## Build

```bash
go mod tidy
go test ./...
go build -o sentinel ./cmd/sentinel
```

Windows PowerShell:

```powershell
go mod tidy
go test ./...
go build -o sentinel.exe ./cmd/sentinel
```

## Scan

Only scan systems you own or have explicit permission to test.

```bash
sentinel scan 192.168.1.0/24
```

Windows:

```powershell
.\sentinel.exe scan 192.168.1.0/24
```

Custom ports:

```bash
sentinel scan 192.168.1.0/24 --ports 22,80,443,445,3306,8080
```

Tune concurrency:

```bash
sentinel scan 192.168.1.0/24 --workers 64 --rate 200 --timeout 800ms
```

JSON:

```bash
sentinel scan 192.168.1.0/24 --json
```

## Inventory

```bash
sentinel inventory
```

## Changes

```bash
sentinel changes
```

## Change demo

First scan:

```text
BLACKTERM // SENTINEL
NETWORK STATE INTELLIGENCE

TARGET     192.168.56.0/24
STATUS     COMPLETE

[+] 192.168.56.10
    22/tcp    SSH

HOSTS      1
SERVICES   1
CHANGES    0
FINDINGS   0
```

Start an HTTP service on an authorized lab machine and scan again:

```text
CHANGE DETECTED

192.168.56.10
+ 8080/tcp HTTP
```

The project stores each scan in SQLite and compares the new network state to the most recent snapshot for the same target string.

## Data location

By default:

```text
~/.sentinel/sentinel.db
```

Override it:

```bash
sentinel --db ./sentinel.db scan 127.0.0.1
```

or set:

```text
SENTINEL_DB=/path/to/sentinel.db
```

## Architecture

```text
Target / CIDR
     │
     ▼
Address Expansion
     │
     ▼
 Bounded Worker Pool
     │
     ▼
 TCP Connect Checks
     │
     ▼
 Service Fingerprint
     │
     ▼
 Inventory Snapshot
     │
     ├──────► SQLite History
     │
     ▼
 Previous Baseline
     │
     ▼
   Diff Engine
     │
     ▼
Terminal / JSON Report
```

## Current V0.1 limits

- IPv4 only
- TCP connect scanning only
- Port-based service naming
- No raw-packet SYN scanning
- No UDP scanning
- No OS fingerprinting
- No CVE correlation
- No exploitation
- No web dashboard

Those are intentional scope boundaries.

## Suggested roadmap

### V0.2 — FINGERPRINT
HTTP metadata, TLS certificates, SSH banners, DNS enrichment.

### V0.3 — WATCH
Scheduled authorized scans, richer history, severity scoring, notifications.

### V0.4 — ANALYZE
Security header review, certificate warnings, exposure analysis, public CVE correlation.

### V1.0 — SENTINEL
Stable CLI, configuration profiles, cross-platform releases, reporting, strong test coverage.

## License

MIT
