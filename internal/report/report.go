package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/cojjjj/blackterm-sentinel/internal/analysis"
	"github.com/cojjjj/blackterm-sentinel/internal/model"
)

const banner = `BLACKTERM // SENTINEL
NETWORK STATE INTELLIGENCE

Observe the network.
Remember the baseline.
Detect the change.`

func Banner(w io.Writer) {
	fmt.Fprintln(w, banner)
	fmt.Fprintln(w)
}

func Scan(w io.Writer, snapshot model.Snapshot, changes []model.Change, verbose bool) {
	fmt.Fprintf(w, "TARGET      %s\n", snapshot.Target)
	if snapshot.Interface != "" {
		fmt.Fprintf(w, "INTERFACE   %s\n", snapshot.Interface)
	}
	fmt.Fprintln(w, "STATUS      COMPLETE")
	fmt.Fprintln(w)

	for _, h := range snapshot.Hosts {
		fmt.Fprintf(w, "[+] %s\n", h.IP)

		if h.Hostname != "" {
			fmt.Fprintf(w, "    HOSTNAME    %s\n", h.Hostname)
		} else {
			fmt.Fprintln(w, "    HOSTNAME    unknown")
		}

		if h.MAC != "" {
			fmt.Fprintf(w, "    MAC         %s\n", h.MAC)
		}

		if len(h.DiscoverySources) > 0 {
			fmt.Fprintf(w, "    DISCOVERY   %s\n", strings.Join(h.DiscoverySources, " + "))
		}

		if len(h.Services) > 0 {
			fmt.Fprintln(w)
			fmt.Fprintln(w, "    SERVICES")
			for _, svc := range h.Services {
				fmt.Fprintf(w, "    %-11s %s\n", fmt.Sprintf("%d/%s", svc.Port, svc.Protocol), svc.Name)
				if verbose {
					printFingerprint(w, svc)
				}
			}
		}

		fmt.Fprintln(w)
	}

	fmt.Fprintln(w, strings.Repeat("─", 44))
	fmt.Fprintln(w)

	services := 0
	responsive := 0
	for _, h := range snapshot.Hosts {
		services += len(h.Services)
		if hasSource(h.DiscoverySources, "TCP") || hasSource(h.DiscoverySources, "ICMP") {
			responsive++
		}
	}

	fmt.Fprintf(w, "ASSETS       %d\n", len(snapshot.Hosts))
	fmt.Fprintf(w, "RESPONSIVE   %d\n", responsive)
	fmt.Fprintf(w, "SERVICES     %d\n", services)
	fmt.Fprintf(w, "CHANGES      %d\n", len(changes))
	fmt.Fprintf(w, "FINDINGS     %d\n", len(snapshot.Findings))

	if len(snapshot.Findings) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "SECURITY ANALYSIS")
		fmt.Fprintln(w, analysis.Summary(snapshot.Findings))

		important := filterImportant(snapshot.Findings)
		if verbose {
			printFindings(w, snapshot.Findings)
		} else if len(important) > 0 {
			fmt.Fprintln(w)
			fmt.Fprintln(w, "IMPORTANT FINDINGS")
			printFindings(w, important)
			fmt.Fprintln(w)
			fmt.Fprintln(w, "Use --verbose to show LOW and INFO findings.")
		} else {
			fmt.Fprintln(w)
			fmt.Fprintln(w, "No HIGH or MEDIUM findings in this scan.")
			fmt.Fprintln(w, "Use --verbose to show LOW and INFO findings.")
		}
	}

	if len(changes) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "CHANGE DETECTED")
		fmt.Fprintln(w)
		sorted := append([]model.Change(nil), changes...)
		sort.SliceStable(sorted, func(i, j int) bool {
			if sorted[i].Host == sorted[j].Host {
				return sorted[i].Port < sorted[j].Port
			}
			return sorted[i].Host < sorted[j].Host
		})
		lastHost := ""
		for _, ch := range sorted {
			if ch.Host != lastHost {
				if lastHost != "" {
					fmt.Fprintln(w)
				}
				fmt.Fprintln(w, ch.Host)
				lastHost = ch.Host
			}
			switch ch.Type {
			case model.HostAdded:
				fmt.Fprintln(w, "+ host discovered")
			case model.HostRemoved:
				fmt.Fprintln(w, "- host no longer observed")
			case model.ServiceAdded:
				fmt.Fprintf(w, "+ %d/%s %s\n", ch.Port, ch.Protocol, ch.Service)
			case model.ServiceRemoved:
				fmt.Fprintf(w, "- %d/%s %s\n", ch.Port, ch.Protocol, ch.Service)
			case model.ServiceChanged:
				fmt.Fprintf(w, "~ %d/%s %s\n", ch.Port, ch.Protocol, ch.Service)
			}
		}
		fmt.Fprintf(w, "\nObserved: %s\n", snapshot.Timestamp.Local().Format("2006-01-02 15:04:05"))
	}
}

func Findings(w io.Writer, findings []model.Finding) {
	Banner(w)

	if len(findings) == 0 {
		fmt.Fprintln(w, "No stored findings.")
		return
	}

	fmt.Fprintln(w, "RECENT FINDINGS")
	fmt.Fprintln(w, analysis.Summary(findings))
	printFindings(w, findings)
}

func printFindings(w io.Writer, findings []model.Finding) {
	sorted := append([]model.Finding(nil), findings...)
	sort.SliceStable(sorted, func(i, j int) bool {
		if severityRank(sorted[i].Severity) == severityRank(sorted[j].Severity) {
			if sorted[i].Host == sorted[j].Host {
				return sorted[i].Port < sorted[j].Port
			}
			return sorted[i].Host < sorted[j].Host
		}
		return severityRank(sorted[i].Severity) < severityRank(sorted[j].Severity)
	})

	for _, f := range sorted {
		fmt.Fprintln(w)
		fmt.Fprintf(w, "[%s] %s\n", f.Severity, f.Title)
		fmt.Fprintf(w, "CATEGORY     %s\n", f.Category)
		fmt.Fprintf(w, "HOST         %s\n", f.Host)
		if f.Port > 0 {
			fmt.Fprintf(w, "SERVICE      %d/%s %s\n", f.Port, f.Protocol, f.Service)
		}
		fmt.Fprintf(w, "DETAIL       %s\n", f.Detail)
		if f.Recommendation != "" {
			fmt.Fprintf(w, "RECOMMEND    %s\n", f.Recommendation)
		}
	}
}

func filterImportant(findings []model.Finding) []model.Finding {
	var out []model.Finding
	for _, f := range findings {
		switch f.Severity {
		case "CRITICAL", "HIGH", "MEDIUM":
			out = append(out, f)
		}
	}
	return out
}

func printFingerprint(w io.Writer, svc model.Service) {
	if svc.HTTP != nil {
		if svc.HTTP.Status != "" {
			fmt.Fprintf(w, "        STATUS       %s\n", svc.HTTP.Status)
		}
		if svc.HTTP.Title != "" {
			fmt.Fprintf(w, "        TITLE        %s\n", svc.HTTP.Title)
		}
		if svc.HTTP.Server != "" {
			fmt.Fprintf(w, "        SERVER       %s\n", svc.HTTP.Server)
		}
		if svc.HTTP.ContentType != "" {
			fmt.Fprintf(w, "        CONTENT-TYPE %s\n", svc.HTTP.ContentType)
		}
		if len(svc.HTTP.LoginIndicators) > 0 {
			fmt.Fprintf(w, "        AUTH SIGNALS %s\n", strings.Join(svc.HTTP.LoginIndicators, ", "))
		}
		if len(svc.HTTP.Headers) > 0 {
			fmt.Fprintf(w, "        SEC HEADERS  %d observed\n", len(svc.HTTP.Headers))
		}
	}

	if svc.TLS != nil {
		if svc.TLS.Version != "" {
			fmt.Fprintf(w, "        TLS          %s\n", svc.TLS.Version)
		}
		if svc.TLS.CipherSuite != "" {
			fmt.Fprintf(w, "        CIPHER       %s\n", svc.TLS.CipherSuite)
		}
		if svc.TLS.Subject != "" {
			fmt.Fprintf(w, "        CERT SUBJECT %s\n", svc.TLS.Subject)
		}
		if svc.TLS.Issuer != "" {
			fmt.Fprintf(w, "        CERT ISSUER  %s\n", svc.TLS.Issuer)
		}
		if !svc.TLS.NotAfter.IsZero() {
			fmt.Fprintf(w, "        CERT EXPIRES %s (%d days)\n", svc.TLS.NotAfter.Format(time.DateOnly), svc.TLS.DaysRemaining)
		}
	}
}

func Inventory(w io.Writer, snaps []model.Snapshot) {
	Banner(w)
	if len(snaps) == 0 {
		fmt.Fprintln(w, "No snapshots stored yet.")
		return
	}
	fmt.Fprintln(w, "RECENT SNAPSHOTS")
	fmt.Fprintln(w)
	for _, s := range snaps {
		if s.Interface != "" {
			fmt.Fprintf(w, "#%-4d %-22s %-15s %s\n", s.ID, s.Target, s.Interface, s.Timestamp.Local().Format(time.DateTime))
		} else {
			fmt.Fprintf(w, "#%-4d %-22s %s\n", s.ID, s.Target, s.Timestamp.Local().Format(time.DateTime))
		}
	}
}

func Changes(w io.Writer, changes []model.Change) {
	Banner(w)
	if len(changes) == 0 {
		fmt.Fprintln(w, "No changes recorded yet.")
		return
	}
	fmt.Fprintln(w, "RECENT CHANGES")
	fmt.Fprintln(w)
	for _, ch := range changes {
		sign := "~"
		switch ch.Type {
		case model.HostAdded, model.ServiceAdded:
			sign = "+"
		case model.HostRemoved, model.ServiceRemoved:
			sign = "-"
		}
		if ch.Port > 0 {
			fmt.Fprintf(w, "%s %-15s %5d/%-3s %-16s %s\n", sign, ch.Host, ch.Port, ch.Protocol, ch.Service, ch.DetectedAt.Local().Format(time.DateTime))
		} else {
			fmt.Fprintf(w, "%s %-15s %-26s %s\n", sign, ch.Host, ch.Type, ch.DetectedAt.Local().Format(time.DateTime))
		}
	}
}

func JSON(w io.Writer, snapshot model.Snapshot, changes []model.Change) error {
	payload := struct {
		Snapshot model.Snapshot `json:"snapshot"`
		Changes  []model.Change `json:"changes"`
	}{
		Snapshot: snapshot,
		Changes:  changes,
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(payload)
}

func hasSource(sources []string, wanted string) bool {
	for _, source := range sources {
		if source == wanted {
			return true
		}
	}
	return false
}

func severityRank(severity string) int {
	switch severity {
	case "CRITICAL":
		return 0
	case "HIGH":
		return 1
	case "MEDIUM":
		return 2
	case "LOW":
		return 3
	case "INFO":
		return 4
	default:
		return 5
	}
}

func Assets(w io.Writer, assets []model.AssetRecord, detailed bool) {
	Banner(w)

	if len(assets) == 0 {
		fmt.Fprintln(w, "No persistent assets recorded yet.")
		return
	}

	fmt.Fprintln(w, "ASSET INTELLIGENCE")
	fmt.Fprintln(w)

	counts := map[model.AssetState]int{}
	for _, asset := range assets {
		counts[asset.State]++
	}

	fmt.Fprintf(
		w,
		"NEW %d | ACTIVE %d | STALE %d | OFFLINE %d\n\n",
		counts[model.AssetNew],
		counts[model.AssetActive],
		counts[model.AssetStale],
		counts[model.AssetOffline],
	)

	if !detailed {
		fmt.Fprintf(w, "%-15s %-24s %-12s %-9s %-5s\n", "IP", "HOSTNAME", "TYPE", "STATE", "SEEN")
		fmt.Fprintln(w, strings.Repeat("─", 72))

		for _, asset := range assets {
			hostname := asset.Hostname
			if hostname == "" {
				hostname = "unknown"
			}
			deviceType := asset.DeviceType
			if deviceType == "" {
				deviceType = "UNKNOWN"
			}

			fmt.Fprintf(
				w,
				"%-15s %-24s %-12s %-9s %-5d\n",
				asset.IP,
				truncate(hostname, 24),
				deviceType,
				asset.State,
				asset.ObservationCount,
			)
		}

		fmt.Fprintln(w)
		fmt.Fprintln(w, "Use --details for full asset records.")
		return
	}

	for _, asset := range assets {
		fmt.Fprintf(w, "[%s] %s\n", asset.State, asset.IP)

		if asset.Hostname != "" {
			fmt.Fprintf(w, "    HOSTNAME     %s\n", asset.Hostname)
		}
		if asset.MAC != "" {
			fmt.Fprintf(w, "    MAC          %s\n", asset.MAC)
		}
		if asset.DeviceType != "" {
			fmt.Fprintf(w, "    TYPE         %s\n", asset.DeviceType)
		}

		fmt.Fprintf(w, "    FIRST SEEN   %s\n", asset.FirstSeen.Local().Format(time.DateTime))
		fmt.Fprintf(w, "    LAST SEEN    %s\n", asset.LastSeen.Local().Format(time.DateTime))
		fmt.Fprintf(w, "    OBSERVATIONS %d\n", asset.ObservationCount)

		if asset.MissedScans > 0 {
			fmt.Fprintf(w, "    MISSED SCANS %d\n", asset.MissedScans)
		}

		fmt.Fprintln(w)
	}
}

func truncate(value string, width int) string {
	if len(value) <= width {
		return value
	}
	if width <= 1 {
		return value[:width]
	}
	return value[:width-1] + "…"
}

func AssetHistory(w io.Writer, assets []model.AssetRecord, services []model.ServiceHistory) {
	Banner(w)

	if len(assets) == 0 {
		fmt.Fprintln(w, "No matching asset history found.")
		return
	}

	fmt.Fprintln(w, "ASSET HISTORY")
	fmt.Fprintln(w)

	for _, asset := range assets {
		fmt.Fprintf(w, "[%s] %s\n", asset.State, asset.IP)

		if asset.Hostname != "" {
			fmt.Fprintf(w, "HOSTNAME      %s\n", asset.Hostname)
		}
		if asset.MAC != "" {
			fmt.Fprintf(w, "MAC           %s\n", asset.MAC)
		}

		fmt.Fprintf(w, "IDENTITY      %s\n", asset.IdentityKey)
		fmt.Fprintf(w, "FIRST SEEN    %s\n", asset.FirstSeen.Local().Format(time.DateTime))
		fmt.Fprintf(w, "LAST SEEN     %s\n", asset.LastSeen.Local().Format(time.DateTime))
		fmt.Fprintf(w, "OBSERVATIONS  %d\n", asset.ObservationCount)
		fmt.Fprintf(w, "MISSED SCANS  %d\n", asset.MissedScans)

		fmt.Fprintln(w)
		fmt.Fprintln(w, "SERVICE HISTORY")

		found := false
		for _, svc := range services {
			if svc.IdentityKey != asset.IdentityKey {
				continue
			}
			found = true

			status := "HISTORICAL"
			if svc.Present {
				status = "PRESENT"
			}

			fmt.Fprintf(
				w,
				"[%s] %d/%s %s\n",
				status,
				svc.Port,
				svc.Protocol,
				svc.Name,
			)
			fmt.Fprintf(w, "    FIRST SEEN   %s\n", svc.FirstSeen.Local().Format(time.DateTime))
			fmt.Fprintf(w, "    LAST SEEN    %s\n", svc.LastSeen.Local().Format(time.DateTime))
			fmt.Fprintf(w, "    OBSERVATIONS %d\n", svc.ObservationCount)
		}

		if !found {
			fmt.Fprintln(w, "No service history recorded.")
		}

		fmt.Fprintln(w)
	}
}

func WebInterfaces(w io.Writer, interfaces []model.WebInterface) {
	Banner(w)

	if len(interfaces) == 0 {
		fmt.Fprintln(w, "No HTTP/HTTPS interface found for that device.")
		return
	}

	fmt.Fprintln(w, "WEB INTERFACES")
	fmt.Fprintln(w)

	for i, web := range interfaces {
		tag := "WEB"
		if len(web.LoginIndicators) > 0 {
			tag = "LOGIN"
		}

		fmt.Fprintf(w, "[%s] %s\n", tag, web.URL)
		if web.Title != "" {
			fmt.Fprintf(w, "    TITLE       %s\n", web.Title)
		}
		if web.Status != "" {
			fmt.Fprintf(w, "    STATUS      %s\n", web.Status)
		}
		if web.Server != "" {
			fmt.Fprintf(w, "    SERVER      %s\n", web.Server)
		}
		if len(web.LoginIndicators) > 0 {
			fmt.Fprintf(w, "    AUTH SIGNAL %s\n", strings.Join(web.LoginIndicators, ", "))
		}
		if i == 0 {
			fmt.Fprintln(w, "    PREFERRED   yes")
		}
		fmt.Fprintln(w)
	}
}

func OpeningWebInterface(w io.Writer, web model.WebInterface) {
	kind := "WEB"
	confidence := "MEDIUM"

	if len(web.LoginIndicators) > 0 {
		kind = "LOGIN"
		confidence = "HIGH"
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w, "OPENING WEB INTERFACE")
	fmt.Fprintln(w)
	fmt.Fprintf(w, "DEVICE       %s\n", web.IP)

	if web.Hostname != "" {
		fmt.Fprintf(w, "HOSTNAME     %s\n", web.Hostname)
	}

	fmt.Fprintf(w, "INTERFACE    %s\n", web.URL)
	fmt.Fprintf(w, "TYPE         %s\n", kind)
	fmt.Fprintf(w, "CONFIDENCE   %s\n", confidence)

	if web.Title != "" {
		fmt.Fprintf(w, "TITLE        %s\n", web.Title)
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w, "[+] Launching default browser...")
}

func WebInventory(w io.Writer, interfaces []model.WebInterface) {
	Banner(w)

	if len(interfaces) == 0 {
		fmt.Fprintln(w, "No HTTP/HTTPS interfaces found in the latest scan.")
		return
	}

	fmt.Fprintln(w, "WEB INTERFACE INVENTORY")
	fmt.Fprintln(w)
	fmt.Fprintf(
		w,
		"%-15s %-22s %-7s %-6s %-9s %s\n",
		"IP",
		"HOSTNAME",
		"SCHEME",
		"PORT",
		"TYPE",
		"TITLE",
	)
	fmt.Fprintln(w, strings.Repeat("─", 88))

	for _, web := range interfaces {
		hostname := web.Hostname
		if hostname == "" {
			hostname = "unknown"
		}

		kind := "WEB"
		if len(web.LoginIndicators) > 0 {
			kind = "LOGIN"
		}

		title := web.Title
		if title == "" {
			title = "-"
		}

		fmt.Fprintf(
			w,
			"%-15s %-22s %-7s %-6d %-9s %s\n",
			web.IP,
			truncate(hostname, 22),
			strings.ToUpper(web.Scheme),
			web.Port,
			kind,
			truncate(title, 30),
		)
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w, "Open one with: sentinel open <ip-or-hostname>")
}

func Events(w io.Writer, events []model.Event) {
	Banner(w)

	if len(events) == 0 {
		fmt.Fprintln(w, "No monitoring events recorded yet.")
		return
	}

	fmt.Fprintln(w, "MONITORING EVENTS")
	fmt.Fprintln(w)
	fmt.Fprintf(w, "%-19s %-9s %-16s %s\n", "TIME", "SEVERITY", "TYPE", "MESSAGE")
	fmt.Fprintln(w, strings.Repeat("─", 96))

	for _, event := range events {
		fmt.Fprintf(
			w,
			"%-19s %-9s %-16s %s\n",
			event.CreatedAt.Local().Format("2006-01-02 15:04:05"),
			event.Severity,
			event.Type,
			event.Message,
		)
	}
}

func WatchStart(w io.Writer, target string, interval time.Duration, notifyEnabled bool, notifyLevel string) {
	Banner(w)
	fmt.Fprintln(w, "MONITORING ACTIVE")
	fmt.Fprintln(w)
	fmt.Fprintf(w, "TARGET      %s\n", target)
	fmt.Fprintf(w, "INTERVAL    %s\n", interval)
	fmt.Fprintln(w, "BASELINE    establishing")
	if notifyEnabled {
		fmt.Fprintf(w, "NOTIFY      enabled (%s+)\n", strings.ToUpper(notifyLevel))
	} else {
		fmt.Fprintln(w, "NOTIFY      disabled")
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Press Ctrl+C to stop.")
	fmt.Fprintln(w)
}

func WatchBaseline(w io.Writer, snapshot model.Snapshot) {
	services := 0
	for _, host := range snapshot.Hosts {
		services += len(host.Services)
	}

	fmt.Fprintf(
		w,
		"[%s] BASELINE ESTABLISHED | %d assets | %d services\n",
		snapshot.Timestamp.Local().Format("15:04:05"),
		len(snapshot.Hosts),
		services,
	)
}

func WatchCycle(w io.Writer, snapshot model.Snapshot, changes []model.Change, events []model.Event, interval time.Duration) {
	services := 0
	for _, host := range snapshot.Hosts {
		services += len(host.Services)
	}

	if len(changes) == 0 {
		fmt.Fprintf(
			w,
			"[%s] OK | %d assets | %d services | next scan %s\n",
			snapshot.Timestamp.Local().Format("15:04:05"),
			len(snapshot.Hosts),
			services,
			interval,
		)
		return
	}

	addedHosts := 0
	removedHosts := 0
	addedServices := 0
	removedServices := 0
	changedServices := 0

	for _, ch := range changes {
		switch ch.Type {
		case model.HostAdded:
			addedHosts++
		case model.HostRemoved:
			removedHosts++
		case model.ServiceAdded:
			addedServices++
		case model.ServiceRemoved:
			removedServices++
		case model.ServiceChanged:
			changedServices++
		}
	}

	fmt.Fprintln(w)
	fmt.Fprintf(
		w,
		"[%s] CHANGE | assets +%d/-%d | services +%d/-%d/~%d\n",
		snapshot.Timestamp.Local().Format("15:04:05"),
		addedHosts,
		removedHosts,
		addedServices,
		removedServices,
		changedServices,
	)
	fmt.Fprintln(w)

	for _, event := range events {
		fmt.Fprintf(
			w,
			"[%s] %s\n",
			event.Severity,
			event.Message,
		)
	}

	fmt.Fprintf(w, "\nNext scan in %s\n", interval)
	fmt.Fprintln(w)
}
