package cli

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/cojjjj/blackterm-sentinel/internal/analysis"
	"github.com/cojjjj/blackterm-sentinel/internal/browser"
	"github.com/cojjjj/blackterm-sentinel/internal/config"
	"github.com/cojjjj/blackterm-sentinel/internal/dashboard"
	"github.com/cojjjj/blackterm-sentinel/internal/diff"
	"github.com/cojjjj/blackterm-sentinel/internal/discovery"
	"github.com/cojjjj/blackterm-sentinel/internal/fingerprint"
	"github.com/cojjjj/blackterm-sentinel/internal/model"
	"github.com/cojjjj/blackterm-sentinel/internal/monitor"
	"github.com/cojjjj/blackterm-sentinel/internal/notify"
	"github.com/cojjjj/blackterm-sentinel/internal/report"
	"github.com/cojjjj/blackterm-sentinel/internal/scanner"
	"github.com/cojjjj/blackterm-sentinel/internal/store"
	"github.com/cojjjj/blackterm-sentinel/internal/target"
	"github.com/spf13/cobra"
)

var (
	dbPath  string
	workers int
	timeout time.Duration
	rateVal int
)

func Execute() error {
	cfg := config.Default()

	root := &cobra.Command{
		Use:           "sentinel",
		Short:         "BLACKTERM defensive network state intelligence",
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	root.PersistentFlags().StringVar(&dbPath, "db", cfg.DBPath, "SQLite database path")

	scanCmd := &cobra.Command{
		Use:   "scan <IPv4-or-CIDR>",
		Short: "Scan an authorized target and compare it to the previous baseline",
		Args:  cobra.ExactArgs(1),
		RunE:  runScan,
	}
	scanCmd.Flags().IntVarP(&workers, "workers", "w", cfg.Workers, "number of concurrent workers")
	scanCmd.Flags().DurationVar(&timeout, "timeout", cfg.Timeout, "TCP connection timeout")
	scanCmd.Flags().IntVar(&rateVal, "rate", cfg.Rate, "maximum connection attempts per second")
	scanCmd.Flags().String("ports", portsString(cfg.Ports), "comma-separated TCP service ports")
	scanCmd.Flags().String(
		"discovery-ports",
		"22,53,80,135,139,443,445,3389,8080",
		"comma-separated TCP ports used to identify active hosts",
	)
	scanCmd.Flags().Bool("json", false, "emit JSON instead of terminal output")
	scanCmd.Flags().BoolP("verbose", "v", false, "show full fingerprints and all findings")
	scanCmd.Flags().Bool("no-icmp", false, "disable ICMP discovery")
	root.AddCommand(scanCmd)

	inventoryCmd := &cobra.Command{
		Use:   "inventory",
		Short: "List recent stored snapshots",
		RunE: func(cmd *cobra.Command, args []string) error {
			s, err := store.Open(dbPath)
			if err != nil {
				return err
			}
			defer s.Close()
			snaps, err := s.ListLatest(25)
			if err != nil {
				return err
			}
			report.Inventory(cmd.OutOrStdout(), snaps)
			return nil
		},
	}
	root.AddCommand(inventoryCmd)

	changesCmd := &cobra.Command{
		Use:   "changes",
		Short: "Show recent detected network changes",
		RunE: func(cmd *cobra.Command, args []string) error {
			s, err := store.Open(dbPath)
			if err != nil {
				return err
			}
			defer s.Close()
			changes, err := s.RecentChanges(50)
			if err != nil {
				return err
			}
			report.Changes(cmd.OutOrStdout(), changes)
			return nil
		},
	}
	root.AddCommand(changesCmd)

	findingsCmd := &cobra.Command{
		Use:   "findings",
		Short: "Show recent stored security findings",
		RunE: func(cmd *cobra.Command, args []string) error {
			s, err := store.Open(dbPath)
			if err != nil {
				return err
			}
			defer s.Close()

			findings, err := s.RecentFindings(100)
			if err != nil {
				return err
			}

			report.Findings(cmd.OutOrStdout(), findings)
			return nil
		},
	}
	root.AddCommand(findingsCmd)

	assetsCmd := &cobra.Command{
		Use:   "assets [target]",
		Short: "Show persistent asset state and observation history",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			s, err := store.Open(dbPath)
			if err != nil {
				return err
			}
			defer s.Close()

			targetFilter := ""
			if len(args) == 1 {
				targetFilter = args[0]
			}

			assets, err := s.Assets(targetFilter)
			if err != nil {
				return err
			}

			details, _ := cmd.Flags().GetBool("details")

			report.Assets(cmd.OutOrStdout(), assets, details)
			return nil
		},
	}
	assetsCmd.Flags().BoolP("details", "d", false, "show full asset records")
	root.AddCommand(assetsCmd)

	historyCmd := &cobra.Command{
		Use:   "history <ip|mac|hostname|identity>",
		Short: "Show persistent history for an asset and its services",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			s, err := store.Open(dbPath)
			if err != nil {
				return err
			}
			defer s.Close()

			assets, services, err := s.AssetHistory(args[0])
			if err != nil {
				return err
			}

			report.AssetHistory(cmd.OutOrStdout(), assets, services)
			return nil
		},
	}
	root.AddCommand(historyCmd)

	openCmd := &cobra.Command{
		Use:   "open <ip|hostname>",
		Short: "Open the preferred known web interface for an authorized device",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			s, err := store.Open(dbPath)
			if err != nil {
				return err
			}
			defer s.Close()

			interfaces, err := s.WebInterfaces(args[0])
			if err != nil {
				return err
			}

			if len(interfaces) == 0 {
				report.WebInterfaces(cmd.OutOrStdout(), interfaces)
				return nil
			}

			listOnly, _ := cmd.Flags().GetBool("list")
			all, _ := cmd.Flags().GetBool("all")

			report.WebInterfaces(cmd.OutOrStdout(), interfaces)

			if listOnly {
				return nil
			}

			if all {
				for _, web := range interfaces {
					report.OpeningWebInterface(cmd.OutOrStdout(), web)
					if err := browser.Open(web.URL); err != nil {
						return err
					}
				}
				return nil
			}

			report.OpeningWebInterface(cmd.OutOrStdout(), interfaces[0])
			return browser.Open(interfaces[0].URL)
		},
	}
	openCmd.Flags().Bool("list", false, "list discovered web interfaces without opening a browser")
	openCmd.Flags().Bool("all", false, "open all discovered web interfaces for the device")
	root.AddCommand(openCmd)

	webCmd := &cobra.Command{
		Use:   "web [target]",
		Short: "List discovered HTTP/HTTPS interfaces from the latest scan",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			s, err := store.Open(dbPath)
			if err != nil {
				return err
			}
			defer s.Close()

			targetFilter := ""
			if len(args) == 1 {
				targetFilter = args[0]
			}

			interfaces, err := s.LatestWebInterfaces(targetFilter)
			if err != nil {
				return err
			}

			report.WebInventory(cmd.OutOrStdout(), interfaces)
			return nil
		},
	}
	root.AddCommand(webCmd)

	watchCmd := &cobra.Command{
		Use:   "watch <IPv4-or-CIDR>",
		Short: "Continuously monitor an authorized network for state changes",
		Args:  cobra.ExactArgs(1),
		RunE:  runWatch,
	}
	watchCmd.Flags().Duration("interval", 5*time.Minute, "time between monitoring scans")
	watchCmd.Flags().Bool("no-icmp", false, "disable ICMP discovery during watch scans")
	watchCmd.Flags().Bool("notify", false, "show Windows desktop notifications for matching events")
	watchCmd.Flags().String("notify-level", "medium", "minimum notification severity: critical, high, medium, low, info")
	root.AddCommand(watchCmd)

	eventsCmd := &cobra.Command{
		Use:   "events [target]",
		Short: "Show recent persistent monitoring events",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			s, err := store.Open(dbPath)
			if err != nil {
				return err
			}
			defer s.Close()

			targetFilter := ""
			if len(args) == 1 {
				targetFilter = args[0]
			}

			events, err := s.RecentEvents(targetFilter, 100)
			if err != nil {
				return err
			}

			report.Events(cmd.OutOrStdout(), events)
			return nil
		},
	}
	root.AddCommand(eventsCmd)

	dashboardCmd := &cobra.Command{
		Use:   "dashboard <target>",
		Short: "Start the local Sentinel web dashboard",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			addr, _ := cmd.Flags().GetString("addr")
			openBrowser, _ := cmd.Flags().GetBool("open")

			if openBrowser {
				go func() {
					time.Sleep(500 * time.Millisecond)
					_ = browser.Open("http://" + addr)
				}()
			}

			err := dashboard.Serve(dashboard.Options{
				Addr:   addr,
				Target: args[0],
				DBPath: dbPath,
			})
			if err == http.ErrServerClosed {
				return nil
			}
			return err
		},
	}
	dashboardCmd.Flags().String("addr", "127.0.0.1:8765", "local dashboard listen address")
	dashboardCmd.Flags().Bool("open", true, "open dashboard in default browser")
	root.AddCommand(dashboardCmd)

	root.SetOut(os.Stdout)
	root.SetErr(os.Stderr)
	return root.Execute()
}

func runScan(cmd *cobra.Command, args []string) error {
	rawPorts, _ := cmd.Flags().GetString("ports")
	ports, err := parsePorts(rawPorts)
	if err != nil {
		return err
	}

	rawDiscoveryPorts, _ := cmd.Flags().GetString("discovery-ports")
	discoveryPorts, err := parsePorts(rawDiscoveryPorts)
	if err != nil {
		return fmt.Errorf("invalid discovery ports: %w", err)
	}

	jsonMode, _ := cmd.Flags().GetBool("json")
	verbose, _ := cmd.Flags().GetBool("verbose")
	noICMP, _ := cmd.Flags().GetBool("no-icmp")

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	s, err := store.Open(dbPath)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer s.Close()

	snapshot, changes, err := performScanCycle(
		ctx,
		s,
		args[0],
		ports,
		discoveryPorts,
		noICMP,
	)
	if err != nil {
		return err
	}

	events := monitor.EventsFromChanges(args[0], changes)
	if err := s.SaveEvents(events); err != nil {
		return fmt.Errorf("save events: %w", err)
	}

	if jsonMode {
		return report.JSON(cmd.OutOrStdout(), snapshot, changes)
	}

	report.Banner(cmd.OutOrStdout())
	report.Scan(cmd.OutOrStdout(), snapshot, changes, verbose)
	return nil
}

func runWatch(cmd *cobra.Command, args []string) error {
	interval, _ := cmd.Flags().GetDuration("interval")
	noICMP, _ := cmd.Flags().GetBool("no-icmp")
	notifyEnabled, _ := cmd.Flags().GetBool("notify")
	notifyLevel, _ := cmd.Flags().GetString("notify-level")

	if interval < time.Second {
		return fmt.Errorf("interval must be at least 1s")
	}
	if !notify.ValidMinimum(notifyLevel) {
		return fmt.Errorf("invalid --notify-level %q: use critical, high, medium, low, or info", notifyLevel)
	}

	cfg := config.Default()
	ports := cfg.Ports
	discoveryPorts := []uint16{22, 53, 80, 135, 139, 443, 445, 3389, 8080}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	s, err := store.Open(dbPath)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer s.Close()

	report.WatchStart(cmd.OutOrStdout(), args[0], interval, notifyEnabled, notifyLevel)

	startedAt := time.Now()
	if err := s.SetMonitoringStatus(model.MonitoringStatus{
		Target:    args[0],
		Active:    true,
		Interval:  interval,
		StartedAt: startedAt,
	}); err != nil {
		return fmt.Errorf("set monitoring status: %w", err)
	}
	defer func() {
		_ = s.SetMonitoringStatus(model.MonitoringStatus{
			Target:   args[0],
			Active:   false,
			Interval: interval,
		})
	}()

	// First cycle establishes a fresh watch baseline. The snapshot is still
	// persisted, but pre-existing differences are intentionally not converted
	// into monitoring events.
	baseline, _, err := performScanCycle(
		ctx,
		s,
		args[0],
		ports,
		discoveryPorts,
		noICMP,
	)
	if err != nil {
		if ctx.Err() != nil {
			return nil
		}
		return err
	}

	if err := s.SetMonitoringStatus(model.MonitoringStatus{
		Target:     args[0],
		Active:     true,
		Interval:   interval,
		StartedAt:  startedAt,
		LastScanAt: baseline.Timestamp,
	}); err != nil {
		return fmt.Errorf("update monitoring status: %w", err)
	}

	report.WatchBaseline(cmd.OutOrStdout(), baseline)

	for {
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			fmt.Fprintln(cmd.OutOrStdout(), "\nMonitoring stopped.")
			return nil
		case <-timer.C:
		}

		snapshot, changes, err := performScanCycle(
			ctx,
			s,
			args[0],
			ports,
			discoveryPorts,
			noICMP,
		)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}

		if err := s.SetMonitoringStatus(model.MonitoringStatus{
			Target:     args[0],
			Active:     true,
			Interval:   interval,
			StartedAt:  startedAt,
			LastScanAt: snapshot.Timestamp,
		}); err != nil {
			return fmt.Errorf("update monitoring status: %w", err)
		}

		events := monitor.EventsFromChanges(args[0], changes)
		if err := s.SaveEvents(events); err != nil {
			return fmt.Errorf("save events: %w", err)
		}

		if notifyEnabled {
			for _, event := range events {
				if !notify.ShouldNotify(event, notifyLevel) {
					continue
				}

				if err := notify.Notify(
					notify.EventTitle(event),
					notify.EventMessage(event),
				); err != nil {
					fmt.Fprintf(
						cmd.ErrOrStderr(),
						"[!] notification failed: %v\n",
						err,
					)
				}
			}
		}

		report.WatchCycle(
			cmd.OutOrStdout(),
			snapshot,
			changes,
			events,
			interval,
		)
	}
}

func performScanCycle(
	ctx context.Context,
	s *store.Store,
	targetArg string,
	ports []uint16,
	discoveryPorts []uint16,
	noICMP bool,
) (model.Snapshot, []model.Change, error) {
	candidates, err := target.Expand(targetArg)
	if err != nil {
		return model.Snapshot{}, nil, err
	}

	previous, hasPrevious, err := s.LatestSnapshot(targetArg)
	if err != nil {
		return model.Snapshot{}, nil, fmt.Errorf("load previous snapshot: %w", err)
	}

	knownIPs, err := s.KnownAssetIPs(targetArg)
	if err != nil {
		return model.Snapshot{}, nil, fmt.Errorf("load known assets: %w", err)
	}

	iface, hasIface, err := discovery.MatchingInterface(targetArg)
	if err != nil {
		return model.Snapshot{}, nil, fmt.Errorf("detect interface: %w", err)
	}

	neighbors, err := discovery.NeighborTable(ctx)
	if err != nil {
		neighbors = nil
	}
	neighbors = filterNeighborsForTarget(neighbors, targetArg)

	activeHosts, err := discovery.Discover(ctx, candidates, discovery.Options{
		Workers: workers,
		Timeout: timeout,
		Rate:    rateVal,
		Ports:   discoveryPorts,
	})
	if err != nil {
		return model.Snapshot{}, nil, fmt.Errorf("host discovery: %w", err)
	}

	var icmpHosts []string
	if !noICMP {
		icmpHosts, err = discovery.DiscoverICMP(ctx, candidates, discovery.ICMPOptions{
			Workers: minInt(workers, 64),
			Timeout: timeout,
			Rate:    minInt(rateVal, 200),
		})
		if err != nil {
			return model.Snapshot{}, nil, fmt.Errorf("icmp discovery: %w", err)
		}
	}

	if hasIface && targetContainsIP(targetArg, iface.IP) {
		activeHosts = append(activeHosts, iface.IP)
	}

	mergedIPs := mergeHostIPs(activeHosts, icmpHosts, knownIPs, neighbors)
	foundServices, err := scanner.Scan(ctx, mergedIPs, ports, scanner.Options{
		Workers: workers,
		Timeout: timeout,
		Rate:    rateVal,
	})
	if err != nil {
		return model.Snapshot{}, nil, err
	}

	hosts := buildInventoryHosts(
		ctx,
		mergedIPs,
		activeHosts,
		icmpHosts,
		knownIPs,
		neighbors,
		foundServices,
	)

	hosts = fingerprint.Enrich(ctx, hosts, fingerprint.EnrichOptions{
		Workers: 16,
		Timeout: 1500 * time.Millisecond,
	})

	now := time.Now()

	snapshot := model.Snapshot{
		Target:    targetArg,
		Timestamp: now,
		Hosts:     hosts,
		Findings: append(
			analysis.AuthExposure(hosts),
			analysis.FingerprintFindings(hosts)...,
		),
	}

	if hasIface {
		snapshot.Interface = iface.IP
	}

	var changes []model.Change
	if hasPrevious {
		changes = diff.Compare(previous, snapshot, now)
	}

	id, err := s.SaveSnapshot(snapshot, changes)
	if err != nil {
		return model.Snapshot{}, nil, fmt.Errorf("save snapshot: %w", err)
	}
	snapshot.ID = id

	return snapshot, changes, nil
}

func filterNeighborsForTarget(neighbors []discovery.Neighbor, rawTarget string) []discovery.Neighbor {
	var out []discovery.Neighbor

	if _, network, err := net.ParseCIDR(rawTarget); err == nil {
		for _, n := range neighbors {
			ip := net.ParseIP(n.IP)
			if ip != nil && network.Contains(ip) {
				out = append(out, n)
			}
		}
		return out
	}

	targetIP := net.ParseIP(rawTarget)
	for _, n := range neighbors {
		if targetIP != nil && n.IP == targetIP.String() {
			out = append(out, n)
		}
	}
	return out
}

func targetContainsIP(rawTarget, rawIP string) bool {
	ip := net.ParseIP(rawIP)
	if ip == nil {
		return false
	}

	if _, network, err := net.ParseCIDR(rawTarget); err == nil {
		return network.Contains(ip)
	}

	targetIP := net.ParseIP(rawTarget)
	return targetIP != nil && targetIP.Equal(ip)
}

func mergeHostIPs(tcpHosts []string, icmpHosts []string, knownIPs []string, neighbors []discovery.Neighbor) []string {
	seen := map[string]bool{}

	for _, ip := range tcpHosts {
		seen[ip] = true
	}
	for _, ip := range icmpHosts {
		seen[ip] = true
	}
	for _, ip := range knownIPs {
		seen[ip] = true
	}
	for _, n := range neighbors {
		seen[n.IP] = true
	}

	out := make([]string, 0, len(seen))
	for ip := range seen {
		seen[ip] = true
		out = append(out, ip)
	}

	sort.Slice(out, func(i, j int) bool { return compareIPv4(out[i], out[j]) })
	return out
}

func buildInventoryHosts(
	ctx context.Context,
	allIPs []string,
	tcpHosts []string,
	icmpHosts []string,
	knownIPs []string,
	neighbors []discovery.Neighbor,
	scanned []model.Host,
) []model.Host {
	tcpSet := makeStringSet(tcpHosts)
	icmpSet := makeStringSet(icmpHosts)
	knownSet := makeStringSet(knownIPs)

	neighborMap := map[string]discovery.Neighbor{}
	for _, n := range neighbors {
		neighborMap[n.IP] = n
	}

	servicesByIP := make(map[string][]model.Service, len(scanned))
	for _, host := range scanned {
		servicesByIP[host.IP] = host.Services
	}

	out := make([]model.Host, 0, len(allIPs))
	for _, ip := range allIPs {
		var sources []string

		if _, ok := neighborMap[ip]; ok {
			sources = append(sources, "NEIGHBOR")
		}
		if tcpSet[ip] {
			sources = append(sources, "TCP")
		}
		if icmpSet[ip] {
			sources = append(sources, "ICMP")
		}
		if knownSet[ip] && len(sources) == 0 {
			sources = append(sources, "HISTORY")
		}

		// Historical-only entries stay in asset intelligence, but are not added
		// as "observed now" hosts. This prevents a quiet/offline device from
		// falsely refreshing its last-seen timestamp.
		if len(sources) == 1 && sources[0] == "HISTORY" {
			continue
		}

		host := model.Host{
			IP:               ip,
			Hostname:         discovery.ReverseDNS(ctx, ip),
			DiscoverySources: sources,
			Services:         servicesByIP[ip],
		}

		if n, ok := neighborMap[ip]; ok {
			host.MAC = n.MAC
		}

		out = append(out, host)
	}

	return out
}

func makeStringSet(values []string) map[string]bool {
	out := make(map[string]bool, len(values))
	for _, value := range values {
		out[value] = true
	}
	return out
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func compareIPv4(a, b string) bool {
	ap := strings.Split(a, ".")
	bp := strings.Split(b, ".")
	if len(ap) != 4 || len(bp) != 4 {
		return a < b
	}

	for i := 0; i < 4; i++ {
		ai, _ := strconv.Atoi(ap[i])
		bi, _ := strconv.Atoi(bp[i])
		if ai != bi {
			return ai < bi
		}
	}
	return false
}

func parsePorts(raw string) ([]uint16, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, fmt.Errorf("ports cannot be empty")
	}
	seen := make(map[uint16]bool)
	var ports []uint16
	for _, part := range strings.Split(raw, ",") {
		n, err := strconv.Atoi(strings.TrimSpace(part))
		if err != nil || n < 1 || n > 65535 {
			return nil, fmt.Errorf("invalid TCP port %q", part)
		}
		p := uint16(n)
		if !seen[p] {
			seen[p] = true
			ports = append(ports, p)
		}
	}
	return ports, nil
}

func portsString(ports []uint16) string {
	out := make([]string, 0, len(ports))
	for _, p := range ports {
		out = append(out, strconv.Itoa(int(p)))
	}
	return strings.Join(out, ",")
}
