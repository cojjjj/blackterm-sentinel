package discovery

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os/exec"
	"runtime"
	"sort"
	"strings"
)

type Neighbor struct {
	IP  string
	MAC string
}

func NeighborTable(ctx context.Context) ([]Neighbor, error) {
	switch runtime.GOOS {
	case "windows":
		return windowsARP(ctx)
	default:
		return nil, nil
	}
}

func windowsARP(ctx context.Context) ([]Neighbor, error) {
	cmd := exec.CommandContext(ctx, "arp", "-a")
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("read Windows ARP table: %w", err)
	}

	var neighbors []Neighbor
	seen := map[string]bool{}

	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}

		ip := net.ParseIP(fields[0])
		if ip == nil || ip.To4() == nil {
			continue
		}

		mac := normalizeMAC(fields[1])
		kind := strings.ToLower(fields[2])
		if kind != "dynamic" {
			continue
		}
		if mac == "" || seen[fields[0]] {
			continue
		}

		seen[fields[0]] = true
		neighbors = append(neighbors, Neighbor{
			IP:  fields[0],
			MAC: mac,
		})
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	sort.Slice(neighbors, func(i, j int) bool {
		return ipLess(neighbors[i].IP, neighbors[j].IP)
	})
	return neighbors, nil
}

func normalizeMAC(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	raw = strings.ReplaceAll(raw, "-", ":")
	return strings.ToUpper(raw)
}
