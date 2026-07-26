package discovery

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/time/rate"
)

type Options struct {
	Workers int
	Timeout time.Duration
	Rate    int
	Ports   []uint16
}

type job struct {
	host string
	port uint16
}

type result struct {
	host   string
	active bool
}

// Discover identifies hosts that positively respond to TCP probes.
//
// A host is considered active when:
//   - a TCP connection succeeds, or
//   - the target explicitly refuses the connection.
//
// An explicit refusal still proves that an IP stack is present at the target.
// Timeouts and unreachable-network errors are not treated as proof of life.
//
// This approach avoids requiring raw sockets or Administrator privileges on
// Windows while keeping V0.1.2 useful on authorized local networks.
func Discover(ctx context.Context, hosts []string, opts Options) ([]string, error) {
	if opts.Workers <= 0 {
		return nil, fmt.Errorf("workers must be greater than zero")
	}
	if opts.Timeout <= 0 {
		return nil, fmt.Errorf("timeout must be greater than zero")
	}
	if opts.Rate <= 0 {
		return nil, fmt.Errorf("rate must be greater than zero")
	}
	if len(opts.Ports) == 0 {
		return nil, fmt.Errorf("at least one discovery port is required")
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	jobs := make(chan job)
	results := make(chan result)
	limiter := rate.NewLimiter(rate.Limit(opts.Rate), opts.Workers)

	var wg sync.WaitGroup
	for i := 0; i < opts.Workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			dialer := net.Dialer{Timeout: opts.Timeout}

			for {
				select {
				case <-ctx.Done():
					return
				case j, ok := <-jobs:
					if !ok {
						return
					}

					if err := limiter.Wait(ctx); err != nil {
						return
					}

					address := net.JoinHostPort(j.host, fmt.Sprintf("%d", j.port))
					conn, err := dialer.DialContext(ctx, "tcp", address)

					active := false
					if err == nil {
						active = true
						_ = conn.Close()
					} else if isConnectionRefused(err) {
						active = true
					}

					select {
					case results <- result{host: j.host, active: active}:
					case <-ctx.Done():
						return
					}
				}
			}
		}()
	}

	go func() {
		defer close(jobs)
		for _, h := range hosts {
			for _, p := range opts.Ports {
				select {
				case jobs <- job{host: h, port: p}:
				case <-ctx.Done():
					return
				}
			}
		}
	}()

	go func() {
		wg.Wait()
		close(results)
	}()

	active := make(map[string]bool)
	for r := range results {
		if r.active {
			active[r.host] = true
		}
	}

	out := make([]string, 0, len(active))
	for host := range active {
		out = append(out, host)
	}
	sort.Slice(out, func(i, j int) bool { return ipLess(out[i], out[j]) })

	return out, nil
}

func isConnectionRefused(err error) bool {
	if err == nil {
		return false
	}

	// Works for wrapped platform errors on Windows, Linux, and macOS.
	if errors.Is(err, syscall.ECONNREFUSED) {
		return true
	}

	// Windows networking errors are sometimes wrapped as text by net.OpError.
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "actively refused") ||
		strings.Contains(msg, "connection refused")
}

func ipLess(a, b string) bool {
	ia := net.ParseIP(a).To4()
	ib := net.ParseIP(b).To4()
	if ia == nil || ib == nil {
		return a < b
	}
	for i := 0; i < 4; i++ {
		if ia[i] != ib[i] {
			return ia[i] < ib[i]
		}
	}
	return false
}
