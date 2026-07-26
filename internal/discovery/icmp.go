package discovery

import (
	"context"
	"fmt"
	"os/exec"
	"runtime"
	"sort"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

type ICMPOptions struct {
	Workers int
	Timeout time.Duration
	Rate    int
}

func DiscoverICMP(ctx context.Context, hosts []string, opts ICMPOptions) ([]string, error) {
	if opts.Workers <= 0 {
		opts.Workers = 32
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 700 * time.Millisecond
	}
	if opts.Rate <= 0 {
		opts.Rate = 100
	}

	jobs := make(chan string)
	results := make(chan string)
	limiter := rate.NewLimiter(rate.Limit(opts.Rate), opts.Workers)

	var wg sync.WaitGroup
	for i := 0; i < opts.Workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			for {
				select {
				case <-ctx.Done():
					return
				case host, ok := <-jobs:
					if !ok {
						return
					}

					if err := limiter.Wait(ctx); err != nil {
						return
					}

					if pingOnce(ctx, host, opts.Timeout) {
						select {
						case results <- host:
						case <-ctx.Done():
							return
						}
					}
				}
			}
		}()
	}

	go func() {
		defer close(jobs)
		for _, host := range hosts {
			select {
			case jobs <- host:
			case <-ctx.Done():
				return
			}
		}
	}()

	go func() {
		wg.Wait()
		close(results)
	}()

	seen := map[string]bool{}
	var out []string
	for host := range results {
		if seen[host] {
			continue
		}
		seen[host] = true
		out = append(out, host)
	}

	sort.Slice(out, func(i, j int) bool { return ipLess(out[i], out[j]) })
	return out, nil
}

func pingOnce(ctx context.Context, host string, timeout time.Duration) bool {
	ms := int(timeout.Milliseconds())
	if ms < 1 {
		ms = 1
	}

	var cmd *exec.Cmd

	switch runtime.GOOS {
	case "windows":
		// -n 1 = one echo, -w = timeout in milliseconds.
		cmd = exec.CommandContext(ctx, "ping", "-n", "1", "-w", fmt.Sprintf("%d", ms), host)
	default:
		// Most Unix ping implementations support -c 1. Timeout is enforced by context.
		pingCtx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		cmd = exec.CommandContext(pingCtx, "ping", "-c", "1", host)
	}

	return cmd.Run() == nil
}
