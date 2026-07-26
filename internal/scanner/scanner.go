package scanner

import (
	"context"
	"fmt"
	"net"
	"sort"
	"sync"
	"time"

	"github.com/cojjjj/blackterm-sentinel/internal/fingerprint"
	"github.com/cojjjj/blackterm-sentinel/internal/model"
	"golang.org/x/time/rate"
)

type Options struct {
	Workers int
	Timeout time.Duration
	Rate    int
}

type job struct {
	host string
	port uint16
}

type result struct {
	host    string
	service model.Service
	open    bool
}

func Scan(ctx context.Context, hosts []string, ports []uint16, opts Options) ([]model.Host, error) {
	if opts.Workers <= 0 {
		return nil, fmt.Errorf("workers must be greater than zero")
	}
	if opts.Timeout <= 0 {
		return nil, fmt.Errorf("timeout must be greater than zero")
	}
	if opts.Rate <= 0 {
		return nil, fmt.Errorf("rate must be greater than zero")
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
					if err != nil {
						select {
						case results <- result{host: j.host, open: false}:
						case <-ctx.Done():
						}
						continue
					}
					_ = conn.Close()
					select {
					case results <- result{
						host: j.host,
						open: true,
						service: model.Service{
							Port:     j.port,
							Protocol: "tcp",
							Name:     fingerprint.ServiceName(j.port),
						},
					}:
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
			for _, p := range ports {
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

	hostMap := make(map[string][]model.Service)
	for r := range results {
		if r.open {
			hostMap[r.host] = append(hostMap[r.host], r.service)
		}
	}

	if err := ctx.Err(); err != nil && err != context.Canceled {
		return nil, err
	}

	out := make([]model.Host, 0, len(hostMap))
	for ip, services := range hostMap {
		sort.Slice(services, func(i, j int) bool {
			return services[i].Port < services[j].Port
		})
		out = append(out, model.Host{IP: ip, Services: services})
	}
	sort.Slice(out, func(i, j int) bool { return ipLess(out[i].IP, out[j].IP) })
	return out, nil
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
