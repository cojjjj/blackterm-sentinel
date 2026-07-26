package fingerprint

import (
	"context"
	"sync"
	"time"

	"github.com/cojjjj/blackterm-sentinel/internal/model"
)

type EnrichOptions struct {
	Workers int
	Timeout time.Duration
}

type enrichJob struct {
	hostIndex    int
	serviceIndex int
	ip           string
	service      model.Service
}

type enrichResult struct {
	hostIndex    int
	serviceIndex int
	http         *model.HTTPFingerprint
	tls          *model.TLSFingerprint
}

func Enrich(ctx context.Context, hosts []model.Host, opts EnrichOptions) []model.Host {
	if opts.Workers <= 0 {
		opts.Workers = 16
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 1200 * time.Millisecond
	}

	out := cloneHosts(hosts)
	jobs := make(chan enrichJob)
	results := make(chan enrichResult)

	var wg sync.WaitGroup
	for i := 0; i < opts.Workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case job, ok := <-jobs:
					if !ok {
						return
					}

					secure := job.service.Name == "HTTPS"
					if job.service.Name != "HTTP" && !secure {
						continue
					}

					httpFP, tlsFP := InspectHTTP(ctx, job.ip, job.service.Port, secure, HTTPOptions{
						Timeout: opts.Timeout,
						MaxBody: 64 * 1024,
					})

					select {
					case results <- enrichResult{
						hostIndex:    job.hostIndex,
						serviceIndex: job.serviceIndex,
						http:         httpFP,
						tls:          tlsFP,
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
		for hi, host := range out {
			for si, svc := range host.Services {
				if svc.Name != "HTTP" && svc.Name != "HTTPS" {
					continue
				}
				select {
				case jobs <- enrichJob{
					hostIndex:    hi,
					serviceIndex: si,
					ip:           host.IP,
					service:      svc,
				}:
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

	for result := range results {
		out[result.hostIndex].Services[result.serviceIndex].HTTP = result.http
		out[result.hostIndex].Services[result.serviceIndex].TLS = result.tls
	}

	return out
}

func cloneHosts(hosts []model.Host) []model.Host {
	out := make([]model.Host, len(hosts))
	for i, host := range hosts {
		out[i] = host
		out[i].DiscoverySources = append([]string(nil), host.DiscoverySources...)
		out[i].Services = make([]model.Service, len(host.Services))
		copy(out[i].Services, host.Services)
	}
	return out
}
