package diff

import (
	"fmt"
	"strings"
	"time"

	"github.com/cojjjj/blackterm-sentinel/internal/model"
)

func Compare(previous, current model.Snapshot, at time.Time) []model.Change {
	prevHosts := hostIndex(previous.Hosts)
	currHosts := hostIndex(current.Hosts)
	var changes []model.Change

	for ip, curr := range currHosts {
		prev, ok := prevHosts[ip]
		if !ok {
			changes = append(changes, model.Change{
				Type: model.HostAdded, Host: ip, DetectedAt: at,
			})
			for _, svc := range curr.Services {
				changes = append(changes, serviceChange(model.ServiceAdded, ip, svc, model.Service{}, at))
			}
			continue
		}
		changes = append(changes, compareServices(ip, prev.Services, curr.Services, at)...)
	}

	for ip, prev := range prevHosts {
		if _, ok := currHosts[ip]; ok {
			continue
		}
		for _, svc := range prev.Services {
			changes = append(changes, serviceChange(model.ServiceRemoved, ip, svc, model.Service{}, at))
		}
		changes = append(changes, model.Change{
			Type: model.HostRemoved, Host: ip, DetectedAt: at,
		})
	}

	return changes
}

func compareServices(ip string, prev, curr []model.Service, at time.Time) []model.Change {
	p := serviceIndex(prev)
	c := serviceIndex(curr)
	var changes []model.Change

	for key, now := range c {
		before, ok := p[key]
		if !ok {
			changes = append(changes, serviceChange(model.ServiceAdded, ip, now, model.Service{}, at))
			continue
		}
		if before.Name != now.Name || before.Banner != now.Banner || serviceFingerprint(before) != serviceFingerprint(now) {
			changes = append(changes, model.Change{
				Type:       model.ServiceChanged,
				Host:       ip,
				Port:       now.Port,
				Protocol:   now.Protocol,
				Service:    now.Name,
				Previous:   serviceFingerprint(before),
				Current:    serviceFingerprint(now),
				DetectedAt: at,
			})
		}
	}

	for key, before := range p {
		if _, ok := c[key]; !ok {
			changes = append(changes, serviceChange(model.ServiceRemoved, ip, before, model.Service{}, at))
		}
	}
	return changes
}

func serviceChange(t model.ChangeType, ip string, svc, _ model.Service, at time.Time) model.Change {
	return model.Change{
		Type:       t,
		Host:       ip,
		Port:       svc.Port,
		Protocol:   svc.Protocol,
		Service:    svc.Name,
		DetectedAt: at,
	}
}

func hostIndex(hosts []model.Host) map[string]model.Host {
	m := make(map[string]model.Host, len(hosts))
	for _, h := range hosts {
		m[h.IP] = h
	}
	return m
}

func serviceIndex(services []model.Service) map[string]model.Service {
	m := make(map[string]model.Service, len(services))
	for _, s := range services {
		key := fmt.Sprintf("%s/%d", s.Protocol, s.Port)
		m[key] = s
	}
	return m
}

func serviceFingerprint(s model.Service) string {
	parts := []string{s.Name}
	if s.Banner != "" {
		parts = append(parts, s.Banner)
	}
	if s.HTTP != nil {
		parts = append(parts,
			fmt.Sprintf("http:%s:%d:%s:%s",
				s.HTTP.Scheme,
				s.HTTP.StatusCode,
				s.HTTP.Server,
				s.HTTP.Title,
			),
		)
	}
	if s.TLS != nil {
		parts = append(parts,
			fmt.Sprintf("tls:%s:%s:%s",
				s.TLS.Version,
				s.TLS.Subject,
				s.TLS.NotAfter.UTC().Format(time.RFC3339),
			),
		)
	}
	return strings.Join(parts, "|")
}
