package target

import (
	"fmt"
	"net"
)

const maxHosts = 65536

func Expand(input string) ([]string, error) {
	if ip := net.ParseIP(input); ip != nil {
		if ip.To4() == nil {
			return nil, fmt.Errorf("IPv6 is not supported in Sentinel V0.1")
		}
		return []string{ip.String()}, nil
	}

	ip, network, err := net.ParseCIDR(input)
	if err != nil {
		return nil, fmt.Errorf("invalid target %q: expected IPv4 address or CIDR", input)
	}
	if ip.To4() == nil {
		return nil, fmt.Errorf("IPv6 is not supported in Sentinel V0.1")
	}

	var hosts []string
	for current := network.IP.Mask(network.Mask); network.Contains(current); inc(current) {
		v4 := current.To4()
		if v4 == nil {
			continue
		}
		hosts = append(hosts, net.IPv4(v4[0], v4[1], v4[2], v4[3]).String())
		if len(hosts) > maxHosts {
			return nil, fmt.Errorf("target expands beyond V0.1 safety limit of %d IPv4 addresses", maxHosts)
		}
	}

	if len(hosts) >= 2 {
		ones, bits := network.Mask.Size()
		if bits == 32 && ones <= 30 {
			hosts = hosts[1 : len(hosts)-1]
		}
	}

	if len(hosts) == 0 {
		return nil, fmt.Errorf("target contains no scannable IPv4 hosts")
	}
	return hosts, nil
}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}
