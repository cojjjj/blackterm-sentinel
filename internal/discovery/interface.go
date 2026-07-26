package discovery

import (
	"fmt"
	"net"
)

type LocalInterface struct {
	Name string
	IP   string
	CIDR string
}

func Interfaces() ([]LocalInterface, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	var out []LocalInterface
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			ip, network, err := net.ParseCIDR(addr.String())
			if err != nil || ip.To4() == nil {
				continue
			}
			out = append(out, LocalInterface{
				Name: iface.Name,
				IP:   ip.String(),
				CIDR: fmt.Sprintf("%s/%d", network.IP.String(), maskSize(network.Mask)),
			})
		}
	}
	return out, nil
}

func MatchingInterface(target string) (LocalInterface, bool, error) {
	ip, network, err := net.ParseCIDR(target)
	if err != nil {
		parsed := net.ParseIP(target)
		if parsed == nil || parsed.To4() == nil {
			return LocalInterface{}, false, nil
		}
		ip = parsed
		network = &net.IPNet{IP: parsed.To4(), Mask: net.CIDRMask(32, 32)}
	}
	_ = ip

	ifaces, err := Interfaces()
	if err != nil {
		return LocalInterface{}, false, err
	}
	for _, iface := range ifaces {
		parsed := net.ParseIP(iface.IP)
		if parsed != nil && network.Contains(parsed) {
			return iface, true, nil
		}
	}
	return LocalInterface{}, false, nil
}

func maskSize(mask net.IPMask) int {
	ones, _ := mask.Size()
	return ones
}
