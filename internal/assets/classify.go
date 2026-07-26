package assets

import (
	"strings"

	"github.com/cojjjj/blackterm-sentinel/internal/model"
)

func Classify(hostname string, services []model.Service) string {
	name := strings.ToLower(strings.TrimSpace(hostname))

	switch {
	case containsAny(name, "iphone", "ipad", "android", "pixel", "galaxy"):
		return "MOBILE"
	case containsAny(name, "roku", "echo", "amazon-", "ringdoorbell", "litter-robot", "lg_smart", "mysimplelink"):
		return "IOT"
	case containsAny(name, "router", "gateway", "asus", "netgear", "orbi", "ubiquiti", "unifi"):
		return "NETWORK"
	case containsAny(name, "printer", "brother", "epson", "canon", "hp-", "laserjet"):
		return "PRINTER"
	case containsAny(name, "desktop", "laptop", "workstation", "pc-", "macbook", "imac"):
		return "WORKSTATION"
	}

	for _, svc := range services {
		switch strings.ToUpper(svc.Name) {
		case "RDP", "SMB", "MSRPC", "NETBIOS":
			return "WORKSTATION"
		case "IPP":
			return "PRINTER"
		}
	}

	return "UNKNOWN"
}

func containsAny(value string, needles ...string) bool {
	for _, needle := range needles {
		if strings.Contains(value, needle) {
			return true
		}
	}
	return false
}
