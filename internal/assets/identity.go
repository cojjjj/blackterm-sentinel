package assets

import (
	"strings"

	"github.com/cojjjj/blackterm-sentinel/internal/model"
)

// IdentityKey prefers MAC identity because IP addresses can change.
// Hosts without a MAC fall back to their IP address.
func IdentityKey(host model.Host) string {
	if strings.TrimSpace(host.MAC) != "" {
		return "mac:" + strings.ToUpper(strings.TrimSpace(host.MAC))
	}
	return "ip:" + strings.TrimSpace(host.IP)
}
