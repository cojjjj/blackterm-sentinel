package discovery

import (
	"context"
	"net"
	"strings"
	"time"
)

func ReverseDNS(ctx context.Context, ip string) string {
	resolver := net.DefaultResolver
	lookupCtx, cancel := context.WithTimeout(ctx, 350*time.Millisecond)
	defer cancel()

	names, err := resolver.LookupAddr(lookupCtx, ip)
	if err != nil || len(names) == 0 {
		return ""
	}

	name := strings.TrimSuffix(names[0], ".")
	return name
}
