package vcs

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"syscall"
	"time"
)

var blockedCIDRs = mustParsePrefixes([]string{
	"0.0.0.0/8",       // Unspecified / current network
	"10.0.0.0/8",      // RFC1918 private
	"100.64.0.0/10",   // RFC6598 CGNAT / Tailscale
	"127.0.0.0/8",     // Loopback
	"169.254.0.0/16",  // Link-local / Cloud IMDS (169.254.169.254)
	"172.16.0.0/12",   // RFC1918 private
	"192.0.0.0/24",    // IETF protocol assignments
	"192.0.2.0/24",    // TEST-NET-1
	"192.168.0.0/16",  // RFC1918 private
	"198.18.0.0/15",   // Benchmarking
	"198.51.100.0/24", // TEST-NET-2
	"203.0.113.0/24",  // TEST-NET-3
	"224.0.0.0/4",     // IPv4 Multicast
	"240.0.0.0/4",     // Reserved / Broadcast
	"::/128",          // IPv6 Unspecified
	"::1/128",         // IPv6 Loopback
	"64:ff9b::/96",    // IPv6 NAT64 well-known prefix
	"64:ff9b:1::/48",  // IPv6 NAT64 local-use
	"100::/64",        // Discard-only
	"2001::/32",       // Teredo tunneling
	"2001:db8::/32",   // Documentation
	"2002::/16",       // 6to4 tunneling
	"fc00::/7",        // IPv6 Unique Local (ULA, incl. AWS fd00:ec2::254 IMDSv2)
	"fe80::/10",       // IPv6 Link-local
	"ff00::/8",        // IPv6 Multicast
})

func mustParsePrefixes(raw []string) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(raw))
	for _, s := range raw {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			panic(err)
		}
		out = append(out, p)
	}
	return out
}

// IsPublicAddr returns true ONLY if addr is a globally routable public unicast IP
// (rejecting loopback, RFC1918, cloud IMDS, CGNAT, IPv6 ULA/NAT64/6to4/Teredo, multicast, and unspecified).
func IsPublicAddr(addr netip.Addr) bool {
	if !addr.IsValid() {
		return false
	}
	unmapped := addr.Unmap()
	if unmapped.IsLoopback() || unmapped.IsPrivate() || unmapped.IsLinkLocalUnicast() ||
		unmapped.IsLinkLocalMulticast() || unmapped.IsMulticast() || unmapped.IsUnspecified() {
		return false
	}
	for _, prefix := range blockedCIDRs {
		if prefix.Contains(unmapped) {
			return false
		}
	}
	return true
}

// SafeDialControl enforces public-IP-only socket connections at dial time (defeating DNS rebinding and SSRF).
func SafeDialControl(network, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("invalid dial address %q: %w", address, err)
	}
	// Strip IPv6 zone if present
	if zoneIdx := strings.IndexByte(host, '%'); zoneIdx != -1 {
		host = host[:zoneIdx]
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return fmt.Errorf("non-IP dial target %q rejected: %w", host, err)
	}
	if !IsPublicAddr(addr) {
		return fmt.Errorf("SSRF guard blocked connection to non-public IP %s", addr.String())
	}
	return nil
}

// NewSafeHTTPClient constructs an SSRF-hardened HTTPS-only HTTP client for untrusted repository verification.
func NewSafeHTTPClient(timeout time.Duration) *http.Client {
	if timeout <= 0 {
		timeout = 400 * time.Millisecond
	}
	dialer := &net.Dialer{
		Timeout: timeout,
		Control: SafeDialControl,
	}
	transport := &http.Transport{
		Proxy:                 nil, // Ignore ambient HTTP_PROXY manipulation for untrusted VCS probes
		DialContext:           dialer.DialContext,
		TLSHandshakeTimeout:   timeout,
		ResponseHeaderTimeout: timeout,
		DisableKeepAlives:     true,
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return fmt.Errorf("excessive VCS redirects")
			}
			if !strings.EqualFold(req.URL.Scheme, "https") {
				return fmt.Errorf("refusing redirect to non-HTTPS scheme %q", req.URL.Scheme)
			}
			// Never forward Authorization header across host boundaries
			if len(via) > 0 && !strings.EqualFold(req.URL.Hostname(), via[0].URL.Hostname()) {
				req.Header.Del("Authorization")
			}
			return nil
		},
	}
}
