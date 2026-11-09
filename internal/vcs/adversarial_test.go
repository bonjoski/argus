package vcs

import (
	"context"
	"net/netip"
	"testing"

	"bonjoski/argus/internal/model"
)

// ARG-05: Enforce SSRF public-IP-only dialing, exact hostname matching, and inconclusive fallback on missing manifest.
func TestAdversarial_ARG05_SSRFGuardAndExactHostnameMatching(t *testing.T) {
	nonPublicIPs := []string{
		"127.0.0.1",
		"127.0.0.53",
		"10.0.0.1",
		"172.16.5.4",
		"192.168.1.1",
		"169.254.169.254", // AWS/GCP/Azure Cloud IMDS
		"100.64.0.1",      // CGNAT / Tailscale
		"0.0.0.0",
		"::1",
		"fe80::1",
		"fd00:ec2::254", // AWS IPv6 IMDS
		"64:ff9b::7f00:1",
	}

	for _, rawIP := range nonPublicIPs {
		addr, err := netip.ParseAddr(rawIP)
		if err != nil {
			t.Fatalf("failed to parse test IP %q: %v", rawIP, err)
		}
		if IsPublicAddr(addr) {
			t.Errorf("SSRF BYPASS: non-public IP %s classified as public!", rawIP)
		}
		if err := SafeDialControl("tcp", netJoinHostPort(rawIP, "443"), nil); err == nil {
			t.Errorf("SSRF BYPASS: SafeDialControl permitted connection to %s!", rawIP)
		}
	}

	if !IsPublicAddr(netip.MustParseAddr("140.82.121.4")) {
		t.Errorf("expected public GitHub IP 140.82.121.4 to be allowed")
	}

	// Production verifier (NewHTTPVerifier(nil)) must block IMDS, loopback, http://, and lookalike github.com domains
	prodVerifier := NewHTTPVerifier(nil)
	spoofedURLs := []string{
		"http://169.254.169.254/latest/meta-data",
		"https://127.0.0.1/facebook/react",
		"https://localhost/facebook/react",
		"http://github.com/facebook/react", // non-HTTPS downgrade
		"https://evil-github.com/facebook/react",
		"https://github.com.attacker.invalid/facebook/react",
	}

	for _, u := range spoofedURLs {
		res, err := prodVerifier.Verify(context.Background(), model.EcosystemNPM, "react", u)
		if err != nil {
			t.Fatalf("Verify(%q) unexpected error: %v", u, err)
		}
		if res.Status == model.VCSStatusVerified {
			t.Errorf("SECURITY BYPASS: spoofed/SSRF URL %q achieved VCSStatusVerified!", u)
		}
	}
}

func netJoinHostPort(host, port string) string {
	for i := 0; i < len(host); i++ {
		if host[i] == ':' {
			return "[" + host + "]:" + port
		}
	}
	return host + ":" + port
}
