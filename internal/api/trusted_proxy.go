package api

import (
	"net"
	"net/http"
	"os"
	"strings"
)

// Trusted-proxy handling.
//
// When the API runs behind a load balancer / ingress (the realistic SaaS
// shape), every request's RemoteAddr is the proxy's, not the client's. That
// breaks per-client rate limiting and turns the access log into a flat line
// of "192.0.2.1, 192.0.2.1, ...". X-Forwarded-For (or RFC 7239 Forwarded)
// solves it but is itself spoofable — a client connecting directly to the
// API can claim any IP it wants — so the server has to know which network
// hops are allowed to set that header before trusting it.
//
// The trust model:
//
//   - BPFCOMPAT_API_TRUSTED_PROXIES is a comma-separated list of CIDRs
//     considered "the load balancer". Only requests whose direct peer is in
//     one of these CIDRs have X-Forwarded-For honored.
//   - When the direct peer is trusted, the rightmost untrusted address in
//     the X-Forwarded-For list becomes the client IP. (Rightmost-untrusted,
//     not leftmost, defeats spoofing: a client controlling the header can't
//     prepend a fake; the proxy appends.)
//   - When the direct peer is not trusted, X-Forwarded-For is ignored and
//     the direct peer is the client.
//
// This is the same model NGINX's real_ip module, HAProxy's accept-proxy,
// and the Kubernetes externalTrafficPolicy=Local document. Anything more
// elaborate (PROXY protocol, RFC 7239 Forwarded) lives behind explicit env.

const (
	// envTrustedProxies holds the comma-separated CIDRs (or bare IPs) of
	// trusted upstream proxies. Empty means "don't trust any forwarding
	// headers" — the safe default; operators behind a load balancer must
	// opt in explicitly.
	envTrustedProxies = "BPFCOMPAT_API_TRUSTED_PROXIES"
)

// trustedProxyConfig is a thin in-memory representation we resolve once per
// request. Parsing on every request keeps the env hot-reloadable without a
// SIGHUP plumbing; the cost is negligible compared to the rest of the
// handler chain (TLS, JSON, registry lookup).
type trustedProxyConfig struct {
	Nets []*net.IPNet
}

// loadTrustedProxies parses BPFCOMPAT_API_TRUSTED_PROXIES once per call.
// Bare IPs are accepted (and treated as /32 or /128); anything that fails
// to parse is silently skipped so a fat-fingered config entry can't take
// the whole list out of service.
func loadTrustedProxies() trustedProxyConfig {
	raw := strings.TrimSpace(os.Getenv(envTrustedProxies))
	if raw == "" {
		return trustedProxyConfig{}
	}
	cfg := trustedProxyConfig{}
	for _, part := range strings.Split(raw, ",") {
		entry := strings.TrimSpace(part)
		if entry == "" {
			continue
		}
		if !strings.Contains(entry, "/") {
			// Bare IP — promote to single-host CIDR.
			if ip := net.ParseIP(entry); ip != nil {
				if ip.To4() != nil {
					entry += "/32"
				} else {
					entry += "/128"
				}
			} else {
				continue
			}
		}
		_, n, err := net.ParseCIDR(entry)
		if err != nil {
			continue
		}
		cfg.Nets = append(cfg.Nets, n)
	}
	return cfg
}

func (c trustedProxyConfig) trusts(ip net.IP) bool {
	if ip == nil {
		return false
	}
	for _, n := range c.Nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// clientIP returns the best-effort end-client IP for the request. When the
// direct peer is one of the configured trusted proxies, the rightmost
// non-trusted entry in X-Forwarded-For is used. Otherwise the direct peer
// is returned. The result is always non-empty (RemoteAddr is the fallback
// so we never panic downstream on lookup).
func clientIP(r *http.Request) string {
	cfg := loadTrustedProxies()
	peerHost, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		peerHost = r.RemoteAddr
	}
	peerIP := net.ParseIP(strings.TrimSpace(peerHost))
	if !cfg.trusts(peerIP) {
		return peerHost
	}
	// Walk X-Forwarded-For right-to-left and return the rightmost address
	// that is NOT a trusted proxy. This is the spoofing-resistant choice
	// because the trusted proxy appends to XFF on the way in.
	hdr := r.Header.Values("X-Forwarded-For")
	for i := len(hdr) - 1; i >= 0; i-- {
		parts := strings.Split(hdr[i], ",")
		for j := len(parts) - 1; j >= 0; j-- {
			entry := parts[j]
			candidate := strings.TrimSpace(entry)
			if candidate == "" {
				continue
			}
			ip := net.ParseIP(candidate)
			if ip == nil {
				continue
			}
			if !cfg.trusts(ip) {
				return candidate
			}
		}
	}
	return peerHost
}
