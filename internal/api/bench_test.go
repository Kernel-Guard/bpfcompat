package api

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"
	"time"
)

// BenchmarkParseWriteIdentityJWT measures the JWT verification cost on the
// happy path. Every authenticated API request runs this once, so a sub-µs
// regression here is felt at scale. We benchmark HS256 specifically because
// it's the deterministic verification path (RS256 would benchmark the RSA
// scalar mul cost which dwarfs everything else and obscures parser
// regressions).
func BenchmarkParseWriteIdentityJWT(b *testing.B) {
	secret := "bench-hs256-secret"
	token := buildHS256TokenForBench(b, secret)
	cfg := writeJWTVerificationConfig{
		HS256Secret: secret,
		NowFn:       func() time.Time { return time.Unix(1_700_000_000, 0) },
	}
	now := cfg.now()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := parseWriteIdentityJWT(token, cfg, now)
		if err != nil {
			b.Fatalf("parse JWT: %v", err)
		}
	}
}

// BenchmarkNormalizeMetricsRoute exercises the metrics route normalizer for
// every request path shape we expect to see. Anything that pushes its cost
// up materially shows up as elevated p99 latency under load because the
// normalizer runs on every metrics-enabled request.
func BenchmarkNormalizeMetricsRoute(b *testing.B) {
	inputs := []string{
		"/",
		"/livez",
		"/api/v1/health",
		"/api/v1/runtime/fetch",
		"/api/v1/registry/artifacts/upload",
		"/api/registry/artifacts/download",
		"/results",
		"/etc/passwd",
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = normalizeMetricsRoute(inputs[i%len(inputs)])
	}
}

func buildHS256TokenForBench(b *testing.B, secret string) string {
	b.Helper()
	headerJSON, err := json.Marshal(map[string]any{"alg": "HS256", "typ": "JWT"})
	if err != nil {
		b.Fatalf("marshal header: %v", err)
	}
	claimsJSON, err := json.Marshal(map[string]any{
		"sub":      "svc-bench",
		"tenant":   "acme",
		"projects": []string{"demo"},
		"exp":      time.Now().Add(1 * time.Hour).Unix(),
	})
	if err != nil {
		b.Fatalf("marshal claims: %v", err)
	}
	enc := base64.RawURLEncoding.EncodeToString
	headerPart := enc(headerJSON)
	claimsPart := enc(claimsJSON)
	signing := headerPart + "." + claimsPart
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(signing))
	sig := enc(mac.Sum(nil))
	return fmt.Sprintf("%s.%s", signing, sig)
}
