package api

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

// FuzzParseWriteIdentityJWT exercises parseWriteIdentityJWT against arbitrary
// strings. The function performs JWT segment splitting, base64 decoding,
// JSON unmarshalling, and signature verification — every layer is a fuzz
// target. A successful parse must not produce a usable identity for invalid
// input; a failed parse must return a non-nil error and never panic.
func FuzzParseWriteIdentityJWT(f *testing.F) {
	// Seed with a couple of plausible tokens so the fuzzer mutates from real
	// JWT shape, not random bytes.
	f.Add("")
	f.Add("not.a.token")
	f.Add("abc.def.ghi")
	f.Add(syntheticUnsignedJWT(`{"alg":"HS256"}`, `{"sub":"x","exp":9999999999}`))
	f.Add(syntheticUnsignedJWT(`{"alg":"none"}`, `{"sub":"x"}`))
	f.Add(syntheticUnsignedJWT(`{"alg":"RS256","kid":"a"}`, `{"sub":"x","exp":9999999999}`))

	cfg := writeJWTVerificationConfig{
		HS256Secret: "fuzz-secret",
		NowFn:       func() time.Time { return time.Unix(1_700_000_000, 0) },
	}
	f.Fuzz(func(t *testing.T, token string) {
		defer func() {
			if rec := recover(); rec != nil {
				t.Fatalf("parseWriteIdentityJWT panicked: %v\ntoken=%q", rec, token)
			}
		}()
		_, _ = parseWriteIdentityJWT(token, cfg, cfg.now())
	})
}

// FuzzNormalizeMetricsRoute checks the route normalizer doesn't panic on
// hostile path shapes. A panic here would crash the metrics middleware and
// take the server down for every request.
func FuzzNormalizeMetricsRoute(f *testing.F) {
	f.Add("")
	f.Add("/")
	f.Add("/api/runtime/fetch")
	f.Add("/api/" + strings.Repeat("a/", 1024))
	f.Add("\x00\x01\x02")

	f.Fuzz(func(t *testing.T, path string) {
		defer func() {
			if rec := recover(); rec != nil {
				t.Fatalf("normalizeMetricsRoute panicked: %v\npath=%q", rec, path)
			}
		}()
		got := normalizeMetricsRoute(path)
		if got == "" {
			t.Fatalf("normalizeMetricsRoute returned empty for %q", path)
		}
	})
}

// syntheticUnsignedJWT produces a JWT-shaped string with a fake signature
// segment. Used as fuzzer seed material so mutators see realistic input.
func syntheticUnsignedJWT(header, claims string) string {
	enc := base64.RawURLEncoding.EncodeToString
	return enc([]byte(header)) + "." + enc([]byte(claims)) + ".AAAA"
}
