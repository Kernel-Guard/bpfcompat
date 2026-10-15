package api

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kernel-guard/bpfcompat/internal/cloudregistry"
)

// resetDenialAuditLimiter installs a fresh limiter driven by nowFn and
// restores the previous one when the test ends.
func resetDenialAuditLimiter(t *testing.T, nowFn func() time.Time) *denialAuditLimiter {
	t.Helper()
	prev := defaultDenialAuditLimiter
	l := newDenialAuditLimiter(nowFn)
	defaultDenialAuditLimiter = l
	t.Cleanup(func() { defaultDenialAuditLimiter = prev })
	return l
}

func countAuditEvents(t *testing.T, workDir, tenant, project string) int {
	t.Helper()
	events, err := cloudregistry.NewStore(workDir).ListAuditEvents(tenant, project, 0)
	if err != nil {
		t.Fatalf("list audit events: %v", err)
	}
	return len(events)
}

// AUTHZ-F3: anonymous callers used to append one *_denied audit event per
// request into any caller-named tenant/project, before any rate limit,
// letting a flood rotate genuine audit history out of the capped log.
func TestRegistryUnauthenticatedDenialAuditIsRateLimited(t *testing.T) {
	defaultRegistryLimiter = newInMemoryRateLimiter(time.Now)
	resetDenialAuditLimiter(t, time.Now)
	t.Setenv("BPFCOMPAT_REGISTRY_AUTH_TOKEN", "admin-boot")
	t.Setenv("BPFCOMPAT_REGISTRY_RATE_LIMIT_MAX_REQUESTS", "3")
	workDir := t.TempDir()
	s := &Server{cfg: Config{WorkDir: workDir}}
	const n = 50
	for i := 0; i < n; i++ {
		req := httptest.NewRequest(http.MethodGet, "/api/registry/artifacts?tenant=victim&project=prod", http.NoBody)
		if i%2 == 1 {
			// A garbage bearer token is still "no valid credential".
			req.Header.Set("Authorization", fmt.Sprintf("Bearer guess-%d", i))
		}
		rec := httptest.NewRecorder()
		s.handleRegistryArtifacts(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("iteration %d: expected 401 (response must not change), got %d", i, rec.Code)
		}
	}
	got := countAuditEvents(t, workDir, "victim", "prod")
	if got == 0 {
		t.Fatalf("expected some unauthenticated denials to still be audited, got 0")
	}
	if got > denialAuditPerClientBurst {
		t.Fatalf("anonymous flood wrote %d audit events into victim/prod; want <= %d", got, denialAuditPerClientBurst)
	}
}

func TestRegistryUnauthenticatedDenialAuditRefillsOverTime(t *testing.T) {
	now := time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)
	resetDenialAuditLimiter(t, func() time.Time { return now })
	t.Setenv("BPFCOMPAT_REGISTRY_AUTH_TOKEN", "admin-boot")
	workDir := t.TempDir()
	s := &Server{cfg: Config{WorkDir: workDir}}
	hit := func() {
		req := httptest.NewRequest(http.MethodGet, "/api/registry/artifacts?tenant=victim&project=prod", http.NoBody)
		s.handleRegistryArtifacts(httptest.NewRecorder(), req)
	}
	for i := 0; i < 3*denialAuditPerClientBurst; i++ {
		hit()
	}
	if got := countAuditEvents(t, workDir, "victim", "prod"); got != denialAuditPerClientBurst {
		t.Fatalf("expected burst of %d audited denials, got %d", denialAuditPerClientBurst, got)
	}
	now = now.Add(time.Hour)
	hit()
	if got := countAuditEvents(t, workDir, "victim", "prod"); got != denialAuditPerClientBurst+1 {
		t.Fatalf("expected denial audit to resume after refill, got %d", got)
	}
}

// A different client IP has its own budget; X-Forwarded-For is ignored
// unless the direct peer is a configured trusted proxy.
func TestRegistryDenialAuditLimiterKeysOnClientIPWithoutTrustingXFF(t *testing.T) {
	resetDenialAuditLimiter(t, time.Now)
	t.Setenv("BPFCOMPAT_REGISTRY_AUTH_TOKEN", "admin-boot")
	t.Setenv(envTrustedProxies, "")
	workDir := t.TempDir()
	s := &Server{cfg: Config{WorkDir: workDir}}
	for i := 0; i < 3*denialAuditPerClientBurst; i++ {
		req := httptest.NewRequest(http.MethodGet, "/api/registry/artifacts?tenant=victim&project=prod", http.NoBody)
		req.RemoteAddr = "198.51.100.7:4000"
		req.Header.Set("X-Forwarded-For", fmt.Sprintf("203.0.113.%d", i))
		s.handleRegistryArtifacts(httptest.NewRecorder(), req)
	}
	if got := countAuditEvents(t, workDir, "victim", "prod"); got != denialAuditPerClientBurst {
		t.Fatalf("spoofed XFF must not mint new budgets: got %d audited, want %d", got, denialAuditPerClientBurst)
	}
	req := httptest.NewRequest(http.MethodGet, "/api/registry/artifacts?tenant=victim&project=prod", http.NoBody)
	req.RemoteAddr = "198.51.100.8:4000"
	s.handleRegistryArtifacts(httptest.NewRecorder(), req)
	if got := countAuditEvents(t, workDir, "victim", "prod"); got != denialAuditPerClientBurst+1 {
		t.Fatalf("a distinct client must keep its own audit budget, got %d", got)
	}
}

// Authenticated principals (a valid credential lacking scope) are always
// audited, no matter how many denials the same client produces.
func TestRegistryAuthenticatedDenialAlwaysAudited(t *testing.T) {
	defaultRegistryLimiter = newInMemoryRateLimiter(time.Now)
	resetDenialAuditLimiter(t, time.Now)
	t.Setenv("BPFCOMPAT_REGISTRY_AUTH_TOKEN", "admin-boot")
	workDir := t.TempDir()
	s := &Server{cfg: Config{WorkDir: workDir}}
	seedTenantScopeProject(t, s, "victim", "prod", "private", "admin-boot")
	if err := cloudregistry.NewStore(workDir).WriteAuthConfig(cloudregistry.AuthConfig{SchemaVersion: "cloud_registry_auth.v0.1", Tokens: []cloudregistry.TokenGrant{{
		Token: "other-tenant-token", Subject: "operator@other", Tenant: "other", Projects: []string{"*"}, CanRead: true,
	}}}); err != nil {
		t.Fatalf("save auth config: %v", err)
	}
	before := countAuditEvents(t, workDir, "victim", "prod")
	const n = 3 * denialAuditPerClientBurst
	for i := 0; i < n; i++ {
		req := httptest.NewRequest(http.MethodGet, "/api/registry/artifacts?tenant=victim&project=prod", http.NoBody)
		req.Header.Set("Authorization", "Bearer other-tenant-token")
		rec := httptest.NewRecorder()
		s.handleRegistryArtifacts(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("iteration %d: expected 403, got %d %s", i, rec.Code, rec.Body.String())
		}
	}
	if got := countAuditEvents(t, workDir, "victim", "prod") - before; got != n {
		t.Fatalf("authenticated denials must all be audited: got %d, want %d", got, n)
	}
}

// Legitimate traffic is unaffected even after the client's anonymous
// denial-audit budget is exhausted.
func TestRegistryDenialAuditLimiterDoesNotAffectLegitTraffic(t *testing.T) {
	defaultRegistryLimiter = newInMemoryRateLimiter(time.Now)
	resetDenialAuditLimiter(t, time.Now)
	t.Setenv("BPFCOMPAT_REGISTRY_AUTH_TOKEN", "admin-boot")
	workDir := t.TempDir()
	s := &Server{cfg: Config{WorkDir: workDir}}
	seedTenantScopeProject(t, s, "victim", "prod", "private", "admin-boot")
	for i := 0; i < 3*denialAuditPerClientBurst; i++ {
		req := httptest.NewRequest(http.MethodGet, "/api/registry/artifacts?tenant=victim&project=prod", http.NoBody)
		s.handleRegistryArtifacts(httptest.NewRecorder(), req)
	}
	req := httptest.NewRequest(http.MethodGet, "/api/registry/artifacts?tenant=victim&project=prod", http.NoBody)
	req.Header.Set("Authorization", "Bearer admin-boot")
	rec := httptest.NewRecorder()
	s.handleRegistryArtifacts(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "secretapp") {
		t.Fatalf("legit read after anonymous flood: %d %s", rec.Code, rec.Body.String())
	}
}

func TestDenialAuditLimiterMemoryBounded(t *testing.T) {
	l := newDenialAuditLimiter(time.Now)
	for i := 0; i < 3*denialAuditMaxClients; i++ {
		l.allow(fmt.Sprintf("client-%d", i))
	}
	if got := l.size(); got > denialAuditMaxClients {
		t.Fatalf("limiter tracks %d clients; want <= %d", got, denialAuditMaxClients)
	}
}

// Rotating client keys cannot exceed the global budget.
func TestDenialAuditLimiterGlobalCap(t *testing.T) {
	l := newDenialAuditLimiter(func() time.Time { return time.Unix(1_000_000, 0) })
	allowed := 0
	for i := 0; i < 10*denialAuditGlobalBurst; i++ {
		if l.allow(fmt.Sprintf("client-%d", i)) {
			allowed++
		}
	}
	if allowed != denialAuditGlobalBurst {
		t.Fatalf("global cap: allowed %d, want %d", allowed, denialAuditGlobalBurst)
	}
}

func TestDenialAuditClientKeyGroupsIPv6Slash64(t *testing.T) {
	t.Setenv(envTrustedProxies, "")
	a := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	a.RemoteAddr = "[2001:db8:1:2::1]:443"
	b := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	b.RemoteAddr = "[2001:db8:1:2:ffff::9]:443"
	c := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
	c.RemoteAddr = "[2001:db8:1:3::1]:443"
	if denialAuditClientKey(a) != denialAuditClientKey(b) {
		t.Fatalf("same /64 must share a key: %q vs %q", denialAuditClientKey(a), denialAuditClientKey(b))
	}
	if denialAuditClientKey(a) == denialAuditClientKey(c) {
		t.Fatalf("different /64 must not share a key")
	}
}

func TestAgentDecisionUnauthenticatedDenialAuditIsRateLimited(t *testing.T) {
	for _, tc := range []struct {
		name     string
		identity bool
	}{
		{name: "registry_token", identity: false},
		{name: "identity_token", identity: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resetDenialAuditLimiter(t, time.Now)
			t.Setenv("BPFCOMPAT_REGISTRY_AUTH_TOKEN", "admin-boot")
			if tc.identity {
				t.Setenv(envRegistryRequireIdentity, "true")
				t.Setenv(envWriteJWTSecret, "test-secret-for-identity-verification")
			}
			workDir := t.TempDir()
			s := &Server{cfg: Config{WorkDir: workDir}}
			for i := 0; i < 50; i++ {
				req := httptest.NewRequest(http.MethodPost, "/api/v1/agent/decision", strings.NewReader(`{
					"tenant":"victim","project":"prod","artifact_name":"aegis",
					"host_probe":{"schema_version":"runtime_probe.v0.1"}}`))
				req.Header.Set("Content-Type", "application/json")
				rec := httptest.NewRecorder()
				s.handleAgentDecision(rec, req)
				if rec.Code != http.StatusUnauthorized {
					t.Fatalf("iteration %d: expected 401, got %d %s", i, rec.Code, rec.Body.String())
				}
			}
			got := countAuditEvents(t, workDir, "victim", "prod")
			if got == 0 || got > denialAuditPerClientBurst {
				t.Fatalf("anonymous agent-decision flood wrote %d audit events; want 1..%d", got, denialAuditPerClientBurst)
			}
		})
	}
}
