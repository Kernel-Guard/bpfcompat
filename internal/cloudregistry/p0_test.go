package cloudregistry

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestAuthorizeTokenRejectsExpiredGrant regresses P0-6. ExpiresAt makes a
// grant unusable once the timestamp is reached; missing ExpiresAt preserves
// the legacy "never expires" semantics so existing tokens.json files keep
// working without manual migration.
func TestAuthorizeTokenRejectsExpiredGrant(t *testing.T) {
	workDir := t.TempDir()
	store := NewStore(workDir)
	store.nowFn = func() time.Time { return time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC) }
	if _, err := store.UpsertProject(CreateProjectInput{Tenant: "acme", Project: "demo", Visibility: "private"}); err != nil {
		t.Fatalf("upsert project: %v", err)
	}

	cfg := AuthConfig{
		SchemaVersion: authSchemaVersion,
		Tokens: []TokenGrant{
			{
				Token:     "expired-token",
				Subject:   "writer",
				Tenant:    "acme",
				Projects:  []string{"demo"},
				CanRead:   true,
				CanWrite:  true,
				ExpiresAt: "2026-01-01T00:00:00Z", // five months before nowFn
			},
			{
				Token:    "live-token",
				Subject:  "writer",
				Tenant:   "acme",
				Projects: []string{"demo"},
				CanRead:  true,
				CanWrite: true,
				// No ExpiresAt → never expires (legacy behaviour preserved).
			},
		},
	}
	writeAuthConfig(t, workDir, cfg)

	if _, err := store.AuthorizeToken("expired-token", "acme", "demo", true); err == nil {
		t.Fatalf("expected expired token to be rejected")
	} else if !errors.Is(err, ErrForbidden) && !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("expected expired token to surface as Forbidden/Unauthorized, got %v", err)
	}

	if _, err := store.AuthorizeToken("live-token", "acme", "demo", true); err != nil {
		t.Fatalf("expected legacy (no expiry) token to authorize: %v", err)
	}
}

// TestAuthorizeTokenHonorsNotBefore regresses the NotBefore half of P0-6.
func TestAuthorizeTokenHonorsNotBefore(t *testing.T) {
	workDir := t.TempDir()
	store := NewStore(workDir)
	store.nowFn = func() time.Time { return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) }
	if _, err := store.UpsertProject(CreateProjectInput{Tenant: "acme", Project: "demo", Visibility: "private"}); err != nil {
		t.Fatalf("upsert project: %v", err)
	}
	cfg := AuthConfig{
		SchemaVersion: authSchemaVersion,
		Tokens: []TokenGrant{
			{
				Token:     "future-token",
				Subject:   "writer",
				Tenant:    "acme",
				Projects:  []string{"demo"},
				CanRead:   true,
				CanWrite:  true,
				NotBefore: "2027-01-01T00:00:00Z",
			},
		},
	}
	writeAuthConfig(t, workDir, cfg)
	if _, err := store.AuthorizeToken("future-token", "acme", "demo", true); err == nil {
		t.Fatalf("expected not_before token to be rejected before its window")
	}

	store.nowFn = func() time.Time { return time.Date(2027, 6, 1, 0, 0, 0, 0, time.UTC) }
	if _, err := store.AuthorizeToken("future-token", "acme", "demo", true); err != nil {
		t.Fatalf("expected token inside not_before window to authorize: %v", err)
	}
}

func TestBootstrapTokenHonorsExpiry(t *testing.T) {
	t.Setenv(bootstrapTokenEnv, "bootstrap-secret")
	t.Setenv(bootstrapTokenExpiresAtEnv, "2026-01-01T00:00:00Z")

	store := NewStore(t.TempDir())
	store.nowFn = func() time.Time { return time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC) }
	if _, err := store.AuthorizeToken("bootstrap-secret", "acme", "demo", true); err == nil {
		t.Fatalf("expected expired bootstrap token to be rejected")
	}

	t.Setenv(bootstrapTokenExpiresAtEnv, "2027-01-01T00:00:00Z")
	if _, err := store.AuthorizeToken("bootstrap-secret", "acme", "demo", true); err != nil {
		t.Fatalf("expected bootstrap token inside expiry window to authorize: %v", err)
	}
}

// TestAuditLogRotation regresses P0-5. Once the active log exceeds MaxBytes,
// AppendAudit must (a) move it into the .1 slot, (b) start a fresh active
// file, and (c) keep ListAuditEvents merging across the retained shards so
// callers don't lose visibility into recent history. With MaxFiles large
// enough to hold every rotation we can also assert no events were evicted.
func TestAuditLogRotation(t *testing.T) {
	// Tiny cap so a handful of events triggers rotation. MaxFiles is set
	// generously so every rotation is retained — that lets us assert the
	// full event set is still queryable.
	t.Setenv(auditMaxBytesEnv, "512")
	t.Setenv(auditMaxFilesEnv, "20")

	workDir := t.TempDir()
	store := NewStore(workDir)
	if _, err := store.UpsertProject(CreateProjectInput{Tenant: "acme", Project: "demo", Visibility: "private"}); err != nil {
		t.Fatalf("upsert project: %v", err)
	}

	const total = 30
	for i := 0; i < total; i++ {
		_, err := store.AppendAudit(AuditEvent{
			Action: "project_read",
			Actor:  fmt.Sprintf("test-actor-%02d", i),
			Tenant: "acme", Project: "demo",
			Status: "success",
		})
		if err != nil {
			t.Fatalf("AppendAudit[%d]: %v", i, err)
		}
	}

	auditDir := filepath.Join(workDir, "cloud-registry", "audit")
	activePath := filepath.Join(auditDir, "events.jsonl")
	if _, err := os.Stat(activePath); err != nil {
		t.Fatalf("expected active audit file: %v", err)
	}
	if _, err := os.Stat(activePath + ".1"); err != nil {
		t.Fatalf("expected at least one rotated audit file (.1): %v", err)
	}

	events, err := store.ListAuditEvents("acme", "demo", 0)
	if err != nil {
		t.Fatalf("ListAuditEvents: %v", err)
	}
	if len(events) != total {
		t.Fatalf("expected %d events to survive rotation with MaxFiles=20, got %d", total, len(events))
	}
}

// TestAuditLogRotationRespectsMaxFiles confirms that the oldest rotation is
// evicted once we exceed MaxFiles. MaxFiles=2 means active + 2 rotations,
// so a fourth rotation file (.3) must not exist.
func TestAuditLogRotationRespectsMaxFiles(t *testing.T) {
	t.Setenv(auditMaxBytesEnv, "256")
	t.Setenv(auditMaxFilesEnv, "2")

	workDir := t.TempDir()
	store := NewStore(workDir)
	if _, err := store.UpsertProject(CreateProjectInput{Tenant: "acme", Project: "demo", Visibility: "private"}); err != nil {
		t.Fatalf("upsert project: %v", err)
	}
	// Write enough to force many rotations.
	for i := 0; i < 200; i++ {
		_, err := store.AppendAudit(AuditEvent{
			Action: "project_read",
			Actor:  fmt.Sprintf("evictor-%03d", i),
			Tenant: "acme", Project: "demo",
			Status: "success",
		})
		if err != nil {
			t.Fatalf("AppendAudit[%d]: %v", i, err)
		}
	}

	auditDir := filepath.Join(workDir, "cloud-registry", "audit")
	// events.jsonl, events.jsonl.1, events.jsonl.2 are allowed; .3 onwards
	// must be evicted by the rotation policy.
	for _, suffix := range []string{".3", ".4", ".5"} {
		if _, err := os.Stat(filepath.Join(auditDir, "events.jsonl"+suffix)); err == nil {
			t.Fatalf("rotation kept unexpected file %s; MaxFiles=2", "events.jsonl"+suffix)
		}
	}
}

// writeAuthConfig is a test helper that materializes the auth/tokens.json
// file. We do this from outside the Store on purpose so the test exercises
// the on-disk format the way real deployments do.
func writeAuthConfig(t *testing.T, workDir string, cfg AuthConfig) {
	t.Helper()
	path := filepath.Join(workDir, "cloud-registry", "auth", "tokens.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir auth dir: %v", err)
	}
	raw, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		t.Fatalf("marshal auth config: %v", err)
	}
	if err := os.WriteFile(path, append(raw, '\n'), 0o644); err != nil {
		t.Fatalf("write auth config: %v", err)
	}
	// Silence "imported and not used" if a future test trims helpers.
	_ = strings.TrimSpace
}
