package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/erenari/bpfcompat/internal/cloudregistry"
)

// TestAdminListTokensJSONRoundtrip seeds tokens.json with a mix of hashed
// and plaintext grants, then asserts the JSON listing redacts plaintext
// and surfaces just enough metadata for an operator to identify each
// grant. Listing endpoint is the one most likely to grow into a leak if
// somebody adds a field without thinking — this test pins the surface.
func TestAdminListTokensJSONRoundtrip(t *testing.T) {
	workDir := t.TempDir()
	seedTokens(t, workDir, []cloudregistry.TokenGrant{
		{
			Subject:       "svc-a",
			Tenant:        "acme",
			Projects:      []string{"demo"},
			CanRead:       true,
			CanWrite:      true,
			TokenHash:     "deadbeefdeadbeef",
			TokenHashSalt: "c2FsdA==",
		},
		{
			Subject:  "svc-legacy",
			Tenant:   "acme",
			Projects: []string{"demo"},
			CanRead:  true,
			Token:    "secret-plaintext-token-DO-NOT-LEAK",
		},
	})

	// Capture stdout — runAdminListTokens writes JSON there in --json mode.
	stdout, restore := captureStdout(t)
	defer restore()

	code := runAdminListTokens([]string{"--workdir", workDir, "--json"})
	if code != 0 {
		t.Fatalf("list-tokens exited %d", code)
	}
	raw := stdout.read()
	if len(raw) == 0 {
		t.Fatalf("expected JSON output, got empty stdout")
	}
	var payload struct {
		Tokens []adminTokenSummary `json:"tokens"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatalf("decode json: %v body=%s", err, raw)
	}
	if len(payload.Tokens) != 2 {
		t.Fatalf("expected 2 tokens listed, got %d", len(payload.Tokens))
	}

	// CRITICAL: the raw plaintext token MUST NOT appear in the output.
	// summarizeTokens is the single function that controls this — if we
	// ever add a Token field to adminTokenSummary, this test fires.
	if got := string(raw); contains(got, "secret-plaintext-token-DO-NOT-LEAK") {
		t.Fatalf("plaintext token leaked in admin listing: %s", got)
	}
	// HashPrefix is set for the hashed grant but empty for the plaintext.
	var hashed, plain adminTokenSummary
	for _, tok := range payload.Tokens {
		if tok.Subject == "svc-a" {
			hashed = tok
		} else {
			plain = tok
		}
	}
	if !hashed.Hashed || hashed.HashPrefix == "" {
		t.Fatalf("hashed grant should have prefix: %+v", hashed)
	}
	if plain.Hashed || !plain.HasPlainTxt {
		t.Fatalf("plaintext grant should be marked: %+v", plain)
	}
}

// TestAdminRevokeTokenRemovesScopedSubject covers the happy path and the
// not-found path. revoke-token must error (non-zero exit) when the
// subject doesn't exist so operators can't believe a no-op succeeded —
// the original incident driver for this command was an operator
// confusing "subject not found" with "subject revoked".
func TestAdminRevokeTokenRemovesScopedSubject(t *testing.T) {
	workDir := t.TempDir()
	seedTokens(t, workDir, []cloudregistry.TokenGrant{
		{Subject: "svc-a", Tenant: "acme", Token: "tok-a"},
		{Subject: "svc-a", Tenant: "other", Token: "tok-a-other"},
		{Subject: "svc-b", Tenant: "acme", Token: "tok-b"},
	})

	if code := runAdminRevokeToken([]string{"--workdir", workDir, "--subject", "svc-a", "--tenant", "acme"}); code != 0 {
		t.Fatalf("revoke svc-a exited %d", code)
	}
	store := cloudregistry.NewStore(workDir)
	cfg, err := store.LoadAuthConfig()
	if err != nil {
		t.Fatalf("reload auth config: %v", err)
	}
	if len(cfg.Tokens) != 2 {
		t.Fatalf("expected 2 grants to remain, got %+v", cfg.Tokens)
	}
	for _, grant := range cfg.Tokens {
		if grant.Subject == "svc-a" && grant.Tenant == "acme" {
			t.Fatalf("tenant-scoped revoke removed wrong grant set: %+v", cfg.Tokens)
		}
	}

	// Revoking a missing subject must fail loudly.
	if code := runAdminRevokeToken([]string{"--workdir", workDir, "--subject", "does-not-exist", "--tenant", "acme"}); code == 0 {
		t.Fatalf("expected non-zero exit for unknown subject")
	}
}

// TestAdminRevokeTokenRequiresScope protects against accidentally removing
// the same service principal across tenants. Operators must name one tenant
// or explicitly opt into the broad --all-tenants blast radius.
func TestAdminRevokeTokenRequiresScope(t *testing.T) {
	workDir := t.TempDir()
	seedTokens(t, workDir, []cloudregistry.TokenGrant{
		{Subject: "svc-a", Tenant: "acme", Token: "tok-a"},
	})
	if code := runAdminRevokeToken([]string{"--workdir", workDir, "--subject", "svc-a"}); code == 0 {
		t.Fatalf("expected revoke without --tenant/--all-tenants to fail")
	}
	if code := runAdminRevokeToken([]string{"--workdir", workDir, "--subject", "svc-a", "--all-tenants", "--dry-run"}); code != 0 {
		t.Fatalf("expected explicit all-tenant dry-run revoke to succeed, got %d", code)
	}
}

func TestAdminRevokeTokenProjectScope(t *testing.T) {
	workDir := t.TempDir()
	seedTokens(t, workDir, []cloudregistry.TokenGrant{
		{Subject: "svc-a", Tenant: "acme", Projects: []string{"demo"}, Token: "tok-a-demo"},
		{Subject: "svc-a", Tenant: "acme", Projects: []string{"prod"}, Token: "tok-a-prod"},
	})
	if code := runAdminRevokeToken([]string{"--workdir", workDir, "--subject", "svc-a", "--tenant", "acme", "--project", "demo"}); code != 0 {
		t.Fatalf("project-scoped revoke exited %d", code)
	}
	store := cloudregistry.NewStore(workDir)
	cfg, err := store.LoadAuthConfig()
	if err != nil {
		t.Fatalf("reload auth config: %v", err)
	}
	if len(cfg.Tokens) != 1 || cfg.Tokens[0].Projects[0] != "prod" {
		t.Fatalf("expected only prod grant to remain, got %+v", cfg.Tokens)
	}
}

// TestAdminRevokeTokenDryRun proves --dry-run never touches the file.
// This is the safety story for production operators running revoke against
// a tokens.json they're not 100% sure about.
func TestAdminRevokeTokenDryRun(t *testing.T) {
	workDir := t.TempDir()
	seedTokens(t, workDir, []cloudregistry.TokenGrant{
		{Subject: "svc-a", Tenant: "acme", Token: "tok-a"},
	})
	before, err := os.ReadFile(tokensPath(workDir))
	if err != nil {
		t.Fatalf("read tokens.json: %v", err)
	}

	if code := runAdminRevokeToken([]string{"--workdir", workDir, "--subject", "svc-a", "--tenant", "acme", "--dry-run"}); code != 0 {
		t.Fatalf("dry-run revoke exited %d", code)
	}
	after, err := os.ReadFile(tokensPath(workDir))
	if err != nil {
		t.Fatalf("read tokens.json: %v", err)
	}
	if string(before) != string(after) {
		t.Fatalf("--dry-run modified tokens.json")
	}
}

// TestAdminVerifyChainEmpty exercises the verify-chain command on an empty
// workdir. The current implementation treats "no history yet" as success
// (zero records, zero invalid) and exits 0, which is the right call for a
// brand-new install — the command would otherwise refuse to run on day 1.
func TestAdminVerifyChainEmpty(t *testing.T) {
	workDir := t.TempDir()
	stdout, restore := captureStdout(t)
	defer restore()
	if code := runAdminVerifyChain([]string{"--workdir", workDir}); code != 0 {
		t.Fatalf("verify-chain on empty workdir exited %d output=%s", code, stdout.read())
	}
}

func seedTokens(t *testing.T, workDir string, grants []cloudregistry.TokenGrant) {
	t.Helper()
	dir := filepath.Join(workDir, "cloud-registry", "auth")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir auth: %v", err)
	}
	cfg := cloudregistry.AuthConfig{
		SchemaVersion: "cloud_registry_auth.v0.1",
		Tokens:        grants,
	}
	body, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		t.Fatalf("marshal cfg: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "tokens.json"), body, 0o600); err != nil {
		t.Fatalf("write tokens.json: %v", err)
	}
}

func tokensPath(workDir string) string {
	return filepath.Join(workDir, "cloud-registry", "auth", "tokens.json")
}

// captureStdout swaps os.Stdout for a pipe so we can assert on JSON output
// from admin subcommands. The reader returns whatever was written between
// the call and the deferred restore.
type stdoutCapture struct {
	r *os.File
	w *os.File
	t *testing.T
}

func (c *stdoutCapture) read() []byte {
	c.t.Helper()
	if err := c.w.Close(); err != nil {
		c.t.Fatalf("close pipe writer: %v", err)
	}
	c.w = nil
	buf := make([]byte, 64*1024)
	n, _ := c.r.Read(buf)
	return buf[:n]
}

func captureStdout(t *testing.T) (*stdoutCapture, func()) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	old := os.Stdout
	os.Stdout = w
	c := &stdoutCapture{r: r, w: w, t: t}
	return c, func() {
		if c.w != nil {
			_ = c.w.Close()
		}
		os.Stdout = old
		_ = r.Close()
	}
}

func contains(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
