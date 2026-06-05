package cloudregistry

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/erenari/bpfcompat/pkg/schema"
)

func TestProjectLifecycleAndList(t *testing.T) {
	store := NewStore(t.TempDir())

	created, err := store.UpsertProject(CreateProjectInput{
		Tenant:            "acme",
		Project:           "agent",
		Visibility:        "private",
		DefaultMatrixPath: "matrices/mvp.yaml",
	})
	if err != nil {
		t.Fatalf("upsert project: %v", err)
	}
	if created.Tenant != "acme" || created.Project != "agent" {
		t.Fatalf("unexpected project identity: %+v", created)
	}
	if created.Visibility != "private" {
		t.Fatalf("unexpected visibility: %q", created.Visibility)
	}

	updated, err := store.UpsertProject(CreateProjectInput{
		Tenant:     "acme",
		Project:    "agent",
		Visibility: "public",
	})
	if err != nil {
		t.Fatalf("update project: %v", err)
	}
	if updated.Visibility != "public" {
		t.Fatalf("expected updated visibility public, got %q", updated.Visibility)
	}
	if updated.CreatedAt != created.CreatedAt {
		t.Fatalf("created_at should remain stable")
	}

	got, err := store.GetProject("acme", "agent")
	if err != nil {
		t.Fatalf("get project: %v", err)
	}
	if got.Visibility != "public" {
		t.Fatalf("expected public visibility, got %q", got.Visibility)
	}

	projects, err := store.ListProjects("acme", 10)
	if err != nil {
		t.Fatalf("list projects: %v", err)
	}
	if len(projects) != 1 {
		t.Fatalf("expected 1 project, got %d", len(projects))
	}
}

func TestAuthorizeTokenAndReadFallback(t *testing.T) {
	workDir := t.TempDir()
	store := NewStore(workDir)

	if _, err := store.UpsertProject(CreateProjectInput{
		Tenant:     "acme",
		Project:    "private-demo",
		Visibility: "private",
	}); err != nil {
		t.Fatalf("create private project: %v", err)
	}
	if _, err := store.UpsertProject(CreateProjectInput{
		Tenant:     "acme",
		Project:    "public-demo",
		Visibility: "public",
	}); err != nil {
		t.Fatalf("create public project: %v", err)
	}

	authPath := filepath.Join(workDir, "cloud-registry", "auth", "tokens.json")
	if err := os.MkdirAll(filepath.Dir(authPath), 0o755); err != nil {
		t.Fatalf("mkdir auth dir: %v", err)
	}
	cfg := AuthConfig{
		SchemaVersion: authSchemaVersion,
		Tokens: []TokenGrant{
			{
				Token:    "writer-token",
				Subject:  "writer",
				Tenant:   "acme",
				Projects: []string{"private-demo"},
				CanRead:  true,
				CanWrite: true,
			},
			{
				Token:    "reader-token",
				Subject:  "reader",
				Tenant:   "acme",
				Projects: []string{"public-demo"},
				CanRead:  true,
				CanWrite: false,
			},
		},
	}
	raw, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		t.Fatalf("marshal auth config: %v", err)
	}
	raw = append(raw, '\n')
	if err := os.WriteFile(authPath, raw, 0o644); err != nil {
		t.Fatalf("write auth config: %v", err)
	}

	writer, err := store.AuthorizeToken("writer-token", "acme", "private-demo", true)
	if err != nil {
		t.Fatalf("authorize writer token: %v", err)
	}
	if !writer.CanWrite {
		t.Fatalf("writer should be writable")
	}

	if _, err := store.AuthorizeToken("reader-token", "acme", "public-demo", true); !errors.Is(err, ErrForbidden) {
		t.Fatalf("expected forbidden for write with reader token, got %v", err)
	}

	if _, err := store.AuthorizeRead("", "acme", "public-demo"); err != nil {
		t.Fatalf("public project should allow anonymous read: %v", err)
	}
	if _, err := store.AuthorizeRead("", "acme", "private-demo"); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("private project should reject anonymous read, got %v", err)
	}

	t.Setenv(bootstrapTokenEnv, "bootstrap-secret")
	if _, err := store.AuthorizeToken("bootstrap-secret", "acme", "private-demo", true); err != nil {
		t.Fatalf("bootstrap token should authorize write: %v", err)
	}
}

func TestUploadArtifactAndVerifyHistory(t *testing.T) {
	workDir := t.TempDir()
	store := NewStore(workDir)
	if _, err := store.UpsertProject(CreateProjectInput{
		Tenant:     "acme",
		Project:    "runtime",
		Visibility: "private",
	}); err != nil {
		t.Fatalf("create project: %v", err)
	}

	report := schema.ReportV01{
		SchemaVersion: "v0.1",
		Run: schema.RunInfo{
			ID:        "run-123",
			StartedAt: "2026-05-16T19:30:00Z",
		},
		Artifact: schema.Artifact{
			Path:      "/tmp/example.bpf.o",
			BaseName:  "example.bpf.o",
			SHA256:    "unused",
			SizeBytes: 4,
		},
		Matrix: schema.MatrixInfo{
			Path: "/tmp/mvp.yaml",
			Name: "mvp",
		},
		Targets: []schema.Target{
			{ProfileID: "ubuntu-22.04-5.15", Required: true, Status: "pass"},
			{ProfileID: "ubuntu-18.04-4.15", Required: true, Status: "fail", ClassificationCode: "UNSUPPORTED_MAP_TYPE"},
		},
		Summary: schema.SummaryInfo{Status: "fail"},
	}

	result, err := store.UploadArtifact(UploadInput{
		Tenant:          "acme",
		Project:         "runtime",
		ArtifactName:    "execsnoop",
		ArtifactVersion: "v1.0.0",
		ArtifactVariant: "ringbuf-modern",
		ArtifactReader:  strings.NewReader("BPF!"),
		Report:          &report,
	})
	if err != nil {
		t.Fatalf("upload artifact: %v", err)
	}

	if result.Record.ArtifactName != "execsnoop" || result.Record.ArtifactVersion != "v1.0.0" {
		t.Fatalf("unexpected stored record identity: %+v", result.Record)
	}
	if result.Record.RecordSHA256 == "" || result.Record.Signature == "" {
		t.Fatalf("expected signed provenance fields on stored record")
	}
	if _, err := os.Stat(result.StoredArtifact); err != nil {
		t.Fatalf("stored artifact path missing: %v", err)
	}

	versions, err := store.ListArtifactVersions("acme", "runtime", "execsnoop", 10)
	if err != nil {
		t.Fatalf("list artifact versions: %v", err)
	}
	if len(versions) != 1 {
		t.Fatalf("expected 1 artifact version record, got %d", len(versions))
	}

	verification, err := store.VerifyHistory("acme", "runtime")
	if err != nil {
		t.Fatalf("verify history: %v", err)
	}
	if len(verification) != 1 || !verification[0].Verified {
		t.Fatalf("expected verified history row, got %+v", verification)
	}

	if _, err := store.UploadArtifact(UploadInput{
		Tenant:          "acme",
		Project:         "runtime",
		ArtifactName:    "execsnoop",
		ArtifactVersion: "v1.0.0",
		ArtifactReader:  strings.NewReader("BPF!"),
	}); !errors.Is(err, ErrConflict) {
		t.Fatalf("expected conflict on duplicate artifact version, got %v", err)
	}
}

func TestAuditEvents(t *testing.T) {
	store := NewStore(t.TempDir())
	if _, err := store.AppendAudit(AuditEvent{
		Action:  "upload",
		Actor:   "writer",
		Tenant:  "acme",
		Project: "alpha",
		Status:  "success",
	}); err != nil {
		t.Fatalf("append first audit: %v", err)
	}
	if _, err := store.AppendAudit(AuditEvent{
		Action:  "download",
		Actor:   "reader",
		Tenant:  "acme",
		Project: "beta",
		Status:  "success",
	}); err != nil {
		t.Fatalf("append second audit: %v", err)
	}

	filtered, err := store.ListAuditEvents("acme", "alpha", 20)
	if err != nil {
		t.Fatalf("list filtered audit events: %v", err)
	}
	if len(filtered) != 1 || filtered[0].Project != "alpha" {
		t.Fatalf("expected single filtered audit event, got %+v", filtered)
	}
}

func TestUploadArtifactQuotaVersionLimit(t *testing.T) {
	t.Setenv(maxArtifactVersionsPerNameEnv, "1")
	workDir := t.TempDir()
	store := NewStore(workDir)
	if _, err := store.UpsertProject(CreateProjectInput{
		Tenant:     "acme",
		Project:    "quota",
		Visibility: "private",
	}); err != nil {
		t.Fatalf("create project: %v", err)
	}

	first, err := store.UploadArtifact(UploadInput{
		Tenant:          "acme",
		Project:         "quota",
		ArtifactName:    "demo",
		ArtifactVersion: "v1",
		ArtifactReader:  strings.NewReader("artifact-1"),
	})
	if err != nil {
		t.Fatalf("first upload should pass: %v", err)
	}
	if first.Record.ArtifactVersion != "v1" {
		t.Fatalf("unexpected first version: %q", first.Record.ArtifactVersion)
	}

	_, err = store.UploadArtifact(UploadInput{
		Tenant:          "acme",
		Project:         "quota",
		ArtifactName:    "demo",
		ArtifactVersion: "v2",
		ArtifactReader:  strings.NewReader("artifact-2"),
	})
	if !errors.Is(err, ErrQuotaExceeded) {
		t.Fatalf("expected quota exceeded on second version, got %v", err)
	}
}

func TestUploadArtifactQuotaSizeLimit(t *testing.T) {
	t.Setenv(maxArtifactBytesEnv, "4")
	workDir := t.TempDir()
	store := NewStore(workDir)
	if _, err := store.UpsertProject(CreateProjectInput{
		Tenant:     "acme",
		Project:    "size",
		Visibility: "private",
	}); err != nil {
		t.Fatalf("create project: %v", err)
	}

	_, err := store.UploadArtifact(UploadInput{
		Tenant:          "acme",
		Project:         "size",
		ArtifactName:    "demo",
		ArtifactVersion: "v1",
		ArtifactReader:  strings.NewReader("12345"),
	})
	if !errors.Is(err, ErrQuotaExceeded) {
		t.Fatalf("expected quota exceeded for artifact size, got %v", err)
	}
}

// TestAuthorizeTokenAcceptsHashedGrant regresses M-5. Tokens stored as
// HMAC-SHA256(salt, plaintext) must authorize the matching plaintext via
// AuthorizeToken; the legacy plaintext-on-disk form is still accepted to
// preserve backward compatibility while operators migrate.
func TestAuthorizeTokenAcceptsHashedGrant(t *testing.T) {
	workDir := t.TempDir()
	store := NewStore(workDir)
	if _, err := store.UpsertProject(CreateProjectInput{
		Tenant: "acme", Project: "demo", Visibility: "private",
	}); err != nil {
		t.Fatalf("upsert project: %v", err)
	}

	plaintext := "hashed-writer-secret-v1"
	hashed, err := HashTokenGrant(TokenGrant{
		Subject:  "writer",
		Tenant:   "acme",
		Projects: []string{"demo"},
		CanRead:  true,
		CanWrite: true,
	}, plaintext)
	if err != nil {
		t.Fatalf("HashTokenGrant: %v", err)
	}
	if strings.TrimSpace(hashed.Token) != "" {
		t.Fatalf("hashed grant should not carry plaintext Token, got %q", hashed.Token)
	}
	if strings.TrimSpace(hashed.TokenHash) == "" || strings.TrimSpace(hashed.TokenHashSalt) == "" {
		t.Fatalf("expected TokenHash + TokenHashSalt to be populated")
	}

	authPath := filepath.Join(workDir, "cloud-registry", "auth", "tokens.json")
	if err := os.MkdirAll(filepath.Dir(authPath), 0o755); err != nil {
		t.Fatalf("mkdir auth dir: %v", err)
	}
	cfg := AuthConfig{SchemaVersion: authSchemaVersion, Tokens: []TokenGrant{hashed}}
	raw, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		t.Fatalf("marshal auth config: %v", err)
	}
	if err := os.WriteFile(authPath, append(raw, '\n'), 0o644); err != nil {
		t.Fatalf("write auth config: %v", err)
	}

	if _, err := store.AuthorizeToken(plaintext, "acme", "demo", true); err != nil {
		t.Fatalf("hashed grant should accept matching plaintext: %v", err)
	}
	if _, err := store.AuthorizeToken("wrong-secret", "acme", "demo", true); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("wrong plaintext should be unauthorized, got %v", err)
	}
}

// TestTokenGrantMatchesFallsBackToPlaintext keeps the backward-compatible
// path covered: operators who haven't migrated their tokens.json yet must
// still be able to authenticate.
func TestTokenGrantMatchesFallsBackToPlaintext(t *testing.T) {
	grant := TokenGrant{Token: "legacy-secret"}
	if !tokenGrantMatches(grant, "legacy-secret") {
		t.Fatalf("expected legacy plaintext grant to accept matching token")
	}
	if tokenGrantMatches(grant, "wrong") {
		t.Fatalf("legacy plaintext grant must reject non-matching token")
	}
	if tokenGrantMatches(TokenGrant{}, "") {
		t.Fatalf("empty grant + empty token must not match")
	}
}
