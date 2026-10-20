package api

import (
	"bytes"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/kernel-guard/bpfcompat/internal/cloudregistry"
)

func seedTenantScopeProject(t *testing.T, s *Server, tenant, project, visibility, token string) {
	t.Helper()
	body := `{"tenant":"` + tenant + `","project":"` + project + `","visibility":"` + visibility + `"}`
	req := httptest.NewRequest(http.MethodPost, "/api/registry/projects", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	s.handleRegistryProjects(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("seed project %s/%s: %d %s", tenant, project, rec.Code, rec.Body.String())
	}
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	_ = mw.WriteField("tenant", tenant)
	_ = mw.WriteField("project", project)
	_ = mw.WriteField("artifact_name", "secretapp")
	_ = mw.WriteField("artifact_version", "v1")
	fw, _ := mw.CreateFormFile("artifact_file", "a.bpf.o")
	_, _ = fw.Write([]byte("TENANT-" + tenant + "-PRIVATE-BYTES"))
	_ = mw.Close()
	up := httptest.NewRequest(http.MethodPost, "/api/registry/artifacts/upload", &buf)
	up.Header.Set("Authorization", "Bearer "+token)
	up.Header.Set("Content-Type", mw.FormDataContentType())
	upRec := httptest.NewRecorder()
	s.handleRegistryArtifactUpload(upRec, up)
	if upRec.Code != http.StatusOK {
		t.Fatalf("seed upload %s/%s: %d %s", tenant, project, upRec.Code, upRec.Body.String())
	}
}

// TestRegistryGrantWithoutTenantCannotReadOtherTenant regresses the
// cross-tenant read: a tokens.json grant with no "tenant" used to act as a
// tenant wildcard and could download another tenant's private artifact.
func TestRegistryGrantWithoutTenantCannotReadOtherTenant(t *testing.T) {
	defaultRegistryLimiter = newInMemoryRateLimiter(time.Now)
	t.Setenv("BPFCOMPAT_REGISTRY_AUTH_TOKEN", "admin-boot")
	workDir := t.TempDir()
	s := &Server{cfg: Config{WorkDir: workDir}}
	seedTenantScopeProject(t, s, "tenant-a", "app", "private", "admin-boot")
	seedTenantScopeProject(t, s, "tenant-b", "app", "private", "admin-boot")

	if err := cloudregistry.NewStore(workDir).WriteAuthConfig(cloudregistry.AuthConfig{
		SchemaVersion: "cloud_registry_auth.v0.1",
		Tokens: []cloudregistry.TokenGrant{
			{Token: "tok-a", Subject: "alice@tenant-a", Projects: []string{"app"}, CanRead: true},
		},
	}); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/api/registry/artifacts/download?tenant=tenant-b&project=app&artifact_name=secretapp&version=v1", http.NoBody)
	req.Header.Set("Authorization", "Bearer tok-a")
	rec := httptest.NewRecorder()
	s.handleRegistryArtifactDownload(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for an empty-tenant grant, got %d body=%q", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "TENANT-tenant-b") {
		t.Fatalf("tenant-b bytes leaked: %q", rec.Body.String())
	}
}

// TestRegistryAuditEventsRequireToken regresses the anonymous audit read: a
// public project's artifacts are anonymously readable, but its audit stream
// (actors, agent hostnames, denial messages) must require a registry token.
func TestRegistryAuditEventsRequireToken(t *testing.T) {
	defaultRegistryLimiter = newInMemoryRateLimiter(time.Now)
	t.Setenv("BPFCOMPAT_REGISTRY_AUTH_TOKEN", "admin-boot")
	workDir := t.TempDir()
	s := &Server{cfg: Config{WorkDir: workDir}}
	seedTenantScopeProject(t, s, "acme", "oss", "public", "admin-boot")
	store := cloudregistry.NewStore(workDir)
	_, _ = store.AppendAudit(cloudregistry.AuditEvent{
		Action: "agent_decision", Actor: "ci-deployer@acme.internal", Tenant: "acme", Project: "oss",
		Status: "success", Metadata: map[string]any{"agent_id": "prod-node-17.acme.internal"},
	})
	if err := store.WriteAuthConfig(cloudregistry.AuthConfig{
		SchemaVersion: "cloud_registry_auth.v0.1",
		Tokens: []cloudregistry.TokenGrant{
			{Token: "acme-reader", Subject: "acme-reader", Tenant: "acme", Projects: []string{"oss"}, CanRead: true},
			{Token: "other-reader", Subject: "other-reader", Tenant: "otherco", Projects: []string{"*"}, CanRead: true},
		},
	}); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name, token string
		want        int
	}{
		{"anonymous", "", http.StatusUnauthorized},
		{"other tenant token", "other-reader", http.StatusForbidden},
		{"tenant reader", "acme-reader", http.StatusOK},
	} {
		req := httptest.NewRequest(http.MethodGet, "/api/registry/audit/events?tenant=acme&project=oss", http.NoBody)
		if tc.token != "" {
			req.Header.Set("Authorization", "Bearer "+tc.token)
		}
		rec := httptest.NewRecorder()
		s.handleRegistryAuditEvents(rec, req)
		if rec.Code != tc.want {
			t.Fatalf("%s: expected %d, got %d body=%s", tc.name, tc.want, rec.Code, rec.Body.String())
		}
		leaked := strings.Contains(rec.Body.String(), "prod-node-17.acme.internal")
		if tc.want != http.StatusOK && leaked {
			t.Fatalf("%s: audit content leaked: %s", tc.name, rec.Body.String())
		}
		if tc.want == http.StatusOK && !leaked {
			t.Fatalf("%s: expected audit records, got %s", tc.name, rec.Body.String())
		}
	}
}

// TestIdentityProjectsClaimRequiresTenant regresses the JWT/mTLS identity
// gate: a projects claim without a tenant claim used to authorize that
// project name in every tenant (and projects:["*"] every tenant/project).
func TestIdentityProjectsClaimRequiresTenant(t *testing.T) {
	for _, id := range []writeAuthIdentity{
		{Subject: "x", AuthType: "jwt", Projects: []string{"app"}},
		{Subject: "x", AuthType: "jwt", Projects: []string{"*"}},
		{Subject: "x", AuthType: "mtls", Projects: []string{"app"}},
	} {
		if err := enforceWriteIdentityTenantProject(id, "tenant-b", "app"); err == nil {
			t.Fatalf("expected projects-only identity %+v to be rejected", id)
		}
	}
	scoped := writeAuthIdentity{Subject: "x", AuthType: "jwt", Tenant: "tenant-b", Projects: []string{"*"}}
	if err := enforceWriteIdentityTenantProject(scoped, "tenant-b", "app"); err != nil {
		t.Fatalf("tenant + projects wildcard must still pass: %v", err)
	}
	tenantOnly := writeAuthIdentity{Subject: "x", AuthType: "jwt", Tenant: "tenant-b"}
	if err := enforceWriteIdentityTenantProject(tenantOnly, "tenant-b", "app"); err != nil {
		t.Fatalf("tenant-only identity must still pass: %v", err)
	}
}
