package cloudregistry

import (
	"bytes"
	"errors"
	"log/slog"
	"strings"
	"testing"
)

// TestAuthorizeTokenEmptyGrantTenantIsNotWildcard regresses a cross-tenant
// finding: a grant whose "tenant" is empty or omitted used to match every
// tenant because matchScope treated an empty pattern like "*". Only an
// explicit "*" is a tenant wildcard now; an empty tenant denies.
func TestAuthorizeTokenEmptyGrantTenantIsNotWildcard(t *testing.T) {
	store := NewStore(t.TempDir())
	if err := store.WriteAuthConfig(AuthConfig{
		SchemaVersion: authSchemaVersion,
		Tokens: []TokenGrant{
			{Token: "no-tenant", Subject: "alice", Projects: []string{"app"}, CanRead: true},
			{Token: "blank-tenant", Subject: "bob", Tenant: "   ", Projects: []string{"*"}, CanRead: true, CanWrite: true},
			{Token: "star-tenant", Subject: "ops", Tenant: "*", Projects: []string{"*"}, CanRead: true},
			{Token: "acme-all", Subject: "acme", Tenant: "acme", CanRead: true},
		},
	}); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		token, tenant, project string
		write                  bool
	}{
		{"no-tenant", "tenant-a", "app", false},
		{"no-tenant", "tenant-b", "app", false},
		{"blank-tenant", "tenant-b", "app", false},
		{"blank-tenant", "tenant-b", "app", true},
		{"blank-tenant", "tenant-b", "", false},
	} {
		_, err := store.AuthorizeToken(tc.token, tc.tenant, tc.project, tc.write)
		if !errors.Is(err, ErrForbidden) {
			t.Fatalf("%s on %s/%s write=%v: expected ErrForbidden, got %v", tc.token, tc.tenant, tc.project, tc.write, err)
		}
	}

	// An explicit "*" tenant is still an intentional wildcard.
	if _, err := store.AuthorizeToken("star-tenant", "tenant-b", "app", false); err != nil {
		t.Fatalf("explicit tenant wildcard should still authorize: %v", err)
	}
	// Empty projects with an explicit tenant keeps meaning "every project of
	// that tenant" for project-scoped calls (existing behaviour).
	if _, err := store.AuthorizeToken("acme-all", "acme", "demo", false); err != nil {
		t.Fatalf("tenant-scoped grant with empty projects should authorize a project: %v", err)
	}
	if _, err := store.AuthorizeToken("acme-all", "other", "demo", false); !errors.Is(err, ErrForbidden) {
		t.Fatalf("tenant-scoped grant must not cross tenants, got %v", err)
	}
}

// TestLoadAuthConfigWarnsOnEmptyGrantTenant checks that operators get a clear
// warning (without the token value) for grants that are now inert, and that
// loading does not fail because of them.
func TestLoadAuthConfigWarnsOnEmptyGrantTenant(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })

	store := NewStore(t.TempDir())
	if err := store.WriteAuthConfig(AuthConfig{
		SchemaVersion: authSchemaVersion,
		Tokens: []TokenGrant{
			{Token: "secret-no-tenant-value", Subject: "alice", Projects: []string{"app"}, CanRead: true},
			{Token: "fine", Subject: "bob", Tenant: "acme", CanRead: true},
		},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.loadAuthConfig(); err != nil {
		t.Fatalf("load must not fail on an empty-tenant grant: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "empty tenant") || !strings.Contains(out, "alice") {
		t.Fatalf("expected an empty-tenant warning naming the subject, got %q", out)
	}
	if strings.Contains(out, "secret-no-tenant-value") {
		t.Fatalf("warning must not leak the token value: %q", out)
	}
	if strings.Contains(out, "subject=bob") {
		t.Fatalf("grant with a tenant must not be warned about: %q", out)
	}
}
