package api

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolveServerLocalManifestPathAcceptsWorkdirLocal(t *testing.T) {
	root := t.TempDir()
	chdirTo(t, root)
	workDir := filepath.Join(root, ".bpfcompat")
	manifest := writeReportFixture(t,
		filepath.Join(workDir, "cloud-registry", "acme", "demo", "artifacts", "a", "v1"),
		"manifest.yaml",
	)

	got, err := resolveServerLocalManifestPath(workDir, manifest)
	if err != nil {
		t.Fatalf("expected accept of workdir-local manifest: %v", err)
	}
	if got == "" {
		t.Fatalf("resolved manifest path is empty")
	}
}

func TestResolveServerLocalManifestPathRejectsOutsideWorkdir(t *testing.T) {
	root := t.TempDir()
	chdirTo(t, root)
	workDir := filepath.Join(root, ".bpfcompat")
	if err := os.MkdirAll(workDir, 0o755); err != nil {
		t.Fatalf("mkdir workdir: %v", err)
	}
	outside := writeReportFixture(t, t.TempDir(), "naughty.yaml")

	for _, c := range []struct {
		name string
		in   string
	}{
		{"absolute outside", outside},
		{"etc passwd", "/etc/passwd"},
		{"sibling reports dir", filepath.Join(root, "reports", "x.yaml")},
		{"empty", ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			if _, err := resolveServerLocalManifestPath(workDir, c.in); err == nil {
				t.Fatalf("expected rejection for %q", c.in)
			}
		})
	}
}

func TestResolveServerLocalManifestPathRejectsSymlinkEscape(t *testing.T) {
	root := t.TempDir()
	chdirTo(t, root)
	workDir := filepath.Join(root, ".bpfcompat")
	if err := os.MkdirAll(workDir, 0o755); err != nil {
		t.Fatalf("mkdir workdir: %v", err)
	}
	target := writeReportFixture(t, t.TempDir(), "secret.yaml")
	link := filepath.Join(workDir, "smuggled.yaml")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	if _, err := resolveServerLocalManifestPath(workDir, link); err == nil {
		t.Fatalf("expected rejection for symlink escape from workdir to %q", target)
	}
}
