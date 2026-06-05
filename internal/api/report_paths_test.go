package api

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const sampleReportJSON = `{
  "schema_version": "v0.1",
  "run": {"id": "test", "started_at": "2026-05-17T00:00:00Z"},
  "artifact": {"path": "x.bpf.o", "basename": "x.bpf.o", "sha256": "0"},
  "matrix": {"path": "m.yaml", "name": "m", "profiles": ["p"]},
  "targets": [{"profile_id": "p", "required": true, "status": "pass"}],
  "summary": {"status": "pass"}
}
`

func writeReportFixture(t *testing.T, dir, name string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, []byte(sampleReportJSON), 0o644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	return path
}

func chdirTo(t *testing.T, dir string) {
	t.Helper()
	prev, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	t.Cleanup(func() {
		_ = os.Chdir(prev)
	})
}

func TestResolveServerLocalReportPathAcceptsWorkdirAndReports(t *testing.T) {
	root := t.TempDir()
	chdirTo(t, root)
	workDir := filepath.Join(root, ".bpfcompat")

	workdirReport := writeReportFixture(t, filepath.Join(workDir, "runs", "abc"), "report.json")
	reportsDirReport := writeReportFixture(t, filepath.Join(root, "reports"), "ui.json")

	for _, c := range []struct {
		name string
		in   string
	}{
		{"workdir absolute", workdirReport},
		{"reports absolute", reportsDirReport},
		{"reports relative", filepath.Join("reports", "ui.json")},
	} {
		t.Run(c.name, func(t *testing.T) {
			got, err := resolveServerLocalReportPath(workDir, c.in)
			if err != nil {
				t.Fatalf("expected accept, got error: %v", err)
			}
			if got == "" {
				t.Fatalf("resolved path is empty")
			}
		})
	}
}

func TestResolveServerLocalReportPathRejectsOutsideRoots(t *testing.T) {
	root := t.TempDir()
	chdirTo(t, root)
	workDir := filepath.Join(root, ".bpfcompat")
	if err := os.MkdirAll(workDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	outside := writeReportFixture(t, t.TempDir(), "elsewhere.json")
	for _, c := range []struct {
		name string
		in   string
	}{
		{"absolute outside", outside},
		{"etc passwd absolute", "/etc/passwd"},
		{"parent escape relative", filepath.Join("..", "secret.json")},
		{"empty", ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			if _, err := resolveServerLocalReportPath(workDir, c.in); err == nil {
				t.Fatalf("expected rejection for %q", c.in)
			}
		})
	}
}

func TestResolveServerLocalReportPathRejectsSymlinkEscape(t *testing.T) {
	root := t.TempDir()
	chdirTo(t, root)
	workDir := filepath.Join(root, ".bpfcompat")
	if err := os.MkdirAll(workDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	target := writeReportFixture(t, t.TempDir(), "elsewhere.json")
	linkPath := filepath.Join(workDir, "escape.json")
	if err := os.Symlink(target, linkPath); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	if _, err := resolveServerLocalReportPath(workDir, linkPath); err == nil {
		t.Fatalf("expected rejection for symlink escape to %q", target)
	}
}

func TestResolveServerLocalReportPathRejectsDirectory(t *testing.T) {
	root := t.TempDir()
	chdirTo(t, root)
	workDir := filepath.Join(root, ".bpfcompat")
	if err := os.MkdirAll(workDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if _, err := resolveServerLocalReportPath(workDir, workDir); err == nil {
		t.Fatalf("expected rejection for directory")
	}
}

func TestHandleCompareRejectsAbsolutePathOutsideRoots(t *testing.T) {
	t.Setenv(envWriteAPIKey, "demo-write-key")
	root := t.TempDir()
	chdirTo(t, root)
	workDir := filepath.Join(root, ".bpfcompat")
	if err := os.MkdirAll(workDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	s := &Server{cfg: Config{WorkDir: workDir}}

	body := `{"base_report":"/etc/passwd","head_report":"/etc/passwd"}`
	req := httptest.NewRequest(http.MethodPost, "/api/compare", strings.NewReader(body))
	req.Header.Set(headerAPIKey, "demo-write-key")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	s.handleCompare(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for outside-roots path, got %d body=%s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "/etc/passwd") {
		t.Fatalf("response leaked the requested path: %s", rec.Body.String())
	}
}

func TestHandleCompareAcceptsServerLocalReports(t *testing.T) {
	t.Setenv(envWriteAPIKey, "demo-write-key")
	root := t.TempDir()
	chdirTo(t, root)
	workDir := filepath.Join(root, ".bpfcompat")
	if err := os.MkdirAll(workDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	basePath := writeReportFixture(t, filepath.Join(root, "reports"), "base.json")
	headPath := writeReportFixture(t, filepath.Join(root, "reports"), "head.json")

	s := &Server{cfg: Config{WorkDir: workDir}}

	body := `{"base_report":"` + basePath + `","head_report":"` + headPath + `"}`
	req := httptest.NewRequest(http.MethodPost, "/api/compare", strings.NewReader(body))
	req.Header.Set(headerAPIKey, "demo-write-key")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	s.handleCompare(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for server-local reports, got %d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "compat_diff.v0.1") {
		t.Fatalf("expected compat_diff payload, got %s", rec.Body.String())
	}
}
