package api

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// legacyRedactPattern and legacyRedactErrorMessage are a verbatim copy of the
// redaction shipped before this change (bc589b3). They are the reference the
// differential test holds the new redactor to.
var legacyRedactPattern = regexp.MustCompile(`(/[A-Za-z0-9._-]+)+`)

func legacyRedactErrorMessage(message string) string {
	return legacyRedactPattern.ReplaceAllStringFunc(message, func(match string) string {
		base := filepath.Base(match)
		if base == "" || base == "." || base == "/" {
			return "[redacted]"
		}
		return "[redacted]/" + base
	})
}

// legacyRemovedBytes returns the byte offsets the legacy redactor removed
// (every byte of a match except the kept basename).
func legacyRemovedBytes(message string) map[int]bool {
	removed := map[int]bool{}
	for _, m := range legacyRedactPattern.FindAllStringIndex(message, -1) {
		match := message[m[0]:m[1]]
		base := filepath.Base(match)
		keep := len(base)
		if base == "" || base == "." || base == "/" {
			keep = 0
		}
		for i := m[0]; i < m[1]-keep; i++ {
			removed[i] = true
		}
	}
	return removed
}

// newRemovedBytes returns the byte offsets the new redactor removes.
func newRemovedBytes(message string) map[int]bool {
	removed := map[int]bool{}
	for _, r := range errorMessageRedactionRanges(message) {
		text := message[r.start:r.end]
		base := filepath.Base(text)
		keepStart, keepEnd := r.end, r.end
		if base != "" && base != "." && base != "/" {
			keepEnd = r.start + len(strings.TrimRight(text, "/"))
			keepStart = keepEnd - len(base)
		}
		for i := r.start; i < r.end; i++ {
			if i < keepStart || i >= keepEnd {
				removed[i] = true
			}
		}
	}
	return removed
}

// referenceExceptionPattern is the reviewer's definition of the only text the
// new redactor may keep although the legacy one removed it: a pure numeric
// ratio \b\d+/\d+\b not adjacent to a further "/", or the literal "and/or".
var referenceExceptionPattern = regexp.MustCompile(`\b\d+/\d+\b|\band/or\b`)

func referenceExceptionBytes(message string) map[int]bool {
	out := map[int]bool{}
	for _, m := range referenceExceptionPattern.FindAllStringIndex(message, -1) {
		if m[0] > 0 && message[m[0]-1] == '/' {
			continue
		}
		if m[1] < len(message) && message[m[1]] == '/' {
			continue
		}
		for i := m[0]; i < m[1]; i++ {
			out[i] = true
		}
	}
	return out
}

var redactionDifferentialCorpus = []string{
	// RAPI2 review corpus (40 messages).
	"open /srv/x/y: permission denied",
	"fork/exec /usr/bin/clang: no such file or directory",
	`open "/tmp/a/b": denied`,
	"workdir=/srv/work/tenants/acme",
	"read config:/etc/bpfcompat/cfg.yaml",
	"bad (/opt/a/b)",
	"bad '/opt/a/b'",
	`C:\Users\op\secret.o`,
	"C:/Users/op/secret.o",
	"open /srv/my dir/secret/tenant/x.o: denied",
	"file:///etc/bpfcompat/key.pem",
	"open ~/work/tenants/acme/x.o",
	"open ./data/tenants/acme/x.o",
	"open .bpfcompat/cloud-registry/tenants/acme/projects/p1/artifacts/a/1.0/object.o: no such file or directory",
	"read artifact history: open .bpfcompat/registry/artifacts/victim/index.json: permission denied",
	"stat bpfcompat-work/runs/abc/out.json: denied",
	"failed at end /var/lib/bpfcompat/x",
	"rename /a/b/c.tmp /a/b/c",
	"/srv/a,b/c/d/e.o",
	"/srv/a;b/c/d/e.o",
	"/srv/data(1)/tenants/acme/x.o",
	"/srv/{x}/tenants/acme/x.o",
	"/srv/a|b/tenants/acme/x.o",
	"/srv/[x]/tenants/acme/x.o",
	"/srv/a<b>/tenants/acme/x.o",
	"/srv/it's/tenants/acme/x.o",
	"lstat /srv/x/y\n/srv/z/w",
	"path=-/srv/a/b",
	"x_/srv/a/b",
	"v1.2/srv/a/b",
	"exit status 1: /usr/local/bin/validator: line 3",
	"http://host:8080/internal/path/x",
	"queue full (active=1/1 queued=0/20)",
	"/home/jürgen/work/x.o",
	"open /srv//b/x.o",
	"\t/srv/a/b",
	"error:/srv/a/b",
	"ab/srv/secret/x",
	"open relative/dir/x.o",
	"tenants/acme/projects/p1",
	// TestRedactErrorMessageTable inputs (15 messages).
	"runtime fetch failed: open /home/op/.bpfcompat/runs/abc/artifact: no such file",
	"/srv/bpfcompat/work/registry/index.json: permission denied",
	"stat /tmp: permission denied",
	`open "/var/lib/bpfcompat/secret.key": denied`,
	"bad config (workdir=/opt/bpfcompat/work)",
	"rename /a/b/c.tmp /a/b/c: exists",
	"paths=/a/x,/b/y",
	"fetch file:///etc/bpfcompat/key.pem failed",
	"open /home/jürgen/work/x.o: denied",
	"open /srv//bpfcompat/x.o",
	"validate queue is full (active=1/1 queued=0/20); try again later",
	"validate queue is full (active=1/1, queued=0/20)",
	"tenant and/or project missing",
	"rate limit 10/s exceeded, profiles 3/5 passed",
	"artifact_name is required",
	// Relative-workdir messages (the server default workdir is ".bpfcompat").
	"read runtime decision history: open .bpfcompat/tenants-acme-secret/runtime_decisions.jsonl: permission denied",
	"read runtime decision history: open .bpfcompat/runtime_decisions.jsonl: permission denied",
	"mkdir .bpfcompat/artifacts/runtime-selected/acme: permission denied",
	"open ./.bpfcompat/cloud-registry/tenants/acme/audit.jsonl: denied",
	"stat ../shared/.bpfcompat/x.json: denied",
	"open bpfcompat-work/tenants/acme/projects/p1/index.json: no such file",
	// Edge cases around the two exceptions.
	"ratio 12/34/56 is a path-like run",
	"x1/2 and 3/4x and v1.2/3",
	"and/or/secret and band/order",
	"",
}

// TestRedactErrorMessageIsSupersetOfLegacy: every byte the legacy redactor
// removed is removed by the new one too, except bytes of a pure numeric ratio
// or the literal "and/or".
func TestRedactErrorMessageIsSupersetOfLegacy(t *testing.T) {
	t.Setenv(envRedactRuntime, "true")
	regressions, excused, stricter := 0, 0, 0
	for _, msg := range redactionDifferentialCorpus {
		oldRemoved := legacyRemovedBytes(msg)
		newRemoved := newRemovedBytes(msg)
		exceptions := referenceExceptionBytes(msg)
		for i := range oldRemoved {
			if newRemoved[i] {
				continue
			}
			if exceptions[i] {
				excused++
				continue
			}
			regressions++
			t.Errorf("legacy redacted byte %d (%q) of %q but the new redactor keeps it\n legacy: %q\n    new: %q",
				i, msg[i], msg, legacyRedactErrorMessage(msg), redactErrorMessage(msg))
		}
		for i := range newRemoved {
			if !oldRemoved[i] {
				stricter++
			}
		}
		if got, want := redactErrorMessage(msg), redactPathRanges(msg, errorMessageRedactionRanges(msg)); got != want {
			t.Fatalf("redactErrorMessage(%q) = %q, ranges give %q", msg, got, want)
		}
	}
	t.Logf("corpus=%d messages; legacy-redacted bytes kept by new: %d outside exceptions, %d inside the ratio/and-or exceptions; bytes redacted only by new: %d",
		len(redactionDifferentialCorpus), regressions, excused, stricter)
	if regressions != 0 {
		t.Fatalf("%d legacy-redacted bytes are no longer redacted", regressions)
	}

	for _, msg := range []string{
		"active=1/1 queued=0/20",
		"validate queue is full (active=1/1 queued=0/20); try again later",
		"tenant and/or project missing",
	} {
		if got := redactErrorMessage(msg); got != msg {
			t.Fatalf("redactErrorMessage(%q) = %q, want unchanged", msg, got)
		}
	}
}

// TestRuntimeDecisionsRelativeWorkdirErrorRedacted: the default server
// workdir is relative (".bpfcompat"). A path-bearing error from the decisions
// endpoint must not reveal any of its path segments.
func TestRuntimeDecisionsRelativeWorkdirErrorRedacted(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can read a 0000 file; the error path is not reached")
	}
	t.Setenv(envRedactRuntime, "true")
	t.Setenv(envAllowAnonymousRead, "true")
	t.Setenv(envWriteAPIKey, "")
	t.Chdir(t.TempDir())
	workDir := filepath.Join(".bpfcompat", "tenants-acme-secret")
	registryDir := filepath.Join(workDir, "registry")
	if err := os.MkdirAll(registryDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(registryDir, "runtime_decisions.jsonl"), []byte("{}\n"), 0o000); err != nil {
		t.Fatal(err)
	}
	s := &Server{cfg: Config{WorkDir: workDir}}
	rec := httptest.NewRecorder()
	s.handleRuntimeDecisions(rec, httptest.NewRequest(http.MethodGet, "/api/runtime/decisions", http.NoBody))
	body := rec.Body.String()
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected the unreadable decision log to fail with 500, got %d body=%s", rec.Code, body)
	}
	if !strings.Contains(body, "[redacted]/runtime_decisions.jsonl") {
		t.Fatalf("expected a redacted basename hint, body=%s", body)
	}
	for _, segment := range []string{".bpfcompat", "tenants-acme-secret", "acme", "secret", "registry/"} {
		if strings.Contains(body, segment) {
			t.Fatalf("decisions error leaked workdir segment %q: %s", segment, body)
		}
	}
}
