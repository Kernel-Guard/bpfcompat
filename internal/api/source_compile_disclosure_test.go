package api

// Regression tests for A1-1: /api/validate source uploads are compiled with
// clang on the API host. Clang diagnostics quote the lines of every file they
// touch, so a source that #includes an arbitrary host file used to get that
// file's contents echoed back in the 400 error body. These tests pin that no
// API client (anonymous or authenticated) can read host file contents through
// compile diagnostics, and that anonymous source compilation is off unless the
// operator explicitly opts in.

import (
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

const (
	// Literal env names (not the package constants) so this file also
	// compiles against the pre-fix tree, where the opt-in did not exist.
	testEnvAllowAnonymousSourceCompile = "BPFCOMPAT_API_ALLOW_ANONYMOUS_SOURCE_COMPILE"
	testDisclosureWriteKey             = "source-compile-disclosure-key"
	testHostSecretToken                = "a1-host-secret-4f2c9d"
	testHostSecretLine                 = "BPFCOMPAT_API_KEY=" + testHostSecretToken
)

type sourceUploadMode int

const (
	sourceUploadAsText sourceUploadMode = iota
	sourceUploadAsFile
)

func writeHostSecretFile(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "server-secret.env")
	// Two lines so a diagnostic that quotes "the next line" still trips.
	content := testHostSecretLine + "\nsecond_line_" + testHostSecretToken + "\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func postValidateSource(t *testing.T, mode sourceUploadMode, source string, authenticated bool) *httptest.ResponseRecorder {
	t.Helper()
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	switch mode {
	case sourceUploadAsFile:
		fw, err := mw.CreateFormFile("source_file", "probe.bpf.c")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := fw.Write([]byte(source)); err != nil {
			t.Fatal(err)
		}
	default:
		if err := mw.WriteField("source_code", source); err != nil {
			t.Fatal(err)
		}
	}
	if err := mw.WriteField("profiles", "ubuntu-22.04"); err != nil {
		t.Fatal(err)
	}
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/validate/start", &body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	if authenticated {
		req.Header.Set(headerAPIKey, testDisclosureWriteKey)
	}

	s := &Server{cfg: Config{WorkDir: t.TempDir(), DefaultConcurrency: 1, DefaultTimeout: 2 * time.Minute}}
	rec := httptest.NewRecorder()
	s.handleValidateStart(rec, req)
	return rec
}

func decodeAPIError(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var payload struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode error body: %v body=%s", err, rec.Body.String())
	}
	return payload.Error
}

// uploadedSourceLocationOnly matches the only structured detail a compile
// failure may carry: line:column pairs inside the uploaded source.
var uploadedSourceLocationOnly = regexp.MustCompile(`^source compilation failed(?: at uploaded source line(?:s)? \d+:\d+(?:, \d+:\d+)*)?(?:\nhint: [^\n]+)?$`)

func TestSourceCompileDiagnosticsDoNotDiscloseHostFiles(t *testing.T) {
	if _, err := exec.LookPath("clang"); err != nil {
		t.Skip("clang not available")
	}
	t.Setenv(envAllowAnonymousValidate, "true")
	t.Setenv(testEnvAllowAnonymousSourceCompile, "true")
	t.Setenv(envAllowAnonymousWrite, "")
	t.Setenv(envWriteAPIKey, testDisclosureWriteKey)
	// Exercise the worst case: the existing path-redaction pass is off, so
	// nothing but the fix itself stands between clang output and the client.
	t.Setenv(envRedactRuntime, "false")
	// Worst case for diagnostics: bare-host clang (operator opt-out), so a
	// host file really is read and only the error filtering protects it.
	forceUnsandboxedSourceCompile(t)

	secretPath := writeHostSecretFile(t)

	cases := []struct {
		name   string
		mode   sourceUploadMode
		source string
	}{
		{name: "quoted absolute include", source: "#include \"" + secretPath + "\"\n"},
		{name: "angle absolute include", source: "#include <" + secretPath + ">\n"},
		{name: "macro computed include", source: "#define P \"" + secretPath + "\"\n#include P\n"},
		{name: "macro pasted angle include", source: "#define Q <" + secretPath + ">\n#include Q\n"},
		{name: "has_include guarded include", source: "#if __has_include(\"" + secretPath + "\")\n#include \"" + secretPath + "\"\n#endif\n"},
		{name: "include after valid code", source: "int ok_before;\n\n#include \"" + secretPath + "\"\nint ok_after;\n"},
		{name: "source_file upload include", mode: sourceUploadAsFile, source: "#include \"" + secretPath + "\"\n"},
	}

	for _, tc := range cases {
		for _, authenticated := range []bool{false, true} {
			client := "anonymous"
			if authenticated {
				client = "authenticated"
			}
			t.Run(tc.name+"/"+client, func(t *testing.T) {
				rec := postValidateSource(t, tc.mode, tc.source, authenticated)
				body := rec.Body.String()
				if rec.Code != http.StatusBadRequest {
					t.Fatalf("expected 400 compile failure, got %d body=%s", rec.Code, body)
				}
				for _, forbidden := range []string{
					testHostSecretToken,
					"BPFCOMPAT_API_KEY",
					"second_line_",
					secretPath,
					filepath.Base(secretPath),
					filepath.Dir(secretPath),
				} {
					if strings.Contains(body, forbidden) {
						t.Fatalf("compile error disclosed host data %q to %s client: %s", forbidden, client, body)
					}
				}
				msg := decodeAPIError(t, rec)
				if !uploadedSourceLocationOnly.MatchString(msg) {
					t.Fatalf("compile error must be generic plus uploaded-source locations only, got %q", msg)
				}
			})
		}
	}
}

func TestSourceCompileFailureReportsUploadedSourceLocations(t *testing.T) {
	if _, err := exec.LookPath("clang"); err != nil {
		t.Skip("clang not available")
	}
	t.Setenv(envAllowAnonymousValidate, "")
	t.Setenv(envAllowAnonymousWrite, "")
	t.Setenv(envWriteAPIKey, testDisclosureWriteKey)
	forceUnsandboxedSourceCompile(t)

	rec := postValidateSource(t, sourceUploadAsText, "int ok;\n\nthis_is_not_c secret_identifier_xyz;\n", true)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d body=%s", rec.Code, rec.Body.String())
	}
	msg := decodeAPIError(t, rec)
	if !strings.HasPrefix(msg, "source compilation failed at uploaded source line 3:") {
		t.Fatalf("expected uploaded-source location for line 3, got %q", msg)
	}
	if strings.Contains(msg, "secret_identifier_xyz") || strings.Contains(msg, "this_is_not_c") {
		t.Fatalf("compile error must not echo source text, got %q", msg)
	}
}

func TestAnonymousSourceCompileDisabledByDefault(t *testing.T) {
	t.Setenv(envAllowAnonymousValidate, "true")
	t.Setenv(testEnvAllowAnonymousSourceCompile, "")
	t.Setenv(envAllowAnonymousWrite, "")
	t.Setenv(envWriteAPIKey, testDisclosureWriteKey)

	secretPath := writeHostSecretFile(t)
	for _, mode := range []sourceUploadMode{sourceUploadAsText, sourceUploadAsFile} {
		rec := postValidateSource(t, mode, "#include \""+secretPath+"\"\n", false)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("mode %d: expected 403 for anonymous source compile, got %d body=%s", mode, rec.Code, rec.Body.String())
		}
		msg := decodeAPIError(t, rec)
		if !strings.Contains(msg, "source compilation") || !strings.Contains(msg, ".bpf.o") {
			t.Fatalf("mode %d: expected clear policy error pointing at prebuilt artifacts, got %q", mode, msg)
		}
		if strings.Contains(rec.Body.String(), testHostSecretToken) {
			t.Fatalf("mode %d: leaked host data: %s", mode, rec.Body.String())
		}
	}
}

func TestAnonymousSourceCompileDisabledEvenWithAnonymousWrite(t *testing.T) {
	t.Setenv(envAllowAnonymousWrite, "true")
	t.Setenv(testEnvAllowAnonymousSourceCompile, "")

	rec := postValidateSource(t, sourceUploadAsText, "int x;\n", false)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for anonymous source compile under anonymous-write, got %d body=%s", rec.Code, rec.Body.String())
	}
}

func TestAnonymousArtifactUploadUnaffectedBySourceCompilePolicy(t *testing.T) {
	t.Setenv(envAllowAnonymousValidate, "true")
	t.Setenv(testEnvAllowAnonymousSourceCompile, "")

	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	fw, err := mw.CreateFormFile("artifact_file", "probe.bpf.o")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = fw.Write([]byte("\x7fELF-not-really"))
	// source_code alongside an artifact is ignored by extractArtifact, so it
	// must not trigger the source-compile policy either.
	_ = mw.WriteField("source_code", "int x;\n")
	// No profiles/matrix: the request fails deterministically *after*
	// artifact extraction, without starting a VM-backed job.
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/validate/start", &body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	s := &Server{cfg: Config{WorkDir: t.TempDir(), DefaultConcurrency: 1, DefaultTimeout: 2 * time.Minute}}
	rec := httptest.NewRecorder()
	s.handleValidateStart(rec, req)

	if rec.Code != http.StatusBadRequest || !strings.Contains(decodeAPIError(t, rec), "no profiles selected") {
		t.Fatalf("expected anonymous artifact upload to pass the source policy and fail on matrix resolution, got %d body=%s", rec.Code, rec.Body.String())
	}
}
