package runtime

import (
	"crypto/sha256"
	"encoding/hex"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/erenari/bpfcompat/internal/artifact"
	"github.com/erenari/bpfcompat/internal/registry"
)

func TestFetchArtifactLocalPath(t *testing.T) {
	srcDir := t.TempDir()
	srcPath := filepath.Join(srcDir, "demo-local.bpf.o")
	content := []byte{0x7f, 'E', 'L', 'F', 0x01, 0x02}
	if err := os.WriteFile(srcPath, content, 0o644); err != nil {
		t.Fatalf("write source artifact: %v", err)
	}
	meta, err := artifact.Inspect(srcPath)
	if err != nil {
		t.Fatalf("inspect source artifact: %v", err)
	}

	outDir := filepath.Join(t.TempDir(), "out")
	record := registry.ArtifactVersionRecord{
		ArtifactName:    "demo",
		ArtifactVersion: "v1",
		ArtifactPath:    srcPath,
		ArtifactSHA256:  meta.SHA256,
	}

	got, err := FetchArtifact(record, outDir)
	if err != nil {
		t.Fatalf("fetch local artifact: %v", err)
	}
	if got.SourcePath != srcPath {
		t.Fatalf("unexpected source path: got=%q want=%q", got.SourcePath, srcPath)
	}
	if _, err := os.Stat(got.OutputPath); err != nil {
		t.Fatalf("fetched output path should exist: %v", err)
	}
	if got.ActualSHA256 != meta.SHA256 {
		t.Fatalf("unexpected fetched hash: got=%q want=%q", got.ActualSHA256, meta.SHA256)
	}
}

func TestFetchArtifactRemoteURI(t *testing.T) {
	// httptest.NewServer listens on 127.0.0.1, which the SSRF guard
	// (validateOutboundHost) blocks by default. Opt in for these tests.
	t.Setenv(fetchAllowInternalEnv, "true")
	content := []byte{0x7f, 'E', 'L', 'F', 0x03, 0x04, 0x05}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/artifacts/demo-v2.bpf.o" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(content)
	}))
	defer server.Close()

	hash := sha256.Sum256(content)
	wantHash := hex.EncodeToString(hash[:])
	outDir := filepath.Join(t.TempDir(), "out")
	record := registry.ArtifactVersionRecord{
		ArtifactName:    "demo",
		ArtifactVersion: "v2",
		ArtifactPath:    "/tmp/does-not-exist.bpf.o",
		ArtifactURI:     server.URL + "/artifacts/demo-v2.bpf.o",
		ArtifactSHA256:  wantHash,
	}

	got, err := FetchArtifact(record, outDir)
	if err != nil {
		t.Fatalf("fetch remote artifact: %v", err)
	}
	if got.SourcePath != record.ArtifactURI {
		t.Fatalf("unexpected source URI: got=%q want=%q", got.SourcePath, record.ArtifactURI)
	}
	if _, err := os.Stat(got.OutputPath); err != nil {
		t.Fatalf("fetched output path should exist: %v", err)
	}
	if got.ActualSHA256 != wantHash {
		t.Fatalf("unexpected fetched hash: got=%q want=%q", got.ActualSHA256, wantHash)
	}
}

func TestFetchArtifactRejectsFileURIByDefault(t *testing.T) {
	t.Setenv(fetchAllowFileURIEnv, "")

	srcDir := t.TempDir()
	srcPath := filepath.Join(srcDir, "demo-file-uri.bpf.o")
	content := []byte{0x7f, 'E', 'L', 'F', 0x09}
	if err := os.WriteFile(srcPath, content, 0o644); err != nil {
		t.Fatalf("write source artifact: %v", err)
	}
	hash := sha256.Sum256(content)
	record := registry.ArtifactVersionRecord{
		ArtifactName:    "demo",
		ArtifactVersion: "file-default",
		ArtifactURI:     "file://" + srcPath,
		ArtifactSHA256:  hex.EncodeToString(hash[:]),
	}

	_, err := FetchArtifact(record, filepath.Join(t.TempDir(), "out"))
	if err == nil {
		t.Fatalf("expected file URI to be disabled by default")
	}
	if !strings.Contains(err.Error(), fetchAllowFileURIEnv) {
		t.Fatalf("expected file URI opt-in hint, got: %v", err)
	}
}

func TestFetchArtifactAllowsFileURIWhenEnabled(t *testing.T) {
	t.Setenv(fetchAllowFileURIEnv, "true")

	srcDir := t.TempDir()
	srcPath := filepath.Join(srcDir, "demo-file-uri-enabled.bpf.o")
	content := []byte{0x7f, 'E', 'L', 'F', 0x0a, 0x0b}
	if err := os.WriteFile(srcPath, content, 0o644); err != nil {
		t.Fatalf("write source artifact: %v", err)
	}
	hash := sha256.Sum256(content)
	wantHash := hex.EncodeToString(hash[:])
	record := registry.ArtifactVersionRecord{
		ArtifactName:    "demo",
		ArtifactVersion: "file-enabled",
		ArtifactURI:     "file://" + srcPath,
		ArtifactSHA256:  wantHash,
	}

	got, err := FetchArtifact(record, filepath.Join(t.TempDir(), "out"))
	if err != nil {
		t.Fatalf("fetch file URI artifact: %v", err)
	}
	if got.SourcePath != record.ArtifactURI {
		t.Fatalf("unexpected source URI: got=%q want=%q", got.SourcePath, record.ArtifactURI)
	}
	if got.ActualSHA256 != wantHash {
		t.Fatalf("unexpected fetched hash: got=%q want=%q", got.ActualSHA256, wantHash)
	}
}

func TestFetchArtifactRemoteHashMismatch(t *testing.T) {
	t.Setenv(fetchAllowInternalEnv, "true")
	content := []byte{0x7f, 'E', 'L', 'F', 0xaa}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(content)
	}))
	defer server.Close()

	record := registry.ArtifactVersionRecord{
		ArtifactName:    "demo",
		ArtifactVersion: "v3",
		ArtifactURI:     server.URL + "/artifact.bpf.o",
		ArtifactSHA256:  strings.Repeat("0", 64),
	}

	_, err := FetchArtifact(record, filepath.Join(t.TempDir(), "out"))
	if err == nil {
		t.Fatalf("expected hash mismatch error")
	}
	if !strings.Contains(err.Error(), "hash mismatch") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestFetchArtifactRejectsUnsupportedURI(t *testing.T) {
	record := registry.ArtifactVersionRecord{
		ArtifactName:    "demo",
		ArtifactVersion: "v4",
		ArtifactURI:     "s3://bucket/key/demo.bpf.o",
		ArtifactSHA256:  strings.Repeat("f", 64),
	}

	_, err := FetchArtifact(record, filepath.Join(t.TempDir(), "out"))
	if err == nil {
		t.Fatalf("expected unsupported URI error")
	}
	if !strings.Contains(err.Error(), "artifact_uri must use one of") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestFetchArtifactEnforcesSizeLimit(t *testing.T) {
	t.Setenv(fetchMaxBytesEnv, "8")
	t.Setenv(fetchAllowInternalEnv, "true")
	content := []byte("0123456789abcdef")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(content)
	}))
	defer server.Close()

	record := registry.ArtifactVersionRecord{
		ArtifactName:    "demo",
		ArtifactVersion: "v5",
		ArtifactURI:     server.URL + "/artifact.bpf.o",
	}

	_, err := FetchArtifact(record, filepath.Join(t.TempDir(), "out"))
	if err == nil {
		t.Fatalf("expected max bytes limit error")
	}
	if !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestFetchArtifactBlocksLoopbackByDefault regresses H-3. Without the SSRF
// guard a write-authorized caller could point artifact_uri at internal
// endpoints (cloud metadata, localhost) and have the server proxy outbound
// requests to them. Default policy now rejects loopback / private targets.
func TestFetchArtifactBlocksLoopbackByDefault(t *testing.T) {
	// Make sure no opt-in is set.
	t.Setenv(fetchAllowInternalEnv, "")

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte{0x7f, 'E', 'L', 'F'})
	}))
	defer server.Close()

	record := registry.ArtifactVersionRecord{
		ArtifactName:    "demo",
		ArtifactVersion: "v6",
		ArtifactURI:     server.URL + "/artifact.bpf.o",
		ArtifactSHA256:  strings.Repeat("0", 64),
	}

	_, err := FetchArtifact(record, filepath.Join(t.TempDir(), "out"))
	if err == nil {
		t.Fatalf("expected SSRF guard to reject loopback URL")
	}
	if !strings.Contains(err.Error(), "internal address") {
		t.Fatalf("expected SSRF rejection message, got: %v", err)
	}
}

// TestValidateOutboundHostInternalRanges covers the IP classifier directly so
// future regressions on RFC1918 / link-local / metadata IP detection get
// caught before they touch the HTTP path.
func TestValidateOutboundHostInternalRanges(t *testing.T) {
	cases := []struct {
		ip     string
		expect bool
	}{
		{"127.0.0.1", true},
		{"10.0.0.1", true},
		{"172.16.0.1", true},
		{"192.168.1.1", true},
		{"169.254.169.254", true}, // cloud metadata
		{"100.64.0.1", true},      // RFC 6598 CGNAT
		{"::1", true},
		{"fe80::1", true},
		{"8.8.8.8", false},
		{"1.1.1.1", false},
	}
	for _, tc := range cases {
		t.Run(tc.ip, func(t *testing.T) {
			got := isInternalIP(net.ParseIP(tc.ip))
			if got != tc.expect {
				t.Fatalf("isInternalIP(%s) = %v, want %v", tc.ip, got, tc.expect)
			}
		})
	}
}
