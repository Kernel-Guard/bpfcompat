package artifact

import (
	"archive/tar"
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

func fakeELF() []byte {
	return append(append([]byte{}, elfMagic...), []byte("\x02\x01\x01\x00 fake bpf object payload")...)
}

func writeGadgetLayout(t *testing.T, mediaType string, payload []byte) string {
	t.Helper()
	layer := static.NewLayer(payload, types.MediaType(mediaType))
	img, err := mutate.AppendLayers(empty.Image, layer)
	if err != nil {
		t.Fatalf("append layer: %v", err)
	}
	dir := t.TempDir()
	p, err := layout.Write(dir, empty.Index)
	if err != nil {
		t.Fatalf("write layout: %v", err)
	}
	if err := p.AppendImage(img); err != nil {
		t.Fatalf("append image: %v", err)
	}
	return dir
}

func TestOciArtifactName(t *testing.T) {
	cases := map[string]string{
		"ghcr.io/inspektor-gadget/gadget/trace_open:latest": "trace_open",
		"ghcr.io/org/gadget@sha256:abcd":                    "gadget",
		"trace_exec:v1.2.3":                                 "trace_exec",
		"/tmp/some/path/mygadget.tar.gz":                    "mygadget",
		"prog.bpf.o":                                        "prog",
		"localhost:5000/repo/thing:latest":                  "thing",
	}
	for in, want := range cases {
		if got := ociArtifactName(in); got != want {
			t.Errorf("ociArtifactName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestIsOCISource(t *testing.T) {
	// A plain ELF file on disk is not an OCI source.
	elfPath := filepath.Join(t.TempDir(), "prog.bpf.o")
	if err := os.WriteFile(elfPath, fakeELF(), 0o644); err != nil {
		t.Fatal(err)
	}
	if IsOCISource(elfPath) {
		t.Errorf("plain ELF file should not be an OCI source")
	}

	// An OCI layout directory is.
	layoutDir := writeGadgetLayout(t, gadgetEBPFMediaType, fakeELF())
	if !IsOCISource(layoutDir) {
		t.Errorf("OCI layout dir should be an OCI source")
	}

	// A registry reference (non-existent local path that parses) is.
	if !IsOCISource("ghcr.io/inspektor-gadget/gadget/trace_open:latest") {
		t.Errorf("registry reference should be an OCI source")
	}

	if IsOCISource("") {
		t.Errorf("empty ref should not be an OCI source")
	}
}

func TestExtractEBPFFromOCILayoutByMediaType(t *testing.T) {
	payload := fakeELF()
	layoutDir := writeGadgetLayout(t, gadgetEBPFMediaType, payload)

	out := t.TempDir()
	got, err := ExtractEBPFFromOCI(context.Background(), layoutDir, out)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	data, err := os.ReadFile(got)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, payload) {
		t.Fatalf("extracted payload mismatch: got %d bytes, want %d", len(data), len(payload))
	}
	info, err := os.Stat(got)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("expected extracted artifact mode 0600, got %o", info.Mode().Perm())
	}
}

func TestExtractEBPFFromOCILayoutByELFMagicFallback(t *testing.T) {
	// No gadget media type: selection must fall back to ELF-magic detection.
	payload := fakeELF()
	layoutDir := writeGadgetLayout(t, string(types.OCILayer), payload)

	out := t.TempDir()
	got, err := ExtractEBPFFromOCI(context.Background(), layoutDir, out)
	if err != nil {
		t.Fatalf("extract (magic fallback): %v", err)
	}
	data, err := os.ReadFile(got)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, payload) {
		t.Fatalf("extracted payload mismatch via magic fallback")
	}
}

func TestExtractEBPFFromOCINoELFLayer(t *testing.T) {
	layoutDir := writeGadgetLayout(t, string(types.OCILayer), []byte("not an elf at all"))
	if _, err := ExtractEBPFFromOCI(context.Background(), layoutDir, t.TempDir()); err == nil {
		t.Fatalf("expected error when no eBPF layer is present")
	}
}

func TestExtractLayerToFileRejectsExpandedOverflow(t *testing.T) {
	payload := append(fakeELF(), []byte("overflow")...)
	layer := static.NewLayer(payload, types.OCILayer)
	out := filepath.Join(t.TempDir(), "artifact.bpf.o")
	err := extractLayerToFile(layer, out, int64(len(fakeELF())))
	if err == nil || !strings.Contains(err.Error(), "exceeds limit") {
		t.Fatalf("expected expanded-size error, got %v", err)
	}
	if _, statErr := os.Stat(out); !os.IsNotExist(statErr) {
		t.Fatalf("partial artifact should be removed, stat error=%v", statErr)
	}
}

func TestExtractTarRejectsExpandedOverflow(t *testing.T) {
	archivePath := filepath.Join(t.TempDir(), "layout.tar")
	f, err := os.Create(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	tw := tar.NewWriter(f)
	payload := []byte("12345")
	header := &tar.Header{
		Name:     "blobs/payload",
		Mode:     0o600,
		Size:     int64(len(payload)),
		Typeflag: tar.TypeReg,
	}
	if err := tw.WriteHeader(header); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	err = extractTarWithLimits(archivePath, t.TempDir(), 4, 10)
	if err == nil || !strings.Contains(err.Error(), "expanded-size limit") {
		t.Fatalf("expected archive size error, got %v", err)
	}
}

func TestSafeJoinRejectsEscape(t *testing.T) {
	if _, err := safeJoin("/tmp/dest", "../../etc/passwd"); err == nil {
		t.Fatalf("expected zip-slip rejection")
	}
	if _, err := safeJoin("/tmp/dest", "blobs/sha256/abcd"); err != nil {
		t.Fatalf("unexpected error for safe path: %v", err)
	}
}

var _ v1.Image // keep v1 import even if helpers change
