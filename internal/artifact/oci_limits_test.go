package artifact

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}

// writeZeroGzipTar writes a gzip'd tar of `entries` zero-filled files.
func writeZeroGzipTar(t *testing.T, path string, entries int, entrySize int64) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gz, err := gzip.NewWriterLevel(f, gzip.BestCompression)
	if err != nil {
		t.Fatal(err)
	}
	tw := tar.NewWriter(gz)
	for i := 0; i < entries; i++ {
		hdr := &tar.Header{Name: "blobs/z" + string(rune('a'+i%26)) + string(rune('a'+i/26)), Mode: 0o600, Size: entrySize, Typeflag: tar.TypeReg}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if _, err := io.CopyN(tw, zeroReader{}, entrySize); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
}

// writeHeaderOnlyGzipTar writes a gzip'd tar whose single entry claims `size`
// bytes but carries no data: it exercises the up-front header check without
// allocating gigabytes in the test.
func writeHeaderOnlyGzipTar(t *testing.T, path string, size int64) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{Name: "blobs/huge", Mode: 0o600, Size: size, Typeflag: tar.TypeReg}); err != nil {
		t.Fatal(err)
	}
	_ = tw.Flush() // reports the missing data; the header is already written
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
}

// tarDir writes dir as a (optionally gzip'd) tar archive at path.
func tarDir(t *testing.T, dir, path string, compress bool) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var w io.Writer = f
	var gz *gzip.Writer
	if compress {
		gz = gzip.NewWriter(f)
		w = gz
	}
	tw := tar.NewWriter(w)
	err = filepath.Walk(dir, func(p string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(dir, p)
		if err != nil || rel == "." {
			return err
		}
		hdr, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		hdr.Name = filepath.ToSlash(rel)
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if info.Mode().IsRegular() {
			src, err := os.Open(p)
			if err != nil {
				return err
			}
			defer src.Close()
			if _, err := io.Copy(tw, src); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if gz != nil {
		if err := gz.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

func treeBytes(root string) int64 {
	var total int64
	_ = filepath.Walk(root, func(_ string, info os.FileInfo, err error) error {
		if err == nil && info.Mode().IsRegular() {
			total += info.Size()
		}
		return nil
	})
	return total
}

// TestDefaultOCILimitsAreTheCLICeilings pins the CLI behaviour: the zero
// value and ExtractEBPFFromOCI keep using the historical 8 GiB archive and
// 512 MiB eBPF-layer ceilings. Only the API passes tighter limits.
func TestDefaultOCILimitsAreTheCLICeilings(t *testing.T) {
	want := OCILimits{MaxArchiveExpandedBytes: 8 << 30, MaxArtifactBytes: 512 << 20}
	if got := DefaultOCILimits(); got != want {
		t.Fatalf("DefaultOCILimits() = %+v, want %+v", got, want)
	}
	if got := (OCILimits{}).normalized(); got != want {
		t.Fatalf("zero OCILimits normalize to %+v, want %+v", got, want)
	}
	if got := (OCILimits{MaxArchiveExpandedBytes: -1, MaxArtifactBytes: -1}).normalized(); got != want {
		t.Fatalf("negative OCILimits normalize to %+v, want %+v", got, want)
	}
	if got := (OCILimits{MaxArchiveExpandedBytes: 1 << 20}).normalized(); got.MaxArchiveExpandedBytes != 1<<20 || got.MaxArtifactBytes != 512<<20 {
		t.Fatalf("partial OCILimits normalized to %+v", got)
	}
}

// TestExtractEBPFFromOCICLIPathKeeps8GiBCeiling proves byte-identical CLI
// behaviour through the public entry point: a 9 GiB entry is rejected with
// the unchanged message naming 8589934592 bytes, while a 7 GiB entry is NOT
// rejected by the limit (it fails later on the truncated body instead).
func TestExtractEBPFFromOCICLIPathKeeps8GiBCeiling(t *testing.T) {
	dir := t.TempDir()
	over := filepath.Join(dir, "over.tar.gz")
	writeHeaderOnlyGzipTar(t, over, 9<<30)
	_, _, err := ExtractEBPFFromOCI(context.Background(), over, t.TempDir())
	if err == nil || !strings.Contains(err.Error(), "OCI archive exceeds expanded-size limit of 8589934592 bytes") {
		t.Fatalf("CLI path: expected unchanged 8 GiB limit error, got %v", err)
	}
	if !errors.Is(err, ErrOCILimitExceeded) {
		t.Fatalf("limit error should match ErrOCILimitExceeded: %v", err)
	}

	under := filepath.Join(dir, "under.tar.gz")
	writeHeaderOnlyGzipTar(t, under, 7<<30)
	_, _, err = ExtractEBPFFromOCI(context.Background(), under, t.TempDir())
	if err == nil {
		t.Fatalf("expected the truncated archive to fail")
	}
	if errors.Is(err, ErrOCILimitExceeded) || strings.Contains(err.Error(), "expanded-size limit") {
		t.Fatalf("CLI path must not cap a 7 GiB entry: %v", err)
	}
}

// TestExtractTarWithLimitsBoundsBytesWritten streams many small entries past
// the cap: extraction must stop before writing more than the cap.
func TestExtractTarWithLimitsBoundsBytesWritten(t *testing.T) {
	dir := t.TempDir()
	arch := filepath.Join(dir, "bomb.tar.gz")
	writeZeroGzipTar(t, arch, 32, 4<<20) // 128 MiB of zeros
	out := filepath.Join(dir, "out")
	if err := os.MkdirAll(out, 0o700); err != nil {
		t.Fatal(err)
	}
	const limit = int64(10 << 20)
	err := extractTarWithLimits(arch, out, limit, maxOCIArchiveEntries)
	if !errors.Is(err, ErrOCILimitExceeded) {
		t.Fatalf("expected ErrOCILimitExceeded, got %v", err)
	}
	if n := treeBytes(out); n > limit {
		t.Fatalf("wrote %d bytes, cap is %d", n, limit)
	}
}

// TestExtractEBPFFromOCIWithLimitsRejectsGzipBomb is the A1-4 shape: a
// ~1 MiB gzip upload that expands to 1 GiB. With API-sized limits it is
// rejected, and the temporary extraction dir is removed.
func TestExtractEBPFFromOCIWithLimitsRejectsGzipBomb(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a 1 GiB-expanding gzip bomb")
	}
	tmpRoot := t.TempDir()
	t.Setenv("TMPDIR", tmpRoot)
	arch := filepath.Join(t.TempDir(), "upload.bpf.o")
	writeZeroGzipTar(t, arch, 64, 16<<20)
	dst := t.TempDir()
	_, _, err := ExtractEBPFFromOCIWithLimits(context.Background(), arch, dst, OCILimits{MaxArchiveExpandedBytes: 64 << 20})
	if !errors.Is(err, ErrOCILimitExceeded) {
		t.Fatalf("expected ErrOCILimitExceeded, got %v", err)
	}
	if left, _ := os.ReadDir(tmpRoot); len(left) != 0 {
		t.Fatalf("temporary extraction output left behind: %d entries", len(left))
	}
	if left, _ := os.ReadDir(dst); len(left) != 0 {
		t.Fatalf("destination should be empty, has %d entries", len(left))
	}
}

// TestExtractEBPFFromOCIWithLimitsCapsEBPFLayer covers the second disk write:
// the extracted eBPF layer itself honours MaxArtifactBytes.
func TestExtractEBPFFromOCIWithLimitsCapsEBPFLayer(t *testing.T) {
	payload := append(fakeELF(), make([]byte, 4096)...)
	layoutDir := writeGadgetLayout(t, gadgetEBPFMediaType, payload)
	dst := t.TempDir()
	_, _, err := ExtractEBPFFromOCIWithLimits(context.Background(), layoutDir, dst, OCILimits{MaxArtifactBytes: 1024})
	if !errors.Is(err, ErrOCILimitExceeded) {
		t.Fatalf("expected ErrOCILimitExceeded for the eBPF layer, got %v", err)
	}
	if left, _ := os.ReadDir(dst); len(left) != 0 {
		t.Fatalf("partial artifact left behind")
	}
}

// TestExtractEBPFFromOCIWithLimitsAcceptsSmallImageArchive: a legitimate
// image archive (`docker save` / tarball format, the archive form that
// extracts today) still extracts under tight, upload-sized limits.
func TestExtractEBPFFromOCIWithLimitsAcceptsSmallImageArchive(t *testing.T) {
	img, err := mutate.AppendLayers(empty.Image, static.NewLayer(fakeELF(), types.OCILayer))
	if err != nil {
		t.Fatal(err)
	}
	arch := filepath.Join(t.TempDir(), "gadget.tar")
	if err := tarball.WriteToFile(arch, name.MustParseReference("example.com/gadget:v1"), img); err != nil {
		t.Fatal(err)
	}
	if !IsOCISource(arch) {
		t.Fatal("image archive should be routed to the OCI path")
	}
	st, err := os.Stat(arch)
	if err != nil {
		t.Fatal(err)
	}
	limits := OCILimits{MaxArchiveExpandedBytes: st.Size(), MaxArtifactBytes: st.Size()}
	got, _, err := ExtractEBPFFromOCIWithLimits(context.Background(), arch, t.TempDir(), limits)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(got)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, fakeELF()) {
		t.Fatal("extracted payload mismatch")
	}
}

// TestOCILayoutArchiveWithinLimitIsNotSizeRejected: a gzip'd OCI-layout
// archive whose content fits the 64x ratio is not rejected by the size limit.
// (Whatever else happens downstream is outside this change's scope.)
func TestOCILayoutArchiveWithinLimitIsNotSizeRejected(t *testing.T) {
	layoutDir := writeGadgetLayout(t, gadgetEBPFMediaType, fakeELF())
	arch := filepath.Join(t.TempDir(), "gadget.tar.gz")
	tarDir(t, layoutDir, arch, true)
	st, err := os.Stat(arch)
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = ExtractEBPFFromOCIWithLimits(context.Background(), arch, t.TempDir(), OCILimits{MaxArchiveExpandedBytes: st.Size() * 64})
	if errors.Is(err, ErrOCILimitExceeded) {
		t.Fatalf("legitimate OCI-layout archive rejected by the size limit: %v", err)
	}
}
