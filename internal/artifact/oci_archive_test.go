package artifact

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
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

// isolateOCIArchiveTempDirs points os.TempDir at a fresh directory so a test
// can assert that no bpfcompat-oci-archive-* directory outlives the call.
func isolateOCIArchiveTempDirs(t *testing.T) string {
	t.Helper()
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	return tmp
}

func ociArchiveTempDirs(t *testing.T, tmp string) []string {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(tmp, "bpfcompat-oci-archive-*"))
	if err != nil {
		t.Fatal(err)
	}
	return matches
}

// tarDirectory packs dir into an (optionally gzip-compressed) tar at path, the
// way `tar -C dir -c .` would package an OCI layout.
func tarDirectory(t *testing.T, dir, path string, compress bool) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
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
		if !info.Mode().IsRegular() {
			return nil
		}
		b, err := os.ReadFile(p) // #nosec G304 -- test fixture under t.TempDir.
		if err != nil {
			return err
		}
		_, err = tw.Write(b)
		return err
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
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

// An OCI-layout archive (plain tar and tar.gz) must yield the eBPF object, and
// the temporary unpack directory must be gone once extraction returns.
func TestExtractEBPFFromOCILayoutArchive(t *testing.T) {
	want := sha256.Sum256(fakeELF())
	layoutDir := writeGadgetLayout(t, gadgetEBPFMediaType, fakeELF())
	for _, tc := range []struct {
		name     string
		file     string
		compress bool
	}{
		{name: "tar", file: "gadget.tar", compress: false},
		{name: "tar.gz", file: "gadget.tar.gz", compress: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tmp := isolateOCIArchiveTempDirs(t)
			archive := filepath.Join(t.TempDir(), tc.file)
			tarDirectory(t, layoutDir, archive, tc.compress)
			if !IsOCISource(archive) {
				t.Fatalf("archive %s not recognised as an OCI source", archive)
			}

			path, digest, err := ExtractEBPFFromOCI(context.Background(), archive, t.TempDir())
			if err != nil {
				t.Fatalf("ExtractEBPFFromOCI: %v", err)
			}
			got, err := os.ReadFile(path) // #nosec G304 -- path is under t.TempDir.
			if err != nil {
				t.Fatal(err)
			}
			if sum := sha256.Sum256(got); sum != want {
				t.Fatalf("extracted payload sha256 mismatch: got %x want %x", sum, want)
			}
			if filepath.Base(path) != "gadget.bpf.o" {
				t.Fatalf("unexpected artifact name %q", filepath.Base(path))
			}
			if !strings.HasPrefix(digest, "sha256:") {
				t.Fatalf("expected an image digest, got %q", digest)
			}
			if left := ociArchiveTempDirs(t, tmp); len(left) != 0 {
				t.Fatalf("temporary OCI archive directories leaked after success: %v", left)
			}
		})
	}
}

// Every failure after the archive was unpacked must still remove the
// temporary directory.
func TestExtractEBPFFromOCILayoutArchiveFailureCleansUp(t *testing.T) {
	t.Run("no eBPF layer", func(t *testing.T) {
		tmp := isolateOCIArchiveTempDirs(t)
		layoutDir := writeGadgetLayout(t, string(types.OCILayer), []byte("not an elf at all"))
		archive := filepath.Join(t.TempDir(), "noelf.tar")
		tarDirectory(t, layoutDir, archive, false)
		_, _, err := ExtractEBPFFromOCI(context.Background(), archive, t.TempDir())
		if err == nil || !strings.Contains(err.Error(), "no eBPF ELF layer") {
			t.Fatalf("expected missing-eBPF-layer error, got %v", err)
		}
		if left := ociArchiveTempDirs(t, tmp); len(left) != 0 {
			t.Fatalf("temporary OCI archive directories leaked: %v", left)
		}
	})
	t.Run("not an OCI layout", func(t *testing.T) {
		tmp := isolateOCIArchiveTempDirs(t)
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "README"), []byte("hello"), 0o600); err != nil {
			t.Fatal(err)
		}
		archive := filepath.Join(t.TempDir(), "notlayout.tar.gz")
		tarDirectory(t, dir, archive, true)
		if _, _, err := ExtractEBPFFromOCI(context.Background(), archive, t.TempDir()); err == nil {
			t.Fatal("expected an error for an archive that is not an OCI layout")
		}
		if left := ociArchiveTempDirs(t, tmp); len(left) != 0 {
			t.Fatalf("temporary OCI archive directories leaked: %v", left)
		}
	})
}

// An archive whose entries claim more than the expanded-size ceiling is still
// rejected with the historical error text before anything is written, and
// leaves no temporary directory behind.
func TestExtractEBPFFromOCIArchiveOverLimitRejected(t *testing.T) {
	tmp := isolateOCIArchiveTempDirs(t)
	archive := filepath.Join(t.TempDir(), "huge.tar")
	f, err := os.Create(archive)
	if err != nil {
		t.Fatal(err)
	}
	tw := tar.NewWriter(f)
	// Only the header is written: the size check fires before any data is
	// read, so the archive need not actually contain 8 GiB.
	if err := tw.WriteHeader(&tar.Header{
		Name:     "blobs/sha256/huge",
		Mode:     0o600,
		Size:     maxOCIArchiveExpandedBytes + 1,
		Typeflag: tar.TypeReg,
	}); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	_, _, err = ExtractEBPFFromOCI(context.Background(), archive, t.TempDir())
	if err == nil || !strings.Contains(err.Error(), "OCI archive exceeds expanded-size limit of 8589934592 bytes") {
		t.Fatalf("expected expanded-size limit error, got %v", err)
	}
	if left := ociArchiveTempDirs(t, tmp); len(left) != 0 {
		t.Fatalf("temporary OCI archive directories leaked: %v", left)
	}
}

// docker-save archives are read directly by go-containerregistry and must keep
// working without any temporary unpack directory.
func TestExtractEBPFFromDockerSaveArchive(t *testing.T) {
	tmp := isolateOCIArchiveTempDirs(t)
	img, err := mutate.AppendLayers(empty.Image, static.NewLayer(fakeELF(), types.MediaType(gadgetEBPFMediaType)))
	if err != nil {
		t.Fatal(err)
	}
	ref, err := name.ParseReference("example.invalid/gadget/trace_open:latest")
	if err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(t.TempDir(), "trace_open.tar")
	if err := tarball.WriteToFile(archive, ref, img); err != nil {
		t.Fatal(err)
	}

	path, _, err := ExtractEBPFFromOCI(context.Background(), archive, t.TempDir())
	if err != nil {
		t.Fatalf("ExtractEBPFFromOCI: %v", err)
	}
	got, err := os.ReadFile(path) // #nosec G304 -- path is under t.TempDir.
	if err != nil {
		t.Fatal(err)
	}
	if sha256.Sum256(got) != sha256.Sum256(fakeELF()) {
		t.Fatal("extracted payload mismatch for docker-save archive")
	}
	if left := ociArchiveTempDirs(t, tmp); len(left) != 0 {
		t.Fatalf("docker-save path created temporary OCI archive directories: %v", left)
	}
}
