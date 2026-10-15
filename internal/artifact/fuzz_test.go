package artifact

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/static"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

// maxFuzzArchiveBytes bounds harness input. OCI archives may be gzip
// compressed, so a small input can still expand by ~1000x; keep the input
// small enough that a worst-case expansion stays far below the fuzz worker's
// memory and disk budget.
const maxFuzzArchiveBytes = 256 << 10

// FuzzExtractTarWithLimits drives the OCI-layout archive extractor with
// arbitrary (optionally gzip-compressed) tar streams. A user-supplied OCI
// archive reaches this code through `bpfcompat test --artifact x.tar`.
//
// Properties: no panic, nothing is ever created outside the destination
// directory (zip-slip containment) whatever the entry names are, and no
// symlinks are materialised.
func FuzzExtractTarWithLimits(f *testing.F) {
	for _, seed := range tarSeeds(f) {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > maxFuzzArchiveBytes {
			data = data[:maxFuzzArchiveBytes]
		}
		root := t.TempDir()
		archivePath := filepath.Join(root, "in.tar")
		if err := os.WriteFile(archivePath, data, 0o600); err != nil {
			t.Fatal(err)
		}
		dst := filepath.Join(root, "dst")
		if err := os.Mkdir(dst, 0o700); err != nil {
			t.Fatal(err)
		}
		_ = extractTarWithLimits(archivePath, dst, 1<<20, 64)

		entries, err := os.ReadDir(root)
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			if entry.Name() != "in.tar" && entry.Name() != "dst" {
				t.Fatalf("extraction escaped the destination: created %q next to it", entry.Name())
			}
		}
		walkErr := filepath.WalkDir(dst, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.Type()&fs.ModeSymlink != 0 {
				t.Fatalf("extraction created a symlink %q", path)
			}
			return nil
		})
		if walkErr != nil {
			t.Fatalf("walk destination: %v", walkErr)
		}
	})
}

// FuzzExtractEBPFFromOCIArchive feeds arbitrary bytes to the full local OCI
// archive path (docker-save tarball first, then OCI-layout tar), as an
// operator-supplied archive would. The input always exists as a local file, so
// the registry-pull branch is never reached and the target stays hermetic.
//
// Properties: no panic; IsOCISource/fileLooksLikeOCIArchive never panic; on
// success the extracted object lives directly inside the destination
// directory and respects the eBPF object size limit.
func FuzzExtractEBPFFromOCIArchive(f *testing.F) {
	for _, seed := range tarSeeds(f) {
		f.Add(seed)
	}
	f.Add(ociLayoutTarSeed(f))
	f.Add(dockerTarballSeed(f))
	f.Add(fakeELF())

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > maxFuzzArchiveBytes {
			data = data[:maxFuzzArchiveBytes]
		}
		root := t.TempDir()
		archivePath := filepath.Join(root, "gadget.tar")
		if err := os.WriteFile(archivePath, data, 0o600); err != nil {
			t.Fatal(err)
		}
		_ = fileLooksLikeOCIArchive(archivePath)
		_ = IsOCISource(archivePath)

		dst := filepath.Join(root, "out")
		out, _, err := ExtractEBPFFromOCI(context.Background(), archivePath, dst)
		if err != nil {
			return
		}
		if filepath.Dir(out) != dst {
			t.Fatalf("extracted object %q is not directly under %q", out, dst)
		}
		info, err := os.Stat(out)
		if err != nil {
			t.Fatalf("extract reported success but object is missing: %v", err)
		}
		if info.Size() > maxEBPFArtifactBytes {
			t.Fatalf("extracted object exceeds limit: %d", info.Size())
		}
	})
}

func tarSeeds(f *testing.F) [][]byte {
	f.Helper()
	build := func(entries []tar.Header, payload []byte) []byte {
		var buf bytes.Buffer
		tw := tar.NewWriter(&buf)
		for i := range entries {
			hdr := entries[i]
			if hdr.Typeflag == tar.TypeReg {
				hdr.Size = int64(len(payload))
			}
			if err := tw.WriteHeader(&hdr); err != nil {
				f.Fatal(err)
			}
			if hdr.Typeflag == tar.TypeReg {
				if _, err := tw.Write(payload); err != nil {
					f.Fatal(err)
				}
			}
		}
		if err := tw.Close(); err != nil {
			f.Fatal(err)
		}
		return buf.Bytes()
	}
	gz := func(raw []byte) []byte {
		var buf bytes.Buffer
		zw := gzip.NewWriter(&buf)
		if _, err := zw.Write(raw); err != nil {
			f.Fatal(err)
		}
		if err := zw.Close(); err != nil {
			f.Fatal(err)
		}
		return buf.Bytes()
	}
	plain := build([]tar.Header{
		{Name: "blobs/", Typeflag: tar.TypeDir, Mode: 0o700},
		{Name: "blobs/sha256/abcd", Typeflag: tar.TypeReg, Mode: 0o600},
		{Name: "oci-layout", Typeflag: tar.TypeReg, Mode: 0o600},
	}, []byte(`{"imageLayoutVersion":"1.0.0"}`))
	escape := build([]tar.Header{
		{Name: "../escape", Typeflag: tar.TypeReg, Mode: 0o600},
	}, []byte("x"))
	symlink := build([]tar.Header{
		{Name: "link", Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd", Mode: 0o777},
	}, nil)
	return [][]byte{plain, gz(plain), escape, symlink, {}, []byte(strings.Repeat("\x00", 1024))}
}

func ociLayoutTarSeed(f *testing.F) []byte {
	f.Helper()
	layer := static.NewLayer(fakeELF(), types.MediaType(gadgetEBPFMediaType))
	img, err := mutate.AppendLayers(empty.Image, layer)
	if err != nil {
		f.Fatal(err)
	}
	dir, err := os.MkdirTemp("", "bpfcompat-fuzz-layout-")
	if err != nil {
		f.Fatal(err)
	}
	defer os.RemoveAll(dir)
	p, err := layout.Write(dir, empty.Index)
	if err != nil {
		f.Fatal(err)
	}
	if err := p.AppendImage(img); err != nil {
		f.Fatal(err)
	}
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	if err := tw.AddFS(os.DirFS(dir)); err != nil {
		f.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		f.Fatal(err)
	}
	return buf.Bytes()
}

func dockerTarballSeed(f *testing.F) []byte {
	f.Helper()
	layer := static.NewLayer(fakeELF(), types.DockerLayer)
	img, err := mutate.AppendLayers(empty.Image, layer)
	if err != nil {
		f.Fatal(err)
	}
	tag, err := name.NewTag("example.invalid/gadget:fuzz")
	if err != nil {
		f.Fatal(err)
	}
	var buf bytes.Buffer
	if err := tarball.Write(tag, img, &buf); err != nil {
		f.Fatal(err)
	}
	return buf.Bytes()
}
