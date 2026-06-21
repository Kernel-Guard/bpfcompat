package artifact

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/go-containerregistry/pkg/crane"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
)

// gadgetEBPFMediaType is the OCI layer media type Inspektor Gadget uses for the
// compiled eBPF program inside a gadget image. We prefer it when present, but
// fall back to ELF-magic detection so the loader also handles gadgets packaged
// by other tools.
const gadgetEBPFMediaType = "application/vnd.gadget.ebpf.program.v1+binary"

// elfMagic is the leading byte sequence of every ELF object (`\x7fELF`).
var elfMagic = []byte{0x7f, 'E', 'L', 'F'}

// IsOCISource reports whether ref names an OCI image we should extract an eBPF
// ELF from rather than a plain `.bpf.o` file. It recognizes three forms:
//
//   - an OCI layout directory (contains an `oci-layout` marker),
//   - an OCI image archive (a `.tar`/`.tar.gz` whose first bytes are a tar or
//     gzip stream, not an ELF), and
//   - a remote registry reference (anything that is not an existing local path
//     but parses as an image reference, e.g. ghcr.io/org/gadget:tag).
//
// A plain ELF object on disk returns false so the existing path is unaffected.
func IsOCISource(ref string) bool {
	if strings.TrimSpace(ref) == "" {
		return false
	}
	info, err := os.Stat(ref)
	if err == nil {
		if info.IsDir() {
			_, layoutErr := os.Stat(filepath.Join(ref, "oci-layout"))
			return layoutErr == nil
		}
		return fileLooksLikeOCIArchive(ref)
	}
	if !errors.Is(err, os.ErrNotExist) {
		return false
	}
	// Not a local path: treat it as a registry reference if it parses as one.
	_, parseErr := name.ParseReference(ref)
	return parseErr == nil
}

// fileLooksLikeOCIArchive peeks at a regular file's leading bytes: an ELF
// object is not an archive, while a gzip or tar stream may be an OCI image
// archive.
func fileLooksLikeOCIArchive(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()

	header := make([]byte, 512)
	n, _ := io.ReadFull(f, header)
	header = header[:n]
	if hasPrefix(header, elfMagic) {
		return false
	}
	if hasPrefix(header, []byte{0x1f, 0x8b}) { // gzip
		return true
	}
	// Uncompressed tar: the "ustar" magic sits at offset 257.
	if len(header) >= 263 && string(header[257:262]) == "ustar" {
		return true
	}
	return false
}

// ExtractEBPFFromOCI loads the OCI image named by ref (registry reference, OCI
// layout directory, or OCI/docker image archive) and writes its eBPF ELF layer
// into dstDir, returning the path to the extracted object.
func ExtractEBPFFromOCI(ref, dstDir string) (string, error) {
	img, err := loadOCIImage(ref)
	if err != nil {
		return "", err
	}

	layers, err := img.Layers()
	if err != nil {
		return "", fmt.Errorf("read OCI image layers: %w", err)
	}
	if len(layers) == 0 {
		return "", fmt.Errorf("OCI image %q has no layers", ref)
	}

	elf, err := selectEBPFLayer(layers)
	if err != nil {
		return "", fmt.Errorf("locate eBPF object in OCI image %q: %w", ref, err)
	}

	if err := os.MkdirAll(dstDir, 0o755); err != nil {
		return "", fmt.Errorf("create destination directory: %w", err)
	}
	outPath := filepath.Join(dstDir, ociArtifactName(ref)+".bpf.o")
	out, err := os.Create(outPath)
	if err != nil {
		return "", fmt.Errorf("create extracted artifact: %w", err)
	}
	defer out.Close()

	rc, err := elf.Uncompressed()
	if err != nil {
		return "", fmt.Errorf("read eBPF layer: %w", err)
	}
	defer rc.Close()
	if _, err := io.Copy(out, rc); err != nil {
		return "", fmt.Errorf("write extracted artifact: %w", err)
	}
	if err := out.Sync(); err != nil {
		return "", fmt.Errorf("sync extracted artifact: %w", err)
	}
	return outPath, nil
}

// loadOCIImage resolves ref to a single image, handling registry references,
// OCI layout directories, and image archives.
func loadOCIImage(ref string) (v1.Image, error) {
	info, statErr := os.Stat(ref)
	switch {
	case statErr == nil && info.IsDir():
		return imageFromLayout(ref)
	case statErr == nil:
		return imageFromArchive(ref)
	default:
		img, err := crane.Pull(ref)
		if err != nil {
			return nil, fmt.Errorf("pull OCI image %q: %w", ref, err)
		}
		return img, nil
	}
}

// imageFromLayout returns the first image in an OCI layout directory.
func imageFromLayout(dir string) (v1.Image, error) {
	p, err := layout.FromPath(dir)
	if err != nil {
		return nil, fmt.Errorf("open OCI layout %q: %w", dir, err)
	}
	idx, err := p.ImageIndex()
	if err != nil {
		return nil, fmt.Errorf("read OCI layout index: %w", err)
	}
	return firstImageFromIndex(idx)
}

// imageFromArchive returns the image in an archive, trying the docker `save`
// format first and falling back to an OCI-layout tar.
func imageFromArchive(path string) (v1.Image, error) {
	if img, err := tarball.ImageFromPath(path, nil); err == nil {
		return img, nil
	}
	dir, err := os.MkdirTemp("", "bpfcompat-oci-archive-")
	if err != nil {
		return nil, fmt.Errorf("create temp dir for OCI archive: %w", err)
	}
	defer os.RemoveAll(dir)
	if err := extractTar(path, dir); err != nil {
		return nil, fmt.Errorf("extract OCI archive %q: %w", path, err)
	}
	return imageFromLayout(dir)
}

func firstImageFromIndex(idx v1.ImageIndex) (v1.Image, error) {
	manifest, err := idx.IndexManifest()
	if err != nil {
		return nil, fmt.Errorf("read index manifest: %w", err)
	}
	for _, desc := range manifest.Manifests {
		if desc.MediaType.IsImage() {
			return idx.Image(desc.Digest)
		}
		if desc.MediaType.IsIndex() {
			child, err := idx.ImageIndex(desc.Digest)
			if err != nil {
				return nil, err
			}
			return firstImageFromIndex(child)
		}
	}
	return nil, errors.New("no image found in OCI index")
}

// selectEBPFLayer picks the eBPF object layer: the Inspektor Gadget media type
// if present, otherwise the first layer whose content starts with ELF magic.
func selectEBPFLayer(layers []v1.Layer) (v1.Layer, error) {
	for _, l := range layers {
		mt, err := l.MediaType()
		if err == nil && string(mt) == gadgetEBPFMediaType {
			return l, nil
		}
	}
	for _, l := range layers {
		rc, err := l.Uncompressed()
		if err != nil {
			continue
		}
		head := make([]byte, len(elfMagic))
		n, _ := io.ReadFull(rc, head)
		rc.Close()
		if hasPrefix(head[:n], elfMagic) {
			return l, nil
		}
	}
	return nil, errors.New("no eBPF ELF layer (looked for the gadget eBPF media type and ELF magic)")
}

// ociArtifactName derives a filesystem-safe base name from an image reference,
// e.g. "ghcr.io/inspektor-gadget/gadget/trace_open:latest" -> "trace_open".
func ociArtifactName(ref string) string {
	base := ref
	// Drop a digest ("@sha256:...") then a tag (":latest").
	if i := strings.IndexByte(base, '@'); i >= 0 {
		base = base[:i]
	}
	if i := strings.LastIndexByte(base, ':'); i >= 0 {
		// Only treat the trailing ":" as a tag separator, not a path char.
		if !strings.ContainsAny(base[i+1:], "/\\") {
			base = base[:i]
		}
	}
	if i := strings.LastIndexAny(base, "/\\"); i >= 0 {
		base = base[i+1:]
	}
	base = strings.TrimSuffix(base, ".bpf.o")
	base = strings.TrimSuffix(base, ".tar.gz")
	base = strings.TrimSuffix(base, ".tar")
	if base == "" {
		return "gadget"
	}
	return base
}

func extractTar(path, dstDir string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	var r io.Reader = f
	br := make([]byte, 2)
	if _, err := io.ReadFull(f, br); err == nil && br[0] == 0x1f && br[1] == 0x8b {
		if _, err := f.Seek(0, io.SeekStart); err != nil {
			return err
		}
		gz, err := gzip.NewReader(f)
		if err != nil {
			return err
		}
		defer gz.Close()
		r = gz
	} else if _, err := f.Seek(0, io.SeekStart); err != nil {
		return err
	}

	tr := tar.NewReader(r)
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		target, err := safeJoin(dstDir, hdr.Name)
		if err != nil {
			return err
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			w, err := os.Create(target)
			if err != nil {
				return err
			}
			if _, err := io.Copy(w, tr); err != nil { //nolint:gosec // size bounded by trusted local archive
				w.Close()
				return err
			}
			w.Close()
		}
	}
}

// safeJoin joins name onto dir, rejecting paths that escape dir (zip-slip).
func safeJoin(dir, name string) (string, error) {
	target := filepath.Join(dir, name)
	cleanDir := filepath.Clean(dir) + string(os.PathSeparator)
	if !strings.HasPrefix(filepath.Clean(target)+string(os.PathSeparator), cleanDir) {
		return "", fmt.Errorf("archive entry escapes destination: %q", name)
	}
	return target, nil
}

func hasPrefix(b, prefix []byte) bool {
	if len(b) < len(prefix) {
		return false
	}
	for i := range prefix {
		if b[i] != prefix[i] {
			return false
		}
	}
	return true
}
