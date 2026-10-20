package artifact

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

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

const (
	maxEBPFArtifactBytes       = int64(512 << 20)
	maxOCIArchiveExpandedBytes = int64(8 << 30)
	maxOCIArchiveEntries       = 100_000
	ociOperationTimeout        = 10 * time.Minute
)

// elfMagic is the leading byte sequence of every ELF object (`\x7fELF`).
var elfMagic = []byte{0x7f, 'E', 'L', 'F'}

// IsOCISource reports whether ref names an OCI image we should extract an eBPF
// ELF from rather than a plain `.bpf.o` file. It recognizes three forms:
//
//   - an OCI layout directory (contains an `oci-layout` marker),
//   - an OCI image archive (a `.tar`/`.tar.gz` whose first bytes are a tar or
//     gzip stream, not an ELF), and
//   - a remote registry reference: not an existing local path, parses as an
//     image reference, and names its registry explicitly (see
//     looksLikeRegistryRef), e.g. ghcr.io/org/gadget:tag.
//
// A plain ELF object on disk returns false so the existing path is unaffected,
// and so does a missing local path: "/home/u/prog.bpf.o" or "build/prog.bpf.o"
// also parse as Docker Hub references, and treating them as such would turn a
// typo into a registry pull that leaks the local path.
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
	// Not a local path: treat it as a registry reference only if it is
	// unambiguously one.
	if !looksLikeRegistryRef(ref) {
		return false
	}
	_, parseErr := name.ParseReference(ref)
	return parseErr == nil
}

// looksLikeRegistryRef reports whether a non-existent ref is unambiguously a
// remote registry reference rather than a (missing) local path. It follows
// is_remote_artifact in action.yml: the component before the first "/" must be
// a registry host (contains "." or ":", or is "localhost"), or the ref must pin
// a digest ("@sha256:"). A ref with an explicit registry host stays remote even
// when its repository or tag ends in .o or .elf (ghcr.io/org/prog.o).
//
// It is deliberately stricter than the Action, in the safe direction only (the
// CLI then reports "no such file" instead of pulling):
//   - path-like refs (absolute, "./", "../", "~", backslashes) are local even
//     with "@sha256:";
//   - refs ending in .bpf.o are local even under a dotted directory
//     (out.d/prog.bpf.o);
//   - bare "localhost" / "localhost:5000" (no repository) and "scheme://"
//     refs are not registry refs.
//
// Implicit Docker Hub short names ("org/name:tag", "name:tag") must be spelled
// with their host, e.g. docker.io/org/name:tag; see DockerHubHint.
func looksLikeRegistryRef(ref string) bool {
	ref = strings.TrimSpace(ref)
	if ref == "" || isPathLike(ref) || strings.Contains(ref, "://") {
		return false
	}
	if strings.HasSuffix(strings.ToLower(ref), ".bpf.o") {
		return false
	}
	if strings.Contains(ref, "@sha256:") {
		return true
	}
	first, _, hasSlash := strings.Cut(ref, "/")
	if !hasSlash {
		return false
	}
	return first == "localhost" || strings.ContainsAny(first, ".:")
}

// isPathLike reports refs that can only be filesystem paths.
func isPathLike(ref string) bool {
	if ref == "." || ref == ".." || filepath.IsAbs(ref) || strings.ContainsRune(ref, '\\') {
		return true
	}
	for _, prefix := range []string{"/", "./", "../", "~"} {
		if strings.HasPrefix(ref, prefix) {
			return true
		}
	}
	return false
}

// DockerHubHint returns the explicit docker.io spelling of ref when ref looks
// like an implicit Docker Hub short reference ("org/name:tag", "name:tag")
// that IsOCISource declines, and "" otherwise. Callers append it to a "no such
// file" error; it only echoes the caller's own input.
func DockerHubHint(ref string) string {
	ref = strings.TrimSpace(ref)
	if ref == "" || isPathLike(ref) || looksLikeRegistryRef(ref) {
		return ""
	}
	if !strings.ContainsAny(ref, ":@") {
		return "" // no tag or digest: more likely a mistyped path
	}
	lower := strings.ToLower(ref)
	if strings.HasSuffix(lower, ".o") || strings.HasSuffix(lower, ".elf") {
		return ""
	}
	if _, err := name.ParseReference(ref); err != nil {
		return ""
	}
	return "docker.io/" + ref
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
// into dstDir. It returns the path to the extracted object and the image's
// immutable content digest.
//
// The digest matters for evidence: a reference like "ghcr.io/org/gadget:latest"
// has moved by the time anyone reads the report, so the tag alone cannot say
// which published image was tested. The digest can. It is best-effort -- an
// image whose digest cannot be computed still yields a usable artifact, which
// is identified by its own SHA-256 either way.
func ExtractEBPFFromOCI(ctx context.Context, ref, dstDir string) (path, digest string, err error) {
	ctx, cancel := context.WithTimeout(ctx, ociOperationTimeout)
	defer cancel()

	img, err := loadOCIImage(ctx, ref)
	if err != nil {
		return "", "", err
	}
	// An image read from an OCI-layout archive is backed by a temporary
	// unpack directory whose blobs are read lazily; keep it until the eBPF
	// layer has been copied out.
	if c, ok := img.(io.Closer); ok {
		defer c.Close()
	}
	if d, digestErr := img.Digest(); digestErr == nil {
		digest = d.String()
	}

	layers, err := img.Layers()
	if err != nil {
		return "", "", fmt.Errorf("read OCI image layers: %w", err)
	}
	if len(layers) == 0 {
		return "", "", fmt.Errorf("OCI image %q has no layers", ref)
	}

	elf, err := selectEBPFLayer(layers)
	if err != nil {
		return "", "", fmt.Errorf("locate eBPF object in OCI image %q: %w", ref, err)
	}

	if err := os.MkdirAll(dstDir, 0o700); err != nil {
		return "", "", fmt.Errorf("create destination directory: %w", err)
	}
	outPath := filepath.Join(dstDir, ociArtifactName(ref)+".bpf.o")
	if err := extractLayerToFile(elf, outPath, maxEBPFArtifactBytes); err != nil {
		return "", "", err
	}
	return outPath, digest, nil
}

// loadOCIImage resolves ref to a single image, handling registry references,
// OCI layout directories, and image archives.
func loadOCIImage(ctx context.Context, ref string) (v1.Image, error) {
	info, statErr := os.Stat(ref)
	switch {
	case statErr == nil && info.IsDir():
		return imageFromLayout(ref)
	case statErr == nil:
		return imageFromArchive(ref)
	default:
		img, err := crane.Pull(ref, crane.WithContext(ctx))
		if err != nil {
			return nil, fmt.Errorf("pull OCI image %q: %w", ref, err)
		}
		return img, nil
	}
}

func extractLayerToFile(layer v1.Layer, outPath string, maxBytes int64) error {
	rc, err := layer.Uncompressed()
	if err != nil {
		return fmt.Errorf("read eBPF layer: %w", err)
	}
	defer rc.Close()

	out, err := os.OpenFile(outPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304 -- outPath is contained in the private runner directory.
	if err != nil {
		return fmt.Errorf("create extracted artifact: %w", err)
	}
	complete := false
	defer func() {
		_ = out.Close()
		if !complete {
			_ = os.Remove(outPath)
		}
	}()

	written, err := io.Copy(out, io.LimitReader(rc, maxBytes+1))
	if err != nil {
		return fmt.Errorf("write extracted artifact: %w", err)
	}
	if written > maxBytes {
		return fmt.Errorf("eBPF layer exceeds limit %d bytes", maxBytes)
	}
	if err := out.Sync(); err != nil {
		return fmt.Errorf("sync extracted artifact: %w", err)
	}
	if err := out.Close(); err != nil {
		return fmt.Errorf("close extracted artifact: %w", err)
	}
	complete = true
	return nil
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
// format first and falling back to an OCI-layout tar. An OCI-layout tar is
// unpacked to a temporary directory that the returned image reads its blobs
// from lazily, so that image is an *unpackedArchiveImage whose Close removes
// the directory; on error the directory is removed before returning.
func imageFromArchive(path string) (v1.Image, error) {
	if img, err := tarball.ImageFromPath(path, nil); err == nil {
		return img, nil
	}
	dir, err := os.MkdirTemp("", "bpfcompat-oci-archive-")
	if err != nil {
		return nil, fmt.Errorf("create temp dir for OCI archive: %w", err)
	}
	keep := false
	defer func() {
		if !keep {
			_ = os.RemoveAll(dir)
		}
	}()
	if err := extractTar(path, dir); err != nil {
		return nil, fmt.Errorf("extract OCI archive %q: %w", path, err)
	}
	img, err := imageFromLayout(dir)
	if err != nil {
		return nil, err
	}
	keep = true
	return &unpackedArchiveImage{Image: img, dir: dir}, nil
}

// unpackedArchiveImage is an image backed by a temporary OCI layout directory.
// The directory must outlive every read of the image's layers; Close removes it.
type unpackedArchiveImage struct {
	v1.Image
	dir string
}

func (i *unpackedArchiveImage) Close() error {
	return os.RemoveAll(i.dir)
}

func firstImageFromIndex(idx v1.ImageIndex) (v1.Image, error) {
	manifest, err := idx.IndexManifest()
	if err != nil {
		return nil, fmt.Errorf("read index manifest: %w", err)
	}
	for i := range manifest.Manifests {
		desc := &manifest.Manifests[i]
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
	return extractTarWithLimits(path, dstDir, maxOCIArchiveExpandedBytes, maxOCIArchiveEntries)
}

func extractTarWithLimits(path, dstDir string, maxBytes int64, maxEntries int) error {
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
	var totalBytes int64
	entries := 0
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		entries++
		if entries > maxEntries {
			return fmt.Errorf("OCI archive exceeds limit of %d entries", maxEntries)
		}
		target, err := safeJoin(dstDir, hdr.Name)
		if err != nil {
			return err
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o700); err != nil {
				return err
			}
		case tar.TypeReg:
			if hdr.Size < 0 || hdr.Size > maxBytes-totalBytes {
				return fmt.Errorf("OCI archive exceeds expanded-size limit of %d bytes", maxBytes)
			}
			totalBytes += hdr.Size
			if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
				return err
			}
			w, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304 -- target is contained under dstDir by safeJoin.
			if err != nil {
				return err
			}
			if _, err := io.CopyN(w, tr, hdr.Size); err != nil {
				_ = w.Close()
				return err
			}
			if err := w.Close(); err != nil {
				return err
			}
		}
	}
}

// safeJoin joins entry onto dir, rejecting paths that escape dir (zip-slip).
func safeJoin(dir, entry string) (string, error) {
	target := filepath.Join(dir, entry)
	cleanDir := filepath.Clean(dir) + string(os.PathSeparator)
	if !strings.HasPrefix(filepath.Clean(target)+string(os.PathSeparator), cleanDir) {
		return "", fmt.Errorf("archive entry escapes destination: %q", entry)
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
