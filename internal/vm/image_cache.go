package vm

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// The image cache can be shared by concurrent runs: every built-in profile
// uses one cache root (~/.cache/bpfcompat by default), and CI hosts often run
// several matrices at once. Publication rules:
//
//   - A download takes a per-image lock (<image>.lock, flock on Unix), then
//     re-checks for the image under the lock, so one image is downloaded once
//     and later callers use what was published.
//   - The download is staged as <image>.<random>.download in the cache
//     directory and published with a same-directory rename. The final path
//     therefore only ever holds a complete image, and a cross-filesystem
//     rename (EXDEV) cannot happen.
//   - A published image is never replaced. A source whose bytes change later
//     does not affect runs that use the cached image; delete the image to
//     refresh it.
//   - Leftover .download files from a downloader that was killed (SIGKILL,
//     OOM, power loss) are removed by the next downloader of that image while
//     it holds the lock, when no live downloader can own them.
//
// Two digests are kept apart throughout:
//
//   - The pinned digest (profile image.sha256) is an expectation and a gate. A
//     download or a cached image whose bytes do not match fails the run. It
//     comes only from the profile, never from a downloaded file or a sidecar.
//   - The observed digest is provenance: the sha256 of the bytes this run
//     boots, recomputed on every run. Without a pin it is recorded, not
//     verified. The <image>.sha256 sidecar is a copy of it for operators and is
//     never read back as a trust source.

// renameImageFn moves a finished download into the image cache; tests inject
// failures (e.g. EXDEV) through it.
var renameImageFn = os.Rename

// imageDownloadTempPath returns a unique, not-yet-existing name in the same
// directory as the cached image, so concurrent runs never share a temp file.
func imageDownloadTempPath(imagePath string) (string, error) {
	suffix := make([]byte, 8)
	if _, err := rand.Read(suffix); err != nil {
		return "", fmt.Errorf("image download temp name: %w", err)
	}
	return fmt.Sprintf("%s.%s.download", imagePath, hex.EncodeToString(suffix)), nil
}

// publishImage downloads url to imagePath unless another run already
// published it, checking the pinned digest (when set) before publication.
func publishImage(ctx context.Context, url, imagePath, pinned string) error {
	if err := os.MkdirAll(filepath.Dir(imagePath), 0o755); err != nil { // #nosec G301 -- shared, non-secret image cache.
		return fmt.Errorf("create image cache directory: %w", err)
	}
	unlock, err := lockImage(ctx, imagePath)
	if err != nil {
		return err
	}
	defer unlock()

	// Another run may have published the image while this one waited.
	if _, err := os.Stat(imagePath); err == nil {
		return nil
	}
	removeStaleDownloads(imagePath)

	tempPath, err := imageDownloadTempPath(imagePath)
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tempPath) }() // no-op once renamed
	if err := downloadFile(ctx, url, tempPath); err != nil {
		return fmt.Errorf("download image: %w", err)
	}
	if pinned != "" {
		observed, err := fileSHA256(tempPath)
		if err != nil {
			return err
		}
		if !strings.EqualFold(observed, pinned) {
			return fmt.Errorf("image checksum mismatch for %s: got %s want %s (pinned image.sha256)", url, observed, pinned)
		}
	}
	if err := renameImageFn(tempPath, imagePath); err != nil {
		return fmt.Errorf("cache downloaded image: %w", err)
	}
	return nil
}

// removeStaleDownloads deletes <image>.*.download leftovers. Call it only
// while holding the image lock: every live downloader of this image holds that
// lock for its whole transfer, so any such file belongs to a dead process.
func removeStaleDownloads(imagePath string) {
	matches, _ := filepath.Glob(escapeGlob(imagePath) + ".*.download")
	for _, m := range matches {
		_ = os.Remove(m)
	}
}

func escapeGlob(p string) string {
	r := strings.NewReplacer(`\`, `\\`, `*`, `\*`, `?`, `\?`, `[`, `\[`)
	return r.Replace(p)
}

// writeFileAtomic replaces path with data via a same-directory temp file and
// rename, so a concurrent reader sees the old or the new content, never a mix.
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	f, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer func() { _ = os.Remove(tmp) }()
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Chmod(perm); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// baseImageDigestNote states how the recorded "base image sha256" relates to
// the profile: verified against a pin, or recorded provenance only. It must not
// start with "base image sha256:" (research tooling parses that note).
func baseImageDigestNote(profile Profile) string {
	if pin := strings.TrimSpace(profile.Image.SHA256); pin != "" {
		return fmt.Sprintf("base image digest: verified, matched the profile's pinned image.sha256 %s before boot", strings.ToLower(pin))
	}
	return "base image digest: not verified, the profile pins no image.sha256; the observed sha256 above is recorded provenance only"
}
