package vm

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
)

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path) // #nosec G304 -- path comes from trusted profile configuration.
	if err != nil {
		return "", fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("hash %s: %w", path, err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// ensureImageChecksum returns the image's sha256, computing and caching it
// in a "<path>.sha256" sidecar on first use so later runs don't re-hash
// multi-hundred-MB images. The sidecar makes every run attributable to
// exact image bytes — vendor "current" cloud-image URLs mutate over time,
// so the URL alone does not identify what was tested.
func ensureImageChecksum(imagePath string) (string, error) {
	sidecarPath := imagePath + ".sha256"
	if data, err := os.ReadFile(sidecarPath); err == nil { // #nosec G304 -- derived from trusted profile path.
		sum := strings.TrimSpace(strings.Fields(string(data))[0])
		if len(sum) == 64 {
			return sum, nil
		}
	}
	sum, err := fileSHA256(imagePath)
	if err != nil {
		return "", err
	}
	content := fmt.Sprintf("%s  %s\n", sum, imagePath)
	if err := os.WriteFile(sidecarPath, []byte(content), 0o644); err != nil {
		return "", fmt.Errorf("write checksum sidecar: %w", err)
	}
	return sum, nil
}

func downloadFile(url, outPath string) error {
	resp, err := http.Get(url) // #nosec G107 -- URL comes from trusted profile configuration in this MVP.
	if err != nil {
		return fmt.Errorf("http get %q: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("unexpected HTTP status %d for %s", resp.StatusCode, url)
	}

	out, err := os.Create(outPath)
	if err != nil {
		return fmt.Errorf("create %s: %w", outPath, err)
	}
	defer out.Close()

	if _, err := io.Copy(out, resp.Body); err != nil {
		return fmt.Errorf("copy response to %s: %w", outPath, err)
	}
	if err := out.Sync(); err != nil {
		return fmt.Errorf("sync %s: %w", outPath, err)
	}
	return nil
}
