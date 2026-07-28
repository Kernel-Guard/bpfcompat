package vm

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

const (
	imageDownloadTimeout  = 45 * time.Minute
	maxImageDownloadBytes = int64(20 << 30)
)

var imageHTTPClient = &http.Client{Timeout: imageDownloadTimeout}

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

// ensureImageChecksum returns the digest of the image bytes used by this run.
// The sidecar is evidence for operators, not a trust source: the image is
// re-hashed every time so replacing both files cannot forge run provenance.
func ensureImageChecksum(imagePath string) (string, error) {
	sidecarPath := imagePath + ".sha256"
	sum, err := fileSHA256(imagePath)
	if err != nil {
		return "", err
	}
	content := fmt.Sprintf("%s  %s\n", sum, imagePath)
	if err := os.WriteFile(sidecarPath, []byte(content), 0o600); err != nil {
		return "", fmt.Errorf("write checksum sidecar: %w", err)
	}
	return sum, nil
}

func downloadFile(ctx context.Context, url, outPath string) error {
	return downloadFileWithLimit(ctx, imageHTTPClient, url, outPath, maxImageDownloadBytes)
}

func downloadFileWithLimit(ctx context.Context, client *http.Client, url, outPath string, maxBytes int64) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody) // #nosec G107 -- URL comes from trusted profile configuration.
	if err != nil {
		return fmt.Errorf("create request for %q: %w", url, err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("http get %q: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("unexpected HTTP status %d for %s", resp.StatusCode, url)
	}
	if resp.ContentLength > maxBytes {
		return fmt.Errorf("download %s is %d bytes, exceeds limit %d", url, resp.ContentLength, maxBytes)
	}

	out, err := os.OpenFile(outPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600) // #nosec G304 -- outPath is a runner-owned temporary path.
	if err != nil {
		return fmt.Errorf("create %s: %w", outPath, err)
	}
	complete := false
	defer func() {
		_ = out.Close()
		if !complete {
			_ = os.Remove(outPath)
		}
	}()

	written, err := io.Copy(out, io.LimitReader(resp.Body, maxBytes+1))
	if err != nil {
		return fmt.Errorf("copy response to %s: %w", outPath, err)
	}
	if written > maxBytes {
		return fmt.Errorf("download %s exceeds limit %d", url, maxBytes)
	}
	if err := out.Sync(); err != nil {
		return fmt.Errorf("sync %s: %w", outPath, err)
	}
	if err := out.Close(); err != nil {
		return fmt.Errorf("close %s: %w", outPath, err)
	}
	complete = true
	return nil
}
