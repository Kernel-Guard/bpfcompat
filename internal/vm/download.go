package vm

import (
	"fmt"
	"io"
	"net/http"
	"os"
)

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
