package artifact

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/kernel-guard/bpfcompat/internal/safepath"
)

func Stage(srcPath, dstDir string) (string, error) {
	srcAbs, err := filepath.Abs(srcPath)
	if err != nil {
		return "", fmt.Errorf("resolve source path: %w", err)
	}
	dstDirAbs, err := filepath.Abs(dstDir)
	if err != nil {
		return "", fmt.Errorf("resolve destination directory: %w", err)
	}

	if err := os.MkdirAll(dstDirAbs, 0o755); err != nil {
		return "", fmt.Errorf("create destination directory: %w", err)
	}

	src, err := os.Open(srcAbs)
	if err != nil {
		return "", fmt.Errorf("open source artifact: %w", err)
	}
	defer src.Close()

	// The destination filename is derived from the source basename; contain
	// it to a single component under the destination directory.
	dstPath, err := safepath.LocalJoin(dstDirAbs, filepath.Base(srcAbs))
	if err != nil {
		return "", fmt.Errorf("resolve staged artifact path: %w", err)
	}
	dst, err := os.Create(dstPath)
	if err != nil {
		return "", fmt.Errorf("create staged artifact: %w", err)
	}
	defer dst.Close()

	if _, err := io.Copy(dst, src); err != nil {
		return "", fmt.Errorf("copy artifact: %w", err)
	}
	if err := dst.Sync(); err != nil {
		return "", fmt.Errorf("sync staged artifact: %w", err)
	}

	return dstPath, nil
}
