package artifact

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
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

	dstPath := filepath.Join(dstDirAbs, filepath.Base(srcAbs))
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
