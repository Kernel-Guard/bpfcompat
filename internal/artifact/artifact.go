package artifact

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

func Stage(srcPath, dstDir string) (stagedPath string, retErr error) {
	srcAbs, err := filepath.Abs(srcPath)
	if err != nil {
		return "", fmt.Errorf("resolve source path: %w", err)
	}
	dstDirAbs, err := filepath.Abs(dstDir)
	if err != nil {
		return "", fmt.Errorf("resolve destination directory: %w", err)
	}

	dstRoot, err := os.OpenRoot(dstDirAbs)
	if err != nil {
		return "", fmt.Errorf("open existing destination directory: %w", err)
	}
	defer dstRoot.Close()

	src, err := os.Open(srcAbs)
	if err != nil {
		return "", fmt.Errorf("open source artifact: %w", err)
	}
	defer src.Close()

	dstName := filepath.Base(srcAbs)
	dst, err := dstRoot.OpenFile(dstName, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", fmt.Errorf("create staged artifact: %w", err)
	}
	defer func() {
		if closeErr := dst.Close(); closeErr != nil && retErr == nil {
			stagedPath = ""
			retErr = fmt.Errorf("close staged artifact: %w", closeErr)
		}
		if retErr == nil {
			return
		}
		if removeErr := dstRoot.Remove(dstName); removeErr != nil && !os.IsNotExist(removeErr) {
			retErr = errors.Join(retErr, fmt.Errorf("remove incomplete staged artifact: %w", removeErr))
		}
	}()
	if err := dst.Chmod(0o600); err != nil {
		return "", fmt.Errorf("set staged artifact permissions: %w", err)
	}

	if _, err := io.Copy(dst, src); err != nil {
		return "", fmt.Errorf("copy artifact: %w", err)
	}
	if err := dst.Sync(); err != nil {
		return "", fmt.Errorf("sync staged artifact: %w", err)
	}

	return filepath.Join(dstDirAbs, dstName), nil
}
