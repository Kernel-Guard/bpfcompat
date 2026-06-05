package artifact

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

type Metadata struct {
	AbsolutePath string
	BaseName     string
	SHA256       string
	SizeBytes    int64
}

func Inspect(path string) (Metadata, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return Metadata{}, fmt.Errorf("resolve artifact path: %w", err)
	}

	file, err := os.Open(absPath)
	if err != nil {
		return Metadata{}, fmt.Errorf("open artifact: %w", err)
	}
	defer file.Close()

	stat, err := file.Stat()
	if err != nil {
		return Metadata{}, fmt.Errorf("stat artifact: %w", err)
	}
	if stat.IsDir() {
		return Metadata{}, fmt.Errorf("artifact path is a directory: %s", absPath)
	}

	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return Metadata{}, fmt.Errorf("hash artifact: %w", err)
	}

	return Metadata{
		AbsolutePath: absPath,
		BaseName:     filepath.Base(absPath),
		SHA256:       hex.EncodeToString(hasher.Sum(nil)),
		SizeBytes:    stat.Size(),
	}, nil
}
