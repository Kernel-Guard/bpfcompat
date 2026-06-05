package runner

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

type RunPaths struct {
	RunID    string
	RunDir   string
	InputDir string
	LogsDir  string
}

func PrepareRun(workdir string, now time.Time) (RunPaths, error) {
	randomSuffix, err := randomHex(3)
	if err != nil {
		return RunPaths{}, fmt.Errorf("generate run suffix: %w", err)
	}
	runID := now.UTC().Format("20060102T150405Z") + "-" + randomSuffix

	runDir := filepath.Join(filepath.Clean(workdir), "runs", runID)
	inputDir := filepath.Join(runDir, "input")
	logsDir := filepath.Join(runDir, "logs")

	for _, dir := range []string{inputDir, logsDir} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return RunPaths{}, fmt.Errorf("create %s: %w", dir, err)
		}
	}

	return RunPaths{
		RunID:    runID,
		RunDir:   runDir,
		InputDir: inputDir,
		LogsDir:  logsDir,
	}, nil
}

func randomHex(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}
