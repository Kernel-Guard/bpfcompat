package vm

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

func parseExitCodeFile(path string) (int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, fmt.Errorf("read %s: %w", path, err)
	}
	text := strings.TrimSpace(string(data))
	if text == "" {
		return 0, fmt.Errorf("empty exit code file")
	}
	code, err := strconv.Atoi(text)
	if err != nil {
		return 0, fmt.Errorf("parse exit code %q: %w", text, err)
	}
	return code, nil
}

// readFileTail returns the trailing up-to-maxBytes of a file (best-effort:
// missing/unreadable files yield ""), trimmed of surrounding whitespace. Used
// to capture bounded stdout/stderr from command-mode validation runs.
func readFileTail(path string, maxBytes int) string {
	data, err := os.ReadFile(path) // #nosec G304 -- path is a run-dir file we wrote.
	if err != nil {
		return ""
	}
	if maxBytes > 0 && len(data) > maxBytes {
		data = data[len(data)-maxBytes:]
	}
	return strings.TrimSpace(string(data))
}
