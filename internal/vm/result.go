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
