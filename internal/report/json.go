package report

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/erenari/bpfcompat/pkg/schema"
)

func WriteJSON(outPath string, report schema.ReportV01) error {
	absOut, err := filepath.Abs(outPath)
	if err != nil {
		return fmt.Errorf("resolve JSON output path: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(absOut), 0o755); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}

	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal report JSON: %w", err)
	}
	data = append(data, '\n')

	if err := os.WriteFile(absOut, data, 0o644); err != nil {
		return fmt.Errorf("write report JSON: %w", err)
	}
	return nil
}
