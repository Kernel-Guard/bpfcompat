package registry

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

const schemaVersion = "registry.v0.1"

type RunRecord struct {
	SchemaVersion   string `json:"schema_version"`
	RunID           string `json:"run_id"`
	StartedAt       string `json:"started_at"`
	ArtifactName    string `json:"artifact_name,omitempty"`
	ArtifactVersion string `json:"artifact_version,omitempty"`
	ArtifactVariant string `json:"artifact_variant,omitempty"`
	ArtifactPath    string `json:"artifact_path"`
	ArtifactURI     string `json:"artifact_uri,omitempty"`
	ArtifactSHA256  string `json:"artifact_sha256"`
	MatrixPath      string `json:"matrix_path"`
	MatrixName      string `json:"matrix_name,omitempty"`
	SummaryStatus   string `json:"summary_status"`
	JSONReportPath  string `json:"json_report_path"`
	MarkdownPath    string `json:"markdown_path,omitempty"`
}

func Persist(workDir, runDir string, record RunRecord) error {
	if workDir == "" {
		return fmt.Errorf("workdir is required")
	}
	if runDir == "" {
		return fmt.Errorf("runDir is required")
	}
	if record.RunID == "" {
		return fmt.Errorf("record.run_id is required")
	}

	if record.SchemaVersion == "" {
		record.SchemaVersion = schemaVersion
	}

	if err := writeRunMetadata(runDir, record); err != nil {
		return err
	}
	if err := appendRegistryJSONL(workDir, record); err != nil {
		return err
	}
	return nil
}

func writeRunMetadata(runDir string, record RunRecord) error {
	metaPath := filepath.Join(runDir, "metadata.json")
	payload, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal run metadata: %w", err)
	}
	payload = append(payload, '\n')
	if err := os.WriteFile(metaPath, payload, 0o644); err != nil {
		return fmt.Errorf("write run metadata file: %w", err)
	}
	return nil
}

func appendRegistryJSONL(workDir string, record RunRecord) error {
	registryDir := filepath.Join(filepath.Clean(workDir), "registry")
	if err := os.MkdirAll(registryDir, 0o755); err != nil {
		return fmt.Errorf("create registry directory: %w", err)
	}

	indexPath := filepath.Join(registryDir, "runs.jsonl")
	f, err := os.OpenFile(indexPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("open registry index: %w", err)
	}
	defer f.Close()

	line, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("marshal registry record: %w", err)
	}
	line = append(line, '\n')

	if _, err := f.Write(line); err != nil {
		return fmt.Errorf("append registry record: %w", err)
	}
	return nil
}
