package registry

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPersistWritesRunMetadataAndRegistryIndex(t *testing.T) {
	workDir := t.TempDir()
	runDir := filepath.Join(workDir, "runs", "run-1")
	if err := os.MkdirAll(runDir, 0o755); err != nil {
		t.Fatalf("mkdir run dir: %v", err)
	}

	record := RunRecord{
		RunID:          "run-1",
		StartedAt:      "2026-05-14T00:00:00Z",
		ArtifactPath:   "/tmp/a.bpf.o",
		ArtifactURI:    "https://example.invalid/artifacts/a.bpf.o",
		ArtifactSHA256: "abc123",
		MatrixPath:     "/tmp/matrix.yaml",
		SummaryStatus:  "pass",
		JSONReportPath: "/tmp/report.json",
		MarkdownPath:   "/tmp/report.md",
	}

	if err := Persist(workDir, runDir, record); err != nil {
		t.Fatalf("persist: %v", err)
	}

	metaPath := filepath.Join(runDir, "metadata.json")
	metaRaw, err := os.ReadFile(metaPath)
	if err != nil {
		t.Fatalf("read metadata file: %v", err)
	}
	var meta RunRecord
	if err := json.Unmarshal(metaRaw, &meta); err != nil {
		t.Fatalf("parse metadata file: %v", err)
	}
	if meta.RunID != "run-1" {
		t.Fatalf("unexpected metadata run id: %q", meta.RunID)
	}
	if meta.SchemaVersion != schemaVersion {
		t.Fatalf("expected schema version %q, got %q", schemaVersion, meta.SchemaVersion)
	}

	indexPath := filepath.Join(workDir, "registry", "runs.jsonl")
	indexRaw, err := os.ReadFile(indexPath)
	if err != nil {
		t.Fatalf("read registry index: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(indexRaw)), "\n")
	if len(lines) != 1 {
		t.Fatalf("expected one jsonl line, got %d", len(lines))
	}
	var indexed RunRecord
	if err := json.Unmarshal([]byte(lines[0]), &indexed); err != nil {
		t.Fatalf("parse jsonl line: %v", err)
	}
	if indexed.ArtifactSHA256 != "abc123" {
		t.Fatalf("unexpected artifact hash in index: %q", indexed.ArtifactSHA256)
	}
	if indexed.ArtifactURI != "https://example.invalid/artifacts/a.bpf.o" {
		t.Fatalf("unexpected artifact URI in index: %q", indexed.ArtifactURI)
	}
}
