package runtime

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/erenari/bpfcompat/internal/registry"
)

func TestVerifySelectedArtifactProvenancePass(t *testing.T) {
	workDir := t.TempDir()
	record := registry.ArtifactVersionRecord{
		RunID:           "run-1",
		RunStartedAt:    "2026-05-16T09:00:00Z",
		CreatedAt:       "2026-05-16T09:00:01Z",
		ArtifactName:    "demo",
		ArtifactVersion: "v1",
		ArtifactPath:    "/tmp/demo-v1.bpf.o",
		ArtifactSHA256:  "abc123",
		MatrixPath:      "/tmp/mvp.yaml",
		SummaryStatus:   "pass",
		RequiredPassed:  1,
		RequiredFailed:  0,
		TotalProfiles:   1,
		JSONReportPath:  "/tmp/demo-v1.json",
	}
	if err := registry.PersistArtifactVersion(workDir, record); err != nil {
		t.Fatalf("persist record v1: %v", err)
	}
	record.RunID = "run-2"
	record.CreatedAt = "2026-05-16T09:00:02Z"
	record.ArtifactVersion = "v2"
	record.ArtifactPath = "/tmp/demo-v2.bpf.o"
	record.JSONReportPath = "/tmp/demo-v2.json"
	if err := registry.PersistArtifactVersion(workDir, record); err != nil {
		t.Fatalf("persist record v2: %v", err)
	}

	selected, err := registry.FindArtifactVersion(workDir, "demo", "v2")
	if err != nil {
		t.Fatalf("find selected record: %v", err)
	}

	got, err := VerifySelectedArtifactProvenance(workDir, selected)
	if err != nil {
		t.Fatalf("verify selected artifact provenance: %v", err)
	}
	if !got.Verified {
		t.Fatalf("expected verified=true")
	}
	if got.Failed != 0 {
		t.Fatalf("expected failed=0, got=%d", got.Failed)
	}
	if !got.Selected.Verified {
		t.Fatalf("expected selected record verified=true")
	}
}

func TestVerifySelectedArtifactProvenanceRejectsTamperedRecord(t *testing.T) {
	workDir := t.TempDir()
	record := registry.ArtifactVersionRecord{
		RunID:           "run-tamper-1",
		RunStartedAt:    "2026-05-16T09:10:00Z",
		CreatedAt:       "2026-05-16T09:10:01Z",
		ArtifactName:    "tamper",
		ArtifactVersion: "v1",
		ArtifactPath:    "/tmp/tamper-v1.bpf.o",
		ArtifactSHA256:  "abc123",
		MatrixPath:      "/tmp/mvp.yaml",
		SummaryStatus:   "pass",
		RequiredPassed:  1,
		RequiredFailed:  0,
		TotalProfiles:   1,
		JSONReportPath:  "/tmp/tamper-v1.json",
	}
	if err := registry.PersistArtifactVersion(workDir, record); err != nil {
		t.Fatalf("persist record: %v", err)
	}

	indexPath := filepath.Join(workDir, "registry", "artifact_versions.jsonl")
	raw, err := os.ReadFile(indexPath)
	if err != nil {
		t.Fatalf("read index: %v", err)
	}
	mutated := strings.ReplaceAll(string(raw), "\"summary_status\":\"pass\"", "\"summary_status\":\"fail\"")
	if mutated == string(raw) {
		t.Fatalf("test mutation did not modify payload")
	}
	if err := os.WriteFile(indexPath, []byte(mutated), 0o644); err != nil {
		t.Fatalf("write mutated index: %v", err)
	}

	selected, err := registry.FindArtifactVersion(workDir, "tamper", "v1")
	if err != nil {
		t.Fatalf("find selected record: %v", err)
	}
	_, err = VerifySelectedArtifactProvenance(workDir, selected)
	if err == nil {
		t.Fatalf("expected tampered record to fail verification")
	}
	if !strings.Contains(err.Error(), "history verification failed") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestVerifySelectedArtifactProvenanceRejectsSignatureTamper(t *testing.T) {
	workDir := t.TempDir()
	record := registry.ArtifactVersionRecord{
		RunID:           "run-sig-1",
		RunStartedAt:    "2026-05-16T09:20:00Z",
		CreatedAt:       "2026-05-16T09:20:01Z",
		ArtifactName:    "sig",
		ArtifactVersion: "v1",
		ArtifactPath:    "/tmp/sig-v1.bpf.o",
		ArtifactSHA256:  "abc123",
		MatrixPath:      "/tmp/mvp.yaml",
		SummaryStatus:   "pass",
		RequiredPassed:  1,
		RequiredFailed:  0,
		TotalProfiles:   1,
		JSONReportPath:  "/tmp/sig-v1.json",
	}
	if err := registry.PersistArtifactVersion(workDir, record); err != nil {
		t.Fatalf("persist record: %v", err)
	}

	indexPath := filepath.Join(workDir, "registry", "artifact_versions.jsonl")
	raw, err := os.ReadFile(indexPath)
	if err != nil {
		t.Fatalf("read index: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) != 1 {
		t.Fatalf("expected exactly one history line, got %d", len(lines))
	}

	var payload map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &payload); err != nil {
		t.Fatalf("decode history record: %v", err)
	}
	payload["signature"] = base64.StdEncoding.EncodeToString([]byte("tampered-signature"))
	line, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("re-encode history record: %v", err)
	}
	if err := os.WriteFile(indexPath, append(line, '\n'), 0o644); err != nil {
		t.Fatalf("write tampered signature record: %v", err)
	}

	selected, err := registry.FindArtifactVersion(workDir, "sig", "v1")
	if err != nil {
		t.Fatalf("find selected record: %v", err)
	}
	_, err = VerifySelectedArtifactProvenance(workDir, selected)
	if err == nil {
		t.Fatalf("expected signature tamper to fail verification")
	}
	if !strings.Contains(err.Error(), "history verification failed") {
		t.Fatalf("unexpected error: %v", err)
	}
}
