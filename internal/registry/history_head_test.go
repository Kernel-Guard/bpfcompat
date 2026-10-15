package registry

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func headTestRecord(version string) ArtifactVersionRecord {
	return ArtifactVersionRecord{
		RunID:           "run-" + version,
		RunStartedAt:    "2026-10-15T00:00:00Z",
		CreatedAt:       "2026-10-15T00:00:00Z",
		ArtifactName:    "app",
		ArtifactVersion: version,
		ArtifactSHA256:  "sha-" + version,
		ArtifactPath:    "/srv/app-" + version + ".o",
		MatrixPath:      "/m.yaml",
		SummaryStatus:   "pass",
		JSONReportPath:  "/r.json",
	}
}

// truncatedSignedHistory writes a 3-record signed history, records the hash
// of every record, then deletes the newest record (a rollback).
func truncatedSignedHistory(t *testing.T) (workDir string, hashes []string) {
	t.Helper()
	t.Setenv(artifactSigningModeEnv, "")
	t.Setenv(artifactTrustedKeysEnv, "")
	t.Setenv(artifactTrustedKeyringPathEnv, "")
	workDir = t.TempDir()
	for _, v := range []string{"v1", "v2", "v3"} {
		if err := PersistArtifactVersion(workDir, headTestRecord(v)); err != nil {
			t.Fatalf("persist %s: %v", v, err)
		}
	}
	full, err := VerifyArtifactVersionHistory(workDir)
	if err != nil {
		t.Fatalf("verify full history: %v", err)
	}
	for i := range full {
		hashes = append(hashes, full[i].RecordSHA256)
	}
	records, head := ArtifactHistoryHead(full)
	if records != 3 || head != hashes[2] {
		t.Fatalf("full history head = (%d, %q), want (3, %q)", records, head, hashes[2])
	}

	indexPath := filepath.Join(workDir, "registry", "artifact_versions.jsonl")
	raw, err := os.ReadFile(indexPath)
	if err != nil {
		t.Fatal(err)
	}
	lines := bytes.Split(bytes.TrimSpace(raw), []byte("\n"))
	if err := os.WriteFile(indexPath, append(bytes.Join(lines[:2], []byte("\n")), '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	return workDir, hashes
}

func TestArtifactHistoryHeadDetectsTruncation(t *testing.T) {
	workDir, hashes := truncatedSignedHistory(t)

	rows, err := VerifyArtifactVersionHistory(workDir)
	if err != nil {
		t.Fatalf("verify truncated history: %v", err)
	}
	// Known limitation (SIGN-3): without a head pin the backward-only chain
	// check still accepts a history whose newest record was deleted.
	for _, row := range rows {
		if !row.Verified {
			t.Fatalf("row %d unexpectedly failed: %v", row.Index, row.Issues)
		}
	}
	records, head := ArtifactHistoryHead(rows)
	if records != 2 || head != hashes[1] {
		t.Fatalf("truncated head = (%d, %q), want (2, %q)", records, head, hashes[1])
	}

	if err := CheckArtifactHistoryHead(rows, hashes[2], 0); err == nil || !strings.Contains(err.Error(), "head") {
		t.Fatalf("expected head mismatch error, got %v", err)
	}
	if err := CheckArtifactHistoryHead(rows, "", 3); err == nil || !strings.Contains(err.Error(), "records") {
		t.Fatalf("expected min-records error, got %v", err)
	}
	if err := CheckArtifactHistoryHead(rows, strings.ToUpper(hashes[1]), 2); err != nil {
		t.Fatalf("correct head and count should pass: %v", err)
	}
	if err := CheckArtifactHistoryHead(rows, "", 0); err != nil {
		t.Fatalf("no expectations should pass: %v", err)
	}
	if err := CheckArtifactHistoryHead(nil, "", 1); err == nil {
		t.Fatalf("expected min-records error for empty history")
	}
}

func TestNormalizeHistoryHeadSHA256(t *testing.T) {
	good := strings.Repeat("ab", 32)
	if got, err := NormalizeHistoryHeadSHA256(" " + strings.ToUpper(good) + " "); err != nil || got != good {
		t.Fatalf("normalize good sha: got %q err %v", got, err)
	}
	for _, bad := range []string{"", "abc", strings.Repeat("g", 64), strings.Repeat("a", 65), "sha256:" + good} {
		if _, err := NormalizeHistoryHeadSHA256(bad); err == nil {
			t.Fatalf("expected error for %q", bad)
		}
	}
	rows := []ArtifactVersionVerification{{RecordSHA256: good, ComputedSHA256: good}}
	if err := CheckArtifactHistoryHead(rows, "not-a-sha", 0); err == nil || !strings.Contains(err.Error(), "sha256") {
		t.Fatalf("expected format error, got %v", err)
	}
}
