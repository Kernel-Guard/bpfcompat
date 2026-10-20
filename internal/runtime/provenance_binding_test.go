package runtime

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kernel-guard/bpfcompat/internal/artifact"
	"github.com/kernel-guard/bpfcompat/internal/registry"
)

func persistBindingRecord(t *testing.T, workDir string, rec registry.ArtifactVersionRecord) registry.ArtifactVersionRecord {
	t.Helper()
	if err := registry.PersistArtifactVersion(workDir, rec); err != nil {
		t.Fatalf("persist record: %v", err)
	}
	selected, err := registry.FindArtifactVersion(workDir, rec.ArtifactName, rec.ArtifactVersion)
	if err != nil {
		t.Fatalf("find selected record: %v", err)
	}
	return selected
}

func bindingBaseRecord() registry.ArtifactVersionRecord {
	return registry.ArtifactVersionRecord{
		RunID:             "run-bind-1",
		RunStartedAt:      "2026-10-01T00:00:00Z",
		CreatedAt:         "2026-10-01T00:00:01Z",
		ArtifactName:      "bind",
		ArtifactVersion:   "v1",
		ArtifactPath:      "/tmp/bind-v1.bpf.o",
		ArtifactSHA256:    strings.Repeat("a", 64),
		MatrixPath:        "/tmp/mvp.yaml",
		SummaryStatus:     "pass",
		RequiredPassed:    1,
		TotalProfiles:     1,
		SupportedProfiles: []string{"ubuntu-22.04"},
		JSONReportPath:    "/tmp/bind-v1.json",
	}
}

// A selected record that shares name/version/run_id with a verified history
// row but differs in any signed field must not be reported as verified: the
// caller would otherwise act on (fetch/execute) unsigned values.
func TestVerifySelectedArtifactProvenanceRejectsSelectedRecordDivergingFromVerifiedRow(t *testing.T) {
	cases := map[string]func(*registry.ArtifactVersionRecord){
		"artifact_sha256":    func(r *registry.ArtifactVersionRecord) { r.ArtifactSHA256 = strings.Repeat("b", 64) },
		"artifact_path":      func(r *registry.ArtifactVersionRecord) { r.ArtifactPath = "/tmp/evil.bpf.o" },
		"artifact_uri":       func(r *registry.ArtifactVersionRecord) { r.ArtifactURI = "https://evil.example/x.bpf.o" },
		"summary_status":     func(r *registry.ArtifactVersionRecord) { r.SummaryStatus = "fail" },
		"required_failed":    func(r *registry.ArtifactVersionRecord) { r.RequiredFailed = 3 },
		"supported_profiles": func(r *registry.ArtifactVersionRecord) { r.SupportedProfiles = []string{"rhel-8"} },
		"artifact_variant":   func(r *registry.ArtifactVersionRecord) { r.ArtifactVariant = "core" },
		"record_sha256":      func(r *registry.ArtifactVersionRecord) { r.RecordSHA256 = strings.Repeat("c", 64) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			workDir := t.TempDir()
			selected := persistBindingRecord(t, workDir, bindingBaseRecord())
			if _, err := VerifySelectedArtifactProvenance(workDir, selected); err != nil {
				t.Fatalf("unmodified selected record should verify: %v", err)
			}
			mutate(&selected)
			got, err := VerifySelectedArtifactProvenance(workDir, selected)
			if err == nil {
				t.Fatalf("expected verification to fail when selected %s differs from the verified row", name)
			}
			if got.Verified || got.Selected.Verified {
				t.Fatalf("expected verified=false, got result=%+v", got)
			}
			if !strings.Contains(err.Error(), "does not match the verified history record") {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

// Regression for SIGN-2: the consumer selects a record from one read of the
// history (attacker-forged sha/path, invalid signature), the history file is
// swapped back to the genuine signed content before the verification read,
// and the gate must not vouch for the forged selected record.
func TestVerifySelectedArtifactProvenanceRejectsHistorySwapBetweenReads(t *testing.T) {
	t.Setenv("BPFCOMPAT_SIGNING_MODE", "")
	t.Setenv("BPFCOMPAT_TRUSTED_SIGNING_PUBLIC_KEYS", "")
	t.Setenv("BPFCOMPAT_TRUSTED_SIGNING_KEYS_PATH", "")
	workDir := t.TempDir()
	artDir := t.TempDir()
	good := filepath.Join(artDir, "good.bpf.o")
	evil := filepath.Join(artDir, "evil.bpf.o")
	if err := os.WriteFile(good, []byte{0x7f, 'E', 'L', 'F', 1}, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(evil, []byte{0x7f, 'E', 'L', 'F', 2, 'X'}, 0o644); err != nil {
		t.Fatal(err)
	}
	gm, err := artifact.Inspect(good)
	if err != nil {
		t.Fatal(err)
	}
	em, err := artifact.Inspect(evil)
	if err != nil {
		t.Fatal(err)
	}

	rec := registry.ArtifactVersionRecord{
		RunID: "run-1", RunStartedAt: "2026-10-01T00:00:00Z", CreatedAt: "2026-10-01T00:00:00Z",
		ArtifactName: "app", ArtifactVersion: "v1", ArtifactPath: good, ArtifactSHA256: gm.SHA256,
		MatrixPath: "/m.yaml", SummaryStatus: "pass", JSONReportPath: "/r.json",
	}
	if err := registry.PersistArtifactVersion(workDir, rec); err != nil {
		t.Fatal(err)
	}
	idx := filepath.Join(workDir, "registry", "artifact_versions.jsonl")
	genuine, err := os.ReadFile(idx)
	if err != nil {
		t.Fatal(err)
	}

	var forged registry.ArtifactVersionRecord
	if err := json.Unmarshal(genuine, &forged); err != nil {
		t.Fatal(err)
	}
	forged.ArtifactPath = evil
	forged.ArtifactSHA256 = em.SHA256
	line, err := json.Marshal(forged)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(idx, append(line, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}

	records, err := registry.ListArtifactVersions(workDir, "app", 0) // consumer read #1
	if err != nil {
		t.Fatal(err)
	}
	selected, err := FindSelectedRecord(records, "app", "v1")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(idx, genuine, 0o644); err != nil { // swap back before read #2
		t.Fatal(err)
	}

	res, err := VerifySelectedArtifactProvenance(workDir, selected)
	if err == nil || res.Verified {
		t.Fatalf("expected the gate to reject the forged selected record, got verified=%v err=%v", res.Verified, err)
	}
	if !strings.Contains(err.Error(), "does not match the verified history record") {
		t.Fatalf("unexpected error: %v", err)
	}
}
