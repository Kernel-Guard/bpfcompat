package registry

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// BenchmarkVerifyArtifactVersionHistory measures the cost of the signed
// hash-chain verification across N records. Cost is roughly linear in N
// (each record: canonical hash + signature verify + prev-pointer check),
// so we benchmark at three sizes that bracket the realistic operating
// envelope:
//
//	100      — a small project, weekly publish cadence over ~2 years
//	1000     — an active artifact, several publishes per day
//	10000    — long tail of a busy multi-team registry
//
// If any of these regress by more than ~2x over a release we have a
// real problem: VerifyArtifactVersionHistory runs on every fetch with
// require_verified_history=true (which is the production default).
func BenchmarkVerifyArtifactVersionHistory(b *testing.B) {
	sizes := []int{100, 1000, 10000}
	for _, n := range sizes {
		n := n
		b.Run(fmt.Sprintf("records=%d", n), func(b *testing.B) {
			workDir := b.TempDir()
			if err := seedHistoryForBench(workDir, n); err != nil {
				b.Fatalf("seed history: %v", err)
			}
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				verification, err := VerifyArtifactVersionHistory(workDir)
				if err != nil {
					b.Fatalf("verify: %v", err)
				}
				if len(verification) != n {
					b.Fatalf("expected %d records verified, got %d", n, len(verification))
				}
			}
		})
	}
}

// seedHistoryForBench writes n signed records into workDir's local
// registry. Done via PersistArtifactVersion so the chain pointers and
// signatures match what production would produce, otherwise the
// benchmark would measure happy-path verify of empty records.
func seedHistoryForBench(workDir string, n int) error {
	for i := 0; i < n; i++ {
		// Pad the version label so artifact_versions.jsonl entries are
		// roughly the size we'd see in production (~700 bytes per row
		// once provenance metadata is appended).
		name := fmt.Sprintf("bench-artifact-%04d", i%16)
		version := fmt.Sprintf("v0.%d.%d-%s", i/100, i%100, strings.Repeat("x", 24))
		rec := ArtifactVersionRecord{
			RunID:           fmt.Sprintf("run-%05d", i),
			RunStartedAt:    "2026-01-01T00:00:00Z",
			CreatedAt:       "2026-01-01T00:00:01Z",
			ArtifactName:    name,
			ArtifactVersion: version,
			ArtifactPath:    filepath.Join(workDir, "artifacts", name, version, "blob.bpf.o"),
			ArtifactSHA256:  "deadbeef",
			MatrixPath:      "matrices/mvp.yaml",
			MatrixName:      "mvp",
			SummaryStatus:   "pass",
			RequiredPassed:  4,
			TotalProfiles:   4,
			JSONReportPath:  filepath.Join(workDir, "reports", fmt.Sprintf("%05d.json", i)),
		}
		if err := os.MkdirAll(filepath.Dir(rec.ArtifactPath), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(rec.ArtifactPath, []byte("elf-placeholder"), 0o644); err != nil {
			return err
		}
		if err := PersistArtifactVersion(workDir, rec); err != nil {
			return err
		}
	}
	return nil
}
