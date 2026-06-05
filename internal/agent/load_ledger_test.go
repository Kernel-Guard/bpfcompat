package agent

import "testing"

func TestLoadLedgerTracksPreviousSuccessfulLoad(t *testing.T) {
	workDir := t.TempDir()
	first := LoadLedgerEntry{
		Operation:       "load",
		Status:          "pass",
		ArtifactName:    "aegis",
		SelectedVersion: "v1",
		SelectedSHA256:  "sha-v1",
		ArtifactPath:    "/var/lib/bpfcompat-agent/selected/aegis-v1.o",
	}
	if _, err := AppendLoadLedgerEntry(workDir, first); err != nil {
		t.Fatalf("append first ledger entry: %v", err)
	}

	previous, ok, err := LastSuccessfulLoad(workDir, "aegis")
	if err != nil {
		t.Fatalf("last successful load: %v", err)
	}
	if !ok {
		t.Fatalf("expected previous load")
	}
	if previous.SelectedVersion != "v1" {
		t.Fatalf("unexpected previous version: %s", previous.SelectedVersion)
	}

	second := LoadLedgerEntry{
		Operation:                  "load",
		Status:                     "pass",
		ArtifactName:               "aegis",
		SelectedVersion:            "v2",
		SelectedSHA256:             "sha-v2",
		PreviousLoadedVersion:      previous.SelectedVersion,
		PreviousLoadedSHA256:       previous.SelectedSHA256,
		PreviousLoadedArtifactPath: previous.ArtifactPath,
	}
	if _, err := AppendLoadLedgerEntry(workDir, second); err != nil {
		t.Fatalf("append second ledger entry: %v", err)
	}

	entries, err := ListLoadLedgerEntries(workDir, "aegis", 2)
	if err != nil {
		t.Fatalf("list ledger: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(entries))
	}
	if entries[0].SelectedVersion != "v2" || entries[1].SelectedVersion != "v1" {
		t.Fatalf("expected newest first, got %+v", entries)
	}
}
