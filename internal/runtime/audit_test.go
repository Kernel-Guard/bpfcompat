package runtime

import (
	"encoding/json"
	"os"
	"testing"
)

func TestPersistDecisionTraceAndListDecisionEvents(t *testing.T) {
	workDir := t.TempDir()

	traceA := DecisionTrace{
		Source:           "cli",
		Operation:        "execute",
		ArtifactName:     "execsnoop",
		RequestedVersion: "v1.0.0",
		CreatedAt:        "2026-05-15T17:00:00Z",
		Status:           "success",
		Selection: &SelectionResult{
			ArtifactName: "execsnoop",
			Selected: SelectionCandidate{
				ArtifactVersion: "v1.0.0",
			},
		},
		Fetch: &FetchResult{
			ArtifactName:    "execsnoop",
			ArtifactVersion: "v1.0.0",
		},
		Execution: &ExecuteResult{
			Status: "pass",
		},
	}
	persistedA, err := PersistDecisionTrace(workDir, traceA)
	if err != nil {
		t.Fatalf("persist decision trace A: %v", err)
	}
	if persistedA.DecisionID == "" {
		t.Fatalf("expected decision id for persisted trace A")
	}
	if _, err := os.Stat(persistedA.TracePath); err != nil {
		t.Fatalf("trace file should exist: %v", err)
	}

	var storedA DecisionTrace
	rawA, err := os.ReadFile(persistedA.TracePath)
	if err != nil {
		t.Fatalf("read trace file A: %v", err)
	}
	if err := json.Unmarshal(rawA, &storedA); err != nil {
		t.Fatalf("decode trace file A: %v", err)
	}
	if storedA.SchemaVersion != decisionTraceSchemaVersion {
		t.Fatalf("unexpected trace schema version: got=%q want=%q", storedA.SchemaVersion, decisionTraceSchemaVersion)
	}
	if storedA.DecisionID != persistedA.DecisionID {
		t.Fatalf("trace file decision id mismatch: got=%q want=%q", storedA.DecisionID, persistedA.DecisionID)
	}

	traceB := DecisionTrace{
		Source:           "api",
		Operation:        "fetch",
		ArtifactName:     "execsnoop",
		RequestedVersion: "v1.1.0",
		CreatedAt:        "2026-05-15T17:01:00Z",
		Status:           "success",
		Selection: &SelectionResult{
			ArtifactName: "execsnoop",
			Selected: SelectionCandidate{
				ArtifactVersion: "v1.1.0",
			},
		},
		Fetch: &FetchResult{
			ArtifactName:    "execsnoop",
			ArtifactVersion: "v1.1.0",
		},
	}
	persistedB, err := PersistDecisionTrace(workDir, traceB)
	if err != nil {
		t.Fatalf("persist decision trace B: %v", err)
	}

	events, err := ListDecisionEvents(workDir, 0)
	if err != nil {
		t.Fatalf("list decision events: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("expected 2 decision events, got %d", len(events))
	}
	if events[0].DecisionID != persistedB.DecisionID {
		t.Fatalf("expected newest event first, got decision id %q", events[0].DecisionID)
	}
	if events[1].DecisionID != persistedA.DecisionID {
		t.Fatalf("expected older event second, got decision id %q", events[1].DecisionID)
	}
	if events[0].SelectedVersion != "v1.1.0" {
		t.Fatalf("unexpected selected version on newest event: %q", events[0].SelectedVersion)
	}
	if events[0].TracePath != persistedB.TracePath {
		t.Fatalf("trace path mismatch on newest event: got=%q want=%q", events[0].TracePath, persistedB.TracePath)
	}

	limited, err := ListDecisionEvents(workDir, 1)
	if err != nil {
		t.Fatalf("list decision events with limit: %v", err)
	}
	if len(limited) != 1 {
		t.Fatalf("expected 1 event with limit, got %d", len(limited))
	}
}

func TestPersistDecisionTraceValidation(t *testing.T) {
	if _, err := PersistDecisionTrace("", DecisionTrace{Operation: "select"}); err == nil {
		t.Fatalf("expected error for empty workdir")
	}
	if _, err := PersistDecisionTrace(t.TempDir(), DecisionTrace{}); err == nil {
		t.Fatalf("expected error for empty operation")
	}
}

func TestListDecisionEventsMissingFile(t *testing.T) {
	events, err := ListDecisionEvents(t.TempDir(), 0)
	if err != nil {
		t.Fatalf("list decision events on empty workdir: %v", err)
	}
	if len(events) != 0 {
		t.Fatalf("expected zero events for missing decision stream, got %d", len(events))
	}
}
