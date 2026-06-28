package agent

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	LoadLedgerSchemaVersion = "agent_load_ledger.v0.1"
	loadLedgerFileName      = "agent-load-ledger.jsonl"
)

type LoadLedgerEntry struct {
	SchemaVersion              string   `json:"schema_version"`
	EntryID                    string   `json:"entry_id"`
	CreatedAt                  string   `json:"created_at"`
	Operation                  string   `json:"operation"`
	Status                     string   `json:"status"`
	AgentID                    string   `json:"agent_id,omitempty"`
	Tenant                     string   `json:"tenant,omitempty"`
	Project                    string   `json:"project,omitempty"`
	ArtifactName               string   `json:"artifact_name,omitempty"`
	SelectedVersion            string   `json:"selected_version,omitempty"`
	SelectedSHA256             string   `json:"selected_sha256,omitempty"`
	ArtifactPath               string   `json:"artifact_path,omitempty"`
	DecisionID                 string   `json:"decision_id,omitempty"`
	TargetProfile              string   `json:"target_profile,omitempty"`
	HostProfileHint            string   `json:"host_profile_hint,omitempty"`
	LoadApproved               bool     `json:"load_approved"`
	ApprovalPinsRequired       bool     `json:"approval_pins_required,omitempty"`
	ApprovalPinsVerified       bool     `json:"approval_pins_verified,omitempty"`
	ApprovalExpectedDecisionID string   `json:"approval_expected_decision_id,omitempty"`
	ApprovalExpectedSHA256     string   `json:"approval_expected_sha256,omitempty"`
	ManifestIntentRequired     bool     `json:"manifest_intent_required,omitempty"`
	ManifestIntentVerified     bool     `json:"manifest_intent_verified,omitempty"`
	ManifestPath               string   `json:"manifest_path,omitempty"`
	ManifestProgramCount       int      `json:"manifest_program_count,omitempty"`
	PolicyRule                 string   `json:"policy_rule,omitempty"`
	PolicyAction               string   `json:"policy_action,omitempty"`
	PolicyReason               string   `json:"policy_reason,omitempty"`
	ExecutionRunDir            string   `json:"execution_run_dir,omitempty"`
	AuditTracePath             string   `json:"audit_trace_path,omitempty"`
	PreviousLoadedVersion      string   `json:"previous_loaded_version,omitempty"`
	PreviousLoadedSHA256       string   `json:"previous_loaded_sha256,omitempty"`
	PreviousLoadedArtifactPath string   `json:"previous_loaded_artifact_path,omitempty"`
	RollbackHint               string   `json:"rollback_hint,omitempty"`
	Error                      string   `json:"error,omitempty"`
	Pins                       []string `json:"pins,omitempty"`
	Notes                      []string `json:"notes,omitempty"`
}

func NewLoadLedgerEntry() (LoadLedgerEntry, error) {
	id, err := newDecisionID()
	if err != nil {
		return LoadLedgerEntry{}, err
	}
	return LoadLedgerEntry{
		SchemaVersion: LoadLedgerSchemaVersion,
		EntryID:       id,
		CreatedAt:     time.Now().UTC().Format(time.RFC3339),
	}, nil
}

func LoadLedgerPath(workDir string) string {
	cleanWorkDir := strings.TrimSpace(workDir)
	if cleanWorkDir == "" {
		cleanWorkDir = ".bpfcompat"
	}
	return filepath.Join(filepath.Clean(cleanWorkDir), loadLedgerFileName)
}

func AppendLoadLedgerEntry(workDir string, entry LoadLedgerEntry) (string, error) {
	if entry.SchemaVersion == "" {
		entry.SchemaVersion = LoadLedgerSchemaVersion
	}
	if entry.EntryID == "" {
		fresh, err := NewLoadLedgerEntry()
		if err != nil {
			return "", fmt.Errorf("generate load ledger entry id: %w", err)
		}
		entry.EntryID = fresh.EntryID
	}
	if entry.CreatedAt == "" {
		entry.CreatedAt = time.Now().UTC().Format(time.RFC3339)
	}
	path := LoadLedgerPath(workDir)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return "", fmt.Errorf("create load ledger directory: %w", err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return "", fmt.Errorf("open load ledger: %w", err)
	}
	raw, err := json.Marshal(entry)
	if err != nil {
		_ = f.Close()
		return "", fmt.Errorf("encode load ledger entry: %w", err)
	}
	if _, err := f.Write(append(raw, '\n')); err != nil {
		_ = f.Close()
		return "", fmt.Errorf("write load ledger entry: %w", err)
	}
	if err := f.Close(); err != nil {
		return "", fmt.Errorf("close load ledger: %w", err)
	}
	return path, nil
}

func ListLoadLedgerEntries(workDir, artifactName string, limit int) ([]LoadLedgerEntry, error) {
	path := LoadLedgerPath(workDir)
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("open load ledger: %w", err)
	}
	defer f.Close()

	artifactName = strings.TrimSpace(artifactName)
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	var entries []LoadLedgerEntry
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		var entry LoadLedgerEntry
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			return nil, fmt.Errorf("decode load ledger entry: %w", err)
		}
		if artifactName != "" && entry.ArtifactName != artifactName {
			continue
		}
		entries = append(entries, entry)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read load ledger: %w", err)
	}
	reverseEntries(entries)
	if limit > 0 && len(entries) > limit {
		entries = entries[:limit]
	}
	return entries, nil
}

func LastSuccessfulLoad(workDir, artifactName string) (LoadLedgerEntry, bool, error) {
	entries, err := ListLoadLedgerEntries(workDir, artifactName, 0)
	if err != nil {
		return LoadLedgerEntry{}, false, err
	}
	for i := range entries {
		entry := &entries[i]
		if entry.Operation == "load" && (entry.Status == "pass" || entry.Status == "success") {
			return *entry, true, nil
		}
	}
	return LoadLedgerEntry{}, false, nil
}

func reverseEntries(entries []LoadLedgerEntry) {
	for i, j := 0, len(entries)-1; i < j; i, j = i+1, j-1 {
		entries[i], entries[j] = entries[j], entries[i]
	}
}
