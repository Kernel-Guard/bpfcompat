package runtime

import (
	"fmt"
	"strings"

	"github.com/erenari/bpfcompat/internal/registry"
)

const runtimeHistoryVerificationSchemaVersion = "runtime_history_verification.v0.1"

type HistoryVerificationSelected struct {
	ArtifactName    string `json:"artifact_name"`
	ArtifactVersion string `json:"artifact_version"`
	RunID           string `json:"run_id,omitempty"`
	Index           int    `json:"index"`
	Verified        bool   `json:"verified"`
}

type HistoryVerificationResult struct {
	SchemaVersion string                      `json:"schema_version"`
	Records       int                         `json:"records"`
	Failed        int                         `json:"failed"`
	Verified      bool                        `json:"verified"`
	Selected      HistoryVerificationSelected `json:"selected"`
}

func VerifySelectedArtifactProvenance(workDir string, selected registry.ArtifactVersionRecord) (HistoryVerificationResult, error) {
	result := HistoryVerificationResult{
		SchemaVersion: runtimeHistoryVerificationSchemaVersion,
		Selected: HistoryVerificationSelected{
			ArtifactName:    strings.TrimSpace(selected.ArtifactName),
			ArtifactVersion: strings.TrimSpace(selected.ArtifactVersion),
			RunID:           strings.TrimSpace(selected.RunID),
			Index:           -1,
		},
	}

	verification, err := registry.VerifyArtifactVersionHistory(workDir)
	if err != nil {
		return result, fmt.Errorf("verify artifact history: %w", err)
	}
	result.Records = len(verification)
	if len(verification) == 0 {
		return result, fmt.Errorf("no artifact history records found")
	}

	failedSamples := make([]string, 0, 3)
	for _, row := range verification {
		if row.Verified {
			continue
		}
		result.Failed++
		if len(failedSamples) < 3 {
			failedSamples = append(failedSamples, formatVerificationSample(row))
		}
	}

	selectedRow, selectedIndex, findErr := findSelectedVerificationRow(verification, selected)
	if findErr != nil {
		if result.Failed > 0 {
			return result, fmt.Errorf("history verification failed: %d/%d invalid (%s); selected record match failed: %v",
				result.Failed, result.Records, strings.Join(failedSamples, " | "), findErr)
		}
		return result, findErr
	}
	result.Selected.Index = selectedIndex
	result.Selected.Verified = selectedRow.Verified

	if result.Failed > 0 {
		return result, fmt.Errorf("history verification failed: %d/%d invalid (%s)",
			result.Failed, result.Records, strings.Join(failedSamples, " | "))
	}
	if !selectedRow.Verified {
		return result, fmt.Errorf("selected record is not verified: %s", formatVerificationSample(selectedRow))
	}

	result.Verified = true
	return result, nil
}

func findSelectedVerificationRow(
	rows []registry.ArtifactVersionVerification,
	selected registry.ArtifactVersionRecord,
) (registry.ArtifactVersionVerification, int, error) {
	name := strings.TrimSpace(selected.ArtifactName)
	version := strings.TrimSpace(selected.ArtifactVersion)
	runID := strings.TrimSpace(selected.RunID)

	for idx, row := range rows {
		if strings.TrimSpace(row.ArtifactName) != name || strings.TrimSpace(row.ArtifactVersion) != version {
			continue
		}
		if runID != "" && strings.TrimSpace(row.RunID) == runID {
			return row, idx, nil
		}
	}

	matches := make([]int, 0, 2)
	for idx, row := range rows {
		if strings.TrimSpace(row.ArtifactName) == name && strings.TrimSpace(row.ArtifactVersion) == version {
			matches = append(matches, idx)
		}
	}
	if len(matches) == 1 {
		idx := matches[0]
		return rows[idx], idx, nil
	}
	if len(matches) > 1 {
		return registry.ArtifactVersionVerification{}, -1, fmt.Errorf(
			"selected record match is ambiguous for %s@%s (run=%s)",
			name, version, runID,
		)
	}

	return registry.ArtifactVersionVerification{}, -1, fmt.Errorf(
		"selected record %s@%s (run=%s) was not found in history verification output",
		name, version, runID,
	)
}

func formatVerificationSample(row registry.ArtifactVersionVerification) string {
	issues := strings.TrimSpace(strings.Join(row.Issues, "; "))
	if issues == "" {
		issues = "unknown verification issue"
	}
	return fmt.Sprintf(
		"idx=%d %s@%s run=%s issues=%s",
		row.Index,
		strings.TrimSpace(row.ArtifactName),
		strings.TrimSpace(row.ArtifactVersion),
		strings.TrimSpace(row.RunID),
		issues,
	)
}
