package agent

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/erenari/bpfcompat/internal/registry"
	"github.com/erenari/bpfcompat/internal/runtime"
)

const DecisionSchemaVersion = "agent_decision.v0.1"

type DecisionRequest struct {
	Tenant                 string                   `json:"tenant,omitempty"`
	Project                string                   `json:"project,omitempty"`
	AgentID                string                   `json:"agent_id,omitempty"`
	ArtifactName           string                   `json:"artifact_name"`
	Version                string                   `json:"version,omitempty"`
	TargetProfile          string                   `json:"target_profile,omitempty"`
	Limit                  int                      `json:"limit,omitempty"`
	RequireVerifiedHistory *bool                    `json:"require_verified_history,omitempty"`
	Policy                 runtime.SelectionPolicy  `json:"policy,omitempty"`
	HostProbe              runtime.HostCapabilities `json:"host_probe"`
}

type SelectedArtifact struct {
	Name              string   `json:"name"`
	Version           string   `json:"version"`
	Variant           string   `json:"variant,omitempty"`
	RunID             string   `json:"run_id,omitempty"`
	SHA256            string   `json:"sha256"`
	ArtifactURI       string   `json:"artifact_uri,omitempty"`
	DownloadURL       string   `json:"download_url,omitempty"`
	ManifestPath      string   `json:"manifest_path,omitempty"`
	SummaryStatus     string   `json:"summary_status"`
	RequiredPassed    int      `json:"required_passed"`
	RequiredFailed    int      `json:"required_failed"`
	SupportedProfiles []string `json:"supported_profiles,omitempty"`
	FailedProfiles    []string `json:"failed_profiles,omitempty"`
}

type DecisionResult struct {
	SchemaVersion       string                             `json:"schema_version"`
	DecisionID          string                             `json:"decision_id"`
	CreatedAt           string                             `json:"created_at"`
	Tenant              string                             `json:"tenant,omitempty"`
	Project             string                             `json:"project,omitempty"`
	AgentID             string                             `json:"agent_id,omitempty"`
	ArtifactName        string                             `json:"artifact_name"`
	RequestedVersion    string                             `json:"requested_version,omitempty"`
	TargetProfile       string                             `json:"target_profile,omitempty"`
	HostProfileHint     string                             `json:"host_profile_hint,omitempty"`
	Policy              *runtime.SelectionPolicy           `json:"policy,omitempty"`
	Selection           runtime.SelectionResult            `json:"selection"`
	SelectedArtifact    SelectedArtifact                   `json:"selected_artifact"`
	HistoryVerification *runtime.HistoryVerificationResult `json:"history_verification,omitempty"`
	ApprovalRequired    bool                               `json:"approval_required"`
	LoadApproved        bool                               `json:"load_approved"`
	Warnings            []string                           `json:"warnings,omitempty"`
}

func BuildDecision(workDir string, records []registry.ArtifactVersionRecord, req DecisionRequest) (DecisionResult, registry.ArtifactVersionRecord, error) {
	artifactName := strings.TrimSpace(req.ArtifactName)
	if artifactName == "" {
		return DecisionResult{}, registry.ArtifactVersionRecord{}, fmt.Errorf("artifact_name is required")
	}
	if strings.TrimSpace(req.HostProbe.SchemaVersion) == "" {
		return DecisionResult{}, registry.ArtifactVersionRecord{}, fmt.Errorf("host_probe is required")
	}

	limit := req.Limit
	if limit <= 0 {
		limit = 5
	}
	selection, err := runtime.SelectBestArtifactVersion(records, req.HostProbe, runtime.SelectionRequest{
		ArtifactName:     artifactName,
		RequestedVersion: strings.TrimSpace(req.Version),
		TargetProfileID:  strings.TrimSpace(req.TargetProfile),
		Limit:            limit,
		Policy:           req.Policy,
	})
	if err != nil {
		return DecisionResult{}, registry.ArtifactVersionRecord{}, err
	}
	selectedRecord, err := runtime.FindSelectedRecord(records, selection.ArtifactName, selection.Selected.ArtifactVersion)
	if err != nil {
		return DecisionResult{}, registry.ArtifactVersionRecord{}, fmt.Errorf("resolve selected record: %w", err)
	}

	var historyVerification *runtime.HistoryVerificationResult
	if requireVerifiedHistory(req) {
		verification, err := runtime.VerifySelectedArtifactProvenance(workDir, selectedRecord)
		if err != nil {
			return DecisionResult{}, registry.ArtifactVersionRecord{}, fmt.Errorf("verify selected artifact provenance: %w", err)
		}
		historyVerification = &verification
	}

	decisionID, err := newDecisionID()
	if err != nil {
		return DecisionResult{}, registry.ArtifactVersionRecord{}, fmt.Errorf("generate agent decision id: %w", err)
	}
	var policyOut *runtime.SelectionPolicy
	if runtime.PolicyHasConstraints(req.Policy) {
		policyCopy := req.Policy
		policyOut = &policyCopy
	}

	result := DecisionResult{
		SchemaVersion:       DecisionSchemaVersion,
		DecisionID:          decisionID,
		CreatedAt:           time.Now().UTC().Format(time.RFC3339),
		Tenant:              strings.TrimSpace(req.Tenant),
		Project:             strings.TrimSpace(req.Project),
		AgentID:             strings.TrimSpace(req.AgentID),
		ArtifactName:        artifactName,
		RequestedVersion:    strings.TrimSpace(req.Version),
		TargetProfile:       strings.TrimSpace(req.TargetProfile),
		HostProfileHint:     runtime.HostProfileHint(req.HostProbe),
		Policy:              policyOut,
		Selection:           selection,
		SelectedArtifact:    SelectedArtifactFromRecord(selectedRecord, ""),
		HistoryVerification: historyVerification,
		ApprovalRequired:    true,
		LoadApproved:        false,
	}
	return result, selectedRecord, nil
}

func SelectedArtifactFromRecord(record registry.ArtifactVersionRecord, downloadURL string) SelectedArtifact {
	return SelectedArtifact{
		Name:              strings.TrimSpace(record.ArtifactName),
		Version:           strings.TrimSpace(record.ArtifactVersion),
		Variant:           strings.TrimSpace(record.ArtifactVariant),
		RunID:             strings.TrimSpace(record.RunID),
		SHA256:            strings.TrimSpace(record.ArtifactSHA256),
		ArtifactURI:       strings.TrimSpace(record.ArtifactURI),
		DownloadURL:       strings.TrimSpace(downloadURL),
		ManifestPath:      strings.TrimSpace(record.ManifestPath),
		SummaryStatus:     strings.TrimSpace(record.SummaryStatus),
		RequiredPassed:    record.RequiredPassed,
		RequiredFailed:    record.RequiredFailed,
		SupportedProfiles: append([]string(nil), record.SupportedProfiles...),
		FailedProfiles:    append([]string(nil), record.FailedProfiles...),
	}
}

func requireVerifiedHistory(req DecisionRequest) bool {
	if req.RequireVerifiedHistory == nil {
		return true
	}
	return *req.RequireVerifiedHistory
}

func newDecisionID() (string, error) {
	buf := make([]byte, 3)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return time.Now().UTC().Format("20060102T150405Z") + "-" + hex.EncodeToString(buf), nil
}
