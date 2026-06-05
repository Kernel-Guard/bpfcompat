package compare

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/erenari/bpfcompat/pkg/schema"
)

const diffSchemaVersion = "compat_diff.v0.1"

type ReportRef struct {
	Path          string `json:"path"`
	RunID         string `json:"run_id"`
	SummaryStatus string `json:"summary_status"`
}

type DiffSummary struct {
	TotalProfiles       int `json:"total_profiles"`
	ChangedProfiles     int `json:"changed_profiles"`
	ImprovedProfiles    int `json:"improved_profiles"`
	RegressedProfiles   int `json:"regressed_profiles"`
	RequiredRegressions int `json:"required_regressions"`
	BaseRequiredFailed  int `json:"base_required_failed"`
	HeadRequiredFailed  int `json:"head_required_failed"`
}

type ProfileDiff struct {
	ProfileID           string `json:"profile_id"`
	Required            bool   `json:"required"`
	Change              string `json:"change"`
	BaseStatus          string `json:"base_status,omitempty"`
	HeadStatus          string `json:"head_status,omitempty"`
	BaseClassification  string `json:"base_classification,omitempty"`
	HeadClassification  string `json:"head_classification,omitempty"`
	BaseConfidence      string `json:"base_confidence,omitempty"`
	HeadConfidence      string `json:"head_confidence,omitempty"`
	ClassificationDelta string `json:"classification_delta,omitempty"`
}

type ReportDiff struct {
	SchemaVersion string        `json:"schema_version"`
	GeneratedAt   string        `json:"generated_at"`
	Base          ReportRef     `json:"base"`
	Head          ReportRef     `json:"head"`
	Summary       DiffSummary   `json:"summary"`
	Profiles      []ProfileDiff `json:"profiles"`
}

func Build(base, head schema.ReportV01, basePath, headPath string, now time.Time) ReportDiff {
	profiles := makeDiffProfiles(base, head)
	summary := summarizeDiff(base, head, profiles)

	return ReportDiff{
		SchemaVersion: diffSchemaVersion,
		GeneratedAt:   now.UTC().Format(time.RFC3339),
		Base: ReportRef{
			Path:          basePath,
			RunID:         base.Run.ID,
			SummaryStatus: base.Summary.Status,
		},
		Head: ReportRef{
			Path:          headPath,
			RunID:         head.Run.ID,
			SummaryStatus: head.Summary.Status,
		},
		Summary:  summary,
		Profiles: profiles,
	}
}

func makeDiffProfiles(base, head schema.ReportV01) []ProfileDiff {
	baseByProfile := make(map[string]schema.Target, len(base.Targets))
	headByProfile := make(map[string]schema.Target, len(head.Targets))
	profileIDs := make(map[string]struct{}, len(base.Targets)+len(head.Targets))

	for _, target := range base.Targets {
		baseByProfile[target.ProfileID] = target
		profileIDs[target.ProfileID] = struct{}{}
	}
	for _, target := range head.Targets {
		headByProfile[target.ProfileID] = target
		profileIDs[target.ProfileID] = struct{}{}
	}

	ids := make([]string, 0, len(profileIDs))
	for id := range profileIDs {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	profiles := make([]ProfileDiff, 0, len(ids))
	for _, id := range ids {
		baseTarget, hasBase := baseByProfile[id]
		headTarget, hasHead := headByProfile[id]

		diff := ProfileDiff{
			ProfileID: id,
			Required:  pickRequired(hasBase, baseTarget, hasHead, headTarget),
		}

		if hasBase {
			diff.BaseStatus = baseTarget.Status
			diff.BaseClassification = baseTarget.ClassificationCode
			diff.BaseConfidence = baseTarget.ClassificationConfidence
		}
		if hasHead {
			diff.HeadStatus = headTarget.Status
			diff.HeadClassification = headTarget.ClassificationCode
			diff.HeadConfidence = headTarget.ClassificationConfidence
		}

		diff.Change = inferChange(hasBase, baseTarget, hasHead, headTarget)
		diff.ClassificationDelta = classificationDelta(baseTarget.ClassificationCode, headTarget.ClassificationCode)
		profiles = append(profiles, diff)
	}
	return profiles
}

func summarizeDiff(base, head schema.ReportV01, profiles []ProfileDiff) DiffSummary {
	summary := DiffSummary{
		TotalProfiles: len(profiles),
	}
	for _, diff := range profiles {
		if diff.Change != "unchanged" {
			summary.ChangedProfiles++
		}
		if diff.Change == "improved" {
			summary.ImprovedProfiles++
		}
		if diff.Change == "regressed" {
			summary.RegressedProfiles++
			if diff.Required {
				summary.RequiredRegressions++
			}
		}
	}

	for _, target := range base.Targets {
		if target.Required && target.Status != "pass" {
			summary.BaseRequiredFailed++
		}
	}
	for _, target := range head.Targets {
		if target.Required && target.Status != "pass" {
			summary.HeadRequiredFailed++
		}
	}
	return summary
}

func pickRequired(hasBase bool, base schema.Target, hasHead bool, head schema.Target) bool {
	switch {
	case hasHead:
		return head.Required
	case hasBase:
		return base.Required
	default:
		return false
	}
}

func inferChange(hasBase bool, base schema.Target, hasHead bool, head schema.Target) string {
	switch {
	case !hasBase && hasHead:
		return "added"
	case hasBase && !hasHead:
		return "removed"
	case !hasBase && !hasHead:
		return "unknown"
	}

	if base.Status == head.Status {
		if strings.TrimSpace(base.ClassificationCode) == strings.TrimSpace(head.ClassificationCode) {
			return "unchanged"
		}
		return "classification_changed"
	}

	baseScore := statusScore(base.Status)
	headScore := statusScore(head.Status)
	switch {
	case headScore > baseScore:
		return "improved"
	case headScore < baseScore:
		return "regressed"
	default:
		return "changed"
	}
}

func statusScore(status string) int {
	switch status {
	case "pass":
		return 3
	case "fail":
		return 2
	case "infra_error":
		return 1
	default:
		return 0
	}
}

func classificationDelta(base, head string) string {
	base = strings.TrimSpace(base)
	head = strings.TrimSpace(head)
	switch {
	case base == "" && head == "":
		return ""
	case base == head:
		return "unchanged"
	case base == "":
		return fmt.Sprintf("new:%s", head)
	case head == "":
		return fmt.Sprintf("cleared:%s", base)
	default:
		return fmt.Sprintf("%s->%s", base, head)
	}
}
