package runtime

import (
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/erenari/bpfcompat/internal/registry"
)

const selectionSchemaVersion = "runtime_selection.v0.1"

func SelectBestArtifactVersion(records []registry.ArtifactVersionRecord, host HostCapabilities, req SelectionRequest) (SelectionResult, error) {
	artifactName := strings.TrimSpace(req.ArtifactName)
	if artifactName == "" {
		return SelectionResult{}, errors.New("artifact name is required")
	}

	filtered := make([]registry.ArtifactVersionRecord, 0, len(records))
	for _, record := range records {
		if record.ArtifactName != artifactName {
			continue
		}
		if req.RequestedVersion != "" && record.ArtifactVersion != req.RequestedVersion {
			continue
		}
		filtered = append(filtered, record)
	}
	if len(filtered) == 0 {
		return SelectionResult{}, fmt.Errorf("no artifact versions found for %q", artifactName)
	}

	hostHint := HostProfileHint(host)
	targetProfile := strings.TrimSpace(req.TargetProfileID)
	policy := normalizePolicy(req.Policy)

	scored := make([]SelectionCandidate, 0, len(filtered))
	accepted := make([]SelectionCandidate, 0, len(filtered))
	for _, record := range filtered {
		score, reasons := scoreRecord(record, hostHint, targetProfile, host)
		policyAccepted, policyViolations := evaluatePolicy(record, host, policy)
		candidate := SelectionCandidate{
			ArtifactVersion:  record.ArtifactVersion,
			ArtifactVariant:  record.ArtifactVariant,
			RunID:            record.RunID,
			SummaryStatus:    record.SummaryStatus,
			Score:            score,
			Reasons:          reasons,
			PolicyAccepted:   policyAccepted,
			PolicyViolations: policyViolations,
		}
		scored = append(scored, candidate)
		if policyAccepted {
			accepted = append(accepted, candidate)
		}
	}

	sort.SliceStable(scored, func(i, j int) bool {
		if scored[i].Score == scored[j].Score {
			return scored[i].RunID > scored[j].RunID
		}
		return scored[i].Score > scored[j].Score
	})

	sort.SliceStable(accepted, func(i, j int) bool {
		if accepted[i].Score == accepted[j].Score {
			return accepted[i].RunID > accepted[j].RunID
		}
		return accepted[i].Score > accepted[j].Score
	})

	if len(accepted) == 0 {
		var samples []string
		for i := range scored {
			if i >= 3 {
				break
			}
			if len(scored[i].PolicyViolations) == 0 {
				continue
			}
			samples = append(samples, fmt.Sprintf("%s@%s rejected: %s",
				artifactName,
				scored[i].ArtifactVersion,
				strings.Join(scored[i].PolicyViolations, "; "),
			))
		}
		if len(samples) == 0 {
			return SelectionResult{}, fmt.Errorf("no candidate accepted by policy for artifact %q", artifactName)
		}
		return SelectionResult{}, fmt.Errorf("no candidate accepted by policy for artifact %q (%s)", artifactName, strings.Join(samples, " | "))
	}

	selected := accepted[0]
	limit := req.Limit
	if limit <= 0 || limit > len(accepted) {
		limit = len(accepted)
	}
	var policyOut *SelectionPolicy
	if PolicyHasConstraints(policy) {
		policyCopy := policy
		policyOut = &policyCopy
	}

	return SelectionResult{
		SchemaVersion:      selectionSchemaVersion,
		ArtifactName:       artifactName,
		RequestedVersion:   req.RequestedVersion,
		TargetProfileID:    targetProfile,
		HostProfileHint:    hostHint,
		Policy:             policyOut,
		Selected:           selected,
		CandidatesReviewed: len(scored),
		CandidatesAccepted: len(accepted),
		Candidates:         accepted[:limit],
	}, nil
}

func scoreRecord(record registry.ArtifactVersionRecord, hostHint, targetProfile string, host HostCapabilities) (int, []SelectionReason) {
	score := 0
	reasons := make([]SelectionReason, 0, 8)

	if record.SummaryStatus == "pass" {
		score += 20
		reasons = append(reasons, SelectionReason{Type: "summary_pass", Weight: 20, Details: "run summary status is pass"})
	}

	if record.RequiredPassed > 0 {
		weight := 10 * record.RequiredPassed
		score += weight
		reasons = append(reasons, SelectionReason{Type: "required_passed", Weight: weight, Details: fmt.Sprintf("required_passed=%d", record.RequiredPassed)})
	}
	if record.RequiredFailed > 0 {
		weight := -50 * record.RequiredFailed
		score += weight
		reasons = append(reasons, SelectionReason{Type: "required_failed", Weight: weight, Details: fmt.Sprintf("required_failed=%d", record.RequiredFailed)})
	}

	bestProfileWeight, detail := profileAlignmentWeight(record, hostHint, targetProfile)
	if bestProfileWeight != 0 {
		score += bestProfileWeight
		reasons = append(reasons, SelectionReason{Type: "profile_alignment", Weight: bestProfileWeight, Details: detail})
	}

	if !host.BTF.KernelAvailable && containsString(record.ClassificationCode, "MISSING_BTF") {
		score -= 40
		reasons = append(reasons, SelectionReason{Type: "btf_risk", Weight: -40, Details: "host lacks kernel BTF and version history includes MISSING_BTF"})
	}

	if ringbufLikelyUnsupported(host) && containsString(record.ClassificationCode, "UNSUPPORTED_MAP_TYPE") {
		score -= 20
		reasons = append(reasons, SelectionReason{Type: "ringbuf_risk", Weight: -20, Details: "host may not support ringbuf and history includes UNSUPPORTED_MAP_TYPE"})
	}

	return score, reasons
}

func profileAlignmentWeight(record registry.ArtifactVersionRecord, hostHint, targetProfile string) (int, string) {
	if targetProfile != "" {
		if containsString(record.SupportedProfiles, targetProfile) {
			return 180, "explicit target profile is supported"
		}
		if containsString(record.FailedProfiles, targetProfile) {
			return -260, "explicit target profile previously failed"
		}
		return -40, "explicit target profile not observed in history"
	}

	if hostHint == "" {
		return 0, ""
	}
	hostDistro, hostVersion, hostKernel := parseProfileID(hostHint)
	bestWeight := 0
	bestReason := ""

	for _, profileID := range record.SupportedProfiles {
		weight, reason := similarityWeight(profileID, hostDistro, hostVersion, hostKernel, true)
		if weight > bestWeight {
			bestWeight = weight
			bestReason = reason
		}
	}
	for _, profileID := range record.FailedProfiles {
		weight, reason := similarityWeight(profileID, hostDistro, hostVersion, hostKernel, false)
		if weight < bestWeight || bestWeight == 0 && weight < 0 {
			bestWeight = weight
			bestReason = reason
		}
	}
	return bestWeight, bestReason
}

func similarityWeight(profileID, hostDistro, hostVersion, hostKernel string, supported bool) (int, string) {
	pDistro, pVersion, pKernel := parseProfileID(profileID)
	if pDistro == "" {
		return 0, ""
	}

	positive := map[string]int{
		"exact":         140,
		"distro_kernel": 95,
		"distro_ver":    80,
		"kernel":        55,
	}
	negative := map[string]int{
		"exact":         -220,
		"distro_kernel": -170,
		"distro_ver":    -140,
		"kernel":        -90,
	}
	weights := positive
	if !supported {
		weights = negative
	}

	switch {
	case pDistro == hostDistro && pVersion == hostVersion && pKernel == hostKernel:
		return weights["exact"], profileID + " exact match"
	case pDistro == hostDistro && pKernel == hostKernel:
		return weights["distro_kernel"], profileID + " same distro+kernel"
	case pDistro == hostDistro && pVersion == hostVersion:
		return weights["distro_ver"], profileID + " same distro+version"
	case pKernel == hostKernel:
		return weights["kernel"], profileID + " same kernel family"
	default:
		return 0, ""
	}
}

func parseProfileID(profileID string) (distro string, version string, kernel string) {
	parts := strings.Split(strings.TrimSpace(profileID), "-")
	if len(parts) < 3 {
		return "", "", ""
	}
	distro = strings.Join(parts[:len(parts)-2], "-")
	version = parts[len(parts)-2]
	kernel = parts[len(parts)-1]
	return distro, version, kernel
}

func containsString(values []string, needle string) bool {
	needle = strings.TrimSpace(needle)
	for _, value := range values {
		if strings.TrimSpace(value) == needle {
			return true
		}
	}
	return false
}

func ringbufLikelyUnsupported(host HostCapabilities) bool {
	if host.Features.MapRingbuf.Restricted {
		return false
	}
	if host.Features.MapRingbuf.Status == SupportUnsupported {
		return true
	}
	if host.Features.MapRingbuf.Status == SupportSupported {
		return false
	}
	kMajor, kMinor, ok := parseKernelVersion(host.Kernel.Release)
	if !ok {
		return false
	}
	if kMajor < 5 {
		return true
	}
	return kMajor == 5 && kMinor < 8
}

func FindSelectedRecord(records []registry.ArtifactVersionRecord, artifactName, artifactVersion string) (registry.ArtifactVersionRecord, error) {
	for _, record := range records {
		if record.ArtifactName != artifactName {
			continue
		}
		if record.ArtifactVersion != artifactVersion {
			continue
		}
		return record, nil
	}
	return registry.ArtifactVersionRecord{}, fmt.Errorf("artifact %s version %s not found", artifactName, artifactVersion)
}

func NewestRecord(records []registry.ArtifactVersionRecord, artifactName string) (registry.ArtifactVersionRecord, error) {
	best := registry.ArtifactVersionRecord{}
	found := false
	for _, record := range records {
		if record.ArtifactName != artifactName {
			continue
		}
		if !found {
			best = record
			found = true
			continue
		}
		if record.CreatedAt == "" {
			continue
		}
		if newerCreatedAt(record.CreatedAt, best.CreatedAt) {
			best = record
		}
	}
	if !found {
		return registry.ArtifactVersionRecord{}, fmt.Errorf("no records found for artifact %s", artifactName)
	}
	return best, nil
}

func newerCreatedAt(lhs, rhs string) bool {
	if lhs == "" && rhs == "" {
		return false
	}
	if lhs != "" && rhs == "" {
		return true
	}
	leftTime, err := time.Parse(time.RFC3339, lhs)
	if err != nil {
		return lhs > rhs
	}
	rightTime, err := time.Parse(time.RFC3339, rhs)
	if err != nil {
		return lhs > rhs
	}
	return leftTime.After(rightTime)
}

func KernelMajorMinor(release string) string {
	major, minor, ok := parseKernelVersion(release)
	if !ok {
		return ""
	}
	return strconv.Itoa(major) + "." + strconv.Itoa(minor)
}
