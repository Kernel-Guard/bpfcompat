package runtime

import (
	"fmt"
	"sort"
	"strings"

	"github.com/erenari/bpfcompat/internal/registry"
)

func normalizePolicy(p SelectionPolicy) SelectionPolicy {
	p.DenyClassificationCodes = normalizeStringList(p.DenyClassificationCodes)
	p.AllowClassificationCodes = normalizeStringList(p.AllowClassificationCodes)
	return p
}

func PolicyHasConstraints(p SelectionPolicy) bool {
	p = normalizePolicy(p)
	return p.RequireSummaryPass ||
		p.MinRequiredPassed > 0 ||
		p.MaxRequiredFailed != nil ||
		p.RequireKernelBTF ||
		p.RequireAttachSupport ||
		p.RequireRingbufSupport ||
		p.RequirePerfEventArraySupport ||
		len(p.DenyClassificationCodes) > 0 ||
		len(p.AllowClassificationCodes) > 0
}

func evaluatePolicy(record registry.ArtifactVersionRecord, host HostCapabilities, policy SelectionPolicy) (bool, []string) {
	policy = normalizePolicy(policy)
	var violations []string

	if policy.RequireSummaryPass && strings.TrimSpace(record.SummaryStatus) != "pass" {
		violations = append(violations, "summary status is not pass")
	}
	if policy.MinRequiredPassed > 0 && record.RequiredPassed < policy.MinRequiredPassed {
		violations = append(violations, fmt.Sprintf("required_passed=%d < min_required_passed=%d", record.RequiredPassed, policy.MinRequiredPassed))
	}
	if policy.MaxRequiredFailed != nil && record.RequiredFailed > *policy.MaxRequiredFailed {
		violations = append(violations, fmt.Sprintf("required_failed=%d > max_required_failed=%d", record.RequiredFailed, *policy.MaxRequiredFailed))
	}
	if policy.RequireKernelBTF && !host.BTF.KernelAvailable {
		violations = append(violations, "host kernel BTF is unavailable")
	}

	classifications := normalizeStringList(record.ClassificationCode)
	if policy.RequireAttachSupport && containsString(classifications, "UNSUPPORTED_ATTACH_TYPE") {
		violations = append(violations, "history contains UNSUPPORTED_ATTACH_TYPE")
	}
	if policy.RequireRingbufSupport && containsString(classifications, "UNSUPPORTED_MAP_TYPE") {
		violations = append(violations, "history contains UNSUPPORTED_MAP_TYPE (ringbuf requirement unsafe)")
	}
	if policy.RequirePerfEventArraySupport && containsString(classifications, "UNSUPPORTED_MAP_TYPE") {
		violations = append(violations, "history contains UNSUPPORTED_MAP_TYPE (perf_event_array requirement unsafe)")
	}

	for _, denied := range policy.DenyClassificationCodes {
		if containsString(classifications, denied) {
			violations = append(violations, "history contains denied classification code "+denied)
		}
	}
	if len(policy.AllowClassificationCodes) > 0 {
		allowSet := make(map[string]struct{}, len(policy.AllowClassificationCodes))
		for _, code := range policy.AllowClassificationCodes {
			allowSet[code] = struct{}{}
		}
		for _, code := range classifications {
			if _, ok := allowSet[code]; !ok {
				violations = append(violations, "history contains classification not in allow list "+code)
			}
		}
	}

	sort.Strings(violations)
	return len(violations) == 0, violations
}

func normalizeStringList(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		v := strings.TrimSpace(strings.ToUpper(value))
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}
