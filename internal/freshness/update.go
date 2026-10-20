package freshness

import (
	"github.com/kernel-guard/bpfcompat/pkg/schema"
)

// SkippedTarget is a report target whose observed host kernel was not recorded
// because the target did not establish the environment its profile requested.
type SkippedTarget struct {
	Profile string
	Kernel  string
	Reason  string
}

// UpdateFromReport merges the host kernels observed in a matrix report into
// the baselines: matching profiles get their kernel and recorded date
// refreshed, unknown profiles are appended without a crawler mapping (they
// show up as uncovered until someone adds one). Returns the profile ids that
// were updated and added, and the targets that were skipped.
//
// A target that did not establish its requested environment (wrong kernel
// series or distribution, or an INFRA_ERROR/UNSUPPORTED outcome) is skipped:
// its host kernel is not the profile's kernel, and recording it -- say a
// 6.8 kernel for a 5.15 profile -- would make every later release of the real
// series compare as fresh. Targets without status, verdict or environment
// (older reports) carry nothing to judge by and are still recorded.
func UpdateFromReport(b *Baselines, rep schema.ReportV01) (updated, added []string, skipped []SkippedTarget) {
	recorded := rep.Run.StartedAt
	if len(recorded) > 10 {
		recorded = recorded[:10]
	}

	index := map[string]int{}
	for i, entry := range b.Baselines {
		index[entry.Profile] = i
	}

	for ti := range rep.Targets {
		target := &rep.Targets[ti]
		if target.Host == nil || target.Host.Kernel == "" {
			continue
		}
		if reason := unestablishedReason(target); reason != "" {
			skipped = append(skipped, SkippedTarget{Profile: target.ProfileID, Kernel: target.Host.Kernel, Reason: reason})
			continue
		}
		if i, ok := index[target.ProfileID]; ok {
			if b.Baselines[i].Kernel == target.Host.Kernel && b.Baselines[i].Recorded != "" {
				continue
			}
			b.Baselines[i].Kernel = target.Host.Kernel
			b.Baselines[i].Recorded = recorded
			updated = append(updated, target.ProfileID)
			continue
		}
		b.Baselines = append(b.Baselines, Baseline{
			Profile:  target.ProfileID,
			Kernel:   target.Host.Kernel,
			Recorded: recorded,
		})
		index[target.ProfileID] = len(b.Baselines) - 1
		added = append(added, target.ProfileID)
	}
	return updated, added, skipped
}

// unestablishedReason returns why target cannot vouch for its profile's
// kernel, or "" when it can. An empty status or verdict is not interpreted:
// no verdict is derived from missing data. target must be non-nil.
func unestablishedReason(target *schema.Target) string {
	if !schema.EstablishedRequestedEnvironment(target) {
		return "did not establish requested environment"
	}
	switch {
	case target.Verdict == schema.VerdictInfraError, target.Status == "infra_error":
		return "did not establish requested environment, outcome " + schema.VerdictInfraError
	case target.Verdict == schema.VerdictUnsupported, target.Status == "unsupported":
		return "did not establish requested environment, outcome " + schema.VerdictUnsupported
	}
	return ""
}
