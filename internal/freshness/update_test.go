package freshness

import (
	"reflect"
	"testing"

	"github.com/kernel-guard/bpfcompat/pkg/schema"
)

const unestablishedBaseKernel = "5.15.0-100-generic"

func unestablishedBaselines() Baselines {
	return Baselines{Baselines: []Baseline{{
		Profile: "ubuntu-22.04-5.15", Kernel: unestablishedBaseKernel, Recorded: "2026-01-01",
		Crawler: &CrawlerRef{Distro: "ubuntu", Target: "ubuntu-generic", ReleasePrefix: "5.15.0-"},
	}}}
}

func boolPtr(v bool) *bool { return &v }

// A target that did not establish the environment its profile requested must
// not become that profile's "last validated" kernel: a guest that booted the
// wrong series would otherwise make every later release of the real series
// read as fresh.
func TestUpdateFromReportSkipsUnestablishedTargets(t *testing.T) {
	cases := map[string]schema.Target{
		"wrong kernel series": {
			Status: "pass", Verdict: schema.VerdictCompatible,
			Host: &schema.TargetEnv{Kernel: "6.8.0-40-generic"},
			Environment: &schema.EnvironmentCheck{
				RequestedKernelFamily: "5.15", ObservedKernel: "6.8.0-40-generic", KernelFamilyMatch: boolPtr(false),
			},
		},
		"wrong distro": {
			Status: "pass", Verdict: schema.VerdictCompatible,
			Host: &schema.TargetEnv{Kernel: "5.15.0-150-generic"},
			Environment: &schema.EnvironmentCheck{
				RequestedKernelFamily: "5.15", ObservedKernel: "5.15.0-150-generic",
				KernelFamilyMatch: boolPtr(true), DistroMatch: boolPtr(false),
			},
		},
		"infra_error verdict": {
			Status: "infra_error", Verdict: schema.VerdictInfraError,
			Host: &schema.TargetEnv{Kernel: "5.15.0-150-generic"},
		},
		"unsupported verdict": {
			Status: "unsupported", Verdict: schema.VerdictUnsupported,
			Host: &schema.TargetEnv{Kernel: "5.15.0-150-generic"},
		},
		"infra_error status without verdict": {
			Status: "infra_error",
			Host:   &schema.TargetEnv{Kernel: "5.15.0-150-generic"},
		},
		"unsupported status without verdict": {
			Status: "unsupported",
			Host:   &schema.TargetEnv{Kernel: "5.15.0-150-generic"},
		},
	}
	for name, target := range cases {
		t.Run(name, func(t *testing.T) {
			b := unestablishedBaselines()
			target.ProfileID = "ubuntu-22.04-5.15"
			target.Required = true
			rep := schema.ReportV01{
				Run:     schema.RunInfo{StartedAt: "2026-10-01T00:00:00Z"},
				Targets: []schema.Target{target},
			}
			updated, added, skipped := UpdateFromReport(&b, rep)
			if len(updated) != 0 || len(added) != 0 {
				t.Errorf("updated=%v added=%v, want none", updated, added)
			}
			if len(skipped) != 1 || skipped[0].Profile != "ubuntu-22.04-5.15" || skipped[0].Kernel != target.Host.Kernel {
				t.Errorf("skipped = %+v", skipped)
			}
			if got := b.Baselines[0]; got.Kernel != unestablishedBaseKernel || got.Recorded != "2026-01-01" {
				t.Errorf("baseline overwritten by unestablished target: %+v", got)
			}
		})
	}
}

// The A4-7 end-to-end symptom: after a wrong-series report, a newer release of
// the real series must still read as stale.
func TestUpdateFromReportWrongSeriesKeepsProfileStale(t *testing.T) {
	b := unestablishedBaselines()
	rep := schema.ReportV01{Run: schema.RunInfo{StartedAt: "2026-10-01T00:00:00Z"}, Targets: []schema.Target{{
		ProfileID: "ubuntu-22.04-5.15", Required: true, Status: "pass", Verdict: schema.VerdictCompatible,
		Host: &schema.TargetEnv{Kernel: "6.8.0-40-generic"},
		Environment: &schema.EnvironmentCheck{
			RequestedKernelFamily: "5.15", ObservedKernel: "6.8.0-40-generic", KernelFamilyMatch: boolPtr(false),
		},
	}}}
	UpdateFromReport(&b, rep)
	inv := Inventory{"ubuntu": {{KernelRelease: "5.15.0-200-generic", Target: "ubuntu-generic"}}}
	res, err := Evaluate(b, func(string) (Inventory, error) { return inv, nil })
	if err != nil {
		t.Fatal(err)
	}
	if res[0].Status != StatusStale {
		t.Fatalf("baseline=%q newest=%q status=%q: a mismatched-kernel target hid a stale profile",
			res[0].Baseline, res[0].Newest, res[0].Status)
	}
}

// A report that predates status/verdict/environment carries nothing to judge
// by, so its host kernels are still recorded (no verdict is derived from an
// empty status).
func TestUpdateFromReportLegacyTargetStillRecorded(t *testing.T) {
	b := unestablishedBaselines()
	rep := schema.ReportV01{Run: schema.RunInfo{StartedAt: "2026-10-01T00:00:00Z"}, Targets: []schema.Target{{
		ProfileID: "ubuntu-22.04-5.15", Host: &schema.TargetEnv{Kernel: "5.15.0-150-generic"},
	}}}
	updated, added, skipped := UpdateFromReport(&b, rep)
	if !reflect.DeepEqual(updated, []string{"ubuntu-22.04-5.15"}) || len(added) != 0 || len(skipped) != 0 {
		t.Fatalf("updated=%v added=%v skipped=%v", updated, added, skipped)
	}
	if b.Baselines[0].Kernel != "5.15.0-150-generic" || b.Baselines[0].Recorded != "2026-10-01" {
		t.Fatalf("legacy target not recorded: %+v", b.Baselines[0])
	}
}

func TestUpdateFromReportMixedReport(t *testing.T) {
	b := unestablishedBaselines()
	b.Baselines = append(b.Baselines, Baseline{Profile: "ubuntu-24.04-6.8", Kernel: "6.8.0-100-generic", Recorded: "2026-01-01"})
	rep := schema.ReportV01{Run: schema.RunInfo{StartedAt: "2026-10-01T00:00:00Z"}, Targets: []schema.Target{
		{
			ProfileID: "ubuntu-22.04-5.15", Required: true, Status: "pass", Verdict: schema.VerdictCompatible,
			Host: &schema.TargetEnv{Kernel: "6.8.0-40-generic"},
			Environment: &schema.EnvironmentCheck{
				RequestedKernelFamily: "5.15", ObservedKernel: "6.8.0-40-generic", KernelFamilyMatch: boolPtr(false),
			},
		},
		{
			ProfileID: "ubuntu-24.04-6.8", Required: true, Status: "pass", Verdict: schema.VerdictCompatible,
			Host:        &schema.TargetEnv{Kernel: "6.8.0-130-generic"},
			Environment: &schema.EnvironmentCheck{RequestedKernelFamily: "6.8", KernelFamilyMatch: boolPtr(true)},
		},
		{
			// A genuine incompatibility still exercised the requested kernel.
			ProfileID: "rocky-9-5.14", Required: true, Status: "fail", Verdict: schema.VerdictIncompatible,
			Host:        &schema.TargetEnv{Kernel: "5.14.0-687.12.1.el9_8.x86_64"},
			Environment: &schema.EnvironmentCheck{RequestedKernelFamily: "5.14", KernelFamilyMatch: boolPtr(true)},
		},
		{
			ProfileID: "debian-12-6.1", Required: true, Status: "infra_error", Verdict: schema.VerdictInfraError,
			Host: &schema.TargetEnv{Kernel: "6.1.0-47-cloud-amd64"},
		},
	}}
	updated, added, skipped := UpdateFromReport(&b, rep)
	if !reflect.DeepEqual(updated, []string{"ubuntu-24.04-6.8"}) {
		t.Errorf("updated = %v", updated)
	}
	if !reflect.DeepEqual(added, []string{"rocky-9-5.14"}) {
		t.Errorf("added = %v", added)
	}
	skippedIDs := make([]string, 0, len(skipped))
	for _, s := range skipped {
		skippedIDs = append(skippedIDs, s.Profile)
	}
	if !reflect.DeepEqual(skippedIDs, []string{"ubuntu-22.04-5.15", "debian-12-6.1"}) {
		t.Errorf("skipped = %+v", skipped)
	}
	if b.Baselines[0].Kernel != unestablishedBaseKernel {
		t.Errorf("wrong-series target recorded: %+v", b.Baselines[0])
	}
	for _, entry := range b.Baselines {
		if entry.Profile == "debian-12-6.1" {
			t.Errorf("infra_error target added: %+v", entry)
		}
	}
}
