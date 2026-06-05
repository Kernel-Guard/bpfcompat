package compare

import (
	"testing"
	"time"

	"github.com/erenari/bpfcompat/pkg/schema"
)

func TestBuildDetectsRegressionsAndImprovements(t *testing.T) {
	base := schema.ReportV01{
		Run:     schema.RunInfo{ID: "base-run"},
		Summary: schema.SummaryInfo{Status: "pass"},
		Targets: []schema.Target{
			{ProfileID: "ubuntu-20.04-5.4", Required: true, Status: "pass"},
			{ProfileID: "ubuntu-22.04-5.15", Required: true, Status: "fail", ClassificationCode: "UNSUPPORTED_MAP_TYPE"},
		},
	}
	head := schema.ReportV01{
		Run:     schema.RunInfo{ID: "head-run"},
		Summary: schema.SummaryInfo{Status: "fail"},
		Targets: []schema.Target{
			{ProfileID: "ubuntu-20.04-5.4", Required: true, Status: "fail", ClassificationCode: "MISSING_BTF"},
			{ProfileID: "ubuntu-22.04-5.15", Required: true, Status: "pass"},
		},
	}

	diff := Build(base, head, "base.json", "head.json", time.Date(2026, 5, 15, 17, 0, 0, 0, time.UTC))
	if diff.SchemaVersion != diffSchemaVersion {
		t.Fatalf("unexpected diff schema version: %q", diff.SchemaVersion)
	}
	if diff.Summary.RegressedProfiles != 1 {
		t.Fatalf("expected 1 regression, got %d", diff.Summary.RegressedProfiles)
	}
	if diff.Summary.ImprovedProfiles != 1 {
		t.Fatalf("expected 1 improvement, got %d", diff.Summary.ImprovedProfiles)
	}
	if diff.Summary.RequiredRegressions != 1 {
		t.Fatalf("expected 1 required regression, got %d", diff.Summary.RequiredRegressions)
	}
}

func TestBuildDetectsAddedAndRemovedProfiles(t *testing.T) {
	base := schema.ReportV01{
		Run:     schema.RunInfo{ID: "base-run"},
		Summary: schema.SummaryInfo{Status: "pass"},
		Targets: []schema.Target{
			{ProfileID: "debian-12-6.1", Required: true, Status: "pass"},
		},
	}
	head := schema.ReportV01{
		Run:     schema.RunInfo{ID: "head-run"},
		Summary: schema.SummaryInfo{Status: "pass"},
		Targets: []schema.Target{
			{ProfileID: "ubuntu-24.04-6.8", Required: false, Status: "pass"},
		},
	}

	diff := Build(base, head, "base.json", "head.json", time.Date(2026, 5, 15, 17, 0, 0, 0, time.UTC))
	if len(diff.Profiles) != 2 {
		t.Fatalf("expected 2 profile entries, got %d", len(diff.Profiles))
	}
	if diff.Profiles[0].Change != "removed" && diff.Profiles[1].Change != "removed" {
		t.Fatalf("expected one removed profile")
	}
	if diff.Profiles[0].Change != "added" && diff.Profiles[1].Change != "added" {
		t.Fatalf("expected one added profile")
	}
}
