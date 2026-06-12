package freshness

import (
	"strings"
	"testing"

	"github.com/kernel-guard/bpfcompat/pkg/schema"
)

func TestCompareKernelReleases(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"5.15.0-184-generic", "5.15.0-92-generic", 1},
		{"5.15.0-92-generic", "5.15.0-184-generic", -1},
		{"5.15.0-184-generic", "5.15.0-184-generic", 0},
		{"6.1.174-217.345.amzn2023.x86_64", "6.1.97-104.177.amzn2023.x86_64", 1},
		{"5.14.0-687.12.1.el9_8.x86_64", "5.14.0-611.5.1.el9_7.x86_64", 1},
		{"6.8.0-130-generic", "5.15.0-184-generic", 1},
		// More numeric components on an equal prefix wins.
		{"5.15.0-184.1-generic", "5.15.0-184-generic", 1},
	}
	for _, tc := range cases {
		if got := CompareKernelReleases(tc.a, tc.b); got != tc.want {
			t.Errorf("CompareKernelReleases(%q, %q) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestInventoryNewest(t *testing.T) {
	inv := Inventory{
		"ubuntu": {
			{KernelRelease: "5.15.0-92-generic", Target: "ubuntu-generic"},
			{KernelRelease: "5.15.0-184-generic", Target: "ubuntu-generic"},
			{KernelRelease: "5.15.0-1102-kvm", Target: "ubuntu-kvm"},
			{KernelRelease: "6.8.0-130-generic", Target: "ubuntu-generic"},
		},
		"rocky": {
			{KernelRelease: "5.14.0-687.12.1.el9_8.x86_64", Target: "rocky"},
			{KernelRelease: "6.12.0-124.8.1.el10_1.x86_64", Target: "rocky"},
		},
	}

	got := inv.Newest(CrawlerRef{Distro: "ubuntu", Target: "ubuntu-generic", ReleasePrefix: "5.15.0-"})
	if got != "5.15.0-184-generic" {
		t.Errorf("ubuntu-generic 5.15: got %q", got)
	}
	got = inv.Newest(CrawlerRef{Distro: "ubuntu", Target: "ubuntu-kvm", ReleasePrefix: "5.15.0-"})
	if got != "5.15.0-1102-kvm" {
		t.Errorf("ubuntu-kvm 5.15: got %q", got)
	}
	got = inv.Newest(CrawlerRef{Distro: "rocky", ReleasePrefix: "5.14.0-", ReleaseContains: "el9"})
	if got != "5.14.0-687.12.1.el9_8.x86_64" {
		t.Errorf("rocky el9: got %q", got)
	}
	if got := inv.Newest(CrawlerRef{Distro: "ubuntu", Target: "ubuntu-generic", ReleasePrefix: "6.5.0-"}); got != "" {
		t.Errorf("EOL series should match nothing, got %q", got)
	}
	if got := inv.Newest(CrawlerRef{Distro: "debian", ReleasePrefix: "6.1."}); got != "" {
		t.Errorf("missing distro should match nothing, got %q", got)
	}
}

func TestParseInventoryDropsUnknownFields(t *testing.T) {
	payload := `{"ubuntu":[{"kernelversion":"1","kernelrelease":"5.15.0-184-generic","target":"ubuntu-generic","headers":["http://example/a.deb"]}]}`
	inv, err := ParseInventory(strings.NewReader(payload))
	if err != nil {
		t.Fatalf("ParseInventory: %v", err)
	}
	if len(inv["ubuntu"]) != 1 || inv["ubuntu"][0].KernelRelease != "5.15.0-184-generic" {
		t.Fatalf("unexpected inventory: %+v", inv)
	}
}

func testBaselines() Baselines {
	return Baselines{Baselines: []Baseline{
		{
			Profile: "ubuntu-22.04-5.15", Kernel: "5.15.0-173-generic", Recorded: "2026-06-11",
			Crawler: &CrawlerRef{Distro: "ubuntu", Target: "ubuntu-generic", ReleasePrefix: "5.15.0-"},
		},
		{
			Profile: "ubuntu-24.04-6.8", Kernel: "6.8.0-130-generic", Recorded: "2026-06-11",
			Crawler: &CrawlerRef{Distro: "ubuntu", Target: "ubuntu-generic", ReleasePrefix: "6.8.0-"},
		},
		{
			Profile: "ubuntu-23.10-6.5", Kernel: "6.5.0-44-generic", Recorded: "2026-06-11",
			Crawler: &CrawlerRef{Distro: "ubuntu", Target: "ubuntu-generic", ReleasePrefix: "6.5.0-"},
		},
		{Profile: "debian-12-6.1", Kernel: "6.1.0-47-cloud-amd64", Note: "kernel-crawler does not publish debian entries"},
		{
			Profile: "ubuntu-22.04-arm64-5.15",
			Crawler: &CrawlerRef{Distro: "ubuntu", Target: "ubuntu-generic", ReleasePrefix: "5.15.0-", Arch: "aarch64"},
		},
	}}
}

func TestEvaluateStatuses(t *testing.T) {
	fetched := map[string]int{}
	fetch := func(arch string) (Inventory, error) {
		fetched[arch]++
		return Inventory{
			"ubuntu": {
				{KernelRelease: "5.15.0-184-generic", Target: "ubuntu-generic"},
				{KernelRelease: "6.8.0-130-generic", Target: "ubuntu-generic"},
			},
		}, nil
	}

	results, err := Evaluate(testBaselines(), fetch)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	want := map[string]string{
		"ubuntu-22.04-5.15":       StatusStale,
		"ubuntu-24.04-6.8":        StatusFresh,
		"ubuntu-23.10-6.5":        StatusNoEntries,
		"debian-12-6.1":           StatusUncovered,
		"ubuntu-22.04-arm64-5.15": StatusNoKernel,
	}
	if len(results) != len(want) {
		t.Fatalf("got %d results, want %d", len(results), len(want))
	}
	for _, r := range results {
		if r.Status != want[r.Profile] {
			t.Errorf("%s: status %q, want %q", r.Profile, r.Status, want[r.Profile])
		}
	}
	if StaleCount(results) != 1 {
		t.Errorf("StaleCount = %d, want 1", StaleCount(results))
	}
	// The arm64 entry has no kernel, so only x86_64 is fetched, exactly once.
	if len(fetched) != 1 || fetched["x86_64"] != 1 {
		t.Errorf("fetch calls: %v", fetched)
	}
}

func TestLoadBaselinesValidation(t *testing.T) {
	good := `baselines:
  - profile: ubuntu-22.04-5.15
    kernel: 5.15.0-173-generic
    crawler:
      distro: ubuntu
      target: ubuntu-generic
      release_prefix: "5.15.0-"
`
	if _, err := LoadBaselines([]byte(good)); err != nil {
		t.Fatalf("valid baselines rejected: %v", err)
	}

	for name, bad := range map[string]string{
		"unknown field":   "baselines:\n  - profile: a\n    kernel: x\n    bogus: y\n",
		"missing profile": "baselines:\n  - kernel: x\n",
		"duplicate":       "baselines:\n  - profile: a\n  - profile: a\n",
		"missing distro":  "baselines:\n  - profile: a\n    crawler:\n      release_prefix: \"5.\"\n",
		"missing prefix":  "baselines:\n  - profile: a\n    crawler:\n      distro: ubuntu\n",
	} {
		if _, err := LoadBaselines([]byte(bad)); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}

func TestUpdateFromReport(t *testing.T) {
	b := testBaselines()
	rep := schema.ReportV01{
		Run: schema.RunInfo{StartedAt: "2026-06-12T10:00:00Z"},
		Targets: []schema.Target{
			{ProfileID: "ubuntu-22.04-5.15", Host: &schema.TargetEnv{Kernel: "5.15.0-184-generic"}},
			{ProfileID: "ubuntu-24.04-6.8", Host: &schema.TargetEnv{Kernel: "6.8.0-130-generic"}}, // unchanged
			{ProfileID: "rocky-9-5.14", Host: &schema.TargetEnv{Kernel: "5.14.0-687.12.1.el9_8.x86_64"}},
			{ProfileID: "no-host-info"},
		},
	}

	updated, added := UpdateFromReport(&b, rep)
	if len(updated) != 1 || updated[0] != "ubuntu-22.04-5.15" {
		t.Errorf("updated = %v", updated)
	}
	if len(added) != 1 || added[0] != "rocky-9-5.14" {
		t.Errorf("added = %v", added)
	}
	for _, entry := range b.Baselines {
		if entry.Profile == "ubuntu-22.04-5.15" {
			if entry.Kernel != "5.15.0-184-generic" || entry.Recorded != "2026-06-12" {
				t.Errorf("entry not refreshed: %+v", entry)
			}
		}
		if entry.Profile == "rocky-9-5.14" && entry.Crawler != nil {
			t.Errorf("added entry should have no crawler mapping")
		}
	}

	// Round-trip through marshal/load.
	out, err := MarshalBaselines(b)
	if err != nil {
		t.Fatalf("MarshalBaselines: %v", err)
	}
	reloaded, err := LoadBaselines(out)
	if err != nil {
		t.Fatalf("reload: %v\n%s", err, out)
	}
	if len(reloaded.Baselines) != len(b.Baselines) {
		t.Errorf("round trip lost entries: %d != %d", len(reloaded.Baselines), len(b.Baselines))
	}
}

func TestMarkdownMarksStale(t *testing.T) {
	md := Markdown([]Result{
		{Profile: "p1", Baseline: "5.15.0-173-generic", Newest: "5.15.0-184-generic", Status: StatusStale, Reason: "behind"},
		{Profile: "p2", Status: StatusUncovered},
	})
	if !strings.Contains(md, "**stale**") || !strings.Contains(md, "1 profile(s) are behind") {
		t.Errorf("markdown missing stale emphasis:\n%s", md)
	}
}

func TestSweepReleases(t *testing.T) {
	inv := Inventory{
		"ubuntu": {
			{KernelRelease: "5.15.0-92-generic", Target: "ubuntu-generic"},
			{KernelRelease: "5.15.0-184-generic", Target: "ubuntu-generic"},
			{KernelRelease: "5.15.0-184-generic", Target: "ubuntu-generic"}, // duplicate
			{KernelRelease: "5.15.0-130-generic", Target: "ubuntu-generic"},
			{KernelRelease: "5.15.0-1102-kvm", Target: "ubuntu-kvm"},
			{KernelRelease: "6.8.0-130-generic", Target: "ubuntu-generic"},
		},
	}
	got := inv.SweepEntries(CrawlerRef{Distro: "ubuntu", Target: "ubuntu-generic", ReleasePrefix: "5.15.0-"}, 2)
	if len(got) != 2 || got[0].KernelRelease != "5.15.0-184-generic" || got[1].KernelRelease != "5.15.0-130-generic" {
		t.Errorf("SweepEntries = %v", got)
	}
	all := inv.SweepEntries(CrawlerRef{Distro: "ubuntu", Target: "ubuntu-generic", ReleasePrefix: "5.15.0-"}, 0)
	if len(all) != 3 {
		t.Errorf("unbounded sweep = %v", all)
	}
}

func TestUbuntuKernelDebs(t *testing.T) {
	entry := Entry{
		KernelRelease: "5.15.0-184-generic",
		Target:        "ubuntu-generic",
		Headers: []string{
			"http://archive.ubuntu.com/ubuntu/pool/main/l/linux/linux-headers-5.15.0-184_5.15.0-184.194_all.deb",
			"http://archive.ubuntu.com/ubuntu/pool/main/l/linux/linux-headers-5.15.0-184-generic_5.15.0-184.194_amd64.deb",
		},
	}
	debs, err := UbuntuKernelDebs(entry)
	if err != nil {
		t.Fatalf("UbuntuKernelDebs: %v", err)
	}
	want := []string{
		"http://archive.ubuntu.com/ubuntu/pool/main/l/linux/linux-modules-5.15.0-184-generic_5.15.0-184.194_amd64.deb",
		"http://archive.ubuntu.com/ubuntu/pool/main/l/linux/linux-image-unsigned-5.15.0-184-generic_5.15.0-184.194_amd64.deb",
	}
	if len(debs) != 2 || debs[0] != want[0] || debs[1] != want[1] {
		t.Errorf("UbuntuKernelDebs = %v, want %v", debs, want)
	}

	// Only the arch-independent header URL: cannot derive package URLs.
	entry.Headers = entry.Headers[:1]
	if _, err := UbuntuKernelDebs(entry); err == nil {
		t.Error("expected error without flavor-specific headers URL")
	}
}
