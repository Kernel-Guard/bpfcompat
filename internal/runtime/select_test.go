package runtime

import (
	"testing"

	"github.com/erenari/bpfcompat/internal/registry"
)

func TestSelectBestArtifactVersionPrefersMatchingProfile(t *testing.T) {
	host := HostCapabilities{}
	host.OS.ID = "ubuntu"
	host.OS.VersionID = "22.04"
	host.Kernel.Release = "5.15.0-100-generic"
	host.BTF.KernelAvailable = true

	records := []registry.ArtifactVersionRecord{
		{
			ArtifactName:      "aegis-bpf",
			ArtifactVersion:   "v1",
			RunID:             "run-1",
			SummaryStatus:     "pass",
			RequiredPassed:    2,
			RequiredFailed:    1,
			SupportedProfiles: []string{"ubuntu-20.04-5.4"},
			FailedProfiles:    []string{"ubuntu-22.04-5.15"},
		},
		{
			ArtifactName:      "aegis-bpf",
			ArtifactVersion:   "v2",
			RunID:             "run-2",
			SummaryStatus:     "pass",
			RequiredPassed:    4,
			RequiredFailed:    0,
			SupportedProfiles: []string{"ubuntu-22.04-5.15"},
		},
	}

	result, err := SelectBestArtifactVersion(records, host, SelectionRequest{
		ArtifactName: "aegis-bpf",
		Limit:        2,
	})
	if err != nil {
		t.Fatalf("select best version: %v", err)
	}
	if result.Selected.ArtifactVersion != "v2" {
		t.Fatalf("expected v2 to be selected, got %s", result.Selected.ArtifactVersion)
	}
	if result.CandidatesReviewed != 2 {
		t.Fatalf("expected 2 candidates reviewed, got %d", result.CandidatesReviewed)
	}
}

func TestSelectBestArtifactVersionUsesExplicitTargetProfile(t *testing.T) {
	host := HostCapabilities{}
	records := []registry.ArtifactVersionRecord{
		{
			ArtifactName:      "aegis-bpf",
			ArtifactVersion:   "ringbuf",
			RunID:             "run-r",
			SummaryStatus:     "pass",
			SupportedProfiles: []string{"ubuntu-24.04-6.8"},
		},
		{
			ArtifactName:      "aegis-bpf",
			ArtifactVersion:   "perfbuf",
			RunID:             "run-p",
			SummaryStatus:     "pass",
			SupportedProfiles: []string{"ubuntu-20.04-5.4"},
		},
	}

	result, err := SelectBestArtifactVersion(records, host, SelectionRequest{
		ArtifactName:    "aegis-bpf",
		TargetProfileID: "ubuntu-20.04-5.4",
	})
	if err != nil {
		t.Fatalf("select best version with explicit profile: %v", err)
	}
	if result.Selected.ArtifactVersion != "perfbuf" {
		t.Fatalf("expected perfbuf selection, got %s", result.Selected.ArtifactVersion)
	}
}

func TestNormalizeVersionID(t *testing.T) {
	if got := normalizeVersionID("22.04.3"); got != "22.04" {
		t.Fatalf("normalize version id: got %q", got)
	}
	if got := normalizeVersionID("12"); got != "12" {
		t.Fatalf("normalize version id fallback: got %q", got)
	}
}

func TestSelectBestArtifactVersionPolicyRequireSummaryPass(t *testing.T) {
	host := HostCapabilities{}
	records := []registry.ArtifactVersionRecord{
		{
			ArtifactName:    "aegis-bpf",
			ArtifactVersion: "v1",
			RunID:           "run-1",
			SummaryStatus:   "fail",
			RequiredPassed:  2,
		},
		{
			ArtifactName:    "aegis-bpf",
			ArtifactVersion: "v2",
			RunID:           "run-2",
			SummaryStatus:   "pass",
			RequiredPassed:  1,
		},
	}

	result, err := SelectBestArtifactVersion(records, host, SelectionRequest{
		ArtifactName: "aegis-bpf",
		Policy: SelectionPolicy{
			RequireSummaryPass: true,
		},
	})
	if err != nil {
		t.Fatalf("select with summary pass policy: %v", err)
	}
	if result.Selected.ArtifactVersion != "v2" {
		t.Fatalf("expected v2 selected with summary policy, got %s", result.Selected.ArtifactVersion)
	}
	if result.CandidatesAccepted != 1 {
		t.Fatalf("expected 1 accepted candidate, got %d", result.CandidatesAccepted)
	}
}

func TestSelectBestArtifactVersionPolicyRejectsAll(t *testing.T) {
	host := HostCapabilities{}
	maxFailed := 0
	records := []registry.ArtifactVersionRecord{
		{
			ArtifactName:    "aegis-bpf",
			ArtifactVersion: "v1",
			RunID:           "run-1",
			SummaryStatus:   "fail",
			RequiredFailed:  1,
		},
	}

	_, err := SelectBestArtifactVersion(records, host, SelectionRequest{
		ArtifactName: "aegis-bpf",
		Policy: SelectionPolicy{
			RequireSummaryPass: true,
			MaxRequiredFailed:  &maxFailed,
		},
	})
	if err == nil {
		t.Fatalf("expected policy rejection error")
	}
	if got := err.Error(); got == "" {
		t.Fatalf("expected non-empty policy error")
	}
}

func TestParseProfileIDSupportsHyphenatedDistros(t *testing.T) {
	tests := []struct {
		profileID string
		distro    string
		version   string
		kernel    string
	}{
		{
			profileID: "ubuntu-24.04-6.8",
			distro:    "ubuntu",
			version:   "24.04",
			kernel:    "6.8",
		},
		{
			profileID: "centos-stream-9-5.14",
			distro:    "centos-stream",
			version:   "9",
			kernel:    "5.14",
		},
		{
			profileID: "redhat-enterprise-linux-9-5.14",
			distro:    "redhat-enterprise-linux",
			version:   "9",
			kernel:    "5.14",
		},
	}

	for _, tt := range tests {
		t.Run(tt.profileID, func(t *testing.T) {
			distro, version, kernel := parseProfileID(tt.profileID)
			if distro != tt.distro || version != tt.version || kernel != tt.kernel {
				t.Fatalf("parseProfileID(%q) = (%q,%q,%q), want (%q,%q,%q)",
					tt.profileID, distro, version, kernel, tt.distro, tt.version, tt.kernel)
			}
		})
	}
}

func TestSelectBestArtifactVersionPrefersHyphenatedDistroMatch(t *testing.T) {
	host := HostCapabilities{}
	host.OS.ID = "centos-stream"
	host.OS.VersionID = "9"
	host.Kernel.Release = "5.14.0-100.el9.x86_64"
	host.BTF.KernelAvailable = true

	records := []registry.ArtifactVersionRecord{
		{
			ArtifactName:      "aegis-bpf",
			ArtifactVersion:   "v-centos",
			RunID:             "run-1",
			SummaryStatus:     "pass",
			RequiredPassed:    1,
			RequiredFailed:    0,
			SupportedProfiles: []string{"centos-stream-9-5.14"},
		},
		{
			ArtifactName:      "aegis-bpf",
			ArtifactVersion:   "v-other",
			RunID:             "run-2",
			SummaryStatus:     "pass",
			RequiredPassed:    1,
			RequiredFailed:    0,
			SupportedProfiles: []string{"ubuntu-22.04-5.15"},
		},
	}

	result, err := SelectBestArtifactVersion(records, host, SelectionRequest{
		ArtifactName: "aegis-bpf",
		Limit:        2,
	})
	if err != nil {
		t.Fatalf("select best version: %v", err)
	}
	if result.Selected.ArtifactVersion != "v-centos" {
		t.Fatalf("expected v-centos to be selected, got %s", result.Selected.ArtifactVersion)
	}
}
