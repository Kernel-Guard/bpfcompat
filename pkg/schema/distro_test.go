package schema

import "testing"

func TestDistroMatch(t *testing.T) {
	for _, tc := range []struct {
		name                 string
		distro, version      string
		osID, osVersion      string
		wantMatch, derivable bool
	}{
		{"rhel matches rhel", "rhel", "8", "rhel", "8.10", true, true},
		// The rhel-8-4.18 slot booted an Oracle Linux 8 (UEK) image.
		{"oracle image in a rhel slot", "rhel", "8", "ol", "8.10", false, true},
		{"alma image in a rhel slot", "rhel", "8", "almalinux", "8.10", false, true},
		{"rhel 9 image in a rhel 8 slot", "rhel", "8", "rhel", "9.4", false, true},
		{"oracle", "oracle", "9", "ol", "9.7", true, true},
		{"centos stream", "centos-stream", "9", "centos", "9", true, true},
		{"amazon linux 2", "amazon-linux", "2", "amzn", "2", true, true},
		{"amazon linux 2023", "amazon-linux", "2023", "amzn", "2023", true, true},
		{"ubuntu", "ubuntu", "22.04", "ubuntu", "22.04", true, true},
		{"ubuntu other release", "ubuntu", "22.04", "ubuntu", "24.04", false, true},
		{"opensuse leap", "opensuse", "15.6", "opensuse-leap", "15.6", true, true},
		{"debian", "debian", "12", "debian", "12", true, true},
		{"azure linux 2.0 reports mariner", "azurelinux", "2.0", "mariner", "2.0", true, true},
		{"azure linux 3.0", "azurelinux", "3.0", "azurelinux", "3.0", true, true},
		{"case and quotes are the parser's job, not tolerated here", "rhel", "8", "RHEL", "8", false, true},
		// Unknown is not a mismatch: no guest identity, or a distro this
		// table does not describe, leaves the answer underivable.
		{"no observed id", "rhel", "8", "", "", false, false},
		{"unmapped profile distro", "talos", "1.8", "talos", "1.8", false, false},
		{"empty profile distro", "", "8", "rhel", "8", false, false},
		// A version that cannot be compared does not decide the match; the
		// distribution id still does.
		{"non-numeric profile version", "fedora-coreos", "stable", "fedora", "40", true, true},
		{"missing observed version", "rhel", "8", "rhel", "", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			match, derivable := DistroMatch(tc.distro, tc.version, tc.osID, tc.osVersion)
			if match != tc.wantMatch || derivable != tc.derivable {
				t.Fatalf("DistroMatch(%q, %q, %q, %q) = (%t, %t), want (%t, %t)",
					tc.distro, tc.version, tc.osID, tc.osVersion, match, derivable, tc.wantMatch, tc.derivable)
			}
		})
	}
}

func TestEstablishedRequestedEnvironmentHonoursDistro(t *testing.T) {
	yes, no := true, false
	for _, tc := range []struct {
		name string
		env  *EnvironmentCheck
		want bool
	}{
		{"no environment", nil, true},
		{"kernel and distro match", &EnvironmentCheck{KernelFamilyMatch: &yes, DistroMatch: &yes}, true},
		{"distro unknown", &EnvironmentCheck{KernelFamilyMatch: &yes}, true},
		{"distro mismatch", &EnvironmentCheck{KernelFamilyMatch: &yes, DistroMatch: &no}, false},
		{"kernel mismatch", &EnvironmentCheck{KernelFamilyMatch: &no, DistroMatch: &yes}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := EstablishedRequestedEnvironment(&Target{Environment: tc.env}); got != tc.want {
				t.Fatalf("got %t, want %t", got, tc.want)
			}
		})
	}
	// RunVerdict: a required pass on another distribution is INFRA_ERROR, never
	// INCOMPATIBLE; RunComplete reports it as incomplete.
	targets := []Target{{ProfileID: "rhel-8-4.18", Required: true, Status: "pass", Verdict: VerdictCompatible,
		Environment: &EnvironmentCheck{KernelFamilyMatch: &yes, DistroMatch: &no}}}
	if v := RunVerdict(targets); v != VerdictInfraError {
		t.Fatalf("RunVerdict = %s, want %s", v, VerdictInfraError)
	}
	if RunComplete(targets) {
		t.Fatal("RunComplete must be false when a target ran on another distribution")
	}
}
