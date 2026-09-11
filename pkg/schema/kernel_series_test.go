package schema

import "testing"

// Real strings from committed evidence and profile definitions. The producer
// and the release differ both depend on these answers, so they are pinned.
func TestKernelSeries(t *testing.T) {
	for _, tc := range []struct {
		in     string
		want   string
		wantOK bool
	}{
		{"5.15", "5.15", true},
		{"6.1.155", "6.1", true},
		{"5.15.0-152-generic", "5.15", true},
		{"5.14.0-687.36.1.el9_8.x86_64", "5.14", true},
		{"6.12.0-107.el9uek.x86_64", "6.12", true},
		{"4.14.336-257.562.amzn2.x86_64", "4.14", true},
		{"  5.10.0-28-amd64  ", "5.10", true},
		{"", "", false},
		{"unknown", "", false},
		{"rhel-latest", "", false},
		{"v5.15", "", false},
	} {
		got, ok := KernelSeries(tc.in)
		if got != tc.want || ok != tc.wantOK {
			t.Errorf("KernelSeries(%q) = %q,%v; want %q,%v", tc.in, got, ok, tc.want, tc.wantOK)
		}
	}
}

func TestKernelFamilyMatch(t *testing.T) {
	for _, tc := range []struct {
		requested, observed string
		match, derivable    bool
	}{
		{"5.15", "5.15.0-186-generic", true, true},
		{"5.14", "5.14.0-687.36.1.el9_8.x86_64", true, true},
		{"4.18", "5.15.0-206.el8uek", false, true},
		{"5.15", "6.12.0-107.el9uek.x86_64", false, true},
		// Not derivable is a third answer, distinct from "they do not match":
		// the producer leaves the field unset, and the verifier refuses a
		// report that filled it in anyway.
		{"", "5.15.0-1", false, false},
		{"5.15", "", false, false},
		{"rhel-latest", "unknown", false, false},
	} {
		match, derivable := KernelFamilyMatch(tc.requested, tc.observed)
		if match != tc.match || derivable != tc.derivable {
			t.Errorf("KernelFamilyMatch(%q, %q) = %v,%v; want %v,%v",
				tc.requested, tc.observed, match, derivable, tc.match, tc.derivable)
		}
	}
}
