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

// A series has to end where a version stops. "5.15forged" is not a 5.15 kernel,
// and reading one out of it would let a string that is not a version number
// answer a question about which kernel ran.
func TestKernelSeriesRejectsNonDelimitedPrefixes(t *testing.T) {
	for _, in := range []string{
		"5.15forged", "5.15x", "4.18abc", "6.1rc1", "5.15٤",
	} {
		if got, ok := KernelSeries(in); ok {
			t.Errorf("KernelSeries(%q) = %q, true; want a refusal", in, got)
		}
	}
	// The separators real kernel strings actually use still read.
	for _, tc := range []struct{ in, want string }{
		{"5.15", "5.15"},
		{"5.15.0-186-generic", "5.15"},
		{"6.1-rc1", "6.1"},
		{"5.15 ", "5.15"},
		{"5.15_custom", "5.15"},
	} {
		got, ok := KernelSeries(tc.in)
		if !ok || got != tc.want {
			t.Errorf("KernelSeries(%q) = %q,%v; want %q,true", tc.in, got, ok, tc.want)
		}
	}
	// A forged observed kernel can no longer borrow a real family's series.
	if match, derivable := KernelFamilyMatch("5.15", "5.15forged"); derivable || match {
		t.Errorf("KernelFamilyMatch(5.15, 5.15forged) = %v,%v; want false,false", match, derivable)
	}
}

// Every kernel family and observed release this project has recorded must still
// parse. The rule is only safe because nothing real is shaped like the strings
// it now refuses.
func TestKernelSeriesAcceptsEveryRealRecordedKernel(t *testing.T) {
	for _, in := range []string{
		// Profile families.
		"4.4", "4.14", "4.15", "4.18", "5.4", "5.6", "5.8", "5.10", "5.14", "5.15",
		"6.1", "6.1.155", "6.4", "6.5", "6.6", "6.8", "6.11", "6.12", "6.14", "6.17", "6.19", "7.0",
		// Observed releases.
		"4.14.26-54.32.amzn2.x86_64", "4.15.0-212-generic", "4.18.0-553.124.4.el8_10.x86_64",
		"4.4.0-210-generic", "5.10.0-42-cloud-amd64", "5.15.0-186-generic",
		"5.14.0-687.36.1.el9_8.x86_64", "6.12.0-107.el9uek.x86_64",
	} {
		if _, ok := KernelSeries(in); !ok {
			t.Errorf("KernelSeries(%q) refused a real recorded kernel string", in)
		}
	}
}
