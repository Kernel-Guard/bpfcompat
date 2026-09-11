package schema

import (
	"regexp"
	"strings"
)

// The kernel-series comparison is part of the compatibility contract, not an
// implementation detail of whoever happens to be asking.
//
// It has two callers with opposite jobs: the runner, which records
// environment.kernel_family_match while a target executes, and the release
// differ, which has to decide whether to believe that recording. If each held
// its own copy of "same kernel family", the two would drift, and the drift
// would appear as either forged-looking honest evidence or trusted forged
// evidence -- both worse than having no check. One definition, used by the
// producer and by the verifier.
var kernelSeriesRe = regexp.MustCompile(`^(\d+)\.(\d+)`)

// KernelSeries extracts the MAJOR.MINOR series from a kernel family ("5.15",
// "6.1.155") or an observed release ("5.15.0-152-generic"). The second return
// is false when no series can be read, which is a different answer from "they
// do not match".
func KernelSeries(s string) (string, bool) {
	m := kernelSeriesRe.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return "", false
	}
	return m[1] + "." + m[2], true
}

// KernelFamilyMatch reports whether an observed kernel belongs to the requested
// family, and whether the question could be answered at all.
//
// derivable is false when either side carries no readable series. A caller
// recording evidence leaves the match unset in that case; a caller verifying
// evidence refuses a recorded match, because a boolean derived from inputs that
// cannot produce one is an assertion rather than a measurement.
func KernelFamilyMatch(requestedFamily, observedKernel string) (match, derivable bool) {
	want, wantOK := KernelSeries(requestedFamily)
	got, gotOK := KernelSeries(observedKernel)
	if !wantOK || !gotOK {
		return false, false
	}
	return want == got, true
}
