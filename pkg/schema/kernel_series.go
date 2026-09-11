package schema

import (
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
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
//
// The series must end where a version stops: at the end of the string or at a
// separator. Matching a bare prefix would read "5.15" out of "5.15forged" and
// call it the same series as a real 5.15 kernel -- a string that is not a
// version number at all answering a question about which kernel ran. Every
// kernel family and observed release this project has recorded (46 distinct
// releases across the committed evidence, 22 profile families) is followed by
// "." or ends there, so nothing real is excluded.
func KernelSeries(s string) (string, bool) {
	s = strings.TrimSpace(s)
	m := kernelSeriesRe.FindStringSubmatch(s)
	if m == nil {
		return "", false
	}
	if rest := s[len(m[0]):]; rest != "" {
		if r, _ := utf8.DecodeRuneInString(rest); unicode.IsLetter(r) || unicode.IsDigit(r) {
			return "", false
		}
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
