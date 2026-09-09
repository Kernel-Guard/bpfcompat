package runner

import (
	"regexp"
	"strings"

	"github.com/kernel-guard/bpfcompat/internal/vm"
	"github.com/kernel-guard/bpfcompat/pkg/schema"
)

var kernelSeriesRe = regexp.MustCompile(`^(\d+)\.(\d+)`)

// kernelSeries extracts the MAJOR.MINOR series from a kernel family
// ("5.15", "6.1.155") or an observed release ("5.15.0-152-generic").
func kernelSeries(s string) (string, bool) {
	m := kernelSeriesRe.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return "", false
	}
	return m[1] + "." + m[2], true
}

// environmentEvidence records which environment actually ran, next to the one
// the profile asked for.
//
// This is not bookkeeping. Committed evidence in reports/ shows targets marked
// `rhel-8-4.18` / `status: pass` whose guest actually booted 5.15.0 UEK, and
// `oracle-linux-9-uek7-5.15` that booted 6.12.0 -- reports that read as proof of
// support for a kernel series that was never exercised. Recording the observed
// kernel beside the requested family makes that visible to a machine instead of
// only to someone who reads the serial log.
//
// observedKernel is empty when the guest never reported one; the match is then
// left nil rather than guessed.
func environmentEvidence(profile vm.Profile, observedKernel string) *schema.EnvironmentCheck {
	env := &schema.EnvironmentCheck{
		RequestedKernelFamily: strings.TrimSpace(profile.KernelFamily),
		ObservedKernel:        strings.TrimSpace(observedKernel),
		ImageSourceURL:        strings.TrimSpace(profile.Image.SourceURL),
		ImageSHA256:           strings.TrimSpace(profile.Image.SHA256),
	}
	want, wantOK := kernelSeries(env.RequestedKernelFamily)
	got, gotOK := kernelSeries(env.ObservedKernel)
	if wantOK && gotOK {
		match := want == got
		env.KernelFamilyMatch = &match
	}
	if env.RequestedKernelFamily == "" && env.ObservedKernel == "" &&
		env.ImageSourceURL == "" && env.ImageSHA256 == "" {
		return nil
	}
	return env
}

// environmentMismatchNote returns the note to attach when the guest that booted
// is not the kernel series the profile claims to validate.
func environmentMismatchNote(env *schema.EnvironmentCheck) (string, bool) {
	if env == nil || env.KernelFamilyMatch == nil || *env.KernelFamilyMatch {
		return "", false
	}
	return "environment mismatch: profile requests kernel family " +
		env.RequestedKernelFamily + " but the guest booted " + env.ObservedKernel +
		"; this target does not support a claim about the requested kernel series", true
}
