package runner

import (
	"strings"

	"github.com/kernel-guard/bpfcompat/internal/vm"
	"github.com/kernel-guard/bpfcompat/pkg/schema"
)

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
	// schema.KernelFamilyMatch is the same primitive the release differ uses to
	// verify this field later. Recording and verifying must not be able to
	// disagree about what a kernel family is.
	if match, derivable := schema.KernelFamilyMatch(env.RequestedKernelFamily, env.ObservedKernel); derivable {
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
