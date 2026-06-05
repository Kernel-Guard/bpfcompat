package classifier

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

type Input struct {
	LoadStatus         string
	LoadErrorCode      int
	LoadError          string
	AttachStatus       string
	AttachMode         string
	KernelBTFAvailable bool
	ArtifactHasBTF     bool
	ArtifactHasBTFExt  bool
	LibbpfLog          string
	KernelRelease      string
	ProgramSections    []string
	TracingProbeStatus string
	TracingProbeError  int
}

type Result struct {
	Code        string
	Confidence  string
	Reason      string
	Remediation string
}

// libbpfMapCreateFailureRe matches the structured "libbpf: map 'NAME':
// failed to create: ERR(CODE)" line that libbpf emits when a specific
// map cannot be created against the running kernel. We pin to this
// exact shape so we can promote to high confidence and surface the
// failing map name, rather than relying on loose substring matching.
var libbpfMapCreateFailureRe = regexp.MustCompile(`(?mi)^\s*libbpf:\s+map\s+'([^']+)':\s+failed to create:\s+(.+?)\s*$`)
var kernelVersionPrefixRe = regexp.MustCompile(`^\s*([0-9]+)\.([0-9]+)`)

func Classify(in Input) Result {
	lowerBlob := strings.ToLower(in.LibbpfLog + "\n" + in.LoadError)

	if in.AttachStatus == "fail" {
		return Result{
			Code:        "UNSUPPORTED_ATTACH_TYPE",
			Confidence:  "high",
			Reason:      "Attach failed after load succeeded.",
			Remediation: "Use a supported attach point for this kernel/profile or ship a fallback artifact.",
		}
	}

	if match := libbpfMapCreateFailureRe.FindStringSubmatch(in.LibbpfLog); match != nil {
		mapName := strings.TrimSpace(match[1])
		errTail := strings.TrimSpace(match[2])
		return Result{
			Code:        "UNSUPPORTED_MAP_TYPE",
			Confidence:  "high",
			Reason:      fmt.Sprintf("Map %q failed to create on this kernel (%s); likely an unsupported map type.", mapName, errTail),
			Remediation: "Confirm the map type used by this map is supported on this kernel/profile, or ship a fallback artifact.",
		}
	}

	if containsAny(lowerBlob,
		"failed to create map",
		"failed to create",
		"map type") &&
		containsAny(lowerBlob, "invalid argument", "not supported") {
		return Result{
			Code:        "UNSUPPORTED_MAP_TYPE",
			Confidence:  "medium",
			Reason:      "Map creation failed, likely due to unsupported map type on this kernel.",
			Remediation: "Use a supported map type on this profile, usually a perf buffer fallback instead of ringbuf.",
		}
	}

	if containsAny(lowerBlob,
		"failed to resolve co-re relocation",
		"failed to relocate",
		"relocation failed",
		"relo failed",
		"invalid co-re relocation",
		"no matching targets found") {
		return Result{
			Code:        "CORE_RELOCATION_FAILURE",
			Confidence:  "high",
			Reason:      "CO-RE relocations failed against target kernel BTF layout.",
			Remediation: "Adjust CO-RE access pattern or ship a profile-specific fallback artifact.",
		}
	}

	if containsAny(lowerBlob,
		"failed to find valid kernel btf",
		"error loading vmlinux btf",
		"btf is required",
		"kernel doesn't support btf") ||
		(!in.KernelBTFAvailable && in.ArtifactHasBTFExt && !containsAny(lowerBlob, "failed to create", "map type")) ||
		(!in.KernelBTFAvailable && in.ArtifactHasBTFExt && containsAny(lowerBlob, "btf")) {
		return Result{
			Code:        "MISSING_BTF",
			Confidence:  "high",
			Reason:      "Artifact appears to require kernel BTF but target BTF is unavailable/unusable.",
			Remediation: "Provide kernel BTF (or external BTF) for this profile, or use a non-CO-RE fallback.",
		}
	}

	if fentrySection, hasFentryFamily := findFentryFamilySection(in.ProgramSections, lowerBlob); hasFentryFamily {
		major, minor, ok := parseKernelMajorMinor(in.KernelRelease)
		if ok && (major < 5 || (major == 5 && minor < 5)) {
			return Result{
				Code:       "UNSUPPORTED_PROGRAM_TYPE",
				Confidence: "high",
				Reason: fmt.Sprintf(
					"Program section %q requires fentry/fexit-style tracing support not available on kernel %d.%d.",
					fentrySection,
					major,
					minor,
				),
				Remediation: "Ship a fallback artifact using tracepoint/kprobe program sections for kernels below 5.5.",
			}
		}
		if containsAny(lowerBlob,
			"invalid argument",
			"operation not supported",
			"not supported",
			"program type not supported") &&
			containsAny(lowerBlob, "fentry/", "fexit/", "fmod_ret/") {
			return Result{
				Code:        "UNSUPPORTED_PROGRAM_TYPE",
				Confidence:  "medium",
				Reason:      fmt.Sprintf("Program section %q appears unsupported on this kernel/runtime verifier path.", fentrySection),
				Remediation: "Use a profile-specific fallback program type (tracepoint/kprobe) for this target kernel.",
			}
		}
		if strings.EqualFold(strings.TrimSpace(in.TracingProbeStatus), "unsupported") ||
			(strings.EqualFold(strings.TrimSpace(in.TracingProbeStatus), "probe_error") && in.TracingProbeError == -95) {
			return Result{
				Code:        "UNSUPPORTED_PROGRAM_TYPE",
				Confidence:  "high",
				Reason:      fmt.Sprintf("Kernel capability probes report tracing program support as %q while section %q is present.", in.TracingProbeStatus, fentrySection),
				Remediation: "Use a fallback artifact that avoids fentry/fexit/fmod_ret program sections on this profile.",
			}
		}
	}

	if containsAny(lowerBlob,
		"lockdown",
		"kernel lockdown",
		"unprivileged_bpf_disabled",
		"bpf is restricted",
		"denied by policy",
		"security policy",
		"apparmor",
		"selinux",
		"lsm") {
		confidence := "medium"
		if containsAny(lowerBlob, "lockdown", "unprivileged_bpf_disabled", "bpf is restricted") {
			confidence = "high"
		}
		return Result{
			Code:        "POLICY_DENIED",
			Confidence:  confidence,
			Reason:      "Kernel/runtime security policy blocked BPF load or attach for this target.",
			Remediation: "Use an approved host policy profile for BPF on this kernel, or route this target to a fallback deployment path.",
		}
	}

	if containsAny(lowerBlob,
		"operation not permitted",
		"permission denied",
		"not permitted") {
		return Result{
			Code:        "CAPABILITY_FAILURE",
			Confidence:  "medium",
			Reason:      "Load failed with permission/capability related error.",
			Remediation: "Ensure required capabilities are available (for example CAP_BPF/CAP_PERFMON/CAP_SYS_ADMIN).",
		}
	}

	if containsAny(lowerBlob,
		"invalid mem access",
		"unbounded loop",
		"back-edge",
		"invalid stack",
		"verifier") {
		return Result{
			Code:        "VERIFIER_REJECTION",
			Confidence:  "medium",
			Reason:      "Verifier rejected program for safety/typing/complexity reasons.",
			Remediation: "Inspect verifier log and simplify/fix program logic for this profile.",
		}
	}

	if in.LoadStatus == "fail" {
		return Result{
			Code:        "UNKNOWN",
			Confidence:  "low",
			Reason:      "Load failed but no known classification pattern matched.",
			Remediation: "Inspect libbpf and verifier logs to derive a profile-specific remediation.",
		}
	}

	return Result{
		Code:        "NONE",
		Confidence:  "high",
		Reason:      "No compatibility failure detected.",
		Remediation: "",
	}
}

func containsAny(blob string, patterns ...string) bool {
	for _, p := range patterns {
		if strings.Contains(blob, strings.ToLower(p)) {
			return true
		}
	}
	return false
}

func findFentryFamilySection(programSections []string, lowerBlob string) (string, bool) {
	prefixes := []string{"fentry/", "fexit/", "fmod_ret/"}
	for _, section := range programSections {
		clean := strings.TrimSpace(section)
		lower := strings.ToLower(clean)
		for _, prefix := range prefixes {
			if strings.HasPrefix(lower, prefix) {
				return clean, true
			}
		}
	}
	for _, prefix := range prefixes {
		if strings.Contains(lowerBlob, prefix) {
			return prefix + "...", true
		}
	}
	return "", false
}

func parseKernelMajorMinor(release string) (major int, minor int, ok bool) {
	match := kernelVersionPrefixRe.FindStringSubmatch(strings.TrimSpace(release))
	if len(match) < 3 {
		return 0, 0, false
	}
	major, err := strconv.Atoi(match[1])
	if err != nil {
		return 0, 0, false
	}
	minor, err = strconv.Atoi(match[2])
	if err != nil {
		return 0, 0, false
	}
	return major, minor, true
}
