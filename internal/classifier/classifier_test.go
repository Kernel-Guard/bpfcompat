package classifier

import (
	"strings"
	"testing"
)

func TestClassifyMissingBTF(t *testing.T) {
	result := Classify(Input{
		LoadStatus:         "fail",
		KernelBTFAvailable: false,
		ArtifactHasBTFExt:  true,
	})
	if result.Code != "MISSING_BTF" {
		t.Fatalf("expected MISSING_BTF, got %s", result.Code)
	}
}

func TestClassifyAttachFailureWithoutEvidenceIsNotAnAttachTypeClaim(t *testing.T) {
	// An attach failure with no per-program errno says only that attach
	// failed. Calling it an unsupported attach type, at high confidence,
	// claimed a cause nothing established.
	result := Classify(Input{
		LoadStatus:   "pass",
		AttachStatus: "fail",
		AttachMode:   "required",
	})
	if result.Code != "ATTACH_FAILED" || result.Confidence != "low" {
		t.Fatalf("expected ATTACH_FAILED/low, got %s/%s", result.Code, result.Confidence)
	}
}

func TestClassifyAttachFailureAttribution(t *testing.T) {
	cases := []struct {
		name     string
		failures []AttachFailure
		wantCode string
		wantConf string
	}{
		{"EINVAL alone", []AttachFailure{{Program: "kp", Section: "kprobe/x", Errno: -22, Detail: "Invalid argument"}}, "ATTACH_FAILED", "low"},
		{"ENOENT on a kprobe", []AttachFailure{{Program: "kp", Section: "kprobe/x", Errno: -2, Detail: "No such file or directory"}}, "ATTACH_FAILED", "low"},
		{"ENOENT on a tracepoint", []AttachFailure{{Program: "tp", Section: "tracepoint/a/b", Errno: -2, Detail: "No such file or directory"}}, "ATTACH_FAILED", "low"},
		{"EPERM", []AttachFailure{{Program: "kp", Section: "kprobe/x", Errno: -1, Detail: "Operation not permitted"}}, "ATTACH_FAILED", "low"},
		{"unknown errno", []AttachFailure{{Program: "kp", Section: "kprobe/x", Errno: 0, Detail: ""}}, "ATTACH_FAILED", "low"},
		{"EOPNOTSUPP", []AttachFailure{{Program: "f", Section: "fentry/x", Errno: -95, Detail: "Operation not supported"}}, "UNSUPPORTED_ATTACH_TYPE", "medium"},
		{"ENOTSUPP", []AttachFailure{{Program: "f", Section: "fentry/x", Errno: -524}}, "UNSUPPORTED_ATTACH_TYPE", "medium"},
		{"mixed EOPNOTSUPP and ENOENT", []AttachFailure{
			{Program: "f", Section: "fentry/x", Errno: -95},
			{Program: "kp", Section: "kprobe/x", Errno: -2},
		}, "ATTACH_FAILED", "low"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Classify(Input{LoadStatus: "pass", AttachStatus: "fail", AttachMode: "required", AttachFailures: tc.failures})
			if got.Code != tc.wantCode || got.Confidence != tc.wantConf {
				t.Fatalf("want %s/%s, got %s/%s", tc.wantCode, tc.wantConf, got.Code, got.Confidence)
			}
			lower := strings.ToLower(got.Reason + " " + got.Remediation)
			for _, claim := range []string{"missing symbol", "symbol is missing", "tracepoint does not exist", "permission denied by", "not supported by this kernel"} {
				if strings.Contains(lower, claim) {
					t.Fatalf("reason asserts an unproven cause %q: %q", claim, got.Reason)
				}
			}
			if !strings.Contains(got.Reason, tc.failures[0].Program) {
				t.Fatalf("reason must name the failing program: %q", got.Reason)
			}
		})
	}
}

func TestClassifyAttachFailureReasonIsBounded(t *testing.T) {
	var failures []AttachFailure
	for i := 0; i < 200; i++ {
		failures = append(failures, AttachFailure{Program: strings.Repeat("p", 200), Section: "kprobe/x", Errno: -2, Detail: strings.Repeat("d", 400)})
	}
	got := Classify(Input{LoadStatus: "pass", AttachStatus: "fail", AttachFailures: failures})
	if len(got.Reason) > 2048 {
		t.Fatalf("reason is unbounded: %d bytes", len(got.Reason))
	}
}

func TestClassifyCapabilityFailure(t *testing.T) {
	result := Classify(Input{
		LoadStatus: "fail",
		LoadError:  "Operation not permitted",
	})
	if result.Code != "CAPABILITY_FAILURE" {
		t.Fatalf("expected CAPABILITY_FAILURE, got %s", result.Code)
	}
}

func TestClassifyPolicyDeniedLockdown(t *testing.T) {
	result := Classify(Input{
		LoadStatus: "fail",
		LibbpfLog: "libbpf: kernel lockdown is enabled; BPF is restricted\n" +
			"libbpf: failed to load object: Operation not permitted\n",
		LoadError: "Operation not permitted",
	})
	if result.Code != "POLICY_DENIED" {
		t.Fatalf("expected POLICY_DENIED, got %s", result.Code)
	}
	if result.Confidence != "high" {
		t.Fatalf("expected high confidence, got %q", result.Confidence)
	}
}

func TestClassifyUnsupportedMapTypePreferredOverMissingBTF(t *testing.T) {
	result := Classify(Input{
		LoadStatus:         "fail",
		KernelBTFAvailable: false,
		ArtifactHasBTFExt:  true,
		LibbpfLog: "libbpf: Kernel doesn't support BTF, skipping uploading it.\n" +
			"libbpf: map 'events': failed to create: Invalid argument(-22)\n",
		LoadError: "Invalid argument",
	})
	if result.Code != "UNSUPPORTED_MAP_TYPE" {
		t.Fatalf("expected UNSUPPORTED_MAP_TYPE, got %s", result.Code)
	}
	if result.Confidence != "high" {
		t.Fatalf("expected high confidence from structured libbpf line, got %q", result.Confidence)
	}
	if !strings.Contains(result.Reason, `"events"`) {
		t.Fatalf("expected reason to name the failing map, got %q", result.Reason)
	}
}

func TestClassifyUnsupportedMapTypeNamesAegisBloomMap(t *testing.T) {
	result := Classify(Input{
		LoadStatus: "fail",
		LibbpfLog: "libbpf: map 'agent_meta_map': created successfully, fd=13\n" +
			"libbpf: map 'deny_bloom': failed to create: Invalid argument(-22)\n" +
			"libbpf: failed to load object '/tmp/aegis.bpf.o'\n",
		LoadError: "Invalid argument",
	})
	if result.Code != "UNSUPPORTED_MAP_TYPE" {
		t.Fatalf("expected UNSUPPORTED_MAP_TYPE, got %s", result.Code)
	}
	if result.Confidence != "high" {
		t.Fatalf("expected high confidence, got %q", result.Confidence)
	}
	if !strings.Contains(result.Reason, `"deny_bloom"`) {
		t.Fatalf("expected reason to name deny_bloom, got %q", result.Reason)
	}
}

func TestClassifyUnsupportedMapTypeMediumWhenOnlyLooseMatch(t *testing.T) {
	result := Classify(Input{
		LoadStatus: "fail",
		LibbpfLog:  "libbpf: failed to create map of type ringbuf",
		LoadError:  "Invalid argument",
	})
	if result.Code != "UNSUPPORTED_MAP_TYPE" {
		t.Fatalf("expected UNSUPPORTED_MAP_TYPE, got %s", result.Code)
	}
	if result.Confidence != "medium" {
		t.Fatalf("expected medium confidence on loose match, got %q", result.Confidence)
	}
}

func TestClassifyCoreRelocationFailure(t *testing.T) {
	result := Classify(Input{
		LoadStatus:         "fail",
		KernelBTFAvailable: true,
		ArtifactHasBTFExt:  true,
		LibbpfLog: "libbpf: prog 'x': relo #0: no matching targets found\n" +
			"libbpf: failed to resolve CO-RE relocation\n",
		LoadError: "Invalid argument",
	})
	if result.Code != "CORE_RELOCATION_FAILURE" {
		t.Fatalf("expected CORE_RELOCATION_FAILURE, got %s", result.Code)
	}
}

func TestClassifyDoesNotTreatKernelBTFPathAsMissingBTF(t *testing.T) {
	result := Classify(Input{
		LoadStatus:         "fail",
		KernelBTFAvailable: true,
		ArtifactHasBTFExt:  true,
		LibbpfLog:          "libbpf: loading kernel BTF '/sys/kernel/btf/vmlinux': 0\n",
		LoadError:          "Invalid argument",
	})
	if result.Code == "MISSING_BTF" {
		t.Fatalf("did not expect MISSING_BTF when kernel BTF path appears without BTF load failure")
	}
}

func TestClassifyUnsupportedProgramTypeForFentryOnKernel54(t *testing.T) {
	result := Classify(Input{
		LoadStatus:      "fail",
		LoadErrorCode:   -22,
		LoadError:       "Invalid argument",
		KernelRelease:   "5.4.0-204-generic",
		ProgramSections: []string{"fentry/do_unlinkat"},
		LibbpfLog: "libbpf: sec 'fentry/do_unlinkat': found program 'do_unlinkat'\n" +
			"libbpf: prog 'do_unlinkat': failed to load: Invalid argument\n",
	})
	if result.Code != "UNSUPPORTED_PROGRAM_TYPE" {
		t.Fatalf("expected UNSUPPORTED_PROGRAM_TYPE, got %s", result.Code)
	}
	if result.Confidence != "high" {
		t.Fatalf("expected high confidence, got %q", result.Confidence)
	}
	if !strings.Contains(result.Reason, "kernel 5.4") {
		t.Fatalf("expected kernel version in reason, got %q", result.Reason)
	}
}
