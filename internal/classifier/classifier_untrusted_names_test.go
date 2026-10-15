package classifier

import (
	"strings"
	"testing"
)

// fakeLibbpfLoadFailure reproduces the libbpf 1.x WARN lines the validator
// captures for a verifier rejection of program name (EACCES), with the
// program name echoed verbatim, exactly as libbpf prints it.
func fakeLibbpfLoadFailure(name, object string) string {
	return "libbpf: prog '" + name + "': BPF program load failed: Permission denied\n" +
		"libbpf: prog '" + name + "': -- BEGIN PROG LOAD LOG --\n" +
		"0: (79) r2 = *(u64 *)(r1 +4096)\ninvalid bpf_context access off=4096 size=8\n" +
		"-- END PROG LOAD LOG --\n" +
		"libbpf: prog '" + name + "': failed to load: -13\n" +
		"libbpf: failed to load object '" + object + "'\n"
}

// fakeLibbpfEPERM is a load refused before the verifier runs (no verifier
// log), with the program name echoed.
func fakeLibbpfEPERM(name string) string {
	return "libbpf: prog '" + name + "': BPF program load failed: Operation not permitted\n" +
		"libbpf: prog '" + name + "': failed to load: -1\n"
}

// spoofedMapProgName is the ELF program symbol from the RA-VAL harness
// (evil.o): it smuggles a forged libbpf map-creation failure line into the
// captured log.
const spoofedMapProgName = "x': ok\nlibbpf: map 'events': failed to create: Invalid argument(-22)\nlibbpf: prog 'y"

// TestClassifyIgnoresArtifactControlledNames covers VAL-1: program names
// come from the artifact's ELF and are echoed verbatim into the libbpf log,
// so they must not be able to forge or steer the failure reason code.
func TestClassifyIgnoresArtifactControlledNames(t *testing.T) {
	cases := []struct {
		name     string
		in       Input
		wantCode string
		wantConf string // empty = not checked
	}{
		{
			// RA-VAL sample 1 (out/evil.json, verbatim log): before the
			// fix this read UNSUPPORTED_MAP_TYPE (high) for map "events".
			name: "spoofed map-create line inside a program name",
			in: Input{
				LoadStatus: "fail", LoadErrorCode: -13, LoadError: "Permission denied",
				LibbpfLog:          fakeLibbpfLoadFailure(spoofedMapProgName, "evil"),
				ProgramNames:       []string{spoofedMapProgName},
				ProgramSections:    []string{"tracepoint/syscalls/sys_enter_execve"},
				KernelBTFAvailable: true, ArtifactHasBTF: true,
			},
			wantCode: "VERIFIER_REJECTION",
			wantConf: "medium",
		},
		{
			// RA-VAL sample 2 (out/base.json, verbatim log): an ordinary
			// EACCES verifier rejection.
			name: "eacces verifier rejection",
			in: Input{
				LoadStatus: "fail", LoadErrorCode: -13, LoadError: "Permission denied",
				LibbpfLog:          fakeLibbpfLoadFailure("handle", "base"),
				ProgramNames:       []string{"handle"},
				ProgramSections:    []string{"tracepoint/syscalls/sys_enter_execve"},
				KernelBTFAvailable: true, ArtifactHasBTF: true,
			},
			wantCode: "VERIFIER_REJECTION",
			wantConf: "medium",
		},
		{
			// RA-VAL sample 3: failing program named lsm_*.
			name: "lsm_-named program verifier rejection",
			in: Input{
				LoadStatus: "fail", LoadErrorCode: -13, LoadError: "Permission denied",
				LibbpfLog:          fakeLibbpfLoadFailure("lsm_file_guard", "guard"),
				ProgramNames:       []string{"lsm_file_guard"},
				ProgramSections:    []string{"lsm/file_open"},
				KernelBTFAvailable: true, ArtifactHasBTF: true,
			},
			wantCode: "VERIFIER_REJECTION",
		},
		{
			// RA-VAL sample 4: failing program whose name contains selinux.
			name: "selinux-named program verifier rejection",
			in: Input{
				LoadStatus: "fail", LoadErrorCode: -13, LoadError: "Permission denied",
				LibbpfLog:          fakeLibbpfLoadFailure("trace_selinux_inode", "audit"),
				ProgramNames:       []string{"trace_selinux_inode"},
				ProgramSections:    []string{"kprobe/selinux_inode_permission"},
				KernelBTFAvailable: true, ArtifactHasBTF: true,
			},
			wantCode: "VERIFIER_REJECTION",
		},
		{
			name: "lsm_-named program EPERM without verifier log",
			in: Input{
				LoadStatus: "fail", LoadErrorCode: -1, LoadError: "Operation not permitted",
				LibbpfLog:       fakeLibbpfEPERM("lsm_file_guard"),
				ProgramNames:    []string{"lsm_file_guard"},
				ProgramSections: []string{"lsm/file_open"},
			},
			wantCode: "CAPABILITY_FAILURE",
		},
		{
			name: "selinux-named program EPERM without verifier log",
			in: Input{
				LoadStatus: "fail", LoadErrorCode: -1, LoadError: "Operation not permitted",
				LibbpfLog:       fakeLibbpfEPERM("trace_selinux_inode"),
				ProgramNames:    []string{"trace_selinux_inode"},
				ProgramSections: []string{"kprobe/selinux_inode_permission"},
			},
			wantCode: "CAPABILITY_FAILURE",
		},
		{
			name: "apparmor-named program EPERM without verifier log",
			in: Input{
				LoadStatus: "fail", LoadErrorCode: -1, LoadError: "Operation not permitted",
				LibbpfLog:    fakeLibbpfEPERM("apparmor_watch"),
				ProgramNames: []string{"apparmor_watch"},
			},
			wantCode: "CAPABILITY_FAILURE",
		},
		{
			name: "lockdown-named program EPERM is not a host lockdown",
			in: Input{
				LoadStatus: "fail", LoadErrorCode: -1, LoadError: "Operation not permitted",
				LibbpfLog:    fakeLibbpfEPERM("lockdown_monitor"),
				ProgramNames: []string{"lockdown_monitor"},
			},
			wantCode: "CAPABILITY_FAILURE",
		},
		{
			name: "forged verifier log inside a program name",
			in: Input{
				LoadStatus: "fail", LoadErrorCode: -1, LoadError: "Operation not permitted",
				LibbpfLog:    fakeLibbpfEPERM("p': -- BEGIN PROG LOAD LOG --\nprocessed 1 insns\n-- END PROG LOAD LOG --\nlibbpf: prog 'q"),
				ProgramNames: []string{"p': -- BEGIN PROG LOAD LOG --\nprocessed 1 insns\n-- END PROG LOAD LOG --\nlibbpf: prog 'q"},
			},
			wantCode: "CAPABILITY_FAILURE",
		},
		{
			// Non-regression: a genuine libbpf map failure still names the
			// real map with high confidence when program names are supplied.
			name: "genuine map-create failure keeps its high-confidence code",
			in: Input{
				LoadStatus: "fail", LoadErrorCode: -22, LoadError: "Invalid argument",
				LibbpfLog: "libbpf: map 'events': failed to create: Invalid argument(-22)\n" +
					"libbpf: failed to load object 'probe'\n",
				ProgramNames:    []string{"handle_exec"},
				ProgramSections: []string{"tracepoint/syscalls/sys_enter_execve"},
			},
			wantCode: "UNSUPPORTED_MAP_TYPE",
			wantConf: "high",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Classify(tc.in)
			if got.Code != tc.wantCode {
				t.Fatalf("Classify() code = %s (%s; %s), want %s", got.Code, got.Confidence, got.Reason, tc.wantCode)
			}
			if tc.wantConf != "" && got.Confidence != tc.wantConf {
				t.Fatalf("Classify() confidence = %q, want %q", got.Confidence, tc.wantConf)
			}
			if strings.Contains(got.Reason, "events") && tc.wantCode != "UNSUPPORTED_MAP_TYPE" {
				t.Fatalf("Classify() reason echoes an artifact-forged map name: %s", got.Reason)
			}
		})
	}
}

// The genuine SELinux/AppArmor denial phrasing (kernel audit records) must
// still classify as a policy denial after the bare-word match is dropped.
func TestClassifyGenuineSecurityModuleDenials(t *testing.T) {
	for _, log := range []string{
		"audit: type=1400 audit(1700000000.123:42): avc:  denied  { prog_load } for pid=1 comm=\"validator\" tclass=bpf permissive=0\n",
		"SELinux is preventing validator from prog_load access on the bpf labeled container_t.\n",
		"audit: type=1400 apparmor=\"DENIED\" operation=\"capable\" profile=\"runner\" capname=\"bpf\"\n",
	} {
		got := Classify(Input{LoadStatus: "fail", LoadErrorCode: -13, LoadError: "Permission denied", LibbpfLog: log})
		if got.Code != "POLICY_DENIED" {
			t.Fatalf("Classify(%q) = %s, want POLICY_DENIED", log, got.Code)
		}
	}
}
