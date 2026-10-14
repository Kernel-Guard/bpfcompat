package classifier

import "testing"

// Verifier logs as the validator captures them: libbpf prints the kernel
// verifier log between "-- BEGIN PROG LOAD LOG --" / "-- END PROG LOAD LOG --"
// at WARN level, and the validator stores libbpf_strerror(err) in LoadError,
// so a verifier EACCES arrives as "Permission denied".
const (
	eaccesVerifierLog = "libbpf: prog 'handle_exec': BPF program load failed: Permission denied\n" +
		"libbpf: prog 'handle_exec': -- BEGIN PROG LOAD LOG --\n" +
		"0: R1=ctx() R10=fp0\n; int handle_exec(void *ctx)\n" +
		"0: (79) r2 = *(u64 *)(r1 +4096)\ninvalid bpf_context access off=4096 size=8\n" +
		"processed 1 insns (limit 1000000) max_states_per_insn 0 total_states 0 peak_states 0 mark_read 0\n" +
		"-- END PROG LOAD LOG --\n" +
		"libbpf: prog 'handle_exec': failed to load: -13\n" +
		"libbpf: failed to load object 'probe.bpf.o'\n"

	lsmVerifierLog = "libbpf: sec 'lsm/file_open': found program 'restrict_open'\n" +
		"libbpf: prog 'restrict_open': BPF program load failed: Permission denied\n" +
		"libbpf: prog 'restrict_open': -- BEGIN PROG LOAD LOG --\n" +
		"0: R1=ctx() R10=fp0\n" +
		"0: (79) r2 = *(u64 *)(r1 +0)\n" +
		"1: (61) r3 = *(u32 *)(r2 +0)\n" +
		"R2 invalid mem access 'scalar'\n" +
		"processed 2 insns (limit 1000000)\n" +
		"-- END PROG LOAD LOG --\n" +
		"libbpf: prog 'restrict_open': failed to load: -13\n"

	// Older libbpf (< 0.7) framed the verifier log differently.
	legacyDumpLog = "libbpf: load bpf program failed: Permission denied\n" +
		"libbpf: -- BEGIN DUMP LOG ---\n" +
		"libbpf: \n" +
		"R1 type=ctx expected=fp\n" +
		"processed 3 insns (limit 1000000)\n" +
		"libbpf: -- END LOG --\n"
)

func TestClassifyPrecedence(t *testing.T) {
	cases := []struct {
		name     string
		in       Input
		wantCode string
		wantConf string // empty = not checked
	}{
		{
			// A3-3: EACCES from the verifier must not be read as a missing capability.
			name: "eacces with verifier log is a verifier rejection",
			in: Input{
				LoadStatus: "fail", LoadErrorCode: -13, LoadError: "Permission denied",
				LibbpfLog:          eaccesVerifierLog,
				KernelBTFAvailable: true, ArtifactHasBTF: true,
			},
			wantCode: "VERIFIER_REJECTION",
			wantConf: "medium",
		},
		{
			name: "eacces with legacy libbpf dump log is a verifier rejection",
			in: Input{
				LoadStatus: "fail", LoadErrorCode: -13, LoadError: "Permission denied",
				LibbpfLog:          legacyDumpLog,
				KernelBTFAvailable: true, ArtifactHasBTF: true,
			},
			wantCode: "VERIFIER_REJECTION",
		},
		{
			// A3-4: an LSM program's section name is not a policy denial.
			name: "lsm/file_open verifier rejection with EACCES is a verifier rejection",
			in: Input{
				LoadStatus: "fail", LoadErrorCode: -13, LoadError: "Permission denied",
				LibbpfLog:       lsmVerifierLog,
				ProgramSections: []string{"lsm/file_open"}, KernelBTFAvailable: true, ArtifactHasBTF: true,
			},
			wantCode: "VERIFIER_REJECTION",
		},
		{
			name: "lsm/file_open verifier rejection with EINVAL is a verifier rejection",
			in: Input{
				LoadStatus: "fail", LoadErrorCode: -22, LoadError: "Invalid argument",
				LibbpfLog: "libbpf: sec 'lsm/file_open': found program 'restrict_open'\n" +
					"libbpf: prog 'restrict_open': -- BEGIN PROG LOAD LOG --\n" +
					"R1 invalid mem access 'scalar'\n-- END PROG LOAD LOG --\n",
				ProgramSections: []string{"lsm/file_open"}, KernelBTFAvailable: true, ArtifactHasBTF: true,
			},
			wantCode: "VERIFIER_REJECTION",
		},
		{
			name: "lsm section with EPERM and no verifier log is a capability failure",
			in: Input{
				LoadStatus: "fail", LoadErrorCode: -1, LoadError: "Operation not permitted",
				LibbpfLog: "libbpf: sec 'lsm/file_open': found program 'restrict_open'\n" +
					"libbpf: prog 'restrict_open': BPF program load failed: Operation not permitted\n",
				ProgramSections: []string{"lsm/file_open"},
			},
			wantCode: "CAPABILITY_FAILURE",
		},
		{
			name: "eperm without verifier log stays a capability failure",
			in: Input{
				LoadStatus: "fail", LoadErrorCode: -1, LoadError: "Operation not permitted",
				LibbpfLog: "libbpf: prog 'handle_exec': BPF program load failed: Operation not permitted\n" +
					"libbpf: failed to load object 'probe.bpf.o'\n",
			},
			wantCode: "CAPABILITY_FAILURE",
			wantConf: "medium",
		},
		{
			name: "eacces without verifier log stays a capability failure",
			in: Input{
				LoadStatus: "fail", LoadErrorCode: -13, LoadError: "Permission denied",
				LibbpfLog: "libbpf: Error in bpf_object__probe_loading():Permission denied(-13).\n",
			},
			wantCode: "CAPABILITY_FAILURE",
			wantConf: "medium",
		},
		{
			name: "kernel lockdown stays a high-confidence policy denial",
			in: Input{
				LoadStatus: "fail", LoadErrorCode: -1, LoadError: "Operation not permitted",
				LibbpfLog: "Lockdown: validator: use of bpf to read kernel RAM is restricted; see man kernel_lockdown.7\n",
			},
			wantCode: "POLICY_DENIED",
			wantConf: "high",
		},
		{
			name: "unprivileged_bpf_disabled stays a high-confidence policy denial",
			in: Input{
				LoadStatus: "fail", LoadErrorCode: -1, LoadError: "Operation not permitted",
				LibbpfLog: "kernel.unprivileged_bpf_disabled = 2\n",
			},
			wantCode: "POLICY_DENIED",
			wantConf: "high",
		},
		{
			name: "selinux avc denial stays a policy denial",
			in: Input{
				LoadStatus: "fail", LoadErrorCode: -13, LoadError: "Permission denied",
				LibbpfLog: "audit: type=1400 audit(1700000000.123:42): avc:  denied  { prog_load } for pid=1234 " +
					"comm=\"validator\" scontext=system_u:system_r:container_t:s0 " +
					"tcontext=system_u:system_r:container_t:s0 tclass=bpf permissive=0\n",
			},
			wantCode: "POLICY_DENIED",
			wantConf: "medium",
		},
		{
			name: "selinux is preventing stays a policy denial",
			in: Input{
				LoadStatus: "fail", LoadErrorCode: -13, LoadError: "Permission denied",
				LibbpfLog: "SELinux is preventing validator from prog_load access on the bpf labeled container_t.\n",
			},
			wantCode: "POLICY_DENIED",
		},
		{
			name: "apparmor denial stays a policy denial",
			in: Input{
				LoadStatus: "fail", LoadErrorCode: -13, LoadError: "Permission denied",
				LibbpfLog: "audit: type=1400 apparmor=\"DENIED\" operation=\"capable\" profile=\"runner\" " +
					"capability=39 capname=\"bpf\"\n",
			},
			wantCode: "POLICY_DENIED",
		},
		{
			name: "explicit lsm= audit marker stays a policy denial",
			in: Input{
				LoadStatus: "fail", LoadErrorCode: -13, LoadError: "Permission denied",
				LibbpfLog: "audit: type=1400 lsm=landlock domain=1a2b3c blockers=bpf\n",
			},
			wantCode: "POLICY_DENIED",
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
		})
	}
}
