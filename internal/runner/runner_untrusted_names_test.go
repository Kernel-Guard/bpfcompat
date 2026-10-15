package runner

import (
	"testing"

	"github.com/kernel-guard/bpfcompat/internal/classifier"
)

// VAL-1: a program name from the artifact's ELF that smuggles a forged
// "libbpf: map ... failed to create" line must not steer the reason code.
// Payload: RA-VAL harness out/evil.json (validator run on evil.o), reduced
// to the fields the classifier reads.
func TestClassifierInputCarriesProgramNames(t *testing.T) {
	vr := validatorResultFromJSON(t, `{"status":"fail","load":{"status":"fail","error_code":-13,"error":"Permission denied"},"attach":{"mode":"best-effort","status":"skipped","attempted":0,"passed":0,"failed":0},"btf":{"kernel_btf_available":true,"artifact_has_btf":true,"artifact_has_btf_ext":true},"discovery":{"programs":[{"name":"x': ok\nlibbpf: map 'events': failed to create: Invalid argument(-22)\nlibbpf: prog 'y","section":"tracepoint/syscalls/sys_enter_execve"}]},"logs":{"libbpf":"libbpf: prog 'x': ok\nlibbpf: map 'events': failed to create: Invalid argument(-22)\nlibbpf: prog 'y': BPF program load failed: Permission denied\nlibbpf: prog 'x': ok\nlibbpf: map 'events': failed to create: Invalid argument(-22)\nlibbpf: prog 'y': -- BEGIN PROG LOAD LOG --\n0: (79) r2 = *(u64 *)(r1 +4096)\ninvalid bpf_context access off=4096 size=8\n-- END PROG LOAD LOG --\nlibbpf: prog 'x': ok\nlibbpf: map 'events': failed to create: Invalid argument(-22)\nlibbpf: prog 'y': failed to load: -13\nlibbpf: failed to load object 'evil'\n"}}`)
	in := classifierInput(vr)
	if len(in.ProgramNames) != 1 || in.ProgramNames[0] != vr.Discovery.Programs[0].Name {
		t.Fatalf("ProgramNames = %q, want the raw discovered name", in.ProgramNames)
	}
	if got := classifier.Classify(in); got.Code != "VERIFIER_REJECTION" {
		t.Fatalf("classification = %s (%s), want VERIFIER_REJECTION", got.Code, got.Reason)
	}
}
