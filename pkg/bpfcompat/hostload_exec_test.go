//go:build hostload

package bpfcompat

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The host-load entry point runs a validator binary and must request the
// attach mode the caller asked for, then evaluate the document like the CLI.
// The validator here is a stub script (no BPF load, no privilege needed); it
// records its arguments and writes a fixed required-mode document.
func TestValidateBeforeLoadRequiredModeThroughValidatorExec(t *testing.T) {
	dir := t.TempDir()
	argsFile := filepath.Join(dir, "args")
	docFile := filepath.Join(dir, "doc.json")
	d := doc{mode: "required", accounting: true, status: "pass", attempted: 1, passed: 1, notAttachable: 1, programs: []prog{tpAttached, xdpUnexer}}
	if err := os.WriteFile(docFile, d.bytes(t), 0o600); err != nil {
		t.Fatal(err)
	}
	stub := filepath.Join(dir, "validator")
	script := "#!/bin/sh\necho \"$@\" > " + argsFile + "\nwhile [ $# -gt 0 ]; do\n  if [ \"$1\" = --out ]; then cp " + docFile + " \"$2\"; fi\n  shift\ndone\nexit 0\n"
	if err := os.WriteFile(stub, []byte(script), 0o700); err != nil { // #nosec G306 -- test stub must be executable.
		t.Fatal(err)
	}
	artifact := filepath.Join(dir, "probe.bpf.o")
	if err := os.WriteFile(artifact, []byte("not really ELF"), 0o600); err != nil {
		t.Fatal(err)
	}

	r, err := ValidateBeforeLoad(context.Background(), artifact, WithMode(LoadAttachRequired), WithValidator(stub))
	if err != nil {
		t.Fatal(err)
	}
	args, _ := os.ReadFile(argsFile)
	if !strings.Contains(string(args), "--attach-mode required") {
		t.Fatalf("validator not asked for required attach: %q", args)
	}
	if r.Status != "unsupported" || r.Classification.Code != "ATTACH_NOT_EXERCISED" || r.Attach.Coverage != "partial" || len(r.Attach.Programs) != 2 {
		t.Fatalf("got status=%s code=%s attach=%+v", r.Status, r.Classification.Code, r.Attach)
	}
}

// A real validator (the embedded static build, or $BPFCOMPAT_TEST_VALIDATOR)
// run through the library as an unprivileged user cannot load BPF; the result
// must still be a structured, classified answer, not a Go error. Skipped when
// run as root (it would really load on the host) or without a validator.
func TestValidateBeforeLoadRealValidatorUnprivileged(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root would load BPF on the host")
	}
	artifact := os.Getenv("BPFCOMPAT_TEST_ARTIFACT")
	if artifact == "" {
		artifact = filepath.Join("..", "..", "examples", "attach-coverage", "mixed.bpf.o")
	}
	if _, err := os.Stat(artifact); err != nil {
		t.Skipf("no test artifact (%v); run `make examples`", err)
	}
	if len(embeddedValidator) == 0 {
		t.Skip("no embedded validator; run `make pkg-embed-validator`")
	}
	r, err := ValidateBeforeLoad(context.Background(), artifact, WithMode(LoadAttachRequired))
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("unprivileged real validator: status=%s verdict=%s load=%s errno=%d code=%s accounting=%s coverage=%s",
		r.Status, r.Verdict, r.Load.Status, r.Load.Errno, r.Classification.Code, r.Attach.Accounting, r.Attach.Coverage)
	if r.Loadable || r.Compatible() || r.Status == "" || r.Verdict == "" {
		t.Fatalf("an unprivileged load cannot pass: %+v", r)
	}
}
