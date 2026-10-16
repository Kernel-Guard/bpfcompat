package runner

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/kernel-guard/bpfcompat/pkg/schema"
)

// A load that fails because the validator process ran out of file
// descriptors (EMFILE/ENFILE) says nothing about the artifact: every loaded
// program and every link holds an fd, and the guest's limit is the
// validator's environment. It must not read as INCOMPATIBLE.

func loadFailureDoc(t *testing.T, code int, msg string) []byte {
	t.Helper()
	r := fakeAttach{mode: "best-effort", accounting: true, programCount: 3, records: 3,
		selected: 3, attachable: 3, status: "skipped", loadFail: true,
		programs: []fakeProgram{
			{name: "a", section: "tracepoint/a/b", outcome: "not_attempted", autoload: true},
			{name: "b", section: "tracepoint/a/b", outcome: "not_attempted", autoload: true},
			{name: "c", section: "tracepoint/a/b", outcome: "not_attempted", autoload: true},
		}}
	var doc map[string]any
	if err := json.Unmarshal(r.json(t), &doc); err != nil {
		t.Fatal(err)
	}
	doc["load"] = map[string]any{"status": "fail", "error_code": code, "error": msg}
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestLoadOutOfFileDescriptorsIsAnInfrastructureLimit(t *testing.T) {
	for _, tc := range []struct {
		code int
		msg  string
	}{{-24, "Too many open files"}, {-23, "Too many open files in system"}} {
		got := runAttachTarget(t, "best-effort", validatorTuning{}, loadFailureDoc(t, tc.code, tc.msg))
		if got.Status != "infra_error" || got.Verdict != schema.VerdictInfraError {
			t.Fatalf("code %d: status=%q verdict=%q", tc.code, got.Status, got.Verdict)
		}
		if !strings.Contains(got.InfraError, "file descriptors") || !strings.Contains(got.InfraError, "not a property of the artifact") {
			t.Fatalf("code %d: reason %q", tc.code, got.InfraError)
		}
		if got.Validation == nil || got.Validation.LoadStatus != "fail" || got.Validation.LoadErrorCode != tc.code {
			t.Fatalf("code %d: load evidence must be kept: %+v", tc.code, got.Validation)
		}
	}
}

func TestOtherLoadFailuresStayIncompatible(t *testing.T) {
	for _, code := range []int{-22, -13, -7, -12, -1} {
		got := runAttachTarget(t, "best-effort", validatorTuning{}, loadFailureDoc(t, code, "x"))
		if got.Status != "fail" || got.Verdict != schema.VerdictIncompatible {
			t.Fatalf("code %d: status=%q verdict=%q", code, got.Status, got.Verdict)
		}
	}
}
