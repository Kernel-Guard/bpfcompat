package bpfcompat

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kernel-guard/bpfcompat/pkg/schema"
)

// cliGoldenEntry is one entry of the CLI golden fixture written by
// internal/runner's TestExecuteTargetGolden: a validator document, the
// attach mode and required programs it was evaluated with, and the target
// the CLI's executeTarget built from it.
type cliGoldenEntry struct {
	Name             string          `json:"name"`
	AttachMode       string          `json:"attach_mode"`
	RequiredPrograms []string        `json:"required_programs"`
	Document         json.RawMessage `json:"validator_document"`
	RunVerdict       string          `json:"run_verdict"`
	Target           schema.Target   `json:"target"`
}

func loadCLIGolden(t *testing.T) []cliGoldenEntry {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "internal", "runner", "testdata", "execute_target_golden.json"))
	if err != nil {
		t.Fatal(err)
	}
	var entries []cliGoldenEntry
	if err := json.Unmarshal(raw, &entries); err != nil {
		t.Fatal(err)
	}
	if len(entries) == 0 {
		t.Fatal("empty CLI golden")
	}
	return entries
}

func modeForAttachFlag(t *testing.T, flag string) Mode {
	t.Helper()
	switch flag {
	case "required":
		return LoadAttachRequired
	case "best-effort":
		return LoadAttach
	case "disabled":
		return LoadOnly
	}
	t.Fatalf("unknown attach mode %q", flag)
	return LoadOnly
}

// TestLibraryMatchesCLIGolden replays every validator document the CLI
// golden pins through both library frontends and requires the CLI's answer:
//
//   - host-load (parseResult): the same status, verdict, failed stage,
//     classification, infra reason and attach evidence as the CLI target for
//     the same document, attach mode and required programs;
//   - matrix (resultFromTarget over the CLI's own target): Compatible() is
//     true exactly when the CLI run over that target, made required, is
//     COMPATIBLE -- including a target whose guest booted another kernel
//     series or distribution than requested.
//
// The cases cover load failure, EMFILE and ENFILE, functional failure and
// pass, required attach complete/partial/not exercised/empty/failed,
// accounting unavailable and inconsistent, unrecognized status, and the
// wrong-kernel environment.
func TestLibraryMatchesCLIGolden(t *testing.T) {
	seen := map[string]bool{}
	for _, e := range loadCLIGolden(t) {
		t.Run(e.Name, func(t *testing.T) {
			cli := e.Target
			mode := modeForAttachFlag(t, e.AttachMode)
			opts := []Option{WithMode(mode)}
			if len(e.RequiredPrograms) > 0 {
				opts = append(opts, WithRequiredPrograms(e.RequiredPrograms...))
			}
			r, err := parseResult(e.Document, newConfig(opts...))
			if err != nil {
				t.Fatal(err)
			}
			if r.Status != cli.Status || r.Verdict != cli.Verdict || r.FailedStage != cli.FailedStage {
				t.Errorf("host-load status/verdict/stage = %s/%s/%s, CLI %s/%s/%s",
					r.Status, r.Verdict, r.FailedStage, cli.Status, cli.Verdict, cli.FailedStage)
			}
			if r.Classification.Code != cli.ClassificationCode || r.Classification.Confidence != cli.ClassificationConfidence ||
				r.Classification.Reason != cli.ClassificationReason {
				t.Errorf("host-load classification = %s/%s/%q, CLI %s/%s/%q",
					r.Classification.Code, r.Classification.Confidence, r.Classification.Reason,
					cli.ClassificationCode, cli.ClassificationConfidence, cli.ClassificationReason)
			}
			// The library has no InfraError field: the CLI's infra reason must
			// reach the caller as the classification reason or a note. (An
			// unrecognized validator status carries neither, on both sides
			// only the status says so.)
			if cli.Status == "infra_error" && !strings.HasPrefix(cli.InfraError, "unrecognized validator status") &&
				r.Classification.Reason != cli.InfraError && !noteContains(r.Notes, cli.InfraError) {
				t.Errorf("host-load infra reason missing: CLI %q, library reason %q notes %q", cli.InfraError, r.Classification.Reason, r.Notes)
			}
			if cli.Validation == nil {
				t.Fatal("CLI target has no validation block")
			}
			if got, want := r.Attach, attachFromValidation(cli.Validation); !attachEqual(got, want) {
				t.Errorf("host-load attach evidence differs:\n got  %+v\n want %+v", got, want)
			}

			m := resultFromTarget(cli)
			required := cli
			required.Required = true
			wantCompatible := schema.RunVerdict([]schema.Target{required}) == schema.VerdictCompatible
			if m.Compatible() != wantCompatible {
				t.Errorf("matrix Compatible() = %v, CLI run verdict for the required target = %s",
					m.Compatible(), schema.RunVerdict([]schema.Target{required}))
			}
			if m.Status != cli.Status || m.Verdict != cli.Verdict || m.Classification.Code != cli.ClassificationCode {
				t.Errorf("matrix result %s/%s/%s, CLI %s/%s/%s", m.Status, m.Verdict, m.Classification.Code,
					cli.Status, cli.Verdict, cli.ClassificationCode)
			}
			seen[cli.Status+"/"+cli.ClassificationCode] = true
			if !schema.EstablishedRequestedEnvironment(&cli) {
				seen["environment-not-established"] = true
			}
		})
	}
	for _, want := range []string{
		"pass/", "fail/UNKNOWN", "fail/FUNCTIONAL_TEST_FAILURE", "fail/ATTACH_FAILED", "fail/UNSUPPORTED_PROGRAM_TYPE",
		"unsupported/ATTACH_NOT_EXERCISED", "unsupported/ATTACH_SCOPE_EMPTY",
		"infra_error/ATTACH_ACCOUNTING_UNAVAILABLE", "infra_error/ATTACH_ACCOUNTING_INCONSISTENT", "infra_error/",
		"environment-not-established",
	} {
		if !seen[want] {
			t.Errorf("CLI golden has no case for %s", want)
		}
	}
}

// attachEqual compares attach evidence by its JSON form: the CLI golden
// round-trips through JSON, so a nil and an empty program list are the same.
func attachEqual(a, b AttachResult) bool {
	if len(a.Programs) == 0 {
		a.Programs = nil
	}
	if len(b.Programs) == 0 {
		b.Programs = nil
	}
	ja, errA := json.Marshal(a)
	jb, errB := json.Marshal(b)
	return errA == nil && errB == nil && string(ja) == string(jb)
}
