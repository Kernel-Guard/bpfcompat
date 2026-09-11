package regressiondiff

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/kernel-guard/bpfcompat/pkg/schema"
)

// The second trust-boundary pass. Gate 2 refused evidence that contradicted
// itself in the obvious spellings; these are the four ways a report could still
// be made to say one thing and decode as another, or to buy a comparison by
// deleting what proves the two runs were about the same thing.

// ---------------------------------------------------------------------------
// JSON field aliases
// ---------------------------------------------------------------------------

// The decoder's real behaviour, pinned. Everything the alias rule does follows
// from this test rather than from an assumption about how Go matches fields: an
// exact tag match is preferred and then a case-insensitive one, so two keys
// that differ only in case bind to one field and the later wins. Removing the
// underscore or spelling the Go field name does not bind, so the rule does not
// pretend it does.
func TestDecoderAliasBehaviourIsWhatTheRuleAssumes(t *testing.T) {
	for _, tc := range []struct {
		name, blob, want string
	}{
		{"later case variant wins", `{"verdict":"INCOMPATIBLE","Verdict":"COMPATIBLE"}`, "COMPATIBLE"},
		{"order decides which wins", `{"Verdict":"COMPATIBLE","verdict":"INCOMPATIBLE"}`, "INCOMPATIBLE"},
		{"upper case binds", `{"verdict":"INCOMPATIBLE","VERDICT":"COMPATIBLE"}`, "COMPATIBLE"},
		{"mixed case binds", `{"verdict":"INCOMPATIBLE","vErDiCt":"COMPATIBLE"}`, "COMPATIBLE"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var tg schema.Target
			if err := json.Unmarshal([]byte(tc.blob), &tg); err != nil {
				t.Fatal(err)
			}
			if tg.Verdict != tc.want {
				t.Fatalf("decoder bound %q, test assumed %q", tg.Verdict, tc.want)
			}
		})
	}

	// The negative half of the assumption, which is why the rule is a case
	// fold and not a looser normalisation.
	for _, tc := range []struct{ name, blob, want string }{
		{"underscore removed does not bind", `{"profile_id":"a","profileid":"b"}`, "a"},
		{"Go field name does not bind", `{"profile_id":"a","ProfileID":"b"}`, "a"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var tg schema.Target
			if err := json.Unmarshal([]byte(tc.blob), &tg); err != nil {
				t.Fatal(err)
			}
			if tg.ProfileID != tc.want {
				t.Fatalf("decoder bound %q, test assumed %q -- the alias rule would be wrong", tg.ProfileID, tc.want)
			}
		})
	}
}

func TestAliasedKeysAreRefused(t *testing.T) {
	base, _ := greenPair(t)
	valid := jsonOf(t, report(target("k", schema.VerdictIncompatible, true)))

	for _, tc := range []struct {
		name, find, replace string
	}{
		{"exact duplicate still refused", `"verdict": "INCOMPATIBLE"`, `"verdict": "INCOMPATIBLE",` + "\n" + `  "verdict": "COMPATIBLE"`},
		{"verdict and Verdict", `"verdict": "INCOMPATIBLE"`, `"verdict": "INCOMPATIBLE",` + "\n" + `  "Verdict": "COMPATIBLE"`},
		{"status and Status", `"status": "fail"`, `"status": "fail",` + "\n" + `  "Status": "pass"`},
		{"required and Required", `"required": true`, `"required": true,` + "\n" + `  "Required": false`},
		{"profile_id and PROFILE_ID", `"profile_id": "k"`, `"profile_id": "k",` + "\n" + `  "PROFILE_ID": "other"`},
		{"nested kernel_family_match", `"kernel_family_match": true`, `"kernel_family_match": true,` + "\n" + `   "Kernel_Family_Match": false`},
		{"report-level summary", `"summary": {`, `"Summary": {"verdict": "COMPATIBLE"},` + "\n" + ` "summary": {`},
		{"report-level targets", `"targets": [`, `"Targets": [],` + "\n" + ` "targets": [`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mutated := strings.Replace(valid, tc.find, tc.replace, 1)
			if mutated == valid {
				t.Fatalf("fixture did not mutate; looked for %q", tc.find)
			}
			_, exit, err := compareFiles(t, base, mutated)
			if err == nil {
				t.Fatal("two keys the decoder binds to one field are ambiguous evidence")
			}
			if exit != ExitInconclusive {
				t.Fatalf("want exit %d, got %d", ExitInconclusive, exit)
			}
		})
	}
}

// The whole point, end to end: a report that reads INCOMPATIBLE on every line a
// human would look at, and decodes to COMPATIBLE. Before the alias rule this
// produced NO_NEW_REGRESSIONS and exit 0.
func TestAliasingCannotTurnAnIncompatibleTargetIntoGreenEvidence(t *testing.T) {
	base, _ := greenPair(t)
	forged := jsonOf(t, report(target("k", schema.VerdictIncompatible, true)))
	// Every derived field made consistent with the aliased values, so nothing
	// but the alias rule can catch it.
	for find, replace := range map[string]string{
		`"status": "fail",`:                `"status": "fail", "Status": "pass",`,
		`"verdict": "INCOMPATIBLE",`:       `"verdict": "INCOMPATIBLE", "Verdict": "COMPATIBLE",`,
		`"verdict": "INCOMPATIBLE"` + "\n": `"verdict": "INCOMPATIBLE", "Verdict": "COMPATIBLE"` + "\n",
	} {
		forged = strings.ReplaceAll(forged, find, replace)
	}
	if !strings.Contains(forged, `"Verdict"`) {
		t.Fatal("fixture did not acquire an alias")
	}

	d, exit, err := compareFiles(t, base, forged)
	if err == nil {
		t.Fatalf("a report whose meaning depends on decoder internals was accepted as %s", d.Summary.Result)
	}
	if exit != ExitInconclusive {
		t.Fatalf("want exit %d, got %d", ExitInconclusive, exit)
	}
}

// Fail-closed must not mean fail-on-everything: ordinary distinct keys, and
// extension fields a future producer might add, still decode.
func TestUnrelatedKeysAreStillAccepted(t *testing.T) {
	base, _ := greenPair(t)
	valid := jsonOf(t, report(target("k", schema.VerdictCompatible, true)))
	noisy := strings.Replace(valid, `"profile_id": "k",`,
		`"profile_id": "k", "vendor_note": "x", "vendorNote": "y", "future_field": 1,`, 1)
	if noisy == valid {
		t.Fatal("fixture did not mutate")
	}
	d, exit, err := compareFiles(t, base, noisy)
	if err != nil {
		t.Fatalf("unrelated keys must not be refused: %v", err)
	}
	if exit != ExitNoRegressions || d.Summary.Result != ResultNoRegressions {
		t.Fatalf("want a clean comparison, got %s/exit %d", d.Summary.Result, exit)
	}
}

// ---------------------------------------------------------------------------
// kernel_family_match is verified, not believed
// ---------------------------------------------------------------------------

func envTarget(t *testing.T, requested, observed string, match *bool) schema.Target {
	t.Helper()
	tg := target("k", schema.VerdictCompatible, true)
	tg.Environment = &schema.EnvironmentCheck{
		RequestedKernelFamily: requested,
		ObservedKernel:        observed,
		KernelFamilyMatch:     match,
	}
	return tg
}

func TestRecordedKernelFamilyMatchMustAgreeWithItsOwnInputs(t *testing.T) {
	yes, no := true, false

	for _, tc := range []struct {
		name                string
		requested, observed string
		recorded            *bool
		wantRefused         bool
		wantEvidence        string
	}{
		{"correct true", "5.15", "5.15.0-186-generic", &yes, false, EnvironmentEstablishedEvidence},
		{"correct false", "4.18", "5.15.0-206.el8uek", &no, false, EnvironmentMismatchEvidence},
		{"correct false, different series", "5.15", "6.12.0-107.el9uek.x86_64", &no, false, EnvironmentMismatchEvidence},
		// The forgery Gate 2 accepted: a kernel series nothing tested, asserted
		// as established.
		{"forged true", "4.18", "5.15.0-206.el8uek", &yes, true, ""},
		{"forged false", "5.15", "5.15.0-186-generic", &no, true, ""},
		// A boolean whose inputs cannot produce one. The producer would have
		// left it unset.
		{"claimed but underivable", "rhel-latest", "unknown", &yes, true, ""},
		{"claimed but underivable, false", "rhel-latest", "unknown", &no, true, ""},
		// Absent stays unknown: readable, never established, never a mismatch.
		{"not recorded", "5.15", "5.15.0-186-generic", nil, false, EnvironmentUnknownEvidence},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := report(envTarget(t, tc.requested, tc.observed, tc.recorded))
			base, _ := greenPair(t)
			d, exit, err := compareFiles(t, base, jsonOf(t, r))

			if tc.wantRefused {
				if err == nil {
					t.Fatalf("an unverifiable environment claim was accepted as %s", d.Summary.Result)
				}
				if exit != ExitInconclusive {
					t.Fatalf("want exit %d, got %d", ExitInconclusive, exit)
				}
				return
			}
			if err != nil {
				t.Fatalf("honest evidence was refused: %v", err)
			}
			if got := onlyCell(t, d).Candidate.EnvironmentEvidence; got != tc.wantEvidence {
				t.Fatalf("environment evidence: want %q, got %q", tc.wantEvidence, got)
			}
		})
	}
}

// The mutation that must make the suite red: flipping the stored boolean while
// leaving its inputs alone.
func TestFlippingTheStoredKernelMatchIsDetected(t *testing.T) {
	base, _ := greenPair(t)
	honest := jsonOf(t, report(envTarget(t, "5.15", "5.15.0-186-generic", func() *bool { v := true; return &v }())))

	if _, _, err := compareFiles(t, base, honest); err != nil {
		t.Fatalf("the honest fixture must be accepted first: %v", err)
	}

	flipped := strings.Replace(honest, `"kernel_family_match": true`, `"kernel_family_match": false`, 1)
	if flipped == honest {
		t.Fatal("fixture did not mutate")
	}
	_, exit, err := compareFiles(t, base, flipped)
	if err == nil {
		t.Fatal("a flipped kernel_family_match must not be believed")
	}
	if !strings.Contains(err.Error(), "does not agree with itself") {
		t.Fatalf("the refusal must name the contradiction: %v", err)
	}
	if exit != ExitInconclusive {
		t.Fatalf("want exit %d, got %d", ExitInconclusive, exit)
	}
}

// One source of truth: whatever the producer's primitive records for a real
// profile/kernel pair, the verifier accepts. If the two ever drift, honest
// evidence starts being refused, and this fails first.
func TestProducerRecordedMatchesAlwaysVerify(t *testing.T) {
	for _, pair := range []struct{ requested, observed string }{
		{"5.15", "5.15.0-186-generic"},
		{"5.14", "5.14.0-687.36.1.el9_8.x86_64"},
		{"4.18", "5.15.0-206.el8uek"},
		{"6.1", "6.1.155"},
		{"4.14", "4.14.336-257.562.amzn2.x86_64"},
		{"6.12", "6.12.0-107.el9uek.x86_64"},
	} {
		match, derivable := schema.KernelFamilyMatch(pair.requested, pair.observed)
		if !derivable {
			t.Fatalf("%q/%q: a real profile pair must be derivable", pair.requested, pair.observed)
		}
		tg := envTarget(t, pair.requested, pair.observed, &match)
		if err := Validate(report(tg), "candidate"); err != nil {
			t.Fatalf("%q/%q: producer-recorded evidence was refused by the verifier: %v",
				pair.requested, pair.observed, err)
		}
	}
}

// ---------------------------------------------------------------------------
// One-sided loss of contract identity
// ---------------------------------------------------------------------------

func profiled(arch, distro, version, family string) schema.Target {
	tg := target("k", schema.VerdictCompatible, true)
	tg.Profile = &schema.TargetEnv{Arch: arch, Distro: distro, Version: version, KernelFamily: family}
	return tg
}

func TestOneSidedObligationMetadataIsInconclusive(t *testing.T) {
	full := profiled("x86_64", "rhel", "9", "5.14")

	for _, tc := range []struct {
		name       string
		base, cand schema.Target
		wantGreen  bool
	}{
		{"arch changed", full, profiled("arm64", "rhel", "9", "5.14"), false},
		{"arch lost by candidate", full, profiled("", "rhel", "9", "5.14"), false},
		{"arch only in candidate", profiled("", "rhel", "9", "5.14"), profiled("arm64", "rhel", "9", "5.14"), false},
		{"distro lost by candidate", full, profiled("x86_64", "", "9", "5.14"), false},
		{"version lost by candidate", full, profiled("x86_64", "rhel", "", "5.14"), false},
		{"kernel family lost by candidate", full, profiled("x86_64", "rhel", "9", ""), false},
		{"whole profile block lost", full, target("k", schema.VerdictCompatible, true), false},
		// Neither side ever recorded it: older evidence, still comparable.
		{"neither side records it", target("k", schema.VerdictCompatible, true), target("k", schema.VerdictCompatible, true), true},
		{"identical obligation", full, full, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, exit, err := compareFiles(t, jsonOf(t, report(tc.base)), jsonOf(t, report(tc.cand)))
			if err != nil {
				t.Fatalf("missing metadata is unusable evidence, not malformed: %v", err)
			}
			cell := onlyCell(t, d)
			if tc.wantGreen {
				if cell.Classification != UnchangedCompatible || exit != ExitNoRegressions {
					t.Fatalf("want a clean comparison, got %s/exit %d (%s)", cell.Classification, exit, cell.Reason)
				}
				return
			}
			if cell.Classification != Inconclusive {
				t.Fatalf("want %s, got %s (%s)", Inconclusive, cell.Classification, cell.Reason)
			}
			if exit != ExitInconclusive {
				t.Fatalf("want exit %d, got %d", ExitInconclusive, exit)
			}
		})
	}
}

// Deleting the candidate's metadata used to convert a changed obligation back
// into an unchanged one -- weakening the evidence bought a greener answer.
func TestDeletingObligationMetadataCannotRecoverGreen(t *testing.T) {
	changed := compareOf(t, profiled("x86_64", "rhel", "9", "5.14"), profiled("arm64", "rhel", "9", "5.14"))
	if changed != ExitInconclusive {
		t.Fatalf("precondition: a changed architecture is inconclusive, got exit %d", changed)
	}
	deleted := compareOf(t, profiled("x86_64", "rhel", "9", "5.14"), target("k", schema.VerdictCompatible, true))
	if deleted == ExitNoRegressions {
		t.Fatal("deleting the candidate's profile metadata turned an inconclusive comparison green")
	}
}

func compareOf(t *testing.T, base, cand schema.Target) int {
	t.Helper()
	_, exit, err := compareFiles(t, jsonOf(t, report(base)), jsonOf(t, report(cand)))
	if err != nil {
		return ExitInconclusive
	}
	return exit
}

func TestOneSidedValidationDepthIsInconclusive(t *testing.T) {
	withAttach := func(mode string) schema.Target {
		tg := target("k", schema.VerdictCompatible, true)
		if mode != "" {
			tg.Validation = &schema.Validation{AttachMode: mode}
		}
		return tg
	}
	for _, tc := range []struct {
		name       string
		base, cand string
		wantGreen  bool
	}{
		{"candidate lost its attach mode", "best-effort", "", false},
		{"only the candidate records one", "", "best-effort", false},
		{"changed attach mode", "best-effort", "disabled", false},
		{"same attach mode", "best-effort", "best-effort", true},
		{"neither records one", "", "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, exit, err := compareFiles(t,
				jsonOf(t, report(withAttach(tc.base))), jsonOf(t, report(withAttach(tc.cand))))
			if err != nil {
				t.Fatalf("unexpected refusal: %v", err)
			}
			cell := onlyCell(t, d)
			if tc.wantGreen {
				if cell.Classification != UnchangedCompatible || exit != ExitNoRegressions {
					t.Fatalf("want a clean comparison, got %s/exit %d", cell.Classification, exit)
				}
				return
			}
			if cell.Classification != Inconclusive || exit != ExitInconclusive {
				t.Fatalf("want %s/exit %d, got %s/exit %d (%s)",
					Inconclusive, ExitInconclusive, cell.Classification, exit, cell.Reason)
			}
		})
	}
}

func commandReport(t *testing.T, invocation string, exitCode *int, loaderSHA string) string {
	t.Helper()
	r := report(target("k", schema.VerdictCompatible, true))
	r.Validator = nil
	cmd := &schema.CommandInfo{
		InvocationSHA256: invocation,
		Binary:           &schema.BinaryIdentity{BaseName: "loader", SHA256: loaderSHA, SizeBytes: 9},
	}
	if exitCode != nil {
		cmd.ExpectedExitCode = *exitCode
	}
	r.Command = cmd
	blob := jsonOf(t, r)
	if exitCode == nil {
		// The Go type cannot express an absent int, so the field is removed
		// from the rendered JSON -- which is exactly the shape under test.
		blob = strings.Replace(blob, `"expected_exit_code": 0,`, "", 1)
		blob = strings.Replace(blob, `"expected_exit_code": 0`, "", 1)
		if strings.Contains(blob, "expected_exit_code") {
			t.Fatalf("fixture still carries expected_exit_code:\n%s", blob)
		}
	}
	if invocation == "" {
		blob = strings.Replace(blob, `"invocation_sha256": "",`, "", 1)
	}
	return blob
}

func TestOneSidedCommandContractIdentityIsInconclusive(t *testing.T) {
	zero, seven := 0, 7

	for _, tc := range []struct {
		name       string
		base, cand string
		wantGreen  bool
	}{
		{
			"same command and success contract",
			commandReport(t, "inv-A", &zero, "loader-v1"),
			commandReport(t, "inv-A", &zero, "loader-v2"), // the loader IS the product; it may change
			true,
		},
		{
			"different command",
			commandReport(t, "inv-A", &zero, "loader-v1"),
			commandReport(t, "inv-B", &zero, "loader-v2"),
			false,
		},
		{
			"candidate lost the command identity",
			commandReport(t, "inv-A", &zero, "loader-v1"),
			commandReport(t, "", &zero, "loader-v2"),
			false,
		},
		{
			"only the candidate records one",
			commandReport(t, "", &zero, "loader-v1"),
			commandReport(t, "inv-A", &zero, "loader-v2"),
			false,
		},
		{
			"different success contract",
			commandReport(t, "inv-A", &zero, "loader-v1"),
			commandReport(t, "inv-A", &seven, "loader-v2"),
			false,
		},
		{
			// The deletion that used to read as "expects 0", matching any
			// baseline that expects success.
			"candidate lost the success contract",
			commandReport(t, "inv-A", &zero, "loader-v1"),
			commandReport(t, "inv-A", nil, "loader-v2"),
			false,
		},
		{
			"neither records a success contract",
			commandReport(t, "inv-A", nil, "loader-v1"),
			commandReport(t, "inv-A", nil, "loader-v2"),
			true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, exit, err := compareFiles(t, tc.base, tc.cand)
			if err != nil {
				t.Fatalf("unexpected refusal: %v", err)
			}
			cell := onlyCell(t, d)
			if tc.wantGreen {
				if cell.Classification != UnchangedCompatible || exit != ExitNoRegressions {
					t.Fatalf("want a clean comparison, got %s/exit %d (%s)", cell.Classification, exit, cell.Reason)
				}
				return
			}
			if cell.Classification != Inconclusive || exit != ExitInconclusive {
				t.Fatalf("want %s/exit %d, got %s/exit %d (%s)",
					Inconclusive, ExitInconclusive, cell.Classification, exit, cell.Reason)
			}
			if len(d.Notes) == 0 {
				t.Fatal("a contract change must be stated in the evidence, not only in a cell")
			}
		})
	}
}

// Pre-Gate-1 evidence must stay readable: it lacks profile metadata, attach
// mode and environment alike, and none of the new one-sided rules may turn that
// into a parser error.
func TestOlderEvidenceRemainsReadableAndInconclusive(t *testing.T) {
	old := schema.ReportV01{
		SchemaVersion: "v0.1",
		Run:           schema.RunInfo{ID: fmt.Sprintf("legacy-%d", runIDs.Add(1))},
		Targets:       []schema.Target{{ProfileID: "k", Required: true, Status: "pass"}},
		Summary:       schema.SummaryInfo{Status: "pass"},
	}
	base, _ := greenPair(t)
	d, exit, err := compareFiles(t, jsonOf(t, old), base)
	if err != nil {
		t.Fatalf("an older report must remain readable, not a hard error: %v", err)
	}
	if got := onlyCell(t, d).Classification; got != Inconclusive {
		t.Fatalf("want %s, got %s", Inconclusive, got)
	}
	if exit != ExitInconclusive {
		t.Fatalf("want exit %d, got %d", ExitInconclusive, exit)
	}
}
