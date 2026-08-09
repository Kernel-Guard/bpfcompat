package conformance

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kernel-guard/bpfcompat/pkg/schema"
)

const testVerifierID = "https://bpfcompat.kernelguard.net/verifiers/program/v0.1"

func TestEvaluateFalcoConformant(t *testing.T) {
	profile := loadFalcoProfile(t)
	report := loadFalcoReport(t)

	evaluation, err := Evaluate(profile, report, testEvaluationOptions())
	if err != nil {
		t.Fatalf("evaluate conformant report: %v", err)
	}
	if evaluation.Decision.Status != StatusConformant {
		t.Fatalf("decision status = %q, want %q: %+v", evaluation.Decision.Status, StatusConformant, evaluation.Decision.Assertions)
	}
	if evaluation.Decision.Subject.Name != "scap-open" ||
		evaluation.Decision.Subject.Digest["sha256"] != "1111111111111111111111111111111111111111111111111111111111111111" {
		t.Fatalf("unexpected subject: %+v", evaluation.Decision.Subject)
	}
	if evaluation.Decision.ValidUntil != "2026-11-04T12:00:00Z" {
		t.Fatalf("valid_until = %q", evaluation.Decision.ValidUntil)
	}
	if len(evaluation.Decision.Properties) != len(profile.Profile.Properties) {
		t.Fatalf("properties = %v, want %v", evaluation.Decision.Properties, profile.Profile.Properties)
	}
	for _, assertion := range evaluation.Decision.Assertions {
		if assertion.Status != AssertionPass {
			t.Fatalf("assertion %s = %s, want pass", assertion.ID, assertion.Status)
		}
	}
	if evaluation.VerificationResult == nil {
		t.Fatal("conformant evaluation did not produce an SVR")
	}
	if evaluation.VerificationResult.PredicateType != SVRPredicateTypeV02 {
		t.Fatalf("SVR predicate type = %q", evaluation.VerificationResult.PredicateType)
	}
	testResult, ok := evaluation.TestResult.Predicate.(TestResultPredicate)
	if !ok {
		t.Fatalf("test result predicate has type %T", evaluation.TestResult.Predicate)
	}
	if testResult.Result != "PASSED" || len(testResult.PassedTests) != len(profile.Profile.Assertions) {
		t.Fatalf("unexpected test result: %+v", testResult)
	}
}

func TestEvaluateFalcoProductFailure(t *testing.T) {
	profile := loadFalcoProfile(t)
	report := loadFalcoReport(t)
	target := &report.Report.Targets[2]
	target.Status = "fail"
	target.FailedStage = "command"
	target.ClassificationCode = "COMMAND_VALIDATION_FAILURE"
	target.Functional.Status = "fail"
	target.Functional.Tests[0].Status = "fail"
	target.Functional.Tests[0].ExitCode = 2
	report.Report.Summary.Status = "fail"
	report = reportDocumentFromStruct(t, report.Report)

	evaluation, err := Evaluate(profile, report, testEvaluationOptions())
	if err != nil {
		t.Fatalf("evaluate nonconformant report: %v", err)
	}
	if evaluation.Decision.Status != StatusNonconformant {
		t.Fatalf("decision status = %q, want %q", evaluation.Decision.Status, StatusNonconformant)
	}
	if evaluation.VerificationResult != nil {
		t.Fatal("nonconformant evaluation produced an SVR")
	}
	assertion := assertionForRule(t, evaluation.Decision, RuleBehaviorCommandPass)
	if assertion.Status != AssertionFail {
		t.Fatalf("behavior assertion = %q, want fail", assertion.Status)
	}
	testResult := evaluation.TestResult.Predicate.(TestResultPredicate)
	if testResult.Result != "FAILED" || len(testResult.FailedTests) != 1 || testResult.FailedTests[0] != assertion.ID {
		t.Fatalf("unexpected failed test result: %+v", testResult)
	}
}

func TestEvaluateFalcoInfrastructureFailureIsInconclusive(t *testing.T) {
	profile := loadFalcoProfile(t)
	report := loadFalcoReport(t)
	target := &report.Report.Targets[0]
	target.Status = "infra_error"
	target.FailedStage = "infra"
	target.InfraError = "guest did not become reachable"
	target.Host = nil
	target.Functional = nil
	report.Report.Summary.Status = "fail"
	report = reportDocumentFromStruct(t, report.Report)

	evaluation, err := Evaluate(profile, report, testEvaluationOptions())
	if err != nil {
		t.Fatalf("evaluate inconclusive report: %v", err)
	}
	if evaluation.Decision.Status != StatusInconclusive {
		t.Fatalf("decision status = %q, want %q", evaluation.Decision.Status, StatusInconclusive)
	}
	if evaluation.VerificationResult != nil {
		t.Fatal("inconclusive evaluation produced an SVR")
	}
	assertion := assertionForRule(t, evaluation.Decision, RuleBehaviorCommandPass)
	if assertion.Status != AssertionInconclusive {
		t.Fatalf("behavior assertion = %q, want inconclusive", assertion.Status)
	}
	testResult := evaluation.TestResult.Predicate.(TestResultPredicate)
	if testResult.Result != "WARNED" || len(testResult.WarnedTests) == 0 {
		t.Fatalf("unexpected inconclusive test result: %+v", testResult)
	}
}

func TestEvaluateKnownProductFailureOutranksInfrastructureGap(t *testing.T) {
	profile := loadFalcoProfile(t)
	report := loadFalcoReport(t)
	failed := &report.Report.Targets[0]
	failed.Status = "fail"
	failed.FailedStage = "command"
	failed.ClassificationCode = "COMMAND_VALIDATION_FAILURE"
	failed.Functional.Status = "fail"
	failed.Functional.Tests[0].Status = "fail"
	failed.Functional.Tests[0].ExitCode = 7
	infrastructure := &report.Report.Targets[1]
	infrastructure.Status = "infra_error"
	infrastructure.FailedStage = "infra"
	infrastructure.InfraError = "runner unavailable"
	infrastructure.Functional = nil
	report.Report.Summary.Status = "fail"
	report = reportDocumentFromStruct(t, report.Report)

	evaluation, err := Evaluate(profile, report, testEvaluationOptions())
	if err != nil {
		t.Fatalf("evaluate mixed report: %v", err)
	}
	if evaluation.Decision.Status != StatusNonconformant {
		t.Fatalf("decision status = %q, want %q", evaluation.Decision.Status, StatusNonconformant)
	}
}

func TestEvaluateWrongCommandAndExpiredReportAreInconclusive(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*ReportDocument)
		now    time.Time
		rule   string
	}{
		{
			name: "wrong command digest",
			mutate: func(report *ReportDocument) {
				report.Report.Command.InvocationSHA256 = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
			},
			now:  time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC),
			rule: RuleCommandContract,
		},
		{
			name:   "expired report",
			mutate: func(*ReportDocument) {},
			now:    time.Date(2026, 11, 5, 12, 0, 1, 0, time.UTC),
			rule:   RuleReportFreshness,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			profile := loadFalcoProfile(t)
			report := loadFalcoReport(t)
			test.mutate(&report)
			report = reportDocumentFromStruct(t, report.Report)
			opts := testEvaluationOptions()
			opts.Now = func() time.Time { return test.now }
			evaluation, err := Evaluate(profile, report, opts)
			if err != nil {
				t.Fatalf("evaluate: %v", err)
			}
			if evaluation.Decision.Status != StatusInconclusive {
				t.Fatalf("decision status = %q, want inconclusive", evaluation.Decision.Status)
			}
			if assertion := assertionForRule(t, evaluation.Decision, test.rule); assertion.Status != AssertionInconclusive {
				t.Fatalf("assertion %s = %s, want inconclusive", assertion.ID, assertion.Status)
			}
		})
	}
}

func TestEvaluateEnvironmentMustMatchProfileContract(t *testing.T) {
	profile := loadFalcoProfile(t)
	report := loadFalcoReport(t)
	report.Report.Targets[0].Profile.Distro = "debian"
	report.Report.Targets[0].Host.Distro = "debian"
	report = reportDocumentFromStruct(t, report.Report)

	evaluation, err := Evaluate(profile, report, testEvaluationOptions())
	if err != nil {
		t.Fatalf("evaluate mismatched environment: %v", err)
	}
	if evaluation.Decision.Status != StatusInconclusive {
		t.Fatalf("decision status = %q, want inconclusive", evaluation.Decision.Status)
	}
	assertion := assertionForRule(t, evaluation.Decision, RuleEnvironmentIdentity)
	if assertion.Status != AssertionInconclusive {
		t.Fatalf("environment assertion = %q, want inconclusive", assertion.Status)
	}
}

func TestWriteEvaluationRemovesStaleSVR(t *testing.T) {
	profile := loadFalcoProfile(t)
	report := loadFalcoReport(t)
	pass, err := Evaluate(profile, report, testEvaluationOptions())
	if err != nil {
		t.Fatal(err)
	}
	outDir := t.TempDir()
	paths, err := WriteEvaluation(outDir, pass)
	if err != nil {
		t.Fatalf("write pass evaluation: %v", err)
	}
	if _, err := os.Stat(paths.VerificationResult); err != nil {
		t.Fatalf("stat SVR: %v", err)
	}

	report.Report.Targets[0].Status = "infra_error"
	report.Report.Targets[0].InfraError = "no KVM"
	report.Report.Targets[0].Functional = nil
	report.Report.Summary.Status = "fail"
	report = reportDocumentFromStruct(t, report.Report)
	inconclusive, err := Evaluate(profile, report, testEvaluationOptions())
	if err != nil {
		t.Fatal(err)
	}
	paths, err = WriteEvaluation(outDir, inconclusive)
	if err != nil {
		t.Fatalf("write inconclusive evaluation: %v", err)
	}
	if paths.VerificationResult != "" {
		t.Fatalf("inconclusive paths contain SVR: %+v", paths)
	}
	if _, err := os.Stat(filepath.Join(outDir, VerificationResultFileName)); !os.IsNotExist(err) {
		t.Fatalf("stale SVR still exists: %v", err)
	}
	for _, path := range []string{paths.Decision, paths.TestResult} {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		var value any
		if err := json.Unmarshal(raw, &value); err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
	}
}

func TestLoadReportRejectsDuplicateKeys(t *testing.T) {
	path := filepath.Join(t.TempDir(), "report.json")
	raw := []byte(`{"schema_version":"v0.1","schema_version":"v9","run":{"id":"run"}}`)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadReport(path); err == nil || !strings.Contains(err.Error(), "duplicate object key") {
		t.Fatalf("expected duplicate-key error, got %v", err)
	}
}

func loadFalcoProfile(t *testing.T) ProfileDocument {
	t.Helper()
	path := filepath.Join("..", "..", "conformance", "falco-modern-bpf-v0.1", "profile.yaml")
	profile, err := LoadProfile(path)
	if err != nil {
		t.Fatalf("load Falco profile: %v", err)
	}
	return profile
}

func loadFalcoReport(t *testing.T) ReportDocument {
	t.Helper()
	report, err := LoadReport(filepath.Join("testdata", "falco-pass-report.json"))
	if err != nil {
		t.Fatalf("load Falco report fixture: %v", err)
	}
	return report
}

func reportDocumentFromStruct(t *testing.T, report schema.ReportV01) ReportDocument {
	t.Helper()
	raw, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("marshal report fixture: %v", err)
	}
	return ReportDocument{Report: report, Raw: raw, SHA256: digestBytes(raw)}
}

func testEvaluationOptions() EvaluateOptions {
	return EvaluateOptions{
		VerifierID: testVerifierID,
		ReportURL:  "https://github.com/falcosecurity/libs/actions/runs/123456789",
		Now: func() time.Time {
			return time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
		},
	}
}

func assertionForRule(t *testing.T, decision Decision, rule string) AssertionResult {
	t.Helper()
	for _, assertion := range decision.Assertions {
		if assertion.Rule == rule {
			return assertion
		}
	}
	t.Fatalf("decision has no assertion for rule %q", rule)
	return AssertionResult{}
}
