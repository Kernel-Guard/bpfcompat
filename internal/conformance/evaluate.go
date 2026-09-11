package conformance

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/kernel-guard/bpfcompat/pkg/schema"
)

var sha256Pattern = regexp.MustCompile(`^[a-fA-F0-9]{64}$`)

const maxConformanceReportBytes = 64 << 20

func LoadReport(path string) (ReportDocument, error) {
	file, err := os.Open(path)
	if err != nil {
		return ReportDocument{}, fmt.Errorf("read conformance report: %w", err)
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, maxConformanceReportBytes+1))
	if err != nil {
		return ReportDocument{}, fmt.Errorf("read conformance report: %w", err)
	}
	if len(raw) > maxConformanceReportBytes {
		return ReportDocument{}, fmt.Errorf("conformance report exceeds %d bytes", maxConformanceReportBytes)
	}
	if err := rejectDuplicateJSONKeys(raw); err != nil {
		return ReportDocument{}, fmt.Errorf("parse conformance report JSON: %w", err)
	}
	var report schema.ReportV01
	if err := json.Unmarshal(raw, &report); err != nil {
		return ReportDocument{}, fmt.Errorf("parse conformance report JSON: %w", err)
	}
	if strings.TrimSpace(report.Run.ID) == "" {
		return ReportDocument{}, errors.New("conformance report run.id is required")
	}
	return ReportDocument{Report: report, Raw: raw, SHA256: digestBytes(raw)}, nil
}

func Evaluate(profileDoc ProfileDocument, reportDoc ReportDocument, opts EvaluateOptions) (Evaluation, error) {
	if err := validateVerifierURI(opts.VerifierID); err != nil {
		return Evaluation{}, err
	}
	if opts.ReportURL != "" {
		if err := validateAbsoluteHTTPSURI("report URL", opts.ReportURL); err != nil {
			return Evaluation{}, err
		}
	}
	if len(profileDoc.Raw) == 0 || profileDoc.SHA256 == "" || len(profileDoc.MatrixRaw) == 0 || profileDoc.MatrixSHA256 == "" {
		return Evaluation{}, errors.New("loaded conformance profile document is incomplete")
	}
	if len(reportDoc.Raw) == 0 || reportDoc.SHA256 == "" {
		return Evaluation{}, errors.New("loaded conformance report document is incomplete")
	}

	now := time.Now().UTC()
	if opts.Now != nil {
		now = opts.Now().UTC()
	}
	ctx := newEvaluationContext(profileDoc, reportDoc, now)
	results := make([]AssertionResult, 0, len(profileDoc.Profile.Assertions))
	for _, assertion := range profileDoc.Profile.Assertions {
		result, err := ctx.evaluateAssertion(assertion)
		if err != nil {
			return Evaluation{}, err
		}
		results = append(results, result)
	}

	status := decisionStatus(results)
	subject, err := subjectDescriptor(reportDoc.Report, profileDoc.Profile.Subject)
	if err != nil {
		return Evaluation{}, err
	}
	validUntil := ""
	if startedAt, err := time.Parse(time.RFC3339, reportDoc.Report.Run.StartedAt); err == nil {
		validUntil = startedAt.UTC().AddDate(0, 0, profileDoc.Profile.Validity.SnapshotDays).Format(time.RFC3339)
	}

	decision := Decision{
		SchemaVersion: DecisionSchemaVersion,
		Status:        status,
		ProgramStatus: profileDoc.Profile.ProgramStatus,
		Claim:         strings.TrimSpace(profileDoc.Profile.Claim),
		Limitations:   append([]string(nil), profileDoc.Profile.Limitations...),
		Subject:       subject,
		Profile: EvaluatedResource{
			ID:     profileDoc.Profile.ID,
			URI:    profileDoc.Profile.ProfileURI,
			SHA256: profileDoc.SHA256,
		},
		Matrix: EvaluatedResource{
			ID:     profileDoc.Matrix.Name,
			URI:    profileDoc.Profile.Matrix.URI,
			SHA256: profileDoc.MatrixSHA256,
		},
		Report: EvaluatedReport{
			SchemaVersion: reportDoc.Report.SchemaVersion,
			RunID:         reportDoc.Report.Run.ID,
			StartedAt:     reportDoc.Report.Run.StartedAt,
			SHA256:        reportDoc.SHA256,
			URL:           strings.TrimSpace(opts.ReportURL),
		},
		Verifier:    VerifierIdentity{ID: strings.TrimSpace(opts.VerifierID)},
		TimeCreated: now.Format(time.RFC3339),
		ValidUntil:  validUntil,
		Assertions:  results,
		Targets:     ctx.targetEvidence(),
	}
	if status == StatusConformant {
		decision.Properties = append([]string(nil), profileDoc.Profile.Properties...)
	}

	testResult := buildTestResultStatement(decision)
	var verificationResult *Statement
	if status == StatusConformant {
		statement := buildVerificationResultStatement(decision)
		verificationResult = &statement
	}
	return Evaluation{
		Decision:           decision,
		TestResult:         testResult,
		VerificationResult: verificationResult,
	}, nil
}

type evaluationContext struct {
	profileDoc ProfileDocument
	reportDoc  ReportDocument
	now        time.Time
	targets    map[string][]*schema.Target
}

func newEvaluationContext(profileDoc ProfileDocument, reportDoc ReportDocument, now time.Time) evaluationContext {
	targets := make(map[string][]*schema.Target, len(reportDoc.Report.Targets))
	for i := range reportDoc.Report.Targets {
		target := &reportDoc.Report.Targets[i]
		id := strings.TrimSpace(target.ProfileID)
		targets[id] = append(targets[id], target)
	}
	return evaluationContext{profileDoc: profileDoc, reportDoc: reportDoc, now: now, targets: targets}
}

func (ctx evaluationContext) evaluateAssertion(assertion AssertionContract) (AssertionResult, error) {
	var status, summary string
	var evidence []string
	switch assertion.Rule {
	case RuleReportSchema:
		status, summary, evidence = ctx.evaluateReportSchema()
	case RuleReportFreshness:
		status, summary, evidence = ctx.evaluateReportFreshness()
	case RuleSubjectLoaderIdentity:
		status, summary, evidence = ctx.evaluateSubjectIdentity()
	case RuleCommandContract:
		status, summary, evidence = ctx.evaluateCommandContract()
	case RuleMatrixRequiredProfiles:
		status, summary, evidence = ctx.evaluateMatrixCoverage()
	case RuleEnvironmentIdentity:
		status, summary, evidence = ctx.evaluateEnvironmentIdentity()
	case RuleEnvironmentImageDigest:
		status, summary, evidence = ctx.evaluateImageDigests()
	case RuleBehaviorCommandPass:
		status, summary, evidence = ctx.evaluateCommandBehavior()
	default:
		return AssertionResult{}, fmt.Errorf("unsupported conformance assertion rule %q", assertion.Rule)
	}
	return AssertionResult{
		ID:          assertion.ID,
		Rule:        assertion.Rule,
		Description: assertion.Description,
		Status:      status,
		Summary:     summary,
		Evidence:    evidence,
	}, nil
}

func (ctx evaluationContext) evaluateReportSchema() (string, string, []string) {
	report := ctx.reportDoc.Report
	if !containsString(ctx.profileDoc.Profile.ReportSchemaVersions, report.SchemaVersion) {
		return AssertionInconclusive, "report schema is not allowed by the profile", []string{"schema_version=" + report.SchemaVersion}
	}
	if report.Summary.Status != "pass" && report.Summary.Status != "fail" {
		return AssertionInconclusive, "report summary status is missing or invalid", []string{"summary.status=" + report.Summary.Status}
	}
	return AssertionPass, "report schema and summary status are valid", []string{
		"schema_version=" + report.SchemaVersion,
		"summary.status=" + report.Summary.Status,
		"report.sha256=" + ctx.reportDoc.SHA256,
	}
}

func (ctx evaluationContext) evaluateReportFreshness() (string, string, []string) {
	startedAt, err := time.Parse(time.RFC3339, ctx.reportDoc.Report.Run.StartedAt)
	if err != nil {
		return AssertionInconclusive, "report run timestamp is missing or invalid", []string{"run.started_at=" + ctx.reportDoc.Report.Run.StartedAt}
	}
	startedAt = startedAt.UTC()
	validUntil := startedAt.AddDate(0, 0, ctx.profileDoc.Profile.Validity.SnapshotDays)
	evidence := []string{
		"run.started_at=" + startedAt.Format(time.RFC3339),
		"valid_until=" + validUntil.Format(time.RFC3339),
		"evaluated_at=" + ctx.now.Format(time.RFC3339),
	}
	if startedAt.After(ctx.now.Add(5 * time.Minute)) {
		return AssertionInconclusive, "report run timestamp is in the future", evidence
	}
	if ctx.now.After(validUntil) {
		return AssertionInconclusive, "report is outside the snapshot validity window", evidence
	}
	return AssertionPass, "report is inside the snapshot validity window", evidence
}

func (ctx evaluationContext) evaluateSubjectIdentity() (string, string, []string) {
	command := ctx.reportDoc.Report.Command
	if command == nil || command.Binary == nil {
		return AssertionInconclusive, "report does not identify a command loader binary", nil
	}
	binary := command.Binary
	evidence := []string{
		"binary.basename=" + binary.BaseName,
		"binary.sha256=" + strings.ToLower(binary.SHA256),
		fmt.Sprintf("binary.size_bytes=%d", binary.SizeBytes),
	}
	if binary.BaseName != ctx.profileDoc.Profile.Subject.BinaryBaseName {
		return AssertionInconclusive, "loader basename does not match the profile subject", evidence
	}
	if !isSHA256(binary.SHA256) || binary.SizeBytes <= 0 {
		return AssertionInconclusive, "loader binary identity is incomplete", evidence
	}
	return AssertionPass, "exact loader binary identity is recorded", evidence
}

func (ctx evaluationContext) evaluateCommandContract() (string, string, []string) {
	command := ctx.reportDoc.Report.Command
	if command == nil {
		return AssertionInconclusive, "report has no command contract", nil
	}
	expectedDigest := commandInvocationDigest(
		ctx.profileDoc.Profile.Subject.Command,
		ctx.profileDoc.Profile.Subject.ExpectedExitCode,
	)
	evidence := []string{
		"invocation.sha256=" + strings.ToLower(command.InvocationSHA256),
		"expected_invocation.sha256=" + expectedDigest,
		fmt.Sprintf("expected_exit_code=%d", command.ExpectedExitCode),
	}
	if !isSHA256(command.InvocationSHA256) || !strings.EqualFold(command.InvocationSHA256, expectedDigest) {
		return AssertionInconclusive, "recorded invocation does not match the profile command", evidence
	}
	if command.ExpectedExitCode != ctx.profileDoc.Profile.Subject.ExpectedExitCode {
		return AssertionInconclusive, "recorded expected exit code does not match the profile", evidence
	}
	return AssertionPass, "recorded invocation matches the profile command contract", evidence
}

func (ctx evaluationContext) evaluateMatrixCoverage() (string, string, []string) {
	reportProfiles := occurrences(ctx.reportDoc.Report.Matrix.Profiles)
	var issues []string
	evidence := make([]string, 0, len(ctx.profileDoc.Matrix.Profiles))
	for _, required := range ctx.profileDoc.Matrix.Profiles {
		id := required.ID
		evidence = append(evidence, "required_profile="+id)
		if reportProfiles[id] != 1 {
			issues = append(issues, fmt.Sprintf("matrix profile %s occurs %d times", id, reportProfiles[id]))
		}
		if len(ctx.targets[id]) != 1 {
			issues = append(issues, fmt.Sprintf("target %s occurs %d times", id, len(ctx.targets[id])))
			continue
		}
		if !ctx.targets[id][0].Required {
			issues = append(issues, "target "+id+" is not marked required")
		}
	}
	if len(issues) > 0 {
		sort.Strings(issues)
		return AssertionInconclusive, "required matrix coverage is incomplete or ambiguous", append(evidence, issues...)
	}
	return AssertionPass, "every canonical matrix profile appears exactly once and is required", evidence
}

func (ctx evaluationContext) evaluateEnvironmentIdentity() (string, string, []string) {
	var issues []string
	evidence := make([]string, 0, len(ctx.profileDoc.Profile.Environments))
	for _, expected := range ctx.profileDoc.Profile.Environments {
		target, ok := ctx.singleTarget(expected.ProfileID)
		if !ok {
			issues = append(issues, expected.ProfileID+": target missing or duplicated")
			continue
		}
		if target.Profile == nil || target.Host == nil {
			issues = append(issues, expected.ProfileID+": requested or actual environment missing")
			continue
		}
		requested := target.Profile
		host := target.Host
		if requested.Distro == "" || requested.Version == "" || requested.KernelFamily == "" || requested.Arch == "" ||
			host.Distro == "" || host.Version == "" || host.KernelFamily == "" || host.Kernel == "" || host.Arch == "" {
			issues = append(issues, expected.ProfileID+": environment identity is incomplete")
			continue
		}
		if requested.Distro != expected.Distro || requested.Version != expected.Version ||
			requested.KernelFamily != expected.KernelFamily || requested.Arch != expected.Arch {
			issues = append(issues, expected.ProfileID+": requested environment does not match the profile contract")
			continue
		}
		if host.Distro != expected.Distro || host.Version != expected.Version ||
			host.KernelFamily != expected.KernelFamily || host.Arch != expected.Arch {
			issues = append(issues, expected.ProfileID+": actual environment does not match the profile contract")
			continue
		}
		evidence = append(evidence, fmt.Sprintf("%s=%s/%s kernel=%s arch=%s", expected.ProfileID, host.Distro, host.Version, host.Kernel, host.Arch))
	}
	if len(issues) > 0 {
		sort.Strings(issues)
		return AssertionInconclusive, "one or more target environment identities are incomplete", append(evidence, issues...)
	}
	return AssertionPass, "requested environments and actual host kernels are recorded", evidence
}

func (ctx evaluationContext) evaluateImageDigests() (string, string, []string) {
	var issues []string
	evidence := make([]string, 0, len(ctx.profileDoc.Matrix.Profiles))
	for _, required := range ctx.profileDoc.Matrix.Profiles {
		target, ok := ctx.singleTarget(required.ID)
		if !ok {
			issues = append(issues, required.ID+": target missing or duplicated")
			continue
		}
		digest, err := imageDigestFromNotes(target.Notes)
		if err != nil {
			issues = append(issues, required.ID+": "+err.Error())
			continue
		}
		evidence = append(evidence, required.ID+".image.sha256="+digest)
	}
	if len(issues) > 0 {
		sort.Strings(issues)
		return AssertionInconclusive, "one or more booted image digests are unavailable", append(evidence, issues...)
	}
	return AssertionPass, "every required target records the booted image digest", evidence
}

func (ctx evaluationContext) evaluateCommandBehavior() (string, string, []string) {
	targetCount := len(ctx.profileDoc.Matrix.Profiles)
	productFailures := make([]string, 0, targetCount)
	inconclusive := make([]string, 0, targetCount)
	evidence := make([]string, 0, targetCount)
	for _, required := range ctx.profileDoc.Matrix.Profiles {
		target, ok := ctx.singleTarget(required.ID)
		if !ok {
			inconclusive = append(inconclusive, required.ID+": target missing or duplicated")
			continue
		}
		if target.Status == "infra_error" || strings.TrimSpace(target.InfraError) != "" {
			inconclusive = append(inconclusive, required.ID+": infrastructure error")
			continue
		}
		test, ok := commandFunctionalTest(target)
		if !ok {
			inconclusive = append(inconclusive, required.ID+": required command result missing or duplicated")
			continue
		}
		if test.Command != ctx.profileDoc.Profile.Subject.Command || test.ExpectedExitCode != ctx.profileDoc.Profile.Subject.ExpectedExitCode {
			inconclusive = append(inconclusive, required.ID+": per-target command contract differs")
			continue
		}
		if target.Status == "pass" && target.Functional != nil && target.Functional.Status == "pass" &&
			test.Status == "pass" && test.ExitCode == test.ExpectedExitCode {
			evidence = append(evidence, fmt.Sprintf("%s=pass exit=%d", required.ID, test.ExitCode))
			continue
		}
		if target.Status == "fail" && target.FailedStage == "command" &&
			target.ClassificationCode == "COMMAND_VALIDATION_FAILURE" && test.Status == "fail" {
			productFailures = append(productFailures, fmt.Sprintf("%s=fail exit=%d expected=%d", required.ID, test.ExitCode, test.ExpectedExitCode))
			continue
		}
		inconclusive = append(inconclusive, required.ID+": command result is internally inconsistent")
	}
	if len(productFailures) > 0 {
		sort.Strings(productFailures)
		sort.Strings(inconclusive)
		return AssertionFail, "the prescribed loader behavior failed on a required target", append(append(evidence, productFailures...), inconclusive...)
	}
	if len(inconclusive) > 0 {
		sort.Strings(inconclusive)
		return AssertionInconclusive, "the prescribed loader behavior was not completed on every required target", append(evidence, inconclusive...)
	}
	return AssertionPass, "the prescribed loader behavior passed on every required target", evidence
}

func (ctx evaluationContext) singleTarget(id string) (*schema.Target, bool) {
	targets := ctx.targets[id]
	if len(targets) != 1 {
		return nil, false
	}
	return targets[0], true
}

func (ctx evaluationContext) targetEvidence() []TargetEvidence {
	evidence := make([]TargetEvidence, 0, len(ctx.profileDoc.Matrix.Profiles))
	for _, required := range ctx.profileDoc.Matrix.Profiles {
		target, ok := ctx.singleTarget(required.ID)
		if !ok {
			evidence = append(evidence, TargetEvidence{ProfileID: required.ID, Status: "missing", Required: true})
			continue
		}
		entry := TargetEvidence{
			ProfileID:          target.ProfileID,
			Status:             target.Status,
			Required:           target.Required,
			ClassificationCode: target.ClassificationCode,
		}
		if target.Host != nil {
			entry.HostKernel = target.Host.Kernel
			entry.Architecture = target.Host.Arch
		}
		if digest, err := imageDigestFromNotes(target.Notes); err == nil {
			entry.ImageSHA256 = digest
		}
		evidence = append(evidence, entry)
	}
	return evidence
}

func decisionStatus(results []AssertionResult) string {
	status := StatusConformant
	for _, result := range results {
		if result.Status == AssertionFail {
			return StatusNonconformant
		}
		if result.Status == AssertionInconclusive {
			status = StatusInconclusive
		}
	}
	return status
}

func subjectDescriptor(report schema.ReportV01, contract SubjectContract) (ResourceDescriptor, error) {
	if report.Command != nil && report.Command.Binary != nil && isSHA256(report.Command.Binary.SHA256) {
		return ResourceDescriptor{
			Name:   report.Command.Binary.BaseName,
			Digest: map[string]string{"sha256": strings.ToLower(report.Command.Binary.SHA256)},
		}, nil
	}
	if isSHA256(report.Artifact.SHA256) {
		name := report.Artifact.BaseName
		if name == "" {
			name = contract.BinaryBaseName
		}
		return ResourceDescriptor{
			Name:   name,
			Digest: map[string]string{"sha256": strings.ToLower(report.Artifact.SHA256)},
		}, nil
	}
	return ResourceDescriptor{}, errors.New("report has no immutable SHA-256 subject identity")
}

func commandInvocationDigest(command string, expectedExit int) string {
	invocation := fmt.Sprintf("%s\x00expected-exit=%d", strings.TrimSpace(command), expectedExit)
	sum := sha256.Sum256([]byte(invocation))
	return hex.EncodeToString(sum[:])
}

func commandFunctionalTest(target *schema.Target) (*schema.FunctionalTest, bool) {
	if target.Functional == nil {
		return nil, false
	}
	var found []*schema.FunctionalTest
	for i := range target.Functional.Tests {
		test := &target.Functional.Tests[i]
		if test.Name == "command" && test.Required {
			found = append(found, test)
		}
	}
	if len(found) != 1 {
		return nil, false
	}
	return found[0], true
}

func imageDigestFromNotes(notes []string) (string, error) {
	const prefix = "base image sha256:"
	values := make(map[string]struct{})
	for _, note := range notes {
		trimmed := strings.TrimSpace(note)
		if !strings.HasPrefix(strings.ToLower(trimmed), prefix) {
			continue
		}
		value := strings.TrimSpace(trimmed[len(prefix):])
		if !isSHA256(value) {
			return "", errors.New("base image SHA-256 note is malformed")
		}
		values[strings.ToLower(value)] = struct{}{}
	}
	if len(values) == 0 {
		return "", errors.New("base image SHA-256 note is missing")
	}
	if len(values) != 1 {
		return "", errors.New("base image SHA-256 notes disagree")
	}
	for value := range values {
		return value, nil
	}
	panic("unreachable")
}

func occurrences(values []string) map[string]int {
	counts := make(map[string]int, len(values))
	for _, value := range values {
		counts[strings.TrimSpace(value)]++
	}
	return counts
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func isSHA256(value string) bool {
	return sha256Pattern.MatchString(strings.TrimSpace(value))
}

func validateVerifierURI(raw string) error {
	if strings.TrimSpace(raw) == "" {
		return errors.New("verifier ID is required")
	}
	return validateAbsoluteHTTPSURI("verifier ID", raw)
}

func validateAbsoluteHTTPSURI(field, raw string) error {
	parsed, err := url.ParseRequestURI(strings.TrimSpace(raw))
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
		return fmt.Errorf("%s must be an absolute https URI", field)
	}
	return nil
}
