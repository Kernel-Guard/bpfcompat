package conformance

import (
	"time"

	"github.com/kernel-guard/bpfcompat/pkg/schema"
)

const (
	ProfileSchemaVersion  = "bpfcompat_conformance_profile.v0.1"
	DecisionSchemaVersion = "bpfcompat_conformance_decision.v0.1"

	StatusConformant    = "conformant"
	StatusNonconformant = "nonconformant"
	StatusInconclusive  = "inconclusive"

	AssertionPass         = "pass"
	AssertionFail         = "fail"
	AssertionInconclusive = "inconclusive"

	StatementTypeV1            = "https://in-toto.io/Statement/v1"
	TestResultPredicateTypeV01 = "https://in-toto.io/attestation/test-result/v0.1"
	SVRPredicateTypeV02        = "https://in-toto.io/attestation/svr/v0.2"
)

type Profile struct {
	SchemaVersion        string                `yaml:"schema_version"`
	ID                   string                `yaml:"id"`
	Title                string                `yaml:"title"`
	ProgramStatus        string                `yaml:"program_status"`
	ProfileURI           string                `yaml:"profile_uri"`
	Claim                string                `yaml:"claim"`
	Limitations          []string              `yaml:"limitations,omitempty"`
	ReportSchemaVersions []string              `yaml:"report_schema_versions"`
	Subject              SubjectContract       `yaml:"subject"`
	Matrix               MatrixContract        `yaml:"matrix"`
	Environments         []EnvironmentContract `yaml:"environments"`
	Validity             ValidityContract      `yaml:"validity"`
	Assertions           []AssertionContract   `yaml:"assertions"`
	Properties           []string              `yaml:"properties"`
}

type SubjectContract struct {
	Kind             string `yaml:"kind"`
	BinaryBaseName   string `yaml:"binary_basename"`
	Command          string `yaml:"command"`
	ExpectedExitCode int    `yaml:"expected_exit_code"`
}

type MatrixContract struct {
	Path string `yaml:"path"`
	URI  string `yaml:"uri"`
}

type EnvironmentContract struct {
	ProfileID    string `yaml:"profile_id"`
	Distro       string `yaml:"distro"`
	Version      string `yaml:"version"`
	KernelFamily string `yaml:"kernel_family"`
	Arch         string `yaml:"arch"`
}

type ValidityContract struct {
	SnapshotDays         int `yaml:"snapshot_days"`
	ContinuousMaxAgeDays int `yaml:"continuous_max_age_days"`
}

type AssertionContract struct {
	ID          string `yaml:"id"`
	Rule        string `yaml:"rule"`
	Description string `yaml:"description"`
}

type ResourceDescriptor struct {
	Name   string            `json:"name,omitempty"`
	URI    string            `json:"uri,omitempty"`
	Digest map[string]string `json:"digest,omitempty"`
}

type Decision struct {
	SchemaVersion string             `json:"schema_version"`
	Status        string             `json:"status"`
	ProgramStatus string             `json:"program_status"`
	Claim         string             `json:"claim"`
	Limitations   []string           `json:"limitations,omitempty"`
	Subject       ResourceDescriptor `json:"subject"`
	Profile       EvaluatedResource  `json:"profile"`
	Matrix        EvaluatedResource  `json:"matrix"`
	Report        EvaluatedReport    `json:"report"`
	Verifier      VerifierIdentity   `json:"verifier"`
	TimeCreated   string             `json:"time_created"`
	ValidUntil    string             `json:"valid_until,omitempty"`
	Properties    []string           `json:"properties,omitempty"`
	Assertions    []AssertionResult  `json:"assertions"`
	Targets       []TargetEvidence   `json:"targets,omitempty"`
}

type EvaluatedResource struct {
	ID     string `json:"id"`
	URI    string `json:"uri,omitempty"`
	SHA256 string `json:"sha256"`
}

type EvaluatedReport struct {
	SchemaVersion string `json:"schema_version"`
	RunID         string `json:"run_id"`
	StartedAt     string `json:"started_at"`
	SHA256        string `json:"sha256"`
	URL           string `json:"url,omitempty"`
}

type VerifierIdentity struct {
	ID string `json:"id"`
}

type AssertionResult struct {
	ID          string   `json:"id"`
	Rule        string   `json:"rule"`
	Description string   `json:"description"`
	Status      string   `json:"status"`
	Summary     string   `json:"summary"`
	Evidence    []string `json:"evidence,omitempty"`
}

type TargetEvidence struct {
	ProfileID          string `json:"profile_id"`
	Status             string `json:"status"`
	Required           bool   `json:"required"`
	HostKernel         string `json:"host_kernel,omitempty"`
	Architecture       string `json:"architecture,omitempty"`
	ImageSHA256        string `json:"image_sha256,omitempty"`
	ClassificationCode string `json:"classification_code,omitempty"`
}

type Statement struct {
	Type          string               `json:"_type"`
	Subject       []ResourceDescriptor `json:"subject"`
	PredicateType string               `json:"predicateType"`
	Predicate     any                  `json:"predicate"`
}

type TestResultPredicate struct {
	Result        string               `json:"result"`
	Configuration []ResourceDescriptor `json:"configuration"`
	URL           string               `json:"url,omitempty"`
	PassedTests   []string             `json:"passedTests,omitempty"`
	WarnedTests   []string             `json:"warnedTests,omitempty"`
	FailedTests   []string             `json:"failedTests,omitempty"`
}

type SVRPredicate struct {
	Verifier    SVRVerifier `json:"verifier"`
	TimeCreated string      `json:"timeCreated"`
	Properties  []string    `json:"properties"`
}

type SVRVerifier struct {
	ID       string               `json:"id"`
	Policies []ResourceDescriptor `json:"policies"`
}

type Evaluation struct {
	Decision           Decision
	TestResult         Statement
	VerificationResult *Statement
}

type EvaluateOptions struct {
	VerifierID string
	ReportURL  string
	Now        func() time.Time
}

type ReportDocument struct {
	Report schema.ReportV01
	Raw    []byte
	SHA256 string
}
