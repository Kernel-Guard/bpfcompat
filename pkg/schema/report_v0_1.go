package schema

type ReportV01 struct {
	SchemaVersion string          `json:"schema_version"`
	Run           RunInfo         `json:"run"`
	Artifact      Artifact        `json:"artifact"`
	Command       *CommandInfo    `json:"command,omitempty"`
	Validator     *BinaryIdentity `json:"validator,omitempty"`
	Matrix        MatrixInfo      `json:"matrix"`
	Targets       []Target        `json:"targets,omitempty"`
	Summary       SummaryInfo     `json:"summary"`
	Paths         Paths           `json:"paths"`
}

type RunInfo struct {
	ID        string `json:"id"`
	StartedAt string `json:"started_at"`
}

type Artifact struct {
	Path   string `json:"path"`
	Source string `json:"source,omitempty"`
	// SourceDigest is the immutable content digest the OCI reference resolved
	// to at pull time. Without it a report whose source is a mutable tag
	// (":latest") cannot be tied back to a specific published image, because
	// the tag has since moved. Empty for local .bpf.o inputs, which are already
	// identified by SHA256.
	SourceDigest string `json:"source_digest,omitempty"`
	BaseName     string `json:"basename"`
	SHA256       string `json:"sha256"`
	SizeBytes    int64  `json:"size_bytes"`
}

// CommandInfo records command-mode provenance without exposing the command
// text, which can contain environment-specific or sensitive arguments.
type CommandInfo struct {
	InvocationSHA256 string          `json:"invocation_sha256"`
	ExpectedExitCode int             `json:"expected_exit_code"`
	Binary           *BinaryIdentity `json:"binary,omitempty"`
}

type BinaryIdentity struct {
	BaseName  string `json:"basename"`
	SHA256    string `json:"sha256"`
	SizeBytes int64  `json:"size_bytes"`
}

type MatrixInfo struct {
	Path     string   `json:"path"`
	Name     string   `json:"name,omitempty"`
	Profiles []string `json:"profiles"`
}

type SummaryInfo struct {
	Status string `json:"status"`
	// Verdict is the run-level compatibility contract result: COMPATIBLE,
	// INCOMPATIBLE, or INFRA_ERROR. New consumers should gate on this rather
	// than on Status.
	Verdict string `json:"verdict,omitempty"`
	// Complete is false when at least one target did not produce a
	// compatibility answer -- an infrastructure failure, an environment
	// bpfcompat cannot execute, or a guest whose kernel did not match the one
	// the profile requested. A COMPATIBLE run with Complete=false means
	// "nothing we managed to test was incompatible", not "the matrix passed".
	Complete *bool    `json:"complete,omitempty"`
	Notes    []string `json:"notes,omitempty"`
}

type Target struct {
	ProfileID string `json:"profile_id"`
	Required  bool   `json:"required"`
	Status    string `json:"status"`
	// Verdict classifies Status into the product contract taxonomy so that a
	// statement about the user's software (INCOMPATIBLE) is structurally
	// distinct from a statement about bpfcompat (INFRA_ERROR, UNSUPPORTED).
	Verdict                  string            `json:"verdict,omitempty"`
	Environment              *EnvironmentCheck `json:"environment,omitempty"`
	Profile                  *TargetEnv        `json:"profile,omitempty"`
	Host                     *TargetEnv        `json:"host,omitempty"`
	Validation               *Validation       `json:"validation,omitempty"`
	Functional               *Functional       `json:"functional,omitempty"`
	FailedStage              string            `json:"failed_stage,omitempty"`
	BTF                      *TargetBTF        `json:"btf,omitempty"`
	ClassificationCode       string            `json:"classification_code,omitempty"`
	ClassificationConfidence string            `json:"classification_confidence,omitempty"`
	ClassificationReason     string            `json:"classification_reason,omitempty"`
	StartedAt                string            `json:"started_at,omitempty"`
	FinishedAt               string            `json:"finished_at,omitempty"`
	DurationMs               int64             `json:"duration_ms,omitempty"`
	VMRunDir                 string            `json:"vm_run_dir,omitempty"`
	QEMUCommand              string            `json:"qemu_command,omitempty"`
	SerialLog                string            `json:"serial_log,omitempty"`
	ValidatorResult          string            `json:"validator_result,omitempty"`
	ValidatorExit            int               `json:"validator_exit"`
	InfraError               string            `json:"infra_error,omitempty"`
	Notes                    []string          `json:"notes,omitempty"`
}

// EnvironmentCheck records which environment was actually exercised, as opposed
// to the one the matrix asked for. The image identity makes a target
// reproducible; KernelFamilyMatch answers whether the guest that booted is the
// one the profile claims to validate.
type EnvironmentCheck struct {
	RequestedKernelFamily string `json:"requested_kernel_family,omitempty"`
	ObservedKernel        string `json:"observed_kernel,omitempty"`
	// KernelFamilyMatch is nil when the comparison could not be made (no
	// observed kernel, or an unparseable family), false when the guest booted a
	// materially different kernel series than the profile requested. A false
	// value means this target does not support a claim about the requested
	// environment, whatever its Status says.
	KernelFamilyMatch *bool  `json:"kernel_family_match,omitempty"`
	ImageSourceURL    string `json:"image_source_url,omitempty"`
	ImageSHA256       string `json:"image_sha256,omitempty"`
}

type TargetBTF struct {
	KernelBTFAvailable bool `json:"kernel_btf_available"`
	ArtifactHasBTF     bool `json:"artifact_has_btf"`
	ArtifactHasBTFExt  bool `json:"artifact_has_btf_ext"`
}

type TargetEnv struct {
	Distro       string `json:"distro,omitempty"`
	Version      string `json:"version,omitempty"`
	KernelFamily string `json:"kernel_family,omitempty"`
	Kernel       string `json:"kernel,omitempty"`
	Arch         string `json:"arch,omitempty"`
}

type Validation struct {
	LoadStatus      string `json:"load_status,omitempty"`
	LoadErrorCode   int    `json:"load_error_code,omitempty"`
	LoadError       string `json:"load_error,omitempty"`
	AttachMode      string `json:"attach_mode,omitempty"`
	AttachStatus    string `json:"attach_status,omitempty"`
	AttachAttempted int    `json:"attach_attempted,omitempty"`
	AttachPassed    int    `json:"attach_passed,omitempty"`
	AttachFailed    int    `json:"attach_failed,omitempty"`
}

type Functional struct {
	Status string           `json:"status,omitempty"`
	Tests  []FunctionalTest `json:"tests,omitempty"`
}

type FunctionalTest struct {
	Name             string `json:"name,omitempty"`
	Required         bool   `json:"required"`
	Status           string `json:"status,omitempty"`
	Command          string `json:"command,omitempty"`
	TimeoutSeconds   int    `json:"timeout_seconds,omitempty"`
	ExpectedExitCode int    `json:"expected_exit_code"`
	ExitCode         int    `json:"exit_code"`
	TimedOut         bool   `json:"timed_out,omitempty"`
	StdoutTail       string `json:"stdout_tail,omitempty"`
	StderrTail       string `json:"stderr_tail,omitempty"`
	Error            string `json:"error,omitempty"`
}

type Paths struct {
	RunDir   string `json:"run_dir"`
	JSON     string `json:"json"`
	Markdown string `json:"markdown,omitempty"`
}
