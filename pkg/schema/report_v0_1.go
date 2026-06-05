package schema

type ReportV01 struct {
	SchemaVersion string      `json:"schema_version"`
	Run           RunInfo     `json:"run"`
	Artifact      Artifact    `json:"artifact"`
	Matrix        MatrixInfo  `json:"matrix"`
	Targets       []Target    `json:"targets,omitempty"`
	Summary       SummaryInfo `json:"summary"`
	Paths         Paths       `json:"paths"`
}

type RunInfo struct {
	ID        string `json:"id"`
	StartedAt string `json:"started_at"`
}

type Artifact struct {
	Path      string `json:"path"`
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
	Status string   `json:"status"`
	Notes  []string `json:"notes,omitempty"`
}

type Target struct {
	ProfileID                string      `json:"profile_id"`
	Required                 bool        `json:"required"`
	Status                   string      `json:"status"`
	Profile                  *TargetEnv  `json:"profile,omitempty"`
	Host                     *TargetEnv  `json:"host,omitempty"`
	Validation               *Validation `json:"validation,omitempty"`
	Functional               *Functional `json:"functional,omitempty"`
	FailedStage              string      `json:"failed_stage,omitempty"`
	BTF                      *TargetBTF  `json:"btf,omitempty"`
	ClassificationCode       string      `json:"classification_code,omitempty"`
	ClassificationConfidence string      `json:"classification_confidence,omitempty"`
	ClassificationReason     string      `json:"classification_reason,omitempty"`
	StartedAt                string      `json:"started_at,omitempty"`
	FinishedAt               string      `json:"finished_at,omitempty"`
	DurationMs               int64       `json:"duration_ms,omitempty"`
	VMRunDir                 string      `json:"vm_run_dir,omitempty"`
	QEMUCommand              string      `json:"qemu_command,omitempty"`
	SerialLog                string      `json:"serial_log,omitempty"`
	ValidatorResult          string      `json:"validator_result,omitempty"`
	ValidatorExit            int         `json:"validator_exit,omitempty"`
	InfraError               string      `json:"infra_error,omitempty"`
	Notes                    []string    `json:"notes,omitempty"`
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
	ExpectedExitCode int    `json:"expected_exit_code,omitempty"`
	ExitCode         int    `json:"exit_code,omitempty"`
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
