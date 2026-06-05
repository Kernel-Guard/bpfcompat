package runtime

type SupportStatus string

const (
	SupportSupported   SupportStatus = "supported"
	SupportUnsupported SupportStatus = "unsupported"
	SupportUnknown     SupportStatus = "unknown"
)

type FeatureProbe struct {
	Status      SupportStatus `json:"status"`
	Confidence  string        `json:"confidence,omitempty"`
	Source      string        `json:"source,omitempty"`
	Reason      string        `json:"reason,omitempty"`
	Restricted  bool          `json:"restricted,omitempty"`
	Description string        `json:"description,omitempty"`
}

type HostCapabilities struct {
	SchemaVersion string `json:"schema_version"`
	CollectedAt   string `json:"collected_at"`
	Host          struct {
		Hostname string `json:"hostname"`
		Arch     string `json:"arch"`
	} `json:"host"`
	OS struct {
		ID         string `json:"id"`
		VersionID  string `json:"version_id"`
		PrettyName string `json:"pretty_name"`
	} `json:"os"`
	Kernel struct {
		Release string `json:"release"`
		Version string `json:"version,omitempty"`
	} `json:"kernel"`
	BTF struct {
		KernelAvailable bool `json:"kernel_available"`
	} `json:"btf"`
	ProbeMode string `json:"probe_mode"`
	Features  struct {
		MapRingbuf         FeatureProbe `json:"map_ringbuf"`
		MapPerfEventArray  FeatureProbe `json:"map_perf_event_array"`
		ProgTracepoint     FeatureProbe `json:"prog_tracepoint"`
		ProgKprobe         FeatureProbe `json:"prog_kprobe"`
		ProgTracing        FeatureProbe `json:"prog_tracing"`
		ProgXDP            FeatureProbe `json:"prog_xdp"`
		AttachTracefs      FeatureProbe `json:"attach_tracefs"`
		AttachKprobeEvents FeatureProbe `json:"attach_kprobe_events"`
	} `json:"features"`
	Warnings []string `json:"warnings,omitempty"`
}

type SelectionRequest struct {
	ArtifactName     string
	RequestedVersion string
	TargetProfileID  string
	Limit            int
	Policy           SelectionPolicy
}

type SelectionReason struct {
	Type    string `json:"type"`
	Weight  int    `json:"weight"`
	Details string `json:"details"`
}

type SelectionPolicy struct {
	RequireSummaryPass           bool     `json:"require_summary_pass,omitempty"`
	MinRequiredPassed            int      `json:"min_required_passed,omitempty"`
	MaxRequiredFailed            *int     `json:"max_required_failed,omitempty"`
	RequireKernelBTF             bool     `json:"require_kernel_btf,omitempty"`
	RequireAttachSupport         bool     `json:"require_attach_support,omitempty"`
	RequireRingbufSupport        bool     `json:"require_ringbuf_support,omitempty"`
	RequirePerfEventArraySupport bool     `json:"require_perf_event_array_support,omitempty"`
	DenyClassificationCodes      []string `json:"deny_classification_codes,omitempty"`
	AllowClassificationCodes     []string `json:"allow_classification_codes,omitempty"`
}

type SelectionCandidate struct {
	ArtifactVersion  string            `json:"artifact_version"`
	ArtifactVariant  string            `json:"artifact_variant,omitempty"`
	RunID            string            `json:"run_id"`
	SummaryStatus    string            `json:"summary_status"`
	Score            int               `json:"score"`
	Reasons          []SelectionReason `json:"reasons,omitempty"`
	PolicyAccepted   bool              `json:"policy_accepted"`
	PolicyViolations []string          `json:"policy_violations,omitempty"`
}

type SelectionResult struct {
	SchemaVersion      string               `json:"schema_version"`
	ArtifactName       string               `json:"artifact_name"`
	RequestedVersion   string               `json:"requested_version,omitempty"`
	TargetProfileID    string               `json:"target_profile_id,omitempty"`
	HostProfileHint    string               `json:"host_profile_hint,omitempty"`
	Policy             *SelectionPolicy     `json:"policy,omitempty"`
	Selected           SelectionCandidate   `json:"selected"`
	CandidatesReviewed int                  `json:"candidates_reviewed"`
	CandidatesAccepted int                  `json:"candidates_accepted"`
	Candidates         []SelectionCandidate `json:"candidates,omitempty"`
}

type FetchResult struct {
	SchemaVersion   string `json:"schema_version"`
	ArtifactName    string `json:"artifact_name"`
	ArtifactVersion string `json:"artifact_version"`
	ArtifactVariant string `json:"artifact_variant,omitempty"`
	SourcePath      string `json:"source_path"`
	OutputPath      string `json:"output_path"`
	ExpectedSHA256  string `json:"expected_sha256"`
	ActualSHA256    string `json:"actual_sha256"`
}
