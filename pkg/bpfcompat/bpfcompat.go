// Package bpfcompat is the embeddable API for validating compiled eBPF
// objects.
//
// The library mode — ValidateBeforeLoad / ValidateBytes — does a real load of a
// BPF object against the LOCAL running kernel, with no VM and no network. It is
// intended for a pre-load gate such as bpfman's: the node it runs on is the node
// the program will load on, so the running kernel IS the target. That is
// strictly more accurate than static ELF/BTF inference, and fast enough to sit
// in front of every load.
//
// Host-kernel loading is gated behind the "hostload" build tag. Binaries that
// must never load BPF on their own kernel (the public demo / server) are built
// WITHOUT the tag, and ValidateBeforeLoad then returns ErrHostLoadNotEnabled.
//
//	import "github.com/kernel-guard/bpfcompat/pkg/bpfcompat"
//
//	res, err := bpfcompat.ValidateBeforeLoad(ctx, "probe.bpf.o")
//	if err != nil { return err }
//	if !res.OK() {
//	    return fmt.Errorf("won't load on %s: %s", res.Kernel.Release, res.Classification.Reason)
//	}
package bpfcompat

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"

	"github.com/kernel-guard/bpfcompat/internal/runner"
	"github.com/kernel-guard/bpfcompat/pkg/schema"
)

// ErrHostLoadNotEnabled is returned by ValidateBeforeLoad / ValidateBytes when
// the package was built without the "hostload" build tag. Build with
// `-tags hostload` to enable host-kernel loading.
var ErrHostLoadNotEnabled = errors.New("bpfcompat: host-kernel loading not enabled (build with -tags hostload)")

// Mode selects how far validation goes.
type Mode int

const (
	// LoadOnly runs the verifier only — no attach. Fastest and least invasive;
	// the right choice for a pre-load gate. This is the default.
	LoadOnly Mode = iota
	// LoadAttach also attaches each program to its hook (best effort). More
	// invasive and requires the hook to exist on the running kernel. A program
	// that fails to attach is recorded but does not fail the result.
	LoadAttach
	// LoadAttachRequired attaches like LoadAttach, but the attach is part of
	// the contract, exactly as the CLI's required attach mode: every selected
	// program must be attached. A proven attach failure is Status "fail"
	// (ATTACH_FAILED); a selected program the validator cannot attach, or no
	// selected program at all, is "unsupported" (ATTACH_NOT_EXERCISED,
	// ATTACH_SCOPE_EMPTY); attach accounting that is missing (an older
	// validator) or contradictory is "infra_error"
	// (ATTACH_ACCOUNTING_UNAVAILABLE / _INCONSISTENT). Check Status or
	// Compatible(), not just OK().
	LoadAttachRequired
)

func (m Mode) attachFlag() string {
	switch m {
	case LoadAttach:
		return "best-effort"
	case LoadAttachRequired:
		return "required"
	default:
		return "disabled"
	}
}

// Result is the outcome of validating one object against one kernel.
type Result struct {
	// Loadable is the gate: did the object pass the verifier?
	Loadable bool

	// Status is the verdict the bpfcompat CLI reaches for the same validator
	// evidence: "pass", "fail", "unsupported" or "infra_error". It differs
	// from Loadable when the requested attach contract was not established
	// (LoadAttachRequired). Verdict is the matching schema verdict
	// (COMPATIBLE, INCOMPATIBLE, UNSUPPORTED, INFRA_ERROR); FailedStage is
	// "load", "attach", "validation", "infra" or empty.
	Status      string
	Verdict     string
	FailedStage string
	// Notes are the load/attach notes the CLI would record, e.g.
	// "attach not fully exercised: 1/2 selected programs attached, ...".
	Notes []string

	// Profile is the matrix profile id this result is for. Empty for
	// ValidateBeforeLoad (the target is simply the local kernel).
	Profile string

	Kernel         KernelInfo     // what it was validated against
	Load           LoadResult     // verifier status, errno, log tail
	Attach         AttachResult   // populated only when Mode == LoadAttach
	Capabilities   Capabilities   // live-probed kernel support
	Classification Classification // stable reason when not Loadable

	// RawJSON is the validator's full result document, for callers that want
	// everything (program_variants, map_fixups, auto_sized_maps, ...).
	RawJSON []byte
}

// OK reports whether the object is safe to load on this kernel: the verifier
// accepted it. It says nothing about attach; see Compatible.
func (r Result) OK() bool { return r.Loadable }

// Compatible reports whether the whole requested contract was established:
// the object loaded and, when an attach mode was requested, the attach
// requirements held (Verdict COMPATIBLE). With LoadAttachRequired this is the
// check to use.
func (r Result) Compatible() bool { return r.Verdict == schema.VerdictCompatible }

// KernelInfo identifies the kernel the object was validated against.
type KernelInfo struct {
	Release string // uname -r, e.g. "6.17.0-35-generic"
	Arch    string // uname -m
	BTF     bool   // kernel BTF present (/sys/kernel/btf/vmlinux)
}

// LoadResult is the verifier outcome.
type LoadResult struct {
	Status  string // "pass" | "fail"
	Errno   int    // 0 on success, negative errno on reject
	LogTail string // tail of the verifier message on failure
}

// AttachResult is the attach outcome (only meaningful in the LoadAttach modes).
type AttachResult struct {
	Mode      string
	Status    string
	Attempted int
	Passed    int
	Failed    int

	// Accounting says whether the fields below can be trusted: "v1" (the
	// validator accounted for every program and the counts add up),
	// "unavailable" (an older validator without accounting) or "inconsistent"
	// (the accounting contradicted itself and was discarded; see Notes). Only
	// with "v1" are the scope counts and Programs populated.
	Accounting string
	// Coverage is how much of the selected scope the attach phase exercised,
	// computed from scope and attempts, never from successes: "complete",
	// "partial", "none", "empty", "not_evaluated" or "unavailable".
	Coverage         string
	EffectiveMode    string
	ProgramCount     int
	Selected         int
	NotSelected      int
	Attachable       int
	NotAttachable    int
	RecordsTruncated bool
	// Programs is the per-program accounting: outcome ("attached", "failed",
	// "not_attachable_by_validator", "not_selected", "not_attempted"), and for
	// a failure the raw errno, detail, errno family (ReasonClass) and
	// Attribution "errno_only" (the errno family, not a diagnosed cause).
	Programs []AttachProgram
}

// AttachProgram is one program's attach accounting (the report schema type).
type AttachProgram = schema.AttachProgram

// Capabilities is what the kernel actually supports, as probed at validate
// time. Values are the validator's probe verdicts ("supported",
// "unsupported", "inconclusive", "permission_denied", ...).
type Capabilities struct {
	MapTypes     map[string]string
	ProgramTypes map[string]string
	BTF          bool
}

// Classification is a stable, machine-readable reason for a verdict — branch on
// Code, don't parse Reason. Empty when the object loaded cleanly.
type Classification struct {
	Code       string
	Confidence string
	Reason     string
}

// config is built up by Options.
type config struct {
	mode             Mode
	probeFeats       bool
	validatorBin     string   // override; empty => embedded (hostload build only)
	requiredPrograms []string // LoadAttachRequired: programs that must attach
}

// Option configures a validation call.
type Option func(*config)

// WithMode selects LoadOnly (default) or LoadAttach.
func WithMode(m Mode) Option { return func(c *config) { c.mode = m } }

// WithFeatureProbe enables the full kernel-capability census (slower; uses
// bpftool when present). Off by default — a pre-load gate only needs the load
// verdict, not a capability map.
func WithFeatureProbe(on bool) Option { return func(c *config) { c.probeFeats = on } }

// WithRequiredPrograms names programs that must be attached under
// LoadAttachRequired (the library equivalent of a manifest's
// attach.required). A named program that was not attached -- not selected,
// absent from the object, or beyond the validator's per-program records --
// makes the result "unsupported" (ATTACH_NOT_EXERCISED). Ignored in other
// modes.
func WithRequiredPrograms(names ...string) Option {
	return func(c *config) { c.requiredPrograms = append(c.requiredPrograms, names...) }
}

// WithValidator pins the validator binary path instead of using the embedded
// one. Useful for tests and for callers shipping their own validator.
func WithValidator(path string) Option { return func(c *config) { c.validatorBin = path } }

func newConfig(opts ...Option) config {
	c := config{mode: LoadOnly}
	for _, o := range opts {
		o(&c)
	}
	return c
}

// validatorProvider runs the validator against an artifact and returns its raw
// result document. It is the seam that decouples the public API from how
// validation is actually performed: the default execProvider runs the embedded
// static binary, and a future in-process CGO implementation can be dropped in
// behind this interface without changing Result or any exported function.
type validatorProvider interface {
	run(ctx context.Context, artifactPath string, c config) ([]byte, error)
}

// validateWith runs a provider and maps its result document into a Result. This
// is the always-built core shared by every entry point.
func validateWith(ctx context.Context, prov validatorProvider, artifactPath string, c config) (Result, error) {
	data, err := prov.run(ctx, artifactPath, c)
	if err != nil {
		return Result{}, err
	}
	return parseResult(data, c)
}

// execProvider runs an external validator binary (the embedded static validator
// once extracted, or a path supplied via WithValidator).
type execProvider struct{ bin string }

func (p execProvider) run(ctx context.Context, artifactPath string, c config) ([]byte, error) {
	outFile, err := os.CreateTemp("", "bpfcompat-result-*.json")
	if err != nil {
		return nil, fmt.Errorf("create result file: %w", err)
	}
	outPath := outFile.Name()
	_ = outFile.Close()
	defer os.Remove(outPath)

	probe := "false"
	if c.probeFeats {
		probe = "true"
	}
	args := []string{
		"--artifact", artifactPath,
		"--out", outPath,
		"--attach-mode", c.mode.attachFlag(),
		"--probe-features", probe,
	}
	cmd := exec.CommandContext(ctx, p.bin, args...)
	// The validator writes its verdict to --out; a non-zero exit is expected on
	// a failed load and is not an execution error. We only surface exec errors
	// when no result document was produced.
	combined, runErr := cmd.CombinedOutput()

	data, readErr := os.ReadFile(outPath)
	if readErr != nil || len(data) == 0 {
		if runErr != nil {
			return nil, fmt.Errorf("validator did not produce a result: %w (output: %s)", runErr, truncate(string(combined), 400))
		}
		return nil, fmt.Errorf("validator produced an empty result")
	}
	return data, nil
}

// validatorDoc is the subset of the validator's result schema the library
// maps directly. Load/attach evidence and the verdict come from
// runner.EvaluateValidatorResult, the same evaluation the CLI applies.
type validatorDoc struct {
	Host struct {
		Release string `json:"release"`
		Machine string `json:"machine"`
	} `json:"host"`
	BTF struct {
		KernelBTFAvailable bool `json:"kernel_btf_available"`
	} `json:"btf"`
	Capabilities struct {
		MapTypes     map[string]probe `json:"map_types"`
		ProgramTypes map[string]probe `json:"program_types"`
	} `json:"capabilities"`
	Logs struct {
		Libbpf string `json:"libbpf"`
	} `json:"logs"`
}

type probe struct {
	Status string `json:"status"`
}

func parseResult(data []byte, c config) (Result, error) {
	var d validatorDoc
	if err := json.Unmarshal(data, &d); err != nil {
		return Result{}, fmt.Errorf("parse validator result: %w", err)
	}
	var required []string
	if c.mode == LoadAttachRequired {
		required = c.requiredPrograms
	}
	ev, err := runner.EvaluateValidatorResult(data, c.mode.attachFlag(), required)
	if err != nil {
		return Result{}, err
	}
	v := ev.Validation

	res := Result{
		Loadable:    v.LoadStatus == "pass",
		Status:      ev.Status,
		Verdict:     ev.Verdict,
		FailedStage: ev.FailedStage,
		Notes:       ev.Notes,
		Kernel: KernelInfo{
			Release: d.Host.Release,
			Arch:    d.Host.Machine,
			BTF:     d.BTF.KernelBTFAvailable,
		},
		Load: LoadResult{
			Status:  v.LoadStatus,
			Errno:   v.LoadErrorCode,
			LogTail: tailOf(d.Logs.Libbpf, v.LoadError),
		},
		Attach: attachFromValidation(&v),
		Capabilities: Capabilities{
			MapTypes:     flattenProbes(d.Capabilities.MapTypes),
			ProgramTypes: flattenProbes(d.Capabilities.ProgramTypes),
			BTF:          d.BTF.KernelBTFAvailable,
		},
		Classification: Classification{
			Code:       ev.ClassificationCode,
			Confidence: ev.ClassificationConfidence,
			Reason:     ev.ClassificationReason,
		},
		RawJSON: data,
	}
	return res, nil
}

// attachFromValidation maps the report schema's attach evidence; the host-load
// and matrix paths share it so they cannot disagree on a field.
func attachFromValidation(v *schema.Validation) AttachResult {
	return AttachResult{
		Mode:             v.AttachMode,
		Status:           v.AttachStatus,
		Attempted:        v.AttachAttempted,
		Passed:           v.AttachPassed,
		Failed:           v.AttachFailed,
		Accounting:       v.AttachAccounting,
		Coverage:         v.AttachCoverage,
		EffectiveMode:    v.AttachEffectiveMode,
		ProgramCount:     v.AttachProgramCount,
		Selected:         v.AttachSelected,
		NotSelected:      v.AttachNotSelected,
		Attachable:       v.AttachAttachable,
		NotAttachable:    v.AttachNotAttachable,
		RecordsTruncated: v.AttachRecordsTruncated,
		Programs:         v.AttachPrograms,
	}
}

func flattenProbes(m map[string]probe) map[string]string {
	if len(m) == 0 {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v.Status
	}
	return out
}

func tailOf(libbpfLog, loadErr string) string {
	if libbpfLog != "" {
		return truncate(libbpfLog, 4096)
	}
	return loadErr
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[len(s)-n:]
}
