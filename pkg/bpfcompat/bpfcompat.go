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

	"github.com/kernel-guard/bpfcompat/internal/classifier"
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
	// LoadAttach also attaches each program to its hook. More invasive and
	// requires the hook to exist on the running kernel.
	LoadAttach
)

func (m Mode) attachFlag() string {
	if m == LoadAttach {
		return "best-effort"
	}
	return "disabled"
}

// Result is the outcome of validating one object against one kernel.
type Result struct {
	// Loadable is the gate: did the object pass the verifier?
	Loadable bool

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

// OK reports whether the object is safe to load on this kernel.
func (r Result) OK() bool { return r.Loadable }

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

// AttachResult is the attach outcome (only meaningful in LoadAttach mode).
type AttachResult struct {
	Mode      string
	Status    string
	Attempted int
	Passed    int
	Failed    int
}

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
	mode         Mode
	probeFeats   bool
	validatorBin string // override; empty => embedded (hostload build only)
}

// Option configures a validation call.
type Option func(*config)

// WithMode selects LoadOnly (default) or LoadAttach.
func WithMode(m Mode) Option { return func(c *config) { c.mode = m } }

// WithFeatureProbe enables the full kernel-capability census (slower; uses
// bpftool when present). Off by default — a pre-load gate only needs the load
// verdict, not a capability map.
func WithFeatureProbe(on bool) Option { return func(c *config) { c.probeFeats = on } }

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
	return parseResult(data)
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

// validatorDoc is the subset of the validator's result schema we map from.
type validatorDoc struct {
	Status string `json:"status"`
	Host   struct {
		Release string `json:"release"`
		Machine string `json:"machine"`
	} `json:"host"`
	Load struct {
		Status    string `json:"status"`
		ErrorCode int    `json:"error_code"`
		Error     string `json:"error"`
	} `json:"load"`
	Attach struct {
		Mode      string `json:"mode"`
		Status    string `json:"status"`
		Attempted int    `json:"attempted"`
		Passed    int    `json:"passed"`
		Failed    int    `json:"failed"`
	} `json:"attach"`
	BTF struct {
		KernelBTFAvailable bool `json:"kernel_btf_available"`
		ArtifactHasBTF     bool `json:"artifact_has_btf"`
		ArtifactHasBTFExt  bool `json:"artifact_has_btf_ext"`
	} `json:"btf"`
	Capabilities struct {
		MapTypes     map[string]probe `json:"map_types"`
		ProgramTypes map[string]probe `json:"program_types"`
	} `json:"capabilities"`
	Logs struct {
		Libbpf string `json:"libbpf"`
	} `json:"logs"`
	Discovery struct {
		Programs []struct {
			Section string `json:"section"`
		} `json:"programs"`
	} `json:"discovery"`
}

type probe struct {
	Status string `json:"status"`
}

func parseResult(data []byte) (Result, error) {
	var d validatorDoc
	if err := json.Unmarshal(data, &d); err != nil {
		return Result{}, fmt.Errorf("parse validator result: %w", err)
	}

	res := Result{
		Loadable: d.Load.Status == "pass",
		Kernel: KernelInfo{
			Release: d.Host.Release,
			Arch:    d.Host.Machine,
			BTF:     d.BTF.KernelBTFAvailable,
		},
		Load: LoadResult{
			Status:  d.Load.Status,
			Errno:   d.Load.ErrorCode,
			LogTail: tailOf(d.Logs.Libbpf, d.Load.Error),
		},
		Attach: AttachResult{
			Mode:      d.Attach.Mode,
			Status:    d.Attach.Status,
			Attempted: d.Attach.Attempted,
			Passed:    d.Attach.Passed,
			Failed:    d.Attach.Failed,
		},
		Capabilities: Capabilities{
			MapTypes:     flattenProbes(d.Capabilities.MapTypes),
			ProgramTypes: flattenProbes(d.Capabilities.ProgramTypes),
			BTF:          d.BTF.KernelBTFAvailable,
		},
		RawJSON: data,
	}

	if !res.Loadable {
		sections := make([]string, 0, len(d.Discovery.Programs))
		for _, p := range d.Discovery.Programs {
			sections = append(sections, p.Section)
		}
		cl := classifier.Classify(classifier.Input{
			LoadStatus:         d.Load.Status,
			LoadErrorCode:      d.Load.ErrorCode,
			LoadError:          d.Load.Error,
			AttachStatus:       d.Attach.Status,
			AttachMode:         d.Attach.Mode,
			KernelBTFAvailable: d.BTF.KernelBTFAvailable,
			ArtifactHasBTF:     d.BTF.ArtifactHasBTF,
			ArtifactHasBTFExt:  d.BTF.ArtifactHasBTFExt,
			LibbpfLog:          d.Logs.Libbpf,
			KernelRelease:      d.Host.Release,
			ProgramSections:    sections,
		})
		res.Classification = Classification{Code: cl.Code, Confidence: cl.Confidence, Reason: cl.Reason}
	}
	return res, nil
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
