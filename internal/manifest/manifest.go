package manifest

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"

	"gopkg.in/yaml.v3"
)

type Manifest struct {
	Name            string                `yaml:"name"`
	Programs        []Program             `yaml:"programs"`
	Maps            []MapFixup            `yaml:"maps,omitempty"`
	ProgramVariants []ProgramVariantGroup `yaml:"program_variants,omitempty"`
	// ProbeCompanions lists programs statically referenced from prog-array
	// map slots; they must stay autoloaded during trial_load probes or
	// slot initialization fails before the probed program is exercised.
	ProbeCompanions  []string         `yaml:"probe_companions,omitempty"`
	RequiredProfiles []string         `yaml:"required_profiles,omitempty"`
	FunctionalTests  []FunctionalTest `yaml:"functional_tests,omitempty"`
	Metadata         map[string]any   `yaml:"metadata,omitempty"`
}

// ProgramVariantGroup declares alternative programs for the same event where
// the artifact's loader probes kernel helper support and autoloads only the
// first satisfying variant (Falco's exit_event_progs_table pattern, e.g.
// recvmmsg_x requires bpf_loop with recvmmsg_old_x as the fallback).
// Programs that lose the selection are expected to fail verification on
// kernels missing their helper; loading them anyway reports a loader-
// contract violation as a compatibility failure.
type ProgramVariantGroup struct {
	Group    string           `yaml:"group"`
	Programs []ProgramVariant `yaml:"programs"`
}

type ProgramVariant struct {
	Name string `yaml:"name"`
	// RequiresHelper is a BPF helper the kernel must support for this
	// variant: a known helper name (for example "bpf_loop") or a numeric
	// helper id. Empty means unconditional — the fallback variant.
	RequiresHelper string `yaml:"requires_helper,omitempty"`
	// Probe set to "trial_load" gates the variant on an isolated trial
	// load on the target kernel (with probe_companions kept autoloaded),
	// mirroring loaders that probe support empirically — Falco's BPF
	// iterator programs are the canonical case.
	Probe string `yaml:"probe,omitempty"`
}

// helperIDs maps the BPF helper names accepted in requires_helper to their
// UAPI enum bpf_func_id values (stable kernel ABI). Unlisted helpers can be
// given numerically.
var helperIDs = map[string]uint32{
	"bpf_probe_read_kernel":    113,
	"bpf_ringbuf_output":       130,
	"bpf_ringbuf_reserve":      131,
	"bpf_get_current_task_btf": 158,
	"bpf_loop":                 181,
}

// HelperID resolves a requires_helper value to a numeric helper id.
func HelperID(value string) (uint32, error) {
	if id, ok := helperIDs[value]; ok {
		return id, nil
	}
	id, err := strconv.ParseUint(value, 10, 32)
	if err != nil || id == 0 {
		return 0, fmt.Errorf("unknown BPF helper %q (use a known name or a positive numeric id)", value)
	}
	return uint32(id), nil
}

// MapFixup declares a pre-load adjustment for a map whose final shape the
// artifact's own loader decides at runtime — for example per-CPU arrays or
// ring buffers sized from the CPU count, which are compiled with
// max_entries=0 and would otherwise fail to load under any generic loader.
// The validator applies fixups between bpf_object open and load.
type MapFixup struct {
	Name string `yaml:"name"`
	// MaxEntries is a positive integer or the literal "cpus", which resolves
	// to the number of possible CPUs on the target kernel at load time.
	MaxEntries EntriesValue `yaml:"max_entries,omitempty"`
	// InnerRingbufBytes creates a BPF_MAP_TYPE_RINGBUF of this byte size and
	// installs it as the inner-map prototype for an array-of-maps.
	InnerRingbufBytes uint32 `yaml:"inner_ringbuf_bytes,omitempty"`
}

// EntriesValue accepts either a YAML integer or the string "cpus".
type EntriesValue string

func (e *EntriesValue) UnmarshalYAML(node *yaml.Node) error {
	*e = EntriesValue(node.Value)
	return nil
}

type Program struct {
	Name    string `yaml:"name"`
	Section string `yaml:"section"`
	Type    string `yaml:"type,omitempty"`
	Attach  Attach `yaml:"attach,omitempty"`
}

type Attach struct {
	Kind     string `yaml:"kind,omitempty"`
	Category string `yaml:"category,omitempty"`
	Name     string `yaml:"name,omitempty"`
	Symbol   string `yaml:"symbol,omitempty"`
	Required bool   `yaml:"required,omitempty"`
}

type FunctionalTest struct {
	Name                 string `yaml:"name"`
	Command              string `yaml:"command"`
	Required             *bool  `yaml:"required,omitempty"`
	Timeout              string `yaml:"timeout,omitempty"`
	ExpectExitCode       *int   `yaml:"expect_exit_code,omitempty"`
	ExpectStdoutContains string `yaml:"expect_stdout_contains,omitempty"`
	ExpectStderrContains string `yaml:"expect_stderr_contains,omitempty"`
}

func Load(path string) (Manifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Manifest{}, fmt.Errorf("read manifest file: %w", err)
	}
	return LoadBytes(data)
}

// LoadBytes is the in-memory form of Load. Centralizing the strict-decode
// here lets the API server's upload path and the CLI's file path share the
// same hardening: unknown fields are rejected so a malicious uploader can't
// hide a future-schema field that bypasses validation in the current binary.
func LoadBytes(data []byte) (Manifest, error) {
	var m Manifest
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&m); err != nil {
		// io.EOF on an empty stream means "valid but empty"; Validate will
		// catch the missing required fields.
		if !errors.Is(err, io.EOF) {
			return Manifest{}, fmt.Errorf("parse manifest YAML: %w", err)
		}
	}
	if err := Validate(m); err != nil {
		return Manifest{}, err
	}
	return m, nil
}
