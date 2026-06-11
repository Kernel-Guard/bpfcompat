package manifest

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"

	"gopkg.in/yaml.v3"
)

type Manifest struct {
	Name             string           `yaml:"name"`
	Programs         []Program        `yaml:"programs"`
	Maps             []MapFixup       `yaml:"maps,omitempty"`
	RequiredProfiles []string         `yaml:"required_profiles,omitempty"`
	FunctionalTests  []FunctionalTest `yaml:"functional_tests,omitempty"`
	Metadata         map[string]any   `yaml:"metadata,omitempty"`
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
