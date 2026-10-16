package matrix

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Matrix struct {
	Name     string          `yaml:"name"`
	Profiles []MatrixProfile `yaml:"profiles"`
}

type MatrixProfile struct {
	ID       string `yaml:"id"`
	Required *bool  `yaml:"required,omitempty"`
	// Timeout is an optional per-target timeout (Go duration, e.g. "20m"),
	// validated at load time. `bpfcompat test` / `test-command` apply it only
	// when --timeout is NOT given on the command line: an explicit --timeout
	// always wins. Callers that set their own timeout (the GitHub Action,
	// which always passes --timeout, the API server, suites, pkg/bpfcompat)
	// ignore it. See runner.Config.MatrixProfileTimeouts.
	Timeout string `yaml:"timeout,omitempty"`
}

// ParseProfileTimeout parses a matrix `timeout:` value: a Go duration
// (time.ParseDuration) greater than zero.
func ParseProfileTimeout(raw string) (time.Duration, error) {
	d, err := time.ParseDuration(strings.TrimSpace(raw))
	if err != nil {
		return 0, fmt.Errorf("must be a duration such as 20m: %w", err)
	}
	if d <= 0 {
		return 0, fmt.Errorf("must be > 0 (got %s)", d)
	}
	return d, nil
}

// TimeoutDuration returns the profile's timeout and true when one is set.
// Validate rejects invalid values, so for a loaded matrix a set timeout is
// always valid; an invalid one reports (0, false) defensively.
func (p MatrixProfile) TimeoutDuration() (time.Duration, bool) {
	if p.Timeout == "" {
		return 0, false
	}
	d, err := ParseProfileTimeout(p.Timeout)
	if err != nil {
		return 0, false
	}
	return d, true
}

func (p MatrixProfile) RequiredBool() bool {
	if p.Required == nil {
		return true
	}
	return *p.Required
}

// QuickProfileIDs is the default kernel set used by `--quick`: a small,
// representative spread (old LTS → recent) for a fast local "does it load?"
// check without writing a matrix file.
var QuickProfileIDs = []string{
	"ubuntu-20.04-5.4",
	"debian-12-6.1",
	"ubuntu-24.04-6.8",
}

// Quick returns the built-in quick-check matrix used by `--quick`.
func Quick() Matrix {
	profiles := make([]MatrixProfile, 0, len(QuickProfileIDs))
	for _, id := range QuickProfileIDs {
		profiles = append(profiles, MatrixProfile{ID: id})
	}
	return Matrix{Name: "quick", Profiles: profiles}
}

func Load(path string) (Matrix, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Matrix{}, fmt.Errorf("read matrix file: %w", err)
	}
	return LoadBytes(data)
}

// LoadBytes mirrors manifest.LoadBytes: KnownFields(true) so the strict
// posture applies to uploaded YAML too. Operators who need a forward-compat
// shape should bump the schema version explicitly.
func LoadBytes(data []byte) (Matrix, error) {
	var m Matrix
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&m); err != nil {
		if !errors.Is(err, io.EOF) {
			return Matrix{}, fmt.Errorf("parse matrix YAML: %w", err)
		}
	}
	if err := Validate(m); err != nil {
		return Matrix{}, err
	}
	return m, nil
}

func (m Matrix) ProfileIDs() []string {
	ids := make([]string, 0, len(m.Profiles))
	for _, profile := range m.Profiles {
		ids = append(ids, profile.ID)
	}
	return ids
}

func (m Matrix) HasProfile(id string) bool {
	for _, profile := range m.Profiles {
		if profile.ID == id {
			return true
		}
	}
	return false
}
