package matrix

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"

	"gopkg.in/yaml.v3"
)

type Matrix struct {
	Name     string          `yaml:"name"`
	Profiles []MatrixProfile `yaml:"profiles"`
}

type MatrixProfile struct {
	ID       string `yaml:"id"`
	Required *bool  `yaml:"required,omitempty"`
	Timeout  string `yaml:"timeout,omitempty"`
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
