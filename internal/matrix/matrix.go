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
