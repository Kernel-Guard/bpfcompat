package conformance

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadFalcoProfile(t *testing.T) {
	profile := loadFalcoProfile(t)
	if profile.Profile.ID != "falco-modern-bpf-v0.1" {
		t.Fatalf("profile id = %q", profile.Profile.ID)
	}
	if len(profile.Matrix.Profiles) != 5 {
		t.Fatalf("matrix profiles = %d, want 5", len(profile.Matrix.Profiles))
	}
	if !isSHA256(profile.SHA256) || !isSHA256(profile.MatrixSHA256) {
		t.Fatalf("profile resources are not digest-bound: %+v", profile)
	}
}

func TestLoadProfileRejectsUnknownFieldsAndMatrixTraversal(t *testing.T) {
	baseProfile, err := os.ReadFile(filepath.Join("..", "..", "conformance", "falco-modern-bpf-v0.1", "profile.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	baseMatrix, err := os.ReadFile(filepath.Join("..", "..", "conformance", "falco-modern-bpf-v0.1", "matrix.yaml"))
	if err != nil {
		t.Fatal(err)
	}

	t.Run("unknown field", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "matrix.yaml"), baseMatrix, 0o600); err != nil {
			t.Fatal(err)
		}
		raw := append(append([]byte(nil), baseProfile...), []byte("unknown_field: true\n")...)
		path := filepath.Join(dir, "profile.yaml")
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadProfile(path); err == nil || !strings.Contains(err.Error(), "field unknown_field not found") {
			t.Fatalf("expected strict YAML error, got %v", err)
		}
	})

	t.Run("matrix traversal", func(t *testing.T) {
		dir := t.TempDir()
		raw := strings.Replace(string(baseProfile), "path: matrix.yaml", "path: ../matrix.yaml", 1)
		path := filepath.Join(dir, "profile.yaml")
		if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadProfile(path); err == nil || !strings.Contains(err.Error(), "must stay inside") {
			t.Fatalf("expected matrix traversal error, got %v", err)
		}
	})

	t.Run("multiple profile documents", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "matrix.yaml"), baseMatrix, 0o600); err != nil {
			t.Fatal(err)
		}
		raw := append(append([]byte(nil), baseProfile...), []byte("---\n{}\n")...)
		path := filepath.Join(dir, "profile.yaml")
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadProfile(path); err == nil || !strings.Contains(err.Error(), "exactly one YAML document") {
			t.Fatalf("expected multiple-document error, got %v", err)
		}
	})

	t.Run("multiple matrix documents", func(t *testing.T) {
		dir := t.TempDir()
		matrix := append(append([]byte(nil), baseMatrix...), []byte("---\n{}\n")...)
		if err := os.WriteFile(filepath.Join(dir, "matrix.yaml"), matrix, 0o600); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, "profile.yaml")
		if err := os.WriteFile(path, baseProfile, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadProfile(path); err == nil || !strings.Contains(err.Error(), "exactly one YAML document") {
			t.Fatalf("expected multiple-document error, got %v", err)
		}
	})
}
