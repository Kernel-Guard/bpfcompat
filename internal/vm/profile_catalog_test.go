package vm

import (
	"path/filepath"
	"testing"
)

func TestAllProfileYAMLLoadAndValidate(t *testing.T) {
	paths, err := filepath.Glob(filepath.Join("..", "..", "vm", "profiles", "*.yaml"))
	if err != nil {
		t.Fatalf("glob profiles: %v", err)
	}
	if len(paths) == 0 {
		t.Fatal("no profile yaml files found")
	}

	seenIDs := make(map[string]struct{}, len(paths))
	for _, path := range paths {
		profile, loadErr := LoadProfile(path)
		if loadErr != nil {
			t.Fatalf("load profile %s: %v", path, loadErr)
		}
		if profile.ID == "" {
			t.Fatalf("profile %s has empty id", path)
		}
		if _, exists := seenIDs[profile.ID]; exists {
			t.Fatalf("duplicate profile id %q", profile.ID)
		}
		seenIDs[profile.ID] = struct{}{}
	}
}

