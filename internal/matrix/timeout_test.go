package matrix

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoadRejectsInvalidProfileTimeout(t *testing.T) {
	for _, raw := range []string{"banana", "0s", "-5m", "20", " "} {
		body := "profiles:\n  - id: a\n    timeout: \"" + raw + "\"\n"
		if _, err := LoadBytes([]byte(body)); err == nil {
			t.Errorf("LoadBytes accepted timeout %q", raw)
		} else if !strings.Contains(err.Error(), "profiles[0].timeout") {
			t.Errorf("timeout %q: error %q does not name the field", raw, err)
		}
	}
}

func TestProfileTimeoutDuration(t *testing.T) {
	m, err := LoadBytes([]byte("profiles:\n  - id: a\n    timeout: 20m\n  - id: b\n"))
	if err != nil {
		t.Fatal(err)
	}
	if d, ok := m.Profiles[0].TimeoutDuration(); !ok || d != 20*time.Minute {
		t.Fatalf("profiles[0]: got %v ok=%v, want 20m", d, ok)
	}
	if d, ok := m.Profiles[1].TimeoutDuration(); ok || d != 0 {
		t.Fatalf("profiles[1] has no timeout: got %v ok=%v", d, ok)
	}
}

// Every committed matrix (kernel-sweep and pre-campaign matrices carry
// `timeout: 20m`) must still load once the field is validated.
func TestCommittedMatricesLoad(t *testing.T) {
	paths, err := filepath.Glob("../../matrices/*.yaml")
	if err != nil || len(paths) == 0 {
		t.Fatalf("glob committed matrices: %v (n=%d)", err, len(paths))
	}
	for _, p := range paths {
		if _, err := Load(p); err != nil {
			t.Errorf("%s: %v", p, err)
		}
	}
}
