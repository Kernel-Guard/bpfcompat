package safepath

import (
	"errors"
	"path/filepath"
	"testing"
)

func TestLocalJoinAllowsLocalNames(t *testing.T) {
	base := filepath.Join("var", "lib", "bpfcompat")
	cases := []struct {
		name       string
		components []string
		want       string
	}{
		{"plain file", []string{"falco.bpf.o"}, filepath.Join(base, "falco.bpf.o")},
		{"nested local", []string{"input", "probe.bpf.o"}, filepath.Join(base, "input", "probe.bpf.o")},
		{"dotdot that nets out local", []string{"a", "..", "b"}, filepath.Join(base, "b")},
		{"dots in name are fine", []string{"v1.2.3.bpf.o"}, filepath.Join(base, "v1.2.3.bpf.o")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := LocalJoin(base, tc.components...)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("LocalJoin = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestLocalJoinRejectsTraversal(t *testing.T) {
	base := filepath.Join("var", "lib", "bpfcompat")
	cases := []struct {
		name       string
		components []string
	}{
		{"parent escape", []string{"..", "etc", "passwd"}},
		{"deep escape", []string{"a", "..", "..", "b"}},
		{"absolute path", []string{"/etc/passwd"}},
		{"parent then absolute-looking", []string{"..", "input", "x"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := LocalJoin(base, tc.components...)
			if err == nil {
				t.Fatalf("expected error for components %v", tc.components)
			}
			var escapeErr *ErrEscapesBase
			if !errors.As(err, &escapeErr) {
				t.Fatalf("expected *ErrEscapesBase, got %T: %v", err, err)
			}
		})
	}
}
