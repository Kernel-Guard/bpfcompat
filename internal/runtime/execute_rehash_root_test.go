package runtime

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The artifact handed to ExecuteArtifactOnHost must resolve inside the
// staging root (the fetch out dir) the caller names; anything else is
// refused before it is opened, even when its bytes match the digest.
func TestExecuteArtifactOnHostRefusesArtifactOutsideRoot(t *testing.T) {
	tmp, fetched := fetchForRehash(t)
	root := filepath.Dir(fetched.OutputPath)
	src := filepath.Join(tmp, "src.bpf.o") // genuine bytes, correct sha, but outside root
	if err := os.Symlink(tmp, filepath.Join(root, "escape")); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		path string
		root string
		want string
	}{
		{name: "sibling_outside_root", path: src, root: root, want: "outside the artifact root"},
		{name: "dotdot_traversal", path: filepath.Join(root, "..", "src.bpf.o"), root: root, want: "outside the artifact root"},
		{name: "absolute_elsewhere", path: "/etc/passwd", root: root, want: "outside the artifact root"},
		{name: "root_itself", path: root, root: root, want: "outside the artifact root"},
		{name: "symlinked_dir_component_escapes", path: filepath.Join(root, "escape", "src.bpf.o"), root: root, want: "open artifact"},
		{name: "missing_root", path: fetched.OutputPath, root: "", want: "artifact root"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			validator, seen := stubRehashValidator(t, tmp, nil)
			req := rehashRequest(tmp, tc.path, validator, fetched.ActualSHA256)
			req.ArtifactRoot = tc.root
			_, err := ExecuteArtifactOnHost(context.Background(), req)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected refusal containing %q, got %v", tc.want, err)
			}
			if seen.called {
				t.Fatalf("validator must not run for an artifact outside the root")
			}
		})
	}
}

func TestExecuteArtifactOnHostPrivateCopyUsesConstantName(t *testing.T) {
	tmp, fetched := fetchForRehash(t)
	validator, seen := stubRehashValidator(t, tmp, nil)
	if _, err := ExecuteArtifactOnHost(context.Background(), rehashRequest(tmp, fetched.OutputPath, validator, fetched.ActualSHA256)); err != nil {
		t.Fatal(err)
	}
	if got := filepath.Base(seen.path); got != privateExecArtifactName {
		t.Fatalf("private copy name=%q, want constant %q", got, privateExecArtifactName)
	}
}
