package artifact

import (
	"path/filepath"
	"testing"
)

// TestIsOCISourceMissingLocalPathIsNotRegistry pins OCI-1: a local artifact
// path that does not exist must never be reinterpreted as a registry
// reference. go-containerregistry happily parses "/home/u/prog.bpf.o" as
// index.docker.io//home/u/prog.bpf.o:latest, which used to turn a typo'd
// --artifact into a Docker Hub pull that leaked the local path.
func TestIsOCISourceMissingLocalPathIsNotRegistry(t *testing.T) {
	missingDir := filepath.Join(t.TempDir(), "does-not-exist")
	notRegistry := []string{
		"/nonexistent.bpf.o",
		"/home/u/prog.bpf.o",
		filepath.Join(missingDir, "prog.bpf.o"),
		filepath.Join(missingDir, "gadget"),
		"build/prog.bpf.o",
		"build/out/prog",
		"./prog.bpf.o",
		"./gadget",
		"../x/prog.o",
		"../x/gadget",
		"~/prog.bpf.o",
		"prog.bpf.o",
		"prog.o",
		"prog.elf",
		"prog",
		"out.d/prog.bpf.o",
	}
	for _, ref := range notRegistry {
		if IsOCISource(ref) {
			t.Errorf("IsOCISource(%q) = true; a missing local path must not be treated as a registry reference", ref)
		}
	}
}

// TestIsOCISourceExplicitRegistryRefs keeps registry references that name
// their registry host explicitly (the same rule action.yml applies).
func TestIsOCISourceExplicitRegistryRefs(t *testing.T) {
	registry := []string{
		"ghcr.io/inspektor-gadget/gadget/trace_open:latest",
		"ghcr.io/org/gadget:tag",
		"ghcr.io/org/gadget",
		"docker.io/x/y@sha256:" + "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		"localhost:5000/team/gadget:y", // note: ggcr rejects 1-char repos such as "x"
		"localhost/gadget:y",
		"registry.example.com:5000/team/gadget:v1",
		"org/gadget@sha256:" + "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
	}
	for _, ref := range registry {
		if !IsOCISource(ref) {
			t.Errorf("IsOCISource(%q) = false; explicit registry reference must stay an OCI source", ref)
		}
	}
}
