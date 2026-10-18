package artifact

import (
	"strings"
	"testing"
)

// actionIsRemoteArtifact is a line-by-line Go transcription of
// is_remote_artifact in action.yml. Keep it in sync with the shell function.
func actionIsRemoteArtifact(a string) bool {
	if strings.Contains(a, "://") || strings.Contains(a, "@sha256:") {
		return true
	}
	first, _, _ := strings.Cut(a, "/")
	switch {
	case first == "" || first == "." || first == "..":
		return false
	case first == "localhost" || strings.HasPrefix(first, "localhost:"):
		return true
	}
	return strings.Contains(a, "/") && strings.ContainsAny(first, ".:")
}

const leadingSpace = " "

const parityDigest = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// TestRegistryGateMatchesActionRule compares the CLI's registry gate with the
// Action's rule. Every divergence must be in the safe direction (the CLI calls
// local what the Action calls remote, so the CLI reports "no such file" and
// never pulls) and must be listed here deliberately.
func TestRegistryGateMatchesActionRule(t *testing.T) {
	// Deliberate, documented divergences: the Action forwards these to the
	// CLI as remote, and the CLI refuses to pull them.
	saferThanAction := map[string]string{
		"localhost":                       "bare host, no repository; ggcr would read it as Docker Hub library/localhost",
		"localhost:5000":                  "bare host:port, no repository",
		"/x@" + parityDigest:              "absolute path is always local",
		"./team/gadget@" + parityDigest:   "./ path is always local",
		"out.d/prog.bpf.o":                ".bpf.o object path is always local, even under a dotted directory",
		leadingSpace + "ghcr.io/org/g:1":  "", // the gate trims; ggcr then rejects it
		"oci://ghcr.io/org/g:1":           "URL scheme; ggcr cannot parse it anyway",
		"https://ghcr.io/org/g:1":         "URL scheme; ggcr cannot parse it anyway",
		"GHCR.IO/org/g:1":                 "",
		"[::1]:5000/team/g:1":             "",
		"ghcr.io/org/g:1@" + parityDigest: "",
		"127.0.0.1:5000/team/g:1":         "",
		"docker.io/library/nginx":         "",
		"docker.io/org/name:tag":          "",
		"localhost:5000/team/gadget:y":    "",
		"team/gadget@" + parityDigest:     "",
		"gadget@" + parityDigest:          "",
		"org/name:tag":                    "",
		"name:tag":                        "",
		"out.d/gadget":                    "",
		"ghcr.io/org/g:1":                 "",
		"ghcr.io/org/prog.o":              "",
		"ghcr.io/org/gadget.elf":          "",
		"ghcr.io/org/gadget:v1.o":         "",
	}
	// The 24 refs from the ROCI review; an empty reason means "must match".
	if len(saferThanAction) != 24 {
		t.Fatalf("expected 24 review refs, have %d", len(saferThanAction))
	}
	for ref, reason := range saferThanAction {
		action := actionIsRemoteArtifact(ref)
		gate := looksLikeRegistryRef(ref)
		switch {
		case reason == "" && gate != action:
			t.Errorf("looksLikeRegistryRef(%q) = %v, action.yml says %v", ref, gate, action)
		case reason != "" && (gate || !action):
			t.Errorf("%q: documented divergence (%s) wants gate=false action=true, got gate=%v action=%v", ref, reason, gate, action)
		}
	}
}

// TestIsOCISourceRemoteObjectSuffixWithRegistryHost: a ref whose first
// component is a registry host stays remote even when the repository or tag
// ends in .o/.elf, matching the Action.
func TestIsOCISourceRemoteObjectSuffixWithRegistryHost(t *testing.T) {
	for _, ref := range []string{"ghcr.io/org/prog.o", "ghcr.io/org/gadget.elf", "ghcr.io/org/gadget:v1.o"} {
		if !IsOCISource(ref) {
			t.Errorf("IsOCISource(%q) = false, want true (explicit registry host)", ref)
		}
	}
}

func TestDockerHubHint(t *testing.T) {
	cases := map[string]string{
		"org/name:tag":                "docker.io/org/name:tag",
		"name:tag":                    "docker.io/name:tag",
		"team/gadget@" + parityDigest: "",
		"build/prog.bpf.o":            "",
		"/home/u/prog.bpf.o":          "",
		"./org/name:tag":              "",
		"build/out/prog":              "",
		"prog.o":                      "",
		"ghcr.io/org/g:1":             "",
		"Org/Name:tag":                "",
	}
	for ref, want := range cases {
		if got := DockerHubHint(ref); got != want {
			t.Errorf("DockerHubHint(%q) = %q, want %q", ref, got, want)
		}
	}
}
