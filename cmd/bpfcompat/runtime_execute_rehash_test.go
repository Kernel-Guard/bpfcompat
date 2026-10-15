package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kernel-guard/bpfcompat/internal/registry"
	"github.com/kernel-guard/bpfcompat/internal/runner"
)

// writeRehashFakeValidator writes a no-sudo fake validator that records the
// --artifact path it was given, the mode of that path's directory and the
// sha256 of the bytes it would load, then reports a pass.
func writeRehashFakeValidator(t *testing.T, dir string) (string, string) {
	t.Helper()
	logPath := filepath.Join(dir, "validator-seen.txt")
	script := `#!/bin/sh
art=""; out=""
while [ $# -gt 0 ]; do
  case "$1" in
    --artifact) art="$2"; shift 2 ;;
    --out) out="$2"; shift 2 ;;
    *) shift ;;
  esac
done
printf '%s\n%s\n%s\n' "$art" "$(stat -c %a "$(dirname "$art")")" "$(sha256sum "$art" | cut -d' ' -f1)" > '` + logPath + `'
printf '{"status":"pass","load":{"status":"pass"}}' > "$out"
`
	validator := filepath.Join(dir, "fake-validator")
	if err := os.WriteFile(validator, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return validator, logPath
}

func seedRehashArtifact(t *testing.T, workDir string) string {
	t.Helper()
	artifactPath := filepath.Join(workDir, "aegis.bpf.o")
	artifactBytes := []byte{0x7f, 'E', 'L', 'F', 0x01, 0x02, 0x03}
	if err := os.WriteFile(artifactPath, artifactBytes, 0o644); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(artifactBytes)
	reportPath := filepath.Join(workDir, "report.json")
	if err := os.WriteFile(reportPath, []byte(`{"schema_version":"v0.1"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := registry.PersistArtifactVersion(workDir, registry.ArtifactVersionRecord{
		RunID:             "run-1",
		ArtifactName:      "aegis",
		ArtifactVersion:   "v1",
		ArtifactPath:      artifactPath,
		ArtifactSHA256:    hex.EncodeToString(sum[:]),
		SummaryStatus:     "pass",
		RequiredPassed:    1,
		SupportedProfiles: []string{"ubuntu-22.04-5.15"},
		JSONReportPath:    reportPath,
	}); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(sum[:])
}

func assertRehashValidatorSawPrivateCopy(t *testing.T, logPath, outDir, wantSHA string) {
	t.Helper()
	raw, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("validator did not run: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) != 3 {
		t.Fatalf("unexpected validator log: %q", raw)
	}
	if strings.HasPrefix(lines[0], filepath.Clean(outDir)+string(filepath.Separator)) {
		t.Fatalf("validator was handed the --out-dir staging path %s", lines[0])
	}
	if lines[1] != "700" {
		t.Fatalf("validator artifact dir mode=%s, want 700", lines[1])
	}
	if lines[2] != wantSHA {
		t.Fatalf("validator loaded sha=%s, want %s", lines[2], wantSHA)
	}
	if _, err := os.Stat(filepath.Dir(lines[0])); !os.IsNotExist(err) {
		t.Fatalf("private exec dir not cleaned up: %v", err)
	}
}

func TestRuntimeExecuteCLIExecutesVerifiedPrivateCopy(t *testing.T) {
	workDir := t.TempDir()
	wantSHA := seedRehashArtifact(t, workDir)
	validator, logPath := writeRehashFakeValidator(t, workDir)
	outDir := filepath.Join(workDir, "selected")
	outPath := filepath.Join(workDir, "execute.json")
	code := runRuntimeExecute([]string{
		"--workdir", workDir,
		"--artifact-name", "aegis",
		"--version", "v1",
		"--allow-host-load",
		"--require-verified-history=false",
		"--use-sudo=false",
		"--validator", validator,
		"--out-dir", outDir,
		"--out", outPath,
	})
	if code != runner.ExitSuccess {
		t.Fatalf("runtime execute exit=%d", code)
	}
	assertRehashValidatorSawPrivateCopy(t, logPath, outDir, wantSHA)
	var payload struct {
		Execution struct {
			ExpectedSHA256 string `json:"expected_sha256"`
		} `json:"execution"`
	}
	raw, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Execution.ExpectedSHA256 != wantSHA {
		t.Fatalf("execution expected_sha256=%q, want record sha %q", payload.Execution.ExpectedSHA256, wantSHA)
	}
}

func TestAgentApplyApprovedLoadExecutesVerifiedPrivateCopy(t *testing.T) {
	workDir := t.TempDir()
	wantSHA := seedRehashArtifact(t, workDir)
	validator, logPath := writeRehashFakeValidator(t, workDir)
	outDir := filepath.Join(workDir, "selected")
	outPath := filepath.Join(workDir, "agent-apply.json")
	code := runAgentApply([]string{
		"--workdir", workDir,
		"--artifact-name", "aegis",
		"--agent-id", "host-1",
		"--probe-use-sudo=false",
		"--out-dir", outDir,
		"--out", outPath,
		"--approve-load",
		"--require-load-policy=false",
		"--use-sudo=false",
		"--validator", validator,
	})
	if code != runner.ExitSuccess {
		raw, _ := os.ReadFile(outPath)
		t.Fatalf("agent apply exit=%d out=%s", code, raw)
	}
	assertRehashValidatorSawPrivateCopy(t, logPath, outDir, wantSHA)
	var payload struct {
		Execution struct {
			ExpectedSHA256 string `json:"expected_sha256"`
		} `json:"execution"`
	}
	raw, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Execution.ExpectedSHA256 != wantSHA {
		t.Fatalf("execution expected_sha256=%q, want record sha %q", payload.Execution.ExpectedSHA256, wantSHA)
	}
}
