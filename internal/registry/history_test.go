package registry

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestPersistAndListArtifactVersions(t *testing.T) {
	workDir := t.TempDir()

	record := ArtifactVersionRecord{
		RunID:           "run-1",
		RunStartedAt:    "2026-05-15T17:00:00Z",
		CreatedAt:       "2026-05-15T17:00:01Z",
		ArtifactName:    "execsnoop",
		ArtifactVersion: "v1",
		ArtifactSHA256:  "abc123",
		ArtifactPath:    "/tmp/execsnoop.bpf.o",
		ArtifactURI:     "https://example.invalid/execsnoop/v1/execsnoop.bpf.o",
		MatrixPath:      "/tmp/mvp.yaml",
		SummaryStatus:   "pass",
		TotalProfiles:   8,
		JSONReportPath:  "/tmp/report.json",
	}
	if err := PersistArtifactVersion(workDir, record); err != nil {
		t.Fatalf("persist artifact record: %v", err)
	}

	recordV2 := record
	recordV2.RunID = "run-2"
	recordV2.ArtifactVersion = "v2"
	recordV2.CreatedAt = "2026-05-15T17:01:01Z"
	recordV2.ArtifactURI = "https://example.invalid/execsnoop/v2/execsnoop.bpf.o"
	recordV2.JSONReportPath = "/tmp/report-v2.json"
	if err := PersistArtifactVersion(workDir, recordV2); err != nil {
		t.Fatalf("persist artifact record v2: %v", err)
	}

	records, err := ListArtifactVersions(workDir, "execsnoop", 0)
	if err != nil {
		t.Fatalf("list artifact versions: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("expected 2 records, got %d", len(records))
	}
	if records[0].ArtifactVersion != "v2" {
		t.Fatalf("expected newest record first, got %q", records[0].ArtifactVersion)
	}
	if records[0].ArtifactURI != "https://example.invalid/execsnoop/v2/execsnoop.bpf.o" {
		t.Fatalf("expected artifact URI on newest record, got %q", records[0].ArtifactURI)
	}
	if records[0].SchemaVersion != artifactHistorySchemaVersion {
		t.Fatalf("expected schema version %q, got %q", artifactHistorySchemaVersion, records[0].SchemaVersion)
	}
	if records[0].RecordSHA256 == "" {
		t.Fatalf("expected record_sha256 to be populated")
	}
	if records[0].SignatureAlg != artifactHistorySignatureAlgorithm {
		t.Fatalf("expected signature_alg %q, got %q", artifactHistorySignatureAlgorithm, records[0].SignatureAlg)
	}
	if records[0].Signature == "" || records[0].SignaturePublicKey == "" || records[0].SignatureKeyID == "" {
		t.Fatalf("expected signature metadata to be populated")
	}
	if _, err := base64.StdEncoding.DecodeString(records[0].SignaturePublicKey); err != nil {
		t.Fatalf("decode signature public key: %v", err)
	}
	if records[0].PrevRecordSHA256 == "" {
		t.Fatalf("expected prev_record_sha256 on newer record")
	}
	if records[1].PrevRecordSHA256 != "" {
		t.Fatalf("expected empty prev_record_sha256 on first record")
	}
}

func TestFindArtifactVersion(t *testing.T) {
	workDir := t.TempDir()
	record := ArtifactVersionRecord{
		RunID:           "run-1",
		RunStartedAt:    "2026-05-15T17:00:00Z",
		CreatedAt:       "2026-05-15T17:00:01Z",
		ArtifactName:    "tracepoint",
		ArtifactVersion: "2026.05.15",
		ArtifactSHA256:  "abc123",
		ArtifactPath:    "/tmp/tracepoint.bpf.o",
		MatrixPath:      "/tmp/mvp.yaml",
		SummaryStatus:   "fail",
		TotalProfiles:   8,
		JSONReportPath:  "/tmp/tracepoint-report.json",
	}
	if err := PersistArtifactVersion(workDir, record); err != nil {
		t.Fatalf("persist artifact record: %v", err)
	}

	found, err := FindArtifactVersion(workDir, "tracepoint", "2026.05.15")
	if err != nil {
		t.Fatalf("find artifact version: %v", err)
	}
	if found.RunID != "run-1" {
		t.Fatalf("unexpected run id: %q", found.RunID)
	}

	_, err = FindArtifactVersion(workDir, "tracepoint", "missing")
	if err == nil {
		t.Fatalf("expected not found for missing version")
	}
}

func TestListAndGetRunRecords(t *testing.T) {
	workDir := t.TempDir()
	runDir := filepath.Join(workDir, "runs", "run-a")
	if err := os.MkdirAll(runDir, 0o755); err != nil {
		t.Fatalf("mkdir run dir a: %v", err)
	}
	if err := Persist(workDir, runDir, RunRecord{
		RunID:          "run-a",
		StartedAt:      "2026-05-15T10:00:00Z",
		ArtifactName:   "demo",
		ArtifactPath:   "/tmp/a.bpf.o",
		ArtifactSHA256: "sha-a",
		MatrixPath:     "/tmp/m.yaml",
		SummaryStatus:  "pass",
		JSONReportPath: "/tmp/a.json",
	}); err != nil {
		t.Fatalf("persist run a: %v", err)
	}

	runDirB := filepath.Join(workDir, "runs", "run-b")
	if err := os.MkdirAll(runDirB, 0o755); err != nil {
		t.Fatalf("mkdir run dir b: %v", err)
	}
	if err := Persist(workDir, runDirB, RunRecord{
		RunID:          "run-b",
		StartedAt:      "2026-05-15T11:00:00Z",
		ArtifactName:   "demo",
		ArtifactPath:   "/tmp/b.bpf.o",
		ArtifactSHA256: "sha-b",
		MatrixPath:     "/tmp/m.yaml",
		SummaryStatus:  "fail",
		JSONReportPath: "/tmp/b.json",
	}); err != nil {
		t.Fatalf("persist run b: %v", err)
	}

	records, err := ListRunRecords(workDir, 0)
	if err != nil {
		t.Fatalf("list runs: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("expected 2 runs, got %d", len(records))
	}
	if records[0].RunID != "run-b" {
		t.Fatalf("expected newest run first, got %q", records[0].RunID)
	}

	found, err := GetRunRecord(workDir, "run-a")
	if err != nil {
		t.Fatalf("get run record: %v", err)
	}
	if found.SummaryStatus != "pass" {
		t.Fatalf("unexpected summary status: %q", found.SummaryStatus)
	}
}

func TestVerifyArtifactVersionHistory(t *testing.T) {
	workDir := t.TempDir()
	record := ArtifactVersionRecord{
		RunID:           "run-1",
		RunStartedAt:    "2026-05-15T17:00:00Z",
		CreatedAt:       "2026-05-15T17:00:01Z",
		ArtifactName:    "tracepoint",
		ArtifactVersion: "v1",
		ArtifactSHA256:  "abc123",
		ArtifactPath:    "/tmp/tracepoint.bpf.o",
		MatrixPath:      "/tmp/mvp.yaml",
		SummaryStatus:   "pass",
		TotalProfiles:   2,
		JSONReportPath:  "/tmp/tracepoint-report.json",
	}
	if err := PersistArtifactVersion(workDir, record); err != nil {
		t.Fatalf("persist artifact record: %v", err)
	}
	record.RunID = "run-2"
	record.CreatedAt = "2026-05-15T17:01:01Z"
	record.ArtifactVersion = "v2"
	if err := PersistArtifactVersion(workDir, record); err != nil {
		t.Fatalf("persist artifact record v2: %v", err)
	}

	verification, err := VerifyArtifactVersionHistory(workDir)
	if err != nil {
		t.Fatalf("verify artifact version history: %v", err)
	}
	if len(verification) != 2 {
		t.Fatalf("expected 2 verification rows, got %d", len(verification))
	}
	if !verification[0].Verified || !verification[1].Verified {
		t.Fatalf("expected all verification rows to pass: %+v", verification)
	}
}

func TestVerifyArtifactVersionHistoryDetectsTamper(t *testing.T) {
	workDir := t.TempDir()
	record := ArtifactVersionRecord{
		RunID:           "run-1",
		RunStartedAt:    "2026-05-15T17:00:00Z",
		CreatedAt:       "2026-05-15T17:00:01Z",
		ArtifactName:    "tracepoint",
		ArtifactVersion: "v1",
		ArtifactSHA256:  "abc123",
		ArtifactPath:    "/tmp/tracepoint.bpf.o",
		MatrixPath:      "/tmp/mvp.yaml",
		SummaryStatus:   "pass",
		TotalProfiles:   2,
		JSONReportPath:  "/tmp/tracepoint-report.json",
	}
	if err := PersistArtifactVersion(workDir, record); err != nil {
		t.Fatalf("persist artifact record: %v", err)
	}

	indexPath := filepath.Join(workDir, "registry", "artifact_versions.jsonl")
	raw, err := os.ReadFile(indexPath)
	if err != nil {
		t.Fatalf("read artifact history index: %v", err)
	}
	mutated := strings.ReplaceAll(string(raw), "\"summary_status\":\"pass\"", "\"summary_status\":\"fail\"")
	if mutated == string(raw) {
		t.Fatalf("failed to mutate test payload")
	}
	if err := os.WriteFile(indexPath, []byte(mutated), 0o644); err != nil {
		t.Fatalf("write mutated artifact history index: %v", err)
	}

	verification, err := VerifyArtifactVersionHistory(workDir)
	if err != nil {
		t.Fatalf("verify artifact version history: %v", err)
	}
	if len(verification) != 1 {
		t.Fatalf("expected 1 verification row, got %d", len(verification))
	}
	if verification[0].Verified {
		t.Fatalf("expected tampered row to fail verification")
	}
}

func TestVerifyArtifactVersionHistoryDetectsSignatureTamper(t *testing.T) {
	workDir := t.TempDir()
	record := ArtifactVersionRecord{
		RunID:           "run-1",
		RunStartedAt:    "2026-05-15T17:00:00Z",
		CreatedAt:       "2026-05-15T17:00:01Z",
		ArtifactName:    "tracepoint",
		ArtifactVersion: "v1",
		ArtifactSHA256:  "abc123",
		ArtifactPath:    "/tmp/tracepoint.bpf.o",
		MatrixPath:      "/tmp/mvp.yaml",
		SummaryStatus:   "pass",
		TotalProfiles:   2,
		JSONReportPath:  "/tmp/tracepoint-report.json",
	}
	if err := PersistArtifactVersion(workDir, record); err != nil {
		t.Fatalf("persist artifact record: %v", err)
	}

	indexPath := filepath.Join(workDir, "registry", "artifact_versions.jsonl")
	raw, err := os.ReadFile(indexPath)
	if err != nil {
		t.Fatalf("read artifact history index: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) != 1 {
		t.Fatalf("expected single history record, got %d", len(lines))
	}

	var payload map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &payload); err != nil {
		t.Fatalf("decode history record: %v", err)
	}
	payload["signature"] = base64.StdEncoding.EncodeToString([]byte("tampered-signature"))
	line, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("encode tampered history record: %v", err)
	}
	if err := os.WriteFile(indexPath, append(line, '\n'), 0o644); err != nil {
		t.Fatalf("write tampered signature history index: %v", err)
	}

	verification, err := VerifyArtifactVersionHistory(workDir)
	if err != nil {
		t.Fatalf("verify artifact version history: %v", err)
	}
	if len(verification) != 1 {
		t.Fatalf("expected 1 verification row, got %d", len(verification))
	}
	if verification[0].Verified {
		t.Fatalf("expected signature-tampered row to fail verification")
	}
	issues := strings.Join(verification[0].Issues, " ")
	if !strings.Contains(issues, "signature") {
		t.Fatalf("expected signature-related verification issue, got: %v", verification[0].Issues)
	}
}

func TestVerifyArtifactVersionHistoryRejectsReSignedRecordWithUntrustedKey(t *testing.T) {
	workDir := t.TempDir()
	record := ArtifactVersionRecord{
		RunID:           "run-1",
		RunStartedAt:    "2026-05-15T17:00:00Z",
		CreatedAt:       "2026-05-15T17:00:01Z",
		ArtifactName:    "tracepoint",
		ArtifactVersion: "v1",
		ArtifactSHA256:  "abc123",
		ArtifactPath:    "/tmp/tracepoint.bpf.o",
		MatrixPath:      "/tmp/mvp.yaml",
		SummaryStatus:   "pass",
		TotalProfiles:   2,
		JSONReportPath:  "/tmp/tracepoint-report.json",
	}
	if err := PersistArtifactVersion(workDir, record); err != nil {
		t.Fatalf("persist artifact record: %v", err)
	}

	indexPath := filepath.Join(workDir, "registry", "artifact_versions.jsonl")
	raw, err := os.ReadFile(indexPath)
	if err != nil {
		t.Fatalf("read artifact history index: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) != 1 {
		t.Fatalf("expected single history record, got %d", len(lines))
	}
	var rec ArtifactVersionRecord
	if err := json.Unmarshal([]byte(lines[0]), &rec); err != nil {
		t.Fatalf("decode history record: %v", err)
	}
	rec.SummaryStatus = "fail"
	payload, hash, err := artifactRecordCanonicalPayloadAndHash(rec)
	if err != nil {
		t.Fatalf("compute canonical payload: %v", err)
	}
	attackerPub, attackerPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate attacker key: %v", err)
	}
	rec.RecordSHA256 = hash
	rec.SignatureAlg = artifactHistorySignatureAlgorithm
	rec.SignatureKeyID = keyIDFromPublicKey(attackerPub)
	rec.SignaturePublicKey = base64.StdEncoding.EncodeToString(attackerPub)
	rec.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(attackerPriv, payload))

	line, err := json.Marshal(rec)
	if err != nil {
		t.Fatalf("encode tampered history record: %v", err)
	}
	if err := os.WriteFile(indexPath, append(line, '\n'), 0o644); err != nil {
		t.Fatalf("write tampered history index: %v", err)
	}

	verification, err := VerifyArtifactVersionHistory(workDir)
	if err != nil {
		t.Fatalf("verify artifact version history: %v", err)
	}
	if len(verification) != 1 {
		t.Fatalf("expected 1 verification row, got %d", len(verification))
	}
	if verification[0].Verified {
		t.Fatalf("expected re-signed untrusted record to fail verification")
	}
}

func TestBackfillArtifactVersionProvenance(t *testing.T) {
	workDir := t.TempDir()
	registryDir := filepath.Join(workDir, "registry")
	if err := os.MkdirAll(registryDir, 0o755); err != nil {
		t.Fatalf("mkdir registry dir: %v", err)
	}

	unsigned := ArtifactVersionRecord{
		SchemaVersion:     artifactHistorySchemaVersion,
		RunID:             "run-legacy",
		RunStartedAt:      "2026-05-15T17:00:00Z",
		CreatedAt:         "2026-05-15T17:00:01Z",
		ArtifactName:      "legacy",
		ArtifactVersion:   "v0",
		ArtifactPath:      "/tmp/legacy.bpf.o",
		ArtifactSHA256:    "abc123",
		MatrixPath:        "/tmp/mvp.yaml",
		SummaryStatus:     "pass",
		TotalProfiles:     1,
		RequiredPassed:    1,
		RequiredFailed:    0,
		JSONReportPath:    "/tmp/legacy-report.json",
		MarkdownPath:      "/tmp/legacy-report.md",
		SupportedProfiles: []string{"ubuntu-22.04-5.15"},
	}
	line, err := json.Marshal(unsigned)
	if err != nil {
		t.Fatalf("marshal unsigned record: %v", err)
	}
	indexPath := filepath.Join(registryDir, "artifact_versions.jsonl")
	if err := os.WriteFile(indexPath, append(line, '\n'), 0o644); err != nil {
		t.Fatalf("write unsigned index: %v", err)
	}

	updated, err := BackfillArtifactVersionProvenance(workDir)
	if err != nil {
		t.Fatalf("backfill provenance: %v", err)
	}
	if updated != 1 {
		t.Fatalf("expected 1 updated record, got %d", updated)
	}

	verification, err := VerifyArtifactVersionHistory(workDir)
	if err != nil {
		t.Fatalf("verify backfilled history: %v", err)
	}
	if len(verification) != 1 {
		t.Fatalf("expected 1 verification row, got %d", len(verification))
	}
	if !verification[0].Verified {
		t.Fatalf("expected backfilled row to verify, issues=%v", verification[0].Issues)
	}
}

func TestPersistArtifactVersionWithExternalSigner(t *testing.T) {
	workDir := t.TempDir()
	signerBinary := buildTestExternalSignerBinary(t)
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519 key: %v", err)
	}

	t.Setenv(artifactSigningModeEnv, artifactSigningModeExternalCmd)
	t.Setenv(artifactSigningExternalCmdEnv, signerBinary)
	t.Setenv("BPFCOMPAT_TEST_SIGNER_PRIVATE_KEY_B64", base64.StdEncoding.EncodeToString(privateKey))
	t.Setenv(artifactTrustedKeysEnv, base64.StdEncoding.EncodeToString(publicKey))

	record := ArtifactVersionRecord{
		RunID:           "run-external-1",
		RunStartedAt:    "2026-05-16T07:00:00Z",
		CreatedAt:       "2026-05-16T07:00:01Z",
		ArtifactName:    "external-signed",
		ArtifactVersion: "v1",
		ArtifactSHA256:  "abc123",
		ArtifactPath:    "/tmp/external-signed.bpf.o",
		MatrixPath:      "/tmp/mvp.yaml",
		SummaryStatus:   "pass",
		TotalProfiles:   1,
		RequiredPassed:  1,
		JSONReportPath:  "/tmp/external-report.json",
	}
	if err := PersistArtifactVersion(workDir, record); err != nil {
		t.Fatalf("persist artifact record with external signer: %v", err)
	}

	records, err := ListArtifactVersions(workDir, "external-signed", 0)
	if err != nil {
		t.Fatalf("list artifact versions: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(records))
	}
	if records[0].SignatureAlg != artifactHistorySignatureAlgorithm {
		t.Fatalf("unexpected signature_alg: %q", records[0].SignatureAlg)
	}
	if records[0].SignatureKeyID != keyIDFromPublicKey(publicKey) {
		t.Fatalf("unexpected signature key id: %q", records[0].SignatureKeyID)
	}

	verification, err := VerifyArtifactVersionHistory(workDir)
	if err != nil {
		t.Fatalf("verify artifact history: %v", err)
	}
	if len(verification) != 1 {
		t.Fatalf("expected 1 verification row, got %d", len(verification))
	}
	if !verification[0].Verified {
		t.Fatalf("expected external-signed record to verify: issues=%v", verification[0].Issues)
	}
}

func TestPersistArtifactVersionWithExternalSignerRejectsInvalidEnvelope(t *testing.T) {
	workDir := t.TempDir()
	scriptPath := filepath.Join(t.TempDir(), "invalid-signer.sh")
	script := "#!/usr/bin/env bash\nset -euo pipefail\ncat >/dev/null\necho '{}'\n"
	if err := os.WriteFile(scriptPath, []byte(script), 0o755); err != nil {
		t.Fatalf("write invalid signer script: %v", err)
	}

	t.Setenv(artifactSigningModeEnv, artifactSigningModeExternalCmd)
	t.Setenv(artifactSigningExternalCmdEnv, scriptPath)

	record := ArtifactVersionRecord{
		RunID:           "run-invalid-1",
		RunStartedAt:    "2026-05-16T07:00:00Z",
		CreatedAt:       "2026-05-16T07:00:01Z",
		ArtifactName:    "invalid-signed",
		ArtifactVersion: "v1",
		ArtifactSHA256:  "abc123",
		ArtifactPath:    "/tmp/invalid-signed.bpf.o",
		MatrixPath:      "/tmp/mvp.yaml",
		SummaryStatus:   "pass",
		TotalProfiles:   1,
		RequiredPassed:  1,
		JSONReportPath:  "/tmp/invalid-report.json",
	}
	err := PersistArtifactVersion(workDir, record)
	if err == nil {
		t.Fatalf("expected invalid external signer envelope error")
	}
	if !strings.Contains(err.Error(), "invalid external signer envelope") {
		t.Fatalf("expected invalid external signer envelope error, got %v", err)
	}
}

func TestPersistArtifactVersionWithExternalSignerMissingCommand(t *testing.T) {
	workDir := t.TempDir()
	t.Setenv(artifactSigningModeEnv, artifactSigningModeExternalCmd)
	t.Setenv(artifactSigningExternalCmdEnv, "")

	record := ArtifactVersionRecord{
		RunID:           "run-missing-cmd",
		RunStartedAt:    "2026-05-16T07:00:00Z",
		CreatedAt:       "2026-05-16T07:00:01Z",
		ArtifactName:    "missing-cmd",
		ArtifactVersion: "v1",
		ArtifactSHA256:  "abc123",
		ArtifactPath:    "/tmp/missing-cmd.bpf.o",
		MatrixPath:      "/tmp/mvp.yaml",
		SummaryStatus:   "pass",
		TotalProfiles:   1,
		RequiredPassed:  1,
		JSONReportPath:  "/tmp/missing-cmd.json",
	}
	err := PersistArtifactVersion(workDir, record)
	if err == nil {
		t.Fatalf("expected missing external signer command error")
	}
	if !strings.Contains(err.Error(), artifactSigningExternalCmdEnv) {
		t.Fatalf("expected error to mention %s, got %v", artifactSigningExternalCmdEnv, err)
	}
}

func buildTestExternalSignerBinary(t *testing.T) string {
	t.Helper()
	tmpDir := t.TempDir()
	sourcePath := filepath.Join(tmpDir, "external_signer.go")
	source := `package main
import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
)
func main() {
	privateKeyRaw := strings.TrimSpace(os.Getenv("BPFCOMPAT_TEST_SIGNER_PRIVATE_KEY_B64"))
	if privateKeyRaw == "" {
		fmt.Fprintln(os.Stderr, "missing BPFCOMPAT_TEST_SIGNER_PRIVATE_KEY_B64")
		os.Exit(2)
	}
	privateDecoded, err := base64.StdEncoding.DecodeString(privateKeyRaw)
	if err != nil {
		fmt.Fprintf(os.Stderr, "decode private key: %v\n", err)
		os.Exit(2)
	}
	var privateKey ed25519.PrivateKey
	switch len(privateDecoded) {
	case ed25519.PrivateKeySize:
		privateKey = ed25519.PrivateKey(privateDecoded)
	case ed25519.SeedSize:
		privateKey = ed25519.NewKeyFromSeed(privateDecoded)
	default:
		fmt.Fprintf(os.Stderr, "unexpected private key length %d\n", len(privateDecoded))
		os.Exit(2)
	}
	payload, err := io.ReadAll(os.Stdin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read payload: %v\n", err)
		os.Exit(2)
	}
	signature := ed25519.Sign(privateKey, payload)
	publicKey := privateKey.Public().(ed25519.PublicKey)
	sum := sha256.Sum256(publicKey)
	keyID := hex.EncodeToString(sum[:6])
	out := map[string]string{
		"signature_alg": "ed25519",
		"signature_key_id": keyID,
		"signature_public_key": base64.StdEncoding.EncodeToString(publicKey),
		"signature": base64.StdEncoding.EncodeToString(signature),
	}
	enc := json.NewEncoder(os.Stdout)
	if err := enc.Encode(out); err != nil {
		fmt.Fprintf(os.Stderr, "encode output: %v\n", err)
		os.Exit(2)
	}
}`
	if err := os.WriteFile(sourcePath, []byte(source), 0o644); err != nil {
		t.Fatalf("write external signer source: %v", err)
	}
	binaryPath := filepath.Join(tmpDir, "external-signer")
	cmd := exec.Command("go", "build", "-o", binaryPath, sourcePath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("build external signer helper: %v: %s", err, strings.TrimSpace(string(output)))
	}
	return binaryPath
}
