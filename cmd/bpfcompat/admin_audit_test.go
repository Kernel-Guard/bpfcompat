package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/erenari/bpfcompat/internal/cloudregistry"
)

// TestAuditExportAndVerifyRoundtrip is the load-bearing test for the
// signed audit pipeline. It seeds events, runs export with --sign-key,
// then runs verify against the produced files. A regression here means
// auditors can't trust the export — the entire compliance story falls
// over.
func TestAuditExportAndVerifyRoundtrip(t *testing.T) {
	workDir := t.TempDir()
	seedAuditEvents(t, workDir)

	keyPath := writeEd25519KeyToFile(t)
	outPath := filepath.Join(t.TempDir(), "audit.ndjson")
	sigPath := outPath + ".sig"

	code := runAdminAuditExport([]string{
		"--workdir", workDir,
		"--out", outPath,
		"--sign-key", keyPath,
		"--sig-out", sigPath,
	})
	if code != 0 {
		t.Fatalf("audit-export exited %d", code)
	}

	if _, err := os.Stat(outPath); err != nil {
		t.Fatalf("expected output file: %v", err)
	}
	if _, err := os.Stat(sigPath); err != nil {
		t.Fatalf("expected signature file: %v", err)
	}

	// Self-attesting verification is available only by explicit opt-in for
	// dev/demo workflows.
	if code := runAdminAuditVerify([]string{"--input", outPath, "--sig", sigPath, "--trust-envelope-key"}); code != 0 {
		t.Fatalf("audit-verify with trusted envelope key failed with code %d", code)
	}

	// Verify again with explicitly pinned pubkey — stronger mode.
	pubPath := writeEd25519PubKeyToFile(t, keyPath)
	if code := runAdminAuditVerify([]string{"--input", outPath, "--sig", sigPath, "--pubkey", pubPath}); code != 0 {
		t.Fatalf("audit-verify with pinned pubkey failed with code %d", code)
	}
}

func TestAuditVerifyRequiresPinnedPubkeyByDefault(t *testing.T) {
	workDir := t.TempDir()
	seedAuditEvents(t, workDir)
	keyPath := writeEd25519KeyToFile(t)
	outPath := filepath.Join(t.TempDir(), "audit.ndjson")
	sigPath := outPath + ".sig"

	if code := runAdminAuditExport([]string{
		"--workdir", workDir,
		"--out", outPath,
		"--sign-key", keyPath,
		"--sig-out", sigPath,
	}); code != 0 {
		t.Fatalf("export exited %d", code)
	}
	if code := runAdminAuditVerify([]string{"--input", outPath, "--sig", sigPath}); code == 0 {
		t.Fatalf("expected audit-verify without --pubkey to fail")
	}
}

// TestAuditVerifyDetectsTamper proves that any byte-level mutation of the
// export breaks verification. This is the actual security property we're
// shipping — the prior test only proves "we can sign and verify our own
// output", this test proves the signature is bound to the bytes.
func TestAuditVerifyDetectsTamper(t *testing.T) {
	workDir := t.TempDir()
	seedAuditEvents(t, workDir)
	keyPath := writeEd25519KeyToFile(t)
	outPath := filepath.Join(t.TempDir(), "audit.ndjson")
	sigPath := outPath + ".sig"

	if code := runAdminAuditExport([]string{
		"--workdir", workDir,
		"--out", outPath,
		"--sign-key", keyPath,
		"--sig-out", sigPath,
	}); code != 0 {
		t.Fatalf("export exited %d", code)
	}

	// Append a single byte to the export — verification MUST fail.
	body, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read export: %v", err)
	}
	body = append(body, ' ')
	if err := os.WriteFile(outPath, body, 0o600); err != nil {
		t.Fatalf("write tampered export: %v", err)
	}

	pubPath := writeEd25519PubKeyToFile(t, keyPath)
	if code := runAdminAuditVerify([]string{"--input", outPath, "--sig", sigPath, "--pubkey", pubPath}); code == 0 {
		t.Fatalf("expected verify to fail on tampered export, got 0")
	}
}

// TestAuditExportRequiresOutWithSignKey covers the input-validation rule
// from the export command. Without --out we'd be streaming bytes to stdout
// and signing a copy that the caller can't reproduce — a worse outcome
// than the small operator friction of having to specify --out.
func TestAuditExportRequiresOutWithSignKey(t *testing.T) {
	workDir := t.TempDir()
	keyPath := writeEd25519KeyToFile(t)
	if code := runAdminAuditExport([]string{
		"--workdir", workDir,
		"--sign-key", keyPath,
	}); code == 0 {
		t.Fatalf("expected non-zero exit when --sign-key without --out/--sig-out")
	}
}

func seedAuditEvents(t *testing.T, workDir string) {
	t.Helper()
	store := cloudregistry.NewStore(workDir)
	for i, action := range []string{"artifact.upload", "artifact.download", "project.create"} {
		if _, err := store.AppendAudit(cloudregistry.AuditEvent{
			Action:  action,
			Tenant:  "acme",
			Project: "demo",
			Status:  "ok",
			Actor:   "svc-test",
			Metadata: map[string]any{
				"idx": i,
			},
		}); err != nil {
			t.Fatalf("append audit event: %v", err)
		}
	}
}

func writeEd25519KeyToFile(t *testing.T) string {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen ed25519 key: %v", err)
	}
	path := filepath.Join(t.TempDir(), "audit-sign.key")
	body := base64.StdEncoding.EncodeToString(priv)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	return path
}

func writeEd25519PubKeyToFile(t *testing.T, privPath string) string {
	t.Helper()
	rawPriv, err := os.ReadFile(privPath)
	if err != nil {
		t.Fatalf("read priv: %v", err)
	}
	decoded, err := base64.StdEncoding.DecodeString(string(rawPriv))
	if err != nil {
		t.Fatalf("decode priv: %v", err)
	}
	priv := ed25519.PrivateKey(decoded)
	pub := priv.Public().(ed25519.PublicKey)
	path := filepath.Join(t.TempDir(), "audit-sign.pub")
	if err := os.WriteFile(path, []byte(base64.StdEncoding.EncodeToString(pub)), 0o600); err != nil {
		t.Fatalf("write pub: %v", err)
	}
	return path
}

// TestSignatureEnvelopeShape is a small structural test that pins the
// on-disk JSON layout. If a downstream verifier hard-codes the field
// names (which it will — that's the point of a stable envelope), changing
// this struct silently would break them. This test forces the change to
// be explicit.
func TestSignatureEnvelopeShape(t *testing.T) {
	env := auditSignatureEnvelope{
		Algorithm: "ed25519",
		PublicKey: "pk",
		SHA256:    "deadbeef",
		Signature: "sig",
	}
	body, err := json.Marshal(env)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got := string(body)
	for _, want := range []string{`"algorithm":"ed25519"`, `"public_key":"pk"`, `"sha256":"deadbeef"`, `"signature":"sig"`} {
		if !contains(got, want) {
			t.Fatalf("envelope missing %q: %s", want, got)
		}
	}
}
