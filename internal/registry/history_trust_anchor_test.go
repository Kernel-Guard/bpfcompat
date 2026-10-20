package registry

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Throwaway keys only: every key in these tests is generated per test run.

func trustAnchorTestEnv(t *testing.T) {
	t.Helper()
	t.Setenv(artifactSigningModeEnv, "")
	t.Setenv(artifactTrustedKeysEnv, "")
	t.Setenv(artifactTrustedKeyringPathEnv, "")
	t.Setenv(artifactTrustWorkdirKeysEnv, "")
}

func trustAnchorTestRecord(run, ver, created string) ArtifactVersionRecord {
	return ArtifactVersionRecord{
		RunID: run, RunStartedAt: created, CreatedAt: created,
		ArtifactName: "app", ArtifactVersion: ver,
		ArtifactSHA256: "sha-" + ver, ArtifactPath: "/srv/app-" + ver + ".o",
		MatrixPath: "/m.yaml", SummaryStatus: "pass", JSONReportPath: "/r.json",
	}
}

// plantForgedHistory persists one legitimately signed record, removes the
// legitimate key material from the workdir (simulating external custody),
// plants an attacker key in <workdir>/keys/trusted-signing-keys.pub and
// appends a record signed by that attacker key. It returns the legitimate
// key id and base64 public key.
func plantForgedHistory(t *testing.T, wd string) (string, string) {
	t.Helper()
	if err := PersistArtifactVersion(wd, trustAnchorTestRecord("run-v1", "v1", "2026-10-01T00:00:00Z")); err != nil {
		t.Fatal(err)
	}
	pubRaw, err := os.ReadFile(filepath.Join(wd, artifactSigningPublicKeyPath))
	if err != nil {
		t.Fatal(err)
	}
	legit := bytes.Fields(pubRaw)
	if len(legit) != 2 {
		t.Fatalf("unexpected public key file: %q", pubRaw)
	}
	_ = os.Remove(filepath.Join(wd, artifactSigningPrivateKeyPath))
	_ = os.Remove(filepath.Join(wd, artifactSigningPublicKeyPath))

	apub, apriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	aid := keyIDFromPublicKey(apub)
	if err := os.WriteFile(filepath.Join(wd, artifactTrustedKeyringPath),
		[]byte(aid+" "+base64.StdEncoding.EncodeToString(apub)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	prev, err := previousArtifactRecordHash(wd)
	if err != nil {
		t.Fatal(err)
	}
	evil := trustAnchorTestRecord("run-evil", "v9", "2026-10-09T00:00:00Z")
	evil.SchemaVersion = artifactHistorySchemaVersion
	evil.ArtifactSHA256 = "attacker-sha"
	evil.ArtifactPath = "/tmp/evil.bpf.o"
	evil.PrevRecordSHA256 = prev
	payload, h, err := artifactRecordCanonicalPayloadAndHash(evil)
	if err != nil {
		t.Fatal(err)
	}
	evil.RecordSHA256 = h
	evil.SignatureAlg = artifactHistorySignatureAlgorithm
	evil.SignatureKeyID = aid
	evil.SignaturePublicKey = base64.StdEncoding.EncodeToString(apub)
	evil.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(apriv, payload))
	line, err := json.Marshal(evil)
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(filepath.Join(wd, "registry", "artifact_versions.jsonl"), os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write(append(line, '\n')); err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	return string(legit[0]), string(legit[1])
}

func verifyTwoRows(t *testing.T, wd string) []ArtifactVersionVerification {
	t.Helper()
	v, err := VerifyArtifactVersionHistory(wd)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if len(v) != 2 {
		t.Fatalf("expected 2 rows, got %d", len(v))
	}
	return v
}

// SIGN-1 (adapted from the RA-SIGN repro TestRASIGN_WorkdirKeyringInjection):
// with an env trust anchor configured, a key planted in the workdir keyring
// must not anchor a forged record.
func TestHistoryEnvAnchorIgnoresWorkdirKeyring(t *testing.T) {
	for _, mode := range []string{"inline", "path"} {
		t.Run(mode, func(t *testing.T) {
			trustAnchorTestEnv(t)
			wd := t.TempDir()
			kid, pub := plantForgedHistory(t, wd)
			switch mode {
			case "inline":
				t.Setenv(artifactTrustedKeysEnv, kid+":"+pub)
			case "path":
				keyring := filepath.Join(t.TempDir(), "trusted.pub")
				if err := os.WriteFile(keyring, []byte(kid+" "+pub+"\n"), 0o644); err != nil {
					t.Fatal(err)
				}
				t.Setenv(artifactTrustedKeyringPathEnv, keyring)
			}

			v := verifyTwoRows(t, wd)
			if !v[0].Verified || v[0].TrustSource != trustSourceEnv {
				t.Fatalf("legit row: verified=%v trust_source=%q issues=%v", v[0].Verified, v[0].TrustSource, v[0].Issues)
			}
			if v[1].Verified || v[1].SignatureValid {
				t.Fatalf("forged row signed by a workdir-planted key verified despite env anchor: %+v", v[1])
			}
			if v[1].TrustSource != "" {
				t.Fatalf("forged row must not carry a trust_source, got %q", v[1].TrustSource)
			}
			if !strings.Contains(strings.Join(v[1].Issues, ";"), "not in trusted keyring") {
				t.Fatalf("unexpected issues: %v", v[1].Issues)
			}
		})
	}
}

// Escape hatch: BPFCOMPAT_TRUST_WORKDIR_KEYS=true restores the union of
// workdir and env keys (documented: planted workdir keys are trusted again).
func TestHistoryEnvAnchorEscapeHatchTrustsWorkdirKeys(t *testing.T) {
	trustAnchorTestEnv(t)
	wd := t.TempDir()
	kid, pub := plantForgedHistory(t, wd)
	t.Setenv(artifactTrustedKeysEnv, kid+":"+pub)
	t.Setenv(artifactTrustWorkdirKeysEnv, "true")

	v := verifyTwoRows(t, wd)
	if !v[0].Verified || v[0].TrustSource != trustSourceEnv {
		t.Fatalf("legit row: verified=%v trust_source=%q", v[0].Verified, v[0].TrustSource)
	}
	if !v[1].Verified || v[1].TrustSource != trustSourceWorkdir {
		t.Fatalf("escape hatch row: verified=%v trust_source=%q issues=%v", v[1].Verified, v[1].TrustSource, v[1].Issues)
	}
}

// No anchor: behaviour unchanged (trust-on-first-use / tamper evidence only).
func TestHistoryNoAnchorStillTrustsWorkdirKeys(t *testing.T) {
	trustAnchorTestEnv(t)
	wd := t.TempDir()
	_, _ = plantForgedHistory(t, wd)

	v := verifyTwoRows(t, wd)
	if v[0].Verified {
		t.Fatalf("legit row should fail: its key was removed from the workdir and no anchor is set")
	}
	if !v[1].Verified || v[1].TrustSource != trustSourceWorkdir {
		t.Fatalf("no-anchor row: verified=%v trust_source=%q issues=%v", v[1].Verified, v[1].TrustSource, v[1].Issues)
	}

	clean := t.TempDir()
	if err := PersistArtifactVersion(clean, trustAnchorTestRecord("run-v1", "v1", "2026-10-01T00:00:00Z")); err != nil {
		t.Fatal(err)
	}
	cv, err := VerifyArtifactVersionHistory(clean)
	if err != nil || len(cv) != 1 || !cv[0].Verified || cv[0].TrustSource != trustSourceWorkdir {
		t.Fatalf("clean no-anchor history: err=%v rows=%+v", err, cv)
	}
}

// ensureArtifactRegistrySigner silently generates a key when the private key
// is missing. With an env anchor that does not contain that key, the record
// it signs must fail closed.
func TestHistoryEnvAnchorRejectsAutoGeneratedWorkdirKey(t *testing.T) {
	trustAnchorTestEnv(t)
	anchorPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv(artifactTrustedKeysEnv, keyIDFromPublicKey(anchorPub)+":"+base64.StdEncoding.EncodeToString(anchorPub))

	wd := t.TempDir()
	if err := PersistArtifactVersion(wd, trustAnchorTestRecord("run-v1", "v1", "2026-10-01T00:00:00Z")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(wd, artifactSigningPublicKeyPath)); err != nil {
		t.Fatalf("expected auto-generated workdir public key: %v", err)
	}
	v, err := VerifyArtifactVersionHistory(wd)
	if err != nil {
		t.Fatal(err)
	}
	if len(v) != 1 || v[0].Verified || v[0].SignatureValid {
		t.Fatalf("auto-generated workdir key must not verify under env anchor: %+v", v)
	}
}

func TestArtifactHistoryTrustAnchorWarning(t *testing.T) {
	trustAnchorTestEnv(t)
	if w := ArtifactHistoryTrustAnchorWarning(); !strings.Contains(w, artifactTrustedKeyringPathEnv) {
		t.Fatalf("expected no-anchor warning, got %q", w)
	}
	inline := "c2VjcmV0LXNob3VsZC1ub3QtbGVhaw=="
	t.Setenv(artifactTrustedKeysEnv, "kid:"+inline)
	if w := ArtifactHistoryTrustAnchorWarning(); w != "" {
		t.Fatalf("expected no warning with anchor, got %q", w)
	}
	t.Setenv(artifactTrustWorkdirKeysEnv, "true")
	w := ArtifactHistoryTrustAnchorWarning()
	if !strings.Contains(w, artifactTrustWorkdirKeysEnv) || strings.Contains(w, inline) {
		t.Fatalf("unexpected escape-hatch warning: %q", w)
	}
}
