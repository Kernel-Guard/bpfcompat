package registry

import (
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
)

const maxFuzzHistoryBytes = 1 << 20

// FuzzReadRegistryHistory writes arbitrary bytes as both registry JSONL
// indexes (artifact_versions.jsonl and runs.jsonl) and drives every reader the
// API history/runs endpoints use.
//
// Properties: no panic; limit is honoured; artifact-name filtering only
// returns matching records; lookups never return a record that does not match
// the requested key.
func FuzzReadRegistryHistory(f *testing.F) {
	f.Add([]byte(`{"run_id":"run-1","created_at":"2026-05-15T17:00:01Z","artifact_name":"execsnoop","artifact_version":"v1","artifact_sha256":"abc123","summary_status":"pass","total_profiles":8}
{"run_id":"run-2","created_at":"2026-05-15T17:01:01Z","artifact_name":"execsnoop","artifact_version":"v2"}
`), "execsnoop", "v2", "run-1")
	f.Add([]byte(`{"run_id":"r","started_at":"2026-01-01T00:00:00Z","status":"pass"}`+"\n\n   \n"), "", "", "r")
	f.Add([]byte("{\"run_id\":1}\n"), "x", "v", "1")
	f.Add([]byte("not json\n"), "x", "v", "r")
	f.Add([]byte(""), "", "", "")

	f.Fuzz(func(t *testing.T, raw []byte, artifactName, version, runID string) {
		if len(raw) > maxFuzzHistoryBytes {
			raw = raw[:maxFuzzHistoryBytes]
		}
		workDir := t.TempDir()
		registryDir := filepath.Join(workDir, "registry")
		if err := os.MkdirAll(registryDir, 0o700); err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{"artifact_versions.jsonl", "runs.jsonl"} {
			if err := os.WriteFile(filepath.Join(registryDir, name), raw, 0o600); err != nil {
				t.Fatal(err)
			}
		}

		versions, err := ListArtifactVersions(workDir, artifactName, 2)
		if err == nil {
			if len(versions) > 2 {
				t.Fatalf("limit 2 returned %d records", len(versions))
			}
			for i := range versions {
				if artifactName != "" && versions[i].ArtifactName != artifactName {
					t.Fatalf("filter %q returned record for %q", artifactName, versions[i].ArtifactName)
				}
			}
		}
		if found, err := FindArtifactVersion(workDir, artifactName, version); err == nil {
			if found.ArtifactName != artifactName || found.ArtifactVersion != version {
				t.Fatalf("FindArtifactVersion(%q,%q) returned %q@%q", artifactName, version, found.ArtifactName, found.ArtifactVersion)
			}
		}

		runs, err := ListRunRecords(workDir, 1)
		if err == nil && len(runs) > 1 {
			t.Fatalf("limit 1 returned %d runs", len(runs))
		}
		if run, err := GetRunRecord(workDir, runID); err == nil && run.RunID != runID {
			t.Fatalf("GetRunRecord(%q) returned run %q", runID, run.RunID)
		}
	})
}

// FuzzParseTrustedSigningKeysLines covers the trusted-keyring parser (the
// keyring file and BPFCOMPAT_TRUSTED_SIGNING_KEYS_PATH content).
//
// Properties: no panic; every accepted key is a full-length Ed25519 public
// key with a non-empty key ID.
func FuzzParseTrustedSigningKeysLines(f *testing.F) {
	pub := make(ed25519.PublicKey, ed25519.PublicKeySize)
	for i := range pub {
		pub[i] = byte(i)
	}
	encoded := base64.StdEncoding.EncodeToString(pub)
	f.Add(encoded + "\n")
	f.Add("# comment\nkey-1 " + encoded + "\n\n")
	f.Add("key-1 " + encoded + " trailing fields\n" + encoded)
	f.Add("key-1 not-base64\n")
	f.Add("AAAA\n")
	f.Add("")

	f.Fuzz(func(t *testing.T, raw string) {
		if len(raw) > maxFuzzHistoryBytes {
			raw = raw[:maxFuzzHistoryBytes]
		}
		keys, err := parseTrustedSigningKeysLines(raw)
		if err != nil {
			return
		}
		for _, key := range keys {
			if len(key.PublicKey) != ed25519.PublicKeySize {
				t.Fatalf("accepted key with length %d", len(key.PublicKey))
			}
			if key.KeyID == "" {
				t.Fatalf("accepted key with empty key ID")
			}
		}
		_, _ = parseInlineTrustedKey(raw)
	})
}
