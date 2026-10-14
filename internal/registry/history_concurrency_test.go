package registry

import (
	"bytes"
	"crypto/ed25519"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
)

const (
	registryHelperWorkDirEnv = "BPFCOMPAT_REGISTRY_TEST_HELPER_WORKDIR"
	registryHelperWriterEnv  = "BPFCOMPAT_REGISTRY_TEST_HELPER_WRITER"
	registryHelperCountEnv   = "BPFCOMPAT_REGISTRY_TEST_HELPER_COUNT"
)

func concurrencyTestRecord(writer, seq int) ArtifactVersionRecord {
	return ArtifactVersionRecord{
		RunID:           fmt.Sprintf("run-w%d-%d", writer, seq),
		ArtifactName:    "concurrent",
		ArtifactVersion: fmt.Sprintf("v%d.%d", writer, seq),
		ArtifactSHA256:  "00",
		JSONReportPath:  "/tmp/report.json",
		SummaryStatus:   "pass",
	}
}

// assertHistoryIntact runs the verification behind `bpfcompat history verify`
// and requires every record to verify with no issues.
func assertHistoryIntact(t *testing.T, workDir string, wantRecords int) {
	t.Helper()
	rows, err := VerifyArtifactVersionHistory(workDir)
	if err != nil {
		t.Fatalf("verify artifact history: %v", err)
	}
	if len(rows) != wantRecords {
		t.Fatalf("expected %d history records, got %d", wantRecords, len(rows))
	}
	bad := 0
	for i := range rows {
		row := &rows[i]
		if row.Verified && len(row.Issues) == 0 {
			continue
		}
		bad++
		if bad <= 5 {
			t.Errorf("record index %d (run %s) failed verification: %v", row.Index, row.RunID, row.Issues)
		}
	}
	if bad > 0 {
		t.Fatalf("%d of %d records failed history verification after concurrent persists", bad, len(rows))
	}
}

// Regression for A4-8: concurrent honest writers sharing one WorkDir (the API
// runs up to two active jobs against the same WorkDir) must not corrupt the
// signed hash chain or race first-use signing-key creation.
func TestPersistArtifactVersionConcurrentWritersKeepHistoryValid(t *testing.T) {
	t.Setenv(artifactSigningModeEnv, "")
	const (
		rounds  = 10
		writers = 8
		perW    = 4
	)
	for round := 0; round < rounds; round++ {
		workDir := t.TempDir()
		var wg sync.WaitGroup
		start := make(chan struct{})
		for w := 0; w < writers; w++ {
			wg.Add(1)
			go func(w int) {
				defer wg.Done()
				<-start
				for i := 0; i < perW; i++ {
					if err := PersistArtifactVersion(workDir, concurrencyTestRecord(w, i)); err != nil {
						t.Errorf("round %d writer %d persist %d: %v", round, w, i, err)
					}
				}
			}(w)
		}
		close(start)
		wg.Wait()
		if t.Failed() {
			t.FailNow()
		}
		assertHistoryIntact(t, workDir, writers*perW)
	}
}

// TestRegistryHistoryHelperProcess is the child body for the cross-process
// regression test below. It is a no-op unless the helper env vars are set.
func TestRegistryHistoryHelperProcess(t *testing.T) {
	workDir := os.Getenv(registryHelperWorkDirEnv)
	if workDir == "" {
		t.Skip("helper process only")
	}
	writer, err := strconv.Atoi(os.Getenv(registryHelperWriterEnv))
	if err != nil {
		t.Fatalf("parse writer: %v", err)
	}
	count, err := strconv.Atoi(os.Getenv(registryHelperCountEnv))
	if err != nil {
		t.Fatalf("parse count: %v", err)
	}
	for i := 0; i < count; i++ {
		if err := PersistArtifactVersion(workDir, concurrencyTestRecord(writer, i)); err != nil {
			t.Fatalf("writer %d persist %d: %v", writer, i, err)
		}
	}
}

func TestPersistArtifactVersionConcurrentProcessesKeepHistoryValid(t *testing.T) {
	const (
		rounds    = 3
		processes = 4
		perProc   = 10
	)
	for round := 0; round < rounds; round++ {
		workDir := t.TempDir()
		cmds := make([]*exec.Cmd, 0, processes)
		outputs := make([]*bytes.Buffer, 0, processes)
		for p := 0; p < processes; p++ {
			cmd := exec.Command(os.Args[0], "-test.run=^TestRegistryHistoryHelperProcess$", "-test.count=1")
			cmd.Env = append(os.Environ(),
				registryHelperWorkDirEnv+"="+workDir,
				registryHelperWriterEnv+"="+strconv.Itoa(p),
				registryHelperCountEnv+"="+strconv.Itoa(perProc),
				artifactSigningModeEnv+"=",
			)
			out := &bytes.Buffer{}
			cmd.Stdout = out
			cmd.Stderr = out
			cmds = append(cmds, cmd)
			outputs = append(outputs, out)
		}
		for p, cmd := range cmds {
			if err := cmd.Start(); err != nil {
				t.Fatalf("start helper %d: %v", p, err)
			}
		}
		for p, cmd := range cmds {
			if err := cmd.Wait(); err != nil {
				t.Fatalf("round %d helper %d failed: %v\n%s", round, p, err, outputs[p].String())
			}
		}
		assertHistoryIntact(t, workDir, processes*perProc)
	}
}

func TestEnsureArtifactRegistrySignerConcurrentFirstUseCreatesOneTrustedKey(t *testing.T) {
	const callers = 16
	for round := 0; round < 10; round++ {
		workDir := t.TempDir()
		keyIDs := make([]string, callers)
		var wg sync.WaitGroup
		start := make(chan struct{})
		for i := 0; i < callers; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				<-start
				signer, err := ensureArtifactRegistrySigner(workDir)
				if err != nil {
					t.Errorf("round %d caller %d: %v", round, i, err)
					return
				}
				keyIDs[i] = signer.KeyID
			}(i)
		}
		close(start)
		wg.Wait()
		if t.Failed() {
			t.FailNow()
		}
		for i, id := range keyIDs {
			if id != keyIDs[0] {
				t.Fatalf("round %d: caller %d got key %q, caller 0 got %q (more than one key created)", round, i, id, keyIDs[0])
			}
		}

		privatePath := filepath.Join(workDir, artifactSigningPrivateKeyPath)
		raw, err := os.ReadFile(privatePath)
		if err != nil {
			t.Fatalf("read private key: %v", err)
		}
		privateKey, err := decodeEd25519PrivateKey(strings.TrimSpace(string(raw)))
		if err != nil {
			t.Fatalf("decode private key: %v", err)
		}
		publicKey := privateKey.Public().(ed25519.PublicKey)
		if got := keyIDFromPublicKey(publicKey); got != keyIDs[0] {
			t.Fatalf("round %d: on-disk private key %q does not match returned key %q", round, got, keyIDs[0])
		}
		info, err := os.Stat(privatePath)
		if err != nil {
			t.Fatalf("stat private key: %v", err)
		}
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Fatalf("round %d: private key mode %o, want 600", round, perm)
		}

		trusted, err := loadTrustedSigningKeys(workDir)
		if err != nil {
			t.Fatalf("load trusted keys: %v", err)
		}
		if len(trusted) != 1 || trusted[0].KeyID != keyIDs[0] || !publicKey.Equal(trusted[0].PublicKey) {
			t.Fatalf("round %d: trusted keyring %+v does not hold exactly the created key %q", round, trusted, keyIDs[0])
		}
		entries, err := os.ReadDir(filepath.Dir(privatePath))
		if err != nil {
			t.Fatalf("read keys dir: %v", err)
		}
		if len(entries) != 2 {
			names := make([]string, 0, len(entries))
			for _, e := range entries {
				names = append(names, e.Name())
			}
			t.Fatalf("round %d: expected exactly the private and public key files, got %v", round, names)
		}
	}
}
