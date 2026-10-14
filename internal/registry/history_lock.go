package registry

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// artifactHistoryLockName is the advisory lock file that guards the signed
// artifact history (registry/artifact_versions.jsonl). It holds no data.
const artifactHistoryLockName = ".history.lock"

// artifactHistoryProcessLocks serializes writers inside one process, keyed by
// the absolute registry directory. The file lock serializes writers across
// processes.
var artifactHistoryProcessLocks sync.Map // map[string]*sync.Mutex

// lockArtifactHistory takes an exclusive lock on the artifact history in
// registryDir and returns the function that releases it. Writers hold it
// across reading the previous record hash, first-use key creation, signing and
// appending, so concurrent writers cannot fork or corrupt the hash chain.
func lockArtifactHistory(registryDir string) (func(), error) {
	absDir, err := filepath.Abs(registryDir)
	if err != nil {
		return nil, fmt.Errorf("resolve registry directory: %w", err)
	}
	value, _ := artifactHistoryProcessLocks.LoadOrStore(absDir, &sync.Mutex{})
	mu := value.(*sync.Mutex)
	mu.Lock()

	f, err := os.OpenFile(filepath.Join(absDir, artifactHistoryLockName), os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		mu.Unlock()
		return nil, fmt.Errorf("open artifact history lock: %w", err)
	}
	if err := lockFileExclusive(f); err != nil {
		_ = f.Close()
		mu.Unlock()
		return nil, fmt.Errorf("lock artifact history: %w", err)
	}
	return func() {
		_ = unlockFile(f)
		_ = f.Close()
		mu.Unlock()
	}, nil
}
