//go:build !unix

package registry

import "os"

// Non-unix builds only get the in-process serialization in
// lockArtifactHistory; concurrent writers in separate processes are not
// supported there.
func lockFileExclusive(*os.File) error { return nil }

func unlockFile(*os.File) error { return nil }
