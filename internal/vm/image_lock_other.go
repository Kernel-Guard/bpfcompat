//go:build !unix

package vm

import "context"

// lockImage is a no-op where flock is unavailable. The VM runner is supported
// on Linux only; on other systems concurrent runs sharing one image cache are
// not serialized.
func lockImage(context.Context, string) (func(), error) { return func() {}, nil }
