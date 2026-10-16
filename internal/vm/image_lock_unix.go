//go:build unix

package vm

import (
	"context"
	"errors"
	"fmt"
	"os"
	"syscall"
	"time"
)

const imageLockPoll = 100 * time.Millisecond

// lockImage takes an exclusive flock on <imagePath>.lock, waiting while
// another process (or another open file in this one) holds it, until ctx
// ends. The kernel drops the lock when its holder exits, however it exits, so
// a killed downloader cannot leave the image locked. flock is local to a host;
// a cache on a network filesystem shared between hosts is not protected.
func lockImage(ctx context.Context, imagePath string) (func(), error) {
	lockPath := imagePath + ".lock"
	f, err := os.OpenFile(lockPath, os.O_RDWR|os.O_CREATE, 0o644) // #nosec G302 G304 -- lock file in the image cache; holds no data.
	if err != nil {
		return nil, fmt.Errorf("open image lock %s: %w", lockPath, err)
	}
	fd := int(f.Fd()) // #nosec G115 -- a file descriptor always fits in int.
	for {
		err := syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return func() {
				_ = syscall.Flock(fd, syscall.LOCK_UN)
				_ = f.Close()
			}, nil
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EINTR) {
			_ = f.Close()
			return nil, fmt.Errorf("lock image %s: %w", lockPath, err)
		}
		select {
		case <-ctx.Done():
			_ = f.Close()
			return nil, fmt.Errorf("wait for image lock %s (another run is downloading this image): %w", lockPath, ctx.Err())
		case <-time.After(imageLockPoll):
		}
	}
}
