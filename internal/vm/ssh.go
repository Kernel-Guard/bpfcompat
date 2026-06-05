package vm

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

const sshProbeToken = "__BPFCOMPAT_OK__"

type sshTarget struct {
	User       string
	PrivateKey string
	Port       int
	Host       string
}

func (t sshTarget) addr() string {
	host := strings.TrimSpace(t.Host)
	if host == "" {
		host = "127.0.0.1"
	}
	return fmt.Sprintf("%s@%s", t.User, host)
}

func (t sshTarget) sshArgs(remoteCmd string) []string {
	return []string{
		"-q",
		"-i", t.PrivateKey,
		"-p", fmt.Sprintf("%d", t.Port),
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "BatchMode=yes",
		"-o", "ConnectTimeout=5",
		t.addr(),
		remoteCmd,
	}
}

func (t sshTarget) scpBaseArgs() []string {
	return []string{
		"-q",
		"-i", t.PrivateKey,
		"-P", fmt.Sprintf("%d", t.Port),
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "BatchMode=yes",
		"-o", "ConnectTimeout=5",
	}
}

func waitForSSHAnyUser(ctx context.Context, base sshTarget, users []string, timeout time.Duration) (sshTarget, error) {
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	deadline := time.Now().Add(timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}

	var lastErr error
	for {
		for _, user := range users {
			user = strings.TrimSpace(user)
			if user == "" {
				continue
			}
			target := base
			target.User = user
			if err := sshProbe(ctx, target); err == nil {
				return target, nil
			} else {
				lastErr = err
			}
		}

		if time.Now().After(deadline) {
			break
		}
		select {
		case <-ctx.Done():
			if lastErr != nil {
				return sshTarget{}, fmt.Errorf("ssh not ready: %w (context: %v)", lastErr, ctx.Err())
			}
			return sshTarget{}, fmt.Errorf("ssh not ready: %w", ctx.Err())
		case <-time.After(1500 * time.Millisecond):
		}
	}

	if lastErr != nil {
		return sshTarget{}, fmt.Errorf("ssh not ready before timeout: %w", lastErr)
	}
	return sshTarget{}, fmt.Errorf("ssh not ready before timeout")
}

func sshProbe(ctx context.Context, target sshTarget) error {
	cmd := exec.CommandContext(ctx, "ssh", target.sshArgs(fmt.Sprintf("printf %q", sshProbeToken))...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(output))
		if msg == "" {
			msg = err.Error()
		}
		return fmt.Errorf("ssh run failed (%s): %s", target.addr(), msg)
	}

	trimmed := strings.TrimSpace(string(output))
	if trimmed != sshProbeToken {
		return fmt.Errorf("ssh probe output mismatch (%s): %q", target.addr(), trimmed)
	}
	return nil
}

func sshRun(ctx context.Context, target sshTarget, remoteCmd string) error {
	cmd := exec.CommandContext(ctx, "ssh", target.sshArgs(remoteCmd)...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(output))
		if msg == "" {
			msg = err.Error()
		}
		return fmt.Errorf("ssh run failed (%s): %s", target.addr(), msg)
	}
	return nil
}

func scpToGuest(ctx context.Context, target sshTarget, localPath, remotePath string) error {
	args := append(target.scpBaseArgs(), localPath, fmt.Sprintf("%s:%s", target.addr(), remotePath))
	cmd := exec.CommandContext(ctx, "scp", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(output))
		if msg == "" {
			msg = err.Error()
		}
		return fmt.Errorf("scp to guest failed (%s -> %s): %s", localPath, remotePath, msg)
	}
	return nil
}

func scpFromGuest(ctx context.Context, target sshTarget, remotePath, localPath string) error {
	args := append(target.scpBaseArgs(), fmt.Sprintf("%s:%s", target.addr(), remotePath), localPath)
	cmd := exec.CommandContext(ctx, "scp", args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(output))
		if msg == "" {
			msg = err.Error()
		}
		return fmt.Errorf("scp from guest failed (%s -> %s): %s", remotePath, localPath, msg)
	}
	return nil
}
