package vm

import (
	"context"
	"io"
	"slices"
	"strings"
	"testing"
)

func TestSSHScriptCommandKeepsGuestScriptOutOfHostArgv(t *testing.T) {
	t.Parallel()

	target := sshTarget{
		User:       "tester",
		PrivateKey: "/tmp/test-key",
		Port:       2222,
		Host:       "127.0.0.1",
	}
	scriptInput := "printf '%s\\n' 'guest payload; $(touch /host-must-not-run)'"

	cmd := sshScriptCommand(context.Background(), target, scriptInput)
	if slices.Contains(cmd.Args, scriptInput) {
		t.Fatalf("guest script must not appear in host ssh argv: %#v", cmd.Args)
	}
	if got := cmd.Args[len(cmd.Args)-1]; got != "bash -s" {
		t.Fatalf("remote ssh command = %q, want fixed %q", got, "bash -s")
	}

	stdin, err := io.ReadAll(cmd.Stdin)
	if err != nil {
		t.Fatalf("read command stdin: %v", err)
	}
	if got := string(stdin); got != scriptInput {
		t.Fatalf("command stdin = %q, want %q", got, scriptInput)
	}
	for _, arg := range cmd.Args {
		if strings.Contains(arg, "host-must-not-run") {
			t.Fatalf("guest payload leaked into host argv argument %q", arg)
		}
	}
}
