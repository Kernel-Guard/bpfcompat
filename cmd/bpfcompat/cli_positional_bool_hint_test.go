package main

import (
	"testing"

	"github.com/kernel-guard/bpfcompat/internal/runner"
)

// Go's flag package parses "--json false" as --json (set to true) followed by
// the positional "false". The command is refused; the refusal must also tell
// the operator how to spell the value they meant. Every other refusal keeps
// the exact message it had before.
func TestPositionalBoolValueAfterBoolFlagGetsHint(t *testing.T) {
	const rest = "; this command takes only flags, and every flag after a positional argument would be ignored"
	cases := []struct {
		name     string
		args     []string
		cmd      string
		stray    string
		wantHint string // "" means the message must carry no hint
	}{
		{"double dash false", []string{"version", "--json", "false"}, "version", "false", " (boolean flags take the form --json=<value>, e.g. --json=false)"},
		{"single dash true", []string{"version", "-json", "true"}, "version", "true", " (boolean flags take the form --json=<value>, e.g. --json=true)"},
		{"ParseBool spelling FALSE", []string{"env", "--markdown", "FALSE", "--json"}, "env", "FALSE", " (boolean flags take the form --markdown=<value>, e.g. --markdown=FALSE)"},
		{"ParseBool spelling 0", []string{"env", "--json", "0"}, "env", "0", " (boolean flags take the form --json=<value>, e.g. --json=0)"},
		{"ParseBool spelling t", []string{"version", "--json", "t"}, "version", "t", " (boolean flags take the form --json=<value>, e.g. --json=t)"},
		{"agent subcommand", []string{"agent", "ledger", "--json", "false"}, "agent ledger", "false", " (boolean flags take the form --json=<value>, e.g. --json=false)"},
		{"runtime probe", []string{"runtime", "probe", "--probe-use-sudo", "false"}, "runtime probe", "false", " (boolean flags take the form --probe-use-sudo=<value>, e.g. --probe-use-sudo=false)"},

		// No hint: the stray word is not a strconv.ParseBool value.
		{"non-bool word after bool flag", []string{"version", "--json", "stray"}, "version", "stray", ""},
		{"yes is not ParseBool", []string{"version", "--json", "yes"}, "version", "yes", ""},
		// No hint: the boolean flag already carried its value.
		{"bool flag with explicit value", []string{"version", "--json=true", "false"}, "version", "false", ""},
		// No hint: nothing precedes the stray word.
		{"first token", []string{"version", "false"}, "version", "false", ""},
		// No hint: the preceding token is the "--" terminator.
		{"after terminator", []string{"version", "--json", "--", "false"}, "version", "false", ""},
		// No hint: the preceding token is a non-boolean flag's value.
		{"after non-bool flag value", []string{"profile", "list", "--matrix", "m.yaml", "false"}, "profile list", "false", ""},
		// No hint: "--json" here is the value of --workdir, not a flag.
		{"bool-looking value of a string flag", []string{"agent", "ledger", "--workdir", "--json", "false"}, "agent ledger", "false", ""},
		// No hint: the boolean flag is earlier, not right before the word.
		{"bool flag not adjacent", []string{"agent", "ledger", "--json", "--workdir", "w", "false"}, "agent ledger", "false", ""},
		// runtime probe without a boolean flag before the stray word.
		{"runtime probe plain stray", []string{"runtime", "probe", "stray"}, "runtime probe", "stray", ""},
		// runtime worker-execute takes no flags at all; it must refuse
		// before reading the request from stdin.
		{"runtime worker-execute", []string{"runtime", "worker-execute", "stray"}, "runtime worker-execute", "stray", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Chdir(t.TempDir())
			code, stdout, stderr := cliRun(t, tc.args...)
			if code != runner.ExitToolError {
				t.Errorf("exit %d, want %d", code, runner.ExitToolError)
			}
			if stdout != "" {
				t.Errorf("a rejected command wrote to stdout:\n%s", stdout)
			}
			want := tc.cmd + `: unexpected positional argument "` + tc.stray + `"` + rest + tc.wantHint + "\n"
			if stderr != want {
				t.Errorf("stderr mismatch\n got: %q\nwant: %q", stderr, want)
			}
		})
	}
}
