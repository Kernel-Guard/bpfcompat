package main

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

func TestActiveWorkflowPins(t *testing.T) {
	sha := strings.Repeat("a", 40)
	tag := "v0.4.0-rc.5"
	good := "Kernel-Guard/bpfcompat@" + sha + " # " + tag
	workflow := func(steps string) string { return "jobs:\n  test:\n    steps:\n" + steps }
	tests := []struct {
		name, mode, text string
		ok               bool
	}{
		{"plain", "all", workflow("      - uses: " + good + "\n"), true},
		{"quoted", "all", workflow("      - uses: 'kernel-guard/bpfcompat@" + sha + "' # " + tag + "\n"), true},
		{"marker", "candidate", workflow("      - name: candidate\n        # bpfcompat-pin: candidate\n        uses: " + good + "\n"), true},
		{"comment-only", "all", workflow("      # - uses: " + good + "\n      - run: true\n"), false},
		{"hidden-ref", "all", workflow("      - uses: " + good + "\n      - uses: Kernel-Guard/bpfcompat@main\n"), false},
		{"folded-ref", "all", workflow("      - uses: " + good + "\n      - uses: >-\n          Kernel-Guard/bpfcompat@main\n"), false},
		{"unicode-ref", "all", workflow("      - uses: " + good + "\n      - uses: \"Kernel-\\u0047uard/bpfcompat@main\"\n"), false},
		{"run-text", "all", workflow("      - run: |\n          uses: " + good + "\n"), false},
		{"run-marker", "candidate", workflow("      - run: |\n          # bpfcompat-pin: candidate\n          uses: " + good + "\n      - uses: Kernel-Guard/bpfcompat@main\n"), false},
		{"flow-stale", "all", workflow("      - uses: " + good + "\n      - {uses: 'Kernel-Guard/bpfcompat@main'}\n"), false},
		{"flow-correct", "all", "jobs: {test: {steps: [{uses: 'Kernel-Guard/bpfcompat@" + sha + "'}]}}\n", false}, // missing tag comment
		{"quoted-key", "all", workflow("      - uses: " + good + "\n      - 'uses': Kernel-Guard/bpfcompat@main\n"), false},
		{"wrong-tag", "all", workflow("      - uses: Kernel-Guard/bpfcompat@" + sha + " # v0.4.0-rc.4\n"), false},
		{"duplicate-key", "all", workflow("      - uses: " + good + "\n        uses: Kernel-Guard/bpfcompat@main\n"), false},
		{"duplicate-marker", "candidate", workflow("      - name: first\n        # bpfcompat-pin: candidate\n        uses: " + good + "\n      - name: second\n        # bpfcompat-pin: candidate\n        uses: " + good + "\n"), false},
		{"alias", "all", workflow("      - uses: &pin Kernel-Guard/bpfcompat@" + sha + " # " + tag + "\n      - uses: *pin\n"), false},
		{"multi-document", "all", workflow("      - uses: "+good+"\n") + "---\njobs: {}\n", false},
		{"no-jobs", "all", "run: 'uses: " + good + "'\n", false},
		{"wrong-type", "all", workflow("      - uses: [invalid]\n"), false},
		{"subpath", "all", workflow("      - uses: " + good + "\n      - uses: Kernel-Guard/bpfcompat/sub@" + sha + " # " + tag + "\n"), false},
		{"disabled-step", "all", workflow("      - if: false\n        uses: " + good + "\n"), false},
		{"disabled-expression", "all", workflow("      - if: ${{ false }}\n        uses: " + good + "\n"), false},
		{"disabled-job", "candidate", "jobs:\n  decoy:\n    if: ${{ false }}\n    steps:\n      - name: decoy\n        # bpfcompat-pin: candidate\n        uses: " + good + "\n  real:\n    steps:\n      - uses: Kernel-Guard/bpfcompat@main\n", false},
		{"disabled-marked-step", "candidate", workflow("      - name: decoy\n        if: 0\n        # bpfcompat-pin: candidate\n        uses: " + good + "\n      - uses: Kernel-Guard/bpfcompat@main\n"), false},
		{"conditional-step", "all", workflow("      - if: needs.plan.outputs.should_run == 'true'\n        uses: " + good + "\n"), true},
		{"conditional-job", "all", "jobs:\n  test:\n    if: ${{ needs.plan.outputs.should_run == 'true' }}\n    uses: " + good + "\n", true},
		{"merge-key", "all", workflow("      - uses: " + good + "\n      - <<: {uses: Kernel-Guard/bpfcompat@main}\n"), false},
		{"case-variant-uses", "all", workflow("      - uses: " + good + "\n      - Uses: Kernel-Guard/bpfcompat@main\n"), false},
		{"case-variant-steps", "all", "jobs:\n  test:\n    Steps:\n      - uses: Kernel-Guard/bpfcompat@main\n  ok:\n    steps:\n      - uses: " + good + "\n", false},
		{"kelvin-sign-owner", "all", workflow("      - uses: \"\u212Aernel-Guard/bpfcompat@" + sha + "\" # " + tag + "\n"), false},
		{"uppercase-sha", "all", workflow("      - uses: Kernel-Guard/bpfcompat@" + strings.ToUpper(sha) + " # " + tag + "\n"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := check(strings.NewReader(tt.text), tt.mode, sha, tag)
			if (err == nil) != tt.ok {
				t.Fatalf("check() = %v, want accepted=%v", err, tt.ok)
			}
		})
	}
}

// A pin on a step or job that can never run must not count. In an expression
// GitHub treats false, 0, -0, the empty string, null and NaN as falsy and
// accepts any JSON number form. An if that is empty or YAML null is no
// condition at all, and keywords are case-insensitive.
func TestNeverRunningPins(t *testing.T) {
	sha := strings.Repeat("a", 40)
	tag := "v0.4.0-rc.5"
	good := "Kernel-Guard/bpfcompat@" + sha + " # " + tag
	for _, cond := range []string{"false", "${{ false }}", "-0", "${{ -0 }}", "-0.0", "0.0", "${{ 0.0 }}", "0e0", ".0", "00",
		"0x0", "${{ 0x0 }}", "0x00", "NaN", "${{ NaN }}", "\"''\"", "${{ '' }}", "${{ null }}", "False", "false && true", "${{ !true }}", "1 == 2"} {
		t.Run("step if "+cond, func(t *testing.T) {
			text := "jobs:\n  test:\n    steps:\n      - if: " + cond + "\n        uses: " + good + "\n"
			if err := check(strings.NewReader(text), "all", sha, tag); err == nil {
				t.Fatalf("pin under if: %s accepted", cond)
			}
		})
		t.Run("job if "+cond, func(t *testing.T) {
			text := "jobs:\n  test:\n    if: " + cond + "\n    uses: " + good + "\n"
			if err := check(strings.NewReader(text), "all", sha, tag); err == nil {
				t.Fatalf("job pin under if: %s accepted", cond)
			}
		})
	}
	for _, cond := range []string{"true", "${{ true }}", "True", "TRUE", "''", "null", "~", "", "needs.plan.outputs.should_run == 'true'", "${{ github.event_name == 'schedule' }}", "always()"} {
		t.Run("runs "+cond, func(t *testing.T) {
			text := "jobs:\n  test:\n    steps:\n      - if: " + cond + "\n        uses: " + good + "\n"
			if err := check(strings.NewReader(text), "all", sha, tag); err != nil {
				t.Fatalf("pin under if: %s rejected: %v", cond, err)
			}
		})
	}
	needs := []struct {
		name, mode, text string
		ok               bool
	}{
		{"needs-disabled", "all", "jobs:\n  a:\n    if: false\n    steps:\n      - run: true\n  b:\n    needs: a\n    steps:\n      - uses: " + good + "\n", false},
		{"needs-list-disabled-candidate", "candidate", "jobs:\n  a:\n    if: false\n    steps:\n      - run: true\n  b:\n    needs: [a]\n    steps:\n      - name: x\n        # bpfcompat-pin: candidate\n        uses: " + good + "\n  c:\n    steps:\n      - uses: Kernel-Guard/bpfcompat@main\n", false},
		{"needs-chain", "all", "jobs:\n  c:\n    needs: b\n    uses: " + good + "\n  b:\n    needs: [a]\n    steps:\n      - run: true\n  a:\n    if: ${{ -0 }}\n    steps:\n      - run: true\n", false},
		{"needs-always", "all", "jobs:\n  a:\n    if: false\n    steps:\n      - run: true\n  b:\n    needs: a\n    if: ${{ always() }}\n    steps:\n      - uses: " + good + "\n", true},
		{"needs-running", "all", "jobs:\n  plan:\n    steps:\n      - run: true\n  b:\n    needs: plan\n    if: needs.plan.outputs.should_run == 'true'\n    steps:\n      - uses: " + good + "\n", true},
		{"needs-mapping", "all", "jobs:\n  a:\n    steps:\n      - run: true\n  b:\n    needs: {a: x}\n    steps:\n      - uses: " + good + "\n", false},
		{"needs-quoted-always", "all", "jobs:\n  a:\n    if: false\n    steps:\n      - run: true\n  b:\n    needs: a\n    if: github.ref != 'always()'\n    steps:\n      - uses: " + good + "\n", false},
		{"needs-failure", "all", "jobs:\n  a:\n    if: false\n    steps:\n      - run: true\n  b:\n    needs: a\n    if: success() || failure()\n    steps:\n      - uses: " + good + "\n", false},
		{"needs-not-cancelled", "all", "jobs:\n  a:\n    if: false\n    steps:\n      - run: true\n  b:\n    needs: a\n    if: ${{ !cancelled() }}\n    steps:\n      - uses: " + good + "\n", true},
		{"needs-case", "all", "jobs:\n  plan:\n    if: false\n    steps:\n      - run: true\n  b:\n    needs: PLAN\n    steps:\n      - uses: " + good + "\n", false},
		{"job-ids-differ-by-case", "all", "jobs:\n  plan:\n    steps:\n      - run: true\n  Plan:\n    steps:\n      - uses: " + good + "\n", false},
		{"needs-unknown", "all", "jobs:\n  b:\n    needs: nope\n    steps:\n      - uses: " + good + "\n", false},
		{"needs-self", "all", "jobs:\n  b:\n    needs: b\n    steps:\n      - uses: " + good + "\n", false},
		{"needs-cycle", "all", "jobs:\n  a:\n    needs: b\n    steps:\n      - run: true\n  b:\n    needs: a\n    steps:\n      - uses: " + good + "\n", false},
	}
	for _, tt := range needs {
		t.Run(tt.name, func(t *testing.T) {
			err := check(strings.NewReader(tt.text), tt.mode, sha, tag)
			if (err == nil) != tt.ok {
				t.Fatalf("check() = %v, want accepted=%v", err, tt.ok)
			}
		})
	}
}

// Case variants are rejected only where GitHub reads its own keywords; user
// data such as env names, inputs and matrix keys may use any spelling.
func TestKeywordPositions(t *testing.T) {
	sha := strings.Repeat("a", 40)
	tag := "v0.4.0-rc.5"
	good := "Kernel-Guard/bpfcompat@" + sha + " # " + tag
	tests := []struct {
		name, text string
		ok         bool
	}{
		{"env-name", "env:\n  ENV: prod\njobs:\n  test:\n    steps:\n      - uses: " + good + "\n", true},
		{"input-name", "jobs:\n  test:\n    steps:\n      - uses: " + good + "\n        with:\n          Steps: x\n", true},
		{"matrix-key", "jobs:\n  test:\n    strategy:\n      matrix:\n        Jobs: [1]\n    steps:\n      - uses: " + good + "\n", true},
		{"job-needs-variant", "jobs:\n  a:\n    if: false\n    steps:\n      - run: true\n  test:\n    Needs: a\n    steps:\n      - uses: " + good + "\n", false},
		{"step-if-variant", "jobs:\n  test:\n    steps:\n      - If: false\n        uses: " + good + "\n", false},
		{"root-jobs-variant", "Jobs:\n  x:\n    steps:\n      - uses: Kernel-Guard/bpfcompat@main\njobs:\n  test:\n    steps:\n      - uses: " + good + "\n", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := check(strings.NewReader(tt.text), "all", sha, tag)
			if (err == nil) != tt.ok {
				t.Fatalf("check() = %v, want accepted=%v", err, tt.ok)
			}
		})
	}
}

// The env check names what it found, so the report can show the stale value.
func TestEnvBindingDetail(t *testing.T) {
	text := "env:\n  CANDIDATE_TAG: v0.4.0-rc.4\njobs:\n  x:\n    steps:\n      - run: true\n"
	err := check(strings.NewReader(text), "env", "CANDIDATE_TAG", "v0.4.0-rc.5")
	if err == nil || !strings.Contains(err.Error(), "v0.4.0-rc.4") {
		t.Fatalf("check() = %v, want an error naming the found value", err)
	}
}

func TestWorkflowEnvBindings(t *testing.T) {
	head := "env:\n  CANDIDATE_TAG: v0.4.0-rc.5\n  CANDIDATE_PUBLISHED_AT: \"2026-11-02T10:00:00Z\"\n"
	tests := []struct {
		name, text, key, want string
		ok                    bool
	}{
		{"top-level", head + "jobs:\n  x:\n    steps:\n      - run: true\n", "CANDIDATE_TAG", "v0.4.0-rc.5", true},
		{"quoted", head + "jobs:\n  x:\n    steps:\n      - run: true\n", "CANDIDATE_PUBLISHED_AT", "2026-11-02T10:00:00Z", true},
		{"stale", head + "jobs:\n  x:\n    steps:\n      - run: true\n", "CANDIDATE_TAG", "v0.4.0-rc.6", false},
		{"run-text-before-stale-env", "jobs:\n  x:\n    steps:\n      - run: |\n          CANDIDATE_TAG: v0.4.0-rc.6\nenv:\n  CANDIDATE_TAG: v0.4.0-rc.5\n", "CANDIDATE_TAG", "v0.4.0-rc.6", false},
		{"absent", "jobs:\n  x:\n    steps:\n      - run: true\n", "CANDIDATE_TAG", "v0.4.0-rc.5", false},
		{"job-shadow", head + "jobs:\n  x:\n    env:\n      CANDIDATE_TAG: v0.4.0-rc.4\n    steps:\n      - run: true\n", "CANDIDATE_TAG", "v0.4.0-rc.5", false},
		{"step-shadow", head + "jobs:\n  x:\n    steps:\n      - run: true\n        env:\n          CANDIDATE_TAG: v0.4.0-rc.4\n", "CANDIDATE_TAG", "v0.4.0-rc.5", false},
		{"step-env-variant", head + "jobs:\n  x:\n    steps:\n      - run: true\n        Env:\n          CANDIDATE_TAG: v0.4.0-rc.4\n", "CANDIDATE_TAG", "v0.4.0-rc.5", false},
		{"duplicate", head + "  CANDIDATE_TAG: v0.4.0-rc.4\njobs:\n  x:\n    steps:\n      - run: true\n", "CANDIDATE_TAG", "v0.4.0-rc.5", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := check(strings.NewReader(tt.text), "env", tt.key, tt.want)
			if (err == nil) != tt.ok {
				t.Fatalf("check() = %v, want accepted=%v", err, tt.ok)
			}
		})
	}
}

// The timed canaries count only from a schedule run whose plan job starts
// 20-30 or 68-78 whole hours after publication, so the designated crons must
// fire inside [T0+20h, T0+31h) and [T0+68h, T0+79h). T0 below is synthetic.
func TestScheduleWindows(t *testing.T) {
	t0 := "2026-11-02T10:00:00Z" // a Monday
	wf := func(crons ...string) string {
		s := "on:\n  workflow_dispatch:\n  schedule:\n"
		for _, c := range crons {
			s += "    - cron: \"" + c + "\"\n"
		}
		return s + "jobs:\n  plan:\n    steps:\n      - run: true\n"
	}
	tests := []struct {
		name, text string
		ok         bool
	}{
		{"precedent-offsets", wf("14 10 3 11 *", "14 10 5 11 *"), true},
		{"window-starts", wf("0 6 3 11 *", "0 6 5 11 *"), true},
		{"last-minutes", wf("59 16 3 11 *", "59 16 5 11 *"), true},
		{"first-window-end-excluded", wf("0 17 3 11 *", "14 10 5 11 *"), false},
		{"second-window-end-excluded", wf("14 10 3 11 *", "0 17 5 11 *"), false},
		{"before-first-window", wf("59 5 3 11 *", "14 10 5 11 *"), false},
		{"previous-candidate-crons", wf("44 17 15 10 *", "44 17 17 10 *"), false},
		{"only-first", wf("14 10 3 11 *"), false},
		{"every-five-minutes", wf("*/5 * * * *"), true},
		{"names-and-ranges", wf("14 10 * NOV TUE", "14 10 * nov thu"), true},
		{"dom-or-dow", wf("14 10 1 11 TUE", "14 10 1 11 THU"), true},
		{"dow-seven-refused", wf("14 10 3 11 *", "14 10 5 11 7"), false},
		{"start-step-form", wf("14 10 3/2 11 *"), true},
		{"star-step-day-is-unrestricted", wf("14 10 */2 11 SUN"), false},
		{"month-name-in-dow", wf("14 10 * 11 NOV"), false},
		{"dow-name-in-month", wf("14 10 3 MON *", "14 10 5 11 *"), false},
		{"plus-sign", wf("14 10 +3 11 *", "14 10 5 11 *"), false},
		{"huge-step", wf("14 10 1-5/9223372036854775807 11 *", "14 10 5 11 *"), false},
		{"timezone-key", "on:\n  schedule:\n    - cron: \"14 10 3 11 *\"\n      timezone: \"Asia/Tokyo\"\n    - cron: \"14 10 5 11 *\"\njobs:\n  plan:\n    steps:\n      - run: true\n", false},
		{"list-and-step", wf("0,30 8-12/2 3,5 11 *"), true},
		{"invalid-field", wf("14 10 3 11 *", "61 10 5 11 *"), false},
		{"too-few-fields", wf("14 10 3 11"), false},
		{"no-schedule", "on:\n  workflow_dispatch:\njobs:\n  plan:\n    steps:\n      - run: true\n", false},
		{"cron-not-string", "on:\n  schedule:\n    - cron: [1]\njobs:\n  plan:\n    steps:\n      - run: true\n", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := check(strings.NewReader(tt.text), "schedule", t0, "-")
			if (err == nil) != tt.ok {
				t.Fatalf("check() = %v, want accepted=%v", err, tt.ok)
			}
		})
	}
	if err := check(strings.NewReader(wf("14 10 3 11 *", "14 10 5 11 *")), "schedule", "not-a-time", "-"); err == nil {
		t.Fatal("an unparsable publication time was accepted")
	}
}

func TestRunExitCodes(t *testing.T) {
	sha := strings.Repeat("a", 40)
	tag := "v0.4.0-rc.5"
	dir := t.TempDir()
	good := dir + "/good.yml"
	stale := dir + "/stale.yml"
	if err := os.WriteFile(good, []byte("jobs:\n  t:\n    steps:\n      - uses: Kernel-Guard/bpfcompat@"+sha+" # "+tag+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(stale, []byte("jobs:\n  t:\n    steps:\n      - uses: Kernel-Guard/bpfcompat@main\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		args []string
		code int
		out  string
	}{
		{"verified", []string{"all", sha, tag, good}, 0, "VERIFIED\n"},
		{"pending", []string{"all", sha, tag, stale}, 0, "PENDING\n"},
		{"usage", []string{"all", sha, tag}, 2, ""},
		{"unknown-mode", []string{"some", sha, tag, good}, 2, ""},
		{"env-mode", []string{"env", "CANDIDATE_TAG", tag, good}, 0, "PENDING\n"},
		{"schedule-mode", []string{"schedule", "2026-11-02T10:00:00Z", "-", good}, 0, "PENDING\n"},
		{"unreadable", []string{"all", sha, tag, dir + "/missing.yml"}, 2, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if code := run(tt.args, &stdout, &stderr); code != tt.code || stdout.String() != tt.out {
				t.Fatalf("run() = %d, %q; want %d, %q (stderr %q)", code, stdout.String(), tt.code, tt.out, stderr.String())
			}
		})
	}
}
