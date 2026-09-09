package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/kernel-guard/bpfcompat/internal/regressiondiff"
)

// runDiff compares two evidence reports and answers one question: did this
// candidate break an environment the baseline supported?
//
// It is deliberately a new subcommand rather than a change to `compare`.
// `compare` predates the Gate 1 verdict contract, ranks statuses ordinally, and
// is consumed by the frozen experimental API; changing its meaning would break
// an existing surface to improve a different one.
func runDiff(args []string) int {
	fs := flag.NewFlagSet("diff", flag.ContinueOnError)
	baseline := fs.String("baseline", "", "Path to the baseline (reference release) compatibility report JSON")
	candidate := fs.String("candidate", "", "Path to the candidate (release under evaluation) compatibility report JSON")
	outPath := fs.String("out", "", "Path to write the diff JSON (optional; printed to stdout when neither --out nor --markdown is set)")
	markdownPath := fs.String("markdown", "", "Path to write the diff Markdown (optional)")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage:\n  bpfcompat diff --baseline <report.json> --candidate <report.json> [flags]\n\n")
		fmt.Fprintf(fs.Output(), "Compares two bpfcompat evidence reports and reports only NEW compatibility\n")
		fmt.Fprintf(fs.Output(), "regressions, separately from known limitations, fixes and coverage changes.\n")
		fmt.Fprintf(fs.Output(), "Offline and stateless: it reads the two files and nothing else.\n\n")
		fmt.Fprintf(fs.Output(), "Exit codes:\n")
		fmt.Fprintf(fs.Output(), "  0  no new required regression; every required comparison was established\n")
		fmt.Fprintf(fs.Output(), "  1  the required comparison could not be established (not a claim about the candidate)\n")
		fmt.Fprintf(fs.Output(), "  2  a required environment the baseline supported is broken in the candidate\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		// --help is a successful request for help, not a failed comparison.
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return regressiondiff.ExitInconclusive
	}

	if strings.TrimSpace(*baseline) == "" || strings.TrimSpace(*candidate) == "" {
		fmt.Fprintln(os.Stderr, "diff requires --baseline and --candidate")
		fs.Usage()
		return regressiondiff.ExitInconclusive
	}

	d, err := regressiondiff.Compare(*baseline, *candidate, time.Now())
	if err != nil {
		// Unreadable, unparseable or unknown-schema evidence is an inability to
		// compare, never a verdict on the candidate.
		fmt.Fprintf(os.Stderr, "diff failed: %v\n", err)
		return regressiondiff.ExitInconclusive
	}

	if err := regressiondiff.WriteJSON(*outPath, d); err != nil {
		fmt.Fprintf(os.Stderr, "write diff JSON: %v\n", err)
		return regressiondiff.ExitInconclusive
	}
	if strings.TrimSpace(*outPath) != "" {
		fmt.Printf("Diff JSON: %s\n", *outPath)
	}
	if err := regressiondiff.WriteMarkdown(*markdownPath, d); err != nil {
		fmt.Fprintf(os.Stderr, "write diff Markdown: %v\n", err)
		return regressiondiff.ExitInconclusive
	}
	if strings.TrimSpace(*markdownPath) != "" {
		fmt.Printf("Diff Markdown: %s\n", *markdownPath)
	}
	// With no output file selected the diff itself is written to stdout, and
	// stdout has to stay machine-readable: the flag help promises JSON there,
	// and `bpfcompat diff ... | jq` must work. The human summary then goes to
	// stderr rather than being appended after the JSON document.
	jsonOnStdout := strings.TrimSpace(*outPath) == "" && strings.TrimSpace(*markdownPath) == ""
	if jsonOnStdout {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(d); err != nil {
			fmt.Fprintf(os.Stderr, "encode diff JSON: %v\n", err)
			return regressiondiff.ExitInconclusive
		}
	}

	summaryOut := os.Stdout
	if jsonOnStdout {
		summaryOut = os.Stderr
	}
	s := d.Summary
	fmt.Fprintf(summaryOut, "Result: %s\n", s.Result)
	fmt.Fprintf(summaryOut, "New required regressions: %d | new optional: %d | existing incompatibilities: %d | fixed: %d | unchanged: %d\n",
		s.NewRequiredRegressions, s.NewOptionalRegressions, s.ExistingIncompatibility, s.Fixed, s.UnchangedCompatible)
	fmt.Fprintf(summaryOut, "Inconclusive required: %d | optional: %d | coverage added: %d | removed required: %d | removed optional: %d\n",
		s.InconclusiveRequired, s.InconclusiveOptional, s.CoverageAddedCount, s.CoverageRemovedRequired, s.CoverageRemovedOptional)

	return regressiondiff.ExitCode(d)
}
