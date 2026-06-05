package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"

	reportpkg "github.com/erenari/bpfcompat/internal/report"
	"github.com/erenari/bpfcompat/internal/runner"
	"github.com/erenari/bpfcompat/pkg/schema"
)

func runReportSummary(args []string) int {
	fs := flag.NewFlagSet("report-summary", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	reportPath := fs.String("report", "", "Path to bpfcompat JSON report")
	maxTargets := fs.Int("max-targets", 25, "Maximum compatibility matrix rows to include")
	maxFailures := fs.Int("max-failures", 10, "Maximum failure detail rows to include")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage:\n  bpfcompat report-summary --report <file> [--max-targets N] [--max-failures N]\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return runner.ExitToolError
	}
	if fs.NArg() != 0 {
		fmt.Fprintf(os.Stderr, "unexpected positional arguments: %v\n", fs.Args())
		return runner.ExitToolError
	}
	if *reportPath == "" {
		fmt.Fprintln(os.Stderr, "--report is required")
		return runner.ExitToolError
	}

	file, err := os.Open(*reportPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "open report: %v\n", err)
		return runner.ExitToolError
	}
	defer file.Close()

	var compatReport schema.ReportV01
	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&compatReport); err != nil {
		fmt.Fprintf(os.Stderr, "decode report: %v\n", err)
		return runner.ExitToolError
	}

	fmt.Print(reportpkg.BuildGitHubActionSummary(compatReport, reportpkg.ActionSummaryOptions{
		MaxTargets:  *maxTargets,
		MaxFailures: *maxFailures,
	}))
	return 0
}
