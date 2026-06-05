package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/erenari/bpfcompat/internal/runner"
	"github.com/erenari/bpfcompat/internal/suite"
)

func runSuite(args []string) int {
	filteredArgs, unsafeAllowHostRunner, err := stripHiddenUnsafeHostRunnerFlag(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid hidden arguments: %v\n", err)
		return runner.ExitToolError
	}

	fs := flag.NewFlagSet("suite", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	suitePath := fs.String("suite", "", "Path to suite YAML")
	outPath := fs.String("out", "", "Path to suite JSON summary output")
	markdownPath := fs.String("markdown", "", "Path to suite Markdown summary output")
	workDir := fs.String("workdir", "", "Override suite/default workdir")
	timeoutText := fs.String("timeout", "", "Override per-target timeout duration")
	concurrency := fs.Int("concurrency", 0, "Override maximum concurrent VM jobs per case")
	stopOnFailure := fs.Bool("stop-on-failure", false, "Stop after the first case that does not pass")
	asJSON := fs.Bool("json", false, "Print suite summary JSON to stdout")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage:\n  bpfcompat suite --suite <file> --out <file> [flags]\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(filteredArgs); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return runner.ExitToolError
	}
	if fs.NArg() != 0 {
		fmt.Fprintf(os.Stderr, "unexpected positional arguments: %v\n", fs.Args())
		return runner.ExitToolError
	}
	if *suitePath == "" {
		fmt.Fprintln(os.Stderr, "--suite is required")
		return runner.ExitToolError
	}

	var timeout time.Duration
	if *timeoutText != "" {
		parsed, err := time.ParseDuration(*timeoutText)
		if err != nil {
			fmt.Fprintf(os.Stderr, "invalid --timeout value %q: %v\n", *timeoutText, err)
			return runner.ExitToolError
		}
		timeout = parsed
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	summary, err := suite.Execute(ctx, suite.RunOptions{
		SuitePath:             *suitePath,
		OutPath:               *outPath,
		MarkdownPath:          *markdownPath,
		WorkDir:               *workDir,
		Timeout:               timeout,
		Concurrency:           *concurrency,
		StopOnFailure:         *stopOnFailure,
		UnsafeAllowHostRunner: unsafeAllowHostRunner,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "bpfcompat suite failed: %v\n", err)
		return runner.ExitToolError
	}

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(summary); err != nil {
			fmt.Fprintf(os.Stderr, "encode suite summary JSON: %v\n", err)
			return runner.ExitToolError
		}
	} else {
		printSuiteSummary(summary)
	}
	return summary.ExitCode
}

func printSuiteSummary(summary suite.Summary) {
	fmt.Printf("Suite: %s\n", summary.Name)
	fmt.Printf("Status: %s\n", summary.Status)
	fmt.Printf("Exit Code: %d\n", summary.ExitCode)
	for _, c := range summary.Cases {
		line := fmt.Sprintf("  - %s: %s", c.Name, c.Status)
		if c.RunID != "" {
			line += fmt.Sprintf(" run=%s", c.RunID)
		}
		if c.Error != "" {
			line += fmt.Sprintf(" error=%s", c.Error)
		}
		fmt.Println(line)
	}
}
