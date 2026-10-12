package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/kernel-guard/bpfcompat/internal/conformance"
	"github.com/kernel-guard/bpfcompat/internal/runner"
)

func runConformance(args []string) int {
	if len(args) == 0 {
		printConformanceUsage()
		return runner.ExitToolError
	}
	switch args[0] {
	case "evaluate":
		return runConformanceEvaluate(args[1:])
	case "-h", "--help", "help":
		printConformanceUsage()
		return runner.ExitSuccess
	default:
		fmt.Fprintf(os.Stderr, "unknown conformance subcommand: %s\n\n", args[0])
		printConformanceUsage()
		return runner.ExitToolError
	}
}

func runConformanceEvaluate(args []string) int {
	fs := flag.NewFlagSet("conformance evaluate", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	profilePath := fs.String("profile", "", "Path to a versioned conformance profile YAML")
	reportPath := fs.String("report", "", "Path to the bpfcompat JSON report to evaluate")
	outDir := fs.String("out-dir", "", "Directory for decision and in-toto statement outputs")
	verifierID := fs.String("verifier-id", "", "Absolute HTTPS URI identifying the verifier")
	reportURL := fs.String("report-url", "", "Optional absolute HTTPS URL for the originating test run")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage:\n  bpfcompat conformance evaluate --profile <file> --report <file> --out-dir <dir> --verifier-id <uri> [--report-url <url>]\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return runner.ExitSuccess
		}
		return runner.ExitToolError
	}
	if fs.NArg() != 0 {
		fmt.Fprintf(os.Stderr, "unexpected positional arguments: %v\n", fs.Args())
		return runner.ExitToolError
	}
	for name, value := range map[string]string{
		"--profile":     *profilePath,
		"--report":      *reportPath,
		"--out-dir":     *outDir,
		"--verifier-id": *verifierID,
	} {
		if strings.TrimSpace(value) == "" {
			fmt.Fprintf(os.Stderr, "%s is required\n", name)
			return runner.ExitToolError
		}
	}

	profile, err := conformance.LoadProfile(*profilePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load conformance profile: %v\n", err)
		return runner.ExitToolError
	}
	report, err := conformance.LoadReport(*reportPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load conformance report: %v\n", err)
		return runner.ExitToolError
	}
	evaluation, err := conformance.Evaluate(profile, report, conformance.EvaluateOptions{
		VerifierID: strings.TrimSpace(*verifierID),
		ReportURL:  strings.TrimSpace(*reportURL),
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "evaluate conformance report: %v\n", err)
		return runner.ExitToolError
	}
	paths, err := conformance.WriteEvaluation(*outDir, evaluation)
	if err != nil {
		fmt.Fprintf(os.Stderr, "write conformance evidence: %v\n", err)
		return runner.ExitToolError
	}

	fmt.Printf("Conformance: %s\n", evaluation.Decision.Status)
	fmt.Printf("Profile: %s sha256:%s\n", evaluation.Decision.Profile.ID, evaluation.Decision.Profile.SHA256)
	fmt.Printf("Subject: %s sha256:%s\n", evaluation.Decision.Subject.Name, evaluation.Decision.Subject.Digest["sha256"])
	fmt.Printf("Decision: %s\n", paths.Decision)
	fmt.Printf("Test Result: %s\n", paths.TestResult)
	if paths.VerificationResult != "" {
		fmt.Printf("Verification Result: %s\n", paths.VerificationResult)
	} else {
		fmt.Println("Verification Result: not issued")
	}

	switch evaluation.Decision.Status {
	case conformance.StatusConformant:
		return runner.ExitSuccess
	case conformance.StatusNonconformant:
		return runner.ExitCompatibilityFailure
	default:
		return runner.ExitToolError
	}
}

func printConformanceUsage() {
	fmt.Println("Usage:")
	fmt.Println("  bpfcompat conformance evaluate --profile <file> --report <file> --out-dir <dir> --verifier-id <uri> [--report-url <url>]")
}
