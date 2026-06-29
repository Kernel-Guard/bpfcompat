package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/kernel-guard/bpfcompat/internal/api"
	"github.com/kernel-guard/bpfcompat/internal/compare"
	"github.com/kernel-guard/bpfcompat/internal/envref"
	"github.com/kernel-guard/bpfcompat/internal/registry"
	"github.com/kernel-guard/bpfcompat/internal/runner"
	"github.com/kernel-guard/bpfcompat/internal/runtime"
	"github.com/kernel-guard/bpfcompat/internal/version"
)

func main() {
	exitCode := run(os.Args[1:])
	os.Exit(exitCode)
}

func run(args []string) int {
	if len(args) == 0 {
		printRootUsage()
		return runner.ExitToolError
	}

	switch args[0] {
	case "test":
		return runTest(args[1:])
	case "suite":
		return runSuite(args[1:])
	case "profile":
		return runProfile(args[1:])
	case "history":
		return runHistory(args[1:])
	case "compare":
		return runCompare(args[1:])
	case "serve":
		return runServe(args[1:])
	case "runtime":
		return runRuntime(args[1:])
	case "agent":
		return runAgent(args[1:])
	case "admin":
		return runAdmin(args[1:])
	case "report-summary":
		return runReportSummary(args[1:])
	case "kernel-freshness":
		return runKernelFreshness(args[1:])
	case "kernel-sweep":
		return runKernelSweep(args[1:])
	case "version", "--version":
		return runVersion(args[1:])
	case "env":
		return runEnv(args[1:])
	case "-h", "--help", "help":
		printRootUsage()
		return 0
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", args[0])
		printRootUsage()
		return runner.ExitToolError
	}
}

// runVersion prints the build identity. With --json it emits the structured
// payload so deployment tooling can match against a known release; the
// default human-readable line is what an operator gets on the shell.
func runVersion(args []string) int {
	fs := flag.NewFlagSet("version", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	asJSON := fs.Bool("json", false, "Print version info as JSON")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage:\n  bpfcompat version [--json]\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return runner.ExitToolError
	}
	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(version.Resolve()); err != nil {
			fmt.Fprintf(os.Stderr, "encode version json: %v\n", err)
			return runner.ExitToolError
		}
		return 0
	}
	fmt.Println(version.String())
	return 0
}

// runEnv prints the env-var catalog. Operators use this to figure out which
// knobs exist without grepping the source. --markdown emits the same
// content as docs/env-reference.md so CI can regenerate the doc and fail
// on drift.
func runEnv(args []string) int {
	fs := flag.NewFlagSet("env", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	asMarkdown := fs.Bool("markdown", false, "Render as Markdown (drop into docs/env-reference.md)")
	asJSON := fs.Bool("json", false, "Render as JSON")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage:\n  bpfcompat env [--markdown|--json]\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return runner.ExitToolError
	}
	switch {
	case *asJSON:
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(envref.All()); err != nil {
			fmt.Fprintf(os.Stderr, "encode env catalog: %v\n", err)
			return runner.ExitToolError
		}
	case *asMarkdown:
		fmt.Print(envref.Markdown())
	default:
		currentCat := ""
		for _, v := range envref.All() {
			if v.Category != currentCat {
				if currentCat != "" {
					fmt.Println()
				}
				fmt.Printf("# %s\n", v.Category)
				currentCat = v.Category
			}
			def := v.Default
			if def == "" {
				def = "(unset)"
			}
			fmt.Printf("  %s\n    default: %s\n    %s\n", v.Name, def, v.Description)
		}
	}
	return 0
}

func runTest(args []string) int {
	filteredArgs, unsafeAllowHostRunner, err := stripHiddenUnsafeHostRunnerFlag(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid hidden arguments: %v\n", err)
		return runner.ExitToolError
	}

	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	var cfg runner.Config
	fs.StringVar(&cfg.ArtifactPath, "artifact", "", "Compiled .bpf.o artifact: a local ELF file, an OCI gadget (registry ref e.g. ghcr.io/org/gadget:tag), or an OCI image archive/layout")
	fs.StringVar(&cfg.Command, "command", "", "Command-mode validation: shell command run inside each kernel VM (verdict = exit code). Exposes $BPFCOMPAT_BIN/$BPFCOMPAT_ARTIFACT. Use instead of --artifact to validate via a real loader binary/command.")
	fs.StringVar(&cfg.CommandBinary, "command-binary", "", "Command mode: local executable shipped into each guest and exposed to --command as $BPFCOMPAT_BIN")
	fs.IntVar(&cfg.CommandExpectExit, "command-expect-exit", 0, "Command mode: exit code that counts as a pass (default 0)")
	fs.StringVar(&cfg.ArtifactURI, "artifact-uri", "", "Optional remote URI for artifact retrieval metadata (http|https|file)")
	fs.StringVar(&cfg.ArtifactName, "artifact-name", "", "Logical artifact family name for version history (optional)")
	fs.StringVar(&cfg.ArtifactVersion, "artifact-version", "", "Artifact version label for version history (optional)")
	fs.StringVar(&cfg.ArtifactVariant, "artifact-variant", "", "Artifact variant label (optional)")
	fs.StringVar(&cfg.ValidationMode, "validation-mode", "", "Validation mode: load_only, load_attach, or behavior (default preserves manifest behavior)")
	fs.StringVar(&cfg.MatrixPath, "matrix", "", "Path to matrix YAML")
	fs.BoolVar(&cfg.Quick, "quick", false, "Use the built-in quick-check kernel set instead of --matrix (fast local 'does it load?' check)")
	fs.StringVar(&cfg.ManifestPath, "manifest", "", "Path to artifact manifest YAML (optional)")
	fs.StringVar(&cfg.OutPath, "out", "", "Path to JSON report output")
	fs.StringVar(&cfg.MarkdownPath, "markdown", "", "Path to Markdown report output (optional)")
	fs.StringVar(&cfg.WorkDir, "workdir", ".bpfcompat", "Working directory root")
	fs.StringVar(&cfg.Runner, "runner", runner.RunnerVM, "Execution runner backend (vm|virtme-ng|firecracker|host)")
	fs.IntVar(&cfg.Concurrency, "concurrency", 2, "Maximum concurrent VM jobs")

	timeoutText := fs.String("timeout", "180s", "Per-target timeout duration")
	keepVMOnFailure := fs.Bool("keep-vm-on-failure", false, "Keep VM overlays/logs on failure")

	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage:\n  bpfcompat test --artifact <file> --matrix <file> --out <file> [flags]\n  bpfcompat test --command <cmd> --matrix <file> --out <file> [--command-binary <file>] [flags]\n\n")
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

	timeout, err := time.ParseDuration(*timeoutText)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid --timeout value %q: %v\n", *timeoutText, err)
		return runner.ExitToolError
	}
	cfg.Timeout = timeout
	cfg.KeepVMOnFailure = *keepVMOnFailure
	cfg.UnsafeAllowHostRunner = unsafeAllowHostRunner

	if err := cfg.Validate(); err != nil {
		fmt.Fprintf(os.Stderr, "invalid arguments: %v\n", err)
		return runner.ExitToolError
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	result, err := runner.ExecuteBootstrap(ctx, cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "bpfcompat test failed: %v\n", err)
		return runner.ExitToolError
	}

	printSummary(result)
	return result.ExitCode
}

func stripHiddenUnsafeHostRunnerFlag(args []string) ([]string, bool, error) {
	const (
		plainA  = "-unsafe-allow-host-runner"
		plainB  = "--unsafe-allow-host-runner"
		prefixA = "-unsafe-allow-host-runner="
		prefixB = "--unsafe-allow-host-runner="
	)

	filtered := make([]string, 0, len(args))
	allow := false

	for _, arg := range args {
		switch {
		case arg == plainA || arg == plainB:
			allow = true
		case strings.HasPrefix(arg, prefixA):
			raw := strings.TrimPrefix(arg, prefixA)
			value, err := strconv.ParseBool(raw)
			if err != nil {
				return nil, false, fmt.Errorf("%s expects bool value: %w", plainB, err)
			}
			allow = value
		case strings.HasPrefix(arg, prefixB):
			raw := strings.TrimPrefix(arg, prefixB)
			value, err := strconv.ParseBool(raw)
			if err != nil {
				return nil, false, fmt.Errorf("%s expects bool value: %w", plainB, err)
			}
			allow = value
		default:
			filtered = append(filtered, arg)
		}
	}

	return filtered, allow, nil
}

func runProfile(args []string) int {
	if len(args) == 0 {
		printProfileUsage()
		return runner.ExitToolError
	}
	if args[0] != "list" {
		fmt.Fprintf(os.Stderr, "unknown profile subcommand: %s\n\n", args[0])
		printProfileUsage()
		return runner.ExitToolError
	}

	fs := flag.NewFlagSet("profile list", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	matrixPath := fs.String("matrix", "", "Path to matrix YAML")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage:\n  bpfcompat profile list --matrix <file>\n\n")
		fs.PrintDefaults()
	}

	if err := fs.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return runner.ExitToolError
	}
	if *matrixPath == "" {
		fmt.Fprintln(os.Stderr, "--matrix is required")
		return runner.ExitToolError
	}

	ids, err := runner.ListProfiles(filepath.Clean(*matrixPath))
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to list profiles: %v\n", err)
		return runner.ExitToolError
	}
	for _, id := range ids {
		fmt.Println(id)
	}
	return 0
}

func runHistory(args []string) int {
	if len(args) == 0 {
		printHistoryUsage()
		return runner.ExitToolError
	}
	switch args[0] {
	case "list":
		return runHistoryList(args[1:])
	case "verify":
		return runHistoryVerify(args[1:])
	case "sign":
		return runHistorySign(args[1:])
	default:
		printHistoryUsage()
		return runner.ExitToolError
	}
}

func runHistoryList(args []string) int {
	fs := flag.NewFlagSet("history list", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	workDir := fs.String("workdir", ".bpfcompat", "Working directory root")
	artifactName := fs.String("artifact-name", "", "Filter by artifact family name")
	limit := fs.Int("limit", 50, "Maximum number of records")
	asJSON := fs.Bool("json", false, "Print JSON output")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage:\n  bpfcompat history list [flags]\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return runner.ExitToolError
	}

	records, err := registry.ListArtifactVersions(*workDir, strings.TrimSpace(*artifactName), *limit)
	if err != nil {
		fmt.Fprintf(os.Stderr, "history list failed: %v\n", err)
		return runner.ExitToolError
	}

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(records); err != nil {
			fmt.Fprintf(os.Stderr, "encode history JSON: %v\n", err)
			return runner.ExitToolError
		}
		return 0
	}

	if len(records) == 0 {
		fmt.Println("No artifact version records found.")
		return 0
	}
	fmt.Println("Artifact Version History:")
	for _, rec := range records {
		fmt.Printf("- %s@%s status=%s required=%d/%d run=%s\n",
			rec.ArtifactName,
			rec.ArtifactVersion,
			rec.SummaryStatus,
			rec.RequiredPassed,
			rec.RequiredFailed,
			rec.RunID,
		)
	}
	return 0
}

func runHistoryVerify(args []string) int {
	fs := flag.NewFlagSet("history verify", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	workDir := fs.String("workdir", ".bpfcompat", "Working directory root")
	asJSON := fs.Bool("json", false, "Print JSON output")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage:\n  bpfcompat history verify [flags]\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return runner.ExitToolError
	}

	verification, err := registry.VerifyArtifactVersionHistory(*workDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "history verify failed: %v\n", err)
		return runner.ExitToolError
	}
	failed := 0
	for _, row := range verification {
		if !row.Verified {
			failed++
		}
	}

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(verification); err != nil {
			fmt.Fprintf(os.Stderr, "encode history verification JSON: %v\n", err)
			return runner.ExitToolError
		}
		if failed > 0 {
			fmt.Fprintf(os.Stderr, "history verify: %d/%d records failed verification\n", failed, len(verification))
			return runner.ExitToolError
		}
		return runner.ExitSuccess
	} else {
		if len(verification) == 0 {
			fmt.Println("No artifact history records found.")
			return runner.ExitSuccess
		}
		fmt.Println("Artifact History Verification:")
		for _, row := range verification {
			status := "ok"
			if !row.Verified {
				status = "fail"
			}
			fmt.Printf("- [%s] idx=%d %s@%s run=%s\n", status, row.Index, row.ArtifactName, row.ArtifactVersion, row.RunID)
			for _, issue := range row.Issues {
				fmt.Printf("    issue: %s\n", issue)
			}
		}
	}

	if failed > 0 {
		fmt.Fprintf(os.Stderr, "history verify: %d/%d records failed verification\n", failed, len(verification))
		return runner.ExitToolError
	}
	fmt.Printf("history verify: all %d records passed\n", len(verification))
	return runner.ExitSuccess
}

func runHistorySign(args []string) int {
	fs := flag.NewFlagSet("history sign", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	workDir := fs.String("workdir", ".bpfcompat", "Working directory root")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage:\n  bpfcompat history sign [flags]\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return runner.ExitToolError
	}

	count, err := registry.BackfillArtifactVersionProvenance(*workDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "history sign failed: %v\n", err)
		return runner.ExitToolError
	}
	if count == 0 {
		fmt.Println("No artifact history records found.")
		return runner.ExitSuccess
	}
	fmt.Printf("history sign: updated %d records\n", count)
	return runner.ExitSuccess
}

func runCompare(args []string) int {
	fs := flag.NewFlagSet("compare", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	baseReport := fs.String("base-report", "", "Path to base report JSON")
	headReport := fs.String("head-report", "", "Path to head report JSON")
	workDir := fs.String("workdir", ".bpfcompat", "Working directory root")
	artifactName := fs.String("artifact-name", "", "Artifact family name for version-based compare")
	baseVersion := fs.String("base-version", "", "Base artifact version label for version-based compare")
	headVersion := fs.String("head-version", "", "Head artifact version label for version-based compare")
	outPath := fs.String("out", "", "Path to write compare JSON output (optional)")
	markdownPath := fs.String("markdown", "", "Path to write compare Markdown output (optional)")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage:\n  bpfcompat compare --base-report <file> --head-report <file> [flags]\n")
		fmt.Fprintf(fs.Output(), "  bpfcompat compare --artifact-name <name> --base-version <v1> --head-version <v2> [flags]\n\n")
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return runner.ExitToolError
	}

	basePath := strings.TrimSpace(*baseReport)
	headPath := strings.TrimSpace(*headReport)
	if basePath == "" || headPath == "" {
		if strings.TrimSpace(*artifactName) == "" || strings.TrimSpace(*baseVersion) == "" || strings.TrimSpace(*headVersion) == "" {
			fmt.Fprintln(os.Stderr, "provide base/head report paths or artifact-name + base-version + head-version")
			return runner.ExitToolError
		}

		baseRecord, err := registry.FindArtifactVersion(*workDir, strings.TrimSpace(*artifactName), strings.TrimSpace(*baseVersion))
		if err != nil {
			fmt.Fprintf(os.Stderr, "resolve base artifact version: %v\n", err)
			return runner.ExitToolError
		}
		headRecord, err := registry.FindArtifactVersion(*workDir, strings.TrimSpace(*artifactName), strings.TrimSpace(*headVersion))
		if err != nil {
			fmt.Fprintf(os.Stderr, "resolve head artifact version: %v\n", err)
			return runner.ExitToolError
		}
		basePath = baseRecord.JSONReportPath
		headPath = headRecord.JSONReportPath
	}

	diff, err := compare.LoadAndBuild(basePath, headPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "compare failed: %v\n", err)
		return runner.ExitToolError
	}

	if strings.TrimSpace(*outPath) != "" {
		if err := compare.WriteJSON(*outPath, diff); err != nil {
			fmt.Fprintf(os.Stderr, "write compare JSON: %v\n", err)
			return runner.ExitToolError
		}
		fmt.Printf("Compare JSON: %s\n", *outPath)
	}
	if strings.TrimSpace(*markdownPath) != "" {
		if err := compare.WriteMarkdown(*markdownPath, diff); err != nil {
			fmt.Fprintf(os.Stderr, "write compare Markdown: %v\n", err)
			return runner.ExitToolError
		}
		fmt.Printf("Compare Markdown: %s\n", *markdownPath)
	}
	if strings.TrimSpace(*outPath) == "" && strings.TrimSpace(*markdownPath) == "" {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(diff); err != nil {
			fmt.Fprintf(os.Stderr, "encode compare JSON: %v\n", err)
			return runner.ExitToolError
		}
	}

	fmt.Printf("Diff summary: profiles=%d changed=%d improved=%d regressed=%d required_regressions=%d\n",
		diff.Summary.TotalProfiles,
		diff.Summary.ChangedProfiles,
		diff.Summary.ImprovedProfiles,
		diff.Summary.RegressedProfiles,
		diff.Summary.RequiredRegressions,
	)
	return 0
}

func runServe(args []string) int {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	addr := fs.String("addr", ":8080", "Address to bind web UI/API server")
	workDir := fs.String("workdir", ".bpfcompat", "Working directory root")
	matrixPath := fs.String("matrix", "matrices/mvp.yaml", "Default matrix path when profile subset is not provided")
	concurrency := fs.Int("concurrency", 2, "Default concurrency for API validation jobs")
	timeoutText := fs.String("timeout", "8m", "Default timeout for API validation jobs")
	tlsCert := fs.String("tls-cert", "", "Path to TLS certificate (PEM). When set with --tls-key, the server listens via HTTPS.")
	tlsKey := fs.String("tls-key", "", "Path to TLS private key (PEM). When set with --tls-cert, the server listens via HTTPS.")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage:\n  bpfcompat serve [flags]\n\n")
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return runner.ExitToolError
	}

	timeout, err := time.ParseDuration(*timeoutText)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid --timeout value %q: %v\n", *timeoutText, err)
		return runner.ExitToolError
	}

	certPath := strings.TrimSpace(*tlsCert)
	keyPath := strings.TrimSpace(*tlsKey)
	if (certPath == "") != (keyPath == "") {
		fmt.Fprintln(os.Stderr, "--tls-cert and --tls-key must be provided together")
		return runner.ExitToolError
	}

	if err := api.Serve(context.Background(), api.Config{
		Addr:               *addr,
		WorkDir:            *workDir,
		DefaultMatrixPath:  *matrixPath,
		DefaultConcurrency: *concurrency,
		DefaultTimeout:     timeout,
		TLSCertPath:        certPath,
		TLSKeyPath:         keyPath,
	}); err != nil {
		fmt.Fprintf(os.Stderr, "serve failed: %v\n", err)
		return runner.ExitToolError
	}
	return 0
}

func runRuntime(args []string) int {
	if len(args) == 0 {
		printRuntimeUsage()
		return runner.ExitToolError
	}

	switch args[0] {
	case "probe":
		return runRuntimeProbe(args[1:])
	case "select":
		return runRuntimeSelect(args[1:])
	case "fetch":
		return runRuntimeFetch(args[1:])
	case "execute":
		return runRuntimeExecute(args[1:])
	case "worker-execute":
		return runRuntimeWorkerExecute(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "unknown runtime subcommand: %s\n\n", args[0])
		printRuntimeUsage()
		return runner.ExitToolError
	}
}

func runRuntimeProbe(args []string) int {
	fs := flag.NewFlagSet("runtime probe", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	probeFlags := addRuntimeProbeFlags(fs)
	outPath := fs.String("out", "", "Write probe result to JSON file (optional)")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage:\n  bpfcompat runtime probe [flags]\n\n")
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

	probe, err := runtime.ProbeHostCapabilitiesWithOptions(probeFlags.BuildProbeOptions())
	if err != nil {
		fmt.Fprintf(os.Stderr, "runtime probe failed: %v\n", err)
		return runner.ExitToolError
	}

	payload, err := json.MarshalIndent(probe, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "encode probe JSON: %v\n", err)
		return runner.ExitToolError
	}
	payload = append(payload, '\n')

	if strings.TrimSpace(*outPath) != "" {
		if err := os.WriteFile(filepath.Clean(*outPath), payload, 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "write probe JSON file: %v\n", err)
			return runner.ExitToolError
		}
		fmt.Printf("Probe JSON: %s\n", *outPath)
	}

	_, _ = os.Stdout.Write(payload)
	return 0
}

type runtimePolicyArgs struct {
	requireSummaryPass           *bool
	minRequiredPassed            *int
	maxRequiredFailed            *string
	requireKernelBTF             *bool
	requireAttachSupport         *bool
	requireRingbufSupport        *bool
	requirePerfEventArraySupport *bool
	denyCodes                    *string
	allowCodes                   *string
}

type runtimeProbeArgs struct {
	preferPrivileged   *bool
	useSudo            *bool
	sudoNonInteractive *bool
}

func addRuntimeProbeFlags(fs *flag.FlagSet) runtimeProbeArgs {
	return runtimeProbeArgs{
		preferPrivileged:   fs.Bool("probe-prefer-privileged", false, "Probe: prefer privileged bpftool feature probe with unprivileged fallback"),
		useSudo:            fs.Bool("probe-use-sudo", true, "Probe: use sudo for privileged probe when not root"),
		sudoNonInteractive: fs.Bool("probe-sudo-non-interactive", true, "Probe: use sudo -n (no password prompt)"),
	}
}

func (a runtimeProbeArgs) BuildProbeOptions() runtime.ProbeOptions {
	return runtime.ProbeOptions{
		PreferPrivileged:   derefBool(a.preferPrivileged),
		UseSudo:            derefBool(a.useSudo),
		SudoNonInteractive: derefBool(a.sudoNonInteractive),
	}
}

func addRuntimePolicyFlags(fs *flag.FlagSet) runtimePolicyArgs {
	return runtimePolicyArgs{
		requireSummaryPass:           fs.Bool("policy-require-summary-pass", false, "Policy: require candidate summary status pass"),
		minRequiredPassed:            fs.Int("policy-min-required-passed", 0, "Policy: minimum required profile passes"),
		maxRequiredFailed:            fs.String("policy-max-required-failed", "", "Policy: maximum required profile failures (optional)"),
		requireKernelBTF:             fs.Bool("policy-require-kernel-btf", false, "Policy: require host kernel BTF availability"),
		requireAttachSupport:         fs.Bool("policy-require-attach-support", false, "Policy: reject history with UNSUPPORTED_ATTACH_TYPE"),
		requireRingbufSupport:        fs.Bool("policy-require-ringbuf-support", false, "Policy: reject history with UNSUPPORTED_MAP_TYPE"),
		requirePerfEventArraySupport: fs.Bool("policy-require-perf-event-array-support", false, "Policy: reject history with UNSUPPORTED_MAP_TYPE"),
		denyCodes:                    fs.String("policy-deny-codes", "", "Policy: comma-separated classification deny-list"),
		allowCodes:                   fs.String("policy-allow-codes", "", "Policy: comma-separated classification allow-list"),
	}
}

func (a runtimePolicyArgs) BuildPolicy() (runtime.SelectionPolicy, error) {
	policy := runtime.SelectionPolicy{
		RequireSummaryPass:           derefBool(a.requireSummaryPass),
		MinRequiredPassed:            derefInt(a.minRequiredPassed),
		RequireKernelBTF:             derefBool(a.requireKernelBTF),
		RequireAttachSupport:         derefBool(a.requireAttachSupport),
		RequireRingbufSupport:        derefBool(a.requireRingbufSupport),
		RequirePerfEventArraySupport: derefBool(a.requirePerfEventArraySupport),
		DenyClassificationCodes:      splitCSVUpper(derefString(a.denyCodes)),
		AllowClassificationCodes:     splitCSVUpper(derefString(a.allowCodes)),
	}
	maxFailedText := strings.TrimSpace(derefString(a.maxRequiredFailed))
	if maxFailedText != "" {
		value, err := strconv.Atoi(maxFailedText)
		if err != nil {
			return runtime.SelectionPolicy{}, fmt.Errorf("invalid policy-max-required-failed %q: %w", maxFailedText, err)
		}
		if value < 0 {
			return runtime.SelectionPolicy{}, fmt.Errorf("policy-max-required-failed must be >= 0")
		}
		policy.MaxRequiredFailed = &value
	}
	return policy, nil
}

func splitCSVUpper(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.ToUpper(strings.TrimSpace(part))
		if part == "" {
			continue
		}
		out = append(out, part)
	}
	return out
}

func derefBool(v *bool) bool {
	if v == nil {
		return false
	}
	return *v
}

func derefInt(v *int) int {
	if v == nil {
		return 0
	}
	return *v
}

func derefString(v *string) string {
	if v == nil {
		return ""
	}
	return *v
}

func runtimePolicyTrace(policy runtime.SelectionPolicy) *runtime.SelectionPolicy {
	if !runtime.PolicyHasConstraints(policy) {
		return nil
	}
	policyCopy := policy
	return &policyCopy
}

func verifyRuntimeHistoryGate(
	workDir string,
	selectedRecord registry.ArtifactVersionRecord,
	required bool,
) (*runtime.HistoryVerificationResult, error) {
	if !required {
		return nil, nil
	}
	result, err := runtime.VerifySelectedArtifactProvenance(workDir, selectedRecord)
	if err != nil {
		return &result, err
	}
	return &result, nil
}

func runRuntimeSelect(args []string) int {
	fs := flag.NewFlagSet("runtime select", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	workDir := fs.String("workdir", ".bpfcompat", "Working directory root")
	artifactName := fs.String("artifact-name", "", "Artifact family name")
	requestedVersion := fs.String("version", "", "Restrict selection to a specific version label")
	targetProfileID := fs.String("target-profile", "", "Explicit profile ID to optimize for (optional)")
	limit := fs.Int("limit", 5, "Max candidates to print")
	probeFlags := addRuntimeProbeFlags(fs)
	policyFlags := addRuntimePolicyFlags(fs)
	outPath := fs.String("out", "", "Write selection result JSON file (optional)")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage:\n  bpfcompat runtime select --artifact-name <name> [flags]\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return runner.ExitToolError
	}
	if strings.TrimSpace(*artifactName) == "" {
		fmt.Fprintln(os.Stderr, "--artifact-name is required")
		return runner.ExitToolError
	}
	policy, err := policyFlags.BuildPolicy()
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid policy flags: %v\n", err)
		return runner.ExitToolError
	}

	probeOpts := probeFlags.BuildProbeOptions()
	probe, err := runtime.ProbeHostCapabilitiesWithOptions(probeOpts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "runtime host probe failed: %v\n", err)
		return runner.ExitToolError
	}

	records, err := registry.ListArtifactVersions(*workDir, strings.TrimSpace(*artifactName), 0)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read artifact history: %v\n", err)
		return runner.ExitToolError
	}

	result, err := runtime.SelectBestArtifactVersion(records, probe, runtime.SelectionRequest{
		ArtifactName:     strings.TrimSpace(*artifactName),
		RequestedVersion: strings.TrimSpace(*requestedVersion),
		TargetProfileID:  strings.TrimSpace(*targetProfileID),
		Limit:            *limit,
		Policy:           policy,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "runtime selection failed: %v\n", err)
		return runner.ExitToolError
	}

	trace := runtime.DecisionTrace{
		Source:           "cli",
		Operation:        "select",
		ArtifactName:     strings.TrimSpace(*artifactName),
		RequestedVersion: strings.TrimSpace(*requestedVersion),
		TargetProfileID:  strings.TrimSpace(*targetProfileID),
		Policy:           runtimePolicyTrace(policy),
		Probe:            &probeOpts,
		HostProbe:        &probe,
		Selection:        &result,
		Status:           "success",
	}
	audit, auditErr := runtime.PersistDecisionTrace(*workDir, trace)

	payloadObj := map[string]any{
		"selection":  result,
		"host_probe": probe,
	}
	if auditErr != nil {
		payloadObj["audit_error"] = auditErr.Error()
	} else {
		payloadObj["audit"] = audit
	}

	payload, err := json.MarshalIndent(payloadObj, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "encode selection JSON: %v\n", err)
		return runner.ExitToolError
	}
	payload = append(payload, '\n')

	if strings.TrimSpace(*outPath) != "" {
		if err := os.WriteFile(filepath.Clean(*outPath), payload, 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "write selection JSON file: %v\n", err)
			return runner.ExitToolError
		}
		fmt.Printf("Selection JSON: %s\n", *outPath)
	}

	fmt.Printf("Selected: %s@%s variant=%s score=%d run=%s\n",
		result.ArtifactName,
		result.Selected.ArtifactVersion,
		result.Selected.ArtifactVariant,
		result.Selected.Score,
		result.Selected.RunID,
	)
	if auditErr != nil {
		fmt.Fprintf(os.Stderr, "warning: persist runtime decision trace: %v\n", auditErr)
	} else {
		fmt.Printf("Decision trace: %s\n", audit.TracePath)
	}
	_, _ = os.Stdout.Write(payload)
	return 0
}

func runRuntimeFetch(args []string) int {
	fs := flag.NewFlagSet("runtime fetch", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	workDir := fs.String("workdir", ".bpfcompat", "Working directory root")
	artifactName := fs.String("artifact-name", "", "Artifact family name")
	artifactVersion := fs.String("version", "", "Artifact version label (optional, newest selected when omitted)")
	targetProfileID := fs.String("target-profile", "", "Explicit target profile for selector (optional)")
	outDir := fs.String("out-dir", "artifacts/runtime-selected", "Directory to write fetched artifact")
	requireVerifiedHistory := fs.Bool("require-verified-history", true, "Require signed artifact history verification before runtime fetch")
	probeFlags := addRuntimeProbeFlags(fs)
	policyFlags := addRuntimePolicyFlags(fs)
	outPath := fs.String("out", "", "Write fetch result JSON file (optional)")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage:\n  bpfcompat runtime fetch --artifact-name <name> [flags]\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return runner.ExitToolError
	}
	if strings.TrimSpace(*artifactName) == "" {
		fmt.Fprintln(os.Stderr, "--artifact-name is required")
		return runner.ExitToolError
	}
	policy, err := policyFlags.BuildPolicy()
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid policy flags: %v\n", err)
		return runner.ExitToolError
	}

	records, err := registry.ListArtifactVersions(*workDir, strings.TrimSpace(*artifactName), 0)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read artifact history: %v\n", err)
		return runner.ExitToolError
	}

	var selectedRecord registry.ArtifactVersionRecord
	var selection *runtime.SelectionResult
	var hostProbe *runtime.HostCapabilities
	var probeOpts *runtime.ProbeOptions
	version := strings.TrimSpace(*artifactVersion)
	if version != "" && !runtime.PolicyHasConstraints(policy) {
		selectedRecord, err = runtime.FindSelectedRecord(records, strings.TrimSpace(*artifactName), version)
		if err != nil {
			fmt.Fprintf(os.Stderr, "find artifact version: %v\n", err)
			return runner.ExitToolError
		}
	} else {
		opts := probeFlags.BuildProbeOptions()
		probe, err := runtime.ProbeHostCapabilitiesWithOptions(opts)
		if err != nil {
			fmt.Fprintf(os.Stderr, "runtime host probe failed: %v\n", err)
			return runner.ExitToolError
		}
		probeOpts = &opts
		hostProbe = &probe
		sel, err := runtime.SelectBestArtifactVersion(records, probe, runtime.SelectionRequest{
			ArtifactName:     strings.TrimSpace(*artifactName),
			RequestedVersion: version,
			TargetProfileID:  strings.TrimSpace(*targetProfileID),
			Limit:            1,
			Policy:           policy,
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "runtime selection failed: %v\n", err)
			return runner.ExitToolError
		}
		selection = &sel
		selectedRecord, err = runtime.FindSelectedRecord(records, sel.ArtifactName, sel.Selected.ArtifactVersion)
		if err != nil {
			fmt.Fprintf(os.Stderr, "resolve selected record: %v\n", err)
			return runner.ExitToolError
		}
	}

	historyVerification, err := verifyRuntimeHistoryGate(*workDir, selectedRecord, *requireVerifiedHistory)
	if err != nil {
		fmt.Fprintf(os.Stderr, "runtime history verification failed: %v\n", err)
		return runner.ExitToolError
	}

	result, err := runtime.FetchArtifact(selectedRecord, *outDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "runtime fetch failed: %v\n", err)
		return runner.ExitToolError
	}

	trace := runtime.DecisionTrace{
		Source:           "cli",
		Operation:        "fetch",
		ArtifactName:     strings.TrimSpace(*artifactName),
		RequestedVersion: version,
		TargetProfileID:  strings.TrimSpace(*targetProfileID),
		Policy:           runtimePolicyTrace(policy),
		Selection:        selection,
		Fetch:            &result,
		Status:           "success",
		Notes: []string{
			fmt.Sprintf("history verification required: %t", *requireVerifiedHistory),
		},
	}
	if hostProbe != nil {
		trace.HostProbe = hostProbe
	}
	if probeOpts != nil {
		trace.Probe = probeOpts
	}
	audit, auditErr := runtime.PersistDecisionTrace(*workDir, trace)

	payloadObj := map[string]any{
		"fetch": result,
	}
	if selection != nil {
		payloadObj["selection"] = selection
	}
	if hostProbe != nil {
		payloadObj["host_probe"] = hostProbe
	}
	if historyVerification != nil {
		payloadObj["history_verification"] = historyVerification
	}
	if auditErr != nil {
		payloadObj["audit_error"] = auditErr.Error()
	} else {
		payloadObj["audit"] = audit
	}

	payload, err := json.MarshalIndent(payloadObj, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "encode fetch result JSON: %v\n", err)
		return runner.ExitToolError
	}
	payload = append(payload, '\n')
	if strings.TrimSpace(*outPath) != "" {
		if err := os.WriteFile(filepath.Clean(*outPath), payload, 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "write fetch result JSON file: %v\n", err)
			return runner.ExitToolError
		}
		fmt.Printf("Fetch JSON: %s\n", *outPath)
	}
	fmt.Printf("Fetched: %s\n", result.OutputPath)
	if auditErr != nil {
		fmt.Fprintf(os.Stderr, "warning: persist runtime decision trace: %v\n", auditErr)
	} else {
		fmt.Printf("Decision trace: %s\n", audit.TracePath)
	}
	_, _ = os.Stdout.Write(payload)
	return 0
}

func runRuntimeExecute(args []string) int {
	fs := flag.NewFlagSet("runtime execute", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	workDir := fs.String("workdir", ".bpfcompat", "Working directory root")
	artifactName := fs.String("artifact-name", "", "Artifact family name")
	artifactVersion := fs.String("version", "", "Artifact version label (optional)")
	targetProfileID := fs.String("target-profile", "", "Explicit target profile for selector (optional)")
	outDir := fs.String("out-dir", "artifacts/runtime-selected", "Directory to write fetched artifact")
	probeFlags := addRuntimeProbeFlags(fs)
	policyFlags := addRuntimePolicyFlags(fs)
	manifestPath := fs.String("manifest", "", "Manifest path override (optional; defaults to selected record manifest)")
	attachMode := fs.String("attach-mode", "best-effort", "Attach mode for host validation (disabled|best-effort|required)")
	probeFeatures := fs.Bool("probe-features", true, "Enable validator capability probing")
	allowHostLoad := fs.Bool("allow-host-load", false, "Required safety gate to execute selected artifact on host")
	requireVerifiedHistory := fs.Bool("require-verified-history", true, "Require signed artifact history verification before runtime execute")
	useSudo := fs.Bool("use-sudo", true, "Run validator with sudo")
	sudoNonInteractive := fs.Bool("sudo-non-interactive", true, "Use sudo -n to avoid password prompts")
	validatorPath := fs.String("validator", "", "Validator binary override path")
	timeoutText := fs.String("timeout", "2m", "Host execution timeout")
	outPath := fs.String("out", "", "Write execution result JSON file (optional)")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage:\n  bpfcompat runtime execute --artifact-name <name> --allow-host-load [flags]\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return runner.ExitToolError
	}
	if strings.TrimSpace(*artifactName) == "" {
		fmt.Fprintln(os.Stderr, "--artifact-name is required")
		return runner.ExitToolError
	}
	if !*allowHostLoad {
		fmt.Fprintln(os.Stderr, "--allow-host-load is required for runtime execute")
		return runner.ExitToolError
	}
	policy, err := policyFlags.BuildPolicy()
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid policy flags: %v\n", err)
		return runner.ExitToolError
	}
	timeout, err := time.ParseDuration(strings.TrimSpace(*timeoutText))
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid --timeout value %q: %v\n", *timeoutText, err)
		return runner.ExitToolError
	}

	records, err := registry.ListArtifactVersions(*workDir, strings.TrimSpace(*artifactName), 0)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read artifact history: %v\n", err)
		return runner.ExitToolError
	}

	var selectedRecord registry.ArtifactVersionRecord
	var selection *runtime.SelectionResult
	var hostProbe *runtime.HostCapabilities
	var probeOpts *runtime.ProbeOptions
	version := strings.TrimSpace(*artifactVersion)
	if version != "" && !runtime.PolicyHasConstraints(policy) {
		selectedRecord, err = runtime.FindSelectedRecord(records, strings.TrimSpace(*artifactName), version)
		if err != nil {
			fmt.Fprintf(os.Stderr, "find artifact version: %v\n", err)
			return runner.ExitToolError
		}
	} else {
		opts := probeFlags.BuildProbeOptions()
		probe, err := runtime.ProbeHostCapabilitiesWithOptions(opts)
		if err != nil {
			fmt.Fprintf(os.Stderr, "runtime host probe failed: %v\n", err)
			return runner.ExitToolError
		}
		probeOpts = &opts
		hostProbe = &probe
		sel, err := runtime.SelectBestArtifactVersion(records, probe, runtime.SelectionRequest{
			ArtifactName:     strings.TrimSpace(*artifactName),
			RequestedVersion: version,
			TargetProfileID:  strings.TrimSpace(*targetProfileID),
			Limit:            1,
			Policy:           policy,
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "runtime selection failed: %v\n", err)
			return runner.ExitToolError
		}
		selection = &sel
		selectedRecord, err = runtime.FindSelectedRecord(records, sel.ArtifactName, sel.Selected.ArtifactVersion)
		if err != nil {
			fmt.Fprintf(os.Stderr, "resolve selected record: %v\n", err)
			return runner.ExitToolError
		}
	}

	historyVerification, err := verifyRuntimeHistoryGate(*workDir, selectedRecord, *requireVerifiedHistory)
	if err != nil {
		fmt.Fprintf(os.Stderr, "runtime history verification failed: %v\n", err)
		return runner.ExitToolError
	}

	fetched, err := runtime.FetchArtifact(selectedRecord, *outDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "runtime fetch failed: %v\n", err)
		return runner.ExitToolError
	}

	manifestToUse := strings.TrimSpace(*manifestPath)
	if manifestToUse == "" {
		manifestToUse = strings.TrimSpace(selectedRecord.ManifestPath)
		if manifestToUse != "" {
			if _, statErr := os.Stat(filepath.Clean(manifestToUse)); statErr != nil {
				manifestToUse = ""
			}
		}
	}

	execution, err := runtime.ExecuteArtifactOnHost(context.Background(), runtime.ExecuteRequest{
		ArtifactPath:        fetched.OutputPath,
		ManifestPath:        manifestToUse,
		AttachMode:          strings.TrimSpace(*attachMode),
		ProbeFeatures:       *probeFeatures,
		AllowHostLoad:       *allowHostLoad,
		UseSudo:             *useSudo,
		SudoNonInteractive:  *sudoNonInteractive,
		ValidatorBinaryPath: strings.TrimSpace(*validatorPath),
		WorkDir:             *workDir,
		Timeout:             timeout,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "runtime execute failed: %v\n", err)
		return runner.ExitToolError
	}

	trace := runtime.DecisionTrace{
		Source:           "cli",
		Operation:        "execute",
		ArtifactName:     strings.TrimSpace(*artifactName),
		RequestedVersion: version,
		TargetProfileID:  strings.TrimSpace(*targetProfileID),
		Policy:           runtimePolicyTrace(policy),
		Selection:        selection,
		Fetch:            &fetched,
		Execution:        &execution,
		Status:           "success",
		Notes: []string{
			fmt.Sprintf("history verification required: %t", *requireVerifiedHistory),
		},
	}
	if hostProbe != nil {
		trace.HostProbe = hostProbe
	}
	if probeOpts != nil {
		trace.Probe = probeOpts
	}
	audit, auditErr := runtime.PersistDecisionTrace(*workDir, trace)

	payloadObj := map[string]any{
		"fetch":     fetched,
		"execution": execution,
	}
	if selection != nil {
		payloadObj["selection"] = selection
	}
	if hostProbe != nil {
		payloadObj["host_probe"] = hostProbe
	}
	if historyVerification != nil {
		payloadObj["history_verification"] = historyVerification
	}
	if auditErr != nil {
		payloadObj["audit_error"] = auditErr.Error()
	} else {
		payloadObj["audit"] = audit
	}

	payload, err := json.MarshalIndent(payloadObj, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "encode execution JSON: %v\n", err)
		return runner.ExitToolError
	}
	payload = append(payload, '\n')
	if strings.TrimSpace(*outPath) != "" {
		if err := os.WriteFile(filepath.Clean(*outPath), payload, 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "write execution JSON file: %v\n", err)
			return runner.ExitToolError
		}
		fmt.Printf("Execution JSON: %s\n", *outPath)
	}

	fmt.Printf("Executed: %s status=%s exit=%d\n", execution.ArtifactPath, execution.Status, execution.ExitCode)
	if auditErr != nil {
		fmt.Fprintf(os.Stderr, "warning: persist runtime decision trace: %v\n", auditErr)
	} else {
		fmt.Printf("Decision trace: %s\n", audit.TracePath)
	}
	_, _ = os.Stdout.Write(payload)

	switch execution.Status {
	case "pass":
		return runner.ExitSuccess
	case "fail":
		return runner.ExitCompatibilityFailure
	default:
		return runner.ExitToolError
	}
}

func runRuntimeWorkerExecute(args []string) int {
	fs := flag.NewFlagSet("runtime worker-execute", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage:\n  bpfcompat runtime worker-execute\n\n")
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

	var req runtime.ExecuteWorkerRequest
	if err := json.NewDecoder(os.Stdin).Decode(&req); err != nil {
		fmt.Fprintf(os.Stderr, "decode runtime worker request: %v\n", err)
		return runner.ExitToolError
	}

	result, err := runtime.ExecuteArtifactOnHost(context.Background(), req.Execute)
	if err != nil {
		fmt.Fprintf(os.Stderr, "runtime worker execute failed: %v\n", err)
		return runner.ExitToolError
	}

	resp := runtime.ExecuteWorkerResponse{Execution: result}
	payload, err := json.Marshal(resp)
	if err != nil {
		fmt.Fprintf(os.Stderr, "encode runtime worker response: %v\n", err)
		return runner.ExitToolError
	}
	payload = append(payload, '\n')
	if _, err := os.Stdout.Write(payload); err != nil {
		fmt.Fprintf(os.Stderr, "write runtime worker response: %v\n", err)
		return runner.ExitToolError
	}
	return runner.ExitSuccess
}

func printSummary(result runner.RunResult) {
	fmt.Printf("Run ID: %s\n", result.Report.Run.ID)
	fmt.Printf("Run Dir: %s\n", result.RunDir)
	fmt.Printf("Artifact: %s\n", result.Report.Artifact.Path)
	fmt.Printf("Hash: %s\n", result.Report.Artifact.SHA256)
	fmt.Printf("Matrix Profiles: %d\n", len(result.Report.Matrix.Profiles))
	fmt.Printf("Status: %s\n", result.Report.Summary.Status)
	if len(result.Report.Targets) > 0 {
		fmt.Println("Targets:")
		for _, target := range result.Report.Targets {
			line := fmt.Sprintf("  - %s: %s", target.ProfileID, target.Status)
			if target.InfraError != "" {
				line += fmt.Sprintf(" (%s)", target.InfraError)
			}
			fmt.Println(line)
		}
	}
	fmt.Printf("JSON Report: %s\n", result.Report.Paths.JSON)
	if result.Report.Paths.Markdown != "" {
		fmt.Printf("Markdown Report: %s\n", result.Report.Paths.Markdown)
	}
	if len(result.Report.Summary.Notes) > 0 {
		fmt.Println("Notes:")
		for _, note := range result.Report.Summary.Notes {
			fmt.Printf("  - %s\n", note)
		}
	}
}

func printRootUsage() {
	fmt.Println("Adaptive BPF Compatibility CLI")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  bpfcompat test --artifact <file> --matrix <file> --out <file> [flags]")
	fmt.Println("  bpfcompat test --command <cmd> --matrix <file> --out <file> [--command-binary <file>] [flags]")
	fmt.Println("  bpfcompat suite --suite <file> --out <file> [flags]")
	fmt.Println("  bpfcompat profile list --matrix <file>")
	fmt.Println("  bpfcompat history list [flags]")
	fmt.Println("  bpfcompat history verify [flags]")
	fmt.Println("  bpfcompat history sign [flags]")
	fmt.Println("  bpfcompat compare --base-report <file> --head-report <file> [flags]")
	fmt.Println("  bpfcompat compare --artifact-name <name> --base-version <v1> --head-version <v2> [flags]")
	fmt.Println("  bpfcompat serve [flags]")
	fmt.Println("  bpfcompat runtime probe [flags]")
	fmt.Println("  bpfcompat runtime select --artifact-name <name> [flags]")
	fmt.Println("  bpfcompat runtime fetch --artifact-name <name> [flags]")
	fmt.Println("  bpfcompat runtime execute --artifact-name <name> --allow-host-load [flags]")
	fmt.Println("  bpfcompat agent preflight [--workdir DIR --out-dir DIR] [--include-load]")
	fmt.Println("  bpfcompat agent plan  --artifact-name <name> [--api-url URL --tenant T --project P] [flags]")
	fmt.Println("  bpfcompat agent apply --artifact-name <name> [--api-url URL --tenant T --project P] [--approve-load] [flags]")
	fmt.Println("  bpfcompat admin list-tokens   [--workdir DIR] [--json]")
	fmt.Println("  bpfcompat admin revoke-token  [--workdir DIR] --subject SUBJ --tenant T [--project P] [--dry-run]")
	fmt.Println("  bpfcompat admin revoke-token  [--workdir DIR] --subject SUBJ --all-tenants [--dry-run]")
	fmt.Println("  bpfcompat admin verify-chain  [--workdir DIR] [--json]  # local artifact history only")
	fmt.Println("  bpfcompat admin audit-export  [--workdir DIR] [--tenant T] [--project P] [--limit N] [--out FILE] [--sign-key FILE --sig-out FILE]")
	fmt.Println("  bpfcompat admin audit-verify  --input FILE --sig FILE --pubkey FILE")
	fmt.Println("  bpfcompat report-summary --report <file>")
	fmt.Println("  bpfcompat kernel-freshness [--baselines <file>] [--fail-on-stale] [--update-from-report <file>]")
	fmt.Println("  bpfcompat kernel-sweep --profile <id> [--count N] [--series <prefix>]")
	fmt.Println("  bpfcompat version [--json]")
	fmt.Println("  bpfcompat env [--markdown|--json]")
}

func printProfileUsage() {
	fmt.Println("Usage:")
	fmt.Println("  bpfcompat profile list --matrix <file>")
}

func printHistoryUsage() {
	fmt.Println("Usage:")
	fmt.Println("  bpfcompat history list [flags]")
	fmt.Println("  bpfcompat history verify [flags]")
	fmt.Println("  bpfcompat history sign [flags]")
}

func printRuntimeUsage() {
	fmt.Println("Usage:")
	fmt.Println("  bpfcompat runtime probe [flags]")
	fmt.Println("  bpfcompat runtime select --artifact-name <name> [flags]")
	fmt.Println("  bpfcompat runtime fetch --artifact-name <name> [flags]")
	fmt.Println("  bpfcompat runtime execute --artifact-name <name> --allow-host-load [flags]")
}
