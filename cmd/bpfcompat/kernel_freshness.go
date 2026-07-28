package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"text/tabwriter"
	"time"

	"github.com/kernel-guard/bpfcompat/internal/freshness"
	"github.com/kernel-guard/bpfcompat/internal/runner"
	"github.com/kernel-guard/bpfcompat/pkg/schema"
)

// runKernelFreshness compares the committed per-profile kernel baselines
// against the inventory published by falcosecurity/kernel-crawler, or (with
// --update-from-report) refreshes the baselines from a matrix report.
func runKernelFreshness(args []string) int {
	fs := flag.NewFlagSet("kernel-freshness", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	baselinesPath := fs.String("baselines", "vm/kernel-baselines.yaml", "Path to the kernel baselines YAML")
	crawlerBase := fs.String("crawler-base", freshness.DefaultCrawlerBase, "Base URL publishing <arch>/list.json inventories")
	crawlerFile := fs.String("crawler-file", "", "Local kernel-crawler list.json (skips download; used for every arch)")
	markdownPath := fs.String("markdown", "", "Optional Markdown report output path")
	jsonPath := fs.String("json", "", "Optional JSON results output path")
	updateFromReport := fs.String("update-from-report", "", "Refresh baselines from a bpfcompat JSON report instead of checking freshness")
	failOnStale := fs.Bool("fail-on-stale", false, "Exit with the compatibility-failure code when any profile is stale")
	timeout := fs.Duration("timeout", 4*time.Minute, "Inventory download timeout (the x86_64 list is ~90 MB)")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage:\n  bpfcompat kernel-freshness [--baselines <file>] [--fail-on-stale] [--markdown <file>]\n  bpfcompat kernel-freshness --update-from-report <report.json>\n\n")
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

	data, err := os.ReadFile(*baselinesPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read baselines: %v\n", err)
		return runner.ExitToolError
	}
	baselines, err := freshness.LoadBaselines(data)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return runner.ExitToolError
	}

	if *updateFromReport != "" {
		return runKernelFreshnessUpdate(*baselinesPath, baselines, *updateFromReport)
	}

	fetch := func(arch string) (freshness.Inventory, error) {
		if *crawlerFile != "" {
			return freshness.LoadInventoryFile(*crawlerFile)
		}
		return freshness.FetchInventory(context.Background(), *crawlerBase, arch, *timeout)
	}

	results, err := freshness.Evaluate(baselines, fetch)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return runner.ExitToolError
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "PROFILE\tLAST VALIDATED\tNEWEST SHIPPING\tSTATUS")
	for _, r := range results {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", r.Profile, dashIfEmpty(r.Baseline), dashIfEmpty(r.Newest), r.Status)
	}
	if err := w.Flush(); err != nil {
		fmt.Fprintf(os.Stderr, "write table: %v\n", err)
		return runner.ExitToolError
	}
	stale := freshness.StaleCount(results)
	fmt.Printf("\n%d profile(s) stale of %d checked\n", stale, len(results))

	if *markdownPath != "" {
		if err := writeOutputFile(*markdownPath, []byte(freshness.Markdown(results))); err != nil {
			fmt.Fprintf(os.Stderr, "write markdown: %v\n", err)
			return runner.ExitToolError
		}
	}
	if *jsonPath != "" {
		payload, err := json.MarshalIndent(results, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "marshal results: %v\n", err)
			return runner.ExitToolError
		}
		if err := writeOutputFile(*jsonPath, append(payload, '\n')); err != nil {
			fmt.Fprintf(os.Stderr, "write json: %v\n", err)
			return runner.ExitToolError
		}
	}

	if *failOnStale && stale > 0 {
		return runner.ExitCompatibilityFailure
	}
	return runner.ExitSuccess
}

func runKernelFreshnessUpdate(baselinesPath string, baselines freshness.Baselines, reportPath string) int {
	file, err := os.Open(reportPath) // #nosec G304 -- operator-supplied path by design
	if err != nil {
		fmt.Fprintf(os.Stderr, "open report: %v\n", err)
		return runner.ExitToolError
	}
	defer file.Close()

	var rep schema.ReportV01
	if err := json.NewDecoder(file).Decode(&rep); err != nil {
		fmt.Fprintf(os.Stderr, "decode report: %v\n", err)
		return runner.ExitToolError
	}

	updated, added := freshness.UpdateFromReport(&baselines, rep)
	if len(updated) == 0 && len(added) == 0 {
		fmt.Println("baselines already match the report; nothing to update")
		return runner.ExitSuccess
	}

	out, err := freshness.MarshalBaselines(baselines)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return runner.ExitToolError
	}
	if err := os.WriteFile(baselinesPath, out, 0o644); err != nil { // #nosec G306,G703 -- operator-selected committed baseline path.
		fmt.Fprintf(os.Stderr, "write baselines: %v\n", err)
		return runner.ExitToolError
	}
	for _, p := range updated {
		fmt.Printf("updated %s\n", p)
	}
	for _, p := range added {
		fmt.Printf("added %s (no crawler mapping yet)\n", p)
	}
	return runner.ExitSuccess
}

func writeOutputFile(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644) // #nosec G306,G703 -- operator-selected report destination, not a sandbox path.
}

func dashIfEmpty(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
