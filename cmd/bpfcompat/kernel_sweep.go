package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/kernel-guard/bpfcompat/internal/freshness"
	"github.com/kernel-guard/bpfcompat/internal/runner"
	"github.com/kernel-guard/bpfcompat/internal/vm"
	"gopkg.in/yaml.v3"
)

// runKernelSweep generates a dense kernel matrix for one base profile: it
// picks the most recent kernel releases for the profile's series from the
// kernel-crawler inventory and emits derived profiles (same image, plus
// install_kernel) and a matrix referencing them. Each derived target boots
// the base image, installs its kernel via apt, reboots into it, and then
// validates — so one cloud image covers a whole release series instead of
// only the kernel it shipped with.
func runKernelSweep(args []string) int {
	fs := flag.NewFlagSet("kernel-sweep", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	profileID := fs.String("profile", "", "Base profile id (debian- and rhel-family profiles)")
	count := fs.Int("count", 4, "Number of most-recent kernel releases to include")
	series := fs.String("series", "", "Kernel release prefix (default: from the baseline mapping, else <kernel_family>.0-)")
	crawlerTarget := fs.String("target", "", "kernel-crawler target flavor (default: from the baseline mapping, else the distro default)")
	baselinesPath := fs.String("baselines", "vm/kernel-baselines.yaml", "Baselines file supplying the profile's kernel-crawler mapping")
	crawlerBase := fs.String("crawler-base", freshness.DefaultCrawlerBase, "Base URL publishing <arch>/list.json inventories")
	crawlerFile := fs.String("crawler-file", "", "Local kernel-crawler list.json (skips download)")
	profileDir := fs.String("profile-dir", "vm/profiles", "Directory for generated profiles")
	matrixOut := fs.String("matrix-out", "", "Generated matrix path (default: matrices/kernel-sweep-<profile>.yaml)")
	targetTimeout := fs.String("target-timeout", "20m", "Per-target timeout written into the matrix (kernel install adds minutes)")
	timeout := fs.Duration("timeout", 4*time.Minute, "Inventory download timeout")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), "Usage:\n  bpfcompat kernel-sweep --profile <id> [--count N] [--series <prefix>]\n\n")
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
	if *profileID == "" {
		fmt.Fprintln(os.Stderr, "--profile is required")
		return runner.ExitToolError
	}
	if *count < 1 {
		fmt.Fprintln(os.Stderr, "--count must be >= 1")
		return runner.ExitToolError
	}

	base, err := vm.LoadProfile(filepath.Join(*profileDir, *profileID+".yaml"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "load base profile: %v\n", err)
		return runner.ExitToolError
	}
	family := vm.KernelInstallFamily(base.Distro)
	if family == "" {
		fmt.Fprintf(os.Stderr, "kernel-sweep supports debian- and rhel-family profiles only (got distro %q)\n", base.Distro)
		return runner.ExitToolError
	}
	if base.InstallKernel != "" {
		fmt.Fprintf(os.Stderr, "base profile %s already sets install_kernel; use the original profile\n", base.ID)
		return runner.ExitToolError
	}

	// The committed baselines already carry each profile's crawler mapping
	// (distro key, target flavor, release prefix, and the release_contains
	// that keeps el9 and el10 apart under one distro key), so prefer it and
	// fall back to distro defaults only for profiles not yet listed.
	ref := defaultCrawlerRef(base.Distro, base.KernelFamily)
	if mapped, err := baselineCrawlerRef(*baselinesPath, base.ID); err != nil {
		fmt.Fprintf(os.Stderr, "read baselines: %v\n", err)
		return runner.ExitToolError
	} else if mapped != nil {
		ref = *mapped
	}
	if ref.Distro == "" {
		fmt.Fprintf(os.Stderr, "no kernel-crawler mapping for distro %q; add one to %s\n", base.Distro, *baselinesPath)
		return runner.ExitToolError
	}
	// Explicit flags win over both sources.
	if *crawlerTarget != "" {
		ref.Target = *crawlerTarget
	}
	if *series != "" {
		ref.ReleasePrefix = *series
	}
	if ref.ReleasePrefix == "" {
		ref.ReleasePrefix = base.KernelFamily + ".0-"
	}

	var inv freshness.Inventory
	if *crawlerFile != "" {
		inv, err = freshness.LoadInventoryFile(*crawlerFile)
	} else {
		arch := freshness.DefaultArch
		if a := strings.TrimSpace(base.Arch); a != "" {
			arch = a
		}
		inv, err = freshness.FetchInventory(context.Background(), *crawlerBase, arch, *timeout)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return runner.ExitToolError
	}

	entries := inv.SweepEntries(ref, *count)
	if len(entries) == 0 {
		fmt.Fprintf(os.Stderr, "no kernel releases match target %q prefix %q\n", ref.Target, ref.ReleasePrefix)
		return runner.ExitToolError
	}

	matrixPath := *matrixOut
	if matrixPath == "" {
		matrixPath = filepath.Join("matrices", "kernel-sweep-"+base.ID+".yaml")
	}

	var matrixBody strings.Builder
	fmt.Fprintf(&matrixBody, "# Generated by `bpfcompat kernel-sweep --profile %s`; regenerate rather than edit.\n", base.ID)
	fmt.Fprintf(&matrixBody, "name: kernel-sweep-%s\nprofiles:\n", base.ID)

	written := 0
	for _, entry := range entries {
		release := entry.KernelRelease
		// Direct pool URLs, because the package indexes only carry the
		// current ABI: superseded releases stay downloadable but are not
		// installable by name.
		var debs []string
		var err error
		if family == vm.KernelFamilyRHEL {
			debs, err = freshness.RHELKernelRPMs(entry)
		} else {
			debs, err = freshness.UbuntuKernelDebs(entry)
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "skip %s: %v\n", release, err)
			continue
		}
		derived := base
		derived.ID = sweepProfileID(base.ID, release)
		derived.InstallKernel = release
		derived.KernelPackages = debs

		payload, err := yaml.Marshal(derived)
		if err != nil {
			fmt.Fprintf(os.Stderr, "encode profile %s: %v\n", derived.ID, err)
			return runner.ExitToolError
		}
		header := fmt.Sprintf("# Generated by `bpfcompat kernel-sweep --profile %s`; regenerate rather than edit.\n", base.ID)
		profilePath := filepath.Join(*profileDir, derived.ID+".yaml")
		if err := os.WriteFile(profilePath, append([]byte(header), payload...), 0o644); err != nil { // #nosec G306 -- generated repo file
			fmt.Fprintf(os.Stderr, "write profile: %v\n", err)
			return runner.ExitToolError
		}
		fmt.Printf("wrote %s (install_kernel: %s)\n", profilePath, release)

		fmt.Fprintf(&matrixBody, "  - id: %s\n    required: true\n    timeout: %s\n", derived.ID, *targetTimeout)
		written++
	}
	if written == 0 {
		fmt.Fprintln(os.Stderr, "no profiles written; package URLs could not be derived for any release")
		return runner.ExitToolError
	}

	if err := os.MkdirAll(filepath.Dir(matrixPath), 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "create matrix directory: %v\n", err)
		return runner.ExitToolError
	}
	if err := os.WriteFile(matrixPath, []byte(matrixBody.String()), 0o644); err != nil { // #nosec G306 -- generated repo file
		fmt.Fprintf(os.Stderr, "write matrix: %v\n", err)
		return runner.ExitToolError
	}
	fmt.Printf("wrote %s (%d targets)\n", matrixPath, written)
	return runner.ExitSuccess
}

// sweepProfileID derives a stable profile id from the base id and the kernel
// release, dropping the flavor suffix the target already implies
// (ubuntu-22.04-5.15 + 5.15.0-118-generic -> ubuntu-22.04-5.15-k5.15.0-118).
func sweepProfileID(baseID, release string) string {
	short := strings.TrimSuffix(release, "-generic")
	short = strings.TrimSuffix(short, "-kvm")
	// RHEL-family releases carry the arch (5.14.0-687.26.1.el9_8.x86_64);
	// it is redundant in the id because the profile already pins arch.
	short = strings.TrimSuffix(short, ".x86_64")
	short = strings.TrimSuffix(short, ".aarch64")
	return baseID + "-k" + short
}

// defaultCrawlerRef supplies the kernel-crawler mapping for profiles that are
// not yet listed in the baselines file. The crawler groups RHEL rebuilds
// under their own distro key with the same value as the target flavor.
func defaultCrawlerRef(distro, kernelFamily string) freshness.CrawlerRef {
	prefix := ""
	if kernelFamily != "" {
		prefix = kernelFamily + ".0-"
	}
	switch strings.ToLower(strings.TrimSpace(distro)) {
	case "ubuntu":
		return freshness.CrawlerRef{Distro: "ubuntu", Target: "ubuntu-generic", ReleasePrefix: prefix}
	case "almalinux":
		return freshness.CrawlerRef{Distro: "almalinux", Target: "almalinux", ReleasePrefix: prefix}
	case "rocky":
		return freshness.CrawlerRef{Distro: "rocky", Target: "rocky", ReleasePrefix: prefix}
	case "centos-stream":
		return freshness.CrawlerRef{Distro: "centos", Target: "centos", ReleasePrefix: prefix}
	default:
		return freshness.CrawlerRef{}
	}
}

// baselineCrawlerRef returns the committed crawler mapping for profileID, or
// nil when the file has no entry (or no mapping) for it. A missing baselines
// file is not an error: the caller falls back to distro defaults.
func baselineCrawlerRef(path, profileID string) (*freshness.CrawlerRef, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- operator-supplied path by design
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	baselines, err := freshness.LoadBaselines(data)
	if err != nil {
		return nil, err
	}
	for _, entry := range baselines.Baselines {
		if entry.Profile == profileID {
			return entry.Crawler, nil
		}
	}
	return nil, nil
}
