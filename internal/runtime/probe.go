package runtime

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const hostProbeSchemaVersion = "runtime_probe.v0.1"

var kernelVersionPattern = regexp.MustCompile(`^([0-9]+)\.([0-9]+)`)

type ProbeOptions struct {
	PreferPrivileged   bool
	UseSudo            bool
	SudoNonInteractive bool
}

var runCommandWithOutputFn = runCommandWithOutput
var getEffectiveUIDFn = os.Geteuid
var lookPathFn = exec.LookPath

func ProbeHostCapabilities() (HostCapabilities, error) {
	return ProbeHostCapabilitiesWithOptions(ProbeOptions{})
}

func ProbeHostCapabilitiesWithOptions(opts ProbeOptions) (HostCapabilities, error) {
	var out HostCapabilities
	out.SchemaVersion = hostProbeSchemaVersion
	out.CollectedAt = time.Now().UTC().Format(time.RFC3339)
	out.Host.Arch = runtime.GOARCH
	hostname, _ := os.Hostname()
	out.Host.Hostname = hostname

	out.OS = readOSRelease()
	release, version := readKernelUname()
	out.Kernel.Release = release
	out.Kernel.Version = version
	out.BTF.KernelAvailable = fileExists("/sys/kernel/btf/vmlinux")

	kMajor, kMinor, parseOK := parseKernelVersion(release)
	if !parseOK {
		out.Warnings = append(out.Warnings, "unable to parse kernel major/minor from release string")
	}

	// Base heuristic predictions (work without special privileges).
	out.ProbeMode = "heuristic"
	out.Features.MapRingbuf = heuristicProbe(parseOK && kernelAtLeast(kMajor, kMinor, 5, 8), "kernel>=5.8 heuristic")
	out.Features.MapPerfEventArray = heuristicProbe(parseOK && kernelAtLeast(kMajor, kMinor, 4, 3), "kernel>=4.3 heuristic")
	out.Features.ProgTracepoint = heuristicProbe(parseOK && kernelAtLeast(kMajor, kMinor, 4, 7), "kernel>=4.7 heuristic")
	out.Features.ProgKprobe = heuristicProbe(parseOK && kernelAtLeast(kMajor, kMinor, 4, 1), "kernel>=4.1 heuristic")
	out.Features.ProgTracing = heuristicProbe(parseOK && kernelAtLeast(kMajor, kMinor, 5, 5), "kernel>=5.5 heuristic")
	out.Features.ProgXDP = heuristicProbe(parseOK && kernelAtLeast(kMajor, kMinor, 4, 8), "kernel>=4.8 heuristic")
	out.Features.AttachTracefs = existenceProbe(
		[]string{"/sys/kernel/tracing/events", "/sys/kernel/debug/tracing/events"},
		"tracefs event directory",
	)
	out.Features.AttachKprobeEvents = existenceProbe(
		[]string{"/sys/kernel/tracing/kprobe_events", "/sys/kernel/debug/tracing/kprobe_events"},
		"kprobe_events file",
	)

	// Best-effort bpftool probe with optional privileged path and unprivileged fallback.
	text, sourceMode, restricted, probeWarning, err := runBPFToolProbe(opts)
	if err == nil && text != "" {
		out.ProbeMode = "heuristic+" + sourceMode
		if strings.TrimSpace(probeWarning) != "" {
			out.Warnings = append(out.Warnings, probeWarning)
		}
		mergeProbe(&out.Features.MapRingbuf, parseBPFToolFeature(text, "eBPF map_type ringbuf"))
		mergeProbe(&out.Features.MapPerfEventArray, parseBPFToolFeature(text, "eBPF map_type perf_event_array"))
		mergeProbe(&out.Features.ProgTracepoint, parseBPFToolFeature(text, "eBPF program_type tracepoint"))
		mergeProbe(&out.Features.ProgKprobe, parseBPFToolFeature(text, "eBPF program_type kprobe"))
		mergeProbe(&out.Features.ProgTracing, parseBPFToolFeature(text, "eBPF program_type tracing"))
		mergeProbe(&out.Features.ProgXDP, parseBPFToolFeature(text, "eBPF program_type xdp"))

		if restricted {
			out.Warnings = append(out.Warnings, "bpftool unprivileged probe indicates restricted visibility; heuristic signals retained")
			markRestricted(&out.Features.MapRingbuf)
			markRestricted(&out.Features.MapPerfEventArray)
			markRestricted(&out.Features.ProgTracepoint)
			markRestricted(&out.Features.ProgKprobe)
			markRestricted(&out.Features.ProgTracing)
			markRestricted(&out.Features.ProgXDP)
		}
	} else if err != nil {
		out.Warnings = append(out.Warnings, fmt.Sprintf("bpftool probe unavailable: %v", err))
	}

	return out, nil
}

func readOSRelease() struct {
	ID         string `json:"id"`
	VersionID  string `json:"version_id"`
	PrettyName string `json:"pretty_name"`
} {
	type osRelease struct {
		ID         string `json:"id"`
		VersionID  string `json:"version_id"`
		PrettyName string `json:"pretty_name"`
	}
	out := osRelease{}
	raw, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return out
	}
	lines := strings.Split(string(raw), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		value := strings.Trim(strings.TrimSpace(parts[1]), "\"")
		switch key {
		case "ID":
			out.ID = strings.ToLower(value)
		case "VERSION_ID":
			out.VersionID = value
		case "PRETTY_NAME":
			out.PrettyName = value
		}
	}
	return out
}

func readKernelUname() (release string, version string) {
	release = strings.TrimSpace(runAndCollect("uname", "-r"))
	version = strings.TrimSpace(runAndCollect("uname", "-v"))
	return release, version
}

func runAndCollect(name string, args ...string) string {
	cmd := exec.Command(name, args...)
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	return string(out)
}

func parseKernelVersion(release string) (major int, minor int, ok bool) {
	release = strings.TrimSpace(release)
	matches := kernelVersionPattern.FindStringSubmatch(release)
	if len(matches) != 3 {
		return 0, 0, false
	}
	major, err := strconv.Atoi(matches[1])
	if err != nil {
		return 0, 0, false
	}
	minor, err = strconv.Atoi(matches[2])
	if err != nil {
		return 0, 0, false
	}
	return major, minor, true
}

func kernelAtLeast(major, minor, wantMajor, wantMinor int) bool {
	if major > wantMajor {
		return true
	}
	if major < wantMajor {
		return false
	}
	return minor >= wantMinor
}

func heuristicProbe(supported bool, reason string) FeatureProbe {
	if supported {
		return FeatureProbe{
			Status:     SupportSupported,
			Confidence: "medium",
			Source:     "heuristic",
			Reason:     reason,
		}
	}
	return FeatureProbe{
		Status:     SupportUnknown,
		Confidence: "low",
		Source:     "heuristic",
		Reason:     reason,
	}
}

func existenceProbe(paths []string, description string) FeatureProbe {
	for _, p := range paths {
		if fileExists(p) {
			return FeatureProbe{
				Status:      SupportSupported,
				Confidence:  "medium",
				Source:      "filesystem",
				Description: description,
				Reason:      filepath.Clean(p),
			}
		}
	}
	return FeatureProbe{
		Status:      SupportUnknown,
		Confidence:  "low",
		Source:      "filesystem",
		Description: description,
		Reason:      "not found",
	}
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func runBPFToolProbe(opts ProbeOptions) (output string, mode string, restricted bool, warning string, err error) {
	// SECURITY: resolve bpftool against $PATH once and pass the absolute path
	// to all downstream invocations. The "sudo" path is configured by the
	// operator (sudoers should pin secure_path) and we want to avoid relying
	// on the caller's $PATH inside the elevated context.
	bpftoolPath, lookErr := lookPathFn("bpftool")
	if lookErr != nil {
		return "", "", false, "", fmt.Errorf("bpftool not found in PATH")
	}

	preferPrivileged := opts.PreferPrivileged || getEffectiveUIDFn() == 0
	var privilegedErr error
	if preferPrivileged {
		if getEffectiveUIDFn() == 0 {
			text, err := runBPFToolPrivileged(bpftoolPath)
			if err == nil {
				return text, "bpftool_privileged", false, "", nil
			}
			privilegedErr = err
		} else if opts.UseSudo {
			text, err := runBPFToolPrivilegedSudo(bpftoolPath, opts.SudoNonInteractive)
			if err == nil {
				return text, "bpftool_privileged_sudo", false, "", nil
			}
			privilegedErr = err
		}
	}

	text, restricted, err := runBPFToolUnprivileged(bpftoolPath)
	if err != nil {
		if privilegedErr != nil {
			return "", "", false, "", fmt.Errorf("privileged bpftool probe failed (%v) and unprivileged probe failed (%w)", privilegedErr, err)
		}
		return "", "", false, "", err
	}
	if privilegedErr != nil {
		return text, "bpftool_unprivileged", restricted, fmt.Sprintf("privileged bpftool probe unavailable, falling back to unprivileged probe: %v", privilegedErr), nil
	}
	return text, "bpftool_unprivileged", restricted, "", nil
}

func runBPFToolPrivileged(bpftoolPath string) (output string, err error) {
	return runCommandWithOutputFn(bpftoolPath, "feature", "probe", "kernel")
}

func runBPFToolPrivilegedSudo(bpftoolPath string, nonInteractive bool) (output string, err error) {
	args := make([]string, 0, 6)
	if nonInteractive {
		args = append(args, "-n")
	}
	// "--" stops sudo flag parsing before the absolute bpftool path so a
	// pathological PATH entry can't be reinterpreted as a sudo option.
	args = append(args, "--", bpftoolPath, "feature", "probe", "kernel")
	return runCommandWithOutputFn("sudo", args...)
}

func runBPFToolUnprivileged(bpftoolPath string) (output string, restricted bool, err error) {
	text, err := runCommandWithOutputFn(bpftoolPath, "feature", "probe", "kernel", "unprivileged")
	if err != nil {
		return "", false, err
	}
	lower := strings.ToLower(text)
	restricted = strings.Contains(lower, "restricted to privileged users")
	return text, restricted, nil
}

func runCommandWithOutput(name string, args ...string) (string, error) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd := exec.Command(name, args...)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("%s failed: %w (%s)", name, err, strings.TrimSpace(stderr.String()))
	}
	return stdout.String(), nil
}

func parseBPFToolFeature(output, prefix string) FeatureProbe {
	prefixLower := strings.ToLower(prefix)
	lines := strings.Split(strings.ToLower(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if !strings.Contains(line, prefixLower) {
			continue
		}
		switch {
		case strings.Contains(line, "is not available"):
			return FeatureProbe{
				Status:     SupportUnsupported,
				Confidence: "high",
				Source:     "bpftool",
				Reason:     strings.TrimSpace(line),
			}
		case strings.Contains(line, "is available"):
			return FeatureProbe{
				Status:     SupportSupported,
				Confidence: "high",
				Source:     "bpftool",
				Reason:     strings.TrimSpace(line),
			}
		}
	}
	return FeatureProbe{}
}

func mergeProbe(base *FeatureProbe, observed FeatureProbe) {
	if observed.Status == "" {
		return
	}
	*base = observed
}

func markRestricted(probe *FeatureProbe) {
	if probe.Status == "" {
		return
	}
	probe.Restricted = true
}

func HostProfileHint(c HostCapabilities) string {
	id := strings.TrimSpace(c.OS.ID)
	versionID := normalizeVersionID(c.OS.VersionID)
	kMajor, kMinor, ok := parseKernelVersion(c.Kernel.Release)
	if id == "" || versionID == "" || !ok {
		return ""
	}
	return fmt.Sprintf("%s-%s-%d.%d", id, versionID, kMajor, kMinor)
}

func normalizeVersionID(version string) string {
	version = strings.TrimSpace(version)
	if version == "" {
		return ""
	}
	parts := strings.Split(version, ".")
	if len(parts) >= 2 {
		return parts[0] + "." + parts[1]
	}
	return parts[0]
}
