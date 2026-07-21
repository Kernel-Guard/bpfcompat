package vm

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
)

type ExecutionRequest struct {
	Profile            Profile
	RunDir             string
	ArtifactPath       string
	ManifestPath       string
	FunctionalPlanPath string
	MapFixups          []MapFixup
	ProgTypes          []ProgTypeOverride
	ProgVariants       []ProgVariantGroup
	ProbeCompanions    []string
	ValidatorBinary    string
	AttachMode         string
	Timeout            time.Duration
	KeepVMOnFailure    bool

	// Command-mode validation. When Command is non-empty the validator is not
	// run; instead Command is executed inside the guest (as root) and the
	// per-kernel verdict is its exit code. CommandBinary, when set, is a local
	// executable shipped into the guest and exposed to Command as $BPFCOMPAT_BIN;
	// ArtifactPath, when set, is staged and exposed as $BPFCOMPAT_ARTIFACT.
	Command       string
	CommandBinary string
}

// ProgVariantGroup mirrors a manifest program-variant group for the
// validator command line. Group and variant names are validated at manifest
// load (identifier characters), so they are shell-safe here.
type ProgVariantGroup struct {
	Group    string
	Variants []ProgVariant
}

type ProgVariant struct {
	Name       string
	HelperID   uint32 // 0 = unconditional fallback
	TrialProbe bool   // gate on an isolated trial load on the target kernel
}

// MapFixup mirrors a manifest map fixup for the validator command line.
// Name and MaxEntries are validated at manifest load (identifier characters
// and "cpus"/positive-integer respectively), so they are shell-safe here.
type MapFixup struct {
	Name              string
	MaxEntries        string
	InnerRingbufBytes uint32
	// Generic inner-map prototype for a map-in-map. InnerMapType is one of the
	// names accepted by the validator (hash, array, lru_hash, ...) and is
	// validated at manifest load, so it is shell-safe here. Empty = unset.
	InnerMapType    string
	InnerKeySize    uint32
	InnerValueSize  uint32
	InnerMaxEntries uint32
}

func mapFixupArgs(fixups []MapFixup) string {
	var b strings.Builder
	for _, fixup := range fixups {
		if fixup.MaxEntries != "" {
			fmt.Fprintf(&b, " --set-map-max-entries %s", shellQuote(fmt.Sprintf("%s=%s", fixup.Name, fixup.MaxEntries)))
		}
		if fixup.InnerRingbufBytes > 0 {
			fmt.Fprintf(&b, " --set-map-inner-ringbuf %s", shellQuote(fmt.Sprintf("%s=%d", fixup.Name, fixup.InnerRingbufBytes)))
		}
		if fixup.InnerMapType != "" {
			fmt.Fprintf(&b, " --set-map-inner-map %s", shellQuote(fmt.Sprintf("%s=%s:%d:%d:%d", fixup.Name,
				fixup.InnerMapType, fixup.InnerKeySize, fixup.InnerValueSize, fixup.InnerMaxEntries)))
		}
	}
	return b.String()
}

// ProgTypeOverride mirrors a manifest program-type override for the validator
// command line. Selector (program name or section) and Type are validated at
// manifest load, so both are shell-safe here.
type ProgTypeOverride struct {
	Selector string
	Type     string
}

func progTypeArgs(overrides []ProgTypeOverride) string {
	var b strings.Builder
	for _, ov := range overrides {
		fmt.Fprintf(&b, " --set-prog-type %s", shellQuote(fmt.Sprintf("%s=%s", ov.Selector, ov.Type)))
	}
	return b.String()
}

func progVariantArgs(groups []ProgVariantGroup) string {
	var b strings.Builder
	for _, group := range groups {
		var operand strings.Builder
		fmt.Fprintf(&operand, "%s=", group.Group)
		for i, variant := range group.Variants {
			if i > 0 {
				operand.WriteByte(',')
			}
			if variant.TrialProbe {
				fmt.Fprintf(&operand, "%s:trial", variant.Name)
			} else {
				fmt.Fprintf(&operand, "%s:%d", variant.Name, variant.HelperID)
			}
		}
		fmt.Fprintf(&b, " --prog-variants %s", shellQuote(operand.String()))
	}
	return b.String()
}

// validatorTuningArgs renders all manifest-declared loader-contract flags
// (map fixups, program variant groups) for the in-guest validator command.
func validatorTuningArgs(req ExecutionRequest) string {
	args := mapFixupArgs(req.MapFixups) + progTypeArgs(req.ProgTypes) + progVariantArgs(req.ProgVariants)
	if len(req.ProbeCompanions) > 0 {
		args += " --probe-companions " + shellQuote(strings.Join(req.ProbeCompanions, ","))
	}
	return args
}

type ExecutionResult struct {
	ProfileID           string
	Status              string
	InfraError          string
	ValidatorExitCode   int
	VMRunDir            string
	SerialLogPath       string
	QEMUCommand         string
	ValidatorResultPath string
	Notes               []string
	StartedAt           time.Time
	FinishedAt          time.Time

	// Command-mode outputs (populated only when ExecutionRequest.Command is set).
	CommandMode       bool
	CommandExitCode   int
	CommandStdoutTail string
	CommandStderrTail string
	HostRelease       string
	HostMachine       string
}

const (
	maxVMCPUs     = 4
	maxVMMemoryMB = 4096
)

type seedDeliveryMode string

const (
	seedDeliveryNoCloudNet         seedDeliveryMode = "nocloud-net"
	seedDeliveryNoCloudConfigDrive seedDeliveryMode = "nocloud-configdrive"
	seedDeliveryNoCloudConfigFS    seedDeliveryMode = "nocloud-configfs"
	seedDeliveryIgnition           seedDeliveryMode = "ignition"
)

func ExecuteProfile(ctx context.Context, req ExecutionRequest) (result ExecutionResult) {
	startedAt := time.Now().UTC()
	result = ExecutionResult{
		ProfileID: req.Profile.ID,
		Status:    "infra_error",
		StartedAt: startedAt,
	}
	defer func() {
		result.FinishedAt = time.Now().UTC()
	}()

	vmRunDir := filepath.Join(req.RunDir, "targets", req.Profile.ID)
	if err := os.MkdirAll(vmRunDir, 0o755); err != nil {
		result.InfraError = fmt.Sprintf("create vm run directory: %v", err)
		return
	}
	result.VMRunDir = vmRunDir

	if _, supported, reason := ExecutionTransport(req.Profile); !supported {
		result.InfraError = reason
		return
	}

	baseImagePath, imageSHA, err := ensureImageAvailable(req.Profile, vmRunDir)
	if err != nil {
		result.InfraError = err.Error()
		return
	}
	if imageSHA != "" {
		result.Notes = append(result.Notes, fmt.Sprintf("base image sha256: %s", imageSHA))
	}

	overlayPath := filepath.Join(vmRunDir, "overlay.qcow2")
	if err := createOverlayImage(ctx, baseImagePath, overlayPath); err != nil {
		result.InfraError = err.Error()
		return
	}
	if req.Profile.InstallKernel != "" {
		// Cloud images ship near-full rootfs; a kernel install plus
		// initramfs generation overflows it. Grow the overlay's virtual
		// disk — cloud-init's growpart expands the partition at boot.
		if err := resizeOverlayImage(ctx, overlayPath, "+4G"); err != nil {
			result.InfraError = err.Error()
			return
		}
		result.Notes = append(result.Notes, "overlay grown +4G for in-guest kernel install")
	}
	// Register the overlay-removal defer immediately so we don't leak the
	// qcow2 if any of the steps between here and startQEMU fail (SSH key
	// generation, seed write, seed image build, seed server bind, port
	// reservation, or QEMU launch itself). qemuProc is captured by the
	// closure and is nil until startQEMU succeeds, so we only terminate
	// a process if we actually started one.
	var qemuProc *os.Process
	defer func() {
		if qemuProc != nil {
			_ = terminateProcess(qemuProc)
		}
		if !req.KeepVMOnFailure {
			_ = os.Remove(overlayPath)
		}
	}()

	privateKeyPath := filepath.Join(vmRunDir, "id_ed25519")
	publicKey, err := generateSSHKeyPair(ctx, privateKeyPath)
	if err != nil {
		result.InfraError = err.Error()
		return
	}

	seedMode, err := seedDeliveryForProfile(req.Profile)
	if err != nil {
		result.InfraError = err.Error()
		return
	}
	seedDir := filepath.Join(vmRunDir, "seed")
	seedURL := ""
	seedImagePath := ""

	// CoreOS-family images boot via Ignition (fw_cfg), not a cloud-init NoCloud
	// seed; write the Ignition config and skip the NoCloud seed entirely.
	if seedMode == seedDeliveryIgnition {
		seedImagePath = filepath.Join(vmRunDir, "config.ign")
		if err := writeIgnitionSeed(seedImagePath, publicKey); err != nil {
			result.InfraError = err.Error()
			return
		}
		result.Notes = append(result.Notes, "seed delivery: Ignition config via fw_cfg (opt/com.coreos/config)")
	} else if err := writeNoCloudSeed(seedDir, req.Profile.ID, publicKey); err != nil {
		result.InfraError = err.Error()
		return
	}

	seedDirAbs, err := filepath.Abs(seedDir)
	if err != nil {
		result.InfraError = fmt.Sprintf("resolve seed directory: %v", err)
		return
	}
	switch seedMode {
	case seedDeliveryIgnition:
		// config.ign already written; nothing more to stage here.
	case seedDeliveryNoCloudConfigDrive:
		seedImagePath = filepath.Join(vmRunDir, "seed-cidata.iso")
		if err := createNoCloudSeedImage(ctx, seedDir, seedImagePath); err != nil {
			result.InfraError = fmt.Sprintf("create NoCloud seed image: %v", err)
			return
		}
		result.Notes = append(result.Notes, "seed delivery: local NoCloud config drive image (cloud-localds)")
	case seedDeliveryNoCloudConfigFS:
		result.Notes = append(result.Notes, "seed delivery: local NoCloud config drive (vvfat, label=cidata) — legacy fallback enabled via BPFCOMPAT_ALLOW_VVFAT_SEED; if this guest never reaches SSH, install cloud-image-utils instead")
	default:
		seedSrv, err := startSeedServer(seedDir)
		if err != nil {
			result.InfraError = fmt.Sprintf("start seed server: %v", err)
			return
		}
		defer seedSrv.closeFn()

		seedURL, err = seedSrv.seedURL()
		if err != nil {
			result.InfraError = fmt.Sprintf("build seed URL: %v", err)
			return
		}
		result.Notes = append(result.Notes, "seed delivery: NoCloud over SMBIOS network URL")
	}

	sshPort, err := reserveLocalPort()
	if err != nil {
		result.InfraError = err.Error()
		return
	}

	serialLogPath := filepath.Join(vmRunDir, "serial.log")
	qemuLogPath := filepath.Join(vmRunDir, "qemu.log")
	cmd, qemuCmdString, err := startQEMU(ctx, req.Profile, overlayPath, serialLogPath, qemuLogPath, sshPort, seedMode, seedURL, seedDirAbs, seedImagePath)
	if err != nil {
		result.InfraError = err.Error()
		return
	}
	qemuProc = cmd.Process
	result.QEMUCommand = qemuCmdString
	result.SerialLogPath = serialLogPath

	sshCtx, cancel := context.WithTimeout(ctx, req.Timeout)
	defer cancel()
	targetBase := sshTarget{
		PrivateKey: privateKeyPath,
		Port:       sshPort,
	}
	sshUsers := sshUserCandidates(req.Profile)
	target, err := waitForSSHAnyUser(sshCtx, targetBase, sshUsers, req.Timeout)
	if err != nil {
		result.InfraError = fmt.Sprintf("wait for SSH (%s): %v", strings.Join(sshUsers, ","), err)
		return
	}
	result.Notes = append(result.Notes, fmt.Sprintf("SSH user selected: %s", target.User))

	if req.Profile.InstallKernel != "" {
		newCmd, err := installGuestKernelAndReboot(ctx, &result, req, target, cmd,
			overlayPath, serialLogPath, qemuLogPath, sshPort, seedMode, seedURL, seedDirAbs, seedImagePath)
		if err != nil {
			result.InfraError = err.Error()
			return
		}
		// newCmd is the post-reboot QEMU process; only qemuProc is read
		// afterward (for cleanup), so we don't reassign cmd here.
		qemuProc = newCmd.Process

		rebootCtx, cancelReboot := context.WithTimeout(ctx, req.Timeout)
		defer cancelReboot()
		target, err = waitForSSHAnyUser(rebootCtx, targetBase, []string{target.User}, req.Timeout)
		if err != nil {
			result.InfraError = fmt.Sprintf("wait for SSH after kernel-install reboot: %v", err)
			return
		}

		booted, err := sshOutput(ctx, target, "uname -r")
		if err != nil {
			result.InfraError = fmt.Sprintf("verify installed kernel: %v", err)
			return
		}
		if booted != req.Profile.InstallKernel {
			result.InfraError = fmt.Sprintf("guest booted kernel %q after install of %q; grub default selection failed", booted, req.Profile.InstallKernel)
			return
		}
		result.Notes = append(result.Notes, fmt.Sprintf("installed kernel booted: %s", booted))
	}

	remoteRoot := "/tmp/bpfcompat"
	if err := sshRun(ctx, target, fmt.Sprintf("mkdir -p %s/bin %s/input %s/out", remoteRoot, remoteRoot, remoteRoot)); err != nil {
		result.InfraError = err.Error()
		return
	}

	artifactRemotePath := ""
	if strings.TrimSpace(req.ArtifactPath) != "" {
		artifactRemotePath = filepath.ToSlash(filepath.Join(remoteRoot, "input", filepath.Base(req.ArtifactPath)))
		if err := scpToGuest(ctx, target, req.ArtifactPath, artifactRemotePath); err != nil {
			result.InfraError = err.Error()
			return
		}
	}

	if strings.TrimSpace(req.Command) != "" {
		runGuestCommand(ctx, req, target, vmRunDir, remoteRoot, artifactRemotePath, &result)
		return
	}

	validatorRemotePath := filepath.ToSlash(filepath.Join(remoteRoot, "bin", "bpfcompat-validator"))
	if err := scpToGuest(ctx, target, req.ValidatorBinary, validatorRemotePath); err != nil {
		result.InfraError = err.Error()
		return
	}
	if err := sshRun(ctx, target, fmt.Sprintf("chmod +x %s", validatorRemotePath)); err != nil {
		result.InfraError = err.Error()
		return
	}

	manifestArg := ""
	if req.ManifestPath != "" {
		manifestRemotePath := filepath.ToSlash(filepath.Join(remoteRoot, "input", filepath.Base(req.ManifestPath)))
		if err := scpToGuest(ctx, target, req.ManifestPath, manifestRemotePath); err != nil {
			result.InfraError = err.Error()
			return
		}
		manifestArg = fmt.Sprintf(" --manifest %s", shellQuote(manifestRemotePath))
	}

	functionalPlanArg := ""
	if req.FunctionalPlanPath != "" {
		functionalPlanRemotePath := filepath.ToSlash(filepath.Join(remoteRoot, "input", filepath.Base(req.FunctionalPlanPath)))
		if err := scpToGuest(ctx, target, req.FunctionalPlanPath, functionalPlanRemotePath); err != nil {
			result.InfraError = err.Error()
			return
		}
		functionalPlanArg = fmt.Sprintf(" --functional-plan %s", shellQuote(functionalPlanRemotePath))
	}

	remoteResultPath := filepath.ToSlash(filepath.Join(remoteRoot, "out", "result.json"))
	remoteExitPath := filepath.ToSlash(filepath.Join(remoteRoot, "out", "validator-exit-code"))
	remoteErrPath := filepath.ToSlash(filepath.Join(remoteRoot, "out", "validator.stderr"))
	remoteLibbpfLogPath := filepath.ToSlash(filepath.Join(remoteRoot, "out", "libbpf.log"))
	attachMode := req.AttachMode
	if attachMode == "" {
		attachMode = "best-effort"
	}
	remoteLogDir := filepath.ToSlash(filepath.Join(remoteRoot, "out"))
	runCmd := fmt.Sprintf("sudo %s --artifact %s%s%s%s --attach-mode %s --out %s --log-dir %s 2>%s; code=$?; echo \"$code\" > %s; exit 0",
		shellQuote(validatorRemotePath),
		shellQuote(artifactRemotePath),
		manifestArg,
		functionalPlanArg,
		validatorTuningArgs(req),
		shellQuote(attachMode),
		shellQuote(remoteResultPath),
		shellQuote(remoteLogDir),
		shellQuote(remoteErrPath),
		shellQuote(remoteExitPath),
	)
	if err := sshRun(ctx, target, runCmd); err != nil {
		result.InfraError = fmt.Sprintf("run validator: %v", err)
		return
	}

	localExitPath := filepath.Join(vmRunDir, "validator-exit-code")
	localErrPath := filepath.Join(vmRunDir, "validator.stderr")
	localLibbpfLogPath := filepath.Join(vmRunDir, "libbpf.log")
	if err := scpFromGuest(ctx, target, remoteExitPath, localExitPath); err == nil {
		if exitCode, parseErr := parseExitCodeFile(localExitPath); parseErr == nil {
			result.ValidatorExitCode = exitCode
		} else {
			result.Notes = append(result.Notes, fmt.Sprintf("failed to parse validator exit code: %v", parseErr))
		}
	}
	_ = scpFromGuest(ctx, target, remoteErrPath, localErrPath)
	_ = scpFromGuest(ctx, target, remoteLibbpfLogPath, localLibbpfLogPath)

	localResultPath := filepath.Join(vmRunDir, "validator-result.json")
	if err := scpFromGuest(ctx, target, remoteResultPath, localResultPath); err != nil {
		if result.ValidatorExitCode != 0 {
			result.InfraError = fmt.Sprintf("validator exited with code %d and no result.json was produced", result.ValidatorExitCode)
		} else {
			result.InfraError = err.Error()
		}
		result.Notes = append(result.Notes, fmt.Sprintf("validator stderr path: %s", localErrPath))
		return
	}

	result.Status = "pass"
	result.ValidatorResultPath = localResultPath
	result.Notes = append(result.Notes, "Validator executed inside VM and result was copied back.")
	return
}

const commandTailBytes = 4096

// guestCommandLine builds the in-guest shell line for command-mode validation.
// The user command is arbitrary shell (the artifact's own loader) run as root;
// it is single-quoted as one `bash -lc` operand and the artifact/bin/root paths
// are passed as quoted env assignments. The wrapper always exits 0 so a non-zero
// command exit is captured in the exit file rather than read as an SSH error.
func guestCommandLine(command, artifactRemotePath, binRemotePath, remoteRoot, stdoutPath, stderrPath, exitPath string) string {
	return fmt.Sprintf(
		"sudo BPFCOMPAT_ARTIFACT=%s BPFCOMPAT_BIN=%s BPFCOMPAT_REMOTE_ROOT=%s bash -lc %s >%s 2>%s; code=$?; echo \"$code\" > %s; exit 0",
		shellQuote(artifactRemotePath),
		shellQuote(binRemotePath),
		shellQuote(remoteRoot),
		shellQuote(command),
		shellQuote(stdoutPath),
		shellQuote(stderrPath),
		shellQuote(exitPath),
	)
}

// runGuestCommand performs command-mode validation inside an already-booted
// guest: it ships the optional command binary, runs req.Command as root with
// $BPFCOMPAT_ARTIFACT/$BPFCOMPAT_BIN/$BPFCOMPAT_REMOTE_ROOT exported, and
// records the command's exit code plus bounded stdout/stderr tails. A command
// that *executes* — whatever its exit code — is an infra success (Status=pass);
// the runner turns the exit code into the per-kernel compatibility verdict.
func runGuestCommand(ctx context.Context, req ExecutionRequest, target sshTarget, vmRunDir, remoteRoot, artifactRemotePath string, result *ExecutionResult) {
	result.CommandMode = true

	binRemotePath := ""
	if strings.TrimSpace(req.CommandBinary) != "" {
		binRemotePath = filepath.ToSlash(filepath.Join(remoteRoot, "bin", filepath.Base(req.CommandBinary)))
		if err := scpToGuest(ctx, target, req.CommandBinary, binRemotePath); err != nil {
			result.InfraError = err.Error()
			return
		}
		if err := sshRun(ctx, target, fmt.Sprintf("chmod +x %s", shellQuote(binRemotePath))); err != nil {
			result.InfraError = err.Error()
			return
		}
	}

	// Record the kernel the command ran against (best-effort; not fatal).
	if release, err := sshOutput(ctx, target, "uname -r"); err == nil {
		result.HostRelease = release
	}
	if machine, err := sshOutput(ctx, target, "uname -m"); err == nil {
		result.HostMachine = machine
	}

	remoteStdoutPath := filepath.ToSlash(filepath.Join(remoteRoot, "out", "command.stdout"))
	remoteStderrPath := filepath.ToSlash(filepath.Join(remoteRoot, "out", "command.stderr"))
	remoteExitPath := filepath.ToSlash(filepath.Join(remoteRoot, "out", "command-exit-code"))

	runCmd := guestCommandLine(req.Command, artifactRemotePath, binRemotePath, remoteRoot, remoteStdoutPath, remoteStderrPath, remoteExitPath)
	if err := sshRun(ctx, target, runCmd); err != nil {
		result.InfraError = fmt.Sprintf("run command: %v", err)
		return
	}

	localStdoutPath := filepath.Join(vmRunDir, "command.stdout")
	localStderrPath := filepath.Join(vmRunDir, "command.stderr")
	localExitPath := filepath.Join(vmRunDir, "command-exit-code")

	if err := scpFromGuest(ctx, target, remoteExitPath, localExitPath); err != nil {
		result.InfraError = fmt.Sprintf("retrieve command exit code: %v", err)
		return
	}
	exitCode, err := parseExitCodeFile(localExitPath)
	if err != nil {
		result.InfraError = fmt.Sprintf("parse command exit code: %v", err)
		return
	}
	result.CommandExitCode = exitCode

	_ = scpFromGuest(ctx, target, remoteStdoutPath, localStdoutPath)
	_ = scpFromGuest(ctx, target, remoteStderrPath, localStderrPath)
	result.CommandStdoutTail = readFileTail(localStdoutPath, commandTailBytes)
	result.CommandStderrTail = readFileTail(localStderrPath, commandTailBytes)

	result.Status = "pass"
	result.Notes = append(result.Notes, fmt.Sprintf("command executed inside VM (exit code %d)", exitCode))
}

// installGuestKernelAndReboot installs profile.install_kernel inside the
// guest via apt, pins it as the grub default, reboots, and relaunches QEMU
// on the same overlay. QEMU runs with -no-reboot, so the guest reboot exits
// the first QEMU process; the second boot comes up on the freshly written
// overlay with the requested kernel selected. Returns the new QEMU command;
// the caller re-establishes SSH and verifies uname -r.
//
// Debian- and RHEL-family only by validation: the release string is
// package-exact and the boot-default selection is distro specific (grub menu
// titles on Ubuntu, grubby on RHEL).
func installGuestKernelAndReboot(ctx context.Context, result *ExecutionResult, req ExecutionRequest, target sshTarget, qemuCmd *exec.Cmd,
	overlayPath, serialLogPath, qemuLogPath string, sshPort int, seedMode seedDeliveryMode, seedURL, seedDir, seedImagePath string) (*exec.Cmd, error) {
	release := req.Profile.InstallKernel

	installCmd := guestKernelInstallCmd(req.Profile.Distro, release, req.Profile.KernelPackages)
	if err := sshRun(ctx, target, installCmd); err != nil {
		return nil, fmt.Errorf("install kernel %s in guest: %w", release, err)
	}
	result.Notes = append(result.Notes, fmt.Sprintf("kernel installed in guest: %s", release))

	// The connection drops as the guest goes down; only the reboot itself
	// matters, so the ssh error is irrelevant.
	_ = sshRun(ctx, target, "sudo systemctl reboot")
	if err := waitProcessExit(qemuCmd, 3*time.Minute); err != nil {
		return nil, err
	}

	newCmd, _, err := startQEMU(ctx, req.Profile, overlayPath, serialLogPath, qemuLogPath, sshPort, seedMode, seedURL, seedDir, seedImagePath)
	if err != nil {
		return nil, fmt.Errorf("relaunch qemu after kernel install: %w", err)
	}
	result.Notes = append(result.Notes, "guest rebooted into installed kernel (qemu relaunched on same overlay)")
	return newCmd, nil
}

// guestKernelInstallCmd builds the in-guest install script. With explicit
// package URLs the .debs are fetched from the archive pool and installed via
// dpkg — required for superseded kernel releases, which stay downloadable in
// the pool but disappear from the apt indexes. Without URLs it falls back to
// apt, which only works for releases the indexes still carry. Both paths pin
// the requested release as the grub default; the dpkg path relies on the
// kernel postinst hooks for initramfs, then pins explicitly. The DPkg lock
// timeout rides out cloud-init/unattended-upgrades holding the apt lock
// right after first boot. All interpolated values are validated at profile
// load (validKernelRelease / validKernelPackageURL), so they are shell-safe.
func guestKernelInstallCmd(distro, release string, packageURLs []string) string {
	if KernelInstallFamily(distro) == KernelFamilyRHEL {
		return guestKernelInstallCmdRHEL(release, packageURLs)
	}
	return guestKernelInstallCmdDebian(release, packageURLs)
}

func guestKernelInstallCmdDebian(release string, packageURLs []string) string {
	var b strings.Builder
	b.WriteString("set -e; export DEBIAN_FRONTEND=noninteractive; ")
	if len(packageURLs) > 0 {
		b.WriteString("mkdir -p /tmp/bpfcompat-kernel; cd /tmp/bpfcompat-kernel; ")
		for i, pkg := range packageURLs {
			fmt.Fprintf(&b, "curl -fsSL --retry 2 -o pkg%02d.deb %s; ", i, shellQuote(pkg))
		}
		b.WriteString("sudo -E dpkg -i pkg*.deb; ")
	} else {
		b.WriteString("sudo -E apt-get -o DPkg::Lock::Timeout=180 -q update; ")
		fmt.Fprintf(&b, "sudo -E apt-get -o DPkg::Lock::Timeout=180 -q -y --no-install-recommends install %s; ", shellQuote("linux-image-"+release))
	}
	b.WriteString("sudo sed -i 's/^GRUB_DEFAULT=.*/GRUB_DEFAULT=saved/' /etc/default/grub; ")
	b.WriteString("sudo update-grub; ")
	fmt.Fprintf(&b, "sudo grub-set-default %s", shellQuote("Advanced options for Ubuntu>Ubuntu, with Linux "+release))
	return b.String()
}

// guestKernelInstallCmdRHEL installs a specific kernel on a RHEL-family
// guest. dnf resolves any dependency the supplied RPMs do not carry from the
// guest's enabled repositories, and grubby selects the new kernel by its
// vmlinuz path — no menu-title matching, unlike Debian's grub.
func guestKernelInstallCmdRHEL(release string, packageURLs []string) string {
	var b strings.Builder
	b.WriteString("set -e; ")
	if len(packageURLs) > 0 {
		b.WriteString("mkdir -p /tmp/bpfcompat-kernel; cd /tmp/bpfcompat-kernel; ")
		for i, pkg := range packageURLs {
			fmt.Fprintf(&b, "curl -fsSL --retry 2 -o pkg%02d.rpm %s; ", i, shellQuote(pkg))
		}
		b.WriteString("sudo dnf -y --nogpgcheck install ./pkg*.rpm; ")
	} else {
		fmt.Fprintf(&b, "sudo dnf -y install %s; ", shellQuote("kernel-core-"+release))
	}
	fmt.Fprintf(&b, "sudo grubby --set-default %s", shellQuote("/boot/vmlinuz-"+release))
	return b.String()
}

// waitProcessExit waits for the guest-initiated QEMU exit (-no-reboot turns
// the reboot into a clean process exit). The exit status is irrelevant.
func waitProcessExit(cmd *exec.Cmd, timeout time.Duration) error {
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case <-done:
		return nil
	case <-time.After(timeout):
		return fmt.Errorf("qemu did not exit within %s after guest reboot request", timeout)
	}
}

// ensureImageAvailable returns the cached image path and its sha256. The
// digest is computed once and cached in a sidecar so every run is
// attributable to exact image bytes; when the profile pins image.sha256, a
// mismatching download or cache fails the run instead of silently testing
// different bytes.
func ensureImageAvailable(profile Profile, vmRunDir string) (string, string, error) {
	basePath := profile.Image.LocalPath
	if basePath == "" {
		return "", "", fmt.Errorf("profile %q missing image.local_path", profile.ID)
	}
	basePathAbs, err := filepath.Abs(basePath)
	if err != nil {
		return "", "", fmt.Errorf("resolve image path: %w", err)
	}

	if _, err := os.Stat(basePathAbs); err != nil {
		if profile.Image.SourceURL == "" {
			return "", "", fmt.Errorf("image missing at %s and no source URL provided", basePathAbs)
		}
		if err := os.MkdirAll(filepath.Dir(basePathAbs), 0o755); err != nil {
			return "", "", fmt.Errorf("create image cache directory: %w", err)
		}
		tempPath := filepath.Join(vmRunDir, "image-download.tmp")
		if err := downloadFile(profile.Image.SourceURL, tempPath); err != nil {
			return "", "", fmt.Errorf("download image: %w", err)
		}
		if pinned := strings.TrimSpace(profile.Image.SHA256); pinned != "" {
			sum, err := fileSHA256(tempPath)
			if err != nil {
				return "", "", err
			}
			if !strings.EqualFold(sum, pinned) {
				_ = os.Remove(tempPath)
				return "", "", fmt.Errorf("image checksum mismatch for %s: got %s want %s", profile.Image.SourceURL, sum, pinned)
			}
		}
		if err := os.Rename(tempPath, basePathAbs); err != nil {
			return "", "", fmt.Errorf("cache downloaded image: %w", err)
		}
		// Invalidate any stale sidecar from a previous image at this path.
		_ = os.Remove(basePathAbs + ".sha256")
	}

	sum, err := ensureImageChecksum(basePathAbs)
	if err != nil {
		return basePathAbs, "", nil //nolint:nilerr // checksum recording is best-effort for unpinned images
	}
	if pinned := strings.TrimSpace(profile.Image.SHA256); pinned != "" && !strings.EqualFold(sum, pinned) {
		return "", "", fmt.Errorf("cached image %s checksum mismatch: got %s want %s (delete the cached file and its .sha256 sidecar to re-download)", basePathAbs, sum, pinned)
	}
	return basePathAbs, sum, nil
}

func createOverlayImage(ctx context.Context, baseImage, overlayPath string) error {
	baseFormat, err := detectImageFormat(ctx, baseImage)
	if err != nil {
		return err
	}
	cmd := exec.CommandContext(ctx, "qemu-img", "create", "-f", "qcow2", "-F", baseFormat, "-b", baseImage, overlayPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("create overlay image failed: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

func resizeOverlayImage(ctx context.Context, overlayPath, delta string) error {
	cmd := exec.CommandContext(ctx, "qemu-img", "resize", overlayPath, delta)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("resize overlay image failed: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

func detectImageFormat(ctx context.Context, baseImage string) (string, error) {
	cmd := exec.CommandContext(ctx, "qemu-img", "info", "--output=json", baseImage)
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("inspect base image format: %w", err)
	}
	var info struct {
		Format string `json:"format"`
	}
	if err := json.Unmarshal(output, &info); err != nil {
		return "", fmt.Errorf("parse base image format: %w", err)
	}
	format := strings.TrimSpace(info.Format)
	if format == "" {
		return "", fmt.Errorf("base image format is empty")
	}
	return format, nil
}

func generateSSHKeyPair(ctx context.Context, privateKeyPath string) (string, error) {
	cmd := exec.CommandContext(ctx, "ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", privateKeyPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("generate ssh key pair failed: %w: %s", err, strings.TrimSpace(string(output)))
	}
	pubPath := privateKeyPath + ".pub"
	pubRaw, err := os.ReadFile(pubPath)
	if err != nil {
		return "", fmt.Errorf("read public key: %w", err)
	}
	return strings.TrimSpace(string(pubRaw)), nil
}

func startQEMU(ctx context.Context, profile Profile, overlayPath, serialLogPath, qemuLogPath string, sshPort int, seedMode seedDeliveryMode, seedURL, seedDir, seedImagePath string) (*exec.Cmd, string, error) {
	qemuLog, err := os.Create(qemuLogPath)
	if err != nil {
		return nil, "", fmt.Errorf("create qemu log: %w", err)
	}

	args := buildQEMUArgs(profile, overlayPath, serialLogPath, sshPort, seedMode, seedURL, seedDir, seedImagePath)

	// aarch64 "virt" has no built-in firmware (unlike x86 SeaBIOS), so a UEFI
	// build must be supplied as pflash or the guest never boots. Resolve and
	// stage it next to the overlay (vmRunDir).
	if normalizeArch(profile.Arch) == "aarch64" {
		fwArgs, err := aarch64FirmwareArgs(filepath.Dir(overlayPath))
		if err != nil {
			return nil, "", err
		}
		args = append(args, fwArgs...)
	}

	qemuBinary := qemuSystemBinary(profile)
	cmd := exec.CommandContext(ctx, qemuBinary, args...)
	cmd.Stdout = qemuLog
	cmd.Stderr = qemuLog
	if err := cmd.Start(); err != nil {
		_ = qemuLog.Close()
		return nil, "", fmt.Errorf("start qemu: %w", err)
	}
	_ = qemuLog.Close()

	commandText := qemuBinary + " " + strings.Join(args, " ")
	return cmd, commandText, nil
}

// aarch64FirmwareArgs resolves a UEFI firmware pair and stages a per-VM writable
// copy of the vars store under vmRunDir, returning the QEMU pflash args. Paths
// are overridable for non-Debian layouts via BPFCOMPAT_AARCH64_UEFI_CODE /
// BPFCOMPAT_AARCH64_UEFI_VARS.
func aarch64FirmwareArgs(vmRunDir string) ([]string, error) {
	code := firstExistingPath(
		os.Getenv("BPFCOMPAT_AARCH64_UEFI_CODE"),
		"/usr/share/AAVMF/AAVMF_CODE.fd",
		"/usr/share/qemu/edk2-aarch64-code.fd",
		"/usr/share/edk2/aarch64/QEMU_EFI-silent-pflash.raw",
	)
	if code == "" {
		return nil, fmt.Errorf("aarch64 UEFI firmware not found; install qemu-efi-aarch64 or set BPFCOMPAT_AARCH64_UEFI_CODE")
	}
	varsTemplate := firstExistingPath(
		os.Getenv("BPFCOMPAT_AARCH64_UEFI_VARS"),
		"/usr/share/AAVMF/AAVMF_VARS.fd",
		"/usr/share/qemu/edk2-arm-vars.fd",
	)
	if varsTemplate == "" {
		return nil, fmt.Errorf("aarch64 UEFI vars template not found; install qemu-efi-aarch64 or set BPFCOMPAT_AARCH64_UEFI_VARS")
	}
	varsCopy := filepath.Join(vmRunDir, "AAVMF_VARS.fd")
	if err := copyRegularFile(varsTemplate, varsCopy); err != nil {
		return nil, fmt.Errorf("stage UEFI vars: %w", err)
	}
	return aarch64PflashArgs(code, varsCopy), nil
}

// aarch64PflashArgs is the pure pflash-arg shape: read-only CODE on unit 0 and a
// writable VARS store on unit 1.
func aarch64PflashArgs(codePath, varsPath string) []string {
	return []string{
		"-drive", fmt.Sprintf("if=pflash,format=raw,unit=0,readonly=on,file=%s", codePath),
		"-drive", fmt.Sprintf("if=pflash,format=raw,unit=1,file=%s", varsPath),
	}
}

func firstExistingPath(candidates ...string) string {
	for _, c := range candidates {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		if _, err := os.Stat(c); err == nil { // #nosec G703 -- operator-supplied firmware path, not untrusted input
			return c
		}
	}
	return ""
}

// copyRegularFile copies src to dst. src/dst are operator-controlled firmware
// paths (env-overridable defaults under /usr/share), not untrusted input.
func copyRegularFile(src, dst string) error {
	in, err := os.Open(src) // #nosec G703 -- operator-supplied firmware path
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst) // #nosec G703 -- staged under the run's private dir
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

func buildQEMUArgs(profile Profile, overlayPath, serialLogPath string, sshPort int, seedMode seedDeliveryMode, seedURL, seedDir, seedImagePath string) []string {
	memoryMB, cpus := boundedVMResources(profile.Boot)

	args := []string{
		"-m", fmt.Sprintf("%d", memoryMB),
		"-smp", fmt.Sprintf("%d", cpus),
		"-nic", "none",
		"-display", "none",
		"-serial", "file:" + serialLogPath,
		"-drive", fmt.Sprintf("file=%s,if=virtio,format=qcow2", overlayPath),
		"-netdev", fmt.Sprintf("user,id=n1,hostfwd=tcp:127.0.0.1:%d-:22", sshPort),
		"-device", "virtio-net-pci,netdev=n1",
	}
	args = append(qemuMachineArgs(profile), args...)
	switch seedMode {
	case seedDeliveryIgnition:
		// CoreOS reads the Ignition config from the qemu firmware config blob.
		args = append(args, "-fw_cfg", fmt.Sprintf("name=opt/com.coreos/config,file=%s", seedImagePath))
	case seedDeliveryNoCloudConfigDrive:
		args = append(args, "-drive", fmt.Sprintf("file=%s,if=ide,media=cdrom,format=raw,readonly=on", seedImagePath))
	case seedDeliveryNoCloudConfigFS:
		args = append(args,
			"-blockdev", fmt.Sprintf("driver=vvfat,node-name=seedcidata,dir=%s,label=cidata,read-only=on", seedDir),
			"-device", "virtio-blk-pci,drive=seedcidata",
		)
	default:
		args = append(args, "-smbios", fmt.Sprintf("type=1,serial=ds=nocloud-net;s=%s", seedURL))
	}
	args = append(args, "-no-reboot")
	return args
}

func qemuSystemBinary(profile Profile) string {
	switch normalizeArch(profile.Arch) {
	case "aarch64":
		return "qemu-system-aarch64"
	default:
		return "qemu-system-x86_64"
	}
}

func qemuMachineArgs(profile Profile) []string {
	guest := normalizeArch(profile.Arch)
	// KVM can only accelerate a guest whose arch matches the host: /dev/kvm on an
	// x86_64 host cannot run an aarch64 guest. Use KVM only for a same-arch guest;
	// otherwise fall back to TCG software emulation (slow but correct).
	kvm := kvmAvailable() && guest == normalizeArch(runtime.GOARCH)
	return machineArgsFor(guest, kvm)
}

// machineArgsFor is the pure acceleration decision: with KVM it pins -cpu host
// for speed; without it (e.g. some hosted runners) it degrades to TCG software
// emulation with -cpu max so results stay correct rather than the launch
// failing outright.
func machineArgsFor(arch string, kvm bool) []string {
	switch arch {
	case "aarch64":
		if kvm {
			return []string{"-machine", "virt,accel=kvm", "-cpu", "host"}
		}
		return []string{"-machine", "virt,accel=tcg", "-cpu", "max"}
	default:
		if kvm {
			return []string{"-enable-kvm", "-cpu", "host"}
		}
		return []string{"-accel", "tcg", "-cpu", "max"}
	}
}

// kvmAvailable reports whether hardware-accelerated virtualization is usable on
// this host. When /dev/kvm is missing (some CI runners), callers degrade to TCG
// software emulation rather than failing the QEMU launch outright.
func kvmAvailable() bool {
	info, err := os.Stat("/dev/kvm")
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

func normalizeArch(arch string) string {
	switch strings.ToLower(strings.TrimSpace(arch)) {
	case "arm64":
		return "aarch64"
	case "amd64":
		return "x86_64"
	default:
		return strings.ToLower(strings.TrimSpace(arch))
	}
}

// needsCIDATASeed reports whether a profile's distro needs the cloud-init seed
// delivered as a CIDATA-labelled disk/ISO rather than the NoCloud-over-SMBIOS
// network seed (the Ubuntu/Debian default). EL (RHEL/AlmaLinux/Rocky/CentOS/
// Oracle), Amazon Linux, and SUSE cloud-init configs do not reliably honour the
// SMBIOS-net seed: on EL8 cloud-init falls back to DataSourceNone and never
// authorises the injected SSH key (observed booting AlmaLinux/Rocky 8). Those
// images do read a CIDATA disk/ConfigDrive, so use that instead.
func needsCIDATASeed(profile Profile) bool {
	switch strings.ToLower(strings.TrimSpace(profile.Distro)) {
	case "rhel", "almalinux", "rocky", "centos", "centos-stream",
		"oracle", "oracle-linux", "amazon-linux", "amazonlinux",
		"sles", "suse", "opensuse":
		return true
	}
	// Keep the explicit ID for any profile that omits a recognised distro.
	return strings.EqualFold(strings.TrimSpace(profile.ID), "rhel-8-4.18")
}

func seedDeliveryForProfile(profile Profile) (seedDeliveryMode, error) {
	if isCoreOSIgnitionDistro(profile) {
		return seedDeliveryIgnition, nil
	}
	if needsCIDATASeed(profile) {
		if commandAvailable("cloud-localds") {
			return seedDeliveryNoCloudConfigDrive, nil
		}
		// The vvfat config-drive fallback is known NOT to boot RHEL-family/
		// Amazon/Oracle/SUSE guests on some hosts (0-byte serial, SSH
		// timeout) — and because the guest simply never comes up, the
		// failure surfaces 15 minutes later as an opaque SSH timeout.
		// Fail fast with the actionable fix instead; the legacy fallback
		// stays reachable behind an explicit opt-in.
		if allowVVFATSeedFallback() {
			return seedDeliveryNoCloudConfigFS, nil
		}
		return "", fmt.Errorf("profile %s needs a cloud-init cidata seed ISO but cloud-localds is not installed; "+
			"install cloud-image-utils (Debian/Ubuntu: apt-get install cloud-image-utils), "+
			"or set BPFCOMPAT_ALLOW_VVFAT_SEED=1 to try the legacy vvfat config-drive fallback "+
			"(known not to boot RHEL-family/Amazon/Oracle/SUSE guests on some hosts)", profile.ID)
	}
	return seedDeliveryNoCloudNet, nil
}

// allowVVFATSeedFallback reports whether the operator explicitly re-enabled
// the legacy vvfat config-drive seed for cidata profiles when cloud-localds
// is missing.
func allowVVFATSeedFallback() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("BPFCOMPAT_ALLOW_VVFAT_SEED"))) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

func commandAvailable(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

func createNoCloudSeedImage(ctx context.Context, seedDir, outPath string) error {
	userData := filepath.Join(seedDir, "user-data")
	metaData := filepath.Join(seedDir, "meta-data")
	cmd := exec.CommandContext(ctx, "cloud-localds", "--filesystem", "iso", outPath, userData, metaData)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("cloud-localds failed: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

func boundedVMResources(boot BootConfig) (memoryMB int, cpus int) {
	memoryMB = boot.MemoryMB
	cpus = boot.CPUs

	if memoryMB <= 0 {
		memoryMB = 1024
	}
	if cpus <= 0 {
		cpus = 1
	}

	if memoryMB > maxVMMemoryMB {
		memoryMB = maxVMMemoryMB
	}
	if cpus > maxVMCPUs {
		cpus = maxVMCPUs
	}
	return memoryMB, cpus
}

func terminateProcess(proc *os.Process) error {
	if proc == nil {
		return nil
	}
	_ = proc.Signal(syscall.SIGTERM)
	done := make(chan error, 1)
	go func() {
		_, err := proc.Wait()
		done <- err
	}()

	select {
	case <-time.After(5 * time.Second):
		_ = proc.Kill()
		return nil
	case <-done:
		return nil
	}
}

func sshUserCandidates(profile Profile) []string {
	distro := strings.ToLower(strings.TrimSpace(profile.Distro))
	candidates := make([]string, 0, 8)

	switch distro {
	case "debian":
		candidates = append(candidates, "debian")
	case "ubuntu":
		candidates = append(candidates, "ubuntu")
	case "amazon-linux", "amzn", "amzn2":
		candidates = append(candidates, "ec2-user")
	case "almalinux":
		candidates = append(candidates, "almalinux")
	case "rocky":
		candidates = append(candidates, "rocky")
	case "oracle":
		candidates = append(candidates, "opc")
	case "opensuse":
		candidates = append(candidates, "opensuse")
	case "sles":
		candidates = append(candidates, "ec2-user", "opensuse")
	case "flatcar", "fedora-coreos", "fcos", "rhcos", "rhel-coreos":
		candidates = append(candidates, "core")
	case "centos", "centos-stream", "rhel", "redhat":
		candidates = append(candidates, "cloud-user", "centos")
	}

	// Keep broad fallbacks so new profile families can still bootstrap without
	// requiring an immediate code change in this selector.
	candidates = append(candidates, "cloud-user", "ubuntu", "debian", "almalinux", "rocky", "centos", "ec2-user", "opensuse", "opc", "core", "root")

	seen := make(map[string]struct{}, len(candidates))
	deduped := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		name := strings.TrimSpace(candidate)
		if name == "" {
			continue
		}
		if _, exists := seen[name]; exists {
			continue
		}
		seen[name] = struct{}{}
		deduped = append(deduped, name)
	}
	return deduped
}
