package vm

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
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
	ProgVariants       []ProgVariantGroup
	ProbeCompanions    []string
	ValidatorBinary    string
	AttachMode         string
	Timeout            time.Duration
	KeepVMOnFailure    bool
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
}

func mapFixupArgs(fixups []MapFixup) string {
	var b strings.Builder
	for _, fixup := range fixups {
		if fixup.MaxEntries != "" {
			fmt.Fprintf(&b, " --set-map-max-entries %s=%s", fixup.Name, fixup.MaxEntries)
		}
		if fixup.InnerRingbufBytes > 0 {
			fmt.Fprintf(&b, " --set-map-inner-ringbuf %s=%d", fixup.Name, fixup.InnerRingbufBytes)
		}
	}
	return b.String()
}

func progVariantArgs(groups []ProgVariantGroup) string {
	var b strings.Builder
	for _, group := range groups {
		fmt.Fprintf(&b, " --prog-variants %s=", group.Group)
		for i, variant := range group.Variants {
			if i > 0 {
				b.WriteByte(',')
			}
			if variant.TrialProbe {
				fmt.Fprintf(&b, "%s:trial", variant.Name)
			} else {
				fmt.Fprintf(&b, "%s:%d", variant.Name, variant.HelperID)
			}
		}
	}
	return b.String()
}

// validatorTuningArgs renders all manifest-declared loader-contract flags
// (map fixups, program variant groups) for the in-guest validator command.
func validatorTuningArgs(req ExecutionRequest) string {
	args := mapFixupArgs(req.MapFixups) + progVariantArgs(req.ProgVariants)
	if len(req.ProbeCompanions) > 0 {
		args += " --probe-companions " + strings.Join(req.ProbeCompanions, ",")
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

	baseImagePath, err := ensureImageAvailable(req.Profile, vmRunDir)
	if err != nil {
		result.InfraError = err.Error()
		return
	}

	overlayPath := filepath.Join(vmRunDir, "overlay.qcow2")
	if err := createOverlayImage(ctx, baseImagePath, overlayPath); err != nil {
		result.InfraError = err.Error()
		return
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

	seedDir := filepath.Join(vmRunDir, "seed")
	if err := writeNoCloudSeed(seedDir, req.Profile.ID, publicKey); err != nil {
		result.InfraError = err.Error()
		return
	}

	seedMode := seedDeliveryForProfile(req.Profile)
	seedURL := ""
	seedImagePath := ""
	seedDirAbs, err := filepath.Abs(seedDir)
	if err != nil {
		result.InfraError = fmt.Sprintf("resolve seed directory: %v", err)
		return
	}
	switch seedMode {
	case seedDeliveryNoCloudConfigDrive:
		seedImagePath = filepath.Join(vmRunDir, "seed-cidata.iso")
		if err := createNoCloudSeedImage(ctx, seedDir, seedImagePath); err != nil {
			result.InfraError = fmt.Sprintf("create NoCloud seed image: %v", err)
			return
		}
		result.Notes = append(result.Notes, "seed delivery: local NoCloud config drive image (cloud-localds)")
	case seedDeliveryNoCloudConfigFS:
		result.Notes = append(result.Notes, "seed delivery: local NoCloud config drive (vvfat, label=cidata)")
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

	remoteRoot := "/tmp/bpfcompat"
	if err := sshRun(ctx, target, fmt.Sprintf("mkdir -p %s/bin %s/input %s/out", remoteRoot, remoteRoot, remoteRoot)); err != nil {
		result.InfraError = err.Error()
		return
	}

	artifactRemotePath := filepath.ToSlash(filepath.Join(remoteRoot, "input", filepath.Base(req.ArtifactPath)))
	if err := scpToGuest(ctx, target, req.ArtifactPath, artifactRemotePath); err != nil {
		result.InfraError = err.Error()
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
		manifestArg = fmt.Sprintf(" --manifest %s", manifestRemotePath)
	}

	functionalPlanArg := ""
	if req.FunctionalPlanPath != "" {
		functionalPlanRemotePath := filepath.ToSlash(filepath.Join(remoteRoot, "input", filepath.Base(req.FunctionalPlanPath)))
		if err := scpToGuest(ctx, target, req.FunctionalPlanPath, functionalPlanRemotePath); err != nil {
			result.InfraError = err.Error()
			return
		}
		functionalPlanArg = fmt.Sprintf(" --functional-plan %s", functionalPlanRemotePath)
	}

	remoteResultPath := filepath.ToSlash(filepath.Join(remoteRoot, "out", "result.json"))
	remoteExitPath := filepath.ToSlash(filepath.Join(remoteRoot, "out", "validator-exit-code"))
	remoteErrPath := filepath.ToSlash(filepath.Join(remoteRoot, "out", "validator.stderr"))
	remoteLibbpfLogPath := filepath.ToSlash(filepath.Join(remoteRoot, "out", "libbpf.log"))
	attachMode := req.AttachMode
	if attachMode == "" {
		attachMode = "best-effort"
	}
	runCmd := fmt.Sprintf("sudo %s --artifact %s%s%s%s --attach-mode %s --out %s --log-dir %s/out 2>%s; code=$?; echo \"$code\" > %s; exit 0",
		validatorRemotePath,
		artifactRemotePath,
		manifestArg,
		functionalPlanArg,
		validatorTuningArgs(req),
		attachMode,
		remoteResultPath,
		remoteRoot,
		remoteErrPath,
		remoteExitPath,
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

func ensureImageAvailable(profile Profile, vmRunDir string) (string, error) {
	basePath := profile.Image.LocalPath
	if basePath == "" {
		return "", fmt.Errorf("profile %q missing image.local_path", profile.ID)
	}
	basePathAbs, err := filepath.Abs(basePath)
	if err != nil {
		return "", fmt.Errorf("resolve image path: %w", err)
	}

	if _, err := os.Stat(basePathAbs); err == nil {
		return basePathAbs, nil
	}
	if profile.Image.SourceURL == "" {
		return "", fmt.Errorf("image missing at %s and no source URL provided", basePathAbs)
	}

	if err := os.MkdirAll(filepath.Dir(basePathAbs), 0o755); err != nil {
		return "", fmt.Errorf("create image cache directory: %w", err)
	}
	tempPath := filepath.Join(vmRunDir, "image-download.tmp")
	if err := downloadFile(profile.Image.SourceURL, tempPath); err != nil {
		return "", fmt.Errorf("download image: %w", err)
	}
	if err := os.Rename(tempPath, basePathAbs); err != nil {
		return "", fmt.Errorf("cache downloaded image: %w", err)
	}
	return basePathAbs, nil
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
	switch normalizeArch(profile.Arch) {
	case "aarch64":
		return []string{"-machine", "virt,accel=kvm", "-cpu", "host"}
	default:
		return []string{"-enable-kvm", "-cpu", "host"}
	}
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

func seedDeliveryForProfile(profile Profile) seedDeliveryMode {
	switch strings.ToLower(strings.TrimSpace(profile.ID)) {
	case "rhel-8-4.18":
		if commandAvailable("cloud-localds") {
			return seedDeliveryNoCloudConfigDrive
		}
		return seedDeliveryNoCloudConfigFS
	default:
		return seedDeliveryNoCloudNet
	}
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
	case "flatcar":
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
