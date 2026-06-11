package vm

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const firecrackerRunner = "firecracker"
const (
	firecrackerResultBegin = "BPFCOMPAT_FIRECRACKER_RESULT_BEGIN"
	firecrackerResultEnd   = "BPFCOMPAT_FIRECRACKER_RESULT_END"
	firecrackerExitBegin   = "BPFCOMPAT_FIRECRACKER_EXIT_CODE_BEGIN"
	firecrackerExitEnd     = "BPFCOMPAT_FIRECRACKER_EXIT_CODE_END"
	firecrackerStderrBegin = "BPFCOMPAT_FIRECRACKER_STDERR_BEGIN"
	firecrackerStderrEnd   = "BPFCOMPAT_FIRECRACKER_STDERR_END"
)

type firecrackerConfig struct {
	BootSource        firecrackerBootSource         `json:"boot-source"`
	Drives            []firecrackerDrive            `json:"drives"`
	MachineConfig     firecrackerMachineConfig      `json:"machine-config"`
	NetworkInterfaces []firecrackerNetworkInterface `json:"network-interfaces,omitempty"`
	Logger            *firecrackerLogger            `json:"logger,omitempty"`
}

type firecrackerBootSource struct {
	KernelImagePath string `json:"kernel_image_path"`
	InitrdPath      string `json:"initrd_path,omitempty"`
	BootArgs        string `json:"boot_args"`
}

type firecrackerDrive struct {
	DriveID      string `json:"drive_id"`
	PathOnHost   string `json:"path_on_host"`
	IsRootDevice bool   `json:"is_root_device"`
	IsReadOnly   bool   `json:"is_read_only"`
}

type firecrackerMachineConfig struct {
	VCPUCount  int  `json:"vcpu_count"`
	MemSizeMiB int  `json:"mem_size_mib"`
	SMT        bool `json:"smt"`
}

type firecrackerNetworkInterface struct {
	IfaceID     string `json:"iface_id"`
	GuestMAC    string `json:"guest_mac"`
	HostDevName string `json:"host_dev_name"`
}

type firecrackerLogger struct {
	LogPath       string `json:"log_path"`
	Level         string `json:"level"`
	ShowLevel     bool   `json:"show_level"`
	ShowLogOrigin bool   `json:"show_log_origin"`
}

func ExecuteFirecrackerProfile(ctx context.Context, req ExecutionRequest) (result ExecutionResult) {
	startedAt := time.Now().UTC()
	result = ExecutionResult{
		ProfileID: req.Profile.ID,
		Status:    "infra_error",
		StartedAt: startedAt,
	}
	defer func() {
		result.FinishedAt = time.Now().UTC()
	}()

	if !strings.EqualFold(strings.TrimSpace(req.Profile.Runner), firecrackerRunner) {
		result.InfraError = fmt.Sprintf("profile %q is not a firecracker profile", req.Profile.ID)
		return
	}

	vmRunDir := filepath.Join(req.RunDir, "targets", req.Profile.ID)
	if err := os.MkdirAll(vmRunDir, 0o755); err != nil {
		result.InfraError = fmt.Sprintf("create firecracker run directory: %v", err)
		return
	}
	result.VMRunDir = vmRunDir

	firecrackerPath, err := firecrackerExecutable()
	if err != nil {
		result.InfraError = "firecracker executable not found; install an official Firecracker release binary before using --runner firecracker"
		return
	}

	if _, err := os.Stat("/dev/kvm"); err != nil {
		result.InfraError = fmt.Sprintf("firecracker requires /dev/kvm: %v", err)
		return
	}

	initrdPath, err := buildFirecrackerInitrd(ctx, req, vmRunDir)
	if err != nil {
		result.InfraError = err.Error()
		return
	}
	result.Notes = append(result.Notes, fmt.Sprintf("firecracker generated initrd: %s", initrdPath))

	cfg, err := buildFirecrackerConfig(req.Profile, vmRunDir, initrdPath)
	if err != nil {
		result.InfraError = err.Error()
		return
	}

	configPath := filepath.Join(vmRunDir, "firecracker-config.json")
	configData, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		result.InfraError = fmt.Sprintf("marshal firecracker config: %v", err)
		return
	}
	if err := os.WriteFile(configPath, append(configData, '\n'), 0o600); err != nil {
		result.InfraError = fmt.Sprintf("write firecracker config: %v", err)
		return
	}
	result.Notes = append(result.Notes, fmt.Sprintf("firecracker config: %s", configPath))

	consoleLogPath := filepath.Join(vmRunDir, "firecracker-console.log")
	result.SerialLogPath = consoleLogPath
	result.QEMUCommand = firecrackerPath + " --api-sock " + filepath.Join(vmRunDir, "firecracker.sock") + " --config-file " + configPath

	runOutput, err := runFirecrackerWithMarkers(ctx, firecrackerPath, configPath, vmRunDir, consoleLogPath, req.Timeout)
	if err != nil {
		result.InfraError = err.Error()
		result.Notes = append(result.Notes, fmt.Sprintf("firecracker console log: %s", consoleLogPath))
		return
	}
	result.ValidatorExitCode = runOutput.ExitCode

	localErrPath := filepath.Join(vmRunDir, "validator.stderr")
	_ = os.WriteFile(localErrPath, []byte(runOutput.ValidatorStderr), 0o600)

	localResultPath := filepath.Join(vmRunDir, "validator-result.json")
	if !json.Valid(runOutput.ResultJSON) {
		result.InfraError = "firecracker validator result marker did not contain valid JSON"
		result.Notes = append(result.Notes, fmt.Sprintf("firecracker console log: %s", consoleLogPath))
		return
	}
	if err := os.WriteFile(localResultPath, runOutput.ResultJSON, 0o600); err != nil {
		result.InfraError = fmt.Sprintf("write firecracker validator result: %v", err)
		return
	}

	result.Status = "pass"
	result.ValidatorResultPath = localResultPath
	result.Notes = append(result.Notes, "Validator executed inside Firecracker microVM and result was copied back over serial markers.")
	return
}

func firecrackerExecutable() (string, error) {
	if explicit := strings.TrimSpace(os.Getenv("BPFCOMPAT_FIRECRACKER_BIN")); explicit != "" {
		if _, err := os.Stat(explicit); err != nil {
			return "", err
		}
		return explicit, nil
	}
	if path, err := exec.LookPath("firecracker"); err == nil {
		return path, nil
	}
	localPath := filepath.Join("bin", "firecracker")
	if _, err := os.Stat(localPath); err != nil {
		return "", err
	}
	return localPath, nil
}

func buildFirecrackerConfig(profile Profile, runDir string, generatedInitrdPath ...string) (firecrackerConfig, error) {
	kernelPath, err := requiredAbsPath(profile.Firecracker.KernelImagePath, "firecracker kernel image")
	if err != nil {
		return firecrackerConfig{}, err
	}

	rootfsPath := ""
	if strings.TrimSpace(profile.Firecracker.RootfsPath) != "" {
		rootfsPath, err = requiredAbsPath(profile.Firecracker.RootfsPath, "firecracker rootfs")
		if err != nil {
			return firecrackerConfig{}, err
		}
	}

	initrdSource := strings.TrimSpace(profile.Firecracker.InitrdPath)
	if len(generatedInitrdPath) > 0 && strings.TrimSpace(generatedInitrdPath[0]) != "" {
		initrdSource = strings.TrimSpace(generatedInitrdPath[0])
	}
	initrdPath := ""
	if initrdSource != "" {
		initrdPath, err = requiredAbsPath(initrdSource, "firecracker initrd")
		if err != nil {
			return firecrackerConfig{}, err
		}
	}

	memoryMB, cpus := boundedVMResources(profile.Boot)
	bootArgs := strings.TrimSpace(profile.Firecracker.BootArgs)
	if bootArgs == "" {
		bootArgs = "console=ttyS0 reboot=k panic=1 pci=off init=/init"
	} else if !strings.Contains(bootArgs, "init=") {
		bootArgs += " init=/init"
	}

	cfg := firecrackerConfig{
		BootSource: firecrackerBootSource{
			KernelImagePath: kernelPath,
			InitrdPath:      initrdPath,
			BootArgs:        bootArgs,
		},
		MachineConfig: firecrackerMachineConfig{
			VCPUCount:  cpus,
			MemSizeMiB: memoryMB,
			SMT:        false,
		},
		Drives: []firecrackerDrive{},
		Logger: &firecrackerLogger{
			LogPath:       filepath.Join(runDir, "firecracker.log"),
			Level:         "Info",
			ShowLevel:     true,
			ShowLogOrigin: true,
		},
	}
	if rootfsPath != "" {
		cfg.Drives = append(cfg.Drives, firecrackerDrive{
			DriveID:      "rootfs",
			PathOnHost:   rootfsPath,
			IsRootDevice: true,
			IsReadOnly:   false,
		})
	}
	if strings.TrimSpace(profile.Firecracker.TapDevice) != "" {
		guestMAC := strings.TrimSpace(profile.Firecracker.GuestMAC)
		if guestMAC == "" {
			guestMAC = "06:00:AC:10:00:02"
		}
		cfg.NetworkInterfaces = append(cfg.NetworkInterfaces, firecrackerNetworkInterface{
			IfaceID:     "net1",
			GuestMAC:    guestMAC,
			HostDevName: strings.TrimSpace(profile.Firecracker.TapDevice),
		})
	}
	return cfg, nil
}

type firecrackerRunOutput struct {
	ResultJSON      []byte
	ValidatorStderr string
	ExitCode        int
}

type firecrackerLine struct {
	stream string
	text   string
}

func buildFirecrackerInitrd(ctx context.Context, req ExecutionRequest, vmRunDir string) (string, error) {
	if _, err := exec.LookPath("cpio"); err != nil {
		return "", fmt.Errorf("build firecracker initrd: missing cpio")
	}
	if _, err := exec.LookPath("gzip"); err != nil {
		return "", fmt.Errorf("build firecracker initrd: missing gzip")
	}

	busyboxPath, err := busyboxExecutable()
	if err != nil {
		return "", err
	}

	rootDir := filepath.Join(vmRunDir, "initrd-root")
	if err := os.RemoveAll(rootDir); err != nil {
		return "", fmt.Errorf("reset firecracker initrd root: %w", err)
	}
	for _, dir := range []string{
		filepath.Join(rootDir, "bin"),
		filepath.Join(rootDir, "dev"),
		filepath.Join(rootDir, "proc"),
		filepath.Join(rootDir, "sys"),
		filepath.Join(rootDir, "tmp"),
		filepath.Join(rootDir, "bpfcompat", "bin"),
		filepath.Join(rootDir, "bpfcompat", "input"),
		filepath.Join(rootDir, "bpfcompat", "out"),
	} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return "", fmt.Errorf("create firecracker initrd directory: %w", err)
		}
	}

	busyboxDst := filepath.Join(rootDir, "bin", "busybox")
	if err := copyFile(busyboxPath, busyboxDst, 0o755); err != nil {
		return "", fmt.Errorf("stage busybox for firecracker initrd: %w", err)
	}
	for _, applet := range []string{
		"sh", "mount", "umount", "mkdir", "mknod", "cat", "echo", "sleep",
		"poweroff", "reboot", "halt", "true", "false", "printf", "grep",
		"timeout", "uname", "cut", "sed", "awk", "ls", "ln", "rm", "cp", "sync",
	} {
		linkPath := filepath.Join(rootDir, "bin", applet)
		if err := os.Symlink("busybox", linkPath); err != nil && !os.IsExist(err) {
			return "", fmt.Errorf("create busybox applet symlink %s: %w", applet, err)
		}
	}

	if err := copyFile(req.ValidatorBinary, filepath.Join(rootDir, "bpfcompat", "bin", "bpfcompat-validator"), 0o755); err != nil {
		return "", fmt.Errorf("stage validator for firecracker initrd: %w", err)
	}
	if err := copyFile(req.ArtifactPath, filepath.Join(rootDir, "bpfcompat", "input", "artifact.bpf.o"), 0o644); err != nil {
		return "", fmt.Errorf("stage artifact for firecracker initrd: %w", err)
	}

	manifestArg := ""
	if strings.TrimSpace(req.ManifestPath) != "" {
		if err := copyFile(req.ManifestPath, filepath.Join(rootDir, "bpfcompat", "input", "manifest.yaml"), 0o644); err != nil {
			return "", fmt.Errorf("stage manifest for firecracker initrd: %w", err)
		}
		manifestArg = " --manifest /bpfcompat/input/manifest.yaml"
	}

	functionalPlanArg := ""
	if strings.TrimSpace(req.FunctionalPlanPath) != "" {
		if err := copyFile(req.FunctionalPlanPath, filepath.Join(rootDir, "bpfcompat", "input", "functional-plan.json"), 0o644); err != nil {
			return "", fmt.Errorf("stage functional plan for firecracker initrd: %w", err)
		}
		functionalPlanArg = " --functional-plan /bpfcompat/input/functional-plan.json"
	}

	attachMode := shellSafeWord(req.AttachMode)
	//nolint:dupword // mount syntax intentionally repeats fs names, e.g. "proc proc /proc".
	initScript := fmt.Sprintf(`#!/bin/sh
set +e
PATH=/bin
mkdir -p /dev /proc /sys /tmp /sys/kernel /sys/kernel/tracing /sys/kernel/debug /sys/fs /sys/fs/bpf /bpfcompat/out
mknod -m 666 /dev/null c 1 3
mount -t devtmpfs devtmpfs /dev 2>/dev/null || true
mount -t proc proc /proc 2>/dev/null || true
mount -t sysfs sysfs /sys 2>/dev/null || true
mount -t debugfs debugfs /sys/kernel/debug 2>/dev/null || true
mount -t tracefs tracefs /sys/kernel/tracing 2>/dev/null || true
mount -t bpf bpf /sys/fs/bpf 2>/dev/null || true

/bpfcompat/bin/bpfcompat-validator --artifact /bpfcompat/input/artifact.bpf.o%s%s%s --attach-mode %s --out /bpfcompat/out/result.json --log-dir /bpfcompat/out 2>/bpfcompat/out/validator.stderr
code=$?
echo "$code" >/bpfcompat/out/validator-exit-code

echo %s
if [ -f /bpfcompat/out/validator-exit-code ]; then cat /bpfcompat/out/validator-exit-code; else echo 255; fi
echo %s
echo %s
if [ -f /bpfcompat/out/result.json ]; then cat /bpfcompat/out/result.json; else echo '{"status":"error","load_status":"error","load_error_message":"validator result missing"}'; fi
echo %s
echo %s
if [ -f /bpfcompat/out/validator.stderr ]; then cat /bpfcompat/out/validator.stderr; fi
echo %s

sync
poweroff -f 2>/dev/null || reboot -f 2>/dev/null || halt -f 2>/dev/null
while true; do sleep 1; done
`,
		manifestArg,
		functionalPlanArg,
		validatorTuningArgs(req),
		attachMode,
		firecrackerExitBegin,
		firecrackerExitEnd,
		firecrackerResultBegin,
		firecrackerResultEnd,
		firecrackerStderrBegin,
		firecrackerStderrEnd,
	)
	initPath := filepath.Join(rootDir, "init")
	if err := os.WriteFile(initPath, []byte(initScript), 0o600); err != nil {
		return "", fmt.Errorf("write firecracker init script: %w", err)
	}
	if err := os.Chmod(initPath, 0o700); err != nil {
		return "", fmt.Errorf("chmod firecracker init script: %w", err)
	}

	initrdPath := filepath.Join(vmRunDir, "initramfs.cpio.gz")
	initrdAbsPath, err := filepath.Abs(initrdPath)
	if err != nil {
		return "", fmt.Errorf("resolve firecracker initrd path: %w", err)
	}
	cmd := exec.CommandContext(ctx, "sh", "-c", `find . -print0 | cpio --null -o -H newc 2>/dev/null | gzip -9 > "$1"`, "build-firecracker-initrd", initrdAbsPath)
	cmd.Dir = rootDir
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("build firecracker initrd failed: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return initrdAbsPath, nil
}

func busyboxExecutable() (string, error) {
	if explicit := strings.TrimSpace(os.Getenv("BPFCOMPAT_BUSYBOX_BIN")); explicit != "" {
		if _, err := os.Stat(explicit); err != nil {
			return "", fmt.Errorf("busybox executable missing at %s: %w", explicit, err)
		}
		return explicit, nil
	}
	if path, err := exec.LookPath("busybox"); err == nil {
		return path, nil
	}
	for _, candidate := range []string{"/usr/bin/busybox", "/bin/busybox"} {
		if _, err := os.Stat(candidate); err == nil {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("busybox executable not found; Firecracker initrd transport requires a static busybox")
}

func runFirecrackerWithMarkers(ctx context.Context, firecrackerPath, configPath, vmRunDir, consoleLogPath string, timeout time.Duration) (firecrackerRunOutput, error) {
	if timeout <= 0 {
		timeout = 5 * time.Minute
	}

	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	apiSock := filepath.Join(vmRunDir, "firecracker.sock")
	_ = os.Remove(apiSock)
	cmd := exec.CommandContext(runCtx, firecrackerPath, "--api-sock", apiSock, "--config-file", configPath)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return firecrackerRunOutput{}, fmt.Errorf("open firecracker stdout pipe: %w", err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return firecrackerRunOutput{}, fmt.Errorf("open firecracker stderr pipe: %w", err)
	}

	consoleLog, err := os.Create(consoleLogPath)
	if err != nil {
		return firecrackerRunOutput{}, fmt.Errorf("create firecracker console log: %w", err)
	}
	defer consoleLog.Close()

	if err := cmd.Start(); err != nil {
		return firecrackerRunOutput{}, fmt.Errorf("start firecracker: %w", err)
	}

	lines := make(chan firecrackerLine, 128)
	var scanWG sync.WaitGroup
	scanWG.Add(2)
	go scanFirecrackerPipe(stdout, "stdout", lines, &scanWG)
	go scanFirecrackerPipe(stderr, "stderr", lines, &scanWG)

	waitCh := make(chan error, 1)
	go func() {
		waitErr := cmd.Wait()
		waitCh <- waitErr
		scanWG.Wait()
		close(lines)
	}()

	var stdoutBuf bytes.Buffer
	var stderrBuf bytes.Buffer
	markerSeen := false
	signaled := false
	waitChOpen := true
	var waitErr error
	runDone := runCtx.Done()
	timedOut := false

	for {
		select {
		case line, ok := <-lines:
			if !ok {
				if timedOut && !markerSeen {
					return firecrackerRunOutput{}, fmt.Errorf("firecracker timed out after %s before validator result markers were observed", timeout)
				}
				if !markerSeen && waitErr != nil {
					return firecrackerRunOutput{}, fmt.Errorf("run firecracker: %w", waitErr)
				}
				return parseFirecrackerMarkedOutput(stdoutBuf.String(), stderrBuf.String())
			}
			if line.stream == "stdout" {
				stdoutBuf.WriteString(line.text)
				stdoutBuf.WriteByte('\n')
			} else {
				stderrBuf.WriteString(line.text)
				stderrBuf.WriteByte('\n')
			}
			_, _ = fmt.Fprintf(consoleLog, "[%s] %s\n", line.stream, line.text)
			if line.text == firecrackerResultEnd && !signaled {
				markerSeen = true
				signaled = true
				_ = cmd.Process.Signal(syscall.SIGTERM)
				time.AfterFunc(2*time.Second, func() {
					_ = cmd.Process.Kill()
				})
			}
		case err := <-waitCh:
			if waitChOpen {
				waitErr = err
				waitChOpen = false
				waitCh = nil
			}
		case <-runDone:
			if !signaled {
				signaled = true
				_ = cmd.Process.Kill()
			}
			timedOut = true
			runDone = nil
		}
	}
}

func scanFirecrackerPipe(r io.Reader, stream string, lines chan<- firecrackerLine, wg *sync.WaitGroup) {
	defer wg.Done()
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 64*1024), 16*1024*1024)
	for scanner.Scan() {
		lines <- firecrackerLine{stream: stream, text: strings.TrimRight(scanner.Text(), "\r")}
	}
	if err := scanner.Err(); err != nil {
		lines <- firecrackerLine{stream: stream, text: fmt.Sprintf("scanner error: %v", err)}
	}
}

func parseFirecrackerMarkedOutput(stdoutText, stderrText string) (firecrackerRunOutput, error) {
	resultText, ok := extractFirecrackerMarkerBlock(stdoutText, firecrackerResultBegin, firecrackerResultEnd)
	if !ok {
		return firecrackerRunOutput{}, fmt.Errorf("firecracker validator result markers not found")
	}
	resultText = strings.TrimSpace(resultText)
	if resultText == "" {
		return firecrackerRunOutput{}, fmt.Errorf("firecracker validator result marker was empty")
	}

	exitCode := 0
	if exitText, ok := extractFirecrackerMarkerBlock(stdoutText, firecrackerExitBegin, firecrackerExitEnd); ok {
		parsed, err := strconv.Atoi(strings.TrimSpace(exitText))
		if err != nil {
			return firecrackerRunOutput{}, fmt.Errorf("parse firecracker validator exit code: %w", err)
		}
		exitCode = parsed
	}

	validatorStderr, _ := extractFirecrackerMarkerBlock(stdoutText, firecrackerStderrBegin, firecrackerStderrEnd)
	if strings.TrimSpace(validatorStderr) == "" && strings.TrimSpace(stderrText) != "" {
		validatorStderr = stderrText
	}

	return firecrackerRunOutput{
		ResultJSON:      []byte(resultText),
		ValidatorStderr: validatorStderr,
		ExitCode:        exitCode,
	}, nil
}

func extractFirecrackerMarkerBlock(text, begin, end string) (string, bool) {
	inBlock := false
	lines := make([]string, 0)
	for _, rawLine := range strings.Split(text, "\n") {
		line := strings.TrimRight(rawLine, "\r")
		if line == begin {
			inBlock = true
			lines = lines[:0]
			continue
		}
		if inBlock && line == end {
			return strings.Join(lines, "\n"), true
		}
		if inBlock {
			lines = append(lines, line)
		}
	}
	return "", false
}

func requiredAbsPath(pathValue, label string) (string, error) {
	pathValue = strings.TrimSpace(pathValue)
	if pathValue == "" {
		return "", fmt.Errorf("%s path is required", label)
	}
	absPath, err := filepath.Abs(pathValue)
	if err != nil {
		return "", fmt.Errorf("resolve %s path: %w", label, err)
	}
	if _, err := os.Stat(absPath); err != nil {
		return "", fmt.Errorf("%s missing at %s: %w", label, absPath, err)
	}
	return absPath, nil
}
