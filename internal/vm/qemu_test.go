package vm

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBoundedVMResources(t *testing.T) {
	memoryMB, cpus := boundedVMResources(BootConfig{
		MemoryMB: 32768,
		CPUs:     16,
	})
	if memoryMB != maxVMMemoryMB {
		t.Fatalf("expected capped memory %d, got %d", maxVMMemoryMB, memoryMB)
	}
	if cpus != maxVMCPUs {
		t.Fatalf("expected capped cpus %d, got %d", maxVMCPUs, cpus)
	}
}

func TestBuildQEMUArgsDisablesDefaultNICAndUsesExplicitForward(t *testing.T) {
	profile := Profile{
		Arch: "x86_64",
		Boot: BootConfig{
			MemoryMB: 1024,
			CPUs:     1,
		},
	}

	args := buildQEMUArgs(profile, "/tmp/overlay.qcow2", "/tmp/serial.log", 2222, seedDeliveryNoCloudNet, "http://127.0.0.1:8080/", "", "")
	joined := strings.Join(args, " ")

	if !strings.Contains(joined, "-nic none") {
		t.Fatalf("expected default NICs to be disabled in args: %s", joined)
	}
	if !strings.Contains(joined, "hostfwd=tcp:127.0.0.1:2222-:22") {
		t.Fatalf("expected explicit localhost ssh hostfwd in args: %s", joined)
	}
	if !strings.Contains(joined, "ds=nocloud-net;s=http://127.0.0.1:8080/") {
		t.Fatalf("expected nocloud-net SMBIOS seed arg in args: %s", joined)
	}
}

func TestQEMUSystemBinaryForARM64(t *testing.T) {
	profile := Profile{Arch: "arm64"}
	if got := qemuSystemBinary(profile); got != "qemu-system-aarch64" {
		t.Fatalf("expected qemu-system-aarch64, got %q", got)
	}

	args := buildQEMUArgs(profile, "/tmp/overlay.qcow2", "/tmp/serial.log", 2222, seedDeliveryNoCloudNet, "http://127.0.0.1:8080/", "", "")
	joined := strings.Join(args, " ")
	if !strings.Contains(joined, "-machine virt,accel=kvm") {
		t.Fatalf("expected arm64 virt machine args: %s", joined)
	}
	if strings.Contains(joined, "-enable-kvm") {
		t.Fatalf("did not expect x86 -enable-kvm form for arm64 args: %s", joined)
	}
}

func TestBuildQEMUArgsUsesConfigFSSeedForProfilesThatNeedIt(t *testing.T) {
	profile := Profile{
		Boot: BootConfig{
			MemoryMB: 1024,
			CPUs:     1,
		},
	}

	args := buildQEMUArgs(profile, "/tmp/overlay.qcow2", "/tmp/serial.log", 2222, seedDeliveryNoCloudConfigFS, "", "/tmp/seed", "")
	joined := strings.Join(args, " ")
	if !strings.Contains(joined, "driver=vvfat") {
		t.Fatalf("expected vvfat seed blockdev in args: %s", joined)
	}
	if !strings.Contains(joined, "label=cidata") {
		t.Fatalf("expected cidata label in vvfat seed arg: %s", joined)
	}
	if strings.Contains(joined, "ds=nocloud-net") {
		t.Fatalf("did not expect nocloud-net SMBIOS seed arg for configfs mode: %s", joined)
	}
}

func TestBuildQEMUArgsUsesConfigDriveSeedImage(t *testing.T) {
	profile := Profile{
		Boot: BootConfig{
			MemoryMB: 1024,
			CPUs:     1,
		},
	}

	args := buildQEMUArgs(profile, "/tmp/overlay.qcow2", "/tmp/serial.log", 2222, seedDeliveryNoCloudConfigDrive, "", "", "/tmp/seed.iso")
	joined := strings.Join(args, " ")
	if !strings.Contains(joined, "media=cdrom") {
		t.Fatalf("expected config-drive cdrom arg in args: %s", joined)
	}
	if !strings.Contains(joined, "file=/tmp/seed.iso") {
		t.Fatalf("expected config-drive seed image path in args: %s", joined)
	}
	if strings.Contains(joined, "ds=nocloud-net") {
		t.Fatalf("did not expect nocloud-net SMBIOS seed arg for configdrive mode: %s", joined)
	}
}

func TestSSHUserCandidates(t *testing.T) {
	tests := []struct {
		name      string
		distro    string
		wantFirst string
		wantSet   []string
	}{
		{
			name:      "ubuntu",
			distro:    "ubuntu",
			wantFirst: "ubuntu",
			wantSet:   []string{"ubuntu", "cloud-user", "debian"},
		},
		{
			name:      "debian",
			distro:    "debian",
			wantFirst: "debian",
			wantSet:   []string{"debian", "cloud-user", "ubuntu"},
		},
		{
			name:      "almalinux",
			distro:    "almalinux",
			wantFirst: "almalinux",
			wantSet:   []string{"almalinux", "cloud-user"},
		},
		{
			name:      "rocky",
			distro:    "rocky",
			wantFirst: "rocky",
			wantSet:   []string{"rocky", "cloud-user"},
		},
		{
			name:      "centos-stream",
			distro:    "centos-stream",
			wantFirst: "cloud-user",
			wantSet:   []string{"cloud-user", "centos"},
		},
		{
			name:      "amazon-linux",
			distro:    "amazon-linux",
			wantFirst: "ec2-user",
			wantSet:   []string{"ec2-user", "cloud-user"},
		},
		{
			name:      "oracle",
			distro:    "oracle",
			wantFirst: "opc",
			wantSet:   []string{"opc", "cloud-user"},
		},
		{
			name:      "opensuse",
			distro:    "opensuse",
			wantFirst: "opensuse",
			wantSet:   []string{"opensuse", "cloud-user"},
		},
		{
			name:      "sles",
			distro:    "sles",
			wantFirst: "ec2-user",
			wantSet:   []string{"ec2-user", "cloud-user"},
		},
		{
			name:      "flatcar",
			distro:    "flatcar",
			wantFirst: "core",
			wantSet:   []string{"core", "cloud-user"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			candidates := sshUserCandidates(Profile{Distro: tt.distro})
			if len(candidates) == 0 {
				t.Fatalf("expected non-empty candidate list")
			}
			if candidates[0] != tt.wantFirst {
				t.Fatalf("expected first candidate %q, got %q", tt.wantFirst, candidates[0])
			}

			seen := make(map[string]struct{}, len(candidates))
			for _, c := range candidates {
				if _, exists := seen[c]; exists {
					t.Fatalf("duplicate candidate %q in %v", c, candidates)
				}
				seen[c] = struct{}{}
			}

			for _, expected := range tt.wantSet {
				if _, ok := seen[expected]; !ok {
					t.Fatalf("expected candidate %q in %v", expected, candidates)
				}
			}
		})
	}
}

func TestExecutionTransport(t *testing.T) {
	tests := []struct {
		name          string
		distro        string
		wantTransport string
		wantSupported bool
		wantInMsg     string
	}{
		{name: "ubuntu", distro: "ubuntu", wantTransport: ExecutionTransportSSH, wantSupported: true},
		{name: "rhel8 supported", distro: "rhel", wantTransport: ExecutionTransportSSH, wantSupported: true},
		{name: "talos blocked", distro: "talos", wantTransport: ExecutionTransportUnsupported, wantSupported: false, wantInMsg: "no ssh"},
		{name: "bottlerocket blocked", distro: "bottlerocket", wantTransport: ExecutionTransportUnsupported, wantSupported: false, wantInMsg: "ssh"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			transport, supported, reason := ExecutionTransport(Profile{Distro: tt.distro})
			if transport != tt.wantTransport {
				t.Fatalf("expected transport=%q, got %q", tt.wantTransport, transport)
			}
			if supported != tt.wantSupported {
				t.Fatalf("expected supported=%t, got %t (reason=%q)", tt.wantSupported, supported, reason)
			}
			if tt.wantInMsg != "" && !strings.Contains(strings.ToLower(reason), strings.ToLower(tt.wantInMsg)) {
				t.Fatalf("expected reason to contain %q, got %q", tt.wantInMsg, reason)
			}
		})
	}
}

func TestBuildVirtmeNGArgs(t *testing.T) {
	profile := Profile{
		ID:     "kernelorg-mainline-7.1-rc6",
		Runner: "virtme-ng",
		Arch:   "x86_64",
		Boot: BootConfig{
			MemoryMB: 2048,
			CPUs:     2,
		},
		VirtmeNG: VirtmeNGCfg{
			Run:       "7.1-rc6",
			ExtraArgs: []string{"--network", "user"},
		},
	}

	args := buildVirtmeNGArgs(profile, "/tmp/bpfcompat-virtme")
	joined := strings.Join(args, " ")

	for _, want := range []string{
		"--run v7.1-rc6",
		"--user root",
		"--memory 2048",
		"--cpus 2",
		"--rwdir=/tmp/bpfcompat-virtme",
		"--exec /tmp/bpfcompat-virtme/run-validator.sh",
		"--network user",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("expected %q in virtme-ng args: %s", want, joined)
		}
	}
}

func TestBuildFirecrackerConfig(t *testing.T) {
	tmpDir := t.TempDir()
	kernelPath := filepath.Join(tmpDir, "vmlinux")
	rootfsPath := filepath.Join(tmpDir, "rootfs.ext4")
	for _, path := range []string{kernelPath, rootfsPath} {
		if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
			t.Fatalf("write fixture %s: %v", path, err)
		}
	}

	cfg, err := buildFirecrackerConfig(Profile{
		ID:           "firecracker-smoke",
		Distro:       "upstream-mainline",
		Version:      "firecracker-alpha",
		KernelFamily: "6.8",
		Arch:         "x86_64",
		Runner:       "firecracker",
		Firecracker: FirecrackerCfg{
			KernelImagePath: kernelPath,
			RootfsPath:      rootfsPath,
			TapDevice:       "tap-test",
		},
		Boot: BootConfig{MemoryMB: 2048, CPUs: 2},
	}, tmpDir)
	if err != nil {
		t.Fatalf("buildFirecrackerConfig failed: %v", err)
	}

	if cfg.BootSource.KernelImagePath != kernelPath {
		t.Fatalf("kernel path = %q, want %q", cfg.BootSource.KernelImagePath, kernelPath)
	}
	if cfg.MachineConfig.VCPUCount != 2 || cfg.MachineConfig.MemSizeMiB != 2048 {
		t.Fatalf("unexpected machine config: %+v", cfg.MachineConfig)
	}
	if len(cfg.Drives) != 1 || cfg.Drives[0].PathOnHost != rootfsPath || !cfg.Drives[0].IsRootDevice {
		t.Fatalf("unexpected drive config: %+v", cfg.Drives)
	}
	if len(cfg.NetworkInterfaces) != 1 || cfg.NetworkInterfaces[0].HostDevName != "tap-test" {
		t.Fatalf("unexpected network config: %+v", cfg.NetworkInterfaces)
	}
}

func TestBuildFirecrackerConfigAllowsInitrdOnly(t *testing.T) {
	tmpDir := t.TempDir()
	kernelPath := filepath.Join(tmpDir, "vmlinux")
	initrdPath := filepath.Join(tmpDir, "initramfs.cpio.gz")
	for _, path := range []string{kernelPath, initrdPath} {
		if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
			t.Fatalf("write fixture %s: %v", path, err)
		}
	}

	cfg, err := buildFirecrackerConfig(Profile{
		ID:           "firecracker-smoke",
		Distro:       "upstream-mainline",
		Version:      "firecracker-alpha",
		KernelFamily: "6.8",
		Arch:         "x86_64",
		Runner:       "firecracker",
		Firecracker: FirecrackerCfg{
			KernelImagePath: kernelPath,
		},
		Boot: BootConfig{MemoryMB: 1024, CPUs: 1},
	}, tmpDir, initrdPath)
	if err != nil {
		t.Fatalf("buildFirecrackerConfig failed: %v", err)
	}

	if cfg.BootSource.InitrdPath != initrdPath {
		t.Fatalf("initrd path = %q, want %q", cfg.BootSource.InitrdPath, initrdPath)
	}
	if !strings.Contains(cfg.BootSource.BootArgs, "init=/init") {
		t.Fatalf("boot args missing init=/init: %q", cfg.BootSource.BootArgs)
	}
	if cfg.Drives == nil || len(cfg.Drives) != 0 {
		t.Fatalf("expected explicit empty drives, got %#v", cfg.Drives)
	}
}

func TestParseFirecrackerMarkedOutput(t *testing.T) {
	stdout := strings.Join([]string{
		"kernel noise",
		firecrackerExitBegin,
		"2",
		firecrackerExitEnd,
		firecrackerResultBegin,
		"{",
		`  "status": "fail"`,
		"}",
		firecrackerResultEnd,
		firecrackerStderrBegin,
		"validator detail",
		firecrackerStderrEnd,
	}, "\n")

	parsed, err := parseFirecrackerMarkedOutput(stdout, "")
	if err != nil {
		t.Fatalf("parseFirecrackerMarkedOutput failed: %v", err)
	}
	if parsed.ExitCode != 2 {
		t.Fatalf("exit code = %d, want 2", parsed.ExitCode)
	}
	if !json.Valid(parsed.ResultJSON) {
		t.Fatalf("expected result JSON to be valid: %s", parsed.ResultJSON)
	}
	if !strings.Contains(parsed.ValidatorStderr, "validator detail") {
		t.Fatalf("validator stderr not captured: %q", parsed.ValidatorStderr)
	}
}

func TestSeedDeliveryForProfile(t *testing.T) {
	if got := seedDeliveryForProfile(Profile{ID: "rhel-8-4.18"}); got != seedDeliveryNoCloudConfigDrive && got != seedDeliveryNoCloudConfigFS {
		t.Fatalf("expected rhel-8-4.18 seed delivery %q or %q, got %q", seedDeliveryNoCloudConfigDrive, seedDeliveryNoCloudConfigFS, got)
	}
	if got := seedDeliveryForProfile(Profile{ID: "ubuntu-22.04-5.15"}); got != seedDeliveryNoCloudNet {
		t.Fatalf("expected default seed delivery %q, got %q", seedDeliveryNoCloudNet, got)
	}
}

func TestMapFixupArgs(t *testing.T) {
	if got := mapFixupArgs(nil); got != "" {
		t.Fatalf("expected empty args for no fixups, got %q", got)
	}
	fixups := []MapFixup{
		{Name: "auxiliary_maps", MaxEntries: "cpus"},
		{Name: "ringbuf_maps", MaxEntries: "16", InnerRingbufBytes: 8388608},
	}
	want := " --set-map-max-entries auxiliary_maps=cpus" +
		" --set-map-max-entries ringbuf_maps=16" +
		" --set-map-inner-ringbuf ringbuf_maps=8388608"
	if got := mapFixupArgs(fixups); got != want {
		t.Fatalf("unexpected args:\n got %q\nwant %q", got, want)
	}
}

func TestProgVariantArgs(t *testing.T) {
	groups := []ProgVariantGroup{{
		Group: "recvmmsg_x",
		Variants: []ProgVariant{
			{Name: "recvmmsg_x", HelperID: 181},
			{Name: "recvmmsg_old_x"},
		},
	}}
	want := " --prog-variants recvmmsg_x=recvmmsg_x:181,recvmmsg_old_x:0"
	if got := progVariantArgs(groups); got != want {
		t.Fatalf("unexpected args:\n got %q\nwant %q", got, want)
	}
}
