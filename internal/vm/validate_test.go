package vm

import "testing"

func TestValidateProfileRequiresIdentityAndBoot(t *testing.T) {
	_, err := LoadProfile("does-not-exist.yaml")
	if err == nil {
		t.Fatal("expected load failure for missing profile")
	}
}

func TestValidateProfileAllowsVirtmeNGWithoutCloudImage(t *testing.T) {
	profile := Profile{
		ID:           "kernelorg-stable-7.0.11",
		Distro:       "kernel.org",
		Version:      "stable",
		KernelFamily: "7.0.11",
		Arch:         "x86_64",
		Runner:       "virtme-ng",
		VirtmeNG:     VirtmeNGCfg{Run: "v7.0.11"},
		Boot:         BootConfig{MemoryMB: 2048, CPUs: 2},
		Validator:    ValidatorCfg{Path: "/bpfcompat/bin/bpfcompat-validator"},
	}

	if err := ValidateProfile(profile); err != nil {
		t.Fatalf("expected virtme-ng profile without cloud image to validate, got %v", err)
	}
}

func TestValidateProfileRequiresVirtmeNGRun(t *testing.T) {
	profile := Profile{
		ID:           "kernelorg-stable",
		Distro:       "kernel.org",
		Version:      "stable",
		KernelFamily: "stable",
		Arch:         "x86_64",
		Runner:       "virtme-ng",
		Boot:         BootConfig{MemoryMB: 2048, CPUs: 2},
		Validator:    ValidatorCfg{Path: "/bpfcompat/bin/bpfcompat-validator"},
	}

	if err := ValidateProfile(profile); err == nil {
		t.Fatal("expected virtme-ng profile without virtme_ng.run to fail")
	}
}

func TestValidateProfileAllowsFirecrackerWithGeneratedInitrd(t *testing.T) {
	profile := Profile{
		ID:           "firecracker-upstream-6.8",
		Distro:       "upstream-mainline",
		Version:      "firecracker-alpha",
		KernelFamily: "6.8",
		Arch:         "x86_64",
		Runner:       "firecracker",
		Firecracker: FirecrackerCfg{
			KernelImagePath: "/tmp/vmlinux",
		},
		Boot:      BootConfig{MemoryMB: 1024, CPUs: 1},
		Validator: ValidatorCfg{Path: "/bpfcompat/bin/bpfcompat-validator"},
	}

	if err := ValidateProfile(profile); err != nil {
		t.Fatalf("expected firecracker generated-initrd profile to validate, got %v", err)
	}
}

func TestValidateProfileRequiresFirecrackerKernel(t *testing.T) {
	profile := Profile{
		ID:           "firecracker-upstream",
		Distro:       "upstream-mainline",
		Version:      "firecracker-alpha",
		KernelFamily: "6.8",
		Arch:         "x86_64",
		Runner:       "firecracker",
		Boot:         BootConfig{MemoryMB: 1024, CPUs: 1},
		Validator:    ValidatorCfg{Path: "/bpfcompat/bin/bpfcompat-validator"},
	}

	if err := ValidateProfile(profile); err == nil {
		t.Fatal("expected firecracker profile without kernel image to fail")
	}
}

func ubuntuVMProfile() Profile {
	return Profile{
		ID:           "ubuntu-22.04-5.15",
		Distro:       "ubuntu",
		Version:      "22.04",
		KernelFamily: "5.15",
		Arch:         "x86_64",
		Image:        ImageConfig{SourceURL: "https://example.com/jammy.img", LocalPath: "vm/cache/jammy.qcow2"},
		Boot:         BootConfig{MemoryMB: 1024, CPUs: 1},
		Validator:    ValidatorCfg{Path: "/usr/local/bin/bpfcompat-validator"},
	}
}

func TestValidateProfileInstallKernel(t *testing.T) {
	profile := ubuntuVMProfile()
	profile.InstallKernel = "5.15.0-118-generic"
	if err := ValidateProfile(profile); err != nil {
		t.Fatalf("valid install_kernel rejected: %v", err)
	}

	nonUbuntu := ubuntuVMProfile()
	nonUbuntu.Distro = "debian"
	nonUbuntu.InstallKernel = "6.1.0-30-cloud-amd64"
	if err := ValidateProfile(nonUbuntu); err == nil {
		t.Fatal("expected install_kernel on non-ubuntu profile to fail")
	}

	virtme := ubuntuVMProfile()
	virtme.Runner = "virtme-ng"
	virtme.VirtmeNG = VirtmeNGCfg{Run: "v6.8"}
	virtme.InstallKernel = "5.15.0-118-generic"
	if err := ValidateProfile(virtme); err == nil {
		t.Fatal("expected install_kernel on virtme-ng runner to fail")
	}

	unsafe := ubuntuVMProfile()
	unsafe.InstallKernel = "5.15.0-118-generic; rm -rf /"
	if err := ValidateProfile(unsafe); err == nil {
		t.Fatal("expected shell-unsafe install_kernel to fail")
	}
}
