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

	oracle := ubuntuVMProfile()
	oracle.Distro = "oracle"
	oracle.InstallKernel = "6.12.0-204.92.4.4.el9uek.x86_64"
	oracle.KernelPackages = []string{
		"https://yum.oracle.com/repo/OracleLinux/OL9/UEKR8/x86_64/getPackage/kernel-uek-core-6.12.0-204.92.4.4.el9uek.x86_64.rpm",
	}
	if err := ValidateProfile(oracle); err != nil {
		t.Fatalf("valid Oracle UEK install_kernel rejected: %v", err)
	}

	amazon2 := ubuntuVMProfile()
	amazon2.Distro = "amazon-linux"
	amazon2.Version = "2"
	amazon2.InstallKernel = "5.10.260-259.1061.amzn2.x86_64"
	if err := ValidateProfile(amazon2); err != nil {
		t.Fatalf("valid Amazon Linux 2 install_kernel rejected: %v", err)
	}

	amazon2023 := ubuntuVMProfile()
	amazon2023.Distro = "amazon-linux"
	amazon2023.Version = "2023"
	amazon2023.InstallKernel = "6.1.177-224.371.amzn2023.x86_64"
	if err := ValidateProfile(amazon2023); err != nil {
		t.Fatalf("valid Amazon Linux 2023 install_kernel rejected: %v", err)
	}

	unknownAmazon := amazon2023
	unknownAmazon.Version = "future"
	if err := ValidateProfile(unknownAmazon); err == nil {
		t.Fatal("expected unknown Amazon version with install_kernel to fail")
	}

	amazonWithURL := amazon2
	amazonWithURL.KernelPackages = []string{"https://example.com/kernel.rpm"}
	if err := ValidateProfile(amazonWithURL); err == nil {
		t.Fatal("expected Amazon install_kernel with direct package URL to fail")
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
