package vm

import (
	"fmt"
	"strings"
)

func ValidateProfile(p Profile) error {
	if p.ID == "" {
		return fmt.Errorf("profile.id is required")
	}
	if p.Distro == "" {
		return fmt.Errorf("profile.distro is required")
	}
	if p.KernelFamily == "" {
		return fmt.Errorf("profile.kernel_family is required")
	}
	if p.Arch == "" {
		return fmt.Errorf("profile.arch is required")
	}

	runner := strings.TrimSpace(p.Runner)
	if runner == "" {
		runner = "vm"
	}
	switch runner {
	case "vm":
		if p.Image.SourceURL == "" && p.Image.LocalPath == "" {
			return fmt.Errorf("profile.image.source_url or profile.image.local_path is required")
		}
	case "virtme-ng":
		if strings.TrimSpace(p.VirtmeNG.Run) == "" {
			return fmt.Errorf("profile.virtme_ng.run is required for runner virtme-ng")
		}
	case "firecracker":
		if strings.TrimSpace(p.Firecracker.KernelImagePath) == "" {
			return fmt.Errorf("profile.firecracker.kernel_image_path is required for runner firecracker")
		}
	default:
		return fmt.Errorf("profile.runner must be one of %q, %q, or %q (got %q)", "vm", "virtme-ng", "firecracker", p.Runner)
	}

	if p.InstallKernel != "" {
		if runner != "vm" {
			return fmt.Errorf("profile.install_kernel requires runner %q (got %q)", "vm", runner)
		}
		family := KernelInstallFamily(p.Distro)
		if family == "" {
			return fmt.Errorf("profile.install_kernel is only supported for debian- and rhel-family profiles (got distro %q)", p.Distro)
		}
		if !validKernelRelease(p.InstallKernel) {
			return fmt.Errorf("profile.install_kernel must match [A-Za-z0-9._+-]+ (got %q)", p.InstallKernel)
		}
		wantExt := ".deb"
		if family == KernelFamilyRHEL {
			wantExt = ".rpm"
		}
		for _, pkg := range p.KernelPackages {
			if !validKernelPackageURL(pkg, wantExt) {
				return fmt.Errorf("profile.kernel_packages entry must be a plain http(s) %s URL (got %q)", wantExt, pkg)
			}
		}
	}
	if len(p.KernelPackages) > 0 && p.InstallKernel == "" {
		return fmt.Errorf("profile.kernel_packages requires profile.install_kernel")
	}

	if p.Boot.MemoryMB <= 0 {
		return fmt.Errorf("profile.boot.memory_mb must be > 0")
	}
	if p.Boot.CPUs <= 0 {
		return fmt.Errorf("profile.boot.cpus must be > 0")
	}
	if p.Validator.Path == "" {
		return fmt.Errorf("profile.validator.path is required")
	}
	return nil
}

// validKernelPackageURL keeps kernel_packages shell-safe: the URLs are
// interpolated into guest curl command lines, so only plain URL characters
// are allowed (no quotes, spaces, or shell metacharacters).
func validKernelPackageURL(value, ext string) bool {
	if !strings.HasPrefix(value, "http://") && !strings.HasPrefix(value, "https://") {
		return false
	}
	if !strings.HasSuffix(value, ext) || len(value) > 512 {
		return false
	}
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '.', r == '_', r == '+', r == '-', r == '/', r == ':', r == '~', r == '%':
		default:
			return false
		}
	}
	return true
}

// validKernelRelease keeps install_kernel shell-safe: it is interpolated
// into guest apt/grub command lines, so only package-name characters are
// allowed.
func validKernelRelease(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '.', r == '_', r == '+', r == '-':
		default:
			return false
		}
	}
	return true
}
