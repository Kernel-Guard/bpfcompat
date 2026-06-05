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
