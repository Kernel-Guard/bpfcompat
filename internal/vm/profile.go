package vm

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type Profile struct {
	ID           string         `yaml:"id"`
	Distro       string         `yaml:"distro"`
	Version      string         `yaml:"version"`
	KernelFamily string         `yaml:"kernel_family"`
	Arch         string         `yaml:"arch"`
	Runner       string         `yaml:"runner,omitempty"`
	Image        ImageConfig    `yaml:"image"`
	VirtmeNG     VirtmeNGCfg    `yaml:"virtme_ng,omitempty"`
	Firecracker  FirecrackerCfg `yaml:"firecracker,omitempty"`
	Boot         BootConfig     `yaml:"boot"`
	Validator    ValidatorCfg   `yaml:"validator"`
	Capabilities Capability     `yaml:"capabilities"`
}

type ImageConfig struct {
	SourceURL string `yaml:"source_url"`
	LocalPath string `yaml:"local_path"`
}

type VirtmeNGCfg struct {
	Run       string   `yaml:"run"`
	ExtraArgs []string `yaml:"extra_args,omitempty"`
}

type FirecrackerCfg struct {
	KernelImagePath string `yaml:"kernel_image_path"`
	RootfsPath      string `yaml:"rootfs_path,omitempty"`
	InitrdPath      string `yaml:"initrd_path,omitempty"`
	BootArgs        string `yaml:"boot_args,omitempty"`
	GuestMAC        string `yaml:"guest_mac,omitempty"`
	TapDevice       string `yaml:"tap_device,omitempty"`
}

type BootConfig struct {
	MemoryMB int `yaml:"memory_mb"`
	CPUs     int `yaml:"cpus"`
}

type ValidatorCfg struct {
	Path string `yaml:"path"`
}

type Capability struct {
	ExpectedBTF bool `yaml:"expected_btf"`
}

func LoadProfile(path string) (Profile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Profile{}, fmt.Errorf("read profile: %w", err)
	}

	var p Profile
	if err := yaml.Unmarshal(data, &p); err != nil {
		return Profile{}, fmt.Errorf("parse profile YAML: %w", err)
	}

	if err := ValidateProfile(p); err != nil {
		return Profile{}, err
	}
	return p, nil
}
