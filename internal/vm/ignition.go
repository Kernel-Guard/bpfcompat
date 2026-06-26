package vm

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// CoreOS-family images (Fedora CoreOS, RHEL CoreOS) boot via Ignition, not
// cloud-init: there is no NoCloud datasource to read a CIDATA seed. Instead the
// QEMU "qemu" platform reads an Ignition config from the firmware config blob
// at opt/com.coreos/config and applies it on first boot. We emit a minimal
// Ignition v3 config that authorises the per-run SSH key for the default
// `core` user, which is all the validator transport needs.

// ignitionConfig is the subset of the Ignition v3 schema we generate.
type ignitionConfig struct {
	Ignition ignitionVersion `json:"ignition"`
	Passwd   ignitionPasswd  `json:"passwd"`
}

type ignitionVersion struct {
	Version string `json:"version"`
}

type ignitionPasswd struct {
	Users []ignitionUser `json:"users"`
}

type ignitionUser struct {
	Name              string   `json:"name"`
	SSHAuthorizedKeys []string `json:"sshAuthorizedKeys"`
}

// writeIgnitionSeed writes a minimal Ignition config that adds publicKey to the
// CoreOS `core` user, returning the path to the written file. The 3.3.0 spec
// version is supported by both current Fedora CoreOS and RHEL CoreOS (OpenShift
// 4.12+), so one config serves both.
func writeIgnitionSeed(path, publicKey string) error {
	cfg := ignitionConfig{
		Ignition: ignitionVersion{Version: "3.3.0"},
		Passwd: ignitionPasswd{
			Users: []ignitionUser{
				{Name: "core", SSHAuthorizedKeys: []string{strings.TrimSpace(publicKey)}},
			},
		},
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal ignition config: %w", err)
	}
	data = append(data, '\n')
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("write ignition config: %w", err)
	}
	return nil
}

// isCoreOSIgnitionDistro reports whether a profile's distro boots via Ignition
// and should use the fw_cfg Ignition seed instead of a cloud-init NoCloud seed.
func isCoreOSIgnitionDistro(profile Profile) bool {
	switch strings.ToLower(strings.TrimSpace(profile.Distro)) {
	case "fedora-coreos", "fcos", "rhcos", "rhel-coreos":
		return true
	}
	return false
}
