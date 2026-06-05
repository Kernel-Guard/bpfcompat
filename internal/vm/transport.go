package vm

import "strings"

const (
	ExecutionTransportSSH         = "ssh"
	ExecutionTransportUnsupported = "unsupported"
)

// ExecutionTransport returns the execution transport and whether the current
// runner supports this profile today.
func ExecutionTransport(profile Profile) (transport string, supported bool, reason string) {
	if strings.EqualFold(strings.TrimSpace(profile.Runner), "virtme-ng") {
		return ExecutionTransportUnsupported, false, "Profile requires the virtme-ng runner; use `--runner virtme-ng` instead of the default QEMU cloud-image runner."
	}
	if strings.EqualFold(strings.TrimSpace(profile.Runner), "firecracker") {
		return ExecutionTransportUnsupported, false, "Profile requires the firecracker runner; use `--runner firecracker` instead of the default QEMU cloud-image runner."
	}

	switch strings.ToLower(strings.TrimSpace(profile.ID)) {
	case "amazon-linux-2-4.14":
		return ExecutionTransportUnsupported, false, "Legacy Amazon Linux 2 (4.14) image in this catalog does not provide reliable cloud-init+SSH bootstrap for current validator executor."
	}

	switch strings.ToLower(strings.TrimSpace(profile.Distro)) {
	case "talos":
		return ExecutionTransportUnsupported, false, "Talos is API-driven (no SSH/shell); current validator runner requires SSH transport."
	case "bottlerocket":
		return ExecutionTransportUnsupported, false, "Bottlerocket requires control/admin container workflows; current validator runner requires direct SSH transport."
	case "flatcar":
		return ExecutionTransportUnsupported, false, "Flatcar images in this matrix require Ignition-style bootstrap; current validator runner depends on cloud-init+SSH provisioning."
	default:
		return ExecutionTransportSSH, true, ""
	}
}
