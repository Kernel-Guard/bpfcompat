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

	switch strings.ToLower(strings.TrimSpace(profile.Distro)) {
	case "talos":
		return ExecutionTransportUnsupported, false, "Talos is API-driven (no SSH/shell); current validator runner requires SSH transport."
	case "bottlerocket":
		return ExecutionTransportUnsupported, false, "Bottlerocket requires control/admin container workflows; current validator runner requires direct SSH transport."
	case "flatcar":
		return ExecutionTransportUnsupported, false, "Flatcar images in this matrix require Ignition-style bootstrap; current validator runner depends on cloud-init+SSH provisioning."
	case "fedora-coreos", "fcos":
		// Boots via Ignition over fw_cfg (opt/com.coreos/config), then SSH as
		// the core user — implemented in ignition.go and proven on FCOS stable.
		return ExecutionTransportSSH, true, ""
	case "rhcos", "rhel-coreos":
		// Shares Fedora CoreOS's Ignition+SSH boot path (now implemented), but
		// the RHCOS image ships only through the pull-secret-gated OpenShift
		// release payload, so it cannot be fetched/verified here. Supply the
		// image to enable it; until then it stays non-runnable.
		return ExecutionTransportUnsupported, false, "RHEL CoreOS shares the Fedora CoreOS Ignition boot path (now supported), but its image is only available via the pull-secret-gated OpenShift release payload; supply the image to enable it."
	default:
		return ExecutionTransportSSH, true, ""
	}
}
