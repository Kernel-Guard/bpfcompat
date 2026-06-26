package vm

import (
	"os"
	"strings"
)

// rhcosOptIn reports whether an operator has explicitly enabled RHCOS
// validation via BPFCOMPAT_ENABLE_RHCOS. RHCOS boots via the same Ignition path
// as Fedora CoreOS (supported), but its image ships through the OpenShift
// release payload and cannot be fetched here, so the operator must stage the
// image (see `make rhcos-image`) and set this flag to assert it is present.
func rhcosOptIn() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("BPFCOMPAT_ENABLE_RHCOS"))) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

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
		// Shares Fedora CoreOS's Ignition+SSH boot path (implemented + proven on
		// FCOS). The only missing piece is the image, which ships through the
		// OpenShift release payload rather than a public cloud-image URL. An
		// operator stages it (see `make rhcos-image`) and opts in explicitly so
		// we never claim RHCOS works without a real image present.
		if rhcosOptIn() {
			return ExecutionTransportSSH, true, ""
		}
		return ExecutionTransportUnsupported, false, "RHEL CoreOS shares the Fedora CoreOS Ignition boot path (supported), but its image ships via the OpenShift release payload, not a public URL. Stage it with `make rhcos-image` and set BPFCOMPAT_ENABLE_RHCOS=1 to enable."
	default:
		return ExecutionTransportSSH, true, ""
	}
}
