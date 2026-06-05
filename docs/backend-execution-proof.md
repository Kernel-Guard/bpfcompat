# Backend Execution Proof

This note records the current local proof state for the three validation
backends. Generated JSON/Markdown reports stay under `reports/` and are not
committed, so this file captures the reproducible command and latest observed
result.

## Latest Local Run

Date: 2026-06-04
Host: x86_64 Linux with `/dev/kvm`
Commit: `71d255e`

| Backend | Command | Run ID | Targets | Summary | Target Duration |
|---|---|---:|---:|---|---:|
| QEMU/KVM cloud image | `make acceptance-dev-one` | `20260604T201134Z-6bb28c` | 1 | pass | 24.787s |
| virtme-ng upstream kernels | `make acceptance-upstream-kernel` | `20260604T201220Z-b337cf` | 4 | pass | 12.502s total |
| Firecracker generated initramfs | `make acceptance-firecracker-dev-one` | `20260604T201210Z-68f8aa` | 1 | pass | 0.753s |

## Backend Roles

- QEMU/KVM remains the customer-distro realism backend because it boots full
  distro cloud images and exercises the SSH/cloud-init executor.
- `virtme-ng` is the upstream-mainline lane for fast checks against bootable
  kernel.org/Ubuntu-mainline kernel bands.
- Firecracker is now an executable microVM lane: it builds a generated initramfs
  containing static BusyBox, `bpfcompat-validator`, the artifact, and optional
  manifest/functional-plan files, then extracts validator JSON over serial
  markers.

## ARM64 Boundary

`make arm64-kvm-preflight` was run on the same host and correctly failed:

```text
ARM64 VM proof requires a native ARM64/aarch64 KVM host; current host is x86_64
```

The GitHub-hosted ARM64 build-smoke workflow passed for commit `71d255e`, but
that is compile/test proof only. Real ARM64 compatibility proof still requires
a self-hosted ARM64 Linux runner with `/dev/kvm`, `qemu-system-aarch64`, an
ARM64 cloud image, and an ARM64 validator binary.

## Current Production Boundary

Firecracker execution is implemented, but a production multi-tenant worker
fleet still requires:

- jailer/cgroup policy for every worker process;
- scheduler and per-tenant job quotas;
- immutable worker images or measured boot/image provenance;
- worker result upload through a trusted channel;
- benchmark runs under load, not only single-target local proof.
