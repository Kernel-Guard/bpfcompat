# Falco-Style Compatibility Parity

This document tracks the gap between `bpfcompat` and the compatibility
infrastructure described by Falco maintainers: CI integration, VM-backed kernel
coverage, multi-artifact suites, behavioral checks, latest-kernel sweeps,
multi-architecture runners, and release matrix publication.

## Implemented Parity

| Capability | Current implementation |
|---|---|
| CI/release gate | `action.yml`, `.github/workflows/bpfcompat-example.yml`, and external proof repo. |
| Multi-artifact input | `bpfcompat suite` and `suites/dev-functional.yaml`. |
| Manifest-described test steps | Manifest `functional_tests` are converted into validator functional plans. |
| Behavioral event proof | `examples/functional-execve` attaches to execve, triggers `/bin/true`, and observes the trace marker while the BPF link is alive. |
| Real VM-backed validation | QEMU/KVM cloud-image runner under `internal/vm` and `internal/runner`. |
| Latest distro-kernel sweep | `.github/workflows/latest-kernel-compatibility.yml` and `matrices/latest-kernel-sweep.yaml`. |
| Upstream-mainline sweep | `--runner virtme-ng`, `make upstream-kernel-runnable`, `make acceptance-upstream-kernel`, and `.github/workflows/upstream-kernel-compatibility.yml`. |
| ARM64 build smoke | `.github/workflows/arm64-build-smoke.yml` runs native ARM64 compile/test checks on GitHub-hosted ARM64 Linux. |
| Multi-architecture lane | `.github/workflows/multiarch-compatibility.yml`, `matrices/arm64-smoke.yaml`, `make acceptance-arm64-smoke`. |
| Firecracker executable backend | `--runner firecracker`, generated initramfs validator execution, serial result extraction, `make acceptance-firecracker-dev-one`, `.github/workflows/firecracker-preflight.yml`, and `docs/firecracker-backend.md`. |
| Catalog maintenance | `.github/workflows/profile-catalog-maintenance.yml`, `make profile-catalog-audit`, `make matrix-readiness`. |
| Release matrix publishing | `.github/workflows/compatibility-matrix-publish.yml`, `scripts/publish-compatibility-site.sh`, optional GitHub Pages deployment, tag release attachment. |
| Project adapter template | `adapters/generic-ebpf-suite/`. |

## Commands

Fast local proof:

```bash
make acceptance-suite-dev-one
```

Behavioral event proof:

```bash
make acceptance-functional-dev-one
```

Latest distro-kernel sweep on an x64 KVM runner:

```bash
make acceptance-latest-kernel
```

Boot-aware upstream-mainline sweep through `virtme-ng`:

```bash
make doctor-virtme
make acceptance-upstream-kernel
```

ARM64 smoke on an ARM64 KVM runner:

```bash
make acceptance-arm64-smoke
```

ARM64 proof preflight:

```bash
make arm64-kvm-preflight
```

Firecracker executable proof:

```bash
make acceptance-firecracker-dev-one
make firecracker-preflight
```

Catalog maintenance:

```bash
make profile-catalog-audit
make matrix-readiness
```

## Remaining Backend Gap

Falco's kernel-testing framework uses Firecracker microVMs and OCI-packaged
kernel/rootfs images. `bpfcompat` now has three executor lanes:

- QEMU/KVM cloud-image validation for distro/customer-like profiles.
- `virtme-ng` upstream-kernel validation for bootable upstream-mainline smoke
  tests, with kernel.org release context recorded during generation.
- Firecracker generated-initramfs validation for fast microVM execution proofs.

That closes the "latest upstream kernel" proof gap and removes the previous
Firecracker executable-validation blocker.

The recommended backend migration path is:

1. define a `ValidatorTransport` interface around VM lifecycle, copy-in,
   command execution, copy-out, and cleanup;
2. keep QEMU/KVM as the default backend;
3. keep the `virtme-ng` backend scoped to upstream-mainline smoke tests;
4. benchmark Firecracker initrd execution against the existing QEMU runner;
5. benchmark boot time, failure isolation, and artifact collection against the
   existing QEMU runner before changing defaults.

Until then, present the current system as:

> VM-backed eBPF compatibility evidence and CI gate with QEMU/KVM,
> upstream-mainline `virtme-ng`, and Firecracker microVM execution lanes.

Do not present it as:

> A production multi-tenant Firecracker service equivalent to Falco's release
> infrastructure.
