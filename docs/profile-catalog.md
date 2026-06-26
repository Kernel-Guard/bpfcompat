# Profile Catalog

This document defines the maintained profile matrices used for compatibility campaigns beyond the MVP baseline.

## Matrices

- Fast acceptance matrix (8 profiles): `matrices/mvp.yaml`
- Extended catalog matrix (15 profiles): `matrices/extended-15.yaml`
- Tier 1 enterprise/cloud matrix: `matrices/tier1-enterprise-cloud.yaml`
- Tier 2 kernel-boundary matrix: `matrices/tier2-kernel-boundaries.yaml`
- Tier 3 cloud-native/hardened matrix: `matrices/tier3-cloud-native.yaml`
- Combined expanded campaign matrix: `matrices/expanded-2026.yaml`
- ARM64 smoke matrix: `matrices/arm64-smoke.yaml`
- Latest distro-kernel sweep: `matrices/latest-kernel-sweep.yaml`
- Generated upstream-mainline sweep: `matrices/upstream-kernel-runnable.yaml` (`make upstream-kernel-runnable`)
- Generated dense kernel sweep: `matrices/kernel-sweep-<profile>.yaml` (`bpfcompat kernel-sweep --profile <id>`; installs exact kernel releases inside the guest, see [`image-pipeline.md`](image-pipeline.md))
- Firecracker backend: Firecracker profiles use `runner: firecracker` and are generated locally by `make firecracker-runnable` because kernel image paths are machine-specific.

## Tiered Coverage Focus

1. Tier 1: distros with large enterprise/cloud footprint and divergent kernel behavior.
   - `amazon-linux-2023-6.1`
   - `amazon-linux-2-5.10`
   - `amazon-linux-2-4.14` (cataloged, currently non-runnable with SSH/cloud-init executor)
   - `rhel-8-4.18` (supported via local NoCloud config-drive bootstrap)
   - `oracle-linux-9-uek7-5.15`
   - `oracle-linux-10-uek8-6.12`
   - `sles-15.6-6.4` (manual licensed image)
   - `opensuse-leap-15.6-6.4`
2. Tier 2: kernel feature boundaries important for selector decisions.
   - `ubuntu-20.04-5.4`
   - `linux-mainline-5.6` (manual image)
   - `ubuntu-20.10-5.8`
   - `ubuntu-22.04-5.15`
   - `ubuntu-23.10-6.5`
   - `ubuntu-24.04-6.8`
3. Tier 3: cloud-native and hardened policy scenarios.
   - `bottlerocket-aws-6.1` (manual image)
   - `flatcar-6.6` (URL-backed image)
   - `talos-6.6` (manual image)
   - `fedora-coreos-stable-6.14` (manual image; Ignition boot — see below)
   - `rhcos-4.16-5.14` (manual image, pull-secret gated; Ignition boot — see below)
   - `ubuntu-22.04-5.15-lockdown`
4. Multi-architecture foundation:
   - `ubuntu-22.04-arm64-5.15` (`aarch64`, requires ARM64-capable runner)
5. Latest distro-kernel sweep:
   - `ubuntu-24.04-6.8`
   - `ubuntu-24.10-6.11`
   - `ubuntu-25.04-6.14`
   - `ubuntu-25.10-6.17`
6. Upstream-mainline sweep:
   - generated `kernelorg-latest-runnable-*`
   - generated feature-boundary/LTS smoke profiles such as `kernelorg-feature-ringbuf-era-*` and `kernelorg-lts-*`

## Maintenance Workflow

1. Validate profile YAML integrity:
   - `go test ./internal/vm -run TestAllProfileYAMLLoadAndValidate -count=1`
2. Validate source URL reachability and generate audit evidence:
   - `make profile-catalog-audit`
3. Cache baseline and extended downloadable images:
   - `make vm-images`
   - `make vm-images-extended`
   - `make vm-images-tier1`
   - `make vm-images-expanded-2026-dry-run`
   - `make vm-images-expanded-2026`
4. Generate a runnable local matrix from the expanded catalog:
   - `make matrix-runnable`
   - `make matrix-runnable-strict` (fails if required profiles are excluded)
   - output: `matrices/expanded-2026-runnable.yaml`
5. Import manual/licensed images into `vm/cache/` for profiles without public URLs.
   - `make import-required-images SLES156_IMG=/abs/path/sles15.6.qcow2`
6. Generate matrix readiness report (image cache + executor transport readiness):
   - `make matrix-readiness`
7. Run scheduled/opt-in Falco-style sweeps:
   - `.github/workflows/latest-kernel-compatibility.yml`
   - `.github/workflows/upstream-kernel-compatibility.yml`
   - `.github/workflows/arm64-build-smoke.yml`
   - `.github/workflows/multiarch-compatibility.yml`
   - `.github/workflows/firecracker-preflight.yml`
   - `.github/workflows/profile-catalog-maintenance.yml`
   - `.github/workflows/kernel-freshness.yml` (weekly: flags profiles whose
     last-validated kernel is behind what the distro currently ships, using
     the falcosecurity/kernel-crawler inventory; baselines live in
     `vm/kernel-baselines.yaml` and are refreshed with
     `bpfcompat kernel-freshness --update-from-report <report.json>`)
8. Densify a kernel series beyond what one image samples:
   - `./bin/bpfcompat kernel-sweep --profile ubuntu-22.04-5.15 --count 4`
     generates per-release `install_kernel` profiles plus a sweep matrix

## Current Strict-Mode Status

- Required-image blockers: none
- Optional manual images still missing:
  - `vm/cache/linux-mainline-5.6.qcow2`
  - `vm/cache/bottlerocket-aws-6.1.qcow2`
  - `vm/cache/talos-6.6.qcow2`
  - `vm/cache/fedora-coreos-stable.qcow2` (also Ignition-gated — see Transport Notes)
  - `vm/cache/rhcos-4.16.qcow2` (pull-secret + Ignition-gated — see Transport Notes)

Strict commands can run now:

- `make manual-image-check-strict`
- `make matrix-runnable-strict`

Optional licensed image source:

- SLES 15 SP6 downloads (account required): `https://www.suse.com/download/sles/`

## Transport Notes

- Current VM validator execution path is SSH-based.
- `talos`, `bottlerocket`, `flatcar`, and `amazon-linux-2-4.14` are cataloged for planning/roadmap and are marked non-blocking in matrix definitions because the current executor cannot run validator payloads on them.
- `fedora-coreos` and `rhcos` (RHEL CoreOS / OpenShift) are cataloged but **not runnable yet**: both boot via Ignition rather than cloud-init, so the SSH executor cannot provision the validator (same gap as `flatcar`). RHCOS additionally ships through the pull-secret-gated OpenShift release payload. Enabling them needs an Ignition-config bootstrap path in the QEMU executor; until then, the matching RHEL/AlmaLinux 9 (5.14) profile approximates the RHCOS kernel, and Fedora CoreOS is the freely-available stand-in for proving the CoreOS boot path.
- `rhel-8-4.18` uses NoCloud config-drive bootstrap in the current SSH executor (prefers `cloud-localds` ISO; falls back to local `vvfat` seed).
- `aarch64`/`arm64` profiles select `qemu-system-aarch64`; `x86_64`/`amd64` profiles select `qemu-system-x86_64`.
- ARM64 validation requires a matching ARM64-capable self-hosted runner, KVM access, an ARM64 cloud image, and a validator binary built for the guest architecture. The default Azure demo VM is x86_64 and should not be presented as ARM64 validation proof.
- Firecracker profiles require a Firecracker release binary, `/dev/kvm`, a static BusyBox, `cpio`, `gzip`, and an uncompressed guest kernel. The current transport generates an initramfs, executes the validator inside the microVM, and extracts JSON results over serial markers.

## Evidence Output

- Profile audit reports are written under `evidence/profile-catalog/` by `scripts/profile-catalog-audit.sh`.
- Matrix readiness reports are written under `evidence/profile-catalog/` by `scripts/matrix-readiness.sh`.
- `matrices/expanded-2026-runnable.yaml` is generated locally per host state and is ignored by git.
- `matrices/latest-kernel-runnable.yaml` is generated locally per host state and is ignored by git.
- `matrices/upstream-kernel-runnable.yaml` and `vm/profiles/kernelorg-*.yaml` are generated from kernel.org release context plus the Ubuntu mainline prebuilt-kernel index, then preflighted through `virtme-ng`; they are ignored by git.
