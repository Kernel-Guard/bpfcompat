# Support Matrix

<!-- GENERATED FILE — do not edit by hand.
     Regenerate with: make support-matrix (or scripts/support-matrix.sh).
     CI fails if this file drifts from vm/profiles/*.yaml. -->

This is the single source of truth for what bpfcompat can actually run.
It is generated from the committed profile definitions, so it can never
claim support the profiles do not describe. "Runnable" is a property of
the profile and executor, independent of whether an image is cached on any
particular machine. For tiering rationale see
[profile-catalog.md](profile-catalog.md); for how images are fetched and
pinned see [image-pipeline.md](image-pipeline.md).

| Category | Count | Meaning |
|---|---|---|
| Runnable (auto-download) | 44 | Supported transport and a public vendor image URL — runs anywhere with KVM, no manual setup. |
| Manual image required | 8 | Supported transport, but the image is licensed or has no public URL; the operator imports it (see `make import-required-images`). |
| Generated lane | 5 | No vendor image at all — the kernel is built/booted at run time (virtme-ng upstream, Firecracker). |
| Cataloged, not runnable here | 4 | Present in the catalog but not bootable on the current SSH/cloud-init executor (immutable images, executor limits). Marked non-blocking in matrices. |

## Runnable now (auto-download)

These run with nothing more than a KVM-capable host; the vendor cloud
image is fetched on first use and its sha256 is recorded.

| Profile ID | Distro | Version | Kernel family | Arch | Transport / runner | Notes |
|---|---|---|---|---|---|---|
| almalinux-10-6.12 | almalinux | 10 | 6.12 | x86_64 | ssh | auto-downloads vendor cloud image on first run |
| almalinux-8-4.18 | almalinux | 8 | 4.18 | x86_64 | ssh | auto-downloads vendor cloud image on first run |
| almalinux-9-5.14 | almalinux | 9 | 5.14 | x86_64 | ssh | auto-downloads vendor cloud image on first run |
| almalinux-9-5.14-k5.14.0-687.26.1.el9_8 | almalinux | 9 | 5.14 | x86_64 | ssh | auto-downloads vendor cloud image on first run |
| amazon-linux-2-5.10 | amazon-linux | 2 | 5.10 | x86_64 | ssh | auto-downloads vendor cloud image on first run |
| amazon-linux-2023-6.1 | amazon-linux | 2023 | 6.1 | x86_64 | ssh | auto-downloads vendor cloud image on first run |
| centos-stream-10-6.12 | centos-stream | 10 | 6.12 | x86_64 | ssh | auto-downloads vendor cloud image on first run |
| centos-stream-9-5.14 | centos-stream | 9 | 5.14 | x86_64 | ssh | auto-downloads vendor cloud image on first run |
| centos-stream-9-5.14-k5.14.0-725.el9 | centos-stream | 9 | 5.14 | x86_64 | ssh | auto-downloads vendor cloud image on first run |
| debian-11-5.10 | debian | 11 | 5.10 | x86_64 | ssh | auto-downloads vendor cloud image on first run |
| debian-12-6.1 | debian | 12 | 6.1 | x86_64 | ssh | auto-downloads vendor cloud image on first run |
| debian-13-6.12 | debian | 13 | 6.12 | x86_64 | ssh | auto-downloads vendor cloud image on first run |
| opensuse-leap-15.6-6.4 | opensuse | 15.6 | 6.4 | x86_64 | ssh | auto-downloads vendor cloud image on first run |
| oracle-linux-10-uek8-6.12 | oracle | 10 | 6.12 | x86_64 | ssh | auto-downloads vendor cloud image on first run |
| oracle-linux-9-uek7-5.15 | oracle | 9 | 5.15 | x86_64 | ssh | auto-downloads vendor cloud image on first run |
| rocky-10-6.12 | rocky | 10 | 6.12 | x86_64 | ssh | auto-downloads vendor cloud image on first run |
| rocky-8-4.18 | rocky | 8 | 4.18 | x86_64 | ssh | auto-downloads vendor cloud image on first run |
| rocky-9-5.14 | rocky | 9 | 5.14 | x86_64 | ssh | auto-downloads vendor cloud image on first run |
| rocky-9-5.14-k5.14.0-687.26.1.el9_8 | rocky | 9 | 5.14 | x86_64 | ssh | auto-downloads vendor cloud image on first run |
| ubuntu-16.04-4.4 | ubuntu | 16.04 | 4.4 | x86_64 | ssh | auto-downloads vendor cloud image on first run |
| ubuntu-18.04-4.15 | ubuntu | 18.04 | 4.15 | x86_64 | ssh | auto-downloads vendor cloud image on first run |
| ubuntu-18.04-4.15-k4.15.0-213 | ubuntu | 18.04 | 4.15 | x86_64 | ssh | auto-downloads vendor cloud image on first run |
| ubuntu-20.04-5.4 | ubuntu | 20.04 | 5.4 | x86_64 | ssh | auto-downloads vendor cloud image on first run |
| ubuntu-20.04-5.4-k5.4.0-218 | ubuntu | 20.04 | 5.4 | x86_64 | ssh | auto-downloads vendor cloud image on first run |
| ubuntu-20.04-minimal-5.4 | ubuntu | 20.04-minimal | 5.4 | x86_64 | ssh | auto-downloads vendor cloud image on first run |
| ubuntu-20.10-5.8 | ubuntu | 20.10 | 5.8 | x86_64 | ssh | auto-downloads vendor cloud image on first run |
| ubuntu-22.04-5.15 | ubuntu | 22.04 | 5.15 | x86_64 | ssh | auto-downloads vendor cloud image on first run |
| ubuntu-22.04-5.15-k5.15.0-181 | ubuntu | 22.04 | 5.15 | x86_64 | ssh | auto-downloads vendor cloud image on first run |
| ubuntu-22.04-5.15-k5.15.0-184 | ubuntu | 22.04 | 5.15 | x86_64 | ssh | auto-downloads vendor cloud image on first run |
| ubuntu-22.04-5.15-k5.15.0-186 | ubuntu | 22.04 | 5.15 | x86_64 | ssh | auto-downloads vendor cloud image on first run |
| ubuntu-22.04-5.15-lockdown | ubuntu | 22.04-lockdown | 5.15 | x86_64 | ssh | auto-downloads vendor cloud image on first run |
| ubuntu-22.04-5.15-lockdown-k5.15.0-186 | ubuntu | 22.04-lockdown | 5.15 | x86_64 | ssh | auto-downloads vendor cloud image on first run |
| ubuntu-22.04-arm64-5.15 | ubuntu | 22.04 | 5.15 | aarch64 | ssh | auto-downloads vendor cloud image on first run |
| ubuntu-22.04-minimal-5.15 | ubuntu | 22.04 | 5.15 | x86_64 | ssh | auto-downloads vendor cloud image on first run |
| ubuntu-23.10-6.5 | ubuntu | 23.10 | 6.5 | x86_64 | ssh | auto-downloads vendor cloud image on first run |
| ubuntu-24.04-6.8 | ubuntu | 24.04 | 6.8 | x86_64 | ssh | auto-downloads vendor cloud image on first run |
| ubuntu-24.04-6.8-k6.8.0-136 | ubuntu | 24.04 | 6.8 | x86_64 | ssh | auto-downloads vendor cloud image on first run |
| ubuntu-24.04-minimal-6.8 | ubuntu | 24.04-minimal | 6.8 | x86_64 | ssh | auto-downloads vendor cloud image on first run |
| ubuntu-24.10-6.11 | ubuntu | 24.10 | 6.11 | x86_64 | ssh | auto-downloads vendor cloud image on first run |
| ubuntu-25.04-6.14 | ubuntu | 25.04 | 6.14 | x86_64 | ssh | auto-downloads vendor cloud image on first run |
| ubuntu-25.10-6.17 | ubuntu | 25.10 | 6.17 | x86_64 | ssh | auto-downloads vendor cloud image on first run |
| ubuntu-25.10-6.17-k6.17.0-41 | ubuntu | 25.10 | 6.17 | x86_64 | ssh | auto-downloads vendor cloud image on first run |
| ubuntu-25.10-minimal-6.17 | ubuntu | 25.10-minimal | 6.17 | x86_64 | ssh | auto-downloads vendor cloud image on first run |
| ubuntu-25.10-minimal-6.17-k6.17.0-41 | ubuntu | 25.10-minimal | 6.17 | x86_64 | ssh | auto-downloads vendor cloud image on first run |

## Manual image required

Supported by the executor, but you must supply the image yourself
(licensed distros, or images with no stable public URL).

| Profile ID | Distro | Version | Kernel family | Arch | Transport / runner | Notes |
|---|---|---|---|---|---|---|
| fedora-coreos-stable-7.0 | fedora-coreos | stable | 7.0 | x86_64 | ssh | no source_url configured — operator supplies the image (see make import-required-images) |
| linux-mainline-5.6 | linux-mainline | 5.6 | 5.6 | x86_64 | ssh | no source_url configured — operator supplies the image (see make import-required-images) |
| rhcos-4.14-5.14 | rhcos | 4.14 | 5.14 | x86_64 | ssh | no source_url configured — operator supplies the image (see make import-required-images) |
| rhcos-4.16-5.14 | rhcos | 4.16 | 5.14 | x86_64 | ssh | no source_url configured — operator supplies the image (see make import-required-images) |
| rhcos-4.16-arm64 | rhcos | 4.16 | 5.14 | arm64 | ssh | no source_url configured — operator supplies the image (see make import-required-images) |
| rhcos-4.18-5.14 | rhcos | 4.18 | 5.14 | x86_64 | ssh | no source_url configured — operator supplies the image (see make import-required-images) |
| rhel-8-4.18 | rhel | 8 | 4.18 | x86_64 | ssh | no source_url configured — operator supplies the image (see make import-required-images) |
| sles-15.6-6.4 | sles | 15.6 | 6.4 | x86_64 | ssh | no source_url configured — operator supplies the image (see make import-required-images) |

## Generated lanes (no prebuilt image)

The environment is constructed at run time; reproducibility comes from the
recorded kernel release, not an image digest.

| Profile ID | Distro | Version | Kernel family | Arch | Transport / runner | Notes |
|---|---|---|---|---|---|---|
| firecracker-dev-one | firecracker-ci-kernel | 6.1.155 | 6.1.155 | x86_64 | firecracker | kernel is built/booted at run time (no vendor image) |
| kernelorg-feature-ringbuf-era-6.8 | upstream-mainline | feature-ringbuf-era | 6.8 | x86_64 | virtme-ng | kernel is built/booted at run time (no vendor image) |
| kernelorg-latest-runnable-6.19 | upstream-mainline | latest-runnable | 6.19 | x86_64 | virtme-ng | kernel is built/booted at run time (no vendor image) |
| kernelorg-lts-5.15 | upstream-mainline | lts | 5.15 | x86_64 | virtme-ng | kernel is built/booted at run time (no vendor image) |
| kernelorg-lts-6.1 | upstream-mainline | lts | 6.1 | x86_64 | virtme-ng | kernel is built/booted at run time (no vendor image) |

## Cataloged, not runnable on the current executor

Tracked for coverage but not bootable via the SSH/cloud-init executor
today (immutable/image-based systems, or a known executor limitation).
These are marked non-blocking wherever they appear in a matrix.

| Profile ID | Distro | Version | Kernel family | Arch | Transport / runner | Notes |
|---|---|---|---|---|---|---|
| amazon-linux-2-4.14 | amazon-linux | 2 | 4.14 | x86_64 | ssh | cataloged; not bootable on current SSH/cloud-init executor |
| bottlerocket-aws-6.1 | bottlerocket | aws | 6.1 | x86_64 | immutable image | no SSH/cloud-init transport on current executor |
| flatcar-6.6 | flatcar | stable | 6.6 | x86_64 | immutable image | no SSH/cloud-init transport on current executor |
| talos-6.6 | talos | 1.12 | 6.6 | x86_64 | immutable image | no SSH/cloud-init transport on current executor |
