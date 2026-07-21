# Image and Profile Pipeline

This document describes where every kernel/distro image used by `bpfcompat`
comes from, how it is cached and integrity-checked, and how to add a new
profile. The goal is that anyone can reproduce a compatibility matrix from
scratch — or verify exactly which image bytes produced a past result.

## Design position

`bpfcompat` does **not** build custom OS images. Profiles reference
unmodified upstream vendor cloud images (Ubuntu cloud images, Debian cloud
images, AlmaLinux/Rocky GenericCloud, Amazon Linux KVM images, Oracle UEK
images, openSUSE Leap, and so on). This is deliberate:

- Distro kernels carry vendor patches and backports that diverge from
  upstream — testing the vendor's own published image tests the kernel your
  users actually run, which custom-built images cannot do.
- Every image is independently obtainable from the vendor: there is no
  private build step between "what the vendor ships" and "what was tested".

The trade-off is that vendor `current/` URLs mutate over time. The
mechanisms below exist to make that explicit and controllable.

## Profile anatomy

Each target is one YAML file under `vm/profiles/`:

```yaml
id: ubuntu-22.04-5.15
distro: ubuntu
version: "22.04"
kernel_family: "5.15"
arch: x86_64
image:
  source_url: "https://cloud-images.ubuntu.com/jammy/current/jammy-server-cloudimg-amd64.img"
  local_path: "vm/cache/ubuntu-22.04.qcow2"
  # Optional: pin the exact image. Requires a release-versioned source_url;
  # "current" URLs mutate and will eventually fail the pin (by design).
  # sha256: "<digest>"
boot:
  memory_mb: 1024
  cpus: 1
```

Matrices (`matrices/*.yaml`) select sets of profile ids; the tiering
rationale is in [`profile-catalog.md`](profile-catalog.md).

## Integrity: recorded always, pinned optionally

- **Recording (always):** the first time an image is used, its sha256 is
  computed and cached in a `<image>.sha256` sidecar next to the file in
  `vm/cache/`. Every VM target's report notes include
  `base image sha256: …`, so any past matrix result is attributable to
  exact image bytes even when the vendor URL has since changed.
- **Pinning (opt-in):** setting `image.sha256` in a profile makes a
  mismatching download or cached file fail the run instead of silently
  testing different bytes. Use pinning with release-versioned URLs
  (for example `releases/22.04/release-20260601/...` instead of
  `current/`).

## Acquisition and caching

Images download on first use into `vm/cache/` (never committed). Bulk
prefetch targets:

```bash
make vm-images                    # MVP matrix images
make vm-images-extended           # extended catalog
make vm-images-tier1              # enterprise/cloud tier
make vm-images-expanded-2026      # full expanded campaign
make vm-images-expanded-2026-dry-run
```

Manual/licensed images (SLES, Bottlerocket, Talos, mainline archives) have
no public URL; import them explicitly:

```bash
make import-required-images SLES156_IMG=/abs/path/sles15.6.qcow2
make manual-image-check
```

## Audit and readiness

- `make profile-catalog-audit` — validates every profile's source URL is
  still reachable and records audit evidence.
- `make matrix-readiness` — reports which matrix profiles are runnable
  right now (image cached + executor transport supported).
- `.github/workflows/profile-catalog-maintenance.yml` — runs the audit on a
  schedule so dead vendor URLs surface as CI signal, not as a failed run.
- `go test ./internal/vm -run TestAllProfileYAMLLoadAndValidate` —
  validates profile YAML integrity.

## Kernel freshness vs kernel-crawler

A cached image keeps producing matrix evidence for the kernel it shipped
with, even after the distro has moved on. The freshness oracle makes that
drift visible by comparing each profile's last-validated kernel release
against the per-distro kernel inventory that
[falcosecurity/kernel-crawler](https://github.com/falcosecurity/kernel-crawler)
publishes weekly ([per-arch `list.json`](https://falcosecurity.github.io/kernel-crawler/)):

```bash
./bin/bpfcompat kernel-freshness                 # download inventory, print table
./bin/bpfcompat kernel-freshness --fail-on-stale # exit 2 when evidence is behind
```

- `vm/kernel-baselines.yaml` (committed) records the last-validated kernel
  per profile plus its crawler mapping: distro key, target flavor
  (`ubuntu-generic` vs `ubuntu-kvm`), a `release_prefix` pinning the series,
  and an optional `release_contains` for distros that mix major releases
  under one key (`el9` vs `el10`).
- After a matrix run, refresh the baselines from the report:
  `bpfcompat kernel-freshness --update-from-report reports/<run>.json`.
  Profiles the file doesn't know yet are appended without a mapping and
  show up as `uncovered` until one is added.
- `.github/workflows/kernel-freshness.yml` runs the comparison weekly
  (after kernel-crawler's own Monday refresh) as a non-blocking signal
  lane. Stale profiles keep the run green and file (or refresh) a single
  "Stale kernel baselines" tracking issue that closes itself once
  everything is fresh again; a red run is reserved for the oracle itself
  breaking (crawler unreachable, invalid baselines file). Never a blocked
  merge either way.
- Statuses are honest about coverage limits: `uncovered` (kernel-crawler
  publishes no Debian entries, for example), `no-entries` (EOL series the
  archive dropped), and `no-kernel` (profile never validated) are reported
  distinctly from `stale`.
- `covered` is the family-aware status. A stock cloud image can never ship
  a kernel newer than itself, while the crawler tracks the newest *package*,
  so an image-based profile would otherwise be flagged `stale` forever
  through no fault of ours. When a
  [kernel-sweep](#dense-kernel-sweeps-one-image-many-kernels)
  profile in the same family (`<base>-k<release>`) has already installed and
  validated the newest kernel, the base profile reports `covered` — naming
  the profile that proves it — and is not counted as stale. Sibling variants
  stay independent: `ubuntu-22.04-5.15-lockdown` is only covered by its own
  `…-lockdown-k…` derivatives, never by plain `ubuntu-22.04-5.15` ones.

The crawler indexes header packages, not bootable images, so it serves as
a freshness oracle only — the boot substrate stays unmodified vendor cloud
images.

## Generated lanes (no prebuilt image at all)

Two lanes construct their environment at run time instead of downloading a
distro image:

- **virtme-ng upstream lane**: `make upstream-kernel-runnable` queries
  kernel.org for current mainline/RC/LTS releases and *generates* profiles
  (`matrices/upstream-kernel-runnable.yaml`); virtme-ng builds/boots the
  kernel directly. Reproducibility comes from the recorded kernel release
  context, not an image digest.
- **Firecracker lane**: `make firecracker-runnable` generates profiles
  around a host-local uncompressed kernel plus a busybox initramfs that
  bpfcompat assembles on the fly (see
  [`firecracker-backend.md`](firecracker-backend.md)). The validator and
  artifact are injected into the generated initramfs; nothing opaque is
  downloaded.

## Dense kernel sweeps (one image, many kernels)

A cloud image boots exactly one kernel release, so image-per-profile
matrices sample a kernel series at one point. The sweep lane densifies
that: a generated profile sets `install_kernel` plus `kernel_packages`
(direct archive-pool `.deb` URLs), and the executor downloads and installs
that exact release inside the guest (dpkg), pins it as the grub default,
reboots into it (QEMU runs with `-no-reboot`, so the reboot exits the
first QEMU process and the executor relaunches it on the same overlay),
verifies `uname -r`, and only then validates. The overlay is grown +4G
before boot — cloud images ship near-full rootfs, and cloud-init's
growpart expands the partition to fit the kernel install.

Direct pool URLs matter: package indexes only carry the *current* ABI, so
superseded kernel releases remain downloadable in the archive pool but are
invisible to `apt-get install` / `dnf install <name>`. The kernel-crawler
inventory records pool URLs per release, which is exactly what makes dense
sweeps possible — the generator derives the real package URLs from the
crawler's headers URLs. The base image stays an unmodified vendor image;
the kernel packages come from the distro's own archive.

The derivation differs per family. Ubuntu's headers `.deb` sits in the same
pool directory as the image and modules `.deb`s, so only the file name
changes. RHEL-family crawler entries publish `kernel-devel` from
**AppStream**, while the packages that actually boot (`kernel-core` plus
modules) live in **BaseOS**, so the component is swapped too — the mirror,
repository version, architecture and any per-letter subdirectory
(Rocky's `Packages/k/`) are inherited from the headers URL.

Generate the profiles and matrix from the crawler inventory:

```bash
./bin/bpfcompat kernel-sweep --profile ubuntu-22.04-5.15 --count 4
./bin/bpfcompat test --artifact app.bpf.o \
  --matrix matrices/kernel-sweep-ubuntu-22.04-5.15.yaml \
  --out reports/sweep.json --timeout 20m
```

This writes `vm/profiles/<base>-k<release>.yaml` per release (newest
first) plus `matrices/kernel-sweep-<base>.yaml`. Targets need generous
timeouts: the package download and reboot add minutes per kernel.

The crawler mapping (distro key, target flavor, release prefix, and the
`release_contains` that separates `el9` from `el10`) is read from
`vm/kernel-baselines.yaml` for the base profile, so a sweep of
`ubuntu-22.04-minimal-5.15` correctly uses the `ubuntu-kvm` flavor rather
than `ubuntu-generic`. `--target` and `--series` override it.

Supported families: **Debian** (`apt`/`dpkg`, boot selected via grub menu
titles) and **RHEL** — AlmaLinux, Rocky, CentOS Stream — (`dnf`, boot
selected with `grubby --set-default`, which matches on the vmlinuz path
rather than a menu string). Deliberately unsupported: Oracle Linux (UEK
ships from its own repositories, not BaseOS), Amazon Linux (kernels are
not published in a browsable pool the crawler maps to), and the
immutable/image-based systems (RHCOS, Fedora CoreOS, Flatcar, Bottlerocket,
Talos), whose kernels are part of the image rather than packages.

## Adding a profile (checklist)

1. Find the vendor's cloud image URL — prefer a release-versioned URL over
   `current/`.
2. Create `vm/profiles/<id>.yaml` with `id`, `distro`, `version`,
   `kernel_family`, `arch`, `image.source_url`, `image.local_path`
   (under `vm/cache/`), and boot resources. Add `image.sha256` if the URL
   is release-versioned.
3. Run `go test ./internal/vm -run TestAllProfileYAMLLoadAndValidate`.
4. Add the profile id to the appropriate matrix in `matrices/` and tier in
   [`profile-catalog.md`](profile-catalog.md).
5. Run `make profile-catalog-audit` and a single-profile smoke:
   `./bin/bpfcompat test --artifact examples/simple-pass/simple_pass.bpf.o
   --matrix <your-matrix> ...`.

Cloud-init differences are handled by profile fields (SSH user candidates,
NoCloud seed delivery mode); see existing RHEL/Amazon Linux profiles for
non-default examples.

## Known gaps (roadmap)

- No multi-version pinned catalog yet: profiles track one URL each, so
  pinning everything to release-versioned URLs needs a refresh routine
  (candidate: extend `profile-catalog-maintenance.yml` to propose pin
  bumps as PRs).
- The freshness oracle flags profiles whose evidence is behind, but
  refreshing is still manual (re-download image, re-run matrix,
  `--update-from-report`). A follow-up could automate that as a proposed
  PR.
- Some cataloged profiles (Talos, Bottlerocket, Flatcar, Amazon Linux 2
  with 4.14) are not runnable on the current SSH/cloud-init executor and
  are marked non-blocking in matrices.
- ARM64 image entries exist but need a native ARM64 KVM runner.
