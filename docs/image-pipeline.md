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
- Some cataloged profiles (Talos, Bottlerocket, Flatcar, Amazon Linux 2
  with 4.14) are not runnable on the current SSH/cloud-init executor and
  are marked non-blocking in matrices.
- ARM64 image entries exist but need a native ARM64 KVM runner.
