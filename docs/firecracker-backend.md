# Firecracker Backend

`bpfcompat` has an executable Firecracker runner:

```bash
./bin/bpfcompat test --runner firecracker ...
```

This backend builds a generated initramfs containing static BusyBox,
`bpfcompat-validator`, the uploaded `.bpf.o`, and optional manifest/functional
plan files. The guest `/init` script runs the validator inside the microVM,
prints the validator result JSON between serial-console markers, and the host
extracts that output into the normal JSON/Markdown report path.

## Why This Is Separate From QEMU

Firecracker is not a drop-in replacement for the current SSH/cloud-init QEMU
runner. Firecracker needs:

- read/write access to `/dev/kvm`;
- a Firecracker release binary;
- an uncompressed guest kernel image;
- a static BusyBox on the host for generated initramfs construction;
- `cpio` and `gzip`;
- explicit networking through TAP if SSH is used;
- production isolation through `jailer` or equally restrictive process
  constraints.

Those requirements match Firecracker's official getting-started and production
host guidance.

## Preflight

Install the official release binary locally:

```bash
make firecracker-install
```

This writes `bin/firecracker` and, when present in the release archive,
`bin/jailer`. The preflight and Go executor also honor
`BPFCOMPAT_FIRECRACKER_BIN` for an operator-managed binary path.

```bash
make firecracker-preflight
```

Optional kernel check:

```bash
export BPFCOMPAT_FIRECRACKER_KERNEL=/abs/path/vmlinux
make firecracker-preflight
```

For a local runnable proof, fetch a Firecracker CI kernel and generate a local
profile/matrix:

```bash
make firecracker-kernel-install
make firecracker-runnable
make acceptance-firecracker-dev-one
```

## Profile Shape

```yaml
id: firecracker-upstream-6.8
distro: upstream-mainline
version: firecracker-alpha
kernel_family: "6.8"
arch: x86_64
runner: firecracker
firecracker:
  kernel_image_path: /abs/path/vmlinux
  boot_args: "console=ttyS0 reboot=k panic=1 pci=off init=/init"
  tap_device: tap0
  guest_mac: "06:00:AC:10:00:02"
boot:
  memory_mb: 1024
  cpus: 1
validator:
  path: /bpfcompat/bin/bpfcompat-validator
capabilities:
  expected_btf: true
```

## Current Status

Implemented:

- `firecracker` runner option;
- Firecracker profile validation;
- Firecracker config generation;
- generated initramfs validator transport;
- serial marker result extraction;
- host/resource preflight script;
- local acceptance target: `make acceptance-firecracker-dev-one`;
- documentation of the production boundary.

Not implemented yet:

- jailer-managed execution;
- benchmark comparison against QEMU/KVM and `virtme-ng`.
- TAP/SSH orchestration for richer guest workflows.

Recommended next implementation step:

Benchmark Firecracker versus QEMU/KVM and `virtme-ng`, then decide whether
Firecracker should become the default high-scale CI worker backend. Production
deployments should still add jailer/cgroup policy, image provenance, and worker
pool controls before taking untrusted jobs.
