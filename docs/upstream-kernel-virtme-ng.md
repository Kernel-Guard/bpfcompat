# Upstream Kernel Testing With virtme-ng

`bpfcompat` has two kernel validation lanes:

| Lane | Backend | Purpose |
|---|---|---|
| Distro matrix | QEMU/KVM cloud images | Validate against customer-like distro kernels, userspace, BTF state, and packaging differences. |
| Upstream kernel matrix | `virtme-ng` | Validate against bootable upstream-mainline kernels without waiting for distro images. |

The upstream lane is an alpha backend. It is useful for early regression
detection, but the QEMU/KVM distro lane remains the default customer
compatibility proof.

## Requirements

- Linux host with `/dev/kvm`
- `vng` from `virtme-ng`
- `qemu-system-x86_64`
- `curl`
- `jq`
- normal build dependencies from `make doctor`

Check the host:

```bash
make doctor-virtme
```

## Generate Runnable Upstream Targets

```bash
make upstream-kernel-runnable
```

This reads `https://www.kernel.org/releases.json` for current release context,
checks `https://kernel.ubuntu.com/mainline/` for `virtme-ng` prebuilt kernels,
preflight-boots candidate kernels with `/bin/true`, and writes:

- generated profiles: `vm/profiles/kernelorg-*.yaml`
- generated matrix: `matrices/upstream-kernel-runnable.yaml`

The generated files are intentionally ignored by git because they change as
upstream releases and local `virtme-ng` bootability change. If the newest exact
kernel.org patch or RC is not bootable through the installed `vng`, the generator
selects the newest runnable upstream-mainline major/minor kernel and logs the
skipped candidate.

## Run The Upstream Kernel Sweep

```bash
make acceptance-upstream-kernel
```

Equivalent CLI form:

```bash
./bin/bpfcompat test \
  --runner virtme-ng \
  --artifact examples/functional-execve/functional_execve.bpf.o \
  --manifest examples/functional-execve/manifest-upstream-kernel.yaml \
  --matrix matrices/upstream-kernel-runnable.yaml \
  --out reports/functional-execve-upstream-kernel.json \
  --markdown reports/functional-execve-upstream-kernel.md \
  --timeout 20m \
  --concurrency 1
```

## Current Scope

Implemented:

- explicit `--runner virtme-ng`
- boot-aware generated upstream-mainline profiles
- normal JSON/Markdown compatibility reports
- local artifact history/provenance reuse
- GitHub workflow: `.github/workflows/upstream-kernel-compatibility.yml`

Not implemented yet:

- building arbitrary kernel source trees through `vng --build`
- linux-next source-tree execution
- ARM64 upstream-kernel validation
- Firecracker backend

For ARM64, use `.github/workflows/arm64-build-smoke.yml` for native ARM64
compile proof and `.github/workflows/multiarch-compatibility.yml` on a real
ARM64 self-hosted KVM runner for VM-backed validation.
