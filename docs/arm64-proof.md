# ARM64 Proof Boundary

`bpfcompat` has two ARM64 lanes:

| Lane | What it proves | Command/workflow |
|---|---|---|
| ARM64 build smoke | The Go CLI, C validator, and ARM64 BPF examples compile on a native ARM64 userspace. | `.github/workflows/arm64-build-smoke.yml` |
| ARM64 VM validation | The artifact loads/attaches inside an ARM64 Linux VM with ARM64 KVM. | `.github/workflows/multiarch-compatibility.yml`, `make acceptance-arm64-smoke` |

The second lane requires a real ARM64/aarch64 KVM host. An x86_64 VM, including
the current Azure demo VM, cannot honestly prove ARM64 KVM behavior.

## Local Preflight

```bash
make arm64-kvm-preflight
```

This checks:

- host architecture is `aarch64`/`arm64`;
- `/dev/kvm` exists and is readable/writable;
- `qemu-system-aarch64` is installed.

If it passes, run:

```bash
make acceptance-arm64-smoke
```

If it fails on x86_64, use the hosted ARM64 build smoke for compile proof and a
self-hosted ARM64 KVM runner for real VM-backed validation.
