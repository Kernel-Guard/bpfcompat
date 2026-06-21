# Reference matrix: enterprise & backported kernels

Enterprise distros heavily **backport** eBPF features onto old kernel bases, so the
kernel version alone does not predict support (RHEL 8's `4.18` carries many 5.x BPF
features; Amazon Linux 2 ships `4.14`/`5.10`). bpfcompat boots the **real distro
cloud image and its actual kernel**, so this is tested directly — not inferred from
an upstream version.

This is a real run across the now-supported enterprise tier.

- **Artifact:** `examples/simple-pass/simple_pass.bpf.o` (sha256 `3be1708f…8876`)
- **Mode:** `load_attach`, inside disposable QEMU/KVM VMs (one per profile)
- **Date:** 2026-06-21 · Run ID `20260621T102403Z-a20af3`
- **Host:** x86_64 KVM

## Result — 14 / 14 pass

| Profile | Actual host kernel | BTF | Result |
|---|---|---|---|
| `almalinux-8-4.18` | `4.18.0-553.124.4.el8_10` | yes | ✅ pass |
| `rocky-8-4.18` | `4.18.0-553.el8_10` | yes | ✅ pass |
| `almalinux-9-5.14` | `5.14.0-687.5.3.el9_8` | yes | ✅ pass |
| `rocky-9-5.14` | `5.14.0-687.10.1.el9_8` | yes | ✅ pass |
| `centos-stream-9-5.14` | `5.14.0-710.el9` | yes | ✅ pass |
| `almalinux-10-6.12` | `6.12.0-211.7.3.el10_2` | yes | ✅ pass |
| `rocky-10-6.12` | `6.12.0-211.16.1.el10_2` | yes | ✅ pass |
| `centos-stream-10-6.12` | `6.12.0-233.el10` | yes | ✅ pass |
| `oracle-linux-9-uek7-5.15` | `6.12.0-107.59.3.3.el9uek` | yes | ✅ pass |
| `oracle-linux-10-uek8-6.12` | `6.12.0-107.59.3.3.el10uek` | yes | ✅ pass |
| `amazon-linux-2-5.10` | `5.10.247-246.989.amzn2` | yes | ✅ pass |
| `amazon-linux-2023-6.1` | `6.1.170-213.321.amzn2023` | yes | ✅ pass |
| `opensuse-leap-15.6-6.4` | `6.4.0-150600.23.100-default` | yes | ✅ pass |
| `amazon-linux-2-4.14` | `4.14.26-54.32.amzn2` | **no** | ✅ pass |

## The no-BTF backport case: Amazon Linux 2 / 4.14

The 2018-era Amazon Linux 2 (`4.14`, **no embedded BTF**) image was previously
excluded as `UNSUPPORTED_TRANSPORT`. The CIDATA seed fix plus dropping that stale
exclusion brought it online: it now boots and validates `load_attach` on a real
`4.14.26-54.32.amzn2` kernel — the heavily-backported, no-BTF case where kernel
version is least informative about feature support.

## Notes

- RHEL itself (`rhel-8-4.18`) is a BYO-image profile (subscription-walled, no public
  image). **AlmaLinux/Rocky/CentOS-Stream** are the free, public, ABI-compatible
  rebuilds used here as the reproducible RHEL stand-in.
- `simple_pass` is a minimal program — a pass proves the toolchain boots that exact
  backported kernel and successfully loads+attaches an eBPF object on it. Per-feature
  boundaries (e.g. ring buffer < 5.8) show up when validating real probes; see
  [case-study-falco-modern-bpf.md](case-study-falco-modern-bpf.md).
- Independent test of public distro images; not affiliated with or endorsed by Red
  Hat, AlmaLinux, Rocky, Oracle, Amazon, or SUSE.

## Reproduce

```bash
# host needs /dev/kvm and cloud-image-utils (cloud-localds) for EL/Amazon/SUSE seeds
bpfcompat test --artifact build/program.bpf.o \
  --matrix matrices/tier1-enterprise-cloud.yaml \
  --out reports/enterprise.json --markdown reports/enterprise.md \
  --validation-mode load_attach --concurrency 3
```
