# Evidence: RHEL CoreOS (OpenShift) validation matrix

Real validation runs of compiled eBPF artifacts **inside booted RHEL CoreOS
guests**, across multiple OpenShift releases. Committed as evidence behind the
opt-in RHCOS path documented in [docs/rhcos-openshift.md](rhcos-openshift.md).
Reproduce with the steps at the bottom.

> Raw run artifacts (full `report.json`, `validator-result.json`, serial logs)
> are written under `evidence/rhcos/` locally; that path is git-ignored as
> high-churn output, so the decisive fields are inlined here.

## Releases under test

Each row is a real RHCOS bootimage from the public OpenShift mirror, booted via
Ignition (`-fw_cfg name=opt/com.coreos/config`), SSH as `core`. The RHCOS
version encodes the RHEL base (e.g. `416.94` = OpenShift 4.16 on RHEL 9.4), and
the kernel column is the **in-guest `uname -r`** captured at run time.

| OpenShift | Arch | RHCOS bootimage | RHEL base | Kernel (`uname -r`) | Kernel BTF |
|---|---|---|---|---|---|
| 4.14 | x86_64 | `414.92.202407091253` | 9.2 | `5.14.0-284.73.1.el9_2.x86_64` | present |
| 4.16 | x86_64 | `416.94.202510081640` | 9.4 | `5.14.0-427.93.1.el9_4.x86_64` | present |
| 4.18 | x86_64 | `418.94.202510081222` | 9.4 | `5.14.0-427.93.1.el9_4.x86_64` | present |
| 4.16 | **aarch64** | `416.94.202501270445` | 9.4 | `5.14.0-427.50.1.el9_4.aarch64` | present |

Note the OCP minor does **not** track the kernel linearly: 4.16 and 4.18 share
the RHEL 9.4 `-427` kernel, while 4.14 is RHEL 9.2 `-284`. That is exactly the
"version number predicts nothing" property bpfcompat tests by booting the real
vendor kernel. (The mirror's `4.18/latest` bootimage is RHEL-9.4-based; later
4.18 z-streams may move to 9.6 — the table records the bootimage actually run.)

## x86_64 matrix (6 artifacts × 3 releases, real boots)

| Artifact | What it exercises | 4.14 (9.2) | 4.16 (9.4) | 4.18 (9.4) |
|---|---|---|---|---|
| `simple-pass` | baseline program load | ✅ load+attach | ✅ load+attach | ✅ load+attach |
| `ringbuf-modern` | tracepoint + ring buffer (upstream ≥ 5.8) | ✅ load+attach | ✅ load+attach | ✅ load+attach |
| `perfbuf-fallback` | tracepoint + perf-event buffer | ✅ load+attach | ✅ load+attach | ✅ load+attach |
| `attach-warn` | kprobe to a missing symbol | ✅ load / attach warn | ✅ load / attach warn | ✅ load / attach warn |
| `aegis` | **BPF-LSM** (4 hooks) + tracepoint | ❌ **rejected** (`CAPABILITY_FAILURE`, −13) | ✅ **load + attach 4/4** | ✅ **load + attach 4/4** |
| `core-relocation-fail` | CO-RE to a non-existent type (negative) | ❌ rejected (`CORE_RELOCATION_FAILURE`, −22) | ❌ rejected | ❌ rejected |

Three things this proves:

1. **Backports work, tested not inferred.** Ring buffer lands upstream in 5.8,
   yet `ringbuf-modern` loads *and attaches* on RHCOS's backported 5.14 (RHEL 9.2
   and 9.4) — the verdict comes from the real kernel, and perf-buffer + kprobe +
   tracepoint program types all behave too.
2. **A real capability boundary only a real boot finds.** The BPF-LSM artifact
   `aegis` is **rejected on 4.14 (RHEL 9.2)** with `EPERM` / `CAPABILITY_FAILURE`
   but **loads and attaches all 4 LSM hooks on 4.16 / 4.18 (RHEL 9.4)**. Same
   nominal kernel line (5.14), different backport: BPF-LSM is active in 9.4 but
   not 9.2. Version inference would miss this entirely.
3. **The verdict discriminates.** `core-relocation-fail` is rejected on every
   release (`errno −22`, `CORE_RELOCATION_FAILURE`), so the passes above are real
   acceptances, not a rubber stamp. (Negative-case targets are non-blocking, so
   they record a per-target failure without failing the run.)

## aarch64 matrix (cross-arch, real boot)

OpenShift on ARM is real in enterprise, so the suite covers it too. RHCOS 4.16
aarch64 was booted on an x86_64 host under **QEMU TCG** (software emulation —
slower, but a genuine aarch64 kernel and a real `bpf()` load):

| Artifact | OpenShift 4.16 aarch64 (`5.14.0-427.50.1.el9_4.aarch64`) |
|---|---|
| `ringbuf-modern` | ✅ **load + attach 1/1** |

This exercised the full aarch64 path: cross-compiled aarch64 validator, EDK II
(AAVMF) UEFI firmware via pflash, Ignition over `-fw_cfg`, SSH as `core`, and a
real ring-buffer load+attach inside the aarch64 guest. On a native ARM64 KVM
host the same run uses hardware acceleration automatically.

## In-guest validator output (representative — 4.16, ring buffer)

```json
{
  "schema_version": "validator.v0.4",
  "status": "pass",
  "host": { "release": "5.14.0-427.93.1.el9_4.x86_64", "machine": "x86_64" },
  "load":   { "status": "pass", "error_code": 0, "error": "" },
  "attach": { "mode": "best-effort", "status": "pass", "attempted": 1, "passed": 1, "failed": 0 },
  "btf":    { "kernel_btf_available": true, "artifact_has_btf": true }
}
```

Rejection record (representative — 4.14, CO-RE failure):

```json
{
  "status": "fail",
  "host": { "release": "5.14.0-284.73.1.el9_2.x86_64" },
  "load": { "status": "fail", "error_code": -22 },
  "classification_code": "CORE_RELOCATION_FAILURE"
}
```

## Guest serial console (excerpt, ANSI stripped — 4.16)

```
GRUB:  Booting `Red Hat Enterprise Linux CoreOS 416.94.202510081640-0 (ostree:0)'
[0.000000] Linux version 5.14.0-427.93.1.el9_4.x86_64 ... #1 SMP PREEMPT_DYNAMIC
[0.000000] Command line: ... ignition.firstboot ... ignition.platform.id=qemu console=ttyS0,115200n8
Welcome to Red Hat Enterprise Linux CoreOS 416.94.202510081640-0 (Initramfs)!
[1.291367] systemd[1]: Starting CoreOS Ignition User Config Setup...
[  OK  ] Finished CoreOS Ignition User Config Setup.
```

## Provenance

Images: public OpenShift mirror,
`mirror.openshift.com/pub/openshift-v4/<arch>/dependencies/rhcos/<ver>/latest/`.
The pull secret gates the container release payload, **not** these boot qcow2s.
Decompressed qcow2 sha256 (as run):

| OpenShift | image | sha256 (decompressed qcow2) |
|---|---|---|
| 4.14 x86_64 | `rhcos-4.14.34-x86_64-qemu.x86_64.qcow2` | `6d271daf23242570520891cc8013d7ab3e2fa5ab8ab9d37485b28b72ab61e99f` |
| 4.16 x86_64 | `rhcos-4.16.51-x86_64-qemu.x86_64.qcow2` | `d03128234c5dc6217bd37ee0caf6f192107d42d39a8a6b5c9b6148b0f4f92399` |
| 4.18 x86_64 | `rhcos-4.18.27-x86_64-qemu.x86_64.qcow2` | `a6f870c3fb8f5039962978980cf6a5a11cd2973a35fc2b2938106658983b18d6` |
| 4.16 aarch64 | `rhcos-4.16.36-aarch64-qemu.aarch64.qcow2` | `7af80164e48fee2ec60901e54494081837f896f909abdedf8a7d1bb7ce1488ac` |

## Honest limits

- **aarch64 here ran under TCG** (software emulation) because the host is x86_64.
  The kernel and `bpf()` load are genuine, just slow; a native ARM64 KVM host
  runs it with hardware acceleration (the executor selects KVM automatically when
  the guest arch matches the host).
- **Not in public CI.** RHCOS is operator-supplied by design (no bundled image),
  so it does not run on every PR like the Ubuntu/FCOS lanes; this matrix is a
  recorded, reproducible operator run.
- **Bootimage, not a live cluster.** This validates the node OS + kernel, not
  OpenShift-cluster-specific MachineConfig state.

## Reproduce

x86_64 (6-artifact matrix across releases):

```sh
b=https://mirror.openshift.com/pub/openshift-v4/x86_64/dependencies/rhcos
for v in 4.14 4.16 4.18; do
  url=$(curl -fsSL "$b/$v/latest/sha256sum.txt" | awk '/qemu.x86_64.qcow2.gz$/{print "'"$b"'/'"$v"'/latest/"$2; exit}')
  make rhcos-image RHCOS_VERSION="$v" RHCOS_IMAGE_URL="$url"   # → vm/cache/rhcos-$v.qcow2
done

for art in simple-pass/simple_pass ringbuf-modern/ringbuf_modern perfbuf-fallback/perfbuf_fallback \
           attach-warn/attach_warn aegis-live/aegis core-relocation-fail/core_relocation_fail; do
  BPFCOMPAT_ENABLE_RHCOS=1 ./bin/bpfcompat test \
    -artifact examples/$art.bpf.o -matrix matrices/rhcos.yaml -runner vm \
    -concurrency 3 -out report-$(basename $art).json
done
```

aarch64 (needs an aarch64 validator + qemu-system-aarch64 + UEFI firmware
`qemu-efi-aarch64`; KVM on an ARM64 host, else TCG):

```sh
b=https://mirror.openshift.com/pub/openshift-v4/aarch64/dependencies/rhcos
url=$(curl -fsSL "$b/4.16/latest/sha256sum.txt" | awk '/qemu.aarch64.qcow2.gz$/{print "'"$b"'/4.16/latest/"$2; exit}')
make rhcos-image RHCOS_VERSION=4.16-arm64 RHCOS_IMAGE_URL="$url"   # → vm/cache/rhcos-4.16-arm64.qcow2
# build the aarch64 validator (aarch64-linux-gnu-gcc + arm64 static libs) and point the run at it
BPFCOMPAT_ENABLE_RHCOS=1 ./bin/bpfcompat test \
  -artifact examples/ringbuf-modern/ringbuf_modern.bpf.o -matrix matrices/rhcos-arm64.yaml -runner vm
```

`RHCOS_VERSION` selects the cache slot (`vm/cache/rhcos-<ver>.qcow2`); the
matching profile lives in `matrices/rhcos.yaml` (x86_64) or
`matrices/rhcos-arm64.yaml` (aarch64). `aegis` rejected on 4.14 and
`core-relocation-fail` rejected everywhere are expected — they are the
discriminators, not regressions.
