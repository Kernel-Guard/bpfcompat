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

| OpenShift | RHCOS bootimage | RHEL base | Kernel (`uname -r`) | Kernel BTF |
|---|---|---|---|---|
| 4.14 | `414.92.202407091253` | 9.2 | `5.14.0-284.73.1.el9_2.x86_64` | present |
| 4.16 | `416.94.202510081640` | 9.4 | `5.14.0-427.93.1.el9_4.x86_64` | present |
| 4.18 | `418.94.202510081222` | 9.4 | `5.14.0-427.93.1.el9_4.x86_64` | present |

Note the OCP minor does **not** track the kernel linearly: 4.16 and 4.18 share
the RHEL 9.4 `-427` kernel, while 4.14 is RHEL 9.2 `-284`. That is exactly the
"version number predicts nothing" property bpfcompat tests by booting the real
vendor kernel. (The mirror's `4.18/latest` bootimage is RHEL-9.4-based; later
4.18 z-streams may move to 9.6 — the table records the bootimage actually run.)

## Matrix result (3 artifacts × 3 releases, real boots)

| Artifact | What it exercises | 4.14 | 4.16 | 4.18 |
|---|---|---|---|---|
| `simple-pass` | baseline program load | ✅ load | ✅ load | ✅ load |
| `ringbuf-modern` | BPF ring buffer (upstream ≥ 5.8) + attach | ✅ load + attach 1/1 | ✅ load + attach 1/1 | ✅ load + attach 1/1 |
| `core-relocation-fail` | CO-RE relocation to a non-existent type | ❌ **rejected** | ❌ **rejected** | ❌ **rejected** |

Two things this proves:

1. **Backports work, tested not inferred.** The ring buffer lands upstream in
   5.8, yet `ringbuf-modern` loads *and attaches* on RHCOS's backported 5.14
   (both RHEL 9.2 and 9.4) — because the verdict comes from the real kernel.
2. **The verdict discriminates.** `core-relocation-fail` is **rejected on every
   release** with `errno -22` and classification `CORE_RELOCATION_FAILURE` — so
   the passes above are real acceptances, not a rubber stamp. (Its matrix targets
   are non-blocking, so they record a per-target failure without failing the run.)

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
`mirror.openshift.com/pub/openshift-v4/x86_64/dependencies/rhcos/<ver>/latest/`.
The pull secret gates the container release payload, **not** these boot qcow2s.
Decompressed qcow2 sha256 (as run):

| OpenShift | image | sha256 (decompressed qcow2) |
|---|---|---|
| 4.14 | `rhcos-4.14.34-x86_64-qemu.x86_64.qcow2` | `6d271daf23242570520891cc8013d7ab3e2fa5ab8ab9d37485b28b72ab61e99f` |
| 4.16 | `rhcos-4.16.51-x86_64-qemu.x86_64.qcow2` | `d03128234c5dc6217bd37ee0caf6f192107d42d39a8a6b5c9b6148b0f4f92399` |
| 4.18 | `rhcos-4.18.27-x86_64-qemu.x86_64.qcow2` | `a6f870c3fb8f5039962978980cf6a5a11cd2973a35fc2b2938106658983b18d6` |

## Honest limits

- **x86_64 only.** OpenShift on ARM (aarch64) is real but not covered here — it
  needs an ARM64-capable KVM host and an aarch64 RHCOS bootimage. Not yet run.
- **Not in public CI.** RHCOS is operator-supplied by design (no bundled image),
  so it does not run on every PR like the Ubuntu/FCOS lanes; this matrix is a
  recorded, reproducible operator run.
- **Bootimage, not a live cluster.** This validates the node OS + kernel, not
  OpenShift-cluster-specific MachineConfig state.

## Reproduce

```sh
b=https://mirror.openshift.com/pub/openshift-v4/x86_64/dependencies/rhcos
for v in 4.14 4.16 4.18; do
  url=$(curl -fsSL "$b/$v/latest/sha256sum.txt" | awk '/qemu.x86_64.qcow2.gz$/{print "'"$b"'/'"$v"'/latest/"$2; exit}')
  make rhcos-image RHCOS_VERSION="$v" RHCOS_IMAGE_URL="$url"   # → vm/cache/rhcos-$v.qcow2
done

for art in simple-pass/simple_pass ringbuf-modern/ringbuf_modern core-relocation-fail/core_relocation_fail; do
  BPFCOMPAT_ENABLE_RHCOS=1 ./bin/bpfcompat test \
    -artifact examples/$art.bpf.o -matrix matrices/rhcos.yaml -runner vm \
    -concurrency 3 -out report-$(basename $art).json
done
```

`RHCOS_VERSION` selects both the cache slot (`vm/cache/rhcos-<ver>.qcow2`) and the
matching profile in `matrices/rhcos.yaml`. `core-relocation-fail` is expected to
be rejected — that is the discriminator, not a regression.
