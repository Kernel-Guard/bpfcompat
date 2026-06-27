# RHEL CoreOS / OpenShift validation

bpfcompat can validate a compiled eBPF artifact **inside a real RHEL CoreOS
(RHCOS) guest** — the immutable node OS used by OpenShift. This is opt-in and
needs an operator-supplied image; the rest of this page is how and why.

## TL;DR

```sh
# 1. Stage an RHCOS qemu image (see "Getting the image" for how to obtain a URL).
make rhcos-image RHCOS_IMAGE_URL="https://.../rhcos-...-qemu.x86_64.qcow2.gz"
#   ...or from a local file:
make rhcos-image RHCOS_IMAGE=/path/to/rhcos-qemu.x86_64.qcow2

# 2. Run, opting in.
BPFCOMPAT_ENABLE_RHCOS=1 ./bin/bpfcompat test \
  -artifact build/probe.bpf.o \
  -matrix matrices/rhcos.yaml -runner vm -out report.json
```

A recorded run is in [`docs/evidence-rhcos.md`](evidence-rhcos.md): RHCOS
`416.94…` on kernel `5.14.0-427.93.1.el9_4` (OpenShift 4.16), a ring-buffer
artifact loading and attaching — **pass**.

## Why it is opt-in

Two facts shape the design:

1. **Boot is solved.** RHCOS boots via [Ignition](https://coreos.github.io/ignition/),
   not cloud-init. bpfcompat writes a minimal Ignition config (an SSH key for the
   `core` user) and passes it to QEMU via `-fw_cfg name=opt/com.coreos/config`
   (`internal/vm/ignition.go`). This is the **same path proven on Fedora CoreOS**,
   which is freely fetchable (`make vm-image-fcos`) and runs out of the box.
2. **The image is operator-specific.** RHCOS ships with an OpenShift release, not
   as a single evergreen public cloud image. So bpfcompat does **not** bundle or
   auto-fetch a "default" RHCOS — the operator supplies the exact image matching
   their cluster.

Because of (2), the `rhcos` profile is **unsupported by default**:
`ExecutionTransport()` refuses it unless `BPFCOMPAT_ENABLE_RHCOS=1` is set, so
bpfcompat never claims RHCOS works without a real image present. Setting the flag
is the operator asserting "I have staged a real RHCOS image."

## Getting the image

RHCOS *boot* images (the qcow2) are published on the public OpenShift mirror —
the **pull secret is for the container release payload, not the boot disk**. For
a given OpenShift minor version:

```sh
base=https://mirror.openshift.com/pub/openshift-v4/x86_64/dependencies/rhcos/4.16/latest
URL=$(curl -fsSL "$base/sha256sum.txt" | awk '/qemu.x86_64.qcow2.gz$/{print "'"$base"'/"$2; exit}')
make rhcos-image RHCOS_IMAGE_URL="$URL"
```

Alternatively, pin the exact build your cluster runs with `openshift-install`:

```sh
openshift-install coreos print-stream-json \
  | jq -r '.architectures.x86_64.artifacts.qemu.formats["qcow2.gz"].disk.location'
```

Enterprises with an internal mirror or an air-gapped copy pass the local file
with `RHCOS_IMAGE=/path/to/rhcos-qemu.x86_64.qcow2` instead. `.gz`/`.xz` images
are decompressed automatically; the result is staged at
`vm/cache/rhcos-4.16.qcow2`.

## Kernel approximation without an image

If you cannot supply an RHCOS image, the **RHEL / AlmaLinux / Rocky 9 (5.14)**
profiles approximate the RHCOS kernel closely: RHCOS for OpenShift 4.16 is the
RHEL 9.4 kernel (`5.14.0-427`), the same heavily-backported base. That covers
most "will my eBPF load on this kernel?" questions; a true RHCOS boot adds the
immutable/ostree userspace and the exact vendor build on top.

## What the run proves

[docs/evidence-rhcos.md](evidence-rhcos.md) records load + attach **inside** the
booted RHCOS guest. The sample artifact uses a BPF ring buffer (upstream since
5.8) and passes on the 5.14 RHCOS kernel — RHEL's backport in action, tested
directly rather than
inferred from the version number.

## Notes & limits

- The profile id `rhcos-4.16-5.14` documents the expected base; the **real**
  booted kernel is captured at runtime in `report.json`.
- The Ignition config is minimal by design (SSH key only). RHCOS in production is
  configured by the Machine Config Operator; bpfcompat only needs enough to get
  a shell and run the validator.
- Requires `/dev/kvm` (or it degrades to slower TCG software emulation) and
  enough memory for the guest (the profile requests 2 GiB).
