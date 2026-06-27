# Evidence: RHEL CoreOS (OpenShift) validation

A real validation run of a compiled eBPF artifact **inside a booted RHEL CoreOS
guest**, recorded here as committed evidence. This is the proof behind the opt-in
RHCOS path documented in [docs/rhcos-openshift.md](rhcos-openshift.md). Reproduce
it with the steps at the bottom.

> The raw run artifacts (full `report.json`, `validator-result.json`, serial log)
> are written under `evidence/rhcos/` locally; that path is git-ignored as
> high-churn output, so the decisive fields are inlined below.

## Result

| Field | Value |
|---|---|
| Profile | `rhcos-4.16-5.14` |
| Booted OS | Red Hat Enterprise Linux CoreOS `416.94.202510081640-0` (OpenShift 4.16) |
| Kernel | `5.14.0-427.93.1.el9_4.x86_64` (RHEL 9.4 base, heavily backported) |
| Arch | x86_64 |
| Boot path | Ignition via QEMU `-fw_cfg name=opt/com.coreos/config`; SSH as `core` |
| Artifact | `examples/ringbuf-modern/ringbuf_modern.bpf.o` (sha256 `569df554…21728`) |
| Load | **pass** (errno 0) |
| Attach | **pass** (1/1, best-effort) |
| Kernel BTF | present (`/sys/kernel/btf/vmlinux`, 4876642 bytes) |
| Overall | **pass** |

The artifact uses a BPF ring buffer, upstream since **5.8**. It loads on this
**5.14** RHCOS kernel because RHEL backports the feature — "kernel version ≠
feature support," tested by booting the real vendor kernel rather than inferred.

## In-guest validator output (`validator.v0.4`, key fields)

```json
{
  "schema_version": "validator.v0.4",
  "status": "pass",
  "host": {
    "release": "5.14.0-427.93.1.el9_4.x86_64",
    "version": "#1 SMP PREEMPT_DYNAMIC Wed Oct 1 11:45:46 EDT 2025",
    "machine": "x86_64"
  },
  "load":   { "status": "pass", "error_code": 0, "error": "" },
  "attach": { "mode": "best-effort", "status": "pass", "attempted": 1, "passed": 1, "failed": 0 },
  "btf":    { "kernel_btf_available": true, "kernel_btf_size": 4876642,
              "artifact_has_btf": true, "artifact_has_btf_ext": true }
}
```

## Guest serial console (excerpt, ANSI stripped)

```
GRUB:  Booting `Red Hat Enterprise Linux CoreOS 416.94.202510081640-0 (ostree:0)'

[0.000000] Linux version 5.14.0-427.93.1.el9_4.x86_64
           (mockbuild@x86-64-03.build.eng.rdu2.redhat.com) #1 SMP PREEMPT_DYNAMIC Wed Oct 1 ...
[0.000000] Command line: ... vmlinuz-5.14.0-427.93.1.el9_4.x86_64 rw ignition.firstboot
           ostree=/ostree/boot.1/rhcos/... ignition.platform.id=qemu console=ttyS0,115200n8

Welcome to Red Hat Enterprise Linux CoreOS 416.94.202510081640-0
          dracut-057-54.git20250423.el9_4.1 (Initramfs)!

[1.291367] systemd[1]: Starting CoreOS Ignition User Config Setup...
[  OK  ] Finished CoreOS Ignition User Config Setup.
```

`ignition.platform.id=qemu` + "CoreOS Ignition User Config Setup" confirm the
boot used the Ignition config bpfcompat delivered over `-fw_cfg`.

## Provenance

- Image: `rhcos-4.16.51-x86_64-qemu.x86_64.qcow2.gz`, public OpenShift mirror
  (`mirror.openshift.com/pub/openshift-v4/x86_64/dependencies/rhcos/4.16/latest/`).
  Published sha256 of the `.gz`:
  `92880764c1b3b61940bc209ee021b97474c4db2d9a36abcece55ddd6d8c17c95`.
- Decompressed qcow2 base-image sha256 (recorded in `report.json`):
  `d03128234c5dc6217bd37ee0caf6f192107d42d39a8a6b5c9b6148b0f4f92399`.
- The pull secret is required for the OpenShift *container release payload*, not
  the RHCOS boot qcow2 used here.

## Reproduce

```sh
base=https://mirror.openshift.com/pub/openshift-v4/x86_64/dependencies/rhcos/4.16/latest
URL=$(curl -fsSL "$base/sha256sum.txt" | awk '/qemu.x86_64.qcow2.gz$/{print "'"$base"'/"$2; exit}')

make rhcos-image RHCOS_IMAGE_URL="$URL"

BPFCOMPAT_ENABLE_RHCOS=1 ./bin/bpfcompat test \
  -artifact examples/ringbuf-modern/ringbuf_modern.bpf.o \
  -matrix matrices/rhcos.yaml -runner vm -out report.json
```

Enterprises with an internal mirror or an `openshift-install`-extracted image
pass `RHCOS_IMAGE=/path/to/rhcos.qcow2` instead of `RHCOS_IMAGE_URL`.
