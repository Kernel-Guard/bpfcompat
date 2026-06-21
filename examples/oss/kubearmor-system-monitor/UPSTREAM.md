# Upstream Reference

- Project: `kubearmor/KubeArmor`
- Artifact: `system_monitor.bpf.o` (the host/container system monitor probe)
- Source: `KubeArmor/BPF/system_monitor.c` (+ `shared.h`, `visibility.h`)
- URL: <https://github.com/kubearmor/KubeArmor/tree/main/KubeArmor/BPF>
- License: `GPL-2.0-only` (per the BPF sources' `char LICENSE[] SEC("license")`)

## Why the object is not vendored here

`system_monitor.bpf.o` is a CO-RE object built from KubeArmor's tree against a
generated `vmlinux.h` and a vendored libbpf submodule. Per this repo's policy,
compiled `*.bpf.o` artifacts are git-ignored and built locally rather than
committed. Build it from a KubeArmor checkout:

```sh
git clone --depth 1 --recursive --shallow-submodules \
  https://github.com/kubearmor/KubeArmor
make -C KubeArmor/KubeArmor/BPF
# -> KubeArmor/KubeArmor/BPF/system_monitor.bpf.o
```

Build host needs: `clang`, `llvm` (`opt`/`llc`/`llvm-dis`), and `bpftool`
(`linux-tools-common linux-tools-generic`) to emit `vmlinux.h`.

## No local adaptations

The object is built and validated as KubeArmor ships it — no source changes.
The only thing this example adds is the bpfcompat `manifest.yaml`, which
declares KubeArmor's own loader contract (the `kubearmor_visibility` inner-map
prototype) so a generic loader can load the object the way KubeArmor's Go
loader does.
