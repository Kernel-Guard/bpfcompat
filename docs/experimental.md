# Experimental tracks

Everything on this page works and has evidence behind it, but it is **not the
project's focus**. Active development centers on the CI compatibility
workflow: `.bpf.o` and command-mode validation, kernel matrices (including the
[quirk library](kernel-quirk-library.md)), suites, and reports. The tracks
below are kept as controlled proofs; interfaces may change or be removed.

## virtme-ng upstream-kernel lane

Boots **upstream mainline kernels** (kernel.org builds, not vendor images)
through `virtme-ng` for boundary sweeps — useful to bisect exactly which
upstream release introduced a feature, before checking which vendors backport
it.

```bash
make doctor-virtme
make upstream-kernel-runnable
make acceptance-upstream-kernel
```

Details: [upstream-kernel-virtme-ng.md](upstream-kernel-virtme-ng.md).
Note: command mode supports the default `vm` runner only.

## Firecracker generated-initramfs backend

An alternative microVM backend that builds a minimal initramfs instead of
booting a cloud image. Faster per-boot, but it does not run *vendor* kernels —
which is the product's differentiator — so it stays a proof.

```bash
make firecracker-preflight
make acceptance-firecracker-dev-one
```

Details: [firecracker-backend.md](firecracker-backend.md).

## Web UI / API

An embedded UI and HTTP API for demos and local inspection of results. The
supported product surface is the **CLI + GitHub Action in CI**; the UI is a
convenience, not a SaaS.

```bash
make serve   # http://127.0.0.1:8080/ and /results
```

The API has `/api/v1/...` routes with legacy `/api/...` compatibility. Public
demo mode can allow anonymous validation/read/runtime-select/fetch without
enabling host execution; runtime execute remains separately gated by
`BPFCOMPAT_API_ENABLE_RUNTIME_EXECUTE` and an approval token.

Details: [api-web-ui.md](api-web-ui.md), [openapi.yaml](openapi.yaml),
[env-reference.md](env-reference.md).

## Runtime decisioning (probe / select / fetch / agent)

A frozen proof-of-concept for *using* compatibility evidence at deploy time:
probe a target host, select the best verified artifact variant, fetch it, and
leave host loading to an explicitly approved local agent path. Host loading
stays disabled/gated by default; treat the whole track as decisioning/proof
unless you run it in a controlled environment.

```bash
make runtime-selector-proof
make runtime-delivery-proof
```

The safer product boundary this track demonstrates:

1. validate artifact variants in CI/VMs;
2. store signed compatibility metadata;
3. probe a target host;
4. select and fetch the best verified artifact;
5. leave host loading to an explicitly approved local agent path.

Details: [runtime-selector-simulation.md](runtime-selector-simulation.md),
[production-runtime-agent-alpha.md](production-runtime-agent-alpha.md),
[runtime-execute-policy.md](runtime-execute-policy.md),
[security-model.md](security-model.md), [threat-model.md](threat-model.md).
