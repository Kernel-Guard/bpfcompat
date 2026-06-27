# Quickstart & trust model

Gate your compiled eBPF objects against the kernels you ship to — in about ten
minutes — and prove they load (and attach) on real kernels before your users
hit a failure.

## Trust model first (read this before adopting)

bpfcompat is **self-hosted-first**. The canonical way to run it is the GitHub
Action (or the CLI) on **your own runner**:

- **Your artifact never leaves your infrastructure.** The `.bpf.o` is loaded in a
  disposable QEMU/KVM VM on your runner; nothing is uploaded to us.
- **No host execution by default.** Validation happens *inside* throwaway guests;
  runtime host-loading is disabled by default and gated behind explicit approval.
- **The public demo is a demo only** (`bpfcompat.kernelguard.net`): disposable VMs,
  sanitized reports, no artifact retention, host-execution hard-disabled. Use it to
  evaluate — run real workloads in your own CI.

Details: [security-model.md](security-model.md) · [threat-model.md](threat-model.md).

## 1. Gate it in CI (GitHub Action — the 10-minute path)

VM-backed validation runs on a stock GitHub-hosted `ubuntu-latest` runner (it now
exposes `/dev/kvm`). A self-hosted KVM runner is only needed for wide matrices,
ARM64, or the Firecracker lane.

```yaml
# .github/workflows/ebpf-compat.yml
name: eBPF compatibility gate
on: [pull_request]

jobs:
  bpfcompat:
    runs-on: ubuntu-latest          # exposes /dev/kvm for KVM acceleration
    steps:
      - uses: actions/checkout@v4
      - uses: Kernel-Guard/bpfcompat@v0.2.0
        with:
          artifact: build/program.bpf.o     # your compiled object
          matrix: matrices/mvp.yaml          # the kernels you support
          out: reports/bpfcompat.json
          markdown: reports/bpfcompat.md
          validation-mode: load_attach       # load_only | load_attach | behavior
```

What you get:

- a per-kernel **pass/fail matrix** written straight to the **GitHub Actions job
  summary**, so a reviewer sees exactly which kernel broke and why;
- a JSON + Markdown report ([evidence schema](evidence-schema.md)) with
  **classified failure reasons** (missing BTF, unsupported map/program/attach type,
  CO-RE relocation, …);
- **exit code 2 on a required-target regression**, which fails the job and blocks
  the merge.

Shipping a whole product? Use **suite mode** to gate a collection in one run:

```yaml
      - uses: Kernel-Guard/bpfcompat@v0.2.0
        with:
          suite: suites/project.yaml
          suite-out: reports/suite.json
          suite-markdown: reports/suite.md
```

The Action is on the
[GitHub Marketplace](https://github.com/marketplace/actions/bpfcompat-ebpf-compatibility-gate).
Pinning to a release tag uses checksum-verified, attested prebuilt binaries
([verifying releases](verifying-releases.md)); otherwise it builds from source.

## 2. Run it locally (CLI)

Install the CLI and validator first — see [Install](../README.md#install)
(prebuilt release binary, source build, or `go install`). The from-source build
is:

```bash
make build && make validator-static
./bin/bpfcompat test \
  --artifact build/program.bpf.o \
  --matrix matrices/mvp.yaml \
  --out reports/bpfcompat.json \
  --markdown reports/bpfcompat.md \
  --validation-mode load_attach
```

Requires a Linux host with `/dev/kvm`. The kernel profiles you can target are in
the [profile catalog](profile-catalog.md).

## When to use bpfcompat vs LVH / vmtest

These are excellent tools and bpfcompat does not replace them:

- **Cilium Little VM Helper / danobi vmtest** are general VM runners — you assemble
  the kernels, the load logic, and the reporting yourself.
- **bpfcompat** is the eBPF-aware **gate**: it packages the "does my `.bpf.o` load and
  attach across these kernels, and if not, *why*" use case into a drop-in CI step
  with a curated kernel matrix and a portable, classified evidence format.

Use bpfcompat when you want a drop-in gate plus shareable compatibility evidence;
reach for LVH/vmtest when you need a fully custom harness or already live in that
tooling.

## Next

- [evidence-schema.md](evidence-schema.md) — the report format + classification taxonomy
- [verifying-releases.md](verifying-releases.md) — verify signed, attested binaries
- [case-study-falco-modern-bpf.md](case-study-falco-modern-bpf.md) — a real reference matrix
