# Reference matrix: Falco modern_bpf across 5 kernels

A public, reproducible example of what bpfcompat produces — using a real-world,
recognizable artifact: Falco's `modern_bpf` probe (`bpf_probe.o`).

> Independent compatibility test of a publicly available artifact. Not affiliated
> with, sponsored by, or endorsed by the Falco project or the CNCF.

## What was tested

- **Artifact:** `bpf_probe.o`, built from `falcosecurity/libs` master
  (`cmake -DUSE_BUNDLED_DEPS=ON -DBUILD_LIBSCAP_MODERN_BPF=ON .. && make ProbeSkeleton`),
  sha256 `4895177ced5618d22fd40c1d69be80c7f16fc28f9552f0eff5fdbf682bbd2722`.
- **Validation mode:** load + attach, inside disposable QEMU/KVM VMs running each
  exact kernel.
- **Loaded exactly as libpman does** — runtime-sized maps, helper-gated program
  variants, trial-probed BPF iterators (declared in a manifest) — so a generic
  libbpf load does not undercount support.

## Result

| Kernel | Result | Notes |
|---|---|---|
| Ubuntu 20.04 — 5.4 | ❌ fail (`UNSUPPORTED_MAP_TYPE`, high) | correct: ring buffer maps require ≥ 5.8 |
| Ubuntu 22.04 — 5.15 | ✅ pass | `recvmmsg_old_x`/`sendmmsg_old_x` selected; `dump_task` detected unsupported |
| Debian 12 — 6.1 | ✅ pass | `recvmmsg_x`/`sendmmsg_x` (bpf_loop) + both iterators |
| Ubuntu 23.10 — 6.5 | ✅ pass | same |
| Ubuntu 24.04 — 6.8 | ✅ pass | same |

BTF was present on all five kernels, so the 5.4 failure is genuinely a map-type
boundary — not a missing-BTF artifact.

## Why this is the interesting part

modern_bpf targets newer kernels by design, so 5.4 *should* fail. The value is that
bpfcompat says **precisely why**, in machine-readable terms a CI gate or a human can
act on:

- `classification_code: UNSUPPORTED_MAP_TYPE` (confidence `high`)
- reason: map `ringbuf_maps` failed to create — `Invalid argument (-22)`; ring buffer
  maps require kernel ≥ 5.8
- plus which **program variants** each kernel actually accepted (e.g. `recvmmsg_x`
  vs the `_old_x` fallback; `dump_task` unsupported on 5.15), recorded per profile

That is the difference between "❌ it broke" and "❌ ring buffer isn't available on
5.4 — ship a non-ringbuf fallback for that band." The output is a decision, not a log.

## Reproduce it

```bash
# In CI (GitHub Action), against your kernel matrix:
- uses: Kernel-Guard/bpfcompat@v0.2.0
  with:
    artifact: build/bpf_probe.o
    matrix: matrices/mvp.yaml
    out: reports/compat.json
    markdown: reports/compat.md
    validation-mode: load_attach
```

On a regression the job exits non-zero and writes the matrix to the GitHub Actions
job summary. The full evidence format is documented in
[evidence-schema.md](evidence-schema.md).
