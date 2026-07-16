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
- **Loaded mirroring libpman's loader contract** — runtime-sized maps,
  helper-gated program variants, trial-probed BPF iterators (declared in a
  manifest) — so a generic libbpf load does not undercount support. This
  reproduces *how* libpman loads the object; it is not Falco's loader binary
  itself (for that, use command mode — see
  [command-validation.md](command-validation.md)).

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

## Upstream: this check now runs in falcosecurity/libs CI

On 2026-07-15, [falcosecurity/libs#3024](https://github.com/falcosecurity/libs/pull/3024)
merged a scheduled bpfcompat compatibility lane into `falcosecurity/libs`
([workflow](https://github.com/falcosecurity/libs/blob/master/.github/workflows/bpfcompat-compatibility.yml)).
It goes one step further than the manifest-mirror approach documented above:
it builds Falco's real userspace loader (`scap-open`, statically linked with
the modern_bpf probe skeleton embedded) from the tree under test and runs it
inside each matrix kernel VM via [command mode](command-validation.md)
(`scap-open --modern_bpf --num_events 10`). The loader's exit code is the
per-kernel verdict — `scap_open()` exercises libpman's full load path
(runtime-sized maps, helper-gated program variants, trial-probed iterators,
attach), then captures a bounded number of events — so there is no manifest to
keep in sync with the loader: the loader is the contract.

## Reproduce it

```bash
# In CI (GitHub Action), against your kernel matrix:
- uses: Kernel-Guard/bpfcompat@v0.3.2
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
