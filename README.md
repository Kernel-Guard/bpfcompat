# bpfcompat

[![CI](https://github.com/Kernel-Guard/bpfcompat/actions/workflows/ci.yml/badge.svg)](https://github.com/Kernel-Guard/bpfcompat/actions/workflows/ci.yml)
[![CodeQL](https://github.com/Kernel-Guard/bpfcompat/actions/workflows/codeql.yml/badge.svg)](https://github.com/Kernel-Guard/bpfcompat/actions/workflows/codeql.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/Kernel-Guard/bpfcompat/badge)](https://scorecard.dev/viewer/?uri=github.com/Kernel-Guard/bpfcompat)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/13230/badge)](https://www.bestpractices.dev/projects/13230)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

`bpfcompat` is an open-source compatibility validator for compiled eBPF
artifacts. It runs real libbpf load/attach checks against Linux kernel profiles
and produces JSON/Markdown reports that can fail CI when an artifact regresses.

The core question is simple:

> Will this `.bpf.o` load and attach on the kernels I care about, and if not,
> what failed?

**Live demo:** [bpfcompat.kernelguard.net](https://bpfcompat.kernelguard.net) — upload a
`.bpf.o` and see the compatibility matrix.

**Quickstart & trust model:** [docs/quickstart.md](docs/quickstart.md) — gate it in CI
in ~10 minutes; self-hosted-first, your artifact never leaves your runner.

## Why not just rely on CO-RE / BTFHub?

CO-RE makes a `.bpf.o` *portable in principle*; it does not guarantee it will
*load* on a given kernel. Real-world failures that CO-RE does not prevent:

- missing or partial kernel BTF,
- CO-RE relocation errors against a divergent kernel,
- unsupported map types (e.g. ringbuf before 5.8),
- unsupported program/attach types,
- capability and kernel-config differences.

`bpfcompat` answers the empirical question CO-RE leaves open: *does it actually
load and attach here?* — by running the artifact in a real kernel.

## Try it in CI without your own KVM box

GitHub-hosted Linux runners now expose `/dev/kvm`, so the full QEMU VM
compatibility gate runs on a stock `ubuntu-latest` runner — no self-hosted KVM
machine required. This is proven end-to-end:
[`.github/workflows/bpfcompat-example-hosted.yml`](.github/workflows/bpfcompat-example-hosted.yml)
boots a disposable VM and runs the `dev-functional` suite (load + behavioral
execve) in **under two minutes**.

One gotcha: some hosted images expose `/dev/kvm` but the runner user isn't in
the `kvm` group, so QEMU can't open it. The example workflow runs
`sudo chmod 0666 /dev/kvm` to handle that. If a runner genuinely lacks KVM,
validation degrades to TCG software emulation (correct, just slower) instead of
failing.

## Proof: a real Falco probe catches a real regression

`bpfcompat` validates Falco's `modern_bpf` probe (`bpf_probe.o`, ~64 programs)
exactly as Falco's own loader runs it, across a 5-kernel matrix:

| Profile | Host kernel | Status | Why |
|---|---|---|---|
| `ubuntu-20.04-5.4` | `5.4.0-216` | ❌ fail | `UNSUPPORTED_MAP_TYPE` — ringbuf needs ≥ 5.8 |
| `ubuntu-22.04-5.15` | `5.15.0-173` | ✅ pass | loads; selects `*_old_x` syscall variants |
| `debian-12-6.1` | `6.1.0-47` | ✅ pass | loads; full variant set |
| `ubuntu-23.10-6.5` | `6.5.0-44` | ✅ pass | loads; full variant set |
| `ubuntu-24.04-6.8` | `6.8.0-106` | ✅ pass | loads; full variant set |

The red `5.4` row is the point: a kernel below Falco's real floor is flagged
*before* shipping, with the exact mechanism (`ringbuf_maps` create returns
`-EINVAL`) and remediation — not a generic "it broke." Reproduce this matrix
locally; see [`docs/falco-parity.md`](docs/falco-parity.md).

## Current Status

The project is a serious MVP for compatibility evidence and CI gating. It is
not a production runtime loader and it is not a production multi-tenant SaaS.

Implemented:

- VM-backed `.bpf.o` validation through QEMU/KVM cloud images.
- C/libbpf validator that records load, attach, BTF, CO-RE, map, program, and
  capability evidence.
- Failure classification for common compatibility cases such as missing BTF,
  CO-RE relocation failures, unsupported map types, unsupported attach types,
  and unsupported program types.
- Multi-artifact suite support for collections of BPF objects/programs.
- JSON, Markdown, GitHub Action summary, and static compatibility-site output.
- Experimental `virtme-ng` upstream-kernel lane.
- Experimental Firecracker generated-initramfs backend.
- Experimental runtime probe/select/fetch/agent flow for verified artifact
  decisioning.

Keep the runtime track framed as decisioning/proof unless you are running it in
a controlled environment. Host loading stays disabled/gated by default.

## Repository Hygiene

Generated runtime outputs are intentionally not committed:

- `.bpfcompat/`
- `reports/`
- `evidence/`
- `vm/cache/`
- generated `.bpf.o` files

Recreate proof artifacts locally with the commands below.

If this repository is being prepared for public release, read
[`docs/public-release-checklist.md`](docs/public-release-checklist.md) before
changing GitHub visibility. Deleting private/generated files in a later commit
does not remove them from git history.

## Prerequisites

For the main QEMU path:

- Linux host (a GitHub-hosted `ubuntu-latest` runner works; `/dev/kvm`
  enables hardware acceleration, and bpfcompat falls back to TCG software
  emulation when it is absent)
- Go 1.25+
- `make`
- `clang`
- `qemu-system-x86_64`
- `qemu-img`
- `ssh`
- `scp`
- `jq`
- `pkg-config`
- development packages for `libbpf`, `libelf`, and `zlib`

Optional lanes:

- ARM64 VM execution requires an ARM64/aarch64 KVM host, `qemu-system-aarch64`,
  an ARM64 cloud image, and an ARM64 validator binary.
- Upstream-kernel execution requires `virtme-ng` (`vng`) and `curl`.
- Firecracker execution requires a Firecracker binary, `/dev/kvm`, `busybox`,
  `cpio`, `gzip`, and an uncompressed guest kernel.

## Build

```bash
make doctor
make deps
make build
make validator
make examples
```

Restricted-network option:

```bash
make vendor
make test-vendor
```

Validator modes:

- `make validator` uses dynamic libbpf linking for local development.
- `make validator-static` builds the guest-side validator used by VM profiles.

## Quickstart: a collection across kernels

Compatibility questions are rarely about one file. A release ships a
collection of BPF objects, and individual programs load differently across
kernels — so suites are the primary workflow: artifacts + manifests + a
kernel matrix in, one collection-level pass/fail matrix out.

Fast first run (one VM profile):

```bash
make examples
make vm-ubuntu-22
make acceptance-suite-dev-one
```

Realistic collection across the 8-profile MVP matrix:

```bash
make examples oss-examples
make vm-images
./bin/bpfcompat suite \
  --suite suites/example-collection.yaml \
  --out reports/example-collection.json \
  --markdown reports/example-collection.md
```

Each case stages its artifact, boots a disposable VM overlay per kernel
profile, runs the C/libbpf validator inside the guest, and rolls the results
into a per-artifact × per-kernel matrix with structured failure reasons.
Exit code `2` means a required profile regressed, so the same command is the
CI gate.

### Single-artifact mode

```bash
./bin/bpfcompat test \
  --artifact examples/simple-pass/simple_pass.bpf.o \
  --manifest examples/simple-pass/manifest-dev-one.yaml \
  --matrix matrices/dev-one.yaml \
  --out reports/dev-one.json \
  --markdown reports/dev-one.md \
  --timeout 8m
```

`make acceptance-dev-one` wraps the same flow.

### Runtime-sized maps

Some artifacts compile maps with `max_entries=0` and size them from
userspace at load time (per-CPU arrays, ring buffers — Falco's `modern_bpf`
probe is the canonical example). Declare those maps in the manifest so the
validator mirrors what the real loader does before load:

```yaml
maps:
  - name: auxiliary_maps
    max_entries: cpus
  - name: ringbuf_maps
    max_entries: cpus
    inner_ringbuf_bytes: 8388608
```

See [`docs/validator.md`](docs/validator.md) for details.

### Dense kernel sweeps and freshness

One cloud image samples a kernel series at a single release. The sweep lane
installs exact kernel releases (from the distro archive pool, indexed by
[falcosecurity/kernel-crawler](https://github.com/falcosecurity/kernel-crawler))
inside the guest and reboots into them before validating:

```bash
./bin/bpfcompat kernel-sweep --profile ubuntu-22.04-5.15 --count 4
./bin/bpfcompat test --artifact app.bpf.o \
  --matrix matrices/kernel-sweep-ubuntu-22.04-5.15.yaml --timeout 20m ...
```

`bpfcompat kernel-freshness` compares each profile's last-validated kernel
against what its distro currently ships and flags stale evidence (run
weekly in CI). See [`docs/image-pipeline.md`](docs/image-pipeline.md).

## Main Acceptance Flows

Fast local checks:

```bash
make acceptance-dev-one
make acceptance-functional-dev-one
make acceptance-suite-dev-one
```

Full MVP matrix:

```bash
make vm-images
make acceptance
```

Expanded runnable matrix:

```bash
make vm-images-expanded-2026
make matrix-runnable
make acceptance-expanded-runnable
```

Real OSS artifact examples:

```bash
make oss-examples
make oss-evidence
```

`make oss-evidence` writes generated outputs under `evidence/oss-validation/`.

## Backend Lanes

QEMU/KVM distro profiles:

```bash
make acceptance-dev-one
```

Upstream-mainline smoke through `virtme-ng`:

```bash
make doctor-virtme
make upstream-kernel-runnable
make acceptance-upstream-kernel
```

Firecracker generated-initramfs proof:

```bash
make firecracker-preflight
make acceptance-firecracker-dev-one
```

ARM64 smoke:

```bash
make doctor-arm64-kvm
make acceptance-arm64-smoke
```

The ARM64 workflow is wired, but real ARM64 VM compatibility proof requires a
native ARM64 KVM runner.

## GitHub Action

This repository includes a composite action that runs `bpfcompat` and appends
the Markdown report to the GitHub Actions job summary. VM-backed validation
runs on a stock GitHub-hosted `ubuntu-latest` runner (which now exposes
`/dev/kvm`); a self-hosted KVM runner is only needed for wide matrices, ARM64,
or the Firecracker lane. See
[`.github/workflows/bpfcompat-example-hosted.yml`](.github/workflows/bpfcompat-example-hosted.yml).

Suite mode (recommended — gates the whole collection):

```yaml
- uses: Kernel-Guard/bpfcompat@v0.1.6
  with:
    suite: suites/project.yaml
    suite-out: reports/suite.json
    suite-markdown: reports/suite.md
```

Suite cases can opt into `validation_mode: load_only`, `load_attach`, or
`behavior`. Behavior mode runs manifest or suite smoke commands while BPF links
are alive and adds the result to the suite-level collection matrix.

Single artifact:

```yaml
- uses: Kernel-Guard/bpfcompat@v0.1.6
  with:
    artifact: path/to/program.bpf.o
    manifest: path/to/manifest.yaml
    matrix: path/to/matrix.yaml
    out: reports/bpfcompat.json
    markdown: reports/bpfcompat.md
    validation-mode: load_attach
    timeout: 8m
```

Marketplace quick start:

1. Add a self-hosted Linux runner with KVM enabled.
2. Commit compiled `.bpf.o` artifacts, manifests, and a matrix YAML.
3. Use the action in CI to produce JSON, Markdown, and job-summary evidence.
4. Treat exit code `2` as a compatibility gate failure.

## Web UI / API

The embedded UI is useful for demos and local inspection:

```bash
make serve
```

Open:

- `http://127.0.0.1:8080/`
- `http://127.0.0.1:8080/results`

The API has `/api/v1/...` routes with legacy `/api/...` compatibility. For
route details, see:

- [`docs/openapi.yaml`](docs/openapi.yaml)
- [`docs/api-web-ui.md`](docs/api-web-ui.md)
- [`docs/env-reference.md`](docs/env-reference.md)

Public demo mode can allow anonymous validation/read/runtime-select/fetch
without enabling host execution. Runtime execute remains separately gated by
`BPFCOMPAT_API_ENABLE_RUNTIME_EXECUTE` and an approval token.

## Runtime Decisioning

> **Status:** experimental, and not the project's current focus. Active
> development centers on the CI compatibility workflow: suites, kernel
> matrices, and reports. This track is kept as a controlled proof and may
> change or be removed.

The runtime path is experimental and should be treated as a controlled proof:

```bash
make runtime-selector-proof
make runtime-delivery-proof
```

The safer product boundary is:

1. validate artifact variants in CI/VMs;
2. store signed compatibility metadata;
3. probe a target host;
4. select and fetch the best verified artifact;
5. leave host loading to an explicitly approved local agent path.

Relevant docs:

- [`docs/runtime-selector-simulation.md`](docs/runtime-selector-simulation.md)
- [`docs/production-runtime-agent-alpha.md`](docs/production-runtime-agent-alpha.md)
- [`docs/runtime-execute-policy.md`](docs/runtime-execute-policy.md)
- [`docs/security-model.md`](docs/security-model.md)
- [`docs/threat-model.md`](docs/threat-model.md)

## Documentation Map

User guide — start here:

- [`docs/architecture.md`](docs/architecture.md)
- [`docs/project-compatibility-suite.md`](docs/project-compatibility-suite.md) — suites and collection matrices
- [`docs/validator.md`](docs/validator.md) — what the in-guest validator checks
- [`docs/profile-catalog.md`](docs/profile-catalog.md) — kernel/distro profiles and image maintenance
- [`docs/image-pipeline.md`](docs/image-pipeline.md) — where images come from, integrity, adding profiles
- [`docs/upstream-kernel-virtme-ng.md`](docs/upstream-kernel-virtme-ng.md)
- [`docs/firecracker-backend.md`](docs/firecracker-backend.md)
- [`docs/api-web-ui.md`](docs/api-web-ui.md)

Internal evidence and program docs (acceptance records, runbooks, and
planning notes — useful for contributors, not needed to use the tool):

- [`docs/acceptance-tests.md`](docs/acceptance-tests.md)
- [`docs/falco-parity.md`](docs/falco-parity.md)
- [`docs/supply-chain.md`](docs/supply-chain.md) — supply-chain controls and maintainer repo settings
- [`docs/backend-execution-proof.md`](docs/backend-execution-proof.md)
- [`docs/external-ci-proof.md`](docs/external-ci-proof.md)
- remaining `docs/*.md` proof, runbook, and checklist documents

## Development

```bash
make test
make openapi-check
make env-docs-check
go vet ./...
golangci-lint run --timeout=5m
govulncheck ./...
```

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for route, env, test, and changelog
expectations.

## Security

Report security issues through [`SECURITY.md`](SECURITY.md), not public issues.

Operator guidance:

- keep runtime execute disabled on public demos;
- require write auth or explicit anonymous-demo flags for POST paths;
- do not enable internal-host or `file://` fetches outside controlled tests;
- run host-loading flows only through a local policy-gated agent path.

### Supply-chain posture

- **Static analysis:** GitHub CodeQL (`codeql.yml`) plus `govulncheck` and
  `golangci-lint` in CI on every PR.
- **Dependency updates:** Dependabot (`dependabot.yml`) for Go modules and
  pinned GitHub Actions, grouped weekly.
- **Risk scoring:** OpenSSF Scorecard (`scorecard.yml`), published to the
  public Scorecard API (badge above).
- **Signed releases + SLSA provenance:** tag builds produce a CycloneDX SBOM,
  cosign keyless (Sigstore OIDC) signatures over the binaries / `SHA256SUMS` /
  SBOM, and **SLSA Build L3 build-provenance attestations** bound to the
  producing commit and workflow (`release-artifacts.yml`). Quick check:

  ```bash
  gh attestation verify ./bpfcompat-linux-amd64 --repo Kernel-Guard/bpfcompat
  ```

  Full verification steps (provenance, cosign, SBOM) are in
  [`docs/verifying-releases.md`](docs/verifying-releases.md).

Maintainer-side repo settings (branch protection, secret-scanning push
protection, OpenSSF Best Practices registration) are tracked in
[`docs/supply-chain.md`](docs/supply-chain.md).

## License

Apache-2.0. See [`LICENSE`](LICENSE).
