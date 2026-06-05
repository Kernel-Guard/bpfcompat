# bpfcompat

`bpfcompat` is an open-source compatibility validator for compiled eBPF
artifacts. It runs real libbpf load/attach checks against Linux kernel profiles
and produces JSON/Markdown reports that can fail CI when an artifact regresses.

The core question is simple:

> Will this `.bpf.o` load and attach on the kernels I care about, and if not,
> what failed?

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

For the main QEMU/KVM path:

- Linux host with `/dev/kvm`
- Go 1.22+
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

## Quickstart

Download the Ubuntu 22.04 dev image and run one profile:

```bash
make vm-ubuntu-22
make acceptance-dev-one
```

Equivalent direct command:

```bash
./bin/bpfcompat test \
  --artifact examples/simple-pass/simple_pass.bpf.o \
  --manifest examples/simple-pass/manifest-dev-one.yaml \
  --matrix matrices/dev-one.yaml \
  --out reports/dev-one.json \
  --markdown reports/dev-one.md \
  --timeout 8m
```

This stages the artifact, boots a disposable VM overlay, runs the C/libbpf
validator inside the guest, copies back target logs, and writes aggregate
reports.

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
the Markdown report to the GitHub Actions job summary.

Single artifact:

```yaml
- uses: erenari/bpfcompat@main
  with:
    artifact: path/to/program.bpf.o
    manifest: path/to/manifest.yaml
    matrix: path/to/matrix.yaml
    out: reports/bpfcompat.json
    markdown: reports/bpfcompat.md
    timeout: 8m
```

Suite mode:

```yaml
- uses: erenari/bpfcompat@main
  with:
    suite: suites/project.yaml
    suite-out: reports/suite.json
    suite-markdown: reports/suite.md
```

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

- [`docs/architecture.md`](docs/architecture.md)
- [`docs/acceptance-tests.md`](docs/acceptance-tests.md)
- [`docs/project-compatibility-suite.md`](docs/project-compatibility-suite.md)
- [`docs/falco-parity.md`](docs/falco-parity.md)
- [`docs/backend-execution-proof.md`](docs/backend-execution-proof.md)
- [`docs/upstream-kernel-virtme-ng.md`](docs/upstream-kernel-virtme-ng.md)
- [`docs/firecracker-backend.md`](docs/firecracker-backend.md)
- [`docs/profile-catalog.md`](docs/profile-catalog.md)
- [`docs/validator.md`](docs/validator.md)
- [`docs/external-ci-proof.md`](docs/external-ci-proof.md)

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

## License

Apache-2.0. See [`LICENSE`](LICENSE).
