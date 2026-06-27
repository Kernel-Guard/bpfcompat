# Project Compatibility Suite

The suite command is the reusable path for projects that ship more than one
eBPF artifact.

It runs a list of artifacts against one or more VM-backed matrices, preserves
the normal per-artifact JSON/Markdown reports, and writes one suite-level
summary for CI and release artifacts.

## Example

```bash
make validator-static
make examples

./bin/bpfcompat suite \
  --suite suites/dev-functional.yaml \
  --out reports/suites/dev-functional/suite.json \
  --markdown reports/suites/dev-functional/suite.md
```

## Suite File

Paths in a suite file are resolved relative to the suite file location. This
keeps external repositories portable when the GitHub Action runs from its own
checked-out action directory.

```yaml
name: my-bpf-suite
defaults:
  matrix: ../matrices/dev-one.yaml
  workdir: ../.bpfcompat
  report_dir: ../reports/suites/my-bpf-suite
  validation_mode: load_attach
  timeout: 8m
  concurrency: 1
cases:
  - name: exec-tracepoint
    artifact: ../build/exec_tracepoint.bpf.o
    manifest: ../manifests/exec_tracepoint.yaml
    artifact_name: exec_tracepoint
  - name: network-xdp
    artifact: ../build/network_xdp.bpf.o
    manifest: ../manifests/network_xdp.yaml
    artifact_name: network_xdp
    validation_mode: load_only
  - name: exec-behavior
    artifact: ../build/exec_tracepoint.bpf.o
    manifest: ../manifests/exec_tracepoint.yaml
    artifact_name: exec_tracepoint
    validation_mode: behavior
    test:
      mode: behavior
      command: ./scripts/smoke-exec.sh
      timeout: 30s
      expect:
        exit_code: 0
        stdout_contains: saw-execve
```

Each case supports the same core inputs as `bpfcompat test`:

- `artifact`
- `artifact_uri`
- `artifact_name`
- `artifact_version`
- `artifact_variant`
- `matrix`
- `manifest`
- `out`
- `markdown`
- `workdir`
- `runner`
- `validation_mode`
- `timeout`
- `concurrency`
- `keep_vm_on_failure`

`validation_mode` controls what each case proves:

- `load_only`: run libbpf load/verifier checks and skip attach and behavior
  commands. This is useful for fast kernel compatibility screening.
- `load_attach`: run load plus attach checks. This is the default suite/web
  gate behavior for most artifacts.
- `behavior`: run load, attach, and functional commands while the BPF links are
  alive. This is the closest match for Falco-style event/smoke assertions.

Behavior commands can be declared in a manifest using `functional_tests`, or
inline in the suite with a `test` block. The inline block is converted into a
generated manifest before the runner starts:

```yaml
cases:
  - name: exec-behavior
    artifact: ../build/exec_tracepoint.bpf.o
    manifest: ../manifests/exec_tracepoint.yaml
    test:
      mode: behavior
      command: ./scripts/smoke-exec.sh
      expect:
        exit_code: 0
        stdout_contains: saw-execve
```

Suite JSON includes per-case target verdicts, and suite Markdown includes both
the case summary and a collection matrix. The matrix is intentionally
high-level: it shows which artifact case passed or failed on each target first,
then links to the per-artifact reports for verifier logs, BTF/CO-RE state,
attach evidence, and behavior-test output.

## GitHub Action

Single-artifact mode remains supported. Suite mode is enabled by setting
`suite`:

```yaml
- uses: Kernel-Guard/bpfcompat@v0.2.0
  with:
    suite: suites/dev-functional.yaml
    suite-out: reports/bpfcompat-suite.json
    suite-markdown: reports/bpfcompat-suite.md
    timeout: 8m
    concurrency: "1"
```

The action writes the suite Markdown to the GitHub job summary and preserves
the per-artifact report files declared by the suite.

## Why This Exists

This matches the integration shape requested by real eBPF maintainers:

1. choose a VM/kernel matrix,
2. provide a list of BPF artifacts,
3. provide manifests that describe attach and functional test steps,
4. fail CI on compatibility regressions,
5. keep a detailed report artifact for debugging.

## Adapter Template

For an external project starting from scratch, copy the template under:

```text
adapters/generic-ebpf-suite/
```

It includes:

- a suite file with multiple artifact cases,
- a manifest with a functional event assertion,
- a GitHub Actions workflow for a self-hosted Linux/KVM runner.

This is the recommended integration shape for projects that do not already
have Falco-style kernel-testing infrastructure.
