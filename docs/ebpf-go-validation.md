# Validating with ebpf-go (cilium/ebpf) instead of libbpf

bpfcompat's bundled validator is built on **libbpf** — the kernel's reference
loader. But if your project loads its objects with
[ebpf-go](https://github.com/cilium/ebpf) (most Go eBPF projects do), that
verdict has a gap: ebpf-go is libbpf-compatible *for the features it supports*,
uses libbpf as its reference implementation, and by its own documentation
trails libbpf's feature set. It is a **separate loader implementation**, so:

> A libbpf load-pass does not guarantee an ebpf-go load-pass on the same
> kernel — and vice versa.

If you ship with ebpf-go, validate through ebpf-go. Command mode makes this a
one-binary recipe: build a tiny static Go loader, ship it into each matrix
kernel, and the per-kernel verdict is *your* loader's exit code.

## The loader

[`examples/ebpf-go-loader`](../examples/ebpf-go-loader/main.go) is a complete,
copyable implementation (~50 lines): parse the object, load every map and
program via `ebpf.NewCollection`, print the verifier log on rejection, exit
`0`/`1`. It reads the object path from `$BPFCOMPAT_ARTIFACT` (set by
bpfcompat inside the guest) or `argv[1]`.

It is a **standalone Go module**, so its `cilium/ebpf` dependency stays out of
the main bpfcompat module. Extend it with your project's real invariants —
attach the programs, poke a map, run your feature probes — the exit code is
the contract.

## Build it static, run it everywhere

Go with `CGO_ENABLED=0` produces a fully static binary — exactly what command
mode wants, since the disposable guests have no Go toolchain and varying
libc versions:

```bash
cd examples/ebpf-go-loader
CGO_ENABLED=0 go build -o ebpf-go-loader .

# Run it across the library of known-tricky vendor kernels:
bpfcompat test-command \
  --cmd '$BPFCOMPAT_BIN $BPFCOMPAT_ARTIFACT' \
  --bin ./ebpf-go-loader \
  --artifact ./your_object.bpf.o \
  --matrix matrices/quirk-library.yaml \
  --out report.json
```

Or in CI with the GitHub Action:

```yaml
- run: cd examples/ebpf-go-loader && CGO_ENABLED=0 go build -o ebpf-go-loader .
- uses: Kernel-Guard/bpfcompat@v0.2.0
  with:
    command: $BPFCOMPAT_BIN $BPFCOMPAT_ARTIFACT
    command-binary: examples/ebpf-go-loader/ebpf-go-loader
    artifact: your_object.bpf.o
    matrix: quirk-library
    out: reports/bpfcompat.json
```

## What a real run looks like

Shipping this loader with a ring-buffer object
(`examples/ringbuf-modern/ringbuf_modern.bpf.o`) across the version-lies
contrast trio:

| Kernel | ebpf-go loader verdict | Why |
|---|---|---|
| `ubuntu-20.04-5.4` | ❌ exit 1 — `map events: map create: invalid argument` | ring buffer lands upstream in 5.8 |
| `almalinux-8-4.18` | ✅ exit 0 — loaded 1 program, 1 map | RHEL backports ring buffer onto 4.18 |
| `ubuntu-22.04-5.15` | ✅ exit 0 — loaded 1 program, 1 map | comfortably past the boundary |

Same object, three kernels, and the *lower-numbered* enterprise kernel passes
while the higher-numbered upstream one fails — through the loader your users
actually run. The libbpf load/attach phase reports `skipped`; the verdict is
entirely ebpf-go's.

## Notes

- **Keep the loader in your repo**, built from your go.mod — the point is to
  validate *your* ebpf-go version and load options, not ours.
- ebpf-go needs kernels ≥ 4.9 (and the example calls
  `rlimit.RemoveMemlock()` for pre-5.11 map accounting).
- For richer checks (attach, map round-trip, feature probes à la
  `features.HaveMapType`), grow the loader; command mode only cares about the
  exit code.
