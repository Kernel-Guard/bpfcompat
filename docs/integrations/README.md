# Integration templates

Copy-paste starting points for wiring bpfcompat into your project. Pick by how
your project loads eBPF, not by what it does.

| Your project | Template |
|---|---|
| Loads eBPF from **Go** (libbpfgo, ebpf-go/cilium) | [`go-loader-compatibility.yml`](go-loader-compatibility.yml) |
| Loads eBPF from **Rust** (Aya) | [`rust-aya-compatibility.yml`](rust-aya-compatibility.yml) |
| Publishes eBPF as **OCI artifacts** (Inspektor Gadget gadgets) | [`inspektor-gadget-compatibility.yml`](inspektor-gadget-compatibility.yml) |
| Loads eBPF **at runtime** in a daemon or agent | [`library-gate.go.md`](library-gate.go.md) |
| Loads eBPF from **C/libbpf** | Use the Go template and swap the build step; the contract is the binary, not the language. A live example is the [falcosecurity/libs lane](https://github.com/falcosecurity/libs/blob/master/.github/workflows/bpfcompat-compatibility.yml), which builds `scap-open` and runs it. |

## The one idea behind all of them

**Bring your own loader. There is nothing to maintain.**

bpfcompat does not re-implement your load path or ask you to describe it in a
manifest. It ships *your* binary into a VM running an unmodified vendor cloud
image, runs it, and takes the exit code as the verdict for that kernel. There
is no second description of your program to drift out of sync, because there is
no second description.

This matters more than it sounds. A libbpf load result does not transfer to
ebpf-go or Aya — those are independent loaders that trail libbpf and can
diverge on older kernels. The only result that is true for your users is the
one produced by the loader you actually ship.

## Why vendor kernels, not kernel versions

The default `quirk-library` matrix boots real vendor images, because on
enterprise kernels the version number stops predicting behaviour:

- RHEL-family **4.18** backports the BPF ring buffer, so an object using it
  passes there and fails on Ubuntu's *newer* vanilla **5.4**.
- BPF-LSM is active in RHEL **9.4** but not **9.2** — the same 5.14 line.

Test images built from upstream kernel versions structurally cannot show you
either of those. Real vendor images can.

## Pinning and supply chain

Every template pins the action by commit SHA. A SHA that matches a release tag
resolves to prebuilt, checksum-verified binaries, so your runner needs no
toolchain; any other ref builds from source and needs `libbpf-dev` and
`zlib1g-dev`. Releases are cosign-signed with SBOM and SLSA provenance.

## Running it somewhere real

The [falcosecurity/libs](https://github.com/falcosecurity/libs) lane runs this
weekly against Falco's `modern_bpf` probe, driven by Falco's own loader
([workflow](https://github.com/falcosecurity/libs/blob/master/.github/workflows/bpfcompat-compatibility.yml)).
