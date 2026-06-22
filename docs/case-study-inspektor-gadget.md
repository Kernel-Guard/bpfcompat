# Reference matrix: Inspektor Gadget gadgets across kernels (zero-config, from OCI)

A public, reproducible example of validating real, published eBPF **gadgets**
across kernels — pulled straight from their OCI registry, with no manifest and
no matrix file to write.

> Independent compatibility test of publicly available artifacts. Not affiliated
> with, sponsored by, or endorsed by Inspektor Gadget or Microsoft.

## What was tested

[Inspektor Gadget](https://github.com/inspektor-gadget/inspektor-gadget) ships
its gadgets as OCI images. bpfcompat can pull a gadget by reference, extract the
eBPF object, and validate it across kernels in one command:

```sh
bpfcompat test --artifact ghcr.io/inspektor-gadget/gadget/trace_open:latest --quick
```

- **No manifest, no matrix file.** `--quick` uses a built-in kernel set; the
  gadget's runtime-sized maps (compiled `max_entries=0`, sized by IG's loader at
  runtime) are auto-sized so the object loads the way the real loader runs it.
- **Validation mode:** load + attach, inside disposable QEMU/KVM VMs running each
  exact kernel.

## Results

### `trace_open` and `trace_exec` — clean compatibility matrices

| Kernel | `trace_open` | `trace_exec` | Notes |
|---|---|---|---|
| Ubuntu 20.04 — 5.4 | ❌ fail | ❌ fail | `events` ring buffer requires ≥ 5.8 |
| Debian 12 — 6.1 | ✅ pass (4/4 attach) | ✅ pass (6/6 attach) | runtime-sized `ig_build_id` auto-sized |
| Ubuntu 24.04 — 6.8 | ✅ pass (4/4 attach) | ✅ pass (6/6 attach) | runtime-sized `ig_build_id` auto-sized |

The `5.4` failure is the point: it is flagged with the exact mechanism (the
`events` ring buffer map cannot be created — ring buffer support lands in 5.8),
not a generic "it broke." Auto-sizing deliberately leaves ring-buffer and
perf-event maps untouched, so the boundary is reported truthfully.

Run against the full enterprise-aware matrix, `trace_open` additionally **passes
on AlmaLinux 8 (kernel 4.18)** — RHEL backported the ring buffer into 4.18, so
the gadget loads there even though it fails on Ubuntu's *newer* vanilla 5.4. That
is the canonical "kernel version ≠ feature support" case, shown empirically.

### `trace_dns` — two loader contracts, neither a kernel limit

`trace_dns` fails to load on **every** kernel (including 6.8 with BTF), which by
itself signals loader contracts rather than a compatibility boundary. It hits two,
in order:

**1. Program type (handled).** The first failure is:

```
prog 'ig_trace_dns': missing BPF prog type, check ELF section name 'socket1'
```

The DNS gadget is a **socket-filter** program in a `socket1` section — a section
name libbpf cannot map to a program type on its own, so IG's loader sets the type
explicitly. bpfcompat now does the same: it auto-types `socket`-prefixed programs
to `SOCKET_FILTER` (and a manifest `program_types:` override can set any type for
any program/section). With that, `trace_dns` clears the program-type stage.

**2. Framework API (the real boundary).** It then fails at a CO-RE relocation:

```
failed to resolve CO-RE relocation struct gadget_socket_value.ipv6only
```

`gadget_socket_value` / `gadget_sockets` is **Inspektor Gadget's socket-enricher
API** — not a kernel struct. Its BTF is supplied by IG's loader/runtime, so a
standalone load has nothing to relocate against, and it fails identically on 6.1
and 6.8. This is *not* a kernel-version result; it is the honest **boundary of
standalone gadget validation**: a framework-coupled gadget that depends on its
host runtime's injected API can be load-checked up to that contract, but fully
loading it would mean reproducing the IG runtime. The same applies to gadgets
whose attach points are rewritten by a WASM module (`fsnotify`, `fsslower`).

## Why this matters

The projects that ship eBPF gadgets (Inspektor Gadget) and the long tail of
third-party gadget authors both need the same answer before shipping: *does this
gadget load and attach on the kernels my users run?* With OCI loading + `--quick`
+ auto-sizing, that answer is a single command against the published artifact —
locally on a laptop or as a CI lane — with the failures classified, not just
counted.

## Reproduce

```sh
# any published gadget; --quick needs no matrix file, auto-size needs no manifest
bpfcompat test --artifact ghcr.io/inspektor-gadget/gadget/trace_open:latest --quick
bpfcompat test --artifact ghcr.io/inspektor-gadget/gadget/trace_exec:latest --quick
```

Artifacts are pulled from the public registry and validated as shipped; no source
changes. See [docs/quickstart.md](quickstart.md) for the trust model.
