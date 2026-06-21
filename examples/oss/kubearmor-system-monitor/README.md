# KubeArmor `system_monitor` — reference behavior lane

This is the reference example for bpfcompat's **behavior lane**: an opt-in,
non-blocking validation depth that runs *after* load + attach, exercising the
syscalls a probe hooks and asserting the loaded program stays live and
non-disruptive on a real workload — not just verifier-accepted.

It validates KubeArmor's `system_monitor.bpf.o` as KubeArmor ships it (see
[`UPSTREAM.md`](./UPSTREAM.md) for how to build it; the `.bpf.o` is not vendored).

## Why this object

`system_monitor` is a host/container system monitor built from ~59 kprobes /
kretprobes on syscalls (`execve`, `openat`/`open`, `close`, `connect`, `accept`,
`socket`, `chown`, `unlink`, `setuid`/`setgid`, `ptrace`, `mount`, …) feeding a
`BPF_PERF_OUTPUT` ring. Two things make it a good reference:

1. **It carries a loader contract.** `kubearmor_visibility` is a
   `BPF_MAP_TYPE_HASH_OF_MAPS` whose inner per-namespace map KubeArmor's Go
   (cilium/ebpf) loader installs at runtime. A generic libbpf load has no inner
   prototype, so map creation fails with `EINVAL` on *every* kernel — including
   6.8 with BTF. [`manifest.yaml`](./manifest.yaml) declares that prototype
   (`maps[].inner_map`) so the object loads the way KubeArmor loads it.
2. **It is kernel-sensitive.** kprobes on `__x64_sys_*` symbols are exactly where
   "kernel version ≠ symbol availability" bites.

## Run it

```sh
# build the object from a KubeArmor checkout (see UPSTREAM.md), then:
bpfcompat test \
  --artifact path/to/system_monitor.bpf.o \
  --manifest examples/oss/kubearmor-system-monitor/manifest.yaml \
  --matrix   examples/oss/kubearmor-system-monitor/matrix.yaml \
  --validation-mode behavior
```

## Result (behavior mode, validated)

| Kernel | Host kernel | Load | Attach (best-effort) | Functional |
|---|---|---|---|---|
| Ubuntu 20.04 (5.4) | `5.4.0-216` | pass | 52/55 | **pass** |
| Ubuntu 22.04 (5.15) | `5.15.0-181` | pass | 52/55 | **pass** |
| Debian 12 (6.1) | `6.1.0-49` | pass | 52/55 | **pass** |
| Ubuntu 24.04 (6.8) | `6.8.0-117` | pass | 52/55 | **pass** |
| AlmaLinux 8 (4.18) | `4.18.0-553` | pass | 52/55 | **pass** |

The functional test (`syscall-stimulus-under-live-monitor`) creates/reads/removes
a file, runs a subprocess, and touches uid/gid syscalls while all attachable
probes are live, asserting each produced the correct result. It passes down to
the RHEL 8 / 4.18 ABI.

The 3 probes that don't attach are **the same 3 on every kernel** (including
6.8), i.e. kprobe symbols that differ across kernels — not a per-version
regression. Attach is `best-effort` here, so they are reported as `warn` and do
not fail the gate.

## What this lane proves — and what it does not

- **Proves:** the object loads (honoring the inner-map contract), attaches its
  probes, and that the loaded+attached monitor runs correctly on a real syscall
  workload across kernels.
- **Does *not* prove (Phase 2):** that a captured event actually reaches the
  `sys_events` perf buffer. That assertion needs KubeArmor's own userspace
  reader to drain the ring and confirm an event was emitted. The behavior-lane
  framework supports it — point a functional test at a reader that prints a
  marker on receipt and assert on it — but it is intentionally out of scope for
  this third-party reference, which validates the object exactly as shipped.

## Gate semantics

`required: false` on the functional test keeps this **non-blocking**: results are
reported but do not trip the exit-2 compatibility gate. Promote a test to
`required: true` once an artifact has proven stable, or declare specific
programs' `attach.required: true` to make attach gating.
