# Library of known-tricky vendor kernels

A curated catalog of real distro kernels where **"kernel version ≠ eBPF feature
support."** These are the kernels that surprise you in production: upstream
feature boundaries, enterprise backports that carry new features onto old bases,
no-BTF kernels, vendor rebases, and program-variant fallback bands.

Every entry is a kernel bpfcompat **actually boots** (real vendor cloud image in
a disposable VM) and has evidence for — not a version string we inferred from.
Run the whole library against a `.bpf.o` *or* your own loader (command mode):

```bash
# A compiled object, the default validator:
bpfcompat test --artifact build/probe.bpf.o \
  --matrix matrices/quirk-library.yaml --out report.json --markdown report.md

# Your own loader binary/command (see docs/command-validation.md):
bpfcompat test --command '$BPFCOMPAT_BIN --self-test' --command-binary ./build/loader \
  --matrix matrices/quirk-library.yaml --out report.json
```

The matrix is [`matrices/quirk-library.yaml`](../matrices/quirk-library.yaml).
Profiles whose pass/fail is artifact-dependent (genuine feature boundaries) are
`required: false`, so the library never forces a verdict the kernel itself
decides.

## The catalog

The "verdict" column below is the **observed** result of running a ring-buffer
probe (`examples/ringbuf-modern/ringbuf_modern.bpf.o`) across the library — see
[Fresh evidence](#fresh-evidence-2026-06-29).

| Profile | Real kernel | The quirk | Ring-buffer probe |
|---|---|---|---|
| `ubuntu-20.04-5.4` | 5.4.0-216 | Ring-buffer maps land upstream in **5.8** — not present here | ❌ `UNSUPPORTED_MAP_TYPE` (high) — *correct*, not a bug |
| `ubuntu-20.10-5.8` | 5.8.0-63 | First upstream kernel **with** ring buffer | ✅ pass — the other side of the line |
| `almalinux-8-4.18` | 4.18.0-553.el8 | **Version lies:** RHEL backports ring buffer onto 4.18, so it works on a kernel numbered *older* than the 5.4 that failed | ✅ **pass despite 4.18** |
| `rocky-8-4.18` | 4.18.0-…el8 | Same RHEL-8 backport base (ABI-compatible rebuild) | ✅ pass |
| `centos-stream-9-5.14` | 5.14.0-706.el9 | RHEL-9 base: 5.14 carrying many 6.x BPF features | ✅ pass |
| `amazon-linux-2-4.14` | 4.14.26-…amzn2 | **Backports are not uniform:** Amazon's 4.14 (no embedded BTF) does **not** carry the ring-buffer backport that RHEL's 4.18 does | ❌ `UNSUPPORTED_MAP_TYPE` — a *simple* program loads here, ring buffer does not |
| `amazon-linux-2-5.10` | 5.10.247-…amzn2 | Amazon backport tier | ✅ pass |
| `oracle-linux-9-uek7-5.15` | **6.12.0**-…el9uek | **Version-string trap:** the `uek7-5.15` profile actually boots a **6.12** UEK kernel on an EL9 userspace | ✅ pass (test, don't assume from the name) |
| `opensuse-leap-15.6-6.4` | 6.4.0-…default | SUSE backport tier | ✅ pass |
| `ubuntu-22.04-5.15` | 5.15.0-173 | **Program-variant fallback band:** a loader must select the `*_old_x` syscall variants; `dump_task` is unsupported | ✅ pass *with the right variant selection* |
| `debian-12-6.1` | 6.1.0-47 | Newer band: `bpf_loop` variants + both BPF iterators available | ✅ pass with the modern variants |

The two ❌ rows are `required: false`: a ring-buffer probe *should* be rejected
there, and that rejection is the evidence, not a failure of the run.

## Fresh evidence (2026-06-29)

Run of `ringbuf_modern.bpf.o` across the library (`load_attach`, real QEMU/KVM
VMs, run `20260629T145413Z-5b261e`). The standout pair:

- **`ubuntu-20.04-5.4` ❌ vs `almalinux-8-4.18` ✅** — the *higher* version number
  (5.4) fails ring buffer while the *lower* one (RHEL 4.18) passes it, because
  RHEL backported the feature. Version number predicts the wrong answer.
- **`almalinux-8-4.18` ✅ vs `amazon-linux-2-4.14` ❌** — two old-numbered
  enterprise kernels disagree on the *same* probe: RHEL backported ring buffer to
  4.18, Amazon did not backport it to 4.14. **"Enterprise backport" is not a
  blanket guarantee — it's per-vendor, per-feature, and has to be tested.**
- `oracle-linux-9-uek7-5.15` actually booted `6.12.0-…el9uek` — the UEK rebase
  ran a far newer kernel than the profile name implies, and still passed.

All other kernels (5.8, 5.10, 5.14, 5.15, 6.1, 6.4) loaded and attached the
ring-buffer probe. The failures carry `classification_code:
UNSUPPORTED_MAP_TYPE` with the verifier detail (`map "events" failed to create —
Invalid argument (-22)`), so a CI gate or human gets the *why*, not just a ❌.

## Why these specific kernels

The catalog is assembled from kernels with documented, reproduced behavior:

- **Ring-buffer boundary + the backport that breaks the rule** — the 5.4 fail vs
  5.8 pass vs AlmaLinux-8 *4.18* pass is the canonical "version ≠ support"
  demonstration. Evidence:
  [case-study-falco-modern-bpf.md](case-study-falco-modern-bpf.md),
  [case-study-enterprise-kernels.md](case-study-enterprise-kernels.md).
- **No-BTF backport (Amazon Linux 2 / 4.14)** — boots and validates
  `load_attach` on a real `4.14.26-54.32.amzn2`; see the enterprise case study.
- **Program-variant bands (5.15 vs 6.1+)** — which syscall variants and
  iterators each kernel accepts, recorded per profile in the Falco modern_bpf
  study.
- **Enterprise/rebase tier (RHEL-family, Oracle UEK, SUSE)** — the 14/14
  backported-tier run in the enterprise case study.

## Scope and honesty

- These are **independent tests of public distro images**; not affiliated with or
  endorsed by Red Hat, AlmaLinux, Rocky, Oracle, Amazon, or SUSE.
- "Tricky" means *behavior is not predictable from the version number*, not that
  the kernel is defective. A ❌ on `ubuntu-20.04-5.4` for a ring-buffer probe is
  the kernel correctly rejecting an unsupported feature.
- RHEL itself is subscription-walled; AlmaLinux/Rocky/CentOS Stream are the free,
  ABI-compatible rebuilds used as the reproducible RHEL stand-in. RHCOS/OpenShift
  is a separate opt-in, operator-supplied path
  ([rhcos-openshift.md](rhcos-openshift.md)).
- The list grows as new quirks are reproduced with evidence. It is deliberately
  small and verified rather than large and inferred.
