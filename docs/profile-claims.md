# Profile Claims: Claimed vs Observed

A profile in `vm/profiles/*.yaml` makes claims: a distribution and release
(`distro`, `version`), a kernel series (`kernel_family`), and sometimes a
property in its id (`-minimal`, `-lockdown`). [`support-matrix.md`](support-matrix.md)
says which profiles **can run**. This page says which of their claims a booted
guest has **actually shown**, and proposes which profiles may gate a release.

Reports already separate requested from observed identity
(`targets[].environment`, see the environment contract in
[`compatibility-contract.md`](compatibility-contract.md)). That covers the
distribution (`/etc/os-release`) and the kernel series. It does **not** cover
security posture: kernel lockdown, Secure Boot, and the LSM stack are not
recorded in reports. A posture word in a profile id is therefore not evidence.

Snapshot: 2026-10-15, base `main` 2f3d1c1. Future-targeted; this page is not
part of the v0.4.0-rc.4 qualification evidence.

## Kernel lockdown: claimed, not observed

The `ubuntu-22.04-5.15-lockdown` profile and its kernel-sweep children
(`…-k5.15.0-186`, `…-k5.15.0-189`) advertised lockdown through their id and
through `version: "22.04-lockdown"`. Nothing in the repository establishes it:

- **Image.** The profile downloads the stock Ubuntu 22.04 cloud image
  (`jammy/current/jammy-server-cloudimg-amd64.img`). No build step, script or
  Makefile target customises it. The cached `vm/cache/ubuntu-22.04-lockdown.qcow2`
  on the operator host is **byte-identical** to `vm/cache/ubuntu-22.04.qcow2`
  (both sha256 `7cd6b514bcc6c43180270f7817efecf140297edd0768351fddfbed9858bd21b7`).
- **Boot.** On x86_64 the executor starts QEMU with no firmware arguments,
  i.e. legacy SeaBIOS. Only aarch64 gets UEFI firmware (`internal/vm/qemu.go`).
  With no UEFI there is no Secure Boot, and Ubuntu's kernel only enables
  lockdown automatically under Secure Boot.
- **Command line.** Nothing adds `lockdown=` to the guest kernel command line.
- **Kernels.** The sweep children install `linux-image-unsigned-*` packages.
  An unsigned kernel could not boot under Secure Boot, so these profiles could
  not represent a Secure Boot lockdown host even with UEFI.

Observed under KVM on 2026-10-15 (command mode, local KVM host, probe script
reading the files below; report-level fields from `targets[].environment`):

| Profile | Observed kernel | os-release | `/sys/kernel/security/lockdown` | `/proc/cmdline` | Firmware |
|---|---|---|---|---|---|
| `ubuntu-22.04-5.15-lockdown` | `5.15.0-185-generic` | `ubuntu 22.04` | `[none] integrity confidentiality` | `BOOT_IMAGE=/boot/vmlinuz-5.15.0-185-generic root=LABEL=cloudimg-rootfs ro console=tty1 console=ttyS0` | no `/sys/firmware/efi` (legacy BIOS); `mokutil`: EFI variables not supported |
| `ubuntu-22.04-5.15-lockdown-k5.15.0-189` | `5.15.0-189-generic` | `ubuntu 22.04` | `[none] integrity confidentiality` | `BOOT_IMAGE=/boot/vmlinuz-5.15.0-189-generic root=UUID=… ro console=tty1 console=ttyS0` | legacy BIOS |
| `ubuntu-22.04-5.15-lockdown-k5.15.0-186` | not booted | — | not observed; same image and boot path, so expected `[none]` | — | legacy BIOS (same executor path) |

Both booted guests also reported `CONFIG_SECURITY_LOCKDOWN_LSM=y`,
`CONFIG_SECURITY_LOCKDOWN_LSM_EARLY=y`, `CONFIG_LOCK_DOWN_KERNEL_FORCE_NONE=y`,
LSM list `lockdown,capability,landlock,yama,apparmor`, and
`kernel.unprivileged_bpf_disabled=2`. The lockdown LSM is compiled in but set
to `none`.

**Verdict: lockdown is not enforced.** Results from these profiles are plain
Ubuntu 22.04 / 5.15 GA-kernel results. They say nothing about how an artifact
behaves under lockdown: `integrity` blocks `bpf_probe_write_user`, and
`confidentiality` also blocks BPF reads of kernel memory such as
`bpf_probe_read_kernel`.

### Correction made here

The smallest honest correction, without renaming ids (renaming would break
matrices, `vm/kernel-baselines.yaml`, freshness derivation and history):

- `version` is now the distribution release, `"22.04"`, in the base profile
  and both sweep children (the same value `bpfcompat kernel-sweep` would
  regenerate from the base). The base profile carries a comment stating that
  lockdown is not enforced.
- `matrices/expanded-2026.yaml` and `matrices/tier3-cloud-native.yaml` mark the
  profile `required: false`.
- The generated support matrix annotates every `*-lockdown*` profile as
  "kernel lockdown NOT enforced".
- `internal/vm/catalog_posture_test.go` fails if a profile's `version`
  advertises lockdown, or if a hand-maintained matrix requires a
  lockdown-named profile. Generated `kernel-sweep-*` matrices are exempt: they
  are a per-release freshness lane and are regenerated, not edited.

**Coverage consequence.**

- *expanded-2026:* no loss. The required `ubuntu-22.04-5.15` target already
  covers Ubuntu 22.04 on the 5.15 GA kernel with a sha256-pinned image. The
  lockdown profile was an unpinned duplicate of it.
- *tier3-cloud-native:* the matrix now has **no required target**, so its run
  verdict is informational (`RunVerdict` only considers required targets).
  That is accurate: no profile in it establishes a cloud-native or hardened
  posture today. The other five are immutable or manual images that the
  current executor cannot run, or that need images the operator must supply.
- *No frozen qualification input lists any lockdown profile*, so release,
  canary and campaign coverage is unchanged (see the list below).

### To actually cover lockdown (proposal, not done here)

1. Boot an x86_64 profile with `lockdown=integrity` (and separately
   `confidentiality`) on the kernel command line, or boot UEFI with Secure Boot
   and a signed kernel.
2. Record `/sys/kernel/security/lockdown` in the report as an observed
   environment field.
3. Only then let a lockdown profile be `required`, and only with a report
   showing `[integrity]` or `[confidentiality]`.

## Claimed vs observed: commonly used matrices

Profiles from `dev-one`, `mvp`, the built-in `--quick` set
(`internal/matrix.QuickProfileIDs`), `expanded-2026` and `tier3-cloud-native`.
`*` after a matrix name means `required: true` there (after this change).

Evidence classes:

- **VM**: booted for this page.
- **L**: a local KVM report from another lane, 2026-10-13..15.
- **H**: a hosted-CI report artifact: release gate 2026-10-14, rc.4 canaries
  38609546766 / 38609582942, latest-kernel 38449327759, quirk-library
  38429421132.
- **B**: `vm/kernel-baselines.yaml`, the last recorded kernel and its date.

"unknown" means no report we could inspect recorded it. "kernel only" means the
report predates `observed_os_id`.

| Profile | In matrices | Claimed distro / version / family | Observed os-release | Observed kernel | Evidence | Image |
|---|---|---|---|---|---|---|
| ubuntu-22.04-5.15 | dev-one\*, mvp\*, expanded-2026\* | ubuntu 22.04 / 5.15 | ubuntu 22.04 | 5.15.0-186-generic | H (release gate, canary), L | pinned `757908b2…` |
| ubuntu-18.04-4.15 | mvp\*, expanded-2026\* | ubuntu 18.04 / 4.15 | ubuntu 18.04 | 4.15.0-212-generic | L, B | unpinned URL |
| ubuntu-20.04-5.4 | mvp\*, expanded-2026\*, quick | ubuntu 20.04 / 5.4 | ubuntu 20.04 | 5.4.0-216-generic | L, H (kernel only), B | unpinned URL |
| ubuntu-22.04-minimal-5.15 | mvp, expanded-2026 | ubuntu 22.04 / 5.15 | ubuntu 22.04 | 5.15.0-1104-kvm | L, B | unpinned URL |
| ubuntu-24.04-6.8 | mvp, expanded-2026\*, quick | ubuntu 24.04 / 6.8 | ubuntu 24.04 | 6.8.0-142-generic (B: 6.8.0-136) | H, B | unpinned URL |
| debian-11-5.10 | mvp, expanded-2026 | debian 11 / 5.10 | debian 11 | 5.10.0-42-cloud-amd64 | L, B | unpinned URL |
| debian-12-6.1 | mvp\*, expanded-2026\*, quick | debian 12 / 6.1 | debian 12 | 6.1.0-53-cloud-amd64 (H); 6.1.0-47-cloud-amd64 (L) | H, L, B | unpinned URL; **drift**: two kernels from one URL |
| debian-13-6.12 | mvp, expanded-2026 | debian 13 / 6.12 | debian 13 | 6.12.86+deb13-cloud-amd64 | L, B | unpinned URL |
| ubuntu-22.04-5.15-lockdown | expanded-2026, tier3-cloud-native | ubuntu 22.04 / 5.15, **+lockdown** | ubuntu 22.04 | 5.15.0-185-generic; **lockdown `[none]`** | VM, B | unpinned URL |
| oracle-linux-9-uek7-5.15 | expanded-2026\* | oracle 9 / 5.15 | unknown | 6.12.0-107…el9uek (H, before the rc.4 pin fix: **mismatch**); 5.15.0-325.221.6.1.el9uek (L, after) | H, L, B | unpinned URL + pinned kernel install |
| amazon-linux-2023-6.1 | expanded-2026\* | amazon-linux 2023 / 6.1 | unknown | B only: 6.1.176-223.369.amzn2023 (2026-07-30) | B | unpinned URL |
| sles-15.6-6.4 | expanded-2026\* | sles 15.6 / 6.4 | unknown | B only: 6.4.0-150600.23.100 (2026-05-19) | B | manual image |
| ubuntu-20.10-5.8 | expanded-2026\* | ubuntu 20.10 / 5.8 | unknown (kernel only) | 5.8.0-63-generic | H, B | unpinned URL |
| ubuntu-23.10-6.5 | expanded-2026\* | ubuntu 23.10 / 6.5 | unknown | B only: 6.5.0-44-generic (2026-06-11) | B | unpinned URL |
| rhel-8-4.18 | expanded-2026 | rhel 8 / 4.18 | **ol 8.10** | **5.15.0-206.153.7.1.el8uek** | L | manual image (operator-supplied image is Oracle Linux; known, see CHANGELOG 0.4.0-rc.4) |
| almalinux-8-4.18 | expanded-2026 | almalinux 8 / 4.18 | almalinux 8.10 | 4.18.0-553.168.1.el8_10 (H); 4.18.0-553.124.4.el8_10 (L) | H, L | unpinned URL; drift |
| rocky-8-4.18 | expanded-2026 | rocky 8 / 4.18 | unknown (kernel only) | 4.18.0-553.el8_10 | H | unpinned URL |
| centos-stream-9-5.14 | expanded-2026 | centos-stream 9 / 5.14 | unknown (kernel only) | 5.14.0-756.el9 (B: 5.14.0-722.el9) | H, B | unpinned URL; drift |
| amazon-linux-2-5.10 | expanded-2026 | amazon-linux 2 / 5.10 | unknown (kernel only) | 5.10.260-259.1054.amzn2 | H, B | unpinned URL |
| amazon-linux-2-4.14 | expanded-2026 | amazon-linux 2 / 4.14 | unknown (kernel only) | 4.14.26-54.32.amzn2 | H | release-dated URL; **runs**, though support-matrix lists it "not runnable" |
| opensuse-leap-15.6-6.4 | expanded-2026 | opensuse 15.6 / 6.4 | unknown (kernel only) | 6.4.0-150600.23.100-default | H, B | unpinned URL |
| ubuntu-24.10-6.11 | expanded-2026 | ubuntu 24.10 / 6.11 | ubuntu 24.10 | 6.11.0-29-generic | H, B | unpinned URL |
| ubuntu-25.04-6.14 | expanded-2026 | ubuntu 25.04 / 6.14 | ubuntu 25.04 | 6.14.0-37-generic | H, B | unpinned URL |
| ubuntu-25.10-6.17 | expanded-2026 | ubuntu 25.10 / 6.17 | ubuntu 25.10 | 6.17.0-40-generic (B: 6.17.0-22) | H, B | unpinned URL |
| ubuntu-16.04-4.4, ubuntu-20.04-minimal-5.4, almalinux-9-5.14, rocky-9-5.14, ubuntu-24.04-minimal-6.8, oracle-linux-10-uek8-6.12, almalinux-10-6.12, rocky-10-6.12, centos-stream-10-6.12, ubuntu-25.10-minimal-6.17 | expanded-2026 | as named | unknown | B only (kernel family consistent with the claim) | B | unpinned URL |
| linux-mainline-5.6, bottlerocket-aws-6.1, talos-6.6, fedora-coreos-stable-7.0, rhcos-4.16-5.14, flatcar-6.6 | expanded-2026 and/or tier3-cloud-native | as named | unknown | unknown | none inspected | manual image or not runnable on the current executor |

All URL-backed profiles in `expanded-2026` (33) answered HTTP 200/302 in a
`make profile-catalog-audit` run on 2026-10-15. The five manual-image profiles
have no URL to probe.

Findings beyond lockdown (reported here, not changed):

- **Unpinned images drift.** One source URL produced different kernels on
  different hosts or days: `debian-12-6.1` (6.1.0-47 vs 6.1.0-53),
  `almalinux-8-4.18` and `centos-stream-9-5.14`. Only `ubuntu-22.04-5.15`
  (and two of its sweep children) pin `image.sha256`. A result from an
  unpinned profile is attributable through the recorded image hash, but it
  is not reproducible from the profile alone.
- **Required but never observed in an inspected report.**
  `amazon-linux-2023-6.1`, `sles-15.6-6.4` and `ubuntu-23.10-6.5` are
  `required: true` in `expanded-2026`, and the only evidence for them is a
  baseline kernel 3–5 months old.
- **`amazon-linux-2-4.14` is understated.** It boots and passes in the hosted
  quirk-library lane, yet `scripts/support-matrix.sh`,
  `scripts/generate-runnable-matrix.sh` and `scripts/matrix-readiness.sh`
  hard-code it as not runnable. `generate-runnable-matrix.sh` is read by the
  frozen latest-kernel workflow, so reclassifying it is left to a follow-up
  that changes all three together.

## Proposed status classes

These classes are a proposal. Nothing enforces them yet except the lockdown
rule above. "Load", "attach" and "command-mode" refer to the loader contract
in [`compatibility-contract.md`](compatibility-contract.md). Attach semantics
(per-program attach accounting, and whether a required attach can be a partial
pass) are being defined by the pending attach-truth change (#254). This page
defers to that definition and does not restate it.

| Status | May be `required` in | Entry criteria | What a `COMPATIBLE` result on it supports |
|---|---|---|---|
| **Gating** | release, canary and campaign matrices | (1) image pinned by `image.sha256` to a release-versioned URL, or an operator image whose sha256 is recorded in the profile; (2) a real report from the last 30 days with `kernel_family_match: true` **and** `distro_match: true`; (3) every property the id or version advertises (`minimal`, `lockdown`, a vendor kernel line) is shown by recorded evidence; (4) runnable on the hosted or self-hosted KVM lane that runs the gate | **Load**: the validator loaded every program on the observed kernel. **Attach**: as the contract defines it once #254 lands; until then, attach is reported but is not a release claim. **Command mode**: the shipped loader exited as expected on that exact guest. All three are statements about the observed kernel and distribution, never about "similar" hosts. |
| **Reference** | non-release campaign matrices (`mvp`, `expanded-2026`, sweeps) | runnable, and the kernel series (and the distribution, where `os-release` is recorded) observed at least once, but the image is unpinned or the evidence is older than 30 days | The same load, attach and command-mode meaning, but only for the kernel recorded in that report. The profile id alone does not name a reproducible environment. |
| **Experimental** | never `required` | identity unobserved or mismatched; manual image with unverified identity; not runnable on the current executor; or the profile advertises a property that is not observed | Nothing beyond the per-run report itself. Results are informational. |

Proposed placement today, from the table above:

- **Gating**: `ubuntu-22.04-5.15`, the only profile that meets (1)–(4).
  `debian-12-6.1` (canary) and `centos-stream-9-5.14` (canary-source) qualify
  once their images are pinned.
- **Reference**: the other profiles with an observed matching kernel series:
  ubuntu 18.04/20.04/20.10/22.04-minimal/24.04/24.10/25.04/25.10,
  debian 11/12/13, almalinux-8, rocky-8, centos-stream-9, amazon-linux-2
  (5.10 and 4.14), opensuse-leap-15.6, and oracle-linux-9-uek7-5.15 (pending
  a hosted re-observation of 5.15 after the rc.4 pin fix).
- **Experimental**: the `ubuntu-22.04-5.15-lockdown` lineage (posture not
  observed), `rhel-8-4.18` (operator image observed as Oracle Linux), the
  manual and immutable-image profiles, and everything marked "B only" until a
  report shows its identity.

Applying the classes to frozen matrices (`dev-one`, `canary`, `canary-source`,
`consumer-external`, `latest-kernel-sweep`) would require pinning more images
and is a release-process decision. It is not made here.

## Frozen qualification inputs left untouched

These are read by the active release, canary or campaign qualification and
were not modified:

- `.github/campaign-candidate.json`
- `matrices/dev-one.yaml` (release-artifacts)
- `matrices/canary.yaml` (release-candidate-canary, consumer-canary)
- `matrices/canary-source.yaml` (consumer-canary source job)
- `matrices/consumer-external.yaml` (external-consumer-canary)
- `matrices/latest-kernel-sweep.yaml`, and the generated
  `matrices/latest-kernel-runnable.yaml` (latest-kernel-compatibility, the
  campaign)
- the profiles those matrices name, and `scripts/generate-runnable-matrix.sh`
  (latest-kernel-compatibility)

None of them references a lockdown profile.
