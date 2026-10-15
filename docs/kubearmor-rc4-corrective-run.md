# KubeArmor corrective run for v0.4.0-rc.4

Status: **awaiting operator approval.** Nothing in this document has been run
against a guest kernel yet. The only execution so far is the `--dry-run`, which
does every step except booting guests.

## Why a corrective run is needed

> External-consumer-canary run **38609582942** (attempt 1, job **116009175474**)
> recorded the KubeArmor lane as passing for the v0.4.0-rc.4 candidate. That
> lane downloaded and ran the **v0.3.7** validator: `V=v0.3.7` was hard-coded
> in the guest command (`.github/workflows/external-consumer-canary.yml`, lines
> 114-123 at the rc.4 tag). Its sha256,
> `4ae1d5b838be07e6e7c304d753389a239c19eb92f6ba3bd77657e5c9583b9d04`, is
> **inferred**: it comes from the cosign-verified v0.3.7 `SHA256SUMS` entry that
> the guest's `sha256sum -c` checked against. The job log does not print the
> hash itself. **Run 38609582942 is NOT rc.4 KubeArmor evidence.** Its
> artifacts stay as they are. This procedure does not modify, overwrite or
> supersede them. It adds a separate evidence bundle.

The offline checker rejects the historical report on its own
(`check-kubearmor-corrective-evidence.sh --report-only`). It has no
`command.binary` identity, and neither kernel prints a
`bpfcompat-validator-sha256=` or `kubearmor-source-sha=` line.

## What is pinned

| Item | Value | Enforced by |
|---|---|---|
| bpfcompat checkout | tag `v0.4.0-rc.4` = `222c3f38a5361fca7c43c33df841290f8bef0021`, clean tree | runner step `checkout` |
| bpfcompat CLI | built from that checkout; `bpfcompat version --json` = `v0.4.0-rc.4` / `222c3f38a536` | runner `build-cli`, checker B2 |
| validator | release asset `bpfcompat-validator-static-linux-amd64` of `v0.4.0-rc.4`, sha256 `e0e7fcf8bd8384be3f85e4716d7330bdc0d3ae4d5de4070e815fa07c278be03a`, checked against `SHA256SUMS` and a GitHub build attestation (signer `release-artifacts.yml@refs/tags/v0.4.0-rc.4`, source digest = the commit) | `scripts/consumer-validator-identity.sh resolve` (PR #249), runner `resolve-validator`, checker B3/R2/R7/B6 |
| KubeArmor | explicit 40-hex commit passed on the command line, fetched by commit in each guest (never the floating default branch) | runner `pin-kubearmor`, guest `test "$(git rev-parse HEAD)" = "$KA_COMMIT"`, checker B4/B5/B6 |
| matrix | `matrices/consumer-external.yaml`: `ubuntu-24.04-6.8` and `almalinux-8-4.18`, both required | checker R4/R6 |
| guest command | PR #249's KubeArmor command with these changes: pinned commit; booted-kernel lines; the built object hashed after the build and again after the validator ran; `$BPFCOMPAT_BIN` hashed **before** it is executed and compared with the embedded `EXPECTED_VALIDATOR_SHA256=e0e7fcf8…` (the guest exits **93** without executing it on a mismatch); the full validator JSON printed between markers | runner writes `meta/guest-command.sh`; checker B4 binds it to the report's `invocation_sha256` |

### Proposed KubeArmor commit: `f2b2da6466b47285fb2d6ef2464def8ac1219ab1`

The goal is to re-test the KubeArmor source that run 38609582942 most likely
built, so that the validator is the only thing that changes. The guests ran
`git clone --depth 1` of the default branch (`main`) at about 2026-10-14T17:48Z.
The KubeArmor `main` push history comes from the GitHub repository activity API
(`GET /repos/kubearmor/KubeArmor/activity?ref=refs/heads/main`, read on
2026-10-15):

| timestamp (UTC) | before -> after |
|---|---|
| 2026-10-13T14:11:58Z | `de022883…` -> `ee4fbe28…` |
| 2026-10-14T10:55:24Z | `ee4fbe28…` -> **`f2b2da64…`** (feat: add support for audit alerts from bpflsm enforcer (#1644)) |
| 2026-10-15T07:31:10Z | `f2b2da64…` -> `28ae2f47…` |

So `main` was `f2b2da64…` from 2026-10-14T10:55:24Z to 2026-10-15T07:31:10Z,
and the clones happened inside that window. The run's KubeArmor report
artifact (`kubearmor.json`, in each target's `stderr_tail`; the job log does
not show it) records the libbpf submodule at
`67a4b1464349345e483df26ed93f8d388a60cee1`, which matches the gitlink at
`f2b2da64…`. That match does not prove the commit, though: the gitlink is the
same at `28ae2f47…`.

The question also matters less than it looks. The GitHub compare API
(`f2b2da64…...28ae2f47…`: ahead by 2, behind by 0) shows the only later
candidate changes just two files, `deployments/helm/KubeArmor/Chart.yaml` and
`deployments/helm/KubeArmorOperator/Chart.yaml` (+2/-2 each). The BPF source
under `KubeArmor/BPF` is identical under either candidate.

**Remaining uncertainty:** the historical log never printed the KubeArmor
commit. The attribution rests on the push timeline only. It would be wrong only
if the guests reached a different GitHub replica state, which is unlikely, and
even then the BPF source would be the same.

## Operator prerequisites

- Linux x86_64 host with read-write `/dev/kvm`, `qemu-system-x86_64`,
  `qemu-img`, `cloud-localds` (package `cloud-image-utils`; the AlmaLinux 8 seed
  needs it), `git`, `go` (the checkout's `go.mod` toolchain is fetched
  automatically), `jq`, `curl`, `make`.
- `gh` >= 2.50 (it needs `gh attestation`), authenticated, on `PATH`. A token
  that can read public attestations is enough.
- Outbound HTTPS to github.com, cloud-images.ubuntu.com, repo.almalinux.org,
  and the guest distro mirrors. Each guest installs clang/llvm and clones
  KubeArmor.
- Disk: the two cloud images are cached under `<checkout>/vm/cache/`
  (gitignored). The overlays (+4 GiB each, sparse) go under `<out-dir>.work/`.

On the preparing host these were all present on 2026-10-15
(`host/prerequisites.txt` in the dry-run bundle: `missing_pre_boot=none`,
`missing_boot=none`, `kvm-access=rw`, QEMU 8.2.2). One exception: the system
`/usr/bin/gh` there is 2.45.0, which has no `gh attestation`. The dry run used a
separately downloaded gh 2.102.0 put first on `PATH`, and a real run needs the
same. The runner aborts `INCONCLUSIVE` when attestation support is missing.

## Exact operator command

Run it from a checkout of this branch (it provides the two scripts plus PR
#249's `consumer-validator-identity.sh`). The rc.4 tree is a separate, clean
clone:

```sh
git clone --branch v0.4.0-rc.4 https://github.com/Kernel-Guard/bpfcompat /var/tmp/bpfcompat-rc4
git -C /var/tmp/bpfcompat-rc4 rev-parse HEAD   # must print 222c3f38a5361fca7c43c33df841290f8bef0021

export PATH=/path/to/gh-2.50-or-newer/bin:$PATH   # only if the system gh lacks `gh attestation`
bash scripts/kubearmor-corrective-run.sh \
  --checkout /var/tmp/bpfcompat-rc4 \
  --kubearmor-commit f2b2da6466b47285fb2d6ef2464def8ac1219ab1 \
  --out-dir /var/tmp/kubearmor-rc4-corrective-$(date -u +%Y%m%dT%H%M%SZ)

bash scripts/check-kubearmor-corrective-evidence.sh /var/tmp/kubearmor-rc4-corrective-<timestamp>
```

Add `--dry-run` to the first command to do everything except boot guests. The
`--out-dir` must not exist: bundles are write-once. The runner exits 0 only on
`VERIFIED` (or `DRY_RUN_OK`).

### Expected runtime

- Pre-boot steps: about 10 s, measured by the dry run whose bundle is
  `dryrun-20261015T154512Z` (`meta/started-at.txt` 2026-10-15T15:45:12Z,
  `meta/finished-at.txt` 15:45:22Z) with a warm Go build cache. The first build on a cold cache adds
  the Go toolchain and module download.
- Guest phase: run 38609582942's guests needed 104 s (ubuntu-24.04-6.8) and
  172 s (almalinux-8-4.18) at concurrency 2 on a hosted runner. That time
  includes the in-guest toolchain install and the KubeArmor build. Add the
  first-time download of the two cloud images.
- Expected total: about 5-15 min. The hard ceiling is the 25 min per-target
  timeout.

## Evidence contract

### Bundle layout (written by `scripts/kubearmor-corrective-run.sh`)

```
SHA256SUMS                      sha256 of every other file in the bundle
verdict.json                    runner verdict (VERIFIED | FAILED | INCONCLUSIVE | DRY_RUN_OK | DRY_RUN_BLOCKED), steps, pins
meta/started-at.txt             `date -u` at start (UTC ISO-8601)
meta/finished-at.txt            `date -u` at end
meta/checkout.txt               checkout HEAD, tags at HEAD, remote
meta/bpfcompat-version.json     `bpfcompat version --json`
meta/bpfcompat-cli.sha256       sha256 of the built CLI
meta/kubearmor-pin.json         pinned commit, tree, committer date, subject, libbpf gitlink
meta/guest-command.sh           exact guest command (with the pinned commit substituted)
meta/guest-command.invocation-sha256
meta/test-command.txt           exact `bpfcompat test` argv
meta/bpfcompat-test.exit-code
validator/bpfcompat-validator   the resolved rc.4 validator binary
validator/validator-identity.json
reports/kubearmor.json, .md     raw bpfcompat report
targets/<profile>/command.stdout, command.stderr, command-exit-code, serial.log
targets/<profile>/validator.json, libbpf.log
                                the validator JSON and its .logs.libbpf, extracted byte-for-byte
                                from command.stdout (bpfcompat does not retrieve the guest's
                                /tmp/kubearmor-load.json, so this is the closest original copy)
logs/procedure.log, make-build.log, resolve-validator.log, kubearmor-pin.log,
     bpfcompat-test.log, verify-report.log, contract-check.log
host/host.txt, qemu-version.txt, kvm.txt, tools.txt, prerequisites.txt
```

### Acceptance clauses (checked by `scripts/check-kubearmor-corrective-evidence.sh`)

The checker recomputes every clause from the raw files. It does not rely on
anything the runner concluded.

| Clause | Requirement |
|---|---|
| B1 | `SHA256SUMS` exists, is well formed, every entry verifies, every file in the bundle is listed, and there are no absolute, `..` or symlinked paths |
| B0 | all required files above are present |
| B2 | CLI `version == v0.4.0-rc.4`, and `commit` is a >=12-char prefix of `222c3f38a5361fca7c43c33df841290f8bef0021` |
| B3 | `validator-identity.json`: `mode=release`, `tag=v0.4.0-rc.4`, `commit=222c3f38…`, `sha256=e0e7fcf8…`, provenance = SHA256SUMS + GitHub attestation. The bundled binary hashes to `e0e7fcf8…` |
| R1-R5 | report `schema_version=v0.1`; `command.binary.sha256 == e0e7fcf8…`; expected exit 0; matrix `consumer-external` with exactly both profiles; summary `COMPATIBLE`/`pass`/`complete` |
| R6 | each required profile has exactly one target with `required`, `pass`, `COMPATIBLE`, kernel-family and distro match, and a passing `command` test. The booted kernel matches the profile family (`^6\.8\.N-N-generic$` / `^4\.18\.0-….el8(_N)?.x86_64$`), and the guest base-image sha256 is recorded |
| R7 | each target's report stdout tail has `bpfcompat-validator-sha256=e0e7fcf8…` (all such lines) and exactly one 40-hex `kubearmor-source-sha=`, and the latter is the same on both kernels |
| B4 | report `command.invocation_sha256 == sha256(meta/guest-command.sh + "\0expected-exit=0")`. The guest command contains `KA_COMMIT=<pin>` and `EXPECTED_VALIDATOR_SHA256=e0e7fcf8…`, and no validator download of its own |
| B5 | guest-observed KubeArmor commit == `meta/kubearmor-pin.json` commit (40-hex) |
| B6 | per kernel, from the full `targets/<profile>/command.stdout`: `guest-uname-r=` equals the report's observed kernel; `guest-proc-version=Linux version <kernel> …` is present; every `bpfcompat-validator-sha256-pre=` (before execution) and every `bpfcompat-validator-sha256=` (after) is `e0e7fcf8…`; `kubearmor-source-sha=` equals the pin; `kubearmor-object-sha256-pre=` (after the build) and `kubearmor-object-sha256=` (after the validator) are one equal 64-hex value; `validator-exit-code=0`; exactly one BEGIN marker and one later END marker, enclosing **exactly one** JSON document (an object) whose `input.artifact == "system_monitor.bpf.o"`, `input.probe_features == true`, `host.release` is the booted kernel, `status=pass`, `load.status=pass`, `discovery.program_count == len(programs) <= 64` (not truncated); every program has a `load_status` (pass, fail or skipped); **zero `fail`** and at least one `pass` |
| B9 | per kernel, the report's `stdout_tail` is exactly the rc.4 tail of `targets/<profile>/command.stdout`, i.e. `internal/vm/result.go` `readFileTail`: the last 4096 bytes, then `strings.TrimSpace`. This binds the bundled stdout to what bpfcompat captured |
| B10 | `targets/<profile>/validator.json` and `libbpf.log` exist and are byte-identical to the block (and its `.logs.libbpf`) re-extracted from `command.stdout` |
| B7 | start and end timestamps are UTC with end >= start; `bpfcompat test` exit code 0; `kvm-access=rw` |
| B8 | `verdict.json` is `VERIFIED`, `dry_run=false`, and has the same KubeArmor commit |

Outcomes: exit 0 with the final line exactly `RESULT: VERIFIED` means
accepted. Exit 1 (`FAILED`) means at least one clause was violated. Broken
bundle integrity, and any **definite identity mismatch** (a present but wrong
validator sha, CLI version, validator identity or KubeArmor commit), is always
`FAILED`, even if the report also carries an `INFRA_ERROR`. Exit 2
(`INCONCLUSIVE`) means an `INFRA_ERROR` in the report, or no report at all,
with no definite mismatch. Any failure, infra error or mismatch means `FAILED`
or `INCONCLUSIVE`, never `VERIFIED`. The test seam
`BPFCOMPAT_EVIDENCE_TEST_VALIDATOR_SHA256` exists only for the synthetic
regression test. When it is set, the checker prints a warning, and a bundle
that would otherwise pass exits **3** with `RESULT: VERIFIED (TEST SEAM …)`, so
it can never be mistaken for acceptance. The runner always calls the checker
with the seam unset, and with the resolver's own test seams
(`BPFCOMPAT_RELEASE_BASE_URL`, `BPFCOMPAT_SOURCE_BUILD_CMD`) unset, and requires
the unqualified `RESULT: VERIFIED`.

`skipped` per-program results are accepted (but counted and printed). The
validator reports `skipped` only when an isolated load is impossible: a
tail-call prog-array slot initialisation fails with EBADF. That is a limit of
isolated loading, not kernel evidence. The whole-object `load.status=pass`
still covers those programs.

Note: a per-program isolated `fail` rejects the run even when the
whole-object load passed. This is deliberate: the contract asks for a clean
per-program verifier outcome on every required kernel. If AlmaLinux 8's 4.18
backport kernel rejects an individual KubeArmor program, the result is
`FAILED` with the program name, errno and verifier-log tail in the bundle. It
is not silently accepted.
