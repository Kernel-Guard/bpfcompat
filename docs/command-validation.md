# Command-mode validation (validate via a binary/command)

The default `bpfcompat test` flow ships a `.bpf.o` plus the bundled C/libbpf
validator into each kernel VM and answers *"does this object load and attach?"*.

**Command mode** answers a different question: *"does my project's own loader —
the real userspace path — come up on this kernel?"* Instead of the bundled
validator, it runs a command (optionally a binary you ship into the guest)
inside each matrix-kernel VM, and the per-kernel verdict is the command's **exit
code**.

This is useful when:

- you want to exercise the **userspace loader path**, not just the kernel's
  acceptance of the object;
- you'd rather **not maintain a manifest** (map fixups, program-variant groups)
  that has to stay in sync with how your loader configures the object — your
  loader already encodes that;
- your artifact isn't a single `.bpf.o` (multiple objects, skeletons, a CLI that
  loads several programs).

It is the analog of running your binary under a per-kernel VM harness (e.g.
`vimto exec`), wired into the same multi-distro matrix, evidence, and history
that the `.bpf.o` flow uses.

## Usage

There are two equivalent front-ends: the dedicated `test-command` verb (shorter
flags: `--cmd`, `--bin`, `--expect-exit`) and `test --command` (the same flags
prefixed with `--command`). Use whichever reads better.

```bash
# Dedicated verb — ship a statically-linked loader, run it on every matrix kernel.
# Pass == exit 0 (override with --expect-exit N).
bpfcompat test-command \
  --cmd '$BPFCOMPAT_BIN --self-test' \
  --bin ./build/myloader \
  --matrix matrices/mvp.yaml \
  --out report.json

# Equivalent flag form on `test`:
bpfcompat test \
  --command '$BPFCOMPAT_BIN --self-test' \
  --command-binary ./build/myloader \
  --matrix matrices/mvp.yaml \
  --out report.json
```

```bash
# Drive a loader against a shipped .bpf.o (both are staged into the guest).
bpfcompat test \
  --command '$BPFCOMPAT_BIN --obj $BPFCOMPAT_ARTIFACT' \
  --command-binary ./build/loader \
  --artifact ./build/probe.bpf.o \
  --matrix matrices/mvp.yaml \
  --out report.json
```

```bash
# No shipped binary — use a tool already present in the guest image.
bpfcompat test \
  --command 'bpftool prog load /tmp/x.bpf.o /sys/fs/bpf/x' \
  --command-binary ./build/x.bpf.o-copier ...   # (or stage via --artifact)
```

### Flags

| Flag | Meaning |
|---|---|
| `--command <cmd>` | Shell command run inside each kernel VM. Required to enter command mode. |
| `--command-binary <file>` | Local executable shipped into each guest, `chmod +x`, exposed as `$BPFCOMPAT_BIN`. |
| `--command-expect-exit <N>` | Exit code that counts as a pass (default `0`). |
| `--artifact <file>` | Optional in command mode; when given it is staged and exposed as `$BPFCOMPAT_ARTIFACT`. |

### Environment available to the command

The command runs **as root** inside the disposable guest with:

- `BPFCOMPAT_BIN` — absolute path to the `--command-binary` you shipped (empty if none);
- `BPFCOMPAT_ARTIFACT` — absolute path to the staged `--artifact` (empty if none);
- `BPFCOMPAT_REMOTE_ROOT` — the per-run scratch root inside the guest.

The command string is executed as a single `bash -lc` operand (it is
shell-quoted, so it cannot break out to inject host-side syntax). Use real shell
inside it freely: pipes, `&&`, redirects.

## Verdict and report

- The kernel **passes** iff the command exits with `--command-expect-exit`
  (default `0`); otherwise it **fails** with classification
  `COMMAND_VALIDATION_FAILURE`.
- The libbpf load/attach phase is **skipped** (`validation.load_status:
  "skipped"`); the outcome is recorded in the report's `functional` section as a
  single synthetic `command` test carrying the exit code and bounded
  stdout/stderr tails.
- A command that *fails to execute at all* (VM didn't boot, SSH failed) is an
  **infra error**, not a compatibility failure — exactly as in the `.bpf.o`
  flow.
- The run is still recorded in artifact version history; with no `.bpf.o` the
  artifact identity is content-addressed from the command string
  (`command://<name>`), so `compare`/history still work.

## GitHub Action

The composite action supports command mode directly, so a project can gate CI
on its own loader with one step. A bare `matrix` name resolves to the
`matrices/` directory shipped with the action — `quirk-library` gives you the
[library of known-tricky vendor kernels](kernel-quirk-library.md) with no file
to copy:

```yaml
- uses: Kernel-Guard/bpfcompat@v0.3.2
  with:
    command: $BPFCOMPAT_BIN --self-test
    command-binary: build/myloader
    command-expect-exit: "0"   # optional, default 0
    matrix: quirk-library
    out: reports/bpfcompat.json
```

The `command` string is passed to the runner through the environment (never
interpolated into the action's shell), and inside the guest it is executed as a
single quoted `bash -lc` operand, exactly as in the CLI flow.

Real-world example: `falcosecurity/libs` runs exactly this flow in its
scheduled CI — it builds Falco's `scap-open` loader statically (modern_bpf
probe skeleton embedded) and validates it per kernel with
`command: $BPFCOMPAT_BIN --modern_bpf --num_events 10`
([falcosecurity/libs#3024](https://github.com/falcosecurity/libs/pull/3024),
[workflow](https://github.com/falcosecurity/libs/blob/master/.github/workflows/bpfcompat-compatibility.yml)).

## Scope / limitations (first cut)

- Command mode currently supports the **`vm`** runner only (the default). It is
  rejected for `virtme-ng`/`firecracker`.
- The verdict is the **exit code**. Richer assertions (stdout/stderr matchers,
  per-program expectations) remain available through the manifest
  `functional_tests` + `--validation-mode behavior` path, which layers commands
  *on top of* a `.bpf.o` load.
