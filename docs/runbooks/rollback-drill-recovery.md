# Rollback drill: manual recovery

Use this only when `rollback-drill.yml` (or `scripts/rollback-drill.sh`)
exits **3** with `RESTORATION FAILED`. In that case the dedicated drill alias
`ghcr.io/kernel-guard/bpfcompat:rollback-drill-vX.Y.Z-rc.N` may still point at
the candidate digest. Exit 1 means the drill failed, but the alias was proven
to be back on the known-good digest. Exit 2 means the inputs were rejected
before anything was written.

The drill never writes `latest`, stable aliases, Git refs, tags or releases.
Recovery must not touch them either.

## 1. Stop and record

- Do not re-dispatch the drill or the promotion workflow until recovery is
  done.
- Record the run URL, the drill alias and both digests from the run's inputs.
  Open an incident note under `docs/releases/` (it is the incident evidence for
  this release; never edit an older release's evidence).

## 2. Inspect (read-only)

```bash
IMAGE=ghcr.io/kernel-guard/bpfcompat
ALIAS=rollback-drill-vX.Y.Z-rc.N            # from the run inputs
BEFORE=sha256:<known-good digest>           # from the run inputs
docker buildx imagetools inspect "$IMAGE:$ALIAS" --format '{{json .Manifest}}' | jq -r .digest
docker buildx imagetools inspect "$IMAGE:latest" --format '{{json .Manifest}}' | jq -r .digest
```

If `latest` is not `$BEFORE`, that is a separate production incident. The
drill cannot have caused it, because it never writes `latest`. Escalate through
`docs/incident-response-runbook.md` and stop here.

## 3. Verify the known-good endpoint before writing

```bash
VERSION=vA.B.C                              # known-good version from the run inputs
cosign verify \
  --certificate-identity "https://github.com/Kernel-Guard/bpfcompat/.github/workflows/release-artifacts.yml@refs/tags/$VERSION" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  "$IMAGE@$BEFORE" >/dev/null
docker run --rm "$IMAGE@$BEFORE" version --json | jq -r .version   # must print $VERSION
```

## 4. Restore the drill alias only

Preferred: re-run just the restore step. It is idempotent and writes
only the drill alias:

```bash
# with the same env as the failed run (IMAGE, DRILL_ALIAS, BEFORE_DIGEST, ...)
bash scripts/rollback-drill.sh restore
```

Otherwise, as the release operator with `packages: write` on GHCR:

```bash
docker buildx imagetools create --tag "$IMAGE:$ALIAS" "$IMAGE@$BEFORE"
docker buildx imagetools inspect "$IMAGE:$ALIAS" --format '{{json .Manifest}}' | jq -r .digest  # must equal $BEFORE
```

Never pass `latest`, a version tag or a stable alias as `--tag`. If the alias
cannot be written (registry outage, permissions), the alias is still only a
drill alias that consumers are not told to use. Leave it, record that in
the incident note, and retry when GHCR recovers.

## 5. Close

- Record in the incident note the final alias digest, the time and who
  performed the recovery.
- A drill that needed manual recovery is **not** rollback evidence. Run a
  fresh drill after recovery. Use as rollback evidence only the
  `evidence.md` of a run whose "Verify recorded evidence" step passed
  (marker `[bpfcompat-rollback-drill:v1]`, `final_digest` equal to the
  known-good digest).
