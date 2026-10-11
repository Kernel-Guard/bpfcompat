#!/usr/bin/env bash
# Regression guard for scripts/prefetch-matrix-images.sh.
#
# The compatibility-matrix-publish lane used an inline `xargs -P6` over
# vm/scripts/fetch-cloud-image.sh with `set -e`. One failed download (a 502
# for the old CentOS Stream URL in runs 36565005828 and 37464388426, an HTTP/2
# PROTOCOL_ERROR in run 33499929031) returned exit 123 from xargs and aborted
# the step before a single VM booted, so the lane produced no report at all
# and the public page silently stayed on the last successful week.
#
# The prefetch script must instead:
#   1. try every image, never stop at the first failure;
#   2. exit 0 when all images are fetched and 2 when any failed, so the
#      workflow can continue to validation (a missing image becomes an
#      INFRA_ERROR target there, never a PASS or FAIL);
#   3. write a summary file naming each failed URL with its reason;
#   4. only consider profiles that have both source_url and local_path.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="$ROOT/scripts/prefetch-matrix-images.sh"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

mkdir -p "$work/vm/profiles" "$work/matrices"
cat >"$work/matrices/m.yaml" <<'YAML'
name: test
profiles:
  - id: good-a
    required: true
  - id: bad-b
    required: true
  - id: manual-c
    required: false
YAML
cat >"$work/vm/profiles/good-a.yaml" <<'YAML'
id: good-a
image:
  source_url: "http://example.invalid/good-a.qcow2"
  local_path: "vm/cache/good-a.qcow2"
YAML
cat >"$work/vm/profiles/bad-b.yaml" <<'YAML'
id: bad-b
image:
  source_url: "http://example.invalid/bad-b.qcow2"
  local_path: "vm/cache/bad-b.qcow2"
YAML
cat >"$work/vm/profiles/manual-c.yaml" <<'YAML'
id: manual-c
image:
  local_path: "vm/cache/manual-c.qcow2"
YAML

# A stand-in fetcher with the real script's contract: <url> <dest>, exit 0 on
# success and non-zero with a FAILED line otherwise. It records every call so
# the test can prove no image was skipped after the first failure.
cat >"$work/fake-fetch.sh" <<'SH'
#!/usr/bin/env bash
echo "$1 $2" >> "$FAKE_CALLS"
case "$1" in
  *bad-b*) echo "fetch-cloud-image: FAILED url=$1 http=502 exit=22" >&2; exit 1 ;;
  *) mkdir -p "$(dirname "$2")"; echo bytes > "$2"; echo "Saved image to $2"; exit 0 ;;
esac
SH
chmod +x "$work/fake-fetch.sh"

fail=0
ok() { printf 'ok:   %s\n' "$1"; }
bad() { printf 'FAIL: %s\n' "$1" >&2; fail=1; }

export FAKE_CALLS="$work/calls.txt"
export BPFCOMPAT_FETCH_SCRIPT="$work/fake-fetch.sh"
summary="$work/prefetch-summary.txt"

rc=0
( cd "$work" && bash "$SCRIPT" matrices/m.yaml "$summary" ) >"$work/out.txt" 2>&1 || rc=$?

if [[ "$rc" -eq 2 ]]; then
  ok "exit code 2 when at least one image failed"
else
  bad "expected exit 2 when an image fails, got $rc"; cat "$work/out.txt" >&2
fi
if grep -q "good-a.qcow2" "$FAKE_CALLS" && grep -q "bad-b.qcow2" "$FAKE_CALLS"; then
  ok "every image with a source_url is attempted"
else
  bad "not every image was attempted"; cat "$FAKE_CALLS" >&2 || true
fi
if grep -q "manual-c" "$FAKE_CALLS"; then
  bad "profile without source_url must not be fetched"
else
  ok "profile without source_url is skipped"
fi
if [[ -f "$summary" ]] && grep -qE "^failed .*bad-b.qcow2" "$summary" && grep -qE "^ok .*good-a.qcow2" "$summary"; then
  ok "summary file names the failed and successful images"
else
  bad "summary file missing or incomplete"; cat "$summary" >&2 || true
fi
if [[ -f "$work/vm/cache/good-a.qcow2" ]]; then
  ok "successful image landed at its local_path"
else
  bad "successful image not written"
fi

# All-good matrix exits 0.
cat >"$work/matrices/good.yaml" <<'YAML'
name: good
profiles:
  - id: good-a
YAML
rc=0
( cd "$work" && bash "$SCRIPT" matrices/good.yaml "$work/summary2.txt" ) >/dev/null 2>&1 || rc=$?
if [[ "$rc" -eq 0 ]]; then
  ok "exit code 0 when every image is available"
else
  bad "expected exit 0 for an all-good matrix, got $rc"
fi

if [[ "$fail" -ne 0 ]]; then
  echo "prefetch-matrix-images_test: FAILED" >&2
  exit 1
fi
echo "prefetch-matrix-images_test: all checks passed"
