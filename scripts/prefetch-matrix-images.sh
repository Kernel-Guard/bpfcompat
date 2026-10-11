#!/usr/bin/env bash
# Prefetch every vendor cloud image a matrix needs, in parallel, and report
# per-image outcomes without aborting on the first failure.
#
#   prefetch-matrix-images.sh <matrix.yaml> <summary-file>
#
# Why this exists: the compatibility-matrix-publish lane ran
# `xargs -P6 fetch-cloud-image.sh` under `set -e`. One failed download
# (HTTP 502 for a renamed CentOS Stream image in runs 36565005828 and
# 37464388426; an HTTP/2 PROTOCOL_ERROR in run 33499929031) made xargs exit
# 123, which aborted the step before any VM booted. No report was produced,
# and the public page silently stayed on the previous successful week.
#
# Contract:
#   - every profile in the matrix that declares both image.source_url and
#     image.local_path is attempted; profiles without a source_url are listed
#     as "manual" and skipped;
#   - exit 0 when all images are present, exit 2 when at least one failed;
#     the caller decides whether to continue. A missing image is an
#     infrastructure condition for that target downstream (INFRA_ERROR),
#     never a compatibility PASS or FAIL;
#   - <summary-file> gets one line per profile:
#       ok <profile> <local_path>
#       cached <profile> <local_path>
#       failed <profile> <url> <reason>
#       manual <profile> <local_path>
#   - per-attempt detail from the fetch script is appended to
#     <summary-file>.fetch.log (BPFCOMPAT_FETCH_LOG) for upload as evidence.
#
# Env overrides (tests): BPFCOMPAT_FETCH_SCRIPT (fetcher with the
# fetch-cloud-image.sh contract), BPFCOMPAT_PREFETCH_PARALLELISM (default 6).
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "Usage: $0 <matrix.yaml> <summary-file>" >&2
  exit 1
fi

matrix="$1"
summary="$2"
fetch_script="${BPFCOMPAT_FETCH_SCRIPT:-vm/scripts/fetch-cloud-image.sh}"
parallelism="${BPFCOMPAT_PREFETCH_PARALLELISM:-6}"

if [[ ! -f "$matrix" ]]; then
  echo "prefetch: matrix not found: $matrix" >&2
  exit 1
fi
command -v python3 >/dev/null || { echo "prefetch: python3 is required" >&2; exit 1; }

mkdir -p "$(dirname "$summary")"
: >"$summary"
export BPFCOMPAT_FETCH_LOG="${summary}.fetch.log"
: >"$BPFCOMPAT_FETCH_LOG"

# profile<TAB>source_url<TAB>local_path  (source_url empty when absent)
plan="$(mktemp)"
trap 'rm -f "$plan"' EXIT
python3 - "$matrix" >"$plan" <<'PY'
import sys, yaml
matrix = yaml.safe_load(open(sys.argv[1]))
for p in matrix.get("profiles", []):
    pid = p["id"]
    prof = yaml.safe_load(open(f"vm/profiles/{pid}.yaml"))
    img = prof.get("image") or {}
    print(f"{pid}\t{img.get('source_url') or ''}\t{img.get('local_path') or ''}")
PY

fetch_one() {
  local pid="$1" url="$2" dest="$3"
  if [[ -z "$dest" ]]; then
    echo "manual $pid -" >>"$summary"
    return 0
  fi
  if [[ -z "$url" ]]; then
    echo "manual $pid $dest" >>"$summary"
    return 0
  fi
  if [[ -f "$dest" ]]; then
    echo "cached $pid $dest" >>"$summary"
    return 0
  fi
  local out
  if out="$(bash "$fetch_script" "$url" "$dest" 2>&1)"; then
    printf '%s\n' "$out"
    echo "ok $pid $dest" >>"$summary"
  else
    printf '%s\n' "$out"
    local reason
    reason="$(printf '%s\n' "$out" | grep -E 'FAILED|curl: \(|wget' | tail -1 || true)"
    echo "failed $pid $url ${reason:-download failed}" >>"$summary"
    echo "::warning::prefetch failed for $pid: $url (${reason:-download failed})"
  fi
}
fetch_line() {
  local pid url dest
  IFS=$'\t' read -r pid url dest <<<"$1"
  fetch_one "$pid" "$url" "$dest"
}
export -f fetch_one fetch_line
export summary fetch_script

# Parallel, but never short-circuit: xargs' own exit status is ignored on
# purpose; the summary file is the source of truth.
# shellcheck disable=SC2016  # $0 is expanded by the child bash, not here
xargs -a "$plan" -d '\n' -n1 -P"$parallelism" bash -c 'fetch_line "$0"' || true

echo "prefetch summary ($matrix):"
sort "$summary"
failed="$(grep -c '^failed ' "$summary" || true)"
if [[ "$failed" -gt 0 ]]; then
  echo "prefetch: $failed image(s) failed; continuing so the remaining targets are validated and the failures surface as INFRA_ERROR" >&2
  exit 2
fi
