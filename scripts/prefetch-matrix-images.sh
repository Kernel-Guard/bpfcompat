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

# Plan: one line per DESTINATION, fields separated by US (0x1f) so an empty
# source_url survives `read` (a tab IFS would collapse adjacent separators):
#   <local_path>US<source_url>US<pid>[,<pid>...]
# Profiles sharing a local_path are fetched once (parallel fetches into one
# path would race on the same .part file) and each gets its own outcome line.
# Profiles with no local_path are listed with an empty destination.
# A second file lists every planned profile id, to check completeness.
plan="$(mktemp)"
planned="$(mktemp)"
trap 'rm -f "$plan" "$planned"' EXIT
python3 - "$matrix" "$planned" >"$plan" <<'PY'
import sys, yaml
matrix = yaml.safe_load(open(sys.argv[1]))
groups = {}
order = []
with open(sys.argv[2], "w") as ids:
    for p in matrix.get("profiles", []):
        pid = p["id"]
        ids.write(pid + "\n")
        prof = yaml.safe_load(open(f"vm/profiles/{pid}.yaml"))
        img = prof.get("image") or {}
        dest = img.get("local_path") or ""
        url = img.get("source_url") or ""
        key = dest if dest else "\0" + pid  # no destination: never grouped
        if key not in groups:
            groups[key] = [dest, url, []]
            order.append(key)
        groups[key][2].append(pid)
for key in order:
    dest, url, pids = groups[key]
    print("\x1f".join([dest, url, ",".join(pids)]))
PY

record() { # status dest-or-url detail pids-csv
  local status="$1" where="$2" detail="$3" pids="$4" pid
  IFS=',' read -r -a _pids <<<"$pids"
  for pid in "${_pids[@]}"; do
    if [[ -n "$detail" ]]; then
      echo "$status $pid $where $detail" >>"$summary"
    else
      echo "$status $pid $where" >>"$summary"
    fi
  done
}

fetch_one() {
  local dest="$1" url="$2" pids="$3"
  if [[ -z "$dest" ]]; then
    record manual - "" "$pids"
    return 0
  fi
  if [[ -z "$url" ]]; then
    record manual "$dest" "" "$pids"
    return 0
  fi
  if [[ -f "$dest" ]]; then
    record cached "$dest" "" "$pids"
    return 0
  fi
  local out
  if out="$(bash "$fetch_script" "$url" "$dest" 2>&1)"; then
    printf '%s\n' "$out"
    record ok "$dest" "" "$pids"
  else
    printf '%s\n' "$out"
    local reason
    reason="$(printf '%s\n' "$out" | grep -E 'FAILED|curl: \(|wget' | tail -1 || true)"
    record failed "$url" "${reason:-download failed}" "$pids"
    echo "::warning::prefetch failed for ${pids}: $url (${reason:-download failed})"
  fi
}
fetch_line() {
  local dest url pids
  IFS=$'\x1f' read -r dest url pids <<<"$1"
  fetch_one "$dest" "$url" "$pids"
}
export -f record fetch_one fetch_line
export summary fetch_script

# Parallel, and an individual download failure never aborts the others
# (fetch_one always returns 0 after recording it). xargs' own status is still
# captured: non-zero means a worker died or could not start, which must not
# read as success.
dispatch_rc=0
# shellcheck disable=SC2016  # $0 is expanded by the child bash, not here
xargs -a "$plan" -d '\n' -n1 -P"$parallelism" bash -c 'fetch_line "$0"' || dispatch_rc=$?

# Completeness: every planned profile must have exactly one outcome. A worker
# killed before recording leaves a gap, which becomes an explicit failure.
while IFS= read -r pid; do
  [[ -z "$pid" ]] && continue
  if ! awk -v p="$pid" '$2 == p {found=1} END {exit !found}' "$summary"; then
    echo "failed $pid - no outcome recorded (prefetch worker exited before reporting; dispatch rc=$dispatch_rc)" >>"$summary"
    echo "::warning::prefetch recorded no outcome for $pid"
  fi
done <"$planned"

echo "prefetch summary ($matrix):"
sort "$summary"
failed="$(grep -c '^failed ' "$summary" || true)"
if [[ "$failed" -gt 0 || "$dispatch_rc" -ne 0 ]]; then
  echo "prefetch: $failed profile(s) without a fetched image (dispatch rc=$dispatch_rc); continuing so the remaining targets are validated and the failures surface as INFRA_ERROR" >&2
  exit 2
fi
