#!/usr/bin/env bash
# Regression guard for network-download hardening in the consumer paths (R6).
#
# The maintenance branch dropped two protections that main carries:
#   - every curl in the Action's prebuilt step and in scripts/install.sh had
#     --connect-timeout and --max-time, so a stalled GitHub API or release CDN
#     fails in bounded time instead of hanging a consumer's CI job until the
#     job-level timeout (default 6 hours on hosted runners);
#   - the Action removed its downloaded-asset temp dir with an EXIT trap, so a
#     failed verification never leaves unverified binaries in the runner's tmp.
#
# This test checks the shipped files themselves (single source of truth):
#   1. every curl invocation (continuation lines joined) carries both
#      --connect-timeout and --max-time;
#   2. every `tmp="$(mktemp -d)"` in action.yml and install.sh is followed
#      on the next line by an EXIT trap that removes it;
#   3. behaviorally, the extracted cleanup pattern removes the directory when
#      the shell exits through a failure.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
fail=0
ok() { printf 'ok:   %s\n' "$1"; }
bad() { printf 'FAIL: %s\n' "$1" >&2; fail=1; }

joined() { # join backslash-continued lines so one curl call is one line
  awk '{ if (sub(/\\[[:space:]]*$/, "")) { buf = buf $0 " " } else { print buf $0; buf = "" } }' "$1"
}

for file in action.yml scripts/install.sh; do
  path="$ROOT/$file"
  calls="$(joined "$path" | grep -E '(^|[^[:alnum:]_-])curl[[:space:]]+-' | grep -vE '^[[:space:]]*#' || true)"
  if [[ -z "$calls" ]]; then
    bad "$file: no curl invocations found (test is not looking at the right file)"
    continue
  fi
  n=0
  while IFS= read -r call; do
    n=$((n + 1))
    if [[ "$call" != *--connect-timeout* || "$call" != *--max-time* ]]; then
      bad "$file: curl without --connect-timeout/--max-time: $(echo "$call" | sed 's/^[[:space:]]*//' | cut -c1-120)"
    fi
  done <<<"$calls"
  ok "$file: checked $n curl invocation(s) for bounded timeouts"

  mapfile -t tmp_lines < <(grep -nE 'tmp="\$\(mktemp -d\)"' "$path" | cut -d: -f1)
  for line in "${tmp_lines[@]}"; do
    next="$(sed -n "$((line + 1))p" "$path")"
    if [[ "$next" =~ trap\ \'rm\ -rf\ \"\$tmp\"\'\ EXIT ]]; then
      ok "$file:$line: temp dir is removed by an EXIT trap"
    else
      bad "$file:$line: mktemp -d is not followed by trap 'rm -rf \"\$tmp\"' EXIT"
    fi
  done
done

# Behavioral: the cleanup pattern removes the dir even when the shell fails.
probe="$(mktemp -d)"
marker="$probe/where"
bash -c 'set -euo pipefail; tmp="$(mktemp -d)"; trap '"'"'rm -rf "$tmp"'"'"' EXIT; echo "$tmp" > "$1"; touch "$tmp/unverified-binary"; false' _ "$marker" || true
left="$(cat "$marker")"
if [[ -n "$left" && ! -e "$left" ]]; then
  ok "EXIT trap removes the temp dir after a failed verification"
else
  bad "temp dir survived a failing shell: $left"
fi
rm -rf "$probe"

if [[ "$fail" -ne 0 ]]; then
  echo "download-hardening_test: FAILED" >&2
  exit 1
fi
echo "download-hardening_test: all checks passed"
