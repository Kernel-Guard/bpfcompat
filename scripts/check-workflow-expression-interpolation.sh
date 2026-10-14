#!/usr/bin/env bash
# No ${{ }} expression may be interpolated into a workflow `run:` script.
#
#   check-workflow-expression-interpolation.sh
#
# The same injection class check-action-input-interpolation.sh closes for
# action.yml: the runner pastes `${{ ... }}` into a run: script as shell
# source before bash parses it, so a value that carries a branch name, PR
# title, dispatch input or anything derived from them is code, not data.
# Values must reach the script through the step's env: block and be read as
# quoted shell variables ("$VAR").
#
# Every non-frozen workflow in .github/workflows (*.yml, *.yaml) and every
# composite action under .github/actions is scanned with the shared guard in
# --strict (default-deny) mode: only a whole-expression run-identity value
# (github.sha, github.run_id, github.run_number, github.run_attempt,
# runner.os, runner.arch) is allowed in a run: script.
#
# Overridable for the regression suite only: BPFCOMPAT_WORKFLOWS_DIR,
# BPFCOMPAT_ACTIONS_DIR.
#
# Exits 0 on PASS, 1 on a finding, 2 on a missing/unparseable file.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
workflows_dir="${BPFCOMPAT_WORKFLOWS_DIR:-$ROOT/.github/workflows}"
actions_dir="${BPFCOMPAT_ACTIONS_DIR:-$ROOT/.github/actions}"
guard="$ROOT/scripts/check-action-input-interpolation.sh"
tag="[workflow-expression-interpolation]"

# FROZEN: the v0.4.0 release-qualification workflows. v0.4.0-rc.4 is under
# active qualification and these files are part of the frozen machinery, so
# they are not edited (and therefore not gated) until v0.4.0 graduates to
# stable. After graduation remove them from this list so they are scanned
# like every other workflow. The skip is by exact name, and a listed file
# that no longer exists is an error, so a rename cannot quietly widen or
# drift the exemption.
FROZEN=(
  release-artifacts.yml
  promote-release.yml
  release-candidate-canary.yml
  consumer-canary.yml
  external-consumer-canary.yml
  latest-kernel-compatibility.yml
  rollback-drill.yml
)

[[ -d "$workflows_dir" ]] || { echo "$tag missing workflows dir: $workflows_dir" >&2; exit 2; }
for f in "${FROZEN[@]}"; do
  [[ -f "$workflows_dir/$f" ]] || {
    echo "$tag frozen workflow not found: $f (update FROZEN in $0)" >&2
    exit 2
  }
done

is_frozen() {
  local f
  for f in "${FROZEN[@]}"; do
    [[ "$1" == "$f" ]] && return 0
  done
  return 1
}

files=()
shopt -s nullglob
for path in "$workflows_dir"/*.yml "$workflows_dir"/*.yaml; do
  if is_frozen "$(basename "$path")"; then
    echo "$tag skipped frozen workflow: $(basename "$path")"
    continue
  fi
  files+=("$path")
done
if [[ -d "$actions_dir" ]]; then
  while IFS= read -r -d '' path; do
    files+=("$path")
  done < <(find "$actions_dir" -type f \( -name action.yml -o -name action.yaml \) -print0 | sort -z)
fi

rc=0
for path in "${files[@]}"; do
  status=0
  bash "$guard" --strict "$path" >/dev/null || status=$?
  if [[ "$status" -gt "$rc" ]]; then
    rc="$status"
  fi
done

if [[ "$rc" -ne 0 ]]; then
  echo "$tag FAIL: move each flagged value into the step's env: and read it as \"\$VAR\"" >&2
  exit "$rc"
fi
echo "$tag PASS: ${#files[@]} non-frozen workflow/action file(s), ${#FROZEN[@]} frozen skipped"
