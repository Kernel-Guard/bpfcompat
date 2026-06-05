#!/usr/bin/env bash
set -euo pipefail

report_dir="${1:-reports}"
out_dir="${2:-public/compatibility}"
version_label="${BPFCOMPAT_COMPATIBILITY_VERSION:-latest}"
version_label="$(printf '%s' "$version_label" | tr -c 'A-Za-z0-9._-' '-')"
version_label="${version_label:-latest}"
version_dir="$out_dir/runs/$version_label"

if ! command -v jq >/dev/null 2>&1; then
  echo "missing jq" >&2
  exit 1
fi

mkdir -p "$out_dir" "$version_dir"

mapfile -t reports < <(find "$report_dir" -type f -name '*.json' | sort)

for report in "${reports[@]}"; do
  cp "$report" "$version_dir/$(basename "$report")"
  markdown_peer="${report%.json}.md"
  if [[ -f "$markdown_peer" ]]; then
    cp "$markdown_peer" "$version_dir/$(basename "$markdown_peer")"
  fi
done
printf '%s\n' "$version_label" > "$out_dir/latest.txt"

html_escape() {
  sed \
    -e 's/&/\&amp;/g' \
    -e 's/</\&lt;/g' \
    -e 's/>/\&gt;/g' \
    -e 's/"/\&quot;/g'
}

report_field() {
  local report="$1"
  local filter="$2"
  jq -r "$filter // \"-\"" "$report"
}

required_counts() {
  local report="$1"
  jq -r '
    [(.targets // [])[] | select(.required == true)] as $required |
    ($required | map(select(.status == "pass")) | length) as $pass |
    ($required | length - $pass) as $fail |
    "\($pass)/\($fail)"
  ' "$report"
}

failure_classes() {
  local report="$1"
  jq -r '
    [(.targets // [])[] | select(.status != "pass") |
      (.classification_code // if (.infra_error // "") != "" then "INFRA_ERROR" else "UNCLASSIFIED_FAILURE" end)] |
    group_by(.) |
    map("\(.[0])=\(length)") |
    join(", ")
  ' "$report"
}

latest_target_rows() {
  local report="$1"
  jq -r '
    (.targets // [])[] |
    [
      (.profile_id // "-"),
      (.required // false | tostring),
      (.status // "-"),
      (.host.kernel // .profile.kernel // "-"),
      (.functional.status // "-"),
      (.classification_code // "-")
    ] | @tsv
  ' "$report"
}

report_link() {
  local report="$1"
  printf 'runs/%s/%s' "$version_label" "$(basename "$report")"
}

markdown_link() {
  local report="$1"
  local markdown_peer="${report%.json}.md"
  if [[ -f "$markdown_peer" ]]; then
    printf 'runs/%s/%s' "$version_label" "$(basename "$markdown_peer")"
  fi
}

{
  echo "# bpfcompat Compatibility Matrix"
  echo
  echo "Generated: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "Version: \`$version_label\`"
  echo
  echo "| Artifact | Run | Status | Required pass/fail | Failure classes | JSON | Markdown |"
  echo "|---|---|---|---|---|---|---|"
  for report in "${reports[@]}"; do
    artifact="$(report_field "$report" '.artifact.basename')"
    run_id="$(report_field "$report" '.run.id')"
    status="$(report_field "$report" '.summary.status')"
    counts="$(required_counts "$report")"
    classes="$(failure_classes "$report")"
    [[ -n "$classes" ]] || classes="-"
    json_href="$(report_link "$report")"
    md_href="$(markdown_link "$report")"
    md_cell="-"
    if [[ -n "$md_href" ]]; then
      md_cell="[md]($md_href)"
    fi
    echo "| \`$artifact\` | \`$run_id\` | \`$status\` | $counts | $classes | [json]($json_href) | $md_cell |"
  done
} > "$out_dir/index.md"

{
  echo '<!doctype html>'
  echo '<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
  echo '<title>bpfcompat Compatibility Matrix</title>'
  echo '<style>body{font:14px system-ui,-apple-system,Segoe UI,sans-serif;margin:24px;line-height:1.45;color:#111827}table{border-collapse:collapse;width:100%;margin:12px 0 24px}th,td{border:1px solid #d1d5db;padding:7px;text-align:left;vertical-align:top}th{background:#f3f4f6}.pass{color:#047857;font-weight:700}.fail,.error{color:#b91c1c;font-weight:700}.warn{color:#b45309;font-weight:700}code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12px}.muted{color:#6b7280}</style>'
  echo '</head><body>'
  echo '<h1>bpfcompat Compatibility Matrix</h1>'
  printf '<p class="muted">Generated %s from %d report(s). Version <code>%s</code>.</p>\n' \
    "$(date -u +%Y-%m-%dT%H:%M:%SZ | html_escape)" \
    "${#reports[@]}" \
    "$(printf '%s' "$version_label" | html_escape)"
  echo '<table><thead><tr><th>Artifact</th><th>Run</th><th>Status</th><th>Required pass/fail</th><th>Failure classes</th><th>JSON</th><th>Markdown</th></tr></thead><tbody>'
  for report in "${reports[@]}"; do
    artifact="$(report_field "$report" '.artifact.basename')"
    run_id="$(report_field "$report" '.run.id')"
    status="$(report_field "$report" '.summary.status')"
    counts="$(required_counts "$report")"
    classes="$(failure_classes "$report")"
    [[ -n "$classes" ]] || classes="-"
    json_href="$(report_link "$report")"
    md_href="$(markdown_link "$report")"
    md_cell='-'
    if [[ -n "$md_href" ]]; then
      md_cell="$(printf '<a href="%s">md</a>' "$(printf '%s' "$md_href" | html_escape)")"
    fi
    printf '<tr><td><code>%s</code></td><td><code>%s</code></td><td class="%s">%s</td><td>%s</td><td>%s</td><td><a href="%s">json</a></td><td>%s</td></tr>\n' \
      "$(printf '%s' "$artifact" | html_escape)" \
      "$(printf '%s' "$run_id" | html_escape)" \
      "$(printf '%s' "$status" | html_escape)" \
      "$(printf '%s' "$status" | html_escape)" \
      "$(printf '%s' "$counts" | html_escape)" \
      "$(printf '%s' "$classes" | html_escape)" \
      "$(printf '%s' "$json_href" | html_escape)" \
      "$md_cell"
  done
  echo '</tbody></table>'
  if [[ "${#reports[@]}" -gt 0 ]]; then
    latest="${reports[-1]}"
    latest_artifact="$(report_field "$latest" '.artifact.basename')"
    latest_run="$(report_field "$latest" '.run.id')"
    printf '<h2>Latest report: <code>%s</code> <span class="muted">%s</span></h2>\n' \
      "$(printf '%s' "$latest_artifact" | html_escape)" \
      "$(printf '%s' "$latest_run" | html_escape)"
    echo '<table><thead><tr><th>Profile</th><th>Required</th><th>Status</th><th>Kernel</th><th>Functional</th><th>Class</th></tr></thead><tbody>'
    while IFS=$'\t' read -r profile required status kernel functional class; do
      printf '<tr><td><code>%s</code></td><td>%s</td><td class="%s">%s</td><td><code>%s</code></td><td><code>%s</code></td><td><code>%s</code></td></tr>\n' \
        "$(printf '%s' "$profile" | html_escape)" \
        "$(printf '%s' "$required" | html_escape)" \
        "$(printf '%s' "$status" | html_escape)" \
        "$(printf '%s' "$status" | html_escape)" \
        "$(printf '%s' "$kernel" | html_escape)" \
        "$(printf '%s' "$functional" | html_escape)" \
        "$(printf '%s' "$class" | html_escape)"
    done < <(latest_target_rows "$latest")
    echo '</tbody></table>'
  fi
  echo '</body></html>'
} > "$out_dir/index.html"

printf 'wrote %s and %s\n' "$out_dir/index.html" "$out_dir/index.md"
