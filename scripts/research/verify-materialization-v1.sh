#!/usr/bin/env bash
set -euo pipefail

BUNDLE="${1:-dist/research-corpus-v1}"

fail() {
  echo "[verify-research-materialization] $*" >&2
  exit 1
}

[[ -d "$BUNDLE" ]] || fail "missing bundle directory: $BUNDLE"
[[ -f "$BUNDLE/SHA256SUMS" ]] || fail "missing SHA256SUMS"
[[ -f "$BUNDLE/materialization.json" ]] || fail "missing materialization.json"

(
  cd "$BUNDLE"
  sha256sum -c SHA256SUMS >/dev/null
) || fail "bundle checksum verification failed"

jq -e '
  .schema_version == "bpfcompat.research.materialization.v1" and
  .corpus_version == "v1" and
  (.artifacts | length) == 9 and
  (all(.artifacts[];
    (.path | type == "string") and
    (.sha256 | test("^sha256:[0-9a-f]{64}$"))
  )) and
  (.validation_contracts | length) == 4 and
  (all(.validation_contracts[];
    test("^sha256:[0-9a-f]{64}$")
  ))
' "$BUNDLE/materialization.json" >/dev/null ||
  fail "materialization.json does not satisfy the v1 contract"

while IFS=$'\t' read -r path expected; do
  [[ -f "$BUNDLE/$path" ]] || fail "missing materialized file: $path"
  actual="$(sha256sum "$BUNDLE/$path" | awk '{print "sha256:" $1}')"
  [[ "$actual" == "$expected" ]] ||
    fail "digest mismatch for $path: expected $expected got $actual"
done < <(
  jq -r '.artifacts[] | [.path, .sha256] | @tsv'     "$BUNDLE/materialization.json"
)

while IFS=$'\t' read -r key expected; do
  canonical="$BUNDLE/contracts/${key}.canonical.json"
  record="$BUNDLE/contracts/${key}.json"
  [[ -f "$canonical" && -f "$record" ]] ||
    fail "missing canonical contract files for $key"

  actual="sha256:$(sha256sum "$canonical" | awk '{print $1}')"
  [[ "$actual" == "$expected" ]] ||
    fail "canonical contract hash mismatch for $key"

  record_id="$(jq -r '.id' "$record")"
  [[ "$record_id" == "$expected" ]] ||
    fail "contract record id mismatch for $key"
done < <(
  jq -r '.validation_contracts | to_entries[] | [.key, .value] | @tsv'     "$BUNDLE/materialization.json"
)

[[ "$(jq -r '.source_revisions.bpfcompat_selection_source' "$BUNDLE/materialization.json")" ==   "b8ef57f4e02ebecee4649f7657ea8eea6af46ca9" ]] ||
  fail "unexpected BPFCompat source revision"

[[ "$(jq -r '.source_revisions.falco' "$BUNDLE/materialization.json")" ==   "1800b330ce92b532456178abfcbfba3dd157f974" ]] ||
  fail "unexpected Falco source revision"

LOCK="research/corpus/v1/materialized-identities.json"
if [[ -s "$LOCK" ]]; then
  actual_lock="$(mktemp)"
  expected_lock="$(mktemp)"
  trap 'rm -f "$actual_lock" "$expected_lock"' EXIT

  jq -S '{
    source_revisions,
    artifacts,
    validation_contracts
  }' "$BUNDLE/materialization.json" > "$actual_lock"

  jq -S '{
    source_revisions,
    artifacts,
    validation_contracts
  }' "$LOCK" > "$expected_lock"

  if ! diff -u "$expected_lock" "$actual_lock"; then
    fail "materialized identities differ from the committed v1 identity lock"
  fi
fi

echo "[verify-research-materialization] PASS"
