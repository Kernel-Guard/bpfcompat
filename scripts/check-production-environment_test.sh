#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
script="${ROOT_DIR}/scripts/check-production-environment.sh"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

mkdir -p "$tmp/bin"
cat >"$tmp/bin/gh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [[ "$*" == *deployment-branch-policies ]]; then
  cat "$POLICIES_FIXTURE"
elif [[ "$*" == */rulesets/42 ]]; then
  cat "$RULESET_FIXTURE"
elif [[ "$*" == */rulesets ]]; then
  cat "$RULESETS_FIXTURE"
else
  cat "$ENVIRONMENT_FIXTURE"
fi
EOF
chmod +x "$tmp/bin/gh"

cat >"$tmp/environment.json" <<'EOF'
{
  "can_admins_bypass": false,
  "protection_rules": [
    {
      "type": "branch_policy"
    },
    {
      "type": "wait_timer",
      "wait_timer": 15
    }
  ],
  "deployment_branch_policy": {
    "protected_branches": false,
    "custom_branch_policies": true
  }
}
EOF
cat >"$tmp/policies.json" <<'EOF'
{
  "branch_policies": [
    {"name": "v*", "type": "tag"}
  ]
}
EOF
cat >"$tmp/rulesets.json" <<'EOF'
[
  {
    "id": 42,
    "name": "Immutable release tags",
    "target": "tag",
    "enforcement": "active"
  }
]
EOF
cat >"$tmp/ruleset.json" <<'EOF'
{
  "id": 42,
  "name": "Immutable release tags",
  "target": "tag",
  "enforcement": "active",
  "conditions": {
    "ref_name": {
      "include": ["refs/tags/v*"],
      "exclude": []
    }
  },
  "bypass_actors": [],
  "rules": [
    {"type": "update"},
    {"type": "deletion"}
  ]
}
EOF

PATH="$tmp/bin:$PATH" \
ENVIRONMENT_FIXTURE="$tmp/environment.json" \
POLICIES_FIXTURE="$tmp/policies.json" \
RULESETS_FIXTURE="$tmp/rulesets.json" \
RULESET_FIXTURE="$tmp/ruleset.json" \
  "$script" Kernel-Guard/bpfcompat production-release solo-maintainer \
  >"$tmp/pass.log"
grep -Fq '[production-environment] PASS' "$tmp/pass.log"

for mutation in \
  '.can_admins_bypass = true' \
  '.protection_rules += [{"type":"required_reviewers","prevent_self_review":true,"reviewers":[]}]' \
  '.protection_rules[1].wait_timer = 0' \
  '.deployment_branch_policy.custom_branch_policies = false'; do
  jq "$mutation" "$tmp/environment.json" >"$tmp/bad-environment.json"
  if PATH="$tmp/bin:$PATH" \
    ENVIRONMENT_FIXTURE="$tmp/bad-environment.json" \
    POLICIES_FIXTURE="$tmp/policies.json" \
    RULESETS_FIXTURE="$tmp/rulesets.json" \
    RULESET_FIXTURE="$tmp/ruleset.json" \
      "$script" Kernel-Guard/bpfcompat production-release solo-maintainer \
      >/dev/null 2>&1; then
    echo "[production-environment-test] accepted unsafe environment: ${mutation}" >&2
    exit 1
  fi
done

jq '.branch_policies = [{"name": "main", "type": "branch"}]' \
  "$tmp/policies.json" >"$tmp/bad-policies.json"
if PATH="$tmp/bin:$PATH" \
  ENVIRONMENT_FIXTURE="$tmp/environment.json" \
  POLICIES_FIXTURE="$tmp/bad-policies.json" \
  RULESETS_FIXTURE="$tmp/rulesets.json" \
  RULESET_FIXTURE="$tmp/ruleset.json" \
    "$script" Kernel-Guard/bpfcompat production-release solo-maintainer \
    >/dev/null 2>&1; then
  echo "[production-environment-test] accepted missing tag policy" >&2
  exit 1
fi

for mutation in \
  '.bypass_actors = [{"actor_type":"User","actor_id":1,"bypass_mode":"always"}]' \
  '.rules = [{"type":"deletion"}]' \
  '.conditions.ref_name.include = ["refs/tags/release-*"]'; do
  jq "$mutation" "$tmp/ruleset.json" >"$tmp/bad-ruleset.json"
  if PATH="$tmp/bin:$PATH" \
    ENVIRONMENT_FIXTURE="$tmp/environment.json" \
    POLICIES_FIXTURE="$tmp/policies.json" \
    RULESETS_FIXTURE="$tmp/rulesets.json" \
    RULESET_FIXTURE="$tmp/bad-ruleset.json" \
      "$script" Kernel-Guard/bpfcompat production-release solo-maintainer \
      >/dev/null 2>&1; then
    echo "[production-environment-test] accepted unsafe tag ruleset: ${mutation}" >&2
    exit 1
  fi
done

echo "[production-environment-test] PASS"
