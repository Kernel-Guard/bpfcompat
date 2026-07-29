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
      "type": "required_reviewers",
      "prevent_self_review": true,
      "reviewers": [
        {
          "type": "User",
          "reviewer": {"login": "yusuf-demirel4"}
        }
      ]
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

PATH="$tmp/bin:$PATH" \
ENVIRONMENT_FIXTURE="$tmp/environment.json" \
POLICIES_FIXTURE="$tmp/policies.json" \
  "$script" Kernel-Guard/bpfcompat production-release yusuf-demirel4 \
  >"$tmp/pass.log"
grep -Fq '[production-environment] PASS' "$tmp/pass.log"

for mutation in \
  '.can_admins_bypass = true' \
  '.protection_rules[0].prevent_self_review = false' \
  '.protection_rules[0].reviewers[0].reviewer.login = "someone-else"' \
  '.deployment_branch_policy.custom_branch_policies = false'; do
  jq "$mutation" "$tmp/environment.json" >"$tmp/bad-environment.json"
  if PATH="$tmp/bin:$PATH" \
    ENVIRONMENT_FIXTURE="$tmp/bad-environment.json" \
    POLICIES_FIXTURE="$tmp/policies.json" \
      "$script" Kernel-Guard/bpfcompat production-release yusuf-demirel4 \
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
    "$script" Kernel-Guard/bpfcompat production-release yusuf-demirel4 \
    >/dev/null 2>&1; then
  echo "[production-environment-test] accepted missing tag policy" >&2
  exit 1
fi

echo "[production-environment-test] PASS"
