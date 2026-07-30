#!/usr/bin/env bash
set -euo pipefail

repo="${1:-}"
environment="${2:-production-release}"
approval_mode="${3:-}"

fail() {
  echo "[production-environment] $*" >&2
  exit 2
}

[[ "$repo" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] ||
  fail "repository must be owner/name"
[[ "$environment" =~ ^[A-Za-z0-9_.-]+$ ]] ||
  fail "environment name contains unsupported characters"
[[ "$approval_mode" == "solo-maintainer" ]] ||
  fail "approval mode must be solo-maintainer"
command -v gh >/dev/null || fail "gh is required"

environment_json="$(gh api "repos/${repo}/environments/${environment}")" ||
  fail "cannot read protected environment ${environment}"

jq -e '
    .can_admins_bypass == false and
    .deployment_branch_policy.protected_branches == false and
    .deployment_branch_policy.custom_branch_policies == true and
    ([.protection_rules[] | select(.type == "required_reviewers")] | length == 0) and
    ([.protection_rules[] | select(.type == "wait_timer" and .wait_timer == 15)] | length == 1)
  ' <<<"$environment_json" >/dev/null ||
  fail "environment must have no required reviewers, use a 15-minute wait, disable admin bypass, and use custom deployment policies"

policies_json="$(
  gh api "repos/${repo}/environments/${environment}/deployment-branch-policies"
)" || fail "cannot read deployment policies for ${environment}"
jq -e '
  [.branch_policies[] | select(.type == "tag" and .name == "v*")] | length == 1
' <<<"$policies_json" >/dev/null ||
  fail "environment must contain exactly one v* tag deployment policy"

rulesets_json="$(gh api "repos/${repo}/rulesets")" ||
  fail "cannot read repository rulesets"
ruleset_id="$(
  jq -r '
    [
      .[] |
      select(
        .name == "Immutable release tags" and
        .target == "tag" and
        .enforcement == "active"
      ) |
      .id
    ] |
    if length == 1 then .[0] else empty end
  ' <<<"$rulesets_json"
)"
[[ "$ruleset_id" =~ ^[1-9][0-9]*$ ]] ||
  fail "repository must have exactly one active Immutable release tags ruleset"
ruleset_json="$(gh api "repos/${repo}/rulesets/${ruleset_id}")" ||
  fail "cannot read immutable release tag ruleset"
jq -e '
  .target == "tag" and
  .enforcement == "active" and
  .conditions.ref_name.include == ["refs/tags/v*"] and
  .conditions.ref_name.exclude == [] and
  (.bypass_actors | length == 0) and
  ([.rules[] | select(.type == "update")] | length == 1) and
  ([.rules[] | select(.type == "deletion")] | length == 1)
' <<<"$ruleset_json" >/dev/null ||
  fail "v* tags must reject updates and deletion without bypass actors"

echo "[production-environment] PASS environment=${environment} mode=${approval_mode} immutable_tags=true"
