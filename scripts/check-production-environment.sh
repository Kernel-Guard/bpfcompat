#!/usr/bin/env bash
set -euo pipefail

repo="${1:-}"
environment="${2:-production-release}"
reviewer="${3:-}"

fail() {
  echo "[production-environment] $*" >&2
  exit 2
}

[[ "$repo" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] ||
  fail "repository must be owner/name"
[[ "$environment" =~ ^[A-Za-z0-9_.-]+$ ]] ||
  fail "environment name contains unsupported characters"
[[ "$reviewer" =~ ^[A-Za-z0-9]([A-Za-z0-9-]{0,37}[A-Za-z0-9])?$ ]] ||
  fail "reviewer must be a valid GitHub login"
command -v gh >/dev/null || fail "gh is required"

environment_json="$(gh api "repos/${repo}/environments/${environment}")" ||
  fail "cannot read protected environment ${environment}"

jq -e \
  --arg reviewer "$reviewer" '
    .can_admins_bypass == false and
    .deployment_branch_policy.protected_branches == false and
    .deployment_branch_policy.custom_branch_policies == true and
    any(
      .protection_rules[];
      .type == "required_reviewers" and
      .prevent_self_review == true and
      any(.reviewers[]?; .type == "User" and .reviewer.login == $reviewer)
    )
  ' <<<"$environment_json" >/dev/null ||
  fail "environment must require ${reviewer}, prevent self-review, disable admin bypass, and use custom deployment policies"

policies_json="$(
  gh api "repos/${repo}/environments/${environment}/deployment-branch-policies"
)" || fail "cannot read deployment policies for ${environment}"
jq -e '
  [.branch_policies[] | select(.type == "tag" and .name == "v*")] | length == 1
' <<<"$policies_json" >/dev/null ||
  fail "environment must contain exactly one v* tag deployment policy"

echo "[production-environment] PASS environment=${environment} reviewer=${reviewer}"
