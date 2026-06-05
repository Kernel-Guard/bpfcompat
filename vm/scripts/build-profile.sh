#!/usr/bin/env bash
set -euo pipefail

profile_id="${1:-}"
if [[ -z "$profile_id" ]]; then
  echo "Usage: $0 <profile-id>" >&2
  exit 1
fi

echo "build-profile.sh is scaffolded only. Requested profile: $profile_id"
echo "Week-2/3 will install validator dependencies and snapshot boot-ready images."

