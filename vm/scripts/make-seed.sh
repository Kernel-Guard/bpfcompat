#!/usr/bin/env bash
set -euo pipefail

seed_dir="${1:-}"
if [[ -z "$seed_dir" ]]; then
  echo "Usage: $0 <seed-dir>" >&2
  exit 1
fi

mkdir -p "$seed_dir"
echo "make-seed.sh is scaffolded only; cloud-init generation is pending."

