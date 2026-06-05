#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "Usage: $0 <source-url> <destination-path>" >&2
  exit 1
fi

source_url="$1"
destination_path="$2"

mkdir -p "$(dirname "$destination_path")"

if [[ -f "$destination_path" ]]; then
  echo "Image already exists at $destination_path"
  exit 0
fi

echo "Downloading $source_url"
if command -v curl >/dev/null 2>&1; then
  curl -fL "$source_url" -o "$destination_path"
elif command -v wget >/dev/null 2>&1; then
  wget -O "$destination_path" "$source_url"
else
  echo "Neither curl nor wget is installed." >&2
  exit 1
fi

echo "Saved image to $destination_path"

