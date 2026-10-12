#!/usr/bin/env bash
# Fetch one vendor cloud image into the local cache.
#
#   fetch-cloud-image.sh <source-url> <destination-path>
#
# Contract (relied on by the Makefile, scripts/fetch-matrix-images.sh and the
# compatibility-matrix-publish prefetch step):
#   - exit 0 and print "Image already exists" when the destination is cached;
#   - download to <destination>.part and rename only on success, so a failed
#     or interrupted download never leaves a file the next run mistakes for a
#     cached image;
#   - retry transient failures (BPFCOMPAT_FETCH_RETRIES, default 3, with
#     BPFCOMPAT_FETCH_RETRY_DELAY seconds between attempts, default 10) —
#     run 33499929031 died on a single mid-stream HTTP/2 PROTOCOL_ERROR;
#   - on failure exit non-zero and print one line pairing the URL with the
#     HTTP status and curl exit code, so a 502 (runs 36565005828/37464388426)
#     is readable without the full log;
#   - when BPFCOMPAT_FETCH_LOG is set, append one machine-readable
#     `status=<cached|ok|failed> url=... ...` line per invocation so a CI lane
#     can upload the prefetch outcome as evidence.
#
# The download result is never a compatibility verdict: a failed fetch makes
# the target an infrastructure error downstream, not a PASS or FAIL.
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "Usage: $0 <source-url> <destination-path>" >&2
  exit 1
fi

source_url="$1"
destination_path="$2"
retries="${BPFCOMPAT_FETCH_RETRIES:-3}"
retry_delay="${BPFCOMPAT_FETCH_RETRY_DELAY:-10}"
fetch_log="${BPFCOMPAT_FETCH_LOG:-}"

log_line() {
  if [[ -n "$fetch_log" ]]; then
    printf '%s\n' "$*" >>"$fetch_log"
  fi
}

mkdir -p "$(dirname "$destination_path")"

if [[ -f "$destination_path" ]]; then
  echo "Image already exists at $destination_path"
  log_line "status=cached url=$source_url path=$destination_path"
  exit 0
fi

part_path="$destination_path.part"
rm -f "$part_path"

echo "Downloading $source_url"
http_code="000"
fetch_exit=0
if command -v curl >/dev/null 2>&1; then
  # -f: HTTP errors are failures; --retry-all-errors: retry on 5xx and
  # transport errors, not only timeouts; -w prints the final HTTP status even
  # when -f fails, which is what the failure line below reports.
  http_code="$(curl -fL \
    --retry "$retries" --retry-delay "$retry_delay" --retry-all-errors \
    --connect-timeout 30 \
    -o "$part_path" -w '%{http_code}' "$source_url")" || fetch_exit=$?
elif command -v wget >/dev/null 2>&1; then
  http_code="n/a"
  wget --tries="$((retries + 1))" --waitretry="$retry_delay" -O "$part_path" "$source_url" || fetch_exit=$?
else
  echo "Neither curl nor wget is installed." >&2
  exit 1
fi

if [[ "$fetch_exit" -ne 0 ]]; then
  rm -f "$part_path"
  echo "fetch-cloud-image: FAILED url=$source_url http=${http_code:-000} exit=$fetch_exit (after $((retries + 1)) attempts)" >&2
  log_line "status=failed url=$source_url http=${http_code:-000} exit=$fetch_exit path=$destination_path"
  exit 1
fi

mv "$part_path" "$destination_path"
echo "Saved image to $destination_path"
log_line "status=ok url=$source_url path=$destination_path"
