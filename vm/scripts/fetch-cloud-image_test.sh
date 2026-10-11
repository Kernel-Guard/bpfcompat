#!/usr/bin/env bash
# Regression guard for vm/scripts/fetch-cloud-image.sh.
#
# The public compatibility lane (compatibility-matrix-publish) prefetches the
# quirk-library images with this script. Two production failures shaped it:
#   - run 33499929031 (2026-09-01): a transient HTTP/2 PROTOCOL_ERROR mid-stream
#     from cloud.centos.org killed the download; there was no retry.
#   - runs 36565005828 / 37464388426 (2026-09-29, 2026-10-06): the CentOS
#     Stream image URL started returning HTTP 502; the log showed only
#     "curl: (22)" with no URL/status pairing, so diagnosis needed the full log.
#
# This test runs the real script against a local HTTP server, no mocks:
#   1. a transient failure is retried and the download succeeds;
#   2. a permanent HTTP error exits non-zero, names the URL and status, and
#      leaves no partial file behind (a partial file would make the next run
#      print "Image already exists" and boot garbage);
#   3. a successful download is reported, and a second call is a no-op;
#   4. BPFCOMPAT_FETCH_LOG receives one machine-readable line per attempt
#      outcome so a CI lane can upload it as evidence.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SCRIPT="$ROOT/vm/scripts/fetch-cloud-image.sh"

command -v python3 >/dev/null || { echo "SKIP: python3 required" >&2; exit 0; }
command -v curl >/dev/null || { echo "SKIP: curl required" >&2; exit 0; }

work="$(mktemp -d)"
trap 'kill "${server_pid:-}" 2>/dev/null || true; rm -rf "$work"' EXIT

cat >"$work/server.py" <<'PY'
import http.server, os, sys
state = os.path.join(sys.argv[2], "flaky-count")
class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_HEAD(self): self.do_GET(head=True)
    def do_GET(self, head=False):
        if self.path == "/ok":
            body = b"image-bytes"
            self.send_response(200); self.send_header("Content-Length", str(len(body))); self.end_headers()
            if not head: self.wfile.write(body)
        elif self.path == "/bad":
            self.send_response(502); self.end_headers()
        elif self.path == "/flaky":
            n = int(open(state).read()) if os.path.exists(state) else 0
            open(state, "w").write(str(n + 1))
            if n < 2:
                self.send_response(503); self.end_headers()
            else:
                body = b"flaky-bytes"
                self.send_response(200); self.send_header("Content-Length", str(len(body))); self.end_headers()
                if not head: self.wfile.write(body)
        else:
            self.send_response(404); self.end_headers()
http.server.ThreadingHTTPServer(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
PY

port="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])')"
python3 "$work/server.py" "$port" "$work" &
server_pid=$!
for _ in $(seq 1 50); do
  curl -fsS -o /dev/null "http://127.0.0.1:$port/ok" 2>/dev/null && break
  sleep 0.1
done

fail=0
ok() { printf 'ok:   %s\n' "$1"; }
bad() { printf 'FAIL: %s\n' "$1" >&2; fail=1; }

# Keep retries fast in the test; the script must honour these knobs.
export BPFCOMPAT_FETCH_RETRIES=3
export BPFCOMPAT_FETCH_RETRY_DELAY=0
export BPFCOMPAT_FETCH_LOG="$work/fetch.log"

# 1. transient failure is retried
if bash "$SCRIPT" "http://127.0.0.1:$port/flaky" "$work/flaky.img" >"$work/flaky.out" 2>&1 \
   && [[ "$(cat "$work/flaky.img")" == "flaky-bytes" ]]; then
  ok "transient 503 is retried and the download completes"
else
  bad "transient 503 was not retried to success"; cat "$work/flaky.out" >&2
fi

# 2. permanent error: non-zero, names URL + status, no partial file
if bash "$SCRIPT" "http://127.0.0.1:$port/bad" "$work/bad.img" >"$work/bad.out" 2>&1; then
  bad "permanent 502 should exit non-zero"
else
  ok "permanent 502 exits non-zero"
fi
if grep -q "http=502" "$work/bad.out" && grep -q "/bad" "$work/bad.out"; then
  ok "failure output names the URL and the HTTP status"
else
  bad "failure output does not pair URL with http=502"; cat "$work/bad.out" >&2
fi
if [[ ! -e "$work/bad.img" && ! -e "$work/bad.img.part" ]]; then
  ok "no partial file is left after a failed download"
else
  bad "partial file left behind after failure"
fi

# 3. success path and idempotence
bash "$SCRIPT" "http://127.0.0.1:$port/ok" "$work/ok.img" >"$work/ok.out" 2>&1 || bad "download of /ok failed"
if [[ "$(cat "$work/ok.img")" == "image-bytes" ]]; then
  ok "successful download writes the full image"
else
  bad "image bytes wrong"
fi
if bash "$SCRIPT" "http://127.0.0.1:$port/ok" "$work/ok.img" 2>&1 | grep -q "already exists"; then
  ok "second call on a cached image is a no-op"
else
  bad "second call did not report the cached image"
fi

# 4. machine-readable log: one terminal line per invocation with status
if grep -qE "^status=ok url=http://127.0.0.1:$port/ok " "$BPFCOMPAT_FETCH_LOG" \
   && grep -qE "^status=failed url=http://127.0.0.1:$port/bad http=502" "$BPFCOMPAT_FETCH_LOG"; then
  ok "fetch log records ok and failed outcomes with URL and status"
else
  bad "fetch log missing expected status lines"; cat "$BPFCOMPAT_FETCH_LOG" >&2 || true
fi

if [[ "$fail" -ne 0 ]]; then
  echo "fetch-cloud-image_test: FAILED" >&2
  exit 1
fi
echo "fetch-cloud-image_test: all checks passed"
