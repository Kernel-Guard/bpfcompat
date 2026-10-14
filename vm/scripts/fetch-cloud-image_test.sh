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

# Readiness timeout for the local test server (see the readiness gate
# below). Validated before anything is started.
ready_secs="${BPFCOMPAT_TEST_SERVER_READY_SECS:-15}"
# A non-numeric or zero value would break the wait loop before the
# server is up; refuse it explicitly instead.
if [[ ! "$ready_secs" =~ ^[1-9][0-9]*$ ]]; then
  echo "FAIL: BPFCOMPAT_TEST_SERVER_READY_SECS must be a positive integer, got '$ready_secs'" >&2
  exit 1
fi

work="$(mktemp -d)"
cleanup() {
  if [[ -n "${server_pid:-}" ]]; then
    kill "$server_pid" 2>/dev/null || true
    # Bounded: a SIGTERM delivered before the child exec'd python can be
    # lost, so escalate to SIGKILL instead of waiting forever.
    for _ in 1 2 3 4 5 6 7 8 9 10; do
      kill -0 "$server_pid" 2>/dev/null || break
      sleep 0.2
    done
    kill -9 "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
  fi
  rm -rf "$work"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

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
python3 "$work/server.py" "$port" "$work" >"$work/server.log" 2>&1 &
server_pid=$!

# Readiness gate. The test's assertions are only meaningful against a live
# server: run 38446833676 (attempt 1) failed with "transient 503 was not
# retried to success ... curl: (7) Failed to connect" because the old 5s poll
# fell through silently while the server was still starting, so the retry
# check burned its attempts on connection-refused and blamed the script.
# Wait up to BPFCOMPAT_TEST_SERVER_READY_SECS (default 15), stop early if the
# server process dies (e.g. port taken between pick and bind), and fail loudly
# as a test-harness error rather than a fetch-cloud-image regression.
ready_deadline=$(( SECONDS + ready_secs ))
server_state="timeout"
while (( SECONDS < ready_deadline )); do
  if curl -fsS -o /dev/null --max-time 2 "http://127.0.0.1:$port/ok" 2>/dev/null; then
    server_state="ready"
    break
  fi
  if ! kill -0 "$server_pid" 2>/dev/null; then
    server_state="exited"
    break
  fi
  sleep 0.1
done
if [[ "$server_state" != "ready" ]]; then
  if [[ "$server_state" == "exited" ]]; then
    echo "FAIL: test server did not become ready: process exited before serving on 127.0.0.1:$port; no fetch-cloud-image checks were run" >&2
  else
    echo "FAIL: test server did not become ready on 127.0.0.1:$port within ${ready_secs}s; no fetch-cloud-image checks were run" >&2
  fi
  echo "--- test server log ---" >&2
  cat "$work/server.log" >&2 || true
  echo "fetch-cloud-image_test: FAILED (test harness, not the script under test)" >&2
  exit 1
fi

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
