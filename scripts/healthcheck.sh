#!/usr/bin/env bash
set -uo pipefail

# Self-hosted liveness watchdog for the bpfcompat demo. Probes the local health
# endpoint; if it is unhealthy after a few retries, logs to the journal,
# optionally posts to a webhook, and restarts the serve unit. Intended to be run
# on a short systemd timer (see packaging/systemd/bpfcompat-healthcheck.*).
#
# This catches "process up but API hung/unhealthy" — a case plain systemd
# Restart=on-failure does not. It is NOT a substitute for an external monitor
# (it cannot alert if the whole box/network is down); pair it with one.
#
# Config (env):
#   BPFCOMPAT_HEALTH_URL       default http://127.0.0.1:8080/api/health
#   BPFCOMPAT_HEALTH_UNIT      systemd unit to restart (default bpfcompat-serve.service)
#   BPFCOMPAT_HEALTH_RETRIES   probe attempts before acting (default 3)
#   BPFCOMPAT_HEALTH_RETRY_GAP seconds between attempts (default 3)
#   BPFCOMPAT_HEALTH_TIMEOUT   per-probe curl timeout seconds (default 5)
#   BPFCOMPAT_HEALTH_WEBHOOK   optional URL to POST a JSON alert on failure
#   BPFCOMPAT_HEALTH_RESTART   "true" (default) to restart the unit on failure

URL="${BPFCOMPAT_HEALTH_URL:-http://127.0.0.1:8080/api/health}"
UNIT="${BPFCOMPAT_HEALTH_UNIT:-bpfcompat-serve.service}"
RETRIES="${BPFCOMPAT_HEALTH_RETRIES:-3}"
GAP="${BPFCOMPAT_HEALTH_RETRY_GAP:-3}"
TIMEOUT="${BPFCOMPAT_HEALTH_TIMEOUT:-5}"
WEBHOOK="${BPFCOMPAT_HEALTH_WEBHOOK:-}"
DO_RESTART="${BPFCOMPAT_HEALTH_RESTART:-true}"

log() { echo "bpfcompat-healthcheck: $*" >&2; }

probe() {
  curl -fsS --max-time "$TIMEOUT" -o /dev/null "$URL"
}

attempt=1
while [ "$attempt" -le "$RETRIES" ]; do
  if probe; then
    [ "$attempt" -gt 1 ] && log "recovered on attempt ${attempt}"
    exit 0
  fi
  log "health probe failed (attempt ${attempt}/${RETRIES}) for ${URL}"
  attempt=$((attempt + 1))
  [ "$attempt" -le "$RETRIES" ] && sleep "$GAP"
done

ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
log "UNHEALTHY after ${RETRIES} attempts at ${ts}"

if [ -n "$WEBHOOK" ]; then
  payload=$(printf '{"text":"bpfcompat demo health check FAILED at %s (%s)"}' "$ts" "$URL")
  curl -fsS --max-time 10 -H 'Content-Type: application/json' -d "$payload" "$WEBHOOK" >/dev/null 2>&1 \
    && log "alert posted to webhook" || log "webhook post failed"
fi

if [ "$DO_RESTART" = "true" ]; then
  log "restarting ${UNIT}"
  systemctl try-restart "$UNIT" && log "restart issued" || log "restart failed"
fi

exit 1
