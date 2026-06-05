#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

evidence_root="${BPFCOMPAT_HOSTILE_EVIDENCE_DIR:-evidence/hostile-suite}"

echo "[hostile-suite] Running hostile artifact hardening checks"

if [[ ! -x ./bin/bpfcompat ]]; then
  echo "[hostile-suite] missing CLI binary at ./bin/bpfcompat (run: make build)" >&2
  exit 1
fi

echo "[hostile-suite] 1/3 runtime fetch hardening unit tests"
go test ./internal/runtime -run 'TestFetchArtifact(RemoteHashMismatch|RejectsUnsupportedURI|EnforcesSizeLimit)' -count=1

echo "[hostile-suite] 2/3 registry tamper-evidence verification unit tests"
go test ./internal/registry -run 'TestVerifyArtifactVersionHistory(DetectsTamper|DetectsSignatureTamper)?' -count=1

echo "[hostile-suite] 3/3 optional VM isolation scenario (non-ELF hostile input)"
if [[ "${BPFCOMPAT_RUN_VM_HOSTILE:-0}" == "1" ]] && [[ -e /dev/kvm && -f vm/cache/ubuntu-22.04.qcow2 ]]; then
  timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
  evidence_dir="${evidence_root}/${timestamp}"
  mkdir -p "$evidence_dir"
  echo "[hostile-suite] Evidence directory: ${evidence_dir}"
  mkdir -p reports
  set +e
  ./bin/bpfcompat test \
    --artifact examples/unknown-load-fail/invalid_object.bin \
    --manifest examples/unknown-load-fail/manifest-dev-one.yaml \
    --matrix matrices/dev-one.yaml \
    --out reports/hostile-unknown-load-dev-one.json \
    --markdown reports/hostile-unknown-load-dev-one.md \
    --timeout 8m \
    2>&1 | tee "${evidence_dir}/hostile-vm-run.log"
  vm_rc=$?
  set -e

  if [[ ! -f reports/hostile-unknown-load-dev-one.json ]]; then
    echo "[hostile-suite] FAIL: hostile VM report was not produced (rc=${vm_rc})"
    exit 1
  fi

  cp reports/hostile-unknown-load-dev-one.json "${evidence_dir}/"
  if [[ -f reports/hostile-unknown-load-dev-one.md ]]; then
    cp reports/hostile-unknown-load-dev-one.md "${evidence_dir}/"
  fi

  if command -v jq >/dev/null 2>&1; then
    status="$(jq -r '.summary.status // empty' reports/hostile-unknown-load-dev-one.json)"
    if [[ "$status" == "error" ]]; then
      echo "[hostile-suite] FAIL: VM isolation scenario ended in infra error"
      exit 1
    fi
  fi
  echo "[hostile-suite] VM isolation scenario completed"
else
  echo "[hostile-suite] SKIP: set BPFCOMPAT_RUN_VM_HOSTILE=1 with KVM/image prerequisites to execute VM scenario"
fi

echo "[hostile-suite] PASS"
