#!/usr/bin/env bash
# Evidence uses the v0.3.7 report contract. No report/validator schema backport.
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
assets="$(realpath "${1:?asset directory required}")"
work="${2:?fresh absolute evidence directory required}"
[[ "$work" == /* && ! -e "$work" ]]
mkdir -p "$work/vm/profiles" "$work/reports"
profiles=(centos-stream-9-5.14 centos-stream-10-6.12 centos-stream-9-5.14-k5.14.0-725.el9)
for profile in "${profiles[@]}"; do cp "$root/vm/profiles/$profile.yaml" "$work/vm/profiles/"; done
validator="$assets/bpfcompat-validator-static-linux-amd64"
cli="$assets/bpfcompat-linux-amd64"
chmod +x "$validator" "$cli"
test -z "$(git -C "$root" status --porcelain -- . ':!dist')"
test "$("$cli" version --json | jq -r .commit)" = "$(git -C "$root" rev-parse HEAD)"
export BPFCOMPAT_VALIDATOR_BIN="$validator"
validator_sha="$(sha256sum "$validator" | awk '{print $1}')"
clang -O2 -g -target bpf -D__TARGET_ARCH_x86 -I/usr/include/x86_64-linux-gnu \
  -c "$root/examples/simple-pass/simple_pass.bpf.c" -o "$work/simple_pass.bpf.o"
python3 - "$work" "$validator_sha" "${profiles[@]}" <<'PY'
import sys
from pathlib import Path
import yaml
work, digest, *profiles = sys.argv[1:]
root = Path(work)
(root / 'matrix.yaml').write_text(yaml.safe_dump({'name': 'maintenance-required', 'profiles': [{'id': p, 'required': True} for p in profiles]}))
positive = {'name': 'maintenance-positive', 'required_profiles': profiles, 'programs': [{'name': 'handle_exec', 'section': 'tracepoint/syscalls/sys_enter_execve', 'type': 'tracepoint', 'attach': {'kind': 'tracepoint', 'category': 'syscalls', 'name': 'sys_enter_execve', 'required': True}}], 'functional_tests': [{'name': 'exact-guest-validator', 'command': 'sha256sum /tmp/bpfcompat/bin/bpfcompat-validator', 'timeout': '5s', 'expect_exit_code': 0, 'expect_stdout_contains': digest}]}
(root / 'positive.yaml').write_text(yaml.safe_dump(positive))
(root / 'negative.yaml').write_text(yaml.safe_dump({'name': 'maintenance-invalid-object', 'required_profiles': profiles}))
PY
cd "$work"
set +e
"$cli" test --artifact "$work/simple_pass.bpf.o" --manifest positive.yaml --matrix matrix.yaml \
  --out reports/release-positive.json --markdown reports/release-positive.md --workdir positive-work --timeout 12m --concurrency 1
positive_rc=$?
"$cli" test --artifact "$root/examples/unknown-load-fail/invalid_object.bin" --manifest negative.yaml --matrix matrix.yaml \
  --out reports/release-negative.json --markdown reports/release-negative.md --workdir negative-work --timeout 12m --concurrency 1
negative_rc=$?
set -e
sha256sum "$cli" "$validator" "$work/simple_pass.bpf.o" "$root/examples/unknown-load-fail/invalid_object.bin" vm/cache/*.qcow2 >reports/artifact-identity.sha256
jq -n --arg commit "$(git -C "$root" rev-parse HEAD)" --argjson positive_exit "$positive_rc" --argjson negative_exit "$negative_rc" \
  --arg validator_sha256 "$validator_sha" --arg cli_sha256 "$(sha256sum "$cli" | awk '{print $1}')" \
  '{source_commit:$commit,positive_exit:$positive_exit,negative_exit:$negative_exit,validator_sha256:$validator_sha256,cli_sha256:$cli_sha256}' >reports/release-artifact-identity.json
test "$positive_rc" -eq 0
test "$negative_rc" -eq 2
jq -e '.schema_version == "v0.1" and .summary.status == "pass" and (.targets|length==3) and all(.targets[]; .required and .status=="pass" and .validation.load_status=="pass" and .validation.attach_status=="pass" and .validation.attach_attempted>0 and .validation.attach_passed==.validation.attach_attempted and .functional.status=="pass" and (.infra_error // "")=="") and any(.targets[]; .profile_id=="centos-stream-9-5.14-k5.14.0-725.el9" and .host.kernel=="5.14.0-725.el9.x86_64")' reports/release-positive.json >/dev/null
jq -e '.schema_version == "v0.1" and .summary.status == "fail" and (.targets|length==3) and all(.targets[]; .required and .status=="fail" and .validation.load_status=="fail" and (.infra_error // "")=="") and any(.targets[]; .profile_id=="centos-stream-9-5.14-k5.14.0-725.el9" and .host.kernel=="5.14.0-725.el9.x86_64")' reports/release-negative.json >/dev/null
jq -e '..|objects|select(.classification_code?=="UNKNOWN")' reports/release-negative.json >/dev/null
echo '[maintenance-vm] exact validator bytes, required load/attach, kernel 725 and negative fixture PASS'
