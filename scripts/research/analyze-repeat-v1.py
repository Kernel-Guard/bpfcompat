#!/usr/bin/env python3
"""Analyze a stratified repeat-run sample against canonical pilot v1 evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any

IMAGE_NOTE = re.compile(r"^base image sha256:\s*([0-9a-fA-F]{64})\s*$")
KERNEL_SERIES_RE = re.compile(r"^(\d+)\.(\d+)")
STATUS_TO_PRODUCER = {
    "pass": "COMPATIBLE",
    "fail": "INCOMPATIBLE",
    "partial": "INCOMPATIBLE",
    "infra_error": "INFRA_ERROR",
    "unsupported": "UNSUPPORTED",
}


def canonical_hash(value: Any) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return "sha256:" + h.hexdigest()


def kernel_series(value: str) -> str | None:
    text = value.strip()
    match = KERNEL_SERIES_RE.match(text)
    if not match:
        return None
    rest = text[match.end() :]
    if rest and rest[0].isalnum():
        return None
    return f"{match.group(1)}.{match.group(2)}"


def image_digest(target: dict[str, Any], label: str) -> str | None:
    for note in target.get("notes") or []:
        text = str(note).strip()
        match = IMAGE_NOTE.match(text)
        if match:
            return "sha256:" + match.group(1).lower()
        if text.lower().startswith("base image sha256:"):
            raise SystemExit(f"{label}: malformed base image SHA-256 note")
    return None


def derive_verdict(status: str, kernel_match: bool | None, env_ok: bool) -> tuple[str, str | None]:
    if status == "infra_error":
        return "inconclusive", "infrastructure_error"
    if status == "unsupported":
        return "inconclusive", "unsupported_execution_path"
    if kernel_match is False:
        return "inconclusive", "environment_unavailable"
    if kernel_match is not True or not env_ok:
        return "inconclusive", "evidence_unavailable"
    if status == "pass":
        return "compatible", None
    if status in {"fail", "partial"}:
        return "incompatible", None
    raise SystemExit(f"unsupported repeat target status: {status!r}")


def canonical_row(data_dir: Path, case_id: str, profile_id: str) -> dict[str, Any]:
    path = data_dir / "processed" / "executions" / f"{case_id}.jsonl"
    matches = [
        json.loads(line)
        for line in path.read_text().splitlines()
        if line.strip() and json.loads(line)["logical_profile_id"] == profile_id
    ]
    if len(matches) != 1:
        raise SystemExit(
            f"canonical row lookup failed for {case_id}/{profile_id}: {len(matches)} rows"
        )
    return matches[0]


def normalize_repeat_target(
    target: dict[str, Any],
    profile_revision: str,
    label: str,
) -> dict[str, Any]:
    profile = target.get("profile") or {}
    host = target.get("host") or {}
    if not isinstance(profile, dict) or not isinstance(host, dict):
        raise SystemExit(f"{label}: profile/host must be objects")

    status = str(target.get("status") or "").strip().lower()
    if status not in STATUS_TO_PRODUCER:
        raise SystemExit(f"{label}: unsupported or missing status {status!r}")

    requested = str(profile.get("kernel_family") or "").strip()
    observed = str(host.get("kernel") or "").strip()
    requested_series = kernel_series(requested)
    observed_series = kernel_series(observed)
    kernel_match = (
        requested_series == observed_series
        if requested_series is not None and observed_series is not None
        else None
    )

    distro = str(profile.get("distro") or "").strip()
    distro_release = str(profile.get("version") or "").strip()
    arch = str(profile.get("arch") or host.get("arch") or "").strip()
    image_sha = image_digest(target, label)

    env_ok = bool(
        kernel_match is not None
        and observed
        and image_sha
        and requested
        and arch
        and distro
        and distro_release
        and profile_revision
    )

    environment_id = None
    if env_ok:
        env_record = {
            "logical_profile_id": str(target.get("profile_id") or "").strip(),
            "distribution": distro,
            "distribution_release": distro_release,
            "architecture": arch,
            "requested_kernel_family": requested,
            "observed_kernel_release": observed,
            "image_source": "",
            "image_identity": image_sha,
            "profile_revision": profile_revision,
            "kernel_family_match": kernel_match,
        }
        environment_id = canonical_hash(env_record)

    verdict, reason = derive_verdict(status, kernel_match, env_ok)
    return {
        "target_status": status,
        "target_verdict": STATUS_TO_PRODUCER[status],
        "verdict": verdict,
        "inconclusive_reason": reason,
        "environment_id": environment_id,
        "kernel_family_match": kernel_match,
        "observed_kernel_release": observed or None,
        "image_identity": image_sha,
    }


def self_test() -> int:
    assert kernel_series("5.15.0-1") == "5.15"
    assert kernel_series("4.18.0-foo") == "4.18"
    assert kernel_series("not-a-kernel") is None
    assert derive_verdict("pass", True, True) == ("compatible", None)
    assert derive_verdict("fail", True, True) == ("incompatible", None)
    assert derive_verdict("pass", False, True) == (
        "inconclusive",
        "environment_unavailable",
    )
    a = canonical_hash({"b": 2, "a": 1})
    b = canonical_hash({"a": 1, "b": 2})
    assert a == b
    print("[analyze-repeat-v1] self-test PASS")
    return 0


def main() -> int:
    if "--self-test" in sys.argv[1:]:
        return self_test()

    ap = argparse.ArgumentParser()
    ap.add_argument("--reports-dir", default="reports/research-repeat-v1")
    ap.add_argument("--sample", default="research/repeat/v1/stability-sample.json")
    ap.add_argument("--data-dir", default="research/data/v1")
    ap.add_argument("--profile-lock", default="research/corpus/v1/profile-identities.json")
    ap.add_argument("--out-dir", default="reports/research-repeat-v1/normalized")
    args = ap.parse_args()

    reports_dir = Path(args.reports_dir)
    data_dir = Path(args.data_dir)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    sample = json.loads(Path(args.sample).read_text())
    if sample.get("schema_version") != "bpfcompat.research.repeat-sample.v1":
        raise SystemExit("unsupported repeat sample schema")
    repeats = int(sample.get("repeats_per_tuple") or 0)
    tuples = sample.get("tuples")
    if repeats <= 0 or not isinstance(tuples, list) or not tuples:
        raise SystemExit("repeat sample must define tuples and positive repeats_per_tuple")

    lock = json.loads(Path(args.profile_lock).read_text())
    revisions = {
        p["id"]: "git-blob:" + p["git_blob"]
        for p in lock.get("profiles") or []
    }

    rows: list[dict[str, Any]] = []
    missing: list[str] = []
    tuple_summaries: list[dict[str, Any]] = []

    for item in tuples:
        tuple_id = str(item.get("id") or "").strip()
        case_id = str(item.get("case_id") or "").strip()
        profile_id = str(item.get("profile_id") or "").strip()
        if not tuple_id or not case_id or profile_id not in revisions:
            raise SystemExit(f"invalid repeat tuple: {item!r}")

        canonical = canonical_row(data_dir, case_id, profile_id)
        local_rows: list[dict[str, Any]] = []

        for repeat in range(1, repeats + 1):
            label = f"{tuple_id}/repeat-{repeat}"
            report_path = reports_dir / "raw" / tuple_id / f"repeat-{repeat}.json"
            if not report_path.is_file():
                missing.append(label)
                continue

            report = json.loads(report_path.read_text())
            if report.get("schema_version") != "v0.1":
                raise SystemExit(f"{label}: unexpected report schema")
            targets = report.get("targets")
            if not isinstance(targets, list) or len(targets) != 1:
                raise SystemExit(f"{label}: expected exactly one target")
            target = targets[0]
            if str(target.get("profile_id") or "").strip() != profile_id:
                raise SystemExit(f"{label}: profile mismatch")

            norm = normalize_repeat_target(
                target,
                revisions[profile_id],
                label,
            )
            if norm["environment_id"] != canonical["environment_id"]:
                comparison = "environment_drift"
            elif norm["verdict"] != canonical["verdict"]:
                comparison = "verdict_instability"
            else:
                comparison = "stable_same_environment"

            row = {
                "tuple_id": tuple_id,
                "repeat": repeat,
                "case_id": case_id,
                "profile_id": profile_id,
                "stratum": item.get("stratum"),
                "canonical_verdict": canonical["verdict"],
                "canonical_environment_id": canonical["environment_id"],
                "canonical_raw_report_sha256": canonical["raw_report_sha256"],
                "repeat_raw_report_sha256": sha256_file(report_path),
                "comparison": comparison,
                **norm,
            }
            rows.append(row)
            local_rows.append(row)

        counts = Counter(r["comparison"] for r in local_rows)
        tuple_summaries.append(
            {
                "tuple_id": tuple_id,
                "case_id": case_id,
                "profile_id": profile_id,
                "stratum": item.get("stratum"),
                "planned_repeats": repeats,
                "observed_repeats": len(local_rows),
                "stable_same_environment": counts["stable_same_environment"],
                "environment_drift": counts["environment_drift"],
                "verdict_instability": counts["verdict_instability"],
            }
        )

    expected = len(tuples) * repeats
    counts = Counter(r["comparison"] for r in rows)
    collection_complete = len(rows) == expected and not missing

    with (out_dir / "repeat-executions.jsonl").open("w") as f:
        for row in rows:
            f.write(json.dumps(row, sort_keys=True) + "\n")

    summary = {
        "schema_version": "bpfcompat.research.repeat-summary.v1",
        "corpus_version": "v1",
        "canonical_run_id": sample["canonical_run_id"],
        "canonical_run_sha": sample["canonical_run_sha"],
        "sampling_design": sample["sampling_design"],
        "planned_tuples": len(tuples),
        "repeats_per_tuple": repeats,
        "planned_attempts": expected,
        "observed_attempts": len(rows),
        "collection_complete": collection_complete,
        "stable_same_environment": counts["stable_same_environment"],
        "environment_drift": counts["environment_drift"],
        "verdict_instability": counts["verdict_instability"],
        "missing": missing,
        "tuple_summaries": tuple_summaries,
        "interpretation": (
            "Verdict instability is counted only when the exact environment ID matches "
            "the canonical run. Environment drift is reported separately and is not "
            "treated as nondeterministic compatibility behavior."
        ),
    }
    (out_dir / "stability-summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n"
    )

    lines = [
        "# Pilot v1 repeat-run stability",
        "",
        "This is a purposeful post-collection stability sample, not a random population sample.",
        "",
        f"- Planned attempts: {expected}",
        f"- Observed attempts: {len(rows)}",
        f"- Stable on the same exact environment: {counts['stable_same_environment']}",
        f"- Environment drift: {counts['environment_drift']}",
        f"- Verdict instability on the same environment: {counts['verdict_instability']}",
        "",
        "Environment drift is kept separate from verdict instability.",
    ]
    (out_dir / "RESULTS.md").write_text("\n".join(lines) + "\n")

    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if collection_complete else 3


if __name__ == "__main__":
    sys.exit(main())
