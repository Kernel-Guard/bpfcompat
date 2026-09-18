#!/usr/bin/env python3
"""Normalize frozen BPFCompat pilot-v1 reports into research execution records."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

IMAGE_NOTE = re.compile(r"^base image sha256:\s*([0-9a-fA-F]{64})\s*$")


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return "sha256:" + h.hexdigest()


def canonical_hash(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def image_digest(target: dict[str, Any]) -> str | None:
    env = target.get("environment") or {}
    raw = str(env.get("image_sha256") or "").strip()
    if raw:
        return raw if raw.startswith("sha256:") else "sha256:" + raw.lower()
    for note in target.get("notes") or []:
        m = IMAGE_NOTE.match(str(note))
        if m:
            return "sha256:" + m.group(1).lower()
    return None


def verdict_for(target: dict[str, Any], environment_complete: bool) -> tuple[str, str | None]:
    status = str(target.get("status") or "").lower()
    verdict = str(target.get("verdict") or "").upper()
    env = target.get("environment") or {}

    if env.get("kernel_family_match") is False:
        return "inconclusive", "environment_unavailable"
    if status == "infra_error" or verdict == "INFRA_ERROR":
        return "inconclusive", "infrastructure_error"
    if status == "unsupported" or verdict == "UNSUPPORTED":
        return "inconclusive", "unsupported_execution_path"
    if not environment_complete:
        return "inconclusive", "evidence_unavailable"
    if verdict == "COMPATIBLE" or status == "pass":
        return "compatible", None
    if verdict == "INCOMPATIBLE" or status in {"fail", "partial"}:
        return "incompatible", None
    return "inconclusive", "unknown"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--reports-dir", required=True)
    ap.add_argument("--study-plan", default="research/corpus/v1/study-plan.json")
    ap.add_argument("--profile-lock", default="research/corpus/v1/profile-identities.json")
    ap.add_argument("--identity-lock", default="research/corpus/v1/materialized-identities.json")
    ap.add_argument("--out-dir", required=True)
    args = ap.parse_args()

    reports_dir = Path(args.reports_dir)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    plan = json.loads(Path(args.study_plan).read_text())
    profile_lock_doc = json.loads(Path(args.profile_lock).read_text())
    identity_lock = json.loads(Path(args.identity_lock).read_text())

    expected_profiles = int(plan["expected_profiles"])
    profile_locks = {
        p["id"]: {
            "path": p["path"],
            "profile_revision": "git-blob:" + p["git_blob"],
        }
        for p in profile_lock_doc["profiles"]
    }
    expected_profile_ids = set(profile_locks)

    artifact_hashes = {a["id"]: a["sha256"] for a in identity_lock["artifacts"]}
    bpf_version = plan["bpfcompat"]["version"]
    bpf_commit = plan["bpfcompat"]["commit"]

    environments: dict[str, dict[str, Any]] = {}
    profile_to_env_ids: dict[str, set[str]] = {p: set() for p in expected_profile_ids}
    executions: list[dict[str, Any]] = []
    case_summaries: list[dict[str, Any]] = []
    missing_cases: list[str] = []

    for case in plan["cases"]:
        case_id = case["id"]
        report_path = reports_dir / f"{case_id}.json"
        if not report_path.is_file():
            missing_cases.append(case_id)
            case_summaries.append({"case_id": case_id, "report": None, "targets": 0})
            continue

        report = json.loads(report_path.read_text())
        report_hash = sha256_file(report_path)
        targets = report.get("targets") or []
        raw_artifact = report.get("artifact") or {}
        command = report.get("command") or {}
        validator = report.get("validator") or {}

        # Fail closed on materialized input drift visible in the report.
        artifact_id = case["artifact_id"]
        if case.get("artifact_path"):
            expected_artifact = artifact_hashes.get(artifact_id)
            observed_artifact = str(raw_artifact.get("sha256") or "")
            observed_artifact = (
                observed_artifact if observed_artifact.startswith("sha256:")
                else ("sha256:" + observed_artifact if observed_artifact else "")
            )
            if expected_artifact and observed_artifact != expected_artifact:
                raise SystemExit(
                    f"{case_id}: artifact digest mismatch: expected {expected_artifact}, "
                    f"got {observed_artifact or '<empty>'}"
                )

        if case["mode"] == "command":
            binary = command.get("binary") or {}
            expected_loader_id = (
                "cilium-ebpf-v022-loader"
                if case_id == "cilium-tracepoint-ebpf-go"
                else "falco-modern-bpf-scap-open"
            )
            expected_loader = artifact_hashes[expected_loader_id]
            observed_loader = str(binary.get("sha256") or "")
            observed_loader = (
                observed_loader if observed_loader.startswith("sha256:")
                else ("sha256:" + observed_loader if observed_loader else "")
            )
            if observed_loader != expected_loader:
                raise SystemExit(
                    f"{case_id}: command loader digest mismatch: expected {expected_loader}, "
                    f"got {observed_loader or '<empty>'}"
                )
        else:
            expected_validator = artifact_hashes["bpfcompat-v037-validator"]
            observed_validator = str(validator.get("sha256") or "")
            observed_validator = (
                observed_validator if observed_validator.startswith("sha256:")
                else ("sha256:" + observed_validator if observed_validator else "")
            )
            if observed_validator != expected_validator:
                raise SystemExit(
                    f"{case_id}: validator digest mismatch: expected {expected_validator}, "
                    f"got {observed_validator or '<empty>'}"
                )

        base_contract = case["base_validation_contract_id"]
        manifest_path = case.get("manifest")
        if manifest_path:
            manifest_sha = sha256_file(Path(manifest_path))
            validation_contract_id = canonical_hash(
                {
                    "base_validation_contract_id": base_contract,
                    "manifest_sha256": manifest_sha,
                }
            )
        else:
            manifest_sha = None
            validation_contract_id = base_contract

        case_counts = {"compatible": 0, "incompatible": 0, "inconclusive": 0}

        for target in targets:
            profile_id = str(target.get("profile_id") or "")
            if profile_id not in profile_locks:
                raise SystemExit(f"{case_id}: unexpected profile in report: {profile_id!r}")

            env = target.get("environment") or {}
            profile = target.get("profile") or {}
            host = target.get("host") or {}

            observed_kernel = str(
                env.get("observed_kernel") or host.get("kernel") or ""
            ).strip()
            img_sha = image_digest(target)
            profile_revision = profile_locks[profile_id]["profile_revision"]
            requested_family = str(
                env.get("requested_kernel_family") or profile.get("kernel_family") or ""
            ).strip()
            arch = str(profile.get("arch") or host.get("arch") or "").strip()
            image_source = str(env.get("image_source_url") or "").strip()

            environment_complete = bool(
                observed_kernel and img_sha and requested_family and arch and profile_revision
            )

            exact_environment_id: str | None = None
            if environment_complete:
                env_record = {
                    "logical_profile_id": profile_id,
                    "distribution": str(profile.get("distro") or "").strip(),
                    "distribution_release": str(profile.get("version") or "").strip(),
                    "architecture": arch,
                    "requested_kernel_family": requested_family,
                    "observed_kernel_release": observed_kernel,
                    "image_source": image_source,
                    "image_identity": img_sha,
                    "profile_revision": profile_revision,
                    "kernel_family_match": env.get("kernel_family_match"),
                }
                exact_environment_id = canonical_hash(env_record)
                env_record["exact_environment_id"] = exact_environment_id
                environments.setdefault(exact_environment_id, env_record)
                profile_to_env_ids[profile_id].add(exact_environment_id)

            verdict, inconclusive_reason = verdict_for(target, environment_complete)
            case_counts[verdict] += 1

            classification = target.get("classification_code")
            if verdict == "incompatible" and not classification:
                classification = "unknown"
            if verdict != "incompatible":
                classification = None

            executions.append(
                {
                    "dataset_version": "v1",
                    "case_id": case_id,
                    "run_id": (report.get("run") or {}).get("id"),
                    "timestamp_utc": (report.get("run") or {}).get("started_at"),
                    "bpfcompat_version": bpf_version,
                    "bpfcompat_commit": bpf_commit,
                    "artifact_id": artifact_id,
                    "artifact_sha256": artifact_hashes.get(artifact_id),
                    "environment_id": exact_environment_id,
                    "logical_profile_id": profile_id,
                    "observed_kernel_release": observed_kernel or None,
                    "architecture": arch or None,
                    "validation_contract_id": validation_contract_id,
                    "base_validation_contract_id": base_contract,
                    "manifest_sha256": manifest_sha,
                    "validation_mode": case["mode"],
                    "verdict": verdict,
                    "classification_code": classification,
                    "inconclusive_reason": inconclusive_reason,
                    "target_status": target.get("status"),
                    "target_verdict": target.get("verdict"),
                    "raw_report_sha256": report_hash,
                    "evidence_path": str(report_path),
                    "classification_confidence": target.get("classification_confidence"),
                    "failed_stage": target.get("failed_stage"),
                }
            )

        case_summaries.append(
            {
                "case_id": case_id,
                "report": str(report_path),
                "targets": len(targets),
                **case_counts,
            }
        )

    profile_environment_counts = {
        profile_id: len(ids) for profile_id, ids in sorted(profile_to_env_ids.items())
    }
    missing_environments = [
        profile_id for profile_id, count in profile_environment_counts.items() if count == 0
    ]
    environment_drift = {
        profile_id: sorted(ids)
        for profile_id, ids in profile_to_env_ids.items()
        if len(ids) > 1
    }
    wrong_target_counts = [
        row["case_id"]
        for row in case_summaries
        if row["report"] is not None and row["targets"] != expected_profiles
    ]

    totals = {"compatible": 0, "incompatible": 0, "inconclusive": 0}
    for row in executions:
        totals[row["verdict"]] += 1

    collection_complete = not (
        missing_cases or wrong_target_counts or missing_environments or environment_drift
    )
    fully_evaluable = collection_complete and totals["inconclusive"] == 0

    env_doc = {
        "schema_version": "bpfcompat.research.exact-environments.v1",
        "corpus_version": "v1",
        "profile_source_commit": profile_lock_doc["source_commit"],
        "environments": sorted(
            environments.values(),
            key=lambda x: (x["logical_profile_id"], x["exact_environment_id"]),
        ),
    }
    (out_dir / "exact-environments.json").write_text(
        json.dumps(env_doc, indent=2, sort_keys=True) + "\n"
    )

    with (out_dir / "executions.jsonl").open("w") as f:
        for row in executions:
            f.write(json.dumps(row, sort_keys=True) + "\n")

    summary = {
        "schema_version": "bpfcompat.research.collection-summary.v1",
        "corpus_version": "v1",
        "github_run_id": os.getenv("GITHUB_RUN_ID"),
        "github_sha": os.getenv("GITHUB_SHA"),
        "expected_cases": len(plan["cases"]),
        "expected_profiles_per_case": expected_profiles,
        "expected_execution_attempts": len(plan["cases"]) * expected_profiles,
        "observed_execution_records": len(executions),
        "case_summaries": case_summaries,
        "totals": totals,
        "profile_environment_counts": profile_environment_counts,
        "missing_cases": missing_cases,
        "wrong_target_counts": wrong_target_counts,
        "missing_environments": missing_environments,
        "environment_drift": environment_drift,
        "collection_complete": collection_complete,
        "fully_evaluable": fully_evaluable,
    }
    (out_dir / "collection-summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n"
    )

    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if collection_complete else 3


if __name__ == "__main__":
    sys.exit(main())
