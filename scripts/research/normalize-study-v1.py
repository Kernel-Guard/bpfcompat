#!/usr/bin/env python3
"""Normalize frozen BPFCompat pilot-v1 reports into fail-closed research records."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any

IMAGE_NOTE = re.compile(r"^base image sha256:\s*([0-9a-fA-F]{64})\s*$")
CLASSIFICATION_NOTE = re.compile(r"^classification:\s*([A-Z0-9_]+)\s*\(([^)]+)\)\s*$")
SHA256_RE = re.compile(r"^(?:sha256:)?([0-9a-fA-F]{64})$")
KERNEL_SERIES_RE = re.compile(r"^(\d+)\.(\d+)")

STATUS_TO_VERDICT = {
    "pass": "COMPATIBLE",
    "fail": "INCOMPATIBLE",
    "partial": "INCOMPATIBLE",
    "infra_error": "INFRA_ERROR",
    "unsupported": "UNSUPPORTED",
}


def sha256_file(path: Path) -> str:
    """Return the SHA-256 identity of a file using the corpus sha256: prefix."""
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return "sha256:" + h.hexdigest()


def canonical_hash(value: Any) -> str:
    """Hash canonical compact JSON so identities do not depend on formatting."""
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def normalize_sha256(value: Any, field: str, *, allow_missing: bool = True) -> str | None:
    """Normalize a SHA-256 string and reject non-empty malformed identities."""
    raw = str(value or "").strip()
    if not raw:
        if allow_missing:
            return None
        raise SystemExit(f"{field}: missing required SHA-256")
    match = SHA256_RE.fullmatch(raw)
    if not match:
        raise SystemExit(f"{field}: malformed SHA-256 value {raw!r}")
    return "sha256:" + match.group(1).lower()


def image_digest(target: dict[str, Any], case_id: str, profile_id: str) -> str | None:
    """Resolve the exact base-image digest from structured evidence or v0.3.7 notes."""
    env = target.get("environment") or {}
    raw = env.get("image_sha256")
    if raw not in (None, ""):
        return normalize_sha256(
            raw, f"{case_id}/{profile_id}: environment.image_sha256"
        )
    for note in target.get("notes") or []:
        text = str(note).strip()
        match = IMAGE_NOTE.match(text)
        if match:
            return "sha256:" + match.group(1).lower()
        if text.lower().startswith("base image sha256:"):
            raise SystemExit(
                f"{case_id}/{profile_id}: malformed base image SHA-256 note {text!r}"
            )
    return None


def classification_from_target(target: dict[str, Any]) -> tuple[str | None, str | None]:
    """Return structured classification fields, falling back to v0.3.7 notes."""
    code = str(target.get("classification_code") or "").strip() or None
    confidence = str(target.get("classification_confidence") or "").strip() or None
    if code:
        return code, confidence
    for note in target.get("notes") or []:
        match = CLASSIFICATION_NOTE.match(str(note))
        if match:
            return match.group(1), match.group(2).lower()
    return None, None


def kernel_series(value: str) -> str | None:
    """Mirror schema.KernelSeries by extracting only a valid MAJOR.MINOR prefix."""
    text = value.strip()
    match = KERNEL_SERIES_RE.match(text)
    if not match:
        return None
    rest = text[match.end() :]
    if rest and rest[0].isalnum():
        return None
    return f"{match.group(1)}.{match.group(2)}"


def validate_status_verdict(
    target: dict[str, Any],
    case_id: str,
    profile_id: str,
    bpf_version: str,
) -> tuple[str, str, str]:
    """Validate status/verdict consistency, deriving v0.3.7's missing verdict."""
    status = str(target.get("status") or "").strip().lower()
    if status not in STATUS_TO_VERDICT:
        raise SystemExit(
            f"{case_id}/{profile_id}: unsupported or missing target status {status!r}"
        )

    expected = STATUS_TO_VERDICT[status]
    raw_verdict = str(target.get("verdict") or "").strip().upper()
    if raw_verdict:
        if raw_verdict != expected:
            raise SystemExit(
                f"{case_id}/{profile_id}: contradictory status/verdict: "
                f"{status!r} requires {expected!r}, got {raw_verdict!r}"
            )
        return status, raw_verdict, "report"

    # The frozen v0.3.7 ReportV01 schema has status but no verdict field.
    if bpf_version != "v0.3.7":
        raise SystemExit(
            f"{case_id}/{profile_id}: missing target verdict for producer {bpf_version}"
        )
    return status, expected, "derived_from_status_v0.3.7"


def validate_kernel_match(
    env: dict[str, Any],
    requested_family: str,
    observed_kernel: str,
    case_id: str,
    profile_id: str,
) -> tuple[bool | None, str]:
    """Validate a reported kernel match or derive it from immutable report fields."""
    requested_series = kernel_series(requested_family)
    observed_series = kernel_series(observed_kernel)
    derived = (
        requested_series == observed_series
        if requested_series is not None and observed_series is not None
        else None
    )

    raw = env.get("kernel_family_match")
    if raw is None:
        return derived, "derived_from_profile_and_host" if derived is not None else "unknown"
    if not isinstance(raw, bool):
        raise SystemExit(
            f"{case_id}/{profile_id}: kernel_family_match must be boolean or null"
        )
    if derived is None:
        raise SystemExit(
            f"{case_id}/{profile_id}: kernel_family_match is recorded but "
            "requested/observed kernel series is not derivable"
        )
    if raw != derived:
        raise SystemExit(
            f"{case_id}/{profile_id}: kernel_family_match={raw} contradicts "
            f"requested {requested_family!r} and observed {observed_kernel!r}"
        )
    return raw, "report"


def verdict_for(
    status: str,
    kernel_match: bool | None,
    environment_identified: bool,
) -> tuple[str, str | None]:
    """Map validated evidence into the research verdict taxonomy."""
    if status == "infra_error":
        return "inconclusive", "infrastructure_error"
    if status == "unsupported":
        return "inconclusive", "unsupported_execution_path"
    if kernel_match is False:
        return "inconclusive", "environment_unavailable"
    if kernel_match is not True or not environment_identified:
        return "inconclusive", "evidence_unavailable"
    if status == "pass":
        return "compatible", None
    if status in {"fail", "partial"}:
        return "incompatible", None
    raise AssertionError(f"validated status escaped taxonomy: {status}")


def unique_index(items: list[dict[str, Any]], key: str, label: str) -> dict[str, dict[str, Any]]:
    """Build a unique keyed index and reject missing or duplicate identities."""
    result: dict[str, dict[str, Any]] = {}
    for item in items:
        item_id = str(item.get(key) or "").strip()
        if not item_id:
            raise SystemExit(f"{label}: entry missing {key}")
        if item_id in result:
            raise SystemExit(f"{label}: duplicate {key} {item_id!r}")
        result[item_id] = item
    return result


def load_execution_provenance(path: Path, artifact_hashes: dict[str, str]) -> tuple[dict[str, Any], str]:
    """Validate execution-time tool identities that v0.3.7 reports do not embed."""
    if not path.is_file():
        raise SystemExit(f"missing execution provenance: {path}")
    provenance = json.loads(path.read_text())
    if provenance.get("schema_version") != "bpfcompat.research.execution-provenance.v1":
        raise SystemExit("unsupported execution provenance schema")

    cli_sha = normalize_sha256(
        (provenance.get("bpfcompat_cli") or {}).get("sha256"),
        "execution provenance bpfcompat_cli.sha256",
        allow_missing=False,
    )
    validator_sha = normalize_sha256(
        (provenance.get("validator") or {}).get("sha256"),
        "execution provenance validator.sha256",
        allow_missing=False,
    )
    if cli_sha != artifact_hashes["bpfcompat-v037-cli"]:
        raise SystemExit("execution provenance BPFCompat CLI identity drift")
    if validator_sha != artifact_hashes["bpfcompat-v037-validator"]:
        raise SystemExit("execution provenance validator identity drift")

    loaders = provenance.get("loaders")
    if not isinstance(loaders, dict):
        raise SystemExit("execution provenance loaders must be an object")
    for loader_id in ("cilium-ebpf-v022-loader", "falco-modern-bpf-scap-open"):
        entry = loaders.get(loader_id) or {}
        observed = normalize_sha256(
            entry.get("sha256"),
            f"execution provenance loader {loader_id}",
            allow_missing=False,
        )
        if observed != artifact_hashes[loader_id]:
            raise SystemExit(
                f"execution provenance loader identity drift for {loader_id}"
            )
    return provenance, sha256_file(path)


def main() -> int:
    """Normalize one frozen study collection and return non-zero if incomplete."""
    ap = argparse.ArgumentParser()
    ap.add_argument("--reports-dir", required=True)
    ap.add_argument("--study-plan", default="research/corpus/v1/study-plan.json")
    ap.add_argument("--profile-lock", default="research/corpus/v1/profile-identities.json")
    ap.add_argument(
        "--identity-lock", default="research/corpus/v1/materialized-identities.json"
    )
    ap.add_argument("--execution-provenance")
    ap.add_argument("--out-dir", required=True)
    args = ap.parse_args()

    reports_dir = Path(args.reports_dir)
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    plan = json.loads(Path(args.study_plan).read_text())
    profile_lock_doc = json.loads(Path(args.profile_lock).read_text())
    identity_lock = json.loads(Path(args.identity_lock).read_text())

    raw_profiles = profile_lock_doc.get("profiles")
    if not isinstance(raw_profiles, list) or not raw_profiles:
        raise SystemExit("profile lock must contain a non-empty profiles array")
    profile_items = unique_index(raw_profiles, "id", "profile lock")
    profile_locks = {
        profile_id: {
            "path": item["path"],
            "profile_revision": "git-blob:" + str(item["git_blob"]),
        }
        for profile_id, item in profile_items.items()
    }
    expected_profile_ids = set(profile_locks)

    try:
        expected_profiles = int(plan["expected_profiles"])
    except (KeyError, TypeError, ValueError) as exc:
        raise SystemExit("study plan expected_profiles must be a positive integer") from exc
    if expected_profiles <= 0 or expected_profiles != len(expected_profile_ids):
        raise SystemExit(
            "study plan expected_profiles does not equal the unique profile-lock count: "
            f"plan={expected_profiles} lock={len(expected_profile_ids)}"
        )

    raw_cases = plan.get("cases")
    if not isinstance(raw_cases, list) or not raw_cases:
        raise SystemExit("study plan must contain a non-empty cases array")
    case_index = unique_index(raw_cases, "id", "study plan")

    raw_artifacts = identity_lock.get("artifacts")
    if not isinstance(raw_artifacts, list) or not raw_artifacts:
        raise SystemExit("materialized identity lock contains no artifacts")
    artifact_index = unique_index(raw_artifacts, "id", "materialized identity lock")
    artifact_hashes = {
        artifact_id: normalize_sha256(
            item.get("sha256"),
            f"materialized identity {artifact_id}",
            allow_missing=False,
        )
        for artifact_id, item in artifact_index.items()
    }

    bpf_version = str((plan.get("bpfcompat") or {}).get("version") or "").strip()
    bpf_commit = str((plan.get("bpfcompat") or {}).get("commit") or "").strip()
    if not bpf_version or not bpf_commit:
        raise SystemExit("study plan is missing BPFCompat version/commit identity")

    provenance_path = (
        Path(args.execution_provenance)
        if args.execution_provenance
        else reports_dir / "execution-provenance.json"
    )
    provenance, provenance_hash = load_execution_provenance(
        provenance_path, artifact_hashes
    )

    environments: dict[str, dict[str, Any]] = {}
    profile_to_env_ids: dict[str, set[str]] = {p: set() for p in expected_profile_ids}
    executions: list[dict[str, Any]] = []
    case_summaries: list[dict[str, Any]] = []
    missing_cases: list[str] = []
    invalid_profile_sets: list[str] = []

    for case_id, case in case_index.items():
        report_path = reports_dir / f"{case_id}.json"
        if not report_path.is_file():
            missing_cases.append(case_id)
            case_summaries.append(
                {
                    "case_id": case_id,
                    "report": None,
                    "targets": 0,
                    "profile_set_valid": False,
                    "missing_profile_ids": sorted(expected_profile_ids),
                    "duplicate_profile_ids": [],
                }
            )
            continue

        report = json.loads(report_path.read_text())
        if report.get("schema_version") != "v0.1":
            raise SystemExit(
                f"{case_id}: unsupported report schema {report.get('schema_version')!r}"
            )

        report_hash = sha256_file(report_path)
        targets = report.get("targets")
        if not isinstance(targets, list):
            raise SystemExit(f"{case_id}: report targets must be an array")

        raw_artifact = report.get("artifact") or {}
        artifact_id = str(case.get("artifact_id") or "").strip()
        if artifact_id not in artifact_hashes:
            raise SystemExit(f"{case_id}: unknown frozen artifact_id {artifact_id!r}")

        if case.get("artifact_path"):
            expected_artifact = artifact_hashes[artifact_id]
            observed_artifact = normalize_sha256(
                raw_artifact.get("sha256"),
                f"{case_id}: report artifact.sha256",
                allow_missing=False,
            )
            if observed_artifact != expected_artifact:
                raise SystemExit(
                    f"{case_id}: artifact digest mismatch: expected {expected_artifact}, "
                    f"got {observed_artifact}"
                )

        if case.get("mode") == "command":
            loader_id = str(case.get("command_binary_artifact_id") or "").strip()
            if loader_id not in artifact_hashes:
                raise SystemExit(
                    f"{case_id}: command case lacks a frozen loader identity binding"
                )
            loader_entry = (provenance.get("loaders") or {}).get(loader_id) or {}
            observed_loader = normalize_sha256(
                loader_entry.get("sha256"),
                f"{case_id}: execution provenance loader {loader_id}",
                allow_missing=False,
            )
            if observed_loader != artifact_hashes[loader_id]:
                raise SystemExit(
                    f"{case_id}: command loader digest mismatch: expected "
                    f"{artifact_hashes[loader_id]}, got {observed_loader}"
                )
        else:
            # v0.3.7 ReportV01 does not embed validator provenance. The runner
            # records the actual binary hash before execution and the normalizer
            # validates it against the frozen materialized identity above.
            validator_obj = report.get("validator")
            if isinstance(validator_obj, dict) and validator_obj.get("sha256"):
                reported_validator = normalize_sha256(
                    validator_obj.get("sha256"),
                    f"{case_id}: report validator.sha256",
                    allow_missing=False,
                )
                if reported_validator != artifact_hashes["bpfcompat-v037-validator"]:
                    raise SystemExit(
                        f"{case_id}: report validator identity contradicts execution provenance"
                    )

        base_contract = str(case.get("base_validation_contract_id") or "").strip()
        if not SHA256_RE.fullmatch(base_contract):
            raise SystemExit(f"{case_id}: malformed base validation contract identity")

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
            validation_contract_id = normalize_sha256(
                base_contract,
                f"{case_id}: base validation contract",
                allow_missing=False,
            )

        case_profile_ids = [str(t.get("profile_id") or "").strip() for t in targets]
        unexpected = sorted(set(case_profile_ids) - expected_profile_ids)
        if unexpected:
            raise SystemExit(
                f"{case_id}: unexpected profile ids in report: {unexpected}"
            )
        if any(not p for p in case_profile_ids):
            raise SystemExit(f"{case_id}: report contains an empty profile_id")

        profile_counts = Counter(case_profile_ids)
        duplicate_profile_ids = sorted(
            profile_id for profile_id, count in profile_counts.items() if count > 1
        )
        missing_profile_ids = sorted(expected_profile_ids - set(case_profile_ids))
        profile_set_valid = not duplicate_profile_ids and not missing_profile_ids
        if not profile_set_valid:
            invalid_profile_sets.append(case_id)

        case_counts = {"compatible": 0, "incompatible": 0, "inconclusive": 0}

        for target in targets:
            profile_id = str(target.get("profile_id") or "").strip()
            status, producer_verdict, verdict_source = validate_status_verdict(
                target, case_id, profile_id, bpf_version
            )

            env = target.get("environment") or {}
            if not isinstance(env, dict):
                raise SystemExit(f"{case_id}/{profile_id}: environment must be an object")
            profile = target.get("profile") or {}
            host = target.get("host") or {}
            if not isinstance(profile, dict) or not isinstance(host, dict):
                raise SystemExit(
                    f"{case_id}/{profile_id}: profile and host must be objects"
                )

            observed_kernel = str(
                env.get("observed_kernel") or host.get("kernel") or ""
            ).strip()
            requested_family = str(
                env.get("requested_kernel_family")
                or profile.get("kernel_family")
                or ""
            ).strip()
            arch = str(profile.get("arch") or host.get("arch") or "").strip()
            distro = str(profile.get("distro") or "").strip()
            distro_release = str(profile.get("version") or "").strip()
            image_source = str(env.get("image_source_url") or "").strip()
            img_sha = image_digest(target, case_id, profile_id)
            profile_revision = profile_locks[profile_id]["profile_revision"]

            kernel_match, kernel_match_source = validate_kernel_match(
                env,
                requested_family,
                observed_kernel,
                case_id,
                profile_id,
            )

            environment_identified = bool(
                kernel_match is not None
                and observed_kernel
                and img_sha
                and requested_family
                and arch
                and distro
                and distro_release
                and profile_revision
            )

            exact_environment_id: str | None = None
            if environment_identified:
                env_record = {
                    "logical_profile_id": profile_id,
                    "distribution": distro,
                    "distribution_release": distro_release,
                    "architecture": arch,
                    "requested_kernel_family": requested_family,
                    "observed_kernel_release": observed_kernel,
                    "image_source": image_source,
                    "image_identity": img_sha,
                    "profile_revision": profile_revision,
                    "kernel_family_match": kernel_match,
                }
                exact_environment_id = canonical_hash(env_record)
                env_record["exact_environment_id"] = exact_environment_id
                environments.setdefault(exact_environment_id, env_record)
                profile_to_env_ids[profile_id].add(exact_environment_id)

            verdict, inconclusive_reason = verdict_for(
                status, kernel_match, environment_identified
            )
            case_counts[verdict] += 1

            classification, classification_confidence = classification_from_target(target)
            if verdict == "incompatible" and not classification:
                classification = "unknown"
            if verdict != "incompatible":
                classification = None
                classification_confidence = None

            executions.append(
                {
                    "dataset_version": "v1",
                    "case_id": case_id,
                    "run_id": (report.get("run") or {}).get("id"),
                    "timestamp_utc": (report.get("run") or {}).get("started_at"),
                    "bpfcompat_version": bpf_version,
                    "bpfcompat_commit": bpf_commit,
                    "workflow_source_commit": provenance.get("workflow_source_commit"),
                    "execution_provenance_sha256": provenance_hash,
                    "artifact_id": artifact_id,
                    "artifact_sha256": artifact_hashes.get(artifact_id),
                    "environment_id": exact_environment_id,
                    "logical_profile_id": profile_id,
                    "observed_kernel_release": observed_kernel or None,
                    "architecture": arch or None,
                    "kernel_family_match": kernel_match,
                    "kernel_family_match_source": kernel_match_source,
                    "validation_contract_id": validation_contract_id,
                    "base_validation_contract_id": base_contract,
                    "manifest_sha256": manifest_sha,
                    "validation_mode": case["mode"],
                    "verdict": verdict,
                    "classification_code": classification,
                    "inconclusive_reason": inconclusive_reason,
                    "target_status": status,
                    "target_verdict": producer_verdict,
                    "target_verdict_source": verdict_source,
                    "raw_report_sha256": report_hash,
                    "evidence_path": str(report_path),
                    "classification_confidence": classification_confidence,
                    "failed_stage": target.get("failed_stage"),
                }
            )

        case_summaries.append(
            {
                "case_id": case_id,
                "report": str(report_path),
                "targets": len(targets),
                "profile_set_valid": profile_set_valid,
                "missing_profile_ids": missing_profile_ids,
                "duplicate_profile_ids": duplicate_profile_ids,
                **case_counts,
            }
        )

    profile_environment_counts = {
        profile_id: len(ids) for profile_id, ids in sorted(profile_to_env_ids.items())
    }
    missing_environments = [
        profile_id
        for profile_id, count in profile_environment_counts.items()
        if count == 0
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

    expected_attempts = len(case_index) * expected_profiles
    collection_complete = not (
        missing_cases
        or wrong_target_counts
        or invalid_profile_sets
        or missing_environments
        or environment_drift
        or len(executions) != expected_attempts
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
        "execution_provenance_sha256": provenance_hash,
        "expected_cases": len(case_index),
        "expected_profiles_per_case": expected_profiles,
        "expected_execution_attempts": expected_attempts,
        "observed_execution_records": len(executions),
        "case_summaries": case_summaries,
        "totals": totals,
        "profile_environment_counts": profile_environment_counts,
        "missing_cases": missing_cases,
        "wrong_target_counts": wrong_target_counts,
        "invalid_profile_sets": sorted(invalid_profile_sets),
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
