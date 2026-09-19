#!/usr/bin/env python3
"""Verify the committed pilot-v1 repeat-stability snapshot."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
REPEAT = ROOT / "research/repeat/v1"
DATA = REPEAT / "data"
ARTIFACT_PREFIX = "reports/research-repeat-v1/"


def fail(message: str) -> None:
    """Abort verification with a stable, grep-friendly error prefix."""
    raise SystemExit(f"[verify-repeat-snapshot-v1] {message}")


def load_json(path: Path) -> Any:
    """Load UTF-8 JSON from the repository and fail closed on parse/read errors."""
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        try:
            display = path.relative_to(ROOT)
        except ValueError:
            display = path
        fail(f"cannot read {display}: {exc}")


def sha256_bytes(data: bytes) -> str:
    """Return a normalized sha256:<hex> digest for in-memory bytes."""
    return "sha256:" + hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    """Return a normalized sha256:<hex> digest for a file."""
    try:
        return sha256_bytes(path.read_bytes())
    except OSError as exc:
        fail(f"cannot hash {path}: {exc}")


def git_blob_sha1(path: Path) -> str:
    """Return the Git blob SHA-1 for the exact bytes at path."""
    try:
        data = path.read_bytes()
    except OSError as exc:
        fail(f"cannot read Git-blob source {path}: {exc}")
    header = f"blob {len(data)}\0".encode()
    return hashlib.sha1(header + data).hexdigest()


def require_exact_fields(
    mapping: dict[str, Any],
    expected: dict[str, Any],
    label: str,
) -> None:
    """Require every expected field to exist with both matching type and value."""
    for key, value in expected.items():
        if key not in mapping:
            fail(f"{label} missing required field: {key}")
        got = mapping[key]
        if type(got) is not type(value) or got != value:
            fail(f"{label} drift: {key}")


def verify_artifact_member_matches_file(
    archive: zipfile.ZipFile,
    member: str,
    committed: Path,
) -> None:
    """Require an artifact member to be byte-identical to a committed file."""
    try:
        data = archive.read(member)
    except KeyError:
        fail(f"canonical artifact is missing {member}")
    try:
        committed_data = committed.read_bytes()
    except OSError as exc:
        fail(f"cannot read committed evidence {committed}: {exc}")
    if data != committed_data:
        fail(f"artifact/committed evidence mismatch: {member}")


def verify_artifact_zip(
    artifact_zip: Path,
    artifact: dict[str, Any],
    reports: list[dict[str, Any]],
    expected_raw_paths: set[str],
    manifest: dict[str, Any],
) -> None:
    """Verify the pinned artifact archive and bind every raw report to its bytes."""
    if not artifact_zip.is_file():
        fail(f"canonical artifact ZIP is missing: {artifact_zip}")

    expected_digest = artifact.get("sha256")
    if sha256_file(artifact_zip) != expected_digest:
        fail("canonical repeat artifact ZIP SHA-256 mismatch")

    expected_size = artifact.get("size_bytes")
    try:
        actual_size = artifact_zip.stat().st_size
    except OSError as exc:
        fail(f"cannot stat canonical artifact ZIP: {exc}")
    if type(expected_size) is not int or actual_size != expected_size:
        fail("canonical repeat artifact ZIP size mismatch")

    try:
        archive = zipfile.ZipFile(artifact_zip)
    except (OSError, zipfile.BadZipFile) as exc:
        fail(f"cannot open canonical artifact ZIP: {exc}")

    with archive:
        bad_member = archive.testzip()
        if bad_member is not None:
            fail(f"canonical artifact ZIP CRC failure: {bad_member}")

        names = set(archive.namelist())
        expected_members = {ARTIFACT_PREFIX + path for path in expected_raw_paths}
        raw_members = {
            name
            for name in names
            if name.startswith(ARTIFACT_PREFIX + "raw/") and name.endswith(".json")
        }
        if raw_members != expected_members:
            fail("canonical artifact raw-report membership drift")

        for row in reports:
            path = row["path"]
            member = ARTIFACT_PREFIX + path
            try:
                info = archive.getinfo(member)
                data = archive.read(info)
            except KeyError:
                fail(f"canonical artifact is missing raw report: {path}")

            expected_report_size = row["size_bytes"]
            if (
                type(expected_report_size) is not int
                or info.file_size != expected_report_size
                or len(data) != expected_report_size
            ):
                fail(f"raw report size mismatch against artifact: {path}")
            if sha256_bytes(data) != row["sha256"]:
                fail(f"raw report SHA-256 mismatch against artifact: {path}")

        verify_artifact_member_matches_file(
            archive,
            ARTIFACT_PREFIX + "normalized/stability-summary.json",
            DATA / "stability-summary.json",
        )
        verify_artifact_member_matches_file(
            archive,
            ARTIFACT_PREFIX + "repeat-provenance.json",
            DATA / "repeat-provenance.json",
        )
        verify_artifact_member_matches_file(
            archive,
            ARTIFACT_PREFIX + "normalized/RESULTS.md",
            DATA / "RESULTS.md",
        )

        projection_dir = DATA / "projection-metadata"
        for committed in sorted(projection_dir.glob("*.json")):
            verify_artifact_member_matches_file(
                archive,
                ARTIFACT_PREFIX + "manifests/" + committed.name,
                committed,
            )

        artifact_evidence = manifest.get("artifact_evidence") or {}
        repeat_executions_member = (
            ARTIFACT_PREFIX
            + str(artifact_evidence.get("repeat_executions_path") or "")
        )
        try:
            repeat_executions = archive.read(repeat_executions_member)
        except KeyError:
            fail("canonical artifact is missing repeat-executions.jsonl")
        if (
            sha256_bytes(repeat_executions)
            != artifact_evidence.get("repeat_executions_sha256")
        ):
            fail("repeat-executions artifact binding drift")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse verifier CLI arguments."""
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--artifact-zip",
        required=True,
        help="Downloaded canonical repeat Actions artifact ZIP",
    )
    return ap.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    """Verify committed metadata, provenance, projections, and artifact bytes."""
    args = parse_args(argv)
    artifact_zip = Path(args.artifact_zip)

    manifest = load_json(REPEAT / "repeat-dataset-manifest.json")
    summary = load_json(DATA / "stability-summary.json")
    provenance = load_json(DATA / "repeat-provenance.json")
    raw = load_json(DATA / "raw-report-checksums.json")
    sample_path = REPEAT / "stability-sample.json"
    sample = load_json(sample_path)
    pilot_manifest = load_json(ROOT / "research/data/v1/dataset-manifest.json")
    study_plan_path = ROOT / "research/corpus/v1/study-plan.json"
    study_plan = load_json(study_plan_path)
    profile_lock_path = ROOT / "research/corpus/v1/profile-identities.json"
    identity_lock = load_json(ROOT / "research/corpus/v1/materialized-identities.json")
    projection_script = ROOT / "scripts/research/project-repeat-manifest-v1.py"

    if manifest.get("schema_version") != "bpfcompat.research.repeat-dataset-manifest.v1":
        fail("unexpected repeat dataset manifest schema")
    if summary.get("schema_version") != "bpfcompat.research.repeat-summary.v1":
        fail("unexpected stability summary schema")
    if provenance.get("schema_version") != "bpfcompat.research.repeat-provenance.v1":
        fail("unexpected repeat provenance schema")
    if raw.get("schema_version") != "bpfcompat.research.repeat-raw-checksums.v1":
        fail("unexpected raw checksum schema")

    canonical = pilot_manifest.get("canonical_workflow_run") or {}
    expected_canonical = manifest.get("canonical_pilot_run") or {}
    if str(canonical.get("id")) != str(expected_canonical.get("id")):
        fail("canonical pilot run id drift")
    if canonical.get("head_sha") != expected_canonical.get("head_sha"):
        fail("canonical pilot run SHA drift")
    if str(summary.get("canonical_run_id")) != str(expected_canonical.get("id")):
        fail("summary canonical run id drift")
    if summary.get("canonical_run_sha") != expected_canonical.get("head_sha"):
        fail("summary canonical run SHA drift")

    repeat_run = manifest.get("repeat_workflow_run") or {}
    if repeat_run != {
        "id": "35445834557",
        "head_sha": "d2a78e05178ea6dd82ead9684f5eedf49066903f",
        "branch": "main",
        "conclusion": "success",
    }:
        fail("canonical repeat workflow identity drift")

    artifact = manifest.get("actions_artifact") or {}
    if artifact.get("id") != "10584409793":
        fail("canonical repeat artifact id drift")
    if (
        artifact.get("sha256")
        != "sha256:895fd41dae147c592d5cdec91bbd99150f9dd14c35afadf72bc14954a192a0e5"
    ):
        fail("canonical repeat artifact SHA-256 drift")
    if artifact.get("size_bytes") != 455756:
        fail("canonical repeat artifact size drift")

    expected_collection = {
        "planned_tuples": 7,
        "repeats_per_tuple": 3,
        "planned_attempts": 21,
        "observed_attempts": 21,
        "collection_complete": True,
        "stable_same_environment": 21,
        "environment_drift": 0,
        "verdict_instability": 0,
    }
    if manifest.get("collection") != expected_collection:
        fail("repeat dataset collection summary drift")
    require_exact_fields(summary, expected_collection, "stability summary")

    if summary.get("missing") != []:
        fail("repeat summary has missing observations")
    if summary.get("sampling_design") != "purposeful_stratified_post_collection":
        fail("repeat sampling design drift")

    provenance_digest = sha256_file(DATA / "repeat-provenance.json")
    if summary.get("repeat_provenance_sha256") != provenance_digest:
        fail("summary does not bind committed repeat provenance")

    if provenance.get("workflow_source_commit") != repeat_run["head_sha"]:
        fail("repeat provenance source commit drift")
    if provenance.get("sample_sha256") != sha256_file(sample_path):
        fail("repeat sample SHA-256 drift")
    if provenance.get("study_plan_sha256") != sha256_file(study_plan_path):
        fail("study plan SHA-256 drift")
    if provenance.get("profile_lock_sha256") != sha256_file(profile_lock_path):
        fail("profile lock SHA-256 drift")
    if provenance.get("manifest_projection_script_sha256") != sha256_file(
        projection_script
    ):
        fail("repeat projection script SHA-256 drift")

    identities = {
        row["id"]: "sha256:" + str(row["sha256"]).removeprefix("sha256:")
        for row in identity_lock.get("artifacts") or []
    }
    if provenance.get("bpfcompat_cli_sha256") != identities.get("bpfcompat-v037-cli"):
        fail("BPFCompat CLI identity drift")
    if provenance.get("validator_sha256") != identities.get(
        "bpfcompat-v037-validator"
    ):
        fail("validator identity drift")
    loaders = provenance.get("loaders") or {}
    if loaders.get("cilium-ebpf-v022-loader") != identities.get(
        "cilium-ebpf-v022-loader"
    ):
        fail("cilium loader identity drift")
    if loaders.get("falco-modern-bpf-scap-open") != identities.get(
        "falco-modern-bpf-scap-open"
    ):
        fail("Falco loader identity drift")

    tuples = sample.get("tuples") or []
    repeats = int(sample.get("repeats_per_tuple") or 0)
    expected_raw_paths = {
        f"raw/{row['id']}/repeat-{repeat}.json"
        for row in tuples
        for repeat in range(1, repeats + 1)
    }
    reports = raw.get("reports") or []
    observed_raw_paths = {row.get("path") for row in reports}
    if raw.get("count") != 21 or len(reports) != 21:
        fail("raw checksum manifest must contain exactly 21 reports")
    if observed_raw_paths != expected_raw_paths:
        fail("raw checksum paths do not match the frozen repeat sample")
    if len({row.get("sha256") for row in reports}) != 21:
        fail("raw report SHA-256 values must be unique")
    for row in reports:
        digest = str(row.get("sha256") or "")
        if not digest.startswith("sha256:") or len(digest) != 71:
            fail(f"invalid raw report SHA-256: {row!r}")
        if type(row.get("size_bytes")) is not int or row["size_bytes"] <= 0:
            fail(f"invalid raw report size: {row!r}")

    tuple_summaries = summary.get("tuple_summaries") or []
    by_id = {row.get("tuple_id"): row for row in tuple_summaries}
    if set(by_id) != {row["id"] for row in tuples}:
        fail("tuple summary coverage drift")
    for row in tuples:
        got = by_id[row["id"]]
        if got.get("case_id") != row["case_id"] or got.get("profile_id") != row[
            "profile_id"
        ]:
            fail(f"tuple binding drift: {row['id']}")
        if got.get("stratum") != row["stratum"]:
            fail(f"tuple stratum drift: {row['id']}")
        if (
            got.get("planned_repeats") != 3
            or got.get("observed_repeats") != 3
            or got.get("stable_same_environment") != 3
            or got.get("environment_drift") != 0
            or got.get("verdict_instability") != 0
        ):
            fail(f"tuple stability drift: {row['id']}")

    cases = {row["id"]: row for row in study_plan.get("cases") or []}
    libbpf_tuples = [
        row
        for row in tuples
        if cases[row["case_id"]].get("mode") in {"load_only", "load_attach"}
    ]
    projection_dir = DATA / "projection-metadata"
    projection_files = sorted(projection_dir.glob("*.json"))
    if len(projection_files) != len(libbpf_tuples):
        fail("projection metadata count drift")

    for row in libbpf_tuples:
        case = cases[row["case_id"]]
        meta_path = projection_dir / f"{row['id']}.json"
        if not meta_path.is_file():
            fail(f"missing projection metadata: {row['id']}")
        meta = load_json(meta_path)
        source_path = ROOT / case["manifest"]
        if meta.get("schema_version") != "bpfcompat.research.repeat-manifest-projection.v1":
            fail(f"projection schema drift: {row['id']}")
        if meta.get("projection") != "required_profiles_singleton":
            fail(f"projection rule drift: {row['id']}")
        if meta.get("profile_id") != row["profile_id"]:
            fail(f"projection profile drift: {row['id']}")
        if meta.get("source_path") != case["manifest"]:
            fail(f"projection source path drift: {row['id']}")
        if meta.get("source_git_blob") != case["manifest_git_blob"]:
            fail(f"projection source blob binding drift: {row['id']}")
        if git_blob_sha1(source_path) != case["manifest_git_blob"]:
            fail(f"frozen source manifest Git blob drift: {row['id']}")
        if meta.get("source_sha256") != sha256_file(source_path):
            fail(f"projection source SHA-256 drift: {row['id']}")
        if meta.get("projected_required_profiles") != [row["profile_id"]]:
            fail(f"projection singleton profile drift: {row['id']}")
        if row["profile_id"] not in (meta.get("source_required_profiles") or []):
            fail(f"sampled profile absent from frozen manifest metadata: {row['id']}")

        with tempfile.TemporaryDirectory() as tmp:
            projected = Path(tmp) / "manifest.yaml"
            generated_meta = Path(tmp) / "meta.json"
            subprocess.run(
                [
                    sys.executable,
                    str(projection_script),
                    "--source",
                    case["manifest"],
                    "--profile-id",
                    row["profile_id"],
                    "--expected-git-blob",
                    case["manifest_git_blob"],
                    "--out",
                    str(projected),
                    "--metadata-out",
                    str(generated_meta),
                ],
                cwd=ROOT,
                check=True,
                stdout=subprocess.DEVNULL,
            )
            regenerated = load_json(generated_meta)
            if regenerated.get("projected_sha256") != meta.get("projected_sha256"):
                fail(f"projection is not reproducible: {row['id']}")

    verify_artifact_zip(
        artifact_zip,
        artifact,
        reports,
        expected_raw_paths,
        manifest,
    )

    print(
        "[verify-repeat-snapshot-v1] PASS: canonical 21/21 repeat snapshot "
        "and pinned artifact bytes are internally consistent"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
