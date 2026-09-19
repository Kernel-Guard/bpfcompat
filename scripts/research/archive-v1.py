#!/usr/bin/env python3
"""Build and verify the fail-closed pilot-v1 scholarly archive payload."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
PLAN_PATH = ROOT / "research/archive/v1/archive-plan.json"
IDENTITIES_PATH = ROOT / "research/corpus/v1/materialized-identities.json"
MANIFEST_NAME = "archive-manifest.json"
PAYLOAD_ZIP_NAME = "bpfcompat-research-v1-payload.zip"
CHECKSUMS_NAME = "RELEASE-CHECKSUMS.txt"
LOCK_NAME = "archive-lock.json"
FIXED_ZIP_TIME = (1980, 1, 1, 0, 0, 0)


def fail(message: str) -> None:
    """Abort with a stable verifier prefix."""
    raise SystemExit(f"[archive-v1] {message}")


def load_json(path: Path) -> Any:
    """Load UTF-8 JSON and fail closed."""
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        fail(f"cannot read JSON {path}: {exc}")


def sha256_bytes(data: bytes) -> str:
    """Return a normalized sha256:<hex> digest."""
    return "sha256:" + hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    """Return a normalized sha256:<hex> digest for a file."""
    try:
        return sha256_bytes(path.read_bytes())
    except OSError as exc:
        fail(f"cannot hash {path}: {exc}")


def safe_member(name: str) -> str:
    """Validate and normalize an archive member name."""
    p = PurePosixPath(name)
    if not name or name.endswith("/"):
        return name
    if p.is_absolute() or ".." in p.parts or "." in p.parts:
        fail(f"unsafe archive member path: {name}")
    normalized = p.as_posix()
    if normalized != name:
        fail(f"non-canonical archive member path: {name}")
    return normalized


def verify_source_zip(path: Path, spec: dict[str, Any], label: str) -> zipfile.ZipFile:
    """Verify a pinned Actions artifact ZIP before reading any member."""
    if not path.is_file():
        fail(f"{label} ZIP missing: {path}")
    if path.stat().st_size != spec["size_bytes"]:
        fail(f"{label} ZIP size mismatch")
    if sha256_file(path) != spec["sha256"]:
        fail(f"{label} ZIP SHA-256 mismatch")
    try:
        archive = zipfile.ZipFile(path)
    except (OSError, zipfile.BadZipFile) as exc:
        fail(f"cannot open {label} ZIP: {exc}")
    names = archive.namelist()
    if len(names) != len(set(names)):
        archive.close()
        fail(f"{label} ZIP contains duplicate member names")
    for name in names:
        safe_member(name)
    bad = archive.testzip()
    if bad is not None:
        archive.close()
        fail(f"{label} ZIP CRC failure: {bad}")
    return archive


def git_blob_sha(path: str) -> str:
    """Return the Git blob identity for one tracked repository path."""
    try:
        blob = subprocess.check_output(
            ["git", "rev-parse", f"HEAD:{path}"], cwd=ROOT, text=True
        ).strip()
    except (OSError, subprocess.CalledProcessError) as exc:
        fail(f"cannot resolve Git blob for {path}: {exc}")
    if len(blob) != 40:
        fail(f"unexpected Git blob identity for {path}: {blob}")
    return blob


def git_tracked_files() -> list[str]:
    """Return all tracked repository paths in deterministic order."""
    try:
        raw = subprocess.check_output(["git", "ls-files", "-z"], cwd=ROOT)
    except (OSError, subprocess.CalledProcessError) as exc:
        fail(f"cannot enumerate tracked repository files: {exc}")
    paths = [item.decode("utf-8") for item in raw.split(b"\0") if item]
    return sorted(paths)


def selected_repository_paths(plan: dict[str, Any]) -> list[str]:
    """Select the reproducibility slice copied into the data payload."""
    cfg = plan["repository_payload"]
    exact = set(cfg["exact_paths"])
    prefixes = tuple(cfg["prefixes"])
    excluded_exact = set(cfg["exclude_exact_paths"])
    excluded_prefixes = tuple(cfg["exclude_prefixes"])
    selected: list[str] = []
    for path in git_tracked_files():
        if path in excluded_exact or path.startswith(excluded_prefixes):
            continue
        if path in exact or path.startswith(prefixes):
            selected.append(path)
    for required in exact:
        if required not in selected:
            fail(f"required repository payload file missing: {required}")
    for third_party_path in cfg["third_party_derived"]:
        if third_party_path not in selected:
            fail(f"third-party repository payload file missing: {third_party_path}")
    return selected


def copy_bytes(payload: Path, archive_path: str, data: bytes) -> None:
    """Write one payload file after validating its relative path."""
    safe_member(archive_path)
    target = payload / PurePosixPath(archive_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(data)


def manifest_row(
    archive_path: str,
    data: bytes,
    provenance_class: str,
    owner_upstream: str,
    source_revision: str,
    redistribution_status: str,
    license_notice_paths: list[str],
    source_layer: str,
    source_member: str,
) -> dict[str, Any]:
    """Create one canonical archive-manifest row."""
    return {
        "path": archive_path,
        "sha256": sha256_bytes(data),
        "size_bytes": len(data),
        "provenance_class": provenance_class,
        "owner_upstream": owner_upstream,
        "source_revision": source_revision,
        "redistribution_status": redistribution_status,
        "license_notice_paths": sorted(license_notice_paths),
        "source_layer": source_layer,
        "source_member": source_member,
    }


def add_repository_files(
    payload: Path,
    plan: dict[str, Any],
    rows: list[dict[str, Any]],
) -> None:
    """Copy the committed research reproducibility slice into the payload."""
    third_party = plan["repository_payload"]["third_party_derived"]
    for rel in selected_repository_paths(plan):
        path = ROOT / rel
        data = path.read_bytes()
        archive_path = f"repository/{rel}"
        if rel in third_party:
            cfg = third_party[rel]
            provenance = "third-party-derived"
            owner = cfg["owner_upstream"]
            revision = cfg["source_revision"]
            status = cfg["status"]
            notices = cfg["license_notice_paths"]
        else:
            provenance = "bpfcompat-owned"
            owner = "Kernel-Guard/bpfcompat"
            revision = f"git-blob:{git_blob_sha(rel)}"
            status = "include"
            notices = []
        copy_bytes(payload, archive_path, data)
        rows.append(
            manifest_row(
                archive_path,
                data,
                provenance,
                owner,
                revision,
                status,
                notices,
                "repository",
                rel,
            )
        )


def add_evidence_files(
    payload: Path,
    archive: zipfile.ZipFile,
    spec: dict[str, Any],
    label: str,
    rows: list[dict[str, Any]],
) -> None:
    """Copy canonical execution evidence selected by frozen prefixes."""
    prefixes = tuple(spec["include_member_prefixes"])
    selected = [
        name
        for name in archive.namelist()
        if not name.endswith("/") and name.startswith(prefixes)
    ]
    if not selected:
        fail(f"{label} evidence selection is empty")
    for member in sorted(selected):
        data = archive.read(member)
        archive_path = f"evidence/{label}/{member}"
        copy_bytes(payload, archive_path, data)
        rows.append(
            manifest_row(
                archive_path,
                data,
                "bpfcompat-owned",
                "Kernel-Guard/bpfcompat",
                spec["head_sha"],
                "include",
                [],
                f"actions-artifact:{label}",
                member,
            )
        )


def bpfcompat_materialization_revision(
    member: str,
    identities: dict[str, Any],
    materialization_head: str,
) -> str:
    """Resolve the most specific frozen BPFCompat source revision for a member."""
    revisions = identities["source_revisions"]
    if member.startswith("bin/"):
        return revisions["bpfcompat_execution"]
    if member.startswith("artifacts/"):
        return revisions["bpfcompat_selection_source"]
    return materialization_head


def add_materialization_files(
    payload: Path,
    archive: zipfile.ZipFile,
    plan: dict[str, Any],
    identities: dict[str, Any],
    rows: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Apply the fail-closed materialization redistribution policy."""
    policy = plan["materialization_policy"]
    source = plan["artifact_sources"]["materialization"]
    owned_exact = set(policy["bpfcompat_owned_exact"])
    owned_prefixes = tuple(policy["bpfcompat_owned_prefixes"])
    third_party = {
        row["path"]: row for row in policy["third_party_include_with_notice"]
    }
    excluded = {row["path"]: row for row in policy["excluded_rebuildable"]}

    classified: set[str] = set()
    for member in sorted(name for name in archive.namelist() if not name.endswith("/")):
        data = archive.read(member)
        if member in excluded:
            cfg = excluded[member]
            if sha256_bytes(data) != cfg["sha256"]:
                fail(f"excluded rebuildable identity drift: {member}")
            classified.add(member)
            continue

        if member in third_party:
            cfg = third_party[member]
            if cfg.get("sha256") and sha256_bytes(data) != cfg["sha256"]:
                fail(f"third-party materialization identity drift: {member}")
            provenance = (
                "third-party-license-notice"
                if member.startswith("licenses/")
                else "third-party-derived"
            )
            owner = cfg["owner_upstream"]
            revision = cfg["source_revision"]
            status = "include-with-notice"
            notices = cfg["license_notice_paths"]
        elif member in owned_exact or member.startswith(owned_prefixes):
            provenance = "bpfcompat-owned"
            owner = "Kernel-Guard/bpfcompat"
            revision = bpfcompat_materialization_revision(
                member, identities, source["head_sha"]
            )
            status = "include"
            notices = []
        else:
            fail(f"unclassified materialization member: {member}")

        archive_path = f"materialized/{member}"
        copy_bytes(payload, archive_path, data)
        rows.append(
            manifest_row(
                archive_path,
                data,
                provenance,
                owner,
                revision,
                status,
                notices,
                "actions-artifact:materialization",
                member,
            )
        )
        classified.add(member)

    all_members = {
        name for name in archive.namelist() if not name.endswith("/")
    }
    if classified != all_members:
        fail("materialization classification coverage drift")

    excluded_rows: list[dict[str, Any]] = []
    for member, cfg in sorted(excluded.items()):
        excluded_rows.append(
            {
                "path": f"materialized/{member}",
                "source_member": member,
                "sha256": cfg["sha256"],
                "provenance_class": "third-party-derived",
                "owner_upstream": cfg["owner_upstream"],
                "source_revision": cfg["source_revision"],
                "redistribution_status": "exclude-rebuildable",
                "license_notice_paths": sorted(cfg["license_notice_paths"]),
                "validation_contract_id": cfg["validation_contract_id"],
                "source_layer": "actions-artifact:materialization",
            }
        )
    return excluded_rows


def validate_rows(
    payload: Path,
    rows: list[dict[str, Any]],
    excluded_rows: list[dict[str, Any]],
) -> None:
    """Enforce the archival redistribution policy against payload bytes."""
    if len({row["path"] for row in rows}) != len(rows):
        fail("duplicate payload manifest paths")

    actual_files = sorted(
        path.relative_to(payload).as_posix()
        for path in payload.rglob("*")
        if path.is_file()
    )
    manifest_files = sorted(row["path"] for row in rows)
    if actual_files != manifest_files:
        fail("payload/manifest file-set mismatch")

    available = set(actual_files)
    for row in rows:
        path = payload / PurePosixPath(row["path"])
        if path.stat().st_size != row["size_bytes"]:
            fail(f"payload size drift: {row['path']}")
        if sha256_file(path) != row["sha256"]:
            fail(f"payload SHA-256 drift: {row['path']}")

        provenance = row["provenance_class"]
        status = row["redistribution_status"]
        if provenance == "bpfcompat-owned":
            if status != "include":
                fail(f"BPFCompat-owned row must use include: {row['path']}")
        else:
            if status == "include":
                fail(f"third-party row cannot use plain include: {row['path']}")
            if status != "include-with-notice":
                fail(f"included third-party row must use include-with-notice: {row['path']}")
            notices = row["license_notice_paths"]
            if not notices:
                fail(f"third-party row lacks notice path: {row['path']}")
            for notice in notices:
                if notice not in available:
                    fail(
                        f"third-party notice path missing from payload: "
                        f"{row['path']} -> {notice}"
                    )

    for row in excluded_rows:
        if row["redistribution_status"] != "exclude-rebuildable":
            fail(f"excluded row has invalid status: {row['path']}")
        if row["path"] in available:
            fail(f"excluded rebuildable unexpectedly present in payload: {row['path']}")
        if not row["license_notice_paths"]:
            fail(f"excluded rebuildable lacks retained notice paths: {row['path']}")
        for notice in row["license_notice_paths"]:
            if notice not in available:
                fail(
                    f"excluded rebuildable notice missing from payload: "
                    f"{row['path']} -> {notice}"
                )


def write_manifest(
    out_dir: Path,
    plan: dict[str, Any],
    rows: list[dict[str, Any]],
    excluded_rows: list[dict[str, Any]],
) -> Path:
    """Write the machine-readable archival manifest."""
    payload = out_dir / "payload"
    rows = sorted(rows, key=lambda row: row["path"])
    excluded_rows = sorted(excluded_rows, key=lambda row: row["path"])
    manifest = {
        "schema_version": "bpfcompat.research.archive-manifest.v1",
        "archive_version": plan["archive_version"],
        "repository_payload_identity": "per-file Git blob plus SHA-256; full source tree bound later by immutable research release tag",
        "scope": plan["scope"],
        "artifact_sources": plan["artifact_sources"],
        "payload": {
            "file_count": len(rows),
            "total_bytes": sum(row["size_bytes"] for row in rows),
            "files": rows,
        },
        "excluded_rebuildable": excluded_rows,
        "release_binding": {
            "full_source_tree": "must be supplied by the immutable research release tag",
            "doi": "must be added only after deposit",
        },
    }
    path = out_dir / MANIFEST_NAME
    path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    validate_rows(payload, rows, excluded_rows)
    return path


def write_deterministic_zip(payload: Path, target: Path) -> None:
    """Create a deterministic ZIP containing exactly the manifest payload files."""
    with zipfile.ZipFile(target, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        for path in sorted(p for p in payload.rglob("*") if p.is_file()):
            rel = path.relative_to(payload).as_posix()
            info = zipfile.ZipInfo(rel, date_time=FIXED_ZIP_TIME)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            info.create_system = 3
            zf.writestr(info, path.read_bytes())


def verify_payload_zip(payload: Path, target: Path) -> None:
    """Require the deterministic payload ZIP to match the payload byte-for-byte."""
    if not target.is_file():
        fail(f"payload ZIP missing: {target}")
    with zipfile.ZipFile(target) as zf:
        names = zf.namelist()
        if len(names) != len(set(names)):
            fail("payload ZIP contains duplicate member names")
        actual = sorted(
            path.relative_to(payload).as_posix()
            for path in payload.rglob("*")
            if path.is_file()
        )
        if sorted(names) != actual:
            fail("payload ZIP file-set mismatch")
        for name in names:
            safe_member(name)
            data = zf.read(name)
            if data != (payload / PurePosixPath(name)).read_bytes():
                fail(f"payload ZIP byte mismatch: {name}")


def archive_lock_document(
    out_dir: Path,
    plan: dict[str, Any],
    rows: list[dict[str, Any]],
    excluded_rows: list[dict[str, Any]],
) -> dict[str, Any]:
    """Return the compact lock document for generated release files."""
    manifest = out_dir / MANIFEST_NAME
    payload_zip = out_dir / PAYLOAD_ZIP_NAME
    return {
        "schema_version": "bpfcompat.research.archive-lock.v1",
        "archive_version": plan["archive_version"],
        "manifest": {
            "sha256": sha256_file(manifest),
            "file_count": len(rows),
            "total_bytes": sum(row["size_bytes"] for row in rows),
        },
        "payload_zip": {
            "sha256": sha256_file(payload_zip),
            "size_bytes": payload_zip.stat().st_size,
        },
        "artifact_sources": {
            key: {
                "artifact_id": value["artifact_id"],
                "sha256": value["sha256"],
                "size_bytes": value["size_bytes"],
            }
            for key, value in sorted(plan["artifact_sources"].items())
        },
        "excluded_rebuildable": [
            {
                "path": row["path"],
                "sha256": row["sha256"],
                "validation_contract_id": row["validation_contract_id"],
            }
            for row in sorted(excluded_rows, key=lambda item: item["path"])
        ],
    }


def write_archive_lock(
    out_dir: Path,
    plan: dict[str, Any],
    rows: list[dict[str, Any]],
    excluded_rows: list[dict[str, Any]],
) -> Path:
    """Write a compact repository lock for the generated release manifest."""
    path = out_dir / LOCK_NAME
    path.write_text(
        json.dumps(
            archive_lock_document(out_dir, plan, rows, excluded_rows),
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
        newline="\n",
    )
    return path


def verify_archive_lock(
    out_dir: Path,
    plan: dict[str, Any],
    rows: list[dict[str, Any]],
    excluded_rows: list[dict[str, Any]],
) -> None:
    """Verify the compact lock exactly matches the generated release files."""
    actual = load_json(out_dir / LOCK_NAME)
    expected = archive_lock_document(out_dir, plan, rows, excluded_rows)
    if actual != expected:
        fail("archive lock drift")

def write_release_checksums(out_dir: Path) -> None:
    """Bind the manifest, compact lock, and deterministic payload ZIP."""
    names = [MANIFEST_NAME, LOCK_NAME, PAYLOAD_ZIP_NAME]
    text = "".join(
        f"{sha256_file(out_dir / name).removeprefix('sha256:')}  {name}\n"
        for name in names
    )
    (out_dir / CHECKSUMS_NAME).write_text(text, encoding="utf-8", newline="\n")


def verify_release_checksums(out_dir: Path) -> None:
    """Verify the release-level checksum file exactly."""
    names = [MANIFEST_NAME, LOCK_NAME, PAYLOAD_ZIP_NAME]
    expected = "".join(
        f"{sha256_file(out_dir / name).removeprefix('sha256:')}  {name}\n"
        for name in names
    )
    actual = (out_dir / CHECKSUMS_NAME).read_text(encoding="utf-8")
    if actual != expected:
        fail("release checksum file drift")


def build(args: argparse.Namespace) -> int:
    """Build and immediately verify the complete archival bundle."""
    plan = load_json(PLAN_PATH)
    identities = load_json(IDENTITIES_PATH)
    if plan.get("schema_version") != "bpfcompat.research.archive-plan.v1":
        fail("unexpected archive-plan schema")

    out_dir = Path(args.out_dir).resolve()
    if out_dir.exists():
        shutil.rmtree(out_dir)
    payload = out_dir / "payload"
    payload.mkdir(parents=True)

    pilot = verify_source_zip(
        Path(args.pilot_zip), plan["artifact_sources"]["pilot"], "pilot"
    )
    repeat = verify_source_zip(
        Path(args.repeat_zip), plan["artifact_sources"]["repeat"], "repeat"
    )
    materialization = verify_source_zip(
        Path(args.materialization_zip),
        plan["artifact_sources"]["materialization"],
        "materialization",
    )

    rows: list[dict[str, Any]] = []
    try:
        add_repository_files(payload, plan, rows)
        add_evidence_files(
            payload, pilot, plan["artifact_sources"]["pilot"], "pilot", rows
        )
        add_evidence_files(
            payload, repeat, plan["artifact_sources"]["repeat"], "repeat", rows
        )
        excluded = add_materialization_files(
            payload, materialization, plan, identities, rows
        )
    finally:
        pilot.close()
        repeat.close()
        materialization.close()

    manifest = write_manifest(out_dir, plan, rows, excluded)
    payload_zip = out_dir / PAYLOAD_ZIP_NAME
    write_deterministic_zip(payload, payload_zip)
    verify_payload_zip(payload, payload_zip)
    write_archive_lock(out_dir, plan, rows, excluded)
    verify_archive_lock(out_dir, plan, rows, excluded)
    write_release_checksums(out_dir)
    verify_release_checksums(out_dir)

    print(
        "[archive-v1] BUILD PASS: "
        f"{len(rows)} payload files, {len(excluded)} excluded rebuildables, "
        f"manifest={sha256_file(manifest)}, payload_zip={sha256_file(payload_zip)}"
    )
    return 0


def verify(args: argparse.Namespace) -> int:
    """Verify an already-built bundle and the pinned source artifact identities."""
    plan = load_json(PLAN_PATH)
    out_dir = Path(args.bundle_dir).resolve()
    payload = out_dir / "payload"
    manifest_path = out_dir / MANIFEST_NAME
    if not payload.is_dir() or not manifest_path.is_file():
        fail("bundle is incomplete")

    for label, arg_name in [
        ("pilot", "pilot_zip"),
        ("repeat", "repeat_zip"),
        ("materialization", "materialization_zip"),
    ]:
        archive = verify_source_zip(
            Path(getattr(args, arg_name)), plan["artifact_sources"][label], label
        )
        archive.close()

    manifest = load_json(manifest_path)
    if manifest.get("schema_version") != "bpfcompat.research.archive-manifest.v1":
        fail("unexpected archive-manifest schema")
    if manifest.get("artifact_sources") != plan["artifact_sources"]:
        fail("archive manifest source-artifact binding drift")
    rows = manifest.get("payload", {}).get("files")
    excluded = manifest.get("excluded_rebuildable")
    if not isinstance(rows, list) or not isinstance(excluded, list):
        fail("archive manifest rows missing")
    if manifest["payload"].get("file_count") != len(rows):
        fail("archive manifest file count drift")
    if manifest["payload"].get("total_bytes") != sum(
        row.get("size_bytes", -1) for row in rows
    ):
        fail("archive manifest byte count drift")
    validate_rows(payload, rows, excluded)
    verify_payload_zip(payload, out_dir / PAYLOAD_ZIP_NAME)
    verify_archive_lock(out_dir, plan, rows, excluded)
    verify_release_checksums(out_dir)
    print("[archive-v1] VERIFY PASS")
    return 0


def parser() -> argparse.ArgumentParser:
    """Construct the CLI parser."""
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="command", required=True)
    for command in ("build", "verify"):
        sp = sub.add_parser(command)
        sp.add_argument("--pilot-zip", required=True)
        sp.add_argument("--repeat-zip", required=True)
        sp.add_argument("--materialization-zip", required=True)
        if command == "build":
            sp.add_argument("--out-dir", required=True)
        else:
            sp.add_argument("--bundle-dir", required=True)
    return ap


def main() -> int:
    """Dispatch the archive builder/verifier."""
    args = parser().parse_args()
    if args.command == "build":
        return build(args)
    return verify(args)


if __name__ == "__main__":
    raise SystemExit(main())
