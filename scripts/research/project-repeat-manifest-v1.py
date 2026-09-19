#!/usr/bin/env python3
"""Create a single-profile repeat-execution projection of a frozen manifest.

The frozen research manifest remains the source of truth. This helper changes
only its top-level required_profiles list so BPFCompat can execute one sampled
profile without requiring the other nine profiles to be present in the repeat
matrix. The source Git blob is verified before projection and projection
metadata is emitted for archival provenance.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import tempfile
from pathlib import Path

PROFILE_ID_RE = re.compile(r"^[A-Za-z0-9._-]+$")
PROFILE_ITEM_RE = re.compile(r"^  - ([A-Za-z0-9._-]+)\s*$")


def sha256_bytes(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def git_blob_sha1(data: bytes) -> str:
    header = f"blob {len(data)}\0".encode()
    return hashlib.sha1(header + data).hexdigest()


def locate_required_profiles(text: str) -> tuple[list[str], int, int, list[str], str]:
    lines = text.splitlines(keepends=True)
    key_indexes = [
        i for i, line in enumerate(lines)
        if line.rstrip("\r\n") == "required_profiles:"
    ]
    if len(key_indexes) != 1:
        raise ValueError(
            f"expected exactly one top-level required_profiles block, found {len(key_indexes)}"
        )

    key_index = key_indexes[0]
    newline = "\n"
    if lines[key_index].endswith("\r\n"):
        newline = "\r\n"

    profiles: list[str] = []
    end = key_index + 1
    while end < len(lines):
        raw = lines[end].rstrip("\r\n")
        match = PROFILE_ITEM_RE.fullmatch(raw)
        if match:
            profiles.append(match.group(1))
            end += 1
            continue

        # A blank/comment or the next top-level key belongs to the suffix.
        if raw.strip() == "" or raw.startswith("#") or not raw.startswith((" ", "\t")):
            break

        # Any other indented content means the frozen block is not in the
        # simple list form this fail-closed projection understands.
        raise ValueError(
            f"unsupported content inside required_profiles block at line {end + 1}: {raw!r}"
        )

    if not profiles:
        raise ValueError("required_profiles block is empty")

    if len(set(profiles)) != len(profiles):
        raise ValueError("required_profiles contains duplicate profile IDs")

    return lines, key_index, end, profiles, newline


def project_manifest(
    source: Path,
    profile_id: str,
    expected_git_blob: str,
    out: Path,
    metadata_out: Path,
) -> dict[str, object]:
    if not PROFILE_ID_RE.fullmatch(profile_id):
        raise ValueError(f"unsafe profile id: {profile_id!r}")

    data = source.read_bytes()
    actual_git_blob = git_blob_sha1(data)
    expected = expected_git_blob.removeprefix("git-blob:")
    if actual_git_blob != expected:
        raise ValueError(
            "source manifest Git blob mismatch: "
            f"expected {expected}, got {actual_git_blob}"
        )

    text = data.decode("utf-8")
    lines, key_index, end, profiles, newline = locate_required_profiles(text)
    if profile_id not in profiles:
        raise ValueError(
            f"profile {profile_id!r} is not required by frozen manifest"
        )

    projected_lines = (
        lines[: key_index + 1]
        + [f"  - {profile_id}{newline}"]
        + lines[end:]
    )
    projected = "".join(projected_lines).encode("utf-8")

    # Re-parse the projection to prove the transformation did exactly what it
    # intended at the required_profiles boundary.
    _, _, _, projected_profiles, _ = locate_required_profiles(
        projected.decode("utf-8")
    )
    if projected_profiles != [profile_id]:
        raise ValueError("projected manifest did not produce a singleton profile list")

    out.parent.mkdir(parents=True, exist_ok=True)
    metadata_out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(projected)

    metadata: dict[str, object] = {
        "schema_version": "bpfcompat.research.repeat-manifest-projection.v1",
        "projection": "required_profiles_singleton",
        "source_path": source.as_posix(),
        "source_git_blob": actual_git_blob,
        "source_sha256": sha256_bytes(data),
        "profile_id": profile_id,
        "source_required_profiles": profiles,
        "projected_required_profiles": [profile_id],
        "projected_path": out.as_posix(),
        "projected_sha256": sha256_bytes(projected),
    }
    metadata_out.write_text(
        json.dumps(metadata, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return metadata


def self_test() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        source = root / "source.yaml"
        out = root / "projected.yaml"
        meta = root / "projection.json"
        source.write_text(
            "name: demo\n"
            "programs:\n"
            "  - name: p\n"
            "required_profiles:\n"
            "  - ubuntu-20.04-5.4\n"
            "  - ubuntu-22.04-5.15\n"
            "metadata:\n"
            "  owner: demo\n",
            encoding="utf-8",
        )
        blob = git_blob_sha1(source.read_bytes())
        metadata = project_manifest(
            source,
            "ubuntu-22.04-5.15",
            blob,
            out,
            meta,
        )
        projected = out.read_text(encoding="utf-8")
        assert "  - ubuntu-22.04-5.15\n" in projected
        assert "  - ubuntu-20.04-5.4\n" not in projected
        assert "metadata:\n  owner: demo\n" in projected
        assert metadata["source_git_blob"] == blob
        assert metadata["projected_required_profiles"] == ["ubuntu-22.04-5.15"]

        try:
            project_manifest(source, "debian-12-6.1", blob, out, meta)
        except ValueError as exc:
            assert "not required by frozen manifest" in str(exc)
        else:
            raise AssertionError("missing-profile projection unexpectedly succeeded")

        try:
            project_manifest(source, "ubuntu-22.04-5.15", "0" * 40, out, meta)
        except ValueError as exc:
            assert "Git blob mismatch" in str(exc)
        else:
            raise AssertionError("wrong source blob unexpectedly succeeded")

    print("[project-repeat-manifest-v1] self-test PASS")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("--source")
    ap.add_argument("--profile-id")
    ap.add_argument("--expected-git-blob")
    ap.add_argument("--out")
    ap.add_argument("--metadata-out")
    args = ap.parse_args()

    if args.self_test:
        return self_test()

    required = {
        "--source": args.source,
        "--profile-id": args.profile_id,
        "--expected-git-blob": args.expected_git_blob,
        "--out": args.out,
        "--metadata-out": args.metadata_out,
    }
    missing = [flag for flag, value in required.items() if not value]
    if missing:
        ap.error("missing required arguments: " + ", ".join(missing))

    try:
        project_manifest(
            Path(args.source),
            args.profile_id,
            args.expected_git_blob,
            Path(args.out),
            Path(args.metadata_out),
        )
    except (OSError, UnicodeError, ValueError) as exc:
        raise SystemExit(f"repeat manifest projection failed: {exc}") from exc
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
