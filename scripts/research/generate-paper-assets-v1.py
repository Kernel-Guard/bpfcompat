#!/usr/bin/env python3
"""Generate deterministic pilot-v1 paper figures and tables from committed evidence."""

from __future__ import annotations

import argparse
import csv
import hashlib
import html
import json
from pathlib import Path
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parents[2]
ANALYSIS = ROOT / "research/analysis/v1/generated"
DATA = ROOT / "research/data/v1/processed"
CORPUS = ROOT / "research/corpus/v1"
REPEAT = ROOT / "research/repeat/v1/data"

CASE_ORDER = [
    "simple-pass-libbpf",
    "perfbuf-fallback-libbpf",
    "ringbuf-modern-libbpf",
    "cilium-tracepoint-libbpf",
    "cilium-tracepoint-ebpf-go",
    "falco-modern-bpf-scap-open",
    "core-relocation-fail-libbpf",
]

CASE_LABELS = {
    "simple-pass-libbpf": "Simple pass / libbpf",
    "perfbuf-fallback-libbpf": "Perfbuf fallback / libbpf",
    "ringbuf-modern-libbpf": "Ringbuf modern / libbpf",
    "cilium-tracepoint-libbpf": "Cilium tracepoint / libbpf",
    "cilium-tracepoint-ebpf-go": "Cilium tracepoint / cilium/ebpf",
    "falco-modern-bpf-scap-open": "Falco modern_bpf / scap-open",
    "core-relocation-fail-libbpf": "CO-RE failure calibration",
}

VERDICT_SYMBOL = {
    "compatible": "C",
    "incompatible": "I",
    "inconclusive": "?",
}

VERDICT_FILL = {
    "compatible": "#d9ead3",
    "incompatible": "#f4cccc",
    "inconclusive": "#eeeeee",
}


def load_json(path: Path) -> Any:
    """Load a UTF-8 JSON document."""
    return json.loads(path.read_text(encoding="utf-8"))


def read_csv(path: Path) -> list[dict[str, str]]:
    """Read a CSV file into a list of dictionaries."""
    with path.open(newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    """Read newline-delimited JSON records."""
    rows: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            rows.append(json.loads(line))
    return rows


def sha256_file(path: Path) -> str:
    """Return sha256:<hex> for a file."""
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def write_text(path: Path, text: str) -> None:
    """Write deterministic UTF-8 text with LF newlines."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text.replace("\r\n", "\n"), encoding="utf-8", newline="\n")


def md_cell(value: Any) -> str:
    """Escape a value for a Markdown table cell."""
    return str(value).replace("|", "\\|").replace("\n", "<br>")


def markdown_table(headers: list[str], rows: Iterable[Iterable[Any]]) -> str:
    """Render a deterministic Markdown table."""
    out = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join("---" for _ in headers) + " |",
    ]
    for row in rows:
        out.append("| " + " | ".join(md_cell(v) for v in row) + " |")
    return "\n".join(out) + "\n"


def parse_series(series: str) -> tuple[int, int]:
    """Parse a major.minor kernel series into an integer tuple."""
    major, minor = series.split(".", 1)
    return int(major), int(minor)


def svg_text(x: float, y: float, text: str, **attrs: Any) -> str:
    """Render an escaped SVG text node."""
    properties = {
        "x": x,
        "y": y,
        "font-family": "Arial, Helvetica, sans-serif",
        "font-size": attrs.pop("font_size", 14),
        "fill": attrs.pop("fill", "#111111"),
    }
    properties.update(attrs)
    encoded = " ".join(
        f'{key.replace("_", "-")}="{html.escape(str(value), quote=True)}"'
        for key, value in properties.items()
    )
    return f"<text {encoded}>{html.escape(text)}</text>"


def figure1_architecture() -> str:
    """Render the deterministic study architecture flow as SVG."""
    width, height = 1320, 250
    labels = [
        ("Frozen artifact + loader selection", "immutable source identities"),
        ("Deterministic materialization", "binary/object SHA-256"),
        ("Exact vendor VM environment", "requested + observed kernel"),
        ("BPFCompat / project loader", "load, attach, command contract"),
        ("Normalized evidence", "verdict + failure taxonomy"),
        ("RQ1–RQ4 analysis", "tables + figures"),
    ]
    margin = 30
    gap = 22
    box_w = (width - 2 * margin - gap * (len(labels) - 1)) / len(labels)
    box_y, box_h = 72, 92

    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
        '<rect width="100%" height="100%" fill="#ffffff"/>',
        svg_text(30, 34, "Figure 1. Pilot v1 study architecture", font_size=20, font_weight="700"),
        svg_text(
            30,
            56,
            "Every stage preserves the identity needed to reproduce or audit the next stage.",
            font_size=13,
            fill="#444444",
        ),
        '<defs><marker id="arrow" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto"><path d="M0,0 L8,4 L0,8 z" fill="#444444"/></marker></defs>',
    ]
    for i, (title, subtitle) in enumerate(labels):
        x = margin + i * (box_w + gap)
        parts.append(
            f'<rect x="{x:.1f}" y="{box_y}" width="{box_w:.1f}" height="{box_h}" rx="8" fill="#f7f7f7" stroke="#555555" stroke-width="1.5"/>'
        )
        parts.append(
            svg_text(
                x + box_w / 2,
                box_y + 37,
                title,
                font_size=11 if i == 0 else 13,
                font_weight="700",
                text_anchor="middle",
            )
        )
        parts.append(
            svg_text(
                x + box_w / 2,
                box_y + 63,
                subtitle,
                font_size=11,
                fill="#555555",
                text_anchor="middle",
            )
        )
        if i < len(labels) - 1:
            x1 = x + box_w
            x2 = x + box_w + gap - 4
            y = box_y + box_h / 2
            parts.append(
                f'<line x1="{x1:.1f}" y1="{y:.1f}" x2="{x2:.1f}" y2="{y:.1f}" stroke="#444444" stroke-width="2" marker-end="url(#arrow)"/>'
            )
    parts.append(
        svg_text(
            30,
            218,
            "Canonical pilot: 70/70 records. Repeat stability snapshot: 21/21 same-environment stable observations.",
            font_size=12,
            fill="#333333",
        )
    )
    parts.append("</svg>\n")
    return "\n".join(parts)


def figure2_ringbuf(rows: list[dict[str, str]]) -> str:
    """Render conclusive ring-buffer version prediction versus observation as SVG."""
    conclusive = [row for row in rows if row["conclusive"] == "true"]
    conclusive.sort(key=lambda row: parse_series(row["observed_series"]))

    width = 1240
    left, right = 310, 140
    top, row_h, bottom = 112, 48, 100
    height = top + row_h * len(conclusive) + bottom

    versions = sorted({parse_series(row["observed_series"]) for row in conclusive} | {(5, 8)})
    positions = {v: i for i, v in enumerate(versions)}
    plot_w = width - left - right

    def x_for(series: str) -> float:
        v = parse_series(series)
        if len(versions) == 1:
            return left + plot_w / 2
        return left + positions[v] * plot_w / (len(versions) - 1)

    threshold_x = x_for("5.8")
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
        '<rect width="100%" height="100%" fill="#ffffff"/>',
        svg_text(28, 32, "Figure 2. Ring-buffer version prediction versus observation", font_size=20, font_weight="700"),
        svg_text(
            28,
            57,
            "Conclusive observations only. Shape encodes observed verdict; the diamond marks the below-threshold compatible exception.",
            font_size=12,
            fill="#444444",
        ),
        f'<line x1="{threshold_x:.1f}" y1="{top-28}" x2="{threshold_x:.1f}" y2="{top+row_h*len(conclusive)-15}" stroke="#555555" stroke-width="1.5" stroke-dasharray="6,5"/>',
        svg_text(
            threshold_x + 6,
            top - 12,
            "upstream 5.8 threshold",
            font_size=11,
            fill="#333333",
        ),
    ]

    for v in versions:
        x = left + positions[v] * plot_w / max(1, len(versions) - 1)
        parts.append(
            f'<line x1="{x:.1f}" y1="{top-18}" x2="{x:.1f}" y2="{top+row_h*len(conclusive)-15}" stroke="#e2e2e2" stroke-width="1"/>'
        )
        parts.append(
            svg_text(
                x,
                top + row_h * len(conclusive) + 10,
                f"{v[0]}.{v[1]}",
                font_size=11,
                text_anchor="middle",
            )
        )

    for idx, row in enumerate(conclusive):
        y = top + idx * row_h
        label = row["logical_profile_id"]
        parts.append(svg_text(left - 14, y + 5, label, font_size=11, text_anchor="end"))
        parts.append(
            f'<line x1="{left}" y1="{y}" x2="{width-right}" y2="{y}" stroke="#eeeeee" stroke-width="1"/>'
        )
        x = x_for(row["observed_series"])
        verdict = row["observed_verdict"]
        exception = row["agreement"] == "false"
        if exception:
            size = 10
            points = f"{x:.1f},{y-size} {x+size:.1f},{y:.1f} {x:.1f},{y+size} {x-size:.1f},{y:.1f}"
            parts.append(
                f'<polygon points="{points}" fill="{VERDICT_FILL[verdict]}" stroke="#111111" stroke-width="2"/>'
            )
        elif verdict == "compatible":
            parts.append(
                f'<circle cx="{x:.1f}" cy="{y:.1f}" r="8" fill="{VERDICT_FILL[verdict]}" stroke="#111111" stroke-width="1.5"/>'
            )
        else:
            parts.append(f'<line x1="{x-8:.1f}" y1="{y-8:.1f}" x2="{x+8:.1f}" y2="{y+8:.1f}" stroke="#111111" stroke-width="2"/>')
            parts.append(f'<line x1="{x+8:.1f}" y1="{y-8:.1f}" x2="{x-8:.1f}" y2="{y+8:.1f}" stroke="#111111" stroke-width="2"/>')
        parts.append(
            svg_text(
                x + 14,
                y + 5,
                "compatible" if verdict == "compatible" else "incompatible",
                font_size=10,
                fill="#444444",
            )
        )

    legend_y = height - 28
    parts.append(f'<circle cx="{left}" cy="{legend_y}" r="7" fill="{VERDICT_FILL["compatible"]}" stroke="#111111"/>')
    parts.append(svg_text(left + 14, legend_y + 4, "compatible", font_size=11))
    parts.append(f'<line x1="{left+112}" y1="{legend_y-7}" x2="{left+126}" y2="{legend_y+7}" stroke="#111111" stroke-width="2"/>')
    parts.append(f'<line x1="{left+126}" y1="{legend_y-7}" x2="{left+112}" y2="{legend_y+7}" stroke="#111111" stroke-width="2"/>')
    parts.append(svg_text(left + 134, legend_y + 4, "incompatible", font_size=11))
    parts.append("</svg>\n")
    return "\n".join(parts)


def load_execution_matrix() -> tuple[list[str], dict[tuple[str, str], str]]:
    """Load all canonical execution shards into a case/profile verdict matrix."""
    profile_lock = load_json(CORPUS / "profile-identities.json")
    profiles = [row["id"] for row in profile_lock["profiles"]]
    matrix: dict[tuple[str, str], str] = {}
    for case_id in CASE_ORDER:
        path = DATA / "executions" / f"{case_id}.jsonl"
        rows = read_jsonl(path)
        for row in rows:
            key = (case_id, row["logical_profile_id"])
            if key in matrix:
                raise ValueError(f"duplicate execution matrix key: {key}")
            matrix[key] = row["verdict"]
    expected = {(case_id, profile) for case_id in CASE_ORDER for profile in profiles}
    if set(matrix) != expected:
        missing = sorted(expected - set(matrix))
        extra = sorted(set(matrix) - expected)
        raise ValueError(f"execution matrix coverage drift; missing={missing}, extra={extra}")
    return profiles, matrix


def figure3_matrix(
    profiles: list[str],
    matrix: dict[tuple[str, str], str],
) -> str:
    """Render the 7x10 compatibility matrix as SVG."""
    left, top = 300, 190
    cell_w, cell_h = 82, 46
    width = left + cell_w * len(profiles) + 40
    height = top + cell_h * len(CASE_ORDER) + 90

    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
        '<rect width="100%" height="100%" fill="#ffffff"/>',
        svg_text(28, 32, "Figure 3. Pilot v1 compatibility matrix", font_size=20, font_weight="700"),
        svg_text(
            28,
            57,
            "C = compatible, I = incompatible, ? = inconclusive. Calibration is separated from primary/controlled cases.",
            font_size=12,
            fill="#444444",
        ),
    ]

    for col, profile in enumerate(profiles):
        x = left + col * cell_w + cell_w / 2
        parts.append(
            f'<g transform="translate({x:.1f},{top-12}) rotate(-55)">'
            + svg_text(0, 0, profile, font_size=10, text_anchor="start")
            + "</g>"
        )

    for row_idx, case_id in enumerate(CASE_ORDER):
        y = top + row_idx * cell_h
        calibration = case_id == "core-relocation-fail-libbpf"
        if calibration:
            parts.append(
                f'<line x1="24" y1="{y-8}" x2="{width-24}" y2="{y-8}" stroke="#333333" stroke-width="2.5"/>'
            )
        parts.append(
            svg_text(
                left - 12,
                y + cell_h / 2 + 5,
                CASE_LABELS[case_id],
                font_size=11,
                font_weight="700" if calibration else "400",
                text_anchor="end",
            )
        )
        for col, profile in enumerate(profiles):
            verdict = matrix[(case_id, profile)]
            x = left + col * cell_w
            parts.append(
                f'<rect x="{x}" y="{y}" width="{cell_w}" height="{cell_h}" fill="{VERDICT_FILL[verdict]}" stroke="#777777" stroke-width="1"/>'
            )
            parts.append(
                svg_text(
                    x + cell_w / 2,
                    y + cell_h / 2 + 6,
                    VERDICT_SYMBOL[verdict],
                    font_size=16,
                    font_weight="700",
                    text_anchor="middle",
                )
            )

    legend_y = height - 32
    legend_x = left
    for verdict, label in [
        ("compatible", "compatible"),
        ("incompatible", "incompatible"),
        ("inconclusive", "inconclusive"),
    ]:
        parts.append(
            f'<rect x="{legend_x}" y="{legend_y-14}" width="24" height="20" fill="{VERDICT_FILL[verdict]}" stroke="#777777"/>'
        )
        parts.append(svg_text(legend_x + 31, legend_y + 1, f"{VERDICT_SYMBOL[verdict]} = {label}", font_size=11))
        legend_x += 180

    parts.append("</svg>\n")
    return "\n".join(parts)


def source_revision_for_case(case_id: str, identities: dict[str, Any]) -> str:
    """Resolve the frozen source revision displayed for a study case."""
    revisions = identities["source_revisions"]
    if case_id == "falco-modern-bpf-scap-open":
        return revisions["falco"]
    if case_id.startswith("cilium-tracepoint-"):
        if case_id == "cilium-tracepoint-ebpf-go":
            return (
                revisions["cilium_tracepoint_upstream"]
                + " (artifact); "
                + revisions["bpfcompat_selection_source"]
                + " (loader)"
            )
        return revisions["cilium_tracepoint_upstream"]
    return revisions["bpfcompat_selection_source"]


def loader_label(case: dict[str, Any]) -> str:
    """Return a human-readable loader label from the frozen study plan."""
    if case["mode"] in {"load_only", "load_attach"}:
        return "BPFCompat v0.3.7 static libbpf validator"
    artifact = case.get("command_binary_artifact_id")
    if artifact == "cilium-ebpf-v022-loader":
        return "cilium/ebpf v0.22.0 custom loader"
    if artifact == "falco-modern-bpf-scap-open":
        return "Falco scap-open modern_bpf path"
    return str(artifact or "command loader")


def table1_corpus_contracts() -> str:
    """Generate Table 1 from frozen study-plan and identity locks."""
    plan = load_json(CORPUS / "study-plan.json")
    identities = load_json(CORPUS / "materialized-identities.json")
    case_outcomes = {
        row["case_id"]: row for row in read_csv(ANALYSIS / "case-outcomes.csv")
    }
    cases = {row["id"]: row for row in plan["cases"]}
    rows = []
    for case_id in CASE_ORDER:
        case = cases[case_id]
        rows.append(
            [
                case_id,
                case_outcomes[case_id]["analysis_role"],
                case.get("artifact_id", ""),
                source_revision_for_case(case_id, identities),
                case["mode"],
                loader_label(case),
                case["base_validation_contract_id"],
            ]
        )
    return (
        "# Table 1 — Frozen corpus and validation contracts\n\n"
        + markdown_table(
            [
                "Case",
                "Analysis role",
                "Artifact",
                "Frozen source revision",
                "Execution mode",
                "Loader / validator",
                "Immutable base contract ID",
            ],
            rows,
        )
    )


def table2_failure_taxonomy() -> str:
    """Generate Table 2 with calibration and non-calibration denominators separated."""
    summary = load_json(ANALYSIS / "analysis-summary.json")
    rq2 = summary["rq2_failure_taxonomy"]
    rows = []
    for scope in ["non_calibration", "calibration"]:
        block = rq2[scope]
        taxonomy = block["taxonomy"]
        taxonomy_text = ", ".join(
            f"{code}={count}" for code, count in sorted(taxonomy.items())
        ) or "none"
        rows.append(
            [
                scope.replace("_", " "),
                block["attempts"],
                block["evaluable"],
                block["compatible"],
                block["incompatible"],
                block["inconclusive"],
                taxonomy_text,
            ]
        )
    return (
        "# Table 2 — Failure taxonomy\n\n"
        "Calibration is reported separately and is not included in real-world compatibility prevalence.\n\n"
        + markdown_table(
            [
                "Scope",
                "Attempts",
                "Evaluable",
                "Compatible",
                "Incompatible",
                "Inconclusive",
                "Incompatibility taxonomy",
            ],
            rows,
        )
    )


def table3_environments() -> str:
    """Generate Table 3 from exact-environment provenance."""
    rows = read_csv(ANALYSIS / "rq4-environments.csv")
    rendered = []
    for row in rows:
        rendered.append(
            [
                row["logical_profile_id"],
                f'{row["distribution"]} {row["distribution_release"]}',
                row["requested_kernel_family"],
                row["observed_kernel_release"],
                row["kernel_family_match"],
                row["image_identity"],
                row["exact_environment_id"],
            ]
        )
    return (
        "# Table 3 — Exact environment provenance\n\n"
        + markdown_table(
            [
                "Logical profile",
                "Distribution",
                "Requested kernel family",
                "Observed kernel release",
                "Family match",
                "Image SHA-256",
                "Exact environment ID",
            ],
            rendered,
        )
    )


def table4_repeat() -> str:
    """Generate Table 4 from the committed repeat stability summary."""
    summary = load_json(REPEAT / "stability-summary.json")
    rows = [
        ["Planned attempts", summary["planned_attempts"]],
        ["Observed attempts", summary["observed_attempts"]],
        ["Stable on same exact environment", summary["stable_same_environment"]],
        ["Environment drift", summary["environment_drift"]],
        ["Same-environment verdict instability", summary["verdict_instability"]],
    ]
    return (
        "# Table 4 — Repeat-run stability\n\n"
        "Purposefully stratified post-collection sample; not a population-wide nondeterminism estimate.\n\n"
        + markdown_table(["Measure", "Result"], rows)
    )


def generate(out_dir: Path) -> None:
    """Generate all final pilot-v1 paper assets and a hash manifest."""
    rq1 = read_csv(ANALYSIS / "rq1-ringbuf-version.csv")
    profiles, matrix = load_execution_matrix()

    outputs: dict[str, str] = {
        "figures/figure-1-study-architecture.svg": figure1_architecture(),
        "figures/figure-2-ringbuf-version.svg": figure2_ringbuf(rq1),
        "figures/figure-3-compatibility-matrix.svg": figure3_matrix(profiles, matrix),
        "tables/table-1-corpus-contracts.md": table1_corpus_contracts(),
        "tables/table-2-failure-taxonomy.md": table2_failure_taxonomy(),
        "tables/table-3-environments.md": table3_environments(),
        "tables/table-4-repeat-stability.md": table4_repeat(),
    }

    for rel, content in outputs.items():
        write_text(out_dir / rel, content)

    input_paths = [
        ANALYSIS / "analysis-summary.json",
        ANALYSIS / "case-outcomes.csv",
        ANALYSIS / "failure-taxonomy.csv",
        ANALYSIS / "rq1-ringbuf-version.csv",
        ANALYSIS / "rq4-environments.csv",
        CORPUS / "study-plan.json",
        CORPUS / "materialized-identities.json",
        CORPUS / "profile-identities.json",
        REPEAT / "stability-summary.json",
    ] + [DATA / "executions" / f"{case_id}.jsonl" for case_id in CASE_ORDER]

    manifest = {
        "schema_version": "bpfcompat.research.paper-assets.v1",
        "dataset_version": "v1",
        "generator": {
            "path": "scripts/research/generate-paper-assets-v1.py",
            "sha256": sha256_file(Path(__file__)),
        },
        "inputs": {
            path.relative_to(ROOT).as_posix(): sha256_file(path)
            for path in input_paths
        },
        "outputs": {
            rel: sha256_file(out_dir / rel)
            for rel in sorted(outputs)
        },
        "claims": {
            "pilot_attempts": 70,
            "repeat_attempts": 21,
            "figures": 3,
            "tables": 4,
        },
    }
    write_text(
        out_dir / "asset-manifest.json",
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
    )

    readme = """# Pilot v1 generated paper assets

These files are generated deterministically by
'scripts/research/generate-paper-assets-v1.py' from the committed pilot v1
normalized dataset, generated RQ1–RQ4 analysis, frozen corpus identity locks,
and committed repeat-stability snapshot.

Do not hand-edit files under this directory. Run
'scripts/research/test-paper-assets-v1.sh' to regenerate into a temporary
directory and diff every output.

The SVG figures use explicit labels/symbols in addition to fill colors so the
compatibility state is not encoded by color alone.
"""
    write_text(out_dir / "README.md", readme)


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--out-dir",
        default="research/paper/generated",
        help="Output directory relative to repository root",
    )
    return ap.parse_args()


def main() -> int:
    """Generate paper assets."""
    args = parse_args()
    out_dir = Path(args.out_dir)
    if not out_dir.is_absolute():
        out_dir = ROOT / out_dir
    generate(out_dir)
    try:
        display = out_dir.relative_to(ROOT)
    except ValueError:
        display = out_dir
    print(f"[generate-paper-assets-v1] wrote {display}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
