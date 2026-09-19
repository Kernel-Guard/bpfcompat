#!/usr/bin/env bash
set -euo pipefail

root="$(git rev-parse --show-toplevel)"
src="$root/docs/paper/latex/main.tex"
frozen="$root/research/paper/generated/figures"
out="${1:-$root/docs/paper/latex/build}"
pkg="$out/arxiv-v1"

for cmd in sha256sum inkscape pdflatex tar; do
  command -v "$cmd" >/dev/null 2>&1 || {
    echo "[preprint-v1] missing required command: $cmd" >&2
    exit 1
  }
done

expected_fig1="e603453187145edb3400bcdb486e179d76d7657a38b02d0619a7d2eb950cad43"
expected_fig2="7fad1b1fa74d42d0cd6e8b870acfe2e200314d63a691f66186d3cb854e6d80f9"
expected_fig3="1c3c8e9f043612e3b55b3f128a12fd5ca7c967ebbdfd4c66a2dd98c2ea49a509"

check_sha() {
  local file="$1"
  local expected="$2"
  local got
  got="$(sha256sum "$file" | awk '{print $1}')"
  [[ "$got" == "$expected" ]] || {
    echo "[preprint-v1] frozen figure hash mismatch: $file" >&2
    echo "expected=$expected" >&2
    echo "got=$got" >&2
    exit 1
  }
}

check_sha "$frozen/figure-1-study-architecture.svg" "$expected_fig1"
check_sha "$frozen/figure-2-ringbuf-version.svg" "$expected_fig2"
check_sha "$frozen/figure-3-compatibility-matrix.svg" "$expected_fig3"

grep -Fq '10.5281/zenodo.22848155' "$src" || {
  echo "[preprint-v1] exact Version DOI missing from main.tex" >&2
  exit 1
}

rm -rf "$out"
mkdir -p "$pkg/figures" "$out/svg-compat"
cp "$src" "$pkg/main.tex"

normalize_svg_use_href() {
  local src_svg="$1"
  local dst_svg="$2"
  python3 - "$src_svg" "$dst_svg" <<'PY'
from pathlib import Path
import sys

src = Path(sys.argv[1])
dst = Path(sys.argv[2])
text = src.read_text(encoding="utf-8")

# Inkscape 1.2 on Ubuntu 24.04 drops SVG2 <use href="#..."> instances.
# Normalize only that presentation syntax for conversion; the frozen source SVG
# remains hash-verified and untouched.
if '<use href=' in text:
    if 'xmlns:xlink=' not in text:
        text = text.replace(
            '<svg xmlns="http://www.w3.org/2000/svg"',
            '<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink"',
            1,
        )
    text = text.replace('<use href=', '<use xlink:href=')

dst.write_text(text, encoding="utf-8")
PY
}

convert_svg() {
  local src_svg="$1"
  local compat_svg="$2"
  local dst_pdf="$3"
  normalize_svg_use_href "$src_svg" "$compat_svg"
  inkscape "$compat_svg" --export-type=pdf --export-filename="$dst_pdf"
}

convert_svg \
  "$frozen/figure-1-study-architecture.svg" \
  "$out/svg-compat/figure-1.svg" \
  "$pkg/figures/figure-1.pdf"
convert_svg \
  "$frozen/figure-2-ringbuf-version.svg" \
  "$out/svg-compat/figure-2.svg" \
  "$pkg/figures/figure-2.pdf"
convert_svg \
  "$frozen/figure-3-compatibility-matrix.svg" \
  "$out/svg-compat/figure-3.svg" \
  "$pkg/figures/figure-3.pdf"

# Figure 3 has 70 matrix cells represented by <use> instances. Ensure the
# compatibility normalization preserved all of them before LaTeX compilation.
test "$(grep -o 'xlink:href=' "$out/svg-compat/figure-3.svg" | wc -l)" -eq 70

(
  cd "$pkg"
  pdflatex -interaction=nonstopmode -halt-on-error main.tex >/tmp/bpfcompat-preprint-v1-pass1.log
  pdflatex -interaction=nonstopmode -halt-on-error main.tex >/tmp/bpfcompat-preprint-v1-pass2.log

  if grep -Eq 'Undefined references|Citation .* undefined|Overfull \\hbox' main.log; then
    echo "[preprint-v1] LaTeX quality gate failed" >&2
    grep -E 'Undefined references|Citation .* undefined|Overfull \\hbox' main.log >&2 || true
    exit 1
  fi

  rm -f main.aux main.log main.out main.toc main.fls main.fdb_latexmk
)

cp "$pkg/main.pdf" "$out/bpfcompat-preprint-v1.pdf"

(
  cd "$pkg"
  sha256sum main.tex figures/figure-1.pdf figures/figure-2.pdf figures/figure-3.pdf \
    > "$out/preprint-v1-SHA256SUMS.txt"
)

tar --sort=name \
  --mtime='UTC 2026-09-19' \
  --owner=0 --group=0 --numeric-owner \
  -czf "$out/bpfcompat-arxiv-v1.tar.gz" \
  -C "$pkg" main.tex figures

sha256sum \
  "$out/bpfcompat-preprint-v1.pdf" \
  "$out/bpfcompat-arxiv-v1.tar.gz" \
  >> "$out/preprint-v1-SHA256SUMS.txt"

echo "[preprint-v1] built:"
echo "  $out/bpfcompat-preprint-v1.pdf"
echo "  $out/bpfcompat-arxiv-v1.tar.gz"
echo "  $out/preprint-v1-SHA256SUMS.txt"
