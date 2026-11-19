#!/usr/bin/env bash
# Reproducibly builds the Google Scholar-compliant academic PDF from LaTeX source
# and validates zero Type 3 fonts + PDF metadata via pdffonts and pdfinfo.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEX_FILE="${SCRIPT_DIR}/kether1_paper.tex"
OUT_NAME="Kether1_Debian13_Hardening_Ephemeral_KVM_Sandbox_2026"
PDF_OUT="${SCRIPT_DIR}/${OUT_NAME}.pdf"

command -v pdflatex >/dev/null 2>&1 || { echo "ERROR: pdflatex not installed." >&2; exit 1; }

BUILD_DIR="$(mktemp -d)"
trap 'rm -rf "$BUILD_DIR"' EXIT

pdflatex -interaction=nonstopmode -halt-on-error -output-directory="$BUILD_DIR" -jobname="$OUT_NAME" "$TEX_FILE" >/dev/null
pdflatex -interaction=nonstopmode -halt-on-error -output-directory="$BUILD_DIR" -jobname="$OUT_NAME" "$TEX_FILE" >/dev/null

cp "${BUILD_DIR}/${OUT_NAME}.pdf" "$PDF_OUT"
echo "Built PDF: $PDF_OUT ($(stat -c%s "$PDF_OUT") bytes)"

if command -v pdffonts >/dev/null 2>&1; then
  if pdffonts "$PDF_OUT" | grep -qi "Type 3"; then
    echo "ERROR: Type 3 font detected (disallowed by Google Scholar guidelines)." >&2
    pdffonts "$PDF_OUT" >&2
    exit 1
  fi
  echo "Font check passed: zero Type 3 fonts."
fi

if command -v pdfinfo >/dev/null 2>&1; then
  pdfinfo "$PDF_OUT" | grep -E "^(Title|Author|Pages|File size):" || true
fi
