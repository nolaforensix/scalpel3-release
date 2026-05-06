#!/bin/bash
#
# postprocess_scalpel.sh
#
# Runs all Scalpel post-processing steps in order:
#   1. ZIP rename pass (postprocess_zip.sh)
#   2. ELF blockvector fill pass (postprocess_elf.py)
#
# Usage:
#   ./postprocess_scalpel.sh --image /path/to/image.dd --blockmap /path/to/scalpel.blockmap [options]
#
# Required args (passed through to postprocess_elf.py):
#   --image PATH       Source disk/image file
#   --blockmap PATH    Scalpel binary blockmap
#
# Optional args:
#   --output-root PATH  Scalpel output dir (default: most recent ./scalpel-output/* dir)
#   --in-place          Modify original ELF candidates in place
#   --dry-run           Compute fills and write reports only, no file writes
#   --enable-phase4     Enable Phase 4 proximity-based fills

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── Argument parsing ────────────────────────────────────────────────────────
IMAGE=""
BLOCKMAP=""
OUTPUT_ROOT=""
ELF_EXTRA_ARGS=()

while [[ $# -gt 0 ]]; do
    case "$1" in
        --image)        IMAGE="$2";       shift 2 ;;
        --blockmap)     BLOCKMAP="$2";    shift 2 ;;
        --output-root)  OUTPUT_ROOT="$2"; shift 2 ;;
        --in-place)     ELF_EXTRA_ARGS+=("--in-place");    shift ;;
        --dry-run)      ELF_EXTRA_ARGS+=("--dry-run");     shift ;;
        --enable-phase4) ELF_EXTRA_ARGS+=("--enable-phase4"); shift ;;
        *)
            echo "Unknown argument: $1" >&2
            exit 1
            ;;
    esac
done

if [[ -z "$IMAGE" || -z "$BLOCKMAP" ]]; then
    echo "Error: --image and --blockmap are required." >&2
    exit 1
fi

# ── Resolve output root ─────────────────────────────────────────────────────
if [[ -z "$OUTPUT_ROOT" ]]; then
    OUTPUT_ROOT=$(find ./scalpel-output -mindepth 1 -maxdepth 1 -type d \
        -exec stat -f "%m %N" {} + 2>/dev/null \
        | sort -n | tail -1 | cut -d' ' -f2-)

    # Fallback for Linux (stat -f is macOS; Linux uses stat -c)
    if [[ -z "$OUTPUT_ROOT" ]]; then
        OUTPUT_ROOT=$(find ./scalpel-output -mindepth 1 -maxdepth 1 -type d \
            -exec stat -c "%Y %n" {} + \
            | sort -n | tail -1 | cut -d' ' -f2-)
    fi

    if [[ -z "$OUTPUT_ROOT" ]]; then
        echo "Error: No directories found under ./scalpel-output and --output-root not specified." >&2
        exit 1
    fi
fi

echo "==> Output root: $OUTPUT_ROOT"

# ── Step 1: ZIP post-processing ─────────────────────────────────────────────
echo ""
echo "── Step 1: ZIP rename pass ─────────────────────────────────────────────"
ZIP_SCRIPT="$SCRIPT_DIR/postprocess_zip.sh"
if [[ ! -f "$ZIP_SCRIPT" ]]; then
    echo "Warning: postprocess_zip.sh not found at $ZIP_SCRIPT — skipping ZIP pass." >&2
else
    bash "$ZIP_SCRIPT"
    echo "ZIP pass complete."
fi

# ── Step 2: Python dependency installation ──────────────────────────────────
echo ""
echo "── Step 2: Python dependency check ────────────────────────────────────"

# postprocess_elf.py uses only the standard library, but ensure Python 3.8+ is present
PYTHON=""
for candidate in python3 python; do
    if command -v "$candidate" &>/dev/null; then
        version=$("$candidate" -c 'import sys; print(sys.version_info >= (3,8))')
        if [[ "$version" == "True" ]]; then
            PYTHON="$candidate"
            break
        fi
    fi
done

if [[ -z "$PYTHON" ]]; then
    echo "Error: Python 3.8 or newer is required but was not found." >&2
    exit 1
fi

echo "Using Python: $PYTHON ($($PYTHON --version))"

# Install any third-party deps here if postprocess_elf.py ever gains them.
# Currently it uses only stdlib (argparse, json, re, shutil, struct, dataclasses,
# pathlib, typing), so no pip install is needed.
#
# Template for future deps:
#   REQUIRED_PACKAGES=("some-package" "another-package")
#   for pkg in "${REQUIRED_PACKAGES[@]}"; do
#       if ! "$PYTHON" -c "import $pkg" &>/dev/null; then
#           echo "Installing $pkg..."
#           "$PYTHON" -m pip install --quiet "$pkg"
#       fi
#   done

echo "All Python dependencies satisfied."

# ── Step 3: ELF blockvector post-processing ──────────────────────────────────
echo ""
echo "── Step 3: ELF blockvector fill pass ───────────────────────────────────"
ELF_SCRIPT="$SCRIPT_DIR/postprocess_elf.py"
if [[ ! -f "$ELF_SCRIPT" ]]; then
    echo "Error: postprocess_elf.py not found at $ELF_SCRIPT" >&2
    exit 1
fi

"$PYTHON" "$ELF_SCRIPT" \
    --image "$IMAGE" \
    --blockmap "$BLOCKMAP" \
    --output-root "$OUTPUT_ROOT" \
    ${ELF_EXTRA_ARGS[@]+"${ELF_EXTRA_ARGS[@]}"}

echo ""
echo "==> All post-processing steps complete."