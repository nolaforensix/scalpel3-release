#!/bin/bash
#
# Submit all performance study jobs for hpcscalpel3.
# Runs EvenSizeSplit and EvenFileSplit at 1, 2, 4, and 8 nodes,
# plus a single-node scalpel3-only baseline (no HPC).
#
# Usage: ./submit_perfstudy.sh --img <imgfile> --blockmap <blockmapfile> [-q blocksize] [extra scalpel args...]
#
# Jobs are submitted sequentially so they get separate job IDs.
# SLURM will schedule them based on resource availability.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Parse --img and --blockmap for validation, then pass all args through
IMG_FILE=""
BLOCKMAP_FILE=""
KEY_FILE=""
FRG_FILE=""
for ((i=1; i<=$#; i++)); do
    arg="${!i}"
    next=$((i+1))
    if [[ "$arg" == "--img" && $next -le $# ]]; then
        IMG_FILE="${!next}"
    elif [[ "$arg" == "--blockmap" && $next -le $# ]]; then
        BLOCKMAP_FILE="${!next}"
    elif [[ "$arg" == "--key" && $next -le $# ]]; then
        KEY_FILE="${!next}"
    elif [[ "$arg" == "--frg" && $next -le $# ]]; then
        FRG_FILE="${!next}"
    fi
done

if [[ -z "$IMG_FILE" || -z "$BLOCKMAP_FILE" ]]; then
    echo "Usage: $0 --img <imgfile> --blockmap <blockmapfile> [--key <keyfile>] [--frg <frgfile>] [-q blocksize] [extra scalpel args...]"
    exit 1
fi

# Resolve to absolute paths
IMG_FILE="$(cd "$(dirname "$IMG_FILE")" && pwd)/$(basename "$IMG_FILE")"
BLOCKMAP_FILE="$(cd "$(dirname "$BLOCKMAP_FILE")" && pwd)/$(basename "$BLOCKMAP_FILE")"

if [[ ! -f "$IMG_FILE" ]]; then
    echo "ERROR: Image file not found: $IMG_FILE"
    exit 1
fi
if [[ ! -f "$BLOCKMAP_FILE" ]]; then
    echo "ERROR: Blockmap file not found: $BLOCKMAP_FILE"
    exit 1
fi

if [[ -n "$KEY_FILE" ]]; then
    KEY_FILE="$(cd "$(dirname "$KEY_FILE")" && pwd)/$(basename "$KEY_FILE")"
    if [[ ! -f "$KEY_FILE" ]]; then
        echo "ERROR: Key file not found: $KEY_FILE"
        exit 1
    fi
fi

if [[ -n "$FRG_FILE" ]]; then
    FRG_FILE="$(cd "$(dirname "$FRG_FILE")" && pwd)/$(basename "$FRG_FILE")"
    if [[ ! -f "$FRG_FILE" ]]; then
        echo "ERROR: FRG file not found: $FRG_FILE"
        exit 1
    fi
fi

echo "===== Submitting hpcscalpel3 Performance Study ====="
echo "Image:    $IMG_FILE"
echo "Blockmap: $BLOCKMAP_FILE"
if [[ -n "$KEY_FILE" ]]; then
    echo "Key:      $KEY_FILE"
    echo "Validation: ENABLED"
    if [[ -n "$FRG_FILE" ]]; then
        echo "FRG:      $FRG_FILE"
    fi
else
    echo "Validation: DISABLED (no --key provided)"
fi
echo ""

# Single-node baseline (no HPC)
echo "--- Baseline (scalpel3 only, no HPC) ---"
SCRIPT="$SCRIPT_DIR/PERFSTUDY_nohpc_baseline.slurm"
if [[ ! -f "$SCRIPT" ]]; then
    echo "ERROR: Missing $SCRIPT"
    exit 1
fi
echo "Submitting no-HPC baseline job..."
sbatch "$SCRIPT" "$@"
echo ""

# SingleNode HPC (1 node)
echo "--- SingleNode HPC ---"
SCRIPT="$SCRIPT_DIR/PERFSTUDY_singlenode_hpc.slurm"
if [[ ! -f "$SCRIPT" ]]; then
    echo "ERROR: Missing $SCRIPT"
    exit 1
fi
echo "Submitting SingleNode HPC job..."
sbatch "$SCRIPT" "$@"
echo ""

# EvenSizeSplit
echo "--- EvenSizeSplit ---"
for N in 2 4 8; do
    SCRIPT="$SCRIPT_DIR/PERFSTUDY_evensizesplit_${N}node.slurm"
    if [[ ! -f "$SCRIPT" ]]; then
        echo "ERROR: Missing $SCRIPT"
        exit 1
    fi
    echo "Submitting EvenSizeSplit ${N}-node job..."
    sbatch "$SCRIPT" "$@"
done
echo ""

# EvenFileSplit
echo "--- EvenFileSplit ---"
for N in 2 4 8; do
    SCRIPT="$SCRIPT_DIR/PERFSTUDY_evenfilesplit_${N}node.slurm"
    if [[ ! -f "$SCRIPT" ]]; then
        echo "ERROR: Missing $SCRIPT"
        exit 1
    fi
    echo "Submitting EvenFileSplit ${N}-node job..."
    sbatch "$SCRIPT" "$@"
done

echo ""
echo "All jobs submitted (8 total). Monitor with: squeue -u \$USER"
echo "After completion, collect results with:"
echo "  ./collect_perfstudy_results.sh"
