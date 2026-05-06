#!/bin/bash
#
# Submit a quick 4-job performance comparison:
#   1. Plain scalpel3 (no HPC) on a single node
#   2. hpcscalpel3 SingleNode on a single node
#   3. EvenSizeSplit 2-node
#   4. EvenFileSplit 2-node
#
# Usage: ./submit_perfstudy_mini.sh --img <imgfile> --blockmap <blockmapfile> [-q blocksize] [extra scalpel args...]

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

echo "===== Submitting Mini Performance Test ====="
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

# 1. Plain scalpel3 baseline (no HPC)
SCRIPT="$SCRIPT_DIR/PERFSTUDY_nohpc_baseline.slurm"
if [[ ! -f "$SCRIPT" ]]; then
    echo "ERROR: Missing $SCRIPT"
    exit 1
fi
echo "Submitting scalpel3 baseline (no HPC)..."
sbatch "$SCRIPT" "$@"

# 2. hpcscalpel3 SingleNode (1 node)
SCRIPT="$SCRIPT_DIR/PERFSTUDY_singlenode_hpc.slurm"
if [[ ! -f "$SCRIPT" ]]; then
    echo "ERROR: Missing $SCRIPT"
    exit 1
fi
echo "Submitting hpcscalpel3 SingleNode..."
sbatch "$SCRIPT" "$@"

# 3. EvenSizeSplit 2-node
SCRIPT="$SCRIPT_DIR/PERFSTUDY_evensizesplit_2node.slurm"
if [[ ! -f "$SCRIPT" ]]; then
    echo "ERROR: Missing $SCRIPT"
    exit 1
fi
echo "Submitting EvenSizeSplit 2-node..."
sbatch "$SCRIPT" "$@"

# 4. EvenFileSplit 2-node
SCRIPT="$SCRIPT_DIR/PERFSTUDY_evenfilesplit_2node.slurm"
if [[ ! -f "$SCRIPT" ]]; then
    echo "ERROR: Missing $SCRIPT"
    exit 1
fi
echo "Submitting EvenFileSplit 2-node..."
sbatch "$SCRIPT" "$@"

echo ""
echo "All 4 jobs submitted. Monitor with: squeue -u \$USER"
echo "After completion, collect results with:"
echo "  ./collect_perfstudy_results.sh"
