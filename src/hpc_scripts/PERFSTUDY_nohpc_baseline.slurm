#!/bin/bash
#SBATCH --job-name=perfstudy_nohpc
#SBATCH --nodes=1
#SBATCH --ntasks=1
#SBATCH --cpus-per-task=20
#SBATCH --mem-per-cpu=3000
#SBATCH --time=24:00:00
#SBATCH --output=perfstudy_nohpc_%j.log
#SBATCH -A hpc_scalpel02
#SBATCH -p workq
#SBATCH --mail-user=bbaudi2@lsu.edu
#SBATCH --mail-type=ALL
#SBATCH --exclusive

set -euo pipefail

LABEL="perfstudy_nohpc"

export OMP_NUM_THREADS="$SLURM_CPUS_PER_TASK"

export PATH="/home/bradjb/.local/bin:$PATH"
export LD_LIBRARY_PATH="/home/bradjb/.local/lib:${LD_LIBRARY_PATH:-}"
export LIBRARY_PATH="/home/bradjb/.local/lib:${LIBRARY_PATH:-}"
export CPATH="/home/bradjb/.local/include:${CPATH:-}"

export WORK_DIR="/work/$USER/$LABEL"
export COPY_DIR="/home/$USER/scalpel3"

export SCALPEL3_HOME="$WORK_DIR/scalpel3"

Q_VAL="16384"
IMG_FILE=""
BLOCKMAP_FILE=""
KEY_FILE=""
FRG_FILE=""
SCALPEL_ARGS=()

while [[ $# -gt 0 ]]; do
	if [[ "$1" == "-q" ]]; then
		Q_VAL="$2"
		shift 2
	elif [[ "$1" == "--img" ]]; then
		IMG_FILE="$2"
		shift 2
	elif [[ "$1" == "--blockmap" ]]; then
		BLOCKMAP_FILE="$2"
		shift 2
	elif [[ "$1" == "--key" ]]; then
		KEY_FILE="$2"
		shift 2
	elif [[ "$1" == "--frg" ]]; then
		FRG_FILE="$2"
		shift 2
	else
		SCALPEL_ARGS+=("$1")
		shift 1
	fi
done

if [[ -z "$IMG_FILE" || -z "$BLOCKMAP_FILE" ]]; then
	echo "ERROR: --img and --blockmap are required" >&2
	exit 1
fi

rm -rf "$WORK_DIR"
mkdir -p "$WORK_DIR"

cp -r "$COPY_DIR" "$WORK_DIR"
cd "$WORK_DIR/scalpel3/src"

rm -rf scalpel-output

echo "===== Performance Study (No HPC - Single Node Baseline): $SLURM_CPUS_PER_TASK cpus ====="
echo "Start: $(date)"
echo ""

set -x

SECONDS=0
./scalpel3 "${SCALPEL_ARGS[@]}" -A 85200 -q "$Q_VAL" -b -U csv -o scalpel-output "$IMG_FILE" "$BLOCKMAP_FILE"
ELAPSED=$SECONDS
set +x

echo ""
echo "PERFSTUDY_RESULT: algorithm=NoHPC nodes=1 cpus_per_task=$SLURM_CPUS_PER_TASK blocksize=$Q_VAL elapsed_seconds=$ELAPSED"
echo ""

# Blockvector validation (optional, requires --key)
if [[ -n "$KEY_FILE" ]]; then
	echo "===== Blockvector Validation ====="
	VALIDATE_SCRIPT="$SCALPEL3_HOME/src/validate_blockvectors_fast.py"
	if [[ ! -f "$VALIDATE_SCRIPT" ]]; then
		echo "WARNING: validate_blockvectors_fast.py not found at $VALIDATE_SCRIPT" >&2
	else
		VALIDATE_CMD=(python3 "$VALIDATE_SCRIPT" --key "$KEY_FILE" --scalpel-dir scalpel-output)
		if [[ -n "$FRG_FILE" ]]; then
			VALIDATE_CMD+=(--frg "$FRG_FILE")
		fi
		echo "Running: ${VALIDATE_CMD[*]}"
		VALIDATE_OUTPUT=$( "${VALIDATE_CMD[@]}" 2>&1 ) || true
		echo "$VALIDATE_OUTPUT"

		# Extract category counts from SUMMARY (ALL FILES) section
		V_UNIVERSE=$(echo "$VALIDATE_OUTPUT" | grep -oP 'GT files \(universe\):\s+\K[0-9]+' | tail -1)
		V_CAT1=$(echo "$VALIDATE_OUTPUT" | grep -oP 'Category 1 \(Perfect\):\s+\K[0-9]+' | tail -1)
		V_CAT2=$(echo "$VALIDATE_OUTPUT" | grep -oP 'Category 2 \(Length mismatch\):\s+\K[0-9]+' | tail -1)
		V_CAT3=$(echo "$VALIDATE_OUTPUT" | grep -oP 'Category 3 \(Partial w/MISSING\):\s+\K[0-9]+' | tail -1)
		V_CAT4=$(echo "$VALIDATE_OUTPUT" | grep -oP 'Category 4 \(Partial correct\):\s+\K[0-9]+' | tail -1)
		V_CAT5=$(echo "$VALIDATE_OUTPUT" | grep -oP 'Category 5 \(Incorrect\):\s+\K[0-9]+' | tail -1)
		V_CAT6=$(echo "$VALIDATE_OUTPUT" | grep -oP 'Category 6 \(Not recovered\):\s+\K[0-9]+' | tail -1)

		echo ""
		echo "PERFSTUDY_VALIDATE: algorithm=NoHPC nodes=1 universe=${V_UNIVERSE:-0} perfect=${V_CAT1:-0} length_mismatch=${V_CAT2:-0} partial_missing=${V_CAT3:-0} partial_correct=${V_CAT4:-0} incorrect=${V_CAT5:-0} not_recovered=${V_CAT6:-0}"
	fi
	echo ""
fi

echo "End: $(date)"
exit 0
