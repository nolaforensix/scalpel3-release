#!/bin/bash
#SBATCH --job-name=cmdline_test_hpc
#SBATCH --nodes=2
#SBATCH --ntasks=2
#SBATCH --ntasks-per-node=1
#SBATCH --cpus-per-task=20
#SBATCH --mem-per-cpu=3000
#SBATCH --time=24:00:00
#SBATCH --output=cmdline_test_hpc_%j.log
#SBATCH -A hpc_scalpel02
#SBATCH -p workq
#SBATCH --mail-user=bbaudi2@lsu.edu
#SBATCH --mail-type=ALL
#SBATCH --exclusive

set -euo pipefail

module purge

# Load Intel compiler + MPI stack (versioned first, then bare name, then openmpi fallback)
if ! module load intel/2021.5.0 intel-mpi/2021.5.1 2>/dev/null; then
    if ! module load intel intel-mpi 2>/dev/null; then
        if ! module load intelmpi 2>/dev/null; then
            if ! module load openmpi 2>/dev/null; then
                echo "Warning: Could not load any MPI module; job will likely fail" >&2
            fi
        fi
    fi
fi

date

export OMP_NUM_THREADS="$SLURM_CPUS_PER_TASK"

# Set PMI2 library path if it exists; this works with both Intel MPI and OpenMPI
if [[ -f /lib64/libpmi2.so ]]; then
    export I_MPI_PMI_LIBRARY=/lib64/libpmi2.so
fi
# OpenMPI-specific environment
export PMIX_SECURITY_MODE="native"
export OMPI_MCA_orte_default_hostfile="/etc/hostfile"

export PATH="/home/bradjb/.local/bin:$PATH"
export LD_LIBRARY_PATH="/home/bradjb/.local/lib:${LD_LIBRARY_PATH:-}"
export LIBRARY_PATH="/home/bradjb/.local/lib:${LIBRARY_PATH:-}"
export CPATH="/home/bradjb/.local/include:${CPATH:-}"

export WORK_DIR="/work/$USER/TEST_evensizesplit"
export COPY_DIR="/home/$USER/scalpel3"

export SCALPEL3_HOME="$WORK_DIR/scalpel3"

# Mirror cmdline.test behavior: parse -q from script args, pass remaining args to scalpel.
Q_VAL="16384"
SCALPEL_ARGS=()

while [[ $# -gt 0 ]]; do
	if [[ "$1" == "-q" ]]; then
		Q_VAL="$2"
		shift 2
	else
		SCALPEL_ARGS+=("$1")
		shift 1
	fi
done

rm -rf "$WORK_DIR"
mkdir -p "$WORK_DIR"

cp -r "$COPY_DIR" "$WORK_DIR"
cd "$WORK_DIR/scalpel3/src"

# Start clean, then run fragmentator + blockmap creation, then hpcscalpel3 EvenSizeSplit.
rm -rf scalpel-output hpc-output
rm -f TESTS/test.img.blockmap TESTS/test.img

set -x
./fragmentator -q "$Q_VAL" -o TESTS/test.img TESTS/test.frg
./crblockmap -q "$Q_VAL" TESTS/test.img TESTS/test.img.blockmap
srun --mpi=pmi2 --ntasks=2 ./hpcscalpel3 \
	-A EvenSizeSplit \
	-D 2 \
	-Q "$Q_VAL" \
	-O scalpel-output \
	TESTS/test.img \
	TESTS/test.img.blockmap \
	--scalpel "${SCALPEL_ARGS[@]}" -b -U csv
./validate_blockvectors_fast.py --verbose --key TESTS/test.img.key --scalpel-dir scalpel-output --frg TESTS/test.frg
set +x

date

exit 0
