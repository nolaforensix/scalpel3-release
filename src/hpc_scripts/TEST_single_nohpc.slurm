#!/bin/bash
#SBATCH --job-name=cmdline_test
#SBATCH --nodes=1
#SBATCH --ntasks=1
#SBATCH --cpus-per-task=20
#SBATCH --mem-per-cpu=3000
#SBATCH --time=24:00:00
#SBATCH --output=cmdline_test_%j.log
#SBATCH -A hpc_scalpel02
#SBATCH -p workq
#SBATCH --mail-user=bbaudi2@lsu.edu
#SBATCH --mail-type=ALL
#SBATCH --exclusive

date

export OMP_NUM_THREADS=$SLURM_CPUS_PER_TASK

export PATH="/home/bradjb/.local/bin:$PATH"
export LD_LIBRARY_PATH="/home/bradjb/.local/lib:$LD_LIBRARY_PATH"
export LIBRARY_PATH="/home/bradjb/.local/lib:$LIBRARY_PATH"
export CPATH="/home/bradjb/.local/include:$CPATH"

export WORK_DIR=/work/$USER/TEST_single_nohpc
export COPY_DIR=/home/$USER/scalpel3

export SCALPEL3_HOME=$WORK_DIR/scalpel3

# Run cmdline.test script from TESTS folder

rm -r $WORK_DIR

mkdir -p $WORK_DIR

cp -r $COPY_DIR $WORK_DIR
cd $WORK_DIR/scalpel3/src

./TESTS/cmdline.test

date

exit 