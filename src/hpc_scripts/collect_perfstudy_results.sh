#!/bin/bash
#
# Collect and display performance study results from completed SLURM logs.
#
# Usage: ./collect_perfstudy_results.sh [log_directory]
#   log_directory defaults to current directory
#
# Looks for PERFSTUDY_RESULT lines in perfstudy_*.log files.

set -euo pipefail

LOG_DIR="${1:-.}"

echo "===== hpcscalpel3 Performance Study Results ====="
echo ""
printf "%-16s  %-8s  %-14s  %-12s  %-16s  %-10s\n" "Algorithm" "Nodes" "CPUs/Task" "Blocksize" "Elapsed (sec)" "Total Cores"
printf "%-16s  %-8s  %-14s  %-12s  %-16s  %-10s\n" "----------" "-----" "---------" "---------" "-------------" "-----------"

for logfile in "$LOG_DIR"/perfstudy_*.log; do
    [[ -f "$logfile" ]] || continue
    while IFS= read -r line; do
        algo=$(echo "$line" | grep -oP 'algorithm=\K[^ ]+')
        nodes=$(echo "$line" | grep -oP 'nodes=\K[0-9]+')
        cpus=$(echo "$line" | grep -oP 'cpus_per_task=\K[0-9]+')
        bs=$(echo "$line" | grep -oP 'blocksize=\K[0-9]+')
        elapsed=$(echo "$line" | grep -oP 'elapsed_seconds=\K[0-9]+')
        total=$((nodes * cpus))
        printf "%-16s  %-8s  %-14s  %-12s  %-16s  %-10s\n" "$algo" "$nodes" "$cpus" "$bs" "$elapsed" "$total"
    done < <(grep "PERFSTUDY_RESULT" "$logfile" 2>/dev/null || true)
done

echo ""
echo "Speedup relative to no-HPC baseline:"
echo ""

BASELINE=""
for logfile in "$LOG_DIR"/perfstudy_nohpc_*.log; do
    [[ -f "$logfile" ]] || continue
    BASELINE=$(grep "PERFSTUDY_RESULT" "$logfile" 2>/dev/null | head -1 | grep -oP 'elapsed_seconds=\K[0-9]+' || true)
    break
done

if [[ -z "$BASELINE" || "$BASELINE" == "0" ]]; then
    echo "  (No-HPC baseline log not found or elapsed=0; cannot compute speedup)"
else
    printf "%-16s  %-8s  %-16s  %-10s\n" "Algorithm" "Nodes" "Elapsed (sec)" "Speedup"
    printf "%-16s  %-8s  %-16s  %-10s\n" "----------" "-----" "-------------" "-------"
    for logfile in "$LOG_DIR"/perfstudy_*.log; do
        [[ -f "$logfile" ]] || continue
        while IFS= read -r line; do
            algo=$(echo "$line" | grep -oP 'algorithm=\K[^ ]+')
            nodes=$(echo "$line" | grep -oP 'nodes=\K[0-9]+')
            elapsed=$(echo "$line" | grep -oP 'elapsed_seconds=\K[0-9]+')
            if [[ "$elapsed" -gt 0 ]]; then
                speedup=$(awk "BEGIN {printf \"%.2fx\", $BASELINE / $elapsed}")
            else
                speedup="N/A"
            fi
            printf "%-16s  %-8s  %-16s  %-10s\n" "$algo" "$nodes" "$elapsed" "$speedup"
        done < <(grep "PERFSTUDY_RESULT" "$logfile" 2>/dev/null || true)
    done
fi

# Validation results (if any)
HAS_VALIDATE=0
for logfile in "$LOG_DIR"/perfstudy_*.log; do
    [[ -f "$logfile" ]] || continue
    if grep -q "PERFSTUDY_VALIDATE" "$logfile" 2>/dev/null; then
        HAS_VALIDATE=1
        break
    fi
done

if [[ "$HAS_VALIDATE" -eq 1 ]]; then
    echo ""
    echo "===== Blockvector Validation Results ====="
    echo ""
    printf "%-16s  %-6s  %-8s  %-8s  %-8s  %-8s  %-8s  %-8s  %-12s\n" \
        "Algorithm" "Nodes" "Universe" "Perfect" "LenMis" "PartMis" "PartOK" "Wrong" "NotRecov"
    printf "%-16s  %-6s  %-8s  %-8s  %-8s  %-8s  %-8s  %-8s  %-12s\n" \
        "----------" "-----" "--------" "-------" "------" "-------" "------" "-----" "--------"
    for logfile in "$LOG_DIR"/perfstudy_*.log; do
        [[ -f "$logfile" ]] || continue
        while IFS= read -r line; do
            algo=$(echo "$line" | grep -oP 'algorithm=\K[^ ]+')
            nodes=$(echo "$line" | grep -oP 'nodes=\K[0-9]+')
            universe=$(echo "$line" | grep -oP 'universe=\K[0-9]+')
            perfect=$(echo "$line" | grep -oP 'perfect=\K[0-9]+')
            lenmis=$(echo "$line" | grep -oP 'length_mismatch=\K[0-9]+')
            partmis=$(echo "$line" | grep -oP 'partial_missing=\K[0-9]+')
            partok=$(echo "$line" | grep -oP 'partial_correct=\K[0-9]+')
            wrong=$(echo "$line" | grep -oP 'incorrect=\K[0-9]+')
            notrecov=$(echo "$line" | grep -oP 'not_recovered=\K[0-9]+')
            printf "%-16s  %-6s  %-8s  %-8s  %-8s  %-8s  %-8s  %-8s  %-12s\n" \
                "$algo" "$nodes" "$universe" "$perfect" "$lenmis" "$partmis" "$partok" "$wrong" "$notrecov"
        done < <(grep "PERFSTUDY_VALIDATE" "$logfile" 2>/dev/null || true)
    done
fi
