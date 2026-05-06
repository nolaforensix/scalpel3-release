#!/usr/bin/env python3
"""
validate_photorec.py

Validates PhotoRec recovered files against ground-truth .key file using block mappings.

Categories
----------
- Recovered perfectly: Blocks map to correct GT file, SHA256 matches, length matches.
- Recovered incorrectly: Blocks map to a GT file, but SHA256/length mismatch.
- Not recovered: GT file has no corresponding recovered file.

Final lines: CORRECT + FAILED == number of GT files in universe.
- CORRECT = Recovered perfectly
- FAILED  = Recovered incorrectly + Not recovered
"""
import argparse
import concurrent.futures
import hashlib
import os
import re
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Set

# ------------------------ Key loading ------------------------

def load_key_file(path: Path) -> Tuple[Dict[str, List[Tuple[int, int]]], Dict[int, Tuple[str, int]], int]:
    """
    Parse the .key file and build:
      - path_to_seq: PATH -> list of (idx, phys) for HEADER/FILE rows (idx >= 0), sorted by idx.
      - phys_to_entry: phys -> (PATH, idx) for HEADER/FILE rows.
    Also parse mandatory BLOCKSIZE and return it.
    """
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except Exception as e:
        raise ValueError(f"Failed to read key file {path}: {e}")

    # Robust BLOCKSIZE parse
    block_size: Optional[int] = None
    for raw in text.splitlines():
        low = raw.lower()
        if ("blocksize" in low) or ("block" in low and "size" in low):
            m = re.search(r"(\d+)", raw.replace(",", ""))
            if m:
                try:
                    val = int(m.group(1))
                    if val > 0:
                        block_size = val
                        break
                except Exception:
                    pass
    if block_size is None:
        raise ValueError("Missing BLOCKSIZE in key file")

    # Parse mapping lines
    line_re = re.compile(
        r"""\[\s*(?P<type>[A-Z]+)\s*\|\s*(?P<path>.*?)\s*\|\s*(?P<idx>-?\d+)\s*\]\s*(?P<phys>\d+)\s*$"""
    )

    path_to_seq: Dict[str, List[Tuple[int, int]]] = {}
    phys_to_entry: Dict[int, Tuple[str, int]] = {}

    for raw in text.splitlines():
        m = line_re.search(raw)
        if not m:
            continue
        typ = m.group("type")
        fpath = m.group("path")
        try:
            idx = int(m.group("idx"))
            phys = int(m.group("phys"))
        except Exception:
            continue
        if typ not in ("HEADER", "FILE") or idx < 0:
            continue
        path_to_seq.setdefault(fpath, []).append((idx, phys))
        phys_to_entry[phys] = (fpath, idx)

    for fpath in path_to_seq:
        path_to_seq[fpath].sort(key=lambda t: t[0])

    if not path_to_seq:
        raise ValueError(f"No HEADER/FILE sequences parsed from key {path}")

    return path_to_seq, phys_to_entry, block_size

# ------------------------ FRG parsing ------------------------

def load_frg_list(path: Path) -> Tuple[Optional[int], Optional[str], List[str], Dict[str, bool]]:
    """
    Parse .frg with C block comment stripping; return (blocksize, outputfile, [FILE: ...], fragmentation_status).
    fragmentation_status is a dict: filepath -> is_fragmented (True if file has GAP/OUTOFORDER/MISSING/FRAGMENTED:TRUE)
    """
    try:
        text = path.read_text(encoding='utf-8', errors='ignore')
    except Exception:
        return None, None, [], {}
    # Remove /* ... */ while preserving line count
    text = re.sub(r'/\*.*?\*/', lambda m: '\n' * m.group(0).count('\n'), text, flags=re.S)

    bs: Optional[int] = None
    of: Optional[str] = None
    files: List[str] = []
    fragmentation: Dict[str, bool] = {}
    
    current_file: Optional[str] = None
    current_is_fragmented = False
    
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith('#'):
            continue
        lo = line.lower()
        
        if lo.startswith('blocksize'):
            m = re.search(r'(\d+)', line)
            if m:
                try:
                    bs = int(m.group(1))
                except Exception:
                    pass
        elif lo.startswith('outputfile'):
            of = line.split(':', 1)[1].strip() if ':' in line else None
        elif lo.startswith('file'):
            # Save previous file's status
            if current_file is not None:
                fragmentation[current_file] = current_is_fragmented
            
            # Start new file
            val = line.split(':', 1)[1].strip() if ':' in line else ''
            if val:
                current_file = val
                current_is_fragmented = False  # Reset for new file
                files.append(val)
        elif current_file is not None:
            # Check for fragmentation indicators
            if lo.startswith('fragmented:'):
                # Parse FRAGMENTED: TRUE/FALSE
                if 'true' in lo:
                    current_is_fragmented = True
            elif lo.startswith('gap') or lo.startswith('outoforder') or lo.startswith('missing'):
                # Any GAP, OUTOFORDER, or MISSING means fragmented
                current_is_fragmented = True
        elif lo.startswith('stop'):
            break
    
    # Save last file's status
    if current_file is not None:
        fragmentation[current_file] = current_is_fragmented
    
    return bs, of, files, fragmentation

# ------------------------ GT path resolution ------------------------

def resolve_gt_path(fpath_str: str, gt_root: Optional[Path], key_dir: Path) -> Optional[Path]:
    """Try absolute, then gt_root/basename, gt_root/full, then relative to key_dir."""
    fp = Path(fpath_str)
    if fp.is_absolute() and fp.exists():
        return fp
    if gt_root is not None:
        c1 = gt_root / fp.name
        if c1.exists():
            return c1.resolve()
        c2 = gt_root / fp
        if c2.exists():
            return c2.resolve()
    c3 = (key_dir / fp).resolve()
    if c3.exists():
        return c3
    return None

# ------------------------ PhotoRec log parsing ------------------------

def parse_photorec_log_with_blocks(log_path: Path) -> Tuple[int, Dict[Path, Tuple[int, int]]]:
    """
    Parse PhotoRec log and return:
      - log_blocksize (int): The blocksize found in the log (often 512 for disk sectors)
      - file_blocks (dict): Path -> (start_block, end_block)
      
    Note: Block numbers in the log appear to be in disk sectors (typically 512 bytes),
    not in PhotoRec's carving blocksize (which might be 16384 or larger).
    """
    try:
        text = log_path.read_text(encoding="utf-8", errors="ignore")
    except Exception as e:
        raise ValueError(f"Failed to read PhotoRec log {log_path}: {e}")

    # Find blocksize - look for the first "blocksize=" after "Pass 0"
    # This is usually the disk's sector size (512 bytes)
    log_blocksize = None
    in_pass_0 = False
    for line in text.splitlines():
        if 'Pass 0' in line:
            in_pass_0 = True
        if in_pass_0:
            m = re.search(r'\bblocksize\s*=\s*(\d+)', line)
            if m:
                log_blocksize = int(m.group(1))
                break

    if log_blocksize is None:
        # Fallback: just find any blocksize
        for line in text.splitlines():
            m = re.search(r'\bblocksize\s*=\s*(\d+)', line)
            if m:
                log_blocksize = int(m.group(1))
                break

    if log_blocksize is None:
        raise ValueError("Could not find blocksize in PhotoRec log")

    # Parse file entries: /path/to/file.ext  start-end
    file_blocks: Dict[Path, Tuple[int, int]] = {}
    # Pattern: filepath followed by whitespace and block range
    pattern = re.compile(r'^(.+?)\s+(\d+)-(\d+)\s*$')
    
    for line in text.splitlines():
        line = line.strip()
        m = pattern.match(line)
        if m:
            filepath = Path(m.group(1))
            start_block = int(m.group(2))
            end_block = int(m.group(3))
            file_blocks[filepath] = (start_block, end_block)

    print(f"[info] PhotoRec log blocksize: {log_blocksize} bytes, found {len(file_blocks)} recovered files", file=sys.stderr)
    return log_blocksize, file_blocks

# ------------------------ Hashing ------------------------

def sha256_of_file(path: Path) -> Tuple[bool, str, int]:
    """Return (success, sha256_hex, file_size). On failure: (False, error_msg, 0)."""
    try:
        h = hashlib.sha256()
        size = 0
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
                size += len(chunk)
        return True, h.hexdigest(), size
    except Exception as e:
        return False, f"read-error:{e}", 0

# ------------------------ Validation ------------------------

def validate_recovered_file(
    rec_path: Path,
    start_block: int,
    end_block: int,
    log_blocksize: int,
    key_blocksize: int,
    block_to_gt: Dict[int, str],
    path_to_seq: Dict[str, List[Tuple[int, int]]],
    gt_root: Optional[Path],
    key_dir: Path
) -> Tuple[str, bool, str, Optional[str]]:
    """
    Validate a single recovered file.
    Returns: (filename, is_ok, message, gt_path_mapped)
    """
    filename = rec_path.name
    
    # Convert log blocks to key blocks if blocksizes differ
    if log_blocksize == key_blocksize:
        phys_start = start_block
        phys_end = end_block
    else:
        # Log block N in bytes = N * log_blocksize
        # Convert to key blocks: byte_offset / key_blocksize
        phys_start = (start_block * log_blocksize) // key_blocksize
        phys_end = (end_block * log_blocksize) // key_blocksize
    
    # Look up which GT file contains this starting block
    gt_path_str = block_to_gt.get(phys_start)
    
    if not gt_path_str:
        return (filename, False, f"start block {phys_start} (log block {start_block}) not in any GT file sequence", None)
    
    # Get expected sequence for this GT file
    seq_pairs = path_to_seq.get(gt_path_str, [])
    expected_blocks = [phys for idx, phys in seq_pairs]
    
    # Resolve GT file on disk
    gt_path = resolve_gt_path(gt_path_str, gt_root, key_dir)
    if gt_path is None or not gt_path.exists():
        return (filename, False, f"mapped to {gt_path_str} but GT file not found on disk", gt_path_str)
    
    # Get GT file size and hash
    ok_gt, gt_hash, gt_size = sha256_of_file(gt_path)
    if not ok_gt:
        return (filename, False, f"mapped to {gt_path_str} but failed to hash GT: {gt_hash}", gt_path_str)
    
    # Get recovered file size and hash
    ok_rec, rec_hash, rec_size = sha256_of_file(rec_path)
    if not ok_rec:
        return (filename, False, f"mapped to {gt_path_str} but failed to hash recovered file: {rec_hash}", gt_path_str)
    
    # Check for mismatches
    if rec_size != gt_size:
        reason = f"length mismatch: recovered={rec_size} bytes, groundtruth={gt_size} bytes"
        return (filename, False, f"mapped to {gt_path_str} - {reason}", gt_path_str)
    
    if rec_hash != gt_hash:
        reason = f"sha256 mismatch: recovered={rec_hash}, groundtruth={gt_hash}"
        return (filename, False, f"mapped to {gt_path_str} - {reason}", gt_path_str)
    
    # Success!
    return (filename, True, f"matches {gt_path_str}", gt_path_str)

# ------------------------ Main ------------------------

def main():
    ap = argparse.ArgumentParser(description="Validate PhotoRec results against .key ground truth using block mappings.")
    ap.add_argument("--key", required=True, type=Path, help="Path to the key file (.img.key).")
    ap.add_argument("--photorec-log", required=True, type=Path, help="Path to photorec.log.")
    ap.add_argument("--gt-root", type=Path, default=None, help="Root directory to resolve ground-truth paths from the key.")
    ap.add_argument("--frg", type=Path, default=None, help="Optional .frg list: limits GT set to these FILE: items.")
    ap.add_argument("--verbose", action="store_true", help="Print [OK] lines for matched recoveries.")
    ap.add_argument("--summary-only", action="store_true", help="Only print the final summary table and CORRECT/FAILED lines.")
    ap.add_argument("--jobs", type=int, default=os.cpu_count() or 8, help="Parallel workers for hashing.")
    args = ap.parse_args()

    key_path = args.key
    key_dir = key_path.parent

    # Load key file
    try:
        path_to_seq, phys_to_entry, key_blocksize = load_key_file(key_path)
    except Exception as e:
        print(f"[fatal] Failed to load key: {e}", file=sys.stderr)
        sys.exit(1)

    # FRG filtering (optional)
    frg_paths: Optional[Set[str]] = None
    fragmentation_status: Dict[str, bool] = {}
    if args.frg:
        _, _, flist, fragmentation_status = load_frg_list(args.frg)
        frg_file_list = flist  # Preserve duplicates for counting
        frg_paths = set(flist)  # For membership checks
        print(f"[info] Loaded fragmentation status for {len(fragmentation_status)} files from FRG", file=sys.stderr)
        frag_count = sum(1 for is_frag in fragmentation_status.values() if is_frag)
        print(f"[info] Fragmented: {frag_count}, Non-fragmented: {len(fragmentation_status) - frag_count}", file=sys.stderr)
        
        # Check for duplicate file paths in FRG
        if len(flist) != len(frg_paths):
            print(f"[warn] FRG contains {len(flist) - len(frg_paths)} duplicate file path(s)", file=sys.stderr)
            from collections import Counter
            counts = Counter(flist)
            for path, count in counts.items():
                if count > 1:
                    print(f"[warn]   {path} appears {count} times", file=sys.stderr)

    # GT universe: preserve duplicates from FRG for correct counting
    if frg_paths is not None:
        universe_gt_list = frg_file_list  # List with duplicates
        universe_gt: Set[str] = frg_paths  # Set for membership
    else:
        universe_gt: Set[str] = set(path_to_seq.keys())
        universe_gt_list = list(universe_gt)

    # Parse PhotoRec log
    try:
        log_blocksize, file_blocks = parse_photorec_log_with_blocks(args.photorec_log)
    except Exception as e:
        print(f"[fatal] Failed to parse PhotoRec log: {e}", file=sys.stderr)
        sys.exit(1)

    print(f"[info] Key blocksize: {key_blocksize}, Log blocksize: {log_blocksize}", file=sys.stderr)
    if log_blocksize != key_blocksize:
        print(f"[info] Block conversion will be applied: log block N → key block {log_blocksize}/{key_blocksize}*N", file=sys.stderr)

    # Build efficient block-to-GT-file lookup (for faster validation)
    print(f"[info] Building block lookup table from {len(path_to_seq)} GT files...", file=sys.stderr)
    block_to_gt: Dict[int, str] = {}
    for gt_path, seq_pairs in path_to_seq.items():
        for idx, phys in seq_pairs:
            block_to_gt[phys] = gt_path
    print(f"[info] Block lookup table built with {len(block_to_gt)} blocks", file=sys.stderr)

    # Validate each recovered file
    results: List[Tuple[str, bool, str, Optional[str]]] = []
    gt_perfect_instances: List[str] = []  # GT file instances recovered perfectly
    gt_attempted_instances: List[str] = []  # GT file instances that had any recovery attempt
    
    # Track which start_block each result corresponds to for deduplication
    result_start_blocks: Dict[str, int] = {}  # filename -> start_block

    total_files = len(file_blocks)
    print(f"[info] Validating {total_files} recovered files with {args.jobs} workers...", file=sys.stderr)

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as ex:
        futures = []
        for rec_path, (start_block, end_block) in file_blocks.items():
            if not rec_path.exists():
                print(f"[warn] Log references {rec_path} but file not found", file=sys.stderr)
                continue
            result_start_blocks[rec_path.name] = start_block  # Store for later
            fut = ex.submit(
                validate_recovered_file,
                rec_path, start_block, end_block,
                log_blocksize, key_blocksize,
                block_to_gt, path_to_seq,
                args.gt_root, key_dir
            )
            futures.append(fut)
        
        # Deduplicate GT instances
        seen_instances: Set[Tuple[str, int]] = set()
        
        completed = 0
        for fut in concurrent.futures.as_completed(futures):
            filename, is_ok, msg, gt_mapped = fut.result()
            results.append((filename, is_ok, msg, gt_mapped))
            
            if gt_mapped:
                # Get the start_block for this recovered file
                rec_start_block = result_start_blocks.get(filename)
                if rec_start_block is not None:
                    # Convert to physical block if needed
                    if log_blocksize == key_blocksize:
                        phys_start = rec_start_block
                    else:
                        phys_start = (rec_start_block * log_blocksize) // key_blocksize
                    
                    # Deduplicate based on (gt_path, physical_start_block)
                    instance_key = (gt_mapped, phys_start)
                    if instance_key not in seen_instances:
                        seen_instances.add(instance_key)
                        gt_attempted_instances.append(gt_mapped)
                        if is_ok:
                            gt_perfect_instances.append(gt_mapped)
            
            completed += 1
            if completed % 500 == 0 or completed == total_files:
                print(f"[progress] {completed}/{total_files} files validated ({100*completed//total_files}%)...", file=sys.stderr)

    print(f"[info] Validation complete. Processing results...", file=sys.stderr)

    # Sort results
    results.sort(key=lambda x: x[0].lower())

    # Print results
    if not args.summary_only:
        for filename, is_ok, msg, gt_mapped in results:
            if is_ok:
                if args.verbose:
                    print(f"[OK]   {filename} - {msg}")
            else:
                print(f"[FAIL] {filename} - {msg}")

    # Category counts (counting GT file instances, not unique paths)
    gt_perfect_set = set(gt_perfect_instances)
    gt_attempted_set = set(gt_attempted_instances)
    
    recovered_perfectly = len(gt_perfect_instances)
    recovered_incorrectly = len(gt_attempted_instances) - len(gt_perfect_instances)
    not_recovered_list = [gt for gt in universe_gt_list if gt not in gt_attempted_set]
    not_recovered_count = len(not_recovered_list)
    total_gt = len(universe_gt_list)
    
    if not args.summary_only and not_recovered_list:
        print("\nNot recovered (no associated recovered file):")
        # Display unique paths, sorted
        for gt in sorted(set(not_recovered_list)):
            print("   ", gt)

    # Break down by fragmentation status
    def count_by_frag(file_list) -> Tuple[int, int]:
        """Return (fragmented_count, non_fragmented_count) - counts instances"""
        frag = sum(1 for f in file_list if fragmentation_status.get(f, False))
        non_frag = len(file_list) - frag
        return frag, non_frag

    # Analyze for duplicate instances - summarize by file type
    duplicate_counts_by_type: Dict[str, int] = {}
    if not args.summary_only:
        # Count duplicate instances in universe_gt_list
        from collections import Counter
        path_counts = Counter(universe_gt_list)
        
        # For each path that appears more than once, count the duplicates by file type
        for path, count in path_counts.items():
            if count > 1:
                ftype = path.split('/')[1] if len(path.split('/')) >= 2 else Path(path).suffix.lstrip('.')
                if not ftype:
                    ftype = 'unknown'
                duplicate_counts_by_type[ftype] = duplicate_counts_by_type.get(ftype, 0) + (count - 1)  # count - 1 = number of duplicates
        
        if duplicate_counts_by_type:
            print(f"\n[info] Duplicate file instances by type:", file=sys.stderr)
            for ftype in sorted(duplicate_counts_by_type.keys()):
                print(f"[info]   {ftype.upper()}: {duplicate_counts_by_type[ftype]} duplicate instances", file=sys.stderr)

    # Calculate incorrect instances list
    incorrect_instances = [gt for gt in gt_attempted_instances if gt not in gt_perfect_set]
    
    perfect_frag, perfect_nonfrag = count_by_frag(gt_perfect_instances)
    incorrect_frag, incorrect_nonfrag = count_by_frag(incorrect_instances)
    notrecov_frag, notrecov_nonfrag = count_by_frag(not_recovered_list)
    total_frag, total_nonfrag = count_by_frag(universe_gt_list)

    # Summary
    print("\nSummary:")
    print(f"  GT files (universe):      {total_gt} (fragmented: {total_frag}, non-fragmented: {total_nonfrag})")
    print(f"  Recovered perfectly:      {recovered_perfectly} (fragmented: {perfect_frag}, non-fragmented: {perfect_nonfrag})")
    print(f"  Recovered incorrectly:    {recovered_incorrectly} (fragmented: {incorrect_frag}, non-fragmented: {incorrect_nonfrag})")
    print(f"  Not recovered:            {not_recovered_count} (fragmented: {notrecov_frag}, non-fragmented: {notrecov_nonfrag})")

    # Final required lines
    correct = recovered_perfectly
    failed = recovered_incorrectly + not_recovered_count
    
    print(f"\nCORRECT: {correct} (fragmented: {perfect_frag}, non-fragmented: {perfect_nonfrag})")
    print(f"FAILED:  {failed} (fragmented: {incorrect_frag + notrecov_frag}, non-fragmented: {incorrect_nonfrag + notrecov_nonfrag})")
    
    # Per-file-type breakdown
    print("\nPer-file-type summary:")
    
    # Extract file types from paths
    def get_file_type(path: str) -> str:
        """Extract file type from path like SCALPEL3_DATA/jpg/file.jpg -> jpg"""
        parts = path.split('/')
        if len(parts) >= 2:
            return parts[1]  # Assumes format: prefix/type/filename
        # Fallback to extension
        ext = Path(path).suffix.lstrip('.')
        return ext if ext else 'unknown'
    
    # Count by file type for each category
    from collections import defaultdict
    type_counts: Dict[str, Dict[str, int]] = defaultdict(lambda: {'perfect': 0, 'incorrect': 0, 'not_recovered': 0})
    
    for f in gt_perfect_instances:
        ftype = get_file_type(f)
        type_counts[ftype]['perfect'] += 1
    
    for f in incorrect_instances:
        ftype = get_file_type(f)
        type_counts[ftype]['incorrect'] += 1
    
    for f in not_recovered_list:
        ftype = get_file_type(f)
        type_counts[ftype]['not_recovered'] += 1
    
    # Print sorted by file type
    for ftype in sorted(type_counts.keys()):
        counts = type_counts[ftype]
        print(f"  {ftype.upper()}: recovered perfectly: {counts['perfect']}, "
              f"recovered incorrectly: {counts['incorrect']}, "
              f"not recovered: {counts['not_recovered']}")

    sys.exit(0 if failed == 0 else 1)

if __name__ == "__main__":
    main()
