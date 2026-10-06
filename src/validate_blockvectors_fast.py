#!/usr/bin/env python3
"""
validate_blockvectors_fast.py

Validates blockvector *.txt files against a ground-truth .key file and reports:

Categories
----------
- Recovered perfectly: blocks, length, and SHA256 all match the ground truth.
- Recovered incorrectly: mapped to a GT file but length/order/SHA mismatch.
- Not recovered: GT file mentioned in .key/.frg had no associated blockvector.

Final lines (guarantee): CORRECT + FAILED == number of GT files in the universe.
- CORRECT = Recovered perfectly
- FAILED  = Recovered incorrectly + Not recovered

Behavior
--------
- Reads mandatory BLOCKSIZE from the .key (robust parse).
- Infers the disk image path from the .key by stripping the '.key' suffix.
- Extracts reconstructed bytes on any failure, using the basename from the .key
  path, placed under --out-dir if provided, else alongside the .txt.
- Trims extracted files to the blockvector Length.
- Hashing policy:
    * Reconstructed: SHA256 over the first N bytes (N = blockvector Length).
    * Ground truth:  SHA256 over the full on-disk file size.
- Error if blockvector Length != ground-truth file size.
- Reports GT files not recovered (no blockvector mapped).
- With --fail-on-invalid-validated, exits nonzero if a file in VALIDATED does
  not match any ground-truth SHA256, a proven ground-truth prefix, or exact
  embedded content within a ground-truth file.
- Byte-exact snapshots retained in PROMISING are Category 1 perfect recoveries,
  just like byte-exact files written to VALIDATED.
- With --require-all-exact, exits nonzero unless every ground-truth file has a
  byte-exact recovered snapshot.
- With --require-exact-at-least N, exits nonzero unless at least N distinct
  ground-truth files have a byte-exact recovered snapshot.

Ground truth resolution
-----------------------
- Ground-truth file paths are used EXACTLY as recorded in the .key:
    * If absolute -> used as-is.
    * If relative -> resolved relative to the .key file's directory.

Optional .frg universe
----------------------
- If you pass --frg file.frg, the set of GT files considered for the
  summary (Correct/Failed/Not recovered) comes from the FRG's FILE:
  entries. Otherwise, the universe is all paths seen in the .key.
- The FRG's BLOCKSIZE/OUTPUTFILE are checked vs .key/inferred image with warnings.
"""

import argparse
import concurrent.futures
import glob
import hashlib
import os
import re
import struct
import sys
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Set


# ---------- Blockmap dedup support ---------- #

def load_exemplar_map(blockmap_path: Path) -> Dict[int, int]:
    """
    Parse a scalpel3 blockmap and return a dict mapping every block number
    to its exemplar block number. Non-duplicate blocks map to themselves and
    zero blocks map to the negative sentinel used for unmapped zero-filled
    blockvector slots.

    Blockmap layout (from blockmap.h):
        [blocksize:u32] [num_blocks:u64]
        [coverage bitmap]  - 1 bit per block
        [dedup bitmap]     - 1 bit per block
        [exemplar bitmap]  - 1 bit per block
        [zero bitmap]      - 1 bit per block
        [refcounts R]      - int64 per block  (for non-exemplar dupes, R[j] = exemplar)
        [reservations T]   - int64 per block
    """
    data = blockmap_path.read_bytes()
    blocksize = struct.unpack_from('<I', data, 0)[0]
    num_blocks = struct.unpack_from('<Q', data, 4)[0]

    bitmap_bytes = (num_blocks + 7) // 8
    # Header: blocksize(4) + numblocks(8) + start_block(8) + end_block(8) = 28 bytes
    bitmaps_start = 28
    dedup_offset = bitmaps_start + bitmap_bytes          # D bitmap (after C)
    exemplar_offset = dedup_offset + bitmap_bytes        # E bitmap (after D)
    zero_offset = exemplar_offset + bitmap_bytes         # Z bitmap (after E)
    # On-disk order after bitmaps: T (reservations), then R (refcounts)
    reservations_offset = bitmaps_start + 4 * bitmap_bytes
    refcount_offset = reservations_offset + 8 * num_blocks  # R follows T

    def bit_set(bitmap_start, bit_index):
        byte_idx = bitmap_start + bit_index // 8
        return (data[byte_idx] >> (bit_index % 8)) & 1

    exemplar_map: Dict[int, int] = {}
    for j in range(num_blocks):
        if bit_set(zero_offset, j):
            exemplar_map[j] = -1
            continue
        d = bit_set(dedup_offset, j)
        e = bit_set(exemplar_offset, j)
        if d and not e:
            # Non-exemplar duplicate: R[j] holds the exemplar block number
            r_off = refcount_offset + j * 8
            exemplar_map[j] = struct.unpack_from('<q', data, r_off)[0]
        else:
            # Exemplar or non-duplicate: maps to itself
            exemplar_map[j] = j

    return exemplar_map


def blocks_equivalent(a: int, b: int, exemplar_map: Optional[Dict[int, int]]) -> bool:
    """Return True for identical, duplicate, or equivalent zero-filled slots."""
    if a == b:
        return True
    if exemplar_map is None:
        return False
    return exemplar_map.get(a, a) == exemplar_map.get(b, b)


def find_exact_embedded_offset(candidate_path: Path, ground_truth_path: Path,
                               start_index: int, block_size: int) -> Optional[int]:
    """Find candidate bytes that begin within the indicated ground-truth block."""
    try:
        candidate_size = candidate_path.stat().st_size
        ground_truth_size = ground_truth_path.stat().st_size
        if candidate_size == 0:
            return None

        search_start = start_index * block_size
        if search_start >= ground_truth_size:
            return None
        search_length = min(block_size, ground_truth_size - search_start)

        with candidate_path.open("rb") as candidate_handle:
            prefix = candidate_handle.read(min(candidate_size, 64))
        with ground_truth_path.open("rb") as ground_truth_handle:
            ground_truth_handle.seek(search_start)
            search_data = ground_truth_handle.read(search_length)

        relative_offset = search_data.find(prefix)
        while relative_offset >= 0:
            candidate_offset = search_start + relative_offset
            if candidate_offset + candidate_size <= ground_truth_size:
                exact = True
                with candidate_path.open("rb") as candidate_handle, \
                        ground_truth_path.open("rb") as ground_truth_handle:
                    ground_truth_handle.seek(candidate_offset)
                    while True:
                        candidate_data = candidate_handle.read(1024 * 1024)
                        if not candidate_data:
                            break
                        if ground_truth_handle.read(len(candidate_data)) != candidate_data:
                            exact = False
                            break
                if exact:
                    return candidate_offset
            relative_offset = search_data.find(prefix, relative_offset + 1)
    except OSError:
        return None

    return None


# ---------- FRG support ---------- #

def frg_argument(value: str) -> str:
    """Apply fragmentator's quoting and single-pass environment expansion."""
    value = value.strip()
    if value.startswith('"'):
        end = value.find('"', 1)
        if end < 0:
            raise ValueError('Unterminated quoted FRG argument')
        value = value[1:end]

    def substitute(match: re.Match) -> str:
        name = match.group(1)
        if name is None or not re.fullmatch(r'[A-Za-z_][A-Za-z_0-9]*', name):
            raise ValueError(f'Invalid FRG environment reference: {match.group(0)}')
        if name not in os.environ:
            raise ValueError(f'FRG environment variable {name!r} is not set')
        return os.environ[name]

    value = re.sub(r'\$\{([^}]*)\}|\$\{', substitute, value)
    if len(os.fsencode(value)) > 2048:
        raise ValueError('Expanded FRG argument exceeds 2048 bytes')
    return value


def load_frg_list(path: Path) -> Tuple[Optional[int], Optional[str], List[str], Dict[str, bool], Dict[str, List[int]]]:
    """
    Parse a .frg file. Returns (blocksize, outputfile, file_list, fragmentation_status, missing_blocks).
      - BLOCKSIZE: first integer after 'BLOCKSIZE:' line if present.
      - OUTPUTFILE: value after 'OUTPUTFILE:' if present.
      - file_list: FILE arguments after quoting and environment expansion.
      - fragmentation_status: dict mapping filepath -> is_fragmented (True if GAP/OUTOFORDER/MISSING/FRAGMENTED:TRUE)
      - missing_blocks: dict mapping filepath -> list of MISSING block indices
    Robust against extra whitespace/comments and 'stop' markers.
    """
    try:
        text = path.read_text(encoding='utf-8', errors='ignore')
    except Exception:
        return None, None, [], {}, {}
    bs: Optional[int] = None
    of: Optional[str] = None
    files: List[str] = []
    fragmentation: Dict[str, bool] = {}
    missing_blocks: Dict[str, List[int]] = {}
    
    current_file: Optional[str] = None
    current_is_fragmented = False
    current_missing_blocks: List[int] = []
    comment = 0
    
    for line_number, raw in enumerate(text.splitlines(), 1):
        quoted = False
        for index, character in enumerate(raw):
            if character == '"':
                quoted = not quoted
            elif character == '#' and not quoted:
                raw = raw[:index]
                break
        line = raw.strip()
        if line.startswith('/*'):
            comment += 1
            continue
        if line.startswith('*/'):
            comment -= 1
            continue
        if not line or line.startswith('#') or comment > 0:
            continue
        lo = line.lower()

        # Check for STOP first - takes priority over everything
        if lo.startswith('stop'):
            break

        key, separator, argument = line.partition(':')
        try:
            argument = frg_argument(argument) if separator else ''
        except ValueError as error:
            raise ValueError(f'{path}:{line_number}: {error}') from error
        lo = key.strip().lower()
        
        if lo == 'blocksize':
            m = re.search(r'(\d+)', argument)
            if m:
                try:
                    bs = int(m.group(1))
                except Exception:
                    pass
        elif lo == 'outputfile':
            of = argument if separator else None
        elif lo == 'file':
            # Save previous file's status
            if current_file is not None:
                fragmentation[current_file] = current_is_fragmented
                if current_missing_blocks:
                    missing_blocks[current_file] = current_missing_blocks.copy()
            
            # Start new file
            val = argument
            if val:
                current_file = val
                current_is_fragmented = False  # Reset for new file
                current_missing_blocks = []
                files.append(val)
        elif current_file is not None:
            # Check for fragmentation indicators
            if lo == 'fragmented':
                # Parse FRAGMENTED: TRUE/FALSE
                if argument.lower() == 'true':
                    current_is_fragmented = True
            elif lo == 'missing':
                # Parse MISSING: block_index, ranges, or comma-separated lists
                # Format: "MISSING: 1", "MISSING: 10-20", "MISSING: 1, 3, 5, 10-20"
                current_is_fragmented = True
                # Extract block indices or ranges
                if separator:
                    try:
                        value = argument
                        # Split by comma for lists like "1, 3, 5, 10-20"
                        elements = [elem.strip() for elem in value.split(',')]
                        for elem in elements:
                            if '-' in elem:
                                # Range format: "26-29"
                                start, end = elem.split('-', 1)
                                start_idx = int(start.strip())
                                end_idx = int(end.strip())
                                # Add all blocks in range (inclusive)
                                for block_idx in range(start_idx, end_idx + 1):
                                    current_missing_blocks.append(block_idx)
                            else:
                                # Single block format: "10"
                                block_idx = int(elem)
                                current_missing_blocks.append(block_idx)
                    except ValueError:
                        pass  # Ignore malformed MISSING lines
            elif lo in ('gap', 'outoforder'):
                # Any GAP or OUTOFORDER means fragmented
                current_is_fragmented = True
    
    # Save last file's status
    if current_file is not None:
        fragmentation[current_file] = current_is_fragmented
        if current_missing_blocks:
            missing_blocks[current_file] = current_missing_blocks.copy()
    
    return bs, of, files, fragmentation, missing_blocks


# ---------- Directory Finding ---------- #

def find_all_txt_files_recursive(base_dir: Path, subdir_name: str) -> Tuple[List[Path], int]:
    """
    Find all .txt files in all subdirectories named 'subdir_name' under base_dir.
    E.g., find all VALIDATED/**/*.txt files.

    Returns (txt_files, non_txt_file_count). The non-.txt count is used to detect
    the case where scalpel3 was run without -b: carved files were written but
    the companion .BLOCKVECTOR.txt metadata files this validator needs were not.
    """
    files: List[Path] = []
    seen = set()
    non_txt_count = 0

    # Find all directories with this name recursively
    for item in base_dir.rglob(subdir_name):
        if item.is_dir():
            # Walk all regular files; collect .txt, count the rest
            for entry in item.rglob("*"):
                if not entry.is_file():
                    continue
                if entry.suffix == ".txt":
                    if entry not in seen:
                        files.append(entry)
                        seen.add(entry)
                else:
                    non_txt_count += 1

    return files, non_txt_count


def warn_missing_blockvector_txt(category: str, txt_count: int, non_txt_count: int) -> bool:
    """
    If a category dir (VALIDATED/PROMISING/INPROGRESS) has carved files but no
    .BLOCKVECTOR.txt companions, print a clear warning and return True. The
    caller uses the return value to print the warning at most once.
    """
    if txt_count > 0 or non_txt_count == 0:
        return False
    print()
    print("=" * 80)
    print(f"WARNING: {category}/ contains {non_txt_count} carved file(s) but no")
    print(f".BLOCKVECTOR.txt metadata files. This validator needs the .txt")
    print(f"companion files that scalpel3 only writes when invoked with '-b'.")
    print()
    print(f"Re-run scalpel3 with -b added, e.g.:")
    print(f"    scalpel3 -b ... <image>")
    print()
    print(f"Without -b, all GT files will be reported as Category 6 (not recovered)")
    print(f"even when scalpel3 carved them successfully.")
    print("=" * 80)
    print()
    return True


# ---------- Regexes ---------- #

# Forgiving: "Length: 12345 bytes" (case-insensitive, flexible spaces)
LENGTH_RE = re.compile(r"(?i)\bLength\s*:\s*(\d+)\s*bytes\b")
CAPACITY_RE = re.compile(r"(?i)\bCapacity\s*:\s*(\d+)\s*blocks\b")


# ---------- Key loading ---------- #

def load_key_file(path: Path) -> Tuple[Dict[str, List[Tuple[int, int]]], Dict[int, Tuple[str, int]], int, bool]:
    """
    Parse the .key file and build:
      - path_to_seq: PATH -> list of (idx, phys) for HEADER/FILE rows (idx >= 0), sorted by idx.
      - phys_to_entry: phys -> (PATH, idx) for HEADER/FILE rows.
    Also parse mandatory BLOCKSIZE and the no_frag flag (set when fragmentator
    was run with -c, meaning all per-file fragmentation directives were stripped).
    Returns (path_to_seq, phys_to_entry, block_size, no_frag).
    """
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except Exception as e:
        raise ValueError(f"Failed to read key file {path}: {e}")

    # Robust BLOCKSIZE parse: accept "BLOCKSIZE:" or "Block size:" with any spacing/tabs,
    # optional "bytes", any casing, stray punctuation. Take first integer on that line.
    block_size: Optional[int] = None
    no_frag: bool = False
    for raw in text.splitlines():
        low = raw.lower()
        # "no_frag:             TRUE" header line written by fragmentator
        if "no_frag" in low:
            if re.search(r"\btrue\b", low):
                no_frag = True
        if ("blocksize" in low) or ("block" in low and "size" in low):
            m = re.search(r"(\d+)", raw.replace(",", ""))
            if m:
                try:
                    val = int(m.group(1))
                    if val > 0 and block_size is None:
                        block_size = val
                except Exception:
                    pass
    if block_size is None:
        raise ValueError("Missing BLOCKSIZE in key file")

    # Parse mapping lines like: "... [ HEADER | PATH | 0 ] 13272"
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

    return path_to_seq, phys_to_entry, block_size, no_frag


# ---------- Blockvector parsing (fixed format) ---------- #

def extract_actual_blocks(text: str) -> Tuple[List[int], str]:
    """
    Extract actual block numbers from a fixed-format blockvector file:

      Expected structure:
        - A header line containing "Index" and "Actual" (case-insensitive).
        - Following rows where each line contains at least 3 integers.
          The first integer is the logical index and the second is the actual
          block number.
        - Parsing stops when a blank/short/non-conforming line is hit.

      Blockvector listings omit unmapped slots. Preserve their logical indices
      by representing each omitted slot as -1; Scalpel3 materializes those
      slots as zero-filled blocks.

      Returns (sequence, method). If not found, returns ([], "bad-format").
    """
    lines = text.splitlines()
    header_re = re.compile(r"(?i)\bIndex\b.*\bActual\b")
    capacity_match = CAPACITY_RE.search(text)
    capacity = int(capacity_match.group(1)) if capacity_match else 0
    indexed: Dict[int, int] = {}
    for i, line in enumerate(lines):
        if header_re.search(line):
            for row in lines[i + 1:]:
                ints = [int(x) for x in re.findall(r"-?\d+", row)]
                if len(ints) >= 3:
                    index = ints[0]
                    actual = ints[1]
                    if index < 0 or actual < -1:
                        return [], "bad-format"
                    indexed[index] = actual
                elif not row.strip():
                    break
                else:
                    if indexed:
                        break
                    else:
                        continue
            if not indexed:
                return [], "bad-format"
            logical_blocks = max(capacity, max(indexed) + 1)
            seq = [-1] * logical_blocks
            for index, actual in indexed.items():
                seq[index] = actual
            return seq, "fixed:Index-Actual"
    return ([], "bad-format")


def parse_blockvector(bv_path: Path) -> Tuple[Optional[int], Optional[List[int]]]:
    """Parse blockvector file and return (length, blocks) or (None, None) on error."""
    try:
        text = bv_path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return None, None
    
    # Extract Length
    m = LENGTH_RE.search(text)
    if not m:
        return None, None
    try:
        length = int(m.group(1))
    except Exception:
        return None, None
    
    # Extract blocks
    blocks, method = extract_actual_blocks(text)
    if not blocks:
        return None, None
    
    return length, blocks


def blocks_within_length(blocks: List[int], length: int,
                         block_size: int) -> List[int]:
    """Return only blockvector slots that contribute bytes to Length."""
    if length <= 0 or block_size <= 0:
        return []
    block_count = (length + block_size - 1) // block_size
    return blocks[:block_count]


# ---------- Hashing / Extraction helpers ---------- #

def sha256_of_file(path: Path, max_bytes: Optional[int] = None) -> Tuple[bool, str]:
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            if max_bytes is None:
                for chunk in iter(lambda: f.read(1024 * 1024), b""):
                    h.update(chunk)
            else:
                remaining = max_bytes
                while remaining > 0:
                    chunk = f.read(min(1024 * 1024, remaining))
                    if not chunk:
                        break
                    h.update(chunk)
                    remaining -= len(chunk)
        return True, h.hexdigest()
    except Exception as e:
        return False, f"read-error:{e}"


def sha256_from_image_blocks(image_path: Path, blocks: List[int], block_size: int, max_bytes: Optional[int]) -> Tuple[bool, str]:
    try:
        h = hashlib.sha256()
        fd = os.open(str(image_path), os.O_RDONLY)
        try:
            written = 0
            need = max_bytes
            zero_block = bytes(block_size)
            for b in blocks:
                if need is not None and written >= need:
                    break
                if b == -1:
                    chunk = zero_block
                elif b < -1:
                    return False, f"invalid negative block index: {b}"
                else:
                    off = b * block_size
                    try:
                        chunk = os.pread(fd, block_size, off)
                    except AttributeError:
                        os.lseek(fd, off, os.SEEK_SET)
                        chunk = os.read(fd, block_size)
                    if len(chunk) != block_size:
                        return False, f"short read at block {b} (wanted {block_size}, got {len(chunk)})"
                if need is None or need - written >= block_size:
                    h.update(chunk)
                    written += block_size
                else:
                    rem = need - written
                    h.update(chunk[:rem])
                    written += rem
                    break
        finally:
            os.close(fd)
        return True, h.hexdigest()
    except Exception as e:
        return False, f"hash-error:{e}"


def reconstructed_prefix_matches(image_path: Path, gt_path: Path,
                                 blocks: List[int], block_size: int,
                                 candidate_length: int,
                                 gt_size: int) -> bool:
    """Return whether the shorter byte extent is an exact source prefix."""
    compare_length = min(candidate_length, gt_size)
    if compare_length <= 0:
        return False
    ok_gt, gt_sha = sha256_of_file(gt_path, max_bytes=compare_length)
    ok_img, img_sha = sha256_from_image_blocks(
        image_path, blocks, block_size, compare_length
    )
    return ok_gt and ok_img and gt_sha == img_sha


def extract_blocks_to_file(image_path: Path, blocks: List[int], block_size: int, out_path: Path, desired_length: Optional[int] = None) -> Tuple[bool, str]:
    try:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(str(image_path), os.O_RDONLY)
        try:
            with open(out_path, "wb") as out:
                bytes_written = 0
                need = desired_length
                zero_block = bytes(block_size)
                for b in blocks:
                    if need is not None and bytes_written >= need:
                        break
                    if b == -1:
                        chunk = zero_block
                    elif b < -1:
                        return False, f"invalid negative block index: {b}"
                    else:
                        off = b * block_size
                        try:
                            chunk = os.pread(fd, block_size, off)
                        except AttributeError:
                            os.lseek(fd, off, os.SEEK_SET)
                            chunk = os.read(fd, block_size)
                        if len(chunk) != block_size:
                            return False, f"short read at block {b} (wanted {block_size}, got {len(chunk)})"
                    if need is None:
                        out.write(chunk)
                        bytes_written += len(chunk)
                    else:
                        rem = need - bytes_written
                        if rem <= 0:
                            break
                        if rem >= block_size:
                            out.write(chunk)
                            bytes_written += block_size
                        else:
                            out.write(chunk[:rem])
                            bytes_written += rem
                            break
        finally:
            os.close(fd)
        return True, (f"wrote {out_path} (trimmed to {desired_length} bytes)" if desired_length is not None else f"wrote {out_path}")
    except Exception as e:
        return False, f"extract error: {e}"


def _handle_failure_extraction(
    file_path: Path,
    actual_seq: List[int],
    reason: str,
    image_path: Path,
    block_size: int,
    out_root: Optional[Path],
    out_suffix: str,
    out_basename: Optional[str] = None,
    desired_length: Optional[int] = None,
    mapped_hint: Optional[str] = None,
    start_block: Optional[int] = None,
) -> Tuple[str, bool, str, Optional[str], Optional[int]]:
    # Name with key-derived basename if available; else default to txt-derived name
    if out_basename:
        out_name = out_basename
    else:
        out_name = Path(file_path.stem + out_suffix).name
    if out_root:
        out_root.mkdir(parents=True, exist_ok=True)
        out_path = out_root / out_name
    else:
        out_path = file_path.with_name(out_name)
    ok, msg = extract_blocks_to_file(image_path, actual_seq, block_size, out_path, desired_length=desired_length)
    if ok:
        return (str(file_path), False, f"{reason}; extracted -> {out_path}", mapped_hint, start_block)
    else:
        return (str(file_path), False, f"{reason}; extract failed: {msg}", mapped_hint, start_block)


# ---------- GT path resolution ---------- #

def resolve_gt_path(fpath_str: str, key_dir: Path) -> Tuple[Optional[Path], str]:
    """
    Resolve ground-truth path using ONLY the path recorded in the .key:
      1) If absolute and exists -> use it.
      2) Else, treat as relative to the key file's directory.
      3) Fallback: try relative to current working directory
      4) Otherwise -> not found.
    """
    fp = Path(fpath_str)
    tried: List[str] = []

    if fp.is_absolute():
        if fp.exists():
            return fp, "abs"
        tried.append(str(fp))

    cand = (key_dir / fp).resolve()
    if cand.exists():
        return cand, "key_dir+relative"
    tried.append(str(cand))
    
    # Fallback: try relative to cwd
    cand_cwd = Path(fpath_str)
    if cand_cwd.exists():
        return cand_cwd.resolve(), "cwd+relative"
    tried.append(str(cand_cwd.resolve()))

    return None, "not-found: " + " | ".join(tried)


# ---------- Discovery ---------- #

def find_txt_files(roots_or_patterns: List[str]) -> List[Path]:
    files: List[Path] = []
    seen = set()
    for pat in roots_or_patterns:
        matches = glob.glob(pat, recursive=True)
        if not matches:
            matches = [pat]
        for m in matches:
            rp = Path(m)
            if rp.is_dir():
                for p in rp.rglob("*.txt"):
                    if p.is_file():
                        key = str(p.resolve())
                        if key not in seen:
                            seen.add(key)
                            files.append(Path(key))
            elif rp.is_file() and rp.suffix.lower() == ".txt":
                key = str(rp.resolve())
                if key not in seen:
                    seen.add(key)
                    files.append(Path(key))
    return files


# ---------- Validation ---------- #

def validate_blockvector_file(
    file_path: Path,
    path_to_seq: Dict[str, List[Tuple[int, int]]],
    phys_to_entry: Dict[int, Tuple[str, int]],
    image_path: Path,
    block_size: int,
    out_root: Optional[Path],
    out_suffix: str,
    verbose: bool,
    key_dir: Path,
    exemplar_map: Optional[Dict[int, int]] = None,
) -> Tuple[str, bool, str, Optional[str], Optional[int]]:
    """
    Returns: (rel_name, is_ok, msg, mapped_path, start_block)
    start_block is None if no mapping, otherwise the physical block number
    """
    rel_name = str(file_path)
    try:
        text = file_path.read_text(encoding="utf-8", errors="ignore")
    except Exception as e:
        return (rel_name, False, f"read-error: {e}", None, None)

    # (1) Blockvector length (mandatory and used for reconstruction & output trimming)
    mlen = LENGTH_RE.search(text)
    if not mlen:
        return (rel_name, False, "blockvector missing Length header", None, None)
    try:
        bv_length = int(mlen.group(1))
        if bv_length < 0:
            raise ValueError
    except Exception:
        return (rel_name, False, "invalid blockvector Length", None, None)

    # (2) Extract blocks (fixed format)
    actual_seq, method = extract_actual_blocks(text)
    if not actual_seq:
        return (rel_name, False, "bad-format: expected a table with 'Index' and 'Actual' header and >=3 integers per row", None, None)
    actual_seq = blocks_within_length(actual_seq, bv_length, block_size)
    if not actual_seq:
        return (rel_name, False, "blockvector Length contains no blocks", None, None)

    # (3) Map start block to key path/index and align
    s0 = actual_seq[0]
    entry = phys_to_entry.get(s0)
    if not entry:
        return (rel_name, False, f"start-block {s0} not found in key (via {method})", None, None)
    fpath, idx0 = entry

    seq_pairs = path_to_seq.get(fpath, [])
    exp = [phys for idx, phys in seq_pairs]

    j = None
    for k, (idx, phys) in enumerate(seq_pairs):
        if idx == idx0:
            j = k
            break
    if j is None:
        try:
            j = exp.index(s0)
        except ValueError:
            return (rel_name, False, f"internal: start-block {s0} missing from its own path sequence", fpath, s0)

    if j + len(actual_seq) > len(exp):
        reason = f"length mismatch within file sequence: found {len(actual_seq)}, only {len(exp) - j} remain (via {method})"
        return _handle_failure_extraction(file_path, actual_seq, reason, image_path, block_size, out_root, out_suffix, out_basename=Path(fpath).name, desired_length=bv_length, mapped_hint=fpath, start_block=s0)

    for i, a in enumerate(actual_seq):
        if not blocks_equivalent(a, exp[j + i], exemplar_map):
            reason = f"mismatch at index {i}: found {a} expected {exp[j + i]} (via {method})"
            return _handle_failure_extraction(file_path, actual_seq, reason, image_path, block_size, out_root, out_suffix, out_basename=Path(fpath).name, desired_length=bv_length, mapped_hint=fpath, start_block=s0)

    # (4) Resolve GT path and sizes
    gt_candidate, how = resolve_gt_path(fpath, key_dir)
    if gt_candidate is None:
        reason = f"ground-truth path not found for {fpath} ({how})"
        return _handle_failure_extraction(file_path, actual_seq, reason, image_path, block_size, out_root, out_suffix, out_basename=Path(fpath).name, desired_length=bv_length, mapped_hint=fpath, start_block=s0)

    gt_path = gt_candidate
    try:
        gt_size = os.stat(gt_path).st_size
    except Exception as e:
        reason = f"ground-truth stat error for {gt_path}: {e}"
        return _handle_failure_extraction(file_path, actual_seq, reason, image_path, block_size, out_root, out_suffix, out_basename=Path(fpath).name, desired_length=bv_length, mapped_hint=fpath, start_block=s0)

    # (5) Hashes: reconstructed (bv_length), ground-truth (full file)
    ok_gt, gt_hash = sha256_of_file(gt_path, max_bytes=None)
    if not ok_gt:
        reason = f"ground-truth read error for {gt_path}: {gt_hash}"
        return _handle_failure_extraction(file_path, actual_seq, reason, image_path, block_size, out_root, out_suffix, out_basename=Path(fpath).name, desired_length=bv_length, mapped_hint=fpath, start_block=s0)

    ok_rec, rec_hash = sha256_from_image_blocks(image_path, actual_seq, block_size, max_bytes=bv_length)
    if not ok_rec:
        reason = f"reconstruction read error: {rec_hash}"
        return _handle_failure_extraction(file_path, actual_seq, reason, image_path, block_size, out_root, out_suffix, out_basename=Path(fpath).name, desired_length=bv_length, mapped_hint=fpath, start_block=s0)

    # (6) Enforce errors for size/sha mismatch
    if bv_length != gt_size:
        reason = f"length mismatch: blockvector={bv_length} bytes, groundtruth={gt_size} bytes"
        return _handle_failure_extraction(file_path, actual_seq, reason, image_path, block_size, out_root, out_suffix, out_basename=Path(fpath).name, desired_length=bv_length, mapped_hint=fpath, start_block=s0)

    if rec_hash != gt_hash:
        reason = f"sha256 mismatch: reconstructed={rec_hash} groundtruth={gt_hash}"
        return _handle_failure_extraction(file_path, actual_seq, reason, image_path, block_size, out_root, out_suffix, out_basename=Path(fpath).name, desired_length=bv_length, mapped_hint=fpath, start_block=s0)

    # All good
    return (rel_name, True, "", fpath, s0)


# ---------- Main ---------- #


def main() -> None:
    ap = argparse.ArgumentParser(description="Validate blockvectors with 6-category classification.")
    ap.add_argument("--key", required=True, type=Path, help="Path to .key file")
    ap.add_argument("--scalpel-dir", required=True, type=Path, help="Scalpel output directory")
    ap.add_argument("--frg", type=Path, default=None, help="Optional .frg file")
    ap.add_argument("--blockmap", required=True, type=Path, help="Blockmap file for dedup-aware comparison")
    ap.add_argument("--verbose", action="store_true", help="Verbose output")
    ap.add_argument(
        "--fail-on-invalid-validated",
        action="store_true",
        help="Exit nonzero if VALIDATED contains a file absent from ground truth",
    )
    ap.add_argument(
        "--require-all-exact",
        action="store_true",
        help="Exit nonzero unless every ground-truth file has an exact recovery",
    )
    ap.add_argument(
        "--require-exact-at-least",
        type=int,
        metavar="N",
        help="Exit nonzero unless at least N ground-truth files have an exact recovery",
    )
    args = ap.parse_args()

    if args.require_exact_at_least is not None and args.require_exact_at_least < 0:
        ap.error("--require-exact-at-least must be nonnegative")
    
    # Load key file
    print(f"[info] Loading key file: {args.key}")
    try:
        path_to_seq, phys_to_entry, block_size, no_frag = load_key_file(args.key)
    except Exception as e:
        print(f"[fatal] Failed to load key: {e}", file=sys.stderr)
        sys.exit(1)

    if no_frag:
        print(f"[info] Key reports no_frag=TRUE (fragmentator -c): treating all files as unfragmented")

    key_dir = args.key.parent
    image_path = args.key.with_suffix("")

    # Load FRG file
    missing_blocks_map: Dict[str, List[int]] = {}
    universe_files: Set[str] = set()
    fragmentation_status: Dict[str, bool] = {}

    if args.frg:
        print(f"[info] Loading FRG file: {args.frg}")
        try:
            frg_bs, frg_out, frg_files, fragmentation_status, missing_blocks_map = load_frg_list(args.frg)
        except ValueError as error:
            print(f"[fatal] Failed to load FRG: {error}", file=sys.stderr)
            sys.exit(1)
        universe_files = set(frg_files)
        print(f"[info] FRG: {len(frg_files)} files, {len(missing_blocks_map)} with MISSING blocks")
    else:
        universe_files = set(path_to_seq.keys())

    # If the image was generated with -c (no_frag), every per-file fragmentation
    # directive in the .frg was stripped during image creation. Override the FRG-
    # derived flags so reporting reflects what's actually on disk.
    if no_frag:
        fragmentation_status = {f: False for f in fragmentation_status}
        missing_blocks_map = {}
    
    # Load blockmap for dedup-aware comparison
    print(f"[info] Loading blockmap: {args.blockmap}")
    exemplar_map = load_exemplar_map(args.blockmap)
    print(f"[info] Blockmap: {len(exemplar_map)} blocks")

    # Calculate universe fragmentation totals
    total_fragmented = sum(1 for f in universe_files if fragmentation_status.get(f, False))
    total_unfragmented = len(universe_files) - total_fragmented
    
    # Initialize category lists
    cat1_perfect: Set[Tuple[str, int]] = set()
    cat2_length: List[Tuple[str, int, Path, int, int]] = []  # (gt, block, path, bv_len, gt_len)
    cat3_missing: List[Tuple[str, int, Path, int, int]] = []  # (gt, block, path, correct, expected)
    cat4_correct: List[Tuple[str, int, Path, int, int]] = []  # (gt, block, path, correct, expected)
    cat5_incorrect: List[Tuple[str, int, Path, int, int, int, int]] = []  # (gt, block, path, first_wrong, correct, expected, carved_count)
    tracked_pairs: Set[Tuple[str, int]] = set()
    exact_recovery_files: Set[str] = set()
    recognized_validated_prefixes: Set[Path] = set()
    nonroot_validated_origins: Dict[Path, Tuple[str, int]] = {}
    
    # Find all directories recursively
    warned_missing_b = False
    print(f"[info] Searching for VALIDATED directories...")
    validated_files, validated_non_txt = find_all_txt_files_recursive(args.scalpel_dir, "VALIDATED")
    print(f"[info] Found {len(validated_files)} VALIDATED files")
    if not warned_missing_b and warn_missing_blockvector_txt("VALIDATED", len(validated_files), validated_non_txt):
        warned_missing_b = True
    
    # Process VALIDATED files
    validated_parse_fail = 0
    validated_no_first_block = 0
    validated_no_seq_pairs = 0
    validated_no_start_block = 0
    validated_no_gt_path = 0
    validated_no_gt_stat = 0
    validated_processed = 0
    
    for bv_path in validated_files:
        bv_length, actual_blocks = parse_blockvector(bv_path)
        if bv_length is None or not actual_blocks:
            validated_parse_fail += 1
            if args.verbose:
                print(f"[debug] VALIDATED parse failed: {bv_path.name}")
            continue
        actual_blocks = blocks_within_length(
            actual_blocks, bv_length, block_size
        )
        if not actual_blocks:
            validated_parse_fail += 1
            continue
        
        # Find GT file
        first_block = actual_blocks[0]
        if first_block not in phys_to_entry:
            validated_no_first_block += 1
            if args.verbose:
                print(f"[debug] VALIDATED first block {first_block} not in key: {bv_path.name}")
            continue
        gt_file, start_idx = phys_to_entry[first_block]
        if gt_file not in universe_files:
            continue
        
        seq_pairs = path_to_seq.get(gt_file, [])
        if not seq_pairs:
            validated_no_seq_pairs += 1
            if args.verbose:
                print(f"[debug] VALIDATED no seq_pairs for {gt_file}: {bv_path.name}")
            continue
        
        # Find start_block
        start_block = None
        for idx, phys in seq_pairs:
            if idx == start_idx:
                start_block = phys
                break
        if start_block is None:
            validated_no_start_block += 1
            if args.verbose:
                print(f"[debug] VALIDATED no start_block for {gt_file}: {bv_path.name}")
            continue

        # A top-level recovery must begin with logical block zero of its ground
        # truth file. Content discovered inside another file is classified
        # separately after its bytes are checked against that source file.
        if start_idx != 0:
            blockvector_suffix = ".BLOCKVECTOR.txt"
            if bv_path.name.endswith(blockvector_suffix):
                data_name = bv_path.name[:-len(blockvector_suffix)]
                data_path = bv_path.with_name(data_name)
                nonroot_validated_origins[data_path] = (gt_file, start_idx)
            continue
        
        pair_key = (gt_file, start_block)
        tracked_pairs.add(pair_key)
        
        # Get GT file size
        gt_path, msg = resolve_gt_path(gt_file, key_dir)
        if not gt_path:
            validated_no_gt_path += 1
            if args.verbose:
                print(f"[debug] VALIDATED no GT path for {gt_file}: {msg}")
            continue
        try:
            gt_size = os.stat(gt_path).st_size
        except:
            validated_no_gt_stat += 1
            if args.verbose:
                print(f"[debug] VALIDATED can't stat {gt_path}")
            continue
        
        validated_processed += 1
        
        # Validate blocks
        exp = [phys for idx, phys in seq_pairs]
        j = start_idx
        all_correct = True
        first_wrong = -1
        blocks_correct = 0
        
        for i, a in enumerate(actual_blocks):
            if j + i >= len(exp) or not blocks_equivalent(a, exp[j + i], exemplar_map):
                all_correct = False
                first_wrong = i
                break
            blocks_correct += 1
        
        # Check if has MISSING
        has_missing = gt_file in missing_blocks_map and missing_blocks_map[gt_file]
        blocks_expected = len(seq_pairs)
        if has_missing:
            first_missing_idx = min(missing_blocks_map[gt_file])
            blocks_expected = sum(1 for idx, phys in seq_pairs if idx < first_missing_idx)
        
        # Byte content is authoritative when duplicate physical blocks or an
        # unauthenticated trailing extent make block identity or length differ.
        content_prefix_matches = reconstructed_prefix_matches(
            image_path, gt_path, actual_blocks, block_size,
            bv_length, gt_size
        )
        if content_prefix_matches:
            if bv_length == gt_size:
                cat1_perfect.add(pair_key)
                exact_recovery_files.add(gt_file)
            elif bv_length > gt_size:
                cat2_length.append(
                    (gt_file, start_block, bv_path, bv_length, gt_size)
                )
                recognized_validated_prefixes.add(bv_path)
            elif has_missing:
                cat3_missing.append(
                    (gt_file, start_block, bv_path,
                     min(len(actual_blocks), blocks_expected),
                     blocks_expected)
                )
                recognized_validated_prefixes.add(bv_path)
            else:
                cat4_correct.append(
                    (gt_file, start_block, bv_path,
                     min(len(actual_blocks), blocks_expected),
                     blocks_expected)
                )
                recognized_validated_prefixes.add(bv_path)
            continue

        # Categorize block-level evidence when the reconstructed bytes are not
        # an exact prefix of the source file.
        is_terminal_wrong = (first_wrong != -1 and first_wrong == len(actual_blocks) - 1)

        if all_correct and len(actual_blocks) == len(seq_pairs):
            cat5_incorrect.append(
                (gt_file, start_block, bv_path, -1, blocks_correct,
                 blocks_expected, len(actual_blocks))
            )
        elif has_missing and blocks_correct >= blocks_expected:
            # Category 3
            cat3_missing.append((gt_file, start_block, bv_path, blocks_correct, blocks_expected))
            recognized_validated_prefixes.add(bv_path)
        elif not has_missing and (first_wrong == -1 or is_terminal_wrong):
            # Category 4 - all correct OR terminal block wrong
            actual_correct = blocks_correct if first_wrong == -1 else first_wrong
            cat4_correct.append((gt_file, start_block, bv_path, actual_correct, blocks_expected))
            if first_wrong == -1:
                recognized_validated_prefixes.add(bv_path)
        else:
            # Category 5
            cat5_incorrect.append((gt_file, start_block, bv_path, first_wrong, blocks_correct, blocks_expected, len(actual_blocks)))
    
    # Debug output for VALIDATED processing
    if args.verbose:
        print(f"[debug] VALIDATED processing summary:")
        print(f"[debug]   Total files: {len(validated_files)}")
        print(f"[debug]   Parse failed: {validated_parse_fail}")
        print(f"[debug]   First block not in key: {validated_no_first_block}")
        print(f"[debug]   No seq_pairs: {validated_no_seq_pairs}")
        print(f"[debug]   No start_block: {validated_no_start_block}")
        print(f"[debug]   GT path not found: {validated_no_gt_path}")
        print(f"[debug]   GT stat failed: {validated_no_gt_stat}")
        print(f"[debug]   Successfully processed: {validated_processed}")
        print(f"[debug]   Tracked pairs added: {len(tracked_pairs)}")
    
    # Find PROMISING and INPROGRESS
    print(f"[info] Searching for PROMISING directories...")
    promising_files, promising_non_txt = find_all_txt_files_recursive(args.scalpel_dir, "PROMISING")
    print(f"[info] Found {len(promising_files)} PROMISING files")
    if not warned_missing_b and warn_missing_blockvector_txt("PROMISING", len(promising_files), promising_non_txt):
        warned_missing_b = True

    print(f"[info] Searching for INPROGRESS directories...")
    inprogress_files, inprogress_non_txt = find_all_txt_files_recursive(args.scalpel_dir, "INPROGRESS")
    print(f"[info] Found {len(inprogress_files)} INPROGRESS files")
    if not warned_missing_b and warn_missing_blockvector_txt("INPROGRESS", len(inprogress_files), inprogress_non_txt):
        warned_missing_b = True
    
    # build recovery pool. a UUID can have several promising snapshots, and a
    # longer speculative path is not necessarily more accurate than an earlier
    # verified prefix, so retain every snapshot until after classification.
    recovery_pool: List[Tuple[Tuple[str, int], Path, int, List[int]]] = []
    recovery_pairs: Set[Tuple[str, int]] = set()
    
    for bv_path in promising_files + inprogress_files:
        bv_length, actual_blocks = parse_blockvector(bv_path)
        if bv_length is None or not actual_blocks:
            continue
        actual_blocks = blocks_within_length(
            actual_blocks, bv_length, block_size
        )
        if not actual_blocks:
            continue
        
        first_block = actual_blocks[0]
        if first_block not in phys_to_entry:
            continue
        gt_file, start_idx = phys_to_entry[first_block]
        if gt_file not in universe_files:
            continue
        
        seq_pairs = path_to_seq.get(gt_file, [])
        if not seq_pairs:
            continue
        
        start_block = None
        for idx, phys in seq_pairs:
            if idx == start_idx:
                start_block = phys
                break
        if start_block is None:
            continue

        if start_idx != 0:
            continue
        
        pair_key = (gt_file, start_block)
        
        recovery_pool.append((pair_key, bv_path, bv_length, actual_blocks))
        recovery_pairs.add(pair_key)

    print(f"[info] Recovery pool: {len(recovery_pairs)} unique pairs, "
          f"{len(recovery_pool)} snapshots")

    # Process recovery pool
    for pair_key, bv_path, bv_length, actual_blocks in recovery_pool:
        gt_file, start_block = pair_key
        tracked_pairs.add(pair_key)
        
        seq_pairs = path_to_seq.get(gt_file, [])
        if not seq_pairs:
            continue
        
        # Find start_idx
        start_idx = None
        for idx, phys in seq_pairs:
            if phys == start_block:
                start_idx = idx
                break
        if start_idx is None:
            continue
        
        # Validate blocks
        exp = [phys for idx, phys in seq_pairs]
        j = start_idx
        all_correct = True
        first_wrong = -1
        blocks_correct = 0
        
        for i, a in enumerate(actual_blocks):
            if j + i >= len(exp) or not blocks_equivalent(a, exp[j + i], exemplar_map):
                all_correct = False
                first_wrong = i
                break
            blocks_correct += 1
        
        # Check if has MISSING
        has_missing = gt_file in missing_blocks_map and missing_blocks_map[gt_file]
        blocks_expected = len(seq_pairs)
        if has_missing:
            first_missing_idx = min(missing_blocks_map[gt_file])
            blocks_expected = sum(1 for idx, phys in seq_pairs if idx < first_missing_idx)

        # A byte-exact recovery or prefix retains the same classification
        # regardless of whether it is in VALIDATED or PROMISING.
        snapshot_prefix_matches = False
        gt_path, _ = resolve_gt_path(gt_file, key_dir)
        if gt_path:
            try:
                gt_size = os.stat(gt_path).st_size
            except OSError:
                gt_size = -1
            if gt_size >= 0:
                snapshot_prefix_matches = reconstructed_prefix_matches(
                    image_path, gt_path, actual_blocks, block_size,
                    bv_length, gt_size
                )
                if snapshot_prefix_matches and bv_length == gt_size:
                    cat1_perfect.add(pair_key)
                    exact_recovery_files.add(gt_file)

        if snapshot_prefix_matches:
            if bv_length > gt_size:
                cat2_length.append(
                    (gt_file, start_block, bv_path, bv_length, gt_size)
                )
            elif bv_length < gt_size and has_missing:
                cat3_missing.append(
                    (gt_file, start_block, bv_path,
                     min(len(actual_blocks), blocks_expected),
                     blocks_expected)
                )
            elif bv_length < gt_size:
                cat4_correct.append(
                    (gt_file, start_block, bv_path,
                     min(len(actual_blocks), blocks_expected),
                     blocks_expected)
                )
            continue
        
        # Categorize
        # For Category 4: terminal block can be wrong ONLY if it's actually the last block
        is_terminal_wrong = (first_wrong != -1 and first_wrong == len(actual_blocks) - 1)
        
        if has_missing and blocks_correct >= blocks_expected:
            cat3_missing.append((gt_file, start_block, bv_path, blocks_correct, blocks_expected))
        elif not has_missing and (first_wrong == -1 or is_terminal_wrong):
            actual_correct = blocks_correct if first_wrong == -1 else first_wrong
            cat4_correct.append((gt_file, start_block, bv_path, actual_correct, blocks_expected))
        else:
            cat5_incorrect.append((gt_file, start_block, bv_path, first_wrong, blocks_correct, blocks_expected, len(actual_blocks)))
    
    # Category 6 - not recovered
    tracked_files = set(gt for gt, blk in tracked_pairs)
    cat6_not_recovered = universe_files - tracked_files
    
    # ========================================================================
    # DEDUPLICATION: Keep only BEST recovery per GT file
    # ========================================================================
    # Build mapping: gt_file -> (category, entry_data)
    file_to_best: Dict[str, Tuple[int, tuple, tuple]] = {}

    def keep_best(gt: str, category: int, entry: tuple, quality: tuple) -> None:
        current = file_to_best.get(gt)
        if (current is None or category < current[0]
                or (category == current[0] and quality > current[2])):
            file_to_best[gt] = (category, entry, quality)
    
    # Process all entries, keeping best category per file
    for gt, blk in cat1_perfect:
        keep_best(gt, 1, (gt, blk), (1,))

    for entry in cat2_length:
        gt = entry[0]
        keep_best(gt, 2, entry, (-abs(entry[3] - entry[4]),))

    for entry in cat3_missing:
        gt = entry[0]
        keep_best(gt, 3, entry, (entry[3] / max(entry[4], 1), entry[3]))

    for entry in cat4_correct:
        gt = entry[0]
        keep_best(gt, 4, entry, (entry[3] / max(entry[4], 1), entry[3]))

    for entry in cat5_incorrect:
        gt = entry[0]
        keep_best(gt, 5, entry,
                  (entry[4] / max(entry[5], 1), entry[4], -entry[6]))
    
    # Rebuild category lists with only best entries
    cat1_perfect_dedup = set()
    cat2_length_dedup = []
    cat3_missing_dedup = []
    cat4_correct_dedup = []
    cat5_incorrect_dedup = []
    
    for gt, (category, entry, _quality) in file_to_best.items():
        if category == 1:
            cat1_perfect_dedup.add(entry)
        elif category == 2:
            cat2_length_dedup.append(entry)
        elif category == 3:
            cat3_missing_dedup.append(entry)
        elif category == 4:
            cat4_correct_dedup.append(entry)
        elif category == 5:
            cat5_incorrect_dedup.append(entry)
    
    # Replace original lists with deduplicated versions
    cat1_perfect = cat1_perfect_dedup
    cat2_length = cat2_length_dedup
    cat3_missing = cat3_missing_dedup
    cat4_correct = cat4_correct_dedup
    cat5_incorrect = cat5_incorrect_dedup
    
    # Helper function to analyze fragmentation for a category
    def analyze_fragmentation(gt_files: List[str]) -> Tuple[List[str], List[str]]:
        """
        Split GT files into fragmented and unfragmented lists.
        Returns (unfragmented_list, fragmented_list)
        """
        unfrag = []
        frag = []
        for gt in gt_files:
            if fragmentation_status.get(gt, False):
                frag.append(gt)
            else:
                unfrag.append(gt)
        return unfrag, frag
    
    # Output
    print("\n" + "="*80)
    print("VALIDATION RESULTS")
    print("="*80 + "\n")
    
    if cat1_perfect:
        gt_files = [gt for gt, blk in cat1_perfect]
        unfrag, frag = analyze_fragmentation(gt_files)
        
        print(f"Category 1: Perfect ({len(cat1_perfect)} files)")
        print("-" * 80)
        print(f"  Unfragmented: {len(unfrag)}/{total_unfragmented}")
        if unfrag:
            for gt in sorted(unfrag):
                print(f"    {gt}")
        print(f"  Fragmented: {len(frag)}/{total_fragmented}")
        if frag:
            for gt in sorted(frag):
                print(f"    {gt}")
        print()
    
    if cat2_length:
        gt_files = [entry[0] for entry in cat2_length]
        unfrag, frag = analyze_fragmentation(gt_files)
        
        print(f"Category 2: Perfect except length ({len(cat2_length)} files)")
        print("-" * 80)
        print(f"  Unfragmented: {len(unfrag)}/{total_unfragmented}")
        if unfrag:
            for gt in sorted(unfrag):
                print(f"    {gt}")
        print(f"  Fragmented: {len(frag)}/{total_fragmented}")
        if frag:
            for gt in sorted(frag):
                print(f"    {gt}")
        print()
        print("Files:")
        for gt, blk, path, bv_len, gt_len in sorted(cat2_length):
            print(f"[CAT 2] {gt} (block {blk}) - all blocks correct but length mismatch: {bv_len} bytes (GT: {gt_len} bytes)")
            print(f"        File: {path}")
        print()
    
    if cat3_missing:
        gt_files = [entry[0] for entry in cat3_missing]
        unfrag, frag = analyze_fragmentation(gt_files)
        
        print(f"Category 3: Perfect partial with MISSING ({len(cat3_missing)} files)")
        print("-" * 80)
        print(f"  Unfragmented: {len(unfrag)}/{total_unfragmented}")
        if unfrag:
            for gt in sorted(unfrag):
                print(f"    {gt}")
        print(f"  Fragmented: {len(frag)}/{total_fragmented}")
        if frag:
            for gt in sorted(frag):
                print(f"    {gt}")
        print()
        print("Files:")
        for gt, blk, path, correct, expected in sorted(cat3_missing):
            pct = 100
            print(f"[CAT 3] {gt} (block {blk}) - perfect partial: {pct}% ({correct}/{expected} blocks to MISSING) [HAS MISSING]")
            print(f"        File: {path}")
        print()
    
    if cat4_correct:
        gt_files = [entry[0] for entry in cat4_correct]
        unfrag, frag = analyze_fragmentation(gt_files)
        
        print(f"Category 4: Perfect partial without MISSING ({len(cat4_correct)} files)")
        print("-" * 80)
        print(f"  Unfragmented: {len(unfrag)}/{total_unfragmented}")
        if unfrag:
            for gt in sorted(unfrag):
                print(f"    {gt}")
        print(f"  Fragmented: {len(frag)}/{total_fragmented}")
        if frag:
            for gt in sorted(frag):
                print(f"    {gt}")
        print()
        print("Files:")
        for gt, blk, path, correct, expected in sorted(cat4_correct):
            pct = int(100.0 * correct / expected) if expected > 0 else 0
            print(f"[CAT 4] {gt} (block {blk}) - correct so far: {pct}% ({correct}/{expected} blocks)")
            print(f"        File: {path}")
        print()
    
    if cat5_incorrect:
        gt_files = [entry[0] for entry in cat5_incorrect]
        unfrag, frag = analyze_fragmentation(gt_files)
        
        print(f"Category 5: Recovered incorrectly ({len(cat5_incorrect)} files)")
        print("-" * 80)
        print(f"  Unfragmented: {len(unfrag)}/{total_unfragmented}")
        if unfrag:
            for gt in sorted(unfrag):
                print(f"    {gt}")
        print(f"  Fragmented: {len(frag)}/{total_fragmented}")
        if frag:
            for gt in sorted(frag):
                print(f"    {gt}")
        print()
        print("Files:")
        for gt, blk, path, first_wrong, correct, expected, carved_count in sorted(cat5_incorrect):
            pct = int(100.0 * correct / expected) if expected > 0 else 0
            print(f"[CAT 5] {gt} (block {blk}) - incorrect at block {first_wrong}: {pct}% ({correct}/{expected} GT blocks, carved has {carved_count} blocks)")
            print(f"        File: {path}")
        print()
    
    if cat6_not_recovered:
        gt_files = list(cat6_not_recovered)
        unfrag, frag = analyze_fragmentation(gt_files)
        
        print(f"Category 6: Not recovered ({len(cat6_not_recovered)} files)")
        print("-" * 80)
        print(f"  Unfragmented: {len(unfrag)}/{total_unfragmented}")
        if unfrag:
            for gt in sorted(unfrag):
                print(f"    [CAT 6] {gt}")
        print(f"  Fragmented: {len(frag)}/{total_fragmented}")
        if frag:
            for gt in sorted(frag):
                print(f"    [CAT 6] {gt}")
        print()
    
    # ========================================================================
    # INVALID CHECK: files in VALIDATED that neither match a complete ground
    # truth file nor a blockvector-proven ground truth prefix.
    # ========================================================================
    # Build set of GT SHA256 hashes
    gt_sha256_set: Set[str] = set()
    gt_sha256_to_file: Dict[str, str] = {}
    for gt_file in universe_files:
        gt_path, msg = resolve_gt_path(gt_file, key_dir)
        if gt_path:
            ok, sha = sha256_of_file(gt_path)
            if ok:
                gt_sha256_set.add(sha)
                gt_sha256_to_file[sha] = gt_file

    recognized_prefix_files: Set[Path] = set()
    for blockvector_path in recognized_validated_prefixes:
        blockvector_suffix = ".BLOCKVECTOR.txt"
        if blockvector_path.name.endswith(blockvector_suffix):
            data_name = blockvector_path.name[:-len(blockvector_suffix)]
            recognized_prefix_files.add(blockvector_path.with_name(data_name))

    # Find all non-.txt files in VALIDATED directories and SHA256-check them.
    # Prefixes already associated through their blockvectors retain their
    # normal Category 2, 3, or 4 classification rather than being counted a
    # second time as invalid.
    invalid_in_validated: List[Tuple[str, int, str]] = []  # (filepath, size, sha256)
    embedded_in_validated: List[Tuple[str, int, str, str, int]] = []
    validated_data_files: List[Path] = []
    for item in args.scalpel_dir.rglob("VALIDATED"):
        if item.is_dir():
            for f in item.rglob("*"):
                if f.is_file() and not f.name.endswith(".txt"):
                    validated_data_files.append(f)

    for data_file in validated_data_files:
        if data_file in recognized_prefix_files:
            continue
        file_size = data_file.stat().st_size
        ok, sha = sha256_of_file(data_file)
        if not ok or sha in gt_sha256_set:
            continue

        origin = nonroot_validated_origins.get(data_file)
        if origin is not None:
            gt_file, start_idx = origin
            gt_path, _ = resolve_gt_path(gt_file, key_dir)
            if gt_path is not None:
                embedded_offset = find_exact_embedded_offset(
                    data_file, Path(gt_path), start_idx, block_size)
                if embedded_offset is not None:
                    embedded_in_validated.append(
                        (str(data_file), file_size, sha, gt_file,
                         embedded_offset))
                    continue

        invalid_in_validated.append((str(data_file), file_size, sha))

    if embedded_in_validated:
        print(
            f"\nEMBEDDED: {len(embedded_in_validated)} file(s) in VALIDATED "
            "match exact content within a ground-truth file"
        )
        print("-" * 80)
        for fpath, fsize, fsha, gt_file, offset in sorted(
                embedded_in_validated, key=lambda entry: entry[1]):
            print(f"  {Path(fpath).name}")
            print(f"    size={fsize}  sha256={fsha}")
            print(f"    source={gt_file}  byte_offset={offset}")
        print()

    if invalid_in_validated:
        print(f"\nINVALID: {len(invalid_in_validated)} file(s) in VALIDATED that do NOT match ground truth")
        print("-" * 80)
        for fpath, fsize, fsha in sorted(invalid_in_validated, key=lambda x: x[1]):
            print(f"  {Path(fpath).name}")
            print(f"    size={fsize}  sha256={fsha}")
        print()
    else:
        print(
            f"\n[OK] All {len(validated_data_files)} file(s) in VALIDATED "
            "match ground truth exactly, as a blockvector-proven prefix, or "
            "as exact embedded content.\n"
        )

    # ========================================================================
    # SUMMARIES - Per File Type and Overall
    # ========================================================================

    # Helper function to get file extension
    def get_extension(filepath: str) -> str:
        """Get file extension in uppercase (e.g., 'GIF', 'PNG')"""
        ext = Path(filepath).suffix.lstrip('.').upper()
        return ext if ext else 'NO_EXT'
    
    # Group universe by file type
    universe_by_type: Dict[str, Set[str]] = defaultdict(set)
    for gt_file in universe_files:
        ext = get_extension(gt_file)
        universe_by_type[ext].add(gt_file)
    
    # Helper function to print summary for a specific file type (or all)
    def print_summary(file_type: Optional[str] = None):
        """Print summary for a specific file type, or all files if file_type is None"""
        if file_type:
            # Filter to this file type
            universe_subset = universe_by_type.get(file_type, set())
            cat1_subset = set((gt, blk) for gt, blk in cat1_perfect if get_extension(gt) == file_type)
            cat2_subset = [e for e in cat2_length if get_extension(e[0]) == file_type]
            cat3_subset = [e for e in cat3_missing if get_extension(e[0]) == file_type]
            cat4_subset = [e for e in cat4_correct if get_extension(e[0]) == file_type]
            cat5_subset = [e for e in cat5_incorrect if get_extension(e[0]) == file_type]
            cat6_subset = set(f for f in cat6_not_recovered if get_extension(f) == file_type)
            
            print("="*80)
            print(f"{file_type} FILES")
            print("="*80)
        else:
            # All files
            universe_subset = universe_files
            cat1_subset = cat1_perfect
            cat2_subset = cat2_length
            cat3_subset = cat3_missing
            cat4_subset = cat4_correct
            cat5_subset = cat5_incorrect
            cat6_subset = cat6_not_recovered
            
            print("="*80)
            print("SUMMARY (ALL FILES)")
            print("="*80)
        
        print(f"  GT files (universe):              {len(universe_subset)}")
        print(f"  Category 1 (Perfect):             {len(cat1_subset)}")
        print(f"  Category 2 (Length mismatch):     {len(cat2_subset)}")
        print(f"  Category 3 (Partial w/MISSING):   {len(cat3_subset)}")
        print(f"  Category 4 (Partial correct):     {len(cat4_subset)}")
        print(f"  Category 5 (Incorrect):           {len(cat5_subset)}")
        print(f"  Category 6 (Not recovered):       {len(cat6_subset)}")
        if file_type is None:
            print(f"  INVALID (in VALIDATED, no match): {len(invalid_in_validated)}")
        print()
        
        # Category 4 breakdown for this subset
        if cat4_subset:
            print("Category 4 Breakdown (by completion percentage):")
            print("-" * 80)
            buckets = defaultdict(int)
            for gt, blk, path, correct, expected in cat4_subset:
                pct = int(100.0 * correct / expected) if expected > 0 else 0
                if pct < 10:
                    bucket = "0-10%"
                elif pct < 20:
                    bucket = "10-20%"
                elif pct < 30:
                    bucket = "20-30%"
                elif pct < 40:
                    bucket = "30-40%"
                elif pct < 50:
                    bucket = "40-50%"
                elif pct < 60:
                    bucket = "50-60%"
                elif pct < 70:
                    bucket = "60-70%"
                elif pct < 80:
                    bucket = "70-80%"
                elif pct < 90:
                    bucket = "80-90%"
                else:
                    bucket = "90-99%"
                buckets[bucket] += 1
            
            for bucket in ["0-10%", "10-20%", "20-30%", "30-40%", "40-50%", "50-60%", "60-70%", "70-80%", "80-90%", "90-99%"]:
                count = buckets.get(bucket, 0)
                print(f"  {bucket:10s}: {count:6d} files")
            print()
    
    # Print per-file-type summaries
    for file_type in sorted(universe_by_type.keys()):
        print_summary(file_type)
    
    # Print overall summary
    print_summary(None)

    failed = False
    if args.fail_on_invalid_validated and invalid_in_validated:
        print(
            f"[fatal] {len(invalid_in_validated)} invalid file(s) were written "
            "to VALIDATED.",
            file=sys.stderr,
        )
        failed = True

    if args.require_all_exact:
        missing_exact = universe_files - exact_recovery_files
        if missing_exact:
            print(
                f"[fatal] {len(missing_exact)} of {len(universe_files)} "
                "ground-truth file(s) lack a byte-exact recovery:",
                file=sys.stderr,
            )
            for gt_file in sorted(missing_exact):
                print(f"  {gt_file}", file=sys.stderr)
            failed = True
        else:
            print(
                f"[OK] All {len(universe_files)} ground-truth file(s) have "
                "a byte-exact recovery."
            )

    if args.require_exact_at_least is not None:
        exact_count = len(universe_files & exact_recovery_files)
        if exact_count < args.require_exact_at_least:
            print(
                f"[fatal] {exact_count} of {len(universe_files)} ground-truth "
                f"file(s) have a byte-exact recovery; "
                f"{args.require_exact_at_least} required.",
                file=sys.stderr,
            )
            failed = True
        else:
            print(
                f"[OK] {exact_count} ground-truth file(s) have a byte-exact "
                f"recovery ({args.require_exact_at_least} required)."
            )

    if failed:
        sys.exit(1)


if __name__ == "__main__":
    main()
