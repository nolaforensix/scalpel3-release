#!/usr/bin/env python3
"""
ELF blockvector post-processing for Scalpel3.

This script:
- reads Scalpel's binary blockmap
- finds ELF blockvector files under validated/ and promising/
- deduplicates repeated candidates by first UUID, preferring the most complete copy
- identifies holes in each blockvector
- fills holes in phases using remaining selectable image blocks
- copies selected image blocks into the corresponding ELF candidate file

Default behavior is conservative:
- strongest phases run first
- only selectable blocks are used
- unresolved holes are left empty
- Phase 4 (proximity-based fills) is DISABLED by default
- original .elf files are NOT modified unless --in-place is passed

Usage example:
  python3 elf_postprocess_no_phase4.py \
      --image /path/to/image.dd \
      --blockmap /path/to/scalpel.blockmap \
      --output-root /path/to/scalpel-output-dir

Notes:
- "available" is interpreted using Scalpel's block selectability semantics:
    in active window, uncovered, and dedup/exemplar bits must match.
  This mirrors is_block_selectable() in blockmap.c.
- By default, patched ELF files are written beside the originals with suffix
  ".POSTPROC.elf". Reports are written as JSON with suffix ".POSTPROC.json".
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

UUID_PREFIX_RE = re.compile(r'^UUIDS-\$\$([0-9a-fA-F-]{36})\$\$')
BV_LINE_RE = re.compile(r'^\s*(\d+)\s+(\d+)\s+(\d+)\s*$')


def bit_is_set(bitmap: bytes, j: int) -> bool:
    return (bitmap[j // 8] & (1 << (j % 8))) != 0


@dataclass
class Blockmap:
    blocksize: int
    numblocks: int
    start_block: int
    end_block: int
    coveragemap: bytes
    dedupmap: bytes
    exemplarmap: bytes
    zeromap: bytes
    reservations: List[int]
    refcounts: List[int]

    @property
    def bitmap_length(self) -> int:
        return (self.numblocks + 7) // 8

    def in_window(self, j: int) -> bool:
        return self.start_block <= j <= self.end_block

    def is_covered(self, j: int) -> bool:
        covered = bit_is_set(self.coveragemap, j)
        if covered or not self.in_window(j):
            return True

        dedup = bit_is_set(self.dedupmap, j)
        exemplar = bit_is_set(self.exemplarmap, j)
        if (not dedup) or exemplar:
            return covered

        exemplar_idx = self.refcounts[j]
        return self.refcounts[exemplar_idx] == 0

    def get_exemplar(self, j: int) -> int:
        if bit_is_set(self.dedupmap, j) and not bit_is_set(self.exemplarmap, j):
            return self.refcounts[j]
        return j

    def is_reserved(self, j: int) -> int:
        return self.reservations[self.get_exemplar(j)]

    def is_selectable(self, j: int) -> bool:
        return (
            self.in_window(j)
            and not bit_is_set(self.coveragemap, j)
            and (bit_is_set(self.dedupmap, j) == bit_is_set(self.exemplarmap, j))
        )


def read_blockmap(path: Path) -> Blockmap:
    data = path.read_bytes()
    off = 0

    def take(fmt: str):
        nonlocal off
        size = struct.calcsize(fmt)
        vals = struct.unpack_from(fmt, data, off)
        off += size
        return vals if len(vals) != 1 else vals[0]

    blocksize = take('<I')
    numblocks = take('<Q')
    start_block = take('<Q')
    end_block = take('<Q')
    bitmap_length = (numblocks + 7) // 8

    coveragemap = data[off:off + bitmap_length]
    off += bitmap_length
    dedupmap = data[off:off + bitmap_length]
    off += bitmap_length
    exemplarmap = data[off:off + bitmap_length]
    off += bitmap_length
    zeromap = data[off:off + bitmap_length]
    off += bitmap_length

    reservations = list(struct.unpack_from(f'<{numblocks}q', data, off))
    off += numblocks * 8
    refcounts = list(struct.unpack_from(f'<{numblocks}q', data, off))
    off += numblocks * 8

    expected = 4 + 8 + 8 + 8 + bitmap_length * 4 + numblocks * 8 + numblocks * 8
    if len(data) != expected:
        raise ValueError(f'Blockmap size mismatch: expected {expected} bytes, got {len(data)}')

    return Blockmap(
        blocksize=blocksize,
        numblocks=numblocks,
        start_block=start_block,
        end_block=end_block,
        coveragemap=coveragemap,
        dedupmap=dedupmap,
        exemplarmap=exemplarmap,
        zeromap=zeromap,
        reservations=reservations,
        refcounts=refcounts,
    )


@dataclass
class Candidate:
    uuid1: str
    bv_path: Path
    elf_path: Path
    folder_kind: str
    capacity_blocks: int
    length_bytes: int
    entries: Dict[int, int]
    apparent: Dict[int, int] = field(default_factory=dict)

    @property
    def filled_count(self) -> int:
        return len(self.entries)

    def to_vector(self) -> List[Optional[int]]:
        vec = [None] * self.capacity_blocks
        for idx, actual in self.entries.items():
            if 0 <= idx < self.capacity_blocks:
                vec[idx] = actual
        return vec


@dataclass
class FillAction:
    index: int
    actual_block: int
    phase: str


def parse_blockvector(path: Path) -> Candidate:
    text = path.read_text(errors='replace').splitlines()
    capacity = None
    length_bytes = None
    entries: Dict[int, int] = {}
    apparent: Dict[int, int] = {}

    for line in text:
        if line.startswith('Capacity:'):
            m = re.search(r'(\d+)', line)
            if m:
                capacity = int(m.group(1))
        elif line.startswith('Length:'):
            m = re.search(r'(\d+)', line)
            if m:
                length_bytes = int(m.group(1))
        else:
            m = BV_LINE_RE.match(line)
            if m:
                idx = int(m.group(1))
                actual = int(m.group(2))
                appr = int(m.group(3))
                entries[idx] = actual
                apparent[idx] = appr

    if capacity is None or length_bytes is None:
        raise ValueError(f'Failed to parse capacity/length from {path}')

    m = UUID_PREFIX_RE.match(path.name)
    if not m:
        raise ValueError(f'Failed to parse first UUID from {path.name}')
    uuid1 = m.group(1)

    folder_kind = 'validated' if 'validated' in path.parts else 'promising'
    elf_name = path.name.replace('.BLOCKVECTOR.txt', '')
    elf_path = path.with_name(elf_name)
    if not elf_path.exists():
        raise FileNotFoundError(f'Corresponding ELF candidate not found for {path}: expected {elf_path}')

    return Candidate(
        uuid1=uuid1,
        bv_path=path,
        elf_path=elf_path,
        folder_kind=folder_kind,
        capacity_blocks=capacity,
        length_bytes=length_bytes,
        entries=entries,
        apparent=apparent,
    )


def choose_best_candidate(cands: List[Candidate]) -> Candidate:
    def key(c: Candidate):
        validated_bias = 1 if c.folder_kind == 'validated' else 0
        return (c.filled_count, c.capacity_blocks, validated_bias, str(c.bv_path))
    return max(cands, key=key)


def find_candidates(output_root: Path) -> List[Candidate]:
    bv_paths = list(output_root.rglob('*.elf.BLOCKVECTOR.txt'))
    grouped: Dict[str, List[Candidate]] = {}
    for path in bv_paths:
        cand = parse_blockvector(path)
        grouped.setdefault(cand.uuid1, []).append(cand)
    return [choose_best_candidate(group) for group in grouped.values()]


def contiguous_run_forward(start: int, max_len: int, available: Set[int]) -> List[int]:
    out = []
    cur = start
    while len(out) < max_len and cur in available:
        out.append(cur)
        cur += 1
    return out


def contiguous_run_backward(end: int, max_len: int, available: Set[int]) -> List[int]:
    out = []
    cur = end
    while len(out) < max_len and cur in available:
        out.append(cur)
        cur -= 1
    out.reverse()
    return out


def holes_in_vector(vec: List[Optional[int]]) -> List[Tuple[int, int]]:
    holes = []
    i = 0
    n = len(vec)
    while i < n:
        if vec[i] is not None:
            i += 1
            continue
        start = i
        while i < n and vec[i] is None:
            i += 1
        holes.append((start, i - 1))
    return holes


def score_candidate_run(run_start: int, run_len: int, left_bound: Optional[int], right_bound: Optional[int]) -> Tuple[int, int, int]:
    left_dist = abs(run_start - left_bound) if left_bound is not None else 10**18
    right_end = run_start + run_len - 1
    right_dist = abs(right_bound - right_end) if right_bound is not None else 10**18
    best_dist = min(left_dist, right_dist)
    sum_dist = (left_dist if left_dist != 10**18 else 0) + (right_dist if right_dist != 10**18 else 0)
    return (best_dist, sum_dist, run_start)


def find_exact_size_runs(hole_size: int, available: Set[int]) -> List[int]:
    if hole_size <= 0 or not available:
        return []
    sorted_avail = sorted(available)
    starts = []
    i = 0
    n = len(sorted_avail)
    while i < n:
        j = i
        while j + 1 < n and sorted_avail[j + 1] == sorted_avail[j] + 1:
            j += 1
        run_len = j - i + 1
        if run_len >= hole_size:
            for s in range(sorted_avail[i], sorted_avail[j] - hole_size + 2):
                starts.append(s)
        i = j + 1
    return starts


def process_candidate(candidate: Candidate, blockmap: Blockmap, global_available: Set[int], enable_phase4: bool = False) -> Tuple[List[Optional[int]], List[FillAction]]:
    vec = candidate.to_vector()
    fills: List[FillAction] = []

    def consume(blocks: List[int]):
        for b in blocks:
            global_available.discard(b)

    # Phase 1: exact bounded contiguous fills
    for hole_start, hole_end in holes_in_vector(vec):
        hole_size = hole_end - hole_start + 1
        left = vec[hole_start - 1] if hole_start > 0 else None
        right = vec[hole_end + 1] if hole_end + 1 < len(vec) else None
        if left is None or right is None:
            continue
        if right - left - 1 != hole_size:
            continue
        run = list(range(left + 1, right))
        if all(b in global_available for b in run):
            for idx, blk in zip(range(hole_start, hole_end + 1), run):
                vec[idx] = blk
                fills.append(FillAction(idx, blk, 'exact_bounded_fill'))
            consume(run)

    # Phase 2: exact one-sided contiguous extensions
    for hole_start, hole_end in holes_in_vector(vec):
        hole_size = hole_end - hole_start + 1
        left = vec[hole_start - 1] if hole_start > 0 else None
        right = vec[hole_end + 1] if hole_end + 1 < len(vec) else None

        left_run = contiguous_run_forward(left + 1, hole_size, global_available) if left is not None else []
        right_run = contiguous_run_backward(right - 1, hole_size, global_available) if right is not None else []

        left_ok = len(left_run) == hole_size
        right_ok = len(right_run) == hole_size

        chosen = None
        chosen_flush = None
        if left_ok and not right_ok:
            chosen, chosen_flush = left_run, 'left'
        elif right_ok and not left_ok:
            chosen, chosen_flush = right_run, 'right'
        elif left_ok and right_ok:
            if left_run[0] <= right_run[0]:
                chosen, chosen_flush = left_run, 'left'
            else:
                chosen, chosen_flush = right_run, 'right'

        if chosen is not None:
            if chosen_flush == 'left':
                for idx, blk in zip(range(hole_start, hole_end + 1), chosen):
                    vec[idx] = blk
                    fills.append(FillAction(idx, blk, 'exact_one_sided_extension'))
            else:
                start_idx = hole_end - hole_size + 1
                for idx, blk in zip(range(start_idx, hole_end + 1), chosen):
                    vec[idx] = blk
                    fills.append(FillAction(idx, blk, 'exact_one_sided_extension'))
            consume(chosen)

    # Phase 3: partial bounded contiguous fills
    for hole_start, hole_end in holes_in_vector(vec):
        hole_size = hole_end - hole_start + 1
        left = vec[hole_start - 1] if hole_start > 0 else None
        right = vec[hole_end + 1] if hole_end + 1 < len(vec) else None

        left_run = contiguous_run_forward(left + 1, hole_size, global_available) if left is not None else []
        right_run = contiguous_run_backward(right - 1, hole_size, global_available) if right is not None else []

        if not left_run and not right_run:
            continue

        if len(left_run) > len(right_run):
            chosen, chosen_flush = left_run, 'left'
        elif len(right_run) > len(left_run):
            chosen, chosen_flush = right_run, 'right'
        else:
            if left_run and right_run:
                if left_run[0] <= right_run[0]:
                    chosen, chosen_flush = left_run, 'left'
                else:
                    chosen, chosen_flush = right_run, 'right'
            elif left_run:
                chosen, chosen_flush = left_run, 'left'
            else:
                chosen, chosen_flush = right_run, 'right'

        if chosen_flush == 'left':
            for idx, blk in zip(range(hole_start, hole_start + len(chosen)), chosen):
                vec[idx] = blk
                fills.append(FillAction(idx, blk, 'partial_bounded_fill'))
        else:
            start_idx = hole_end - len(chosen) + 1
            for idx, blk in zip(range(start_idx, hole_end + 1), chosen):
                vec[idx] = blk
                fills.append(FillAction(idx, blk, 'partial_bounded_fill'))
        consume(chosen)

    # Phase 4: proximity-based contiguous run fills (optional; OFF by default)
    if enable_phase4:
        for hole_start, hole_end in holes_in_vector(vec):
            hole_size = hole_end - hole_start + 1
            left = vec[hole_start - 1] if hole_start > 0 else None
            right = vec[hole_end + 1] if hole_end + 1 < len(vec) else None

            starts = find_exact_size_runs(hole_size, global_available)
            if not starts:
                continue

            best_start = min(starts, key=lambda s: score_candidate_run(s, hole_size, left, right))
            chosen = list(range(best_start, best_start + hole_size))
            for idx, blk in zip(range(hole_start, hole_end + 1), chosen):
                vec[idx] = blk
                fills.append(FillAction(idx, blk, 'proximity_based_fill'))
            consume(chosen)

    return vec, fills


def patch_elf_from_vector(image_path: Path, elf_src_path: Path, elf_dst_path: Path, vec: List[Optional[int]], blocksize: int):
    if elf_src_path.resolve() != elf_dst_path.resolve():
        shutil.copy2(elf_src_path, elf_dst_path)

    with image_path.open('rb') as img, elf_dst_path.open('r+b') as outf:
        buf = bytearray(blocksize)
        for idx, actual in enumerate(vec):
            if actual is None:
                continue
            out_off = idx * blocksize
            img_off = actual * blocksize
            img.seek(img_off)
            n = img.readinto(buf)
            if n <= 0:
                raise IOError(f'Failed to read image block {actual}')
            if n < blocksize:
                buf[n:] = b'\x00' * (blocksize - n)
            outf.seek(out_off)
            outf.write(buf)


def build_report(candidate: Candidate, original_vec: List[Optional[int]], final_vec: List[Optional[int]], fills: List[FillAction], phase4_enabled: bool) -> dict:
    phase_counts: Dict[str, int] = {}
    for f in fills:
        phase_counts[f.phase] = phase_counts.get(f.phase, 0) + 1

    remaining_holes = holes_in_vector(final_vec)
    return {
        'candidate_uuid1': candidate.uuid1,
        'blockvector_path': str(candidate.bv_path),
        'elf_path': str(candidate.elf_path),
        'capacity_blocks': candidate.capacity_blocks,
        'length_bytes': candidate.length_bytes,
        'phase4_enabled': phase4_enabled,
        'original_filled_slots': sum(v is not None for v in original_vec),
        'final_filled_slots': sum(v is not None for v in final_vec),
        'phase_counts': phase_counts,
        'remaining_holes': [{'start': s, 'end': e, 'size': e - s + 1} for s, e in remaining_holes],
        'fills': [{'index': f.index, 'actual_block': f.actual_block, 'phase': f.phase} for f in fills],
    }


def determine_output_elf_path(elf_path: Path, in_place: bool) -> Path:
    if in_place:
        return elf_path
    if elf_path.suffix == '.elf':
        return elf_path.with_name(f'{elf_path.stem}.POSTPROC.elf')
    return elf_path.with_name(elf_path.name + '.POSTPROC')


def main():
    ap = argparse.ArgumentParser(description='Post-process Scalpel ELF blockvectors using block locality.')
    ap.add_argument('--image', required=True, type=Path, help='Path to source disk/image file')
    ap.add_argument('--blockmap', required=True, type=Path, help='Path to Scalpel binary blockmap')
    ap.add_argument('--output-root', required=True, type=Path, help='Root Scalpel output directory to search')
    ap.add_argument('--in-place', action='store_true', help='Modify original ELF candidates in place')
    ap.add_argument('--dry-run', action='store_true', help='Compute fills and write only reports')
    ap.add_argument('--enable-phase4', action='store_true', help='Enable Phase 4 proximity-based fills (disabled by default)')
    args = ap.parse_args()

    blockmap = read_blockmap(args.blockmap)
    candidates = find_candidates(args.output_root)
    if not candidates:
        raise SystemExit('No ELF blockvector files found.')

    available: Set[int] = {
        j for j in range(blockmap.start_block, blockmap.end_block + 1)
        if blockmap.is_selectable(j) and blockmap.is_reserved(j) == 0
    }

    summary = {
        'image': str(args.image),
        'blockmap': str(args.blockmap),
        'output_root': str(args.output_root),
        'blocksize': blockmap.blocksize,
        'numblocks': blockmap.numblocks,
        'window': {'start_block': blockmap.start_block, 'end_block': blockmap.end_block},
        'phase4_enabled': args.enable_phase4,
        'initial_available_blocks': len(available),
        'candidates_processed': [],
    }

    for cand in sorted(candidates, key=lambda c: (str(c.elf_path.parent), str(c.elf_path.name))):
        original_vec = cand.to_vector()
        final_vec, fills = process_candidate(cand, blockmap, available, enable_phase4=args.enable_phase4)

        out_elf = determine_output_elf_path(cand.elf_path, args.in_place)
        report_path = out_elf.with_suffix(out_elf.suffix + '.POSTPROC.json')

        if not args.dry_run:
            patch_elf_from_vector(args.image, cand.elf_path, out_elf, final_vec, blockmap.blocksize)

        report = build_report(cand, original_vec, final_vec, fills, phase4_enabled=args.enable_phase4)
        report['output_elf_path'] = str(out_elf)
        report_path.write_text(json.dumps(report, indent=2))
        summary['candidates_processed'].append(report)

        print(f'Processed {cand.bv_path.name}: {len(fills)} new block placements -> {out_elf.name}')

    summary['remaining_available_blocks'] = len(available)
    summary_path = args.output_root / 'elf_postprocess_summary.json'
    summary_path.write_text(json.dumps(summary, indent=2))
    print(f'Wrote summary: {summary_path}')


if __name__ == '__main__':
    main()
