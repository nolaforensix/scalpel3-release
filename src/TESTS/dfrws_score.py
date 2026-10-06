#!/usr/bin/env python3
"""Independent DFRWS scoring; nothing in this module is supplied to recovery."""

from __future__ import annotations

import csv
import hashlib
import json
import re
import zipfile
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path


BLOCK_SIZE = 512
SUFFIX = ".BLOCKVECTOR.txt"
PUBLISHED_STATES = {"VALIDATED", "PROMISING"}


def digest_stream(source, algorithm="md5"):
    digest = hashlib.new(algorithm)
    for block in iter(lambda: source.read(1024 * 1024), b""):
        digest.update(block)
    return digest.hexdigest()


def digest_file(path, algorithm="md5"):
    with Path(path).open("rb") as source:
        return digest_stream(source, algorithm)


@dataclass
class Expected:
    name: str
    file_type: str
    size: int
    md5: str
    scenario: str = ""
    layout: tuple[int | None, ...] = ()

    @property
    def complete(self):
        return None not in self.layout

    @property
    def available(self):
        return tuple(block for block in self.layout if block is not None)

    @property
    def available_bytes(self):
        return sum(min(BLOCK_SIZE, max(0, self.size - index * BLOCK_SIZE))
                   for index, block in enumerate(self.layout) if block is not None)

    @property
    def prefix(self):
        end = self.layout.index(None) if not self.complete else len(self.layout)
        return self.layout[:end]


@dataclass
class Candidate:
    path: Path
    status: str
    length: int
    sectors: tuple[int, ...]
    md5: str = ""
    data_size: int | None = None
    ranges_valid: bool = True
    written: float = 0.0

    @property
    def identity(self):
        return self.md5, self.length, self.sectors, self.ranges_valid


def sector_range(value):
    if value.strip().lower() == "not used":
        return None
    match = re.fullmatch(r"\s*(\d+)-(\d+)\s*", value)
    if not match or int(match[1]) > int(match[2]):
        raise ValueError(f"invalid sector range: {value!r}")
    return int(match[1]), int(match[2])


def load_expected(challenge, metadata):
    metadata = Path(metadata)
    if challenge == "2006":
        expected = []
        with zipfile.ZipFile(metadata / "dfrws-2006-challenge-files.zip") as archive:
            for entry in sorted(archive.infolist(), key=lambda entry: entry.filename):
                path = Path(entry.filename)
                if entry.is_dir():
                    continue
                if path.parts[0] != "fullfiles" or len(path.parts) != 2:
                    raise ValueError(f"unexpected ground truth archive member: {path}")
                with archive.open(entry) as source:
                    digest = digest_stream(source)
                expected.append(Expected(path.name, path.suffix[1:], entry.file_size, digest))
        if len(expected) != 32:
            raise ValueError(f"expected 32 original 2006 files, found {len(expected)}")
        return expected

    info = {}
    with (metadata / "challenge-file-info.txt").open(newline="", encoding="utf-8-sig") as source:
        for row in csv.DictReader(source):
            info[row["IMG NAME"].strip()] = int(row["SIZE"]), row["MD5"].strip().lower()
    layouts = defaultdict(list)
    with (metadata / "challenge-layout.txt").open(newline="", encoding="utf-8-sig") as source:
        for row in csv.DictReader(source):
            layouts[row["Name"].strip()].append(row)
    # The official file-info includes an absent ASF and omits two layout ZIPs.
    if set(info) - set(layouts) != {"1.asf"}:
        raise ValueError("unexpected disagreement between file-info and image layout")

    expected = []
    for name, rows in sorted(layouts.items()):
        ranges = [sector_range(row["FileSectorOffset"]) for row in rows]
        if any(value is None for value in ranges):
            raise ValueError(f"missing source range for {name}")
        highest = max(value[1] for value in ranges)
        size, digest = info.get(name, ((highest + 1) * BLOCK_SIZE, ""))
        count = max((size + BLOCK_SIZE - 1) // BLOCK_SIZE, highest + 1)
        layout = [None] * count
        assigned = set()
        types, scenarios = set(), set()
        for row, (start, end) in zip(rows, ranges):
            image = sector_range(row["ImageSectorOffset"])
            if image and image[1] - image[0] != end - start:
                raise ValueError(f"source/image range mismatch for {name}")
            for index in range(start, end + 1):
                block = image[0] + index - start if image else None
                if index in assigned and layout[index] != block:
                    raise ValueError(f"conflicting layout rows for {name}")
                layout[index] = block
                assigned.add(index)
            types.add(row["Type"].strip().lower())
            scenarios.add(row["Scenario"].strip())
        if len(assigned) != count or len(types) != 1:
            raise ValueError(f"incomplete or ambiguous official layout for {name}")
        expected.append(Expected(name, next(iter(types)), size, digest,
                                 ",".join(sorted(scenarios, key=int)), tuple(layout)))
    if len(expected) != 119 or sum(item.complete for item in expected) != 85:
        raise ValueError("expected 85 complete and 34 incomplete 2007 files")
    return expected


def verify_saved_ranges(candidate, image):
    """Hash a saved blockvector directly from the evidence, without expanding a file."""
    if candidate.data_size is not None or not candidate.ranges_valid:
        return candidate
    digest = hashlib.md5()
    remaining = candidate.length
    with Path(image).open("rb") as source:
        image_size = source.seek(0, 2)
        for sector in candidate.sectors:
            take = min(BLOCK_SIZE, remaining)
            offset = sector * BLOCK_SIZE
            if offset > image_size or take > image_size - offset:
                candidate.ranges_valid = False
                return candidate
            source.seek(offset)
            block = source.read(take)
            if len(block) != take:
                candidate.ranges_valid = False
                return candidate
            digest.update(block)
            remaining -= take
    if remaining != 0:
        candidate.ranges_valid = False
    else:
        candidate.md5 = digest.hexdigest()
    return candidate


def load_candidate(path, output, image=None):
    relative = path.relative_to(output)
    status = next((part for part in relative.parts
                   if part in PUBLISHED_STATES or part == "INPROGRESS"), "OTHER")
    length, capacity = None, None
    sectors, indices = [], []
    with path.open(encoding="utf-8") as source:
        for line in source:
            match = re.fullmatch(r"Length:\s+(\d+) bytes\s*", line)
            capacity_match = re.fullmatch(r"Capacity:\s+(\d+) blocks\s*", line)
            row = re.fullmatch(r"\s*(\d+)\s+(-?\d+)\s+(-?\d+)\s*", line)
            if match:
                length = int(match[1])
            elif capacity_match:
                capacity = int(capacity_match[1])
            elif row:
                indices.append(int(row[1]))
                sectors.append(int(row[2]))
    if length is None or capacity is None:
        raise ValueError(f"missing blockvector length/capacity: {path}")
    count = (length + BLOCK_SIZE - 1) // BLOCK_SIZE
    # Saved capacity can include search slots beyond the candidate's byte length.
    ranges_valid = (indices == list(range(len(indices)))
                    and len(indices) <= capacity and len(sectors) >= count
                    and all(block >= 0 for block in sectors[:count]))
    sectors = sectors[:count]
    data_path = Path(str(path)[:-len(SUFFIX)])
    data_size = data_path.stat().st_size if data_path.is_file() else None
    written = path.stat().st_mtime
    if data_size is not None:
        written = max(written, data_path.stat().st_mtime)
        ranges_valid = ranges_valid and data_size == length
    candidate = Candidate(path, status, length, tuple(sectors),
                          digest_file(data_path) if data_size is not None else "",
                          data_size, ranges_valid, written)
    return verify_saved_ranges(candidate, image) if image is not None else candidate


def load_candidates(output, image=None):
    output = Path(output)
    if not output.is_dir():
        raise ValueError(f"no recovery output directory: {output}")
    return [load_candidate(path, output, image) for path in sorted(output.rglob(f"*{SUFFIX}"))]


def published_snapshot(output, cache, expected=None, image=None):
    """Read stable recovery output while carving continues, reusing unchanged hashes."""
    output = Path(output)
    current = {}
    sizes = {item.size for item in expected or () if item.complete and item.md5}
    rounded_sizes = {item.size for item in expected or () if item.complete and not item.md5}

    def possible_size(size):
        return expected is None or size in sizes or any(
            limit - BLOCK_SIZE < size <= limit for limit in rounded_sizes)

    for path in output.rglob(f"*{SUFFIX}"):
        if not PUBLISHED_STATES.intersection(path.relative_to(output).parts):
            continue
        data_path = Path(str(path)[:-len(SUFFIX)])

        def signature():
            try:
                data_stat = data_path.stat()
            except FileNotFoundError:
                data_stat = None
            return tuple((stat.st_dev, stat.st_ino, stat.st_size,
                          stat.st_mtime_ns, stat.st_ctime_ns) if stat is not None else None
                         for stat in (path.stat(), data_stat,
                                      Path(image).stat() if image is not None else None))

        try:
            before = signature()
            # Partial outputs cannot match a complete reference of a different size.
            if before[1] is not None and not possible_size(before[1][2]):
                continue
            if before[1] is None and image is None:
                continue
            cached = cache.get(path)
            candidate = (cached[1] if cached and cached[0] == before
                         else load_candidate(path, output))
            if not possible_size(candidate.length):
                continue
            if image is not None and not candidate.md5:
                verify_saved_ranges(candidate, image)
            # A listing or its payload may still be being written or replaced.
            if (candidate.ranges_valid or candidate.data_size == candidate.length) and before == signature():
                current[path] = before, candidate
        except (FileNotFoundError, ValueError):
            continue
    cache.clear()
    cache.update(current)
    return [candidate for _, candidate in current.values()]


def range_match(item, candidate):
    if not item.layout or not candidate.ranges_valid or candidate.sectors != item.available:
        return False
    # Never let a listing excuse bytes with a known wrong digest.
    if item.complete and item.md5 and candidate.md5:
        return False
    if not item.complete:
        return candidate.length == item.available_bytes
    return not item.md5 or candidate.length >= item.size


def score(expected, candidates):
    unique = {}
    for candidate in sorted(candidates, key=lambda item: item.status != "VALIDATED"):
        if candidate.status in PUBLISHED_STATES:
            unique.setdefault(candidate.identity, candidate)
    by_md5, by_sectors = defaultdict(list), defaultdict(list)
    for candidate in unique.values():
        if candidate.md5:
            by_md5[candidate.md5].append(candidate)
        if candidate.ranges_valid:
            by_sectors[candidate.sectors].append(candidate)
    used, results = set(), []
    for item in expected:
        match = next((candidate for candidate in by_md5.get(item.md5, ())
                      if candidate.identity not in used
                      and (candidate.data_size == item.size or (
                          candidate.data_size is None and candidate.ranges_valid
                          and candidate.length == item.size))), None)
        method = "exact-md5" if match else "not-recovered"
        if match is None:
            match = next((candidate for candidate in by_sectors.get(item.available, ())
                          if candidate.identity not in used and range_match(item, candidate)), None)
            if match:
                method = "exact-complete-ranges" if item.complete else "exact-available-ranges"
        if match:
            used.add(match.identity)
        results.append((item, method, match))
    unmatched = [candidate for identity, candidate in unique.items() if identity not in used]
    return results, unmatched


def classify_prefix(item, candidate):
    available, prefix = item.available, item.prefix
    shared = 0
    for actual, wanted in zip(candidate.sectors, available):
        if actual != wanted:
            break
        shared += 1
    shared_bytes = min(shared * BLOCK_SIZE, candidate.length, item.available_bytes)
    if candidate.data_size is not None:
        shared_bytes = min(shared_bytes, candidate.data_size)
    if not candidate.ranges_valid:
        return 0, "inconsistent-blockvector", 0
    if candidate.sectors == available and candidate.length == item.available_bytes:
        return 7, "exact-all-available", shared_bytes
    if candidate.sectors == prefix and shared_bytes == len(prefix) * BLOCK_SIZE:
        return 6, "exact-through-first-missing", shared_bytes
    if shared_bytes >= len(prefix) * BLOCK_SIZE:
        if shared == len(candidate.sectors):
            return 5, "correct-past-first-missing-partial", shared_bytes
        return 4, "correct-prefix-plus-wrong-tail", shared_bytes
    if shared == len(candidate.sectors):
        return 3, "incomplete-correct-prefix", shared_bytes
    return 2, "partial-prefix-plus-wrong-tail", shared_bytes


def score_prefixes(expected, candidates):
    by_start = defaultdict(list)
    for candidate in candidates:
        if candidate.status in PUBLISHED_STATES and candidate.sectors:
            by_start[candidate.sectors[0]].append(candidate)
    results = []
    for item in expected:
        if item.complete:
            continue
        if not item.prefix:
            results.append((item, "header-missing", 0, None))
            continue
        options = []
        for candidate in by_start[item.prefix[0]]:
            rank, category, shared = classify_prefix(item, candidate)
            options.append((rank, shared, -candidate.length, category, candidate))
        if options:
            _, shared, _, category, candidate = max(options, key=lambda value: value[:3])
            results.append((item, category, shared, candidate))
        else:
            results.append((item, "no-candidate-from-header", 0, None))
    return results


def write_tsv(path, fields, rows):
    with path.open("w", encoding="utf-8", newline="") as target:
        writer = csv.writer(target, delimiter="\t", lineterminator="\n")
        writer.writerow(fields)
        writer.writerows(rows)


def recovery_time(results, candidates, timing, through_epoch):
    """Remember the earliest observed write of each correct complete file."""
    start = timing["carving_start_epoch"]
    first = timing.setdefault("complete_file_written_seconds", {})
    written = {}
    for candidate in candidates:
        if candidate.status in PUBLISHED_STATES and start <= candidate.written <= through_epoch:
            seconds = candidate.written - start
            written[candidate.identity] = min(written.get(candidate.identity, seconds), seconds)
    complete = [(item, candidate) for item, _, candidate in results if item.complete]
    for item, candidate in complete:
        if candidate is not None and candidate.identity in written:
            seconds = written[candidate.identity]
            first[item.name] = min(first.get(item.name, seconds), seconds)
    if not complete or any(candidate is None or item.name not in first
                           for item, candidate in complete):
        return None
    seconds = round(max(first[item.name] for item, _ in complete), 3)
    timing["all_complete_written_by_seconds"] = seconds
    return seconds


def write_report(expected, candidates, destination, timing=None):
    destination = Path(destination)
    destination.mkdir(parents=True, exist_ok=True)
    results, unmatched = score(expected, candidates)
    prefixes = score_prefixes(expected, candidates)
    complete = sum(item.complete for item in expected)
    exact = sum(item.complete and candidate is not None for item, _, candidate in results)
    methods = Counter(method for _, method, _ in results)
    unmatched_states = Counter(candidate.status for candidate in unmatched)
    summary = {
        "expected_files": len(expected), "complete_files_in_image": complete,
        "incomplete_files_in_image": len(expected) - complete,
        "complete_files_exact": exact, "complete_files_missing": complete - exact,
        "exact_md5": methods["exact-md5"],
        "exact_complete_ranges": methods["exact-complete-ranges"],
        "exact_available_ranges": methods["exact-available-ranges"],
        "unique_unmatched_validated": unmatched_states["VALIDATED"],
        "unique_unmatched_promising": unmatched_states["PROMISING"],
        "raw_candidate_blockvectors": len(candidates),
        "incomplete_prefixes": dict(Counter(category for _, category, _, _ in prefixes)),
    }
    summary["passed"] = exact == complete and unmatched_states["VALIDATED"] == 0
    write_tsv(destination / "expected-results.tsv",
              ("name", "type", "scenario", "complete_in_image", "size", "md5", "result",
               "candidate_status", "candidate_length", "candidate_blockvector"),
              ((item.name, item.file_type, item.scenario, int(item.complete), item.size,
                item.md5, method, candidate.status if candidate else "",
                candidate.length if candidate else "", str(candidate.path) if candidate else "")
               for item, method, candidate in results))
    write_tsv(destination / "unmatched-candidates.tsv",
              ("status", "length", "md5", "blockvector"),
              ((candidate.status, candidate.length, candidate.md5, str(candidate.path))
               for candidate in unmatched))
    write_tsv(destination / "incomplete-prefix-results.tsv",
              ("name", "type", "prefix_bytes_before_missing", "available_sectors", "result",
               "correct_leading_bytes", "candidate_status", "candidate_length", "blockvector"),
              ((item.name, item.file_type, len(item.prefix) * BLOCK_SIZE, len(item.available),
                category, shared, candidate.status if candidate else "",
                candidate.length if candidate else "", str(candidate.path) if candidate else "")
               for item, category, shared, candidate in prefixes))
    if timing:
        summary["carving_seconds"] = timing["carving_seconds"]
        summary["scalpel_exit_status"] = timing["scalpel_exit_status"]
        if "all_complete_verified_seconds" in timing:
            summary["all_complete_verified_seconds"] = timing["all_complete_verified_seconds"]
        summary["passed"] = summary["passed"] and timing["scalpel_exit_status"] == 0
        seconds = recovery_time(results, candidates, timing, timing["carving_end_epoch"])
        if seconds is not None:
            summary["all_complete_written_by_seconds"] = seconds
        summary["timing_note"] = (
            "Recovery time uses the earliest observed write timestamps of correct outputs, "
            "not verification completion. It is an upper bound if output was rewritten "
            "before its first observation."
        )
    (destination / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(f"Complete files recovered: {exact}/{complete}", flush=True)
    print(f"Unmatched VALIDATED outputs: {unmatched_states['VALIDATED']}", flush=True)
    if prefixes:
        print("Incomplete files (reported separately):", flush=True)
        for category, count in sorted(summary["incomplete_prefixes"].items()):
            print(f"  {category}: {count}", flush=True)
    if timing:
        print(f"Carving runtime: {timing['carving_seconds']:.3f} seconds", flush=True)
        if "all_complete_written_by_seconds" in summary:
            print(f"All complete files recovered in {summary['all_complete_written_by_seconds']:.3f} "
                  "seconds", flush=True)
    print(f"{'PASS' if summary['passed'] else 'FAIL'}: {destination / 'summary.json'}", flush=True)
    return summary
