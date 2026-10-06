#!/usr/bin/env python3
"""Download, run, and independently score the official DFRWS carving images."""

from __future__ import annotations

import argparse
import fcntl
import json
import os
import shlex
import signal
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import zipfile
from pathlib import Path

from dfrws_score import (digest_file, load_candidates, load_expected, published_snapshot,
                         recovery_time, score, write_report)


TESTS = Path(__file__).resolve().parent
SOURCE = TESTS.parent
CHALLENGES = {
    "2006": {
        "image": "dfrws-2006-challenge.raw",
        "bytes": 49_999_872,
        "md5": "bd09d612fc8b3f92662b98f9456f2ada",
        "url": "https://www.dropbox.com/s/genp058scvl8hbp/dfrws-2006-challenge.zip?dl=1",
        "sha256": "fffafba5a65ad37e069e1d7be82abf705d299cc9105aada3774da2a397bb9c4b",
    },
    "2007": {
        "image": "dfrws-2007-challenge.img",
        "bytes": 346_971_136,
        "md5": "8a501f3f525c85a50a3aa0bf698bffe7",
        "url": "https://www.dropbox.com/s/5ze0r2o1vjxf811/dfrws-2007-challenge.zip?dl=1",
        "sha256": "46d58c27bca97fd76f9c51c19c8fa3a467ca30250fcbbfc090d1450ec7630ea3",
    },
}
GROUND_TRUTH_2006 = (
    "https://www.dropbox.com/s/aqdsxy0juetbcym/dfrws-2006-challenge-files.zip?dl=1",
    "5629d0ad5583bc2e51554a53d3d068c480fd81774bfccd73f3bf39ccbe13b8c8",
)
METADATA_REVISION = "d72ce64b7e6e9ddb2184924d0eecf229d485f659"
METADATA_2007 = {
    "challenge-file-info.txt": "4d3eba8cd2a3aac31c6c607f10139efb053cd2e1406c7f4274e2690bc57b6ccc",
    "challenge-layout.txt": "48c39daf4ff19399cb7a8058d6f8d314742ec45332c22f876bc46eba14145434",
}


def verify(path, digest, algorithm="sha256", size=None):
    if not path.is_file() or (size is not None and path.stat().st_size != size):
        raise ValueError(f"missing file or wrong size: {path}")
    actual = digest_file(path, algorithm)
    if actual != digest:
        raise ValueError(f"{algorithm} mismatch for {path}: expected {digest}, got {actual}. "
                         "Existing files are not overwritten; move it aside to download again.")


def download(url, target, expected_sha256, max_bytes):
    if target.exists():
        print(f"Checking cached download: {target.name}", flush=True)
        verify(target, expected_sha256)
        print(f"Verified cached download: {target.name}", flush=True)
        return
    # The caller holds the per-challenge download lock. A deterministic staging
    # name also permits cleanup after an interrupted previous download.
    partial = target.with_name(target.name + ".part")
    for attempt in range(3):
        partial.unlink(missing_ok=True)
        try:
            print(f"Downloading {target.name} (attempt {attempt + 1}/3). "
                  "Connecting to the server; recovery has not started.", flush=True)
            request = urllib.request.Request(url, headers={"User-Agent": "Scalpel3-DFRWS-tests"})
            started = time.monotonic()
            with urllib.request.urlopen(request, timeout=60) as response, partial.open("xb") as output:
                written = 0
                reported = started
                header = getattr(response, "headers", {}).get("Content-Length", "")
                total = int(header) if header.isdigit() else 0
                if total > max_bytes:
                    raise ValueError(f"download exceeds expected size bound: {target.name}")
                while True:
                    block = response.read(64 * 1024)
                    if not block:
                        break
                    written += len(block)
                    if written > max_bytes:
                        raise ValueError(f"download exceeds expected size bound: {target.name}")
                    output.write(block)
                    now = time.monotonic()
                    if now - reported >= 2:
                        progress = f"{written / (1024 * 1024):.1f} MiB"
                        if total:
                            progress += f" / {total / (1024 * 1024):.1f} MiB ({100 * written / total:.0f}%)"
                        print(f"  Downloading {target.name}: {progress}, "
                              f"{now - started:.0f}s elapsed", flush=True)
                        reported = now
                output.flush()
                os.fsync(output.fileno())
            print(f"Downloaded {target.name}: {written / (1024 * 1024):.1f} MiB "
                  f"in {time.monotonic() - started:.1f}s. Checking SHA256...", flush=True)
            verify(partial, expected_sha256)
            os.replace(partial, target)
            print(f"Download verified: {target.name}", flush=True)
            return
        except (OSError, urllib.error.URLError) as error:
            if attempt == 2:
                raise
            print(f"Download interrupted: {error}. Retrying in {2 ** attempt}s...", flush=True)
            time.sleep(2 ** attempt)
        finally:
            partial.unlink(missing_ok=True)


def prepare_data(challenge, data_dir, need_image=True):
    spec = CHALLENGES[challenge]
    metadata = data_dir / "dfrws-data" / challenge
    metadata.mkdir(parents=True, exist_ok=True)
    image = data_dir / spec["image"]
    with (metadata / "download.lock").open("a") as lock:
        print(f"Preparing DFRWS {challenge} inputs. Downloads, extraction and verification "
              "are separate from recovery and may take several minutes.", flush=True)
        print("Waiting for exclusive access to the downloaded inputs...", flush=True)
        fcntl.flock(lock, fcntl.LOCK_EX)
        if need_image:
            if not image.exists():
                archive = metadata / f"dfrws-{challenge}-challenge.zip"
                download(spec["url"], archive, spec["sha256"], 400 * 1024 * 1024)
                partial = image.with_name(image.name + ".part")
                partial.unlink(missing_ok=True)
                try:
                    print(f"Extracting {spec['image']} "
                          f"({spec['bytes'] / (1024 * 1024):.1f} MiB)...", flush=True)
                    # Extract exactly the named image, never archive-supplied paths.
                    with zipfile.ZipFile(archive) as zipped:
                        member = zipped.getinfo(spec["image"])
                        if member.file_size != spec["bytes"]:
                            raise ValueError("unexpected uncompressed image size")
                        with zipped.open(member) as source, partial.open("xb") as output:
                            while True:
                                block = source.read(1024 * 1024)
                                if not block:
                                    break
                                output.write(block)
                            output.flush()
                            os.fsync(output.fileno())
                    print("Checking extracted image checksum...", flush=True)
                    verify(partial, spec["md5"], "md5", spec["bytes"])
                    os.replace(partial, image)
                finally:
                    partial.unlink(missing_ok=True)
            print(f"Checking challenge image: {image}", flush=True)
            verify(image, spec["md5"], "md5", spec["bytes"])
            print(f"Verified challenge image: {image}", flush=True)
        if challenge == "2006":
            download(GROUND_TRUTH_2006[0], metadata / "dfrws-2006-challenge-files.zip",
                     GROUND_TRUTH_2006[1], 64 * 1024 * 1024)
        else:
            for filename, digest in METADATA_2007.items():
                url = ("https://raw.githubusercontent.com/dfrws/dfrws2007-challenge/"
                       f"{METADATA_REVISION}/{filename}")
                download(url, metadata / filename, digest, 1024 * 1024)
    return image, metadata


def save_record(path, record):
    staging = path.with_suffix(".json.part")
    with staging.open("w", encoding="utf-8") as target:
        json.dump(record, target, indent=2)
        target.write("\n")
        target.flush()
        os.fsync(target.fileno())
    os.replace(staging, path)


def recent_status(path):
    with path.open("rb") as source:
        source.seek(0, 2)
        source.seek(max(0, source.tell() - 8192))
        lines = source.read().decode("utf-8", errors="replace").splitlines(keepends=True)
    # A running carver can be in the middle of writing its next status line.
    lines = [line.rstrip() for line in lines if line.endswith(("\n", "\r"))]
    statuses = [index for index, line in enumerate(lines)
                if (line.startswith("Status:") or "MoDiCo classified" in line)
                and (not line.startswith("Status: promising queue:")
                     or "total elapsed time:" in " ".join(lines[index:index + 2]))]
    if statuses:
        index = statuses[-1]
        return " ".join(lines[index:index + 2])[:600]
    return "No new recovery status yet; see the log."


def tool_environment():
    environment = os.environ.copy()
    if not environment.get("SCALPEL3_HOME"):
        environment["SCALPEL3_HOME"] = str(SOURCE.parent)
    return environment


def output_argument(output):
    """Use the shorter equivalent pathname for the carver's local control socket."""
    relative = os.path.relpath(output, SOURCE)
    return relative if len(os.fsencode(relative)) < len(os.fsencode(output)) else str(output)


def completion_banner(challenge, count, seconds, continuation):
    elapsed = (f"All complete files recovered in {seconds:.3f} seconds." if seconds is not None
               else "Recovery time unavailable from output timestamps.")
    lines = [f"DFRWS {challenge}: ALL {count} COMPLETE FILES RECOVERED EXACTLY",
             elapsed, "", continuation]
    if continuation == "Continuing to search for the best possible fragments of incomplete files.":
        lines.append("Press Ctrl-C to checkpoint, stop, and report the results.")
    border = "*" * 78
    print("\n" + border, flush=True)
    for line in lines:
        print("* " + line.center(74) + " *", flush=True)
    print(border + "\n", flush=True)


def run_tool(command, log_path, completed=None, stop_when_complete=False):
    print("Running: " + shlex.join(str(arg) for arg in command), flush=True)
    print(f"Full output: {log_path}", flush=True)
    start = time.monotonic()
    reported = start
    completion_reported = False
    with log_path.open("wb") as log:
        with subprocess.Popen(command, cwd=SOURCE, stdin=subprocess.DEVNULL,
                              stdout=log, stderr=subprocess.STDOUT,
                              env=tool_environment(), start_new_session=True) as process:
            try:
                while True:
                    try:
                        return process.wait(timeout=2 if completed and not completion_reported else 30)
                    except subprocess.TimeoutExpired:
                        if completed and not completion_reported and completed():
                            completion_reported = True
                            if stop_when_complete and process.poll() is None:
                                process.send_signal(signal.SIGUSR1)
                        now = time.monotonic()
                        if now - reported >= 30:
                            print(f"[{now - start:.0f}s] {recent_status(log_path)}", flush=True)
                            reported = now
            except BaseException as error:
                print("Stopping the active tool; keeping its output and logs.", flush=True)
                if process.poll() is None:
                    process.send_signal(signal.SIGUSR1 if Path(command[0]).name == "scalpel3"
                                        else signal.SIGTERM)
                returncode = process.wait()
                if isinstance(error, KeyboardInterrupt):
                    # A requested checkpoint is a normal carver exit. Its saved
                    # results are scored below, without masking a real failure.
                    return returncode if Path(command[0]).name == "scalpel3" else 130
                raise


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Run and score a DFRWS challenge. Remaining options go to scalpel3.",
        epilog="Example: TESTS/cmdline.dfrws2007 -e 16",
        allow_abbrev=False)
    parser.add_argument("challenge", choices=CHALLENGES)
    parser.add_argument("--data-dir", type=Path, default=TESTS,
                        help="image/download directory (default: TESTS)")
    parser.add_argument("-o", "--output", type=Path,
                        help="new run directory for logs, blockmap, recovery, and scores")
    parser.add_argument("-q", type=int, default=512, help="challenge sector size; must be 512")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--download-only", action="store_true", help="verify/download inputs and stop")
    mode.add_argument("--score-only", type=Path, help="score an existing Scalpel3 output directory")
    parser.add_argument("--stop-when-complete", action="store_true",
                        help="checkpoint and exit after every complete file has been verified")
    args, extra = parser.parse_known_args(argv)
    if args.q != 512:
        parser.error("these images use 512-byte sectors; larger blocks change the recovery problem")
    if extra and extra[0] == "--":
        extra.pop(0)
    if any(arg.startswith(("-q", "-o", "--output")) for arg in extra):
        parser.error("put -q/-o options before --; the scripts supply the image and blockmap")
    if any(not arg.startswith("-") for arg in extra[:1]):
        parser.error("unexpected positional argument; the scripts supply the image and blockmap")
    if (args.download_only or args.score_only) and extra:
        parser.error("Scalpel3 options apply only to a recovery run")
    if (args.download_only or args.score_only) and args.stop_when_complete:
        parser.error("--stop-when-complete applies only to a recovery run")
    return args, extra


def main(argv=None):
    args, extra = parse_args(argv)
    if not args.download_only and not args.score_only:
        for name in ("scalpel3", "crblockmap"):
            if not os.access(SOURCE / name, os.X_OK):
                raise ValueError(f"missing executable {SOURCE / name}; run init_scalpel3.sh first")
    image, metadata = prepare_data(args.challenge, args.data_dir.resolve())
    # Validate the reference metadata before spending time on recovery.
    expected = load_expected(args.challenge, metadata)
    if args.download_only:
        print("Challenge inputs are verified and ready.", flush=True)
        return 0
    if args.output:
        destination = args.output.resolve()
        destination.mkdir(parents=True, exist_ok=False)
    else:
        root = TESTS / "dfrws-results"
        root.mkdir(exist_ok=True)
        destination = Path(tempfile.mkdtemp(prefix=f"{args.challenge}-{time.strftime('%Y%m%d-%H%M%S')}-",
                                           dir=root))
    print(f"Run directory: {destination}", flush=True)
    output = args.score_only.resolve() if args.score_only else destination / "scalpel-output"
    record = {"challenge": args.challenge, "image": str(image),
              "image_md5": CHALLENGES[args.challenge]["md5"], "block_size": 512,
              "scalpel_home": tool_environment()["SCALPEL3_HOME"],
              "scorer_sha256": digest_file(TESTS / "dfrws_score.py", "sha256"),
              "script_sha256": digest_file(Path(__file__), "sha256"),
              "stop_when_complete": args.stop_when_complete,
              "state": "scoring" if args.score_only else "blockmap"}
    record_path = destination / "run.json"
    save_record(record_path, record)
    timing, rc = None, 0
    try:
        if not args.score_only:
            blockmap = destination / "image.blockmap"
            record["scalpel_sha256"] = digest_file(SOURCE / "scalpel3", "sha256")
            record["crblockmap_sha256"] = digest_file(SOURCE / "crblockmap", "sha256")
            command = [str(SOURCE / "scalpel3"), "-q", "512", "-b", "-w", *extra,
                       "-o", output_argument(output), str(image), str(blockmap)]
            record["command"] = command
            save_record(record_path, record)
            rc = run_tool([str(SOURCE / "crblockmap"), "-q", "512", str(image), str(blockmap)],
                          destination / "crblockmap.log")
            if rc != 0:
                raise RuntimeError(f"crblockmap exited with status {rc}")
            record["state"] = "carving"
            record["carving_start_epoch"] = time.time()
            save_record(record_path, record)
            start = time.monotonic()
            cache = {}
            previous_exact = -1
            complete = sum(item.complete for item in expected)

            def completed():
                nonlocal previous_exact
                candidates = published_snapshot(output, cache, expected, image)
                results, _ = score(expected, candidates)
                seconds = recovery_time(results, candidates, record, time.time())
                exact = sum(item.complete and candidate is not None
                            for item, _, candidate in results)
                if exact != previous_exact:
                    print(f"Independently verified complete files: {exact}/{complete}", flush=True)
                    previous_exact = exact
                    save_record(record_path, record)
                if exact != complete:
                    return False
                record["all_complete_verified_seconds"] = round(time.monotonic() - start, 3)
                save_record(record_path, record)
                completion_banner(args.challenge, complete, seconds,
                                  "Requesting a clean checkpoint and exit." if args.stop_when_complete
                                  else "Continuing to search for the best possible fragments of incomplete files.")
                return True

            print("Starting recovery. There is no test time limit; runtime depends on the "
                  "machine and remaining candidates. Progress is reported every 30 seconds.",
                  flush=True)
            print("A banner will announce when every complete file has been independently verified.",
                  flush=True)
            if args.stop_when_complete:
                print("--stop-when-complete: recovery will then checkpoint and exit.", flush=True)
            rc = run_tool(command, destination / "scalpel3.log", completed, args.stop_when_complete)
            record["carving_seconds"] = time.monotonic() - start
            record["carving_end_epoch"] = time.time()
            record["scalpel_exit_status"] = rc
            record["state"] = "scoring"
            save_record(record_path, record)
            timing = record
            if not output.is_dir():
                raise RuntimeError(f"scalpel3 exited with status {rc} without creating output")
        candidates = load_candidates(output, image)
        if timing and rc == 0 and "all_complete_verified_seconds" not in record:
            results, _ = score(expected, candidates)
            if all(candidate is not None for item, _, candidate in results if item.complete):
                record["all_complete_verified_seconds"] = round(time.monotonic() - start, 3)
                seconds = recovery_time(results, candidates, record, record["carving_end_epoch"])
                completion_banner(args.challenge, sum(item.complete for item in expected),
                                  seconds,
                                  "Recovery has ended; final output verified.")
        report = write_report(expected, candidates, destination / "scoring", timing)
        record["state"] = "passed" if report["passed"] and rc == 0 else "failed"
        save_record(record_path, record)
        return 0 if record["state"] == "passed" else 1
    except BaseException as error:
        record["state"] = "interrupted" if isinstance(error, KeyboardInterrupt) else "failed"
        record["error"] = str(error)
        save_record(record_path, record)
        raise


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
    except (OSError, ValueError, RuntimeError, zipfile.BadZipFile, urllib.error.URLError) as error:
        print(f"DFRWS test failed: {error}", file=sys.stderr)
        sys.exit(1)
