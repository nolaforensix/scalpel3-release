#!/usr/bin/env python3
'''Generate a deterministic SQLite database for the Scalpel3 regression test.

The database is sized relative to Scalpel3's block size so the same GAP and
OUTOFORDER directives can be exercised with different -q values.

Usage:
    python3 generate-sqlite-file.py <output_filename> <blocksize>
'''

import os
import sqlite3
import sys


def sqlite_page_size_for_blocksize(blocksize):
    if 512 <= blocksize <= 65536 and blocksize & (blocksize - 1) == 0:
        return blocksize
    return 4096


def deterministic_payload(row_id, length):
    return bytes(((row_id * 17 + offset * 31) & 0xff)
                 for offset in range(length))


def create_sqlite_file(filename, blocksize):
    if blocksize <= 0:
        raise ValueError("blocksize must be positive")

    if os.path.exists(filename):
        os.remove(filename)

    page_size = sqlite_page_size_for_blocksize(blocksize)
    target_size = 24 * blocksize
    connection = sqlite3.connect(filename)

    try:
        connection.execute(f"PRAGMA page_size={page_size}")
        connection.execute("PRAGMA journal_mode=DELETE")
        connection.execute("PRAGMA synchronous=OFF")
        connection.execute("PRAGMA auto_vacuum=NONE")
        connection.execute("PRAGMA application_id=0x53434c33")
        connection.execute("PRAGMA user_version=1")
        connection.execute(
            "CREATE TABLE records ("
            "id INTEGER PRIMARY KEY, "
            "label TEXT NOT NULL UNIQUE, "
            "payload BLOB NOT NULL, "
            "checksum INTEGER NOT NULL)"
        )
        connection.execute("CREATE INDEX records_checksum ON records(checksum)")

        row_id = 1
        while True:
            rows = []
            for _ in range(64):
                payload = deterministic_payload(row_id, 1536)
                rows.append((row_id, f"sqlite-regression-{row_id:06d}",
                             payload, sum(payload)))
                row_id += 1

            connection.executemany(
                "INSERT INTO records(id, label, payload, checksum) VALUES (?, ?, ?, ?)",
                rows)
            connection.commit()

            if os.path.getsize(filename) >= target_size:
                break

        integrity = connection.execute("PRAGMA integrity_check").fetchone()[0]
        if integrity != "ok":
            raise RuntimeError(f"generated database failed integrity_check: {integrity}")

        page_count = connection.execute("PRAGMA page_count").fetchone()[0]
    finally:
        connection.close()

    size = os.path.getsize(filename)
    print(f"Generated {filename} ({size} bytes, blocksize={blocksize}, "
          f"SQLite page size={page_size}, pages={page_count}, rows={row_id - 1})")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <output_filename> <blocksize>",
              file=sys.stderr)
        sys.exit(1)

    create_sqlite_file(sys.argv[1], int(sys.argv[2]))
