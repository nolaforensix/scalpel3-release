#!/usr/bin/env python3
'''Generate a deterministic CSV file for the Scalpel3 regression test.

The file remains smaller than one Scalpel3 block and exercises empty fields,
escaped quotes, embedded delimiters, multiline fields, and UTF-8 text.

Usage:
    python3 generate-csv-file.py <output_filename> <blocksize>
'''

import csv
import io
import sys


def create_csv_file(filename, blocksize):
    if blocksize < 512:
        raise ValueError("blocksize must be at least 512")

    rows = [
        ("id", "name", "note", "amount", "active"),
        ("1", "Ada Lovelace", "first, analytical engine", "12.50", "true"),
        ("2", 'Grace "Amazing" Hopper', "", "-3.25", "true"),
        ("3", "Jos\u00e9 Alvarez", "UTF-8: jalape\u00f1o", "0", "false"),
        ("4", "", "empty field retained", "18.75", "false"),
        ("5", "Katherine Johnson", "line one\nline two", "101.0", "true"),
    ]
    output = io.StringIO(newline="")
    writer = csv.writer(output, lineterminator="\n")
    writer.writerows(rows)
    data = output.getvalue().encode("utf-8")

    if len(data) >= blocksize:
        raise ValueError(
            f"generated CSV is {len(data)} bytes and does not fit in a "
            f"{blocksize}-byte block"
        )

    with open(filename, "wb") as csv_file:
        csv_file.write(data)

    print(f"Generated {filename} ({len(data)} bytes, blocksize={blocksize})")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <output_filename> <blocksize>",
              file=sys.stderr)
        sys.exit(1)

    create_csv_file(sys.argv[1], int(sys.argv[2]))
