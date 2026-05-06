#!/usr/bin/env python3
'''
Generate a synthetic ".abc" file for testing the scalpel3 abc validator.

The .abc file format (defined in abc.h) consists of 26 blocks:

    [BLOCK  1]  "#0123456789#" + 'A' padding to blocksize
    [BLOCK  2]  'B' * blocksize
    [BLOCK  3]  'C' * blocksize
    ...
    [BLOCK 25]  'Y' * blocksize
    [BLOCK 26]  'Z' padding + "#9876543210#"

Total file size is always 26 * blocksize.

Usage:
    python3 generate-abc-file.py <output_filename> <blocksize>

Example:
    python3 generate-abc-file.py test.abc 512
'''

import sys

FILE_HEADER = b"#0123456789#"
FILE_FOOTER = b"#9876543210#"
NUM_BLOCKS = 26  # A-Z


def create_abc_file(filename, blocksize):
    if blocksize < len(FILE_HEADER):
        print(f"Error: blocksize must be at least {len(FILE_HEADER)}", file=sys.stderr)
        sys.exit(1)

    with open(filename, "wb") as f:
        # Block 1: header + 'A' padding
        f.write(FILE_HEADER + b'A' * (blocksize - len(FILE_HEADER)))

        # Blocks 2-25: B through Y
        for letter in range(ord('B'), ord('Z')):
            f.write(bytes([letter]) * blocksize)

        # Block 26: 'Z' padding + footer
        f.write(b'Z' * (blocksize - len(FILE_FOOTER)) + FILE_FOOTER)

    print(f"Generated {filename} ({NUM_BLOCKS * blocksize} bytes, blocksize={blocksize})")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <output_filename> <blocksize>", file=sys.stderr)
        sys.exit(1)

    create_abc_file(sys.argv[1], int(sys.argv[2]))
