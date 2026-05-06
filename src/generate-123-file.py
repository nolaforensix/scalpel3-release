#!/usr/bin/env python3
'''
Generate a synthetic ".123" file for testing the scalpel3 123 validator.

The .123 file format (defined in 123.h) consists of:

    [HEADER BLOCK]     "#HEADER#" + 8-char hex file ID + '-' padding
    [0-section blocks]  one or more blocks filled with '0'
    [1-section blocks]  one or more blocks filled with '1'
    ...
    [9-section blocks]  one or more blocks filled with '9'
    [METADATA BLOCK]   "#METADATA#" + 8-char hex file ID + 10 records + '-' padding
    [FOOTER BLOCK]     "#FOOTER#" padded with '-' to blocksize

The 8-character hex file ID ties the header and metadata together,
allowing the reassembler to match the correct metadata to its header
when multiple 123 files coexist in an image.

Each metadata record is: <section_type:1><offset:8><size:8> (ASCII digits).

Usage:
    python3 generate-123-file.py <output_filename> <blocksize> [blocks_per_section]

    blocks_per_section defaults to 1.  Pass a larger value to create files
    with multi-block sections.

Examples:
    python3 generate-123-file.py test.123 512
    python3 generate-123-file.py big.123 4096 3
'''

import os
import sys

HEADER_SIG = b"#HEADER#"
FOOTER_SIG = b"#FOOTER#"
METADATA_SIG = b"#METADATA#"
FILE_ID_SIZE = 8        # 8 hex characters
NUM_SECTIONS = 10       # sections 0-9


def create_123_file(filename, blocksize, blocks_per_section=1):
    header_size = len(HEADER_SIG)
    footer_size = len(FOOTER_SIG)
    metadata_sig_size = len(METADATA_SIG)
    record_size = 17  # 1 (type) + 8 (offset) + 8 (size)
    metadata_data_size = metadata_sig_size + FILE_ID_SIZE + NUM_SECTIONS * record_size

    if blocksize < max(header_size + FILE_ID_SIZE, footer_size, metadata_data_size):
        print(f"Error: blocksize must be at least {metadata_data_size}", file=sys.stderr)
        sys.exit(1)

    # Generate a random 8-char hex file ID
    file_id = os.urandom(4).hex().encode('ascii')  # 4 random bytes -> 8 hex chars

    # Compute section layout: sections 0-9, each blocks_per_section blocks
    # Layout: header(1) + sections(10 * bps) + metadata(1) + footer(1)
    section_size = blocks_per_section * blocksize
    sections = []
    offset = blocksize  # first section starts after header block
    for sec in range(NUM_SECTIONS):
        sections.append((sec, offset, section_size))
        offset += section_size

    with open(filename, "wb") as f:
        # Header block: signature + file ID + dash padding
        f.write(HEADER_SIG + file_id + b'-' * (blocksize - header_size - FILE_ID_SIZE))

        # Section data blocks
        for sec_type, _, sec_size in sections:
            digit = str(sec_type).encode('ascii')
            for _ in range(sec_size // blocksize):
                f.write(digit * blocksize)

        # Metadata block: signature + file ID + records + dash padding
        meta = bytearray(METADATA_SIG + file_id)
        for sec_type, sec_offset, sec_size in sections:
            meta += f"{sec_type}{sec_offset:08d}{sec_size:08d}".encode('ascii')
        meta += b'-' * (blocksize - len(meta))
        f.write(bytes(meta))

        # Footer block
        f.write(FOOTER_SIG + b'-' * (blocksize - footer_size))

    total_blocks = 1 + NUM_SECTIONS * blocks_per_section + 1 + 1
    total_size = total_blocks * blocksize
    print(f"Generated {filename} ({total_size} bytes, blocksize={blocksize}, "
          f"{blocks_per_section} block(s)/section, {total_blocks} total blocks, "
          f"id={file_id.decode()})")


if __name__ == "__main__":
    if len(sys.argv) < 3 or len(sys.argv) > 4:
        print(f"Usage: {sys.argv[0]} <output_filename> <blocksize> [blocks_per_section]",
              file=sys.stderr)
        sys.exit(1)

    output = sys.argv[1]
    bs = int(sys.argv[2])
    bps = int(sys.argv[3]) if len(sys.argv) == 4 else 1
    create_123_file(output, bs, bps)
