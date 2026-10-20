# Known Limitations

## 1. Block-Aligned Nested Executables

A Windows PE executable can contain another complete executable, for example
as an embedded resource. If the embedded executable's header falls on a carving
block boundary in the disk image, Scalpel3 may detect and recover it independently.
Alignment depends on the block size selected with `-q`; embedded executable
headers are not generally guaranteed to align with carving blocks.

If the embedded executable is recovered first, its blocks may be marked as
covered and excluded from subsequent reassembly searches. The enclosing
executable can then be recovered incompletely or missed, even when all of its
bytes are present in the image. The outcome depends on alignment and recovery
order; not every nested executable is affected.

Excluding covered blocks keeps the search space manageable on large images.
Scalpel3 does not currently guarantee recovery of both an embedded executable
and its enclosing executable when they share those blocks.

## 2. Ambiguous Fragmented ELF Content

ELF metadata and internal references can establish that parts of a reconstruction
are consistent, but cannot prove that every code or application-data block belongs
to that executable. Difficult out-of-order fragmentation, including tested cases
with 512-byte carving blocks, can still produce incorrect reconstructions that
pass validation. This is a known accuracy limitation, not a guarantee that all
such files are recovered incorrectly.

Treat validation as evidence of format consistency, not proof of byte-for-byte
identity. Independently verify recovered executables whenever a trusted original,
hash or other external evidence is available.
