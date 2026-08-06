# Template for fragmentator configuration. Blank lines are ignored.
# A '#' outside a double-quoted argument begins an inline comment, so
# quote pathnames containing '#'. Multiline comments are supported:
# use /* and */ to bracket lines and place the /* and */ strings on
# lines by themselves. All options are case insensitive.

# Numeric arguments must contain unsigned base-10 digits only. Except
# for BLOCKSIZE and file block-number sets/ranges, they may range from
# 0 through 9223372036854775807.

# OUTPUTFILE (REQUIRED): Pathname for generated image file. It's
# recommended that this match the name of the template file with the
# extension ".img" instead of ".frg".  If the ".img" extension isn't
# provided, it is automatically created.  A ".key" file will also be
# created, which contains the ground truth for the generated image
# file.

OUTPUTFILE: something.img

# SEED (REQUIRED): Seed for random number generator.  Allows
# deterministic generation of fragmented image files.

SEED: 1

# BLOCKSIZE (REQUIRED): Block size for generated image file. This must
# be from 512 through 1073741824, inclusive, and divisible by 512.

BLOCKSIZE: 8192

# HEADERBLOCKS (OPTIONAL): If this option is present, it specifies the
# number of initial blocks for each file that will not be fragmented.
# This affects all files.  The default is 1 block.

HEADERBLOCKS: 1

# ZEROPADBLOCKS (OPTIONAL): If this option is present and non-zero,
# the generated image file is padded with zero-filled blocks to reach
# the specified number of blocks. Put another way, the specified
# number indicates the minumum final number of blocks in the image
# file, with zero-filled blocks used to reach this size. If the number
# of blocks in the image file prior to padding exceeds this number,
# then this option is ignored. ONLY ONE OF ZEROPAD AND RANDOMPAD MAY
# BE SPECIFIED.

ZEROPADBLOCKS: 0

# RANDOMPADBLOCKS (OPTIONAL): If this option is present and non-zero,
# the generated image file is padded with randomly filled blocks to
# reach the specified number of blocks. Put another way, the specified
# number indicates the minumum final number of blocks in the image
# file, with random-filled blocks used to reach this size. If the number
# of blocks in the image file prior to padding exceeds this number,
# then this option is ignored. ONLY ONE OF ZEROPAD AND RANDOMPAD MAY
# BE SPECIFIED.

RANDOMPADBLOCKS: 0

# INITIALRANDOMBLOCKS (OPTIONAL): If this option is present and non-zero, the
# specified number of blocks containing random data are inserted at the beginning
# of the image file.

INITIALRANDOMBLOCKS: 0

# INITIALZEROBLOCKS (OPTIONAL): If this option is present and non-zero, the
# specified number of blocks containing zeros are inserted at the beginning of the
# image file.

INITIALZEROBLOCKS: 0

# RANDOMBLOCKS (OPTIONAL): If this option is present and non-zero, the
# specified number of blocks containing random data are inserted at
# random locations in the image file after all file data is inserted.

RANDOMBLOCKS: 0

# ZEROBLOCKS (OPTIONAL): If this option is present and non-zero, the
# specified number of blocks containing zeros are inserted at random
# locations in the image file after all file data is inserted.

ZEROBLOCKS: 0

# When MISSING blocks, OUTOFORDERBLOCKS, or GAPS are specified for a
# FILE: definition (see below), "holes" are created in a file that
# must be filled with other data.  These holes can be filled with
# portions of or entire files that fit within a hole, RANDOM data, or
# ZEROs.  The FILLHOLESPRIMARY and FILLHOLESSECONDARY options set
# global preferences for how to fill file holes. The secondary
# preference is used ONLY when it is impossible to identify data to
# fill a hole using the primary preference.  This only occurs when the
# primary is FILE, as it is always possible to generate random or
# zero-filled blocks. The default is FILE for FILLHOLESPRIMARY and
# RANDOM for FILLHOLESSECONDARY.  Only RANDOM or ZERO may be specified
# for FILLHOLESSECONDARY.

# In the following, filling holes with FILE data is preferred, with
# ZERO fills used as a backup when no appropriate FILE data is
# available.

FILLHOLESPRIMARY: FILE

FILLHOLESSECONDARY: ZERO

# FILE definitions indicate which files should be used to build the
# disk image. FILE definitions ust appear AFTER all other options are
# specified. The single argument following FILE: is the pathname of
# the file.  Options on lines following the FILE: line control how the
# file data is fragmented and these options have local scope--they
# apply only to the current FILE definition.

# The file options (MISSING, OUTOFORDER, FRAGMENTED, DUPLICATE:, and
# GAP, all of which are optional) then appear one by one on separate
# lines, terminated by a subsequent FILE: line or the end of file.
# Blocks are numbered from 0.

# MISSING allows specification of block numbers (or ranges) for file
# blocks that should be omitted entirely from the generated image
# file.

# OUTOFORDER allows specification of block numbers (or ranges) for
# file blocks that should be placed randomly in the generated image
# file instead of contigously within the file.

# DUPLICATE allows specification of block numbers (or ranges) for
# file blocks that should be duplicated and then placed randomly in
# the generated image.

# GAP is intended to allow simulation of file fragmentation where the
# file is sequentially sliced into fragments which are separated by
# spans of unrelated blocks. Unlike OUTOFORDER, which moves specified
# blocks into another region of the generated image file, GAP inserts
# blocks into the file.  GAP block numbers must be less than or equal
# to the number of the blocks in the file - 2 (that is, there must
# always be at least one file block after a particular GAP block
# number).

# By default, files are NOT fragmented (FRAGMENTED: FALSE is assumed),
# have no gaps, have no out of order blocks, and contain no missing
# blocks.

# There are rules regarding the compatibility of the various file
# options:

# o Block numbers and range endpoints must contain digits only and
# must identify blocks that exist in the current FILE.

# o OUTOFORDER AND FRAGMENTED: TRUE are mutually exclusive options--the
# file may either contain specified out of order blocks or be
# FRAGMENTED, but not both.

# o MISSING and FRAGMENTED: TRUE are mutually exclusive options--the file
# may be either contain missing blocks or be FRAGMENTED, but not both.

# o GAP and FRAGMENTED: TRUE are mutually exclusive options--the file
# may be either contain specified gaps or be FRAGMENTED, but not both.

# o MISSING, OUTOFORDER, and GAP can't be used on contiguous header
# blocks.  e.g., if HEADERBLOCKS is 3, no MISSING, OUTOFORDER, or GAP
# block number can be less than 2.

# Care should be used when combining MISSING, OUTOFORDER, and
# GAP. Simple test cases should be generated to ensure that the
# results are consistent with expectations.

# Long input lines should be be broken by using multiple MISSING, GAP,
# and OUTOFORDER options for a single FILE: definition.  Duplicate
# FRAGMENTED options are not detected (and don't really make sense),
# but the last one will always take precedence for a FILE: definition.

# The MISSING, OUTOFORDER, FRAGMENTED, and GAP options are illustrated
# using examples, below.

# In the following example, a file "file1.dat" is inserted into the
# image file, with blocks 1, 3, 5 and 10-20 (recall blocks are
# numbered starting from 0) omitted from the generated image
# file. Blocks 22 and 23 are placed in a random location in the image
# file and two other blocks substituted in their place. Otherwise, the
# file remains unfragmented.

FILE: file1.dat
MISSING: 1, 3, 5, 10-20
OUTOFORDER: 22, 23

# This example is exactly the same as the one above--it's permissible
# and more readable to use multiple MISSING or OUTOFORDER lines:

FILE: file1.dat
MISSING: 1
MISSING: 3
MISSING: 5
MISSING: 10-20
OUTOFORDER: 22
OUTOFORDER: 23

# In the following example, a file "file1.dat" is fragmented and
# inserted in its entirety into the generated image file.

FILE: file1.dat
FRAGMENTED: TRUE

# In the following example, a file "file1.dat" is not fragmented and
# inserted in its entirety into the generated image file.

FILE: file1.dat
FRAGMENTED: FALSE

# In the following example, a file "file1.dat" is not fragmented and
# inserted in its entirety into the generated image file (FRAGMENTED:
# FALSE is the default).

FILE: file1.dat

# In this example, the file "file1.dat" is fragmented but blocks 3-10
# are completely omitted from the generated image file.

FILE: file1.dat
FRAGMENTED: TRUE
MISSING: 3-10

# The following example will NOT work and will generate an
# error--FRAGMENTED and OUTOFORDER may not both be specified.

FILE: file1.dat
FRAGMENTED: TRUE
OUTOFORDER: 3-10

# The following example uses GAP to introduce gaps between file
# blocks. "file1.dat" has a total of 9 blocks. Block numbers
# specified in the GAP option refer to the original block numbers in
# the unfragmented file:

FILE: file1.dat
GAP: 2-3            # insert non-file blocks in blocks 2 and 3
GAP: 5-7            # insert non-file blocks in 5, 6, and 7

# The resulting fragmented file in the generated image is positioned
# in a random location with the following layout.  "x" denotes a block
# chosen by fragmentator that is not in the file "file1.dat":

# [header] [gap 2-3] [  frag1   ] [ gap 5-7 ] [   frag 2   ]
#   0  1     x  x       2  3  4     x  x  x     5  6  7  8

# In the following example, GAP is used with out of order
# blocks. "file1.dat" has a total of 9 blocks:

FILE: file1.dat
GAP: 2-3            # insert non-file blocks in blocks 2 and 3
GAP: 5-7            # insert non-file blocks in 5, 6, and 7
OUTOFORDER: 7       # block 7 placed randomly elsewhere in the image

# The resulting fragmented file in the generated image is positioned
# in a random location with the following layout.  "x" denotes a block
# chosen by fragmentator that is not in the file "file1.dat":

# [header] [gap 2-3] [  frag1   ] [ gap 5-7 ] [frag 2] [ooo 7] [frag 3]
#   0  1      x  x      2  3  4     x  x  x     5  6      x       8

# In this example, GAP, OUTOFORDER, AND MISSING are also present:

FILE: file1.dat
GAP: 2-3            # insert non-file blocks in blocks 2 and 3
GAP: 5-7            # insert non-file blocks in 5, 6, and 7
OUTOFORDER: 7       # block 7 placed randomly elsewhere in the image
MISSING: 4

# The resulting fragmented file in the generated image is positioned
# in a random location with the following layout.  "x" denotes a block
# chosen by fragmentator that is not in the file "file1.dat".  Block 4
# is completely eliminated and does not appear in the generated image:

# [header] [gap 2-3] [  frag1 ] [missing 4] [ gap 5-7 ] [frag 2] [ooo 7] [frag 3]
#   0  1      x  x      2  3        x         x  x  x     5  6      x       8
