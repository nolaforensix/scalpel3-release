OUTPUTFILE: test.img
SEED: 5
BLOCKSIZE: 16384
HEADERBLOCKS: 2
ZEROPADBLOCKS: 0
RANDOMPADBLOCKS: 0
RANDOMBLOCKS: 0
ZEROBLOCKS: 0
FILLHOLESPRIMARY: ZERO
FILLHOLESSECONDARY: RANDOM

# PNG
FILE: TESTS/cyber-lsu.png
OUTOFORDER: 7

FILE: TESTS/g3pres.png
GAP: 5

FILE: TESTS/ggr-academic-genealogy.png
OUTOFORDER: 3

# JPG

FILE: TESTS/g3-bleh.jpg
GAP: 3
GAP: 7

FILE: TESTS/g4-rocks.jpg
GAP: 4-5

FILE: TESTS/KofButter.jpg
GAP: 5-9

# GIF

FILE: TESTS/cat.gif
GAP: 2

FILE: TESTS/earth.gif
GAP: 3

FILE: TESTS/cosmos.gif

FILE: TESTS/golden-smile.gif

# ABC

FILE: TESTS/file.abc
FRAGMENTED: true

FILE: TESTS/file2.abc
GAP: 3

# 123

FILE: TESTS/file.123
GAP: 2

FILE: TESTS/file2.123
OUTOFORDER: 4

# ELF

FILE: TESTS/ls.elf
GAP: 4
FILE: TESTS/yelp.elf
FILE: TESTS/zip.elf
FILE: TESTS/grep.elf

# EXE

FILE: TESTS/putty-0.84-x86_64.exe
GAP: 12

# AVI

FILE: TESTS/test-video-cc-by-sa.avi
GAP: 5

# ZIP

FILE: TESTS/test.zip
GAP: 5

# SQLite

FILE: TESTS/test.sqlite
GAP: 5
OUTOFORDER: 12-13

# CSV

FILE: TESTS/test.csv

# MP3

FILE: TESTS/music1.mp3
GAP: 10
FILE: TESTS/music2.mp3
FILE: TESTS/music3.mp3
FILE: TESTS/music4.mp3
FILE: TESTS/music5.mp3

# PDF

FILE: TESTS/chemical_comp_titin.pdf
FILE: TESTS/nist.fips.197.pdf
GAP: 10
FILE: TESTS/28233-pdf.pdf
