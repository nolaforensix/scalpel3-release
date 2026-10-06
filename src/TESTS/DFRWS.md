# DFRWS Carving Challenges

From `src`, run:

```sh
TESTS/cmdline.dfrws2006

or

TESTS/cmdline.dfrws2007
```

Each script downloads the official image if needed, verifies its checksum,
creates a fresh blockmap, runs Scalpel3 with `-b -w`, and checks the recovered
files against the challenge references. A banner announces when all complete files
have been recovered correctly and reports their recovery time. Recovery continues
to search for partial files. There is no execution time limit; press Ctrl-C to
request a clean checkpoint and stop, then check the final output.
Python 3.9 or later and a compiled Scalpel3 toolchain are required.

The first run may spend several minutes downloading and verifying inputs before
recovery starts. Download progress, extraction, and checksum checks are reported
separately. Recovery then reports progress every 30 seconds; its duration depends
on the machine and the candidates still being examined.

Images are stored in `TESTS`. Each run creates a new directory under
`TESTS/dfrws-results` containing the logs, recovered files, blockmap, timings,
and per-file scoring reports. Existing results are retained. Downloads and
results are ignored by Git.

Scalpel3 options can be supplied normally, for example `-e 16`. The challenge
sector size is fixed at 512 bytes. `-o DIRECTORY` selects a new results
directory. `--download-only` obtains the inputs without running recovery;
`--score-only DIRECTORY` checks an existing Scalpel3 output directory.
Use `--stop-when-complete` to checkpoint and exit at the completion banner instead.
MoDiCo can be selected explicitly with `-y true` or `-y false`.

Exact files in PROMISING and VALIDATED count equally--this is because some Scalpel3
file validators err on the side of not permanently owning blocks, to prevent stealing
blocks from other validators. The reports distinguish complete files from files with
missing fragments and identify unmatched output. The complete-file totals are 32 for
2006 and 85 for 2007. Reference data is used only for scoring and is not used in
reconstruction logic.  Reports separate recovery of all complete files from total runtime.
Recovery times use the earliest observed write timestamps of correct outputs, excluding
the delay in checking them.

Official images and reference data:

[DFRWS 2006](https://github.com/dfrws/dfrws2006-challenge) and

[DFRWS 2007](https://github.com/dfrws/dfrws2007-challenge).
