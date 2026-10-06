## License and Integration Policy

Scalpel3, including its backend, toolchain, and all file validators, is licensed under the GNU
General Public License as published by the Free Software Foundation, version 3 only.

Third-party components remain subject to their respective licenses. See `THIRD_PARTY_NOTICES` for
details.

### GPL Integration Notice

The Scalpel3 copyright holders consider linking or embedding Scalpel3, statically or
dynamically, into another program to create a single combined work governed by GPL v3. Anyone
distributing such a combined work must comply with GPL v3, including providing the complete
corresponding source for the combined work.

For proprietary or commercial use cases that require integration or support, contact Golden G.
Richard III (golden@cct.lsu.edu) to discuss commercial licensing.

# Background and Information

Scalpel3 is a file carving application that runs on Linux and macOS.  The first version of scalpel,
released in 2005, was based on Foremost 0.69. Since then, a number of releases have followed, with
the latest being scalpel3.  scalpel3 is a complete rewrite and has an entirely different internal
architecture, focused on high-performance recovery of both unfragmented and fragmented
files. Important features of scalpel3 include a massively threaded design, asynchronous read and
write operations to hide latency associated with data transfers, and dependence on single-threaded
but thread-safe architecture-agnostic file and block validator functions.  These file and block
validator functions allow support for new file types to be rapidly integrated and tested without
modifying (or even understanding) the complex threading model and other optimizations used by
scalpel3.  Of course we encourage you to actually understand how it all works, if you're curious.

File types are defined in scalpelconf.c.  See this file for more information on the parameters and
functions that are required to support a new file type. The implementation of a very simple file
type called "abc" and implemented in "abc.h" is a good starting point for understanding block and
file validators.  For complex file types that aren't amenable to left to right reassembly, custom
reassembly functions are required.  See "123.h" for a synthetic file type that offers a gentle
introduction to this complex topic.  You'll also want to carefully study the default reassembly
function, LR_reassembly(), and its helper functions (all contained in reassembly.c), as there are
some important issues that must be addressed.

IMPORTANT NOTES:

o Some of the file validators included in the release are still are under active development and may
  contain crusty code or exhibit performance or accuracy anomalies.  Validators can be removed by
  commenting their entries out in scalpelconf.c and recompiling or by using the -U command line
  option.

o Some validators err on the side of not "stealing" blocks when a candidate cannot be positively
  validated.  As a result, a file that was recovered exactly may be written to PROMISING rather than
  VALIDATED.  In general, use the -w option to maximize file recovery, as this always writes PROMISING
  candidates.

# Hardware Recommendations

Scalpel3 supports CPU-only execution using `-Y cpu`. For demanding workloads, we recommend a
powerful Apple Silicon Mac or a Linux system with a multicore CPU and a compatible NVIDIA GPU,
ample RAM, and fast SSD storage. Hardware acceleration speeds up the machine-learning components;
fragmented reassembly also depends heavily on CPU performance. Memory and storage requirements
depend on image size, enabled file types, and recovery output.

# Toolchain

In addition to the scalpel3 carver, the release contains a supporting toolchain.  The following
tools are included:

- `scalpel3-ctl` monitors and controls a running scalpel3 process through its local IPC interface.

- `fragmentator` reproducibly creates synthetic disk images and ground truth layout files for
  testing.  The user has control over fragmentation patterns for individual files, zero and random
  padding, etc.

- `crblockmap` creates a blockmap and identifies duplicate and zero blocks in an image.  Blockmaps
  are required for scalpel3 execution.

- `modblockmap` covers or uncovers blocks, changes the active carve window, and can import coverage
  produced by external tools.

- `cmpblockmaps` reports differences between two compatible blockmaps.

- `mergeblockmap` combines compatible blockmaps produced by distributed or windowed carving.

- `blockmapfs` provides a read-only FUSE filesystem that exposes files that have an adjacent
   ".blockmap" file.  Reading files in the mounted directory hides file blocks that are marked
   covered in the associated blockmap. The source and mount directories must not overlap. Source
   files and blockmaps are immutable for the lifetime of a mount; unmount and remount if the files
   need to be modified.

- `dumphf` displays the serialized header and footer location database written by scalpel3.

- `dumpbt` displays the serialized block type confidence database written by scalpel3.

- `mergecps` combines compatible scalpel3 checkpoints.

- `diskviz` visualizes layouts recorded in the ground truth files produced by `fragmentator`.

# Compilation Instructions

On Linux, the configuration script installs needed dependencies, including FUSE 3 for blockmapfs.

On macOS, the optional blockmapfs utility requires [macFUSE](https://macfuse.github.io/). The first
macFUSE installation or upgrade may require approval in System Settings under Privacy & Security and
a restart; rerun the configuration script after installing and approving it. Scalpel3 and the rest
of the toolchain do not require macFUSE.

To build scalpel3, issue the following command:

$ ./init_scalpel3.sh

On Linux, the script checks the C/C++ ONNX Runtime libraries with a small inference test.
It keeps a working CUDA 12 or 13 installation rather than replacing shared GPU libraries.
If GPU acceleration is unavailable, it clearly reports CPU mode and the steps needed to
enable acceleration; run Scalpel3 and its test scripts with `-Y cpu` in that case.
An explicit `-Y cuda` request never silently falls back to CPU.

Use `./init_scalpel3.sh --cuda=12` or `--cuda=13` to install missing GPU libraries under
`${XDG_DATA_HOME:-$HOME/.local/share}/scalpel3/runtime`. This does not install or change the
NVIDIA driver. `--cuda=cpu` selects CPU inference. `--check-onnx` checks existing libraries
without installing anything, and `--onnx-only` selects libraries without the full build.
`ONNXRUNTIME_INSTALL_PREFIX` can point to an existing C/C++ installation (with `include`
and `lib` directories); `SCALPEL3_CUDA_RUNTIME_DIR` selects a private CUDA library tree,
or `system` to use the system loader. These Linux options do not change macOS installation.

Once this step is performed, changes to source files in the src directory require only that make be
executed to rebuild scalpel3 and all associated utilities, including blockmapfs.  New releases
ALWAYS require running the init script again.

# Testing

To test your installation, navigate to the src directory and then issue this command:

$ TESTS/cmdline.test

This script illustrates simple use of the scalpel3 toolchain, including running fragmentator to
create a synthetic disk image, creating a blockmap, and then running scalpel3.  Output will be in
the scalpel-output directory.  This very simple test should take no more than a minute or two on a
fast machine.

To generate and display the small disk visualization example, run `TESTS/cmdline.diskviz` from the
`src` directory.

To run the DFRWS carving challenges, use `TESTS/cmdline.dfrws2006` or `TESTS/cmdline.dfrws2007`.
The scripts download missing images, run the toolchain, and check the recovered files. See
[`src/TESTS/DFRWS.md`](src/TESTS/DFRWS.md) for options and output details.
A banner announces when every complete file has been recovered exactly; the scripts then
continue searching for partial recoveries unless `--stop-when-complete` is specified.

IMPORTANT: Only one active scalpel3 process may use a given base output directory.  Scalpel3
enforces this with a persistent `.scalpel3.lock` file whose operating-system lock is held for the
process lifetime.  The file may remain after scalpel3 exits; its presence alone does not indicate
that a process is active.  Newly created scalpel3 output directories and files are owner-only
(`0700` and `0600`, respectively); permissions can be changed externally when output must be shared.

# Ongoing Work

We are working hard to improve the entire architecture and available documentation, so please be
patient with us.

If you have trouble with specific validators and want to exclude them, look at the -U option for
scalpel3.

Please send bug reports, comments, complaints, feature requests, and enormous monetary gifts to
support continued development to the primary author, Golden G. Richard III, at golden@cct.lsu.edu.
Enormous monetary gifts will be shared with the development team.
