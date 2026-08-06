//
// Scalpel3 is Copyright(C) 2021 - 2026 by Golden G. Richard III and contributors.
//
// This program is free software : you can redistribute it and / or modify it under the terms of the
// GNU General Public License as published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
// even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
// General Public License for more details.
//
// You should have received a copy of the GNU General Public License along with this program. If
// not, see <https://www.gnu.org/licenses/>.
//
//------------------------------
// Additional Integration Terms
// -----------------------------
//
// Linking or embedding Scalpel3 (statically or dynamically) into another program such that the
// resulting executable or library forms a single combined work constitutes creation of a derivative
// work under the GPL. Any party distributing such a combined work must make the entire source code
// available under the terms of the GPL as well.
//
// Commercial entities wishing to use Scalpel3 in a closed-source or proprietary product or
// requiring support must obtain a separate commercial license.
//
// For commercial licensing or questions about integration, contact: Golden G. Richard III
// (golden@cct.lsu.edu).
//
// Please see LICENSE.md and README.md for further information.
//
//
// scalpel3 is a complete rewrite of the open source scalpel, which was originally developed by
// Golden G. Richard III in 2005 and then enhanced by both Vico Marziale and Golden G. Richard until
// ~2013. Earlier versions of scalpel had their roots in Foremost 0.69. The emphasis of scalpel3 is
// on *practical* solutions to solving file fragmentation for selected file types and making this
// process as fast as possible on modern hardware.
//
// IMPORTANT: scalpel3 internals differ significantly from earlier versions of scalpel and the
// configuration for scalpel3 is NOT compatible with earlier versions.
//

#include "scalpel.h"
#include "modico_onnx_global.h"
#include "modico_classmap.h"
#include "onnx_providers.h"

#if defined(__APPLE__)
#include <mach-o/dyld.h>
#endif

// function prototypes
static void usage(void);
static int find_search_spec_filetype(const char *filetype);
static void parse_filetype_filter_arg(const char *arg, bool *filter,
                                      const char *option_name,
                                      bool allow_duplicates);
static void parse_block_validation_disposition_arg(const char *arg,
                                                   bool *disposition_seen);
static void apply_filetype_filter(const bool *include_filter,
                                  const bool *exclude_filter,
                                  bool include_seen,
                                  bool exclude_seen);
static void copy_command_line_path(char *destination, size_t destination_size,
                                   const char *source, const char *description);
static void process_command_line_args(int argc, char *argv[]);
static void initialize_state(int argc, char *argv[]);
static char *resolve_running_executable(const char *argv0);
static void hash_running_executable(const char *argv0);

static bool parse_bounded_uint64(const char *value, uint64_t minimum,
                                 uint64_t maximum, uint64_t *parsed);
static bool parse_true_false_option(const char *option_name, const char *value);
static int modico_onnx_intra_threads(const char *accelerator);
static void initialize_AI(const char *scalpel3_home);

// Canonical -Y provider request; CoreML MoDiCo aliases are retained separately.
static char onnx_provider_cli[64];

typedef enum {
  MODICO_COREML_MODEL_DEFAULT = 0,
  MODICO_COREML_MODEL_GRAPHCUT,
  MODICO_COREML_MODEL_LEGACY
} modico_coreml_model_t;

static modico_coreml_model_t modico_coreml_model =
    MODICO_COREML_MODEL_DEFAULT;


static void copy_command_line_path(char *destination, size_t destination_size,
                                   const char *source, const char *description) {

  if (copy_string_complete(destination, destination_size, source)) {
    return;
  }

  lock_fprintf(stderr, "%s", RED);
  lock_fprintf(stderr,
               "\nERROR: The %s pathname is too long (maximum %zu characters). Aborting.\n",
               description, destination_size - 1);
  lock_fprintf(stderr, "%s", BLACK);
  exit(-1);
}


// print scalpel usage info
static void usage(void) {
  lock_fprintf(stderr, "%s", BLUE);
  lock_fprintf(stderr, SCALPEL_BANNER_STRING ".\n");
  lock_fprintf(stderr, SCALPEL_COPYRIGHT_STRING "\n");

  lock_fprintf(stderr,
               "Scalpel carves files or data fragments from a disk image based on a set of\n"
               "file carving patterns, which include headers, footers, and other information.\n\n"

               "Usage: scalpel3 [-a] [-A secs] [-b] [-B] [-c] [-C] [-d]\n"
               "                [-D disposition:filetype[,filetype]...] [-e #] [-F secs] [-g #] [-G #] [-h]\n"
               "                [-H block-validation|header-footer] [-i #] [-I secs] [-j #] [-k #] [-L] [-m]\n"
               "                [-M] [-n] [-o scalpel_output_dir] [-O] [-p] [-P] [-q clustersize] [-R]\n"
               "                [-r #] [-s #] [-S] [-t #] [-u #] [-U filetype[,filetype]...] [-v] [-V] [-w] [-x]\n"
               "                [-y true|false] [-Y provider[:devicelist]] [-z filetype[,filetype]...]\n"
               "                img_filename blockmap_filename\n\n"

               "Options:\n"

               "-a  Turn off aggressive memory allocation, to reduce overhead.  Default is on. Leave this on unless\n"
               "    you experience out of memory errors or excessive swapping.\n"

               "-A  Create a checkpoint and stop execution after a specified number of seconds in the fragmented reassembly\n"
               "    phase of execution. This option is not checkpointed and must be specified on every execution where this\n"
               "    behavior is desired.\n"

               "-B  Don't backtrack.  Default is backtracking on.  Useful only for debugging.\n"

               "-b  Write blockvectors.  Default is to not write blockvectors.\n"

               "-c  Don't attempt fragmented recovery for any supported file type. This essentially sets NO_DEFRAG to true\n"
               "    for all file types. Block validators declared reassembly-only are skipped; MoDiCo remains controlled by\n"
               "    the -y option.\n"

               "-C  Turn off IPC.  Generally not recommended, but useful in environments that don't support Unix domain\n"
               "    sockets. Default is on.\n"

               "-d  Turn off header reuse for contiguous files. Default is on and you should generally leave this on.\n"

               "-D  Override when block validation runs for one or more file types. always runs in all modes,\n"
               "    reassembly is skipped under -c, and disabled never runs, e.g., -D disabled:ELF or\n"
               "    -D reassembly:PNG,GIF. This option may be repeated. Its settings are checkpointed and cannot\n"
               "    be changed during restore.\n"

               "-e  Override detected number of physical CPU cores. scalpel3 detects the number of physical CPU cores for\n"
               "    determining thread pool sizes. On systems with hyperthreading, it may be beneficial to increase the number\n"
               "    of perceived CPU cores using -e. On Apple Silicon systems, the number of performance cores is used to size\n"
               "    thread pools and -e can be used to experimentally increase the sizes of all thread pools.\n"

               "-F  Create a checkpoint and stop execution when a new file hasn't been validated for a specified\n"
               "    number of seconds in the fragmented reassembly phase of execution. This option is not checkpointed\n"
               "    and must be specified on every execution where this behavior is desired.\n"

               "-g  Set reassembly gallop factor.\n"

               "-G  Set reassembly gallop limit.\n"

               "-h  Display this help message and then exit.\n"

               "-H  Stop after the required phase: block-validation writes blockclassification.dat; header-footer also writes\n"
               "    headersfooters.dat before exiting.\n"

               "-i  Set minimum number of validated files to trigger periodic checkpoint and blockmap swap. This overrides\n"
               "    VALIDATION_CP_THRESHOLD in scalpel.h.\n"

               "-I  Set periodic checkpointing interval (in seconds).  This overrides CHECKPOINTING_INTERVAL in scalpel.h.\n"

               "-j  Treat blocks in the image before the specified block number as covered.  This option in conjunction\n"
               "    with -k allows execution of scalpel3 against a window of blocks in the input file.\n"

               "-k  Treat blocks in the image after the specified block number as covered.  This option in conjunction\n"
               "    with -j allows execution of scalpel3 against a window of blocks in the input file.\n"

               "-L  Provide a brief list of supported file types and exit.\n"

               "-m  Perform memory profiling.  Produces lots of output.\n"

               "-M  Disable shadow blockmap peeking for block selection.  The default is on. Only useful for debugging.\n"

               "-n  Disable backtrace on crash.  The default is to generate backtraces and this should generally be left on.\n"

               "-o  Set output directory for carved files. Only one active scalpel3 process may use an output directory.\n"

               "-O  Don't organize carved files into subdirectories. Default is organize.\n"

               "-p  Turn on file type prioritization for fragmented file reassembly.  Default is off.\n"

	       "-P  Write INPROGRESS files on every checkpoint.  The default is only to write INPROGRESS when this is\n"
	       "    requested via IPC (e.g., scalpel3-ctl -c).  This is primarily for debugging, as it adds substantial\n"
	       "    overhead.\n"

               "-q  Specify block/cluster size. Default is 512 bytes.\n"

               "-R  Resume from checkpoint.\n"

               "-r  Specify the maximum number of threads per filemirror pool.\n"

               "-s  Specify the maximum number of reassembly threads.\n"

               "-S  Turn off reassembly thread work sharing. Default is on.\n"

               "-t  Specify the maximum number of search threads.\n"

               "-u  Specify the maximum number of validation threads.\n"

               "-U  Deactivate carving for one or more file types, e.g., -U JPG or -U JPG,PNG. Not compatible with -z.\n"

               "-v  Verbose mode.\n"

               "-V  Print copyright information and exit.\n"

               "-w  Write promising candidates that didn't validate completely. The default is to only write fully\n"
               "    validated files, to save disk space, but you probably want this on if partial results are useful\n"
               "    (e.g., initial fragments of photographic images).\n"

	       "-x  Override checkpoint integrity checks. Use this only if you know what you're doing!\n"

               "-y  Explicitly enable or disable MoDiCo block prioritization. MoDiCo is enabled by default; use\n"
               "    -y false to disable it. This option is checkpointed and cannot be changed during checkpoint\n"
               "    restore.\n"

               "-Y  Select the ONNX execution provider (and GPUs) used by all AI components for this run: cpu,\n"
               "    cuda, coreml, or auto, with an optional CUDA device list, e.g. -Y cuda:0,2. On Apple Silicon,\n"
               "    coreml uses an installed graph-cut MoDiCo model by default; coreml-graphcut selects it explicitly and\n"
               "    coreml-legacy selects the original model. The default (auto) uses all healthy NVIDIA GPUs, CoreML\n"
               "    on Apple Silicon, or CPU when no accelerator is present. An unavailable requested or detected\n"
               "    accelerator is an error; use -Y cpu to intentionally select CPU inference.\n"

               "-z  Carve only one or more specified file types, e.g., -z JPG or -z JPG,PNG. Not compatible with -U.\n");

  lock_fprintf(stderr, "%s", BLACK);
}

static int find_search_spec_filetype(const char *filetype) {
  for (uint32_t j = 0; j < scalpel_state.num_specs; j++) {
    if (! strcasecmp(scalpel_state.search_specs[j].FILETYPE, filetype)) {
      return (int)j;
    }
  }
  return -1;
}

static void parse_filetype_filter_arg(const char *arg, bool *filter,
                                      const char *option_name,
                                      bool allow_duplicates) {
  const char *pos = arg;
  char filetype[MAX_STRING_LENGTH];

  if (! arg || ! *arg) {
    lock_fprintf(stderr, "\nERROR: Empty file type list for %s option.\n", option_name);
    lock_fprintf(stderr, "%s", BLACK);
    exit(-1);
  }

  while (*pos) {
    const char *start = pos;
    const char *delimiter = strchr(pos, ',');
    const char *end = delimiter;
    size_t len;
    int foundat;

    if (! end) {
      end = pos + strlen(pos);
    }
    while (start < end && isspace((unsigned char)*start)) {
      start++;
    }
    while (end > start && isspace((unsigned char)*(end - 1))) {
      end--;
    }
    if (start == end) {
      lock_fprintf(stderr, "\nERROR: Empty file type in %s list.\n", option_name);
      lock_fprintf(stderr, "%s", BLACK);
      exit(-1);
    }

    len = (size_t)(end - start);
    if (len >= sizeof(filetype)) {
      lock_fprintf(stderr, "\nERROR: File type in %s list is too long.\n", option_name);
      lock_fprintf(stderr, "%s", BLACK);
      exit(-1);
    }
    memcpy(filetype, start, len);
    filetype[len] = 0;

    foundat = find_search_spec_filetype(filetype);
    if (foundat < 0) {
      lock_fprintf(stderr, "\nERROR: For %s, file type \"%s\" not found in \"scalpelconf.c\".\n",
                   option_name, filetype);
      lock_fprintf(stderr, "%s", BLACK);
      exit(-1);
    }
    if (filter[foundat] && ! allow_duplicates) {
      lock_fprintf(stderr, "\nERROR: Duplicate file type \"%s\" in %s list.\n",
                   filetype, option_name);
      lock_fprintf(stderr, "%s", BLACK);
      exit(-1);
    }
    filter[foundat] = true;

    if (delimiter && delimiter[1] == 0) {
      lock_fprintf(stderr, "\nERROR: Empty file type in %s list.\n", option_name);
      lock_fprintf(stderr, "%s", BLACK);
      exit(-1);
    }
    pos = delimiter ? delimiter + 1 : end;
  }
}


static void parse_block_validation_disposition_arg(const char *arg,
                                                   bool *disposition_seen) {
  const char *colon;
  const char *start;
  const char *end;
  char disposition_name[32];
  BlockValidationScope disposition;
  bool *selected;
  size_t len;

  if (! arg || ! *arg || ! (colon = strchr(arg, ':'))) {
    lock_fprintf(
        stderr,
        "\nERROR: -D requires disposition:filetype[,filetype]..., where disposition is "
        "always, reassembly, or disabled.\n");
    lock_fprintf(stderr, "%s", BLACK);
    exit(-1);
  }

  start = arg;
  end = colon;
  while (start < end && isspace((unsigned char)*start)) {
    start++;
  }
  while (end > start && isspace((unsigned char)*(end - 1))) {
    end--;
  }
  len = (size_t)(end - start);
  if (len == 0 || len >= sizeof(disposition_name)) {
    lock_fprintf(stderr, "\nERROR: Invalid block validation disposition for -D.\n");
    lock_fprintf(stderr, "%s", BLACK);
    exit(-1);
  }
  memcpy(disposition_name, start, len);
  disposition_name[len] = 0;

  if (! strcasecmp(disposition_name, "always")) {
    disposition = BLOCK_VALIDATION_ALWAYS;
  }
  else if (! strcasecmp(disposition_name, "reassembly")) {
    disposition = BLOCK_VALIDATION_REASSEMBLY_ONLY;
  }
  else if (! strcasecmp(disposition_name, "disabled")) {
    disposition = BLOCK_VALIDATION_DISABLED;
  }
  else {
    lock_fprintf(
        stderr,
        "\nERROR: Invalid block validation disposition \"%s\" for -D; expected "
        "always, reassembly, or disabled.\n",
        disposition_name);
    lock_fprintf(stderr, "%s", BLACK);
    exit(-1);
  }

  selected = calloc(scalpel_state.num_specs, sizeof(bool));
  check_memory_allocation(selected, __LINE__, __FILE__,
                          "block validation disposition file types");
  parse_filetype_filter_arg(colon + 1, selected, "-D", true);

  for (uint32_t i = 0; i < scalpel_state.num_specs; i++) {
    if (! selected[i]) {
      continue;
    }
    if (disposition_seen[i]
        && scalpel_state.search_specs[i].BLOCKVALIDATIONSCOPE
               != disposition) {
      lock_fprintf(
          stderr,
          "\nERROR: Conflicting -D dispositions for file type \"%s\".\n",
          scalpel_state.search_specs[i].FILETYPE);
      lock_fprintf(stderr, "%s", BLACK);
      free(selected);
      exit(-1);
    }
    scalpel_state.search_specs[i].BLOCKVALIDATIONSCOPE = disposition;
    disposition_seen[i] = true;
  }

  free(selected);
}


static void apply_filetype_filter(const bool *include_filter,
                                  const bool *exclude_filter,
                                  bool include_seen,
                                  bool exclude_seen) {
  uint32_t write_index = 0;

  if (! include_seen && ! exclude_seen) {
    return;
  }

  for (uint32_t read_index = 0; read_index < scalpel_state.num_specs; read_index++) {
    bool keep = include_seen ? include_filter[read_index]
                             : ! exclude_filter[read_index];
    if (keep) {
      if (write_index != read_index) {
        scalpel_state.search_specs[write_index] =
            scalpel_state.search_specs[read_index];
      }
      write_index++;
    }
  }

  if (write_index == 0) {
    lock_fprintf(stderr, "\nERROR: File type filter eliminated all file types.\n");
    lock_fprintf(stderr, "%s", BLACK);
    exit(-1);
  }

  scalpel_state.num_specs = write_index;
  scalpel_state.search_specs =
      realloc(scalpel_state.search_specs,
              sizeof(SearchSpec) * (scalpel_state.num_specs + 1));
  check_memory_allocation(scalpel_state.search_specs, __LINE__, __FILE__,
                          "scalpel_state.search_specs");
  scalpel_state.search_specs[scalpel_state.num_specs].FILETYPE[0] = 0;
}

// parse command line arguments
static void process_command_line_args(int argc, char *argv[]) {
  int i;
  unsigned int j;
  bool cp_restricted = false;  // option incompatible with checkpoint restore chosen?
  bool include_seen = false;
  bool exclude_seen = false;
  bool *include_filter;
  bool *exclude_filter;
  bool *disposition_seen;
  uint64_t parsed;

  include_filter = calloc(scalpel_state.num_specs, sizeof(bool));
  check_memory_allocation(include_filter, __LINE__, __FILE__, "include_filter");
  exclude_filter = calloc(scalpel_state.num_specs, sizeof(bool));
  check_memory_allocation(exclude_filter, __LINE__, __FILE__, "exclude_filter");
  disposition_seen = calloc(scalpel_state.num_specs, sizeof(bool));
  check_memory_allocation(disposition_seen, __LINE__, __FILE__,
                          "block validation disposition tracking");

  lock_fprintf(stderr, "%s", RED);

  while ((i = getopt(argc, argv, "+aA:BbcCdD:e:F:g:G:hH:i:I:j:k:LmMnNo:OpPq:r:Rs:St:u:U:vVwxy:Y:z:")) != -1) {
    switch (i) {
    case 'a':
      scalpel_state.reduce_aggressive_allocation = true;
      cp_restricted = true;
      break;

    case 'A':
      if (! parse_bounded_uint64(optarg, 10, INT_MAX, &parsed)) {
        lock_fprintf(stderr, "\nERROR: Invalid number of seconds for exit -A option.\n");
        lock_fprintf(stderr, "%s", BLACK);
        exit(-1);
      }
      scalpel_state.exit_after_secs = (uint32_t)parsed;
      break;

    case 'b':
      scalpel_state.write_blockvectors = true;
      cp_restricted = true;
      break;

    case 'B':
      scalpel_state.backtrack = false;
      cp_restricted = true;
      break;

    case 'c':
      scalpel_state.no_defrag = true;
      cp_restricted = true;
      break;

    case 'C':
      no_IPC = true;
      break;

    case 'd':
      scalpel_state.contig_header_reuse = false;
      cp_restricted = true;
      break;

    case 'D':
      parse_block_validation_disposition_arg(optarg, disposition_seen);
      cp_restricted = true;
      break;

    case 'e':
      if (! parse_bounded_uint64(optarg, 1, 65536, &parsed)) {
        lock_fprintf(stderr, "\nERROR: Invalid # of CPU cores for -e command line option.\n");
        lock_fprintf(stderr, "%s", BLACK);
        exit(-1);
      }
      NC = (int)parsed;
      break;

    case 'F':
      if (! parse_bounded_uint64(optarg, 10, INT_MAX, &parsed)) {
        lock_fprintf(stderr, "\nERROR: Invalid number of seconds for validation gap for -F option.\n");
        lock_fprintf(stderr, "%s", BLACK);
        exit(-1);
      }
      scalpel_state.exit_after_val_gap = (uint32_t)parsed;
      break;

    case 'g':
      if (! parse_bounded_uint64(optarg, 0, UINT64_MAX, &parsed)
          || (parsed && (parsed & (parsed - 1)))) {
        lock_fprintf(stderr, "\nERROR: Gallop factor for -g command line option must be a power of 2.\n");
        lock_fprintf(stderr, "%s", BLACK);
        exit(-1);
      }
      scalpel_state.gallop_factor = parsed;

      cp_restricted = true;
      break;

    case 'G':
      if (! parse_bounded_uint64(optarg, 0, UINT64_MAX, &parsed)
          || (parsed && (parsed & (parsed - 1)))) {
        lock_fprintf(stderr, "\nERROR: Gallop limit for -G command line option must be a power of 2.\n");
        lock_fprintf(stderr, "%s", BLACK);
        exit(-1);
      }
      scalpel_state.gallop_limit = parsed;

      cp_restricted = true;
      break;

    case 'h':
      usage();
      exit(EXIT_SUCCESS);

    case 'H':
      if (! strcasecmp(optarg, "block-validation")) {
        scalpel_state.halt_after = HALT_AFTER_BLOCK_VALIDATION;
      }
      else if (! strcasecmp(optarg, "header-footer")) {
        scalpel_state.halt_after = HALT_AFTER_HEADER_FOOTER;
      }
      else {
        lock_fprintf(stderr,
                     "\nERROR: -H requires block-validation or header-footer.\n");
        lock_fprintf(stderr, "%s", BLACK);
        exit(-1);
      }
      cp_restricted = true;
      break;

    case 'i':
      if (! parse_bounded_uint64(optarg, 1, 65536, &parsed)) {
        lock_fprintf(stderr, "\nERROR: Invalid validation checkpointing threshold for -i command line option.\n"
                             "Must be 1 <= i <= 65536.\n");
        lock_fprintf(stderr, "%s", BLACK);
        exit(-1);
      }
      scalpel_state.validation_cp_threshold = (uint32_t)parsed;
      break;

    case 'I':
      if (! parse_bounded_uint64(optarg, 5, 65536, &parsed)) {
        lock_fprintf(stderr, "\nERROR: Invalid checkpointing interval for -I command line option.\n"
                             "Must be 5 <= I <= 65536.\n");
        lock_fprintf(stderr, "%s", BLACK);
        exit(-1);
      }
      scalpel_state.checkpointing_interval = (uint32_t)parsed;
      if (scalpel_state.checkpointing_interval > RECOVERY_CHECKPOINTING_INTERVAL) {
        lock_fprintf(stderr,
                     "\nWARNING: Checkpointing interval exceeds RECOVERY_CHECKPOINTING_INTERVAL (= %d seconds)\n"
                     "and will be ignored.\n",
                     RECOVERY_CHECKPOINTING_INTERVAL);
        lock_fprintf(stderr, "%s", BLACK);
      }
      break;

    case 'j':
      if (! parse_bounded_uint64(optarg, 0, INT64_MAX, &parsed)) {
        fprintf(stderr, "\nERROR: Start block for -j option must be >= 0.\n");
        fprintf(stderr, "%s", BLACK);
        exit(-1);
      }
      scalpel_state.start_block = parsed;

      cp_restricted = true;
      break;

    case 'k':
      if (! parse_bounded_uint64(optarg, 0, INT64_MAX, &parsed)) {
        fprintf(stderr, "\nERROR: End block for -k option must be >= 0.\n");
        fprintf(stderr, "%s", BLACK);
        exit(-1);
      }
      scalpel_state.end_block = parsed;

      cp_restricted = true;
      break;

    case 'L':
      for (j = 0; j < scalpel_state.num_specs; j++) {
        lock_fprintf(stderr, "%s %s\n", scalpel_state.search_specs[j].FILETYPE,
                     scalpel_state.search_specs[j].MASTER ? "(master)" : "");
      }
      exit(EXIT_SUCCESS);

    case 'm':
      scalpel_state.memory_profiling = true;
      cp_restricted = true;
      break;

    case 'M':
      scalpel_state.disable_shadow_peeking = true;
      cp_restricted = true;
      break;

    case 'n':
      scalpel_state.disable_backtrace = true;
      cp_restricted = true;
      break;

    case 'N':
      scalpel_state.neon++;
      break;

    case 'o':
      // reserve room for the timestamp, status, file type, and filename components appended later
      copy_command_line_path(scalpel_state.output_directory,
                             sizeof(scalpel_state.output_directory) / 2,
                             optarg, "output directory");
      break;

    case 'O':
      scalpel_state.organize_subdirectories = false;
      cp_restricted = true;
      break;

    case 'p':
      scalpel_state.prioritize_types = true;
      cp_restricted = true;
      break;

    case 'P':
      scalpel_state.write_inprogress = true;
      break;

    case 'q':
      if (! parse_bounded_uint64(optarg, 512, UINT64_C(1024) * 1024 * 1024,
                                 &parsed)
          || parsed % 512) {
        lock_fprintf(stderr, "\nERROR: Invalid blocksize \"%s\" for -q command line option. Blocksize must be\n"
                             "at least 512 bytes and divisible by 512.\n", optarg);
        lock_fprintf(stderr, "%s", BLACK);
        exit(-1);
      }
      scalpel_state.blocksize = (uint32_t)parsed;
      cp_restricted = true;
      break;

    case 'r':
      if (! parse_bounded_uint64(optarg, 1, 65536, &parsed)) {
        lock_fprintf(stderr, "\nERROR: Invalid # of filemirror threads for -r command line option.\n");
        lock_fprintf(stderr, "%s", BLACK);
        exit(-1);
      }
      scalpel_state.max_filemirror_threads = (int32_t)parsed;
      max_filemirror_threads_override = scalpel_state.max_filemirror_threads;
      break;

    case 'R':
      scalpel_state.restore_from_checkpoint = true;
      break;

    case 's':
      if (! parse_bounded_uint64(optarg, 1, 65536, &parsed)) {
        lock_fprintf(stderr, "\nERROR: Invalid # of reassembly threads for -s command line option.\n");
        lock_fprintf(stderr, "%s", BLACK);
        exit(-1);
      }
      scalpel_state.max_reassembly_threads = (int32_t)parsed;
      max_reassembly_threads_override = scalpel_state.max_reassembly_threads;
      break;

    case 'S':
      scalpel_state.share_reassembly = false;
      cp_restricted = true;
      break;

    case 't':
      if (! parse_bounded_uint64(optarg, 1, 65536, &parsed)) {
        lock_fprintf(stderr, "\nERROR: Invalid # of search threads for -t command line option.\n");
        lock_fprintf(stderr, "%s", BLACK);
        exit(-1);
      }
      scalpel_state.max_search_threads = (int32_t)parsed;
      max_search_threads_override = scalpel_state.max_search_threads;
      break;

    case 'u':
      if (! parse_bounded_uint64(optarg, 1, 65536, &parsed)) {
        lock_fprintf(stderr, "\nERROR: Invalid # of validation threads for -u command line option.\n");
        lock_fprintf(stderr, "%s", BLACK);
        exit(-1);
      }
      scalpel_state.max_validation_threads = (int32_t)parsed;
      max_validation_threads_override = scalpel_state.max_validation_threads;
      break;

    case 'U':
      if (include_seen) {
        lock_fprintf(stderr, "\nERROR: -U is not compatible with -z.\n");
        lock_fprintf(stderr, "%s", BLACK);
        exit(-1);
      }
      exclude_seen = true;
      parse_filetype_filter_arg(optarg, exclude_filter, "-U", false);
      cp_restricted = true;
      break;

    case 'v':
      scalpel_state.mode_verbose = true;
      break;

    case 'V':
      lock_fprintf(stderr, "%s", BLUE);
      lock_fprintf(stderr, SCALPEL_BANNER_STRING ".\n");
      lock_fprintf(stderr, SCALPEL_COPYRIGHT_STRING "\n");
      lock_fprintf(stderr, "%s", BLACK);
      exit(EXIT_SUCCESS);

    case 'w':
      scalpel_state.write_promising = true;
      cp_restricted = true;
      break;

    case 'x':
      scalpel_state.no_cp_validation = true;
      break;

    case 'y':
      scalpel_state.modico_requested =
          parse_true_false_option("-y", optarg) ? 1 : 0;
      cp_restricted = true;
      break;

    case 'Y':
      // full validation (provider names, device list, machine capability) happens in
      // onnx_providers_resolve(), called from initialize_AI()
      if (! optarg || ! *optarg
          || strlen(optarg) >= sizeof(onnx_provider_cli)) {
        lock_fprintf(stderr,
                     "\nERROR: -Y requires provider[:devicelist], e.g. -Y coreml or -Y cuda:0,1.\n");
        lock_fprintf(stderr, "%s", BLACK);
        exit(-1);
      }
      const char *provider_arg = optarg;
      modico_coreml_model = MODICO_COREML_MODEL_DEFAULT;
      if (! strcasecmp(optarg, "coreml-graphcut")) {
        provider_arg = "coreml";
        modico_coreml_model = MODICO_COREML_MODEL_GRAPHCUT;
      }
      else if (! strcasecmp(optarg, "coreml-legacy")) {
        provider_arg = "coreml";
        modico_coreml_model = MODICO_COREML_MODEL_LEGACY;
      }
      strncpy(onnx_provider_cli, provider_arg,
              sizeof(onnx_provider_cli) - 1);
      onnx_provider_cli[sizeof(onnx_provider_cli) - 1] = '\0';
      break;

    case 'z':
      if (exclude_seen) {
        lock_fprintf(stderr, "\nERROR: -z is not compatible with -U.\n");
        lock_fprintf(stderr, "%s", BLACK);
        exit(-1);
      }
      include_seen = true;
      parse_filetype_filter_arg(optarg, include_filter, "-z", false);
      cp_restricted = true;
      break;

    default:
      lock_fprintf(stderr, "%s", BLACK);
      exit(-1);
    }
  }

  // if a checkpoint restore is requested, don't allow incompatible options
  if (cp_restricted && scalpel_state.restore_from_checkpoint) {
    lock_fprintf(stderr,
                 "\nERROR: Only -A, -F, -i, -I, -o, -v, and thread pool-related options are allowed during checkpoint restore.\n");
    lock_fprintf(stderr, "%s", BLACK);
    exit(-1);
  }

  if (scalpel_state.halt_after != HALT_AFTER_NONE
      && scalpel_state.no_defrag) {
    lock_fprintf(stderr, "\nERROR: -H and -c cannot be used together.\n");
    lock_fprintf(stderr, "%s", BLACK);
    exit(-1);
  }

  apply_filetype_filter(include_filter, exclude_filter, include_seen, exclude_seen);
  free(include_filter);
  free(exclude_filter);
  free(disposition_seen);

  lock_fprintf(stderr, "%s", BLACK);
}



static bool parse_bounded_uint64(const char *value, uint64_t minimum,
                                 uint64_t maximum, uint64_t *parsed) {
  char *end = NULL;
  unsigned long long converted;

  if (! value || value[0] < '0' || value[0] > '9') {
    return false;
  }

  errno = 0;
  converted = strtoull(value, &end, 10);
  if (errno == ERANGE || ! end || *end != '\0'
      || converted < minimum || converted > maximum) {
    return false;
  }

  *parsed = (uint64_t)converted;
  return true;
}


static bool parse_true_false_option(const char *option_name, const char *value) {
  if (! value || ! *value) {
    lock_fprintf(stderr, "\nERROR: %s requires true or false.\n",
                 option_name);
    lock_fprintf(stderr, "%s", BLACK);
    exit(-1);
  }

  if (! strcasecmp(value, "true")) {
    return true;
  }

  if (! strcasecmp(value, "false")) {
    return false;
  }

  lock_fprintf(stderr, "\nERROR: %s requires true or false.\n", option_name);
  lock_fprintf(stderr, "%s", BLACK);
  exit(-1);
}

static int modico_onnx_intra_threads(const char *accelerator) {
  const char *e = getenv("SCALPEL3_MODICO_INTRA_THREADS");
  if (e && *e) {
    char *end = NULL;
    long v = strtol(e, &end, 10);
    if (end != e && v >= 0 && v <= 0x7fffffffL) {
      return (int)v;
    }
  }

  if (accelerator && ! strcasecmp(accelerator, "cpu")) {
    int logical = num_logical_cores();
    if (logical <= 0) {
      return 0;
    }
    return logical > 12 ? 12 : logical;
  }

  return 0;
}


// resolve the canonical path of the executable currently running. Native process metadata is
// authoritative on supported platforms; argv[0] and PATH provide a portable fallback.
static char *resolve_running_executable(const char *argv0) {

  char *resolved;

#if defined(__APPLE__)
  char executable_path[PATH_MAX];
  uint32_t executable_path_size = sizeof(executable_path);

  if (_NSGetExecutablePath(executable_path, &executable_path_size) == 0) {
    resolved = realpath(executable_path, NULL);
    if (resolved) {
      return resolved;
    }
  }
  else {
    char *dynamic_path = malloc(executable_path_size);
    check_memory_allocation(dynamic_path, __LINE__, __FILE__, "dynamic_path");
    if (_NSGetExecutablePath(dynamic_path, &executable_path_size) == 0) {
      resolved = realpath(dynamic_path, NULL);
      free(dynamic_path);
      if (resolved) {
        return resolved;
      }
    }
    else {
      free(dynamic_path);
    }
  }
#elif defined(__linux__)
  char executable_path[PATH_MAX + 1];
  ssize_t executable_path_length = readlink("/proc/self/exe", executable_path,
                                            sizeof(executable_path) - 1);

  if (executable_path_length > 0
      && (size_t)executable_path_length < sizeof(executable_path) - 1) {
    executable_path[executable_path_length] = 0;
    resolved = realpath(executable_path, NULL);
    if (resolved) {
      return resolved;
    }
  }
#endif

  if (! argv0 || ! argv0[0]) {
    return NULL;
  }

  if (strchr(argv0, '/')) {
    return realpath(argv0, NULL);
  }

  const char *path_environment = getenv("PATH");
  if (! path_environment) {
    return NULL;
  }

  char *path_copy = strdup(path_environment);
  check_memory_allocation(path_copy, __LINE__, __FILE__, "path_copy");
  char *next = path_copy;
  char *component;
  char candidate[PATH_MAX];

  while ((component = strsep(&next, ":")) != NULL) {
    const char *directory = component[0] ? component : ".";
    int written = snprintf(candidate, sizeof(candidate), "%s/%s", directory, argv0);
    if (written < 0 || (size_t)written >= sizeof(candidate)
        || access(candidate, X_OK) != 0) {
      continue;
    }

    struct stat candidate_stat;
    if (stat(candidate, &candidate_stat) != 0 || ! S_ISREG(candidate_stat.st_mode)) {
      continue;
    }

    resolved = realpath(candidate, NULL);
    if (resolved) {
      free(path_copy);
      return resolved;
    }
  }

  free(path_copy);
  return NULL;
}


// hash the executable bytes that created this process for checkpoint compatibility checks
static void hash_running_executable(const char *argv0) {

  struct stat executable_stat;
  char *executable_path = resolve_running_executable(argv0);

  if (! executable_path || stat(executable_path, &executable_stat) != 0
      || executable_stat.st_size <= 0
      || (uintmax_t)executable_stat.st_size > SIZE_MAX) {
    free(executable_path);
    handle_error(SCALPEL_ERROR_CHECKPOINT_IMAGE,
                 "Couldn't locate scalpel3 executable to calculate SHA256 hash.\n",
                 __LINE__, __FILE__);
  }

  size_t executable_size = (size_t)executable_stat.st_size;
  unsigned char *executable = malloc(executable_size);
  check_memory_allocation(executable, __LINE__, __FILE__, "executable");
  FILE *executable_file = fopen(executable_path, "rb");

  if (! executable_file
      || fread(executable, 1, executable_size, executable_file) != executable_size) {
    handle_error(SCALPEL_ERROR_CHECKPOINT_IMAGE,
                 "Couldn't read scalpel3 executable to calculate SHA256 hash.\n",
                 __LINE__, __FILE__);
  }

  SHA256(executable, executable_size, scalpel_state.sha256);
  fclose(executable_file);
  free(executable);
  free(executable_path);
}


// initialize scalpel state variable and set configuration
void initialize_state(int argc, char *argv[]) {
  char **argvcopy = argv;
  const char *argv0 = argv[0];
  unsigned int i;

  scalpel_state.candidates = 0;
  scalpel_state.chopped = 0;
  atomic_init(&scalpel_state.validated_files, 0);
  atomic_init(&scalpel_state.files_written, 0);
  if (! FORCE_VERBOSE_MODE) {
    scalpel_state.mode_verbose = false;
  }
  scalpel_state.organize_subdirectories = true;
  scalpel_state.blocksize = SCALPEL_BLOCK_SIZE;
  scalpel_state.write_promising = false;
  scalpel_state.write_blockvectors = false;
  scalpel_state.reduce_aggressive_allocation = false;
  scalpel_state.share_reassembly = true;
  scalpel_state.contig_header_reuse = true;
  scalpel_state.no_defrag = false;
  scalpel_state.halt_after = HALT_AFTER_NONE;
  scalpel_state.backtrack = true;
  scalpel_state.start_block = 0;
  scalpel_state.end_block = UINT64_MAX;
  scalpel_state.reservations = true;
  scalpel_state.memory_profiling = false;
  scalpel_state.disable_shadow_peeking = false;
  scalpel_state.disable_backtrace = false;
  scalpel_state.prioritize_types = false;
  scalpel_state.write_inprogress = false;
  scalpel_state.gallop_factor = SCALPEL_GALLOP_FACTOR;
  scalpel_state.gallop_limit = SCALPEL_GALLOP_LIMIT;
  scalpel_state.current_priority = PRIORITY_FLOOR;
  scalpel_state.num_specs = 0;
  scalpel_state.largest_maxfilesize = 0;
  scalpel_state.restore_from_checkpoint = false;
  scalpel_state.checkpointing_interval = PERIODIC_CHECKPOINTING_INTERVAL;
  scalpel_state.validation_cp_threshold = VALIDATION_CP_THRESHOLD;
  scalpel_state.exit_after_secs = EXIT_AFTER_SECONDS;
  scalpel_state.exit_after_val_gap = EXIT_AFTER_VAL_GAP;
  scalpel_state.block_validation_complete = false;
  scalpel_state.contiguous_recovery_complete = false;
  scalpel_state.F1_initiated = false;
  scalpel_state.F2_initiated = false;
  scalpel_state.neon = 0;
  scalpel_state.no_cp_validation = false;
  scalpel_state.modico_requested = -1;
  scalpel_state.audit_file = NULL;

  // default values for output directory coverage blockmap directory
  strncpy(scalpel_state.output_directory, SCALPEL_DEFAULT_OUTPUT_DIR, strlen(SCALPEL_DEFAULT_OUTPUT_DIR) + 1);
  scalpel_state.invocation[0] = 0;

  // copy the invocation string into the state
  do {
    strncat(scalpel_state.invocation, *argvcopy, MAX_STRING_LENGTH - strlen(scalpel_state.invocation) - 1);
    strncat(scalpel_state.invocation, " ", MAX_STRING_LENGTH - strlen(scalpel_state.invocation) - 1);
    argvcopy++;
  } while (*argvcopy);

  // number of file types must be known before command line args can be processed because of -U
  // option
  while (INITIAL_SEARCH_SPECS[scalpel_state.num_specs].FILETYPE[0]) {
    scalpel_state.num_specs++;
  }

  scalpel_state.search_specs = malloc(sizeof(SearchSpec) * (scalpel_state.num_specs + 1));
  check_memory_allocation(scalpel_state.search_specs, __LINE__, __FILE__, "scalpel_state.search_specs");
  scalpel_state.search_specs_capacity = scalpel_state.num_specs + 1;
  // copy static search specs into scalpel state and initialize fields that aren't specified in
  // scalpelconf.c. The copy is performed so search specs can be modified as needed. Also remember
  // original index in SEARCH_SPECS for each (-U can reorder scalpel_state.search_specs) so function
  // pointers can be initialized during checkpoint restore.
  for (i = 0; i < scalpel_state.num_specs; i++) {
    copy_search_spec(&scalpel_state.search_specs[i], &INITIAL_SEARCH_SPECS[i]);
    scalpel_state.search_specs[i].mastertype = i;
  }
  scalpel_state.search_specs[scalpel_state.num_specs].FILETYPE[0] = 0;

  // BLOCKVALIDATOR and BATCHEDBLOCKVALIDATOR are mutually exclusive: a file type is validated either
  // one block at a time (BLOCKVALIDATOR, serviced by the validation threads) or by a self-iterating
  // batched validator, never both. Reject a scalpelconf.c entry that sets both.
  for (i = 0; i < scalpel_state.num_specs; i++) {
    if (scalpel_state.search_specs[i].BLOCKVALIDATOR
        && scalpel_state.search_specs[i].BATCHEDBLOCKVALIDATOR) {
      char errmsg[MAX_STRING_LENGTH + 128];
      snprintf(errmsg, sizeof(errmsg),
               "File type \"%s\" defines both BLOCKVALIDATOR and BATCHEDBLOCKVALIDATOR in "
               "scalpelconf.c; these are mutually exclusive.",
               scalpel_state.search_specs[i].FILETYPE);
      handle_error(SCALPEL_GENERAL_ABORT, errmsg, __LINE__, __FILE__);
    }
    if (scalpel_state.search_specs[i].BLOCKVALIDATIONSCOPE != BLOCK_VALIDATION_ALWAYS
        && scalpel_state.search_specs[i].BLOCKVALIDATIONSCOPE
               != BLOCK_VALIDATION_REASSEMBLY_ONLY
        && scalpel_state.search_specs[i].BLOCKVALIDATIONSCOPE
               != BLOCK_VALIDATION_DISABLED) {
      char errmsg[MAX_STRING_LENGTH + 128];
      snprintf(errmsg, sizeof(errmsg),
               "File type \"%s\" has an invalid BLOCKVALIDATIONSCOPE in scalpelconf.c.",
               scalpel_state.search_specs[i].FILETYPE);
      handle_error(SCALPEL_GENERAL_ABORT, errmsg, __LINE__, __FILE__);
    }
    if (scalpel_state.search_specs[i].BLOCKVALIDATIONSCOPE
            == BLOCK_VALIDATION_REASSEMBLY_ONLY
        && ! scalpel_state.search_specs[i].BLOCKVALIDATOR
        && ! scalpel_state.search_specs[i].BATCHEDBLOCKVALIDATOR) {
      char errmsg[MAX_STRING_LENGTH + 160];
      snprintf(errmsg, sizeof(errmsg),
               "File type \"%s\" declares reassembly-only block validation but defines neither "
               "BLOCKVALIDATOR nor BATCHEDBLOCKVALIDATOR in scalpelconf.c.",
               scalpel_state.search_specs[i].FILETYPE);
      handle_error(SCALPEL_GENERAL_ABORT, errmsg, __LINE__, __FILE__);
    }
  }

  process_command_line_args(argc, argv);
  argv += optind;

  // reserve slack capacity for the file subtypes (e.g., csv-Ncol) that add_file_subtype()
  // creates during block validation. Preallocating here, after -U/-z compaction has settled
  // the base file-type set and before any threads exist, lets add_file_subtype() append a
  // subtype in place instead of realloc()ing, which would relocate search_specs (and its
  // embedded mutexes and atomics) while validation threads read it lock-free. On a checkpoint
  // restore the deserializer sizes the array and no subtypes are ever created, so this is
  // skipped for restores.
  if (! scalpel_state.restore_from_checkpoint) {
    scalpel_state.search_specs_capacity = scalpel_state.num_specs + MAX_FILE_SUBTYPES + 1;
    scalpel_state.search_specs = realloc(scalpel_state.search_specs,
                                         sizeof(SearchSpec) * scalpel_state.search_specs_capacity);
    check_memory_allocation(scalpel_state.search_specs, __LINE__, __FILE__, "scalpel_state.search_specs");
    // zero the reserved slots (indices num_specs .. capacity - 1); this also keeps the
    // null-terminator sentinel (FILETYPE[0] == 0) valid at index num_specs
    memset(&scalpel_state.search_specs[scalpel_state.num_specs], 0,
           sizeof(SearchSpec) * (MAX_FILE_SUBTYPES + 1));

    // initialize the base file types' mutexes at their final location. The copy only zeroes
    // them, so initialize them here, after -U/-z compaction and the slack realloc have settled
    // the array, rather than relying on a zeroed pthread_mutex_t being a valid default-
    // initialized mutex. Doing it after the realloc also ensures no initialized mutex is ever
    // relocated. (Subtype slots are initialized in add_file_subtype(); the checkpoint-restore
    // path initializes all specs' mutexes in scalpel_state_serialization().)
    for (uint32_t s = 0; s < scalpel_state.num_specs; s++) {
      if (pthread_mutex_init(&scalpel_state.search_specs[s].filewritelock, NULL)
          || pthread_mutex_init(&scalpel_state.search_specs[s].offsets.headerlock, NULL)
          || pthread_mutex_init(&scalpel_state.search_specs[s].offsets.footerlock, NULL)) {
        // fatal
        handle_error(SCALPEL_ERROR_MUTEX_FAILURE, "initialize_state()", __LINE__, __FILE__);
      }
    }
  }

  // blocksize must be a multiple of 512 for correct operation
  if (scalpel_state.blocksize % 512) {
    // fatal
    handle_error(SCALPEL_ERROR_BAD_BLOCKSIZE, "main()", __LINE__, __FILE__);
  }

  // check consistency of start_block and end_block
  if (scalpel_state.end_block < scalpel_state.start_block) {
    // fatal
    handle_error(SCALPEL_ERROR_BAD_START_END_BLOCKS, "main()", __LINE__, __FILE__);
  }

  // power of 2 requirement was verified in command line processing, but the relationship between
  // these is also important
  if (scalpel_state.gallop_limit < scalpel_state.gallop_factor) {
    // fatal
    lock_fprintf(stderr, "%s", RED);
    lock_fprintf(stderr, "The gallop rate must be <= the gallop limit.  Check the -g and -G arguments.\n");
    lock_fprintf(stderr, "%s", BLACK);
    exit(-1);
  }

  if (argc - optind > 2) {
    usage();
    lock_fprintf(stderr, "%s", RED);
    lock_fprintf(stderr, "\nERROR: <imgfilename> and <blockmapfilename> must be the last two command line arguments.\n\n");
    lock_fprintf(stderr, "%s", BLACK);
    exit(-1);
  }

  if (argc - optind < 2) {
    usage();
    lock_fprintf(stderr, "%s", RED);
    lock_fprintf(stderr, "\nERROR: Both <imgfilename> and <blockmapfilename> are required.\n\n");
    lock_fprintf(stderr, "%s", BLACK);
    exit(-1);
  }

  copy_command_line_path(scalpel_state.image_pathname,
                         sizeof(scalpel_state.image_pathname), *argv,
                         "image file");
  argv++;
  // reserve one byte for the temporary suffix used during atomic blockmap publication
  copy_command_line_path(scalpel_state.blockmap_pathname,
                         sizeof(scalpel_state.blockmap_pathname) - 1, *argv,
                         "blockmap file");

  // informational options exit during command-line processing, before executable discovery
  hash_running_executable(argv0);

  // initialize lock for adding subtypes
  pthread_mutexattr_t mutextype;  // used to set type of search_spec_lock mutex
  if (pthread_mutexattr_init(&mutextype) != 0) {
    // fatal
    handle_error(SCALPEL_ERROR_MUTEX_FAILURE, "initialize_state()", __LINE__, __FILE__);
  }

  if (pthread_mutexattr_settype(&mutextype, PTHREAD_MUTEX_TYPE) != 0) {
    // fatal
    handle_error(SCALPEL_ERROR_MUTEX_FAILURE, "initialize_state()", __LINE__, __FILE__);
  }

  if (pthread_mutex_init(&scalpel_state.search_specs_lock, &mutextype)) {
    // fatal
    handle_error(SCALPEL_ERROR_MUTEX_FAILURE, "initialize_state()", __LINE__, __FILE__);
  }

  // note longest footer--this will not include file subtypes derived from master file types
  scalpel_state.longest_footer = find_longest_footer();

  // GGRIII: These thread pool size defaults may need more investigation.

  // deal with thread pool size overrides
  int default_thread_count = num_physical_cores();

  scalpel_state.max_filemirror_threads = max_filemirror_threads_override ? (int32_t)max_filemirror_threads_override
                                                                         : default_thread_count;

  scalpel_state.max_reassembly_threads = max_reassembly_threads_override ? (int32_t)max_reassembly_threads_override
                                                                         : default_thread_count;

  scalpel_state.max_search_threads = max_search_threads_override ? (int32_t)max_search_threads_override : default_thread_count;

  scalpel_state.max_validation_threads = max_validation_threads_override ? (int32_t)max_validation_threads_override
                                                                         : default_thread_count;
}

// initialize the machine-level AI state used during carving: resolve the ONNX execution
// provider and GPU device list for the whole run (-Y; see onnx_providers.h), then set up the
// optional MoDiCo block classifier. Validators that use ONNX read the resolved provider
// through the onnx_providers.h accessors and manage their own model lifecycles inside their
// own .h files; nothing validator-specific lives here. 'scalpel3_home' is the base scalpel3
// directory used to locate the MoDiCo models. MoDiCo is disabled (and Scalpel runs vanilla)
// when no model exists for this block size, its class map is missing or mismatched, or it is
// turned off by flag (-y false) or environment (SCALPEL3_NO_MODICO).
//
static void initialize_AI(const char *scalpel3_home) {

  char onnx_errbuf[512];
  char provider_desc[160];
  int desc_len;
  int modico_intra_threads;

  // resolve the ONNX execution provider and GPU device list once for the whole run
  if (! onnx_providers_resolve(onnx_provider_cli[0] ? onnx_provider_cli : NULL,
                               onnx_errbuf, sizeof(onnx_errbuf))) {
    lock_fprintf(stderr, "\nERROR: %s\n", onnx_errbuf);
    lock_fprintf(stderr, "%s", BLACK);
    exit(-1);
  }

  const char *onnx_accel = onnx_resolved_accelerator();

  // surface an auto step-down from detected accelerator hardware, so a machine with a GPU
  // that lands on cpu does not look like a cpu-only machine
  if (onnx_resolve_note()[0]) {
    scalpel_log("%s\n", onnx_resolve_note());
  }

  desc_len = snprintf(provider_desc, sizeof(provider_desc), "%s%s", onnx_accel,
                      onnx_resolved_was_explicit() ? " (selected with -Y)"
                                                   : " (auto-selected)");
  if (! strcasecmp(onnx_accel, "cuda")) {
    // report physical device ids so the line matches nvidia-smi even when the resolved
    // ordinals live in a CUDA_VISIBLE_DEVICES-narrowed space
    for (int i = 0;
         i < onnx_resolved_num_devices() && desc_len < (int)sizeof(provider_desc);
         i++) {
      desc_len += snprintf(provider_desc + desc_len,
                           sizeof(provider_desc) - (size_t)desc_len, "%s%d",
                           i ? "," : ", devices ",
                           onnx_cuda_physical_device(onnx_resolved_device_list()[i]));
    }
  }
  scalpel_log("ONNX execution provider: %s.\n", provider_desc);
  if (! strcasecmp(onnx_accel, "cuda")
      && onnx_cuda_runtime_description()[0]) {
    scalpel_log("CUDA user-space runtime: %s.\n",
                onnx_cuda_runtime_description());
  }

  modico_intra_threads = modico_onnx_intra_threads(onnx_accel);
  scalpel_log("MoDiCo ONNX intra-op threads: %d\n",
              modico_intra_threads);

  // set up the optional MoDiCo block classifier. MoDiCo scores each block's
  // file type and is used to PRIORITIZE block selection during fragmented
  // reassembly; it COMPLEMENTS the structural block validators (which trump
  // it) and never excludes a block. If no exported model exists for this
  // image's block size, or the class-name map is missing/mismatched, MoDiCo
  // is disabled and Scalpel runs exactly as before (vanilla).
  scalpel_state.modico_enabled = false;
  scalpel_state.modico_spec_to_class = NULL;
  scalpel_state.modico_num_specs = 0;

  if (scalpel_state.restore_from_checkpoint) {
    scalpel_log("MoDiCo setup skipped during checkpoint restore; block "
                "classification state is restored from checkpoint data.\n");
    return;
  }

  // MoDiCo is enabled by default on every provider, including cpu; -y false (or the
  // SCALPEL3_NO_MODICO environment variable) disables it
  bool modico_should_run = scalpel_state.modico_requested != 0;

  if (scalpel_state.modico_requested < 0 && getenv("SCALPEL3_NO_MODICO")) {
    modico_should_run = false;
  }

  if (! modico_should_run) {
    if (scalpel_state.modico_requested == 0) {
      scalpel_log("MoDiCo block prioritization disabled (-y false).\n");
    }
    else {
      scalpel_log("MoDiCo block prioritization disabled "
                  "(SCALPEL3_NO_MODICO is set).\n");
    }
    return;
  }

  // model directory: SCALPEL3_MODICO_DIR overrides; default is the model
  // directory under the scalpel3 tree.
  char modico_dir[PATH_MAX];
  const char *env_dir = getenv("SCALPEL3_MODICO_DIR");
  if (env_dir && strlen(env_dir)) {
    snprintf(modico_dir, sizeof(modico_dir), "%s", env_dir);
  }
  else {
    snprintf(modico_dir, sizeof(modico_dir), "%s/src/exe_vision/unix",
             scalpel3_home);
  }

  // The three-input graph-cut artifact moves histogram construction out of
  // the ONNX graph and works with both CUDA and CoreML. The historical
  // filename is retained for compatibility with installed model sets.
  bool native_histogram_model =
      ! strcasecmp(onnx_accel, "cuda")
      || (! strcasecmp(onnx_accel, "coreml")
          && modico_coreml_model != MODICO_COREML_MODEL_LEGACY);
  bool native_histogram_fallback = false;
  bool native_histogram_required =
      ! strcasecmp(onnx_accel, "coreml")
      && modico_coreml_model == MODICO_COREML_MODEL_GRAPHCUT;
  if (native_histogram_model
      && ! native_histogram_required) {
    char graphcut_path[PATH_MAX];
    int graphcut_len = snprintf(graphcut_path, sizeof(graphcut_path),
                                "%s/modico_%u_coreml_graphcut.onnx",
                                modico_dir, scalpel_state.blocksize);
    if (graphcut_len < 0 || (size_t)graphcut_len >= sizeof(graphcut_path)
        || access(graphcut_path, R_OK) != 0) {
      native_histogram_model = false;
      native_histogram_fallback = true;
    }
  }
  if (! strcasecmp(onnx_accel, "coreml")) {
    const char *selection =
        modico_coreml_model == MODICO_COREML_MODEL_LEGACY
            ? "legacy (selected with -Y coreml-legacy)"
            : (native_histogram_fallback
                   ? "legacy (no graph-cut model for this block size)"
                   : (modico_coreml_model == MODICO_COREML_MODEL_GRAPHCUT
                          ? "graph-cut (selected with -Y coreml-graphcut)"
                          : "graph-cut (default)"));
    scalpel_log("MoDiCo CoreML model variant: %s.\n", selection);
  }
  else if (! strcasecmp(onnx_accel, "cuda")) {
    scalpel_log("MoDiCo CUDA model variant: %s.\n",
                native_histogram_fallback
                    ? "legacy (no native-histogram model for this block size)"
                    : "native histograms (default)");
  }

  // The auto-select loader appends ".onnx" (and prefers "_int8.onnx" on
  // capable CPUs). The native-histogram model has no INT8 sibling.
  char modico_base[PATH_MAX];
  snprintf(modico_base, sizeof(modico_base), "%s/modico_%u%s",
           modico_dir, scalpel_state.blocksize,
           native_histogram_model ? "_coreml_graphcut" : "");

  int modico_device = onnx_resolved_num_devices() > 0
                      ? onnx_resolved_device_list()[0] : 0;

  if (! modico_onnx_global_init(modico_base, modico_intra_threads,
                                onnx_accel, modico_device)) {
    char fp32_model[PATH_MAX];
    int fp32_len = snprintf(fp32_model, sizeof(fp32_model), "%s.onnx",
                            modico_base);

    if (fp32_len < 0 || (size_t)fp32_len >= sizeof(fp32_model)
        || access(fp32_model, R_OK) != 0) {
      scalpel_log("No MoDiCo model for blocksize %u (looked for %s.onnx); "
                  "running without MoDiCo block prioritization.\n",
                  scalpel_state.blocksize, modico_base);
      return;
    }

    char errmsg[512];
    snprintf(errmsg, sizeof(errmsg),
             "The MoDiCo model for block size %u is present, but the resolved "
             "'%s' ONNX execution provider could not initialize it. Rerun "
             "init_scalpel3.sh to verify the ONNX runtime, or explicitly "
             "select -Y cpu for an intentional CPU run.",
             scalpel_state.blocksize, onnx_accel);
    handle_error(SCALPEL_GENERAL_ABORT, errmsg, __LINE__, __FILE__);
  }

  if (strcasecmp(onnx_accel, modico_onnx_global_provider()) != 0) {
    char errmsg[256];
    snprintf(errmsg, sizeof(errmsg),
             "MoDiCo initialized the '%s' execution provider after Scalpel3 "
             "resolved '%s'; refusing to change providers during a run.",
             modico_onnx_global_provider(), onnx_accel);
    handle_error(SCALPEL_GENERAL_ABORT, errmsg, __LINE__, __FILE__);
  }

  // build the SearchSpec -> MoDiCo-class table from the class-name file.
  char classmap_path[PATH_MAX];
  const char *env_cm = getenv("SCALPEL3_MODICO_CLASSMAP");
  if (env_cm && strlen(env_cm)) {
    snprintf(classmap_path, sizeof(classmap_path), "%s", env_cm);
  }
  else {
    snprintf(classmap_path, sizeof(classmap_path), "%s/class_names.json",
             modico_dir);
  }

  const char **spec_names =
      malloc((size_t)scalpel_state.num_specs * sizeof(char *));
  check_memory_allocation(spec_names, __LINE__, __FILE__, "spec_names");
  for (uint32_t si = 0; si < scalpel_state.num_specs; si++) {
    spec_names[si] = scalpel_state.search_specs[si].FILETYPE;
  }

  int parsed = 0;
  int mapped = 0;
  int *s2c = modico_classmap_build(classmap_path,
                                   (const char *const *)spec_names,
                                   (int)scalpel_state.num_specs,
                                   &parsed, &mapped);
  free(spec_names);

  int model_classes = modico_onnx_global_num_classes();

  if (! s2c) {
    scalpel_log("MoDiCo: could not read class map %s; disabling MoDiCo "
                "block prioritization.\n", classmap_path);
    modico_onnx_global_shutdown();
    return;
  }

  if (parsed != model_classes) {
    scalpel_log("MoDiCo: class-map count (%d) != model output classes "
                "(%d); disabling MoDiCo to avoid misrouting.\n",
                parsed, model_classes);
    free(s2c);
    modico_onnx_global_shutdown();
    return;
  }

  scalpel_state.modico_spec_to_class = s2c;
  scalpel_state.modico_num_specs = scalpel_state.num_specs;
  scalpel_state.modico_enabled = true;

  char enabled_msg[PATH_MAX + 160];
  int enabled_len = snprintf(enabled_msg, sizeof(enabled_msg),
                             "MoDiCo enabled: %s.onnx (%d classes), %d of %u carved "
                             "types mapped, execution provider=%s",
                             modico_base, model_classes, mapped,
                             scalpel_state.num_specs,
                             modico_onnx_global_provider());
  if (modico_onnx_global_uses_cuda()
      && enabled_len > 0 && (size_t)enabled_len < sizeof(enabled_msg)) {
    snprintf(enabled_msg + enabled_len, sizeof(enabled_msg) - (size_t)enabled_len,
             " device=%d", modico_onnx_global_device_id());
  }
  scalpel_log("%s.\n", enabled_msg);
}


int main(int argc, char *argv[]) {
  // PyThreadState *thread_state = NULL;
  uint64_t total_wait;
  struct timespec endtime;
  struct stat s;
  char nows[27];
  time_t now;
  char sha256hex[32 * 2 + 1];
  char *scalpel3_home;
  char sockname[PATH_MAX];
  char cmdline[MAX_STRING_LENGTH];
  uint64_t i;

  // restrict newly created evidence and state to the current user
  umask(S_IRWXG | S_IRWXO);

#if DISABLE_COLOR > 0
  DISABLE_ALL_COLOR;
#endif

  // don't use color for redirected output
  if (! isatty(1) || ! isatty(2)) {
    DISABLE_ALL_COLOR;
  }

  // not initiating new checkpoints of any kind
  atomic_init(&TAKE_CHECKPOINT_AND_EXIT, false);
  atomic_init(&TAKE_RECOVERY_CHECKPOINT, false);
  atomic_init(&TAKE_PERIODIC_CHECKPOINT, false);
  atomic_init(&TAKE_PROGRESS_CHECKPOINT, false);
  atomic_init(&RESTARTABLE_CHECKPOINT_AVAILABLE, false);
  atomic_init(&REASS_RETURN_TO_IDLE, false);

  // init flags that threads depend on
  atomic_init(&carvelist_initialized, false);   // carvelist is not yet ready
  atomic_init(&promising_initialized, false);   // promising queue is not yet ready
  atomic_init(&kill_queue_initialized, false);  // kill queue is not yet ready
  atomic_init(&kill_queue_generation, 1);

  // initialize performance stats
  atomic_init(&header_footer_wait, 0);

  // register signal handler for control-C
  setup_sigint_handler();

  // ignore SIGPIPE errors
  signal(SIGPIPE, SIG_IGN);

  // IPC is initially assumed on unless overridden with command line option
  ipcsocket = -1;
  no_IPC = false;

  // make "random" choices as reproducible as possible
  portable_srandom(0);

  if (FORCE_VERBOSE_MODE) {
    scalpel_state.mode_verbose = true;
  }

  // get start time and establish last checkpoint time
  clock_gettime(CLOCK_MONOTONIC, &starttime);
  last_checkpoint = starttime;

  // display logo
  scalpel_logo();

  // finalize setup of Scalpel's initial state
  initialize_state(argc, argv);

  // locate runtime resources only after informational options have exited successfully
  scalpel3_home = getenv("SCALPEL3_HOME");

  if (! scalpel3_home || ! strlen(scalpel3_home)) {
    lock_fprintf(stderr, "%s", RED);
    lock_fprintf(stderr, "\nThe SCALPEL3_HOME environment variable MUST be set to the base scalpel3 directory for\n"
                         "scalpel3 to operate correctly. Aborting.\n");
    lock_fprintf(stderr, "%s", BLACK);
    exit(-1);
  }

  // reconstruct command line for log
  cmdline[0] = 0;
  size_t cmdline_remaining = MAX_STRING_LENGTH - 1;
  for (i = 0; i < (uint64_t)argc && cmdline_remaining > 0; i++) {
    size_t arglen = strlen(argv[i]);
    size_t current_len = strlen(cmdline);

    // check if there's room for for arg plus a space
    if (arglen + 1 < cmdline_remaining) {
      strncat(cmdline, argv[i], cmdline_remaining);
      cmdline_remaining -= arglen;
      current_len += arglen;

      // add space if not the last argument and if there's room
      if (i < (uint64_t)argc - 1 && cmdline_remaining > 0) {
        cmdline[current_len] = ' ';
        cmdline[current_len + 1] = '\0';
        cmdline_remaining--;
      }
    }
    else {
      // not enough room - truncate with indicator
      if (cmdline_remaining > 4) {
        strncat(cmdline, "...", cmdline_remaining);
      }
      break;
    }
  }

  time(&now);
  strcpy(nows, ctime(&now));
  nows[strlen(nows) - 1] = 0;
  lock_fprintf(stdout, "%s", BLUE);
  scalpel_log(SCALPEL_BANNER_STRING);
  scalpel_log(" starting execution at %s.\n", nows);
  lock_fprintf(stdout, "%s", BLACK);

  if (scalpel_state.memory_profiling) {
    memory_footprint("scalpel state init complete");
  }

  scalpel_log("Command line: %s\n", cmdline);

  // this has to happen after init of scalpel_state
  if (! scalpel_state.disable_backtrace) {
    // initialize backtrace and register signal handler for seg fault
    bt_state = backtrace_create_state(NULL, 0, bt_error_callback, NULL);
    signal(SIGSEGV, sigsegv_signal_handler);
  }

  // stat() image file to make sure it's non-empty
  if (lstat(scalpel_state.image_pathname, &s) || s.st_size == 0) {
    lock_fprintf(stderr, "The image file must exist and be non-empty.  Aborting.\n");
    return -1;
  }

  if (scalpel_state.mode_verbose) {
    lock_fprintf(stdout, "Verbose mode is on.\n");
  }


  // claim the base output directory before potentially expensive model initialization. No other
  // scalpel3 process may touch its shared databases, checkpoints, or IPC endpoint while we run.
  lock_fprintf(stdout, "Locking output directory.\n");
  lock_output_directory();

  initialize_AI(scalpel3_home);

  lock_fprintf(stdout, "Initialized scalpel state.\n");

  scalpel_log("Block reservation system is %s.\n", scalpel_state.reservations ? "ON" : "OFF");

  // set up the timestamped output directory, which will contain carved files
  lock_fprintf(stdout, "Setting up invocation output directory.\n");
  init_output_directory();

  // remove IPC endpoint file if it exists
  snprintf(sockname, PATH_MAX, "%s/.scalpel3IPC", scalpel_state.base_output_directory);
  unlink(sockname);

  // set up the audit file, which tracks important actions
  lock_fprintf(stdout, "Creating audit file.\n");
  open_audit_file();

  sprinthex(sha256hex, (char *)scalpel_state.sha256, 32, false);
  scalpel_log("SHA256 of scalpel3 executable is %s.\n", sha256hex);

  if (scalpel_state.restore_from_checkpoint) {
    frame_message("ATTEMPTING TO RESTART FROM CHECKPOINT");
    // get checkpointed scalpel state before proceeding with CP restoration
    restore_checkpointed_scalpel_state();
  }

  scalpel_log("Backtrace on crash is %s.\n", scalpel_state.disable_backtrace ? "OFF" : "ON");

  // final version of active file types for this run
  scalpel_log("Number of active file types is %d.\n", scalpel_state.num_specs);

  if (NC <= 0) {
    scalpel_log("Number of physical/performance CPU cores detected: %d.\n", num_physical_cores());
  }
  else {
    scalpel_log("Number of physical CPU cores overridden to %d cores.\n", NC);
  }

  scalpel_log("Number of logical CPU cores detected: %d.\n", num_logical_cores());

  scalpel_log("Max filemirror threads: %" PRId32 "\n", scalpel_state.max_filemirror_threads);
  scalpel_log("Max search threads: %" PRId32 "\n", scalpel_state.max_search_threads);
  scalpel_log("Max reassembly threads: %" PRId32 "\n", scalpel_state.max_reassembly_threads);
  scalpel_log("Max validation threads: %" PRId32 "\n", scalpel_state.max_validation_threads);

  print_simd_banner();

  // start the image file mirror and potentially read checkpointed state
  lock_fprintf(stdout, "Starting file mirror.\n");
  scalpel_state.filemirror = filemirror_start(scalpel_state.image_pathname, scalpel_state.blockmap_pathname,
                                              scalpel_state.blocksize, FILEMIRROR_BUFFER_SIZE, READAHEAD_BUFFERS,
                                              scalpel_state.max_filemirror_threads, scalpel_state.longest_footer,
                                              scalpel_state.restore_from_checkpoint, scalpel_state.reduce_aggressive_allocation,
                                              scalpel_state.start_block, scalpel_state.end_block);

  lock_fprintf(stdout, "File mirror started.\n");

  // now the checkpointed promising queue data can be restored, since this relies on the file mirror
  // being up
  if (scalpel_state.restore_from_checkpoint) {
    lock_fprintf(stdout, "Restoring promising queue from checkpoint data.\n");
    restore_checkpointed_promising_queue();
  }

  if (scalpel_state.memory_profiling) {
    memory_footprint("before carving");
  }

  // carve both logically contiguous and fragmented files
  carve_files();

  // shutdown file mirror
  filemirror_stop(scalpel_state.filemirror);

  if (scalpel_state.memory_profiling) {
    memory_footprint("scalpel exiting");
  }

  // get end time
  clock_gettime(CLOCK_MONOTONIC, &endtime);
  total_wait = (endtime.tv_sec - starttime.tv_sec) * NANOSECONDS_PER_SECOND
               + (endtime.tv_nsec - starttime.tv_nsec);

#if VALIDATOR_PERFORMANCE_STATS > 0
  if (! scalpel_state.no_defrag
      && scalpel_state.halt_after == HALT_AFTER_NONE) {
    scalpel_log("\nFragmented reassembly backtracking report:\n");
    for (i = 0; i < scalpel_state.num_specs; i++) {
      if (! scalpel_state.search_specs[i].MASTER && ! scalpel_state.search_specs[i].NO_DEFRAG
          && (scalpel_state.search_specs[i].FILEVALIDATOR || scalpel_state.search_specs[i].REASSEMBLYFUNC)) {
        scalpel_log("  %-10s%9" PRIu64 " backtracking operations\n", scalpel_state.search_specs[i].FILETYPE,
                    scalpel_state.search_specs[i].backtracked);
      }
    }

    scalpel_log("\nFragmented reassembly file validator performance:\n");
    for (i = 0; i < scalpel_state.num_specs; i++) {
      if (! scalpel_state.search_specs[i].MASTER && ! scalpel_state.search_specs[i].NO_DEFRAG
          && (scalpel_state.search_specs[i].FILEVALIDATOR || scalpel_state.search_specs[i].REASSEMBLYFUNC)) {
        scalpel_log("  %-10s%9" PRIu64 " calls, \t%8.4lf secs total time, \t%5.4lf secs longest time\n",
                    scalpel_state.search_specs[i].FILETYPE,
                    atomic_load_explicit(&scalpel_state.search_specs[i].FV_calls, memory_order_acquire),
                    (double)atomic_load_explicit(&scalpel_state.search_specs[i].FV_total, memory_order_acquire) / 1e9,
                    (double)atomic_load_explicit(&scalpel_state.search_specs[i].FV_longest, memory_order_acquire) / 1e9);
      }
    }
  }
#endif

#if BLOCK_SELECTION_PERFORMANCE_STATS > 0
  if (! scalpel_state.no_defrag
      && scalpel_state.halt_after == HALT_AFTER_NONE) {
    scalpel_log("\nFragmented reassembly block selection performance:\n");
    for (i = 0; i < scalpel_state.num_specs; i++) {
      if (! scalpel_state.search_specs[i].MASTER && ! scalpel_state.search_specs[i].NO_DEFRAG
          && (scalpel_state.search_specs[i].FILEVALIDATOR || scalpel_state.search_specs[i].REASSEMBLYFUNC)) {
        scalpel_log("  %-10s%9" PRIu64 " calls, \t%8.4lf secs total time, \t%5.4lf secs longest time, \tmost considered: %9" PRIu64
                    "\n",
                    scalpel_state.search_specs[i].FILETYPE,
                    atomic_load_explicit(&scalpel_state.search_specs[i].BLK_calls, memory_order_acquire),
                    (double)atomic_load_explicit(&scalpel_state.search_specs[i].BLK_total, memory_order_acquire) / 1e9,
                    (double)atomic_load_explicit(&scalpel_state.search_specs[i].BLK_longest, memory_order_acquire) / 1e9,
                    atomic_load_explicit(&scalpel_state.search_specs[i].BLK_most_blocks, memory_order_acquire));
      }
    }
  }
#endif

  scalpel_log("\nCarving stats:\n"
	      "Header/footer discovery [real time]   = %.4lf secs.\n"
	      "Sequential I/O wait     [real time]   = %.4lf secs.\n"
	      "Random read wait        [overlapping] = %.4lf secs.\n"
	      "Random write wait       [overlapping] = %.4lf secs.\n"
	      "Total elapsed time                    = %.4lf secs.\n"
	      "Validated files                       = %" PRIu64 ".\n"
	      "Total unique files carved             = %" PRIu64 ".\n",
	      (double)atomic_load_explicit(&header_footer_wait, memory_order_acquire) / 1e9, (double)seq_io_wait / 1e9,
	      (double)atomic_load_explicit(&random_read_wait, memory_order_acquire) / 1e9, (double)random_write_wait / 1e9,
	      (double)total_wait / 1e9, atomic_load_explicit(&scalpel_state.validated_files, memory_order_acquire),
	      atomic_load_explicit(&scalpel_state.files_written, memory_order_acquire));

  if (! atomic_load_explicit(&TAKE_CHECKPOINT_AND_EXIT, memory_order_acquire)
      || ! atomic_load_explicit(&RESTARTABLE_CHECKPOINT_AVAILABLE, memory_order_acquire)) {
    // on successful non-checkpointing exit, checkpointing data (excluding the blockmap, which is
    // never deleted explicitly) is removed, since modifications made to the blockmap and other
    // critical state mean that the checkpoint is invalid anyway.
    remove_checkpoint();
  }

  // tear down MoDiCo (safe whether or not it was enabled)
  modico_onnx_global_shutdown();
  if (scalpel_state.modico_spec_to_class) {
    free(scalpel_state.modico_spec_to_class);
    scalpel_state.modico_spec_to_class = NULL;
  }
  scalpel_state.modico_enabled = false;
  scalpel_state.modico_num_specs = 0;

  time(&now);
  strcpy(nows, ctime(&now));
  nows[strlen(nows) - 1] = 0;

  if (! atomic_load_explicit(&TAKE_CHECKPOINT_AND_EXIT, memory_order_acquire)) {
    lock_fprintf(stdout, "%s", BLUE);
    scalpel_log("scalpel3 completed execution on %s.\n", nows);
    lock_fprintf(stdout, "%s", BLACK);
  }
  else if (! atomic_load_explicit(&RESTARTABLE_CHECKPOINT_AVAILABLE,
                                  memory_order_acquire)) {
    lock_fprintf(stdout, "%s", RED);
    scalpel_log("scalpel3 stopped before checkpointable recovery state existed on %s.\n", nows);
    lock_fprintf(stdout, "%s", BLACK);
  }
  else {
    lock_fprintf(stdout, "%s", RED);
    scalpel_log("scalpel3 stopped because of checkpoint event on %s.\n", nows);
    lock_fprintf(stdout, "%s", BLACK);
  }

  close_audit_file();
  // remove IPC endpoint file if it exists
  snprintf(sockname, PATH_MAX, "%s/.scalpel3IPC", scalpel_state.base_output_directory);
  unlink(sockname);

  return 0;
}

