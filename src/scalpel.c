//
// Scalpel3 is Copyright(C) 2021 - 2026 by Golden G.Richard III and contributors.
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

// function prototypes
static void usage(void);
static int find_search_spec_filetype(const char *filetype);
static void parse_filetype_filter_arg(const char *arg, bool *filter,
                                      const char *option_name);
static void apply_filetype_filter(const bool *include_filter,
                                  const bool *exclude_filter,
                                  bool include_seen,
                                  bool exclude_seen);
static void process_command_line_args(int argc, char *argv[]);
static void initialize_state(int argc, char *argv[]);

static bool read_onnx_config_value(const char *cfg_path, const char *key, char *out, size_t out_sz);
static void load_onnx_runtime_config(const char *scalpel3_home, char *accelerator, size_t accelerator_sz);

// print scalpel usage info
static void usage(void) {
  lock_fprintf(stderr, "%s", BLUE);
  lock_fprintf(stderr, SCALPEL_BANNER_STRING ".\n");
  lock_fprintf(stderr, SCALPEL_COPYRIGHT_STRING "\n");

  lock_fprintf(stderr,
               "Scalpel carves files or data fragments from a disk image based on a set of\n"
               "file carving patterns, which include headers, footers, and other information.\n\n"

               "Usage: scalpel3 [-a] [-A secs] [-b] [-B] [-c] [-C] [-d] [-f] [-e #] [-F secs] [-g #] [-G #] [-h] [-H] [-i #]\n"
               "                [-I secs] [-j #] [-k #] [-L] [-m] [-M] [-n] [-o scalpel_output_dir] [-O] [-p] [-P] [-q clustersize] [-R]\n"
               "                [-r #] [-s #] [-t #] [-u #] [-U filetype[,filetype]...] [-v] [-V] [-w] [-x]\n"
               "                [-z filetype[,filetype]...]\n"
               "                img_filename blockmap_filename\n\n"

               "Options:\n"

               "-a  Turn off aggressive memory allocation, to reduce overhead.  Default is on. Leave this on unless you "
               "experience\n"
               "    out of memory errors or excessive swapping.\n"

               "-A  Create a checkpoint and stop execution after a specified number of seconds in the fragmented reassembly\n"
               "    phase of execution. This option is not checkpointed and must be specified on every execution where this\n"
               "    behavior is desired.\n"

               "-B  Don't backtrack.  Default is backtracking on.  Useful only for debugging.\n"

               "-b  Write blockvectors.  Default is to not write blockvectors.\n"

               "-c  Turn off reassembly thread work sharing. Default is on.\n"

               "-C  Turn off IPC.  Generally not recommended, but useful in environments that don't support Unix domain sockets.\n"
               "    Default is on.\n"

               "-d  Turn off header reuse for contiguous files. Default is on and you should generally leave this on.\n"

               "-e  Override detected number of physical CPU cores. scalpel3 detects the number of physical CPU cores for\n"
               "    determining thread pool sizes. On systems with hyperthreading, it may be beneficial to increase the number\n"
               "    of perceived CPU cores using -e. On Apple Silicon systems, the number of performance cores is used to size\n"
               "    thread pools and -e can be used to experimentally increase the sizes of all thread pools.\n"

               "-f  Don't attempt fragmented recovery for any supported file type. This essentially sets NO_DEFRAG to true for "
               "all\n"
               "    file types.\n"

               "-F  Create a checkpoint and stop execution when a new file hasn't been validated for a specified\n"
               "    number of seconds in the fragmented reassembly phase of execution. This option is not checkpointed\n"
               "    and must be specified on every execution where this behavior is desired.\n"

               "-g  Set reassembly gallop factor.\n"

               "-G  Set reassembly gallop limit.\n"

               "-h  Display this help message and then exit.\n"

	       "-H  Write header/footer database and then exit.\n"

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

               "-o  Set output directory for carved files.\n"

               "-O  Don't organize carved files into subdirectories. Default is organize.\n"

               "-p  Turn on file type prioritization for fragmented file reassembly.  Default is off.\n"

	       "-P  Write INPROGRESS files on every checkpoint.  The default is only to write INPROGRESS when this is\n"
	       "    requested via IPC (e.g., scalpel3-ctl -c).  This is primarily for debugging, as it adds substantial\n"
	       "    overhead.\n"

               "-q  Specify block/cluster size. Default is 512 bytes.\n"

               "-R  Resume from checkpoint.\n"

               "-r  Specify the maximum number of threads per filemirror pool.\n"

               "-s  Specify the maximum number of reassembly threads.\n"

               "-t  Specify the maximum number of search threads.\n"

               "-u  Specify the maximum number of validation threads.\n"

               "-U  Deactivate carving for one or more file types, e.g., -U JPG or -U JPG,PNG. Not compatible with -z.\n"

               "-v  Verbose mode.\n"

               "-V  Print copyright information and exit.\n"

               "-w  Write promising candidates that didn't validate completely. The default is to only write fully\n"
               "    validated files, to save disk space, but you probably want this on if partial results are useful\n"
               "    (e.g., initial fragments of photographic images).\n"

	       "-x  Override checkpoint integrity checks. Use this only if you know what you're doing!\n"

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
                                      const char *option_name) {
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
    if (filter[foundat]) {
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
  char *endptr;
  long long temp;

  include_filter = calloc(scalpel_state.num_specs, sizeof(bool));
  check_memory_allocation(include_filter, __LINE__, __FILE__, "include_filter");
  exclude_filter = calloc(scalpel_state.num_specs, sizeof(bool));
  check_memory_allocation(exclude_filter, __LINE__, __FILE__, "exclude_filter");

  lock_fprintf(stderr, "%s", RED);

  while ((i = getopt(argc, argv, "+aA:BbcCde:fF:g:G:hHi:I:j:k:LmMnNo:OpPq:r:Rs:t:u:U:vVwxz:")) != -1) {
    switch (i) {
    case 'a':
      scalpel_state.reduce_aggressive_allocation = true;
      cp_restricted = true;
      break;

    case 'A':
      if (strtoul(optarg, NULL, 10) < 10 || strtoul(optarg, NULL, 10) > INT_MAX) {
        lock_fprintf(stderr, "\nERROR: Invalid number of seconds for exit -A option.\n");
        lock_fprintf(stderr, "%s", BLACK);
        exit(-1);
      }
      else {
        scalpel_state.exit_after_secs = strtoul(optarg, NULL, 10);
      }
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
      scalpel_state.share_reassembly = false;
      cp_restricted = true;
      break;

    case 'C':
      no_IPC = true;
      break;

    case 'd':
      scalpel_state.contig_header_reuse = false;
      cp_restricted = true;
      break;

    case 'e':
      NC = strtoul(optarg, NULL, 10);
      if (NC < 1 || NC > 65536) {
        lock_fprintf(stderr, "\nERROR: Invalid # of CPU cores for -e command line option.\n");
        lock_fprintf(stderr, "%s", BLACK);
        exit(-1);
      }
      break;

    case 'f':
      scalpel_state.no_defrag = true;
      cp_restricted = true;
      break;

    case 'F':
      if (strtoul(optarg, NULL, 10) < 10 || strtoul(optarg, NULL, 10) > INT_MAX) {
        lock_fprintf(stderr, "\nERROR: Invalid number of seconds for validation gap for -F option.\n");
        lock_fprintf(stderr, "%s", BLACK);
        exit(-1);
      }
      else {
        scalpel_state.exit_after_val_gap = strtoul(optarg, NULL, 10);
      }
      break;

    case 'g':
      scalpel_state.gallop_factor = strtoul(optarg, NULL, 10);
      if (scalpel_state.gallop_factor & (scalpel_state.gallop_factor - 1)) {
        lock_fprintf(stderr, "\nERROR: Gallop factor for -g command line option must be a power of 2.\n");
        lock_fprintf(stderr, "%s", BLACK);
        exit(-1);
      }

      cp_restricted = true;
      break;

    case 'G':
      scalpel_state.gallop_limit = strtoul(optarg, NULL, 10);
      if (scalpel_state.gallop_limit & (scalpel_state.gallop_limit - 1)) {
        lock_fprintf(stderr, "\nERROR: Gallop limit for -G command line option must be a power of 2.\n");
        lock_fprintf(stderr, "%s", BLACK);
        exit(-1);
      }

      cp_restricted = true;
      break;

    case 'h':
      usage();
      exit(-1);

    case 'H':
      scalpel_state.hf_only = true;
      cp_restricted = true;
      break;

    case 'i':
      scalpel_state.validation_cp_threshold = strtoul(optarg, NULL, 10);
      if (scalpel_state.validation_cp_threshold < 1 || scalpel_state.validation_cp_threshold > 65536) {
        lock_fprintf(stderr, "\nERROR: Invalid validation checkpointing threshold for -i command line option.\n"
                             "Must be 1 <= i <= 65536.\n");
        lock_fprintf(stderr, "%s", BLACK);
        exit(-1);
      }
      break;

    case 'I':
      scalpel_state.checkpointing_interval = strtoul(optarg, NULL, 10);
      if (scalpel_state.checkpointing_interval < 5 || scalpel_state.checkpointing_interval > 65536) {
        lock_fprintf(stderr, "\nERROR: Invalid checkpointing interval for -I command line option.\n"
                             "Must be 5 <= I <= 65536.\n");
        lock_fprintf(stderr, "%s", BLACK);
        exit(-1);
      }
      else if (scalpel_state.checkpointing_interval > RECOVERY_CHECKPOINTING_INTERVAL) {
        lock_fprintf(stderr,
                     "\nWARNING: Checkpointing interval exceeds RECOVERY_CHECKPOINTING_INTERVAL (= %d seconds)\n"
                     "and will be ignored.\n",
                     RECOVERY_CHECKPOINTING_INTERVAL);
        lock_fprintf(stderr, "%s", BLACK);
      }
      break;

    case 'j':
      errno = 0;
      temp = strtoll(optarg, &endptr, 10);
      if (errno != 0 || *endptr != '\0' || temp < 0) {
        fprintf(stderr, "\nERROR: Start block for -j option must be >= 0.\n");
        fprintf(stderr, "%s", BLACK);
        exit(-1);
      }
      scalpel_state.start_block = (uint64_t)temp;

      cp_restricted = true;
      break;

    case 'k':
      errno = 0;
      temp = strtoll(optarg, &endptr, 10);
      if (errno != 0 || *endptr != '\0' || temp < 0) {
        fprintf(stderr, "\nERROR: End block for -k option must be >= 0.\n");
        fprintf(stderr, "%s", BLACK);
        exit(-1);
      }
      scalpel_state.end_block = (uint64_t)temp;

      cp_restricted = true;
      break;

    case 'L':
      for (j = 0; j < scalpel_state.num_specs; j++) {
        lock_fprintf(stderr, "%s %s\n", scalpel_state.search_specs[j].FILETYPE,
                     scalpel_state.search_specs[j].MASTER ? "(master)" : "");
      }
      exit(-1);

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
      strncpy(scalpel_state.output_directory, optarg,
              PATH_MAX / 2);                                 // constrain copy to PATH_MAX / 2 to prevent malicious overflows
      scalpel_state.output_directory[PATH_MAX / 2 - 1] = 0;  // force null termination
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
      scalpel_state.blocksize = strtoul(optarg, NULL, 10);
      if (scalpel_state.blocksize <= 0 || scalpel_state.blocksize > 1024 * 1024 * 1024 || scalpel_state.blocksize % 512) {
        lock_fprintf(stderr, "\nERROR: Invalid blocksize %d for -q command line option. Blocksize must be\n"
                             "at least 512 bytes and divisible by 512.\n", scalpel_state.blocksize);
        lock_fprintf(stderr, "%s", BLACK);
        exit(-1);
      }
      cp_restricted = true;
      break;

    case 'r':
      scalpel_state.max_filemirror_threads = strtoul(optarg, NULL, 10);
      if (scalpel_state.max_filemirror_threads < 1 || scalpel_state.max_filemirror_threads > 65536) {
        lock_fprintf(stderr, "\nERROR: Invalid # of filemirror threads for -r command line option.\n");
        lock_fprintf(stderr, "%s", BLACK);
        exit(-1);
      }
      max_filemirror_threads_override = scalpel_state.max_filemirror_threads;
      break;

    case 'R':
      scalpel_state.restore_from_checkpoint = true;
      break;

    case 's':
      scalpel_state.max_reassembly_threads = strtoul(optarg, NULL, 10);
      if (scalpel_state.max_reassembly_threads < 1 || scalpel_state.max_reassembly_threads > 65536) {
        lock_fprintf(stderr, "\nERROR: Invalid # of reassembly threads for -s command line option.\n");
        lock_fprintf(stderr, "%s", BLACK);
        exit(-1);
      }
      max_reassembly_threads_override = scalpel_state.max_reassembly_threads;
      break;

    case 't':
      scalpel_state.max_search_threads = strtoul(optarg, NULL, 10);
      if (scalpel_state.max_search_threads < 1 || scalpel_state.max_search_threads > 65536) {
        lock_fprintf(stderr, "\nERROR: Invalid # of search threads for -t command line option.\n");
        lock_fprintf(stderr, "%s", BLACK);
        exit(-1);
      }
      max_search_threads_override = scalpel_state.max_search_threads;
      break;

    case 'u':
      scalpel_state.max_validation_threads = strtoul(optarg, NULL, 10);
      if (scalpel_state.max_validation_threads < 1 || scalpel_state.max_validation_threads > 65536) {
        lock_fprintf(stderr, "\nERROR: Invalid # of validation threads for -u command line option.\n");
        lock_fprintf(stderr, "%s", BLACK);
        exit(-1);
      }
      max_validation_threads_override = scalpel_state.max_validation_threads;
      break;

    case 'U':
      if (include_seen) {
        lock_fprintf(stderr, "\nERROR: -U is not compatible with -z.\n");
        lock_fprintf(stderr, "%s", BLACK);
        exit(-1);
      }
      exclude_seen = true;
      parse_filetype_filter_arg(optarg, exclude_filter, "-U");
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
      exit(-1);

    case 'w':
      scalpel_state.write_promising = true;
      cp_restricted = true;
      break;

    case 'x':
      scalpel_state.no_cp_validation = true;
      break;

    case 'z':
      if (exclude_seen) {
        lock_fprintf(stderr, "\nERROR: -z is not compatible with -U.\n");
        lock_fprintf(stderr, "%s", BLACK);
        exit(-1);
      }
      include_seen = true;
      parse_filetype_filter_arg(optarg, include_filter, "-z");
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

  apply_filetype_filter(include_filter, exclude_filter, include_seen, exclude_seen);
  free(include_filter);
  free(exclude_filter);

  lock_fprintf(stderr, "%s", BLACK);
}



static bool read_onnx_config_value(const char *cfg_path, const char *key, char *out, size_t out_sz) {
  FILE *fp;
  char line[1024];
  size_t keylen;

  if (!cfg_path || !key || !out || out_sz == 0) {
    return false;
  }

  fp = fopen(cfg_path, "r");
  if (!fp) {
    return false;
  }

  keylen = strlen(key);
  out[0] = '\0';

  while (fgets(line, sizeof(line), fp)) {
    char *p = line;
    char *val;
    char *end;

    while (*p == ' ' || *p == '\t') {
      p++;
    }

    if (*p == '#' || *p == '\n' || *p == '\0') {
      continue;
    }

    if (strncmp(p, key, keylen) != 0 || p[keylen] != '=') {
      continue;
    }

    val = p + keylen + 1;

    while (*val == ' ' || *val == '\t') {
      val++;
    }

    if (*val == '"') {
      val++;
      end = strchr(val, '"');
      if (!end) {
        fclose(fp);
        return false;
      }
    }
    else {
      end = val;
      while (*end && *end != '\n' && *end != '\r') {
        end++;
      }
    }

    {
      size_t len = (size_t)(end - val);
      if (len >= out_sz) {
        len = out_sz - 1;
      }
      memcpy(out, val, len);
      out[len] = '\0';
    }

    fclose(fp);
    return true;
  }

  fclose(fp);
  return false;
}

static void load_onnx_runtime_config(const char *scalpel3_home, char *accelerator, size_t accelerator_sz) {
  char cfg_path[PATH_MAX];
  char tmp[64];

  if (!accelerator || accelerator_sz == 0) {
    return;
  }

  /* Safe default */
  strncpy(accelerator, "cpu", accelerator_sz - 1);
  accelerator[accelerator_sz - 1] = '\0';

  if (!scalpel3_home || !strlen(scalpel3_home)) {
    return;
  }

  snprintf(cfg_path, sizeof(cfg_path), "%s/.scalpel3_onnx.conf", scalpel3_home);

  if (!read_onnx_config_value(cfg_path, "SCALPEL3_ONNX_ACCELERATOR", tmp, sizeof(tmp))) {
    return;
  }

  if (!strcasecmp(tmp, "cuda")) {
    strncpy(accelerator, "cuda", accelerator_sz - 1);
    accelerator[accelerator_sz - 1] = '\0';
  }
  else {
    strncpy(accelerator, "cpu", accelerator_sz - 1);
    accelerator[accelerator_sz - 1] = '\0';
  }
}



// initialize scalpel state variable and set configuration
void initialize_state(int argc, char *argv[]) {
  char **argvcopy = argv;
  unsigned int i;
  char path[PATH_MAX * 2];
  char *scalpelpath;
  struct stat s;
  FILE *fp;
  unsigned char *exe;

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-result"
  // compute SHA256 of current scalpel3 executable for checkpoint verification
  if (argv[0][0] == '/') {
    scalpelpath = malloc(strlen(argv[0]) + 1);
    check_memory_allocation(scalpelpath, __LINE__, __FILE__, "scalpelpath");
    strcpy(scalpelpath, argv[0]);
  }
  else {
    getcwd(path, PATH_MAX);
    strcat(path, "/");
    strcat(path, argv[0]);
    scalpelpath = realpath(path, NULL);
  }

  if (! scalpelpath || stat(scalpelpath, &s) != 0) {
    handle_error(SCALPEL_ERROR_CHECKPOINT_IMAGE, "Couldn't locate scalpel3 executable to calculate SHA256 hash.\n", __LINE__,
                 __FILE__);
  }
  exe = malloc(s.st_size);
  check_memory_allocation(exe, __LINE__, __FILE__, "exe");
  fp = fopen(scalpelpath, "r");
  if (! fp || fread(exe, s.st_size, 1, fp) != 1) {
    handle_error(SCALPEL_ERROR_CHECKPOINT_IMAGE, "Couldn't read scalpel3 executable to calculate SHA256 hash.\n", __LINE__,
                 __FILE__);
  }
  SHA256(exe, s.st_size, scalpel_state.sha256);
  fclose(fp);
  free(exe);
  free(scalpelpath);
#pragma GCC diagnostic pop

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
  scalpel_state.hf_only = false;
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
  scalpel_state.F1_initiated = false;
  scalpel_state.F2_initiated = false;
  scalpel_state.neon = 0;
  scalpel_state.no_cp_validation = false;
  scalpel_state.audit_file = NULL;

  // default values for output directory coverage blockmap directory
  strncpy(scalpel_state.output_directory, SCALPEL_DEFAULT_OUTPUT_DIR, strlen(SCALPEL_DEFAULT_OUTPUT_DIR) + 1);
  scalpel_state.invocation[0] = 0;

  // copy the invocation string into the state
  do {
    strncat(scalpel_state.invocation, *argvcopy, MAX_STRING_LENGTH - strlen(scalpel_state.invocation));
    strncat(scalpel_state.invocation, " ", MAX_STRING_LENGTH - strlen(scalpel_state.invocation));
    argvcopy++;
  } while (*argvcopy);

  // number of file types must be known before command line args can be processed because of -U
  // option
  while (INITIAL_SEARCH_SPECS[scalpel_state.num_specs].FILETYPE[0]) {
    scalpel_state.num_specs++;
  }

  scalpel_state.search_specs = malloc(sizeof(SearchSpec) * (scalpel_state.num_specs + 1));
  check_memory_allocation(scalpel_state.search_specs, __LINE__, __FILE__, "scalpel_state.search_specs");
  // copy static search specs into scalpel state and initialize fields that aren't specified in
  // scalpelconf.c. The copy is performed so search specs can be modified as needed. Also remember
  // original index in SEARCH_SPECS for each (-U can reorder scalpel_state.search_specs) so function
  // pointers can be initialized during checkpoint restore.
  for (i = 0; i < scalpel_state.num_specs; i++) {
    copy_search_spec(&scalpel_state.search_specs[i], &INITIAL_SEARCH_SPECS[i]);
    scalpel_state.search_specs[i].mastertype = i;
  }
  scalpel_state.search_specs[scalpel_state.num_specs].FILETYPE[0] = 0;

  process_command_line_args(argc, argv);
  argv += optind;

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

  strncpy(scalpel_state.image_pathname, *argv, PATH_MAX / 2 - 1);
  scalpel_state.image_pathname[PATH_MAX / 2 - 1] = 0;
  argv++;
  strncpy(scalpel_state.blockmap_pathname, *argv, PATH_MAX / 2 - 1);
  scalpel_state.blockmap_pathname[PATH_MAX / 2 - 1] = 0;

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
  scalpel_state.max_filemirror_threads = max_filemirror_threads_override ? (int32_t)max_filemirror_threads_override
                                                                         : (num_physical_cores());

  scalpel_state.max_reassembly_threads = max_reassembly_threads_override ? (int32_t)max_reassembly_threads_override
                                                                         : (num_physical_cores());

  scalpel_state.max_search_threads = max_search_threads_override ? (int32_t)max_search_threads_override : (num_physical_cores());

  scalpel_state.max_validation_threads = max_validation_threads_override ? (int32_t)max_validation_threads_override
                                                                         : (num_physical_cores());
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

#if DISABLE_COLOR > 0
  DISABLE_ALL_COLOR;
#endif

  // don't use color for redirected output
  if (! isatty(1) || ! isatty(2)) {
    DISABLE_ALL_COLOR;
  }

  // try to get value of environment variable SCALPEL3_HOME
  scalpel3_home = getenv("SCALPEL3_HOME");

  if (! scalpel3_home || ! strlen(scalpel3_home)) {
    lock_fprintf(stderr, "%s", RED);
    lock_fprintf(stderr, "\nThe SCALPEL3_HOME environment variable MUST be set to the base scalpel3 directory for\n"
                         "scalpel3 to operate correctly. Aborting.\n");
    lock_fprintf(stderr, "%s", BLACK);
    exit(-1);
  }

  // not initiating new checkpoints of any kind
  atomic_init(&TAKE_CHECKPOINT_AND_EXIT, false);
  atomic_init(&TAKE_RECOVERY_CHECKPOINT, false);
  atomic_init(&TAKE_PERIODIC_CHECKPOINT, false);
  atomic_init(&TAKE_PROGRESS_CHECKPOINT, false);
  atomic_init(&REASS_RETURN_TO_IDLE, false);

  // init flags that threads depend on
  atomic_init(&carvelist_initialized, false);   // carvelist is not yet ready
  atomic_init(&promising_initialized, false);   // promising queue is not yet ready
  atomic_init(&kill_queue_initialized, false);  // kill queue is not yet ready

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


    // Set up the ONNX runtime once and allow block validation threads to reuse
  {
    char model_path[PATH_MAX];
    char onnx_accel[32];

    snprintf(model_path, sizeof(model_path), "%s/src/exe_vision/unix/elf_unet.onnx", scalpel3_home);
    load_onnx_runtime_config(scalpel3_home, onnx_accel, sizeof(onnx_accel));

    if (! elf_onnx_global_init(model_path, onnx_accel)) {
      char errmsg[PATH_MAX + 128];
      snprintf(errmsg, sizeof(errmsg),
               "Failed to initialize ELF ONNX model (elf_unet.onnx) with accelerator '%s'.",
               onnx_accel);
      handle_error(SCALPEL_GENERAL_ABORT, errmsg, __LINE__, __FILE__);
    }

    if (scalpel_state.mode_verbose) {
      lock_fprintf(stdout, "Initialized ELF ONNX model: %s\n", model_path);
      lock_fprintf(stdout, "Requested ONNX accelerator: %s\n", onnx_accel);
    }

    scalpel_log("Requested ONNX accelerator: %s\n", onnx_accel);
  }

  lock_fprintf(stdout, "Initialized scalpel state.\n");

  scalpel_log("Block reservation system is %s.\n", scalpel_state.reservations ? "ON" : "OFF");

  // set up the output directory, which will contain carved files
  lock_fprintf(stdout, "Setting up output directory.\n");
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
  total_wait = (endtime.tv_sec - starttime.tv_sec) * 1e9 + (endtime.tv_nsec - starttime.tv_nsec);

#if VALIDATOR_PERFORMANCE_STATS > 0
  if (! scalpel_state.no_defrag && ! scalpel_state.hf_only) {
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
  if (! scalpel_state.no_defrag && ! scalpel_state.hf_only) {
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

  if (! atomic_load_explicit(&TAKE_CHECKPOINT_AND_EXIT, memory_order_acquire)) {
    // on successful non-checkpointing exit, checkpointing data (excluding the blockmap, which is
    // never deleted explicitly) is removed, since modifications made to the blockmap and other
    // critical state mean that the checkpoint is invalid anyway.
    remove_checkpoint();
  }

  // tear down ONNX Runtime
  elf_onnx_global_shutdown();

  time(&now);
  strcpy(nows, ctime(&now));
  nows[strlen(nows) - 1] = 0;

  if (! atomic_load_explicit(&TAKE_CHECKPOINT_AND_EXIT, memory_order_acquire)) {
    lock_fprintf(stdout, "%s", BLUE);
    scalpel_log("scalpel3 completed execution on %s.\n", nows);
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

