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
// ----------------------------
// Additional Integration Terms
// ----------------------------
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
// scalpel3 fragmented disk image creator, v2. This version substantially increases the number of
// options available, to facilitate creating more realistic fragmentation scenarios. The original
// version has incompatible options and configuration, but is available as fragmentator-legacy. This
// one's better. :)
//
// Design by Golden G. Richard III and Karley Waguespack, 2024-6.
//
// Written by Golden G. Richard III (@nolaforensix), 2024-6.
//
// All options are now specified in a configuration file, which precisely defines the creation of a
// fragmented image. The preferred extension is ".frg". Please refer to the file "template.frg" to
// understand available options. This file should be used a template for new fragmentation
// configuration files.
//
// TODO:
//
// o Insert full or partial filesystem metadata, e.g., for ext4, ExFAT, or similar to create
// mountable images
//

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>
#define SCALPEL3_EXTERNAL
#include "colors.h"
#include "longsset.h"
#include "scalpel.h"
#include "scalpelv.h"

// static configuration
#define MAX_LINE_LENGTH 2048
#define MAX_FRAGMENTATOR_BLOCK_SIZE INT64_C(1073741824)

#define FRAGMENTATOR_BANNER_STRING                                                                                                 \
  "fragmentator v%s -- "                                                                                                           \
  "Written by Golden G. Richard III (@nolaforensix).",                                                                             \
      SCALPEL_VERSION

// preference for filling GAP, MISSING, and OUTOFORDER holes in a fragmented file
typedef enum FillHolesPref {
  FILLHOLES_UNKNOWN = -1,
  FILLHOLES_FILE,
  FILLHOLES_RANDOM,
  FILLHOLES_ZERO,
  FILLHOLES_COUNT  // always last: number of keywords
} FillHolesPref;

const char *fillholes_keywords[FILLHOLES_COUNT] = {"FILE", "RANDOM", "ZERO"};

// defines type of one block in a cluster
typedef enum ClusterBlockType {
  CLUSTER_BLOCK_UNKNOWN = -1,
  CLUSTER_BLOCK_HEADER,
  CLUSTER_BLOCK_FILE,
  CLUSTER_BLOCK_RANDOM,
  CLUSTER_BLOCK_ZERO,
  CLUSTER_BLOCK_NEEDSFILL
} ClusterBlockType;

// defines one block in a cluster
typedef struct ClusterBlock {
  ClusterBlockType type;  // type of this block
  char *fn;               // associated filename of FILE: definition
                          // if CLUSTER_BLOCK_FILE or CLUSTER_BLOCK_NEEDSFILL
  int64_t blocknum;       // blocknum in file if CLUSTER_FILE
} ClusterBlock;

typedef struct Cluster {
  bool coalesced;         // has this cluster been coalesced into another cluster?
  ClusterBlock *blocks;   // array of blocks that makes up cluster
  int64_t numblocks;      // total number of blocks, including fill blocks
  bool needs_fill;        // true if the cluster contains any CLUSTER_BLOCK_NEEDSFILL blocks
  int64_t seq;            // creation-order sequence; stable tie-break for sorting
} Cluster;

// defines one FILE: in configuration file
typedef struct File {
  char *fn;              // pathname
  int64_t length;        // actual length of file
  int64_t numblocks;     // number of blocks in file
  LongsSet *missing;     // these blocks are omitted entirely
  LongsSet *outoforder;  // non-file blocks are substituted for these blocks
  LongsSet *gap;         // gaps are introduced into the layout
                         // of an otherwise non-fragmented file by inserting other blocks at these
                         // "gap" block locations
  LongsSet *duplicate;   // these blocks are duplicated elsewhere in the image
  bool fragmented;       // file layout is automatically fragmented?
} File;

// legal keywords in configuration file
typedef enum KeywordType {
  KEYWORD_UNKNOWN = -1,
  KEYWORD_OUTPUTFILE,           // string argument
  KEYWORD_SEED,                 // numeric argument
  KEYWORD_BLOCKSIZE,            // numeric argument
  KEYWORD_HEADERBLOCKS,         // numeric argument
  KEYWORD_ZEROPADBLOCKS,        // numeric argument
  KEYWORD_RANDOMPADBLOCKS,      // numeric argument
  KEYWORD_INITIALRANDOMBLOCKS,  // numeric argument
  KEYWORD_INITIALZEROBLOCKS,    // numeric argument
  KEYWORD_RANDOMBLOCKS,         // numeric argument
  KEYWORD_ZEROBLOCKS,           // numeric argument
  KEYWORD_FILE,                 // string argument
  KEYWORD_MISSING,              // comma separated numeric and ranges
  KEYWORD_OUTOFORDER,           // comma separated numeric and ranges
  KEYWORD_GAP,                  // comma separated numeric and ranges
  KEYWORD_DUPLICATE,            // comma separated numeric and ranges
  KEYWORD_FRAGMENTED,           // 0 / 1 or TRUE / FALSE argument
  KEYWORD_FILLHOLESPRIMARY,     // FILE, RANDOM, or ZERO string argument
  KEYWORD_FILLHOLESSECONDARY,   // FILE, RANDOM, or ZERO string argument
  KEYWORD_COUNT                 // always last: number of keywords
} KeywordType;

const char *keywords[KEYWORD_COUNT] = {"OUTPUTFILE:",
                                       "SEED:",
                                       "BLOCKSIZE:",
                                       "HEADERBLOCKS:",
                                       "ZEROPADBLOCKS:",
                                       "RANDOMPADBLOCKS:",
                                       "INITIALRANDOMBLOCKS:",
                                       "INITIALZEROBLOCKS:",
                                       "RANDOMBLOCKS:",
                                       "ZEROBLOCKS:",
                                       "FILE:",
                                       "MISSING:",
                                       "OUTOFORDER:",
                                       "GAP:",
                                       "DUPLICATE:",
                                       "FRAGMENTED:",
                                       "FILLHOLESPRIMARY:",
                                       "FILLHOLESSECONDARY:"};

// keyword and argument for one line in configuration file
typedef struct ParsedLine {
  KeywordType type;
  char argument[MAX_LINE_LENGTH + 1];

} ParsedLine;

//
// GLOBALS
//
int64_t LINENUMBER = 0;             // used for error reporting
int64_t FILENUM = 0;                // current index into FILES array
int64_t MAXFILES = 0;               // current capacity of FILES array
int64_t TOTALBLOCKS = 0;            // total blocks in all clusters
File *FILES = NULL;                 // all files that contribute to image
int64_t CLUSTERNUM = -1;            // current index into CLUSTERS array
int64_t MAXCLUSTERS = 0;            // current capacity of CLUSTERS array
Cluster *CLUSTERS = NULL;           // all clusters of blocks that contribute to image
size_t longest_input_pathname = 6;  // longest length for FILE: argument seen

// global config file options, initialized in main()
char OUTPUTFILE[MAX_LINE_LENGTH + 1];  // value for OUTPUTFILE: in config
int64_t SEED;                          // value for SEED: in config
int32_t BLOCKSIZE;                     // value for BLOCKSIZE: in config
int64_t HEADERBLOCKS;                  // value for HEADERBLOCKS: in config
int64_t ZEROPADBLOCKS;                 // value for ZEROPADBLOCKS: in config
int64_t RANDOMPADBLOCKS;               // value for RANDOMPADBLOCKS: in config
int64_t INITIALRANDOMBLOCKS;           // value for INITIALRANDOMBLOCKS: in config
int64_t INITIALZEROBLOCKS;             // value for INITIALZEROBLOCKS: in config
int64_t RANDOMBLOCKS;                  // value for RANDOMBLOCKS: in config
int64_t ZEROBLOCKS;                    // value for ZEROBLOCKS: in config
int64_t FILLHOLESPRIMARY;              // value for FILLHOLESPRIMARY: in config
int64_t FILLHOLESSECONDARY;            // value for FILLHOLESSECONDARY: in config

// command line overrides for global config file options, initialized in main()
char cmd_OUTPUTFILE[MAX_LINE_LENGTH + 1];  // cmd line override for OUTPUTFILE:
int64_t cmd_SEED;                          // cmd line override for SEED:
int32_t cmd_BLOCKSIZE;                     // cmd line override for BLOCKSIZE:
int64_t cmd_HEADERBLOCKS;                  // cmd line override for HEADERBLOCKS:
int64_t cmd_ZEROPADBLOCKS;                 // cmd line override for ZEROPADBLOCKS:
int64_t cmd_RANDOMPADBLOCKS;               // cmd line override for RANDOMPADBLOCKS:
int64_t cmd_INITIALRANDOMBLOCKS;           // cmd line override for RANDOMBLOCKS:
int64_t cmd_INITIALZEROBLOCKS;             // cmd line override for ZEROBLOCKS:
int64_t cmd_RANDOMBLOCKS;                  // cmd line override for RANDOMBLOCKS:
int64_t cmd_ZEROBLOCKS;                    // cmd line override for ZEROBLOCKS:
int64_t cmd_FILLHOLESPRIMARY;              // cmd line override for FILLHOLESPRIMARY:
int64_t cmd_FILLHOLESSECONDARY;            // cmd line override for FILLHOLESSECONDARY:

// other command line options
int DEBUG = 0;            // verbose output during image generation
bool no_frag = false;     // if true, strip all fragmentation directives and generate a contiguous
                          // disk image

// function prototypes
static bool parse_bounded_int64(const char *value, int64_t minimum,
                                int64_t maximum, int64_t *parsed);
static bool is_boolean(char *str, bool *val);
static char *trim_whitespace(char *str);
static void strip_line_comment(char *input);
static int compare_clusters(const void *a, const void *b);
static bool parse_argument(char *arg_start, char *argument);
static void parse_line(char *input, ParsedLine *result);
static void parse_input(char *pathname);
static LongsSet *process_int_or_intset_or_range(char *args, int64_t maximum);
static void check_File_definition(File f);
static void init_new_cluster(ClusterBlock *blocks, int64_t numblocks, bool needs_fill);
static bool read_file_block(char *fn, int64_t block, char *data);
static void create_clusters(void);
static void print_cluster(Cluster c, int64_t num, FILE *fp, int64_t *imgblocknum);
static void display_all_clusters(void);
static bool generate_output(FILE *out, FILE *outlog);
static void fragmentator_logo(void);
static void process_command_line_args(int argc, char *argv[]);
static void usage(void);
static void print_config_summary(FILE *fp);

static void usage(void) {

  fprintf(stderr, "%s", BLUE);
  fprintf(stderr, "Fragmentator generates synthetic disk images for testing data carving tools, based on instructions\n"
                  "in a config file. See template.frg for full details.  Global options in the config file can be\n"
                  "overridden on the command line, but care must be taken to ensure that the options are consistent.\n"
                  "For example, RANDOMPAD and ZEROPAD are mutually exclusive options. Setting RANDOMPAD > 0 in the config\n"
                  "file and then specifying ZEROPAD > 0 on the command line will generate an error. This particular situation\n"
                  "can be corrected by specifying values for both RANDOMPAD (=0) and ZEROPAD (>0) on the command line, to fully\n"
                  " override these values in the config file.  In general, use of the command line overrides is most appropriate for\n"
                  "scripting and testing purposes--it's generally easier and less error prone to simply generate appropriate\n"
                  "stand-alone config files for fragmentator.\n"
                  "Numeric arguments must contain unsigned base-10 digits only.\n\n"

                  "Usage: fragmentator [-a initialrandomblocks] [-b initialzeroblocks] [-f ZERO | RANDOM | FILE]\n"
                  "                    [-F ZERO | RANDOM] [-h]  [-H headerblocks] [-o outputfile] [-q blocksize]\n"
                  "                    [-r randompadblocks] [-R randomblocks] [-s seed] [-v] [-z zeropadblocks]\n"
                  "                    [-Z zeroblocks] configfile\n\n"

                  "Options:\n"
                  "-a Override INITIALRANDOMBLOCKS in the template.\n"
                  "-b Override INITIALZEROBLOCKS in the template.\n"
                  "-c Ignore ALL fragmentation directives in FILE: entries. Generate a fully contiguous image file.\n"
                  "-f Override FILLHOLESPRIMARY in the template.\n"
                  "-F Override FILLHOLESSECONDARY in the template.\n"
                  "-h Display this usage menu.\n"
                  "-H Override HEADERBLOCKS in the template.\n"
                  "-o Override OUTPUTFILE setting in the template.\n"
                  "-r Override RANDOMPADBLOCKS in the template.\n"
                  "-R Override RANDOMBLOCKS in the template.\n"
                  "-s Override random SEED in the template.\n"
                  "-q Override BLOCKSIZE in the template.\n"
                  "-z Override ZEROPADBLOCKS in the template.\n"
                  "-Z Override ZEROBLOCKS in the template.\n"
                  "-v Display global configuration. Specifying -v once outputs basic summary information. Specifying\n"
                  "   -v twice outputs FILE configs.  A third -v displays extensive debugging output.\n\n");
  fprintf(stderr, "%s", BLACK);
}


static void print_config_summary(FILE *fp) {

  fprintf(fp, "Configuration:\n");
  fprintf(fp, "no_frag:             %s\n", no_frag ? "TRUE" : "FALSE");
  fprintf(fp, "# FILES:             %7" PRIu64 "\n", FILENUM + 1);
  fprintf(fp, "BLOCKSIZE:           %7d\n", BLOCKSIZE);
  fprintf(fp, "SEED:                %7" PRId64 "\n", SEED);
  fprintf(fp, "HEADERBLOCKS:        %7" PRId64 "\n", HEADERBLOCKS);
  fprintf(fp, "ZEROPADBLOCKS:       %7" PRId64 "\n", ZEROPADBLOCKS);
  fprintf(fp, "RANDOMPADBLOCKS:     %7" PRId64 "\n", RANDOMPADBLOCKS);
  fprintf(fp, "INITIALZEROBLOCKS:   %7" PRId64 "\n", INITIALZEROBLOCKS);
  fprintf(fp, "INITIALRANDOMBLOCKS: %7" PRId64 "\n", INITIALRANDOMBLOCKS);
  fprintf(fp, "ZEROBLOCKS:          %7" PRId64 "\n", ZEROBLOCKS);
  fprintf(fp, "RANDOMBLOCKS:        %7" PRId64 "\n", RANDOMBLOCKS);
  fprintf(fp, "FILLHOLESPRIMARY:          %s\n",
          FILLHOLESPRIMARY == FILLHOLES_ZERO     ? "ZERO"
          : FILLHOLESPRIMARY == FILLHOLES_RANDOM ? "RANDOM"
            : "FILE");
  fprintf(fp, "FILLHOLESSECONDARY:        %s\n", FILLHOLESSECONDARY == FILLHOLES_ZERO ? "ZERO" : "RANDOM");

}


// parse command line arguments, which largely allow overriding global .frg options
static void process_command_line_args(int argc, char *argv[]) {

  int i;
  int64_t parsed;
  bool match;

  fprintf(stderr, "%s", RED);
  while ((i = getopt(argc, argv, "+a:b:co:s:q:H:z:r:R:Z:f:F:vh")) != -1) {
    switch (i) {

    case 'a':
      // random blocks override
      if (! parse_bounded_int64(optarg, 0, INT64_MAX, &parsed)) {
        fprintf(stderr, "Fatal error for -a option: Argument must be an integer >= 0.\n");
        fprintf(stderr, "%s", BLACK);
        // fatal
        exit(-1);
      }
      cmd_INITIALRANDOMBLOCKS = parsed;
      break;

    case 'b':
      // random blocks override
      if (! parse_bounded_int64(optarg, 0, INT64_MAX, &parsed)) {
        fprintf(stderr, "Fatal error for -b option: Argument must be an integer >= 0.\n");
        fprintf(stderr, "%s", BLACK);
        // fatal
        exit(-1);
      }
      cmd_INITIALZEROBLOCKS = parsed;
      break;

     case 'c':
     // strip all fragmentation directives from FILE: entries
     no_frag = true;
     break;

    case 'f':
      // fill holes primary override
      match = false;
      for (i = 0; i < FILLHOLES_COUNT && ! match; i++) {
        if (! strncasecmp(optarg, fillholes_keywords[i], strlen(optarg))) {
          match = true;
          cmd_FILLHOLESPRIMARY = i;
        }
      }

      if (! match) {
        fprintf(stderr, "Fatal error for -f option: Argument must be FILE, RANDOM, or ZERO.\n");
        fprintf(stderr, "%s", BLACK);
        // fatal
        exit(-1);
      }
      break;

    case 'F':
      // fill holes secondary override
      match = false;
      for (i = 0; i < FILLHOLES_COUNT && ! match; i++) {
        if (! strncasecmp(optarg, fillholes_keywords[i], strlen(optarg))) {
          match = true;
          cmd_FILLHOLESSECONDARY = i;
        }
      }

      if (! match || cmd_FILLHOLESSECONDARY == FILLHOLES_FILE) {
        fprintf(stderr, "Fatal error for -F option: Argument must be RANDOM or ZERO.\n");
        fprintf(stderr, "%s", BLACK);
        // fatal
        exit(-1);
      }
      break;

    case 'h':
      usage();
      fprintf(stderr, "%s", BLACK);
      exit(0);

    case 'H':
      // header blocks override
      if (! parse_bounded_int64(optarg, 0, INT64_MAX, &parsed)) {
        fprintf(stderr, "Fatal error for -H option: Argument must be an integer >= 0.\n");
        fprintf(stderr, "%s", BLACK);
        // fatal
        exit(-1);
      }
      cmd_HEADERBLOCKS = parsed;
      break;

    case 'o':
      if (strlen(optarg) > 4 && ! strncasecmp(optarg + strlen(optarg) - 4, ".frg", 4)) {
        fprintf(stderr, "Fatal error for -o option: fragmentator will not generate image files that end in \".frg\",\n"
                        "as that's almost certainly not what you want.\n");
        fprintf(stderr, "%s", BLACK);
        // fatal
        exit(-1);
      }
      strcpy(cmd_OUTPUTFILE, optarg);
      break;

    case 'q':
      // blocksize override
      if (! parse_bounded_int64(optarg, 512, MAX_FRAGMENTATOR_BLOCK_SIZE, &parsed) || parsed % 512) {
        fprintf(stderr,
                "Fatal error for -q option: Argument must be an integer from 512 through %" PRId64
                " and divisible by 512.\n",
                MAX_FRAGMENTATOR_BLOCK_SIZE);
        fprintf(stderr, "%s", BLACK);
        // fatal
        exit(-1);
      }
      cmd_BLOCKSIZE = (int32_t)parsed;
      break;

    case 'r':
      // random pad blocks override
      if (! parse_bounded_int64(optarg, 0, INT64_MAX, &parsed)) {
        fprintf(stderr, "Fatal error for -r option: Argument must be an integer >= 0.\n");
        fprintf(stderr, "%s", BLACK);
        // fatal
        exit(-1);
      }
      cmd_RANDOMPADBLOCKS = parsed;
      break;

    case 'R':
      // random blocks override
      if (! parse_bounded_int64(optarg, 0, INT64_MAX, &parsed)) {
        fprintf(stderr, "Fatal error for -R option: Argument must be an integer >= 0.\n");
        fprintf(stderr, "%s", BLACK);
        // fatal
        exit(-1);
      }
      cmd_RANDOMBLOCKS = parsed;
      break;

    case 's':
      // random seed override
      if (! parse_bounded_int64(optarg, 0, INT64_MAX, &parsed)) {
        fprintf(stderr, "Fatal error for -s option: Argument must be an integer >= 0.\n");
        fprintf(stderr, "%s", BLACK);
        // fatal
        exit(-1);
      }
      cmd_SEED = parsed;
      break;

    case 'v':
      DEBUG++;
      break;

    case 'z':
      // zero pad blocks override
      if (! parse_bounded_int64(optarg, 0, INT64_MAX, &parsed)) {
        fprintf(stderr, "Fatal error for -z option: Argument must be an integer >= 0.\n");
        fprintf(stderr, "%s", BLACK);
        // fatal
        exit(-1);
      }
      cmd_ZEROPADBLOCKS = parsed;
      break;

    case 'Z':
      // zero blocks override
      if (! parse_bounded_int64(optarg, 0, INT64_MAX, &parsed)) {
        fprintf(stderr, "Fatal error for -Z option: Argument must be an integer >= 0.\n");
        fprintf(stderr, "%s", BLACK);
        // fatal
        exit(-1);
      }
      cmd_ZEROBLOCKS = parsed;
      break;

    default:
      fprintf(stderr, "%s", BLACK);
      exit(-1);
    }
  }

  fprintf(stderr, "%s", BLACK);
}


static void fragmentator_logo(void) {

  char *logo[] = {"\n",
                  "\n",
                  " ..........................................................................................\n",
                  ".  ______ ______   ___   _____ ___  ___ _____  _   _  _____   ___   _____  _____ ______    .\n",
                  ".  |  ___|| ___ \\ / _ \\ |  __ \\|  \\/  ||  ___|| \\ | ||_   _| / _ \\ |_   _||  _  || ___ \\   .\n",
                  ".  | |_   | |_/ // /_\\ \\| |  \\/| .  . || |__  |  \\| |  | |  / /_\\ \\  | |  | | | || |_/ /   .\n",
                  ".  |  _|  |    / |  _  || | __ | |\\/| ||  __| | . ` |  | |  |  _  |  | |  | | | ||    /    .\n",
                  ".  | |    | |\\ \\ | | | || |_\\ \\| |  | || |___ | |\\  |  | |  | | | |  | |  \\ \\_/ /| |\\ \\    .\n",
                  ".  \\_|    \\_| \\_|\\_| |_/ \\____/\\_|  |_/\\____/ \\_| \\_/  \\_/  \\_| |_/  \\_/   \\___/ \\_| \\_|   .\n",
                  " ..........................................................................................\n",
                  ""};

  int i = 0;
  size_t j;
  size_t len;

  // only display logo if the terminal is wide enough
  if (get_terminal_width() < 92) {
    return;
  }

  while (logo[i][0]) {
    len = strlen(logo[i]);
    for (j = 0; j < len; j++) {
      if (isspace(logo[i][j]) || i < 3 || i > 8 || j < 2 || j > 90) {
        fprintf(stdout, "%s", BLACK);
      }
      else {
        fprintf(stdout, "%s%s", BOLD, LOGOP);
      }

      fputc(logo[i][j], stdout);
      fprintf(stdout, "%s", BLACK);
    }
    i++;
  }
  fputc('\n', stdout);
}


// Cluster comparison function for qsort(). Total order: primary key is numblocks
// (ascending), secondary key is the creation-order seq. The seq tie-break makes
// equal-size clusters sort identically regardless of the libc qsort implementation,
// so the same recipe and seed produce a byte-identical image on any platform.
//
static int compare_clusters(const void *a, const void *b) {
  const Cluster *ca = (const Cluster *)a;
  const Cluster *cb = (const Cluster *)b;

  if (ca->numblocks != cb->numblocks) {
    return (ca->numblocks > cb->numblocks) - (ca->numblocks < cb->numblocks);
  }
  return (ca->seq > cb->seq) - (ca->seq < cb->seq);
}

// parse a digits-only integer and require it to fit within the supplied bounds
static bool parse_bounded_int64(const char *value, int64_t minimum,
                                int64_t maximum, int64_t *parsed) {

  char *end = NULL;
  unsigned long long converted;

  if (! value || ! parsed || minimum < 0 || maximum < minimum
      || value[0] < '0' || value[0] > '9') {
    return false;
  }

  errno = 0;
  converted = strtoull(value, &end, 10);
  if (errno == ERANGE || ! end || *end != '\0'
      || converted < (uint64_t)minimum || converted > (uint64_t)maximum) {
    return false;
  }

  *parsed = (int64_t)converted;
  return true;
}


// check if a string contains a boolean value (0 / 1 / true / false) and set 'val' argument if so
static bool is_boolean(char *str, bool *val) {

  *val = false;

  if (! strcasecmp(str, "true") || ! strcmp(str, "1")) {
    *val = true;
    return true;
  }
  else if (! strcasecmp(str, "false") || ! strcmp(str, "0")) {
    return true;
  }
  else {
    return false;
  }
}


// trim leading and trailing whitepace from 'str'
static char *trim_whitespace(char *str) {

  char *end;

  while (isspace((unsigned char)*str)) {
    str++;
  }

  if (*str == 0) {
    return str;
  }

  end = str + strlen(str) - 1;

  while (end > str && isspace((unsigned char)*end)) {
    end--;
  };

  *(end + 1) = 0;

  return str;
}


// strip an inline comment while preserving hash characters inside quoted arguments
static void strip_line_comment(char *input) {

  bool in_quotes = false;

  while (*input) {
    if (*input == '"') {
      in_quotes = ! in_quotes;
    }
    else if (*input == '#' && ! in_quotes) {
      *input = 0;
      return;
    }
    input++;
  }
}


// parse argument for keywords that allow integers or integer ranges as arguments. A set of longs is
// returned that contains all ranges expanded. Duplicates are *not* removed by this function.
static LongsSet *process_int_or_intset_or_range(char *args, int64_t maximum) {

  char *token = strtok(args, ", ");
  LongsSet *set;

  create_LongsSet(&set);

  while (token) {
    token = trim_whitespace(token);
    char *dash = strchr(token, '-');
    if (dash) {
      int64_t start = 0;
      int64_t end = 0;

      *dash = '\0';
      bool valid = ! strchr(dash + 1, '-')
                   && parse_bounded_int64(token, 0, maximum, &start)
                   && parse_bounded_int64(dash + 1, 0, maximum, &end)
                   && start <= end;
      *dash = '-';

      if (! valid) {
        fprintf(stderr, "%s", RED);
        fprintf(stderr, "Fatal error: Invalid range '%s'. Start and end must be fully numeric and\n", token);
        fprintf(stderr, "between 0 and %" PRId64 " on line %" PRId64 ".\n", maximum, LINENUMBER);
        fprintf(stderr, "%s", BLACK);
        // fatal
        exit(-1);
      }

      add_to_LongsSet(set, start, end);
    }
    else {
      int64_t value;

      if (! parse_bounded_int64(token, 0, maximum, &value)) {
        fprintf(stderr, "%s", RED);
        fprintf(stderr, "Fatal error: Invalid number '%s'. It must be fully numeric and between\n", token);
        fprintf(stderr, "0 and %" PRId64 " on line %" PRId64 ".\n", maximum, LINENUMBER);
        fprintf(stderr, "%s", BLACK);
        // fatal
        exit(-1);
      }

      add_to_LongsSet(set, value, value);
    }
    token = strtok(NULL, ", ");
  }

  return set;
}


// parse argument for one line of input from config file
static bool parse_argument(char *arg_start, char *argument) {

  arg_start = trim_whitespace(arg_start);

  if (*arg_start == '"') {
    arg_start++;
    const char *arg_end = strchr(arg_start, '"');

    if (! arg_end) {
      return false;
    }
    size_t arg_len = arg_end - arg_start;

    strncpy(argument, arg_start, arg_len);
    argument[arg_len] = 0;
  }
  else {
    size_t i = 0;

    while (arg_start[i] && arg_start[i] != '\n' && i < MAX_LINE_LENGTH) {
      argument[i] = arg_start[i];
      i++;
    }
    argument[i] = 0;
  }

  return true;
}


// parse one line of config file, separating command and argument
static void parse_line(char *input, ParsedLine *result) {

  result->type = KEYWORD_UNKNOWN;
  result->argument[0] = 0;
  input = trim_whitespace(input);
  for (int32_t i = 0; i < KEYWORD_COUNT; i++) {
    const char *key = keywords[i];
    size_t keylen = strlen(key);

    if (! strncasecmp(input, key, keylen)) {
      if (parse_argument(input + keylen, result->argument) && result->argument[0]) {
        result->type = (KeywordType)i;
        return;
      }
      else {
        // something wrong with the argument
        if (! result->argument[0]) {
          fprintf(stderr, "%s", RED);
          fprintf(stderr, "\nFatal error: Missing argument on line %" PRId64 ".\n", LINENUMBER);
          fprintf(stderr, "%s", BLACK);
        }
        // fatal
        exit(-1);
      }
    }
  }

  fprintf(stderr, "%s", RED);
  fprintf(stderr, "\nFatal error: Unrecognized configuration option on line %" PRId64 ".\n", LINENUMBER);
  fprintf(stderr, "%s", BLACK);
  // fatal
  exit(-1);
}


// check FILE: definition for inconsistencies. If DEBUG > 0, output info associated with FILE:
// definition. If the File structure fails validation checks, a fatal error is issued and execution
// is terminated. This function also updates the global 'longest_input_pathname'.
static void check_File_definition(File file) {

  int64_t common;

  if (DEBUG > 1) {
    fprintf(stdout, "\nFILE: definition \"%s\":\n", file.fn);
    fprintf(stdout, "length = %" PRId64 "\n", file.length);
    fprintf(stdout, "numblocks = %" PRId64 "\n", file.numblocks);
    fprintf(stdout, "FRAGMENTED: %s\n", file.fragmented ? "TRUE" : "FALSE");
    fprintf(stdout, "MISSING: ");
    display_LongsSet(file.missing);
    fprintf(stdout, "\n");
    fprintf(stdout, "OUTOFORDER: ");
    display_LongsSet(file.outoforder);
    fprintf(stdout, "\n");
    fprintf(stdout, "GAP: ");
    display_LongsSet(file.gap);
    fprintf(stdout, "\n");
    fprintf(stdout, "DUPLICATE: ");
    display_LongsSet(file.duplicate);
    fprintf(stdout, "\n");
  }

  // be sure use of GAP, OUTOFORDER, MISSING, et al are consistent with the size of the file, with
  // each other, and with HEADERBLOCKS value

  if (file.missing && file.missing->set[file.missing->len - 1] > file.numblocks - 1) {
    fprintf(stderr, "%s", RED);
    fprintf(stderr, "\nFatal error: MISSING block number %" PRId64 " exceeds file size for \"%s\".\n",
            file.missing->set[file.missing->len - 1], file.fn);
    fprintf(stderr, "%s", BLACK);
    // fatal
    exit(-1);
  }
  else if (file.outoforder && file.outoforder->set[file.outoforder->len - 1] > file.numblocks - 1) {
    fprintf(stderr, "%s", RED);
    fprintf(stderr, "\nFatal error: OUTOFORDER block number %" PRId64 " exceeds file size for \"%s\".\n",
            file.outoforder->set[file.outoforder->len - 1], file.fn);
    fprintf(stderr, "%s", BLACK);
    // fatal
    exit(-1);
  }
  else if (file.gap && file.gap->set[file.gap->len - 1] >= file.numblocks - 1) {
    fprintf(stderr, "%s", RED);
    fprintf(stderr, "\nFatal error: GAP block number %" PRId64 " exceeds file size for \"%s\".\n", file.gap->set[file.gap->len - 1],
            file.fn);
    fprintf(stderr, "%s", BLACK);
    // fatal
    exit(-1);
  }
  else if (file.duplicate && file.duplicate->set[file.duplicate->len - 1] > file.numblocks - 1) {
    fprintf(stderr, "%s", RED);
    fprintf(stderr, "\nFatal error: DUPLICATE block number %" PRId64 " exceeds file size for \"%s\".\n",
            file.duplicate->set[file.duplicate->len - 1], file.fn);
    fprintf(stderr, "%s", BLACK);
    // fatal
    exit(-1);
  }
  else if (file.missing && file.outoforder && any_intersection_LongsSets(file.missing, file.outoforder, &common)) {
    fprintf(stderr, "%s", RED);
    fprintf(stderr, "\nFatal error: block number %" PRId64 " is in both MISSING and OUTOFORDER sets for \"%s\".\n", common,
            file.fn);
    fprintf(stderr, "%s", BLACK);
    // fatal
    exit(-1);
  }
  else if (HEADERBLOCKS > 0 && file.missing && file.missing->set[0] < (int64_t)HEADERBLOCKS) {
    fprintf(stderr, "%s", RED);
    fprintf(stderr, "\nFatal error: MISSING block number %" PRId64 " is less than HEADERBLOCKS value for \"%s\".\n",
            file.missing->set[0], file.fn);
    fprintf(stderr, "%s", BLACK);
    // fatal
    exit(-1);
  }
  else if (HEADERBLOCKS > 0 && file.outoforder && file.outoforder->set[0] < (int64_t)HEADERBLOCKS) {
    fprintf(stderr, "%s", RED);
    fprintf(stderr, "\nFatal error: OUTOFORDER block number %" PRId64 " is less than HEADERBLOCKS value for \"%s\".\n",
            file.outoforder->set[0], file.fn);
    fprintf(stderr, "%s", BLACK);
    // fatal
    exit(-1);
  }
  else if (HEADERBLOCKS && file.gap && file.gap->set[0] < (int64_t)HEADERBLOCKS) {
    fprintf(stderr, "%s", RED);
    fprintf(stderr, "\nFatal error: GAP block number %" PRId64 " is less than HEADERBLOCKS value for \"%s\".\n", file.gap->set[0],
            file.fn);
    fprintf(stderr, "%s", BLACK);
    // fatal
    exit(-1);
  }
  else if (file.fragmented && (file.gap || file.outoforder || file.missing)) {
    fprintf(stderr, "%s", RED);
    fprintf(stderr,
            "\nFatal error: FRAGMENTED may not be TRUE if GAP, OUTOFORDER, or MISSING\n"
            "is specified for file \"%s\".\n",
            file.fn);
    fprintf(stderr, "%s", BLACK);
    // fatal
    exit(-1);
  }

  // capture longest pathname for nicer formatting
  if (strlen(file.fn) > longest_input_pathname) {
    longest_input_pathname = strlen(file.fn);
  }
}


// parse entire config file and build configuration for generating image file
static void parse_input(char *pathname) {

  ParsedLine parsed;
  char input_line[MAX_LINE_LENGTH + 1];
  char *input;
  FILE *fp;
  bool file_seen = false;
  int multiline_comment = 0;
  LongsSet *setarg;
  int i;
  int64_t parsed_number;
  bool stop = false;
  off_t len;
  int perc1, perc2;

  fp = fopen(pathname, "r");
  if (! fp) {
    fprintf(stderr, "%s", RED);
    fprintf(stderr, "\nFatal error: Can't open configuration file \"%s\".\n", pathname);
    fprintf(stderr, "%s", BLACK);
    // fatal
    exit(-1);
  }

  fseek(fp, 0, SEEK_END);
  len = ftello(fp);
  fseek(fp, 0, SEEK_SET);

  perc1 = 0;
  perc2 = 0;

  while (! stop && fgets(input_line, MAX_LINE_LENGTH, fp)) {
    perc2 = (int)((double)ftello(fp) / (double)len * (double)100);
    if (DEBUG <= 2 && perc1 != perc2 && isatty(1)) {
      perc1 = perc2;
      fprintf(stdout, "\b\b\b\b%3d%%", perc1);
      fflush(stdout);
    }

    LINENUMBER++;

    // check for truncation
    if (strlen(input_line) == MAX_LINE_LENGTH) {
      fprintf(stderr, "%s", RED);
      fprintf(stderr,
              "\nFatal error: Line %" PRId64 " exceeds maximum line length.\n"
              "Break up the input line to continue.\n",
              LINENUMBER);
      fprintf(stderr, "%s", BLACK);
      // fatal
      exit(-1);
    }

    // strip leading and trailing whitespace and comments
    input = trim_whitespace(input_line);
    strip_line_comment(input);

    if (! input[0]) {
      // comment line, just skip
      continue;
    }

    // handle potentially nested multiline comments
    if (strlen(input) >= 2) {
      if (! strncmp(input, "/*", 2)) {
        multiline_comment++;
        continue;
      }
      else if (! strncmp(input, "*/", 2)) {
        multiline_comment--;
        continue;
      }

      if (multiline_comment) {
        // skip comment lines
        continue;
      }
    }

    if (! strncasecmp(input, "whoathere", strlen("whoathere"))
        || ! strncasecmp(input, "whoanelly", strlen("whoanelly"))
        || ! strncasecmp(input, "stop", strlen("stop"))) {
      // simulated end of input
      stop = true;
      continue;
    }

    parse_line(input_line, &parsed);  // doesn't return if there's an error
    setarg = NULL;

    // certain configuration options are valid only until the first FILE: is processed
    switch (parsed.type) {
    case KEYWORD_OUTPUTFILE:
    case KEYWORD_SEED:
    case KEYWORD_BLOCKSIZE:
    case KEYWORD_HEADERBLOCKS:
    case KEYWORD_ZEROPADBLOCKS:
    case KEYWORD_RANDOMPADBLOCKS:
    case KEYWORD_INITIALRANDOMBLOCKS:
    case KEYWORD_INITIALZEROBLOCKS:
    case KEYWORD_RANDOMBLOCKS:
    case KEYWORD_ZEROBLOCKS:
    case KEYWORD_FILLHOLESPRIMARY:
    case KEYWORD_FILLHOLESSECONDARY:
      if (file_seen) {
        fprintf(stderr, "%s", RED);
        fprintf(stderr, "\nFatal error: Option on line %" PRId64 " must appear before any FILE: options.\n", LINENUMBER);
        fprintf(stderr, "%s", BLACK);
        // fatal
        exit(-1);
      }
      break;
    default:;
    }

    // ...and some don't make sense unless a FILE: is currently being processed
    switch (parsed.type) {
    case KEYWORD_MISSING:
    case KEYWORD_OUTOFORDER:
    case KEYWORD_GAP:
    case KEYWORD_DUPLICATE:
    case KEYWORD_FRAGMENTED:
      if (! file_seen) {
        fprintf(stderr, "%s", RED);
        fprintf(stderr, "\nFatal error: Option on line %" PRId64 " must appear within a FILE: definition.\n", LINENUMBER);
        fprintf(stderr, "%s", BLACK);
        // fatal
        exit(-1);
      }
      break;
    default:;
    }

    // expand file block sets only after checking their bounds against the current file
    if (parsed.type == KEYWORD_MISSING || parsed.type == KEYWORD_OUTOFORDER || parsed.type == KEYWORD_GAP
        || parsed.type == KEYWORD_DUPLICATE) {
      setarg = process_int_or_intset_or_range(parsed.argument, FILES[FILENUM].numblocks - 1);
    }

    // option is valid, so evaluate arguments
    switch (parsed.type) {
    case KEYWORD_OUTPUTFILE:  // string argument
      if (OUTPUTFILE[0]) {
        fprintf(stderr, "%s", RED);
        fprintf(stderr,
                "\nFatal error: Option on line %" PRId64 " should appear only once in the configuration\n"
                "file.\n",
                LINENUMBER);
        fprintf(stderr, "%s", BLACK);
        // fatal
        exit(-1);
      }

      if (strlen(parsed.argument) > 4 && ! strncasecmp(parsed.argument + strlen(parsed.argument) - 4, ".frg", 4)) {
        fprintf(stderr, "%s", RED);
        fprintf(stderr,
                "\nFatal error: fragmentator will not generate image files that end in \".frg\",\n"
                "as that's almost certainly not what you want.  Check line %" PRId64 " for the error.\n",
                LINENUMBER);
        fprintf(stderr, "%s", BLACK);
        // fatal
        exit(-1);
      }

      strcpy(OUTPUTFILE, parsed.argument);
      break;

    case KEYWORD_SEED:  // numeric argument
      if (SEED >= 0) {
        fprintf(stderr, "%s", RED);
        fprintf(stderr, "\nFatal error: Option on line %" PRId64 " should appear only once in the configuration file.\n",
                LINENUMBER);
        fprintf(stderr, "%s", BLACK);
        // fatal
        exit(-1);
      }
      else if (! parse_bounded_int64(parsed.argument, 0, INT64_MAX, &SEED)) {
        fprintf(stderr, "%s", RED);
        fprintf(stderr, "\nFatal error: Argument \"%s\" on line %" PRId64 " must be an integer >= 0.\n", parsed.argument,
                LINENUMBER);
        fprintf(stderr, "%s", BLACK);
        // fatal
        exit(-1);
      }
      break;

    case KEYWORD_BLOCKSIZE:  // numeric argument
      if (BLOCKSIZE > 0) {
        fprintf(stderr, "%s", RED);
        fprintf(stderr, "\nFatal error: Option on line %" PRId64 " should appear only once in the configuration file.\n",
                LINENUMBER);
        fprintf(stderr, "%s", BLACK);
        // fatal
        exit(-1);
      }
      else if (! parse_bounded_int64(parsed.argument, 512, MAX_FRAGMENTATOR_BLOCK_SIZE, &parsed_number)
               || parsed_number % 512) {
        fprintf(stderr, "%s", RED);
        fprintf(stderr,
                "\nFatal error: Argument \"%s\" on line %" PRId64 " must be an integer from 512 through %" PRId64
                " and divisible by 512.\n",
                parsed.argument, LINENUMBER, MAX_FRAGMENTATOR_BLOCK_SIZE);
        fprintf(stderr, "%s", BLACK);
        // fatal
        exit(-1);
      }

      BLOCKSIZE = (int32_t)parsed_number;
      break;

    case KEYWORD_HEADERBLOCKS:  // numeric argument
      if (HEADERBLOCKS >= 0) {
        fprintf(stderr, "%s", RED);
        fprintf(stderr, "\nFatal error: Option on line %" PRId64 " should appear only once in the configuration file.\n",
                LINENUMBER);
        fprintf(stderr, "%s", BLACK);
        // fatal
        exit(-1);
      }
      else if (! parse_bounded_int64(parsed.argument, 0, INT64_MAX, &HEADERBLOCKS)) {
        fprintf(stderr, "%s", RED);
        fprintf(stderr, "\nFatal error: Argument \"%s\" on line %" PRId64 " must be an integer >= 0.\n", parsed.argument,
                LINENUMBER);
        fprintf(stderr, "%s", BLACK);
        // fatal
        exit(-1);
      }
      break;

    case KEYWORD_ZEROPADBLOCKS:  // numeric argument
      if (ZEROPADBLOCKS >= 0) {
        fprintf(stderr, "%s", RED);
        fprintf(stderr, "\nFatal error: Option on line %" PRId64 " should appear only once in the configuration file.\n",
                LINENUMBER);
        fprintf(stderr, "%s", BLACK);
        // fatal
        exit(-1);
      }
      else if (! parse_bounded_int64(parsed.argument, 0, INT64_MAX, &ZEROPADBLOCKS)) {
        fprintf(stderr, "%s", RED);
        fprintf(stderr, "\nFatal error: Argument \"%s\" on line %" PRId64 " must be an integer >= 0.\n", parsed.argument,
                LINENUMBER);
        fprintf(stderr, "%s", BLACK);
        // fatal
        exit(-1);
      }
      break;

    case KEYWORD_RANDOMPADBLOCKS:  // numeric argument
      if (RANDOMPADBLOCKS >= 0) {
        fprintf(stderr, "%s", RED);
        fprintf(stderr, "\nFatal error: Option on line %" PRId64 " should appear only once in the configuration file.\n",
                LINENUMBER);
        fprintf(stderr, "%s", BLACK);
        // fatal
        exit(-1);
      }
      else if (! parse_bounded_int64(parsed.argument, 0, INT64_MAX, &RANDOMPADBLOCKS)) {
        fprintf(stderr, "%s", RED);
        fprintf(stderr, "\nFatal error: Argument \"%s\" on line %" PRId64 " must be an integer >= 0.\n", parsed.argument,
                LINENUMBER);
        fprintf(stderr, "%s", BLACK);
        // fatal
        exit(-1);
      }
      break;

    case KEYWORD_RANDOMBLOCKS:  // numeric argument
      if (RANDOMBLOCKS >= 0) {
        fprintf(stderr, "%s", RED);
        fprintf(stderr, "\nFatal error: Option on line %" PRId64 " should appear only once in the configuration file.\n",
                LINENUMBER);
        fprintf(stderr, "%s", BLACK);
        // fatal
        exit(-1);
      }
      else if (! parse_bounded_int64(parsed.argument, 0, INT64_MAX, &RANDOMBLOCKS)) {
        fprintf(stderr, "%s", RED);
        fprintf(stderr, "\nFatal error: Argument \"%s\" on line %" PRId64 " must be an integer >= 0.\n", parsed.argument,
                LINENUMBER);
        fprintf(stderr, "%s", BLACK);
        // fatal
        exit(-1);
      }
      break;

    case KEYWORD_ZEROBLOCKS:  // numeric argument
      if (ZEROBLOCKS >= 0) {
        fprintf(stderr, "%s", RED);
        fprintf(stderr, "\nFatal error: Option on line %" PRId64 " should appear only once in the configuration file.\n",
                LINENUMBER);
        fprintf(stderr, "%s", BLACK);
        // fatal
        exit(-1);
      }
      else if (! parse_bounded_int64(parsed.argument, 0, INT64_MAX, &ZEROBLOCKS)) {
        fprintf(stderr, "%s", RED);
        fprintf(stderr, "\nFatal error: Argument \"%s\" on line %" PRId64 " must be an integer >= 0.\n", parsed.argument,
                LINENUMBER);
        fprintf(stderr, "%s", BLACK);
        // fatal
        exit(-1);
      }
      break;

    case KEYWORD_INITIALRANDOMBLOCKS:  // numeric argument
      if (INITIALRANDOMBLOCKS >= 0) {
        fprintf(stderr, "%s", RED);
        fprintf(stderr, "\nFatal error: Option on line %" PRId64 " should appear only once in the configuration file.\n",
                LINENUMBER);
        fprintf(stderr, "%s", BLACK);
        // fatal
        exit(-1);
      }
      else if (! parse_bounded_int64(parsed.argument, 0, INT64_MAX, &INITIALRANDOMBLOCKS)) {
        fprintf(stderr, "%s", RED);
        fprintf(stderr, "\nFatal error: Argument \"%s\" on line %" PRId64 " must be an integer >= 0.\n", parsed.argument,
                LINENUMBER);
        fprintf(stderr, "%s", BLACK);
        // fatal
        exit(-1);
      }
      break;

    case KEYWORD_INITIALZEROBLOCKS:  // numeric argument
      if (INITIALZEROBLOCKS >= 0) {
        fprintf(stderr, "%s", RED);
        fprintf(stderr, "\nFatal error: Option on line %" PRId64 " should appear only once in the configuration file.\n",
                LINENUMBER);
        fprintf(stderr, "%s", BLACK);
        // fatal
        exit(-1);
      }
      else if (! parse_bounded_int64(parsed.argument, 0, INT64_MAX, &INITIALZEROBLOCKS)) {
        fprintf(stderr, "%s", RED);
        fprintf(stderr, "\nFatal error: Argument \"%s\" on line %" PRId64 " must be an integer >= 0.\n", parsed.argument,
                LINENUMBER);
        fprintf(stderr, "%s", BLACK);
        // fatal
        exit(-1);
      }
      break;

    case KEYWORD_FILLHOLESPRIMARY:  // FILE, RANDOM, or ZERO string argument
      if (FILLHOLESPRIMARY >= 0) {
        fprintf(stderr, "%s", RED);
        fprintf(stderr, "\nFatal error: Option on line %" PRId64 " should appear only once in the configuration file.\n",
                LINENUMBER);
        fprintf(stderr, "%s", BLACK);
        // fatal
        exit(-1);
      }
      else {
        for (i = 0; i < FILLHOLES_COUNT; i++) {
          if (! strcasecmp(parsed.argument, fillholes_keywords[i])) {
            FILLHOLESPRIMARY = i;
          }
        }
      }

      if (FILLHOLESPRIMARY < 0) {
        fprintf(stderr, "%s", RED);
        fprintf(stderr, "\nFatal error: Argument \"%s\" on line %" PRId64 " must be FILE, RANDOM, or ZERO.\n", parsed.argument,
                LINENUMBER);
        fprintf(stderr, "%s", BLACK);
        // fatal
        exit(-1);
      }
      break;

    case KEYWORD_FILLHOLESSECONDARY:  // FILE, RANDOM, or ZERO string argument

      if (FILLHOLESSECONDARY >= 0) {
        fprintf(stderr, "%s", RED);
        fprintf(stderr, "\nFatal error: Option on line %" PRId64 " should appear only once in the configuration file.\n",
                LINENUMBER);
        fprintf(stderr, "%s", BLACK);
        // fatal
        exit(-1);
      }
      else {
        for (i = 0; i < FILLHOLES_COUNT; i++) {
          if (! strcasecmp(parsed.argument, fillholes_keywords[i])) {
            FILLHOLESSECONDARY = i;
          }
        }
      }

      if (FILLHOLESSECONDARY < 0 || FILLHOLESSECONDARY == FILLHOLES_FILE) {
        fprintf(stderr, "%s", RED);
        fprintf(stderr,
                "\nFatal error: Argument \"%s\" on line %" PRId64 " must be RANDOM or ZERO.\n"
                "Only FILLHOLESPRIMARY can be \"FILE\".\n",
                parsed.argument, LINENUMBER);
        fprintf(stderr, "%s", BLACK);
        // fatal
        exit(-1);
      }
      break;

    case KEYWORD_FILE:  // string argument
      if (file_seen) {
        FILENUM++;
      }

      if (! file_seen) {
	// deal with command line overrides for global options when the very first FILE: definition is seen
	if (cmd_OUTPUTFILE[0]) {
	  strcpy(OUTPUTFILE, cmd_OUTPUTFILE);
	}

	if (cmd_SEED >= 0) {
	  SEED = cmd_SEED;
	}

	if (cmd_BLOCKSIZE > 0) {
	  BLOCKSIZE = cmd_BLOCKSIZE;
	}

	if (cmd_HEADERBLOCKS >= 0) {
	  HEADERBLOCKS = cmd_HEADERBLOCKS;
	}

	if (cmd_ZEROPADBLOCKS >= 0) {
	  ZEROPADBLOCKS = cmd_ZEROPADBLOCKS;
	}

	if (cmd_RANDOMPADBLOCKS >= 0) {
	  RANDOMPADBLOCKS = cmd_RANDOMPADBLOCKS;
	}

	if (cmd_INITIALRANDOMBLOCKS >= 0) {
	  INITIALRANDOMBLOCKS = cmd_INITIALRANDOMBLOCKS;
	}

	if (cmd_INITIALZEROBLOCKS >= 0) {
	  INITIALZEROBLOCKS = cmd_INITIALZEROBLOCKS;
	}

	if (cmd_RANDOMBLOCKS >= 0) {
	  RANDOMBLOCKS = cmd_RANDOMBLOCKS;
	}

	if (cmd_ZEROBLOCKS >= 0) {
	  ZEROBLOCKS = cmd_ZEROBLOCKS;
	}

	if (cmd_FILLHOLESPRIMARY >= 0) {
	  FILLHOLESPRIMARY = cmd_FILLHOLESPRIMARY;
	}

	if (cmd_FILLHOLESSECONDARY >= 0) {
	  FILLHOLESSECONDARY = cmd_FILLHOLESSECONDARY;
	}
      }

      file_seen = true;

      if (FILENUM >= MAXFILES) {
        MAXFILES += 1000;
        FILES = realloc(FILES, MAXFILES * sizeof(File));
      }

      // make sure file exists and get length
      FILE *f = fopen(parsed.argument, "rb");
      if (! f) {
        fprintf(stderr, "%s", RED);
        fprintf(stderr, "\nFatal error: File \"%s\" on line %" PRId64 " not found.\n", parsed.argument, LINENUMBER);
        fprintf(stderr, "%s", BLACK);
        // fatal
        exit(-1);
      }

      struct stat source_stat;
      if (fstat(fileno(f), &source_stat) != 0) {
        int saved_errno = errno;
        fclose(f);
        fprintf(stderr, "%s", RED);
        fprintf(stderr,
                "\nFatal error: Can't inspect file \"%s\" on line %" PRId64 ": %s.\n",
                parsed.argument, LINENUMBER, strerror(saved_errno));
        fprintf(stderr, "%s", BLACK);
        exit(-1);
      }
      if (! S_ISREG(source_stat.st_mode)) {
        fclose(f);
        fprintf(stderr, "%s", RED);
        fprintf(stderr,
                "\nFatal error: File \"%s\" on line %" PRId64 " is not a regular file.\n",
                parsed.argument, LINENUMBER);
        fprintf(stderr, "%s", BLACK);
        exit(-1);
      }
      if (fclose(f) != 0) {
        int saved_errno = errno;
        fprintf(stderr, "%s", RED);
        fprintf(stderr,
                "\nFatal error: Can't close file \"%s\" on line %" PRId64 ": %s.\n",
                parsed.argument, LINENUMBER, strerror(saved_errno));
        fprintf(stderr, "%s", BLACK);
        exit(-1);
      }

      FILES[FILENUM].length = source_stat.st_size;
      FILES[FILENUM].numblocks = CEILDIV(FILES[FILENUM].length, BLOCKSIZE);
      FILES[FILENUM].fn = malloc(strlen(parsed.argument) + 1);
      strcpy(FILES[FILENUM].fn, parsed.argument);
      FILES[FILENUM].missing = NULL;
      FILES[FILENUM].outoforder = NULL;
      FILES[FILENUM].gap = NULL;
      FILES[FILENUM].duplicate = NULL;
      FILES[FILENUM].fragmented = false;
      break;

    case KEYWORD_MISSING:     // comma separated numeric and ranges
      if (! no_frag) {
	if (! FILES[FILENUM].missing) {
	  FILES[FILENUM].missing = setarg;
	}
	else {
	  LongsSet *temp = FILES[FILENUM].missing;
	  FILES[FILENUM].missing = union_longsSets(temp, setarg);
	  destroy_LongsSet(&temp);
	  destroy_LongsSet(&setarg);
	}
      }
      break;

    case KEYWORD_OUTOFORDER:  // comma separated numeric and ranges
      if (! no_frag) {
	if (! FILES[FILENUM].outoforder) {
	  FILES[FILENUM].outoforder = setarg;
	}
	else {
	  LongsSet *temp = FILES[FILENUM].outoforder;
	  FILES[FILENUM].outoforder = union_longsSets(temp, setarg);
	  destroy_LongsSet(&temp);
	  destroy_LongsSet(&setarg);
	}
      }
      break;

    case KEYWORD_GAP:         // comma separated numeric and ranges
      if (! no_frag) {
	if (! FILES[FILENUM].gap) {
	  FILES[FILENUM].gap = setarg;
	}
	else {
	  LongsSet *temp = FILES[FILENUM].gap;
	  FILES[FILENUM].gap = union_longsSets(temp, setarg);
	  destroy_LongsSet(&temp);
	  destroy_LongsSet(&setarg);
	}
      }
      break;

    case KEYWORD_DUPLICATE:   // comma separated numeric and ranges
      if (! no_frag) {
	if (! FILES[FILENUM].duplicate) {
	  FILES[FILENUM].duplicate = setarg;
	}
	else {
	  LongsSet *temp = FILES[FILENUM].duplicate;
	  FILES[FILENUM].duplicate = union_longsSets(temp, setarg);
	  destroy_LongsSet(&temp);
	  destroy_LongsSet(&setarg);
	}
      }
      break;

    case KEYWORD_FRAGMENTED:  // 0 / 1 or TRUE / FALSE argument
      if (! is_boolean(parsed.argument, &FILES[FILENUM].fragmented)) {
        fprintf(stderr, "%s", RED);
        fprintf(stderr, "\nFatal error: Argument \"%s\" on line %" PRId64 " must be a Boolean value (0, 1, TRUE, or FALSE).\n",
                parsed.argument, LINENUMBER);
        fprintf(stderr, "%s", BLACK);
        // fatal
        exit(-1);
      }
      if (no_frag) {
	FILES[FILENUM].fragmented = false;
      }
      break;

    default:
      fprintf(stderr, "%s", RED);
      fprintf(stderr, "\nFatal error: Something is very wrong in source line %d.\n", __LINE__);
      fprintf(stderr, "%s", BLACK);
      // fatal
      exit(-1);
    }
  }

  if (DEBUG <= 2 && isatty(1)) {
    fprintf(stdout, "\b\b\b\b%3d%%\n", 100);
  }

  if (multiline_comment) {
    // runaway comment
    fprintf(stderr, "%s", RED);
    fprintf(stderr, "Fatal error: Runaway multiline comment: check use of /* and */ in input file.\n");
    fprintf(stderr, "%s", BLACK);
    // fatal
    exit(-1);
  }

  if (! file_seen) {
    fprintf(stderr, "%s", RED);
    fprintf(stderr, "\nFatal error: Reached end of file with no FILE: definitions.\n");
    fprintf(stderr, "%s", BLACK);
    // fatal
    exit(-1);
  }

  // validate all file definitions
  for (int i = 0; i <= FILENUM; i++) {
    check_File_definition(FILES[i]);  // no return on error
  }

  if (! OUTPUTFILE[0]) {
    fprintf(stderr, "%s", RED);
    fprintf(stderr, "\nFatal error: Reached end of file with no OUTPUTFILE: definition.\n");
    fprintf(stderr, "%s", BLACK);
    // fatal
    exit(-1);
  }

  if (SEED < 0) {
    fprintf(stderr, "%s", RED);
    fprintf(stderr, "\nFatal error: Reached end of file with no SEED: definition.\n");
    fprintf(stderr, "%s", BLACK);
    // fatal
    exit(-1);
  }

  if (BLOCKSIZE < 0) {
    fprintf(stderr, "%s", RED);
    fprintf(stderr, "\nFatal error: Reached end of file with no BLOCKSIZE: definition.\n");
    fprintf(stderr, "%s", BLACK);
    // fatal
    exit(-1);
  }

  if (HEADERBLOCKS == -1) {
    HEADERBLOCKS = 1;
  }

  if (ZEROPADBLOCKS == -1) {
    ZEROPADBLOCKS = 0;
  }

  if (RANDOMPADBLOCKS == -1) {
    RANDOMPADBLOCKS = 0;
  }

  if (INITIALRANDOMBLOCKS == -1) {
    INITIALRANDOMBLOCKS = 0;
  }

  if (INITIALZEROBLOCKS == -1) {
    INITIALZEROBLOCKS = 0;
  }

  if (RANDOMBLOCKS == -1) {
    RANDOMBLOCKS = 0;
  }

  if (ZEROBLOCKS == -1) {
    ZEROBLOCKS = 0;
  }

  if (FILLHOLESPRIMARY == -1) {
    FILLHOLESPRIMARY = FILLHOLES_FILE;
  }

  if (FILLHOLESSECONDARY == -1) {
    FILLHOLESSECONDARY = FILLHOLES_RANDOM;
  }

  if (RANDOMPADBLOCKS > 0 && ZEROPADBLOCKS > 0) {
    fprintf(stderr, "%s", RED);
    fprintf(stderr, "\nFatal error: RANDOMPAD and ZEROPAD are mutually exclusive options.\n");
    fprintf(stderr, "%s", BLACK);
    // fatal
    exit(-1);
  }
}


// fills CLUSTERS[++CLUSTERNUM] with a new initialized Cluster
static void init_new_cluster(ClusterBlock *blocks, int64_t numblocks, bool needs_fill) {

  CLUSTERNUM++;
  if (CLUSTERNUM >= MAXCLUSTERS) {
    MAXCLUSTERS += 1000;
    CLUSTERS = realloc(CLUSTERS, MAXCLUSTERS * sizeof(Cluster));
  }

  bzero(&CLUSTERS[CLUSTERNUM], sizeof(Cluster));
  CLUSTERS[CLUSTERNUM].coalesced = false;
  CLUSTERS[CLUSTERNUM].blocks = blocks;
  CLUSTERS[CLUSTERNUM].numblocks = numblocks;
  CLUSTERS[CLUSTERNUM].needs_fill = needs_fill;
  CLUSTERS[CLUSTERNUM].seq = CLUSTERNUM;
  TOTALBLOCKS += CLUSTERS[CLUSTERNUM].numblocks;
}


// open 'fn' and read 'blocknum'-th block into 'data' and then close
// 'fn'
bool read_file_block(char *fn, int64_t block, char *data) {

  FILE *fp;
  off_t offset;
  size_t ret;
  int saved_errno;
  int at_eof;
  int read_error;

  if (BLOCKSIZE <= 0 || block < 0 || block > INT64_MAX / BLOCKSIZE) {
    fprintf(stderr, "%s", RED);
    fprintf(stderr, "Fatal error: Invalid block number %" PRId64 " for input file \"%s\".\n", block, fn);
    fprintf(stderr, "%s", BLACK);
    return false;
  }

  fp = fopen(fn, "rb");
  if (! fp) {
    saved_errno = errno;
    fprintf(stderr, "%s", RED);
    fprintf(stderr, "Fatal error: Can't open input \"%s\": %s.\n", fn, strerror(saved_errno));
    fprintf(stderr, "%s", BLACK);
    return false;
  }

  offset = (off_t)(block * (int64_t)BLOCKSIZE);
  if (fseeko(fp, offset, SEEK_SET) != 0) {
    saved_errno = errno;
    fclose(fp);
    fprintf(stderr, "%s", RED);
    fprintf(stderr,
            "Fatal error: Can't seek to block %" PRId64 " in input file \"%s\": %s.\n",
            block, fn, strerror(saved_errno));
    fprintf(stderr, "%s", BLACK);
    return false;
  }

  bzero(data, BLOCKSIZE);

  errno = 0;
  ret = fread(data, 1, BLOCKSIZE, fp);
  saved_errno = errno;
  at_eof = feof(fp);
  read_error = ferror(fp);
  if (! ret || read_error) {
    fclose(fp);
    fprintf(stderr, "%s", RED);
    fprintf(stderr,
            "Fatal error: Can't read block %" PRId64 " from input file \"%s\": "
            "%zu bytes read, feof() = %d, ferror() = %d%s%s.\n",
            block, fn, ret, at_eof, read_error,
            read_error ? ", error = " : "",
            read_error ? strerror(saved_errno ? saved_errno : EIO) : "");
    fprintf(stderr, "%s", BLACK);
    return false;
  }

  if (fclose(fp) != 0) {
    saved_errno = errno;
    fprintf(stderr, "%s", RED);
    fprintf(stderr, "Fatal error: Can't close input file \"%s\": %s.\n", fn, strerror(saved_errno));
    fprintf(stderr, "%s", BLACK);
    return false;
  }

  return true;
}


// output info about cluster 'c' to file 'fp'. c.needs_fill info is output only if needs_fill is
// true.
static void print_cluster(Cluster c, int64_t num, FILE *fp, int64_t *imgblocknum) {

  int64_t j;
  char *type;
  bool first = true;

  fprintf(fp, "CLUSTER # %8" PRId64 " (# blocks: %8" PRId64 "):", num, c.numblocks);

  for (j = 0; j < c.numblocks; j++) {
    switch (c.blocks[j].type) {
    case CLUSTER_BLOCK_UNKNOWN:
      type = "UNKNOWN";
      break;

    case CLUSTER_BLOCK_HEADER:
      type = "HEADER";
      break;

    case CLUSTER_BLOCK_FILE:
      type = "FILE";
      break;

    case CLUSTER_BLOCK_RANDOM:
      type = "RANDOM";
      break;

    case CLUSTER_BLOCK_ZERO:
      type = "ZERO";
      break;

    case CLUSTER_BLOCK_NEEDSFILL:
      type = "NEEDSFILL";
      break;

    default:
      fprintf(stderr, "%s", RED);
      fprintf(stderr, "Fatal error:  Something went horribly wrong in display_clusters(): %d.\n", c.blocks[j].type);
      fprintf(stderr, "%s", BLACK);
      exit(-1);
    }

    if (first) {
      first = false;
      fprintf(fp, "  ");
    }
    else {
      fprintf(fp, "                                          ");
    }

    if (imgblocknum) {
      fprintf(fp, "[%9s | %*s |  %8" PRId64 "]\t\t  %" PRId64 "\n", type, (int)(longest_input_pathname + 1),
              c.blocks[j].fn ? c.blocks[j].fn : "NONE", c.blocks[j].blocknum, *imgblocknum);
      (*imgblocknum)++;
    }
    else {
      fprintf(fp, "[%9s | %*s |  %8" PRId64 "]\t\t\n", type, (int)(longest_input_pathname + 1), c.blocks[j].fn,
              c.blocks[j].blocknum);
    }
  }
}


// display contents of all clusters
static void display_all_clusters(void) {

  int64_t i;

  for (i = 0; i <= CLUSTERNUM; i++) {
    print_cluster(CLUSTERS[i], i + 1, stdout, NULL);
  }
}


// generate set of clusters used to create image file
static void create_clusters(void) {

  ClusterBlock *blocks;
  ClusterBlock *subcluster_blocks;
  int64_t i, j, k;

  int64_t ooo_idx, missing_idx, gap_idx, start_idx, end_idx, gap_blocks, headerblocks, numblocks;
  FillHolesPref fillpref;
  int perc1, perc2;

  // Cluster generation proceeds as follows:
  //
  // (1)
  //
  // First, each file is used to generate one or more clusters:
  //
  // Whether a file is fragmented (FRAGMENT:TRUE) or not, DUPLICATE blocks are each used to create
  // new cluster.
  //
  // Fully fragmented files (with FRAGMENT: TRUE) generate a separate cluster for each block, with
  // the exception of contiguous header blocks, which are used to form a single cluster.
  //
  // Files that are not fully fragmented are composed of a single cluster, with MISSING blocks,
  // GAPS, and OUTOFORDER blocks marked as needing to be filled during cluster coalescing (see (2),
  // below). MISSING blocks are discarded while OUTOFORDER blocks are used to generate additional
  // clusters.
  //
  // (2)
  //
  // Once the initial clusters have been created, if the FILLHOLESPRIMARY preference is FILE, an
  // attempt is made to coalesce smaller clusters into larger ones to fill GAPS, OUTOFORDER, and
  // MISSING blocks. Otherwise, fills are satisfied using random or zero data, according to the
  // FILLGAPSSECONDARY preference.
  //
  // (3)
  //
  // Then additional clusters are potentially created, based on the RANDOMBLOCKS and ZEROBLOCKS
  // options. Each of the random or zero blocks is placed in a single block cluster.
  //


  // (1) all files

  fprintf(stdout, "Cluster generation phase 1/3: Generating clusters from file data...    ");
  fflush(stdout);

  perc1 = 0;
  perc2 = 0;

  for (i = 0; i <= FILENUM; i++) {
    perc2 = FILENUM > 0 ? (int)((double)i / (double)FILENUM * (double)100) : 100;
    if (perc1 != perc2 && isatty(1)) {
      perc1 = perc2;
      fprintf(stdout, "\b\b\b\b%3d%%", perc1);
      fflush(stdout);
    }

    // DUPLICATE is legal for both fragmented and unfragmented files--handle first

    if (FILES[i].duplicate) {
      // generate a separate cluster for each duplicate block
      for (j = 0; j < (int64_t)FILES[i].duplicate->len; j++) {
        blocks = malloc(sizeof(ClusterBlock));
        blocks[0].type = CLUSTER_BLOCK_FILE;
        blocks[0].fn = FILES[i].fn;
        blocks[0].blocknum = FILES[i].duplicate->set[j];
        init_new_cluster(blocks, 1, false);
      }
    }

    if (FILES[i].fragmented) {
      // fully fragmented file--doesn't have GAPS, OUTOFORDER, or MISSING blocks

      // first handle contiguous header blocks
      headerblocks = (int64_t)HEADERBLOCKS <= FILES[i].numblocks ? (int64_t)HEADERBLOCKS : FILES[i].numblocks;
      blocks = malloc(sizeof(ClusterBlock) * headerblocks);

      for (j = 0; j < (int64_t)headerblocks; j++) {
        blocks[j].type = CLUSTER_BLOCK_HEADER;
        blocks[j].fn = FILES[i].fn;
        blocks[j].blocknum = j;
      }

      init_new_cluster(blocks, headerblocks, false);

      // then the rest of the blocks
      for (j = (int64_t)headerblocks; j < (int64_t)FILES[i].numblocks; j++) {
        blocks = malloc(sizeof(ClusterBlock));
        blocks[0].type = CLUSTER_BLOCK_FILE;
        blocks[0].fn = FILES[i].fn;
        blocks[0].blocknum = j;
        init_new_cluster(blocks, 1, false);
      }
    }
    else {
      // unfragmented or partially fragmented file
      numblocks = FILES[i].numblocks + (FILES[i].gap ? FILES[i].gap->len : 0);
      blocks = malloc(sizeof(ClusterBlock) * numblocks);

      // handle contiguous header blocks
      headerblocks = (int64_t)HEADERBLOCKS <= FILES[i].numblocks ? (int64_t)HEADERBLOCKS : FILES[i].numblocks;
      for (j = 0; j < headerblocks; j++) {
        blocks[j].type = CLUSTER_BLOCK_HEADER;
        blocks[j].fn = FILES[i].fn;
        blocks[j].blocknum = j;
      }

      ooo_idx = 0;
      missing_idx = 0;

      // handle spans of normal, out of order, and missing blocks beyond the header
      j = HEADERBLOCKS;
      while (j < FILES[i].numblocks) {
        start_idx = j;
        end_idx = j - 1;

        if (FILES[i].outoforder && ooo_idx < FILES[i].outoforder->len && FILES[i].outoforder->set[ooo_idx] == j) {
          // handle span of out of order blocks
          while (ooo_idx < FILES[i].outoforder->len && j < FILES[i].numblocks && FILES[i].outoforder->set[ooo_idx] == j) {
            end_idx++;
            ooo_idx++;
            j++;
          }

          if (start_idx <= end_idx) {
            // there was an out of order span--mark blocks in cluster as needing to be filled and
            // generate a new fragment containing blocks for this file
            subcluster_blocks = malloc(sizeof(ClusterBlock) * (end_idx - start_idx + 1));
            for (k = start_idx; k <= end_idx; k++) {
              blocks[k].type = CLUSTER_BLOCK_NEEDSFILL;
              blocks[k].fn = FILES[i].fn;
              blocks[k].blocknum = -1;

              subcluster_blocks[k - start_idx].type = CLUSTER_BLOCK_FILE;
              subcluster_blocks[k - start_idx].fn = FILES[i].fn;
              subcluster_blocks[k - start_idx].blocknum = k;
            }

            // new cluster for out of order span
            init_new_cluster(subcluster_blocks, end_idx - start_idx + 1, false);
          }
        }
        else if (FILES[i].missing && missing_idx < FILES[i].missing->len && FILES[i].missing->set[missing_idx] == j) {
          // handle span of missing blocks
          while (missing_idx < FILES[i].missing->len && j < FILES[i].numblocks && FILES[i].missing->set[missing_idx] == j) {
            end_idx++;
            missing_idx++;
            j++;
          }

          if (start_idx <= end_idx) {
            // there was a span of missing blocks---mark blocks in cluster as needing to be filled,
            // but no new cluster is needed
            for (k = start_idx; k <= end_idx; k++) {
              blocks[k].type = CLUSTER_BLOCK_NEEDSFILL;
              blocks[k].fn = FILES[i].fn;
              blocks[k].blocknum = -1;
            }
          }
        }
        else {
          // handle normal block
          blocks[j].type = CLUSTER_BLOCK_FILE;
          blocks[j].fn = FILES[i].fn;
          blocks[j].blocknum = j;
          j++;
        }
      }

      // handle spans of gaps
      gap_idx = 0;
      gap_blocks = 0;

      if (FILES[i].gap) {
        while (FILES[i].gap && gap_idx < FILES[i].gap->len) {
          start_idx = FILES[i].gap->set[gap_idx++];
          end_idx = start_idx;

          // find contiguous span
          while (gap_idx < FILES[i].gap->len && FILES[i].gap->set[gap_idx] == FILES[i].gap->set[gap_idx - 1] + 1) {
            gap_idx++;
            end_idx++;
          }

          // create space between cluster blocks to contain new gap span
          memmove(blocks + gap_blocks + end_idx + 1, blocks + gap_blocks + start_idx,
                  (FILES[i].numblocks - start_idx) * sizeof(ClusterBlock));

          // mark the new blocks as needing fill in (2)
          for (k = start_idx + gap_blocks; k <= end_idx + gap_blocks; k++) {
            blocks[k].type = CLUSTER_BLOCK_NEEDSFILL;
            blocks[k].fn = FILES[i].fn;
            blocks[k].blocknum = -1;
          }

          gap_blocks += (end_idx - start_idx + 1);
        }
      }
      init_new_cluster(blocks, numblocks, FILES[i].gap || FILES[i].missing || FILES[i].outoforder);
    }
  }

  if (isatty(1)) {
    fprintf(stdout, "\b\b\b\b%3d%%\n", 100);
  }
  else {
    fprintf(stdout, "\n");
  }

  fprintf(stdout, "Done.\n");

  if (DEBUG > 2) {
    fprintf(stdout, "\nClusters after Phase 1:\n");
    display_all_clusters();
    fprintf(stdout, "\n\n");
  }

  // (2) coalesce clusters and fill blocks

  fprintf(stdout, "Cluster generation phase 2.1/3: Sorting...    ");
  if (isatty(1)) {
    fprintf(stdout, "\b\b\b\b%3d%%", 0);
    fflush(stdout);
  }
  else {
    fprintf(stdout, "\n");
  }

  // sort clusters by size, EXCEPT for initial zero and random blocks
  qsort(CLUSTERS, CLUSTERNUM + 1, sizeof(Cluster), compare_clusters);

  if (isatty(1)) {
    fprintf(stdout, "\b\b\b\b%3d%%\n", 100);
  }

  fprintf(stdout, "Done.\n");

  fprintf(stdout, "Cluster generation phase 2.2/3: Coalescing and filling...    ");
  fflush(stdout);

  // then evaluate each cluster to see if it needs filling
  i = 0;
  perc1 = 0;
  perc2 = 0;

  while (i <= CLUSTERNUM) {
    perc2 = CLUSTERNUM > 0 ? (int)((double)i / (double)CLUSTERNUM * (double)100) : 100;
    if (perc1 != perc2 && isatty(1)) {
      perc1 = perc2;
      fprintf(stdout, "\b\b\b\b%3d%%", perc1);
      fflush(stdout);
    }

    if (! CLUSTERS[i].needs_fill) {
      i++;
      continue;
    }

    // cluster needs fill
    j = 0;
    while (j < CLUSTERS[i].numblocks) {
      if (CLUSTERS[i].blocks[j].type != CLUSTER_BLOCK_NEEDSFILL) {
        j++;
        continue;
      }

      // found a sequence of blocks that needs fill
      start_idx = j;
      end_idx = j;
      while (++j < CLUSTERS[i].numblocks && CLUSTERS[i].blocks[j].type == CLUSTER_BLOCK_NEEDSFILL) {
        end_idx++;
      }

      // start_idx...end_idx defines a collection of blocks that need to be filled
      fillpref = FILLHOLESPRIMARY;

      if (fillpref == FILLHOLES_FILE) {
        // try to find smaller clusters of file data that will fit into this hole
        k = i - 1;
        while (k >= 0 && start_idx <= end_idx) {
          if (CLUSTERS[k].coalesced) {
            // this cluster was already merged with another
            k--;
            continue;
          }
          else if (CLUSTERS[k].numblocks == 0 || CLUSTERS[k].numblocks > end_idx - start_idx + 1) {
            k--;
            continue;
          }
          else if (! strcasecmp(CLUSTERS[i].blocks[start_idx].fn, CLUSTERS[k].blocks[0].fn)) {
            // don't allow clusters to be reinserted into the files from which they were generated
            k--;
            continue;
          }

          // coalesce
          CLUSTERS[k].coalesced = true;
          memcpy(CLUSTERS[i].blocks + start_idx, CLUSTERS[k].blocks, CLUSTERS[k].numblocks * sizeof(ClusterBlock));
          start_idx += CLUSTERS[k].numblocks;
          k--;
        }

        // if start_idx <= end_idx, a suitable cluster couldn't be found to fill some blocks in the
        // hole--fall back on secondary fill choice
        fillpref = FILLHOLESSECONDARY;
      }

      if (fillpref == FILLHOLES_ZERO) {
        for (k = start_idx; k <= end_idx; k++) {
          CLUSTERS[i].blocks[k].type = CLUSTER_BLOCK_ZERO;
          CLUSTERS[i].blocks[k].fn = NULL;
          CLUSTERS[i].blocks[k].blocknum = -1;
        }
      }
      else if (fillpref == FILLHOLES_RANDOM) {
        for (k = start_idx; k <= end_idx; k++) {
          CLUSTERS[i].blocks[k].type = CLUSTER_BLOCK_RANDOM;
          CLUSTERS[i].blocks[k].fn = NULL;
          CLUSTERS[i].blocks[k].blocknum = -1;
        }
      }
    }
    i++;
  }

  if (isatty(1)) {
    fprintf(stdout, "\b\b\b\b%3d%%\n", 100);
  }
  else {
    fprintf(stdout, "\n");
  }

  fprintf(stdout, "Done.\n");

  if (DEBUG > 2) {
    fprintf(stdout, "\nClusters after Phase 2.2:\n");
    display_all_clusters();
    fprintf(stdout, "\n\n");
  }

  fprintf(stdout, "Phase 2.3/3: Cleaning up...    ");
  fflush(stdout);

  // remove coalesced clusters in one pass while preserving survivor order
  perc1 = 0;
  perc2 = 0;

  for (i = 0, j = 0; i <= CLUSTERNUM; i++) {
    perc2 = CLUSTERNUM > 0 ? (int)((double)i / (double)CLUSTERNUM * (double)100) : 100;
    if (perc1 != perc2 && isatty(1)) {
      perc1 = perc2;
      fprintf(stdout, "\b\b\b\b%3d%%", perc1);
      fflush(stdout);
    }

    if (CLUSTERS[i].coalesced) {
      TOTALBLOCKS -= CLUSTERS[i].numblocks;
      free(CLUSTERS[i].blocks);
      continue;
    }

    if (i != j) {
      CLUSTERS[j] = CLUSTERS[i];
    }
    j++;
  }
  CLUSTERNUM = j - 1;

  if (isatty(1)) {
    fprintf(stdout, "\b\b\b\b%3d%%\n", 100);
  }
  else {
    fprintf(stdout, "\n");
  }

  fprintf(stdout, "Done.\n");

  if (DEBUG > 2) {
    fprintf(stdout, "\nClusters after Phase 2.3:\n");
    display_all_clusters();
    fprintf(stdout, "\n\n");
  }

  // (3) insert clusters associated with RANDOMBLOCKS / ZEROBLOCKS

  fprintf(stdout, "Phase 3/3: Inserting random and zero blocks...    ");
  fflush(stdout);

  perc1 = 0;
  perc2 = 0;
  j = 0;

  for (i = 0; i < RANDOMBLOCKS; i++) {
    perc2 = (int)((double)j / (double)(RANDOMBLOCKS + ZEROBLOCKS) * (double)100);
    if (perc1 != perc2 && isatty(1)) {
      perc1 = perc2;
      fprintf(stdout, "\b\b\b\b%3d%%", perc1);
      fflush(stdout);
    }
    blocks = malloc(sizeof(ClusterBlock));
    blocks[0].type = CLUSTER_BLOCK_RANDOM;
    blocks[0].fn = NULL;
    blocks[0].blocknum = -1;
    init_new_cluster(blocks, 1, false);
    j++;
  }

  perc1 = 0;
  perc2 = 0;

  for (i = 0; i < ZEROBLOCKS; i++) {
    perc2 = (int)((double)j / (double)(RANDOMBLOCKS + ZEROBLOCKS) * (double)100);
    if (perc1 != perc2 && isatty(1)) {
      perc1 = perc2;
      fprintf(stdout, "\b\b\b\b%3d%%", perc1);
      fflush(stdout);
    }
    blocks = malloc(sizeof(ClusterBlock));
    blocks[0].type = CLUSTER_BLOCK_ZERO;
    blocks[0].fn = NULL;
    blocks[0].blocknum = -1;
    init_new_cluster(blocks, 1, false);
    j++;
  }

  if (isatty(1)) {
    fprintf(stdout, "\b\b\b\b%3d%%\n", 100);
  }
  else {
    fprintf(stdout, "\n");
  }
}


// generate image file and .key file based on cluster set
static bool generate_output(FILE *out, FILE *outlog) {

  int64_t i, j, k;
  uint64_t blocks = 0;
  bool success = true;
  char *data;         // block of data to write
  char *ZEROBLOCK;    // block containing BLOCKSIZE zeroes
  char *DATABLOCK;    // block containing file data
  long *RANDOMBLOCK;  // block containing random data
  int64_t c = 0;
  int64_t imgblocknum = 0;
  int perc1, perc2;
  Cluster zerocluster;
  Cluster randomcluster;
  ClusterBlock zeroclusterblock[1] = {{CLUSTER_BLOCK_ZERO, NULL, -1}};
  ClusterBlock randomclusterblock[1] = {{CLUSTER_BLOCK_RANDOM, NULL, -1}};

  print_config_summary(outlog);

  fprintf(outlog, "CLUSTER INFO\t\t\t\t   BLOCK TYPE%*sFILE%*s FILE BLOCK    DISK BLOCK\n", (int)(longest_input_pathname) / 2, "",
          (int)(longest_input_pathname) / 2, "");
  fprintf(outlog, "------------\t\t\t\t   ----------%*s----%*s ----------    ----------\n", (int)(longest_input_pathname) / 2, "",
          (int)(longest_input_pathname) / 2, "");

  // initialize zero block and random block
  ZEROBLOCK = calloc(BLOCKSIZE, 1);
  DATABLOCK = calloc(BLOCKSIZE, 1);
  RANDOMBLOCK = calloc(BLOCKSIZE, 1);

  // initialize zero cluster and random cluster
  zerocluster.coalesced = false;
  zerocluster.blocks = zeroclusterblock;
  zerocluster.numblocks = 1;
  zerocluster.needs_fill = false;
  randomcluster.coalesced = false;
  randomcluster.blocks = randomclusterblock;
  randomcluster.numblocks = 1;
  randomcluster.needs_fill = false;

  TOTALBLOCKS = TOTALBLOCKS + INITIALZEROBLOCKS + INITIALRANDOMBLOCKS;
  TOTALBLOCKS += (TOTALBLOCKS < (RANDOMPADBLOCKS + ZEROPADBLOCKS) ? ((RANDOMPADBLOCKS + ZEROPADBLOCKS) - TOTALBLOCKS) : 0);

  perc1 = 0;
  perc2 = 0;

  for (i = 0; i < INITIALZEROBLOCKS; i++) {
    blocks++;
    perc2 = (int)((double)blocks / (double)TOTALBLOCKS * (double)100);
    if (perc1 != perc2 && isatty(1)) {
      perc1 = perc2;
      fprintf(stdout, "\b\b\b\b%3d%%", perc1);
      fflush(stdout);
    }

    success = fwrite(ZEROBLOCK, BLOCKSIZE, 1, out);
    if (! success) {
      fprintf(stderr, "\n%s", RED);
      fprintf(stderr, "Fatal error: Can't write to output file.\n");
      fprintf(stderr, "%s", BLACK);
      // fatal
      return false;
    }

    c++;
    print_cluster(zerocluster, c, outlog, &imgblocknum);
  }

  perc1 = 0;
  perc2 = 0;

  for (i = 0; i < INITIALRANDOMBLOCKS; i++) {
    blocks++;
    perc2 = (int)((double)blocks / (double)TOTALBLOCKS * (double)100);
    if (perc1 != perc2 && isatty(1)) {
      perc1 = perc2;
      fprintf(stdout, "\b\b\b\b%3d%%", perc1);
      fflush(stdout);
    }

    // generate random block
    for (k = 0; k < BLOCKSIZE / (int64_t)sizeof(long); k++) {
      RANDOMBLOCK[k] = portable_random();
    }

    success = fwrite(RANDOMBLOCK, BLOCKSIZE, 1, out);
    if (! success) {
      fprintf(stderr, "\n%s", RED);
      fprintf(stderr, "Fatal error: Can't write to output file.\n");
      fprintf(stderr, "%s", BLACK);
      // fatal
      return false;
    }

    c++;
    print_cluster(randomcluster, c, outlog, &imgblocknum);
  }

  perc1 = 0;
  perc2 = 0;

  while (CLUSTERNUM >= 0) {
    perc2 = (int)((double)blocks / (double)TOTALBLOCKS * (double)100);
    if (perc1 != perc2 && isatty(1)) {
      perc1 = perc2;
      fprintf(stdout, "\b\b\b\b%3d%%", perc1);
      fflush(stdout);
    }

    // choose random cluster
    i = portable_random() % (CLUSTERNUM + 1);

    c++;
    print_cluster(CLUSTERS[i], c, outlog, &imgblocknum);
    for (j = 0; j < CLUSTERS[i].numblocks; j++) {
      blocks++;

      switch (CLUSTERS[i].blocks[j].type) {
      case CLUSTER_BLOCK_HEADER:
      case CLUSTER_BLOCK_FILE:
        data = DATABLOCK;
        if (! read_file_block(CLUSTERS[i].blocks[j].fn, CLUSTERS[i].blocks[j].blocknum, data)) {
          // fatal
          return false;
        }
        break;

      case CLUSTER_BLOCK_RANDOM:
        // generate random block
        for (k = 0; k < BLOCKSIZE / (int64_t)sizeof(long); k++) {
          RANDOMBLOCK[k] = portable_random();
        }
        data = (char *)RANDOMBLOCK;
        break;

      case CLUSTER_BLOCK_ZERO:
        data = ZEROBLOCK;
        break;

      default:
        fprintf(stderr, "\n%s", RED);
        fprintf(stderr, "Fatal error:  Something went horribly wrong in generate_output().\n");
        fprintf(stderr, "%s", BLACK);
        // fatal
        return false;
      }

      // write block
      if (success) {
        success = fwrite(data, BLOCKSIZE, 1, out);
        if (! success) {
          fprintf(stderr, "\n%s", RED);
          fprintf(stderr, "Fatal error: Can't write to output file.\n");
          fprintf(stderr, "%s", BLACK);
          // fatal
          return false;
        }
      }
    }

    free(CLUSTERS[i].blocks);

    // remove cluster
    if (i != CLUSTERNUM) {
      CLUSTERS[i] = CLUSTERS[CLUSTERNUM];
    }

    CLUSTERNUM--;
  }

  // now pad with zeros or all random data to satisfy ZEROPADBLOCKS or RANDOMPADBLOCKS, as required

  perc1 = 0;
  perc2 = 0;

  while (imgblocknum < ZEROPADBLOCKS) {
    blocks++;
    perc2 = (int)((double)blocks / (double)TOTALBLOCKS * (double)100);
    if (perc1 != perc2 && isatty(1)) {
      perc1 = perc2;
      fprintf(stdout, "\b\b\b\b%3d%%", perc1);
      fflush(stdout);
    }

    success = fwrite(ZEROBLOCK, BLOCKSIZE, 1, out);

    if (! success) {
      fprintf(stderr, "\n%s", RED);
      fprintf(stderr, "Fatal error: Can't write to output file.\n");
      fprintf(stderr, "%s", BLACK);
      // fatal
      return false;
    }

    c++;
    print_cluster(zerocluster, c, outlog, &imgblocknum);
  }

  perc1 = 0;
  perc2 = 0;

  while (imgblocknum < RANDOMPADBLOCKS) {
    blocks++;
    perc2 = (int)((double)blocks / (double)TOTALBLOCKS * (double)100);
    if (perc1 != perc2 && isatty(1)) {
      perc1 = perc2;
      fprintf(stdout, "\b\b\b\b%3d%%", perc1);
      fflush(stdout);
    }

    // generate random block
    for (k = 0; k < BLOCKSIZE / (int64_t)sizeof(long); k++) {
      RANDOMBLOCK[k] = portable_random();
    }
    success = fwrite(RANDOMBLOCK, BLOCKSIZE, 1, out);
    if (! success) {
      fprintf(stderr, "\n%s", RED);
      fprintf(stderr, "Fatal error: Can't write to output file.\n");
      fprintf(stderr, "%s", BLACK);
      // fatal
      return false;
    }

    c++;
    print_cluster(randomcluster, c, outlog, &imgblocknum);
  }

  free(ZEROBLOCK);
  free(DATABLOCK);
  free(RANDOMBLOCK);

  if (isatty(1)) {
    fprintf(stdout, "\b\b\b\b%3d%%\n", 100);
  }
  else {
    fprintf(stdout, "\n");
  }

  return true;
}


int main(int argc, char *argv[]) {

  char outlog_fn[MAX_LINE_LENGTH * 2 + 1];
  FILE *out;
  FILE *outlog;
  bool fail = true;
  int idx = 1;

#if DISABLE_COLOR > 0
  DISABLE_ALL_COLOR;
#endif

  // set up initial state
  OUTPUTFILE[0] = 0;
  SEED = -1;
  BLOCKSIZE = -1;
  HEADERBLOCKS = -1;
  ZEROPADBLOCKS = -1;
  RANDOMPADBLOCKS = -1;
  INITIALRANDOMBLOCKS = -1;
  INITIALZEROBLOCKS = -1;
  RANDOMBLOCKS = -1;
  ZEROBLOCKS = -1;
  FILLHOLESPRIMARY = -1;
  FILLHOLESSECONDARY = -1;
  cmd_OUTPUTFILE[0] = 0;
  cmd_SEED = -1;
  cmd_BLOCKSIZE = -1;
  cmd_HEADERBLOCKS = -1;
  cmd_ZEROPADBLOCKS = -1;
  cmd_RANDOMPADBLOCKS = -1;
  cmd_INITIALRANDOMBLOCKS = -1;
  cmd_INITIALZEROBLOCKS = -1;
  cmd_RANDOMBLOCKS = -1;
  cmd_ZEROBLOCKS = -1;
  cmd_FILLHOLESPRIMARY = -1;
  cmd_FILLHOLESSECONDARY = -1;

  // don't use color for redirected output
  if (! isatty(1) || ! isatty(2)) {
    DISABLE_ALL_COLOR;
  }

  fragmentator_logo();
  fprintf(stdout, "%s", BLUE);
  fprintf(stdout, FRAGMENTATOR_BANNER_STRING);
  fprintf(stdout, "%s", BLACK);
  fprintf(stdout, "\n\n");

  process_command_line_args(argc, argv);
  idx = optind;

  if (idx >= argc) {
    usage();
    fprintf(stderr, "%s", RED);
    fprintf(stderr, "Missing <configfile>.\n");
    fprintf(stderr, "%s", BLACK);
    return -1;
  }

  if (argc - idx > 1) {
    usage();
    fprintf(stderr, "%s", RED);
    fprintf(stderr, "<configfile> must be the last argument on the command line.\n");
    fprintf(stderr, "%s", BLACK);
    return -1;
  }

  if (strlen(argv[idx]) > MAX_LINE_LENGTH) {
    fprintf(stderr, "%s", RED);
    fprintf(stderr, "Fatal error: This isn't an exploit development exercise.\n");
    fprintf(stderr, "%s", BLACK);
    return -1;
  }

  fprintf(stdout, "Parsing input, please wait...    ");
  fflush(stdout);
  parse_input(argv[idx]);
  if (DEBUG > 0) {
    fprintf(stdout, "\n");
  }
  fprintf(stdout, "Done.\n");

  if (DEBUG > 0) {
    fprintf(stdout, "\n");
    print_config_summary(stdout);
    fprintf(stdout, "\n");
  }

  // seed random number generator
  portable_srandom((uint64_t)SEED);

  // open image file
  out = fopen(OUTPUTFILE, "wb");
  if (! out) {
    fprintf(stderr, "%s", RED);
    fprintf(stderr, "Fatal error: Can't open output file \"%s\".\n", OUTPUTFILE);
    fprintf(stderr, "%s", BLACK);
    // fatal
    return -1;
  }

  // get pathname for .key file
  snprintf(outlog_fn, sizeof(outlog_fn), "%s.key", OUTPUTFILE);
  outlog = fopen(outlog_fn, "w");
  if (! outlog) {
    fprintf(stderr, "%s", RED);
    fprintf(stderr, "Fatal error: Can't open output file \"%s\".\n", outlog_fn);
    fprintf(stderr, "%s", BLACK);
    // fatal
    return -1;
  }

  // create set of clusters that comprise image file
  fprintf(stdout, "Generating randomized layout for clusters, please wait\n");
  create_clusters();
  fprintf(stdout, "Done.\n");

  // generate image file and .key file
  fprintf(stdout, "Generating output files \"%s\" and \n\"%s\", please wait...    ", OUTPUTFILE, outlog_fn);
  fflush(stdout);
  fail = ! generate_output(out, outlog);
  fclose(out);
  fclose(outlog);

  if (fail) {
    fprintf(stderr, "%s", RED);
    fprintf(stderr, "Deleting output files.\n");
    fprintf(stderr, "%s", BLACK);
    unlink(OUTPUTFILE);
    unlink(outlog_fn);
    return -1;
  }
  else {
    fprintf(stdout, "Wrote %" PRIu64 " files into image, total blocks = %" PRId64 ".\n", FILENUM + 1, TOTALBLOCKS);
    fprintf(stdout, "All done.\n");
    return 0;
  }
}

