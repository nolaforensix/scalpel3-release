//
// Scalpel3 is Copyright(C) 2021 - 2026 by Golden G. Richard III and contributors.
//
// This program is free software : you can redistribute it and / or modify it under the terms of the GNU General Public
// License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later
// version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied
// warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along with this program. If not, see
// <https://www.gnu.org/licenses/>.
//
//------------------------------
// Additional Integration Terms
// -----------------------------
//
// Linking or embedding Scalpel3 (statically or dynamically) into another program such that the resulting executable or
// library forms a single combined work constitutes creation of a derivative work under the GPL. Any party distributing
// such a combined work must make the entire source code available under the terms of the GPL as well.
//
// Commercial entities wishing to use Scalpel3 in a closed-source or proprietary product or requiring support must
// obtain a separate commercial license.
//
// For commercial licensing or questions about integration, contact: Golden G. Richard III (golden@cct.lsu.edu).
//
// Please see LICENSE.md and README.md for further information.
//
//
// Manipulates an existing scalpel3 blockmap, allowing covering and uncovering single blocks as well as ranges of
// blocks. This version uses the new blockmap format as defined in blockmap.h, which supports deduplication. This
// version is NOT compatible with older versions of scalpel3, crblockmap, or modblockmap.
//
// Design and implementation Copyright (c) 2021-2026 by Golden G. Richard III (@nolaforensix) and 2024-2026 by Karley
// Waguespack.
//
// Block ranges must NOT contain whitespace and blocks are numbered starting from 0. If only the blockmap filename and
// blocksize are provided, then the contents of the blockmap is displayed and no changes are made.
//
// See "blockmap.h" for blockmap format.
//
// July 2023: Support for traditional forensics tools that generate logs is a work in progress. The following tools are
// currently supported:
//
//////////////////////////////////////////////////////////////////////////
///////////////////////////// photorec 7.2+ //////////////////////////////
//////////////////////////////////////////////////////////////////////////
//
// photorec must be executed from the command line, using one of these formats:
//
// Example: recover ALL file types:

// photorec /log /logname photorec.log /d ./photorec_recovered /cmd <imagename>
//          partition_none,blocksize,<blocksize>,fileopt,everything,enable,search
//
// Example: recover only jpg, gif, zip:
//
// photorec /log /logname photorec.log /d ./photorec_recovered /cmd <imagename>
//          partition_none,blocksize,<blocksize>,fileopt,everything,disable,jpg,
//          enable,gif,enable,zip,enable,search
//
// Command line execution must be used because photorec does not allow explicit specification of block sizes within the
// text GUI.
//
// **IMPORTANT**: the pathname argument for "/d" must not contain spaces!
//
// modblockmap can then be used to mark blocks associated with successfully recovered files using a command line like
// this:
//
// ./modblockmap -q <blocksize> <img_filename> <blockmap_filename> photorec photorec.log
//

#define SCALPEL3_EXTERNAL 1
#include "scalpel.h"
#include "blockmap.h"
#include "colors.h"
#include "scalpelv.h"
#include <ctype.h>
#include <dirent.h>
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

#define MODBLOCKMAP_BANNER_STRING                                                                                      \
  "modblockmap v%s -- "                                                                                                \
  "Written by Golden G. Richard III (@nolaforensix).",                                                                 \
      SCALPEL_VERSION

#define MAX_STRING_LENGTH (4096 + 1)

typedef enum ToolResult {
  TOOL_RESULT_ERROR = -1,
  TOOL_RESULT_NO_CHANGES = 0,
  TOOL_RESULT_CHANGED = 1
} ToolResult;

typedef struct Tool {
  char toolname[PATH_MAX];
  ToolResult (*tool)(Blockmap *blockmap, char *logfile);
} Tool;

typedef struct PhotorecRange {
  int64_t first;
  int64_t last;
} PhotorecRange;


// function prototypes for local functions
static int32_t detect_tool(char *tool);
static bool numeric(char *s);
static void modblockmap_logo(void);
static void usage(void);


// function prototypes for external tool handling functions
static bool extract_photorec_target(char *line, char target[PATH_MAX]);
static ToolResult handle_photorec(Blockmap *blockmap, char *logfile);
static bool parse_photorec_range(const char *text, int64_t *first, int64_t *last);
static bool photorec_path_matches_target(const char *path, const char *target);

//////////////////////////////////////////////////////////
// DEFINITIONS FOR EXTERNAL TOOL HANDLING FUNCTIONS //
//////////////////////////////////////////////////////////

//////////////
// PHOTOREC //
//////////////

// extract the whitespace-delimited /d argument from a photorec command line.
static bool extract_photorec_target(char *line, char target[PATH_MAX]) {

  char *saveptr = NULL;
  char *token;
  size_t length;

  token = strtok_r(line, " \t\r\n", &saveptr);
  while (token) {
    if (! strcmp(token, "/d")) {
      token = strtok_r(NULL, " \t\r\n", &saveptr);
      if (! token || ! copy_string_complete(target, PATH_MAX, token)) {
        return false;
      }

      // normalize trailing separators so both target/ and target.1 records match.
      length = strlen(target);
      while (length > 1 && target[length - 1] == '/') {
        target[--length] = 0;
      }
      return true;
    }
    token = strtok_r(NULL, " \t\r\n", &saveptr);
  }

  return false;
}


// return true only when path names the configured photorec output or one of its numbered directories.
static bool photorec_path_matches_target(const char *path, const char *target) {

  size_t target_length = strlen(target);

  return ! strncmp(path, target, target_length) &&
         (path[target_length] == 0 || path[target_length] == '/' || path[target_length] == '.');
}


// parse a complete nonnegative m-n range without accepting signs, overflow, or trailing data.
static bool parse_photorec_range(const char *text, int64_t *first, int64_t *last) {

  char *endptr;
  intmax_t value;

  if (! text || ! isdigit((unsigned char)text[0])) {
    return false;
  }

  errno = 0;
  value = strtoimax(text, &endptr, 10);
  if (errno == ERANGE || value < 0 || *endptr != '-') {
    return false;
  }
  *first = (int64_t)value;

  text = endptr + 1;
  if (! isdigit((unsigned char)text[0])) {
    return false;
  }

  errno = 0;
  value = strtoimax(text, &endptr, 10);
  if (errno == ERANGE || value < 0 || *endptr != 0) {
    return false;
  }
  *last = (int64_t)value;

  return *first <= *last;
}


// process a complete photorec log transactionally, then cover blocks associated with recovered files.
static ToolResult handle_photorec(Blockmap *blockmap, char *logfile) {

  char target[PATH_MAX] = "";
  char *line = NULL;
  char *command;
  char *path;
  char *range_text;
  char *saveptr;
  FILE *fp = NULL;
  PhotorecRange *ranges = NULL;
  PhotorecRange *grown;
  size_t line_capacity = 0;
  size_t line_number = 0;
  size_t range_capacity = 0;
  size_t range_count = 0;
  size_t new_capacity;
  int64_t first;
  int64_t last;
  int64_t block;
  bool target_found = false;
  ToolResult result = TOOL_RESULT_ERROR;

  if (! (fp = fopen(logfile, "r"))) {
    fprintf(stderr, "%s", RED);
    fprintf(stderr, "Failed to open photorec log file \"%s\". No updates performed. Aborting.\n", logfile);
    fprintf(stderr, "%s", BLACK);
    goto done;
  }

  while (getline(&line, &line_capacity, fp) >= 0) {
    line_number++;

    if (! target_found && (command = strstr(line, "Command line:"))) {
      if (! extract_photorec_target(command, target)) {
        fprintf(stderr, "%s", RED);
        fprintf(stderr,
                "Failed to get /d argument from photorec log file \"%s\" at line %zu. "
                "No updates performed. Aborting.\n",
                logfile, line_number);
        fprintf(stderr, "%s", BLACK);
        goto done;
      }
      target_found = true;
      continue;
    }

    if (! target_found) {
      continue;
    }

    saveptr = NULL;
    path = strtok_r(line, " \t\r\n", &saveptr);
    if (! path || ! photorec_path_matches_target(path, target)) {
      continue;
    }

    range_text = strtok_r(NULL, " \t\r\n", &saveptr);
    if (! parse_photorec_range(range_text, &first, &last)) {
      fprintf(stderr, "%s", RED);
      fprintf(stderr,
              "ERROR: Bad range format in photorec log file \"%s\" at line %zu. "
              "No updates performed. Aborting.\n",
              logfile, line_number);
      fprintf(stderr, "%s", BLACK);
      goto done;
    }

    if ((uint64_t)first >= blockmap->numblocks || (uint64_t)last >= blockmap->numblocks) {
      fprintf(stderr, "%s", RED);
      fprintf(stderr,
              "ERROR: Bad block range %" PRId64 "-%" PRId64
              " in photorec log file \"%s\" at line %zu. No updates performed. Aborting.\n",
              first, last, logfile, line_number);
      fprintf(stderr, "%s", BLACK);
      goto done;
    }

    if (range_count == range_capacity) {
      if (range_capacity > SIZE_MAX / 2) {
        fprintf(stderr, "%s", RED);
        fprintf(stderr,
                "ERROR: Too many ranges in photorec log file \"%s\". No updates performed. Aborting.\n",
                logfile);
        fprintf(stderr, "%s", BLACK);
        goto done;
      }

      new_capacity = range_capacity ? range_capacity * 2 : 64;
      if (new_capacity > SIZE_MAX / sizeof(*ranges)) {
        fprintf(stderr, "%s", RED);
        fprintf(stderr,
                "ERROR: Too many ranges in photorec log file \"%s\". No updates performed. Aborting.\n",
                logfile);
        fprintf(stderr, "%s", BLACK);
        goto done;
      }

      grown = realloc(ranges, new_capacity * sizeof(*ranges));
      check_memory_allocation(grown, __LINE__, __FILE__, "photorec block ranges");
      ranges = grown;
      range_capacity = new_capacity;
    }

    ranges[range_count++] = (PhotorecRange){.first = first, .last = last};
  }

  if (ferror(fp)) {
    fprintf(stderr, "%s", RED);
    fprintf(stderr, "ERROR: Failed to read photorec log file \"%s\". No updates performed. Aborting.\n", logfile);
    fprintf(stderr, "%s", BLACK);
    goto done;
  }

  if (! target_found) {
    fprintf(stderr, "%s", RED);
    fprintf(stderr, "Failed to get /d argument from photorec log file \"%s\". No updates performed. Aborting.\n",
            logfile);
    fprintf(stderr, "%s", BLACK);
    goto done;
  }

  if (fclose(fp)) {
    fp = NULL;
    fprintf(stderr, "%s", RED);
    fprintf(stderr, "ERROR: Failed to close photorec log file \"%s\". No updates performed. Aborting.\n", logfile);
    fprintf(stderr, "%s", BLACK);
    goto done;
  }
  fp = NULL;

  for (size_t i = 0; i < range_count; i++) {
    first = ranges[i].first;
    last = ranges[i].last;

    if ((uint64_t)first < blockmap->start_block || (uint64_t)first > blockmap->end_block) {
      fprintf(stderr, "%s", BLUE);
      fprintf(stderr,
              "\nWARNING: Start of range block %" PRId64
              " in photorec log is outside the active carve window %" PRIu64 " - %" PRIu64 ".\n\n",
              first, blockmap->start_block, blockmap->end_block);
      fprintf(stderr, "%s", BLACK);
    }

    if ((uint64_t)last < blockmap->start_block || (uint64_t)last > blockmap->end_block) {
      fprintf(stderr, "%s", BLUE);
      fprintf(stderr,
              "\nWARNING: End of range block %" PRId64
              " in photorec log is outside the active carve window %" PRIu64 " - %" PRIu64 ".\n\n",
              last, blockmap->start_block, blockmap->end_block);
      fprintf(stderr, "%s", BLACK);
    }

    fprintf(stdout, "Covering blocks in the range %" PRId64 "-%" PRId64 ".\n", first, last);
    for (block = first;; block++) {
      cover_block(blockmap, block);
      if (block == last) {
        break;
      }
    }
  }

  result = range_count ? TOOL_RESULT_CHANGED : TOOL_RESULT_NO_CHANGES;

done:
  if (fp) {
    fclose(fp);
  }
  free(line);
  free(ranges);
  return result;
}

//////////////////////////////////////////////////////////
// END DEFINITIONS FOR EXTERNAL TOOL HANDLING FUNCTIONS //
//////////////////////////////////////////////////////////

// list of tool names and handler functions. The array *MUST* be terminated with a NULL entry!
Tool tools[] = {{.toolname = "photorec", .tool = handle_photorec},

                // DO NOT REMOVE THIS ELEMENT
                {.toolname = "", .tool = NULL}};


// returns true if 's' contains only digits 0-9, otherwise false
static bool numeric(char *s) {

  uint32_t i;

  for (i = 0; i < strlen(s); i++) {
    if (s[i] != 32 && (s[i] < '0' || s[i] > '9')) {
      return false;
    }
  }

  return true;
}


// detect a user specified third-party tool for log processing
static int32_t detect_tool(char *tool) {

  int32_t toolidx = -1;

  for (int32_t i = 0; toolidx == -1 && tools[i].toolname[0] && tools[i].tool; i++) {
    if (! strcmp(tool, tools[i].toolname)) {
      toolidx = i;
    }
  }

  return toolidx;
}


static void usage(void) {

  int i;

  fprintf(stderr, "%s", BLUE);
  fprintf(stderr, "Usage: modblockmap [-j start_block] [-k end_block] img_filename  blockmap_filename\n"
                  "       [0:block#]          [1:block#]           [?:block#]\n"
                  "       [0:block#-block#]   [1:block#-block#]    [?:block#-block#]\n"
                  "       [toolname tool_log_filename]\n\n"
                  "0 = uncover block, 1 = cover block, ? = query status of block.\n\n"
		  "If start_block and end_block are specified, the active carve window is modified.\n\n"
                  "If only the img filename and blockmap filename are provided, then the contents of the blockmap\n"
                  "is displayed.\n\n"
                  "Tools supported by this release:\n");

  for (i = 0; tools[i].toolname[0]; i++) {
    fprintf(stderr, "\"%s\"\n", tools[i].toolname);
  }

  fprintf(stderr, "\n");
  fprintf(stderr, "%s", BLACK);
}


static void modblockmap_logo(void) {

  char *logo[] = {
      "\n",
      "\n",
      " .............................................................................................................\n",
      ".                                                                                                             .\n",
      ".  888b     d888               888 888888b.   888                   888      888b     d888                    .\n",
      ".  8888b   d8888               888 888  \"88b  888                   888      8888b   d8888                    .\n",
      ".  88888b.d88888               888 888  .88P  888                   888      88888b.d88888                    .\n",
      ".  888Y88888P888  .d88b.   .d88888 8888888K.  888  .d88b.   .d8888b 888  888 888Y88888P888  8888b.  88888b.   .\n",
      ".  888 Y888P 888 d88\"\"88b d88\" 888 888  \"Y88b 888 d88\"\"88b d88P\"    888 .88P 888 Y888P 888     \"88b 888 \"88b  .\n",
      ".  888  Y8P  888 888  888 888  888 888    888 888 888  888 888      888888K  888  Y8P  888 .d888888 888  888  .\n",
      ".  888   \"   888 Y88..88P Y88b 888 888   d88P 888 Y88..88P Y88b.    888 \"88b 888   \"   888 888  888 888 d88P  .\n",
      ".  888       888  \"Y88P\"   \"Y88888 8888888P\"  888  \"Y88P\"   \"Y8888P 888  888 888       888 \"Y888888 88888P\"   .\n",
      ".                                                                                                   888       .\n",
      ".                                                                                                   888       .\n",
      ".                                                                                                   888       .\n",
      " .............................................................................................................\n",
      ""};

  int i = 0;
  size_t j;
  size_t len;

  // only display logo if the terminal is wide enough
  if (get_terminal_width() < 112) {
    return;
  }

  while (logo[i][0]) {
    len = strlen(logo[i]);
    for (j = 0; j < len; j++) {
      if (isspace(logo[i][j]) || i < 3 || i > 14 || j < 2 || j > 107) {
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


int main(int argc, char *argv[]) {

  char imagefn[PATH_MAX];
  char blockmapfn[PATH_MAX];
  char buf[PATH_MAX];
  FILE *f = NULL;
  int64_t block, block1, block2;
  char *dash;
  char *endptr;
  int i;
  int64_t j;
  uint64_t start_block = 0, end_block = 0;
  bool start_block_set = false, end_block_set = false;
  int32_t toolidx;
  uint64_t deduped, zeroblocks;
  uint64_t numblocks;
  long long temp;
  Blockmap *blockmap;
  bool changes = false;
  ToolResult tool_result;

#if DISABLE_COLOR > 0
  DISABLE_ALL_COLOR;
#endif

  // don't use color for redirected output
  if (! isatty(1) || ! isatty(2)) {
    DISABLE_ALL_COLOR;
  }

  modblockmap_logo();
  fprintf(stdout, "%s", BLUE);
  fprintf(stdout, MODBLOCKMAP_BANNER_STRING);
  fprintf(stdout, "%s", BLACK);
  fprintf(stdout, "\n\n");

  if (argc < 2) {
    usage();
    fprintf(stderr, "%s", RED);
    fprintf(stderr, "\nERROR: Both <imgfilename> and <blockmapfilename> are required. Aborting.\n");
    fprintf(stderr, "%s", BLACK);
    return -1;
  }

  while ((i = getopt(argc, argv, "+j:k:")) != -1) {
    switch (i) {

    case 'j':
      errno = 0;
      temp = strtoll(optarg, &endptr, 10);
      if (errno != 0 || *endptr != '\0' || temp < 0) {
        fprintf(stderr, "%s", RED);
        fprintf(stderr, "\nERROR: Start block for -j option must be >= 0. Aborting.\n");
        fprintf(stderr, "%s", BLACK);
        return -1;
      }
      start_block = (uint64_t)temp;
      start_block_set = true;
      break;

    case 'k':
      errno = 0;
      temp = strtoll(optarg, &endptr, 10);
      if (errno != 0 || *endptr != '\0' || temp < 0) {
        fprintf(stderr, "%s", RED);
        fprintf(stderr, "\nERROR: End block for -k option must be >= 0. Aborting.\n");
        fprintf(stderr, "%s", BLACK);
        return -1;
      }
      end_block = (uint64_t)temp;
      end_block_set = true;
      break;
    }
  }

  if (optind < argc && argv[optind]) {
    // image filename
    if (! copy_string_complete(imagefn, sizeof(imagefn), argv[optind])) {
      fprintf(stderr, "%s", RED);
      fprintf(stderr,
              "\nERROR: Image pathname is too long (maximum %zu characters). Aborting.\n",
              sizeof(imagefn) - 1);
      fprintf(stderr, "%s", BLACK);
      return -1;
    }
  }
  else {
    fprintf(stderr, "%s", RED);
    fprintf(stderr, "\nERROR: <imgfilename> must be provided. Aborting.\n");
    fprintf(stderr, "%s", BLACK);
    return -1;
  }

  optind++;

  if (optind < argc && argv[optind]) {
    if (! copy_string_complete(blockmapfn, sizeof(blockmapfn), argv[optind])) {
      fprintf(stderr, "%s", RED);
      fprintf(stderr,
              "\nERROR: Blockmap pathname is too long (maximum %zu characters). Aborting.\n",
              sizeof(blockmapfn) - 1);
      fprintf(stderr, "%s", BLACK);
      return -1;
    }
  }
  else {
    fprintf(stderr, "%s", RED);
    fprintf(stderr, "\nERROR: <blockmapfilename> must be provided. Aborting.\n");
    fprintf(stderr, "%s", BLACK);
    return -1;
  }

  optind++;

  f = fopen(blockmapfn, "rb");
  if (! f) {
    fprintf(stderr, "%s", RED);
    fprintf(stderr, "\nERROR: Couldn't open blockmap file \"%s\". Aborting.\n", blockmapfn);
    fprintf(stderr, "%s", BLACK);
    return -1;
  }

  if (! read_blockmap(&blockmap, f)) {
    fprintf(stderr, "%s", RED);
    fprintf(stderr, "\nERROR: Couldn't read blockmap from file \"%s\". Aborting.\n", blockmapfn);
    fprintf(stderr, "%s", BLACK);
    fclose(f);
    return -1;
  }

  if (blockmap->blocksize < 512 || blockmap->blocksize % 512) {
    fprintf(stderr, "%s", RED);
    fprintf(stderr,
            "\nERROR: Something is very wrong with the blockmap file \"%s\"!\n"
            "Blocksize must be >= 512 bytes and a multiple of 512. Aborting.\n",
            blockmapfn);
    fprintf(stderr, "%s", BLACK);
    fclose(f);
    return -1;
  }

  fclose(f);

  if (! start_block_set) {
    start_block = blockmap->start_block;
  }

  if (! end_block_set) {
    end_block = blockmap->end_block;
  }

  f = fopen(imagefn, "rb");
  if (! f) {
    fprintf(stderr, "%s", RED);
    fprintf(stderr, "\nERROR: Couldn't open image file \"%s\". Aborting.\n", imagefn);
    fprintf(stderr, "%s", BLACK);
    return -1;
  }

  // discover actual size of image file
  fseek(f, 0, SEEK_END);
  numblocks = CEILDIV(ftello(f), blockmap->blocksize);

  if (numblocks != blockmap->numblocks) {
    fprintf(stderr, "%s", RED);
    fprintf(stderr, "\nERROR: The number of blocks represented by the blockmap must be exactly the same as \n"
                    "the number of blocks in the image file.  Aborting.\n");
    fprintf(stderr, "%s", BLACK);
    fclose(f);
    return -1;
  }

  if (start_block > end_block || start_block > numblocks - 1 || end_block > numblocks - 1) {
    fprintf(stderr, "%s", RED);
    fprintf(stderr, "\nERROR: Active carve window start block must be <= end block and both must be <= the number\n"
                    "of blocks in the image file for -j and -k options. Aborting.\n");
    fprintf(stderr, "%s", BLACK);
    fclose(f);
    return -1;
  }

  if (optind == argc && ! start_block_set && ! end_block_set) {
    // no modifications, just display blockmap
    display_blockmap(blockmap);
    fclose(f);
    return 0;
  }

  if ((start_block_set || end_block_set) && start_block == blockmap->start_block && end_block == blockmap->end_block) {
    fprintf(stdout,
            "\nSpecified start / end blocks for active carve window match existing window, no changes necessary.\n");
  }

  if (optind == argc && start_block == blockmap->start_block && end_block == blockmap->end_block) {
    // nothing more to do
    fclose(f);
    return 0;
  }

  // adjust active window, if necessary. This will cause dedup to be recalculated.
  if (start_block != blockmap->start_block || end_block != blockmap->end_block) {
    fprintf(stdout, "\nAdjusting active window from %" PRId64 " - %" PRId64 " to %" PRId64 " - %" PRId64 "...\n",
            blockmap->start_block, blockmap->end_block, start_block, end_block);
    set_blockmap_window(blockmap, start_block, end_block);
    dedup_blockmap(blockmap, f, &deduped, &zeroblocks, true);
    changes = true;
  }

  fclose(f);

  // now process any blockmap update requests. Updates are allowed outside the active window, although warnings are
  // emitted for these cases.

  i = optind;
  while (i < argc) {
    if (! copy_string_complete(buf, sizeof(buf), argv[i])) {
      fprintf(stderr, "%s", RED);
      fprintf(stderr,
              "\nERROR: Blockmap update request is too long (maximum %zu characters). Aborting.\n",
              sizeof(buf) - 1);
      fprintf(stderr, "%s", BLACK);
      return -1;
    }

    if ((toolidx = detect_tool(buf)) >= 0) {
      // get logfile
      i++;
      if (i >= argc) {
        fprintf(stderr, "%s", RED);
        fprintf(stderr, "\nERROR: Log file must be specified for tool \"%s\".  No updates performed. Aborting.\n", buf);
        fprintf(stderr, "%s", BLACK);
        return -1;
      }

      tool_result = tools[toolidx].tool(blockmap, argv[i]);
      if (tool_result == TOOL_RESULT_ERROR) {
        return -1;
      }
      if (tool_result == TOOL_RESULT_CHANGED) {
        changes = true;
      }
    }
    else if (isalpha(buf[0])) {
      fprintf(stderr, "%s", RED);
      fprintf(stderr, "\nERROR: Bad tool name \"%s\". No updates performed. Aborting.\n", buf);
      fprintf(stderr, "%s", BLACK);
      return -1;
    }
    else {
      // format check for single blockmap operations
      if ((buf[0] != '0' && buf[0] != '1' && buf[0] != '?') || strlen(buf) < 2 || buf[1] != ':') {
        fprintf(stderr, "%s", RED);
        fprintf(stderr,
                "\nERROR: Bad formatting for block modification request \"%s\". No updates performed. Aborting.\n",
                buf);
        fprintf(stderr, "%s", BLACK);
        return -1;
      }

      if (! (dash = (strchr(buf, '-')))) {
        // single block
        block = atoll(buf + 2);
        fprintf(stderr, "%s", RED);
        if (! numeric(buf + 2) || block < 0 || block > (int64_t)blockmap->numblocks - 1) {
          fprintf(stderr,
                  "\nERROR: Block numbers must be in the range 0 <= n <= %" PRIu64
                  ".  No updates performed. Aborting.\n",
                  blockmap->numblocks);
          fprintf(stderr, "%s", BLACK);
          return -1;
        }

        if (block < (int64_t)blockmap->start_block || block > (int64_t)blockmap->end_block) {
          fprintf(stderr, "%s", BLUE);
          fprintf(stderr,
                  "\nWARNING: Operation on block %" PRIu64 ", which is outside the active carve window %" PRId64
                  " - %" PRId64 ".\n\n",
                  block, blockmap->start_block, blockmap->end_block);
          fprintf(stderr, "%s", BLACK);
        }

        if (buf[0] == '1') {
          cover_block(blockmap, block);
          changes = true;
        }
        else if (buf[0] == '0') {
          uncover_block(blockmap, block);
          changes = true;
        }

        fprintf(stdout, "Block %7" PRIu64 " status:  (C / D / E / Z / refcount) is: ", block);
        display_blockmap_entry(blockmap, block);
        putchar('\n');
      }
      else {
        // range
        *dash = 0;
        block1 = atoll(buf + 2);
        *dash = ' ';
        block2 = atoll(dash);

        if (! numeric(buf + 2) || ! numeric(dash) || block1 < 0 || block1 > (int64_t)blockmap->numblocks - 1 ||
            block2 < 0 || block2 > (int64_t)blockmap->numblocks - 1) {
          fprintf(stderr, "%s", RED);
          fprintf(stderr,
                  "\nERROR: Block numbers must be in the range 0 <= n <= %" PRIu64
                  ".  No updates performed. Aborting.\n",
                  blockmap->numblocks);
          fprintf(stderr, "%s", BLACK);
          return -1;
        }

        if (block1 > block2) {
          fprintf(stderr, "%s", RED);
          fprintf(stderr, "\nERROR: The first block number in the range must be <= the second block number.\n"
                          "No updates performed. Aborting.\n");
          fprintf(stderr, "%s", BLACK);
          return -1;
        }

        if (block1 < (int64_t)blockmap->start_block || block1 > (int64_t)blockmap->end_block) {
          fprintf(stderr, "%s", BLUE);
          fprintf(stderr,
                  "\nWARNING: Start of range block %" PRIu64 " is outside the active carve window %" PRId64
                  " - %" PRId64 ".\n\n",
                  block1, blockmap->start_block, blockmap->end_block);
          fprintf(stderr, "%s", BLACK);
        }

        if (block2 < (int64_t)blockmap->start_block || block2 > (int64_t)blockmap->end_block) {
          fprintf(stderr, "%s", BLUE);
          fprintf(stderr,
                  "\nWARNING: End of of range block %" PRIu64 " is outside the active carve window %" PRId64
                  " - %" PRId64 ".\n\n",
                  block2, blockmap->start_block, blockmap->end_block);
          fprintf(stderr, "%s", BLACK);
        }

        if (buf[0] == '1') {
          fprintf(stdout, "Covering blocks in the range %" PRIu64 "-%" PRIu64 ".\n", block1, block2);
        }
        else if (buf[0] == '0') {
          fprintf(stdout, "Uncovering blocks in the range %" PRIu64 "-%" PRIu64 ".\n", block1, block2);
        }

        for (j = block1; j <= block2; j++) {
          if (buf[0] == '1') {
            cover_block(blockmap, j);
            changes = true;
          }
          else if (buf[0] == '0') {
            uncover_block(blockmap, j);
            changes = true;
          }
          else {
            fprintf(stdout, "Block %" PRIu64 " status (C / D / E / Z / refcount) is: ", j);
            display_blockmap_entry(blockmap, j);
            putchar('\n');
          }
        }
      }
    }
    // next arg
    i++;
  }

  if (changes) {
    // write updated blockmap
    fprintf(stdout, "\nWriting updated blockmap \"%s\"...\n", blockmapfn);

    f = fopen(blockmapfn, "wb");
    if (! f) {
      fprintf(stderr, "%s", RED);
      fprintf(stderr, "\nERROR: Couldn't update blockmap file \"%s\". Aborting.\n", blockmapfn);
      fprintf(stderr, "%s", BLACK);
      return -1;
    }

    if (! write_blockmap(blockmap, f)) {
      fprintf(stderr, "%s", RED);
      fprintf(stderr,
              "\nERROR: Couldn't write new blockmap file \"%s\". The blockmap will need\n"
              "to be recreated. Aborting.\n",
              blockmapfn);
      fprintf(stderr, "%s", BLACK);
      goto die;
    }

    fclose(f);
  }

  fprintf(stdout, "Done.\n");

  return 0;

die:
  fclose(f);
  unlink(blockmapfn);
  return -1;
}
