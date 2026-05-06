//
// Scalpel3 is Copyright(C) 2021 - 2026 by Golden G.Richard III and contributors.
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
// Creates an empty blockmap associated with an image file and blocksize and performs block deduplication. This version
// uses a new blockmap format that includes deduplication and reference count info, as defined in blockmap.h.
//
// This version is NOT compatible with older versions of scalpel3, crblockmap, or modblockmap.
//
// Design and implementation Copyright (c) 2021-2026 by Golden G. Richard III (@nolaforensix) and 2024-2026 by Karley
// Waguespack.
//
// See "blockmap.h" for blockmap format.
//

#define SCALPEL3_EXTERNAL 1
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <math.h>
#include <openssl/sha.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>
#define SCALPEL3_EXTERNAL 1
#include "scalpel.h"
#include "blockmap.h"
#include "colors.h"
#include "hashv4.h"
#include "scalpelv.h"


#define CRBLOCKMAP_BANNER_STRING                                                                                       \
  "crblockmap v%s -- "                                                                                                 \
  "Written by Golden G. Richard III (@nolaforensix).",                                                                 \
      SCALPEL_VERSION

#define MAX_STRING_LENGTH (4096 + 1)

// function prototypes for private crblockmap functions
static void usage(void);
static void crblockmap_logo(void);


static void crblockmap_logo(void) {

  char *logo[] = {
      "\n",
      "\n",
      " ................................................................................................\n",
      ".                                                                                                .\n",
      ".   .d8888b.          888888b.   888                   888      888b     d888                    .\n",
      ".  d88P  Y88b         888  \"88b  888                   888      8888b   d8888                    .\n",
      ".  888    888         888  .88P  888                   888      88888b.d88888                    .\n",
      ".  888        888d888 8888888K.  888  .d88b.   .d8888b 888  888 888Y88888P888  8888b.  88888b.   .\n",
      ".  888        888P\"   888  \"Y88b 888 d88\"\"88b d88P\"    888 .88P 888 Y888P 888     \"88b 888 \"88b  .\n",
      ".  888    888 888     888    888 888 888  888 888      888888K  888  Y8P  888 .d888888 888  888  .\n",
      ".  Y88b  d88P 888     888   d88P 888 Y88..88P Y88b.    888 \"88b 888   \"   888 888  888 888 d88P  .\n",
      ".   \"Y8888P\"  888     8888888P\"  888  \"Y88P\"   \"Y8888P 888  888 888       888 \"Y888888 88888P\"   .\n",
      ".                                                                                      888       .\n",
      ".                                                                                      888       .\n",
      ".                                                                                      888       .\n",
      " ................................................................................................\n",
      ""};

  int i = 0;
  size_t j;
  size_t len;

  // refuse to print a logo that is wider than terminal width

  if (get_terminal_width() < 99) {
    return;
  }

  while (logo[i][0]) {
    len = strlen(logo[i]);
    for (j = 0; j < len; j++) {
      if (isspace(logo[i][j]) || i < 3 || i > 14 || j < 2 || j > 94) {
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


static void usage(void) {

  fprintf(stderr, "%s", BLUE);
  fprintf(stderr, "Usage: crblockmap [-j startblock] [-k endblock] [-q clustersize] img_filename blockmap_filename\n\n"
                  "The arguments to -j and -k specify a carve window for the image file.\n"
                  "Deduplication and zero block detection will occur only inside this window.\n"
                  "Blocks outside this window are considered implicitly covered by scalpel3\n"
                  "and the scalpel3 toolchain.\n\n");
  fprintf(stderr, "%s", BLACK);
}


int main(int argc, char *argv[]) {

  FILE *imgfile = NULL;
  FILE *blockmapfile = NULL;
  Blockmap *blockmap = NULL;
  char imgfn[PATH_MAX];
  char blockmapfn[PATH_MAX * 2];
  uint64_t deduped = 0;
  uint64_t zeroblocks = 0;
  uint64_t filesize;
  uint64_t numblocks;
  uint64_t start_block = 0, end_block = 0;
  bool start_block_set = false, end_block_set = false;
  int32_t arg;
  uint32_t blocksize = SCALPEL_BLOCK_SIZE;
  char *endptr;
  long long temp;

#if DISABLE_COLOR > 0
  DISABLE_ALL_COLOR;
#endif

  // don't use color for redirected output
  if (! isatty(1) || ! isatty(2)) {
    DISABLE_ALL_COLOR;
  }

  crblockmap_logo();
  fprintf(stdout, "%s", BLUE);
  fprintf(stdout, CRBLOCKMAP_BANNER_STRING);
  fprintf(stdout, "\n\n");
  fprintf(stdout, "%s", BLACK);

  fprintf(stderr, "%s", RED);
  while ((arg = getopt(argc, argv, "+j:k:q:")) != -1) {
    switch (arg) {
    case 'j':
      errno = 0;
      temp = strtoll(optarg, &endptr, 10);
      if (errno != 0 || *endptr != '\0' || temp < 0) {
        fprintf(stderr, "\nERROR: Start block for -j option must be >= 0.  Aborting.\n");
        fprintf(stderr, "%s", BLACK);
        exit(-1);
      }
      start_block = (uint64_t)temp;
      start_block_set = true;
      break;

    case 'k':
      errno = 0;
      temp = strtoll(optarg, &endptr, 10);
      if (errno != 0 || *endptr != '\0' || temp < 0) {
        fprintf(stderr, "\nERROR: End block for -k option must be >= 0.  Aborting.\n");
        fprintf(stderr, "%s", BLACK);
        exit(-1);
      }
      end_block = (uint64_t)temp;
      end_block_set = true;
      break;

    case 'q':
      errno = 0;
      temp = strtol(optarg, &endptr, 10);
      if (errno != 0 || *endptr != '\0' || temp < 0 || temp % 512) {
        fprintf(stderr, "\nERROR: blocksize for -q option must be >= 512 and a multiple of 512.  Aborting.\n");
        fprintf(stderr, "%s", BLACK);
        exit(-1);
      }
      blocksize = (uint32_t)temp;
      break;


    default:
      usage();
      fprintf(stderr, "%s", BLACK);
      exit(-1);
    }
  }

  if (argc - optind < 2) {
    usage();
    fprintf(stderr, "%s", RED);
    fprintf(stderr, "\nERROR: Both <imgfilename> and <blockmapfilename> are required. Aborting.\n");
    fprintf(stderr, "%s", BLACK);
    return -1;
  }

  fprintf(stdout, "%s", BLACK);

  strncpy(imgfn, argv[optind], PATH_MAX / 2 - 1);
  imgfn[PATH_MAX / 2 - 1] = 0;
  optind++;
  strncpy(blockmapfn, argv[optind], PATH_MAX / 2 - 1);
  blockmapfn[PATH_MAX / 2 - 1] = 0;

  fprintf(stdout, "Image file:\t\t\t\t%s\"\n", imgfn);
  fprintf(stdout, "Blockmap file:\t\t\t\t\"%s\"\n", blockmapfn);
  fprintf(stdout, "Blocksize:\t\t\t\t%u\n", blocksize);

  // see if blockmap exists
  blockmapfile = fopen(blockmapfn, "rb");
  if (blockmapfile) {
    fclose(blockmapfile);
    fprintf(stderr, "%s", RED);
    fprintf(stderr,
            "\nERROR: Refusing to overwrite existing blockmap file \"%s\".\n"
            "Delete it and then run crblockmap again.  Aborting.\n",
            blockmapfn);
    fprintf(stderr, "%s", BLACK);
    return -1;
  }

  imgfile = fopen(imgfn, "rb");
  if (! imgfile) {
    fprintf(stderr, "%s", RED);
    fprintf(stderr, "\nERROR: Couldn't open image file \"%s\". Aborting.\n", imgfn);
    fprintf(stderr, "%s", BLACK);
    goto die;
  }

  // get size of image file
  fseek(imgfile, 0, SEEK_END);
  filesize = ftello(imgfile);
  fseek(imgfile, 0, SEEK_SET);

  // establish number of blocks that blockmap must cover
  numblocks = CEILDIV(filesize, blocksize);

  if (! start_block_set) {
    start_block = 0;
  }

  if (! end_block_set) {
    end_block = numblocks - 1;
  }

  fprintf(stdout, "Number of blocks in image file:\t\t%" PRIu64 "\n", numblocks);
  fprintf(stdout, "Active carve window:\t\t\t%" PRIu64 " - %" PRIu64 "\n\n", start_block, end_block);

  if (start_block > end_block || start_block > numblocks - 1 || end_block > numblocks - 1) {
    fprintf(stderr, "%s", RED);
    fprintf(stderr, "\nERROR: Active carve window start block must be <= end block and both must be <= the number\n"
                    "of blocks in the image file for -j and -k options. Aborting.\n");
    fprintf(stderr, "%s", BLACK);
    goto die;
  }

  blockmapfile = fopen(blockmapfn, "wb");
  if (! blockmapfile) {
    fprintf(stderr, "%s", RED);
    fprintf(stderr, "\nERROR: Couldn't create new blockmap file \"%s\". Aborting.\n", blockmapfn);
    fprintf(stderr, "%s", BLACK);
    goto die;
  }

  if (! allocate_blockmap(&blockmap, blocksize, numblocks)) {
    fprintf(stderr, "%s", RED);
    fprintf(stderr, "\nERROR: Memory exhausted while allocating blockmap. Aborting.\n");
    fprintf(stderr, "%s", BLACK);
    goto die;
  }

  set_blockmap_window(blockmap, start_block, end_block);

  if (! dedup_blockmap(blockmap, imgfile, &deduped, &zeroblocks, true)) {
    fprintf(stderr, "%s", RED);
    fprintf(stderr, "\nERROR: Couldn't complete deduplication and zero detection. Aborting.\n");
    fprintf(stderr, "%s", BLACK);
    goto die;
  }

  fprintf(stdout, "Done.\n");
  fprintf(stdout, "Writing blockmap...\n");

  if (! write_blockmap(blockmap, blockmapfile)) {
    fprintf(stderr, "%s", RED);
    fprintf(stderr, "\nERROR: Couldn't write blockmap to file \"%s\". Aborting.\n", blockmapfn);
    fprintf(stderr, "%s", BLACK);
    goto die;
  }

  fclose(imgfile);
  fclose(blockmapfile);

  if (blockmap) {
    free_blockmap(&blockmap);
  }

  fprintf(stdout, "Done.\n");

  return 0;

die:
  if (blockmap) {
    free(blockmap);
  }
  if (imgfile) {
    fclose(imgfile);
  }

  if (blockmapfile) {
    fclose(blockmapfile);
    unlink(blockmapfn);
  }

  return -1;
}

