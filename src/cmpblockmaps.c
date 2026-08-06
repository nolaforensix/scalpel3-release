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
//-----------------------------
// Additional Integration Terms
// ----------------------------
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
// Compares two scalpel3 blockmaps, outputting only differences.
//
// Design and implementation Copyright (c) 2021-2026 by Golden G. Richard III (@nolaforensix).
//
// See "blockmap.h" for blockmap format.
//

#define SCALPEL3_EXTERNAL
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
#include <math.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>

#define CMPBLOCKMAPS_BANNER_STRING                                                                                     \
  "cmpblockmaps v%s -- "                                                                                               \
  "Written by Golden G. Richard III (@nolaforensix).",                                                                 \
      SCALPEL_VERSION

#define MAX_STRING_LENGTH (4096 + 1)

static void cmpblockmaps_logo(void);

static void cmpblockmaps_logo(void) {

  char *logo[] = {
      "\n",
      "\n",
      " ........................................................................................................................\n",
      ".                                                                                                                        .\n",
      ".  .d8888b.  888b     d888 8888888b.  888888b.   888                   888      888b     d888                            .\n",
      ". d88P  Y88b 8888b   d8888 888   Y88b 888  \"88b  888                   888      8888b   d8888                            .\n",
      ". 888    888 88888b.d88888 888    888 888  .88P  888                   888      88888b.d88888                            .\n",
      ". 888        888Y88888P888 888   d88P 8888888K.  888  .d88b.   .d8888b 888  888 888Y88888P888  8888b.  88888b.  .d8888b  .\n",
      ". 888        888 Y888P 888 8888888P\"  888  \"Y88b 888 d88\"\"88b d88P\"    888 .88P 888 Y888P 888     \"88b 888 \"88b 88K      .\n",
      ". 888    888 888  Y8P  888 888        888    888 888 888  888 888      888888K  888  Y8P  888 .d888888 888  888 \"Y8888b. .\n",
      ". Y88b  d88P 888   \"   888 888        888   d88P 888 Y88..88P Y88b.    888 \"88b 888   \"   888 888  888 888 d88P      X88 .\n",
      ".  \"Y8888P\"  888       888 888        8888888P\"  888  \"Y88P\"   \"Y8888P 888  888 888       888 \"Y888888 88888P\"   88888P' .\n",
      ".                                                                                                      888               .\n",
      ".                                                                                                      888               .\n",
      ".                                                                                                      888               .\n",
      " ........................................................................................................................\n",
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
      if (isspace(logo[i][j]) || i < 3 || i > 14 || j < 2 || j > 120) {
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

  char fn1[PATH_MAX], fn2[PATH_MAX];
  FILE *f1, *f2;
  Blockmap *blockmap1, *blockmap2;

#if DISABLE_COLOR > 0
  DISABLE_ALL_COLOR;
#endif

  // don't use color for redirected output
  if (! isatty(1) || ! isatty(2)) {
    DISABLE_ALL_COLOR;
  }

  cmpblockmaps_logo();
  fprintf(stdout, "%s", BLUE);
  fprintf(stdout, CMPBLOCKMAPS_BANNER_STRING);
  fprintf(stdout, "%s", BLACK);
  fprintf(stdout, "\n\n");

  if (argc != 3) {
    fprintf(stderr, "%s", BLUE);
    fprintf(stderr, "Usage: cmpblockmaps blockmap_filename_1 blockmap_filename_2\n\n"
                    "Displays the differences between two blockmaps.\n\n");
    fprintf(stderr, "%s", BLACK);
    return -1;
  }

  if (! copy_string_complete(fn1, sizeof(fn1), argv[1])
      || ! copy_string_complete(fn2, sizeof(fn2), argv[2])) {
    fprintf(stderr, "%s", RED);
    fprintf(stderr,
            "Blockmap pathname is too long (maximum %zu characters).\n",
            sizeof(fn1) - 1);
    fprintf(stderr, "%s", BLACK);
    return -1;
  }

  f1 = fopen(fn1, "rb");
  if (! f1) {
    fprintf(stderr, "%s", RED);
    fprintf(stderr, "Couldn't open blockmap file \"%s\".\n", fn1);
    fprintf(stderr, "%s", BLACK);
    return -1;
  }

  f2 = fopen(fn2, "rb");
  if (! f2) {
    fprintf(stderr, "%s", RED);
    fprintf(stderr, "Couldn't open blockmap file \"%s\".\n", fn2);
    fprintf(stderr, "%s", BLACK);
    return -1;
  }

  if (! read_blockmap(&blockmap1, f1)) {
    fprintf(stderr, "%s", RED);
    fprintf(stderr, "Couldn't read blockmap from file \"%s\".\n", fn1);
    fprintf(stderr, "%s", BLACK);
    return -1;
  }

  if (! read_blockmap(&blockmap2, f2)) {
    fprintf(stderr, "%s", RED);
    fprintf(stderr, "Couldn't read blockmap from file \"%s\".\n", fn2);
    fprintf(stderr, "%s", BLACK);
    return -1;
  }

  if (blockmap1->numblocks != blockmap2->numblocks) {
    fprintf(stderr, "%s", RED);
    fprintf(stderr, "Can't compare blockmaps of different sizes.\n");
    fprintf(stderr, "%s", BLACK);
    return -1;
  }

  if (blockmap1->blocksize < 512 || blockmap1->blocksize % 512) {
    fprintf(stderr, "%s", RED);
    fprintf(stderr,
            "Something is wrong with the blockmap file \"%s\"!\n"
            "Blocksize must be >= 512 bytes and a multiple of 512.\n",
            fn1);
    fprintf(stderr, "%s", BLACK);
    return -1;
  }

  if (blockmap2->blocksize < 512 || blockmap2->blocksize % 512) {
    fprintf(stderr, "%s", RED);
    fprintf(stderr,
            "Something is wrong with the blockmap file \"%s\"!\n"
            "Blocksize must be >= 512 bytes and a multiple of 512.\n",
            fn1);
    fprintf(stderr, "%s", BLACK);
    return -1;
  }

  diff_blockmaps(blockmap1, blockmap2);

  fclose(f1);
  fclose(f2);

  fprintf(stdout, "Done.\n");

  return 0;
}
