//
// SPDX-License-Identifier: GPL-3.0-only
//
// The Scalpel Project is Copyright (C) 2005-2026 by Golden G. Richard III
// and contributors.
//
// Scalpel3 is Copyright (C) 2021-2026 by Golden G. Richard III and the
// contributors listed in AUTHORS.
//
// This file is part of Scalpel3.
//
// Scalpel3 is free software: you can redistribute it and/or modify it under
// the terms of the GNU General Public License as published by the Free
// Software Foundation, version 3 only.
//
// Scalpel3 is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
// more details.
//
// You should have received a copy of the GNU General Public License along
// with Scalpel3. If not, see <https://www.gnu.org/licenses/>.
//
// For proprietary or commercial use cases that require integration or
// support, contact Golden G. Richard III (golden@cct.lsu.edu) to discuss
// commercial licensing.
//
// Please see LICENSE.md, README.md, and THIRD_PARTY_NOTICES for details.
//

// Dumps the content of the serialized headers/footers database.
//

#define SCALPEL3_EXTERNAL 1
#include "scalpel.h"

#define DUMPHF_BANNER_STRING                                                                                                       \
  "dumphf v%s -- "                                                                                                                 \
  "Written by Golden G. Richard III (@nolaforensix).",                                                                             \
      SCALPEL_VERSION


// function prototypes for private "dumphf.c" functions
static void dumphf_logo(void);
static void usage(void);

static void usage(void) {
  fprintf(stderr, "%s", BLUE);
  fprintf(stderr, "\nUsage: dumphf [header_footer_database_pathname]\n");
  fprintf(stderr, "If database pathname is not specified, the default is \"scalpel-output/headersfooters.dat\".\n");
  fprintf(stderr, "%s", BLACK);
}


static void dumphf_logo(void) {

  // Logo dimensions: 73 chars wide (excluding newline)
  char *logo[] = {"\n",
                  "\n",
                  " .......................................................................\n",
                  ".                                                                       .\n",
                  ".  8888888b.                                    888    888 8888888888   .\n",
                  ".  888  \"Y88b                                   888    888 888          .\n",
                  ".  888    888                                   888    888 888          .\n",
                  ".  888    888 888  888 88888b.d88b.  88888b.    8888888888 8888888      .\n",
                  ".  888    888 888  888 888 \"888 \"88b 888 \"88b   888    888 888          .\n",
                  ".  888    888 888  888 888  888  888 888  888   888    888 888          .\n",
                  ".  888  .d88P Y88b 888 888  888  888 888 d88P   888    888 888          .\n",
                  ".  8888888P\"   \"Y88888 888  888  888 88888P\"    888    888 888          .\n",
                  ".                                    888                                .\n",
                  ".                                    888                                .\n",
                  ".                                    888                                .\n",
                  " .......................................................................\n",
                  ""};

  int i = 0;
  size_t j;
  size_t len;

  // refuse to print a logo that is wider than terminal width. Logo is 73 chars wide + margins.
  if (get_terminal_width() < 75) {
    return;
  }

  while (logo[i][0]) {
    len = strlen(logo[i]);
    for (j = 0; j < len; j++) {
      if (isspace(logo[i][j]) || i < 3 || i > 14 || j < 2 || j > 70) {
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

  char *filename = "scalpel-output/headersfooters.dat";
  uint32_t num_specs = 0;
  EssentialSearchSpecOffsets *specs = NULL;

#if DISABLE_COLOR > 0
  DISABLE_ALL_COLOR;
#endif

  // don't use color for redirected output
  if (! isatty(1) || ! isatty(2)) {
    DISABLE_ALL_COLOR;
  }

  dumphf_logo();
  fprintf(stdout, "%s", BLUE);
  fprintf(stdout, DUMPHF_BANNER_STRING);
  fprintf(stdout, "\n\n");
  fprintf(stdout, "%s", BLACK);

  if (argc > 1) {
    filename = argv[1];
  }

  // try to deserialize the header/footer database
  specs = deserialize_essential_offsets(filename, &num_specs);

  if (! specs) {
    fprintf(stderr, "%s", RED);
    fprintf(stderr, "\nERROR: Failed to deserialize file \"%s\". Aborting.\n", filename);
    fprintf(stderr, "%s", BLACK);

    // if user provided no arguments and the default failed, show usage
    if (argc < 2) {
      usage();
    }

    return -1;
  }

  fprintf(stdout, "%sSuccessfully loaded header/footer data for %" PRIu32 " file types.\n\n", BLUE, num_specs);
  fprintf(stdout, "%s", BLACK);

  for (uint32_t i = 0; i < num_specs; i++) {
    fprintf(stdout, "Spec #%" PRIu32 " [%s]:\n", i, specs[i].filetype ? specs[i].filetype : "unknown");

    fprintf(stdout, "  Headers (Count: %" PRIu64 "):\n", specs[i].numheaders);
    if (specs[i].numheaders > 0) {
      for (uint64_t j = 0; j < specs[i].numheaders; j++) {
        fprintf(stdout, "    [%3" PRIu64 "] Offset: %-12" PRIu64 " Length: %zu\n", j, specs[i].headers[j], specs[i].headerlens[j]);
      }
    }
    else {
      fprintf(stdout, "    (None)\n");
    }

    fprintf(stdout, "  Footers (Count: %" PRIu64 "):\n", specs[i].numfooters);
    if (specs[i].numfooters > 0) {
      for (uint64_t j = 0; j < specs[i].numfooters; j++) {
        fprintf(stdout, "    [%3" PRIu64 "] Offset: %-12" PRIu64 " Length: %zu\n", j, specs[i].footers[j], specs[i].footerlens[j]);
      }
    }
    else {
      fprintf(stdout, "    (None)\n");
    }

    fprintf(stdout, "\n");
  }

  // cleanup
  if (specs) {
    for (uint32_t i = 0; i < num_specs; i++) {
      free(specs[i].filetype);
      free(specs[i].headers);
      free(specs[i].headerlens);
      free(specs[i].footers);
      free(specs[i].footerlens);
    }
    free(specs);
  }

  fprintf(stdout, "Done.\n");

  return 0;
}
