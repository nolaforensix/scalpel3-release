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

// Dumps the content of the persistent block classification database.
//

#define SCALPEL3_EXTERNAL 1
#include "scalpel.h"

#define DUMPBT_BANNER_STRING                                                        \
  "dumpbt v%s -- Written by Golden G. Richard III (@nolaforensix).", SCALPEL_VERSION


typedef struct BlockTypeDatabaseHeader {
  uint32_t version;
  uint64_t blocksize;
  uint64_t numblocks;
  uint32_t num_specs;
  char **filetypes;
} BlockTypeDatabaseHeader;


// function prototypes for private "dumpbt.c" functions
static void dumpbt_logo(void);
static void usage(void);
static void free_database_header(BlockTypeDatabaseHeader *header);
static bool read_database_header(FILE *fp, BlockTypeDatabaseHeader *header);
static void print_confidence_range(uint64_t first_block, uint64_t last_block,
                                   unsigned char confidence);
static bool dump_blocktypes(FILE *fp, const BlockTypeDatabaseHeader *header);


static void usage(void) {

  fprintf(stderr, "%s", BLUE);
  fprintf(stderr, "\nUsage: dumpbt [block_classification_database_pathname]\n");
  fprintf(stderr, "If database pathname is not specified, the default is "
                  "\"scalpel-output/blockclassification.dat\".\n");
  fprintf(stderr, "%s", BLACK);
}


static void dumpbt_logo(void) {

  // Logo dimensions: 73 chars wide (excluding newline)
  char *logo[] = {"\n",
                  "\n",
                  " .......................................................................\n",
                  ".                                                                       .\n",
                  ".  8888888b.                                    888888b.  8888888888   .\n",
                  ".  888  \"Y88b                                   888  \"88b    888       .\n",
                  ".  888    888                                   888  .88P    888       .\n",
                  ".  888    888 888  888 88888b.d88b.  88888b.    8888888K.    888       .\n",
                  ".  888    888 888  888 888 \"888 \"88b 888 \"88b   888  \"Y88b   888       .\n",
                  ".  888    888 888  888 888  888  888 888  888   888    888   888       .\n",
                  ".  888  .d88P Y88b 888 888  888  888 888 d88P   888   d88P   888       .\n",
                  ".  8888888P\"   \"Y88888 888  888  888 88888P\"    8888888P\"    888       .\n",
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


// release file type names allocated while reading the database header.
static void free_database_header(BlockTypeDatabaseHeader *header) {

  if (! header || ! header->filetypes) {
    return;
  }

  for (uint32_t i = 0; i < header->num_specs; i++) {
    free(header->filetypes[i]);
  }
  free(header->filetypes);
  header->filetypes = NULL;
}


// read and validate the fixed database metadata and file type directory.
static bool read_database_header(FILE *fp, BlockTypeDatabaseHeader *header) {

  char magic[BLOCKCLASSIFICATION_MAGIC_SIZE];
  struct stat file_info;
  off_t directory_offset;
  off_t data_offset;
  uint64_t payload_bytes;
  uint64_t remaining_bytes;

  memset(header, 0, sizeof(*header));
  if (fread(magic, 1, sizeof(magic), fp) != sizeof(magic)
      || memcmp(magic, BLOCKCLASSIFICATION_MAGIC, sizeof(magic)) != 0
      || fread(&header->version, sizeof(header->version), 1, fp) != 1
      || header->version != BLOCKCLASSIFICATION_VERSION
      || fread(&header->blocksize, sizeof(header->blocksize), 1, fp) != 1
      || header->blocksize == 0
      || fread(&header->numblocks, sizeof(header->numblocks), 1, fp) != 1
      || fread(&header->num_specs, sizeof(header->num_specs), 1, fp) != 1
      || header->num_specs == 0) {
    return false;
  }

  directory_offset = ftello(fp);
  if (directory_offset < 0 || fstat(fileno(fp), &file_info) != 0
      || file_info.st_size < directory_offset) {
    return false;
  }
  remaining_bytes = (uint64_t)(file_info.st_size - directory_offset);
  if (header->num_specs
          > remaining_bytes / (sizeof(uint32_t) + 1)
      || (header->numblocks > 0
          && header->num_specs > remaining_bytes / header->numblocks)) {
    return false;
  }

  header->filetypes = calloc(header->num_specs, sizeof(char *));
  check_memory_allocation(header->filetypes, __LINE__, __FILE__,
                          "block classification file type directory");

  for (uint32_t i = 0; i < header->num_specs; i++) {
    uint32_t filetype_len;

    if (fread(&filetype_len, sizeof(filetype_len), 1, fp) != 1
        || filetype_len == 0 || filetype_len >= MAX_STRING_LENGTH) {
      return false;
    }
    header->filetypes[i] = malloc((size_t)filetype_len + 1);
    check_memory_allocation(header->filetypes[i], __LINE__, __FILE__,
                            "block classification file type");
    if (fread(header->filetypes[i], 1, filetype_len, fp) != filetype_len
        || memchr(header->filetypes[i], '\0', filetype_len) != NULL) {
      return false;
    }
    header->filetypes[i][filetype_len] = '\0';
  }

  data_offset = ftello(fp);
  if (data_offset < 0 || file_info.st_size < data_offset
      || (header->numblocks > 0
          && header->num_specs > UINT64_MAX / header->numblocks)) {
    return false;
  }
  payload_bytes = header->numblocks * header->num_specs;
  if ((uint64_t)(file_info.st_size - data_offset) != payload_bytes) {
    return false;
  }

  return true;
}


// print one maximal range of blocks that share a confidence value.
static void print_confidence_range(uint64_t first_block, uint64_t last_block,
                                   unsigned char confidence) {

  const char *meaning = "";

  if (confidence == BLOCK_CONFIDENCE_INVALID) {
    meaning = " (invalid)";
  }
  else if (confidence == BLOCK_CONFIDENCE_VALID) {
    meaning = " (valid)";
  }

  if (first_block == last_block) {
    fprintf(stdout, "  Block  %12" PRIu64 ": Confidence: %3u%s\n",
            first_block, (uint32_t)confidence, meaning);
  }
  else {
    fprintf(stdout,
            "  Blocks %12" PRIu64 " - %-12" PRIu64
            ": Confidence: %3u%s\n",
            first_block, last_block, (uint32_t)confidence, meaning);
  }
}


// stream each column and combine adjacent equal values into readable ranges.
static bool dump_blocktypes(FILE *fp, const BlockTypeDatabaseHeader *header) {

  for (uint32_t spec = 0; spec < header->num_specs; spec++) {
    unsigned char confidence;
    unsigned char prior_confidence;
    uint64_t first_block = 0;

    fprintf(stdout, "Spec #%" PRIu32 " [%s]:\n", spec,
            header->filetypes[spec]);
    if (header->numblocks == 0) {
      fprintf(stdout, "  (No blocks)\n\n");
      continue;
    }

    if (fread(&prior_confidence, 1, 1, fp) != 1) {
      return false;
    }
    if (prior_confidence > BLOCK_CONFIDENCE_VALID) {
      return false;
    }
    for (uint64_t block = 1; block < header->numblocks; block++) {
      if (fread(&confidence, 1, 1, fp) != 1) {
        return false;
      }
      if (confidence > BLOCK_CONFIDENCE_VALID) {
        return false;
      }
      if (confidence != prior_confidence) {
        print_confidence_range(first_block, block - 1, prior_confidence);
        first_block = block;
        prior_confidence = confidence;
      }
    }
    print_confidence_range(first_block, header->numblocks - 1,
                           prior_confidence);
    fprintf(stdout, "\n");
  }

  return true;
}


int main(int argc, char *argv[]) {

  char *filename = "scalpel-output/blockclassification.dat";
  BlockTypeDatabaseHeader header;
  FILE *fp;
  bool ok;

#if DISABLE_COLOR > 0
  DISABLE_ALL_COLOR;
#endif

  // don't use color for redirected output
  if (! isatty(1) || ! isatty(2)) {
    DISABLE_ALL_COLOR;
  }

  dumpbt_logo();
  fprintf(stdout, "%s", BLUE);
  fprintf(stdout, DUMPBT_BANNER_STRING);
  fprintf(stdout, "\n\n");
  fprintf(stdout, "%s", BLACK);

  if (argc > 2) {
    usage();
    return EXIT_FAILURE;
  }
  if (argc == 2) {
    filename = argv[1];
  }

  fp = fopen(filename, "rb");
  if (! fp) {
    fprintf(stderr, "%s\nERROR: Failed to open file \"%s\". Aborting.\n%s",
            RED, filename, BLACK);
    if (argc < 2) {
      usage();
    }
    return EXIT_FAILURE;
  }

  ok = read_database_header(fp, &header);
  if (! ok) {
    fprintf(stderr,
            "%s\nERROR: File \"%s\" is not a supported block "
            "classification database. Aborting.\n%s",
            RED, filename, BLACK);
    free_database_header(&header);
    fclose(fp);
    return EXIT_FAILURE;
  }

  fprintf(stdout, "%sSuccessfully loaded block type data.\n%s", BLUE,
          BLACK);
  fprintf(stdout, "  Version:    %" PRIu32 "\n", header.version);
  fprintf(stdout, "  Block size: %" PRIu64 " bytes\n", header.blocksize);
  fprintf(stdout, "  Blocks:     %" PRIu64 "\n", header.numblocks);
  fprintf(stdout, "  File types: %" PRIu32 "\n\n", header.num_specs);

  ok = dump_blocktypes(fp, &header);
  if (ok && fgetc(fp) != EOF) {
    ok = false;
  }
  if (fclose(fp) != 0) {
    ok = false;
  }
  free_database_header(&header);

  if (! ok) {
    fprintf(stderr,
            "%sERROR: The block type payload in \"%s\" is invalid, truncated, "
            "or has trailing data. Aborting.\n%s",
            RED, filename, BLACK);
    return EXIT_FAILURE;
  }

  fprintf(stdout, "Done.\n");
  return EXIT_SUCCESS;
}
