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
//-----------------------------
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
// Blockmap design and implementation Copyright (c) 2021-2025 by Golden G. Richard III and 2024-2025
// by Karley Waguespack. Blockmaps handle block coverage, deduplication, and block reservations in
// scalpel3.
//
// IMPORTANT: synchronization and thread-safety in blockmap.c functions are optimized for maximum
// performance in scalpel3 and may not be appropriate in other multithreaded contexts. For example,
// blockmap cloning is always done in a single-threaded context in scalpel3, therefore locks are not
// needed.
//

// CHANGE TO ALLOW PARAMETERIZED BLOCKMAP MERGING
// REQUIRES A MAIN FUNCTION?
// IMPLEMENT IN START AND END BLOCK FUNCTIONALITY

#define SCALPEL3_EXTERNAL 1
#include "blockmap.h"
//#include "scalpel.h"
#include "scalpelv.h"
#include <inttypes.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

// Copy every set bit from source bitmap to destination bitmap,
// for block indices start_block..end_block (inclusive).
static void cycle_bit_copy(atomic_uchar *bitmap_merge, atomic_uchar *bitmap_copyfrom, uint64_t start_block, uint64_t end_block) {
  for (uint64_t i = start_block; i <= end_block; i++) {
    if (is_bit_set(bitmap_copyfrom, i)) {
      set_bit(bitmap_merge, i);
    }
  }
}


// Merges given blockmap into merged blockmap
static void merge_blockmap(Blockmap *merged, Blockmap *blockmap, bool first) {
  // Combine the 2 blockmaps
  cycle_bit_copy(merged->coveragemap, blockmap->coveragemap, blockmap->start_block, blockmap->end_block);
  // Copy start_block and end_block of first merged blockmap
  if (first) {
    merged->start_block = blockmap->start_block;
    merged->end_block = blockmap->end_block;
  }
  // Only change start_block and/or end_block when outside of range
  else {
    if (merged->start_block > blockmap->start_block) {
      merged->start_block = blockmap->start_block;
    }
    if (merged->end_block < blockmap->end_block) {
      merged->end_block = blockmap->end_block;
    }
  }
}


// Function to compute all pairwise overlaps and return them as uint64_t**.
// Returns NULL with *returnSize == 0 if no overlaps found.
// Returns NULL with *returnSize < 0 on allocation failure.
static uint64_t **check_overlap(uint64_t *input[], int n, int *returnSize) {
  int capacity = 10;
  int count = 0;

  uint64_t **result = malloc(capacity * sizeof(uint64_t *));
  if (!result) {
    *returnSize = -1;
    return NULL;
  }

  for (int i = 0; i < n; ++i) {
    for (int j = i + 1; j < n; ++j) {
      uint64_t start = (input[i][0] > input[j][0]) ? input[i][0] : input[j][0];
      uint64_t end   = (input[i][1] < input[j][1]) ? input[i][1] : input[j][1];

      if (start <= end) {
        if (count >= capacity) {
          capacity *= 2;
          uint64_t **tmp = realloc(result, capacity * sizeof(uint64_t *));
          if (!tmp) {
            for (int k = 0; k < count; k++) free(result[k]);
            free(result);
            *returnSize = -1;
            return NULL;
          }
          result = tmp;
        }

        result[count] = malloc(2 * sizeof(uint64_t));
        if (!result[count]) {
          for (int k = 0; k < count; k++) free(result[k]);
          free(result);
          *returnSize = -1;
          return NULL;
        }
        result[count][0] = start;
        result[count][1] = end;
        count++;
      }
    }
  }

  if (count == 0) {
    free(result);
    *returnSize = 0;
    return NULL;
  }

  *returnSize = count;
  return result;
}


int main(int argc, char **argv) {

  //Checks for correct usage
  if (argc < 4) {
    fprintf(stderr, "Usage: %s output_file image_file blockmap_file1 blockmap_file2 ... blockmap_fileN\n", argv[0]);
    return -1;
  }

  //Read in blockmaps from files
  int num_blockmaps = argc - 3;
  FILE *files[num_blockmaps];  // Array of FILE pointers

  // Open each file
  for (int i = 0; i < num_blockmaps; ++i) {
    files[i] = fopen(argv[i + 3], "rb");
    if (files[i] == NULL) {
      perror(argv[i + 3]);
      // Close previously opened files
      for (int j = 0; j < i; ++j) {
        fclose(files[j]);
      }
      return -1;
    }
  }

  Blockmap *blockmaps[num_blockmaps];

  // Read each file into blockmaps
  for (int i = 0; i < num_blockmaps; ++i) {
    bool error_check = read_blockmap(&blockmaps[i], files[i], false);
    if (error_check == false) {
      perror(argv[i + 3]);
      // Close previously opened files
      for (int j = 0; j < num_blockmaps; ++j) {
        fclose(files[j]);
      }
      return -1;
    }
  }

  for (int j = 0; j < num_blockmaps; ++j) {
    fclose(files[j]);
  }

  // Validate that all input blockmaps have identical geometry
  for (int i = 1; i < num_blockmaps; i++) {
    if (blockmaps[i]->blocksize != blockmaps[0]->blocksize ||
        blockmaps[i]->numblocks != blockmaps[0]->numblocks) {
      fprintf(stderr, "mergeblockmap error: blockmap %s has incompatible blocksize or numblocks\n", argv[i + 3]);
      for (int j = 0; j < num_blockmaps; j++) free_blockmap(&blockmaps[j]);
      return -1;
    }
  }

  // Begin check for overlapping ranges
  uint64_t *ranges[num_blockmaps];

  for (int i = 0; i < num_blockmaps; i++) {
    ranges[i] = (uint64_t *)malloc(2 * sizeof(uint64_t));
    if (!ranges[i]) {
      fprintf(stderr, "mergeblockmap: memory allocation failure\n");
      for (int j = 0; j < i; j++) free(ranges[j]);
      for (int j = 0; j < num_blockmaps; j++) free_blockmap(&blockmaps[j]);
      return -1;
    }
    ranges[i][0] = blockmaps[i]->start_block;
    ranges[i][1] = blockmaps[i]->end_block;
  }

  int return_size = 0;
  uint64_t **overlap = check_overlap(ranges, num_blockmaps, &return_size);

  if (return_size < 0) {
    fprintf(stderr, "mergeblockmap: memory allocation failure in overlap check\n");
    for (int i = 0; i < num_blockmaps; i++) {
      free(ranges[i]);
      free_blockmap(&blockmaps[i]);
    }
    return -1;
  }

  // Error if there is overlap
  if (return_size > 0) {
    fprintf(stderr, "mergeblockmap error: overlapping blocks detected\n");
    fprintf(stderr, "Overlapping Ranges:\n");
    for (int i = 0; i < return_size; i++) {
      fprintf(stderr, "%" PRIu64 " - %" PRIu64 "\n", overlap[i][0], overlap[i][1]);
      free(overlap[i]);
    }
    free(overlap);
    for (int i = 0; i < num_blockmaps; i++) {
      free(ranges[i]);
      free_blockmap(&blockmaps[i]);
    }
    return -1;
  }

  // Create output blockmap
  // Will have same blocksize and numblocks as every other blockmap
  Blockmap *merge;
  uint32_t blocksize = blockmaps[0]->blocksize;
  uint64_t numblocks = blockmaps[0]->numblocks;
  bool alo_check = allocate_blockmap(&merge, blocksize, numblocks);
  if (!alo_check) {
    fprintf(stderr, "Could not allocate blockmap\n");
    for (int i = 0; i < num_blockmaps; i++) {
      free(ranges[i]);
      free_blockmap(&blockmaps[i]);
    }
    return -1;
  }

  // Merges first blockmap into output blockmap, copys start_block and end_block settings
  merge_blockmap(merge, blockmaps[0], true);

  // Merges remaining blockmaps into output blockmap, only changes start_block and end_block when necessary
  for (int i = 1; i < num_blockmaps; i++) {
    merge_blockmap(merge, blockmaps[i], false);
  }

  // Open image file for deduping
  FILE *image_file = fopen(argv[2], "rb");
  if (image_file == NULL) {
    perror(argv[2]);
    for (int i = 0; i < num_blockmaps; i++) {
      free(ranges[i]);
      free_blockmap(&blockmaps[i]);
    }
    free_blockmap(&merge);
    return -1;
  }

  // Run dedup on merged blockmap
  uint64_t deduped = 0, zeroblocks = 0;
  if (!dedup_blockmap(merge, image_file, &deduped, &zeroblocks, false)) {
    fprintf(stderr, "mergeblockmap: dedup_blockmap failed\n");
    for (int i = 0; i < num_blockmaps; i++) {
      free(ranges[i]);
      free_blockmap(&blockmaps[i]);
    }
    free_blockmap(&merge);
    fclose(image_file);
    return -1;
  }

  // Creates file for output blockmap
  FILE *output = fopen(argv[1], "wb");
  if (output == NULL) {
    perror(argv[1]);
    for (int i = 0; i < num_blockmaps; i++) {
      free(ranges[i]);
      free_blockmap(&blockmaps[i]);
    }
    free_blockmap(&merge);
    fclose(image_file);
    return -1;
  }
  if (!write_blockmap(merge, output)) {
    fprintf(stderr, "mergeblockmap: write_blockmap failed\n");
    for (int i = 0; i < num_blockmaps; i++) {
      free(ranges[i]);
      free_blockmap(&blockmaps[i]);
    }
    free_blockmap(&merge);
    fclose(image_file);
    fclose(output);
    return -1;
  }

  // Free memory and close files
  for (int i = 0; i < num_blockmaps; i++) {
    free_blockmap(&blockmaps[i]);
    free(ranges[i]);
  }
  free_blockmap(&merge);
  fclose(image_file);
  fclose(output);

  return 0;
}
