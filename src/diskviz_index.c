//
// SPDX-License-Identifier: GPL-3.0-only
//
// Scalpel3 is Copyright (C) 2021-2026 by Golden G. Richard III and contributors.
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

#include "diskviz_index.h"

#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
  int file_block;
  int disk_block;
} OrderEntry;

static bool allocation_fits(int count, size_t element_size) {
  return count >= 0 && (size_t)count <= SIZE_MAX / element_size;
}

static int compare_order_entries(const void *left, const void *right) {
  const OrderEntry *a = left;
  const OrderEntry *b = right;

  if (a->file_block < b->file_block) {
    return -1;
  }
  if (a->file_block > b->file_block) {
    return 1;
  }
  if (a->disk_block < b->disk_block) {
    return -1;
  }
  if (a->disk_block > b->disk_block) {
    return 1;
  }
  return 0;
}

void diskviz_index_destroy(DiskvizIndex *index) {
  if (! index) {
    return;
  }

  free(index->linear_map);
  free(index->file_start);
  free(index->file_end);
  free(index->max_file_block);
  free(index->segment_offsets);
  free(index->segment_starts);
  memset(index, 0, sizeof(*index));
}

bool diskviz_index_build(DiskvizIndex *index, const DiskBlock *blocks,
                         int total_blocks, int num_files) {
  int *counts = NULL;
  int *irregular_offsets = NULL;
  int *write_positions = NULL;
  int *segment_positions = NULL;
  unsigned char *irregular = NULL;
  OrderEntry *irregular_entries = NULL;
  int file_blocks = 0;
  int irregular_blocks = 0;
  int segments = 0;
  bool result = false;

  if (! index || total_blocks < 0 || num_files < 0 || num_files == INT_MAX ||
      (total_blocks > 0 && ! blocks) ||
      ! allocation_fits(total_blocks, sizeof(int)) ||
      ! allocation_fits(num_files + 1, sizeof(int))) {
    return false;
  }

  diskviz_index_destroy(index);
  index->total_blocks = total_blocks;
  index->num_files = num_files;

  if (total_blocks > 0) {
    index->linear_map = malloc((size_t)total_blocks * sizeof(int));
    if (! index->linear_map) {
      goto done;
    }
    for (int i = 0; i < total_blocks; i++) {
      index->linear_map[i] = -1;
    }
  }

  if (num_files == 0) {
    for (int i = 0; i < total_blocks; i++) {
      if (blocks[i].file_id != -1) {
        goto done;
      }
      index->linear_map[i] = i;
    }
    result = true;
    goto done;
  }

  counts = calloc((size_t)num_files, sizeof(int));
  irregular = calloc((size_t)num_files, sizeof(unsigned char));
  index->file_start = malloc((size_t)num_files * sizeof(int));
  index->file_end = malloc((size_t)num_files * sizeof(int));
  index->max_file_block = malloc((size_t)num_files * sizeof(int));
  index->segment_offsets = calloc((size_t)num_files + 1, sizeof(int));
  if (! counts || ! irregular || ! index->file_start || ! index->file_end ||
      ! index->max_file_block || ! index->segment_offsets) {
    goto done;
  }

  for (int file = 0; file < num_files; file++) {
    index->file_start[file] = -1;
    index->file_end[file] = -1;
    index->max_file_block[file] = -1;
  }

  for (int block = 0; block < total_blocks; block++) {
    int file = blocks[block].file_id;
    if (file < -1 || file >= num_files) {
      goto done;
    }
    if (file >= 0) {
      if (counts[file] == INT_MAX || file_blocks == INT_MAX) {
        goto done;
      }
      counts[file]++;
      file_blocks++;
      if (blocks[block].file_block > index->max_file_block[file]) {
        index->max_file_block[file] = blocks[block].file_block;
      }
    }
  }

  int next = 0;
  for (int file = 0; file < num_files; file++) {
    if (counts[file] > 0) {
      index->file_start[file] = next;
      index->file_end[file] = next + counts[file] - 1;
      next += counts[file];
    }
  }

  // place the normal dense 0..N-1 file-block numbering directly.
  for (int block = 0; block < total_blocks; block++) {
    int file = blocks[block].file_id;
    if (file < 0) {
      continue;
    }

    int file_block = blocks[block].file_block;
    if (file_block < 0 || file_block >= counts[file]) {
      irregular[file] = 1;
      continue;
    }

    int position = index->file_start[file] + file_block;
    if (index->linear_map[position] != -1) {
      irregular[file] = 1;
      continue;
    }
    index->linear_map[position] = block;
  }

  for (int file = 0; file < num_files; file++) {
    if (irregular[file]) {
      if (irregular_blocks > INT_MAX - counts[file]) {
        goto done;
      }
      irregular_blocks += counts[file];
    }
  }

  if (irregular_blocks > 0) {
    if (! allocation_fits(irregular_blocks, sizeof(OrderEntry))) {
      goto done;
    }
    irregular_offsets = calloc((size_t)num_files + 1, sizeof(int));
    write_positions = calloc((size_t)num_files, sizeof(int));
    irregular_entries = malloc((size_t)irregular_blocks * sizeof(OrderEntry));
    if (! irregular_offsets || ! write_positions || ! irregular_entries) {
      goto done;
    }

    next = 0;
    for (int file = 0; file < num_files; file++) {
      irregular_offsets[file] = next;
      if (irregular[file]) {
        next += counts[file];
      }
      write_positions[file] = irregular_offsets[file];
    }
    irregular_offsets[num_files] = next;

    for (int block = 0; block < total_blocks; block++) {
      int file = blocks[block].file_id;
      if (file >= 0 && irregular[file]) {
        int position = write_positions[file]++;
        irregular_entries[position].file_block = blocks[block].file_block;
        irregular_entries[position].disk_block = block;
      }
    }

    for (int file = 0; file < num_files; file++) {
      if (! irregular[file]) {
        continue;
      }
      OrderEntry *entries = irregular_entries + irregular_offsets[file];
      qsort(entries, (size_t)counts[file], sizeof(*entries),
            compare_order_entries);
      for (int i = 0; i < counts[file]; i++) {
        index->linear_map[index->file_start[file] + i] =
            entries[i].disk_block;
      }
    }
  }

  next = file_blocks;
  for (int block = 0; block < total_blocks; block++) {
    if (blocks[block].file_id == -1) {
      index->linear_map[next++] = block;
    }
  }
  if (next != total_blocks) {
    goto done;
  }

  // retain only the first connector segments that the renderer can display.
  int previous_file = -1;
  for (int block = 0; block < total_blocks; block++) {
    int file = blocks[block].file_id;
    if (file >= 0 && file != previous_file &&
        index->segment_offsets[file] < DISKVIZ_MAX_SEGMENTS_PER_FILE) {
      index->segment_offsets[file]++;
    }
    previous_file = file;
  }

  next = 0;
  for (int file = 0; file < num_files; file++) {
    int count = index->segment_offsets[file];
    index->segment_offsets[file] = next;
    next += count;
  }
  index->segment_offsets[num_files] = next;
  segments = next;

  if (segments > 0) {
    index->segment_starts = malloc((size_t)segments * sizeof(int));
    segment_positions = malloc((size_t)num_files * sizeof(int));
    if (! index->segment_starts || ! segment_positions) {
      goto done;
    }
    memcpy(segment_positions, index->segment_offsets,
           (size_t)num_files * sizeof(int));

    previous_file = -1;
    for (int block = 0; block < total_blocks; block++) {
      int file = blocks[block].file_id;
      if (file >= 0 && file != previous_file &&
          segment_positions[file] < index->segment_offsets[file + 1]) {
        index->segment_starts[segment_positions[file]++] = block;
      }
      previous_file = file;
    }
  }
  index->num_segments = segments;
  result = true;

done:
  free(counts);
  free(irregular_offsets);
  free(write_positions);
  free(segment_positions);
  free(irregular);
  free(irregular_entries);
  if (! result) {
    diskviz_index_destroy(index);
  }
  return result;
}
