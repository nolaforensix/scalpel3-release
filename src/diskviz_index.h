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
#ifndef DISKVIZ_INDEX_H
#define DISKVIZ_INDEX_H

#include <stdbool.h>

#define DISKVIZ_MAX_SEGMENTS_PER_FILE 12

typedef enum { BTYPE_FILE, BTYPE_HEADER, BTYPE_ZERO, BTYPE_RANDOM } BlockType;

typedef struct {
  BlockType type;
  int file_id;
  int file_block;
  int disk_block;
} DiskBlock;

typedef struct {
  int *linear_map;
  int *file_start;
  int *file_end;
  int *max_file_block;
  int *segment_offsets;
  int *segment_starts;
  int num_segments;
  int total_blocks;
  int num_files;
} DiskvizIndex;

bool diskviz_index_build(DiskvizIndex *index, const DiskBlock *blocks,
                         int total_blocks, int num_files);
void diskviz_index_destroy(DiskvizIndex *index);

#endif
