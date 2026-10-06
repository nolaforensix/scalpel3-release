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

#ifndef BLOCKMAPFS_INDEX_H
#define BLOCKMAPFS_INDEX_H

#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#define BMFS_OFFSET_INDEX_STRIDE 4096ULL

typedef bool (*BmfsBlockCoveredFn)(void *context, uint64_t blocknumber);

typedef struct BmfsOffsetIndex {
  uint64_t *visible_prefix;
  uint64_t entry_count;
  uint64_t numblocks;
  uint64_t source_size;
  uint64_t visible_size;
  uint32_t blocksize;
} BmfsOffsetIndex;


// return the physical byte length of a source block.
static inline uint64_t bmfs_source_block_length(const BmfsOffsetIndex *index,
                                                uint64_t blocknumber) {
  uint64_t start;

  if (! index || ! index->blocksize || blocknumber >= index->numblocks
      || blocknumber > UINT64_MAX / index->blocksize) {
    return 0;
  }

  start = blocknumber * index->blocksize;
  if (start >= index->source_size) {
    return 0;
  }
  if (index->source_size - start < index->blocksize) {
    return index->source_size - start;
  }
  return index->blocksize;
}


// release resources owned by an offset index.
static inline void bmfs_offset_index_destroy(BmfsOffsetIndex *index) {
  if (! index) {
    return;
  }

  free(index->visible_prefix);
  memset(index, 0, sizeof(*index));
}


// build visible-byte prefix totals at fixed physical-block boundaries.
static inline bool bmfs_offset_index_build(BmfsOffsetIndex *index,
                                           uint64_t numblocks,
                                           uint32_t blocksize,
                                           uint64_t source_size,
                                           BmfsBlockCoveredFn covered,
                                           void *context) {
  BmfsOffsetIndex result = {0};
  uint64_t expected_blocks;
  uint64_t chunks;
  uint64_t visible = 0;

  if (! index || ! covered || ! blocksize || source_size > INT64_MAX) {
    errno = EINVAL;
    return false;
  }

  expected_blocks = source_size == 0 ? 0 : 1 + (source_size - 1) / blocksize;
  if (expected_blocks != numblocks) {
    errno = EINVAL;
    return false;
  }

  chunks = numblocks / BMFS_OFFSET_INDEX_STRIDE;
  if (numblocks % BMFS_OFFSET_INDEX_STRIDE) {
    chunks++;
  }
  if (chunks == UINT64_MAX
      || chunks + 1 > SIZE_MAX / sizeof(*result.visible_prefix)) {
    errno = EOVERFLOW;
    return false;
  }

  result.visible_prefix =
      (uint64_t *)malloc((size_t)(chunks + 1) * sizeof(*result.visible_prefix));
  if (! result.visible_prefix) {
    errno = ENOMEM;
    return false;
  }
  result.entry_count = chunks + 1;
  result.numblocks = numblocks;
  result.source_size = source_size;
  result.blocksize = blocksize;

  for (uint64_t chunk = 0; chunk < chunks; chunk++) {
    uint64_t first = chunk * BMFS_OFFSET_INDEX_STRIDE;
    uint64_t stop = first + BMFS_OFFSET_INDEX_STRIDE;

    result.visible_prefix[chunk] = visible;
    if (stop > numblocks) {
      stop = numblocks;
    }
    for (uint64_t block = first; block < stop; block++) {
      if (! covered(context, block)) {
        visible += bmfs_source_block_length(&result, block);
      }
    }
  }
  result.visible_prefix[chunks] = visible;
  result.visible_size = visible;

  bmfs_offset_index_destroy(index);
  *index = result;
  return true;
}


// clone an immutable offset index.
static inline bool bmfs_offset_index_clone(const BmfsOffsetIndex *source,
                                           BmfsOffsetIndex *destination) {
  BmfsOffsetIndex result = {0};

  if (! source || ! destination || ! source->visible_prefix
      || ! source->entry_count
      || source->entry_count > SIZE_MAX / sizeof(*source->visible_prefix)) {
    errno = EINVAL;
    return false;
  }

  result.visible_prefix = (uint64_t *)malloc(
      (size_t)source->entry_count * sizeof(*result.visible_prefix));
  if (! result.visible_prefix) {
    errno = ENOMEM;
    return false;
  }
  memcpy(result.visible_prefix, source->visible_prefix,
         (size_t)source->entry_count * sizeof(*result.visible_prefix));
  result.entry_count = source->entry_count;
  result.numblocks = source->numblocks;
  result.source_size = source->source_size;
  result.visible_size = source->visible_size;
  result.blocksize = source->blocksize;

  bmfs_offset_index_destroy(destination);
  *destination = result;
  return true;
}


// translate a visible byte offset to a physical block and in-block offset.
static inline bool bmfs_offset_index_locate(const BmfsOffsetIndex *index,
                                            uint64_t visible_offset,
                                            BmfsBlockCoveredFn covered,
                                            void *context,
                                            uint64_t *physical_block,
                                            uint32_t *block_offset) {
  uint64_t low = 0;
  uint64_t high;
  uint64_t anchor;
  uint64_t block;
  uint64_t stop;
  uint64_t visible;

  if (! index || ! index->visible_prefix || ! index->entry_count || ! covered
      || ! physical_block || ! block_offset
      || visible_offset >= index->visible_size) {
    return false;
  }

  high = index->entry_count;
  while (low < high) {
    uint64_t middle = low + (high - low) / 2;

    if (index->visible_prefix[middle] <= visible_offset) {
      low = middle + 1;
    }
    else {
      high = middle;
    }
  }

  anchor = low ? low - 1 : 0;
  if (anchor + 1 >= index->entry_count) {
    return false;
  }
  block = anchor * BMFS_OFFSET_INDEX_STRIDE;
  stop = block + BMFS_OFFSET_INDEX_STRIDE;
  if (stop > index->numblocks) {
    stop = index->numblocks;
  }
  visible = index->visible_prefix[anchor];

  for (; block < stop; block++) {
    uint64_t length;

    if (covered(context, block)) {
      continue;
    }
    length = bmfs_source_block_length(index, block);
    if (visible_offset - visible < length) {
      *physical_block = block;
      *block_offset = (uint32_t)(visible_offset - visible);
      return true;
    }
    visible += length;
  }

  return false;
}


// read from the compacted visible view without copying covered blocks.
static inline ssize_t bmfs_offset_index_pread(const BmfsOffsetIndex *index,
                                              int fd,
                                              void *buffer,
                                              size_t size,
                                              uint64_t visible_offset,
                                              BmfsBlockCoveredFn covered,
                                              void *context) {
  uint64_t block;
  uint64_t available;
  uint32_t block_offset;
  size_t target;
  size_t total = 0;

  if (! index || ! buffer || ! covered || fd < 0) {
    errno = EINVAL;
    return -1;
  }
  if (! size || visible_offset >= index->visible_size) {
    return 0;
  }
  if (size > (size_t)SSIZE_MAX) {
    size = (size_t)SSIZE_MAX;
  }
  available = index->visible_size - visible_offset;
  target = available < size ? (size_t)available : size;

  if (! bmfs_offset_index_locate(index, visible_offset, covered, context,
                                  &block, &block_offset)) {
    errno = EIO;
    return -1;
  }

  while (total < target) {
    uint64_t run_bytes;
    uint64_t next;
    uint64_t physical_offset;
    size_t request;

    while (block < index->numblocks && covered(context, block)) {
      block++;
    }
    if (block >= index->numblocks) {
      errno = EIO;
      return -1;
    }

    run_bytes = bmfs_source_block_length(index, block) - block_offset;
    next = block + 1;
    while (run_bytes < target - total && next < index->numblocks
           && ! covered(context, next)) {
      run_bytes += bmfs_source_block_length(index, next);
      next++;
    }

    request = target - total;
    if (run_bytes < request) {
      request = (size_t)run_bytes;
    }
    physical_offset = block * index->blocksize + block_offset;

    while (request) {
      ssize_t bytesread;

      do {
        bytesread = pread(fd, (char *)buffer + total, request,
                          (off_t)physical_offset);
      } while (bytesread < 0 && errno == EINTR);

      if (bytesread < 0) {
        return -1;
      }
      if (! bytesread) {
        errno = EIO;
        return -1;
      }

      total += (size_t)bytesread;
      request -= (size_t)bytesread;
      physical_offset += (uint64_t)bytesread;
    }

    block = next;
    block_offset = 0;
  }

  return (ssize_t)total;
}

#endif
