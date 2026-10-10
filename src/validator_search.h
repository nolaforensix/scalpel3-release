// SPDX-License-Identifier: GPL-3.0-only
// The Scalpel Project is Copyright (C) 2005-2026 by Golden G. Richard III
// and contributors.
//
// Scalpel3 is Copyright (C) 2021-2026 by Golden G. Richard III and the
// contributors listed in AUTHORS.
// See LICENSE.md and README.md for licensing and commercial-use information.

#ifndef SCALPEL_VALIDATOR_SEARCH_H
#define SCALPEL_VALIDATOR_SEARCH_H

#include "filemirror.h"

static inline XXH128_hash_t validator_search_view(CarveInfo *candidate);

// A saved ranking is reusable only for the same prefix and available-block view.
// Call at save/load boundaries, not for individual trial blocks.
static inline XXH128_hash_t validator_search_view(CarveInfo *candidate) {
  XXH3_state_t hash;
  XXH3_128bits_reset(&hash);
  const uint64_t blocks = blockvector_get_num_blocks(candidate->b);
  const uint64_t length = blockvector_get_data_length(candidate->b);
  const uint64_t image_blocks = CEILDIV(filemirror_filesize(scalpel_state.filemirror),
                                       scalpel_state.blocksize);
  const uint64_t geometry[] = {blocks, length, image_blocks, scalpel_state.blocksize,
                               candidate->needleidx, scalpel_state.modico_enabled};
  XXH3_128bits_update(&hash, geometry, sizeof(geometry));
  for (uint64_t i = 0; i < blocks; i++) {
    int64_t actual = blockvector_get_actual_blocknumber(candidate->b, i);
    XXH3_128bits_update(&hash, &actual, sizeof(actual));
  }
  XXH3_128bits_update(&hash, blockvector_get_data_pointer(candidate->b), (size_t)length);
  uint8_t view[512];
  for (uint64_t first = 0; first < image_blocks;) {
    size_t count = image_blocks - first > sizeof(view) / 2
        ? sizeof(view) / 2 : (size_t)(image_blocks - first);
    for (size_t i = 0; i < count; i++) {
      view[2 * i] = filemirror_actual_block_covered(scalpel_state.filemirror, (int64_t)(first + i));
      view[2 * i + 1] = filemirror_get_blocktype(scalpel_state.filemirror,
                                               (int64_t)(first + i), candidate->needleidx);
      const int64_t apparent = filemirror_apparent_blocknumber(
          scalpel_state.filemirror, (int64_t)(first + i));
      XXH3_128bits_update(&hash, &apparent, sizeof(apparent));
    }
    XXH3_128bits_update(&hash, view, 2 * count);
    first += count;
  }
  return XXH3_128bits_digest(&hash);
}

#endif
