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

#if !defined(SCALPEL_PST_H)
#define SCALPEL_PST_H

#include "scalpel.h"

#include <inttypes.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>

#define PST_HEADER_MAGIC                    UINT32_C(0x4e444221)
#define PST_HEADER_MINIMUM_SIZE             UINT64_C(512)
#define PST_UNICODE_HEADER_SIZE             UINT64_C(564)
#define PST_HEADER_PARTIAL_CRC_OFFSET        UINT64_C(4)
#define PST_HEADER_PARTIAL_CRC_DATA_OFFSET   UINT64_C(8)
#define PST_HEADER_PARTIAL_CRC_DATA_SIZE     UINT64_C(471)
#define PST_HEADER_FULL_CRC_OFFSET           UINT64_C(524)
#define PST_HEADER_FULL_CRC_DATA_SIZE        UINT64_C(516)
#define PST_ANSI_AMAP_VALID_OFFSET            UINT64_C(200)
#define PST_UNICODE_AMAP_VALID_OFFSET         UINT64_C(248)
#define PST_STANDARD_AMAP_FIRST_OFFSET        UINT64_C(0x4400)
#define PST_STANDARD_AMAP_INTERVAL            UINT64_C(253952)
#define PST_UNICODE_4K_AMAP_FIRST_OFFSET      UINT64_C(0x22000)
#define PST_UNICODE_4K_AMAP_INTERVAL          UINT64_C(16678912)
#define PST_ANSI_PAGE_SIZE                   UINT64_C(512)
#define PST_UNICODE_PAGE_SIZE                UINT64_C(512)
#define PST_UNICODE_4K_PAGE_SIZE             UINT64_C(4096)
#define PST_ANSI_BLOCK_TRAILER_SIZE          UINT64_C(12)
#define PST_UNICODE_BLOCK_TRAILER_SIZE       UINT64_C(16)
#define PST_UNICODE_4K_BLOCK_TRAILER_SIZE    UINT64_C(24)
#define PST_STANDARD_BLOCK_ALIGNMENT         UINT64_C(64)
#define PST_UNICODE_4K_BLOCK_ALIGNMENT       UINT64_C(512)
#define PST_STANDARD_MAXIMUM_BLOCK_SIZE      UINT64_C(8192)
#define PST_UNICODE_4K_MAXIMUM_BLOCK_SIZE    UINT64_C(65536)
#define PST_PAGE_TYPE_BBT                    UINT8_C(0x80)
#define PST_PAGE_TYPE_NBT                    UINT8_C(0x81)
#define PST_PAGE_TYPE_AMAP                   UINT8_C(0x84)
#define PST_MAXIMUM_BTREE_DEPTH              UINT32_C(64)
#define PST_MAXIMUM_FILE_SIZE                UINT64_C(1099511627776)
#define PST_BLOCK_CONFIDENCE                 95
#define PST_STATE_MAGIC                      UINT32_C(0x50535452)
#define PST_STATE_VERSION                    UINT32_C(5)
#define PST_REASSEMBLY_POLL_INTERVAL         UINT64_C(64)
#define PST_REASSEMBLY_FAST_SHIFT_LIMIT      UINT64_C(64)
#define PST_REASSEMBLY_HYPOTHESIS_LIMIT      UINT32_C(16)

typedef enum PstProfile {
  PST_PROFILE_UNKNOWN = 0,
  PST_PROFILE_PST,
  PST_PROFILE_OST,
  PST_PROFILE_PAB
} PstProfile;

typedef enum PstVariant {
  PST_VARIANT_UNKNOWN = 0,
  PST_VARIANT_ANSI,
  PST_VARIANT_UNICODE,
  PST_VARIANT_UNICODE_4K
} PstVariant;

typedef enum PstAnchorKind {
  PST_ANCHOR_NONE = 0,
  PST_ANCHOR_AMAP_PAGE,
  PST_ANCHOR_BTREE_PAGE,
  PST_ANCHOR_DATA_BLOCK
} PstAnchorKind;

typedef struct PstFailureAnchor {
  PstAnchorKind kind;
  uint8_t page_type;
  uint8_t page_level;
  uint64_t logical_offset;
  uint64_t bid;
  uint64_t extent;
  uint32_t data_size;
} PstFailureAnchor;

typedef struct PstBlockReference {
  uint64_t bid;
  uint64_t offset;
  uint32_t data_size;
} PstBlockReference;

typedef struct PstOffsetSet {
  uint64_t *entries;
  uint64_t capacity;
  uint64_t count;
} PstOffsetSet;

typedef struct PstLayout {
  const uint8_t *data;
  uint64_t length;
  uint64_t file_size;
  uint64_t page_size;
  uint64_t page_data_size;
  uint64_t page_metadata_offset;
  uint64_t page_trailer_offset;
  uint64_t block_trailer_size;
  uint64_t block_alignment;
  uint64_t maximum_block_size;
  uint64_t amap_first_offset;
  uint64_t amap_last_offset;
  uint64_t amap_interval;
  uint64_t amap_data_offset;
  uint64_t amap_data_size;
  uint64_t amap_granularity;
  uint64_t amap_free_bytes;
  uint64_t nbt_root_bid;
  uint64_t nbt_root_offset;
  uint64_t bbt_root_bid;
  uint64_t bbt_root_offset;
  uint64_t failure_offset;
  uint64_t amap_failure_offset;
  uint64_t verified_amap_pages;
  uint64_t verified_amap_allocations;
  uint64_t verified_pages;
  uint64_t verified_blocks;
  uint64_t verified_nbt_entries;
  PstFailureAnchor amap_failure_anchor;
  PstFailureAnchor failure_anchor;
  bool amap_dirty;
  bool amap_free_consistent;
  PstProfile profile;
  PstVariant variant;
  PstBlockReference *blocks;
  uint64_t block_count;
  uint64_t block_capacity;
  PstOffsetSet visited_pages;
} PstLayout;

typedef struct PstTrialResult {
  bool complete;
  PstProfile profile;
  PstVariant variant;
  uint64_t file_size;
  uint64_t failure_offset;
  uint64_t amap_failure_offset;
  uint64_t verified_amap_pages;
  uint64_t verified_amap_allocations;
  uint64_t verified_pages;
  uint64_t verified_blocks;
  uint64_t verified_nbt_entries;
  PstFailureAnchor amap_failure_anchor;
  PstFailureAnchor failure_anchor;
} PstTrialResult;

typedef enum PstSearchContext {
  PST_SEARCH_BACKSHIFT,
  PST_SEARCH_AMAP_BACKSHIFT,
  PST_SEARCH_BOUNDARY,
  PST_SEARCH_AMAP_ANCHOR,
  PST_SEARCH_ANCHOR,
  PST_SEARCH_TRAILER,
  PST_SEARCH_SUFFIX,
  PST_SEARCH_BLOCK,
  PST_SEARCH_NEIGHBOR,
  PST_SEARCH_AMAP_SWAP,
  PST_SEARCH_SWAP,
  PST_SEARCH_TWO_RUN,
  PST_SEARCH_CONTEXTS
} PstSearchContext;

// Retain physical runs, validation evidence, and the next trial instead of
// file bytes or apparent block numbers. A split data block uses two runs;
// permutations are reproduced from the committed mapping after a checkpoint.
typedef struct PstRepairSearch {
  PstTrialResult best_result;
  uint32_t repairs;
  uint32_t pass;
  uint64_t target_slot;
  uint64_t next_actual;
  uint64_t next_boundary;
  uint64_t next_width;
  uint64_t best_first_slot;
  uint64_t best_blocks;
  int64_t best_actual;
  int64_t best_tail_actual;
  uint64_t best_prefix_blocks;
  int64_t first_amap_actual;
  uint64_t best_shift;
  uint32_t best_boundary_evidence;
  BlockValidationDecision best_confidence;
  uint64_t best_skipped_total;
  int64_t best_reservations;
  int64_t best_distance;
  bool initialized;
  bool done;
  bool ambiguous;
  bool amap_identity_ambiguous;
  bool best_permuted;
} PstRepairSearch;

// Publication uses the committed mapping plus one physical continuation.
// Keep the next trial and output count so checkpoints neither repeat earlier
// alternatives nor consume the publication budget again.
typedef struct PstFreeGapSearch {
  uint32_t repairs;
  uint32_t phase;
  uint32_t hypotheses;
  uint64_t next_slot;
  uint64_t width;
  bool initialized;
  bool done;
} PstFreeGapSearch;

typedef struct PstContinuityRun {
  uint64_t first_slot;
  uint64_t blocks;
  int64_t actual;
} PstContinuityRun;

// Retain substitutions, not file bytes. The parent mapping stays unchanged
// while one cumulative free-space alternative is checked and checkpointed.
typedef struct PstContinuitySearch {
  PstContinuityRun *runs;
  uint64_t count;
  uint64_t capacity;
  uint64_t next_slot;
  uint64_t run_start;
  uint32_t repairs;
  bool initialized;
  bool done;
  bool unverified;
} PstContinuitySearch;

typedef struct PstCarveState {
  uint32_t magic;
  uint32_t version;
  uint32_t profile;
  uint32_t variant;
  uint32_t initialized;
  uint32_t repairs;
  uint32_t search_phase;
  uint32_t amap_dirty;
  uint64_t file_size;
  uint64_t failure_offset;
  uint64_t target_slot;
  uint64_t resume_choice;
  XXH128_hash_t checkpoint_view;
  bool checkpoint_saved;
  PstRepairSearch searches[PST_SEARCH_CONTEXTS];
  PstFreeGapSearch free_gaps;
  PstContinuitySearch continuity;
} PstCarveState;

static uint32_t pst_crc32_table[256];
static pthread_once_t pst_crc32_once = PTHREAD_ONCE_INIT;

static inline uint16_t pst_read_le16(const uint8_t *data);
static inline uint32_t pst_read_le32(const uint8_t *data);
static inline uint64_t pst_read_le64(const uint8_t *data);
static inline bool pst_range_available(uint64_t length, uint64_t offset,
                                       uint64_t size);
static void pst_initialize_crc32_table(void);
static inline uint32_t pst_weak_crc32(const uint8_t *data, uint64_t length);
static inline uint32_t pst_weak_crc32_with_substitution(
    const uint8_t *data, uint64_t length, uint64_t substituted_offset,
    uint8_t substituted_value);
static inline uint16_t pst_compute_signature(uint64_t offset, uint64_t bid);
static inline uint64_t pst_normalize_bid(uint64_t bid);
static inline uint64_t pst_round_up(uint64_t value, uint64_t alignment);
static inline uint64_t pst_hash_offset(uint64_t value);
static inline void pst_clear_failure_anchor(PstLayout *layout);
static inline void pst_set_failure_anchor(
    PstLayout *layout, PstAnchorKind kind, uint64_t logical_offset,
    uint64_t bid, uint64_t extent, uint32_t data_size,
    uint8_t page_type, uint8_t page_level);
static inline void pst_offset_set_clear(PstOffsetSet *set);
static inline bool pst_offset_set_resize(PstOffsetSet *set,
                                         uint64_t capacity);
static inline bool pst_offset_set_insert(PstOffsetSet *set, uint64_t offset);
static inline bool pst_offset_set_contains(const PstOffsetSet *set, uint64_t offset);
static inline void pst_layout_clear(PstLayout *layout);
static inline bool pst_append_block(PstLayout *layout, uint64_t bid,
                                    uint64_t offset, uint32_t data_size);
static int pst_compare_block_bid(const void *left, const void *right);
static inline const PstBlockReference *pst_find_block(
    const PstLayout *layout, uint64_t bid);
static inline bool pst_parse_header(const uint8_t *data, uint64_t length,
                                    PstLayout *layout);
static inline bool pst_validate_amap_page(PstLayout *layout, uint64_t offset,
                                          uint64_t *free_bytes);
static inline bool pst_validate_allocation_maps(PstLayout *layout);
static inline bool pst_amap_range_allocated(const PstLayout *layout,
                                            uint64_t offset,
                                            uint64_t size);
static inline bool pst_amap_range_free(const PstLayout *layout,
                                       uint64_t offset,
                                       uint64_t size);
static inline bool pst_validate_known_allocations(PstLayout *layout);
static inline bool pst_validate_page(PstLayout *layout, uint64_t offset,
                                     uint64_t expected_bid,
                                     uint8_t expected_type,
                                     uint32_t expected_level,
                                     uint32_t depth);
static inline bool pst_validate_block(PstLayout *layout,
                                      const PstBlockReference *block);
static inline bool pst_validate_nbt_references(PstLayout *layout,
                                               uint64_t offset,
                                               uint64_t expected_bid,
                                               uint32_t expected_level,
                                               uint32_t depth);
static inline bool pst_parse(const uint8_t *data, uint64_t length,
                             PstLayout *layout);
static inline char *pst_no_header_discovery(char *base, uint64_t offset,
                                            uint64_t remaining,
                                            char **matchpos,
                                            uint32_t *matchlen,
                                            uint32_t blocksize);
static inline uint32_t pst_block_validate(
    char *data, uint64_t length, BlockValidationDecision *decision,
    uint64_t *validates_to, uint32_t needleidx, uint32_t blocksize,
    void *blockhashkey);
static inline void pst_file_validate(char *data, uint64_t length,
                                     bool *validates,
                                     uint64_t *validates_to,
                                     bool *promising,
                                     uint32_t needleidx,
                                     uint32_t blocksize,
                                     void *carvehashkey);
static inline const char *pst_profile_filetype(PstProfile profile);
static inline void pst_assign_candidate_profile(CarveInfo *candidate,
                                                PstProfile profile);
static inline void pst_candidate_classify(CarveInfo *candidate,
                                          bool *validates,
                                          uint64_t *validates_to,
                                          bool *promising);
static inline bool pst_reassembly_initialize_candidate(
    CarveInfo *candidate, PstCarveState *state);
static inline bool pst_reassembly_evaluate_candidate(
    CarveInfo *candidate, PstTrialResult *result);
static inline int pst_reassembly_compare_trials(
    const PstTrialResult *left, const PstTrialResult *right);
static inline int64_t pst_reassembly_find_actual_slot(
    BlockVector *blockvector, int64_t actual_block);
static inline PstRepairSearch *pst_reassembly_search(
    PstCarveState *state, PstSearchContext context,
    const PstTrialResult *current, uint64_t target_slot);
static inline void pst_reassembly_record_best(
    PstRepairSearch *search, const PstTrialResult *result,
    uint64_t first_slot, uint64_t blocks, int64_t actual);
static inline void pst_reassembly_restore_best(
    BlockVector *blockvector, const PstRepairSearch *search, int64_t *best);
static inline bool pst_reassembly_anchor_mapping(
    BlockVector *blockvector, PstVariant variant, int64_t *mapping,
    uint64_t first_slot, uint64_t blocks, int64_t actual, bool permute);
static inline XXH128_hash_t pst_reassembly_view_hash(CarveInfo *candidate);
static inline void pst_reassembly_resume_searches(
    CarveInfo *candidate, PstCarveState *state);
static inline bool pst_reassembly_poll(ThreadWork *work,
                                       CarveInfo **candidate,
                                       PstCarveState *state,
                                       uuid_string_t uuidp,
                                       uuid_string_t uuidc);
static inline bool pst_reassembly_try_boundary_refinement(
    ThreadWork *work, CarveInfo **candidate, PstCarveState *state,
    const PstTrialResult *current, uuid_string_t uuidp,
    uuid_string_t uuidc, bool *improved);
static inline bool pst_reassembly_anchor_matches(
    const PstTrialResult *current, const PstFailureAnchor *anchor,
    const uint8_t *data, uint64_t available);
static inline bool pst_reassembly_try_transition_backshift(
    ThreadWork *work, CarveInfo **candidate, PstCarveState *state,
    const PstTrialResult *current, const PstFailureAnchor *anchor,
    uuid_string_t uuidp, uuid_string_t uuidc, bool *improved);
static inline bool pst_reassembly_try_anchor_replacement(
    ThreadWork *work, CarveInfo **candidate, PstCarveState *state,
    const PstTrialResult *current, const PstFailureAnchor *anchor,
    uuid_string_t uuidp, uuid_string_t uuidc, bool permute, bool *improved);
static inline bool pst_reassembly_data_trailer_matches(
    const PstTrialResult *current, const uint8_t *data,
    uint64_t available);
static inline bool pst_reassembly_try_data_trailer_replacement(
    ThreadWork *work, CarveInfo **candidate, PstCarveState *state,
    const PstTrialResult *current, uuid_string_t uuidp,
    uuid_string_t uuidc, bool *improved);
static inline bool pst_reassembly_try_split_data(
    ThreadWork *work, CarveInfo **candidate, PstCarveState *state,
    const PstTrialResult *current, uuid_string_t uuidp,
    uuid_string_t uuidc, bool *improved);
static inline bool pst_reassembly_try_suffix_shift(
    ThreadWork *work, CarveInfo **candidate, PstCarveState *state,
    const PstTrialResult *current, uint64_t target_slot,
    uuid_string_t uuidp, uuid_string_t uuidc, bool *improved);
static inline bool pst_reassembly_write_free_gap_hypotheses(
    ThreadWork *work, CarveInfo **candidate, PstCarveState *state,
    uuid_string_t uuidp, uuid_string_t uuidc);
static inline void pst_continuity_clear(PstContinuitySearch *search);
static inline bool pst_reassembly_write_continuity_hypothesis(
    ThreadWork *work, CarveInfo **candidate, PstCarveState *state,
    uuid_string_t uuidp, uuid_string_t uuidc);
static inline bool pst_reassembly_try_block_replacement(
    ThreadWork *work, CarveInfo **candidate, PstCarveState *state,
    const PstTrialResult *current, uint64_t target_slot,
    uuid_string_t uuidp, uuid_string_t uuidc, bool *improved);
static inline void pst_reassembly(ThreadWork *work,
                                  CarveInfo **candidate,
                                  uuid_string_t uuidp,
                                  uuid_string_t uuidc);
static inline bool pst_serialize_carve_state(void **state, FILE *fp,
                                             StateSerialization mode);
static inline void *pst_clone_carve_state(const void *srcstate);
static inline void pst_free_carve_state(void **state);
static inline void pst_print_carve_state(const void *state);

static inline uint16_t pst_read_le16(const uint8_t *data) {
  return (uint16_t)data[0] | ((uint16_t)data[1] << 8);
}

static inline uint32_t pst_read_le32(const uint8_t *data) {
  return (uint32_t)data[0]
         | ((uint32_t)data[1] << 8)
         | ((uint32_t)data[2] << 16)
         | ((uint32_t)data[3] << 24);
}

static inline uint64_t pst_read_le64(const uint8_t *data) {
  return (uint64_t)pst_read_le32(data)
         | ((uint64_t)pst_read_le32(data + 4) << 32);
}

static inline bool pst_range_available(uint64_t length, uint64_t offset,
                                       uint64_t size) {
  return offset <= length && size <= length - offset;
}

static void pst_initialize_crc32_table(void) {
  for (uint32_t index = 0; index < 256; index++) {
    uint32_t crc = index;

    for (uint32_t bit = 0; bit < 8; bit++) {
      crc = (crc & 1) != 0 ? UINT32_C(0xedb88320) ^ (crc >> 1)
                           : crc >> 1;
    }
    pst_crc32_table[index] = crc;
  }
}

// PST uses the CRC-32 polynomial without the initial and final complements
// used by the conventional zlib interface.
//
static inline uint32_t pst_weak_crc32(const uint8_t *data, uint64_t length) {
  pthread_once(&pst_crc32_once, pst_initialize_crc32_table);

  uint32_t crc = 0;

  for (uint64_t offset = 0; offset < length; offset++) {
    crc = pst_crc32_table[(crc ^ data[offset]) & UINT32_C(0xff)]
          ^ (crc >> 8);
  }
  return crc;
}

static inline uint32_t pst_weak_crc32_with_substitution(
    const uint8_t *data, uint64_t length, uint64_t substituted_offset,
    uint8_t substituted_value) {
  pthread_once(&pst_crc32_once, pst_initialize_crc32_table);

  uint32_t crc = 0;

  for (uint64_t offset = 0; offset < length; offset++) {
    const uint8_t value = offset == substituted_offset
                              ? substituted_value : data[offset];

    crc = pst_crc32_table[(crc ^ value) & UINT32_C(0xff)] ^ (crc >> 8);
  }
  return crc;
}

static inline uint16_t pst_compute_signature(uint64_t offset, uint64_t bid) {
  const uint32_t value = (uint32_t)(offset ^ bid);
  return (uint16_t)((uint16_t)value ^ (uint16_t)(value >> 16));
}

static inline uint64_t pst_normalize_bid(uint64_t bid) {
  return bid & ~UINT64_C(1);
}

static inline uint64_t pst_round_up(uint64_t value, uint64_t alignment) {
  if (alignment == 0 || value > UINT64_MAX - (alignment - 1)) {
    return 0;
  }
  return ((value + alignment - 1) / alignment) * alignment;
}

static inline uint64_t pst_hash_offset(uint64_t value) {
  value ^= value >> 30;
  value *= UINT64_C(0xbf58476d1ce4e5b9);
  value ^= value >> 27;
  value *= UINT64_C(0x94d049bb133111eb);
  value ^= value >> 31;
  return value;
}

static inline void pst_clear_failure_anchor(PstLayout *layout) {
  if (!layout) {
    return;
  }
  memset(&layout->failure_anchor, 0, sizeof(layout->failure_anchor));
}

static inline void pst_set_failure_anchor(
    PstLayout *layout, PstAnchorKind kind, uint64_t logical_offset,
    uint64_t bid, uint64_t extent, uint32_t data_size,
    uint8_t page_type, uint8_t page_level) {
  if (!layout) {
    return;
  }
  layout->failure_anchor.kind = kind;
  layout->failure_anchor.page_type = page_type;
  layout->failure_anchor.page_level = page_level;
  layout->failure_anchor.logical_offset = logical_offset;
  layout->failure_anchor.bid = bid;
  layout->failure_anchor.extent = extent;
  layout->failure_anchor.data_size = data_size;
}

static inline void pst_offset_set_clear(PstOffsetSet *set) {
  if (!set) {
    return;
  }
  free(set->entries);
  memset(set, 0, sizeof(*set));
}

static inline bool pst_offset_set_resize(PstOffsetSet *set,
                                         uint64_t capacity) {
  if (!set || capacity < 16 || capacity > SIZE_MAX / sizeof(uint64_t)) {
    return false;
  }
  uint64_t *entries = (uint64_t *)calloc((size_t)capacity,
                                         sizeof(*entries));

  if (!entries) {
    return false;
  }
  if (set->entries) {
    for (uint64_t index = 0; index < set->capacity; index++) {
      const uint64_t stored = set->entries[index];

      if (stored == 0) {
        continue;
      }
      uint64_t slot = pst_hash_offset(stored) & (capacity - 1);

      while (entries[slot] != 0) {
        slot = (slot + 1) & (capacity - 1);
      }
      entries[slot] = stored;
    }
  }
  free(set->entries);
  set->entries = entries;
  set->capacity = capacity;
  return true;
}

// Insert offset + 1 so that byte offset zero remains representable while a
// zero hash entry continues to mean unused.
//
static inline bool pst_offset_set_insert(PstOffsetSet *set, uint64_t offset) {
  if (!set || offset == UINT64_MAX) {
    return false;
  }
  if (set->capacity == 0 && !pst_offset_set_resize(set, 16)) {
    return false;
  }
  if ((set->count + 1) * 10 >= set->capacity * 7
      && !pst_offset_set_resize(set, set->capacity * 2)) {
    return false;
  }
  const uint64_t stored = offset + 1;
  uint64_t slot = pst_hash_offset(stored) & (set->capacity - 1);

  while (set->entries[slot] != 0) {
    if (set->entries[slot] == stored) {
      return false;
    }
    slot = (slot + 1) & (set->capacity - 1);
  }
  set->entries[slot] = stored;
  set->count++;
  return true;
}

static inline bool pst_offset_set_contains(const PstOffsetSet *set,
                                            uint64_t offset) {
  if (!set || set->capacity == 0 || offset == UINT64_MAX) {
    return false;
  }
  const uint64_t stored = offset + 1;
  uint64_t slot = pst_hash_offset(stored) & (set->capacity - 1);
  while (set->entries[slot] != 0) {
    if (set->entries[slot] == stored) {
      return true;
    }
    slot = (slot + 1) & (set->capacity - 1);
  }
  return false;
}

static inline void pst_layout_clear(PstLayout *layout) {
  if (!layout) {
    return;
  }
  free(layout->blocks);
  layout->blocks = NULL;
  layout->block_count = 0;
  layout->block_capacity = 0;
  pst_offset_set_clear(&layout->visited_pages);
}

static inline bool pst_append_block(PstLayout *layout, uint64_t bid,
                                    uint64_t offset, uint32_t data_size) {
  if (!layout || bid == 0 || data_size == 0) {
    return false;
  }
  if (layout->block_count == layout->block_capacity) {
    uint64_t capacity = layout->block_capacity == 0
                            ? 256 : layout->block_capacity * 2;

    if (capacity > SIZE_MAX / sizeof(*layout->blocks)) {
      return false;
    }
    PstBlockReference *blocks = (PstBlockReference *)realloc(
        layout->blocks, (size_t)capacity * sizeof(*blocks));

    if (!blocks) {
      return false;
    }
    layout->blocks = blocks;
    layout->block_capacity = capacity;
  }
  PstBlockReference *block = &layout->blocks[layout->block_count++];

  block->bid = pst_normalize_bid(bid);
  block->offset = offset;
  block->data_size = data_size;
  return true;
}

static int pst_compare_block_bid(const void *left, const void *right) {
  const PstBlockReference *a = (const PstBlockReference *)left;
  const PstBlockReference *b = (const PstBlockReference *)right;

  if (a->bid < b->bid) {
    return -1;
  }
  if (a->bid > b->bid) {
    return 1;
  }
  return 0;
}

static inline const PstBlockReference *pst_find_block(
    const PstLayout *layout, uint64_t bid) {
  if (!layout || layout->block_count == 0 || bid == 0) {
    return NULL;
  }
  PstBlockReference key;

  memset(&key, 0, sizeof(key));
  key.bid = pst_normalize_bid(bid);
  return (const PstBlockReference *)bsearch(
      &key, layout->blocks, (size_t)layout->block_count,
      sizeof(*layout->blocks), pst_compare_block_bid);
}

static inline bool pst_parse_header(const uint8_t *data, uint64_t length,
                                    PstLayout *layout) {
  if (!layout) {
    return false;
  }
  memset(layout, 0, sizeof(*layout));
  if (!data || length < PST_HEADER_MINIMUM_SIZE
      || pst_read_le32(data) != PST_HEADER_MAGIC) {
    return false;
  }
  layout->data = data;
  layout->length = length;
  layout->failure_offset = 0;

  if (data[8] == 'S' && data[9] == 'M') {
    layout->profile = PST_PROFILE_PST;
  }
  else if (data[8] == 'S' && data[9] == 'O') {
    layout->profile = PST_PROFILE_OST;
  }
  else if (data[8] == 'B' && data[9] == 'A') {
    layout->profile = PST_PROFILE_PAB;
  }
  else {
    return false;
  }

  const uint16_t version = pst_read_le16(data + 10);
  uint64_t amap_valid_offset = 0;

  if (version == 14 || version == 15) {
    layout->variant = PST_VARIANT_ANSI;
    layout->page_size = PST_ANSI_PAGE_SIZE;
    layout->page_data_size = 500;
    layout->page_metadata_offset = 496;
    layout->page_trailer_offset = 500;
    layout->block_trailer_size = PST_ANSI_BLOCK_TRAILER_SIZE;
    layout->block_alignment = PST_STANDARD_BLOCK_ALIGNMENT;
    layout->maximum_block_size = PST_STANDARD_MAXIMUM_BLOCK_SIZE;
    layout->amap_first_offset = PST_STANDARD_AMAP_FIRST_OFFSET;
    layout->amap_interval = PST_STANDARD_AMAP_INTERVAL;
    layout->amap_data_offset = 4;
    layout->amap_data_size = 496;
    layout->amap_granularity = PST_STANDARD_BLOCK_ALIGNMENT;
    amap_valid_offset = PST_ANSI_AMAP_VALID_OFFSET;
  }
  else if (version == 21 || version == 23) {
    layout->variant = PST_VARIANT_UNICODE;
    layout->page_size = PST_UNICODE_PAGE_SIZE;
    layout->page_data_size = 496;
    layout->page_metadata_offset = 488;
    layout->page_trailer_offset = 496;
    layout->block_trailer_size = PST_UNICODE_BLOCK_TRAILER_SIZE;
    layout->block_alignment = PST_STANDARD_BLOCK_ALIGNMENT;
    layout->maximum_block_size = PST_STANDARD_MAXIMUM_BLOCK_SIZE;
    layout->amap_first_offset = PST_STANDARD_AMAP_FIRST_OFFSET;
    layout->amap_interval = PST_STANDARD_AMAP_INTERVAL;
    layout->amap_data_size = 496;
    layout->amap_granularity = PST_STANDARD_BLOCK_ALIGNMENT;
    amap_valid_offset = PST_UNICODE_AMAP_VALID_OFFSET;
  }
  else if (version >= 36) {
    layout->variant = PST_VARIANT_UNICODE_4K;
    layout->page_size = PST_UNICODE_4K_PAGE_SIZE;
    layout->page_data_size = 4072;
    layout->page_metadata_offset = 4056;
    layout->page_trailer_offset = 4072;
    layout->block_trailer_size = PST_UNICODE_4K_BLOCK_TRAILER_SIZE;
    layout->block_alignment = PST_UNICODE_4K_BLOCK_ALIGNMENT;
    layout->maximum_block_size = PST_UNICODE_4K_MAXIMUM_BLOCK_SIZE;
    layout->amap_first_offset = PST_UNICODE_4K_AMAP_FIRST_OFFSET;
    layout->amap_interval = PST_UNICODE_4K_AMAP_INTERVAL;
    layout->amap_data_size = 4072;
    layout->amap_granularity = PST_UNICODE_4K_BLOCK_ALIGNMENT;
    amap_valid_offset = PST_UNICODE_AMAP_VALID_OFFSET;
  }
  else {
    return false;
  }

  const uint32_t partial_crc = pst_read_le32(
      data + PST_HEADER_PARTIAL_CRC_OFFSET);
  uint8_t crc_amap_value = data[amap_valid_offset];

  if (crc_amap_value > 2) {
    return false;
  }
  layout->amap_dirty = crc_amap_value == 0;

  if (pst_weak_crc32(data + PST_HEADER_PARTIAL_CRC_DATA_OFFSET,
                     PST_HEADER_PARTIAL_CRC_DATA_SIZE) != partial_crc) {
    crc_amap_value = 0;
    if (data[amap_valid_offset] == 0) {
      for (uint8_t value = 1; value <= 2; value++) {
        if (pst_weak_crc32_with_substitution(
                data + PST_HEADER_PARTIAL_CRC_DATA_OFFSET,
                PST_HEADER_PARTIAL_CRC_DATA_SIZE,
                amap_valid_offset - PST_HEADER_PARTIAL_CRC_DATA_OFFSET,
                value) == partial_crc) {
          crc_amap_value = value;
          break;
        }
      }
    }
    if (crc_amap_value == 0) {
      return false;
    }
    // Writers clear fAMapValid while modifying allocation metadata. A
    // read-only validator accepts that transactional byte only when restoring
    // a defined valid value exactly reproduces every stored header CRC.
    //
    layout->amap_dirty = true;
  }

  if (layout->variant == PST_VARIANT_ANSI) {
    if (data[460] != UINT8_C(0x80) || data[461] > 2) {
      return false;
    }
    layout->file_size = pst_read_le32(data + 168);
    layout->amap_last_offset = pst_read_le32(data + 172);
    layout->amap_free_bytes = pst_read_le32(data + 176);
    layout->nbt_root_bid = pst_read_le32(data + 184);
    layout->nbt_root_offset = pst_read_le32(data + 188);
    layout->bbt_root_bid = pst_read_le32(data + 192);
    layout->bbt_root_offset = pst_read_le32(data + 196);
  }
  else {
    if (length < PST_UNICODE_HEADER_SIZE || data[512] != UINT8_C(0x80)
        || data[513] > 2) {
      return false;
    }
    const uint32_t full_crc = pst_read_le32(
        data + PST_HEADER_FULL_CRC_OFFSET);

    const uint32_t calculated_full_crc = layout->amap_dirty
        ? pst_weak_crc32_with_substitution(
              data + PST_HEADER_PARTIAL_CRC_DATA_OFFSET,
              PST_HEADER_FULL_CRC_DATA_SIZE,
              amap_valid_offset - PST_HEADER_PARTIAL_CRC_DATA_OFFSET,
              crc_amap_value)
        : pst_weak_crc32(data + PST_HEADER_PARTIAL_CRC_DATA_OFFSET,
                         PST_HEADER_FULL_CRC_DATA_SIZE);

    if (calculated_full_crc != full_crc) {
      return false;
    }
    layout->file_size = pst_read_le64(data + 184);
    layout->amap_last_offset = pst_read_le64(data + 192);
    layout->amap_free_bytes = pst_read_le64(data + 200);
    layout->nbt_root_bid = pst_read_le64(data + 216);
    layout->nbt_root_offset = pst_read_le64(data + 224);
    layout->bbt_root_bid = pst_read_le64(data + 232);
    layout->bbt_root_offset = pst_read_le64(data + 240);
  }

  if (layout->file_size < PST_HEADER_MINIMUM_SIZE
      || layout->file_size > PST_MAXIMUM_FILE_SIZE
      || layout->file_size % layout->block_alignment != 0
      || layout->nbt_root_bid == 0 || layout->bbt_root_bid == 0
      || layout->nbt_root_offset < PST_HEADER_MINIMUM_SIZE
      || layout->bbt_root_offset < PST_HEADER_MINIMUM_SIZE
      || layout->nbt_root_offset % layout->page_size != 0
      || layout->bbt_root_offset % layout->page_size != 0
      || !pst_range_available(layout->file_size, layout->nbt_root_offset,
                              layout->page_size)
      || !pst_range_available(layout->file_size, layout->bbt_root_offset,
                              layout->page_size)) {
    return false;
  }
  layout->failure_offset = PST_HEADER_MINIMUM_SIZE;
  return true;
}

static inline bool pst_validate_amap_page(PstLayout *layout, uint64_t offset,
                                          uint64_t *free_bytes) {
  if (!layout || !layout->data || !free_bytes
      || layout->amap_data_size == 0 || layout->amap_granularity == 0
      || !pst_range_available(layout->file_size, offset,
                              layout->page_size)
      || !pst_range_available(layout->length, offset,
                              layout->page_size)) {
    if (layout) {
      layout->failure_offset = offset;
      pst_set_failure_anchor(layout, PST_ANCHOR_AMAP_PAGE, offset, offset,
                             layout->page_size, 0,
                             PST_PAGE_TYPE_AMAP, 0);
    }
    return false;
  }

  const uint8_t *page = layout->data + offset;
  const uint8_t *map = page + layout->amap_data_offset;
  const uint8_t *trailer = page + layout->page_trailer_offset;
  uint32_t stored_crc = 0;
  uint64_t stored_bid = 0;

  if (layout->variant == PST_VARIANT_ANSI) {
    stored_bid = pst_read_le32(trailer + 4);
    stored_crc = pst_read_le32(trailer + 8);
  }
  else {
    stored_crc = pst_read_le32(trailer + 4);
    stored_bid = pst_read_le64(trailer + 8);
  }

  if (trailer[0] != PST_PAGE_TYPE_AMAP
      || trailer[1] != PST_PAGE_TYPE_AMAP
      || pst_read_le16(trailer + 2) != 0 || stored_bid != offset
      || stored_crc != pst_weak_crc32(map, layout->amap_data_size)
      || map[0] != UINT8_C(0xff)) {
    layout->failure_offset = offset;
    pst_set_failure_anchor(layout, PST_ANCHOR_AMAP_PAGE, offset, offset,
                           layout->page_size, 0,
                           PST_PAGE_TYPE_AMAP, 0);
    return false;
  }

  uint64_t allocated_bits = 0;

  for (uint64_t index = 0; index < layout->amap_data_size; index++) {
    allocated_bits += (uint64_t)__builtin_popcount((unsigned int)map[index]);
  }
  const uint64_t total_bits = layout->amap_data_size * 8;
  const uint64_t page_free_bytes = (total_bits - allocated_bits)
                                   * layout->amap_granularity;

  if (*free_bytes > UINT64_MAX - page_free_bytes) {
    layout->failure_offset = offset;
    pst_clear_failure_anchor(layout);
    return false;
  }
  *free_bytes += page_free_bytes;
  layout->verified_amap_pages++;
  return true;
}

// AMaps are authoritative only when the header marks them valid. Their page
// trailers authenticate the allocation data independently of the BBT and NBT.
//
static inline bool pst_validate_allocation_maps(PstLayout *layout) {
  if (!layout || !layout->data) {
    return false;
  }
  if (layout->amap_dirty) {
    return true;
  }
  if (layout->amap_first_offset == 0 || layout->amap_interval == 0
      || layout->amap_data_size == 0 || layout->amap_granularity == 0
      || layout->file_size < layout->page_size
      || layout->amap_first_offset
             > layout->file_size - layout->page_size) {
    layout->failure_offset = layout->amap_first_offset;
    return false;
  }

  const uint64_t expected_last = layout->amap_first_offset
      + ((layout->file_size - layout->page_size
          - layout->amap_first_offset) / layout->amap_interval)
            * layout->amap_interval;

  if (layout->amap_last_offset != expected_last) {
    layout->failure_offset = layout->amap_last_offset;
    return false;
  }

  uint64_t free_bytes = 0;

  for (uint64_t offset = layout->amap_first_offset;;) {
    if (!pst_validate_amap_page(layout, offset, &free_bytes)) {
      return false;
    }
    if (offset == layout->amap_last_offset) {
      break;
    }
    if (offset > layout->amap_last_offset - layout->amap_interval) {
      layout->failure_offset = offset;
      return false;
    }
    offset += layout->amap_interval;
  }
  layout->amap_free_consistent = free_bytes == layout->amap_free_bytes;
  return true;
}

static inline bool pst_amap_range_allocated(const PstLayout *layout,
                                            uint64_t offset,
                                            uint64_t size) {
  if (!layout || !layout->data || size == 0
      || offset > UINT64_MAX - size || offset + size > layout->file_size
      || offset % layout->amap_granularity != 0
      || size % layout->amap_granularity != 0) {
    return false;
  }

  const uint64_t end = offset + size;

  while (offset < end) {
    if (offset < layout->amap_first_offset) {
      const uint64_t before_maps = layout->amap_first_offset - offset;
      const uint64_t skip = before_maps < end - offset
                                ? before_maps : end - offset;

      offset += skip;
      continue;
    }

    const uint64_t map_index = (offset - layout->amap_first_offset)
                               / layout->amap_interval;
    const uint64_t map_offset = layout->amap_first_offset
                                + map_index * layout->amap_interval;
    const uint64_t relative = offset - map_offset;
    const uint64_t bit_index = relative / layout->amap_granularity;

    if (map_offset > layout->amap_last_offset
        || bit_index >= layout->amap_data_size * 8) {
      return false;
    }
    const uint8_t map_byte = layout->data[
        map_offset + layout->amap_data_offset + bit_index / 8];

    if ((map_byte & (UINT8_C(0x80) >> (bit_index % 8))) == 0) {
      return false;
    }
    offset += layout->amap_granularity;
  }
  return true;
}

// Confirm that every allocation unit in a range covered by an authenticated
// AMap is free. Bytes before the first AMap are not classified by this helper.
//
static inline bool pst_amap_range_free(const PstLayout *layout,
                                       uint64_t offset,
                                       uint64_t size) {
  if (!layout || !layout->data || size == 0
      || layout->amap_dirty || layout->verified_amap_pages == 0
      || offset < layout->amap_first_offset
      || offset > UINT64_MAX - size || offset + size > layout->file_size
      || offset % layout->amap_granularity != 0
      || size % layout->amap_granularity != 0) {
    return false;
  }

  const uint64_t end = offset + size;

  while (offset < end) {
    const uint64_t map_index = (offset - layout->amap_first_offset)
                               / layout->amap_interval;
    const uint64_t map_offset = layout->amap_first_offset
                                + map_index * layout->amap_interval;
    const uint64_t relative = offset - map_offset;
    const uint64_t bit_index = relative / layout->amap_granularity;

    if (map_offset > layout->amap_last_offset
        || bit_index >= layout->amap_data_size * 8) {
      return false;
    }
    const uint8_t map_byte = layout->data[
        map_offset + layout->amap_data_offset + bit_index / 8];

    if ((map_byte & (UINT8_C(0x80) >> (bit_index % 8))) != 0) {
      return false;
    }
    offset += layout->amap_granularity;
  }
  return true;
}

static inline bool pst_validate_known_allocations(PstLayout *layout) {
  if (!layout || !layout->data) {
    return false;
  }
  if (layout->amap_dirty) {
    return true;
  }

  for (uint64_t index = 0; index < layout->visited_pages.capacity; index++) {
    const uint64_t stored = layout->visited_pages.entries[index];

    if (stored == 0) {
      continue;
    }
    const uint64_t offset = stored - 1;

    if (!pst_amap_range_allocated(layout, offset, layout->page_size)) {
      layout->failure_offset = offset;
      return false;
    }
    layout->verified_amap_allocations++;
  }

  for (uint64_t index = 0; index < layout->block_count; index++) {
    const PstBlockReference *block = &layout->blocks[index];
    const uint64_t allocation_size = pst_round_up(
        block->data_size + layout->block_trailer_size,
        layout->block_alignment);

    if (allocation_size == 0
        || !pst_amap_range_allocated(layout, block->offset,
                                     allocation_size)) {
      layout->failure_offset = block->offset;
      return false;
    }
    layout->verified_amap_allocations++;
  }
  return true;
}

static inline bool pst_validate_page(PstLayout *layout, uint64_t offset,
                                     uint64_t expected_bid,
                                     uint8_t expected_type,
                                     uint32_t expected_level,
                                     uint32_t depth) {
  if (!layout || !layout->data || depth > PST_MAXIMUM_BTREE_DEPTH
      || expected_bid == 0 || offset % layout->page_size != 0
      || !pst_range_available(layout->file_size, offset,
                              layout->page_size)
      || !pst_range_available(layout->length, offset,
                              layout->page_size)) {
    if (layout && offset < layout->file_size) {
      layout->failure_offset = offset;
      pst_set_failure_anchor(layout, PST_ANCHOR_BTREE_PAGE, offset,
                             expected_bid, layout->page_size, 0,
                             expected_type,
                             depth == 0 ? UINT8_MAX
                                        : (uint8_t)expected_level);
    }
    return false;
  }
  if (!pst_offset_set_insert(&layout->visited_pages, offset)) {
    layout->failure_offset = offset;
    pst_clear_failure_anchor(layout);
    return false;
  }

  const uint8_t *page = layout->data + offset;
  const uint8_t *metadata = page + layout->page_metadata_offset;
  const uint8_t *trailer = page + layout->page_trailer_offset;
  uint32_t entry_count = 0;
  uint32_t maximum_entries = 0;
  uint8_t entry_size = 0;
  uint8_t level = 0;
  uint8_t page_type = trailer[0];
  uint8_t page_type_copy = trailer[1];
  uint16_t signature = pst_read_le16(trailer + 2);
  uint32_t stored_crc = 0;
  uint64_t stored_bid = 0;

  if (layout->variant == PST_VARIANT_ANSI) {
    entry_count = metadata[0];
    maximum_entries = metadata[1];
    entry_size = metadata[2];
    level = metadata[3];
    stored_bid = pst_read_le32(trailer + 4);
    stored_crc = pst_read_le32(trailer + 8);
  }
  else {
    if (layout->variant == PST_VARIANT_UNICODE_4K) {
      entry_count = pst_read_le16(metadata);
      maximum_entries = pst_read_le16(metadata + 2);
      entry_size = metadata[4];
      level = metadata[5];
    }
    else {
      entry_count = metadata[0];
      maximum_entries = metadata[1];
      entry_size = metadata[2];
      level = metadata[3];
    }
    stored_crc = pst_read_le32(trailer + 4);
    stored_bid = pst_read_le64(trailer + 8);
  }

  const uint8_t expected_entry_size = level == 0
      ? (expected_type == PST_PAGE_TYPE_BBT
             ? (layout->variant == PST_VARIANT_ANSI ? 12 : 24)
             : (layout->variant == PST_VARIANT_ANSI ? 16 : 32))
      : (layout->variant == PST_VARIANT_ANSI ? 12 : 24);
  const uint32_t calculated_maximum = (uint32_t)(
      layout->page_metadata_offset / expected_entry_size);
  const bool root_bid_transition = layout->amap_dirty && depth == 0;

  if (page_type != expected_type || page_type_copy != expected_type
      || level != expected_level || entry_count == 0
      || entry_size != expected_entry_size
      || maximum_entries != calculated_maximum
      || entry_count > maximum_entries
      || (uint64_t)entry_count * entry_size
             > layout->page_metadata_offset
      || (!root_bid_transition
          && pst_normalize_bid(stored_bid)
                 != pst_normalize_bid(expected_bid))
      || signature != pst_compute_signature(offset, stored_bid)
      || stored_crc != pst_weak_crc32(page, layout->page_data_size)) {
    layout->failure_offset = offset;
    pst_set_failure_anchor(layout, PST_ANCHOR_BTREE_PAGE, offset,
                           root_bid_transition ? 0 : expected_bid,
                           layout->page_size, 0, expected_type,
                           depth == 0 ? UINT8_MAX
                                      : (uint8_t)expected_level);
    return false;
  }
  layout->verified_pages++;

  uint64_t previous_key = 0;
  uint64_t first_child_failure = 0;
  PstFailureAnchor first_child_anchor = {0};
  bool children_complete = true;

  for (uint32_t index = 0; index < entry_count; index++) {
    const uint8_t *entry = page + (uint64_t)index * entry_size;
    const uint64_t key = layout->variant == PST_VARIANT_ANSI
                             ? pst_read_le32(entry)
                             : pst_read_le64(entry);

    if (key == 0 || (index != 0 && key <= previous_key)) {
      layout->failure_offset = offset + (uint64_t)index * entry_size;
      pst_clear_failure_anchor(layout);
      return false;
    }
    previous_key = key;

    if (level != 0) {
      const uint64_t child_bid = layout->variant == PST_VARIANT_ANSI
                                     ? pst_read_le32(entry + 4)
                                     : pst_read_le64(entry + 8);
      const uint64_t child_offset = layout->variant == PST_VARIANT_ANSI
                                        ? pst_read_le32(entry + 8)
                                        : pst_read_le64(entry + 16);

      if (!pst_validate_page(layout, child_offset, child_bid,
                             expected_type, level - 1, depth + 1)) {
        if (children_complete) {
          first_child_failure = layout->failure_offset;
          first_child_anchor = layout->failure_anchor;
        }
        children_complete = false;
      }
    }
    else if (expected_type == PST_PAGE_TYPE_BBT) {
      const uint64_t bid = key;
      const uint64_t block_offset = layout->variant == PST_VARIANT_ANSI
                                        ? pst_read_le32(entry + 4)
                                        : pst_read_le64(entry + 8);
      const uint32_t data_size = pst_read_le16(
          entry + (layout->variant == PST_VARIANT_ANSI ? 8 : 16));

      if (!pst_append_block(layout, bid, block_offset, data_size)) {
        layout->failure_offset = offset + (uint64_t)index * entry_size;
        pst_clear_failure_anchor(layout);
        return false;
      }
    }
  }
  if (!children_complete) {
    layout->failure_offset = first_child_failure;
    layout->failure_anchor = first_child_anchor;
  }
  return children_complete;
}

static inline bool pst_validate_block(PstLayout *layout,
                                      const PstBlockReference *block) {
  if (!layout || !block || block->bid == 0 || block->data_size == 0
      || block->offset % layout->block_alignment != 0
      || block->data_size > layout->maximum_block_size
      || block->data_size > UINT64_MAX - layout->block_trailer_size) {
    if (layout && block) {
      layout->failure_offset = block->offset;
      pst_clear_failure_anchor(layout);
    }
    return false;
  }
  const uint64_t allocation_size = pst_round_up(
      block->data_size + layout->block_trailer_size,
      layout->block_alignment);

  if (allocation_size == 0 || allocation_size > layout->maximum_block_size
      || !pst_range_available(layout->file_size, block->offset,
                              allocation_size)
      || !pst_range_available(layout->length, block->offset,
                              allocation_size)) {
    layout->failure_offset = block->offset;
    if (allocation_size != 0) {
      pst_set_failure_anchor(layout, PST_ANCHOR_DATA_BLOCK,
                             block->offset, block->bid, allocation_size,
                             block->data_size, 0, 0);
    }
    else {
      pst_clear_failure_anchor(layout);
    }
    return false;
  }

  const uint8_t *data = layout->data + block->offset;
  const uint8_t *trailer = data + allocation_size
                           - layout->block_trailer_size;
  const uint32_t stored_size = pst_read_le16(trailer);
  const uint16_t stored_signature = pst_read_le16(trailer + 2);
  uint32_t stored_crc = 0;
  uint64_t stored_bid = 0;

  if (layout->variant == PST_VARIANT_ANSI) {
    stored_bid = pst_read_le32(trailer + 4);
    stored_crc = pst_read_le32(trailer + 8);
  }
  else {
    stored_crc = pst_read_le32(trailer + 4);
    stored_bid = pst_read_le64(trailer + 8);
  }

  if (stored_size != block->data_size
      || pst_normalize_bid(stored_bid) != block->bid
      || stored_signature != pst_compute_signature(block->offset,
                                                   stored_bid)
      || stored_crc != pst_weak_crc32(data, block->data_size)) {
    layout->failure_offset = block->offset;
    pst_set_failure_anchor(layout, PST_ANCHOR_DATA_BLOCK,
                           block->offset, block->bid, allocation_size,
                           block->data_size, 0, 0);
    return false;
  }
  layout->verified_blocks++;
  return true;
}

// Revisit the NBT after the BBT has been collected so every data and subnode
// BID can be checked against an independently validated block reference.
//
static inline bool pst_validate_nbt_references(PstLayout *layout,
                                               uint64_t offset,
                                               uint64_t expected_bid,
                                               uint32_t expected_level,
                                               uint32_t depth) {
  if (!layout || !layout->data || depth > PST_MAXIMUM_BTREE_DEPTH
      || expected_bid == 0 || offset % layout->page_size != 0
      || !pst_range_available(layout->length, offset,
                              layout->page_size)) {
    if (layout) {
      layout->failure_offset = offset;
      pst_clear_failure_anchor(layout);
    }
    return false;
  }
  const uint8_t *page = layout->data + offset;
  const uint8_t *metadata = page + layout->page_metadata_offset;
  uint32_t entry_count = 0;
  uint8_t entry_size = 0;
  uint8_t level = 0;

  if (layout->variant == PST_VARIANT_UNICODE_4K) {
    entry_count = pst_read_le16(metadata);
    entry_size = metadata[4];
    level = metadata[5];
  }
  else {
    entry_count = metadata[0];
    entry_size = metadata[2];
    level = metadata[3];
  }
  if (level != expected_level) {
    layout->failure_offset = offset;
    pst_clear_failure_anchor(layout);
    return false;
  }

  uint64_t first_failure = 0;
  bool complete = true;

  for (uint32_t index = 0; index < entry_count; index++) {
    const uint8_t *entry = page + (uint64_t)index * entry_size;

    if (level != 0) {
      const uint64_t child_bid = layout->variant == PST_VARIANT_ANSI
                                     ? pst_read_le32(entry + 4)
                                     : pst_read_le64(entry + 8);
      const uint64_t child_offset = layout->variant == PST_VARIANT_ANSI
                                        ? pst_read_le32(entry + 8)
                                        : pst_read_le64(entry + 16);

      if (!pst_validate_nbt_references(layout, child_offset, child_bid,
                                       level - 1, depth + 1)) {
        if (complete) {
          first_failure = layout->failure_offset;
        }
        complete = false;
      }
      continue;
    }

    const uint64_t data_bid = layout->variant == PST_VARIANT_ANSI
                                  ? pst_read_le32(entry + 4)
                                  : pst_read_le64(entry + 8);
    const uint64_t subnode_bid = layout->variant == PST_VARIANT_ANSI
                                     ? pst_read_le32(entry + 8)
                                     : pst_read_le64(entry + 16);

    if ((data_bid != 0 && !pst_find_block(layout, data_bid))
        || (subnode_bid != 0 && !pst_find_block(layout, subnode_bid))) {
      if (complete) {
        first_failure = offset + (uint64_t)index * entry_size;
      }
      pst_clear_failure_anchor(layout);
      complete = false;
      continue;
    }
    layout->verified_nbt_entries++;
  }
  if (!complete) {
    layout->failure_offset = first_failure;
  }
  return complete;
}

static inline bool pst_parse(const uint8_t *data, uint64_t length,
                             PstLayout *layout) {
  if (!layout || !pst_parse_header(data, length, layout)) {
    return false;
  }
  if (length < layout->file_size) {
    layout->failure_offset = length;
    pst_clear_failure_anchor(layout);
    return false;
  }

  const bool allocation_maps_complete = pst_validate_allocation_maps(layout);
  const uint64_t allocation_map_failure = layout->failure_offset;
  const PstFailureAnchor allocation_map_anchor = layout->failure_anchor;

  if (!allocation_maps_complete) {
    layout->amap_failure_offset = allocation_map_failure;
    layout->amap_failure_anchor = allocation_map_anchor;
  }
  layout->failure_offset = PST_HEADER_MINIMUM_SIZE;
  pst_clear_failure_anchor(layout);

  const uint8_t *bbt_metadata = data + layout->bbt_root_offset
                                + layout->page_metadata_offset;
  const uint32_t bbt_root_level = layout->variant
                                      == PST_VARIANT_UNICODE_4K
                                      ? bbt_metadata[5] : bbt_metadata[3];

  uint64_t structural_failure = UINT64_MAX;
  PstFailureAnchor structural_anchor = {0};
  const bool bbt_pages_complete = pst_validate_page(
      layout, layout->bbt_root_offset, layout->bbt_root_bid,
      PST_PAGE_TYPE_BBT, bbt_root_level, 0);

  if (!bbt_pages_complete) {
    structural_failure = layout->failure_offset;
    structural_anchor = layout->failure_anchor;
  }

  if (layout->block_count > 1) {
    qsort(layout->blocks, (size_t)layout->block_count,
          sizeof(*layout->blocks), pst_compare_block_bid);
  }
  bool bbt_entries_unique = true;

  for (uint64_t index = 1; index < layout->block_count; index++) {
    if (layout->blocks[index - 1].bid == layout->blocks[index].bid) {
      if (layout->blocks[index].offset < structural_failure) {
        structural_failure = layout->blocks[index].offset;
        memset(&structural_anchor, 0, sizeof(structural_anchor));
      }
      bbt_entries_unique = false;
    }
  }
  bool blocks_complete = true;

  for (uint64_t index = 0; index < layout->block_count; index++) {
    pst_clear_failure_anchor(layout);
    if (!pst_validate_block(layout, &layout->blocks[index])) {
      if (layout->failure_offset < structural_failure) {
        structural_failure = layout->failure_offset;
        structural_anchor = layout->failure_anchor;
      }
      blocks_complete = false;
    }
  }

  const uint8_t *nbt_metadata = data + layout->nbt_root_offset
                                + layout->page_metadata_offset;
  const uint32_t nbt_root_level = layout->variant
                                      == PST_VARIANT_UNICODE_4K
                                      ? nbt_metadata[5] : nbt_metadata[3];

  pst_clear_failure_anchor(layout);
  const bool nbt_pages_complete = pst_validate_page(
      layout, layout->nbt_root_offset, layout->nbt_root_bid,
      PST_PAGE_TYPE_NBT, nbt_root_level, 0);

  if (!nbt_pages_complete && layout->failure_offset < structural_failure) {
    structural_failure = layout->failure_offset;
    structural_anchor = layout->failure_anchor;
  }

  bool nbt_references_complete = false;

  if (bbt_pages_complete && bbt_entries_unique && nbt_pages_complete) {
    pst_clear_failure_anchor(layout);
    nbt_references_complete = pst_validate_nbt_references(
        layout, layout->nbt_root_offset, layout->nbt_root_bid,
        nbt_root_level, 0);
    if (!nbt_references_complete
        && layout->failure_offset < structural_failure) {
      structural_failure = layout->failure_offset;
      structural_anchor = layout->failure_anchor;
    }
  }

  if (!bbt_pages_complete || !bbt_entries_unique || !blocks_complete
      || !nbt_pages_complete || !nbt_references_complete) {
    layout->failure_offset = structural_failure != UINT64_MAX
                                 ? structural_failure
                                 : PST_HEADER_MINIMUM_SIZE;
    layout->failure_anchor = structural_anchor;
    return false;
  }
  if (!allocation_maps_complete) {
    layout->failure_offset = allocation_map_failure;
    layout->failure_anchor = allocation_map_anchor;
    return false;
  }
  pst_clear_failure_anchor(layout);
  if (!pst_validate_known_allocations(layout)) {
    return false;
  }
  layout->failure_offset = layout->file_size;
  pst_clear_failure_anchor(layout);
  return layout->verified_pages >= 2 && layout->verified_blocks != 0
         && layout->verified_nbt_entries != 0;
}

static inline char *pst_no_header_discovery(char *base, uint64_t offset,
                                            uint64_t remaining,
                                            char **matchpos,
                                            uint32_t *matchlen,
                                            uint32_t blocksize) {
  (void)base;
  (void)offset;
  (void)remaining;
  (void)blocksize;
  if (matchpos) {
    *matchpos = NULL;
  }
  if (matchlen) {
    *matchlen = 0;
  }
  return NULL;
}

static inline uint32_t pst_block_validate(
    char *data, uint64_t length, BlockValidationDecision *decision,
    uint64_t *validates_to, uint32_t needleidx, uint32_t blocksize,
    void *blockhashkey) {
  (void)blocksize;
  (void)blockhashkey;

  if (!data || !decision || !validates_to || length == 0) {
    return needleidx;
  }
  *validates_to = length - 1;
  if (*decision == BLOCK_CONFIDENCE_INVALID) {
    *decision = BLOCK_CONFIDENCE_LOW;
  }
  if (length >= PST_HEADER_MINIMUM_SIZE
      && pst_read_le32((const uint8_t *)data) == PST_HEADER_MAGIC) {
    PstLayout layout = {0};

    if (pst_parse_header((const uint8_t *)data, length, &layout)) {
      *decision = BLOCK_CONFIDENCE_VALID;
      pst_layout_clear(&layout);
      return needleidx;
    }
  }

  if (*decision >= PST_BLOCK_CONFIDENCE) {
    return needleidx;
  }

  // ANSI index pages store their CRC after the BID; Unicode pages store it
  // before the BID. Page evidence raises confidence but does not prove order.
  static const struct {
    uint64_t page_size;
    uint64_t trailer_offset;
    uint64_t crc_offset;
  } formats[] = {
    {PST_ANSI_PAGE_SIZE, 500, 8},
    {PST_UNICODE_PAGE_SIZE, 496, 4},
    {PST_UNICODE_4K_PAGE_SIZE, 4072, 4}
  };
  const uint8_t *bytes = (const uint8_t *)data;

  for (uint32_t variant = 0;
       variant < sizeof(formats) / sizeof(formats[0]); variant++) {
    const uint64_t page_size = formats[variant].page_size;
    const uint64_t trailer_offset = formats[variant].trailer_offset;

    if (length < page_size) {
      continue;
    }

    for (uint64_t offset = 0; offset <= length - page_size;
         offset += page_size) {
      const uint8_t *page = bytes + offset;
      const uint8_t *trailer = page + trailer_offset;

      if ((trailer[0] == PST_PAGE_TYPE_BBT
           || trailer[0] == PST_PAGE_TYPE_NBT)
          && trailer[1] == trailer[0]
          && pst_read_le32(trailer + formats[variant].crc_offset)
                 == pst_weak_crc32(page, trailer_offset)) {
        *decision = (BlockValidationDecision)PST_BLOCK_CONFIDENCE;
        return needleidx;
      }
    }
  }
  return needleidx;
}

static inline void pst_file_validate(char *data, uint64_t length,
                                     bool *validates,
                                     uint64_t *validates_to,
                                     bool *promising,
                                     uint32_t needleidx,
                                     uint32_t blocksize,
                                     void *carvehashkey) {
  (void)needleidx;

  if (!validates || !validates_to || !promising) {
    return;
  }
  *validates = false;
  *validates_to = 0;
  *promising = false;

  PstLayout layout = {0};
  const bool complete = pst_parse((const uint8_t *)data, length, &layout);
  PstCarveState state;

  memset(&state, 0, sizeof(state));
  state.magic = PST_STATE_MAGIC;
  state.version = PST_STATE_VERSION;
  state.profile = (uint32_t)layout.profile;
  state.variant = (uint32_t)layout.variant;
  state.amap_dirty = layout.amap_dirty ? 1 : 0;
  state.file_size = layout.file_size;
  state.failure_offset = layout.failure_offset;
  if (layout.profile != PST_PROFILE_UNKNOWN && layout.file_size != 0) {
    carve_put_state(carvehashkey, &state);
  }

  if (layout.profile != PST_PROFILE_UNKNOWN) {
    *promising = true;
    if (blocksize != 0 && layout.failure_offset >= blocksize) {
      *validates_to = (layout.failure_offset / blocksize) * blocksize - 1;
    }
    if (*validates_to < sizeof(uint32_t) - 1) {
      *validates_to = sizeof(uint32_t) - 1;
    }
    if (layout.file_size > 0 && *validates_to >= layout.file_size) {
      *validates_to = layout.file_size - 1;
    }
  }
  if (complete) {
    *validates = true;
    *promising = false;
    *validates_to = layout.file_size - 1;
    // PST allocation metadata authenticates referenced pages and blocks, but
    // not every byte in free or orphaned extents. During fragmented recovery,
    // structural completeness therefore establishes a promising hypothesis,
    // not byte-exact provenance for the complete physical mapping.
    if (!scalpel_state.no_defrag) {
      *validates = false;
      *promising = true;
    }
  }
  pst_layout_clear(&layout);
}

static inline const char *pst_profile_filetype(PstProfile profile) {
  switch (profile) {
    case PST_PROFILE_PST:
      return "pst";
    case PST_PROFILE_OST:
      return "ost";
    case PST_PROFILE_PAB:
      return "pab";
    default:
      return "pff";
  }
}

static inline void pst_assign_candidate_profile(CarveInfo *candidate,
                                                PstProfile profile) {
  if (!candidate) {
    return;
  }
  const char *filetype = pst_profile_filetype(profile);

  if (strcmp(filetype, "pff") == 0) {
    return;
  }
  for (uint32_t index = 0; index < scalpel_state.num_specs; index++) {
    if (strcmp(scalpel_state.search_specs[index].FILETYPE, filetype) == 0) {
      candidate->needleidx = (int32_t)index;
      candidate->filetype = scalpel_state.search_specs[index].FILETYPE;
      return;
    }
  }
}

static inline void pst_candidate_classify(CarveInfo *candidate,
                                          bool *validates,
                                          uint64_t *validates_to,
                                          bool *promising) {
  (void)validates;
  (void)validates_to;
  (void)promising;

  if (!candidate || !candidate->b) {
    return;
  }
  PstCarveState *state = (PstCarveState *)carve_get_state(
      candidate->carvehashkey);

  if (!state || state->magic != PST_STATE_MAGIC
      || state->version != PST_STATE_VERSION) {
    pst_free_carve_state((void **)&state);
    return;
  }
  pst_assign_candidate_profile(candidate, (PstProfile)state->profile);
  if (validates && promising && *validates && !scalpel_state.no_defrag) {
    *validates = false;
    *promising = true;
  }
  pst_free_carve_state((void **)&state);
}

// Materialize the complete logical extent from the exact size in the PST
// header. Start with physical adjacency, wrapping to earlier image blocks if
// necessary to form a legal trial. This is only a starting hypothesis: PST
// structure and checksums still determine repairs and acceptance. Preserve
// committed repairs and do not reuse their blocks when extending a mapping.
//
static inline bool pst_reassembly_initialize_candidate(
    CarveInfo *candidate, PstCarveState *state) {
  if (!candidate || !candidate->b || !state || state->file_size == 0
      || scalpel_state.blocksize == 0) {
    return false;
  }
  const uint64_t total_blocks = CEILDIV(state->file_size,
                                        scalpel_state.blocksize);
  const uint64_t image_blocks = CEILDIV(
      filemirror_filesize(scalpel_state.filemirror), scalpel_state.blocksize);
  const uint64_t existing_blocks = blockvector_get_num_blocks(candidate->b);
  if (existing_blocks == 0) {
    return false;
  }
  const int64_t header_actual = blockvector_get_actual_blocknumber(
      candidate->b, 0);

  if (total_blocks == 0 || header_actual < 0
      || (uint64_t)header_actual >= image_blocks
      || image_blocks > INT64_MAX || total_blocks > image_blocks) {
    return false;
  }
  resize_blockvector(candidate->b, total_blocks);
  if (!state->initialized || existing_blocks < total_blocks) {
    const uint64_t first_slot = state->initialized ? existing_blocks : 0;
    PstOffsetSet retained = {0};
    for (uint64_t slot = 0; slot < first_slot; slot++) {
      const int64_t actual = blockvector_get_actual_blocknumber(candidate->b, slot);
      if (actual >= 0
          && !pst_offset_set_insert(&retained, (uint64_t)actual)
          && !pst_offset_set_contains(&retained, (uint64_t)actual)) {
        pst_offset_set_clear(&retained);
        return false;
      }
    }
    uint64_t next_actual = (uint64_t)header_actual + first_slot;
    if (next_actual >= image_blocks) {
      next_actual -= image_blocks;
    }
    uint64_t examined = 0;

    for (uint64_t slot = first_slot; slot < total_blocks; slot++) {
      while (examined < image_blocks
             && pst_offset_set_contains(&retained, next_actual)) {
        examined++;
        next_actual++;
        if (next_actual == image_blocks) {
          next_actual = 0;
        }
      }
      if (examined == image_blocks) {
        pst_offset_set_clear(&retained);
        return false;
      }
      const int64_t actual = (int64_t)next_actual;
      examined++;
      next_actual++;
      if (next_actual == image_blocks) {
        next_actual = 0;
      }
      const int64_t apparent = filemirror_apparent_blocknumber(
          scalpel_state.filemirror, actual);

      if (apparent < 0
          && !filemirror_actual_block_is_zero(scalpel_state.filemirror,
                                              actual)) {
        pst_offset_set_clear(&retained);
        return false;
      }
      blockvector_set_apparent_blocknumber(candidate->b, slot, apparent);
    }
    pst_offset_set_clear(&retained);
    state->initialized = 1;
    state->search_phase = 0;
    state->target_slot = 0;
    state->resume_choice = 0;
    carve_put_state(candidate->carvehashkey, state);
  }
  inflate_blockvector(candidate->b);
  blockvector_set_data_length(candidate->b, state->file_size);
  return true;
}

static inline bool pst_reassembly_evaluate_candidate(
    CarveInfo *candidate, PstTrialResult *result) {
  if (!candidate || !candidate->b || !result) {
    return false;
  }
  memset(result, 0, sizeof(*result));

  const uint8_t *data = (const uint8_t *)blockvector_get_data_pointer(
      candidate->b);
  const uint64_t length = blockvector_get_data_length(candidate->b);
  PstLayout layout = {0};

  result->complete = pst_parse(data, length, &layout);
  result->profile = layout.profile;
  result->variant = layout.variant;
  result->file_size = layout.file_size;
  result->failure_offset = result->complete
                               ? layout.file_size : layout.failure_offset;
  result->amap_failure_offset = layout.amap_failure_offset;
  result->verified_amap_pages = layout.verified_amap_pages;
  result->verified_amap_allocations = layout.verified_amap_allocations;
  result->verified_pages = layout.verified_pages;
  result->verified_blocks = layout.verified_blocks;
  result->verified_nbt_entries = layout.verified_nbt_entries;
  result->amap_failure_anchor = layout.amap_failure_anchor;
  result->failure_anchor = layout.failure_anchor;
  if (result->failure_offset > length) {
    result->failure_offset = length;
  }
  pst_layout_clear(&layout);
  return true;
}

static inline int pst_reassembly_compare_trials(
    const PstTrialResult *left, const PstTrialResult *right) {
  if (!left || !right) {
    return 0;
  }
  if (left->complete != right->complete) {
    return left->complete ? 1 : -1;
  }
  if (left->verified_amap_pages != right->verified_amap_pages) {
    return left->verified_amap_pages > right->verified_amap_pages ? 1 : -1;
  }
  const uint64_t left_units = left->verified_pages
                              + left->verified_blocks
                              + left->verified_nbt_entries;
  const uint64_t right_units = right->verified_pages
                               + right->verified_blocks
                               + right->verified_nbt_entries;

  if (left_units != right_units) {
    return left_units > right_units ? 1 : -1;
  }
  if (left->verified_amap_allocations
      != right->verified_amap_allocations) {
    return left->verified_amap_allocations
               > right->verified_amap_allocations ? 1 : -1;
  }
  if (left->verified_pages != right->verified_pages) {
    return left->verified_pages > right->verified_pages ? 1 : -1;
  }
  if (left->verified_blocks != right->verified_blocks) {
    return left->verified_blocks > right->verified_blocks ? 1 : -1;
  }
  if (left->verified_nbt_entries != right->verified_nbt_entries) {
    return left->verified_nbt_entries > right->verified_nbt_entries ? 1 : -1;
  }
  if (left->failure_offset != right->failure_offset) {
    return left->failure_offset > right->failure_offset ? 1 : -1;
  }
  return 0;
}

static inline int64_t pst_reassembly_find_actual_slot(
    BlockVector *blockvector, int64_t actual_block) {
  if (!blockvector || actual_block < 0) {
    return -1;
  }
  const uint64_t blocks = blockvector_get_num_blocks(blockvector);

  for (uint64_t slot = 0; slot < blocks; slot++) {
    if (blockvector_get_actual_blocknumber(blockvector, slot)
        == actual_block) {
      return (int64_t)slot;
    }
  }
  return -1;
}

// Search contexts are independent within one committed mapping. A repair
// changes the query, while a checkpoint retains its cursor and best evidence.
static inline PstRepairSearch *pst_reassembly_search(
    PstCarveState *state, PstSearchContext context,
    const PstTrialResult *current, uint64_t target_slot) {
  PstRepairSearch *search = &state->searches[context];
  if (!search->initialized || search->repairs != state->repairs
      || search->target_slot != target_slot) {
    memset(search, 0, sizeof(*search));
    search->initialized = true;
    search->repairs = state->repairs;
    search->target_slot = target_slot;
    search->best_result = *current;
    search->best_actual = -1;
    search->first_amap_actual = -1;
    search->best_reservations = INT64_MAX;
    search->best_distance = INT64_MAX;
    search->best_skipped_total = UINT64_MAX;
  }
  return search;
}

static inline void pst_reassembly_record_best(
    PstRepairSearch *search, const PstTrialResult *result,
    uint64_t first_slot, uint64_t blocks, int64_t actual) {
  search->best_result = *result;
  search->best_first_slot = first_slot;
  search->best_blocks = blocks;
  search->best_actual = actual;
  search->best_tail_actual = -1;
  search->best_prefix_blocks = 0;
  search->best_permuted = false;
}

// Move an authenticated run into its logical slots. With permute set, swap
// blocks already in other slots rather than duplicating them; otherwise reject
// reuse outside the target range. The caller supplies a copy of the committed
// mapping. Failure leaves it unchanged, and checkpoints reproduce the same swap.
static inline bool pst_reassembly_anchor_mapping(
    BlockVector *blockvector, PstVariant variant, int64_t *mapping,
    uint64_t first_slot, uint64_t blocks, int64_t actual, bool permute) {
  const uint64_t total = blockvector_get_num_blocks(blockvector);
  const uint64_t blocksize = scalpel_state.blocksize;
  if (!mapping || blocksize == 0 || actual < 0 || blocks == 0
      || first_slot >= total || blocks > total - first_slot) {
    return false;
  }
  const uint64_t image_blocks = CEILDIV(
      filemirror_filesize(scalpel_state.filemirror), blocksize);
  const uint64_t header_blocks = CEILDIV(
      variant == PST_VARIANT_ANSI ? PST_HEADER_MINIMUM_SIZE
                                  : PST_UNICODE_HEADER_SIZE, blocksize);
  if (first_slot < header_blocks || (uint64_t)actual >= image_blocks
      || blocks > image_blocks - (uint64_t)actual
      || blocks - 1 > (uint64_t)(INT64_MAX - actual)) {
    return false;
  }
  for (uint64_t i = 0; i < blocks; i++) {
    const int64_t physical = actual + (int64_t)i;
    const int64_t apparent = filemirror_apparent_blocknumber(
        scalpel_state.filemirror, physical);
    if (apparent < 0) {
      if (!filemirror_actual_block_is_zero(scalpel_state.filemirror, physical)) {
        return false;
      }
      continue;
    }
    bool present = false;
    for (uint64_t slot = 0; slot < total; slot++) {
      if (mapping[slot] == apparent) {
        if (slot < header_blocks) {
          return false;
        }
        if (!permute && (slot < first_slot || slot >= first_slot + blocks)) {
          return false;
        }
        present = true;
      }
    }
    if (!present && filemirror_actual_block_covered(
                        scalpel_state.filemirror, physical)) {
      return false;
    }
  }
  for (uint64_t i = 0; i < blocks; i++) {
    const int64_t apparent = filemirror_apparent_blocknumber(
        scalpel_state.filemirror, actual + (int64_t)i);
    const uint64_t target = first_slot + i;
    if (permute && apparent >= 0 && mapping[target] != apparent) {
      for (uint64_t slot = 0; slot < total; slot++) {
        if (mapping[slot] == apparent) {
          mapping[slot] = mapping[target];
          break;
        }
      }
    }
    mapping[target] = apparent;
  }
  return true;
}

// Reconstruct the best trial from the committed mapping in the current
// apparent address space, including any swaps outside the target run.
static inline void pst_reassembly_restore_best(
    BlockVector *blockvector, const PstRepairSearch *search, int64_t *best) {
  const uint64_t blocks = blockvector_get_num_blocks(blockvector);
  if (search->best_actual < 0 || search->best_first_slot >= blocks
      || search->best_blocks > blocks - search->best_first_slot) {
    return;
  }
  if (search->best_permuted) {
    const uint64_t prefix = search->best_prefix_blocks;
    if (prefix != 0 && prefix < search->best_blocks) {
      if (pst_reassembly_anchor_mapping(blockvector, search->best_result.variant,
              best, search->best_first_slot, prefix, search->best_actual, true)) {
        pst_reassembly_anchor_mapping(blockvector, search->best_result.variant,
            best, search->best_first_slot + prefix, search->best_blocks - prefix,
            search->best_tail_actual, true);
      }
    }
    else {
      pst_reassembly_anchor_mapping(blockvector, search->best_result.variant,
          best, search->best_first_slot, search->best_blocks, search->best_actual, true);
    }
    return;
  }
  for (uint64_t i = 0; i < search->best_blocks; i++) {
    best[search->best_first_slot + i] = filemirror_apparent_blocknumber(
        scalpel_state.filemirror, search->best_actual + (int64_t)i);
  }
}

// Physical mappings survive apparent renumbering. A changed coverage set
// changes which substitutions are legal and requires fresh search evidence.
static inline XXH128_hash_t pst_reassembly_view_hash(CarveInfo *candidate) {
  XXH3_state_t hash;
  XXH3_128bits_reset(&hash);
  const uint64_t metadata[] = {blockvector_get_num_blocks(candidate->b),
      blockvector_get_data_length(candidate->b),
      filemirror_filesize(scalpel_state.filemirror), scalpel_state.blocksize};
  XXH3_128bits_update(&hash, metadata, sizeof(metadata));
  int64_t mapping[256];
  for (uint64_t first = 0; first < metadata[0];) {
    uint64_t count = metadata[0] - first;
    if (count > sizeof(mapping) / sizeof(mapping[0])) {
      count = sizeof(mapping) / sizeof(mapping[0]);
    }
    for (uint64_t i = 0; i < count; i++) {
      mapping[i] = blockvector_get_actual_blocknumber(candidate->b, first + i);
    }
    XXH3_128bits_update(&hash, mapping, (size_t)count * sizeof(mapping[0]));
    first += count;
  }
  const uint64_t image_blocks = CEILDIV(metadata[2], metadata[3]);
  uint8_t covered[256];
  for (uint64_t first = 0; first < image_blocks;) {
    uint64_t count = image_blocks - first;
    if (count > sizeof(covered)) {
      count = sizeof(covered);
    }
    for (uint64_t i = 0; i < count; i++) {
      covered[i] = filemirror_actual_block_covered(
          scalpel_state.filemirror, (int64_t)(first + i)) ? 1 : 0;
    }
    XXH3_128bits_update(&hash, covered, (size_t)count);
    first += count;
  }
  return XXH3_128bits_digest(&hash);
}

static inline void pst_reassembly_resume_searches(
    CarveInfo *candidate, PstCarveState *state) {
  if (state->checkpoint_saved) {
    const XXH128_hash_t view = pst_reassembly_view_hash(candidate);
    if (!XXH128_isEqual(view, state->checkpoint_view)) {
      memset(state->searches, 0, sizeof(state->searches));
      memset(&state->free_gaps, 0, sizeof(state->free_gaps));
      pst_continuity_clear(&state->continuity);
    }
    state->checkpoint_saved = false;
  }
}

// Poll only with the committed mapping installed. Save search state before
// transferring the candidate back to the backend's promising queue.
//
static inline bool pst_reassembly_poll(ThreadWork *work,
                                       CarveInfo **candidate,
                                       PstCarveState *state,
                                       uuid_string_t uuidp,
                                       uuid_string_t uuidc) {
  if (!work || !candidate || !*candidate || !state) {
    return true;
  }
  if (reassembly_check_kill_queue(work, candidate, uuidp, uuidc)) {
    return true;
  }
  if (atomic_load_explicit(&REASS_RETURN_TO_IDLE, memory_order_acquire)) {
    state->checkpoint_view = pst_reassembly_view_hash(*candidate);
    state->checkpoint_saved = true;
    carve_put_state((*candidate)->carvehashkey, state);
    if (reassembly_time_to_checkpoint(work->id, *candidate, uuidp, uuidc)) {
      return true;
    }
    state->checkpoint_saved = false;
  }
  return false;
}

// A provisional suffix repair can begin before an unreferenced region and
// still recover distant allocation maps. Once later repairs expose the full
// BBT, a failure immediately before that transition identifies it as too
// early. Move the transition forward and retain the first best frontier.
//
static inline bool pst_reassembly_try_boundary_refinement(
    ThreadWork *work, CarveInfo **candidate, PstCarveState *state,
    const PstTrialResult *current, uuid_string_t uuidp,
    uuid_string_t uuidc, bool *improved) {
  if (!work || !candidate || !*candidate || !(*candidate)->b || !state
      || !current || !improved || scalpel_state.blocksize == 0) {
    return false;
  }
  *improved = false;

  BlockVector *blockvector = (*candidate)->b;
  const uint64_t total_blocks = blockvector_get_num_blocks(blockvector);

  if (total_blocks < 3) {
    return false;
  }

  uint64_t failure_slot = current->failure_offset / scalpel_state.blocksize;

  if (failure_slot >= total_blocks) {
    return false;
  }

  uint64_t transition = 0;
  uint64_t next_transition = total_blocks;

  for (uint64_t slot = 1; slot < total_blocks; slot++) {
    const int64_t previous = blockvector_get_actual_blocknumber(
        blockvector, slot - 1);
    const int64_t actual = blockvector_get_actual_blocknumber(
        blockvector, slot);

    if (previous < 0 || actual < 0 || actual == previous + 1) {
      continue;
    }
    if (transition == 0
        && (slot == failure_slot || slot == failure_slot + 1)) {
      transition = slot;
      continue;
    }
    if (transition != 0 && slot > transition) {
      next_transition = slot;
      break;
    }
  }
  if (transition == 0 || transition + 1 >= next_transition) {
    return false;
  }

  const int64_t previous_actual = blockvector_get_actual_blocknumber(
      blockvector, transition - 1);
  const int64_t transition_actual = blockvector_get_actual_blocknumber(
      blockvector, transition);

  if (previous_actual < 0 || transition_actual <= previous_actual + 1
      || (uint64_t)(transition - 1) > (uint64_t)previous_actual) {
    return false;
  }
  const uint64_t before_origin = (uint64_t)previous_actual
                                 - (transition - 1);
  const uint64_t image_blocks = CEILDIV(
      filemirror_filesize(scalpel_state.filemirror), scalpel_state.blocksize);
  PstRepairSearch *search = pst_reassembly_search(
      state, PST_SEARCH_BOUNDARY, current, transition);
  if (search->done) {
    return false;
  }
  if (search->next_boundary == 0) {
    search->next_boundary = transition + 1;
  }
  int64_t *saved = (int64_t *)malloc(
      (size_t)total_blocks * sizeof(*saved));
  int64_t *best = (int64_t *)malloc(
      (size_t)total_blocks * sizeof(*best));

  check_memory_allocation(saved, __LINE__, __FILE__,
                          "PST transition mapping");
  check_memory_allocation(best, __LINE__, __FILE__,
                          "PST best transition mapping");
  for (uint64_t slot = 0; slot < total_blocks; slot++) {
    saved[slot] = blockvector_get_apparent_blocknumber(blockvector, slot);
    best[slot] = saved[slot];
  }

  pst_reassembly_restore_best(blockvector, search, best);
  PstTrialResult best_result = search->best_result;
  uint64_t best_boundary = search->best_actual >= 0
      ? search->best_first_slot + search->best_blocks : 0;
  uint64_t trials = 0;

  state->search_phase = 4;
  state->target_slot = transition;
  for (uint64_t boundary = search->next_boundary;
       boundary < next_transition; boundary++) {
    search->next_boundary = boundary + 1;
    bool available = true;

    for (uint64_t slot = transition; slot < boundary; slot++) {
      if (before_origin > UINT64_MAX - slot
          || before_origin + slot >= image_blocks) {
        available = false;
        break;
      }
      const int64_t actual = (int64_t)(before_origin + slot);
      const int64_t source_slot = pst_reassembly_find_actual_slot(
          blockvector, actual);
      const int64_t apparent = filemirror_apparent_blocknumber(
          scalpel_state.filemirror, actual);

      if ((source_slot >= 0
           && ((uint64_t)source_slot < transition
               || (uint64_t)source_slot >= boundary))
          || (filemirror_actual_block_covered(scalpel_state.filemirror,
                                             actual)
              && source_slot < 0)
          || (apparent < 0
              && !filemirror_actual_block_is_zero(
                     scalpel_state.filemirror, actual))) {
        available = false;
        break;
      }
      blockvector_set_apparent_blocknumber(blockvector, slot, apparent);
    }

    PstTrialResult trial;

    memset(&trial, 0, sizeof(trial));
    if (available) {
      inflate_blockvector(blockvector);
      blockvector_set_data_length(blockvector, state->file_size);
      pst_reassembly_evaluate_candidate(*candidate, &trial);

      if (pst_reassembly_compare_trials(&trial, &best_result) > 0) {
        best_result = trial;
        best_boundary = boundary;
        pst_reassembly_record_best(search, &trial, transition,
            boundary - transition, (int64_t)(before_origin + transition));
        for (uint64_t slot = 0; slot < total_blocks; slot++) {
          best[slot] = blockvector_get_apparent_blocknumber(
              blockvector, slot);
        }
        if (trial.complete) {
          break;
        }
      }
    }

    for (uint64_t slot = transition; slot < boundary; slot++) {
      blockvector_set_apparent_blocknumber(blockvector, slot, saved[slot]);
    }
    normalize_blockvector(blockvector);
    trials++;
    if ((trials % PST_REASSEMBLY_POLL_INTERVAL) == 0) {
      inflate_blockvector(blockvector);
      blockvector_set_data_length(blockvector, state->file_size);
      if (pst_reassembly_poll(work, candidate, state, uuidp, uuidc)) {
        free(best);
        free(saved);
        return true;
      }
    }
  }

  search->done = true;

  if (best_boundary != 0
      && pst_reassembly_compare_trials(&best_result, current) > 0) {
    for (uint64_t slot = 0; slot < total_blocks; slot++) {
      blockvector_set_apparent_blocknumber(blockvector, slot, best[slot]);
    }
    inflate_blockvector(blockvector);
    blockvector_set_data_length(blockvector, state->file_size);
    state->profile = (uint32_t)best_result.profile;
    state->variant = (uint32_t)best_result.variant;
    state->failure_offset = best_result.failure_offset;
    state->repairs++;
    state->search_phase = 0;
    state->target_slot = 0;
    state->resume_choice = 0;
    carve_put_state((*candidate)->carvehashkey, state);
    *improved = true;
  }
  else {
    for (uint64_t slot = 0; slot < total_blocks; slot++) {
      blockvector_set_apparent_blocknumber(blockvector, slot, saved[slot]);
    }
    inflate_blockvector(blockvector);
    blockvector_set_data_length(blockvector, state->file_size);
  }
  free(best);
  free(saved);
  return false;
}

static inline bool pst_reassembly_anchor_matches(
    const PstTrialResult *current, const PstFailureAnchor *anchor,
    const uint8_t *data, uint64_t available) {
  if (!current || !anchor || !data) {
    return false;
  }

  if (anchor->kind == PST_ANCHOR_NONE || anchor->extent == 0
      || available < anchor->extent) {
    return false;
  }

  uint64_t page_size = PST_UNICODE_PAGE_SIZE;
  uint64_t page_data_size = 496;
  uint64_t page_metadata_offset = 488;
  uint64_t page_trailer_offset = 496;
  uint64_t block_trailer_size = PST_UNICODE_BLOCK_TRAILER_SIZE;

  if (current->variant == PST_VARIANT_ANSI) {
    page_size = PST_ANSI_PAGE_SIZE;
    page_data_size = 500;
    page_metadata_offset = 496;
    page_trailer_offset = 500;
    block_trailer_size = PST_ANSI_BLOCK_TRAILER_SIZE;
  }
  else if (current->variant == PST_VARIANT_UNICODE_4K) {
    page_size = PST_UNICODE_4K_PAGE_SIZE;
    page_data_size = 4072;
    page_metadata_offset = 4056;
    page_trailer_offset = 4072;
    block_trailer_size = PST_UNICODE_4K_BLOCK_TRAILER_SIZE;
  }
  else if (current->variant != PST_VARIANT_UNICODE) {
    return false;
  }

  if (anchor->kind == PST_ANCHOR_AMAP_PAGE) {
    if (anchor->extent != page_size) {
      return false;
    }
    const uint64_t map_offset = current->variant == PST_VARIANT_ANSI ? 4 : 0;
    const uint64_t map_size = current->variant == PST_VARIANT_UNICODE_4K
                                  ? 4072 : 496;
    const uint8_t *map = data + map_offset;
    const uint8_t *trailer = data + page_trailer_offset;
    uint32_t stored_crc = 0;
    uint64_t stored_bid = 0;

    if (current->variant == PST_VARIANT_ANSI) {
      stored_bid = pst_read_le32(trailer + 4);
      stored_crc = pst_read_le32(trailer + 8);
    }
    else {
      stored_crc = pst_read_le32(trailer + 4);
      stored_bid = pst_read_le64(trailer + 8);
    }
    return trailer[0] == PST_PAGE_TYPE_AMAP
           && trailer[1] == PST_PAGE_TYPE_AMAP
           && pst_read_le16(trailer + 2) == 0
           && stored_bid == anchor->logical_offset
           && stored_crc == pst_weak_crc32(map, map_size)
           && map[0] == UINT8_C(0xff);
  }

  if (anchor->kind == PST_ANCHOR_BTREE_PAGE) {
    if (anchor->extent != page_size
        || (anchor->page_type != PST_PAGE_TYPE_BBT
            && anchor->page_type != PST_PAGE_TYPE_NBT)) {
      return false;
    }
    const uint8_t *metadata = data + page_metadata_offset;
    const uint8_t *trailer = data + page_trailer_offset;
    const uint8_t level = current->variant == PST_VARIANT_UNICODE_4K
                              ? metadata[5] : metadata[3];
    uint32_t stored_crc = 0;
    uint64_t stored_bid = 0;

    if (current->variant == PST_VARIANT_ANSI) {
      stored_bid = pst_read_le32(trailer + 4);
      stored_crc = pst_read_le32(trailer + 8);
    }
    else {
      stored_crc = pst_read_le32(trailer + 4);
      stored_bid = pst_read_le64(trailer + 8);
    }
    return trailer[0] == anchor->page_type
           && trailer[1] == anchor->page_type
           && (anchor->page_level == UINT8_MAX
               || level == anchor->page_level)
           && (anchor->bid == 0
               || pst_normalize_bid(stored_bid)
                      == pst_normalize_bid(anchor->bid))
           && pst_read_le16(trailer + 2)
                  == pst_compute_signature(anchor->logical_offset,
                                           stored_bid)
           && stored_crc == pst_weak_crc32(data, page_data_size);
  }

  if (anchor->kind == PST_ANCHOR_DATA_BLOCK) {
    if (anchor->data_size == 0
        || anchor->extent < block_trailer_size
        || anchor->data_size > anchor->extent - block_trailer_size) {
      return false;
    }
    const uint8_t *trailer = data + anchor->extent - block_trailer_size;
    const uint32_t stored_size = pst_read_le16(trailer);
    const uint16_t stored_signature = pst_read_le16(trailer + 2);
    uint32_t stored_crc = 0;
    uint64_t stored_bid = 0;

    if (current->variant == PST_VARIANT_ANSI) {
      stored_bid = pst_read_le32(trailer + 4);
      stored_crc = pst_read_le32(trailer + 8);
    }
    else {
      stored_crc = pst_read_le32(trailer + 4);
      stored_bid = pst_read_le64(trailer + 8);
    }
    return stored_size == anchor->data_size
           && pst_normalize_bid(stored_bid)
                  == pst_normalize_bid(anchor->bid)
           && stored_signature
                  == pst_compute_signature(anchor->logical_offset,
                                           stored_bid)
           && stored_crc == pst_weak_crc32(data, anchor->data_size);
  }
  return false;
}

// A suffix repair can initially begin after an unreferenced region because
// later allocation maps provide more evidence than the structure crossing the
// true fragmentation boundary. Move that transition backward only when an
// authenticated page or block then validates and the parser advances.
//
static inline bool pst_reassembly_try_transition_backshift(
    ThreadWork *work, CarveInfo **candidate, PstCarveState *state,
    const PstTrialResult *current, const PstFailureAnchor *anchor,
    uuid_string_t uuidp, uuid_string_t uuidc, bool *improved) {
  if (!work || !candidate || !*candidate || !(*candidate)->b || !state
      || !current || !anchor || !improved || scalpel_state.blocksize == 0) {
    return false;
  }
  *improved = false;

  BlockVector *blockvector = (*candidate)->b;
  const uint64_t total_blocks = blockvector_get_num_blocks(blockvector);
  const uint64_t image_blocks = CEILDIV(
      filemirror_filesize(scalpel_state.filemirror), scalpel_state.blocksize);

  if (anchor->kind == PST_ANCHOR_NONE || anchor->extent == 0
      || anchor->logical_offset >= state->file_size
      || anchor->extent > state->file_size - anchor->logical_offset) {
    return false;
  }

  const uint64_t first_anchor_slot = anchor->logical_offset
                                     / scalpel_state.blocksize;
  const uint64_t last_anchor_slot = (anchor->logical_offset
                                     + anchor->extent - 1)
                                    / scalpel_state.blocksize;

  if (first_anchor_slot == 0 || last_anchor_slot >= total_blocks
      || last_anchor_slot + 1 >= total_blocks) {
    return false;
  }

  uint64_t transition = 0;

  for (uint64_t slot = last_anchor_slot + 1; slot < total_blocks; slot++) {
    const int64_t previous = blockvector_get_actual_blocknumber(
        blockvector, slot - 1);
    const int64_t actual = blockvector_get_actual_blocknumber(
        blockvector, slot);

    if (previous >= 0 && actual > previous + 1) {
      transition = slot;
      break;
    }
  }
  if (transition == 0) {
    return false;
  }

  const int64_t previous_actual = blockvector_get_actual_blocknumber(
      blockvector, transition - 1);
  const int64_t transition_actual = blockvector_get_actual_blocknumber(
      blockvector, transition);

  if (previous_actual < 0 || transition_actual < 0
      || (uint64_t)previous_actual < transition - 1
      || (uint64_t)transition_actual < transition) {
    return false;
  }
  const uint64_t before_origin = (uint64_t)previous_actual
                                 - (transition - 1);
  const uint64_t after_origin = (uint64_t)transition_actual - transition;

  if (after_origin <= before_origin) {
    return false;
  }

  PstRepairSearch *search = pst_reassembly_search(
      state, anchor == &current->amap_failure_anchor
          ? PST_SEARCH_AMAP_BACKSHIFT : PST_SEARCH_BACKSHIFT,
      current, first_anchor_slot);
  if (search->done) {
    return false;
  }
  if (search->next_boundary == 0) {
    search->next_boundary = first_anchor_slot;
  }

  int64_t *saved = (int64_t *)malloc(
      (size_t)total_blocks * sizeof(*saved));
  int64_t *best = (int64_t *)malloc(
      (size_t)total_blocks * sizeof(*best));

  check_memory_allocation(saved, __LINE__, __FILE__,
                          "PST transition backshift mapping");
  check_memory_allocation(best, __LINE__, __FILE__,
                          "PST best transition backshift mapping");
  for (uint64_t slot = 0; slot < total_blocks; slot++) {
    saved[slot] = blockvector_get_apparent_blocknumber(blockvector, slot);
    best[slot] = saved[slot];
  }

  pst_reassembly_restore_best(blockvector, search, best);
  PstTrialResult best_result = search->best_result;
  uint64_t best_boundary = search->best_actual >= 0 ? search->best_first_slot : 0;
  bool ambiguous = search->ambiguous;
  uint64_t trials = 0;

  state->search_phase = 6;
  state->target_slot = first_anchor_slot;
  for (uint64_t boundary = search->next_boundary;
       boundary <= last_anchor_slot && boundary < transition; boundary++) {
    search->next_boundary = boundary + 1;
    bool available = true;

    for (uint64_t slot = boundary; slot < transition; slot++) {
      if (after_origin > UINT64_MAX - slot
          || after_origin + slot >= image_blocks) {
        available = false;
        break;
      }
      const int64_t actual = (int64_t)(after_origin + slot);
      const int64_t source_slot = pst_reassembly_find_actual_slot(
          blockvector, actual);
      const int64_t apparent = filemirror_apparent_blocknumber(
          scalpel_state.filemirror, actual);

      if ((source_slot >= 0
           && ((uint64_t)source_slot < boundary
               || (uint64_t)source_slot >= transition))
          || (source_slot < 0
              && filemirror_actual_block_covered(
                     scalpel_state.filemirror, actual))
          || (apparent < 0
              && !filemirror_actual_block_is_zero(
                     scalpel_state.filemirror, actual))) {
        available = false;
        break;
      }
    }
    if (available) {
      for (uint64_t slot = boundary; slot < transition; slot++) {
        const int64_t actual = (int64_t)(after_origin + slot);
        const int64_t apparent = filemirror_apparent_blocknumber(
            scalpel_state.filemirror, actual);

        blockvector_set_apparent_blocknumber(blockvector, slot, apparent);
      }
      inflate_blockvector(blockvector);
      blockvector_set_data_length(blockvector, state->file_size);

      const uint8_t *data = (const uint8_t *)
          blockvector_get_data_pointer(blockvector);

      if (data && pst_reassembly_anchor_matches(
                      current, anchor, data + anchor->logical_offset,
                      state->file_size - anchor->logical_offset)) {
        PstTrialResult trial;

        memset(&trial, 0, sizeof(trial));
        pst_reassembly_evaluate_candidate(*candidate, &trial);
        const int compared_to_best = pst_reassembly_compare_trials(
            &trial, &best_result);
        const int compared_to_current = pst_reassembly_compare_trials(
            &trial, current);

        if (compared_to_best > 0) {
          best_result = trial;
          best_boundary = boundary;
          ambiguous = false;
          pst_reassembly_record_best(search, &trial, boundary,
              transition - boundary, (int64_t)(after_origin + boundary));
          for (uint64_t slot = 0; slot < total_blocks; slot++) {
            best[slot] = blockvector_get_apparent_blocknumber(
                blockvector, slot);
          }
        }
        else if (compared_to_best == 0 && compared_to_current > 0
                 && best_boundary != 0 && best_boundary != boundary) {
          ambiguous = true;
        }
      }
    }

    for (uint64_t slot = boundary; slot < transition; slot++) {
      blockvector_set_apparent_blocknumber(
          blockvector, slot, saved[slot]);
    }
    normalize_blockvector(blockvector);
    trials++;
    if ((trials % PST_REASSEMBLY_POLL_INTERVAL) == 0) {
      search->ambiguous = ambiguous;
      inflate_blockvector(blockvector);
      blockvector_set_data_length(blockvector, state->file_size);
      if (pst_reassembly_poll(work, candidate, state, uuidp, uuidc)) {
        free(best);
        free(saved);
        return true;
      }
    }
  }

  search->done = true;

  if (best_boundary != 0 && !ambiguous
      && pst_reassembly_compare_trials(&best_result, current) > 0) {
    for (uint64_t slot = 0; slot < total_blocks; slot++) {
      blockvector_set_apparent_blocknumber(blockvector, slot, best[slot]);
    }
    inflate_blockvector(blockvector);
    blockvector_set_data_length(blockvector, state->file_size);
    state->profile = (uint32_t)best_result.profile;
    state->variant = (uint32_t)best_result.variant;
    state->failure_offset = best_result.failure_offset;
    state->repairs++;
    state->search_phase = 0;
    state->target_slot = 0;
    state->resume_choice = 0;
    carve_put_state((*candidate)->carvehashkey, state);
    *improved = true;
  }
  else {
    for (uint64_t slot = 0; slot < total_blocks; slot++) {
      blockvector_set_apparent_blocknumber(blockvector, slot, saved[slot]);
    }
    inflate_blockvector(blockvector);
    blockvector_set_data_length(blockvector, state->file_size);
  }
  free(best);
  free(saved);
  return false;
}

// PST page and block trailers bind CRC-authenticated content to its logical
// offset and BID. Use that identity to locate a displaced physical run before
// attempting speculative suffix or individual-block searches.
//
static inline bool pst_reassembly_try_anchor_replacement(
    ThreadWork *work, CarveInfo **candidate, PstCarveState *state,
    const PstTrialResult *current, const PstFailureAnchor *anchor,
    uuid_string_t uuidp, uuid_string_t uuidc, bool permute, bool *improved) {
  if (!work || !candidate || !*candidate || !(*candidate)->b || !state
      || !current || !anchor || !improved || scalpel_state.blocksize == 0) {
    return false;
  }
  *improved = false;

  BlockVector *blockvector = (*candidate)->b;
  const uint64_t total_blocks = blockvector_get_num_blocks(blockvector);
  const uint64_t image_size = filemirror_filesize(scalpel_state.filemirror);
  const uint64_t image_blocks = CEILDIV(image_size,
                                        scalpel_state.blocksize);

  if (anchor->kind == PST_ANCHOR_NONE || anchor->extent == 0
      || anchor->logical_offset >= state->file_size
      || anchor->extent > state->file_size - anchor->logical_offset) {
    return false;
  }

  const uint64_t first_slot = anchor->logical_offset
                              / scalpel_state.blocksize;
  const uint64_t relative = anchor->logical_offset
                            % scalpel_state.blocksize;
  const uint64_t span_blocks = CEILDIV(relative + anchor->extent,
                                       scalpel_state.blocksize);

  if (first_slot == 0 || span_blocks == 0 || first_slot >= total_blocks
      || span_blocks > total_blocks - first_slot
      || span_blocks > image_blocks) {
    return false;
  }

  const bool amap = anchor == &current->amap_failure_anchor;
  const PstSearchContext context = permute
      ? (amap ? PST_SEARCH_AMAP_SWAP : PST_SEARCH_SWAP)
      : (amap ? PST_SEARCH_AMAP_ANCHOR : PST_SEARCH_ANCHOR);
  PstRepairSearch *search = pst_reassembly_search(
      state, context, current, first_slot);
  if (search->done) {
    return false;
  }

  int64_t *saved = (int64_t *)malloc(
      (size_t)total_blocks * sizeof(*saved));
  int64_t *best = (int64_t *)malloc(
      (size_t)total_blocks * sizeof(*best));

  check_memory_allocation(saved, __LINE__, __FILE__,
                          "PST anchor mapping");
  check_memory_allocation(best, __LINE__, __FILE__,
                          "PST best anchor mapping");
  int64_t *trial_mapping = (int64_t *)malloc(
      (size_t)total_blocks * sizeof(*trial_mapping));
  check_memory_allocation(trial_mapping, __LINE__, __FILE__,
                          "PST trial anchor mapping");
  for (uint64_t slot = 0; slot < total_blocks; slot++) {
    saved[slot] = blockvector_get_apparent_blocknumber(blockvector, slot);
    best[slot] = saved[slot];
  }

  pst_reassembly_restore_best(blockvector, search, best);
  PstTrialResult best_result = search->best_result;
  int64_t best_source_actual = search->best_actual;
  bool ambiguous = search->ambiguous;
  const uint8_t *first_amap_match = NULL;
  bool amap_identity_ambiguous = search->amap_identity_ambiguous;
  if (search->first_amap_actual >= 0) {
    uint64_t length = 0;
    const uint8_t *data = (const uint8_t *)filemirror_actual_block_data_pointer(
        scalpel_state.filemirror, search->first_amap_actual, &length);
    if (data && length > relative) {
      first_amap_match = data + relative;
    }
  }

  state->search_phase = 5;
  state->target_slot = first_slot;
  for (uint64_t actual_index = search->next_actual;
       actual_index <= image_blocks - span_blocks; actual_index++) {
    search->next_actual = actual_index;
    if ((actual_index % PST_REASSEMBLY_POLL_INTERVAL) == 0) {
      search->ambiguous = ambiguous;
      search->amap_identity_ambiguous = amap_identity_ambiguous;
      if (pst_reassembly_poll(work, candidate, state, uuidp, uuidc)) {
        free(trial_mapping);
        free(best);
        free(saved);
        return true;
      }
    }

    const uint64_t source_byte = actual_index * scalpel_state.blocksize;

    if (relative > image_size - source_byte) {
      continue;
    }
    const uint64_t available = image_size - source_byte - relative;
    uint64_t first_block_length = 0;
    const uint8_t *first_block = (const uint8_t *)
        filemirror_actual_block_data_pointer(
            scalpel_state.filemirror, (int64_t)actual_index,
            &first_block_length);

    if (!first_block || first_block_length <= relative
        || !pst_reassembly_anchor_matches(
               current, anchor, first_block + relative, available)) {
      continue;
    }
    if (anchor->kind == PST_ANCHOR_AMAP_PAGE) {
      const uint8_t *matched_page = first_block + relative;

      if (!first_amap_match) {
        first_amap_match = matched_page;
        search->first_amap_actual = (int64_t)actual_index;
      }
      else if (memcmp(first_amap_match, matched_page,
                      (size_t)anchor->extent) != 0) {
        // AMap pages do not identify their parent PST. Distinct matches at the
        // same logical offset make a global substitution unsafe.
        amap_identity_ambiguous = true;
      }
    }

    memcpy(trial_mapping, saved, (size_t)total_blocks * sizeof(*saved));
    if (!pst_reassembly_anchor_mapping(blockvector, current->variant,
            trial_mapping, first_slot, span_blocks, (int64_t)actual_index, permute)) {
      continue;
    }
    for (uint64_t slot = 0; slot < total_blocks; slot++) {
      blockvector_set_apparent_blocknumber(blockvector, slot, trial_mapping[slot]);
    }

    inflate_blockvector(blockvector);
    blockvector_set_data_length(blockvector, state->file_size);

    PstTrialResult trial;

    memset(&trial, 0, sizeof(trial));
    pst_reassembly_evaluate_candidate(*candidate, &trial);

    const int compared_to_best = pst_reassembly_compare_trials(
        &trial, &best_result);
    const int compared_to_current = pst_reassembly_compare_trials(
        &trial, current);

    if (compared_to_best > 0) {
      best_result = trial;
      best_source_actual = (int64_t)actual_index;
      ambiguous = false;
      pst_reassembly_record_best(search, &trial, first_slot, span_blocks,
                                 best_source_actual);
      search->best_permuted = permute;
      for (uint64_t slot = 0; slot < total_blocks; slot++) {
        best[slot] = blockvector_get_apparent_blocknumber(blockvector, slot);
      }
    }
    else if (compared_to_best == 0 && compared_to_current > 0
             && best_source_actual >= 0
             && best_source_actual != (int64_t)actual_index) {
      uint64_t mapped_length = span_blocks * scalpel_state.blocksize;
      const uint64_t logical_start = first_slot * scalpel_state.blocksize;

      if (mapped_length > state->file_size - logical_start) {
        mapped_length = state->file_size - logical_start;
      }
      const uint64_t available_source_bytes = image_size - source_byte;
      const uint64_t best_source_byte = (uint64_t)best_source_actual
                                        * scalpel_state.blocksize;
      const uint64_t best_available = image_size - best_source_byte;
      uint64_t best_length = 0;
      const uint8_t *best_data = (const uint8_t *)
          filemirror_actual_block_data_pointer(
              scalpel_state.filemirror, best_source_actual, &best_length);

      if (!best_data || best_length == 0
          || mapped_length > available_source_bytes
          || mapped_length > best_available
          || memcmp(best_data, first_block, (size_t)mapped_length) != 0) {
        ambiguous = true;
      }
    }

    for (uint64_t index = 0; index < total_blocks; index++) {
      blockvector_set_apparent_blocknumber(
          blockvector, index, saved[index]);
    }
    inflate_blockvector(blockvector);
    blockvector_set_data_length(blockvector, state->file_size);
  }

  search->done = true;

  if (pst_reassembly_compare_trials(&best_result, current) > 0
      && !ambiguous && !amap_identity_ambiguous) {
    for (uint64_t slot = 0; slot < total_blocks; slot++) {
      blockvector_set_apparent_blocknumber(blockvector, slot, best[slot]);
    }
    inflate_blockvector(blockvector);
    blockvector_set_data_length(blockvector, state->file_size);
    state->profile = (uint32_t)best_result.profile;
    state->variant = (uint32_t)best_result.variant;
    state->failure_offset = best_result.failure_offset;
    state->repairs++;
    state->search_phase = 0;
    state->target_slot = 0;
    state->resume_choice = 0;
    carve_put_state((*candidate)->carvehashkey, state);
    *improved = true;
  }
  else {
    for (uint64_t slot = 0; slot < total_blocks; slot++) {
      blockvector_set_apparent_blocknumber(blockvector, slot, saved[slot]);
    }
    inflate_blockvector(blockvector);
    blockvector_set_data_length(blockvector, state->file_size);
  }
  free(best);
  free(saved);
  free(trial_mapping);
  return false;
}

static inline bool pst_reassembly_data_trailer_matches(
    const PstTrialResult *current, const uint8_t *data,
    uint64_t available) {
  if (!current || !data
      || current->failure_anchor.kind != PST_ANCHOR_DATA_BLOCK) {
    return false;
  }
  const PstFailureAnchor *anchor = &current->failure_anchor;
  uint64_t trailer_size = PST_UNICODE_BLOCK_TRAILER_SIZE;

  if (current->variant == PST_VARIANT_ANSI) {
    trailer_size = PST_ANSI_BLOCK_TRAILER_SIZE;
  }
  else if (current->variant == PST_VARIANT_UNICODE_4K) {
    trailer_size = PST_UNICODE_4K_BLOCK_TRAILER_SIZE;
  }
  else if (current->variant != PST_VARIANT_UNICODE) {
    return false;
  }
  if (available < trailer_size || anchor->data_size == 0
      || anchor->extent < trailer_size) {
    return false;
  }

  const uint32_t stored_size = pst_read_le16(data);
  const uint16_t stored_signature = pst_read_le16(data + 2);
  uint64_t stored_bid = 0;

  if (current->variant == PST_VARIANT_ANSI) {
    stored_bid = pst_read_le32(data + 4);
  }
  else {
    stored_bid = pst_read_le64(data + 8);
  }
  return stored_size == anchor->data_size
         && pst_normalize_bid(stored_bid) == pst_normalize_bid(anchor->bid)
         && stored_signature
                == pst_compute_signature(anchor->logical_offset, stored_bid);
}

// If an OOO run contains the end of a larger data block, its trailer provides
// a strong anchor even though the complete data-block CRC cannot be checked in
// physical order. Trial the shortest ending run first and retain only a unique
// global improvement.
//
static inline bool pst_reassembly_try_data_trailer_replacement(
    ThreadWork *work, CarveInfo **candidate, PstCarveState *state,
    const PstTrialResult *current, uuid_string_t uuidp,
    uuid_string_t uuidc, bool *improved) {
  if (!work || !candidate || !*candidate || !(*candidate)->b || !state
      || !current || !improved || scalpel_state.blocksize == 0
      || current->failure_anchor.kind != PST_ANCHOR_DATA_BLOCK) {
    return false;
  }
  *improved = false;

  const PstFailureAnchor *anchor = &current->failure_anchor;
  BlockVector *blockvector = (*candidate)->b;
  const uint64_t total_blocks = blockvector_get_num_blocks(blockvector);
  const uint64_t image_size = filemirror_filesize(scalpel_state.filemirror);
  const uint64_t image_blocks = CEILDIV(image_size,
                                        scalpel_state.blocksize);
  uint64_t trailer_size = PST_UNICODE_BLOCK_TRAILER_SIZE;

  if (current->variant == PST_VARIANT_ANSI) {
    trailer_size = PST_ANSI_BLOCK_TRAILER_SIZE;
  }
  else if (current->variant == PST_VARIANT_UNICODE_4K) {
    trailer_size = PST_UNICODE_4K_BLOCK_TRAILER_SIZE;
  }
  else if (current->variant != PST_VARIANT_UNICODE) {
    return false;
  }
  if (anchor->extent < trailer_size
      || anchor->logical_offset >= state->file_size
      || anchor->extent > state->file_size - anchor->logical_offset) {
    return false;
  }

  const uint64_t object_first_slot = anchor->logical_offset
                                     / scalpel_state.blocksize;
  const uint64_t trailer_offset = anchor->logical_offset + anchor->extent
                                  - trailer_size;
  const uint64_t trailer_slot = trailer_offset / scalpel_state.blocksize;
  const uint64_t trailer_relative = trailer_offset
                                    % scalpel_state.blocksize;
  const uint64_t maximum_run = trailer_slot - object_first_slot + 1;

  if (object_first_slot == 0 || trailer_slot >= total_blocks
      || maximum_run == 0 || maximum_run > image_blocks) {
    return false;
  }

  PstRepairSearch *search = pst_reassembly_search(
      state, PST_SEARCH_TRAILER, current, trailer_slot);
  if (search->done) {
    return false;
  }

  int64_t *saved = (int64_t *)malloc(
      (size_t)total_blocks * sizeof(*saved));
  int64_t *best = (int64_t *)malloc(
      (size_t)total_blocks * sizeof(*best));

  check_memory_allocation(saved, __LINE__, __FILE__,
                          "PST data-trailer mapping");
  check_memory_allocation(best, __LINE__, __FILE__,
                          "PST best data-trailer mapping");
  for (uint64_t slot = 0; slot < total_blocks; slot++) {
    saved[slot] = blockvector_get_apparent_blocknumber(blockvector, slot);
    best[slot] = saved[slot];
  }

  pst_reassembly_restore_best(blockvector, search, best);
  PstTrialResult best_result = search->best_result;
  int64_t best_source_first = search->best_actual;
  uint64_t best_run = search->best_blocks != 0 ? search->best_blocks : UINT64_MAX;
  bool ambiguous = search->ambiguous;

  state->search_phase = 6;
  state->target_slot = trailer_slot;
  for (uint64_t actual_index = search->next_actual; actual_index < image_blocks;
       actual_index++) {
    search->next_actual = actual_index;
    if ((actual_index % PST_REASSEMBLY_POLL_INTERVAL) == 0) {
      search->ambiguous = ambiguous;
      if (pst_reassembly_poll(work, candidate, state, uuidp, uuidc)) {
        free(best);
        free(saved);
        return true;
      }
    }

    uint64_t block_length = 0;
    const uint8_t *block = (const uint8_t *)
        filemirror_actual_block_data_pointer(
            scalpel_state.filemirror, (int64_t)actual_index,
            &block_length);

    if (!block || trailer_relative > block_length
        || !pst_reassembly_data_trailer_matches(
               current, block + trailer_relative,
               block_length - trailer_relative)) {
      continue;
    }

    for (uint64_t run = search->next_width != 0 ? search->next_width : 1;
         run <= maximum_run; run++) {
      search->next_width = run;
      if ((run % PST_REASSEMBLY_POLL_INTERVAL) == 0) {
        search->ambiguous = ambiguous;
        inflate_blockvector(blockvector);
        blockvector_set_data_length(blockvector, state->file_size);
        if (pst_reassembly_poll(work, candidate, state, uuidp, uuidc)) {
          free(best);
          free(saved);
          return true;
        }
      }
      search->next_width = run + 1;
      if (actual_index + 1 < run) {
        break;
      }
      const uint64_t source_first = actual_index + 1 - run;
      const uint64_t target_first = trailer_slot + 1 - run;
      bool source_available = true;

      for (uint64_t index = 0; index < run; index++) {
        const int64_t actual = (int64_t)(source_first + index);
        const int64_t source_slot = pst_reassembly_find_actual_slot(
            blockvector, actual);

        if ((source_slot >= 0
             && ((uint64_t)source_slot < target_first
                 || (uint64_t)source_slot >= target_first + run))
            || (source_slot < 0
                && filemirror_actual_block_covered(
                       scalpel_state.filemirror, actual))) {
          source_available = false;
          break;
        }
        const int64_t apparent = filemirror_apparent_blocknumber(
            scalpel_state.filemirror, actual);

        if (apparent < 0
            && !filemirror_actual_block_is_zero(scalpel_state.filemirror,
                                                actual)) {
          source_available = false;
          break;
        }
        blockvector_set_apparent_blocknumber(
            blockvector, target_first + index, apparent);
      }
      if (!source_available) {
        for (uint64_t index = 0; index < run; index++) {
          blockvector_set_apparent_blocknumber(
              blockvector, target_first + index,
              saved[target_first + index]);
        }
        normalize_blockvector(blockvector);
        continue;
      }

      inflate_blockvector(blockvector);
      blockvector_set_data_length(blockvector, state->file_size);

      PstTrialResult trial;

      memset(&trial, 0, sizeof(trial));
      pst_reassembly_evaluate_candidate(*candidate, &trial);

      const int compared_to_best = pst_reassembly_compare_trials(
          &trial, &best_result);
      const int compared_to_current = pst_reassembly_compare_trials(
          &trial, current);

      if (compared_to_best > 0
          || (compared_to_best == 0 && compared_to_current > 0
              && run < best_run)) {
        best_result = trial;
        best_source_first = (int64_t)source_first;
        best_run = run;
        ambiguous = false;
        pst_reassembly_record_best(search, &trial, target_first, run,
                                   best_source_first);
        for (uint64_t slot = 0; slot < total_blocks; slot++) {
          best[slot] = blockvector_get_apparent_blocknumber(
              blockvector, slot);
        }
      }
      else if (compared_to_best == 0 && compared_to_current > 0
               && run == best_run && best_source_first >= 0
               && best_source_first != (int64_t)source_first) {
        uint64_t mapped_length = run * scalpel_state.blocksize;
        const uint64_t logical_start = target_first
                                       * scalpel_state.blocksize;
        const uint64_t source_byte = source_first
                                     * scalpel_state.blocksize;
        const uint64_t best_source_byte = (uint64_t)best_source_first
                                          * scalpel_state.blocksize;
        uint64_t best_length = 0;
        const uint8_t *best_data = (const uint8_t *)
            filemirror_actual_block_data_pointer(
                scalpel_state.filemirror, best_source_first, &best_length);

        if (mapped_length > state->file_size - logical_start) {
          mapped_length = state->file_size - logical_start;
        }
        if (!best_data || best_length == 0
            || mapped_length > image_size - source_byte
            || mapped_length > image_size - best_source_byte
            || memcmp(best_data,
                      block - (run - 1) * scalpel_state.blocksize,
                      (size_t)mapped_length) != 0) {
          ambiguous = true;
        }
      }

      for (uint64_t index = 0; index < run; index++) {
        blockvector_set_apparent_blocknumber(
            blockvector, target_first + index,
            saved[target_first + index]);
      }
      inflate_blockvector(blockvector);
      blockvector_set_data_length(blockvector, state->file_size);
    }
    search->next_width = 1;
  }

  search->done = true;

  if (pst_reassembly_compare_trials(&best_result, current) > 0
      && !ambiguous) {
    for (uint64_t slot = 0; slot < total_blocks; slot++) {
      blockvector_set_apparent_blocknumber(blockvector, slot, best[slot]);
    }
    inflate_blockvector(blockvector);
    blockvector_set_data_length(blockvector, state->file_size);
    state->profile = (uint32_t)best_result.profile;
    state->variant = (uint32_t)best_result.variant;
    state->failure_offset = best_result.failure_offset;
    state->repairs++;
    state->search_phase = 0;
    state->target_slot = 0;
    state->resume_choice = 0;
    carve_put_state((*candidate)->carvehashkey, state);
    *improved = true;
  }
  else {
    for (uint64_t slot = 0; slot < total_blocks; slot++) {
      blockvector_set_apparent_blocknumber(blockvector, slot, saved[slot]);
    }
    inflate_blockvector(blockvector);
    blockvector_set_data_length(blockvector, state->file_size);
  }
  free(best);
  free(saved);
  return false;
}

// A matching data trailer supplies the payload length, BID, logical-offset
// signature, and CRC. Test two physical runs against that CRC before parsing
// or inflating the whole candidate. Both search cursors and the best pair use
// physical positions so a checkpoint can resume after apparent renumbering.
static inline bool pst_reassembly_try_split_data(
    ThreadWork *work, CarveInfo **candidate, PstCarveState *state,
    const PstTrialResult *current, uuid_string_t uuidp,
    uuid_string_t uuidc, bool *improved) {
  if (!work || !candidate || !*candidate || !(*candidate)->b || !state
      || !current || !improved || scalpel_state.blocksize == 0) {
    return false;
  }
  *improved = false;
  const PstFailureAnchor *anchor = &current->failure_anchor;
  const uint64_t bs = scalpel_state.blocksize;
  const uint64_t trailer_size = current->variant == PST_VARIANT_ANSI
      ? PST_ANSI_BLOCK_TRAILER_SIZE
      : current->variant == PST_VARIANT_UNICODE ? PST_UNICODE_BLOCK_TRAILER_SIZE
                                               : PST_UNICODE_4K_BLOCK_TRAILER_SIZE;
  if (anchor->kind != PST_ANCHOR_DATA_BLOCK || anchor->data_size == 0
      || anchor->extent < trailer_size
      || anchor->data_size > anchor->extent - trailer_size
      || anchor->logical_offset >= state->file_size
      || anchor->extent > state->file_size - anchor->logical_offset) {
    return false;
  }
  BlockVector *bv = (*candidate)->b;
  const uint64_t total = blockvector_get_num_blocks(bv);
  const uint64_t first = anchor->logical_offset / bs;
  const uint64_t relative = anchor->logical_offset % bs;
  const uint64_t trailer_offset = anchor->logical_offset
                                  + anchor->extent - trailer_size;
  const uint64_t last = trailer_offset / bs;
  const uint64_t trailer_relative = trailer_offset % bs;
  const uint64_t span = last - first + 1;
  const uint64_t image_size = filemirror_filesize(scalpel_state.filemirror);
  const uint64_t image_blocks = CEILDIV(image_size, bs);
  if (first == 0 || last >= total || span < 2 || span > image_blocks
      || total > SIZE_MAX / sizeof(int64_t)
      || trailer_relative + trailer_size > bs) {
    return false;
  }
  PstRepairSearch *search = pst_reassembly_search(
      state, PST_SEARCH_TWO_RUN, current, first);
  if (search->done) {
    return false;
  }
  int64_t *saved = (int64_t *)malloc((size_t)total * sizeof(*saved));
  int64_t *best = (int64_t *)malloc((size_t)total * sizeof(*best));
  int64_t *trial_mapping = (int64_t *)malloc(
      (size_t)total * sizeof(*trial_mapping));
  check_memory_allocation(saved, __LINE__, __FILE__, "PST split-data mapping");
  check_memory_allocation(best, __LINE__, __FILE__, "PST best split-data mapping");
  check_memory_allocation(trial_mapping, __LINE__, __FILE__,
                          "PST trial split-data mapping");
  for (uint64_t slot = 0; slot < total; slot++) {
    saved[slot] = blockvector_get_apparent_blocknumber(bv, slot);
    best[slot] = saved[slot];
  }
  pst_reassembly_restore_best(bv, search, best);
  PstTrialResult best_result = search->best_result;
  bool ambiguous = search->ambiguous;
  state->target_slot = first;
  for (uint64_t tail = search->next_actual; tail < image_blocks; tail++) {
    search->next_actual = tail;
    if ((tail % PST_REASSEMBLY_POLL_INTERVAL) == 0) {
      search->ambiguous = ambiguous;
      if (pst_reassembly_poll(work, candidate, state, uuidp, uuidc)) {
        free(trial_mapping);
        free(best);
        free(saved);
        return true;
      }
    }
    uint64_t available = 0;
    const uint8_t *tail_data = (const uint8_t *)
        filemirror_actual_block_data_pointer(
            scalpel_state.filemirror, (int64_t)tail, &available);
    if (!tail_data || trailer_relative > available
        || !pst_reassembly_data_trailer_matches(
               current, tail_data + trailer_relative, available - trailer_relative)) {
      continue;
    }
    const uint8_t *trailer = tail_data + trailer_relative;
    const uint32_t stored_crc = pst_read_le32(
        trailer + (current->variant == PST_VARIANT_ANSI ? 8 : 4));
    for (uint64_t width = search->next_width ? search->next_width : 1;
         width < span && width <= tail + 1; width++) {
      search->next_width = width;
      const uint64_t suffix = tail + 1 - width;
      const uint64_t prefix_blocks = span - width;
      const uint64_t prefix_bytes = prefix_blocks * bs - relative;
      // Bytes after the payload are padding, not evidence for choosing a run.
      if (prefix_bytes >= anchor->data_size) {
        search->next_boundary = 0;
        continue;
      }
      const uint64_t suffix_bytes = anchor->data_size - prefix_bytes;
      uint64_t suffix_available = 0;
      const uint8_t *suffix_data = (const uint8_t *)
          filemirror_actual_block_data_pointer(
              scalpel_state.filemirror, (int64_t)suffix, &suffix_available);
      if (!suffix_data || suffix_available == 0
          || suffix_bytes > image_size - suffix * bs) {
        search->next_boundary = 0;
        continue;
      }
      const uint32_t suffix_crc = pst_weak_crc32(suffix_data, suffix_bytes);
      const uLong shift = crc32_combine_gen((z_off_t)suffix_bytes);
      for (uint64_t start = search->next_boundary;
           start <= image_blocks - prefix_blocks; start++) {
        search->next_boundary = start;
        if ((start % PST_REASSEMBLY_POLL_INTERVAL) == 0) {
          search->ambiguous = ambiguous;
          if (pst_reassembly_poll(work, candidate, state, uuidp, uuidc)) {
            free(trial_mapping);
            free(best);
            free(saved);
            return true;
          }
        }
        search->next_boundary = start + 1;
        if (start < suffix + width && suffix < start + prefix_blocks) {
          continue;
        }
        const uint64_t byte = start * bs;
        if (relative > image_size - byte
            || prefix_bytes > image_size - byte - relative) {
          continue;
        }
        uint64_t start_available = 0;
        const uint8_t *start_data = (const uint8_t *)
            filemirror_actual_block_data_pointer(
                scalpel_state.filemirror, (int64_t)start, &start_available);
        if (!start_data || start_available <= relative) {
          continue;
        }
        const uint32_t prefix_crc = pst_weak_crc32(
            start_data + relative, prefix_bytes);
        if ((uint32_t)crc32_combine_op(prefix_crc, suffix_crc, shift) != stored_crc) {
          continue;
        }
        memcpy(trial_mapping, saved, (size_t)total * sizeof(*saved));
        if (!pst_reassembly_anchor_mapping(bv, current->variant, trial_mapping,
                first, prefix_blocks, (int64_t)start, true)
            || !pst_reassembly_anchor_mapping(bv, current->variant, trial_mapping,
                first + prefix_blocks, width, (int64_t)suffix, true)) {
          continue;
        }
        for (uint64_t slot = 0; slot < total; slot++) {
          blockvector_set_apparent_blocknumber(bv, slot, trial_mapping[slot]);
        }
        inflate_blockvector(bv);
        blockvector_set_data_length(bv, state->file_size);
        const uint8_t *data = (const uint8_t *)blockvector_get_data_pointer(bv);
        if (data && pst_reassembly_anchor_matches(
                current, anchor, data + anchor->logical_offset,
                state->file_size - anchor->logical_offset)) {
          PstTrialResult trial;
          pst_reassembly_evaluate_candidate(*candidate, &trial);
          const int compared = pst_reassembly_compare_trials(&trial, &best_result);
          if (compared > 0) {
            best_result = trial;
            ambiguous = false;
            memcpy(best, trial_mapping, (size_t)total * sizeof(*best));
            pst_reassembly_record_best(search, &trial, first, span, (int64_t)start);
            search->best_permuted = true;
            search->best_tail_actual = (int64_t)suffix;
            search->best_prefix_blocks = prefix_blocks;
          }
          else if (compared == 0
                   && pst_reassembly_compare_trials(&trial, current) > 0
                   && memcmp(best, trial_mapping, (size_t)total * sizeof(*best)) != 0) {
            ambiguous = true;
          }
        }
        for (uint64_t slot = 0; slot < total; slot++) {
          blockvector_set_apparent_blocknumber(bv, slot, saved[slot]);
        }
        inflate_blockvector(bv);
        blockvector_set_data_length(bv, state->file_size);
      }
      search->next_boundary = 0;
    }
    search->next_width = 1;
  }
  search->done = true;
  if (!ambiguous && pst_reassembly_compare_trials(&best_result, current) > 0) {
    for (uint64_t slot = 0; slot < total; slot++) {
      blockvector_set_apparent_blocknumber(bv, slot, best[slot]);
    }
    inflate_blockvector(bv);
    blockvector_set_data_length(bv, state->file_size);
    state->profile = (uint32_t)best_result.profile;
    state->variant = (uint32_t)best_result.variant;
    state->failure_offset = best_result.failure_offset;
    state->repairs++;
    state->search_phase = 0;
    state->target_slot = 0;
    state->resume_choice = 0;
    carve_put_state((*candidate)->carvehashkey, state);
    *improved = true;
  }
  free(trial_mapping);
  free(best);
  free(saved);
  return false;
}

// Test physically forward suffixes in increasing gap width. Equally valid
// repairs first preserve authenticated block evidence and physical runs that
// continue across a contrasting filler region. Before the first allocation
// map is recovered, remaining ties preserve the longest header prefix. Once an
// allocation map is available, the repair closest to the failed structure
// changes the least speculative context. Competing displacements remain
// ambiguous.
//
static inline bool pst_reassembly_try_suffix_shift(
    ThreadWork *work, CarveInfo **candidate, PstCarveState *state,
    const PstTrialResult *current, uint64_t target_slot,
    uuid_string_t uuidp, uuid_string_t uuidc, bool *improved) {
  if (!work || !candidate || !*candidate || !(*candidate)->b || !state
      || !current || !improved) {
    return false;
  }
  *improved = false;

  BlockVector *blockvector = (*candidate)->b;
  const uint64_t total_blocks = blockvector_get_num_blocks(blockvector);
  const uint64_t image_blocks = CEILDIV(
      filemirror_filesize(scalpel_state.filemirror), scalpel_state.blocksize);

  if (target_slot == 0 || target_slot >= total_blocks) {
    return false;
  }

  const uint64_t maximum_allocation = state->variant
                                           == PST_VARIANT_UNICODE_4K
                                       ? PST_UNICODE_4K_MAXIMUM_BLOCK_SIZE
                                       : PST_STANDARD_MAXIMUM_BLOCK_SIZE;
  uint64_t boundary_window = CEILDIV(maximum_allocation,
                                     scalpel_state.blocksize);

  if (boundary_window == 0) {
    boundary_window = 1;
  }
  uint64_t first_boundary = target_slot;
  uint64_t last_boundary = target_slot;

  const bool amap_guided = current->amap_failure_offset != 0
                           && current->amap_failure_offset < state->file_size;
  const bool preserve_longest_prefix = amap_guided
                                       && current->verified_amap_pages == 0;

  if (amap_guided) {
    first_boundary = 1;
    if (current->verified_amap_pages != 0) {
      const uint64_t amap_first = state->variant == PST_VARIANT_UNICODE_4K
                                      ? PST_UNICODE_4K_AMAP_FIRST_OFFSET
                                      : PST_STANDARD_AMAP_FIRST_OFFSET;
      const uint64_t amap_interval = state->variant
                                         == PST_VARIANT_UNICODE_4K
                                     ? PST_UNICODE_4K_AMAP_INTERVAL
                                     : PST_STANDARD_AMAP_INTERVAL;
      const uint64_t amap_page_size = state->variant
                                          == PST_VARIANT_UNICODE_4K
                                      ? PST_UNICODE_4K_PAGE_SIZE
                                      : PST_UNICODE_PAGE_SIZE;
      const uint64_t verified_index = current->verified_amap_pages - 1;

      if (verified_index <= (UINT64_MAX - amap_first) / amap_interval) {
        const uint64_t verified_offset = amap_first
                                         + verified_index * amap_interval;

        if (verified_offset <= UINT64_MAX - amap_page_size) {
          first_boundary = CEILDIV(verified_offset + amap_page_size,
                                   scalpel_state.blocksize);
        }
      }
    }
    if (first_boundary == 0) {
      first_boundary = 1;
    }
    if (first_boundary > last_boundary) {
      first_boundary = last_boundary;
    }
  }

  // Once one structural anchor has been repaired, the next failed PST
  // allocation can follow an earlier physical fragmentation boundary. Search
  // from the first movable block through every boundary the failed allocation
  // could straddle.
  //
  else if (state->repairs != 0) {
    first_boundary = 1;
    last_boundary = target_slot + boundary_window;
    if (last_boundary >= total_blocks) {
      last_boundary = total_blocks - 1;
    }
  }

  PstRepairSearch *search = pst_reassembly_search(
      state, PST_SEARCH_SUFFIX, current, target_slot);
  if (search->done) {
    return false;
  }

  int64_t *saved = (int64_t *)malloc(
      (size_t)total_blocks * sizeof(*saved));
  int64_t *best = (int64_t *)malloc(
      (size_t)total_blocks * sizeof(*best));

  check_memory_allocation(saved, __LINE__, __FILE__,
                          "PST suffix mapping");
  check_memory_allocation(best, __LINE__, __FILE__,
                          "PST best suffix mapping");
  for (uint64_t slot = 0; slot < total_blocks; slot++) {
    saved[slot] = blockvector_get_apparent_blocknumber(blockvector, slot);
    best[slot] = saved[slot];
  }

  pst_reassembly_restore_best(blockvector, search, best);
  PstTrialResult best_result = search->best_result;
  bool ambiguous = search->ambiguous;
  uint64_t trials = 0;
  uint64_t best_boundary = search->best_actual >= 0 ? search->best_first_slot : 0;
  uint64_t best_shift = search->best_shift;
  uint32_t best_boundary_evidence = search->best_boundary_evidence;
  BlockValidationDecision best_skipped_peak = search->best_actual >= 0
      ? search->best_confidence : BLOCK_CONFIDENCE_VALID;
  uint64_t best_skipped_total = search->best_skipped_total;
  const uint32_t resume_pass = search->pass;
  const uint64_t resume_boundary = search->next_boundary;
  const uint64_t resume_shift = search->next_width;

  state->search_phase = 1;
  state->target_slot = target_slot;
  for (uint32_t pass = resume_pass; pass < 3; pass++) {
    search->pass = pass;
    for (uint64_t boundary = pass == resume_pass && resume_boundary != 0
                                ? resume_boundary : first_boundary;
         boundary <= last_boundary; boundary++) {
      search->next_boundary = boundary;
      if ((pass == 1 && boundary != target_slot)
          || (pass == 2 && boundary == target_slot)) {
        continue;
      }
      const uint64_t suffix_blocks = total_blocks - boundary;
      int64_t base_actual = blockvector_get_actual_blocknumber(
          blockvector, boundary);

      if (base_actual < 0 && boundary > 0) {
        const int64_t previous = blockvector_get_actual_blocknumber(
            blockvector, boundary - 1);

        if (previous >= 0) {
          base_actual = previous + 1;
        }
      }
      if (base_actual < 0 || (uint64_t)base_actual >= image_blocks
          || suffix_blocks > image_blocks - (uint64_t)base_actual) {
        continue;
      }
      const uint64_t maximum_shift = image_blocks
                                     - (uint64_t)base_actual
                                     - suffix_blocks;
      uint64_t first_shift = 1;
      uint64_t last_shift = maximum_shift;

      if (pass == 0 && last_shift > PST_REASSEMBLY_FAST_SHIFT_LIMIT) {
        last_shift = PST_REASSEMBLY_FAST_SHIFT_LIMIT;
      }
      else if (pass != 0) {
        first_shift = PST_REASSEMBLY_FAST_SHIFT_LIMIT + 1;
      }
      if (pass == resume_pass && boundary == resume_boundary
          && resume_shift > first_shift) {
        first_shift = resume_shift;
      }
      if (first_shift > last_shift) {
        continue;
      }

      for (uint64_t shift = first_shift; shift <= last_shift; shift++) {
        search->next_width = shift + 1;
        const uint64_t source_start = (uint64_t)base_actual + shift;
        bool available = true;
        uint32_t boundary_evidence = 0;
        BlockValidationDecision skipped_peak = BLOCK_CONFIDENCE_INVALID;
        uint64_t skipped_total = 0;

        for (uint64_t slot = 0; slot < boundary; slot++) {
          const int64_t actual = blockvector_get_actual_blocknumber(
              blockvector, slot);

          if (actual >= 0 && (uint64_t)actual >= source_start
              && (uint64_t)actual - source_start < suffix_blocks) {
            available = false;
            break;
          }
        }
        for (uint64_t index = 0; available && index < suffix_blocks;
             index++) {
          const int64_t actual = (int64_t)(source_start + index);
          const int64_t apparent = filemirror_apparent_blocknumber(
              scalpel_state.filemirror, actual);

          if ((filemirror_actual_block_covered(scalpel_state.filemirror,
                                               actual)
               && pst_reassembly_find_actual_slot(blockvector, actual) < 0)
              || (apparent < 0
                  && !filemirror_actual_block_is_zero(
                         scalpel_state.filemirror, actual))) {
            available = false;
            break;
          }
          blockvector_set_apparent_blocknumber(
              blockvector, boundary + index, apparent);
        }

        if (available) {
          bool skipped_opposes_boundary = base_actual > 0;
          const bool before_zero = base_actual > 0
              && filemirror_actual_block_is_zero(
                     scalpel_state.filemirror, base_actual - 1);
          const bool after_zero = filemirror_actual_block_is_zero(
              scalpel_state.filemirror, (int64_t)source_start);
          const BlockValidationDecision before_confidence = base_actual > 0
              ? filemirror_get_blocktype(
                    scalpel_state.filemirror, base_actual - 1,
                    (*candidate)->needleidx)
              : BLOCK_CONFIDENCE_INVALID;
          const BlockValidationDecision after_confidence =
              filemirror_get_blocktype(
                  scalpel_state.filemirror, (int64_t)source_start,
                  (*candidate)->needleidx);

          for (uint64_t index = 0; index < shift; index++) {
            const int64_t skipped_actual = base_actual + (int64_t)index;
            const bool skipped_zero = filemirror_actual_block_is_zero(
                scalpel_state.filemirror, skipped_actual);
            const BlockValidationDecision skipped_confidence =
                filemirror_get_blocktype(
                    scalpel_state.filemirror, skipped_actual,
                    (*candidate)->needleidx);

            if (skipped_zero == before_zero) {
              skipped_opposes_boundary = false;
            }
            if (skipped_confidence > skipped_peak) {
              skipped_peak = skipped_confidence;
            }
            skipped_total += (uint64_t)skipped_confidence;
          }
          if (before_zero == after_zero && skipped_opposes_boundary) {
            if (before_zero) {
              boundary_evidence = 2;
            }
            else {
              const uint32_t confidence_difference =
                  before_confidence > after_confidence
                      ? (uint32_t)(before_confidence - after_confidence)
                      : (uint32_t)(after_confidence - before_confidence);

              if (confidence_difference <= 1) {
                boundary_evidence = 1;
              }
            }
          }
        }

        PstTrialResult trial;

        memset(&trial, 0, sizeof(trial));
        if (available) {
          inflate_blockvector(blockvector);
          blockvector_set_data_length(blockvector, state->file_size);
          pst_reassembly_evaluate_candidate(*candidate, &trial);

          const int compared_to_best = pst_reassembly_compare_trials(
              &trial, &best_result);
          const int compared_to_current = pst_reassembly_compare_trials(
              &trial, current);

          if (compared_to_best > 0) {
            best_result = trial;
            ambiguous = false;
            best_boundary = boundary;
            best_shift = shift;
            best_boundary_evidence = boundary_evidence;
            best_skipped_peak = skipped_peak;
            best_skipped_total = skipped_total;
            pst_reassembly_record_best(search, &trial, boundary,
                suffix_blocks, (int64_t)source_start);
            for (uint64_t slot = 0; slot < total_blocks; slot++) {
              best[slot] = blockvector_get_apparent_blocknumber(
                  blockvector, slot);
            }
          }
          else if (compared_to_best == 0 && compared_to_current > 0) {
            bool different = false;

            for (uint64_t slot = 0; slot < total_blocks; slot++) {
              if (best[slot] != blockvector_get_apparent_blocknumber(
                                    blockvector, slot)) {
                different = true;
                break;
              }
            }
            if (different) {
              if (shift == best_shift) {
                const uint64_t boundary_distance = boundary > target_slot
                                                       ? boundary - target_slot
                                                       : target_slot - boundary;
                const uint64_t best_distance = best_boundary > target_slot
                                                   ? best_boundary - target_slot
                                                   : target_slot - best_boundary;
                const bool stronger_boundary =
                    boundary_evidence > best_boundary_evidence
                    || (boundary_evidence == best_boundary_evidence
                        && skipped_peak < best_skipped_peak)
                    || (boundary_evidence == best_boundary_evidence
                        && skipped_peak == best_skipped_peak
                        && skipped_total < best_skipped_total);
                const bool equal_boundary =
                    boundary_evidence == best_boundary_evidence
                    && skipped_peak == best_skipped_peak
                    && skipped_total == best_skipped_total;

                if (stronger_boundary
                    || (equal_boundary && preserve_longest_prefix
                        && boundary > best_boundary)
                    || (equal_boundary && !preserve_longest_prefix
                        && (boundary_distance < best_distance
                            || (boundary_distance == best_distance
                                && boundary > best_boundary)))) {
                  best_boundary = boundary;
                  best_boundary_evidence = boundary_evidence;
                  best_skipped_peak = skipped_peak;
                  best_skipped_total = skipped_total;
                  pst_reassembly_record_best(search, &best_result, boundary,
                      suffix_blocks, (int64_t)source_start);
                  for (uint64_t slot = 0; slot < total_blocks; slot++) {
                    best[slot] = blockvector_get_apparent_blocknumber(
                        blockvector, slot);
                  }
                }
              }
              else {
                ambiguous = true;
              }
            }
          }
        }

        for (uint64_t index = 0; index < suffix_blocks; index++) {
          blockvector_set_apparent_blocknumber(
              blockvector, boundary + index, saved[boundary + index]);
        }
        // The next trial uses physical block numbers and reservations. Restore
        // those without rereading bytes, which are materialized for validation.
        normalize_blockvector(blockvector);
        trials++;
        if ((trials % PST_REASSEMBLY_POLL_INTERVAL) == 0) {
          search->ambiguous = ambiguous;
          search->best_shift = best_shift;
          search->best_boundary_evidence = best_boundary_evidence;
          search->best_confidence = best_skipped_peak;
          search->best_skipped_total = best_skipped_total;
          inflate_blockvector(blockvector);
          blockvector_set_data_length(blockvector, state->file_size);
          if (pst_reassembly_poll(work, candidate, state, uuidp, uuidc)) {
            free(best);
            free(saved);
            return true;
          }
        }
      }
    }
    if (pst_reassembly_compare_trials(&best_result, current) > 0
        && !ambiguous) {
      break;
    }
  }

  search->done = true;

  if (pst_reassembly_compare_trials(&best_result, current) > 0
      && !ambiguous) {
    for (uint64_t slot = 0; slot < total_blocks; slot++) {
      blockvector_set_apparent_blocknumber(blockvector, slot, best[slot]);
    }
    inflate_blockvector(blockvector);
    blockvector_set_data_length(blockvector, state->file_size);
    state->profile = (uint32_t)best_result.profile;
    state->variant = (uint32_t)best_result.variant;
    state->failure_offset = best_result.failure_offset;
    state->repairs++;
    state->search_phase = 0;
    state->target_slot = 0;
    state->resume_choice = 0;
    carve_put_state((*candidate)->carvehashkey, state);
    *improved = true;
  }
  else {
    for (uint64_t slot = 0; slot < total_blocks; slot++) {
      blockvector_set_apparent_blocknumber(blockvector, slot, saved[slot]);
    }
    inflate_blockvector(blockvector);
    blockvector_set_data_length(blockvector, state->file_size);
    state->search_phase = 2;
    state->target_slot = target_slot;
  }
  free(best);
  free(saved);
  return false;
}

// A complete PST parse does not inspect bytes in AMap-declared free space.
// Preserve the complete mapping, then publish bounded alternatives when a
// low-confidence physical run interrupts zero-filled free space. These
// alternatives remain PROMISING because the format cannot identify the
// original contents of unallocated space.
//
static inline bool pst_reassembly_write_free_gap_hypotheses(
    ThreadWork *work, CarveInfo **candidate, PstCarveState *state,
    uuid_string_t uuidp, uuid_string_t uuidc) {
  if (!work || !candidate || !*candidate || !(*candidate)->b || !state
      || !scalpel_state.write_promising || scalpel_state.blocksize == 0) {
    return false;
  }

  BlockVector *blockvector = (*candidate)->b;
  const uint64_t total_blocks = blockvector_get_num_blocks(blockvector);
  const uint64_t image_blocks = CEILDIV(
      filemirror_filesize(scalpel_state.filemirror), scalpel_state.blocksize);
  const uint64_t length = blockvector_get_data_length(blockvector);
  const uint8_t *data = (const uint8_t *)blockvector_get_data_pointer(
      blockvector);
  PstLayout layout = {0};

  if (total_blocks < 3 || !data || length == 0
      || !pst_parse(data, length, &layout)
      || layout.amap_dirty || !layout.amap_free_consistent
      || layout.verified_amap_pages == 0
      || scalpel_state.blocksize % layout.amap_granularity != 0) {
    pst_layout_clear(&layout);
    return false;
  }

  PstFreeGapSearch *search = &state->free_gaps;
  if (!search->initialized || search->repairs != state->repairs) {
    *search = (PstFreeGapSearch){.initialized = true,
                               .repairs = state->repairs};
  }
  if (search->done || search->next_slot > total_blocks
      || search->width > total_blocks - search->next_slot) {
    pst_layout_clear(&layout);
    return false;
  }
  const uint64_t first_slot = CEILDIV(
      layout.amap_first_offset + layout.page_size, scalpel_state.blocksize);

  int64_t *saved = (int64_t *)malloc(
      (size_t)total_blocks * sizeof(*saved));
  check_memory_allocation(saved, __LINE__, __FILE__,
                          "PST free-space hypothesis mapping");
  for (uint64_t slot = 0; slot < total_blocks; slot++) {
    saved[slot] = blockvector_get_apparent_blocknumber(blockvector, slot);
  }

  if (search->phase == 0) {
    // A complete parse can leave several unrelated free-space gaps invisible.
    // Build one cumulative alternative directly from the physical run so that
    // all short contrasting extents can be omitted together. The alternative
    // remains PROMISING because reserved and unallocated bytes are not
    // authenticated by the PST structures.
    //
    const int64_t header_actual = blockvector_get_actual_blocknumber(
        blockvector, 0);
    int64_t source_actual = header_actual;
    bool combined_available = header_actual >= 0;
    bool combined_changed = false;

    for (uint64_t slot = 0; combined_available && slot < total_blocks; slot++) {
      if (slot > 0 && source_actual > 0
          && (uint64_t)source_actual < image_blocks
          && filemirror_actual_block_is_zero(
                 scalpel_state.filemirror, source_actual - 1)
          && !filemirror_actual_block_is_zero(
                 scalpel_state.filemirror, source_actual)) {
        uint64_t width = 0;
        bool low_confidence = true;

        while (width < PST_REASSEMBLY_FAST_SHIFT_LIMIT
               && (uint64_t)source_actual + width < image_blocks
               && !filemirror_actual_block_is_zero(
                      scalpel_state.filemirror,
                      source_actual + (int64_t)width)) {
          if (filemirror_get_blocktype(
                  scalpel_state.filemirror,
                  source_actual + (int64_t)width,
                  (*candidate)->needleidx) > BLOCK_CONFIDENCE_LOW) {
            low_confidence = false;
          }
          width++;
        }

        const uint64_t logical_offset = slot * scalpel_state.blocksize;
        uint64_t logical_size = width * scalpel_state.blocksize;
        bool logical_region_unverified = false;

        if (logical_offset < state->file_size
            && logical_size > state->file_size - logical_offset) {
          logical_size = state->file_size - logical_offset;
        }
        if (logical_size != 0) {
          if (logical_offset < layout.amap_first_offset
              && logical_size
                     <= layout.amap_first_offset - logical_offset) {
            logical_region_unverified = true;
          }
          else if (logical_size % layout.amap_granularity == 0
                   && pst_amap_range_free(&layout, logical_offset,
                                          logical_size)) {
            logical_region_unverified = true;
          }
        }

        if (low_confidence && width > 0
            && width < PST_REASSEMBLY_FAST_SHIFT_LIMIT
            && (uint64_t)source_actual + width < image_blocks
            && filemirror_actual_block_is_zero(
                   scalpel_state.filemirror,
                   source_actual + (int64_t)width)
            && logical_region_unverified) {
          source_actual += (int64_t)width;
          combined_changed = true;
        }
      }

      if ((uint64_t)source_actual >= image_blocks
          || filemirror_actual_block_covered(scalpel_state.filemirror,
                                             source_actual)) {
        combined_available = false;
        break;
      }
      const int64_t apparent = filemirror_apparent_blocknumber(
          scalpel_state.filemirror, source_actual);

      if (apparent < 0
          && !filemirror_actual_block_is_zero(scalpel_state.filemirror,
                                              source_actual)) {
        combined_available = false;
        break;
      }
      blockvector_set_apparent_blocknumber(blockvector, slot, apparent);
      source_actual++;
    }

    if (combined_available && combined_changed) {
      PstTrialResult trial;

      inflate_blockvector(blockvector);
      blockvector_set_data_length(blockvector, state->file_size);
      memset(&trial, 0, sizeof(trial));
      pst_reassembly_evaluate_candidate(*candidate, &trial);
      if (trial.complete) {
        const CarveInfoFlavor saved_flavor = (*candidate)->flavor;
        const uint64_t saved_validates_to = (*candidate)->best_validates_to;

        (*candidate)->flavor = PROMISING;
        (*candidate)->best_validates_to = state->file_size - 1;
        write_candidate(candidate, true);
        (*candidate)->flavor = saved_flavor;
        (*candidate)->best_validates_to = saved_validates_to;
        search->hypotheses++;
      }
    }

    for (uint64_t slot = 0; slot < total_blocks; slot++) {
      blockvector_set_apparent_blocknumber(blockvector, slot, saved[slot]);
    }
    inflate_blockvector(blockvector);
    blockvector_set_data_length(blockvector, state->file_size);
    pst_layout_clear(&layout);
    const uint8_t *restored_data = (const uint8_t *)
        blockvector_get_data_pointer(blockvector);

    if (!restored_data
        || !pst_parse(restored_data, state->file_size, &layout)) {
      free(saved);
      pst_layout_clear(&layout);
      return false;
    }
    search->phase = 1;
    search->next_slot = first_slot;
    if (pst_reassembly_poll(work, candidate, state, uuidp, uuidc)) {
      free(saved);
      pst_layout_clear(&layout);
      return true;
    }
  }

  // Allocation maps cannot authenticate stale bytes in free space. When a
  // recovered physical run ends immediately before a nonzero source block but
  // the current free-space hypothesis resumes with zero blocks elsewhere,
  // publish each bounded physical continuation as a PROMISING alternative.
  //
  for (uint64_t slot = search->next_slot;
       search->phase == 1 && slot < total_blocks
       && search->hypotheses < PST_REASSEMBLY_HYPOTHESIS_LIMIT;
       slot++, search->next_slot = slot) {
    const int64_t previous_actual = slot > 0
        ? blockvector_get_actual_blocknumber(blockvector, slot - 1) : -1;
    const int64_t current_actual = blockvector_get_actual_blocknumber(
        blockvector, slot);

    if (previous_actual < 0 || current_actual < 0
        || current_actual == previous_actual + 1
        || !filemirror_actual_block_is_zero(
               scalpel_state.filemirror, current_actual)) {
      continue;
    }

    uint64_t width = search->width;
    // Only the committed mapping is checkpointed. Reinstall the already
    // tested physical prefix without parsing or publishing it again.
    for (uint64_t offset = 0; offset < width; offset++) {
      blockvector_set_apparent_blocknumber(blockvector, slot + offset,
          filemirror_apparent_blocknumber(scalpel_state.filemirror,
              previous_actual + (int64_t)offset + 1));
    }

    while (slot + width < total_blocks
           && search->hypotheses < PST_REASSEMBLY_HYPOTHESIS_LIMIT) {
      const uint64_t target_slot = slot + width;
      const int64_t mapped_actual = blockvector_get_actual_blocknumber(
          blockvector, target_slot);

      if (mapped_actual < 0
          || !filemirror_actual_block_is_zero(
                 scalpel_state.filemirror, mapped_actual)
          || width > (uint64_t)(INT64_MAX - previous_actual - 1)) {
        break;
      }
      const int64_t source_actual = previous_actual + (int64_t)width + 1;

      if (source_actual < 0 || (uint64_t)source_actual >= image_blocks
          || filemirror_actual_block_is_zero(
                 scalpel_state.filemirror, source_actual)
          || filemirror_actual_block_covered(
                 scalpel_state.filemirror, source_actual)
          || pst_reassembly_find_actual_slot(blockvector, source_actual) >= 0) {
        break;
      }
      const uint64_t logical_offset = target_slot * scalpel_state.blocksize;
      uint64_t logical_size = scalpel_state.blocksize;

      if (logical_offset >= state->file_size) {
        break;
      }
      if (logical_size > state->file_size - logical_offset) {
        logical_size = state->file_size - logical_offset;
      }
      // Inflation can move the byte buffer between free-space trials.
      layout.data = (const uint8_t *)blockvector_get_data_pointer(blockvector);
      if (logical_size == 0
          || logical_size % layout.amap_granularity != 0
          || !pst_amap_range_free(&layout, logical_offset, logical_size)) {
        break;
      }
      const int64_t source_apparent = filemirror_apparent_blocknumber(
          scalpel_state.filemirror, source_actual);

      if (source_apparent < 0) {
        break;
      }
      blockvector_set_apparent_blocknumber(blockvector, target_slot,
                                           source_apparent);
      width++;
      inflate_blockvector(blockvector);
      blockvector_set_data_length(blockvector, state->file_size);

      PstTrialResult trial;

      memset(&trial, 0, sizeof(trial));
      pst_reassembly_evaluate_candidate(*candidate, &trial);
      if (trial.complete) {
        const CarveInfoFlavor saved_flavor = (*candidate)->flavor;
        const uint64_t saved_validates_to = (*candidate)->best_validates_to;

        (*candidate)->flavor = PROMISING;
        (*candidate)->best_validates_to = state->file_size - 1;
        write_candidate(candidate, true);
        (*candidate)->flavor = saved_flavor;
        (*candidate)->best_validates_to = saved_validates_to;
        search->hypotheses++;
      }
      search->width = width;

      const bool checkpoint_requested = atomic_load_explicit(
          &REASS_RETURN_TO_IDLE, memory_order_acquire);

      if (!checkpoint_requested
          && (width % PST_REASSEMBLY_POLL_INTERVAL) == 0
          && reassembly_check_kill_queue(
                 work, candidate, uuidp, uuidc)) {
        free(saved);
        pst_layout_clear(&layout);
        return true;
      }
      if (checkpoint_requested) {
        // Checkpoint only the committed mapping. If the request is withdrawn,
        // reconstruct the current trial prefix and continue the same search.
        for (uint64_t target = slot; target < slot + width; target++) {
          blockvector_set_apparent_blocknumber(blockvector, target,
                                               saved[target]);
        }
        inflate_blockvector(blockvector);
        blockvector_set_data_length(blockvector, state->file_size);
        if (pst_reassembly_poll(work, candidate, state, uuidp, uuidc)) {
          free(saved);
          pst_layout_clear(&layout);
          return true;
        }
        for (uint64_t offset = 0; offset < width; offset++) {
          const int64_t trial_actual = previous_actual
                                       + (int64_t)offset + 1;
          const int64_t trial_apparent = filemirror_apparent_blocknumber(
              scalpel_state.filemirror, trial_actual);

          blockvector_set_apparent_blocknumber(blockvector, slot + offset,
                                               trial_apparent);
        }
        inflate_blockvector(blockvector);
        blockvector_set_data_length(blockvector, state->file_size);
      }
    }
    for (uint64_t target = slot; target < slot + width; target++) {
      blockvector_set_apparent_blocknumber(blockvector, target,
                                           saved[target]);
    }
    if (width != 0) {
      inflate_blockvector(blockvector);
      blockvector_set_data_length(blockvector, state->file_size);
      slot += width - 1;
    }
    search->next_slot = slot + 1;
    search->width = 0;
    if (pst_reassembly_poll(work, candidate, state, uuidp, uuidc)) {
      free(saved);
      pst_layout_clear(&layout);
      return true;
    }
  }

  if (search->phase == 1) {
    search->phase = 2;
    search->next_slot = first_slot;
    search->width = 0;
  }
  for (uint64_t slot = search->next_slot;
       slot + 1 < total_blocks
       && search->hypotheses < PST_REASSEMBLY_HYPOTHESIS_LIMIT;
       slot++, search->next_slot = slot) {
    const int64_t previous_actual = blockvector_get_actual_blocknumber(
        blockvector, slot - 1);
    const int64_t current_actual = blockvector_get_actual_blocknumber(
        blockvector, slot);

    if (previous_actual < 0 || current_actual != previous_actual + 1
        || !filemirror_actual_block_is_zero(
               scalpel_state.filemirror, previous_actual)
        || filemirror_actual_block_is_zero(
               scalpel_state.filemirror, current_actual)) {
      continue;
    }

    uint64_t width = 0;
    bool low_confidence = true;

    while (width < PST_REASSEMBLY_FAST_SHIFT_LIMIT
           && (uint64_t)current_actual + width < image_blocks
           && !filemirror_actual_block_is_zero(
                  scalpel_state.filemirror,
                  current_actual + (int64_t)width)) {
      if (filemirror_get_blocktype(
              scalpel_state.filemirror, current_actual + (int64_t)width,
              (*candidate)->needleidx) > BLOCK_CONFIDENCE_LOW) {
        low_confidence = false;
      }
      width++;
    }
    if (!low_confidence || width == 0
        || width >= PST_REASSEMBLY_FAST_SHIFT_LIMIT
        || (uint64_t)current_actual + width >= image_blocks
        || !filemirror_actual_block_is_zero(
               scalpel_state.filemirror,
               current_actual + (int64_t)width)) {
      continue;
    }

    const uint64_t logical_offset = slot * scalpel_state.blocksize;
    uint64_t logical_size = width * scalpel_state.blocksize;

    if (logical_offset >= state->file_size) {
      break;
    }
    if (logical_size > state->file_size - logical_offset) {
      logical_size = state->file_size - logical_offset;
    }
    layout.data = (const uint8_t *)blockvector_get_data_pointer(blockvector);
    if (logical_size == 0
        || logical_size % layout.amap_granularity != 0
        || !pst_amap_range_free(&layout, logical_offset, logical_size)) {
      continue;
    }

    bool available = true;

    for (uint64_t target = slot; target < total_blocks; target++) {
      const int64_t saved_actual = blockvector_get_actual_blocknumber(
          blockvector, target);

      if (saved_actual < 0
          || (uint64_t)saved_actual > UINT64_MAX - width
          || (uint64_t)saved_actual + width >= image_blocks) {
        available = false;
        break;
      }
      const int64_t source_actual = saved_actual + (int64_t)width;
      const int64_t source_slot = pst_reassembly_find_actual_slot(
          blockvector, source_actual);

      if ((source_slot >= 0 && (uint64_t)source_slot < slot)
          || (source_slot < 0
              && filemirror_actual_block_covered(
                     scalpel_state.filemirror, source_actual))) {
        available = false;
        break;
      }
      const int64_t apparent = filemirror_apparent_blocknumber(
          scalpel_state.filemirror, source_actual);

      if (apparent < 0
          && !filemirror_actual_block_is_zero(
                 scalpel_state.filemirror, source_actual)) {
        available = false;
        break;
      }
      blockvector_set_apparent_blocknumber(blockvector, target, apparent);
    }

    PstTrialResult trial;

    memset(&trial, 0, sizeof(trial));
    if (available) {
      inflate_blockvector(blockvector);
      blockvector_set_data_length(blockvector, state->file_size);
      pst_reassembly_evaluate_candidate(*candidate, &trial);

      if (trial.complete) {
        const CarveInfoFlavor saved_flavor = (*candidate)->flavor;
        const uint64_t saved_validates_to = (*candidate)->best_validates_to;

        (*candidate)->flavor = PROMISING;
        (*candidate)->best_validates_to = state->file_size - 1;
        write_candidate(candidate, true);
        (*candidate)->flavor = saved_flavor;
        (*candidate)->best_validates_to = saved_validates_to;
        search->hypotheses++;
      }
    }

    for (uint64_t target = 0; target < total_blocks; target++) {
      blockvector_set_apparent_blocknumber(blockvector, target,
                                           saved[target]);
    }
    inflate_blockvector(blockvector);
    blockvector_set_data_length(blockvector, state->file_size);

    slot += width - 1;
    search->next_slot = slot + 1;
    if (pst_reassembly_poll(work, candidate, state, uuidp, uuidc)) {
      free(saved);
      pst_layout_clear(&layout);
      return true;
    }
    pst_layout_clear(&layout);
    const uint8_t *restored_data = (const uint8_t *)
        blockvector_get_data_pointer(blockvector);

    if (!restored_data
        || !pst_parse(restored_data, state->file_size, &layout)) {
      break;
    }
  }

  search->done = true;
  free(saved);
  pst_layout_clear(&layout);
  return false;
}

static inline void pst_continuity_clear(PstContinuitySearch *search) {
  if (search) {
    free(search->runs);
    memset(search, 0, sizeof(*search));
  }
}

// A physically continuous run can include reserved or unallocated bytes that
// PST checksums do not cover. Try extending backwards from the next known run,
// or forwards from the preceding run at EOF. Retain the original mapping and
// publish at most one cumulative alternative, always as PROMISING.
//
static inline bool pst_reassembly_write_continuity_hypothesis(
    ThreadWork *work, CarveInfo **candidate, PstCarveState *state,
    uuid_string_t uuidp, uuid_string_t uuidc) {
  if (!work || !candidate || !*candidate || !(*candidate)->b || !state
      || !scalpel_state.write_promising || scalpel_state.blocksize == 0) {
    return false;
  }
  PstContinuitySearch *search = &state->continuity;
  if (!search->initialized || search->repairs != state->repairs) {
    pst_continuity_clear(search);
    search->initialized = true;
    search->repairs = state->repairs;
    search->unverified = true;
  }
  if (search->done) {
    return false;
  }

  BlockVector *blockvector = (*candidate)->b;
  const uint64_t blocksize = scalpel_state.blocksize;
  const uint64_t total_blocks = blockvector_get_num_blocks(blockvector);
  const uint64_t image_size = filemirror_filesize(scalpel_state.filemirror);
  const uint64_t image_blocks = CEILDIV(image_size, blocksize);
  const uint64_t length = blockvector_get_data_length(blockvector);
  const uint8_t *data = (const uint8_t *)blockvector_get_data_pointer(blockvector);
  PstLayout layout = {0};
  if (length == 0 || length != state->file_size
      || total_blocks != CEILDIV(length, blocksize)
      || total_blocks > SIZE_MAX / sizeof(int64_t) || image_blocks > INT64_MAX
      || search->next_slot > total_blocks + 1
      || search->run_start > total_blocks || !data
      || !pst_parse(data, length, &layout)
      || layout.amap_dirty || !layout.amap_free_consistent
      || layout.verified_amap_pages == 0
      || blocksize % layout.amap_granularity != 0) {
    pst_layout_clear(&layout);
    search->done = true;
    return false;
  }

  int64_t *saved = (int64_t *)malloc((size_t)total_blocks * sizeof(*saved));
  check_memory_allocation(saved, __LINE__, __FILE__, "PST committed mapping");
  int64_t *alternate = (int64_t *)malloc(
      (size_t)total_blocks * sizeof(*alternate));
  check_memory_allocation(alternate, __LINE__, __FILE__,
                          "PST continuity mapping");
  for (uint64_t slot = 0; slot < total_blocks; slot++) {
    saved[slot] = blockvector_get_apparent_blocknumber(blockvector, slot);
    alternate[slot] = blockvector_get_actual_blocknumber(blockvector, slot);
  }
  for (uint64_t i = 0; i < search->count; i++) {
    const PstContinuityRun *run = &search->runs[i];
    for (uint64_t j = 0; j < run->blocks; j++) {
      alternate[run->first_slot + j] = run->actual + (int64_t)j;
    }
  }
  const uint64_t header_size = layout.variant == PST_VARIANT_ANSI
      ? PST_HEADER_MINIMUM_SIZE : PST_UNICODE_HEADER_SIZE;

  for (uint64_t slot = search->next_slot; slot <= total_blocks; slot++) {
    const int64_t actual = slot < total_blocks
        ? blockvector_get_actual_blocknumber(blockvector, slot) : -1;
    const int64_t previous = slot > 0
        ? blockvector_get_actual_blocknumber(blockvector, slot - 1) : -1;
    if (slot > 0 && (slot == total_blocks || actual < 0 || previous < 0
                     || actual != previous + 1)) {
      const uint64_t first = search->run_start;
      const uint64_t width = slot - first;
      int64_t source = -1;
      if (first > 0 && width > 0 && search->unverified) {
        if (slot < total_blocks && actual >= 0 && (uint64_t)actual >= width) {
          source = actual - (int64_t)width;
        }
        else if (slot == total_blocks && alternate[first - 1] >= 0
                 && alternate[first - 1] < INT64_MAX) {
          source = alternate[first - 1] + 1;
        }
      }
      const uint64_t bytes = slot == total_blocks
          ? length - first * blocksize : width * blocksize;
      bool available = source >= 0 && (uint64_t)source < image_blocks
          && bytes <= image_size - (uint64_t)source * blocksize;
      bool changed = false;
      PstOffsetSet retained = {0};
      if (available) {
        for (uint64_t i = 0; i < total_blocks; i++) {
          if ((i < first || i >= slot) && alternate[i] >= 0
              && !pst_offset_set_insert(&retained, (uint64_t)alternate[i])
              && !pst_offset_set_contains(&retained, (uint64_t)alternate[i])) {
            available = false;
            break;
          }
        }
      }
      for (uint64_t i = 0; available && i < width; i++) {
        const int64_t proposed = source + (int64_t)i;
        if (filemirror_actual_block_covered(scalpel_state.filemirror, proposed)
            || pst_offset_set_contains(&retained, (uint64_t)proposed)
            || (filemirror_apparent_blocknumber(scalpel_state.filemirror,
                                                proposed) < 0
                && !filemirror_actual_block_is_zero(scalpel_state.filemirror,
                                                     proposed))) {
          available = false;
        }
        if (alternate[first + i] != proposed) {
          changed = true;
        }
      }
      pst_offset_set_clear(&retained);

      if (available && changed) {
        for (uint64_t i = 0; i < total_blocks; i++) {
          const int64_t proposed = i >= first && i < slot
              ? source + (int64_t)(i - first) : alternate[i];
          const int64_t apparent = proposed < 0 ? -1
              : filemirror_apparent_blocknumber(scalpel_state.filemirror,
                                                 proposed);
          blockvector_set_apparent_blocknumber(blockvector, i, apparent);
        }
        inflate_blockvector(blockvector);
        blockvector_set_data_length(blockvector, length);
        PstTrialResult trial = {0};
        pst_reassembly_evaluate_candidate(*candidate, &trial);
        if (trial.complete && trial.file_size == length
            && trial.profile == layout.profile && trial.variant == layout.variant) {
          if (search->count == search->capacity) {
            const uint64_t capacity = search->capacity == 0
                ? 8 : search->capacity * 2;
            if (capacity > SIZE_MAX / sizeof(*search->runs)) {
              handle_error(SCALPEL_GENERAL_ABORT,
                           "PST continuity mapping is too large", __LINE__, __FILE__);
            }
            search->runs = (PstContinuityRun *)realloc(
                search->runs, (size_t)capacity * sizeof(*search->runs));
            check_memory_allocation(search->runs, __LINE__, __FILE__,
                                    "PST continuity runs");
            search->capacity = capacity;
          }
          search->runs[search->count++] = (PstContinuityRun){first, width, source};
          for (uint64_t i = 0; i < width; i++) {
            alternate[first + i] = source + (int64_t)i;
          }
        }
        for (uint64_t i = 0; i < total_blocks; i++) {
          blockvector_set_apparent_blocknumber(blockvector, i, saved[i]);
        }
        inflate_blockvector(blockvector);
        blockvector_set_data_length(blockvector, length);
        layout.data = (const uint8_t *)blockvector_get_data_pointer(blockvector);
      }
      search->run_start = slot;
      search->unverified = true;
    }
    if (slot < total_blocks && search->unverified) {
      const uint64_t offset = slot * blocksize;
      const uint64_t bytes = length - offset < blocksize
          ? length - offset : blocksize;
      search->unverified = offset >= header_size
          && ((offset < layout.amap_first_offset
               && bytes <= layout.amap_first_offset - offset)
              || pst_amap_range_free(&layout, offset, bytes));
    }
    search->next_slot = slot + 1;
    if ((slot % PST_REASSEMBLY_POLL_INTERVAL) == 0
        || atomic_load_explicit(&REASS_RETURN_TO_IDLE, memory_order_acquire)) {
      if (pst_reassembly_poll(work, candidate, state, uuidp, uuidc)) {
        free(alternate);
        free(saved);
        pst_layout_clear(&layout);
        return true;
      }
    }
  }

  if (search->count != 0) {
    for (uint64_t slot = 0; slot < total_blocks; slot++) {
      const int64_t apparent = alternate[slot] < 0 ? -1
          : filemirror_apparent_blocknumber(scalpel_state.filemirror,
                                             alternate[slot]);
      blockvector_set_apparent_blocknumber(blockvector, slot, apparent);
    }
    inflate_blockvector(blockvector);
    blockvector_set_data_length(blockvector, length);
    PstTrialResult trial = {0};
    pst_reassembly_evaluate_candidate(*candidate, &trial);
    if (trial.complete && trial.file_size == length
        && trial.profile == layout.profile && trial.variant == layout.variant) {
      const CarveInfoFlavor flavor = (*candidate)->flavor;
      const uint64_t validates_to = (*candidate)->best_validates_to;
      (*candidate)->flavor = PROMISING;
      (*candidate)->best_validates_to = length - 1;
      write_candidate(candidate, true);
      (*candidate)->flavor = flavor;
      (*candidate)->best_validates_to = validates_to;
    }
    for (uint64_t slot = 0; slot < total_blocks; slot++) {
      blockvector_set_apparent_blocknumber(blockvector, slot, saved[slot]);
    }
    inflate_blockvector(blockvector);
    blockvector_set_data_length(blockvector, length);
  }
  search->done = true;
  free(alternate);
  free(saved);
  pst_layout_clear(&layout);
  return false;
}

// Replace the block containing the first rejected structure with an unmapped
// physical block. Blocks already present in the candidate are left to suffix
// relocation so an improvement cannot displace correct but unverified data.
//
static inline bool pst_reassembly_try_block_replacement(
    ThreadWork *work, CarveInfo **candidate, PstCarveState *state,
    const PstTrialResult *current, uint64_t target_slot,
    uuid_string_t uuidp, uuid_string_t uuidc, bool *improved) {
  if (!work || !candidate || !*candidate || !(*candidate)->b || !state
      || !current || !improved) {
    return false;
  }
  *improved = false;

  BlockVector *blockvector = (*candidate)->b;
  const uint64_t total_blocks = blockvector_get_num_blocks(blockvector);
  const uint64_t image_blocks = CEILDIV(
      filemirror_filesize(scalpel_state.filemirror), scalpel_state.blocksize);

  if (target_slot == 0 || target_slot >= total_blocks) {
    return false;
  }

  const PstSearchContext context = target_slot
      == CEILDIV(current->failure_offset, scalpel_state.blocksize)
      && target_slot != current->failure_offset / scalpel_state.blocksize
          ? PST_SEARCH_NEIGHBOR : PST_SEARCH_BLOCK;
  PstRepairSearch *search = pst_reassembly_search(
      state, context, current, target_slot);
  if (search->done) {
    return false;
  }

  int64_t *best = (int64_t *)malloc((size_t)total_blocks * sizeof(*best));
  check_memory_allocation(best, __LINE__, __FILE__,
                          "PST best block mapping");
  for (uint64_t slot = 0; slot < total_blocks; slot++) {
    best[slot] = blockvector_get_apparent_blocknumber(blockvector, slot);
  }

  pst_reassembly_restore_best(blockvector, search, best);
  PstTrialResult best_result = search->best_result;
  BlockValidationDecision best_confidence = search->best_confidence;
  int64_t best_reservations = search->best_reservations;
  int64_t best_distance = search->best_distance;
  bool ambiguous = search->ambiguous;
  const int64_t saved_apparent = blockvector_get_apparent_blocknumber(
      blockvector, target_slot);
  const int64_t saved_actual = blockvector_get_actual_blocknumber(
      blockvector, target_slot);

  state->search_phase = 2;
  state->target_slot = target_slot;
  for (uint64_t actual_index = search->next_actual; actual_index < image_blocks;
       actual_index++) {
    search->next_actual = actual_index;
    if ((actual_index % PST_REASSEMBLY_POLL_INTERVAL) == 0) {
      search->ambiguous = ambiguous;
      search->best_confidence = best_confidence;
      search->best_reservations = best_reservations;
      search->best_distance = best_distance;
      inflate_blockvector(blockvector);
      blockvector_set_data_length(blockvector, state->file_size);
      if (pst_reassembly_poll(work, candidate, state, uuidp, uuidc)) {
        free(best);
        return true;
      }
    }
    const int64_t actual = (int64_t)actual_index;
    const int64_t source_slot = pst_reassembly_find_actual_slot(
        blockvector, actual);

    if (actual == saved_actual || source_slot >= 0
        || filemirror_actual_block_covered(scalpel_state.filemirror,
                                           actual)) {
      continue;
    }

    const int64_t source_apparent = filemirror_apparent_blocknumber(
        scalpel_state.filemirror, actual);

    if (source_apparent < 0
        && !filemirror_actual_block_is_zero(scalpel_state.filemirror,
                                            actual)) {
      continue;
    }

    blockvector_set_apparent_blocknumber(blockvector, target_slot,
                                         source_apparent);
    inflate_blockvector(blockvector);
    blockvector_set_data_length(blockvector, state->file_size);

    PstTrialResult trial;

    memset(&trial, 0, sizeof(trial));
    pst_reassembly_evaluate_candidate(*candidate, &trial);

    const BlockValidationDecision confidence = filemirror_get_blocktype(
        scalpel_state.filemirror, actual, (*candidate)->needleidx);
    const int64_t reservations = scalpel_state.reservations
        ? filemirror_actual_block_reserved(scalpel_state.filemirror, actual)
        : 0;
    const int64_t distance = saved_actual >= 0
        ? llabs(actual - saved_actual) : INT64_MAX;
    const int compared_to_best = pst_reassembly_compare_trials(
        &trial, &best_result);
    const int compared_to_current = pst_reassembly_compare_trials(
        &trial, current);
    const bool better = compared_to_best > 0
        || (compared_to_best == 0 && compared_to_current > 0
            && (confidence > best_confidence
                || (confidence == best_confidence
                    && reservations < best_reservations)
                || (confidence == best_confidence
                    && reservations == best_reservations
                    && distance < best_distance)));

    if (better) {
      best_result = trial;
      best_confidence = confidence;
      best_reservations = reservations;
      best_distance = distance;
      ambiguous = false;
      pst_reassembly_record_best(search, &trial, target_slot, 1, actual);
      for (uint64_t slot = 0; slot < total_blocks; slot++) {
        best[slot] = blockvector_get_apparent_blocknumber(blockvector, slot);
      }
    }
    else if (compared_to_best == 0 && compared_to_current > 0
             && confidence == best_confidence
             && reservations == best_reservations
             && distance == best_distance) {
      ambiguous = true;
    }

    blockvector_set_apparent_blocknumber(blockvector, target_slot,
                                         saved_apparent);
    normalize_blockvector(blockvector);
  }

  search->done = true;

  if (pst_reassembly_compare_trials(&best_result, current) > 0
      && !ambiguous) {
    for (uint64_t slot = 0; slot < total_blocks; slot++) {
      blockvector_set_apparent_blocknumber(blockvector, slot, best[slot]);
    }
    inflate_blockvector(blockvector);
    blockvector_set_data_length(blockvector, state->file_size);
    state->profile = (uint32_t)best_result.profile;
    state->variant = (uint32_t)best_result.variant;
    state->failure_offset = best_result.failure_offset;
    state->repairs++;
    state->search_phase = 0;
    state->target_slot = 0;
    state->resume_choice = 0;
    carve_put_state((*candidate)->carvehashkey, state);
    *improved = true;
  }
  else {
    blockvector_set_apparent_blocknumber(blockvector, target_slot,
                                         saved_apparent);
    inflate_blockvector(blockvector);
    blockvector_set_data_length(blockvector, state->file_size);
    state->search_phase = 3;
    state->target_slot = target_slot;
  }
  free(best);
  return false;
}

static inline void pst_reassembly(ThreadWork *work,
                                  CarveInfo **candidate,
                                  uuid_string_t uuidp,
                                  uuid_string_t uuidc) {
  PstCarveState *state = candidate && *candidate
      ? (PstCarveState *)carve_get_state((*candidate)->carvehashkey) : NULL;

  if (!candidate || !*candidate || !state
      || state->magic != PST_STATE_MAGIC
      || state->version != PST_STATE_VERSION
      || state->file_size == 0) {
    pst_free_carve_state((void **)&state);
    if (candidate && *candidate) {
      if (scalpel_state.write_promising) {
        (*candidate)->flavor = PROMISING;
        write_candidate(candidate, false);
      }
      else {
        destroy_candidate(candidate);
      }
    }
    return;
  }
  if (!pst_reassembly_initialize_candidate(*candidate, state)) {
    pst_free_carve_state((void **)&state);
    destroy_candidate(candidate);
    return;
  }
  pst_reassembly_resume_searches(*candidate, state);

  while (*candidate) {
    PstTrialResult current;

    memset(&current, 0, sizeof(current));
    if (!pst_reassembly_evaluate_candidate(*candidate, &current)) {
      break;
    }
    state->profile = (uint32_t)current.profile;
    state->variant = (uint32_t)current.variant;
    state->failure_offset = current.failure_offset;
    carve_put_state((*candidate)->carvehashkey, state);

    if (current.complete) {
      if (pst_reassembly_write_free_gap_hypotheses(
              work, candidate, state, uuidp, uuidc)) {
        pst_free_carve_state((void **)&state);
        return;
      }
      if (pst_reassembly_write_continuity_hypothesis(
              work, candidate, state, uuidp, uuidc)) {
        pst_free_carve_state((void **)&state);
        return;
      }
      break;
    }

    const uint64_t total_blocks = blockvector_get_num_blocks((*candidate)->b);
    uint64_t target_slot = current.failure_offset / scalpel_state.blocksize;

    if (target_slot == 0) {
      target_slot = 1;
    }
    if (target_slot >= total_blocks || state->repairs >= total_blocks) {
      break;
    }

    bool improved = false;
    uint64_t suffix_target_slot = target_slot;

    if (pst_reassembly_try_transition_backshift(
            work, candidate, state, &current, &current.failure_anchor,
            uuidp, uuidc, &improved)) {
      pst_free_carve_state((void **)&state);
      return;
    }
    if (!*candidate) {
      pst_free_carve_state((void **)&state);
      return;
    }
    if (improved) {
      continue;
    }

    if (pst_reassembly_try_transition_backshift(
            work, candidate, state, &current,
            &current.amap_failure_anchor, uuidp, uuidc, &improved)) {
      pst_free_carve_state((void **)&state);
      return;
    }
    if (!*candidate) {
      pst_free_carve_state((void **)&state);
      return;
    }
    if (improved) {
      continue;
    }

    if (pst_reassembly_try_boundary_refinement(
            work, candidate, state, &current, uuidp, uuidc, &improved)) {
      pst_free_carve_state((void **)&state);
      return;
    }
    if (!*candidate) {
      pst_free_carve_state((void **)&state);
      return;
    }
    if (improved) {
      continue;
    }

    if (pst_reassembly_try_anchor_replacement(
            work, candidate, state, &current,
            &current.amap_failure_anchor, uuidp, uuidc, false, &improved)) {
      pst_free_carve_state((void **)&state);
      return;
    }
    if (!*candidate) {
      pst_free_carve_state((void **)&state);
      return;
    }
    if (improved) {
      continue;
    }

    if (pst_reassembly_try_anchor_replacement(
            work, candidate, state, &current, &current.failure_anchor,
            uuidp, uuidc, false, &improved)) {
      pst_free_carve_state((void **)&state);
      return;
    }
    if (!*candidate) {
      pst_free_carve_state((void **)&state);
      return;
    }
    if (improved) {
      continue;
    }

    if (pst_reassembly_try_data_trailer_replacement(
            work, candidate, state, &current, uuidp, uuidc, &improved)) {
      pst_free_carve_state((void **)&state);
      return;
    }
    if (!*candidate) {
      pst_free_carve_state((void **)&state);
      return;
    }
    if (improved) {
      continue;
    }

    if (current.amap_failure_offset != 0
        && current.amap_failure_offset < state->file_size) {
      suffix_target_slot = current.amap_failure_offset
                           / scalpel_state.blocksize;
      if (suffix_target_slot == 0) {
        suffix_target_slot = 1;
      }
      if (suffix_target_slot >= total_blocks) {
        suffix_target_slot = target_slot;
      }
    }

    if (pst_reassembly_try_suffix_shift(
            work, candidate, state, &current, suffix_target_slot,
            uuidp, uuidc, &improved)) {
      pst_free_carve_state((void **)&state);
      return;
    }
    if (!*candidate) {
      pst_free_carve_state((void **)&state);
      return;
    }
    if (improved) {
      continue;
    }

    if (pst_reassembly_try_block_replacement(
            work, candidate, state, &current, target_slot,
            uuidp, uuidc, &improved)) {
      pst_free_carve_state((void **)&state);
      return;
    }
    if (!*candidate) {
      pst_free_carve_state((void **)&state);
      return;
    }
    if (improved) {
      continue;
    }

    // A rejected PST page or block can begin near the end of one Scalpel3
    // block and consume bytes from the next. If replacing the block that
    // contains the failure offset does not help, test that boundary neighbor
    // under the same complete structural and CRC comparison.
    const uint64_t boundary_target_slot = CEILDIV(
        current.failure_offset, scalpel_state.blocksize);

    if (boundary_target_slot != target_slot
        && boundary_target_slot < total_blocks) {
      if (pst_reassembly_try_block_replacement(
              work, candidate, state, &current, boundary_target_slot,
              uuidp, uuidc, &improved)) {
        pst_free_carve_state((void **)&state);
        return;
      }
      if (!*candidate) {
        pst_free_carve_state((void **)&state);
        return;
      }
      if (improved) {
        continue;
      }
    }
    // Prefer physical run continuity before permuting authenticated structures.
    if (pst_reassembly_try_anchor_replacement(
            work, candidate, state, &current, &current.amap_failure_anchor,
            uuidp, uuidc, true, &improved)) {
      pst_free_carve_state((void **)&state);
      return;
    }
    if (!*candidate) {
      pst_free_carve_state((void **)&state);
      return;
    }
    if (improved) {
      continue;
    }
    if (pst_reassembly_try_anchor_replacement(
            work, candidate, state, &current, &current.failure_anchor,
            uuidp, uuidc, true, &improved)) {
      pst_free_carve_state((void **)&state);
      return;
    }
    if (!*candidate) {
      pst_free_carve_state((void **)&state);
      return;
    }
    if (improved) {
      continue;
    }
    if (pst_reassembly_try_split_data(
            work, candidate, state, &current, uuidp, uuidc, &improved)) {
      pst_free_carve_state((void **)&state);
      return;
    }
    if (!*candidate) {
      pst_free_carve_state((void **)&state);
      return;
    }
    if (improved) {
      continue;
    }
    break;
  }

  if (*candidate) {
    PstTrialResult final_result;

    memset(&final_result, 0, sizeof(final_result));
    pst_reassembly_evaluate_candidate(*candidate, &final_result);
    state->profile = (uint32_t)final_result.profile;
    state->variant = (uint32_t)final_result.variant;
    state->failure_offset = final_result.failure_offset;
    blockvector_set_data_length((*candidate)->b, state->file_size);
    resize_blockvector((*candidate)->b,
                       CEILDIV(state->file_size, scalpel_state.blocksize));
    carve_put_state((*candidate)->carvehashkey, state);
    pst_assign_candidate_profile(*candidate,
                                 (PstProfile)state->profile);

    if (final_result.complete && scalpel_state.no_defrag) {
      (*candidate)->best_validates_to = state->file_size - 1;
      (*candidate)->flavor = VALIDATED;
      write_candidate(candidate, false);
    }
    else if (scalpel_state.write_promising) {
      if (final_result.complete) {
        (*candidate)->best_validates_to = state->file_size - 1;
      }
      (*candidate)->flavor = PROMISING;
      write_candidate(candidate, false);
    }
    else {
      destroy_candidate(candidate);
    }
  }
  pst_free_carve_state((void **)&state);
}

static inline bool pst_serialize_carve_state(void **state, FILE *fp,
                                             StateSerialization mode) {
  if (!state || !fp) {
    return false;
  }
  PstCarveState **typed = (PstCarveState **)state;

  if (mode == SERIALIZE) {
    if (!*typed) {
      return false;
    }
    PstCarveState header = **typed;
    header.continuity.runs = NULL;
    header.continuity.capacity = header.continuity.count;
    if (fwrite(&header, sizeof(header), 1, fp) != 1
        || (header.continuity.count != 0
            && fwrite((*typed)->continuity.runs,
                      sizeof(*header.continuity.runs),
                      (size_t)header.continuity.count, fp)
                   != header.continuity.count)) {
      handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
    }
    return true;
  }

  if (mode == DESERIALIZE) {
    *typed = (PstCarveState *)calloc(1, sizeof(**typed));
    check_memory_allocation(*typed, __LINE__, __FILE__,
                            "PST carve state");
  }
  const size_t count = fread(*typed, sizeof(**typed), 1, fp);

  if (count != 1) {
    handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
  }
  if (mode == DESERIALIZE) {
    PstContinuitySearch *continuity = &(*typed)->continuity;
    continuity->runs = NULL;
    continuity->capacity = 0;
    const uint64_t blocks = scalpel_state.blocksize != 0
        ? CEILDIV((*typed)->file_size, scalpel_state.blocksize)
        : (*typed)->file_size;
    bool valid = (*typed)->magic == PST_STATE_MAGIC
        && (*typed)->version == PST_STATE_VERSION
        && (*typed)->file_size <= PST_MAXIMUM_FILE_SIZE
        && (*typed)->free_gaps.phase <= 2
        && (*typed)->free_gaps.hypotheses <= PST_REASSEMBLY_HYPOTHESIS_LIMIT
        && (*typed)->free_gaps.next_slot <= PST_MAXIMUM_FILE_SIZE
        && (*typed)->free_gaps.width
               <= PST_MAXIMUM_FILE_SIZE - (*typed)->free_gaps.next_slot
        && ((*typed)->free_gaps.phase == 1 || (*typed)->free_gaps.width == 0)
        && continuity->count <= blocks
        && continuity->count <= SIZE_MAX / sizeof(*continuity->runs)
        && continuity->next_slot <= blocks + 1
        && continuity->run_start <= blocks
        && continuity->run_start <= continuity->next_slot
        && (continuity->initialized || continuity->count == 0);
    for (uint32_t i = 0; valid && i < PST_SEARCH_CONTEXTS; i++) {
      const PstRepairSearch *search = &(*typed)->searches[i];
      valid = search->pass < 3 && search->best_actual >= -1
          && search->first_amap_actual >= -1
          && search->next_actual <= INT64_MAX
          && (search->best_blocks == 0
              || (search->best_actual >= 0
                  && search->best_blocks - 1
                         <= (uint64_t)(INT64_MAX - search->best_actual)));
      if (valid && search->best_prefix_blocks != 0) {
        valid = search->best_permuted
            && search->best_first_slot < blocks
            && search->best_blocks <= blocks - search->best_first_slot
            && search->best_prefix_blocks < search->best_blocks
            && search->best_tail_actual >= 0
            && search->best_blocks - search->best_prefix_blocks - 1
                   <= (uint64_t)(INT64_MAX - search->best_tail_actual);
      }
    }
    if (!valid) {
      pst_free_carve_state(state);
      return false;
    }
    if (continuity->count != 0) {
      continuity->runs = (PstContinuityRun *)malloc(
          (size_t)continuity->count * sizeof(*continuity->runs));
      check_memory_allocation(continuity->runs, __LINE__, __FILE__,
                              "PST continuity checkpoint");
      continuity->capacity = continuity->count;
      if (fread(continuity->runs, sizeof(*continuity->runs),
                (size_t)continuity->count, fp) != continuity->count) {
        handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
      }
      uint64_t previous_end = 1;
      for (uint64_t i = 0; i < continuity->count; i++) {
        const PstContinuityRun *run = &continuity->runs[i];
        if (run->first_slot < previous_end || run->first_slot >= blocks
            || run->blocks == 0 || run->blocks > blocks - run->first_slot
            || run->actual < 0
            || run->blocks - 1 > (uint64_t)(INT64_MAX - run->actual)
            || run->first_slot + run->blocks >= continuity->next_slot) {
          pst_free_carve_state(state);
          return false;
        }
        previous_end = run->first_slot + run->blocks;
      }
    }
  }
  return true;
}

static inline void *pst_clone_carve_state(const void *srcstate) {
  if (!srcstate) {
    return NULL;
  }
  PstCarveState *clone = (PstCarveState *)malloc(sizeof(*clone));

  check_memory_allocation(clone, __LINE__, __FILE__,
                          "PST carve state clone");
  memcpy(clone, srcstate, sizeof(*clone));
  clone->continuity.runs = NULL;
  clone->continuity.capacity = clone->continuity.count;
  if (clone->continuity.count != 0) {
    clone->continuity.runs = (PstContinuityRun *)malloc(
        (size_t)clone->continuity.count * sizeof(*clone->continuity.runs));
    check_memory_allocation(clone->continuity.runs, __LINE__, __FILE__,
                            "PST continuity clone");
    memcpy(clone->continuity.runs,
           ((const PstCarveState *)srcstate)->continuity.runs,
           (size_t)clone->continuity.count * sizeof(*clone->continuity.runs));
  }
  return clone;
}

static inline void pst_free_carve_state(void **state) {
  if (state && *state) {
    pst_continuity_clear(&((PstCarveState *)*state)->continuity);
    free(*state);
    *state = NULL;
  }
}

static inline void pst_print_carve_state(const void *state) {
  const PstCarveState *typed = (const PstCarveState *)state;

  if (!typed) {
    printf("NULL\n");
    return;
  }
  printf("profile=%s file_size=%" PRIu64
         " failure_offset=%" PRIu64 " repairs=%u\n",
         pst_profile_filetype((PstProfile)typed->profile),
         typed->file_size, typed->failure_offset, typed->repairs);
  for (uint32_t i = 0; i < PST_SEARCH_CONTEXTS; i++) {
    const PstRepairSearch *search = &typed->searches[i];
    if (search->initialized && !search->done && search->repairs == typed->repairs) {
      printf("PST search %u, actual %" PRIu64 ", boundary %" PRIu64
             ", width %" PRIu64 ", pass %u, best actual %" PRId64
             ", ambiguous %d\n", i, search->next_actual,
             search->next_boundary, search->next_width, search->pass,
             search->best_actual,
             search->ambiguous || search->amap_identity_ambiguous);
    }
  }
}

#endif
