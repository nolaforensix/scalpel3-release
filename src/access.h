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

#if !defined(SCALPEL_ACCESS_H)
#define SCALPEL_ACCESS_H

#include "scalpel.h"
#include "validator_search.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define ACCESS_HEADER_SIZE              UINT64_C(154)
#define ACCESS_ENGINE_OFFSET            UINT64_C(4)
#define ACCESS_ENGINE_SIZE              UINT64_C(15)
#define ACCESS_VERSION_OFFSET           UINT64_C(20)
#define ACCESS_ENCODING_KEY_OFFSET      UINT64_C(62)
#define ACCESS_ENCODING_KEY_MASK        UINT32_C(0x4ebc8afb)
#define ACCESS_JET3_PAGE_SIZE            UINT32_C(2048)
#define ACCESS_JET4_PAGE_SIZE            UINT32_C(4096)
#define ACCESS_MAXIMUM_DATABASE_SIZE     UINT64_C(4294967296)
#define ACCESS_MAXIMUM_ROWS_PER_PAGE     UINT32_C(255)
#define ACCESS_ROW_OFFSET_MASK           UINT16_C(0x1fff)
#define ACCESS_PAGE_INVALID              UINT8_C(0)
#define ACCESS_PAGE_DATA                 UINT8_C(1)
#define ACCESS_PAGE_TABLE_DEFINITION     UINT8_C(2)
#define ACCESS_PAGE_INDEX_NODE           UINT8_C(3)
#define ACCESS_PAGE_INDEX_LEAF           UINT8_C(4)
#define ACCESS_PAGE_USAGE_MAP            UINT8_C(5)
#define ACCESS_LONG_VALUE_PAGE_MARKER     UINT32_C(0x4c41564c)
#define ACCESS_MAP_INLINE                UINT8_C(0)
#define ACCESS_MAP_REFERENCE             UINT8_C(1)
#define ACCESS_BLOCK_CONFIDENCE          85
#define ACCESS_REASSEMBLY_POLL_INTERVAL  UINT64_C(64)
#define ACCESS_REASSEMBLY_HYPOTHESIS_LIMIT 16
#define ACCESS_REASSEMBLY_STRUCTURE_LEVELS 5

typedef enum AccessProfile {
  ACCESS_PROFILE_UNKNOWN = 0,
  ACCESS_PROFILE_MDB,
  ACCESS_PROFILE_ACCDB,
  ACCESS_PROFILE_MPD
} AccessProfile;

typedef enum AccessRecoveryResult {
  ACCESS_RECOVERY_NO_MATCH = 0,
  ACCESS_RECOVERY_MATCH,
  ACCESS_RECOVERY_AMBIGUOUS,
  ACCESS_RECOVERY_INTERRUPTED
} AccessRecoveryResult;

typedef struct AccessLayout {
  uint32_t page_size;
  uint32_t version;
  uint32_t encoding_key;
  uint32_t available_pages;
  uint32_t required_pages;
  uint32_t highest_used_page;
  uint64_t inferred_size;
  uint64_t failure_offset;
  uint64_t repair_offset;
  bool ace;
  bool encoded;
  bool unsupported_encoding;
  AccessProfile profile;
  uint8_t *used_pages;
} AccessLayout;

typedef struct AccessRunRank {
  uint32_t structure_score;
  BlockValidationDecision confidence;
  int64_t reservations;
  uint32_t boundary_score;
} AccessRunRank;

// The four solver records distinguish supported-boundary searches from their
// exhaustive fallbacks. Completed records prevent replay of earlier searches.
#define ACCESS_SEARCH_MAGIC UINT32_C(0x41434331)
typedef struct {
  uint64_t next_skip;
  BlockValidationDecision partial_confidence;
  uint64_t partial_skip;
  bool partial_extends_prefix;
  bool partial_supported;
  bool partial_preferred;
  bool have_complete;
  BlockValidationDecision complete_confidence;
  uint32_t complete_boundary_score;
  uint64_t complete_skip;
  bool complete_preferred;
  AccessProfile complete_profile;
} AccessGapProgress;

typedef struct {
  uint64_t next_run;
  uint64_t next_source;
  bool layout_ready;
  bool have_best;
  bool ambiguous;
  bool best_matches_preferred;
  uint32_t best_structure_score;
  BlockValidationDecision best_confidence;
  int64_t best_reservations;
  uint32_t best_boundary_score;
  uint64_t best_run_length;
  uint64_t best_sources[ACCESS_REASSEMBLY_HYPOTHESIS_LIMIT];
  uint32_t best_source_count;
  bool have_hypothesis_rank[ACCESS_REASSEMBLY_STRUCTURE_LEVELS];
  bool hypothesis_matches_preferred[ACCESS_REASSEMBLY_STRUCTURE_LEVELS];
  BlockValidationDecision hypothesis_confidence[ACCESS_REASSEMBLY_STRUCTURE_LEVELS];
  int64_t hypothesis_reservations[ACCESS_REASSEMBLY_STRUCTURE_LEVELS];
  uint32_t hypothesis_boundary_score[ACCESS_REASSEMBLY_STRUCTURE_LEVELS];
  uint64_t hypothesis_run_length[ACCESS_REASSEMBLY_STRUCTURE_LEVELS];
  uint64_t hypothesis_sources[ACCESS_REASSEMBLY_STRUCTURE_LEVELS][ACCESS_REASSEMBLY_HYPOTHESIS_LIMIT];
  uint64_t hypothesis_run_lengths[ACCESS_REASSEMBLY_STRUCTURE_LEVELS][ACCESS_REASSEMBLY_HYPOTHESIS_LIMIT];
  AccessProfile hypothesis_profiles[ACCESS_REASSEMBLY_STRUCTURE_LEVELS][ACCESS_REASSEMBLY_HYPOTHESIS_LIMIT];
  uint32_t hypothesis_count[ACCESS_REASSEMBLY_STRUCTURE_LEVELS];
  bool have_partial;
  bool partial_ambiguous;
  bool partial_matches_preferred;
  uint64_t best_partial_progress;
  uint64_t best_partial_repair_offset;
  uint64_t best_partial_blocks;
  uint64_t best_partial_run_length;
  uint64_t best_partial_source;
  AccessRunRank best_partial_rank;
  AccessProfile best_partial_profile;
} AccessDisplacedProgress;

typedef struct {
  uint64_t prefix_blocks;
  uint64_t total_blocks;
  uint64_t target_length;
  uint64_t preferred;
  uint64_t partial_progress;
  uint64_t partial_repair_offset;
  uint64_t partial_mapping_blocks;
  uint32_t hypotheses_written;
  AccessProfile profile;
  AccessRecoveryResult result;
  bool finished;
  bool mapping_committed;
  bool strong_hypothesis;
  bool file_local_support;
  AccessGapProgress gap;
  AccessDisplacedProgress displaced;
} AccessSolverProgress;

typedef struct {
  AccessSolverProgress progress;
  AccessLayout layout;
  int64_t *partial_mapping;
  int64_t *solution_mapping;
} AccessSolverState;

typedef struct {
  uint32_t magic;
  XXH128_hash_t view;
  XXH128_hash_t prefix_view;
  uint64_t retained_blocks;
  uint64_t retained_target_length;
  unsigned char last_reviewed_mapping[SHA256_DIGEST_LENGTH];
  uint64_t last_reviewed_target_length;
  uint64_t last_reviewed_repair_blocks;
  uint64_t last_reviewed_run_width;
  bool have_last_reviewed_mapping;
  bool iteration_active;
  uint64_t internal_repair_blocks;
  uint64_t internal_run_width;
  bool internal_repair_from_confidence;
  uint64_t current_progress;
  uint64_t current_repair_offset;
  uint64_t preparation_cursor;
  bool fallback_started;
  uint64_t next_apparent;
  int64_t best_apparent;
  uint64_t best_progress;
  BlockValidationDecision best_confidence;
  int64_t best_distance;
  int64_t best_reserved;
  bool best_valid;
  bool tail_started;
  uint64_t tail_initial_length;
  uint64_t tail_accepted_length;
  bool tail_extended;
} AccessSearchProgress;

typedef struct {
  AccessSearchProgress progress;
  AccessSolverState *solvers[4];
} AccessCarveState;

static inline bool access_serialize_carve_state(void **state, FILE *fp, StateSerialization mode);
static inline void *access_clone_carve_state(const void *state);
static inline void access_free_carve_state(void **state);
static inline size_t access_sizeof_carve_state(const void *state);
static inline void access_print_carve_state(const void *state);
static inline XXH128_hash_t access_prefix_view(CarveInfo *candidate);
static inline void access_search_reset(AccessCarveState *state);
static inline void access_search_scope(CarveInfo *candidate, AccessCarveState *state);
static inline void access_search_save(CarveInfo *candidate, AccessCarveState *state);
static inline AccessSolverState *access_solver_state(
    AccessCarveState *state, unsigned index, CarveInfo *candidate,
    uint64_t prefix_blocks, uint64_t total_blocks, uint64_t target_length,
    uint64_t preferred, uint64_t partial_progress, uint64_t partial_repair_offset,
    uint64_t partial_mapping_blocks, AccessProfile profile, uint32_t hypotheses_written,
    const int64_t *partial_mapping);
static inline bool access_preparation_poll(ThreadWork *work, CarveInfo **candidate,
    uuid_string_t uuidp, uuid_string_t uuidc, uint64_t *iterations, AccessCarveState *state);
static inline void access_reassembly_continue(ThreadWork *work, CarveInfo **candidate,
    uuid_string_t uuidp, uuid_string_t uuidc, AccessCarveState *state);
static inline AccessRecoveryResult access_reassembly_gap_search(
    ThreadWork *work, CarveInfo **candidate, uuid_string_t uuidp,
    uuid_string_t uuidc, uint64_t prefix_blocks, uint64_t total_blocks,
    uint64_t target_length, uint64_t current_progress,
    uint64_t preferred_skip, uint8_t *trial_data,
    int64_t *trial_mapping, int64_t *partial_mapping,
    int64_t *solution_mapping, uint64_t *partial_progress,
    uint64_t *partial_repair_offset, uint64_t *partial_mapping_blocks,
    AccessProfile *profile,
    uint64_t *iterations,
    uint32_t *hypotheses_written, bool *mapping_committed, AccessCarveState *state, AccessSolverState *record);
static inline AccessRecoveryResult access_reassembly_displaced_search(
    ThreadWork *work, CarveInfo **candidate, uuid_string_t uuidp,
    uuid_string_t uuidc, uint64_t prefix_blocks, uint64_t total_blocks,
    uint64_t target_length, uint64_t preferred_run_length,
    uint8_t *trial_data,
    int64_t *trial_mapping, int64_t *partial_mapping,
    uint64_t *partial_progress, uint64_t *partial_repair_offset,
    uint64_t *partial_mapping_blocks,
    AccessProfile *profile, uint64_t *iterations,
    uint32_t *hypotheses_written, bool *strong_hypothesis,
    bool *partial_has_file_local_support, bool *mapping_committed,
    AccessCarveState *state, AccessSolverState *record);



static const uint8_t access_file_prefix[4] = {
  0x00, 0x01, 0x00, 0x00
};

static const uint8_t access_jet_engine[ACCESS_ENGINE_SIZE] = {
  'S', 't', 'a', 'n', 'd', 'a', 'r', 'd', ' ', 'J', 'e', 't', ' ', 'D', 'B'
};

static const uint8_t access_ace_engine[ACCESS_ENGINE_SIZE] = {
  'S', 't', 'a', 'n', 'd', 'a', 'r', 'd', ' ', 'A', 'C', 'E', ' ', 'D', 'B'
};

static inline uint16_t access_read_le16(const uint8_t *data);
static inline uint32_t access_read_le32(const uint8_t *data);
static inline uint32_t access_read_be24(const uint8_t *data);
static inline bool access_range_available(uint64_t length, uint64_t offset,
                                          uint64_t size);
static inline void access_layout_clear(AccessLayout *layout);
static inline bool access_header_parse(const uint8_t *data, uint64_t length,
                                       AccessLayout *layout);
static inline void access_rc4(uint8_t *data, uint64_t length,
                              uint32_t key);
static inline bool access_copy_page(const uint8_t *data, uint64_t length,
                                    const AccessLayout *layout,
                                    uint32_t page_number, uint8_t *page);
static inline bool access_page_pointer_valid(
    uint32_t page_number, const AccessLayout *layout, bool allow_zero);
static inline bool access_data_page_valid(const uint8_t *page,
                                          const AccessLayout *layout);
static inline bool access_page_all_zero(const uint8_t *page,
                                        uint32_t page_size);
static inline bool access_page_valid(const uint8_t *page,
                                     const AccessLayout *layout);
static inline bool access_index_leaf_references_valid(
    const uint8_t *data, uint64_t length, AccessLayout *layout,
    uint32_t owner, const uint8_t *leaf, uint8_t *target);
// Verify the outbound relationships for one allocated page. Keeping the
// single-page check separate allows reassembly to reject a proposed mapping
// before invoking the complete database parser.
//
static inline bool access_page_relationship_valid(
    const uint8_t *data, uint64_t length, AccessLayout *layout,
    uint32_t page_number, const uint8_t *page, uint8_t *target);
static inline bool access_page_relationships_valid(
    const uint8_t *data, uint64_t length, AccessLayout *layout,
    uint8_t *page);
static inline bool access_page_plausible(const uint8_t *page,
                                         const AccessLayout *layout);
static inline void access_extend_contiguous_extent(
    const uint8_t *data, uint64_t length, AccessLayout *layout,
    uint8_t *scratch);
static inline bool access_contains_utf16le(const uint8_t *data,
                                           uint64_t length,
                                           const char *text);
static inline void access_note_semantics(const uint8_t *page,
                                         const AccessLayout *layout,
                                         uint32_t *project_evidence);
static inline bool access_inline_global_map(const uint8_t *row,
                                            uint64_t row_length,
                                            AccessLayout *layout);
static inline bool access_reference_global_map(
    const uint8_t *data, uint64_t length, const uint8_t *row,
    uint64_t row_length, AccessLayout *layout, uint8_t *scratch);
static inline bool access_parse_global_map(const uint8_t *data,
                                           uint64_t length,
                                           AccessLayout *layout,
                                           uint8_t *scratch);
static inline bool access_parse(const uint8_t *data, uint64_t length,
                                AccessLayout *layout);
static inline char *access_header_discovery(
    char *base, uint64_t offset, uint64_t remaining, char **matchpos,
    uint32_t *matchlen, uint32_t blocksize);
static inline char *access_no_header_discovery(
    char *base, uint64_t offset, uint64_t remaining, char **matchpos,
    uint32_t *matchlen, uint32_t blocksize);
static inline uint32_t access_block_validate(
    char *data, uint64_t length, BlockValidationDecision *decision,
    uint64_t *validates_to, uint32_t needleidx, uint32_t blocksize,
    void *blockhashkey);
static inline void access_file_validate(char *data, uint64_t length,
                                        bool *validates,
                                        uint64_t *validates_to,
                                        bool *promising,
                                        uint32_t needleidx,
                                        uint32_t blocksize,
                                        void *carvehashkey);
static inline const char *access_profile_filetype(AccessProfile profile);
static inline void access_assign_candidate_profile(CarveInfo *candidate,
                                                   AccessProfile profile);
static inline void access_candidate_classify(CarveInfo *candidate,
                                             bool *validates,
                                             uint64_t *validates_to,
                                             bool *promising);
static inline bool access_candidate_is_contiguous(
    const CarveInfo *candidate);
static inline bool access_reassembly_poll(ThreadWork *work,
                                          CarveInfo **candidate,
                                          uuid_string_t uuidp,
                                          uuid_string_t uuidc,
                                          uint64_t *iterations, AccessCarveState *state);
static inline bool access_reassembly_range_available(
    const CarveInfo *candidate, int64_t first, uint64_t count,
    uint64_t protected_prefix_blocks,
    int64_t excluded_first, uint64_t excluded_count);
static inline bool access_reassembly_boundary_separated(
    const CarveInfo *candidate, int64_t apparent);
static inline BlockValidationDecision access_reassembly_run_confidence(
    const CarveInfo *candidate, int64_t first, uint64_t count);
static inline int64_t access_reassembly_run_reservations(
    int64_t first, uint64_t count);
static inline int access_reassembly_compare_run_rank(
    const AccessRunRank *first, const AccessRunRank *second);
static inline bool access_reassembly_span_covers_complete_pages(
    uint64_t first_block, uint64_t count, uint32_t page_size);
static inline bool access_reassembly_build_usage_layout(
    const uint8_t *data, uint64_t length, AccessLayout *layout);
static inline bool access_reassembly_span_contains_allocated_page(
    uint64_t first_block, uint64_t count, const AccessLayout *layout);
static inline bool access_reassembly_copy_run(
    uint8_t *data, uint64_t data_length, uint64_t destination_slot,
    int64_t source_first, uint64_t count);
static inline uint32_t access_reassembly_run_structure_score(
    const uint8_t *data, uint64_t length, AccessLayout *layout,
    uint64_t first_byte, uint64_t range_length, uint8_t *scratch);
static inline bool access_reassembly_pages_valid(
    const uint8_t *data, uint64_t length, AccessLayout *layout,
    uint64_t first_byte, uint64_t range_length, uint8_t *scratch,
    uint8_t *target, bool relationships);
static inline bool access_reassembly_mappings_equal(
    const int64_t *first, const int64_t *second, uint64_t count,
    uint64_t data_length);
static inline bool access_reassembly_parse_trial(
    uint8_t *data, uint64_t length, bool *valid,
    uint64_t *progress, uint64_t *repair_offset,
    AccessProfile *profile);
static inline void access_reassembly_fill_prefix_mapping(
    const CarveInfo *candidate, int64_t *mapping, uint64_t count);
static inline bool access_reassembly_commit_mapping(
    CarveInfo *candidate, const int64_t *mapping, uint64_t total_blocks,
    uint64_t length, AccessProfile *profile);
static inline AccessRecoveryResult access_reassembly_extend_contiguous_tail(
    ThreadWork *work, CarveInfo **candidate, uuid_string_t uuidp,
    uuid_string_t uuidc, AccessProfile *profile, AccessCarveState *state);
static inline bool access_reassembly_write_mapping_hypothesis(
    CarveInfo *candidate, const int64_t *mapping, uint64_t total_blocks,
    uint64_t length, AccessProfile profile);
static inline AccessRecoveryResult access_reassembly_try_gap(
    ThreadWork *work, CarveInfo **candidate, uuid_string_t uuidp,
    uuid_string_t uuidc, uint64_t prefix_blocks, uint64_t total_blocks,
    uint64_t target_length, uint64_t current_progress,
    uint64_t preferred_skip, uint8_t *trial_data,
    int64_t *trial_mapping, int64_t *partial_mapping,
    int64_t *solution_mapping, uint64_t *partial_progress,
    uint64_t *partial_repair_offset, uint64_t *partial_mapping_blocks,
    AccessProfile *profile,
    uint64_t *iterations,
    uint32_t *hypotheses_written, bool *mapping_committed, AccessCarveState *state);
static inline AccessRecoveryResult access_reassembly_try_displaced_run(
    ThreadWork *work, CarveInfo **candidate, uuid_string_t uuidp,
    uuid_string_t uuidc, uint64_t prefix_blocks, uint64_t total_blocks,
    uint64_t target_length, uint64_t preferred_run_length,
    uint8_t *trial_data,
    int64_t *trial_mapping, int64_t *partial_mapping,
    uint64_t *partial_progress, uint64_t *partial_repair_offset,
    uint64_t *partial_mapping_blocks,
    AccessProfile *profile, uint64_t *iterations,
    uint32_t *hypotheses_written, bool *strong_hypothesis,
    bool *partial_has_file_local_support, bool *mapping_committed, AccessCarveState *state);
static inline void access_reassembly(ThreadWork *work,
                                     CarveInfo **candidate,
                                     uuid_string_t uuidp,
                                     uuid_string_t uuidc);

static inline uint16_t access_read_le16(const uint8_t *data) {
  return (uint16_t)((uint16_t)data[0] | ((uint16_t)data[1] << 8));
}

static inline uint32_t access_read_le32(const uint8_t *data) {
  return (uint32_t)data[0] | ((uint32_t)data[1] << 8)
         | ((uint32_t)data[2] << 16) | ((uint32_t)data[3] << 24);
}

static inline uint32_t access_read_be24(const uint8_t *data) {
  return ((uint32_t)data[0] << 16) | ((uint32_t)data[1] << 8)
         | (uint32_t)data[2];
}

static inline bool access_range_available(uint64_t length, uint64_t offset,
                                          uint64_t size) {
  return offset <= length && size <= length - offset;
}

static inline void access_layout_clear(AccessLayout *layout) {
  if (!layout) {
    return;
  }
  free(layout->used_pages);
  layout->used_pages = NULL;
}

// Parse the unencoded database header. Jet and ACE obscure selected header
// fields with a fixed mask; the per-database page encoding key is one of them.
//
static inline bool access_header_parse(const uint8_t *data, uint64_t length,
                                       AccessLayout *layout) {
  if (!data || !layout || length < ACCESS_HEADER_SIZE
      || memcmp(data, access_file_prefix, sizeof(access_file_prefix)) != 0) {
    return false;
  }

  const bool jet = memcmp(data + ACCESS_ENGINE_OFFSET, access_jet_engine,
                          ACCESS_ENGINE_SIZE) == 0;
  const bool ace = memcmp(data + ACCESS_ENGINE_OFFSET, access_ace_engine,
                          ACCESS_ENGINE_SIZE) == 0;

  if (!jet && !ace) {
    return false;
  }

  const uint32_t version = data[ACCESS_VERSION_OFFSET];

  if (!((jet && (version == 0 || version == 1))
        || (ace && (version == 2 || version == 3
                    || version == 5 || version == 6)))) {
    return false;
  }

  memset(layout, 0, sizeof(*layout));
  layout->version = version;
  layout->ace = ace;
  layout->page_size = version == 0 ? ACCESS_JET3_PAGE_SIZE
                                   : ACCESS_JET4_PAGE_SIZE;
  layout->encoding_key = access_read_le32(
      data + ACCESS_ENCODING_KEY_OFFSET) ^ ACCESS_ENCODING_KEY_MASK;
  layout->encoded = layout->encoding_key != 0;
  layout->unsupported_encoding = layout->encoded && version > 1;
  layout->profile = ace ? ACCESS_PROFILE_ACCDB : ACCESS_PROFILE_MDB;
  layout->failure_offset = ACCESS_HEADER_SIZE;
  layout->repair_offset = ACCESS_HEADER_SIZE;
  return true;
}

// Jet page encryption uses RC4 with the database key XORed with the logical
// page number. The key bytes are consumed in little-endian order.
//
static inline void access_rc4(uint8_t *data, uint64_t length,
                              uint32_t key) {
  uint8_t state[256];
  uint8_t key_bytes[4] = {
    (uint8_t)key,
    (uint8_t)(key >> 8),
    (uint8_t)(key >> 16),
    (uint8_t)(key >> 24)
  };

  for (uint32_t index = 0; index < 256; index++) {
    state[index] = (uint8_t)index;
  }

  uint32_t swap_index = 0;

  for (uint32_t index = 0; index < 256; index++) {
    swap_index = (swap_index + state[index] + key_bytes[index & 3]) & 0xff;
    const uint8_t saved = state[index];
    state[index] = state[swap_index];
    state[swap_index] = saved;
  }

  uint32_t left = 0;
  uint32_t right = 0;

  for (uint64_t offset = 0; offset < length; offset++) {
    left = (left + 1) & 0xff;
    right = (right + state[left]) & 0xff;
    const uint8_t saved = state[left];
    state[left] = state[right];
    state[right] = saved;
    data[offset] ^= state[(state[left] + state[right]) & 0xff];
  }
}

static inline bool access_copy_page(const uint8_t *data, uint64_t length,
                                    const AccessLayout *layout,
                                    uint32_t page_number, uint8_t *page) {
  if (!data || !layout || !page
      || page_number >= layout->available_pages) {
    return false;
  }
  const uint64_t offset = (uint64_t)page_number * layout->page_size;

  if (!access_range_available(length, offset, layout->page_size)) {
    return false;
  }
  memcpy(page, data + offset, layout->page_size);
  if (page_number != 0 && layout->encoded) {
    if (layout->unsupported_encoding) {
      return false;
    }
    access_rc4(page, layout->page_size,
               layout->encoding_key ^ page_number);
  }
  return true;
}

static inline bool access_page_pointer_valid(
    uint32_t page_number, const AccessLayout *layout, bool allow_zero) {
  if (allow_zero && page_number == 0) {
    return true;
  }
  return layout && layout->used_pages
         && page_number < layout->available_pages
         && layout->used_pages[page_number] != 0;
}

static inline bool access_data_page_valid(const uint8_t *page,
                                          const AccessLayout *layout) {
  const uint32_t row_count_offset = layout->version == 0 ? 8 : 12;
  const uint32_t row_offset = layout->version == 0 ? 10 : 14;
  const uint32_t row_count = access_read_le16(page + row_count_offset);
  const uint64_t directory_end = (uint64_t)row_offset
                                 + (uint64_t)row_count * 2;
  const uint32_t free_space = access_read_le16(page + 2);

  if (row_count > ACCESS_MAXIMUM_ROWS_PER_PAGE
      || directory_end > layout->page_size
      || free_space > layout->page_size) {
    return false;
  }

  const uint32_t owner = access_read_le32(page + 4);

  if (owner != ACCESS_LONG_VALUE_PAGE_MARKER
      && !access_page_pointer_valid(owner, layout, true)) {
    return false;
  }

  uint32_t previous_start = layout->page_size;

  for (uint32_t row = 0; row < row_count; row++) {
    const uint32_t row_start = access_read_le16(
        page + row_offset + (uint64_t)row * 2) & ACCESS_ROW_OFFSET_MASK;

    if (row_start < directory_end || row_start > previous_start) {
      return false;
    }
    previous_start = row_start;
  }
  return true;
}

static inline bool access_page_all_zero(const uint8_t *page,
                                        uint32_t page_size) {
  if (!page) {
    return false;
  }
  for (uint32_t offset = 0; offset < page_size; offset++) {
    if (page[offset] != 0) {
      return false;
    }
  }
  return true;
}

static inline bool access_page_valid(const uint8_t *page,
                                     const AccessLayout *layout) {
  if (!page || !layout || layout->page_size < 32) {
    return false;
  }

  if (page[0] == ACCESS_PAGE_INVALID) {
    return access_page_all_zero(page, layout->page_size);
  }

  const uint8_t page_type = page[0] & UINT8_C(0x07);

  if ((page[0] & UINT8_C(0xf8)) != 0
      && (page[0] & UINT8_C(0xf8)) != UINT8_C(0x08)) {
    return false;
  }
  if (page[1] != 1) {
    return false;
  }
  if (page_type == ACCESS_PAGE_DATA) {
    return access_data_page_valid(page, layout);
  }
  if (page_type == ACCESS_PAGE_TABLE_DEFINITION) {
    return access_page_pointer_valid(access_read_le32(page + 4), layout,
                                     true);
  }
  if (page_type == ACCESS_PAGE_USAGE_MAP) {
    return true;
  }
  if (page_type == ACCESS_PAGE_INDEX_NODE
      || page_type == ACCESS_PAGE_INDEX_LEAF) {
    const uint32_t prev_offset = layout->version == 0 ? 8 : 12;
    const uint32_t next_offset = layout->version == 0 ? 12 : 16;
    const uint32_t child_offset = layout->version == 0 ? 16 : 20;
    const uint32_t prefix_offset = layout->version == 0 ? 20 : 24;

    return access_read_le16(page + 2) <= layout->page_size
           && access_page_pointer_valid(access_read_le32(page + 4), layout,
                                     false)
           && access_page_pointer_valid(access_read_le32(page + prev_offset),
                                        layout, true)
           && access_page_pointer_valid(access_read_le32(page + next_offset),
                                        layout, true)
           && access_page_pointer_valid(access_read_le32(page + child_offset),
                                        layout, true)
           && access_read_le16(page + prefix_offset) <= layout->page_size;
  }
  return false;
}

// Every leaf-index entry ends with a three-byte data page number and a
// one-byte row number. Resolve those references against the candidate so an
// index page cannot authenticate unrelated data borrowed from another file.
//
static inline bool access_index_leaf_references_valid(
    const uint8_t *data, uint64_t length, AccessLayout *layout,
    uint32_t owner, const uint8_t *leaf, uint8_t *target) {
  if (!data || !layout || !leaf || !target) {
    return false;
  }
  const uint32_t mask_start = layout->version == 0 ? 0x16 : 0x1b;
  const uint32_t entry_base = layout->version == 0 ? 0xf8 : 0x1e0;
  uint32_t entry_start = entry_base;

  for (uint32_t relative = 1;
       relative <= layout->page_size - entry_base; relative++) {
    const uint32_t mask_byte = mask_start + relative / 8;
    const uint32_t mask_bit = relative & 7;

    if (mask_byte >= entry_base
        || (leaf[mask_byte] & (UINT8_C(1) << mask_bit)) == 0) {
      continue;
    }
    const uint32_t entry_end = entry_base + relative;

    if (entry_end < entry_start + 4 || entry_end > layout->page_size) {
      return false;
    }
    const uint32_t data_page = access_read_be24(leaf + entry_end - 4);
    const uint32_t row_number = leaf[entry_end - 1];

    if (!access_copy_page(data, length, layout, data_page, target)
        || (target[0] & UINT8_C(0x07)) != ACCESS_PAGE_DATA
        || access_read_le32(target + 4) != owner) {
      layout->repair_offset = (uint64_t)data_page * layout->page_size;
      return false;
    }
    const uint32_t row_count_offset = layout->version == 0 ? 8 : 12;

    if (row_number >= access_read_le16(target + row_count_offset)) {
      layout->repair_offset = (uint64_t)data_page * layout->page_size;
      return false;
    }
    entry_start = entry_end;
  }
  return true;
}

static inline bool access_page_relationship_valid(
    const uint8_t *data, uint64_t length, AccessLayout *layout,
    uint32_t page_number, const uint8_t *page, uint8_t *target) {
  if (!data || !layout || !page || !target) {
    return false;
  }

  const uint8_t page_type = page[0] & UINT8_C(0x07);
  const uint32_t owner = access_read_le32(page + 4);

  if (page_type == ACCESS_PAGE_DATA
      && owner != 0 && owner != ACCESS_LONG_VALUE_PAGE_MARKER) {
    if (!access_copy_page(data, length, layout, owner, target)
        || (target[0] & UINT8_C(0x07))
               != ACCESS_PAGE_TABLE_DEFINITION) {
      layout->failure_offset =
          (uint64_t)page_number * layout->page_size;
      layout->repair_offset = (uint64_t)owner * layout->page_size;
      return false;
    }
  }
  else if (page_type == ACCESS_PAGE_TABLE_DEFINITION && owner != 0) {
    if (!access_copy_page(data, length, layout, owner, target)
        || (target[0] & UINT8_C(0x07))
               != ACCESS_PAGE_TABLE_DEFINITION) {
      layout->failure_offset =
          (uint64_t)page_number * layout->page_size;
      layout->repair_offset = (uint64_t)owner * layout->page_size;
      return false;
    }
  }
  else if (page_type == ACCESS_PAGE_INDEX_NODE
           || page_type == ACCESS_PAGE_INDEX_LEAF) {
    if (!access_copy_page(data, length, layout, owner, target)
        || (target[0] & UINT8_C(0x07))
               != ACCESS_PAGE_TABLE_DEFINITION) {
      layout->failure_offset =
          (uint64_t)page_number * layout->page_size;
      layout->repair_offset = (uint64_t)owner * layout->page_size;
      return false;
    }

    const uint32_t prev_offset = layout->version == 0 ? 8 : 12;
    const uint32_t next_offset = layout->version == 0 ? 12 : 16;
    const uint32_t child_offset = layout->version == 0 ? 16 : 20;
    const uint32_t previous = access_read_le32(page + prev_offset);
    const uint32_t next = access_read_le32(page + next_offset);
    const uint32_t child = access_read_le32(page + child_offset);

    if (previous != 0
        && (!access_copy_page(data, length, layout, previous, target)
            || ((target[0] & UINT8_C(0x07)) != ACCESS_PAGE_INDEX_NODE
                && (target[0] & UINT8_C(0x07))
                       != ACCESS_PAGE_INDEX_LEAF)
            || access_read_le32(target + next_offset) != page_number)) {
      layout->failure_offset =
          (uint64_t)page_number * layout->page_size;
      layout->repair_offset = (uint64_t)previous * layout->page_size;
      return false;
    }
    if (next != 0
        && (!access_copy_page(data, length, layout, next, target)
            || ((target[0] & UINT8_C(0x07)) != ACCESS_PAGE_INDEX_NODE
                && (target[0] & UINT8_C(0x07))
                       != ACCESS_PAGE_INDEX_LEAF)
            || access_read_le32(target + prev_offset) != page_number)) {
      layout->failure_offset =
          (uint64_t)page_number * layout->page_size;
      layout->repair_offset = (uint64_t)next * layout->page_size;
      return false;
    }
    if (child != 0
        && (!access_copy_page(data, length, layout, child, target)
            || ((target[0] & UINT8_C(0x07)) != ACCESS_PAGE_INDEX_NODE
                && (target[0] & UINT8_C(0x07))
                       != ACCESS_PAGE_INDEX_LEAF))) {
      layout->failure_offset =
          (uint64_t)page_number * layout->page_size;
      layout->repair_offset = (uint64_t)child * layout->page_size;
      return false;
    }
    if (page_type == ACCESS_PAGE_INDEX_LEAF) {
      layout->repair_offset =
          (uint64_t)page_number * layout->page_size;
    }
    if (page_type == ACCESS_PAGE_INDEX_LEAF
        && !access_index_leaf_references_valid(
               data, length, layout, owner, page, target)) {
      layout->failure_offset =
          (uint64_t)page_number * layout->page_size;
      return false;
    }
  }
  return true;
}

// Cross-check page relationships after individual page validation. These
// links distinguish pages belonging to one database from structurally valid
// pages borrowed from another Jet or ACE file.
//
static inline bool access_page_relationships_valid(
    const uint8_t *data, uint64_t length, AccessLayout *layout,
    uint8_t *page) {
  if (!data || !layout || !page || !layout->used_pages) {
    return false;
  }
  uint8_t *target = (uint8_t *)malloc(layout->page_size);

  check_memory_allocation(target, __LINE__, __FILE__,
                          "Access relationship target page");

  for (uint32_t page_number = 2;
       page_number <= layout->highest_used_page; page_number++) {
    if (!layout->used_pages[page_number]) {
      continue;
    }
    if (!access_copy_page(data, length, layout, page_number, page)) {
      layout->failure_offset = (uint64_t)page_number * layout->page_size;
      layout->repair_offset = layout->failure_offset;
      free(target);
      return false;
    }
    if (!access_page_relationship_valid(
            data, length, layout, page_number, page, target)) {
      free(target);
      return false;
    }
  }
  free(target);
  return true;
}

// Free database pages can retain stale rows and page links, so they cannot be
// held to the allocated-page checks above. Their page headers still provide a
// conservative way to retain contiguous allocation slack at the physical tail.
//
static inline bool access_page_plausible(const uint8_t *page,
                                         const AccessLayout *layout) {
  if (!page || !layout || layout->page_size < 32) {
    return false;
  }
  if (page[0] == ACCESS_PAGE_INVALID) {
    return access_page_all_zero(page, layout->page_size);
  }

  const uint8_t page_type = page[0] & UINT8_C(0x07);
  const uint8_t page_flags = page[0] & UINT8_C(0xf8);

  return (page_type >= ACCESS_PAGE_DATA
          && page_type <= ACCESS_PAGE_USAGE_MAP
          && (page_flags == 0 || page_flags == UINT8_C(0x08))
          && page[1] == 1
          && access_read_le16(page + 2) <= layout->page_size)
         || (page[0] == UINT8_C(0x08) && page[1] == 1
             && access_read_le16(page + 2) <= layout->page_size);
}

static inline void access_extend_contiguous_extent(
    const uint8_t *data, uint64_t length, AccessLayout *layout,
    uint8_t *scratch) {
  if (!data || !layout || !scratch || !layout->used_pages) {
    return;
  }

  uint32_t last_nonzero_page = layout->highest_used_page;

  for (uint32_t page_number = layout->highest_used_page + 1;
       page_number < layout->available_pages; page_number++) {
    if (!access_copy_page(data, length, layout, page_number, scratch)
        || !access_page_plausible(scratch, layout)) {
      break;
    }
    if (!access_page_all_zero(scratch, layout->page_size)) {
      last_nonzero_page = page_number;
    }
  }

  const uint64_t contiguous_extent =
      ((uint64_t)last_nonzero_page + 1) * layout->page_size;

  if (contiguous_extent > layout->inferred_size) {
    layout->inferred_size = contiguous_extent;
  }
}

static inline bool access_contains_utf16le(const uint8_t *data,
                                           uint64_t length,
                                           const char *text) {
  if (!data || !text) {
    return false;
  }
  const uint64_t text_length = strlen(text);

  if (text_length == 0 || text_length > length / 2) {
    return false;
  }
  for (uint64_t offset = 0; offset + text_length * 2 <= length; offset++) {
    bool matches = true;

    for (uint64_t index = 0; index < text_length; index++) {
      if (data[offset + index * 2] != (uint8_t)text[index]
          || data[offset + index * 2 + 1] != 0) {
        matches = false;
        break;
      }
    }
    if (matches) {
      return true;
    }
  }
  return false;
}

static inline void access_note_semantics(const uint8_t *page,
                                         const AccessLayout *layout,
                                         uint32_t *project_evidence) {
  if (!page || !layout || !project_evidence) {
    return;
  }
  if (access_contains_utf16le(page, layout->page_size, "MSP_PROJECTS")) {
    *project_evidence |= UINT32_C(1) << 0;
  }
  if (access_contains_utf16le(page, layout->page_size, "MSP_TASKS")) {
    *project_evidence |= UINT32_C(1) << 1;
  }
  if (access_contains_utf16le(page, layout->page_size, "MSP_RESOURCES")) {
    *project_evidence |= UINT32_C(1) << 2;
  }
  if (access_contains_utf16le(page, layout->page_size,
                              "Project_Information")) {
    *project_evidence |= UINT32_C(1) << 3;
  }
  if (access_contains_utf16le(page, layout->page_size,
                              "Task_Information")) {
    *project_evidence |= UINT32_C(1) << 4;
  }
  if (access_contains_utf16le(page, layout->page_size,
                              "Resource_Information")) {
    *project_evidence |= UINT32_C(1) << 5;
  }
}

static inline bool access_inline_global_map(const uint8_t *row,
                                            uint64_t row_length,
                                            AccessLayout *layout) {
  if (!row || !layout || row_length < 6
      || row[0] != ACCESS_MAP_INLINE) {
    return false;
  }
  const uint32_t start_page = access_read_le32(row + 1);
  const uint64_t map_bits = (row_length - 5) * 8;

  for (uint64_t bit = 0; bit < map_bits; bit++) {
    const uint64_t page_number = (uint64_t)start_page + bit;

    if ((row[5 + bit / 8] & (UINT8_C(1) << (bit & 7))) != 0) {
      continue;
    }
    if (page_number >= UINT32_MAX) {
      layout->required_pages = UINT32_MAX;
      continue;
    }
    if (page_number + 1 > layout->required_pages) {
      layout->required_pages = (uint32_t)(page_number + 1);
    }
    if (page_number >= layout->available_pages) {
      continue;
    }
    layout->used_pages[page_number] = 1;
    if (page_number > layout->highest_used_page) {
      layout->highest_used_page = (uint32_t)page_number;
    }
  }
  return true;
}

static inline bool access_reference_global_map(
    const uint8_t *data, uint64_t length, const uint8_t *row,
    uint64_t row_length, AccessLayout *layout, uint8_t *scratch) {
  if (!data || !row || !layout || !scratch || row_length < 5
      || row[0] != ACCESS_MAP_REFERENCE) {
    return false;
  }
  const uint64_t pointer_count = (row_length - 1) / 4;
  const uint64_t bits_per_page = (layout->page_size - 4) * 8;

  for (uint64_t pointer_index = 0; pointer_index < pointer_count;
       pointer_index++) {
    const uint32_t map_page = access_read_le32(
        row + 1 + pointer_index * 4);

    if ((int32_t)map_page <= 0) {
      continue;
    }
    if (map_page + 1 > layout->required_pages) {
      layout->required_pages = map_page + 1;
    }
    if (map_page >= layout->available_pages) {
      continue;
    }
    if (!access_copy_page(data, length, layout, map_page, scratch)
        || scratch[0] != ACCESS_PAGE_USAGE_MAP || scratch[1] != 1) {
      layout->failure_offset = (uint64_t)map_page * layout->page_size;
      layout->repair_offset = layout->failure_offset;
      return false;
    }
    layout->used_pages[map_page] = 1;
    if (map_page > layout->highest_used_page) {
      layout->highest_used_page = map_page;
    }

    for (uint64_t bit = 0; bit < bits_per_page; bit++) {
      const uint64_t page_number = pointer_index * bits_per_page + bit;

      if ((scratch[4 + bit / 8]
           & (UINT8_C(1) << (bit & 7))) != 0) {
        continue;
      }
      if (page_number + 1 > layout->required_pages) {
        layout->required_pages = (uint32_t)(page_number + 1);
      }
      if (page_number >= layout->available_pages) {
        continue;
      }
      layout->used_pages[page_number] = 1;
      if (page_number > layout->highest_used_page) {
        layout->highest_used_page = (uint32_t)page_number;
      }
    }
  }
  return true;
}

static inline bool access_parse_global_map(const uint8_t *data,
                                           uint64_t length,
                                           AccessLayout *layout,
                                           uint8_t *scratch) {
  if (!access_copy_page(data, length, layout, 1, scratch)
      || scratch[0] != ACCESS_PAGE_DATA || scratch[1] != 1) {
    layout->failure_offset = layout->page_size;
    layout->repair_offset = layout->failure_offset;
    return false;
  }

  const uint32_t row_count_offset = layout->version == 0 ? 8 : 12;
  const uint32_t row_offset = layout->version == 0 ? 10 : 14;
  const uint32_t row_count = access_read_le16(scratch + row_count_offset);

  if (row_count == 0 || row_count > ACCESS_MAXIMUM_ROWS_PER_PAGE
      || (uint64_t)row_offset + (uint64_t)row_count * 2
             > layout->page_size) {
    layout->failure_offset = layout->page_size + row_count_offset;
    layout->repair_offset = layout->page_size;
    return false;
  }

  const uint32_t row_start = access_read_le16(
      scratch + row_offset) & ACCESS_ROW_OFFSET_MASK;

  if (row_start < row_offset + row_count * 2
      || row_start >= layout->page_size) {
    layout->failure_offset = layout->page_size + row_offset;
    layout->repair_offset = layout->page_size;
    return false;
  }
  const uint8_t *row = scratch + row_start;
  const uint64_t row_length = layout->page_size - row_start;

  if (row[0] == ACCESS_MAP_INLINE) {
    return access_inline_global_map(row, row_length, layout);
  }
  if (row[0] == ACCESS_MAP_REFERENCE) {
    uint8_t *map_page = (uint8_t *)malloc(layout->page_size);

    check_memory_allocation(map_page, __LINE__, __FILE__,
                            "Access usage map page");
    const bool valid = access_reference_global_map(
        data, length, row, row_length, layout, map_page);
    free(map_page);
    return valid;
  }
  layout->failure_offset = layout->page_size + row_start;
  layout->repair_offset = layout->page_size;
  return false;
}

// The global usage map identifies every allocated page needed to open the
// database. Free pages after the highest allocated page are allocation slack,
// not recoverable file content once filesystem metadata is unavailable.
//
static inline bool access_parse(const uint8_t *data, uint64_t length,
                                AccessLayout *layout) {
  if (!layout) {
    return false;
  }
  memset(layout, 0, sizeof(*layout));
  if (!access_header_parse(data, length, layout)) {
    return false;
  }
  if (layout->unsupported_encoding) {
    layout->failure_offset = layout->page_size;
    layout->repair_offset = layout->failure_offset;
    return false;
  }
  if (length < (uint64_t)layout->page_size * 2
      || length > ACCESS_MAXIMUM_DATABASE_SIZE) {
    layout->failure_offset = length;
    layout->repair_offset = layout->failure_offset;
    return false;
  }

  const uint64_t available_pages = length / layout->page_size;

  if (available_pages < 2 || available_pages > UINT32_MAX) {
    layout->failure_offset = length;
    layout->repair_offset = layout->failure_offset;
    return false;
  }
  layout->available_pages = (uint32_t)available_pages;
  layout->used_pages = (uint8_t *)calloc(layout->available_pages, 1);
  check_memory_allocation(layout->used_pages, __LINE__, __FILE__,
                          "Access used page map");
  layout->used_pages[0] = 1;
  layout->used_pages[1] = 1;
  layout->required_pages = 2;
  layout->highest_used_page = 1;

  uint8_t *scratch = (uint8_t *)malloc(layout->page_size);
  check_memory_allocation(scratch, __LINE__, __FILE__,
                          "Access page scratch");

  if (!access_parse_global_map(data, length, layout, scratch)) {
    free(scratch);
    return false;
  }
  layout->inferred_size = (uint64_t)layout->required_pages
                          * layout->page_size;

  uint32_t project_evidence = 0;

  for (uint32_t page_number = 1;
       page_number <= layout->highest_used_page; page_number++) {
    if (!layout->used_pages[page_number]) {
      continue;
    }
    if (!access_copy_page(data, length, layout, page_number, scratch)
        || !access_page_valid(scratch, layout)) {
      layout->failure_offset = (uint64_t)page_number * layout->page_size;
      layout->repair_offset = layout->failure_offset;
      free(scratch);
      return false;
    }
    access_note_semantics(scratch, layout, &project_evidence);
  }
  if (layout->required_pages > layout->available_pages) {
    layout->failure_offset = (uint64_t)layout->available_pages
                             * layout->page_size;
    layout->repair_offset = layout->failure_offset;
    free(scratch);
    return false;
  }
  if (!access_page_relationships_valid(data, length, layout, scratch)) {
    free(scratch);
    return false;
  }
  access_extend_contiguous_extent(data, length, layout, scratch);
  free(scratch);
  const uint32_t modern_project_evidence = project_evidence & UINT32_C(0x07);
  const uint32_t legacy_project_evidence =
      (project_evidence >> 3) & UINT32_C(0x07);

  if ((modern_project_evidence
       & (modern_project_evidence - UINT32_C(1))) != 0
      || (legacy_project_evidence
          & (legacy_project_evidence - UINT32_C(1))) != 0) {
    layout->profile = ACCESS_PROFILE_MPD;
  }
  layout->failure_offset = layout->inferred_size;
  layout->repair_offset = layout->inferred_size;
  return true;
}

static inline char *access_header_discovery(
    char *base, uint64_t offset, uint64_t remaining, char **matchpos,
    uint32_t *matchlen, uint32_t blocksize) {
  (void)blocksize;
  if (!base || !matchpos || !matchlen) {
    return NULL;
  }
  *matchpos = NULL;
  *matchlen = 20;
  const uint8_t *region = (const uint8_t *)base + offset;
  uint64_t searched = 0;

  while (searched + 20 <= remaining) {
    const uint8_t *candidate = memchr(region + searched, 0,
                                      (size_t)(remaining - searched - 19));

    if (!candidate) {
      break;
    }
    const uint64_t position = (uint64_t)(candidate - region);
    AccessLayout layout;

    if (access_header_parse(candidate, remaining - position, &layout)) {
      *matchpos = (char *)candidate;
      return NULL;
    }
    searched = position + 1;
  }
  return NULL;
}

static inline char *access_no_header_discovery(
    char *base, uint64_t offset, uint64_t remaining, char **matchpos,
    uint32_t *matchlen, uint32_t blocksize) {
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

static inline uint32_t access_block_validate(
    char *data, uint64_t length, BlockValidationDecision *decision,
    uint64_t *validates_to, uint32_t needleidx, uint32_t blocksize,
    void *blockhashkey) {
  (void)blockhashkey;
  (void)blocksize;
  if (!data || !decision || !validates_to || length == 0) {
    return needleidx;
  }
  *validates_to = length - 1;
  if (*decision == BLOCK_CONFIDENCE_INVALID) {
    *decision = BLOCK_CONFIDENCE_LOW;
  }
  if (scalpel_state.no_defrag) {
    return needleidx;
  }

  AccessLayout layout;

  if (access_header_parse((const uint8_t *)data, length, &layout)) {
    *decision = BLOCK_CONFIDENCE_VALID;
    return needleidx;
  }

  uint32_t evidence = 0;
  // Jet pages are 2048 bytes and ACE pages are 4096 bytes. Scan at the smaller
  // alignment and accept either page limit so isolated sub-page Scalpel blocks
  // can recognize an ACE header without having the database header in hand.
  const uint32_t stride = ACCESS_JET3_PAGE_SIZE;

  for (uint64_t offset = 0; offset + 32 <= length; offset += stride) {
    const uint8_t *page = (const uint8_t *)data + offset;

    const uint8_t page_type = page[0] & UINT8_C(0x07);

    const bool typed_page = page_type >= ACCESS_PAGE_DATA
        && page_type <= ACCESS_PAGE_USAGE_MAP
        && ((page[0] & UINT8_C(0xf8)) == 0
            || (page[0] & UINT8_C(0xf8)) == UINT8_C(0x08));
    const bool opaque_page = page[0] == UINT8_C(0x08);

    if ((typed_page || opaque_page) && page[1] == 1
        && access_read_le16(page + 2) <= ACCESS_JET4_PAGE_SIZE) {
      evidence++;
    }
  }
  if (evidence != 0 && *decision < ACCESS_BLOCK_CONFIDENCE) {
    *decision = (BlockValidationDecision)ACCESS_BLOCK_CONFIDENCE;
  }
  return needleidx;
}

static inline void access_file_validate(char *data, uint64_t length,
                                        bool *validates,
                                        uint64_t *validates_to,
                                        bool *promising,
                                        uint32_t needleidx,
                                        uint32_t blocksize,
                                        void *carvehashkey) {
  (void)needleidx;
  (void)carvehashkey;
  if (!validates || !validates_to || !promising) {
    return;
  }
  *validates = false;
  *validates_to = 0;
  *promising = false;

  AccessLayout layout;

  if (!access_header_parse((const uint8_t *)data, length, &layout)) {
    return;
  }
  const bool valid = access_parse((const uint8_t *)data, length, &layout);

  if (valid) {
    *validates_to = layout.inferred_size - 1;
    // Jet and ACE allocation structures do not authenticate opaque row data
    // or free-page contents. Accept the complete structure under an explicit
    // contiguous-only assumption; otherwise retain it for independent review.
    if (scalpel_state.no_defrag) {
      *validates = true;
    }
    else {
      *promising = true;
    }
  }
  else {
    *promising = true;
    if (blocksize != 0 && layout.failure_offset >= blocksize) {
      *validates_to = (layout.failure_offset / blocksize) * blocksize - 1;
    }
    else {
      *validates_to = 19;
    }
    if (*validates_to >= length) {
      *validates_to = length - 1;
    }
  }
  access_layout_clear(&layout);
}

static inline const char *access_profile_filetype(AccessProfile profile) {
  switch (profile) {
  case ACCESS_PROFILE_MDB:
    return "mdb";
  case ACCESS_PROFILE_ACCDB:
    return "accdb";
  case ACCESS_PROFILE_MPD:
    return "mpd";
  case ACCESS_PROFILE_UNKNOWN:
  default:
    return "access";
  }
}

static inline void access_assign_candidate_profile(CarveInfo *candidate,
                                                   AccessProfile profile) {
  if (!candidate) {
    return;
  }
  const char *filetype = access_profile_filetype(profile);

  if (strcmp(filetype, "access") == 0) {
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

static inline void access_candidate_classify(CarveInfo *candidate,
                                             bool *validates,
                                             uint64_t *validates_to,
                                             bool *promising) {
  (void)validates_to;
  (void)promising;
  if (!candidate || !candidate->b || !validates || !*validates) {
    return;
  }

  AccessLayout layout;
  const uint8_t *data = (const uint8_t *)blockvector_get_data_pointer(
      candidate->b);
  const uint64_t length = blockvector_get_data_length(candidate->b);

  if (access_parse(data, length, &layout)) {
    access_assign_candidate_profile(candidate, layout.profile);
  }
  access_layout_clear(&layout);
}

static inline bool access_candidate_is_contiguous(
    const CarveInfo *candidate) {
  if (!candidate || !candidate->b) {
    return false;
  }

  const uint64_t blocks = blockvector_get_num_blocks(candidate->b);

  if (blocks < 2) {
    return true;
  }
  const int64_t first = blockvector_get_actual_blocknumber(candidate->b, 0);

  if (first < 0) {
    return false;
  }
  for (uint64_t slot = 1; slot < blocks; slot++) {
    if (blockvector_get_actual_blocknumber(candidate->b, slot)
        != first + (int64_t)slot) {
      return false;
    }
  }
  return true;
}

// Keep whole-image reconstruction searches responsive to queue shutdown and
// checkpoint requests without exposing partially tested mappings.
//
static inline bool access_reassembly_poll(ThreadWork *work,
                                          CarveInfo **candidate,
                                          uuid_string_t uuidp,
                                          uuid_string_t uuidc,
                                          uint64_t *iterations, AccessCarveState *state) {
  if (!work || !candidate || !*candidate || !iterations) {
    return true;
  }
  (*iterations)++;
  const bool return_to_idle = atomic_load_explicit(
      &REASS_RETURN_TO_IDLE, memory_order_acquire);

  if (!return_to_idle
      && *iterations % ACCESS_REASSEMBLY_POLL_INTERVAL != 0) {
    return false;
  }
  if (reassembly_check_kill_queue(work, candidate, uuidp, uuidc)) {
    return true;
  }
  if (return_to_idle) {
    access_search_save(*candidate, state);
    if (reassembly_time_to_checkpoint(work->id, *candidate, uuidp, uuidc)) {
      return true;
    }
  }
  return false;
}

// Confirm that a physical run is still available and does not reuse a block
// already present in the retained prefix or in another run in the trial.
//
static inline bool access_reassembly_range_available(
    const CarveInfo *candidate, int64_t first, uint64_t count,
    uint64_t protected_prefix_blocks,
    int64_t excluded_first, uint64_t excluded_count) {
  if (!candidate || !candidate->b || first < 0) {
    return false;
  }
  if (count == 0) {
    return true;
  }
  const uint64_t image_blocks =
      filemirror_apparent_blocks(scalpel_state.filemirror);
  const uint64_t start = (uint64_t)first;

  if (start >= image_blocks || count > image_blocks - start) {
    return false;
  }
  if (excluded_first >= 0 && excluded_count != 0) {
    const uint64_t excluded_start = (uint64_t)excluded_first;
    const uint64_t end = start + count;
    const uint64_t excluded_end = excluded_start + excluded_count;

    if (start < excluded_end && excluded_start < end) {
      return false;
    }
  }
  const uint64_t candidate_blocks =
      blockvector_get_num_blocks(candidate->b);

  if (protected_prefix_blocks > candidate_blocks) {
    protected_prefix_blocks = candidate_blocks;
  }
  for (uint64_t offset = 0; offset < count; offset++) {
    const int64_t apparent = first + (int64_t)offset;
    const int64_t actual = filemirror_actual_blocknumber(
        scalpel_state.filemirror, apparent);

    if (actual < 0
        || filemirror_actual_block_covered(
               scalpel_state.filemirror, actual)) {
      return false;
    }
    for (uint64_t slot = 0; slot < protected_prefix_blocks; slot++) {
      if (blockvector_get_apparent_blocknumber(candidate->b, slot)
          == apparent) {
        return false;
      }
    }
  }
  return true;
}

// A relocated extent is stronger when the blocks immediately outside it do
// not look like a continuation of the same file type. This is ranking evidence,
// not an exclusion rule; low-confidence blocks remain eligible inside a run.
//
static inline bool access_reassembly_boundary_separated(
    const CarveInfo *candidate, int64_t apparent) {
  if (!candidate || apparent < 0
      || (uint64_t)apparent
             >= filemirror_apparent_blocks(scalpel_state.filemirror)) {
    return true;
  }
  const int64_t actual = filemirror_actual_blocknumber(
      scalpel_state.filemirror, apparent);

  if (actual < 0
      || filemirror_actual_block_covered(scalpel_state.filemirror, actual)) {
    return true;
  }
  return filemirror_get_blocktype(
             scalpel_state.filemirror, actual, candidate->needleidx)
         < ACCESS_BLOCK_CONFIDENCE;
}

// Rank a run by its weakest block. Low-confidence blocks remain eligible, but
// a complete reconstruction supported by format evidence is preferred over an
// otherwise equal reconstruction assembled from structurally opaque blocks.
//
static inline BlockValidationDecision access_reassembly_run_confidence(
    const CarveInfo *candidate, int64_t first, uint64_t count) {
  if (!candidate || first < 0 || count == 0) {
    return BLOCK_CONFIDENCE_INVALID;
  }
  BlockValidationDecision confidence = BLOCK_CONFIDENCE_VALID;

  for (uint64_t offset = 0; offset < count; offset++) {
    const int64_t apparent = first + (int64_t)offset;
    const int64_t actual = filemirror_actual_blocknumber(
        scalpel_state.filemirror, apparent);

    if (actual < 0) {
      return BLOCK_CONFIDENCE_INVALID;
    }
    const BlockValidationDecision block_confidence =
        filemirror_get_blocktype(
            scalpel_state.filemirror, actual, candidate->needleidx);

    if (block_confidence < confidence) {
      confidence = block_confidence;
    }
  }
  return confidence;
}

static inline int64_t access_reassembly_run_reservations(
    int64_t first, uint64_t count) {
  if (!scalpel_state.reservations || first < 0 || count == 0) {
    return 0;
  }
  int64_t total = 0;

  for (uint64_t offset = 0; offset < count; offset++) {
    if (offset > (uint64_t)(INT64_MAX - first)) {
      return INT64_MAX;
    }
    const int64_t apparent = first + (int64_t)offset;
    const int64_t actual = filemirror_actual_blocknumber(
        scalpel_state.filemirror, apparent);
    const int64_t reserved = actual < 0 ? 0
        : filemirror_actual_block_reserved(
              scalpel_state.filemirror, actual);

    if (reserved > 0) {
      if (total > INT64_MAX - reserved) {
        return INT64_MAX;
      }
      total += reserved;
    }
  }
  return total;
}

static inline int access_reassembly_compare_run_rank(
    const AccessRunRank *first, const AccessRunRank *second) {
  if (!first || !second) {
    return 0;
  }
  if (first->confidence != second->confidence) {
    return first->confidence > second->confidence ? 1 : -1;
  }
  if (first->boundary_score != second->boundary_score) {
    return first->boundary_score > second->boundary_score ? 1 : -1;
  }
  if (first->structure_score != second->structure_score) {
    return first->structure_score > second->structure_score ? 1 : -1;
  }
  if (first->reservations != second->reservations) {
    return first->reservations < second->reservations ? 1 : -1;
  }
  return 0;
}

// Zero and confidence runs are unambiguous placement evidence only when their
// logical extent covers complete Access pages. Smaller Scalpel blocks can be
// zero or structurally opaque inside an otherwise valid database page.
//
static inline bool access_reassembly_span_covers_complete_pages(
    uint64_t first_block, uint64_t count, uint32_t page_size) {
  const uint64_t blocksize = scalpel_state.blocksize;

  if (blocksize == 0 || page_size == 0 || count == 0
      || first_block > UINT64_MAX / blocksize
      || count > UINT64_MAX / blocksize) {
    return false;
  }
  const uint64_t first_byte = first_block * blocksize;
  const uint64_t span_bytes = count * blocksize;

  return first_byte % page_size == 0 && span_bytes % page_size == 0;
}

// Reassembly needs the complete allocation map before all database pages have
// been reconstructed. The map is stored near the header and can therefore be
// decoded independently of the later pages that caused parser failure.
//
static inline bool access_reassembly_build_usage_layout(
    const uint8_t *data, uint64_t length, AccessLayout *layout) {
  if (!layout) {
    return false;
  }
  memset(layout, 0, sizeof(*layout));
  if (!access_header_parse(data, length, layout)
      || layout->unsupported_encoding || layout->page_size == 0) {
    return false;
  }
  const uint64_t available_pages = length / layout->page_size;

  if (available_pages < 2 || available_pages > UINT32_MAX) {
    return false;
  }
  layout->available_pages = (uint32_t)available_pages;
  layout->used_pages = (uint8_t *)calloc(layout->available_pages, 1);
  check_memory_allocation(layout->used_pages, __LINE__, __FILE__,
                          "Access reassembly usage map");
  layout->used_pages[0] = 1;
  layout->used_pages[1] = 1;
  layout->required_pages = 2;
  layout->highest_used_page = 1;

  uint8_t scratch[ACCESS_JET4_PAGE_SIZE];

  if (!access_parse_global_map(data, length, layout, scratch)) {
    access_layout_clear(layout);
    return false;
  }
  return true;
}

static inline bool access_reassembly_span_contains_allocated_page(
    uint64_t first_block, uint64_t count, const AccessLayout *layout) {
  if (!layout || !layout->used_pages
      || !access_reassembly_span_covers_complete_pages(
             first_block, count, layout->page_size)) {
    return false;
  }
  const uint64_t blocksize = scalpel_state.blocksize;
  const uint64_t first_page = first_block * blocksize / layout->page_size;
  const uint64_t page_count = count * blocksize / layout->page_size;

  if (first_page > layout->available_pages
      || page_count > layout->available_pages - first_page) {
    return false;
  }
  for (uint64_t page = first_page;
       page < first_page + page_count; page++) {
    if (layout->used_pages[page] != 0) {
      return true;
    }
  }
  return false;
}

// Copy a physical run into its proposed logical position in a complete trial
// image. Short terminal image blocks are zero padded just as blockvectors are.
//
static inline bool access_reassembly_copy_run(
    uint8_t *data, uint64_t data_length, uint64_t destination_slot,
    int64_t source_first, uint64_t count) {
  if (!data || source_first < 0 || scalpel_state.blocksize == 0) {
    return false;
  }
  const uint64_t blocksize = scalpel_state.blocksize;

  for (uint64_t offset = 0; offset < count; offset++) {
    if (destination_slot + offset > UINT64_MAX / blocksize) {
      return false;
    }
    const uint64_t destination = (destination_slot + offset) * blocksize;

    if (destination >= data_length) {
      return false;
    }
    const int64_t apparent = source_first + (int64_t)offset;
    const int64_t actual = filemirror_actual_blocknumber(
        scalpel_state.filemirror, apparent);
    uint64_t source_length = 0;
    const uint8_t *source = (const uint8_t *)
        filemirror_actual_block_data_pointer(
            scalpel_state.filemirror, actual, &source_length);
    const uint64_t destination_length =
        data_length - destination < blocksize
            ? data_length - destination : blocksize;

    if (!source || source_length == 0) {
      return false;
    }
    const uint64_t copy_length = source_length < destination_length
                                     ? source_length : destination_length;

    memcpy(data + destination, source, (size_t)copy_length);
    if (copy_length < destination_length) {
      memset(data + destination + copy_length, 0,
             (size_t)(destination_length - copy_length));
    }
  }
  return true;
}

// Rank a proposed run using page structure even when the database allocation
// map marks the corresponding logical pages free. Full LVAL continuation pages
// carry the next logical page number, which is stronger placement evidence than
// a generic page header. A mismatch lowers rank but never excludes the run.
//
static inline uint32_t access_reassembly_run_structure_score(
    const uint8_t *data, uint64_t length, AccessLayout *layout,
    uint64_t first_byte, uint64_t range_length, uint8_t *scratch) {
  if (!data || !layout || !scratch || layout->page_size == 0
      || range_length == 0 || first_byte >= length) {
    return 0;
  }
  const uint64_t available = length - first_byte;
  const uint64_t checked_length = range_length < available
                                      ? range_length : available;
  const uint64_t last_byte = first_byte + checked_length - 1;
  const uint64_t first_page = first_byte / layout->page_size;
  const uint64_t last_page = last_byte / layout->page_size;
  uint32_t run_score = UINT32_MAX;

  for (uint64_t page = first_page; page <= last_page; page++) {
    if (page >= layout->available_pages
        || !access_copy_page(
               data, length, layout, (uint32_t)page, scratch)) {
      return 0;
    }
    uint32_t page_score = access_page_plausible(scratch, layout) ? 1 : 0;

    if (access_page_valid(scratch, layout)) {
      page_score = 2;
    }

    const uint8_t page_type = scratch[0] & UINT8_C(0x07);
    const uint32_t owner = access_read_le32(scratch + 4);

    if (page_type == ACCESS_PAGE_DATA
        && owner == ACCESS_LONG_VALUE_PAGE_MARKER
        && page_score >= 2) {
      page_score = 3;

      const uint32_t row_count_offset = layout->version == 0 ? 8 : 12;
      const uint32_t row_offset = layout->version == 0 ? 10 : 14;
      const uint32_t row_count = access_read_le16(
          scratch + row_count_offset);
      const uint32_t directory_end = row_offset + row_count * 2;
      const uint32_t free_space = access_read_le16(scratch + 2);

      if (row_count == 1 && free_space == 4
          && directory_end <= layout->page_size - 4) {
        const uint32_t row_start = access_read_le16(
            scratch + row_offset) & ACCESS_ROW_OFFSET_MASK;

        if (row_start == directory_end + 4
            && row_start <= layout->page_size - 4) {
          const uint32_t next = access_read_le32(scratch + row_start);
          const uint32_t next_page = next >> 8;
          const uint32_t next_row = next & UINT32_C(0xff);

          page_score = next_row == 0 && next_page == page + 1 ? 4 : 1;
        }
      }
    }
    if (page_score < run_score) {
      run_score = page_score;
    }
  }
  return run_score == UINT32_MAX ? 0 : run_score;
}

// Reject a trial when an allocated page touched by the proposed mapping fails
// the same page or relationship checks used by the complete parser. A caller can
// defer relationship checks until every range referenced by that page has been
// materialized. Unallocated pages remain unconstrained because they can retain
// stale data that is unrelated to the current database.
//
static inline bool access_reassembly_pages_valid(
    const uint8_t *data, uint64_t length, AccessLayout *layout,
    uint64_t first_byte, uint64_t range_length, uint8_t *scratch,
    uint8_t *target, bool relationships) {
  if (!data || !layout || !scratch || !target) {
    return false;
  }
  if (!layout->used_pages || layout->page_size == 0
      || range_length == 0 || first_byte >= length) {
    return true;
  }

  const uint64_t available = length - first_byte;
  const uint64_t checked_length = range_length < available
                                      ? range_length : available;
  const uint64_t last_byte = first_byte + checked_length - 1;
  const uint64_t first_page = first_byte / layout->page_size;
  const uint64_t last_page = last_byte / layout->page_size;

  for (uint64_t page = first_page; page <= last_page; page++) {
    if (page >= layout->available_pages) {
      return false;
    }
    if (!layout->used_pages[page]) {
      continue;
    }
    if (!access_copy_page(data, length, layout, (uint32_t)page, scratch)
        || !access_page_valid(scratch, layout)
        || (relationships
            && !access_page_relationship_valid(
                data, length, layout, (uint32_t)page, scratch, target))) {
      return false;
    }
  }
  return true;
}

// Compare the file bytes represented by two mappings. Different physical
// blocks are equivalent when they contribute identical bytes to the recovered
// file, including the zero padding used for a short terminal image block.
//
static inline bool access_reassembly_mappings_equal(
    const int64_t *first, const int64_t *second, uint64_t count,
    uint64_t data_length) {
  if (!first || !second || scalpel_state.blocksize == 0) {
    return false;
  }
  const uint64_t blocksize = scalpel_state.blocksize;

  for (uint64_t slot = 0; slot < count; slot++) {
    if (first[slot] == second[slot]) {
      continue;
    }
    if (slot > UINT64_MAX / blocksize) {
      return false;
    }
    const uint64_t destination = slot * blocksize;

    if (destination >= data_length) {
      break;
    }
    const uint64_t compare_length =
        data_length - destination < blocksize
            ? data_length - destination : blocksize;
    const int64_t first_actual = filemirror_actual_blocknumber(
        scalpel_state.filemirror, first[slot]);
    const int64_t second_actual = filemirror_actual_blocknumber(
        scalpel_state.filemirror, second[slot]);
    uint64_t first_length = 0;
    uint64_t second_length = 0;
    const uint8_t *first_data = (const uint8_t *)
        filemirror_actual_block_data_pointer(
            scalpel_state.filemirror, first_actual, &first_length);
    const uint8_t *second_data = (const uint8_t *)
        filemirror_actual_block_data_pointer(
            scalpel_state.filemirror, second_actual, &second_length);

    if (!first_data || !second_data) {
      return false;
    }
    if (first_length > compare_length) {
      first_length = compare_length;
    }
    if (second_length > compare_length) {
      second_length = compare_length;
    }
    const uint64_t common_length = first_length < second_length
                                       ? first_length : second_length;

    if (common_length != 0
        && memcmp(first_data, second_data, (size_t)common_length) != 0) {
      return false;
    }
    uint8_t nonzero = 0;

    for (uint64_t offset = common_length; offset < first_length; offset++) {
      nonzero |= first_data[offset];
    }
    for (uint64_t offset = common_length; offset < second_length; offset++) {
      nonzero |= second_data[offset];
    }
    if (nonzero != 0) {
      return false;
    }
  }
  return true;
}

static inline bool access_reassembly_parse_trial(
    uint8_t *data, uint64_t length, bool *valid,
    uint64_t *progress, uint64_t *repair_offset,
    AccessProfile *profile) {
  if (!data || !valid || !progress || !repair_offset || !profile) {
    return false;
  }
  AccessLayout layout;

  *valid = access_parse(data, length, &layout);
  *progress = *valid ? layout.inferred_size : layout.failure_offset;
  *repair_offset = *valid ? layout.inferred_size : layout.repair_offset;
  *profile = layout.profile;
  access_layout_clear(&layout);
  return true;
}

static inline void access_reassembly_fill_prefix_mapping(
    const CarveInfo *candidate, int64_t *mapping, uint64_t count) {
  if (!candidate || !candidate->b || !mapping) {
    return;
  }
  for (uint64_t slot = 0; slot < count; slot++) {
    mapping[slot] = blockvector_get_apparent_blocknumber(candidate->b, slot);
  }
}

// Install and revalidate a complete mapping before publishing it. Noncontiguous
// Access recovery remains PROMISING because page structure supplies strong
// consistency evidence but no whole-file cryptographic integrity check.
//
static inline bool access_reassembly_commit_mapping(
    CarveInfo *candidate, const int64_t *mapping, uint64_t total_blocks,
    uint64_t length, AccessProfile *profile) {
  if (!candidate || !candidate->b || !mapping || !profile
      || total_blocks == 0 || length == 0) {
    return false;
  }
  resize_blockvector(candidate->b, total_blocks);
  for (uint64_t slot = 0; slot < total_blocks; slot++) {
    blockvector_set_apparent_blocknumber(candidate->b, slot, mapping[slot]);
  }
  blockvector_set_data_length(candidate->b, length);
  normalize_blockvector(candidate->b);
  inflate_blockvector(candidate->b);

  AccessLayout layout;
  const bool valid = access_parse(
      (const uint8_t *)blockvector_get_data_pointer(candidate->b),
      blockvector_get_data_length(candidate->b), &layout);

  if (!valid) {
    access_layout_clear(&layout);
    return false;
  }
  // A complete Jet or ACE mapping can contain trailing allocation-slack pages
  // that are not referenced by an internal table. The complete parser has
  // validated the requested trial, so retain its represented length.
  const uint64_t final_length = length;

  *profile = layout.profile;
  access_layout_clear(&layout);
  blockvector_set_data_length(candidate->b, final_length);
  resize_blockvector(candidate->b,
                     CEILDIV(final_length, scalpel_state.blocksize));
  candidate->best_validates_to = final_length - 1;
  return true;
}

// Extend a structurally complete database through physically adjacent,
// nonzero allocation-slack pages. A zero page is treated as a physical file
// boundary because it cannot be distinguished safely from external padding.
// The candidate is kept in a parser-valid state before every checkpoint poll.
//
static inline AccessRecoveryResult access_reassembly_extend_contiguous_tail(
    ThreadWork *work, CarveInfo **candidate, uuid_string_t uuidp,
    uuid_string_t uuidc, AccessProfile *profile, AccessCarveState *state) {
  if (!work || !candidate || !*candidate || !(*candidate)->b || !profile
      || scalpel_state.blocksize == 0) {
    return ACCESS_RECOVERY_NO_MATCH;
  }

  BlockVector *blockvector = (*candidate)->b;
  AccessLayout layout;
  const bool initially_valid = access_parse(
      (const uint8_t *)blockvector_get_data_pointer(blockvector),
      blockvector_get_data_length(blockvector), &layout);

  if (!initially_valid || layout.page_size == 0
      || layout.inferred_size == 0) {
    access_layout_clear(&layout);
    return ACCESS_RECOVERY_NO_MATCH;
  }

  AccessSearchProgress *saved = &state->progress;
  if (!saved->tail_started) {
    saved->tail_started = true;
    saved->tail_initial_length = layout.inferred_size;
    saved->tail_accepted_length = layout.inferred_size;
    saved->tail_extended = false;
  }
  const uint64_t initial_length = saved->tail_initial_length;
  const uint64_t initial_blocks = CEILDIV(
      initial_length, scalpel_state.blocksize);
  uint64_t accepted_length = saved->tail_accepted_length;
  uint64_t accepted_blocks = CEILDIV(accepted_length, scalpel_state.blocksize);
  uint64_t iterations = 0;
  bool extended = saved->tail_extended;
  uint8_t *scratch = (uint8_t *)malloc(layout.page_size);

  check_memory_allocation(scratch, __LINE__, __FILE__,
                          "Access tail page");
  *profile = layout.profile;

  resize_blockvector(blockvector, accepted_blocks);
  blockvector_set_data_length(blockvector, accepted_length);
  normalize_blockvector(blockvector);
  inflate_blockvector(blockvector);

  while (*candidate) {
    const uint64_t page_size = layout.page_size;
    const uint64_t maximum_size =
        scalpel_state.search_specs[(*candidate)->needleidx].MAXIMUMSIZE;

    if (accepted_length > UINT64_MAX - page_size
        || accepted_length + page_size > maximum_size) {
      break;
    }
    const uint64_t probe_length = accepted_length + page_size;
    const uint64_t page_number = accepted_length / page_size;

    if (page_number > UINT32_MAX) {
      break;
    }
    const uint64_t needed_blocks = CEILDIV(
        probe_length, scalpel_state.blocksize);
    bool materialized = true;

    while (blockvector_get_num_blocks(blockvector) < needed_blocks) {
      const uint64_t current_blocks =
          blockvector_get_num_blocks(blockvector);
      const int64_t previous = blockvector_get_apparent_blocknumber(
          blockvector, current_blocks - 1);

      if (previous < 0 || previous == INT64_MAX
          || !access_reassembly_range_available(
              *candidate, previous + 1, 1, current_blocks, -1, 0)) {
        materialized = false;
        break;
      }
      resize_blockvector(blockvector, current_blocks + 1);
      blockvector_set_apparent_blocknumber(
          blockvector, current_blocks, previous + 1);
    }

    if (!materialized) {
      resize_blockvector(blockvector, accepted_blocks);
      blockvector_set_data_length(blockvector, accepted_length);
      normalize_blockvector(blockvector);
      inflate_blockvector(blockvector);
      break;
    }

    blockvector_set_data_length(blockvector, probe_length);
    normalize_blockvector(blockvector);
    inflate_blockvector(blockvector);
    layout.available_pages = (uint32_t)page_number + 1;

    const bool plausible = access_copy_page(
        (const uint8_t *)blockvector_get_data_pointer(blockvector),
        probe_length, &layout, (uint32_t)page_number, scratch)
        && access_page_plausible(scratch, &layout);
    const bool all_zero = plausible
        && access_page_all_zero(scratch, layout.page_size);

    if (all_zero && scalpel_state.write_promising
        && !access_candidate_is_contiguous(*candidate)) {
      int64_t *zero_tail_mapping = (int64_t *)malloc(
          needed_blocks * sizeof(*zero_tail_mapping));

      check_memory_allocation(zero_tail_mapping, __LINE__, __FILE__,
                              "Access zero-tail mapping");
      access_reassembly_fill_prefix_mapping(
          *candidate, zero_tail_mapping, needed_blocks);
      (void)access_reassembly_write_mapping_hypothesis(
          *candidate, zero_tail_mapping, needed_blocks,
          probe_length, *profile);
      free(zero_tail_mapping);
    }

    if (!plausible || all_zero) {
      resize_blockvector(blockvector, accepted_blocks);
      blockvector_set_data_length(blockvector, accepted_length);
      normalize_blockvector(blockvector);
      inflate_blockvector(blockvector);
      break;
    }

    accepted_length = probe_length;
    accepted_blocks = needed_blocks;
    extended = true;
    blockvector_set_data_length(blockvector, accepted_length);
    resize_blockvector(blockvector, accepted_blocks);
    normalize_blockvector(blockvector);
    inflate_blockvector(blockvector);
    (*candidate)->best_validates_to = accepted_length - 1;

    saved->tail_accepted_length = accepted_length;
    saved->tail_extended = extended;
    if (access_reassembly_poll(
            work, candidate, uuidp, uuidc, &iterations, state)) {
      free(scratch);
      access_layout_clear(&layout);
      return ACCESS_RECOVERY_INTERRUPTED;
    }
  }

  free(scratch);
  access_layout_clear(&layout);

  if (!extended || !*candidate) {
    return ACCESS_RECOVERY_NO_MATCH;
  }

  AccessLayout final_layout;
  const bool final_valid = access_parse(
      (const uint8_t *)blockvector_get_data_pointer(blockvector),
      blockvector_get_data_length(blockvector), &final_layout);

  if (!final_valid) {
    access_layout_clear(&final_layout);
    resize_blockvector(blockvector, initial_blocks);
    blockvector_set_data_length(blockvector, initial_length);
    normalize_blockvector(blockvector);
    inflate_blockvector(blockvector);
    (*candidate)->best_validates_to = initial_length - 1;
    return ACCESS_RECOVERY_NO_MATCH;
  }

  *profile = final_layout.profile;
  access_layout_clear(&final_layout);
  resize_blockvector(
      blockvector, CEILDIV(accepted_length, scalpel_state.blocksize));
  blockvector_set_data_length(blockvector, accepted_length);
  normalize_blockvector(blockvector);
  inflate_blockvector(blockvector);
  (*candidate)->best_validates_to = accepted_length - 1;
  return ACCESS_RECOVERY_MATCH;
}

// Publish a complete mapping without replacing the live recovery candidate.
// Access page relationships can prove structural consistency without proving
// which of several byte-distinct allocation-slack pages is the original one.
// Such alternatives remain PROMISING for independent verification.
//
static inline bool access_reassembly_write_mapping_hypothesis(
    CarveInfo *candidate, const int64_t *mapping, uint64_t total_blocks,
    uint64_t length, AccessProfile profile) {
  if (!candidate || !candidate->b || !mapping
      || !scalpel_state.write_promising) {
    return false;
  }
  BlockVector *parent_blockvector = candidate->b;
  BlockVector *hypothesis = NULL;
  const CarveInfoFlavor parent_flavor = candidate->flavor;
  const int32_t parent_needleidx = candidate->needleidx;
  const uint64_t parent_best_validates_to = candidate->best_validates_to;
  char *parent_filetype = candidate->filetype;

  clone_blockvector(parent_blockvector, &hypothesis, true);
  candidate->b = hypothesis;

  AccessProfile final_profile = profile;
  const bool complete = access_reassembly_commit_mapping(
      candidate, mapping, total_blocks, length, &final_profile);

  if (complete) {
    AccessLayout tail_layout;
    uint32_t page_size = 0;

    if (!access_candidate_is_contiguous(candidate)) {
      if (access_parse(
              (const uint8_t *)blockvector_get_data_pointer(candidate->b),
              blockvector_get_data_length(candidate->b), &tail_layout)) {
        page_size = tail_layout.page_size;
      }
    }
    else {
      memset(&tail_layout, 0, sizeof(tail_layout));
    }

    access_assign_candidate_profile(candidate, final_profile);
    candidate->flavor = PROMISING;
    write_candidate(&candidate, true);

    const uint64_t maximum_size =
        scalpel_state.search_specs[candidate->needleidx].MAXIMUMSIZE;

    if (page_size != 0 && mapping[total_blocks - 1] >= 0) {
      uint8_t *scratch = (uint8_t *)malloc(page_size);

      check_memory_allocation(scratch, __LINE__, __FILE__,
                              "Access tail hypothesis page");

      for (uint64_t tail_pages = 1;
           tail_pages <= ACCESS_REASSEMBLY_HYPOTHESIS_LIMIT;
           tail_pages++) {
        if (tail_pages > (UINT64_MAX - length) / page_size) {
          break;
        }
        const uint64_t extended_length = length + tail_pages * page_size;

        if (extended_length > maximum_size || extended_length > SIZE_MAX) {
          break;
        }
        const uint64_t extended_blocks = CEILDIV(
            extended_length, scalpel_state.blocksize);
        const uint64_t image_blocks =
            filemirror_apparent_blocks(scalpel_state.filemirror);

        if (extended_blocks < total_blocks
            || extended_blocks > image_blocks) {
          break;
        }
        int64_t *extended_mapping = (int64_t *)malloc(
            extended_blocks * sizeof(*extended_mapping));

        check_memory_allocation(extended_mapping, __LINE__, __FILE__,
                                "Access tail hypothesis");
        memcpy(extended_mapping, mapping,
               total_blocks * sizeof(*extended_mapping));

        bool available = true;

        if (extended_blocks > total_blocks) {
          const int64_t last = mapping[total_blocks - 1];
          const uint64_t added_blocks = extended_blocks - total_blocks;

          available = last >= 0
              && added_blocks <= (uint64_t)(INT64_MAX - last)
              && access_reassembly_range_available(
                    candidate, last + 1, added_blocks,
                    total_blocks, -1, 0);
          if (available) {
            for (uint64_t slot = total_blocks;
                 slot < extended_blocks; slot++) {
              extended_mapping[slot] =
                  last + 1 + (int64_t)(slot - total_blocks);
            }
          }
        }

        AccessProfile extended_profile = final_profile;

        if (available && access_reassembly_commit_mapping(
                candidate, extended_mapping, extended_blocks,
                extended_length, &extended_profile)) {
          const uint32_t page_number =
              (uint32_t)(extended_length / page_size - 1);

          tail_layout.available_pages = page_number + 1;
          if (access_copy_page(
                  (const uint8_t *)blockvector_get_data_pointer(candidate->b),
                  extended_length, &tail_layout, page_number, scratch)
              && access_page_plausible(scratch, &tail_layout)) {
            access_assign_candidate_profile(candidate, extended_profile);
            candidate->flavor = PROMISING;
            write_candidate(&candidate, true);
          }
          else {
            free(extended_mapping);
            break;
          }
        }
        else {
          free(extended_mapping);
          break;
        }
        free(extended_mapping);
      }
      free(scratch);
    }
    access_layout_clear(&tail_layout);
  }

  free_blockvector(&candidate->b);
  candidate->b = parent_blockvector;
  candidate->flavor = parent_flavor;
  candidate->needleidx = parent_needleidx;
  candidate->filetype = parent_filetype;
  candidate->best_validates_to = parent_best_validates_to;
  return complete;
}

// Test physically ordered tails in increasing gap width. Complete mappings are
// ranked by block evidence, physical boundaries, and locality. Partial
// mappings must advance beyond the retained prefix and prefer the nearest
// continuation before block confidence and parser progress.
//
static inline AccessRecoveryResult access_reassembly_gap_search(
    ThreadWork *work, CarveInfo **candidate, uuid_string_t uuidp,
    uuid_string_t uuidc, uint64_t prefix_blocks, uint64_t total_blocks,
    uint64_t target_length, uint64_t current_progress,
    uint64_t preferred_skip, uint8_t *trial_data,
    int64_t *trial_mapping, int64_t *partial_mapping,
    int64_t *solution_mapping, uint64_t *partial_progress,
    uint64_t *partial_repair_offset, uint64_t *partial_mapping_blocks,
    AccessProfile *profile,
    uint64_t *iterations,
    uint32_t *hypotheses_written, bool *mapping_committed, AccessCarveState *state, AccessSolverState *record) {
  if (!work || !candidate || !*candidate || !trial_data || !trial_mapping
      || !partial_mapping || !solution_mapping || !partial_progress
      || !partial_repair_offset || !partial_mapping_blocks
      || !profile || !iterations
      || !hypotheses_written
      || !mapping_committed || prefix_blocks >= total_blocks) {
    return ACCESS_RECOVERY_NO_MATCH;
  }
  const uint64_t remaining = total_blocks - prefix_blocks;
  const int64_t previous = trial_mapping[prefix_blocks - 1];
  const uint64_t image_blocks =
      filemirror_apparent_blocks(scalpel_state.filemirror);

  if (previous < 0 || (uint64_t)previous + 1 > image_blocks
      || remaining > image_blocks - ((uint64_t)previous + 1)) {
    return ACCESS_RECOVERY_NO_MATCH;
  }
  const uint64_t first = (uint64_t)previous + 1;
  const uint64_t max_skip = image_blocks - first - remaining;
  AccessLayout gap_layout;
  const uint32_t page_size = access_header_parse(
      trial_data, target_length, &gap_layout) ? gap_layout.page_size : 0;
  AccessGapProgress *cursor = &record->progress.gap;

  *mapping_committed = false;

  for (uint64_t skip = cursor->next_skip; skip <= max_skip; skip++) {
    const uint64_t source_start = first + skip;

    if (source_start <= INT64_MAX
        && access_reassembly_range_available(
            *candidate, (int64_t)source_start, remaining,
            prefix_blocks, -1, 0)
        && access_reassembly_copy_run(
            trial_data, target_length, prefix_blocks,
            (int64_t)source_start, remaining)) {
      for (uint64_t offset = 0; offset < remaining; offset++) {
        trial_mapping[prefix_blocks + offset] =
            (int64_t)(source_start + offset);
      }

      const bool preferred = skip == preferred_skip;
      uint64_t supported_mapping_blocks = prefix_blocks;

      if (preferred) {
        for (uint64_t offset = 0; offset < remaining; offset++) {
          const int64_t apparent = (int64_t)(source_start + offset);
          const int64_t actual = filemirror_actual_blocknumber(
              scalpel_state.filemirror, apparent);

          if (actual < 0
              || !filemirror_actual_block_is_zero(
                     scalpel_state.filemirror, actual)) {
            continue;
          }

          uint64_t end = offset;

          while (end < remaining) {
            const int64_t zero_apparent =
                (int64_t)(source_start + end);
            const int64_t zero_actual = filemirror_actual_blocknumber(
                scalpel_state.filemirror, zero_apparent);

            if (zero_actual < 0
                || !filemirror_actual_block_is_zero(
                       scalpel_state.filemirror, zero_actual)) {
              break;
            }
            end++;
          }
          if (end < remaining) {
            const int64_t following_apparent =
                (int64_t)(source_start + end);
            const int64_t following_actual = filemirror_actual_blocknumber(
                scalpel_state.filemirror, following_apparent);
            const BlockValidationDecision following_confidence =
                following_actual < 0 ? BLOCK_CONFIDENCE_INVALID
                : filemirror_get_blocktype(
                      scalpel_state.filemirror, following_actual,
                      (*candidate)->needleidx);
            const bool complete_page_span =
                access_reassembly_span_covers_complete_pages(
                    prefix_blocks + offset, end - offset, page_size);

            if (following_confidence >= ACCESS_BLOCK_CONFIDENCE
                && complete_page_span) {
              supported_mapping_blocks = prefix_blocks + offset;
            }
          }
          if (supported_mapping_blocks > prefix_blocks || end >= remaining) {
            break;
          }
          offset = end - 1;
        }
      }

      bool valid = false;
      uint64_t progress = 0;
      uint64_t repair_offset = 0;
      AccessProfile trial_profile = ACCESS_PROFILE_UNKNOWN;

      access_reassembly_parse_trial(trial_data, target_length, &valid,
                                    &progress, &repair_offset,
                                    &trial_profile);
      if (scalpel_state.mode_verbose && skip == preferred_skip) {
        lock_fprintf(
            stdout,
            "Access preferred ordered gap width %" PRIu64
            " reached byte %" PRIu64 ", repair offset %" PRIu64
            ", complete=%s.\n",
            skip, progress, repair_offset, valid ? "true" : "false");
      }
      if (valid) {
        const BlockValidationDecision confidence =
            access_reassembly_run_confidence(
                *candidate, (int64_t)source_start, remaining);
        uint32_t boundary_score = 0;

        if (access_reassembly_boundary_separated(
                *candidate, (int64_t)source_start - 1)) {
          boundary_score++;
        }
        if (access_reassembly_boundary_separated(
                *candidate, (int64_t)(source_start + remaining))) {
          boundary_score++;
        }
        const bool better =
            !cursor->have_complete || preferred > cursor->complete_preferred
            || (preferred == cursor->complete_preferred
                && confidence > cursor->complete_confidence)
            || (preferred == cursor->complete_preferred
                && confidence == cursor->complete_confidence
                && boundary_score > cursor->complete_boundary_score)
            || (preferred == cursor->complete_preferred
                && confidence == cursor->complete_confidence
                && boundary_score == cursor->complete_boundary_score
                && skip < cursor->complete_skip);

        if (better) {
          memcpy(solution_mapping, trial_mapping,
                 total_blocks * sizeof(*solution_mapping));
          cursor->complete_confidence = confidence;
          cursor->complete_boundary_score = boundary_score;
          cursor->complete_skip = skip;
          cursor->complete_preferred = preferred;
          cursor->complete_profile = trial_profile;
          cursor->have_complete = true;
        }
        // A fully parsed mapping at the detected physical gap is committed
        // below, so no alternative gap width can supersede it.
        if (preferred) {
          break;
        }
      }
      else if (progress > current_progress
               || supported_mapping_blocks > prefix_blocks) {
        uint64_t progressed_blocks = CEILDIV(
            progress, scalpel_state.blocksize);

        if (progressed_blocks > total_blocks) {
          progressed_blocks = total_blocks;
        }
        uint64_t mapping_blocks = progressed_blocks;

        if (supported_mapping_blocks > prefix_blocks) {
          mapping_blocks = supported_mapping_blocks;
        }
        const uint64_t extension_blocks = mapping_blocks > prefix_blocks
            ? mapping_blocks - prefix_blocks : 1;
        const BlockValidationDecision confidence =
            access_reassembly_run_confidence(
                *candidate, (int64_t)source_start, extension_blocks);
        const bool extends_prefix = mapping_blocks > prefix_blocks;
        const bool supported = confidence >= ACCESS_BLOCK_CONFIDENCE;
        const bool preferred_mapping = preferred && extends_prefix;
        const bool better =
            preferred_mapping > cursor->partial_preferred
            || (preferred_mapping == cursor->partial_preferred
                && extends_prefix > cursor->partial_extends_prefix)
            || (preferred_mapping == cursor->partial_preferred
                && extends_prefix == cursor->partial_extends_prefix
                && skip < cursor->partial_skip)
            || (preferred_mapping == cursor->partial_preferred
                && extends_prefix == cursor->partial_extends_prefix
                && skip == cursor->partial_skip
                && supported > cursor->partial_supported)
            || (preferred_mapping == cursor->partial_preferred
                && extends_prefix == cursor->partial_extends_prefix
                && skip == cursor->partial_skip
                && supported == cursor->partial_supported
                && progress > *partial_progress)
            || (preferred_mapping == cursor->partial_preferred
                && extends_prefix == cursor->partial_extends_prefix
                && skip == cursor->partial_skip
                && supported == cursor->partial_supported
                && progress == *partial_progress
                && confidence > cursor->partial_confidence);

        if (better) {
          if (scalpel_state.mode_verbose) {
            lock_fprintf(
                stdout,
                "Access ordered reconstruction advanced to byte "
                "%" PRIu64 " with gap width %" PRIu64
                ", repair offset %" PRIu64 ", and confidence %u.\n",
                progress, skip, repair_offset,
                (unsigned int)confidence);
          }
          memcpy(partial_mapping, trial_mapping,
                 total_blocks * sizeof(*partial_mapping));
          *partial_progress = progress;
          *partial_repair_offset = repair_offset;
          *partial_mapping_blocks = mapping_blocks;
          cursor->partial_confidence = confidence;
          cursor->partial_skip = skip;
          cursor->partial_extends_prefix = extends_prefix;
          cursor->partial_supported = supported;
          cursor->partial_preferred = preferred_mapping;
        }
      }
    }
    cursor->next_skip = skip + 1;
    if (access_reassembly_poll(work, candidate, uuidp, uuidc, iterations, state)) {
      return ACCESS_RECOVERY_INTERRUPTED;
    }
  }
  if (scalpel_state.mode_verbose && *partial_progress > current_progress) {
    lock_fprintf(stdout,
                 "Access ordered reconstruction stopped at byte "
                 "%" PRIu64 " with gap width %" PRIu64
                 " and confidence %u.\n",
                 *partial_progress, cursor->partial_skip,
                 (unsigned int)cursor->partial_confidence);
  }
  if (cursor->have_complete) {
    if (!cursor->complete_preferred && cursor->partial_preferred
        && cursor->complete_confidence < ACCESS_BLOCK_CONFIDENCE) {
      return ACCESS_RECOVERY_MATCH;
    }
    if (scalpel_state.mode_verbose) {
      lock_fprintf(
          stdout,
          "Access ordered reconstruction retained gap width %" PRIu64
          " at logical block %" PRIu64
          " with confidence %u and boundary score %u.\n",
          cursor->complete_skip, prefix_blocks,
          (unsigned int)cursor->complete_confidence, cursor->complete_boundary_score);
    }
    if (cursor->complete_preferred) {
      BlockVector *original = NULL;

      clone_blockvector((*candidate)->b, &original, true);
      if (access_reassembly_commit_mapping(
              *candidate, solution_mapping, total_blocks, target_length,
              &cursor->complete_profile)) {
        free_blockvector(&original);
        *profile = cursor->complete_profile;
        *mapping_committed = true;
        return ACCESS_RECOVERY_MATCH;
      }
      free_blockvector(&(*candidate)->b);
      (*candidate)->b = original;
    }

    const bool written = access_reassembly_write_mapping_hypothesis(
        *candidate, solution_mapping, total_blocks, target_length,
        cursor->complete_profile);

    if (written) {
      (*hypotheses_written)++;
    }
    *profile = cursor->complete_profile;
    return ACCESS_RECOVERY_MATCH;
  }
  return *partial_mapping_blocks > prefix_blocks
      ? ACCESS_RECOVERY_MATCH : ACCESS_RECOVERY_NO_MATCH;
}

static inline AccessRecoveryResult access_reassembly_try_gap(
    ThreadWork *work, CarveInfo **candidate, uuid_string_t uuidp,
    uuid_string_t uuidc, uint64_t prefix_blocks, uint64_t total_blocks,
    uint64_t target_length, uint64_t current_progress,
    uint64_t preferred_skip, uint8_t *trial_data,
    int64_t *trial_mapping, int64_t *partial_mapping,
    int64_t *solution_mapping, uint64_t *partial_progress,
    uint64_t *partial_repair_offset, uint64_t *partial_mapping_blocks,
    AccessProfile *profile,
    uint64_t *iterations,
    uint32_t *hypotheses_written, bool *mapping_committed, AccessCarveState *state) {
  AccessSolverState *record = access_solver_state(
      state, preferred_skip == UINT64_MAX ? 1 : 0, *candidate,
      prefix_blocks, total_blocks, target_length, preferred_skip,
      *partial_progress, *partial_repair_offset, *partial_mapping_blocks,
      *profile, *hypotheses_written, partial_mapping);
  AccessSolverProgress *p = &record->progress;
  if (!p->finished) {
    p->result = access_reassembly_gap_search(
        work, candidate, uuidp, uuidc, prefix_blocks, total_blocks,
        target_length, current_progress, preferred_skip, trial_data,
        trial_mapping, record->partial_mapping, record->solution_mapping,
        &p->partial_progress, &p->partial_repair_offset, &p->partial_mapping_blocks,
        &p->profile, iterations, &p->hypotheses_written, &p->mapping_committed,
        state, record);
    p->finished = p->result != ACCESS_RECOVERY_INTERRUPTED;
  }
  memcpy(partial_mapping, record->partial_mapping, total_blocks * sizeof(*partial_mapping));
  memcpy(solution_mapping, record->solution_mapping, total_blocks * sizeof(*solution_mapping));
  *partial_progress = p->partial_progress;
  *partial_repair_offset = p->partial_repair_offset;
  *partial_mapping_blocks = p->partial_mapping_blocks;
  *profile = p->profile;
  *hypotheses_written = p->hypotheses_written;
  *mapping_committed = p->mapping_committed;
  return p->result;
}

// Reconstruct one displaced contiguous run. Fragmentator-style displacement
// leaves an equal-sized physical hole at the logical run position, so the
// ordered suffix begins after that hole. Physical isolation distinguishes a
// relocated run from compatible pages inside another database; confidence and
// reservations then rank mappings that pass local checks and complete parsing.
// Every byte-distinct mapping in the best successful rank remains available as
// a PROMISING alternative.
//
static inline AccessRecoveryResult access_reassembly_displaced_search(
    ThreadWork *work, CarveInfo **candidate, uuid_string_t uuidp,
    uuid_string_t uuidc, uint64_t prefix_blocks, uint64_t total_blocks,
    uint64_t target_length, uint64_t preferred_run_length,
    uint8_t *trial_data,
    int64_t *trial_mapping, int64_t *partial_mapping,
    uint64_t *partial_progress, uint64_t *partial_repair_offset,
    uint64_t *partial_mapping_blocks,
    AccessProfile *profile, uint64_t *iterations,
    uint32_t *hypotheses_written, bool *strong_hypothesis,
    bool *partial_has_file_local_support, bool *mapping_committed,
    AccessCarveState *state, AccessSolverState *record) {
  if (!work || !candidate || !*candidate || !trial_data || !trial_mapping
      || !partial_mapping || !partial_progress || !partial_repair_offset
      || !partial_mapping_blocks
      || !profile || !iterations
      || !hypotheses_written || !strong_hypothesis
      || !partial_has_file_local_support || !mapping_committed
      || prefix_blocks == 0 || prefix_blocks >= total_blocks) {
    return ACCESS_RECOVERY_NO_MATCH;
  }
  const uint64_t remaining = total_blocks - prefix_blocks;
  const int64_t previous = trial_mapping[prefix_blocks - 1];
  const uint64_t image_blocks =
      filemirror_apparent_blocks(scalpel_state.filemirror);
  AccessDisplacedProgress *cursor = &record->progress.displaced;

  if (previous < 0) {
    return ACCESS_RECOVERY_NO_MATCH;
  }
  bool fragmented_prefix = false;

  for (uint64_t slot = 1; slot < prefix_blocks; slot++) {
    const int64_t prior = trial_mapping[slot - 1];
    const int64_t apparent = trial_mapping[slot];

    if (prior < 0 || apparent < 0 || prior == INT64_MAX
        || apparent != prior + 1) {
      fragmented_prefix = true;
      break;
    }
  }
  uint8_t page_scratch[ACCESS_JET4_PAGE_SIZE];
  uint8_t target_scratch[ACCESS_JET4_PAGE_SIZE];


  const bool have_preferred_run = preferred_run_length != 0
      && preferred_run_length <= remaining;

  for (uint64_t run_index = cursor->next_run; run_index < remaining; run_index++) {
    uint64_t run_length = run_index + 1;

    if (have_preferred_run) {
      if (run_index == 0) {
        run_length = preferred_run_length;
      }
      else if (run_index < preferred_run_length) {
        run_length = run_index;
      }
      else {
        run_length = run_index + 1;
      }
    }

    if ((uint64_t)previous + 1 > UINT64_MAX - run_length) {
      break;
    }
    const uint64_t suffix_start =
        (uint64_t)previous + 1 + run_length;
    const uint64_t suffix_count = remaining - run_length;
    uint64_t suffix_supported_count = suffix_count;

    if (suffix_start > INT64_MAX
        || (suffix_count != 0
            && !access_reassembly_range_available(
                *candidate, (int64_t)suffix_start, suffix_count,
                prefix_blocks, -1, 0))) {
      continue;
    }
    if (suffix_count != 0
        && !access_reassembly_copy_run(
            trial_data, target_length, prefix_blocks + run_length,
            (int64_t)suffix_start, suffix_count)) {
      continue;
    }
    for (uint64_t offset = 0; offset < suffix_count; offset++) {
      trial_mapping[prefix_blocks + run_length + offset] =
          (int64_t)(suffix_start + offset);
    }

    for (uint64_t offset = 0; offset < suffix_count; offset++) {
      const int64_t apparent = (int64_t)(suffix_start + offset);
      const int64_t actual = filemirror_actual_blocknumber(
          scalpel_state.filemirror, apparent);

      if (actual < 0
          || !filemirror_actual_block_is_zero(
                 scalpel_state.filemirror, actual)) {
        continue;
      }
      uint64_t end = offset;

      while (end < suffix_count) {
        const int64_t zero_apparent = (int64_t)(suffix_start + end);
        const int64_t zero_actual = filemirror_actual_blocknumber(
            scalpel_state.filemirror, zero_apparent);

        if (zero_actual < 0
            || !filemirror_actual_block_is_zero(
                   scalpel_state.filemirror, zero_actual)) {
          break;
        }
        end++;
      }
      if (end < suffix_count) {
        const int64_t following_apparent =
            (int64_t)(suffix_start + end);
        const int64_t following_actual = filemirror_actual_blocknumber(
            scalpel_state.filemirror, following_apparent);
        const BlockValidationDecision following_confidence =
            following_actual < 0 ? BLOCK_CONFIDENCE_INVALID
            : filemirror_get_blocktype(
                  scalpel_state.filemirror, following_actual,
                  (*candidate)->needleidx);

        if (scalpel_state.blocksize >= record->layout.page_size
            && following_confidence >= ACCESS_BLOCK_CONFIDENCE
            && access_reassembly_span_covers_complete_pages(
                   prefix_blocks + run_length + offset,
                   end - offset, record->layout.page_size)) {
          suffix_supported_count = offset;
        }
      }
      break;
    }

    const uint64_t suffix_slot = prefix_blocks + run_length;

    if (suffix_slot > UINT64_MAX / (uint64_t)scalpel_state.blocksize) {
      continue;
    }
    const uint64_t suffix_offset =
        suffix_slot * (uint64_t)scalpel_state.blocksize;

    if (suffix_supported_count != 0) {
      if (suffix_offset >= target_length) {
        continue;
      }
      uint64_t suffix_validation_length = target_length - suffix_offset;

      if (suffix_supported_count
          <= UINT64_MAX / (uint64_t)scalpel_state.blocksize) {
        const uint64_t supported_length =
            suffix_supported_count * (uint64_t)scalpel_state.blocksize;

        if (supported_length < suffix_validation_length) {
          suffix_validation_length = supported_length;
        }
      }
      if (!access_reassembly_pages_valid(
              trial_data, target_length, &record->layout, suffix_offset,
              suffix_validation_length, page_scratch,
              target_scratch, false)) {
        continue;
      }
    }

    if (run_length > image_blocks) {
      break;
    }
    const uint64_t last_source = image_blocks - run_length;

    const int64_t excluded_first = suffix_count == 0
                                       ? -1 : (int64_t)suffix_start;
    for (uint64_t source_start = run_index == cursor->next_run ? cursor->next_source : 0; source_start <= last_source;
         source_start++) {
      if (source_start <= (uint64_t)INT64_MAX - run_length
          && access_reassembly_range_available(
              *candidate, (int64_t)source_start, run_length,
              prefix_blocks, excluded_first, suffix_count)
          && access_reassembly_copy_run(
              trial_data, target_length, prefix_blocks,
              (int64_t)source_start, run_length)
          && access_reassembly_pages_valid(
              trial_data, target_length, &record->layout,
              prefix_blocks * (uint64_t)scalpel_state.blocksize,
              run_length * (uint64_t)scalpel_state.blocksize,
              page_scratch, target_scratch, true)) {
        for (uint64_t offset = 0; offset < run_length; offset++) {
          trial_mapping[prefix_blocks + offset] =
              (int64_t)(source_start + offset);
        }

        bool valid = false;
        uint64_t progress = 0;
        uint64_t repair_offset = 0;
        AccessProfile trial_profile = ACCESS_PROFILE_UNKNOWN;

        access_reassembly_parse_trial(trial_data, target_length, &valid,
                                      &progress, &repair_offset,
                                      &trial_profile);
        AccessRunRank rank;
        const bool matches_preferred = have_preferred_run
            && run_length == preferred_run_length;

        rank.structure_score = access_reassembly_run_structure_score(
            trial_data, target_length, &record->layout,
            prefix_blocks * (uint64_t)scalpel_state.blocksize,
            run_length * (uint64_t)scalpel_state.blocksize,
            page_scratch);
        rank.confidence = access_reassembly_run_confidence(
            *candidate, (int64_t)source_start, run_length);
        rank.reservations = access_reassembly_run_reservations(
            (int64_t)source_start, run_length);
        rank.boundary_score = 0;
        if (access_reassembly_boundary_separated(
                *candidate, (int64_t)source_start - 1)) {
          rank.boundary_score++;
        }
        if (access_reassembly_boundary_separated(
                *candidate,
                (int64_t)(source_start + run_length))) {
          rank.boundary_score++;
        }
        if (valid) {
          AccessRunRank best_rank = {
            cursor->best_structure_score, cursor->best_confidence,
            cursor->best_reservations, cursor->best_boundary_score
          };
          const bool preferred_better = fragmented_prefix
              && matches_preferred && !cursor->best_matches_preferred;
          const bool same_preference = !fragmented_prefix
              || matches_preferred == cursor->best_matches_preferred;
          const int rank_comparison = cursor->have_best
              ? access_reassembly_compare_run_rank(
                    &rank, &best_rank) : 1;
          const bool better = !cursor->have_best
              || preferred_better
              || (same_preference
                  && (rank_comparison > 0
                      || (rank_comparison == 0
                          && run_length < cursor->best_run_length)));

          if (better) {
            if (scalpel_state.mode_verbose) {
              lock_fprintf(
                  stdout,
                  "Access displaced reconstruction selected run length "
                  "%" PRIu64 " from apparent block %" PRIu64
                  " at logical block %" PRIu64
                  " with structure score %u, confidence %u, reservations "
                  "%" PRId64 ", and boundary score %u.\n",
                  run_length, source_start, prefix_blocks,
                  rank.structure_score,
                  (unsigned int)rank.confidence, rank.reservations,
                  rank.boundary_score);
            }
            *profile = trial_profile;
            cursor->have_best = true;
            cursor->ambiguous = false;
            cursor->best_structure_score = rank.structure_score;
            cursor->best_confidence = rank.confidence;
            cursor->best_reservations = rank.reservations;
            cursor->best_boundary_score = rank.boundary_score;
            cursor->best_run_length = run_length;
            cursor->best_matches_preferred = matches_preferred;
            cursor->best_sources[0] = source_start;
            cursor->best_source_count = 1;
          }
          else if (rank_comparison == 0
                   && run_length == cursor->best_run_length
                   && source_start != cursor->best_sources[0]) {
            if (scalpel_state.mode_verbose) {
              lock_fprintf(
                  stdout,
                  "Access displaced reconstruction has another "
                  "top-ranked run length %" PRIu64
                  " from apparent block %" PRIu64 ".\n",
                  run_length, source_start);
            }
            cursor->ambiguous = true;
            if (cursor->best_source_count < ACCESS_REASSEMBLY_HYPOTHESIS_LIMIT) {
              cursor->best_sources[cursor->best_source_count++] = source_start;
            }
          }

          // Page numbers and row links can repeat across independent
          // databases. Keep a bounded set at each structural rank so strong
          // evidence from one database cannot erase the correct lower-ranked
          // physical hypothesis for another database.
          uint32_t hypothesis_level = rank.structure_score;

          if (hypothesis_level >= ACCESS_REASSEMBLY_STRUCTURE_LEVELS) {
            hypothesis_level = ACCESS_REASSEMBLY_STRUCTURE_LEVELS - 1;
          }
          AccessRunRank hypothesis_rank = rank;
          AccessRunRank best_hypothesis_rank = {
            rank.structure_score, cursor->hypothesis_confidence[hypothesis_level],
            cursor->hypothesis_reservations[hypothesis_level],
            cursor->hypothesis_boundary_score[hypothesis_level]
          };

          hypothesis_rank.reservations = 0;
          best_hypothesis_rank.reservations = 0;
          const bool hypothesis_preferred_better = fragmented_prefix
              && matches_preferred
              && !cursor->hypothesis_matches_preferred[hypothesis_level];
          const bool same_hypothesis_preference = !fragmented_prefix
              || matches_preferred
                     == cursor->hypothesis_matches_preferred[hypothesis_level];
          const int hypothesis_comparison =
              cursor->have_hypothesis_rank[hypothesis_level]
              ? access_reassembly_compare_run_rank(
                    &hypothesis_rank, &best_hypothesis_rank) : 1;
          const bool better_hypothesis =
              !cursor->have_hypothesis_rank[hypothesis_level]
              || hypothesis_preferred_better
              || (same_hypothesis_preference
                  && (hypothesis_comparison > 0
                      || (hypothesis_comparison == 0
                          && run_length
                                 < cursor->hypothesis_run_length[hypothesis_level])));

          if (better_hypothesis) {
            cursor->have_hypothesis_rank[hypothesis_level] = true;
            cursor->hypothesis_matches_preferred[hypothesis_level] =
                matches_preferred;
            cursor->hypothesis_confidence[hypothesis_level] = rank.confidence;
            cursor->hypothesis_reservations[hypothesis_level] = rank.reservations;
            cursor->hypothesis_boundary_score[hypothesis_level] =
                rank.boundary_score;
            cursor->hypothesis_run_length[hypothesis_level] = run_length;
            cursor->hypothesis_sources[hypothesis_level][0] = source_start;
            cursor->hypothesis_run_lengths[hypothesis_level][0] = run_length;
            cursor->hypothesis_profiles[hypothesis_level][0] = trial_profile;
            cursor->hypothesis_count[hypothesis_level] = 1;
          }
          else if (same_hypothesis_preference
                   && hypothesis_comparison == 0
                   && run_length
                          == cursor->hypothesis_run_length[hypothesis_level]
                   && cursor->hypothesis_count[hypothesis_level]
                          < ACCESS_REASSEMBLY_HYPOTHESIS_LIMIT) {
            const uint32_t index = cursor->hypothesis_count[hypothesis_level];

            cursor->hypothesis_sources[hypothesis_level][index] = source_start;
            cursor->hypothesis_run_lengths[hypothesis_level][index] = run_length;
            cursor->hypothesis_profiles[hypothesis_level][index] = trial_profile;
            cursor->hypothesis_count[hypothesis_level]++;
          }
        }
        else {
          const uint64_t candidate_mapping_blocks =
              prefix_blocks + run_length + suffix_supported_count;

          if (candidate_mapping_blocks > prefix_blocks) {
            const int rank_comparison = cursor->have_partial
                ? access_reassembly_compare_run_rank(
                      &rank, &cursor->best_partial_rank) : 1;
            const bool better = !cursor->have_partial
                || matches_preferred > cursor->partial_matches_preferred
                || (matches_preferred == cursor->partial_matches_preferred
                    && progress > cursor->best_partial_progress)
                || (matches_preferred == cursor->partial_matches_preferred
                    && progress == cursor->best_partial_progress
                    && repair_offset > cursor->best_partial_repair_offset)
                || (matches_preferred == cursor->partial_matches_preferred
                    && progress == cursor->best_partial_progress
                    && repair_offset == cursor->best_partial_repair_offset
                    && rank_comparison > 0)
                || (matches_preferred == cursor->partial_matches_preferred
                    && progress == cursor->best_partial_progress
                    && repair_offset == cursor->best_partial_repair_offset
                    && rank_comparison == 0
                    && run_length < cursor->best_partial_run_length);

            if (better) {
              memcpy(partial_mapping, trial_mapping,
                     total_blocks * sizeof(*partial_mapping));
              cursor->have_partial = true;
              cursor->partial_ambiguous = false;
              cursor->partial_matches_preferred = matches_preferred;
              cursor->best_partial_progress = progress;
              cursor->best_partial_repair_offset = repair_offset;
              cursor->best_partial_blocks = candidate_mapping_blocks;
              cursor->best_partial_run_length = run_length;
              cursor->best_partial_source = source_start;
              cursor->best_partial_rank = rank;
              cursor->best_partial_profile = trial_profile;
            }
            else if (matches_preferred == cursor->partial_matches_preferred
                     && progress == cursor->best_partial_progress
                     && repair_offset == cursor->best_partial_repair_offset
                     && rank_comparison == 0
                     && run_length == cursor->best_partial_run_length
                     && !access_reassembly_mappings_equal(
                         partial_mapping, trial_mapping, total_blocks,
                         target_length)) {
              cursor->partial_ambiguous = true;
            }
          }
        }
      }
      cursor->next_run = run_index;
      cursor->next_source = source_start + 1;
      if (access_reassembly_poll(work, candidate, uuidp, uuidc,
                                 iterations, state)) {
        return ACCESS_RECOVERY_INTERRUPTED;
      }
    }
    cursor->next_run = run_index + 1;
    cursor->next_source = 0;
    if (cursor->have_best && cursor->best_boundary_score == 2
        && cursor->best_run_length == run_length) {
      break;
    }
  }
  if (!cursor->have_best) {
    if (cursor->have_partial && !cursor->partial_ambiguous) {
      const bool repairs_allocated_page =
          access_reassembly_span_contains_allocated_page(
              prefix_blocks, cursor->best_partial_run_length, &record->layout);
      *partial_has_file_local_support = repairs_allocated_page
          && cursor->best_partial_rank.structure_score >= 4
          && cursor->best_partial_rank.confidence >= ACCESS_BLOCK_CONFIDENCE
          && cursor->best_partial_rank.boundary_score == 2;
      if (scalpel_state.mode_verbose) {
        lock_fprintf(
            stdout,
            "Access displaced partial selected run length %" PRIu64
            " from apparent block %" PRIu64
            " at logical block %" PRIu64
            " with structure score %u, confidence %u, reservations "
            "%" PRId64 ", boundary score %u, and allocated-page "
            "support=%s.\n",
            cursor->best_partial_run_length, cursor->best_partial_source, prefix_blocks,
            cursor->best_partial_rank.structure_score,
            (unsigned int)cursor->best_partial_rank.confidence,
            cursor->best_partial_rank.reservations,
            cursor->best_partial_rank.boundary_score,
            repairs_allocated_page ? "true" : "false");
      }
      *partial_progress = cursor->best_partial_progress;
      *partial_repair_offset = cursor->best_partial_repair_offset;
      *partial_mapping_blocks = cursor->best_partial_blocks;
      *profile = cursor->best_partial_profile;
      return ACCESS_RECOVERY_MATCH;
    }
    return cursor->partial_ambiguous
        ? ACCESS_RECOVERY_AMBIGUOUS : ACCESS_RECOVERY_NO_MATCH;
  }

  const uint64_t suffix_start =
      (uint64_t)previous + 1 + cursor->best_run_length;
  const uint64_t suffix_count = remaining - cursor->best_run_length;

  for (uint64_t offset = 0; offset < suffix_count; offset++) {
    trial_mapping[prefix_blocks + cursor->best_run_length + offset] =
        (int64_t)(suffix_start + offset);
  }

  for (uint64_t offset = 0; offset < cursor->best_run_length; offset++) {
    trial_mapping[prefix_blocks + offset] =
        (int64_t)(cursor->best_sources[0] + offset);
  }

  // Continue a unique, physically isolated, file-local repair in the live
  // candidate. The next loop can then detect and repair a later discontinuity.
  if (!cursor->ambiguous && cursor->best_source_count == 1 && cursor->best_boundary_score == 2
      && cursor->best_structure_score >= 4) {
    BlockVector *original = NULL;

    clone_blockvector((*candidate)->b, &original, true);
    if (access_reassembly_commit_mapping(
            *candidate, trial_mapping, total_blocks, target_length,
            profile)) {
      free_blockvector(&original);
      *mapping_committed = true;
      return ACCESS_RECOVERY_MATCH;
    }
    free_blockvector(&(*candidate)->b);
    (*candidate)->b = original;
  }

  // An unbounded run can be an interior slice of an unrelated database, so
  // retain one fallback per structural rank. Preserve every bounded candidate
  // tied on confidence and physical isolation at that rank.
  uint32_t written_here = 0;
  uint32_t total_hypothesis_count = 0;
  bool wrote_bounded_hypothesis = false;

  for (uint32_t level = 0;
       level < ACCESS_REASSEMBLY_STRUCTURE_LEVELS; level++) {
    if (!cursor->have_hypothesis_rank[level]) {
      continue;
    }
    total_hypothesis_count += cursor->hypothesis_count[level];
    const uint32_t write_count = cursor->hypothesis_boundary_score[level] == 0
                                     ? 1 : cursor->hypothesis_count[level];

    for (uint32_t index = 0; index < write_count; index++) {
      const uint64_t run_length =
          cursor->hypothesis_run_lengths[level][index];
      const uint64_t source_start = cursor->hypothesis_sources[level][index];
      const uint64_t hypothesis_suffix_start =
          (uint64_t)previous + 1 + run_length;
      const uint64_t hypothesis_suffix_count = remaining - run_length;

      for (uint64_t offset = 0; offset < run_length; offset++) {
        trial_mapping[prefix_blocks + offset] =
            (int64_t)(source_start + offset);
      }
      for (uint64_t offset = 0;
           offset < hypothesis_suffix_count; offset++) {
        trial_mapping[prefix_blocks + run_length + offset] =
            (int64_t)(hypothesis_suffix_start + offset);
      }
      if (access_reassembly_write_mapping_hypothesis(
              *candidate, trial_mapping, total_blocks, target_length,
              cursor->hypothesis_profiles[level][index])) {
        written_here++;
        if (cursor->hypothesis_boundary_score[level] == 2) {
          wrote_bounded_hypothesis = true;
        }
      }
    }
  }
  *hypotheses_written += written_here;
  *strong_hypothesis = wrote_bounded_hypothesis;
  return cursor->ambiguous || total_hypothesis_count > 1
      ? ACCESS_RECOVERY_AMBIGUOUS : ACCESS_RECOVERY_MATCH;
}

static inline AccessRecoveryResult access_reassembly_try_displaced_run(
    ThreadWork *work, CarveInfo **candidate, uuid_string_t uuidp,
    uuid_string_t uuidc, uint64_t prefix_blocks, uint64_t total_blocks,
    uint64_t target_length, uint64_t preferred_run_length,
    uint8_t *trial_data,
    int64_t *trial_mapping, int64_t *partial_mapping,
    uint64_t *partial_progress, uint64_t *partial_repair_offset,
    uint64_t *partial_mapping_blocks,
    AccessProfile *profile, uint64_t *iterations,
    uint32_t *hypotheses_written, bool *strong_hypothesis,
    bool *partial_has_file_local_support, bool *mapping_committed, AccessCarveState *state) {
  const unsigned index = preferred_run_length == UINT64_MAX ? 3 : 2;
  AccessSolverState *record = access_solver_state(
      state, index, *candidate, prefix_blocks, total_blocks, target_length,
      preferred_run_length, *partial_progress, *partial_repair_offset,
      *partial_mapping_blocks, *profile, *hypotheses_written, partial_mapping);
  if (!record->progress.displaced.layout_ready) {
    (void)access_parse(trial_data, target_length, &record->layout);
    record->progress.displaced.layout_ready = true;
  }
  AccessSolverProgress *p = &record->progress;
  if (!p->finished) {
    p->result = access_reassembly_displaced_search(
        work, candidate, uuidp, uuidc, prefix_blocks, total_blocks,
        target_length, preferred_run_length, trial_data, trial_mapping,
        record->partial_mapping, &p->partial_progress, &p->partial_repair_offset,
        &p->partial_mapping_blocks, &p->profile, iterations, &p->hypotheses_written,
        &p->strong_hypothesis, &p->file_local_support, &p->mapping_committed,
        state, record);
    p->finished = p->result != ACCESS_RECOVERY_INTERRUPTED;
  }
  memcpy(partial_mapping, record->partial_mapping, total_blocks * sizeof(*partial_mapping));
  *partial_progress = p->partial_progress;
  *partial_repair_offset = p->partial_repair_offset;
  *partial_mapping_blocks = p->partial_mapping_blocks;
  *profile = p->profile;
  *hypotheses_written = p->hypotheses_written;
  *strong_hypothesis = p->strong_hypothesis;
  *partial_has_file_local_support = p->file_local_support;
  *mapping_committed = p->mapping_committed;
  return p->result;
}

// Repair a database at the first logical page rejected by the Jet or ACE
// parser. Ordered-tail and displaced-run proofs are attempted before the
// single-page fallback, and only candidates that move the structural frontier
// forward are retained.
//
static inline void access_reassembly(ThreadWork *work,
                                     CarveInfo **candidate,
                                     uuid_string_t uuidp,
                                     uuid_string_t uuidc) {
  if (!candidate || !*candidate || !(*candidate)->b || scalpel_state.blocksize == 0) {
    if (candidate && *candidate) {
      destroy_candidate(candidate);
    }
    return;
  }
  normalize_blockvector((*candidate)->b);
  inflate_blockvector((*candidate)->b);
  AccessCarveState *state = carve_get_state((*candidate)->carvehashkey);
  if (!state) {
    state = calloc(1, sizeof(*state));
    check_memory_allocation(state, __LINE__, __FILE__, "Access search state");
    state->progress.magic = ACCESS_SEARCH_MAGIC;
    state->progress.retained_blocks = blockvector_get_num_blocks((*candidate)->b);
    state->progress.last_reviewed_repair_blocks = UINT64_MAX;
    state->progress.prefix_view = access_prefix_view(*candidate);
  }
  else if (!XXH128_isEqual(state->progress.view, validator_search_view(*candidate))) {
    access_search_reset(state);
  }
  access_reassembly_continue(work, candidate, uuidp, uuidc, state);
  access_free_carve_state((void **)&state);
}

static inline void access_reassembly_continue(ThreadWork *work,
                                     CarveInfo **candidate,
                                     uuid_string_t uuidp,
                                     uuid_string_t uuidc, AccessCarveState *state) {
  if (!work || !candidate || !*candidate || !(*candidate)->b
      || scalpel_state.blocksize == 0) {
    if (candidate && *candidate) {
      destroy_candidate(candidate);
    }
    return;
  }

  normalize_blockvector((*candidate)->b);
  inflate_blockvector((*candidate)->b);

  // Contiguous validation has already established this prefix. A conservative
  // internal relationship failure may precede the first fragmented page, so
  // reassembly must never discard that known-good frontier.
  AccessSearchProgress *saved = &state->progress;

  if (blockvector_get_data_length((*candidate)->b) != 0
      && (*candidate)->best_validates_to
             < blockvector_get_data_length((*candidate)->b) - 1) {
    (*candidate)->best_validates_to =
        blockvector_get_data_length((*candidate)->b) - 1;
  }

  while (*candidate) {
    access_search_scope(*candidate, state);
    BlockVector *blockvector = (*candidate)->b;
    uint64_t blocks = blockvector_get_num_blocks(blockvector);

    if (blocks < 2
        || blockvector_get_actual_blocknumber(blockvector, 0) < 0) {
      destroy_candidate(candidate);
      return;
    }
    for (uint64_t slot = 1; slot < blocks; slot++) {
      if (blockvector_get_actual_blocknumber(blockvector, slot) < 0) {
        resize_blockvector(blockvector, slot);
        blockvector_set_data_length(
            blockvector, slot * (uint64_t)scalpel_state.blocksize);
        inflate_blockvector(blockvector);
        blocks = slot;
        break;
      }
    }

    AccessLayout current_layout;
    bool current_valid = access_parse(
        (const uint8_t *)blockvector_get_data_pointer(blockvector),
        blockvector_get_data_length(blockvector), &current_layout);
    if (current_layout.inferred_size > saved->retained_target_length) {
      saved->retained_target_length = current_layout.inferred_size;
    }
    const uint64_t target_length = saved->retained_target_length;
    uint64_t current_progress = current_valid
        ? target_length : current_layout.failure_offset;
    uint64_t current_repair_offset = current_layout.repair_offset;
    const AccessProfile current_profile = current_layout.profile;
    const uint32_t current_page_size = current_layout.page_size;
    uint64_t internal_repair_blocks = 0;
    uint64_t internal_run_width = 0;
    bool internal_repair_from_confidence = false;
    if (saved->iteration_active) {
      current_valid = false;
      current_progress = saved->current_progress;
      current_repair_offset = saved->current_repair_offset;
      internal_repair_blocks = saved->internal_repair_blocks;
      internal_run_width = saved->internal_run_width;
      internal_repair_from_confidence = saved->internal_repair_from_confidence;
    }

    if (scalpel_state.mode_verbose && current_valid) {
      lock_fprintf(
          stdout,
          "Access complete mapping review: represented blocks=%" PRIu64
          ", inferred bytes=%" PRIu64 ", retained target bytes=%" PRIu64
          ".\n",
          blocks, current_layout.inferred_size, saved->retained_target_length);
    }

    if (current_valid && !scalpel_state.no_defrag) {
      const uint64_t target_blocks = CEILDIV(
          target_length, scalpel_state.blocksize);
      const uint32_t review_passes =
          scalpel_state.blocksize < current_page_size ? 1 : 2;

      for (uint32_t pass = 0;
           pass < review_passes && internal_run_width == 0; pass++) {
        for (uint64_t slot = 1;
             slot + 1 < target_blocks; slot++) {
          const int64_t previous_apparent =
              blockvector_get_apparent_blocknumber(blockvector, slot - 1);
          const int64_t first_apparent =
              blockvector_get_apparent_blocknumber(blockvector, slot);

          if (previous_apparent < 0 || first_apparent < 0
              || first_apparent != previous_apparent + 1) {
            continue;
          }
          const int64_t first_actual = filemirror_actual_blocknumber(
              scalpel_state.filemirror, first_apparent);
          const BlockValidationDecision first_confidence = first_actual < 0
              ? BLOCK_CONFIDENCE_INVALID
              : filemirror_get_blocktype(
                    scalpel_state.filemirror, first_actual,
                    (*candidate)->needleidx);
          const bool first_matches = pass == 0
              ? first_actual >= 0
                    && filemirror_actual_block_is_zero(
                           scalpel_state.filemirror, first_actual)
              : first_confidence < ACCESS_BLOCK_CONFIDENCE;

          if (!first_matches) {
            continue;
          }

          uint64_t end = slot;

          while (end < target_blocks) {
            const int64_t apparent =
                blockvector_get_apparent_blocknumber(blockvector, end);
            const uint64_t relative = end - slot;

            if (relative > (uint64_t)(INT64_MAX - first_apparent)) {
              break;
            }
            const int64_t expected = first_apparent + (int64_t)relative;
            const int64_t actual = filemirror_actual_blocknumber(
                scalpel_state.filemirror, apparent);
            const BlockValidationDecision confidence = actual < 0
                ? BLOCK_CONFIDENCE_INVALID
                : filemirror_get_blocktype(
                      scalpel_state.filemirror, actual,
                      (*candidate)->needleidx);
            const bool matches = pass == 0
                ? actual >= 0
                      && filemirror_actual_block_is_zero(
                             scalpel_state.filemirror, actual)
                : confidence < ACCESS_BLOCK_CONFIDENCE;

            if (apparent < 0 || apparent != expected || !matches) {
              break;
            }
            end++;
          }
          if (end >= target_blocks || end == slot) {
            continue;
          }
          const int64_t following_apparent =
              blockvector_get_apparent_blocknumber(blockvector, end);
          const int64_t following_actual = filemirror_actual_blocknumber(
              scalpel_state.filemirror, following_apparent);
          const BlockValidationDecision following_confidence =
              following_actual < 0 ? BLOCK_CONFIDENCE_INVALID
              : filemirror_get_blocktype(
                    scalpel_state.filemirror, following_actual,
                    (*candidate)->needleidx);

          if (following_apparent
                  == first_apparent + (int64_t)(end - slot)
              && following_confidence >= ACCESS_BLOCK_CONFIDENCE
              && access_reassembly_span_covers_complete_pages(
                     slot, end - slot, current_page_size)) {
            internal_repair_blocks = slot;
            internal_run_width = end - slot;
            internal_repair_from_confidence = pass != 0;
            if (scalpel_state.mode_verbose) {
              lock_fprintf(
                  stdout,
                  "Access complete mapping review selected logical block "
                  "%" PRIu64 ", width %" PRIu64 ", evidence=%s.\n",
                  slot, internal_run_width,
                  internal_repair_from_confidence
                      ? "block confidence" : "physical zero run");
            }
            break;
          }
        }
      }
    }

    if (scalpel_state.mode_verbose && !current_valid) {
      lock_fprintf(
          stdout,
          "Access reconstruction frontier: failure byte %" PRIu64
          ", repair byte %" PRIu64 ", retained blocks %" PRIu64 ".\n",
          current_progress, current_repair_offset, blocks);
    }

    if (current_valid && internal_run_width != 0) {
      const uint64_t target_blocks = CEILDIV(
          target_length, scalpel_state.blocksize);
      int64_t *current_mapping = (int64_t *)malloc(
          target_blocks * sizeof(*current_mapping));

      check_memory_allocation(current_mapping, __LINE__, __FILE__,
                              "Access current mapping");
      access_reassembly_fill_prefix_mapping(
          *candidate, current_mapping, target_blocks);
      unsigned char mapping_digest[SHA256_DIGEST_LENGTH];

      SHA256((const unsigned char *)current_mapping,
             target_blocks * sizeof(*current_mapping), mapping_digest);
      const bool already_reviewed = internal_repair_from_confidence
          && saved->have_last_reviewed_mapping
          && target_length == saved->last_reviewed_target_length
          && internal_repair_blocks == saved->last_reviewed_repair_blocks
          && internal_run_width == saved->last_reviewed_run_width
          && memcmp(mapping_digest, saved->last_reviewed_mapping,
                    sizeof(mapping_digest)) == 0;

      if (!already_reviewed && internal_repair_from_confidence) {
        memcpy(saved->last_reviewed_mapping, mapping_digest,
               sizeof(saved->last_reviewed_mapping));
        saved->last_reviewed_target_length = target_length;
        saved->last_reviewed_repair_blocks = internal_repair_blocks;
        saved->last_reviewed_run_width = internal_run_width;
        saved->have_last_reviewed_mapping = true;
      }
      if (!already_reviewed) {
        (void)access_reassembly_write_mapping_hypothesis(
            *candidate, current_mapping, target_blocks,
            target_length, current_profile);
      }
      free(current_mapping);

      if (already_reviewed) {
        internal_run_width = 0;
      } else {
        resize_blockvector(blockvector, internal_repair_blocks);
        blockvector_set_data_length(
            blockvector,
            internal_repair_blocks * (uint64_t)scalpel_state.blocksize);
        normalize_blockvector(blockvector);
        inflate_blockvector(blockvector);
        saved->retained_blocks = internal_repair_blocks;
        (*candidate)->best_validates_to =
            internal_repair_blocks * (uint64_t)scalpel_state.blocksize - 1;
        blocks = internal_repair_blocks;
        current_valid = false;
        current_progress =
            internal_repair_blocks * (uint64_t)scalpel_state.blocksize;
        current_repair_offset = current_progress;
      }
    }

    if (current_valid) {
      uint64_t extent = target_length;
      AccessProfile resolved_profile = current_profile;

      access_layout_clear(&current_layout);
      if (!scalpel_state.no_defrag) {
        const AccessRecoveryResult tail_result =
            access_reassembly_extend_contiguous_tail(
                work, candidate, uuidp, uuidc, &resolved_profile, state);

        if (tail_result == ACCESS_RECOVERY_INTERRUPTED || !*candidate) {
          return;
        }
        blockvector = (*candidate)->b;
        extent = blockvector_get_data_length(blockvector);
      }
      else {
        blockvector_set_data_length(blockvector, extent);
        resize_blockvector(blockvector,
                           CEILDIV(extent, scalpel_state.blocksize));
      }
      access_assign_candidate_profile(*candidate, resolved_profile);
      if (scalpel_state.no_defrag
          && access_candidate_is_contiguous(*candidate)) {
        (*candidate)->flavor = VALIDATED;
        write_candidate(candidate, false);
      }
      else if (scalpel_state.write_promising) {
        (*candidate)->flavor = PROMISING;
        write_candidate(candidate, false);
      }
      else {
        destroy_candidate(candidate);
      }
      return;
    }
    access_layout_clear(&current_layout);

    uint64_t keep_blocks = CEILDIV(current_progress,
                                   scalpel_state.blocksize);

    if (keep_blocks < 2) {
      keep_blocks = 2;
    }
    if (keep_blocks < saved->retained_blocks) {
      keep_blocks = saved->retained_blocks;
    }
    if (keep_blocks < blocks) {
      resize_blockvector(blockvector, keep_blocks);
      blockvector_set_data_length(
          blockvector, keep_blocks * (uint64_t)scalpel_state.blocksize);
      inflate_blockvector(blockvector);
      blocks = keep_blocks;
    }
    if (reassembly_check_max_size(work->id, *candidate, uuidp, uuidc)) {
      break;
    }

    access_search_scope(*candidate, state);
    saved->iteration_active = true;
    saved->current_progress = current_progress;
    saved->current_repair_offset = current_repair_offset;
    saved->internal_repair_blocks = internal_repair_blocks;
    saved->internal_run_width = internal_run_width;
    saved->internal_repair_from_confidence = internal_repair_from_confidence;

    const uint64_t committed_length =
        blocks * (uint64_t)scalpel_state.blocksize;
    const uint64_t target_blocks = target_length == 0
        ? 0 : CEILDIV(target_length, scalpel_state.blocksize);

    if (target_length > committed_length && target_blocks > blocks
        && target_blocks <= filemirror_apparent_blocks(
                                scalpel_state.filemirror)
        && target_length <= SIZE_MAX) {
      uint8_t *trial_data = (uint8_t *)calloc((size_t)target_length, 1);
      int64_t *trial_mapping = (int64_t *)malloc(
          target_blocks * sizeof(*trial_mapping));
      int64_t *partial_mapping = (int64_t *)malloc(
          target_blocks * sizeof(*partial_mapping));
      int64_t *solution_mapping = (int64_t *)malloc(
          target_blocks * sizeof(*solution_mapping));

      check_memory_allocation(trial_data, __LINE__, __FILE__,
                              "Access reassembly trial data");
      check_memory_allocation(trial_mapping, __LINE__, __FILE__,
                              "Access reassembly trial mapping");
      check_memory_allocation(partial_mapping, __LINE__, __FILE__,
                              "Access reassembly partial mapping");
      check_memory_allocation(solution_mapping, __LINE__, __FILE__,
                              "Access reassembly solution mapping");

      memcpy(trial_data, blockvector_get_data_pointer(blockvector),
             (size_t)committed_length);
      AccessLayout support_layout;
      const bool have_support_layout = access_reassembly_build_usage_layout(
          trial_data, target_length, &support_layout);
      access_reassembly_fill_prefix_mapping(
          *candidate, trial_mapping, blocks);
      access_reassembly_fill_prefix_mapping(
          *candidate, partial_mapping, blocks);
      access_reassembly_fill_prefix_mapping(
          *candidate, solution_mapping, blocks);

      uint64_t partial_progress = current_progress;
      uint64_t partial_repair_offset = current_progress;
      uint64_t partial_mapping_blocks = blocks;
      AccessProfile recovered_profile = current_profile;
      uint64_t iterations = 0;
      uint32_t hypotheses_written = 0;
      bool mapping_committed = false;
      bool strong_hypothesis = false;
      uint64_t trusted_partial_blocks = blocks;

      // A page can expose a broken relationship before the physical gap that
      // caused it. Walk through the intervening Access-supported pages and
      // let the complete gap solver start at the first unsupported run. This
      // is an accelerator only; the exhaustive search at the parser frontier
      // still runs below when the supported boundary is inconclusive.
      uint64_t supported_prefix_blocks = blocks;
      int64_t supported_apparent = trial_mapping[blocks - 1];
      uint64_t supported_gap_width = 0;
      bool supported_gap_found = false;

      // A complete mapping review can locate an embedded physical hole before
      // the candidate is shortened to its repair point. Preserve that result
      // so the gap and displaced-run solvers evaluate the reviewed width
      // directly instead of trying to rediscover it from the shorter prefix.
      if (internal_run_width != 0
          && !internal_repair_from_confidence
          && internal_repair_blocks == blocks) {
        supported_gap_width = internal_run_width;
        supported_gap_found = true;
      }

      // An all-zero run embedded between Access-supported blocks is stronger
      // gap evidence than a low classifier score alone. Prefer that physical
      // boundary, while retaining the confidence-only fallback below for
      // nonzero gaps.
      for (uint64_t slot = 1;
           slot + 1 < blocks && !supported_gap_found; slot++) {
        const int64_t previous_apparent = trial_mapping[slot - 1];
        const int64_t first_apparent = trial_mapping[slot];

        if (previous_apparent < 0 || first_apparent < 0
            || first_apparent != previous_apparent + 1) {
          continue;
        }
        const int64_t first_actual = filemirror_actual_blocknumber(
            scalpel_state.filemirror, first_apparent);

        if (first_actual < 0
            || !filemirror_actual_block_is_zero(
                   scalpel_state.filemirror, first_actual)) {
          continue;
        }

        uint64_t end = slot;

        while (end < blocks) {
          const int64_t apparent = trial_mapping[end];
          const uint64_t relative = end - slot;

          if (relative > (uint64_t)(INT64_MAX - first_apparent)) {
            break;
          }
          const int64_t expected = first_apparent + (int64_t)relative;
          const int64_t actual = filemirror_actual_blocknumber(
              scalpel_state.filemirror, apparent);

          if (apparent < 0 || apparent != expected || actual < 0
              || !filemirror_actual_block_is_zero(
                     scalpel_state.filemirror, actual)) {
            break;
          }
          end++;
        }
        if (end < blocks && end > slot) {
          const int64_t following_apparent = trial_mapping[end];
          const int64_t following_actual = filemirror_actual_blocknumber(
              scalpel_state.filemirror, following_apparent);
          const BlockValidationDecision following_confidence =
              following_actual < 0 ? BLOCK_CONFIDENCE_INVALID
              : filemirror_get_blocktype(
                    scalpel_state.filemirror, following_actual,
                    (*candidate)->needleidx);
          const uint64_t following_relative = end - slot;

          if (following_relative
                  <= (uint64_t)(INT64_MAX - first_apparent)
              && following_apparent
                  == first_apparent + (int64_t)following_relative
              && following_confidence >= ACCESS_BLOCK_CONFIDENCE
              && have_support_layout
              && access_reassembly_span_contains_allocated_page(
                     slot, end - slot, &support_layout)) {
            supported_prefix_blocks = slot;
            supported_apparent = previous_apparent;
            supported_gap_width = end - slot;
            supported_gap_found = true;
          }
        }
      }

      // Relationship failures can precede a later physical hole by many
      // pages. Search the expected contiguous extent for an actual zero run
      // before relying on classifier confidence, materializing every
      // intervening block so reconstruction can begin at the true boundary.
      if (!supported_gap_found && supported_apparent >= 0
          && supported_apparent < INT64_MAX) {
        uint64_t scan_slot = supported_prefix_blocks;
        int64_t scan_apparent = supported_apparent + 1;
        const uint64_t apparent_blocks =
            filemirror_apparent_blocks(scalpel_state.filemirror);

        while (scan_slot + 1 < target_blocks && scan_apparent >= 0
               && (uint64_t)scan_apparent < apparent_blocks) {
          const int64_t scan_actual = filemirror_actual_blocknumber(
              scalpel_state.filemirror, scan_apparent);

          if (scan_actual < 0
              || filemirror_actual_block_covered(
                     scalpel_state.filemirror, scan_actual)
              || apparent_block_in_blockvector(
                     blockvector, scan_apparent)) {
            break;
          }
          if (!filemirror_actual_block_is_zero(
                  scalpel_state.filemirror, scan_actual)) {
            if (!access_reassembly_copy_run(
                    trial_data, target_length, scan_slot,
                    scan_apparent, 1)) {
              break;
            }
            trial_mapping[scan_slot] = scan_apparent;
            scan_slot++;
            scan_apparent++;
          }
          else {
            const uint64_t zero_slot = scan_slot;
            const int64_t zero_apparent = scan_apparent;

            while (scan_slot < target_blocks && scan_apparent >= 0
                   && (uint64_t)scan_apparent < apparent_blocks) {
              const int64_t zero_actual = filemirror_actual_blocknumber(
                  scalpel_state.filemirror, scan_apparent);

              if (zero_actual < 0
                  || !filemirror_actual_block_is_zero(
                         scalpel_state.filemirror, zero_actual)) {
                break;
              }
              scan_slot++;
              scan_apparent++;
            }

            if (scan_slot < target_blocks && scan_apparent >= 0
                && (uint64_t)scan_apparent < apparent_blocks) {
              const int64_t following_actual =
                  filemirror_actual_blocknumber(
                      scalpel_state.filemirror, scan_apparent);

              if (following_actual >= 0
                  && !filemirror_actual_block_is_zero(
                         scalpel_state.filemirror, following_actual)
                  && have_support_layout
                  && access_reassembly_span_contains_allocated_page(
                         zero_slot, scan_slot - zero_slot,
                         &support_layout)) {
                supported_prefix_blocks = zero_slot;
                supported_apparent = zero_apparent - 1;
                supported_gap_width = scan_slot - zero_slot;
                supported_gap_found = supported_gap_width != 0;
              }
            }
            if (supported_gap_found) {
              break;
            }
            for (uint64_t offset = 0;
                 offset < scan_slot - zero_slot; offset++) {
              trial_mapping[zero_slot + offset] =
                  zero_apparent + (int64_t)offset;
            }
          }

          if (access_preparation_poll(
                  work, candidate, uuidp, uuidc, &iterations, state)) {
            access_layout_clear(&support_layout);
            free(solution_mapping);
            free(partial_mapping);
            free(trial_mapping);
            free(trial_data);
            return;
          }
        }
      }

      // First consider a low-confidence run already embedded in the retained
      // contiguous hypothesis. Repairing it replaces the old suffix, so those
      // suffix blocks remain available at their corrected logical positions.
      for (uint64_t slot = 1;
           slot + 1 < blocks && !supported_gap_found; slot++) {
        const int64_t previous_apparent = trial_mapping[slot - 1];
        const int64_t first_apparent = trial_mapping[slot];

        if (previous_apparent < 0 || first_apparent < 0
            || first_apparent != previous_apparent + 1) {
          continue;
        }
        const int64_t first_actual = filemirror_actual_blocknumber(
            scalpel_state.filemirror, first_apparent);
        const BlockValidationDecision first_confidence = first_actual < 0
            ? BLOCK_CONFIDENCE_INVALID
            : filemirror_get_blocktype(
                  scalpel_state.filemirror, first_actual,
                  (*candidate)->needleidx);

        if (first_confidence >= ACCESS_BLOCK_CONFIDENCE) {
          continue;
        }

        uint64_t end = slot;

        while (end < blocks) {
          const int64_t apparent = trial_mapping[end];
          const uint64_t relative = end - slot;

          if (relative > (uint64_t)(INT64_MAX - first_apparent)) {
            break;
          }
          const int64_t expected = first_apparent + (int64_t)relative;

          if (apparent < 0 || apparent != expected) {
            break;
          }
          const int64_t actual = filemirror_actual_blocknumber(
              scalpel_state.filemirror, apparent);
          const BlockValidationDecision confidence = actual < 0
              ? BLOCK_CONFIDENCE_INVALID
              : filemirror_get_blocktype(
                    scalpel_state.filemirror, actual,
                    (*candidate)->needleidx);

          if (confidence >= ACCESS_BLOCK_CONFIDENCE) {
            break;
          }
          end++;
        }
        if (end < blocks && end > slot) {
          const int64_t following_apparent = trial_mapping[end];
          const int64_t following_actual = filemirror_actual_blocknumber(
              scalpel_state.filemirror, following_apparent);
          const BlockValidationDecision following_confidence =
              following_actual < 0 ? BLOCK_CONFIDENCE_INVALID
              : filemirror_get_blocktype(
                    scalpel_state.filemirror, following_actual,
                    (*candidate)->needleidx);

          const uint64_t following_relative = end - slot;

          if (following_relative
                  <= (uint64_t)(INT64_MAX - first_apparent)
              && following_apparent
                  == first_apparent + (int64_t)following_relative
              && following_confidence >= ACCESS_BLOCK_CONFIDENCE
              && have_support_layout
              && access_reassembly_span_contains_allocated_page(
                     slot, end - slot, &support_layout)) {
            supported_prefix_blocks = slot;
            supported_apparent = previous_apparent;
            supported_gap_width = end - slot;
            supported_gap_found = true;
          }
        }
      }

      while (!supported_gap_found
             && supported_prefix_blocks < target_blocks
             && supported_apparent >= 0
             && supported_apparent < INT64_MAX) {
        const int64_t next_apparent = supported_apparent + 1;
        const int64_t next_actual = filemirror_actual_blocknumber(
            scalpel_state.filemirror, next_apparent);

        if (next_actual < 0
            || filemirror_actual_block_covered(
                   scalpel_state.filemirror, next_actual)
            || apparent_block_in_blockvector(
                   blockvector, next_apparent)) {
          break;
        }
        const BlockValidationDecision confidence =
            filemirror_get_blocktype(
                scalpel_state.filemirror, next_actual,
                (*candidate)->needleidx);

        if (confidence < ACCESS_BLOCK_CONFIDENCE) {
          int64_t gap_apparent = next_apparent;
          const uint64_t gap_slot = supported_prefix_blocks;
          const uint64_t apparent_blocks =
              filemirror_apparent_blocks(scalpel_state.filemirror);
          bool bounded_gap = false;

          while (gap_apparent >= 0
                 && (uint64_t)gap_apparent < apparent_blocks) {
            const int64_t gap_actual = filemirror_actual_blocknumber(
                scalpel_state.filemirror, gap_apparent);

            if (gap_actual < 0
                || filemirror_actual_block_covered(
                       scalpel_state.filemirror, gap_actual)
                || apparent_block_in_blockvector(
                       blockvector, gap_apparent)) {
              break;
            }
            const BlockValidationDecision gap_confidence =
                filemirror_get_blocktype(
                    scalpel_state.filemirror, gap_actual,
                    (*candidate)->needleidx);

            if (gap_confidence >= ACCESS_BLOCK_CONFIDENCE) {
              bounded_gap = supported_gap_width != 0;
              break;
            }
            supported_gap_width++;
            gap_apparent++;

            if (access_preparation_poll(
                    work, candidate, uuidp, uuidc, &iterations, state)) {
              access_layout_clear(&support_layout);
              free(solution_mapping);
              free(partial_mapping);
              free(trial_mapping);
              free(trial_data);
              return;
            }
          }
          if (bounded_gap
              && have_support_layout
              && access_reassembly_span_contains_allocated_page(
                     gap_slot, supported_gap_width, &support_layout)) {
            supported_gap_found = true;
            break;
          }
          if (!bounded_gap
              || !access_reassembly_copy_run(
                     trial_data, target_length, gap_slot,
                     next_apparent, supported_gap_width)) {
            break;
          }
          for (uint64_t offset = 0;
               offset < supported_gap_width; offset++) {
            trial_mapping[gap_slot + offset] =
                next_apparent + (int64_t)offset;
          }
          supported_prefix_blocks += supported_gap_width;
          supported_apparent += (int64_t)supported_gap_width;
          supported_gap_width = 0;
          continue;
        }
        if (!access_reassembly_copy_run(
                trial_data, target_length, supported_prefix_blocks,
                next_apparent, 1)) {
          break;
        }
        trial_mapping[supported_prefix_blocks] = next_apparent;
        supported_prefix_blocks++;
        supported_apparent = next_apparent;

        if (access_preparation_poll(
                work, candidate, uuidp, uuidc, &iterations, state)) {
          access_layout_clear(&support_layout);
          free(solution_mapping);
          free(partial_mapping);
          free(trial_mapping);
          free(trial_data);
          return;
        }
      }

      access_layout_clear(&support_layout);
      AccessRecoveryResult recovery = ACCESS_RECOVERY_NO_MATCH;

      if (supported_gap_found) {
        if (scalpel_state.mode_verbose) {
          lock_fprintf(
              stdout,
              "Access supported gap boundary: logical block %" PRIu64
              ", apparent block %" PRId64 ", width %" PRIu64 ".\n",
              supported_prefix_blocks, supported_apparent + 1,
              supported_gap_width);
        }

        recovery = access_reassembly_try_gap(
            work, candidate, uuidp, uuidc, supported_prefix_blocks,
            target_blocks, target_length, current_progress,
            supported_gap_width, trial_data, trial_mapping,
            partial_mapping, solution_mapping,
            &partial_progress, &partial_repair_offset,
            &partial_mapping_blocks, &recovered_profile,
            &iterations, &hypotheses_written,
            &mapping_committed, state);
        if (recovery == ACCESS_RECOVERY_INTERRUPTED || !*candidate) {
          free(solution_mapping);
          free(partial_mapping);
          free(trial_mapping);
          free(trial_data);
          return;
        }
        if (mapping_committed) {
          free(solution_mapping);
          free(partial_mapping);
          free(trial_mapping);
          free(trial_data);
          continue;
        }

        uint64_t displaced_progress = current_progress;
        uint64_t displaced_repair_offset = current_repair_offset;
        uint64_t displaced_mapping_blocks = blocks;
        AccessProfile displaced_profile = current_profile;
        bool displaced_strong = false;
        bool displaced_has_file_local_support = false;
        bool displaced_committed = false;

        access_reassembly_fill_prefix_mapping(
            *candidate, trial_mapping, blocks);
        access_reassembly_fill_prefix_mapping(
            *candidate, solution_mapping, blocks);
        memcpy(trial_data, blockvector_get_data_pointer(blockvector),
               (size_t)committed_length);

        const AccessRecoveryResult displaced_recovery =
            access_reassembly_try_displaced_run(
                work, candidate, uuidp, uuidc, supported_prefix_blocks,
                target_blocks, target_length, supported_gap_width,
                trial_data, trial_mapping, solution_mapping,
                &displaced_progress, &displaced_repair_offset,
                &displaced_mapping_blocks, &displaced_profile,
                &iterations, &hypotheses_written, &displaced_strong,
                &displaced_has_file_local_support,
                &displaced_committed, state);

        if (displaced_recovery == ACCESS_RECOVERY_INTERRUPTED
            || !*candidate) {
          free(solution_mapping);
          free(partial_mapping);
          free(trial_mapping);
          free(trial_data);
          return;
        }
        if (displaced_committed) {
          free(solution_mapping);
          free(partial_mapping);
          free(trial_mapping);
          free(trial_data);
          continue;
        }
        if (displaced_strong) {
          free(solution_mapping);
          free(partial_mapping);
          free(trial_mapping);
          free(trial_data);
          destroy_candidate(candidate);
          return;
        }
        if (displaced_mapping_blocks > blocks) {
          // A zero-filled physical hole can represent either a removed gap or
          // the original position of a displaced run. Prefer the displaced
          // repair only when its structurally screened mapping reaches more
          // supported logical blocks than the ordered alternative and repairs
          // a live page with file-local structure and isolated boundaries.
          const bool displaced_better = partial_mapping_blocks <= blocks
              || (displaced_has_file_local_support
                  && displaced_mapping_blocks > partial_mapping_blocks);

          if (scalpel_state.mode_verbose) {
            lock_fprintf(
                stdout,
                "Access physical reconstruction alternatives at logical "
                "block %" PRIu64 ": ordered blocks=%" PRIu64
                ", progress=%" PRIu64 ", repair=%" PRIu64
                "; displaced blocks=%" PRIu64 ", progress=%" PRIu64
                ", repair=%" PRIu64 "; selected=%s.\n",
                supported_prefix_blocks, partial_mapping_blocks,
                partial_progress, partial_repair_offset,
                displaced_mapping_blocks, displaced_progress,
                displaced_repair_offset,
                displaced_better ? "displaced" : "ordered");
          }
          if (displaced_better) {
            memcpy(partial_mapping, solution_mapping,
                   target_blocks * sizeof(*partial_mapping));
            partial_progress = displaced_progress;
            partial_repair_offset = displaced_repair_offset;
            partial_mapping_blocks = displaced_mapping_blocks;
            recovered_profile = displaced_profile;
            recovery = displaced_recovery;
          }
        }
      }

      if (!supported_gap_found || partial_mapping_blocks <= blocks) {
        access_reassembly_fill_prefix_mapping(
            *candidate, trial_mapping, blocks);
        memcpy(trial_data, blockvector_get_data_pointer(blockvector),
               (size_t)committed_length);
        recovery = access_reassembly_try_gap(
            work, candidate, uuidp, uuidc, blocks, target_blocks,
            target_length, current_progress, UINT64_MAX, trial_data,
            trial_mapping, partial_mapping, solution_mapping,
            &partial_progress, &partial_repair_offset,
            &partial_mapping_blocks, &recovered_profile,
            &iterations, &hypotheses_written, &mapping_committed, state);

        if (recovery == ACCESS_RECOVERY_INTERRUPTED || !*candidate) {
          free(solution_mapping);
          free(partial_mapping);
          free(trial_mapping);
          free(trial_data);
          return;
        }
        if (mapping_committed) {
          free(solution_mapping);
          free(partial_mapping);
          free(trial_mapping);
          free(trial_data);
          continue;
        }
      }

      if (partial_mapping_blocks <= blocks) {
        access_reassembly_fill_prefix_mapping(
            *candidate, trial_mapping, blocks);
        memcpy(trial_data, blockvector_get_data_pointer(blockvector),
               (size_t)committed_length);
        bool displaced_strong = false;
        bool displaced_has_file_local_support = false;
        bool displaced_committed = false;

        recovery = access_reassembly_try_displaced_run(
            work, candidate, uuidp, uuidc, blocks, target_blocks,
            target_length, UINT64_MAX, trial_data, trial_mapping,
            partial_mapping, &partial_progress, &partial_repair_offset,
            &partial_mapping_blocks, &recovered_profile,
            &iterations, &hypotheses_written,
            &displaced_strong, &displaced_has_file_local_support,
            &displaced_committed, state);
        strong_hypothesis = displaced_strong;
        if (recovery == ACCESS_RECOVERY_INTERRUPTED || !*candidate) {
          free(solution_mapping);
          free(partial_mapping);
          free(trial_mapping);
          free(trial_data);
          return;
        }
        if (displaced_committed) {
          free(solution_mapping);
          free(partial_mapping);
          free(trial_mapping);
          free(trial_data);
          continue;
        }
        if (strong_hypothesis) {
          free(solution_mapping);
          free(partial_mapping);
          free(trial_mapping);
          free(trial_data);
          destroy_candidate(candidate);
          return;
        }
      }

      uint64_t partial_change_start = blocks;

      for (uint64_t slot = 0;
           slot < blocks && slot < target_blocks; slot++) {
        if (partial_mapping[slot]
            != blockvector_get_apparent_blocknumber(blockvector, slot)) {
          partial_change_start = slot;
          break;
        }
      }

      bool has_physical_gap = false;

      if (partial_mapping_blocks > blocks) {
        for (uint64_t slot = 1;
             slot < partial_mapping_blocks; slot++) {
          const int64_t previous = partial_mapping[slot - 1];
          const int64_t apparent = partial_mapping[slot];

          if (previous >= 0 && apparent >= 0
              && (previous == INT64_MAX || apparent != previous + 1)) {
            has_physical_gap = true;
            break;
          }
        }
      }

      if (has_physical_gap) {
        trusted_partial_blocks = partial_mapping_blocks;
      }

      if (recovery == ACCESS_RECOVERY_INTERRUPTED || !*candidate) {
        free(solution_mapping);
        free(partial_mapping);
        free(trial_mapping);
        free(trial_data);
        return;
      }

      // Retain the Access-supported mapping through the next physical
      // discontinuity so later damage can be repaired in a subsequent pass.
      if (!strong_hypothesis && trusted_partial_blocks > blocks
          && *candidate) {
        resize_blockvector(blockvector, trusted_partial_blocks);
        for (uint64_t slot = partial_change_start;
             slot < trusted_partial_blocks; slot++) {
          blockvector_set_apparent_blocknumber(
              blockvector, slot, partial_mapping[slot]);
        }
        blockvector_set_data_length(
            blockvector,
            trusted_partial_blocks * (uint64_t)scalpel_state.blocksize);
        normalize_blockvector(blockvector);
        inflate_blockvector(blockvector);
        saved->retained_blocks = trusted_partial_blocks;
        (*candidate)->best_validates_to =
            trusted_partial_blocks * (uint64_t)scalpel_state.blocksize - 1;

        free(solution_mapping);
        free(partial_mapping);
        free(trial_mapping);
        free(trial_data);
        continue;
      }
      if (strong_hypothesis) {
        free(solution_mapping);
        free(partial_mapping);
        free(trial_mapping);
        free(trial_data);
        destroy_candidate(candidate);
        return;
      }

      free(solution_mapping);
      free(partial_mapping);
      free(trial_mapping);
      free(trial_data);
    }

    const uint64_t trial_slot = blocks;
    const int64_t previous_apparent =
        blockvector_get_apparent_blocknumber(blockvector, trial_slot - 1);
    const int64_t image_blocks = filemirror_apparent_blocks(
        scalpel_state.filemirror);
    if (!saved->fallback_started) {
      saved->fallback_started = true;
      saved->next_apparent = 0;
      saved->best_apparent = -1;
      saved->best_progress = current_progress;
      saved->best_confidence = BLOCK_CONFIDENCE_INVALID;
      saved->best_distance = INT64_MAX;
      saved->best_reserved = INT64_MAX;
      saved->best_valid = false;
    }
    uint64_t examined = 0;

    resize_blockvector(blockvector, trial_slot + 1);
    blockvector_set_apparent_blocknumber(blockvector, trial_slot, -1);

    for (int64_t apparent = (int64_t)saved->next_apparent; apparent < image_blocks; apparent++) {
      if (++examined % UINT64_C(256) == 0) {
        resize_blockvector(blockvector, trial_slot);
        blockvector_set_data_length(blockvector, committed_length);
        if (reassembly_check_kill_queue(work, candidate, uuidp, uuidc)) {
          return;
        }
        if (atomic_load_explicit(&REASS_RETURN_TO_IDLE, memory_order_acquire)) {
          saved->next_apparent = (uint64_t)apparent;
          access_search_save(*candidate, state);
          if (reassembly_time_to_checkpoint(work->id, *candidate, uuidp, uuidc)) {
            return;
          }
        }
        resize_blockvector(blockvector, trial_slot + 1);
        blockvector_set_apparent_blocknumber(blockvector, trial_slot, -1);
      }
      const int64_t actual = filemirror_actual_blocknumber(
          scalpel_state.filemirror, apparent);

      if (actual < 0
          || filemirror_actual_block_covered(scalpel_state.filemirror,
                                             actual)
          || apparent_block_in_blockvector(blockvector, apparent)) {
        continue;
      }

      const BlockValidationDecision confidence = filemirror_get_blocktype(
          scalpel_state.filemirror, actual, (*candidate)->needleidx);

      if (confidence == BLOCK_CONFIDENCE_INVALID) {
        continue;
      }

      blockvector_set_apparent_blocknumber(blockvector, trial_slot, apparent);
      const uint64_t old_length = inflate_blockvector_single_block(
          blockvector, trial_slot);
      AccessLayout trial_layout;
      const bool trial_valid = access_parse(
          (const uint8_t *)blockvector_get_data_pointer(blockvector),
          blockvector_get_data_length(blockvector), &trial_layout);
      const uint64_t trial_progress = trial_valid
          ? trial_layout.inferred_size : trial_layout.failure_offset;

      access_layout_clear(&trial_layout);
      deflate_blockvector_single_block(blockvector, trial_slot, old_length);

      const int64_t distance = apparent >= previous_apparent
          ? apparent - previous_apparent : INT64_MAX;
      const int64_t reserved = scalpel_state.reservations
          ? filemirror_actual_block_reserved(scalpel_state.filemirror,
                                             actual) : 0;

      const bool advances = trial_valid || trial_progress > current_progress;

      if (advances
          && ((trial_valid && !saved->best_valid)
              || (trial_valid == saved->best_valid
                  && (distance < saved->best_distance
                      || (distance == saved->best_distance
                          && confidence > saved->best_confidence)
                      || (distance == saved->best_distance
                          && confidence == saved->best_confidence
                          && reserved < saved->best_reserved)
                      || (distance == saved->best_distance
                          && confidence == saved->best_confidence
                          && reserved == saved->best_reserved
                          && trial_progress > saved->best_progress))))) {
        saved->best_apparent = apparent;
        saved->best_progress = trial_progress;
        saved->best_confidence = confidence;
        saved->best_distance = distance;
        saved->best_reserved = reserved;
        saved->best_valid = trial_valid;
      }

      if (advances && distance == 1) {
        break;
      }

      saved->next_apparent = (uint64_t)apparent + 1;
    }

    if (saved->best_apparent < 0
        || (!saved->best_valid && saved->best_progress <= current_progress)) {
      resize_blockvector(blockvector, trial_slot);
      blockvector_set_data_length(blockvector, committed_length);
      break;
    }

    blockvector_set_apparent_blocknumber(blockvector, trial_slot,
                                         saved->best_apparent);
    inflate_blockvector_single_block(blockvector, trial_slot);
    blockvector_set_data_length(
        blockvector, (trial_slot + 1)
                         * (uint64_t)scalpel_state.blocksize);
    saved->retained_blocks = trial_slot + 1;
    if (saved->best_progress != 0) {
      (*candidate)->best_validates_to = saved->best_progress - 1;
    }
  }

  if (*candidate) {
    if (scalpel_state.write_promising) {
      (*candidate)->flavor = PROMISING;
      write_candidate(candidate, false);
    }
    else {
      destroy_candidate(candidate);
    }
  }
}



// Reset speculative search state, retaining established extent and review history.
static inline void access_search_reset(AccessCarveState *state) {
  for (size_t i = 0; i < 4; i++) {
    AccessSolverState *record = state->solvers[i];
    if (record) {
      access_layout_clear(&record->layout);
      free(record->partial_mapping);
      free(record->solution_mapping);
      free(record);
      state->solvers[i] = NULL;
    }
  }
  state->progress.iteration_active = false;
  state->progress.preparation_cursor = 0;
  state->progress.fallback_started = false;
  state->progress.tail_started = false;
}

static inline XXH128_hash_t access_prefix_view(CarveInfo *candidate) {
  XXH3_state_t hash;
  XXH3_128bits_reset(&hash);
  const uint64_t geometry[] = {
    blockvector_get_num_blocks(candidate->b), blockvector_get_data_length(candidate->b),
    scalpel_state.blocksize, candidate->needleidx
  };
  XXH3_128bits_update(&hash, geometry, sizeof(geometry));
  for (uint64_t i = 0; i < geometry[0]; i++) {
    const int64_t actual = blockvector_get_actual_blocknumber(candidate->b, i);
    XXH3_128bits_update(&hash, &actual, sizeof(actual));
  }
  XXH3_128bits_update(&hash, blockvector_get_data_pointer(candidate->b), (size_t)geometry[1]);
  return XXH3_128bits_digest(&hash);
}

static inline void access_search_scope(CarveInfo *candidate, AccessCarveState *state) {
  const XXH128_hash_t prefix = access_prefix_view(candidate);
  if (!XXH128_isEqual(prefix, state->progress.prefix_view)) {
    access_search_reset(state);
    state->progress.prefix_view = prefix;
  }
}

static inline void access_search_save(CarveInfo *candidate, AccessCarveState *state) {
  state->progress.prefix_view = access_prefix_view(candidate);
  state->progress.view = validator_search_view(candidate);
  carve_put_state(candidate->carvehashkey, state);
}

// Preparatory scans reconstruct inexpensive scratch data on entry. Do not
// checkpoint again at an already completed preparation step; expensive solver
// trials resume directly from their separately retained cursors and rankings.
static inline bool access_preparation_poll(ThreadWork *work, CarveInfo **candidate,
    uuid_string_t uuidp, uuid_string_t uuidc, uint64_t *iterations, AccessCarveState *state) {
  if (*iterations < state->progress.preparation_cursor) {
    (*iterations)++;
    return *iterations % ACCESS_REASSEMBLY_POLL_INTERVAL == 0
        && reassembly_check_kill_queue(work, candidate, uuidp, uuidc);
  }
  state->progress.preparation_cursor = *iterations + 1;
  return access_reassembly_poll(work, candidate, uuidp, uuidc, iterations, state);
}

// A record owns its best mappings. Temporary trial bytes are reconstructed from
// the unchanged image; no pointers into the file mirror are checkpointed.
static inline AccessSolverState *access_solver_state(
    AccessCarveState *state, unsigned index, CarveInfo *candidate,
    uint64_t prefix_blocks, uint64_t total_blocks, uint64_t target_length,
    uint64_t preferred, uint64_t partial_progress, uint64_t partial_repair_offset,
    uint64_t partial_mapping_blocks, AccessProfile profile, uint32_t hypotheses_written,
    const int64_t *partial_mapping) {
  AccessSolverState *record = state->solvers[index];
  if (record && (record->progress.prefix_blocks != prefix_blocks
      || record->progress.total_blocks != total_blocks
      || record->progress.target_length != target_length
      || record->progress.preferred != preferred)) {
    access_layout_clear(&record->layout);
    free(record->partial_mapping);
    free(record->solution_mapping);
    free(record);
    state->solvers[index] = NULL;
    record = NULL;
  }
  if (!record) {
    record = calloc(1, sizeof(*record));
    check_memory_allocation(record, __LINE__, __FILE__, "Access solver progress");
    state->solvers[index] = record;
    AccessSolverProgress *p = &record->progress;
    p->prefix_blocks = prefix_blocks;
    p->total_blocks = total_blocks;
    p->target_length = target_length;
    p->preferred = preferred;
    p->partial_progress = partial_progress;
    p->partial_repair_offset = partial_repair_offset;
    p->partial_mapping_blocks = partial_mapping_blocks;
    p->profile = profile;
    p->hypotheses_written = hypotheses_written;
    p->gap.partial_skip = UINT64_MAX;
    p->gap.complete_skip = UINT64_MAX;
    p->displaced.best_reservations = INT64_MAX;
    p->displaced.best_run_length = UINT64_MAX;
    p->displaced.best_partial_run_length = UINT64_MAX;
    p->displaced.best_partial_source = UINT64_MAX;
    p->displaced.best_partial_rank.reservations = INT64_MAX;
    for (size_t i = 0; i < ACCESS_REASSEMBLY_STRUCTURE_LEVELS; i++) {
      p->displaced.hypothesis_reservations[i] = INT64_MAX;
      p->displaced.hypothesis_run_length[i] = UINT64_MAX;
    }
    record->partial_mapping = malloc(total_blocks * sizeof(*record->partial_mapping));
    record->solution_mapping = malloc(total_blocks * sizeof(*record->solution_mapping));
    check_memory_allocation(record->partial_mapping, __LINE__, __FILE__, "Access retained partial");
    check_memory_allocation(record->solution_mapping, __LINE__, __FILE__, "Access retained solution");
    for (uint64_t i = 0; i < total_blocks; i++) {
      record->partial_mapping[i] = i < partial_mapping_blocks ? partial_mapping[i] : -1;
      record->solution_mapping[i] = i < blockvector_get_num_blocks(candidate->b)
          ? blockvector_get_apparent_blocknumber(candidate->b, i) : -1;
    }
  }
  return record;
}

static inline void access_free_carve_state(void **state) {
  if (state && *state) {
    access_search_reset(*state);
    free(*state);
    *state = NULL;
  }
}

static inline void *access_clone_carve_state(const void *state) {
  if (!state) {
    return NULL;
  }
  const AccessCarveState *saved = state;
  AccessCarveState *copy = calloc(1, sizeof(*copy));
  check_memory_allocation(copy, __LINE__, __FILE__, "Access state clone");
  copy->progress = saved->progress;
  for (size_t i = 0; i < 4; i++) {
    const AccessSolverState *source = saved->solvers[i];
    if (!source) {
      continue;
    }
    AccessSolverState *record = malloc(sizeof(*record));
    check_memory_allocation(record, __LINE__, __FILE__, "Access solver clone");
    *record = *source;
    copy->solvers[i] = record;
    const size_t bytes = source->progress.total_blocks * sizeof(int64_t);
    record->partial_mapping = malloc(bytes);
    record->solution_mapping = malloc(bytes);
    check_memory_allocation(record->partial_mapping, __LINE__, __FILE__, "Access partial clone");
    check_memory_allocation(record->solution_mapping, __LINE__, __FILE__, "Access solution clone");
    memcpy(record->partial_mapping, source->partial_mapping, bytes);
    memcpy(record->solution_mapping, source->solution_mapping, bytes);
    if (source->layout.used_pages) {
      record->layout.used_pages = malloc(source->layout.available_pages);
      check_memory_allocation(record->layout.used_pages, __LINE__, __FILE__, "Access usage clone");
      memcpy(record->layout.used_pages, source->layout.used_pages, source->layout.available_pages);
    }
  }
  return copy;
}

static inline size_t access_sizeof_carve_state(const void *state) {
  const AccessCarveState *saved = state;
  size_t size = saved ? sizeof(*saved) : 0;
  for (size_t i = 0; saved && i < 4; i++) {
    const AccessSolverState *record = saved->solvers[i];
    if (record) {
      size += sizeof(*record) + 2 * record->progress.total_blocks * sizeof(int64_t);
      if (record->layout.used_pages) {
        size += record->layout.available_pages;
      }
    }
  }
  return size;
}

static inline void access_print_carve_state(const void *state) {
  const AccessCarveState *saved = state;
  if (saved) {
    printf("Access search: retained=%" PRIu64 " target=%" PRIu64 " next=%" PRIu64 "\n",
           saved->progress.retained_blocks, saved->progress.retained_target_length,
           saved->progress.next_apparent);
    for (size_t i = 0; i < 4; i++) {
      const AccessSolverState *record = saved->solvers[i];
      if (record) {
        printf("  solver=%zu done=%u gap=%" PRIu64 " run=%" PRIu64 " source=%" PRIu64 "\n",
               i, (unsigned)record->progress.finished, record->progress.gap.next_skip,
               record->progress.displaced.next_run, record->progress.displaced.next_source);
      }
    }
  }
}

static inline bool access_serialize_carve_state(void **state, FILE *fp, StateSerialization mode) {
  if (!state || !fp || (mode == SERIALIZE && !*state)) {
    return false;
  }
  AccessCarveState *saved = mode == SERIALIZE ? *state : calloc(1, sizeof(*saved));
  check_memory_allocation(saved, __LINE__, __FILE__, "Access checkpoint state");
  if (mode == SERIALIZE) {
    if (fwrite(&saved->progress, sizeof(saved->progress), 1, fp) != 1) {
      return false;
    }
  }
  else if (fread(&saved->progress, sizeof(saved->progress), 1, fp) != 1
      || saved->progress.magic != ACCESS_SEARCH_MAGIC
      || saved->progress.retained_target_length > ACCESS_MAXIMUM_DATABASE_SIZE
      || saved->progress.next_apparent > INT64_MAX) {
    access_free_carve_state((void **)&saved);
    return false;
  }
  for (size_t i = 0; i < 4; i++) {
    uint8_t present = saved->solvers[i] != NULL;
    if (mode == SERIALIZE) {
      if (fwrite(&present, sizeof(present), 1, fp) != 1) {
        return false;
      }
    }
    else if (fread(&present, sizeof(present), 1, fp) != 1 || present > 1) {
      goto invalid;
    }
    if (!present) {
      continue;
    }
    if (mode == DESERIALIZE) {
      saved->solvers[i] = calloc(1, sizeof(*saved->solvers[i]));
      check_memory_allocation(saved->solvers[i], __LINE__, __FILE__, "Access restored solver");
    }
    AccessSolverState *record = saved->solvers[i];
    AccessSolverProgress *p = &record->progress;
    uint8_t have_usage = record->layout.used_pages != NULL;
    if (mode == SERIALIZE) {
      if (fwrite(p, sizeof(*p), 1, fp) != 1
          || fwrite(&record->layout, offsetof(AccessLayout, used_pages), 1, fp) != 1
          || fwrite(&have_usage, sizeof(have_usage), 1, fp) != 1) {
        return false;
      }
    }
    else {
      if (fread(p, sizeof(*p), 1, fp) != 1
          || p->target_length == 0 || p->target_length > ACCESS_MAXIMUM_DATABASE_SIZE
          || p->total_blocks == 0 || p->total_blocks > p->target_length
          || p->total_blocks > SIZE_MAX / sizeof(int64_t)
          || p->prefix_blocks == 0 || p->prefix_blocks >= p->total_blocks
          || p->partial_mapping_blocks > p->total_blocks
          || p->displaced.next_run > p->total_blocks
          || p->displaced.next_source > INT64_MAX || p->gap.next_skip > INT64_MAX
          || p->displaced.best_source_count > ACCESS_REASSEMBLY_HYPOTHESIS_LIMIT
          || p->displaced.best_partial_blocks > p->total_blocks
          || (p->displaced.have_best
              && (p->displaced.best_run_length == 0
                  || p->displaced.best_run_length > p->total_blocks - p->prefix_blocks))
          || (p->displaced.have_partial
              && (p->displaced.best_partial_run_length == 0
                  || p->displaced.best_partial_run_length > p->total_blocks - p->prefix_blocks))
          || (unsigned)p->profile > ACCESS_PROFILE_MPD
          || (unsigned)p->result > ACCESS_RECOVERY_INTERRUPTED
          || fread(&record->layout, offsetof(AccessLayout, used_pages), 1, fp) != 1
          || record->layout.available_pages > ACCESS_MAXIMUM_DATABASE_SIZE / ACCESS_JET3_PAGE_SIZE
          || fread(&have_usage, sizeof(have_usage), 1, fp) != 1 || have_usage > 1) {
        goto invalid;
      }
      for (size_t level = 0; level < ACCESS_REASSEMBLY_STRUCTURE_LEVELS; level++) {
        if (p->displaced.hypothesis_count[level] > ACCESS_REASSEMBLY_HYPOTHESIS_LIMIT) {
          goto invalid;
        }
        for (size_t item = 0; item < p->displaced.hypothesis_count[level]; item++) {
          if (p->displaced.hypothesis_run_lengths[level][item] == 0
              || p->displaced.hypothesis_run_lengths[level][item] > p->total_blocks - p->prefix_blocks
              || p->displaced.hypothesis_sources[level][item] > INT64_MAX
              || (unsigned)p->displaced.hypothesis_profiles[level][item] > ACCESS_PROFILE_MPD) {
            goto invalid;
          }
        }
      }
      const uint64_t bytes = p->total_blocks * (2 * sizeof(int64_t))
          + (have_usage ? record->layout.available_pages : 0);
      const off_t position = ftello(fp);
      if (position >= 0 && fseeko(fp, 0, SEEK_END) == 0) {
        const off_t end = ftello(fp);
        if (fseeko(fp, position, SEEK_SET) != 0 || end < position
            || (uint64_t)(end - position) < bytes) {
          goto invalid;
        }
      }
      record->partial_mapping = malloc(p->total_blocks * sizeof(int64_t));
      record->solution_mapping = malloc(p->total_blocks * sizeof(int64_t));
      check_memory_allocation(record->partial_mapping, __LINE__, __FILE__, "Access restored partial");
      check_memory_allocation(record->solution_mapping, __LINE__, __FILE__, "Access restored solution");
      if (have_usage) {
        record->layout.used_pages = malloc(record->layout.available_pages);
        check_memory_allocation(record->layout.used_pages, __LINE__, __FILE__, "Access restored usage");
      }
    }
    if (mode == SERIALIZE) {
      if (fwrite(record->partial_mapping, sizeof(int64_t), p->total_blocks, fp) != p->total_blocks
          || fwrite(record->solution_mapping, sizeof(int64_t), p->total_blocks, fp) != p->total_blocks
          || (have_usage && fwrite(record->layout.used_pages, 1, record->layout.available_pages, fp)
                            != record->layout.available_pages)) {
        return false;
      }
    }
    else if (fread(record->partial_mapping, sizeof(int64_t), p->total_blocks, fp) != p->total_blocks
        || fread(record->solution_mapping, sizeof(int64_t), p->total_blocks, fp) != p->total_blocks
        || (have_usage && fread(record->layout.used_pages, 1, record->layout.available_pages, fp)
                          != record->layout.available_pages)) {
      goto invalid;
    }
    if (mode == DESERIALIZE) {
      for (uint64_t slot = 0; slot < p->total_blocks; slot++) {
        if (record->partial_mapping[slot] < -1 || record->solution_mapping[slot] < -1) {
          goto invalid;
        }
      }
    }
  }
  if (mode == DESERIALIZE) {
    *state = saved;
  }
  return true;
invalid:
  access_free_carve_state((void **)&saved);
  return false;
}

#endif
