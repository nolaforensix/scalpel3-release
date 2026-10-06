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

#if !defined(SCALPEL_SQLITE_H)
#define SCALPEL_SQLITE_H

#include "scalpel.h"

#include <ctype.h>
#include <inttypes.h>
#include <limits.h>
#include <sqlite3.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define SQLITE_FILE_SIGNATURE                "SQLite format 3\000"
#define SQLITE_FILE_SIGNATURE_SIZE           UINT64_C(16)
#define SQLITE_FILE_HEADER_SIZE              UINT64_C(100)
#define SQLITE_MINIMUM_PAGE_SIZE             UINT32_C(512)
#define SQLITE_MAXIMUM_PAGE_SIZE             UINT32_C(65536)
#define SQLITE_MINIMUM_USABLE_SIZE           UINT32_C(480)
#define SQLITE_REASSEMBLY_POLL_INTERVAL       UINT64_C(8)
#define SQLITE_REASSEMBLY_PROGRESS_INTERVAL   UINT64_C(4096)
#define SQLITE_FAST_PROBE_MAXIMUM_GAP_BLOCKS  UINT64_C(8)
#define SQLITE_FAST_PROBE_MAXIMUM_RUN_BLOCKS  UINT64_C(8)
#define SQLITE_GAP_GRID_SAMPLES                UINT64_C(32)
#define SQLITE_GAP_LOCAL_MINIMUM_SUPPORT       UINT64_C(8)
#define SQLITE_MULTI_REGION_MINIMUM_SUPPORT    UINT64_C(2)
#define SQLITE_DIRECT_OOO_MINIMUM_SUPPORT      UINT64_C(16)
#define SQLITE_PAGE_TRANSITION_LIMIT           UINT64_C(8)
#define SQLITE_COMPOSED_REPAIR_PROBE_LIMIT     UINT64_C(64)
#define SQLITE_COMPOSED_HYPOTHESIS_LIMIT       UINT64_C(128)
#define SQLITE_PAGE_CONFIDENCE                 70
#define SQLITE_CARVE_STATE_MAGIC              UINT32_C(0x53514c33)
#define SQLITE_CARVE_STATE_VERSION            UINT32_C(12)

typedef struct SqliteLayout {
  uint64_t extent;
  uint32_t page_size;
  uint32_t usable_size;
  uint32_t page_count;
  uint32_t largest_root_page;
} SqliteLayout;

typedef struct SqliteIntegrity {
  uint32_t error_count;
  uint32_t first_page;
  uint32_t last_page;
  int result_code;
  bool valid;
} SqliteIntegrity;

typedef struct SqliteCheckContext {
  bool custom_collation_requested;
  bool cell_diagnostic_found;
  uint32_t cell_page;
  uint32_t cell_index;
} SqliteCheckContext;

typedef enum SqliteRepairResult {
  SQLITE_REPAIR_NO_MATCH = 0,
  SQLITE_REPAIR_MATCH = 1,
  SQLITE_REPAIR_STOPPED = 2,
  // Structural ranking still requires the caller's full integrity check.
  SQLITE_REPAIR_PLAUSIBLE = 3,
  // Structurally clean alternatives were preserved without selecting one as authoritative.
  SQLITE_REPAIR_PRESERVED = 4
} SqliteRepairResult;

typedef enum SqliteSearchStage {
  SQLITE_SEARCH_INITIAL_PROBES = 0,
  SQLITE_SEARCH_RANKED_GAP_OOO = 1,
  SQLITE_SEARCH_BASE_GAP = 2,
  SQLITE_SEARCH_BEST_GAP_OOO = 3,
  SQLITE_SEARCH_BASE_OOO = 4,
  SQLITE_SEARCH_BEST_OOO_GAP = 5,
  SQLITE_SEARCH_EXHAUSTIVE_GAP_OOO = 6,
  SQLITE_SEARCH_MULTI_REGION = 7,
  SQLITE_SEARCH_COMPLETE = 8
} SqliteSearchStage;

typedef struct SqliteSearchCursor {
  uint64_t pass;
  uint64_t width;
  uint64_t source;
} SqliteSearchCursor;

typedef struct SqliteRepairDescriptor {
  uint64_t target;
  uint64_t width;
  uint64_t source;
  uint32_t valid;
  uint32_t reserved;
} SqliteRepairDescriptor;

typedef struct SqliteRepairList {
  SqliteRepairDescriptor *repairs;
  uint64_t count;
  uint64_t capacity;
  // Zero retains every evidence-ranked repair. With reservations enabled, a nonzero limit applies
  // independently to reserved and unreserved sources so either class cannot crowd out the other.
  uint64_t limit;
  uint64_t reserved_count;
  uint64_t unreserved_count;
  bool allocation_failed;
  // A prior OOO repair can enclose another unused source inside the mapping envelope.
  bool include_internal_sources;
} SqliteRepairList;

typedef struct SqliteCarveState {
  uint32_t magic;
  uint32_t version;
  uint32_t stage;
  uint32_t probe_step;
  uint64_t extent;
  uint64_t total_blocks;
  uint64_t apparent_blocks;
  uint64_t base_mapping_hash;
  uint64_t preferred_target;
  SqliteSearchCursor cursor;
  SqliteSearchCursor outer_cursor;
  SqliteRepairDescriptor best_gap;
  SqliteRepairDescriptor best_ooo;
  SqliteRepairDescriptor active_outer_gap;
  SqliteIntegrity baseline_integrity;
  SqliteIntegrity best_gap_integrity;
  SqliteIntegrity best_ooo_integrity;
} SqliteCarveState;

static inline uint16_t sqlite_read_be16(const uint8_t *data);
static inline uint32_t sqlite_read_be32(const uint8_t *data);
static inline bool sqlite_read_varint(const uint8_t *data,
                                      uint64_t length,
                                      uint64_t *value,
                                      uint32_t *consumed);
static inline bool sqlite_power_of_two(uint32_t value);
static inline bool sqlite_parse_header(const uint8_t *data, uint64_t length,
                                       SqliteLayout *layout);
static inline void sqlite_integrity_initialize(SqliteIntegrity *integrity);
static inline void sqlite_integrity_note_text(SqliteIntegrity *integrity,
                                              const char *text,
                                              SqliteCheckContext *context);
static inline int sqlite_fallback_collation(void *context,
                                            int left_length,
                                            const void *left,
                                            int right_length,
                                            const void *right);
static inline void sqlite_collation_needed(void *context,
                                           sqlite3 *database,
                                           int encoding,
                                           const char *name);
static inline bool sqlite_schema_dependency_error(const char *message);
static inline bool sqlite_run_integrity_pragma(sqlite3 *database,
                                               const char *pragma,
                                               SqliteIntegrity *integrity,
                                               SqliteCheckContext *context);
static inline bool sqlite_check_mutable_context(
    uint8_t *data, uint64_t length, SqliteIntegrity *integrity,
    SqliteCheckContext *context, const char *primary_pragma,
    bool allow_schema_fallback);
static inline bool sqlite_integrity_check_mutable_context(
    uint8_t *data, uint64_t length, SqliteIntegrity *integrity,
    SqliteCheckContext *context);
static inline bool sqlite_integrity_check_mutable(uint8_t *data,
                                                  uint64_t length,
                                                  SqliteIntegrity *integrity);
static inline bool sqlite_quick_check_mutable(uint8_t *data,
                                              uint64_t length,
                                              SqliteIntegrity *integrity);
static inline bool sqlite_integrity_check(const uint8_t *data,
                                          uint64_t length,
                                          SqliteIntegrity *integrity);
static inline char *sqlite_header_discovery(char *base, uint64_t offset,
                                            uint64_t remaining,
                                            char **matchpos,
                                            uint32_t *matchlen,
                                            uint32_t blocksize);
static inline bool sqlite_page_header_plausible(
    const uint8_t *data, uint64_t length, uint32_t page_size);
static inline bool sqlite_pointer_map_page_plausible(
    const uint8_t *data, uint64_t length, uint32_t page_number,
    const SqliteLayout *layout);
static inline bool sqlite_overflow_page_plausible(
    const uint8_t *data, uint64_t length, const SqliteLayout *layout);
static inline uint32_t sqlite_block_validate(
    char *data, uint64_t length, BlockValidationDecision *decision,
    uint64_t *validates_to, uint32_t needleidx, uint32_t blocksize,
    void *blockhashkey);
static inline void sqlite_file_validate(char *data, uint64_t length,
                                        bool *validates,
                                        uint64_t *validates_to,
                                        bool *promising, uint32_t needleidx,
                                        uint32_t blocksize,
                                        void *carvehashkey);
static inline bool sqlite_mapping_materialize(const int64_t *mapping,
                                              uint64_t blocks,
                                              uint64_t extent,
                                              uint8_t *data);
static inline bool sqlite_mapping_block_is_zero(const int64_t *mapping,
                                                uint64_t slot);
static inline bool sqlite_source_overlaps_mapping(const int64_t *mapping,
                                                  uint64_t blocks,
                                                  uint64_t destination,
                                                  uint64_t run_blocks,
                                                  int64_t source);
static inline bool sqlite_source_has_page_evidence(uint64_t source,
                                                   uint64_t run_blocks,
                                                   uint32_t needleidx);
static inline bool sqlite_source_has_classification_evidence(
    uint64_t source, uint64_t run_blocks, uint32_t needleidx);
static inline bool sqlite_source_has_aligned_page_evidence(
    uint64_t source, uint64_t run_blocks, uint64_t target,
    uint64_t page_blocks, uint32_t needleidx);
static inline bool sqlite_source_has_layout_page_evidence(
    uint64_t source, uint64_t run_blocks, uint64_t target,
    const SqliteLayout *layout, uint32_t needleidx);
static inline bool sqlite_ooo_page_key_order_plausible(
    const int64_t *base_mapping, uint64_t total_blocks,
    uint64_t target, uint64_t run_blocks, uint64_t source,
    const SqliteLayout *layout, uint8_t *page_data,
    bool *page_initialized);
static inline uint64_t sqlite_ranked_run_width(uint64_t rank,
                                               uint64_t maximum,
                                               uint64_t target,
                                               uint64_t page_blocks);
static inline bool sqlite_mapping_check(const int64_t *mapping,
                                        uint64_t blocks, uint64_t extent,
                                        uint8_t *data,
                                        SqliteIntegrity *integrity);
static inline bool sqlite_mapping_check_diagnostic(
    const int64_t *mapping, uint64_t blocks, uint64_t extent,
    uint8_t *data, SqliteIntegrity *integrity,
    SqliteCheckContext *context);
static inline bool sqlite_mapping_ooo_check(
    const int64_t *mapping, uint64_t blocks, uint64_t extent,
    uint8_t *data, SqliteIntegrity *integrity,
    const SqliteIntegrity *reference, bool collect_improvement);
static inline bool sqlite_ooo_changes_are_necessary(
    const int64_t *base_mapping, int64_t *trial_mapping,
    uint64_t target, uint64_t run_blocks, uint64_t total_blocks,
    uint64_t extent, uint8_t *data);
static inline bool sqlite_integrity_better(const SqliteIntegrity *candidate,
                                           const SqliteIntegrity *current);
static inline bool sqlite_integrity_composition_better(
    const SqliteIntegrity *candidate, const SqliteIntegrity *current);
static inline bool sqlite_carve_state_valid(const SqliteCarveState *state);
static inline bool sqlite_serialize_carve_state(void **state, FILE *fp,
                                                StateSerialization mode);
static inline void *sqlite_clone_carve_state(const void *srcstate);
static inline void sqlite_free_carve_state(void **state);
static inline size_t sqlite_sizeof_carve_state(const void *state);
static inline void sqlite_print_carve_state(const void *state);
static inline uint64_t sqlite_mapping_hash(const int64_t *mapping,
                                           uint64_t blocks);
static inline void sqlite_cursor_reset(SqliteSearchCursor *cursor);
static inline bool sqlite_apply_gap_descriptor(
    const int64_t *base_mapping, uint64_t total_blocks,
    const SqliteRepairDescriptor *repair, int64_t *mapping);
static inline bool sqlite_apply_ooo_descriptor(
    const int64_t *base_mapping, uint64_t total_blocks,
    const SqliteRepairDescriptor *repair, int64_t *mapping);
static inline bool sqlite_repair_list_append(
    SqliteRepairList *list, const SqliteRepairDescriptor *repair);
static inline bool sqlite_reassembly_poll(ThreadWork *work,
                                          CarveInfo **candidate,
                                          uuid_string_t uuidp,
                                          uuid_string_t uuidc,
                                          SqliteCarveState *state,
                                          uint64_t *iterations);
static inline bool sqlite_commit_mapping(CarveInfo *candidate,
                                         const int64_t *mapping,
                                         uint64_t blocks,
                                         uint64_t extent);
static inline bool sqlite_write_mapping_hypothesis(
    CarveInfo *candidate, const int64_t *mapping,
    uint64_t blocks, uint64_t extent);
static inline SqliteRepairResult sqlite_preserve_ooo_extensions(
    ThreadWork *work, CarveInfo **candidate, uuid_string_t uuidp,
    uuid_string_t uuidc, const SqliteLayout *layout,
    const int64_t *base_mapping, uint64_t total_blocks,
    uint64_t target, uint64_t run_blocks, uint64_t source,
    uint8_t *trial_data, int64_t *trial_mapping,
    int64_t *extended_mapping,
    SqliteCarveState *state, uint64_t *iterations,
    bool *ambiguity_closed);
static inline SqliteRepairResult sqlite_preserve_gap_alternatives(
    ThreadWork *work, CarveInfo **candidate, uuid_string_t uuidp,
    uuid_string_t uuidc, const SqliteLayout *layout,
    const int64_t *base_mapping, uint64_t total_blocks,
    const SqliteRepairDescriptor *selected_gap,
    const int64_t *selected_gap_mapping,
    const int64_t *selected_solution_mapping,
    uint8_t *trial_data, int64_t *trial_mapping,
    SqliteCarveState *state, uint64_t *iterations);
static inline SqliteRepairResult sqlite_preserve_partial_page_completions(
    ThreadWork *work, CarveInfo **candidate, uuid_string_t uuidp,
    uuid_string_t uuidc, const SqliteLayout *layout,
    const int64_t *base_mapping, uint64_t total_blocks,
    const uint64_t *targets, const uint64_t *widths,
    uint64_t target_count, uint8_t *trial_data,
    int64_t *trial_mapping, SqliteCarveState *state,
    uint64_t *iterations);
static inline uint64_t sqlite_page_block(uint32_t page,
                                         const SqliteLayout *layout,
                                         uint64_t blocksize,
                                         uint64_t total_blocks);
static inline uint64_t sqlite_diagnostic_cell_block(
    const SqliteCheckContext *context, const uint8_t *data,
    const SqliteLayout *layout, uint64_t blocksize,
    uint64_t total_blocks);
static inline uint64_t sqlite_failure_block(const SqliteIntegrity *integrity,
                                            const SqliteLayout *layout,
                                            const int64_t *mapping,
                                            uint64_t blocksize,
                                            uint64_t total_blocks);
static inline SqliteRepairResult sqlite_probe_gap_repair(
    ThreadWork *work, CarveInfo **candidate, uuid_string_t uuidp,
    uuid_string_t uuidc, const SqliteLayout *layout,
    const SqliteIntegrity *baseline_integrity,
    const int64_t *base_mapping, uint64_t total_blocks,
    uint64_t target_hint, uint8_t *trial_data,
    int64_t *trial_mapping, int64_t *solution_mapping,
    int64_t *composition_mapping, bool compose,
    SqliteCarveState *state, uint64_t *iterations);
static inline SqliteRepairResult sqlite_probe_ooo_repair(
    ThreadWork *work, CarveInfo **candidate, uuid_string_t uuidp,
    uuid_string_t uuidc, const SqliteLayout *layout,
    const SqliteIntegrity *baseline_integrity,
    const int64_t *base_mapping, uint64_t total_blocks,
    uint64_t target_hint, bool exact_target, uint64_t width_hint,
    uint8_t *trial_data,
    int64_t *trial_mapping, int64_t *solution_mapping,
    int64_t *composition_mapping, bool compose,
    bool high_confidence_only, bool key_order_only,
    SqliteRepairList *plausible_repairs,
    SqliteCarveState *state, uint64_t *iterations);
static inline SqliteRepairResult sqlite_preserve_two_ooo_alternatives(
    ThreadWork *work, CarveInfo **candidate, uuid_string_t uuidp,
    uuid_string_t uuidc, const SqliteLayout *layout,
    const SqliteIntegrity *baseline_integrity,
    const int64_t *base_mapping, uint64_t total_blocks,
    const uint64_t targets[2], const uint64_t widths[2],
    uint8_t *trial_data, int64_t *first_mapping,
    int64_t *trial_mapping, SqliteCarveState *state,
    uint64_t *iterations);
static inline SqliteRepairResult sqlite_probe_shifted_page_gap(
    ThreadWork *work, CarveInfo **candidate, uuid_string_t uuidp,
    uuid_string_t uuidc, const SqliteLayout *layout,
    const SqliteIntegrity *integrity, const int64_t *base_mapping,
    uint64_t total_blocks, uint8_t *trial_data,
    int64_t *trial_mapping, int64_t *solution_mapping,
    int64_t *composition_mapping, bool compose,
    bool allow_multi_region,
    SqliteCarveState *state, uint64_t *iterations);
static inline SqliteRepairResult sqlite_probe_gap_diagnostics(
    ThreadWork *work, CarveInfo **candidate, uuid_string_t uuidp,
    uuid_string_t uuidc, const SqliteLayout *layout,
    const SqliteIntegrity *integrity, const int64_t *base_mapping,
    uint64_t total_blocks, uint8_t *trial_data,
    int64_t *trial_mapping, int64_t *solution_mapping,
    int64_t *composition_mapping, bool compose,
    SqliteCarveState *state, uint64_t *iterations);
static inline SqliteRepairResult sqlite_probe_gap_grid(
    ThreadWork *work, CarveInfo **candidate, uuid_string_t uuidp,
    uuid_string_t uuidc, const SqliteLayout *layout,
    const SqliteIntegrity *baseline_integrity,
    const int64_t *base_mapping, uint64_t total_blocks,
    uint8_t *trial_data, int64_t *trial_mapping,
    int64_t *solution_mapping, SqliteRepairDescriptor *best_repair,
    SqliteIntegrity *best_integrity, SqliteCarveState *state,
    uint64_t *iterations);
static inline SqliteRepairResult sqlite_probe_ooo_diagnostics(
    ThreadWork *work, CarveInfo **candidate, uuid_string_t uuidp,
    uuid_string_t uuidc, const SqliteLayout *layout,
    const SqliteIntegrity *integrity, const int64_t *base_mapping,
    uint64_t total_blocks, uint8_t *trial_data,
    int64_t *trial_mapping, int64_t *solution_mapping,
    int64_t *composition_mapping, bool compose,
    bool high_confidence_only,
    SqliteCarveState *state, uint64_t *iterations);
static inline SqliteRepairResult sqlite_try_gap_repair(
    ThreadWork *work, CarveInfo **candidate, uuid_string_t uuidp,
    uuid_string_t uuidc, const SqliteLayout *layout,
    const int64_t *base_mapping, uint64_t total_blocks,
    uint64_t preferred_target, uint8_t *trial_data,
    int64_t *trial_mapping, int64_t *solution_mapping,
    SqliteSearchCursor *cursor, SqliteRepairDescriptor *best_repair,
    SqliteIntegrity *best_integrity, SqliteCarveState *state,
    uint64_t *iterations);
static inline SqliteRepairResult sqlite_try_ooo_repair(
    ThreadWork *work, CarveInfo **candidate, uuid_string_t uuidp,
    uuid_string_t uuidc, const SqliteLayout *layout,
    const int64_t *base_mapping, uint64_t total_blocks,
    uint64_t preferred_target, uint8_t *trial_data,
    int64_t *trial_mapping, int64_t *solution_mapping,
    SqliteSearchCursor *cursor, SqliteRepairDescriptor *best_repair,
    SqliteIntegrity *best_integrity, bool preferred_only,
    uint64_t maximum_width, SqliteCarveState *state,
    uint64_t *iterations);
static inline SqliteRepairResult sqlite_try_composed_repair(
    ThreadWork *work, CarveInfo **candidate, uuid_string_t uuidp,
    uuid_string_t uuidc, const SqliteLayout *layout,
    const int64_t *base_mapping, uint64_t total_blocks,
    uint64_t preferred_target, uint8_t *trial_data,
    int64_t *trial_mapping, int64_t *outer_mapping,
    int64_t *solution_mapping, SqliteCarveState *state,
    uint64_t *iterations);
static inline void sqlite_reassembly(ThreadWork *work,
                                     CarveInfo **candidate,
                                     uuid_string_t uuidp,
                                     uuid_string_t uuidc);

static inline uint16_t sqlite_read_be16(const uint8_t *data) {
  return (uint16_t)(((uint16_t)data[0] << 8) | data[1]);
}

static inline uint32_t sqlite_read_be32(const uint8_t *data) {
  return ((uint32_t)data[0] << 24) | ((uint32_t)data[1] << 16)
         | ((uint32_t)data[2] << 8) | (uint32_t)data[3];
}

static inline bool sqlite_read_varint(const uint8_t *data,
                                      uint64_t length,
                                      uint64_t *value,
                                      uint32_t *consumed) {
  if (!data || !value || !consumed) {
    return false;
  }

  uint64_t result = 0;
  for (uint32_t offset = 0; offset < 8; offset++) {
    if (offset >= length) {
      return false;
    }
    const uint8_t byte = data[offset];
    result = (result << 7) | (uint64_t)(byte & UINT8_C(0x7f));
    if ((byte & UINT8_C(0x80)) == 0) {
      *value = result;
      *consumed = offset + 1;
      return true;
    }
  }
  if (length < 9) {
    return false;
  }
  *value = (result << 8) | data[8];
  *consumed = 9;
  return true;
}

static inline bool sqlite_power_of_two(uint32_t value) {
  return value != 0 && (value & (value - 1)) == 0;
}

// Parse the database header and derive its exact recorded extent. A stale in-header page count
// cannot establish a safe carve boundary, so it is not accepted as an exact database size.
static inline bool sqlite_parse_header(const uint8_t *data, uint64_t length,
                                       SqliteLayout *layout) {
  if (!data || !layout || length < SQLITE_FILE_HEADER_SIZE
      || memcmp(data, SQLITE_FILE_SIGNATURE,
                SQLITE_FILE_SIGNATURE_SIZE) != 0) {
    return false;
  }

  uint32_t page_size = sqlite_read_be16(data + 16);
  if (page_size == 1) {
    page_size = SQLITE_MAXIMUM_PAGE_SIZE;
  }
  if (page_size < SQLITE_MINIMUM_PAGE_SIZE
      || page_size > SQLITE_MAXIMUM_PAGE_SIZE
      || !sqlite_power_of_two(page_size)
      || (data[18] != 1 && data[18] != 2)
      || (data[19] != 1 && data[19] != 2)
      || data[21] != 64 || data[22] != 32 || data[23] != 32) {
    return false;
  }

  const uint32_t reserved = data[20];
  if (reserved > page_size - SQLITE_MINIMUM_USABLE_SIZE) {
    return false;
  }

  const uint32_t page_count = sqlite_read_be32(data + 28);
  const uint32_t change_counter = sqlite_read_be32(data + 24);
  const uint32_t freelist_trunk = sqlite_read_be32(data + 32);
  const uint32_t freelist_pages = sqlite_read_be32(data + 36);
  const uint32_t schema_format = sqlite_read_be32(data + 44);
  const uint32_t largest_root = sqlite_read_be32(data + 52);
  const uint32_t encoding = sqlite_read_be32(data + 56);
  const uint32_t incremental_vacuum = sqlite_read_be32(data + 64);
  const uint32_t version_valid_for = sqlite_read_be32(data + 92);

  if (page_count == 0 || page_count == UINT32_MAX
      || change_counter != version_valid_for
      || freelist_trunk > page_count
      || freelist_pages > page_count || largest_root > page_count
      || (freelist_pages == 0 && freelist_trunk != 0)
      || (freelist_pages != 0 && freelist_trunk == 0)
      || (largest_root == 0 && incremental_vacuum != 0)
      || (schema_format != 0 && (schema_format < 1 || schema_format > 4))
      || (encoding != 0 && (encoding < 1 || encoding > 3))) {
    return false;
  }
  for (uint32_t index = 72; index < 92; index++) {
    if (data[index] != 0) {
      return false;
    }
  }

  uint64_t extent = 0;
  if (__builtin_mul_overflow((uint64_t)page_count,
                             (uint64_t)page_size, &extent)
      || extent < SQLITE_FILE_HEADER_SIZE) {
    return false;
  }

  layout->extent = extent;
  layout->page_size = page_size;
  layout->usable_size = page_size - reserved;
  layout->page_count = page_count;
  layout->largest_root_page = largest_root;
  return true;
}

static inline void sqlite_integrity_initialize(SqliteIntegrity *integrity) {
  memset(integrity, 0, sizeof(*integrity));
  integrity->result_code = SQLITE_OK;
}

// Collect page numbers and a stable error count from SQLite diagnostics. Page references are used
// only to prioritize recovery trials; final acceptance always requires a clean integrity check.
static inline void sqlite_integrity_note_text(SqliteIntegrity *integrity,
                                              const char *text,
                                              SqliteCheckContext *context) {
  if (!integrity || !text) {
    return;
  }

  // SQLite can return many integrity failures in one newline-delimited result row.
  // Count the individual diagnostics so recovery ranking reflects actual progress.
  bool at_line_start = true;
  for (const char *cursor = text; *cursor; cursor++) {
    if (*cursor == '\n') {
      at_line_start = true;
    }
    else if (at_line_start) {
      if (integrity->error_count < UINT32_MAX) {
        integrity->error_count++;
      }
      at_line_start = false;
    }
  }
  if (integrity->error_count == 0) {
    integrity->error_count = 1;
  }
  for (const char *cursor = text; *cursor; cursor++) {
    if (!cursor[1] || !cursor[2] || !cursor[3]
        || tolower((unsigned char)cursor[0]) != 'p'
        || tolower((unsigned char)cursor[1]) != 'a'
        || tolower((unsigned char)cursor[2]) != 'g'
        || tolower((unsigned char)cursor[3]) != 'e') {
      continue;
    }
    const char *number = cursor + 4;
    while (*number == ' ' || *number == '#' || *number == '=') {
      number++;
    }
    if (!isdigit((unsigned char)*number)) {
      continue;
    }
    uint64_t page = 0;
    while (isdigit((unsigned char)*number)) {
      page = page * 10 + (uint64_t)(*number - '0');
      if (page > UINT32_MAX) {
        page = 0;
        break;
      }
      number++;
    }
    if (context && !context->cell_diagnostic_found
        && page > 0 && page <= UINT32_MAX) {
      const char *cell = number;
      while (*cell == ' ') {
        cell++;
      }
      if (cell[0] && cell[1] && cell[2] && cell[3]
          && tolower((unsigned char)cell[0]) == 'c'
          && tolower((unsigned char)cell[1]) == 'e'
          && tolower((unsigned char)cell[2]) == 'l'
          && tolower((unsigned char)cell[3]) == 'l') {
        cell += 4;
        while (*cell == ' ' || *cell == '#' || *cell == '=') {
          cell++;
        }
        if (isdigit((unsigned char)*cell)) {
          uint64_t cell_index = 0;
          while (isdigit((unsigned char)*cell)) {
            cell_index = cell_index * 10
                         + (uint64_t)(*cell - '0');
            if (cell_index > UINT32_MAX) {
              cell_index = UINT64_MAX;
              break;
            }
            cell++;
          }
          if (cell_index <= UINT32_MAX) {
            context->cell_diagnostic_found = true;
            context->cell_page = (uint32_t)page;
            context->cell_index = (uint32_t)cell_index;
          }
        }
      }
    }
    if (page == 0) {
      continue;
    }
    if (integrity->first_page == 0 || page < integrity->first_page) {
      integrity->first_page = (uint32_t)page;
    }
    if (page > integrity->last_page) {
      integrity->last_page = (uint32_t)page;
    }
  }
}

// Application-defined collations are not available while carving. A deterministic bytewise
// comparator lets SQLite load the schema; it is used only to decide whether a structural
// quick-check fallback is necessary, never as proof that application-specific indexes agree.
static inline int sqlite_fallback_collation(void *context,
                                            int left_length,
                                            const void *left,
                                            int right_length,
                                            const void *right) {
  (void)context;
  const int common = left_length < right_length ? left_length : right_length;
  const int compared = common > 0 ? memcmp(left, right, (size_t)common) : 0;
  if (compared != 0) {
    return compared;
  }
  return (left_length > right_length) - (left_length < right_length);
}

static inline void sqlite_collation_needed(void *context,
                                           sqlite3 *database,
                                           int encoding,
                                           const char *name) {
  SqliteCheckContext *check_context = (SqliteCheckContext *)context;
  if (check_context) {
    check_context->custom_collation_requested = true;
  }
  if (database && name) {
    sqlite3_create_collation(database, name, encoding, NULL,
                             sqlite_fallback_collation);
  }
}

static inline bool sqlite_schema_dependency_error(const char *message) {
  return message
         && (strstr(message, "unknown function:")
             || strstr(message, "no such function:")
             || strstr(message, "no such collation sequence:")
             || strstr(message, "no such module:"));
}

static inline bool sqlite_run_integrity_pragma(sqlite3 *database,
                                               const char *pragma,
                                               SqliteIntegrity *integrity,
                                               SqliteCheckContext *context) {
  sqlite3_stmt *statement = NULL;
  int result = sqlite3_prepare_v2(database, pragma, -1, &statement, NULL);
  bool saw_ok = false;
  bool saw_error = false;

  if (result == SQLITE_OK) {
    while ((result = sqlite3_step(statement)) == SQLITE_ROW) {
      const char *message = (const char *)sqlite3_column_text(statement, 0);
      if (message && strcmp(message, "ok") == 0) {
        saw_ok = true;
      }
      else {
        saw_error = true;
        sqlite_integrity_note_text(integrity,
                                   message ? message : "integrity error",
                                   context);
      }
    }
    if (result == SQLITE_DONE) {
      result = SQLITE_OK;
    }
  }

  if (result != SQLITE_OK) {
    integrity->result_code = result;
    sqlite_integrity_note_text(integrity,
                               sqlite3_errmsg(database), context);
  }
  else {
    integrity->result_code = SQLITE_OK;
  }
  integrity->valid = result == SQLITE_OK && saw_ok && !saw_error;
  sqlite3_finalize(statement);
  return integrity->valid;
}

// Validate a mutable, exact-length database image with SQLite's own integrity checker. WAL format
// bytes are temporarily changed to rollback mode because the carved main database is checked
// without a sidecar; no database content is otherwise modified.
static inline bool sqlite_check_mutable_context(
    uint8_t *data, uint64_t length, SqliteIntegrity *integrity,
    SqliteCheckContext *context, const char *primary_pragma,
    bool allow_schema_fallback) {
  sqlite_integrity_initialize(integrity);
  SqliteCheckContext local_context = {0};
  if (!context) {
    context = &local_context;
  }
  else {
    memset(context, 0, sizeof(*context));
  }
  if (!data || !primary_pragma || length < SQLITE_FILE_HEADER_SIZE
      || length > INT64_MAX) {
    integrity->result_code = SQLITE_TOOBIG;
    integrity->error_count = UINT32_MAX;
    return false;
  }

  const uint8_t read_version = data[18];
  const uint8_t write_version = data[19];
  data[18] = 1;
  data[19] = 1;

  sqlite3 *database = NULL;
  int result = sqlite3_open_v2(":memory:", &database,
                               SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE
                                   | SQLITE_OPEN_NOMUTEX,
                               NULL);
  if (result == SQLITE_OK) {
    result = sqlite3_collation_needed(database, context,
                                      sqlite_collation_needed);
  }
  if (result == SQLITE_OK) {
    sqlite3_extended_result_codes(database, 1);
    result = sqlite3_deserialize(database, "main", data,
                                 (sqlite3_int64)length,
                                 (sqlite3_int64)length,
                                 SQLITE_DESERIALIZE_READONLY);
  }
  if (result == SQLITE_OK) {
    sqlite3_exec(database, "PRAGMA cell_size_check=ON", NULL, NULL, NULL);
  }

  if (result == SQLITE_OK) {
    sqlite_run_integrity_pragma(database, primary_pragma,
                                integrity, context);
    const bool schema_dependency =
        context->custom_collation_requested
        || sqlite_schema_dependency_error(sqlite3_errmsg(database));
    if (!integrity->valid && allow_schema_fallback
        && schema_dependency) {
      sqlite_integrity_initialize(integrity);
      sqlite_run_integrity_pragma(database, "PRAGMA quick_check(100)",
                                  integrity, context);
    }
  }
  else {
    integrity->result_code = result;
    sqlite_integrity_note_text(
        integrity, database ? sqlite3_errmsg(database) : "SQLite open error",
        context);
  }

  if (database) {
    sqlite3_close(database);
  }
  data[18] = read_version;
  data[19] = write_version;
  return integrity->valid;
}

static inline bool sqlite_integrity_check_mutable_context(
    uint8_t *data, uint64_t length, SqliteIntegrity *integrity,
    SqliteCheckContext *context) {
  return sqlite_check_mutable_context(
      data, length, integrity, context,
      "PRAGMA integrity_check(100)", true);
}

static inline bool sqlite_integrity_check_mutable(uint8_t *data,
                                                  uint64_t length,
                                                  SqliteIntegrity *integrity) {
  return sqlite_integrity_check_mutable_context(
      data, length, integrity, NULL);
}

static inline bool sqlite_quick_check_mutable(uint8_t *data,
                                              uint64_t length,
                                              SqliteIntegrity *integrity) {
  return sqlite_check_mutable_context(
      data, length, integrity, NULL,
      "PRAGMA quick_check(1)", false);
}

static inline bool sqlite_integrity_check(const uint8_t *data,
                                          uint64_t length,
                                          SqliteIntegrity *integrity) {
  if (!data || length > SIZE_MAX) {
    sqlite_integrity_initialize(integrity);
    integrity->result_code = SQLITE_TOOBIG;
    integrity->error_count = UINT32_MAX;
    return false;
  }
  uint8_t *copy = (uint8_t *)malloc((size_t)length);
  check_memory_allocation(copy, __LINE__, __FILE__,
                          "SQLite integrity buffer");
  memcpy(copy, data, (size_t)length);
  const bool valid = sqlite_integrity_check_mutable(copy, length,
                                                    integrity);
  free(copy);
  return valid;
}

// Search for SQLite headers and suppress incidental signature strings by checking every fixed
// database-header field needed to establish a safe extent.
static inline char *sqlite_header_discovery(char *base, uint64_t offset,
                                            uint64_t remaining,
                                            char **matchpos,
                                            uint32_t *matchlen,
                                            uint32_t blocksize) {
  (void)blocksize;
  if (!base || !matchpos || !matchlen) {
    return NULL;
  }
  *matchpos = NULL;
  *matchlen = (uint32_t)SQLITE_FILE_SIGNATURE_SIZE;
  if (remaining < SQLITE_FILE_HEADER_SIZE) {
    return NULL;
  }

  char signature[SQLITE_FILE_SIGNATURE_SIZE] = {
      'S', 'Q', 'L', 'i', 't', 'e', ' ', 'f',
      'o', 'r', 'm', 'a', 't', ' ', '3', '\0'};
  size_t table[UCHAR_MAX + 1];
  init_bm_table(signature, table, sizeof(signature), true);
  char *region = base + offset;
  char *candidate = find_binary_string(signature, sizeof(signature), region,
                                       remaining, table, true);
  while (candidate) {
    const uint64_t consumed = (uint64_t)(candidate - region);
    SqliteLayout layout;
    if (sqlite_parse_header((const uint8_t *)candidate,
                            remaining - consumed, &layout)) {
      *matchpos = candidate;
      return NULL;
    }
    if (consumed + 1 >= remaining) {
      break;
    }
    candidate = find_binary_string(signature, sizeof(signature),
                                   candidate + 1,
                                   remaining - consumed - 1,
                                   table, true);
  }
  return NULL;
}

static inline bool sqlite_page_header_plausible(
    const uint8_t *data, uint64_t length, uint32_t page_size) {
  if (!data || length < 12 || page_size < SQLITE_MINIMUM_PAGE_SIZE
      || page_size > SQLITE_MAXIMUM_PAGE_SIZE) {
    return false;
  }

  const uint8_t page_type = data[0];
  const bool interior = page_type == 2 || page_type == 5;
  if (!interior && page_type != 10 && page_type != 13) {
    return false;
  }
  const uint32_t header_size = interior ? 12 : 8;
  const uint32_t first_free = sqlite_read_be16(data + 1);
  const uint32_t cells = sqlite_read_be16(data + 3);
  uint32_t content_start = sqlite_read_be16(data + 5);
  if (content_start == 0) {
    content_start = page_size;
  }
  const uint64_t pointer_end =
      (uint64_t)header_size + (uint64_t)cells * 2;
  if (data[7] > 60 || pointer_end > page_size
      || content_start < pointer_end || content_start > page_size
      || (first_free != 0
          && (first_free < header_size || first_free >= page_size))
      || (interior && sqlite_read_be32(data + 8) == 0)) {
    return false;
  }
  if (pointer_end <= length) {
    for (uint32_t cell = 0; cell < cells; cell++) {
      const uint32_t cell_offset = sqlite_read_be16(
          data + header_size + (uint64_t)cell * 2);
      if (cell_offset < content_start || cell_offset >= page_size) {
        return false;
      }
    }
  }
  return true;
}

// Auto-vacuum databases place pointer-map pages at positions derived from the usable page size.
// Validate only entries that describe pages present in this database; unused tail bytes are not
// required to have any particular value.
static inline bool sqlite_pointer_map_page_plausible(
    const uint8_t *data, uint64_t length, uint32_t page_number,
    const SqliteLayout *layout) {
  if (!data || !layout || layout->largest_root_page == 0
      || layout->usable_size < 5 || length < layout->usable_size
      || page_number < 2 || page_number > layout->page_count) {
    return false;
  }

  const uint32_t entries_per_map = layout->usable_size / 5;
  const uint32_t map_spacing = entries_per_map + 1;
  const uint32_t pending_byte_page =
      UINT32_C(0x40000000) / layout->page_size + 1;
  uint32_t expected_map =
      ((page_number - 2) / map_spacing) * map_spacing + 2;
  if (expected_map == pending_byte_page) {
    expected_map++;
  }
  if (page_number != expected_map) {
    return false;
  }

  uint32_t entries = 0;
  for (uint32_t described_page = page_number + 1;
       described_page <= layout->page_count
       && entries < entries_per_map; described_page++) {
    if (described_page == pending_byte_page) {
      break;
    }
    uint32_t next_map =
        ((described_page - 2) / map_spacing) * map_spacing + 2;
    if (next_map == pending_byte_page) {
      next_map++;
    }
    if (described_page == next_map) {
      break;
    }

    const uint8_t type = data[(uint64_t)entries * 5];
    const uint32_t parent = sqlite_read_be32(
        data + (uint64_t)entries * 5 + 1);
    if (type < 1 || type > 5 || parent > layout->page_count
        || ((type == 1 || type == 2) && parent != 0)
        || (type >= 3 && parent == 0)) {
      return false;
    }
    entries++;
  }
  return entries > 0;
}

// Overflow pages contain the next overflow page number followed by payload. This is ranking
// evidence only; the complete database still has to pass SQLite's integrity checker.
static inline bool sqlite_overflow_page_plausible(
    const uint8_t *data, uint64_t length, const SqliteLayout *layout) {
  if (!data || !layout || layout->usable_size <= 4
      || length < layout->usable_size
      || sqlite_read_be32(data) > layout->page_count) {
    return false;
  }
  for (uint32_t offset = 4; offset < layout->usable_size; offset++) {
    if (data[offset] != 0) {
      return true;
    }
  }
  return false;
}

// Grade blocks that begin with a SQLite database header or a plausible b-tree page. Most SQLite
// page roles have no standalone signature, so absence of this evidence remains low confidence
// rather than excluding the block from reassembly.
static inline uint32_t sqlite_block_validate(
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
  if (scalpel_state.no_defrag) {
    return needleidx;
  }

  SqliteLayout layout;
  if (sqlite_parse_header((const uint8_t *)data, length, &layout)) {
    *decision = BLOCK_CONFIDENCE_VALID;
    return needleidx;
  }
  if (length < 12) {
    return needleidx;
  }

  if (sqlite_page_header_plausible(
          (const uint8_t *)data, length, SQLITE_MAXIMUM_PAGE_SIZE)
      && *decision < (BlockValidationDecision)SQLITE_PAGE_CONFIDENCE) {
    *decision = (BlockValidationDecision)SQLITE_PAGE_CONFIDENCE;
  }
  return needleidx;
}

// A complete database must pass SQLite's integrity checker. During fragmented recovery, a clean
// database remains promising because SQLite does not authenticate free space and other unused
// bytes. An invalid complete view also remains promising at its full extent so the custom
// reassembly function can replace or skip blocks without losing the intact suffix.
static inline void sqlite_file_validate(char *data, uint64_t length,
                                        bool *validates,
                                        uint64_t *validates_to,
                                        bool *promising, uint32_t needleidx,
                                        uint32_t blocksize,
                                        void *carvehashkey) {
  (void)blocksize;
  (void)carvehashkey;
  if (!validates || !validates_to || !promising) {
    return;
  }
  *validates = false;
  *validates_to = 0;
  *promising = false;

  SqliteLayout layout;
  if (!sqlite_parse_header((const uint8_t *)data, length, &layout)
      || layout.extent
             > scalpel_state.search_specs[needleidx].MAXIMUMSIZE) {
    return;
  }
  *promising = true;
  if (length < layout.extent) {
    *validates_to = length > 0 ? length - 1 : 0;
    return;
  }

  SqliteIntegrity integrity;
  if (sqlite_integrity_check((const uint8_t *)data, layout.extent,
                             &integrity)) {
    if (scalpel_state.no_defrag) {
      *validates = true;
      *promising = false;
    }
  }
  *validates_to = layout.extent - 1;
}

static inline bool sqlite_mapping_materialize(const int64_t *mapping,
                                              uint64_t blocks,
                                              uint64_t extent,
                                              uint8_t *data) {
  if (!mapping || !data || blocks == 0) {
    return false;
  }
  const uint64_t blocksize = scalpel_state.blocksize;
  for (uint64_t slot = 0; slot < blocks; slot++) {
    const uint64_t offset = slot * blocksize;
    uint64_t count = blocksize;
    if (offset >= extent) {
      return false;
    }
    if (count > extent - offset) {
      count = extent - offset;
    }
    if (mapping[slot] < 0 || count > UINT32_MAX
        || !get_apparent_block_bytes(scalpel_state.filemirror,
                                     mapping[slot], 0,
                                     (uint32_t)count, data + offset)) {
      return false;
    }
  }
  return true;
}

static inline bool sqlite_mapping_block_is_zero(const int64_t *mapping,
                                                uint64_t slot) {
  if (!mapping || mapping[slot] < 0) {
    return false;
  }
  const int64_t actual = filemirror_actual_blocknumber(
      scalpel_state.filemirror, mapping[slot]);
  return actual >= 0
         && filemirror_actual_block_is_zero(scalpel_state.filemirror,
                                            actual);
}

static inline bool sqlite_source_overlaps_mapping(const int64_t *mapping,
                                                  uint64_t blocks,
                                                  uint64_t destination,
                                                  uint64_t run_blocks,
                                                  int64_t source) {
  const int64_t source_end = source + (int64_t)run_blocks;
  for (uint64_t slot = 0; slot < blocks; slot++) {
    if (slot >= destination && slot < destination + run_blocks) {
      continue;
    }
    if (mapping[slot] >= source && mapping[slot] < source_end) {
      return true;
    }
  }
  return false;
}

static inline bool sqlite_source_has_page_evidence(uint64_t source,
                                                   uint64_t run_blocks,
                                                   uint32_t needleidx) {
  const uint64_t apparent_blocks =
      filemirror_apparent_blocks(scalpel_state.filemirror);
  if (source >= apparent_blocks || run_blocks > apparent_blocks - source) {
    return false;
  }
  for (uint64_t offset = 0; offset < run_blocks; offset++) {
    const int64_t actual = filemirror_actual_blocknumber(
        scalpel_state.filemirror, (int64_t)(source + offset));
    if (filemirror_get_blocktype(scalpel_state.filemirror, actual,
                                 needleidx)
        >= (BlockValidationDecision)SQLITE_PAGE_CONFIDENCE) {
      return true;
    }
  }
  return false;
}

// Confidence 1 is the generic fallback for an otherwise unclassified block. Search runs whose
// blocks all have stronger evidence first; the following pass still considers every other run.
static inline bool sqlite_source_has_classification_evidence(
    uint64_t source, uint64_t run_blocks, uint32_t needleidx) {
  const uint64_t apparent_blocks =
      filemirror_apparent_blocks(scalpel_state.filemirror);
  if (source >= apparent_blocks || run_blocks > apparent_blocks - source) {
    return false;
  }
  for (uint64_t offset = 0; offset < run_blocks; offset++) {
    const int64_t actual = filemirror_actual_blocknumber(
        scalpel_state.filemirror, (int64_t)(source + offset));
    if (filemirror_get_blocktype(scalpel_state.filemirror, actual,
                                 needleidx)
        <= BLOCK_CONFIDENCE_LOW) {
      return false;
    }
  }
  return true;
}

static inline bool sqlite_source_has_aligned_page_evidence(
    uint64_t source, uint64_t run_blocks, uint64_t target,
    uint64_t page_blocks, uint32_t needleidx) {
  if (page_blocks == 0) {
    return false;
  }
  const uint64_t first_boundary =
      (page_blocks - target % page_blocks) % page_blocks;
  if (first_boundary >= run_blocks) {
    return false;
  }
  for (uint64_t offset = first_boundary; offset < run_blocks;
       offset += page_blocks) {
    if (!sqlite_source_has_page_evidence(source + offset, 1,
                                         needleidx)) {
      return false;
    }
  }
  return true;
}

// A carve block can contain one or more complete SQLite pages. B-tree and pointer-map pages provide
// direct evidence that ranks a source ahead of the complete fallback search.
static inline bool sqlite_source_has_layout_page_evidence(
    uint64_t source, uint64_t run_blocks, uint64_t target,
    const SqliteLayout *layout, uint32_t needleidx) {
  if (!layout || scalpel_state.blocksize == 0) {
    return false;
  }
  const uint64_t page_blocks = CEILDIV(
      layout->page_size, scalpel_state.blocksize);
  if (layout->page_size > scalpel_state.blocksize) {
    const uint64_t apparent_blocks =
        filemirror_apparent_blocks(scalpel_state.filemirror);
    if (layout->page_size % scalpel_state.blocksize == 0
        && target % page_blocks == 0 && run_blocks >= page_blocks
        && source < apparent_blocks
        && page_blocks <= apparent_blocks - source) {
      uint8_t page_data[SQLITE_MAXIMUM_PAGE_SIZE];
      bool materialized = true;
      for (uint64_t block = 0; block < page_blocks; block++) {
        if (!get_apparent_block_bytes(
                scalpel_state.filemirror, (int64_t)(source + block), 0,
                (uint32_t)scalpel_state.blocksize,
                page_data + block * scalpel_state.blocksize)) {
          materialized = false;
          break;
        }
      }
      if (materialized) {
        const uint64_t page_number64 = target / page_blocks + 1;
        if (page_number64 <= layout->page_count) {
          const uint32_t page_number = (uint32_t)page_number64;
          const uint8_t *page_header = page_data;
          uint64_t page_header_length = layout->page_size;
          if (page_number == 1) {
            page_header = page_data + SQLITE_FILE_HEADER_SIZE;
            page_header_length -= SQLITE_FILE_HEADER_SIZE;
          }
          const bool btree_page = sqlite_page_header_plausible(
              page_header, page_header_length, layout->page_size);
          const bool pointer_map_page = sqlite_pointer_map_page_plausible(
              page_data, layout->page_size, page_number, layout);
          if (btree_page || pointer_map_page) {
            return true;
          }
        }
      }
    }
    return sqlite_source_has_aligned_page_evidence(
        source, run_blocks, target, page_blocks, needleidx);
  }

  const uint64_t apparent_blocks =
      filemirror_apparent_blocks(scalpel_state.filemirror);
  if (source >= apparent_blocks
      || run_blocks > apparent_blocks - source) {
    return false;
  }
  for (uint64_t block = 0; block < run_blocks; block++) {
    const int64_t actual = filemirror_actual_blocknumber(
        scalpel_state.filemirror, (int64_t)(source + block));
    if (actual < 0 || target > UINT64_MAX - block) {
      return false;
    }
    uint64_t length = 0;
    const uint8_t *data = (const uint8_t *)
        filemirror_actual_block_data_pointer(
            scalpel_state.filemirror, actual, &length);
    const uint64_t logical_block = target + block;
    uint64_t logical_base = 0;
    if (!data
        || __builtin_mul_overflow(logical_block,
                                  scalpel_state.blocksize,
                                  &logical_base)
        || logical_base >= layout->extent) {
      return false;
    }
    uint64_t logical_length = layout->extent - logical_base;
    if (logical_length > scalpel_state.blocksize) {
      logical_length = scalpel_state.blocksize;
    }
    if (logical_length > length) {
      logical_length = length;
    }

    const uint64_t first_page =
        (layout->page_size - logical_base % layout->page_size)
        % layout->page_size;
    bool all_structured = true;
    bool inspected = false;
    for (uint64_t offset = first_page;
         offset <= logical_length
         && layout->page_size <= logical_length - offset;
         offset += layout->page_size) {
      inspected = true;
      if (sqlite_page_header_plausible(
              data + offset, layout->page_size, layout->page_size)) {
        continue;
      }

      const uint64_t page_number64 =
          (logical_base + offset) / layout->page_size + 1;
      if (page_number64 > layout->page_count
          || (!sqlite_pointer_map_page_plausible(
                  data + offset, layout->page_size,
                  (uint32_t)page_number64, layout)
              && !sqlite_overflow_page_plausible(
                  data + offset, layout->page_size, layout))) {
        all_structured = false;
      }
    }
    if (!inspected || !all_structured) {
      return false;
    }
  }
  return true;
}

// Table b-tree cell pointers are stored in key order. Reconstruct the affected page and use that
// ordering as strong source-ranking evidence when an OOO run contains no standalone page header.
static inline bool sqlite_ooo_page_key_order_plausible(
    const int64_t *base_mapping, uint64_t total_blocks,
    uint64_t target, uint64_t run_blocks, uint64_t source,
    const SqliteLayout *layout, uint8_t *page_data,
    bool *page_initialized) {
  if (!base_mapping || !layout || !page_data || !page_initialized
      || run_blocks == 0
      || scalpel_state.blocksize == 0
      || layout->page_size < scalpel_state.blocksize
      || layout->page_size % scalpel_state.blocksize != 0) {
    return false;
  }

  const uint64_t page_blocks =
      layout->page_size / scalpel_state.blocksize;
  const uint64_t page_start = target - target % page_blocks;
  if (page_start >= total_blocks
      || page_blocks > total_blocks - page_start
      || target < page_start
      || run_blocks > page_start + page_blocks - target) {
    return false;
  }
  const uint64_t apparent_blocks =
      filemirror_apparent_blocks(scalpel_state.filemirror);
  if (source >= apparent_blocks
      || run_blocks > apparent_blocks - source) {
    return false;
  }

  if (!*page_initialized) {
    for (uint64_t offset = 0; offset < page_blocks; offset++) {
      const uint64_t slot = page_start + offset;
      if (slot >= target && slot < target + run_blocks) {
        continue;
      }
      const int64_t apparent = base_mapping[slot];
      if (apparent < 0
          || !get_apparent_block_bytes(
              scalpel_state.filemirror, apparent, 0,
              (uint32_t)scalpel_state.blocksize,
              page_data + offset * scalpel_state.blocksize)) {
        return false;
      }
    }
    *page_initialized = true;
  }
  for (uint64_t offset = 0; offset < run_blocks; offset++) {
    if (!get_apparent_block_bytes(
            scalpel_state.filemirror, (int64_t)(source + offset), 0,
            (uint32_t)scalpel_state.blocksize,
            page_data + (target - page_start + offset)
                            * scalpel_state.blocksize)) {
      return false;
    }
  }

  const uint64_t header_offset = page_start == 0
      ? SQLITE_FILE_HEADER_SIZE : 0;
  if (header_offset + 12 > layout->page_size) {
    return false;
  }
  const uint8_t page_type = page_data[header_offset];
  const bool interior = page_type == 5;
  if (!interior && page_type != 13) {
    return false;
  }
  if (!sqlite_page_header_plausible(
          page_data + header_offset,
          layout->page_size - header_offset,
          layout->page_size)) {
    return false;
  }

  const uint64_t header_size = interior ? 12 : 8;
  const uint32_t cells = sqlite_read_be16(
      page_data + header_offset + 3);
  if (cells < 2) {
    return false;
  }

  const uint64_t repair_begin =
      (target - page_start) * scalpel_state.blocksize;
  const uint64_t repair_end =
      repair_begin + run_blocks * scalpel_state.blocksize;
  bool repair_touches_order_evidence =
      repair_begin < header_offset + header_size
      && repair_end > header_offset;

  uint64_t previous_key = 0;
  bool have_previous_key = false;
  for (uint32_t cell = 0; cell < cells; cell++) {
    const uint64_t pointer_offset = header_offset + header_size
                                    + (uint64_t)cell * 2;
    if (pointer_offset + 2 > layout->page_size) {
      return false;
    }
    if (repair_begin < pointer_offset + 2
        && repair_end > pointer_offset) {
      repair_touches_order_evidence = true;
    }
    uint64_t cell_offset = sqlite_read_be16(page_data + pointer_offset);
    if (cell_offset >= layout->page_size) {
      return false;
    }
    if (interior) {
      if (cell_offset + 4 > layout->page_size) {
        return false;
      }
      if (repair_begin < cell_offset + 4
          && repair_end > cell_offset) {
        repair_touches_order_evidence = true;
      }
      const uint32_t child = sqlite_read_be32(page_data + cell_offset);
      if (child == 0 || child > layout->page_count) {
        return false;
      }
      cell_offset += 4;
    }
    else {
      uint64_t payload = 0;
      uint32_t payload_bytes = 0;
      if (!sqlite_read_varint(
              page_data + cell_offset,
              layout->page_size - cell_offset,
              &payload, &payload_bytes)) {
        return false;
      }
      (void)payload;
      if (repair_begin < cell_offset + payload_bytes
          && repair_end > cell_offset) {
        repair_touches_order_evidence = true;
      }
      cell_offset += payload_bytes;
    }

    uint64_t key = 0;
    uint32_t key_bytes = 0;
    if (!sqlite_read_varint(
            page_data + cell_offset,
            layout->page_size - cell_offset,
            &key, &key_bytes)) {
      return false;
    }
    if (repair_begin < cell_offset + key_bytes
        && repair_end > cell_offset) {
      repair_touches_order_evidence = true;
    }
    if (have_previous_key && key <= previous_key) {
      return false;
    }
    previous_key = key;
    have_previous_key = true;
  }
  return repair_touches_order_evidence;
}

// Complete SQLite-page spans are less ambiguous because integrity_check may not inspect unused
// bytes within a page. Nonaligned widths remain in the ordering after every aligned width.
static inline uint64_t sqlite_ranked_run_width(uint64_t rank,
                                               uint64_t maximum,
                                               uint64_t target,
                                               uint64_t page_blocks) {
  if (rank == 0 || rank > maximum || page_blocks <= 1
      || target % page_blocks != 0) {
    return rank;
  }
  const uint64_t aligned = maximum / page_blocks;
  if (rank <= aligned) {
    return rank * page_blocks;
  }
  const uint64_t nonaligned_rank = rank - aligned;
  return nonaligned_rank
         + (nonaligned_rank - 1) / (page_blocks - 1);
}

static inline bool sqlite_mapping_check(const int64_t *mapping,
                                        uint64_t blocks, uint64_t extent,
                                        uint8_t *data,
                                        SqliteIntegrity *integrity) {
  if (!sqlite_mapping_materialize(mapping, blocks, extent, data)) {
    sqlite_integrity_initialize(integrity);
    integrity->result_code = SQLITE_CORRUPT;
    integrity->error_count = UINT32_MAX;
    return false;
  }
  return sqlite_integrity_check_mutable(data, extent, integrity);
}

static inline bool sqlite_mapping_check_diagnostic(
    const int64_t *mapping, uint64_t blocks, uint64_t extent,
    uint8_t *data, SqliteIntegrity *integrity,
    SqliteCheckContext *context) {
  if (!sqlite_mapping_materialize(mapping, blocks, extent, data)) {
    sqlite_integrity_initialize(integrity);
    if (context) {
      memset(context, 0, sizeof(*context));
    }
    integrity->result_code = SQLITE_CORRUPT;
    integrity->error_count = UINT32_MAX;
    return false;
  }
  return sqlite_integrity_check_mutable_context(
      data, extent, integrity, context);
}

// Quick-check rejects structurally impossible OOO sources before the full integrity oracle. A
// source that survives quick-check must still pass integrity_check before it can be preserved.
static inline bool sqlite_mapping_ooo_check(
    const int64_t *mapping, uint64_t blocks, uint64_t extent,
    uint8_t *data, SqliteIntegrity *integrity,
    const SqliteIntegrity *reference, bool collect_improvement) {
  if (!sqlite_mapping_materialize(mapping, blocks, extent, data)) {
    sqlite_integrity_initialize(integrity);
    integrity->result_code = SQLITE_CORRUPT;
    integrity->error_count = UINT32_MAX;
    return false;
  }

  SqliteIntegrity quick_integrity;
  if (!sqlite_quick_check_mutable(data, extent, &quick_integrity)) {
    const bool diagnostic_advanced =
        collect_improvement && reference
        && quick_integrity.first_page > 0
        && (reference->first_page == 0
            || quick_integrity.first_page > reference->first_page);
    if (!diagnostic_advanced) {
      *integrity = quick_integrity;
      integrity->error_count = UINT32_MAX;
      return false;
    }
  }
  return sqlite_integrity_check_mutable(data, extent, integrity);
}

// SQLite does not inspect unused bytes while checking integrity. Require every changed block in an
// OOO trial to contribute to the clean result so an unnecessarily broad replacement cannot be
// mistaken for an exact recovery.
static inline bool sqlite_ooo_changes_are_necessary(
    const int64_t *base_mapping, int64_t *trial_mapping,
    uint64_t target, uint64_t run_blocks, uint64_t total_blocks,
    uint64_t extent, uint8_t *data) {
  if (!base_mapping || !trial_mapping || !data || target >= total_blocks
      || run_blocks == 0 || run_blocks > total_blocks - target) {
    return false;
  }

  bool changed = false;
  for (uint64_t offset = 0; offset < run_blocks; offset++) {
    const uint64_t slot = target + offset;
    if (base_mapping[slot] == trial_mapping[slot]) {
      continue;
    }
    const int64_t base_actual = filemirror_actual_blocknumber(
        scalpel_state.filemirror, base_mapping[slot]);
    const int64_t trial_actual = filemirror_actual_blocknumber(
        scalpel_state.filemirror, trial_mapping[slot]);
    if (base_actual >= 0 && trial_actual >= 0
        && filemirror_get_exemplar(scalpel_state.filemirror, base_actual)
               == filemirror_get_exemplar(scalpel_state.filemirror,
                                          trial_actual)) {
      continue;
    }

    changed = true;
    const int64_t trial_block = trial_mapping[slot];
    trial_mapping[slot] = base_mapping[slot];
    SqliteIntegrity integrity;
    const bool still_valid = sqlite_mapping_check(
        trial_mapping, total_blocks, extent, data, &integrity);
    trial_mapping[slot] = trial_block;
    if (still_valid) {
      return false;
    }
  }
  return changed;
}

static inline bool sqlite_integrity_better(const SqliteIntegrity *candidate,
                                           const SqliteIntegrity *current) {
  if (candidate->valid != current->valid) {
    return candidate->valid;
  }
  const bool candidate_completed = candidate->result_code == SQLITE_OK;
  const bool current_completed = current->result_code == SQLITE_OK;
  if (candidate_completed != current_completed) {
    return candidate_completed;
  }
  if (candidate->error_count != current->error_count) {
    return candidate->error_count < current->error_count;
  }
  if (candidate->first_page != current->first_page) {
    if (candidate->first_page == 0) {
      return false;
    }
    if (current->first_page == 0) {
      return true;
    }
    return candidate->first_page > current->first_page;
  }
  return candidate->last_page > current->last_page;
}

// Intermediate mappings can expose a second defect by causing SQLite to stop earlier with fewer
// diagnostics. Rank those mappings by observed structural progress; this affects probe order only.
static inline bool sqlite_integrity_composition_better(
    const SqliteIntegrity *candidate, const SqliteIntegrity *current) {
  if (candidate->valid != current->valid) {
    return candidate->valid;
  }
  if (candidate->error_count != current->error_count) {
    return candidate->error_count < current->error_count;
  }
  const bool candidate_completed = candidate->result_code == SQLITE_OK;
  const bool current_completed = current->result_code == SQLITE_OK;
  if (candidate_completed != current_completed) {
    return candidate_completed;
  }
  if (candidate->first_page != current->first_page) {
    if (candidate->first_page == 0) {
      return false;
    }
    if (current->first_page == 0) {
      return true;
    }
    return candidate->first_page > current->first_page;
  }
  return candidate->last_page > current->last_page;
}

static inline bool sqlite_carve_state_valid(const SqliteCarveState *state) {
  if (!state || state->magic != SQLITE_CARVE_STATE_MAGIC
      || state->version != SQLITE_CARVE_STATE_VERSION
      || state->stage > SQLITE_SEARCH_COMPLETE
      || state->probe_step > 4
      || state->extent < SQLITE_MINIMUM_PAGE_SIZE
      || state->total_blocks == 0
      || state->apparent_blocks == 0
      || state->preferred_target >= state->total_blocks
      || state->cursor.pass > state->total_blocks
      || state->outer_cursor.pass > state->total_blocks) {
    return false;
  }
  if (state->best_gap.valid
      && (state->best_gap.target == 0
          || state->best_gap.target >= state->total_blocks
          || state->best_gap.width == 0
          || state->best_gap.width >= state->apparent_blocks)) {
    return false;
  }
  if (state->best_ooo.valid
      && (state->best_ooo.target == 0
          || state->best_ooo.target >= state->total_blocks
          || state->best_ooo.width == 0
          || state->best_ooo.width
                 > state->total_blocks - state->best_ooo.target
          || state->best_ooo.source >= state->apparent_blocks
          || state->best_ooo.width
                 > state->apparent_blocks - state->best_ooo.source)) {
    return false;
  }
  if (state->active_outer_gap.valid
      && (state->active_outer_gap.target == 0
          || state->active_outer_gap.target >= state->total_blocks
          || state->active_outer_gap.width == 0
          || state->active_outer_gap.width >= state->apparent_blocks)) {
    return false;
  }
  return true;
}

static inline bool sqlite_serialize_carve_state(void **state, FILE *fp,
                                                StateSerialization mode) {
  SqliteCarveState **sqlite_state = (SqliteCarveState **)state;
  if (!sqlite_state || !fp) {
    return false;
  }
  if (mode == SERIALIZE) {
    if (!sqlite_carve_state_valid(*sqlite_state)) {
      handle_error(SCALPEL_ERROR_CHECKPOINT, "invalid SQLite carve state",
                   __LINE__, __FILE__);
    }
    if (fwrite(*sqlite_state, sizeof(**sqlite_state), 1, fp) != 1) {
      perror("SQLite carve state serialization");
      handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
    }
    return true;
  }

  SqliteCarveState *restored =
      (SqliteCarveState *)malloc(sizeof(*restored));
  check_memory_allocation(restored, __LINE__, __FILE__,
                          "SQLite carve state");
  if (fread(restored, sizeof(*restored), 1, fp) != 1) {
    free(restored);
    handle_error(SCALPEL_ERROR_CHECKPOINT, "invalid SQLite carve state",
                 __LINE__, __FILE__);
  }
  // Older states use different search-stage or cursor ordering. Restart their ranking search so
  // persisted numeric fields are never interpreted using the current scheduler.
  if (restored->magic == SQLITE_CARVE_STATE_MAGIC
      && (restored->version == UINT32_C(6)
          || restored->version == UINT32_C(7)
          || restored->version == UINT32_C(8)
          || restored->version == UINT32_C(9))) {
    restored->version = SQLITE_CARVE_STATE_VERSION;
    restored->stage = SQLITE_SEARCH_INITIAL_PROBES;
    restored->probe_step = 0;
    sqlite_cursor_reset(&restored->cursor);
    sqlite_cursor_reset(&restored->outer_cursor);
    memset(&restored->best_gap, 0, sizeof(restored->best_gap));
    memset(&restored->best_ooo, 0, sizeof(restored->best_ooo));
    memset(&restored->active_outer_gap, 0,
           sizeof(restored->active_outer_gap));
    restored->best_gap_integrity = restored->baseline_integrity;
    restored->best_ooo_integrity = restored->baseline_integrity;
  }
  if (!sqlite_carve_state_valid(restored)) {
    free(restored);
    handle_error(SCALPEL_ERROR_CHECKPOINT, "invalid SQLite carve state",
                 __LINE__, __FILE__);
  }
  *sqlite_state = restored;
  return true;
}

static inline void *sqlite_clone_carve_state(const void *srcstate) {
  const SqliteCarveState *source = (const SqliteCarveState *)srcstate;
  if (!sqlite_carve_state_valid(source)) {
    return NULL;
  }
  SqliteCarveState *clone = (SqliteCarveState *)malloc(sizeof(*clone));
  check_memory_allocation(clone, __LINE__, __FILE__,
                          "SQLite carve state clone");
  memcpy(clone, source, sizeof(*clone));
  return clone;
}

static inline void sqlite_free_carve_state(void **state) {
  if (state) {
    free(*state);
    *state = NULL;
  }
}

static inline size_t sqlite_sizeof_carve_state(const void *state) {
  (void)state;
  return sizeof(SqliteCarveState);
}

static inline void sqlite_print_carve_state(const void *state) {
  const SqliteCarveState *sqlite_state =
      (const SqliteCarveState *)state;
  if (!sqlite_state) {
    fprintf(stdout, "NULL");
    return;
  }
  fprintf(stdout,
          "stage=%u pass=%" PRIu64 " width=%" PRIu64
          " source=%" PRIu64,
          sqlite_state->stage, sqlite_state->cursor.pass,
          sqlite_state->cursor.width, sqlite_state->cursor.source);
}

static inline uint64_t sqlite_mapping_hash(const int64_t *mapping,
                                           uint64_t blocks) {
  uint64_t hash = UINT64_C(1469598103934665603);
  for (uint64_t slot = 0; slot < blocks; slot++) {
    int64_t actual = mapping[slot] < 0
        ? -1
        : filemirror_actual_blocknumber(scalpel_state.filemirror,
                                        mapping[slot]);
    hash ^= (uint64_t)actual;
    hash *= UINT64_C(1099511628211);
    hash ^= slot;
    hash *= UINT64_C(1099511628211);
  }
  return hash;
}

static inline void sqlite_cursor_reset(SqliteSearchCursor *cursor) {
  if (cursor) {
    cursor->pass = 0;
    cursor->width = 1;
    cursor->source = 0;
  }
}

static inline bool sqlite_apply_gap_descriptor(
    const int64_t *base_mapping, uint64_t total_blocks,
    const SqliteRepairDescriptor *repair, int64_t *mapping) {
  if (!base_mapping || !repair || !mapping || !repair->valid
      || repair->target == 0 || repair->target >= total_blocks
      || repair->width == 0 || base_mapping[repair->target] < 0
      || repair->width > INT64_MAX
      || base_mapping[repair->target]
             > INT64_MAX - (int64_t)repair->width) {
    return false;
  }
  const uint64_t apparent_blocks =
      filemirror_apparent_blocks(scalpel_state.filemirror);
  memcpy(mapping, base_mapping, total_blocks * sizeof(*mapping));
  for (uint64_t slot = repair->target; slot < total_blocks; slot++) {
    const uint64_t offset = slot - repair->target;
    if (offset > INT64_MAX
        || base_mapping[repair->target] > INT64_MAX - (int64_t)offset) {
      return false;
    }
    const int64_t expected = base_mapping[repair->target]
                             + (int64_t)offset;
    if (base_mapping[slot] == expected) {
      if (expected > INT64_MAX - (int64_t)repair->width
          || (uint64_t)(expected + (int64_t)repair->width)
                 >= apparent_blocks) {
        return false;
      }
      mapping[slot] = expected + (int64_t)repair->width;
    }
  }
  return true;
}

static inline bool sqlite_apply_ooo_descriptor(
    const int64_t *base_mapping, uint64_t total_blocks,
    const SqliteRepairDescriptor *repair, int64_t *mapping) {
  const uint64_t apparent_blocks =
      filemirror_apparent_blocks(scalpel_state.filemirror);
  if (!base_mapping || !repair || !mapping || !repair->valid
      || repair->target == 0 || repair->target >= total_blocks
      || repair->width == 0
      || repair->width > total_blocks - repair->target
      || repair->source >= apparent_blocks
      || repair->width > apparent_blocks - repair->source
      || sqlite_source_overlaps_mapping(base_mapping, total_blocks,
                                        repair->target, repair->width,
                                        (int64_t)repair->source)) {
    return false;
  }
  memcpy(mapping, base_mapping, total_blocks * sizeof(*mapping));
  for (uint64_t offset = 0; offset < repair->width; offset++) {
    mapping[repair->target + offset] =
        (int64_t)(repair->source + offset);
  }
  return true;
}

static inline bool sqlite_repair_list_append(
    SqliteRepairList *list, const SqliteRepairDescriptor *repair) {
  if (!list || !repair || list->allocation_failed) {
    return false;
  }
  if (list->count == list->capacity) {
    uint64_t capacity = list->capacity == 0 ? 16 : list->capacity * 2;
    if (capacity < list->capacity
        || capacity > SIZE_MAX / sizeof(*list->repairs)) {
      list->allocation_failed = true;
      return false;
    }
    SqliteRepairDescriptor *repairs = (SqliteRepairDescriptor *)realloc(
        list->repairs, (size_t)capacity * sizeof(*list->repairs));
    if (!repairs) {
      list->allocation_failed = true;
      return false;
    }
    list->repairs = repairs;
    list->capacity = capacity;
  }
  list->repairs[list->count++] = *repair;
  if (repair->reserved) {
    list->reserved_count++;
  }
  else {
    list->unreserved_count++;
  }
  return true;
}

static inline bool sqlite_reassembly_poll(ThreadWork *work,
                                          CarveInfo **candidate,
                                          uuid_string_t uuidp,
                                          uuid_string_t uuidc,
                                          SqliteCarveState *state,
                                          uint64_t *iterations) {
  (*iterations)++;
  if (*iterations % SQLITE_REASSEMBLY_PROGRESS_INTERVAL == 0
      && !scalpel_state.mode_verbose) {
    lock_fprintf(stdout, "%s.%s", BLUE, BLACK);
    fflush(stdout);
  }
  if (*iterations % SQLITE_REASSEMBLY_POLL_INTERVAL != 0) {
    return false;
  }
  if (reassembly_check_kill_queue(work, candidate, uuidp, uuidc)) {
    return true;
  }
  if (atomic_load_explicit(&REASS_RETURN_TO_IDLE, memory_order_acquire)
      && candidate && *candidate) {
    SqliteCarveState checkpoint_state = *state;
    if (atomic_load_explicit(&TAKE_CHECKPOINT_AND_EXIT,
                             memory_order_acquire)) {
      // Periodic checkpoints advance past bounded probes so a very large candidate cannot restart
      // one forever. A checkpoint-and-exit has no such forward-progress requirement: rerun the
      // interrupted probe after restore rather than falling immediately into exhaustive search.
      if (checkpoint_state.stage == SQLITE_SEARCH_INITIAL_PROBES
          && checkpoint_state.probe_step > 0) {
        if (checkpoint_state.probe_step == 4) {
          memset(&checkpoint_state.best_gap, 0,
                 sizeof(checkpoint_state.best_gap));
          checkpoint_state.best_gap_integrity =
              checkpoint_state.baseline_integrity;
        }
        checkpoint_state.probe_step--;
      }
      else if (checkpoint_state.stage == SQLITE_SEARCH_RANKED_GAP_OOO
               && checkpoint_state.outer_cursor.pass == 1
               && checkpoint_state.cursor.pass == 0
               && checkpoint_state.cursor.width == 1
               && checkpoint_state.cursor.source == 0) {
        checkpoint_state.outer_cursor.pass = 0;
      }
    }
    carve_put_state((*candidate)->carvehashkey, &checkpoint_state);
    if (reassembly_time_to_checkpoint(work->id, *candidate, uuidp, uuidc)) {
      return true;
    }
  }
  return false;
}

static inline bool sqlite_commit_mapping(CarveInfo *candidate,
                                         const int64_t *mapping,
                                         uint64_t blocks,
                                         uint64_t extent) {
  if (!candidate || !candidate->b || !mapping) {
    return false;
  }
  resize_blockvector(candidate->b, blocks);
  for (uint64_t slot = 0; slot < blocks; slot++) {
    blockvector_set_apparent_blocknumber(candidate->b, slot,
                                         mapping[slot]);
  }
  normalize_blockvector(candidate->b);
  blockvector_set_data_length(candidate->b, extent);
  inflate_blockvector(candidate->b);
  return true;
}

// SQLite integrity does not authenticate every byte in database free space. Preserve each clean,
// byte-distinct mapping as a promising hypothesis so structural ambiguity remains explicit.
static inline bool sqlite_write_mapping_hypothesis(
    CarveInfo *candidate, const int64_t *mapping,
    uint64_t blocks, uint64_t extent) {
  if (!scalpel_state.write_promising || !candidate || !candidate->b
      || !mapping) {
    return false;
  }

  BlockVector *parent_blockvector = candidate->b;
  BlockVector *hypothesis = NULL;
  const CarveInfoFlavor parent_flavor = candidate->flavor;

  clone_blockvector(parent_blockvector, &hypothesis, true);
  candidate->b = hypothesis;
  const bool committed = sqlite_commit_mapping(
      candidate, mapping, blocks, extent);
  if (committed) {
    candidate->flavor = PROMISING;
    CarveInfo *preserved_candidate = candidate;
    write_candidate(&preserved_candidate, true);
  }
  free_blockvector(&candidate->b);
  candidate->b = parent_blockvector;
  candidate->flavor = parent_flavor;
  return committed;
}

// A clean SQLite mapping can omit adjacent displaced blocks that contain free or otherwise unused
// bytes. Preserve clean extensions in both directions before treating the local repair as complete.
static inline SqliteRepairResult sqlite_preserve_ooo_extensions(
    ThreadWork *work, CarveInfo **candidate, uuid_string_t uuidp,
    uuid_string_t uuidc, const SqliteLayout *layout,
    const int64_t *base_mapping, uint64_t total_blocks,
    uint64_t target, uint64_t run_blocks, uint64_t source,
    uint8_t *trial_data, int64_t *trial_mapping,
    int64_t *extended_mapping,
    SqliteCarveState *state, uint64_t *iterations,
    bool *ambiguity_closed) {
  const uint64_t apparent_blocks =
      filemirror_apparent_blocks(scalpel_state.filemirror);
  bool direction_closed[2] = {false, false};

  if (ambiguity_closed) {
    *ambiguity_closed = false;
  }
  for (uint32_t direction = 0; direction < 2; direction++) {
    for (uint64_t extension = 1;
         extension <= SQLITE_FAST_PROBE_MAXIMUM_RUN_BLOCKS;
         extension++) {
      uint64_t extended_target = target;
      uint64_t extended_source = source;
      if (direction == 1) {
        if (extension > target || extension > source) {
          direction_closed[direction] = true;
          break;
        }
        extended_target -= extension;
        extended_source -= extension;
      }
      const uint64_t extended_run = run_blocks + extension;
      if (extended_target >= total_blocks
          || extended_run > total_blocks - extended_target
          || extended_source >= apparent_blocks
          || extended_run > apparent_blocks - extended_source
          || sqlite_source_overlaps_mapping(
              base_mapping, total_blocks, extended_target,
              extended_run, (int64_t)extended_source)) {
        direction_closed[direction] = true;
        break;
      }

      memcpy(trial_mapping, base_mapping,
             total_blocks * sizeof(*trial_mapping));
      for (uint64_t offset = 0; offset < extended_run; offset++) {
        trial_mapping[extended_target + offset] =
            (int64_t)(extended_source + offset);
      }
      SqliteIntegrity integrity;
      if (!sqlite_mapping_check(trial_mapping, total_blocks,
                                layout->extent, trial_data,
                                &integrity)) {
        direction_closed[direction] = true;
        break;
      }
      sqlite_write_mapping_hypothesis(
          *candidate, trial_mapping, total_blocks, layout->extent);
      if (extended_mapping) {
        memcpy(extended_mapping, trial_mapping,
               total_blocks * sizeof(*extended_mapping));
      }
      if (sqlite_reassembly_poll(work, candidate, uuidp, uuidc,
                                 state, iterations)) {
        return SQLITE_REPAIR_STOPPED;
      }
    }
  }
  if (ambiguity_closed) {
    *ambiguity_closed = direction_closed[0] && direction_closed[1];
  }
  return SQLITE_REPAIR_NO_MATCH;
}

// SQLite may not inspect an unused block adjacent to the apparent gap. Once a clean displaced run
// is known, apply that same run to nearby gap boundaries and preserve every mapping that remains
// structurally clean. This records byte-distinct alternatives instead of treating an arbitrary
// integrity tie as ground truth.
static inline SqliteRepairResult sqlite_preserve_gap_alternatives(
    ThreadWork *work, CarveInfo **candidate, uuid_string_t uuidp,
    uuid_string_t uuidc, const SqliteLayout *layout,
    const int64_t *base_mapping, uint64_t total_blocks,
    const SqliteRepairDescriptor *selected_gap,
    const int64_t *selected_gap_mapping,
    const int64_t *selected_solution_mapping,
    uint8_t *trial_data, int64_t *trial_mapping,
    SqliteCarveState *state, uint64_t *iterations) {
  if (!candidate || !*candidate || !layout || !base_mapping
      || !selected_gap || !selected_gap->valid
      || !selected_gap_mapping || !selected_solution_mapping
      || !trial_data || !trial_mapping || total_blocks < 2) {
    return SQLITE_REPAIR_NO_MATCH;
  }

  uint64_t radius = CEILDIV(layout->page_size,
                            scalpel_state.blocksize);
  if (radius < SQLITE_FAST_PROBE_MAXIMUM_GAP_BLOCKS) {
    radius = SQLITE_FAST_PROBE_MAXIMUM_GAP_BLOCKS;
  }
  uint64_t first_target = selected_gap->target > radius
      ? selected_gap->target - radius : 1;
  uint64_t last_target = total_blocks - 1;
  if (radius < last_target - selected_gap->target) {
    last_target = selected_gap->target + radius;
  }

  uint64_t preserved = 0;
  for (uint64_t target = first_target; target <= last_target;
       target++) {
    if (target == selected_gap->target) {
      continue;
    }
    SqliteRepairDescriptor alternative = *selected_gap;
    alternative.target = target;
    if (!sqlite_apply_gap_descriptor(base_mapping, total_blocks,
                                     &alternative, trial_mapping)) {
      continue;
    }
    for (uint64_t slot = 0; slot < total_blocks; slot++) {
      if (selected_solution_mapping[slot]
          != selected_gap_mapping[slot]) {
        trial_mapping[slot] = selected_solution_mapping[slot];
      }
    }

    SqliteIntegrity integrity;
    if (sqlite_mapping_check(trial_mapping, total_blocks,
                             layout->extent, trial_data,
                             &integrity)) {
      sqlite_write_mapping_hypothesis(
          *candidate, trial_mapping, total_blocks, layout->extent);
      preserved++;
    }
    if (sqlite_reassembly_poll(work, candidate, uuidp, uuidc,
                               state, iterations)) {
      return SQLITE_REPAIR_STOPPED;
    }
  }
  if (preserved > 0 && scalpel_state.mode_verbose) {
    lock_fprintf(stdout,
                 "SQLite reassembly: preserved %" PRIu64
                 " clean neighboring GAP mapping%s.\n",
                 preserved, preserved == 1 ? "" : "s");
  }
  return SQLITE_REPAIR_NO_MATCH;
}

// A clean repair can identify only the inspected portion of a SQLite page. Complete that page
// from each repaired anchor and preserve every full-page mapping that remains structurally clean.
static inline SqliteRepairResult sqlite_preserve_partial_page_completions(
    ThreadWork *work, CarveInfo **candidate, uuid_string_t uuidp,
    uuid_string_t uuidc, const SqliteLayout *layout,
    const int64_t *base_mapping, uint64_t total_blocks,
    const uint64_t *targets, const uint64_t *widths,
    uint64_t target_count, uint8_t *trial_data,
    int64_t *trial_mapping, SqliteCarveState *state,
    uint64_t *iterations) {
  if (!candidate || !*candidate || !layout || !base_mapping
      || !targets || !widths || !trial_data || !trial_mapping
      || !state || !iterations || scalpel_state.blocksize == 0
      || layout->page_size % scalpel_state.blocksize != 0) {
    return SQLITE_REPAIR_NO_MATCH;
  }

  const uint64_t page_blocks =
      layout->page_size / scalpel_state.blocksize;
  if (page_blocks <= 1) {
    return SQLITE_REPAIR_NO_MATCH;
  }
  const uint64_t apparent_blocks =
      filemirror_apparent_blocks(scalpel_state.filemirror);
  uint64_t attempted_targets[
      SQLITE_PAGE_TRANSITION_LIMIT * 2] = {0};
  uint64_t attempted_sources[
      SQLITE_PAGE_TRANSITION_LIMIT * 2] = {0};
  uint64_t attempted_count = 0;
  uint64_t preserved = 0;

  for (uint64_t repair = 0; repair < target_count; repair++) {
    if (targets[repair] >= total_blocks) {
      continue;
    }
    uint64_t repair_width = widths[repair];
    if (repair_width > total_blocks - targets[repair]) {
      repair_width = total_blocks - targets[repair];
    }
    if (repair_width == 0) {
      continue;
    }
    const uint64_t anchor_count = repair_width > 1 ? 2 : 1;
    for (uint64_t anchor_rank = 0; anchor_rank < anchor_count;
         anchor_rank++) {
      const uint64_t offset = anchor_rank == 0
          ? 0 : repair_width - 1;
      const uint64_t anchor = targets[repair] + offset;
      const uint64_t page_target = (anchor / page_blocks) * page_blocks;
      uint64_t page_width = page_blocks;
      if (page_width > total_blocks - page_target) {
        page_width = total_blocks - page_target;
      }
      const uint64_t anchor_offset = anchor - page_target;
      if (base_mapping[anchor] < 0
          || (uint64_t)base_mapping[anchor] < anchor_offset) {
        continue;
      }
      const uint64_t page_source =
          (uint64_t)base_mapping[anchor] - anchor_offset;
      if (page_source >= apparent_blocks
          || page_width > apparent_blocks - page_source) {
        continue;
      }

      bool attempted = false;
      for (uint64_t prior = 0; prior < attempted_count; prior++) {
        if (attempted_targets[prior] == page_target
            && attempted_sources[prior] == page_source) {
          attempted = true;
          break;
        }
      }
      if (attempted) {
        continue;
      }
      if (attempted_count
          < SQLITE_PAGE_TRANSITION_LIMIT * 2) {
        attempted_targets[attempted_count] = page_target;
        attempted_sources[attempted_count] = page_source;
        attempted_count++;
      }

      if (sqlite_source_overlaps_mapping(
              base_mapping, total_blocks, page_target, page_width,
              (int64_t)page_source)) {
        continue;
      }
      memcpy(trial_mapping, base_mapping,
             total_blocks * sizeof(*trial_mapping));
      bool changed = false;
      for (uint64_t page_offset = 0; page_offset < page_width;
           page_offset++) {
        const int64_t source = (int64_t)(page_source + page_offset);
        if (trial_mapping[page_target + page_offset] != source) {
          changed = true;
          trial_mapping[page_target + page_offset] = source;
        }
      }
      if (!changed) {
        continue;
      }

      SqliteIntegrity integrity;
      if (sqlite_mapping_check(trial_mapping, total_blocks,
                               layout->extent, trial_data,
                               &integrity)
          && sqlite_write_mapping_hypothesis(
              *candidate, trial_mapping, total_blocks,
              layout->extent)) {
        preserved++;
      }
      if (sqlite_reassembly_poll(work, candidate, uuidp, uuidc,
                                 state, iterations)) {
        return SQLITE_REPAIR_STOPPED;
      }
    }
  }
  return preserved > 0 ? SQLITE_REPAIR_PRESERVED
                       : SQLITE_REPAIR_NO_MATCH;
}

static inline uint64_t sqlite_page_block(uint32_t page,
                                         const SqliteLayout *layout,
                                         uint64_t blocksize,
                                         uint64_t total_blocks) {
  if (!layout || page == 0 || page > layout->page_count
      || blocksize == 0) {
    return 0;
  }
  const uint64_t offset = ((uint64_t)page - 1) * layout->page_size;
  const uint64_t block = offset / blocksize;
  return block < total_blocks ? block : 0;
}

// SQLite integrity diagnostics identify damaged b-tree cells. Resolve the cell pointer to the
// carve block containing that cell so opaque sub-page content can still guide OOO search.
static inline uint64_t sqlite_diagnostic_cell_block(
    const SqliteCheckContext *context, const uint8_t *data,
    const SqliteLayout *layout, uint64_t blocksize,
    uint64_t total_blocks) {
  if (!context || !context->cell_diagnostic_found || !data || !layout
      || context->cell_page == 0
      || context->cell_page > layout->page_count || blocksize == 0) {
    return 0;
  }
  const uint64_t page_offset =
      ((uint64_t)context->cell_page - 1) * layout->page_size;
  const uint64_t header_offset = context->cell_page == 1
      ? SQLITE_FILE_HEADER_SIZE : 0;
  if (page_offset >= layout->extent
      || header_offset + 12 > layout->extent - page_offset) {
    return 0;
  }

  const uint8_t *page = data + page_offset;
  const uint8_t *header = page + header_offset;
  const bool interior = header[0] == 2 || header[0] == 5;
  if (!interior && header[0] != 10 && header[0] != 13) {
    return 0;
  }
  const uint64_t header_size = interior ? 12 : 8;
  const uint32_t cells = sqlite_read_be16(header + 3);
  if (context->cell_index >= cells) {
    return 0;
  }
  const uint64_t pointer_offset = header_offset + header_size
                                  + (uint64_t)context->cell_index * 2;
  if (pointer_offset + 2 > layout->page_size
      || pointer_offset + 2 > layout->extent - page_offset) {
    return 0;
  }
  const uint32_t cell_offset = sqlite_read_be16(page + pointer_offset);
  if (cell_offset == 0 || cell_offset >= layout->page_size) {
    return 0;
  }
  const uint64_t block = (page_offset + cell_offset) / blocksize;
  return block > 0 && block < total_blocks ? block : 0;
}

static inline uint64_t sqlite_failure_block(const SqliteIntegrity *integrity,
                                            const SqliteLayout *layout,
                                            const int64_t *mapping,
                                            uint64_t blocksize,
                                            uint64_t total_blocks) {
  uint64_t preferred = 1;
  uint32_t diagnostic_page = 0;
  if (integrity) {
    diagnostic_page = integrity->last_page > 0
        ? integrity->last_page : integrity->first_page;
  }
  const uint64_t block = sqlite_page_block(
      diagnostic_page, layout, blocksize, total_blocks);
  if (block > 0) {
    preferred = block;
  }

  // Fragmentation holes are frequently zero-filled. Prefer the first such block at or after the
  // diagnostic location, but use this only as search ordering; exact integrity still decides.
  if (mapping) {
    for (uint64_t slot = preferred; slot < total_blocks; slot++) {
      if (sqlite_mapping_block_is_zero(mapping, slot)) {
        return slot;
      }
    }
    for (uint64_t slot = 1; slot < preferred; slot++) {
      if (sqlite_mapping_block_is_zero(mapping, slot)) {
        return slot;
      }
    }
  }
  return preferred;
}

// Probe short runs that overlap a diagnostic location immediately after a trial improves
// integrity. The damaged page may identify any block in a displaced run, not necessarily its
// first block. This remains an ordering optimization; the complete search below has no run-width
// limit.
static inline SqliteRepairResult sqlite_probe_ooo_repair(
    ThreadWork *work, CarveInfo **candidate, uuid_string_t uuidp,
    uuid_string_t uuidc, const SqliteLayout *layout,
    const SqliteIntegrity *baseline_integrity,
    const int64_t *base_mapping, uint64_t total_blocks,
    uint64_t target_hint, bool exact_target, uint64_t width_hint,
    uint8_t *trial_data,
    int64_t *trial_mapping, int64_t *solution_mapping,
    int64_t *composition_mapping, bool compose,
    bool high_confidence_only, bool key_order_only,
    SqliteRepairList *plausible_repairs,
    SqliteCarveState *state, uint64_t *iterations) {
  const uint64_t apparent_blocks =
      filemirror_apparent_blocks(scalpel_state.filemirror);
  SqliteIntegrity best_integrity;
  bool have_improvement = false;
  bool preserved_clean_hypothesis = false;
  bool preserved_bounded_hypothesis = false;
  bool preserved_necessary_hypothesis = false;
  if (baseline_integrity) {
    best_integrity = *baseline_integrity;
  }
  if (target_hint == 0 || target_hint >= total_blocks) {
    return SQLITE_REPAIR_NO_MATCH;
  }
  uint64_t target_span = CEILDIV(layout->page_size,
                                 scalpel_state.blocksize);
  if (target_span == 0) {
    target_span = 1;
  }
  if (!key_order_only
      && target_span <= SQLITE_FAST_PROBE_MAXIMUM_RUN_BLOCKS) {
    target_span = SQLITE_FAST_PROBE_MAXIMUM_RUN_BLOCKS + 1;
  }
  uint64_t last_target = exact_target ? target_hint : total_blocks - 1;
  if (!exact_target && target_span - 1 < last_target - target_hint) {
    last_target = target_hint + target_span - 1;
  }
  uint64_t mapping_min = apparent_blocks;
  uint64_t mapping_max = 0;
  for (uint64_t slot = 0; slot < total_blocks; slot++) {
    if (base_mapping[slot] >= 0) {
      const uint64_t apparent = (uint64_t)base_mapping[slot];
      if (apparent < mapping_min) {
        mapping_min = apparent;
      }
      if (apparent > mapping_max) {
        mapping_max = apparent;
      }
    }
  }

  const uint32_t confidence_passes = key_order_only
      ? 2 : (high_confidence_only
          ? (plausible_repairs ? 5 : 2) : 7);
  uint8_t page_data[SQLITE_MAXIMUM_PAGE_SIZE];
  uint64_t page_data_target = UINT64_MAX;
  uint64_t page_data_run_blocks = 0;
  bool page_data_initialized = false;
  uint64_t page_blocks = CEILDIV(layout->page_size,
                                 scalpel_state.blocksize);
  if (page_blocks == 0) {
    page_blocks = 1;
  }
  bool direct_key_order_target = exact_target || !compose;
  if (baseline_integrity) {
    const uint64_t first_page_target = sqlite_page_block(
        baseline_integrity->first_page, layout,
        scalpel_state.blocksize, total_blocks);
    if (first_page_target > 0) {
      direct_key_order_target = target_hint >= first_page_target
          && target_hint - first_page_target < page_blocks;
    }
  }
  // Cell diagnostics inside SQLite's first damaged page are strong direct OOO evidence. A target
  // beyond that page can describe a later defect, so classification remains ahead of key order.
  const uint32_t key_order_pass = direct_key_order_target ? 0U : 2U;
  if (key_order_only && key_order_pass != 0) {
    return SQLITE_REPAIR_NO_MATCH;
  }
  uint64_t maximum_probe = total_blocks - target_hint;
  if (maximum_probe > SQLITE_FAST_PROBE_MAXIMUM_RUN_BLOCKS) {
    maximum_probe = SQLITE_FAST_PROBE_MAXIMUM_RUN_BLOCKS;
  }
  if (maximum_probe > apparent_blocks) {
    maximum_probe = apparent_blocks;
  }
  if (width_hint != 0 && width_hint < maximum_probe) {
    maximum_probe = width_hint;
  }
  const uint32_t reservation_passes = scalpel_state.reservations ? 2 : 1;
  for (uint32_t confidence_pass = 0;
       confidence_pass < confidence_passes; confidence_pass++) {
    for (uint32_t reservation_pass = 0;
         reservation_pass < reservation_passes; reservation_pass++) {
      for (uint64_t pass = 1; pass <= maximum_probe; pass++) {
        uint64_t run_blocks = pass;
        if (width_hint != 0 && width_hint <= maximum_probe) {
          run_blocks = pass == 1 ? width_hint
              : (pass <= width_hint ? pass - 1 : pass);
        }
        else if (page_blocks <= 2) {
          run_blocks = sqlite_ranked_run_width(
              pass, maximum_probe, target_hint, page_blocks);
        }
        uint64_t first_target = target_hint;
        if (run_blocks > 1) {
          first_target = run_blocks - 1 < target_hint
              ? target_hint - (run_blocks - 1) : 1;
        }
        const uint64_t target_count = last_target - first_target + 1;
        const uint64_t right_targets = last_target - target_hint + 1;
        for (uint64_t target_rank = 0;
             target_rank < target_count; target_rank++) {
          const uint64_t target = target_rank < right_targets
              ? target_hint + target_rank
              : target_hint - 1 - (target_rank - right_targets);
          uint64_t maximum_run = total_blocks - target;
          if (maximum_run > maximum_probe) {
            maximum_run = maximum_probe;
          }
          if (run_blocks > maximum_run) {
            continue;
          }
          const uint64_t last_source = apparent_blocks - run_blocks;
          const uint64_t after_start = mapping_max < last_source
              ? mapping_max + 1 : last_source + 1;
          const uint64_t after_count = after_start <= last_source
              ? last_source - after_start + 1 : 0;
          const uint64_t before_count = mapping_min >= run_blocks
              ? mapping_min - run_blocks + 1 : 0;
          const uint64_t internal_start = mapping_min <= last_source
              ? mapping_min : last_source + 1;
          const uint64_t internal_end = mapping_max < last_source
              ? mapping_max : last_source;
          const uint64_t internal_count = plausible_repairs
              && plausible_repairs->include_internal_sources
              && internal_start <= internal_end
                  ? internal_end - internal_start + 1 : 0;
          // A prior OOO repair can expand the physical envelope around another displaced run.
          // Search unused blocks inside that envelope first. Appended fragments are the most likely
          // exterior sources, so search the range after the candidate before wrapping backward.
          const uint64_t source_count =
              internal_count + after_count + before_count;
          for (uint64_t source_rank = 0;
               source_rank < source_count; source_rank++) {
              uint64_t source = 0;
              if (source_rank < internal_count) {
                source = internal_start + source_rank;
              }
              else {
                const uint64_t exterior_rank =
                    source_rank - internal_count;
                source = exterior_rank < after_count
                    ? after_start + exterior_rank
                    : before_count - 1
                        - (exterior_rank - after_count);
              }
              bool unchanged_source = true;
              for (uint64_t offset = 0; offset < run_blocks; offset++) {
                if (base_mapping[target + offset]
                    != (int64_t)(source + offset)) {
                  unchanged_source = false;
                  break;
                }
              }
              if (unchanged_source) {
                if (sqlite_reassembly_poll(work, candidate, uuidp, uuidc,
                                           state, iterations)) {
                  return SQLITE_REPAIR_STOPPED;
                }
                continue;
              }
              if (key_order_only) {
                const bool classification_evidence =
                    sqlite_source_has_classification_evidence(
                        source, run_blocks, (*candidate)->needleidx);
                if ((confidence_pass == 0) != classification_evidence) {
                  if (sqlite_reassembly_poll(work, candidate, uuidp,
                                             uuidc, state, iterations)) {
                    return SQLITE_REPAIR_STOPPED;
                  }
                  continue;
                }
              }
              bool layout_evidence = false;
              bool block_evidence = false;
              bool classification_evidence = false;
              bool left_block_evidence = false;
              bool right_block_evidence = false;
              if (!key_order_only) {
                layout_evidence = sqlite_source_has_layout_page_evidence(
                    source, run_blocks, target, layout,
                    (*candidate)->needleidx);
                block_evidence = sqlite_source_has_page_evidence(
                    source, run_blocks, (*candidate)->needleidx);
                classification_evidence =
                    sqlite_source_has_classification_evidence(
                        source, run_blocks, (*candidate)->needleidx);
              uint64_t previous_stride = 0;
              for (uint64_t sqlite_page_size =
                       SQLITE_MINIMUM_PAGE_SIZE;
                   sqlite_page_size <= SQLITE_MAXIMUM_PAGE_SIZE;
                   sqlite_page_size *= 2) {
                const uint64_t evidence_stride = CEILDIV(
                    sqlite_page_size, scalpel_state.blocksize);
                if (evidence_stride == previous_stride) {
                  continue;
                }
                previous_stride = evidence_stride;
                left_block_evidence = left_block_evidence
                    || (source >= evidence_stride
                        && sqlite_source_has_page_evidence(
                            source - evidence_stride, 1,
                            (*candidate)->needleidx));
                right_block_evidence = right_block_evidence
                    || (source + evidence_stride < apparent_blocks
                        && sqlite_source_has_page_evidence(
                            source + evidence_stride, 1,
                            (*candidate)->needleidx));
                if (left_block_evidence || right_block_evidence) {
                  break;
                }
              }
              }
              const bool block_isolated =
                  !left_block_evidence && !right_block_evidence;
              const bool layout_isolated = block_isolated;
              if (page_data_target != target
                  || page_data_run_blocks != run_blocks) {
                page_data_target = target;
                page_data_run_blocks = run_blocks;
                page_data_initialized = false;
              }
              const bool key_order_evidence =
                  (key_order_only || confidence_pass == key_order_pass)
                  && (key_order_only || !layout_evidence)
                  && run_blocks < page_blocks
                  && sqlite_ooo_page_key_order_plausible(
                      base_mapping, total_blocks, target,
                      run_blocks, source, layout, page_data,
                      &page_data_initialized);
              if (key_order_only && !key_order_evidence) {
                if (sqlite_reassembly_poll(work, candidate, uuidp,
                                           uuidc, state, iterations)) {
                  return SQLITE_REPAIR_STOPPED;
                }
                continue;
              }
              const bool evidence_bounded_hint =
                  width_hint != 0 && run_blocks <= width_hint
                  && (key_order_evidence || layout_evidence
                      || block_evidence);
              uint32_t source_pass = 0;
              if (key_order_evidence) {
                source_pass = key_order_pass;
              }
              else if (layout_evidence) {
                source_pass = layout_isolated ? 0U : 1U;
              }
              else if (block_evidence) {
                source_pass = plausible_repairs
                    ? (block_isolated ? 2U : 3U)
                    : (block_isolated ? 3U : 4U);
              }
              else if (classification_evidence) {
                source_pass = 4U;
              }
              else {
                source_pass = block_isolated ? 5U : 6U;
              }
              if (!key_order_only && confidence_pass != source_pass) {
                if (sqlite_reassembly_poll(work, candidate, uuidp,
                                           uuidc, state, iterations)) {
                  return SQLITE_REPAIR_STOPPED;
                }
                continue;
              }
              if (sqlite_source_overlaps_mapping(base_mapping, total_blocks,
                                                 target, run_blocks,
                                                 (int64_t)source)) {
                if (sqlite_reassembly_poll(work, candidate, uuidp, uuidc,
                                           state, iterations)) {
                  return SQLITE_REPAIR_STOPPED;
                }
                continue;
              }
              bool source_reserved = false;
              if (scalpel_state.reservations) {
                for (uint64_t offset = 0; offset < run_blocks; offset++) {
                  const int64_t actual = filemirror_actual_blocknumber(
                      scalpel_state.filemirror,
                      (int64_t)(source + offset));
                  if (filemirror_actual_block_reserved(
                          scalpel_state.filemirror, actual) > 0) {
                    source_reserved = true;
                    break;
                  }
                }
              }
              const bool wrong_reservation_pass =
                  (evidence_bounded_hint && !plausible_repairs
                   && reservation_pass > 0)
                  || ((!evidence_bounded_hint || plausible_repairs)
                      && ((reservation_pass == 0 && source_reserved)
                          || (reservation_pass > 0
                              && !source_reserved)));
              if (wrong_reservation_pass) {
                continue;
              }

              if (plausible_repairs) {
                const uint64_t reservation_class_count = source_reserved
                    ? plausible_repairs->reserved_count
                    : plausible_repairs->unreserved_count;
                if (scalpel_state.reservations
                    && plausible_repairs->limit > 0
                    && reservation_class_count
                           >= plausible_repairs->limit) {
                  if (sqlite_reassembly_poll(
                          work, candidate, uuidp, uuidc, state,
                          iterations)) {
                    return SQLITE_REPAIR_STOPPED;
                  }
                  continue;
                }
                const SqliteRepairDescriptor repair = {
                    .target = target,
                    .width = run_blocks,
                    .source = source,
                    .valid = 1,
                    .reserved = source_reserved ? 1U : 0U};
                if (!sqlite_repair_list_append(
                        plausible_repairs, &repair)) {
                  return SQLITE_REPAIR_NO_MATCH;
                }
                if (plausible_repairs->limit > 0
                    && ((!scalpel_state.reservations
                         && plausible_repairs->count
                                >= plausible_repairs->limit)
                        || (scalpel_state.reservations
                            && plausible_repairs->reserved_count
                                   >= plausible_repairs->limit
                            && plausible_repairs->unreserved_count
                                   >= plausible_repairs->limit))) {
                  return SQLITE_REPAIR_PLAUSIBLE;
                }
                if (sqlite_reassembly_poll(
                        work, candidate, uuidp, uuidc, state,
                        iterations)) {
                  return SQLITE_REPAIR_STOPPED;
                }
                continue;
              }

              memcpy(trial_mapping, base_mapping,
                     total_blocks * sizeof(*trial_mapping));
              for (uint64_t offset = 0; offset < run_blocks; offset++) {
                trial_mapping[target + offset] =
                    (int64_t)(source + offset);
              }
              if (key_order_only) {
                memcpy(solution_mapping, trial_mapping,
                       total_blocks * sizeof(*solution_mapping));
                return SQLITE_REPAIR_PLAUSIBLE;
              }
              SqliteIntegrity integrity;
              const bool mapping_valid = sqlite_mapping_ooo_check(
                  trial_mapping, total_blocks, layout->extent, trial_data,
                  &integrity,
                  baseline_integrity ? &best_integrity : NULL,
                  compose && baseline_integrity
                      && composition_mapping);
              if (mapping_valid) {
                const bool changes_are_necessary =
                    sqlite_ooo_changes_are_necessary(
                        base_mapping, trial_mapping, target, run_blocks,
                        total_blocks, layout->extent, trial_data);
                // A remaining zero run supplies an exact destination and width. Preserve an
                // otherwise ambiguous source only when its page role or key order also matches;
                // SQLite cannot distinguish arbitrary replacements for unauthenticated payload.
                const bool preserve_bounded_ambiguity =
                    exact_target && width_hint != 0
                    && run_blocks == width_hint
                    && (key_order_evidence || layout_evidence);
                if (changes_are_necessary
                    || preserve_bounded_ambiguity) {
                  if (sqlite_write_mapping_hypothesis(
                          *candidate, trial_mapping, total_blocks,
                          layout->extent)) {
                    preserved_clean_hypothesis = true;
                    if (preserve_bounded_ambiguity) {
                      preserved_bounded_hypothesis = true;
                    }
                  }
                }
                if (changes_are_necessary) {
                  if (scalpel_state.mode_verbose) {
                    lock_fprintf(
                        stdout,
                        "SQLite reassembly: clean necessary OOO mapping "
                        "at slot %" PRIu64 ", width=%" PRIu64
                        ", source=%" PRIu64 ", confidence tier=%u.\n",
                        target, run_blocks, source, confidence_pass);
                  }
                  preserved_necessary_hypothesis = true;
                  memcpy(solution_mapping, trial_mapping,
                         total_blocks * sizeof(*solution_mapping));
                  const SqliteRepairResult extension_result =
                      sqlite_preserve_ooo_extensions(
                          work, candidate, uuidp, uuidc, layout,
                          base_mapping, total_blocks, target, run_blocks,
                          source, trial_data, trial_mapping,
                          solution_mapping, state,
                          iterations, NULL);
                  if (extension_result == SQLITE_REPAIR_STOPPED
                      || !*candidate) {
                    return SQLITE_REPAIR_STOPPED;
                  }
                }
              }
              if (!mapping_valid && compose && baseline_integrity
                  && composition_mapping
                  && sqlite_integrity_composition_better(
                      &integrity, &best_integrity)) {
                best_integrity = integrity;
                memcpy(composition_mapping, trial_mapping,
                       total_blocks * sizeof(*composition_mapping));
                have_improvement = true;
              }
              if (sqlite_reassembly_poll(work, candidate, uuidp, uuidc,
                                         state, iterations)) {
                return SQLITE_REPAIR_STOPPED;
              }
          }
        }
      }
      if (preserved_bounded_hypothesis
          && !preserved_necessary_hypothesis) {
        return SQLITE_REPAIR_PRESERVED;
      }
    }
  }
  if (plausible_repairs && plausible_repairs->count > 0) {
    return SQLITE_REPAIR_PLAUSIBLE;
  }
  if (preserved_clean_hypothesis) {
    return SQLITE_REPAIR_PRESERVED;
  }
  if (have_improvement) {
    return sqlite_probe_gap_diagnostics(
        work, candidate, uuidp, uuidc, layout, &best_integrity,
        composition_mapping, total_blocks, trial_data, trial_mapping,
        solution_mapping, NULL, false, state, iterations);
  }
  return SQLITE_REPAIR_NO_MATCH;
}

// Two displaced overflow payloads can be structurally interchangeable. Preserve a bounded set of
// clean combinations in evidence order so the ambiguity remains visible without an unbounded
// Cartesian search.
static inline SqliteRepairResult sqlite_preserve_two_ooo_alternatives(
    ThreadWork *work, CarveInfo **candidate, uuid_string_t uuidp,
    uuid_string_t uuidc, const SqliteLayout *layout,
    const SqliteIntegrity *baseline_integrity,
    const int64_t *base_mapping, uint64_t total_blocks,
    const uint64_t targets[2], const uint64_t widths[2],
    uint8_t *trial_data, int64_t *first_mapping,
    int64_t *trial_mapping, SqliteCarveState *state,
    uint64_t *iterations) {
  if (!scalpel_state.write_promising || !candidate || !*candidate
      || !layout || !baseline_integrity || !base_mapping
      || !targets || !widths || !trial_data || !first_mapping
      || !trial_mapping || !state || !iterations) {
    return SQLITE_REPAIR_NO_MATCH;
  }

  SqliteRepairList alternatives[2] = {
      {.limit = SQLITE_COMPOSED_REPAIR_PROBE_LIMIT,
       .include_internal_sources = true},
      {.limit = SQLITE_COMPOSED_REPAIR_PROBE_LIMIT,
       .include_internal_sources = true}};
  SqliteRepairResult outcome = SQLITE_REPAIR_NO_MATCH;

  for (uint32_t slot = 0; slot < 2; slot++) {
    const SqliteRepairResult result = sqlite_probe_ooo_repair(
        work, candidate, uuidp, uuidc, layout, baseline_integrity,
        base_mapping, total_blocks, targets[slot], true, widths[slot],
        trial_data, first_mapping, trial_mapping, NULL, false, true,
        false, &alternatives[slot], state, iterations);
    if (result == SQLITE_REPAIR_STOPPED || !*candidate) {
      outcome = SQLITE_REPAIR_STOPPED;
      goto cleanup;
    }
    if (alternatives[slot].count == 0
        || alternatives[slot].allocation_failed) {
      goto cleanup;
    }
  }

  uint64_t class_indices[2][2][SQLITE_COMPOSED_REPAIR_PROBE_LIMIT] = {{{0}}};
  uint64_t class_counts[2][2] = {{0}};
  for (uint32_t slot = 0; slot < 2; slot++) {
    for (uint64_t repair = 0; repair < alternatives[slot].count;
         repair++) {
      const uint32_t reservation_class =
          alternatives[slot].repairs[repair].reserved ? 1U : 0U;
      uint64_t *class_count =
          &class_counts[slot][reservation_class];
      if (*class_count >= SQLITE_COMPOSED_REPAIR_PROBE_LIMIT) {
        continue;
      }
      class_indices[slot][reservation_class][(*class_count)++] = repair;
    }
  }

  const uint32_t class_pairs[4][2] = {
      {0, 0}, {0, 1}, {1, 0}, {1, 1}};
  uint64_t preserved = 0;
  for (uint32_t pair = 0; pair < 4; pair++) {
    const uint32_t first_class = class_pairs[pair][0];
    const uint32_t second_class = class_pairs[pair][1];
    const uint64_t first_count = class_counts[0][first_class];
    const uint64_t second_count = class_counts[1][second_class];
    if (first_count == 0 || second_count == 0) {
      continue;
    }
    const uint64_t last_diagonal = first_count + second_count - 2;
    for (uint64_t diagonal = 0; diagonal <= last_diagonal;
         diagonal++) {
      const uint64_t first_begin = diagonal >= second_count
          ? diagonal - (second_count - 1) : 0;
      uint64_t first_end = diagonal;
      if (first_end >= first_count) {
        first_end = first_count - 1;
      }
      for (uint64_t first_rank = first_begin;
           first_rank <= first_end; first_rank++) {
        const uint64_t second_rank = diagonal - first_rank;
        const SqliteRepairDescriptor *first_repair =
            &alternatives[0].repairs[
                class_indices[0][first_class][first_rank]];
        const SqliteRepairDescriptor *second_repair =
            &alternatives[1].repairs[
                class_indices[1][second_class][second_rank]];
        if (sqlite_apply_ooo_descriptor(
                base_mapping, total_blocks, first_repair,
                first_mapping)
            && sqlite_apply_ooo_descriptor(
                first_mapping, total_blocks, second_repair,
                trial_mapping)) {
          SqliteIntegrity integrity;
          if (sqlite_mapping_check(
                  trial_mapping, total_blocks, layout->extent,
                  trial_data, &integrity)
              && sqlite_write_mapping_hypothesis(
                  *candidate, trial_mapping, total_blocks,
                  layout->extent)) {
            preserved++;
            if (preserved >= SQLITE_COMPOSED_HYPOTHESIS_LIMIT) {
              outcome = SQLITE_REPAIR_PRESERVED;
              goto cleanup;
            }
          }
        }
        if (sqlite_reassembly_poll(work, candidate, uuidp, uuidc,
                                   state, iterations)) {
          outcome = SQLITE_REPAIR_STOPPED;
          goto cleanup;
        }
      }
    }
  }
  if (preserved > 0) {
    outcome = SQLITE_REPAIR_PRESERVED;
  }

cleanup:
  free(alternatives[1].repairs);
  free(alternatives[0].repairs);
  return outcome;
}

// Probe all gap widths at one diagnostic location. A miss returns to the unrestricted search, so
// this changes only the order in which mappings are considered.
static inline SqliteRepairResult sqlite_probe_gap_repair(
    ThreadWork *work, CarveInfo **candidate, uuid_string_t uuidp,
    uuid_string_t uuidc, const SqliteLayout *layout,
    const SqliteIntegrity *baseline_integrity,
    const int64_t *base_mapping, uint64_t total_blocks,
    uint64_t target_hint, uint8_t *trial_data,
    int64_t *trial_mapping, int64_t *solution_mapping,
    int64_t *composition_mapping, bool compose,
    SqliteCarveState *state, uint64_t *iterations) {
  const uint64_t apparent_blocks =
      filemirror_apparent_blocks(scalpel_state.filemirror);
  SqliteIntegrity best_integrity;
  SqliteRepairDescriptor best_gap = {0};
  bool have_improvement = false;
  if (baseline_integrity) {
    best_integrity = *baseline_integrity;
  }
  if (target_hint == 0 || target_hint >= total_blocks) {
    return SQLITE_REPAIR_NO_MATCH;
  }
  uint64_t target_span = CEILDIV(layout->page_size,
                                 scalpel_state.blocksize);
  if (target_span == 0) {
    target_span = 1;
  }
  uint64_t last_target = total_blocks - 1;
  if (target_span - 1 < last_target - target_hint) {
    last_target = target_hint + target_span - 1;
  }

  for (uint64_t target = target_hint; target <= last_target; target++) {
    if (base_mapping[target] < 0) {
      continue;
    }
    const uint64_t suffix_blocks = total_blocks - target;
    const uint64_t source_start = (uint64_t)base_mapping[target];
    if (source_start >= apparent_blocks
        || suffix_blocks > apparent_blocks - source_start) {
      continue;
    }
    uint64_t maximum_gap = apparent_blocks - source_start - suffix_blocks;
    if (maximum_gap > SQLITE_FAST_PROBE_MAXIMUM_GAP_BLOCKS) {
      maximum_gap = SQLITE_FAST_PROBE_MAXIMUM_GAP_BLOCKS;
    }
    for (uint64_t gap = 1; gap <= maximum_gap; gap++) {
      memcpy(trial_mapping, base_mapping,
             total_blocks * sizeof(*trial_mapping));
      for (uint64_t slot = target; slot < total_blocks; slot++) {
        const int64_t expected = base_mapping[target]
                                 + (int64_t)(slot - target);
        if (base_mapping[slot] == expected) {
          trial_mapping[slot] = expected + (int64_t)gap;
        }
      }
      SqliteIntegrity integrity;
      if (sqlite_mapping_check(trial_mapping, total_blocks,
                               layout->extent, trial_data,
                               &integrity)) {
        if (solution_mapping != trial_mapping) {
          memcpy(solution_mapping, trial_mapping,
                 total_blocks * sizeof(*solution_mapping));
        }
        return SQLITE_REPAIR_MATCH;
      }
      if (compose && baseline_integrity && composition_mapping
          && sqlite_integrity_composition_better(
              &integrity, &best_integrity)) {
        best_integrity = integrity;
        best_gap.target = target;
        best_gap.width = gap;
        best_gap.source = 0;
        best_gap.valid = 1;
        best_gap.reserved = 0;
        memcpy(composition_mapping, trial_mapping,
               total_blocks * sizeof(*composition_mapping));
        have_improvement = true;
      }
      if (sqlite_reassembly_poll(work, candidate, uuidp, uuidc,
                                 state, iterations)) {
        return SQLITE_REPAIR_STOPPED;
      }
    }
  }
  if (have_improvement) {
    memcpy(solution_mapping, composition_mapping,
           total_blocks * sizeof(*solution_mapping));
    SqliteRepairResult result = sqlite_probe_ooo_diagnostics(
        work, candidate, uuidp, uuidc, layout, &best_integrity,
        composition_mapping, total_blocks, trial_data, trial_mapping,
        solution_mapping, NULL, false, false, state, iterations);
    if (result == SQLITE_REPAIR_STOPPED || !*candidate) {
      return SQLITE_REPAIR_STOPPED;
    }
    if (result == SQLITE_REPAIR_PRESERVED) {
      return result;
    }
    SqliteIntegrity solution_integrity;
    if (best_gap.valid
        && sqlite_mapping_check(solution_mapping, total_blocks,
                                layout->extent, trial_data,
                                &solution_integrity)) {
      result = sqlite_preserve_gap_alternatives(
          work, candidate, uuidp, uuidc, layout, base_mapping,
          total_blocks, &best_gap, composition_mapping,
          solution_mapping, trial_data, trial_mapping, state,
          iterations);
      return result == SQLITE_REPAIR_STOPPED
          ? SQLITE_REPAIR_STOPPED : SQLITE_REPAIR_MATCH;
    }
    return result;
  }
  return SQLITE_REPAIR_NO_MATCH;
}

static inline SqliteRepairResult sqlite_probe_shifted_page_gap(
    ThreadWork *work, CarveInfo **candidate, uuid_string_t uuidp,
    uuid_string_t uuidc, const SqliteLayout *layout,
    const SqliteIntegrity *integrity, const int64_t *base_mapping,
    uint64_t total_blocks, uint8_t *trial_data,
    int64_t *trial_mapping, int64_t *solution_mapping,
    int64_t *composition_mapping, bool compose,
    bool allow_multi_region,
    SqliteCarveState *state, uint64_t *iterations) {
  SqliteRepairResult result = SQLITE_REPAIR_NO_MATCH;

  // A gap before a SQLite page shifts recognizable page evidence away from its expected block
  // boundary. Test that measured shift across the preceding page before considering generic gap
  // locations.
  if (integrity && candidate && *candidate) {
    uint64_t page_blocks = CEILDIV(layout->page_size,
                                   scalpel_state.blocksize);
    const uint64_t apparent_blocks =
        filemirror_apparent_blocks(scalpel_state.filemirror);
    if (page_blocks > 0 && page_blocks <= total_blocks) {
      uint64_t best_boundary = 0;
      uint64_t best_gap = 0;
      uint64_t best_support = 0;
      uint64_t left_support = 0;
      uint64_t transition_boundaries[SQLITE_PAGE_TRANSITION_LIMIT] = {0};
      uint64_t transition_gaps[SQLITE_PAGE_TRANSITION_LIMIT] = {0};
      uint64_t transition_support[SQLITE_PAGE_TRANSITION_LIMIT] = {0};
      bool transition_zero_backed[SQLITE_PAGE_TRANSITION_LIMIT] = {false};
      uint64_t transition_count = 0;

      // Zero-filled database pages are common and do not by themselves identify inserted gaps.
      // Use zero runs only after structural page transitions have bounded a repair location.
      const bool bounded_zero_transitions = false;

      // A low-confidence page boundary surrounded by recognized SQLite pages is the strongest
      // gap signal. Rank all transitions before invoking integrity_check.
      for (uint64_t boundary = page_blocks;
           boundary <= total_blocks - page_blocks;
           boundary += page_blocks) {
        if (base_mapping[boundary] < 0) {
          left_support = 0;
          continue;
        }
        const uint64_t source = (uint64_t)base_mapping[boundary];
        if (sqlite_source_has_layout_page_evidence(
                source, page_blocks, boundary, layout,
                (*candidate)->needleidx)) {
          left_support++;
          continue;
        }
        if (source >= apparent_blocks
            || page_blocks > apparent_blocks - source) {
          continue;
        }

        uint64_t maximum_gap = SQLITE_FAST_PROBE_MAXIMUM_GAP_BLOCKS;
        const uint64_t available_shift =
            apparent_blocks - source - page_blocks;
        if (maximum_gap > available_shift) {
          maximum_gap = available_shift;
        }
        for (uint64_t gap = 1; gap <= maximum_gap; gap++) {
          if (!sqlite_source_has_layout_page_evidence(
                  source + gap, page_blocks, boundary, layout,
                  (*candidate)->needleidx)) {
            continue;
          }
          uint64_t right_support = 0;
          uint64_t logical_offset = 0;
          const uint64_t shifted_source = source + gap;
          while (logical_offset <= total_blocks - boundary - page_blocks
                 && logical_offset
                        <= apparent_blocks - page_blocks - shifted_source
                 && sqlite_source_has_layout_page_evidence(
                     shifted_source + logical_offset, page_blocks,
                     boundary + logical_offset, layout,
                     (*candidate)->needleidx)) {
            right_support++;
            logical_offset += page_blocks;
          }
          const uint64_t support = left_support == 0
              ? right_support
              : (left_support < right_support
                    ? left_support : right_support);
          const uint64_t transition_gap =
              bounded_zero_transitions ? gap : 1;
          const bool zero_backed = bounded_zero_transitions
              && sqlite_mapping_block_is_zero(base_mapping, boundary);
          bool duplicate_transition = false;
          for (uint64_t prior = 0; prior < transition_count; prior++) {
            if (transition_boundaries[prior] == boundary
                && transition_gaps[prior] == transition_gap) {
              duplicate_transition = true;
              break;
            }
            if (!zero_backed && !transition_zero_backed[prior]
                && transition_gaps[prior] == transition_gap) {
              duplicate_transition = true;
              break;
            }
          }
          if (duplicate_transition) {
            break;
          }
          uint64_t transition = transition_count;
          while (transition > 0) {
            const uint64_t previous = transition - 1;
            if ((!zero_backed && transition_zero_backed[previous])
                || (!zero_backed
                    && boundary >= transition_boundaries[previous])
                || (zero_backed == transition_zero_backed[previous]
                    && (support < transition_support[previous]
                        || (support == transition_support[previous]
                            && transition_gap
                                   <= transition_gaps[previous])))) {
              break;
            }
            if (transition < SQLITE_PAGE_TRANSITION_LIMIT) {
              transition_boundaries[transition] =
                  transition_boundaries[previous];
              transition_gaps[transition] = transition_gaps[previous];
              transition_support[transition] =
                  transition_support[previous];
              transition_zero_backed[transition] =
                  transition_zero_backed[previous];
            }
            transition--;
          }
          if (transition < SQLITE_PAGE_TRANSITION_LIMIT) {
            transition_boundaries[transition] = boundary;
            transition_gaps[transition] = transition_gap;
            transition_support[transition] = support;
            transition_zero_backed[transition] = zero_backed;
            if (transition_count < SQLITE_PAGE_TRANSITION_LIMIT) {
              transition_count++;
            }
          }
          if (support > best_support) {
            best_boundary = boundary;
            best_gap = gap;
            best_support = support;
          }
          break;
        }
        left_support = 0;
      }

      // Test each measured transition as a physical gap. When several damaged regions remain,
      // test the other transitions at their corrected logical positions as displaced runs. This
      // preserves the general search while avoiding a blind Cartesian walk over every logical
      // slot and image block.
      if (compose && composition_mapping && transition_count > 0) {
        SqliteIntegrity gap_integrities[SQLITE_PAGE_TRANSITION_LIMIT];
        bool gap_clean[SQLITE_PAGE_TRANSITION_LIMIT] = {false};
        bool gap_usable[SQLITE_PAGE_TRANSITION_LIMIT] = {false};
        bool gap_target_zero_backed[SQLITE_PAGE_TRANSITION_LIMIT] = {false};
        uint64_t gap_targets[SQLITE_PAGE_TRANSITION_LIMIT] = {0};
        uint64_t ranked_gap_transition = UINT64_MAX;
        for (uint64_t gap_transition = 0;
             gap_transition < transition_count; gap_transition++) {
          const uint64_t boundary =
              transition_boundaries[gap_transition];
          uint64_t first_target = boundary;
          if (page_blocks > 1) {
            const uint64_t preceding = page_blocks - 1;
            first_target = boundary > preceding
                ? boundary - preceding : 1;
          }
          for (uint64_t target = first_target; target <= boundary;
               target++) {
            const SqliteRepairDescriptor probe_gap = {
                .target = target,
                .width = transition_gaps[gap_transition],
                .source = 0,
                .valid = 1,
                .reserved = 0};
            if (!sqlite_apply_gap_descriptor(
                    base_mapping, total_blocks, &probe_gap,
                    composition_mapping)) {
              continue;
            }
            SqliteIntegrity probe_integrity;
            const bool probe_clean = sqlite_mapping_check(
                composition_mapping, total_blocks, layout->extent,
                trial_data, &probe_integrity);
            const bool probe_zero_backed =
                sqlite_mapping_block_is_zero(base_mapping, target);
            if (!gap_usable[gap_transition]
                || (probe_zero_backed
                    != gap_target_zero_backed[gap_transition]
                    && probe_zero_backed)
                || (probe_zero_backed
                        == gap_target_zero_backed[gap_transition]
                    && sqlite_integrity_composition_better(
                        &probe_integrity,
                        &gap_integrities[gap_transition]))) {
              gap_usable[gap_transition] = true;
              gap_clean[gap_transition] = probe_clean;
              gap_target_zero_backed[gap_transition] =
                  probe_zero_backed;
              gap_targets[gap_transition] = target;
              gap_integrities[gap_transition] = probe_integrity;
            }
            if (sqlite_reassembly_poll(work, candidate, uuidp, uuidc,
                                       state, iterations)) {
              return SQLITE_REPAIR_STOPPED;
            }
          }
          if (!gap_usable[gap_transition]) {
            continue;
          }
          if (ranked_gap_transition == UINT64_MAX
              || (!bounded_zero_transitions
                  && transition_boundaries[gap_transition]
                         < transition_boundaries[
                             ranked_gap_transition])
              || (bounded_zero_transitions
                  && sqlite_integrity_composition_better(
                      &gap_integrities[gap_transition],
                      &gap_integrities[ranked_gap_transition]))) {
            ranked_gap_transition = gap_transition;
          }
        }
        if (scalpel_state.mode_verbose
            && ranked_gap_transition != UINT64_MAX) {
          lock_fprintf(
              stdout,
              "SQLite reassembly: composing first GAP at slot %" PRIu64
              ", width=%" PRIu64 ", transition boundary=%" PRIu64
              ", errors=%u.\n",
              gap_targets[ranked_gap_transition],
              transition_gaps[ranked_gap_transition],
              transition_boundaries[ranked_gap_transition],
              gap_integrities[ranked_gap_transition].error_count);
        }

        // Test every measured transition as a simple physical gap before doing any displaced-run
        // search. This is both exact and inexpensive when a candidate has only one damaged region.
        for (uint64_t gap_rank = 0; gap_rank < transition_count;
             gap_rank++) {
          uint64_t gap_transition = gap_rank;
          if (ranked_gap_transition != UINT64_MAX) {
            if (gap_rank == 0) {
              gap_transition = ranked_gap_transition;
            }
            else {
              gap_transition = gap_rank - 1;
              if (gap_transition >= ranked_gap_transition) {
                gap_transition++;
              }
            }
          }
          if (!gap_usable[gap_transition]) {
            continue;
          }
          if (!gap_clean[gap_transition]) {
            continue;
          }
          const SqliteRepairDescriptor clean_gap = {
              .target = gap_targets[gap_transition],
              .width = transition_gaps[gap_transition],
              .source = 0,
              .valid = 1,
              .reserved = 0};
          if (!sqlite_apply_gap_descriptor(
                  base_mapping, total_blocks, &clean_gap,
                  solution_mapping)) {
            continue;
          }
          sqlite_write_mapping_hypothesis(
              *candidate, solution_mapping, total_blocks,
              layout->extent);

          // Integrity checks can accept a zero-filled overflow or free page because SQLite does
          // not authenticate every payload byte. Preserve the clean gap-only mapping, then use
          // any remaining zero runs as exact targets for a structurally ranked displaced-run
          // probe before declaring the repair complete.
          if (allow_multi_region) {
            for (uint64_t slot = 1; slot < total_blocks;) {
              if (!sqlite_mapping_block_is_zero(solution_mapping,
                                                slot)) {
                slot++;
                continue;
              }
              const uint64_t zero_start = slot;
              while (slot + 1 < total_blocks
                     && sqlite_mapping_block_is_zero(
                         solution_mapping, slot + 1)) {
                slot++;
              }
              const uint64_t zero_width = slot - zero_start + 1;
              result = sqlite_probe_ooo_repair(
                  work, candidate, uuidp, uuidc, layout,
                  &gap_integrities[gap_transition], solution_mapping,
                  total_blocks, zero_start, true, zero_width,
                  trial_data, trial_mapping, composition_mapping,
                  NULL, false, true, false, NULL, state, iterations);
              if (result == SQLITE_REPAIR_STOPPED || !*candidate) {
                return SQLITE_REPAIR_STOPPED;
              }
              if (result == SQLITE_REPAIR_PRESERVED) {
                return result;
              }
              if (result == SQLITE_REPAIR_MATCH) {
                memcpy(solution_mapping, composition_mapping,
                       total_blocks * sizeof(*solution_mapping));
                return SQLITE_REPAIR_MATCH;
              }
              slot++;
            }
          }
          return SQLITE_REPAIR_MATCH;
        }

        // Intermediate integrity identifies the transition that restores the most coherent page
        // stream. Deep composition requires structural support on both sides of each repaired
        // region; weaker transitions remain available to the ordinary one-region searches.
        for (uint64_t gap_rank = 0;
             allow_multi_region && gap_rank < transition_count;
             gap_rank++) {
          uint64_t gap_transition = gap_rank;
          if (ranked_gap_transition != UINT64_MAX) {
            if (gap_rank == 0) {
              gap_transition = ranked_gap_transition;
            }
            else {
              gap_transition = gap_rank - 1;
              if (gap_transition >= ranked_gap_transition) {
                gap_transition++;
              }
            }
          }
          if (!gap_usable[gap_transition]) {
            continue;
          }
          const SqliteRepairDescriptor gap_repair = {
              .target = gap_targets[gap_transition],
              .width = transition_gaps[gap_transition],
              .source = 0,
              .valid = 1,
              .reserved = 0};
          if (!sqlite_apply_gap_descriptor(
                  base_mapping, total_blocks, &gap_repair,
                  composition_mapping)) {
            continue;
          }

          SqliteIntegrity gap_integrity =
              gap_integrities[gap_transition];

          // Once the physical gap is removed, remaining gaps and displaced runs become bounded
          // holes in an aligned page stream. Keep every strong short transition because support
          // ranks the search but does not identify which kind of fragmentation caused the hole.
          uint64_t repaired_boundaries[SQLITE_PAGE_TRANSITION_LIMIT] = {0};
          uint64_t repaired_widths[SQLITE_PAGE_TRANSITION_LIMIT] = {0};
          uint64_t repaired_support[SQLITE_PAGE_TRANSITION_LIMIT] = {0};
          uint64_t repaired_gap_targets[SQLITE_PAGE_TRANSITION_LIMIT] = {0};
          bool repaired_zero_backed[SQLITE_PAGE_TRANSITION_LIMIT] = {false};
          bool repaired_page_aligned[SQLITE_PAGE_TRANSITION_LIMIT] = {false};
          uint64_t repaired_transition_count = 0;

          // On pages larger than a carve block, a physical gap can occur inside a page while the
          // next recognizable page header appears at a later boundary. Record the earliest
          // observed suffix shift and let integrity testing locate the gap within that window.
          uint64_t repaired_page_left_support = 0;
          for (uint64_t boundary = page_blocks;
               boundary <= total_blocks - page_blocks;
               boundary += page_blocks) {
            if (composition_mapping[boundary] < 0) {
              repaired_page_left_support = 0;
              continue;
            }
            const uint64_t source =
                (uint64_t)composition_mapping[boundary];
            if (sqlite_source_has_layout_page_evidence(
                    source, page_blocks, boundary, layout,
                    (*candidate)->needleidx)) {
              repaired_page_left_support++;
              continue;
            }
            if (source >= apparent_blocks
                || page_blocks > apparent_blocks - source) {
              repaired_page_left_support = 0;
              continue;
            }
            uint64_t maximum_gap =
                SQLITE_FAST_PROBE_MAXIMUM_GAP_BLOCKS;
            const uint64_t available_shift =
                apparent_blocks - source - page_blocks;
            if (maximum_gap > available_shift) {
              maximum_gap = available_shift;
            }
            for (uint64_t observed_gap = 1;
                 observed_gap <= maximum_gap; observed_gap++) {
              if (!sqlite_source_has_layout_page_evidence(
                      source + observed_gap, page_blocks, boundary,
                      layout, (*candidate)->needleidx)) {
                continue;
              }
              uint64_t right_support = 0;
              uint64_t logical_offset = 0;
              while (logical_offset
                         <= total_blocks - boundary - page_blocks
                     && logical_offset
                            <= apparent_blocks - page_blocks
                                   - source - observed_gap
                     && sqlite_source_has_layout_page_evidence(
                         source + observed_gap + logical_offset,
                         page_blocks, boundary + logical_offset,
                         layout, (*candidate)->needleidx)) {
                right_support++;
                logical_offset += page_blocks;
              }
              const uint64_t support = repaired_page_left_support == 0
                  ? right_support
                  : (repaired_page_left_support < right_support
                        ? repaired_page_left_support : right_support);
              const uint64_t repair_width = 1;
              bool duplicate_transition = false;
              for (uint64_t prior = 0;
                   prior < repaired_transition_count; prior++) {
                if (repaired_page_aligned[prior]
                    && repaired_widths[prior] == repair_width) {
                  duplicate_transition = true;
                  break;
                }
              }
              if (!duplicate_transition
                  && repaired_transition_count
                         < SQLITE_PAGE_TRANSITION_LIMIT) {
                const uint64_t transition = repaired_transition_count++;
                repaired_boundaries[transition] = boundary;
                repaired_widths[transition] = repair_width;
                repaired_support[transition] = support;
                repaired_gap_targets[transition] = boundary;
                repaired_page_aligned[transition] = true;
              }
              break;
            }
            repaired_page_left_support = 0;
            if (sqlite_reassembly_poll(work, candidate, uuidp, uuidc,
                                       state, iterations)) {
              return SQLITE_REPAIR_STOPPED;
            }
          }

          uint64_t repaired_left_support = 0;
          // Only carve-block-sized pages provide independent structural evidence at every logical
          // slot. Larger pages are handled by the complete-page transition scan above; their
          // interior blocks are not damage merely because they lack a page header.
          for (uint64_t boundary = 1;
               page_blocks == 1 && boundary < total_blocks;
               boundary++) {
            if (sqlite_reassembly_poll(work, candidate, uuidp, uuidc,
                                       state, iterations)) {
              return SQLITE_REPAIR_STOPPED;
            }
            if (composition_mapping[boundary] < 0) {
              repaired_left_support = 0;
              continue;
            }
            if (sqlite_source_has_layout_page_evidence(
                    (uint64_t)composition_mapping[boundary], 1,
                    boundary, layout, (*candidate)->needleidx)) {
              repaired_left_support++;
              continue;
            }
            if (repaired_left_support == 0) {
              continue;
            }

            uint64_t width = 1;
            while (width <= SQLITE_FAST_PROBE_MAXIMUM_RUN_BLOCKS
                   && width < total_blocks - boundary
                   && composition_mapping[boundary + width] >= 0
                   && !sqlite_source_has_layout_page_evidence(
                       (uint64_t)composition_mapping[boundary + width],
                       1, boundary + width, layout,
                       (*candidate)->needleidx)) {
              width++;
            }
            if (width > SQLITE_FAST_PROBE_MAXIMUM_RUN_BLOCKS
                || width >= total_blocks - boundary
                || composition_mapping[boundary + width] < 0) {
              repaired_left_support = 0;
              continue;
            }

            uint64_t right_support = 0;
            while (right_support < total_blocks - boundary - width
                   && composition_mapping[
                          boundary + width + right_support] >= 0
                   && sqlite_source_has_layout_page_evidence(
                       (uint64_t)composition_mapping[
                           boundary + width + right_support],
                       1, boundary + width + right_support, layout,
                       (*candidate)->needleidx)) {
              right_support++;
              if (sqlite_reassembly_poll(work, candidate, uuidp, uuidc,
                                         state, iterations)) {
                return SQLITE_REPAIR_STOPPED;
              }
            }
            const uint64_t support =
                repaired_left_support < right_support
                    ? repaired_left_support : right_support;
            bool duplicate_transition = false;
            for (uint64_t prior = 0;
                 prior < repaired_transition_count; prior++) {
              if (repaired_boundaries[prior] == boundary
                  && repaired_widths[prior] == width) {
                duplicate_transition = true;
                break;
              }
            }
            if (duplicate_transition) {
              repaired_left_support = 0;
              continue;
            }
            uint64_t repaired_transition = repaired_transition_count;
            while (repaired_transition > 0) {
              const uint64_t previous = repaired_transition - 1;
              if (repaired_zero_backed[previous]
                  || repaired_page_aligned[previous]
                  || support < repaired_support[previous]
                  || (support == repaired_support[previous]
                      && width <= repaired_widths[previous])) {
                break;
              }
              if (repaired_transition < SQLITE_PAGE_TRANSITION_LIMIT) {
                repaired_boundaries[repaired_transition] =
                    repaired_boundaries[previous];
                repaired_widths[repaired_transition] =
                    repaired_widths[previous];
                repaired_support[repaired_transition] =
                    repaired_support[previous];
                repaired_gap_targets[repaired_transition] =
                    repaired_gap_targets[previous];
                repaired_zero_backed[repaired_transition] =
                    repaired_zero_backed[previous];
                repaired_page_aligned[repaired_transition] =
                    repaired_page_aligned[previous];
              }
              repaired_transition--;
            }
            if (repaired_transition < SQLITE_PAGE_TRANSITION_LIMIT) {
              repaired_boundaries[repaired_transition] = boundary;
              repaired_widths[repaired_transition] = width;
              repaired_support[repaired_transition] = support;
              repaired_gap_targets[repaired_transition] = boundary;
              repaired_zero_backed[repaired_transition] = false;
              repaired_page_aligned[repaired_transition] = false;
              if (repaired_transition_count
                  < SQLITE_PAGE_TRANSITION_LIMIT) {
                repaired_transition_count++;
              }
            }
            repaired_left_support = 0;
          }

          uint64_t one_gap_layout_evidence = 0;
          for (uint64_t slot = 1; slot < total_blocks; slot++) {
            if (composition_mapping[slot] >= 0
                && sqlite_source_has_layout_page_evidence(
                    (uint64_t)composition_mapping[slot], 1, slot,
                    layout, (*candidate)->needleidx)) {
              one_gap_layout_evidence++;
            }
          }
          SqliteRepairDescriptor ranked_second_gap = {0};
          SqliteIntegrity ranked_second_gap_integrity = gap_integrity;
          uint64_t ranked_second_gap_transition = UINT64_MAX;
          for (uint64_t transition = 0;
               transition < repaired_transition_count; transition++) {
            if (repaired_support[transition]
                    < SQLITE_MULTI_REGION_MINIMUM_SUPPORT
                && !repaired_zero_backed[transition]
                && !repaired_page_aligned[transition]) {
              continue;
            }
            uint64_t first_target = repaired_boundaries[transition];
            if (repaired_page_aligned[transition] && page_blocks > 1) {
              const uint64_t preceding = page_blocks - 1;
              first_target = repaired_boundaries[transition] > preceding
                  ? repaired_boundaries[transition] - preceding : 1;
            }
            bool transition_usable = false;
            bool transition_target_zero_backed = false;
            SqliteIntegrity transition_integrity = gap_integrity;
            uint64_t transition_target =
                repaired_boundaries[transition];
            for (uint64_t target = first_target;
                 target <= repaired_boundaries[transition]; target++) {
              const SqliteRepairDescriptor repair = {
                  .target = target,
                  .width = repaired_widths[transition],
                  .source = 0,
                  .valid = 1,
                  .reserved = 0};
              if (!sqlite_apply_gap_descriptor(
                      composition_mapping, total_blocks, &repair,
                      trial_mapping)) {
                continue;
              }
              SqliteIntegrity integrity;
              sqlite_mapping_check(trial_mapping, total_blocks,
                                   layout->extent, trial_data,
                                   &integrity);
              uint64_t layout_evidence = 0;
              for (uint64_t slot = 1; slot < total_blocks; slot++) {
                if (trial_mapping[slot] >= 0
                    && sqlite_source_has_layout_page_evidence(
                        (uint64_t)trial_mapping[slot], 1, slot,
                        layout, (*candidate)->needleidx)) {
                  layout_evidence++;
                }
              }
              const bool integrity_improved =
                  sqlite_integrity_composition_better(
                      &integrity, &gap_integrity);
              if (layout_evidence <= one_gap_layout_evidence
                  && !integrity_improved) {
                continue;
              }
              const bool target_zero_backed =
                  sqlite_mapping_block_is_zero(
                      composition_mapping, target);
              if (!transition_usable
                  || (target_zero_backed
                      != transition_target_zero_backed
                      && target_zero_backed)
                  || (target_zero_backed
                          == transition_target_zero_backed
                      && sqlite_integrity_composition_better(
                          &integrity, &transition_integrity))) {
                transition_usable = true;
                transition_target_zero_backed = target_zero_backed;
                transition_integrity = integrity;
                transition_target = target;
              }
              if (sqlite_reassembly_poll(work, candidate, uuidp, uuidc,
                                         state, iterations)) {
                return SQLITE_REPAIR_STOPPED;
              }
            }
            if (!transition_usable) {
              continue;
            }
            repaired_gap_targets[transition] = transition_target;
            const SqliteRepairDescriptor repair = {
                .target = transition_target,
                .width = repaired_widths[transition],
                .source = 0,
                .valid = 1,
                .reserved = 0};
            if (!ranked_second_gap.valid
                || sqlite_integrity_composition_better(
                    &transition_integrity,
                    &ranked_second_gap_integrity)) {
              ranked_second_gap = repair;
              ranked_second_gap_integrity = transition_integrity;
              ranked_second_gap_transition = transition;
            }
          }
          if (scalpel_state.mode_verbose && ranked_second_gap.valid) {
            lock_fprintf(
                stdout,
                "SQLite reassembly: composing second GAP at slot %" PRIu64
                ", width=%" PRIu64 ", transition boundary=%" PRIu64
                ", errors=%u.\n",
                ranked_second_gap.target, ranked_second_gap.width,
                repaired_boundaries[ranked_second_gap_transition],
                ranked_second_gap_integrity.error_count);
          }
          for (uint64_t repaired_transition = 0;
               repaired_transition < repaired_transition_count;
               repaired_transition++) {
            const SqliteRepairDescriptor second_gap = {
                .target = repaired_gap_targets[repaired_transition],
                .width = repaired_widths[repaired_transition],
                .source = 0,
                .valid = 1,
                .reserved = 0};
            if (sqlite_apply_gap_descriptor(
                    composition_mapping, total_blocks, &second_gap,
                    trial_mapping)) {
              SqliteIntegrity second_gap_integrity;
              if (sqlite_mapping_check(
                      trial_mapping, total_blocks, layout->extent,
                      trial_data, &second_gap_integrity)) {
                ranked_second_gap = second_gap;
                ranked_second_gap_integrity = second_gap_integrity;
                ranked_second_gap_transition = repaired_transition;
                sqlite_write_mapping_hypothesis(
                    *candidate, trial_mapping, total_blocks,
                    layout->extent);
                if (scalpel_state.mode_verbose) {
                  lock_fprintf(
                      stdout,
                      "SQLite reassembly: clean second GAP at slot "
                      "%" PRIu64 ", width=%" PRIu64 ".\n",
                      second_gap.target, second_gap.width);
                }
                break;
              }

            }
          }

          // A long aligned run on each side of a bounded hole identifies a displaced run without
          // requiring a broad source search. Weak holes remain ordering hints for later stages.
          for (uint64_t repaired_transition = 0;
               !ranked_second_gap.valid
                   && repaired_transition < repaired_transition_count;
               repaired_transition++) {
            if (repaired_support[repaired_transition]
                < SQLITE_DIRECT_OOO_MINIMUM_SUPPORT) {
              continue;
            }
            memcpy(solution_mapping, composition_mapping,
                   total_blocks * sizeof(*solution_mapping));
            result = sqlite_probe_ooo_repair(
                work, candidate, uuidp, uuidc, layout,
                &gap_integrity, composition_mapping, total_blocks,
                repaired_boundaries[repaired_transition], true,
                repaired_widths[repaired_transition], trial_data,
                trial_mapping, solution_mapping, NULL, false, true,
                false, NULL, state, iterations);
            if (result == SQLITE_REPAIR_STOPPED || !*candidate) {
              return SQLITE_REPAIR_STOPPED;
            }
            if (result == SQLITE_REPAIR_PRESERVED) {
              return result;
            }
            SqliteIntegrity solution_integrity;
            if (result == SQLITE_REPAIR_MATCH
                || sqlite_mapping_check(
                    solution_mapping, total_blocks, layout->extent,
                    trial_data, &solution_integrity)) {
              result = sqlite_preserve_gap_alternatives(
                  work, candidate, uuidp, uuidc, layout,
                  base_mapping, total_blocks, &gap_repair,
                  composition_mapping, solution_mapping, trial_data,
                  trial_mapping, state, iterations);
              return result == SQLITE_REPAIR_STOPPED
                  ? SQLITE_REPAIR_STOPPED : SQLITE_REPAIR_MATCH;
            }
          }

          // A ranked second gap indicates multiple damaged regions. Try that composition before
          // one-repair interpretations, which remain covered by the ordinary search stages.
          if (ranked_second_gap.valid
              && ranked_second_gap_transition != UINT64_MAX
              && sqlite_apply_gap_descriptor(
                  composition_mapping, total_blocks,
                  &ranked_second_gap, trial_mapping)) {
            int64_t *two_gap_mapping = (int64_t *)malloc(
                total_blocks * sizeof(*two_gap_mapping));
            int64_t *current_mapping = (int64_t *)malloc(
                total_blocks * sizeof(*current_mapping));
            check_memory_allocation(two_gap_mapping, __LINE__, __FILE__,
                                    "SQLite two-gap mapping");
            check_memory_allocation(current_mapping, __LINE__, __FILE__,
                                    "SQLite current multi-region mapping");
            memcpy(two_gap_mapping, trial_mapping,
                   total_blocks * sizeof(*two_gap_mapping));
            memcpy(current_mapping, two_gap_mapping,
                   total_blocks * sizeof(*current_mapping));
            SqliteIntegrity current_integrity =
                ranked_second_gap_integrity;
            uint64_t visited_hashes[
                SQLITE_PAGE_TRANSITION_LIMIT + 1] = {0};
            uint64_t visited_count = 1;
            visited_hashes[0] = sqlite_mapping_hash(
                current_mapping, total_blocks);
            bool repaired_ooo_transitions[
                SQLITE_PAGE_TRANSITION_LIMIT] = {false};
            bool multi_region_valid = false;

            for (uint64_t repair_pass = 0;
                 repair_pass < SQLITE_PAGE_TRANSITION_LIMIT;
                 repair_pass++) {
              memcpy(solution_mapping, current_mapping,
                     total_blocks * sizeof(*solution_mapping));
              SqliteIntegrity next_integrity = current_integrity;
              bool have_ranked_improvement = false;

              uint64_t isolated_page_targets[
                  SQLITE_PAGE_TRANSITION_LIMIT] = {0};
              uint64_t isolated_page_count = 0;
              if (page_blocks <= total_blocks / 3) {
                for (uint64_t boundary = page_blocks;
                     boundary <= total_blocks - 2 * page_blocks;
                     boundary += page_blocks) {
                  const uint64_t previous = boundary - page_blocks;
                  const uint64_t following = boundary + page_blocks;
                  if (current_mapping[previous] < 0
                      || current_mapping[boundary] < 0
                      || current_mapping[following] < 0) {
                    continue;
                  }
                  const bool previous_evidence =
                      sqlite_source_has_layout_page_evidence(
                          (uint64_t)current_mapping[previous], page_blocks,
                          previous, layout, (*candidate)->needleidx);
                  const bool current_evidence =
                      sqlite_source_has_layout_page_evidence(
                          (uint64_t)current_mapping[boundary], page_blocks,
                          boundary, layout, (*candidate)->needleidx);
                  const bool following_evidence =
                      sqlite_source_has_layout_page_evidence(
                          (uint64_t)current_mapping[following], page_blocks,
                          following, layout, (*candidate)->needleidx);
                  if (previous_evidence && !current_evidence
                      && following_evidence) {
                    isolated_page_targets[isolated_page_count++] =
                        boundary;
                    if (isolated_page_count
                        >= SQLITE_PAGE_TRANSITION_LIMIT) {
                      break;
                    }
                  }
                }
              }

              const uint64_t repair_probe_count =
                  repaired_transition_count
                  + isolated_page_count + 1;

              for (uint64_t transition = 0;
                   transition < repair_probe_count;
                   transition++) {
                const bool ranked_transition_probe =
                    transition < repaired_transition_count;
                const bool isolated_page_probe =
                    !ranked_transition_probe
                    && transition
                           < repaired_transition_count
                                 + isolated_page_count;
                const bool diagnostic_probe =
                    !ranked_transition_probe && !isolated_page_probe;
                uint64_t ooo_target = 0;
                uint64_t ooo_width = 0;
                bool exact_target = false;
                if (diagnostic_probe) {
                  ooo_target = sqlite_failure_block(
                      &current_integrity, layout, current_mapping,
                      scalpel_state.blocksize, total_blocks);
                  if (ooo_target == 0) {
                    ooo_target = sqlite_page_block(
                        current_integrity.first_page, layout,
                        scalpel_state.blocksize, total_blocks);
                  }
                  if (ooo_target == 0 || ooo_target >= total_blocks) {
                    continue;
                  }
                }
                else if (isolated_page_probe) {
                  ooo_target = isolated_page_targets[
                      transition - repaired_transition_count];
                  ooo_width = 1;
                  exact_target = true;
                }
                else {
                  if (transition == ranked_second_gap_transition
                      || repaired_ooo_transitions[transition]) {
                    continue;
                  }
                  if (multi_region_valid
                      && !repaired_zero_backed[transition]) {
                    continue;
                  }
                  ooo_target = repaired_boundaries[transition];
                  ooo_width = repaired_widths[transition];
                  exact_target = true;
                  if (ooo_target > ranked_second_gap.target) {
                    if (ooo_target - ranked_second_gap.target
                        < ranked_second_gap.width) {
                      continue;
                    }
                    ooo_target -= ranked_second_gap.width;
                  }
                  if (ooo_target == 0 || ooo_target >= total_blocks
                      || ooo_width == 0
                      || ooo_width > total_blocks - ooo_target) {
                    continue;
                  }
                }

                SqliteRepairList ranked_repairs = {
                    .limit = SQLITE_COMPOSED_REPAIR_PROBE_LIMIT,
                    .include_internal_sources = true};
                result = sqlite_probe_ooo_repair(
                    work, candidate, uuidp, uuidc, layout,
                    &current_integrity, current_mapping, total_blocks,
                    ooo_target, exact_target, ooo_width, trial_data,
                    trial_mapping, solution_mapping, NULL, false, true,
                    false, &ranked_repairs, state, iterations);
                if (result == SQLITE_REPAIR_STOPPED || !*candidate) {
                  free(ranked_repairs.repairs);
                  free(current_mapping);
                  free(two_gap_mapping);
                  return SQLITE_REPAIR_STOPPED;
                }
                for (uint64_t repair = 0;
                     repair < ranked_repairs.count; repair++) {
                  if ((ranked_transition_probe || isolated_page_probe)
                      && (ranked_repairs.repairs[repair].target
                              != ooo_target
                          || ranked_repairs.repairs[repair].width
                              != ooo_width)) {
                    continue;
                  }
                  if (!sqlite_apply_ooo_descriptor(
                          current_mapping, total_blocks,
                          &ranked_repairs.repairs[repair],
                          trial_mapping)) {
                    continue;
                  }
                  SqliteIntegrity ranked_integrity;
                  const bool ranked_valid = sqlite_mapping_check(
                      trial_mapping, total_blocks, layout->extent,
                      trial_data, &ranked_integrity);
                  if (ranked_valid) {
                    sqlite_write_mapping_hypothesis(
                        *candidate, trial_mapping, total_blocks,
                        layout->extent);
                    memcpy(solution_mapping, trial_mapping,
                           total_blocks * sizeof(*solution_mapping));
                    next_integrity = ranked_integrity;
                    have_ranked_improvement = true;
                    multi_region_valid = true;
                    if (ranked_transition_probe) {
                      repaired_ooo_transitions[transition] = true;
                    }
                    break;
                  }
                  if (sqlite_integrity_composition_better(
                          &ranked_integrity, &next_integrity)) {
                    memcpy(solution_mapping, trial_mapping,
                           total_blocks * sizeof(*solution_mapping));
                    next_integrity = ranked_integrity;
                    have_ranked_improvement = true;
                    if (ranked_transition_probe) {
                      repaired_ooo_transitions[transition] = true;
                    }
                  }
                  if (sqlite_reassembly_poll(
                          work, candidate, uuidp, uuidc, state,
                          iterations)) {
                    free(ranked_repairs.repairs);
                    free(current_mapping);
                    free(two_gap_mapping);
                    return SQLITE_REPAIR_STOPPED;
                  }
                }
                free(ranked_repairs.repairs);
                if (multi_region_valid || have_ranked_improvement) {
                  break;
                }
              }

              const uint64_t next_hash = sqlite_mapping_hash(
                  solution_mapping, total_blocks);
              bool repeated_mapping = false;
              for (uint64_t visited = 0; visited < visited_count;
                   visited++) {
                if (visited_hashes[visited] == next_hash) {
                  repeated_mapping = true;
                  break;
                }
              }
              if (repeated_mapping) {
                break;
              }
              visited_hashes[visited_count++] = next_hash;
              memcpy(current_mapping, solution_mapping,
                     total_blocks * sizeof(*current_mapping));
              current_integrity = next_integrity;
            }

            SqliteIntegrity final_multi_region_integrity;
            multi_region_valid = sqlite_mapping_check(
                current_mapping, total_blocks, layout->extent,
                trial_data, &final_multi_region_integrity);
            if (multi_region_valid) {
              memcpy(solution_mapping, current_mapping,
                     total_blocks * sizeof(*solution_mapping));
            }

            if (multi_region_valid) {
              sqlite_write_mapping_hypothesis(
                  *candidate, solution_mapping, total_blocks,
                  layout->extent);

              // Integrity cannot distinguish equal-width overflow payloads that belong to
              // different repaired slots. Preserve the bounded set of clean source permutations
              // instead of treating the first structurally ranked assignment as authoritative.
              uint64_t ooo_targets[SQLITE_PAGE_TRANSITION_LIMIT] = {0};
              uint64_t ooo_widths[SQLITE_PAGE_TRANSITION_LIMIT] = {0};
              uint64_t ooo_count = 0;
              for (uint64_t target = 1; target < total_blocks;) {
                if (solution_mapping[target] == two_gap_mapping[target]) {
                  target++;
                  continue;
                }
                uint64_t width = 1;
                while (target + width < total_blocks
                       && solution_mapping[target + width]
                              != two_gap_mapping[target + width]
                       && solution_mapping[target + width]
                              == solution_mapping[target]
                                     + (int64_t)width) {
                  width++;
                }
                if (ooo_count >= SQLITE_PAGE_TRANSITION_LIMIT) {
                  break;
                }
                ooo_targets[ooo_count] = target;
                ooo_widths[ooo_count] = width;
                ooo_count++;
                target += width;
              }

              result = sqlite_preserve_partial_page_completions(
                  work, candidate, uuidp, uuidc, layout,
                  solution_mapping, total_blocks, ooo_targets,
                  ooo_widths, ooo_count, trial_data, trial_mapping,
                  state, iterations);
              if (result == SQLITE_REPAIR_STOPPED || !*candidate) {
                free(current_mapping);
                free(two_gap_mapping);
                return SQLITE_REPAIR_STOPPED;
              }

              uint64_t zero_targets[SQLITE_PAGE_TRANSITION_LIMIT] = {0};
              uint64_t zero_widths[SQLITE_PAGE_TRANSITION_LIMIT] = {0};
              uint64_t zero_count = 0;
              for (uint64_t target = 1;
                   target < total_blocks
                       && zero_count < SQLITE_PAGE_TRANSITION_LIMIT;) {
                if (!sqlite_mapping_block_is_zero(
                        solution_mapping, target)) {
                  target++;
                  continue;
                }
                uint64_t width = 1;
                while (target + width < total_blocks
                       && sqlite_mapping_block_is_zero(
                           solution_mapping, target + width)) {
                  width++;
                }
                zero_targets[zero_count] = target;
                zero_widths[zero_count] = width;
                zero_count++;
                target += width;
              }

              uint64_t overflow_targets[
                  SQLITE_PAGE_TRANSITION_LIMIT] = {0};
              uint64_t overflow_widths[
                  SQLITE_PAGE_TRANSITION_LIMIT] = {0};
              uint64_t overflow_count = 0;
              for (uint64_t repair = 0; repair < ooo_count;
                   repair++) {
                const uint64_t logical_start =
                    ooo_targets[repair] * scalpel_state.blocksize;
                uint64_t logical_end = logical_start;
                if (__builtin_mul_overflow(
                        ooo_widths[repair], scalpel_state.blocksize,
                        &logical_end)
                    || __builtin_add_overflow(
                        logical_start, logical_end, &logical_end)
                    || logical_start >= layout->extent) {
                  continue;
                }
                if (logical_end > layout->extent) {
                  logical_end = layout->extent;
                }
                const uint64_t first_page =
                    logical_start / layout->page_size;
                const uint64_t last_page =
                    (logical_end - 1) / layout->page_size;
                bool inspected = false;
                bool overflow_only = true;
                for (uint64_t page = first_page;
                     page <= last_page; page++) {
                  const uint64_t page_offset = page * layout->page_size;
                  const uint8_t *page_data = trial_data + page_offset;
                  const uint8_t *page_header = page_data;
                  uint64_t page_header_length = layout->page_size;
                  if (page == 0) {
                    page_header += SQLITE_FILE_HEADER_SIZE;
                    page_header_length -= SQLITE_FILE_HEADER_SIZE;
                  }
                  const uint32_t page_number = (uint32_t)(page + 1);
                  const bool btree_page = sqlite_page_header_plausible(
                      page_header, page_header_length,
                      layout->page_size);
                  const bool pointer_map_page =
                      sqlite_pointer_map_page_plausible(
                          page_data, layout->page_size, page_number,
                          layout);
                  const bool overflow_page =
                      sqlite_overflow_page_plausible(
                          page_data, layout->page_size, layout);
                  inspected = true;
                  if (btree_page || pointer_map_page
                      || !overflow_page) {
                    overflow_only = false;
                    break;
                  }
                }
                if (inspected && overflow_only) {
                  overflow_targets[overflow_count] =
                      ooo_targets[repair];
                  overflow_widths[overflow_count] =
                      ooo_widths[repair];
                  overflow_count++;
                }
              }

              if (overflow_count == 2) {
                result = sqlite_preserve_two_ooo_alternatives(
                    work, candidate, uuidp, uuidc, layout,
                    &ranked_second_gap_integrity, two_gap_mapping,
                    total_blocks, overflow_targets, overflow_widths,
                    trial_data, current_mapping, trial_mapping, state,
                    iterations);
                if (result == SQLITE_REPAIR_STOPPED || !*candidate) {
                  free(current_mapping);
                  free(two_gap_mapping);
                  return SQLITE_REPAIR_STOPPED;
                }
              }
              else if (zero_count == 2) {
                result = sqlite_preserve_two_ooo_alternatives(
                    work, candidate, uuidp, uuidc, layout,
                    &final_multi_region_integrity, solution_mapping,
                    total_blocks, zero_targets, zero_widths, trial_data,
                    current_mapping, trial_mapping, state, iterations);
                if (result == SQLITE_REPAIR_STOPPED || !*candidate) {
                  free(current_mapping);
                  free(two_gap_mapping);
                  return SQLITE_REPAIR_STOPPED;
                }
              }
              else if (ooo_count == 2) {
                result = sqlite_preserve_two_ooo_alternatives(
                    work, candidate, uuidp, uuidc, layout,
                    &ranked_second_gap_integrity, two_gap_mapping,
                    total_blocks, ooo_targets, ooo_widths, trial_data,
                    current_mapping, trial_mapping, state, iterations);
                if (result == SQLITE_REPAIR_STOPPED || !*candidate) {
                  free(current_mapping);
                  free(two_gap_mapping);
                  return SQLITE_REPAIR_STOPPED;
                }
              }

              const uint64_t permutation_limit =
                  SQLITE_COMPOSED_REPAIR_PROBE_LIMIT;
              if (ooo_count > 1
                  && total_blocks
                         <= SIZE_MAX / sizeof(int64_t)
                                / permutation_limit) {
                int64_t *permutations = (int64_t *)malloc(
                    permutation_limit * total_blocks
                    * sizeof(*permutations));
                uint64_t *permutation_hashes = (uint64_t *)malloc(
                    permutation_limit * sizeof(*permutation_hashes));
                check_memory_allocation(permutations, __LINE__, __FILE__,
                                        "SQLite OOO permutations");
                check_memory_allocation(permutation_hashes, __LINE__,
                                        __FILE__,
                                        "SQLite OOO permutation hashes");
                memcpy(permutations, solution_mapping,
                       total_blocks * sizeof(*permutations));
                permutation_hashes[0] = sqlite_mapping_hash(
                    solution_mapping, total_blocks);
                uint64_t permutation_count = 1;

                for (uint64_t permutation = 0;
                     permutation < permutation_count
                         && permutation_count < permutation_limit;
                     permutation++) {
                  const int64_t *source_mapping =
                      permutations + permutation * total_blocks;
                  for (uint64_t left = 0; left < ooo_count;
                       left++) {
                    for (uint64_t right = left + 1;
                         right < ooo_count; right++) {
                      if (ooo_widths[left] != ooo_widths[right]) {
                        continue;
                      }
                      memcpy(trial_mapping, source_mapping,
                             total_blocks * sizeof(*trial_mapping));
                      for (uint64_t offset = 0;
                           offset < ooo_widths[left]; offset++) {
                        const int64_t swap =
                            trial_mapping[ooo_targets[left] + offset];
                        trial_mapping[ooo_targets[left] + offset] =
                            trial_mapping[ooo_targets[right] + offset];
                        trial_mapping[ooo_targets[right] + offset] = swap;
                      }

                      const uint64_t hash = sqlite_mapping_hash(
                          trial_mapping, total_blocks);
                      bool duplicate = false;
                      for (uint64_t prior = 0;
                           prior < permutation_count; prior++) {
                        if (permutation_hashes[prior] == hash
                            && memcmp(
                                permutations + prior * total_blocks,
                                trial_mapping,
                                total_blocks
                                    * sizeof(*trial_mapping)) == 0) {
                          duplicate = true;
                          break;
                        }
                      }
                      if (duplicate) {
                        continue;
                      }

                      SqliteIntegrity permutation_integrity;
                      if (!sqlite_mapping_check(
                              trial_mapping, total_blocks,
                              layout->extent, trial_data,
                              &permutation_integrity)) {
                        continue;
                      }
                      sqlite_write_mapping_hypothesis(
                          *candidate, trial_mapping, total_blocks,
                          layout->extent);
                      memcpy(permutations
                                 + permutation_count * total_blocks,
                             trial_mapping,
                             total_blocks * sizeof(*trial_mapping));
                      permutation_hashes[permutation_count] = hash;
                      permutation_count++;
                      if (sqlite_reassembly_poll(
                              work, candidate, uuidp, uuidc, state,
                              iterations)) {
                        free(permutation_hashes);
                        free(permutations);
                        free(current_mapping);
                        free(two_gap_mapping);
                        return SQLITE_REPAIR_STOPPED;
                      }
                      if (permutation_count >= permutation_limit) {
                        break;
                      }
                    }
                    if (permutation_count >= permutation_limit) {
                      break;
                    }
                  }
                }
                free(permutation_hashes);
                free(permutations);
              }

              if (sqlite_apply_gap_descriptor(
                      base_mapping, total_blocks, &gap_repair,
                      trial_mapping)) {
                result = sqlite_preserve_gap_alternatives(
                    work, candidate, uuidp, uuidc, layout,
                    trial_mapping, total_blocks, &ranked_second_gap,
                    two_gap_mapping, solution_mapping, trial_data,
                    composition_mapping, state, iterations);
                if (result == SQLITE_REPAIR_STOPPED || !*candidate) {
                  free(current_mapping);
                  free(two_gap_mapping);
                  return SQLITE_REPAIR_STOPPED;
                }
                result = sqlite_preserve_gap_alternatives(
                    work, candidate, uuidp, uuidc, layout,
                    base_mapping, total_blocks, &gap_repair,
                    trial_mapping, solution_mapping, trial_data,
                    composition_mapping, state, iterations);
                if (result == SQLITE_REPAIR_STOPPED || !*candidate) {
                  free(current_mapping);
                  free(two_gap_mapping);
                  return SQLITE_REPAIR_STOPPED;
                }
              }
              free(current_mapping);
              free(two_gap_mapping);
              return SQLITE_REPAIR_MATCH;
            }
            free(current_mapping);
            free(two_gap_mapping);
          }
        }
      }

      // A displaced run can appear as a bounded hole in an otherwise recognizable page stream.
      // Probe the strongest holes as OOO targets after trying composed repairs when several
      // independent transitions are present. The complete search remains the fallback when none
      // of these ordering hints succeeds.
      for (uint64_t transition = 0;
           transition < transition_count; transition++) {
        result = sqlite_probe_ooo_repair(
            work, candidate, uuidp, uuidc, layout, integrity,
            base_mapping, total_blocks,
            transition_boundaries[transition], true,
            transition_gaps[transition], trial_data, trial_mapping,
            solution_mapping, composition_mapping, compose, true, false,
            NULL, state, iterations);
        if (result != SQLITE_REPAIR_NO_MATCH || !*candidate) {
          return result;
        }
      }

      if (best_support > 0) {
        if (scalpel_state.mode_verbose) {
          lock_fprintf(stdout,
                       "SQLite reassembly: ranked page transition at "
                       "slot %" PRIu64 ", physical gap=%" PRIu64
                       ", support=%" PRIu64 ".\n",
                       best_boundary, best_gap, best_support);
        }
        SqliteIntegrity local_integrity = *integrity;
        SqliteRepairDescriptor local_gap = {0};
        bool have_local_improvement = false;
        const uint64_t local_radius =
            best_support >= SQLITE_GAP_LOCAL_MINIMUM_SUPPORT
                ? SQLITE_GAP_GRID_SAMPLES : 0;
        for (uint64_t distance = 0;
             distance <= local_radius; distance++) {
          for (uint32_t direction = 0; direction < 2; direction++) {
            if (distance == 0 && direction > 0) {
              continue;
            }
            uint64_t target = best_boundary;
            if (direction == 0) {
              if (distance >= total_blocks - best_boundary) {
                continue;
              }
              target += distance;
            }
            else {
              if (distance >= best_boundary) {
                continue;
              }
              target -= distance;
            }
            if (target == 0 || target >= total_blocks) {
              continue;
            }
            const SqliteRepairDescriptor repair = {
                .target = target,
                .width = best_gap,
                .source = 0,
                .valid = 1,
                .reserved = 0};
            if (!sqlite_apply_gap_descriptor(
                    base_mapping, total_blocks, &repair,
                    trial_mapping)) {
              continue;
            }
            SqliteIntegrity trial_integrity;
            if (sqlite_mapping_check(trial_mapping, total_blocks,
                                     layout->extent, trial_data,
                                     &trial_integrity)) {
              memcpy(solution_mapping, trial_mapping,
                     total_blocks * sizeof(*solution_mapping));
              sqlite_write_mapping_hypothesis(
                  *candidate, trial_mapping, total_blocks,
                  layout->extent);
              return SQLITE_REPAIR_MATCH;
            }
            // Long page runs on both sides identify a physical gap independently of integrity
            // diagnostics from any remaining damaged region. Preserve that mapping as the first
            // composition probe; the complete searches still run if it does not lead to a match.
            if (distance == 0 && direction == 0
                && best_support >= SQLITE_GAP_LOCAL_MINIMUM_SUPPORT
                && state
                && state->stage == SQLITE_SEARCH_INITIAL_PROBES
                && !state->best_gap.valid) {
              state->best_gap = repair;
              state->best_gap_integrity = trial_integrity;
            }
            if (compose && composition_mapping
                && sqlite_integrity_composition_better(
                    &trial_integrity, &local_integrity)) {
              local_integrity = trial_integrity;
              local_gap = repair;
              memcpy(composition_mapping, trial_mapping,
                     total_blocks * sizeof(*composition_mapping));
              have_local_improvement = true;
            }
            if (sqlite_reassembly_poll(work, candidate, uuidp, uuidc,
                                       state, iterations)) {
              return SQLITE_REPAIR_STOPPED;
            }
          }
        }
        if (have_local_improvement) {
          memcpy(solution_mapping, composition_mapping,
                 total_blocks * sizeof(*solution_mapping));
          result = sqlite_probe_ooo_diagnostics(
              work, candidate, uuidp, uuidc, layout,
              &local_integrity, composition_mapping, total_blocks,
              trial_data, trial_mapping, solution_mapping, NULL,
              false, true, state, iterations);
          if (result == SQLITE_REPAIR_STOPPED || !*candidate) {
            return SQLITE_REPAIR_STOPPED;
          }
          if (result == SQLITE_REPAIR_PRESERVED) {
            return result;
          }
          SqliteIntegrity solution_integrity;
          if (local_gap.valid
              && sqlite_mapping_check(
                  solution_mapping, total_blocks, layout->extent,
                  trial_data, &solution_integrity)) {
            result = sqlite_preserve_gap_alternatives(
                work, candidate, uuidp, uuidc, layout,
                base_mapping, total_blocks, &local_gap,
                composition_mapping, solution_mapping, trial_data,
                trial_mapping, state, iterations);
            return result == SQLITE_REPAIR_STOPPED
                ? SQLITE_REPAIR_STOPPED : SQLITE_REPAIR_MATCH;
          }
        }
      }
    }
    else if (page_blocks > 1) {
      uint64_t last_aligned_boundary = 0;
      for (uint64_t boundary = page_blocks; boundary < total_blocks;
           boundary += page_blocks) {
        if (base_mapping[boundary] < 0) {
          continue;
        }
        if (sqlite_source_has_page_evidence(
                (uint64_t)base_mapping[boundary], 1,
                (*candidate)->needleidx)) {
          last_aligned_boundary = boundary;
          continue;
        }
        uint64_t maximum_gap = SQLITE_FAST_PROBE_MAXIMUM_GAP_BLOCKS;
        const uint64_t source = (uint64_t)base_mapping[boundary];
        if (source >= apparent_blocks) {
          continue;
        }
        if (maximum_gap >= page_blocks) {
          maximum_gap = page_blocks - 1;
        }
        if (maximum_gap >= apparent_blocks - source) {
          maximum_gap = apparent_blocks - source - 1;
        }
        for (uint64_t gap = 1; gap <= maximum_gap; gap++) {
          if (!sqlite_source_has_page_evidence(
                  source + gap, 1, (*candidate)->needleidx)) {
            continue;
          }
          SqliteIntegrity best_integrity = *integrity;
          SqliteRepairDescriptor best_gap = {0};
          SqliteRepairList key_order_repairs = {0};
          uint64_t key_order_probe_target = 0;
          bool key_order_exact_target = false;
          bool key_order_scanned = false;
          bool have_improvement = false;
          bool have_match = false;
          const uint64_t first_target = last_aligned_boundary + 1;
          if (scalpel_state.mode_verbose) {
            lock_fprintf(stdout,
                         "SQLite reassembly: shifted page boundary at "
                         "slot %" PRIu64 ", physical gap=%" PRIu64
                         ", target range=%" PRIu64 "-%" PRIu64 ".\n",
                         boundary, gap, first_target, boundary);
          }
          for (uint32_t zero_pass = 0; zero_pass < 2; zero_pass++) {
            const uint64_t target_count = boundary - first_target + 1;
            for (uint64_t target_rank = 0;
                 target_rank < target_count; target_rank++) {
              const uint64_t gap_target = boundary - target_rank;
              const bool zero_target = sqlite_mapping_block_is_zero(
                  base_mapping, gap_target);
              if ((zero_pass == 0) != zero_target) {
                continue;
              }
              const SqliteRepairDescriptor repair = {
                  .target = gap_target,
                  .width = gap,
                  .source = 0,
                  .valid = 1,
                  .reserved = 0};
              if (!sqlite_apply_gap_descriptor(base_mapping, total_blocks,
                                               &repair, trial_mapping)) {
                continue;
              }
              SqliteIntegrity trial_integrity;
              if (sqlite_mapping_check(trial_mapping, total_blocks,
                                       layout->extent, trial_data,
                                       &trial_integrity)) {
                if (!have_match) {
                  memcpy(solution_mapping, trial_mapping,
                         total_blocks * sizeof(*solution_mapping));
                }
                sqlite_write_mapping_hypothesis(
                    *candidate, trial_mapping, total_blocks,
                    layout->extent);
                have_match = true;
              }
              if (compose && composition_mapping) {
                memcpy(solution_mapping, trial_mapping,
                       total_blocks * sizeof(*solution_mapping));
                result = sqlite_probe_ooo_diagnostics(
                    work, candidate, uuidp, uuidc, layout,
                    &trial_integrity, trial_mapping, total_blocks,
                    trial_data, composition_mapping, solution_mapping,
                    NULL, false, true, state, iterations);
                if (result == SQLITE_REPAIR_STOPPED || !*candidate) {
                  free(key_order_repairs.repairs);
                  return SQLITE_REPAIR_STOPPED;
                }
                if (result == SQLITE_REPAIR_PRESERVED) {
                  free(key_order_repairs.repairs);
                  return result;
                }
                SqliteIntegrity solution_integrity;
                if (sqlite_mapping_check(
                        solution_mapping, total_blocks, layout->extent,
                        trial_data, &solution_integrity)) {
                  sqlite_write_mapping_hypothesis(
                      *candidate, solution_mapping, total_blocks,
                      layout->extent);
                  result = sqlite_preserve_gap_alternatives(
                      work, candidate, uuidp, uuidc, layout,
                      base_mapping, total_blocks, &repair, trial_mapping,
                      solution_mapping, trial_data, composition_mapping,
                      state, iterations);
                  free(key_order_repairs.repairs);
                  return result == SQLITE_REPAIR_STOPPED
                      ? SQLITE_REPAIR_STOPPED : SQLITE_REPAIR_MATCH;
                }
              }
              const bool improved = sqlite_integrity_composition_better(
                  &trial_integrity, integrity);
              if (compose && composition_mapping
                  && (zero_target || improved)) {
                if (!have_improvement
                    || sqlite_integrity_composition_better(
                        &trial_integrity, &best_integrity)) {
                  best_integrity = trial_integrity;
                  best_gap = repair;
                  have_improvement = true;
                }

                const uint64_t ooo_target = sqlite_failure_block(
                    &trial_integrity, layout, trial_mapping,
                    scalpel_state.blocksize, total_blocks);
                const uint64_t first_ooo_target = sqlite_page_block(
                    trial_integrity.first_page, layout,
                    scalpel_state.blocksize, total_blocks);
                if (first_ooo_target > 0) {
                  const bool exact_ooo_target = ooo_target > 0
                      && ooo_target >= first_ooo_target
                      && ooo_target - first_ooo_target < page_blocks;
                  const uint64_t probe_target = exact_ooo_target
                      ? ooo_target : first_ooo_target;
                  const bool reusable_page = gap_target < first_ooo_target;
                  if (reusable_page
                      && (!key_order_scanned
                          || key_order_probe_target != probe_target
                          || key_order_exact_target != exact_ooo_target)) {
                    free(key_order_repairs.repairs);
                    memset(&key_order_repairs, 0,
                           sizeof(key_order_repairs));
                    key_order_probe_target = probe_target;
                    key_order_exact_target = exact_ooo_target;
                    key_order_scanned = true;
                    memcpy(solution_mapping, trial_mapping,
                           total_blocks * sizeof(*solution_mapping));
                    result = sqlite_probe_ooo_repair(
                        work, candidate, uuidp, uuidc, layout,
                        &trial_integrity, trial_mapping, total_blocks,
                        probe_target, exact_ooo_target, 0, trial_data,
                        composition_mapping, solution_mapping, NULL,
                        false, true, true, &key_order_repairs,
                        state, iterations);
                    if (result == SQLITE_REPAIR_STOPPED || !*candidate) {
                      free(key_order_repairs.repairs);
                      return SQLITE_REPAIR_STOPPED;
                    }
                  }
                  if (reusable_page
                      && !key_order_repairs.allocation_failed) {
                    for (uint64_t repair_index = 0;
                         repair_index < key_order_repairs.count;
                         repair_index++) {
                      if (!sqlite_apply_ooo_descriptor(
                              trial_mapping, total_blocks,
                              &key_order_repairs.repairs[repair_index],
                              solution_mapping)) {
                        continue;
                      }
                      SqliteIntegrity solution_integrity;
                      const bool mapping_valid = sqlite_mapping_check(
                              solution_mapping, total_blocks,
                              layout->extent, trial_data,
                              &solution_integrity);
                      const bool changes_are_necessary = mapping_valid
                          && sqlite_ooo_changes_are_necessary(
                              trial_mapping, solution_mapping,
                              key_order_repairs.repairs[repair_index].target,
                              key_order_repairs.repairs[repair_index].width,
                              total_blocks, layout->extent, trial_data);
                      if (mapping_valid) {
                        sqlite_write_mapping_hypothesis(
                            *candidate, solution_mapping, total_blocks,
                            layout->extent);
                      }
                      if (changes_are_necessary) {
                        memcpy(composition_mapping, trial_mapping,
                               total_blocks
                                   * sizeof(*composition_mapping));
                        free(key_order_repairs.repairs);
                        result = sqlite_preserve_gap_alternatives(
                            work, candidate, uuidp, uuidc, layout,
                            base_mapping, total_blocks, &repair,
                            composition_mapping, solution_mapping,
                            trial_data, trial_mapping, state, iterations);
                        return result == SQLITE_REPAIR_STOPPED
                            ? SQLITE_REPAIR_STOPPED
                            : SQLITE_REPAIR_MATCH;
                      }
                      if (sqlite_reassembly_poll(
                              work, candidate, uuidp, uuidc, state,
                              iterations)) {
                        free(key_order_repairs.repairs);
                        return SQLITE_REPAIR_STOPPED;
                      }
                    }
                  }
                }
              }
              if (sqlite_reassembly_poll(work, candidate, uuidp, uuidc,
                                         state, iterations)) {
                free(key_order_repairs.repairs);
                return SQLITE_REPAIR_STOPPED;
              }
            }
          }
          free(key_order_repairs.repairs);
          if (have_match) {
            return SQLITE_REPAIR_MATCH;
          }
          if (have_improvement) {
            if (!sqlite_apply_gap_descriptor(
                    base_mapping, total_blocks, &best_gap,
                    composition_mapping)) {
              break;
            }
            if (scalpel_state.mode_verbose) {
              lock_fprintf(
                  stdout,
                  "SQLite reassembly: composed GAP at slot %" PRIu64
                  ", width=%" PRIu64 ", errors=%u, pages=%u-%u.\n",
                  best_gap.target, best_gap.width,
                  best_integrity.error_count,
                  best_integrity.first_page,
                  best_integrity.last_page);
            }
            memcpy(solution_mapping, composition_mapping,
                   total_blocks * sizeof(*solution_mapping));
            result = sqlite_probe_ooo_diagnostics(
                work, candidate, uuidp, uuidc, layout,
                &best_integrity, composition_mapping, total_blocks,
                trial_data, trial_mapping, solution_mapping, NULL,
                false, false, state, iterations);
            if (result == SQLITE_REPAIR_STOPPED || !*candidate) {
              return result;
            }
            if (result == SQLITE_REPAIR_PRESERVED) {
              return result;
            }
            SqliteIntegrity solution_integrity;
            if (best_gap.valid
                && sqlite_mapping_check(
                    solution_mapping, total_blocks, layout->extent,
                    trial_data, &solution_integrity)) {
              result = sqlite_preserve_gap_alternatives(
                  work, candidate, uuidp, uuidc, layout,
                  base_mapping, total_blocks, &best_gap,
                  composition_mapping, solution_mapping, trial_data,
                  trial_mapping, state, iterations);
              return result == SQLITE_REPAIR_STOPPED
                  ? SQLITE_REPAIR_STOPPED : SQLITE_REPAIR_MATCH;
            }
            if (result != SQLITE_REPAIR_NO_MATCH) {
              return result;
            }
          }
          break;
        }
      }
    }
  }
  return result;
}

static inline SqliteRepairResult sqlite_probe_gap_diagnostics(
    ThreadWork *work, CarveInfo **candidate, uuid_string_t uuidp,
    uuid_string_t uuidc, const SqliteLayout *layout,
    const SqliteIntegrity *integrity, const int64_t *base_mapping,
    uint64_t total_blocks, uint8_t *trial_data,
    int64_t *trial_mapping, int64_t *solution_mapping,
    int64_t *composition_mapping, bool compose,
    SqliteCarveState *state, uint64_t *iterations) {
  SqliteRepairResult result = sqlite_probe_shifted_page_gap(
      work, candidate, uuidp, uuidc, layout, integrity, base_mapping,
      total_blocks, trial_data, trial_mapping, solution_mapping,
      composition_mapping, compose, false, state, iterations);
  if (result != SQLITE_REPAIR_NO_MATCH) {
    return result;
  }

  uint64_t target = sqlite_failure_block(
      integrity, layout, base_mapping, scalpel_state.blocksize,
      total_blocks);
  result = sqlite_probe_gap_repair(
      work, candidate, uuidp, uuidc, layout, integrity,
      base_mapping, total_blocks, target, trial_data, trial_mapping,
      solution_mapping, composition_mapping, compose, state,
      iterations);
  if (result != SQLITE_REPAIR_NO_MATCH || !integrity) {
    return result;
  }

  const uint64_t first_target = sqlite_page_block(
      integrity->first_page, layout, scalpel_state.blocksize,
      total_blocks);
  if (first_target > 0 && first_target != target) {
    result = sqlite_probe_gap_repair(
        work, candidate, uuidp, uuidc, layout, integrity,
        base_mapping, total_blocks, first_target, trial_data,
        trial_mapping, solution_mapping, composition_mapping,
        compose, state, iterations);
    if (result != SQLITE_REPAIR_NO_MATCH) {
      return result;
    }
  }

  return result;
}

// A wrong gap location leaves a bounded interval of shifted SQLite pages. Sample the target space,
// then refine around the best sample for each short gap width. This ranks the complete search; it
// does not replace the unrestricted checkpointed sweep below.
static inline SqliteRepairResult sqlite_probe_gap_grid(
    ThreadWork *work, CarveInfo **candidate, uuid_string_t uuidp,
    uuid_string_t uuidc, const SqliteLayout *layout,
    const SqliteIntegrity *baseline_integrity,
    const int64_t *base_mapping, uint64_t total_blocks,
    uint8_t *trial_data, int64_t *trial_mapping,
    int64_t *solution_mapping, SqliteRepairDescriptor *best_repair,
    SqliteIntegrity *best_integrity, SqliteCarveState *state,
    uint64_t *iterations) {
  if (!baseline_integrity || !base_mapping || total_blocks < 2
      || !trial_data || !trial_mapping || !solution_mapping
      || !best_repair || !best_integrity) {
    return SQLITE_REPAIR_NO_MATCH;
  }

  const uint64_t target_count = total_blocks - 1;
  uint64_t stride = CEILDIV(target_count, SQLITE_GAP_GRID_SAMPLES);
  if (stride == 0) {
    stride = 1;
  }
  uint64_t maximum_width = SQLITE_FAST_PROBE_MAXIMUM_GAP_BLOCKS;
  const uint64_t apparent_blocks =
      filemirror_apparent_blocks(scalpel_state.filemirror);
  if (maximum_width >= apparent_blocks) {
    maximum_width = apparent_blocks - 1;
  }

  for (uint64_t width = 1; width <= maximum_width; width++) {
    SqliteRepairDescriptor width_best = {0};
    SqliteIntegrity width_integrity = *baseline_integrity;
    for (uint32_t phase = 0; phase < 2; phase++) {
      if (phase == 1 && !width_best.valid) {
        continue;
      }
      uint64_t first_target = 1;
      uint64_t last_target = total_blocks - 1;
      uint64_t step = stride;
      if (phase == 1) {
        first_target = width_best.target > stride
            ? width_best.target - stride + 1 : 1;
        last_target = width_best.target + stride - 1;
        if (last_target >= total_blocks) {
          last_target = total_blocks - 1;
        }
        step = 1;
      }

      for (uint64_t target = first_target; target <= last_target;) {
        const SqliteRepairDescriptor repair = {
            .target = target,
            .width = width,
            .source = 0,
            .valid = 1,
            .reserved = 0};
        if (sqlite_apply_gap_descriptor(base_mapping, total_blocks,
                                        &repair, trial_mapping)) {
          SqliteIntegrity integrity;
          if (sqlite_mapping_check(trial_mapping, total_blocks,
                                   layout->extent, trial_data,
                                   &integrity)) {
            memcpy(solution_mapping, trial_mapping,
                   total_blocks * sizeof(*solution_mapping));
            return SQLITE_REPAIR_MATCH;
          }
          if (sqlite_integrity_composition_better(
                  &integrity, &width_integrity)) {
            width_best = repair;
            width_integrity = integrity;
          }
          if (sqlite_integrity_composition_better(
                  &integrity, best_integrity)) {
            *best_repair = repair;
            *best_integrity = integrity;
          }
        }
        if (sqlite_reassembly_poll(work, candidate, uuidp, uuidc,
                                   state, iterations)) {
          return SQLITE_REPAIR_STOPPED;
        }
        if (last_target - target < step) {
          break;
        }
        target += step;
      }
    }
  }

  if (best_repair->valid && scalpel_state.mode_verbose) {
    lock_fprintf(stdout,
                 "SQLite reassembly: ranked GAP at slot %" PRIu64
                 ", width=%" PRIu64 ", errors=%u, pages=%u-%u.\n",
                 best_repair->target, best_repair->width,
                 best_integrity->error_count,
                 best_integrity->first_page,
                 best_integrity->last_page);
  }
  return SQLITE_REPAIR_NO_MATCH;
}

static inline SqliteRepairResult sqlite_probe_ooo_diagnostics(
    ThreadWork *work, CarveInfo **candidate, uuid_string_t uuidp,
    uuid_string_t uuidc, const SqliteLayout *layout,
    const SqliteIntegrity *integrity, const int64_t *base_mapping,
    uint64_t total_blocks, uint8_t *trial_data,
    int64_t *trial_mapping, int64_t *solution_mapping,
    int64_t *composition_mapping, bool compose,
    bool high_confidence_only,
    SqliteCarveState *state, uint64_t *iterations) {
  uint64_t target = sqlite_failure_block(
      integrity, layout, base_mapping, scalpel_state.blocksize,
      total_blocks);
  const uint64_t first_target = sqlite_page_block(
      integrity->first_page, layout, scalpel_state.blocksize,
      total_blocks);
  uint64_t page_blocks = CEILDIV(layout->page_size,
                                 scalpel_state.blocksize);
  if (page_blocks == 0) {
    page_blocks = 1;
  }
  SqliteRepairResult result = SQLITE_REPAIR_NO_MATCH;

  // A zero run at the diagnosed location identifies the displaced run's likely start and an upper
  // bound for the first probes. Test its measured width before widening the damaged-page search.
  for (uint64_t slot = 1; slot < total_blocks;) {
    if (!sqlite_mapping_block_is_zero(base_mapping, slot)) {
      slot++;
      continue;
    }
    const uint64_t zero_start = slot;
    while (slot + 1 < total_blocks
           && sqlite_mapping_block_is_zero(base_mapping, slot + 1)) {
      slot++;
    }
    const bool in_first_error_page = first_target > 0
        && (zero_start <= first_target
                ? slot >= first_target
                : zero_start - first_target < page_blocks);
    if (zero_start == target || zero_start == first_target
        || in_first_error_page) {
      result = sqlite_probe_ooo_repair(
          work, candidate, uuidp, uuidc, layout, integrity,
          base_mapping, total_blocks, zero_start, true,
          slot - zero_start + 1, trial_data, trial_mapping,
          solution_mapping, composition_mapping, compose,
          high_confidence_only, false, NULL, state, iterations);
      if (result != SQLITE_REPAIR_NO_MATCH) {
        return result;
      }
    }
    slot++;
  }

  if (target > 0) {
    // A cell diagnostic can point beyond the first damaged page when more than one defect is
    // present. Use it as a strong ordering hint, but do not exhaust the source space before
    // testing the first page reported by SQLite below.
    result = sqlite_probe_ooo_repair(
        work, candidate, uuidp, uuidc, layout, integrity,
        base_mapping, total_blocks, target, true, 0, trial_data,
        trial_mapping, solution_mapping, composition_mapping, compose,
        true, false, NULL, state, iterations);
  }
  if (result != SQLITE_REPAIR_NO_MATCH || !integrity) {
    return result;
  }

  // The first reported damaged page is a direct structural location. Sweep it only after the
  // exact diagnostic and hole locations have been exhausted.
  if (first_target > 0) {
    result = sqlite_probe_ooo_repair(
        work, candidate, uuidp, uuidc, layout, integrity,
        base_mapping, total_blocks, first_target, false, 0, trial_data,
        trial_mapping, solution_mapping, composition_mapping, compose,
        high_confidence_only, false, NULL, state, iterations);
  }

  return result;
}

// Test every logical slot at one gap width before increasing the width. The diagnostic slot remains
// first within each width. There is no arbitrary gap-width cap; checkpoint polling bounds latency.
static inline SqliteRepairResult sqlite_try_gap_repair(
    ThreadWork *work, CarveInfo **candidate, uuid_string_t uuidp,
    uuid_string_t uuidc, const SqliteLayout *layout,
    const int64_t *base_mapping, uint64_t total_blocks,
    uint64_t preferred_target, uint8_t *trial_data,
    int64_t *trial_mapping, int64_t *solution_mapping,
    SqliteSearchCursor *cursor, SqliteRepairDescriptor *best_repair,
    SqliteIntegrity *best_integrity, SqliteCarveState *state,
    uint64_t *iterations) {
  const uint64_t apparent_blocks =
      filemirror_apparent_blocks(scalpel_state.filemirror);
  if (!cursor) {
    return SQLITE_REPAIR_NO_MATCH;
  }

  uint64_t maximum_gap = 0;
  for (uint64_t pass = 0; pass < total_blocks; pass++) {
    const uint64_t target = pass == 0 ? preferred_target : pass;
    if ((pass > 0 && target == preferred_target)
        || target == 0 || target >= total_blocks
        || base_mapping[target] < 0) {
      continue;
    }
    const uint64_t suffix_blocks = total_blocks - target;
    const uint64_t source_start = (uint64_t)base_mapping[target];
    if (source_start >= apparent_blocks
        || suffix_blocks > apparent_blocks - source_start) {
      continue;
    }
    const uint64_t target_maximum_gap =
        apparent_blocks - source_start - suffix_blocks;
    if (target_maximum_gap > maximum_gap) {
      maximum_gap = target_maximum_gap;
    }
  }

  if (cursor->pass >= total_blocks || maximum_gap == 0) {
    cursor->pass = total_blocks;
    cursor->width = maximum_gap + 1;
    cursor->source = 0;
    return SQLITE_REPAIR_NO_MATCH;
  }
  uint64_t first_gap = cursor->width;
  if (first_gap == 0) {
    first_gap = 1;
  }
  for (uint64_t gap = first_gap; gap <= maximum_gap; gap++) {
    const uint64_t first_pass =
        gap == first_gap && cursor->source != 0
            ? total_blocks
            : (gap == first_gap ? cursor->pass : 0);
    for (uint64_t pass = first_pass; pass < total_blocks; pass++) {
      const uint64_t target = pass == 0 ? preferred_target : pass;
      if (pass + 1 < total_blocks) {
        cursor->pass = pass + 1;
        cursor->width = gap;
        cursor->source = 0;
      }
      else {
        cursor->pass = 0;
        cursor->width = gap;
        cursor->source = 1;
      }

      if ((pass > 0 && target == preferred_target)
          || target == 0 || target >= total_blocks
          || base_mapping[target] < 0) {
        continue;
      }
      const uint64_t suffix_blocks = total_blocks - target;
      const uint64_t source_start = (uint64_t)base_mapping[target];
      if (source_start >= apparent_blocks
          || suffix_blocks > apparent_blocks - source_start
          || gap > apparent_blocks - source_start - suffix_blocks) {
        continue;
      }
      memcpy(trial_mapping, base_mapping,
             total_blocks * sizeof(*trial_mapping));
      for (uint64_t slot = target; slot < total_blocks; slot++) {
        const int64_t expected = base_mapping[target]
                                 + (int64_t)(slot - target);
        if (base_mapping[slot] == expected) {
          trial_mapping[slot] = expected + (int64_t)gap;
        }
      }
      SqliteIntegrity integrity;
      if (sqlite_mapping_check(trial_mapping, total_blocks,
                               layout->extent, trial_data, &integrity)) {
        if (best_repair) {
          best_repair->target = target;
          best_repair->width = gap;
          best_repair->source = 0;
          best_repair->valid = 1;
          best_repair->reserved = 0;
        }
        memcpy(solution_mapping, trial_mapping,
               total_blocks * sizeof(*solution_mapping));
        return SQLITE_REPAIR_MATCH;
      }
      if (best_repair && best_integrity
          && sqlite_integrity_better(&integrity, best_integrity)) {
        best_repair->target = target;
        best_repair->width = gap;
        best_repair->source = 0;
        best_repair->valid = 1;
        best_repair->reserved = 0;
        *best_integrity = integrity;
        if (scalpel_state.mode_verbose) {
          lock_fprintf(stdout,
                       "SQLite reassembly: GAP improvement at slot "
                       "%" PRIu64 ", width=%" PRIu64
                       ", errors=%u, pages=%u-%u.\n",
                       target, gap, integrity.error_count,
                       integrity.first_page, integrity.last_page);
        }

      }

      if (sqlite_reassembly_poll(work, candidate, uuidp, uuidc,
                                 state, iterations)) {
        return SQLITE_REPAIR_STOPPED;
      }
    }
    // Probe only the best intermediate mapping found at this width. Trying every incremental
    // improvement can spend the entire checkpoint interval composing mappings before the direct
    // gap sweep reaches the correct slot.
    if (best_repair && best_integrity && best_repair->valid
        && best_repair->width == gap
        && sqlite_apply_gap_descriptor(base_mapping, total_blocks,
                                       best_repair, trial_mapping)) {
      SqliteRepairResult probe_result = sqlite_probe_ooo_diagnostics(
          work, candidate, uuidp, uuidc, layout, best_integrity,
          trial_mapping, total_blocks, trial_data, solution_mapping,
          solution_mapping, NULL, false, false, state, iterations);
      if (probe_result != SQLITE_REPAIR_NO_MATCH) {
        return probe_result;
      }
    }
    cursor->pass = 0;
    cursor->width = gap + 1;
    cursor->source = 0;
  }
  cursor->pass = total_blocks;
  cursor->width = maximum_gap + 1;
  cursor->source = 0;
  return SQLITE_REPAIR_NO_MATCH;
}

// Replace a logical run with every physically contiguous source run in the apparent image. The
// integrity oracle and the changed-block necessity check reject repairs that merely replace bytes
// SQLite does not inspect. No run-width limit is imposed.
static inline SqliteRepairResult sqlite_try_ooo_repair(
    ThreadWork *work, CarveInfo **candidate, uuid_string_t uuidp,
    uuid_string_t uuidc, const SqliteLayout *layout,
    const int64_t *base_mapping, uint64_t total_blocks,
    uint64_t preferred_target, uint8_t *trial_data,
    int64_t *trial_mapping, int64_t *solution_mapping,
    SqliteSearchCursor *cursor, SqliteRepairDescriptor *best_repair,
    SqliteIntegrity *best_integrity, bool preferred_only,
    uint64_t maximum_width, SqliteCarveState *state,
    uint64_t *iterations) {
  const uint64_t apparent_blocks =
      filemirror_apparent_blocks(scalpel_state.filemirror);
  if (!cursor) {
    return SQLITE_REPAIR_NO_MATCH;
  }

  uint64_t mapping_max = 0;
  bool have_mapping = false;
  for (uint64_t slot = 0; slot < total_blocks; slot++) {
    if (base_mapping[slot] >= 0
        && (!have_mapping
            || (uint64_t)base_mapping[slot] > mapping_max)) {
      mapping_max = (uint64_t)base_mapping[slot];
      have_mapping = true;
    }
  }

  const uint64_t pass_limit = preferred_only ? 1 : total_blocks;
  for (uint64_t pass = cursor->pass; pass < pass_limit; pass++) {
    uint64_t target = pass == 0 ? preferred_target : pass;
    if (pass > 0 && target == preferred_target) {
      cursor->pass = pass + 1;
      cursor->width = 1;
      cursor->source = 0;
      continue;
    }
    if (target == 0 || target >= total_blocks) {
      cursor->pass = pass + 1;
      cursor->width = 1;
      cursor->source = 0;
      continue;
    }
    uint64_t maximum_run = total_blocks - target;
    if (maximum_width != 0 && maximum_run > maximum_width) {
      maximum_run = maximum_width;
    }
    uint64_t first_rank = pass == cursor->pass ? cursor->width : 1;
    if (first_rank == 0) {
      first_rank = 1;
    }
    uint64_t page_blocks = CEILDIV(layout->page_size,
                                   scalpel_state.blocksize);
    if (page_blocks == 0) {
      page_blocks = 1;
    }
    for (uint64_t run_rank = first_rank; run_rank <= maximum_run;
         run_rank++) {
      const uint64_t run_blocks = sqlite_ranked_run_width(
          run_rank, maximum_run, target, page_blocks);
      if (run_blocks > apparent_blocks) {
        continue;
      }
      const uint64_t last_source = apparent_blocks - run_blocks;
      const uint64_t source_count = last_source + 1;
      const uint64_t source_origin = !have_mapping
          ? 0
          : (mapping_max < last_source
              ? mapping_max + 1 : source_count);
      const uint64_t after_count = source_count - source_origin;
      uint64_t first_source_rank =
          pass == cursor->pass && run_rank == first_rank
              ? cursor->source : 0;
      for (uint64_t source_rank = first_source_rank;
           source_rank < source_count; source_rank++) {
        const uint64_t source = source_rank < after_count
            ? source_origin + source_rank
            : source_origin - 1 - (source_rank - after_count);
        cursor->pass = source_rank < last_source
                           ? pass
                           : (run_rank < maximum_run
                                  ? pass : pass + 1);
        cursor->width = source_rank < last_source
                            ? run_rank
                            : (run_rank < maximum_run
                                   ? run_rank + 1 : 1);
        cursor->source = source_rank < last_source
                             ? source_rank + 1 : 0;

        if (sqlite_source_overlaps_mapping(base_mapping, total_blocks,
                                           target, run_blocks,
                                           (int64_t)source)) {
          if (sqlite_reassembly_poll(work, candidate, uuidp, uuidc,
                                     state, iterations)) {
            return SQLITE_REPAIR_STOPPED;
          }
          continue;
        }
        memcpy(trial_mapping, base_mapping,
               total_blocks * sizeof(*trial_mapping));
        for (uint64_t offset = 0; offset < run_blocks; offset++) {
          trial_mapping[target + offset] = (int64_t)(source + offset);
        }
        SqliteIntegrity integrity;
        const bool mapping_valid = sqlite_mapping_ooo_check(
            trial_mapping, total_blocks, layout->extent, trial_data,
            &integrity, best_integrity,
            best_repair && best_integrity);
        if (mapping_valid) {
          const bool changes_are_necessary =
              sqlite_ooo_changes_are_necessary(
                  base_mapping, trial_mapping, target, run_blocks,
                  total_blocks, layout->extent, trial_data);
          sqlite_write_mapping_hypothesis(
              *candidate, trial_mapping, total_blocks,
              layout->extent);
          if (changes_are_necessary) {
            memcpy(solution_mapping, trial_mapping,
                   total_blocks * sizeof(*solution_mapping));
            bool ambiguity_closed = false;
            const SqliteRepairResult extension_result =
                sqlite_preserve_ooo_extensions(
                    work, candidate, uuidp, uuidc, layout,
                    base_mapping, total_blocks, target, run_blocks,
                    source, trial_data, trial_mapping,
                    solution_mapping, state,
                    iterations, &ambiguity_closed);
            if (extension_result == SQLITE_REPAIR_STOPPED
                || !*candidate) {
              return SQLITE_REPAIR_STOPPED;
            }
            if (ambiguity_closed) {
              return SQLITE_REPAIR_MATCH;
            }
          }
        }
        if (!mapping_valid && best_repair && best_integrity
            && sqlite_integrity_better(&integrity, best_integrity)) {
          best_repair->target = target;
          best_repair->width = run_blocks;
          best_repair->source = source;
          best_repair->valid = 1;
          best_repair->reserved = 0;
          *best_integrity = integrity;
          if (scalpel_state.mode_verbose) {
            lock_fprintf(stdout,
                         "SQLite reassembly: OOO improvement at slot "
                         "%" PRIu64 ", width=%" PRIu64
                         ", source=%" PRIu64
                         ", errors=%u, pages=%u-%u.\n",
                         target, run_blocks, source,
                         integrity.error_count, integrity.first_page,
                         integrity.last_page);
          }

        }
        if (sqlite_reassembly_poll(work, candidate, uuidp, uuidc,
                                   state, iterations)) {
          return SQLITE_REPAIR_STOPPED;
        }
      }
      cursor->pass = run_rank < maximum_run ? pass : pass + 1;
      cursor->width = run_rank < maximum_run ? run_rank + 1 : 1;
      cursor->source = 0;
    }
    cursor->pass = pass + 1;
    cursor->width = 1;
    cursor->source = 0;
  }
  cursor->pass = pass_limit;
  cursor->width = 1;
  cursor->source = 0;
  return SQLITE_REPAIR_NO_MATCH;
}

// The ranked paths normally identify one defect and expose the second quickly. If ranking chooses
// the wrong intermediate, enumerate every gap and run combination so ranking affects only time,
// not whether a database within the supported fragmentation model can be recovered.
static inline SqliteRepairResult sqlite_try_composed_repair(
    ThreadWork *work, CarveInfo **candidate, uuid_string_t uuidp,
    uuid_string_t uuidc, const SqliteLayout *layout,
    const int64_t *base_mapping, uint64_t total_blocks,
    uint64_t preferred_target, uint8_t *trial_data,
    int64_t *trial_mapping, int64_t *outer_mapping,
    int64_t *solution_mapping, SqliteCarveState *state,
    uint64_t *iterations) {
  const uint64_t apparent_blocks =
      filemirror_apparent_blocks(scalpel_state.filemirror);
  uint64_t maximum_gap = 0;
  for (uint64_t pass = 0; pass < total_blocks; pass++) {
    const uint64_t target = pass == 0 ? preferred_target : pass;
    if ((pass > 0 && target == preferred_target)
        || target == 0 || target >= total_blocks
        || base_mapping[target] < 0) {
      continue;
    }
    const uint64_t suffix_blocks = total_blocks - target;
    const uint64_t source_start = (uint64_t)base_mapping[target];
    if (source_start >= apparent_blocks
        || suffix_blocks > apparent_blocks - source_start) {
      continue;
    }
    const uint64_t target_maximum_gap =
        apparent_blocks - source_start - suffix_blocks;
    if (target_maximum_gap > maximum_gap) {
      maximum_gap = target_maximum_gap;
    }
  }

  while (state->outer_cursor.pass < total_blocks
         || state->active_outer_gap.valid) {
    if (!state->active_outer_gap.valid) {
      bool found = false;
      uint64_t first_gap = state->outer_cursor.width;
      if (first_gap == 0) {
        first_gap = 1;
      }
      for (uint64_t gap = first_gap;
           gap <= maximum_gap && !found; gap++) {
        const uint64_t first_pass = gap == first_gap
            ? state->outer_cursor.pass : 0;
        for (uint64_t pass = first_pass;
             pass < total_blocks && !found; pass++) {
          const uint64_t target = pass == 0 ? preferred_target : pass;
          if (pass + 1 < total_blocks) {
            state->outer_cursor.pass = pass + 1;
            state->outer_cursor.width = gap;
          }
          else if (gap < maximum_gap) {
            state->outer_cursor.pass = 0;
            state->outer_cursor.width = gap + 1;
          }
          else {
            state->outer_cursor.pass = total_blocks;
            state->outer_cursor.width = gap + 1;
          }
          state->outer_cursor.source = 0;

          if ((pass > 0 && target == preferred_target)
              || target == 0 || target >= total_blocks
              || base_mapping[target] < 0) {
            continue;
          }
          const uint64_t suffix_blocks = total_blocks - target;
          const uint64_t source_start =
              (uint64_t)base_mapping[target];
          if (source_start >= apparent_blocks
              || suffix_blocks > apparent_blocks - source_start
              || gap > apparent_blocks - source_start - suffix_blocks) {
            continue;
          }

          state->active_outer_gap.target = target;
          state->active_outer_gap.width = gap;
          state->active_outer_gap.source = 0;
          state->active_outer_gap.valid = 1;
          state->active_outer_gap.reserved = 0;
          sqlite_cursor_reset(&state->cursor);
          found = true;
        }
      }
      if (!found) {
        state->outer_cursor.pass = total_blocks;
        return SQLITE_REPAIR_NO_MATCH;
      }
    }

    if (!sqlite_apply_gap_descriptor(base_mapping, total_blocks,
                                     &state->active_outer_gap,
                                     outer_mapping)) {
      memset(&state->active_outer_gap, 0,
             sizeof(state->active_outer_gap));
      sqlite_cursor_reset(&state->cursor);
      continue;
    }
    SqliteRepairResult result = sqlite_try_ooo_repair(
        work, candidate, uuidp, uuidc, layout, outer_mapping,
        total_blocks, preferred_target, trial_data, trial_mapping,
        solution_mapping, &state->cursor, NULL, NULL, false, 0,
        state, iterations);
    if (result != SQLITE_REPAIR_NO_MATCH) {
      return result;
    }
    memset(&state->active_outer_gap, 0,
           sizeof(state->active_outer_gap));
    sqlite_cursor_reset(&state->cursor);
  }
  return SQLITE_REPAIR_NO_MATCH;
}

// Recover a database with an inserted physical gap, a displaced contiguous run, or one of each.
// Trial mappings never alter the live candidate. The final mapping is committed only after the
// complete database passes SQLite's integrity checker.
static inline void sqlite_reassembly(ThreadWork *work,
                                     CarveInfo **candidate,
                                     uuid_string_t uuidp,
                                     uuid_string_t uuidc) {
  SqliteCarveState *state = NULL;
  if (!work || !candidate || !*candidate || !(*candidate)->b) {
    return;
  }

  normalize_blockvector((*candidate)->b);
  inflate_blockvector((*candidate)->b);
  SqliteLayout layout;
  if (!sqlite_parse_header(
          (const uint8_t *)blockvector_get_data_pointer((*candidate)->b),
          blockvector_get_data_length((*candidate)->b), &layout)
      || layout.extent
             > scalpel_state.search_specs[(*candidate)->needleidx].MAXIMUMSIZE) {
    destroy_candidate(candidate);
    return;
  }

  const uint64_t total_blocks =
      CEILDIV(layout.extent, scalpel_state.blocksize);
  const uint64_t current_blocks =
      blockvector_get_num_blocks((*candidate)->b);
  if (total_blocks == 0 || total_blocks > SIZE_MAX / sizeof(int64_t)
      || layout.extent > SIZE_MAX) {
    destroy_candidate(candidate);
    return;
  }

  int64_t *base_mapping =
      (int64_t *)malloc(total_blocks * sizeof(*base_mapping));
  int64_t *trial_mapping =
      (int64_t *)malloc(total_blocks * sizeof(*trial_mapping));
  int64_t *solution_mapping =
      (int64_t *)malloc(total_blocks * sizeof(*solution_mapping));
  int64_t *intermediate_mapping =
      (int64_t *)malloc(total_blocks * sizeof(*intermediate_mapping));
  uint8_t *trial_data = (uint8_t *)malloc((size_t)layout.extent);
  check_memory_allocation(base_mapping, __LINE__, __FILE__,
                          "SQLite base mapping");
  check_memory_allocation(trial_mapping, __LINE__, __FILE__,
                          "SQLite trial mapping");
  check_memory_allocation(solution_mapping, __LINE__, __FILE__,
                          "SQLite solution mapping");
  check_memory_allocation(intermediate_mapping, __LINE__, __FILE__,
                          "SQLite intermediate mapping");
  check_memory_allocation(trial_data, __LINE__, __FILE__,
                          "SQLite trial data");

  int64_t next_apparent = -1;
  for (uint64_t slot = 0; slot < total_blocks; slot++) {
    if (slot < current_blocks) {
      base_mapping[slot] =
          blockvector_get_apparent_blocknumber((*candidate)->b, slot);
      next_apparent = base_mapping[slot] + 1;
    }
    else if (next_apparent >= 0
             && (uint64_t)next_apparent
                    < filemirror_apparent_blocks(scalpel_state.filemirror)) {
      base_mapping[slot] = next_apparent++;
    }
    else {
      base_mapping[slot] = -1;
    }
  }

  SqliteIntegrity baseline_integrity;
  SqliteCheckContext baseline_context;
  sqlite_mapping_check_diagnostic(
      base_mapping, total_blocks, layout.extent, trial_data,
      &baseline_integrity, &baseline_context);
  const bool baseline_was_valid = baseline_integrity.valid;

  // A one-block database has no replaceable position after its header block at the current carving
  // granularity. Preserve it as promising when requested, but do not enter an empty search.
  if (total_blocks < 2) {
    if (baseline_was_valid) {
      memcpy(solution_mapping, base_mapping,
             total_blocks * sizeof(*solution_mapping));
      goto validated;
    }
    goto not_recovered;
  }

  uint64_t diagnostic_cell_target = 0;
  uint64_t preferred_target = 0;
  if (baseline_was_valid) {
    for (uint64_t slot = 1; slot < total_blocks; slot++) {
      if (sqlite_mapping_block_is_zero(base_mapping, slot)) {
        preferred_target = slot;
        break;
      }
    }
    if (scalpel_state.no_defrag || !scalpel_state.write_promising
        || preferred_target == 0) {
      memcpy(solution_mapping, base_mapping,
             total_blocks * sizeof(*solution_mapping));
      goto validated;
    }
  }
  else {
    diagnostic_cell_target = sqlite_diagnostic_cell_block(
        &baseline_context, trial_data, &layout,
        scalpel_state.blocksize, total_blocks);
    preferred_target = diagnostic_cell_target > 0
        ? diagnostic_cell_target
        : sqlite_failure_block(&baseline_integrity, &layout,
                               base_mapping, scalpel_state.blocksize,
                               total_blocks);
    if (preferred_target == 0 || preferred_target >= total_blocks) {
      preferred_target = 1;
    }
  }
  if (scalpel_state.mode_verbose) {
    lock_fprintf(
        stdout,
        "SQLite reassembly: header block=%" PRId64
        ", blocks=%" PRIu64 ", page size=%" PRIu32
        ", integrity errors=%" PRIu32 ", first page=%" PRIu32
        ", last page=%" PRIu32 ", preferred block=%" PRIu64 ".\n",
        blockvector_get_actual_blocknumber((*candidate)->b, 0),
        total_blocks, layout.page_size, baseline_integrity.error_count,
        baseline_integrity.first_page, baseline_integrity.last_page,
        preferred_target);
    if (diagnostic_cell_target > 0) {
      lock_fprintf(
          stdout,
          "SQLite reassembly: integrity cell points to block "
          "%" PRIu64 ".\n",
          diagnostic_cell_target);
    }
  }
  const uint64_t apparent_blocks =
      filemirror_apparent_blocks(scalpel_state.filemirror);
  const uint64_t base_mapping_hash =
      sqlite_mapping_hash(base_mapping, total_blocks);

  state = (SqliteCarveState *)carve_get_state(
      (*candidate)->carvehashkey);
  if (!sqlite_carve_state_valid(state)
      || state->extent != layout.extent
      || state->total_blocks != total_blocks
      || state->apparent_blocks != apparent_blocks
      || state->base_mapping_hash != base_mapping_hash
      || state->preferred_target != preferred_target) {
    sqlite_free_carve_state((void **)&state);
    state = (SqliteCarveState *)calloc(1, sizeof(*state));
    check_memory_allocation(state, __LINE__, __FILE__,
                            "SQLite carve state");
    state->magic = SQLITE_CARVE_STATE_MAGIC;
    state->version = SQLITE_CARVE_STATE_VERSION;
    state->stage = SQLITE_SEARCH_INITIAL_PROBES;
    state->extent = layout.extent;
    state->total_blocks = total_blocks;
    state->apparent_blocks = apparent_blocks;
    state->base_mapping_hash = base_mapping_hash;
    state->preferred_target = preferred_target;
    state->baseline_integrity = baseline_integrity;
    state->best_gap_integrity = baseline_integrity;
    state->best_ooo_integrity = baseline_integrity;
    sqlite_cursor_reset(&state->cursor);
    sqlite_cursor_reset(&state->outer_cursor);
  }
  uint64_t iterations = 0;
  SqliteRepairResult repair_result = SQLITE_REPAIR_NO_MATCH;
  if (baseline_was_valid) {
    if (state->probe_step == 0) {
      sqlite_write_mapping_hypothesis(
          *candidate, base_mapping, total_blocks, layout.extent);
      state->probe_step = 1;
      state->outer_cursor.source = preferred_target;
    }
    uint64_t slot = state->outer_cursor.source;
    if (slot == 0 || slot >= total_blocks) {
      slot = preferred_target;
    }
    while (slot < total_blocks) {
      if (!sqlite_mapping_block_is_zero(base_mapping, slot)) {
        slot++;
        state->outer_cursor.source = slot;
        continue;
      }
      const uint64_t zero_start = slot;
      while (slot + 1 < total_blocks
             && sqlite_mapping_block_is_zero(base_mapping, slot + 1)) {
        slot++;
      }
      const uint64_t zero_width = slot - zero_start + 1;
      state->outer_cursor.source = zero_start;
      repair_result = sqlite_probe_ooo_repair(
          work, candidate, uuidp, uuidc, &layout, &baseline_integrity,
          base_mapping, total_blocks, zero_start, true, zero_width,
          trial_data, trial_mapping, solution_mapping,
          intermediate_mapping, false, true, false, NULL, state,
          &iterations);
      if (repair_result == SQLITE_REPAIR_STOPPED || !*candidate) {
        goto done;
      }
      if (repair_result == SQLITE_REPAIR_PRESERVED) {
        goto alternatives_preserved;
      }
      if (repair_result == SQLITE_REPAIR_MATCH) {
        goto validated;
      }
      slot++;
      state->outer_cursor.source = slot;
    }
    memcpy(solution_mapping, base_mapping,
           total_blocks * sizeof(*solution_mapping));
    goto validated;
  }
  const bool localized_damage =
      baseline_integrity.first_page > 0
      && baseline_integrity.last_page >= baseline_integrity.first_page
      && baseline_integrity.last_page - baseline_integrity.first_page <= 1;

  while (*candidate && state->stage < SQLITE_SEARCH_COMPLETE) {
    if (state->stage == SQLITE_SEARCH_INITIAL_PROBES) {
      if (state->probe_step == 0) {
        state->probe_step = 1;
        repair_result = sqlite_probe_shifted_page_gap(
            work, candidate, uuidp, uuidc, &layout,
            &baseline_integrity, base_mapping, total_blocks,
            trial_data, trial_mapping, solution_mapping,
            intermediate_mapping, true, true, state, &iterations);
        if (repair_result == SQLITE_REPAIR_MATCH) {
          goto validated;
        }
        if (repair_result == SQLITE_REPAIR_PRESERVED) {
          goto alternatives_preserved;
        }
        if (repair_result == SQLITE_REPAIR_STOPPED || !*candidate) {
          goto done;
        }
      }
      if (state->probe_step == 1) {
        state->probe_step = 2;
        if (diagnostic_cell_target > 0) {
          repair_result = sqlite_probe_ooo_repair(
              work, candidate, uuidp, uuidc, &layout,
              &baseline_integrity, base_mapping, total_blocks,
              diagnostic_cell_target, true, 0, trial_data,
              trial_mapping,
              solution_mapping, intermediate_mapping, false, true,
              false, NULL, state, &iterations);
          if (repair_result == SQLITE_REPAIR_MATCH) {
            goto validated;
          }
          if (repair_result == SQLITE_REPAIR_PRESERVED) {
            goto alternatives_preserved;
          }
          if (repair_result == SQLITE_REPAIR_STOPPED || !*candidate) {
            goto done;
          }
        }
        repair_result = sqlite_probe_ooo_diagnostics(
            work, candidate, uuidp, uuidc, &layout,
            &baseline_integrity, base_mapping, total_blocks,
            trial_data, trial_mapping, solution_mapping,
            intermediate_mapping, false, true, state, &iterations);
        if (repair_result == SQLITE_REPAIR_MATCH) {
          goto validated;
        }
        if (repair_result == SQLITE_REPAIR_PRESERVED) {
          goto alternatives_preserved;
        }
        if (repair_result == SQLITE_REPAIR_STOPPED || !*candidate) {
          goto done;
        }
      }
      if (state->probe_step == 2) {
        state->probe_step = 3;
        repair_result = sqlite_probe_gap_diagnostics(
            work, candidate, uuidp, uuidc, &layout,
            &baseline_integrity, base_mapping, total_blocks,
            trial_data, trial_mapping, solution_mapping,
            intermediate_mapping, true, state, &iterations);
        if (repair_result == SQLITE_REPAIR_MATCH) {
          goto validated;
        }
        if (repair_result == SQLITE_REPAIR_PRESERVED) {
          goto alternatives_preserved;
        }
        if (repair_result == SQLITE_REPAIR_STOPPED || !*candidate) {
          goto done;
        }
      }
      // A physical gap shifts the remaining page stream and normally produces errors over a wide
      // page range. Rank that gap before source discovery; damage confined to one or two pages
      // retains the OOO-first ordering.
      if (state->probe_step == 3 && !localized_damage) {
        state->probe_step = 4;
        if (!state->best_gap.valid) {
          repair_result = sqlite_probe_gap_grid(
              work, candidate, uuidp, uuidc, &layout,
              &baseline_integrity, base_mapping, total_blocks,
              trial_data, trial_mapping, solution_mapping,
              &state->best_gap, &state->best_gap_integrity,
              state, &iterations);
          if (repair_result == SQLITE_REPAIR_MATCH) {
            goto validated;
          }
          if (repair_result == SQLITE_REPAIR_STOPPED || !*candidate) {
            goto done;
          }
        }
        state->stage = state->best_gap.valid
            ? SQLITE_SEARCH_RANKED_GAP_OOO
            : SQLITE_SEARCH_BASE_GAP;
        sqlite_cursor_reset(&state->cursor);
        continue;
      }
      if (state->probe_step == 3) {
        state->probe_step = 4;
        if (diagnostic_cell_target > 0) {
          repair_result = sqlite_probe_ooo_repair(
              work, candidate, uuidp, uuidc, &layout,
              &baseline_integrity, base_mapping, total_blocks,
              diagnostic_cell_target, true, 0, trial_data,
              trial_mapping,
              solution_mapping, intermediate_mapping, true, false,
              false, NULL, state, &iterations);
          if (repair_result == SQLITE_REPAIR_MATCH) {
            goto validated;
          }
          if (repair_result == SQLITE_REPAIR_PRESERVED) {
            goto alternatives_preserved;
          }
          if (repair_result == SQLITE_REPAIR_STOPPED || !*candidate) {
            goto done;
          }
        }
        repair_result = sqlite_probe_ooo_diagnostics(
            work, candidate, uuidp, uuidc, &layout,
            &baseline_integrity, base_mapping, total_blocks,
            trial_data, trial_mapping, solution_mapping,
            intermediate_mapping, true, false, state, &iterations);
        if (repair_result == SQLITE_REPAIR_MATCH) {
          goto validated;
        }
        if (repair_result == SQLITE_REPAIR_PRESERVED) {
          goto alternatives_preserved;
        }
        if (repair_result == SQLITE_REPAIR_STOPPED || !*candidate) {
          goto done;
        }
      }
      state->stage = !localized_damage && state->best_gap.valid
          ? SQLITE_SEARCH_RANKED_GAP_OOO
          : SQLITE_SEARCH_BASE_GAP;
      sqlite_cursor_reset(&state->cursor);
      continue;
    }

    if (state->stage == SQLITE_SEARCH_RANKED_GAP_OOO) {
      if (sqlite_apply_gap_descriptor(base_mapping, total_blocks,
                                      &state->best_gap,
                                      intermediate_mapping)) {
        SqliteIntegrity ranked_integrity;
        SqliteCheckContext ranked_context;
        sqlite_mapping_check_diagnostic(
            intermediate_mapping, total_blocks, layout.extent,
            trial_data, &ranked_integrity, &ranked_context);
        uint64_t second_target = sqlite_diagnostic_cell_block(
            &ranked_context, trial_data, &layout,
            scalpel_state.blocksize, total_blocks);
        if (second_target == 0 || second_target >= total_blocks) {
          second_target = sqlite_failure_block(
              &ranked_integrity, &layout, intermediate_mapping,
              scalpel_state.blocksize, total_blocks);
        }
        if (second_target == 0 || second_target >= total_blocks) {
          second_target = preferred_target;
        }
        const uint64_t first_error_target = sqlite_page_block(
            ranked_integrity.first_page, &layout,
            scalpel_state.blocksize, total_blocks);
        if (scalpel_state.mode_verbose) {
          lock_fprintf(
              stdout,
              "SQLite reassembly: ranked GAP diagnostics select "
              "cell block=%" PRIu64 ", first error block=%" PRIu64
              ".\n",
              second_target, first_error_target);
        }
        memcpy(solution_mapping, intermediate_mapping,
               total_blocks * sizeof(*solution_mapping));
        // Probe short source runs using structural evidence before entering the checkpointed
        // complete scan. Advance the marker first so an interrupted optimization cannot restart
        // indefinitely across progress checkpoints.
        if (state->outer_cursor.pass == 0) {
          state->outer_cursor.pass = 1;
          const uint64_t primary_target =
              first_error_target > 0 && first_error_target < total_blocks
                  ? first_error_target : second_target;
          const bool primary_target_is_exact =
              primary_target != first_error_target;
          repair_result = sqlite_probe_ooo_repair(
              work, candidate, uuidp, uuidc, &layout,
              &ranked_integrity, intermediate_mapping, total_blocks,
              primary_target, primary_target_is_exact, 0,
              trial_data, trial_mapping,
              solution_mapping, NULL, false, true, false, NULL, state,
              &iterations);
          if (repair_result == SQLITE_REPAIR_PRESERVED) {
            goto alternatives_preserved;
          }
          if (repair_result == SQLITE_REPAIR_STOPPED || !*candidate) {
            goto done;
          }
          SqliteIntegrity fast_integrity;
          bool have_fast_solution = sqlite_mapping_check(
              solution_mapping, total_blocks, layout.extent,
              trial_data, &fast_integrity);
          if (!have_fast_solution && second_target != primary_target) {
            repair_result = sqlite_probe_ooo_repair(
                work, candidate, uuidp, uuidc, &layout,
                &ranked_integrity, intermediate_mapping, total_blocks,
                second_target, true, 0, trial_data, trial_mapping,
                solution_mapping, NULL, false, true, false, NULL, state,
                &iterations);
            if (repair_result == SQLITE_REPAIR_PRESERVED) {
              goto alternatives_preserved;
            }
            if (repair_result == SQLITE_REPAIR_STOPPED || !*candidate) {
              goto done;
            }
            have_fast_solution = sqlite_mapping_check(
                solution_mapping, total_blocks, layout.extent,
                trial_data, &fast_integrity);
          }
          if (!have_fast_solution) {
            repair_result = sqlite_probe_ooo_diagnostics(
                work, candidate, uuidp, uuidc, &layout,
                &ranked_integrity, intermediate_mapping,
                total_blocks, trial_data, trial_mapping,
                solution_mapping, NULL, false, false, state,
                &iterations);
            if (repair_result == SQLITE_REPAIR_PRESERVED) {
              goto alternatives_preserved;
            }
            if (repair_result == SQLITE_REPAIR_STOPPED
                || !*candidate) {
              goto done;
            }
          }
        }
        SqliteIntegrity solution_integrity;
        bool have_clean_solution = sqlite_mapping_check(
            solution_mapping, total_blocks, layout.extent,
            trial_data, &solution_integrity);
        if (!have_clean_solution) {
          repair_result = sqlite_try_ooo_repair(
              work, candidate, uuidp, uuidc, &layout,
              intermediate_mapping, total_blocks, second_target,
              trial_data, trial_mapping, solution_mapping,
              &state->cursor, NULL, NULL, true,
              SQLITE_FAST_PROBE_MAXIMUM_RUN_BLOCKS,
              state, &iterations);
          if (repair_result == SQLITE_REPAIR_STOPPED || !*candidate) {
            goto done;
          }
          have_clean_solution = sqlite_mapping_check(
              solution_mapping, total_blocks, layout.extent,
              trial_data, &solution_integrity);
        }
        if (have_clean_solution) {
          repair_result = sqlite_preserve_gap_alternatives(
              work, candidate, uuidp, uuidc, &layout, base_mapping,
              total_blocks, &state->best_gap, intermediate_mapping,
              solution_mapping, trial_data, trial_mapping, state,
              &iterations);
          if (repair_result == SQLITE_REPAIR_STOPPED || !*candidate) {
            goto done;
          }
          state->outer_cursor.pass = 2;
          goto validated;
        }
      }
      state->stage = SQLITE_SEARCH_BASE_GAP;
      sqlite_cursor_reset(&state->cursor);
      sqlite_cursor_reset(&state->outer_cursor);
      continue;
    }

    if (state->stage == SQLITE_SEARCH_BASE_GAP) {
      repair_result = sqlite_try_gap_repair(
          work, candidate, uuidp, uuidc, &layout, base_mapping,
          total_blocks, preferred_target, trial_data, trial_mapping,
          solution_mapping, &state->cursor, &state->best_gap,
          &state->best_gap_integrity, state, &iterations);
      if (repair_result == SQLITE_REPAIR_MATCH) {
        goto validated;
      }
      if (repair_result == SQLITE_REPAIR_PRESERVED) {
        goto alternatives_preserved;
      }
      if (repair_result == SQLITE_REPAIR_STOPPED || !*candidate) {
        goto done;
      }
      state->stage = SQLITE_SEARCH_BEST_GAP_OOO;
      sqlite_cursor_reset(&state->cursor);
      continue;
    }

    if (state->stage == SQLITE_SEARCH_BEST_GAP_OOO) {
      if (sqlite_apply_gap_descriptor(base_mapping, total_blocks,
                                      &state->best_gap,
                                      intermediate_mapping)) {
        SqliteIntegrity repaired_integrity;
        SqliteCheckContext repaired_context;
        sqlite_mapping_check_diagnostic(
            intermediate_mapping, total_blocks, layout.extent,
            trial_data, &repaired_integrity, &repaired_context);
        uint64_t second_target = sqlite_diagnostic_cell_block(
            &repaired_context, trial_data, &layout,
            scalpel_state.blocksize, total_blocks);
        if (second_target == 0 || second_target >= total_blocks) {
          second_target = sqlite_failure_block(
              &repaired_integrity, &layout, intermediate_mapping,
              scalpel_state.blocksize, total_blocks);
        }
        if (second_target == 0 || second_target >= total_blocks) {
          second_target = preferred_target;
        }
        repair_result = sqlite_try_ooo_repair(
            work, candidate, uuidp, uuidc, &layout,
            intermediate_mapping, total_blocks, second_target,
            trial_data, trial_mapping, solution_mapping,
            &state->cursor, NULL, NULL, false, 0, state,
            &iterations);
        if (repair_result == SQLITE_REPAIR_MATCH) {
          goto validated;
        }
        if (repair_result == SQLITE_REPAIR_PRESERVED) {
          goto alternatives_preserved;
        }
        if (repair_result == SQLITE_REPAIR_STOPPED || !*candidate) {
          goto done;
        }
      }
      state->stage = SQLITE_SEARCH_BASE_OOO;
      sqlite_cursor_reset(&state->cursor);
      continue;
    }

    if (state->stage == SQLITE_SEARCH_BASE_OOO) {
      repair_result = sqlite_try_ooo_repair(
          work, candidate, uuidp, uuidc, &layout, base_mapping,
          total_blocks, preferred_target, trial_data, trial_mapping,
          solution_mapping, &state->cursor, &state->best_ooo,
          &state->best_ooo_integrity, false, 0, state,
          &iterations);
      if (repair_result == SQLITE_REPAIR_MATCH) {
        goto validated;
      }
      if (repair_result == SQLITE_REPAIR_PRESERVED) {
        goto alternatives_preserved;
      }
      if (repair_result == SQLITE_REPAIR_STOPPED || !*candidate) {
        goto done;
      }
      state->stage = SQLITE_SEARCH_BEST_OOO_GAP;
      sqlite_cursor_reset(&state->cursor);
      continue;
    }

    if (state->stage == SQLITE_SEARCH_BEST_OOO_GAP) {
      if (sqlite_apply_ooo_descriptor(base_mapping, total_blocks,
                                      &state->best_ooo,
                                      intermediate_mapping)) {
        SqliteRepairDescriptor composed_gap = {0};
        uint64_t second_target = sqlite_failure_block(
            &state->best_ooo_integrity, &layout, intermediate_mapping,
            scalpel_state.blocksize, total_blocks);
        if (second_target == 0 || second_target >= total_blocks) {
          second_target = preferred_target;
        }
        repair_result = sqlite_try_gap_repair(
            work, candidate, uuidp, uuidc, &layout,
            intermediate_mapping, total_blocks, second_target,
            trial_data, trial_mapping, solution_mapping,
            &state->cursor, &composed_gap, NULL, state, &iterations);
        if (repair_result == SQLITE_REPAIR_MATCH) {
          sqlite_write_mapping_hypothesis(
              *candidate, solution_mapping, total_blocks, layout.extent);
          const bool have_gap_only_mapping = sqlite_apply_gap_descriptor(
              base_mapping, total_blocks, &composed_gap, trial_mapping);
          const bool changes_are_necessary = have_gap_only_mapping
              && sqlite_ooo_changes_are_necessary(
                  trial_mapping, solution_mapping,
                  state->best_ooo.target, state->best_ooo.width,
                  total_blocks, layout.extent, trial_data);
          if (changes_are_necessary) {
            goto validated;
          }
          repair_result = SQLITE_REPAIR_NO_MATCH;
        }
        if (repair_result == SQLITE_REPAIR_STOPPED || !*candidate) {
          goto done;
        }
        if (repair_result == SQLITE_REPAIR_PRESERVED) {
          goto alternatives_preserved;
        }
      }
      state->stage = SQLITE_SEARCH_EXHAUSTIVE_GAP_OOO;
      sqlite_cursor_reset(&state->cursor);
      sqlite_cursor_reset(&state->outer_cursor);
      memset(&state->active_outer_gap, 0,
             sizeof(state->active_outer_gap));
      continue;
    }

    if (state->stage == SQLITE_SEARCH_EXHAUSTIVE_GAP_OOO) {
      repair_result = sqlite_try_composed_repair(
          work, candidate, uuidp, uuidc, &layout, base_mapping,
          total_blocks, preferred_target, trial_data, trial_mapping,
          intermediate_mapping, solution_mapping, state, &iterations);
      if (repair_result == SQLITE_REPAIR_MATCH) {
        goto validated;
      }
      if (repair_result == SQLITE_REPAIR_PRESERVED) {
        goto alternatives_preserved;
      }
      if (repair_result == SQLITE_REPAIR_STOPPED || !*candidate) {
        goto done;
      }
      state->stage = SQLITE_SEARCH_MULTI_REGION;
      continue;
    }

    // Multi-region composition is the complete fallback. Simple cases first use the less
    // expensive one-region search stages above.
    repair_result = sqlite_probe_shifted_page_gap(
        work, candidate, uuidp, uuidc, &layout, &baseline_integrity,
        base_mapping, total_blocks, trial_data, trial_mapping,
        solution_mapping, intermediate_mapping, true, true, state,
        &iterations);
    if (repair_result == SQLITE_REPAIR_MATCH) {
      goto validated;
    }
    if (repair_result == SQLITE_REPAIR_PRESERVED) {
      goto alternatives_preserved;
    }
    if (repair_result == SQLITE_REPAIR_STOPPED || !*candidate) {
      goto done;
    }
    state->stage = SQLITE_SEARCH_COMPLETE;
  }
  goto not_recovered;

alternatives_preserved:
  if (*candidate) {
    destroy_candidate(candidate);
  }
  goto done;

not_recovered:
  if (scalpel_state.write_promising) {
    uint64_t safe_length = scalpel_state.blocksize;
    if (baseline_integrity.first_page > 1) {
      safe_length = (uint64_t)(baseline_integrity.first_page - 1)
                    * layout.page_size;
    }
    if (safe_length > layout.extent) {
      safe_length = layout.extent;
    }
    if (safe_length == 0) {
      safe_length = 1;
    }
    blockvector_set_data_length((*candidate)->b, safe_length);
    resize_blockvector((*candidate)->b,
                       CEILDIV(safe_length, scalpel_state.blocksize));
    (*candidate)->best_validates_to = safe_length - 1;
    (*candidate)->flavor = PROMISING;
    write_candidate(candidate, false);
  }
  else {
    destroy_candidate(candidate);
  }
  goto done;

validated:
  if (*candidate) {
    SqliteIntegrity final_integrity;
    if (sqlite_mapping_check(solution_mapping, total_blocks,
                             layout.extent, trial_data,
                             &final_integrity)
        && sqlite_commit_mapping(*candidate, solution_mapping,
                                 total_blocks, layout.extent)) {
      // Structural integrity cannot authenticate free or unused bytes. Preserve a complete
      // recovered database as promising whenever fragmented recovery is enabled.
      (*candidate)->flavor = scalpel_state.no_defrag ? VALIDATED : PROMISING;
      write_candidate(candidate, false);
    }
    else {
      goto not_recovered;
    }
  }

done:
  sqlite_free_carve_state((void **)&state);
  free(trial_data);
  free(intermediate_mapping);
  free(solution_mapping);
  free(trial_mapping);
  free(base_mapping);
}

#endif  // SCALPEL_SQLITE_H
