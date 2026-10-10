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
#define SQLITE_CARVE_STATE_VERSION            UINT32_C(24)

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

typedef struct SqliteOooExtensionState {
  uint64_t view;
  SqliteRepairDescriptor repair;
  SqliteRepairDescriptor last;
  uint64_t next_extension;
  uint64_t next_gap_target;
  uint32_t direction;
  uint32_t closed;
  uint32_t owner_stage;
  uint32_t active;
} SqliteOooExtensionState;

typedef struct SqliteGapGridState {
  uint64_t view;
  uint64_t width;
  uint64_t next_target;
  uint64_t last_target;
  uint64_t step;
  SqliteRepairDescriptor width_best;
  SqliteIntegrity width_integrity;
  uint32_t phase;
  uint32_t window_ready;
  uint32_t active;
} SqliteGapGridState;

typedef struct SqliteOooProbeProgress {
  uint64_t key;
  uint64_t confidence_pass;
  uint64_t reservation_pass;
  uint64_t width_pass;
  uint64_t target_rank;
  uint64_t source_rank;
  uint64_t repair_count;
  SqliteIntegrity best_integrity;
  SqliteRepairDescriptor composition;
  SqliteRepairDescriptor solution;
  SqliteOooExtensionState extension;
  uint32_t scan_complete;
  uint32_t preserved_clean;
  uint32_t preserved_bounded;
  uint32_t preserved_necessary;
  uint32_t extending;
  uint32_t key_match;
  uint32_t initialized;
} SqliteOooProbeProgress;

typedef struct SqliteOooProbeState {
  SqliteOooProbeProgress progress;
  SqliteRepairDescriptor *repairs;
  struct SqliteOooProbeState *next;
} SqliteOooProbeState;

typedef enum SqliteGapProbeKind {
  SQLITE_GAP_PROBE_RANKING = 0,
  SQLITE_GAP_PROBE_ALTERNATIVES = 1
} SqliteGapProbeKind;

typedef struct SqliteGapProbeProgress {
  uint64_t key;
  uint64_t next_target;
  uint64_t next_width;
  uint64_t preserved;
  SqliteIntegrity best_integrity;
  SqliteRepairDescriptor best_gap;
  uint32_t kind;
  uint32_t initialized;
  uint32_t scan_complete;
  uint32_t matched;
} SqliteGapProbeProgress;

typedef struct SqliteGapProbeState {
  SqliteGapProbeProgress progress;
  struct SqliteGapProbeState *next;
} SqliteGapProbeState;

typedef struct SqlitePairProbeProgress {
  uint64_t key;
  uint64_t diagonal;
  uint64_t first_rank;
  uint64_t preserved;
  uint64_t class_counts[2][2];
  uint32_t class_pair;
  uint32_t scan_complete;
} SqlitePairProbeProgress;

typedef struct SqlitePairProbeState {
  SqlitePairProbeProgress progress;
  struct SqlitePairProbeState *next;
} SqlitePairProbeState;

typedef struct SqlitePageCompletionProgress {
  uint64_t key;
  uint64_t target_count;
  uint64_t repair;
  uint64_t anchor;
  uint64_t attempted_count;
  uint64_t preserved;
  uint64_t attempted_targets[SQLITE_PAGE_TRANSITION_LIMIT * 2];
  uint64_t attempted_sources[SQLITE_PAGE_TRANSITION_LIMIT * 2];
  uint32_t complete;
} SqlitePageCompletionProgress;

typedef struct SqlitePageCompletionState {
  SqlitePageCompletionProgress progress;
  struct SqlitePageCompletionState *next;
} SqlitePageCompletionState;

typedef struct SqlitePermutationProgress {
  uint64_t key;
  uint64_t target_count;
  uint64_t count;
  uint64_t permutation;
  uint64_t left;
  uint64_t right;
  uint64_t hashes[SQLITE_COMPOSED_REPAIR_PROBE_LIMIT];
  uint8_t order[SQLITE_COMPOSED_REPAIR_PROBE_LIMIT][SQLITE_PAGE_TRANSITION_LIMIT];
  uint32_t complete;
} SqlitePermutationProgress;

typedef struct SqlitePermutationState {
  SqlitePermutationProgress progress;
  struct SqlitePermutationState *next;
} SqlitePermutationState;

typedef struct SqliteTransitionRankingProgress {
  uint64_t key;
  uint64_t first_target;
  uint64_t last_target;
  uint64_t width;
  uint64_t next_target;
  uint64_t best_target;
  SqliteIntegrity best_integrity;
  uint32_t usable;
  uint32_t clean;
  uint32_t zero_backed;
  uint32_t complete;
} SqliteTransitionRankingProgress;

typedef struct SqliteTransitionRankingState {
  SqliteTransitionRankingProgress progress;
  struct SqliteTransitionRankingState *next;
} SqliteTransitionRankingState;

typedef enum SqliteTransitionScanPhase {
  SQLITE_TRANSITION_SCAN_PAGES = 0,
  SQLITE_TRANSITION_SCAN_BLOCK_POLL = 1,
  SQLITE_TRANSITION_SCAN_BLOCK = 2,
  SQLITE_TRANSITION_SCAN_RIGHT = 3,
  SQLITE_TRANSITION_SCAN_COMPLETE = 4
} SqliteTransitionScanPhase;

typedef struct SqliteTransitionScanProgress {
  uint64_t key;
  uint64_t page_blocks;
  uint64_t boundary;
  uint64_t left_support;
  uint64_t width;
  uint64_t right_support;
  uint64_t count;
  uint64_t boundaries[SQLITE_PAGE_TRANSITION_LIMIT];
  uint64_t widths[SQLITE_PAGE_TRANSITION_LIMIT];
  uint64_t support[SQLITE_PAGE_TRANSITION_LIMIT];
  uint64_t gap_targets[SQLITE_PAGE_TRANSITION_LIMIT];
  uint32_t zero_backed[SQLITE_PAGE_TRANSITION_LIMIT];
  uint32_t page_aligned[SQLITE_PAGE_TRANSITION_LIMIT];
  uint32_t phase;
} SqliteTransitionScanProgress;

typedef struct SqliteTransitionScanState {
  SqliteTransitionScanProgress progress;
  struct SqliteTransitionScanState *next;
} SqliteTransitionScanState;

typedef struct SqliteRadiusProgress {
  uint64_t key;
  uint64_t boundary;
  uint64_t width;
  uint64_t radius;
  uint64_t next_trial;
  SqliteRepairDescriptor best_gap;
  SqliteIntegrity best_integrity;
  uint32_t improved;
  uint32_t matched;
  uint32_t complete;
} SqliteRadiusProgress;

typedef struct SqliteRadiusState {
  SqliteRadiusProgress progress;
  struct SqliteRadiusState *next;
} SqliteRadiusState;

typedef struct SqliteMultiRegionProgress {
  uint64_t key;
  uint64_t chain_count;
  uint64_t transition;
  uint64_t next_repair;
  uint64_t repair_count;
  uint64_t repair_hash;
  SqliteRepairDescriptor chain[SQLITE_PAGE_TRANSITION_LIMIT];
  SqliteRepairDescriptor best;
  SqliteIntegrity current_integrity;
  SqliteIntegrity next_integrity;
  SqliteIntegrity final_integrity;
  uint32_t repaired_mask;
  uint32_t multi_region_valid;
  uint32_t transition_active;
  uint32_t list_ready;
  uint32_t complete;
} SqliteMultiRegionProgress;

typedef struct SqliteMultiRegionState {
  SqliteMultiRegionProgress progress;
  struct SqliteMultiRegionState *next;
} SqliteMultiRegionState;

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
  SqliteOooExtensionState extension;
  SqliteGapGridState gap_grid;
  uint64_t probe_owner;
  uint64_t probe_view;
  uint64_t probe_count;
  uint64_t reservation_bytes;
  uint64_t gap_probe_count;
  uint64_t pair_probe_count;
  uint64_t page_completion_count;
  uint64_t permutation_count;
  uint64_t transition_ranking_count;
  uint64_t transition_scan_count;
  uint64_t radius_count;
  uint64_t multi_region_count;
  roaring64_bitmap_t *probe_reservations;
  SqliteOooProbeState *ooo_probes;
  SqliteGapProbeState *gap_probes;
  SqlitePairProbeState *pair_probes;
  SqlitePageCompletionState *page_completions;
  SqlitePermutationState *permutations;
  SqliteTransitionRankingState *transition_rankings;
  SqliteTransitionScanState *transition_scans;
  SqliteRadiusState *radius_rankings;
  SqliteMultiRegionState *multi_regions;
} SqliteCarveState;

static inline uint16_t sqlite_read_be16(const uint8_t *data);
static inline void sqlite_clear_ooo_probes(SqliteCarveState *state);
static inline bool sqlite_ooo_probes_valid(const SqliteCarveState *state);
static inline bool sqlite_probe_reservations_io(
    SqliteCarveState *state, FILE *fp, StateSerialization mode, bool dense);
static inline uint64_t sqlite_probe_source_view(uint64_t needleidx);
static inline void sqlite_probe_prepare(SqliteCarveState *state, uint32_t needleidx);
static inline SqliteGapProbeState *sqlite_gap_probe_begin(
    SqliteCarveState *state, uint64_t key, SqliteGapProbeKind kind, uint32_t needleidx);
static inline bool sqlite_gap_probes_valid(const SqliteCarveState *state);
static inline bool sqlite_pair_probes_valid(const SqliteCarveState *state);
static inline bool sqlite_page_completions_valid(const SqliteCarveState *state);
static inline bool sqlite_permutations_valid(const SqliteCarveState *state);
static inline bool sqlite_transition_rankings_valid(const SqliteCarveState *state);
static inline bool sqlite_transition_scans_valid(const SqliteCarveState *state);
static inline bool sqlite_radius_rankings_valid(const SqliteCarveState *state);
static inline bool sqlite_multi_regions_valid(const SqliteCarveState *state);
static inline SqliteMultiRegionState *sqlite_multi_region_begin(
    SqliteCarveState *state, uint64_t key, const SqliteIntegrity *baseline,
    uint32_t needleidx);
static inline SqliteRepairResult sqlite_compose_multi_region(
    ThreadWork *work, CarveInfo **candidate, uuid_string_t uuidp, uuid_string_t uuidc,
    const SqliteLayout *layout, const SqliteIntegrity *baseline,
    const int64_t *two_gap_mapping, uint64_t total_blocks,
    const SqliteRepairDescriptor *second_gap, uint64_t second_transition,
    uint64_t transition_count, const uint64_t *boundaries, const uint64_t *widths,
    const bool *zero_backed, uint8_t *trial_data, int64_t *trial_mapping,
    int64_t *current_mapping, int64_t *solution_mapping, SqliteIntegrity *final_result,
    SqliteCarveState *state,
    uint64_t *iterations);
static inline SqliteRadiusState *sqlite_radius_begin(
    SqliteCarveState *state, uint64_t key, uint64_t boundary, uint64_t width,
    uint64_t radius, const SqliteIntegrity *baseline, uint32_t needleidx);
static inline SqliteRepairResult sqlite_rank_radius_targets(
    ThreadWork *work, CarveInfo **candidate, uuid_string_t uuidp, uuid_string_t uuidc,
    const SqliteLayout *layout, const int64_t *base_mapping, uint64_t total_blocks,
    uint64_t boundary, uint64_t width, uint64_t support, const SqliteIntegrity *baseline,
    bool compose, uint8_t *trial_data, int64_t *trial_mapping, SqliteCarveState *state,
    uint64_t *iterations, SqliteRadiusProgress **ranking);
static inline SqliteTransitionScanState *sqlite_transition_scan_begin(
    SqliteCarveState *state, uint64_t key, uint64_t page_blocks, uint32_t needleidx);
static inline SqliteRepairResult sqlite_scan_repaired_transitions(
    ThreadWork *work, CarveInfo **candidate, uuid_string_t uuidp, uuid_string_t uuidc,
    const SqliteLayout *layout, const int64_t *mapping, uint64_t total_blocks,
    SqliteCarveState *state, uint64_t *iterations, SqliteTransitionScanProgress **scan);
static inline SqliteTransitionRankingState *sqlite_transition_ranking_begin(
    SqliteCarveState *state, uint64_t key, uint64_t first_target,
    uint64_t last_target, uint64_t width, uint32_t needleidx);
static inline SqliteRepairResult sqlite_rank_transition_targets(
    ThreadWork *work, CarveInfo **candidate, uuid_string_t uuidp, uuid_string_t uuidc,
    const SqliteLayout *layout, const int64_t *base_mapping, uint64_t total_blocks,
    uint64_t first_target, uint64_t last_target, uint64_t width,
    const SqliteIntegrity *baseline, uint64_t baseline_evidence,
    uint8_t *trial_data, int64_t *trial_mapping, SqliteCarveState *state,
    uint64_t *iterations, SqliteTransitionRankingProgress **ranking);
static inline SqlitePermutationState *sqlite_permutation_begin(
    SqliteCarveState *state, uint64_t key, uint64_t target_count, uint32_t needleidx);
static inline void sqlite_permutation_mapping(const int64_t *base, uint64_t blocks,
    const uint64_t *targets, const uint64_t *widths, uint64_t target_count,
    const uint8_t *order, int64_t *mapping);
static inline SqliteRepairResult sqlite_preserve_permutations(
    ThreadWork *work, CarveInfo **candidate, uuid_string_t uuidp, uuid_string_t uuidc,
    const SqliteLayout *layout, const int64_t *base_mapping, uint64_t total_blocks,
    const uint64_t *targets, const uint64_t *widths, uint64_t target_count,
    uint8_t *trial_data, int64_t *trial_mapping, SqliteCarveState *state,
    uint64_t *iterations);
static inline SqlitePageCompletionState *sqlite_page_completion_begin(
    SqliteCarveState *state, uint64_t key, uint64_t target_count, uint32_t needleidx);
static inline SqlitePairProbeState *sqlite_pair_probe_begin(
    SqliteCarveState *state, uint64_t key, uint32_t needleidx);
static inline SqliteOooProbeState *sqlite_ooo_probe_begin(
    SqliteCarveState *state, uint64_t key, uint32_t needleidx);
static inline bool sqlite_probe_source_reserved(
    const SqliteCarveState *state, uint64_t source, uint64_t width);
static inline bool sqlite_probe_copy_repairs(
    const SqliteOooProbeState *probe, SqliteRepairList *list);
static inline bool sqlite_probe_add_repair(
    SqliteOooProbeState *probe, const SqliteRepairDescriptor *repair);
static inline bool sqlite_probe_repair_valid(
    const SqliteRepairDescriptor *repair, const SqliteCarveState *state);
static inline void sqlite_probe_apply_repair(
    const int64_t *base, uint64_t blocks,
    const SqliteRepairDescriptor *repair, int64_t *mapping);
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
static inline bool sqlite_integrity_flag_valid(const SqliteIntegrity *integrity);
static inline bool sqlite_carve_state_valid(const SqliteCarveState *state);
static inline bool sqlite_integrity_flag_valid(const SqliteIntegrity *integrity) {
  const bool valid_values[] = {false, true};
  // Check checkpoint bytes before evaluating a possibly invalid bool representation.
  return memcmp(&integrity->valid, &valid_values[0], sizeof(integrity->valid)) == 0
      || memcmp(&integrity->valid, &valid_values[1], sizeof(integrity->valid)) == 0;
}

static inline bool sqlite_extension_state_valid(
    const SqliteOooExtensionState *extension, const SqliteCarveState *state);
static inline bool sqlite_gap_grid_state_valid(
    const SqliteGapGridState *grid, const SqliteCarveState *state);
static inline uint64_t sqlite_gap_grid_view(
    const SqliteLayout *layout, const SqliteIntegrity *baseline,
    const int64_t *base_mapping, uint64_t total_blocks,
    uint64_t maximum_width);
static inline uint64_t sqlite_extension_view(
    const SqliteLayout *layout, const int64_t *base_mapping,
    uint64_t total_blocks, uint64_t preferred_target, bool preferred_only,
    uint64_t maximum_width, const SqliteRepairDescriptor *repair);
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
    bool *ambiguity_closed, SqliteOooExtensionState *progress);
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

static inline bool sqlite_extension_state_valid(
    const SqliteOooExtensionState *extension, const SqliteCarveState *state) {
  if (!extension->active) {
    return true;
  }
  if (extension->active != 1 || extension->owner_stage != state->stage
      || extension->direction > 2 || extension->closed > 3
      || extension->next_extension == 0
      || extension->next_extension > SQLITE_FAST_PROBE_MAXIMUM_RUN_BLOCKS + 1
      || extension->next_gap_target > state->total_blocks
      || (extension->next_gap_target != 0
          && (state->stage != SQLITE_SEARCH_RANKED_GAP_OOO
              || extension->direction != 2 || extension->closed != 3))) {
    return false;
  }
  const SqliteRepairDescriptor *repairs[] = {
      &extension->repair, &extension->last};
  for (size_t index = 0; index < sizeof(repairs) / sizeof(repairs[0]); index++) {
    const SqliteRepairDescriptor *repair = repairs[index];
    if (!repair->valid || (index == 0 && repair->target == 0)
        || repair->target >= state->total_blocks || repair->width == 0
        || repair->width > state->total_blocks - repair->target
        || repair->source >= state->apparent_blocks
        || repair->width > state->apparent_blocks - repair->source) {
      return false;
    }
  }
  const SqliteRepairDescriptor *root = &extension->repair;
  const SqliteRepairDescriptor *last = &extension->last;
  if (last->width < root->width
      || last->width - root->width > SQLITE_FAST_PROBE_MAXIMUM_RUN_BLOCKS) {
    return false;
  }
  const uint64_t extra = last->width - root->width;
  return (last->target == root->target && last->source == root->source)
      || (extra <= root->target && extra <= root->source
          && last->target == root->target - extra
          && last->source == root->source - extra);
}

// Retain the refinement window chosen from the completed coarse samples. Its best location may
// improve during refinement; recalculating the window after a checkpoint would change the search.
static inline bool sqlite_gap_grid_state_valid(
    const SqliteGapGridState *grid, const SqliteCarveState *state) {
  if (!sqlite_integrity_flag_valid(&grid->width_integrity)) {
    return false;
  }
  if (!grid->active) {
    return true;
  }
  if (grid->active != 1 || state->stage != SQLITE_SEARCH_INITIAL_PROBES
      || state->probe_step != 3 || state->total_blocks < 2
      || grid->width == 0
      || grid->width > SQLITE_FAST_PROBE_MAXIMUM_GAP_BLOCKS
      || grid->width >= state->apparent_blocks
      || grid->phase > 1 || grid->window_ready > 1) {
    return false;
  }
  if (grid->window_ready
      && (grid->next_target == 0 || grid->last_target == 0
          || grid->last_target >= state->total_blocks
          || grid->next_target > grid->last_target + 1
          || grid->step == 0 || grid->step >= state->total_blocks
          || (grid->phase == 1 && grid->step != 1))) {
    return false;
  }
  return !grid->width_best.valid
      || (grid->width_best.target > 0
          && grid->width_best.target < state->total_blocks
          && grid->width_best.width == grid->width);
}

static inline bool sqlite_probe_repair_valid(
    const SqliteRepairDescriptor *repair, const SqliteCarveState *state) {
  return repair->valid == 0
      || (repair->valid == 1 && repair->reserved <= 1
          && repair->target < state->total_blocks && repair->width > 0
          && repair->width <= state->total_blocks - repair->target
          && repair->source < state->apparent_blocks
          && repair->width <= state->apparent_blocks - repair->source);
}

static inline bool sqlite_ooo_probes_valid(const SqliteCarveState *state) {
  if (state->reservation_bytes > SIZE_MAX
      || (state->reservation_bytes == 0) != (state->probe_reservations == NULL)
      || (state->probe_reservations
          && (state->reservation_bytes != roaring64_bitmap_portable_size_in_bytes(
                  state->probe_reservations)
              || (!roaring64_bitmap_is_empty(state->probe_reservations)
                  && roaring64_bitmap_maximum(state->probe_reservations)
                         >= state->apparent_blocks)))) {
    return false;
  }
  uint64_t count = 0;
  for (const SqliteOooProbeState *probe = state->ooo_probes;
       probe; probe = probe->next) {
    const SqliteOooProbeProgress *p = &probe->progress;
    if (count++ >= state->probe_count
        || !sqlite_integrity_flag_valid(&p->best_integrity)
        || p->confidence_pass > 7 || p->reservation_pass > 2
        || p->width_pass == 0
        || p->width_pass > SQLITE_FAST_PROBE_MAXIMUM_RUN_BLOCKS + 1
        || p->target_rank > state->total_blocks
        || p->source_rank > state->apparent_blocks
        || p->scan_complete > 1 || p->preserved_clean > 1
        || p->preserved_bounded > 1 || p->preserved_necessary > 1
        || p->extending > 1 || p->key_match > 1 || p->initialized != 1
        || p->repair_count > SIZE_MAX / sizeof(*probe->repairs)
        || (p->repair_count != 0 && !probe->repairs)
        || !sqlite_probe_repair_valid(&p->composition, state)
        || !sqlite_probe_repair_valid(&p->solution, state)
        || (p->extending
            && (p->extension.direction > 2
                || p->extension.next_extension == 0
                || p->extension.next_extension
                       > SQLITE_FAST_PROBE_MAXIMUM_RUN_BLOCKS + 1
                || p->extension.closed > 3
                || !p->extension.repair.valid
                || !p->extension.last.valid
                || !sqlite_probe_repair_valid(&p->extension.repair, state)
                || !sqlite_probe_repair_valid(&p->extension.last, state)))) {
      return false;
    }
    for (uint64_t index = 0; index < p->repair_count; index++) {
      if (!probe->repairs[index].valid
          || !sqlite_probe_repair_valid(&probe->repairs[index], state)) {
        return false;
      }
    }
  }
  return count == state->probe_count;
}

static inline void sqlite_clear_ooo_probes(SqliteCarveState *state) {
  SqliteOooProbeState *probe = state->ooo_probes;
  while (probe) {
    SqliteOooProbeState *next = probe->next;
    free(probe->repairs);
    free(probe);
    probe = next;
  }
  state->ooo_probes = NULL;
  state->probe_count = 0;
  SqliteGapProbeState *gap = state->gap_probes;
  while (gap) {
    SqliteGapProbeState *next = gap->next;
    free(gap);
    gap = next;
  }
  state->gap_probes = NULL;
  state->gap_probe_count = 0;
  SqlitePairProbeState *pair = state->pair_probes;
  while (pair) {
    SqlitePairProbeState *next = pair->next;
    free(pair);
    pair = next;
  }
  state->pair_probes = NULL;
  state->pair_probe_count = 0;
  SqlitePageCompletionState *completion = state->page_completions;
  while (completion) {
    SqlitePageCompletionState *next = completion->next;
    free(completion);
    completion = next;
  }
  state->page_completions = NULL;
  state->page_completion_count = 0;
  SqlitePermutationState *permutation = state->permutations;
  while (permutation) {
    SqlitePermutationState *next = permutation->next;
    free(permutation);
    permutation = next;
  }
  state->permutations = NULL;
  state->permutation_count = 0;
  SqliteTransitionRankingState *ranking = state->transition_rankings;
  while (ranking) {
    SqliteTransitionRankingState *next = ranking->next;
    free(ranking);
    ranking = next;
  }
  state->transition_rankings = NULL;
  state->transition_ranking_count = 0;
  SqliteTransitionScanState *scan = state->transition_scans;
  while (scan) {
    SqliteTransitionScanState *next = scan->next;
    free(scan);
    scan = next;
  }
  state->transition_scans = NULL;
  state->transition_scan_count = 0;
  SqliteRadiusState *radius = state->radius_rankings;
  while (radius) {
    SqliteRadiusState *next = radius->next;
    free(radius);
    radius = next;
  }
  state->radius_rankings = NULL;
  state->radius_count = 0;
  SqliteMultiRegionState *multi = state->multi_regions;
  while (multi) {
    SqliteMultiRegionState *next = multi->next;
    free(multi);
    multi = next;
  }
  state->multi_regions = NULL;
  state->multi_region_count = 0;
  if (state->probe_reservations) {
    roaring64_bitmap_free(state->probe_reservations);
  }
  state->probe_reservations = NULL;
  state->reservation_bytes = 0;
}

static inline bool sqlite_gap_probes_valid(const SqliteCarveState *state) {
  uint64_t count = 0;
  for (const SqliteGapProbeState *probe = state->gap_probes; probe; probe = probe->next) {
    const SqliteGapProbeProgress *p = &probe->progress;
    if (count++ >= state->gap_probe_count || p->kind > SQLITE_GAP_PROBE_ALTERNATIVES
        || !sqlite_integrity_flag_valid(&p->best_integrity)
        || p->initialized != 1 || p->scan_complete > 1 || p->matched > 1
        || p->next_target == 0 || p->next_target > state->total_blocks
        || p->next_width == 0 || p->next_width > SQLITE_FAST_PROBE_MAXIMUM_GAP_BLOCKS + 1
        || p->preserved > state->total_blocks
        || (p->best_gap.valid
            && (p->best_gap.valid != 1 || p->best_gap.target == 0
                || p->best_gap.target >= state->total_blocks || p->best_gap.width == 0
                || p->best_gap.width >= state->apparent_blocks))
        || (p->matched && (!p->scan_complete || !p->best_gap.valid))) {
      return false;
    }
  }
  return count == state->gap_probe_count;
}

static inline bool sqlite_pair_probes_valid(const SqliteCarveState *state) {
  uint64_t count = 0;
  for (const SqlitePairProbeState *probe = state->pair_probes; probe; probe = probe->next) {
    const SqlitePairProbeProgress *p = &probe->progress;
    if (count++ >= state->pair_probe_count || p->class_pair > 4
        || p->diagonal > 2 * SQLITE_COMPOSED_REPAIR_PROBE_LIMIT - 1
        || p->first_rank > SQLITE_COMPOSED_REPAIR_PROBE_LIMIT
        || p->preserved > SQLITE_COMPOSED_HYPOTHESIS_LIMIT || p->scan_complete > 1
        || (p->class_pair == 4 && !p->scan_complete)
        || (p->preserved == SQLITE_COMPOSED_HYPOTHESIS_LIMIT && !p->scan_complete)
        || (p->scan_complete && p->class_pair != 4
            && p->preserved != SQLITE_COMPOSED_HYPOTHESIS_LIMIT)) {
      return false;
    }
    for (uint32_t slot = 0; slot < 2; slot++) {
      const uint64_t unreserved = p->class_counts[slot][0];
      const uint64_t reserved = p->class_counts[slot][1];
      if (unreserved > SQLITE_COMPOSED_REPAIR_PROBE_LIMIT
          || reserved > SQLITE_COMPOSED_REPAIR_PROBE_LIMIT
          || unreserved + reserved == 0) {
        return false;
      }
    }
    if (p->class_pair == 4) {
      if (p->diagonal != 0 || p->first_rank != 0) {
        return false;
      }
    }
    else {
      const uint64_t first_count = p->class_counts[0][p->class_pair / 2];
      const uint64_t second_count = p->class_counts[1][p->class_pair % 2];
      if (first_count == 0 || second_count == 0
          || p->diagonal > first_count + second_count - 2) {
        return false;
      }
      const uint64_t first_begin = p->diagonal >= second_count
          ? p->diagonal - (second_count - 1) : 0;
      const uint64_t first_end = p->diagonal < first_count
          ? p->diagonal : first_count - 1;
      if (p->first_rank < first_begin || p->first_rank > first_end + 1) {
        return false;
      }
    }
  }
  return count == state->pair_probe_count;
}

static inline bool sqlite_page_completions_valid(const SqliteCarveState *state) {
  uint64_t count = 0;
  for (const SqlitePageCompletionState *entry = state->page_completions;
       entry; entry = entry->next) {
    const SqlitePageCompletionProgress *p = &entry->progress;
    if (count++ >= state->page_completion_count
        || p->target_count > UINT64_MAX / 2 || p->repair > p->target_count
        || p->anchor > 2 || p->attempted_count > SQLITE_PAGE_TRANSITION_LIMIT * 2
        || p->preserved > p->target_count * 2 || p->complete > 1
        || (p->repair == p->target_count && p->anchor != 0)
        || (p->complete && (p->repair != p->target_count || p->anchor != 0))) {
      return false;
    }
    for (uint64_t index = 0; index < p->attempted_count; index++) {
      if (p->attempted_targets[index] >= state->total_blocks
          || p->attempted_sources[index] >= state->apparent_blocks) {
        return false;
      }
    }
  }
  return count == state->page_completion_count;
}

static inline bool sqlite_permutations_valid(const SqliteCarveState *state) {
  uint64_t count = 0;
  for (const SqlitePermutationState *entry = state->permutations;
       entry; entry = entry->next) {
    const SqlitePermutationProgress *p = &entry->progress;
    if (count++ >= state->permutation_count || p->target_count < 2
        || p->target_count > SQLITE_PAGE_TRANSITION_LIMIT || p->count == 0
        || p->count > SQLITE_COMPOSED_REPAIR_PROBE_LIMIT || p->permutation > p->count
        || p->left > p->target_count || p->right <= p->left
        || p->right > p->target_count + 1 || p->complete > 1
        || (p->complete && p->permutation < p->count
            && p->count < SQLITE_COMPOSED_REPAIR_PROBE_LIMIT)
        || (p->permutation == p->count && (p->left != 0 || p->right != 1))) {
      return false;
    }
    for (uint64_t permutation = 0; permutation < p->count; permutation++) {
      uint32_t used = 0;
      for (uint64_t slot = 0; slot < p->target_count; slot++) {
        const uint8_t source = p->order[permutation][slot];
        if (source >= p->target_count || (used & (UINT32_C(1) << source))) {
          return false;
        }
        used |= UINT32_C(1) << source;
      }
    }
  }
  return count == state->permutation_count;
}

static inline bool sqlite_transition_rankings_valid(const SqliteCarveState *state) {
  uint64_t count = 0;
  for (const SqliteTransitionRankingState *entry = state->transition_rankings;
       entry; entry = entry->next) {
    const SqliteTransitionRankingProgress *p = &entry->progress;
    if (count++ >= state->transition_ranking_count || p->first_target == 0
        || p->first_target > p->last_target || p->last_target >= state->total_blocks
        || p->width == 0 || p->width >= state->apparent_blocks
        || p->next_target < p->first_target || p->next_target > p->last_target + 1
        || p->usable > 1 || p->clean > 1 || p->zero_backed > 1 || p->complete > 1
        || !sqlite_integrity_flag_valid(&p->best_integrity)
        || (bool)p->clean != p->best_integrity.valid
        || (p->clean && (p->best_integrity.error_count != 0
                        || p->best_integrity.result_code != SQLITE_OK))
        || (p->complete && p->next_target != p->last_target + 1)
        || (p->usable && (p->best_target < p->first_target
                         || p->best_target >= p->next_target))
        || (!p->usable && (p->best_target != 0 || p->clean || p->zero_backed))) {
      return false;
    }
  }
  return count == state->transition_ranking_count;
}

// Check retained scan cursors before they can index a restored candidate or transition table.
static inline bool sqlite_transition_scans_valid(const SqliteCarveState *state) {
  uint64_t count = 0;
  for (const SqliteTransitionScanState *entry = state->transition_scans;
       entry; entry = entry->next) {
    const SqliteTransitionScanProgress *p = &entry->progress;
    if (count++ >= state->transition_scan_count || p->page_blocks == 0
        || p->page_blocks > state->total_blocks || p->boundary == 0
        || p->boundary > state->total_blocks || p->left_support >= p->boundary
        || p->phase > SQLITE_TRANSITION_SCAN_COMPLETE
        || p->count > SQLITE_PAGE_TRANSITION_LIMIT) {
      return false;
    }
    if (p->phase == SQLITE_TRANSITION_SCAN_PAGES) {
      if (p->boundary % p->page_blocks != 0
          || p->left_support >= p->boundary / p->page_blocks
          || p->width != 0 || p->right_support != 0) {
        return false;
      }
    }
    else if (p->phase == SQLITE_TRANSITION_SCAN_COMPLETE) {
      if (p->boundary != state->total_blocks || p->left_support != 0
          || p->width != 0 || p->right_support != 0) {
        return false;
      }
    }
    else {
      if (p->page_blocks != 1
          || (p->phase != SQLITE_TRANSITION_SCAN_BLOCK_POLL
              && p->boundary == state->total_blocks)) {
        return false;
      }
      if (p->phase == SQLITE_TRANSITION_SCAN_RIGHT) {
        if (p->left_support == 0 || p->width == 0
            || p->width > SQLITE_FAST_PROBE_MAXIMUM_RUN_BLOCKS
            || p->width >= state->total_blocks - p->boundary
            || p->right_support > state->total_blocks - p->boundary - p->width) {
          return false;
        }
      }
      else if (p->width != 0 || p->right_support != 0) {
        return false;
      }
    }
    for (uint64_t slot = 0; slot < p->count; slot++) {
      if (p->boundaries[slot] == 0 || p->boundaries[slot] >= state->total_blocks
          || p->widths[slot] == 0
          || p->widths[slot] > SQLITE_FAST_PROBE_MAXIMUM_RUN_BLOCKS
          || p->widths[slot] > state->total_blocks - p->boundaries[slot]
          || p->gap_targets[slot] != p->boundaries[slot]
          || p->support[slot] > state->total_blocks
          || p->zero_backed[slot] != 0 || p->page_aligned[slot] > 1
          || (p->page_aligned[slot]
              && (slot != 0 || p->widths[slot] != 1
                  || p->boundaries[slot] % p->page_blocks != 0
                  || p->page_blocks > state->total_blocks - p->boundaries[slot]))
          || (!p->page_aligned[slot] && p->page_blocks != 1)) {
        return false;
      }
      for (uint64_t prior = 0; prior < slot; prior++) {
        if (p->boundaries[prior] == p->boundaries[slot]
            && p->widths[prior] == p->widths[slot]) {
          return false;
        }
      }
    }
  }
  return count == state->transition_scan_count;
}

// Radius trials run center, +1, -1, +2, -2; retain the winner until its child search finishes.
static inline bool sqlite_radius_rankings_valid(const SqliteCarveState *state) {
  uint64_t count = 0;
  for (const SqliteRadiusState *entry = state->radius_rankings; entry; entry = entry->next) {
    const SqliteRadiusProgress *p = &entry->progress;
    if (count++ >= state->radius_count || p->boundary == 0
        || p->boundary >= state->total_blocks || p->width == 0
        || p->width >= state->apparent_blocks
        || (p->radius != 0 && p->radius != SQLITE_GAP_GRID_SAMPLES)
        || p->next_trial > p->radius * 2 + 1
        || p->improved > 1 || p->matched > 1 || p->complete > 1
        || !sqlite_integrity_flag_valid(&p->best_integrity)
        || (p->improved && !p->matched && p->best_integrity.valid)
        || (p->matched && (!p->complete || !p->best_integrity.valid
                          || p->best_integrity.error_count != 0
                          || p->best_integrity.result_code != SQLITE_OK))
        || (p->complete && !p->matched && p->next_trial != p->radius * 2 + 1)
        || p->best_gap.valid != (p->matched || p->improved)) {
      return false;
    }
    if (p->best_gap.valid) {
      const uint64_t target = p->best_gap.target;
      const uint64_t distance = target >= p->boundary
          ? target - p->boundary : p->boundary - target;
      if (target == 0 || target >= state->total_blocks || distance > p->radius
          || p->best_gap.width != p->width || p->best_gap.source != 0
          || p->best_gap.reserved != 0) {
        return false;
      }
      const uint64_t trial = distance == 0 ? 0
          : 2 * distance - (target > p->boundary ? 1 : 0);
      if (trial >= p->next_trial || (p->matched && trial != p->next_trial - 1)) {
        return false;
      }
    }
  }
  return count == state->radius_count;
}

// A repair chain is bounded by the existing pass limit. Cursors refer to one completed child list.
static inline bool sqlite_multi_regions_valid(const SqliteCarveState *state) {
  uint64_t count = 0;
  for (const SqliteMultiRegionState *entry = state->multi_regions; entry; entry = entry->next) {
    const SqliteMultiRegionProgress *p = &entry->progress;
    if (count++ >= state->multi_region_count
        || p->chain_count > SQLITE_PAGE_TRANSITION_LIMIT
        || p->transition > SQLITE_PAGE_TRANSITION_LIMIT * 2 + 1
        || p->repair_count > SQLITE_COMPOSED_REPAIR_PROBE_LIMIT * 2
        || p->next_repair > p->repair_count
        || p->repaired_mask >= (UINT32_C(1) << SQLITE_PAGE_TRANSITION_LIMIT)
        || p->multi_region_valid > 1 || p->transition_active > 1
        || p->list_ready > 1 || p->complete > 1
        || !sqlite_integrity_flag_valid(&p->current_integrity)
        || !sqlite_integrity_flag_valid(&p->next_integrity)
        || !sqlite_integrity_flag_valid(&p->final_integrity)
        || !sqlite_probe_repair_valid(&p->best, state)
        || (p->best.valid && (p->best.target == 0 || !p->list_ready
                            || p->next_repair == 0
                            || (!p->next_integrity.valid
                                && !sqlite_integrity_composition_better(
                                    &p->next_integrity, &p->current_integrity))))
        || (p->list_ready && !p->transition_active)
        || (!p->list_ready && (p->next_repair != 0 || p->repair_count != 0
                              || p->repair_hash != 0))
        || (!p->complete && p->chain_count == SQLITE_PAGE_TRANSITION_LIMIT)
        || (p->complete && (p->transition_active || p->list_ready || p->best.valid))
        || (!p->complete && p->multi_region_valid
            && !p->current_integrity.valid && !p->next_integrity.valid)) {
      return false;
    }
    for (uint64_t slot = 0; slot < p->chain_count; slot++) {
      if (!p->chain[slot].valid || p->chain[slot].target == 0
          || !sqlite_probe_repair_valid(&p->chain[slot], state)) {
        return false;
      }
    }
  }
  return count == state->multi_region_count;
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
      || state->outer_cursor.pass > state->total_blocks
      || !sqlite_integrity_flag_valid(&state->baseline_integrity)
      || !sqlite_integrity_flag_valid(&state->best_gap_integrity)
      || !sqlite_integrity_flag_valid(&state->best_ooo_integrity)
      || !sqlite_extension_state_valid(&state->extension, state)
      || !sqlite_gap_grid_state_valid(&state->gap_grid, state)
      || !sqlite_ooo_probes_valid(state)
      || !sqlite_gap_probes_valid(state)
      || !sqlite_pair_probes_valid(state)
      || !sqlite_page_completions_valid(state)
      || !sqlite_permutations_valid(state)
      || !sqlite_transition_rankings_valid(state)
      || !sqlite_transition_scans_valid(state)
      || !sqlite_radius_rankings_valid(state)
      || !sqlite_multi_regions_valid(state)) {
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

static inline bool sqlite_probe_reservations_io(
    SqliteCarveState *state, FILE *fp, StateSerialization mode, bool dense) {
  const uint64_t size = state->reservation_bytes;
  if (size == 0) {
    return true;
  }
  if (size > SIZE_MAX || state->apparent_blocks > (UINT64_MAX - 1024) / 32
      || size > state->apparent_blocks * 32 + 1024
      || (dense && size != state->apparent_blocks / 8
                             + (state->apparent_blocks % 8 != 0))) {
    return false;
  }
  char *bytes = (char *)malloc((size_t)size);
  check_memory_allocation(bytes, __LINE__, __FILE__, "SQLite reservation checkpoint");
  bool valid;
  if (mode == SERIALIZE) {
    valid = roaring64_bitmap_portable_serialize(state->probe_reservations, bytes) == size
        && fwrite(bytes, (size_t)size, 1, fp) == 1;
  }
  else {
    valid = fread(bytes, (size_t)size, 1, fp) == 1;
    if (valid && dense) {
      state->probe_reservations = roaring64_bitmap_create();
      check_memory_allocation(state->probe_reservations, __LINE__, __FILE__,
                              "SQLite legacy reservation order");
      for (uint64_t block = 0; block < state->apparent_blocks; block++) {
        if (((uint8_t)bytes[block / 8] & (1U << (block % 8))) != 0) {
          roaring64_bitmap_add(state->probe_reservations, block);
        }
      }
      roaring64_bitmap_run_optimize(state->probe_reservations);
      state->reservation_bytes =
          roaring64_bitmap_portable_size_in_bytes(state->probe_reservations);
    }
    else if (valid) {
      state->probe_reservations = roaring64_bitmap_portable_deserialize_safe(
          bytes, (size_t)size);
      valid = state->probe_reservations
          && roaring64_bitmap_internal_validate(state->probe_reservations, NULL)
          && (roaring64_bitmap_is_empty(state->probe_reservations)
              || roaring64_bitmap_maximum(state->probe_reservations)
                     < state->apparent_blocks);
    }
  }
  free(bytes);
  return valid;
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
    SqliteCarveState *saved = *sqlite_state;
    if (fwrite(saved, offsetof(SqliteCarveState, probe_reservations), 1, fp) != 1
        || !sqlite_probe_reservations_io(saved, fp, mode, false)) {
      perror("SQLite carve state serialization");
      handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
    }
    for (const SqliteOooProbeState *probe = saved->ooo_probes;
         probe; probe = probe->next) {
      if (fwrite(&probe->progress, sizeof(probe->progress), 1, fp) != 1
          || (probe->progress.repair_count != 0
              && fwrite(probe->repairs, sizeof(*probe->repairs),
                        probe->progress.repair_count, fp)
                     != probe->progress.repair_count)) {
        handle_error(SCALPEL_ERROR_CHECKPOINT, "SQLite probe serialization",
                     __LINE__, __FILE__);
      }
    }
    for (const SqliteGapProbeState *probe = saved->gap_probes; probe; probe = probe->next) {
      if (fwrite(&probe->progress, sizeof(probe->progress), 1, fp) != 1) {
        handle_error(SCALPEL_ERROR_CHECKPOINT, "SQLite gap probe serialization",
                     __LINE__, __FILE__);
      }
    }
    for (const SqlitePairProbeState *probe = saved->pair_probes; probe; probe = probe->next) {
      if (fwrite(&probe->progress, sizeof(probe->progress), 1, fp) != 1) {
        handle_error(SCALPEL_ERROR_CHECKPOINT, "SQLite pair probe serialization",
                     __LINE__, __FILE__);
      }
    }
    for (const SqlitePageCompletionState *entry = saved->page_completions;
         entry; entry = entry->next) {
      if (fwrite(&entry->progress, sizeof(entry->progress), 1, fp) != 1) {
        handle_error(SCALPEL_ERROR_CHECKPOINT, "SQLite page completion serialization",
                     __LINE__, __FILE__);
      }
    }
    for (const SqlitePermutationState *entry = saved->permutations;
         entry; entry = entry->next) {
      if (fwrite(&entry->progress, sizeof(entry->progress), 1, fp) != 1) {
        handle_error(SCALPEL_ERROR_CHECKPOINT, "SQLite permutation serialization",
                     __LINE__, __FILE__);
      }
    }
    for (const SqliteTransitionRankingState *entry = saved->transition_rankings;
         entry; entry = entry->next) {
      if (fwrite(&entry->progress, sizeof(entry->progress), 1, fp) != 1) {
        handle_error(SCALPEL_ERROR_CHECKPOINT, "SQLite transition ranking serialization",
                     __LINE__, __FILE__);
      }
    }
    for (const SqliteTransitionScanState *entry = saved->transition_scans;
         entry; entry = entry->next) {
      if (fwrite(&entry->progress, sizeof(entry->progress), 1, fp) != 1) {
        handle_error(SCALPEL_ERROR_CHECKPOINT, "SQLite transition scan serialization",
                     __LINE__, __FILE__);
      }
    }
    for (const SqliteRadiusState *entry = saved->radius_rankings; entry; entry = entry->next) {
      if (fwrite(&entry->progress, sizeof(entry->progress), 1, fp) != 1) {
        handle_error(SCALPEL_ERROR_CHECKPOINT, "SQLite radius serialization",
                     __LINE__, __FILE__);
      }
    }
    for (const SqliteMultiRegionState *entry = saved->multi_regions; entry; entry = entry->next) {
      if (fwrite(&entry->progress, sizeof(entry->progress), 1, fp) != 1) {
        handle_error(SCALPEL_ERROR_CHECKPOINT, "SQLite multi-region serialization",
                     __LINE__, __FILE__);
      }
    }
    return true;
  }

  SqliteCarveState *restored =
      (SqliteCarveState *)calloc(1, sizeof(*restored));
  check_memory_allocation(restored, __LINE__, __FILE__,
                          "SQLite carve state");
  const size_t prefix_size = offsetof(SqliteCarveState, stage);
  if (fread(restored, prefix_size, 1, fp) != 1
      || restored->magic != SQLITE_CARVE_STATE_MAGIC
      || (restored->version != SQLITE_CARVE_STATE_VERSION
          && restored->version != UINT32_C(23)
          && restored->version != UINT32_C(22)
          && restored->version != UINT32_C(21)
          && restored->version != UINT32_C(20)
          && restored->version != UINT32_C(19)
          && restored->version != UINT32_C(18)
          && restored->version != UINT32_C(17)
          && restored->version != UINT32_C(16)
          && restored->version != UINT32_C(15)
          && restored->version != UINT32_C(14)
          && restored->version != UINT32_C(13)
          && restored->version != UINT32_C(12)
          && (restored->version < UINT32_C(6)
              || restored->version > UINT32_C(9)))) {
    free(restored);
    handle_error(SCALPEL_ERROR_CHECKPOINT, "invalid SQLite carve state",
                 __LINE__, __FILE__);
  }
  const uint32_t saved_version = restored->version;
  const size_t record_size = restored->version >= UINT32_C(24)
      ? offsetof(SqliteCarveState, probe_reservations)
      : restored->version == UINT32_C(23)
          ? offsetof(SqliteCarveState, multi_region_count)
      : restored->version == UINT32_C(22)
          ? offsetof(SqliteCarveState, radius_count)
      : restored->version == UINT32_C(21)
          ? offsetof(SqliteCarveState, transition_scan_count)
      : restored->version == UINT32_C(20)
          ? offsetof(SqliteCarveState, transition_ranking_count)
      : restored->version == UINT32_C(19)
          ? offsetof(SqliteCarveState, permutation_count)
      : restored->version == UINT32_C(18)
          ? offsetof(SqliteCarveState, page_completion_count)
      : restored->version == UINT32_C(17)
          ? offsetof(SqliteCarveState, pair_probe_count)
      : restored->version >= UINT32_C(15)
          ? offsetof(SqliteCarveState, gap_probe_count)
      : restored->version == UINT32_C(14)
          ? offsetof(SqliteCarveState, probe_owner)
      : restored->version == UINT32_C(13)
          ? offsetof(SqliteCarveState, gap_grid)
          : offsetof(SqliteCarveState, extension);
  if (fread((uint8_t *)restored + prefix_size,
            record_size - prefix_size, 1, fp) != 1) {
    free(restored);
    handle_error(SCALPEL_ERROR_CHECKPOINT, "invalid SQLite carve state",
                 __LINE__, __FILE__);
  }
  if (saved_version >= UINT32_C(15)) {
    if (!sqlite_probe_reservations_io(restored, fp, mode,
                                      saved_version == UINT32_C(15))) {
      sqlite_free_carve_state((void **)&restored);
      handle_error(SCALPEL_ERROR_CHECKPOINT, "invalid SQLite reservation state",
                   __LINE__, __FILE__);
    }
    const uint64_t count = restored->probe_count;
    restored->probe_count = 0;
    SqliteOooProbeState **tail = &restored->ooo_probes;
    for (uint64_t index = 0; index < count; index++) {
      SqliteOooProbeProgress progress;
      if (fread(&progress, sizeof(progress), 1, fp) != 1
          || progress.repair_count > SIZE_MAX / sizeof(SqliteRepairDescriptor)) {
        sqlite_free_carve_state((void **)&restored);
        handle_error(SCALPEL_ERROR_CHECKPOINT, "invalid SQLite probe state",
                     __LINE__, __FILE__);
      }
      *tail = (SqliteOooProbeState *)calloc(1, sizeof(**tail));
      check_memory_allocation(*tail, __LINE__, __FILE__, "SQLite probe state");
      (*tail)->progress = progress;
      restored->probe_count++;
      if (progress.repair_count != 0) {
        (*tail)->repairs = (SqliteRepairDescriptor *)malloc(
            (size_t)progress.repair_count * sizeof(*(*tail)->repairs));
        check_memory_allocation((*tail)->repairs, __LINE__, __FILE__,
                                "SQLite probe repairs");
        if (fread((*tail)->repairs, sizeof(*(*tail)->repairs),
                  progress.repair_count, fp) != progress.repair_count) {
          sqlite_free_carve_state((void **)&restored);
          handle_error(SCALPEL_ERROR_CHECKPOINT, "truncated SQLite probe repairs",
                       __LINE__, __FILE__);
        }
      }
      tail = &(*tail)->next;
    }
    restored->version = SQLITE_CARVE_STATE_VERSION;
  }
  if (saved_version >= UINT32_C(17)) {
    const uint64_t count = restored->gap_probe_count;
    restored->gap_probe_count = 0;
    SqliteGapProbeState **tail = &restored->gap_probes;
    for (uint64_t index = 0; index < count; index++) {
      *tail = (SqliteGapProbeState *)calloc(1, sizeof(**tail));
      check_memory_allocation(*tail, __LINE__, __FILE__, "SQLite gap probe state");
      restored->gap_probe_count++;
      if (fread(&(*tail)->progress, sizeof((*tail)->progress), 1, fp) != 1) {
        sqlite_free_carve_state((void **)&restored);
        handle_error(SCALPEL_ERROR_CHECKPOINT, "truncated SQLite gap probe state",
                     __LINE__, __FILE__);
      }
      tail = &(*tail)->next;
    }
  }
  if (saved_version >= UINT32_C(18)) {
    const uint64_t count = restored->pair_probe_count;
    restored->pair_probe_count = 0;
    SqlitePairProbeState **tail = &restored->pair_probes;
    for (uint64_t index = 0; index < count; index++) {
      *tail = (SqlitePairProbeState *)calloc(1, sizeof(**tail));
      check_memory_allocation(*tail, __LINE__, __FILE__, "SQLite pair probe state");
      restored->pair_probe_count++;
      if (fread(&(*tail)->progress, sizeof((*tail)->progress), 1, fp) != 1) {
        sqlite_free_carve_state((void **)&restored);
        handle_error(SCALPEL_ERROR_CHECKPOINT, "truncated SQLite pair probe state",
                     __LINE__, __FILE__);
      }
      tail = &(*tail)->next;
    }
  }
  if (saved_version >= UINT32_C(19)) {
    const uint64_t count = restored->page_completion_count;
    restored->page_completion_count = 0;
    SqlitePageCompletionState **tail = &restored->page_completions;
    for (uint64_t index = 0; index < count; index++) {
      *tail = (SqlitePageCompletionState *)calloc(1, sizeof(**tail));
      check_memory_allocation(*tail, __LINE__, __FILE__, "SQLite page completion state");
      restored->page_completion_count++;
      if (fread(&(*tail)->progress, sizeof((*tail)->progress), 1, fp) != 1) {
        sqlite_free_carve_state((void **)&restored);
        handle_error(SCALPEL_ERROR_CHECKPOINT, "truncated SQLite page completion state",
                     __LINE__, __FILE__);
      }
      tail = &(*tail)->next;
    }
  }
  if (saved_version >= UINT32_C(20)) {
    const uint64_t count = restored->permutation_count;
    restored->permutation_count = 0;
    SqlitePermutationState **tail = &restored->permutations;
    for (uint64_t index = 0; index < count; index++) {
      *tail = (SqlitePermutationState *)calloc(1, sizeof(**tail));
      check_memory_allocation(*tail, __LINE__, __FILE__, "SQLite permutation state");
      restored->permutation_count++;
      if (fread(&(*tail)->progress, sizeof((*tail)->progress), 1, fp) != 1) {
        sqlite_free_carve_state((void **)&restored);
        handle_error(SCALPEL_ERROR_CHECKPOINT, "truncated SQLite permutation state",
                     __LINE__, __FILE__);
      }
      tail = &(*tail)->next;
    }
  }
  if (saved_version >= UINT32_C(21)) {
    const uint64_t count = restored->transition_ranking_count;
    restored->transition_ranking_count = 0;
    SqliteTransitionRankingState **tail = &restored->transition_rankings;
    for (uint64_t index = 0; index < count; index++) {
      *tail = (SqliteTransitionRankingState *)calloc(1, sizeof(**tail));
      check_memory_allocation(*tail, __LINE__, __FILE__, "SQLite transition ranking state");
      restored->transition_ranking_count++;
      if (fread(&(*tail)->progress, sizeof((*tail)->progress), 1, fp) != 1) {
        sqlite_free_carve_state((void **)&restored);
        handle_error(SCALPEL_ERROR_CHECKPOINT, "truncated SQLite transition ranking state",
                     __LINE__, __FILE__);
      }
      tail = &(*tail)->next;
    }
  }
  if (saved_version >= UINT32_C(22)) {
    const uint64_t count = restored->transition_scan_count;
    restored->transition_scan_count = 0;
    SqliteTransitionScanState **tail = &restored->transition_scans;
    for (uint64_t index = 0; index < count; index++) {
      *tail = (SqliteTransitionScanState *)calloc(1, sizeof(**tail));
      check_memory_allocation(*tail, __LINE__, __FILE__, "SQLite transition scan state");
      restored->transition_scan_count++;
      if (fread(&(*tail)->progress, sizeof((*tail)->progress), 1, fp) != 1) {
        sqlite_free_carve_state((void **)&restored);
        handle_error(SCALPEL_ERROR_CHECKPOINT, "truncated SQLite transition scan state",
                     __LINE__, __FILE__);
      }
      tail = &(*tail)->next;
    }
  }
  if (saved_version >= UINT32_C(23)) {
    const uint64_t count = restored->radius_count;
    restored->radius_count = 0;
    SqliteRadiusState **tail = &restored->radius_rankings;
    for (uint64_t index = 0; index < count; index++) {
      *tail = (SqliteRadiusState *)calloc(1, sizeof(**tail));
      check_memory_allocation(*tail, __LINE__, __FILE__, "SQLite radius state");
      restored->radius_count++;
      if (fread(&(*tail)->progress, sizeof((*tail)->progress), 1, fp) != 1) {
        sqlite_free_carve_state((void **)&restored);
        handle_error(SCALPEL_ERROR_CHECKPOINT, "truncated SQLite radius state",
                     __LINE__, __FILE__);
      }
      tail = &(*tail)->next;
    }
  }
  if (saved_version >= UINT32_C(24)) {
    const uint64_t count = restored->multi_region_count;
    restored->multi_region_count = 0;
    SqliteMultiRegionState **tail = &restored->multi_regions;
    for (uint64_t index = 0; index < count; index++) {
      *tail = (SqliteMultiRegionState *)calloc(1, sizeof(**tail));
      check_memory_allocation(*tail, __LINE__, __FILE__, "SQLite multi-region state");
      restored->multi_region_count++;
      if (fread(&(*tail)->progress, sizeof((*tail)->progress), 1, fp) != 1) {
        sqlite_free_carve_state((void **)&restored);
        handle_error(SCALPEL_ERROR_CHECKPOINT, "truncated SQLite multi-region state",
                     __LINE__, __FILE__);
      }
      tail = &(*tail)->next;
    }
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
  if (restored->version == UINT32_C(12)
      || restored->version == UINT32_C(13)) {
    // These versions marked the final preliminary probe complete before doing its work. They did
    // not store its refinement window, so restart that probe rather than skipping its remainder.
    if (restored->stage == SQLITE_SEARCH_INITIAL_PROBES
        && restored->probe_step == 4) {
      restored->probe_step = 3;
      memset(&restored->best_gap, 0, sizeof(restored->best_gap));
      restored->best_gap_integrity = restored->baseline_integrity;
    }
    else if (restored->stage == SQLITE_SEARCH_INITIAL_PROBES
             && restored->probe_step > 0) {
      restored->probe_step--;
    }
    restored->version = SQLITE_CARVE_STATE_VERSION;
  }
  if (saved_version >= UINT32_C(12) && saved_version <= UINT32_C(14)) {
    // These versions advanced markers before finishing nested probes. Their missing cursors cannot
    // be reconstructed, so repeat that one preliminary phase rather than skip unfinished work.
    if (saved_version == UINT32_C(14) && restored->stage == SQLITE_SEARCH_INITIAL_PROBES
        && restored->probe_step > 0 && !restored->gap_grid.active) {
      restored->probe_step--;
    }
    else if (restored->stage == SQLITE_SEARCH_RANKED_GAP_OOO
             && restored->outer_cursor.pass == 1
             && restored->cursor.pass == 0 && restored->cursor.width == 1
             && restored->cursor.source == 0) {
      restored->outer_cursor.pass = 0;
    }
    restored->version = SQLITE_CARVE_STATE_VERSION;
  }
  if (!sqlite_carve_state_valid(restored)) {
    sqlite_free_carve_state((void **)&restored);
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
  clone->ooo_probes = NULL;
  clone->probe_count = 0;
  clone->probe_reservations = NULL;
  clone->gap_probes = NULL;
  clone->gap_probe_count = 0;
  clone->pair_probes = NULL;
  clone->pair_probe_count = 0;
  clone->page_completions = NULL;
  clone->page_completion_count = 0;
  clone->permutations = NULL;
  clone->permutation_count = 0;
  clone->transition_rankings = NULL;
  clone->transition_ranking_count = 0;
  clone->transition_scans = NULL;
  clone->transition_scan_count = 0;
  clone->radius_rankings = NULL;
  clone->radius_count = 0;
  clone->multi_regions = NULL;
  clone->multi_region_count = 0;
  if (source->reservation_bytes != 0) {
    clone->probe_reservations = roaring64_bitmap_copy(source->probe_reservations);
    check_memory_allocation(clone->probe_reservations, __LINE__, __FILE__,
                            "SQLite probe reservation clone");
  }
  SqliteOooProbeState **tail = &clone->ooo_probes;
  for (const SqliteOooProbeState *probe = source->ooo_probes;
       probe; probe = probe->next) {
    *tail = (SqliteOooProbeState *)calloc(1, sizeof(**tail));
    check_memory_allocation(*tail, __LINE__, __FILE__, "SQLite probe clone");
    (*tail)->progress = probe->progress;
    clone->probe_count++;
    if (probe->progress.repair_count != 0) {
      const size_t bytes = (size_t)probe->progress.repair_count * sizeof(*probe->repairs);
      (*tail)->repairs = (SqliteRepairDescriptor *)malloc(bytes);
      check_memory_allocation((*tail)->repairs, __LINE__, __FILE__,
                              "SQLite probe repair clone");
      memcpy((*tail)->repairs, probe->repairs, bytes);
    }
    tail = &(*tail)->next;
  }
  SqliteGapProbeState **gap_tail = &clone->gap_probes;
  for (const SqliteGapProbeState *probe = source->gap_probes; probe; probe = probe->next) {
    *gap_tail = (SqliteGapProbeState *)calloc(1, sizeof(**gap_tail));
    check_memory_allocation(*gap_tail, __LINE__, __FILE__, "SQLite gap probe clone");
    (*gap_tail)->progress = probe->progress;
    clone->gap_probe_count++;
    gap_tail = &(*gap_tail)->next;
  }
  SqlitePairProbeState **pair_tail = &clone->pair_probes;
  for (const SqlitePairProbeState *probe = source->pair_probes; probe; probe = probe->next) {
    *pair_tail = (SqlitePairProbeState *)calloc(1, sizeof(**pair_tail));
    check_memory_allocation(*pair_tail, __LINE__, __FILE__, "SQLite pair probe clone");
    (*pair_tail)->progress = probe->progress;
    clone->pair_probe_count++;
    pair_tail = &(*pair_tail)->next;
  }
  SqlitePageCompletionState **completion_tail = &clone->page_completions;
  for (const SqlitePageCompletionState *entry = source->page_completions;
       entry; entry = entry->next) {
    *completion_tail = (SqlitePageCompletionState *)calloc(1, sizeof(**completion_tail));
    check_memory_allocation(*completion_tail, __LINE__, __FILE__, "SQLite page completion clone");
    (*completion_tail)->progress = entry->progress;
    clone->page_completion_count++;
    completion_tail = &(*completion_tail)->next;
  }
  SqlitePermutationState **permutation_tail = &clone->permutations;
  for (const SqlitePermutationState *entry = source->permutations;
       entry; entry = entry->next) {
    *permutation_tail = (SqlitePermutationState *)calloc(1, sizeof(**permutation_tail));
    check_memory_allocation(*permutation_tail, __LINE__, __FILE__, "SQLite permutation clone");
    (*permutation_tail)->progress = entry->progress;
    clone->permutation_count++;
    permutation_tail = &(*permutation_tail)->next;
  }
  SqliteTransitionRankingState **ranking_tail = &clone->transition_rankings;
  for (const SqliteTransitionRankingState *entry = source->transition_rankings;
       entry; entry = entry->next) {
    *ranking_tail = (SqliteTransitionRankingState *)calloc(1, sizeof(**ranking_tail));
    check_memory_allocation(*ranking_tail, __LINE__, __FILE__, "SQLite transition ranking clone");
    (*ranking_tail)->progress = entry->progress;
    clone->transition_ranking_count++;
    ranking_tail = &(*ranking_tail)->next;
  }
  SqliteTransitionScanState **scan_tail = &clone->transition_scans;
  for (const SqliteTransitionScanState *entry = source->transition_scans;
       entry; entry = entry->next) {
    *scan_tail = (SqliteTransitionScanState *)calloc(1, sizeof(**scan_tail));
    check_memory_allocation(*scan_tail, __LINE__, __FILE__, "SQLite transition scan clone");
    (*scan_tail)->progress = entry->progress;
    clone->transition_scan_count++;
    scan_tail = &(*scan_tail)->next;
  }
  SqliteRadiusState **radius_tail = &clone->radius_rankings;
  for (const SqliteRadiusState *entry = source->radius_rankings; entry; entry = entry->next) {
    *radius_tail = (SqliteRadiusState *)calloc(1, sizeof(**radius_tail));
    check_memory_allocation(*radius_tail, __LINE__, __FILE__, "SQLite radius clone");
    (*radius_tail)->progress = entry->progress;
    clone->radius_count++;
    radius_tail = &(*radius_tail)->next;
  }
  SqliteMultiRegionState **multi_tail = &clone->multi_regions;
  for (const SqliteMultiRegionState *entry = source->multi_regions; entry; entry = entry->next) {
    *multi_tail = (SqliteMultiRegionState *)calloc(1, sizeof(**multi_tail));
    check_memory_allocation(*multi_tail, __LINE__, __FILE__, "SQLite multi-region clone");
    (*multi_tail)->progress = entry->progress;
    clone->multi_region_count++;
    multi_tail = &(*multi_tail)->next;
  }
  return clone;
}

static inline void sqlite_free_carve_state(void **state) {
  if (state && *state) {
    sqlite_clear_ooo_probes((SqliteCarveState *)*state);
    free(*state);
    *state = NULL;
  }
}

static inline size_t sqlite_sizeof_carve_state(const void *state) {
  const SqliteCarveState *saved = (const SqliteCarveState *)state;
  size_t bytes = sizeof(SqliteCarveState);
  if (saved) {
    bytes += (size_t)saved->reservation_bytes;
    bytes += (size_t)saved->gap_probe_count * sizeof(SqliteGapProbeState);
    bytes += (size_t)saved->pair_probe_count * sizeof(SqlitePairProbeState);
    bytes += (size_t)saved->page_completion_count * sizeof(SqlitePageCompletionState);
    bytes += (size_t)saved->permutation_count * sizeof(SqlitePermutationState);
    bytes += (size_t)saved->transition_ranking_count * sizeof(SqliteTransitionRankingState);
    bytes += (size_t)saved->transition_scan_count * sizeof(SqliteTransitionScanState);
    bytes += (size_t)saved->radius_count * sizeof(SqliteRadiusState);
    bytes += (size_t)saved->multi_region_count * sizeof(SqliteMultiRegionState);
    for (const SqliteOooProbeState *probe = saved->ooo_probes;
         probe; probe = probe->next) {
      bytes += sizeof(*probe)
          + (size_t)probe->progress.repair_count * sizeof(*probe->repairs);
    }
  }
  return bytes;
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

static inline uint64_t sqlite_probe_source_view(uint64_t needleidx) {
  uint64_t hash = UINT64_C(1469598103934665603);
  const uint64_t blocks = filemirror_apparent_blocks(scalpel_state.filemirror);
  for (uint64_t source = 0; source < blocks; source++) {
    const int64_t actual = filemirror_actual_blocknumber(
        scalpel_state.filemirror, (int64_t)source);
    hash = (hash ^ (uint64_t)actual) * UINT64_C(1099511628211);
    hash = (hash ^ (uint64_t)filemirror_get_blocktype(
        scalpel_state.filemirror, actual, (uint32_t)needleidx))
        * UINT64_C(1099511628211);
  }
  return hash;
}

// Nested calls can finish before their parent does. Retain those completed scans as well as the
// active one, but release them when the enclosing search advances to another independent query.
static inline void sqlite_probe_prepare(SqliteCarveState *state, uint32_t needleidx) {
  if (state->probe_view == 0) {
    state->probe_view = sqlite_probe_source_view(needleidx);
  }
  const uint64_t fields[] = {state->stage, state->probe_step, state->probe_view,
      state->cursor.pass, state->cursor.width, state->cursor.source,
      state->outer_cursor.pass, state->outer_cursor.width, state->outer_cursor.source,
      state->base_mapping_hash, state->apparent_blocks, scalpel_state.reservations};
  uint64_t owner = UINT64_C(1469598103934665603);
  for (size_t index = 0; index < sizeof(fields) / sizeof(fields[0]); index++) {
    owner = (owner ^ fields[index]) * UINT64_C(1099511628211);
  }
  if (state->probe_owner != owner) {
    sqlite_clear_ooo_probes(state);
    state->probe_owner = owner;
    if (scalpel_state.reservations) {
      state->probe_reservations = roaring64_bitmap_create();
      check_memory_allocation(state->probe_reservations, __LINE__, __FILE__,
                              "SQLite probe reservation order");
      for (uint64_t source = 0; source < state->apparent_blocks; source++) {
        const int64_t actual = filemirror_actual_blocknumber(
            scalpel_state.filemirror, (int64_t)source);
        if (filemirror_actual_block_reserved(scalpel_state.filemirror, actual) > 0) {
          roaring64_bitmap_add(state->probe_reservations, source);
        }
      }
      roaring64_bitmap_run_optimize(state->probe_reservations);
      state->reservation_bytes =
          roaring64_bitmap_portable_size_in_bytes(state->probe_reservations);
    }
  }
}

static inline SqliteOooProbeState *sqlite_ooo_probe_begin(
    SqliteCarveState *state, uint64_t key, uint32_t needleidx) {
  sqlite_probe_prepare(state, needleidx);
  SqliteOooProbeState **tail = &state->ooo_probes;
  while (*tail) {
    if ((*tail)->progress.key == key) {
      return *tail;
    }
    tail = &(*tail)->next;
  }
  *tail = (SqliteOooProbeState *)calloc(1, sizeof(**tail));
  check_memory_allocation(*tail, __LINE__, __FILE__, "SQLite nested OOO probe");
  (*tail)->progress.key = key;
  (*tail)->progress.width_pass = 1;
  state->probe_count++;
  return *tail;
}

static inline SqliteGapProbeState *sqlite_gap_probe_begin(
    SqliteCarveState *state, uint64_t key, SqliteGapProbeKind kind, uint32_t needleidx) {
  sqlite_probe_prepare(state, needleidx);
  SqliteGapProbeState **tail = &state->gap_probes;
  while (*tail) {
    if ((*tail)->progress.key == key && (*tail)->progress.kind == (uint32_t)kind) {
      return *tail;
    }
    tail = &(*tail)->next;
  }
  *tail = (SqliteGapProbeState *)calloc(1, sizeof(**tail));
  check_memory_allocation(*tail, __LINE__, __FILE__, "SQLite nested gap probe");
  (*tail)->progress.key = key;
  (*tail)->progress.kind = (uint32_t)kind;
  (*tail)->progress.next_target = 1;
  (*tail)->progress.next_width = 1;
  state->gap_probe_count++;
  return *tail;
}

static inline SqlitePairProbeState *sqlite_pair_probe_begin(
    SqliteCarveState *state, uint64_t key, uint32_t needleidx) {
  sqlite_probe_prepare(state, needleidx);
  SqlitePairProbeState **tail = &state->pair_probes;
  while (*tail) {
    if ((*tail)->progress.key == key) {
      return *tail;
    }
    tail = &(*tail)->next;
  }
  *tail = (SqlitePairProbeState *)calloc(1, sizeof(**tail));
  check_memory_allocation(*tail, __LINE__, __FILE__, "SQLite nested pair probe");
  (*tail)->progress.key = key;
  state->pair_probe_count++;
  return *tail;
}

// Retain partial-page alternatives independently of the parent repair that discovered them.
static inline SqlitePageCompletionState *sqlite_page_completion_begin(
    SqliteCarveState *state, uint64_t key, uint64_t target_count, uint32_t needleidx) {
  sqlite_probe_prepare(state, needleidx);
  SqlitePageCompletionState **tail = &state->page_completions;
  while (*tail) {
    if ((*tail)->progress.key == key && (*tail)->progress.target_count == target_count) {
      return *tail;
    }
    tail = &(*tail)->next;
  }
  *tail = (SqlitePageCompletionState *)calloc(1, sizeof(**tail));
  check_memory_allocation(*tail, __LINE__, __FILE__, "SQLite page completion");
  (*tail)->progress.key = key;
  (*tail)->progress.target_count = target_count;
  state->page_completion_count++;
  return *tail;
}

// A permutation stores source-run identities, not a full copy of the candidate for every choice.
static inline SqlitePermutationState *sqlite_permutation_begin(
    SqliteCarveState *state, uint64_t key, uint64_t target_count, uint32_t needleidx) {
  sqlite_probe_prepare(state, needleidx);
  SqlitePermutationState **tail = &state->permutations;
  while (*tail) {
    if ((*tail)->progress.key == key && (*tail)->progress.target_count == target_count) {
      return *tail;
    }
    tail = &(*tail)->next;
  }
  *tail = (SqlitePermutationState *)calloc(1, sizeof(**tail));
  check_memory_allocation(*tail, __LINE__, __FILE__, "SQLite permutation");
  SqlitePermutationProgress *p = &(*tail)->progress;
  p->key = key;
  p->target_count = target_count;
  p->count = 1;
  p->right = 1;
  for (uint64_t slot = 0; slot < target_count; slot++) {
    p->order[0][slot] = (uint8_t)slot;
  }
  state->permutation_count++;
  return *tail;
}

// A nested transition keeps its ranked result while the enclosing repair explores other choices.
static inline SqliteTransitionRankingState *sqlite_transition_ranking_begin(
    SqliteCarveState *state, uint64_t key, uint64_t first_target,
    uint64_t last_target, uint64_t width, uint32_t needleidx) {
  sqlite_probe_prepare(state, needleidx);
  SqliteTransitionRankingState **tail = &state->transition_rankings;
  while (*tail) {
    const SqliteTransitionRankingProgress *p = &(*tail)->progress;
    if (p->key == key && p->first_target == first_target
        && p->last_target == last_target && p->width == width) {
      return *tail;
    }
    tail = &(*tail)->next;
  }
  *tail = (SqliteTransitionRankingState *)calloc(1, sizeof(**tail));
  check_memory_allocation(*tail, __LINE__, __FILE__, "SQLite transition ranking");
  (*tail)->progress.key = key;
  (*tail)->progress.first_target = first_target;
  (*tail)->progress.last_target = last_target;
  (*tail)->progress.next_target = first_target;
  (*tail)->progress.width = width;
  state->transition_ranking_count++;
  return *tail;
}

// Each repaired mapping owns a distinct bounded table, including a completed empty result.
static inline SqliteTransitionScanState *sqlite_transition_scan_begin(
    SqliteCarveState *state, uint64_t key, uint64_t page_blocks, uint32_t needleidx) {
  sqlite_probe_prepare(state, needleidx);
  SqliteTransitionScanState **tail = &state->transition_scans;
  while (*tail) {
    if ((*tail)->progress.key == key && (*tail)->progress.page_blocks == page_blocks) {
      return *tail;
    }
    tail = &(*tail)->next;
  }
  *tail = (SqliteTransitionScanState *)calloc(1, sizeof(**tail));
  check_memory_allocation(*tail, __LINE__, __FILE__, "SQLite transition scan");
  (*tail)->progress.key = key;
  (*tail)->progress.page_blocks = page_blocks;
  (*tail)->progress.boundary = page_blocks;
  state->transition_scan_count++;
  return *tail;
}

// Bind a radius winner and cursor to the same mapping, layout and baseline query.
static inline SqliteRadiusState *sqlite_radius_begin(
    SqliteCarveState *state, uint64_t key, uint64_t boundary, uint64_t width,
    uint64_t radius, const SqliteIntegrity *baseline, uint32_t needleidx) {
  sqlite_probe_prepare(state, needleidx);
  SqliteRadiusState **tail = &state->radius_rankings;
  while (*tail) {
    const SqliteRadiusProgress *p = &(*tail)->progress;
    if (p->key == key && p->boundary == boundary && p->width == width && p->radius == radius) {
      return *tail;
    }
    tail = &(*tail)->next;
  }
  *tail = (SqliteRadiusState *)calloc(1, sizeof(**tail));
  check_memory_allocation(*tail, __LINE__, __FILE__, "SQLite radius ranking");
  (*tail)->progress.key = key;
  (*tail)->progress.boundary = boundary;
  (*tail)->progress.width = width;
  (*tail)->progress.radius = radius;
  (*tail)->progress.best_integrity = *baseline;
  state->radius_count++;
  return *tail;
}

static inline SqliteMultiRegionState *sqlite_multi_region_begin(
    SqliteCarveState *state, uint64_t key, const SqliteIntegrity *baseline,
    uint32_t needleidx) {
  sqlite_probe_prepare(state, needleidx);
  SqliteMultiRegionState **tail = &state->multi_regions;
  while (*tail) {
    if ((*tail)->progress.key == key) {
      return *tail;
    }
    tail = &(*tail)->next;
  }
  *tail = (SqliteMultiRegionState *)calloc(1, sizeof(**tail));
  check_memory_allocation(*tail, __LINE__, __FILE__, "SQLite multi-region progress");
  (*tail)->progress.key = key;
  (*tail)->progress.current_integrity = *baseline;
  (*tail)->progress.next_integrity = *baseline;
  state->multi_region_count++;
  return *tail;
}

// Reservations rank sources; they do not authenticate data. Freeze that order for this search so
// another worker cannot move a source into an already completed tier across a checkpoint.
static inline bool sqlite_probe_source_reserved(
    const SqliteCarveState *state, uint64_t source, uint64_t width) {
  if (!state->probe_reservations) {
    return false;
  }
  for (uint64_t offset = 0; offset < width; offset++) {
    const uint64_t block = source + offset;
    if (roaring64_bitmap_contains(state->probe_reservations, block)) {
      return true;
    }
  }
  return false;
}

static inline void sqlite_probe_apply_repair(
    const int64_t *base, uint64_t blocks,
    const SqliteRepairDescriptor *repair, int64_t *mapping) {
  if (!mapping || !repair->valid) {
    return;
  }
  memcpy(mapping, base, (size_t)blocks * sizeof(*mapping));
  for (uint64_t offset = 0; offset < repair->width; offset++) {
    mapping[repair->target + offset] = (int64_t)(repair->source + offset);
  }
}

static inline bool sqlite_probe_copy_repairs(
    const SqliteOooProbeState *probe, SqliteRepairList *list) {
  if (!list) {
    return probe->progress.repair_count == 0;
  }
  for (uint64_t index = 0; index < probe->progress.repair_count; index++) {
    if (!sqlite_repair_list_append(list, &probe->repairs[index])) {
      return false;
    }
  }
  return true;
}

static inline bool sqlite_probe_add_repair(
    SqliteOooProbeState *probe, const SqliteRepairDescriptor *repair) {
  if (probe->progress.repair_count >= SIZE_MAX / sizeof(*probe->repairs)) {
    return false;
  }
  const size_t count = (size_t)probe->progress.repair_count + 1;
  SqliteRepairDescriptor *repairs = (SqliteRepairDescriptor *)realloc(
      probe->repairs, count * sizeof(*probe->repairs));
  if (!repairs) {
    return false;
  }
  probe->repairs = repairs;
  probe->repairs[probe->progress.repair_count++] = *repair;
  return true;
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
    carve_put_state((*candidate)->carvehashkey, state);
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
    bool *ambiguity_closed, SqliteOooExtensionState *progress) {
  const uint64_t apparent_blocks =
      filemirror_apparent_blocks(scalpel_state.filemirror);
  SqliteOooExtensionState local = {0};
  if (!progress) {
    progress = &local;
    progress->next_extension = 1;
  }

  if (ambiguity_closed) {
    *ambiguity_closed = false;
  }
  for (; progress->direction < 2; progress->direction++) {
    const uint32_t direction = progress->direction;
    for (uint64_t extension = progress->next_extension;
         extension <= SQLITE_FAST_PROBE_MAXIMUM_RUN_BLOCKS;
         extension++) {
      uint64_t extended_target = target;
      uint64_t extended_source = source;
      if (direction == 1) {
        if (extension > target || extension > source) {
          progress->closed |= UINT32_C(1) << direction;
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
        progress->closed |= UINT32_C(1) << direction;
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
        progress->closed |= UINT32_C(1) << direction;
        break;
      }
      sqlite_write_mapping_hypothesis(
          *candidate, trial_mapping, total_blocks, layout->extent);
      if (extended_mapping) {
        memcpy(extended_mapping, trial_mapping,
               total_blocks * sizeof(*extended_mapping));
      }
      progress->last = (SqliteRepairDescriptor){
          .target = extended_target, .width = extended_run,
          .source = extended_source, .valid = 1};
      progress->next_extension = extension + 1;
      if (sqlite_reassembly_poll(work, candidate, uuidp, uuidc,
                                 state, iterations)) {
        return SQLITE_REPAIR_STOPPED;
      }
    }
    progress->next_extension = 1;
  }
  if (ambiguity_closed) {
    *ambiguity_closed = progress->closed == 3;
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
      || !trial_data || !trial_mapping || !state || total_blocks < 2) {
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

  SqliteOooExtensionState *pending = &state->extension;
  const bool resume_selected = pending->active
      && state->stage == SQLITE_SEARCH_RANKED_GAP_OOO
      && pending->direction == 2 && pending->closed == 3;
  if (resume_selected && pending->next_gap_target >= first_target) {
    first_target = pending->next_gap_target;
  }
  uint64_t key = sqlite_mapping_hash(base_mapping, total_blocks);
  const uint64_t fields[] = {layout->extent, layout->page_size, total_blocks,
      scalpel_state.blocksize, selected_gap->target, selected_gap->width,
      sqlite_mapping_hash(selected_gap_mapping, total_blocks),
      sqlite_mapping_hash(selected_solution_mapping, total_blocks)};
  for (size_t index = 0; index < sizeof(fields) / sizeof(fields[0]); index++) {
    key = (key ^ fields[index]) * UINT64_C(1099511628211);
  }
  SqliteGapProbeProgress *progress = &sqlite_gap_probe_begin(
      state, key, SQLITE_GAP_PROBE_ALTERNATIVES, (*candidate)->needleidx)->progress;
  if (!progress->initialized) {
    progress->initialized = 1;
    progress->next_target = first_target;
  }
  for (uint64_t target = progress->next_target;
       !progress->scan_complete && target <= last_target;
       target++) {
    progress->next_target = target + 1;
    if (resume_selected) {
      pending->next_gap_target = target + 1;
    }
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
      progress->preserved++;
    }
    if (sqlite_reassembly_poll(work, candidate, uuidp, uuidc,
                               state, iterations)) {
      return SQLITE_REPAIR_STOPPED;
    }
  }
  progress->scan_complete = 1;
  if (progress->preserved > 0 && scalpel_state.mode_verbose) {
    lock_fprintf(stdout,
                 "SQLite reassembly: preserved %" PRIu64
                 " clean neighboring GAP mapping%s.\n",
                 progress->preserved, progress->preserved == 1 ? "" : "s");
  }
  if (resume_selected) {
    memset(pending, 0, sizeof(*pending));
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
      || target_count > UINT64_MAX / 2
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
  uint64_t key = sqlite_mapping_hash(base_mapping, total_blocks);
  const uint64_t fields[] = {layout->extent, layout->page_size, total_blocks,
      scalpel_state.blocksize, target_count};
  for (size_t index = 0; index < sizeof(fields) / sizeof(fields[0]); index++) {
    key = (key ^ fields[index]) * UINT64_C(1099511628211);
  }
  for (uint64_t index = 0; index < target_count; index++) {
    key = (key ^ targets[index]) * UINT64_C(1099511628211);
    key = (key ^ widths[index]) * UINT64_C(1099511628211);
  }
  SqlitePageCompletionProgress *progress = &sqlite_page_completion_begin(
      state, key, target_count, (*candidate)->needleidx)->progress;
  for (; !progress->complete && progress->repair < target_count;
       progress->repair++, progress->anchor = 0) {
    const uint64_t repair = progress->repair;
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
    for (; progress->anchor < anchor_count; progress->anchor++) {
      const uint64_t anchor_rank = progress->anchor;
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
      for (uint64_t prior = 0; prior < progress->attempted_count; prior++) {
        if (progress->attempted_targets[prior] == page_target
            && progress->attempted_sources[prior] == page_source) {
          attempted = true;
          break;
        }
      }
      if (attempted) {
        continue;
      }
      if (progress->attempted_count
          < SQLITE_PAGE_TRANSITION_LIMIT * 2) {
        progress->attempted_targets[progress->attempted_count] = page_target;
        progress->attempted_sources[progress->attempted_count] = page_source;
        progress->attempted_count++;
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
        progress->preserved++;
      }
      progress->anchor++;
      if (sqlite_reassembly_poll(work, candidate, uuidp, uuidc,
                                 state, iterations)) {
        return SQLITE_REPAIR_STOPPED;
      }
      progress->anchor--;
    }
  }
  progress->complete = 1;
  return progress->preserved > 0 ? SQLITE_REPAIR_PRESERVED
                       : SQLITE_REPAIR_NO_MATCH;
}

// Rebuild a retained run assignment from the unchanged selected candidate.
static inline void sqlite_permutation_mapping(const int64_t *base, uint64_t blocks,
    const uint64_t *targets, const uint64_t *widths, uint64_t target_count,
    const uint8_t *order, int64_t *mapping) {
  memcpy(mapping, base, (size_t)blocks * sizeof(*mapping));
  for (uint64_t slot = 0; slot < target_count; slot++) {
    memcpy(mapping + targets[slot], base + targets[order[slot]],
           (size_t)widths[slot] * sizeof(*mapping));
  }
}

// Preserve the breadth-first permutation frontier and next pair, including failed trials.
static inline SqliteRepairResult sqlite_preserve_permutations(
    ThreadWork *work, CarveInfo **candidate, uuid_string_t uuidp, uuid_string_t uuidc,
    const SqliteLayout *layout, const int64_t *base_mapping, uint64_t total_blocks,
    const uint64_t *targets, const uint64_t *widths, uint64_t target_count,
    uint8_t *trial_data, int64_t *trial_mapping, SqliteCarveState *state,
    uint64_t *iterations) {
  if (!candidate || !*candidate || !layout || !base_mapping || !targets || !widths
      || !trial_data || !trial_mapping || !state || !iterations || target_count < 2
      || target_count > SQLITE_PAGE_TRANSITION_LIMIT
      || total_blocks > SIZE_MAX / sizeof(int64_t) / SQLITE_COMPOSED_REPAIR_PROBE_LIMIT) {
    return SQLITE_REPAIR_NO_MATCH;
  }
  uint64_t key = sqlite_mapping_hash(base_mapping, total_blocks);
  const uint64_t fields[] = {layout->extent, total_blocks, scalpel_state.blocksize,
      target_count};
  for (size_t index = 0; index < sizeof(fields) / sizeof(fields[0]); index++) {
    key = (key ^ fields[index]) * UINT64_C(1099511628211);
  }
  for (uint64_t slot = 0; slot < target_count; slot++) {
    if (targets[slot] >= total_blocks || widths[slot] == 0
        || widths[slot] > total_blocks - targets[slot]
        || (slot && targets[slot] < targets[slot - 1] + widths[slot - 1])) {
      return SQLITE_REPAIR_NO_MATCH;
    }
    key = (key ^ targets[slot]) * UINT64_C(1099511628211);
    key = (key ^ widths[slot]) * UINT64_C(1099511628211);
  }
  SqlitePermutationProgress *p = &sqlite_permutation_begin(
      state, key, target_count, (*candidate)->needleidx)->progress;
  p->hashes[0] = sqlite_mapping_hash(base_mapping, total_blocks);
  for (uint64_t permutation = 0; permutation < p->count; permutation++) {
    for (uint64_t slot = 0; slot < target_count; slot++) {
      if (widths[slot] != widths[p->order[permutation][slot]]) {
        handle_error(SCALPEL_ERROR_CHECKPOINT, "invalid SQLite permutation widths",
                     __LINE__, __FILE__);
      }
    }
  }
  if (p->complete) {
    return p->count > 1 ? SQLITE_REPAIR_PRESERVED : SQLITE_REPAIR_NO_MATCH;
  }
  int64_t *comparison = (int64_t *)malloc((size_t)total_blocks * sizeof(*comparison));
  check_memory_allocation(comparison, __LINE__, __FILE__, "SQLite permutation comparison");
  for (; p->permutation < p->count && p->count < SQLITE_COMPOSED_REPAIR_PROBE_LIMIT;
       p->permutation++, p->left = 0, p->right = 1) {
    for (; p->left < target_count; p->left++, p->right = p->left + 1) {
      for (; p->right < target_count; p->right++) {
        const uint64_t left = p->left;
        const uint64_t right = p->right;
        if (widths[left] != widths[right]) {
          continue;
        }
        uint8_t order[SQLITE_PAGE_TRANSITION_LIMIT];
        memcpy(order, p->order[p->permutation], sizeof(order));
        const uint8_t swap = order[left];
        order[left] = order[right];
        order[right] = swap;
        sqlite_permutation_mapping(base_mapping, total_blocks, targets, widths,
                                   target_count, order, trial_mapping);
        const uint64_t hash = sqlite_mapping_hash(trial_mapping, total_blocks);
        bool duplicate = false;
        for (uint64_t prior = 0; prior < p->count; prior++) {
          if (p->hashes[prior] != hash) {
            continue;
          }
          sqlite_permutation_mapping(base_mapping, total_blocks, targets, widths,
                                     target_count, p->order[prior], comparison);
          if (memcmp(comparison, trial_mapping,
                     (size_t)total_blocks * sizeof(*comparison)) == 0) {
            duplicate = true;
            break;
          }
        }
        if (duplicate) {
          continue;
        }
        SqliteIntegrity integrity;
        if (!sqlite_mapping_check(trial_mapping, total_blocks, layout->extent,
                                  trial_data, &integrity)) {
          continue;
        }
        sqlite_write_mapping_hypothesis(*candidate, trial_mapping, total_blocks,
                                        layout->extent);
        memcpy(p->order[p->count], order, sizeof(order));
        p->hashes[p->count++] = hash;
        p->right++;
        if (sqlite_reassembly_poll(work, candidate, uuidp, uuidc, state, iterations)) {
          free(comparison);
          return SQLITE_REPAIR_STOPPED;
        }
        p->right--;
        if (p->count >= SQLITE_COMPOSED_REPAIR_PROBE_LIMIT) {
          break;
        }
      }
      if (p->count >= SQLITE_COMPOSED_REPAIR_PROBE_LIMIT) {
        break;
      }
    }
  }
  p->complete = 1;
  free(comparison);
  return p->count > 1 ? SQLITE_REPAIR_PRESERVED : SQLITE_REPAIR_NO_MATCH;
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
  uint64_t key = sqlite_mapping_hash(base_mapping, total_blocks);
  const uint64_t fields[] = {layout->extent, layout->page_size, total_blocks,
      scalpel_state.blocksize, target_hint, exact_target, width_hint, compose,
      composition_mapping != NULL, high_confidence_only, key_order_only,
      plausible_repairs != NULL, plausible_repairs ? plausible_repairs->limit : 0,
      plausible_repairs ? plausible_repairs->include_internal_sources : 0,
      baseline_integrity != NULL, baseline_integrity ? baseline_integrity->valid : 0,
      baseline_integrity ? baseline_integrity->error_count : 0,
      baseline_integrity ? baseline_integrity->first_page : 0,
      baseline_integrity ? baseline_integrity->last_page : 0,
      baseline_integrity ? (uint64_t)baseline_integrity->result_code : 0};
  for (size_t index = 0; index < sizeof(fields) / sizeof(fields[0]); index++) {
    key = (key ^ fields[index]) * UINT64_C(1099511628211);
  }
  SqliteOooProbeState *probe = sqlite_ooo_probe_begin(
      state, key, (*candidate)->needleidx);
  SqliteOooProbeProgress *progress = &probe->progress;
  if (!progress->initialized) {
    if (baseline_integrity) {
      progress->best_integrity = *baseline_integrity;
    }
    progress->initialized = 1;
  }
  sqlite_probe_apply_repair(base_mapping, total_blocks,
                            &progress->composition, composition_mapping);
  sqlite_probe_apply_repair(base_mapping, total_blocks,
                            &progress->solution, solution_mapping);
  if (!sqlite_probe_copy_repairs(probe, plausible_repairs)) {
    return SQLITE_REPAIR_NO_MATCH;
  }
  if (progress->extending) {
    sqlite_probe_apply_repair(base_mapping, total_blocks,
                              &progress->extension.last, solution_mapping);
    const SqliteRepairDescriptor *repair = &progress->extension.repair;
    const SqliteRepairResult extension_result = sqlite_preserve_ooo_extensions(
        work, candidate, uuidp, uuidc, layout, base_mapping, total_blocks,
        repair->target, repair->width, repair->source, trial_data, trial_mapping,
        solution_mapping, state, iterations, NULL, &progress->extension);
    progress->solution = progress->extension.last;
    sqlite_probe_apply_repair(base_mapping, total_blocks,
                              &progress->solution, solution_mapping);
    if (extension_result == SQLITE_REPAIR_STOPPED || !*candidate) {
      return SQLITE_REPAIR_STOPPED;
    }
    progress->extending = 0;
  }
  const uint32_t reservation_passes = scalpel_state.reservations ? 2 : 1;
  for (; !progress->scan_complete && progress->confidence_pass < confidence_passes;
       progress->confidence_pass++, progress->reservation_pass = 0) {
    const uint32_t confidence_pass = (uint32_t)progress->confidence_pass;
    for (; progress->reservation_pass < reservation_passes;
         progress->reservation_pass++, progress->width_pass = 1) {
      const uint32_t reservation_pass = (uint32_t)progress->reservation_pass;
      for (; progress->width_pass <= maximum_probe;
           progress->width_pass++, progress->target_rank = 0) {
        const uint64_t pass = progress->width_pass;
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
        for (; progress->target_rank < target_count;
             progress->target_rank++, progress->source_rank = 0) {
          const uint64_t target_rank = progress->target_rank;
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
          for (uint64_t source_rank = progress->source_rank;
               source_rank < source_count; source_rank++) {
              progress->source_rank = source_rank + 1;
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
              const bool source_reserved =
                  sqlite_probe_source_reserved(state, source, run_blocks);
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
                if (!sqlite_repair_list_append(plausible_repairs, &repair)
                    || !sqlite_probe_add_repair(probe, &repair)) {
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
                  progress->scan_complete = 1;
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
                progress->solution = (SqliteRepairDescriptor){
                    .target = target, .width = run_blocks,
                    .source = source, .valid = 1};
                progress->key_match = 1;
                progress->scan_complete = 1;
                return SQLITE_REPAIR_PLAUSIBLE;
              }
              SqliteIntegrity integrity;
              const bool mapping_valid = sqlite_mapping_ooo_check(
                  trial_mapping, total_blocks, layout->extent, trial_data,
                  &integrity,
                  baseline_integrity ? &progress->best_integrity : NULL,
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
                    progress->preserved_clean = 1;
                    if (preserve_bounded_ambiguity) {
                      progress->preserved_bounded = 1;
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
                  progress->preserved_necessary = 1;
                  progress->solution = (SqliteRepairDescriptor){
                      .target = target, .width = run_blocks,
                      .source = source, .valid = 1};
                  memcpy(solution_mapping, trial_mapping,
                         total_blocks * sizeof(*solution_mapping));
                  memset(&progress->extension, 0, sizeof(progress->extension));
                  progress->extension.repair = progress->solution;
                  progress->extension.last = progress->solution;
                  progress->extension.next_extension = 1;
                  progress->extending = 1;
                  const SqliteRepairResult extension_result =
                      sqlite_preserve_ooo_extensions(
                          work, candidate, uuidp, uuidc, layout,
                          base_mapping, total_blocks, target, run_blocks,
                          source, trial_data, trial_mapping,
                          solution_mapping, state,
                          iterations, NULL, &progress->extension);
                  progress->solution = progress->extension.last;
                  if (extension_result == SQLITE_REPAIR_STOPPED
                      || !*candidate) {
                    return SQLITE_REPAIR_STOPPED;
                  }
                  progress->extending = 0;
                }
              }
              if (!mapping_valid && compose && baseline_integrity
                  && composition_mapping
                  && sqlite_integrity_composition_better(
                      &integrity, &progress->best_integrity)) {
                progress->best_integrity = integrity;
                progress->composition = (SqliteRepairDescriptor){
                    .target = target, .width = run_blocks,
                    .source = source, .valid = 1};
                memcpy(composition_mapping, trial_mapping,
                       total_blocks * sizeof(*composition_mapping));
              }
              if (sqlite_reassembly_poll(work, candidate, uuidp, uuidc,
                                         state, iterations)) {
                return SQLITE_REPAIR_STOPPED;
              }
          }
        }
      }
      if (progress->preserved_bounded && !progress->preserved_necessary) {
        progress->scan_complete = 1;
        return SQLITE_REPAIR_PRESERVED;
      }
    }
  }
  progress->scan_complete = 1;
  if (progress->key_match || (plausible_repairs && plausible_repairs->count > 0)) {
    return SQLITE_REPAIR_PLAUSIBLE;
  }
  if (progress->preserved_clean) {
    return SQLITE_REPAIR_PRESERVED;
  }
  if (progress->composition.valid) {
    return sqlite_probe_gap_diagnostics(
        work, candidate, uuidp, uuidc, layout, &progress->best_integrity,
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
  uint64_t key = sqlite_mapping_hash(base_mapping, total_blocks);
  const uint64_t fields[] = {layout->extent, layout->page_size, total_blocks,
      scalpel_state.blocksize, targets[0], targets[1], widths[0], widths[1]};
  for (size_t index = 0; index < sizeof(fields) / sizeof(fields[0]); index++) {
    key = (key ^ fields[index]) * UINT64_C(1099511628211);
  }
  // The child probes retain their evidence and reservation ordering. Bind the
  // pair cursor to both ordered lists, not just their counts or destinations.
  for (uint32_t slot = 0; slot < 2; slot++) {
    key = (key ^ alternatives[slot].count) * UINT64_C(1099511628211);
    for (uint64_t index = 0; index < alternatives[slot].count; index++) {
      const SqliteRepairDescriptor *repair = &alternatives[slot].repairs[index];
      const uint64_t item[] = {repair->target, repair->width, repair->source,
          repair->valid, repair->reserved};
      for (size_t field = 0; field < sizeof(item) / sizeof(item[0]); field++) {
        key = (key ^ item[field]) * UINT64_C(1099511628211);
      }
    }
  }
  SqlitePairProbeProgress *progress = &sqlite_pair_probe_begin(
      state, key, (*candidate)->needleidx)->progress;
  if (memcmp(progress->class_counts, class_counts, sizeof(class_counts)) != 0) {
    memset(progress, 0, sizeof(*progress));
    progress->key = key;
    memcpy(progress->class_counts, class_counts, sizeof(class_counts));
  }
  if (progress->scan_complete) {
    outcome = progress->preserved ? SQLITE_REPAIR_PRESERVED : SQLITE_REPAIR_NO_MATCH;
    goto cleanup;
  }
  for (; progress->class_pair < 4;
       progress->class_pair++, progress->diagonal = 0, progress->first_rank = 0) {
    const uint32_t pair = progress->class_pair;
    const uint32_t first_class = class_pairs[pair][0];
    const uint32_t second_class = class_pairs[pair][1];
    const uint64_t first_count = class_counts[0][first_class];
    const uint64_t second_count = class_counts[1][second_class];
    if (first_count == 0 || second_count == 0) {
      continue;
    }
    const uint64_t last_diagonal = first_count + second_count - 2;
    for (; progress->diagonal <= last_diagonal;
         progress->diagonal++, progress->first_rank = 0) {
      const uint64_t diagonal = progress->diagonal;
      const uint64_t first_begin = diagonal >= second_count
          ? diagonal - (second_count - 1) : 0;
      uint64_t first_end = diagonal;
      if (first_end >= first_count) {
        first_end = first_count - 1;
      }
      for (uint64_t first_rank = first_begin > progress->first_rank
                                    ? first_begin : progress->first_rank;
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
            progress->preserved++;
            if (progress->preserved >= SQLITE_COMPOSED_HYPOTHESIS_LIMIT) {
              progress->first_rank = first_rank + 1;
              progress->scan_complete = 1;
              outcome = SQLITE_REPAIR_PRESERVED;
              goto cleanup;
            }
          }
        }
        progress->first_rank = first_rank + 1;
        if (sqlite_reassembly_poll(work, candidate, uuidp, uuidc,
                                   state, iterations)) {
          outcome = SQLITE_REPAIR_STOPPED;
          goto cleanup;
        }
      }
    }
  }
  progress->scan_complete = 1;
  if (progress->preserved > 0) {
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

  uint64_t key = sqlite_mapping_hash(base_mapping, total_blocks);
  const uint64_t fields[] = {layout->extent, layout->page_size, total_blocks,
      scalpel_state.blocksize, target_hint, compose, composition_mapping != NULL,
      baseline_integrity != NULL, baseline_integrity ? baseline_integrity->valid : 0,
      baseline_integrity ? baseline_integrity->error_count : 0,
      baseline_integrity ? baseline_integrity->first_page : 0,
      baseline_integrity ? baseline_integrity->last_page : 0,
      baseline_integrity ? (uint64_t)baseline_integrity->result_code : 0};
  for (size_t index = 0; index < sizeof(fields) / sizeof(fields[0]); index++) {
    key = (key ^ fields[index]) * UINT64_C(1099511628211);
  }
  SqliteGapProbeProgress *progress = &sqlite_gap_probe_begin(
      state, key, SQLITE_GAP_PROBE_RANKING, (*candidate)->needleidx)->progress;
  if (!progress->initialized) {
    progress->initialized = 1;
    progress->next_target = target_hint;
    if (baseline_integrity) {
      progress->best_integrity = *baseline_integrity;
    }
  }
  if (progress->matched) {
    sqlite_apply_gap_descriptor(base_mapping, total_blocks,
                                &progress->best_gap, solution_mapping);
    return SQLITE_REPAIR_MATCH;
  }
  for (; !progress->scan_complete && progress->next_target <= last_target;
       progress->next_target++, progress->next_width = 1) {
    const uint64_t target = progress->next_target;
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
    for (uint64_t gap = progress->next_width; gap <= maximum_gap; gap++) {
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
        progress->best_gap = (SqliteRepairDescriptor){
            .target = target, .width = gap, .valid = 1};
        progress->matched = 1;
        progress->scan_complete = 1;
        return SQLITE_REPAIR_MATCH;
      }
      if (compose && baseline_integrity && composition_mapping
          && sqlite_integrity_composition_better(
              &integrity, &progress->best_integrity)) {
        progress->best_integrity = integrity;
        progress->best_gap = (SqliteRepairDescriptor){
            .target = target, .width = gap, .valid = 1};
        memcpy(composition_mapping, trial_mapping,
               total_blocks * sizeof(*composition_mapping));
      }
      progress->next_width = gap + 1;
      if (sqlite_reassembly_poll(work, candidate, uuidp, uuidc,
                                 state, iterations)) {
        return SQLITE_REPAIR_STOPPED;
      }
    }
  }
  progress->scan_complete = 1;
  if (progress->best_gap.valid && composition_mapping) {
    sqlite_apply_gap_descriptor(base_mapping, total_blocks,
                                &progress->best_gap, composition_mapping);
    memcpy(solution_mapping, composition_mapping,
           total_blocks * sizeof(*solution_mapping));
    SqliteRepairResult result = sqlite_probe_ooo_diagnostics(
        work, candidate, uuidp, uuidc, layout, &progress->best_integrity,
        composition_mapping, total_blocks, trial_data, trial_mapping,
        solution_mapping, NULL, false, false, state, iterations);
    if (result == SQLITE_REPAIR_STOPPED || !*candidate) {
      return SQLITE_REPAIR_STOPPED;
    }
    if (result == SQLITE_REPAIR_PRESERVED) {
      return result;
    }
    SqliteIntegrity solution_integrity;
    if (progress->best_gap.valid
        && sqlite_mapping_check(solution_mapping, total_blocks,
                                layout->extent, trial_data,
                                &solution_integrity)) {
      result = sqlite_preserve_gap_alternatives(
          work, candidate, uuidp, uuidc, layout, base_mapping,
          total_blocks, &progress->best_gap, composition_mapping,
          solution_mapping, trial_data, trial_mapping, state,
          iterations);
      return result == SQLITE_REPAIR_STOPPED
          ? SQLITE_REPAIR_STOPPED : SQLITE_REPAIR_MATCH;
    }
    return result;
  }
  return SQLITE_REPAIR_NO_MATCH;
}

// Rank possible gap starts in one page window. A second-gap query additionally requires improved
// page evidence or integrity; neither mode changes the original preference for zero-backed starts.
static inline SqliteRepairResult sqlite_rank_transition_targets(
    ThreadWork *work, CarveInfo **candidate, uuid_string_t uuidp, uuid_string_t uuidc,
    const SqliteLayout *layout, const int64_t *base_mapping, uint64_t total_blocks,
    uint64_t first_target, uint64_t last_target, uint64_t width,
    const SqliteIntegrity *baseline, uint64_t baseline_evidence,
    uint8_t *trial_data, int64_t *trial_mapping, SqliteCarveState *state,
    uint64_t *iterations, SqliteTransitionRankingProgress **ranking) {
  *ranking = NULL;
  if (first_target == 0 || first_target > last_target || last_target >= total_blocks
      || width == 0 || width >= state->apparent_blocks) {
    return SQLITE_REPAIR_NO_MATCH;
  }
  uint64_t key = sqlite_mapping_hash(base_mapping, total_blocks);
  const uint64_t fields[] = {layout->extent, layout->page_size, layout->usable_size,
      layout->page_count, layout->largest_root_page, total_blocks,
      scalpel_state.blocksize, first_target, last_target, width, baseline != NULL,
      baseline ? baseline_evidence : 0, baseline ? baseline->error_count : 0,
      baseline ? baseline->first_page : 0, baseline ? baseline->last_page : 0,
      baseline ? (uint64_t)baseline->result_code : 0, baseline ? baseline->valid : 0};
  for (size_t index = 0; index < sizeof(fields) / sizeof(fields[0]); index++) {
    key = (key ^ fields[index]) * UINT64_C(1099511628211);
  }
  SqliteTransitionRankingProgress *p = &sqlite_transition_ranking_begin(
      state, key, first_target, last_target, width, (*candidate)->needleidx)->progress;
  *ranking = p;
  if (p->complete) {
    return p->usable ? SQLITE_REPAIR_PLAUSIBLE : SQLITE_REPAIR_NO_MATCH;
  }
  while (p->next_target <= last_target) {
    const uint64_t target = p->next_target++;
    const SqliteRepairDescriptor repair = {
        .target = target, .width = width, .source = 0, .valid = 1, .reserved = 0};
    if (!sqlite_apply_gap_descriptor(base_mapping, total_blocks, &repair, trial_mapping)) {
      continue;
    }
    SqliteIntegrity integrity;
    const bool clean = sqlite_mapping_check(
        trial_mapping, total_blocks, layout->extent, trial_data, &integrity);
    if (baseline) {
      uint64_t evidence = 0;
      for (uint64_t slot = 1; slot < total_blocks; slot++) {
        if (trial_mapping[slot] >= 0
            && sqlite_source_has_layout_page_evidence(
                (uint64_t)trial_mapping[slot], 1, slot, layout, (*candidate)->needleidx)) {
          evidence++;
        }
      }
      if (evidence <= baseline_evidence
          && !sqlite_integrity_composition_better(&integrity, baseline)) {
        continue;
      }
    }
    const bool zero_backed = sqlite_mapping_block_is_zero(base_mapping, target);
    if (!p->usable || (zero_backed != (bool)p->zero_backed && zero_backed)
        || (zero_backed == (bool)p->zero_backed
            && sqlite_integrity_composition_better(&integrity, &p->best_integrity))) {
      p->usable = 1;
      p->clean = clean;
      p->zero_backed = zero_backed;
      p->best_target = target;
      p->best_integrity = integrity;
    }
    if (sqlite_reassembly_poll(work, candidate, uuidp, uuidc, state, iterations)) {
      return SQLITE_REPAIR_STOPPED;
    }
  }
  p->complete = 1;
  return p->usable ? SQLITE_REPAIR_PLAUSIBLE : SQLITE_REPAIR_NO_MATCH;
}

// Discover bounded transitions after removing a gap. Save both the table and the exact next
// evidence check before yielding; a later nested probe must not force this scan to start over.
static inline SqliteRepairResult sqlite_scan_repaired_transitions(
    ThreadWork *work, CarveInfo **candidate, uuid_string_t uuidp, uuid_string_t uuidc,
    const SqliteLayout *layout, const int64_t *mapping, uint64_t total_blocks,
    SqliteCarveState *state, uint64_t *iterations, SqliteTransitionScanProgress **scan) {
  *scan = NULL;
  if (!candidate || !*candidate || !mapping || scalpel_state.blocksize == 0) {
    return SQLITE_REPAIR_NO_MATCH;
  }
  const uint64_t page_blocks = CEILDIV(layout->page_size, scalpel_state.blocksize);
  const uint64_t apparent_blocks = filemirror_apparent_blocks(scalpel_state.filemirror);
  if (page_blocks == 0 || page_blocks > total_blocks) {
    return SQLITE_REPAIR_NO_MATCH;
  }
  uint64_t key = sqlite_mapping_hash(mapping, total_blocks);
  const uint64_t fields[] = {layout->extent, layout->page_size, layout->usable_size,
      layout->page_count, layout->largest_root_page, total_blocks,
      scalpel_state.blocksize, apparent_blocks};
  for (size_t index = 0; index < sizeof(fields) / sizeof(fields[0]); index++) {
    key = (key ^ fields[index]) * UINT64_C(1099511628211);
  }
  SqliteTransitionScanProgress *p = &sqlite_transition_scan_begin(
      state, key, page_blocks, (*candidate)->needleidx)->progress;
  *scan = p;
  if (p->phase == SQLITE_TRANSITION_SCAN_COMPLETE) {
    return SQLITE_REPAIR_NO_MATCH;
  }

  // A gap inside a larger page can move the next recognizable header beyond its boundary.
  while (p->phase == SQLITE_TRANSITION_SCAN_PAGES
         && p->boundary <= total_blocks - page_blocks) {
    const uint64_t boundary = p->boundary;
    p->boundary += page_blocks;
    if (mapping[boundary] < 0) {
      p->left_support = 0;
      continue;
    }
    const uint64_t source = (uint64_t)mapping[boundary];
    if (sqlite_source_has_layout_page_evidence(
            source, page_blocks, boundary, layout, (*candidate)->needleidx)) {
      p->left_support++;
      continue;
    }
    if (source >= apparent_blocks || page_blocks > apparent_blocks - source) {
      p->left_support = 0;
      continue;
    }
    uint64_t maximum_gap = SQLITE_FAST_PROBE_MAXIMUM_GAP_BLOCKS;
    const uint64_t available_shift = apparent_blocks - source - page_blocks;
    if (maximum_gap > available_shift) {
      maximum_gap = available_shift;
    }
    for (uint64_t observed_gap = 1; observed_gap <= maximum_gap; observed_gap++) {
      if (!sqlite_source_has_layout_page_evidence(
              source + observed_gap, page_blocks, boundary, layout,
              (*candidate)->needleidx)) {
        continue;
      }
      uint64_t right_support = 0;
      uint64_t logical_offset = 0;
      while (logical_offset <= total_blocks - boundary - page_blocks
             && logical_offset <= apparent_blocks - page_blocks - source - observed_gap
             && sqlite_source_has_layout_page_evidence(
                 source + observed_gap + logical_offset, page_blocks,
                 boundary + logical_offset, layout, (*candidate)->needleidx)) {
        right_support++;
        logical_offset += page_blocks;
      }
      const uint64_t support = p->left_support == 0 ? right_support
          : (p->left_support < right_support ? p->left_support : right_support);
      bool duplicate_transition = false;
      for (uint64_t prior = 0; prior < p->count; prior++) {
        if (p->page_aligned[prior] && p->widths[prior] == 1) {
          duplicate_transition = true;
          break;
        }
      }
      if (!duplicate_transition && p->count < SQLITE_PAGE_TRANSITION_LIMIT) {
        const uint64_t slot = p->count++;
        p->boundaries[slot] = boundary;
        p->widths[slot] = 1;
        p->support[slot] = support;
        p->gap_targets[slot] = boundary;
        p->page_aligned[slot] = 1;
      }
      break;
    }
    p->left_support = 0;
    if (sqlite_reassembly_poll(work, candidate, uuidp, uuidc, state, iterations)) {
      return SQLITE_REPAIR_STOPPED;
    }
  }
  if (p->phase == SQLITE_TRANSITION_SCAN_PAGES) {
    p->phase = SQLITE_TRANSITION_SCAN_BLOCK_POLL;
    p->boundary = 1;
    p->left_support = 0;
  }

  // Only block-sized pages provide independent page evidence at each candidate position.
  while (page_blocks == 1 && p->boundary < total_blocks) {
    const uint64_t boundary = p->boundary;
    if (p->phase == SQLITE_TRANSITION_SCAN_BLOCK_POLL) {
      p->phase = SQLITE_TRANSITION_SCAN_BLOCK;
      if (sqlite_reassembly_poll(work, candidate, uuidp, uuidc, state, iterations)) {
        return SQLITE_REPAIR_STOPPED;
      }
    }
    if (p->phase == SQLITE_TRANSITION_SCAN_BLOCK) {
      if (mapping[boundary] < 0) {
        p->left_support = 0;
      }
      else if (sqlite_source_has_layout_page_evidence(
                   (uint64_t)mapping[boundary], 1, boundary, layout,
                   (*candidate)->needleidx)) {
        p->left_support++;
      }
      else if (p->left_support != 0) {
        uint64_t width = 1;
        while (width <= SQLITE_FAST_PROBE_MAXIMUM_RUN_BLOCKS
               && width < total_blocks - boundary && mapping[boundary + width] >= 0
               && !sqlite_source_has_layout_page_evidence(
                   (uint64_t)mapping[boundary + width], 1, boundary + width,
                   layout, (*candidate)->needleidx)) {
          width++;
        }
        if (width <= SQLITE_FAST_PROBE_MAXIMUM_RUN_BLOCKS
            && width < total_blocks - boundary && mapping[boundary + width] >= 0) {
          p->width = width;
          p->right_support = 0;
          p->phase = SQLITE_TRANSITION_SCAN_RIGHT;
        }
        else {
          p->left_support = 0;
        }
      }
      if (p->phase == SQLITE_TRANSITION_SCAN_BLOCK) {
        p->boundary++;
        p->phase = SQLITE_TRANSITION_SCAN_BLOCK_POLL;
        continue;
      }
    }

    while (p->right_support < total_blocks - boundary - p->width
           && mapping[boundary + p->width + p->right_support] >= 0
           && sqlite_source_has_layout_page_evidence(
               (uint64_t)mapping[boundary + p->width + p->right_support],
               1, boundary + p->width + p->right_support, layout, (*candidate)->needleidx)) {
      p->right_support++;
      if (sqlite_reassembly_poll(work, candidate, uuidp, uuidc, state, iterations)) {
        return SQLITE_REPAIR_STOPPED;
      }
    }
    const uint64_t support = p->left_support < p->right_support
        ? p->left_support : p->right_support;
    bool duplicate_transition = false;
    for (uint64_t prior = 0; prior < p->count; prior++) {
      if (p->boundaries[prior] == boundary && p->widths[prior] == p->width) {
        duplicate_transition = true;
        break;
      }
    }
    if (!duplicate_transition) {
      uint64_t slot = p->count;
      while (slot > 0) {
        const uint64_t previous = slot - 1;
        if (p->zero_backed[previous] || p->page_aligned[previous]
            || support < p->support[previous]
            || (support == p->support[previous] && p->width <= p->widths[previous])) {
          break;
        }
        if (slot < SQLITE_PAGE_TRANSITION_LIMIT) {
          p->boundaries[slot] = p->boundaries[previous];
          p->widths[slot] = p->widths[previous];
          p->support[slot] = p->support[previous];
          p->gap_targets[slot] = p->gap_targets[previous];
          p->zero_backed[slot] = p->zero_backed[previous];
          p->page_aligned[slot] = p->page_aligned[previous];
        }
        slot--;
      }
      if (slot < SQLITE_PAGE_TRANSITION_LIMIT) {
        p->boundaries[slot] = boundary;
        p->widths[slot] = p->width;
        p->support[slot] = support;
        p->gap_targets[slot] = boundary;
        p->zero_backed[slot] = 0;
        p->page_aligned[slot] = 0;
        if (p->count < SQLITE_PAGE_TRANSITION_LIMIT) {
          p->count++;
        }
      }
    }
    p->left_support = 0;
    p->width = 0;
    p->right_support = 0;
    p->boundary++;
    p->phase = SQLITE_TRANSITION_SCAN_BLOCK_POLL;
  }
  p->boundary = total_blocks;
  p->left_support = 0;
  p->width = 0;
  p->right_support = 0;
  p->phase = SQLITE_TRANSITION_SCAN_COMPLETE;
  return SQLITE_REPAIR_NO_MATCH;
}

// Check nearby gap starts in the original outward order. A completed failed winner still feeds
// the existing composition search, so preserve it as well as unfinished ranking trials.
static inline SqliteRepairResult sqlite_rank_radius_targets(
    ThreadWork *work, CarveInfo **candidate, uuid_string_t uuidp, uuid_string_t uuidc,
    const SqliteLayout *layout, const int64_t *base_mapping, uint64_t total_blocks,
    uint64_t boundary, uint64_t width, uint64_t support, const SqliteIntegrity *baseline,
    bool compose, uint8_t *trial_data, int64_t *trial_mapping, SqliteCarveState *state,
    uint64_t *iterations, SqliteRadiusProgress **ranking) {
  *ranking = NULL;
  if (boundary == 0 || boundary >= total_blocks || width == 0
      || width >= state->apparent_blocks || !baseline) {
    return SQLITE_REPAIR_NO_MATCH;
  }
  const uint64_t radius = support >= SQLITE_GAP_LOCAL_MINIMUM_SUPPORT
      ? SQLITE_GAP_GRID_SAMPLES : 0;
  uint64_t key = sqlite_mapping_hash(base_mapping, total_blocks);
  const uint64_t fields[] = {layout->extent, layout->page_size, layout->usable_size,
      layout->page_count, layout->largest_root_page, total_blocks,
      scalpel_state.blocksize, boundary, width, support, radius, compose,
      baseline->error_count, baseline->first_page, baseline->last_page,
      (uint64_t)baseline->result_code, baseline->valid};
  for (size_t index = 0; index < sizeof(fields) / sizeof(fields[0]); index++) {
    key = (key ^ fields[index]) * UINT64_C(1099511628211);
  }
  SqliteRadiusProgress *p = &sqlite_radius_begin(
      state, key, boundary, width, radius, baseline, (*candidate)->needleidx)->progress;
  *ranking = p;
  while (!p->complete && p->next_trial <= radius * 2) {
    const uint64_t trial = p->next_trial++;
    const uint64_t distance = (trial + 1) / 2;
    const bool backward = trial != 0 && trial % 2 == 0;
    uint64_t target;
    if (backward) {
      if (distance >= boundary) {
        continue;
      }
      target = boundary - distance;
    }
    else {
      if (distance >= total_blocks - boundary) {
        continue;
      }
      target = boundary + distance;
    }
    const SqliteRepairDescriptor repair = {
        .target = target, .width = width, .source = 0, .valid = 1, .reserved = 0};
    if (!sqlite_apply_gap_descriptor(base_mapping, total_blocks, &repair, trial_mapping)) {
      continue;
    }
    SqliteIntegrity integrity;
    if (sqlite_mapping_check(trial_mapping, total_blocks, layout->extent, trial_data,
                             &integrity)) {
      p->best_gap = repair;
      p->best_integrity = integrity;
      p->matched = 1;
      p->complete = 1;
      break;
    }
    if (trial == 0 && support >= SQLITE_GAP_LOCAL_MINIMUM_SUPPORT
        && state->stage == SQLITE_SEARCH_INITIAL_PROBES && !state->best_gap.valid) {
      state->best_gap = repair;
      state->best_gap_integrity = integrity;
    }
    if (compose && sqlite_integrity_composition_better(&integrity, &p->best_integrity)) {
      p->best_gap = repair;
      p->best_integrity = integrity;
      p->improved = 1;
    }
    if (sqlite_reassembly_poll(work, candidate, uuidp, uuidc, state, iterations)) {
      return SQLITE_REPAIR_STOPPED;
    }
  }
  p->complete = 1;
  return p->matched ? SQLITE_REPAIR_MATCH
      : (p->improved ? SQLITE_REPAIR_PLAUSIBLE : SQLITE_REPAIR_NO_MATCH);
}

// Retain accepted repairs and the parent integrity-trial frontier through nested yields.
static inline SqliteRepairResult sqlite_compose_multi_region(
    ThreadWork *work, CarveInfo **candidate, uuid_string_t uuidp, uuid_string_t uuidc,
    const SqliteLayout *layout, const SqliteIntegrity *baseline,
    const int64_t *two_gap_mapping, uint64_t total_blocks,
    const SqliteRepairDescriptor *second_gap, uint64_t second_transition,
    uint64_t transition_count, const uint64_t *boundaries, const uint64_t *widths,
    const bool *zero_backed, uint8_t *trial_data, int64_t *trial_mapping,
    int64_t *current_mapping, int64_t *solution_mapping, SqliteIntegrity *final_result,
    SqliteCarveState *state,
    uint64_t *iterations) {
  uint64_t key = sqlite_mapping_hash(two_gap_mapping, total_blocks);
  const uint64_t fields[] = {layout->extent, layout->page_size, layout->usable_size,
      layout->page_count, layout->largest_root_page, total_blocks, scalpel_state.blocksize,
      second_gap->target, second_gap->width, second_gap->source, second_transition,
      transition_count, baseline->valid, baseline->error_count, baseline->first_page,
      baseline->last_page, (uint64_t)baseline->result_code};
  for (size_t field = 0; field < sizeof(fields) / sizeof(fields[0]); field++) {
    key = (key ^ fields[field]) * UINT64_C(1099511628211);
  }
  for (uint64_t slot = 0; slot < transition_count; slot++) {
    key = (key ^ boundaries[slot]) * UINT64_C(1099511628211);
    key = (key ^ widths[slot]) * UINT64_C(1099511628211);
    key = (key ^ zero_backed[slot]) * UINT64_C(1099511628211);
  }
  SqliteMultiRegionProgress *p = &sqlite_multi_region_begin(
      state, key, baseline, (*candidate)->needleidx)->progress;
  memcpy(current_mapping, two_gap_mapping, total_blocks * sizeof(*current_mapping));
  uint64_t visited_hashes[SQLITE_PAGE_TRANSITION_LIMIT + 1] = {0};
  uint64_t visited_count = 1;
  visited_hashes[0] = sqlite_mapping_hash(current_mapping, total_blocks);
  // Rebuild scratch buffers without repeating any integrity trial.
  for (uint64_t slot = 0; slot < p->chain_count; slot++) {
    if (!sqlite_apply_ooo_descriptor(current_mapping, total_blocks,
                                     &p->chain[slot], trial_mapping)) {
      handle_error(SCALPEL_ERROR_CHECKPOINT, "invalid SQLite multi-region chain",
                   __LINE__, __FILE__);
    }
    memcpy(current_mapping, trial_mapping, total_blocks * sizeof(*current_mapping));
    visited_hashes[visited_count++] = sqlite_mapping_hash(current_mapping, total_blocks);
  }
  const uint64_t page_blocks = CEILDIV(layout->page_size, scalpel_state.blocksize);
  while (!p->complete && p->chain_count < SQLITE_PAGE_TRANSITION_LIMIT) {
    memcpy(solution_mapping, current_mapping, total_blocks * sizeof(*solution_mapping));
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
        transition_count
        + isolated_page_count + 1;

    for (; p->transition < repair_probe_count; p->transition++) {
      const uint64_t transition = p->transition;
      const bool ranked_transition_probe =
          transition < transition_count;
      const bool isolated_page_probe =
          !ranked_transition_probe
          && transition
                 < transition_count
                       + isolated_page_count;
      const bool diagnostic_probe =
          !ranked_transition_probe && !isolated_page_probe;
      uint64_t ooo_target = 0;
      uint64_t ooo_width = 0;
      bool exact_target = false;
      if (diagnostic_probe) {
        ooo_target = sqlite_failure_block(
            &p->current_integrity, layout, current_mapping,
            scalpel_state.blocksize, total_blocks);
        if (ooo_target == 0) {
          ooo_target = sqlite_page_block(
              p->current_integrity.first_page, layout,
              scalpel_state.blocksize, total_blocks);
        }
        if (ooo_target == 0 || ooo_target >= total_blocks) {
          continue;
        }
      }
      else if (isolated_page_probe) {
        ooo_target = isolated_page_targets[
            transition - transition_count];
        ooo_width = 1;
        exact_target = true;
      }
      else {
        if (!p->transition_active
            && (transition == second_transition
                || (p->repaired_mask & (UINT32_C(1) << transition)))) {
          continue;
        }
        if (!p->transition_active && p->multi_region_valid
            && !zero_backed[transition]) {
          continue;
        }
        ooo_target = boundaries[transition];
        ooo_width = widths[transition];
        exact_target = true;
        if (ooo_target > second_gap->target) {
          if (ooo_target - second_gap->target
              < second_gap->width) {
            continue;
          }
          ooo_target -= second_gap->width;
        }
        if (ooo_target == 0 || ooo_target >= total_blocks
            || ooo_width == 0
            || ooo_width > total_blocks - ooo_target) {
          continue;
        }
      }

      p->transition_active = 1;
      SqliteRepairList ranked_repairs = {
          .limit = SQLITE_COMPOSED_REPAIR_PROBE_LIMIT,
          .include_internal_sources = true};
      SqliteRepairResult result = sqlite_probe_ooo_repair(
          work, candidate, uuidp, uuidc, layout,
          &p->current_integrity, current_mapping, total_blocks,
          ooo_target, exact_target, ooo_width, trial_data,
          trial_mapping, solution_mapping, NULL, false, true,
          false, &ranked_repairs, state, iterations);
      if (result == SQLITE_REPAIR_STOPPED || !*candidate) {
        free(ranked_repairs.repairs);
        return SQLITE_REPAIR_STOPPED;
      }
      if (ranked_repairs.allocation_failed) {
        check_memory_allocation(NULL, __LINE__, __FILE__, "SQLite multi-region repairs");
      }
      uint64_t repair_hash = UINT64_C(1469598103934665603);
      for (uint64_t slot = 0; slot < ranked_repairs.count; slot++) {
        const SqliteRepairDescriptor *repair = &ranked_repairs.repairs[slot];
        const uint64_t fields[] = {repair->target, repair->width, repair->source,
                                  repair->valid, repair->reserved};
        for (size_t field = 0; field < sizeof(fields) / sizeof(fields[0]); field++) {
          repair_hash = (repair_hash ^ fields[field]) * UINT64_C(1099511628211);
        }
      }
      if (p->list_ready && (p->repair_count != ranked_repairs.count
                           || p->repair_hash != repair_hash)) {
        handle_error(SCALPEL_ERROR_CHECKPOINT, "changed SQLite multi-region repair list",
                     __LINE__, __FILE__);
      }
      p->repair_count = ranked_repairs.count;
      p->repair_hash = repair_hash;
      p->list_ready = 1;
      // Rematerializing the child list resets its scratch solution. Restore our own winner.
      if (p->best.valid && !sqlite_apply_ooo_descriptor(
              current_mapping, total_blocks, &p->best, solution_mapping)) {
        handle_error(SCALPEL_ERROR_CHECKPOINT, "invalid SQLite multi-region best repair",
                     __LINE__, __FILE__);
      }
      for (uint64_t repair = p->next_repair;
           repair < ranked_repairs.count; repair++) {
        p->next_repair = repair + 1;
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
          p->next_integrity = ranked_integrity;
          p->best = ranked_repairs.repairs[repair];
          p->multi_region_valid = true;
          if (ranked_transition_probe) {
            p->repaired_mask |= UINT32_C(1) << transition;
          }
          break;
        }
        if (sqlite_integrity_composition_better(
                &ranked_integrity, &p->next_integrity)) {
          memcpy(solution_mapping, trial_mapping,
                 total_blocks * sizeof(*solution_mapping));
          p->next_integrity = ranked_integrity;
          p->best = ranked_repairs.repairs[repair];
          if (ranked_transition_probe) {
            p->repaired_mask |= UINT32_C(1) << transition;
          }
        }
        if (sqlite_reassembly_poll(
                work, candidate, uuidp, uuidc, state,
                iterations)) {
          free(ranked_repairs.repairs);
          return SQLITE_REPAIR_STOPPED;
        }
      }
      free(ranked_repairs.repairs);
      p->transition_active = 0;
      p->list_ready = 0;
      p->next_repair = p->repair_count = p->repair_hash = 0;
      if (p->multi_region_valid || p->best.valid) {
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
    if (!p->best.valid) {
      handle_error(SCALPEL_ERROR_CHECKPOINT, "missing SQLite multi-region chain repair",
                   __LINE__, __FILE__);
    }
    p->chain[p->chain_count++] = p->best;
    visited_hashes[visited_count++] = next_hash;
    memcpy(current_mapping, solution_mapping, total_blocks * sizeof(*current_mapping));
    p->current_integrity = p->next_integrity;
    memset(&p->best, 0, sizeof(p->best));
    p->transition = 0;
  }
  if (!p->complete) {
    sqlite_mapping_check(current_mapping, total_blocks, layout->extent,
                         trial_data, &p->final_integrity);
    p->complete = 1;
    p->transition_active = p->list_ready = 0;
    p->next_repair = p->repair_count = p->repair_hash = 0;
    memset(&p->best, 0, sizeof(p->best));
  }
  if (p->final_integrity.valid) {
    memcpy(solution_mapping, current_mapping, total_blocks * sizeof(*solution_mapping));
  }
  *final_result = p->final_integrity;
  return p->final_integrity.valid ? SQLITE_REPAIR_MATCH : SQLITE_REPAIR_NO_MATCH;
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
          SqliteTransitionRankingProgress *ranking = NULL;
          const SqliteRepairResult ranking_result = sqlite_rank_transition_targets(
              work, candidate, uuidp, uuidc, layout, base_mapping, total_blocks,
              first_target, boundary, transition_gaps[gap_transition], NULL, 0,
              trial_data, composition_mapping, state, iterations, &ranking);
          if (ranking_result == SQLITE_REPAIR_STOPPED) {
            return ranking_result;
          }
          if (ranking && ranking->usable) {
            gap_usable[gap_transition] = true;
            gap_clean[gap_transition] = ranking->clean;
            gap_targets[gap_transition] = ranking->best_target;
            gap_integrities[gap_transition] = ranking->best_integrity;
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
          SqliteTransitionScanProgress *scan = NULL;
          if (sqlite_scan_repaired_transitions(
                  work, candidate, uuidp, uuidc, layout, composition_mapping, total_blocks,
                  state, iterations, &scan) == SQLITE_REPAIR_STOPPED) {
            return SQLITE_REPAIR_STOPPED;
          }
          if (!scan) {
            continue;
          }
          uint64_t repaired_boundaries[SQLITE_PAGE_TRANSITION_LIMIT] = {0};
          uint64_t repaired_widths[SQLITE_PAGE_TRANSITION_LIMIT] = {0};
          uint64_t repaired_support[SQLITE_PAGE_TRANSITION_LIMIT] = {0};
          uint64_t repaired_gap_targets[SQLITE_PAGE_TRANSITION_LIMIT] = {0};
          bool repaired_zero_backed[SQLITE_PAGE_TRANSITION_LIMIT] = {false};
          bool repaired_page_aligned[SQLITE_PAGE_TRANSITION_LIMIT] = {false};
          uint64_t repaired_transition_count = scan->count;
          for (uint64_t slot = 0; slot < repaired_transition_count; slot++) {
            repaired_boundaries[slot] = scan->boundaries[slot];
            repaired_widths[slot] = scan->widths[slot];
            repaired_support[slot] = scan->support[slot];
            repaired_gap_targets[slot] = scan->gap_targets[slot];
            repaired_zero_backed[slot] = scan->zero_backed[slot] != 0;
            repaired_page_aligned[slot] = scan->page_aligned[slot] != 0;
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
            SqliteTransitionRankingProgress *ranking = NULL;
            const SqliteRepairResult ranking_result = sqlite_rank_transition_targets(
                work, candidate, uuidp, uuidc, layout, composition_mapping, total_blocks,
                first_target, repaired_boundaries[transition], repaired_widths[transition],
                &gap_integrity, one_gap_layout_evidence, trial_data, trial_mapping,
                state, iterations, &ranking);
            if (ranking_result == SQLITE_REPAIR_STOPPED) {
              return ranking_result;
            }
            if (!ranking || !ranking->usable) {
              continue;
            }
            const uint64_t transition_target = ranking->best_target;
            const SqliteIntegrity transition_integrity = ranking->best_integrity;
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
            SqliteIntegrity final_multi_region_integrity;
            result = sqlite_compose_multi_region(
                work, candidate, uuidp, uuidc, layout, &ranked_second_gap_integrity,
                two_gap_mapping, total_blocks, &ranked_second_gap,
                ranked_second_gap_transition, repaired_transition_count,
                repaired_boundaries, repaired_widths, repaired_zero_backed,
                trial_data, trial_mapping, current_mapping, solution_mapping,
                &final_multi_region_integrity, state, iterations);
            if (result == SQLITE_REPAIR_STOPPED || !*candidate) {
              free(current_mapping);
              free(two_gap_mapping);
              return SQLITE_REPAIR_STOPPED;
            }
            const bool multi_region_valid = result == SQLITE_REPAIR_MATCH;

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
              // Completion trials reuse this buffer. Inspect the selected solution, not the
              // last alternative (which may differ when a completed query resumes).
              const bool have_solution_bytes = sqlite_mapping_materialize(
                  solution_mapping, total_blocks, layout->extent, trial_data);
              for (uint64_t repair = 0; repair < ooo_count;
                   repair++) {
                if (!have_solution_bytes) {
                  break;
                }
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

              result = sqlite_preserve_permutations(
                  work, candidate, uuidp, uuidc, layout, solution_mapping,
                  total_blocks, ooo_targets, ooo_widths, ooo_count,
                  trial_data, trial_mapping, state, iterations);
              if (result == SQLITE_REPAIR_STOPPED || !*candidate) {
                free(current_mapping);
                free(two_gap_mapping);
                return SQLITE_REPAIR_STOPPED;
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
        SqliteRadiusProgress *ranking = NULL;
        result = sqlite_rank_radius_targets(
            work, candidate, uuidp, uuidc, layout, base_mapping, total_blocks,
            best_boundary, best_gap, best_support, integrity,
            compose && composition_mapping != NULL, trial_data, trial_mapping,
            state, iterations, &ranking);
        if (result == SQLITE_REPAIR_STOPPED || !*candidate) {
          return SQLITE_REPAIR_STOPPED;
        }
        if (!ranking) {
          return SQLITE_REPAIR_NO_MATCH;
        }
        const SqliteIntegrity local_integrity = ranking->best_integrity;
        const SqliteRepairDescriptor local_gap = ranking->best_gap;
        if (result == SQLITE_REPAIR_MATCH) {
          if (!sqlite_apply_gap_descriptor(
                  base_mapping, total_blocks, &local_gap, solution_mapping)) {
            return SQLITE_REPAIR_NO_MATCH;
          }
          sqlite_write_mapping_hypothesis(
              *candidate, solution_mapping, total_blocks, layout->extent);
          return SQLITE_REPAIR_MATCH;
        }
        if (ranking->improved) {
          if (!sqlite_apply_gap_descriptor(
                  base_mapping, total_blocks, &local_gap, composition_mapping)) {
            return SQLITE_REPAIR_NO_MATCH;
          }
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

// Scope the grid to the actual blocks it can use. Changes elsewhere in the image do not erase a
// completed ranking, but changed source adjacency must not reuse stale apparent positions.
static inline uint64_t sqlite_gap_grid_view(
    const SqliteLayout *layout, const SqliteIntegrity *baseline,
    const int64_t *base_mapping, uint64_t total_blocks,
    uint64_t maximum_width) {
  uint64_t view = sqlite_mapping_hash(base_mapping, total_blocks);
  const uint64_t apparent_blocks =
      filemirror_apparent_blocks(scalpel_state.filemirror);
  const uint64_t fields[] = {layout->extent, layout->page_size, total_blocks,
      scalpel_state.blocksize, maximum_width, baseline->valid,
      baseline->error_count, baseline->first_page, baseline->last_page,
      (uint64_t)baseline->result_code};
  for (size_t index = 0; index < sizeof(fields) / sizeof(fields[0]); index++) {
    view = (view ^ fields[index]) * UINT64_C(1099511628211);
  }
  for (uint64_t slot = 1; slot < total_blocks; slot++) {
    for (uint64_t gap = 1; gap <= maximum_width; gap++) {
      int64_t actual = -1;
      if (base_mapping[slot] >= 0
          && base_mapping[slot] <= INT64_MAX - (int64_t)gap
          && (uint64_t)base_mapping[slot] + gap < apparent_blocks) {
        actual = filemirror_actual_blocknumber(
            scalpel_state.filemirror, base_mapping[slot] + (int64_t)gap);
      }
      view = (view ^ (uint64_t)actual) * UINT64_C(1099511628211);
    }
  }
  return view;
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
      || !best_repair || !best_integrity || !state) {
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
  if (apparent_blocks < 2) {
    return SQLITE_REPAIR_NO_MATCH;
  }
  if (maximum_width >= apparent_blocks) {
    maximum_width = apparent_blocks - 1;
  }

  SqliteGapGridState *grid = &state->gap_grid;
  const uint64_t view = sqlite_gap_grid_view(
      layout, baseline_integrity, base_mapping, total_blocks, maximum_width);
  if (!grid->active || grid->view != view) {
    if (grid->active) {
      memset(best_repair, 0, sizeof(*best_repair));
      *best_integrity = *baseline_integrity;
    }
    memset(grid, 0, sizeof(*grid));
    grid->active = 1;
    grid->view = view;
    grid->width = 1;
    grid->width_integrity = *baseline_integrity;
  }
  while (grid->width <= maximum_width) {
    while (grid->phase < 2) {
      if (grid->phase == 1 && !grid->width_best.valid) {
        break;
      }
      if (!grid->window_ready) {
        grid->next_target = 1;
        grid->last_target = total_blocks - 1;
        grid->step = stride;
        if (grid->phase == 1) {
          grid->next_target = grid->width_best.target > stride
              ? grid->width_best.target - stride + 1 : 1;
          const uint64_t after = total_blocks - 1 - grid->width_best.target;
          grid->last_target = grid->width_best.target
              + (stride - 1 < after ? stride - 1 : after);
          grid->step = 1;
        }
        grid->window_ready = 1;
      }
      while (grid->next_target <= grid->last_target) {
        const uint64_t target = grid->next_target;
        const SqliteRepairDescriptor repair = {
            .target = target,
            .width = grid->width,
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
            memset(grid, 0, sizeof(*grid));
            return SQLITE_REPAIR_MATCH;
          }
          if (sqlite_integrity_composition_better(
                  &integrity, &grid->width_integrity)) {
            grid->width_best = repair;
            grid->width_integrity = integrity;
          }
          if (sqlite_integrity_composition_better(
                  &integrity, best_integrity)) {
            *best_repair = repair;
            *best_integrity = integrity;
          }
        }
        grid->next_target = grid->last_target - target < grid->step
            ? grid->last_target + 1 : target + grid->step;
        if (sqlite_reassembly_poll(work, candidate, uuidp, uuidc,
                                   state, iterations)) {
          return SQLITE_REPAIR_STOPPED;
        }
      }
      grid->phase++;
      grid->window_ready = 0;
    }
    grid->width++;
    grid->phase = 0;
    grid->window_ready = 0;
    memset(&grid->width_best, 0, sizeof(grid->width_best));
    grid->width_integrity = *baseline_integrity;
  }
  memset(grid, 0, sizeof(*grid));
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

// Only the current extension's source window and base mapping affect resumption.
static inline uint64_t sqlite_extension_view(
    const SqliteLayout *layout, const int64_t *base_mapping,
    uint64_t total_blocks, uint64_t preferred_target, bool preferred_only,
    uint64_t maximum_width, const SqliteRepairDescriptor *repair) {
  uint64_t view = sqlite_mapping_hash(base_mapping, total_blocks);
  uint64_t apparent_blocks = filemirror_apparent_blocks(scalpel_state.filemirror);
  if (repair->source >= apparent_blocks
      || repair->width > apparent_blocks - repair->source) {
    return 0;
  }
  const uint64_t scope[] = {layout->extent, layout->page_size, total_blocks,
      apparent_blocks, scalpel_state.blocksize, preferred_target,
      preferred_only, maximum_width, repair->target, repair->width,
      repair->source};
  for (size_t index = 0; index < sizeof(scope) / sizeof(scope[0]); index++) {
    view = (view ^ scope[index]) * UINT64_C(1099511628211);
  }
  uint64_t first = repair->source > SQLITE_FAST_PROBE_MAXIMUM_RUN_BLOCKS
      ? repair->source - SQLITE_FAST_PROBE_MAXIMUM_RUN_BLOCKS : 0;
  uint64_t last = repair->source + repair->width;
  uint64_t available = apparent_blocks - last;
  last += available < SQLITE_FAST_PROBE_MAXIMUM_RUN_BLOCKS
      ? available : SQLITE_FAST_PROBE_MAXIMUM_RUN_BLOCKS;
  for (uint64_t source = first; source < last; source++) {
    int64_t actual = filemirror_actual_blocknumber(scalpel_state.filemirror,
                                                   (int64_t)source);
    view = (view ^ (uint64_t)actual) * UINT64_C(1099511628211);
  }
  return view;
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

  SqliteOooExtensionState *pending = &state->extension;
  if (pending->active) {
    if (!sqlite_extension_state_valid(pending, state)
        || pending->view != sqlite_extension_view(
            layout, base_mapping, total_blocks, preferred_target,
            preferred_only, maximum_width, &pending->repair)) {
      memset(pending, 0, sizeof(*pending));
      sqlite_cursor_reset(cursor);
      if (best_repair && best_integrity) {
        memset(best_repair, 0, sizeof(*best_repair));
        *best_integrity = state->baseline_integrity;
      }
    }
    else {
      // The outer cursor already names the next source. Finish the saved clean
      // source first, reconstructing its last accepted extension without replay.
      memcpy(solution_mapping, base_mapping,
             total_blocks * sizeof(*solution_mapping));
      for (uint64_t offset = 0; offset < pending->last.width; offset++) {
        solution_mapping[pending->last.target + offset] =
            (int64_t)(pending->last.source + offset);
      }
      bool ambiguity_closed = false;
      SqliteRepairResult result = sqlite_preserve_ooo_extensions(
          work, candidate, uuidp, uuidc, layout, base_mapping, total_blocks,
          pending->repair.target, pending->repair.width,
          pending->repair.source, trial_data, trial_mapping, solution_mapping,
          state, iterations, &ambiguity_closed, pending);
      if (result == SQLITE_REPAIR_STOPPED || !*candidate) {
        return SQLITE_REPAIR_STOPPED;
      }
      if (ambiguity_closed) {
        if (state->stage != SQLITE_SEARCH_RANKED_GAP_OOO) {
          memset(pending, 0, sizeof(*pending));
        }
        return SQLITE_REPAIR_MATCH;
      }
      memset(pending, 0, sizeof(*pending));
    }
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
            memset(pending, 0, sizeof(*pending));
            pending->repair = (SqliteRepairDescriptor){
                .target = target, .width = run_blocks,
                .source = source, .valid = 1};
            pending->last = pending->repair;
            pending->next_extension = 1;
            pending->owner_stage = state->stage;
            pending->active = 1;
            pending->view = sqlite_extension_view(
                layout, base_mapping, total_blocks, preferred_target,
                preferred_only, maximum_width, &pending->repair);
            bool ambiguity_closed = false;
            const SqliteRepairResult extension_result =
                sqlite_preserve_ooo_extensions(
                    work, candidate, uuidp, uuidc, layout,
                    base_mapping, total_blocks, target, run_blocks,
                    source, trial_data, trial_mapping,
                    solution_mapping, state,
                    iterations, &ambiguity_closed, pending);
            if (extension_result == SQLITE_REPAIR_STOPPED
                || !*candidate) {
              return SQLITE_REPAIR_STOPPED;
            }
            if (ambiguity_closed) {
              // Ranked recovery still examines neighboring gap boundaries.
              // Retain its selected reconstruction until that work finishes.
              if (state->stage != SQLITE_SEARCH_RANKED_GAP_OOO) {
                memset(pending, 0, sizeof(*pending));
              }
              return SQLITE_REPAIR_MATCH;
            }
            memset(pending, 0, sizeof(*pending));
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
  if (state->probe_count != 0 || state->gap_probe_count != 0
      || state->pair_probe_count != 0 || state->page_completion_count != 0
      || state->permutation_count != 0 || state->transition_ranking_count != 0
      || state->transition_scan_count != 0 || state->radius_count != 0
      || state->multi_region_count != 0) {
    state->probe_view = sqlite_probe_source_view((*candidate)->needleidx);
  }
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
        state->probe_step = 1;
      }
      if (state->probe_step == 1) {
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
        state->probe_step = 2;
      }
      if (state->probe_step == 2) {
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
        state->probe_step = 3;
      }
      // A physical gap shifts the remaining page stream and normally produces errors over a wide
      // page range. Rank that gap before source discovery; damage confined to one or two pages
      // retains the OOO-first ordering.
      if (state->probe_step == 3 && !localized_damage) {
        if (!state->best_gap.valid || state->gap_grid.active) {
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
        state->probe_step = 4;
        state->stage = state->best_gap.valid
            ? SQLITE_SEARCH_RANKED_GAP_OOO
            : SQLITE_SEARCH_BASE_GAP;
        sqlite_cursor_reset(&state->cursor);
        continue;
      }
      if (state->probe_step == 3) {
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
        state->probe_step = 4;
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
        // Finish the retained short-source probes before entering the complete scan.
        if (state->outer_cursor.pass == 0) {
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
          state->outer_cursor.pass = 1;
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
