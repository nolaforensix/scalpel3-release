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

#if !defined(SCALPEL_CFBF_H)
#define SCALPEL_CFBF_H

#include "gif.h"
#include "jpg.h"
#include "png.h"
#include "scalpel.h"

#include <inttypes.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>

#include "simde/simde/x86/avx2.h"

#define CFBF_HEADER_SIZE                   UINT64_C(512)
#define CFBF_DIFAT_HEADER_ENTRIES          UINT32_C(109)
#define CFBF_DIRECTORY_ENTRY_SIZE          UINT32_C(128)
#define CFBF_MINI_STREAM_CUTOFF            UINT32_C(4096)
#define CFBF_MAGIC_SIZE                     8u
#define CFBF_STATE_MAGIC                   UINT32_C(0x43464246)
#define CFBF_STATE_VERSION                UINT32_C(47)
#define CFBF_FREE_SECTOR                   UINT32_C(0xffffffff)
#define CFBF_END_OF_CHAIN                  UINT32_C(0xfffffffe)
#define CFBF_FAT_SECTOR                    UINT32_C(0xfffffffd)
#define CFBF_DIFAT_SECTOR                  UINT32_C(0xfffffffc)
#define CFBF_MAX_REGULAR_SECTOR            UINT32_C(0xfffffffa)
#define CFBF_NO_STREAM                     UINT32_C(0xffffffff)
#define CFBF_AMBIGUOUS_DIRECTORY_PARENT    UINT32_C(0xfffffffe)
#define CFBF_VISIO_MAX_DEPTH                64u
#define CFBF_MAXIMUM_SIZE                   UINT64_C(4294967296)
#define CFBF_BIFF_TEMPLATE_RECORD           UINT16_C(0x0060)
#define CFBF_BIFF_ADDIN_RECORD              UINT16_C(0x0087)
#define CFBF_NEARBY_SUFFIX_SHIFT_LIMIT      UINT64_C(8)
#define CFBF_NEARBY_RUN_WIDTH_LIMIT         UINT64_C(8)
#define CFBF_UNIFORM_CONCENTRATION_LIMIT    UINT64_C(512)
#define CFBF_STRONG_FILLER_CONCENTRATION_LIMIT UINT64_C(384)
#define CFBF_MINIMUM_BOUNDARY_EVIDENCE       INT64_C(32)
#define CFBF_MODEL_STRONG_FILLER_CONFIDENCE   UINT32_C(3)
#define CFBF_MODEL_FILLER_CONFIDENCE         UINT32_C(10)
#define CFBF_MODEL_BOUNDARY_RADIUS             UINT32_C(4)
#define CFBF_MODEL_PROFILE_SAMPLE_LIMIT       UINT32_C(64)
#define CFBF_MODEL_SINGLE_GAP_LIMIT            UINT32_C(16)
#define CFBF_MODEL_GAP_LIMIT                  UINT32_C(64)
#define CFBF_MODEL_SOURCE_LIMIT               UINT32_C(512)
#define CFBF_SUPPORTED_GAP_LIMIT                UINT32_C(16)
// This bounds early prioritization only; the complete pair search runs later.
#define CFBF_SUPPORTED_PAIR_PREPASS_GAP_LIMIT    UINT32_C(4)
#define CFBF_RANKED_SOURCE_LIMIT              UINT32_C(128)
#define CFBF_CONTENT_PAIR_LIMIT                 UINT32_C(64)
#define CFBF_CONTENT_PAIR_HYPOTHESIS_LIMIT      UINT32_C(32)
#define CFBF_MODEL_COMPLETE_HYPOTHESIS_LIMIT   UINT32_C(1)
#define CFBF_MODEL_PARTIAL_HYPOTHESIS_LIMIT    UINT32_C(1)
#define CFBF_CONTENT_TARGET_LIMIT                UINT32_C(8)
#define CFBF_CONTENT_SOURCE_LIMIT               UINT32_C(64)
#define CFBF_CONTENT_HYPOTHESIS_LIMIT          UINT32_C(128)
// Bound this heuristic so the complete fallback searches remain reachable.
#define CFBF_CONTENT_TRIAL_LIMIT                UINT32_C(128)
#define CFBF_ATOMIC_PREFERRED_GAP_LIMIT           UINT32_C(4)
#define CFBF_SUFFIX_HYPOTHESIS_LIMIT              UINT32_C(32)
// Small concentration fluctuations are noise relative to boundary evidence.
#define CFBF_CONTENT_CONCENTRATION_GRANULARITY  UINT64_C(64)
#define CFBF_ISOLATED_HYPOTHESIS_LIMIT           UINT32_C(64)
#define CFBF_ISOLATED_TARGET_HYPOTHESIS_LIMIT    UINT32_C(32)
#define CFBF_ISOLATED_SINGLE_HYPOTHESIS_LIMIT     UINT32_C(4)
#define CFBF_DETACHED_SOURCE_NONE                  UINT32_C(0)
#define CFBF_DETACHED_SOURCE_WEAK_BOUNDARY         UINT32_C(1)
#define CFBF_DETACHED_SOURCE_ISOLATED_MIN          UINT32_C(2)
#define CFBF_CONTEXT_FINGERPRINT_BINS          UINT32_C(16)
#define CFBF_CONTEXT_CACHE_LIMIT               UINT64_C(268435456)
#define CFBF_MAXIMUM_REPEATED_TEXT_CODEPOINT UINT32_C(1024)
#define CFBF_MSPHOTOED_PALETTE_OFFSET          UINT64_C(18)
#define CFBF_MSPHOTOED_PIXEL_OFFSET           UINT64_C(822)
#define CFBF_MPP_VIEW_STYLE_PRIMARY_KEY     UINT32_C(0x22400008)
#define CFBF_MPP_VIEW_STYLE_COMPANION_KEY   UINT32_C(0x22400030)
#define CFBF_REASSEMBLY_FINALIZED            UINT32_C(8)
#define CFBF_REASSEMBLY_INDEXED_COMPLETION   UINT32_C(9)
#define CFBF_REASSEMBLY_RANKED_RUNS           UINT32_C(10)
#define CFBF_REASSEMBLY_CONTENT_COMBINED       UINT32_C(11)
#define CFBF_REASSEMBLY_CONTENT_COMPLETE       UINT32_C(12)
#define CFBF_REASSEMBLY_STRUCTURAL_ANCHORS     UINT32_C(13)
#define CFBF_STRUCTURAL_RESUME_TARGET_SCAN       UINT32_C(1)
#define CFBF_STRUCTURAL_RESUME_SOURCE_SCAN       UINT32_C(2)
#define CFBF_STRUCTURAL_SOURCE_TRIAL_LIMIT     UINT64_C(128)

typedef enum CfbfProfile {
  CFBF_PROFILE_UNKNOWN = 0,
  CFBF_PROFILE_DOC,
  CFBF_PROFILE_XLS,
  CFBF_PROFILE_PPT,
  CFBF_PROFILE_MSG,
  CFBF_PROFILE_PUB,
  CFBF_PROFILE_VSD,
  CFBF_PROFILE_MPP,
  CFBF_PROFILE_BINDER,
  CFBF_PROFILE_ENCRYPTED_OFFICE,
  CFBF_PROFILE_DOT,
  CFBF_PROFILE_XLT,
  CFBF_PROFILE_XLA,
  CFBF_PROFILE_PPA,
  CFBF_PROFILE_OFT
} CfbfProfile;

typedef enum CfbfSemanticStrength {
  CFBF_SEMANTIC_INVALID = 0,
  CFBF_SEMANTIC_PLAUSIBLE,
  CFBF_SEMANTIC_STRONG
} CfbfSemanticStrength;

typedef struct CfbfSemanticEvidence {
  bool profile_evidence;
  uint32_t examined_payloads;
  uint32_t validated_payloads;
  uint32_t coherence_payloads;
  uint64_t coherence_cost;
  uint64_t coherence_extent;
} CfbfSemanticEvidence;

typedef struct CfbfDirectoryEntry {
  char name[65];
  uint8_t object_type;
  uint32_t left_sibling;
  uint32_t right_sibling;
  uint32_t child;
  uint32_t parent;
  uint8_t clsid[16];
  uint32_t start_sector;
  uint64_t stream_size;
} CfbfDirectoryEntry;

typedef struct CfbfLayout {
  const uint8_t *data;
  bool canonical;
  bool referenced_sector;
  uint64_t length;
  uint64_t sector_size;
  uint64_t mini_sector_size;
  uint64_t available_sectors;
  uint64_t highest_referenced_sector;
  uint64_t inferred_size;
  uint64_t failure_offset;
  uint32_t major_version;
  uint32_t mini_stream_cutoff;
  uint32_t first_directory_sector;
  uint32_t first_minifat_sector;
  uint32_t minifat_sector_count;
  uint32_t *fat;
  uint64_t fat_count;
  uint32_t *minifat;
  uint64_t minifat_count;
  CfbfDirectoryEntry *directories;
  uint64_t directory_count;
  uint64_t root_index;
  CfbfProfile profile;
} CfbfLayout;

typedef struct CfbfRepairCandidate {
  uint32_t valid;
  uint32_t authenticated;
  uint32_t complete;
  uint32_t profile;
  uint32_t profile_evidence;
  uint32_t semantic_strength;
  uint32_t coherence_payloads;
  uint32_t has_confidence;
  uint32_t all_positive;
  uint32_t target_strong;
  uint32_t target_exact;
  uint32_t source_isolation;
  uint32_t reserved;
  uint64_t slot;
  uint64_t width;
  uint64_t actual;
  uint64_t score;
  uint64_t coherence_cost;
  uint64_t coherence_extent;
  uint64_t context_distance;
  uint64_t target_concentration;
  uint64_t source_evidence;
  int64_t confidence_gain;
} CfbfRepairCandidate;

typedef struct CfbfAtomicCandidate {
  uint32_t valid;
  uint64_t suffix_slot;
  uint64_t suffix_shift;
  uint64_t target_slot;
  uint64_t width;
  uint64_t source_actual;
} CfbfAtomicCandidate;

typedef struct CfbfTrialResult {
  bool structurally_valid;
  bool profile_evidence;
  CfbfSemanticStrength semantic_strength;
  CfbfProfile profile;
  uint32_t examined_payloads;
  uint32_t validated_payloads;
  uint32_t coherence_payloads;
  uint64_t inferred_size;
  uint64_t failure_offset;
  uint64_t score;
  uint64_t coherence_cost;
  uint64_t coherence_extent;
} CfbfTrialResult;

typedef struct CfbfSuffixHypothesis {
  uint32_t valid;
  uint32_t has_confidence;
  uint32_t all_positive;
  uint32_t reserved;
  uint64_t slot;
  uint64_t shift;
  uint64_t score;
  uint64_t concentration;
  int64_t confidence_gain;
  int64_t boundary_evidence;
  CfbfTrialResult result;
} CfbfSuffixHypothesis;

typedef struct CfbfCarveState {
  uint32_t magic;
  uint32_t version;
  uint32_t profile;
  uint32_t semantic_strength;
  uint32_t initialized;
  uint32_t repairs;
  uint32_t search_phase;
  uint32_t suffix_pass;
  uint32_t pair_suffix_possible;
  uint32_t opaque_baseline_shared;
  uint32_t initial_tail_trimmed;
  uint32_t content_extent_expanded;
  uint32_t structural_shift_valid;
  uint32_t structural_search_complete;
  uint32_t structural_repairs;
  uint32_t structural_shift_support;
  uint32_t structural_reserved;
  uint32_t structural_coherence_payloads;
  uint32_t model_search_complete;
  uint32_t model_search_repairs;
  uint64_t inferred_size;
  uint64_t failure_offset;
  int64_t structural_shift;
  int64_t structural_resume_shift;
  uint64_t structural_shift_slot;
  uint64_t structural_shift_score;
  uint64_t structural_coherence_cost;
  uint64_t structural_coherence_extent;
  uint64_t structural_resume_actual;
  uint64_t structural_overlap_target;
  uint64_t structural_resume_source_order;
  uint64_t resume_slot;
  uint64_t resume_choice;
  uint64_t resume_run_width;
  uint64_t resume_run_left;
  uint32_t resume_source_pass;
  uint32_t atomic_resume_valid;
  uint32_t atomic_search_pass;
  uint64_t atomic_suffix_slot;
  uint64_t atomic_shift;
  uint64_t atomic_width_order;
  uint64_t atomic_target_slot;
  uint64_t atomic_source_actual;
  CfbfAtomicCandidate atomic_candidate;
  CfbfAtomicCandidate
      atomic_width_candidates[CFBF_NEARBY_RUN_WIDTH_LIMIT];
  CfbfRepairCandidate
      atomic_width_ranks[CFBF_NEARBY_RUN_WIDTH_LIMIT];
  uint32_t repair_candidate_valid;
  uint32_t repair_candidate_authenticated;
  uint32_t repair_candidate_complete;
  uint32_t repair_candidate_profile;
  uint32_t repair_candidate_profile_evidence;
  uint32_t repair_candidate_semantic_strength;
  uint32_t repair_candidate_coherence_payloads;
  uint32_t repair_candidate_has_confidence;
  uint32_t repair_candidate_all_positive;
  uint32_t repair_candidate_target_strong;
  uint32_t repair_candidate_target_exact;
  uint32_t repair_candidate_source_isolation;
  uint32_t repair_candidate_reserved;
  uint64_t repair_candidate_slot;
  uint64_t repair_candidate_width;
  uint64_t repair_candidate_actual;
  uint64_t repair_candidate_score;
  uint64_t repair_candidate_coherence_cost;
  uint64_t repair_candidate_coherence_extent;
  uint64_t repair_candidate_context_distance;
  uint64_t repair_candidate_target_concentration;
  uint64_t repair_candidate_source_evidence;
  int64_t repair_candidate_confidence_gain;
  CfbfRepairCandidate repair_alternate;
  CfbfRepairCandidate repair_semantic;
  CfbfRepairCandidate repair_isolated[CFBF_ISOLATED_HYPOTHESIS_LIMIT];
  uint32_t suffix_candidate_valid;
  uint32_t suffix_candidate_has_confidence;
  uint32_t suffix_candidate_all_positive;
  uint32_t suffix_candidate_reserved;
  uint64_t suffix_candidate_slot;
  uint64_t suffix_candidate_shift;
  uint64_t suffix_candidate_score;
  uint64_t suffix_candidate_concentration;
  int64_t suffix_candidate_confidence_gain;
  int64_t suffix_candidate_boundary_evidence;
  uint32_t suffix_hypothesis_count;
  CfbfSuffixHypothesis
      suffix_hypotheses[CFBF_SUFFIX_HYPOTHESIS_LIMIT];
} CfbfCarveState;

typedef struct CfbfSourceRunIterator {
  uint64_t width;
  uint64_t next_actual;
  uint64_t last_actual;
} CfbfSourceRunIterator;

typedef struct CfbfModelRun {
  uint32_t all_zero;
  uint64_t actual;
  uint64_t width;
  int64_t evidence;
  uint64_t confidence;
} CfbfModelRun;

typedef enum CfbfModelHypothesisKind {
  CFBF_MODEL_HYPOTHESIS_NONE = 0,
  CFBF_MODEL_HYPOTHESIS_SINGLE_GAP,
  CFBF_MODEL_HYPOTHESIS_GAP_PAIR,
  CFBF_MODEL_HYPOTHESIS_COMBINED
} CfbfModelHypothesisKind;

typedef struct CfbfModelHypothesis {
  uint32_t valid;
  CfbfModelHypothesisKind kind;
  uint32_t repairs;
  uint64_t target_slot;
  uint64_t shift;
  uint64_t first_actual;
  uint64_t first_width;
  uint64_t second_actual;
  uint64_t second_width;
  uint64_t run_slot;
  uint64_t run_width;
  uint64_t source_actual;
  CfbfTrialResult result;
} CfbfModelHypothesis;

typedef struct CfbfRankedSource {
  uint64_t actual;
  uint64_t context_distance;
  int64_t profile_gain;
  int64_t generic_gain;
  uint32_t reserved;
  uint32_t source_isolation;
  uint32_t profile_boundary_gain;
  uint32_t generic_boundary_gain;
  uint32_t profile_all_positive;
  uint32_t generic_all_positive;
} CfbfRankedSource;

typedef struct CfbfCombinedPair {
  uint32_t first_index;
  uint32_t second_index;
  uint32_t authenticated;
  uint32_t recoverable;
  uint32_t complete;
  uint32_t structurally_valid;
  uint32_t zero_runs;
  uint64_t score;
  uint64_t failure_offset;
  uint64_t target_concentration;
  uint64_t target_width;
  uint64_t concentration;
  uint64_t first_actual;
  uint64_t second_actual;
  int64_t minimum_evidence;
  int64_t evidence;
} CfbfCombinedPair;

typedef struct CfbfCombinedTarget {
  uint32_t gap_index;
  uint32_t all_zero;
  uint64_t slot;
  uint64_t width;
  uint64_t failure_distance;
  uint64_t concentration;
  int64_t evidence;
} CfbfCombinedTarget;

typedef struct CfbfContentHypothesis {
  uint32_t valid;
  uint32_t dirty;
  uint32_t pair_position;
  uint32_t target_gap_index;
  uint32_t repairs;
  uint64_t target_slot;
  uint64_t source_actual;
  CfbfTrialResult result;
} CfbfContentHypothesis;

typedef struct CfbfMappingIndexEntry {
  uint64_t actual_key;
  uint64_t logical_slot;
} CfbfMappingIndexEntry;

typedef struct CfbfMappingIndex {
  CfbfMappingIndexEntry *entries;
  uint64_t capacity;
} CfbfMappingIndex;

typedef struct CfbfMd4State {
  uint32_t words[4];
  uint64_t length;
  uint8_t block[64];
  uint32_t block_length;
} CfbfMd4State;

static const uint8_t cfbf_magic[CFBF_MAGIC_SIZE] = {
  0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1
};

// Root CLSIDs are stored in the mixed-endian byte order used by CFBF.
static const uint8_t cfbf_ppa_root_clsid[16] = {
  0xf0, 0x46, 0x72, 0x81, 0x0a, 0x72, 0xcf, 0x11,
  0x87, 0x18, 0x00, 0xaa, 0x00, 0x60, 0x26, 0x3b
};
static const uint8_t cfbf_oft_root_clsid[16] = {
  0x46, 0xf0, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00,
  0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46
};
static const uint8_t cfbf_word6_document_root_clsid[16] = {
  0x00, 0x09, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
  0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46
};
static const uint8_t cfbf_word6_template_root_clsid[16] = {
  0x01, 0x09, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
  0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46
};
static const uint8_t cfbf_word8_document_root_clsid[16] = {
  0x06, 0x09, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
  0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46
};
static const uint8_t cfbf_word8_template_root_clsid[16] = {
  0x07, 0x09, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
  0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46
};

static pthread_once_t cfbf_uniform_cache_once = PTHREAD_ONCE_INIT;
static _Atomic uint64_t *cfbf_uniform_cache_known = NULL;
static _Atomic uint64_t *cfbf_uniform_cache_value = NULL;
static uint8_t *cfbf_context_fingerprint_cache = NULL;
static uint64_t cfbf_uniform_cache_blocks = 0;
static uint64_t cfbf_uniform_cache_words = 0;
static pthread_mutex_t cfbf_uniform_cache_lock = PTHREAD_MUTEX_INITIALIZER;

static inline uint16_t cfbf_read_le16(const uint8_t *data);
static inline uint32_t cfbf_read_le32(const uint8_t *data);
static inline uint64_t cfbf_read_le64(const uint8_t *data);
static inline bool cfbf_range_available(uint64_t length, uint64_t offset,
                                        uint64_t size);
static inline void cfbf_note_sector(CfbfLayout *layout, uint32_t sector);
static inline bool cfbf_has_header(const uint8_t *data, uint64_t length);
static inline uint64_t cfbf_header_extent_lower_bound(
    const uint8_t *data, uint64_t length);
static inline uint64_t cfbf_header_search_extent(
    const uint8_t *data, uint64_t length, uint64_t current_extent);
static inline bool cfbf_sector_offset(const CfbfLayout *layout,
                                      uint32_t sector, uint64_t *offset);
static inline void cfbf_layout_clear(CfbfLayout *layout);
static inline bool cfbf_append_sector(uint32_t **sectors, uint64_t *count,
                                      uint64_t *capacity, uint32_t sector);
static inline bool cfbf_collect_fat_sectors(CfbfLayout *layout,
                                            uint32_t fat_sector_count,
                                            uint32_t first_difat_sector,
                                            uint32_t difat_sector_count,
                                            uint32_t **fat_sectors);
static inline bool cfbf_build_fat(CfbfLayout *layout,
                                  const uint32_t *fat_sectors,
                                  uint32_t fat_sector_count);
static inline bool cfbf_follow_chain(const CfbfLayout *layout,
                                     const uint32_t *fat,
                                     uint64_t fat_count,
                                     uint32_t first_sector,
                                     uint64_t expected_count,
                                     bool exact_length,
                                     uint32_t **sectors,
                                     uint64_t *sector_count,
                                     uint64_t *failure_offset);
static inline bool cfbf_parse_directory_name(const uint8_t *entry,
                                             char name[65]);
static inline bool cfbf_parse_directories(CfbfLayout *layout);
static inline bool cfbf_assign_directory_parents(CfbfLayout *layout);
static inline bool cfbf_build_minifat(CfbfLayout *layout);
static inline bool cfbf_validate_streams(CfbfLayout *layout);
static inline bool cfbf_name_equals(const CfbfDirectoryEntry *entry,
                                    const char *name);
static inline bool cfbf_name_starts_with(const CfbfDirectoryEntry *entry,
                                         const char *prefix);
static inline const CfbfDirectoryEntry *cfbf_find_directory(
    const CfbfLayout *layout, const char *name);
static inline const CfbfDirectoryEntry *cfbf_find_child_directory(
    const CfbfLayout *layout, const CfbfDirectoryEntry *parent,
    const char *name);
static inline bool cfbf_copy_regular_stream(const CfbfLayout *layout,
                                            uint32_t first_sector,
                                            uint64_t stream_size,
                                            uint8_t **data);
static inline bool cfbf_materialize_stream(const CfbfLayout *layout,
                                           const CfbfDirectoryEntry *entry,
                                           uint8_t **data,
                                           uint64_t *length);
static inline bool cfbf_stream_file_offset(
    const CfbfLayout *layout, const CfbfDirectoryEntry *entry,
    uint64_t stream_offset, uint64_t *file_offset);
static inline void cfbf_mark_stream_failure(
    CfbfLayout *layout, const CfbfDirectoryEntry *entry,
    uint64_t stream_offset);
static inline bool cfbf_all_zero(const uint8_t *data, uint64_t length);
static inline bool cfbf_validate_thumbnail(const uint8_t *data,
                                           uint64_t length);
static inline bool cfbf_validate_property_set(const uint8_t *data,
                                              uint64_t length);
static inline bool cfbf_analyze_xls_stream(const uint8_t *data,
                                           uint64_t length,
                                           bool *template_record,
                                           bool *addin_record);
static inline bool cfbf_validate_xls_stream(const uint8_t *data,
                                            uint64_t length);
static inline bool cfbf_clsid_equals(const CfbfLayout *layout,
                                     const uint8_t expected[16]);
static inline bool cfbf_contains_bytes(const uint8_t *data,
                                       uint64_t length,
                                       const char *needle);
static inline bool cfbf_process_vba_compressed_container(
    const uint8_t *data, uint64_t length, uint8_t *output,
    uint64_t output_capacity, uint64_t *output_length);
static inline bool cfbf_decompress_vba_compressed_container(
    const uint8_t *data, uint64_t length, uint8_t **output,
    uint64_t *output_length);
static inline bool cfbf_validate_vba_compressed_container(
    const uint8_t *data, uint64_t length);
static inline bool cfbf_validate_vba_modules(
    const CfbfLayout *layout, const CfbfDirectoryEntry *vba,
    const uint8_t *directory_data, uint64_t directory_length);
static inline bool cfbf_name_is_vba_srp(const CfbfDirectoryEntry *entry);
static inline void cfbf_collect_ppa_srp_coherence(
    const CfbfLayout *layout, const CfbfDirectoryEntry *vba,
    CfbfSemanticEvidence *evidence);
static inline bool cfbf_validate_ppa_streams(
    const CfbfLayout *layout, CfbfSemanticEvidence *evidence);
static inline bool cfbf_validate_doc_clx(const uint8_t *word,
                                         uint64_t word_length,
                                         const uint8_t *table,
                                         uint64_t table_length);
static inline uint32_t cfbf_rotate_left32(uint32_t value, uint32_t shift);
static inline void cfbf_md4_transform(CfbfMd4State *state,
                                      const uint8_t block[64]);
static inline void cfbf_md4_initialize(CfbfMd4State *state);
static inline void cfbf_md4_update(CfbfMd4State *state,
                                   const uint8_t *data, uint64_t length);
static inline void cfbf_md4_finish(CfbfMd4State *state,
                                   uint8_t digest[16]);
static inline void cfbf_md4_digest(const uint8_t *data, uint64_t length,
                                   uint8_t digest[16]);
static inline bool cfbf_md4_inflate(const uint8_t *data, uint64_t length,
                                    uint64_t expected_length,
                                    uint8_t digest[16]);
static inline bool cfbf_validate_officeart_blip(const uint8_t *data,
                                                uint64_t length,
                                                uint8_t digest[16],
                                                bool *authenticated);
static inline bool cfbf_validate_ppt_pictures(const uint8_t *data,
                                              uint64_t length);
static inline bool cfbf_validate_ppt_records(const uint8_t *data,
                                             uint64_t length,
                                             uint32_t depth,
                                             uint64_t *record_count);
static inline const CfbfDirectoryEntry *cfbf_find_msg_property_value(
    const CfbfLayout *layout, const CfbfDirectoryEntry *parent,
    uint32_t property_tag);
static inline bool cfbf_validate_rtf_compressed(const uint8_t *data,
                                                 uint64_t length);
static inline bool cfbf_validate_msg_unicode_stream(
    const uint8_t *data, uint64_t length);
static inline bool cfbf_validate_embedded_image(const uint8_t *data,
                                                uint64_t length);
static inline bool cfbf_validate_emf(const uint8_t *data,
                                     uint64_t length);
static inline bool cfbf_validate_msphotoed_contents(
    const uint8_t *data, uint64_t length, uint64_t *coherence_cost,
    uint64_t *coherence_extent);
static inline bool cfbf_validate_msg_property_object(
    const CfbfLayout *layout, const CfbfDirectoryEntry *parent,
    uint64_t header_size, uint64_t *property_count);
static inline bool cfbf_validate_msg_streams(
    const CfbfLayout *layout, CfbfSemanticEvidence *evidence);
static inline bool cfbf_validate_publisher_contents_stream(
    const uint8_t *data, uint64_t length);
static inline bool cfbf_validate_publisher_quill_stream(
    const uint8_t *data, uint64_t length);
static inline bool cfbf_validate_publisher_streams(
    const CfbfLayout *layout);
static inline bool cfbf_visio_decompress(const uint8_t *input,
                                         uint64_t input_length,
                                         uint8_t **output,
                                         uint64_t *output_length);
static inline uint64_t cfbf_visio_chunk_trailer(uint32_t chunk_type,
                                                uint32_t list,
                                                uint16_t level,
                                                uint8_t unknown,
                                                uint8_t version);
static inline bool cfbf_validate_visio_chunks(const uint8_t *data,
                                              uint64_t length,
                                              uint8_t version);
static inline bool cfbf_validate_visio_pointer(
    const uint8_t *document, uint64_t document_length,
    uint32_t pointer_type, uint64_t pointer_offset,
    uint64_t pointer_length, uint16_t pointer_format,
    uint8_t version, uint64_t *visited_offsets,
    uint64_t *visited_lengths, uint32_t depth);
static inline bool cfbf_validate_visio_streams(const CfbfLayout *layout);
static inline bool cfbf_validate_mpp_props_stream(const uint8_t *data,
                                                  uint64_t length);
static inline bool cfbf_validate_mpp8_table_sections(
    const uint8_t *data, uint64_t length, uint64_t offset);
static inline bool cfbf_validate_mpp_var_meta_stream(const uint8_t *data,
                                                     uint64_t length,
                                                     uint8_t version,
                                                     const uint8_t *variable_data,
                                                     uint64_t data_length,
                                                     uint64_t *metadata_failure,
                                                     uint64_t *data_failure);
static inline bool cfbf_validate_mpp_fixed_meta_stream(const uint8_t *data,
                                                       uint64_t length);
static inline void cfbf_collect_mpp_view_coherence(
    const uint8_t *metadata, uint64_t metadata_length, uint8_t version,
    const uint8_t *variable_data, uint64_t variable_data_length,
    CfbfSemanticEvidence *evidence);
static inline bool cfbf_validate_mpp_streams(
    CfbfLayout *layout, CfbfSemanticEvidence *evidence);
static inline void cfbf_collect_embedded_office_evidence(
    const CfbfLayout *layout, CfbfSemanticEvidence *evidence);
static inline CfbfSemanticStrength cfbf_validate_semantics(
    CfbfLayout *layout, bool fragmented_reassembly,
    CfbfSemanticEvidence *evidence);
static inline CfbfProfile cfbf_classify(const CfbfLayout *layout);
static inline const char *cfbf_profile_filetype(CfbfProfile profile);
static inline bool cfbf_profile_authenticates_all_content(
    CfbfProfile profile);
static inline bool cfbf_parse(const uint8_t *data, uint64_t length,
                              CfbfLayout *layout);
static inline char *cfbf_no_header_discovery(char *base, uint64_t offset,
                                             uint64_t remaining,
                                             char **matchpos,
                                             uint32_t *matchlen,
                                             uint32_t blocksize);
static inline void cfbf_file_validate(char *data, uint64_t length,
                                      bool *validates,
                                      uint64_t *validates_to,
                                      bool *promising,
                                      uint32_t needleidx,
                                      uint32_t blocksize,
                                      void *carvehashkey);
static inline void cfbf_candidate_classify(CarveInfo *candidate,
                                           bool *validates,
                                           uint64_t *validates_to,
                                           bool *promising);
static inline bool cfbf_contains_candidate(const CarveInfo *candidate,
                                           uint64_t candidate_length);
static inline void cfbf_zip_candidate_validate(CarveInfo *candidate,
                                               bool *validates,
                                               uint64_t *validates_to,
                                               bool *promising);
static inline void cfbf_assign_candidate_profile(CarveInfo *candidate,
                                                 CfbfProfile profile);
static inline bool cfbf_reassembly_initialize_candidate(
    CarveInfo *candidate, CfbfCarveState *state);
static inline bool cfbf_reassembly_evaluate_data(
    const uint8_t *data, uint64_t length, CfbfTrialResult *result);
static inline bool cfbf_reassembly_semantic_trial_complete(
    const CfbfLayout *base_layout, const uint8_t *data, uint64_t length);
static inline bool cfbf_reassembly_evaluate_candidate(
    CarveInfo *candidate, CfbfTrialResult *result);
static inline int64_t cfbf_reassembly_find_actual_slot(
    BlockVector *blockvector, int64_t actual_block);
static inline bool cfbf_reassembly_mapping_source(
    BlockVector *blockvector, int64_t actual_block,
    int64_t *apparent_block, int64_t *source_slot);
static inline bool cfbf_reassembly_run_source_available(
    BlockVector *blockvector, uint64_t run_blocks, int64_t source_actual);
static inline int32_t cfbf_reassembly_confidence_spec(CfbfProfile profile);
static inline CfbfProfile cfbf_reassembly_model_profile(
    BlockVector *blockvector, CfbfProfile parsed_profile);
static inline void cfbf_reassembly_retain_model_run(
    CfbfModelRun *runs, uint32_t *count, uint32_t limit,
    const CfbfModelRun *candidate);
static inline uint32_t cfbf_reassembly_collect_supported_gaps(
    int64_t header_actual, uint64_t signal_end,
    CfbfModelRun *runs, uint32_t capacity);
static inline void cfbf_reassembly_run_metrics(
    BlockVector *blockvector, const int64_t *mapping, uint64_t target_slot,
    uint64_t run_blocks, int64_t source_actual, CfbfProfile profile,
    bool *has_confidence, bool *all_positive,
    int64_t *confidence_gain, uint32_t *reserved,
    uint32_t *minimum_source_confidence);
static inline uint64_t cfbf_reassembly_run_concentration(
    int64_t source_actual, uint64_t run_blocks);
static inline bool cfbf_reassembly_measure_block(
    int64_t actual_block, uint64_t *concentration,
    uint8_t fingerprint[CFBF_CONTEXT_FINGERPRINT_BINS]);
static inline int64_t cfbf_reassembly_suffix_boundary_evidence(
    int64_t skipped_actual, uint64_t shift, CfbfProfile profile);
static void cfbf_reassembly_initialize_uniform_cache(void);
static inline bool cfbf_reassembly_block_is_uniform(int64_t actual_block);
static inline uint64_t cfbf_reassembly_source_run_count(uint64_t width);
static inline void cfbf_reassembly_source_run_iterator_initialize(
    CfbfSourceRunIterator *iterator, uint64_t width,
    uint64_t minimum_actual);
static inline bool cfbf_reassembly_next_source_run(
    CfbfSourceRunIterator *iterator, uint64_t *actual_block);
static inline uint64_t cfbf_reassembly_context_distance(
    BlockVector *blockvector, const int64_t *mapping,
    uint64_t target_slot, uint64_t run_blocks, int64_t source_actual);
static inline bool cfbf_reassembly_context_fingerprint(
    int64_t actual_block,
    uint8_t fingerprint[CFBF_CONTEXT_FINGERPRINT_BINS]);
static inline uint64_t cfbf_reassembly_context_sketch_distance(
    BlockVector *blockvector, const int64_t *mapping,
    uint64_t target_slot, uint64_t run_blocks, int64_t source_actual);
static inline bool cfbf_reassembly_ranked_source_is_better(
    const CfbfRankedSource *candidate, const CfbfRankedSource *retained,
    uint32_t rank_mode);
static inline void cfbf_reassembly_retain_ranked_source(
    CfbfRankedSource *sources, uint32_t *count, uint32_t limit,
    const CfbfRankedSource *candidate, uint32_t rank_mode);
static inline uint32_t cfbf_reassembly_collect_ranked_sources(
    BlockVector *blockvector, const int64_t *mapping,
    uint64_t target_slot, uint64_t run_blocks, CfbfProfile profile,
    CfbfRankedSource *sources, uint32_t capacity);
static inline int32_t cfbf_reassembly_compare_coherence(
    uint32_t candidate_payloads, uint64_t candidate_cost,
    uint64_t candidate_extent, uint32_t retained_payloads,
    uint64_t retained_cost, uint64_t retained_extent);
static inline bool cfbf_reassembly_target_within_result(
    const CfbfTrialResult *result, uint64_t target_slot,
    uint64_t run_blocks, uint64_t total_blocks);
static inline bool cfbf_reassembly_repair_is_better(
    const CfbfRepairCandidate *candidate,
    const CfbfRepairCandidate *retained);
static inline bool cfbf_reassembly_isolated_repair_is_better(
    const CfbfRepairCandidate *candidate,
    const CfbfRepairCandidate *retained);
static inline bool cfbf_reassembly_semantic_repair_is_better(
    const CfbfRepairCandidate *candidate,
    const CfbfRepairCandidate *retained);
static inline void cfbf_reassembly_reset_repair_candidates(
    CfbfCarveState *state);
static inline void cfbf_reassembly_reset_atomic_search(
    CfbfCarveState *state);
static inline void cfbf_reassembly_remember_repair(
    CfbfCarveState *state, BlockVector *blockvector,
    uint64_t target_slot, uint64_t run_blocks, uint64_t source_actual,
    const CfbfTrialResult *result,
    bool has_confidence, bool all_positive,
    bool target_strong, bool target_exact,
    int64_t confidence_gain, uint32_t reserved,
    uint64_t context_distance,
    uint64_t target_concentration, uint64_t source_concentration);
static inline bool cfbf_reassembly_share_alternate(
    ThreadWork *work, CarveInfo **candidate, CfbfCarveState *state,
    const int64_t *base_mapping, const uint8_t *base_data, uint64_t length);
static inline bool cfbf_reassembly_preserve_current_hypothesis(
    CarveInfo *candidate, CfbfCarveState *state,
    const CfbfTrialResult *result);
static inline void cfbf_reassembly_reset_suffix_candidate(
    CfbfCarveState *state);
static inline CfbfProfile cfbf_reassembly_supported_profile(
    const CfbfCarveState *state);
static inline bool cfbf_reassembly_suffix_hypothesis_is_better(
    const CfbfSuffixHypothesis *candidate,
    const CfbfSuffixHypothesis *retained);
static inline void cfbf_reassembly_retain_suffix_hypothesis(
    CfbfCarveState *state, const CfbfSuffixHypothesis *candidate,
    uint32_t limit);
static inline void cfbf_reassembly_remember_suffix(
    CfbfCarveState *state, uint64_t target_slot, uint64_t shift,
    const CfbfTrialResult *result, bool has_confidence,
    bool all_positive, int64_t confidence_gain, uint32_t reserved,
    uint64_t concentration, int64_t boundary_evidence);
static inline bool cfbf_reassembly_materialize_mapping(
    BlockVector *blockvector, const int64_t *mapping,
    const uint8_t *base_data, uint8_t *trial_data, uint64_t length);
static inline bool cfbf_reassembly_update_mapping_data(
    BlockVector *blockvector, const int64_t *from_mapping,
    const int64_t *to_mapping, uint8_t *trial_data, uint64_t length);
static inline bool cfbf_reassembly_update_run_data(
    BlockVector *blockvector, const int64_t *mapping,
    const uint8_t *base_data, uint8_t *trial_data, uint64_t length,
    uint64_t target_slot, uint64_t run_blocks, int64_t source_actual,
    bool restore);
static inline bool cfbf_reassembly_evaluate_run_repair(
    BlockVector *blockvector, CfbfCarveState *state,
    const CfbfTrialResult *current, const CfbfLayout *base_layout,
    bool semantic_prefilter_available, const int64_t *base_mapping,
    int64_t *trial_mapping, const uint8_t *base_data,
    uint8_t *trial_data, uint64_t length, uint64_t target_slot,
    uint64_t run_blocks, int64_t source_actual,
    CfbfTrialResult *result);
static inline bool cfbf_reassembly_build_suffix_mapping(
    BlockVector *blockvector, const int64_t *base_mapping,
    int64_t *trial_mapping, uint64_t target_slot, uint64_t shift,
    int64_t header_actual);
static inline bool cfbf_reassembly_build_signed_suffix_mapping(
    BlockVector *blockvector, const int64_t *base_mapping,
    const CfbfMappingIndex *mapping_index, int64_t *trial_mapping,
    uint64_t target_slot, int64_t shift, int64_t header_actual,
    bool permit_prefix_overlap, bool permit_trailing_unavailable,
    uint64_t *mapped_blocks);
static inline bool cfbf_reassembly_build_suffix_mapping_prefix(
    BlockVector *blockvector, const int64_t *base_mapping,
    int64_t *trial_mapping, uint64_t target_slot, uint64_t shift,
    int64_t header_actual, bool permit_trailing_unavailable,
    uint64_t *mapped_blocks);
static inline bool cfbf_reassembly_build_combined_suffix_mapping(
    BlockVector *blockvector, const int64_t *base_mapping,
    int64_t *trial_mapping, uint64_t target_slot, uint64_t shift,
    int64_t header_actual, uint64_t gap_actual, uint64_t gap_width);
static inline int64_t cfbf_reassembly_find_mapping_actual(
    const int64_t *mapping, uint64_t total_blocks, int64_t actual_block);
static inline bool cfbf_reassembly_mapping_index_initialize(
    CfbfMappingIndex *index, uint64_t total_blocks);
static inline void cfbf_reassembly_mapping_index_clear(
    CfbfMappingIndex *index);
static inline bool cfbf_reassembly_mapping_index_build(
    CfbfMappingIndex *index, const int64_t *mapping,
    uint64_t total_blocks);
static inline int64_t cfbf_reassembly_mapping_index_find(
    const CfbfMappingIndex *index, int64_t actual_block);
static inline bool cfbf_reassembly_build_mapped_run_indexed(
    BlockVector *blockvector, const int64_t *base_mapping,
    const CfbfMappingIndex *mapping_index, int64_t *trial_mapping,
    uint64_t target_slot, uint64_t run_blocks, int64_t source_actual);
static inline bool cfbf_reassembly_build_mapped_run(
    BlockVector *blockvector, const int64_t *base_mapping,
    int64_t *trial_mapping, uint64_t target_slot,
    uint64_t run_blocks, int64_t source_actual);
static inline uint64_t cfbf_reassembly_mapping_concentration(
    const int64_t *mapping, uint64_t target_slot, uint64_t run_blocks);
static inline bool cfbf_reassembly_mapping_run_isolated(
    const int64_t *mapping, uint64_t total_blocks,
    uint64_t target_slot, uint64_t run_blocks);
static inline uint32_t cfbf_reassembly_source_run_isolation(
    int64_t source_actual, uint64_t run_blocks, bool *eligible);
static inline bool cfbf_reassembly_build_run_mapping(
    BlockVector *blockvector, const int64_t *base_mapping,
    int64_t *trial_mapping, uint64_t target_slot,
    uint64_t run_blocks, int64_t source_actual);
static inline bool cfbf_reassembly_trial_complete(
    const CfbfTrialResult *result);
static inline bool cfbf_reassembly_trial_publishable(
    const CfbfTrialResult *result);
static inline bool cfbf_reassembly_trial_recoverable(
    const CfbfTrialResult *result);
static inline bool cfbf_reassembly_trial_authenticated(
    const CfbfTrialResult *result);
static inline int32_t cfbf_reassembly_compare_trial_results(
    const CfbfTrialResult *candidate,
    const CfbfTrialResult *retained);
static inline void cfbf_reassembly_commit_mapping(
    CarveInfo *candidate, CfbfCarveState *state,
    const int64_t *mapping, const CfbfTrialResult *result,
    uint32_t repairs);
static inline bool cfbf_reassembly_commit_remembered_suffix(
    CarveInfo *candidate, CfbfCarveState *state,
    const CfbfTrialResult *current);
static inline bool cfbf_reassembly_write_mapping_hypothesis(
    CarveInfo *candidate, CfbfCarveState *state,
    const int64_t *mapping, const CfbfTrialResult *result,
    uint32_t repairs, bool permit_opaque);
static inline bool cfbf_reassembly_write_repair_hypothesis(
    CarveInfo *candidate, CfbfCarveState *state,
    const int64_t *base_mapping, int64_t *trial_mapping,
    const uint8_t *base_data, uint8_t *trial_data, uint64_t length,
    const CfbfRepairCandidate *repair);
static inline bool cfbf_reassembly_handle_supported_suffix(
    CarveInfo *candidate, CfbfCarveState *state,
    const CfbfTrialResult *current);
static inline bool cfbf_reassembly_branch_partial_suffix(
    CarveInfo *candidate, CfbfCarveState *state,
    const CfbfTrialResult *current, const int64_t *primary_mapping,
    const CfbfTrialResult *primary_result, uint32_t primary_repairs);
static inline bool cfbf_reassembly_poll(ThreadWork *work,
                                        CarveInfo **candidate,
                                        CfbfCarveState *state,
                                        uuid_string_t uuidp,
                                        uuid_string_t uuidc);
static inline bool cfbf_reassembly_try_ranked_runs(
    ThreadWork *work, CarveInfo **candidate, CfbfCarveState *state,
    const CfbfTrialResult *current, uint64_t target_hint,
    uuid_string_t uuidp, uuid_string_t uuidc, bool *improved);
static inline bool cfbf_reassembly_try_suffix_shifts(
    ThreadWork *work, CarveInfo **candidate, CfbfCarveState *state,
    const CfbfTrialResult *current, uint64_t target_slot,
    uint64_t minimum_shift, uint64_t shift_limit,
    uuid_string_t uuidp, uuid_string_t uuidc, bool *improved,
    bool *validated);
static inline bool cfbf_reassembly_probe_supported_suffixes(
    ThreadWork *work, CarveInfo **candidate, CfbfCarveState *state,
    const CfbfTrialResult *current, uint64_t targeted_slot,
    uuid_string_t uuidp, uuid_string_t uuidc);
static inline bool cfbf_reassembly_try_structural_anchors(
    ThreadWork *work, CarveInfo **candidate, CfbfCarveState *state,
    const CfbfTrialResult *current, uint64_t targeted_slot,
    uuid_string_t uuidp, uuid_string_t uuidc, bool *improved);
static inline bool cfbf_reassembly_try_complete_run_search(
    ThreadWork *work, CarveInfo **candidate, CfbfCarveState *state,
    const CfbfTrialResult *current, uint64_t target_hint,
    uuid_string_t uuidp,
    uuid_string_t uuidc, bool *improved, bool *validated);
static inline bool cfbf_reassembly_try_block_replacements(
    ThreadWork *work, CarveInfo **candidate, CfbfCarveState *state,
    const CfbfTrialResult *current, uint64_t first_slot,
    uint64_t last_slot, uuid_string_t uuidp, uuid_string_t uuidc,
    bool *improved, bool *validated);
static inline bool cfbf_reassembly_try_atomic_pair(
    ThreadWork *work, CarveInfo **candidate, CfbfCarveState *state,
    const CfbfTrialResult *current, bool exhaustive, uuid_string_t uuidp,
    uuid_string_t uuidc, bool *improved, bool *validated);
static inline bool cfbf_reassembly_try_model_combined(
    ThreadWork *work, CarveInfo **candidate, CfbfCarveState *state,
    const CfbfTrialResult *current, uuid_string_t uuidp,
    uuid_string_t uuidc, bool *improved);
static inline bool cfbf_reassembly_combined_pair_is_better(
    const CfbfCombinedPair *candidate, const CfbfCombinedPair *retained);
static inline bool cfbf_reassembly_combined_target_is_better(
    const CfbfCombinedTarget *candidate,
    const CfbfCombinedTarget *retained);
static inline bool cfbf_reassembly_try_supported_gap_pairs(
    ThreadWork *work, CarveInfo **candidate, CfbfCarveState *state,
    uint32_t maximum_gap_count, uuid_string_t uuidp,
    uuid_string_t uuidc, bool *attempted, bool *improved);
static inline bool cfbf_reassembly_try_content_combined(
    ThreadWork *work, CarveInfo **candidate, CfbfCarveState *state,
    const CfbfTrialResult *current, uuid_string_t uuidp,
    uuid_string_t uuidc, bool *improved);
static inline void cfbf_reassembly(ThreadWork *work,
                                   CarveInfo **candidate,
                                   uuid_string_t uuidp,
                                   uuid_string_t uuidc);
static inline bool cfbf_serialize_carve_state(void **state, FILE *fp,
                                              StateSerialization mode);
static inline void *cfbf_clone_carve_state(const void *srcstate);
static inline void cfbf_free_carve_state(void **state);
static inline size_t cfbf_sizeof_carve_state(const void *state);
static inline void cfbf_print_carve_state(const void *state);

// Read an unsigned 16-bit little-endian value without alignment assumptions.
//
static inline uint16_t cfbf_read_le16(const uint8_t *data) {

  return (uint16_t)data[0]
         | ((uint16_t)data[1] << 8);
}

// Read an unsigned 32-bit little-endian value without alignment assumptions.
//
static inline uint32_t cfbf_read_le32(const uint8_t *data) {

  return (uint32_t)data[0]
         | ((uint32_t)data[1] << 8)
         | ((uint32_t)data[2] << 16)
         | ((uint32_t)data[3] << 24);
}

// Read an unsigned 64-bit little-endian value without alignment assumptions.
//
static inline uint64_t cfbf_read_le64(const uint8_t *data) {

  return (uint64_t)cfbf_read_le32(data)
         | ((uint64_t)cfbf_read_le32(data + 4) << 32);
}

// Determine whether [offset, offset + size) lies within a byte buffer.
//
static inline bool cfbf_range_available(uint64_t length, uint64_t offset,
                                        uint64_t size) {

  return offset <= length && size <= length - offset;
}

// Extend the inferred container extent using a sector that is reachable from
// an allocation structure or declared stream chain.
//
static inline void cfbf_note_sector(CfbfLayout *layout, uint32_t sector) {

  if (!layout || sector >= CFBF_MAX_REGULAR_SECTOR
      || layout->sector_size == 0) {
    return;
  }
  if (!layout->referenced_sector
      || sector > layout->highest_referenced_sector) {
    layout->referenced_sector = true;
    layout->highest_referenced_sector = sector;
    layout->inferred_size = ((uint64_t)sector + 2)
                            * layout->sector_size;
  }
}

// Test the fixed CFBF signature.
//
static inline bool cfbf_has_header(const uint8_t *data, uint64_t length) {

  return data && length >= CFBF_MAGIC_SIZE
         && memcmp(data, cfbf_magic, CFBF_MAGIC_SIZE) == 0;
}

// Derive the minimum physical extent required by sector identifiers stored in
// the CFBF header. This remains useful when a fragmented FAT or directory
// prevents complete parsing; a repaired FAT can subsequently increase it to
// the exact allocated extent.
//
static inline uint64_t cfbf_header_extent_lower_bound(
    const uint8_t *data, uint64_t length) {

  if (!cfbf_has_header(data, length) || length < CFBF_HEADER_SIZE) {
    return 0;
  }
  const uint16_t major_version = cfbf_read_le16(data + 26);
  const uint16_t sector_shift = cfbf_read_le16(data + 30);
  const uint32_t fat_sector_count = cfbf_read_le32(data + 44);
  const uint32_t first_directory_sector = cfbf_read_le32(data + 48);

  if (!((major_version == 3 && sector_shift == 9)
        || (major_version == 4 && sector_shift == 12))
      || cfbf_read_le16(data + 28) != UINT16_C(0xfffe)
      || cfbf_read_le16(data + 32) != 6
      || fat_sector_count == 0
      || first_directory_sector >= CFBF_MAX_REGULAR_SECTOR
      || cfbf_read_le32(data + 56) != CFBF_MINI_STREAM_CUTOFF) {
    return 0;
  }
  const uint64_t sector_size = UINT64_C(1) << sector_shift;
  uint32_t highest_sector = 0;
  bool found = false;
  const uint32_t fixed_sectors[] = {
    cfbf_read_le32(data + 48),
    cfbf_read_le32(data + 60),
    cfbf_read_le32(data + 68)
  };

  for (uint64_t index = 0;
       index < sizeof(fixed_sectors) / sizeof(fixed_sectors[0]); index++) {
    if (fixed_sectors[index] < CFBF_MAX_REGULAR_SECTOR) {
      if (!found || fixed_sectors[index] > highest_sector) {
        highest_sector = fixed_sectors[index];
      }
      found = true;
    }
  }
  for (uint32_t index = 0; index < CFBF_DIFAT_HEADER_ENTRIES; index++) {
    const uint32_t sector = cfbf_read_le32(
        data + 76 + (uint64_t)index * sizeof(uint32_t));

    if (sector < CFBF_MAX_REGULAR_SECTOR) {
      if (!found || sector > highest_sector) {
        highest_sector = sector;
      }
      found = true;
    }
  }
  if (!found || (uint64_t)highest_sector > UINT64_MAX / sector_size - 2) {
    return sector_size;
  }
  return ((uint64_t)highest_sector + 2) * sector_size;
}

// Derive an exploratory extent from the FAT capacity declared in the header.
// One damaged FAT sector can hide one sector's worth of allocation entries,
// so reassembly exposes that much additional addressable space at a time.
//
static inline uint64_t cfbf_header_search_extent(
    const uint8_t *data, uint64_t length, uint64_t current_extent) {

  if (!cfbf_has_header(data, length) || length < CFBF_HEADER_SIZE) {
    return current_extent;
  }
  const uint16_t major_version = cfbf_read_le16(data + 26);
  const uint16_t sector_shift = cfbf_read_le16(data + 30);

  if (!((major_version == 3 && sector_shift == 9)
        || (major_version == 4 && sector_shift == 12))) {
    return current_extent;
  }
  const uint64_t sector_size = UINT64_C(1) << sector_shift;
  const uint64_t entries_per_fat_sector = sector_size / sizeof(uint32_t);
  const uint32_t fat_sector_count = cfbf_read_le32(data + 44);
  const uint32_t difat_sector_count = cfbf_read_le32(data + 72);
  const uint64_t entries_per_difat_sector = entries_per_fat_sector - 1;
  const uint64_t maximum_declared_fat_sectors =
      CFBF_DIFAT_HEADER_ENTRIES
      + (uint64_t)difat_sector_count * entries_per_difat_sector;

  if (fat_sector_count == 0
      || fat_sector_count > maximum_declared_fat_sectors) {
    return current_extent;
  }

  const uint64_t represented_sectors =
      (uint64_t)fat_sector_count * entries_per_fat_sector;
  uint64_t declared_capacity = (represented_sectors + 1) * sector_size;
  const uint64_t repair_window = entries_per_fat_sector * sector_size;
  uint64_t next_extent = current_extent;

  if (next_extent <= UINT64_MAX - repair_window) {
    next_extent += repair_window;
  }
  else {
    next_extent = UINT64_MAX;
  }
  if (declared_capacity > CFBF_MAXIMUM_SIZE) {
    declared_capacity = CFBF_MAXIMUM_SIZE;
  }
  if (next_extent > declared_capacity) {
    next_extent = declared_capacity;
  }
  return next_extent > current_extent ? next_extent : current_extent;
}

// Convert a CFBF sector identifier into a byte offset. Sector zero begins
// after the format's full header sector, which is 512 bytes for version 3 and
// 4096 bytes for version 4.
//
static inline bool cfbf_sector_offset(const CfbfLayout *layout,
                                      uint32_t sector, uint64_t *offset) {

  if (!layout || !offset || sector >= CFBF_MAX_REGULAR_SECTOR
      || sector >= layout->available_sectors
      || (uint64_t)sector > UINT64_MAX / layout->sector_size - 1) {
    return false;
  }

  *offset = ((uint64_t)sector + 1) * layout->sector_size;
  return cfbf_range_available(layout->length, *offset,
                              layout->sector_size);
}

// Release all allocations associated with a parsed layout.
//
static inline void cfbf_layout_clear(CfbfLayout *layout) {

  if (!layout) {
    return;
  }

  free(layout->fat);
  free(layout->minifat);
  free(layout->directories);
  memset(layout, 0, sizeof(*layout));
}

// Append one sector identifier to a dynamically sized list.
//
static inline bool cfbf_append_sector(uint32_t **sectors, uint64_t *count,
                                      uint64_t *capacity, uint32_t sector) {

  if (!sectors || !count || !capacity) {
    return false;
  }
  if (*count == *capacity) {
    uint64_t next_capacity = *capacity ? *capacity * 2 : 16;

    if (next_capacity < *capacity
        || next_capacity > SIZE_MAX / sizeof(**sectors)) {
      return false;
    }
    uint32_t *replacement = (uint32_t *)realloc(
        *sectors, (size_t)next_capacity * sizeof(**sectors));

    check_memory_allocation(replacement, __LINE__, __FILE__,
                            "CFBF sector list");
    *sectors = replacement;
    *capacity = next_capacity;
  }
  (*sectors)[(*count)++] = sector;
  return true;
}

// Collect the FAT sector identifiers from the header DIFAT and any chained
// DIFAT sectors. The declared count must be satisfied exactly and every
// referenced sector must be physically available.
//
static inline bool cfbf_collect_fat_sectors(CfbfLayout *layout,
                                            uint32_t fat_sector_count,
                                            uint32_t first_difat_sector,
                                            uint32_t difat_sector_count,
                                            uint32_t **fat_sectors) {

  if (!layout || !fat_sectors || fat_sector_count == 0
      || fat_sector_count > layout->available_sectors) {
    return false;
  }

  *fat_sectors = (uint32_t *)malloc(
      (size_t)fat_sector_count * sizeof(**fat_sectors));
  check_memory_allocation(*fat_sectors, __LINE__, __FILE__,
                          "CFBF FAT sector identifiers");

  uint64_t found = 0;

  for (uint32_t index = 0;
       index < CFBF_DIFAT_HEADER_ENTRIES && found < fat_sector_count;
       index++) {
    const uint32_t sector = cfbf_read_le32(
        layout->data + 76 + (uint64_t)index * sizeof(uint32_t));

    if (sector == CFBF_FREE_SECTOR) {
      continue;
    }
    if (sector >= CFBF_MAX_REGULAR_SECTOR
        || sector >= layout->available_sectors) {
      layout->failure_offset = 76 + (uint64_t)index * sizeof(uint32_t);
      return false;
    }
    for (uint64_t prior = 0; prior < found; prior++) {
      if ((*fat_sectors)[prior] == sector) {
        layout->failure_offset = 76 + (uint64_t)index * sizeof(uint32_t);
        return false;
      }
    }
    (*fat_sectors)[found++] = sector;
    cfbf_note_sector(layout, sector);
  }

  uint32_t difat_sector = first_difat_sector;
  const uint64_t entries_per_difat = layout->sector_size / sizeof(uint32_t) - 1;

  for (uint32_t chain_index = 0;
       chain_index < difat_sector_count && found < fat_sector_count;
       chain_index++) {
    uint64_t offset = 0;

    if (!cfbf_sector_offset(layout, difat_sector, &offset)) {
      layout->failure_offset = layout->length;
      return false;
    }
    cfbf_note_sector(layout, difat_sector);
    for (uint64_t index = 0;
         index < entries_per_difat && found < fat_sector_count; index++) {
      const uint32_t sector = cfbf_read_le32(
          layout->data + offset + index * sizeof(uint32_t));

      if (sector == CFBF_FREE_SECTOR) {
        continue;
      }
      if (sector >= CFBF_MAX_REGULAR_SECTOR
          || sector >= layout->available_sectors) {
        layout->failure_offset = offset + index * sizeof(uint32_t);
        return false;
      }
      for (uint64_t prior = 0; prior < found; prior++) {
        if ((*fat_sectors)[prior] == sector) {
          layout->failure_offset = offset + index * sizeof(uint32_t);
          return false;
        }
      }
      (*fat_sectors)[found++] = sector;
      cfbf_note_sector(layout, sector);
    }

    const uint32_t next = cfbf_read_le32(
        layout->data + offset + entries_per_difat * sizeof(uint32_t));

    if (chain_index + 1 == difat_sector_count) {
      if (next == CFBF_FREE_SECTOR) {
        layout->canonical = false;
      }
      else if (next != CFBF_END_OF_CHAIN) {
        layout->failure_offset = offset + entries_per_difat
                                 * sizeof(uint32_t);
        return false;
      }
    }
    else if (next >= CFBF_MAX_REGULAR_SECTOR
             || next >= layout->available_sectors) {
      layout->failure_offset = offset + entries_per_difat
                               * sizeof(uint32_t);
      return false;
    }
    difat_sector = next;
  }

  if (found != fat_sector_count) {
    layout->failure_offset = 44;
    return false;
  }
  if (difat_sector_count == 0) {
    if (first_difat_sector == CFBF_FREE_SECTOR) {
      layout->canonical = false;
    }
    else if (first_difat_sector != CFBF_END_OF_CHAIN) {
      layout->failure_offset = 68;
      return false;
    }
  }
  return true;
}

// Build the regular FAT in logical sector order and validate the reserved FAT
// and DIFAT markers that can be checked without following any stream chain.
//
static inline bool cfbf_build_fat(CfbfLayout *layout,
                                  const uint32_t *fat_sectors,
                                  uint32_t fat_sector_count) {

  const uint64_t entries_per_sector = layout->sector_size / sizeof(uint32_t);
  uint64_t capacity = (uint64_t)fat_sector_count * entries_per_sector;

  if (capacity > layout->available_sectors) {
    capacity = layout->available_sectors;
  }
  if (capacity == 0 || capacity > SIZE_MAX / sizeof(*layout->fat)) {
    return false;
  }

  layout->fat = (uint32_t *)malloc((size_t)capacity
                                   * sizeof(*layout->fat));
  check_memory_allocation(layout->fat, __LINE__, __FILE__, "CFBF FAT");
  layout->fat_count = capacity;

  uint64_t copied = 0;

  for (uint32_t fat_index = 0;
       fat_index < fat_sector_count && copied < capacity; fat_index++) {
    uint64_t offset = 0;

    if (!cfbf_sector_offset(layout, fat_sectors[fat_index], &offset)) {
      layout->failure_offset = layout->length;
      return false;
    }
    uint64_t count = entries_per_sector;

    if (count > capacity - copied) {
      count = capacity - copied;
    }
    for (uint64_t index = 0; index < count; index++) {
      layout->fat[copied++] = cfbf_read_le32(
          layout->data + offset + index * sizeof(uint32_t));
    }
  }

  for (uint32_t index = 0; index < fat_sector_count; index++) {
    const uint32_t sector = fat_sectors[index];
    bool marker_valid = false;

    if (sector < layout->fat_count) {
      const uint32_t marker = layout->fat[sector];

      marker_valid = marker == CFBF_FAT_SECTOR
                     || marker == CFBF_END_OF_CHAIN;
      if (marker_valid && marker != CFBF_FAT_SECTOR) {
        layout->canonical = false;
      }
      for (uint32_t target = 0;
           !marker_valid && target < fat_sector_count; target++) {
        marker_valid = marker == fat_sectors[target];
        if (marker_valid) {
          layout->canonical = false;
        }
      }
    }
    if (!marker_valid) {
      layout->failure_offset = ((uint64_t)sector + 1)
                               * layout->sector_size;
      return false;
    }
  }
  for (uint32_t index = 0; index < fat_sector_count; index++) {
    layout->fat[fat_sectors[index]] = CFBF_FAT_SECTOR;
  }
  return true;
}

// Follow either a regular FAT chain or a mini-FAT chain. If expected_count is
// nonzero, the chain must contain at least that many sectors; exact_length also
// requires EOC immediately after the final expected sector.
//
static inline bool cfbf_follow_chain(const CfbfLayout *layout,
                                     const uint32_t *fat,
                                     uint64_t fat_count,
                                     uint32_t first_sector,
                                     uint64_t expected_count,
                                     bool exact_length,
                                     uint32_t **sectors,
                                     uint64_t *sector_count,
                                     uint64_t *failure_offset) {

  if (!layout || !fat || !sectors || !sector_count || !failure_offset) {
    return false;
  }

  *sectors = NULL;
  *sector_count = 0;
  uint64_t capacity = 0;

  if (expected_count == 0) {
    return true;
  }
  if (first_sector >= fat_count || first_sector >= CFBF_MAX_REGULAR_SECTOR) {
    *failure_offset = layout->length;
    return false;
  }

  uint8_t *visited = (uint8_t *)calloc((size_t)fat_count, sizeof(*visited));
  check_memory_allocation(visited, __LINE__, __FILE__, "CFBF chain visits");
  uint32_t sector = first_sector;
  bool valid = true;

  while (sector != CFBF_END_OF_CHAIN) {
    if (sector >= fat_count || sector >= CFBF_MAX_REGULAR_SECTOR
        || visited[sector]) {
      *failure_offset = layout->length;
      valid = false;
      break;
    }
    visited[sector] = 1;
    if (!cfbf_append_sector(sectors, sector_count, &capacity, sector)) {
      valid = false;
      break;
    }
    if (*sector_count > fat_count) {
      valid = false;
      break;
    }
    sector = fat[sector];
    if (sector == CFBF_FREE_SECTOR || sector == CFBF_FAT_SECTOR
        || sector == CFBF_DIFAT_SECTOR) {
      *failure_offset = layout->length;
      valid = false;
      break;
    }
  }
  free(visited);

  if (valid && (*sector_count < expected_count
                || (exact_length && *sector_count != expected_count))) {
    *failure_offset = layout->length;
    valid = false;
  }
  if (!valid) {
    free(*sectors);
    *sectors = NULL;
    *sector_count = 0;
  }
  return valid;
}

// Decode the constrained UTF-16LE directory name into a stable ASCII form.
// Non-ASCII code points are retained as '?' because all semantic profile names
// used by this validator are ASCII names defined by Microsoft formats.
//
static inline bool cfbf_parse_directory_name(const uint8_t *entry,
                                             char name[65]) {

  const uint16_t name_length = cfbf_read_le16(entry + 64);

  memset(name, 0, 65);
  if (name_length == 0) {
    return true;
  }
  if (name_length < 2 || name_length > 64 || (name_length & 1) != 0
      || entry[name_length - 2] != 0 || entry[name_length - 1] != 0) {
    return false;
  }

  const uint16_t characters = name_length / 2 - 1;

  for (uint16_t index = 0; index < characters && index < 64; index++) {
    const uint16_t value = cfbf_read_le16(entry + (uint64_t)index * 2);

    name[index] = value > 0 && value <= 0x7f ? (char)value : '?';
  }
  return true;
}

// Parse every directory entry reachable through the directory-sector chain.
// Empty directory slots are retained so sibling and child identifiers continue
// to use their on-disk indexes.
//
static inline bool cfbf_parse_directories(CfbfLayout *layout) {

  uint32_t *sectors = NULL;
  uint64_t sector_count = 0;
  uint64_t failure = 0;
  uint64_t expected = layout->major_version == 4
                          ? cfbf_read_le32(layout->data + 40)
                          : 1;

  if (expected == 0) {
    expected = 1;
  }
  if (!cfbf_follow_chain(layout, layout->fat, layout->fat_count,
                         layout->first_directory_sector, expected, false,
                         &sectors, &sector_count, &failure)) {
    layout->failure_offset = failure;
    return false;
  }

  const uint64_t entries_per_sector = layout->sector_size
                                      / CFBF_DIRECTORY_ENTRY_SIZE;

  if (sector_count > UINT64_MAX / entries_per_sector
      || sector_count * entries_per_sector
             > SIZE_MAX / sizeof(*layout->directories)) {
    free(sectors);
    return false;
  }
  layout->directory_count = sector_count * entries_per_sector;
  layout->directories = (CfbfDirectoryEntry *)calloc(
      (size_t)layout->directory_count, sizeof(*layout->directories));
  check_memory_allocation(layout->directories, __LINE__, __FILE__,
                          "CFBF directory entries");
  layout->root_index = UINT64_MAX;

  for (uint64_t sector_index = 0; sector_index < sector_count;
       sector_index++) {
    uint64_t offset = 0;

    cfbf_note_sector(layout, sectors[sector_index]);
    if (!cfbf_sector_offset(layout, sectors[sector_index], &offset)) {
      free(sectors);
      layout->failure_offset = layout->length;
      return false;
    }
    for (uint64_t entry_index = 0; entry_index < entries_per_sector;
         entry_index++) {
      const uint64_t logical_index = sector_index * entries_per_sector
                                     + entry_index;
      const uint8_t *source = layout->data + offset
                              + entry_index * CFBF_DIRECTORY_ENTRY_SIZE;
      CfbfDirectoryEntry *destination =
          &layout->directories[logical_index];

      destination->parent = CFBF_NO_STREAM;
      destination->object_type = source[66];
      if (destination->object_type > 5
          || destination->object_type == 3
          || destination->object_type == 4) {
        free(sectors);
        layout->failure_offset = offset
                                 + entry_index * CFBF_DIRECTORY_ENTRY_SIZE;
        return false;
      }
      if (destination->object_type == 0) {
        continue;
      }
      if (!cfbf_parse_directory_name(source, destination->name)) {
        if (destination->object_type == 5) {
          layout->canonical = false;
          destination->name[0] = '\0';
        }
        else {
          free(sectors);
          layout->failure_offset = offset
                                   + entry_index
                                         * CFBF_DIRECTORY_ENTRY_SIZE;
          return false;
        }
      }
      destination->left_sibling = cfbf_read_le32(source + 68);
      destination->right_sibling = cfbf_read_le32(source + 72);
      destination->child = cfbf_read_le32(source + 76);
      memcpy(destination->clsid, source + 80,
             sizeof(destination->clsid));
      destination->start_sector = cfbf_read_le32(source + 116);
      destination->stream_size = cfbf_read_le64(source + 120);
      if (layout->major_version == 3) {
        destination->stream_size &= UINT64_C(0xffffffff);
      }

      const uint32_t links[3] = {
        destination->left_sibling,
        destination->right_sibling,
        destination->child
      };

      for (uint32_t link_index = 0; link_index < 3; link_index++) {
        if (links[link_index] != CFBF_NO_STREAM
            && links[link_index] >= layout->directory_count) {
          free(sectors);
          layout->failure_offset = offset
                                   + entry_index
                                         * CFBF_DIRECTORY_ENTRY_SIZE
                                   + 68 + link_index * sizeof(uint32_t);
          return false;
        }
      }
      if (destination->object_type == 5) {
        if (layout->root_index != UINT64_MAX || logical_index != 0) {
          free(sectors);
          layout->failure_offset = offset
                                   + entry_index
                                         * CFBF_DIRECTORY_ENTRY_SIZE;
          return false;
        }
        layout->root_index = logical_index;
      }
    }
  }
  free(sectors);
  return layout->root_index == 0;
}

// Associate each directory entry with the storage whose red-black tree owns
// it. The parent relationship is implicit on disk, but application formats
// use it to distinguish identically named streams in different storages.
//
static inline bool cfbf_assign_directory_parents(CfbfLayout *layout) {

  if (!layout || !layout->directories
      || layout->directory_count > UINT32_MAX) {
    return false;
  }

  uint32_t *stack = (uint32_t *)malloc(
      (size_t)layout->directory_count * sizeof(*stack));
  uint64_t *seen = (uint64_t *)calloc(
      (size_t)layout->directory_count, sizeof(*seen));
  check_memory_allocation(stack, __LINE__, __FILE__,
                          "CFBF directory traversal stack");
  check_memory_allocation(seen, __LINE__, __FILE__,
                          "CFBF directory traversal state");
  bool valid = true;

  for (uint64_t parent_index = 0;
       parent_index < layout->directory_count; parent_index++) {
    CfbfDirectoryEntry *parent = &layout->directories[parent_index];

    if ((parent->object_type != 1 && parent->object_type != 5)
        || parent->child == CFBF_NO_STREAM) {
      continue;
    }
    const uint64_t generation = parent_index + 1;
    uint64_t stack_count = 0;

    seen[parent->child] = generation;
    stack[stack_count++] = parent->child;
    while (stack_count != 0) {
      const uint32_t child_index = stack[--stack_count];
      CfbfDirectoryEntry *child = &layout->directories[child_index];

      if (child->object_type == 0 || child->object_type == 5) {
        valid = false;
        continue;
      }
      if (child->parent == CFBF_NO_STREAM) {
        child->parent = (uint32_t)parent_index;
      }
      else if (child->parent != parent_index) {
        child->parent = CFBF_AMBIGUOUS_DIRECTORY_PARENT;
        valid = false;
      }

      const uint32_t links[2] = {
        child->left_sibling,
        child->right_sibling
      };

      for (uint32_t link_index = 0; link_index < 2; link_index++) {
        const uint32_t link = links[link_index];

        if (link == CFBF_NO_STREAM) {
          continue;
        }
        if (seen[link] == generation) {
          valid = false;
          continue;
        }
        seen[link] = generation;
        stack[stack_count++] = link;
      }
    }
  }
  free(seen);
  free(stack);
  return valid;
}

// Read the mini-FAT chain into logical mini-sector order.
//
static inline bool cfbf_build_minifat(CfbfLayout *layout) {

  bool minifat_required = false;

  for (uint64_t index = 0; index < layout->directory_count; index++) {
    const CfbfDirectoryEntry *entry = &layout->directories[index];

    if (entry->object_type == 2 && entry->stream_size > 0
        && entry->stream_size < layout->mini_stream_cutoff) {
      minifat_required = true;
      break;
    }
  }
  if (!minifat_required) {
    if (layout->minifat_sector_count != 0
        || layout->first_minifat_sector != CFBF_END_OF_CHAIN) {
      layout->canonical = false;
    }
    return true;
  }
  if (layout->minifat_sector_count == 0) {
    return false;
  }

  uint32_t *sectors = NULL;
  uint64_t sector_count = 0;
  uint64_t failure = 0;

  if (!cfbf_follow_chain(layout, layout->fat, layout->fat_count,
                         layout->first_minifat_sector,
                         layout->minifat_sector_count, true,
                         &sectors, &sector_count, &failure)) {
    layout->failure_offset = failure;
    return false;
  }

  const uint64_t entries_per_sector = layout->sector_size / sizeof(uint32_t);

  if (sector_count > UINT64_MAX / entries_per_sector
      || sector_count * entries_per_sector
             > SIZE_MAX / sizeof(*layout->minifat)) {
    free(sectors);
    return false;
  }
  layout->minifat_count = sector_count * entries_per_sector;
  layout->minifat = (uint32_t *)malloc((size_t)layout->minifat_count
                                      * sizeof(*layout->minifat));
  check_memory_allocation(layout->minifat, __LINE__, __FILE__,
                          "CFBF mini-FAT");

  uint64_t copied = 0;

  for (uint64_t sector_index = 0; sector_index < sector_count;
       sector_index++) {
    uint64_t offset = 0;

    cfbf_note_sector(layout, sectors[sector_index]);
    if (!cfbf_sector_offset(layout, sectors[sector_index], &offset)) {
      free(sectors);
      layout->failure_offset = layout->length;
      return false;
    }
    for (uint64_t index = 0; index < entries_per_sector; index++) {
      layout->minifat[copied++] = cfbf_read_le32(
          layout->data + offset + index * sizeof(uint32_t));
    }
  }
  free(sectors);
  return true;
}

// Validate all regular and mini-stream chains. The CFBF allocation tables are
// the authoritative structure; a complete verdict requires every declared
// stream to have exactly enough sectors and no cyclic or reserved-sector link.
//
static inline bool cfbf_validate_streams(CfbfLayout *layout) {

  if (layout->root_index >= layout->directory_count) {
    return false;
  }
  const CfbfDirectoryEntry *root =
      &layout->directories[layout->root_index];
  const uint64_t root_sectors = root->stream_size == 0
                                    ? 0
                                    : CEILDIV(root->stream_size,
                                              layout->sector_size);
  uint32_t *root_chain = NULL;
  uint64_t root_chain_count = 0;
  uint64_t failure = 0;

  if (root->stream_size == 0
      && root->start_sector != CFBF_END_OF_CHAIN
      && root->start_sector != CFBF_FREE_SECTOR) {
    layout->canonical = false;
  }

  if (!cfbf_follow_chain(layout, layout->fat, layout->fat_count,
                         root->start_sector, root_sectors, false,
                         &root_chain, &root_chain_count, &failure)) {
    layout->failure_offset = failure;
    return false;
  }
  if (root_chain_count != root_sectors) {
    layout->canonical = false;
  }
  for (uint64_t chain_index = 0; chain_index < root_chain_count;
       chain_index++) {
    cfbf_note_sector(layout, root_chain[chain_index]);
  }
  free(root_chain);

  for (uint64_t index = 0; index < layout->directory_count; index++) {
    const CfbfDirectoryEntry *entry = &layout->directories[index];

    if (entry->object_type != 2) {
      continue;
    }
    const bool mini = entry->stream_size > 0
                      && entry->stream_size < layout->mini_stream_cutoff;
    const uint64_t unit_size = mini ? layout->mini_sector_size
                                    : layout->sector_size;
    const uint64_t expected = entry->stream_size == 0
                                  ? 0
                                  : CEILDIV(entry->stream_size, unit_size);
    const uint32_t *fat = mini ? layout->minifat : layout->fat;
    const uint64_t fat_count = mini ? layout->minifat_count
                                    : layout->fat_count;
    uint32_t *chain = NULL;
    uint64_t chain_count = 0;

    if (!fat && expected > 0) {
      layout->failure_offset = layout->length;
      return false;
    }
    if (expected == 0
        && entry->start_sector != CFBF_END_OF_CHAIN
        && entry->start_sector != CFBF_FREE_SECTOR) {
      layout->canonical = false;
    }
    if (!cfbf_follow_chain(layout, fat, fat_count, entry->start_sector,
                           expected, false, &chain, &chain_count, &failure)) {
      layout->failure_offset = failure;
      return false;
    }
    if (chain_count != expected) {
      layout->canonical = false;
    }
    if (!mini) {
      for (uint64_t chain_index = 0; chain_index < chain_count;
           chain_index++) {
        cfbf_note_sector(layout, chain[chain_index]);
      }
    }
    if (mini) {
      for (uint64_t chain_index = 0; chain_index < chain_count;
           chain_index++) {
        if ((uint64_t)chain[chain_index]
                > UINT64_MAX / layout->mini_sector_size
            || (uint64_t)chain[chain_index] * layout->mini_sector_size
                   >= root->stream_size) {
          free(chain);
          layout->failure_offset = layout->length;
          return false;
        }
      }
    }
    free(chain);
  }
  return true;
}

// Compare a decoded directory name without case folding. Microsoft-defined
// stream names use fixed ASCII spelling.
//
static inline bool cfbf_name_equals(const CfbfDirectoryEntry *entry,
                                    const char *name) {

  return entry && name && strcmp(entry->name, name) == 0;
}

// Test an ASCII prefix used by families such as MAPI property streams.
//
static inline bool cfbf_name_starts_with(const CfbfDirectoryEntry *entry,
                                         const char *prefix) {

  return entry && prefix
         && strncmp(entry->name, prefix, strlen(prefix)) == 0;
}

// Locate a stream or storage by its decoded CFBF directory name.
//
static inline const CfbfDirectoryEntry *cfbf_find_directory(
    const CfbfLayout *layout, const char *name) {

  if (!layout || !name) {
    return NULL;
  }
  for (uint64_t index = 0; index < layout->directory_count; index++) {
    if (layout->directories[index].object_type != 0
        && cfbf_name_equals(&layout->directories[index], name)) {
      return &layout->directories[index];
    }
  }
  return NULL;
}

// Locate a direct child of one storage. Stream names such as Props, VarMeta,
// and FixedMeta are reused throughout Microsoft Project containers, so a flat
// directory-name match is not sufficient semantic evidence.
//
static inline const CfbfDirectoryEntry *cfbf_find_child_directory(
    const CfbfLayout *layout, const CfbfDirectoryEntry *parent,
    const char *name) {

  if (!layout || !layout->directories || !parent || !name
      || parent < layout->directories
      || parent >= layout->directories + layout->directory_count) {
    return NULL;
  }
  const uint64_t parent_index = (uint64_t)(parent - layout->directories);

  for (uint64_t index = 0; index < layout->directory_count; index++) {
    const CfbfDirectoryEntry *entry = &layout->directories[index];

    if (entry->object_type != 0 && entry->parent == parent_index
        && cfbf_name_equals(entry, name)) {
      return entry;
    }
  }
  return NULL;
}

// Materialize a regular FAT-backed stream into a caller-owned buffer.
//
static inline bool cfbf_copy_regular_stream(const CfbfLayout *layout,
                                            uint32_t first_sector,
                                            uint64_t stream_size,
                                            uint8_t **data) {

  if (!layout || !data) {
    return false;
  }
  *data = NULL;
  if (stream_size == 0) {
    return first_sector == CFBF_END_OF_CHAIN
           || first_sector == CFBF_FREE_SECTOR;
  }
  if (stream_size > SIZE_MAX) {
    return false;
  }

  const uint64_t expected = CEILDIV(stream_size, layout->sector_size);
  uint32_t *sectors = NULL;
  uint64_t sector_count = 0;
  uint64_t failure = 0;

  if (!cfbf_follow_chain(layout, layout->fat, layout->fat_count,
                         first_sector, expected, true, &sectors,
                         &sector_count, &failure)) {
    return false;
  }
  uint8_t *output = (uint8_t *)malloc((size_t)stream_size);
  check_memory_allocation(output, __LINE__, __FILE__,
                          "CFBF regular stream");
  uint64_t copied = 0;

  for (uint64_t index = 0; index < sector_count; index++) {
    uint64_t offset = 0;
    if (!cfbf_sector_offset(layout, sectors[index], &offset)) {
      free(output);
      free(sectors);
      return false;
    }
    uint64_t count = stream_size - copied;
    if (count > layout->sector_size) {
      count = layout->sector_size;
    }
    memcpy(output + copied, layout->data + offset, (size_t)count);
    copied += count;
  }
  free(sectors);
  if (copied != stream_size) {
    free(output);
    return false;
  }
  *data = output;
  return true;
}

// Materialize either a regular stream or a mini-stream entry. Mini-stream
// sectors are addressed through the root stream and the mini-FAT.
//
static inline bool cfbf_materialize_stream(const CfbfLayout *layout,
                                           const CfbfDirectoryEntry *entry,
                                           uint8_t **data,
                                           uint64_t *length) {

  if (!layout || !entry || !data || !length || entry->object_type != 2) {
    return false;
  }
  *data = NULL;
  *length = entry->stream_size;
  if (entry->stream_size == 0) {
    return entry->start_sector == CFBF_END_OF_CHAIN
           || entry->start_sector == CFBF_FREE_SECTOR;
  }
  if (entry->stream_size >= layout->mini_stream_cutoff) {
    return cfbf_copy_regular_stream(layout, entry->start_sector,
                                    entry->stream_size, data);
  }
  if (layout->root_index >= layout->directory_count || !layout->minifat
      || entry->stream_size > SIZE_MAX) {
    return false;
  }

  const CfbfDirectoryEntry *root =
      &layout->directories[layout->root_index];
  uint8_t *mini_stream = NULL;
  if (!cfbf_copy_regular_stream(layout, root->start_sector,
                                root->stream_size, &mini_stream)) {
    return false;
  }

  const uint64_t expected = CEILDIV(entry->stream_size,
                                    layout->mini_sector_size);
  uint32_t *sectors = NULL;
  uint64_t sector_count = 0;
  uint64_t failure = 0;
  if (!cfbf_follow_chain(layout, layout->minifat, layout->minifat_count,
                         entry->start_sector, expected, true, &sectors,
                         &sector_count, &failure)) {
    free(mini_stream);
    return false;
  }

  uint8_t *output = (uint8_t *)malloc((size_t)entry->stream_size);
  check_memory_allocation(output, __LINE__, __FILE__, "CFBF mini stream");
  uint64_t copied = 0;

  for (uint64_t index = 0; index < sector_count; index++) {
    const uint64_t offset = (uint64_t)sectors[index]
                            * layout->mini_sector_size;
    uint64_t count = entry->stream_size - copied;
    if (count > layout->mini_sector_size) {
      count = layout->mini_sector_size;
    }
    if (!cfbf_range_available(root->stream_size, offset, count)) {
      free(output);
      free(sectors);
      free(mini_stream);
      return false;
    }
    memcpy(output + copied, mini_stream + offset, (size_t)count);
    copied += count;
  }
  free(sectors);
  free(mini_stream);
  if (copied != entry->stream_size) {
    free(output);
    return false;
  }
  *data = output;
  return true;
}

// Map a byte in a regular or mini stream back to its byte position in the
// compound file. Parsed FAT chains make this lookup deterministic.
//
static inline bool cfbf_stream_file_offset(
    const CfbfLayout *layout, const CfbfDirectoryEntry *entry,
    uint64_t stream_offset, uint64_t *file_offset) {

  if (!layout || !entry || !file_offset || entry->object_type != 2
      || stream_offset >= entry->stream_size) {
    return false;
  }

  uint32_t sector = entry->start_sector;
  uint64_t regular_offset = stream_offset;

  if (entry->stream_size < layout->mini_stream_cutoff) {
    if (!layout->minifat || layout->mini_sector_size == 0
        || layout->root_index >= layout->directory_count) {
      return false;
    }
    const uint64_t mini_index = stream_offset / layout->mini_sector_size;

    if (mini_index >= layout->minifat_count) {
      return false;
    }
    for (uint64_t index = 0; index < mini_index; index++) {
      if (sector >= layout->minifat_count
          || sector >= CFBF_MAX_REGULAR_SECTOR) {
        return false;
      }
      sector = layout->minifat[sector];
    }
    if (sector >= layout->minifat_count
        || sector >= CFBF_MAX_REGULAR_SECTOR
        || (uint64_t)sector
               > (UINT64_MAX - stream_offset % layout->mini_sector_size)
                     / layout->mini_sector_size) {
      return false;
    }
    regular_offset = (uint64_t)sector * layout->mini_sector_size
                     + stream_offset % layout->mini_sector_size;
    const CfbfDirectoryEntry *root =
        &layout->directories[layout->root_index];

    if (regular_offset >= root->stream_size) {
      return false;
    }
    sector = root->start_sector;
  }

  if (!layout->fat || layout->sector_size == 0) {
    return false;
  }
  const uint64_t regular_index = regular_offset / layout->sector_size;

  if (regular_index >= layout->fat_count) {
    return false;
  }
  for (uint64_t index = 0; index < regular_index; index++) {
    if (sector >= layout->fat_count
        || sector >= CFBF_MAX_REGULAR_SECTOR) {
      return false;
    }
    sector = layout->fat[sector];
  }
  uint64_t sector_offset = 0;

  if (sector >= layout->fat_count || sector >= CFBF_MAX_REGULAR_SECTOR
      || !cfbf_sector_offset(layout, sector, &sector_offset)) {
    return false;
  }
  const uint64_t within_sector = regular_offset % layout->sector_size;

  if (sector_offset > UINT64_MAX - within_sector) {
    return false;
  }
  *file_offset = sector_offset + within_sector;
  return *file_offset < layout->length;
}

// Preserve the earliest physical byte identified by semantic stream
// validation so fragmented reassembly can repair the corresponding block.
//
static inline void cfbf_mark_stream_failure(
    CfbfLayout *layout, const CfbfDirectoryEntry *entry,
    uint64_t stream_offset) {

  if (!layout || !entry || entry->stream_size == 0) {
    return;
  }
  if (stream_offset >= entry->stream_size) {
    stream_offset = entry->stream_size - 1;
  }
  uint64_t file_offset = 0;

  if (cfbf_stream_file_offset(layout, entry, stream_offset, &file_offset)
      && (layout->failure_offset == 0
          || file_offset < layout->failure_offset)) {
    layout->failure_offset = file_offset;
  }
}

// Test whether a padding region contains only zero bytes.
//
static inline bool cfbf_all_zero(const uint8_t *data, uint64_t length) {

  if (!data && length != 0) {
    return false;
  }
  for (uint64_t index = 0; index < length; index++) {
    if (data[index] != 0) {
      return false;
    }
  }
  return true;
}

// Validate common Windows thumbnail encodings embedded in SummaryInformation.
// Image pixels remain opaque, but their DIB, WMF, EMF, or JPEG container must
// consume the complete declared clipboard payload without malformed framing.
//
static inline bool cfbf_validate_thumbnail(const uint8_t *data,
                                           uint64_t length) {

  if (!data || length < 12
      || cfbf_read_le32(data) != UINT32_C(0x0047)) {
    return false;
  }
  const uint32_t clipboard_size = cfbf_read_le32(data + 4);

  if (clipboard_size < 4
      || !cfbf_range_available(length, 8, clipboard_size)) {
    return false;
  }
  const uint32_t clipboard_tag = cfbf_read_le32(data + 8);

  if (clipboard_tag == 0) {
    return clipboard_size == 4;
  }
  if (clipboard_size < 8) {
    return false;
  }
  const uint32_t format = cfbf_read_le32(data + 12);
  const uint8_t *payload = data + 16;
  const uint64_t payload_length = clipboard_size - 8;

  if (format == 8) {
    if (payload_length < 40) {
      return false;
    }
    const uint32_t header_size = cfbf_read_le32(payload);
    const int32_t width = (int32_t)cfbf_read_le32(payload + 4);
    const int32_t height = (int32_t)cfbf_read_le32(payload + 8);
    const uint16_t planes = cfbf_read_le16(payload + 12);
    const uint16_t bits_per_pixel = cfbf_read_le16(payload + 14);
    const uint32_t compression = cfbf_read_le32(payload + 16);
    const uint32_t image_size = cfbf_read_le32(payload + 20);

    if (header_size < 40 || header_size > payload_length || width == 0
        || height == 0 || planes != 1
        || (bits_per_pixel != 1 && bits_per_pixel != 4
            && bits_per_pixel != 8 && bits_per_pixel != 16
            && bits_per_pixel != 24 && bits_per_pixel != 32)
        || compression > 6
        || image_size > payload_length - header_size) {
      return false;
    }
    return true;
  }

  if (format == 3) {
    if (payload_length < 26) {
      return false;
    }
    const uint8_t *wmf = payload + 8;
    const uint64_t wmf_available = payload_length - 8;
    const uint16_t type = cfbf_read_le16(wmf);
    const uint16_t header_words = cfbf_read_le16(wmf + 2);
    const uint16_t version = cfbf_read_le16(wmf + 4);
    const uint32_t file_words = cfbf_read_le32(wmf + 6);
    const uint32_t maximum_record = cfbf_read_le32(wmf + 12);
    const uint64_t file_size = (uint64_t)file_words * 2;

    if ((type != 1 && type != 2) || header_words != 9
        || (version != UINT16_C(0x0100)
            && version != UINT16_C(0x0300))
        || file_size < 18 || file_size > wmf_available
        || maximum_record < 3 || maximum_record > file_words) {
      return false;
    }
    uint64_t offset = 18;
    bool eof = false;

    while (offset < file_size) {
      if (!cfbf_range_available(file_size, offset, 6)) {
        return false;
      }
      const uint32_t record_words = cfbf_read_le32(wmf + offset);
      const uint16_t function = cfbf_read_le16(wmf + offset + 4);
      const uint64_t record_size = (uint64_t)record_words * 2;

      if (record_words < 3
          || !cfbf_range_available(file_size, offset, record_size)) {
        return false;
      }
      offset += record_size;
      if (function == 0) {
        eof = record_words == 3;
        break;
      }
    }
    return eof && offset == file_size;
  }

  if (format == 14) {
    if (payload_length < 88 || cfbf_read_le32(payload) != 1) {
      return false;
    }
    const uint32_t header_size = cfbf_read_le32(payload + 4);
    const uint32_t signature = cfbf_read_le32(payload + 40);
    const uint32_t file_size = cfbf_read_le32(payload + 48);
    const uint32_t expected_records = cfbf_read_le32(payload + 52);

    if (header_size < 88 || header_size > payload_length
        || signature != UINT32_C(0x464d4520)
        || file_size < header_size || file_size > payload_length
        || expected_records == 0) {
      return false;
    }
    uint64_t offset = 0;
    uint32_t records = 0;
    uint32_t last_type = 0;

    while (offset < file_size) {
      if (!cfbf_range_available(file_size, offset, 8)) {
        return false;
      }
      const uint32_t type = cfbf_read_le32(payload + offset);
      const uint32_t record_size = cfbf_read_le32(payload + offset + 4);

      if (record_size < 8 || (record_size & 3) != 0
          || !cfbf_range_available(file_size, offset, record_size)) {
        return false;
      }
      last_type = type;
      records++;
      offset += record_size;
    }
    return offset == file_size && records == expected_records
           && last_type == 14;
  }

  if (format == UINT32_C(0x0333)) {
    return payload_length >= 4 && payload[0] == 0xff && payload[1] == 0xd8
           && payload[payload_length - 2] == 0xff
           && payload[payload_length - 1] == 0xd9;
  }

  // SummaryInformation permits application-specific clipboard encodings.
  return true;
}

// Validate the directory and section tables of an OLE property-set stream.
// Typed property payloads are format-specific, but every section and property
// offset must remain inside the declared stream and section extents.
//
static inline bool cfbf_validate_property_set(const uint8_t *data,
                                              uint64_t length) {

  if (!data || length < 48 || cfbf_read_le16(data) != UINT16_C(0xfffe)) {
    return false;
  }
  const uint16_t version = cfbf_read_le16(data + 2);
  const uint32_t sections = cfbf_read_le32(data + 24);
  if (version > 1 || sections == 0 || sections > 16
      || !cfbf_range_available(length, 28,
                               (uint64_t)sections * 20)) {
    return false;
  }

  for (uint32_t section = 0; section < sections; section++) {
    const uint64_t descriptor = 28 + (uint64_t)section * 20;
    const uint32_t offset = cfbf_read_le32(data + descriptor + 16);
    if (!cfbf_range_available(length, offset, 8)) {
      return false;
    }
    const uint32_t section_size = cfbf_read_le32(data + offset);
    const uint32_t properties = cfbf_read_le32(data + offset + 4);
    if (section_size < 8 || section_size > length - offset
        || properties > (section_size - 8) / 8) {
      return false;
    }
    for (uint32_t property = 0; property < properties; property++) {
      const uint64_t table = offset + 8 + (uint64_t)property * 8;
      const uint32_t property_id = cfbf_read_le32(data + table);
      const uint32_t value_offset = cfbf_read_le32(data + table + 4);
      if (value_offset < 8 + (uint64_t)properties * 8
          || value_offset > section_size - 4) {
        return false;
      }
      if (property_id == UINT32_C(0x11)
          && !cfbf_validate_thumbnail(data + offset + value_offset,
                                      section_size - value_offset)) {
        return false;
      }
    }
  }
  return true;
}

// Validate BIFF record framing, BOF/EOF substreams, and worksheet offsets in
// an Excel Workbook stream. Template and add-in records are defined format
// markers and therefore remain reliable when the original filename is lost.
//
static inline bool cfbf_analyze_xls_stream(const uint8_t *data,
                                           uint64_t length,
                                           bool *template_record,
                                           bool *addin_record) {

  if (template_record) {
    *template_record = false;
  }
  if (addin_record) {
    *addin_record = false;
  }

  if (!data || length < 12) {
    return false;
  }
  uint64_t offset = 0;
  uint64_t records = 0;
  uint32_t open_substreams = 0;
  uint32_t bof_count = 0;
  uint32_t eof_count = 0;
  uint16_t document_type = 0;

  while (offset < length) {
    if (length - offset < 4) {
      return cfbf_all_zero(data + offset, length - offset)
             && open_substreams == 0 && bof_count != 0;
    }
    const uint16_t type = cfbf_read_le16(data + offset);
    const uint16_t size = cfbf_read_le16(data + offset + 2);
    if (type == 0 && size == 0
        && cfbf_all_zero(data + offset, length - offset)) {
      break;
    }
    if (size > 8224 || !cfbf_range_available(length, offset + 4, size)) {
      return false;
    }
    if (type == UINT16_C(0x0809) || type == UINT16_C(0x0409)
        || type == UINT16_C(0x0209) || type == UINT16_C(0x0009)) {
      if (size < 4 || open_substreams != 0) {
        return false;
      }
      open_substreams = 1;
      document_type = cfbf_read_le16(data + offset + 6);
      bof_count++;
    }
    else if (type == UINT16_C(0x000a)) {
      if (open_substreams == 0) {
        return false;
      }
      open_substreams = 0;
      document_type = 0;
      eof_count++;
    }
    else if (type == UINT16_C(0x0085)) {
      if (size < 8) {
        return false;
      }
      const uint32_t sheet = cfbf_read_le32(data + offset + 4);
      if (!cfbf_range_available(length, sheet, 4)) {
        return false;
      }
      const uint16_t sheet_type = cfbf_read_le16(data + sheet);
      if (sheet_type != UINT16_C(0x0809)
          && sheet_type != UINT16_C(0x0409)
          && sheet_type != UINT16_C(0x0209)
          && sheet_type != UINT16_C(0x0009)) {
        return false;
      }
    }
    else if (open_substreams != 0
             && document_type == UINT16_C(0x0005)
             && type == CFBF_BIFF_TEMPLATE_RECORD) {
      if (template_record) {
        *template_record = true;
      }
    }
    else if (open_substreams != 0
             && document_type == UINT16_C(0x0005)
             && type == CFBF_BIFF_ADDIN_RECORD) {
      if (addin_record) {
        *addin_record = true;
      }
    }
    offset += 4 + size;
    records++;
  }
  return records != 0 && bof_count != 0 && bof_count == eof_count
         && open_substreams == 0;
}

static inline bool cfbf_validate_xls_stream(const uint8_t *data,
                                            uint64_t length) {

  return cfbf_analyze_xls_stream(data, length, NULL, NULL);
}

// Compare an application-defining root CLSID without converting it to its
// printable GUID representation.
//
static inline bool cfbf_clsid_equals(const CfbfLayout *layout,
                                     const uint8_t expected[16]) {

  return layout && layout->directories && expected
         && layout->root_index < layout->directory_count
         && memcmp(layout->directories[layout->root_index].clsid,
                   expected, 16) == 0;
}

static inline bool cfbf_contains_bytes(const uint8_t *data,
                                       uint64_t length,
                                       const char *needle) {

  if (!data || !needle) {
    return false;
  }
  const size_t needle_length = strlen(needle);

  if (needle_length == 0 || needle_length > length) {
    return false;
  }
  for (uint64_t offset = 0; offset <= length - needle_length; offset++) {
    if (memcmp(data + offset, needle, needle_length) == 0) {
      return true;
    }
  }
  return false;
}

// Walk one MS-OVBA compressed container. Supplying an output buffer performs
// decompression; omitting it validates framing and computes the output size.
//
static inline bool cfbf_process_vba_compressed_container(
    const uint8_t *data, uint64_t length, uint8_t *output,
    uint64_t output_capacity, uint64_t *output_length) {

  if (!data || !output_length || length < 4
      || data[0] != UINT8_C(0x01)) {
    return false;
  }
  uint64_t position = 1;
  uint64_t total_output = 0;
  uint64_t chunks = 0;

  while (position < length) {
    if (!cfbf_range_available(length, position, 2)) {
      return false;
    }
    const uint16_t header = cfbf_read_le16(data + position);
    const uint64_t chunk_size = (uint64_t)(header & UINT16_C(0x0fff)) + 3;
    const bool compressed = (header & UINT16_C(0x8000)) != 0;

    if ((header & UINT16_C(0x7000)) != UINT16_C(0x3000)
        || !cfbf_range_available(length, position, chunk_size)) {
      return false;
    }
    const uint64_t chunk_end = position + chunk_size;
    uint64_t cursor = position + 2;
    uint32_t chunk_output = 0;

    if (!compressed) {
      if (chunk_size != UINT64_C(4098)) {
        return false;
      }
      chunk_output = 4096;
      if (output) {
        if (!cfbf_range_available(output_capacity, total_output,
                                  chunk_output)) {
          return false;
        }
        memcpy(output + total_output, data + cursor, chunk_output);
      }
      cursor += chunk_output;
    }
    else {
      while (cursor < chunk_end) {
        const uint8_t flags = data[cursor++];

        for (uint32_t bit = 0; bit < 8 && cursor < chunk_end; bit++) {
          if ((flags & (UINT8_C(1) << bit)) == 0) {
            if (chunk_output >= 4096) {
              return false;
            }
            if (output) {
              if (!cfbf_range_available(output_capacity,
                                        total_output + chunk_output, 1)) {
                return false;
              }
              output[total_output + chunk_output] = data[cursor];
            }
            cursor++;
            chunk_output++;
          }
          else {
            if (!cfbf_range_available(chunk_end, cursor, 2)) {
              return false;
            }
            const uint16_t token = cfbf_read_le16(data + cursor);
            uint32_t offset_bits = 4;

            cursor += 2;
            while (offset_bits < 12
                   && (UINT32_C(1) << offset_bits) < chunk_output) {
              offset_bits++;
            }
            const uint16_t length_mask = (uint16_t)(UINT16_MAX
                                                    >> offset_bits);
            const uint32_t copy_offset =
                (uint32_t)(token >> (16 - offset_bits)) + 1;
            const uint32_t copy_length =
                (uint32_t)(token & length_mask) + 3;

            if (copy_offset > chunk_output
                || copy_length > 4096 - chunk_output) {
              return false;
            }
            if (output) {
              if (!cfbf_range_available(output_capacity,
                                        total_output + chunk_output,
                                        copy_length)) {
                return false;
              }
              for (uint32_t copy = 0; copy < copy_length; copy++) {
                output[total_output + chunk_output + copy] =
                    output[total_output + chunk_output + copy
                           - copy_offset];
              }
            }
            chunk_output += copy_length;
          }
        }
      }
      if (chunk_output == 0) {
        return false;
      }
    }
    if (cursor != chunk_end
        || total_output > UINT64_MAX - chunk_output) {
      return false;
    }
    total_output += chunk_output;
    position = chunk_end;
    chunks++;
  }
  *output_length = total_output;
  return position == length && chunks != 0;
}

// Decompress a validated MS-OVBA container into a caller-owned buffer.
//
static inline bool cfbf_decompress_vba_compressed_container(
    const uint8_t *data, uint64_t length, uint8_t **output,
    uint64_t *output_length) {

  if (!output || !output_length) {
    return false;
  }
  *output = NULL;
  *output_length = 0;
  uint64_t required = 0;

  if (!cfbf_process_vba_compressed_container(
          data, length, NULL, 0, &required)
      || required == 0 || required > SIZE_MAX) {
    return false;
  }
  uint8_t *decoded = (uint8_t *)malloc((size_t)required);
  check_memory_allocation(decoded, __LINE__, __FILE__,
                          "CFBF VBA decompressed stream");
  uint64_t produced = 0;

  if (!cfbf_process_vba_compressed_container(
          data, length, decoded, required, &produced)
      || produced != required) {
    free(decoded);
    return false;
  }
  *output = decoded;
  *output_length = produced;
  return true;
}

// Validate the token framing and back references without retaining output.
//
static inline bool cfbf_validate_vba_compressed_container(
    const uint8_t *data, uint64_t length) {

  uint64_t output_length = 0;

  return cfbf_process_vba_compressed_container(
      data, length, NULL, 0, &output_length);
}

// Read a conventional MS-OVBA record whose identifier and payload size are
// followed by the payload bytes.
//
static inline bool cfbf_read_vba_record(
    const uint8_t *data, uint64_t length, uint64_t *position,
    uint16_t expected_identifier, const uint8_t **payload,
    uint32_t *payload_length) {

  if (!data || !position
      || !cfbf_range_available(length, *position, 6)
      || cfbf_read_le16(data + *position) != expected_identifier) {
    return false;
  }
  const uint32_t size = cfbf_read_le32(data + *position + 2);
  const uint64_t start = *position + 6;

  if (!cfbf_range_available(length, start, size)) {
    return false;
  }
  if (payload) {
    *payload = data + start;
  }
  if (payload_length) {
    *payload_length = size;
  }
  *position = start + size;
  return true;
}

// Convert the UTF-16LE module stream name to the representation used for CFBF
// directory entries. Application-defined non-ASCII characters map to '?'.
//
static inline bool cfbf_decode_vba_stream_name(
    const uint8_t *data, uint32_t length, char name[65]) {

  if (!data || !name || length == 0 || (length & 1) != 0
      || length / 2 >= 65) {
    return false;
  }
  const uint32_t characters = length / 2;

  memset(name, 0, 65);
  for (uint32_t index = 0; index < characters; index++) {
    const uint16_t value = cfbf_read_le16(data + (uint64_t)index * 2);

    if (value == 0) {
      return false;
    }
    name[index] = value <= 0x7f ? (char)value : '?';
  }
  return true;
}

// Parse one MODULE record and validate the compressed source carried by the
// corresponding stream in the VBA storage.
//
static inline bool cfbf_validate_vba_module_record(
    const CfbfLayout *layout, const CfbfDirectoryEntry *vba,
    const uint8_t *data, uint64_t length, uint64_t *position) {

  const uint8_t *payload = NULL;
  uint32_t payload_length = 0;

  if (!cfbf_read_vba_record(data, length, position, UINT16_C(0x0019),
                            NULL, NULL)) {
    return false;
  }
  if (cfbf_range_available(length, *position, 2)
      && cfbf_read_le16(data + *position) == UINT16_C(0x0047)
      && !cfbf_read_vba_record(data, length, position,
                               UINT16_C(0x0047), NULL, NULL)) {
    return false;
  }
  if (!cfbf_read_vba_record(data, length, position, UINT16_C(0x001a),
                            NULL, NULL)
      || !cfbf_range_available(length, *position, 6)
      || cfbf_read_le16(data + *position) != UINT16_C(0x0032)) {
    return false;
  }
  payload_length = cfbf_read_le32(data + *position + 2);
  *position += 6;
  if (!cfbf_range_available(length, *position, payload_length)) {
    return false;
  }
  char stream_name[65];

  if (!cfbf_decode_vba_stream_name(data + *position, payload_length,
                                   stream_name)) {
    return false;
  }
  *position += payload_length;
  if (!cfbf_read_vba_record(data, length, position, UINT16_C(0x001c),
                            NULL, NULL)
      || !cfbf_range_available(length, *position, 6)
      || cfbf_read_le16(data + *position) != UINT16_C(0x0048)) {
    return false;
  }
  payload_length = cfbf_read_le32(data + *position + 2);
  *position += 6;
  if (!cfbf_range_available(length, *position, payload_length)) {
    return false;
  }
  *position += payload_length;
  if (!cfbf_read_vba_record(data, length, position, UINT16_C(0x0031),
                            &payload, &payload_length)
      || payload_length != 4) {
    return false;
  }
  const uint32_t source_offset = cfbf_read_le32(payload);

  if (!cfbf_read_vba_record(data, length, position, UINT16_C(0x001e),
                            NULL, &payload_length)
      || payload_length != 4
      || !cfbf_read_vba_record(data, length, position,
                               UINT16_C(0x002c), NULL, &payload_length)
      || payload_length != 2
      || !cfbf_range_available(length, *position, 6)) {
    return false;
  }
  const uint16_t module_type = cfbf_read_le16(data + *position);

  if (module_type != UINT16_C(0x0021)
      && module_type != UINT16_C(0x0022)) {
    return false;
  }
  *position += 6;
  const uint16_t optional_records[] = {
    UINT16_C(0x0025), UINT16_C(0x0028)
  };

  for (uint32_t index = 0;
       index < sizeof(optional_records) / sizeof(optional_records[0]);
       index++) {
    if (cfbf_range_available(length, *position, 2)
        && cfbf_read_le16(data + *position) == optional_records[index]) {
      if (!cfbf_range_available(length, *position, 6)) {
        return false;
      }
      *position += 6;
    }
  }
  if (!cfbf_range_available(length, *position, 6)
      || cfbf_read_le16(data + *position) != UINT16_C(0x002b)) {
    return false;
  }
  *position += 6;

  const CfbfDirectoryEntry *module = cfbf_find_child_directory(
      layout, vba, stream_name);
  uint8_t *module_data = NULL;
  uint64_t module_length = 0;
  const bool valid = module && module->object_type == 2
                     && cfbf_materialize_stream(layout, module,
                                                &module_data,
                                                &module_length)
                     && source_offset < module_length
                     && cfbf_validate_vba_compressed_container(
                            module_data + source_offset,
                            module_length - source_offset);

  free(module_data);
  return valid;
}

// Locate the declared module table in a decompressed dir stream and require
// every module record to resolve to a structurally valid source stream.
//
static inline bool cfbf_validate_vba_modules(
    const CfbfLayout *layout, const CfbfDirectoryEntry *vba,
    const uint8_t *directory_data, uint64_t directory_length) {

  if (!layout || !vba || !directory_data || directory_length < 16) {
    return false;
  }
  for (uint64_t start = 0; start <= directory_length - 16; start++) {
    if (cfbf_read_le16(directory_data + start) != UINT16_C(0x000f)
        || cfbf_read_le32(directory_data + start + 2) != 2) {
      continue;
    }
    const uint16_t module_count = cfbf_read_le16(
        directory_data + start + 6);
    if (module_count == 0 || module_count > layout->directory_count
        || cfbf_read_le16(directory_data + start + 8)
               != UINT16_C(0x0013)
        || cfbf_read_le32(directory_data + start + 10) != 2) {
      continue;
    }
    uint64_t position = start + 16;
    bool valid = true;

    for (uint16_t module = 0; module < module_count; module++) {
      if (!cfbf_validate_vba_module_record(
              layout, vba, directory_data, directory_length, &position)) {
        valid = false;
        break;
      }
    }
    if (valid) {
      return true;
    }
  }
  return false;
}

// Identify implementation-specific VBA performance-cache streams. Their
// contents are opaque, so they are useful for relative consistency ranking but
// never as a validity requirement.
//
static inline bool cfbf_name_is_vba_srp(const CfbfDirectoryEntry *entry) {

  static const char prefix[] = "__SRP_";

  if (!entry || entry->object_type != 2
      || !cfbf_name_starts_with(entry, prefix)) {
    return false;
  }
  const char *suffix = entry->name + sizeof(prefix) - 1;

  if (*suffix == '\0') {
    return false;
  }
  while (*suffix != '\0') {
    if (!((*suffix >= '0' && *suffix <= '9')
          || (*suffix >= 'a' && *suffix <= 'f')
          || (*suffix >= 'A' && *suffix <= 'F'))) {
      return false;
    }
    suffix++;
  }
  return true;
}

// Same-length VBA performance caches are emitted from related compiler state.
// Compare every such pair to rank otherwise valid mappings without treating an
// undocumented cache representation as proof of validity.
//
static inline void cfbf_collect_ppa_srp_coherence(
    const CfbfLayout *layout, const CfbfDirectoryEntry *vba,
    CfbfSemanticEvidence *evidence) {

  if (!layout || !layout->directories || !vba || !evidence
      || vba < layout->directories
      || vba >= layout->directories + layout->directory_count) {
    return;
  }
  const uint64_t vba_index = (uint64_t)(vba - layout->directories);
  uint64_t stream_count = 0;

  for (uint64_t index = 0; index < layout->directory_count; index++) {
    const CfbfDirectoryEntry *entry = &layout->directories[index];

    if (entry->parent == vba_index && entry->stream_size != 0
        && cfbf_name_is_vba_srp(entry)) {
      stream_count++;
    }
  }
  if (stream_count < 2 || stream_count > SIZE_MAX / sizeof(void *)) {
    return;
  }

  const CfbfDirectoryEntry **streams =
      (const CfbfDirectoryEntry **)malloc(
          (size_t)stream_count * sizeof(*streams));
  uint8_t **payloads = (uint8_t **)calloc(
      (size_t)stream_count, sizeof(*payloads));
  uint64_t *lengths = (uint64_t *)calloc(
      (size_t)stream_count, sizeof(*lengths));

  check_memory_allocation(streams, __LINE__, __FILE__,
                          "PPA SRP stream list");
  check_memory_allocation(payloads, __LINE__, __FILE__,
                          "PPA SRP payload list");
  check_memory_allocation(lengths, __LINE__, __FILE__,
                          "PPA SRP length list");

  uint64_t stream = 0;

  for (uint64_t index = 0; index < layout->directory_count; index++) {
    const CfbfDirectoryEntry *entry = &layout->directories[index];

    if (entry->parent == vba_index && entry->stream_size != 0
        && cfbf_name_is_vba_srp(entry)) {
      streams[stream++] = entry;
    }
  }
  for (uint64_t left = 0; left < stream_count; left++) {
    bool has_peer = false;

    for (uint64_t right = 0; right < stream_count; right++) {
      if (left != right
          && streams[left]->stream_size == streams[right]->stream_size) {
        has_peer = true;
        break;
      }
    }
    if (has_peer) {
      (void)cfbf_materialize_stream(layout, streams[left],
                                    &payloads[left], &lengths[left]);
    }
  }
  for (uint64_t left = 0; left < stream_count; left++) {
    if (!payloads[left]) {
      continue;
    }
    for (uint64_t right = left + 1; right < stream_count; right++) {
      if (!payloads[right] || lengths[left] != lengths[right]) {
        continue;
      }
      uint64_t difference = 0;

      for (uint64_t byte = 0; byte < lengths[left]; byte++) {
        if (payloads[left][byte] != payloads[right][byte]) {
          difference++;
        }
      }
      if (evidence->coherence_payloads < UINT32_MAX) {
        evidence->coherence_payloads++;
      }
      if (UINT64_MAX - evidence->coherence_cost < difference) {
        evidence->coherence_cost = UINT64_MAX;
      }
      else {
        evidence->coherence_cost += difference;
      }
      if (UINT64_MAX - evidence->coherence_extent < lengths[left]) {
        evidence->coherence_extent = UINT64_MAX;
      }
      else {
        evidence->coherence_extent += lengths[left];
      }
    }
  }
  for (uint64_t index = 0; index < stream_count; index++) {
    free(payloads[index]);
  }
  free(lengths);
  free(payloads);
  free(streams);
}

// A PowerPoint add-in is a VBA project rather than a presentation stream.
// Validate its defining CLSID, textual project description, compiled project
// header, and compressed directory before assigning a strong semantic result.
//
static inline bool cfbf_validate_ppa_streams(
    const CfbfLayout *layout, CfbfSemanticEvidence *evidence) {

  if (!cfbf_clsid_equals(layout, cfbf_ppa_root_clsid)) {
    return false;
  }
  const CfbfDirectoryEntry *vba = cfbf_find_directory(layout, "VBA");

  if (!vba || vba->object_type != 1
      || vba->parent >= layout->directory_count) {
    return false;
  }
  const CfbfDirectoryEntry *project_parent =
      &layout->directories[vba->parent];
  const CfbfDirectoryEntry *project = cfbf_find_child_directory(
      layout, project_parent, "PROJECT");
  const CfbfDirectoryEntry *directory = cfbf_find_child_directory(
      layout, vba, "dir");
  const CfbfDirectoryEntry *compiled = cfbf_find_child_directory(
      layout, vba, "_VBA_PROJECT");
  uint8_t *project_data = NULL;
  uint8_t *directory_data = NULL;
  uint8_t *decoded_directory = NULL;
  uint8_t *compiled_data = NULL;
  uint64_t project_length = 0;
  uint64_t directory_length = 0;
  uint64_t decoded_directory_length = 0;
  uint64_t compiled_length = 0;

  const bool valid = project && directory && compiled
                     && cfbf_materialize_stream(layout, project,
                                                &project_data,
                                                &project_length)
                     && cfbf_materialize_stream(layout, directory,
                                                &directory_data,
                                                &directory_length)
                     && cfbf_materialize_stream(layout, compiled,
                                                &compiled_data,
                                                &compiled_length)
                     && cfbf_contains_bytes(project_data, project_length,
                                            "ID=\"")
                     && cfbf_contains_bytes(project_data, project_length,
                                            "Name=\"")
                     && compiled_length >= 2
                     && cfbf_read_le16(compiled_data) == UINT16_C(0x61cc)
                     && cfbf_decompress_vba_compressed_container(
                            directory_data, directory_length,
                            &decoded_directory,
                            &decoded_directory_length)
                     && cfbf_validate_vba_modules(
                            layout, vba, decoded_directory,
                            decoded_directory_length);

  if (valid) {
    cfbf_collect_ppa_srp_coherence(layout, vba, evidence);
  }

  free(decoded_directory);
  free(compiled_data);
  free(directory_data);
  free(project_data);
  return valid;
}

// Validate the Word FIB and the CLX piece table that maps logical characters
// into the WordDocument stream. The piece table supplies order-sensitive
// cross-stream evidence that simple CFBF allocation checks cannot provide,
// including the required paragraph mark at the end of the main document.
//
static inline bool cfbf_validate_doc_clx(const uint8_t *word,
                                         uint64_t word_length,
                                         const uint8_t *table,
                                         uint64_t table_length) {

  if (!word || !table || word_length < 154
      || cfbf_read_le16(word) != UINT16_C(0xa5ec)) {
    return false;
  }
  const uint32_t fc_min = cfbf_read_le32(word + 24);
  const uint32_t fc_mac = cfbf_read_le32(word + 28);
  if (fc_min > fc_mac || fc_mac > word_length) {
    return false;
  }

  uint64_t offset = 32;
  const uint16_t csw = cfbf_read_le16(word + offset);
  offset += 2;
  if (!cfbf_range_available(word_length, offset, (uint64_t)csw * 2 + 2)) {
    return false;
  }
  offset += (uint64_t)csw * 2;
  const uint16_t cslw = cfbf_read_le16(word + offset);
  offset += 2;
  if (!cfbf_range_available(word_length, offset, (uint64_t)cslw * 4 + 2)) {
    return false;
  }
  if (cslw <= 3) {
    return false;
  }
  const uint32_t ccp_text = cfbf_read_le32(word + offset + 3 * 4);
  if (ccp_text == 0 || ccp_text > INT32_MAX) {
    return false;
  }
  offset += (uint64_t)cslw * 4;
  const uint16_t pairs = cfbf_read_le16(word + offset);
  offset += 2;
  if (pairs <= 33
      || !cfbf_range_available(word_length, offset,
                               (uint64_t)pairs * 8)) {
    return false;
  }
  const uint32_t fc_clx = cfbf_read_le32(word + offset + 33 * 8);
  const uint32_t lcb_clx = cfbf_read_le32(word + offset + 33 * 8 + 4);
  if (lcb_clx < 5 || !cfbf_range_available(table_length, fc_clx, lcb_clx)) {
    return false;
  }

  uint64_t clx = fc_clx;
  const uint64_t clx_end = (uint64_t)fc_clx + lcb_clx;
  while (clx < clx_end && table[clx] == 1) {
    if (!cfbf_range_available(clx_end, clx + 1, 2)) {
      return false;
    }
    const uint16_t grpprl = cfbf_read_le16(table + clx + 1);
    if (!cfbf_range_available(clx_end, clx + 3, grpprl)) {
      return false;
    }
    clx += 3 + grpprl;
  }
  if (!cfbf_range_available(clx_end, clx, 5) || table[clx] != 2) {
    return false;
  }
  const uint32_t plc_size = cfbf_read_le32(table + clx + 1);
  clx += 5;
  if (plc_size < 16 || (plc_size - 4) % 12 != 0
      || !cfbf_range_available(clx_end, clx, plc_size)) {
    return false;
  }
  const uint64_t pieces = (plc_size - 4) / 12;
  const uint64_t cp_bytes = (pieces + 1) * 4;
  uint32_t previous_cp = cfbf_read_le32(table + clx);
  uint64_t characters_checked = 0;
  uint64_t unusual_controls = 0;
  bool high_surrogate = false;
  bool main_document_end_found = false;

  if (previous_cp != 0) {
    return false;
  }
  for (uint64_t piece = 0; piece < pieces; piece++) {
    const uint32_t next_cp = cfbf_read_le32(
        table + clx + (piece + 1) * 4);
    if (next_cp < previous_cp || next_cp > INT32_MAX) {
      return false;
    }
    const uint64_t pcd = clx + cp_bytes + piece * 8;
    const uint16_t pcd_flags = cfbf_read_le16(table + pcd);
    const uint32_t raw_fc = cfbf_read_le32(table + pcd + 2);
    const bool compressed = (raw_fc & UINT32_C(0x40000000)) != 0;
    uint64_t file_offset = raw_fc & UINT32_C(0x3fffffff);

    // A dirty Pcd cannot be used by a conforming Word document.
    if ((pcd_flags & UINT16_C(0x0004)) != 0) {
      return false;
    }
    if (compressed) {
      file_offset /= 2;
    }
    const uint64_t characters = (uint64_t)next_cp - previous_cp;
    const uint64_t bytes = characters * (compressed ? 1 : 2);
    if (!cfbf_range_available(word_length, file_offset, bytes)) {
      return false;
    }

    for (uint64_t index = 0; index < characters; index++) {
      const uint16_t character = compressed
                                     ? word[file_offset + index]
                                     : cfbf_read_le16(
                                           word + file_offset + index * 2);

      if (high_surrogate) {
        if (character < UINT16_C(0xdc00)
            || character > UINT16_C(0xdfff)) {
          return false;
        }
        high_surrogate = false;
      }
      else if (character >= UINT16_C(0xd800)
               && character <= UINT16_C(0xdbff)) {
        high_surrogate = true;
      }
      else if (character >= UINT16_C(0xdc00)
               && character <= UINT16_C(0xdfff)) {
        return false;
      }

      const bool expected_control = character == UINT16_C(0x0001)
                                    || character == UINT16_C(0x0002)
                                    || character == UINT16_C(0x0005)
                                    || character == UINT16_C(0x0007)
                                    || character == UINT16_C(0x0009)
                                    || character == UINT16_C(0x000a)
                                    || character == UINT16_C(0x000b)
                                    || character == UINT16_C(0x000c)
                                    || character == UINT16_C(0x000d)
                                    || character == UINT16_C(0x0013)
                                    || character == UINT16_C(0x0014)
                                    || character == UINT16_C(0x0015)
                                    || character == UINT16_C(0x001e)
                                    || character == UINT16_C(0x001f);

      if ((character < UINT16_C(0x0020) && !expected_control)
          || character == UINT16_C(0x007f)) {
        unusual_controls++;
      }
      if ((uint64_t)previous_cp + index + 1 == ccp_text) {
        if (character != UINT16_C(0x000d)) {
          return false;
        }
        main_document_end_found = true;
      }
      characters_checked++;
    }
    previous_cp = next_cp;
  }
  // Word text legitimately embeds control characters for fields, tables, and
  // document marks. Reject only when uncommon controls form a sustained part
  // of the decoded piece text rather than a small document-specific exception.
  if (!main_document_end_found || high_surrogate
      || (unusual_controls > 16
                         && unusual_controls > characters_checked / 128)) {
    return false;
  }
  return clx + plc_size == clx_end;
}

// OfficeArt picture UIDs use MD4 over the uncompressed picture bytes. Keeping
// this implementation local avoids relying on an optional legacy crypto
// provider when validating old Office files.
//
static inline uint32_t cfbf_rotate_left32(uint32_t value, uint32_t shift) {

  return (value << shift) | (value >> (32 - shift));
}

static inline void cfbf_md4_transform(CfbfMd4State *state,
                                      const uint8_t block[64]) {

  uint32_t values[16];
  for (uint32_t index = 0; index < 16; index++) {
    values[index] = cfbf_read_le32(block + index * 4);
  }

  uint32_t a = state->words[0];
  uint32_t b = state->words[1];
  uint32_t c = state->words[2];
  uint32_t d = state->words[3];

#define CFBF_MD4_F(x, y, z) (((x) & (y)) | (~(x) & (z)))
#define CFBF_MD4_G(x, y, z) (((x) & (y)) | ((x) & (z)) | ((y) & (z)))
#define CFBF_MD4_H(x, y, z) ((x) ^ (y) ^ (z))
#define CFBF_MD4_F_STEP(x, y, z, w, index, shift)                         \
  do {                                                                    \
    (x) = cfbf_rotate_left32((x) + CFBF_MD4_F((y), (z), (w))             \
                                  + values[(index)], (shift));            \
  } while (0)
#define CFBF_MD4_G_STEP(x, y, z, w, index, shift)                         \
  do {                                                                    \
    (x) = cfbf_rotate_left32((x) + CFBF_MD4_G((y), (z), (w))             \
                                  + values[(index)]                       \
                                  + UINT32_C(0x5a827999), (shift));       \
  } while (0)
#define CFBF_MD4_H_STEP(x, y, z, w, index, shift)                         \
  do {                                                                    \
    (x) = cfbf_rotate_left32((x) + CFBF_MD4_H((y), (z), (w))             \
                                  + values[(index)]                       \
                                  + UINT32_C(0x6ed9eba1), (shift));       \
  } while (0)

  CFBF_MD4_F_STEP(a, b, c, d, 0, 3);
  CFBF_MD4_F_STEP(d, a, b, c, 1, 7);
  CFBF_MD4_F_STEP(c, d, a, b, 2, 11);
  CFBF_MD4_F_STEP(b, c, d, a, 3, 19);
  CFBF_MD4_F_STEP(a, b, c, d, 4, 3);
  CFBF_MD4_F_STEP(d, a, b, c, 5, 7);
  CFBF_MD4_F_STEP(c, d, a, b, 6, 11);
  CFBF_MD4_F_STEP(b, c, d, a, 7, 19);
  CFBF_MD4_F_STEP(a, b, c, d, 8, 3);
  CFBF_MD4_F_STEP(d, a, b, c, 9, 7);
  CFBF_MD4_F_STEP(c, d, a, b, 10, 11);
  CFBF_MD4_F_STEP(b, c, d, a, 11, 19);
  CFBF_MD4_F_STEP(a, b, c, d, 12, 3);
  CFBF_MD4_F_STEP(d, a, b, c, 13, 7);
  CFBF_MD4_F_STEP(c, d, a, b, 14, 11);
  CFBF_MD4_F_STEP(b, c, d, a, 15, 19);

  CFBF_MD4_G_STEP(a, b, c, d, 0, 3);
  CFBF_MD4_G_STEP(d, a, b, c, 4, 5);
  CFBF_MD4_G_STEP(c, d, a, b, 8, 9);
  CFBF_MD4_G_STEP(b, c, d, a, 12, 13);
  CFBF_MD4_G_STEP(a, b, c, d, 1, 3);
  CFBF_MD4_G_STEP(d, a, b, c, 5, 5);
  CFBF_MD4_G_STEP(c, d, a, b, 9, 9);
  CFBF_MD4_G_STEP(b, c, d, a, 13, 13);
  CFBF_MD4_G_STEP(a, b, c, d, 2, 3);
  CFBF_MD4_G_STEP(d, a, b, c, 6, 5);
  CFBF_MD4_G_STEP(c, d, a, b, 10, 9);
  CFBF_MD4_G_STEP(b, c, d, a, 14, 13);
  CFBF_MD4_G_STEP(a, b, c, d, 3, 3);
  CFBF_MD4_G_STEP(d, a, b, c, 7, 5);
  CFBF_MD4_G_STEP(c, d, a, b, 11, 9);
  CFBF_MD4_G_STEP(b, c, d, a, 15, 13);

  CFBF_MD4_H_STEP(a, b, c, d, 0, 3);
  CFBF_MD4_H_STEP(d, a, b, c, 8, 9);
  CFBF_MD4_H_STEP(c, d, a, b, 4, 11);
  CFBF_MD4_H_STEP(b, c, d, a, 12, 15);
  CFBF_MD4_H_STEP(a, b, c, d, 2, 3);
  CFBF_MD4_H_STEP(d, a, b, c, 10, 9);
  CFBF_MD4_H_STEP(c, d, a, b, 6, 11);
  CFBF_MD4_H_STEP(b, c, d, a, 14, 15);
  CFBF_MD4_H_STEP(a, b, c, d, 1, 3);
  CFBF_MD4_H_STEP(d, a, b, c, 9, 9);
  CFBF_MD4_H_STEP(c, d, a, b, 5, 11);
  CFBF_MD4_H_STEP(b, c, d, a, 13, 15);
  CFBF_MD4_H_STEP(a, b, c, d, 3, 3);
  CFBF_MD4_H_STEP(d, a, b, c, 11, 9);
  CFBF_MD4_H_STEP(c, d, a, b, 7, 11);
  CFBF_MD4_H_STEP(b, c, d, a, 15, 15);

#undef CFBF_MD4_H_STEP
#undef CFBF_MD4_G_STEP
#undef CFBF_MD4_F_STEP
#undef CFBF_MD4_H
#undef CFBF_MD4_G
#undef CFBF_MD4_F

  state->words[0] += a;
  state->words[1] += b;
  state->words[2] += c;
  state->words[3] += d;
}

static inline void cfbf_md4_initialize(CfbfMd4State *state) {

  memset(state, 0, sizeof(*state));
  state->words[0] = UINT32_C(0x67452301);
  state->words[1] = UINT32_C(0xefcdab89);
  state->words[2] = UINT32_C(0x98badcfe);
  state->words[3] = UINT32_C(0x10325476);
}

static inline void cfbf_md4_update(CfbfMd4State *state,
                                   const uint8_t *data, uint64_t length) {

  if (!state || (!data && length != 0)) {
    return;
  }
  state->length += length;
  if (state->block_length != 0) {
    uint64_t copied = 64 - state->block_length;
    if (copied > length) {
      copied = length;
    }
    memcpy(state->block + state->block_length, data, (size_t)copied);
    state->block_length += (uint32_t)copied;
    data += copied;
    length -= copied;
    if (state->block_length == 64) {
      cfbf_md4_transform(state, state->block);
      state->block_length = 0;
    }
  }
  while (length >= 64) {
    cfbf_md4_transform(state, data);
    data += 64;
    length -= 64;
  }
  if (length != 0) {
    memcpy(state->block, data, (size_t)length);
    state->block_length = (uint32_t)length;
  }
}

static inline void cfbf_md4_finish(CfbfMd4State *state,
                                   uint8_t digest[16]) {

  static const uint8_t padding[64] = { 0x80 };
  const uint64_t bit_length = state->length * 8;
  const uint32_t padding_length = state->block_length < 56
                                      ? 56 - state->block_length
                                      : 120 - state->block_length;
  uint8_t encoded_length[8];

  for (uint32_t byte = 0; byte < 8; byte++) {
    encoded_length[byte] = (uint8_t)(bit_length >> (byte * 8));
  }
  cfbf_md4_update(state, padding, padding_length);
  cfbf_md4_update(state, encoded_length, sizeof(encoded_length));
  for (uint32_t word = 0; word < 4; word++) {
    for (uint32_t byte = 0; byte < 4; byte++) {
      digest[word * 4 + byte] = (uint8_t)(state->words[word]
                                          >> (byte * 8));
    }
  }
}

static inline void cfbf_md4_digest(const uint8_t *data, uint64_t length,
                                   uint8_t digest[16]) {

  CfbfMd4State state;

  cfbf_md4_initialize(&state);
  cfbf_md4_update(&state, data, length);
  cfbf_md4_finish(&state, digest);
}

// Hash a zlib-wrapped OfficeArt metafile without materializing the expanded
// stream. This keeps validation memory bounded by a small fixed buffer.
//
static inline bool cfbf_md4_inflate(const uint8_t *data, uint64_t length,
                                    uint64_t expected_length,
                                    uint8_t digest[16]) {

  if ((!data && length != 0) || !digest
      || length > CFBF_MAXIMUM_SIZE
      || expected_length > CFBF_MAXIMUM_SIZE) {
    return false;
  }
  z_stream stream;
  memset(&stream, 0, sizeof(stream));
  if (inflateInit(&stream) != Z_OK) {
    return false;
  }

  CfbfMd4State state;
  cfbf_md4_initialize(&state);
  uint8_t output[32768];
  uint64_t assigned = 0;
  uint64_t expanded = 0;
  bool valid = false;

  for (;;) {
    if (stream.avail_in == 0 && assigned < length) {
      uint64_t count = length - assigned;
      if (count > UINT_MAX) {
        count = UINT_MAX;
      }
      stream.next_in = (Bytef *)(data + assigned);
      stream.avail_in = (uInt)count;
      assigned += count;
    }
    stream.next_out = output;
    stream.avail_out = (uInt)sizeof(output);
    const int status = inflate(&stream, Z_NO_FLUSH);
    const uint64_t produced = sizeof(output) - stream.avail_out;

    if (produced != 0) {
      cfbf_md4_update(&state, output, produced);
      expanded += produced;
      if (expanded > expected_length) {
        break;
      }
    }
    if (status == Z_STREAM_END) {
      valid = expanded == expected_length && assigned == length
              && stream.avail_in == 0;
      break;
    }
    if (status != Z_OK
        || (produced == 0 && stream.avail_in == 0
            && assigned == length)) {
      break;
    }
  }
  inflateEnd(&stream);
  if (valid) {
    cfbf_md4_finish(&state, digest);
  }
  return valid;
}

// Validate one OfficeArt BLIP or embedded FBSE record and return the digest
// that identifies its uncompressed picture data.
//
static inline bool cfbf_validate_officeart_blip(const uint8_t *data,
                                                uint64_t length,
                                                uint8_t digest[16],
                                                bool *authenticated) {

  if (!data || !digest || !authenticated || length < 8) {
    return false;
  }
  *authenticated = false;
  const uint16_t version_instance = cfbf_read_le16(data);
  const uint8_t version = (uint8_t)(version_instance & 0x0f);
  const uint16_t instance = version_instance >> 4;
  const uint16_t type = cfbf_read_le16(data + 2);
  const uint32_t size = cfbf_read_le32(data + 4);

  if ((uint64_t)size + 8 != length) {
    return false;
  }
  if (type == UINT16_C(0xf007)) {
    if (version != 2 || size < 36) {
      return false;
    }
    const uint8_t *body = data + 8;
    const uint8_t windows_type = body[0];
    const uint8_t mac_type = body[1];
    const uint32_t embedded_size = cfbf_read_le32(body + 20);
    const uint32_t references = cfbf_read_le32(body + 24);
    const uint32_t delayed_offset = cfbf_read_le32(body + 28);
    const uint8_t name_length = body[33];

    if ((instance != windows_type && instance != mac_type)
        || (name_length & 1) != 0
        || name_length > size - 36) {
      return false;
    }
    if (name_length != 0
        && (body[36 + name_length - 2] != 0
            || body[36 + name_length - 1] != 0)) {
      return false;
    }
    const uint64_t blip_offset = 8 + 36 + name_length;
    const uint64_t blip_length = length - blip_offset;
    if (blip_length == 0) {
      if (delayed_offset == UINT32_C(0xffffffff) && references != 0) {
        return false;
      }
      memcpy(digest, body + 2, 16);
      return true;
    }
    bool embedded_authenticated = false;
    if (embedded_size != blip_length
        || !cfbf_validate_officeart_blip(data + blip_offset, blip_length,
                                         digest, &embedded_authenticated)
        || memcmp(body + 2, digest, 16) != 0) {
      return false;
    }
    *authenticated = true;
    return true;
  }
  if (version != 0) {
    return false;
  }

  bool metafile = false;
  bool two_uids = false;
  switch (type) {
    case UINT16_C(0xf01a):
      metafile = true;
      if (instance != UINT16_C(0x3d4)
          && instance != UINT16_C(0x3d5)) {
        return false;
      }
      two_uids = instance == UINT16_C(0x3d5);
      break;
    case UINT16_C(0xf01b):
      metafile = true;
      if (instance != UINT16_C(0x216)
          && instance != UINT16_C(0x217)) {
        return false;
      }
      two_uids = instance == UINT16_C(0x217);
      break;
    case UINT16_C(0xf01c):
      metafile = true;
      if (instance != UINT16_C(0x542)
          && instance != UINT16_C(0x543)) {
        return false;
      }
      two_uids = instance == UINT16_C(0x543);
      break;
    case UINT16_C(0xf01d):
    case UINT16_C(0xf02a):
      if (instance != UINT16_C(0x46a)
          && instance != UINT16_C(0x46b)
          && instance != UINT16_C(0x6e2)
          && instance != UINT16_C(0x6e3)) {
        return false;
      }
      two_uids = instance == UINT16_C(0x46b)
                 || instance == UINT16_C(0x6e3);
      break;
    case UINT16_C(0xf01e):
      if (instance != UINT16_C(0x6e0)
          && instance != UINT16_C(0x6e1)) {
        return false;
      }
      two_uids = instance == UINT16_C(0x6e1);
      break;
    case UINT16_C(0xf01f):
      if (instance != UINT16_C(0x7a8)
          && instance != UINT16_C(0x7a9)) {
        return false;
      }
      two_uids = instance == UINT16_C(0x7a9);
      break;
    case UINT16_C(0xf029):
      if (instance != UINT16_C(0x6e4)
          && instance != UINT16_C(0x6e5)) {
        return false;
      }
      two_uids = instance == UINT16_C(0x6e5);
      break;
    default:
      return false;
  }

  const uint64_t uid_length = two_uids ? 32 : 16;
  const uint8_t *expected_digest = data + 8 + (two_uids ? 16 : 0);
  if (metafile) {
    const uint64_t fixed_length = uid_length + 34;
    if (size < fixed_length) {
      return false;
    }
    const uint8_t *header = data + 8 + uid_length;
    const uint8_t *payload = header + 34;
    const uint64_t payload_length = size - fixed_length;
    const uint32_t expanded_length = cfbf_read_le32(header);
    const uint32_t stored_length = cfbf_read_le32(header + 28);
    const uint8_t compression = header[32];

    if (stored_length != payload_length || header[33] != 0xfe) {
      return false;
    }
    if (compression == 0xfe) {
      if (expanded_length != payload_length) {
        return false;
      }
      cfbf_md4_digest(payload, payload_length, digest);
    } else if (compression == 0) {
      if (!cfbf_md4_inflate(payload, payload_length, expanded_length,
                            digest)) {
        return false;
      }
    } else {
      return false;
    }
  } else {
    const uint64_t fixed_length = uid_length + 1;
    if (size < fixed_length) {
      return false;
    }
    cfbf_md4_digest(data + 8 + fixed_length, size - fixed_length, digest);
  }
  *authenticated = memcmp(expected_digest, digest, 16) == 0;

  // Some legacy writers leave a stale UID on an otherwise well-formed
  // compressed metafile. Successful decompression still proves its framing,
  // but only a matching UID authenticates its payload.
  return *authenticated || metafile;
}

// A PowerPoint Pictures stream contains OfficeArt image records followed, in
// some writers, by zero-filled reserved space. Known records are authenticated
// by their embedded digest; future record types retain strict outer framing.
//
static inline bool cfbf_validate_ppt_pictures(const uint8_t *data,
                                              uint64_t length) {

  if ((!data && length != 0) || length == 0) {
    return length == 0;
  }
  uint64_t offset = 0;
  uint64_t records = 0;
  bool authenticated = false;
  while (offset < length) {
    if (cfbf_all_zero(data + offset, length - offset)) {
      return records != 0 && authenticated;
    }
    if (!cfbf_range_available(length, offset, 8)) {
      return false;
    }
    const uint16_t version_instance = cfbf_read_le16(data + offset);
    const uint8_t version = (uint8_t)(version_instance & 0x0f);
    const uint16_t type = cfbf_read_le16(data + offset + 2);
    const uint32_t size = cfbf_read_le32(data + offset + 4);
    const uint64_t record_length = (uint64_t)size + 8;

    if (!cfbf_range_available(length, offset, record_length)) {
      return false;
    }
    if (type == UINT16_C(0xf007)
        || (type >= UINT16_C(0xf01a) && type <= UINT16_C(0xf01f))
        || type == UINT16_C(0xf029) || type == UINT16_C(0xf02a)) {
      uint8_t digest[16];
      bool record_authenticated = false;
      if (!cfbf_validate_officeart_blip(data + offset, record_length,
                                        digest,
                                        &record_authenticated)) {
        return false;
      }
      authenticated = authenticated || record_authenticated;
    } else if (version != 0 || type < UINT16_C(0xf018)
               || type > UINT16_C(0xf117)) {
      return false;
    }
    records++;
    offset += record_length;
  }
  return records != 0 && authenticated;
}

// Recursively validate PowerPoint record framing. Container records contain
// only child records, while atom records are skipped by their declared size.
//
static inline bool cfbf_validate_ppt_records(const uint8_t *data,
                                             uint64_t length,
                                             uint32_t depth,
                                             uint64_t *record_count) {

  if ((!data && length != 0) || !record_count || depth > 64) {
    return false;
  }
  uint64_t offset = 0;
  while (offset < length) {
    if (!cfbf_range_available(length, offset, 8)) {
      return false;
    }
    const uint16_t version_instance = cfbf_read_le16(data + offset);
    const uint8_t version = (uint8_t)(version_instance & 0x0f);
    const uint32_t size = cfbf_read_le32(data + offset + 4);
    if (!cfbf_range_available(length, offset + 8, size)) {
      return false;
    }
    (*record_count)++;
    if (version == 0x0f
        && !cfbf_validate_ppt_records(data + offset + 8, size, depth + 1,
                                      record_count)) {
      return false;
    }
    offset += 8 + size;
  }
  return offset == length;
}

// Find the direct child stream or storage that contains one MAPI property.
//
static inline const CfbfDirectoryEntry *cfbf_find_msg_property_value(
    const CfbfLayout *layout, const CfbfDirectoryEntry *parent,
    uint32_t property_tag) {

  static const char digits[] = "0123456789ABCDEF";
  char name[21] = "__substg1.0_00000000";

  for (uint32_t digit = 0; digit < 8; digit++) {
    const uint32_t shift = (7 - digit) * 4;

    name[12 + digit] = digits[(property_tag >> shift) & 0x0f];
  }
  return cfbf_find_child_directory(layout, parent, name);
}

// Validate the framing and checksum used by the compressed RTF MAPI
// property. The uncompressed representation has no checksum, but retains the
// same framing and a distinct magic value.
//
static inline bool cfbf_validate_rtf_compressed(const uint8_t *data,
                                                 uint64_t length) {

  if (!data || length < 16 || length - 4 > UINT32_MAX) {
    return false;
  }
  const uint32_t stored_length = cfbf_read_le32(data);
  const uint32_t magic = cfbf_read_le32(data + 8);
  const uint32_t expected_crc = cfbf_read_le32(data + 12);

  if (stored_length != length - 4) {
    return false;
  }
  if (magic == UINT32_C(0x414c454d)) {
    return expected_crc == 0;
  }
  if (magic != UINT32_C(0x75465a4c)) {
    return false;
  }

  uint32_t crc = 0;

  for (uint64_t offset = 16; offset < length; offset++) {
    crc ^= data[offset];
    for (uint32_t bit = 0; bit < 8; bit++) {
      crc = (crc >> 1) ^ ((crc & 1) != 0
                              ? UINT32_C(0xedb88320) : UINT32_C(0));
    }
  }
  return crc == expected_crc;
}

// Validate a large external MAPI Unicode value. UTF-16 surrogate pairs and
// Unicode noncharacters expose displaced binary blocks without imposing a
// language or script restriction. A very long run of one nonzero code point
// is retained as promising rather than accepted as authenticated message text.
//
static inline bool cfbf_validate_msg_unicode_stream(
    const uint8_t *data, uint64_t length) {

  if ((!data && length != 0) || (length & 1) != 0) {
    return false;
  }
  uint32_t previous = UINT32_MAX;
  uint32_t repeated = 0;

  for (uint64_t offset = 0; offset < length; offset += 2) {
    const uint16_t first = cfbf_read_le16(data + offset);
    uint32_t codepoint = first;

    if (first >= UINT16_C(0xd800) && first <= UINT16_C(0xdbff)) {
      if (!cfbf_range_available(length, offset + 2, 2)) {
        return false;
      }
      const uint16_t second = cfbf_read_le16(data + offset + 2);

      if (second < UINT16_C(0xdc00) || second > UINT16_C(0xdfff)) {
        return false;
      }
      codepoint = UINT32_C(0x10000)
                  + ((uint32_t)(first - UINT16_C(0xd800)) << 10)
                  + (uint32_t)(second - UINT16_C(0xdc00));
      offset += 2;
    }
    else if (first >= UINT16_C(0xdc00) && first <= UINT16_C(0xdfff)) {
      return false;
    }

    if ((codepoint >= UINT32_C(0xfdd0)
         && codepoint <= UINT32_C(0xfdef))
        || (codepoint & UINT32_C(0xffff)) == UINT32_C(0xfffe)
        || (codepoint & UINT32_C(0xffff)) == UINT32_C(0xffff)) {
      return false;
    }
    if (codepoint != 0 && codepoint == previous) {
      repeated++;
      if (repeated > CFBF_MAXIMUM_REPEATED_TEXT_CODEPOINT) {
        return false;
      }
    }
    else {
      repeated = 1;
    }
    previous = codepoint;
  }
  return true;
}

// Validate an embedded image with the corresponding complete-file validator.
// Other attachment types remain opaque to this additional semantic check.
//
static inline bool cfbf_validate_embedded_image(const uint8_t *data,
                                                uint64_t length) {

  if (!data || length == 0) {
    return false;
  }

  bool validates = false;
  bool promising = false;
  uint64_t validates_to = 0;

  if (length >= 3 && data[0] == 0xff && data[1] == 0xd8
      && data[2] == 0xff) {
    jpg_file_validate((char *)data, length, &validates, &validates_to,
                      &promising, 0, scalpel_state.blocksize, NULL);
  }
  else if (length >= 8
           && memcmp(data, "\x89PNG\r\n\x1a\n", 8) == 0) {
    validates = png_try_complete_contiguous(
        (char *)data, length, &validates_to);
  }
  else if (length >= 6
           && (memcmp(data, "GIF87a", 6) == 0
               || memcmp(data, "GIF89a", 6) == 0)) {
    gif_file_validate((char *)data, length, &validates, &validates_to,
                      &promising, 0, scalpel_state.blocksize, NULL);
  }
  else if (length >= 88
           && cfbf_read_le32(data) == UINT32_C(1)
           && cfbf_read_le32(data + 40) == UINT32_C(0x464d4520)) {
    return cfbf_validate_emf(data, length);
  }
  return validates && validates_to < length
         && validates_to + 1 == length;
}

// Validate the complete record chain of an Enhanced Metafile. An EPRINT
// stream can contain private data after the metafile, so the EMF header's
// declared byte count bounds the chain rather than the enclosing stream.
//
static inline bool cfbf_validate_emf(const uint8_t *data,
                                     uint64_t length) {

  if (!data || length < 88
      || cfbf_read_le32(data) != UINT32_C(1)) {
    return false;
  }
  const uint32_t header_size = cfbf_read_le32(data + 4);
  const uint32_t signature = cfbf_read_le32(data + 40);
  const uint32_t version = cfbf_read_le32(data + 44);
  const uint32_t emf_bytes = cfbf_read_le32(data + 48);
  const uint32_t declared_records = cfbf_read_le32(data + 52);

  if (header_size < 88 || (header_size & 3) != 0
      || header_size > length
      || signature != UINT32_C(0x464d4520)
      || version != UINT32_C(0x00010000)
      || emf_bytes < (uint64_t)header_size + 20 || (emf_bytes & 3) != 0
      || emf_bytes > length || declared_records < 2) {
    return false;
  }

  const uint32_t description_characters = cfbf_read_le32(data + 60);
  const uint32_t description_offset = cfbf_read_le32(data + 64);

  if (description_characters != 0
      && (description_characters > UINT32_MAX / 2
          || description_offset < 88
          || !cfbf_range_available(
                 header_size, description_offset,
                 (uint64_t)description_characters * 2))) {
    return false;
  }

  uint64_t offset = 0;
  uint32_t records = 0;
  bool saw_eof = false;

  while (offset < emf_bytes) {
    if (!cfbf_range_available(emf_bytes, offset, 8)) {
      return false;
    }
    const uint32_t type = cfbf_read_le32(data + offset);
    const uint32_t size = cfbf_read_le32(data + offset + 4);

    if (size < 8 || (size & 3) != 0
        || !cfbf_range_available(emf_bytes, offset, size)
        || (records == 0 ? type != UINT32_C(1)
                         : type == UINT32_C(1))) {
      return false;
    }
    if (type == UINT32_C(14)) {
      if (size < 20 || offset + size != emf_bytes
          || cfbf_read_le32(data + offset + size - 4) != size) {
        return false;
      }
      const uint32_t palette_entries = cfbf_read_le32(data + offset + 8);
      const uint32_t palette_offset = cfbf_read_le32(data + offset + 12);

      if (palette_entries != 0
          && (palette_entries > UINT32_MAX / 4
              || palette_offset < 16 || (palette_offset & 3) != 0
              || !cfbf_range_available(
                     size - 4, palette_offset,
                     (uint64_t)palette_entries * 4))) {
        return false;
      }
      saw_eof = true;
    }
    else if (offset + size == emf_bytes) {
      return false;
    }
    records++;
    offset += size;
  }
  return saw_eof && offset == emf_bytes && records == declared_records;
}

// Validate the packed bitmap stored by Microsoft Photo Editor and measure its
// image continuity. The private header records bit depth, width, and height;
// indexed images use the embedded RGB palette. Continuity ranks otherwise
// indistinguishable fragmented mappings but is not an authentication verdict.
//
static inline bool cfbf_validate_msphotoed_contents(
    const uint8_t *data, uint64_t length, uint64_t *coherence_cost,
    uint64_t *coherence_extent) {

  if (!data || !coherence_cost || !coherence_extent
      || length < CFBF_MSPHOTOED_PIXEL_OFFSET) {
    return false;
  }
  *coherence_cost = 0;
  *coherence_extent = 0;

  const uint16_t depth_code = cfbf_read_le16(data);
  const uint64_t width = cfbf_read_le16(data + 2);
  const uint64_t height = cfbf_read_le16(data + 4);
  const uint64_t bytes_per_pixel = depth_code == 3 ? 3 : 1;

  if ((depth_code != 1 && depth_code != 2 && depth_code != 3)
      || width == 0 || height == 0 || width > UINT64_MAX / height) {
    return false;
  }
  const uint64_t pixels = width * height;
  const __uint128_t comparisons =
      ((__uint128_t)height * (width - 1)
       + (__uint128_t)(height - 1) * width) * 3;

  if (pixels > (UINT64_MAX - CFBF_MSPHOTOED_PIXEL_OFFSET)
                   / bytes_per_pixel
      || CFBF_MSPHOTOED_PIXEL_OFFSET + pixels * bytes_per_pixel
             != length) {
    return false;
  }
  *coherence_extent = comparisons > UINT64_MAX
                          ? UINT64_MAX : (uint64_t)comparisons;

  uint64_t cost = 0;
  const uint8_t *pixel_data = data + CFBF_MSPHOTOED_PIXEL_OFFSET;
  const uint8_t *palette = data + CFBF_MSPHOTOED_PALETTE_OFFSET;

  if (bytes_per_pixel == 3) {
    const uint64_t row_bytes = width * 3;

    for (uint64_t row = 0; row < height; row++) {
      const uint8_t *current_row = pixel_data + row * row_bytes;
      uint64_t offset = 3;

      for (; offset + 32 <= row_bytes; offset += 32) {
        const simde__m256i current = simde_mm256_loadu_si256(
            (const simde__m256i *)(const void *)(current_row + offset));
        const simde__m256i prior = simde_mm256_loadu_si256(
            (const simde__m256i *)(const void *)(current_row + offset - 3));
        const simde__m256i sums = simde_mm256_sad_epu8(current, prior);
        uint64_t lanes[4];

        simde_mm256_storeu_si256((simde__m256i *)(void *)lanes, sums);
        cost += lanes[0] + lanes[1] + lanes[2] + lanes[3];
      }
      for (; offset < row_bytes; offset++) {
        const uint8_t value = current_row[offset];
        const uint8_t prior = current_row[offset - 3];

        cost += value > prior ? value - prior : prior - value;
      }
      if (row != 0) {
        const uint8_t *prior_row = current_row - row_bytes;
        offset = 0;

        for (; row_bytes - offset >= 32; offset += 32) {
          const simde__m256i current = simde_mm256_loadu_si256(
              (const simde__m256i *)(const void *)(current_row + offset));
          const simde__m256i prior = simde_mm256_loadu_si256(
              (const simde__m256i *)(const void *)(prior_row + offset));
          const simde__m256i sums = simde_mm256_sad_epu8(current, prior);
          uint64_t lanes[4];

          simde_mm256_storeu_si256((simde__m256i *)(void *)lanes, sums);
          cost += lanes[0] + lanes[1] + lanes[2] + lanes[3];
        }
        for (; offset < row_bytes; offset++) {
          const uint8_t value = current_row[offset];
          const uint8_t prior = prior_row[offset];

          cost += value > prior ? value - prior : prior - value;
        }
      }
    }
    *coherence_cost = cost;
    return true;
  }

  for (uint64_t row = 0; row < height; row++) {
    for (uint64_t column = 0; column < width; column++) {
      const uint64_t pixel = row * width + column;

      for (uint64_t channel = 0; channel < 3; channel++) {
        const uint64_t color_offset =
            (uint64_t)pixel_data[pixel] * 3 + channel;
        const uint8_t value = palette[color_offset];

        if (column != 0) {
          const uint64_t prior_pixel = pixel - 1;
          const uint64_t prior_offset =
              (uint64_t)pixel_data[prior_pixel] * 3 + channel;
          const uint8_t prior = palette[prior_offset];

          cost += value > prior ? value - prior : prior - value;
        }
        if (row != 0) {
          const uint64_t prior_pixel = pixel - width;
          const uint64_t prior_offset =
              (uint64_t)pixel_data[prior_pixel] * 3 + channel;
          const uint8_t prior = palette[prior_offset];

          cost += value > prior ? value - prior : prior - value;
        }
      }
    }
  }
  *coherence_cost = cost;
  return true;
}

// Validate one MSG object's property table and its external property values.
// Old Outlook writers disagree about whether a string terminator contributes
// to the recorded size, so both documented encodings are accepted.
//
static inline bool cfbf_validate_msg_property_object(
    const CfbfLayout *layout, const CfbfDirectoryEntry *parent,
    uint64_t header_size, uint64_t *property_count) {

  if (!layout || !parent || !property_count
      || (header_size != 8 && header_size != 24 && header_size != 32)) {
    return false;
  }
  const CfbfDirectoryEntry *properties = cfbf_find_child_directory(
      layout, parent, "__properties_version1.0");
  uint8_t *property_data = NULL;
  uint64_t property_length = 0;

  if (!properties || properties->object_type != 2
      || !cfbf_materialize_stream(layout, properties, &property_data,
                                  &property_length)
      || property_length <= header_size
      || (property_length - header_size) % 16 != 0) {
    free(property_data);
    return false;
  }

  for (uint64_t offset = header_size; offset < property_length; offset += 16) {
    const uint32_t property_tag = cfbf_read_le32(property_data + offset);
    const uint16_t property_type = (uint16_t)property_tag;
    const uint16_t base_type = property_type & UINT16_C(0x0fff);
    const bool multiple = (property_type & UINT16_C(0x1000)) != 0;
    const uint32_t declared_size = cfbf_read_le32(
        property_data + offset + 8);
    bool external = multiple;
    uint64_t element_size = 0;

    switch (base_type) {
    case UINT16_C(0x0001):
      element_size = 0;
      break;
    case UINT16_C(0x0002):
      element_size = 2;
      break;
    case UINT16_C(0x0003):
    case UINT16_C(0x0004):
    case UINT16_C(0x000a):
      element_size = 4;
      break;
    case UINT16_C(0x0005):
    case UINT16_C(0x0006):
    case UINT16_C(0x0007):
    case UINT16_C(0x0014):
    case UINT16_C(0x0040):
      element_size = 8;
      break;
    case UINT16_C(0x000b):
      element_size = 2;
      break;
    case UINT16_C(0x000d):
    case UINT16_C(0x001e):
    case UINT16_C(0x001f):
    case UINT16_C(0x0048):
    case UINT16_C(0x00fb):
    case UINT16_C(0x00fd):
    case UINT16_C(0x00fe):
    case UINT16_C(0x0102):
      external = true;
      break;
    default:
      free(property_data);
      return false;
    }

    if (!external) {
      (*property_count)++;
      continue;
    }

    const CfbfDirectoryEntry *value = cfbf_find_msg_property_value(
        layout, parent, property_tag);

    if (!value) {
      free(property_data);
      return false;
    }
    const uint64_t actual_size = value->stream_size;

    if (multiple) {
      if (value->object_type != 2 || actual_size != declared_size
          || (element_size != 0 && actual_size % element_size != 0)
          || (element_size == 0 && actual_size % 4 != 0)) {
        free(property_data);
        return false;
      }
    }
    else if (base_type == UINT16_C(0x000d)) {
      if ((value->object_type == 1 && declared_size != UINT32_MAX)
          || (value->object_type == 2
              && declared_size != UINT32_MAX
              && actual_size != declared_size)) {
        free(property_data);
        return false;
      }
    }
    else if (value->object_type != 2) {
      free(property_data);
      return false;
    }
    else if (base_type == UINT16_C(0x001e)) {
      if (declared_size != actual_size
          && declared_size != actual_size + 1) {
        free(property_data);
        return false;
      }
    }
    else if (base_type == UINT16_C(0x001f)) {
      uint8_t *value_data = NULL;
      uint64_t value_length = 0;
      uint64_t text_length = actual_size;
      bool valid_size = declared_size == actual_size
                        || declared_size == actual_size + 2;

      // Some Outlook writers pad a Unicode property stream to the next mini
      // sector while retaining the unpadded property length. Require exact
      // mini-sector alignment and zero padding before accepting that form.
      if (!valid_size && declared_size < actual_size
          && actual_size == CEILDIV(declared_size,
                                    layout->mini_sector_size)
                            * layout->mini_sector_size
          && cfbf_materialize_stream(layout, value, &value_data,
                                     &value_length)) {
        valid_size = value_length == actual_size;
        for (uint64_t padding = declared_size;
             valid_size && padding < value_length; padding++) {
          if (value_data[padding] != 0) {
            valid_size = false;
          }
        }
        if (valid_size) {
          text_length = declared_size;
        }
      }
      if ((text_length & 1) != 0 || !valid_size) {
        free(value_data);
        free(property_data);
        return false;
      }
      if (actual_size >= layout->mini_stream_cutoff) {
        if ((!value_data
             && !cfbf_materialize_stream(layout, value, &value_data,
                                         &value_length))
            || value_length < text_length
            || !cfbf_validate_msg_unicode_stream(value_data, text_length)) {
          free(value_data);
          free(property_data);
          return false;
        }
      }
      free(value_data);
    }
    else if (base_type == UINT16_C(0x0048)) {
      if (actual_size != 16 || declared_size != actual_size) {
        free(property_data);
        return false;
      }
    }
    else if (declared_size != actual_size) {
      free(property_data);
      return false;
    }

    if (property_tag == UINT32_C(0x10090102)) {
      uint8_t *value_data = NULL;
      uint64_t value_length = 0;

      if (!cfbf_materialize_stream(layout, value, &value_data,
                                   &value_length)
          || (value_length != 0
              && !cfbf_validate_rtf_compressed(value_data,
                                               value_length))) {
        free(value_data);
        free(property_data);
        return false;
      }
      free(value_data);
    }

    (*property_count)++;
  }
  free(property_data);
  return true;
}

// Validate the object hierarchy and MAPI property relationships in an MSG
// container. Independently checkable image attachments provide additional
// ranking evidence; other payloads remain opaque.
//
static inline bool cfbf_validate_msg_streams(
    const CfbfLayout *layout, CfbfSemanticEvidence *evidence) {

  if (!layout || !layout->directories
      || layout->root_index >= layout->directory_count) {
    return false;
  }
  const CfbfDirectoryEntry *root = &layout->directories[layout->root_index];
  const CfbfDirectoryEntry *properties = cfbf_find_child_directory(
      layout, root, "__properties_version1.0");
  uint8_t *property_data = NULL;
  uint64_t property_length = 0;

  if (!properties || properties->object_type != 2
      || !cfbf_materialize_stream(layout, properties, &property_data,
                                  &property_length)
      || property_length < 32 || (property_length - 32) % 16 != 0) {
    free(property_data);
    return false;
  }
  const uint32_t expected_recipients = cfbf_read_le32(property_data + 16);
  const uint32_t expected_attachments = cfbf_read_le32(property_data + 20);
  free(property_data);

  if (expected_recipients > 2048 || expected_attachments > 2048) {
    return false;
  }
  uint64_t property_count = 0;
  uint32_t recipients = 0;
  uint32_t attachments = 0;

  if (!cfbf_validate_msg_property_object(layout, root, 32,
                                         &property_count)) {
    return false;
  }

  for (uint64_t index = 0; index < layout->directory_count; index++) {
    const CfbfDirectoryEntry *entry = &layout->directories[index];

    if (entry->object_type != 1 || entry->parent != layout->root_index) {
      continue;
    }
    uint32_t *object_count = NULL;
    uint64_t expected_length = 0;
    bool attachment = false;

    if (cfbf_name_starts_with(entry, "__recip_version1.0_#")) {
      object_count = &recipients;
      expected_length = 28;
    }
    else if (cfbf_name_starts_with(entry, "__attach_version1.0_#")) {
      object_count = &attachments;
      expected_length = 29;
      attachment = true;
    }
    else {
      continue;
    }
    if (strlen(entry->name) != expected_length) {
      return false;
    }
    for (uint64_t digit = expected_length - 8;
         digit < expected_length; digit++) {
      const char value = entry->name[digit];

      if (!((value >= '0' && value <= '9')
            || (value >= 'A' && value <= 'F'))) {
        return false;
      }
    }
    if (!cfbf_validate_msg_property_object(layout, entry, 8,
                                           &property_count)) {
      return false;
    }
    if (attachment && evidence) {
      const CfbfDirectoryEntry *payload = cfbf_find_msg_property_value(
          layout, entry, UINT32_C(0x37010102));
      uint8_t *payload_data = NULL;
      uint64_t payload_length = 0;

      if (payload && payload->object_type == 2
          && cfbf_materialize_stream(layout, payload, &payload_data,
                                     &payload_length)) {
        evidence->examined_payloads++;
        if (cfbf_validate_embedded_image(payload_data, payload_length)) {
          evidence->validated_payloads++;
        }
      }
      free(payload_data);
    }
    (*object_count)++;
  }
  const bool counts_match = recipients == expected_recipients
                            && attachments == expected_attachments;
  const bool stale_attachment_count = recipients == expected_recipients
                                      && attachments == 0
                                      && expected_attachments != 0;

  // Some Outlook writers retain the former attachment count after removing
  // every attachment storage. The recipient count and all surviving property
  // objects must still agree with the directory hierarchy.
  return property_count != 0 && (counts_match || stale_attachment_count);
}

// Validate the Publisher document stream and its version-specific trailer.
// The trailer indexes every content chunk, including the document chunk that
// is required for a usable publication.
//
static inline bool cfbf_validate_publisher_contents_stream(
    const uint8_t *data, uint64_t length) {

  if (!data || length < 0x1e || data[0] != 0xe8 || data[1] != 0xac
      || data[3] != 0) {
    return false;
  }
  const uint8_t version = data[2];
  const uint64_t trailer_field = version == 0x22 ? 0x16 : 0x1a;

  if ((version != 0x22 && version != 0x2c)
      || !cfbf_range_available(length, trailer_field, 4)) {
    return false;
  }
  const uint32_t trailer_offset = cfbf_read_le32(data + trailer_field);

  if (!cfbf_range_available(length, trailer_offset,
                            version == 0x22 ? 2 : 4)) {
    return false;
  }
  if (version == 0x2c) {
    const uint32_t trailer_length = cfbf_read_le32(data + trailer_offset);

    return trailer_length >= 16
           && trailer_length == length - trailer_offset;
  }

  const uint16_t chunks = cfbf_read_le16(data + trailer_offset);
  const uint64_t table_offset = (uint64_t)trailer_offset + 2;

  if (chunks == 0
      || !cfbf_range_available(length, table_offset,
                               (uint64_t)chunks * 10)) {
    return false;
  }
  bool document = false;

  for (uint16_t chunk = 0; chunk < chunks; chunk++) {
    const uint64_t descriptor = table_offset + (uint64_t)chunk * 10;
    const uint32_t chunk_offset = cfbf_read_le32(data + descriptor + 6);

    if (!cfbf_range_available(length, chunk_offset, 2)) {
      return false;
    }
    if (cfbf_read_le16(data + chunk_offset) == UINT16_C(0x0015)) {
      document = true;
    }
  }
  return document;
}

// Validate the Publisher Quill directory. Its fixed descriptor table maps
// named document components into bounded ranges of the CONTENTS stream and
// supplies order-sensitive evidence beyond the generic CFBF allocation data.
//
static inline bool cfbf_validate_publisher_quill_stream(
    const uint8_t *data, uint64_t length) {

  if (!data || length < 512 || memcmp(data, "CHNKINK ", 8) != 0) {
    return false;
  }
  uint64_t active = 0;

  for (uint64_t index = 0; index < 20; index++) {
    const uint64_t descriptor = 0x20 + index * 24;

    if (data[descriptor] == 0 && data[descriptor + 1] == 0) {
      continue;
    }
    if (data[descriptor] != 0x18 || data[descriptor + 1] != 0) {
      return false;
    }
    for (uint64_t byte = 2; byte < 6; byte++) {
      if (data[descriptor + byte] < 0x20
          || data[descriptor + byte] > 0x7e) {
        return false;
      }
    }
    for (uint64_t byte = 12; byte < 16; byte++) {
      if (data[descriptor + byte] < 0x20
          || data[descriptor + byte] > 0x7e) {
        return false;
      }
    }

    const uint32_t offset = cfbf_read_le32(data + descriptor + 16);
    const uint32_t size = cfbf_read_le32(data + descriptor + 20);

    if (offset < 512 || !cfbf_range_available(length, offset, size)) {
      return false;
    }
    active++;
  }
  return active != 0;
}

// Validate every Publisher stream for which the format supplies independent
// framing. Publications normally carry both the document and Quill streams;
// validating both prevents an intact auxiliary stream from hiding damaged
// document content.
//
static inline bool cfbf_validate_publisher_streams(
    const CfbfLayout *layout) {

  if (!layout) {
    return false;
  }
  const CfbfDirectoryEntry *contents = cfbf_find_directory(layout,
                                                            "Contents");
  const CfbfDirectoryEntry *quill = cfbf_find_directory(layout,
                                                         "CONTENTS");
  bool checked = false;

  if (contents) {
    uint8_t *data = NULL;
    uint64_t length = 0;

    checked = true;
    if (!cfbf_materialize_stream(layout, contents, &data, &length)
        || !cfbf_validate_publisher_contents_stream(data, length)) {
      free(data);
      return false;
    }
    free(data);
  }
  if (quill) {
    uint8_t *data = NULL;
    uint64_t length = 0;

    checked = true;
    if (!cfbf_materialize_stream(layout, quill, &data, &length)
        || !cfbf_validate_publisher_quill_stream(data, length)) {
      free(data);
      return false;
    }
    free(data);
  }
  return checked;
}

// Expand a compressed Visio stream using its 4096-byte sliding window.
// Pointer and chunk validation operate on the expanded representation.
//
static inline bool cfbf_visio_decompress(const uint8_t *input,
                                         uint64_t input_length,
                                         uint8_t **output,
                                         uint64_t *output_length) {

  if (!input || !output || !output_length || input_length == 0
      || input_length > (SIZE_MAX - 16) / 9) {
    return false;
  }
  *output = NULL;
  *output_length = 0;

  const size_t capacity = (size_t)input_length * 9 + 16;
  uint8_t *expanded = (uint8_t *)malloc(capacity);
  uint8_t window[4096];

  check_memory_allocation(expanded, __LINE__, __FILE__,
                          "expanded Visio stream");
  memset(window, 0, sizeof(window));

  uint64_t input_offset = 0;
  uint64_t expanded_offset = 0;
  uint64_t window_position = 0;

  while (input_offset < input_length) {
    const uint8_t flags = input[input_offset++];

    if (input_offset >= input_length) {
      break;
    }
    uint8_t mask = 1;

    for (uint32_t bit = 0;
         bit < 8 && input_offset < input_length; bit++, mask <<= 1) {
      if ((flags & mask) != 0) {
        const uint8_t value = input[input_offset++];

        if (expanded_offset >= capacity) {
          free(expanded);
          return false;
        }
        window[window_position & UINT64_C(4095)] = value;
        expanded[expanded_offset++] = value;
        window_position++;
        continue;
      }
      if (input_length - input_offset < 2) {
        free(expanded);
        return false;
      }
      const uint8_t address_low = input[input_offset++];
      const uint8_t address_high = input[input_offset++];
      const uint32_t run_length = (address_high & 0x0f) + 3;
      uint32_t source = ((uint32_t)(address_high & 0xf0) << 4)
                        | address_low;

      if (source > 4078) {
        source -= 4078;
      }
      else {
        source += 18;
      }
      if (run_length > capacity - expanded_offset) {
        free(expanded);
        return false;
      }
      for (uint32_t index = 0; index < run_length; index++) {
        const uint8_t value = window[(source + index) & 4095];

        window[(window_position + index) & UINT64_C(4095)] = value;
        expanded[expanded_offset++] = value;
      }
      window_position += run_length;
    }
  }

  *output = expanded;
  *output_length = expanded_offset;
  return expanded_offset != 0;
}

// Calculate the trailer associated with a Visio 6 or Visio 11 chunk header.
// The trailer rules are part of the stream framing and make displaced bytes
// visible without interpreting every drawing record.
//
static inline uint64_t cfbf_visio_chunk_trailer(uint32_t chunk_type,
                                                uint32_t list,
                                                uint16_t level,
                                                uint8_t unknown,
                                                uint8_t version) {

  uint64_t trailer = 0;

  if (version == 6) {
    if (list != 0 || chunk_type == 0x76 || chunk_type == 0x73
        || chunk_type == 0x72 || chunk_type == 0x71
        || chunk_type == 0x70 || chunk_type == 0x6f
        || chunk_type == 0x6e || chunk_type == 0x6d
        || chunk_type == 0x6c || chunk_type == 0x6b
        || chunk_type == 0x6a || chunk_type == 0x69
        || chunk_type == 0x68 || chunk_type == 0x67
        || chunk_type == 0x66 || chunk_type == 0x65
        || chunk_type == 0x64 || chunk_type == 0x2c
        || chunk_type == 0x0d) {
      trailer = 8;
    }
    if (chunk_type == 0x1f || chunk_type == 0xc9) {
      trailer = 0;
    }
    return trailer;
  }

  if (list != 0 || chunk_type == 0x71 || chunk_type == 0x70
      || chunk_type == 0x6b || chunk_type == 0x6a
      || chunk_type == 0x69 || chunk_type == 0x66
      || chunk_type == 0x65 || chunk_type == 0x2c) {
    trailer += 8;
  }
  if (list != 0 || (level == 2 && unknown == 0x55)
      || (level == 2 && unknown == 0x54 && chunk_type == 0xaa)
      || (level == 3 && unknown != 0x50 && unknown != 0x54)) {
    trailer += 4;
  }

  const uint32_t additional_trailer_types[] = {
    0x64, 0x65, 0x66, 0x69, 0x6a, 0x6b, 0x6f,
    0x71, 0x92, 0xa9, 0xb4, 0xb6, 0xb9, 0xc7
  };

  for (uint64_t index = 0;
       index < sizeof(additional_trailer_types)
                   / sizeof(additional_trailer_types[0]); index++) {
    if (chunk_type == additional_trailer_types[index]
        && trailer != 12 && trailer != 4) {
      trailer += 4;
      break;
    }
  }
  if (chunk_type == 0x1f || chunk_type == 0xc9
      || chunk_type == 0x2d || chunk_type == 0xd1) {
    trailer = 0;
  }
  return trailer;
}

// Walk a Visio chunk stream and require every record and trailer to fit the
// exact expanded stream boundary.
//
static inline bool cfbf_validate_visio_chunks(const uint8_t *data,
                                              uint64_t length,
                                              uint8_t version) {

  if (!data || length == 0
      || (version != 5 && version != 6 && version != 11)) {
    return false;
  }

  uint64_t offset = 0;
  uint64_t chunks = 0;

  while (offset < length) {
    while (offset < length && data[offset] == 0) {
      offset++;
    }
    if (offset == length) {
      return chunks != 0;
    }
    uint32_t chunk_type = 0;
    uint32_t data_length = 0;
    uint64_t record_length = 0;

    if (version == 5) {
      if (!cfbf_range_available(length, offset, 12)) {
        return false;
      }
      chunk_type = cfbf_read_le16(data + offset);
      data_length = cfbf_read_le32(data + offset + 8);
      record_length = UINT64_C(12) + data_length;
    }
    else {
      if (!cfbf_range_available(length, offset, 19)) {
        return false;
      }
      chunk_type = cfbf_read_le32(data + offset);
      const uint32_t list = cfbf_read_le32(data + offset + 8);
      data_length = cfbf_read_le32(data + offset + 12);
      const uint16_t level = cfbf_read_le16(data + offset + 16);
      const uint8_t unknown = data[offset + 18];
      const uint64_t trailer = cfbf_visio_chunk_trailer(
          chunk_type, list, level, unknown, version);

      record_length = UINT64_C(19) + data_length + trailer;
    }

    if (chunk_type == 0
        || !cfbf_range_available(length, offset, record_length)) {
      return false;
    }
    offset += record_length;
    chunks++;
  }
  return chunks != 0;
}

// Validate one Visio stream pointer. Container pointers are followed through
// the complete document, compressed streams are expanded, and chunk streams
// are checked using their version-specific framing rules.
//
static inline bool cfbf_validate_visio_pointer(
    const uint8_t *document, uint64_t document_length,
    uint32_t pointer_type, uint64_t pointer_offset,
    uint64_t pointer_length, uint16_t pointer_format,
    uint8_t version, uint64_t *visited_offsets,
    uint64_t *visited_lengths, uint32_t depth) {

  if (!document || !visited_offsets || !visited_lengths
      || depth >= CFBF_VISIO_MAX_DEPTH
      || !cfbf_range_available(document_length, pointer_offset,
                               pointer_length)) {
    return false;
  }
  if (pointer_length == 0) {
    return true;
  }
  for (uint32_t index = 0; index < depth; index++) {
    if (visited_offsets[index] == pointer_offset
        && visited_lengths[index] == pointer_length) {
      return false;
    }
  }
  visited_offsets[depth] = pointer_offset;
  visited_lengths[depth] = pointer_length;

  const bool compressed = (pointer_format & 2) != 0;
  const uint8_t *stream = document + pointer_offset;
  uint64_t stream_length = pointer_length;
  uint8_t *expanded = NULL;

  if (compressed
      && !cfbf_visio_decompress(stream, stream_length, &expanded,
                                &stream_length)) {
    return false;
  }
  if (compressed) {
    stream = expanded;
  }

  const uint32_t format_family = pointer_format >> 4;
  // A Visio trailer owns the page collection, and a page collection owns at
  // least one page. Empty lists are parseable but cannot describe a drawing.
  uint32_t required_child_type = 0;
  if (format_family == 5 && pointer_type == UINT32_C(0x14)) {
    required_child_type = UINT32_C(0x27);
  }
  else if (format_family == 5 && pointer_type == UINT32_C(0x27)) {
    required_child_type = UINT32_C(0x15);
  }
  bool required_child_seen = required_child_type == 0;
  bool valid = false;

  if (pointer_type == 0x1f) {
    valid = stream_length >= 4
            && cfbf_read_le32(stream) == stream_length - 4;
  }
  else if (version == 5 && format_family == 5
           && pointer_type != 0x16) {
    const uint64_t shift = compressed ? 4 : 0;
    uint64_t count_offset = shift + 0x0a;

    switch (pointer_type) {
    case 0x14:
      count_offset = shift + 0x82;
      break;
    case 0x15:
      count_offset = shift + 0x42;
      break;
    case 0x18:
      count_offset = shift + 0x2e;
      break;
    case 0x1a:
      count_offset = shift + 0x12;
      break;
    case 0x1d:
    case 0x4e:
      count_offset = shift + 0x1e;
      break;
    case 0x1e:
      count_offset = shift + 0x36;
      break;
    default:
      if (pointer_type > 0x45) {
        count_offset = shift + 0x1e;
      }
      break;
    }

    if (cfbf_range_available(stream_length, count_offset, 2)) {
      const int16_t pointer_count = (int16_t)cfbf_read_le16(
          stream + count_offset);
      const uint64_t pointers_offset = count_offset + 2;

      if (pointer_count >= 0
          && (uint64_t)pointer_count
                 <= (stream_length - pointers_offset) / 16) {
        valid = true;
        for (int16_t index = 0; index < pointer_count; index++) {
          const uint64_t entry = pointers_offset + (uint64_t)index * 16;
          const uint32_t child_type = cfbf_read_le16(stream + entry)
                                      & UINT32_C(0xff);

          if (child_type == 0) {
            continue;
          }
          if (child_type == required_child_type) {
            required_child_seen = true;
          }
          const uint16_t child_format = cfbf_read_le16(stream + entry + 2)
                                        & UINT16_C(0xff);
          const uint32_t child_offset = cfbf_read_le32(stream + entry + 8);
          const uint32_t child_length = cfbf_read_le32(stream + entry + 12);

          if (!cfbf_validate_visio_pointer(
                  document, document_length, child_type, child_offset,
                  child_length, child_format, version, visited_offsets,
                  visited_lengths, depth + 1)) {
            valid = false;
            break;
          }
        }
      }
    }
  }
  else if (format_family == 5 && pointer_type != 0x16) {
    const uint64_t shift = compressed ? 4 : 0;

    if (cfbf_range_available(stream_length, shift, 4)) {
      const uint32_t pointer_info = cfbf_read_le32(stream + shift);
      const uint64_t pointer_info_offset = (uint64_t)pointer_info + shift;

      if (pointer_info_offset >= 4) {
        const uint64_t list_offset = pointer_info_offset - 4;

        if (cfbf_range_available(stream_length, list_offset, 12)) {
          const uint32_t list_size = cfbf_read_le32(stream + list_offset);
          const int32_t pointer_count = (int32_t)cfbf_read_le32(
              stream + list_offset + 4);
          const uint64_t pointers_offset = list_offset + 12;

          if (pointer_count >= 0
              && (uint64_t)pointer_count
                     <= (stream_length - pointers_offset) / 18
              && cfbf_range_available(
                     stream_length,
                     pointers_offset + (uint64_t)pointer_count * 18,
                     (uint64_t)list_size * 4)) {
            valid = true;
            for (int32_t index = 0; index < pointer_count; index++) {
              const uint64_t entry = pointers_offset
                                     + (uint64_t)index * 18;
              const uint32_t child_type = cfbf_read_le32(stream + entry);

              if (child_type == 0) {
                continue;
              }
              if (child_type == required_child_type) {
                required_child_seen = true;
              }
              const uint32_t child_offset = cfbf_read_le32(
                  stream + entry + 8);
              const uint32_t child_length = cfbf_read_le32(
                  stream + entry + 12);
              const uint16_t child_format = cfbf_read_le16(
                  stream + entry + 16);

              if (!cfbf_validate_visio_pointer(
                      document, document_length, child_type, child_offset,
                      child_length, child_format, version, visited_offsets,
                      visited_lengths, depth + 1)) {
                valid = false;
                break;
              }
            }
          }
        }
      }
    }
  }
  else if (format_family == 8 || format_family == 12
           || format_family == 13) {
    valid = cfbf_validate_visio_chunks(stream, stream_length, version);
  }
  else {
    valid = format_family == 0 || format_family == 4
            || format_family == 5 || format_family == 6;
  }
  if (!required_child_seen) {
    valid = false;
  }

  free(expanded);
  return valid;
}

// Validate the internal VisioDocument pointer graph for the two binary Visio
// versions that use the modern pointer representation.
//
static inline bool cfbf_validate_visio_streams(const CfbfLayout *layout) {

  if (!layout) {
    return false;
  }
  const CfbfDirectoryEntry *entry = cfbf_find_directory(layout,
                                                         "VisioDocument");
  uint8_t *document = NULL;
  uint64_t document_length = 0;

  if (!entry
      || !cfbf_materialize_stream(layout, entry, &document,
                                  &document_length)
      || document_length < 0x36
      || memcmp(document, "Visio (TM) Drawing\r\n\0", 21) != 0) {
    free(document);
    return false;
  }

  const uint8_t version = document[0x1a];

  if (version != 5 && version != 6 && version != 11) {
    free(document);
    return false;
  }
  const uint32_t pointer_type = version == 5
                                    ? cfbf_read_le16(document + 0x24)
                                          & UINT32_C(0xff)
                                    : cfbf_read_le32(document + 0x24);
  const uint32_t pointer_offset = cfbf_read_le32(document + 0x2c);
  const uint32_t pointer_length = cfbf_read_le32(document + 0x30);
  const uint16_t pointer_format = version == 5
                                      ? cfbf_read_le16(document + 0x26)
                                            & UINT16_C(0xff)
                                      : cfbf_read_le16(document + 0x34);
  uint64_t visited_offsets[CFBF_VISIO_MAX_DEPTH];
  uint64_t visited_lengths[CFBF_VISIO_MAX_DEPTH];

  memset(visited_offsets, 0, sizeof(visited_offsets));
  memset(visited_lengths, 0, sizeof(visited_lengths));
  const bool valid = pointer_type == 0x14 && pointer_length != 0
                     && pointer_offset >= (version == 5 ? 0x34 : 0x36)
                     && cfbf_validate_visio_pointer(
                            document, document_length, pointer_type,
                            pointer_offset, pointer_length, pointer_format,
                            version, visited_offsets, visited_lengths, 0);

  free(document);
  return valid;
}

// Validate the fixed tables that follow the declared Project 98 properties.
// Each table describes its complete fixed-record extent. The 24-byte records
// carry a fixed field marker and reserved bytes, which make corruption in the
// otherwise opaque tail of a Props stream detectable.
//
static inline bool cfbf_validate_mpp8_table_sections(
    const uint8_t *data, uint64_t length, uint64_t offset) {

  if (!data || offset >= length) {
    return true;
  }
  uint64_t section_offset = offset;
  bool section_header = false;

  if (cfbf_range_available(length, section_offset, 28)) {
    const uint32_t section_size = cfbf_read_le32(data + section_offset);
    const uint32_t repeated_size = cfbf_read_le32(data + section_offset + 4);
    const uint32_t payload_size = cfbf_read_le32(data + section_offset + 16);
    const uint32_t version = cfbf_read_le32(data + section_offset + 20);
    const uint32_t record_size = cfbf_read_le32(data + section_offset + 24);

    section_header = section_size >= 24 && section_size == repeated_size
                     && cfbf_range_available(length, section_offset + 4,
                                             section_size)
                     && payload_size <= section_size - 24
                     && version == 1 && record_size == 24
                     && payload_size % record_size == 0;
  }
  if (!section_header) {
    if (!cfbf_range_available(length, offset, 4)) {
      return true;
    }
    const uint32_t names_length = cfbf_read_le32(data + offset);

    if (names_length == 0 || (names_length & 1) != 0
        || !cfbf_range_available(length, offset + 4, names_length)
        || data[offset + 4 + names_length - 2] != 0
        || data[offset + 4 + names_length - 1] != 0) {
      return true;
    }
    section_offset = offset + 4 + names_length;
  }

  uint64_t sections = 0;

  while (cfbf_range_available(length, section_offset, 28)) {
    const uint32_t section_size = cfbf_read_le32(data + section_offset);
    const uint32_t repeated_size = cfbf_read_le32(data + section_offset + 4);
    const uint32_t payload_size = cfbf_read_le32(data + section_offset + 16);
    const uint32_t version = cfbf_read_le32(data + section_offset + 20);
    const uint32_t record_size = cfbf_read_le32(data + section_offset + 24);

    if (section_size < 24 || section_size != repeated_size
        || !cfbf_range_available(length, section_offset + 4, section_size)
        || payload_size > section_size - 24 || version != 1
        || record_size != 24 || payload_size % record_size != 0) {
      break;
    }
    const uint64_t records = payload_size / record_size;
    const uint64_t records_offset = section_offset + 28;

    for (uint64_t record = 0; record < records; record++) {
      const uint64_t record_offset = records_offset + record * record_size;

      if (data[record_offset + 10] != 0x40
          || cfbf_read_le16(data + record_offset + 14) != 0) {
        return false;
      }
    }
    sections++;
    section_offset += (uint64_t)section_size + 4;
  }

  return sections >= 2 && length - section_offset <= 512;
}

// Validate one Microsoft Project property stream. Project 98 selects the value
// length from three descriptor fields, while later versions store it directly.
// Both layouts require every declared record to fit the materialized stream.
//
static inline bool cfbf_validate_mpp_props_stream(const uint8_t *data,
                                                  uint64_t length) {

  if (!data || length < 16) {
    return false;
  }
  const uint16_t record_count = cfbf_read_le16(data + 12);

  if (record_count == 0
      || (uint64_t)record_count > (length - 16) / 12) {
    return false;
  }

  // Project 2000 and later use a direct 12-byte descriptor followed by the
  // length-prefixed value.
  uint64_t offset = 16;
  bool direct_valid = true;

  for (uint16_t record = 0; record < record_count; record++) {
    if (!cfbf_range_available(length, offset, 12)) {
      direct_valid = false;
      break;
    }
    const uint32_t value_length = cfbf_read_le32(data + offset);

    offset += 12;
    if (value_length == 0
        || !cfbf_range_available(length, offset, value_length)) {
      direct_valid = false;
      break;
    }
    offset += value_length;
    if ((value_length & 1) != 0) {
      if (!cfbf_range_available(length, offset, 1)) {
        direct_valid = false;
        break;
      }
      offset++;
    }
  }
  if (direct_valid) {
    return cfbf_validate_mpp8_table_sections(data, length, offset);
  }

  // Project 98 uses a conditional length field in the same descriptor.
  offset = 16;
  for (uint16_t record = 0; record < record_count; record++) {
    if (!cfbf_range_available(length, offset, 12)) {
      return false;
    }
    const uint32_t first_attribute = cfbf_read_le32(data + offset);
    const uint8_t length_selector = data[offset + 6];
    const uint32_t fifth_attribute = cfbf_read_le32(data + offset + 8);
    uint64_t value_length = length_selector == 64
                                ? first_attribute : fifth_attribute;

    if (fifth_attribute == UINT32_C(65536)) {
      value_length = 4;
    }
    offset += 12;
    if (value_length == 0
        || !cfbf_range_available(length, offset, value_length)) {
      return false;
    }
    offset += value_length;
    if ((value_length & 1) != 0) {
      if (!cfbf_range_available(length, offset, 1)) {
        return false;
      }
      offset++;
    }
  }
  return cfbf_validate_mpp8_table_sections(data, length, offset);
}

// Validate the index that maps variable-length Microsoft Project records into
// the companion data stream. Version 9 uses compact eight-byte entries, while
// later versions use twelve-byte entries.
//
static inline bool cfbf_validate_mpp_var_meta_stream(const uint8_t *data,
                                                     uint64_t length,
                                                     uint8_t version,
                                                     const uint8_t *variable_data,
                                                     uint64_t data_length,
                                                     uint64_t *metadata_failure,
                                                     uint64_t *data_failure) {

  if (metadata_failure) {
    *metadata_failure = UINT64_MAX;
  }
  if (data_failure) {
    *data_failure = UINT64_MAX;
  }

  if (!data || length < 24
      || (version != 9 && version != 12 && version != 14)) {
    if (metadata_failure) {
      *metadata_failure = 0;
    }
    return false;
  }
  const uint32_t magic = cfbf_read_le32(data);
  const uint32_t record_count = cfbf_read_le32(data + 8);
  const uint32_t data_size = cfbf_read_le32(data + 20);
  const uint64_t record_size = version == 9 ? 8 : 12;

  if ((version == 9 && magic != UINT32_C(0xfadfadba))
      || (version != 9 && magic != 0
          && magic != UINT32_C(0xfadfadba))) {
    if (metadata_failure) {
      *metadata_failure = 0;
    }
    return false;
  }
  const uint64_t available_records = (length - 24) / record_size;

  // Version 12 metadata produced by Microsoft Project can overstate the
  // record count; the reference parser consumes the complete records that are
  // present. Version 9 requires every compact record to be present.
  if (version == 9 && record_count > available_records) {
    if (metadata_failure) {
      *metadata_failure = 8;
    }
    return false;
  }
  if ((data_size == 0 && data_length != 0)
      || (data_size != 0
          && (!variable_data || data_length != data_size))) {
    if (metadata_failure) {
      *metadata_failure = 20;
    }
    return false;
  }
  uint64_t records_to_validate = record_count;

  if (records_to_validate > available_records) {
    records_to_validate = available_records;
  }
  for (uint64_t record = 0; record < records_to_validate; record++) {
    const uint64_t offset = 24 + (uint64_t)record * record_size;
    const uint32_t data_offset = cfbf_read_le32(data + offset + 4);

    if (!cfbf_range_available(data_length, data_offset, 4)) {
      if (metadata_failure) {
        *metadata_failure = offset + 4;
      }
      return false;
    }
    const uint32_t value_length = cfbf_read_le32(
        variable_data + data_offset);

    if (!cfbf_range_available(data_length, (uint64_t)data_offset + 4,
                              value_length)) {
      if (data_failure) {
        *data_failure = data_offset;
      }
      return false;
    }
  }
  return true;
}

// Validate the fixed-record metadata header and require enough payload for
// every declared record. Record widths vary by table and Project version.
//
static inline bool cfbf_validate_mpp_fixed_meta_stream(const uint8_t *data,
                                                       uint64_t length) {

  if (!data || length < 16
      || cfbf_read_le32(data) != UINT32_C(0xfadfadba)) {
    return false;
  }
  const uint32_t record_count = cfbf_read_le32(data + 8);

  return record_count == 0
         || (uint64_t)record_count <= (length - 16) / 8;
}

// Compare the parallel fixed-layout view payloads stored in Project variable
// data. The result ranks otherwise valid fragmented mappings; it is not a
// validity requirement because Project versions do not all emit both values.
//
static inline void cfbf_collect_mpp_view_coherence(
    const uint8_t *metadata, uint64_t metadata_length, uint8_t version,
    const uint8_t *variable_data, uint64_t variable_data_length,
    CfbfSemanticEvidence *evidence) {

  if (!metadata || metadata_length < 24 || !variable_data || !evidence
      || (version != 9 && version != 12 && version != 14)) {
    return;
  }
  const uint64_t record_size = version == 9 ? 8 : 12;
  uint64_t record_count = cfbf_read_le32(metadata + 8);
  const uint64_t available_records = (metadata_length - 24) / record_size;

  if (record_count > available_records) {
    record_count = available_records;
  }
  for (uint64_t record = 0; record < record_count; record++) {
    const uint64_t record_offset = 24 + record * record_size;
    const uint32_t value_type = version == 9
                                    ? metadata[record_offset + 3]
                                    : cfbf_read_le16(
                                          metadata + record_offset + 8);
    const uint32_t data_offset = cfbf_read_le32(
        metadata + record_offset + 4);

    if (value_type != 6
        || !cfbf_range_available(variable_data_length, data_offset, 4)) {
      continue;
    }
    bool duplicate = false;

    for (uint64_t prior = 0; prior < record; prior++) {
      const uint64_t prior_offset = 24 + prior * record_size;
      const uint32_t prior_type = version == 9
                                      ? metadata[prior_offset + 3]
                                      : cfbf_read_le16(
                                            metadata + prior_offset + 8);

      if (prior_type == value_type
          && cfbf_read_le32(metadata + prior_offset + 4)
                 == data_offset) {
        duplicate = true;
        break;
      }
    }
    if (duplicate) {
      continue;
    }
    const uint32_t properties_length = cfbf_read_le32(
        variable_data + data_offset);
    const uint64_t properties_offset = (uint64_t)data_offset + 4;

    if (properties_length < 16
        || !cfbf_range_available(variable_data_length, properties_offset,
                                 properties_length)) {
      continue;
    }
    const uint8_t *properties = variable_data + properties_offset;
    const uint16_t property_count = cfbf_read_le16(properties + 12);
    const uint8_t *primary = NULL;
    const uint8_t *companion = NULL;
    uint32_t primary_length = 0;
    uint32_t companion_length = 0;
    uint64_t offset = 16;

    for (uint16_t property = 0; property < property_count; property++) {
      if (!cfbf_range_available(properties_length, offset, 12)) {
        break;
      }
      const uint32_t value_length = cfbf_read_le32(properties + offset);
      const uint32_t key = cfbf_read_le32(properties + offset + 4);
      const uint64_t value_offset = offset + 12;

      if (value_length == 0
          || !cfbf_range_available(properties_length, value_offset,
                                   value_length)) {
        break;
      }
      if (key == CFBF_MPP_VIEW_STYLE_PRIMARY_KEY) {
        primary = properties + value_offset;
        primary_length = value_length;
      }
      else if (key == CFBF_MPP_VIEW_STYLE_COMPANION_KEY) {
        companion = properties + value_offset;
        companion_length = value_length;
      }
      offset = value_offset + value_length;
      if ((value_length & 1) != 0) {
        if (!cfbf_range_available(properties_length, offset, 1)) {
          break;
        }
        offset++;
      }
    }
    if (!primary || !companion || primary_length == 0
        || primary_length != companion_length) {
      continue;
    }
    uint64_t difference = 0;

    for (uint32_t byte = 0; byte < primary_length; byte++) {
      if (primary[byte] != companion[byte]) {
        difference++;
      }
    }
    if (evidence->coherence_payloads < UINT32_MAX) {
      evidence->coherence_payloads++;
    }
    if (UINT64_MAX - evidence->coherence_cost < difference) {
      evidence->coherence_cost = UINT64_MAX;
    }
    else {
      evidence->coherence_cost += difference;
    }
    if (UINT64_MAX - evidence->coherence_extent < primary_length) {
      evidence->coherence_extent = UINT64_MAX;
    }
    else {
      evidence->coherence_extent += primary_length;
    }
  }
}

// Validate the Project root, project tables, and companion metadata/data
// streams used by Project 98, MPP9, MPP12, and MPP14 containers.
//
static inline bool cfbf_validate_mpp_streams(
    CfbfLayout *layout, CfbfSemanticEvidence *evidence) {

  if (!layout || layout->root_index >= layout->directory_count) {
    return false;
  }
  const CfbfDirectoryEntry *root =
      &layout->directories[layout->root_index];
  uint8_t version = 0;

  if (cfbf_find_child_directory(layout, root, "Props14")) {
    version = 14;
  }
  else if (cfbf_find_child_directory(layout, root, "Props12")) {
    version = 12;
  }
  else if (cfbf_find_child_directory(layout, root, "Props9")) {
    version = 9;
  }
  else if (cfbf_find_child_directory(layout, root, "Props")) {
    version = 8;
  }
  if (version == 0) {
    return false;
  }

  // Converted Project files can retain complete storage trees from older
  // versions. Prefer the tree named by the current root properties so metadata
  // from different versions is never interpreted with the same record layout.
  const CfbfDirectoryEntry *project_storage = NULL;
  const CfbfDirectoryEntry *view_storage = NULL;
  const CfbfDirectoryEntry *task_storage = NULL;
  const CfbfDirectoryEntry *resource_storage = NULL;
  const CfbfDirectoryEntry *project_properties = NULL;
  const char *project_storage_name = version == 14 ? "   114"
      : (version == 12 ? "   112"
         : (version == 9 ? "   19" : "   1"));
  const char *view_storage_name = version == 14 ? "   214"
      : (version == 12 ? "   212"
         : (version == 9 ? "   29" : "   2"));

  project_storage = cfbf_find_child_directory(
      layout, root, project_storage_name);
  view_storage = cfbf_find_child_directory(layout, root, view_storage_name);

  if (project_storage) {
    task_storage = cfbf_find_child_directory(
        layout, project_storage, "TBkndTask");
    resource_storage = cfbf_find_child_directory(
        layout, project_storage, "TBkndRsc");
    project_properties = cfbf_find_child_directory(
        layout, project_storage, "Props");
  }

  for (uint64_t index = 0;
       !project_storage && index < layout->directory_count; index++) {
    const CfbfDirectoryEntry *entry = &layout->directories[index];

    if (entry->object_type != 1 || entry->parent != layout->root_index) {
      continue;
    }
    const CfbfDirectoryEntry *task = cfbf_find_child_directory(
        layout, entry, "TBkndTask");
    const CfbfDirectoryEntry *resource = cfbf_find_child_directory(
        layout, entry, "TBkndRsc");
    const CfbfDirectoryEntry *properties = cfbf_find_child_directory(
        layout, entry, "Props");

    if (task && resource && properties) {
      project_storage = entry;
      task_storage = task;
      resource_storage = resource;
      project_properties = properties;
      break;
    }
  }
  if (!project_storage || !task_storage || !resource_storage
      || !project_properties) {
    return false;
  }

  if (version != 8) {
    const char *required_names[] = {
      "VarMeta", "FixedMeta", "FixedData"
    };

    for (uint64_t required = 0;
         required < sizeof(required_names) / sizeof(required_names[0]);
         required++) {
      if (!cfbf_find_child_directory(layout, task_storage,
                                     required_names[required])
          || !cfbf_find_child_directory(layout, resource_storage,
                                        required_names[required])) {
        return false;
      }
    }
  }

  uint64_t property_streams = 0;
  uint64_t metadata_streams = 0;
  const uint64_t project_storage_index = (uint64_t)(
      project_storage - layout->directories);
  const uint64_t view_storage_index = view_storage
      ? (uint64_t)(view_storage - layout->directories) : UINT64_MAX;

  for (uint64_t index = 0; index < layout->directory_count; index++) {
    const CfbfDirectoryEntry *entry = &layout->directories[index];

    if (entry->object_type != 2 || entry->stream_size == 0) {
      continue;
    }
    bool active_tree = false;
    uint32_t ancestor = entry->parent;

    for (uint32_t depth = 0;
         depth < 3 && ancestor < layout->directory_count; depth++) {
      if ((uint64_t)ancestor == project_storage_index
          || (uint64_t)ancestor == view_storage_index) {
        active_tree = true;
        break;
      }
      ancestor = layout->directories[ancestor].parent;
    }
    const bool root_property = entry->parent == layout->root_index
        && ((version == 8 && cfbf_name_equals(entry, "Props"))
            || (version == 9 && cfbf_name_equals(entry, "Props9"))
            || (version == 12 && cfbf_name_equals(entry, "Props12"))
            || (version == 14 && cfbf_name_equals(entry, "Props14")));

    if (!active_tree && !root_property) {
      continue;
    }
    const bool property = cfbf_name_equals(entry, "Props")
                          || root_property;
    const bool variable_metadata = cfbf_name_equals(entry, "VarMeta");
    const bool fixed_metadata = cfbf_name_equals(entry, "FixedMeta")
                                || cfbf_name_equals(entry,
                                                    "Fixed2Meta");

    if (!property && !variable_metadata && !fixed_metadata) {
      continue;
    }

    uint8_t *stream = NULL;
    uint64_t stream_length = 0;

    if (!cfbf_materialize_stream(layout, entry, &stream,
                                 &stream_length)) {
      free(stream);
      return false;
    }
    bool valid = false;

    if (property) {
      valid = cfbf_validate_mpp_props_stream(stream, stream_length);
      if (!valid) {
        cfbf_mark_stream_failure(layout, entry, 0);
      }
      property_streams++;
    }
    else if (variable_metadata) {
      const CfbfDirectoryEntry *parent =
          entry->parent < layout->directory_count
              ? &layout->directories[entry->parent] : NULL;
      const CfbfDirectoryEntry *companion = cfbf_find_child_directory(
          layout, parent, "Var2Data");
      uint8_t *variable_data = NULL;
      uint64_t variable_data_length = 0;
      uint64_t metadata_failure = UINT64_MAX;
      uint64_t data_failure = UINT64_MAX;

      if (companion && companion->stream_size != 0
          && !cfbf_materialize_stream(layout, companion, &variable_data,
                                      &variable_data_length)) {
        valid = false;
        cfbf_mark_stream_failure(layout, companion, 0);
      }
      else {
        valid = cfbf_validate_mpp_var_meta_stream(
            stream, stream_length, version, variable_data,
            variable_data_length, &metadata_failure, &data_failure);
        if (!valid && data_failure != UINT64_MAX && companion) {
          cfbf_mark_stream_failure(layout, companion, data_failure);
        }
        else if (!valid && metadata_failure != UINT64_MAX) {
          cfbf_mark_stream_failure(layout, entry, metadata_failure);
        }
      }
      if (valid && evidence && variable_data && parent
          && cfbf_name_equals(parent, "CV_iew")) {
        cfbf_collect_mpp_view_coherence(
            stream, stream_length, version, variable_data,
            variable_data_length, evidence);
      }
      free(variable_data);
      metadata_streams++;
    }
    else {
      valid = cfbf_validate_mpp_fixed_meta_stream(stream, stream_length);
      if (!valid) {
        cfbf_mark_stream_failure(layout, entry, 0);
      }
      metadata_streams++;
    }
    free(stream);
    if (!valid) {
      return false;
    }
  }
  if (version == 8) {
    return property_streams >= 2;
  }
  return property_streams >= 2 && metadata_streams >= 4;
}

// Validate recognizable Office documents embedded below the root storage.
// These checks rank fragmented mappings without treating opaque objects as
// malformed or changing the enclosing file's validation verdict.
//
static inline void cfbf_collect_embedded_office_evidence(
    const CfbfLayout *layout, CfbfSemanticEvidence *evidence) {

  if (!layout || !layout->directories || !evidence) {
    return;
  }

  for (uint64_t index = 0; index < layout->directory_count; index++) {
    const CfbfDirectoryEntry *entry = &layout->directories[index];

    if (entry->object_type != 2 || entry->parent >= layout->directory_count
        || entry->parent == layout->root_index) {
      continue;
    }
    const CfbfDirectoryEntry *parent = &layout->directories[entry->parent];
    bool recognized = false;
    bool valid = false;
    bool coherent = false;
    uint64_t coherence_cost = 0;
    uint64_t coherence_extent = 0;
    uint8_t *data = NULL;
    uint64_t length = 0;

    if (cfbf_name_equals(entry, "Workbook")
        || cfbf_name_equals(entry, "Book")) {
      recognized = true;
      valid = cfbf_materialize_stream(layout, entry, &data, &length)
              && cfbf_analyze_xls_stream(data, length, NULL, NULL);
    }
    else if (cfbf_name_equals(entry, "WordDocument")) {
      if (cfbf_materialize_stream(layout, entry, &data, &length)
          && length >= 12) {
        const uint16_t flags = cfbf_read_le16(data + 10);
        const char *table_name = (flags & UINT16_C(0x0200)) != 0
                                     ? "1Table" : "0Table";
        const CfbfDirectoryEntry *table_entry = cfbf_find_child_directory(
            layout, parent, table_name);
        uint8_t *table = NULL;
        uint64_t table_length = 0;

        if (table_entry) {
          recognized = true;
          valid = cfbf_materialize_stream(layout, table_entry, &table,
                                          &table_length)
                  && cfbf_validate_doc_clx(data, length, table,
                                           table_length);
        }
        free(table);
      }
    }
    else if (cfbf_name_equals(entry, "PowerPoint Document")) {
      const CfbfDirectoryEntry *current_entry = cfbf_find_child_directory(
          layout, parent, "Current User");

      if (current_entry) {
        uint8_t *current = NULL;
        uint64_t current_length = 0;
        uint64_t records = 0;

        recognized = true;
        valid = cfbf_materialize_stream(layout, entry, &data, &length)
                && cfbf_materialize_stream(layout, current_entry, &current,
                                           &current_length)
                && current_length >= 20
                && cfbf_read_le16(current + 2) == UINT16_C(0x0ff6)
                && cfbf_validate_ppt_records(data, length, 0, &records)
                && records != 0;
        if (valid) {
          const uint32_t current_edit = cfbf_read_le32(current + 16);

          valid = cfbf_range_available(length, current_edit, 8)
                  && cfbf_read_le16(data + current_edit + 2)
                         == UINT16_C(0x0ff5);
        }
        free(current);
      }
    }
    else if (cfbf_name_equals(entry, "\003EPRINT")) {
      const CfbfDirectoryEntry *grandparent =
          parent->parent < layout->directory_count
              ? &layout->directories[parent->parent] : NULL;

      if (grandparent && cfbf_name_equals(grandparent, "ObjectPool")) {
        recognized = true;
        valid = cfbf_materialize_stream(layout, entry, &data, &length)
                && cfbf_validate_emf(data, length);
      }
    }
    else if (cfbf_name_equals(entry, "CONTENTS")) {
      const CfbfDirectoryEntry *compobj = cfbf_find_child_directory(
          layout, parent, "\001CompObj");
      uint8_t *compobj_data = NULL;
      uint64_t compobj_length = 0;

      if (compobj
          && cfbf_materialize_stream(layout, compobj, &compobj_data,
                                     &compobj_length)
          && cfbf_contains_bytes(compobj_data, compobj_length,
                                 "MSPhotoEd.3")) {
        recognized = true;
        valid = cfbf_materialize_stream(layout, entry, &data, &length)
                && cfbf_validate_msphotoed_contents(
                       data, length, &coherence_cost,
                       &coherence_extent);
        coherent = valid && coherence_extent != 0;
      }
      free(compobj_data);
    }
    free(data);

    if (recognized && evidence->examined_payloads < UINT32_MAX) {
      evidence->examined_payloads++;
      if (valid) {
        evidence->validated_payloads++;
      }
    }
    if (coherent && evidence->coherence_payloads < UINT32_MAX) {
      evidence->coherence_payloads++;
      if (UINT64_MAX - evidence->coherence_cost < coherence_cost) {
        evidence->coherence_cost = UINT64_MAX;
      }
      else {
        evidence->coherence_cost += coherence_cost;
      }
      if (UINT64_MAX - evidence->coherence_extent < coherence_extent) {
        evidence->coherence_extent = UINT64_MAX;
      }
      else {
        evidence->coherence_extent += coherence_extent;
      }
    }
  }
}

// Apply profile-specific semantic checks after the CFBF allocation and
// directory structures validate. A PLAUSIBLE verdict is intentionally not
// enough to publish a fragmented reconstruction as validated.
//
static inline CfbfSemanticStrength cfbf_validate_semantics(
    CfbfLayout *layout, bool fragmented_reassembly,
    CfbfSemanticEvidence *evidence) {

  if (!layout) {
    return CFBF_SEMANTIC_INVALID;
  }
  if (evidence) {
    memset(evidence, 0, sizeof(*evidence));
    if (fragmented_reassembly) {
      cfbf_collect_embedded_office_evidence(layout, evidence);
    }
  }

  bool metadata_valid = true;
  const CfbfDirectoryEntry *summary = cfbf_find_directory(
      layout, "\005SummaryInformation");
  if (summary) {
    uint8_t *data = NULL;
    uint64_t length = 0;
    if (!cfbf_materialize_stream(layout, summary, &data, &length)
        || !cfbf_validate_property_set(data, length)) {
      metadata_valid = false;
    }
    free(data);
  }

  if (layout->profile == CFBF_PROFILE_XLS
      || layout->profile == CFBF_PROFILE_XLT
      || layout->profile == CFBF_PROFILE_XLA) {
    const CfbfDirectoryEntry *entry = cfbf_find_directory(layout,
                                                           "Workbook");
    if (!entry) {
      entry = cfbf_find_directory(layout, "Book");
    }
    uint8_t *data = NULL;
    uint64_t length = 0;
    bool template_record = false;
    bool addin_record = false;
    const bool valid = entry
                       && cfbf_materialize_stream(layout, entry, &data,
                                                  &length)
                       && cfbf_analyze_xls_stream(data, length,
                                                  &template_record,
                                                  &addin_record);
    if (addin_record) {
      layout->profile = CFBF_PROFILE_XLA;
    }
    else if (template_record) {
      layout->profile = CFBF_PROFILE_XLT;
    }
    else {
      layout->profile = CFBF_PROFILE_XLS;
    }
    free(data);
    return valid && metadata_valid && layout->canonical
               ? CFBF_SEMANTIC_STRONG : CFBF_SEMANTIC_PLAUSIBLE;
  }

  if (layout->profile == CFBF_PROFILE_DOC
      || layout->profile == CFBF_PROFILE_DOT) {
    const CfbfDirectoryEntry *word_entry = cfbf_find_directory(
        layout, "WordDocument");
    uint8_t *word = NULL;
    uint64_t word_length = 0;
    if (!word_entry
        || !cfbf_materialize_stream(layout, word_entry, &word,
                                    &word_length)
        || word_length < 12) {
      free(word);
      return CFBF_SEMANTIC_PLAUSIBLE;
    }
    const uint16_t flags = cfbf_read_le16(word + 10);
    layout->profile = (flags & UINT16_C(0x0001)) != 0
                          ? CFBF_PROFILE_DOT : CFBF_PROFILE_DOC;
    const char *table_name = (flags & UINT16_C(0x0200)) != 0
                                 ? "1Table" : "0Table";
    const CfbfDirectoryEntry *table_entry = cfbf_find_directory(
        layout, table_name);
    uint8_t *table = NULL;
    uint64_t table_length = 0;
    const bool valid = table_entry
                       && cfbf_materialize_stream(layout, table_entry,
                                                  &table, &table_length)
                       && cfbf_validate_doc_clx(word, word_length, table,
                                                table_length);
    free(table);
    free(word);
    return valid && metadata_valid && layout->canonical
               ? CFBF_SEMANTIC_STRONG : CFBF_SEMANTIC_PLAUSIBLE;
  }

  if (layout->profile == CFBF_PROFILE_PPA) {
    return cfbf_validate_ppa_streams(layout, evidence) && metadata_valid
                   && layout->canonical
               ? CFBF_SEMANTIC_STRONG : CFBF_SEMANTIC_PLAUSIBLE;
  }

  if (layout->profile == CFBF_PROFILE_PPT) {
    const CfbfDirectoryEntry *document_entry = cfbf_find_directory(
        layout, "PowerPoint Document");
    const CfbfDirectoryEntry *current_entry = cfbf_find_directory(
        layout, "Current User");
    uint8_t *document = NULL;
    uint8_t *current = NULL;
    uint64_t document_length = 0;
    uint64_t current_length = 0;
    uint64_t records = 0;
    bool valid = document_entry && current_entry
                 && cfbf_materialize_stream(layout, document_entry,
                                            &document, &document_length)
                 && cfbf_materialize_stream(layout, current_entry,
                                            &current, &current_length)
                 && current_length >= 20
                 && cfbf_read_le16(current + 2) == UINT16_C(0x0ff6)
                 && cfbf_validate_ppt_records(document, document_length, 0,
                                              &records)
                 && records != 0;
    if (valid) {
      const uint32_t current_edit = cfbf_read_le32(current + 16);
      valid = cfbf_range_available(document_length, current_edit, 8)
              && cfbf_read_le16(document + current_edit + 2)
                     == UINT16_C(0x0ff5);
    }
    const CfbfDirectoryEntry *pictures_entry = cfbf_find_directory(
        layout, "Pictures");
    uint8_t *pictures = NULL;
    uint64_t pictures_length = 0;
    // Legacy writers can retain stale picture UIDs. Contiguous recovery does
    // not need those UIDs, while fragmented recovery uses them to prove that
    // every selected picture record still contains its original bytes.
    if (valid && fragmented_reassembly && pictures_entry) {
      valid = pictures_entry->object_type == 2
              && cfbf_materialize_stream(layout, pictures_entry,
                                         &pictures, &pictures_length)
              && cfbf_validate_ppt_pictures(pictures, pictures_length);
    }
    free(pictures);
    free(current);
    free(document);
    return valid && metadata_valid && layout->canonical
               ? CFBF_SEMANTIC_STRONG : CFBF_SEMANTIC_PLAUSIBLE;
  }

  if (layout->profile == CFBF_PROFILE_MSG
      || layout->profile == CFBF_PROFILE_OFT) {
    // MSG properties can validate the message structure, but attachment and
    // body streams may contain opaque data without an independent checksum.
    // Their presence cannot authenticate every selected physical block.
    if (evidence) {
      evidence->profile_evidence = cfbf_validate_msg_streams(layout, evidence);
    }
    (void)metadata_valid;
    return CFBF_SEMANTIC_PLAUSIBLE;
  }

  if (layout->profile == CFBF_PROFILE_PUB) {
    return cfbf_validate_publisher_streams(layout) && metadata_valid
                   && layout->canonical
               ? CFBF_SEMANTIC_STRONG : CFBF_SEMANTIC_PLAUSIBLE;
  }

  if (layout->profile == CFBF_PROFILE_VSD) {
    return cfbf_validate_visio_streams(layout) && metadata_valid
                   && layout->canonical
               ? CFBF_SEMANTIC_STRONG : CFBF_SEMANTIC_PLAUSIBLE;
  }

  if (layout->profile == CFBF_PROFILE_MPP) {
    const bool profile_valid = cfbf_validate_mpp_streams(layout, evidence);

    if (evidence) {
      evidence->profile_evidence = profile_valid;
    }
    return profile_valid && metadata_valid && layout->canonical
               ? CFBF_SEMANTIC_STRONG : CFBF_SEMANTIC_PLAUSIBLE;
  }

  // The CFBF container proves the family for these formats, but their main
  // streams need additional order-sensitive parsers before a fragmented
  // reconstruction can receive a strong verdict.
  if (layout->profile == CFBF_PROFILE_BINDER
      || layout->profile == CFBF_PROFILE_ENCRYPTED_OFFICE) {
    return CFBF_SEMANTIC_PLAUSIBLE;
  }
  return CFBF_SEMANTIC_PLAUSIBLE;
}

// Classify a completely parsed compound file using application-defining root
// streams. Strong format roots take precedence over names found inside an
// embedded object storage.
//
static inline CfbfProfile cfbf_classify(const CfbfLayout *layout) {

  bool word_document = false;
  bool word_table = false;
  bool workbook = false;
  bool powerpoint = false;
  bool current_user = false;
  bool message_properties = false;
  bool message_substg = false;
  bool publisher_contents = false;
  bool publisher_support = false;
  bool visio_document = false;
  bool project_props = false;
  bool binder = false;
  bool encrypted_package = false;
  bool encryption_info = false;
  const bool word_document_root =
      cfbf_clsid_equals(layout, cfbf_word6_document_root_clsid)
      || cfbf_clsid_equals(layout, cfbf_word8_document_root_clsid);
  const bool word_template_root =
      cfbf_clsid_equals(layout, cfbf_word6_template_root_clsid)
      || cfbf_clsid_equals(layout, cfbf_word8_template_root_clsid);

  for (uint64_t index = 0; index < layout->directory_count; index++) {
    const CfbfDirectoryEntry *entry = &layout->directories[index];

    if (entry->object_type == 0
        || entry->parent != layout->root_index) {
      continue;
    }
    word_document |= cfbf_name_equals(entry, "WordDocument");
    word_table |= cfbf_name_equals(entry, "0Table")
                  || cfbf_name_equals(entry, "1Table");
    workbook |= cfbf_name_equals(entry, "Workbook")
                || cfbf_name_equals(entry, "Book");
    powerpoint |= cfbf_name_equals(entry, "PowerPoint Document");
    current_user |= cfbf_name_equals(entry, "Current User");
    message_properties |= cfbf_name_equals(
        entry, "__properties_version1.0");
    message_substg |= cfbf_name_starts_with(entry, "__substg1.0_");
    publisher_contents |= cfbf_name_equals(entry, "Contents")
                          || cfbf_name_equals(entry, "CONTENTS");
    publisher_support |= cfbf_name_equals(entry, "Quill")
                         || cfbf_name_equals(entry, "Escher");
    visio_document |= cfbf_name_equals(entry, "VisioDocument");
    project_props |= cfbf_name_equals(entry, "Props")
                     || cfbf_name_equals(entry, "Props9")
                     || cfbf_name_equals(entry, "Props12")
                     || cfbf_name_equals(entry, "Props14");
    binder |= cfbf_name_equals(entry, "Binder")
              || cfbf_name_equals(entry, "BinderFile");
    encrypted_package |= cfbf_name_equals(entry, "EncryptedPackage");
    encryption_info |= cfbf_name_equals(entry, "EncryptionInfo");
  }

  if (encrypted_package && encryption_info) {
    return CFBF_PROFILE_ENCRYPTED_OFFICE;
  }
  if (cfbf_clsid_equals(layout, cfbf_ppa_root_clsid)) {
    return CFBF_PROFILE_PPA;
  }
  if (message_properties && message_substg) {
    return cfbf_clsid_equals(layout, cfbf_oft_root_clsid)
               ? CFBF_PROFILE_OFT : CFBF_PROFILE_MSG;
  }
  if (word_document
      && (word_table || word_document_root || word_template_root)) {
    return word_template_root ? CFBF_PROFILE_DOT : CFBF_PROFILE_DOC;
  }
  if (workbook) {
    return CFBF_PROFILE_XLS;
  }
  if (powerpoint && current_user) {
    return CFBF_PROFILE_PPT;
  }
  if (publisher_contents && publisher_support) {
    return CFBF_PROFILE_PUB;
  }
  if (visio_document) {
    return CFBF_PROFILE_VSD;
  }
  if (project_props) {
    return CFBF_PROFILE_MPP;
  }
  if (binder) {
    return CFBF_PROFILE_BINDER;
  }
  return CFBF_PROFILE_UNKNOWN;
}

// Map a semantic CFBF profile to its Scalpel3 output file type.
//
static inline const char *cfbf_profile_filetype(CfbfProfile profile) {

  switch (profile) {
  case CFBF_PROFILE_DOC:
    return "doc";
  case CFBF_PROFILE_DOT:
    return "dot";
  case CFBF_PROFILE_XLS:
    return "xls";
  case CFBF_PROFILE_XLT:
    return "xlt";
  case CFBF_PROFILE_XLA:
    return "xla";
  case CFBF_PROFILE_PPT:
    return "ppt";
  case CFBF_PROFILE_PPA:
    return "ppa";
  case CFBF_PROFILE_MSG:
    return "msg";
  case CFBF_PROFILE_OFT:
    return "oft";
  case CFBF_PROFILE_PUB:
    return "pub";
  case CFBF_PROFILE_VSD:
    return "vsd";
  case CFBF_PROFILE_MPP:
    return "mpp";
  case CFBF_PROFILE_BINDER:
    return "obd";
  case CFBF_PROFILE_ENCRYPTED_OFFICE:
    return "office-encrypted";
  case CFBF_PROFILE_UNKNOWN:
  default:
    return "cfbf";
  }
}

// Parse and structurally validate one CFBF container. The inferred size is the
// end of the highest allocated sector in the FAT; unrelated search peekahead
// is therefore excluded from the validated result.
//
static inline bool cfbf_parse(const uint8_t *data, uint64_t length,
                              CfbfLayout *layout) {

  if (!layout) {
    return false;
  }
  memset(layout, 0, sizeof(*layout));
  layout->data = data;
  layout->canonical = true;
  layout->length = length;
  layout->failure_offset = 0;
  layout->root_index = UINT64_MAX;

  if (!cfbf_has_header(data, length)) {
    return false;
  }
  if (length < CFBF_HEADER_SIZE) {
    layout->failure_offset = length;
    return false;
  }
  if (cfbf_read_le16(data + 28) != UINT16_C(0xfffe)) {
    layout->failure_offset = 28;
    return false;
  }

  layout->major_version = cfbf_read_le16(data + 26);
  const uint16_t sector_shift = cfbf_read_le16(data + 30);
  const uint16_t mini_sector_shift = cfbf_read_le16(data + 32);

  if (!((layout->major_version == 3 && sector_shift == 9)
        || (layout->major_version == 4 && sector_shift == 12))
      || mini_sector_shift != 6) {
    layout->failure_offset = 26;
    return false;
  }
  layout->sector_size = UINT64_C(1) << sector_shift;
  layout->mini_sector_size = UINT64_C(1) << mini_sector_shift;
  layout->inferred_size = layout->sector_size;
  if (length < layout->sector_size) {
    layout->failure_offset = length;
    return false;
  }
  layout->available_sectors = length / layout->sector_size - 1;
  if (layout->available_sectors == 0
      || layout->available_sectors > UINT32_MAX) {
    layout->failure_offset = length;
    return false;
  }

  const uint32_t fat_sector_count = cfbf_read_le32(data + 44);
  layout->first_directory_sector = cfbf_read_le32(data + 48);
  layout->mini_stream_cutoff = cfbf_read_le32(data + 56);
  layout->first_minifat_sector = cfbf_read_le32(data + 60);
  layout->minifat_sector_count = cfbf_read_le32(data + 64);
  const uint32_t first_difat_sector = cfbf_read_le32(data + 68);
  const uint32_t difat_sector_count = cfbf_read_le32(data + 72);

  if (fat_sector_count == 0
      || layout->first_directory_sector >= CFBF_MAX_REGULAR_SECTOR
      || layout->mini_stream_cutoff != CFBF_MINI_STREAM_CUTOFF) {
    layout->failure_offset = 44;
    return false;
  }

  uint32_t *fat_sectors = NULL;

  if (!cfbf_collect_fat_sectors(layout, fat_sector_count,
                                first_difat_sector, difat_sector_count,
                                &fat_sectors)
      || !cfbf_build_fat(layout, fat_sectors, fat_sector_count)) {
    free(fat_sectors);
    return false;
  }

  if (!cfbf_parse_directories(layout)) {
    free(fat_sectors);
    return false;
  }
  if (!cfbf_assign_directory_parents(layout)) {
    layout->canonical = false;
  }
  if (!cfbf_build_minifat(layout)
      || !cfbf_validate_streams(layout)) {
    free(fat_sectors);
    return false;
  }
  free(fat_sectors);
  layout->profile = cfbf_classify(layout);
  layout->failure_offset = layout->inferred_size;
  return true;
}

// Dormant semantic CFBF specs use this no-op header function so they can own
// output directories and validator callbacks without independently searching
// the image or creating duplicate candidates.
//
static inline char *cfbf_no_header_discovery(char *base, uint64_t offset,
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

// Validate a CFBF candidate and retain its semantic profile long enough for
// the candidate-level callback to select the correct output type. A valid CFBF
// container with an unknown application profile remains a valid cfbf file.
//
static inline void cfbf_file_validate(char *data, uint64_t length,
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

  if (!cfbf_has_header((const uint8_t *)data, length)) {
    return;
  }

  CfbfLayout layout;
  const bool structurally_valid = cfbf_parse((const uint8_t *)data, length,
                                             &layout);
  const CfbfSemanticStrength semantic = structurally_valid
                                            ? cfbf_validate_semantics(
                                                  &layout,
                                                  !scalpel_state.no_defrag,
                                                  NULL)
                                            : CFBF_SEMANTIC_INVALID;
  const uint64_t header_extent = cfbf_header_extent_lower_bound(
      (const uint8_t *)data, length);
  CfbfCarveState state;

  memset(&state, 0, sizeof(state));
  state.magic = CFBF_STATE_MAGIC;
  state.version = CFBF_STATE_VERSION;
  state.profile = structurally_valid ? (uint32_t)layout.profile
                                     : (uint32_t)CFBF_PROFILE_UNKNOWN;
  state.semantic_strength = (uint32_t)semantic;
  // The FAT establishes the logical container extent before directory and
  // stream validation. Preserve that extent when later structure is damaged
  // so fragmented reassembly can evaluate a complete candidate.
  state.inferred_size = layout.inferred_size > header_extent
                            ? layout.inferred_size : header_extent;
  state.failure_offset = layout.failure_offset;
  carve_put_state(carvehashkey, &state);

  if (structurally_valid) {
    *validates = true;
    *validates_to = layout.inferred_size - 1;
  }
  else {
    *promising = true;
    // LR reassembly can replace only the block after the validated prefix.
    // A structural failure can be detected partway through a block whose
    // contents are wrong, so retain only complete blocks before that block.
    if (!structurally_valid && blocksize > 0
        && layout.failure_offset >= blocksize) {
      *validates_to = (layout.failure_offset / blocksize) * blocksize - 1;
    }
    const uint64_t retained_header = header_extent >= CFBF_HEADER_SIZE
        ? CFBF_HEADER_SIZE : CFBF_MAGIC_SIZE;

    if (*validates_to < retained_header - 1) {
      *validates_to = retained_header - 1;
    }
    if (*validates_to >= length) {
      *validates_to = length - 1;
    }
  }
  cfbf_layout_clear(&layout);
}

// Assign a compound file to its semantic output spec. Classification occurs
// only after the container has been parsed, so changing the needle index does
// not invalidate restartable reassembly state.
//
static inline void cfbf_candidate_classify(CarveInfo *candidate,
                                           bool *validates,
                                           uint64_t *validates_to,
                                           bool *promising) {

  (void)validates_to;

  if (!candidate || !candidate->b) {
    return;
  }

  CfbfCarveState *state = (CfbfCarveState *)carve_get_state(
      candidate->carvehashkey);

  if (!state || state->magic != CFBF_STATE_MAGIC
      || state->version != CFBF_STATE_VERSION) {
    cfbf_free_carve_state((void **)&state);
    return;
  }

  cfbf_assign_candidate_profile(candidate, (CfbfProfile)state->profile);

  const CfbfProfile profile = (CfbfProfile)state->profile;

  // Contiguous-only operation accepts a complete CFBF allocation graph under
  // the caller's explicit contiguity assumption. During fragmented recovery,
  // weak semantics and formats with unchecksummed opaque regions remain
  // promising because structure alone cannot authenticate every selected
  // block.
  if (validates && promising && *validates && !scalpel_state.no_defrag
      && (state->semantic_strength != CFBF_SEMANTIC_STRONG
          || !cfbf_profile_authenticates_all_content(profile))) {
    *validates = false;
    *promising = true;
  }
  cfbf_free_carve_state((void **)&state);
}

// Determine whether every byte selected by a candidate lies within the
// physical extent established by an active CFBF header. Requiring valid CFBF
// fixed fields, sector alignment, and complete physical containment avoids
// treating a neighboring standalone archive as embedded content.
//
static inline bool cfbf_contains_candidate(const CarveInfo *candidate,
                                           uint64_t candidate_length) {

  if (!candidate || !candidate->b || candidate_length == 0
      || scalpel_state.blocksize == 0) {
    return false;
  }
  const uint64_t blocksize = scalpel_state.blocksize;
  const uint64_t candidate_blocks = blockvector_get_num_blocks(candidate->b);

  if (candidate_blocks == 0
      || candidate_blocks > UINT64_MAX / blocksize
      || candidate_length > candidate_blocks * blocksize
      || blockvector_get_actual_blocknumber(candidate->b, 0) < 0) {
    return false;
  }
  const uint64_t candidate_start =
      blockvector_data_pointer_offset_to_actual_location(candidate->b, 0);

  for (uint32_t spec_index = 0; spec_index < scalpel_state.num_specs;
       spec_index++) {
    SearchSpec *spec = &scalpel_state.search_specs[spec_index];

    if (strcmp(spec->FILETYPE, "cfbf") != 0) {
      continue;
    }
    for (uint64_t header_index = 0;
         header_index < spec->offsets.numheaders; header_index++) {
      const uint64_t header = spec->offsets.headers[header_index];

      if (header >= candidate_start
          || candidate_start - header >= CFBF_MAXIMUM_SIZE) {
        continue;
      }
      const int64_t header_block = (int64_t)(header / blocksize);
      uint64_t available = 0;
      const uint8_t *block = (const uint8_t *)
          filemirror_actual_block_data_pointer(
              scalpel_state.filemirror, header_block, &available);
      const uint64_t header_offset = header % blocksize;

      if (!block || header_offset > available
          || available - header_offset < CFBF_HEADER_SIZE) {
        continue;
      }
      const uint8_t *data = block + header_offset;
      const uint64_t extent = cfbf_header_extent_lower_bound(
          data, available - header_offset);
      const uint16_t sector_shift = cfbf_read_le16(data + 30);

      if (extent < CFBF_HEADER_SIZE || sector_shift >= 64) {
        continue;
      }
      const uint64_t sector_size = UINT64_C(1) << sector_shift;

      if ((candidate_start - header) % sector_size != 0
          || header > UINT64_MAX - extent) {
        continue;
      }
      const uint64_t container_end = header + extent;
      uint64_t logical_offset = 0;
      bool contained = true;

      while (logical_offset < candidate_length) {
        const uint64_t slot = logical_offset / blocksize;
        const int64_t actual = blockvector_get_actual_blocknumber(
            candidate->b, slot);

        if (actual < 0) {
          contained = false;
          break;
        }
        const uint64_t actual_location =
            blockvector_data_pointer_offset_to_actual_location(
                candidate->b, logical_offset);
        uint64_t chunk = blocksize - actual_location % blocksize;

        if (chunk > candidate_length - logical_offset) {
          chunk = candidate_length - logical_offset;
        }
        if (actual_location < header || actual_location >= container_end
            || chunk > container_end - actual_location) {
          contained = false;
          break;
        }
        logical_offset += chunk;
      }
      if (contained) {
        return true;
      }
    }
    return false;
  }
  return false;
}

// Preserve complete ZIP streams embedded in compound documents without
// allowing their blocks to hide the enclosing document from reassembly.
//
static inline void cfbf_zip_candidate_validate(CarveInfo *candidate,
                                               bool *validates,
                                               uint64_t *validates_to,
                                               bool *promising) {

  zip_candidate_validate(candidate, validates, validates_to, promising);
  if (!candidate || !candidate->b || !validates || !validates_to
      || !promising || !*validates || *validates_to == UINT64_MAX) {
    return;
  }
  const uint64_t archive_length = *validates_to + 1;

  if (!cfbf_contains_candidate(candidate, archive_length)) {
    return;
  }
  ZipCarveState *state = (ZipCarveState *)calloc(1, sizeof(*state));

  check_memory_allocation(state, __LINE__, __FILE__,
                          "enclosed ZIP carve state");
  state->archive_size = archive_length;
  state->observed_archive_size = archive_length;
  state->enclosed_by_cfbf = true;
  carve_put_state(candidate->carvehashkey, state);
  zip_free_carve_state((void **)&state);

  resize_blockvector(candidate->b, CEILDIV(archive_length,
                                           scalpel_state.blocksize));
  blockvector_set_data_length(candidate->b, archive_length);
  *validates = false;
  *promising = true;
}

// Only profiles whose semantic validation covers every selected byte can turn
// a speculative mapping into a validated recovery. New profiles remain
// conservative until their validators provide that guarantee.
//
static inline bool cfbf_profile_authenticates_all_content(
    CfbfProfile profile) {

  switch (profile) {
  case CFBF_PROFILE_BINDER:
  case CFBF_PROFILE_ENCRYPTED_OFFICE:
    return true;
  default:
    return false;
  }
}

// Assign a parsed compound file to the dormant semantic search specification
// that owns its output directory.
//
static inline void cfbf_assign_candidate_profile(CarveInfo *candidate,
                                                 CfbfProfile profile) {

  if (!candidate) {
    return;
  }
  const char *filetype = cfbf_profile_filetype(profile);

  if (strcmp(filetype, "cfbf") == 0) {
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

// Expand a fragmented candidate to the extent established by its header or
// parsed allocation graph. Preserve mappings retained during contiguous
// recovery, then extend beyond them without treating unrelated image blocks
// as part of the logical file.
//
static inline bool cfbf_reassembly_initialize_candidate(
    CarveInfo *candidate, CfbfCarveState *state) {

  if (!candidate || !candidate->b || !state || state->inferred_size == 0
      || scalpel_state.blocksize == 0
      || blockvector_get_num_blocks(candidate->b) == 0) {
    return false;
  }
  uint64_t total_blocks = CEILDIV(state->inferred_size,
                                  scalpel_state.blocksize);
  const uint64_t image_blocks = CEILDIV(
      filemirror_filesize(scalpel_state.filemirror), scalpel_state.blocksize);
  const int64_t header_actual = blockvector_get_actual_blocknumber(
      candidate->b, 0);
  const uint64_t existing_blocks = blockvector_get_num_blocks(candidate->b);
  const uint64_t available_blocks = header_actual >= 0
                                        && (uint64_t)header_actual
                                               < image_blocks
                                    ? image_blocks - (uint64_t)header_actual
                                    : 0;

  // A damaged FAT sector can hide the container's remaining allocation
  // entries. Expose one FAT sector's addressable range while searching, but
  // retain the supported extent when that expansion would consume all space
  // available for a suffix displacement.
  if (state->semantic_strength != CFBF_SEMANTIC_STRONG
      && header_actual >= 0 && (uint64_t)header_actual < image_blocks) {
    const uint8_t *data = (const uint8_t *)blockvector_get_data_pointer(
        candidate->b);
    const uint64_t data_length = blockvector_get_data_length(candidate->b);
    const uint64_t search_extent = cfbf_header_search_extent(
        data, data_length, state->inferred_size);
    const uint64_t search_blocks = CEILDIV(search_extent,
                                           scalpel_state.blocksize);
    if (search_blocks > total_blocks
        && search_blocks < available_blocks) {
      total_blocks = search_blocks;
    }
  }
  if (!state->initialized && available_blocks > 0
      && existing_blocks == available_blocks
      && existing_blocks > total_blocks) {
    state->initial_tail_trimmed = 1;
  }
  // A header near the end of the image may leave the initial contiguous carve
  // spanning every remaining block. Start from the bounded exploratory extent
  // so a suffix repair has room to move, then preserve every expansion made by
  // an initialized or restored reassembly candidate.
  if (state->initialized && existing_blocks > total_blocks) {
    total_blocks = existing_blocks;
  }

  if (total_blocks == 0 || header_actual < 0
      || (uint64_t)header_actual >= image_blocks
      || total_blocks > image_blocks - (uint64_t)header_actual) {
    return false;
  }
  resize_blockvector(candidate->b, total_blocks);
  if (!state->initialized || existing_blocks < total_blocks) {
    const uint64_t first_slot = existing_blocks < total_blocks
                                    ? existing_blocks : total_blocks;
    int64_t extension_shift = 0;

    // Continue a suffix repair only when the live mapping confirms that the
    // retained shift is installed. A ranked but uncommitted suffix must not
    // alter later candidate expansion.
    if (state->initialized && state->suffix_candidate_valid != 0
        && state->suffix_candidate_slot < existing_blocks
        && state->suffix_candidate_shift <= (uint64_t)INT64_MAX) {
      const uint64_t probe_slot = existing_blocks - 1;
      const uint64_t header = (uint64_t)header_actual;
      const uint64_t shift = state->suffix_candidate_shift;

      if (header <= UINT64_MAX - probe_slot
          && header + probe_slot <= UINT64_MAX - shift) {
        const uint64_t expected_actual = header + probe_slot + shift;

        if (expected_actual < image_blocks
            && expected_actual <= (uint64_t)INT64_MAX) {
          const int64_t expected_apparent =
              filemirror_apparent_blocknumber(
                  scalpel_state.filemirror, (int64_t)expected_actual);
          const int64_t mapped_apparent =
              blockvector_get_apparent_blocknumber(
                  candidate->b, probe_slot);

          if (expected_apparent == mapped_apparent) {
            extension_shift = (int64_t)shift;
          }
        }
      }
    }

    int64_t next_actual = header_actual + (int64_t)first_slot
                          + extension_shift;

    // A blockmap swap can remove a validated file that occupied a gap in this
    // candidate. Continue from the retained mapping so extension follows the
    // now-contiguous apparent image instead of re-entering covered blocks.
    if (first_slot > 0) {
      const int64_t previous_actual = blockvector_get_actual_blocknumber(
          candidate->b, first_slot - 1);

      if (previous_actual >= 0 && previous_actual < INT64_MAX) {
        next_actual = previous_actual + 1;
      }
    }
    uint64_t actual_limit = image_blocks;

    if (scalpel_state.end_block != UINT64_MAX
        && scalpel_state.end_block < actual_limit) {
      actual_limit = scalpel_state.end_block + 1;
    }

    for (uint64_t slot = first_slot; slot < total_blocks; slot++) {
      while (next_actual >= 0 && (uint64_t)next_actual < actual_limit
             && !filemirror_actual_block_is_zero(
                    scalpel_state.filemirror, next_actual)
             && filemirror_actual_block_covered(
                    scalpel_state.filemirror, next_actual)) {
        next_actual++;
      }
      if (next_actual < 0 || (uint64_t)next_actual >= actual_limit) {
        return false;
      }
      const bool zero = filemirror_actual_block_is_zero(
          scalpel_state.filemirror, next_actual);
      const int64_t apparent = zero ? -1 : filemirror_apparent_blocknumber(
          scalpel_state.filemirror, next_actual);

      if (!zero && apparent < 0) {
        return false;
      }
      blockvector_set_apparent_blocknumber(candidate->b, slot, apparent);
      next_actual++;
    }
    if (!state->initialized) {
      state->initialized = 1;
      state->search_phase = 0;
      state->suffix_pass = 0;
      state->resume_slot = 0;
      state->resume_choice = 0;
      state->resume_run_width = 0;
      state->resume_run_left = 0;
      state->resume_source_pass = 0;
    }
    carve_put_state(candidate->carvehashkey, state);
  }
  inflate_blockvector(candidate->b);
  blockvector_set_data_length(
      candidate->b, blockvector_get_num_blocks(candidate->b)
                        * (uint64_t)scalpel_state.blocksize);
  return true;
}

// Evaluate one materialized CFBF mapping. Structural progress orders partial
// trials; semantic evidence is required before a fragmented compound file can
// be accepted as complete.
//
static inline bool cfbf_reassembly_evaluate_data(
    const uint8_t *data, uint64_t length, CfbfTrialResult *result) {

  if (!data || length == 0 || !result) {
    return false;
  }
  memset(result, 0, sizeof(*result));
  result->profile = CFBF_PROFILE_UNKNOWN;
  result->semantic_strength = CFBF_SEMANTIC_INVALID;

  CfbfLayout layout;

  result->structurally_valid = cfbf_parse(data, length, &layout);
  result->inferred_size = layout.inferred_size;
  result->failure_offset = result->structurally_valid
                               ? layout.inferred_size
                               : layout.failure_offset;
  if (result->structurally_valid) {
    CfbfSemanticEvidence evidence;

    result->semantic_strength = cfbf_validate_semantics(
        &layout, true, &evidence);
    result->profile = layout.profile;
    result->profile_evidence = evidence.profile_evidence
                               || result->semantic_strength
                                      == CFBF_SEMANTIC_STRONG;
    result->examined_payloads = evidence.examined_payloads;
    result->validated_payloads = evidence.validated_payloads;
    result->coherence_payloads = evidence.coherence_payloads;
    result->coherence_cost = evidence.coherence_cost;
    result->coherence_extent = evidence.coherence_extent;
    if (layout.failure_offset != 0
        && layout.failure_offset < result->failure_offset) {
      result->failure_offset = layout.failure_offset;
    }
  }

  uint64_t extent = result->inferred_size;

  if (extent == 0 || extent > length) {
    extent = length;
  }
  if (result->failure_offset > extent) {
    result->failure_offset = extent;
  }
  result->score = result->failure_offset;
  if (result->structurally_valid) {
    result->score = extent * UINT64_C(2);
    if (result->semantic_strength == CFBF_SEMANTIC_PLAUSIBLE) {
      result->score = extent * UINT64_C(3);
    }
    else if (result->semantic_strength == CFBF_SEMANTIC_STRONG) {
      result->score = extent * UINT64_C(4);
    }
    if (result->profile_evidence
        && result->semantic_strength != CFBF_SEMANTIC_STRONG) {
      result->score += extent / UINT64_C(2) + 1;
    }
    if (result->examined_payloads != 0
        && result->validated_payloads != 0) {
      result->score += (extent / UINT64_C(4)
                        * result->validated_payloads)
                       / result->examined_payloads;
    }
  }
  cfbf_layout_clear(&layout);
  return true;
}

// Reuse a valid allocation graph to reject losing data-stream substitutions
// without reparsing the entire compound file. A positive result is only a
// prefilter: the caller must still parse and validate the complete trial before
// retaining it.
//
static inline bool cfbf_reassembly_semantic_trial_complete(
    const CfbfLayout *base_layout, const uint8_t *data, uint64_t length) {

  if (!base_layout || !data || length == 0
      || base_layout->profile == CFBF_PROFILE_UNKNOWN) {
    return true;
  }

  // The copy borrows the parsed arrays owned by base_layout. Only the data
  // pointer and semantic profile may change during this prefilter.
  CfbfLayout trial = *base_layout;
  trial.data = data;
  trial.length = length;

  if (trial.profile == CFBF_PROFILE_MPP) {
    return cfbf_validate_mpp_streams(&trial, NULL);
  }
  if (trial.profile == CFBF_PROFILE_PPA) {
    return cfbf_validate_ppa_streams(&trial, NULL);
  }

  CfbfSemanticEvidence evidence;
  const CfbfSemanticStrength semantic = cfbf_validate_semantics(
      &trial, true, &evidence);

  return semantic == CFBF_SEMANTIC_STRONG || evidence.profile_evidence;
}

// Evaluate the live mapping without replacing its checkpointed search state.
//
static inline bool cfbf_reassembly_evaluate_candidate(
    CarveInfo *candidate, CfbfTrialResult *result) {

  if (!candidate || !candidate->b || !result) {
    return false;
  }
  const uint8_t *data = (const uint8_t *)blockvector_get_data_pointer(
      candidate->b);
  const uint64_t length = blockvector_get_data_length(candidate->b);

  return cfbf_reassembly_evaluate_data(data, length, result);
}

// Find the logical slot currently backed by an actual image block.
//
static inline int64_t cfbf_reassembly_find_actual_slot(
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

// Resolve an actual image block to the apparent block number that can be
// stored in a trial mapping. Blocks already owned by this candidate remain
// selectable even though the candidate holds reservations on them.
//
static inline bool cfbf_reassembly_mapping_source(
    BlockVector *blockvector, int64_t actual_block,
    int64_t *apparent_block, int64_t *source_slot) {

  if (!blockvector || actual_block < 0 || !apparent_block || !source_slot) {
    return false;
  }
  const uint64_t image_blocks = CEILDIV(
      filemirror_filesize(scalpel_state.filemirror), scalpel_state.blocksize);

  if ((uint64_t)actual_block >= image_blocks) {
    return false;
  }
  *source_slot = cfbf_reassembly_find_actual_slot(blockvector, actual_block);
  if (*source_slot >= 0) {
    *apparent_block = blockvector_get_apparent_blocknumber(
        blockvector, (uint64_t)*source_slot);
    return true;
  }
  // Zero sectors are interchangeable and only their canonical exemplar has an
  // apparent block number after blockmap deduplication.
  if (filemirror_actual_block_is_zero(scalpel_state.filemirror,
                                      actual_block)) {
    const int64_t exemplar = filemirror_get_exemplar(
        scalpel_state.filemirror, actual_block);

    *apparent_block = filemirror_apparent_blocknumber(
        scalpel_state.filemirror, exemplar);
    return *apparent_block >= 0;
  }
  if (filemirror_actual_block_covered(scalpel_state.filemirror,
                                      actual_block)) {
    return false;
  }
  const int64_t exemplar = filemirror_get_exemplar(
      scalpel_state.filemirror, actual_block);
  *apparent_block = filemirror_apparent_blocknumber(
      scalpel_state.filemirror, exemplar);
  if (*apparent_block < 0
      && !filemirror_actual_block_is_zero(scalpel_state.filemirror,
                                          actual_block)) {
    return false;
  }
  return true;
}

// Reject a physical run once per candidate when any constituent block is
// unavailable. Target-specific overlap checks remain in the mapping builder.
//
static inline bool cfbf_reassembly_run_source_available(
    BlockVector *blockvector, uint64_t run_blocks, int64_t source_actual) {

  if (!blockvector || run_blocks == 0 || source_actual < 0) {
    return false;
  }
  for (uint64_t index = 0; index < run_blocks; index++) {
    int64_t apparent_block = -1;
    int64_t source_slot = -1;

    if (!cfbf_reassembly_mapping_source(
            blockvector, source_actual + (int64_t)index,
            &apparent_block, &source_slot)
        || source_slot == 0) {
      return false;
    }
  }
  return true;
}

// Map CFBF subtypes to the active file type specification whose block
// confidence describes their physical contents. The model's "dot" class
// describes source text, not Word templates, so DOT intentionally shares the
// DOC specification.
//
static inline int32_t cfbf_reassembly_confidence_spec(CfbfProfile profile) {

  if (!scalpel_state.search_specs || !scalpel_state.modico_enabled
      || !scalpel_state.modico_spec_to_class) {
    return -1;
  }
  const char *profile_filetype = NULL;
  const char *family_filetype = NULL;

  switch (profile) {
  case CFBF_PROFILE_DOC:
    profile_filetype = "doc";
    family_filetype = "doc";
    break;
  case CFBF_PROFILE_DOT:
    profile_filetype = "dot";
    family_filetype = "doc";
    break;
  case CFBF_PROFILE_XLS:
    profile_filetype = "xls";
    family_filetype = "xls";
    break;
  case CFBF_PROFILE_XLT:
    profile_filetype = "xlt";
    family_filetype = "xls";
    break;
  case CFBF_PROFILE_XLA:
    profile_filetype = "xla";
    family_filetype = "xls";
    break;
  case CFBF_PROFILE_PPT:
    profile_filetype = "ppt";
    family_filetype = "ppt";
    break;
  case CFBF_PROFILE_PPA:
    profile_filetype = "ppa";
    family_filetype = "ppt";
    break;
  case CFBF_PROFILE_MPP:
    profile_filetype = "mpp";
    family_filetype = "ppt";
    break;
  default:
    return -1;
  }

  const char *filetypes[2] = { profile_filetype, family_filetype };

  for (uint32_t pass = 0; pass < 2; pass++) {
    if (pass != 0 && strcmp(filetypes[0], filetypes[1]) == 0) {
      continue;
    }
    for (uint32_t index = 0;
         index < scalpel_state.num_specs
         && index < scalpel_state.modico_num_specs; index++) {
      if (strcmp(scalpel_state.search_specs[index].FILETYPE,
                 filetypes[pass]) == 0
          && scalpel_state.modico_spec_to_class[index] >= 0) {
        return (int32_t)index;
      }
    }
  }
  return -1;
}

// Select the model class used only to order a repair search. A parsed subtype
// is authoritative. Otherwise, a uniquely strong header classification can
// identify a damaged file before parsing succeeds, with bounded whole-file
// sampling as a fallback when the header is ambiguous.
static inline CfbfProfile cfbf_reassembly_model_profile(
    BlockVector *blockvector, CfbfProfile parsed_profile) {

  if (parsed_profile == CFBF_PROFILE_DOC
      || parsed_profile == CFBF_PROFILE_DOT) {
    return CFBF_PROFILE_DOC;
  }
  if (parsed_profile == CFBF_PROFILE_XLS
      || parsed_profile == CFBF_PROFILE_XLT
      || parsed_profile == CFBF_PROFILE_XLA) {
    return CFBF_PROFILE_XLS;
  }
  if (parsed_profile == CFBF_PROFILE_PPT
      || parsed_profile == CFBF_PROFILE_PPA) {
    return CFBF_PROFILE_PPT;
  }
  if (parsed_profile == CFBF_PROFILE_MPP) {
    return CFBF_PROFILE_MPP;
  }
  if (!blockvector || blockvector_get_num_blocks(blockvector) == 0) {
    return CFBF_PROFILE_UNKNOWN;
  }
  const CfbfProfile profiles[] = {
    CFBF_PROFILE_DOC,
    CFBF_PROFILE_XLS,
    CFBF_PROFILE_PPT
  };
  const int64_t header_actual = blockvector_get_actual_blocknumber(
      blockvector, 0);

  if (header_actual >= 0) {
    CfbfProfile header_profile = CFBF_PROFILE_UNKNOWN;
    uint32_t header_best = 0;
    uint32_t header_second = 0;

    for (uint32_t index = 0;
         index < sizeof(profiles) / sizeof(profiles[0]); index++) {
      const int32_t spec = cfbf_reassembly_confidence_spec(profiles[index]);
      const uint32_t confidence = spec >= 0
          ? filemirror_get_blocktype(scalpel_state.filemirror,
                                     header_actual, (uint32_t)spec)
          : 0;

      if (confidence > header_best) {
        header_second = header_best;
        header_best = confidence;
        header_profile = profiles[index];
      }
      else if (confidence > header_second) {
        header_second = confidence;
      }
    }
    if (header_best >= BLOCK_CONFIDENCE_VALID / 2
        && header_best > header_second) {
      return header_profile;
    }
  }
  const uint64_t total_blocks = blockvector_get_num_blocks(blockvector);
  const uint64_t samples = total_blocks < CFBF_MODEL_PROFILE_SAMPLE_LIMIT
      ? total_blocks : CFBF_MODEL_PROFILE_SAMPLE_LIMIT;
  uint64_t scores[sizeof(profiles) / sizeof(profiles[0])] = { 0 };
  uint64_t sampled = 0;

  for (uint64_t sample = 0; sample < samples; sample++) {
    const uint64_t slot = samples == 1
        ? 0 : sample * (total_blocks - 1) / (samples - 1);
    const int64_t actual = blockvector_get_actual_blocknumber(
        blockvector, slot);

    if (actual < 0) {
      continue;
    }
    sampled++;
    for (uint32_t index = 0;
         index < sizeof(profiles) / sizeof(profiles[0]); index++) {
      const int32_t spec = cfbf_reassembly_confidence_spec(profiles[index]);

      if (spec >= 0) {
        scores[index] += filemirror_get_blocktype(
            scalpel_state.filemirror, actual, (uint32_t)spec);
      }
    }
  }
  if (sampled == 0) {
    return CFBF_PROFILE_UNKNOWN;
  }
  CfbfProfile best_profile = CFBF_PROFILE_UNKNOWN;
  uint64_t best = 0;
  uint64_t second = 0;

  for (uint32_t index = 0;
       index < sizeof(profiles) / sizeof(profiles[0]); index++) {
    if (scores[index] > best) {
      second = best;
      best = scores[index];
      best_profile = profiles[index];
    }
    else if (scores[index] > second) {
      second = scores[index];
    }
  }
  const uint64_t minimum_score = sampled * (BLOCK_CONFIDENCE_VALID / 4);
  const uint64_t minimum_margin = sampled * (BLOCK_CONFIDENCE_VALID / 20);
  const bool selected = best >= minimum_score
                        && best > second + minimum_margin;

  if (scalpel_state.mode_verbose) {
    lock_fprintf(
        stdout,
        "CFBF model profile rank: samples=%" PRIu64
        " doc=%" PRIu64 " xls=%" PRIu64 " ppt=%" PRIu64
        " selected=%s.\n",
        sampled, scores[0], scores[1], scores[2],
        selected ? cfbf_profile_filetype(best_profile) : "none");
  }

  return selected ? best_profile : CFBF_PROFILE_UNKNOWN;
}

// Keep a small, ordered set of physical model signals. The list bounds full
// parser trials without turning model confidence into an exclusion rule for
// the general reassembly search.
static inline void cfbf_reassembly_retain_model_run(
    CfbfModelRun *runs, uint32_t *count, uint32_t limit,
    const CfbfModelRun *candidate) {

  if (!runs || !count || !candidate || limit == 0
      || candidate->width == 0 || candidate->evidence <= 0) {
    return;
  }
  uint32_t position = *count;

  if (position < limit) {
    (*count)++;
  }
  else {
    const CfbfModelRun *last = &runs[limit - 1];
    const bool better = candidate->evidence > last->evidence
        || (candidate->evidence == last->evidence
            && candidate->confidence > last->confidence)
        || (candidate->evidence == last->evidence
            && candidate->confidence == last->confidence
            && candidate->width < last->width)
        || (candidate->evidence == last->evidence
            && candidate->confidence == last->confidence
            && candidate->width == last->width
            && candidate->actual < last->actual);

    if (!better) {
      return;
    }
    position = limit - 1;
  }

  while (position > 0) {
    const CfbfModelRun *prior = &runs[position - 1];
    const bool better = candidate->evidence > prior->evidence
        || (candidate->evidence == prior->evidence
            && candidate->confidence > prior->confidence)
        || (candidate->evidence == prior->evidence
            && candidate->confidence == prior->confidence
            && candidate->width < prior->width)
        || (candidate->evidence == prior->evidence
            && candidate->confidence == prior->confidence
            && candidate->width == prior->width
            && candidate->actual < prior->actual);

    if (!better) {
      break;
    }
    runs[position] = runs[position - 1];
    position--;
  }
  runs[position] = *candidate;
}

// Retain maximal physical runs whose boundaries are supported independently
// of a CFBF parse. Covered blocks belong to an already accepted file, while a
// low-concentration byte distribution identifies likely high-entropy filler.
static inline uint32_t cfbf_reassembly_collect_supported_gaps(
    int64_t header_actual, uint64_t signal_end,
    CfbfModelRun *runs, uint32_t capacity) {

  if (header_actual < 0 || !runs || capacity == 0) {
    return 0;
  }
  const uint64_t image_blocks = CEILDIV(
      filemirror_filesize(scalpel_state.filemirror), scalpel_state.blocksize);

  if ((uint64_t)header_actual >= image_blocks) {
    return 0;
  }
  if (signal_end > image_blocks) {
    signal_end = image_blocks;
  }
  uint64_t actual = (uint64_t)header_actual + 1;
  uint32_t count = 0;

  while (actual < signal_end) {
    const bool first_covered = filemirror_actual_block_covered(
        scalpel_state.filemirror, (int64_t)actual);
    const bool first_uniform = !first_covered
        && cfbf_reassembly_block_is_uniform((int64_t)actual);

    if (!first_covered && !first_uniform) {
      actual++;
      continue;
    }
    const uint64_t run_start = actual;
    uint64_t total_concentration = 0;
    bool all_zero = true;
    bool has_covered = false;

    while (actual < image_blocks) {
      const bool covered = filemirror_actual_block_covered(
          scalpel_state.filemirror, (int64_t)actual);
      const bool zero = !covered
          && filemirror_actual_block_is_zero(
                 scalpel_state.filemirror, (int64_t)actual);
      const bool uniform = !covered
          && cfbf_reassembly_block_is_uniform((int64_t)actual);

      if (!covered && !uniform) {
        break;
      }
      if (actual >= signal_end && !covered) {
        break;
      }
      uint64_t concentration = cfbf_reassembly_run_concentration(
          (int64_t)actual, 1);

      if (concentration == UINT64_MAX) {
        concentration = 0;
      }
      if (total_concentration <= UINT64_MAX - concentration) {
        total_concentration += concentration;
      }
      else {
        total_concentration = UINT64_MAX;
      }
      if (!zero) {
        all_zero = false;
      }
      has_covered = has_covered || covered;
      actual++;
    }
    const uint64_t width = actual - run_start;

    if (width == 0 || actual >= image_blocks) {
      continue;
    }
    const bool right_covered = filemirror_actual_block_covered(
        scalpel_state.filemirror, (int64_t)actual);
    const bool right_uniform = !right_covered
        && cfbf_reassembly_block_is_uniform((int64_t)actual);

    if (right_covered || right_uniform) {
      continue;
    }
    const uint64_t average = total_concentration == UINT64_MAX
        ? UINT64_MAX : total_concentration / width;
    const CfbfModelRun signal = {
      .all_zero = all_zero ? 1 : 0,
      .actual = run_start,
      .width = width,
      .evidence = has_covered
                      ? INT64_MAX
                      : (width > (uint64_t)INT64_MAX
                             ? INT64_MAX : (int64_t)width),
      .confidence = has_covered ? width : UINT64_MAX - average
    };

    cfbf_reassembly_retain_model_run(runs, &count, capacity, &signal);
  }
  return count;
}

// Rank a displaced run by the confidence it gains over the blocks currently
// occupying those logical slots and by contention with other candidates.
// Reservations and confidence guide ordering only; the exhaustive search still
// considers lower-ranked hypotheses.
//
static inline void cfbf_reassembly_run_metrics(
    BlockVector *blockvector, const int64_t *mapping, uint64_t target_slot,
    uint64_t run_blocks, int64_t source_actual, CfbfProfile profile,
    bool *has_confidence, bool *all_positive,
    int64_t *confidence_gain, uint32_t *reserved,
    uint32_t *minimum_source_confidence) {

  if (has_confidence) {
    *has_confidence = false;
  }
  if (all_positive) {
    *all_positive = false;
  }
  if (confidence_gain) {
    *confidence_gain = 0;
  }
  if (reserved) {
    *reserved = 0;
  }
  if (minimum_source_confidence) {
    *minimum_source_confidence = 0;
  }
  if (!blockvector || run_blocks == 0 || source_actual < 0
      || !has_confidence || !all_positive || !confidence_gain
      || !reserved) {
    return;
  }

  const int32_t confidence_spec = cfbf_reassembly_confidence_spec(profile);

  *has_confidence = confidence_spec >= 0;
  *all_positive = *has_confidence;

  if (minimum_source_confidence && *has_confidence) {
    *minimum_source_confidence = UINT32_MAX;
  }

  for (uint64_t index = 0; index < run_blocks; index++) {
    const int64_t source = source_actual + (int64_t)index;
    const int64_t source_slot = mapping
        ? cfbf_reassembly_find_mapping_actual(
              mapping, blockvector_get_num_blocks(blockvector), source)
        : cfbf_reassembly_find_actual_slot(blockvector, source);

    if (source_slot < 0) {
      const int64_t source_reservations = filemirror_actual_block_reserved(
          scalpel_state.filemirror, source);

      if (source_reservations > 0) {
        const uint64_t total = (uint64_t)*reserved
                               + (uint64_t)source_reservations;
        *reserved = total > UINT32_MAX ? UINT32_MAX : (uint32_t)total;
      }
    }
    if (*has_confidence) {
      const int64_t destination = mapping
          ? (mapping[target_slot + index] >= 0
                 ? filemirror_actual_blocknumber(
                       scalpel_state.filemirror,
                       mapping[target_slot + index])
                 : -1)
          : blockvector_get_actual_blocknumber(
                blockvector, target_slot + index);
      const int32_t source_confidence = (int32_t)filemirror_get_blocktype(
          scalpel_state.filemirror, source, (uint32_t)confidence_spec);
      const int32_t destination_confidence = destination >= 0
          ? (int32_t)filemirror_get_blocktype(
                scalpel_state.filemirror, destination,
                (uint32_t)confidence_spec)
          : (int32_t)BLOCK_CONFIDENCE_INVALID;
      const int32_t delta = source_confidence - destination_confidence;

      *confidence_gain += (int64_t)delta;
      if (minimum_source_confidence
          && (uint32_t)source_confidence
                 < *minimum_source_confidence) {
        *minimum_source_confidence = (uint32_t)source_confidence;
      }
      if (delta <= 0) {
        *all_positive = false;
      }
    }
  }
}

// Measure one block once for both concentration tests and the compact byte
// distribution fingerprint used to order displaced-run hypotheses.
//
static inline bool cfbf_reassembly_measure_block(
    int64_t actual_block, uint64_t *concentration,
    uint8_t fingerprint[CFBF_CONTEXT_FINGERPRINT_BINS]) {

  if (actual_block < 0 || !concentration) {
    return false;
  }
  if (fingerprint) {
    memset(fingerprint, 0, CFBF_CONTEXT_FINGERPRINT_BINS);
  }
  if (filemirror_actual_block_is_zero(
          scalpel_state.filemirror, actual_block)) {
    *concentration = 0;
    if (fingerprint) {
      fingerprint[0] = UINT8_MAX;
    }
    return true;
  }
  uint64_t length = 0;
  const uint8_t *data = (const uint8_t *)
      filemirror_actual_block_data_pointer(
          scalpel_state.filemirror, actual_block, &length);

  if (!data || length == 0 || length > UINT32_MAX) {
    return false;
  }
  uint64_t frequencies[256] = { 0 };
  uint64_t squared = 0;

  for (uint64_t offset = 0; offset < length; offset++) {
    frequencies[data[offset]]++;
  }
  for (uint32_t value = 0; value < 256; value++) {
    squared += frequencies[value] * frequencies[value];
  }
  const uint64_t denominator = length * length;

  if (squared <= UINT64_MAX / UINT64_C(65536)) {
    *concentration = squared * UINT64_C(65536) / denominator;
  }
  else {
    *concentration = squared / length;
  }
  if (fingerprint) {
    const uint32_t values_per_bin = 256
        / CFBF_CONTEXT_FINGERPRINT_BINS;

    for (uint32_t bin = 0;
         bin < CFBF_CONTEXT_FINGERPRINT_BINS; bin++) {
      uint64_t count = 0;
      const uint32_t first = bin * values_per_bin;

      for (uint32_t value = first;
           value < first + values_per_bin; value++) {
        count += frequencies[value];
      }
      fingerprint[bin] = (uint8_t)(
          (count * UINT64_C(255) + length / 2) / length);
    }
  }
  return true;
}

// Measure how closely a run resembles statistically uniform unrelated data.
// This is only a tiebreaker among complete format-valid suffix repairs. Lower
// concentration is stronger evidence that the skipped physical run was not
// part of the compound file.
//
static inline uint64_t cfbf_reassembly_run_concentration(
    int64_t source_actual, uint64_t run_blocks) {

  if (source_actual < 0 || run_blocks == 0) {
    return UINT64_MAX;
  }
  uint64_t total_score = 0;
  uint64_t measured = 0;

  for (uint64_t block = 0; block < run_blocks; block++) {
    uint64_t score = 0;

    if (!cfbf_reassembly_measure_block(
            source_actual + (int64_t)block, &score, NULL)) {
      continue;
    }
    if (total_score <= UINT64_MAX - score) {
      total_score += score;
    }
    else {
      total_score = UINT64_MAX;
    }
    measured++;
  }
  return measured == 0 ? UINT64_MAX : total_score / measured;
}

// Measure whether a skipped physical run is bounded by blocks that look more
// like the candidate's file type. When no model class exists, byte-distribution
// concentration supplies the same ordering signal. This ranks GAP hypotheses
// but never excludes a lower-ranked displacement.
//
static inline int64_t cfbf_reassembly_suffix_boundary_evidence(
    int64_t skipped_actual, uint64_t shift, CfbfProfile profile) {

  if (skipped_actual <= 0 || shift == 0) {
    return 0;
  }
  const uint64_t image_blocks = CEILDIV(
      filemirror_filesize(scalpel_state.filemirror), scalpel_state.blocksize);

  if ((uint64_t)skipped_actual >= image_blocks
      || shift >= image_blocks - (uint64_t)skipped_actual) {
    return 0;
  }
  const int32_t confidence_spec = cfbf_reassembly_confidence_spec(profile);

  if (confidence_spec >= 0) {
    int32_t skipped_max = 0;

    for (uint64_t block = 0; block < shift; block++) {
      const int32_t confidence = (int32_t)filemirror_get_blocktype(
          scalpel_state.filemirror, skipped_actual + (int64_t)block,
          (uint32_t)confidence_spec);

      if (confidence > skipped_max) {
        skipped_max = confidence;
      }
    }
    const int32_t left = (int32_t)filemirror_get_blocktype(
        scalpel_state.filemirror, skipped_actual - 1,
        (uint32_t)confidence_spec);
    const int32_t right = (int32_t)filemirror_get_blocktype(
        scalpel_state.filemirror, skipped_actual + (int64_t)shift,
        (uint32_t)confidence_spec);
    const int32_t boundary = left < right ? left : right;

    return (int64_t)boundary - (int64_t)skipped_max;
  }

  const uint64_t skipped = cfbf_reassembly_run_concentration(
      skipped_actual, shift);
  const uint64_t left = cfbf_reassembly_run_concentration(
      skipped_actual - 1, 1);
  const uint64_t right = cfbf_reassembly_run_concentration(
      skipped_actual + (int64_t)shift, 1);
  const uint64_t boundary = left < right ? left : right;

  if (skipped == UINT64_MAX || boundary <= skipped) {
    return 0;
  }
  const uint64_t difference = boundary - skipped;

  return difference > (uint64_t)INT64_MAX
             ? INT64_MAX : (int64_t)difference;
}

// Allocate a process-wide two-bit cache for the uniform/nonuniform decision.
// Every block is measured at most once even when many candidates scan the same
// image concurrently.
//
static void cfbf_reassembly_initialize_uniform_cache(void) {

  cfbf_uniform_cache_blocks = CEILDIV(
      filemirror_filesize(scalpel_state.filemirror), scalpel_state.blocksize);
  cfbf_uniform_cache_words = CEILDIV(cfbf_uniform_cache_blocks, 64);

  if (cfbf_uniform_cache_words == 0) {
    return;
  }
  cfbf_uniform_cache_known = (_Atomic uint64_t *)calloc(
      (size_t)cfbf_uniform_cache_words,
      sizeof(*cfbf_uniform_cache_known));
  cfbf_uniform_cache_value = (_Atomic uint64_t *)calloc(
      (size_t)cfbf_uniform_cache_words,
      sizeof(*cfbf_uniform_cache_value));
  check_memory_allocation(cfbf_uniform_cache_known, __LINE__, __FILE__,
                          "CFBF concentration cache state");
  check_memory_allocation(cfbf_uniform_cache_value, __LINE__, __FILE__,
                          "CFBF concentration cache values");

  if (cfbf_uniform_cache_blocks
          <= CFBF_CONTEXT_CACHE_LIMIT
             / CFBF_CONTEXT_FINGERPRINT_BINS
      && cfbf_uniform_cache_blocks
          <= SIZE_MAX / CFBF_CONTEXT_FINGERPRINT_BINS) {
    cfbf_context_fingerprint_cache = (uint8_t *)calloc(
        (size_t)cfbf_uniform_cache_blocks,
        CFBF_CONTEXT_FINGERPRINT_BINS);
  }

  for (uint64_t word = 0; word < cfbf_uniform_cache_words; word++) {
    atomic_init(&cfbf_uniform_cache_known[word], UINT64_C(0));
    atomic_init(&cfbf_uniform_cache_value[word], UINT64_C(0));
  }
}

// Return the cached side of the concentration threshold used by the isolated
// run search. Publishing the value before the known bit makes concurrent reads
// deterministic without serializing workers.
//
static inline bool cfbf_reassembly_block_is_uniform(int64_t actual_block) {

  if (actual_block < 0) {
    return false;
  }
  pthread_once(&cfbf_uniform_cache_once,
               cfbf_reassembly_initialize_uniform_cache);

  if (!cfbf_uniform_cache_known || !cfbf_uniform_cache_value
      || (uint64_t)actual_block >= cfbf_uniform_cache_blocks) {
    return false;
  }
  const uint64_t word = (uint64_t)actual_block / UINT64_C(64);
  const uint64_t bit = UINT64_C(1)
                       << ((uint64_t)actual_block % UINT64_C(64));
  const uint64_t known = atomic_load_explicit(
      &cfbf_uniform_cache_known[word], memory_order_acquire);

  if ((known & bit) != 0) {
    return (atomic_load_explicit(
                &cfbf_uniform_cache_value[word], memory_order_relaxed)
            & bit) != 0;
  }

  MUTEX_ERROR_CHECK(pthread_mutex_lock(&cfbf_uniform_cache_lock),
                    __LINE__, __FILE__);
  const uint64_t known_after_lock = atomic_load_explicit(
      &cfbf_uniform_cache_known[word], memory_order_acquire);

  if ((known_after_lock & bit) != 0) {
    const bool uniform = (atomic_load_explicit(
                              &cfbf_uniform_cache_value[word],
                              memory_order_relaxed)
                          & bit) != 0;

    MUTEX_ERROR_CHECK(pthread_mutex_unlock(&cfbf_uniform_cache_lock),
                      __LINE__, __FILE__);
    return uniform;
  }
  uint64_t concentration = UINT64_MAX;
  uint8_t fingerprint[CFBF_CONTEXT_FINGERPRINT_BINS];
  const bool measured = cfbf_reassembly_measure_block(
      actual_block, &concentration, fingerprint);
  const bool uniform = measured
      && concentration <= CFBF_UNIFORM_CONCENTRATION_LIMIT;

  if (measured && cfbf_context_fingerprint_cache) {
    memcpy(cfbf_context_fingerprint_cache
               + (size_t)actual_block * CFBF_CONTEXT_FINGERPRINT_BINS,
           fingerprint, CFBF_CONTEXT_FINGERPRINT_BINS);
  }

  if (uniform) {
    atomic_fetch_or_explicit(&cfbf_uniform_cache_value[word], bit,
                             memory_order_relaxed);
  }
  atomic_fetch_or_explicit(&cfbf_uniform_cache_known[word], bit,
                           memory_order_release);
  MUTEX_ERROR_CHECK(pthread_mutex_unlock(&cfbf_uniform_cache_lock),
                    __LINE__, __FILE__);
  return uniform;
}

// Count every image-bounded source run of a requested width. Model confidence,
// subtype evidence, and local continuity order the fast pass, but the complete
// pass must also reach valid compressed or encrypted sectors that resemble
// random filler.
//
static inline uint64_t cfbf_reassembly_source_run_count(uint64_t width) {

  const uint64_t image_blocks = CEILDIV(
      filemirror_filesize(scalpel_state.filemirror), scalpel_state.blocksize);

  if (width == 0 || width > image_blocks) {
    return 0;
  }
  return image_blocks - width + 1;
}

// Initialize an ascending, restartable traversal of every image-bounded source
// run. The ranked pass has already tried likely sources, so this iterator is
// the correctness fallback rather than the primary ordering mechanism.
//
static inline void cfbf_reassembly_source_run_iterator_initialize(
    CfbfSourceRunIterator *iterator, uint64_t width,
    uint64_t minimum_actual) {

  if (!iterator) {
    return;
  }
  const uint64_t image_blocks = CEILDIV(
      filemirror_filesize(scalpel_state.filemirror), scalpel_state.blocksize);

  iterator->width = width > 0 && width <= image_blocks ? width : 0;
  iterator->next_actual = minimum_actual;
  iterator->last_actual = iterator->width == 0
      ? 0 : image_blocks - iterator->width;
}

// Return the next source run of the requested width.
//
static inline bool cfbf_reassembly_next_source_run(
    CfbfSourceRunIterator *iterator, uint64_t *actual_block) {

  if (!iterator || !actual_block || iterator->width == 0) {
    return false;
  }
  if (iterator->next_actual > iterator->last_actual) {
    return false;
  }
  *actual_block = iterator->next_actual;
  if (iterator->next_actual == UINT64_MAX) {
    iterator->width = 0;
  }
  else {
    iterator->next_actual++;
  }
  return true;
}

// Compare the byte distributions at both ends of a proposed run with the
// logical blocks that surround its destination. This ranks opaque payload
// alternatives by local continuity without treating that evidence as proof.
//
static inline uint64_t cfbf_reassembly_context_distance(
    BlockVector *blockvector, const int64_t *mapping,
    uint64_t target_slot, uint64_t run_blocks, int64_t source_actual) {

  if (!blockvector || run_blocks == 0 || source_actual < 0) {
    return UINT64_MAX;
  }
  const uint64_t total_blocks = blockvector_get_num_blocks(blockvector);
  uint64_t distance = 0;
  uint64_t measured = 0;

  for (uint32_t side = 0; side < 2; side++) {
    uint64_t neighbor_slot = 0;
    int64_t source_block = source_actual;

    if (side == 0) {
      if (target_slot == 0) {
        continue;
      }
      neighbor_slot = target_slot - 1;
    }
    else {
      if (target_slot + run_blocks >= total_blocks) {
        continue;
      }
      neighbor_slot = target_slot + run_blocks;
      source_block += (int64_t)run_blocks - 1;
    }
    const int64_t neighbor_apparent = mapping
        ? mapping[neighbor_slot]
        : blockvector_get_apparent_blocknumber(blockvector, neighbor_slot);

    if (neighbor_apparent < 0) {
      continue;
    }
    const int64_t neighbor_actual = filemirror_actual_blocknumber(
        scalpel_state.filemirror, neighbor_apparent);
    uint64_t source_length = 0;
    uint64_t neighbor_length = 0;
    const uint8_t *source = (const uint8_t *)
        filemirror_actual_block_data_pointer(
            scalpel_state.filemirror, source_block, &source_length);
    const uint8_t *neighbor = (const uint8_t *)
        filemirror_actual_block_data_pointer(
            scalpel_state.filemirror, neighbor_actual, &neighbor_length);

    if (!source || !neighbor || source_length == 0 || neighbor_length == 0) {
      continue;
    }
    uint64_t source_counts[256] = { 0 };
    uint64_t neighbor_counts[256] = { 0 };

    for (uint64_t offset = 0; offset < source_length; offset++) {
      source_counts[source[offset]]++;
    }
    for (uint64_t offset = 0; offset < neighbor_length; offset++) {
      neighbor_counts[neighbor[offset]]++;
    }
    uint64_t side_distance = 0;

    for (uint32_t value = 0; value < 256; value++) {
      const uint64_t source_frequency =
          source_counts[value] * UINT64_C(65536) / source_length;
      const uint64_t neighbor_frequency =
          neighbor_counts[value] * UINT64_C(65536) / neighbor_length;

      side_distance += source_frequency > neighbor_frequency
          ? source_frequency - neighbor_frequency
          : neighbor_frequency - source_frequency;
    }
    distance += side_distance;
    measured++;
  }
  return measured == 0 ? UINT64_MAX : distance / measured;
}

// Return the compact byte-distribution fingerprint populated with the shared
// concentration cache. Large images fall back to direct measurement rather
// than making this ordering optimization consume unbounded memory.
//
static inline bool cfbf_reassembly_context_fingerprint(
    int64_t actual_block,
    uint8_t fingerprint[CFBF_CONTEXT_FINGERPRINT_BINS]) {

  if (actual_block < 0 || !fingerprint) {
    return false;
  }
  (void)cfbf_reassembly_block_is_uniform(actual_block);
  if (cfbf_context_fingerprint_cache
      && (uint64_t)actual_block < cfbf_uniform_cache_blocks) {
    memcpy(fingerprint,
           cfbf_context_fingerprint_cache
               + (size_t)actual_block * CFBF_CONTEXT_FINGERPRINT_BINS,
           CFBF_CONTEXT_FINGERPRINT_BINS);
    uint32_t total = 0;

    for (uint32_t bin = 0;
         bin < CFBF_CONTEXT_FINGERPRINT_BINS; bin++) {
      total += fingerprint[bin];
    }
    if (total != 0) {
      return true;
    }
  }
  uint64_t concentration = 0;

  return cfbf_reassembly_measure_block(
      actual_block, &concentration, fingerprint);
}

// Approximate the full byte-distribution seam score with cached fingerprints.
// This is used only to order trials; the exact score and complete validators
// still rank and accept the materialized mappings.
//
static inline uint64_t cfbf_reassembly_context_sketch_distance(
    BlockVector *blockvector, const int64_t *mapping,
    uint64_t target_slot, uint64_t run_blocks, int64_t source_actual) {

  if (!blockvector || run_blocks == 0 || source_actual < 0) {
    return UINT64_MAX;
  }
  const uint64_t total_blocks = blockvector_get_num_blocks(blockvector);
  uint64_t distance = 0;
  uint64_t measured = 0;

  for (uint32_t side = 0; side < 2; side++) {
    uint64_t neighbor_slot = 0;
    int64_t source_block = source_actual;

    if (side == 0) {
      if (target_slot == 0) {
        continue;
      }
      neighbor_slot = target_slot - 1;
    }
    else {
      if (target_slot + run_blocks >= total_blocks) {
        continue;
      }
      neighbor_slot = target_slot + run_blocks;
      source_block += (int64_t)run_blocks - 1;
    }
    const int64_t neighbor_apparent = mapping
        ? mapping[neighbor_slot]
        : blockvector_get_apparent_blocknumber(blockvector, neighbor_slot);

    if (neighbor_apparent < 0) {
      continue;
    }
    const int64_t neighbor_actual = filemirror_actual_blocknumber(
        scalpel_state.filemirror, neighbor_apparent);
    uint8_t source_fingerprint[CFBF_CONTEXT_FINGERPRINT_BINS];
    uint8_t neighbor_fingerprint[CFBF_CONTEXT_FINGERPRINT_BINS];

    if (!cfbf_reassembly_context_fingerprint(
            source_block, source_fingerprint)
        || !cfbf_reassembly_context_fingerprint(
               neighbor_actual, neighbor_fingerprint)) {
      continue;
    }
    for (uint32_t bin = 0;
         bin < CFBF_CONTEXT_FINGERPRINT_BINS; bin++) {
      distance += source_fingerprint[bin] > neighbor_fingerprint[bin]
          ? source_fingerprint[bin] - neighbor_fingerprint[bin]
          : neighbor_fingerprint[bin] - source_fingerprint[bin];
    }
    measured++;
  }
  return measured == 0 ? UINT64_MAX : distance / measured;
}

// Compare source hypotheses for one of four independent ordering views:
// subtype confidence, generic legacy Office confidence, local continuity, or
// source isolation. Keeping separate views prevents one weak signal from
// burying a strong one.
//
static inline bool cfbf_reassembly_ranked_source_is_better(
    const CfbfRankedSource *candidate, const CfbfRankedSource *retained,
    uint32_t rank_mode) {

  if (!candidate) {
    return false;
  }
  if (!retained) {
    return true;
  }
  if (rank_mode == 0) {
    if (candidate->profile_all_positive
        != retained->profile_all_positive) {
      return candidate->profile_all_positive
             > retained->profile_all_positive;
    }
    if (candidate->profile_boundary_gain
        != retained->profile_boundary_gain) {
      return candidate->profile_boundary_gain
             > retained->profile_boundary_gain;
    }
    if (candidate->profile_gain != retained->profile_gain) {
      return candidate->profile_gain > retained->profile_gain;
    }
  }
  else if (rank_mode == 1) {
    if (candidate->generic_all_positive
        != retained->generic_all_positive) {
      return candidate->generic_all_positive
             > retained->generic_all_positive;
    }
    if (candidate->generic_boundary_gain
        != retained->generic_boundary_gain) {
      return candidate->generic_boundary_gain
             > retained->generic_boundary_gain;
    }
    if (candidate->generic_gain != retained->generic_gain) {
      return candidate->generic_gain > retained->generic_gain;
    }
  }
  if (rank_mode == 3
      && candidate->source_isolation != retained->source_isolation) {
    return candidate->source_isolation > retained->source_isolation;
  }
  if (candidate->context_distance != retained->context_distance) {
    return candidate->context_distance < retained->context_distance;
  }
  if (candidate->reserved != retained->reserved) {
    return candidate->reserved < retained->reserved;
  }
  if (rank_mode != 1
      && candidate->generic_all_positive
         != retained->generic_all_positive) {
    return candidate->generic_all_positive
           > retained->generic_all_positive;
  }
  if (rank_mode != 1
      && candidate->generic_gain != retained->generic_gain) {
    return candidate->generic_gain > retained->generic_gain;
  }
  if (rank_mode != 0
      && candidate->profile_all_positive
         != retained->profile_all_positive) {
    return candidate->profile_all_positive
           > retained->profile_all_positive;
  }
  if (rank_mode != 0
      && candidate->profile_gain != retained->profile_gain) {
    return candidate->profile_gain > retained->profile_gain;
  }
  return candidate->actual < retained->actual;
}

// Retain the strongest fixed-size prefix for one ordering view.
//
static inline void cfbf_reassembly_retain_ranked_source(
    CfbfRankedSource *sources, uint32_t *count, uint32_t limit,
    const CfbfRankedSource *candidate, uint32_t rank_mode) {

  if (!sources || !count || !candidate || limit == 0) {
    return;
  }
  uint32_t position = *count;

  if (position < limit) {
    (*count)++;
  }
  else {
    if (!cfbf_reassembly_ranked_source_is_better(
            candidate, &sources[limit - 1], rank_mode)) {
      return;
    }
    position = limit - 1;
  }
  while (position > 0
         && cfbf_reassembly_ranked_source_is_better(
                candidate, &sources[position - 1], rank_mode)) {
    sources[position] = sources[position - 1];
    position--;
  }
  sources[position] = *candidate;
}

// Build a bounded union of the strongest source runs under independent model
// and continuity orderings. This changes only time-to-trial: sources outside
// the union remain reachable through the existing exhaustive traversal.
//
static inline uint32_t cfbf_reassembly_collect_ranked_sources(
    BlockVector *blockvector, const int64_t *mapping,
    uint64_t target_slot, uint64_t run_blocks, CfbfProfile profile,
    CfbfRankedSource *sources, uint32_t capacity) {

  if (!blockvector || !sources || run_blocks == 0
      || run_blocks > CFBF_NEARBY_RUN_WIDTH_LIMIT
      || capacity < CFBF_RANKED_SOURCE_LIMIT) {
    return 0;
  }
  const uint64_t image_blocks = CEILDIV(
      filemirror_filesize(scalpel_state.filemirror), scalpel_state.blocksize);

  if (run_blocks > image_blocks) {
    return 0;
  }
  CfbfRankedSource profile_sources[CFBF_RANKED_SOURCE_LIMIT];
  CfbfRankedSource generic_sources[CFBF_RANKED_SOURCE_LIMIT];
  CfbfRankedSource context_sources[CFBF_RANKED_SOURCE_LIMIT];
  CfbfRankedSource isolated_sources[CFBF_RANKED_SOURCE_LIMIT];
  uint32_t profile_count = 0;
  uint32_t generic_count = 0;
  uint32_t context_count = 0;
  uint32_t isolated_count = 0;
  const int32_t profile_spec = cfbf_reassembly_confidence_spec(profile);
  const int32_t office_specs[3] = {
    cfbf_reassembly_confidence_spec(CFBF_PROFILE_DOC),
    cfbf_reassembly_confidence_spec(CFBF_PROFILE_XLS),
    cfbf_reassembly_confidence_spec(CFBF_PROFILE_PPT)
  };
  uint32_t office_count = 0;

  for (uint32_t index = 0; index < 3; index++) {
    if (office_specs[index] >= 0) {
      office_count++;
    }
  }

  for (uint64_t actual = 0;
       actual <= image_blocks - run_blocks; actual++) {
    if (!cfbf_reassembly_run_source_available(
            blockvector, run_blocks, (int64_t)actual)) {
      continue;
    }
    CfbfRankedSource source;

    memset(&source, 0, sizeof(source));
    source.actual = actual;
    source.source_isolation = cfbf_reassembly_source_run_isolation(
        (int64_t)actual, run_blocks, NULL);
    source.context_distance = cfbf_reassembly_context_sketch_distance(
        blockvector, mapping, target_slot, run_blocks, (int64_t)actual);

    bool has_profile_confidence = false;
    bool profile_all_positive = false;
    uint32_t minimum_profile_confidence = 0;

    cfbf_reassembly_run_metrics(
        blockvector, mapping, target_slot, run_blocks, (int64_t)actual,
        profile, &has_profile_confidence, &profile_all_positive,
        &source.profile_gain, &source.reserved,
        &minimum_profile_confidence);
    source.profile_all_positive = profile_all_positive ? 1 : 0;

    if (profile_spec >= 0) {
      uint32_t outside = 0;

      if (actual > 0) {
        outside = filemirror_get_blocktype(
            scalpel_state.filemirror, (int64_t)actual - 1,
            (uint32_t)profile_spec);
      }
      if (actual + run_blocks < image_blocks) {
        const uint32_t right = filemirror_get_blocktype(
            scalpel_state.filemirror, (int64_t)(actual + run_blocks),
            (uint32_t)profile_spec);

        if (right > outside) {
          outside = right;
        }
      }
      source.profile_boundary_gain = minimum_profile_confidence > outside
          ? minimum_profile_confidence - outside : 0;
    }

    if (office_count > 0) {
      bool generic_all_positive = true;
      uint32_t minimum_generic_confidence = UINT32_MAX;

      for (uint64_t block = 0; block < run_blocks; block++) {
        const int64_t destination_apparent = mapping
            ? mapping[target_slot + block]
            : blockvector_get_apparent_blocknumber(
                  blockvector, target_slot + block);
        const int64_t destination = destination_apparent >= 0
            ? filemirror_actual_blocknumber(
                  scalpel_state.filemirror, destination_apparent)
            : -1;
        uint32_t source_max = 0;
        uint32_t destination_max = 0;

        for (uint32_t index = 0; index < 3; index++) {
          if (office_specs[index] < 0) {
            continue;
          }
          const uint32_t source_value = filemirror_get_blocktype(
              scalpel_state.filemirror, (int64_t)(actual + block),
              (uint32_t)office_specs[index]);
          const uint32_t destination_value = destination >= 0
              ? filemirror_get_blocktype(
                    scalpel_state.filemirror, destination,
                    (uint32_t)office_specs[index])
              : BLOCK_CONFIDENCE_INVALID;

          if (source_value > source_max) {
            source_max = source_value;
          }
          if (destination_value > destination_max) {
            destination_max = destination_value;
          }
        }
        source.generic_gain += (int64_t)source_max
                               - (int64_t)destination_max;
        if (source_max < minimum_generic_confidence) {
          minimum_generic_confidence = source_max;
        }
        if (source_max <= destination_max) {
          generic_all_positive = false;
        }
      }
      source.generic_all_positive = generic_all_positive ? 1 : 0;
      uint32_t outside = 0;

      for (uint32_t index = 0; index < 3; index++) {
        if (office_specs[index] < 0) {
          continue;
        }
        if (actual > 0) {
          const uint32_t left = filemirror_get_blocktype(
              scalpel_state.filemirror, (int64_t)actual - 1,
              (uint32_t)office_specs[index]);

          if (left > outside) {
            outside = left;
          }
        }
        if (actual + run_blocks < image_blocks) {
          const uint32_t right = filemirror_get_blocktype(
              scalpel_state.filemirror, (int64_t)(actual + run_blocks),
              (uint32_t)office_specs[index]);

          if (right > outside) {
            outside = right;
          }
        }
      }
      source.generic_boundary_gain = minimum_generic_confidence > outside
          ? minimum_generic_confidence - outside : 0;
    }
    if (profile_spec >= 0 && has_profile_confidence) {
      cfbf_reassembly_retain_ranked_source(
          profile_sources, &profile_count, CFBF_RANKED_SOURCE_LIMIT,
          &source, 0);
    }
    if (office_count > 0) {
      cfbf_reassembly_retain_ranked_source(
          generic_sources, &generic_count, CFBF_RANKED_SOURCE_LIMIT,
          &source, 1);
    }
    cfbf_reassembly_retain_ranked_source(
        context_sources, &context_count, CFBF_RANKED_SOURCE_LIMIT,
        &source, 2);
    if (source.source_isolation != 0) {
      cfbf_reassembly_retain_ranked_source(
          isolated_sources, &isolated_count, CFBF_RANKED_SOURCE_LIMIT,
          &source, 3);
    }
  }

  uint32_t output_count = 0;
  const CfbfRankedSource *ordered[4];
  const uint32_t counts[4] = {
    profile_spec >= 0 ? profile_count : context_count,
    generic_count,
    profile_spec >= 0 ? context_count : profile_count,
    isolated_count
  };

  ordered[0] = profile_spec >= 0 ? profile_sources : context_sources;
  ordered[1] = generic_sources;
  ordered[2] = profile_spec >= 0 ? context_sources : profile_sources;
  ordered[3] = isolated_sources;

  uint32_t positions[4] = {0, 0, 0, 0};

  while (output_count < capacity) {
    bool consumed = false;

    for (uint32_t group = 0; group < 4 && output_count < capacity; group++) {
      while (positions[group] < counts[group]) {
        const CfbfRankedSource *candidate =
            &ordered[group][positions[group]++];
        bool duplicate = false;

        consumed = true;
        for (uint32_t prior = 0; prior < output_count; prior++) {
          if (sources[prior].actual == candidate->actual) {
            duplicate = true;
            break;
          }
        }
        if (!duplicate) {
          sources[output_count++] = *candidate;
          break;
        }
      }
    }
    if (!consumed) {
      break;
    }
  }
  return output_count;
}

// Compare coherence only when both mappings expose the same evidence. Counts
// or extents that differ can describe different opaque structures, so neither
// is treated as intrinsically better.
//
static inline int32_t cfbf_reassembly_compare_coherence(
    uint32_t candidate_payloads, uint64_t candidate_cost,
    uint64_t candidate_extent, uint32_t retained_payloads,
    uint64_t retained_cost, uint64_t retained_extent) {

  const bool candidate_has_evidence = candidate_payloads != 0
                                      && candidate_extent != 0;
  const bool retained_has_evidence = retained_payloads != 0
                                     && retained_extent != 0;

  if (candidate_has_evidence != retained_has_evidence) {
    return candidate_has_evidence ? 1 : -1;
  }
  if (!candidate_has_evidence) {
    return 0;
  }
  if (candidate_payloads != retained_payloads
      || candidate_extent != retained_extent) {
    return 0;
  }
  if (candidate_cost != retained_cost) {
    return candidate_cost < retained_cost ? 1 : -1;
  }
  return 0;
}

// Compare complete repair hypotheses without making any evidence source an
// exclusion rule. The ordering is also used for the bounded multi-block
// alternative retained for opaque file content.
//
static inline bool cfbf_reassembly_repair_is_better(
    const CfbfRepairCandidate *candidate,
    const CfbfRepairCandidate *retained) {

  if (!candidate || candidate->valid == 0) {
    return false;
  }
  if (!retained || retained->valid == 0) {
    return true;
  }
  if (candidate->authenticated != retained->authenticated) {
    return candidate->authenticated != 0;
  }
  if (candidate->complete != retained->complete) {
    return candidate->complete != 0;
  }
  if (candidate->semantic_strength != retained->semantic_strength) {
    return candidate->semantic_strength > retained->semantic_strength;
  }
  if (candidate->profile_evidence != retained->profile_evidence) {
    return candidate->profile_evidence != 0;
  }
  if (candidate->score != retained->score) {
    return candidate->score > retained->score;
  }
  const int32_t coherence_order = cfbf_reassembly_compare_coherence(
      candidate->coherence_payloads, candidate->coherence_cost,
      candidate->coherence_extent, retained->coherence_payloads,
      retained->coherence_cost, retained->coherence_extent);

  if (coherence_order != 0) {
    return coherence_order > 0;
  }
  if (candidate->target_strong != retained->target_strong) {
    return candidate->target_strong != 0;
  }
  if (candidate->target_exact != retained->target_exact) {
    return candidate->target_exact != 0;
  }
  if (candidate->target_concentration != retained->target_concentration) {
    return candidate->target_concentration
           < retained->target_concentration;
  }
  if (candidate->has_confidence != retained->has_confidence) {
    return candidate->has_confidence != 0;
  }
  if (candidate->has_confidence != 0
      && candidate->all_positive != retained->all_positive) {
    return candidate->all_positive != 0;
  }
  if (candidate->has_confidence != 0
      && candidate->confidence_gain != retained->confidence_gain) {
    return candidate->confidence_gain > retained->confidence_gain;
  }
  if (candidate->context_distance != retained->context_distance) {
    return candidate->context_distance < retained->context_distance;
  }
  if (candidate->reserved != retained->reserved) {
    return candidate->reserved < retained->reserved;
  }
  if (candidate->source_evidence != retained->source_evidence) {
    return candidate->source_evidence > retained->source_evidence;
  }
  const uint64_t candidate_width_rank = candidate->width == 2
      ? 0 : (candidate->width == 1 ? 1 : candidate->width);
  const uint64_t retained_width_rank = retained->width == 2
      ? 0 : (retained->width == 1 ? 1 : retained->width);

  return candidate_width_rank < retained_width_rank;
}

// Order detached source runs with clean filler boundaries. Parser and physical
// evidence precede learned confidence because a classifier is a search hint,
// not an authentication mechanism for opaque stream payloads.
//
static inline bool cfbf_reassembly_isolated_repair_is_better(
    const CfbfRepairCandidate *candidate,
    const CfbfRepairCandidate *retained) {

  if (!candidate || candidate->valid == 0
      || candidate->source_isolation
             < CFBF_DETACHED_SOURCE_ISOLATED_MIN) {
    return false;
  }
  if (!retained || retained->valid == 0
      || retained->source_isolation
             < CFBF_DETACHED_SOURCE_ISOLATED_MIN) {
    return true;
  }
  if (candidate->authenticated != retained->authenticated) {
    return candidate->authenticated != 0;
  }
  if (candidate->complete != retained->complete) {
    return candidate->complete != 0;
  }
  if (candidate->semantic_strength != retained->semantic_strength) {
    return candidate->semantic_strength > retained->semantic_strength;
  }
  if (candidate->profile_evidence != retained->profile_evidence) {
    return candidate->profile_evidence != 0;
  }
  if (candidate->score != retained->score) {
    return candidate->score > retained->score;
  }
  const int32_t coherence_order = cfbf_reassembly_compare_coherence(
      candidate->coherence_payloads, candidate->coherence_cost,
      candidate->coherence_extent, retained->coherence_payloads,
      retained->coherence_cost, retained->coherence_extent);

  if (coherence_order != 0) {
    return coherence_order > 0;
  }
  if (candidate->target_exact != retained->target_exact) {
    return candidate->target_exact != 0;
  }
  if (candidate->target_strong != retained->target_strong) {
    return candidate->target_strong != 0;
  }
  if (candidate->target_concentration != retained->target_concentration) {
    return candidate->target_concentration
           < retained->target_concentration;
  }
  if (candidate->source_isolation != retained->source_isolation) {
    return candidate->source_isolation > retained->source_isolation;
  }
  if (candidate->reserved != retained->reserved) {
    return candidate->reserved < retained->reserved;
  }
  if (candidate->context_distance != retained->context_distance) {
    return candidate->context_distance < retained->context_distance;
  }
  if (candidate->source_evidence != retained->source_evidence) {
    return candidate->source_evidence > retained->source_evidence;
  }
  const uint64_t candidate_width_rank = candidate->width == 2
      ? 0 : (candidate->width == 1 ? 1 : candidate->width);
  const uint64_t retained_width_rank = retained->width == 2
      ? 0 : (retained->width == 1 ? 1 : retained->width);

  if (candidate_width_rank != retained_width_rank) {
    return candidate_width_rank < retained_width_rank;
  }
  if (candidate->has_confidence != retained->has_confidence) {
    return candidate->has_confidence != 0;
  }
  if (candidate->has_confidence != 0
      && candidate->all_positive != retained->all_positive) {
    return candidate->all_positive != 0;
  }
  if (candidate->has_confidence != 0
      && candidate->confidence_gain != retained->confidence_gain) {
    return candidate->confidence_gain > retained->confidence_gain;
  }
  return candidate->actual < retained->actual;
}

// Preserve the strongest independent Project payload interpretation. Project
// exposes order-sensitive companion streams that can distinguish otherwise
// equivalent compound-file mappings.
//
static inline bool cfbf_reassembly_semantic_repair_is_better(
    const CfbfRepairCandidate *candidate,
    const CfbfRepairCandidate *retained) {

  if (!candidate || candidate->valid == 0
      || candidate->profile != CFBF_PROFILE_MPP
      || candidate->coherence_payloads == 0
      || candidate->coherence_extent == 0) {
    return false;
  }
  if (!retained || retained->valid == 0) {
    return true;
  }
  if (candidate->authenticated != retained->authenticated) {
    return candidate->authenticated != 0;
  }
  if (candidate->complete != retained->complete) {
    return candidate->complete != 0;
  }
  if (candidate->semantic_strength != retained->semantic_strength) {
    return candidate->semantic_strength > retained->semantic_strength;
  }
  if (candidate->profile_evidence != retained->profile_evidence) {
    return candidate->profile_evidence != 0;
  }
  if (candidate->coherence_payloads != retained->coherence_payloads) {
    return candidate->coherence_payloads > retained->coherence_payloads;
  }
  if (candidate->coherence_extent != retained->coherence_extent) {
    return candidate->coherence_extent > retained->coherence_extent;
  }
  if (candidate->score != retained->score) {
    return candidate->score > retained->score;
  }
  if (candidate->target_exact != retained->target_exact) {
    return candidate->target_exact != 0;
  }
  if (candidate->target_strong != retained->target_strong) {
    return candidate->target_strong != 0;
  }
  if (candidate->reserved != retained->reserved) {
    return candidate->reserved < retained->reserved;
  }
  if (candidate->context_distance != retained->context_distance) {
    return candidate->context_distance < retained->context_distance;
  }
  if (candidate->source_evidence != retained->source_evidence) {
    return candidate->source_evidence > retained->source_evidence;
  }
  if (candidate->source_isolation != retained->source_isolation) {
    return candidate->source_isolation > retained->source_isolation;
  }
  if (candidate->has_confidence != retained->has_confidence) {
    return candidate->has_confidence != 0;
  }
  if (candidate->has_confidence != 0
      && candidate->all_positive != retained->all_positive) {
    return candidate->all_positive != 0;
  }
  if (candidate->has_confidence != 0
      && candidate->confidence_gain != retained->confidence_gain) {
    return candidate->confidence_gain > retained->confidence_gain;
  }
  return candidate->actual < retained->actual;
}

// Clear all restartable repair hypotheses before beginning a new search.
//
static inline void cfbf_reassembly_reset_repair_candidates(
    CfbfCarveState *state) {

  if (!state) {
    return;
  }
  state->repair_candidate_valid = 0;
  state->repair_candidate_authenticated = 0;
  state->repair_candidate_complete = 0;
  state->repair_candidate_profile = CFBF_PROFILE_UNKNOWN;
  state->repair_candidate_profile_evidence = 0;
  state->repair_candidate_semantic_strength = 0;
  state->repair_candidate_coherence_payloads = 0;
  state->repair_candidate_has_confidence = 0;
  state->repair_candidate_all_positive = 0;
  state->repair_candidate_target_strong = 0;
  state->repair_candidate_target_exact = 0;
  state->repair_candidate_source_isolation = 0;
  state->repair_candidate_reserved = 0;
  state->repair_candidate_slot = 0;
  state->repair_candidate_width = 0;
  state->repair_candidate_actual = 0;
  state->repair_candidate_score = 0;
  state->repair_candidate_coherence_cost = 0;
  state->repair_candidate_coherence_extent = 0;
  state->repair_candidate_context_distance = UINT64_MAX;
  state->repair_candidate_target_concentration = UINT64_MAX;
  state->repair_candidate_source_evidence = 0;
  state->repair_candidate_confidence_gain = 0;
  memset(&state->repair_alternate, 0, sizeof(state->repair_alternate));
  state->repair_alternate.context_distance = UINT64_MAX;
  state->repair_alternate.target_concentration = UINT64_MAX;
  memset(&state->repair_semantic, 0, sizeof(state->repair_semantic));
  state->repair_semantic.context_distance = UINT64_MAX;
  state->repair_semantic.target_concentration = UINT64_MAX;
  memset(state->repair_isolated, 0, sizeof(state->repair_isolated));
  for (uint32_t index = 0;
       index < CFBF_ISOLATED_HYPOTHESIS_LIMIT; index++) {
    state->repair_isolated[index].context_distance = UINT64_MAX;
    state->repair_isolated[index].target_concentration = UINT64_MAX;
  }
}

// Clear the restartable nested-loop cursor and retained atomic GAP+OOO result.
//
static inline void cfbf_reassembly_reset_atomic_search(
    CfbfCarveState *state) {

  if (!state) {
    return;
  }
  state->atomic_resume_valid = 0;
  state->atomic_search_pass = 0;
  state->atomic_suffix_slot = 0;
  state->atomic_shift = 0;
  state->atomic_width_order = 0;
  state->atomic_target_slot = 0;
  state->atomic_source_actual = 0;
  memset(&state->atomic_candidate, 0, sizeof(state->atomic_candidate));
  memset(state->atomic_width_candidates, 0,
         sizeof(state->atomic_width_candidates));
  memset(state->atomic_width_ranks, 0,
         sizeof(state->atomic_width_ranks));
  for (uint32_t index = 0;
       index < CFBF_NEARBY_RUN_WIDTH_LIMIT; index++) {
    state->atomic_width_ranks[index].context_distance = UINT64_MAX;
    state->atomic_width_ranks[index].target_concentration = UINT64_MAX;
  }
}

// Retain the best complete hypothesis, the strongest multi-block repair, and
// the strongest detached-source repair in restartable state. A complete
// displaced run is a distinct fragmentation model that must not be discarded
// merely because an opaque one-block repair has a stronger local rank.
//
static inline void cfbf_reassembly_remember_repair(
    CfbfCarveState *state, BlockVector *blockvector,
    uint64_t target_slot, uint64_t run_blocks, uint64_t source_actual,
    const CfbfTrialResult *result,
    bool has_confidence, bool all_positive,
    bool target_strong, bool target_exact,
    int64_t confidence_gain, uint32_t reserved,
    uint64_t context_distance,
    uint64_t target_concentration, uint64_t source_concentration) {

  if (!state || !blockvector || !result || run_blocks == 0) {
    return;
  }
  uint64_t source_evidence = 0;
  bool source_eligible = false;
  uint32_t source_isolation = cfbf_reassembly_source_run_isolation(
      (int64_t)source_actual, run_blocks, &source_eligible);
  bool source_detached = true;

  for (uint64_t block = 0; block < run_blocks; block++) {
    if (cfbf_reassembly_find_actual_slot(
            blockvector, (int64_t)(source_actual + block)) >= 0) {
      source_detached = false;
      break;
    }
  }
  if (source_detached && source_eligible) {
    source_isolation++;
  }
  else {
    source_isolation = CFBF_DETACHED_SOURCE_NONE;
  }

  if (target_concentration != UINT64_MAX
      && source_concentration != UINT64_MAX
      && source_concentration > target_concentration) {
    const uint64_t difference = source_concentration
                                - target_concentration;

    source_evidence = difference > UINT64_MAX / run_blocks
        ? UINT64_MAX : difference * run_blocks;
  }
  CfbfRepairCandidate candidate = {
    .valid = 1,
    .authenticated = cfbf_reassembly_trial_authenticated(result) ? 1 : 0,
    .complete = cfbf_reassembly_trial_complete(result) ? 1 : 0,
    .profile = (uint32_t)result->profile,
    .profile_evidence = result->profile_evidence ? 1 : 0,
    .semantic_strength = (uint32_t)result->semantic_strength,
    .coherence_payloads = result->coherence_payloads,
    .has_confidence = has_confidence ? 1 : 0,
    .all_positive = all_positive ? 1 : 0,
    .target_strong = target_strong ? 1 : 0,
    .target_exact = target_exact ? 1 : 0,
    .source_isolation = source_isolation,
    .reserved = reserved,
    .slot = target_slot,
    .width = run_blocks,
    .actual = source_actual,
    .score = result->score,
    .coherence_cost = result->coherence_cost,
    .coherence_extent = result->coherence_extent,
    .context_distance = context_distance,
    .target_concentration = target_concentration,
    .source_evidence = source_evidence,
    .confidence_gain = confidence_gain
  };
  CfbfRepairCandidate primary = {
    .valid = state->repair_candidate_valid,
    .authenticated = state->repair_candidate_authenticated,
    .complete = state->repair_candidate_complete,
    .profile = state->repair_candidate_profile,
    .profile_evidence = state->repair_candidate_profile_evidence,
    .semantic_strength = state->repair_candidate_semantic_strength,
    .coherence_payloads = state->repair_candidate_coherence_payloads,
    .has_confidence = state->repair_candidate_has_confidence,
    .all_positive = state->repair_candidate_all_positive,
    .target_strong = state->repair_candidate_target_strong,
    .target_exact = state->repair_candidate_target_exact,
    .source_isolation = state->repair_candidate_source_isolation,
    .reserved = state->repair_candidate_reserved,
    .slot = state->repair_candidate_slot,
    .width = state->repair_candidate_width,
    .actual = state->repair_candidate_actual,
    .score = state->repair_candidate_score,
    .coherence_cost = state->repair_candidate_coherence_cost,
    .coherence_extent = state->repair_candidate_coherence_extent,
    .context_distance = state->repair_candidate_context_distance,
    .target_concentration = state->repair_candidate_target_concentration,
    .source_evidence = state->repair_candidate_source_evidence,
    .confidence_gain = state->repair_candidate_confidence_gain
  };
  const bool candidate_weak_boundary =
      cfbf_reassembly_trial_recoverable(result)
      && candidate.source_isolation
             == CFBF_DETACHED_SOURCE_WEAK_BOUNDARY;
  const bool alternate_weak_boundary = state->repair_alternate.valid != 0
      && state->repair_alternate.source_isolation
             == CFBF_DETACHED_SOURCE_WEAK_BOUNDARY;

  if (cfbf_reassembly_semantic_repair_is_better(
          &candidate, &state->repair_semantic)) {
    state->repair_semantic = candidate;
  }

  if ((candidate.width >= 2 || candidate_weak_boundary)
      && ((candidate_weak_boundary && !alternate_weak_boundary)
          || (candidate_weak_boundary == alternate_weak_boundary
              && cfbf_reassembly_repair_is_better(
                     &candidate, &state->repair_alternate)))) {
    state->repair_alternate = candidate;
    if (scalpel_state.mode_verbose) {
      lock_fprintf(
          stdout,
          "CFBF multi-block repair rank: header=%" PRId64
          " slot=%" PRIu64
          " width=%" PRIu64 " source=%" PRIu64
          " profile=%s score=%" PRIu64 ".\n",
          blockvector_get_actual_blocknumber(blockvector, 0),
          target_slot, run_blocks, source_actual,
          cfbf_profile_filetype(result->profile), result->score);
    }
  }
  if (candidate.source_isolation >= CFBF_DETACHED_SOURCE_ISOLATED_MIN
      && (candidate.width >= 2 || candidate.complete != 0)) {
    uint32_t retained_count = 0;
    uint32_t same_hypothesis = CFBF_ISOLATED_HYPOTHESIS_LIMIT;

    while (retained_count < CFBF_ISOLATED_HYPOTHESIS_LIMIT
           && state->repair_isolated[retained_count].valid != 0) {
      if (state->repair_isolated[retained_count].slot == candidate.slot
          && state->repair_isolated[retained_count].width
                 == candidate.width
          && state->repair_isolated[retained_count].actual
                 == candidate.actual) {
        same_hypothesis = retained_count;
      }
      retained_count++;
    }
    bool retain = true;

    if (same_hypothesis < retained_count) {
      retain = cfbf_reassembly_isolated_repair_is_better(
          &candidate, &state->repair_isolated[same_hypothesis]);
      if (retain) {
        for (uint32_t index = same_hypothesis;
             index + 1 < retained_count; index++) {
          state->repair_isolated[index] =
              state->repair_isolated[index + 1];
        }
        retained_count--;
        memset(&state->repair_isolated[retained_count], 0,
               sizeof(state->repair_isolated[retained_count]));
      }
    }
    if (retain) {
      uint32_t target_count = 0;
      uint32_t weakest_target = CFBF_ISOLATED_HYPOTHESIS_LIMIT;

      for (uint32_t index = 0; index < retained_count; index++) {
        if (state->repair_isolated[index].slot == candidate.slot
            && state->repair_isolated[index].width == candidate.width) {
          target_count++;
          weakest_target = index;
        }
      }
      if (target_count >= CFBF_ISOLATED_TARGET_HYPOTHESIS_LIMIT) {
        retain = weakest_target < retained_count
            && cfbf_reassembly_isolated_repair_is_better(
                   &candidate, &state->repair_isolated[weakest_target]);
        if (retain) {
          for (uint32_t index = weakest_target;
               index + 1 < retained_count; index++) {
            state->repair_isolated[index] =
                state->repair_isolated[index + 1];
          }
          retained_count--;
          memset(&state->repair_isolated[retained_count], 0,
                 sizeof(state->repair_isolated[retained_count]));
        }
      }
    }
    if (retain) {
      uint32_t single_count = 0;
      uint32_t weakest_single = CFBF_ISOLATED_HYPOTHESIS_LIMIT;

      for (uint32_t index = 0; index < retained_count; index++) {
        if (state->repair_isolated[index].width == 1) {
          single_count++;
          weakest_single = index;
        }
      }
      const bool candidate_single = candidate.width == 1;
      const bool retained_multi = single_count < retained_count;
      bool replace_single = false;

      if (candidate_single && retained_multi
          && single_count >= CFBF_ISOLATED_SINGLE_HYPOTHESIS_LIMIT) {
        replace_single = weakest_single < retained_count
            && cfbf_reassembly_isolated_repair_is_better(
                   &candidate, &state->repair_isolated[weakest_single]);
        retain = replace_single;
      }
      else if (!candidate_single
               && retained_count == CFBF_ISOLATED_HYPOTHESIS_LIMIT
               && single_count
                      > CFBF_ISOLATED_SINGLE_HYPOTHESIS_LIMIT) {
        replace_single = weakest_single < retained_count;
      }
      if (retain && replace_single) {
        for (uint32_t index = weakest_single;
             index + 1 < retained_count; index++) {
          state->repair_isolated[index] =
              state->repair_isolated[index + 1];
        }
        retained_count--;
        memset(&state->repair_isolated[retained_count], 0,
               sizeof(state->repair_isolated[retained_count]));
      }
    }
    if (retain) {
      uint32_t position = 0;

      while (position < retained_count
             && !cfbf_reassembly_isolated_repair_is_better(
                    &candidate, &state->repair_isolated[position])) {
        position++;
      }
      if (position < CFBF_ISOLATED_HYPOTHESIS_LIMIT) {
        uint32_t move = retained_count < CFBF_ISOLATED_HYPOTHESIS_LIMIT
            ? retained_count : CFBF_ISOLATED_HYPOTHESIS_LIMIT - 1;

        while (move > position) {
          state->repair_isolated[move] =
              state->repair_isolated[move - 1];
          move--;
        }
        state->repair_isolated[position] = candidate;
      }
    }
  }

  if (cfbf_reassembly_repair_is_better(&candidate, &primary)) {
    state->repair_candidate_valid = candidate.valid;
    state->repair_candidate_authenticated = candidate.authenticated;
    state->repair_candidate_complete = candidate.complete;
    state->repair_candidate_profile = candidate.profile;
    state->repair_candidate_profile_evidence = candidate.profile_evidence;
    state->repair_candidate_semantic_strength = candidate.semantic_strength;
    state->repair_candidate_coherence_payloads =
        candidate.coherence_payloads;
    state->repair_candidate_has_confidence = candidate.has_confidence;
    state->repair_candidate_all_positive = candidate.all_positive;
    state->repair_candidate_target_strong = candidate.target_strong;
    state->repair_candidate_target_exact = candidate.target_exact;
    state->repair_candidate_source_isolation = candidate.source_isolation;
    state->repair_candidate_reserved = candidate.reserved;
    state->repair_candidate_slot = candidate.slot;
    state->repair_candidate_width = candidate.width;
    state->repair_candidate_actual = candidate.actual;
    state->repair_candidate_score = candidate.score;
    state->repair_candidate_coherence_cost = candidate.coherence_cost;
    state->repair_candidate_coherence_extent = candidate.coherence_extent;
    state->repair_candidate_context_distance = candidate.context_distance;
    state->repair_candidate_target_concentration =
        candidate.target_concentration;
    state->repair_candidate_source_evidence = candidate.source_evidence;
    state->repair_candidate_confidence_gain = candidate.confidence_gain;
    if (scalpel_state.mode_verbose) {
      lock_fprintf(
          stdout,
          "CFBF repair rank: header=%" PRId64
          " slot=%" PRIu64 " width=%" PRIu64
          " source=%" PRIu64 " profile=%s score=%" PRIu64
          " reserved=%" PRIu32 " confidence=%s/%s target=%s/%s"
          " gain=%" PRId64 " context=%" PRIu64 " target=%" PRIu64
          " source-evidence=%" PRIu64 " source-isolation=%" PRIu32
          " coherence=%" PRIu32 "/%" PRIu64 "/%" PRIu64 ".\n",
          blockvector_get_actual_blocknumber(blockvector, 0),
          target_slot, run_blocks, source_actual,
          cfbf_profile_filetype(result->profile), result->score, reserved,
          has_confidence ? "yes" : "no", all_positive ? "all" : "mixed",
          target_strong ? "strong" : "weak",
          target_exact ? "exact" : "open", confidence_gain,
          context_distance, target_concentration, source_evidence,
          candidate.source_isolation, candidate.coherence_payloads,
          candidate.coherence_cost, candidate.coherence_extent);
    }
    return;
  }
}

// Clear the restartable suffix hypothesis before beginning a new sweep.
//
static inline void cfbf_reassembly_reset_suffix_candidate(
    CfbfCarveState *state) {

  if (!state) {
    return;
  }
  state->suffix_candidate_valid = 0;
  state->suffix_candidate_has_confidence = 0;
  state->suffix_candidate_all_positive = 0;
  state->suffix_candidate_reserved = 0;
  state->suffix_candidate_slot = 0;
  state->suffix_candidate_shift = 0;
  state->suffix_candidate_score = 0;
  state->suffix_candidate_concentration = UINT64_MAX;
  state->suffix_candidate_confidence_gain = 0;
  state->suffix_candidate_boundary_evidence = INT64_MIN;
  state->suffix_hypothesis_count = 0;
  memset(state->suffix_hypotheses, 0,
         sizeof(state->suffix_hypotheses));
}

// Return the subtype parsed from the strongest retained suffix hypothesis.
// Retained hypotheses are ordered by complete validation evidence.
//
static inline CfbfProfile cfbf_reassembly_supported_profile(
    const CfbfCarveState *state) {

  if (!state) {
    return CFBF_PROFILE_UNKNOWN;
  }
  uint32_t count = state->suffix_hypothesis_count;

  if (count > CFBF_SUFFIX_HYPOTHESIS_LIMIT) {
    count = CFBF_SUFFIX_HYPOTHESIS_LIMIT;
  }
  for (uint32_t index = 0; index < count; index++) {
    const CfbfSuffixHypothesis *hypothesis =
        &state->suffix_hypotheses[index];

    if (hypothesis->valid != 0
        && hypothesis->result.profile != CFBF_PROFILE_UNKNOWN) {
      return hypothesis->result.profile;
    }
  }
  return CFBF_PROFILE_UNKNOWN;
}

static inline bool cfbf_reassembly_suffix_hypothesis_is_better(
    const CfbfSuffixHypothesis *candidate,
    const CfbfSuffixHypothesis *retained) {

  if (!candidate || candidate->valid == 0) {
    return false;
  }
  if (!retained || retained->valid == 0) {
    return true;
  }
  const int32_t result_order = cfbf_reassembly_compare_trial_results(
      &candidate->result, &retained->result);

  if (result_order != 0) {
    return result_order > 0;
  }
  if (candidate->boundary_evidence != retained->boundary_evidence) {
    return candidate->boundary_evidence > retained->boundary_evidence;
  }
  if (candidate->has_confidence != retained->has_confidence) {
    return candidate->has_confidence != 0;
  }
  if (candidate->has_confidence != 0
      && candidate->all_positive != retained->all_positive) {
    return candidate->all_positive != 0;
  }
  if (candidate->has_confidence != 0
      && candidate->confidence_gain != retained->confidence_gain) {
    return candidate->confidence_gain > retained->confidence_gain;
  }
  if (candidate->concentration != retained->concentration) {
    return candidate->concentration < retained->concentration;
  }
  if (candidate->slot != retained->slot) {
    return candidate->slot < retained->slot;
  }
  if (candidate->reserved != retained->reserved) {
    return candidate->reserved < retained->reserved;
  }
  return candidate->shift < retained->shift;
}

// Preserve a bounded set of distinct recoverable mappings when format evidence
// cannot distinguish where file-owned padding ends and an inserted run begins.
//
static inline void cfbf_reassembly_retain_suffix_hypothesis(
    CfbfCarveState *state, const CfbfSuffixHypothesis *candidate,
    uint32_t limit) {

  if (!state || !candidate || candidate->valid == 0 || limit == 0) {
    return;
  }
  if (limit > CFBF_SUFFIX_HYPOTHESIS_LIMIT) {
    limit = CFBF_SUFFIX_HYPOTHESIS_LIMIT;
  }
  uint32_t count = state->suffix_hypothesis_count;

  if (count > limit) {
    count = limit;
  }
  for (uint32_t index = 0; index < count; index++) {
    CfbfSuffixHypothesis *retained = &state->suffix_hypotheses[index];

    if (retained->slot != candidate->slot
        || retained->shift != candidate->shift) {
      continue;
    }
    if (!cfbf_reassembly_suffix_hypothesis_is_better(
            candidate, retained)) {
      return;
    }
    for (uint32_t move = index; move + 1 < count; move++) {
      state->suffix_hypotheses[move] =
          state->suffix_hypotheses[move + 1];
    }
    count--;
    break;
  }

  uint32_t position = 0;

  while (position < count
         && !cfbf_reassembly_suffix_hypothesis_is_better(
                candidate, &state->suffix_hypotheses[position])) {
    position++;
  }
  if (position >= limit) {
    state->suffix_hypothesis_count = count;
    return;
  }
  uint32_t move = count < limit ? count : limit - 1;

  while (move > position) {
    state->suffix_hypotheses[move] =
        state->suffix_hypotheses[move - 1];
    move--;
  }
  state->suffix_hypotheses[position] = *candidate;
  if (count < limit) {
    count++;
  }
  state->suffix_hypothesis_count = count;
}

// Retain the suffix displacement that advances validation furthest across the
// nearby-gap sweep. Model confidence, physical concentration, and reservations
// rank otherwise equivalent candidates without excluding later hypotheses.
//
static inline void cfbf_reassembly_remember_suffix(
    CfbfCarveState *state, uint64_t target_slot, uint64_t shift,
    const CfbfTrialResult *result, bool has_confidence,
    bool all_positive, int64_t confidence_gain, uint32_t reserved,
    uint64_t concentration, int64_t boundary_evidence) {

  if (!state || !result || target_slot == 0 || shift == 0) {
    return;
  }
  bool better = state->suffix_candidate_valid == 0;

  if (!better && result->score != state->suffix_candidate_score) {
    better = result->score > state->suffix_candidate_score;
  }
  else if (!better
           && boundary_evidence
                  != state->suffix_candidate_boundary_evidence) {
    better = boundary_evidence
             > state->suffix_candidate_boundary_evidence;
  }
  else if (!better
           && has_confidence
                  != (state->suffix_candidate_has_confidence != 0)) {
    better = has_confidence;
  }
  else if (!better && has_confidence
           && all_positive
                  != (state->suffix_candidate_all_positive != 0)) {
    better = all_positive;
  }
  else if (!better && has_confidence
           && confidence_gain
                  != state->suffix_candidate_confidence_gain) {
    better = confidence_gain > state->suffix_candidate_confidence_gain;
  }
  else if (!better
           && concentration != state->suffix_candidate_concentration) {
    better = concentration < state->suffix_candidate_concentration;
  }
  else if (!better && target_slot != state->suffix_candidate_slot) {
    better = target_slot < state->suffix_candidate_slot;
  }
  else if (!better && reserved != state->suffix_candidate_reserved) {
    better = reserved < state->suffix_candidate_reserved;
  }
  else if (!better && shift != state->suffix_candidate_shift) {
    better = shift < state->suffix_candidate_shift;
  }

  if (!better) {
    return;
  }
  if (scalpel_state.mode_verbose) {
    lock_fprintf(
        stdout,
        "CFBF suffix rank: slot=%" PRIu64 " shift=%" PRIu64
        " profile=%s score=%" PRIu64 " boundary=%" PRId64
        " confidence=%s/%s gain=%" PRId64 " concentration=%" PRIu64
        ".\n",
        target_slot, shift, cfbf_profile_filetype(result->profile),
        result->score, boundary_evidence,
        has_confidence ? "yes" : "no", all_positive ? "all" : "mixed",
        confidence_gain, concentration);
  }
  state->suffix_candidate_valid = 1;
  state->suffix_candidate_has_confidence = has_confidence ? 1 : 0;
  state->suffix_candidate_all_positive = all_positive ? 1 : 0;
  state->suffix_candidate_reserved = reserved;
  state->suffix_candidate_slot = target_slot;
  state->suffix_candidate_shift = shift;
  state->suffix_candidate_score = result->score;
  state->suffix_candidate_concentration = concentration;
  state->suffix_candidate_confidence_gain = confidence_gain;
  state->suffix_candidate_boundary_evidence = boundary_evidence;
}

// Materialize an apparent-block mapping in private memory. Search trials never
// alter reservations, validity bits, or the live blockvector; only a proven
// mapping is committed.
//
static inline bool cfbf_reassembly_materialize_mapping(
    BlockVector *blockvector, const int64_t *mapping,
    const uint8_t *base_data, uint8_t *trial_data, uint64_t length) {

  if (!blockvector || !mapping || !base_data || !trial_data || length == 0) {
    return false;
  }
  const uint64_t total_blocks = blockvector_get_num_blocks(blockvector);
  const uint64_t blocksize = scalpel_state.blocksize;

  if (blocksize == 0 || total_blocks > UINT64_MAX / blocksize
      || length > total_blocks * blocksize) {
    return false;
  }
  memcpy(trial_data, base_data, (size_t)length);

  for (uint64_t slot = 0; slot < total_blocks; slot++) {
    if (mapping[slot]
        == blockvector_get_apparent_blocknumber(blockvector, slot)) {
      continue;
    }
    const uint64_t offset = slot * blocksize;

    if (offset >= length) {
      break;
    }
    uint64_t copy_length = length - offset;

    if (copy_length > blocksize) {
      copy_length = blocksize;
    }
    if (mapping[slot] < 0) {
      memset(trial_data + offset, 0, (size_t)copy_length);
      continue;
    }
    const int64_t actual = filemirror_actual_blocknumber(
        scalpel_state.filemirror, mapping[slot]);
    uint64_t source_length = 0;
    const uint8_t *source = (const uint8_t *)
        filemirror_actual_block_data_pointer(scalpel_state.filemirror,
                                             actual, &source_length);

    if (!source) {
      return false;
    }
    uint64_t available = source_length;

    if (available > copy_length) {
      available = copy_length;
    }
    memcpy(trial_data + offset, source, (size_t)available);
    if (available < copy_length) {
      memset(trial_data + offset + available, 0,
             (size_t)(copy_length - available));
    }
  }
  return true;
}

// Update private trial data from one apparent-block mapping to another. Source
// blocks are checked before any bytes change so a failed mapping leaves the
// existing trial intact and can be retried or restored safely.
//
static inline bool cfbf_reassembly_update_mapping_data(
    BlockVector *blockvector, const int64_t *from_mapping,
    const int64_t *to_mapping, uint8_t *trial_data, uint64_t length) {

  if (!blockvector || !from_mapping || !to_mapping || !trial_data
      || length == 0) {
    return false;
  }
  const uint64_t total_blocks = blockvector_get_num_blocks(blockvector);
  const uint64_t blocksize = scalpel_state.blocksize;

  if (blocksize == 0 || total_blocks > UINT64_MAX / blocksize
      || length > total_blocks * blocksize) {
    return false;
  }

  // The file mirror is immutable during reassembly. Validate the complete
  // delta before writing so this operation is atomic from the caller's view.
  for (uint64_t slot = 0; slot < total_blocks; slot++) {
    if (from_mapping[slot] == to_mapping[slot] || to_mapping[slot] < 0) {
      continue;
    }
    const uint64_t offset = slot * blocksize;

    if (offset >= length) {
      break;
    }
    const int64_t actual = filemirror_actual_blocknumber(
        scalpel_state.filemirror, to_mapping[slot]);
    uint64_t source_length = 0;
    const uint8_t *source = (const uint8_t *)
        filemirror_actual_block_data_pointer(
            scalpel_state.filemirror, actual, &source_length);

    if (!source) {
      return false;
    }
  }

  for (uint64_t slot = 0; slot < total_blocks; slot++) {
    if (from_mapping[slot] == to_mapping[slot]) {
      continue;
    }
    const uint64_t offset = slot * blocksize;

    if (offset >= length) {
      break;
    }
    uint64_t copy_length = length - offset;

    if (copy_length > blocksize) {
      copy_length = blocksize;
    }
    if (to_mapping[slot] < 0) {
      memset(trial_data + offset, 0, (size_t)copy_length);
      continue;
    }
    const int64_t actual = filemirror_actual_blocknumber(
        scalpel_state.filemirror, to_mapping[slot]);
    uint64_t source_length = 0;
    const uint8_t *source = (const uint8_t *)
        filemirror_actual_block_data_pointer(
            scalpel_state.filemirror, actual, &source_length);
    uint64_t available = source_length;

    if (available > copy_length) {
      available = copy_length;
    }
    memcpy(trial_data + offset, source, (size_t)available);
    if (available < copy_length) {
      memset(trial_data + offset + available, 0,
             (size_t)(copy_length - available));
    }
  }
  return true;
}

// Apply or restore only the slots changed by an isolated-run mapping. Trial
// data begins as a private copy of the candidate, so avoiding a whole-file copy
// for every hypothesis preserves identical bytes at substantially lower cost.
//
static inline bool cfbf_reassembly_update_run_data(
    BlockVector *blockvector, const int64_t *mapping,
    const uint8_t *base_data, uint8_t *trial_data, uint64_t length,
    uint64_t target_slot, uint64_t run_blocks, int64_t source_actual,
    bool restore) {

  if (!blockvector || !mapping || !base_data || !trial_data || length == 0
      || run_blocks == 0 || source_actual < 0
      || run_blocks > CFBF_NEARBY_RUN_WIDTH_LIMIT) {
    return false;
  }
  const uint64_t total_blocks = blockvector_get_num_blocks(blockvector);
  const uint64_t blocksize = scalpel_state.blocksize;

  if (blocksize == 0 || total_blocks > UINT64_MAX / blocksize
      || target_slot >= total_blocks
      || run_blocks > total_blocks - target_slot
      || length > total_blocks * blocksize) {
    return false;
  }
  uint64_t changed_slots[CFBF_NEARBY_RUN_WIDTH_LIMIT * 2];
  uint64_t changed_count = 0;

  for (uint64_t index = 0; index < run_blocks; index++) {
    changed_slots[changed_count++] = target_slot + index;
    const int64_t source_slot = cfbf_reassembly_find_actual_slot(
        blockvector, source_actual + (int64_t)index);

    if (source_slot > 0) {
      changed_slots[changed_count++] = (uint64_t)source_slot;
    }
  }
  for (uint64_t index = 0; index < changed_count; index++) {
    const uint64_t slot = changed_slots[index];
    const uint64_t offset = slot * blocksize;

    if (offset >= length) {
      continue;
    }
    uint64_t copy_length = length - offset;

    if (copy_length > blocksize) {
      copy_length = blocksize;
    }
    if (restore) {
      memcpy(trial_data + offset, base_data + offset, (size_t)copy_length);
      continue;
    }
    if (mapping[slot] < 0) {
      memset(trial_data + offset, 0, (size_t)copy_length);
      continue;
    }
    const int64_t actual = filemirror_actual_blocknumber(
        scalpel_state.filemirror, mapping[slot]);
    uint64_t source_length = 0;
    const uint8_t *source = (const uint8_t *)
        filemirror_actual_block_data_pointer(
            scalpel_state.filemirror, actual, &source_length);

    if (!source) {
      return false;
    }
    uint64_t available = source_length;

    if (available > copy_length) {
      available = copy_length;
    }
    memcpy(trial_data + offset, source, (size_t)available);
    if (available < copy_length) {
      memset(trial_data + offset + available, 0,
             (size_t)(copy_length - available));
    }
  }
  return true;
}

// Evaluate one displaced-run mapping and retain it only after complete CFBF
// parsing. Confidence and byte continuity rank proven mappings but never make
// a mapping valid and never remove another source from the exhaustive search.
//
static inline bool cfbf_reassembly_evaluate_run_repair(
    BlockVector *blockvector, CfbfCarveState *state,
    const CfbfTrialResult *current, const CfbfLayout *base_layout,
    bool semantic_prefilter_available, const int64_t *base_mapping,
    int64_t *trial_mapping, const uint8_t *base_data,
    uint8_t *trial_data, uint64_t length, uint64_t target_slot,
    uint64_t run_blocks, int64_t source_actual,
    CfbfTrialResult *result) {

  if (!blockvector || !state || !current || !base_mapping
      || !trial_mapping || !base_data || !trial_data || length == 0
      || run_blocks == 0 || source_actual < 0 || !result) {
    return false;
  }
  const uint64_t total_blocks = blockvector_get_num_blocks(blockvector);

  if (target_slot == 0 || target_slot >= total_blocks
      || run_blocks > total_blocks - target_slot
      || !cfbf_reassembly_build_run_mapping(
             blockvector, base_mapping, trial_mapping, target_slot,
             run_blocks, source_actual)) {
    return false;
  }
  const uint64_t target_concentration =
      cfbf_reassembly_mapping_concentration(
          base_mapping, target_slot, run_blocks);
  const uint64_t context_distance = cfbf_reassembly_context_distance(
      blockvector, base_mapping, target_slot, run_blocks, source_actual);
  bool has_confidence = false;
  bool all_positive = false;
  int64_t confidence_gain = 0;
  uint32_t reserved = 0;

  cfbf_reassembly_run_metrics(
      blockvector, base_mapping, target_slot, run_blocks, source_actual,
      current->profile, &has_confidence, &all_positive, &confidence_gain,
      &reserved, NULL);

  memset(result, 0, sizeof(*result));
  const bool materialized = cfbf_reassembly_update_run_data(
      blockvector, trial_mapping, base_data, trial_data, length,
      target_slot, run_blocks, source_actual, false);
  const bool prefilter_passed = materialized
      && (!semantic_prefilter_available
          || cfbf_reassembly_semantic_trial_complete(
                 base_layout, trial_data, length));
  const bool evaluated = prefilter_passed
      && cfbf_reassembly_evaluate_data(trial_data, length, result);

  if (!cfbf_reassembly_update_run_data(
          blockvector, trial_mapping, base_data, trial_data, length,
          target_slot, run_blocks, source_actual, true)) {
    memcpy(trial_data, base_data, (size_t)length);
  }
  if (!evaluated || !cfbf_reassembly_trial_recoverable(result)) {
    return false;
  }
  if (result->profile != current->profile) {
    cfbf_reassembly_run_metrics(
        blockvector, base_mapping, target_slot, run_blocks, source_actual,
        result->profile, &has_confidence, &all_positive, &confidence_gain,
        &reserved, NULL);
  }
  uint64_t source_concentration = cfbf_reassembly_run_concentration(
      source_actual, run_blocks);

  if (source_concentration == UINT64_MAX) {
    source_concentration = 0;
  }
  const bool target_exact = cfbf_reassembly_mapping_run_isolated(
      base_mapping, total_blocks, target_slot, run_blocks);
  const bool target_strong = target_concentration
      <= CFBF_STRONG_FILLER_CONCENTRATION_LIMIT;

  cfbf_reassembly_remember_repair(
      state, blockvector, target_slot, run_blocks,
      (uint64_t)source_actual, result,
      has_confidence, all_positive, target_strong, target_exact,
      confidence_gain, reserved, context_distance, target_concentration,
      source_concentration);
  return true;
}

// Build a suffix displacement without altering the live blockvector. Model
// trials may stop at unavailable trailing blocks, but callers must prove that
// the parser's inferred file extent lies inside the mapped prefix.
//
static inline bool cfbf_reassembly_build_suffix_mapping_prefix(
    BlockVector *blockvector, const int64_t *base_mapping,
    int64_t *trial_mapping, uint64_t target_slot, uint64_t shift,
    int64_t header_actual, bool permit_trailing_unavailable,
    uint64_t *mapped_blocks) {

  if (!blockvector || !base_mapping || !trial_mapping || target_slot == 0
      || shift == 0 || header_actual < 0) {
    return false;
  }
  if (mapped_blocks) {
    *mapped_blocks = 0;
  }
  const uint64_t total_blocks = blockvector_get_num_blocks(blockvector);

  if (target_slot >= total_blocks) {
    return false;
  }
  memcpy(trial_mapping, base_mapping,
         (size_t)total_blocks * sizeof(*trial_mapping));
  bool changed = false;
  bool lane_found = false;
  int64_t lane_shift = 0;

  // Determine the cumulative displacement immediately before this gap. A
  // pair of consecutive physical blocks identifies the contiguous lane while
  // excluding a previously repaired out-of-order run.
  for (uint64_t probe = target_slot; probe > 1; probe--) {
    const uint64_t right_slot = probe - 1;
    const uint64_t left_slot = right_slot - 1;

    if (base_mapping[left_slot] < 0 || base_mapping[right_slot] < 0) {
      continue;
    }
    const int64_t left_actual = filemirror_actual_blocknumber(
        scalpel_state.filemirror, base_mapping[left_slot]);
    const int64_t right_actual = filemirror_actual_blocknumber(
        scalpel_state.filemirror, base_mapping[right_slot]);
    const int64_t nominal = header_actual + (int64_t)right_slot;

    if (left_actual >= 0 && right_actual == left_actual + 1
        && right_actual >= nominal) {
      lane_shift = right_actual - nominal;
      lane_found = true;
      break;
    }
  }
  if (!lane_found) {
    for (uint64_t probe = target_slot; probe > 0; probe--) {
      const uint64_t slot = probe - 1;

      if (base_mapping[slot] < 0) {
        continue;
      }
      const int64_t actual = filemirror_actual_blocknumber(
          scalpel_state.filemirror, base_mapping[slot]);
      const int64_t nominal = header_actual + (int64_t)slot;

      if (actual >= nominal) {
        lane_shift = actual - nominal;
        lane_found = true;
        break;
      }
    }
  }
  if (!lane_found || shift < (uint64_t)lane_shift) {
    return false;
  }

  for (uint64_t slot = target_slot; slot < total_blocks; slot++) {
    int64_t base_actual = -1;

    if (base_mapping[slot] >= 0) {
      base_actual = filemirror_actual_blocknumber(
          scalpel_state.filemirror, base_mapping[slot]);
    }
    const int64_t lane_actual = header_actual + (int64_t)slot
                                + lane_shift;

    // Preserve a displaced run already installed in this logical suffix.
    // Deduplicated blocks may carry the exemplar's physical number rather
    // than the lane block's number, so compare canonical identities.
    if (base_actual >= 0 && base_actual != lane_actual
        && filemirror_get_exemplar(scalpel_state.filemirror, base_actual)
               != filemirror_get_exemplar(scalpel_state.filemirror,
                                          lane_actual)) {
      continue;
    }
    const int64_t actual = header_actual + (int64_t)slot
                           + (int64_t)shift;
    int64_t apparent = -1;
    int64_t existing_slot = -1;

    if (!cfbf_reassembly_mapping_source(blockvector, actual, &apparent,
                                        &existing_slot)) {
      if (permit_trailing_unavailable && slot > target_slot && changed) {
        if (mapped_blocks) {
          *mapped_blocks = slot;
        }
        return true;
      }
      return false;
    }
    if (existing_slot >= 0
        && (uint64_t)existing_slot < target_slot) {
      return false;
    }
    if (trial_mapping[slot] != apparent) {
      changed = true;
    }
    trial_mapping[slot] = apparent;
  }
  if (mapped_blocks) {
    *mapped_blocks = total_blocks;
  }
  return changed;
}

// Build a complete whole-suffix displacement. Existing source blocks may
// reappear later in the oversized contiguous candidate because the inserted
// physical run is being skipped.
//
static inline bool cfbf_reassembly_build_suffix_mapping(
    BlockVector *blockvector, const int64_t *base_mapping,
    int64_t *trial_mapping, uint64_t target_slot, uint64_t shift,
    int64_t header_actual) {

  return cfbf_reassembly_build_suffix_mapping_prefix(
      blockvector, base_mapping, trial_mapping, target_slot, shift,
      header_actual, false, NULL);
}

// Build a suffix lane identified directly by CFBF allocation metadata. A
// negative displacement may temporarily overlap the logical run that was
// moved elsewhere; combined repair callers explicitly permit that overlap and
// must replace the duplicated prefix before retaining the mapping.
//
static inline bool cfbf_reassembly_build_signed_suffix_mapping(
    BlockVector *blockvector, const int64_t *base_mapping,
    const CfbfMappingIndex *mapping_index, int64_t *trial_mapping,
    uint64_t target_slot, int64_t shift, int64_t header_actual,
    bool permit_prefix_overlap, bool permit_trailing_unavailable,
    uint64_t *mapped_blocks) {

  if (!blockvector || !base_mapping || !trial_mapping || target_slot == 0
      || shift == 0 || shift == INT64_MIN || header_actual < 0
      || scalpel_state.blocksize == 0) {
    return false;
  }
  if (mapped_blocks) {
    *mapped_blocks = 0;
  }
  const uint64_t total_blocks = blockvector_get_num_blocks(blockvector);
  const uint64_t image_blocks = CEILDIV(
      filemirror_filesize(scalpel_state.filemirror), scalpel_state.blocksize);

  if (target_slot >= total_blocks) {
    return false;
  }
  memcpy(trial_mapping, base_mapping,
         (size_t)total_blocks * sizeof(*trial_mapping));
  bool changed = false;

  for (uint64_t slot = target_slot; slot < total_blocks; slot++) {
    if (slot > (uint64_t)INT64_MAX
        || header_actual > INT64_MAX - (int64_t)slot) {
      return false;
    }
    const int64_t nominal = header_actual + (int64_t)slot;

    if ((shift > 0 && nominal > INT64_MAX - shift)
        || (shift < 0 && nominal < -shift)) {
      return false;
    }
    const int64_t actual = nominal + shift;
    if ((uint64_t)actual >= image_blocks) {
      if (permit_trailing_unavailable && slot > target_slot && changed) {
        if (mapped_blocks) {
          *mapped_blocks = slot;
        }
        return true;
      }
      return false;
    }
    int64_t apparent = -1;
    const int64_t source_slot = mapping_index
        ? cfbf_reassembly_mapping_index_find(mapping_index, actual)
        : cfbf_reassembly_find_actual_slot(blockvector, actual);

    if (source_slot >= 0) {
      apparent = base_mapping[(uint64_t)source_slot];
    }
    else if (filemirror_actual_block_is_zero(
                 scalpel_state.filemirror, actual)) {
      const int64_t exemplar = filemirror_get_exemplar(
          scalpel_state.filemirror, actual);

      apparent = filemirror_apparent_blocknumber(
          scalpel_state.filemirror, exemplar);
    }
    else if (!filemirror_actual_block_covered(
                  scalpel_state.filemirror, actual)) {
      const int64_t exemplar = filemirror_get_exemplar(
          scalpel_state.filemirror, actual);

      apparent = filemirror_apparent_blocknumber(
          scalpel_state.filemirror, exemplar);
    }
    if (apparent < 0) {
      if (permit_trailing_unavailable && slot > target_slot && changed) {
        if (mapped_blocks) {
          *mapped_blocks = slot;
        }
        return true;
      }
      return false;
    }
    if (source_slot == 0
        || (!permit_prefix_overlap && source_slot > 0
            && (uint64_t)source_slot < target_slot)) {
      return false;
    }
    if (trial_mapping[slot] != apparent) {
      changed = true;
    }
    trial_mapping[slot] = apparent;
  }
  if (mapped_blocks) {
    *mapped_blocks = total_blocks;
  }
  return changed;
}

// Apply one leg of a combined gap repair. A prior repair may already have
// removed the same physical run, in which case preserving that mapping is the
// correct idempotent result rather than a failed hypothesis.
//
static inline bool cfbf_reassembly_build_combined_suffix_mapping(
    BlockVector *blockvector, const int64_t *base_mapping,
    int64_t *trial_mapping, uint64_t target_slot, uint64_t shift,
    int64_t header_actual, uint64_t gap_actual, uint64_t gap_width) {

  if (!blockvector || !base_mapping || !trial_mapping || target_slot == 0
      || gap_width == 0 || gap_actual == 0
      || gap_actual > UINT64_MAX - gap_width) {
    return false;
  }
  if (cfbf_reassembly_build_suffix_mapping(
          blockvector, base_mapping, trial_mapping, target_slot, shift,
          header_actual)) {
    return true;
  }
  const uint64_t total_blocks = blockvector_get_num_blocks(blockvector);

  if (target_slot >= total_blocks || base_mapping[target_slot - 1] < 0
      || base_mapping[target_slot] < 0) {
    return false;
  }
  const int64_t left_actual = filemirror_actual_blocknumber(
      scalpel_state.filemirror, base_mapping[target_slot - 1]);
  const int64_t right_actual = filemirror_actual_blocknumber(
      scalpel_state.filemirror, base_mapping[target_slot]);

  if (left_actual < 0 || right_actual < 0
      || (uint64_t)left_actual + 1 != gap_actual
      || (uint64_t)right_actual != gap_actual + gap_width) {
    return false;
  }
  memcpy(trial_mapping, base_mapping,
         (size_t)total_blocks * sizeof(*trial_mapping));
  return true;
}

// Find an actual image block in an arbitrary private mapping.
//
static inline int64_t cfbf_reassembly_find_mapping_actual(
    const int64_t *mapping, uint64_t total_blocks, int64_t actual_block) {

  if (!mapping || actual_block < 0) {
    return -1;
  }
  for (uint64_t slot = 0; slot < total_blocks; slot++) {
    if (mapping[slot] >= 0
        && filemirror_actual_blocknumber(scalpel_state.filemirror,
                                         mapping[slot]) == actual_block) {
      return (int64_t)slot;
    }
  }
  return -1;
}

// Index the actual blocks present in one private mapping. The table is bounded
// by the candidate size, and retaining the first duplicate preserves the result
// of the linear lookup used when no index is supplied.
//
static inline bool cfbf_reassembly_mapping_index_initialize(
    CfbfMappingIndex *index, uint64_t total_blocks) {

  if (!index || total_blocks == 0 || total_blocks > UINT64_MAX / 2) {
    return false;
  }
  uint64_t capacity = 8;
  const uint64_t required = total_blocks * 2;

  while (capacity < required) {
    if (capacity > UINT64_MAX / 2) {
      return false;
    }
    capacity *= 2;
  }
  if (capacity > SIZE_MAX / sizeof(*index->entries)) {
    return false;
  }
  index->entries = (CfbfMappingIndexEntry *)calloc(
      (size_t)capacity, sizeof(*index->entries));
  check_memory_allocation(index->entries, __LINE__, __FILE__,
                          "CFBF mapping index");
  index->capacity = capacity;
  return true;
}

static inline void cfbf_reassembly_mapping_index_clear(
    CfbfMappingIndex *index) {

  if (!index) {
    return;
  }
  free(index->entries);
  index->entries = NULL;
  index->capacity = 0;
}

static inline bool cfbf_reassembly_mapping_index_build(
    CfbfMappingIndex *index, const int64_t *mapping,
    uint64_t total_blocks) {

  if (!index || !index->entries || index->capacity == 0 || !mapping
      || total_blocks > index->capacity / 2) {
    return false;
  }
  memset(index->entries, 0,
         (size_t)index->capacity * sizeof(*index->entries));

  for (uint64_t slot = 0; slot < total_blocks; slot++) {
    if (mapping[slot] < 0) {
      continue;
    }
    const int64_t actual = filemirror_actual_blocknumber(
        scalpel_state.filemirror, mapping[slot]);

    if (actual < 0) {
      continue;
    }
    const uint64_t key = (uint64_t)actual + 1;
    uint64_t position = (key * UINT64_C(11400714819323198485))
                        & (index->capacity - 1);

    while (index->entries[position].actual_key != 0
           && index->entries[position].actual_key != key) {
      position = (position + 1) & (index->capacity - 1);
    }
    if (index->entries[position].actual_key == 0) {
      index->entries[position].actual_key = key;
      index->entries[position].logical_slot = slot;
    }
  }
  return true;
}

static inline int64_t cfbf_reassembly_mapping_index_find(
    const CfbfMappingIndex *index, int64_t actual_block) {

  if (!index || !index->entries || index->capacity == 0
      || actual_block < 0) {
    return -1;
  }
  const uint64_t key = (uint64_t)actual_block + 1;
  uint64_t position = (key * UINT64_C(11400714819323198485))
                      & (index->capacity - 1);

  while (index->entries[position].actual_key != 0) {
    if (index->entries[position].actual_key == key) {
      return (int64_t)index->entries[position].logical_slot;
    }
    position = (position + 1) & (index->capacity - 1);
  }
  return -1;
}

// Apply a displaced physical run to an arbitrary private base mapping. Source
// blocks already present in that mapping are exchanged with the target run.
//
static inline bool cfbf_reassembly_build_mapped_run_indexed(
    BlockVector *blockvector, const int64_t *base_mapping,
    const CfbfMappingIndex *mapping_index, int64_t *trial_mapping,
    uint64_t target_slot, uint64_t run_blocks, int64_t source_actual) {

  if (!blockvector || !base_mapping || !trial_mapping || target_slot == 0
      || run_blocks == 0 || source_actual < 0) {
    return false;
  }
  const uint64_t total_blocks = blockvector_get_num_blocks(blockvector);
  const uint64_t image_blocks = CEILDIV(
      filemirror_filesize(scalpel_state.filemirror), scalpel_state.blocksize);

  if (target_slot >= total_blocks
      || run_blocks > total_blocks - target_slot
      || (uint64_t)source_actual >= image_blocks
      || run_blocks > image_blocks - (uint64_t)source_actual) {
    return false;
  }
  memcpy(trial_mapping, base_mapping,
         (size_t)total_blocks * sizeof(*trial_mapping));
  bool changed = false;

  for (uint64_t index = 0; index < run_blocks; index++) {
    const int64_t source = source_actual + (int64_t)index;
    const int64_t source_slot = mapping_index
        ? cfbf_reassembly_mapping_index_find(mapping_index, source)
        : cfbf_reassembly_find_mapping_actual(
              base_mapping, total_blocks, source);
    int64_t source_apparent = -1;

    if (source_slot == 0
        || (source_slot >= (int64_t)target_slot
        && source_slot < (int64_t)(target_slot + run_blocks))) {
      return false;
    }
    if (source_slot >= 0) {
      source_apparent = base_mapping[(uint64_t)source_slot];
    }
    else {
      if (filemirror_actual_block_covered(scalpel_state.filemirror, source)) {
        return false;
      }
      const int64_t exemplar = filemirror_get_exemplar(
          scalpel_state.filemirror, source);

      source_apparent = filemirror_apparent_blocknumber(
          scalpel_state.filemirror, exemplar);
      if (source_apparent < 0
          && !filemirror_actual_block_is_zero(scalpel_state.filemirror,
                                              source)) {
        return false;
      }
    }
    const int64_t target_apparent = trial_mapping[target_slot + index];
    const int64_t target_actual = target_apparent >= 0
        ? filemirror_actual_blocknumber(
              scalpel_state.filemirror, target_apparent)
        : -1;
    const int64_t target_exemplar = target_actual >= 0
        ? filemirror_get_exemplar(scalpel_state.filemirror, target_actual)
        : -1;
    const int64_t source_exemplar = filemirror_get_exemplar(
        scalpel_state.filemirror, source);

    if (target_exemplar != source_exemplar) {
      changed = true;
    }
    trial_mapping[target_slot + index] = source_apparent;
    if (source_slot > 0) {
      const int64_t replacement_apparent = base_mapping[target_slot + index];
      const int64_t replacement_actual = replacement_apparent >= 0
          ? filemirror_actual_blocknumber(
                scalpel_state.filemirror, replacement_apparent)
          : -1;
      const int64_t replacement_exemplar = replacement_actual >= 0
          ? filemirror_get_exemplar(
                scalpel_state.filemirror, replacement_actual)
          : -1;

      if (source_exemplar != replacement_exemplar) {
        changed = true;
      }
      trial_mapping[(uint64_t)source_slot] = replacement_apparent;
    }
  }
  return changed;
}

static inline bool cfbf_reassembly_build_mapped_run(
    BlockVector *blockvector, const int64_t *base_mapping,
    int64_t *trial_mapping, uint64_t target_slot,
    uint64_t run_blocks, int64_t source_actual) {

  return cfbf_reassembly_build_mapped_run_indexed(
      blockvector, base_mapping, NULL, trial_mapping, target_slot,
      run_blocks, source_actual);
}

// Measure the concentration of blocks currently occupying a private mapping
// run. Lower values are closer to uniform unrelated data.
//
static inline uint64_t cfbf_reassembly_mapping_concentration(
    const int64_t *mapping, uint64_t target_slot, uint64_t run_blocks) {

  if (!mapping || run_blocks == 0) {
    return UINT64_MAX;
  }
  uint64_t total = 0;

  for (uint64_t index = 0; index < run_blocks; index++) {
    if (mapping[target_slot + index] < 0) {
      continue;
    }
    const int64_t actual = filemirror_actual_blocknumber(
        scalpel_state.filemirror, mapping[target_slot + index]);
    const uint64_t score = cfbf_reassembly_run_concentration(actual, 1);

    if (total <= UINT64_MAX - score) {
      total += score;
    }
    else {
      total = UINT64_MAX;
    }
  }
  return total / run_blocks;
}

// Identify a complete filler island in the current logical mapping. The
// displaced source may contain statistically weak blocks, but the run it
// replaces remains bounded by file data on each available side.
//
static inline bool cfbf_reassembly_mapping_run_isolated(
    const int64_t *mapping, uint64_t total_blocks,
    uint64_t target_slot, uint64_t run_blocks) {

  if (!mapping || run_blocks == 0 || target_slot >= total_blocks
      || run_blocks > total_blocks - target_slot) {
    return false;
  }
  if (cfbf_reassembly_mapping_concentration(
          mapping, target_slot, run_blocks)
      > CFBF_UNIFORM_CONCENTRATION_LIMIT) {
    return false;
  }
  if (target_slot > 0
      && cfbf_reassembly_mapping_concentration(
             mapping, target_slot - 1, 1)
             <= CFBF_UNIFORM_CONCENTRATION_LIMIT) {
    return false;
  }
  if (target_slot + run_blocks < total_blocks
      && cfbf_reassembly_mapping_concentration(
             mapping, target_slot + run_blocks, 1)
             <= CFBF_UNIFORM_CONCENTRATION_LIMIT) {
    return false;
  }
  return true;
}

// Rank a complete source island. A source may contain legitimate zero-filled
// sectors, but it must contain some nonuniform file content. The optional
// eligibility result distinguishes weak physical boundaries from an invalid
// source. Random-like boundaries establish the basic island, while each
// independently known zero or following CFBF boundary strengthens the result.
// A run beginning inside another CFBF file is not a detached source island.
// The complete validators remain authoritative.
//
static inline uint32_t cfbf_reassembly_source_run_isolation(
    int64_t source_actual, uint64_t run_blocks, bool *eligible) {

  if (eligible) {
    *eligible = false;
  }

  if (source_actual < 0 || run_blocks == 0) {
    return 0;
  }
  const uint64_t image_blocks = CEILDIV(
      filemirror_filesize(scalpel_state.filemirror), scalpel_state.blocksize);
  const uint64_t source = (uint64_t)source_actual;

  if (source >= image_blocks || run_blocks > image_blocks - source) {
    return 0;
  }
  bool has_nonuniform_content = false;

  for (uint64_t block = 0; block < run_blocks; block++) {
    const int64_t actual = source_actual + (int64_t)block;
    uint64_t data_length = 0;
    const uint8_t *data = (const uint8_t *)
        filemirror_actual_block_data_pointer(
            scalpel_state.filemirror, actual, &data_length);

    if (data && cfbf_has_header(data, data_length)) {
      return 0;
    }
    if (!filemirror_actual_block_is_zero(scalpel_state.filemirror, actual)
        && !cfbf_reassembly_block_is_uniform(actual)) {
      has_nonuniform_content = true;
    }
  }
  if (!has_nonuniform_content) {
    return 0;
  }
  if (eligible) {
    *eligible = true;
  }
  uint32_t strength = 1;

  if (source > 0) {
    const int64_t left = source_actual - 1;
    uint64_t data_length = 0;
    const uint8_t *data = (const uint8_t *)
        filemirror_actual_block_data_pointer(
            scalpel_state.filemirror, left, &data_length);

    if (data && cfbf_has_header(data, data_length)) {
      if (eligible) {
        *eligible = false;
      }
      return 0;
    }
    if (filemirror_actual_block_is_zero(scalpel_state.filemirror, left)) {
      strength++;
    }
    else if (!cfbf_reassembly_block_is_uniform(left)) {
      return 0;
    }
  }
  if (source + run_blocks < image_blocks) {
    const int64_t right = source_actual + (int64_t)run_blocks;
    uint64_t data_length = 0;
    const uint8_t *data = (const uint8_t *)
        filemirror_actual_block_data_pointer(
            scalpel_state.filemirror, right, &data_length);

    if (filemirror_actual_block_is_zero(scalpel_state.filemirror, right)) {
      strength++;
    }
    else if (data && cfbf_has_header(data, data_length)) {
      strength++;
    }
    else if (!cfbf_reassembly_block_is_uniform(right)) {
      return 0;
    }
  }
  return strength;
}

// Build one atomic displaced-run hypothesis. If source blocks currently occur
// elsewhere in an oversized candidate, exchange the two runs so the trial does
// not contain duplicate physical blocks.
//
static inline bool cfbf_reassembly_build_run_mapping(
    BlockVector *blockvector, const int64_t *base_mapping,
    int64_t *trial_mapping, uint64_t target_slot,
    uint64_t run_blocks, int64_t source_actual) {

  return cfbf_reassembly_build_mapped_run(
      blockvector, base_mapping, trial_mapping, target_slot,
      run_blocks, source_actual);
}

// Require a complete allocation graph and format-specific semantic evidence
// before a speculative mapping can terminate the search.
//
static inline bool cfbf_reassembly_trial_complete(
    const CfbfTrialResult *result) {

  return result && result->structurally_valid
         && result->profile != CFBF_PROFILE_UNKNOWN
         && (result->semantic_strength == CFBF_SEMANTIC_STRONG
             || result->profile_evidence);
}

// Publish only hypotheses supported by the format-specific semantic checks.
// Structurally valid intermediate trials remain available to the search.
//
static inline bool cfbf_reassembly_trial_publishable(
    const CfbfTrialResult *result) {

  return cfbf_reassembly_trial_complete(result);
}

// A complete allocation graph with a known subtype is recoverable even when
// opaque application data cannot authenticate every selected block. Such a
// hypothesis remains PROMISING unless the stronger test above also succeeds.
//
static inline bool cfbf_reassembly_trial_recoverable(
    const CfbfTrialResult *result) {

  return result && result->structurally_valid
         && result->profile != CFBF_PROFILE_UNKNOWN;
}

// Some legacy formats contain opaque, unchecksummed regions. Their semantic
// validators can prove the parsed structures but cannot authenticate every
// selected block, so those mappings remain ranked PROMISING hypotheses.
//
static inline bool cfbf_reassembly_trial_authenticated(
    const CfbfTrialResult *result) {

  if (!cfbf_reassembly_trial_complete(result)) {
    return false;
  }
  return cfbf_profile_authenticates_all_content(result->profile);
}

// A Project repair must affect bytes retained in the recovered file. Other
// profiles may need repairs beyond an incomplete intermediate size estimate.
//
static inline bool cfbf_reassembly_target_within_result(
    const CfbfTrialResult *result, uint64_t target_slot,
    uint64_t run_blocks, uint64_t total_blocks) {

  if (!result || run_blocks == 0 || target_slot >= total_blocks
      || run_blocks > total_blocks - target_slot) {
    return false;
  }
  if (result->profile != CFBF_PROFILE_MPP || result->inferred_size == 0) {
    return true;
  }
  const uint64_t inferred_blocks = CEILDIV(
      result->inferred_size, scalpel_state.blocksize);

  return target_slot < inferred_blocks
         && run_blocks <= inferred_blocks - target_slot;
}

// Order complete trial results without changing their validation verdicts.
// Embedded payload checks distinguish mappings only when the enclosing format
// exposes independently validated content; equal evidence remains ambiguous.
//
static inline int32_t cfbf_reassembly_compare_trial_results(
    const CfbfTrialResult *candidate,
    const CfbfTrialResult *retained) {

  if (!candidate) {
    return retained ? -1 : 0;
  }
  if (!retained) {
    return 1;
  }

  const bool candidate_authenticated =
      cfbf_reassembly_trial_authenticated(candidate);
  const bool retained_authenticated =
      cfbf_reassembly_trial_authenticated(retained);

  if (candidate_authenticated != retained_authenticated) {
    return candidate_authenticated ? 1 : -1;
  }

  const bool candidate_complete = cfbf_reassembly_trial_complete(candidate);
  const bool retained_complete = cfbf_reassembly_trial_complete(retained);

  if (candidate_complete != retained_complete) {
    return candidate_complete ? 1 : -1;
  }
  if (candidate->semantic_strength != retained->semantic_strength) {
    return candidate->semantic_strength > retained->semantic_strength
               ? 1 : -1;
  }
  if (candidate->profile_evidence != retained->profile_evidence) {
    return candidate->profile_evidence ? 1 : -1;
  }

  const bool candidate_payloads_complete =
      candidate->examined_payloads != 0
      && candidate->examined_payloads == candidate->validated_payloads;
  const bool retained_payloads_complete =
      retained->examined_payloads != 0
      && retained->examined_payloads == retained->validated_payloads;

  if (candidate_payloads_complete != retained_payloads_complete) {
    return candidate_payloads_complete ? 1 : -1;
  }
  if (candidate->examined_payloads != 0
      && retained->examined_payloads != 0) {
    const uint64_t candidate_ratio =
        (uint64_t)candidate->validated_payloads
        * retained->examined_payloads;
    const uint64_t retained_ratio =
        (uint64_t)retained->validated_payloads
        * candidate->examined_payloads;

    if (candidate_ratio != retained_ratio) {
      return candidate_ratio > retained_ratio ? 1 : -1;
    }
  }
  if (candidate->validated_payloads != retained->validated_payloads) {
    return candidate->validated_payloads > retained->validated_payloads
               ? 1 : -1;
  }
  const bool both_mpp = candidate->profile == CFBF_PROFILE_MPP
                        && retained->profile == CFBF_PROFILE_MPP;

  // Project payload coverage is semantic evidence; coherence cost is only a
  // layout heuristic. Leave equal coverage tied for the caller to resolve.
  if (both_mpp) {
    if (candidate->coherence_payloads != retained->coherence_payloads) {
      return candidate->coherence_payloads
                     > retained->coherence_payloads
                 ? 1 : -1;
    }
    if (candidate->coherence_extent != retained->coherence_extent) {
      return candidate->coherence_extent > retained->coherence_extent
                 ? 1 : -1;
    }
  }
  else {
    const int32_t coherence_order = cfbf_reassembly_compare_coherence(
        candidate->coherence_payloads, candidate->coherence_cost,
        candidate->coherence_extent, retained->coherence_payloads,
        retained->coherence_cost, retained->coherence_extent);

    if (coherence_order != 0) {
      return coherence_order;
    }
  }
  if (candidate->score != retained->score) {
    return candidate->score > retained->score ? 1 : -1;
  }
  return 0;
}

// Install a proven mapping and discard any speculative extent beyond the size
// established by the repaired allocation graph.
//
static inline void cfbf_reassembly_commit_mapping(
    CarveInfo *candidate, CfbfCarveState *state,
    const int64_t *mapping, const CfbfTrialResult *result,
    uint32_t repairs) {

  if (!candidate || !candidate->b || !state || !mapping || !result) {
    return;
  }
  BlockVector *blockvector = candidate->b;
  uint64_t total_blocks = blockvector_get_num_blocks(blockvector);
  const bool recoverable = cfbf_reassembly_trial_recoverable(result);

  for (uint64_t slot = 0; slot < total_blocks; slot++) {
    blockvector_set_apparent_blocknumber(blockvector, slot, mapping[slot]);
  }
  if (recoverable && result->inferred_size > 0) {
    const uint64_t proven_blocks = CEILDIV(result->inferred_size,
                                           scalpel_state.blocksize);

    if (proven_blocks > 0 && proven_blocks < total_blocks) {
      resize_blockvector(blockvector, proven_blocks);
      total_blocks = proven_blocks;
    }
  }
  inflate_blockvector(blockvector);
  blockvector_set_data_length(
      blockvector, recoverable && result->inferred_size > 0
                       ? result->inferred_size
                       : total_blocks * (uint64_t)scalpel_state.blocksize);

  state->profile = (uint32_t)result->profile;
  state->semantic_strength = (uint32_t)result->semantic_strength;
  state->failure_offset = result->failure_offset;
  if (recoverable && result->inferred_size > 0) {
    state->inferred_size = result->inferred_size;
  }
  else if (result->inferred_size > state->inferred_size) {
    state->inferred_size = result->inferred_size;
  }
  state->repairs += repairs;
  state->search_phase = 0;
  state->suffix_pass = 0;
  state->pair_suffix_possible = 0;
  state->resume_slot = 0;
  state->resume_choice = 0;
  state->resume_run_width = 0;
  state->resume_run_left = 0;
  state->resume_source_pass = 0;
  cfbf_reassembly_reset_atomic_search(state);
  carve_put_state(candidate->carvehashkey, state);
}

// Preserve one distinct multi-block hypothesis when opaque application streams
// admit more than one recoverable CFBF mapping. The parent retains the primary
// result and one work-sharing clone receives the alternate; both remain
// PROMISING unless stronger validation promotes them later.
//
static inline bool cfbf_reassembly_share_alternate(
    ThreadWork *work, CarveInfo **candidate, CfbfCarveState *state,
    const int64_t *base_mapping, const uint8_t *base_data, uint64_t length) {

  if (!work || !candidate || !*candidate || !(*candidate)->b || !state
      || !base_mapping || !base_data || length == 0
      || !scalpel_state.share_reassembly || (*candidate)->clone
      || state->repair_candidate_valid == 0
      || state->repair_alternate.valid == 0
      || (state->repair_alternate.slot == state->repair_candidate_slot
          && state->repair_alternate.width == state->repair_candidate_width
          && state->repair_alternate.actual
                 == state->repair_candidate_actual)) {
    return false;
  }
  const bool weak_boundary_alternate =
      state->repair_alternate.source_isolation
      == CFBF_DETACHED_SOURCE_WEAK_BOUNDARY;

  if (state->repair_alternate.complete == 0 && !weak_boundary_alternate) {
    return false;
  }
  const uint64_t total_blocks = blockvector_get_num_blocks((*candidate)->b);

  if (total_blocks == 0 || total_blocks > SIZE_MAX / sizeof(int64_t)
      || length > SIZE_MAX) {
    return false;
  }
  int64_t *alternate_mapping = (int64_t *)malloc(
      (size_t)total_blocks * sizeof(*alternate_mapping));
  uint8_t *alternate_data = (uint8_t *)malloc((size_t)length);

  check_memory_allocation(alternate_mapping, __LINE__, __FILE__,
                          "CFBF alternate mapping");
  check_memory_allocation(alternate_data, __LINE__, __FILE__,
                          "CFBF alternate data");
  bool shareable = cfbf_reassembly_build_run_mapping(
                       (*candidate)->b, base_mapping, alternate_mapping,
                       state->repair_alternate.slot,
                       state->repair_alternate.width,
                       (int64_t)state->repair_alternate.actual)
      && cfbf_reassembly_materialize_mapping(
             (*candidate)->b, alternate_mapping, base_data,
             alternate_data, length);
  CfbfTrialResult alternate_result;

  memset(&alternate_result, 0, sizeof(alternate_result));
  shareable = shareable
      && cfbf_reassembly_evaluate_data(
             alternate_data, length, &alternate_result)
      && (weak_boundary_alternate
              ? cfbf_reassembly_trial_recoverable(&alternate_result)
              : cfbf_reassembly_trial_complete(&alternate_result));
  bool shared = false;

  if (shareable) {
    BlockVector *parent_blockvector = (*candidate)->b;
    BlockVector *alternate_blockvector = NULL;
    const CarveInfoFlavor parent_flavor = (*candidate)->flavor;
    const CfbfCarveState parent_state = *state;

    clone_blockvector(parent_blockvector, &alternate_blockvector, true);
    (*candidate)->b = alternate_blockvector;
    cfbf_reassembly_commit_mapping(
        *candidate, state, alternate_mapping, &alternate_result,
        state->repair_alternate.width > UINT32_MAX
            ? UINT32_MAX : (uint32_t)state->repair_alternate.width);
    state->search_phase = CFBF_REASSEMBLY_FINALIZED;
    (*candidate)->flavor = PROMISING;
    carve_put_state((*candidate)->carvehashkey, state);
    shared = reassembly_share_work_count(work->id, *candidate) > 0;

    free_blockvector(&((*candidate)->b));
    (*candidate)->b = parent_blockvector;
    (*candidate)->flavor = parent_flavor;
    *state = parent_state;
    carve_put_state((*candidate)->carvehashkey, state);

    if (shared && scalpel_state.mode_verbose) {
      lock_fprintf(
          stdout,
          "CFBF alternate repair shared: header=%" PRId64
          " slot=%" PRIu64 " width=%" PRIu64 " source=%" PRIu64
          " profile=%s.\n",
          blockvector_get_actual_blocknumber(parent_blockvector, 0),
          parent_state.repair_alternate.slot,
          parent_state.repair_alternate.width,
          parent_state.repair_alternate.actual,
          cfbf_profile_filetype(alternate_result.profile));
    }
  }
  free(alternate_data);
  free(alternate_mapping);
  return shared;
}

// Preserve a structurally complete opaque mapping before broader repair search
// changes it. The live candidate continues evaluating stronger or structurally
// distinct hypotheses.
//
static inline bool cfbf_reassembly_preserve_current_hypothesis(
    CarveInfo *candidate, CfbfCarveState *state,
    const CfbfTrialResult *result) {

  if (!candidate || !candidate->b || !state || !result
      || state->opaque_baseline_shared != 0
      || !cfbf_reassembly_trial_recoverable(result)) {
    return false;
  }
  const uint64_t total_blocks = blockvector_get_num_blocks(candidate->b);

  if (total_blocks == 0 || total_blocks > SIZE_MAX / sizeof(int64_t)) {
    return false;
  }
  int64_t *mapping = (int64_t *)malloc(
      (size_t)total_blocks * sizeof(*mapping));

  check_memory_allocation(mapping, __LINE__, __FILE__,
                          "CFBF opaque baseline mapping");
  for (uint64_t slot = 0; slot < total_blocks; slot++) {
    mapping[slot] = blockvector_get_apparent_blocknumber(candidate->b, slot);
  }
  const bool written = cfbf_reassembly_write_mapping_hypothesis(
      candidate, state, mapping, result, 0, true);

  free(mapping);
  if (written) {
    state->opaque_baseline_shared = 1;
    carve_put_state(candidate->carvehashkey, state);
  }
  if (written && scalpel_state.mode_verbose) {
    lock_fprintf(
        stdout,
        "CFBF complete opaque hypothesis preserved: header=%" PRId64 ".\n",
        blockvector_get_actual_blocknumber(candidate->b, 0));
  }
  return written;
}

// Rebuild and commit the best suffix retained by a restartable nearby-gap
// sweep. Revalidation keeps checkpointed ranking state from becoming an
// implicit correctness decision, while strict score advancement allows a
// file with multiple perturbations to be repaired one operation at a time.
//
static inline bool cfbf_reassembly_commit_remembered_suffix(
    CarveInfo *candidate, CfbfCarveState *state,
    const CfbfTrialResult *current) {

  if (!candidate || !candidate->b || !state || !current
      || state->suffix_candidate_valid == 0) {
    return false;
  }
  BlockVector *blockvector = candidate->b;
  const uint64_t total_blocks = blockvector_get_num_blocks(blockvector);
  const uint64_t length = blockvector_get_data_length(blockvector);
  const int64_t header_actual = blockvector_get_actual_blocknumber(
      blockvector, 0);

  if (total_blocks == 0 || length == 0 || header_actual < 0) {
    return false;
  }
  int64_t *base_mapping = (int64_t *)malloc(
      (size_t)total_blocks * sizeof(*base_mapping));
  int64_t *trial_mapping = (int64_t *)malloc(
      (size_t)total_blocks * sizeof(*trial_mapping));
  uint8_t *trial_data = (uint8_t *)malloc((size_t)length);

  check_memory_allocation(base_mapping, __LINE__, __FILE__,
                          "CFBF retained suffix base mapping");
  check_memory_allocation(trial_mapping, __LINE__, __FILE__,
                          "CFBF retained suffix trial mapping");
  check_memory_allocation(trial_data, __LINE__, __FILE__,
                          "CFBF retained suffix trial data");
  for (uint64_t slot = 0; slot < total_blocks; slot++) {
    base_mapping[slot] = blockvector_get_apparent_blocknumber(
        blockvector, slot);
  }
  const uint8_t *base_data = (const uint8_t *)
      blockvector_get_data_pointer(blockvector);
  CfbfTrialResult result;
  uint64_t mapped_blocks = 0;

  memset(&result, 0, sizeof(result));
  const bool improved = cfbf_reassembly_build_suffix_mapping_prefix(
                            blockvector, base_mapping, trial_mapping,
                            state->suffix_candidate_slot,
                            state->suffix_candidate_shift, header_actual,
                            true, &mapped_blocks)
                        && cfbf_reassembly_materialize_mapping(
                               blockvector, trial_mapping, base_data,
                               trial_data, length)
                        && cfbf_reassembly_evaluate_data(
                               trial_data, length, &result)
                        && (mapped_blocks == total_blocks
                            || (result.inferred_size > 0
                                && CEILDIV(result.inferred_size,
                                           scalpel_state.blocksize)
                                       <= mapped_blocks))
                        && result.score >= state->suffix_candidate_score
                        && result.score > current->score;

  if (improved) {
    cfbf_reassembly_commit_mapping(candidate, state, trial_mapping,
                                   &result, 1);
  }
  free(trial_data);
  free(trial_mapping);
  free(base_mapping);
  return improved;
}

// Write one complete mapping as a non-destructive PROMISING hypothesis. A
// structurally complete current mapping may be preserved without authenticating
// opaque application bytes; speculative mappings still require format-specific
// semantic evidence. The live candidate is restored before returning.
// Cloning may reinflate the parent blockvector, so callers retaining its byte
// pointer must reacquire that pointer after this function returns.
//
static inline bool cfbf_reassembly_write_mapping_hypothesis(
    CarveInfo *candidate, CfbfCarveState *state,
    const int64_t *mapping, const CfbfTrialResult *result,
    uint32_t repairs, bool permit_opaque) {

  if (!candidate || !candidate->b || !state || !mapping || !result
      || !scalpel_state.write_promising
      || (!cfbf_reassembly_trial_publishable(result)
          && (!permit_opaque
              || !cfbf_reassembly_trial_recoverable(result)))) {
    return false;
  }
  BlockVector *parent_blockvector = candidate->b;
  BlockVector *hypothesis = NULL;
  const CfbfCarveState parent_state = *state;
  const CarveInfoFlavor parent_flavor = candidate->flavor;
  const int32_t parent_needleidx = candidate->needleidx;
  char *parent_filetype = candidate->filetype;

  clone_blockvector(parent_blockvector, &hypothesis, true);
  candidate->b = hypothesis;
  cfbf_reassembly_commit_mapping(candidate, state, mapping, result, repairs);
  state->search_phase = CFBF_REASSEMBLY_FINALIZED;
  cfbf_assign_candidate_profile(candidate, result->profile);
  candidate->flavor = PROMISING;
  carve_put_state(candidate->carvehashkey, state);
  write_candidate(&candidate, true);

  free_blockvector(&candidate->b);
  candidate->b = parent_blockvector;
  candidate->flavor = parent_flavor;
  candidate->needleidx = parent_needleidx;
  candidate->filetype = parent_filetype;
  *state = parent_state;
  carve_put_state(candidate->carvehashkey, state);
  return true;
}

// Rebuild and publish one retained displaced-run hypothesis. Retention stores
// only compact coordinates, so the restartable state remains independent of
// candidate size.
//
static inline bool cfbf_reassembly_write_repair_hypothesis(
    CarveInfo *candidate, CfbfCarveState *state,
    const int64_t *base_mapping, int64_t *trial_mapping,
    const uint8_t *base_data, uint8_t *trial_data, uint64_t length,
    const CfbfRepairCandidate *repair) {

  if (!candidate || !candidate->b || !state || !base_mapping
      || !trial_mapping || !base_data || !trial_data || length == 0
      || !repair || repair->valid == 0 || repair->width == 0
      || repair->actual > (uint64_t)INT64_MAX) {
    return false;
  }
  CfbfTrialResult result;

  memset(&result, 0, sizeof(result));
  if (!cfbf_reassembly_build_run_mapping(
          candidate->b, base_mapping, trial_mapping,
          repair->slot, repair->width, (int64_t)repair->actual)
      || !cfbf_reassembly_materialize_mapping(
             candidate->b, trial_mapping, base_data, trial_data, length)
      || !cfbf_reassembly_evaluate_data(trial_data, length, &result)
      || !cfbf_reassembly_trial_recoverable(&result)) {
    return false;
  }
  const uint32_t repairs = repair->width > UINT32_MAX
      ? UINT32_MAX : (uint32_t)repair->width;

  return cfbf_reassembly_write_mapping_hypothesis(
      candidate, state, trial_mapping, &result, repairs, true);
}

static inline bool cfbf_reassembly_model_hypothesis_is_better(
    const CfbfTrialResult *result,
    const CfbfModelHypothesis *retained) {

  if (!result) {
    return false;
  }
  if (!retained || retained->valid == 0) {
    return true;
  }
  return cfbf_reassembly_compare_trial_results(
             result, &retained->result) > 0;
}

static inline void cfbf_reassembly_retain_model_hypothesis(
    CfbfModelHypothesis *hypotheses, uint32_t *count, uint32_t limit,
    const CfbfModelHypothesis *candidate) {

  if (!hypotheses || !count || !candidate || candidate->valid == 0
      || limit == 0) {
    return;
  }
  uint32_t position = 0;

  while (position < *count
         && !cfbf_reassembly_model_hypothesis_is_better(
                &candidate->result, &hypotheses[position])) {
    position++;
  }
  if (position >= limit) {
    return;
  }
  uint32_t move_end = *count < limit ? *count : limit - 1;

  while (move_end > position) {
    hypotheses[move_end] = hypotheses[move_end - 1];
    move_end--;
  }
  hypotheses[position] = *candidate;
  if (*count < limit) {
    (*count)++;
  }
}

// Rebuild one parser-ranked model hypothesis from compact physical
// coordinates. This avoids retaining another blockvector-sized mapping while
// all alternatives are compared.
//
static inline bool cfbf_reassembly_write_model_hypothesis(
    CarveInfo *candidate, CfbfCarveState *state,
    const int64_t *base_mapping, int64_t *first_mapping,
    int64_t *pair_mapping, int64_t *trial_mapping,
    CfbfMappingIndex *pair_index, CfbfModelHypothesis *hypothesis,
    int64_t header_actual) {

  if (!candidate || !candidate->b || !state || !base_mapping
      || !first_mapping || !pair_mapping || !trial_mapping || !pair_index
      || !hypothesis || hypothesis->valid == 0 || header_actual < 0) {
    return false;
  }
  const uint64_t total_blocks = blockvector_get_num_blocks(candidate->b);
  uint64_t mapped_blocks = total_blocks;
  bool built = false;

  switch (hypothesis->kind) {
  case CFBF_MODEL_HYPOTHESIS_SINGLE_GAP: {
    mapped_blocks = 0;

    built = hypothesis->target_slot > 0
        && hypothesis->target_slot < total_blocks
        && cfbf_reassembly_build_suffix_mapping_prefix(
               candidate->b, base_mapping, trial_mapping,
               hypothesis->target_slot, hypothesis->shift, header_actual,
               true, &mapped_blocks);
    break;
  }
  case CFBF_MODEL_HYPOTHESIS_GAP_PAIR:
  case CFBF_MODEL_HYPOTHESIS_COMBINED: {
    if (hypothesis->first_actual <= (uint64_t)header_actual
        || hypothesis->second_actual
               <= (uint64_t)header_actual + hypothesis->first_width
        || hypothesis->first_width
               > UINT64_MAX - hypothesis->second_width) {
      return false;
    }
    const uint64_t first_slot = hypothesis->first_actual
                                - (uint64_t)header_actual;
    const uint64_t second_slot = hypothesis->second_actual
                                 - (uint64_t)header_actual
                                 - hypothesis->first_width;
    const uint64_t cumulative_shift = hypothesis->first_width
                                      + hypothesis->second_width;

    built = first_slot > 0 && first_slot < total_blocks
        && second_slot > first_slot && second_slot < total_blocks
        && cfbf_reassembly_build_combined_suffix_mapping(
               candidate->b, base_mapping, first_mapping, first_slot,
               hypothesis->first_width, header_actual,
               hypothesis->first_actual, hypothesis->first_width)
        && cfbf_reassembly_build_combined_suffix_mapping(
               candidate->b, first_mapping, pair_mapping, second_slot,
               cumulative_shift, header_actual,
               hypothesis->second_actual, hypothesis->second_width);
    if (built && hypothesis->kind == CFBF_MODEL_HYPOTHESIS_GAP_PAIR) {
      memcpy(trial_mapping, pair_mapping,
             (size_t)total_blocks * sizeof(*trial_mapping));
    }
    else if (built) {
      built = hypothesis->run_slot > 0
          && hypothesis->run_slot < total_blocks
          && hypothesis->run_width <= total_blocks - hypothesis->run_slot
          && hypothesis->source_actual <= (uint64_t)INT64_MAX
          && cfbf_reassembly_mapping_index_build(
                 pair_index, pair_mapping, total_blocks)
          && cfbf_reassembly_build_mapped_run_indexed(
                 candidate->b, pair_mapping, pair_index, trial_mapping,
                 hypothesis->run_slot, hypothesis->run_width,
                 (int64_t)hypothesis->source_actual);
    }
    break;
  }
  default:
    return false;
  }
  const bool mapped_extent = mapped_blocks == total_blocks
      || (hypothesis->result.inferred_size > 0
          && CEILDIV(hypothesis->result.inferred_size,
                     scalpel_state.blocksize) <= mapped_blocks);

  return built && mapped_extent
      && cfbf_reassembly_write_mapping_hypothesis(
                      candidate, state, trial_mapping,
                      &hypothesis->result, hypothesis->repairs, true);
}

static inline void cfbf_reassembly_flush_model_hypotheses(
    CarveInfo *candidate, CfbfCarveState *state,
    const int64_t *base_mapping, int64_t *first_mapping,
    int64_t *pair_mapping, int64_t *trial_mapping,
    CfbfMappingIndex *pair_index,
    CfbfModelHypothesis *complete_hypotheses,
    uint32_t *complete_count,
    CfbfModelHypothesis *partial_hypotheses,
    uint32_t *partial_count, int64_t header_actual) {

  CfbfModelHypothesis *hypothesis_sets[2] = {
    complete_hypotheses, partial_hypotheses
  };
  uint32_t *hypothesis_counts[2] = {
    complete_count, partial_count
  };
  for (uint32_t set = 0; set < 2; set++) {
    if (!hypothesis_sets[set] || !hypothesis_counts[set]) {
      continue;
    }
    for (uint32_t index = 0;
         index < *hypothesis_counts[set]; index++) {
      CfbfModelHypothesis *hypothesis = &hypothesis_sets[set][index];

      if (hypothesis->valid != 0
          && cfbf_reassembly_write_model_hypothesis(
                 candidate, state, base_mapping, first_mapping,
                 pair_mapping, trial_mapping, pair_index, hypothesis,
                 header_actual)) {
        hypothesis->valid = 0;
      }
    }
    *hypothesis_counts[set] = 0;
  }
}

// Preserve a complete, physically supported gap hypothesis without replacing
// the primary displaced-run search. An incomplete advancing suffix remains in
// restartable state until a complete primary hypothesis has also been saved.
//
static inline bool cfbf_reassembly_handle_supported_suffix(
    CarveInfo *candidate, CfbfCarveState *state,
    const CfbfTrialResult *current) {

  if (!candidate || !candidate->b || !state || !current
      || state->suffix_candidate_valid == 0) {
    return false;
  }
  BlockVector *blockvector = candidate->b;
  const uint64_t total_blocks = blockvector_get_num_blocks(blockvector);
  const uint64_t length = blockvector_get_data_length(blockvector);
  const int64_t header_actual = blockvector_get_actual_blocknumber(
      blockvector, 0);

  if (total_blocks == 0 || length == 0 || header_actual < 0) {
    cfbf_reassembly_reset_suffix_candidate(state);
    return false;
  }
  int64_t *base_mapping = (int64_t *)malloc(
      (size_t)total_blocks * sizeof(*base_mapping));
  int64_t *trial_mapping = (int64_t *)malloc(
      (size_t)total_blocks * sizeof(*trial_mapping));
  uint8_t *trial_data = (uint8_t *)malloc((size_t)length);

  check_memory_allocation(base_mapping, __LINE__, __FILE__,
                          "CFBF supported suffix base mapping");
  check_memory_allocation(trial_mapping, __LINE__, __FILE__,
                          "CFBF supported suffix trial mapping");
  check_memory_allocation(trial_data, __LINE__, __FILE__,
                          "CFBF supported suffix trial data");
  for (uint64_t slot = 0; slot < total_blocks; slot++) {
    base_mapping[slot] = blockvector_get_apparent_blocknumber(
        blockvector, slot);
  }
  const uint8_t *base_data = (const uint8_t *)
      blockvector_get_data_pointer(blockvector);
  CfbfTrialResult result;
  uint64_t mapped_blocks = 0;

  memset(&result, 0, sizeof(result));
  const bool evaluated = base_data
      && cfbf_reassembly_build_suffix_mapping_prefix(
             blockvector, base_mapping, trial_mapping,
             state->suffix_candidate_slot,
             state->suffix_candidate_shift, header_actual,
             true, &mapped_blocks)
      && cfbf_reassembly_materialize_mapping(
             blockvector, trial_mapping, base_data, trial_data, length)
      && cfbf_reassembly_evaluate_data(trial_data, length, &result)
      && (mapped_blocks == total_blocks
          || (result.inferred_size > 0
              && CEILDIV(result.inferred_size, scalpel_state.blocksize)
                     <= mapped_blocks))
      && result.score >= state->suffix_candidate_score;
  const bool advancing_partial = evaluated
      && !cfbf_reassembly_trial_recoverable(&result)
      && result.score > current->score;
  const bool reusable_combined = evaluated
      && !cfbf_reassembly_trial_authenticated(&result)
      && result.score >= current->score;

  const uint32_t hypothesis_count =
      state->suffix_hypothesis_count <= CFBF_SUFFIX_HYPOTHESIS_LIMIT
          ? state->suffix_hypothesis_count
          : CFBF_SUFFIX_HYPOTHESIS_LIMIT;

  if (hypothesis_count != 0) {
    for (uint32_t index = 0; index < hypothesis_count; index++) {
      const CfbfSuffixHypothesis hypothesis =
          state->suffix_hypotheses[index];

      if (hypothesis.valid == 0) {
        continue;
      }
      CfbfTrialResult hypothesis_result;
      uint64_t hypothesis_mapped_blocks = 0;

      memset(&hypothesis_result, 0, sizeof(hypothesis_result));
      const bool hypothesis_evaluated =
          cfbf_reassembly_build_suffix_mapping_prefix(
              blockvector, base_mapping, trial_mapping,
              hypothesis.slot, hypothesis.shift, header_actual,
              true, &hypothesis_mapped_blocks)
          && cfbf_reassembly_materialize_mapping(
                 blockvector, trial_mapping, base_data, trial_data, length)
          && cfbf_reassembly_evaluate_data(
                 trial_data, length, &hypothesis_result)
          && (hypothesis_mapped_blocks == total_blocks
              || (hypothesis_result.inferred_size > 0
                  && CEILDIV(hypothesis_result.inferred_size,
                             scalpel_state.blocksize)
                         <= hypothesis_mapped_blocks))
          && cfbf_reassembly_compare_trial_results(
                 &hypothesis_result, &hypothesis.result) >= 0
          && cfbf_reassembly_trial_recoverable(&hypothesis_result);

      if (hypothesis_evaluated
          && cfbf_reassembly_write_mapping_hypothesis(
                 candidate, state, trial_mapping, &hypothesis_result,
                 1, true)
          && scalpel_state.mode_verbose) {
        lock_fprintf(
            stdout,
            "CFBF supported suffix preserved: header=%" PRId64
            " slot=%" PRIu64 " shift=%" PRIu64 " profile=%s.\n",
            header_actual, hypothesis.slot, hypothesis.shift,
            cfbf_profile_filetype(hypothesis_result.profile));
      }
      base_data = (const uint8_t *)
          blockvector_get_data_pointer(blockvector);
      if (!base_data) {
        break;
      }
    }
  }
  else if (evaluated && cfbf_reassembly_trial_recoverable(&result)) {
    (void)cfbf_reassembly_write_mapping_hypothesis(
        candidate, state, trial_mapping, &result, 1, true);
  }
  const bool retain_for_combined_search = reusable_combined
      && (current->profile == CFBF_PROFILE_MPP
          || result.profile == CFBF_PROFILE_MPP
          || cfbf_reassembly_supported_profile(state) == CFBF_PROFILE_MPP);

  if (!retain_for_combined_search) {
    state->suffix_hypothesis_count = 0;
    memset(state->suffix_hypotheses, 0,
           sizeof(state->suffix_hypotheses));
  }
  if (!advancing_partial && !reusable_combined) {
    cfbf_reassembly_reset_suffix_candidate(state);
  }
  carve_put_state(candidate->carvehashkey, state);
  free(trial_data);
  free(trial_mapping);
  free(base_mapping);
  return false;
}

// Save a complete primary mapping, then continue the live candidate from an
// advancing partial suffix. This explores both fragmentation models without
// relying on idle-thread work sharing or replacing a known complete result.
//
static inline bool cfbf_reassembly_branch_partial_suffix(
    CarveInfo *candidate, CfbfCarveState *state,
    const CfbfTrialResult *current, const int64_t *primary_mapping,
    const CfbfTrialResult *primary_result, uint32_t primary_repairs) {

  if (!candidate || !candidate->b || !state || !current
      || !primary_mapping || !primary_result
      || state->suffix_candidate_valid == 0) {
    return false;
  }
  BlockVector *blockvector = candidate->b;
  const uint64_t total_blocks = blockvector_get_num_blocks(blockvector);
  const uint64_t length = blockvector_get_data_length(blockvector);
  const int64_t header_actual = blockvector_get_actual_blocknumber(
      blockvector, 0);

  if (total_blocks == 0 || length == 0 || header_actual < 0) {
    return false;
  }
  int64_t *base_mapping = (int64_t *)malloc(
      (size_t)total_blocks * sizeof(*base_mapping));
  int64_t *suffix_mapping = (int64_t *)malloc(
      (size_t)total_blocks * sizeof(*suffix_mapping));
  uint8_t *suffix_data = (uint8_t *)malloc((size_t)length);

  check_memory_allocation(base_mapping, __LINE__, __FILE__,
                          "CFBF branch base mapping");
  check_memory_allocation(suffix_mapping, __LINE__, __FILE__,
                          "CFBF branch suffix mapping");
  check_memory_allocation(suffix_data, __LINE__, __FILE__,
                          "CFBF branch suffix data");
  for (uint64_t slot = 0; slot < total_blocks; slot++) {
    base_mapping[slot] = blockvector_get_apparent_blocknumber(
        blockvector, slot);
  }
  const uint8_t *base_data = (const uint8_t *)
      blockvector_get_data_pointer(blockvector);
  CfbfTrialResult suffix_result;
  uint64_t mapped_blocks = 0;

  memset(&suffix_result, 0, sizeof(suffix_result));
  const bool advancing_partial = base_data
      && cfbf_reassembly_build_suffix_mapping_prefix(
             blockvector, base_mapping, suffix_mapping,
             state->suffix_candidate_slot,
             state->suffix_candidate_shift, header_actual,
             true, &mapped_blocks)
      && cfbf_reassembly_materialize_mapping(
             blockvector, suffix_mapping, base_data,
             suffix_data, length)
      && cfbf_reassembly_evaluate_data(
             suffix_data, length, &suffix_result)
      && (mapped_blocks == total_blocks
          || (suffix_result.inferred_size > 0
              && CEILDIV(suffix_result.inferred_size,
                         scalpel_state.blocksize) <= mapped_blocks))
      && suffix_result.score >= state->suffix_candidate_score
      && !cfbf_reassembly_trial_recoverable(&suffix_result)
      && suffix_result.score > current->score;
  bool branched = false;

  if (advancing_partial
      && cfbf_reassembly_write_mapping_hypothesis(
             candidate, state, primary_mapping,
             primary_result, primary_repairs, true)) {
    const uint64_t suffix_slot = state->suffix_candidate_slot;
    const uint64_t suffix_shift = state->suffix_candidate_shift;

    cfbf_reassembly_commit_mapping(candidate, state, suffix_mapping,
                                   &suffix_result, 1);
    cfbf_reassembly_reset_suffix_candidate(state);
    carve_put_state(candidate->carvehashkey, state);
    branched = true;
    if (scalpel_state.mode_verbose) {
      lock_fprintf(
          stdout,
          "CFBF partial suffix branch selected: header=%" PRId64
          " slot=%" PRIu64 " shift=%" PRIu64 ".\n",
          header_actual, suffix_slot, suffix_shift);
    }
  }
  free(suffix_data);
  free(suffix_mapping);
  free(base_mapping);
  return branched;
}

// Poll remote-control and checkpoint requests only while the candidate holds
// its committed mapping. The fixed search cursors make the scan restartable.
//
static inline bool cfbf_reassembly_poll(ThreadWork *work,
                                        CarveInfo **candidate,
                                        CfbfCarveState *state,
                                        uuid_string_t uuidp,
                                        uuid_string_t uuidc) {

  if (!work || !candidate || !*candidate || !state) {
    return true;
  }
  carve_put_state((*candidate)->carvehashkey, state);
  if (reassembly_check_kill_queue(work, candidate, uuidp, uuidc)) {
    return true;
  }
  if (atomic_load_explicit(&REASS_RETURN_TO_IDLE, memory_order_acquire)
      && reassembly_time_to_checkpoint(work->id, *candidate, uuidp, uuidc)) {
    return true;
  }
  return false;
}

// Use self-identifying FAT sectors to derive physical displacement lanes.
// The header fixes both the logical FAT-sector order and the positions at
// which FATSECT markers must occur. A matching image block therefore supplies
// a displacement hypothesis without relying on corpus-specific byte strings.
// Every resulting mapping still passes through the complete CFBF and subtype
// validators before it can be retained.
//
static inline bool cfbf_reassembly_try_structural_anchors(
    ThreadWork *work, CarveInfo **candidate, CfbfCarveState *state,
    const CfbfTrialResult *current, uint64_t targeted_slot,
    uuid_string_t uuidp, uuid_string_t uuidc, bool *improved) {

  if (!work || !candidate || !*candidate || !(*candidate)->b || !state
      || !current || !improved) {
    return false;
  }
  *improved = false;

  BlockVector *blockvector = (*candidate)->b;
  const uint64_t total_blocks = blockvector_get_num_blocks(blockvector);
  const uint64_t length = blockvector_get_data_length(blockvector);
  const uint64_t image_blocks = CEILDIV(
      filemirror_filesize(scalpel_state.filemirror), scalpel_state.blocksize);
  const int64_t header_actual = blockvector_get_actual_blocknumber(
      blockvector, 0);
  const uint8_t *base_data = (const uint8_t *)
      blockvector_get_data_pointer(blockvector);

  if (!base_data || total_blocks < 2 || length == 0 || image_blocks == 0
      || header_actual < 0 || (uint64_t)header_actual >= image_blocks
      || targeted_slot == 0
      || targeted_slot >= total_blocks || length < CFBF_HEADER_SIZE) {
    return false;
  }
  const uint16_t sector_shift = cfbf_read_le16(base_data + 30);

  if (sector_shift >= 63) {
    return false;
  }
  const uint64_t sector_size = UINT64_C(1) << sector_shift;

  // A sector spanning multiple carving blocks requires a different physical
  // mapping model. The complete generic search remains available in that case.
  if (sector_size != scalpel_state.blocksize
      || sector_size < sizeof(uint32_t)) {
    return false;
  }
  const uint64_t entries_per_sector = sector_size / sizeof(uint32_t);
  const uint32_t declared_fat_count = cfbf_read_le32(base_data + 44);
  uint32_t fat_sectors[CFBF_DIFAT_HEADER_ENTRIES];
  uint32_t known_fat_count = 0;

  for (uint32_t index = 0;
       index < CFBF_DIFAT_HEADER_ENTRIES
       && known_fat_count < declared_fat_count; index++) {
    const uint32_t sector = cfbf_read_le32(
        base_data + 76 + (uint64_t)index * sizeof(uint32_t));

    if (sector == CFBF_FREE_SECTOR) {
      continue;
    }
    if (sector >= CFBF_MAX_REGULAR_SECTOR) {
      return false;
    }
    fat_sectors[known_fat_count++] = sector;
  }
  if (known_fat_count == 0) {
    return false;
  }

  int64_t *base_mapping = (int64_t *)malloc(
      (size_t)total_blocks * sizeof(*base_mapping));
  int64_t *trial_mapping = (int64_t *)malloc(
      (size_t)total_blocks * sizeof(*trial_mapping));
  int64_t *combined_mapping = (int64_t *)malloc(
      (size_t)total_blocks * sizeof(*combined_mapping));
  uint8_t *trial_data = (uint8_t *)malloc((size_t)length);

  check_memory_allocation(base_mapping, __LINE__, __FILE__,
                          "CFBF structural-anchor base mapping");
  check_memory_allocation(trial_mapping, __LINE__, __FILE__,
                          "CFBF structural-anchor trial mapping");
  check_memory_allocation(combined_mapping, __LINE__, __FILE__,
                          "CFBF structural-anchor combined mapping");
  check_memory_allocation(trial_data, __LINE__, __FILE__,
                          "CFBF structural-anchor trial data");
  for (uint64_t slot = 0; slot < total_blocks; slot++) {
    base_mapping[slot] = blockvector_get_apparent_blocknumber(
        blockvector, slot);
  }

  const bool resuming = state->search_phase
                        == CFBF_REASSEMBLY_STRUCTURAL_ANCHORS;
  const bool resuming_targets = resuming
      && state->structural_reserved
             == CFBF_STRUCTURAL_RESUME_TARGET_SCAN;
  const bool resuming_sources = resuming
      && state->structural_reserved
             == CFBF_STRUCTURAL_RESUME_SOURCE_SCAN;
  const int64_t resume_shift = state->structural_resume_shift;
  const uint64_t resume_target = state->structural_resume_actual;
  const uint64_t resume_overlap_target = state->structural_overlap_target;
  const uint64_t resume_source_order =
      state->structural_resume_source_order;
  uint64_t scan_start = scalpel_state.start_block;
  uint64_t scan_end = image_blocks - 1;
  int64_t structural_shifts[CFBF_DIFAT_HEADER_ENTRIES] = { 0 };
  uint32_t structural_support[CFBF_DIFAT_HEADER_ENTRIES] = { 0 };
  bool structural_anchor_seen[CFBF_DIFAT_HEADER_ENTRIES]
                             [CFBF_DIFAT_HEADER_ENTRIES] = { { false } };
  bool structural_shift_complete[CFBF_DIFAT_HEADER_ENTRIES] = { false };
  bool anchorable_fat_page[CFBF_DIFAT_HEADER_ENTRIES] = { false };
  bool nominal_anchor_seen[CFBF_DIFAT_HEADER_ENTRIES] = { false };
  uint64_t structural_first_anchor[CFBF_DIFAT_HEADER_ENTRIES];
  uint64_t nominal_anchors[CFBF_DIFAT_HEADER_ENTRIES] = { 0 };
  uint32_t structural_shift_count = 0;
  uint32_t nominal_anchor_count = 0;

  for (uint32_t index = 0; index < CFBF_DIFAT_HEADER_ENTRIES; index++) {
    structural_first_anchor[index] = UINT64_MAX;
  }
  for (uint32_t index = 0; index < known_fat_count; index++) {
    const uint64_t fat_page = (uint64_t)fat_sectors[index]
                              / entries_per_sector;

    if (fat_page < known_fat_count) {
      anchorable_fat_page[fat_page] = true;
    }
  }

  if (scalpel_state.end_block != UINT64_MAX
      && scalpel_state.end_block < scan_end) {
    scan_end = scalpel_state.end_block;
  }
  if (scan_start > scan_end) {
    free(trial_data);
    free(combined_mapping);
    free(trial_mapping);
    free(base_mapping);
    return false;
  }
  if (!resuming) {
    state->structural_shift_valid = 0;
    state->structural_shift = 0;
    state->structural_resume_shift = 0;
    state->structural_shift_slot = 0;
    state->structural_shift_score = current->score;
    state->structural_shift_support = 0;
    state->structural_coherence_payloads = current->coherence_payloads;
    state->structural_coherence_cost = current->coherence_cost;
    state->structural_coherence_extent = current->coherence_extent;
    state->structural_resume_actual = 0;
    state->structural_overlap_target = 0;
    state->structural_resume_source_order = 0;
    state->structural_reserved = 0;
    state->structural_search_complete = 0;
  }
  state->search_phase = CFBF_REASSEMBLY_STRUCTURAL_ANCHORS;

  for (uint64_t actual = scan_start; actual <= scan_end; actual++) {
    uint64_t block_length = 0;
    const uint8_t *block = (const uint8_t *)
        filemirror_actual_block_data_pointer(
            scalpel_state.filemirror, (int64_t)actual, &block_length);
    int64_t block_shifts[CFBF_DIFAT_HEADER_ENTRIES];
    uint32_t block_shift_count = 0;

    if (block && block_length >= sector_size) {
      for (uint64_t entry = 0; entry < entries_per_sector; entry++) {
        if (cfbf_read_le32(block + entry * sizeof(uint32_t))
            != CFBF_FAT_SECTOR) {
          continue;
        }
        for (uint32_t fat = 0; fat < known_fat_count; fat++) {
          const uint32_t marked_sector = fat_sectors[fat];

          if ((uint64_t)marked_sector % entries_per_sector != entry) {
            continue;
          }
          const uint64_t fat_index = (uint64_t)marked_sector
                                     / entries_per_sector;

          if (fat_index >= known_fat_count) {
            continue;
          }
          bool page_matches = false;

          for (uint32_t known = 0; known < known_fat_count; known++) {
            if ((uint64_t)fat_sectors[known] / entries_per_sector
                != fat_index) {
              continue;
            }
            page_matches = true;
            if (cfbf_read_le32(
                    block + ((uint64_t)fat_sectors[known]
                             % entries_per_sector) * sizeof(uint32_t))
                != CFBF_FAT_SECTOR) {
              page_matches = false;
              break;
            }
          }
          if (!page_matches) {
            continue;
          }
          const uint64_t anchor_slot =
              (uint64_t)fat_sectors[fat_index] + 1;

          if (anchor_slot > (uint64_t)INT64_MAX
              || header_actual > INT64_MAX - (int64_t)anchor_slot) {
            continue;
          }
          const int64_t nominal = header_actual + (int64_t)anchor_slot;
          const int64_t shift = (int64_t)actual - nominal;

          bool duplicate = false;

          for (uint32_t prior = 0; prior < block_shift_count; prior++) {
            if (block_shifts[prior] == shift) {
              duplicate = true;
              break;
            }
          }
          if (duplicate) {
            continue;
          }
          if (block_shift_count < CFBF_DIFAT_HEADER_ENTRIES) {
            block_shifts[block_shift_count++] = shift;
          }

          if (shift == 0) {
            if (!nominal_anchor_seen[fat_index]
                && nominal_anchor_count < CFBF_DIFAT_HEADER_ENTRIES) {
              nominal_anchor_seen[fat_index] = true;
              nominal_anchors[nominal_anchor_count++] = anchor_slot;
            }
            continue;
          }

          uint32_t shift_index = 0;

          while (shift_index < structural_shift_count
                 && structural_shifts[shift_index] != shift) {
            shift_index++;
          }
          if (shift_index == structural_shift_count
              && structural_shift_count < CFBF_DIFAT_HEADER_ENTRIES) {
            structural_shifts[shift_index] = shift;
            structural_first_anchor[shift_index] = anchor_slot;
            structural_shift_count++;
          }
          if (shift_index < structural_shift_count
              && !structural_anchor_seen[shift_index][fat_index]) {
            structural_anchor_seen[shift_index][fat_index] = true;
            structural_support[shift_index]++;
            if (anchor_slot < structural_first_anchor[shift_index]) {
              structural_first_anchor[shift_index] = anchor_slot;
            }
          }
        }
      }
    }
    if ((actual & UINT64_C(0xff)) == 0
        && cfbf_reassembly_poll(
               work, candidate, state, uuidp, uuidc)) {
      free(trial_data);
      free(combined_mapping);
      free(trial_mapping);
      free(base_mapping);
      return true;
    }
  }

  bool complete_shift_found = false;

  for (uint32_t index = 0; index < structural_shift_count; index++) {
    bool complete = true;

    for (uint32_t fat = 0; fat < known_fat_count; fat++) {
      if (anchorable_fat_page[fat] && !nominal_anchor_seen[fat]
          && !structural_anchor_seen[index][fat]) {
        complete = false;
        break;
      }
    }
    structural_shift_complete[index] = complete;
    complete_shift_found = complete_shift_found || complete;
  }

  // A complete displacement lane can expose allocation metadata beyond the
  // candidate's first bounded search window. Grow the exploratory mapping
  // geometrically toward the FAT capacity declared by the header, then rerun
  // the structural search over that larger view. This changes no validation
  // verdict and avoids allocating the full capacity at once for large files.
  const uint64_t represented_sectors =
      (uint64_t)declared_fat_count * entries_per_sector;
  uint64_t declared_blocks = represented_sectors == UINT64_MAX
                                 ? UINT64_MAX
                                 : represented_sectors + 1;
  const uint64_t maximum_blocks = CFBF_MAXIMUM_SIZE / sector_size;

  if (declared_blocks > maximum_blocks) {
    declared_blocks = maximum_blocks;
  }
  if (complete_shift_found && declared_blocks > total_blocks) {
    uint64_t expanded_blocks = total_blocks <= UINT64_MAX / 2
                                   ? total_blocks * 2 : UINT64_MAX;

    if (expanded_blocks < total_blocks + entries_per_sector) {
      expanded_blocks = total_blocks + entries_per_sector;
    }
    if (expanded_blocks > declared_blocks) {
      expanded_blocks = declared_blocks;
    }
    const uint64_t available_blocks = image_blocks - (uint64_t)header_actual;

    if (expanded_blocks > available_blocks) {
      expanded_blocks = available_blocks;
    }
    bool expansion_valid = expanded_blocks > total_blocks;

    if (expansion_valid) {
      resize_blockvector(blockvector, expanded_blocks);
      for (uint64_t slot = total_blocks; slot < expanded_blocks; slot++) {
        if (slot > (uint64_t)INT64_MAX
            || header_actual > INT64_MAX - (int64_t)slot) {
          expansion_valid = false;
          break;
        }
        const int64_t actual = header_actual + (int64_t)slot;
        const int64_t apparent = filemirror_apparent_blocknumber(
            scalpel_state.filemirror, actual);

        if (apparent < 0
            && !filemirror_actual_block_is_zero(
                   scalpel_state.filemirror, actual)) {
          expansion_valid = false;
          break;
        }
        blockvector_set_apparent_blocknumber(blockvector, slot, apparent);
      }
    }
    if (!expansion_valid) {
      resize_blockvector(blockvector, total_blocks);
      inflate_blockvector(blockvector);
      blockvector_set_data_length(blockvector, length);
      base_data = (const uint8_t *)
          blockvector_get_data_pointer(blockvector);
    }
    else {
      inflate_blockvector(blockvector);
      blockvector_set_data_length(
          blockvector,
          expanded_blocks * (uint64_t)scalpel_state.blocksize);
      state->search_phase = 0;
      state->structural_shift_valid = 0;
      state->structural_shift = 0;
      state->structural_shift_slot = 0;
      state->structural_shift_score = 0;
      state->structural_shift_support = 0;
      state->structural_coherence_payloads = 0;
      state->structural_coherence_cost = 0;
      state->structural_coherence_extent = 0;
      state->structural_resume_shift = 0;
      state->structural_resume_actual = 0;
      state->structural_overlap_target = 0;
      state->structural_resume_source_order = 0;
      state->structural_reserved = 0;
      state->structural_search_complete = 0;
      carve_put_state((*candidate)->carvehashkey, state);
      *improved = true;
      if (scalpel_state.mode_verbose) {
        lock_fprintf(
            stdout,
            "CFBF structural search extent expanded: header=%" PRId64
            " blocks=%" PRIu64 "->%" PRIu64 ".\n",
            header_actual, total_blocks, expanded_blocks);
      }
      free(trial_data);
      free(combined_mapping);
      free(trial_mapping);
      free(base_mapping);
      return false;
    }
  }

  bool processed_shifts[CFBF_DIFAT_HEADER_ENTRIES] = { false };
  uint64_t structural_trials = 0;
  bool resume_shift_pending = resuming_targets || resuming_sources;
  CfbfMappingIndex base_index = { 0 };

  if (!cfbf_reassembly_mapping_index_initialize(&base_index, total_blocks)
      || !cfbf_reassembly_mapping_index_build(
             &base_index, base_mapping, total_blocks)) {
    cfbf_reassembly_mapping_index_clear(&base_index);
    free(trial_data);
    free(combined_mapping);
    free(trial_mapping);
    free(base_mapping);
    return false;
  }

  if (resume_shift_pending) {
    bool resume_shift_found = false;

    for (uint32_t index = 0; index < structural_shift_count; index++) {
      if (structural_shifts[index] == resume_shift
          && (!complete_shift_found || structural_shift_complete[index])) {
        resume_shift_found = true;
        break;
      }
    }
    if (!resume_shift_found) {
      resume_shift_pending = false;
    }
  }

  for (uint32_t order = 0; order < structural_shift_count; order++) {
    uint32_t shift_index = UINT32_MAX;

    for (uint32_t index = 0; index < structural_shift_count; index++) {
      if (processed_shifts[index]
          || (complete_shift_found && !structural_shift_complete[index])) {
        continue;
      }
      if (shift_index == UINT32_MAX
          || structural_support[index] > structural_support[shift_index]
          || (structural_support[index] == structural_support[shift_index]
              && structural_first_anchor[index]
                    < structural_first_anchor[shift_index])) {
        shift_index = index;
      }
    }
    if (shift_index == UINT32_MAX) {
      break;
    }
    processed_shifts[shift_index] = true;

    const int64_t shift = structural_shifts[shift_index];
    const bool resumed_shift = resume_shift_pending && shift == resume_shift;

    if (resume_shift_pending && !resumed_shift) {
      continue;
    }
    resume_shift_pending = false;

    uint64_t first_target = 1;
    uint64_t last_target = structural_first_anchor[shift_index];

    if (last_target >= total_blocks) {
      last_target = total_blocks - 1;
    }
    for (uint32_t index = 0; index < nominal_anchor_count; index++) {
      if (nominal_anchors[index] < last_target
          && nominal_anchors[index] + 1 > first_target) {
        first_target = nominal_anchors[index] + 1;
      }
    }
    if (first_target > last_target) {
      continue;
    }
    if (resumed_shift && resuming_sources
        && resume_overlap_target > first_target) {
      first_target = resume_overlap_target;
    }
    else if (resumed_shift && resuming_targets
             && resume_target > first_target) {
      first_target = resume_target;
    }
    if (first_target > last_target) {
      state->structural_reserved = 0;
      state->structural_resume_shift = 0;
      state->structural_resume_actual = 0;
      state->structural_overlap_target = 0;
      state->structural_resume_source_order = 0;
      continue;
    }
    if (scalpel_state.mode_verbose) {
      lock_fprintf(
          stdout,
          "CFBF structural displacement: header=%" PRId64
          " shift=%" PRId64 " support=%" PRIu32
          " coverage=%s target-range=%" PRIu64 "-%" PRIu64 ".\n",
          header_actual, shift, structural_support[shift_index],
          structural_shift_complete[shift_index] ? "complete" : "partial",
          first_target, last_target);
    }

    state->structural_reserved = CFBF_STRUCTURAL_RESUME_TARGET_SCAN;
    state->structural_resume_shift = shift;
    state->structural_resume_actual = first_target;
    carve_put_state((*candidate)->carvehashkey, state);
    uint64_t target = first_target;
    bool positive_trial_initialized = false;

    while (target <= last_target) {
      const bool resume_this_source = resumed_shift && resuming_sources
          && target == resume_overlap_target;
      int64_t first_source_slot = -1;
      bool prefix_overlap = false;

      state->structural_reserved = CFBF_STRUCTURAL_RESUME_TARGET_SCAN;
      state->structural_resume_shift = shift;
      state->structural_resume_actual = target;
      state->structural_overlap_target = 0;
      state->structural_resume_source_order = 0;

      if (target <= (uint64_t)INT64_MAX
          && header_actual <= INT64_MAX - (int64_t)target) {
        const int64_t nominal = header_actual + (int64_t)target;

        if (!((shift > 0 && nominal > INT64_MAX - shift)
              || (shift < 0 && nominal < -shift))) {
          const int64_t source_actual = nominal + shift;

          first_source_slot = cfbf_reassembly_mapping_index_find(
              &base_index, source_actual);
          if (first_source_slot > 0
              && (uint64_t)first_source_slot < target) {
            prefix_overlap = true;
          }
        }
      }

      CfbfTrialResult trial;

      memset(&trial, 0, sizeof(trial));
      uint64_t mapped_blocks = total_blocks;
      const bool mapped = cfbf_reassembly_build_signed_suffix_mapping(
          blockvector, base_mapping, &base_index, trial_mapping, target,
          shift, header_actual, prefix_overlap,
          shift > 0 && !prefix_overlap, &mapped_blocks);
      bool materialized = false;
      const bool complete_mapping = mapped_blocks == total_blocks;

      if (mapped) {
        if (shift > 0 && positive_trial_initialized) {
          materialized = cfbf_reassembly_update_mapping_data(
              blockvector, combined_mapping, trial_mapping,
              trial_data, length);
        }
        else {
          materialized = cfbf_reassembly_materialize_mapping(
              blockvector, trial_mapping, base_data, trial_data, length);
        }
        if (materialized && shift > 0) {
          memcpy(combined_mapping, trial_mapping,
                 (size_t)total_blocks * sizeof(*combined_mapping));
          positive_trial_initialized = true;
        }
        else if (shift > 0) {
          positive_trial_initialized = false;
        }
      }
      const bool evaluated = materialized
          && cfbf_reassembly_evaluate_data(trial_data, length, &trial);
      const bool mapped_trial_extent = evaluated
          && (complete_mapping
              || (trial.inferred_size > 0
                  && CEILDIV(trial.inferred_size, scalpel_state.blocksize)
                         <= mapped_blocks));
      bool structural_better = false;

      // Encrypted or otherwise opaque application streams can leave multiple
      // container-complete displacement boundaries indistinguishable. Preserve
      // those alternatives as PROMISING unless subtype content supplies a
      // coherence score that can rank the mappings directly.
      if (mapped_trial_extent && !prefix_overlap
          && trial.coherence_payloads == 0
          && cfbf_reassembly_trial_recoverable(&trial)) {
        (void)cfbf_reassembly_write_mapping_hypothesis(
            *candidate, state, trial_mapping, &trial, 1, true);
        base_data = (const uint8_t *)
            blockvector_get_data_pointer(blockvector);
      }

      if (mapped_trial_extent) {
        const int32_t coherence_order =
            cfbf_reassembly_compare_coherence(
                trial.coherence_payloads, trial.coherence_cost,
                trial.coherence_extent,
                state->structural_coherence_payloads,
                state->structural_coherence_cost,
                state->structural_coherence_extent);

        if (trial.score != state->structural_shift_score) {
          structural_better = trial.score > state->structural_shift_score;
        }
        else if (coherence_order != 0) {
          structural_better = coherence_order > 0;
        }
        else if (structural_support[shift_index]
                 != state->structural_shift_support) {
          structural_better = structural_support[shift_index]
                              > state->structural_shift_support;
        }
        else {
          structural_better = state->structural_shift_valid == 0
                              || target < state->structural_shift_slot;
        }
      }
      if (structural_better) {
        state->structural_shift_valid = 1;
        state->structural_shift = shift;
        state->structural_shift_slot = target;
        state->structural_shift_score = trial.score;
        state->structural_shift_support =
            structural_support[shift_index];
        state->structural_coherence_payloads = trial.coherence_payloads;
        state->structural_coherence_cost = trial.coherence_cost;
        state->structural_coherence_extent = trial.coherence_extent;
      }

      // A negative displacement can require relocating the overlapped run at
      // the same time. Test that atomic repair even when the intermediate
      // one-leg mapping is not independently recoverable; complete subtype
      // validation still governs every retained alternative.
      if (mapped && prefix_overlap && shift < 0
          && first_source_slot > 0
          && (uint64_t)first_source_slot < target) {
        const uint64_t overlap_slot = (uint64_t)first_source_slot;
        const uint64_t overlap_width = target - overlap_slot;
        const uint64_t header_block = (uint64_t)header_actual;
        const uint64_t left_distance = header_block;
        const uint64_t right_distance = image_blocks - header_block - 1;
        const uint64_t maximum_distance = left_distance > right_distance
                                              ? left_distance
                                              : right_distance;
        uint64_t source_order_limit = maximum_distance > UINT64_MAX / 2
                                          ? UINT64_MAX
                                          : maximum_distance * 2;

        if (source_order_limit > CFBF_STRUCTURAL_SOURCE_TRIAL_LIMIT) {
          source_order_limit = CFBF_STRUCTURAL_SOURCE_TRIAL_LIMIT;
        }
        uint64_t source_order = resume_this_source
                                    ? resume_source_order : 0;

        state->structural_reserved = CFBF_STRUCTURAL_RESUME_SOURCE_SCAN;
        state->structural_resume_shift = shift;
        state->structural_resume_actual = target;
        state->structural_overlap_target = target;
        state->structural_resume_source_order = source_order;
        carve_put_state((*candidate)->carvehashkey, state);

        while (source_order < source_order_limit) {
          const uint64_t distance = source_order / 2 + 1;
          const bool scan_right = (source_order & UINT64_C(1)) != 0;
          bool source_in_range = false;
          uint64_t source = 0;

          if (scan_right) {
            if (distance <= right_distance) {
              source = header_block + distance;
              source_in_range = overlap_width <= image_blocks - source;
            }
          }
          else if (distance <= left_distance) {
            source = header_block - distance;
            source_in_range = overlap_width <= image_blocks - source;
          }

          if (source_in_range && source <= (uint64_t)INT64_MAX) {
            CfbfTrialResult combined;
            const bool run_mapped = cfbf_reassembly_build_mapped_run(
                blockvector, trial_mapping, combined_mapping,
                overlap_slot, overlap_width, (int64_t)source);
            const bool run_materialized = run_mapped
                && cfbf_reassembly_materialize_mapping(
                       blockvector, combined_mapping, base_data,
                       trial_data, length);

            memset(&combined, 0, sizeof(combined));
            const bool run_evaluated = run_materialized
                && cfbf_reassembly_evaluate_data(
                       trial_data, length, &combined);
            const bool run_recoverable = run_evaluated
                && cfbf_reassembly_trial_recoverable(&combined);
            if (run_recoverable) {
              const uint64_t repair_count = overlap_width + 1;

              (void)cfbf_reassembly_write_mapping_hypothesis(
                  *candidate, state, combined_mapping, &combined,
                  repair_count > UINT32_MAX
                      ? UINT32_MAX : (uint32_t)repair_count, true);
              base_data = (const uint8_t *)
                  blockvector_get_data_pointer(blockvector);
            }
          }
          source_order++;
          state->structural_resume_source_order = source_order;
          structural_trials++;
          if ((structural_trials & UINT64_C(0x0f)) == 0
              && cfbf_reassembly_poll(
                     work, candidate, state, uuidp, uuidc)) {
            cfbf_reassembly_mapping_index_clear(&base_index);
            free(trial_data);
            free(combined_mapping);
            free(trial_mapping);
            free(base_mapping);
            return true;
          }
        }
        state->structural_reserved = CFBF_STRUCTURAL_RESUME_TARGET_SCAN;
        state->structural_overlap_target = 0;
        state->structural_resume_source_order = 0;
      }

      state->structural_resume_actual = target == UINT64_MAX
                                             ? target : target + 1;
      structural_trials++;
      if ((structural_trials & UINT64_C(0x0f)) == 0
          && cfbf_reassembly_poll(
                 work, candidate, state, uuidp, uuidc)) {
        cfbf_reassembly_mapping_index_clear(&base_index);
        free(trial_data);
        free(combined_mapping);
        free(trial_mapping);
        free(base_mapping);
        return true;
      }
      if (target == UINT64_MAX) {
        break;
      }
      target++;
    }
    state->structural_reserved = 0;
    state->structural_resume_shift = 0;
    state->structural_resume_actual = 0;
    state->structural_overlap_target = 0;
    state->structural_resume_source_order = 0;
  }

  state->structural_reserved = 0;
  state->structural_resume_shift = 0;
  state->structural_resume_actual = 0;
  state->structural_overlap_target = 0;
  state->structural_resume_source_order = 0;

  bool selected = false;
  bool selected_prefix_overlap = false;
  uint64_t selected_mapped_blocks = total_blocks;
  CfbfTrialResult selected_result;

  memset(&selected_result, 0, sizeof(selected_result));
  if (state->structural_shift_valid != 0
      && state->structural_shift_slot <= (uint64_t)INT64_MAX
      && header_actual
             <= INT64_MAX - (int64_t)state->structural_shift_slot) {
    const int64_t nominal = header_actual
                            + (int64_t)state->structural_shift_slot;
    const int64_t shift = state->structural_shift;

    if (!((shift > 0 && nominal > INT64_MAX - shift)
          || (shift < 0 && nominal < -shift))) {
      int64_t source_apparent = -1;
      int64_t source_slot = -1;

      if (cfbf_reassembly_mapping_source(
              blockvector, nominal + shift, &source_apparent, &source_slot)
          && source_slot > 0
          && (uint64_t)source_slot < state->structural_shift_slot) {
        selected_prefix_overlap = true;
      }
    }
  }
  if (state->structural_shift_valid != 0
      && state->structural_shift_slot > 0
      && state->structural_shift_slot < total_blocks) {
    bool selected_mapping_built = false;

    selected_mapping_built = cfbf_reassembly_build_signed_suffix_mapping(
        blockvector, base_mapping, &base_index, trial_mapping,
        state->structural_shift_slot, state->structural_shift,
        header_actual, selected_prefix_overlap,
        state->structural_shift > 0 && !selected_prefix_overlap,
        &selected_mapped_blocks);
    if (selected_mapping_built
        && cfbf_reassembly_materialize_mapping(
               blockvector, trial_mapping, base_data, trial_data, length)
        && cfbf_reassembly_evaluate_data(
               trial_data, length, &selected_result)
        && (selected_mapped_blocks == total_blocks
            || (selected_result.inferred_size > 0
                && CEILDIV(selected_result.inferred_size,
                           scalpel_state.blocksize)
                       <= selected_mapped_blocks))
        && cfbf_reassembly_compare_trial_results(
               &selected_result, current) > 0) {
      selected = true;
    }
  }

  state->search_phase = 0;
  state->structural_resume_actual = 0;
  state->structural_overlap_target = 0;
  state->structural_resume_source_order = 0;
  if (selected && cfbf_reassembly_trial_recoverable(&selected_result)
      && !cfbf_reassembly_trial_authenticated(&selected_result)) {
    // Allocation consistency alone cannot establish opaque stream contents.
    // Publish the hypothesis, but retain the original mapping for later searches.
    (void)cfbf_reassembly_write_mapping_hypothesis(
        *candidate, state, trial_mapping, &selected_result, 1, true);
    selected = false;
  }
  if (selected) {
    const int64_t selected_shift = state->structural_shift;
    const uint64_t selected_slot = state->structural_shift_slot;
    const uint32_t selected_support = state->structural_shift_support;

    cfbf_reassembly_commit_mapping(*candidate, state, trial_mapping,
                                   &selected_result, 1);
    state->structural_shift_valid = 1;
    state->structural_shift = selected_shift;
    state->structural_shift_slot = selected_slot;
    state->structural_shift_score = selected_result.score;
    state->structural_shift_support = selected_support;
    state->structural_coherence_payloads =
        selected_result.coherence_payloads;
    state->structural_coherence_cost = selected_result.coherence_cost;
    state->structural_coherence_extent = selected_result.coherence_extent;
    state->structural_search_complete = 1;
    state->structural_repairs = state->repairs;
    carve_put_state((*candidate)->carvehashkey, state);
    *improved = true;
  }
  else {
    state->structural_shift_valid = 0;
    state->structural_shift = 0;
    state->structural_shift_slot = 0;
    state->structural_shift_score = 0;
    state->structural_shift_support = 0;
    state->structural_coherence_payloads = 0;
    state->structural_coherence_cost = 0;
    state->structural_coherence_extent = 0;
    state->structural_search_complete = 1;
    state->structural_repairs = state->repairs;
  }
  cfbf_reassembly_mapping_index_clear(&base_index);
  free(trial_data);
  free(combined_mapping);
  free(trial_mapping);
  free(base_mapping);
  return false;
}

// Try a bounded union of source runs ordered independently by subtype model
// confidence, generic Office confidence, and byte continuity. Every mapping is
// still parsed by the complete CFBF and subtype validators. The later isolated
// and exhaustive phases remain unchanged and therefore preserve completeness.
//
static inline bool cfbf_reassembly_try_ranked_runs(
    ThreadWork *work, CarveInfo **candidate, CfbfCarveState *state,
    const CfbfTrialResult *current, uint64_t target_hint,
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
  const uint64_t length = blockvector_get_data_length(blockvector);
  uint64_t target_blocks = !current->structurally_valid
                               || current->inferred_size == 0
      ? total_blocks : CEILDIV(current->inferred_size,
                               scalpel_state.blocksize);

  if (total_blocks < 2 || image_blocks == 0 || length == 0) {
    return false;
  }
  if (target_blocks < 2 || target_blocks > total_blocks) {
    target_blocks = total_blocks;
  }

  int64_t *base_mapping = (int64_t *)malloc(
      (size_t)total_blocks * sizeof(*base_mapping));
  int64_t *trial_mapping = (int64_t *)malloc(
      (size_t)total_blocks * sizeof(*trial_mapping));
  uint8_t *trial_data = (uint8_t *)malloc((size_t)length);
  uint64_t *target_slots = (uint64_t *)malloc(
      (size_t)total_blocks * sizeof(*target_slots));

  check_memory_allocation(base_mapping, __LINE__, __FILE__,
                          "CFBF ranked-run base mapping");
  check_memory_allocation(trial_mapping, __LINE__, __FILE__,
                          "CFBF ranked-run trial mapping");
  check_memory_allocation(trial_data, __LINE__, __FILE__,
                          "CFBF ranked-run trial data");
  check_memory_allocation(target_slots, __LINE__, __FILE__,
                          "CFBF ranked-run target slots");
  for (uint64_t slot = 0; slot < total_blocks; slot++) {
    base_mapping[slot] = blockvector_get_apparent_blocknumber(
        blockvector, slot);
  }
  const uint8_t *base_data = (const uint8_t *)
      blockvector_get_data_pointer(blockvector);

  if (!base_data) {
    free(target_slots);
    free(trial_data);
    free(trial_mapping);
    free(base_mapping);
    return false;
  }
  memcpy(trial_data, base_data, (size_t)length);

  CfbfLayout base_layout;
  memset(&base_layout, 0, sizeof(base_layout));
  const bool semantic_prefilter_available =
      cfbf_reassembly_trial_complete(current)
      && cfbf_parse(base_data, length, &base_layout)
      && base_layout.profile != CFBF_PROFILE_UNKNOWN;
  const bool relaxed_biff_target = current->profile == CFBF_PROFILE_XLS
                                   || current->profile == CFBF_PROFILE_XLT
                                   || current->profile == CFBF_PROFILE_XLA;
  const bool scan_all_biff_targets = relaxed_biff_target
                                     && current->structurally_valid;
  const bool scan_all_repaired_targets = state->repairs > 0;
  const bool require_isolated_target = current->structurally_valid
                                       && !relaxed_biff_target;
  bool resuming = state->search_phase == CFBF_REASSEMBLY_RANKED_RUNS;

  if (!resuming) {
    cfbf_reassembly_reset_repair_candidates(state);
    state->resume_run_width = 2;
    state->resume_slot = 1;
    state->resume_choice = 0;
    state->resume_run_left = 0;
    state->resume_source_pass = 0;
  }
  state->search_phase = CFBF_REASSEMBLY_RANKED_RUNS;

  uint64_t maximum_width = CFBF_NEARBY_RUN_WIDTH_LIMIT;

  if (maximum_width >= total_blocks) {
    maximum_width = total_blocks - 1;
  }
  uint64_t first_width_order = 0;

  if (resuming && state->resume_run_width == 1) {
    first_width_order = maximum_width - 1;
  }
  else if (resuming && state->resume_run_width >= 2
           && state->resume_run_width <= maximum_width) {
    first_width_order = state->resume_run_width - 2;
  }
  uint64_t polls = 0;

  for (uint64_t width_order = first_width_order;
       width_order < maximum_width; width_order++) {
    uint64_t width = width_order + 2;

    if (width > maximum_width) {
      width = 1;
    }
    state->resume_run_width = width;
    uint64_t target_count = 0;

    for (uint64_t target_slot = 1;
         target_slot + width <= target_blocks; target_slot++) {
      if (!require_isolated_target && !scan_all_biff_targets
          && !scan_all_repaired_targets
          && target_hint > 0
          && (target_slot > target_hint
              || target_hint >= target_slot + width)) {
        continue;
      }
      const uint64_t target_concentration =
          cfbf_reassembly_mapping_concentration(
              base_mapping, target_slot, width);
      const bool target_strong = target_concentration
          <= CFBF_STRONG_FILLER_CONCENTRATION_LIMIT;
      const bool target_isolated = cfbf_reassembly_mapping_run_isolated(
          base_mapping, total_blocks, target_slot, width);
      const bool target_candidate = scan_all_repaired_targets
          || (target_concentration <= CFBF_UNIFORM_CONCENTRATION_LIMIT
              && (!require_isolated_target
                  || target_strong || target_isolated));

      if (target_candidate) {
        target_slots[target_count++] = target_slot;
      }
      polls++;
      if ((polls & UINT64_C(0x3ff)) == 0
          && cfbf_reassembly_poll(
                 work, candidate, state, uuidp, uuidc)) {
        cfbf_layout_clear(&base_layout);
        free(target_slots);
        free(trial_data);
        free(trial_mapping);
        free(base_mapping);
        return true;
      }
    }

    uint64_t first_target_index = 0;

    if (resuming && state->resume_slot > 1) {
      while (first_target_index < target_count
             && target_slots[first_target_index] < state->resume_slot) {
        first_target_index++;
      }
    }
    for (uint64_t target_index = first_target_index;
         target_index < target_count; target_index++) {
      const uint64_t target_slot = target_slots[target_index];
      CfbfRankedSource ranked_sources[CFBF_RANKED_SOURCE_LIMIT * 4];
      const uint32_t ranked_count = cfbf_reassembly_collect_ranked_sources(
          blockvector, base_mapping, target_slot, width, current->profile,
          ranked_sources, CFBF_RANKED_SOURCE_LIMIT * 4);

      state->resume_slot = target_slot;
      state->resume_choice = 0;
      for (uint32_t source_index = 0;
           source_index < ranked_count; source_index++) {
        const int64_t source_actual =
            (int64_t)ranked_sources[source_index].actual;
        CfbfTrialResult trial;

        if (cfbf_reassembly_evaluate_run_repair(
                blockvector, state, current, &base_layout,
                semantic_prefilter_available, base_mapping, trial_mapping,
                base_data, trial_data, length, target_slot, width,
                source_actual, &trial)
            && cfbf_reassembly_trial_authenticated(&trial)) {
          const uint32_t repairs = width > UINT32_MAX
              ? UINT32_MAX : (uint32_t)width;

          if (!cfbf_reassembly_branch_partial_suffix(
                  *candidate, state, current, trial_mapping,
                  &trial, repairs)) {
            (void)cfbf_reassembly_share_alternate(
                work, candidate, state, base_mapping, base_data, length);
            cfbf_reassembly_commit_mapping(
                *candidate, state, trial_mapping, &trial, repairs);
            state->search_phase = CFBF_REASSEMBLY_FINALIZED;
            carve_put_state((*candidate)->carvehashkey, state);
          }
          *improved = true;
          cfbf_layout_clear(&base_layout);
          free(target_slots);
          free(trial_data);
          free(trial_mapping);
          free(base_mapping);
          return false;
        }
        polls++;
        if ((polls & UINT64_C(0x1f)) == 0
            && cfbf_reassembly_poll(
                   work, candidate, state, uuidp, uuidc)) {
          cfbf_layout_clear(&base_layout);
          free(target_slots);
          free(trial_data);
          free(trial_mapping);
          free(base_mapping);
          return true;
        }
      }
      state->resume_slot = target_slot + 1;
      state->resume_choice = 0;
      resuming = false;
    }
    state->resume_slot = 1;
    state->resume_choice = 0;
    state->resume_run_width = width == 1 ? 0 : width + 1;
  }

  CfbfTrialResult hypothesis;
  memset(&hypothesis, 0, sizeof(hypothesis));
  const bool have_hypothesis = state->repair_candidate_valid != 0
      && cfbf_reassembly_build_run_mapping(
             blockvector, base_mapping, trial_mapping,
             state->repair_candidate_slot, state->repair_candidate_width,
             (int64_t)state->repair_candidate_actual)
      && cfbf_reassembly_materialize_mapping(
             blockvector, trial_mapping, base_data, trial_data, length)
      && cfbf_reassembly_evaluate_data(trial_data, length, &hypothesis)
      && cfbf_reassembly_trial_recoverable(&hypothesis);

  const int64_t header_actual = blockvector_get_actual_blocknumber(
      blockvector, 0);
  const uint64_t expanded_extent = cfbf_header_search_extent(
      base_data, length, state->inferred_size);
  const uint64_t expanded_blocks = CEILDIV(
      expanded_extent, scalpel_state.blocksize);
  const uint64_t available_blocks = header_actual >= 0
                                        && (uint64_t)header_actual
                                               < image_blocks
                                    ? image_blocks - (uint64_t)header_actual
                                    : 0;

  // Allocation metadata can prove that the first bounded candidate is too
  // short even when no single-run repair is yet recoverable. Restart against
  // that larger header-bounded extent before advancing to broader searches.
  // Initialization does not expand semantically strong candidates. Reporting
  // improvement for those candidates would repeat this unchanged search.
  if (!have_hypothesis
      && state->semantic_strength != CFBF_SEMANTIC_STRONG
      && expanded_blocks > total_blocks
      && expanded_blocks < available_blocks) {
    cfbf_reassembly_reset_repair_candidates(state);
    state->search_phase = 0;
    state->resume_slot = 0;
    state->resume_choice = 0;
    state->resume_run_width = 0;
    state->resume_run_left = 0;
    state->resume_source_pass = 0;
    carve_put_state((*candidate)->carvehashkey, state);
    *improved = true;
    cfbf_layout_clear(&base_layout);
    free(target_slots);
    free(trial_data);
    free(trial_mapping);
    free(base_mapping);
    return false;
  }

  if (have_hypothesis) {
    const uint32_t repairs = state->repair_candidate_width > UINT32_MAX
        ? UINT32_MAX : (uint32_t)state->repair_candidate_width;

    (void)cfbf_reassembly_write_mapping_hypothesis(
        *candidate, state, trial_mapping, &hypothesis, repairs, true);
    base_data = (const uint8_t *)
        blockvector_get_data_pointer(blockvector);
  }

  // A displaced run can border unrelated file data on one side. Preserve the
  // strongest recoverable hypothesis from that independent ranking view.
  const CfbfRepairCandidate *boundary = &state->repair_alternate;
  CfbfTrialResult boundary_hypothesis;

  memset(&boundary_hypothesis, 0, sizeof(boundary_hypothesis));
  const bool duplicate_boundary_primary = state->repair_candidate_valid != 0
      && boundary->slot == state->repair_candidate_slot
      && boundary->width == state->repair_candidate_width
      && boundary->actual == state->repair_candidate_actual;
  const bool have_boundary_hypothesis = boundary->valid != 0
      && boundary->source_isolation
             == CFBF_DETACHED_SOURCE_WEAK_BOUNDARY
      && !duplicate_boundary_primary
      && cfbf_reassembly_build_run_mapping(
             blockvector, base_mapping, trial_mapping,
             boundary->slot, boundary->width,
             (int64_t)boundary->actual)
      && cfbf_reassembly_materialize_mapping(
             blockvector, trial_mapping, base_data, trial_data, length)
      && cfbf_reassembly_evaluate_data(
             trial_data, length, &boundary_hypothesis)
      && cfbf_reassembly_trial_recoverable(&boundary_hypothesis);

  if (have_boundary_hypothesis) {
    const uint32_t repairs = boundary->width > UINT32_MAX
        ? UINT32_MAX : (uint32_t)boundary->width;

    (void)cfbf_reassembly_write_mapping_hypothesis(
        *candidate, state, trial_mapping, &boundary_hypothesis, repairs,
        true);
    base_data = (const uint8_t *)
        blockvector_get_data_pointer(blockvector);
    if (scalpel_state.mode_verbose) {
      lock_fprintf(
          stdout,
          "CFBF detached boundary hypothesis preserved: header=%" PRId64
          " slot=%" PRIu64 " width=%" PRIu64 " source=%" PRIu64
          " profile=%s.\n",
          blockvector_get_actual_blocknumber(blockvector, 0),
          boundary->slot, boundary->width, boundary->actual,
          cfbf_profile_filetype(boundary_hypothesis.profile));
    }
  }

  const CfbfRepairCandidate *semantic = &state->repair_semantic;
  const bool semantic_is_primary = semantic->valid != 0
      && semantic->slot == state->repair_candidate_slot
      && semantic->width == state->repair_candidate_width
      && semantic->actual == state->repair_candidate_actual;
  const bool semantic_is_boundary = semantic->valid != 0
      && boundary->valid != 0
      && semantic->slot == boundary->slot
      && semantic->width == boundary->width
      && semantic->actual == boundary->actual;

  if (semantic->valid != 0 && !semantic_is_primary
      && !semantic_is_boundary) {
    (void)cfbf_reassembly_write_repair_hypothesis(
        *candidate, state, base_mapping, trial_mapping, base_data,
        trial_data, length, semantic);
    base_data = (const uint8_t *)
        blockvector_get_data_pointer(blockvector);
  }

  // Opaque streams can leave several structurally recoverable source islands
  // indistinguishable. Preserve the bounded clean-island alternatives as
  // PROMISING.
  for (uint32_t index = 0;
       index < CFBF_ISOLATED_HYPOTHESIS_LIMIT
       && state->repair_isolated[index].valid != 0; index++) {
    const CfbfRepairCandidate *isolated = &state->repair_isolated[index];
    CfbfTrialResult isolated_hypothesis;

    memset(&isolated_hypothesis, 0, sizeof(isolated_hypothesis));
    const bool duplicate_primary = state->repair_candidate_valid != 0
        && isolated->slot == state->repair_candidate_slot
        && isolated->width == state->repair_candidate_width
        && isolated->actual == state->repair_candidate_actual;
    const bool duplicate_semantic = semantic->valid != 0
        && isolated->slot == semantic->slot
        && isolated->width == semantic->width
        && isolated->actual == semantic->actual;
    const bool have_isolated_hypothesis = !duplicate_primary
        && !duplicate_semantic
        && cfbf_reassembly_build_run_mapping(
               blockvector, base_mapping, trial_mapping,
               isolated->slot, isolated->width,
               (int64_t)isolated->actual)
        && cfbf_reassembly_materialize_mapping(
               blockvector, trial_mapping, base_data, trial_data, length)
        && cfbf_reassembly_evaluate_data(
               trial_data, length, &isolated_hypothesis)
        && cfbf_reassembly_trial_recoverable(&isolated_hypothesis);

    if (have_isolated_hypothesis) {
      const uint32_t repairs = isolated->width > UINT32_MAX
          ? UINT32_MAX : (uint32_t)isolated->width;

      (void)cfbf_reassembly_write_mapping_hypothesis(
          *candidate, state, trial_mapping, &isolated_hypothesis, repairs,
          true);
      base_data = (const uint8_t *)
          blockvector_get_data_pointer(blockvector);
      if (scalpel_state.mode_verbose) {
        lock_fprintf(
            stdout,
            "CFBF detached hypothesis preserved: header=%" PRId64
            " rank=%" PRIu32 " slot=%" PRIu64 " width=%" PRIu64
            " source=%" PRIu64 " profile=%s.\n",
            blockvector_get_actual_blocknumber(blockvector, 0), index,
            isolated->slot, isolated->width, isolated->actual,
            cfbf_profile_filetype(isolated_hypothesis.profile));
      }
    }
  }

  // Ranked evidence accelerates discovery but must not displace alternatives
  // retained by the complete search for opaque, unauthenticated file content.
  cfbf_reassembly_reset_repair_candidates(state);
  state->search_phase = 7;
  state->resume_slot = 1;
  state->resume_choice = 0;
  state->resume_run_width = 2;
  state->resume_run_left = 0;
  state->resume_source_pass = 0;
  carve_put_state((*candidate)->carvehashkey, state);

  cfbf_layout_clear(&base_layout);
  free(target_slots);
  free(trial_data);
  free(trial_mapping);
  free(base_mapping);
  return false;
}

// Test every image-bounded whole-block suffix displacement. This directly
// models an inserted run between two portions of a compound file and avoids
// committing any hypothesis that does not improve validation evidence.
//
static inline bool cfbf_reassembly_try_suffix_shifts(
    ThreadWork *work, CarveInfo **candidate, CfbfCarveState *state,
    const CfbfTrialResult *current, uint64_t target_slot,
    uint64_t minimum_shift, uint64_t shift_limit,
    uuid_string_t uuidp, uuid_string_t uuidc, bool *improved,
    bool *validated) {

  if (!work || !candidate || !*candidate || !(*candidate)->b || !state
      || !current || !improved || !validated) {
    return false;
  }
  *improved = false;
  *validated = false;

  BlockVector *blockvector = (*candidate)->b;
  const uint64_t total_blocks = blockvector_get_num_blocks(blockvector);
  const uint64_t image_blocks = CEILDIV(
      filemirror_filesize(scalpel_state.filemirror), scalpel_state.blocksize);
  const int64_t header_actual = blockvector_get_actual_blocknumber(
      blockvector, 0);
  const uint64_t length = blockvector_get_data_length(blockvector);

  if (target_slot == 0 || target_slot >= total_blocks || header_actual < 0
      || (uint64_t)header_actual >= image_blocks
      || total_blocks > image_blocks - (uint64_t)header_actual
      || length == 0
      || (shift_limit != 0 && minimum_shift > shift_limit)) {
    return false;
  }
  // A provisional candidate can extend to the end of the image even when
  // the parser's inferred file extent is shorter. Permit a shifted suffix
  // as long as its first block exists; the mapped-prefix check below proves
  // that every block required by the inferred extent is available.
  uint64_t maximum_shift = image_blocks
                           - (uint64_t)header_actual - target_slot - 1;

  if (shift_limit != 0 && maximum_shift > shift_limit) {
    maximum_shift = shift_limit;
  }
  int64_t *base_mapping = (int64_t *)malloc(
      (size_t)total_blocks * sizeof(*base_mapping));
  int64_t *trial_mapping = (int64_t *)malloc(
      (size_t)total_blocks * sizeof(*trial_mapping));
  int64_t *best_mapping = (int64_t *)malloc(
      (size_t)total_blocks * sizeof(*best_mapping));
  uint8_t *trial_data = (uint8_t *)malloc((size_t)length);

  check_memory_allocation(base_mapping, __LINE__, __FILE__,
                          "CFBF base suffix mapping");
  check_memory_allocation(trial_mapping, __LINE__, __FILE__,
                          "CFBF trial suffix mapping");
  check_memory_allocation(best_mapping, __LINE__, __FILE__,
                          "CFBF best suffix mapping");
  check_memory_allocation(trial_data, __LINE__, __FILE__,
                          "CFBF suffix trial data");
  for (uint64_t slot = 0; slot < total_blocks; slot++) {
    base_mapping[slot] = blockvector_get_apparent_blocknumber(
        blockvector, slot);
    best_mapping[slot] = base_mapping[slot];
  }
  const uint8_t *base_data = (const uint8_t *)
      blockvector_get_data_pointer(blockvector);

  CfbfTrialResult best_result = *current;
  uint64_t first_shift = minimum_shift == 0 ? 1 : minimum_shift;

  if (state->search_phase == 1 && state->resume_slot == target_slot
      && state->resume_choice > first_shift) {
    first_shift = state->resume_choice;
  }
  state->search_phase = 1;
  state->resume_slot = target_slot;
  bool supported_gap = true;

  if (shift_limit == 0 && first_shift > 1) {
    for (uint64_t prior_shift = 1;
         prior_shift < first_shift && supported_gap; prior_shift++) {
      const int64_t skipped_actual = header_actual
                                     + (int64_t)target_slot
                                     + (int64_t)prior_shift - 1;

      supported_gap = cfbf_reassembly_block_is_uniform(skipped_actual)
          || filemirror_actual_block_covered(
                 scalpel_state.filemirror, skipped_actual);
    }
  }

  for (uint64_t shift = first_shift; shift <= maximum_shift; shift++) {
    const int64_t skipped_actual = header_actual
                                   + (int64_t)target_slot
                                   + (int64_t)shift - 1;

    if (!cfbf_reassembly_block_is_uniform(skipped_actual)
        && !filemirror_actual_block_covered(
               scalpel_state.filemirror, skipped_actual)) {
      supported_gap = false;
    }
    if (shift_limit == 0
        && shift > CFBF_NEARBY_SUFFIX_SHIFT_LIMIT
        && !supported_gap) {
      break;
    }
    uint64_t mapped_blocks = 0;
    bool available = cfbf_reassembly_build_suffix_mapping_prefix(
        blockvector, base_mapping, trial_mapping, target_slot, shift,
        header_actual, true, &mapped_blocks);

    CfbfTrialResult trial;

    memset(&trial, 0, sizeof(trial));

    if (available
        && cfbf_reassembly_materialize_mapping(
               blockvector, trial_mapping, base_data, trial_data, length)) {
      if (!cfbf_reassembly_evaluate_data(trial_data, length, &trial)) {
        available = false;
      }
      if (available && mapped_blocks < total_blocks
          && (trial.inferred_size == 0
              || CEILDIV(trial.inferred_size, scalpel_state.blocksize)
                     > mapped_blocks)) {
        available = false;
      }

      if (available && shift_limit != 0
          && trial.score >= current->score) {
        // Keep the strongest supported split in restartable state. The
        // exhaustive scan still evaluates every split, while delayed emission
        // avoids materializing a separate file for each ambiguous boundary.
        bool has_confidence = false;
        bool all_positive = false;
        int64_t confidence_gain = 0;
        uint32_t reserved = 0;
        const uint64_t run_blocks = total_blocks - target_slot;
        const int64_t source_actual = header_actual
                                      + (int64_t)target_slot
                                      + (int64_t)shift;
        const uint64_t concentration =
            cfbf_reassembly_run_concentration(
                header_actual + (int64_t)target_slot, shift);
        const CfbfProfile confidence_profile =
            trial.profile != CFBF_PROFILE_UNKNOWN
                ? trial.profile : current->profile;
        const int64_t boundary_evidence =
            cfbf_reassembly_suffix_boundary_evidence(
                header_actual + (int64_t)target_slot, shift,
                confidence_profile);
        const bool physical_advance = concentration
                  <= CFBF_STRONG_FILLER_CONCENTRATION_LIMIT
            && boundary_evidence >= CFBF_MINIMUM_BOUNDARY_EVIDENCE;

        const uint64_t recovered_blocks = trial.inferred_size == 0
            ? total_blocks
            : CEILDIV(trial.inferred_size, scalpel_state.blocksize);

        if (cfbf_reassembly_trial_recoverable(&trial)
            && target_slot < recovered_blocks) {
          const CfbfSuffixHypothesis hypothesis = {
            .valid = 1,
            .has_confidence = 0,
            .all_positive = 0,
            .reserved = 0,
            .slot = target_slot,
            .shift = shift,
            .score = trial.score,
            .concentration = concentration,
            .confidence_gain = 0,
            .boundary_evidence = boundary_evidence,
            .result = trial
          };

          const uint32_t retention_limit = current->structurally_valid
              ? CFBF_SUFFIX_HYPOTHESIS_LIMIT
              : CFBF_ATOMIC_PREFERRED_GAP_LIMIT;

          cfbf_reassembly_retain_suffix_hypothesis(
              state, &hypothesis, retention_limit);
        }

        if (trial.score > current->score || physical_advance) {
          cfbf_reassembly_run_metrics(
              blockvector, NULL, target_slot, run_blocks, source_actual,
              confidence_profile, &has_confidence, &all_positive,
              &confidence_gain, &reserved, NULL);
          cfbf_reassembly_remember_suffix(
              state, target_slot, shift, &trial, has_confidence,
              all_positive, confidence_gain, reserved, concentration,
              boundary_evidence);
          if (trial.structurally_valid
              && trial.profile != CFBF_PROFILE_UNKNOWN
              && !cfbf_reassembly_trial_complete(&trial)) {
            state->pair_suffix_possible = 1;
          }
        }
      }
      else if (available && trial.score > current->score
               && cfbf_reassembly_trial_complete(&trial)) {
        cfbf_reassembly_commit_mapping(*candidate, state, trial_mapping,
                                       &trial, 1);
        *improved = true;
        free(trial_data);
        free(best_mapping);
        free(trial_mapping);
        free(base_mapping);
        return false;
      }
      if (available && trial.score > best_result.score) {
        best_result = trial;
        memcpy(best_mapping, trial_mapping,
               (size_t)total_blocks * sizeof(*best_mapping));
      }
    }

    state->resume_choice = shift + 1;
    if ((shift & UINT64_C(0x3f)) == 0) {
      const uint64_t next_shift = state->resume_choice;

      // Only the unbounded scan commits its local best mapping. Bounded
      // scans retain hypotheses in checkpointed state and resume in place.
      if (shift_limit == 0 && best_result.score > current->score) {
        state->resume_choice = 1;
      }
      if (cfbf_reassembly_poll(work, candidate, state, uuidp, uuidc)) {
        free(trial_data);
        free(best_mapping);
        free(trial_mapping);
        free(base_mapping);
        return true;
      }
      state->resume_choice = next_shift;
    }
  }

  if (shift_limit != 0) {
    state->search_phase = 3;
    state->resume_slot = 0;
    state->resume_choice = 0;
    free(trial_data);
    free(best_mapping);
    free(trial_mapping);
    free(base_mapping);
    return false;
  }

  const bool acceptable = best_result.score > current->score;

  if (acceptable) {
    cfbf_reassembly_commit_mapping(*candidate, state, best_mapping,
                                   &best_result, 1);
    *improved = true;
  }
  else {
    state->search_phase = 3;
    state->resume_slot = 0;
    state->resume_choice = 0;
  }
  free(trial_data);
  free(best_mapping);
  free(trial_mapping);
  free(base_mapping);
  return false;
}

// Rank nearby whole-suffix gap hypotheses at parser-indicated or filler-like
// positions. This bounded pass does not replace a complete primary mapping;
// it only records an alternative or an objectively advancing partial repair.
//
static inline bool cfbf_reassembly_probe_supported_suffixes(
    ThreadWork *work, CarveInfo **candidate, CfbfCarveState *state,
    const CfbfTrialResult *current, uint64_t targeted_slot,
    uuid_string_t uuidp, uuid_string_t uuidc) {

  if (!work || !candidate || !*candidate || !(*candidate)->b || !state
      || !current) {
    return false;
  }
  const uint64_t total_blocks = blockvector_get_num_blocks((*candidate)->b);
  const uint64_t image_blocks = CEILDIV(
      filemirror_filesize(scalpel_state.filemirror), scalpel_state.blocksize);
  const int64_t header_actual = blockvector_get_actual_blocknumber(
      (*candidate)->b, 0);

  if (total_blocks < 2 || header_actual < 0) {
    return false;
  }
  const bool resuming = (state->search_phase == 1
                         || state->search_phase == 6)
                        && state->suffix_pass == 6;
  uint64_t first_slot = 1;

  if (!resuming) {
    state->pair_suffix_possible = 0;
    cfbf_reassembly_reset_suffix_candidate(state);
  }
  else if (state->resume_slot > 0
           && state->resume_slot < total_blocks) {
    first_slot = state->resume_slot;
  }
  else if (state->resume_slot >= total_blocks) {
    state->search_phase = 0;
    state->suffix_pass = 0;
    state->resume_slot = 0;
    state->resume_choice = 0;
    return false;
  }

  state->suffix_pass = 6;
  for (uint64_t suffix_slot = first_slot;
       suffix_slot < total_blocks; suffix_slot++) {
    const int64_t actual = blockvector_get_actual_blocknumber(
        (*candidate)->b, suffix_slot);
    const int64_t nominal = header_actual + (int64_t)suffix_slot;
    int64_t signal_actual = actual;

    // Zero blocks have no apparent mapping. Use the physical position of the
    // contiguous baseline so an inserted zero run remains visible as a gap
    // signal even when the parser detects the resulting damage later.
    if (signal_actual < 0 && nominal >= 0
        && (uint64_t)nominal < image_blocks
        && (filemirror_actual_block_is_zero(
                scalpel_state.filemirror, nominal)
            || filemirror_actual_block_covered(
                   scalpel_state.filemirror, nominal))) {
      signal_actual = nominal;
    }
    const bool likely_gap = suffix_slot == targeted_slot
        || (signal_actual >= 0
            && (cfbf_reassembly_block_is_uniform(signal_actual)
                || filemirror_actual_block_covered(
                       scalpel_state.filemirror, signal_actual)));
    uint64_t minimum_shift = 1;
    uint64_t shift_limit = CFBF_NEARBY_SUFFIX_SHIFT_LIMIT;
    uint64_t supported_run = 0;

    if (signal_actual >= 0 && (uint64_t)signal_actual < image_blocks) {
      const bool covered = filemirror_actual_block_covered(
          scalpel_state.filemirror, signal_actual);
      const bool zero = !covered
          && filemirror_actual_block_is_zero(
                 scalpel_state.filemirror, signal_actual);
      const bool uniform = !covered
          && cfbf_reassembly_block_is_uniform(signal_actual);

      if (covered || uniform) {
        uint64_t run_actual = (uint64_t)signal_actual;

        while (run_actual < image_blocks) {
          const bool run_covered = filemirror_actual_block_covered(
              scalpel_state.filemirror, (int64_t)run_actual);
          const bool run_zero = !run_covered
              && filemirror_actual_block_is_zero(
                     scalpel_state.filemirror, (int64_t)run_actual);
          const bool same_signal = covered ? run_covered
              : (zero ? run_zero
                      : (!run_zero
                         && cfbf_reassembly_block_is_uniform(
                                (int64_t)run_actual)));

          if (!same_signal) {
            break;
          }
          supported_run++;
          run_actual++;
        }

        if (supported_run > 0 && signal_actual >= nominal
            && (uint64_t)(signal_actual - nominal)
                   <= UINT64_MAX - supported_run) {
          const uint64_t signal_delta =
              (uint64_t)(signal_actual - nominal);

          // Covered blocks are unavailable as one complete run. An
          // unowned zero or uniform run can include legitimate file padding,
          // so validation must consider every possible nonempty gap prefix.
          minimum_shift = covered ? signal_delta + supported_run
                                  : signal_delta + 1;
          shift_limit = signal_delta + supported_run;
        }
      }
    }
    bool improved = false;
    bool validated = false;

    if (likely_gap
        && cfbf_reassembly_try_suffix_shifts(
               work, candidate, state, current, suffix_slot,
               minimum_shift, shift_limit, uuidp, uuidc,
               &improved, &validated)) {
      return true;
    }
    if (!*candidate) {
      return true;
    }
    state->search_phase = 6;
    state->suffix_pass = 6;
    state->resume_slot = suffix_slot + 1;
    state->resume_choice = 1;
    if (cfbf_reassembly_poll(work, candidate, state, uuidp, uuidc)) {
      return true;
    }
  }
  state->search_phase = 0;
  state->suffix_pass = 0;
  state->resume_slot = 0;
  state->resume_choice = 0;
  return false;
}

// Search for an ordered run displaced elsewhere in the image. Ranked model and
// continuity evidence provide the fast pass; the restartable traversal that
// follows examines every image-bounded source run. Every selected mapping must
// still satisfy the complete CFBF and subtype validators.
//
static inline bool cfbf_reassembly_try_complete_run_search(
    ThreadWork *work, CarveInfo **candidate, CfbfCarveState *state,
    const CfbfTrialResult *current, uint64_t target_hint,
    uuid_string_t uuidp,
    uuid_string_t uuidc, bool *improved, bool *validated) {

  if (!work || !candidate || !*candidate || !(*candidate)->b || !state
      || !current || !improved || !validated) {
    return false;
  }
  *improved = false;
  *validated = false;

  BlockVector *blockvector = (*candidate)->b;
  const uint64_t total_blocks = blockvector_get_num_blocks(blockvector);
  const uint64_t image_blocks = CEILDIV(
      filemirror_filesize(scalpel_state.filemirror), scalpel_state.blocksize);
  const uint64_t length = blockvector_get_data_length(blockvector);
  uint64_t target_blocks = !current->structurally_valid
                               || current->inferred_size == 0
      ? total_blocks : CEILDIV(current->inferred_size,
                               scalpel_state.blocksize);

  if (total_blocks < 2 || image_blocks == 0 || length == 0) {
    return false;
  }
  if (target_blocks < 2 || target_blocks > total_blocks) {
    target_blocks = total_blocks;
  }

  if (state->search_phase != 7) {
    bool ranked_improved = false;

    if (cfbf_reassembly_try_ranked_runs(
            work, candidate, state, current, target_hint, uuidp, uuidc,
            &ranked_improved)) {
      return true;
    }
    if (ranked_improved || !*candidate) {
      *improved = ranked_improved;
      return false;
    }
  }

  int64_t *base_mapping = (int64_t *)malloc(
      (size_t)total_blocks * sizeof(*base_mapping));
  int64_t *trial_mapping = (int64_t *)malloc(
      (size_t)total_blocks * sizeof(*trial_mapping));
  uint8_t *trial_data = (uint8_t *)malloc((size_t)length);

  check_memory_allocation(base_mapping, __LINE__, __FILE__,
                          "CFBF complete-run base mapping");
  check_memory_allocation(trial_mapping, __LINE__, __FILE__,
                          "CFBF complete-run trial mapping");
  check_memory_allocation(trial_data, __LINE__, __FILE__,
                          "CFBF complete-run trial data");
  for (uint64_t slot = 0; slot < total_blocks; slot++) {
    base_mapping[slot] = blockvector_get_apparent_blocknumber(
        blockvector, slot);
  }
  const uint8_t *base_data = (const uint8_t *)
      blockvector_get_data_pointer(blockvector);
  CfbfLayout base_layout;

  if (!base_data) {
    free(trial_data);
    free(trial_mapping);
    free(base_mapping);
    return false;
  }
  memcpy(trial_data, base_data, (size_t)length);

  memset(&base_layout, 0, sizeof(base_layout));
  const bool semantic_prefilter_available =
      cfbf_reassembly_trial_complete(current)
      && cfbf_parse(base_data, length, &base_layout)
      && base_layout.profile != CFBF_PROFILE_UNKNOWN;
  const bool relaxed_biff_target = current->profile == CFBF_PROFILE_XLS
                                   || current->profile == CFBF_PROFILE_XLT
                                   || current->profile == CFBF_PROFILE_XLA;
  const bool scan_all_biff_targets = relaxed_biff_target
                                     && current->structurally_valid;
  const bool scan_all_repaired_targets = state->repairs > 0;
  const bool require_isolated_target = current->structurally_valid
                                       && !relaxed_biff_target;
  bool resuming = state->search_phase == 7;

  if (!resuming) {
    cfbf_reassembly_reset_repair_candidates(state);
    state->resume_slot = 1;
    state->resume_run_width = 1;
    state->resume_choice = 0;
    state->resume_source_pass = 0;
  }
  state->search_phase = 7;

  uint64_t *target_slots = (uint64_t *)malloc(
      (size_t)total_blocks * sizeof(*target_slots));

  check_memory_allocation(target_slots, __LINE__, __FILE__,
                          "CFBF isolated-run target slots");
  uint64_t maximum_width = CFBF_NEARBY_RUN_WIDTH_LIMIT;

  if (maximum_width >= total_blocks) {
    maximum_width = total_blocks - 1;
  }
  uint64_t first_width_order = 0;

  if (resuming && state->resume_run_width == 1) {
    first_width_order = maximum_width - 1;
  }
  else if (resuming && state->resume_run_width >= 2
           && state->resume_run_width <= maximum_width) {
    first_width_order = state->resume_run_width - 2;
  }
  uint64_t polls = 0;

  // Multi-block islands are both more selective and more expensive to miss.
  // Test widths 2..N first, then the noisier one-block island population.
  for (uint64_t width_order = first_width_order;
       width_order < maximum_width; width_order++) {
    uint64_t width = width_order + 2;

    if (width > maximum_width) {
      width = 1;
    }
    state->resume_run_width = width;
    uint64_t target_count = 0;

    // Build the exact filler-island list once per width. The source-oriented
    // loop below then scans the image only once for that width.
    for (uint64_t target_slot = 1;
         target_slot + width <= target_blocks; target_slot++) {
      // Compressed BIFF records can place a displaced run directly beside
      // high-entropy workbook data, so their structurally valid candidates
      // retain the complete target scan.
      if (!require_isolated_target && !scan_all_biff_targets
          && !scan_all_repaired_targets
          && target_hint > 0
          && (target_slot > target_hint
              || target_hint >= target_slot + width)) {
        continue;
      }
      const uint64_t target_concentration =
          cfbf_reassembly_mapping_concentration(
              base_mapping, target_slot, width);

      // Compressed file blocks can resemble random filler. A strongly uniform
      // target is therefore sufficient evidence even when either neighboring
      // file block has a similar byte distribution.
      const bool target_strong = target_concentration
          <= CFBF_STRONG_FILLER_CONCENTRATION_LIMIT;
      const bool target_isolated =
          cfbf_reassembly_mapping_run_isolated(
              base_mapping, total_blocks, target_slot, width);
      const bool target_candidate = scan_all_repaired_targets
          || (target_concentration <= CFBF_UNIFORM_CONCENTRATION_LIMIT
              && (!require_isolated_target
                  || target_strong || target_isolated));
      if (target_candidate) {
        target_slots[target_count++] = target_slot;
      }
      polls++;
      if ((polls & UINT64_C(0xff)) == 0
          && cfbf_reassembly_poll(
                 work, candidate, state, uuidp, uuidc)) {
        cfbf_layout_clear(&base_layout);
        free(target_slots);
        free(trial_data);
        free(trial_mapping);
        free(base_mapping);
        return true;
      }
    }

    if (target_count == 0) {
      state->resume_slot = 1;
      state->resume_choice = 0;
      resuming = false;
      continue;
    }

    uint64_t first_actual = 0;

    if (resuming && width == state->resume_run_width
        && state->resume_choice < image_blocks) {
      first_actual = state->resume_choice;
    }
    const uint64_t source_count =
        cfbf_reassembly_source_run_count(width);

    if (scalpel_state.mode_verbose) {
      lock_fprintf(
          stdout,
          "CFBF complete run search: header=%" PRId64
          " profile=%s width=%" PRIu64 " targets=%" PRIu64
          " sources=%" PRIu64 ".\n",
          blockvector_get_actual_blocknumber(blockvector, 0),
          cfbf_profile_filetype(current->profile), width, target_count,
          source_count);
    }

    CfbfSourceRunIterator source_iterator;
    cfbf_reassembly_source_run_iterator_initialize(
        &source_iterator, width, first_actual);
    uint64_t actual = 0;

    while (cfbf_reassembly_next_source_run(
               &source_iterator, &actual)) {

      const bool source_available = cfbf_reassembly_run_source_available(
          blockvector, width, (int64_t)actual);

      if (!source_available) {
        state->resume_slot = 1;
        state->resume_choice = actual + 1;
        resuming = false;
        continue;
      }
      uint64_t first_target_index = 0;

      if (resuming && width == state->resume_run_width
          && actual == state->resume_choice
          && state->resume_slot > 1) {
        while (first_target_index < target_count
               && target_slots[first_target_index] < state->resume_slot) {
          first_target_index++;
        }
      }
      for (uint64_t target_index = first_target_index;
           target_index < target_count; target_index++) {
        const uint64_t target_slot = target_slots[target_index];

        if (!cfbf_reassembly_build_run_mapping(
                blockvector, base_mapping, trial_mapping,
                target_slot, width, (int64_t)actual)) {
          continue;
        }
        CfbfTrialResult trial;
        const bool trial_recoverable =
            cfbf_reassembly_evaluate_run_repair(
                blockvector, state, current, &base_layout,
                semantic_prefilter_available, base_mapping, trial_mapping,
                base_data, trial_data, length, target_slot, width,
                (int64_t)actual, &trial);

        if (trial_recoverable
            && cfbf_reassembly_trial_authenticated(&trial)) {
          const uint32_t repairs = width > UINT32_MAX
              ? UINT32_MAX : (uint32_t)width;

          if (!cfbf_reassembly_branch_partial_suffix(
                  *candidate, state, current, trial_mapping,
                  &trial, repairs)) {
            (void)cfbf_reassembly_share_alternate(
                work, candidate, state, base_mapping, base_data, length);
            cfbf_reassembly_commit_mapping(
                *candidate, state, trial_mapping, &trial, repairs);
            state->search_phase = CFBF_REASSEMBLY_FINALIZED;
            carve_put_state((*candidate)->carvehashkey, state);
          }
          *improved = true;
          cfbf_layout_clear(&base_layout);
          free(target_slots);
          free(trial_data);
          free(trial_mapping);
          free(base_mapping);
          return false;
        }
        state->resume_slot = target_slot + 1;
        state->resume_choice = actual;
        polls++;
        if ((polls & UINT64_C(0xff)) == 0
            && cfbf_reassembly_poll(
                   work, candidate, state, uuidp, uuidc)) {
          cfbf_layout_clear(&base_layout);
          free(target_slots);
          free(trial_data);
          free(trial_mapping);
          free(base_mapping);
          return true;
        }
      }
      state->resume_slot = 1;
      state->resume_choice = actual + 1;
      resuming = false;
      polls++;
      if ((polls & UINT64_C(0x3f)) == 0
          && cfbf_reassembly_poll(
                 work, candidate, state, uuidp, uuidc)) {
        cfbf_layout_clear(&base_layout);
        free(target_slots);
        free(trial_data);
        free(trial_mapping);
        free(base_mapping);
        return true;
      }
    }
    state->resume_slot = 1;
    state->resume_choice = 0;
  }
  free(target_slots);

  CfbfTrialResult solution;
  memset(&solution, 0, sizeof(solution));
  const bool found = state->repair_candidate_valid != 0
      && cfbf_reassembly_build_run_mapping(
             blockvector, base_mapping, trial_mapping,
             state->repair_candidate_slot,
             state->repair_candidate_width,
             (int64_t)state->repair_candidate_actual)
      && cfbf_reassembly_materialize_mapping(
             blockvector, trial_mapping, base_data, trial_data, length)
      && cfbf_reassembly_evaluate_data(trial_data, length, &solution)
      && cfbf_reassembly_trial_recoverable(&solution);

  uint64_t exhaustive_target_slot = 0;

  if (found && cfbf_reassembly_trial_authenticated(&solution)) {
    if (scalpel_state.mode_verbose) {
      lock_fprintf(
          stdout,
          "CFBF complete run selected: header=%" PRId64
          " slot=%" PRIu64 " width=%" PRIu64
          " source=%" PRIu64 " profile=%s.\n",
          blockvector_get_actual_blocknumber(blockvector, 0),
          state->repair_candidate_slot, state->repair_candidate_width,
          state->repair_candidate_actual,
          cfbf_profile_filetype(solution.profile));
    }
    const uint32_t repairs = state->repair_candidate_width > UINT32_MAX
        ? UINT32_MAX : (uint32_t)state->repair_candidate_width;

    if (!cfbf_reassembly_branch_partial_suffix(
            *candidate, state, current, trial_mapping,
            &solution, repairs)) {
      (void)cfbf_reassembly_share_alternate(
          work, candidate, state, base_mapping, base_data, length);
      cfbf_reassembly_commit_mapping(*candidate, state, trial_mapping,
                                     &solution, repairs);
      state->search_phase = CFBF_REASSEMBLY_FINALIZED;
      carve_put_state((*candidate)->carvehashkey, state);
    }
    *improved = true;
  }
  else if (found) {
    const uint32_t repairs = state->repair_candidate_width > UINT32_MAX
        ? UINT32_MAX : (uint32_t)state->repair_candidate_width;

    // Preserve this complete recoverable mapping before the refinement scan.
    // The scan may legitimately outlive the execution cap.
    (void)cfbf_reassembly_write_mapping_hypothesis(
        *candidate, state, trial_mapping, &solution, repairs, true);
    exhaustive_target_slot = state->repair_candidate_slot;
    state->search_phase = CFBF_REASSEMBLY_INDEXED_COMPLETION;
    state->suffix_pass = 3;
    state->resume_slot = exhaustive_target_slot;
    state->resume_choice = 0;
    state->resume_run_width = 1;
    state->resume_run_left = 0;
    state->resume_source_pass = 2;
    if (scalpel_state.mode_verbose) {
      lock_fprintf(
          stdout,
          "CFBF complete run retained for exhaustive ranking:"
          " header=%" PRId64 " slot=%" PRIu64 " width=%" PRIu64
          " source=%" PRIu64 " profile=%s.\n",
          blockvector_get_actual_blocknumber(blockvector, 0),
          state->repair_candidate_slot, state->repair_candidate_width,
          state->repair_candidate_actual,
          cfbf_profile_filetype(solution.profile));
    }
  }
  else {
    cfbf_reassembly_reset_repair_candidates(state);
    state->search_phase = 0;
    state->resume_slot = 0;
    state->resume_choice = 0;
    state->resume_run_width = 0;
    state->resume_run_left = 0;
    state->resume_source_pass = 0;
  }
  cfbf_layout_clear(&base_layout);
  free(trial_data);
  free(trial_mapping);
  free(base_mapping);
  if (exhaustive_target_slot != 0) {
    return cfbf_reassembly_try_block_replacements(
        work, candidate, state, current, exhaustive_target_slot,
        exhaustive_target_slot, uuidp, uuidc, improved, validated);
  }
  return false;
}

// Replace a physically contiguous displaced run as one atomic hypothesis.
// A one-block trial that advances structural validation serves as an anchor;
// the search then expands both sides of that anchor without committing the
// partial trial. This preserves recoverability when no individual block can
// complete a multi-block repair.
//
static inline bool cfbf_reassembly_try_block_replacements(
    ThreadWork *work, CarveInfo **candidate, CfbfCarveState *state,
    const CfbfTrialResult *current, uint64_t first_slot,
    uint64_t last_slot, uuid_string_t uuidp, uuid_string_t uuidc,
    bool *improved, bool *validated) {

  if (!work || !candidate || !*candidate || !(*candidate)->b || !state
      || !current || !improved || !validated) {
    return false;
  }
  *improved = false;
  *validated = false;

  BlockVector *blockvector = (*candidate)->b;
  const uint64_t total_blocks = blockvector_get_num_blocks(blockvector);
  const uint64_t image_blocks = CEILDIV(
      filemirror_filesize(scalpel_state.filemirror), scalpel_state.blocksize);
  const uint64_t length = blockvector_get_data_length(blockvector);
  if (first_slot == 0 || first_slot > last_slot
      || first_slot >= total_blocks || last_slot >= total_blocks
      || length == 0) {
    return false;
  }

  int64_t *base_mapping = (int64_t *)malloc(
      (size_t)total_blocks * sizeof(*base_mapping));
  int64_t *trial_mapping = (int64_t *)malloc(
      (size_t)total_blocks * sizeof(*trial_mapping));
  int64_t *solution_mapping = (int64_t *)malloc(
      (size_t)total_blocks * sizeof(*solution_mapping));
  uint8_t *trial_data = (uint8_t *)malloc((size_t)length);

  check_memory_allocation(base_mapping, __LINE__, __FILE__,
                          "CFBF base run mapping");
  check_memory_allocation(trial_mapping, __LINE__, __FILE__,
                          "CFBF trial run mapping");
  check_memory_allocation(solution_mapping, __LINE__, __FILE__,
                          "CFBF run solution mapping");
  check_memory_allocation(trial_data, __LINE__, __FILE__,
                          "CFBF run trial data");
  for (uint64_t slot = 0; slot < total_blocks; slot++) {
    base_mapping[slot] = blockvector_get_apparent_blocknumber(
        blockvector, slot);
    solution_mapping[slot] = base_mapping[slot];
  }
  const uint8_t *base_data = (const uint8_t *)
      blockvector_get_data_pointer(blockvector);
  CfbfMappingIndex base_index = { 0 };
  CfbfTrialResult solution_result;

  if (!base_data
      || !cfbf_reassembly_mapping_index_initialize(
             &base_index, total_blocks)
      || !cfbf_reassembly_mapping_index_build(
             &base_index, base_mapping, total_blocks)) {
    cfbf_reassembly_mapping_index_clear(&base_index);
    free(trial_data);
    free(solution_mapping);
    free(trial_mapping);
    free(base_mapping);
    return false;
  }
  memcpy(trial_data, base_data, (size_t)length);
  memset(&solution_result, 0, sizeof(solution_result));
  bool found = false;
  uint32_t solution_blocks = 0;
  uint64_t trials = 0;
  uint64_t start_slot = first_slot;

  bool indexed_completion = state->search_phase
                            == CFBF_REASSEMBLY_INDEXED_COMPLETION;
  bool resume_direct = state->search_phase == 5 || indexed_completion;
  const bool resuming = state->search_phase == 2 || resume_direct;
  const uint64_t indexed_source = indexed_completion
      ? state->repair_candidate_actual : 0;
  const uint64_t indexed_width = indexed_completion
      ? state->repair_candidate_width : 0;
  const uint64_t indexed_end = indexed_width > UINT64_MAX - indexed_source
      ? UINT64_MAX : indexed_source + indexed_width;
  const bool restrict_to_indexed_source = indexed_completion
      && state->repair_candidate_semantic_strength
         == CFBF_SEMANTIC_STRONG;

  // A recoverable subrun establishes one source-to-slot displacement. Test
  // every ordered extension of that run before returning to the unrestricted
  // search, because allocation metadata near one end can validate before the
  // application stream occupying the rest of the run has been restored.
  if (indexed_completion && state->resume_source_pass == 2
      && indexed_width > 0
      && state->repair_candidate_slot > 0
      && state->repair_candidate_slot < total_blocks
      && indexed_width
             <= total_blocks - state->repair_candidate_slot
      && indexed_source < image_blocks
      && indexed_width <= image_blocks - indexed_source) {
    const uint64_t indexed_slot = state->repair_candidate_slot;
    const uint64_t indexed_slot_end = indexed_slot + indexed_width;
    const uint64_t indexed_source_end = indexed_source + indexed_width;
    uint64_t extension_target_blocks = total_blocks;
    CfbfTrialResult indexed_result;

    memset(&indexed_result, 0, sizeof(indexed_result));
    const bool indexed_materialized =
        cfbf_reassembly_build_mapped_run_indexed(
            blockvector, base_mapping, &base_index, trial_mapping,
            indexed_slot, indexed_width, (int64_t)indexed_source)
        && cfbf_reassembly_update_mapping_data(
               blockvector, base_mapping, trial_mapping,
               trial_data, length);

    if (indexed_materialized
        && cfbf_reassembly_evaluate_data(
               trial_data, length, &indexed_result)
        && cfbf_reassembly_trial_recoverable(&indexed_result)
        && indexed_result.inferred_size > 0) {
      const uint64_t inferred_blocks = CEILDIV(
          indexed_result.inferred_size, scalpel_state.blocksize);

      if (inferred_blocks >= indexed_slot_end
          && inferred_blocks < extension_target_blocks) {
        extension_target_blocks = inferred_blocks;
      }
    }
    if (indexed_materialized
        && !cfbf_reassembly_update_mapping_data(
               blockvector, trial_mapping, base_mapping,
               trial_data, length)) {
      memcpy(trial_data, base_data, (size_t)length);
    }
    uint64_t maximum_left = indexed_slot - 1;
    uint64_t maximum_right = extension_target_blocks - indexed_slot_end;

    if (maximum_left > indexed_source) {
      maximum_left = indexed_source;
    }
    if (maximum_right > image_blocks - indexed_source_end) {
      maximum_right = image_blocks - indexed_source_end;
    }
    const uint64_t maximum_extension = maximum_left + maximum_right;
    uint64_t first_extension = state->resume_run_width;

    if (first_extension == 0) {
      first_extension = 1;
    }
    for (uint64_t extension = first_extension;
         extension <= maximum_extension; extension++) {
      uint64_t minimum_left = extension > maximum_right
                                  ? extension - maximum_right : 0;
      uint64_t final_left = extension < maximum_left
                                ? extension : maximum_left;
      uint64_t first_left = minimum_left;

      if (extension == first_extension
          && state->resume_run_left >= minimum_left
          && state->resume_run_left <= final_left) {
        first_left = state->resume_run_left;
      }
      for (uint64_t left = first_left; left <= final_left; left++) {
        const uint64_t run_slot = indexed_slot - left;
        const uint64_t run_width = indexed_width + extension;
        const int64_t run_actual = (int64_t)(indexed_source - left);
        CfbfTrialResult extension_result;

        memset(&extension_result, 0, sizeof(extension_result));
        const bool materialized = cfbf_reassembly_build_mapped_run_indexed(
            blockvector, base_mapping, &base_index, trial_mapping,
            run_slot, run_width, run_actual)
            && cfbf_reassembly_update_mapping_data(
                   blockvector, base_mapping, trial_mapping,
                   trial_data, length);
        const bool evaluated = materialized
            && cfbf_reassembly_evaluate_data(
                   trial_data, length, &extension_result);

        if (evaluated
            && cfbf_reassembly_trial_authenticated(&extension_result)) {
          const uint32_t repairs = run_width > UINT32_MAX
              ? UINT32_MAX : (uint32_t)run_width;

          if (!cfbf_reassembly_branch_partial_suffix(
                  *candidate, state, current, trial_mapping,
                  &extension_result, repairs)) {
            cfbf_reassembly_commit_mapping(
                *candidate, state, trial_mapping,
                &extension_result, repairs);
            state->search_phase = CFBF_REASSEMBLY_FINALIZED;
            carve_put_state((*candidate)->carvehashkey, state);
          }
          *improved = true;
          cfbf_reassembly_mapping_index_clear(&base_index);
          free(trial_data);
          free(solution_mapping);
          free(trial_mapping);
          free(base_mapping);
          return false;
        }
        if (evaluated
            && cfbf_reassembly_trial_recoverable(&extension_result)) {
          bool has_confidence = false;
          bool all_positive = false;
          int64_t confidence_gain = 0;
          uint32_t reserved = 0;

          cfbf_reassembly_run_metrics(
              blockvector, NULL, run_slot, run_width, run_actual,
              extension_result.profile, &has_confidence, &all_positive,
              &confidence_gain, &reserved, NULL);
          const uint64_t context_distance =
              cfbf_reassembly_context_distance(
                  blockvector, base_mapping, run_slot, run_width,
                  run_actual);
          const uint64_t target_concentration =
              cfbf_reassembly_mapping_concentration(
                  base_mapping, run_slot, run_width);
          const bool target_exact = cfbf_reassembly_mapping_run_isolated(
              base_mapping, total_blocks, run_slot, run_width);
          const bool target_strong = target_concentration
              <= CFBF_STRONG_FILLER_CONCENTRATION_LIMIT;

          cfbf_reassembly_remember_repair(
              state, blockvector, run_slot, run_width,
              (uint64_t)run_actual, &extension_result, has_confidence,
              all_positive, target_strong, target_exact, confidence_gain,
              reserved, context_distance, target_concentration,
              cfbf_reassembly_run_concentration(run_actual, run_width));
        }
        if (materialized
            && !cfbf_reassembly_update_mapping_data(
                   blockvector, trial_mapping, base_mapping,
                   trial_data, length)) {
          memcpy(trial_data, base_data, (size_t)length);
        }

        if (left < final_left) {
          state->resume_run_width = extension;
          state->resume_run_left = left + 1;
        }
        else {
          state->resume_run_width = extension + 1;
          state->resume_run_left = 0;
        }
        trials++;
        if ((trials & UINT64_C(0x1f)) == 0
            && cfbf_reassembly_poll(
                   work, candidate, state, uuidp, uuidc)) {
          cfbf_reassembly_mapping_index_clear(&base_index);
          free(trial_data);
          free(solution_mapping);
          free(trial_mapping);
          free(base_mapping);
          return true;
        }
      }
    }
    state->resume_source_pass = 0;
    state->resume_slot = first_slot;
    state->resume_choice = 0;
    state->resume_run_width = 2;
    state->resume_run_left = 0;
    carve_put_state((*candidate)->carvehashkey, state);
  }

  if (!resuming) {
    cfbf_reassembly_reset_repair_candidates(state);
    state->resume_source_pass = 0;
  }

  if ((state->search_phase == 2 || resume_direct)
      && state->resume_slot >= first_slot
      && state->resume_slot <= last_slot) {
    start_slot = state->resume_slot;
  }
  if (!resume_direct) {
    state->search_phase = 2;
  }
  for (uint64_t slot = start_slot;
       !resume_direct && slot <= last_slot && !found; slot++) {
    uint64_t first_actual = 0;

    if (state->resume_slot == slot && state->resume_choice < image_blocks) {
      first_actual = state->resume_choice;
    }
    state->resume_slot = slot;
    CfbfSourceRunIterator source_iterator;
    cfbf_reassembly_source_run_iterator_initialize(
        &source_iterator, 1, first_actual);
    uint64_t actual_index = 0;

    while (!found && cfbf_reassembly_next_source_run(
                         &source_iterator, &actual_index)) {
      const int64_t actual = (int64_t)actual_index;

      CfbfTrialResult trial;

      memset(&trial, 0, sizeof(trial));
      const bool one_block_available =
          cfbf_reassembly_build_mapped_run_indexed(
              blockvector, base_mapping, &base_index, trial_mapping,
              slot, 1, actual);
      const bool one_block_materialized = one_block_available
          && cfbf_reassembly_update_mapping_data(
                 blockvector, base_mapping, trial_mapping,
                 trial_data, length);
      const bool one_block_evaluated = one_block_materialized
          && cfbf_reassembly_evaluate_data(trial_data, length, &trial);

      if (one_block_materialized
          && !cfbf_reassembly_update_mapping_data(
                 blockvector, trial_mapping, base_mapping,
                 trial_data, length)) {
        memcpy(trial_data, base_data, (size_t)length);
      }
      if (one_block_evaluated) {
        const bool one_block_complete = cfbf_reassembly_trial_complete(&trial);
        const bool one_block_recoverable =
            cfbf_reassembly_trial_recoverable(&trial);

        if (one_block_recoverable) {
          bool has_confidence = false;
          bool all_positive = false;
          int64_t confidence_gain = 0;
          uint32_t reserved = 0;

          cfbf_reassembly_run_metrics(
              blockvector, NULL, slot, 1, actual, trial.profile,
              &has_confidence, &all_positive, &confidence_gain, &reserved,
              NULL);
          const uint64_t context_distance =
              cfbf_reassembly_context_distance(
                  blockvector, base_mapping, slot, 1, actual);
          const uint64_t target_concentration =
              cfbf_reassembly_mapping_concentration(
                  base_mapping, slot, 1);
          const uint64_t source_concentration =
              cfbf_reassembly_run_concentration(actual, 1);
          const bool target_exact =
              cfbf_reassembly_mapping_run_isolated(
                  base_mapping, total_blocks, slot, 1);
          const bool target_strong = target_concentration
              <= CFBF_STRONG_FILLER_CONCENTRATION_LIMIT;

          cfbf_reassembly_remember_repair(
              state, blockvector, slot, 1, actual_index, &trial,
              has_confidence,
              all_positive, target_strong, target_exact,
              confidence_gain, reserved,
              context_distance, target_concentration,
              source_concentration);
        }
        if (one_block_complete || trial.score > current->score) {
          uint64_t maximum_left = slot - 1;

          if (maximum_left > actual_index) {
            maximum_left = actual_index;
          }
          uint64_t maximum_right = total_blocks - slot - 1;
          const uint64_t image_right = image_blocks - actual_index - 1;

          if (maximum_right > image_right) {
            maximum_right = image_right;
          }
          const uint64_t maximum_width = maximum_left + 1
                                         + maximum_right;

          // Test shorter repairs first. A displaced run retains its physical
          // order, so every complete expansion is represented by one width and
          // one number of blocks to the left of this anchor.
          for (uint64_t width = 2; width <= maximum_width && !found;
               width++) {
            uint64_t minimum_left = 0;

            if (width - 1 > maximum_right) {
              minimum_left = width - 1 - maximum_right;
            }
            uint64_t last_left = width - 1;

            if (last_left > maximum_left) {
              last_left = maximum_left;
            }
            for (uint64_t left_offset = 0;
                 left_offset <= last_left - minimum_left && !found;
                 left_offset++) {
              const uint64_t left = last_left - left_offset;
              const uint64_t run_slot = slot - left;
              const int64_t run_actual = actual - (int64_t)left;

              if (!cfbf_reassembly_build_mapped_run_indexed(
                      blockvector, base_mapping, &base_index, trial_mapping,
                      run_slot, width, run_actual)
                  || !cfbf_reassembly_update_mapping_data(
                         blockvector, base_mapping, trial_mapping,
                         trial_data, length)) {
                continue;
              }
              CfbfTrialResult run_trial;

              memset(&run_trial, 0, sizeof(run_trial));
              const bool evaluated = cfbf_reassembly_evaluate_data(
                  trial_data, length, &run_trial);

              if (!cfbf_reassembly_update_mapping_data(
                      blockvector, trial_mapping, base_mapping,
                      trial_data, length)) {
                memcpy(trial_data, base_data, (size_t)length);
              }
              if (evaluated
                  && cfbf_reassembly_trial_recoverable(&run_trial)) {
                bool has_confidence = false;
                bool all_positive = false;
                int64_t confidence_gain = 0;
                uint32_t reserved = 0;

                cfbf_reassembly_run_metrics(
                    blockvector, NULL, run_slot, width, run_actual,
                    run_trial.profile, &has_confidence, &all_positive,
                    &confidence_gain, &reserved, NULL);
                const uint64_t context_distance =
                    cfbf_reassembly_context_distance(
                        blockvector, base_mapping, run_slot, width,
                        run_actual);
                const uint64_t target_concentration =
                    cfbf_reassembly_mapping_concentration(
                        base_mapping, run_slot, width);
                const uint64_t source_concentration =
                    cfbf_reassembly_run_concentration(run_actual, width);
                const bool target_exact =
                    cfbf_reassembly_mapping_run_isolated(
                        base_mapping, total_blocks, run_slot, width);
                const bool target_strong = target_concentration
                    <= CFBF_STRONG_FILLER_CONCENTRATION_LIMIT;

                cfbf_reassembly_remember_repair(
                    state, blockvector, run_slot, width,
                    (uint64_t)run_actual,
                    &run_trial, has_confidence, all_positive,
                    target_strong, target_exact, confidence_gain, reserved,
                    context_distance, target_concentration,
                    source_concentration);
              }
              trials++;
              if (!found && (trials & UINT64_C(0xff)) == 0
                  && cfbf_reassembly_poll(
                         work, candidate, state, uuidp, uuidc)) {
                cfbf_reassembly_mapping_index_clear(&base_index);
                free(trial_data);
                free(solution_mapping);
                free(trial_mapping);
                free(base_mapping);
                return true;
              }
            }
          }
        }

      }

      state->resume_choice = actual_index + 1;
      if ((actual_index & UINT64_C(0x3f)) == 0
          && cfbf_reassembly_poll(work, candidate, state, uuidp, uuidc)) {
        cfbf_reassembly_mapping_index_clear(&base_index);
        free(trial_data);
        free(solution_mapping);
        free(trial_mapping);
        free(base_mapping);
        return true;
      }
    }
    state->resume_choice = 0;
  }

  // Some CFBF streams are opaque until every displaced block is restored, so
  // no single block provides a scoring anchor. Complete the search by testing
  // ordered runs directly, shortest first. For a targeted parser failure the
  // run may begin on either side of that slot; the later exhaustive pass tests
  // each remaining logical start exactly once.
  if (!found) {
    const bool targeted_search = first_slot == last_slot;
    uint64_t direct_start_slot = resume_direct ? start_slot : first_slot;

    state->search_phase = indexed_completion
        ? CFBF_REASSEMBLY_INDEXED_COMPLETION : 5;
    if (scalpel_state.mode_verbose) {
      lock_fprintf(
          stdout,
          "CFBF direct run search: header=%" PRId64
          " slots=%" PRIu64 "-%" PRIu64 " blocks=%" PRIu64
          " failure=%" PRIu64 ".\n",
          blockvector_get_actual_blocknumber(blockvector, 0), first_slot,
          last_slot, total_blocks, current->failure_offset);
    }
    for (uint64_t slot = direct_start_slot;
         slot <= last_slot && !found; slot++) {
      uint64_t first_width = 2;

      if (resume_direct && state->resume_slot == slot
          && state->resume_run_width >= 2) {
        first_width = state->resume_run_width;
      }
      state->resume_slot = slot;

      for (uint64_t width = first_width;
           width < total_blocks && !found; width++) {
        if (width > image_blocks) {
          break;
        }
        uint64_t minimum_left = 0;
        uint64_t maximum_left = 0;

        if (targeted_search) {
          maximum_left = width - 1;
          if (maximum_left > slot - 1) {
            maximum_left = slot - 1;
          }
          const uint64_t maximum_right = total_blocks - slot - 1;

          if (width - 1 > maximum_right) {
            minimum_left = width - 1 - maximum_right;
          }
        }
        else if (width > total_blocks - slot) {
          break;
        }
        uint64_t first_left = minimum_left;

        if (resume_direct && state->resume_slot == slot
            && state->resume_run_width == width
            && state->resume_run_left >= minimum_left
            && state->resume_run_left <= maximum_left) {
          first_left = state->resume_run_left;
        }
        state->resume_run_width = width;

        for (uint64_t left = first_left;
             left <= maximum_left && !found; left++) {
          const uint64_t run_slot = slot - left;
          uint32_t first_source_pass = 0;

          if (resume_direct && state->resume_slot == slot
              && state->resume_run_width == width
              && state->resume_run_left == left
              && state->resume_source_pass <= 1) {
            first_source_pass = state->resume_source_pass;
          }
          state->resume_run_left = left;
          for (uint32_t source_pass = first_source_pass;
               source_pass < 2 && !found; source_pass++) {
            uint64_t first_actual = 0;

            if (resume_direct && state->resume_slot == slot
                && state->resume_run_width == width
                && state->resume_run_left == left
                && state->resume_source_pass == source_pass
                && state->resume_choice < image_blocks) {
              first_actual = state->resume_choice;
            }
            state->resume_source_pass = source_pass;
            CfbfSourceRunIterator source_iterator;
            cfbf_reassembly_source_run_iterator_initialize(
                &source_iterator, width, first_actual);
            uint64_t actual_index = first_actual;

            while (!found) {
              if (source_pass == 0) {
                if (!cfbf_reassembly_next_source_run(
                        &source_iterator, &actual_index)) {
                  break;
                }
              }
              else if (actual_index > image_blocks - width) {
                break;
              }

              const bool overlaps_indexed_source = !restrict_to_indexed_source
                  || (actual_index < indexed_end
                      && indexed_source < actual_index + width);

              if (overlaps_indexed_source
                  && cfbf_reassembly_build_mapped_run_indexed(
                         blockvector, base_mapping, &base_index,
                         trial_mapping, run_slot, width,
                         (int64_t)actual_index)
                  && cfbf_reassembly_update_mapping_data(
                         blockvector, base_mapping, trial_mapping,
                         trial_data, length)) {
                CfbfTrialResult run_trial;

                memset(&run_trial, 0, sizeof(run_trial));
                const bool evaluated = cfbf_reassembly_evaluate_data(
                    trial_data, length, &run_trial);

                if (!cfbf_reassembly_update_mapping_data(
                        blockvector, trial_mapping, base_mapping,
                        trial_data, length)) {
                  memcpy(trial_data, base_data, (size_t)length);
                }
                if (evaluated
                    && cfbf_reassembly_trial_recoverable(&run_trial)) {
                  bool has_confidence = false;
                  bool all_positive = false;
                  int64_t confidence_gain = 0;
                  uint32_t reserved = 0;

                  cfbf_reassembly_run_metrics(
                      blockvector, NULL, run_slot, width,
                      (int64_t)actual_index,
                      run_trial.profile, &has_confidence, &all_positive,
                      &confidence_gain, &reserved, NULL);
                  const uint64_t context_distance =
                      cfbf_reassembly_context_distance(
                          blockvector, base_mapping, run_slot, width,
                          (int64_t)actual_index);
                  const uint64_t target_concentration =
                      cfbf_reassembly_mapping_concentration(
                          base_mapping, run_slot, width);
                  const bool target_exact =
                      cfbf_reassembly_mapping_run_isolated(
                          base_mapping, total_blocks, run_slot, width);
                  const bool target_strong = target_concentration
                      <= CFBF_STRONG_FILLER_CONCENTRATION_LIMIT;

                  cfbf_reassembly_remember_repair(
                      state, blockvector, run_slot, width, actual_index,
                      &run_trial,
                      has_confidence, all_positive, target_strong,
                      target_exact, confidence_gain,
                      reserved, context_distance, target_concentration,
                      cfbf_reassembly_run_concentration(
                          (int64_t)actual_index, width));
                }
              }
              actual_index++;
              state->resume_choice = actual_index;
              trials++;
              if (!found && (trials & UINT64_C(0xff)) == 0
                  && cfbf_reassembly_poll(
                         work, candidate, state, uuidp, uuidc)) {
                cfbf_reassembly_mapping_index_clear(&base_index);
                free(trial_data);
                free(solution_mapping);
                free(trial_mapping);
                free(base_mapping);
                return true;
              }
            }
            state->resume_choice = 0;
            resume_direct = false;
          }
          state->resume_source_pass = 0;
        }
        state->resume_run_left = 0;
      }
      state->resume_run_width = 0;
    }
  }

  if (!found && state->repair_candidate_valid != 0
      && cfbf_reassembly_build_mapped_run_indexed(
             blockvector, base_mapping, &base_index, solution_mapping,
             state->repair_candidate_slot, state->repair_candidate_width,
             (int64_t)state->repair_candidate_actual)
      && cfbf_reassembly_materialize_mapping(
             blockvector, solution_mapping, base_data, trial_data, length)
      && cfbf_reassembly_evaluate_data(
             trial_data, length, &solution_result)
      && cfbf_reassembly_trial_recoverable(&solution_result)
      && cfbf_reassembly_target_within_result(
             &solution_result, state->repair_candidate_slot,
             state->repair_candidate_width, total_blocks)) {
    solution_blocks = state->repair_candidate_width > UINT32_MAX
                          ? UINT32_MAX
                          : (uint32_t)state->repair_candidate_width;
    found = true;
  }

  if (found) {
    const bool authenticated =
        cfbf_reassembly_trial_authenticated(&solution_result);

    if (cfbf_reassembly_branch_partial_suffix(
            *candidate, state, current, solution_mapping,
            &solution_result, solution_blocks)) {
      *improved = true;
    }
    else if (authenticated) {
      (void)cfbf_reassembly_share_alternate(
          work, candidate, state, base_mapping, base_data, length);
      cfbf_reassembly_commit_mapping(*candidate, state, solution_mapping,
                                     &solution_result, solution_blocks);
      state->search_phase = CFBF_REASSEMBLY_FINALIZED;
      carve_put_state((*candidate)->carvehashkey, state);
      *improved = true;
    }
    else {
      // Opaque application streams can satisfy their structural validators
      // under several mappings. Preserve the bounded independent rankings,
      // then continue so another repair can be applied to the same candidate.
      (void)cfbf_reassembly_share_alternate(
          work, candidate, state, base_mapping, base_data, length);
      (void)cfbf_reassembly_write_mapping_hypothesis(
          *candidate, state, solution_mapping, &solution_result,
          solution_blocks, true);
      base_data = (const uint8_t *)
          blockvector_get_data_pointer(blockvector);

      const CfbfRepairCandidate *boundary = &state->repair_alternate;
      const bool boundary_is_primary = boundary->valid != 0
          && boundary->slot == state->repair_candidate_slot
          && boundary->width == state->repair_candidate_width
          && boundary->actual == state->repair_candidate_actual;

      if (boundary->valid != 0 && !boundary_is_primary) {
        (void)cfbf_reassembly_write_repair_hypothesis(
            *candidate, state, base_mapping, trial_mapping, base_data,
            trial_data, length, boundary);
        base_data = (const uint8_t *)
            blockvector_get_data_pointer(blockvector);
      }
      const CfbfRepairCandidate *semantic = &state->repair_semantic;
      const bool semantic_is_primary = semantic->valid != 0
          && semantic->slot == state->repair_candidate_slot
          && semantic->width == state->repair_candidate_width
          && semantic->actual == state->repair_candidate_actual;
      const bool semantic_is_boundary = semantic->valid != 0
          && boundary->valid != 0
          && semantic->slot == boundary->slot
          && semantic->width == boundary->width
          && semantic->actual == boundary->actual;

      if (semantic->valid != 0 && !semantic_is_primary
          && !semantic_is_boundary) {
        (void)cfbf_reassembly_write_repair_hypothesis(
            *candidate, state, base_mapping, trial_mapping, base_data,
            trial_data, length, semantic);
        base_data = (const uint8_t *)
            blockvector_get_data_pointer(blockvector);
      }
      for (uint32_t index = 0;
           index < CFBF_ISOLATED_HYPOTHESIS_LIMIT
           && state->repair_isolated[index].valid != 0; index++) {
        const CfbfRepairCandidate *isolated =
            &state->repair_isolated[index];
        const bool isolated_is_primary =
            isolated->slot == state->repair_candidate_slot
            && isolated->width == state->repair_candidate_width
            && isolated->actual == state->repair_candidate_actual;
        const bool isolated_is_boundary = boundary->valid != 0
            && isolated->slot == boundary->slot
            && isolated->width == boundary->width
            && isolated->actual == boundary->actual;
        const bool isolated_is_semantic = semantic->valid != 0
            && isolated->slot == semantic->slot
            && isolated->width == semantic->width
            && isolated->actual == semantic->actual;

        if (isolated_is_primary || isolated_is_boundary
            || isolated_is_semantic) {
          continue;
        }
        (void)cfbf_reassembly_write_repair_hypothesis(
            *candidate, state, base_mapping, trial_mapping, base_data,
            trial_data, length, isolated);
        base_data = (const uint8_t *)
            blockvector_get_data_pointer(blockvector);
      }
      cfbf_reassembly_reset_repair_candidates(state);
      state->search_phase = 3;
      state->resume_slot = 0;
      state->resume_choice = 0;
      state->resume_run_width = 0;
      state->resume_run_left = 0;
      state->resume_source_pass = 0;
      carve_put_state((*candidate)->carvehashkey, state);
    }
  }
  else {
    state->search_phase = 3;
    state->resume_slot = 0;
    state->resume_choice = 0;
    state->resume_run_width = 0;
    state->resume_run_left = 0;
    state->resume_source_pass = 0;
  }
  cfbf_reassembly_mapping_index_clear(&base_index);
  free(trial_data);
  free(solution_mapping);
  free(trial_mapping);
  free(base_mapping);
  return false;
}

// Test a bounded set of model-supported gap and displaced-run hypotheses.
// Model confidence proposes physical boundaries but never authenticates a
// mapping. Complete CFBF and subtype validation remain mandatory, and the
// exhaustive search below remains available when these signals are absent.
static inline bool cfbf_reassembly_try_model_combined(
    ThreadWork *work, CarveInfo **candidate, CfbfCarveState *state,
    const CfbfTrialResult *current, uuid_string_t uuidp,
    uuid_string_t uuidc, bool *improved) {

  if (!work || !candidate || !*candidate || !(*candidate)->b || !state
      || !current || !improved) {
    return false;
  }
  *improved = false;

  if (state->model_search_complete != 0
      && state->model_search_repairs == state->repairs) {
    return false;
  }
  if (state->model_search_repairs != state->repairs) {
    state->model_search_complete = 0;
    state->model_search_repairs = state->repairs;
    carve_put_state((*candidate)->carvehashkey, state);
  }

  BlockVector *blockvector = (*candidate)->b;
  const CfbfProfile profile = cfbf_reassembly_model_profile(
      blockvector, current->profile);
  const int32_t confidence_spec = cfbf_reassembly_confidence_spec(profile);
  const uint64_t total_blocks = blockvector_get_num_blocks(blockvector);
  const uint64_t image_blocks = CEILDIV(
      filemirror_filesize(scalpel_state.filemirror), scalpel_state.blocksize);
  const int64_t header_actual = blockvector_get_actual_blocknumber(
      blockvector, 0);
  const uint64_t length = blockvector_get_data_length(blockvector);

  if ((profile != CFBF_PROFILE_DOC && profile != CFBF_PROFILE_XLS
       && profile != CFBF_PROFILE_PPT)
      || confidence_spec < 0 || total_blocks < 3 || image_blocks < 3
      || header_actual < 0 || (uint64_t)header_actual >= image_blocks
      || length == 0) {
    return false;
  }

  CfbfModelRun gaps[CFBF_MODEL_GAP_LIMIT];
  CfbfModelRun broad_gaps[CFBF_MODEL_GAP_LIMIT];
  uint32_t gap_count = 0;
  uint32_t broad_gap_count = 0;
  uint64_t signal_end = (uint64_t)header_actual + total_blocks
                        + CFBF_NEARBY_SUFFIX_SHIFT_LIMIT * 2;

  if (signal_end > image_blocks) {
    signal_end = image_blocks;
  }
  for (uint32_t signal_pass = 0; signal_pass < 2; signal_pass++) {
    const uint32_t threshold = signal_pass == 0
        ? CFBF_MODEL_STRONG_FILLER_CONFIDENCE
        : CFBF_MODEL_FILLER_CONFIDENCE;
    CfbfModelRun *signals = signal_pass == 0 ? gaps : broad_gaps;
    uint32_t *signal_count = signal_pass == 0
        ? &gap_count : &broad_gap_count;
    uint64_t actual = (uint64_t)header_actual + 1;

    while (actual < signal_end) {
      const uint32_t first_value = filemirror_get_blocktype(
          scalpel_state.filemirror, (int64_t)actual,
          (uint32_t)confidence_spec);

      if (first_value > threshold) {
        actual++;
        continue;
      }
      const uint64_t run_start = actual;
      uint32_t maximum = first_value;
      uint64_t confidence = 0;

      while (actual < signal_end) {
        const uint32_t value = filemirror_get_blocktype(
            scalpel_state.filemirror, (int64_t)actual,
            (uint32_t)confidence_spec);

        if (value > threshold) {
          break;
        }
        if (value > maximum) {
          maximum = value;
        }
        confidence += value;
        actual++;
      }
      const uint64_t width = actual - run_start;

      if (width == 0 || actual >= image_blocks) {
        continue;
      }
      const uint32_t left = filemirror_get_blocktype(
          scalpel_state.filemirror, (int64_t)run_start - 1,
          (uint32_t)confidence_spec);
      const uint32_t right = filemirror_get_blocktype(
          scalpel_state.filemirror, (int64_t)actual,
          (uint32_t)confidence_spec);
      const uint32_t boundary = left < right ? left : right;

      if (boundary <= maximum) {
        continue;
      }
      const uint64_t contrast = (uint64_t)boundary - maximum;
      const int64_t persistent_evidence =
          width > (uint64_t)INT64_MAX / contrast
              ? INT64_MAX : (int64_t)(width * contrast);
      const CfbfModelRun signal = {
        .actual = run_start,
        .width = width,
        .evidence = persistent_evidence,
        .confidence = confidence
      };

      cfbf_reassembly_retain_model_run(
          signals, signal_count, CFBF_MODEL_GAP_LIMIT, &signal);
    }
  }
  for (uint32_t broad_index = 0;
       broad_index < broad_gap_count
       && gap_count < CFBF_MODEL_GAP_LIMIT; broad_index++) {
    bool duplicate = false;

    for (uint32_t gap_index = 0; gap_index < gap_count; gap_index++) {
      if (gaps[gap_index].actual == broad_gaps[broad_index].actual
          && gaps[gap_index].width == broad_gaps[broad_index].width) {
        duplicate = true;
        break;
      }
    }
    if (!duplicate) {
      gaps[gap_count++] = broad_gaps[broad_index];
    }
  }
  if (gap_count == 0) {
    state->model_search_complete = 1;
    state->model_search_repairs = state->repairs;
    carve_put_state((*candidate)->carvehashkey, state);
    return false;
  }

  int64_t *base_mapping = (int64_t *)malloc(
      (size_t)total_blocks * sizeof(*base_mapping));
  int64_t *first_mapping = (int64_t *)malloc(
      (size_t)total_blocks * sizeof(*first_mapping));
  int64_t *pair_mapping = (int64_t *)malloc(
      (size_t)total_blocks * sizeof(*pair_mapping));
  int64_t *trial_mapping = (int64_t *)malloc(
      (size_t)total_blocks * sizeof(*trial_mapping));
  uint8_t *trial_data = (uint8_t *)malloc((size_t)length);

  check_memory_allocation(base_mapping, __LINE__, __FILE__,
                          "CFBF model combined base mapping");
  check_memory_allocation(first_mapping, __LINE__, __FILE__,
                          "CFBF model combined first mapping");
  check_memory_allocation(pair_mapping, __LINE__, __FILE__,
                          "CFBF model combined pair mapping");
  check_memory_allocation(trial_mapping, __LINE__, __FILE__,
                          "CFBF model combined trial mapping");
  check_memory_allocation(trial_data, __LINE__, __FILE__,
                          "CFBF model combined trial data");
  for (uint64_t slot = 0; slot < total_blocks; slot++) {
    base_mapping[slot] = blockvector_get_apparent_blocknumber(
        blockvector, slot);
  }
  const uint8_t *base_data = (const uint8_t *)
      blockvector_get_data_pointer(blockvector);
  CfbfMappingIndex pair_index = { 0 };
  uint64_t trials = 0;
  CfbfModelHypothesis
      complete_hypotheses[CFBF_MODEL_COMPLETE_HYPOTHESIS_LIMIT];
  CfbfModelHypothesis
      partial_hypotheses[CFBF_MODEL_PARTIAL_HYPOTHESIS_LIMIT];
  uint32_t complete_hypothesis_count = 0;
  uint32_t partial_hypothesis_count = 0;

  memset(complete_hypotheses, 0, sizeof(complete_hypotheses));
  memset(partial_hypotheses, 0, sizeof(partial_hypotheses));

  if (!base_data
      || !cfbf_reassembly_mapping_index_initialize(
             &pair_index, total_blocks)) {
    cfbf_reassembly_mapping_index_clear(&pair_index);
    free(trial_data);
    free(trial_mapping);
    free(pair_mapping);
    free(first_mapping);
    free(base_mapping);
    return false;
  }

  const uint32_t single_gap_count = gap_count < CFBF_MODEL_SINGLE_GAP_LIMIT
      ? gap_count : CFBF_MODEL_SINGLE_GAP_LIMIT;
  const uint32_t boundary_positions = CFBF_MODEL_BOUNDARY_RADIUS * 2 + 1;

  for (uint32_t left_index = 0;
       left_index < gap_count; left_index++) {
    for (uint32_t right_index = left_index + 1;
         right_index < gap_count; right_index++) {
      const CfbfModelRun *first = &gaps[left_index];
      const CfbfModelRun *second = &gaps[right_index];

      if (second->actual < first->actual) {
        const CfbfModelRun *swap = first;

        first = second;
        second = swap;
      }
      if (first->actual + first->width > second->actual
          || first->actual <= (uint64_t)header_actual
          || second->actual <= (uint64_t)header_actual + first->width) {
        continue;
      }
      if (profile == CFBF_PROFILE_XLS
          && (first->evidence < CFBF_MINIMUM_BOUNDARY_EVIDENCE
              || second->evidence < CFBF_MINIMUM_BOUNDARY_EVIDENCE)) {
        continue;
      }
      const uint64_t first_slot = first->actual
                                  - (uint64_t)header_actual;
      const uint64_t second_slot = second->actual
                                   - (uint64_t)header_actual
                                   - first->width;
      const uint64_t cumulative_shift = first->width + second->width;

      if (first_slot == 0 || first_slot >= total_blocks
          || second_slot <= first_slot || second_slot >= total_blocks
          || !cfbf_reassembly_build_combined_suffix_mapping(
                 blockvector, base_mapping, first_mapping, first_slot,
                 first->width, header_actual, first->actual, first->width)
          || !cfbf_reassembly_build_combined_suffix_mapping(
                 blockvector, first_mapping, pair_mapping, second_slot,
                 cumulative_shift, header_actual, second->actual,
                 second->width)
          || !cfbf_reassembly_mapping_index_build(
                 &pair_index, pair_mapping, total_blocks)
          || !cfbf_reassembly_materialize_mapping(
                 blockvector, pair_mapping, base_data, trial_data,
                 length)) {
        continue;
      }
      CfbfTrialResult pair_result;

      memset(&pair_result, 0, sizeof(pair_result));
      if (!cfbf_reassembly_evaluate_data(
              trial_data, length, &pair_result)) {
        continue;
      }
      trials++;
      if (cfbf_reassembly_trial_recoverable(&pair_result)) {
        if (cfbf_reassembly_trial_authenticated(&pair_result)) {
          cfbf_reassembly_commit_mapping(*candidate, state, pair_mapping,
                                         &pair_result, 2);
          state->search_phase = CFBF_REASSEMBLY_FINALIZED;
          carve_put_state((*candidate)->carvehashkey, state);
          *improved = true;
          cfbf_reassembly_mapping_index_clear(&pair_index);
          free(trial_data);
          free(trial_mapping);
          free(pair_mapping);
          free(first_mapping);
          free(base_mapping);
          return false;
        }
        const CfbfModelHypothesis hypothesis = {
          .valid = 1,
          .kind = CFBF_MODEL_HYPOTHESIS_GAP_PAIR,
          .repairs = 2,
          .first_actual = first->actual,
          .first_width = first->width,
          .second_actual = second->actual,
          .second_width = second->width,
          .result = pair_result
        };

        if (cfbf_reassembly_trial_complete(&pair_result)) {
          cfbf_reassembly_retain_model_hypothesis(
              complete_hypotheses, &complete_hypothesis_count,
              CFBF_MODEL_COMPLETE_HYPOTHESIS_LIMIT, &hypothesis);
        }
        else {
          cfbf_reassembly_retain_model_hypothesis(
              partial_hypotheses, &partial_hypothesis_count,
              CFBF_MODEL_PARTIAL_HYPOTHESIS_LIMIT, &hypothesis);
        }
      }
      const bool pair_can_support_run = profile == CFBF_PROFILE_XLS
          || (pair_result.structurally_valid
              && pair_result.profile == CFBF_PROFILE_PPT);

      if (!pair_can_support_run) {
        if ((trials & UINT64_C(0x3f)) == 0) {
          if (atomic_load_explicit(
                  &REASS_RETURN_TO_IDLE, memory_order_acquire)) {
            cfbf_reassembly_flush_model_hypotheses(
                *candidate, state, base_mapping, first_mapping,
                pair_mapping, trial_mapping, &pair_index,
                complete_hypotheses, &complete_hypothesis_count,
                partial_hypotheses, &partial_hypothesis_count,
                header_actual);
            base_data = (const uint8_t *)
                blockvector_get_data_pointer(blockvector);
          }
          if (!base_data || cfbf_reassembly_poll(
                  work, candidate, state, uuidp, uuidc)) {
            cfbf_reassembly_mapping_index_clear(&pair_index);
            free(trial_data);
            free(trial_mapping);
            free(pair_mapping);
            free(first_mapping);
            free(base_mapping);
            return true;
          }
        }
        continue;
      }

      for (uint32_t target_index = 0;
           target_index < gap_count; target_index++) {
        const CfbfModelRun *target = &gaps[target_index];
        const bool overlaps_first = target->actual
                                         < first->actual + first->width
            && first->actual < target->actual + target->width;
        const bool overlaps_second = target->actual
                                          < second->actual + second->width
            && second->actual < target->actual + target->width;

        if (target->width > CFBF_NEARBY_RUN_WIDTH_LIMIT
            || overlaps_first || overlaps_second
            || (profile == CFBF_PROFILE_XLS
                && target->evidence
                       < CFBF_MINIMUM_BOUNDARY_EVIDENCE)) {
          continue;
        }
        uint64_t skipped = 0;

        if (target->actual >= first->actual + first->width) {
          skipped += first->width;
        }
        if (target->actual >= second->actual + second->width) {
          skipped += second->width;
        }
        if (target->actual < (uint64_t)header_actual + skipped) {
          continue;
        }
        const uint64_t target_slot = target->actual
                                     - (uint64_t)header_actual - skipped;

        if (target_slot == 0 || target_slot >= total_blocks
            || target->width > total_blocks - target_slot) {
          continue;
        }
        bool target_matches = true;
        uint32_t target_confidence[CFBF_NEARBY_RUN_WIDTH_LIMIT];

        for (uint64_t index = 0; index < target->width; index++) {
          const int64_t apparent = pair_mapping[target_slot + index];
          const int64_t actual = apparent >= 0
              ? filemirror_actual_blocknumber(
                    scalpel_state.filemirror, apparent)
              : -1;

          if (actual != (int64_t)(target->actual + index)) {
            target_matches = false;
            break;
          }
          target_confidence[index] = filemirror_get_blocktype(
              scalpel_state.filemirror, actual,
              (uint32_t)confidence_spec);
        }
        if (!target_matches) {
          continue;
        }

        CfbfModelRun sources[CFBF_MODEL_SOURCE_LIMIT];
        uint32_t source_count = 0;

        for (uint64_t source = 1;
             source + target->width < image_blocks; source++) {
          uint64_t confidence = 0;
          bool all_positive = true;

          for (uint64_t index = 0; index < target->width; index++) {
            const uint32_t value = filemirror_get_blocktype(
                scalpel_state.filemirror, (int64_t)(source + index),
                (uint32_t)confidence_spec);

            if (value <= target_confidence[index]) {
              all_positive = false;
              break;
            }
            confidence += value;
          }
          if (!all_positive) {
            continue;
          }
          const uint32_t before = filemirror_get_blocktype(
              scalpel_state.filemirror, (int64_t)source - 1,
              (uint32_t)confidence_spec);
          const uint32_t after = filemirror_get_blocktype(
              scalpel_state.filemirror,
              (int64_t)(source + target->width),
              (uint32_t)confidence_spec);
          const int64_t contrast = (int64_t)(confidence * UINT64_C(2))
              - (int64_t)(target->width
                          * ((uint64_t)before + (uint64_t)after));

          if (contrast <= 0) {
            continue;
          }
          const CfbfModelRun signal = {
            .actual = source,
            .width = target->width,
            .evidence = contrast,
            .confidence = confidence
          };

          cfbf_reassembly_retain_model_run(
              sources, &source_count, CFBF_MODEL_SOURCE_LIMIT, &signal);
        }

        for (uint32_t source_index = 0;
             source_index < source_count; source_index++) {
          const CfbfModelRun *source = &sources[source_index];

          if (!cfbf_reassembly_build_mapped_run_indexed(
                  blockvector, pair_mapping, &pair_index, trial_mapping,
                  target_slot, target->width, (int64_t)source->actual)
              || !cfbf_reassembly_update_mapping_data(
                     blockvector, pair_mapping, trial_mapping,
                     trial_data, length)) {
            continue;
          }
          CfbfTrialResult trial;

          memset(&trial, 0, sizeof(trial));
          trials++;
          const bool trial_evaluated = cfbf_reassembly_evaluate_data(
              trial_data, length, &trial);

          if (trial_evaluated
              && cfbf_reassembly_trial_recoverable(&trial)) {
            if (cfbf_reassembly_trial_authenticated(&trial)) {
              if (scalpel_state.mode_verbose) {
                lock_fprintf(
                    stdout,
                    "CFBF model combined repair selected:"
                    " header=%" PRId64 " gaps=%" PRIu64 "/%" PRIu64
                    ",%" PRIu64 "/%" PRIu64 " run=%" PRIu64
                    "/%" PRIu64 " source=%" PRIu64 " profile=%s.\n",
                    header_actual, first->actual, first->width,
                    second->actual, second->width, target_slot,
                    target->width, source->actual,
                    cfbf_profile_filetype(trial.profile));
              }
              cfbf_reassembly_commit_mapping(
                  *candidate, state, trial_mapping, &trial, 3);
              state->search_phase = CFBF_REASSEMBLY_FINALIZED;
              carve_put_state((*candidate)->carvehashkey, state);
              *improved = true;
              cfbf_reassembly_mapping_index_clear(&pair_index);
              free(trial_data);
              free(trial_mapping);
              free(pair_mapping);
              free(first_mapping);
              free(base_mapping);
              return false;
            }
            const CfbfModelHypothesis hypothesis = {
              .valid = 1,
              .kind = CFBF_MODEL_HYPOTHESIS_COMBINED,
              .repairs = 3,
              .first_actual = first->actual,
              .first_width = first->width,
              .second_actual = second->actual,
              .second_width = second->width,
              .run_slot = target_slot,
              .run_width = target->width,
              .source_actual = source->actual,
              .result = trial
            };

            if (cfbf_reassembly_trial_complete(&trial)) {
              cfbf_reassembly_retain_model_hypothesis(
                  complete_hypotheses, &complete_hypothesis_count,
                  CFBF_MODEL_COMPLETE_HYPOTHESIS_LIMIT, &hypothesis);
            }
            else {
              cfbf_reassembly_retain_model_hypothesis(
                  partial_hypotheses, &partial_hypothesis_count,
                  CFBF_MODEL_PARTIAL_HYPOTHESIS_LIMIT, &hypothesis);
            }
          }
          if (!cfbf_reassembly_update_mapping_data(
                  blockvector, trial_mapping, pair_mapping,
                  trial_data, length)
              && !cfbf_reassembly_materialize_mapping(
                     blockvector, pair_mapping, base_data, trial_data,
                     length)) {
            handle_error(
                SCALPEL_GENERAL_ABORT,
                "CFBF model combined mapping could not be restored",
                __LINE__, __FILE__);
          }
          if ((trials & UINT64_C(0x3f)) == 0) {
            if (atomic_load_explicit(
                    &REASS_RETURN_TO_IDLE, memory_order_acquire)) {
              cfbf_reassembly_flush_model_hypotheses(
                  *candidate, state, base_mapping, first_mapping,
                  pair_mapping, trial_mapping, &pair_index,
                  complete_hypotheses, &complete_hypothesis_count,
                  partial_hypotheses, &partial_hypothesis_count,
                  header_actual);
              base_data = (const uint8_t *)
                  blockvector_get_data_pointer(blockvector);
            }
            if (!base_data || cfbf_reassembly_poll(
                    work, candidate, state, uuidp, uuidc)) {
              cfbf_reassembly_mapping_index_clear(&pair_index);
              free(trial_data);
              free(trial_mapping);
              free(pair_mapping);
              free(first_mapping);
              free(base_mapping);
              return true;
            }
          }
        }
      }
    }
  }

  for (uint32_t gap_index = 0;
       gap_index < single_gap_count; gap_index++) {
    const CfbfModelRun *gap = &gaps[gap_index];
    const uint64_t source_boundary = gap->actual + gap->width;

    if (gap->actual > (uint64_t)INT64_MAX
        || source_boundary > (uint64_t)INT64_MAX) {
      continue;
    }

    for (uint32_t target_order = 0;
         target_order < boundary_positions; target_order++) {
      const int64_t target_delta = target_order == 0
          ? 0 : (target_order & 1U
                     ? (int64_t)((target_order + 1) / 2)
                     : -(int64_t)(target_order / 2));

      if ((target_delta < 0
           && gap->actual < (uint64_t)(-target_delta))
          || (target_delta > 0
              && gap->actual > UINT64_MAX - (uint64_t)target_delta)) {
        continue;
      }
      const int64_t target_actual = (int64_t)gap->actual + target_delta;
      const int64_t target_slot = cfbf_reassembly_find_mapping_actual(
          base_mapping, total_blocks, target_actual);

      if (target_actual <= header_actual || target_slot <= 0
          || (uint64_t)target_slot >= total_blocks) {
        continue;
      }

      for (uint32_t source_order = 0;
           source_order < boundary_positions; source_order++) {
        const int64_t source_delta = source_order == 0
            ? 0 : (source_order & 1U
                       ? (int64_t)((source_order + 1) / 2)
                       : -(int64_t)(source_order / 2));

        if ((source_delta < 0
             && source_boundary < (uint64_t)(-source_delta))
            || (source_delta > 0
                && source_boundary
                       > UINT64_MAX - (uint64_t)source_delta)) {
          continue;
        }
        const int64_t source_actual =
            (int64_t)source_boundary + source_delta;
        const int64_t nominal = header_actual + target_slot;

        if (source_actual <= nominal
            || (uint64_t)source_actual >= image_blocks) {
          continue;
        }
        const uint64_t shift = (uint64_t)(source_actual - nominal);
        uint64_t mapped_blocks = 0;

        if (!cfbf_reassembly_build_suffix_mapping_prefix(
                blockvector, base_mapping, trial_mapping,
                (uint64_t)target_slot, shift, header_actual, true,
                &mapped_blocks)
            || !cfbf_reassembly_materialize_mapping(
                   blockvector, trial_mapping, base_data, trial_data,
                   length)) {
          continue;
        }
        CfbfTrialResult trial;

        memset(&trial, 0, sizeof(trial));
        trials++;
        const bool evaluated = cfbf_reassembly_evaluate_data(
            trial_data, length, &trial);
        const bool mapped_trial_extent = evaluated
            && trial.inferred_size > 0
            && CEILDIV(trial.inferred_size, scalpel_state.blocksize)
                   <= mapped_blocks;

        if (mapped_trial_extent
            && cfbf_reassembly_trial_recoverable(&trial)) {
          if (cfbf_reassembly_trial_authenticated(&trial)) {
            if (scalpel_state.mode_verbose) {
              lock_fprintf(
                  stdout,
                  "CFBF model gap repair selected: header=%" PRId64
                  " target=%" PRId64 " source=%" PRId64
                  " shift=%" PRIu64 " profile=%s.\n",
                  header_actual, target_actual, source_actual, shift,
                  cfbf_profile_filetype(trial.profile));
            }
            cfbf_reassembly_commit_mapping(
                *candidate, state, trial_mapping, &trial, 1);
            state->search_phase = CFBF_REASSEMBLY_FINALIZED;
            carve_put_state((*candidate)->carvehashkey, state);
            *improved = true;
            cfbf_reassembly_mapping_index_clear(&pair_index);
            free(trial_data);
            free(trial_mapping);
            free(pair_mapping);
            free(first_mapping);
            free(base_mapping);
            return false;
          }
          const uint32_t repairs = shift > UINT32_MAX
              ? UINT32_MAX : (uint32_t)shift;
          const CfbfModelHypothesis hypothesis = {
            .valid = 1,
            .kind = CFBF_MODEL_HYPOTHESIS_SINGLE_GAP,
            .repairs = repairs,
            .target_slot = (uint64_t)target_slot,
            .shift = shift,
            .result = trial
          };

          if (cfbf_reassembly_trial_complete(&trial)) {
            cfbf_reassembly_retain_model_hypothesis(
                complete_hypotheses, &complete_hypothesis_count,
                CFBF_MODEL_COMPLETE_HYPOTHESIS_LIMIT, &hypothesis);
          }
          else {
            cfbf_reassembly_retain_model_hypothesis(
                partial_hypotheses, &partial_hypothesis_count,
                CFBF_MODEL_PARTIAL_HYPOTHESIS_LIMIT, &hypothesis);
          }
        }
        if ((trials & UINT64_C(0x0f)) == 0) {
          if (atomic_load_explicit(
                  &REASS_RETURN_TO_IDLE, memory_order_acquire)) {
            cfbf_reassembly_flush_model_hypotheses(
                *candidate, state, base_mapping, first_mapping,
                pair_mapping, trial_mapping, &pair_index,
                complete_hypotheses, &complete_hypothesis_count,
                partial_hypotheses, &partial_hypothesis_count,
                header_actual);
            base_data = (const uint8_t *)
                blockvector_get_data_pointer(blockvector);
          }
          if (!base_data || cfbf_reassembly_poll(
                  work, candidate, state, uuidp, uuidc)) {
            cfbf_reassembly_mapping_index_clear(&pair_index);
            free(trial_data);
            free(trial_mapping);
            free(pair_mapping);
            free(first_mapping);
            free(base_mapping);
            return true;
          }
        }
      }
    }
  }
  cfbf_reassembly_flush_model_hypotheses(
      *candidate, state, base_mapping, first_mapping, pair_mapping,
      trial_mapping, &pair_index, complete_hypotheses,
      &complete_hypothesis_count, partial_hypotheses,
      &partial_hypothesis_count, header_actual);
  cfbf_reassembly_mapping_index_clear(&pair_index);
  free(trial_data);
  free(trial_mapping);
  free(pair_mapping);
  free(first_mapping);
  free(base_mapping);
  state->model_search_complete = 1;
  state->model_search_repairs = state->repairs;
  carve_put_state((*candidate)->carvehashkey, state);
  return false;
}

// Order complete two-gap candidates by parser evidence before using filler
// concentration and physical location as tiebreakers. The content search never
// treats any ranking signal as proof; every resulting mapping is reparsed below.
//
static inline bool cfbf_reassembly_combined_pair_is_better(
    const CfbfCombinedPair *candidate, const CfbfCombinedPair *retained) {

  if (!candidate) {
    return false;
  }
  if (!retained) {
    return true;
  }
  if (candidate->authenticated != retained->authenticated) {
    return candidate->authenticated > retained->authenticated;
  }
  if (candidate->recoverable != retained->recoverable) {
    return candidate->recoverable > retained->recoverable;
  }
  if (candidate->complete != retained->complete) {
    return candidate->complete > retained->complete;
  }
  if (candidate->structurally_valid != retained->structurally_valid) {
    return candidate->structurally_valid > retained->structurally_valid;
  }
  if (candidate->score != retained->score) {
    return candidate->score > retained->score;
  }
  if (candidate->failure_offset != retained->failure_offset) {
    return candidate->failure_offset > retained->failure_offset;
  }
  if (candidate->zero_runs != retained->zero_runs) {
    return candidate->zero_runs < retained->zero_runs;
  }
  const uint64_t candidate_concentration = candidate->concentration
      / CFBF_CONTENT_CONCENTRATION_GRANULARITY;
  const uint64_t retained_concentration = retained->concentration
      / CFBF_CONTENT_CONCENTRATION_GRANULARITY;

  if (candidate_concentration != retained_concentration) {
    return candidate_concentration < retained_concentration;
  }
  if (candidate->first_actual != retained->first_actual) {
    return candidate->first_actual < retained->first_actual;
  }
  if (candidate->second_actual != retained->second_actual) {
    return candidate->second_actual < retained->second_actual;
  }
  if (candidate->minimum_evidence != retained->minimum_evidence) {
    return candidate->minimum_evidence > retained->minimum_evidence;
  }
  if (candidate->evidence != retained->evidence) {
    return candidate->evidence > retained->evidence;
  }
  if (candidate->target_concentration != retained->target_concentration) {
    return candidate->target_concentration < retained->target_concentration;
  }
  if (candidate->target_width != retained->target_width) {
    return candidate->target_width > retained->target_width;
  }
  if (candidate->concentration != retained->concentration) {
    return candidate->concentration < retained->concentration;
  }
  if (candidate->first_index != retained->first_index) {
    return candidate->first_index < retained->first_index;
  }
  return candidate->second_index < retained->second_index;
}

// Prefer a target that intersects the parser failure, then test equally
// plausible targets from the earliest unresolved logical slot. This affects
// trial order only.
//
static inline bool cfbf_reassembly_combined_target_is_better(
    const CfbfCombinedTarget *candidate,
    const CfbfCombinedTarget *retained) {

  if (!candidate) {
    return false;
  }
  if (!retained) {
    return true;
  }
  if (candidate->all_zero != retained->all_zero) {
    return candidate->all_zero < retained->all_zero;
  }
  if (candidate->failure_distance != retained->failure_distance) {
    return candidate->failure_distance < retained->failure_distance;
  }
  const uint64_t candidate_concentration = candidate->concentration
      / CFBF_CONTENT_CONCENTRATION_GRANULARITY;
  const uint64_t retained_concentration = retained->concentration
      / CFBF_CONTENT_CONCENTRATION_GRANULARITY;

  if (candidate_concentration != retained_concentration) {
    return candidate_concentration < retained_concentration;
  }
  if (candidate->slot != retained->slot) {
    return candidate->slot < retained->slot;
  }
  if (candidate->evidence != retained->evidence) {
    return candidate->evidence > retained->evidence;
  }
  if (candidate->width != retained->width) {
    return candidate->width > retained->width;
  }
  if (candidate->concentration != retained->concentration) {
    return candidate->concentration < retained->concentration;
  }
  return candidate->gap_index < retained->gap_index;
}

// Rebuild one retained combined hypothesis from compact search coordinates.
// The mapping is deterministic, so retaining coordinates avoids a full extra
// blockvector-sized buffer while the search compares parser evidence.
//
static inline bool cfbf_reassembly_write_content_hypothesis(
    CarveInfo *candidate, CfbfCarveState *state,
    const int64_t *base_mapping, int64_t *first_mapping,
    int64_t *pair_mapping, int64_t *trial_mapping,
    CfbfMappingIndex *pair_index, const CfbfModelRun *gaps,
    uint32_t gap_count, const CfbfCombinedPair *pairs,
    uint32_t pair_count, CfbfContentHypothesis *hypothesis,
    int64_t header_actual) {

  if (!candidate || !candidate->b || !state || !base_mapping
      || !first_mapping || !pair_mapping || !trial_mapping || !pair_index
      || !gaps || !pairs || !hypothesis || hypothesis->valid == 0
      || header_actual < 0
      || hypothesis->pair_position >= pair_count
      || hypothesis->target_gap_index >= gap_count
      || hypothesis->source_actual > (uint64_t)INT64_MAX) {
    return false;
  }
  const CfbfCombinedPair *pair = &pairs[hypothesis->pair_position];

  if (pair->first_index >= gap_count || pair->second_index >= gap_count) {
    return false;
  }
  const CfbfModelRun *first = &gaps[pair->first_index];
  const CfbfModelRun *second = &gaps[pair->second_index];
  const CfbfModelRun *target = &gaps[hypothesis->target_gap_index];
  const uint64_t total_blocks = blockvector_get_num_blocks(candidate->b);

  if (first->actual <= (uint64_t)header_actual
      || second->actual <= (uint64_t)header_actual + first->width
      || first->width > UINT64_MAX - second->width) {
    return false;
  }
  const uint64_t first_slot = first->actual - (uint64_t)header_actual;
  const uint64_t second_slot = second->actual
                               - (uint64_t)header_actual - first->width;
  const uint64_t cumulative_shift = first->width + second->width;

  if (first_slot == 0 || first_slot >= total_blocks
      || second_slot <= first_slot || second_slot >= total_blocks
      || hypothesis->target_slot == 0
      || hypothesis->target_slot >= total_blocks
      || target->width > total_blocks - hypothesis->target_slot
      || !cfbf_reassembly_build_combined_suffix_mapping(
             candidate->b, base_mapping, first_mapping, first_slot,
             first->width, header_actual, first->actual, first->width)
      || !cfbf_reassembly_build_combined_suffix_mapping(
             candidate->b, first_mapping, pair_mapping, second_slot,
             cumulative_shift, header_actual, second->actual, second->width)
      || !cfbf_reassembly_mapping_index_build(
             pair_index, pair_mapping, total_blocks)
      || !cfbf_reassembly_build_mapped_run_indexed(
             candidate->b, pair_mapping, pair_index, trial_mapping,
             hypothesis->target_slot, target->width,
             (int64_t)hypothesis->source_actual)) {
    return false;
  }
  const bool written = cfbf_reassembly_write_mapping_hypothesis(
      candidate, state, trial_mapping, &hypothesis->result,
      hypothesis->repairs, true);

  if (written) {
    hypothesis->dirty = 0;
  }
  return written;
}

// Test pairs of physical gaps supported independently by allocation state or
// uniform filler. These bounded hypotheses precede searches that mutate the
// primary mapping, while complete CFBF validation remains authoritative.
//
static inline bool cfbf_reassembly_try_supported_gap_pairs(
    ThreadWork *work, CarveInfo **candidate, CfbfCarveState *state,
    uint32_t maximum_gap_count, uuid_string_t uuidp,
    uuid_string_t uuidc, bool *attempted, bool *improved) {

  if (!work || !candidate || !*candidate || !(*candidate)->b || !state
      || !attempted || !improved || state->search_phase != 0
      || state->repairs != 0) {
    return false;
  }
  *attempted = false;
  *improved = false;

  BlockVector *blockvector = (*candidate)->b;
  const uint64_t total_blocks = blockvector_get_num_blocks(blockvector);
  const uint64_t image_blocks = CEILDIV(
      filemirror_filesize(scalpel_state.filemirror), scalpel_state.blocksize);
  const int64_t header_actual = blockvector_get_actual_blocknumber(
      blockvector, 0);
  const uint64_t length = blockvector_get_data_length(blockvector);

  if (total_blocks < 4 || image_blocks < 4 || header_actual < 0
      || (uint64_t)header_actual >= image_blocks || length == 0) {
    return false;
  }

  CfbfModelRun gaps[CFBF_SUPPORTED_GAP_LIMIT];
  uint64_t signal_end = (uint64_t)header_actual + total_blocks
                        + CFBF_NEARBY_SUFFIX_SHIFT_LIMIT * 2;

  if (signal_end > image_blocks) {
    signal_end = image_blocks;
  }
  const uint32_t gap_count = cfbf_reassembly_collect_supported_gaps(
      header_actual, signal_end, gaps, CFBF_SUPPORTED_GAP_LIMIT);

  if (gap_count < 2
      || (maximum_gap_count != 0 && gap_count > maximum_gap_count)) {
    return false;
  }
  *attempted = true;
  if (scalpel_state.mode_verbose) {
    lock_fprintf(
        stdout,
        "CFBF supported gap signals: header=%" PRId64
        " count=%" PRIu32 ".\n",
        header_actual, gap_count);
    for (uint32_t index = 0; index < gap_count; index++) {
      lock_fprintf(
          stdout,
          "  signal=%" PRIu32 " actual=%" PRIu64
          " width=%" PRIu64 " evidence=%" PRId64 ".\n",
          index, gaps[index].actual,
          gaps[index].width, gaps[index].evidence);
    }
  }

  int64_t *base_mapping = (int64_t *)malloc(
      (size_t)total_blocks * sizeof(*base_mapping));
  int64_t *first_mapping = (int64_t *)malloc(
      (size_t)total_blocks * sizeof(*first_mapping));
  int64_t *pair_mapping = (int64_t *)malloc(
      (size_t)total_blocks * sizeof(*pair_mapping));
  uint8_t *trial_data = (uint8_t *)malloc((size_t)length);

  check_memory_allocation(base_mapping, __LINE__, __FILE__,
                          "CFBF supported pair base mapping");
  check_memory_allocation(first_mapping, __LINE__, __FILE__,
                          "CFBF supported pair first mapping");
  check_memory_allocation(pair_mapping, __LINE__, __FILE__,
                          "CFBF supported pair mapping");
  check_memory_allocation(trial_data, __LINE__, __FILE__,
                          "CFBF supported pair trial data");

  for (uint64_t slot = 0; slot < total_blocks; slot++) {
    base_mapping[slot] = blockvector_get_apparent_blocknumber(
        blockvector, slot);
  }
  const uint8_t *base_data = (const uint8_t *)
      blockvector_get_data_pointer(blockvector);

  if (!base_data) {
    free(trial_data);
    free(pair_mapping);
    free(first_mapping);
    free(base_mapping);
    return false;
  }

  uint64_t trials = 0;
  uint32_t hypotheses_written = 0;

  for (uint32_t left_index = 0; left_index < gap_count; left_index++) {
    for (uint32_t right_index = left_index + 1;
         right_index < gap_count; right_index++) {
      const CfbfModelRun *first = &gaps[left_index];
      const CfbfModelRun *second = &gaps[right_index];

      if (second->actual < first->actual) {
        const CfbfModelRun *swap = first;

        first = second;
        second = swap;
      }
      trials++;
      if (first->actual > UINT64_MAX - first->width
          || first->actual + first->width > second->actual
          || first->actual <= (uint64_t)header_actual
          || second->actual
                 <= (uint64_t)header_actual + first->width
          || first->width > UINT64_MAX - second->width) {
        goto cfbf_supported_pair_prepass_poll;
      }
      const uint64_t first_slot = first->actual
                                  - (uint64_t)header_actual;
      const uint64_t second_slot = second->actual
                                   - (uint64_t)header_actual
                                   - first->width;
      const uint64_t cumulative_shift = first->width + second->width;

      if (first_slot == 0 || first_slot >= total_blocks
          || second_slot <= first_slot || second_slot >= total_blocks
          || !cfbf_reassembly_build_combined_suffix_mapping(
                 blockvector, base_mapping, first_mapping, first_slot,
                 first->width, header_actual, first->actual, first->width)
          || !cfbf_reassembly_build_combined_suffix_mapping(
                 blockvector, first_mapping, pair_mapping, second_slot,
                 cumulative_shift, header_actual, second->actual,
                 second->width)
          || !cfbf_reassembly_materialize_mapping(
                 blockvector, pair_mapping, base_data, trial_data, length)) {
        goto cfbf_supported_pair_prepass_poll;
      }
      CfbfTrialResult result;

      memset(&result, 0, sizeof(result));
      const bool evaluated = cfbf_reassembly_evaluate_data(
          trial_data, length, &result);

      if (scalpel_state.mode_verbose) {
        lock_fprintf(
            stdout,
            "CFBF supported pair trial: gaps=%" PRIu64 "/%" PRIu64
            ",%" PRIu64 "/%" PRIu64
            " structural=%s profile=%s semantic=%u"
            " inferred=%" PRIu64 " failure=%" PRIu64 ".\n",
            first->actual, first->width, second->actual, second->width,
            result.structurally_valid ? "true" : "false",
            cfbf_profile_filetype(result.profile),
            (uint32_t)result.semantic_strength,
            result.inferred_size, result.failure_offset);
      }
      if (evaluated && cfbf_reassembly_trial_recoverable(&result)) {
        const uint32_t repairs = cumulative_shift > UINT32_MAX
            ? UINT32_MAX : (uint32_t)cumulative_shift;

        if (cfbf_reassembly_trial_authenticated(&result)) {
          cfbf_reassembly_commit_mapping(
              *candidate, state, pair_mapping, &result, repairs);
          state->search_phase = CFBF_REASSEMBLY_FINALIZED;
          carve_put_state((*candidate)->carvehashkey, state);
          *improved = true;
          if (scalpel_state.mode_verbose) {
            lock_fprintf(
                stdout,
                "CFBF supported two-gap repair selected: header=%" PRId64
                " gaps=%" PRIu64 "/%" PRIu64 ",%" PRIu64 "/%" PRIu64
                " profile=%s.\n",
                header_actual, first->actual, first->width,
                second->actual, second->width,
                cfbf_profile_filetype(result.profile));
          }
          free(trial_data);
          free(pair_mapping);
          free(first_mapping);
          free(base_mapping);
          return false;
        }
        if (hypotheses_written < CFBF_CONTENT_PAIR_HYPOTHESIS_LIMIT
            && cfbf_reassembly_write_mapping_hypothesis(
                   *candidate, state, pair_mapping, &result,
                   repairs, true)) {
          hypotheses_written++;
          base_data = (const uint8_t *)
              blockvector_get_data_pointer(blockvector);
          if (!base_data) {
            free(trial_data);
            free(pair_mapping);
            free(first_mapping);
            free(base_mapping);
            return false;
          }
        }
      }

cfbf_supported_pair_prepass_poll:
      if ((trials & UINT64_C(0x0f)) == 0
          && cfbf_reassembly_poll(
                 work, candidate, state, uuidp, uuidc)) {
        free(trial_data);
        free(pair_mapping);
        free(first_mapping);
        free(base_mapping);
        return true;
      }
    }
  }

  free(trial_data);
  free(pair_mapping);
  free(first_mapping);
  free(base_mapping);
  return false;
}

// Repair two inserted physical runs and, when necessary, one displaced logical
// run as a single hypothesis when no subtype-specific model solver succeeds.
// Low-concentration islands identify where data may have been inserted; byte
// continuity orders possible displaced sources. Ambiguous complete mappings are
// written as PROMISING alternatives rather than allowing opaque stream data to
// become an unsupported validation decision.
//
static inline bool cfbf_reassembly_try_content_combined(
    ThreadWork *work, CarveInfo **candidate, CfbfCarveState *state,
    const CfbfTrialResult *current, uuid_string_t uuidp,
    uuid_string_t uuidc, bool *improved) {

  if (!work || !candidate || !*candidate || !(*candidate)->b || !state
      || !current || !improved) {
    return false;
  }
  *improved = false;

  const bool resuming = state->search_phase
                        == CFBF_REASSEMBLY_CONTENT_COMBINED;

  if ((!resuming && state->search_phase != 0) || state->repairs != 0) {
    return false;
  }

  BlockVector *blockvector = (*candidate)->b;
  const uint64_t total_blocks = blockvector_get_num_blocks(blockvector);
  const uint64_t image_blocks = CEILDIV(
      filemirror_filesize(scalpel_state.filemirror), scalpel_state.blocksize);
  const int64_t header_actual = blockvector_get_actual_blocknumber(
      blockvector, 0);
  const uint64_t length = blockvector_get_data_length(blockvector);

  if (total_blocks < 4 || image_blocks < 4 || header_actual < 0
      || (uint64_t)header_actual >= image_blocks || length == 0) {
    return false;
  }

  CfbfModelRun gaps[CFBF_MODEL_GAP_LIMIT];
  uint32_t gap_count = 0;
  uint64_t signal_end = (uint64_t)header_actual + total_blocks
                        + CFBF_NEARBY_SUFFIX_SHIFT_LIMIT * 2;

  if (signal_end > image_blocks) {
    signal_end = image_blocks;
  }
  uint64_t actual = (uint64_t)header_actual + 1;

  while (actual < signal_end) {
    uint64_t first_concentration = cfbf_reassembly_run_concentration(
        (int64_t)actual, 1);

    if (first_concentration > CFBF_STRONG_FILLER_CONCENTRATION_LIMIT) {
      actual++;
      continue;
    }
    const uint64_t run_start = actual;
    uint64_t maximum_concentration = first_concentration;
    uint64_t total_concentration = 0;
    uint64_t prior_concentration = cfbf_reassembly_run_concentration(
        (int64_t)run_start - 1, 1);
    uint64_t concentration = first_concentration;
    uint64_t right_concentration = UINT64_MAX;
    uint64_t embedded_start = UINT64_MAX;
    uint64_t embedded_concentration = 0;
    bool prior_zero = filemirror_actual_block_is_zero(
        scalpel_state.filemirror, (int64_t)run_start - 1);
    bool all_zero = true;

    while (actual < signal_end) {
      if (concentration > CFBF_STRONG_FILLER_CONCENTRATION_LIMIT) {
        break;
      }
      const bool block_zero = filemirror_actual_block_is_zero(
          scalpel_state.filemirror, (int64_t)actual);

      if (!block_zero && prior_zero && embedded_start == UINT64_MAX) {
        embedded_start = actual;
        embedded_concentration = 0;
      }
      if (!block_zero && embedded_start != UINT64_MAX) {
        if (embedded_concentration <= UINT64_MAX - concentration) {
          embedded_concentration += concentration;
        }
        else {
          embedded_concentration = UINT64_MAX;
        }
      }
      else if (block_zero && embedded_start != UINT64_MAX) {
        const uint64_t embedded_width = actual - embedded_start;

        if (embedded_width <= CFBF_NEARBY_RUN_WIDTH_LIMIT) {
          const uint64_t average = embedded_concentration == UINT64_MAX
                                       ? UINT64_MAX
                                       : embedded_concentration
                                             / embedded_width;
          const CfbfModelRun embedded = {
            .all_zero = 0,
            .actual = embedded_start,
            .width = embedded_width,
            .evidence = average >= (uint64_t)INT64_MAX
                            ? 1 : INT64_MAX - (int64_t)average,
            .confidence = average
          };

          cfbf_reassembly_retain_model_run(
              gaps, &gap_count, CFBF_MODEL_GAP_LIMIT, &embedded);
        }
        embedded_start = UINT64_MAX;
        embedded_concentration = 0;
      }
      if (concentration > maximum_concentration) {
        maximum_concentration = concentration;
      }
      if (total_concentration <= UINT64_MAX - concentration) {
        total_concentration += concentration;
      }
      else {
        total_concentration = UINT64_MAX;
      }
      if (!block_zero) {
        all_zero = false;
      }
      actual++;
      right_concentration = actual < image_blocks
          ? cfbf_reassembly_run_concentration((int64_t)actual, 1)
          : UINT64_MAX;

      // Preserve an isolated filler block even when neighboring opaque file
      // data also falls below the broad low-concentration threshold.
      if (prior_concentration > concentration
          && right_concentration > concentration) {
        const uint64_t boundary_concentration =
            prior_concentration < right_concentration
                ? prior_concentration : right_concentration;
        const uint64_t difference = boundary_concentration - concentration;
        const CfbfModelRun signal = {
          .all_zero = block_zero ? 1 : 0,
          .actual = actual - 1,
          .width = 1,
          .evidence = difference > (uint64_t)INT64_MAX
                          ? INT64_MAX : (int64_t)difference,
          .confidence = concentration
        };

        cfbf_reassembly_retain_model_run(
            gaps, &gap_count, CFBF_MODEL_GAP_LIMIT, &signal);
      }
      prior_concentration = concentration;
      concentration = right_concentration;
      prior_zero = block_zero;
    }
    const uint64_t width = actual - run_start;

    if (width == 0 || width > CFBF_NEARBY_RUN_WIDTH_LIMIT
        || run_start == 0 || actual >= image_blocks) {
      continue;
    }
    if (width == 1) {
      continue;
    }
    const uint64_t left_concentration = cfbf_reassembly_run_concentration(
        (int64_t)run_start - 1, 1);
    const uint64_t boundary_concentration = left_concentration
                                                < right_concentration
                                            ? left_concentration
                                            : right_concentration;

    if (boundary_concentration <= maximum_concentration) {
      continue;
    }
    const uint64_t difference = boundary_concentration
                                - maximum_concentration;
    const CfbfModelRun signal = {
      .all_zero = all_zero ? 1 : 0,
      .actual = run_start,
      .width = width,
      .evidence = difference > (uint64_t)INT64_MAX
                      ? INT64_MAX : (int64_t)difference,
      .confidence = total_concentration == UINT64_MAX
                        ? UINT64_MAX : total_concentration / width
    };

    cfbf_reassembly_retain_model_run(
        gaps, &gap_count, CFBF_MODEL_GAP_LIMIT, &signal);
  }
  if (gap_count < 2) {
    return false;
  }
  // A damaged allocation sector can truncate the first exploratory extent.
  // Expose one additional header-bounded repair window before combined search.
  if (!state->content_extent_expanded
      && !cfbf_reassembly_trial_recoverable(current)) {
    const uint8_t *candidate_data = (const uint8_t *)
        blockvector_get_data_pointer(blockvector);
    const uint64_t expanded_extent = cfbf_header_search_extent(
        candidate_data, length, length);
    const uint64_t expanded_blocks = CEILDIV(
        expanded_extent, scalpel_state.blocksize);
    const uint64_t available_blocks = image_blocks - (uint64_t)header_actual;

    state->content_extent_expanded = 1;
    if (expanded_blocks > total_blocks
        && expanded_blocks <= available_blocks) {
      resize_blockvector(blockvector, expanded_blocks);
      for (uint64_t slot = total_blocks; slot < expanded_blocks; slot++) {
        const int64_t expanded_actual = header_actual + (int64_t)slot;
        int64_t apparent = filemirror_apparent_blocknumber(
            scalpel_state.filemirror, expanded_actual);

        if (apparent < 0
            && !filemirror_actual_block_is_zero(
                   scalpel_state.filemirror, expanded_actual)) {
          resize_blockvector(blockvector, total_blocks);
          inflate_blockvector(blockvector);
          blockvector_set_data_length(blockvector, length);
          carve_put_state((*candidate)->carvehashkey, state);
          return false;
        }
        blockvector_set_apparent_blocknumber(blockvector, slot, apparent);
      }
      inflate_blockvector(blockvector);
      blockvector_set_data_length(
          blockvector, expanded_blocks * (uint64_t)scalpel_state.blocksize);
      carve_put_state((*candidate)->carvehashkey, state);
      *improved = true;
      if (scalpel_state.mode_verbose) {
        lock_fprintf(
            stdout,
            "CFBF boundary search extent expanded: header=%" PRId64
            " blocks=%" PRIu64 "->%" PRIu64 ".\n",
            header_actual, total_blocks, expanded_blocks);
      }
      return false;
    }
    carve_put_state((*candidate)->carvehashkey, state);
  }

  int64_t *base_mapping = (int64_t *)malloc(
      (size_t)total_blocks * sizeof(*base_mapping));
  int64_t *first_mapping = (int64_t *)malloc(
      (size_t)total_blocks * sizeof(*first_mapping));
  int64_t *pair_mapping = (int64_t *)malloc(
      (size_t)total_blocks * sizeof(*pair_mapping));
  int64_t *trial_mapping = (int64_t *)malloc(
      (size_t)total_blocks * sizeof(*trial_mapping));
  uint8_t *trial_data = (uint8_t *)malloc((size_t)length);

  check_memory_allocation(base_mapping, __LINE__, __FILE__,
                          "CFBF content combined base mapping");
  check_memory_allocation(first_mapping, __LINE__, __FILE__,
                          "CFBF content combined first mapping");
  check_memory_allocation(pair_mapping, __LINE__, __FILE__,
                          "CFBF content combined pair mapping");
  check_memory_allocation(trial_mapping, __LINE__, __FILE__,
                          "CFBF content combined trial mapping");
  check_memory_allocation(trial_data, __LINE__, __FILE__,
                          "CFBF content combined trial data");

  for (uint64_t slot = 0; slot < total_blocks; slot++) {
    base_mapping[slot] = blockvector_get_apparent_blocknumber(
        blockvector, slot);
  }
  const uint8_t *base_data = (const uint8_t *)
      blockvector_get_data_pointer(blockvector);
  CfbfMappingIndex pair_index = { 0 };

  if (!base_data
      || !cfbf_reassembly_mapping_index_initialize(
             &pair_index, total_blocks)) {
    cfbf_reassembly_mapping_index_clear(&pair_index);
    free(trial_data);
    free(trial_mapping);
    free(pair_mapping);
    free(first_mapping);
    free(base_mapping);
    return false;
  }

  CfbfCombinedPair pairs[CFBF_CONTENT_PAIR_LIMIT];
  uint32_t pair_count = 0;
  uint32_t pair_hypothesis_written = 0;
  uint64_t trials = 0;

  for (uint32_t left_index = 0; left_index < gap_count; left_index++) {
    for (uint32_t right_index = left_index + 1;
         right_index < gap_count; right_index++) {
      uint32_t first_index = left_index;
      uint32_t second_index = right_index;

      if (gaps[second_index].actual < gaps[first_index].actual) {
        const uint32_t swap = first_index;

        first_index = second_index;
        second_index = swap;
      }
      const CfbfModelRun *first = &gaps[first_index];
      const CfbfModelRun *second = &gaps[second_index];

      if (first->actual + first->width > second->actual
          || first->actual <= (uint64_t)header_actual
          || second->actual <= (uint64_t)header_actual + first->width) {
        continue;
      }
      const uint64_t first_slot = first->actual
                                  - (uint64_t)header_actual;
      const uint64_t second_slot = second->actual
                                   - (uint64_t)header_actual
                                   - first->width;
      const uint64_t cumulative_shift = first->width + second->width;

      if (first_slot == 0 || first_slot >= total_blocks
          || second_slot <= first_slot || second_slot >= total_blocks
          || !cfbf_reassembly_build_combined_suffix_mapping(
                 blockvector, base_mapping, first_mapping, first_slot,
                 first->width, header_actual, first->actual, first->width)
          || !cfbf_reassembly_build_combined_suffix_mapping(
                 blockvector, first_mapping, pair_mapping, second_slot,
                 cumulative_shift, header_actual, second->actual,
                 second->width)
          || !cfbf_reassembly_materialize_mapping(
                 blockvector, pair_mapping, base_data, trial_data, length)) {
        continue;
      }
      CfbfTrialResult pair_result;

      memset(&pair_result, 0, sizeof(pair_result));
      if (!cfbf_reassembly_evaluate_data(
              trial_data, length, &pair_result)) {
        continue;
      }
      if (!cfbf_reassembly_trial_recoverable(&pair_result)
          && pair_result.failure_offset != 0) {
        const uint64_t failure_slot = pair_result.failure_offset
                                      / scalpel_state.blocksize;

        // Signals beyond the parser frontier cannot explain the failure
        // produced by this pair. Later gaps remain eligible when an earlier
        // correction advances that frontier.
        if (first_slot > failure_slot || second_slot > failure_slot) {
          continue;
        }
      }
      if (cfbf_reassembly_trial_recoverable(&pair_result)
          && pair_result.inferred_size != 0) {
        const uint64_t inferred_blocks = CEILDIV(
            pair_result.inferred_size, scalpel_state.blocksize);

        if (first_slot >= inferred_blocks
            || first->width > inferred_blocks - first_slot
            || second_slot >= inferred_blocks
            || second->width > inferred_blocks - second_slot) {
          continue;
        }
      }
      uint32_t target_all_zero = 1;
      uint64_t target_concentration = UINT64_MAX;
      uint64_t target_width = 0;

      for (uint32_t gap_index = 0; gap_index < gap_count; gap_index++) {
        if (gap_index == first_index || gap_index == second_index) {
          continue;
        }
        const CfbfModelRun *target = &gaps[gap_index];

        if (target->all_zero < target_all_zero
            || (target->all_zero == target_all_zero
                && target->confidence < target_concentration)
            || (target->all_zero == target_all_zero
                && target->confidence == target_concentration
                && target->width > target_width)) {
          target_all_zero = target->all_zero;
          target_concentration = target->confidence;
          target_width = target->width;
        }
      }
      const CfbfCombinedPair pair = {
        .first_index = first_index,
        .second_index = second_index,
        .authenticated =
            cfbf_reassembly_trial_authenticated(&pair_result) ? 1 : 0,
        .recoverable = cfbf_reassembly_trial_recoverable(&pair_result) ? 1 : 0,
        .complete = cfbf_reassembly_trial_complete(&pair_result) ? 1 : 0,
        .structurally_valid = pair_result.structurally_valid ? 1 : 0,
        .zero_runs = first->all_zero + second->all_zero,
        .score = pair_result.score,
        .failure_offset = pair_result.failure_offset,
        .target_concentration = target_concentration,
        .target_width = target_width,
        .concentration = first->confidence > UINT64_MAX - second->confidence
                             ? UINT64_MAX
                             : first->confidence + second->confidence,
        .first_actual = first->actual,
        .second_actual = second->actual,
        .minimum_evidence = first->evidence < second->evidence
                                ? first->evidence : second->evidence,
        .evidence = first->evidence > INT64_MAX - second->evidence
                        ? INT64_MAX : first->evidence + second->evidence
      };
      uint32_t position = 0;

      while (position < pair_count
             && !cfbf_reassembly_combined_pair_is_better(
                    &pair, &pairs[position])) {
        position++;
      }
      if (position < CFBF_CONTENT_PAIR_LIMIT) {
        uint32_t move_end = pair_count < CFBF_CONTENT_PAIR_LIMIT
                                ? pair_count : CFBF_CONTENT_PAIR_LIMIT - 1;

        while (move_end > position) {
          pairs[move_end] = pairs[move_end - 1];
          move_end--;
        }
        pairs[position] = pair;
        if (pair_count < CFBF_CONTENT_PAIR_LIMIT) {
          pair_count++;
        }
      }
      trials++;
      if ((trials & UINT64_C(0x3f)) == 0
          && cfbf_reassembly_poll(
                 work, candidate, state, uuidp, uuidc)) {
        cfbf_reassembly_mapping_index_clear(&pair_index);
        free(trial_data);
        free(trial_mapping);
        free(pair_mapping);
        free(first_mapping);
        free(base_mapping);
        return true;
      }
    }
  }
  if (pair_count == 0) {
    cfbf_reassembly_mapping_index_clear(&pair_index);
    free(trial_data);
    free(trial_mapping);
    free(pair_mapping);
    free(first_mapping);
    free(base_mapping);
    return false;
  }
  // A complete two-gap mapping needs no displaced-run hypothesis. Rebuild only
  // the strongest recoverable pair after ranking; opaque formats retain it as
  // PROMISING while fully authenticated content terminates the search.
  if (pairs[0].recoverable != 0) {
    const CfbfModelRun *first = &gaps[pairs[0].first_index];
    const CfbfModelRun *second = &gaps[pairs[0].second_index];
    const uint64_t first_slot = first->actual
                                - (uint64_t)header_actual;
    const uint64_t second_slot = second->actual
                                 - (uint64_t)header_actual - first->width;
    const uint64_t cumulative_shift = first->width + second->width;
    CfbfTrialResult pair_result;

    memset(&pair_result, 0, sizeof(pair_result));
    if (cfbf_reassembly_build_combined_suffix_mapping(
            blockvector, base_mapping, first_mapping, first_slot,
            first->width, header_actual, first->actual, first->width)
        && cfbf_reassembly_build_combined_suffix_mapping(
               blockvector, first_mapping, pair_mapping, second_slot,
               cumulative_shift, header_actual, second->actual,
               second->width)
        && cfbf_reassembly_materialize_mapping(
               blockvector, pair_mapping, base_data, trial_data, length)
        && cfbf_reassembly_evaluate_data(
               trial_data, length, &pair_result)
        && cfbf_reassembly_trial_recoverable(&pair_result)) {
      const uint32_t repairs = cumulative_shift > UINT32_MAX
          ? UINT32_MAX : (uint32_t)cumulative_shift;

      if (cfbf_reassembly_trial_authenticated(&pair_result)) {
        cfbf_reassembly_commit_mapping(
            *candidate, state, pair_mapping, &pair_result, repairs);
        state->search_phase = CFBF_REASSEMBLY_FINALIZED;
        carve_put_state((*candidate)->carvehashkey, state);
        *improved = true;
        if (scalpel_state.mode_verbose) {
          lock_fprintf(
              stdout,
              "CFBF content two-gap repair selected: header=%" PRId64
              " gaps=%" PRIu64 "/%" PRIu64 ",%" PRIu64 "/%" PRIu64
              " profile=%s.\n",
              header_actual, first->actual, first->width,
              second->actual, second->width,
              cfbf_profile_filetype(pair_result.profile));
        }
        cfbf_reassembly_mapping_index_clear(&pair_index);
        free(trial_data);
        free(trial_mapping);
        free(pair_mapping);
        free(first_mapping);
        free(base_mapping);
        return false;
      }
      if (cfbf_reassembly_write_mapping_hypothesis(
              *candidate, state, pair_mapping, &pair_result, repairs,
              true)) {
        pair_hypothesis_written = 1;
        base_data = (const uint8_t *)
            blockvector_get_data_pointer(blockvector);
        if (!base_data) {
          cfbf_reassembly_mapping_index_clear(&pair_index);
          free(trial_data);
          free(trial_mapping);
          free(pair_mapping);
          free(first_mapping);
          free(base_mapping);
          return false;
        }
      }
    }
  }
  uint64_t first_pair_position = resuming ? state->resume_slot : 0;

  if (first_pair_position >= pair_count) {
    first_pair_position = 0;
  }
  if (!resuming) {
    state->resume_slot = 0;
    state->resume_run_width = 0;
    state->resume_choice = 0;
  }
  state->search_phase = CFBF_REASSEMBLY_CONTENT_COMBINED;
  carve_put_state((*candidate)->carvehashkey, state);

  uint64_t recoverable_hypotheses = 0;
  uint32_t repair_trials = 0;
  uint32_t written_hypotheses = 0;
  CfbfContentHypothesis retained_hypothesis;

  memset(&retained_hypothesis, 0, sizeof(retained_hypothesis));

  for (uint32_t pair_position = (uint32_t)first_pair_position;
       pair_position < pair_count
       && repair_trials < CFBF_CONTENT_TRIAL_LIMIT
       && recoverable_hypotheses < CFBF_CONTENT_HYPOTHESIS_LIMIT;
       pair_position++) {
    const CfbfCombinedPair *pair = &pairs[pair_position];
    const CfbfModelRun *first = &gaps[pair->first_index];
    const CfbfModelRun *second = &gaps[pair->second_index];
    const uint64_t first_slot = first->actual
                                - (uint64_t)header_actual;
    const uint64_t second_slot = second->actual
                                 - (uint64_t)header_actual
                                 - first->width;
    const uint64_t cumulative_shift = first->width + second->width;

    if (!cfbf_reassembly_build_combined_suffix_mapping(
            blockvector, base_mapping, first_mapping, first_slot,
            first->width, header_actual, first->actual, first->width)
        || !cfbf_reassembly_build_combined_suffix_mapping(
               blockvector, first_mapping, pair_mapping, second_slot,
               cumulative_shift, header_actual, second->actual,
               second->width)
        || !cfbf_reassembly_mapping_index_build(
               &pair_index, pair_mapping, total_blocks)
        || !cfbf_reassembly_materialize_mapping(
               blockvector, pair_mapping, base_data, trial_data, length)) {
      continue;
    }
    CfbfTrialResult pair_result;

    memset(&pair_result, 0, sizeof(pair_result));
    if (!cfbf_reassembly_evaluate_data(trial_data, length, &pair_result)) {
      continue;
    }
    CfbfCombinedTarget targets[CFBF_CONTENT_TARGET_LIMIT];
    uint32_t target_count = 0;
    const uint64_t failure_slot = pair_result.failure_offset
                                  / scalpel_state.blocksize;
    uint64_t target_block_limit = total_blocks;

    if (cfbf_reassembly_trial_recoverable(&pair_result)
        && pair_result.inferred_size != 0) {
      const uint64_t inferred_blocks = CEILDIV(
          pair_result.inferred_size, scalpel_state.blocksize);

      if (inferred_blocks < target_block_limit) {
        target_block_limit = inferred_blocks;
      }
    }
    else if (pair_result.failure_offset != 0
             && failure_slot < target_block_limit) {
      target_block_limit = failure_slot + 1;
    }

    for (uint32_t gap_index = 0; gap_index < gap_count; gap_index++) {
      if (gap_index == pair->first_index || gap_index == pair->second_index) {
        continue;
      }
      const CfbfModelRun *target = &gaps[gap_index];
      uint64_t skipped = 0;

      if (target->actual >= first->actual + first->width) {
        skipped += first->width;
      }
      if (target->actual >= second->actual + second->width) {
        skipped += second->width;
      }
      if (target->actual < (uint64_t)header_actual + skipped) {
        continue;
      }
      const uint64_t target_slot = target->actual
                                   - (uint64_t)header_actual - skipped;

      if (target_slot == 0 || target_slot >= target_block_limit
          || target->width > target_block_limit - target_slot) {
        continue;
      }
      bool target_matches = true;

      for (uint64_t index = 0; index < target->width; index++) {
        const int64_t apparent = pair_mapping[target_slot + index];
        const int64_t mapped_actual = apparent >= 0
            ? filemirror_actual_blocknumber(
                  scalpel_state.filemirror, apparent)
            : -1;

        if (mapped_actual != (int64_t)(target->actual + index)) {
          target_matches = false;
          break;
        }
      }
      if (!target_matches) {
        continue;
      }
      uint64_t failure_distance = UINT64_MAX;

      if (!pair_result.structurally_valid
          || pair_result.failure_offset < pair_result.inferred_size) {
        if (failure_slot < target_slot) {
          failure_distance = target_slot - failure_slot;
        }
        else if (failure_slot >= target_slot + target->width) {
          failure_distance = failure_slot
                             - (target_slot + target->width - 1);
        }
        else {
          failure_distance = 0;
        }
      }
      const CfbfCombinedTarget combined_target = {
        .gap_index = gap_index,
        .all_zero = target->all_zero,
        .slot = target_slot,
        .width = target->width,
        .failure_distance = failure_distance,
        .concentration = target->confidence,
        .evidence = target->evidence
      };
      uint32_t position = 0;

      while (position < target_count
             && !cfbf_reassembly_combined_target_is_better(
                    &combined_target, &targets[position])) {
        position++;
      }
      if (position < CFBF_CONTENT_TARGET_LIMIT) {
        uint32_t move_end = target_count < CFBF_CONTENT_TARGET_LIMIT
                                ? target_count
                                : CFBF_CONTENT_TARGET_LIMIT - 1;

        while (move_end > position) {
          targets[move_end] = targets[move_end - 1];
          move_end--;
        }
        targets[position] = combined_target;
        if (target_count < CFBF_CONTENT_TARGET_LIMIT) {
          target_count++;
        }
      }
    }
    uint64_t first_target_position = resuming
                                         && pair_position
                                                == first_pair_position
                                     ? state->resume_run_width : 0;

    if (first_target_position >= target_count) {
      first_target_position = 0;
    }
    for (uint32_t target_position = (uint32_t)first_target_position;
         target_position < target_count
         && repair_trials < CFBF_CONTENT_TRIAL_LIMIT
         && recoverable_hypotheses < CFBF_CONTENT_HYPOTHESIS_LIMIT;
         target_position++) {
      const CfbfCombinedTarget *target = &targets[target_position];
      const CfbfModelRun *target_run = &gaps[target->gap_index];
      CfbfRankedSource sources[CFBF_RANKED_SOURCE_LIMIT];
      const uint32_t source_count = cfbf_reassembly_collect_ranked_sources(
          blockvector, pair_mapping, target->slot, target_run->width,
          pair_result.profile, sources, CFBF_RANKED_SOURCE_LIMIT);

      uint64_t first_source_position = resuming
                                           && pair_position
                                                  == first_pair_position
                                           && target_position
                                                  == first_target_position
                                       ? state->resume_choice : 0;

      if (first_source_position >= source_count) {
        first_source_position = 0;
      }

      for (uint32_t source_position = (uint32_t)first_source_position;
           source_position < source_count
           && source_position < CFBF_CONTENT_SOURCE_LIMIT
           && repair_trials < CFBF_CONTENT_TRIAL_LIMIT
           && recoverable_hypotheses < CFBF_CONTENT_HYPOTHESIS_LIMIT;
           source_position++) {
        const int64_t source_actual = (int64_t)sources[source_position].actual;

        state->resume_slot = pair_position;
        state->resume_run_width = target_position;
        state->resume_choice = source_position + 1;

        if (!cfbf_reassembly_build_mapped_run_indexed(
                blockvector, pair_mapping, &pair_index, trial_mapping,
                target->slot, target_run->width, source_actual)
            || !cfbf_reassembly_update_mapping_data(
                   blockvector, pair_mapping, trial_mapping,
                   trial_data, length)) {
          continue;
        }
        CfbfTrialResult trial;

        memset(&trial, 0, sizeof(trial));
        trials++;
        repair_trials++;
        if (cfbf_reassembly_evaluate_data(trial_data, length, &trial)
            && cfbf_reassembly_trial_recoverable(&trial)) {
          const uint32_t repairs = cumulative_shift + target_run->width
                                       > UINT32_MAX
                                   ? UINT32_MAX
                                   : (uint32_t)(cumulative_shift
                                                + target_run->width);
          const bool decisive =
              cfbf_reassembly_trial_authenticated(&trial)
              && trial.profile != CFBF_PROFILE_MPP;

          if (decisive) {
            cfbf_reassembly_commit_mapping(
                *candidate, state, trial_mapping, &trial, repairs);
            state->search_phase = CFBF_REASSEMBLY_FINALIZED;
            carve_put_state((*candidate)->carvehashkey, state);
            *improved = true;
            if (scalpel_state.mode_verbose) {
              lock_fprintf(
                  stdout,
                  "CFBF content combined repair selected:"
                  " header=%" PRId64 " gaps=%" PRIu64 "/%" PRIu64
                  ",%" PRIu64 "/%" PRIu64 " run=%" PRIu64
                  "/%" PRIu64 " source=%" PRId64 " profile=%s.\n",
                  header_actual, first->actual, first->width,
                  second->actual, second->width, target->slot,
                  target_run->width, source_actual,
                  cfbf_profile_filetype(trial.profile));
            }
            cfbf_reassembly_mapping_index_clear(&pair_index);
            free(trial_data);
            free(trial_mapping);
            free(pair_mapping);
            free(first_mapping);
            free(base_mapping);
            return false;
          }
          recoverable_hypotheses++;
          const int32_t comparison = retained_hypothesis.valid != 0
              ? cfbf_reassembly_compare_trial_results(
                    &trial, &retained_hypothesis.result)
              : 1;

          if (comparison > 0) {
            retained_hypothesis.valid = 1;
            retained_hypothesis.dirty = 1;
            retained_hypothesis.pair_position = pair_position;
            retained_hypothesis.target_gap_index = target->gap_index;
            retained_hypothesis.repairs = repairs;
            retained_hypothesis.target_slot = target->slot;
            retained_hypothesis.source_actual = (uint64_t)source_actual;
            retained_hypothesis.result = trial;
          }
        }
        if (!cfbf_reassembly_update_mapping_data(
                blockvector, trial_mapping, pair_mapping,
                trial_data, length)
            && !cfbf_reassembly_materialize_mapping(
                   blockvector, pair_mapping, base_data, trial_data,
                   length)) {
          handle_error(
              SCALPEL_GENERAL_ABORT,
              "CFBF content combined mapping could not be restored",
              __LINE__, __FILE__);
        }
        if ((trials & UINT64_C(0x1f)) == 0) {
          if (retained_hypothesis.dirty != 0
              && atomic_load_explicit(
                     &REASS_RETURN_TO_IDLE, memory_order_acquire)
              && cfbf_reassembly_write_content_hypothesis(
                     *candidate, state, base_mapping, first_mapping,
                     pair_mapping, trial_mapping, &pair_index, gaps,
                     gap_count, pairs, pair_count, &retained_hypothesis,
                     header_actual)) {
            written_hypotheses++;
            base_data = (const uint8_t *)
                blockvector_get_data_pointer(blockvector);
          }
          if (cfbf_reassembly_poll(
                  work, candidate, state, uuidp, uuidc)) {
            cfbf_reassembly_mapping_index_clear(&pair_index);
            free(trial_data);
            free(trial_mapping);
            free(pair_mapping);
            free(first_mapping);
            free(base_mapping);
            return true;
          }
        }
      }
      state->resume_choice = 0;
      state->resume_run_width = target_position + 1;
    }
    state->resume_run_width = 0;
    state->resume_slot = pair_position + 1;
  }

  if (retained_hypothesis.dirty != 0
      && cfbf_reassembly_write_content_hypothesis(
             *candidate, state, base_mapping, first_mapping,
             pair_mapping, trial_mapping, &pair_index, gaps, gap_count,
             pairs, pair_count, &retained_hypothesis, header_actual)) {
    written_hypotheses++;
  }

  state->search_phase = CFBF_REASSEMBLY_CONTENT_COMPLETE;
  state->resume_slot = 0;
  state->resume_run_width = 0;
  state->resume_choice = 0;
  carve_put_state((*candidate)->carvehashkey, state);

  if (scalpel_state.mode_verbose) {
    lock_fprintf(
        stdout,
        "CFBF content combined search complete: header=%" PRId64
        " signals=%" PRIu32 " pairs=%" PRIu32
        " pair hypotheses=%" PRIu32 " trials=%" PRIu32
        " recoverable=%" PRIu64
        " written=%" PRIu32 ".\n",
        header_actual, gap_count, pair_count, pair_hypothesis_written,
        repair_trials, recoverable_hypotheses, written_hypotheses);
  }

  cfbf_reassembly_mapping_index_clear(&pair_index);
  free(trial_data);
  free(trial_mapping);
  free(pair_mapping);
  free(first_mapping);
  free(base_mapping);
  return false;
}

// Resolve a gap and a displaced run as one atomic hypothesis. Every trial is
// materialized privately. The bounded pass prioritizes the retained gap and
// strongest source evidence; exhaustive traversal remains available when those
// rankings do not identify a recoverable mapping.
//
static inline bool cfbf_reassembly_try_atomic_pair(
    ThreadWork *work, CarveInfo **candidate, CfbfCarveState *state,
    const CfbfTrialResult *current, bool exhaustive, uuid_string_t uuidp,
    uuid_string_t uuidc, bool *improved, bool *validated) {

  if (!work || !candidate || !*candidate || !(*candidate)->b || !state
      || !current || !improved || !validated) {
    return false;
  }
  *improved = false;
  *validated = false;

  BlockVector *blockvector = (*candidate)->b;
  const uint64_t total_blocks = blockvector_get_num_blocks(blockvector);
  const uint64_t image_blocks = CEILDIV(
      filemirror_filesize(scalpel_state.filemirror), scalpel_state.blocksize);
  const int64_t header_actual = blockvector_get_actual_blocknumber(
      blockvector, 0);
  const uint64_t length = blockvector_get_data_length(blockvector);
  const CfbfProfile supported_profile =
      cfbf_reassembly_supported_profile(state);
  const CfbfProfile ranking_profile =
      supported_profile != CFBF_PROFILE_UNKNOWN
          ? supported_profile
          : cfbf_reassembly_model_profile(blockvector, current->profile);

  if (total_blocks < 2 || header_actual < 0
      || (uint64_t)header_actual >= image_blocks
      || total_blocks > image_blocks - (uint64_t)header_actual
      || length == 0) {
    return false;
  }
  const uint64_t maximum_shift = image_blocks
                                 - (uint64_t)header_actual - total_blocks;
  if (maximum_shift == 0) {
    return false;
  }
  CfbfModelRun preferred_gaps[CFBF_ATOMIC_PREFERRED_GAP_LIMIT];
  uint32_t preferred_gap_count = 0;

  if (!exhaustive || ranking_profile == CFBF_PROFILE_MPP) {
    uint64_t retained_slot = 0;
    uint64_t retained_shift = 0;
    uint32_t seed_gap_count = 0;

    if (ranking_profile == CFBF_PROFILE_MPP) {
      const uint32_t hypothesis_count =
          state->suffix_hypothesis_count <= CFBF_SUFFIX_HYPOTHESIS_LIMIT
              ? state->suffix_hypothesis_count
              : CFBF_SUFFIX_HYPOTHESIS_LIMIT;

      for (uint32_t index = 0;
           index < hypothesis_count
           && seed_gap_count < CFBF_ATOMIC_PREFERRED_GAP_LIMIT; index++) {
        const CfbfSuffixHypothesis *hypothesis =
            &state->suffix_hypotheses[index];

        if (hypothesis->valid == 0 || hypothesis->slot == 0
            || hypothesis->slot >= total_blocks || hypothesis->shift == 0
            || hypothesis->shift > maximum_shift) {
          continue;
        }
        preferred_gaps[seed_gap_count++] = (CfbfModelRun) {
          .actual = hypothesis->slot,
          .width = hypothesis->shift,
          .evidence = hypothesis->boundary_evidence,
          .confidence = UINT64_MAX - hypothesis->concentration
        };
      }
    }

    if (state->suffix_candidate_valid != 0
        && state->suffix_candidate_slot > 0
        && state->suffix_candidate_slot < total_blocks
        && state->suffix_candidate_shift > 0
        && state->suffix_candidate_shift <= maximum_shift) {
      retained_slot = state->suffix_candidate_slot;
      retained_shift = state->suffix_candidate_shift;
      bool duplicate = false;

      for (uint32_t index = 0; index < seed_gap_count; index++) {
        if (preferred_gaps[index].actual == retained_slot
            && preferred_gaps[index].width == retained_shift) {
          duplicate = true;
          break;
        }
      }
      if (!duplicate
          && seed_gap_count < CFBF_ATOMIC_PREFERRED_GAP_LIMIT) {
        preferred_gaps[seed_gap_count++] = (CfbfModelRun) {
          .actual = retained_slot,
          .width = retained_shift,
          .evidence = state->suffix_candidate_boundary_evidence,
          .confidence = UINT64_MAX
                        - state->suffix_candidate_concentration
        };
      }
    }
    uint32_t alternative_gap_count = 0;
    uint64_t shift_limit = maximum_shift;

    if (shift_limit > CFBF_NEARBY_SUFFIX_SHIFT_LIMIT) {
      shift_limit = CFBF_NEARBY_SUFFIX_SHIFT_LIMIT;
    }
    for (uint64_t slot = 1; slot < total_blocks; slot++) {
      for (uint64_t shift = 1; shift <= shift_limit; shift++) {
        bool duplicate = false;

        for (uint32_t index = 0; index < seed_gap_count; index++) {
          if (preferred_gaps[index].actual == slot
              && preferred_gaps[index].width == shift) {
            duplicate = true;
            break;
          }
        }
        if (duplicate) {
          continue;
        }
        const int64_t skipped_actual = header_actual + (int64_t)slot;
        const uint64_t concentration = cfbf_reassembly_run_concentration(
            skipped_actual, shift);

        if (concentration > CFBF_UNIFORM_CONCENTRATION_LIMIT) {
          continue;
        }
        const int64_t boundary_evidence =
            cfbf_reassembly_suffix_boundary_evidence(
                skipped_actual, shift, current->profile);
        const CfbfModelRun gap = {
          .actual = slot,
          .width = shift,
          .evidence = boundary_evidence,
          .confidence = UINT64_MAX - concentration
        };

        cfbf_reassembly_retain_model_run(
            &preferred_gaps[seed_gap_count],
            &alternative_gap_count,
            CFBF_ATOMIC_PREFERRED_GAP_LIMIT - seed_gap_count,
            &gap);
      }
    }
    preferred_gap_count = seed_gap_count + alternative_gap_count;
  }

  int64_t *base_mapping = (int64_t *)malloc(
      (size_t)total_blocks * sizeof(*base_mapping));
  int64_t *suffix_mapping = (int64_t *)malloc(
      (size_t)total_blocks * sizeof(*suffix_mapping));
  int64_t *trial_mapping = (int64_t *)malloc(
      (size_t)total_blocks * sizeof(*trial_mapping));
  int64_t *solution_mapping = (int64_t *)malloc(
      (size_t)total_blocks * sizeof(*solution_mapping));
  uint8_t *trial_data = (uint8_t *)malloc((size_t)length);

  check_memory_allocation(base_mapping, __LINE__, __FILE__,
                          "CFBF atomic base mapping");
  check_memory_allocation(suffix_mapping, __LINE__, __FILE__,
                          "CFBF atomic suffix mapping");
  check_memory_allocation(trial_mapping, __LINE__, __FILE__,
                          "CFBF atomic trial mapping");
  check_memory_allocation(solution_mapping, __LINE__, __FILE__,
                          "CFBF atomic solution mapping");
  check_memory_allocation(trial_data, __LINE__, __FILE__,
                          "CFBF atomic trial data");
  for (uint64_t slot = 0; slot < total_blocks; slot++) {
    base_mapping[slot] = blockvector_get_apparent_blocknumber(
        blockvector, slot);
    solution_mapping[slot] = base_mapping[slot];
  }
  const uint8_t *base_data = (const uint8_t *)
      blockvector_get_data_pointer(blockvector);
  CfbfMappingIndex suffix_index = { 0 };

  if (!base_data
      || !cfbf_reassembly_mapping_index_initialize(
             &suffix_index, total_blocks)) {
    cfbf_reassembly_mapping_index_clear(&suffix_index);
    free(trial_data);
    free(solution_mapping);
    free(trial_mapping);
    free(suffix_mapping);
    free(base_mapping);
    return false;
  }

  CfbfTrialResult solution_result;
  memset(&solution_result, 0, sizeof(solution_result));
  bool found = false;
  bool solution_has_confidence = false;
  bool solution_all_positive = false;
  bool solution_authenticated = false;
  bool solution_suffix_exact = false;
  bool solution_target_exact = false;
  uint32_t solution_reserved = UINT32_MAX;
  int64_t solution_confidence_gain = INT64_MIN;
  uint64_t solution_suffix_concentration = UINT64_MAX;
  uint64_t solution_target_concentration = UINT64_MAX;
  uint64_t solution_source_concentration = 0;
  uint32_t solution_source_isolation = 0;
  uint64_t solution_context_distance = UINT64_MAX;
  uint64_t solution_width = 0;
  uint64_t trials = 0;
  const uint32_t requested_suffix_pass = exhaustive ? 7 : 6;
  const bool resuming = state->search_phase == 4
                        && state->suffix_pass == requested_suffix_pass
                        && state->atomic_resume_valid != 0;
  const uint32_t resume_search_pass = state->atomic_search_pass;
  const uint64_t resume_suffix_slot = state->atomic_suffix_slot;
  const uint64_t resume_shift = state->atomic_shift;
  const uint64_t resume_width_order = state->atomic_width_order;
  const uint64_t resume_target_slot = state->atomic_target_slot;
  const uint64_t resume_source_actual = state->atomic_source_actual;

  if (!resuming) {
    cfbf_reassembly_reset_atomic_search(state);
    state->atomic_resume_valid = 1;
    state->atomic_search_pass = 0;
    state->atomic_suffix_slot = 1;
    state->atomic_shift = 1;
  }
  state->search_phase = 4;
  state->suffix_pass = requested_suffix_pass;

  const bool mpp_guided_search = exhaustive
                                  && ranking_profile == CFBF_PROFILE_MPP
                                  && preferred_gap_count > 0;
  const uint32_t search_passes = !exhaustive && preferred_gap_count > 0
      ? preferred_gap_count
      : (mpp_guided_search
             ? preferred_gap_count + 1
             : (exhaustive && state->pair_suffix_possible != 0 ? 3 : 1));

  bool strong_mpp_solution = found
      && solution_result.profile == CFBF_PROFILE_MPP
      && solution_result.semantic_strength >= CFBF_SEMANTIC_STRONG
      && solution_result.profile_evidence
      && solution_reserved == 0
      && ((solution_suffix_exact
           && solution_source_isolation
                  >= CFBF_DETACHED_SOURCE_ISOLATED_MIN
           && (solution_target_exact
               || solution_result.coherence_payloads != 0))
          || (solution_target_exact
              && solution_source_isolation != 0
              && solution_result.coherence_payloads != 0));

  if (resuming && state->atomic_candidate.valid != 0
      && cfbf_reassembly_build_suffix_mapping(
             blockvector, base_mapping, suffix_mapping,
             state->atomic_candidate.suffix_slot,
             state->atomic_candidate.suffix_shift, header_actual)
      && cfbf_reassembly_mapping_index_build(
             &suffix_index, suffix_mapping, total_blocks)
      && cfbf_reassembly_build_mapped_run_indexed(
             blockvector, suffix_mapping, &suffix_index, solution_mapping,
             state->atomic_candidate.target_slot,
             state->atomic_candidate.width,
             (int64_t)state->atomic_candidate.source_actual)
      && cfbf_reassembly_materialize_mapping(
             blockvector, solution_mapping, base_data, trial_data, length)
      && cfbf_reassembly_evaluate_data(
             trial_data, length, &solution_result)
      && cfbf_reassembly_trial_recoverable(&solution_result)) {
    const int64_t skipped_actual = header_actual
        + (int64_t)state->atomic_candidate.suffix_slot;

    found = true;
    solution_authenticated =
        cfbf_reassembly_trial_authenticated(&solution_result);
    solution_suffix_concentration =
        cfbf_reassembly_run_concentration(
            skipped_actual, state->atomic_candidate.suffix_shift);
    solution_suffix_exact = solution_suffix_concentration
                            <= CFBF_UNIFORM_CONCENTRATION_LIMIT;
    if (solution_suffix_exact && skipped_actual > 0
        && cfbf_reassembly_run_concentration(skipped_actual - 1, 1)
               <= CFBF_UNIFORM_CONCENTRATION_LIMIT) {
      solution_suffix_exact = false;
    }
    if (solution_suffix_exact
        && (uint64_t)skipped_actual + state->atomic_candidate.suffix_shift
               < image_blocks
        && cfbf_reassembly_run_concentration(
               skipped_actual
                   + (int64_t)state->atomic_candidate.suffix_shift,
               1)
               <= CFBF_UNIFORM_CONCENTRATION_LIMIT) {
      solution_suffix_exact = false;
    }
    solution_target_concentration =
        cfbf_reassembly_mapping_concentration(
            suffix_mapping, state->atomic_candidate.target_slot,
            state->atomic_candidate.width);
    solution_target_exact = solution_target_concentration
                            <= CFBF_UNIFORM_CONCENTRATION_LIMIT;
    if (solution_target_exact && state->atomic_candidate.target_slot > 1
        && cfbf_reassembly_mapping_concentration(
               suffix_mapping, state->atomic_candidate.target_slot - 1, 1)
               <= CFBF_UNIFORM_CONCENTRATION_LIMIT) {
      solution_target_exact = false;
    }
    if (solution_target_exact
        && state->atomic_candidate.target_slot
               + state->atomic_candidate.width < total_blocks
        && cfbf_reassembly_mapping_concentration(
               suffix_mapping,
               state->atomic_candidate.target_slot
                   + state->atomic_candidate.width,
               1)
               <= CFBF_UNIFORM_CONCENTRATION_LIMIT) {
      solution_target_exact = false;
    }
    solution_source_concentration =
        cfbf_reassembly_run_concentration(
            (int64_t)state->atomic_candidate.source_actual,
            state->atomic_candidate.width);
    if (solution_source_concentration == UINT64_MAX) {
      solution_source_concentration = 0;
    }
    solution_source_isolation = cfbf_reassembly_source_run_isolation(
        (int64_t)state->atomic_candidate.source_actual,
        state->atomic_candidate.width, NULL);
    solution_context_distance =
        cfbf_reassembly_context_distance(
            blockvector, suffix_mapping,
            state->atomic_candidate.target_slot,
            state->atomic_candidate.width,
            (int64_t)state->atomic_candidate.source_actual);
    solution_width = state->atomic_candidate.width;
    cfbf_reassembly_run_metrics(
        blockvector, suffix_mapping, state->atomic_candidate.target_slot,
        state->atomic_candidate.width,
        (int64_t)state->atomic_candidate.source_actual,
        solution_result.profile, &solution_has_confidence,
        &solution_all_positive, &solution_confidence_gain,
        &solution_reserved, NULL);
  }
  else if (resuming) {
    memset(&state->atomic_candidate, 0,
           sizeof(state->atomic_candidate));
  }

  if (scalpel_state.mode_verbose) {
    lock_fprintf(
        stdout,
        "CFBF atomic search: header=%" PRId64
        " exhaustive=%s pair-evidence=%s passes=%" PRIu32
        " preferred-gaps=%" PRIu32 " suffix=%u/%" PRIu64
        "/%" PRIu64 ".\n",
        header_actual, exhaustive ? "true" : "false",
        state->pair_suffix_possible != 0 ? "true" : "false",
        search_passes, preferred_gap_count,
        state->suffix_candidate_valid, state->suffix_candidate_slot,
        state->suffix_candidate_shift);
  }

  const uint32_t first_search_pass = resuming && mpp_guided_search
                                     && strong_mpp_solution
      ? search_passes
      : resuming
      && resume_search_pass < search_passes
          ? resume_search_pass : 0;

  for (uint32_t search_pass = first_search_pass;
       search_pass < search_passes; search_pass++) {
    const bool broad_mpp_fallback = mpp_guided_search
                                    && search_pass == preferred_gap_count;

    // A preferred Project repair backed by independent semantic and physical
    // evidence does not need the unrestricted suffix fallback.
    strong_mpp_solution = found
        && solution_result.profile == CFBF_PROFILE_MPP
        && solution_result.semantic_strength >= CFBF_SEMANTIC_STRONG
        && solution_result.profile_evidence
        && solution_reserved == 0
        && ((solution_suffix_exact
             && solution_source_isolation
                    >= CFBF_DETACHED_SOURCE_ISOLATED_MIN
             && (solution_target_exact
                 || solution_result.coherence_payloads != 0))
            || (solution_target_exact
                && solution_source_isolation != 0
                && solution_result.coherence_payloads != 0));

    if (broad_mpp_fallback && strong_mpp_solution) {
      break;
    }
    const bool preferred_gap_pass = (!exhaustive
                                     && preferred_gap_count > 0)
                                    || (mpp_guided_search
                                        && search_pass
                                               < preferred_gap_count);
    const uint32_t preferred_gap_index = search_pass;
    const CfbfModelRun *preferred_gap = preferred_gap_pass
        ? &preferred_gaps[preferred_gap_index] : NULL;
    const bool isolated_only = !exhaustive
                               || (mpp_guided_search
                                   && !preferred_gap_pass)
                               || (!mpp_guided_search
                                   && search_pass == 0);
    const bool isolated_target_only = isolated_only
                                      || (mpp_guided_search
                                          && preferred_gap_pass);
    const bool bounded_shift_pass = mpp_guided_search
                                        ? !preferred_gap_pass
                                        : search_pass < 2;
    const uint64_t shift_limit = bounded_shift_pass
        && maximum_shift > CFBF_NEARBY_SUFFIX_SHIFT_LIMIT
            ? CFBF_NEARBY_SUFFIX_SHIFT_LIMIT : maximum_shift;
    const uint64_t first_suffix_slot = preferred_gap
        ? preferred_gap->actual
        : (resuming && search_pass == resume_search_pass
               && resume_suffix_slot > 0
               && resume_suffix_slot < total_blocks
           ? resume_suffix_slot : 1);
    const uint64_t suffix_slot_limit = preferred_gap
        ? preferred_gap->actual + 1 : total_blocks;

    for (uint64_t suffix_slot = first_suffix_slot;
         suffix_slot < suffix_slot_limit; suffix_slot++) {
      const uint64_t first_shift = preferred_gap
          ? preferred_gap->width
          : (resuming && search_pass == resume_search_pass
                 && suffix_slot == resume_suffix_slot
                 && resume_shift > 0
                 && resume_shift <= shift_limit
             ? resume_shift : 1);
      const uint64_t final_shift = preferred_gap
          ? preferred_gap->width : shift_limit;

      for (uint64_t shift = first_shift;
           shift <= final_shift; shift++) {
        state->atomic_search_pass = search_pass;
        state->atomic_suffix_slot = suffix_slot;
        state->atomic_shift = shift;
        if (!cfbf_reassembly_build_suffix_mapping(
                blockvector, base_mapping, suffix_mapping, suffix_slot,
                shift, header_actual)
            || !cfbf_reassembly_mapping_index_build(
                   &suffix_index, suffix_mapping, total_blocks)
            || !cfbf_reassembly_materialize_mapping(
                   blockvector, suffix_mapping, base_data, trial_data,
                   length)) {
          continue;
        }
        CfbfTrialResult suffix_result;

        memset(&suffix_result, 0, sizeof(suffix_result));
        if (!cfbf_reassembly_evaluate_data(
                trial_data, length, &suffix_result)) {
          continue;
        }
        if (ranking_profile == CFBF_PROFILE_MPP
            && preferred_gap_pass
            && suffix_result.score > current->score
            && !cfbf_reassembly_trial_authenticated(&suffix_result)
            && cfbf_reassembly_trial_recoverable(&suffix_result)
            && cfbf_reassembly_write_mapping_hypothesis(
                   *candidate, state, suffix_mapping, &suffix_result,
                   1, true)
            && scalpel_state.mode_verbose) {
          lock_fprintf(
              stdout,
              "CFBF Project suffix hypothesis written: header=%" PRId64
              " slot=%" PRIu64 " shift=%" PRIu64 ".\n",
              header_actual, suffix_slot, shift);
        }
        base_data = (const uint8_t *)
            blockvector_get_data_pointer(blockvector);
        if (!base_data) {
          cfbf_reassembly_mapping_index_clear(&suffix_index);
          free(trial_data);
          free(solution_mapping);
          free(trial_mapping);
          free(suffix_mapping);
          free(base_mapping);
          return false;
        }
        if (suffix_result.score > current->score
            && cfbf_reassembly_trial_authenticated(&suffix_result)) {
          cfbf_reassembly_commit_mapping(*candidate, state, suffix_mapping,
                                         &suffix_result, 1);
          *improved = true;
          cfbf_reassembly_mapping_index_clear(&suffix_index);
          free(trial_data);
          free(solution_mapping);
          free(trial_mapping);
          free(suffix_mapping);
          free(base_mapping);
          return false;
        }
        if (exhaustive && !mpp_guided_search && search_pass == 1
            && (suffix_result.score <= current->score
                || !suffix_result.structurally_valid
                || suffix_result.profile == CFBF_PROFILE_UNKNOWN)) {
          continue;
        }

        const int64_t skipped_actual = header_actual
                                       + (int64_t)suffix_slot;
        const uint64_t suffix_concentration =
            cfbf_reassembly_run_concentration(skipped_actual, shift);
        bool suffix_exact = suffix_concentration
                            <= CFBF_UNIFORM_CONCENTRATION_LIMIT;

        if (suffix_exact && skipped_actual > 0
            && cfbf_reassembly_run_concentration(
                   skipped_actual - 1, 1)
                   <= CFBF_UNIFORM_CONCENTRATION_LIMIT) {
          suffix_exact = false;
        }
        if (suffix_exact
            && (uint64_t)skipped_actual + shift < image_blocks
            && cfbf_reassembly_run_concentration(
                   skipped_actual + (int64_t)shift, 1)
                   <= CFBF_UNIFORM_CONCENTRATION_LIMIT) {
          suffix_exact = false;
        }
        if (isolated_only
            && suffix_concentration
                   > CFBF_UNIFORM_CONCENTRATION_LIMIT) {
          continue;
        }

        uint64_t width_limit = total_blocks - 1;

        if ((!exhaustive || search_pass < 2
             || (mpp_guided_search && preferred_gap_pass))
            && width_limit > CFBF_NEARBY_RUN_WIDTH_LIMIT) {
          width_limit = CFBF_NEARBY_RUN_WIDTH_LIMIT;
        }
        const uint64_t first_width_order = resuming
            && search_pass == resume_search_pass
            && suffix_slot == resume_suffix_slot
            && shift == resume_shift
            && resume_width_order < width_limit
            ? resume_width_order : 0;

        for (uint64_t width_order = first_width_order;
             width_order < width_limit; width_order++) {
          uint64_t width = width_order + 1;

          if (width_limit > 1) {
            if (width_order == 0) {
              width = 2;
            }
            else if (width_order == 1) {
              width = 1;
            }
          }
          if (exhaustive && !mpp_guided_search && search_pass == 2
              && shift <= CFBF_NEARBY_SUFFIX_SHIFT_LIMIT
              && width <= CFBF_NEARBY_RUN_WIDTH_LIMIT) {
            continue;
          }
          if (width > image_blocks) {
            continue;
          }
          CfbfRankedSource ranked_sources[
              CFBF_RANKED_SOURCE_LIMIT * 4];
          const CfbfProfile source_profile =
              suffix_result.profile != CFBF_PROFILE_UNKNOWN
                  ? suffix_result.profile : ranking_profile;
          uint32_t ranked_source_count = 0;

          const uint64_t first_target_slot = resuming
              && search_pass == resume_search_pass
              && suffix_slot == resume_suffix_slot
              && shift == resume_shift
              && width_order == resume_width_order
              && resume_target_slot > 0
              && resume_target_slot + width <= total_blocks
              ? resume_target_slot : 1;

          state->atomic_width_order = width_order;

          for (uint64_t target_slot = first_target_slot;
               target_slot + width <= total_blocks; target_slot++) {
            if (!cfbf_reassembly_target_within_result(
                    &suffix_result, target_slot, width, total_blocks)) {
              continue;
            }
            const uint64_t target_concentration =
                cfbf_reassembly_mapping_concentration(
                    suffix_mapping, target_slot, width);
            bool target_exact = target_concentration
                                <= CFBF_UNIFORM_CONCENTRATION_LIMIT;

            if (target_exact && target_slot > 1
                && cfbf_reassembly_mapping_concentration(
                       suffix_mapping, target_slot - 1, 1)
                       <= CFBF_UNIFORM_CONCENTRATION_LIMIT) {
              target_exact = false;
            }
            if (target_exact && target_slot + width < total_blocks
                && cfbf_reassembly_mapping_concentration(
                       suffix_mapping, target_slot + width, 1)
                       <= CFBF_UNIFORM_CONCENTRATION_LIMIT) {
              target_exact = false;
            }
            if (isolated_target_only
                && target_concentration
                       > CFBF_UNIFORM_CONCENTRATION_LIMIT) {
              continue;
            }
            const bool scan_all_isolated_sources = !exhaustive
                && ranking_profile == CFBF_PROFILE_MPP
                && suffix_exact && target_exact;
            uint64_t source_count = !exhaustive
                                       && !scan_all_isolated_sources
                ? 1
                : (isolated_only
                       ? cfbf_reassembly_source_run_count(width)
                       : image_blocks - width + 1);

            if (source_count == 0) {
              continue;
            }

            if (!exhaustive && !scan_all_isolated_sources) {
              ranked_source_count = cfbf_reassembly_collect_ranked_sources(
                  blockvector, suffix_mapping, target_slot, width,
                  source_profile, ranked_sources,
                  CFBF_RANKED_SOURCE_LIMIT * 4);
              source_count = ranked_source_count;
              if (source_count == 0) {
                continue;
              }
            }

            CfbfSourceRunIterator source_iterator;
            const bool resume_source = resuming
                && search_pass == resume_search_pass
                && suffix_slot == resume_suffix_slot
                && shift == resume_shift
                && width_order == resume_width_order
                && target_slot == resume_target_slot;
            const uint64_t first_source_actual = resume_source
                ? resume_source_actual : 0;
            uint64_t first_source_position = 0;

            if (!exhaustive && !scan_all_isolated_sources && resume_source
                && resume_source_actual > 0) {
              for (uint64_t position = 0;
                   position < source_count; position++) {
                if (ranked_sources[position].actual + 1
                    == resume_source_actual) {
                  first_source_position = position + 1;
                  break;
                }
              }
            }

            cfbf_reassembly_source_run_iterator_initialize(
                &source_iterator, width, first_source_actual);
            state->atomic_target_slot = target_slot;

            for (uint64_t source_index = first_source_position;
                 source_index < source_count; source_index++) {
              uint64_t actual_index = !exhaustive
                                      && !scan_all_isolated_sources
                  ? ranked_sources[source_index].actual
                  : (isolated_only
                         ? first_source_actual
                         : first_source_actual + source_index);

              if ((exhaustive || scan_all_isolated_sources) && isolated_only
                  && !cfbf_reassembly_next_source_run(
                         &source_iterator, &actual_index)) {
                break;
              }
              else if ((exhaustive || scan_all_isolated_sources)
                       && !isolated_only
                       && actual_index > image_blocks - width) {
                break;
              }
              const bool available =
                  cfbf_reassembly_build_mapped_run_indexed(
                      blockvector, suffix_mapping, &suffix_index,
                      trial_mapping, target_slot, width,
                      (int64_t)actual_index);

              trials++;
              state->atomic_source_actual = actual_index + 1;
              const bool materialized = available
                  && cfbf_reassembly_update_mapping_data(
                         blockvector, suffix_mapping, trial_mapping,
                         trial_data, length);

              if (materialized) {
                CfbfTrialResult trial;

                memset(&trial, 0, sizeof(trial));
                const bool evaluated = cfbf_reassembly_evaluate_data(
                    trial_data, length, &trial);
                const bool trial_recoverable = evaluated
                    && cfbf_reassembly_trial_recoverable(&trial);

                if (trial_recoverable && trial.score > current->score) {
                  bool has_confidence = false;
                  bool all_positive = false;
                  const bool authenticated =
                      cfbf_reassembly_trial_authenticated(&trial);
                  int64_t confidence_gain = 0;
                  uint32_t reserved = 0;
                  uint64_t source_concentration =
                      cfbf_reassembly_run_concentration(
                          (int64_t)actual_index, width);
                  const uint32_t source_isolation =
                      cfbf_reassembly_source_run_isolation(
                          (int64_t)actual_index, width, NULL);

                  if (source_concentration == UINT64_MAX) {
                    source_concentration = 0;
                  }
                  cfbf_reassembly_run_metrics(
                      blockvector, suffix_mapping, target_slot, width,
                      (int64_t)actual_index, trial.profile,
                      &has_confidence, &all_positive, &confidence_gain,
                      &reserved, NULL);
                  const uint64_t context_distance =
                      cfbf_reassembly_context_distance(
                          blockvector, suffix_mapping, target_slot, width,
                          (int64_t)actual_index);
                  uint64_t source_evidence = 0;

                  if (target_concentration != UINT64_MAX
                      && source_concentration > target_concentration) {
                    const uint64_t difference = source_concentration
                                                - target_concentration;

                    source_evidence = difference > UINT64_MAX / width
                        ? UINT64_MAX : difference * width;
                  }
                  const CfbfRepairCandidate width_candidate = {
                    .valid = 1,
                    .authenticated = authenticated ? 1 : 0,
                    .complete = cfbf_reassembly_trial_complete(&trial)
                                    ? 1 : 0,
                    .profile = (uint32_t)trial.profile,
                    .profile_evidence = trial.profile_evidence ? 1 : 0,
                    .semantic_strength =
                        (uint32_t)trial.semantic_strength,
                    .coherence_payloads = trial.coherence_payloads,
                    .has_confidence = has_confidence ? 1 : 0,
                    .all_positive = all_positive ? 1 : 0,
                    .target_strong = target_concentration
                        <= CFBF_STRONG_FILLER_CONCENTRATION_LIMIT,
                    .target_exact = target_exact ? 1 : 0,
                    .source_isolation = source_isolation,
                    .reserved = reserved,
                    .slot = target_slot,
                    .width = width,
                    .actual = actual_index,
                    .score = trial.score,
                    .coherence_cost = trial.coherence_cost,
                    .coherence_extent = trial.coherence_extent,
                    .context_distance = context_distance,
                    .target_concentration = target_concentration,
                    .source_evidence = source_evidence,
                    .confidence_gain = confidence_gain
                  };

                  if (width <= CFBF_NEARBY_RUN_WIDTH_LIMIT) {
                    const uint64_t width_index = width - 1;

                    if (cfbf_reassembly_repair_is_better(
                            &width_candidate,
                            &state->atomic_width_ranks[width_index])) {
                      state->atomic_width_ranks[width_index] =
                          width_candidate;
                      state->atomic_width_candidates[width_index] =
                          (CfbfAtomicCandidate) {
                            .valid = 1,
                            .suffix_slot = suffix_slot,
                            .suffix_shift = shift,
                            .target_slot = target_slot,
                            .width = width,
                            .source_actual = actual_index
                          };
                    }
                  }

                  if (authenticated && exhaustive) {
                    cfbf_reassembly_commit_mapping(
                        *candidate, state, trial_mapping, &trial, 2);
                    state->search_phase = CFBF_REASSEMBLY_FINALIZED;
                    carve_put_state((*candidate)->carvehashkey, state);
                    *improved = true;
                    cfbf_reassembly_mapping_index_clear(&suffix_index);
                    free(trial_data);
                    free(solution_mapping);
                    free(trial_mapping);
                    free(suffix_mapping);
                    free(base_mapping);
                    return false;
                  }

                  const bool mpp_tie = found
                      && trial.profile == CFBF_PROFILE_MPP
                      && solution_result.profile == CFBF_PROFILE_MPP;
                  const int32_t semantic_comparison = found
                      ? cfbf_reassembly_compare_trial_results(
                            &trial, &solution_result)
                      : 1;
                  bool better = !found;

                  if (mpp_tie
                      && trial.semantic_strength
                             != solution_result.semantic_strength) {
                    better = trial.semantic_strength
                             > solution_result.semantic_strength;
                  }
                  else if (mpp_tie
                           && trial.profile_evidence
                                  != solution_result.profile_evidence) {
                    better = trial.profile_evidence;
                  }
                  else if (mpp_tie
                           && suffix_exact != solution_suffix_exact) {
                    better = suffix_exact;
                  }
                  else if (mpp_tie
                           && trial.coherence_payloads == 0
                           && solution_result.coherence_payloads == 0
                           && target_exact != solution_target_exact) {
                    better = target_exact;
                  }
                  else if (mpp_tie
                           && (source_isolation != 0)
                                  != (solution_source_isolation != 0)) {
                    better = source_isolation != 0;
                  }
                  else if (semantic_comparison != 0) {
                    better = semantic_comparison > 0;
                  }
                  else {
                    // Type confidence cannot distinguish blocks belonging to
                    // different Project files. Prefer physical ownership
                    // evidence before classifier and target-shape heuristics.
                    if (mpp_tie && reserved != solution_reserved) {
                      better = reserved < solution_reserved;
                    }
                    else if (mpp_tie
                             && trial.coherence_cost
                                    != solution_result.coherence_cost) {
                      better = trial.coherence_cost
                               < solution_result.coherence_cost;
                    }
                    else if (mpp_tie
                             && context_distance
                                    != solution_context_distance) {
                      better = context_distance
                               < solution_context_distance;
                    }
                    else if (target_exact != solution_target_exact) {
                      better = target_exact;
                    }
                    else if (has_confidence != solution_has_confidence) {
                      better = has_confidence;
                    }
                    else if (has_confidence
                             && all_positive != solution_all_positive) {
                      better = all_positive;
                    }
                    else if (has_confidence
                             && confidence_gain
                                    != solution_confidence_gain) {
                      better = confidence_gain
                               > solution_confidence_gain;
                    }
                    else if (!mpp_tie && reserved != solution_reserved) {
                      better = reserved < solution_reserved;
                    }
                    else if (!mpp_tie && source_isolation
                             != solution_source_isolation) {
                      better = source_isolation
                               > solution_source_isolation;
                    }
                    else if (!mpp_tie && context_distance
                             != solution_context_distance) {
                      better = context_distance
                               < solution_context_distance;
                    }
                    else if (suffix_concentration
                             != solution_suffix_concentration) {
                      better = suffix_concentration
                               < solution_suffix_concentration;
                    }
                    else if (target_concentration
                             != solution_target_concentration) {
                      better = target_concentration
                               < solution_target_concentration;
                    }
                    else if (source_concentration
                             != solution_source_concentration) {
                      better = source_concentration
                               > solution_source_concentration;
                    }
                    else if (width != solution_width) {
                      if (solution_width == 1 && width == 2) {
                        better = true;
                      }
                      else if (solution_width > 2 && width >= 2
                               && width < solution_width) {
                        better = true;
                      }
                    }
                  }

                  if (better) {
                    found = true;
                    solution_result = trial;
                    memcpy(solution_mapping, trial_mapping,
                           (size_t)total_blocks
                               * sizeof(*solution_mapping));
                    solution_has_confidence = has_confidence;
                    solution_all_positive = all_positive;
                    solution_authenticated = authenticated;
                    solution_suffix_exact = suffix_exact;
                    solution_target_exact = target_exact;
                    solution_reserved = reserved;
                    solution_confidence_gain = confidence_gain;
                    solution_suffix_concentration =
                        suffix_concentration;
                    solution_target_concentration =
                        target_concentration;
                    solution_source_concentration =
                        source_concentration;
                    solution_source_isolation = source_isolation;
                    solution_context_distance = context_distance;
                    solution_width = width;
                    state->atomic_candidate = (CfbfAtomicCandidate) {
                      .valid = 1,
                      .suffix_slot = suffix_slot,
                      .suffix_shift = shift,
                      .target_slot = target_slot,
                      .width = width,
                      .source_actual = actual_index
                    };
                  }
                }
              }
              if (materialized
                  && !cfbf_reassembly_update_mapping_data(
                         blockvector, trial_mapping, suffix_mapping,
                         trial_data, length)
                  && !cfbf_reassembly_materialize_mapping(
                         blockvector, suffix_mapping, base_data, trial_data,
                         length)) {
                handle_error(
                    SCALPEL_GENERAL_ABORT,
                    "CFBF trial mapping could not be restored",
                    __LINE__, __FILE__);
              }
              if ((trials & UINT64_C(0xff)) == 0
                  && cfbf_reassembly_poll(
                         work, candidate, state, uuidp, uuidc)) {
                cfbf_reassembly_mapping_index_clear(&suffix_index);
                free(trial_data);
                free(solution_mapping);
                free(trial_mapping);
                free(suffix_mapping);
                free(base_mapping);
                return true;
              }
            }
            state->atomic_source_actual = 0;
          }
          state->atomic_target_slot = 1;
        }
        state->atomic_width_order = 0;
      }
      state->atomic_shift = 1;
    }
    state->atomic_suffix_slot = 1;
  }

  for (uint64_t width_index = 0;
       width_index < CFBF_NEARBY_RUN_WIDTH_LIMIT; width_index++) {
    const CfbfAtomicCandidate *width_candidate =
        &state->atomic_width_candidates[width_index];

    if (width_candidate->valid == 0
        || !cfbf_reassembly_build_suffix_mapping(
               blockvector, base_mapping, suffix_mapping,
               width_candidate->suffix_slot,
               width_candidate->suffix_shift, header_actual)
        || !cfbf_reassembly_mapping_index_build(
               &suffix_index, suffix_mapping, total_blocks)
        || !cfbf_reassembly_build_mapped_run_indexed(
               blockvector, suffix_mapping, &suffix_index, trial_mapping,
               width_candidate->target_slot, width_candidate->width,
               (int64_t)width_candidate->source_actual)
        || !cfbf_reassembly_materialize_mapping(
               blockvector, trial_mapping, base_data, trial_data, length)) {
      continue;
    }
    CfbfTrialResult width_result;

    memset(&width_result, 0, sizeof(width_result));
    if (!cfbf_reassembly_evaluate_data(
            trial_data, length, &width_result)
        || !cfbf_reassembly_trial_recoverable(&width_result)) {
      continue;
    }
    const uint64_t repair_count = width_candidate->suffix_shift
                                  + width_candidate->width;
    const uint32_t repairs = repair_count > UINT32_MAX
        ? UINT32_MAX : (uint32_t)repair_count;

    if (cfbf_reassembly_write_mapping_hypothesis(
            *candidate, state, trial_mapping, &width_result,
            repairs, true)
        && scalpel_state.mode_verbose) {
      lock_fprintf(
          stdout,
          "CFBF bounded atomic hypothesis written: header=%" PRId64
          " gap=%" PRIu64 "/%" PRIu64
          " slot=%" PRIu64 " width=%" PRIu64
          " source=%" PRIu64 " profile=%s.\n",
          header_actual, width_candidate->suffix_slot,
          width_candidate->suffix_shift, width_candidate->target_slot,
          width_candidate->width, width_candidate->source_actual,
          cfbf_profile_filetype(width_result.profile));
    }
    base_data = (const uint8_t *)
        blockvector_get_data_pointer(blockvector);
    if (!base_data) {
      cfbf_reassembly_mapping_index_clear(&suffix_index);
      free(trial_data);
      free(solution_mapping);
      free(trial_mapping);
      free(suffix_mapping);
      free(base_mapping);
      return false;
    }
  }

  if (exhaustive && ranking_profile == CFBF_PROFILE_MPP) {
    state->suffix_hypothesis_count = 0;
    memset(state->suffix_hypotheses, 0,
           sizeof(state->suffix_hypotheses));
  }

  strong_mpp_solution = found
      && ranking_profile == CFBF_PROFILE_MPP
      && solution_result.profile == CFBF_PROFILE_MPP
      && solution_result.semantic_strength >= CFBF_SEMANTIC_STRONG
      && solution_result.profile_evidence
      && solution_reserved == 0
      && ((solution_suffix_exact
           && solution_source_isolation
                  >= CFBF_DETACHED_SOURCE_ISOLATED_MIN
           && (solution_target_exact
               || solution_result.coherence_payloads != 0))
          || (solution_target_exact
              && solution_source_isolation != 0
              && solution_result.coherence_payloads != 0));

  if (!exhaustive && ranking_profile == CFBF_PROFILE_MPP
      && scalpel_state.mode_verbose) {
    lock_fprintf(
        stdout,
        "CFBF bounded Project result: found=%s strong=%s profile=%s"
        " semantic=%u evidence=%s suffix=%s target=%s"
        " isolation=%" PRIu32 "/%" PRIu64 " reserved=%" PRIu32
        " coherence=%" PRIu32 " gap=%" PRIu64 "/%" PRIu64
        " slot=%" PRIu64 " source=%" PRIu64
        ".\n",
        found ? "true" : "false",
        strong_mpp_solution ? "true" : "false",
        cfbf_profile_filetype(solution_result.profile),
        (uint32_t)solution_result.semantic_strength,
        solution_result.profile_evidence ? "true" : "false",
        solution_suffix_exact ? "exact" : "open",
        solution_target_exact ? "exact" : "open",
        solution_source_isolation, solution_width, solution_reserved,
        solution_result.coherence_payloads,
        state->atomic_candidate.suffix_slot,
        state->atomic_candidate.suffix_shift,
        state->atomic_candidate.target_slot,
        state->atomic_candidate.source_actual);
  }

  if (!exhaustive && !solution_authenticated && !strong_mpp_solution) {
    if (found && ranking_profile != CFBF_PROFILE_MPP
        && cfbf_reassembly_trial_recoverable(&solution_result)) {
      (void)cfbf_reassembly_write_mapping_hypothesis(
          *candidate, state, solution_mapping, &solution_result, 2, true);
    }
    found = false;
    memset(&state->atomic_candidate, 0,
           sizeof(state->atomic_candidate));
  }

  if (found) {
    if (scalpel_state.mode_verbose) {
      lock_fprintf(
          stdout,
          "CFBF atomic repair selected: header=%" PRId64
          " width=%" PRIu64 " profile=%s semantic=%u evidence=%s.\n",
          header_actual, solution_width,
          cfbf_profile_filetype(solution_result.profile),
          (uint32_t)solution_result.semantic_strength,
          solution_result.profile_evidence ? "true" : "false");
    }
    cfbf_reassembly_commit_mapping(*candidate, state, solution_mapping,
                                   &solution_result, 2);
    state->search_phase = CFBF_REASSEMBLY_FINALIZED;
    carve_put_state((*candidate)->carvehashkey, state);
    *improved = true;
  }
  else {
    cfbf_reassembly_reset_atomic_search(state);
    state->search_phase = 3;
    if (exhaustive) {
      state->pair_suffix_possible = 0;
    }
    state->resume_slot = 0;
    state->resume_choice = 0;
    state->resume_run_width = 0;
    state->resume_run_left = 0;
    state->resume_source_pass = 0;
  }
  cfbf_reassembly_mapping_index_clear(&suffix_index);
  free(trial_data);
  free(solution_mapping);
  free(trial_mapping);
  free(suffix_mapping);
  free(base_mapping);
  return false;
}

// Reassemble externally fragmented CFBF files by repairing the complete FAT
// extent. Whole-suffix movement handles gaps, while block replacement handles
// displaced runs. Because some allocated streams and padding remain opaque,
// reconstructed compound files remain PROMISING for independent verification
// even when their parsed structures provide strong ranking evidence.
//
static inline void cfbf_reassembly(ThreadWork *work,
                                   CarveInfo **candidate,
                                   uuid_string_t uuidp,
                                   uuid_string_t uuidc) {

  CfbfCarveState *state = candidate && *candidate
      ? (CfbfCarveState *)carve_get_state((*candidate)->carvehashkey) : NULL;

  if (!candidate || !*candidate || !state
      || state->magic != CFBF_STATE_MAGIC
      || state->version != CFBF_STATE_VERSION
      || state->inferred_size == 0) {
    if (scalpel_state.mode_verbose && candidate && *candidate) {
      lock_fprintf(
          stdout,
          "CFBF custom reassembly unavailable: state=%s magic=%08" PRIx32
          " version=%" PRIu32 " inferred=%" PRIu64 ".\n",
          state ? "present" : "missing",
          state ? state->magic : UINT32_C(0),
          state ? state->version : UINT32_C(0),
          state ? state->inferred_size : UINT64_C(0));
    }
    cfbf_free_carve_state((void **)&state);
    if (candidate && *candidate) {
      destroy_candidate(candidate);
    }
    return;
  }
  if (!cfbf_reassembly_initialize_candidate(*candidate, state)) {
    cfbf_free_carve_state((void **)&state);
    destroy_candidate(candidate);
    return;
  }
  while (*candidate) {
    if (!cfbf_reassembly_initialize_candidate(*candidate, state)) {
      break;
    }
    CfbfTrialResult current;

    memset(&current, 0, sizeof(current));
    if (!cfbf_reassembly_evaluate_candidate(*candidate, &current)) {
      break;
    }

    state->profile = (uint32_t)current.profile;
    state->semantic_strength = (uint32_t)current.semantic_strength;
    state->failure_offset = current.failure_offset;

    if (scalpel_state.mode_verbose) {
      lock_fprintf(
          stdout,
          "CFBF candidate: header=%" PRId64 " blocks=%" PRIu64
          " structural=%s profile=%s semantic=%u evidence=%s"
          " payloads=%" PRIu32 "/%" PRIu32
          " inferred=%" PRIu64 " failure=%" PRIu64 ".\n",
          blockvector_get_actual_blocknumber((*candidate)->b, 0),
          blockvector_get_num_blocks((*candidate)->b),
          current.structurally_valid ? "true" : "false",
          cfbf_profile_filetype(current.profile),
          (uint32_t)current.semantic_strength,
          current.profile_evidence ? "true" : "false",
          current.validated_payloads, current.examined_payloads,
          current.inferred_size, current.failure_offset);
    }

    if (state->search_phase == CFBF_REASSEMBLY_FINALIZED) {
      break;
    }

    const bool current_complete = cfbf_reassembly_trial_complete(&current);
    const bool current_recoverable =
        cfbf_reassembly_trial_recoverable(&current);
    const bool opaque_recoverable = current_recoverable
        && !cfbf_reassembly_trial_authenticated(&current);

    if (opaque_recoverable) {
      (void)cfbf_reassembly_preserve_current_hypothesis(
          *candidate, state, &current);
    }
    if (current_complete && !opaque_recoverable) {
      break;
    }

    const uint64_t total_blocks = blockvector_get_num_blocks((*candidate)->b);
    CfbfProfile search_profile = cfbf_reassembly_model_profile(
        (*candidate)->b, current.profile);
    uint64_t targeted_slot = 0;

    if (total_blocks > 1) {
      targeted_slot = current.failure_offset / scalpel_state.blocksize;
      if (targeted_slot == 0) {
        targeted_slot = 1;
      }
      if (targeted_slot >= total_blocks) {
        targeted_slot = total_blocks - 1;
      }
    }
    uint64_t isolated_target_hint = targeted_slot;

    if (!current_complete && isolated_target_hint == 0
        && total_blocks > 1) {
      isolated_target_hint = current.failure_offset
                             / scalpel_state.blocksize;
      if (isolated_target_hint == 0) {
        isolated_target_hint = 1;
      }
      if (isolated_target_hint >= total_blocks) {
        isolated_target_hint = total_blocks - 1;
      }
    }

    bool improved = false;
    bool validated = false;

    const bool resume_supported_suffix =
        (state->search_phase == 1 || state->search_phase == 6)
        && state->suffix_pass == 6;
    const bool resume_suffix = state->search_phase == 1
                               && !resume_supported_suffix;
    bool resume_nearby_suffix = state->search_phase == 6
                                && state->suffix_pass == 5;
    const bool resume_replacement = state->search_phase == 2
                                    || state->search_phase == 5
                                    || state->search_phase
                                       == CFBF_REASSEMBLY_INDEXED_COMPLETION;
    const bool resume_pair = state->search_phase == 4;
    const bool resume_bounded_pair = resume_pair
                                     && state->suffix_pass == 6;
    const bool resume_isolated = state->search_phase == 7
                                 || state->search_phase
                                    == CFBF_REASSEMBLY_RANKED_RUNS;
    const bool resume_structural = state->search_phase
                                   == CFBF_REASSEMBLY_STRUCTURAL_ANCHORS;
    const bool resume_exhaustive_pair = resume_pair
                                        && state->suffix_pass == 7;
    const bool resume_targeted_suffix = resume_suffix
                                        && state->suffix_pass == 2;
    const bool resume_targeted_replacement = resume_replacement
                                             && state->suffix_pass == 3;
    const bool resume_exhaustive_replacement = resume_replacement
                                               && state->suffix_pass == 4;
    bool isolated_attempted = false;
    bool preferred_atomic_attempted = false;
    bool supported_pairs_attempted = false;

    // Allocation metadata can locate displaced blocks. Try those mappings
    // before broader searches; the full validator still checks each result.
    if ((state->search_phase == 0 || resume_structural)
        && !current_complete && isolated_target_hint > 0
        && (resume_structural
            || state->structural_search_complete == 0
            || state->structural_repairs != state->repairs)) {
      if (cfbf_reassembly_try_structural_anchors(
              work, candidate, state, &current, isolated_target_hint,
              uuidp, uuidc, &improved)) {
        cfbf_free_carve_state((void **)&state);
        return;
      }
      if (!*candidate) {
        cfbf_free_carve_state((void **)&state);
        return;
      }
      if (improved) {
        continue;
      }
    }

    // Probe parser-supported gap boundaries before generic searches emit
    // alternatives. A successful trial can identify a subtype even when the
    // original damaged mapping cannot be parsed.
    if (state->search_phase == 0 && !current_complete) {
      if (cfbf_reassembly_probe_supported_suffixes(
              work, candidate, state, &current, targeted_slot,
              uuidp, uuidc)) {
        cfbf_free_carve_state((void **)&state);
        return;
      }
      if (!*candidate) {
        cfbf_free_carve_state((void **)&state);
        return;
      }
      const CfbfProfile supported_profile =
          cfbf_reassembly_supported_profile(state);

      if (supported_profile != CFBF_PROFILE_UNKNOWN) {
        search_profile = supported_profile;
      }
    }

    // Project variable-data streams provide enough semantic evidence to rank a
    // gap and displaced run together. Resolve that model before generic CFBF
    // searches emit structurally valid but dominated alternatives.
    if (state->search_phase == 0 && search_profile == CFBF_PROFILE_MPP
        && state->suffix_candidate_valid != 0) {
        if (cfbf_reassembly_try_atomic_pair(
                work, candidate, state, &current, false, uuidp, uuidc,
                &improved, &validated)) {
          cfbf_free_carve_state((void **)&state);
          return;
        }
        if (validated || !*candidate) {
          cfbf_free_carve_state((void **)&state);
          return;
        }
        if (improved) {
          continue;
        }
        state->search_phase = 0;
        state->suffix_pass = 0;
        state->resume_slot = 0;
        state->resume_choice = 0;
        carve_put_state((*candidate)->carvehashkey, state);
        if (cfbf_reassembly_try_atomic_pair(
                work, candidate, state, &current, true, uuidp, uuidc,
                &improved, &validated)) {
          cfbf_free_carve_state((void **)&state);
          return;
        }
        if (validated || !*candidate) {
          cfbf_free_carve_state((void **)&state);
          return;
        }
        if (improved) {
          continue;
        }
        state->search_phase = 0;
        state->suffix_pass = 0;
        state->resume_slot = 0;
        state->resume_choice = 0;
        carve_put_state((*candidate)->carvehashkey, state);
    }

    if (state->search_phase == 0) {
      if (cfbf_reassembly_try_supported_gap_pairs(
              work, candidate, state,
              CFBF_SUPPORTED_PAIR_PREPASS_GAP_LIMIT,
              uuidp, uuidc, &supported_pairs_attempted, &improved)) {
        cfbf_free_carve_state((void **)&state);
        return;
      }
      if (!*candidate) {
        cfbf_free_carve_state((void **)&state);
        return;
      }
      if (improved) {
        continue;
      }
    }

    if (state->search_phase == 0) {
      if (cfbf_reassembly_try_model_combined(
              work, candidate, state, &current, uuidp, uuidc,
              &improved)) {
        cfbf_free_carve_state((void **)&state);
        return;
      }
      if (!*candidate) {
        cfbf_free_carve_state((void **)&state);
        return;
      }
      if (improved) {
        continue;
      }
    }

    // Rank physically supported whole-suffix gaps before entering the broader
    // combined search. Keep the original mapping active so a displaced run
    // can be evaluated together with the retained suffix before either is
    // committed.
    if (current.structurally_valid
        && (resume_supported_suffix || resume_nearby_suffix
            || state->search_phase == 0)) {
      if (cfbf_reassembly_probe_supported_suffixes(
              work, candidate, state, &current, targeted_slot,
              uuidp, uuidc)) {
        cfbf_free_carve_state((void **)&state);
        return;
      }
      if (!*candidate) {
        cfbf_free_carve_state((void **)&state);
        return;
      }
      resume_nearby_suffix = false;
    }

    if (state->search_phase == 0 && !supported_pairs_attempted) {
      if (cfbf_reassembly_try_supported_gap_pairs(
              work, candidate, state, 0, uuidp, uuidc,
              &supported_pairs_attempted, &improved)) {
        cfbf_free_carve_state((void **)&state);
        return;
      }
      if (!*candidate) {
        cfbf_free_carve_state((void **)&state);
        return;
      }
      if (improved) {
        continue;
      }
    }

    if (state->search_phase == 0
        || state->search_phase == CFBF_REASSEMBLY_CONTENT_COMBINED) {
      if (cfbf_reassembly_try_content_combined(
              work, candidate, state, &current, uuidp, uuidc,
              &improved)) {
        cfbf_free_carve_state((void **)&state);
        return;
      }
      if (!*candidate) {
        cfbf_free_carve_state((void **)&state);
        return;
      }
      if (improved) {
        continue;
      }
    }
    if (state->search_phase == CFBF_REASSEMBLY_CONTENT_COMPLETE) {
      state->search_phase = 0;
      carve_put_state((*candidate)->carvehashkey, state);
    }

    // A structurally valid allocation graph can expose an isolated displaced
    // run directly. Resolve that bounded OOO case after the coordinated
    // GAP+OOO search, which must retain the original contiguous mapping.
    if (state->search_phase == 0 && current.structurally_valid
        && state->suffix_candidate_valid == 0
        && !current_complete) {
      isolated_attempted = true;
      if (cfbf_reassembly_try_complete_run_search(
              work, candidate, state, &current, isolated_target_hint,
              uuidp, uuidc, &improved, &validated)) {
        cfbf_free_carve_state((void **)&state);
        return;
      }
      if (validated || !*candidate) {
        cfbf_free_carve_state((void **)&state);
        return;
      }
      if (improved) {
        continue;
      }
    }

    if (!current.structurally_valid
        && (resume_supported_suffix
            || (state->search_phase == 0
                && state->suffix_candidate_valid == 0))) {
      if (cfbf_reassembly_probe_supported_suffixes(
              work, candidate, state, &current, targeted_slot,
              uuidp, uuidc)) {
        cfbf_free_carve_state((void **)&state);
        return;
      }
      if (!*candidate) {
        cfbf_free_carve_state((void **)&state);
        return;
      }
    }
    if (state->search_phase == 0
        && state->suffix_candidate_valid != 0
        && cfbf_reassembly_handle_supported_suffix(
               *candidate, state, &current)) {
      continue;
    }

    // After one repair, a structurally valid candidate can expose the exact
    // target of a displaced run. Preserve bounded direct hypotheses before a
    // second plausible suffix changes that target mapping.
    if (!improved && !validated && *candidate
        && state->repairs > 0 && current.structurally_valid
        && state->suffix_candidate_valid != 0
        && !resume_suffix && !resume_replacement && !resume_pair
        && !resume_nearby_suffix && !resume_isolated) {
      bool ranked_improved = false;

      if (cfbf_reassembly_try_ranked_runs(
              work, candidate, state, &current, isolated_target_hint,
              uuidp, uuidc, &ranked_improved)) {
        cfbf_free_carve_state((void **)&state);
        return;
      }
      if (!*candidate) {
        cfbf_free_carve_state((void **)&state);
        return;
      }
      if (ranked_improved) {
        continue;
      }
      state->search_phase = 0;
      state->resume_slot = 0;
      state->resume_choice = 0;
      state->resume_run_width = 0;
      state->resume_run_left = 0;
      state->resume_source_pass = 0;
      carve_put_state((*candidate)->carvehashkey, state);
    }

    if (resume_isolated) {
      isolated_attempted = true;
      if (cfbf_reassembly_try_complete_run_search(
              work, candidate, state, &current, isolated_target_hint,
              uuidp, uuidc,
              &improved, &validated)) {
        cfbf_free_carve_state((void **)&state);
        return;
      }
      if (validated || !*candidate) {
        cfbf_free_carve_state((void **)&state);
        return;
      }
      if (improved) {
        continue;
      }
      if (current_complete) {
        break;
      }
    }

    // Structural failures usually identify the first incorrect logical
    // block. A gap moves the suffix beginning there, while an out-of-order
    // run replaces that slot. Trying those two repairs first avoids complete
    // image scans in the common case without removing the exhaustive paths.
    // A displaced run surrounded by filler has a direct, bounded search.
    // Try that exact OOO model before evaluating every possible nearby GAP
    // position, which otherwise repeats a full semantic parse at each slot.
    if (!improved && !validated && *candidate && !isolated_attempted
        && state->suffix_candidate_valid == 0
        && !resume_suffix && !resume_replacement && !resume_pair
        && !resume_nearby_suffix) {
      isolated_attempted = true;
      if (cfbf_reassembly_try_complete_run_search(
              work, candidate, state, &current, isolated_target_hint,
              uuidp, uuidc,
              &improved, &validated)) {
        cfbf_free_carve_state((void **)&state);
        return;
      }
      if (validated || !*candidate) {
        cfbf_free_carve_state((void **)&state);
        return;
      }
      if (improved) {
        continue;
      }
    }

    // A plausible gap can expose the displaced-run target without completing
    // the file. Test the physically ranked combined repair before committing
    // that gap alone so the original mapping remains available to both parts
    // of the hypothesis.
    if (!improved && !validated && *candidate
        && (resume_bounded_pair
            || (state->suffix_candidate_valid != 0
                && !resume_suffix && !resume_replacement && !resume_pair
                && !resume_nearby_suffix && !resume_isolated))) {
      preferred_atomic_attempted = true;
      if (cfbf_reassembly_try_atomic_pair(
              work, candidate, state, &current, false, uuidp, uuidc,
              &improved, &validated)) {
        cfbf_free_carve_state((void **)&state);
        return;
      }
      if (validated || !*candidate) {
        cfbf_free_carve_state((void **)&state);
        return;
      }
      if (improved) {
        continue;
      }
      state->search_phase = 0;
      state->suffix_pass = 0;
      state->resume_slot = 0;
      state->resume_choice = 0;
      carve_put_state((*candidate)->carvehashkey, state);

      if (search_profile == CFBF_PROFILE_MPP) {
        if (cfbf_reassembly_try_atomic_pair(
                work, candidate, state, &current, true, uuidp, uuidc,
                &improved, &validated)) {
          cfbf_free_carve_state((void **)&state);
          return;
        }
        if (validated || !*candidate) {
          cfbf_free_carve_state((void **)&state);
          return;
        }
        if (improved) {
          continue;
        }
      }

      // If the combined repair did not authenticate, test displaced runs
      // against the same baseline before a partial suffix changes its mapping.
      isolated_attempted = true;
      if (cfbf_reassembly_try_complete_run_search(
              work, candidate, state, &current, isolated_target_hint,
              uuidp, uuidc,
              &improved, &validated)) {
        cfbf_free_carve_state((void **)&state);
        return;
      }
      if (validated || !*candidate) {
        cfbf_free_carve_state((void **)&state);
        return;
      }
      if (improved) {
        continue;
      }
      if (cfbf_reassembly_commit_remembered_suffix(
              *candidate, state, &current)) {
        continue;
      }
    }
    if (!improved && !validated && *candidate
        && resume_exhaustive_pair
        && search_profile == CFBF_PROFILE_MPP) {
      if (cfbf_reassembly_try_atomic_pair(
              work, candidate, state, &current, true, uuidp, uuidc,
              &improved, &validated)) {
        cfbf_free_carve_state((void **)&state);
        return;
      }
      if (validated || !*candidate) {
        cfbf_free_carve_state((void **)&state);
        return;
      }
      if (improved) {
        continue;
      }
    }
    if (current_complete) {
      break;
    }
    if (current.structurally_valid) {
      break;
    }

    if (!improved && !validated && *candidate
        && !resume_exhaustive_pair && !preferred_atomic_attempted) {
      if (cfbf_reassembly_try_atomic_pair(
              work, candidate, state, &current, false, uuidp, uuidc,
              &improved, &validated)) {
        cfbf_free_carve_state((void **)&state);
        return;
      }
      if (validated || !*candidate) {
        cfbf_free_carve_state((void **)&state);
        return;
      }
    }

    if (!improved && !validated && *candidate
        && !resume_replacement && !resume_exhaustive_pair
        && total_blocks > 1
        && (resume_targeted_suffix
            || (!resume_suffix && targeted_slot != 0))) {
      const uint64_t suffix_slot = resume_targeted_suffix
                                   ? state->resume_slot : targeted_slot;

      state->suffix_pass = 2;
      if (cfbf_reassembly_try_suffix_shifts(
              work, candidate, state, &current, suffix_slot, 1, 0,
              uuidp, uuidc, &improved, &validated)) {
        cfbf_free_carve_state((void **)&state);
        return;
      }
    }

    if (!improved && !validated && *candidate && !resume_exhaustive_pair
        && (resume_targeted_replacement
            || ((!resume_suffix || resume_targeted_suffix)
                && !resume_replacement && targeted_slot != 0))) {
      const uint64_t replacement_slot = resume_targeted_replacement
                                        ? state->resume_slot : targeted_slot;

      state->suffix_pass = 3;
      if (cfbf_reassembly_try_block_replacements(
              work, candidate, state, &current, replacement_slot,
              replacement_slot, uuidp, uuidc, &improved, &validated)) {
        cfbf_free_carve_state((void **)&state);
        return;
      }
    }

    if (!improved && !validated && *candidate
        && !resume_exhaustive_replacement && !resume_exhaustive_pair) {
      if (total_blocks > 1) {
        uint64_t first_strong_slot = 1;

        if (resume_suffix && state->resume_slot > 0
            && state->resume_slot < total_blocks) {
          first_strong_slot = state->resume_slot;
        }
        state->suffix_pass = 0;
        for (uint64_t suffix_slot = first_strong_slot;
             suffix_slot < total_blocks; suffix_slot++) {
          if (cfbf_reassembly_try_suffix_shifts(
                  work, candidate, state, &current, suffix_slot, 1, 0,
                  uuidp, uuidc, &improved, &validated)) {
            cfbf_free_carve_state((void **)&state);
            return;
          }
          if (improved || validated || !*candidate) {
            break;
          }
        }
      }
    }
    if (!improved && !validated && *candidate
        && (resume_exhaustive_pair || !resume_exhaustive_replacement)) {
      if (cfbf_reassembly_try_atomic_pair(
              work, candidate, state, &current, true, uuidp, uuidc,
              &improved, &validated)) {
        cfbf_free_carve_state((void **)&state);
        return;
      }
      if (validated || !*candidate) {
        cfbf_free_carve_state((void **)&state);
        return;
      }
    }
    if (!improved && !validated && *candidate) {
      state->suffix_pass = 4;
      if (cfbf_reassembly_try_block_replacements(
              work, candidate, state, &current, 1, total_blocks - 1,
              uuidp, uuidc, &improved, &validated)) {
        cfbf_free_carve_state((void **)&state);
        return;
      }
      if (validated || !*candidate) {
        cfbf_free_carve_state((void **)&state);
        return;
      }
    }
    if (validated || !*candidate) {
      cfbf_free_carve_state((void **)&state);
      return;
    }
    if (improved) {
      continue;
    }
    break;
  }

  if (*candidate) {
    CfbfTrialResult final_result;

    memset(&final_result, 0, sizeof(final_result));
    if (!cfbf_reassembly_evaluate_candidate(*candidate, &final_result)) {
      final_result.profile = CFBF_PROFILE_UNKNOWN;
    }
    state->profile = (uint32_t)final_result.profile;
    state->semantic_strength = (uint32_t)final_result.semantic_strength;
    state->failure_offset = final_result.failure_offset;
    const bool final_recoverable =
        cfbf_reassembly_trial_recoverable(&final_result);

    if (final_recoverable && final_result.inferred_size > 0) {
      state->inferred_size = final_result.inferred_size;
    }
    else if (final_result.inferred_size > state->inferred_size) {
      state->inferred_size = final_result.inferred_size;
    }
    if (state->inferred_size > 0) {
      const uint64_t proven_blocks = CEILDIV(
          state->inferred_size, scalpel_state.blocksize);

      if (final_recoverable && proven_blocks > 0
          && proven_blocks
                 < blockvector_get_num_blocks((*candidate)->b)) {
        resize_blockvector((*candidate)->b, proven_blocks);
        inflate_blockvector((*candidate)->b);
      }
      blockvector_set_data_length((*candidate)->b, state->inferred_size);
    }
    carve_put_state((*candidate)->carvehashkey, state);
    cfbf_assign_candidate_profile(*candidate, final_result.profile);
    if (scalpel_state.write_promising) {
      (*candidate)->flavor = PROMISING;
      write_candidate(candidate, false);
    }
    else {
      destroy_candidate(candidate);
    }
  }
  cfbf_free_carve_state((void **)&state);
}

// Serialize the fixed-size CFBF validation state.
//
static inline bool cfbf_serialize_carve_state(void **state, FILE *fp,
                                              StateSerialization mode) {

  if (!state || !fp) {
    return false;
  }

  CfbfCarveState **typed = (CfbfCarveState **)state;

  if (mode == DESERIALIZE) {
    *typed = (CfbfCarveState *)malloc(sizeof(**typed));
    check_memory_allocation(*typed, __LINE__, __FILE__,
                            "CFBF carve state");
  }
  size_t count = mode == SERIALIZE
                     ? fwrite(*typed, sizeof(**typed), 1, fp)
                     : fread(*typed, sizeof(**typed), 1, fp);

  if (count != 1) {
    handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
  }
  return true;
}

// Clone the fixed-size CFBF validation state.
//
static inline void *cfbf_clone_carve_state(const void *srcstate) {

  if (!srcstate) {
    return NULL;
  }
  CfbfCarveState *clone = (CfbfCarveState *)malloc(sizeof(*clone));
  check_memory_allocation(clone, __LINE__, __FILE__,
                          "CFBF carve state clone");
  memcpy(clone, srcstate, sizeof(*clone));
  return clone;
}

// Release a cloned CFBF validation state.
//
static inline void cfbf_free_carve_state(void **state) {

  if (state && *state) {
    free(*state);
    *state = NULL;
  }
}

// Report the fixed allocation size to the carve-state fast path.
//
static inline size_t cfbf_sizeof_carve_state(const void *state) {

  (void)state;
  return sizeof(CfbfCarveState);
}

// Print CFBF validation state for the optional state debugging facility.
//
static inline void cfbf_print_carve_state(const void *state) {

  const CfbfCarveState *typed = (const CfbfCarveState *)state;

  if (!typed) {
    printf("NULL\n");
    return;
  }
  printf("profile=%s inferred_size=%" PRIu64 " failure_offset=%" PRIu64
         "\n",
         cfbf_profile_filetype((CfbfProfile)typed->profile),
         typed->inferred_size, typed->failure_offset);
}

#endif
