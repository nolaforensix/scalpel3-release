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

#if !defined(SCALPEL_BIFF_H)
#define SCALPEL_BIFF_H

#include "scalpel.h"
#include "validator_search.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define BIFF_MINIMUM_SIZE       UINT64_C(14)
#define BIFF_RECORD_HEADER_SIZE UINT64_C(4)
#define BIFF_LEGACY_MAX_RECORD_SIZE UINT16_C(2080)
#define BIFF8_MAX_RECORD_SIZE   UINT16_C(8224)
#define BIFF_REASSEMBLY_LOOKAHEAD_RECORD_SIZE BIFF8_MAX_RECORD_SIZE
#define BIFF_RECORD_EOF         UINT16_C(0x000a)
#define BIFF_RECORD_INDEX2      UINT16_C(0x000b)
#define BIFF_RECORD_INDEX3_8    UINT16_C(0x020b)
#define BIFF_RECORD_HEADER      UINT16_C(0x0014)
#define BIFF_RECORD_FOOTER      UINT16_C(0x0015)
#define BIFF_BOF2               UINT16_C(0x0009)
#define BIFF_BOF3               UINT16_C(0x0209)
#define BIFF_BOF4               UINT16_C(0x0409)
#define BIFF_BOF5_8             UINT16_C(0x0809)
#define BIFF_TYPE_WORKBOOK      UINT16_C(0x0005)
#define BIFF_TYPE_WORKSHEET     UINT16_C(0x0010)
#define BIFF_TYPE_CHART         UINT16_C(0x0020)
#define BIFF_TYPE_MACRO         UINT16_C(0x0040)
#define BIFF_TYPE_WORKSPACE     UINT16_C(0x0100)
#define BIFF_REASSEMBLY_POLL_MASK UINT64_C(0xff)
#define BIFF_MODICO_LOW_CONFIDENCE ((BlockValidationDecision)2)

typedef struct BiffRecordRange {
  uint16_t first;
  uint16_t last;
} BiffRecordRange;

typedef enum BiffParseResult {
  BIFF_PARSE_INVALID = 0,
  BIFF_PARSE_COMPLETE,
  BIFF_PARSE_TRUNCATED,
  BIFF_PARSE_DAMAGED
} BiffParseResult;

typedef struct BiffParseSummary {
  uint64_t verified_end;
  uint64_t record_count;
  uint64_t recognized_header_count;
  uint64_t unknown_header_count;
  uint64_t known_header_end;
  uint64_t continuation_origin;
  uint64_t first_continuation_header_end;
  uint64_t first_continuation_record_end;
  uint64_t required_stream_end;
  uint64_t index_record_offset;
  uint64_t resume_offset;
  uint64_t pending_record_end;
  uint32_t dimension_last_row;
  uint32_t last_cell_row;
  uint32_t first_continuation_cell_row;
  uint32_t same_record_streak;
  uint32_t alternating_record_streak;
  uint16_t bof_id;
  uint16_t document_type;
  uint16_t current_document_type;
  uint16_t previous_complete_record_id;
  uint16_t last_complete_record_id;
  uint16_t pending_record_id;
  uint16_t first_continuation_record_id;
  uint16_t last_cell_column;
  uint16_t first_continuation_cell_column;
  bool workbook_stream;
  bool saw_content_substream;
  bool pending_header_complete;
  bool pending_header_known;
  bool continuation_active;
  bool continuation_skip_origin_record;
  bool first_continuation_header_known;
  bool premature_eof;
  bool saw_index_record;
  bool invalid_index_target;
  bool saw_dimension;
  bool saw_cell_record;
  bool first_continuation_cell_seen;
} BiffParseSummary;

typedef struct BiffTrialScore {
  bool found;
  bool complete;
  bool clean;
  bool adjacent;
  bool first_header_known;
  bool continuation_match;
  bool sequence_match;
  bool cell_sequence_match;
  int64_t start_actual;
  uint64_t commit_blocks;
  uint64_t verified_end;
  uint64_t new_records;
  uint64_t new_known_headers;
  uint64_t new_unknown_headers;
  uint64_t confidence_sum;
  uint64_t reservation_sum;
  uint64_t physical_distance;
  uint64_t discontinuity;
  uint64_t cell_distance;
  uint64_t run_blocks;
  BlockValidationDecision start_confidence;
  BlockValidationDecision minimum_confidence;
} BiffTrialScore;

#define BIFF_SEARCH_STATE_MAGIC UINT32_C(0x42494631)
typedef struct {
  uint32_t magic;
  uint32_t phase;
  uint32_t pass;
  bool pass_started;
  bool scan_started;
  uint32_t adjacent_stage;
  uint64_t next_actual;
  bool run_active;
  uint64_t run_next_actual;
  uint64_t run_blocks;
  uint64_t prefix_blocks;
  uint64_t probe_blocks;
  XXH128_hash_t view;
  BiffTrialScore best;
} BiffSearchProgress;

typedef struct {
  BiffSearchProgress progress;
  int64_t *best_actual;
} BiffCarveState;

// Record identifiers defined by BIFF2 through BIFF8. Unknown identifiers are
// accepted for compatibility, but known identifiers provide stronger evidence
// when fragmented streams are ranked.
//
static const BiffRecordRange biff_known_record_ranges[] = {
  {UINT16_C(0x0000), UINT16_C(0x002b)},
  {UINT16_C(0x002f), UINT16_C(0x002f)},
  {UINT16_C(0x0031), UINT16_C(0x0033)},
  {UINT16_C(0x0036), UINT16_C(0x0037)},
  {UINT16_C(0x003c), UINT16_C(0x003e)},
  {UINT16_C(0x0040), UINT16_C(0x0045)},
  {UINT16_C(0x004d), UINT16_C(0x004d)},
  {UINT16_C(0x0050), UINT16_C(0x0052)},
  {UINT16_C(0x0055), UINT16_C(0x0056)},
  {UINT16_C(0x0059), UINT16_C(0x0061)},
  {UINT16_C(0x0063), UINT16_C(0x0063)},
  {UINT16_C(0x007d), UINT16_C(0x007d)},
  {UINT16_C(0x0080), UINT16_C(0x0086)},
  {UINT16_C(0x008c), UINT16_C(0x008d)},
  {UINT16_C(0x0090), UINT16_C(0x0090)},
  {UINT16_C(0x0092), UINT16_C(0x0092)},
  {UINT16_C(0x0097), UINT16_C(0x009e)},
  {UINT16_C(0x00a0), UINT16_C(0x00a1)},
  {UINT16_C(0x00ab), UINT16_C(0x00ab)},
  {UINT16_C(0x00ae), UINT16_C(0x00b2)},
  {UINT16_C(0x00b4), UINT16_C(0x00b6)},
  {UINT16_C(0x00b8), UINT16_C(0x00b9)},
  {UINT16_C(0x00bd), UINT16_C(0x00be)},
  {UINT16_C(0x00c1), UINT16_C(0x00c1)},
  {UINT16_C(0x00c5), UINT16_C(0x00d3)},
  {UINT16_C(0x00d5), UINT16_C(0x00da)},
  {UINT16_C(0x00dc), UINT16_C(0x00de)},
  {UINT16_C(0x00e0), UINT16_C(0x00e3)},
  {UINT16_C(0x00e5), UINT16_C(0x00e5)},
  {UINT16_C(0x00e9), UINT16_C(0x00e9)},
  {UINT16_C(0x00eb), UINT16_C(0x00ed)},
  {UINT16_C(0x00ef), UINT16_C(0x00f2)},
  {UINT16_C(0x00f4), UINT16_C(0x00f9)},
  {UINT16_C(0x00fb), UINT16_C(0x00fd)},
  {UINT16_C(0x00ff), UINT16_C(0x0100)},
  {UINT16_C(0x0103), UINT16_C(0x0103)},
  {UINT16_C(0x0122), UINT16_C(0x0122)},
  {UINT16_C(0x0137), UINT16_C(0x0138)},
  {UINT16_C(0x013b), UINT16_C(0x013b)},
  {UINT16_C(0x013d), UINT16_C(0x0140)},
  {UINT16_C(0x014a), UINT16_C(0x014b)},
  {UINT16_C(0x014d), UINT16_C(0x0154)},
  {UINT16_C(0x015f), UINT16_C(0x0161)},
  {UINT16_C(0x0191), UINT16_C(0x0198)},
  {UINT16_C(0x01a9), UINT16_C(0x01b2)},
  {UINT16_C(0x01b5), UINT16_C(0x01be)},
  {UINT16_C(0x01c0), UINT16_C(0x01c2)},
  {UINT16_C(0x0200), UINT16_C(0x0201)},
  {UINT16_C(0x0203), UINT16_C(0x0209)},
  {UINT16_C(0x020b), UINT16_C(0x020b)},
  {UINT16_C(0x0218), UINT16_C(0x0218)},
  {UINT16_C(0x0221), UINT16_C(0x0221)},
  {UINT16_C(0x0223), UINT16_C(0x0223)},
  {UINT16_C(0x0225), UINT16_C(0x0225)},
  {UINT16_C(0x0231), UINT16_C(0x0231)},
  {UINT16_C(0x0236), UINT16_C(0x0236)},
  {UINT16_C(0x023e), UINT16_C(0x023e)},
  {UINT16_C(0x0243), UINT16_C(0x0243)},
  {UINT16_C(0x027e), UINT16_C(0x027e)},
  {UINT16_C(0x0293), UINT16_C(0x0293)},
  {UINT16_C(0x0406), UINT16_C(0x0406)},
  {UINT16_C(0x0409), UINT16_C(0x0409)},
  {UINT16_C(0x0418), UINT16_C(0x0418)},
  {UINT16_C(0x041e), UINT16_C(0x041e)},
  {UINT16_C(0x043c), UINT16_C(0x043c)},
  {UINT16_C(0x0443), UINT16_C(0x0443)},
  {UINT16_C(0x04bc), UINT16_C(0x04bc)},
  {UINT16_C(0x0800), UINT16_C(0x0810)},
  {UINT16_C(0x0812), UINT16_C(0x0813)},
  {UINT16_C(0x0850), UINT16_C(0x085a)},
  {UINT16_C(0x0862), UINT16_C(0x0868)},
  {UINT16_C(0x086a), UINT16_C(0x086c)},
  {UINT16_C(0x0871), UINT16_C(0x0872)},
  {UINT16_C(0x0874), UINT16_C(0x087f)},
  {UINT16_C(0x0884), UINT16_C(0x0890)},
  {UINT16_C(0x0892), UINT16_C(0x089f)},
  {UINT16_C(0x08a3), UINT16_C(0x08a7)},
  {UINT16_C(0x1001), UINT16_C(0x1003)},
  {UINT16_C(0x1006), UINT16_C(0x1007)},
  {UINT16_C(0x1009), UINT16_C(0x100d)},
  {UINT16_C(0x1014), UINT16_C(0x1022)},
  {UINT16_C(0x1024), UINT16_C(0x1027)},
  {UINT16_C(0x1032), UINT16_C(0x1035)},
  {UINT16_C(0x103a), UINT16_C(0x103a)},
  {UINT16_C(0x103c), UINT16_C(0x1041)},
  {UINT16_C(0x1043), UINT16_C(0x1046)},
  {UINT16_C(0x1048), UINT16_C(0x1048)},
  {UINT16_C(0x104a), UINT16_C(0x104b)},
  {UINT16_C(0x104e), UINT16_C(0x1051)},
  {UINT16_C(0x105b), UINT16_C(0x105d)},
  {UINT16_C(0x105f), UINT16_C(0x1068)}
};

static inline uint16_t biff_read_le16(const uint8_t *data);
static inline uint32_t biff_read_le32(const uint8_t *data);
static inline bool biff_bof_id(uint16_t record_id);
static inline bool biff_document_type(uint16_t type);
static inline uint16_t biff_max_record_size(uint16_t bof_id);
static inline bool biff_known_record_id(uint16_t record_id);
static inline bool biff_record_length_plausible(uint16_t record_id,
                                                uint16_t record_length);
static inline bool biff_record_version_compatible(uint16_t bof_id,
                                                  uint16_t record_id);
static inline bool biff_cell_range(uint16_t record_id,
                                   const uint8_t *record_data,
                                   uint16_t record_length,
                                   uint32_t *row,
                                   uint16_t *first_column,
                                   uint16_t *last_column);
static inline void biff_update_index_bounds(const uint8_t *record_data,
                                            uint16_t record_length,
                                            uint16_t bof_id,
                                            BiffParseSummary *summary);
static inline bool biff_index_targets_valid(const uint8_t *data,
                                            uint64_t length,
                                            const BiffParseSummary *summary);
static inline BiffParseResult biff_parse_records(const uint8_t *data,
                                                 uint64_t length,
                                                 BiffParseSummary *summary);
static inline BiffParseResult biff_parse_continue(
    const uint8_t *data, uint64_t length, BiffParseSummary *summary);
static inline char *biff_header_discovery(char *base, uint64_t offset,
                                          uint64_t remaining,
                                          char **matchpos,
                                          uint32_t *matchlen,
                                          uint32_t blocksize);
static inline BiffParseResult biff_parse(const uint8_t *data,
                                         uint64_t length,
                                         BiffParseSummary *summary);
static inline void biff_file_validate(char *data, uint64_t length,
                                      bool *validates,
                                      uint64_t *validates_to,
                                      bool *promising,
                                      uint32_t needleidx,
                                      uint32_t blocksize,
                                      void *carvehashkey);
static inline bool biff_candidate_is_contiguous(const CarveInfo *candidate);
static inline void biff_candidate_validate(CarveInfo *candidate,
                                           bool *validates,
                                           uint64_t *validates_to,
                                           bool *promising);
static inline bool biff_reassembly_poll(ThreadWork *work,
                                        CarveInfo **candidate,
                                        uuid_string_t uuidp,
                                        uuid_string_t uuidc);
static inline bool biff_reassembly_copy_block(uint8_t *destination,
                                              int64_t actual);
static inline uint64_t biff_reassembly_collect_run(
    CarveInfo *candidate, int64_t start_actual, uint64_t maximum_blocks,
    uint8_t *trial_data, uint64_t destination_slot, int64_t *mapping,
    bool split_low_confidence, bool skip_low_confidence,
    BiffSearchProgress *progress, bool *interrupted);
static inline bool biff_trial_score_better(const BiffTrialScore *trial,
                                           const BiffTrialScore *best);
static inline bool biff_reassembly_score_mapping(
    CarveInfo *candidate, const BiffParseSummary *current_summary,
    uint8_t *trial_data, int64_t *trial_mapping, uint64_t mapping_blocks,
    BiffTrialScore *score);
static inline bool biff_reassembly_evaluate_run(
    CarveInfo *candidate, const BiffParseSummary *current_summary,
    int64_t start_actual, uint64_t maximum_blocks, uint8_t *trial_data,
    int64_t *trial_mapping, BiffTrialScore *score,
    bool split_low_confidence, bool skip_low_confidence,
    BiffSearchProgress *progress, bool *interrupted);
static inline bool biff_reassembly_find_continuation_bridge(
    ThreadWork *work, CarveInfo **candidate,
    const BiffParseSummary *current_summary, uint8_t *trial_data,
    int64_t *trial_mapping, uint64_t maximum_blocks,
    BiffTrialScore *best, int64_t *best_mapping, BiffSearchProgress *progress, bool *interrupted,
    uuid_string_t uuidp, uuid_string_t uuidc);
static inline void biff_reassembly(ThreadWork *work,
                                   CarveInfo **candidate,
                                   uuid_string_t uuidp,
                                   uuid_string_t uuidc);
static inline XXH128_hash_t biff_search_view(CarveInfo *candidate);
static inline void biff_save_search(CarveInfo *candidate, BiffSearchProgress *progress,
                                    const BiffTrialScore *best, const int64_t *best_mapping,
                                    const int64_t *trial_mapping);
static inline void biff_load_search(CarveInfo *candidate, BiffSearchProgress *progress,
                                    BiffTrialScore *best, int64_t *best_mapping,
                                    int64_t *trial_mapping);
static inline bool biff_serialize_carve_state(void **state, FILE *fp, StateSerialization mode);
static inline void *biff_clone_carve_state(const void *state);
static inline void biff_free_carve_state(void **state);
static inline size_t biff_sizeof_carve_state(const void *state);
static inline void biff_print_carve_state(const void *state);

static inline uint16_t biff_read_le16(const uint8_t *data) {

  return (uint16_t)data[0] | ((uint16_t)data[1] << 8);
}

static inline uint32_t biff_read_le32(const uint8_t *data) {

  return (uint32_t)data[0] | ((uint32_t)data[1] << 8)
         | ((uint32_t)data[2] << 16) | ((uint32_t)data[3] << 24);
}

static inline bool biff_bof_id(uint16_t record_id) {

  return record_id == BIFF_BOF2 || record_id == BIFF_BOF3
         || record_id == BIFF_BOF4 || record_id == BIFF_BOF5_8;
}

static inline bool biff_document_type(uint16_t type) {

  return type == BIFF_TYPE_WORKBOOK || type == BIFF_TYPE_WORKSHEET
         || type == BIFF_TYPE_CHART || type == BIFF_TYPE_MACRO
         || type == BIFF_TYPE_WORKSPACE;
}

// BIFF2 through BIFF5 limit record payloads to 2,080 bytes. The shared
// BIFF5/BIFF8 BOF identifier does not always identify the version reliably, so
// retain the BIFF8 ceiling for that identifier and use the tighter limit only
// where the BOF identifier is unambiguous.
//
static inline uint16_t biff_max_record_size(uint16_t bof_id) {

  return bof_id == BIFF_BOF5_8 ? BIFF8_MAX_RECORD_SIZE
                               : BIFF_LEGACY_MAX_RECORD_SIZE;
}

// Determine whether a record identifier is defined by a documented BIFF
// version. Binary search keeps the check inexpensive for large worksheets.
//
static inline bool biff_known_record_id(uint16_t record_id) {

  uint64_t first = 0;
  uint64_t count = sizeof(biff_known_record_ranges)
                   / sizeof(biff_known_record_ranges[0]);

  while (count > 0) {
    const uint64_t step = count / 2;
    const uint64_t index = first + step;

    if (record_id < biff_known_record_ranges[index].first) {
      count = step;
    }
    else if (record_id > biff_known_record_ranges[index].last) {
      first = index + 1;
      count -= step + 1;
    }
    else {
      return true;
    }
  }
  return false;
}

// Enforce record lengths that are invariant across supported BIFF versions.
// BIFF permits an empty EOF record and empty worksheet header/footer strings;
// other zero-length records commonly arise from misaligned payload bytes.
//
static inline bool biff_record_length_plausible(uint16_t record_id,
                                                uint16_t record_length) {

  if (record_id == BIFF_RECORD_EOF) {
    return record_length == 0;
  }
  if (record_id == UINT16_C(0x000e)) {
    return record_length == 2;
  }
  if (record_id == UINT16_C(0x0040)) {
    return record_length == 2;
  }
  return record_length != 0 || record_id == BIFF_RECORD_HEADER
         || record_id == BIFF_RECORD_FOOTER;
}

// Reject record encodings that identify a different BIFF generation. Several
// record families retained older identifiers in later versions, so only IDs
// whose generation is unambiguous are constrained here.
//
static inline bool biff_record_version_compatible(uint16_t bof_id,
                                                  uint16_t record_id) {

  if (bof_id == BIFF_BOF2) {
    return record_id != UINT16_C(0x0206)
           && record_id != UINT16_C(0x0406)
           && record_id != UINT16_C(0x0243)
           && record_id != UINT16_C(0x0443);
  }
  if (bof_id == BIFF_BOF3) {
    return record_id != UINT16_C(0x0000)
           && record_id != UINT16_C(0x0001)
           && record_id != UINT16_C(0x0002)
           && record_id != UINT16_C(0x0003)
           && record_id != UINT16_C(0x0004)
           && record_id != UINT16_C(0x0005)
           && record_id != UINT16_C(0x0006)
           && record_id != UINT16_C(0x0007)
           && record_id != UINT16_C(0x0008)
           && record_id != UINT16_C(0x000b)
           && record_id != UINT16_C(0x0406)
           && record_id != UINT16_C(0x0043)
           && record_id != UINT16_C(0x0443)
           && record_id != UINT16_C(0x041e);
  }
  if (bof_id == BIFF_BOF4) {
    return record_id != UINT16_C(0x0000)
           && record_id != UINT16_C(0x0001)
           && record_id != UINT16_C(0x0002)
           && record_id != UINT16_C(0x0003)
           && record_id != UINT16_C(0x0004)
           && record_id != UINT16_C(0x0005)
           && record_id != UINT16_C(0x0006)
           && record_id != UINT16_C(0x0007)
           && record_id != UINT16_C(0x0008)
           && record_id != UINT16_C(0x000b)
           && record_id != UINT16_C(0x0206)
           && record_id != UINT16_C(0x0043)
           && record_id != UINT16_C(0x0243);
  }
  return true;
}

// Extract the ordered worksheet coordinates carried by BIFF cell records.
// Multiple-cell records identify their first and last columns explicitly.
//
static inline bool biff_cell_range(uint16_t record_id,
                                   const uint8_t *record_data,
                                   uint16_t record_length,
                                   uint32_t *row,
                                   uint16_t *first_column,
                                   uint16_t *last_column) {

  if (!record_data || !row || !first_column || !last_column
      || record_length < 4) {
    return false;
  }

  switch (record_id) {
    case UINT16_C(0x0001):
    case UINT16_C(0x0002):
    case UINT16_C(0x0003):
    case UINT16_C(0x0004):
    case UINT16_C(0x0005):
    case UINT16_C(0x0006):
    case UINT16_C(0x0201):
    case UINT16_C(0x0203):
    case UINT16_C(0x0204):
    case UINT16_C(0x0205):
    case UINT16_C(0x0206):
    case UINT16_C(0x027e):
    case UINT16_C(0x0406):
      *row = biff_read_le16(record_data);
      *first_column = biff_read_le16(record_data + 2);
      *last_column = *first_column;
      return true;

    case UINT16_C(0x00bd):
    case UINT16_C(0x00be):
      if (record_length < 6) {
        return false;
      }
      *row = biff_read_le16(record_data);
      *first_column = biff_read_le16(record_data + 2);
      *last_column = biff_read_le16(record_data + record_length - 2);
      return *last_column >= *first_column;

    default:
      return false;
  }
}

// INDEX records contain absolute stream positions for records that appear
// later in BIFF2 through BIFF4 worksheet streams. A valid EOF cannot precede
// any nonzero position already declared by the stream itself.
//
static inline void biff_update_index_bounds(const uint8_t *record_data,
                                            uint16_t record_length,
                                            uint16_t bof_id,
                                            BiffParseSummary *summary) {

  if (!record_data || !summary) {
    return;
  }

  uint16_t array_offset = 0;

  if (bof_id == BIFF_BOF2 && record_length >= 8) {
    const uint32_t first_record = biff_read_le32(record_data);

    if (first_record != 0
        && (uint64_t)first_record + BIFF_RECORD_HEADER_SIZE
               > summary->required_stream_end) {
      summary->required_stream_end = (uint64_t)first_record
                                     + BIFF_RECORD_HEADER_SIZE;
    }
    array_offset = 8;
  }
  else if ((bof_id == BIFF_BOF3 || bof_id == BIFF_BOF4)
           && record_length >= 12) {
    const uint32_t first_record = biff_read_le32(record_data);
    const uint32_t first_xf = biff_read_le32(record_data + 8);

    if (first_record != 0
        && (uint64_t)first_record + BIFF_RECORD_HEADER_SIZE
               > summary->required_stream_end) {
      summary->required_stream_end = (uint64_t)first_record
                                     + BIFF_RECORD_HEADER_SIZE;
    }
    if (first_xf != 0
        && (uint64_t)first_xf + BIFF_RECORD_HEADER_SIZE
               > summary->required_stream_end) {
      summary->required_stream_end = (uint64_t)first_xf
                                     + BIFF_RECORD_HEADER_SIZE;
    }
    array_offset = 12;
  }

  for (uint16_t offset = array_offset;
       array_offset != 0 && offset + sizeof(uint32_t) <= record_length;
       offset += sizeof(uint32_t)) {
    const uint32_t record_position = biff_read_le32(record_data + offset);

    if (record_position != 0
        && (uint64_t)record_position + BIFF_RECORD_HEADER_SIZE
               > summary->required_stream_end) {
      summary->required_stream_end = (uint64_t)record_position
                                     + BIFF_RECORD_HEADER_SIZE;
    }
  }
}

// Verify absolute record positions carried by a legacy INDEX record. The XF
// pointer and every row-block pointer identify version-specific record types,
// providing independent evidence that a reconstructed stream retained its
// original logical layout.
//
static inline bool biff_index_targets_valid(
    const uint8_t *data, uint64_t length, const BiffParseSummary *summary) {

  if (!data || !summary || !summary->saw_index_record) {
    return true;
  }
  if (summary->index_record_offset > length
      || length - summary->index_record_offset < BIFF_RECORD_HEADER_SIZE) {
    return false;
  }

  const uint8_t *header = data + summary->index_record_offset;
  const uint16_t record_id = biff_read_le16(header);
  const uint16_t record_length = biff_read_le16(header + 2);
  const uint64_t record_end = summary->index_record_offset
                              + BIFF_RECORD_HEADER_SIZE + record_length;

  if ((record_id != BIFF_RECORD_INDEX2
       && record_id != BIFF_RECORD_INDEX3_8)
      || record_end > length) {
    return false;
  }

  const uint8_t *record_data = header + BIFF_RECORD_HEADER_SIZE;
  uint16_t row_pointer_offset = 0;
  uint16_t expected_row_id = 0;

  if (summary->bof_id == BIFF_BOF2 && record_length >= 8) {
    row_pointer_offset = 8;
    expected_row_id = UINT16_C(0x0008);
  }
  else if ((summary->bof_id == BIFF_BOF3
            || summary->bof_id == BIFF_BOF4)
           && record_length >= 12) {
    const uint32_t xf_position = biff_read_le32(record_data + 8);
    const uint16_t expected_xf_id = summary->bof_id == BIFF_BOF3
                                        ? UINT16_C(0x0243)
                                        : UINT16_C(0x0443);

    if (xf_position != 0
        && ((uint64_t)xf_position + BIFF_RECORD_HEADER_SIZE > length
            || biff_read_le16(data + xf_position) != expected_xf_id)) {
      return false;
    }
    row_pointer_offset = 12;
    expected_row_id = UINT16_C(0x0208);
  }

  for (uint16_t offset = row_pointer_offset;
       row_pointer_offset != 0 && offset + sizeof(uint32_t) <= record_length;
       offset += sizeof(uint32_t)) {
    const uint32_t row_position = biff_read_le32(record_data + offset);

    if (row_position != 0
        && ((uint64_t)row_position + BIFF_RECORD_HEADER_SIZE > length
            || biff_read_le16(data + row_position) != expected_row_id)) {
      return false;
    }
  }
  return true;
}

// Find old raw BIFF streams by checking the complete BOF record prefix rather
// than emitting candidates for every incidental two-byte BOF identifier.
//
static inline char *biff_header_discovery(char *base, uint64_t offset,
                                          uint64_t remaining,
                                          char **matchpos,
                                          uint32_t *matchlen,
                                          uint32_t blocksize) {

  (void)blocksize;

  if (!base || !matchpos || !matchlen) {
    return NULL;
  }
  *matchpos = NULL;
  *matchlen = 8;

  if (remaining < 8) {
    return NULL;
  }

  const uint8_t *region = (const uint8_t *)base + offset;
  uint64_t searched = 0;

  while (searched + 8 <= remaining) {
    const uint8_t *candidate = memchr(region + searched, 0x09,
                                     (size_t)(remaining - searched - 7));

    if (!candidate) {
      break;
    }

    const uint64_t position = (uint64_t)(candidate - region);
    const uint16_t record_id = biff_read_le16(candidate);
    const uint16_t record_length = biff_read_le16(candidate + 2);

    if (biff_bof_id(record_id) && record_length >= 4
        && record_length <= biff_max_record_size(record_id)
        && position + BIFF_RECORD_HEADER_SIZE + record_length <= remaining
        && biff_document_type(biff_read_le16(candidate + 6))) {
      *matchpos = (char *)candidate;
      return NULL;
    }
    searched = position + 1;
  }

  return NULL;
}

// Continue parsing at summary->resume_offset. The summary records parser state
// immediately before the incomplete or damaged record, so fragmented trials do
// not have to rescan a large verified prefix.
//
static inline BiffParseResult biff_parse_records(const uint8_t *data,
                                                 uint64_t length,
                                                 BiffParseSummary *summary) {

  if (!data || !summary || summary->resume_offset > length) {
    return BIFF_PARSE_INVALID;
  }

  uint64_t offset = summary->resume_offset;

  while (offset < length) {
    summary->resume_offset = offset;
    summary->pending_record_end = 0;
    summary->pending_record_id = 0;
    summary->pending_header_complete = false;
    summary->pending_header_known = false;

    if (length - offset < BIFF_RECORD_HEADER_SIZE) {
      return summary->record_count > 0 ? BIFF_PARSE_TRUNCATED
                                       : BIFF_PARSE_INVALID;
    }

    const uint16_t record_id = biff_read_le16(data + offset);
    const uint16_t record_length = biff_read_le16(data + offset + 2);
    const bool known_record = biff_known_record_id(record_id);
    const bool continuation_record = summary->continuation_active
                                     && (offset > summary->continuation_origin
                                         || (offset
                                                 == summary->continuation_origin
                                             && !summary
                                                     ->continuation_skip_origin_record));

    summary->pending_record_id = record_id;
    summary->pending_header_complete = true;
    summary->pending_header_known = known_record;
    if (record_length > biff_max_record_size(summary->bof_id)
        || !biff_record_length_plausible(record_id, record_length)
        || !biff_record_version_compatible(summary->bof_id, record_id)) {
      return summary->record_count > 0 ? BIFF_PARSE_DAMAGED
                                       : BIFF_PARSE_INVALID;
    }

    if (continuation_record
        && summary->first_continuation_header_end == 0) {
      summary->first_continuation_header_end = offset
                                               + BIFF_RECORD_HEADER_SIZE;
      summary->first_continuation_record_id = record_id;
      summary->first_continuation_header_known = known_record;
    }
    if (known_record) {
      summary->recognized_header_count++;
      if (offset + BIFF_RECORD_HEADER_SIZE > summary->known_header_end) {
        summary->known_header_end = offset + BIFF_RECORD_HEADER_SIZE;
      }
    }
    else {
      summary->unknown_header_count++;
    }

    const uint64_t record_end = offset + BIFF_RECORD_HEADER_SIZE
                                + record_length;

    summary->pending_record_end = record_end;
    if (record_end > length) {
      return summary->record_count > 0 ? BIFF_PARSE_TRUNCATED
                                       : BIFF_PARSE_INVALID;
    }
    if (summary->record_count == 0 && record_id != summary->bof_id) {
      return BIFF_PARSE_INVALID;
    }
    if (record_id == BIFF_RECORD_INDEX2
        || record_id == BIFF_RECORD_INDEX3_8) {
      biff_update_index_bounds(data + offset + BIFF_RECORD_HEADER_SIZE,
                               record_length, summary->bof_id, summary);
      summary->index_record_offset = offset;
      summary->saw_index_record = true;
    }
    if (summary->saw_index_record && summary->required_stream_end != 0
        && summary->required_stream_end <= length
        && !biff_index_targets_valid(data, length, summary)) {
      summary->invalid_index_target = true;
      return BIFF_PARSE_DAMAGED;
    }

    const uint8_t *record_data = data + offset + BIFF_RECORD_HEADER_SIZE;

    if ((record_id == UINT16_C(0x0000)
         || record_id == UINT16_C(0x0200))) {
      if (record_length >= 14) {
        summary->dimension_last_row = biff_read_le32(record_data + 4);
        summary->saw_dimension = true;
      }
      else if (record_length >= 8) {
        summary->dimension_last_row = biff_read_le16(record_data + 2);
        summary->saw_dimension = true;
      }
    }

    uint32_t cell_row = 0;
    uint16_t first_cell_column = 0;
    uint16_t last_cell_column = 0;

    if (biff_cell_range(record_id, record_data, record_length, &cell_row,
                        &first_cell_column, &last_cell_column)) {
      if (continuation_record
          && !summary->first_continuation_cell_seen) {
        summary->first_continuation_cell_row = cell_row;
        summary->first_continuation_cell_column = first_cell_column;
        summary->first_continuation_cell_seen = true;
      }
      summary->last_cell_row = cell_row;
      summary->last_cell_column = last_cell_column;
      summary->saw_cell_record = true;
    }

    if (summary->record_count == 0) {
      summary->same_record_streak = 1;
      summary->alternating_record_streak = 1;
    }
    else {
      if (record_id == summary->last_complete_record_id) {
        if (summary->same_record_streak < UINT32_MAX) {
          summary->same_record_streak++;
        }
      }
      else {
        summary->same_record_streak = 1;
      }

      if (summary->record_count >= 2
          && record_id == summary->previous_complete_record_id
          && record_id != summary->last_complete_record_id) {
        if (summary->alternating_record_streak < UINT32_MAX) {
          summary->alternating_record_streak++;
        }
      }
      else if (record_id != summary->last_complete_record_id) {
        summary->alternating_record_streak = 2;
      }
      else {
        summary->alternating_record_streak = 1;
      }
    }
    summary->previous_complete_record_id =
        summary->last_complete_record_id;
    summary->last_complete_record_id = record_id;
    summary->record_count++;
    summary->verified_end = record_end;
    if (continuation_record
        && summary->first_continuation_record_end == 0) {
      summary->first_continuation_record_end = record_end;
    }
    summary->resume_offset = record_end;
    summary->pending_record_end = 0;
    summary->pending_header_complete = false;
    offset = record_end;

    if (record_id == BIFF_RECORD_EOF) {
      if (record_length != 0 || summary->record_count < 2) {
        return BIFF_PARSE_DAMAGED;
      }
      if (!summary->workbook_stream) {
        if (summary->required_stream_end > record_end) {
          summary->premature_eof = true;
          return BIFF_PARSE_DAMAGED;
        }
        if (!biff_index_targets_valid(data, record_end, summary)) {
          summary->invalid_index_target = true;
          return BIFF_PARSE_DAMAGED;
        }
        return BIFF_PARSE_COMPLETE;
      }
      if (summary->current_document_type != BIFF_TYPE_WORKBOOK) {
        summary->saw_content_substream = true;
      }
      if (offset == length) {
        if (summary->saw_content_substream
            && summary->required_stream_end > record_end) {
          summary->premature_eof = true;
          return BIFF_PARSE_DAMAGED;
        }
        if (summary->saw_content_substream
            && !biff_index_targets_valid(data, record_end, summary)) {
          summary->invalid_index_target = true;
          return BIFF_PARSE_DAMAGED;
        }
        return summary->saw_content_substream ? BIFF_PARSE_COMPLETE
                                              : BIFF_PARSE_TRUNCATED;
      }
      if (length - offset < 8) {
        return BIFF_PARSE_TRUNCATED;
      }

      const uint16_t next_bof_id = biff_read_le16(data + offset);
      const uint16_t next_bof_length = biff_read_le16(data + offset + 2);
      const uint16_t next_document_type = biff_read_le16(data + offset + 6);

      if (!biff_bof_id(next_bof_id) || next_bof_length < 4
          || next_bof_length > biff_max_record_size(next_bof_id)
          || !biff_document_type(next_document_type)
          || next_document_type == BIFF_TYPE_WORKBOOK) {
        return summary->saw_content_substream ? BIFF_PARSE_COMPLETE
                                              : BIFF_PARSE_DAMAGED;
      }
      if (BIFF_RECORD_HEADER_SIZE + next_bof_length > length - offset) {
        return BIFF_PARSE_TRUNCATED;
      }
      summary->current_document_type = next_document_type;
      summary->dimension_last_row = 0;
      summary->last_cell_row = 0;
      summary->last_cell_column = 0;
      summary->saw_dimension = false;
      summary->saw_cell_record = false;
    }
  }

  summary->resume_offset = offset;
  summary->pending_record_end = 0;
  summary->pending_header_complete = false;
  return BIFF_PARSE_TRUNCATED;
}

// Reparse the incomplete record in a trial mapping without counting its header
// twice. State for every complete preceding record remains intact.
//
static inline BiffParseResult biff_parse_continue(
    const uint8_t *data, uint64_t length, BiffParseSummary *summary) {

  if (!summary) {
    return BIFF_PARSE_INVALID;
  }
  const bool pending_header_complete = summary->pending_header_complete;

  if (pending_header_complete) {
    if (summary->pending_header_known
        && summary->recognized_header_count > 0) {
      summary->recognized_header_count--;
    }
    else if (!summary->pending_header_known
             && summary->unknown_header_count > 0) {
      summary->unknown_header_count--;
    }
  }
  summary->pending_record_end = 0;
  summary->pending_record_id = 0;
  summary->pending_header_complete = false;
  summary->pending_header_known = false;
  summary->continuation_origin = summary->resume_offset;
  summary->first_continuation_header_end = 0;
  summary->first_continuation_record_end = 0;
  summary->first_continuation_record_id = 0;
  summary->first_continuation_header_known = false;
  summary->first_continuation_cell_row = 0;
  summary->first_continuation_cell_column = 0;
  summary->first_continuation_cell_seen = false;
  summary->continuation_active = true;
  summary->continuation_skip_origin_record = pending_header_complete;
  return biff_parse_records(data, length, summary);
}

// Parse one raw BIFF substream. CFBF-hosted Workbook streams are handled by
// cfbf.h; this path is for older files whose BIFF record stream begins at byte
// zero. A workbook-global BOF remains partial because additional sheet
// substreams may follow its first EOF record.
//
static inline BiffParseResult biff_parse(const uint8_t *data,
                                         uint64_t length,
                                         BiffParseSummary *summary) {

  if (!summary) {
    return BIFF_PARSE_INVALID;
  }
  memset(summary, 0, sizeof(*summary));

  if (!data || length < BIFF_MINIMUM_SIZE) {
    return BIFF_PARSE_INVALID;
  }

  const uint16_t bof_id = biff_read_le16(data);
  const uint16_t bof_length = biff_read_le16(data + 2);

  if (!biff_bof_id(bof_id) || bof_length < 4
      || bof_length > biff_max_record_size(bof_id)
      || BIFF_RECORD_HEADER_SIZE + bof_length > length) {
    return BIFF_PARSE_INVALID;
  }

  const uint16_t document_type = biff_read_le16(data + 6);

  if (!biff_document_type(document_type)) {
    return BIFF_PARSE_INVALID;
  }

  summary->bof_id = bof_id;
  summary->document_type = document_type;
  summary->current_document_type = document_type;
  summary->workbook_stream = document_type == BIFF_TYPE_WORKBOOK;
  summary->saw_content_substream = !summary->workbook_stream;
  return biff_parse_records(data, length, summary);
}

static inline void biff_file_validate(char *data, uint64_t length,
                                      bool *validates,
                                      uint64_t *validates_to,
                                      bool *promising,
                                      uint32_t needleidx,
                                      uint32_t blocksize,
                                      void *carvehashkey) {

  (void)needleidx;
  (void)blocksize;
  (void)carvehashkey;

  if (!validates || !validates_to || !promising) {
    return;
  }
  *validates = false;
  *validates_to = 0;
  *promising = false;

  BiffParseSummary summary;
  const BiffParseResult result = biff_parse((const uint8_t *)data,
                                            length, &summary);

  if (summary.verified_end > 0) {
    *validates_to = summary.verified_end - 1;
  }
  if (result == BIFF_PARSE_COMPLETE) {
    *validates = true;
  }
  else if (result == BIFF_PARSE_TRUNCATED) {
    *promising = true;
    if (length > 0) {
      *validates_to = length - 1;
    }
  }
  else if (result == BIFF_PARSE_DAMAGED) {
    *promising = summary.verified_end > 0;
  }
}

// Report whether every block in a candidate remains physically contiguous.
// BIFF record framing cannot prove the provenance of bytes inside opaque record
// payloads, so this distinction controls the final validation flavor.
//
static inline bool biff_candidate_is_contiguous(const CarveInfo *candidate) {

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

// Structurally complete noncontiguous BIFF streams remain PROMISING because
// record headers do not authenticate opaque payload bytes.
//
static inline void biff_candidate_validate(CarveInfo *candidate,
                                           bool *validates,
                                           uint64_t *validates_to,
                                           bool *promising) {

  (void)validates_to;

  if (!candidate || !validates || !promising || !*validates) {
    return;
  }
  if (!biff_candidate_is_contiguous(candidate)) {
    *validates = false;
    *promising = true;
  }
}

// Identify the committed prefix and available image view. A changed blockmap
// requires a fresh ranking; an unchanged checkpoint retains its scan frontier.
static inline XXH128_hash_t biff_search_view(CarveInfo *candidate) {
  return validator_search_view(candidate);
}


// Save before handing the candidate to checkpointing. Store physical positions,
// never the apparent block numbers that checkpoint compaction can change.
static inline void biff_save_search(CarveInfo *candidate, BiffSearchProgress *progress,
                                    const BiffTrialScore *best, const int64_t *best_mapping,
                                    const int64_t *trial_mapping) {
  if (!atomic_load_explicit(&REASS_RETURN_TO_IDLE, memory_order_acquire)) {
    return;
  }
  BiffCarveState saved = {.progress = *progress};
  saved.progress.magic = BIFF_SEARCH_STATE_MAGIC;
  saved.progress.best = *best;
  saved.progress.view = biff_search_view(candidate);
  const uint64_t best_count = best->found ? best->run_blocks : 0;
  const uint64_t run_count = progress->run_active ? progress->run_blocks : 0;
  if (best_count + run_count) {
    saved.best_actual = malloc((size_t)(best_count + run_count) * sizeof(*saved.best_actual));
    check_memory_allocation(saved.best_actual, __LINE__, __FILE__, "BIFF checkpoint mapping");
    for (uint64_t i = 0; i < best_count; i++) {
      saved.best_actual[i] = filemirror_actual_blocknumber(scalpel_state.filemirror, best_mapping[i]);
    }
    for (uint64_t i = 0; i < run_count; i++) {
      saved.best_actual[best_count + i] = filemirror_actual_blocknumber(scalpel_state.filemirror, trial_mapping[i]);
    }
  }
  carve_put_state(candidate->carvehashkey, &saved);
  free(saved.best_actual);
}


static inline void biff_load_search(CarveInfo *candidate, BiffSearchProgress *progress,
                                    BiffTrialScore *best, int64_t *best_mapping,
                                    int64_t *trial_mapping) {
  BiffCarveState *saved = carve_get_state(candidate->carvehashkey);
  if (!saved) {
    return;
  }
  const BiffSearchProgress *p = &saved->progress;
  bool usable = p->magic == BIFF_SEARCH_STATE_MAGIC
      && p->prefix_blocks == progress->prefix_blocks && p->probe_blocks == progress->probe_blocks
      && XXH128_isEqual(p->view, biff_search_view(candidate));
  const uint64_t best_count = p->best.found ? p->best.run_blocks : 0;
  const uint64_t run_count = p->run_active ? p->run_blocks : 0;
  if (usable) {
    for (uint64_t i = 0; i < best_count + run_count; i++) {
      if (saved->best_actual[i] < 0
          || (uint64_t)saved->best_actual[i] >= CEILDIV(filemirror_filesize(scalpel_state.filemirror),
                                                       scalpel_state.blocksize)) {
        usable = false;
        break;
      }
      int64_t apparent = filemirror_apparent_blocknumber(scalpel_state.filemirror, saved->best_actual[i]);
      if (apparent < 0
          || filemirror_actual_block_covered(scalpel_state.filemirror, saved->best_actual[i])
          || apparent_block_in_blockvector(candidate->b, apparent)) {
        usable = false;
        break;
      }
      if (i < best_count) {
        best_mapping[i] = apparent;
      }
      else {
        trial_mapping[i - best_count] = apparent;
      }
    }
  }
  if (usable) {
    *progress = *p;
    *best = p->best;
  }
  biff_free_carve_state((void **)&saved);
}


// Poll the two control paths that can return an active candidate to Scalpel's
// scheduler. Trials never alter the candidate, so either path is safe here.
//
static inline bool biff_reassembly_poll(ThreadWork *work,
                                        CarveInfo **candidate,
                                        uuid_string_t uuidp,
                                        uuid_string_t uuidc) {

  if (!candidate || !*candidate
      || reassembly_check_kill_queue(work, candidate, uuidp, uuidc)) {
    return true;
  }
  if (atomic_load_explicit(&REASS_RETURN_TO_IDLE, memory_order_acquire)
      && reassembly_time_to_checkpoint(work->id, *candidate, uuidp, uuidc)) {
    return true;
  }
  return false;
}

// Copy one actual image block into a zero-padded trial slot.
//
static inline bool biff_reassembly_copy_block(uint8_t *destination,
                                              int64_t actual) {

  if (!destination || actual < 0) {
    return false;
  }

  uint64_t available = 0;
  const char *source = filemirror_actual_block_data_pointer(
      scalpel_state.filemirror, actual, &available);

  if (!source) {
    return false;
  }
  if (available > scalpel_state.blocksize) {
    available = scalpel_state.blocksize;
  }
  memset(destination, 0, scalpel_state.blocksize);
  memcpy(destination, source, available);
  return true;
}

// Materialize blocks beginning at start_actual. Strict global trials stop at
// low-confidence boundaries, while the adjacent strict trial can skip likely
// gap filler to join consecutive local runs. The permissive pass retains every
// nonzero-confidence block.
//
static inline uint64_t biff_reassembly_collect_run(
    CarveInfo *candidate, int64_t start_actual, uint64_t maximum_blocks,
    uint8_t *trial_data, uint64_t destination_slot, int64_t *mapping,
    bool split_low_confidence, bool skip_low_confidence,
    BiffSearchProgress *progress, bool *interrupted) {

  if (!candidate || !candidate->b || start_actual < 0 || !trial_data
      || !mapping || scalpel_state.blocksize == 0) {
    return 0;
  }

  const uint64_t actual_blocks = CEILDIV(
      filemirror_filesize(scalpel_state.filemirror),
      (uint64_t)scalpel_state.blocksize);
  uint64_t collected = progress->run_active ? progress->run_blocks : 0;
  uint64_t next_actual = progress->run_active ? progress->run_next_actual : (uint64_t)start_actual;
  uint64_t inspected = 0;
  // Reconstruct only the already selected probe blocks, not the skipped image span.
  for (uint64_t i = 0; i < collected; i++) {
    if (!biff_reassembly_copy_block(
            trial_data + (destination_slot + i) * (uint64_t)scalpel_state.blocksize,
            filemirror_actual_blocknumber(scalpel_state.filemirror, mapping[i]))) {
      progress->run_active = false;
      return 0;
    }
  }

  while (collected < maximum_blocks
         && next_actual < actual_blocks) {
    const int64_t actual = (int64_t)next_actual;
    const BlockValidationDecision confidence = filemirror_get_blocktype(
        scalpel_state.filemirror, actual, candidate->needleidx);

    inspected++;
    if ((inspected & BIFF_REASSEMBLY_POLL_MASK) == 0
        && atomic_load_explicit(&REASS_RETURN_TO_IDLE,
                                memory_order_acquire)) {
      progress->run_active = true;
      progress->run_next_actual = next_actual;
      progress->run_blocks = collected;
      *interrupted = true;
      return 0;
    }
    next_actual++;
    if (confidence == BLOCK_CONFIDENCE_INVALID
        || filemirror_actual_block_covered(scalpel_state.filemirror, actual)) {
      if (skip_low_confidence) {
        continue;
      }
      break;
    }
    if (confidence <= BIFF_MODICO_LOW_CONFIDENCE) {
      if (skip_low_confidence) {
        continue;
      }
      if (split_low_confidence && collected > 0) {
        break;
      }
    }
    const int64_t apparent = filemirror_apparent_blocknumber(
        scalpel_state.filemirror, actual);

    if (apparent < 0) {
      break;
    }
    if (apparent_block_in_blockvector(candidate->b, apparent)) {
      if (skip_low_confidence) {
        continue;
      }
      break;
    }
    for (uint64_t prior = 0; prior < collected; prior++) {
      if (mapping[prior] == apparent) {
        progress->run_active = false;
        return collected;
      }
    }
    if (!biff_reassembly_copy_block(
            trial_data + (destination_slot + collected)
                         * (uint64_t)scalpel_state.blocksize,
            actual)) {
      break;
    }
    mapping[collected] = apparent;
    collected++;
  }
  progress->run_active = false;
  progress->run_blocks = 0;
  return collected;
}

// Compare two structurally plausible extensions. Completion and record
// recognition provide the strongest structural evidence. MoDiCo confidence,
// physical locality, and parser progress resolve remaining ties.
//
static inline bool biff_trial_score_better(const BiffTrialScore *trial,
                                           const BiffTrialScore *best) {

  if (!trial || !trial->found) {
    return false;
  }
  if (!best || !best->found) {
    return true;
  }
  if (trial->continuation_match != best->continuation_match) {
    return trial->continuation_match;
  }
  if (trial->cell_sequence_match != best->cell_sequence_match) {
    return trial->cell_sequence_match;
  }
  if (trial->cell_sequence_match
      && trial->cell_distance != best->cell_distance) {
    return trial->cell_distance < best->cell_distance;
  }
  if (trial->sequence_match != best->sequence_match) {
    return trial->sequence_match;
  }
  if (trial->complete != best->complete) {
    return trial->complete;
  }
  if (trial->adjacent != best->adjacent) {
    return trial->adjacent;
  }
  if (trial->reservation_sum != best->reservation_sum) {
    return trial->reservation_sum < best->reservation_sum;
  }
  if (trial->discontinuity != best->discontinuity) {
    return trial->discontinuity < best->discontinuity;
  }
  if (trial->first_header_known != best->first_header_known) {
    return trial->first_header_known;
  }
  if (trial->start_confidence != best->start_confidence) {
    return trial->start_confidence > best->start_confidence;
  }
  if (trial->physical_distance != best->physical_distance) {
    return trial->physical_distance < best->physical_distance;
  }
  if (trial->new_known_headers != best->new_known_headers) {
    return trial->new_known_headers > best->new_known_headers;
  }
  if (trial->new_records != best->new_records) {
    return trial->new_records > best->new_records;
  }
  if (trial->new_unknown_headers != best->new_unknown_headers) {
    return trial->new_unknown_headers < best->new_unknown_headers;
  }
  if (trial->clean != best->clean) {
    return trial->clean;
  }
  if (trial->verified_end != best->verified_end) {
    return trial->verified_end > best->verified_end;
  }
  const uint64_t trial_weighted = trial->confidence_sum * best->run_blocks;
  const uint64_t best_weighted = best->confidence_sum * trial->run_blocks;

  if (trial_weighted != best_weighted) {
    return trial_weighted > best_weighted;
  }
  if (trial->minimum_confidence != best->minimum_confidence) {
    return trial->minimum_confidence > best->minimum_confidence;
  }
  return trial->commit_blocks > best->commit_blocks;
}

// Score an explicit block mapping without modifying the live candidate. A
// trial must reach a new known record header, complete an additional record
// beyond the pending opaque record, or finish the stream before it can be
// retained.
//
static inline bool biff_reassembly_score_mapping(
    CarveInfo *candidate, const BiffParseSummary *current_summary,
    uint8_t *trial_data, int64_t *trial_mapping, uint64_t mapping_blocks,
    BiffTrialScore *score) {

  if (!candidate || !candidate->b || !current_summary || !trial_data
      || !trial_mapping || !score || mapping_blocks == 0) {
    return false;
  }

  const uint64_t current_blocks = blockvector_get_num_blocks(candidate->b);
  BiffParseSummary trial_summary = *current_summary;
  const uint64_t trial_length = (current_blocks + mapping_blocks)
                                * (uint64_t)scalpel_state.blocksize;
  const BiffParseResult result = biff_parse_continue(
      trial_data, trial_length, &trial_summary);

  if (trial_summary.premature_eof || trial_summary.invalid_index_target) {
    return false;
  }
  const uint64_t new_records = trial_summary.record_count
                                   > current_summary->record_count
                               ? trial_summary.record_count
                                     - current_summary->record_count
                               : 0;
  const uint64_t new_known = trial_summary.recognized_header_count
                                  > current_summary->recognized_header_count
                              ? trial_summary.recognized_header_count
                                    - current_summary->recognized_header_count
                              : 0;
  const uint64_t new_unknown = trial_summary.unknown_header_count
                                    > current_summary->unknown_header_count
                                ? trial_summary.unknown_header_count
                                      - current_summary->unknown_header_count
                                : 0;
  const uint64_t pending_records = current_summary->pending_header_complete
                                       ? 1 : 0;
  bool continuation_match = false;
  bool sequence_match = false;
  bool cell_sequence_match = false;
  uint64_t cell_distance = UINT64_MAX;

  if (current_summary->pending_header_complete
      && current_summary->pending_record_end
             >= current_summary->resume_offset + BIFF_RECORD_HEADER_SIZE) {
    const uint64_t pending_length = current_summary->pending_record_end
                                    - current_summary->resume_offset
                                    - BIFF_RECORD_HEADER_SIZE;

    continuation_match =
        pending_length == biff_max_record_size(current_summary->bof_id)
        && trial_summary.first_continuation_record_id == UINT16_C(0x003c);
  }

  if (current_summary->pending_header_complete
      && current_summary->same_record_streak >= 4
      && current_summary->pending_record_id
             == current_summary->last_complete_record_id) {
    sequence_match = trial_summary.first_continuation_record_id
                     == current_summary->last_complete_record_id;
  }
  if (current_summary->pending_header_complete && !sequence_match
      && current_summary->alternating_record_streak >= 4) {
    uint16_t expected_record_id =
        current_summary->previous_complete_record_id;

    if (current_summary->pending_header_complete
        && current_summary->pending_record_id
               == current_summary->previous_complete_record_id) {
      expected_record_id = current_summary->last_complete_record_id;
    }
    sequence_match = trial_summary.first_continuation_record_id
                     == expected_record_id;
  }

  if (current_summary->saw_dimension
      && current_summary->saw_cell_record
      && current_summary->dimension_last_row
             > current_summary->last_cell_row + 1
      && trial_summary.first_continuation_cell_seen
      && (trial_summary.first_continuation_cell_row
              > current_summary->last_cell_row
          || (trial_summary.first_continuation_cell_row
                  == current_summary->last_cell_row
              && trial_summary.first_continuation_cell_column
                     >= current_summary->last_cell_column))) {
    const uint64_t row_distance =
        trial_summary.first_continuation_cell_row
        - current_summary->last_cell_row;
    const uint64_t column_distance =
        row_distance == 0
            ? trial_summary.first_continuation_cell_column
                  - current_summary->last_cell_column
            : trial_summary.first_continuation_cell_column;

    cell_sequence_match = true;
    cell_distance = row_distance * (UINT64_C(1) << 16)
                    + column_distance;
  }

  if (result != BIFF_PARSE_COMPLETE && new_known == 0
      && new_records <= pending_records) {
    return false;
  }

  uint64_t evidence_end = trial_summary.first_continuation_header_end;

  if (evidence_end == 0) {
    evidence_end = trial_summary.first_continuation_record_end;
  }
  if (result == BIFF_PARSE_COMPLETE) {
    evidence_end = trial_summary.verified_end;
  }
  uint64_t commit_blocks = CEILDIV(
      evidence_end, (uint64_t)scalpel_state.blocksize);

  if (continuation_match && result != BIFF_PARSE_COMPLETE) {
    commit_blocks = current_blocks + mapping_blocks;
  }

  if (commit_blocks > current_blocks + mapping_blocks) {
    commit_blocks = current_blocks + mapping_blocks;
  }
  if (commit_blocks <= current_blocks) {
    return false;
  }

  const uint64_t committed_length = commit_blocks
                                    * (uint64_t)scalpel_state.blocksize;
  BiffParseSummary committed_summary;
  const BiffParseResult committed_result = biff_parse(
      trial_data, committed_length, &committed_summary);

  if (committed_result == BIFF_PARSE_INVALID
      || committed_result == BIFF_PARSE_DAMAGED
      || committed_summary.verified_end < current_summary->verified_end
      || (result == BIFF_PARSE_COMPLETE
          && committed_result != BIFF_PARSE_COMPLETE)) {
    return false;
  }

  const uint64_t used_blocks = commit_blocks - current_blocks;
  BlockValidationDecision minimum_confidence = BLOCK_CONFIDENCE_VALID;
  uint64_t confidence_sum = 0;
  uint64_t reservation_sum = 0;
  uint64_t discontinuity = 0;
  const uint64_t blocks = blockvector_get_num_blocks(candidate->b);
  const int64_t previous_actual = blockvector_get_actual_blocknumber(
      candidate->b, blocks - 1);
  int64_t expected_mapping_actual = previous_actual + 1;

  for (uint64_t slot = 0; slot < used_blocks; slot++) {
    const int64_t actual = filemirror_actual_blocknumber(
        scalpel_state.filemirror, trial_mapping[slot]);
    const BlockValidationDecision confidence = filemirror_get_blocktype(
        scalpel_state.filemirror, actual, candidate->needleidx);

    if (confidence < minimum_confidence) {
      minimum_confidence = confidence;
    }
    confidence_sum += confidence;
    discontinuity += actual >= expected_mapping_actual
                         ? (uint64_t)(actual - expected_mapping_actual)
                         : (uint64_t)(expected_mapping_actual - actual);
    expected_mapping_actual = actual + 1;
    if (scalpel_state.reservations) {
      const int64_t reserved = filemirror_actual_block_reserved(
          scalpel_state.filemirror, actual);

      if (reserved > 0) {
        reservation_sum += (uint64_t)reserved;
      }
    }
  }

  const int64_t selected_start_actual = filemirror_actual_blocknumber(
      scalpel_state.filemirror, trial_mapping[0]);
  const int64_t expected_actual = previous_actual + 1;
  const uint64_t physical_distance = selected_start_actual >= expected_actual
                                         ? (uint64_t)(selected_start_actual
                                                      - expected_actual)
                                         : (uint64_t)(expected_actual
                                                      - selected_start_actual);

  memset(score, 0, sizeof(*score));
  score->found = true;
  score->complete = result == BIFF_PARSE_COMPLETE;
  score->clean = result != BIFF_PARSE_INVALID
                 && result != BIFF_PARSE_DAMAGED;
  score->adjacent = selected_start_actual == expected_actual;
  score->first_header_known = trial_summary.first_continuation_header_known;
  score->continuation_match = continuation_match;
  score->sequence_match = sequence_match;
  score->cell_sequence_match = cell_sequence_match;
  score->start_actual = selected_start_actual;
  score->commit_blocks = commit_blocks;
  score->verified_end = trial_summary.verified_end;
  score->new_records = new_records;
  score->new_known_headers = new_known;
  score->new_unknown_headers = new_unknown;
  score->confidence_sum = confidence_sum;
  score->reservation_sum = reservation_sum;
  score->physical_distance = physical_distance;
  score->discontinuity = discontinuity;
  score->cell_distance = cell_distance;
  score->run_blocks = used_blocks;
  score->start_confidence = filemirror_get_blocktype(
      scalpel_state.filemirror, selected_start_actual, candidate->needleidx);
  score->minimum_confidence = minimum_confidence;
  return true;
}

// Evaluate one physical run without modifying the live candidate.
//
static inline bool biff_reassembly_evaluate_run(
    CarveInfo *candidate, const BiffParseSummary *current_summary,
    int64_t start_actual, uint64_t maximum_blocks, uint8_t *trial_data,
    int64_t *trial_mapping, BiffTrialScore *score,
    bool split_low_confidence, bool skip_low_confidence,
    BiffSearchProgress *progress, bool *interrupted) {

  if (!candidate || !candidate->b || !current_summary || !trial_data
      || !trial_mapping || !score || maximum_blocks == 0) {
    return false;
  }

  const uint64_t current_blocks = blockvector_get_num_blocks(candidate->b);
  const uint64_t run_blocks = biff_reassembly_collect_run(
      candidate, start_actual, maximum_blocks, trial_data, current_blocks,
      trial_mapping, split_low_confidence, skip_low_confidence, progress, interrupted);

  if (run_blocks == 0) {
    return false;
  }
  return biff_reassembly_score_mapping(candidate, current_summary, trial_data,
                                       trial_mapping, run_blocks, score);
}

// Bridge an opaque maximum-sized record using the exact logical position of
// its CONTINUE header. The bytes before that header may span two physical runs,
// so test every split between the run following the current block and the run
// ending at the anchored header block. Only mappings that reproduce the header
// and parse cleanly are eligible.
//
static inline bool biff_reassembly_find_continuation_bridge(
    ThreadWork *work, CarveInfo **candidate,
    const BiffParseSummary *current_summary, uint8_t *trial_data,
    int64_t *trial_mapping, uint64_t maximum_blocks,
    BiffTrialScore *best, int64_t *best_mapping, BiffSearchProgress *progress, bool *interrupted,
    uuid_string_t uuidp, uuid_string_t uuidc) {

  if (!work || !candidate || !*candidate || !(*candidate)->b
      || !current_summary || !trial_data || !trial_mapping || !best
      || !best_mapping || !progress || !interrupted || scalpel_state.blocksize == 0
      || !current_summary->pending_header_complete
      || current_summary->pending_record_end
             < current_summary->resume_offset + BIFF_RECORD_HEADER_SIZE) {
    return false;
  }

  const uint64_t pending_length = current_summary->pending_record_end
                                  - current_summary->resume_offset
                                  - BIFF_RECORD_HEADER_SIZE;

  if (pending_length != biff_max_record_size(current_summary->bof_id)) {
    return false;
  }

  const uint64_t current_blocks = blockvector_get_num_blocks((*candidate)->b);
  const uint64_t target_slot = current_summary->pending_record_end
                               / (uint64_t)scalpel_state.blocksize;
  const uint64_t target_offset = current_summary->pending_record_end
                                 % (uint64_t)scalpel_state.blocksize;

  if (target_slot < current_blocks
      || target_offset + BIFF_RECORD_HEADER_SIZE > scalpel_state.blocksize) {
    return false;
  }

  const uint64_t bridge_blocks = target_slot + 1 - current_blocks;

  if (bridge_blocks == 0 || bridge_blocks > maximum_blocks) {
    return false;
  }

  const int64_t previous_actual = blockvector_get_actual_blocknumber(
      (*candidate)->b, current_blocks - 1);
  const uint64_t actual_blocks = CEILDIV(
      filemirror_filesize(scalpel_state.filemirror),
      (uint64_t)scalpel_state.blocksize);
  uint64_t examined = 0;

  for (uint64_t target_actual_u = progress->next_actual; target_actual_u < actual_blocks;
       target_actual_u++) {
    const int64_t target_actual = (int64_t)target_actual_u;
    uint64_t available = 0;
    const uint8_t *target_data = (const uint8_t *)
        filemirror_actual_block_data_pointer(scalpel_state.filemirror,
                                             target_actual, &available);

    examined++;
    if ((examined & BIFF_REASSEMBLY_POLL_MASK) == 0) {
      progress->next_actual = target_actual_u;
      biff_save_search(*candidate, progress, best, best_mapping, trial_mapping);
      if (biff_reassembly_poll(work, candidate, uuidp, uuidc)) {
        *interrupted = true;
        return false;
      }
    }
    if (!target_data || target_offset + BIFF_RECORD_HEADER_SIZE > available
        || biff_read_le16(target_data + target_offset) != UINT16_C(0x003c)
        || biff_read_le16(target_data + target_offset + 2)
               > biff_max_record_size(current_summary->bof_id)) {
      continue;
    }

    for (uint64_t prefix_blocks = 0; prefix_blocks <= bridge_blocks;
         prefix_blocks++) {
      const uint64_t suffix_blocks = bridge_blocks - prefix_blocks;
      int64_t suffix_start = 0;

      if (suffix_blocks == 0) {
        if (target_actual != previous_actual + (int64_t)bridge_blocks) {
          continue;
        }
      }
      else {
        if (target_actual_u + 1 < suffix_blocks) {
          continue;
        }
        suffix_start = target_actual - (int64_t)suffix_blocks + 1;
      }

      bool mapping_valid = true;

      for (uint64_t slot = 0; slot < bridge_blocks; slot++) {
        const int64_t actual = slot < prefix_blocks
                                   ? previous_actual + 1 + (int64_t)slot
                                   : suffix_start
                                         + (int64_t)(slot - prefix_blocks);

        if (actual < 0 || (uint64_t)actual >= actual_blocks
            || filemirror_actual_block_covered(scalpel_state.filemirror,
                                               actual)
            || filemirror_get_blocktype(scalpel_state.filemirror, actual,
                                        (*candidate)->needleidx)
                   == BLOCK_CONFIDENCE_INVALID) {
          mapping_valid = false;
          break;
        }

        const int64_t apparent = filemirror_apparent_blocknumber(
            scalpel_state.filemirror, actual);

        if (apparent < 0
            || apparent_block_in_blockvector((*candidate)->b, apparent)) {
          mapping_valid = false;
          break;
        }
        for (uint64_t prior = 0; prior < slot; prior++) {
          if (trial_mapping[prior] == apparent) {
            mapping_valid = false;
            break;
          }
        }
        if (!mapping_valid
            || !biff_reassembly_copy_block(
                trial_data
                    + (current_blocks + slot)
                          * (uint64_t)scalpel_state.blocksize,
                actual)) {
          mapping_valid = false;
          break;
        }
        trial_mapping[slot] = apparent;
      }

      BiffTrialScore trial;

      if (mapping_valid
          && biff_reassembly_score_mapping(
              *candidate, current_summary, trial_data, trial_mapping,
              bridge_blocks, &trial)
          && trial.continuation_match
          && biff_trial_score_better(&trial, best)) {
        *best = trial;
        memcpy(best_mapping, trial_mapping,
               trial.run_blocks * sizeof(*best_mapping));
      }
    }
  }
  return best->found;
}

// Reassemble a raw BIFF stream as a sequence of physically contiguous runs.
// Each search probes far enough to cross the current opaque record and observe
// an independent record boundary. Only the retained best run modifies the live
// blockvector, preventing generic work sharing from multiplying ambiguous
// candidates and output artifacts.
//
static inline void biff_reassembly(ThreadWork *work,
                                   CarveInfo **candidate,
                                   uuid_string_t uuidp,
                                   uuid_string_t uuidc) {

  if (!work || !candidate || !*candidate || !(*candidate)->b
      || scalpel_state.blocksize == 0) {
    if (candidate && *candidate) {
      destroy_candidate(candidate);
    }
    return;
  }

  (*candidate)->chopped = false;

  while (*candidate) {
    BlockVector *blockvector = (*candidate)->b;
    uint64_t blocks = blockvector_get_num_blocks(blockvector);

    if (blocks == 0
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

    blockvector_set_data_length(
        blockvector, blocks * (uint64_t)scalpel_state.blocksize);
    inflate_blockvector(blockvector);
    const uint8_t *current_data = (const uint8_t *)
        blockvector_get_data_pointer(blockvector);
    BiffParseSummary current_summary;
    const BiffParseResult current_result = biff_parse(
        current_data, blockvector_get_data_length(blockvector),
        &current_summary);

    if (current_result == BIFF_PARSE_COMPLETE) {
      blockvector_set_data_length(blockvector, current_summary.verified_end);
      resize_blockvector(blockvector,
                         CEILDIV(current_summary.verified_end,
                                 (uint64_t)scalpel_state.blocksize));
      if (biff_candidate_is_contiguous(*candidate)) {
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

    if (current_summary.pending_header_complete
        && current_summary.pending_record_end
               >= current_summary.resume_offset + BIFF_RECORD_HEADER_SIZE) {
      const uint64_t pending_length = current_summary.pending_record_end
                                      - current_summary.resume_offset
                                      - BIFF_RECORD_HEADER_SIZE;
      const uint64_t bridge_base_blocks =
          current_summary.resume_offset
              / (uint64_t)scalpel_state.blocksize
          + 1;

      // Reconsider every opaque payload block after the record header when a
      // maximum-sized record crosses a fragmented boundary. Its CONTINUE
      // header supplies the independent anchor used by the bridge search.
      //
      if (pending_length == biff_max_record_size(current_summary.bof_id)
          && bridge_base_blocks < blocks
          && current_summary.pending_record_end
                     / (uint64_t)scalpel_state.blocksize
                 >= blocks) {
        resize_blockvector(blockvector, bridge_base_blocks);
        blockvector_set_data_length(
            blockvector,
            bridge_base_blocks * (uint64_t)scalpel_state.blocksize);
        inflate_blockvector(blockvector);
        continue;
      }
    }

    if (current_result == BIFF_PARSE_INVALID
        || current_result == BIFF_PARSE_DAMAGED) {
      const uint64_t bad_slot = current_summary.resume_offset
                                / (uint64_t)scalpel_state.blocksize;

      if (current_summary.record_count == 0 || bad_slot == 0
          || bad_slot >= blocks) {
        break;
      }
      resize_blockvector(blockvector, bad_slot);
      blockvector_set_data_length(
          blockvector, bad_slot * (uint64_t)scalpel_state.blocksize);
      inflate_blockvector(blockvector);
      continue;
    }

    if (reassembly_check_max_size(work->id, *candidate, uuidp, uuidc)) {
      break;
    }

    uint64_t target_length = current_summary.pending_record_end;

    if (target_length <= blockvector_get_data_length(blockvector)) {
      target_length = current_summary.resume_offset
                      + BIFF_RECORD_HEADER_SIZE
                      + BIFF_REASSEMBLY_LOOKAHEAD_RECORD_SIZE;
    }
    const uint64_t lookahead = BIFF_RECORD_HEADER_SIZE
                               + BIFF_REASSEMBLY_LOOKAHEAD_RECORD_SIZE
                               + BIFF_RECORD_HEADER_SIZE;

    if (UINT64_MAX - target_length < lookahead) {
      break;
    }
    target_length += lookahead;

    uint64_t target_blocks = CEILDIV(
        target_length, (uint64_t)scalpel_state.blocksize);
    const uint64_t maximum_file_blocks = CEILDIV(
        scalpel_state.search_specs[(*candidate)->needleidx].MAXIMUMSIZE,
        (uint64_t)scalpel_state.blocksize);

    if (target_blocks > maximum_file_blocks) {
      target_blocks = maximum_file_blocks;
    }
    if (target_blocks <= blocks) {
      if (blocks == maximum_file_blocks) {
        break;
      }
      target_blocks = blocks + 1;
    }

    const uint64_t probe_blocks = target_blocks - blocks;

    if (target_blocks > SIZE_MAX / scalpel_state.blocksize
        || probe_blocks > SIZE_MAX / sizeof(int64_t)) {
      break;
    }

    uint8_t *trial_data = (uint8_t *)malloc(
        (size_t)(target_blocks * (uint64_t)scalpel_state.blocksize));
    int64_t *trial_mapping = (int64_t *)malloc(
        (size_t)probe_blocks * sizeof(*trial_mapping));
    int64_t *best_mapping = (int64_t *)malloc(
        (size_t)probe_blocks * sizeof(*best_mapping));
    check_memory_allocation(trial_data, __LINE__, __FILE__,
                            "BIFF trial data");
    check_memory_allocation(trial_mapping, __LINE__, __FILE__,
                            "BIFF trial mapping");
    check_memory_allocation(best_mapping, __LINE__, __FILE__,
                            "BIFF best mapping");
    memcpy(trial_data, current_data,
           blocks * (uint64_t)scalpel_state.blocksize);

    BiffTrialScore best = {0};
    BiffSearchProgress progress = {.magic = BIFF_SEARCH_STATE_MAGIC,
                                   .prefix_blocks = blocks, .probe_blocks = probe_blocks};
    biff_load_search(*candidate, &progress, &best, best_mapping, trial_mapping);
    const int64_t previous_actual = blockvector_get_actual_blocknumber(
        blockvector, blocks - 1);
    const int64_t adjacent_actual = previous_actual + 1;
    BiffTrialScore trial;
    const uint32_t search_passes = scalpel_state.modico_enabled ? 2 : 1;
    bool bridge_interrupted = false;
    bool run_interrupted = false;

    if (progress.phase == 0) {
      biff_reassembly_find_continuation_bridge(
          work, candidate, &current_summary, trial_data, trial_mapping,
          probe_blocks, &best, best_mapping, &progress, &bridge_interrupted, uuidp, uuidc);
    }
    if (bridge_interrupted) {
      free(best_mapping);
      free(trial_mapping);
      free(trial_data);
      return;
    }
    const bool bridge_found = progress.phase == 0 && best.found;
    if (progress.phase == 0) {
      progress.phase = 1;
      progress.next_actual = 0;
    }

    for (uint32_t pass = progress.pass; !bridge_found && pass < search_passes; pass++) {
      progress.pass = pass;
      const bool split_low_confidence = scalpel_state.modico_enabled
                                        && pass == 0;

      if (!progress.pass_started) {
        memset(&best, 0, sizeof(best));
        progress.pass_started = true;
        progress.adjacent_stage = 0;
      }
      if (progress.adjacent_stage == 0) {
        if (biff_reassembly_evaluate_run(
              *candidate, &current_summary, adjacent_actual, probe_blocks,
              trial_data, trial_mapping, &trial, false, false, &progress, &run_interrupted)) {
          best = trial;
          memcpy(best_mapping, trial_mapping,
                 best.run_blocks * sizeof(*best_mapping));
        }
        if (run_interrupted) {
          goto checkpoint_search;
        }
        progress.adjacent_stage = 1;
      }

      if (progress.adjacent_stage == 1) {
        // MoDiCo confidence ranks gap alternatives, but it cannot veto the
        // physically adjacent block. If the direct probe does not finish the
        // stream, also test the local run reached by skipping likely filler.
        //
        if (split_low_confidence && (!best.found || !best.complete)
            && biff_reassembly_evaluate_run(
                *candidate, &current_summary, adjacent_actual, probe_blocks,
                trial_data, trial_mapping, &trial, true, true, &progress, &run_interrupted)
            && biff_trial_score_better(&trial, &best)) {
          best = trial;
          memcpy(best_mapping, trial_mapping,
                   best.run_blocks * sizeof(*best_mapping));
        }
        if (run_interrupted) {
          goto checkpoint_search;
        }
        progress.adjacent_stage = 2;
      }

      // A physically adjacent run that completes the stream is conclusive.
      // Otherwise inspect every available run and retain the strongest BIFF
      // continuation found in this pass.
      //
      if (progress.scan_started || !best.found || !best.complete) {
        progress.scan_started = true;
        const uint64_t apparent_blocks = filemirror_apparent_blocks(
            scalpel_state.filemirror);
        uint64_t examined = 0;

        for (uint64_t apparent = 0; apparent < apparent_blocks; apparent++) {
          const int64_t actual = filemirror_actual_blocknumber(
              scalpel_state.filemirror, (int64_t)apparent);

          if (actual < 0 || (uint64_t)actual < progress.next_actual) {
            continue;
          }
          if (actual == adjacent_actual) {
            continue;
          }
          progress.next_actual = (uint64_t)actual;
          if (biff_reassembly_evaluate_run(
                  *candidate, &current_summary, actual, probe_blocks,
                  trial_data, trial_mapping, &trial, split_low_confidence,
                  false, &progress, &run_interrupted)
              && biff_trial_score_better(&trial, &best)) {
            best = trial;
            memcpy(best_mapping, trial_mapping,
                   best.run_blocks * sizeof(*best_mapping));
          }
          if (run_interrupted) {
            goto checkpoint_search;
          }

          examined++;
          if ((examined & BIFF_REASSEMBLY_POLL_MASK) == 0) {
            progress.next_actual = (uint64_t)actual + 1;
            biff_save_search(*candidate, &progress, &best, best_mapping, trial_mapping);
            if (biff_reassembly_poll(work, candidate, uuidp, uuidc)) {
              free(best_mapping);
              free(trial_mapping);
              free(trial_data);
              return;
            }
          }
        }
      }
      if (best.found) {
        break;
      }
      progress.pass_started = false;
      progress.scan_started = false;
      progress.next_actual = 0;
    }

    if (!best.found || !*candidate) {
      free(best_mapping);
      free(trial_mapping);
      free(trial_data);
      break;
    }

    const uint64_t extension_blocks = best.commit_blocks - blocks;

    if (scalpel_state.mode_verbose) {
      lock_fprintf(
          stdout,
          "BIFF reassembly extension: header=%" PRId64
          " blocks=%" PRIu64 "->%" PRIu64 " source=%" PRId64
          " adjacent=%u complete=%u records=%" PRIu64
          " known=%" PRIu64 " unknown=%" PRIu64
          " distance=%" PRIu64 " confidence=%" PRIu64 "/%" PRIu64
          ".\n",
          blockvector_get_actual_blocknumber(blockvector, 0), blocks,
          best.commit_blocks, best.start_actual, best.adjacent, best.complete,
          best.new_records, best.new_known_headers,
          best.new_unknown_headers, best.physical_distance,
          best.confidence_sum, best.run_blocks);
    }

    resize_blockvector(blockvector, best.commit_blocks);
    for (uint64_t slot = 0; slot < extension_blocks; slot++) {
      blockvector_set_apparent_blocknumber(blockvector, blocks + slot,
                                           best_mapping[slot]);
    }
    inflate_blockvector(blockvector);
    blockvector_set_data_length(
        blockvector, best.complete ? best.verified_end
                                   : best.commit_blocks
                                         * (uint64_t)scalpel_state.blocksize);

    free(best_mapping);
    free(trial_mapping);
    free(trial_data);
    continue;

checkpoint_search:
    biff_save_search(*candidate, &progress, &best, best_mapping, trial_mapping);
    const bool yielded = biff_reassembly_poll(work, candidate, uuidp, uuidc);
    free(best_mapping);
    free(trial_mapping);
    free(trial_data);
    if (yielded) {
      return;
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

// Only progress and the retained physical mapping are persistent; trial bytes
// are reconstructed from the image after restart.
static inline bool biff_serialize_carve_state(void **state, FILE *fp, StateSerialization mode) {
  if (!state || !fp || (mode == SERIALIZE && !*state)) {
    return false;
  }
  if (mode == SERIALIZE) {
    const BiffCarveState *saved = *state;
    const uint64_t count = (saved->progress.best.found ? saved->progress.best.run_blocks : 0)
        + (saved->progress.run_active ? saved->progress.run_blocks : 0);
    return fwrite(&saved->progress, sizeof(saved->progress), 1, fp) == 1
        && (!count || fwrite(saved->best_actual, sizeof(*saved->best_actual), (size_t)count, fp) == count);
  }
  BiffCarveState *saved = calloc(1, sizeof(*saved));
  check_memory_allocation(saved, __LINE__, __FILE__, "BIFF restored search");
  BiffSearchProgress *p = &saved->progress;
  if (fread(p, sizeof(*p), 1, fp) != 1 || p->magic != BIFF_SEARCH_STATE_MAGIC
      || p->phase > 1 || p->pass > 1 || p->adjacent_stage > 2
      || !p->prefix_blocks || !p->probe_blocks
      || p->probe_blocks > SIZE_MAX / (2 * sizeof(*saved->best_actual))
      || p->run_blocks > p->probe_blocks
      || p->best.run_blocks > p->probe_blocks
      || (p->best.found && (!p->best.run_blocks || p->best.commit_blocks <= p->prefix_blocks
                           || p->best.commit_blocks - p->prefix_blocks > p->best.run_blocks))) {
    free(saved);
    return false;
  }
  const uint64_t count = (p->best.found ? p->best.run_blocks : 0)
      + (p->run_active ? p->run_blocks : 0);
  struct stat st;
  off_t offset = ftello(fp);
  if (count > SIZE_MAX / sizeof(*saved->best_actual)
      || (fstat(fileno(fp), &st) == 0 && S_ISREG(st.st_mode)
          && (offset < 0 || offset > st.st_size
              || count > (uint64_t)(st.st_size - offset) / sizeof(*saved->best_actual)))) {
    free(saved);
    return false;
  }
  if (count) {
    saved->best_actual = malloc((size_t)count * sizeof(*saved->best_actual));
    check_memory_allocation(saved->best_actual, __LINE__, __FILE__, "BIFF restored mapping");
    if (fread(saved->best_actual, sizeof(*saved->best_actual), (size_t)count, fp) != count) {
      biff_free_carve_state((void **)&saved);
      return false;
    }
    for (uint64_t i = 0; i < count; i++) {
      if (saved->best_actual[i] < 0) {
        biff_free_carve_state((void **)&saved);
        return false;
      }
    }
  }
  *state = saved;
  return true;
}


static inline void *biff_clone_carve_state(const void *state) {
  if (!state) {
    return NULL;
  }
  const BiffCarveState *saved = state;
  BiffCarveState *copy = malloc(sizeof(*copy));
  check_memory_allocation(copy, __LINE__, __FILE__, "BIFF search clone");
  *copy = *saved;
  copy->best_actual = NULL;
  const uint64_t count = (saved->progress.best.found ? saved->progress.best.run_blocks : 0)
      + (saved->progress.run_active ? saved->progress.run_blocks : 0);
  if (count) {
    size_t size = (size_t)count * sizeof(*copy->best_actual);
    copy->best_actual = malloc(size);
    check_memory_allocation(copy->best_actual, __LINE__, __FILE__, "BIFF mapping clone");
    memcpy(copy->best_actual, saved->best_actual, size);
  }
  return copy;
}


static inline void biff_free_carve_state(void **state) {
  if (state && *state) {
    BiffCarveState *saved = *state;
    free(saved->best_actual);
    free(saved);
    *state = NULL;
  }
}


static inline size_t biff_sizeof_carve_state(const void *state) {
  const BiffCarveState *saved = state;
  if (!saved) {
    return 0;
  }
  const uint64_t count = (saved->progress.best.found ? saved->progress.best.run_blocks : 0)
      + (saved->progress.run_active ? saved->progress.run_blocks : 0);
  return sizeof(*saved) + (size_t)count * sizeof(*saved->best_actual);
}


static inline void biff_print_carve_state(const void *state) {
  const BiffCarveState *saved = state;
  if (saved) {
    printf("BIFF search: phase=%u pass=%u next physical block=%" PRIu64 "\n",
           saved->progress.phase, saved->progress.pass, saved->progress.next_actual);
  }
}

#endif
