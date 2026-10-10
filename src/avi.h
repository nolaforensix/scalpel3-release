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

// Audio Video Interleave (AVI) validation and fragmented recovery.
//
// AVI is a RIFF container. The declared RIFF and chunk lengths provide an exact logical layout,
// while legacy idx1 and OpenDML indexes independently describe media chunk locations. The file
// validator checks both forms of index and validates self-describing MJPEG and PNG frame payloads.
// Fragmented recovery repairs the complete declared layout while codec-aware checks protect
// self-validating media payloads from structurally plausible but incorrect block arrangements.
//

#ifndef SCALPEL3_AVI_H
#define SCALPEL3_AVI_H

#include "scalpel.h"

#include <jpeglib.h>
#include <limits.h>
#include <setjmp.h>
#include <zlib.h>

#define AVI_FOURCC(a, b, c, d)                                                \
  ((uint32_t)(uint8_t)(a) | ((uint32_t)(uint8_t)(b) << 8)                     \
   | ((uint32_t)(uint8_t)(c) << 16) | ((uint32_t)(uint8_t)(d) << 24))

#define AVI_RIFF_HEADER_SIZE 12U
#define AVI_CHUNK_HEADER_SIZE 8U
#define AVI_MAIN_HEADER_SIZE 56U
#define AVI_STREAM_HEADER_SIZE 56U
#define AVI_BITMAP_HEADER_SIZE 40U
#define AVI_WAVE_FORMAT_SIZE 16U
#define AVI_INDEX_ENTRY_SIZE 16U
#define AVI_STANDARD_INDEX_HEADER_SIZE 24U
#define AVI_SUPER_INDEX_HEADER_SIZE 24U
#define AVI_MAX_STREAMS 100U
#define AVI_MAX_MOVI_LISTS 256U
#define AVI_MAX_RECURSION_DEPTH 16U
#define AVI_MAX_PNG_CHUNK_SIZE (256U * 1024U * 1024U)
#define AVI_MAX_ARCHIVE_SIZE UINT64_C(1099511627776)
#define AVI_PAYLOAD_CONFIDENCE_MAX 99
#define AVI_SOURCE_BOUNDARY_MAX_CONFIDENCE 2
#define AVI_CONTENT_HISTOGRAM_BINS 32U
#define AVI_CONTENT_CONTEXT_BLOCKS 6U
#define AVI_CONTENT_COARSE_SAMPLES 1024U
#define AVI_CONTENT_FINE_SAMPLES 16384U
#define AVI_CONTENT_FALLBACK_RUNS 64U
#define AVI_CONTENT_RATIO_NUMERATOR 3U
#define AVI_CONTENT_RATIO_DENOMINATOR 4U
#define AVI_CONTENT_BOUNDARY_NUMERATOR 4U
#define AVI_CONTENT_BOUNDARY_DENOMINATOR 3U
#define AVI_CARVE_STATE_MAGIC UINT32_C(0x41564953)
#define AVI_CARVE_STATE_VERSION 8U

#define AVI_FLAG_HAS_INDEX UINT32_C(0x00000010)
#define AVI_INDEX_OF_INDEXES 0U
#define AVI_INDEX_OF_CHUNKS 1U

typedef enum AviParseResult {
  AVI_PARSE_INVALID = 0,
  AVI_PARSE_PARTIAL = 1,
  AVI_PARSE_COMPLETE = 2
} AviParseResult;

typedef enum AviTrialResult {
  AVI_TRIAL_ERROR = 0,
  AVI_TRIAL_READY = 1,
  AVI_TRIAL_INTERRUPTED = 2
} AviTrialResult;

typedef enum AviRunSearchResult {
  AVI_RUN_SEARCH_NO_MATCH = 0,
  AVI_RUN_SEARCH_VALIDATED = 1,
  AVI_RUN_SEARCH_IMPROVED = 2,
  AVI_RUN_SEARCH_COMPLETE = 3,
  AVI_RUN_SEARCH_REPAIRED = 4,
  AVI_RUN_SEARCH_STOPPED = 5
} AviRunSearchResult;

typedef struct AviStream {
  uint32_t type;
  uint32_t handler;
  uint32_t compression;
  uint32_t scale;
  uint32_t rate;
  uint32_t length;
  uint32_t width;
  uint32_t height;
  uint16_t format_tag;
  uint16_t channels;
  uint16_t block_align;
  uint16_t bits_per_sample;
  uint64_t media_chunks;
  bool ffv1_crc;
  bool saw_header;
  bool saw_format;
} AviStream;

typedef struct AviLayout {
  AviStream streams[AVI_MAX_STREAMS];
  uint64_t movi_type_offsets[AVI_MAX_MOVI_LISTS];
  uint64_t failure_offset;
  uint64_t failure_media_offset;
  uint64_t failure_media_end;
  uint64_t described_extent;
  uint64_t required_extent;
  uint64_t indexed_extent;
  uint64_t media_chunks;
  uint64_t payloads_proven;
  uint64_t opaque_payloads;
  uint64_t super_index_entries;
  uint64_t super_index_entries_verified;
  uint64_t super_index_failure_offset;
  uint64_t index_entries;
  uint64_t index_entries_verified;
  uint64_t ffv1_crc_slices;
  uint64_t riff_segments;
  uint32_t main_flags;
  uint32_t main_streams;
  uint32_t stream_count;
  uint32_t movi_count;
  uint32_t super_indexes;
  uint32_t standard_indexes;
  bool header_valid;
  bool saw_hdrl;
  bool saw_main_header;
  bool saw_movi;
  bool saw_legacy_index;
  bool interrupted;
} AviLayout;

typedef struct AviParser {
  const uint8_t *data;
  uint64_t length;
  AviLayout *layout;
  uint64_t payload_validation_from;
  bool deep_payload_validation;
} AviParser;

typedef struct AviJpegError {
  struct jpeg_error_mgr manager;
  jmp_buf recovery;
  volatile uint64_t input_length;
  volatile uint64_t failure_offset;
} AviJpegError;

typedef struct AviStateIndexEntry {
  uint64_t offset;
  uint32_t id;
  uint32_t size;
} AviStateIndexEntry;

typedef struct AviBlockSearch {
  uint64_t view;
  uint64_t target_slot;
  uint64_t image_blocks;
  uint64_t next_actual;
  uint64_t baseline_to;
  uint64_t best_validates_to;
  uint64_t best_distance;
  int64_t best_actual;
  int64_t best_reserved;
  uint32_t best_confidence;
  uint32_t blocksize;
  uint32_t active;
  uint32_t reserved;
} AviBlockSearch;

typedef struct AviRunContentCandidate {
  uint64_t start;
  uint64_t cost;
} AviRunContentCandidate;

typedef struct AviClassifiedRunTrial {
  uint64_t start;
  uint64_t validates_to;
  uint64_t crc_slices;
  uint64_t confidence;
  uint64_t content_cost;
  uint64_t distance;
  int64_t reserved;
  uint32_t validates;
  uint32_t complete;
  uint32_t contiguous;
  uint32_t isolated;
} AviClassifiedRunTrial;

typedef struct AviClassifiedSearch {
  uint64_t view;
  uint64_t target_slot;
  uint64_t run_blocks;
  uint64_t image_blocks;
  uint64_t baseline_to;
  uint64_t next_actual;
  uint64_t lowest_content_cost;
  uint64_t second_content_cost;
  uint64_t lowest_content_start;
  uint64_t second_content_start;
  uint64_t lowest_content_confidence;
  int64_t lowest_content_reserved;
  AviClassifiedRunTrial best;
  AviRunContentCandidate fallback[AVI_CONTENT_FALLBACK_RUNS];
  uint32_t fallback_count;
  uint32_t fallback_next;
  uint32_t lowest_content_isolated;
  uint32_t blocksize;
  uint32_t allow_content_only;
  uint32_t require_complete;
  uint32_t owner;
  uint32_t active;
} AviClassifiedSearch;

typedef struct AviShiftSearch {
  uint64_t view;
  uint64_t target_slot;
  uint64_t image_blocks;
  uint64_t baseline_to;
  uint64_t repair_end;
  uint64_t next_entry;
  uint64_t next_shift;
  uint64_t best_shift;
  uint64_t best_validates_to;
  uint64_t classified_slot;
  uint32_t blocksize;
  uint32_t phase;
  uint32_t owner;
  uint32_t reserved;
} AviShiftSearch;

typedef struct AviDisplacedSearch {
  uint64_t view;
  uint64_t target_slot;
  uint64_t image_blocks;
  uint64_t baseline_to;
  uint64_t repair_end;
  uint64_t next_actual;
  uint64_t probe_blocks;
  uint64_t reconnects_to;
  uint64_t mapped;
  uint64_t proven_blocks;
  uint64_t previous_validates_to;
  int64_t best_start;
  uint64_t best_mapped;
  uint64_t best_validates_to;
  uint32_t blocksize;
  // Full probe, proven-prefix probe, incremental extension, commit, exhausted.
  uint32_t phase;
} AviDisplacedSearch;

typedef struct AviCarveState {
  uint32_t magic;
  uint32_t version;
  uint64_t archive_extent;
  uint64_t entry_count;
  uint64_t repairs;
  uint32_t initialized;
  uint32_t reserved;
  AviBlockSearch block_search;
  // Indexed-run comparisons retain the current extension and earlier best run.
  struct {
    uint64_t view;
    uint64_t target_slot;
    uint64_t image_blocks;
    uint64_t baseline_to;
    uint64_t next_actual;
    uint64_t mapped;
    uint64_t minimum_blocks;
    uint64_t previous_validates_to;
    int64_t best_start;
    uint64_t best_mapped;
    uint64_t best_validates_to;
    uint64_t classified_slot;
    uint32_t blocksize;
    uint32_t active;
  } indexed_search;
  // Separate cursors for complete-only and partial zero-gap passes.
  struct {
    uint64_t view;
    uint64_t start_slot;
    uint64_t next_slot;
    uint64_t image_blocks;
    uint64_t baseline_to;
    uint32_t blocksize;
    uint32_t active;
  } zero_gap_search[2];
  AviClassifiedSearch classified_search;
  AviShiftSearch shift_search;
  AviDisplacedSearch displaced_search;
  AviStateIndexEntry entries[];
} AviCarveState;

typedef struct AviContentHistogram {
  uint64_t bins[AVI_CONTENT_HISTOGRAM_BINS];
  uint64_t samples;
} AviContentHistogram;

static inline uint16_t avi_read_le16(const uint8_t *data);
static inline uint32_t avi_read_le32(const uint8_t *data);
static inline uint64_t avi_read_le64(const uint8_t *data);
static inline uint32_t avi_read_be32(const uint8_t *data);
static void avi_crc32_mpeg2_initialize(void);
static inline uint32_t avi_crc32_mpeg2(const uint8_t *data,
                                       uint64_t length);
static inline bool avi_ffv1_configuration_has_crc(const uint8_t *data,
                                                  uint64_t length);
static inline uint64_t avi_count_ffv1_crc_suffix_slices(
    const uint8_t *data, uint64_t length);
static inline bool avi_range_available(uint64_t length, uint64_t offset,
                                       uint64_t wanted);
static inline bool avi_chunk_id_printable(uint32_t id);
static inline int32_t avi_stream_number(uint32_t id);
static inline bool avi_is_media_chunk(uint32_t id);
static inline bool avi_media_chunk_ids_compatible(uint32_t expected,
                                                  uint32_t actual);
static inline bool avi_parser_stop_requested(AviParser *parser);
static inline bool avi_parser_fail(AviParser *parser, uint64_t offset);
static inline bool avi_trailing_padding(const uint8_t *data, uint64_t length,
                                        uint64_t offset);
static inline void avi_jpeg_error_exit(j_common_ptr decoder);
static inline void avi_jpeg_emit_message(j_common_ptr decoder,
                                         int message_level);
static inline bool avi_decode_jpeg_payload(const uint8_t *data,
                                           uint64_t length,
                                           uint32_t expected_width,
                                           uint32_t expected_height,
                                           uint64_t *failure_offset);
static inline bool avi_validate_jpeg_payload(const uint8_t *data,
                                             uint64_t length);
static inline bool avi_validate_jpeg_prefix(const uint8_t *data,
                                            uint64_t available,
                                            uint64_t declared,
                                            bool *complete,
                                            uint64_t *failure_offset);
static inline bool avi_validate_png_payload(const uint8_t *data,
                                            uint64_t length);
static inline bool avi_validate_png_prefix(const uint8_t *data,
                                           uint64_t available,
                                           uint64_t declared,
                                           bool *complete,
                                           uint64_t *failure_offset);
static inline bool avi_has_mpeg_start_code(const uint8_t *data,
                                           uint64_t length);
static inline bool avi_validate_mp3_payload(const uint8_t *data,
                                            uint64_t length);
static inline bool avi_chunk_matches(const uint8_t *data, uint64_t length,
                                     uint64_t offset, uint32_t id,
                                     uint32_t size);
static inline bool avi_index_entry_matches(const uint8_t *data,
                                           uint64_t length,
                                           uint64_t offset, uint32_t id,
                                           uint32_t size,
                                           uint64_t *matched_offset);
static inline bool avi_validate_idx1(AviParser *parser, uint64_t offset,
                                     uint32_t size);
static inline bool avi_validate_standard_index(AviParser *parser,
                                               uint32_t index_id,
                                               uint64_t offset,
                                               uint32_t size);
static inline bool avi_validate_super_index(AviParser *parser,
                                            uint64_t offset,
                                            uint32_t size);
static inline bool avi_carve_state_size(uint64_t entry_count,
                                        size_t *state_size);
static inline bool avi_carve_state_valid(const AviCarveState *state);
static inline AviCarveState *avi_capture_legacy_index(
    const uint8_t *data, uint64_t length, const AviLayout *layout);
static inline bool avi_validate_indexed_prefix(
    const uint8_t *data, uint64_t length, const AviCarveState *state,
    uint64_t *failure_offset);
static inline bool avi_serialize_carve_state(void **state, FILE *fp,
                                             StateSerialization mode);
static inline void *avi_clone_carve_state(const void *srcstate);
static inline void avi_free_carve_state(void **state);
static inline void avi_print_carve_state(const void *state);
static inline bool avi_parse_main_header(AviParser *parser, uint64_t offset,
                                         uint32_t size);
static inline bool avi_parse_stream_header(AviParser *parser,
                                           uint32_t stream_index,
                                           uint64_t offset, uint32_t size);
static inline bool avi_parse_stream_format(AviParser *parser,
                                           uint32_t stream_index,
                                           uint64_t offset, uint32_t size);
static inline bool avi_validate_media_payload(AviParser *parser, uint32_t id,
                                              uint64_t offset,
                                              uint32_t size);
static inline bool avi_validate_partial_media_payload(
    AviParser *parser, uint32_t id, uint64_t offset, uint64_t available,
    uint32_t size);
static inline bool avi_prepare_list(AviParser *parser, uint32_t list_type,
                                    uint64_t payload, int32_t stream_index,
                                    bool inside_movi, int32_t *child_stream,
                                    bool *child_movi);
static inline bool avi_parse_region(AviParser *parser, uint64_t start,
                                    uint64_t end, int32_t stream_index,
                                    bool inside_movi, uint32_t depth);
static inline bool avi_parse_segment(AviParser *parser, uint64_t offset,
                                     uint32_t expected_form,
                                     uint64_t *next_offset);
static inline bool avi_deep_validate_prefix(const uint8_t *data,
                                            uint64_t length,
                                            uint64_t payload_validation_from,
                                            AviLayout *layout);
static inline AviParseResult avi_parse_file(const uint8_t *data,
                                            uint64_t length,
                                            uint64_t payload_validation_from,
                                            AviLayout *layout);
static inline char *avi_header_discovery(char *base, uint64_t offset,
                                         uint64_t remaining, char **matchpos,
                                         uint32_t *matchlen,
                                         uint32_t blocksize);
static inline char *avi_footer_discovery(char *base, uint64_t offset,
                                         uint64_t remaining, char **matchpos,
                                         uint32_t *matchlen,
                                         uint32_t blocksize);
static inline uint32_t avi_block_validate(
    char *data, uint64_t length, BlockValidationDecision *decision,
    uint64_t *validates_to, uint32_t needleidx, uint32_t blocksize,
    void *blockhashkey);
static inline void avi_file_validate(char *data, uint64_t length,
                                     bool *validates, uint64_t *validates_to,
                                     bool *promising, uint32_t needleidx,
                                     uint32_t blocksize, void *carvehashkey);
static inline bool avi_reassembly_initialize_candidate(
    CarveInfo *candidate, AviCarveState *state);
static inline AviTrialResult avi_reassembly_validate_candidate(
    CarveInfo *candidate, const AviCarveState *state,
    bool *validates, uint64_t *validates_to, uint64_t *repair_from,
    uint64_t *repair_end, uint64_t payload_validation_from);
static inline bool avi_reassembly_checkpoint(
    ThreadWork *work, CarveInfo *candidate, AviCarveState *state,
    uuid_string_t uuidp, uuid_string_t uuidc);
static inline uint64_t avi_reassembly_block_search_view(
    const CarveInfo *candidate, const AviCarveState *state);
static inline bool avi_reassembly_block_search_current(
    const CarveInfo *candidate, const AviCarveState *state,
    uint64_t target_slot, uint64_t image_blocks, uint64_t validates_to);
static inline bool avi_reassembly_indexed_search_current(
    const CarveInfo *candidate, const AviCarveState *state,
    uint64_t target_slot, uint64_t image_blocks, uint64_t validates_to);
static inline bool avi_reassembly_zero_gap_search_current(
    const CarveInfo *candidate, const AviCarveState *state,
    uint64_t start_slot, uint64_t image_blocks, uint64_t validates_to,
    bool require_complete);
static inline bool avi_reassembly_classified_search_current(
    const CarveInfo *candidate, const AviCarveState *state,
    uint64_t image_blocks, uint64_t validates_to);
static inline bool avi_reassembly_shift_search_current(
    const CarveInfo *candidate, const AviCarveState *state,
    uint64_t image_blocks, uint64_t validates_to, uint64_t repair_end);
static inline bool avi_reassembly_shift_matches(
    const uint8_t *data, uint64_t length, const AviStateIndexEntry *entry,
    uint64_t shift);
static inline bool avi_reassembly_refresh_state(
    CarveInfo *candidate, AviCarveState **state);
static inline bool avi_reassembly_actual_block_suspect(
    const CarveInfo *candidate, int64_t actual);
static inline bool avi_reassembly_source_boundary(
    const CarveInfo *candidate, int64_t actual);
static inline uint64_t avi_reassembly_suspect_run(
    const CarveInfo *candidate, uint64_t target_slot);
static inline bool avi_reassembly_find_suspect_run(
    const CarveInfo *candidate, uint64_t start_slot,
    uint64_t *target_slot, uint64_t *run_blocks);
static inline uint64_t avi_reassembly_media_start_slot(
    const CarveInfo *candidate);
static inline void avi_content_histogram_add(
    AviContentHistogram *histogram, const uint8_t *data, uint64_t length,
    uint64_t sample_limit);
static inline uint64_t avi_content_histogram_cost(
    const AviContentHistogram *left, const AviContentHistogram *right);
static inline bool avi_reassembly_context_histogram(
    const CarveInfo *candidate, uint64_t target_slot, uint64_t run_blocks,
    uint64_t sample_limit, AviContentHistogram *histogram);
static inline bool avi_reassembly_source_histogram(
    uint64_t start, uint64_t run_blocks, uint64_t sample_limit,
    AviContentHistogram *histogram);
static inline bool avi_reassembly_source_run_isolated(
    uint64_t start, uint64_t run_blocks);
static inline bool avi_reassembly_content_boundary(
    const CarveInfo *candidate, int64_t actual,
    const AviContentHistogram *context_histogram, uint64_t source_cost);
static inline AviTrialResult avi_reassembly_trial_classified_run(
    CarveInfo *candidate, const AviCarveState *state, uint64_t target_slot,
    uint64_t run_blocks, uint64_t start, const int64_t *saved,
    const AviContentHistogram *context_histogram,
    AviClassifiedRunTrial *trial);
static inline bool avi_classified_run_trial_better(
    const AviClassifiedRunTrial *trial,
    const AviClassifiedRunTrial *best, bool allow_content_only,
    bool base_complete,
    uint64_t base_crc_slices, uint64_t current_validates_to);
static inline AviRunSearchResult avi_reassembly_find_classified_run(
    ThreadWork *work, CarveInfo **candidate, AviCarveState *state,
    uint64_t target_slot, uint64_t run_blocks, uint64_t image_blocks,
    uint64_t current_validates_to, bool allow_content_only,
    bool require_complete, uuid_string_t uuidp, uuid_string_t uuidc);
static inline int64_t avi_reassembly_find_actual_slot(
    BlockVector *blockvector, int64_t actual_block);
static inline int64_t avi_reassembly_find_apparent_slot(
    BlockVector *blockvector, int64_t apparent_block);
static inline bool avi_reassembly_rotate_suffix(
    CarveInfo *candidate, const AviCarveState *state,
    uint64_t target_slot, uint64_t shift, uint64_t image_blocks,
    uint64_t required_validates_to, bool retain_partial,
    bool *validates, uint64_t *validates_to);
static inline bool avi_reassembly_rotate_suffix_trial(
    CarveInfo *candidate, const AviCarveState *state,
    uint64_t target_slot, uint64_t shift, uint64_t image_blocks,
    uint64_t required_validates_to, bool retain_partial,
    bool *validates, uint64_t *validates_to, bool *interrupted);
static inline AviRunSearchResult avi_reassembly_find_zero_gap(
    ThreadWork *work, CarveInfo **candidate, AviCarveState *state,
    uint64_t start_slot, uint64_t image_blocks,
    uint64_t current_validates_to, bool require_complete,
    uint64_t *repair_slot, uuid_string_t uuidp, uuid_string_t uuidc);
static inline AviRunSearchResult avi_reassembly_find_shifted_suffix(
    ThreadWork *work, CarveInfo **candidate, AviCarveState *state,
    uint64_t target_slot, uint64_t image_blocks, uint64_t current_validates_to,
    uint64_t repair_end, uuid_string_t uuidp, uuid_string_t uuidc);
static inline bool avi_reassembly_source_matches_index(
    int64_t source_start, uint64_t target_slot, uint64_t image_blocks,
    const AviStateIndexEntry *entry, uint64_t *minimum_blocks);
static inline uint64_t avi_reassembly_failure_slot(
    const CarveInfo *candidate, const AviCarveState *state,
    uint64_t failure_offset);
static inline uint64_t avi_reassembly_earliest_repair_slot(
    const AviCarveState *state, uint64_t failure_offset,
    uint64_t target_slot);
static inline AviRunSearchResult avi_reassembly_find_indexed_run(
    ThreadWork *work, CarveInfo **candidate, AviCarveState *state,
    uint64_t target_slot, uint64_t image_blocks, uint64_t current_validates_to,
    uuid_string_t uuidp, uuid_string_t uuidc);
static inline AviRunSearchResult avi_reassembly_find_displaced_run(
    ThreadWork *work, CarveInfo **candidate, AviCarveState *state,
    uint64_t target_slot, uint64_t image_blocks, uint64_t current_validates_to,
    uint64_t repair_end, uuid_string_t uuidp, uuid_string_t uuidc);
static inline bool avi_reassembly_displaced_search_current(
    const CarveInfo *candidate, const AviCarveState *state,
    uint64_t image_blocks, uint64_t validates_to, uint64_t repair_end);
static inline void avi_reassembly(ThreadWork *work, CarveInfo **candidate,
                                  uuid_string_t uuidp,
                                  uuid_string_t uuidc);


static inline uint16_t avi_read_le16(const uint8_t *data) {

  return (uint16_t)data[0] | ((uint16_t)data[1] << 8);
}


static inline uint32_t avi_read_le32(const uint8_t *data) {

  return (uint32_t)data[0]
      | ((uint32_t)data[1] << 8)
      | ((uint32_t)data[2] << 16)
      | ((uint32_t)data[3] << 24);
}


static inline uint64_t avi_read_le64(const uint8_t *data) {

  return (uint64_t)avi_read_le32(data)
      | ((uint64_t)avi_read_le32(data + sizeof(uint32_t)) << 32);
}


static inline uint32_t avi_read_be32(const uint8_t *data) {

  return ((uint32_t)data[0] << 24)
      | ((uint32_t)data[1] << 16)
      | ((uint32_t)data[2] << 8)
      | (uint32_t)data[3];
}


static pthread_once_t avi_crc32_mpeg2_once = PTHREAD_ONCE_INIT;
static uint32_t avi_crc32_mpeg2_table[256];


static void avi_crc32_mpeg2_initialize(void) {

  for (uint32_t value = 0; value < 256; value++) {
    uint32_t crc = value << 24;

    for (uint32_t bit = 0; bit < 8; bit++) {
      crc = (crc << 1)
          ^ ((crc & UINT32_C(0x80000000)) != 0
              ? UINT32_C(0x04c11db7) : 0);
    }
    avi_crc32_mpeg2_table[value] = crc;
  }
}


static inline uint32_t avi_crc32_mpeg2(const uint8_t *data,
                                       uint64_t length) {

  if (!data) {
    return UINT32_MAX;
  }
  pthread_once(&avi_crc32_mpeg2_once, avi_crc32_mpeg2_initialize);
  uint32_t crc = 0;

  for (uint64_t position = 0; position < length; position++) {
    uint8_t index = (uint8_t)((crc >> 24) ^ data[position]);

    crc = (crc << 8) ^ avi_crc32_mpeg2_table[index];
  }
  return crc;
}


static inline bool avi_ffv1_configuration_has_crc(const uint8_t *data,
                                                  uint64_t length) {

  return data && length >= sizeof(uint32_t)
      && avi_crc32_mpeg2(data, length) == 0;
}


// FFV1 version 3 places an independently checkable CRC at the end of each slice. Walking from the
// frame tail does not require range decoding and retains useful evidence when an earlier slice was
// already damaged in the source file.
static inline uint64_t avi_count_ffv1_crc_suffix_slices(
    const uint8_t *data, uint64_t length) {

  uint64_t slices = 0;
  uint64_t end = length;

  while (data && end >= 8) {
    uint64_t footer = end - 8;
    uint64_t payload = ((uint64_t)data[footer] << 16)
        | ((uint64_t)data[footer + 1] << 8)
        | (uint64_t)data[footer + 2];

    if (payload == 0 || payload > footer || data[footer + 3] > 2) {
      break;
    }
    uint64_t start = footer - payload;

    if (avi_crc32_mpeg2(data + start, end - start) != 0) {
      break;
    }
    slices++;
    end = start;
  }
  return slices;
}


static inline bool avi_range_available(uint64_t length, uint64_t offset,
                                       uint64_t wanted) {

  return offset <= length && wanted <= length - offset;
}


static inline bool avi_chunk_id_printable(uint32_t id) {

  for (uint32_t shift = 0; shift < 32; shift += 8) {
    uint8_t value = (uint8_t)(id >> shift);

    if (value < 0x20 || value > 0x7e) {
      return false;
    }
  }
  return true;
}


static inline int32_t avi_stream_number(uint32_t id) {

  uint8_t high = (uint8_t)id;
  uint8_t low = (uint8_t)(id >> 8);

  if (high < '0' || high > '9' || low < '0' || low > '9') {
    return -1;
  }
  return (high - '0') * 10 + low - '0';
}


static inline bool avi_is_media_chunk(uint32_t id) {

  uint8_t third;
  uint8_t fourth;

  if (avi_stream_number(id) < 0) {
    return false;
  }
  third = (uint8_t)(id >> 16);
  fourth = (uint8_t)(id >> 24);
  return (third == 'd' && (fourth == 'b' || fourth == 'c'))
      || (third == 'w' && fourth == 'b')
      || (third == 'p' && fourth == 'c')
      || (third == 't' && fourth == 'x');
}


static inline bool avi_media_chunk_ids_compatible(uint32_t expected,
                                                  uint32_t actual) {

  if (expected == actual) {
    return true;
  }
  int32_t expected_stream = avi_stream_number(expected);
  int32_t actual_stream = avi_stream_number(actual);
  uint8_t expected_type = (uint8_t)(expected >> 16);
  uint8_t actual_type = (uint8_t)(actual >> 16);
  uint8_t expected_variant = (uint8_t)(expected >> 24);
  uint8_t actual_variant = (uint8_t)(actual >> 24);

  return expected_stream >= 0 && expected_stream == actual_stream
      && expected_type == 'd' && actual_type == 'd'
      && (expected_variant == 'b' || expected_variant == 'c')
      && (actual_variant == 'b' || actual_variant == 'c');
}


static inline bool avi_parser_stop_requested(AviParser *parser) {

  // The exit request precedes the point at which workers may safely yield.
  if (atomic_load_explicit(&REASS_RETURN_TO_IDLE, memory_order_acquire)) {
    parser->layout->interrupted = true;
    return true;
  }
  return false;
}


static inline bool avi_parser_fail(AviParser *parser, uint64_t offset) {

  parser->layout->failure_offset = offset;
  return false;
}


static inline bool avi_trailing_padding(const uint8_t *data, uint64_t length,
                                        uint64_t offset) {

  while (offset < length) {
    if (data[offset] != 0 && data[offset] != UINT8_C(0xff)) {
      return false;
    }
    offset++;
  }
  return true;
}


static inline void avi_jpeg_error_exit(j_common_ptr decoder) {

  AviJpegError *error = (AviJpegError *)decoder->err;

  if (decoder->is_decompressor) {
    j_decompress_ptr decompressor = (j_decompress_ptr)decoder;

    if (decompressor->src
        && decompressor->src->bytes_in_buffer <= error->input_length) {
      error->failure_offset = error->input_length
          - decompressor->src->bytes_in_buffer;
    }
  }
  longjmp(error->recovery, 1);
}


static inline void avi_jpeg_emit_message(j_common_ptr decoder,
                                         int message_level) {

  if (message_level < 0) {
    avi_jpeg_error_exit(decoder);
  }
}


// Decode all entropy-coded coefficients without performing color conversion or inverse DCT.
static inline bool avi_decode_jpeg_payload(const uint8_t *data,
                                           uint64_t length,
                                           uint32_t expected_width,
                                           uint32_t expected_height,
                                           uint64_t *failure_offset) {

  struct jpeg_decompress_struct decoder;
  AviJpegError error;
  volatile bool decoder_created = false;
  volatile bool valid = false;

  if (!data || !failure_offset || length == 0 || length > ULONG_MAX) {
    return false;
  }
  *failure_offset = 0;
  memset(&decoder, 0, sizeof(decoder));
  decoder.err = jpeg_std_error(&error.manager);
  error.manager.error_exit = avi_jpeg_error_exit;
  error.manager.emit_message = avi_jpeg_emit_message;
  error.input_length = length;
  error.failure_offset = 0;
  if (setjmp(error.recovery)) {
    goto decode_complete;
  }
  jpeg_create_decompress(&decoder);
  decoder_created = true;
  jpeg_mem_src(&decoder, data, (unsigned long)length);
  if (jpeg_read_header(&decoder, TRUE) != JPEG_HEADER_OK
      || decoder.image_width != expected_width
      || decoder.image_height != expected_height) {
    goto decode_complete;
  }
  jvirt_barray_ptr *coefficients = jpeg_read_coefficients(&decoder);

  if (!coefficients) {
    goto decode_complete;
  }
  for (int component = 0; component < decoder.num_components; component++) {
    jpeg_component_info *info = &decoder.comp_info[component];

    for (JDIMENSION row = 0; row < info->height_in_blocks; row++) {
      JBLOCKARRAY blocks = decoder.mem->access_virt_barray(
          (j_common_ptr)&decoder, coefficients[component], row, 1, FALSE);

      if (!blocks) {
        goto decode_complete;
      }
    }
  }
  valid = jpeg_finish_decompress(&decoder) == TRUE;

decode_complete:
  *failure_offset = error.failure_offset;
  if (decoder_created) {
    jpeg_destroy_decompress(&decoder);
  }
  return valid;
}


// Validate the available prefix of a JPEG frame. The declared chunk length lets malformed marker
// lengths be rejected before the remainder of a fragmented frame has been assembled.
static inline bool avi_validate_jpeg_prefix(const uint8_t *data,
                                            uint64_t available,
                                            uint64_t declared,
                                            bool *complete,
                                            uint64_t *failure_offset) {

  uint64_t position = 0;
  bool entropy = false;
  bool saw_scan = false;

  if (!data || !complete || !failure_offset || available > declared) {
    return false;
  }
  *complete = false;
  *failure_offset = 0;
  if (available == 0) {
    return declared > 0;
  }
  if (data[0] != UINT8_C(0xff)) {
    return false;
  }
  if (available == 1) {
    return declared > 1;
  }
  if (data[1] != UINT8_C(0xd8)) {
    *failure_offset = 1;
    return false;
  }
  position = 2;

  while (position < available) {
    uint64_t marker_offset = position;

    if (entropy) {
      if (data[position] != UINT8_C(0xff)) {
        position++;
        continue;
      }
      while (position < available && data[position] == UINT8_C(0xff)) {
        position++;
      }
      if (position == available) {
        if (available == declared) {
          *failure_offset = marker_offset;
        }
        return available < declared;
      }
      uint8_t marker = data[position];

      if (marker == 0 || (marker >= UINT8_C(0xd0)
                          && marker <= UINT8_C(0xd7))) {
        position++;
        continue;
      }
      if (marker == UINT8_C(0xd9)) {
        position++;
        bool alignment_padding = declared - position <= 3;

        // Some AVI writers include JPEG's 32-bit alignment bytes in the media chunk length.
        while (position < available) {
          if (!alignment_padding && data[position] != 0
              && data[position] != UINT8_C(0xff)) {
            *failure_offset = position;
            return false;
          }
          position++;
        }
        *complete = available == declared;
        return true;
      }
      entropy = false;
      position = marker_offset;
      continue;
    }

    if (data[position] != UINT8_C(0xff)) {
      *failure_offset = position;
      return false;
    }
    while (position < available && data[position] == UINT8_C(0xff)) {
      position++;
    }
    if (position == available) {
      if (available == declared) {
        *failure_offset = marker_offset;
      }
      return available < declared;
    }
    uint8_t marker = data[position++];

    if (marker == 0 || marker == UINT8_C(0xd8)
        || (marker >= UINT8_C(0xd0) && marker <= UINT8_C(0xd7))) {
      *failure_offset = position - 1;
      return false;
    }
    if (marker == UINT8_C(0xd9)) {
      if (!saw_scan) {
        *failure_offset = position - 1;
        return false;
      }
      bool alignment_padding = declared - position <= 3;

      while (position < available) {
        if (!alignment_padding && data[position] != 0
            && data[position] != UINT8_C(0xff)) {
          *failure_offset = position;
          return false;
        }
        position++;
      }
      *complete = available == declared;
      return true;
    }
    if (marker == UINT8_C(0x01)) {
      continue;
    }
    if (marker < UINT8_C(0xc0) || marker > UINT8_C(0xfe)) {
      *failure_offset = position - 1;
      return false;
    }
    if (position + 2 > declared) {
      *failure_offset = marker_offset;
      return false;
    }
    if (position + 2 > available) {
      return true;
    }
    uint16_t segment_length = ((uint16_t)data[position] << 8)
        | (uint16_t)data[position + 1];

    if (segment_length < 2 || position + segment_length > declared) {
      *failure_offset = position;
      return false;
    }
    if (position + segment_length > available) {
      return true;
    }
    position += segment_length;
    if (marker == UINT8_C(0xda)) {
      saw_scan = true;
      entropy = true;
    }
  }

  if (available == declared) {
    *failure_offset = available > 0 ? available - 1 : 0;
    return false;
  }
  return true;
}


// Validate a complete JPEG codestream, including all entropy-coded scans and the EOI marker.
static inline bool avi_validate_jpeg_payload(const uint8_t *data,
                                             uint64_t length) {

  bool complete;
  uint64_t failure_offset;

  return avi_validate_jpeg_prefix(data, length, length, &complete,
                                  &failure_offset)
      && complete;
}


// Validate each complete PNG chunk in the available frame prefix. A chunk whose payload is not yet
// present remains possible, but every complete chunk must have the correct CRC.
static inline bool avi_validate_png_prefix(const uint8_t *data,
                                           uint64_t available,
                                           uint64_t declared,
                                           bool *complete,
                                           uint64_t *failure_offset) {

  static const uint8_t signature[8] = {
      UINT8_C(0x89), 'P', 'N', 'G', UINT8_C(0x0d), UINT8_C(0x0a),
      UINT8_C(0x1a), UINT8_C(0x0a)};
  uint64_t position = sizeof(signature);
  bool saw_header = false;

  if (!data || !complete || !failure_offset || available > declared) {
    return false;
  }
  *complete = false;
  *failure_offset = 0;
  uint64_t signature_bytes = available < sizeof(signature)
      ? available : sizeof(signature);

  if (memcmp(data, signature, signature_bytes) != 0) {
    while (*failure_offset < signature_bytes
           && data[*failure_offset] == signature[*failure_offset]) {
      (*failure_offset)++;
    }
    return false;
  }
  if (available < sizeof(signature)) {
    return available < declared;
  }

  while (position < available) {
    if (!avi_range_available(available, position, 8)) {
      if (available == declared) {
        *failure_offset = position;
      }
      return available < declared;
    }
    uint32_t chunk_length = avi_read_be32(data + position);
    uint64_t payload = position + 8;
    uint64_t crc_offset;

    if (chunk_length > AVI_MAX_PNG_CHUNK_SIZE
        || __builtin_add_overflow(payload, (uint64_t)chunk_length,
                                  &crc_offset)
        || !avi_range_available(declared, crc_offset, sizeof(uint32_t))) {
      *failure_offset = position;
      return false;
    }
    if (!avi_range_available(available, crc_offset, sizeof(uint32_t))) {
      if (available == declared) {
        *failure_offset = position;
      }
      return available < declared;
    }

    uLong crc = crc32(0L, Z_NULL, 0);
    crc = crc32(crc, data + position + 4, 4);
    crc = crc32(crc, data + payload, chunk_length);
    if ((uint32_t)crc != avi_read_be32(data + crc_offset)) {
      *failure_offset = crc_offset;
      return false;
    }

    uint32_t type = avi_read_le32(data + position + 4);
    if (!saw_header) {
      if (type != AVI_FOURCC('I', 'H', 'D', 'R') || chunk_length != 13) {
        *failure_offset = position + 4;
        return false;
      }
      saw_header = true;
    }
    position = crc_offset + sizeof(uint32_t);
    if (type == AVI_FOURCC('I', 'E', 'N', 'D')) {
      if (chunk_length != 0
          || !avi_trailing_padding(data, available, position)) {
        *failure_offset = position;
        return false;
      }
      *complete = available == declared;
      return true;
    }
  }
  if (available == declared) {
    *failure_offset = available > 0 ? available - 1 : 0;
    return false;
  }
  return true;
}


// Validate every PNG chunk CRC so a complete PNG video frame supplies payload-level evidence
// rather than only RIFF structure.
static inline bool avi_validate_png_payload(const uint8_t *data,
                                            uint64_t length) {

  bool complete;
  uint64_t failure_offset;

  return avi_validate_png_prefix(data, length, length, &complete,
                                 &failure_offset)
      && complete;
}


static inline bool avi_has_mpeg_start_code(const uint8_t *data,
                                           uint64_t length) {

  uint64_t limit = length < 256 ? length : 256;

  for (uint64_t position = 0; position + 4 <= limit; position++) {
    if (data[position] == 0 && data[position + 1] == 0
        && data[position + 2] == 1
        && data[position + 3] >= UINT8_C(0xb0)
        && data[position + 3] <= UINT8_C(0xb6)) {
      return true;
    }
  }
  return false;
}


static inline bool avi_validate_mp3_payload(const uint8_t *data,
                                            uint64_t length) {

  uint64_t position = 0;
  uint32_t frames = 0;
  static const uint16_t bitrates[2][3][16] = {
      {{0}, {0}, {0}},
      {{0, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 0},
       {0, 32, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 384, 0},
       {0, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 0}}};
  static const uint32_t rates[4][4] = {
      {11025, 12000, 8000, 0},
      {0, 0, 0, 0},
      {22050, 24000, 16000, 0},
      {44100, 48000, 32000, 0}};

  while (avi_range_available(length, position, 4)) {
    uint32_t header = avi_read_be32(data + position);
    uint32_t version = (header >> 19) & 3U;
    uint32_t layer_bits = (header >> 17) & 3U;
    uint32_t bitrate_index = (header >> 12) & 15U;
    uint32_t rate_index = (header >> 10) & 3U;
    uint32_t padding = (header >> 9) & 1U;

    if ((header & UINT32_C(0xffe00000)) != UINT32_C(0xffe00000)
        || version == 1 || layer_bits == 0 || bitrate_index == 0
        || bitrate_index == 15 || rate_index == 3) {
      return false;
    }

    uint32_t rate = rates[version][rate_index];
    uint32_t layer = 4U - layer_bits;
    uint32_t version_group = version == 3 ? 1U : 0U;
    uint32_t bitrate;
    uint64_t frame_length;

    if (version_group == 1) {
      bitrate = bitrates[1][layer - 1][bitrate_index];
    }
    else {
      static const uint16_t low_bitrates[3][16] = {
          {0, 32, 48, 56, 64, 80, 96, 112, 128, 144, 160, 176, 192, 224, 256, 0},
          {0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160, 0},
          {0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160, 0}};
      bitrate = low_bitrates[layer - 1][bitrate_index];
    }
    if (rate == 0 || bitrate == 0) {
      return false;
    }

    if (layer == 1) {
      frame_length = ((UINT64_C(12000) * bitrate / rate) + padding) * 4;
    }
    else {
      uint32_t coefficient = version == 3 || layer == 2 ? 144U : 72U;
      frame_length = UINT64_C(1000) * coefficient * bitrate / rate + padding;
    }
    if (frame_length < 4
        || !avi_range_available(length, position, frame_length)) {
      return false;
    }
    position += frame_length;
    frames++;
  }

  return frames > 0 && avi_trailing_padding(data, length, position);
}


static inline bool avi_chunk_matches(const uint8_t *data, uint64_t length,
                                     uint64_t offset, uint32_t id,
                                     uint32_t size) {

  uint64_t candidates[2] = {offset, offset >= AVI_CHUNK_HEADER_SIZE
      ? offset - AVI_CHUNK_HEADER_SIZE : UINT64_MAX};

  for (uint32_t candidate = 0; candidate < 2; candidate++) {
    uint64_t position = candidates[candidate];

    if (position != UINT64_MAX
        && avi_range_available(length, position, AVI_CHUNK_HEADER_SIZE)
        && avi_media_chunk_ids_compatible(
            id, avi_read_le32(data + position))
        && avi_read_le32(data + position + 4) == size) {
      return true;
    }
  }
  return false;
}


static inline bool avi_index_entry_matches(const uint8_t *data,
                                           uint64_t length,
                                           uint64_t offset, uint32_t id,
                                           uint32_t size,
                                           uint64_t *matched_offset) {

  uint64_t candidates[2] = {offset, offset >= AVI_CHUNK_HEADER_SIZE
      ? offset - AVI_CHUNK_HEADER_SIZE : UINT64_MAX};

  for (uint32_t candidate = 0; candidate < 2; candidate++) {
    uint64_t position = candidates[candidate];

    if (position == UINT64_MAX) {
      continue;
    }
    if (avi_is_media_chunk(id)
        && avi_range_available(length, position, AVI_CHUNK_HEADER_SIZE)
        && avi_media_chunk_ids_compatible(
            id, avi_read_le32(data + position))
        && avi_read_le32(data + position + 4) == size) {
      if (matched_offset) {
        *matched_offset = position;
      }
      return true;
    }
    if (id == AVI_FOURCC('r', 'e', 'c', ' ')
        && avi_range_available(length, position,
                               AVI_RIFF_HEADER_SIZE)
        && avi_read_le32(data + position)
               == AVI_FOURCC('L', 'I', 'S', 'T')
        && avi_read_le32(data + position + 4) == size
        && avi_read_le32(data + position + 8) == id) {
      if (matched_offset) {
        *matched_offset = position;
      }
      return true;
    }
  }
  return false;
}


// Legacy AVI writers use several documented and de facto idx1 offset bases. A valid archive must
// use one convention consistently for every entry.
static inline bool avi_validate_idx1(AviParser *parser, uint64_t offset,
                                     uint32_t size) {

  uint32_t base_mask;
  uint64_t verified_entries = 0;

  if ((size % AVI_INDEX_ENTRY_SIZE) != 0 || parser->layout->movi_count == 0) {
    return avi_parser_fail(parser, offset);
  }
  if (parser->layout->movi_count >= 8) {
    base_mask = UINT32_MAX;
  }
  else {
    base_mask = (UINT32_C(1) << (parser->layout->movi_count * 4)) - 1;
  }

  for (uint32_t entry = 0; entry < size / AVI_INDEX_ENTRY_SIZE; entry++) {
    uint64_t position = offset + (uint64_t)entry * AVI_INDEX_ENTRY_SIZE;
    uint32_t id = avi_read_le32(parser->data + position);
    int32_t stream_number = avi_stream_number(id);
    uint32_t relative = avi_read_le32(parser->data + position + 8);
    uint32_t chunk_size = avi_read_le32(parser->data + position + 12);
    uint32_t surviving = 0;
    bool media_entry = avi_is_media_chunk(id);
    bool record_entry = id == AVI_FOURCC('r', 'e', 'c', ' ');

    // Some OpenDML writers add zero-length private markers to the compatibility index. They
    // describe no file bytes and therefore supply no evidence, but do not invalidate later entries.
    if (!media_entry && !record_entry && chunk_size == 0
        && avi_chunk_id_printable(id)) {
      continue;
    }
    if ((!media_entry && !record_entry)
        || (media_entry && (stream_number < 0
            || (uint32_t)stream_number >= parser->layout->stream_count))) {
      return avi_parser_fail(parser, position);
    }
    if (media_entry && chunk_size == 0) {
      continue;
    }
    for (uint32_t movi = 0; movi < parser->layout->movi_count && movi < 8;
         movi++) {
      uint64_t movi_type = parser->layout->movi_type_offsets[movi];
      uint64_t bases[4] = {0, movi_type, movi_type + 4,
                           movi_type >= 8 ? movi_type - 8 : 0};

      for (uint32_t mode = 0; mode < 4; mode++) {
        uint32_t bit = UINT32_C(1) << (movi * 4 + mode);
        uint64_t target;

        if ((base_mask & bit) == 0
            || __builtin_add_overflow(bases[mode], (uint64_t)relative,
                                      &target)) {
          continue;
        }
        if (avi_index_entry_matches(parser->data, parser->length, target,
                                    id, chunk_size, NULL)) {
          surviving |= bit;
        }
      }
    }
    base_mask &= surviving;
    if (base_mask == 0) {
      return avi_parser_fail(parser, position);
    }
    parser->layout->index_entries++;
    parser->layout->index_entries_verified++;
    verified_entries++;
    if ((entry & 1023U) == 0 && avi_parser_stop_requested(parser)) {
      return avi_parser_fail(parser, position);
    }
  }
  if (verified_entries == 0) {
    return avi_parser_fail(parser, offset);
  }
  parser->layout->saw_legacy_index = true;
  return true;
}


static inline bool avi_validate_standard_index(AviParser *parser,
                                               uint32_t index_id,
                                               uint64_t offset,
                                               uint32_t size) {

  if (size < AVI_STANDARD_INDEX_HEADER_SIZE) {
    return avi_parser_fail(parser, offset);
  }

  uint16_t longs_per_entry = avi_read_le16(parser->data + offset);
  uint8_t index_type = parser->data[offset + 3];
  uint32_t entries = avi_read_le32(parser->data + offset + 4);
  uint32_t chunk_id = avi_read_le32(parser->data + offset + 8);
  int32_t stream_number = avi_stream_number(chunk_id);
  uint32_t expected_index_id = AVI_FOURCC(
      'i', 'x', (uint8_t)chunk_id, (uint8_t)(chunk_id >> 8));
  uint64_t base = avi_read_le64(parser->data + offset + 12);
  uint64_t entry_size = (uint64_t)longs_per_entry * sizeof(uint32_t);
  uint64_t entries_size;
  uint64_t target_adjustment = UINT64_MAX;
  uint64_t previous_media_offset = UINT64_MAX;

  if (longs_per_entry < 2 || index_type != AVI_INDEX_OF_CHUNKS
      || index_id != expected_index_id || !avi_is_media_chunk(chunk_id)
      || stream_number < 0
      || (uint32_t)stream_number >= parser->layout->stream_count
      || __builtin_mul_overflow((uint64_t)entries, entry_size, &entries_size)
      || !avi_range_available(size, AVI_STANDARD_INDEX_HEADER_SIZE,
                              entries_size)) {
    return avi_parser_fail(parser, offset);
  }

  for (uint32_t entry = 0; entry < entries; entry++) {
    uint64_t position = offset + AVI_STANDARD_INDEX_HEADER_SIZE
        + (uint64_t)entry * entry_size;
    uint32_t relative = avi_read_le32(parser->data + position);
    uint32_t raw_size = avi_read_le32(parser->data + position + 4);
    uint32_t chunk_size = raw_size & UINT32_C(0x7fffffff);
    uint64_t target;

    if (__builtin_add_overflow(base, (uint64_t)relative, &target)) {
      return avi_parser_fail(parser, position);
    }
    if (chunk_size == 0) {
      if (target > parser->length) {
        return avi_parser_fail(parser, target);
      }
    }
    else {
      uint64_t matched_offset = UINT64_MAX;

      if (!avi_index_entry_matches(parser->data, parser->length, target,
                                   chunk_id, chunk_size,
                                   &matched_offset)) {
        uint64_t expected_offset = target;

        if (target_adjustment != UINT64_MAX
            && target >= target_adjustment) {
          expected_offset = target - target_adjustment;
        }
        if (previous_media_offset != UINT64_MAX) {
          parser->layout->failure_media_offset = previous_media_offset;
          parser->layout->failure_media_end = expected_offset;
        }
        return avi_parser_fail(parser, expected_offset);
      }
      if (target_adjustment == UINT64_MAX) {
        target_adjustment = target - matched_offset;
      }
      previous_media_offset = matched_offset + AVI_CHUNK_HEADER_SIZE;
    }
    parser->layout->index_entries++;
    parser->layout->index_entries_verified++;
    if ((entry & 1023U) == 0 && avi_parser_stop_requested(parser)) {
      return avi_parser_fail(parser, position);
    }
  }
  parser->layout->standard_indexes++;
  return true;
}


static inline bool avi_validate_super_index(AviParser *parser,
                                            uint64_t offset,
                                            uint32_t size) {

  if (size < AVI_SUPER_INDEX_HEADER_SIZE) {
    return avi_parser_fail(parser, offset);
  }

  uint16_t longs_per_entry = avi_read_le16(parser->data + offset);
  uint8_t index_type = parser->data[offset + 3];
  uint32_t entries = avi_read_le32(parser->data + offset + 4);
  uint32_t chunk_id = avi_read_le32(parser->data + offset + 8);
  int32_t stream_number = avi_stream_number(chunk_id);
  uint32_t expected_index_id = AVI_FOURCC(
      'i', 'x', (uint8_t)chunk_id, (uint8_t)(chunk_id >> 8));
  uint64_t entry_size = (uint64_t)longs_per_entry * sizeof(uint32_t);
  uint64_t entries_size;

  if (longs_per_entry < 4 || index_type != AVI_INDEX_OF_INDEXES
      || !avi_is_media_chunk(chunk_id) || stream_number < 0
      || (uint32_t)stream_number >= parser->layout->stream_count
      || __builtin_mul_overflow((uint64_t)entries, entry_size, &entries_size)
      || !avi_range_available(size, AVI_SUPER_INDEX_HEADER_SIZE,
                              entries_size)) {
    return avi_parser_fail(parser, offset);
  }

  for (uint32_t entry = 0; entry < entries; entry++) {
    uint64_t position = offset + AVI_SUPER_INDEX_HEADER_SIZE
        + (uint64_t)entry * entry_size;
    uint64_t index_offset = avi_read_le64(parser->data + position);
    uint32_t index_size = avi_read_le32(parser->data + position + 8);
    uint64_t required;

    if (index_offset == 0 || index_size < AVI_CHUNK_HEADER_SIZE
        || __builtin_add_overflow(index_offset, (uint64_t)index_size,
                                  &required)) {
      return avi_parser_fail(parser, position);
    }
    if (required > parser->layout->required_extent) {
      parser->layout->required_extent = required;
    }
    if (required > parser->layout->indexed_extent) {
      parser->layout->indexed_extent = required;
    }
    parser->layout->super_index_entries++;
    if (!avi_range_available(parser->length, index_offset,
                             AVI_CHUNK_HEADER_SIZE)) {
      if (index_offset < parser->layout->super_index_failure_offset) {
        parser->layout->super_index_failure_offset = index_offset;
      }
      continue;
    }
    uint32_t index_id = avi_read_le32(parser->data + index_offset);
    if (index_id != expected_index_id
        || (uint64_t)avi_read_le32(parser->data + index_offset + 4)
               + AVI_CHUNK_HEADER_SIZE > index_size) {
      if (index_offset < parser->layout->super_index_failure_offset) {
        parser->layout->super_index_failure_offset = index_offset;
      }
      continue;
    }
    parser->layout->super_index_entries_verified++;
    parser->layout->index_entries_verified++;
  }
  parser->layout->super_indexes++;
  return true;
}


static inline bool avi_carve_state_size(uint64_t entry_count,
                                        size_t *state_size) {

  size_t entries_size;

  if (!state_size || entry_count > SIZE_MAX / sizeof(AviStateIndexEntry)) {
    return false;
  }
  entries_size = (size_t)entry_count * sizeof(AviStateIndexEntry);
  if (entries_size > SIZE_MAX - offsetof(AviCarveState, entries)) {
    return false;
  }
  *state_size = offsetof(AviCarveState, entries) + entries_size;
  return true;
}


static inline bool avi_carve_state_valid(const AviCarveState *state) {

  if (!state || state->magic != AVI_CARVE_STATE_MAGIC
      || state->version != AVI_CARVE_STATE_VERSION
      || state->archive_extent < AVI_RIFF_HEADER_SIZE
      || state->archive_extent > AVI_MAX_ARCHIVE_SIZE
      || state->initialized > 1
      || state->entry_count > UINT32_MAX / AVI_INDEX_ENTRY_SIZE
      || state->entry_count > state->archive_extent / AVI_INDEX_ENTRY_SIZE) {
    return false;
  }
  const AviBlockSearch *search = &state->block_search;

  if (search->active > 1) {
    return false;
  }
  if (search->active
      && (!state->initialized || search->blocksize == 0
          || search->target_slot == 0
          || search->target_slot >= CEILDIV(state->archive_extent,
                                             search->blocksize)
          || search->image_blocks == 0 || search->image_blocks > INT64_MAX
          || search->next_actual > search->image_blocks
          || search->baseline_to >= state->archive_extent
          || search->best_validates_to < search->baseline_to
          || search->best_validates_to >= state->archive_extent
          || search->best_actual < -1 || search->best_reserved < 0
          || search->best_confidence > 100
          || (search->best_actual >= 0
              && ((uint64_t)search->best_actual >= search->next_actual
                  || search->best_validates_to == search->baseline_to))
          || (search->best_actual < 0
              && search->best_validates_to != search->baseline_to))) {
    return false;
  }
  for (uint64_t entry = 0; entry < state->entry_count; entry++) {
    if (!avi_is_media_chunk(state->entries[entry].id)
        || state->entries[entry].offset >= state->archive_extent
        || state->entries[entry].size > state->archive_extent) {
      return false;
    }
  }
  if (state->indexed_search.active > 2) {
    return false;
  }
  if (state->indexed_search.active) {
    const uint32_t bs = state->indexed_search.blocksize;
    if (!state->initialized || !bs
        || !state->indexed_search.target_slot
        || state->indexed_search.target_slot >= CEILDIV(state->archive_extent, bs)
        || !state->indexed_search.image_blocks
        || state->indexed_search.image_blocks > INT64_MAX
        || state->indexed_search.next_actual > state->indexed_search.image_blocks
        || state->indexed_search.baseline_to >= state->archive_extent
        || state->indexed_search.best_validates_to < state->indexed_search.baseline_to
        || state->indexed_search.best_validates_to >= state->archive_extent
        || state->indexed_search.previous_validates_to < state->indexed_search.baseline_to
        || state->indexed_search.previous_validates_to >= state->archive_extent
        || state->indexed_search.best_start < -1) {
      return false;
    }
    uint64_t suffix = CEILDIV(state->archive_extent, bs)
        - state->indexed_search.target_slot;
    if (state->indexed_search.mapped > suffix
        || state->indexed_search.mapped > state->indexed_search.image_blocks
            - state->indexed_search.next_actual
        || state->indexed_search.minimum_blocks > suffix
        || state->indexed_search.best_mapped > suffix
        || (state->indexed_search.active == 2
            && (state->indexed_search.next_actual != state->indexed_search.image_blocks
                || state->indexed_search.mapped))
        || (state->indexed_search.best_start < 0
            && (state->indexed_search.best_mapped
                || state->indexed_search.best_validates_to != state->indexed_search.baseline_to))
        || (state->indexed_search.best_start >= 0
            && (!state->indexed_search.best_mapped
                || state->indexed_search.best_validates_to == state->indexed_search.baseline_to
                || (uint64_t)state->indexed_search.best_start >= state->indexed_search.image_blocks
                || state->indexed_search.best_mapped > state->indexed_search.image_blocks
                    - (uint64_t)state->indexed_search.best_start))) {
      return false;
    }
  }
  for (uint32_t index = 0; index < 2; index++) {
    if (state->zero_gap_search[index].active > 1) {
      return false;
    }
    if (state->zero_gap_search[index].active
        && (!state->initialized || !state->zero_gap_search[index].blocksize
            || !state->zero_gap_search[index].image_blocks
            || state->zero_gap_search[index].image_blocks > INT64_MAX
            || state->zero_gap_search[index].baseline_to >= state->archive_extent
            || state->zero_gap_search[index].next_slot < state->zero_gap_search[index].start_slot
            || state->zero_gap_search[index].next_slot > CEILDIV(state->archive_extent,
                                                    state->zero_gap_search[index].blocksize))) {
      return false;
    }
  }
  const AviClassifiedSearch *classified = &state->classified_search;
  if (classified->active > 2) {
    return false;
  }
  if (classified->active) {
    if (!state->initialized || !classified->blocksize || !classified->run_blocks
        || !classified->image_blocks || classified->image_blocks > INT64_MAX
        || classified->baseline_to >= state->archive_extent
        || classified->target_slot >= CEILDIV(state->archive_extent, classified->blocksize)
        || classified->run_blocks > CEILDIV(state->archive_extent, classified->blocksize)
            - classified->target_slot
        || classified->run_blocks > classified->image_blocks
        || classified->next_actual > classified->image_blocks - classified->run_blocks + 1
        || classified->fallback_count > AVI_CONTENT_FALLBACK_RUNS
        || classified->fallback_next > classified->fallback_count
        || classified->allow_content_only > 1 || classified->require_complete > 1
        || classified->lowest_content_isolated > 1
        || classified->owner < 1 || classified->owner > 4
        || classified->lowest_content_reserved < 0
        || classified->best.reserved < 0 || classified->best.validates > 1
        || classified->best.complete > 1 || classified->best.contiguous > 1
        || classified->best.isolated > 1
        || classified->best.validates_to < classified->baseline_to
        || classified->best.validates_to >= state->archive_extent
        || (classified->active == 2
            && (classified->next_actual != classified->image_blocks - classified->run_blocks + 1
                || classified->fallback_next != classified->fallback_count))
        || (classified->fallback_next
            && classified->next_actual != classified->image_blocks - classified->run_blocks + 1)
        || classified->owner != (classified->baseline_to == state->archive_extent - 1 ? 1U
            : classified->require_complete ? 2U : classified->run_blocks > 1 ? 3U : 4U)) {
      return false;
    }
    const uint64_t sources[] = {classified->best.start, classified->lowest_content_start,
                                classified->second_content_start};
    for (uint32_t index = 0; index < 3; index++) {
      if (sources[index] != UINT64_MAX
          && sources[index] > classified->image_blocks - classified->run_blocks) {
        return false;
      }
    }
    for (uint32_t index = 0; index < classified->fallback_count; index++) {
      if (classified->fallback[index].start > classified->image_blocks - classified->run_blocks) {
        return false;
      }
    }
  }
  const AviShiftSearch *shift = &state->shift_search;
  if (shift->phase > 5) {
    return false;
  }
  if (shift->phase) {
    if (!state->initialized || !shift->blocksize || !shift->target_slot
        || shift->target_slot >= CEILDIV(state->archive_extent, shift->blocksize)
        || !shift->image_blocks || shift->image_blocks > INT64_MAX
        || shift->baseline_to >= state->archive_extent
        || shift->repair_end > state->archive_extent
        || shift->next_entry > state->entry_count
        || !shift->next_shift
        || shift->next_shift > CEILDIV(state->archive_extent, shift->blocksize) - shift->target_slot
        || shift->best_shift >= CEILDIV(state->archive_extent, shift->blocksize) - shift->target_slot
        || shift->best_validates_to < shift->baseline_to
        || shift->best_validates_to >= state->archive_extent
        || (shift->best_shift == 0 && shift->best_validates_to != shift->baseline_to)
        || (shift->best_shift && shift->best_validates_to == shift->baseline_to)
        || (shift->phase == 1 && !state->entry_count)
        || (shift->phase == 4 && (!shift->best_shift
            || shift->best_validates_to != state->archive_extent - 1))
        || shift->owner < 1 || shift->owner > 2) {
      return false;
    }
  }
  const AviDisplacedSearch *displaced = &state->displaced_search;
  if (displaced->phase > 5) {
    return false;
  }
  if (displaced->phase) {
    if (!state->initialized || !displaced->blocksize || !displaced->target_slot
        || displaced->target_slot >= CEILDIV(state->archive_extent, displaced->blocksize)
        || !displaced->image_blocks || displaced->image_blocks > INT64_MAX
        || displaced->next_actual > displaced->image_blocks
        || displaced->baseline_to >= state->archive_extent
        || displaced->repair_end > state->archive_extent
        || displaced->reconnects_to >= state->archive_extent
        || displaced->previous_validates_to < displaced->baseline_to
        || displaced->previous_validates_to >= state->archive_extent
        || displaced->best_validates_to < displaced->baseline_to
        || displaced->best_validates_to >= state->archive_extent
        || displaced->best_start < -1) {
      return false;
    }
    uint64_t suffix = CEILDIV(state->archive_extent, displaced->blocksize)
        - displaced->target_slot;
    if (displaced->probe_blocks > suffix || displaced->mapped > suffix
        || displaced->mapped > displaced->image_blocks - displaced->next_actual
        || displaced->proven_blocks > displaced->mapped
        || displaced->best_mapped > suffix
        || ((displaced->phase == 1 || displaced->phase == 2)
            && !displaced->probe_blocks)
        || (displaced->phase == 1 && (displaced->mapped || displaced->proven_blocks))
        || (displaced->phase == 2 && (!displaced->mapped || !displaced->proven_blocks))
        || (displaced->phase == 3 && (displaced->probe_blocks || displaced->proven_blocks))
        || (displaced->phase >= 4 && (displaced->mapped || displaced->proven_blocks
            || displaced->next_actual != displaced->image_blocks))
        || (displaced->best_start < 0 && (displaced->best_mapped
            || displaced->best_validates_to != displaced->baseline_to))
        || (displaced->best_start >= 0 && (!displaced->best_mapped
            || (uint64_t)displaced->best_start >= displaced->image_blocks
            || displaced->best_mapped > displaced->image_blocks - (uint64_t)displaced->best_start
            || displaced->best_validates_to == displaced->baseline_to))) {
      return false;
    }
  }
  return true;
}


static inline AviCarveState *avi_capture_legacy_index(
    const uint8_t *data, uint64_t length, const AviLayout *layout) {

  uint64_t idx_position = UINT64_MAX;
  uint64_t idx_entries = 0;
  uint64_t archive_extent;

  if (!data || !layout || length < AVI_RIFF_HEADER_SIZE
      || avi_read_le32(data) != AVI_FOURCC('R', 'I', 'F', 'F')
      || avi_read_le32(data + 8) != AVI_FOURCC('A', 'V', 'I', ' ')
      || __builtin_add_overflow((uint64_t)avi_read_le32(data + 4),
                                (uint64_t)AVI_CHUNK_HEADER_SIZE,
                                &archive_extent)
      || archive_extent < AVI_RIFF_HEADER_SIZE
      || archive_extent > AVI_MAX_ARCHIVE_SIZE) {
    return NULL;
  }
  // A damaged child chunk can advertise an arbitrary payload size. Only parsed RIFF segments and
  // structurally valid OpenDML index entries may extend the top-level RIFF declaration.
  if (layout->described_extent > archive_extent) {
    archive_extent = layout->described_extent;
  }
  if (layout->indexed_extent > archive_extent) {
    archive_extent = layout->indexed_extent;
  }
  if (archive_extent > AVI_MAX_ARCHIVE_SIZE) {
    return NULL;
  }
  for (uint64_t position = AVI_RIFF_HEADER_SIZE;
       avi_range_available(length, position, AVI_CHUNK_HEADER_SIZE);
       position++) {
    if (avi_read_le32(data + position) == AVI_FOURCC('i', 'd', 'x', '1')) {
      uint32_t size = avi_read_le32(data + position + 4);
      uint64_t available = length - position - AVI_CHUNK_HEADER_SIZE;
      uint64_t entries;

      if (size == 0 || (size % AVI_INDEX_ENTRY_SIZE) != 0) {
        continue;
      }
      if (available > size) {
        available = size;
      }
      entries = available / AVI_INDEX_ENTRY_SIZE;
      if (entries == 0 || entries <= idx_entries) {
        continue;
      }
      bool structurally_valid = true;

      for (uint64_t entry = 0; entry < entries; entry++) {
        uint64_t entry_position = position + AVI_CHUNK_HEADER_SIZE
            + entry * AVI_INDEX_ENTRY_SIZE;
        uint32_t id = avi_read_le32(data + entry_position);
        int32_t stream = avi_stream_number(id);
        bool media_entry = avi_is_media_chunk(id);
        bool record_entry = id == AVI_FOURCC('r', 'e', 'c', ' ');

        if ((!media_entry && !record_entry)
            || (media_entry && (stream < 0
                || (uint32_t)stream >= layout->stream_count))
            || avi_read_le32(data + entry_position + 8) >= archive_extent
            || avi_read_le32(data + entry_position + 12)
                   > archive_extent) {
          structurally_valid = false;
          break;
        }
      }
      if (structurally_valid) {
        idx_position = position + AVI_CHUNK_HEADER_SIZE;
        idx_entries = entries;
      }
    }
  }
  uint64_t entry_count = 0;

  if (idx_position != UINT64_MAX) {
    for (uint64_t entry = 0; entry < idx_entries; entry++) {
      uint64_t position = idx_position + entry * AVI_INDEX_ENTRY_SIZE;

      if (avi_is_media_chunk(avi_read_le32(data + position))) {
        entry_count++;
      }
    }
  }
  size_t state_size;

  if (!avi_carve_state_size(entry_count, &state_size)) {
    return NULL;
  }
  AviCarveState *state = (AviCarveState *)calloc(1, state_size);

  check_memory_allocation(state, __LINE__, __FILE__, "AviCarveState");
  state->magic = AVI_CARVE_STATE_MAGIC;
  state->version = AVI_CARVE_STATE_VERSION;
  state->archive_extent = archive_extent;
  state->entry_count = entry_count;

  if (entry_count == 0 || layout->movi_count == 0) {
    state->entry_count = 0;
    return state;
  }

  uint32_t selected_movi = 0;
  uint32_t selected_mode = 0;
  uint64_t best_matches = 0;

  // idx1 offsets have several conventions in deployed AVI writers. Select the convention with the
  // longest verified prefix so the first fragmented entry becomes a repair target rather than
  // invalidating an otherwise genuine index.
  for (uint32_t movi = 0; movi < layout->movi_count && movi < 8; movi++) {
    uint64_t movi_type = layout->movi_type_offsets[movi];
    uint64_t bases[4] = {0, movi_type, movi_type + 4,
                         movi_type >= 8 ? movi_type - 8 : 0};

    for (uint32_t mode = 0; mode < 4; mode++) {
      uint64_t matches = 0;

      for (uint64_t entry = 0; entry < idx_entries; entry++) {
        uint64_t position = idx_position + entry * AVI_INDEX_ENTRY_SIZE;
        uint64_t target;

        if (__builtin_add_overflow(
                bases[mode],
                (uint64_t)avi_read_le32(data + position + 8), &target)
            || !avi_index_entry_matches(
                data, length, target, avi_read_le32(data + position),
                avi_read_le32(data + position + 12), NULL)) {
          break;
        }
        matches++;
      }
      if (matches > best_matches) {
        best_matches = matches;
        selected_movi = movi;
        selected_mode = mode;
      }
    }
  }
  if (best_matches == 0) {
    state->entry_count = 0;
    return state;
  }

  uint64_t movi_type = layout->movi_type_offsets[selected_movi];
  uint64_t bases[4] = {0, movi_type, movi_type + 4,
                       movi_type >= 8 ? movi_type - 8 : 0};

  uint64_t stored = 0;
  for (uint64_t entry = 0; entry < idx_entries; entry++) {
    uint64_t position = idx_position + entry * AVI_INDEX_ENTRY_SIZE;
    uint32_t id = avi_read_le32(data + position);
    uint32_t relative = avi_read_le32(data + position + 8);
    uint64_t target;
    uint64_t matched_offset;

    if (!avi_is_media_chunk(id)) {
      continue;
    }
    if (__builtin_add_overflow(bases[selected_mode], (uint64_t)relative,
                               &target)) {
      break;
    }
    matched_offset = target;
    avi_index_entry_matches(
        data, length, target, id,
        avi_read_le32(data + position + 12), &matched_offset);
    state->entries[stored].offset = matched_offset;
    state->entries[stored].id = id;
    state->entries[stored].size = avi_read_le32(data + position + 12);
    stored++;
  }
  state->entry_count = stored;
  return state;
}


static inline bool avi_validate_indexed_prefix(
    const uint8_t *data, uint64_t length, const AviCarveState *state,
    uint64_t *failure_offset) {

  if (!data || !state || !failure_offset
      || state->magic != AVI_CARVE_STATE_MAGIC
      || state->version != AVI_CARVE_STATE_VERSION) {
    return false;
  }
  for (uint64_t entry = 0; entry < state->entry_count; entry++) {
    const AviStateIndexEntry *expected = &state->entries[entry];

    if (expected->offset >= length) {
      break;
    }
    if (!avi_range_available(length, expected->offset, AVI_CHUNK_HEADER_SIZE)) {
      *failure_offset = expected->offset;
      return false;
    }
    if (!avi_chunk_matches(data, length, expected->offset, expected->id,
                           expected->size)) {
      *failure_offset = expected->offset;
      return false;
    }
  }
  return true;
}


static inline bool avi_serialize_carve_state(void **state, FILE *fp,
                                             StateSerialization mode) {

  AviCarveState **avi_state = (AviCarveState **)state;
  AviCarveState header;
  size_t state_size;

  if (!avi_state || !fp) {
    return false;
  }
  if (mode == SERIALIZE) {
    if (!avi_carve_state_valid(*avi_state)
        || !avi_carve_state_size((*avi_state)->entry_count, &state_size)
        || fwrite(*avi_state, state_size, 1, fp) != 1) {
      perror("AVI carve state serialization");
      handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
    }
    return true;
  }

  memset(&header, 0, sizeof(header));
  const size_t legacy_size = offsetof(AviCarveState, block_search);

  if (fread(&header, legacy_size, 1, fp) != 1
      || header.magic != AVI_CARVE_STATE_MAGIC
      || (header.version != AVI_CARVE_STATE_VERSION
          && header.version != 7U && header.version != 6U
          && header.version != 5U && header.version != 4U
          && header.version != 3U && header.version != 2U)
      || header.archive_extent < AVI_RIFF_HEADER_SIZE
      || header.archive_extent > AVI_MAX_ARCHIVE_SIZE
      || header.initialized > 1
      || header.entry_count > UINT32_MAX / AVI_INDEX_ENTRY_SIZE
      || header.entry_count > header.archive_extent / AVI_INDEX_ENTRY_SIZE
      || !avi_carve_state_size(header.entry_count, &state_size)) {
    handle_error(SCALPEL_ERROR_CHECKPOINT, "invalid AVI carve state",
                 __LINE__, __FILE__);
  }
  if (header.version >= 3U
      && fread(&header.block_search, sizeof(header.block_search), 1, fp)
             != 1) {
    handle_error(SCALPEL_ERROR_CHECKPOINT, "invalid AVI block search state",
                 __LINE__, __FILE__);
  }
  if (header.version >= 4U
      && fread(&header.indexed_search, sizeof(header.indexed_search), 1, fp) != 1) {
    handle_error(SCALPEL_ERROR_CHECKPOINT, "invalid AVI indexed search state",
                 __LINE__, __FILE__);
  }
  if (header.version >= 5U
      && fread(header.zero_gap_search, sizeof(header.zero_gap_search), 1, fp) != 1) {
    handle_error(SCALPEL_ERROR_CHECKPOINT, "invalid AVI zero-gap search state",
                 __LINE__, __FILE__);
  }
  if (header.version >= 6U
      && fread(&header.classified_search, sizeof(header.classified_search), 1, fp) != 1) {
    handle_error(SCALPEL_ERROR_CHECKPOINT, "invalid AVI classified search state",
                 __LINE__, __FILE__);
  }
  if (header.version >= 7U
      && fread(&header.shift_search, sizeof(header.shift_search), 1, fp) != 1) {
    handle_error(SCALPEL_ERROR_CHECKPOINT, "invalid AVI shifted search state",
                 __LINE__, __FILE__);
  }
  if (header.version >= 8U
      && fread(&header.displaced_search, sizeof(header.displaced_search), 1, fp) != 1) {
    handle_error(SCALPEL_ERROR_CHECKPOINT, "invalid AVI displaced search state",
                 __LINE__, __FILE__);
  }
  header.version = AVI_CARVE_STATE_VERSION;
  *avi_state = (AviCarveState *)malloc(state_size);
  check_memory_allocation(*avi_state, __LINE__, __FILE__, "AviCarveState");
  memcpy(*avi_state, &header, offsetof(AviCarveState, entries));
  size_t entries_size = state_size - offsetof(AviCarveState, entries);

  if (entries_size > 0
      && fread((*avi_state)->entries, 1, entries_size, fp) != entries_size) {
    perror("AVI carve state deserialization");
    handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
  }
  if (!avi_carve_state_valid(*avi_state)) {
    handle_error(SCALPEL_ERROR_CHECKPOINT, "invalid AVI carve state",
                 __LINE__, __FILE__);
  }
  return true;
}


static inline void *avi_clone_carve_state(const void *srcstate) {

  const AviCarveState *source = (const AviCarveState *)srcstate;
  size_t state_size;

  if (!avi_carve_state_valid(source)
      || !avi_carve_state_size(source->entry_count, &state_size)) {
    return NULL;
  }
  AviCarveState *destination = (AviCarveState *)malloc(state_size);

  check_memory_allocation(destination, __LINE__, __FILE__,
                          "AviCarveState clone");
  memcpy(destination, source, state_size);
  return destination;
}


static inline void avi_free_carve_state(void **state) {

  if (state) {
    free(*state);
    *state = NULL;
  }
}


static inline void avi_print_carve_state(const void *state) {

  const AviCarveState *avi_state = (const AviCarveState *)state;

  if (!avi_state) {
    fprintf(stdout, "NULL");
    return;
  }
  fprintf(stdout, "extent=%" PRIu64 " indexed-chunks=%" PRIu64,
          avi_state->archive_extent, avi_state->entry_count);
}


static inline bool avi_parse_main_header(AviParser *parser, uint64_t offset,
                                         uint32_t size) {

  if (size < AVI_MAIN_HEADER_SIZE || parser->layout->saw_main_header) {
    return avi_parser_fail(parser, offset);
  }
  uint32_t streams = avi_read_le32(parser->data + offset + 24);
  uint32_t width = avi_read_le32(parser->data + offset + 32);
  uint32_t height = avi_read_le32(parser->data + offset + 36);

  if (streams == 0 || streams > AVI_MAX_STREAMS
      || width > UINT32_C(1048576) || height > UINT32_C(1048576)) {
    return avi_parser_fail(parser, offset);
  }
  parser->layout->main_flags = avi_read_le32(parser->data + offset + 12);
  parser->layout->main_streams = streams;
  parser->layout->saw_main_header = true;
  return true;
}


static inline bool avi_parse_stream_header(AviParser *parser,
                                           uint32_t stream_index,
                                           uint64_t offset, uint32_t size) {

  if (stream_index >= AVI_MAX_STREAMS || size < AVI_STREAM_HEADER_SIZE) {
    return avi_parser_fail(parser, offset);
  }
  AviStream *stream = &parser->layout->streams[stream_index];
  stream->type = avi_read_le32(parser->data + offset);
  stream->handler = avi_read_le32(parser->data + offset + 4);
  stream->scale = avi_read_le32(parser->data + offset + 20);
  stream->rate = avi_read_le32(parser->data + offset + 24);
  stream->length = avi_read_le32(parser->data + offset + 32);

  if (stream->saw_header
      || (stream->type != AVI_FOURCC('v', 'i', 'd', 's')
          && stream->type != AVI_FOURCC('a', 'u', 'd', 's')
          && stream->type != AVI_FOURCC('t', 'x', 't', 's')
          && stream->type != AVI_FOURCC('m', 'i', 'd', 's'))
      || ((stream->type == AVI_FOURCC('v', 'i', 'd', 's')
           || stream->type == AVI_FOURCC('a', 'u', 'd', 's'))
          && (stream->scale == 0 || stream->rate == 0))) {
    return avi_parser_fail(parser, offset);
  }
  stream->saw_header = true;
  return true;
}


static inline bool avi_parse_stream_format(AviParser *parser,
                                           uint32_t stream_index,
                                           uint64_t offset, uint32_t size) {

  if (stream_index >= AVI_MAX_STREAMS
      || !parser->layout->streams[stream_index].saw_header) {
    return avi_parser_fail(parser, offset);
  }
  AviStream *stream = &parser->layout->streams[stream_index];
  if (stream->saw_format) {
    return avi_parser_fail(parser, offset);
  }

  if (stream->type == AVI_FOURCC('v', 'i', 'd', 's')) {
    if (size < AVI_BITMAP_HEADER_SIZE
        || avi_read_le32(parser->data + offset) < AVI_BITMAP_HEADER_SIZE) {
      return avi_parser_fail(parser, offset);
    }
    int32_t width = (int32_t)avi_read_le32(parser->data + offset + 4);
    int32_t height = (int32_t)avi_read_le32(parser->data + offset + 8);
    uint16_t planes = avi_read_le16(parser->data + offset + 12);

    if (width == 0 || height == 0 || planes != 1) {
      return avi_parser_fail(parser, offset);
    }
    stream->width = (uint32_t)(width < 0 ? -(int64_t)width : width);
    stream->height = (uint32_t)(height < 0 ? -(int64_t)height : height);
    stream->bits_per_sample = avi_read_le16(parser->data + offset + 14);
    stream->compression = avi_read_le32(parser->data + offset + 16);
    bool ffv1 = stream->handler == AVI_FOURCC('F', 'F', 'V', '1')
        || stream->compression == AVI_FOURCC('F', 'F', 'V', '1');

    if (ffv1 && size > AVI_BITMAP_HEADER_SIZE) {
      stream->ffv1_crc = avi_ffv1_configuration_has_crc(
          parser->data + offset + AVI_BITMAP_HEADER_SIZE,
          size - AVI_BITMAP_HEADER_SIZE);
    }
  }
  else if (stream->type == AVI_FOURCC('a', 'u', 'd', 's')) {
    if (size < AVI_WAVE_FORMAT_SIZE) {
      return avi_parser_fail(parser, offset);
    }
    stream->format_tag = avi_read_le16(parser->data + offset);
    stream->channels = avi_read_le16(parser->data + offset + 2);
    stream->block_align = avi_read_le16(parser->data + offset + 12);
    stream->bits_per_sample = avi_read_le16(parser->data + offset + 14);
    if (stream->format_tag == 0 || stream->channels == 0
        || avi_read_le32(parser->data + offset + 4) == 0
        || stream->block_align == 0) {
      return avi_parser_fail(parser, offset);
    }
  }
  stream->saw_format = true;
  return true;
}


static inline bool avi_validate_media_payload(AviParser *parser, uint32_t id,
                                              uint64_t offset,
                                              uint32_t size) {

  int32_t stream_number = avi_stream_number(id);
  if (stream_number < 0
      || (uint32_t)stream_number >= parser->layout->stream_count) {
    return avi_parser_fail(parser, offset);
  }
  parser->layout->media_chunks++;
  if (size == 0) {
    return true;
  }

  AviStream *stream = &parser->layout->streams[stream_number];
  const uint8_t *payload = parser->data + offset;
  bool jpeg = stream->handler == AVI_FOURCC('M', 'J', 'P', 'G')
      || stream->handler == AVI_FOURCC('J', 'P', 'E', 'G')
      || stream->handler == AVI_FOURCC('d', 'm', 'b', '1')
      || stream->compression == AVI_FOURCC('M', 'J', 'P', 'G')
      || stream->compression == AVI_FOURCC('J', 'P', 'E', 'G')
      || stream->compression == AVI_FOURCC('d', 'm', 'b', '1');
  bool png = stream->handler == AVI_FOURCC('M', 'P', 'N', 'G')
      || stream->handler == AVI_FOURCC('P', 'N', 'G', ' ')
      || stream->compression == AVI_FOURCC('M', 'P', 'N', 'G')
      || stream->compression == AVI_FOURCC('P', 'N', 'G', ' ');
  bool trusted_payload = offset <= parser->payload_validation_from
      && (uint64_t)size <= parser->payload_validation_from - offset;

  stream->media_chunks++;

  // Trial mappings do not alter media before this boundary. Retain its established evidence while
  // continuing to parse every chunk header; complete candidates are revalidated from byte zero.
  if (trusted_payload) {
    if (jpeg || png) {
      parser->layout->payloads_proven++;
    }
    else {
      parser->layout->opaque_payloads++;
    }
    return true;
  }

  if (jpeg) {
    bool complete;
    uint64_t failure_offset = 0;
    bool prefix_valid = avi_validate_jpeg_prefix(
        payload, size, size, &complete, &failure_offset);
    bool decode_valid = true;

    if (prefix_valid && complete && parser->deep_payload_validation) {
      decode_valid = avi_decode_jpeg_payload(
          payload, size, stream->width, stream->height, &failure_offset);
    }
    if (!prefix_valid || !complete || !decode_valid) {
      parser->layout->failure_media_offset = offset;
      parser->layout->failure_media_end = offset + size + (size & 1U);
      return avi_parser_fail(parser, offset + failure_offset);
    }
    parser->layout->payloads_proven++;
    return true;
  }
  if (png) {
    bool complete;
    uint64_t failure_offset = 0;

    if (!avi_validate_png_prefix(payload, size, size, &complete,
                                 &failure_offset)
        || !complete) {
      parser->layout->failure_media_offset = offset;
      parser->layout->failure_media_end = offset + size + (size & 1U);
      return avi_parser_fail(parser, offset + failure_offset);
    }
    parser->layout->payloads_proven++;
    return true;
  }
  if (stream->ffv1_crc) {
    parser->layout->ffv1_crc_slices +=
        avi_count_ffv1_crc_suffix_slices(payload, size);
    parser->layout->opaque_payloads++;
    return true;
  }
  if (stream->type == AVI_FOURCC('a', 'u', 'd', 's')
      && stream->format_tag == UINT16_C(0x0055)
      && avi_validate_mp3_payload(payload, size)) {
    // Frame structure identifies MP3 data but cannot prove arbitrary payload bytes.
    parser->layout->opaque_payloads++;
    return true;
  }
  if (stream->type == AVI_FOURCC('v', 'i', 'd', 's')
      && avi_has_mpeg_start_code(payload, size)) {
    // A start code identifies an MPEG frame but does not validate its compressed payload bytes.
    parser->layout->opaque_payloads++;
    return true;
  }
  if (stream->type == AVI_FOURCC('a', 'u', 'd', 's')
      && stream->block_align != 0 && size % stream->block_align == 0) {
    // Block alignment verifies container structure, not the contents of raw audio samples.
    parser->layout->opaque_payloads++;
    return true;
  }
  parser->layout->opaque_payloads++;
  return true;
}


static inline bool avi_validate_partial_media_payload(
    AviParser *parser, uint32_t id, uint64_t offset, uint64_t available,
    uint32_t size) {

  int32_t stream_number = avi_stream_number(id);

  if (stream_number < 0
      || (uint32_t)stream_number >= parser->layout->stream_count
      || available > size) {
    return avi_parser_fail(parser, offset);
  }
  parser->layout->media_chunks++;
  if (available == 0) {
    return true;
  }

  AviStream *stream = &parser->layout->streams[stream_number];
  const uint8_t *payload = parser->data + offset;
  bool jpeg = stream->handler == AVI_FOURCC('M', 'J', 'P', 'G')
      || stream->handler == AVI_FOURCC('J', 'P', 'E', 'G')
      || stream->handler == AVI_FOURCC('d', 'm', 'b', '1')
      || stream->compression == AVI_FOURCC('M', 'J', 'P', 'G')
      || stream->compression == AVI_FOURCC('J', 'P', 'E', 'G')
      || stream->compression == AVI_FOURCC('d', 'm', 'b', '1');
  bool png = stream->handler == AVI_FOURCC('M', 'P', 'N', 'G')
      || stream->handler == AVI_FOURCC('P', 'N', 'G', ' ')
      || stream->compression == AVI_FOURCC('M', 'P', 'N', 'G')
      || stream->compression == AVI_FOURCC('P', 'N', 'G', ' ');
  bool complete;
  uint64_t failure_offset = 0;

  stream->media_chunks++;

  if (jpeg) {
    if (!avi_validate_jpeg_prefix(payload, available, size, &complete,
                                  &failure_offset)) {
      parser->layout->failure_media_offset = offset;
      parser->layout->failure_media_end = offset + size + (size & 1U);
      return avi_parser_fail(parser, offset + failure_offset);
    }
    if (complete) {
      parser->layout->payloads_proven++;
    }
    return true;
  }
  if (png) {
    if (!avi_validate_png_prefix(payload, available, size, &complete,
                                 &failure_offset)) {
      parser->layout->failure_media_offset = offset;
      parser->layout->failure_media_end = offset + size + (size & 1U);
      return avi_parser_fail(parser, offset + failure_offset);
    }
    if (complete) {
      parser->layout->payloads_proven++;
    }
    return true;
  }
  parser->layout->opaque_payloads++;
  return true;
}


static inline bool avi_prepare_list(AviParser *parser, uint32_t list_type,
                                    uint64_t payload, int32_t stream_index,
                                    bool inside_movi, int32_t *child_stream,
                                    bool *child_movi) {

  if (!parser || !child_stream || !child_movi) {
    return false;
  }
  *child_stream = stream_index;
  *child_movi = inside_movi;
  if (list_type == AVI_FOURCC('h', 'd', 'r', 'l')) {
    parser->layout->saw_hdrl = true;
  }
  else if (list_type == AVI_FOURCC('s', 't', 'r', 'l')) {
    if (parser->layout->stream_count >= AVI_MAX_STREAMS) {
      return avi_parser_fail(parser, payload);
    }
    *child_stream = (int32_t)parser->layout->stream_count++;
  }
  else if (list_type == AVI_FOURCC('m', 'o', 'v', 'i')) {
    if (parser->layout->movi_count >= AVI_MAX_MOVI_LISTS) {
      return avi_parser_fail(parser, payload);
    }
    parser->layout->movi_type_offsets[parser->layout->movi_count++] =
        payload;
    parser->layout->saw_movi = true;
    *child_movi = true;
  }
  else if (list_type == AVI_FOURCC('r', 'e', 'c', ' ')) {
    *child_movi = true;
  }
  return true;
}


static inline bool avi_parse_region(AviParser *parser, uint64_t start,
                                    uint64_t end, int32_t stream_index,
                                    bool inside_movi, uint32_t depth) {

  uint64_t position = start;
  uint64_t previous_media_offset = UINT64_MAX;
  uint64_t previous_media_end = UINT64_MAX;

  if (depth > AVI_MAX_RECURSION_DEPTH || end > parser->length) {
    return avi_parser_fail(parser, start);
  }

  while (position < end) {
    if (!avi_range_available(end, position, AVI_CHUNK_HEADER_SIZE)) {
      parser->layout->failure_offset = end;
      return false;
    }
    uint32_t id = avi_read_le32(parser->data + position);
    uint32_t size = avi_read_le32(parser->data + position + 4);
    uint64_t payload = position + AVI_CHUNK_HEADER_SIZE;
    uint64_t payload_end;
    uint64_t next;

    if (!avi_chunk_id_printable(id)
        || __builtin_add_overflow(payload, (uint64_t)size, &payload_end)
        || __builtin_add_overflow(payload_end, (uint64_t)(size & 1U),
                                  &next)) {
      // A whole-block insertion inside opaque media is first visible when the following chunk
      // header is displaced. Retain the preceding media span as the bounded repair window.
      if (inside_movi && previous_media_offset != UINT64_MAX) {
        parser->layout->failure_media_offset = previous_media_offset;
        parser->layout->failure_media_end = previous_media_end;
      }
      return avi_parser_fail(parser, position);
    }
    if (payload_end > end) {
      if (payload_end > parser->layout->required_extent) {
        parser->layout->required_extent = payload_end;
      }
      if (id == AVI_FOURCC('L', 'I', 'S', 'T')
          && avi_range_available(end, payload, sizeof(uint32_t))) {
        uint32_t list_type = avi_read_le32(parser->data + payload);
        int32_t child_stream;
        bool child_movi;

        if (!avi_prepare_list(parser, list_type, payload, stream_index,
                              inside_movi, &child_stream, &child_movi)) {
          return false;
        }
        if (!avi_parse_region(parser, payload + sizeof(uint32_t), end,
                              child_stream, child_movi, depth + 1)) {
          return false;
        }
      }
      else if (inside_movi && avi_is_media_chunk(id)
               && !avi_validate_partial_media_payload(
                   parser, id, payload, end - payload, size)) {
        return false;
      }
      else if (inside_movi && avi_is_media_chunk(id)) {
        parser->layout->failure_media_offset = payload;
        parser->layout->failure_media_end = next;
      }
      parser->layout->failure_offset = end;
      return false;
    }

    if (id == AVI_FOURCC('L', 'I', 'S', 'T')) {
      if (size < sizeof(uint32_t)) {
        return avi_parser_fail(parser, position);
      }
      uint32_t list_type = avi_read_le32(parser->data + payload);
      int32_t child_stream;
      bool child_movi;
      bool structural_list = list_type == AVI_FOURCC('h', 'd', 'r', 'l')
          || list_type == AVI_FOURCC('s', 't', 'r', 'l')
          || list_type == AVI_FOURCC('m', 'o', 'v', 'i')
          || list_type == AVI_FOURCC('r', 'e', 'c', ' ');

      if (!avi_prepare_list(parser, list_type, payload, stream_index,
                            inside_movi, &child_stream, &child_movi)
          || (structural_list
              && !avi_parse_region(
                  parser, payload + sizeof(uint32_t), payload_end,
                  child_stream, child_movi, depth + 1))) {
        return false;
      }
    }
    else if (id == AVI_FOURCC('a', 'v', 'i', 'h')) {
      if (!avi_parse_main_header(parser, payload, size)) {
        return false;
      }
    }
    else if (id == AVI_FOURCC('s', 't', 'r', 'h')) {
      if (stream_index < 0
          || !avi_parse_stream_header(parser, (uint32_t)stream_index,
                                      payload, size)) {
        return avi_parser_fail(parser, position);
      }
    }
    else if (id == AVI_FOURCC('s', 't', 'r', 'f')) {
      if (stream_index < 0
          || !avi_parse_stream_format(parser, (uint32_t)stream_index,
                                      payload, size)) {
        return avi_parser_fail(parser, position);
      }
    }
    else if (id == AVI_FOURCC('i', 'd', 'x', '1')) {
      if (!avi_validate_idx1(parser, payload, size)) {
        return false;
      }
    }
    else if (id == AVI_FOURCC('i', 'n', 'd', 'x')) {
      if (!avi_validate_super_index(parser, payload, size)) {
        return false;
      }
    }
    else if ((id & UINT32_C(0x0000ffff))
             == AVI_FOURCC('i', 'x', 0, 0)) {
      if (!avi_validate_standard_index(parser, id, payload, size)) {
        return false;
      }
    }
    else if (inside_movi && avi_is_media_chunk(id)) {
      if (!avi_validate_media_payload(parser, id, payload, size)) {
        return false;
      }
      previous_media_offset = payload;
      previous_media_end = next;
    }

    if (next > end) {
      if (next > parser->layout->required_extent) {
        parser->layout->required_extent = next;
      }
      parser->layout->failure_offset = end;
      return false;
    }

    position = next;
    parser->layout->failure_offset = position;
    if ((parser->layout->media_chunks & 255U) == 0
        && avi_parser_stop_requested(parser)) {
      return avi_parser_fail(parser, position);
    }
  }
  return position == end;
}


static inline bool avi_parse_segment(AviParser *parser, uint64_t offset,
                                     uint32_t expected_form,
                                     uint64_t *next_offset) {

  if (!avi_range_available(parser->length, offset, AVI_RIFF_HEADER_SIZE)
      || avi_read_le32(parser->data + offset) != AVI_FOURCC('R', 'I', 'F', 'F')
      || avi_read_le32(parser->data + offset + 8) != expected_form) {
    return avi_parser_fail(parser, offset);
  }
  uint32_t size = avi_read_le32(parser->data + offset + 4);
  uint64_t segment_end;
  uint64_t padded_end;

  if (size < sizeof(uint32_t)
      || __builtin_add_overflow(offset + AVI_CHUNK_HEADER_SIZE,
                                (uint64_t)size, &segment_end)) {
    return avi_parser_fail(parser, offset);
  }
  uint64_t available_end = segment_end < parser->length
      ? segment_end : parser->length;

  if (!avi_parse_region(parser, offset + AVI_RIFF_HEADER_SIZE, available_end,
                        -1, false, 0)) {
    return false;
  }
  if (segment_end > parser->length) {
    parser->layout->required_extent = segment_end;
    parser->layout->failure_offset = parser->length;
    return false;
  }
  padded_end = segment_end;
  if ((size & 1U) != 0 && segment_end < parser->length) {
    padded_end++;
  }
  parser->layout->riff_segments++;
  parser->layout->described_extent = padded_end;
  *next_offset = padded_end;
  return true;
}


// Decode codec-validated media in every structurally readable prefix. A later RIFF break must not
// hide an earlier corrupt frame, because reassembly must always repair the earliest proven error.
static inline bool avi_deep_validate_prefix(const uint8_t *data,
                                            uint64_t length,
                                            uint64_t payload_validation_from,
                                            AviLayout *layout) {

  if (!data || !layout) {
    return false;
  }
  AviLayout deep_layout;
  AviParser deep_parser;
  uint64_t next = 0;
  bool complete;

  memset(&deep_layout, 0, sizeof(deep_layout));
  deep_layout.failure_offset = UINT64_MAX;
  deep_layout.failure_media_offset = UINT64_MAX;
  deep_layout.failure_media_end = UINT64_MAX;
  deep_layout.super_index_failure_offset = UINT64_MAX;
  deep_parser.data = data;
  deep_parser.length = length;
  deep_parser.layout = &deep_layout;
  deep_parser.payload_validation_from = payload_validation_from;
  deep_parser.deep_payload_validation = true;
  complete = avi_parse_segment(&deep_parser, 0,
                               AVI_FOURCC('A', 'V', 'I', ' '), &next);
  while (complete && avi_range_available(length, next,
                                         AVI_RIFF_HEADER_SIZE)
         && avi_read_le32(data + next) == AVI_FOURCC('R', 'I', 'F', 'F')
         && avi_read_le32(data + next + 8)
                == AVI_FOURCC('A', 'V', 'I', 'X')) {
    complete = avi_parse_segment(&deep_parser, next,
                                 AVI_FOURCC('A', 'V', 'I', 'X'), &next);
  }
  if (deep_layout.interrupted) {
    layout->interrupted = true;
  }
  if (deep_layout.failure_offset != UINT64_MAX
      && (layout->failure_offset == UINT64_MAX
          || deep_layout.failure_offset < layout->failure_offset)) {
    layout->failure_offset = deep_layout.failure_offset;
    layout->failure_media_offset = deep_layout.failure_media_offset;
    layout->failure_media_end = deep_layout.failure_media_end;
  }
  return complete && !deep_layout.interrupted;
}


static inline AviParseResult avi_parse_file(const uint8_t *data,
                                            uint64_t length,
                                            uint64_t payload_validation_from,
                                            AviLayout *layout) {

  AviParser parser;
  uint64_t next = 0;
  uint32_t active_streams = 0;

  if (!layout) {
    return AVI_PARSE_INVALID;
  }
  memset(layout, 0, sizeof(*layout));
  layout->failure_offset = UINT64_MAX;
  layout->failure_media_offset = UINT64_MAX;
  layout->failure_media_end = UINT64_MAX;
  layout->super_index_failure_offset = UINT64_MAX;
  if (!data || length < AVI_RIFF_HEADER_SIZE
      || avi_read_le32(data) != AVI_FOURCC('R', 'I', 'F', 'F')
      || avi_read_le32(data + 8) != AVI_FOURCC('A', 'V', 'I', ' ')) {
    return AVI_PARSE_INVALID;
  }
  layout->header_valid = true;
  parser.data = data;
  parser.length = length;
  parser.layout = layout;
  parser.payload_validation_from = payload_validation_from;
  parser.deep_payload_validation = false;

  if (!avi_parse_segment(&parser, 0, AVI_FOURCC('A', 'V', 'I', ' '),
                         &next)) {
    if (layout->payloads_proven > 0) {
      avi_deep_validate_prefix(data, length, payload_validation_from, layout);
    }
    return AVI_PARSE_PARTIAL;
  }
  while (avi_range_available(length, next, AVI_RIFF_HEADER_SIZE)
         && avi_read_le32(data + next) == AVI_FOURCC('R', 'I', 'F', 'F')
         && avi_read_le32(data + next + 8) == AVI_FOURCC('A', 'V', 'I', 'X')) {
    if (!avi_parse_segment(&parser, next, AVI_FOURCC('A', 'V', 'I', 'X'),
                           &next)) {
      if (layout->payloads_proven > 0) {
        avi_deep_validate_prefix(data, length, payload_validation_from,
                                 layout);
      }
      return AVI_PARSE_PARTIAL;
    }
  }

  if (layout->interrupted || !layout->saw_hdrl || !layout->saw_main_header
      || !layout->saw_movi || layout->stream_count == 0
      || layout->main_streams > layout->stream_count
      || layout->media_chunks == 0) {
    return AVI_PARSE_PARTIAL;
  }
  for (uint32_t stream = 0; stream < layout->stream_count; stream++) {
    if (!layout->streams[stream].saw_header
        || ((layout->streams[stream].type == AVI_FOURCC('v', 'i', 'd', 's')
             || layout->streams[stream].type
                    == AVI_FOURCC('a', 'u', 'd', 's'))
            && !layout->streams[stream].saw_format)) {
      return AVI_PARSE_PARTIAL;
    }
    if (layout->streams[stream].media_chunks > 0) {
      active_streams++;
    }
  }
  if (active_streams > layout->main_streams) {
    return AVI_PARSE_PARTIAL;
  }
  if ((layout->main_flags & AVI_FLAG_HAS_INDEX) != 0
      && !layout->saw_legacy_index && layout->super_indexes == 0
      && layout->standard_indexes == 0) {
    return AVI_PARSE_PARTIAL;
  }
  if (layout->required_extent > layout->described_extent) {
    layout->failure_offset = layout->described_extent;
    return AVI_PARSE_PARTIAL;
  }
  if (layout->super_index_entries_verified
      != layout->super_index_entries) {
    layout->failure_offset = layout->super_index_failure_offset;
    return AVI_PARSE_PARTIAL;
  }
  if (layout->payloads_proven > 0) {
    if (!avi_deep_validate_prefix(data, length, payload_validation_from,
                                  layout)) {
      return AVI_PARSE_PARTIAL;
    }
  }
  layout->failure_offset = UINT64_MAX;
  return AVI_PARSE_COMPLETE;
}


static inline char *avi_header_discovery(char *base, uint64_t offset,
                                         uint64_t remaining, char **matchpos,
                                         uint32_t *matchlen,
                                         uint32_t blocksize) {

  (void)blocksize;
  if (!base || !matchpos || !matchlen) {
    return NULL;
  }
  *matchpos = NULL;
  *matchlen = AVI_RIFF_HEADER_SIZE;
  if (remaining < AVI_RIFF_HEADER_SIZE) {
    return NULL;
  }

  uint8_t *search = (uint8_t *)base + offset;
  uint64_t available = remaining;
  while (available >= AVI_RIFF_HEADER_SIZE) {
    uint8_t *found = (uint8_t *)memchr(search, 'R', (size_t)available);
    if (!found) {
      break;
    }
    uint64_t consumed = (uint64_t)(found - search);
    available -= consumed;
    if (available >= AVI_RIFF_HEADER_SIZE
        && avi_read_le32(found) == AVI_FOURCC('R', 'I', 'F', 'F')
        && avi_read_le32(found + 8) == AVI_FOURCC('A', 'V', 'I', ' ')
        && avi_read_le32(found + 4) >= sizeof(uint32_t)) {
      *matchpos = (char *)found;
      return NULL;
    }
    search = found + 1;
    available--;
  }
  return NULL;
}


// RIFF has no terminal signature. Report a synthetic footer one byte after each AVI/AVIX RIFF
// header and use its declared segment size as the match length. This lets contiguous carving build
// a bounded candidate without reading MAXIMUMSIZE bytes before the validator can trim it. The most
// distant matching AVIX segment also supplies the end of an OpenDML file.
static inline char *avi_footer_discovery(char *base, uint64_t offset,
                                         uint64_t remaining, char **matchpos,
                                         uint32_t *matchlen,
                                         uint32_t blocksize) {

  (void)blocksize;
  if (!base || !matchpos || !matchlen) {
    return NULL;
  }
  *matchpos = NULL;
  *matchlen = 0;
  if (remaining < AVI_RIFF_HEADER_SIZE) {
    return NULL;
  }

  uint8_t *search = (uint8_t *)base + offset;
  uint64_t available = remaining;
  while (available >= AVI_RIFF_HEADER_SIZE) {
    uint8_t *found = (uint8_t *)memchr(search, 'R', (size_t)available);
    if (!found) {
      break;
    }
    uint64_t consumed = (uint64_t)(found - search);
    available -= consumed;
    if (available >= AVI_RIFF_HEADER_SIZE
        && avi_read_le32(found) == AVI_FOURCC('R', 'I', 'F', 'F')) {
      uint32_t form = avi_read_le32(found + 8);
      uint64_t segment_length = (uint64_t)avi_read_le32(found + 4)
          + AVI_CHUNK_HEADER_SIZE;

      if ((form == AVI_FOURCC('A', 'V', 'I', ' ')
           || form == AVI_FOURCC('A', 'V', 'I', 'X'))
          && segment_length >= AVI_RIFF_HEADER_SIZE
          && segment_length - 1 <= UINT32_MAX) {
        *matchpos = (char *)found + 1;
        *matchlen = (uint32_t)(segment_length - 1);
        return NULL;
      }
    }
    search = found + 1;
    available--;
  }
  return NULL;
}


static inline uint32_t avi_block_validate(
    char *data, uint64_t length, BlockValidationDecision *decision,
    uint64_t *validates_to, uint32_t needleidx, uint32_t blocksize,
    void *blockhashkey) {

  (void)blocksize;
  (void)blockhashkey;
  if (!data || !decision || !validates_to || length == 0) {
    return needleidx;
  }
  if (*decision == BLOCK_CONFIDENCE_INVALID) {
    *decision = BLOCK_CONFIDENCE_LOW;
  }
  *validates_to = length - 1;

  const uint8_t *bytes = (const uint8_t *)data;
  bool avi_evidence_found = false;
  for (uint64_t position = 0; position + AVI_CHUNK_HEADER_SIZE <= length;
       position++) {
    uint32_t id = avi_read_le32(bytes + position);
    bool strong = false;

    if (id == AVI_FOURCC('R', 'I', 'F', 'F')
        && position + AVI_RIFF_HEADER_SIZE <= length) {
      uint32_t form = avi_read_le32(bytes + position + 8);
      strong = form == AVI_FOURCC('A', 'V', 'I', ' ')
          || form == AVI_FOURCC('A', 'V', 'I', 'X');
    }
    else if (id == AVI_FOURCC('L', 'I', 'S', 'T')
             && position + AVI_RIFF_HEADER_SIZE <= length) {
      uint32_t type = avi_read_le32(bytes + position + 8);
      strong = type == AVI_FOURCC('h', 'd', 'r', 'l')
          || type == AVI_FOURCC('s', 't', 'r', 'l')
          || type == AVI_FOURCC('m', 'o', 'v', 'i')
          || type == AVI_FOURCC('r', 'e', 'c', ' ');
    }
    else {
      strong = id == AVI_FOURCC('a', 'v', 'i', 'h')
          || id == AVI_FOURCC('s', 't', 'r', 'h')
          || id == AVI_FOURCC('s', 't', 'r', 'f')
          || id == AVI_FOURCC('i', 'd', 'x', '1')
          || id == AVI_FOURCC('i', 'n', 'd', 'x')
          || (id & UINT32_C(0x0000ffff)) == AVI_FOURCC('i', 'x', 0, 0);
      strong = strong || avi_is_media_chunk(id);
    }
    if (strong) {
      avi_evidence_found = true;
      break;
    }
  }
  // AVI structure proves file type, but not that a block belongs in the current reassembly slot.
  // Keep all AVI confidence below LR's unconditional-accept value so adjacency can preserve runs.
  if (avi_evidence_found || *decision == BLOCK_CONFIDENCE_VALID) {
    *decision = (BlockValidationDecision)AVI_PAYLOAD_CONFIDENCE_MAX;
  }
  return needleidx;
}


static inline void avi_file_validate(char *data, uint64_t length,
                                     bool *validates, uint64_t *validates_to,
                                     bool *promising, uint32_t needleidx,
                                     uint32_t blocksize, void *carvehashkey) {

  (void)needleidx;
  (void)blocksize;
  if (!validates || !validates_to || !promising) {
    return;
  }
  *validates = false;
  *validates_to = 0;
  *promising = false;

  AviLayout layout;
  AviParseResult result = avi_parse_file((const uint8_t *)data, length, 0,
                                         &layout);
  AviCarveState *state = carvehashkey
      ? (AviCarveState *)carve_get_state(carvehashkey) : NULL;

  if (result == AVI_PARSE_INVALID) {
    avi_free_carve_state((void **)&state);
    return;
  }
  if (!state && carvehashkey) {
    state = avi_capture_legacy_index((const uint8_t *)data, length, &layout);
    if (state) {
      carve_put_state(carvehashkey, state);
    }
  }
  if (state) {
    uint64_t index_failure = length;

    if (!avi_validate_indexed_prefix((const uint8_t *)data, length, state,
                                     &index_failure)) {
      result = AVI_PARSE_PARTIAL;
      if (layout.failure_offset == UINT64_MAX
          || index_failure < layout.failure_offset) {
        layout.failure_offset = index_failure;
      }
    }
  }
  *promising = true;
  if (layout.failure_offset == UINT64_MAX) {
    *validates_to = AVI_RIFF_HEADER_SIZE - 1;
  }
  else if (layout.failure_offset > 0) {
    *validates_to = layout.failure_offset - 1;
  }
  if (result == AVI_PARSE_COMPLETE && layout.described_extent > 0) {
    *validates_to = layout.described_extent - 1;
    if (scalpel_state.no_defrag || layout.opaque_payloads == 0) {
      *validates = true;
      *promising = false;
    }
  }
  avi_free_carve_state((void **)&state);
}


static inline bool avi_reassembly_initialize_candidate(
    CarveInfo *candidate, AviCarveState *state) {

  if (!candidate || !candidate->b || !state || state->archive_extent == 0
      || scalpel_state.blocksize == 0
      || blockvector_get_num_blocks(candidate->b) == 0) {
    return false;
  }

  uint64_t total_blocks = CEILDIV(state->archive_extent,
                                  scalpel_state.blocksize);
  uint64_t image_blocks = CEILDIV(
      filemirror_filesize(scalpel_state.filemirror), scalpel_state.blocksize);
  uint64_t candidate_blocks = blockvector_get_num_blocks(candidate->b);
  int64_t header_actual = blockvector_get_actual_blocknumber(candidate->b, 0);

  if (header_actual < 0 || total_blocks == 0 || total_blocks > image_blocks
      || (uint64_t)header_actual >= image_blocks) {
    return false;
  }
  resize_blockvector(candidate->b, total_blocks);
  if (!state->initialized) {
    uint64_t retained_blocks = candidate_blocks < total_blocks
        ? candidate_blocks : total_blocks;
    int64_t next_apparent = -1;

    // Contiguous carving already expresses the best available logical prefix in apparent block
    // order. Preserve it and extend only the RIFF-declared tail.
    if (retained_blocks > 0) {
      int64_t tail_apparent = blockvector_get_apparent_blocknumber(
          candidate->b, retained_blocks - 1);

      if (tail_apparent >= 0 && tail_apparent < INT64_MAX) {
        next_apparent = tail_apparent + 1;
      }
    }
    uint64_t apparent_blocks = filemirror_apparent_blocks(
        scalpel_state.filemirror);

    for (uint64_t slot = retained_blocks; slot < total_blocks; slot++) {
      int64_t apparent = next_apparent >= 0
              && (uint64_t)next_apparent < apparent_blocks
          ? next_apparent : -1;

      blockvector_set_apparent_blocknumber(candidate->b, slot, apparent);
      if (next_apparent >= 0 && next_apparent < INT64_MAX) {
        next_apparent++;
      }
    }
    state->initialized = 1;
    carve_put_state(candidate->carvehashkey, state);
  }
  inflate_blockvector(candidate->b);
  blockvector_set_data_length(candidate->b, state->archive_extent);
  return true;
}


static inline AviTrialResult avi_reassembly_validate_candidate(
    CarveInfo *candidate, const AviCarveState *state,
    bool *validates, uint64_t *validates_to, uint64_t *repair_from,
    uint64_t *repair_end, uint64_t payload_validation_from) {

  if (!candidate || !candidate->b || !state || !validates
      || !validates_to) {
    return AVI_TRIAL_ERROR;
  }
  const uint8_t *data = (const uint8_t *)blockvector_get_data_pointer(
      candidate->b);
  uint64_t length = blockvector_get_data_length(candidate->b);
  AviLayout layout;
  AviParseResult result = avi_parse_file(data, length,
                                         payload_validation_from, &layout);

  *validates = false;
  *validates_to = 0;
  if (repair_from) {
    *repair_from = 0;
  }
  if (repair_end) {
    *repair_end = 0;
  }
  if (layout.interrupted) {
    return AVI_TRIAL_INTERRUPTED;
  }
  if (result == AVI_PARSE_INVALID) {
    return AVI_TRIAL_READY;
  }
  uint64_t index_failure = length;

  if (!avi_validate_indexed_prefix(data, length, state, &index_failure)) {
    result = AVI_PARSE_PARTIAL;
    if (layout.failure_offset == UINT64_MAX
        || index_failure < layout.failure_offset) {
      layout.failure_offset = index_failure;
    }
  }
  // A trial may reuse codec evidence from its unchanged prefix. Before accepting a complete
  // candidate, decode that prefix once so every byte still crosses the normal validation boundary.
  if (result == AVI_PARSE_COMPLETE && payload_validation_from > 0) {
    AviLayout complete_layout;

    result = avi_parse_file(data, length, 0, &complete_layout);
    layout = complete_layout;
    if (layout.interrupted) {
      return AVI_TRIAL_INTERRUPTED;
    }
  }
  if (layout.failure_offset == UINT64_MAX) {
    *validates_to = AVI_RIFF_HEADER_SIZE - 1;
  }
  else if (layout.failure_offset > 0) {
    *validates_to = layout.failure_offset - 1;
  }
  if (repair_from && layout.failure_offset != UINT64_MAX) {
    *repair_from = layout.failure_offset;
    if (layout.failure_media_offset != UINT64_MAX
        && layout.failure_media_offset <= layout.failure_offset) {
      *repair_from = layout.failure_media_offset;
    }
  }
  if (repair_end && layout.failure_media_end != UINT64_MAX
      && layout.failure_media_end <= state->archive_extent) {
    *repair_end = layout.failure_media_end;
  }
  if (result == AVI_PARSE_COMPLETE && layout.described_extent > 0) {
    *validates_to = layout.described_extent - 1;
    // RIFF and index structure cannot prove the order of opaque raw payload bytes. During
    // fragmented recovery, only codec-validated media may cross the VALIDATED boundary.
    if (layout.opaque_payloads == 0) {
      *validates = true;
    }
  }
  return AVI_TRIAL_READY;
}


// Queue only a coherent parent mapping; parsing interruption is not rejection.
static inline bool avi_reassembly_checkpoint(
    ThreadWork *work, CarveInfo *candidate, AviCarveState *state,
    uuid_string_t uuidp, uuid_string_t uuidc) {

  if (!atomic_load_explicit(&REASS_RETURN_TO_IDLE, memory_order_acquire)) {
    return false;
  }
  inflate_blockvector(candidate->b);
  blockvector_set_data_length(candidate->b, state->archive_extent);
  carve_put_state(candidate->carvehashkey, state);
  return reassembly_time_to_checkpoint(work->id, candidate, uuidp, uuidc);
}


// Search decisions depend on physical candidate content, not renumbered apparent blocks.
static inline uint64_t avi_reassembly_block_search_view(
    const CarveInfo *candidate, const AviCarveState *state) {

  uint64_t view = UINT64_C(14695981039346656037);
  uint64_t blocks = blockvector_get_num_blocks(candidate->b);
  const uint64_t geometry[] = {blocks, state->archive_extent,
      state->entry_count, state->repairs};

  for (size_t index = 0; index < sizeof(geometry) / sizeof(geometry[0]); index++) {
    view = (view ^ geometry[index]) * UINT64_C(1099511628211);
  }
  for (uint64_t slot = 0; slot < blocks; slot++) {
    view = (view ^ (uint64_t)blockvector_get_actual_blocknumber(candidate->b,
                                                                slot))
        * UINT64_C(1099511628211);
  }
  for (uint64_t entry = 0; entry < state->entry_count; entry++) {
    view = (view ^ state->entries[entry].offset) * UINT64_C(1099511628211);
    view = (view ^ state->entries[entry].id) * UINT64_C(1099511628211);
    view = (view ^ state->entries[entry].size) * UINT64_C(1099511628211);
  }
  return view;
}


static inline bool avi_reassembly_block_search_current(
    const CarveInfo *candidate, const AviCarveState *state,
    uint64_t target_slot, uint64_t image_blocks, uint64_t validates_to) {

  const AviBlockSearch *search = &state->block_search;

  if (!search->active || search->target_slot != target_slot
      || search->image_blocks != image_blocks
      || search->blocksize != scalpel_state.blocksize
      || search->baseline_to != validates_to
      || search->view != avi_reassembly_block_search_view(candidate, state)) {
    return false;
  }
  // A newly claimed winner requires a new search rather than committing stale evidence.
  if (search->best_actual >= 0
      && avi_reassembly_find_actual_slot(candidate->b, search->best_actual) < 0
      && (filemirror_apparent_blocknumber(scalpel_state.filemirror,
                                          search->best_actual) < 0
          || filemirror_actual_block_covered(scalpel_state.filemirror,
                                             search->best_actual))) {
    return false;
  }
  return true;
}


// A checkpoint resumes one indexed extension against the same physical prefix.
static inline bool avi_reassembly_indexed_search_current(
    const CarveInfo *candidate, const AviCarveState *state,
    uint64_t target_slot, uint64_t image_blocks, uint64_t validates_to) {

  if (!state->indexed_search.active
      || state->indexed_search.target_slot != target_slot
      || state->indexed_search.image_blocks != image_blocks
      || state->indexed_search.baseline_to != validates_to
      || state->indexed_search.blocksize != scalpel_state.blocksize
      || state->indexed_search.view != avi_reassembly_block_search_view(candidate, state)) {
    return false;
  }
  if (state->indexed_search.best_start >= 0) {
    for (uint64_t slot = 0; slot < state->indexed_search.best_mapped; slot++) {
      int64_t actual = state->indexed_search.best_start + (int64_t)slot;
      if (filemirror_apparent_blocknumber(scalpel_state.filemirror, actual) < 0
          || filemirror_actual_block_covered(scalpel_state.filemirror, actual)) {
        return false;
      }
    }
  }
  return true;
}


static inline bool avi_reassembly_zero_gap_search_current(
    const CarveInfo *candidate, const AviCarveState *state,
    uint64_t start_slot, uint64_t image_blocks, uint64_t validates_to,
    bool require_complete) {

  uint32_t index = require_complete ? 1 : 0;
  return state->zero_gap_search[index].active
      && state->zero_gap_search[index].view == avi_reassembly_block_search_view(candidate, state)
      && state->zero_gap_search[index].start_slot == start_slot
      && state->zero_gap_search[index].image_blocks == image_blocks
      && state->zero_gap_search[index].baseline_to == validates_to
      && state->zero_gap_search[index].blocksize == scalpel_state.blocksize;
}


// Ranking survives apparent renumbering; a newly claimed ranked source needs reconsideration.
static inline bool avi_reassembly_classified_search_current(
    const CarveInfo *candidate, const AviCarveState *state,
    uint64_t image_blocks, uint64_t validates_to) {

  const AviClassifiedSearch *search = &state->classified_search;
  if (!search->active || search->image_blocks != image_blocks
      || search->baseline_to != validates_to || search->blocksize != scalpel_state.blocksize
      || search->view != avi_reassembly_block_search_view(candidate, state)) {
    return false;
  }
  for (uint32_t index = 0; index < 3 + search->fallback_count; index++) {
    uint64_t source = index == 0 ? search->best.start
        : index == 1 ? search->lowest_content_start
        : index == 2 ? search->second_content_start
        : search->fallback[index - 3].start;
    if (source == UINT64_MAX) {
      continue;
    }
    for (uint64_t block = 0; block < search->run_blocks; block++) {
      int64_t actual = (int64_t)(source + block);
      if (filemirror_apparent_blocknumber(scalpel_state.filemirror, actual) < 0
          || filemirror_actual_block_covered(scalpel_state.filemirror, actual)) {
        return false;
      }
    }
  }
  return true;
}


// A retained repair can expose index entries that were beyond the readable initial prefix. Replace
// the private state only when the repaired candidate provides strictly more index evidence.
static inline bool avi_reassembly_refresh_state(
    CarveInfo *candidate, AviCarveState **state) {

  if (!candidate || !candidate->b || !state || !*state) {
    return false;
  }
  const uint8_t *data = (const uint8_t *)blockvector_get_data_pointer(
      candidate->b);
  uint64_t length = blockvector_get_data_length(candidate->b);
  AviLayout layout;
  AviParseResult result = avi_parse_file(data, length, UINT64_MAX, &layout);

  if (layout.interrupted || result == AVI_PARSE_INVALID) {
    return false;
  }
  AviCarveState *refreshed = avi_capture_legacy_index(data, length, &layout);

  if (refreshed) {
    // The original RIFF-derived extent remains authoritative while payload corruption is repaired.
    refreshed->archive_extent = (*state)->archive_extent;
  }
  if (!avi_carve_state_valid(refreshed)) {
    avi_free_carve_state((void **)&refreshed);
    return false;
  }
  uint64_t old_matches = 0;
  uint64_t refreshed_matches = 0;

  while (old_matches < (*state)->entry_count
         && avi_chunk_matches(data, length,
                              (*state)->entries[old_matches].offset,
                              (*state)->entries[old_matches].id,
                              (*state)->entries[old_matches].size)) {
    old_matches++;
  }
  while (refreshed_matches < refreshed->entry_count
         && avi_chunk_matches(data, length,
                              refreshed->entries[refreshed_matches].offset,
                              refreshed->entries[refreshed_matches].id,
                              refreshed->entries[refreshed_matches].size)) {
    refreshed_matches++;
  }
  if (refreshed->entry_count < (*state)->entry_count
      || (refreshed->entry_count == (*state)->entry_count
          && refreshed_matches <= old_matches)) {
    avi_free_carve_state((void **)&refreshed);
    return false;
  }
  if (scalpel_state.mode_verbose) {
    lock_fprintf(stdout,
                 "AVI reassembly: refreshed index from %" PRIu64
                 "/%" PRIu64 " to %" PRIu64 "/%" PRIu64
                 " verified entries.\n",
                 old_matches, (*state)->entry_count, refreshed_matches,
                 refreshed->entry_count);
  }
  refreshed->initialized = (*state)->initialized;
  refreshed->repairs = (*state)->repairs;
  avi_free_carve_state((void **)state);
  *state = refreshed;
  return true;
}


static inline bool avi_reassembly_actual_block_suspect(
    const CarveInfo *candidate, int64_t actual) {

  if (!candidate || actual < 0) {
    return true;
  }
  BlockValidationDecision confidence = filemirror_get_blocktype(
      scalpel_state.filemirror, actual, candidate->needleidx);

  return confidence == BLOCK_CONFIDENCE_INVALID
      || filemirror_actual_block_is_zero(scalpel_state.filemirror, actual);
}


// A very low classifier score does not establish that neighboring blocks belong to the same run.
// Treat it as a source-island boundary without excluding the block from use inside a trial run.
static inline bool avi_reassembly_source_boundary(
    const CarveInfo *candidate, int64_t actual) {

  if (!candidate || actual < 0
      || filemirror_actual_block_is_zero(scalpel_state.filemirror, actual)) {
    return true;
  }
  BlockValidationDecision confidence = filemirror_get_blocktype(
      scalpel_state.filemirror, actual, candidate->needleidx);

  return confidence <= AVI_SOURCE_BOUNDARY_MAX_CONFIDENCE;
}


static inline uint64_t avi_reassembly_suspect_run(
    const CarveInfo *candidate, uint64_t target_slot) {

  if (!candidate || !candidate->b) {
    return 0;
  }
  uint64_t total_blocks = blockvector_get_num_blocks(candidate->b);
  uint64_t run_blocks = 0;

  while (target_slot + run_blocks < total_blocks) {
    int64_t actual = blockvector_get_actual_blocknumber(
        candidate->b, target_slot + run_blocks);

    if (!avi_reassembly_actual_block_suspect(candidate, actual)) {
      break;
    }
    run_blocks++;
  }
  return run_blocks;
}


static inline bool avi_reassembly_find_suspect_run(
    const CarveInfo *candidate, uint64_t start_slot,
    uint64_t *target_slot, uint64_t *run_blocks) {

  if (!candidate || !candidate->b || !target_slot || !run_blocks) {
    return false;
  }
  uint64_t total_blocks = blockvector_get_num_blocks(candidate->b);

  for (uint64_t slot = start_slot; slot < total_blocks; slot++) {
    uint64_t blocks = avi_reassembly_suspect_run(candidate, slot);

    if (blocks > 0) {
      *target_slot = slot;
      *run_blocks = blocks;
      return true;
    }
  }
  return false;
}


static inline uint64_t avi_reassembly_media_start_slot(
    const CarveInfo *candidate) {

  if (!candidate || !candidate->b || scalpel_state.blocksize == 0) {
    return 1;
  }
  const uint8_t *data = (const uint8_t *)blockvector_get_data_pointer(
      candidate->b);
  uint64_t length = blockvector_get_data_length(candidate->b);
  AviLayout layout;

  avi_parse_file(data, length, 0, &layout);
  if (layout.movi_count == 0) {
    return 1;
  }
  uint64_t media_offset = layout.movi_type_offsets[0];

  for (uint32_t movi = 1; movi < layout.movi_count; movi++) {
    if (layout.movi_type_offsets[movi] < media_offset) {
      media_offset = layout.movi_type_offsets[movi];
    }
  }
  uint64_t media_slot = media_offset / scalpel_state.blocksize;

  return media_slot > 0 ? media_slot : 1;
}


static inline void avi_content_histogram_add(
    AviContentHistogram *histogram, const uint8_t *data, uint64_t length,
    uint64_t sample_limit) {

  if (!histogram || !data || length == 0 || sample_limit == 0) {
    return;
  }
  uint64_t samples = length < sample_limit ? length : sample_limit;

  for (uint64_t sample = 0; sample < samples; sample++) {
    uint64_t position = samples == length
        ? sample : (sample * length) / samples;

    histogram->bins[data[position] >> 3]++;
  }
  histogram->samples += samples;
}


// Compare normalized byte-class distributions without floating point. The result is the L1
// distance on a fixed scale, so costs remain comparable when context and source lengths differ.
static inline uint64_t avi_content_histogram_cost(
    const AviContentHistogram *left, const AviContentHistogram *right) {

  if (!left || !right || left->samples == 0 || right->samples == 0) {
    return UINT64_MAX;
  }
  uint64_t cost = 0;

  for (uint32_t bin = 0; bin < AVI_CONTENT_HISTOGRAM_BINS; bin++) {
    uint64_t left_scaled = left->bins[bin] * UINT64_C(65536)
        / left->samples;
    uint64_t right_scaled = right->bins[bin] * UINT64_C(65536)
        / right->samples;

    cost += left_scaled > right_scaled
        ? left_scaled - right_scaled : right_scaled - left_scaled;
  }
  return cost;
}


// Opaque media cannot be ordered from RIFF structure alone. Summarize nearby proven blocks so
// otherwise equivalent displaced-run hypotheses can be ordered by content compatibility.
static inline bool avi_reassembly_context_histogram(
    const CarveInfo *candidate, uint64_t target_slot, uint64_t run_blocks,
    uint64_t sample_limit, AviContentHistogram *histogram) {

  if (!candidate || !candidate->b || !histogram
      || scalpel_state.blocksize == 0) {
    return false;
  }
  memset(histogram, 0, sizeof(*histogram));
  const uint8_t *data = (const uint8_t *)blockvector_get_data_pointer(
      candidate->b);
  uint64_t length = blockvector_get_data_length(candidate->b);
  uint64_t total_blocks = blockvector_get_num_blocks(candidate->b);

  if (!data || target_slot >= total_blocks
      || run_blocks > total_blocks - target_slot) {
    return false;
  }
  for (uint64_t distance = 1; distance <= AVI_CONTENT_CONTEXT_BLOCKS;
       distance++) {
    uint64_t slots[2];
    uint32_t slot_count = 0;

    if (target_slot >= distance) {
      slots[slot_count++] = target_slot - distance;
    }
    if (target_slot + run_blocks <= total_blocks
        && distance <= total_blocks - target_slot - run_blocks) {
      slots[slot_count++] = target_slot + run_blocks + distance - 1;
    }
    for (uint32_t index = 0; index < slot_count; index++) {
      uint64_t slot = slots[index];
      int64_t actual = blockvector_get_actual_blocknumber(candidate->b, slot);
      uint64_t offset;

      if (avi_reassembly_actual_block_suspect(candidate, actual)
          || __builtin_mul_overflow(slot,
                                    (uint64_t)scalpel_state.blocksize,
                                    &offset)
          || offset >= length) {
        continue;
      }
      uint64_t available = length - offset;

      if (available > scalpel_state.blocksize) {
        available = scalpel_state.blocksize;
      }
      avi_content_histogram_add(histogram, data + offset, available,
                                sample_limit);
    }
  }
  return histogram->samples > 0;
}


static inline bool avi_reassembly_source_histogram(
    uint64_t start, uint64_t run_blocks, uint64_t sample_limit,
    AviContentHistogram *histogram) {

  if (!histogram || run_blocks == 0 || start > INT64_MAX
      || run_blocks - 1 > (uint64_t)INT64_MAX - start) {
    return false;
  }
  memset(histogram, 0, sizeof(*histogram));

  for (uint64_t block = 0; block < run_blocks; block++) {
    uint64_t available = 0;
    const uint8_t *data = (const uint8_t *)
        filemirror_actual_block_data_pointer(
            scalpel_state.filemirror, (int64_t)(start + block), &available);

    if (!data || available == 0) {
      return false;
    }
    avi_content_histogram_add(histogram, data, available, sample_limit);
  }
  return histogram->samples > 0;
}


// A displaced multiblock run should be internally more consistent than either physical boundary.
// This prevents a trial from beginning in adjacent padding or borrowing blocks from the middle of
// another file's contiguous media run.
static inline bool avi_reassembly_source_run_isolated(
    uint64_t start, uint64_t run_blocks) {

  if (run_blocks < 2 || scalpel_state.blocksize == 0) {
    return false;
  }
  uint64_t image_blocks = CEILDIV(
      filemirror_filesize(scalpel_state.filemirror),
      scalpel_state.blocksize);

  if (start >= image_blocks || run_blocks > image_blocks - start) {
    return false;
  }
  AviContentHistogram first;
  AviContentHistogram previous;
  AviContentHistogram current;

  if (!avi_reassembly_source_histogram(
          start, 1, AVI_CONTENT_FINE_SAMPLES, &first)) {
    return false;
  }
  previous = first;
  uint64_t internal_cost = 0;

  for (uint64_t block = 1; block < run_blocks; block++) {
    if (!avi_reassembly_source_histogram(
            start + block, 1, AVI_CONTENT_FINE_SAMPLES, &current)) {
      return false;
    }
    uint64_t pair_cost = avi_content_histogram_cost(&previous, &current);

    if (pair_cost == UINT64_MAX
        || UINT64_MAX - internal_cost < pair_cost) {
      return false;
    }
    internal_cost += pair_cost;
    previous = current;
  }
  internal_cost /= run_blocks - 1;
  uint32_t boundaries = 0;

  if (start > 0) {
    AviContentHistogram left;

    if (!avi_reassembly_source_histogram(
            start - 1, 1, AVI_CONTENT_FINE_SAMPLES, &left)
        || avi_content_histogram_cost(&left, &first) <= internal_cost) {
      return false;
    }
    boundaries++;
  }
  if (start + run_blocks < image_blocks) {
    AviContentHistogram right;

    if (!avi_reassembly_source_histogram(
            start + run_blocks, 1, AVI_CONTENT_FINE_SAMPLES, &right)
        || avi_content_histogram_cost(&previous, &right) <= internal_cost) {
      return false;
    }
    boundaries++;
  }
  return boundaries > 0;
}


static inline bool avi_reassembly_content_boundary(
    const CarveInfo *candidate, int64_t actual,
    const AviContentHistogram *context_histogram, uint64_t source_cost) {

  if (!candidate || actual < 0
      || filemirror_actual_block_is_zero(scalpel_state.filemirror, actual)
      || avi_reassembly_find_actual_slot(candidate->b, actual) >= 0
      || filemirror_actual_block_covered(scalpel_state.filemirror, actual)) {
    return true;
  }
  AviContentHistogram neighbor_histogram;

  if (context_histogram && source_cost != UINT64_MAX
      && avi_reassembly_source_histogram(
             (uint64_t)actual, 1, AVI_CONTENT_FINE_SAMPLES,
             &neighbor_histogram)) {
    uint64_t neighbor_cost = avi_content_histogram_cost(
        context_histogram, &neighbor_histogram);

    return neighbor_cost * AVI_CONTENT_BOUNDARY_DENOMINATOR
        > source_cost * AVI_CONTENT_BOUNDARY_NUMERATOR;
  }
  return avi_reassembly_source_boundary(candidate, actual);
}


static inline AviTrialResult avi_reassembly_trial_classified_run(
    CarveInfo *candidate, const AviCarveState *state, uint64_t target_slot,
    uint64_t run_blocks, uint64_t start, const int64_t *saved,
    const AviContentHistogram *context_histogram,
    AviClassifiedRunTrial *trial) {

  if (!candidate || !candidate->b || !state || !saved || !trial
      || run_blocks == 0 || start > INT64_MAX
      || run_blocks - 1 > (uint64_t)INT64_MAX - start) {
    return AVI_TRIAL_ERROR;
  }
  memset(trial, 0, sizeof(*trial));
  trial->start = start;
  trial->reserved = 0;
  trial->content_cost = UINT64_MAX;
  int64_t previous_actual = target_slot > 0
      ? blockvector_get_actual_blocknumber(candidate->b, target_slot - 1) : -1;
  trial->contiguous = previous_actual >= 0
      && start == (uint64_t)previous_actual + 1;
  trial->distance = previous_actual >= 0
      ? (start > (uint64_t)previous_actual
          ? start - (uint64_t)previous_actual
          : (uint64_t)previous_actual - start)
      : UINT64_MAX;

  bool available = true;
  for (uint64_t block = 0; block < run_blocks; block++) {
    int64_t actual = (int64_t)(start + block);
    int64_t apparent = filemirror_apparent_blocknumber(
        scalpel_state.filemirror, actual);

    if (apparent < 0
        || avi_reassembly_actual_block_suspect(candidate, actual)
        || avi_reassembly_find_actual_slot(candidate->b, actual) >= 0
        || filemirror_actual_block_covered(scalpel_state.filemirror, actual)) {
      available = false;
      break;
    }
    trial->confidence += (uint64_t)filemirror_get_blocktype(
        scalpel_state.filemirror, actual, candidate->needleidx);
    if (scalpel_state.reservations) {
      int64_t reserved = filemirror_actual_block_reserved(
          scalpel_state.filemirror, actual);

      if (reserved > INT64_MAX - trial->reserved) {
        trial->reserved = INT64_MAX;
      }
      else {
        trial->reserved += reserved;
      }
    }
    blockvector_set_apparent_blocknumber(
        candidate->b, target_slot + block, apparent);
  }
  if (!available) {
    for (uint64_t block = 0; block < run_blocks; block++) {
      blockvector_set_apparent_blocknumber(
          candidate->b, target_slot + block, saved[block]);
    }
    return AVI_TRIAL_ERROR;
  }

  AviContentHistogram source_histogram;

  if (avi_reassembly_source_histogram(start, run_blocks,
                                      AVI_CONTENT_FINE_SAMPLES,
                                      &source_histogram)) {
    trial->content_cost = avi_content_histogram_cost(
        context_histogram, &source_histogram);
  }
  uint64_t image_blocks = CEILDIV(
      filemirror_filesize(scalpel_state.filemirror), scalpel_state.blocksize);

  if (run_blocks > 1) {
    trial->isolated = avi_reassembly_source_run_isolated(
        start, run_blocks);
  }
  else {
    trial->isolated = (start == 0
                       || avi_reassembly_content_boundary(
                              candidate, (int64_t)start - 1,
                              context_histogram, trial->content_cost))
        && (start + run_blocks == image_blocks
            || avi_reassembly_content_boundary(
                   candidate, (int64_t)(start + run_blocks),
                   context_histogram, trial->content_cost));
  }
  inflate_blockvector(candidate->b);
  blockvector_set_data_length(candidate->b, state->archive_extent);
  bool validates = false;
  AviTrialResult validation = avi_reassembly_validate_candidate(
      candidate, state, &validates, &trial->validates_to, NULL, NULL,
      target_slot * (uint64_t)scalpel_state.blocksize);

  trial->validates = validates;
  const uint8_t *trial_data = (const uint8_t *)
      blockvector_get_data_pointer(candidate->b);
  AviLayout trial_layout;
  AviParseResult trial_result = avi_parse_file(
      trial_data, state->archive_extent, 0, &trial_layout);
  uint64_t index_failure = state->archive_extent;
  bool index_valid = avi_validate_indexed_prefix(
      trial_data, state->archive_extent, state, &index_failure);

  trial->complete = trial_result == AVI_PARSE_COMPLETE && index_valid;
  trial->crc_slices = trial_layout.ffv1_crc_slices;
  for (uint64_t block = 0; block < run_blocks; block++) {
    blockvector_set_apparent_blocknumber(
        candidate->b, target_slot + block, saved[block]);
  }
  inflate_blockvector(candidate->b);
  blockvector_set_data_length(candidate->b, state->archive_extent);
  if (validation == AVI_TRIAL_INTERRUPTED || trial_layout.interrupted) {
    return AVI_TRIAL_INTERRUPTED;
  }
  return validation;
}


static inline bool avi_classified_run_trial_better(
    const AviClassifiedRunTrial *trial,
    const AviClassifiedRunTrial *best, bool allow_content_only,
    bool base_complete,
    uint64_t base_crc_slices, uint64_t current_validates_to) {

  if (!trial || !best) {
    return false;
  }
  bool content_repair = allow_content_only
      && trial->validates_to >= current_validates_to
      && trial->confidence > 0 && trial->content_cost != UINT64_MAX
      && trial->isolated;
  bool stronger = trial->validates
      || (!base_complete && trial->validates_to > current_validates_to)
      || (base_complete && trial->complete
          && trial->crc_slices > base_crc_slices)
      || content_repair;

  if (!stronger) {
    return false;
  }
  if (best->start == UINT64_MAX) {
    return true;
  }
  if (trial->validates_to != best->validates_to) {
    return trial->validates_to > best->validates_to;
  }
  if (trial->crc_slices != best->crc_slices) {
    return trial->crc_slices > best->crc_slices;
  }
  if (trial->contiguous != best->contiguous) {
    return trial->contiguous;
  }
  if (trial->reserved != best->reserved) {
    return trial->reserved < best->reserved;
  }
  if (trial->content_cost != best->content_cost) {
    return trial->content_cost < best->content_cost;
  }
  if (trial->distance != best->distance) {
    return trial->distance < best->distance;
  }
  return trial->confidence > best->confidence;
}


// A displaced block run is often left as a zero or unclassified hole while the original run is
// physically isolated elsewhere. Test the complete hole width in one operation. This is essential
// for opaque codec payloads, where no individual block can advance the RIFF parser before the
// complete run has been restored.
static inline AviRunSearchResult avi_reassembly_find_classified_run(
    ThreadWork *work, CarveInfo **candidate, AviCarveState *state,
    uint64_t target_slot, uint64_t run_blocks, uint64_t image_blocks,
    uint64_t current_validates_to, bool allow_content_only,
    bool require_complete, uuid_string_t uuidp, uuid_string_t uuidc) {

  if (!work || !candidate || !*candidate || !(*candidate)->b || !state
      || run_blocks == 0 || run_blocks > image_blocks) {
    return AVI_RUN_SEARCH_NO_MATCH;
  }
  uint64_t total_blocks = blockvector_get_num_blocks((*candidate)->b);

  if (target_slot >= total_blocks || run_blocks > total_blocks - target_slot
      || run_blocks > SIZE_MAX / sizeof(int64_t)) {
    return AVI_RUN_SEARCH_NO_MATCH;
  }
  int64_t *saved = (int64_t *)malloc(
      (size_t)run_blocks * sizeof(*saved));

  check_memory_allocation(saved, __LINE__, __FILE__,
                          "AVI classified displaced run");
  bool target_all_zero = true;

  for (uint64_t slot = 0; slot < run_blocks; slot++) {
    saved[slot] = blockvector_get_apparent_blocknumber(
        (*candidate)->b, target_slot + slot);
    int64_t actual = blockvector_get_actual_blocknumber(
        (*candidate)->b, target_slot + slot);

    if (actual < 0
        || !filemirror_actual_block_is_zero(scalpel_state.filemirror,
                                             actual)) {
      target_all_zero = false;
    }
  }

classified_base_parse:
  ;
  const uint8_t *base_data = (const uint8_t *)blockvector_get_data_pointer(
      (*candidate)->b);
  uint64_t length = blockvector_get_data_length((*candidate)->b);
  AviLayout base_layout;
  AviParseResult base_result = avi_parse_file(base_data, length, 0,
                                               &base_layout);
  if (base_layout.interrupted) {
    if (avi_reassembly_checkpoint(work, *candidate, state, uuidp, uuidc)) {
      free(saved);
      return AVI_RUN_SEARCH_STOPPED;
    }
    goto classified_base_parse;
  }
  uint64_t base_index_failure = length;
  bool base_index_valid = avi_validate_indexed_prefix(
      base_data, length, state, &base_index_failure);
  bool base_complete = base_result == AVI_PARSE_COMPLETE && base_index_valid;
  AviContentHistogram coarse_context;
  AviContentHistogram fine_context;
  AviContentHistogram current_content;
  bool have_coarse_context = avi_reassembly_context_histogram(
      *candidate, target_slot, run_blocks, AVI_CONTENT_COARSE_SAMPLES,
      &coarse_context);
  bool have_fine_context = avi_reassembly_context_histogram(
      *candidate, target_slot, run_blocks, AVI_CONTENT_FINE_SAMPLES,
      &fine_context);

  memset(&current_content, 0, sizeof(current_content));
  if (base_data) {
    for (uint64_t block = 0; block < run_blocks; block++) {
      uint64_t slot = target_slot + block;
      uint64_t offset;

      if (__builtin_mul_overflow(slot,
                                 (uint64_t)scalpel_state.blocksize,
                                 &offset)
          || offset >= length) {
        continue;
      }
      uint64_t available = length - offset;

      if (available > scalpel_state.blocksize) {
        available = scalpel_state.blocksize;
      }
      avi_content_histogram_add(&current_content, base_data + offset,
                                available, AVI_CONTENT_FINE_SAMPLES);
    }
  }
  uint64_t base_content_cost = have_fine_context
      ? avi_content_histogram_cost(&fine_context, &current_content)
      : UINT64_MAX;
  AviClassifiedSearch *search = &state->classified_search;
  if (!avi_reassembly_classified_search_current(*candidate, state, image_blocks,
                                                current_validates_to)
      || search->target_slot != target_slot || search->run_blocks != run_blocks
      || search->allow_content_only != (uint32_t)allow_content_only
      || search->require_complete != (uint32_t)require_complete) {
    memset(search, 0, sizeof(*search));
    search->view = avi_reassembly_block_search_view(*candidate, state);
    search->target_slot = target_slot;
    search->run_blocks = run_blocks;
    search->image_blocks = image_blocks;
    search->baseline_to = current_validates_to;
    search->blocksize = scalpel_state.blocksize;
    search->allow_content_only = allow_content_only;
    search->require_complete = require_complete;
    search->owner = current_validates_to == state->archive_extent - 1 ? 1
        : require_complete ? 2 : run_blocks > 1 ? 3 : 4;
    search->active = 1;
    search->best.start = UINT64_MAX;
    search->best.validates_to = current_validates_to;
    search->best.crc_slices = base_layout.ffv1_crc_slices;
    search->best.content_cost = UINT64_MAX;
    search->best.distance = UINT64_MAX;
    search->best.reserved = INT64_MAX;
    search->lowest_content_cost = UINT64_MAX;
    search->second_content_cost = UINT64_MAX;
    search->lowest_content_start = UINT64_MAX;
    search->second_content_start = UINT64_MAX;
    search->lowest_content_reserved = INT64_MAX;
  }
  if (search->active == 2) {
    free(saved);
    return AVI_RUN_SEARCH_NO_MATCH;
  }
  int64_t previous_actual = target_slot > 0
      ? blockvector_get_actual_blocknumber(
            (*candidate)->b, target_slot - 1) : -1;

  for (uint64_t start = search->next_actual; start + run_blocks <= image_blocks;
       start++, search->next_actual = start) {
    if ((start & UINT64_C(0x3f)) == 0) {
      if (reassembly_check_kill_queue(work, candidate, uuidp, uuidc)) {
        free(saved);
        return AVI_RUN_SEARCH_STOPPED;
      }
      if (avi_reassembly_checkpoint(work, *candidate, state, uuidp, uuidc)) {
        free(saved);
        return AVI_RUN_SEARCH_STOPPED;
      }
    }

    bool source_contiguous = previous_actual >= 0
        && start == (uint64_t)previous_actual + 1;
    bool left_boundary = source_contiguous || start == 0
        || avi_reassembly_source_boundary(
               *candidate, (int64_t)start - 1);
    bool right_boundary = start + run_blocks == image_blocks
        || avi_reassembly_source_boundary(
               *candidate, (int64_t)(start + run_blocks));
    bool available = true;

    for (uint64_t block = 0; block < run_blocks; block++) {
      int64_t actual = (int64_t)(start + block);
      int64_t apparent = filemirror_apparent_blocknumber(
          scalpel_state.filemirror, actual);

      if (apparent < 0
          || avi_reassembly_actual_block_suspect(*candidate, actual)
          || avi_reassembly_find_actual_slot((*candidate)->b, actual) >= 0
          || filemirror_actual_block_covered(scalpel_state.filemirror,
                                              actual)) {
        available = false;
        break;
      }
    }
    if (!available) {
      continue;
    }

    if (!left_boundary || !right_boundary) {
      AviContentHistogram source_histogram;
      uint64_t cost = UINT64_MAX;

      if (have_coarse_context
          && avi_reassembly_source_histogram(
                 start, run_blocks, AVI_CONTENT_COARSE_SAMPLES,
                 &source_histogram)) {
        cost = avi_content_histogram_cost(&coarse_context,
                                          &source_histogram);
      }
      if (cost != UINT64_MAX) {
        if (search->fallback_count < AVI_CONTENT_FALLBACK_RUNS) {
          search->fallback[search->fallback_count++] = (AviRunContentCandidate){
              .start = start,
              .cost = cost
          };
        }
        else {
          uint32_t worst = 0;

          for (uint32_t index = 1; index < search->fallback_count; index++) {
            if (search->fallback[index].cost > search->fallback[worst].cost
                || (search->fallback[index].cost == search->fallback[worst].cost
                    && search->fallback[index].start > search->fallback[worst].start)) {
              worst = index;
            }
          }
          if (cost < search->fallback[worst].cost
              || (cost == search->fallback[worst].cost
                  && start < search->fallback[worst].start)) {
            search->fallback[worst] = (AviRunContentCandidate){
                .start = start,
                .cost = cost
            };
          }
        }
      }
      continue;
    }

classified_source_retry:
    ;
    AviClassifiedRunTrial trial;
    AviTrialResult result = avi_reassembly_trial_classified_run(
        *candidate, state, target_slot, run_blocks, start, saved,
        &fine_context, &trial);
    if (result == AVI_TRIAL_INTERRUPTED) {
      if (avi_reassembly_checkpoint(work, *candidate, state, uuidp, uuidc)) {
        free(saved);
        return AVI_RUN_SEARCH_STOPPED;
      }
      goto classified_source_retry;
    }
    if (result != AVI_TRIAL_READY) {
      continue;
    }
    if (trial.validates_to >= current_validates_to
        && trial.content_cost != UINT64_MAX && trial.isolated) {
      if (trial.reserved < search->lowest_content_reserved) {
        search->lowest_content_reserved = trial.reserved;
        search->second_content_cost = UINT64_MAX;
        search->second_content_start = UINT64_MAX;
        search->lowest_content_cost = trial.content_cost;
        search->lowest_content_start = trial.start;
        search->lowest_content_confidence = trial.confidence;
        search->lowest_content_isolated = trial.isolated;
      }
      else if (trial.reserved == search->lowest_content_reserved
               && trial.content_cost < search->lowest_content_cost) {
        search->second_content_cost = search->lowest_content_cost;
        search->second_content_start = search->lowest_content_start;
        search->lowest_content_cost = trial.content_cost;
        search->lowest_content_start = trial.start;
        search->lowest_content_confidence = trial.confidence;
        search->lowest_content_isolated = trial.isolated;
      }
      else if (trial.reserved == search->lowest_content_reserved
               && trial.content_cost < search->second_content_cost) {
        search->second_content_cost = trial.content_cost;
        search->second_content_start = trial.start;
      }
    }
    bool complete_trial = trial.validates
        || trial.validates_to == state->archive_extent - 1;

    if ((!require_complete || complete_trial)
        && avi_classified_run_trial_better(
            &trial, &search->best, allow_content_only, base_complete,
            base_layout.ffv1_crc_slices, current_validates_to)) {
      search->best = trial;
    }
  }

  for (uint32_t index = search->fallback_next; index < search->fallback_count;
       index++, search->fallback_next = index) {
classified_fallback_retry:
    ;
    if (avi_reassembly_checkpoint(work, *candidate, state, uuidp, uuidc)) {
      free(saved);
      return AVI_RUN_SEARCH_STOPPED;
    }
    AviClassifiedRunTrial trial;
    AviTrialResult result = avi_reassembly_trial_classified_run(
        *candidate, state, target_slot, run_blocks,
        search->fallback[index].start, saved, &fine_context, &trial);
    if (result == AVI_TRIAL_INTERRUPTED) {
      if (avi_reassembly_checkpoint(work, *candidate, state, uuidp, uuidc)) {
        free(saved);
        return AVI_RUN_SEARCH_STOPPED;
      }
      goto classified_fallback_retry;
    }
    if (result != AVI_TRIAL_READY) {
      continue;
    }
    if (trial.validates_to >= current_validates_to
        && trial.content_cost != UINT64_MAX && trial.isolated) {
      if (trial.reserved < search->lowest_content_reserved) {
        search->lowest_content_reserved = trial.reserved;
        search->second_content_cost = UINT64_MAX;
        search->second_content_start = UINT64_MAX;
        search->lowest_content_cost = trial.content_cost;
        search->lowest_content_start = trial.start;
        search->lowest_content_confidence = trial.confidence;
        search->lowest_content_isolated = trial.isolated;
      }
      else if (trial.reserved == search->lowest_content_reserved
               && trial.content_cost < search->lowest_content_cost) {
        search->second_content_cost = search->lowest_content_cost;
        search->second_content_start = search->lowest_content_start;
        search->lowest_content_cost = trial.content_cost;
        search->lowest_content_start = trial.start;
        search->lowest_content_confidence = trial.confidence;
        search->lowest_content_isolated = trial.isolated;
      }
      else if (trial.reserved == search->lowest_content_reserved
               && trial.content_cost < search->second_content_cost) {
        search->second_content_cost = trial.content_cost;
        search->second_content_start = trial.start;
      }
    }
    bool complete_trial = trial.validates
        || trial.validates_to == state->archive_extent - 1;

    if ((!require_complete || complete_trial)
        && avi_classified_run_trial_better(
            &trial, &search->best, allow_content_only, base_complete,
            base_layout.ffv1_crc_slices, current_validates_to)) {
      search->best = trial;
    }
  }

  if (search->best.start == UINT64_MAX) {
    search->active = 2;
    if (scalpel_state.mode_verbose) {
      lock_fprintf(stdout,
                   "AVI classified run unavailable: target=%" PRIu64
                   " blocks=%" PRIu64 " content-start=%" PRIu64
                   " content-cost=%" PRIu64 " second=%" PRIu64
                   " confidence=%" PRIu64 " reservations=%" PRId64
                   " isolated=%s.\n",
                   target_slot, run_blocks, search->lowest_content_start,
                   search->lowest_content_cost, search->second_content_cost,
                   search->lowest_content_confidence, search->lowest_content_reserved,
                   search->lowest_content_isolated ? "true" : "false");
    }
    free(saved);
    return AVI_RUN_SEARCH_NO_MATCH;
  }

  bool content_only = !search->best.validates
      && search->best.validates_to <= current_validates_to
      && search->best.crc_slices <= base_layout.ffv1_crc_slices;

  // Content similarity can order opaque payload hypotheses only when the target is a literal zero
  // run. Nonzero payload blocks require structural, index, or codec evidence before replacement.
  if (content_only
      && (!allow_content_only
          || !target_all_zero
          || base_content_cost == UINT64_MAX
          || search->best.content_cost == UINT64_MAX
          || search->best.content_cost * AVI_CONTENT_RATIO_DENOMINATOR
                 > base_content_cost * AVI_CONTENT_RATIO_NUMERATOR
          || (search->second_content_cost != UINT64_MAX
              && search->best.content_cost * AVI_CONTENT_RATIO_DENOMINATOR
                     > search->second_content_cost * AVI_CONTENT_RATIO_NUMERATOR))) {
    search->active = 2;
    if (scalpel_state.mode_verbose) {
      lock_fprintf(stdout,
                   "AVI classified run rejected: target=%" PRIu64
                   " blocks=%" PRIu64 " source=%" PRIu64
                   " base-cost=%" PRIu64 " content-cost=%" PRIu64
                   " second=%" PRIu64 " confidence=%" PRIu64
                   " reservations=%" PRId64 " isolated=%s.\n",
                   target_slot, run_blocks, search->best.start, base_content_cost,
                   search->best.content_cost, search->second_content_cost, search->best.confidence,
                   search->best.reserved, search->best.isolated ? "true" : "false");
    }
    free(saved);
    return AVI_RUN_SEARCH_NO_MATCH;
  }

classified_apply_retry:
  for (uint64_t block = 0; block < run_blocks; block++) {
    int64_t apparent = filemirror_apparent_blocknumber(
        scalpel_state.filemirror, (int64_t)(search->best.start + block));

    if (apparent < 0
        || filemirror_actual_block_covered(
            scalpel_state.filemirror, (int64_t)(search->best.start + block))
        || avi_reassembly_find_actual_slot(
            (*candidate)->b, (int64_t)(search->best.start + block)) >= 0) {
      free(saved);
      return AVI_RUN_SEARCH_NO_MATCH;
    }
  }
  for (uint64_t block = 0; block < run_blocks; block++) {
    int64_t apparent = filemirror_apparent_blocknumber(
        scalpel_state.filemirror, (int64_t)(search->best.start + block));
    blockvector_set_apparent_blocknumber((*candidate)->b, target_slot + block, apparent);
  }
  inflate_blockvector((*candidate)->b);
  blockvector_set_data_length((*candidate)->b, state->archive_extent);
  bool validates = false;
  uint64_t validates_to = 0;

  AviTrialResult validation = avi_reassembly_validate_candidate(
      *candidate, state, &validates, &validates_to, NULL, NULL,
      target_slot * (uint64_t)scalpel_state.blocksize);
  if (validation != AVI_TRIAL_READY) {
    for (uint64_t block = 0; block < run_blocks; block++) {
      blockvector_set_apparent_blocknumber(
          (*candidate)->b, target_slot + block, saved[block]);
    }
    inflate_blockvector((*candidate)->b);
    blockvector_set_data_length((*candidate)->b, state->archive_extent);
    if (validation == AVI_TRIAL_INTERRUPTED) {
      if (avi_reassembly_checkpoint(work, *candidate, state, uuidp, uuidc)) {
        free(saved);
        return AVI_RUN_SEARCH_STOPPED;
      }
      goto classified_apply_retry;
    }
    free(saved);
    return AVI_RUN_SEARCH_NO_MATCH;
  }
  if (scalpel_state.mode_verbose) {
    lock_fprintf(stdout,
                 "AVI classified run: target=%" PRIu64
                 " source=%" PRIu64 " blocks=%" PRIu64
                 " advances to=%" PRIu64 " CRC slices=%" PRIu64
                 " content-cost=%" PRIu64 " reservations=%" PRId64 ".\n",
                 target_slot, search->best.start, run_blocks, validates_to,
                 search->best.crc_slices, search->best.content_cost, search->best.reserved);
  }
  free(saved);
  if (validates) {
    return AVI_RUN_SEARCH_VALIDATED;
  }
  if (validates_to == state->archive_extent - 1) {
    return AVI_RUN_SEARCH_COMPLETE;
  }
  if (validates_to > current_validates_to) {
    return AVI_RUN_SEARCH_IMPROVED;
  }
  return content_only ? AVI_RUN_SEARCH_REPAIRED
      : AVI_RUN_SEARCH_NO_MATCH;
}


static inline int64_t avi_reassembly_find_actual_slot(
    BlockVector *blockvector, int64_t actual_block) {

  if (!blockvector || actual_block < 0) {
    return -1;
  }
  uint64_t blocks = blockvector_get_num_blocks(blockvector);

  for (uint64_t slot = 0; slot < blocks; slot++) {
    if (blockvector_get_actual_blocknumber(blockvector, slot)
        == actual_block) {
      return (int64_t)slot;
    }
  }
  return -1;
}


static inline int64_t avi_reassembly_find_apparent_slot(
    BlockVector *blockvector, int64_t apparent_block) {

  if (!blockvector || apparent_block < 0) {
    return -1;
  }
  uint64_t blocks = blockvector_get_num_blocks(blockvector);

  for (uint64_t slot = 0; slot < blocks; slot++) {
    if (blockvector_get_apparent_blocknumber(blockvector, slot)
        == apparent_block) {
      return (int64_t)slot;
    }
  }
  return -1;
}


// Rotate a physically shifted suffix as one unit. The mapping is restored unless the complete file
// validates or the caller explicitly requests retention of a strictly better partial result.
static inline bool avi_reassembly_rotate_suffix_trial(
    CarveInfo *candidate, const AviCarveState *state,
    uint64_t target_slot, uint64_t shift, uint64_t image_blocks,
    uint64_t required_validates_to, bool retain_partial,
    bool *validates, uint64_t *validates_to, bool *interrupted) {

  if (interrupted) {
    *interrupted = false;
  }
  if (!candidate || !candidate->b || !state || !validates
      || !validates_to) {
    return false;
  }
  *validates = false;
  *validates_to = 0;
  uint64_t total_blocks = blockvector_get_num_blocks(candidate->b);

  if (target_slot >= total_blocks || shift == 0
      || shift >= total_blocks - target_slot) {
    return false;
  }
  uint64_t suffix_blocks = total_blocks - target_slot;
  if (suffix_blocks > SIZE_MAX / sizeof(int64_t)) {
    return false;
  }
  int64_t *saved = (int64_t *)malloc(
      (size_t)suffix_blocks * sizeof(int64_t));

  check_memory_allocation(saved, __LINE__, __FILE__,
                          "AVI suffix rotation");
  // Continue the physical suffix from its saved tail. A displaced run elsewhere in the candidate
  // does not alter the location of the blocks that follow this suffix.
  int64_t suffix_tail_actual = blockvector_get_actual_blocknumber(
      candidate->b, total_blocks - 1);

  for (uint64_t slot = 0; slot < total_blocks; slot++) {
    if (slot >= target_slot) {
      saved[slot - target_slot] =
          blockvector_get_apparent_blocknumber(candidate->b, slot);
    }
  }

  bool available = suffix_tail_actual >= 0;
  for (uint64_t slot = target_slot;
       available && slot + shift < total_blocks; slot++) {
    blockvector_set_apparent_blocknumber(
        candidate->b, slot, saved[slot - target_slot + shift]);
  }

  uint64_t *tail_conflicts = (uint64_t *)calloc(
      (size_t)shift, sizeof(*tail_conflicts));

  check_memory_allocation(tail_conflicts, __LINE__, __FILE__,
                          "AVI suffix tail conflicts");
  // The actual mapping is unchanged by positive apparent assignments until inflation. Count its
  // conflicts once instead of scanning it for every tail block; only an explicit unmap removes one.
  for (uint64_t slot = 0; available && slot < total_blocks; slot++) {
    int64_t actual = blockvector_get_actual_blocknumber(candidate->b, slot);

    if (actual <= suffix_tail_actual
        || (uint64_t)(actual - suffix_tail_actual) > shift) {
      continue;
    }
    uint64_t index = (uint64_t)(actual - suffix_tail_actual - 1);

    tail_conflicts[index]++;
  }
  for (uint64_t tail = 0; available && tail < shift; tail++) {
    if (suffix_tail_actual == INT64_MAX
        || tail > (uint64_t)(INT64_MAX - suffix_tail_actual - 1)) {
      available = false;
      break;
    }
    int64_t actual = suffix_tail_actual + 1 + (int64_t)tail;
    int64_t apparent = -1;

    if (actual < 0 || (uint64_t)actual >= image_blocks
        || tail_conflicts[tail] > 0) {
      available = false;
      break;
    }
    apparent = filemirror_apparent_blocknumber(scalpel_state.filemirror,
                                                actual);
    if (apparent < 0
        && !filemirror_actual_block_is_zero(scalpel_state.filemirror,
                                             actual)) {
      available = false;
      break;
    }
    if (apparent < 0) {
      int64_t previous = blockvector_get_actual_blocknumber(
          candidate->b, total_blocks - shift + tail);

      if (previous > suffix_tail_actual
          && (uint64_t)(previous - suffix_tail_actual) <= shift) {
        tail_conflicts[(uint64_t)(previous - suffix_tail_actual - 1)]--;
      }
    }
    blockvector_set_apparent_blocknumber(
        candidate->b, total_blocks - shift + tail, apparent);
  }
  free(tail_conflicts);

  bool parsed = false;
  if (available) {
    inflate_blockvector(candidate->b);
    blockvector_set_data_length(candidate->b, state->archive_extent);
    AviTrialResult result = avi_reassembly_validate_candidate(
        candidate, state, validates, validates_to, NULL, NULL,
        target_slot * (uint64_t)scalpel_state.blocksize);
    parsed = result == AVI_TRIAL_READY;
    if (interrupted) {
      *interrupted = result == AVI_TRIAL_INTERRUPTED;
    }
  }
  bool retained = parsed
      && (*validates
          || (retain_partial && *validates_to > required_validates_to));

  if (!retained) {
    for (uint64_t slot = target_slot; slot < total_blocks; slot++) {
      blockvector_set_apparent_blocknumber(
          candidate->b, slot, saved[slot - target_slot]);
    }
    inflate_blockvector(candidate->b);
    blockvector_set_data_length(candidate->b, state->archive_extent);
  }
  free(saved);
  return retained;
}


static inline bool avi_reassembly_rotate_suffix(
    CarveInfo *candidate, const AviCarveState *state,
    uint64_t target_slot, uint64_t shift, uint64_t image_blocks,
    uint64_t required_validates_to, bool retain_partial,
    bool *validates, uint64_t *validates_to) {

  return avi_reassembly_rotate_suffix_trial(candidate, state, target_slot,
      shift, image_blocks, required_validates_to, retain_partial,
      validates, validates_to, NULL);
}


// A zero run states an exact possible gap width. Prefer a repair that reaches the complete declared
// extent, while allowing the caller to make a second pass that retains structural progress.
static inline AviRunSearchResult avi_reassembly_find_zero_gap(
    ThreadWork *work, CarveInfo **candidate, AviCarveState *state,
    uint64_t start_slot, uint64_t image_blocks,
    uint64_t current_validates_to, bool require_complete,
    uint64_t *repair_slot, uuid_string_t uuidp, uuid_string_t uuidc) {

  if (!work || !candidate || !*candidate || !(*candidate)->b || !state
      || !repair_slot || state->archive_extent == 0) {
    return AVI_RUN_SEARCH_NO_MATCH;
  }
  uint64_t total_blocks = blockvector_get_num_blocks((*candidate)->b);
  uint32_t index = require_complete ? 1 : 0;
  if (start_slot >= total_blocks) {
    return AVI_RUN_SEARCH_NO_MATCH;
  }
  if (!avi_reassembly_zero_gap_search_current(*candidate, state, start_slot,
                                             image_blocks, current_validates_to,
                                             require_complete)) {
    memset(&state->zero_gap_search[index], 0, sizeof(state->zero_gap_search[index]));
    state->zero_gap_search[index].view = avi_reassembly_block_search_view(*candidate, state);
    state->zero_gap_search[index].start_slot = start_slot;
    state->zero_gap_search[index].next_slot = start_slot;
    state->zero_gap_search[index].image_blocks = image_blocks;
    state->zero_gap_search[index].baseline_to = current_validates_to;
    state->zero_gap_search[index].blocksize = scalpel_state.blocksize;
    state->zero_gap_search[index].active = 1;
  }
  uint64_t search_slot = state->zero_gap_search[index].next_slot;
  uint64_t suspect_slot = 0;
  uint64_t suspect_blocks = 0;

  while (avi_reassembly_find_suspect_run(
             *candidate, search_slot, &suspect_slot, &suspect_blocks)) {
    state->zero_gap_search[index].next_slot = suspect_slot;
    if (avi_reassembly_checkpoint(work, *candidate, state, uuidp, uuidc)) {
      return AVI_RUN_SEARCH_STOPPED;
    }
    uint64_t zero_blocks = 0;
    bool interrupted = false;

    while (suspect_slot + zero_blocks < total_blocks) {
      int64_t actual = blockvector_get_actual_blocknumber(
          (*candidate)->b, suspect_slot + zero_blocks);

      if (actual < 0
          || !filemirror_actual_block_is_zero(scalpel_state.filemirror,
                                              actual)) {
        break;
      }
      zero_blocks++;
    }
    if (zero_blocks > 0 && zero_blocks < total_blocks - suspect_slot) {
      bool gap_validates = false;
      uint64_t gap_validates_to = 0;
      uint64_t required_validates_to = current_validates_to;

      if (require_complete && state->archive_extent > 1) {
        required_validates_to = state->archive_extent - 2;
      }
      if (avi_reassembly_rotate_suffix_trial(
              *candidate, state, suspect_slot, zero_blocks, image_blocks,
              required_validates_to, true, &gap_validates,
              &gap_validates_to, &interrupted)) {
        if (scalpel_state.mode_verbose) {
          lock_fprintf(stdout,
                       "AVI zero-gap suffix: target=%" PRIu64
                       " shift=%" PRIu64 " advances to=%" PRIu64 ".\n",
                       suspect_slot, zero_blocks, gap_validates_to);
        }
        *repair_slot = suspect_slot;
        if (gap_validates) {
          return AVI_RUN_SEARCH_VALIDATED;
        }
        if (gap_validates_to == state->archive_extent - 1) {
          return AVI_RUN_SEARCH_COMPLETE;
        }
        return AVI_RUN_SEARCH_IMPROVED;
      }
    }
    // Rotation restores the parent on interruption; retry this unfinished width.
    if (!interrupted) {
      search_slot = suspect_slot + suspect_blocks;
      state->zero_gap_search[index].next_slot = search_slot;
    }
    if (avi_reassembly_checkpoint(work, *candidate, state, uuidp, uuidc)) {
      return AVI_RUN_SEARCH_STOPPED;
    }
    if (reassembly_check_kill_queue(work, candidate, uuidp, uuidc)) {
      return AVI_RUN_SEARCH_STOPPED;
    }
  }
  state->zero_gap_search[index].next_slot = total_blocks;
  return AVI_RUN_SEARCH_NO_MATCH;
}


// A whole-block gap shifts every later chunk header by the same amount. Use index entries as anchors
// to identify possible shifts, then require the repaired candidate to pass normal AVI validation.
static inline bool avi_reassembly_shift_search_current(
    const CarveInfo *candidate, const AviCarveState *state,
    uint64_t image_blocks, uint64_t validates_to, uint64_t repair_end) {

  const AviShiftSearch *search = &state->shift_search;
  if (!search->phase || search->image_blocks != image_blocks
      || search->baseline_to != validates_to || search->repair_end != repair_end
      || search->blocksize != scalpel_state.blocksize
      || search->view != avi_reassembly_block_search_view(candidate, state)) {
    return false;
  }
  int64_t tail = blockvector_get_actual_blocknumber(candidate->b,
      blockvector_get_num_blocks(candidate->b) - 1);
  for (uint64_t index = 0; index < search->best_shift; index++) {
    if (tail < 0 || (uint64_t)tail >= image_blocks
        || index >= image_blocks - (uint64_t)tail - 1) {
      return false;
    }
    int64_t actual = tail + 1 + (int64_t)index;
    if (filemirror_apparent_blocknumber(scalpel_state.filemirror, actual) < 0
        && !filemirror_actual_block_is_zero(scalpel_state.filemirror, actual)) {
      return false;
    }
  }
  return true;
}


static inline bool avi_reassembly_shift_matches(
    const uint8_t *data, uint64_t length, const AviStateIndexEntry *entry,
    uint64_t shift) {

  uint64_t bytes;
  uint64_t offset;
  return data
      && !__builtin_mul_overflow(shift, (uint64_t)scalpel_state.blocksize, &bytes)
      && !__builtin_add_overflow(entry->offset, bytes, &offset)
      && avi_range_available(length, offset, AVI_CHUNK_HEADER_SIZE)
      && avi_read_le32(data + offset) == entry->id
      && avi_read_le32(data + offset + 4) == entry->size;
}


// Keep the trial cursor and winner; reconstruct only the cheap duplicate-shift index on restore.
static inline AviRunSearchResult avi_reassembly_find_shifted_suffix(
    ThreadWork *work, CarveInfo **candidate, AviCarveState *state,
    uint64_t target_slot, uint64_t image_blocks, uint64_t current_validates_to,
    uint64_t repair_end, uuid_string_t uuidp, uuid_string_t uuidc) {

  if (!work || !candidate || !*candidate || !(*candidate)->b || !state
      || scalpel_state.blocksize == 0) {
    return AVI_RUN_SEARCH_NO_MATCH;
  }
  uint64_t total_blocks = blockvector_get_num_blocks((*candidate)->b);
  if (target_slot >= total_blocks) {
    return AVI_RUN_SEARCH_NO_MATCH;
  }
  uint64_t possible_shifts = total_blocks - target_slot;
  uint64_t length = blockvector_get_data_length((*candidate)->b);
  if (possible_shifts > SIZE_MAX
      || (!state->entry_count && (!repair_end || repair_end > length))) {
    return AVI_RUN_SEARCH_NO_MATCH;
  }
  AviShiftSearch *search = &state->shift_search;
  if (!avi_reassembly_shift_search_current(*candidate, state, image_blocks,
                                            current_validates_to, repair_end)
      || search->target_slot != target_slot) {
    uint32_t owner = search->owner == 1 ? 1 : 2;
    uint64_t classified_slot = search->classified_slot;
    *search = (AviShiftSearch){
        .view = avi_reassembly_block_search_view(*candidate, state),
        .target_slot = target_slot, .image_blocks = image_blocks,
        .baseline_to = current_validates_to, .repair_end = repair_end,
        .next_shift = 1, .best_validates_to = current_validates_to,
        .classified_slot = classified_slot, .blocksize = scalpel_state.blocksize,
        .phase = state->entry_count ? 1 : 2, .owner = owner};
  }
  if (search->phase == 5) {
    return AVI_RUN_SEARCH_NO_MATCH;
  }
  uint8_t *tried = (uint8_t *)calloc((size_t)possible_shifts, 1);
  check_memory_allocation(tried, __LINE__, __FILE__, "AVI shifted suffix candidates");

  // A completed trial is identified by an earlier matching index entry, or an earlier shift
  // at the saved entry. Rebuilding these flags never repeats codec validation.
  const uint8_t *data = (const uint8_t *)blockvector_get_data_pointer((*candidate)->b);
  for (uint64_t entry = 0; entry < state->entry_count && entry <= search->next_entry;
       entry++) {
    const AviStateIndexEntry *anchor = &state->entries[entry];
    if (anchor->offset <= current_validates_to
        || !avi_range_available(state->archive_extent, anchor->offset, AVI_CHUNK_HEADER_SIZE)) {
      continue;
    }
    uint64_t end = entry < search->next_entry ? possible_shifts : search->next_shift;
    for (uint64_t shift = 1; shift < end; shift++) {
      if (avi_reassembly_shift_matches(data, state->archive_extent, anchor, shift)) {
        tried[shift] = 1;
      }
    }
  }

  while (search->phase <= 2) {
    if (reassembly_check_kill_queue(work, candidate, uuidp, uuidc)) {
      free(tried);
      return AVI_RUN_SEARCH_STOPPED;
    }
    if (avi_reassembly_checkpoint(work, *candidate, state, uuidp, uuidc)) {
      free(tried);
      return AVI_RUN_SEARCH_STOPPED;
    }
    if (search->phase == 1 && search->next_entry == state->entry_count) {
      search->phase = search->best_shift ? 3 : 2;
      search->next_shift = 1;
      continue;
    }
    if (search->next_shift == possible_shifts) {
      if (search->phase == 1) {
        search->next_entry++;
        search->next_shift = 1;
      }
      else {
        search->phase = 3;
      }
      continue;
    }
    uint64_t shift = search->next_shift;
    data = (const uint8_t *)blockvector_get_data_pointer((*candidate)->b);
    bool anchor_matches = false;
    if (data && !tried[shift] && search->phase == 1) {
      const AviStateIndexEntry *entry = &state->entries[search->next_entry];
      anchor_matches = entry->offset > current_validates_to
          && avi_range_available(state->archive_extent, entry->offset, AVI_CHUNK_HEADER_SIZE)
          && avi_reassembly_shift_matches(data, state->archive_extent, entry, shift);
    }
    else if (data && !tried[shift] && search->phase == 2 && repair_end
             && repair_end <= state->archive_extent) {
      uint64_t bytes;
      uint64_t offset;
      if (!__builtin_mul_overflow(shift, (uint64_t)scalpel_state.blocksize, &bytes)
          && !__builtin_add_overflow(repair_end, bytes, &offset)
          && avi_range_available(length, offset, AVI_CHUNK_HEADER_SIZE)) {
        uint32_t id = avi_read_le32(data + offset);
        uint32_t size = avi_read_le32(data + offset + 4);
        anchor_matches = (avi_is_media_chunk(id) || id == AVI_FOURCC('L', 'I', 'S', 'T')
                || id == AVI_FOURCC('J', 'U', 'N', 'K') || id == AVI_FOURCC('i', 'd', 'x', '1'))
            && size <= state->archive_extent
            && (id != AVI_FOURCC('L', 'I', 'S', 'T') || size >= sizeof(uint32_t));
      }
    }
    if (!anchor_matches) {
      search->next_shift++;
      continue;
    }
    bool validates = false;
    bool interrupted = false;
    uint64_t validates_to = 0;
    bool retained = avi_reassembly_rotate_suffix_trial(*candidate, state,
        target_slot, shift, image_blocks, current_validates_to, false,
        &validates, &validates_to, &interrupted);
    if (interrupted) {
      if (avi_reassembly_checkpoint(work, *candidate, state, uuidp, uuidc)) {
        free(tried);
        return AVI_RUN_SEARCH_STOPPED;
      }
      continue;
    }
    if (retained && validates) {
      free(tried);
      return AVI_RUN_SEARCH_VALIDATED;
    }
    tried[shift] = 1;
    search->next_shift++;
    if ((search->phase == 1 || validates_to >= repair_end - 1)
        && validates_to > search->best_validates_to) {
      search->best_shift = shift;
      search->best_validates_to = validates_to;
    }
    if (search->phase == 1 && validates_to == state->archive_extent - 1) {
      search->phase = 4;
    }
  }

  while (search->best_shift) {
    bool validates = false;
    bool interrupted = false;
    uint64_t validates_to = 0;
    bool retained = avi_reassembly_rotate_suffix_trial(*candidate, state,
        target_slot, search->best_shift, image_blocks, current_validates_to, true,
        &validates, &validates_to, &interrupted);
    if (interrupted) {
      if (avi_reassembly_checkpoint(work, *candidate, state, uuidp, uuidc)) {
        free(tried);
        return AVI_RUN_SEARCH_STOPPED;
      }
      continue;
    }
    if (retained) {
      free(tried);
      if (validates) {
        return AVI_RUN_SEARCH_VALIDATED;
      }
      return validates_to == state->archive_extent - 1
          ? AVI_RUN_SEARCH_COMPLETE : AVI_RUN_SEARCH_IMPROVED;
    }
    break;
  }
  search->phase = 5;
  free(tried);
  return AVI_RUN_SEARCH_NO_MATCH;
}


static inline bool avi_reassembly_source_matches_index(
    int64_t source_start, uint64_t target_slot, uint64_t image_blocks,
    const AviStateIndexEntry *entry, uint64_t *minimum_blocks) {

  if (source_start < 0 || !entry || !minimum_blocks
      || scalpel_state.blocksize == 0) {
    return false;
  }
  uint64_t target_offset;
  if (__builtin_mul_overflow(target_slot,
                             (uint64_t)scalpel_state.blocksize,
                             &target_offset)
      || entry->offset < target_offset) {
    return false;
  }
  uint64_t relative = entry->offset - target_offset;
  uint64_t anchor_delta = relative / scalpel_state.blocksize;
  uint64_t in_block = relative % scalpel_state.blocksize;
  uint64_t anchor_index;

  if (__builtin_add_overflow((uint64_t)source_start, anchor_delta,
                             &anchor_index)
      || anchor_index >= image_blocks) {
    return false;
  }

  uint8_t header[AVI_CHUNK_HEADER_SIZE];
  uint64_t available = 0;
  const uint8_t *block = (const uint8_t *)
      filemirror_actual_block_data_pointer(
          scalpel_state.filemirror, (int64_t)anchor_index, &available);

  if (!block || in_block >= available) {
    return false;
  }
  uint64_t first = available - in_block;
  if (first > AVI_CHUNK_HEADER_SIZE) {
    first = AVI_CHUNK_HEADER_SIZE;
  }
  memcpy(header, block + in_block, (size_t)first);
  if (first < AVI_CHUNK_HEADER_SIZE) {
    if (anchor_index + 1 >= image_blocks) {
      return false;
    }
    uint64_t next_available = 0;
    const uint8_t *next = (const uint8_t *)
        filemirror_actual_block_data_pointer(
            scalpel_state.filemirror, (int64_t)(anchor_index + 1),
            &next_available);
    uint64_t needed = AVI_CHUNK_HEADER_SIZE - first;

    if (!next || next_available < needed) {
      return false;
    }
    memcpy(header + first, next, (size_t)needed);
  }
  if (avi_read_le32(header) != entry->id
      || avi_read_le32(header + 4) != entry->size) {
    return false;
  }
  uint64_t header_extent;
  if (__builtin_add_overflow(in_block, (uint64_t)AVI_CHUNK_HEADER_SIZE,
                             &header_extent)) {
    return false;
  }
  *minimum_blocks = anchor_delta
      + CEILDIV(header_extent, scalpel_state.blocksize);
  return *minimum_blocks > 0;
}


// An indexed chunk header can cross a block boundary. Repair the block containing the first
// mismatching header byte rather than an earlier block that still contains valid header bytes.
static inline uint64_t avi_reassembly_failure_slot(
    const CarveInfo *candidate, const AviCarveState *state,
    uint64_t failure_offset) {

  if (scalpel_state.blocksize == 0) {
    return 0;
  }
  uint64_t target_slot = failure_offset / scalpel_state.blocksize;

  if (!candidate || !candidate->b || !state) {
    return target_slot;
  }
  const uint8_t *data = (const uint8_t *)
      blockvector_get_data_pointer(candidate->b);

  if (!data) {
    return target_slot;
  }
  for (uint64_t index = 0; index < state->entry_count; index++) {
    const AviStateIndexEntry *entry = &state->entries[index];

    if (entry->offset != failure_offset
        || !avi_range_available(state->archive_extent, entry->offset,
                                AVI_CHUNK_HEADER_SIZE)) {
      continue;
    }
    for (uint64_t byte = 0; byte < AVI_CHUNK_HEADER_SIZE; byte++) {
      uint32_t expected = byte < sizeof(uint32_t)
          ? entry->id : entry->size;
      uint8_t expected_byte = (uint8_t)(
          expected >> ((byte % sizeof(uint32_t)) * 8));

      if (data[entry->offset + byte] != expected_byte) {
        return (entry->offset + byte) / scalpel_state.blocksize;
      }
    }
  }
  return target_slot;
}


// Codec validation can detect corruption after its first bad block. Limit backward structured
// probes to the indexed media chunk containing the observed failure.
static inline uint64_t avi_reassembly_earliest_repair_slot(
    const AviCarveState *state, uint64_t failure_offset,
    uint64_t target_slot) {

  if (!state || scalpel_state.blocksize == 0) {
    return target_slot;
  }
  for (uint64_t index = 0; index < state->entry_count; index++) {
    const AviStateIndexEntry *entry = &state->entries[index];
    uint64_t payload;
    uint64_t end;

    if (__builtin_add_overflow(entry->offset,
                               (uint64_t)AVI_CHUNK_HEADER_SIZE, &payload)
        || __builtin_add_overflow(payload, (uint64_t)entry->size, &end)
        || __builtin_add_overflow(end, (uint64_t)(entry->size & 1U), &end)
        || failure_offset < payload || failure_offset >= end) {
      continue;
    }
    uint64_t first_slot = payload / scalpel_state.blocksize;

    return first_slot < target_slot ? first_slot : target_slot;
  }
  return target_slot;
}


// Use the first unverified index entry to locate a displaced physical run. Mapping continues through
// that independently described chunk header before validation decides whether the run is useful.
static inline AviRunSearchResult avi_reassembly_find_indexed_run(
    ThreadWork *work, CarveInfo **candidate, AviCarveState *state,
    uint64_t target_slot, uint64_t image_blocks, uint64_t current_validates_to,
    uuid_string_t uuidp, uuid_string_t uuidc) {

  if (!work || !candidate || !*candidate || !(*candidate)->b || !state
      || state->entry_count == 0) {
    return AVI_RUN_SEARCH_NO_MATCH;
  }
  const AviStateIndexEntry *anchor = NULL;
  const AviStateIndexEntry *corroborator = NULL;
  uint64_t anchor_index = 0;
  for (uint64_t entry = 0; entry < state->entry_count; entry++) {
    if (state->entries[entry].offset > current_validates_to) {
      anchor = &state->entries[entry];
      anchor_index = entry;
      break;
    }
  }
  if (!anchor) {
    return AVI_RUN_SEARCH_NO_MATCH;
  }
  for (uint64_t entry = anchor_index + 1; entry < state->entry_count;
       entry++) {
    if (state->entries[entry].id != anchor->id
        || state->entries[entry].size != anchor->size) {
      corroborator = &state->entries[entry];
      break;
    }
  }
  if (!corroborator && anchor_index + 1 < state->entry_count) {
    corroborator = &state->entries[anchor_index + 1];
  }
  if (!corroborator) {
    return AVI_RUN_SEARCH_NO_MATCH;
  }

  uint64_t total_blocks = blockvector_get_num_blocks((*candidate)->b);
  if (target_slot >= total_blocks) {
    return AVI_RUN_SEARCH_NO_MATCH;
  }
  uint64_t suffix_blocks = total_blocks - target_slot;
  uint64_t suspect_blocks = avi_reassembly_suspect_run(
      *candidate, target_slot);
  if (suffix_blocks > SIZE_MAX / sizeof(int64_t)) {
    return AVI_RUN_SEARCH_NO_MATCH;
  }
  int64_t *saved = (int64_t *)malloc(
      (size_t)suffix_blocks * sizeof(int64_t));

  check_memory_allocation(saved, __LINE__, __FILE__,
                          "AVI indexed displaced run");
  for (uint64_t slot = target_slot; slot < total_blocks; slot++) {
    saved[slot - target_slot] =
        blockvector_get_apparent_blocknumber((*candidate)->b, slot);
  }

  if (!avi_reassembly_indexed_search_current(*candidate, state, target_slot,
                                             image_blocks, current_validates_to)) {
    uint64_t classified_slot = state->indexed_search.classified_slot;
    memset(&state->indexed_search, 0, sizeof(state->indexed_search));
    state->indexed_search.view = avi_reassembly_block_search_view(*candidate, state);
    state->indexed_search.target_slot = target_slot;
    state->indexed_search.image_blocks = image_blocks;
    state->indexed_search.baseline_to = current_validates_to;
    state->indexed_search.previous_validates_to = current_validates_to;
    state->indexed_search.best_start = -1;
    state->indexed_search.best_validates_to = current_validates_to;
    state->indexed_search.classified_slot = classified_slot;
    state->indexed_search.blocksize = scalpel_state.blocksize;
    state->indexed_search.active = 1;
  }
  int64_t best_start = state->indexed_search.best_start;
  uint64_t best_mapped = state->indexed_search.best_mapped;
  uint64_t best_validates_to = state->indexed_search.best_validates_to;

  for (uint64_t start_index = state->indexed_search.next_actual; start_index < image_blocks;
       start_index++) {
    state->indexed_search.next_actual = start_index;
    if ((start_index & 63U) == 0
        && reassembly_check_kill_queue(work, candidate, uuidp, uuidc)) {
      free(saved);
      return AVI_RUN_SEARCH_STOPPED;
    }
    if (avi_reassembly_checkpoint(work, *candidate, state, uuidp, uuidc)) {
      free(saved);
      return AVI_RUN_SEARCH_STOPPED;
    }
    int64_t start = (int64_t)start_index;
    uint64_t pending_mapped = state->indexed_search.mapped;
    state->indexed_search.mapped = 0;
    uint64_t minimum_blocks = 0;
    uint64_t corroborating_blocks = 0;

    if (!avi_reassembly_source_matches_index(
            start, target_slot, image_blocks, anchor, &minimum_blocks)
        || !avi_reassembly_source_matches_index(
            start, target_slot, image_blocks, corroborator,
            &corroborating_blocks)
        || minimum_blocks > suffix_blocks) {
      continue;
    }
    if (corroborating_blocks > minimum_blocks) {
      minimum_blocks = corroborating_blocks;
    }
    if (suspect_blocks > minimum_blocks) {
      minimum_blocks = suspect_blocks;
    }
    if (minimum_blocks > suffix_blocks) {
      continue;
    }
    int64_t start_apparent = filemirror_apparent_blocknumber(
        scalpel_state.filemirror, start);
    if (start_apparent < 0
        || avi_reassembly_find_apparent_slot((*candidate)->b,
                                              start_apparent) >= 0
        || filemirror_actual_block_covered(scalpel_state.filemirror,
                                            start)) {
      continue;
    }

    uint64_t previous_validates_to = pending_mapped
        ? state->indexed_search.previous_validates_to : current_validates_to;
    uint64_t mapped = pending_mapped;
    if (mapped) {
      bool available = true;
      for (uint64_t slot = 0; slot < mapped; slot++) {
        int64_t actual = start + (int64_t)slot;
        int64_t apparent = filemirror_apparent_blocknumber(scalpel_state.filemirror, actual);
        if (apparent < 0 || avi_reassembly_find_apparent_slot((*candidate)->b, apparent) >= 0
            || filemirror_actual_block_covered(scalpel_state.filemirror, actual)) {
          available = false;
          break;
        }
        blockvector_set_apparent_blocknumber((*candidate)->b, target_slot + slot, apparent);
      }
      if (!available) {
        for (uint64_t slot = 0; slot < mapped; slot++) {
          blockvector_set_apparent_blocknumber((*candidate)->b, target_slot + slot, saved[slot]);
        }
        mapped = 0;
        state->indexed_search.mapped = 0;
        previous_validates_to = current_validates_to;
      }
      else {
        minimum_blocks = state->indexed_search.minimum_blocks;
      }
    }
    for (; mapped < suffix_blocks && start_index + mapped < image_blocks;
         mapped++) {
      state->indexed_search.mapped = mapped;
      state->indexed_search.minimum_blocks = minimum_blocks;
      state->indexed_search.previous_validates_to = previous_validates_to;
      if (atomic_load_explicit(&REASS_RETURN_TO_IDLE, memory_order_acquire)) {
        for (uint64_t slot = 0; slot < mapped; slot++) {
          blockvector_set_apparent_blocknumber((*candidate)->b, target_slot + slot, saved[slot]);
        }
        if (avi_reassembly_checkpoint(work, *candidate, state, uuidp, uuidc)) {
          free(saved);
          return AVI_RUN_SEARCH_STOPPED;
        }
        for (uint64_t slot = 0; slot < mapped; slot++) {
          int64_t apparent = filemirror_apparent_blocknumber(
              scalpel_state.filemirror, start + (int64_t)slot);
          blockvector_set_apparent_blocknumber((*candidate)->b, target_slot + slot, apparent);
        }
      }
      int64_t actual = start + (int64_t)mapped;
      int64_t apparent = filemirror_apparent_blocknumber(
          scalpel_state.filemirror, actual);

      if (apparent < 0
          || avi_reassembly_find_apparent_slot((*candidate)->b,
                                                apparent) >= 0
          || filemirror_actual_block_covered(scalpel_state.filemirror,
                                              actual)) {
        break;
      }
      blockvector_set_apparent_blocknumber(
          (*candidate)->b, target_slot + mapped, apparent);
      if (mapped + 1 < minimum_blocks) {
        continue;
      }

      inflate_blockvector((*candidate)->b);
      blockvector_set_data_length((*candidate)->b, state->archive_extent);
      bool validates = false;
      uint64_t validates_to = 0;

      if (avi_reassembly_validate_candidate(
              *candidate, state, &validates, &validates_to, NULL, NULL,
              target_slot * (uint64_t)scalpel_state.blocksize)
              != AVI_TRIAL_READY) {
        for (uint64_t slot = 0; slot <= mapped; slot++) {
          blockvector_set_apparent_blocknumber((*candidate)->b, target_slot + slot, saved[slot]);
        }
        inflate_blockvector((*candidate)->b);
        blockvector_set_data_length((*candidate)->b, state->archive_extent);
        free(saved);
        if (avi_reassembly_checkpoint(work, *candidate, state, uuidp, uuidc)) {
          return AVI_RUN_SEARCH_STOPPED;
        }
        return AVI_RUN_SEARCH_NO_MATCH;
      }
      if (validates) {
        free(saved);
        return AVI_RUN_SEARCH_VALIDATED;
      }
      if (validates_to == state->archive_extent - 1) {
        free(saved);
        return AVI_RUN_SEARCH_COMPLETE;
      }
      if (validates_to > best_validates_to) {
        uint64_t failure_slot = (validates_to + 1)
            / scalpel_state.blocksize;
        uint64_t proven_blocks = failure_slot > target_slot
            ? failure_slot - target_slot : mapped + 1;

        if (proven_blocks > mapped + 1) {
          proven_blocks = mapped + 1;
        }
        best_start = start;
        best_mapped = proven_blocks;
        best_validates_to = validates_to;
        state->indexed_search.best_start = best_start;
        state->indexed_search.best_mapped = best_mapped;
        state->indexed_search.best_validates_to = best_validates_to;
      }
      if (validates_to < previous_validates_to) {
        mapped++;
        break;
      }
      if (validates_to == previous_validates_to) {
        if (mapped + 1 >= minimum_blocks) {
          mapped++;
          break;
        }
      }
      else {
        previous_validates_to = validates_to;
        uint64_t target_offset;

        if (__builtin_mul_overflow(
                target_slot, (uint64_t)scalpel_state.blocksize,
                &target_offset)) {
          mapped++;
          break;
        }
        minimum_blocks = suffix_blocks;
        for (uint64_t entry = 0; entry < state->entry_count; entry++) {
          if (state->entries[entry].offset <= validates_to
              || state->entries[entry].offset < target_offset) {
            continue;
          }
          uint64_t relative = state->entries[entry].offset - target_offset;
          uint64_t through_header;

          if (!__builtin_add_overflow(
                  relative, (uint64_t)AVI_CHUNK_HEADER_SIZE,
                  &through_header)) {
            minimum_blocks = CEILDIV(
                through_header, scalpel_state.blocksize);
          }
          break;
        }
        if (minimum_blocks <= mapped + 1 && mapped + 1 < suffix_blocks) {
          minimum_blocks = mapped + 2;
        }
        if (suspect_blocks > minimum_blocks) {
          minimum_blocks = suspect_blocks;
        }
      }
    }

    for (uint64_t slot = 0; slot < mapped; slot++) {
      blockvector_set_apparent_blocknumber(
          (*candidate)->b, target_slot + slot, saved[slot]);
    }
    inflate_blockvector((*candidate)->b);
    blockvector_set_data_length((*candidate)->b, state->archive_extent);
    state->indexed_search.mapped = 0;
    state->indexed_search.next_actual = start_index + 1;
  }
  state->indexed_search.next_actual = image_blocks;
  state->indexed_search.active = 2;

  if (best_start >= 0) {
    bool available = true;
    if (scalpel_state.mode_verbose) {
      lock_fprintf(stdout,
                   "AVI indexed run: retaining source=%" PRId64
                   " blocks=%" PRIu64 " validates-to=%" PRIu64 ".\n",
                   best_start, best_mapped, best_validates_to);
    }
    for (uint64_t mapped = 0; mapped < best_mapped; mapped++) {
      int64_t apparent = filemirror_apparent_blocknumber(
          scalpel_state.filemirror, best_start + (int64_t)mapped);

      if (apparent < 0
          || avi_reassembly_find_apparent_slot((*candidate)->b,
                                                apparent) >= 0
          || filemirror_actual_block_covered(
              scalpel_state.filemirror, best_start + (int64_t)mapped)) {
        available = false;
        break;
      }
      blockvector_set_apparent_blocknumber(
          (*candidate)->b, target_slot + mapped, apparent);
    }
    if (!available) {
      for (uint64_t slot = target_slot; slot < total_blocks; slot++) {
        blockvector_set_apparent_blocknumber(
            (*candidate)->b, slot, saved[slot - target_slot]);
      }
    }
    inflate_blockvector((*candidate)->b);
    blockvector_set_data_length((*candidate)->b, state->archive_extent);
    free(saved);
    return available ? AVI_RUN_SEARCH_IMPROVED : AVI_RUN_SEARCH_NO_MATCH;
  }

  free(saved);
  return AVI_RUN_SEARCH_NO_MATCH;
}


// Retain physical search positions while unrelated blockmap entries are renumbered.
static inline bool avi_reassembly_displaced_search_current(
    const CarveInfo *candidate, const AviCarveState *state,
    uint64_t image_blocks, uint64_t validates_to, uint64_t repair_end) {

  const AviDisplacedSearch *search = &state->displaced_search;
  if (!search->phase || search->image_blocks != image_blocks
      || search->baseline_to != validates_to || search->repair_end != repair_end
      || search->blocksize != scalpel_state.blocksize
      || search->view != avi_reassembly_block_search_view(candidate, state)) {
    return false;
  }
  if (search->best_start >= 0) {
    for (uint64_t slot = 0; slot < search->best_mapped; slot++) {
      int64_t actual = search->best_start + (int64_t)slot;
      if (filemirror_apparent_blocknumber(scalpel_state.filemirror, actual) < 0
          || filemirror_actual_block_covered(scalpel_state.filemirror, actual)) {
        return false;
      }
    }
  }
  return true;
}


// Keep the pending probe separate from completed extensions. Temporary mappings are rolled back
// before checkpointing, then reconstructed without repeating their completed codec checks.
static inline AviRunSearchResult avi_reassembly_find_displaced_run(
    ThreadWork *work, CarveInfo **candidate, AviCarveState *state,
    uint64_t target_slot, uint64_t image_blocks, uint64_t current_validates_to,
    uint64_t repair_end, uuid_string_t uuidp, uuid_string_t uuidc) {

  if (!work || !candidate || !*candidate || !(*candidate)->b || !state
      || !scalpel_state.blocksize) {
    return AVI_RUN_SEARCH_NO_MATCH;
  }
  uint64_t total_blocks = blockvector_get_num_blocks((*candidate)->b);
  if (!target_slot || target_slot >= total_blocks) {
    return AVI_RUN_SEARCH_NO_MATCH;
  }
  uint64_t suffix_blocks = total_blocks - target_slot;
  if (suffix_blocks > SIZE_MAX / sizeof(int64_t)) {
    return AVI_RUN_SEARCH_NO_MATCH;
  }
  AviDisplacedSearch *search = &state->displaced_search;
  if (!avi_reassembly_displaced_search_current(*candidate, state, image_blocks,
                                                current_validates_to, repair_end)
      || search->target_slot != target_slot) {
    uint64_t interval_end = repair_end;
    uint64_t suspect_blocks = avi_reassembly_suspect_run(*candidate, target_slot);
    if (interval_end <= current_validates_to + 1) {
      for (uint64_t entry = 0; entry < state->entry_count; entry++) {
        if (state->entries[entry].offset > current_validates_to + 1) {
          interval_end = state->entries[entry].offset;
          break;
        }
      }
    }
    *search = (AviDisplacedSearch){
        .view = avi_reassembly_block_search_view(*candidate, state),
        .target_slot = target_slot, .image_blocks = image_blocks,
        .baseline_to = current_validates_to, .repair_end = repair_end,
        .previous_validates_to = current_validates_to, .best_start = -1,
        .best_validates_to = current_validates_to,
        .blocksize = scalpel_state.blocksize, .phase = 3};
    if (interval_end > current_validates_to + 1) {
      uint64_t end_slot = CEILDIV(interval_end, scalpel_state.blocksize);
      search->probe_blocks = end_slot > target_slot ? end_slot - target_slot : 0;
      if (search->probe_blocks < suspect_blocks) {
        search->probe_blocks = suspect_blocks;
      }
      if (search->probe_blocks > suffix_blocks) {
        search->probe_blocks = suffix_blocks;
      }
      if (__builtin_add_overflow(interval_end, (uint64_t)AVI_CHUNK_HEADER_SIZE - 1,
                                 &search->reconnects_to)
          || search->reconnects_to >= state->archive_extent) {
        search->reconnects_to = state->archive_extent - 1;
      }
      search->phase = search->probe_blocks ? 1 : 4;
      if (!search->probe_blocks) {
        search->next_actual = image_blocks;
      }
    }
  }
  if (search->phase == 5) {
    return AVI_RUN_SEARCH_NO_MATCH;
  }
  int64_t *saved = (int64_t *)malloc((size_t)suffix_blocks * sizeof(int64_t));
  check_memory_allocation(saved, __LINE__, __FILE__, "AVI displaced run");
  for (uint64_t slot = 0; slot < suffix_blocks; slot++) {
    saved[slot] = blockvector_get_apparent_blocknumber((*candidate)->b, target_slot + slot);
  }

  while (search->phase < 4) {
    if (reassembly_check_kill_queue(work, candidate, uuidp, uuidc)) {
      free(saved);
      return AVI_RUN_SEARCH_STOPPED;
    }
    if (avi_reassembly_checkpoint(work, *candidate, state, uuidp, uuidc)) {
      free(saved);
      return AVI_RUN_SEARCH_STOPPED;
    }
    if (search->next_actual == image_blocks) {
      search->phase = 4;
      search->mapped = 0;
      search->proven_blocks = 0;
      break;
    }
    uint64_t wanted = search->phase == 1 ? search->probe_blocks
        : search->phase == 2 ? search->proven_blocks : search->mapped + 1;
    uint64_t mapped = 0;
    for (; mapped < wanted && mapped < image_blocks - search->next_actual; mapped++) {
      int64_t actual = (int64_t)(search->next_actual + mapped);
      int64_t apparent = filemirror_apparent_blocknumber(scalpel_state.filemirror, actual);
      if (apparent < 0
          || avi_reassembly_find_apparent_slot((*candidate)->b, apparent) >= 0
          || filemirror_actual_block_covered(scalpel_state.filemirror, actual)) {
        break;
      }
      blockvector_set_apparent_blocknumber((*candidate)->b, target_slot + mapped, apparent);
    }
    bool validates = false;
    uint64_t validates_to = 0;
    AviTrialResult result = AVI_TRIAL_READY;
    bool evaluated = mapped > 0 && (search->phase == 1 || mapped == wanted);
    if (evaluated) {
      inflate_blockvector((*candidate)->b);
      blockvector_set_data_length((*candidate)->b, state->archive_extent);
      result = avi_reassembly_validate_candidate(
          *candidate, state, &validates, &validates_to, NULL, NULL,
          target_slot * (uint64_t)scalpel_state.blocksize);
      if (result == AVI_TRIAL_READY
          && (validates || validates_to == state->archive_extent - 1)) {
        free(saved);
        return validates ? AVI_RUN_SEARCH_VALIDATED : AVI_RUN_SEARCH_COMPLETE;
      }
    }
    for (uint64_t slot = 0; slot < mapped; slot++) {
      blockvector_set_apparent_blocknumber((*candidate)->b, target_slot + slot, saved[slot]);
    }
    inflate_blockvector((*candidate)->b);
    blockvector_set_data_length((*candidate)->b, state->archive_extent);
    if (result == AVI_TRIAL_INTERRUPTED) {
      if (avi_reassembly_checkpoint(work, *candidate, state, uuidp, uuidc)) {
        free(saved);
        return AVI_RUN_SEARCH_STOPPED;
      }
      continue;
    }

    if (evaluated && result == AVI_TRIAL_READY && search->phase == 1) {
      uint64_t proven = 0;
      if (validates_to > current_validates_to) {
        uint64_t failure_slot = (validates_to + 1) / scalpel_state.blocksize;
        proven = failure_slot > target_slot ? failure_slot - target_slot : 0;
        if (proven > mapped) {
          proven = mapped;
        }
      }
      if (proven) {
        search->mapped = mapped;
        search->proven_blocks = proven;
        search->phase = 2;
        continue;
      }
    }
    else if (evaluated && result == AVI_TRIAL_READY && search->phase == 2) {
      if (validates_to >= search->reconnects_to
          && validates_to > search->best_validates_to) {
        search->best_start = (int64_t)search->next_actual;
        search->best_mapped = search->proven_blocks;
        search->best_validates_to = validates_to;
      }
    }
    else if (evaluated && result == AVI_TRIAL_READY && search->phase == 3) {
      uint64_t failure_slot = (validates_to + 1) / scalpel_state.blocksize;
      if (validates_to > search->previous_validates_to
          || (validates_to == search->previous_validates_to
              && failure_slot > target_slot + mapped - 1)) {
        search->previous_validates_to = validates_to;
        search->mapped = mapped;
        if (mapped < suffix_blocks && mapped < image_blocks - search->next_actual) {
          continue;
        }
      }
    }
    search->next_actual++;
    search->mapped = 0;
    search->proven_blocks = 0;
    search->previous_validates_to = current_validates_to;
    search->phase = search->probe_blocks ? 1 : 3;
  }

  if (avi_reassembly_checkpoint(work, *candidate, state, uuidp, uuidc)) {
    free(saved);
    return AVI_RUN_SEARCH_STOPPED;
  }
  bool available = search->best_start >= 0;
  if (available) {
    for (uint64_t mapped = 0; mapped < search->best_mapped; mapped++) {
      int64_t actual = search->best_start + (int64_t)mapped;
      int64_t apparent = filemirror_apparent_blocknumber(scalpel_state.filemirror, actual);
      if (apparent < 0
          || avi_reassembly_find_apparent_slot((*candidate)->b, apparent) >= 0
          || filemirror_actual_block_covered(scalpel_state.filemirror, actual)) {
        available = false;
        break;
      }
      blockvector_set_apparent_blocknumber((*candidate)->b, target_slot + mapped, apparent);
    }
    if (available && scalpel_state.mode_verbose) {
      lock_fprintf(stdout, "AVI media run: target=%" PRIu64
          " source=%" PRId64 " blocks=%" PRIu64 " advances to=%" PRIu64 ".\n",
          target_slot, search->best_start, search->best_mapped, search->best_validates_to);
    }
  }
  if (!available) {
    for (uint64_t slot = 0; slot < suffix_blocks; slot++) {
      blockvector_set_apparent_blocknumber((*candidate)->b, target_slot + slot, saved[slot]);
    }
  }
  inflate_blockvector((*candidate)->b);
  blockvector_set_data_length((*candidate)->b, state->archive_extent);
  search->phase = 5;
  free(saved);
  return available ? AVI_RUN_SEARCH_IMPROVED : AVI_RUN_SEARCH_NO_MATCH;
}


// Repair the complete declared AVI layout rather than growing only a prefix. Later chunk and index
// structure can then reject a wrong opaque payload block as soon as it is tried. A block already in
// the candidate is swapped into the failing slot, which naturally moves inserted gaps toward the
// tail and restores displaced runs without duplicating physical blocks.
static inline void avi_reassembly(ThreadWork *work, CarveInfo **candidate,
                                  uuid_string_t uuidp,
                                  uuid_string_t uuidc) {

  AviCarveState *state = candidate && *candidate
      ? (AviCarveState *)carve_get_state((*candidate)->carvehashkey) : NULL;

  if (!candidate || !*candidate || !state) {
    avi_free_carve_state((void **)&state);
    if (candidate && *candidate) {
      LR_reassembly(work, candidate, uuidp, uuidc);
    }
    return;
  }
  if (!avi_reassembly_initialize_candidate(*candidate, state)) {
    avi_free_carve_state((void **)&state);
    destroy_candidate(candidate);
    return;
  }

  uint64_t total_blocks = blockvector_get_num_blocks((*candidate)->b);
  uint64_t image_blocks = CEILDIV(
      filemirror_filesize(scalpel_state.filemirror), scalpel_state.blocksize);
  uint64_t current_validates_to = 0;
  uint64_t current_repair_from = 0;
  uint64_t current_repair_end = 0;
  bool current_validates = false;

  if (avi_reassembly_validate_candidate(*candidate, state,
                                         &current_validates,
                                         &current_validates_to,
                                         &current_repair_from,
                                         &current_repair_end, 0)
          != AVI_TRIAL_READY) {
    if (avi_reassembly_checkpoint(work, *candidate, state, uuidp, uuidc)) {
      avi_free_carve_state((void **)&state);
      return;
    }
    avi_free_carve_state((void **)&state);
    destroy_candidate(candidate);
    return;
  }
  if (scalpel_state.mode_verbose) {
    lock_fprintf(stdout,
                 "AVI reassembly: extent=%" PRIu64
                 " blocks=%" PRIu64 " indexed=%" PRIu64
                 " validates-to=%" PRIu64 ".\n",
                 state->archive_extent, total_blocks, state->entry_count,
                 current_validates_to);
  }
  if (current_validates) {
    (*candidate)->flavor = VALIDATED;
    blockvector_set_data_length((*candidate)->b, state->archive_extent);
    avi_free_carve_state((void **)&state);
    write_candidate(candidate, false);
    return;
  }

  while (state->repairs <= total_blocks * 2) {
    if (avi_reassembly_checkpoint(work, *candidate, state, uuidp, uuidc)) {
      avi_free_carve_state((void **)&state);
      return;
    }
    if (reassembly_check_max_size(work->id, *candidate, uuidp, uuidc)) {
      break;
    }
    if (current_validates_to == state->archive_extent - 1) {
      uint64_t search_slot = avi_reassembly_media_start_slot(*candidate);
      uint64_t suspect_slot = 0;
      uint64_t suspect_blocks = 0;
      AviRunSearchResult classified_result = AVI_RUN_SEARCH_NO_MATCH;
      if (avi_reassembly_classified_search_current(*candidate, state,
              image_blocks, current_validates_to) && state->classified_search.owner == 1) {
        search_slot = state->classified_search.target_slot;
      }

      while (avi_reassembly_find_suspect_run(
                 *candidate, search_slot, &suspect_slot, &suspect_blocks)) {
        // A complete RIFF layout can conceal a displaced opaque payload. Restrict content-only
        // cleanup to a multiblock zero island before another displaced run has been repaired;
        // isolated zero blocks are common legitimate media content.
        bool allow_content_only = suspect_blocks > 1 && state->repairs <= 1;

        classified_result = avi_reassembly_find_classified_run(
            work, candidate, state, suspect_slot, suspect_blocks,
            image_blocks, current_validates_to, allow_content_only, true,
            uuidp, uuidc);
        if (classified_result != AVI_RUN_SEARCH_NO_MATCH) {
          break;
        }
        search_slot = suspect_slot + suspect_blocks;
      }

      if (classified_result == AVI_RUN_SEARCH_NO_MATCH
          && avi_reassembly_checkpoint(work, *candidate, state, uuidp, uuidc)) {
        avi_free_carve_state((void **)&state);
        return;
      }
      if (classified_result == AVI_RUN_SEARCH_VALIDATED) {
        (*candidate)->flavor = VALIDATED;
        state->repairs += suspect_blocks;
        carve_put_state((*candidate)->carvehashkey, state);
        avi_free_carve_state((void **)&state);
        write_candidate(candidate, false);
        return;
      }
      if (classified_result == AVI_RUN_SEARCH_IMPROVED
          || classified_result == AVI_RUN_SEARCH_COMPLETE
          || classified_result == AVI_RUN_SEARCH_REPAIRED) {
        state->repairs += suspect_blocks;
        avi_reassembly_refresh_state(*candidate, &state);
        carve_put_state((*candidate)->carvehashkey, state);
        if (avi_reassembly_validate_candidate(
                *candidate, state, &current_validates,
                &current_validates_to, &current_repair_from,
                &current_repair_end,
                suspect_slot * (uint64_t)scalpel_state.blocksize)
                != AVI_TRIAL_READY) {
          if (avi_reassembly_checkpoint(work, *candidate, state, uuidp, uuidc)) {
            avi_free_carve_state((void **)&state);
            return;
          }
          avi_free_carve_state((void **)&state);
          destroy_candidate(candidate);
          return;
        }
        if (current_validates) {
          (*candidate)->flavor = VALIDATED;
          avi_free_carve_state((void **)&state);
          write_candidate(candidate, false);
          return;
        }
        continue;
      }
      if (classified_result == AVI_RUN_SEARCH_STOPPED) {
        avi_free_carve_state((void **)&state);
        return;
      }
      break;
    }
    uint64_t failure_offset = current_validates_to + 1;
    uint64_t target_slot = avi_reassembly_failure_slot(
        *candidate, state, failure_offset);

    if (target_slot == 0) {
      target_slot = 1;
    }
    if (target_slot >= total_blocks) {
      break;
    }
    if (avi_reassembly_block_search_current(
            *candidate, state, target_slot, image_blocks, current_validates_to)) {
      goto single_block_search;
    }
    memset(&state->block_search, 0, sizeof(state->block_search));
    uint64_t earliest_repair_slot = avi_reassembly_earliest_repair_slot(
        state, failure_offset, target_slot);

    if (current_repair_from < failure_offset) {
      uint64_t media_slot = current_repair_from / scalpel_state.blocksize;

      if (media_slot < earliest_repair_slot) {
        earliest_repair_slot = media_slot;
      }
    }
    if (earliest_repair_slot == 0) {
      earliest_repair_slot = 1;
    }
    if (scalpel_state.mode_verbose
        && earliest_repair_slot < target_slot) {
      lock_fprintf(stdout,
                   "AVI reassembly: structured repair window=%" PRIu64
                   "-%" PRIu64 ".\n",
                   earliest_repair_slot, target_slot);
    }

    uint64_t media_search_slot = avi_reassembly_media_start_slot(*candidate);
    uint64_t structured_slot = target_slot;
    uint64_t classified_repair_slot = UINT64_MAX;

    // Start with the classified island nearest the proven failure. If the failure lies inside a
    // low-confidence run, repair from the run boundary rather than an isolated low score earlier
    // in otherwise valid opaque media.
    for (uint64_t slot = target_slot; slot >= earliest_repair_slot; slot--) {
      int64_t actual = blockvector_get_actual_blocknumber(
          (*candidate)->b, slot);

      if (avi_reassembly_source_boundary(*candidate, actual)) {
        classified_repair_slot = slot;
        while (classified_repair_slot > earliest_repair_slot) {
          int64_t previous = blockvector_get_actual_blocknumber(
              (*candidate)->b, classified_repair_slot - 1);

          if (!avi_reassembly_source_boundary(*candidate, previous)) {
            break;
          }
          classified_repair_slot--;
        }
        break;
      }
      if (slot == earliest_repair_slot) {
        break;
      }
    }

    uint64_t suspect_search_slot = media_search_slot;
    uint64_t suspect_slot = 0;
    uint64_t suspect_blocks = 0;
    uint64_t classified_blocks = 0;
    uint32_t content_pass = 0;
    uint64_t content_resume_slot = UINT64_MAX;
    uint64_t fallback_slot = target_slot;
    AviRunSearchResult classified_result = AVI_RUN_SEARCH_NO_MATCH;
    AviRunSearchResult suffix_result = AVI_RUN_SEARCH_NO_MATCH;
    if (avi_reassembly_displaced_search_current(*candidate, state, image_blocks,
                                                 current_validates_to, current_repair_end)) {
      structured_slot = state->displaced_search.target_slot;
      goto displaced_run_search;
    }
    if (avi_reassembly_shift_search_current(*candidate, state, image_blocks,
                                             current_validates_to, current_repair_end)) {
      classified_repair_slot = state->shift_search.classified_slot;
      if (state->shift_search.owner == 1) {
        goto classified_shifted_search;
      }
      fallback_slot = state->shift_search.target_slot;
      goto fallback_shifted_search;
    }
    if (avi_reassembly_indexed_search_current(*candidate, state,
            state->indexed_search.target_slot, image_blocks, current_validates_to)) {
      structured_slot = state->indexed_search.target_slot;
      classified_repair_slot = state->indexed_search.classified_slot;
      goto indexed_run_search;
    }
    if (avi_reassembly_zero_gap_search_current(*candidate, state, media_search_slot,
                                               image_blocks, current_validates_to, false)
        && state->zero_gap_search[0].next_slot < total_blocks) {
      goto partial_zero_gap_search;
    }
    if (avi_reassembly_classified_search_current(*candidate, state,
                                                 image_blocks, current_validates_to)) {
      if (state->classified_search.owner == 2) {
        suspect_search_slot = state->classified_search.target_slot;
        goto structural_classified_search;
      }
      if (state->classified_search.owner >= 3) {
        content_pass = state->classified_search.owner - 3;
        content_resume_slot = state->classified_search.target_slot;
        goto content_classified_search;
      }
    }
    suffix_result = avi_reassembly_find_zero_gap(
        work, candidate, state, media_search_slot, image_blocks,
        current_validates_to, true, &structured_slot, uuidp, uuidc);

    // If no gap reaches the complete declared extent, repair displaced runs that improve
    // structural or codec evidence before retaining a merely partial gap repair.
structural_classified_search:
    while (suffix_result == AVI_RUN_SEARCH_NO_MATCH
           && avi_reassembly_find_suspect_run(
               *candidate, suspect_search_slot, &suspect_slot,
               &suspect_blocks)) {
      int64_t suspect_actual = blockvector_get_actual_blocknumber(
          (*candidate)->b, suspect_slot);
      bool suspect_zero = suspect_actual >= 0
          && filemirror_actual_block_is_zero(scalpel_state.filemirror,
                                             suspect_actual);

      if (suspect_zero || suspect_slot >= earliest_repair_slot) {
        classified_result = avi_reassembly_find_classified_run(
            work, candidate, state, suspect_slot, suspect_blocks,
            image_blocks, current_validates_to, false, true, uuidp, uuidc);
        if (classified_result != AVI_RUN_SEARCH_NO_MATCH) {
          classified_repair_slot = suspect_slot;
          classified_blocks = suspect_blocks;
          break;
        }
      }
      suspect_search_slot = suspect_slot + suspect_blocks;
    }

partial_zero_gap_search:
    if (suffix_result == AVI_RUN_SEARCH_NO_MATCH
        && classified_result == AVI_RUN_SEARCH_NO_MATCH) {
      suffix_result = avi_reassembly_find_zero_gap(
          work, candidate, state, media_search_slot, image_blocks,
          current_validates_to, false, &structured_slot, uuidp, uuidc);
    }

    // A displaced run may not improve parsing until an earlier gap is repaired. Test multiblock
    // holes first because their combined content provides stronger ordering evidence than a single
    // block; single-block displacement remains fully supported on the second pass.
content_classified_search:
    for (; content_pass < 2 && suffix_result == AVI_RUN_SEARCH_NO_MATCH
             && classified_result == AVI_RUN_SEARCH_NO_MATCH;
         content_pass++) {
      suspect_search_slot = content_resume_slot == UINT64_MAX
          ? media_search_slot : content_resume_slot;
      content_resume_slot = UINT64_MAX;
      while (avi_reassembly_find_suspect_run(
                 *candidate, suspect_search_slot, &suspect_slot,
                 &suspect_blocks)) {
        int64_t suspect_actual = blockvector_get_actual_blocknumber(
            (*candidate)->b, suspect_slot);
        bool suspect_zero = suspect_actual >= 0
            && filemirror_actual_block_is_zero(scalpel_state.filemirror,
                                               suspect_actual);
        bool multiblock = suspect_blocks > 1;

        if (multiblock == (content_pass == 0)
            && (suspect_zero || suspect_slot >= earliest_repair_slot)) {
          classified_result = avi_reassembly_find_classified_run(
              work, candidate, state, suspect_slot, suspect_blocks,
              image_blocks, current_validates_to, true, false, uuidp,
              uuidc);
          if (classified_result != AVI_RUN_SEARCH_NO_MATCH) {
            classified_repair_slot = suspect_slot;
            classified_blocks = suspect_blocks;
            break;
          }
        }
        suspect_search_slot = suspect_slot + suspect_blocks;
      }
    }

    if (classified_result == AVI_RUN_SEARCH_NO_MATCH
        && suffix_result == AVI_RUN_SEARCH_NO_MATCH
        && avi_reassembly_checkpoint(work, *candidate, state, uuidp, uuidc)) {
      avi_free_carve_state((void **)&state);
      return;
    }
    if (classified_result != AVI_RUN_SEARCH_NO_MATCH) {
      if (classified_result == AVI_RUN_SEARCH_VALIDATED) {
        (*candidate)->flavor = VALIDATED;
        state->repairs += classified_blocks;
        carve_put_state((*candidate)->carvehashkey, state);
        avi_free_carve_state((void **)&state);
        write_candidate(candidate, false);
        return;
      }
      if (classified_result == AVI_RUN_SEARCH_IMPROVED
          || classified_result == AVI_RUN_SEARCH_COMPLETE
          || classified_result == AVI_RUN_SEARCH_REPAIRED) {
        state->repairs += classified_blocks;
        avi_reassembly_refresh_state(*candidate, &state);
        carve_put_state((*candidate)->carvehashkey, state);
        if (avi_reassembly_validate_candidate(
                *candidate, state, &current_validates,
                &current_validates_to, &current_repair_from,
                &current_repair_end,
                classified_repair_slot
                    * (uint64_t)scalpel_state.blocksize) != AVI_TRIAL_READY) {
          if (avi_reassembly_checkpoint(work, *candidate, state, uuidp, uuidc)) {
            avi_free_carve_state((void **)&state);
            return;
          }
          avi_free_carve_state((void **)&state);
          destroy_candidate(candidate);
          return;
        }
        if (current_validates) {
          (*candidate)->flavor = VALIDATED;
          avi_free_carve_state((void **)&state);
          write_candidate(candidate, false);
          return;
        }
        continue;
      }
      if (classified_result == AVI_RUN_SEARCH_STOPPED) {
        avi_free_carve_state((void **)&state);
        return;
      }
    }

classified_shifted_search:
    if (classified_repair_slot != UINT64_MAX
        && suffix_result == AVI_RUN_SEARCH_NO_MATCH) {
      state->shift_search.owner = 1;
      state->shift_search.classified_slot = classified_repair_slot;
      suffix_result = avi_reassembly_find_shifted_suffix(
          work, candidate, state, classified_repair_slot, image_blocks,
          current_validates_to, current_repair_end, uuidp, uuidc);
      structured_slot = classified_repair_slot;
    }

    state->indexed_search.classified_slot = classified_repair_slot;
    if (suffix_result == AVI_RUN_SEARCH_NO_MATCH) {
      structured_slot = target_slot;
    }
indexed_run_search:
    ;
    AviRunSearchResult indexed_run_result = AVI_RUN_SEARCH_NO_MATCH;

    while (suffix_result == AVI_RUN_SEARCH_NO_MATCH) {
      indexed_run_result = avi_reassembly_find_indexed_run(
          work, candidate, state, structured_slot, image_blocks,
          current_validates_to, uuidp, uuidc);
      if (indexed_run_result != AVI_RUN_SEARCH_NO_MATCH
          || structured_slot == earliest_repair_slot) {
        break;
      }
      structured_slot--;
    }

    if (indexed_run_result == AVI_RUN_SEARCH_NO_MATCH
        && suffix_result == AVI_RUN_SEARCH_NO_MATCH
        && avi_reassembly_checkpoint(work, *candidate, state, uuidp, uuidc)) {
      avi_free_carve_state((void **)&state);
      return;
    }
    if (indexed_run_result == AVI_RUN_SEARCH_VALIDATED) {
      (*candidate)->flavor = VALIDATED;
      state->repairs++;
      carve_put_state((*candidate)->carvehashkey, state);
      avi_free_carve_state((void **)&state);
      write_candidate(candidate, false);
      return;
    }
    if (indexed_run_result == AVI_RUN_SEARCH_IMPROVED
        || indexed_run_result == AVI_RUN_SEARCH_COMPLETE) {
      state->repairs++;
      avi_reassembly_refresh_state(*candidate, &state);
      carve_put_state((*candidate)->carvehashkey, state);
      if (avi_reassembly_validate_candidate(
              *candidate, state, &current_validates,
              &current_validates_to, &current_repair_from,
              &current_repair_end,
              structured_slot * (uint64_t)scalpel_state.blocksize)
              != AVI_TRIAL_READY) {
        if (avi_reassembly_checkpoint(work, *candidate, state, uuidp, uuidc)) {
          avi_free_carve_state((void **)&state);
          return;
        }
        avi_free_carve_state((void **)&state);
        destroy_candidate(candidate);
        return;
      }
      if (current_validates) {
        carve_put_state((*candidate)->carvehashkey, state);
        avi_free_carve_state((void **)&state);
        (*candidate)->flavor = VALIDATED;
        write_candidate(candidate, false);
        return;
      }
      continue;
    }
    if (indexed_run_result == AVI_RUN_SEARCH_STOPPED) {
      avi_free_carve_state((void **)&state);
      return;
    }

fallback_shifted_search:
    while (suffix_result == AVI_RUN_SEARCH_NO_MATCH) {
      if (fallback_slot == classified_repair_slot) {
        if (fallback_slot == earliest_repair_slot) {
          break;
        }
        fallback_slot--;
        continue;
      }
      state->shift_search.owner = 2;
      state->shift_search.classified_slot = classified_repair_slot;
      suffix_result = avi_reassembly_find_shifted_suffix(
          work, candidate, state, fallback_slot, image_blocks,
          current_validates_to, current_repair_end, uuidp, uuidc);
      structured_slot = fallback_slot;
      if (suffix_result != AVI_RUN_SEARCH_NO_MATCH
          || fallback_slot == earliest_repair_slot) {
        break;
      }
      fallback_slot--;
    }

    if (suffix_result == AVI_RUN_SEARCH_NO_MATCH
        && avi_reassembly_checkpoint(work, *candidate, state, uuidp, uuidc)) {
      avi_free_carve_state((void **)&state);
      return;
    }
    if (suffix_result == AVI_RUN_SEARCH_VALIDATED) {
      (*candidate)->flavor = VALIDATED;
      state->repairs++;
      carve_put_state((*candidate)->carvehashkey, state);
      avi_free_carve_state((void **)&state);
      write_candidate(candidate, false);
      return;
    }
    if (suffix_result == AVI_RUN_SEARCH_IMPROVED
        || suffix_result == AVI_RUN_SEARCH_COMPLETE) {
      state->repairs++;
      avi_reassembly_refresh_state(*candidate, &state);
      carve_put_state((*candidate)->carvehashkey, state);
      if (avi_reassembly_validate_candidate(
              *candidate, state, &current_validates,
              &current_validates_to, &current_repair_from,
              &current_repair_end,
              structured_slot * (uint64_t)scalpel_state.blocksize)
              != AVI_TRIAL_READY) {
        if (avi_reassembly_checkpoint(work, *candidate, state, uuidp, uuidc)) {
          avi_free_carve_state((void **)&state);
          return;
        }
        avi_free_carve_state((void **)&state);
        destroy_candidate(candidate);
        return;
      }
      if (current_validates) {
        carve_put_state((*candidate)->carvehashkey, state);
        avi_free_carve_state((void **)&state);
        (*candidate)->flavor = VALIDATED;
        write_candidate(candidate, false);
        return;
      }
      continue;
    }
    if (suffix_result == AVI_RUN_SEARCH_STOPPED) {
      avi_free_carve_state((void **)&state);
      return;
    }

    structured_slot = target_slot;
displaced_run_search:
    ;
    AviRunSearchResult run_result = AVI_RUN_SEARCH_NO_MATCH;
    while (true) {
      run_result = avi_reassembly_find_displaced_run(
          work, candidate, state, structured_slot, image_blocks,
          current_validates_to, current_repair_end, uuidp, uuidc);
      if (run_result != AVI_RUN_SEARCH_NO_MATCH
          || structured_slot == earliest_repair_slot) {
        break;
      }
      structured_slot--;
    }

    if (run_result == AVI_RUN_SEARCH_NO_MATCH
        && avi_reassembly_checkpoint(work, *candidate, state, uuidp, uuidc)) {
      avi_free_carve_state((void **)&state);
      return;
    }
    if (run_result == AVI_RUN_SEARCH_VALIDATED) {
      (*candidate)->flavor = VALIDATED;
      state->repairs++;
      carve_put_state((*candidate)->carvehashkey, state);
      avi_free_carve_state((void **)&state);
      write_candidate(candidate, false);
      return;
    }
    if (run_result == AVI_RUN_SEARCH_IMPROVED
        || run_result == AVI_RUN_SEARCH_COMPLETE) {
      state->repairs++;
      avi_reassembly_refresh_state(*candidate, &state);
      carve_put_state((*candidate)->carvehashkey, state);
      if (avi_reassembly_validate_candidate(
              *candidate, state, &current_validates,
              &current_validates_to, &current_repair_from,
              &current_repair_end,
              structured_slot * (uint64_t)scalpel_state.blocksize)
              != AVI_TRIAL_READY) {
        if (avi_reassembly_checkpoint(work, *candidate, state, uuidp, uuidc)) {
          avi_free_carve_state((void **)&state);
          return;
        }
        avi_free_carve_state((void **)&state);
        destroy_candidate(candidate);
        return;
      }
      if (current_validates) {
        carve_put_state((*candidate)->carvehashkey, state);
        avi_free_carve_state((void **)&state);
        (*candidate)->flavor = VALIDATED;
        write_candidate(candidate, false);
        return;
      }
      continue;
    }
    if (run_result == AVI_RUN_SEARCH_STOPPED) {
      avi_free_carve_state((void **)&state);
      return;
    }

single_block_search:
    ;
    int64_t target_apparent = blockvector_get_apparent_blocknumber(
        (*candidate)->b, target_slot);
    int64_t target_actual = blockvector_get_actual_blocknumber(
        (*candidate)->b, target_slot);
    int64_t previous_actual = blockvector_get_actual_blocknumber(
        (*candidate)->b, target_slot - 1);
    AviBlockSearch *search = &state->block_search;

    if (!search->active) {
      *search = (AviBlockSearch){
          .view = avi_reassembly_block_search_view(*candidate, state),
          .target_slot = target_slot, .image_blocks = image_blocks,
          .baseline_to = current_validates_to,
          .best_actual = -1, .best_validates_to = current_validates_to,
          .best_confidence = BLOCK_CONFIDENCE_INVALID,
          .best_reserved = INT64_MAX, .best_distance = UINT64_MAX,
          .blocksize = scalpel_state.blocksize, .active = 1};
    }
    int64_t best_actual = search->best_actual;
    uint64_t best_validates_to = search->best_validates_to;
    BlockValidationDecision best_confidence = search->best_confidence;
    int64_t best_reserved = search->best_reserved;
    uint64_t best_distance = search->best_distance;

    for (uint64_t actual_index = search->next_actual; actual_index < image_blocks;
         actual_index++) {
      search->next_actual = actual_index;
      if ((actual_index & UINT64_C(0x3f)) == 0) {
        if (reassembly_check_kill_queue(work, candidate, uuidp, uuidc)) {
          avi_free_carve_state((void **)&state);
          return;
        }
        if (avi_reassembly_checkpoint(work, *candidate, state, uuidp, uuidc)) {
          avi_free_carve_state((void **)&state);
          return;
        }
      }
      int64_t actual = (int64_t)actual_index;
      int64_t available_apparent = filemirror_apparent_blocknumber(
          scalpel_state.filemirror, actual);
      int64_t source_slot = avi_reassembly_find_apparent_slot(
          (*candidate)->b, available_apparent);

      if (actual == target_actual || source_slot == 0
          || (source_slot < 0
              && filemirror_actual_block_covered(scalpel_state.filemirror,
                                                 actual))) {
        search->next_actual = actual_index + 1;
        continue;
      }
      int64_t trial_apparent = available_apparent;

      if (trial_apparent < 0) {
        search->next_actual = actual_index + 1;
        continue;
      }
      int64_t source_apparent = source_slot >= 0
          ? blockvector_get_apparent_blocknumber((*candidate)->b,
                                                 (uint64_t)source_slot)
          : -1;

      blockvector_set_apparent_blocknumber((*candidate)->b, target_slot,
                                           trial_apparent);
      if (source_slot >= 0) {
        blockvector_set_apparent_blocknumber((*candidate)->b,
                                             (uint64_t)source_slot,
                                             target_apparent);
      }
      inflate_blockvector((*candidate)->b);
      blockvector_set_data_length((*candidate)->b, state->archive_extent);

      uint64_t trial_validates_to = 0;
      bool trial_validates = false;
      uint64_t trial_deep_slot = target_slot;

      if (source_slot >= 0 && (uint64_t)source_slot < trial_deep_slot) {
        trial_deep_slot = (uint64_t)source_slot;
      }
      uint64_t trial_deep_from = trial_deep_slot
          * (uint64_t)scalpel_state.blocksize;

      AviTrialResult validation = avi_reassembly_validate_candidate(
          *candidate, state, &trial_validates, &trial_validates_to, NULL, NULL,
          trial_deep_from);
      if (validation == AVI_TRIAL_ERROR) {
        trial_validates_to = 0;
      }

      if (trial_validates) {
        (*candidate)->flavor = VALIDATED;
        blockvector_set_data_length((*candidate)->b, state->archive_extent);
        state->repairs++;
        memset(search, 0, sizeof(*search));
        carve_put_state((*candidate)->carvehashkey, state);
        avi_free_carve_state((void **)&state);
        write_candidate(candidate, false);
        return;
      }

      blockvector_set_apparent_blocknumber((*candidate)->b, target_slot,
                                           target_apparent);
      if (source_slot >= 0) {
        blockvector_set_apparent_blocknumber((*candidate)->b,
                                             (uint64_t)source_slot,
                                             source_apparent);
      }
      if (validation == AVI_TRIAL_INTERRUPTED
          && avi_reassembly_checkpoint(work, *candidate, state, uuidp, uuidc)) {
        avi_free_carve_state((void **)&state);
        return;
      }

      BlockValidationDecision confidence = filemirror_get_blocktype(
          scalpel_state.filemirror, actual, (*candidate)->needleidx);
      int64_t reserved = scalpel_state.reservations
          ? filemirror_actual_block_reserved(scalpel_state.filemirror, actual)
          : 0;
      uint64_t distance = previous_actual >= 0
          ? (uint64_t)llabs(actual - previous_actual) : UINT64_MAX;

      if (trial_validates_to > best_validates_to
          || (trial_validates_to == best_validates_to
              && best_actual >= 0
              && (confidence > best_confidence
                  || (confidence == best_confidence
                      && (reserved < best_reserved
                          || (reserved == best_reserved
                              && distance < best_distance)))))) {
        best_actual = actual;
        best_validates_to = trial_validates_to;
        best_confidence = confidence;
        best_reserved = reserved;
        best_distance = distance;
        search->best_actual = best_actual;
        search->best_validates_to = best_validates_to;
        search->best_confidence = best_confidence;
        search->best_reserved = best_reserved;
        search->best_distance = best_distance;
      }
      search->next_actual = actual_index + 1;
    }

    // Trials restore the apparent mapping immediately; synchronize the derived actual mapping and
    // data once before selecting and committing the best trial.
    inflate_blockvector((*candidate)->b);
    blockvector_set_data_length((*candidate)->b, state->archive_extent);

    if (avi_reassembly_checkpoint(work, *candidate, state, uuidp, uuidc)) {
      avi_free_carve_state((void **)&state);
      return;
    }
    if (best_actual < 0 || best_validates_to <= current_validates_to) {
      if (scalpel_state.mode_verbose) {
        lock_fprintf(stdout,
                     "AVI reassembly: no improving block for slot=%" PRIu64
                     " validates-to=%" PRIu64 ".\n",
                     target_slot, current_validates_to);
      }
      break;
    }
    if (scalpel_state.mode_verbose) {
      lock_fprintf(stdout,
                   "AVI reassembly: slot=%" PRIu64 " actual=%" PRId64
                   " advances validation from %" PRIu64 " to %" PRIu64
                   ".\n",
                   target_slot, best_actual, current_validates_to,
                   best_validates_to);
    }
    int64_t best_source_slot = avi_reassembly_find_actual_slot(
        (*candidate)->b, best_actual);
    int64_t best_apparent = best_source_slot >= 0
        ? blockvector_get_apparent_blocknumber((*candidate)->b,
                                               (uint64_t)best_source_slot)
        : filemirror_apparent_blocknumber(scalpel_state.filemirror,
                                          best_actual);

    if (best_apparent < 0 || best_source_slot == 0) {
      break;
    }

    // An inserted gap shifts the remaining physical run without changing its contents. Try the
    // corresponding suffix rotation as one operation, but retain it only when validation proves
    // that it is better than the individual block repair.
    if (best_source_slot > (int64_t)target_slot) {
      uint64_t shift = (uint64_t)best_source_slot - target_slot;
      uint64_t rotation_validates_to = 0;
      bool rotation_validates = false;

      if (avi_reassembly_rotate_suffix(
              *candidate, state, target_slot, shift, image_blocks,
              best_validates_to, true, &rotation_validates,
              &rotation_validates_to)) {
        memset(search, 0, sizeof(*search));
        state->repairs += shift;
        avi_reassembly_refresh_state(*candidate, &state);
        carve_put_state((*candidate)->carvehashkey, state);
        if (avi_reassembly_validate_candidate(
                *candidate, state, &rotation_validates,
                &rotation_validates_to, &current_repair_from,
                &current_repair_end,
                target_slot * (uint64_t)scalpel_state.blocksize)
                != AVI_TRIAL_READY) {
          if (avi_reassembly_checkpoint(work, *candidate, state, uuidp, uuidc)) {
            avi_free_carve_state((void **)&state);
            return;
          }
          avi_free_carve_state((void **)&state);
          destroy_candidate(candidate);
          return;
        }
        if (rotation_validates) {
          avi_free_carve_state((void **)&state);
          (*candidate)->flavor = VALIDATED;
          write_candidate(candidate, false);
          return;
        }
        current_validates_to = rotation_validates_to;
        continue;
      }
    }

    if (avi_reassembly_checkpoint(work, *candidate, state, uuidp, uuidc)) {
      avi_free_carve_state((void **)&state);
      return;
    }
    memset(search, 0, sizeof(*search));
    blockvector_set_apparent_blocknumber((*candidate)->b, target_slot,
                                         best_apparent);
    if (best_source_slot >= 0) {
      blockvector_set_apparent_blocknumber((*candidate)->b,
                                           (uint64_t)best_source_slot,
                                           target_apparent);
    }
    inflate_blockvector((*candidate)->b);
    blockvector_set_data_length((*candidate)->b, state->archive_extent);
    state->repairs++;
    uint64_t committed_deep_slot = target_slot;

    if (best_source_slot >= 0
        && (uint64_t)best_source_slot < committed_deep_slot) {
      committed_deep_slot = (uint64_t)best_source_slot;
    }
    if (avi_reassembly_validate_candidate(
            *candidate, state, &current_validates,
            &current_validates_to, &current_repair_from,
            &current_repair_end,
            committed_deep_slot * (uint64_t)scalpel_state.blocksize)
            != AVI_TRIAL_READY) {
      if (avi_reassembly_checkpoint(work, *candidate, state, uuidp, uuidc)) {
        avi_free_carve_state((void **)&state);
        return;
      }
      avi_free_carve_state((void **)&state);
      destroy_candidate(candidate);
      return;
    }
    carve_put_state((*candidate)->carvehashkey, state);
  }

  if (avi_reassembly_checkpoint(work, *candidate, state, uuidp, uuidc)) {
    avi_free_carve_state((void **)&state);
    return;
  }
  avi_free_carve_state((void **)&state);
  if (scalpel_state.write_promising) {
    (*candidate)->flavor = PROMISING;
    write_candidate(candidate, false);
  }
  else {
    destroy_candidate(candidate);
  }
}

#endif // SCALPEL3_AVI_H
