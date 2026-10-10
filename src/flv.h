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

// Flash Video validation and fragmented recovery support.
//
// FLV tag headers describe payload lengths, stream identifiers, and timestamps.
// Each tag is followed by a back pointer to the preceding header and payload.
// These independent fields make tag boundaries strong recovery anchors even
// when the media payload itself is opaque. FLV has no mandatory end marker,
// and structural metadata cannot prove opaque payload bytes, so recovered FLV
// files remain PROMISING for independent review.

#ifndef SCALPEL3_FLV_H
#define SCALPEL3_FLV_H

#include "scalpel.h"

#include <math.h>

#define FLV_HEADER_SIZE UINT64_C(9)
#define FLV_PREVIOUS_TAG_SIZE UINT64_C(4)
#define FLV_TAG_HEADER_SIZE UINT64_C(11)
#define FLV_MINIMUM_SIZE \
  (FLV_HEADER_SIZE + FLV_PREVIOUS_TAG_SIZE + FLV_TAG_HEADER_SIZE \
   + FLV_PREVIOUS_TAG_SIZE)
#define FLV_MAXIMUM_SIZE UINT64_C(4294967295)
#define FLV_PAYLOAD_CONFIDENCE_MAX 99
#define FLV_MAX_HEADER_EXTENSION UINT64_C(1048576)
#define FLV_REPAIR_ANCHOR_TAGS 3U
#define FLV_REPAIR_CONTEXT_BLOCKS 2U
#define FLV_REPAIR_EXTENSION_BLOCKS 64U
#define FLV_REPAIR_SCAN_QUANTUM UINT64_C(256)
#define FLV_CONTENT_HISTOGRAM_BINS 32U
#define FLV_REPAIR_CONTENT_DECISIVE_MARGIN UINT64_C(8192)
#define FLV_REPAIR_CONTENT_TARGET_TOLERANCE UINT64_C(1024)
#define FLV_REPAIR_BOUNDARY_CANDIDATES 128U
#define FLV_REPAIR_AMBIGUITY_SLOTS 128U
#define FLV_REPAIR_HISTORY_MAX 8U
#define FLV_REPAIR_OUTPUT_MAX 64U
#define FLV_REPAIR_ANY_PREVIOUS_SIZE UINT32_MAX
#define FLV_CARVE_STATE_MAGIC UINT32_C(0x464c5653)
#define FLV_CARVE_STATE_VERSION 8U

#define FLV_TAG_AUDIO UINT8_C(8)
#define FLV_TAG_VIDEO UINT8_C(9)
#define FLV_TAG_SCRIPT UINT8_C(18)

typedef enum FlvParseResult {
  FLV_PARSE_INVALID = 0,
  FLV_PARSE_PARTIAL = 1,
  FLV_PARSE_COMPLETE = 2
} FlvParseResult;

typedef struct FlvLayout {
  uint64_t parsed_extent;
  uint64_t observed_extent;
  uint64_t failure_offset;
  uint64_t required_extent;
  uint64_t current_tag_offset;
  uint64_t current_tag_back_pointer_offset;
  uint64_t tag_count;
  uint64_t audio_tags;
  uint64_t video_tags;
  uint64_t script_tags;
  uint64_t matching_back_pointers;
  uint64_t mismatching_back_pointers;
  uint64_t last_mismatching_back_pointer_offset;
  uint64_t last_mismatching_tag_offset;
  uint64_t metadata_file_size;
  uint32_t current_tag_expected_size;
  uint32_t last_mismatching_expected_size;
  uint32_t maximum_media_timestamp;
  double metadata_duration;
  bool metadata_duration_known;
  bool metadata_file_size_known;
  bool current_tag_shape_valid;
  bool current_tag_header_valid;
  bool terminal_extent_proven;
} FlvLayout;

typedef enum FlvRepairStage {
  FLV_REPAIR_STAGE_NONE = 0,
  FLV_REPAIR_STAGE_SCAN = 1,
  FLV_REPAIR_STAGE_EXTEND = 2,
  FLV_REPAIR_STAGE_PAIR_FIRST_SCAN = 3,
  FLV_REPAIR_STAGE_PAIR_SECOND_SCAN = 4,
  FLV_REPAIR_STAGE_PAIR_EXTEND = 5
} FlvRepairStage;

typedef enum FlvRepairResult {
  FLV_REPAIR_NO_MATCH = 0,
  FLV_REPAIR_READY = 1,
  FLV_REPAIR_PROGRESSED = 2,
  FLV_REPAIR_STOPPED = 3
} FlvRepairResult;

typedef struct FlvRepairChoice {
  uint64_t target_slot;
  int64_t actual_start;
  uint64_t content_cost;
  uint64_t confidence;
  int64_t reservations;
} FlvRepairChoice;

typedef struct FlvRepairAmbiguity {
  uint64_t first_target_slot;
  uint64_t last_target_slot;
  uint32_t choice_count;
  uint32_t reserved;
  int64_t baseline_actual[FLV_REPAIR_AMBIGUITY_SLOTS];
  FlvRepairChoice choices[FLV_REPAIR_BOUNDARY_CANDIDATES];
} FlvRepairAmbiguity;

typedef struct FlvCarveState {
  uint32_t magic;
  uint32_t version;
  uint32_t stage;
  uint32_t extension_terminal_only;
  uint64_t signature;
  uint64_t next_actual;
  uint64_t best_target_slot;
  int64_t best_actual;
  uint64_t best_content_cost;
  uint64_t best_confidence;
  int64_t best_reservations;
  uint64_t repairs;
  uint64_t preserved_terminal_generation;
  uint64_t pair_target_slot;
  uint64_t pair_first_blocks;
  uint64_t pair_minimum_first_blocks;
  uint64_t pair_maximum_first_blocks;
  uint64_t pair_next_second_actual;
  uint64_t pair_source_bytes;
  int64_t pair_first_actual;
  int64_t pair_second_actual;
  uint32_t ambiguity_count;
  uint32_t ambiguity_reserved;
  FlvRepairAmbiguity pending_ambiguity;
  FlvRepairAmbiguity ambiguities[FLV_REPAIR_HISTORY_MAX];
  uint64_t extension_mapped;
  uint64_t extension_signature;
} FlvCarveState;

typedef struct FlvContentHistogram {
  uint64_t bins[FLV_CONTENT_HISTOGRAM_BINS];
  uint64_t samples;
} FlvContentHistogram;

typedef struct FlvRepairAnchor {
  uint64_t target_slot;
  int64_t actual_start;
  uint64_t source_bytes;
  uint64_t content_cost;
  uint64_t confidence;
  int64_t reservations;
} FlvRepairAnchor;

typedef struct FlvPairAnchor {
  uint64_t target_slot;
  uint64_t first_blocks;
  uint64_t source_bytes;
  int64_t first_actual;
  int64_t second_actual;
} FlvPairAnchor;

static inline uint32_t flv_read_be24(const uint8_t *data);
static inline uint32_t flv_read_be32(const uint8_t *data);
static inline double flv_read_be_double(const uint8_t *data);
static inline bool flv_tag_type_valid(uint8_t type);
static inline bool flv_header_valid(const uint8_t *data, uint64_t length,
                                    uint64_t *data_offset);
static inline bool flv_find_amf_number(const uint8_t *data, uint64_t length,
                                       const char *name, double *value);
static inline void flv_read_script_metadata(const uint8_t *data,
                                            uint64_t length,
                                            FlvLayout *layout);
static inline bool flv_tag_payload_header_valid(uint8_t type,
                                                const uint8_t *data,
                                                uint64_t length);
static inline FlvParseResult flv_parse_file(const uint8_t *data,
                                            uint64_t length,
                                            FlvLayout *layout);
static inline bool flv_layout_has_media(const FlvLayout *layout);
static inline bool flv_layout_terminal_likely(const FlvLayout *layout);
static inline bool flv_layout_terminal_boundary(const FlvLayout *layout,
                                                FlvParseResult result,
                                                uint64_t length);
static inline bool flv_layout_structural_terminal_candidate(
    const FlvLayout *layout, FlvParseResult result, uint64_t length);
static inline bool flv_write_extent_hypothesis(CarveInfo *candidate,
                                               uint64_t extent);
static inline char *flv_header_discovery(char *base, uint64_t offset,
                                         uint64_t remaining, char **matchpos,
                                         uint32_t *matchlen,
                                         uint32_t blocksize);
static inline char *flv_footer_discovery(char *base, uint64_t offset,
                                         uint64_t remaining, char **matchpos,
                                         uint32_t *matchlen,
                                         uint32_t blocksize);
static inline uint32_t flv_block_validate(
    char *data, uint64_t length, BlockValidationDecision *decision,
    uint64_t *validates_to, uint32_t needleidx, uint32_t blocksize,
    void *blockhashkey);
static inline void flv_file_validate(char *data, uint64_t length,
                                     bool *validates,
                                     uint64_t *validates_to,
                                     bool *promising, uint32_t needleidx,
                                     uint32_t blocksize,
                                     void *carvehashkey);
static inline bool flv_serialize_carve_state(void **state, FILE *fp,
                                             StateSerialization mode);
static inline uint64_t flv_extension_signature(
    BlockVector *original, uint64_t target, int64_t actual);
static inline uint64_t flv_reassembly_restore_extension(
    CarveInfo *candidate, FlvCarveState *state, uint64_t mapped,
    uint64_t maximum_blocks, uint64_t image_blocks);
static inline void *flv_clone_carve_state(const void *srcstate);
static inline void flv_free_carve_state(void **state);
static inline void flv_print_carve_state(const void *state);
static inline bool flv_carve_state_valid(const FlvCarveState *state);
static inline void flv_repair_ambiguity_reset(
    FlvRepairAmbiguity *ambiguity);
static inline void flv_repair_ambiguity_prepare(
    const CarveInfo *candidate, uint64_t first_target,
    uint64_t last_target, FlvRepairAmbiguity *ambiguity);
static inline void flv_repair_ambiguity_retain(
    FlvRepairAmbiguity *ambiguity, const FlvRepairAnchor *anchor);
static inline void flv_repair_ambiguity_commit(
    FlvCarveState *state, uint64_t selected_target,
    int64_t selected_actual);
static inline void flv_publish_ambiguities(
    CarveInfo *candidate, const FlvCarveState *state);
static inline uint64_t flv_repair_signature(const FlvLayout *layout,
                                            uint64_t length);
static inline void flv_content_histogram_add(
    FlvContentHistogram *histogram, const uint8_t *data, uint64_t length);
static inline uint64_t flv_content_histogram_cost(
    const FlvContentHistogram *left, const FlvContentHistogram *right);
static inline bool flv_candidate_context_histogram(
    const CarveInfo *candidate, uint64_t target_slot,
    FlvContentHistogram *histogram);
static inline bool flv_source_histogram(int64_t actual_start,
                                        FlvContentHistogram *histogram);
static inline bool flv_candidate_block_histogram(
    const CarveInfo *candidate, uint64_t slot,
    FlvContentHistogram *histogram);
static inline bool flv_actual_block_histogram(
    int64_t actual, FlvContentHistogram *histogram);
static inline bool flv_read_actual_run(int64_t actual_start,
                                       uint64_t offset, uint8_t *output,
                                       uint64_t length);
static inline bool flv_read_actual_pair(int64_t first_actual,
                                        uint64_t first_bytes,
                                        int64_t second_actual,
                                        uint64_t offset, uint8_t *output,
                                        uint64_t length);
static inline bool flv_actual_in_prefix(const CarveInfo *candidate,
                                        uint64_t target_slot,
                                        int64_t actual);
static inline bool flv_source_range_available(const CarveInfo *candidate,
                                              uint64_t target_slot,
                                              int64_t actual_start,
                                              uint64_t source_bytes);
static inline bool flv_repair_anchor_valid(const CarveInfo *candidate,
                                           uint64_t target_slot,
                                           uint64_t context_slot,
                                           int64_t actual_start,
                                           uint64_t back_pointer_offset,
                                           uint32_t expected_size,
                                           FlvRepairAnchor *anchor);
static inline bool flv_repair_anchor_better(const FlvRepairAnchor *trial,
                                            const FlvRepairAnchor *best);
static inline bool flv_repair_partial_anchor_valid(
    const CarveInfo *candidate, uint64_t target_slot, int64_t actual_start,
    uint64_t back_pointer_offset, uint32_t expected_size,
    uint64_t *minimum_first_blocks, uint64_t *maximum_first_blocks);
static inline bool flv_repair_pair_anchor_valid(
    const CarveInfo *candidate, uint64_t target_slot,
    int64_t first_actual, uint64_t first_blocks, int64_t second_actual,
    uint64_t back_pointer_offset, uint32_t expected_size,
    FlvPairAnchor *anchor);
static inline void flv_repair_refine_pair_anchor(
    const CarveInfo *candidate, uint64_t back_pointer_offset,
    uint32_t expected_size, FlvPairAnchor *anchor);
static inline FlvRepairResult flv_reassembly_find_anchor(
    ThreadWork *work, CarveInfo **candidate, const FlvLayout *layout,
    FlvCarveState *state, FlvRepairAnchor *anchor,
    uuid_string_t uuidp, uuid_string_t uuidc);
static inline FlvRepairResult flv_reassembly_extend_anchor(
    ThreadWork *work, CarveInfo **candidate, FlvCarveState *state,
    uuid_string_t uuidp, uuid_string_t uuidc);
static inline FlvRepairResult flv_reassembly_find_pair_anchor(
    ThreadWork *work, CarveInfo **candidate, const FlvLayout *layout,
    FlvCarveState *state, FlvPairAnchor *anchor,
    uuid_string_t uuidp, uuid_string_t uuidc);
static inline FlvRepairResult flv_reassembly_extend_pair(
    ThreadWork *work, CarveInfo **candidate, FlvCarveState *state,
    uuid_string_t uuidp, uuid_string_t uuidc);
static inline void flv_reassembly(ThreadWork *work, CarveInfo **candidate,
                                  uuid_string_t uuidp,
                                  uuid_string_t uuidc);

static inline uint32_t flv_read_be24(const uint8_t *data) {
  return ((uint32_t)data[0] << 16) | ((uint32_t)data[1] << 8)
      | (uint32_t)data[2];
}

static inline uint32_t flv_read_be32(const uint8_t *data) {
  return ((uint32_t)data[0] << 24) | ((uint32_t)data[1] << 16)
      | ((uint32_t)data[2] << 8) | (uint32_t)data[3];
}

static inline double flv_read_be_double(const uint8_t *data) {
  uint64_t bits = ((uint64_t)data[0] << 56) | ((uint64_t)data[1] << 48)
      | ((uint64_t)data[2] << 40) | ((uint64_t)data[3] << 32)
      | ((uint64_t)data[4] << 24) | ((uint64_t)data[5] << 16)
      | ((uint64_t)data[6] << 8) | (uint64_t)data[7];
  double value;

  memcpy(&value, &bits, sizeof(value));
  return value;
}

static inline bool flv_tag_type_valid(uint8_t type) {
  return type == FLV_TAG_AUDIO || type == FLV_TAG_VIDEO
      || type == FLV_TAG_SCRIPT;
}

static inline bool flv_header_valid(const uint8_t *data, uint64_t length,
                                    uint64_t *data_offset) {
  if (!data || length < FLV_HEADER_SIZE
      || memcmp(data, "FLV", 3) != 0 || data[3] == 0
      || (data[4] & UINT8_C(0xfa)) != 0) {
    return false;
  }
  uint64_t offset = flv_read_be32(data + 5);

  if (offset < FLV_HEADER_SIZE || offset > FLV_MAX_HEADER_EXTENSION
      || offset > length) {
    return false;
  }
  if (data_offset) {
    *data_offset = offset;
  }
  return true;
}

// AMF0 stores an object property as a two-byte name length, the property name,
// a one-byte type, and the encoded value. Numeric metadata can therefore be
// read without interpreting unrelated nested values.
static inline bool flv_find_amf_number(const uint8_t *data, uint64_t length,
                                       const char *name, double *value) {
  if (!data || !name || !value) {
    return false;
  }
  size_t name_length = strlen(name);
  if (name_length == 0 || name_length > UINT16_MAX
      || length < name_length + 11) {
    return false;
  }

  for (uint64_t position = 0;
       position + 2 + name_length + 1 + sizeof(double) <= length;
       position++) {
    if (data[position] != (uint8_t)(name_length >> 8)
        || data[position + 1] != (uint8_t)name_length
        || memcmp(data + position + 2, name, name_length) != 0
        || data[position + 2 + name_length] != 0) {
      continue;
    }
    double candidate = flv_read_be_double(
        data + position + 3 + name_length);
    if (isfinite(candidate) && candidate >= 0.0) {
      *value = candidate;
      return true;
    }
  }
  return false;
}

static inline void flv_read_script_metadata(const uint8_t *data,
                                            uint64_t length,
                                            FlvLayout *layout) {
  if (!data || !layout || length < 4) {
    return;
  }
  double value;

  if (!layout->metadata_duration_known
      && flv_find_amf_number(data, length, "duration", &value)) {
    layout->metadata_duration = value;
    layout->metadata_duration_known = true;
  }
  if (!layout->metadata_file_size_known
      && flv_find_amf_number(data, length, "filesize", &value)
      && value >= (double)FLV_MINIMUM_SIZE
      && value <= (double)FLV_MAXIMUM_SIZE) {
    uint64_t rounded = (uint64_t)(value + 0.5);
    if (fabs(value - (double)rounded) <= 0.5) {
      layout->metadata_file_size = rounded;
      layout->metadata_file_size_known = true;
    }
  }
}

static inline bool flv_tag_payload_header_valid(uint8_t type,
                                                const uint8_t *data,
                                                uint64_t length) {
  if (length == 0) {
    return true;
  }
  if (!data) {
    return false;
  }
  if (type == FLV_TAG_AUDIO) {
    uint8_t format = data[0] >> 4;
    return format <= 15;
  }
  if (type == FLV_TAG_VIDEO) {
    uint8_t frame_type = data[0] >> 4;
    uint8_t codec = data[0] & UINT8_C(0x0f);
    return frame_type >= 1 && frame_type <= 5 && codec >= 1 && codec <= 15;
  }
  return type == FLV_TAG_SCRIPT;
}

static inline FlvParseResult flv_parse_file(const uint8_t *data,
                                            uint64_t length,
                                            FlvLayout *layout) {
  if (!layout) {
    return FLV_PARSE_INVALID;
  }
  memset(layout, 0, sizeof(*layout));
  layout->failure_offset = UINT64_MAX;
  layout->required_extent = UINT64_MAX;
  layout->current_tag_offset = UINT64_MAX;
  layout->current_tag_back_pointer_offset = UINT64_MAX;
  layout->last_mismatching_back_pointer_offset = UINT64_MAX;
  layout->last_mismatching_tag_offset = UINT64_MAX;

  uint64_t data_offset;
  if (!flv_header_valid(data, length, &data_offset)) {
    return FLV_PARSE_INVALID;
  }
  layout->observed_extent = data_offset;
  if (data_offset > UINT64_MAX - FLV_PREVIOUS_TAG_SIZE) {
    return FLV_PARSE_INVALID;
  }
  if (length < data_offset + FLV_PREVIOUS_TAG_SIZE) {
    layout->failure_offset = data_offset;
    layout->required_extent = data_offset + FLV_PREVIOUS_TAG_SIZE;
    return FLV_PARSE_PARTIAL;
  }
  if (flv_read_be32(data + data_offset) != 0) {
    return FLV_PARSE_INVALID;
  }

  uint64_t position = data_offset + FLV_PREVIOUS_TAG_SIZE;
  layout->parsed_extent = position;
  layout->observed_extent = position;
  while (position < length) {
    layout->current_tag_offset = position;
    layout->current_tag_shape_valid = false;
    layout->current_tag_header_valid = false;
    if (length - position < FLV_TAG_HEADER_SIZE) {
      layout->failure_offset = position;
      layout->required_extent = position + FLV_TAG_HEADER_SIZE;
      layout->observed_extent = length;
      if (length - position >= 8) {
        uint8_t partial_flags_and_type = data[position];
        uint8_t partial_type = partial_flags_and_type & UINT8_C(0x1f);
        uint64_t partial_payload_length = flv_read_be24(
            data + position + 1);

        if ((partial_flags_and_type & UINT8_C(0xc0)) == 0
            && flv_tag_type_valid(partial_type)
            && partial_payload_length <= UINT64_MAX - position
                - FLV_TAG_HEADER_SIZE - FLV_PREVIOUS_TAG_SIZE) {
          layout->current_tag_back_pointer_offset = position
              + FLV_TAG_HEADER_SIZE + partial_payload_length;
          layout->current_tag_expected_size = (uint32_t)(
              FLV_TAG_HEADER_SIZE + partial_payload_length);
          layout->current_tag_shape_valid = true;
          layout->required_extent = layout->current_tag_back_pointer_offset
              + FLV_PREVIOUS_TAG_SIZE;
        }
      }
      return FLV_PARSE_PARTIAL;
    }

    uint8_t flags_and_type = data[position];
    uint8_t type = flags_and_type & UINT8_C(0x1f);
    uint64_t payload_length = flv_read_be24(data + position + 1);
    if ((flags_and_type & UINT8_C(0xc0)) != 0
        || !flv_tag_type_valid(type)) {
      layout->failure_offset = position;
      layout->observed_extent = position;
      return layout->tag_count > 0 ? FLV_PARSE_PARTIAL
                                   : FLV_PARSE_INVALID;
    }
    if (payload_length > UINT64_MAX - position - FLV_TAG_HEADER_SIZE
        - FLV_PREVIOUS_TAG_SIZE) {
      layout->failure_offset = position;
      return FLV_PARSE_INVALID;
    }
    uint64_t payload_offset = position + FLV_TAG_HEADER_SIZE;
    layout->current_tag_back_pointer_offset = payload_offset
        + payload_length;
    layout->current_tag_expected_size = (uint32_t)(FLV_TAG_HEADER_SIZE
        + payload_length);
    layout->current_tag_shape_valid = true;
    layout->required_extent = layout->current_tag_back_pointer_offset
        + FLV_PREVIOUS_TAG_SIZE;

    uint32_t timestamp = flv_read_be24(data + position + 4)
        | ((uint32_t)data[position + 7] << 24);
    uint32_t stream_id = flv_read_be24(data + position + 8);

    if (stream_id != 0) {
      layout->failure_offset = position;
      layout->observed_extent = position + FLV_TAG_HEADER_SIZE;
      return layout->tag_count > 0 ? FLV_PARSE_PARTIAL
                                   : FLV_PARSE_INVALID;
    }
    layout->current_tag_header_valid = true;
    layout->observed_extent = position + FLV_TAG_HEADER_SIZE;
    uint64_t next_position = payload_offset + payload_length
        + FLV_PREVIOUS_TAG_SIZE;
    if (next_position > length) {
      layout->failure_offset = length;
      layout->observed_extent = length;
      return FLV_PARSE_PARTIAL;
    }
    if (!flv_tag_payload_header_valid(type, data + payload_offset,
                                      payload_length)) {
      layout->failure_offset = payload_offset;
      layout->observed_extent = payload_offset;
      return layout->tag_count > 0 ? FLV_PARSE_PARTIAL
                                   : FLV_PARSE_INVALID;
    }

    uint32_t previous_size = flv_read_be32(
        data + payload_offset + payload_length);
    uint32_t expected_previous = (uint32_t)(FLV_TAG_HEADER_SIZE
        + payload_length);
    if (previous_size == expected_previous) {
      layout->matching_back_pointers++;
    }
    else {
      layout->mismatching_back_pointers++;
      layout->last_mismatching_back_pointer_offset =
          payload_offset + payload_length;
      layout->last_mismatching_tag_offset = position;
      layout->last_mismatching_expected_size = expected_previous;
    }

    if (type == FLV_TAG_AUDIO) {
      layout->audio_tags++;
      if (timestamp > layout->maximum_media_timestamp) {
        layout->maximum_media_timestamp = timestamp;
      }
    }
    else if (type == FLV_TAG_VIDEO) {
      layout->video_tags++;
      if (timestamp > layout->maximum_media_timestamp) {
        layout->maximum_media_timestamp = timestamp;
      }
    }
    else {
      layout->script_tags++;
      flv_read_script_metadata(data + payload_offset, payload_length,
                               layout);
    }
    layout->tag_count++;
    position = next_position;
    layout->parsed_extent = position;
    layout->observed_extent = position;
    layout->current_tag_shape_valid = false;
    layout->current_tag_header_valid = false;
  }

  if (layout->tag_count == 0 || !flv_layout_has_media(layout)) {
    return FLV_PARSE_INVALID;
  }
  if (layout->metadata_file_size_known
      && layout->metadata_file_size == layout->parsed_extent) {
    layout->terminal_extent_proven = true;
  }
  return FLV_PARSE_COMPLETE;
}

static inline bool flv_layout_has_media(const FlvLayout *layout) {
  return layout && (layout->audio_tags > 0 || layout->video_tags > 0);
}

static inline bool flv_layout_terminal_likely(const FlvLayout *layout) {
  if (!layout || layout->tag_count == 0 || !flv_layout_has_media(layout)) {
    return false;
  }
  if (layout->terminal_extent_proven) {
    return true;
  }
  if (!layout->metadata_duration_known || layout->metadata_duration <= 0.0) {
    return false;
  }
  double expected_timestamp = layout->metadata_duration * 1000.0;
  double delta = fabs(expected_timestamp
      - (double)layout->maximum_media_timestamp);
  return delta <= 1000.0;
}

static inline bool flv_layout_terminal_boundary(const FlvLayout *layout,
                                                FlvParseResult result,
                                                uint64_t length) {
  if (!layout || !flv_layout_terminal_likely(layout)) {
    return false;
  }
  if (layout->terminal_extent_proven) {
    return true;
  }
  return result == FLV_PARSE_PARTIAL
      && layout->parsed_extent > 0 && layout->parsed_extent < length
      && layout->failure_offset != length
      && (layout->required_extent == UINT64_MAX
          || layout->required_extent <= length);
}

static inline bool flv_layout_structural_terminal_candidate(
    const FlvLayout *layout, FlvParseResult result, uint64_t length) {
  if (!layout || layout->tag_count == 0 || !flv_layout_has_media(layout)
      || layout->parsed_extent == 0 || layout->parsed_extent > length) {
    return false;
  }
  if (result == FLV_PARSE_COMPLETE
      && layout->parsed_extent == length) {
    return true;
  }
  return result == FLV_PARSE_PARTIAL
      && !layout->current_tag_shape_valid
      && layout->current_tag_offset == layout->parsed_extent
      && layout->failure_offset == layout->current_tag_offset;
}

static inline char *flv_header_discovery(char *base, uint64_t offset,
                                         uint64_t remaining, char **matchpos,
                                         uint32_t *matchlen,
                                         uint32_t blocksize) {
  (void)blocksize;
  if (!base || !matchpos || !matchlen) {
    return NULL;
  }
  *matchpos = NULL;
  *matchlen = (uint32_t)FLV_HEADER_SIZE;
  if (remaining < FLV_HEADER_SIZE) {
    return NULL;
  }

  uint8_t *search = (uint8_t *)base + offset;
  uint64_t available = remaining;
  while (available >= FLV_HEADER_SIZE) {
    uint8_t *found = memchr(search, 'F', (size_t)available);
    if (!found) {
      break;
    }
    uint64_t consumed = (uint64_t)(found - search);
    available -= consumed;
    if (flv_header_valid(found, available, NULL)) {
      *matchpos = (char *)found;
      return NULL;
    }
    search = found + 1;
    available--;
  }
  return NULL;
}

// FLV has no footer signature. Parse each header's contiguous tag chain and
// report a synthetic footer whose match length bounds the initial candidate.
// Fragmented candidates stop at their first structural discontinuity and are
// repaired during reassembly rather than being accepted as complete here.
static inline char *flv_footer_discovery(char *base, uint64_t offset,
                                         uint64_t remaining, char **matchpos,
                                         uint32_t *matchlen,
                                         uint32_t blocksize) {
  (void)blocksize;
  if (!base || !matchpos || !matchlen) {
    return NULL;
  }
  *matchpos = NULL;
  *matchlen = 0;
  if (remaining < FLV_MINIMUM_SIZE) {
    return NULL;
  }

  uint8_t *search = (uint8_t *)base + offset;
  uint64_t available = remaining;
  while (available >= FLV_MINIMUM_SIZE) {
    uint8_t *found = memchr(search, 'F', (size_t)available);
    if (!found) {
      break;
    }
    uint64_t consumed = (uint64_t)(found - search);
    available -= consumed;
    uint64_t data_offset;
    if (!flv_header_valid(found, available, &data_offset)) {
      search = found + 1;
      available--;
      continue;
    }

    FlvLayout layout;
    FlvParseResult result = flv_parse_file(found, available, &layout);
    uint64_t extent = layout.observed_extent;
    if (result == FLV_PARSE_COMPLETE) {
      extent = layout.parsed_extent;
    }
    if (layout.tag_count > 0 && flv_layout_has_media(&layout)
        && extent >= FLV_MINIMUM_SIZE && extent - 1 <= UINT32_MAX) {
      *matchpos = (char *)found + 1;
      *matchlen = (uint32_t)(extent - 1);
      return NULL;
    }
    search = found + 1;
    available--;
  }
  return NULL;
}

static inline uint32_t flv_block_validate(
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
  for (uint64_t position = 0;
       position + FLV_PREVIOUS_TAG_SIZE + FLV_TAG_HEADER_SIZE <= length;
       position++) {
    uint64_t header = position + FLV_PREVIOUS_TAG_SIZE;
    uint8_t flags_and_type = bytes[header];
    uint8_t type = flags_and_type & UINT8_C(0x1f);
    if ((flags_and_type & UINT8_C(0xc0)) != 0
        || !flv_tag_type_valid(type)
        || flv_read_be24(bytes + header + 8) != 0) {
      continue;
    }
    uint32_t previous_size = flv_read_be32(bytes + position);
    if (previous_size >= FLV_TAG_HEADER_SIZE
        && previous_size <= UINT32_C(0x0100000a)) {
      *decision = (BlockValidationDecision)FLV_PAYLOAD_CONFIDENCE_MAX;
      break;
    }
  }
  return needleidx;
}

static inline bool flv_carve_state_valid(const FlvCarveState *state) {
  if (!state || state->magic != FLV_CARVE_STATE_MAGIC
      || state->version != FLV_CARVE_STATE_VERSION
      || state->stage > FLV_REPAIR_STAGE_PAIR_EXTEND
      || state->extension_mapped > FLV_MAXIMUM_SIZE
      || state->ambiguity_count > FLV_REPAIR_HISTORY_MAX
      || state->pending_ambiguity.choice_count
          > FLV_REPAIR_BOUNDARY_CANDIDATES) {
    return false;
  }
  const FlvRepairAmbiguity *pending = &state->pending_ambiguity;
  if (pending->choice_count > 0) {
    if (pending->last_target_slot <= pending->first_target_slot
        || pending->last_target_slot - pending->first_target_slot
            > FLV_REPAIR_AMBIGUITY_SLOTS) {
      return false;
    }
    for (uint32_t choice = 0; choice < pending->choice_count; choice++) {
      if (pending->choices[choice].actual_start < 0
          || pending->choices[choice].target_slot
              < pending->first_target_slot
          || pending->choices[choice].target_slot
              > pending->last_target_slot) {
        return false;
      }
    }
  }
  for (uint32_t index = 0; index < state->ambiguity_count; index++) {
    const FlvRepairAmbiguity *ambiguity = &state->ambiguities[index];

    if (ambiguity->choice_count < 2
        || ambiguity->choice_count > FLV_REPAIR_BOUNDARY_CANDIDATES
        || ambiguity->last_target_slot <= ambiguity->first_target_slot
        || ambiguity->last_target_slot - ambiguity->first_target_slot
            > FLV_REPAIR_AMBIGUITY_SLOTS) {
      return false;
    }
    for (uint32_t choice = 0; choice < ambiguity->choice_count; choice++) {
      if (ambiguity->choices[choice].actual_start < 0
          || ambiguity->choices[choice].target_slot
              < ambiguity->first_target_slot
          || ambiguity->choices[choice].target_slot
              > ambiguity->last_target_slot) {
        return false;
      }
    }
  }
  return true;
}

static inline void flv_repair_ambiguity_reset(
    FlvRepairAmbiguity *ambiguity) {
  if (ambiguity) {
    memset(ambiguity, 0, sizeof(*ambiguity));
  }
}

static inline void flv_repair_ambiguity_prepare(
    const CarveInfo *candidate, uint64_t first_target,
    uint64_t last_target, FlvRepairAmbiguity *ambiguity) {
  flv_repair_ambiguity_reset(ambiguity);
  if (!candidate || !candidate->b || !ambiguity
      || first_target >= last_target
      || last_target - first_target > FLV_REPAIR_AMBIGUITY_SLOTS
      || last_target > blockvector_get_num_blocks(candidate->b)) {
    return;
  }

  ambiguity->first_target_slot = first_target;
  ambiguity->last_target_slot = last_target;
  for (uint64_t slot = first_target; slot < last_target; slot++) {
    int64_t actual = blockvector_get_actual_blocknumber(candidate->b, slot);

    if (actual < 0) {
      flv_repair_ambiguity_reset(ambiguity);
      return;
    }
    ambiguity->baseline_actual[slot - first_target] = actual;
  }
}

static inline void flv_repair_ambiguity_retain(
    FlvRepairAmbiguity *ambiguity, const FlvRepairAnchor *anchor) {
  if (!ambiguity || !anchor || anchor->actual_start < 0
      || ambiguity->first_target_slot >= ambiguity->last_target_slot
      || anchor->target_slot < ambiguity->first_target_slot
      || anchor->target_slot > ambiguity->last_target_slot) {
    return;
  }

  for (uint32_t index = 0; index < ambiguity->choice_count; index++) {
    FlvRepairChoice *choice = &ambiguity->choices[index];

    if (choice->target_slot != anchor->target_slot) {
      continue;
    }
    bool replace = anchor->content_cost < choice->content_cost
        || (anchor->content_cost == choice->content_cost
            && (anchor->confidence > choice->confidence
                || (anchor->confidence == choice->confidence
                    && (anchor->reservations < choice->reservations
                        || (anchor->reservations == choice->reservations
                            && anchor->actual_start
                                < choice->actual_start)))));
    if (replace) {
      *choice = (FlvRepairChoice){
          .target_slot = anchor->target_slot,
          .actual_start = anchor->actual_start,
          .content_cost = anchor->content_cost,
          .confidence = anchor->confidence,
          .reservations = anchor->reservations
      };
    }
    return;
  }

  if (ambiguity->choice_count < FLV_REPAIR_BOUNDARY_CANDIDATES) {
    ambiguity->choices[ambiguity->choice_count++] = (FlvRepairChoice){
        .target_slot = anchor->target_slot,
        .actual_start = anchor->actual_start,
        .content_cost = anchor->content_cost,
        .confidence = anchor->confidence,
        .reservations = anchor->reservations
    };
  }
}

static inline void flv_repair_ambiguity_commit(
    FlvCarveState *state, uint64_t selected_target,
    int64_t selected_actual) {
  if (!state) {
    return;
  }
  FlvRepairAmbiguity *pending = &state->pending_ambiguity;

  if (state->ambiguity_count >= FLV_REPAIR_HISTORY_MAX
      || pending->choice_count < 2
      || selected_actual < 0
      || selected_target < pending->first_target_slot
      || selected_target > pending->last_target_slot
      || pending->last_target_slot - selected_target
          > (uint64_t)(INT64_MAX - selected_actual)) {
    flv_repair_ambiguity_reset(pending);
    return;
  }
  int64_t convergence_actual = selected_actual
      + (int64_t)(pending->last_target_slot - selected_target);
  uint32_t retained = 0;

  for (uint32_t index = 0; index < pending->choice_count; index++) {
    FlvRepairChoice choice = pending->choices[index];

    if (choice.target_slot < pending->first_target_slot
        || choice.target_slot > pending->last_target_slot
        || choice.actual_start < 0
        || pending->last_target_slot - choice.target_slot
            > (uint64_t)(INT64_MAX - choice.actual_start)
        || choice.actual_start
               + (int64_t)(pending->last_target_slot - choice.target_slot)
            != convergence_actual) {
      continue;
    }
    pending->choices[retained++] = choice;
  }
  pending->choice_count = retained;
  if (retained > 1) {
    state->ambiguities[state->ambiguity_count++] = *pending;
  }
  flv_repair_ambiguity_reset(pending);
}

static inline void flv_publish_ambiguities(
    CarveInfo *candidate, const FlvCarveState *state) {
  if (!scalpel_state.write_promising || !candidate || !candidate->b
      || !state || state->ambiguity_count == 0) {
    return;
  }

  uint64_t combinations = 1;
  for (uint32_t history = 0; history < state->ambiguity_count; history++) {
    uint32_t choices = state->ambiguities[history].choice_count;

    if (choices < 2) {
      continue;
    }
    if (combinations > UINT64_MAX / choices) {
      combinations = UINT64_MAX;
      break;
    }
    combinations *= choices;
  }
  uint64_t output_count = combinations;
  if (output_count > FLV_REPAIR_OUTPUT_MAX) {
    output_count = FLV_REPAIR_OUTPUT_MAX;
  }
  const uint64_t data_length = blockvector_get_data_length(candidate->b);
  const uint64_t total_blocks = blockvector_get_num_blocks(candidate->b);
  BlockVector *parent_blockvector = candidate->b;
  const CarveInfoFlavor parent_flavor = candidate->flavor;
  const uint64_t parent_validates_to = candidate->best_validates_to;
  const bool parent_no_initial_extension =
      candidate->no_initial_block_extension;

  for (uint64_t output = 0; output < output_count; output++) {
    uint64_t combination = output;
    if (combinations > output_count && output_count > 1) {
      uint64_t denominator = output_count - 1;
      uint64_t span = combinations - 1;
      combination = (span / denominator) * output
          + ((span % denominator) * output) / denominator;
    }
    BlockVector *hypothesis = NULL;
    bool changed = false;
    bool usable = true;
    uint64_t divisor = 1;

    clone_blockvector(candidate->b, &hypothesis, false);
    for (uint32_t history = 0;
         history < state->ambiguity_count && usable; history++) {
      const FlvRepairAmbiguity *ambiguity = &state->ambiguities[history];
      if (ambiguity->choice_count < 2) {
        continue;
      }
      uint32_t choice_index = (uint32_t)(
          (combination / divisor) % ambiguity->choice_count);
      const FlvRepairChoice *choice = &ambiguity->choices[choice_index];

      if (divisor <= UINT64_MAX / ambiguity->choice_count) {
        divisor *= ambiguity->choice_count;
      }
      for (uint64_t slot = ambiguity->first_target_slot;
           slot < ambiguity->last_target_slot; slot++) {
        if (slot >= total_blocks) {
          usable = false;
          break;
        }
        int64_t actual;
        if (slot < choice->target_slot) {
          actual = ambiguity->baseline_actual[
              slot - ambiguity->first_target_slot];
        }
        else if (slot - choice->target_slot
                     > (uint64_t)(INT64_MAX - choice->actual_start)) {
          usable = false;
          break;
        }
        else {
          actual = choice->actual_start
              + (int64_t)(slot - choice->target_slot);
        }
        int64_t apparent = filemirror_apparent_blocknumber(
            scalpel_state.filemirror, actual);
        if (apparent < 0) {
          usable = false;
          break;
        }
        if (blockvector_get_actual_blocknumber(hypothesis, slot) != actual) {
          blockvector_set_apparent_blocknumber(hypothesis, slot, apparent);
          changed = true;
        }
      }
    }
    if (usable && changed) {
      normalize_blockvector(hypothesis);
      inflate_blockvector(hypothesis);
      blockvector_set_data_length(hypothesis, data_length);
      candidate->b = hypothesis;
      candidate->flavor = PROMISING;
      candidate->best_validates_to = data_length > 0 ? data_length - 1 : 0;
      CarveInfo *preserved_candidate = candidate;
      write_candidate(&preserved_candidate, true);
    }
    candidate->b = parent_blockvector;
    free_blockvector(&hypothesis);
  }

  candidate->b = parent_blockvector;
  candidate->flavor = parent_flavor;
  candidate->best_validates_to = parent_validates_to;
  candidate->no_initial_block_extension = parent_no_initial_extension;
}

static inline bool flv_serialize_carve_state(void **state, FILE *fp,
                                             StateSerialization mode) {
  FlvCarveState **flv_state = (FlvCarveState **)state;

  if (!flv_state || !fp) {
    return false;
  }
  if (mode == DESERIALIZE) {
    *flv_state = (FlvCarveState *)calloc(1, sizeof(**flv_state));
    check_memory_allocation(*flv_state, __LINE__, __FILE__,
                            "FlvCarveState");
  }
  size_t record_size = mode == DESERIALIZE
      ? offsetof(FlvCarveState, extension_mapped) : sizeof(**flv_state);
  if ((mode == SERIALIZE && !flv_carve_state_valid(*flv_state))
      || (mode == SERIALIZE
          ? fwrite(*flv_state, record_size, 1, fp)
          : fread(*flv_state, record_size, 1, fp)) != 1) {
    if (mode == DESERIALIZE) {
      free(*flv_state);
      *flv_state = NULL;
    }
    handle_error(SCALPEL_ERROR_CHECKPOINT, "FLV carve state", __LINE__,
                 __FILE__);
  }
  if (mode == DESERIALIZE && (*flv_state)->version == 7U) {
    (*flv_state)->version = FLV_CARVE_STATE_VERSION;
  }
  else if (mode == DESERIALIZE
           && (*flv_state)->version == FLV_CARVE_STATE_VERSION) {
    if (fread((uint8_t *)*flv_state + record_size,
              sizeof(**flv_state) - record_size, 1, fp) != 1) {
      free(*flv_state);
      *flv_state = NULL;
      handle_error(SCALPEL_ERROR_CHECKPOINT, "FLV extension state",
                   __LINE__, __FILE__);
    }
  }
  if (mode == DESERIALIZE && !flv_carve_state_valid(*flv_state)) {
    free(*flv_state);
    *flv_state = NULL;
    handle_error(SCALPEL_ERROR_CHECKPOINT, "invalid FLV carve state",
                 __LINE__, __FILE__);
  }
  return true;
}

static inline void *flv_clone_carve_state(const void *srcstate) {
  const FlvCarveState *source = (const FlvCarveState *)srcstate;

  if (!flv_carve_state_valid(source)) {
    return NULL;
  }
  FlvCarveState *copy = (FlvCarveState *)malloc(sizeof(*copy));

  check_memory_allocation(copy, __LINE__, __FILE__, "FlvCarveState");
  memcpy(copy, source, sizeof(*copy));
  return copy;
}

static inline void flv_free_carve_state(void **state) {
  if (state) {
    free(*state);
    *state = NULL;
  }
}

static inline void flv_print_carve_state(const void *state) {
  const FlvCarveState *flv_state = (const FlvCarveState *)state;

  if (!flv_carve_state_valid(flv_state)) {
    fprintf(stdout, "NULL");
    return;
  }
  fprintf(stdout,
          "stage=%u next=%" PRIu64 " target=%" PRIu64
          " actual=%" PRId64 " repairs=%" PRIu64,
          flv_state->stage, flv_state->next_actual,
          flv_state->best_target_slot, flv_state->best_actual,
          flv_state->repairs);
}

static inline uint64_t flv_repair_signature(const FlvLayout *layout,
                                            uint64_t length) {
  if (!layout) {
    return 0;
  }
  uint64_t signature = UINT64_C(0x9e3779b97f4a7c15) ^ length;

  signature ^= layout->last_mismatching_back_pointer_offset
      + UINT64_C(0x9e3779b97f4a7c15) + (signature << 6) + (signature >> 2);
  signature ^= layout->last_mismatching_tag_offset
      + UINT64_C(0x9e3779b97f4a7c15) + (signature << 6) + (signature >> 2);
  signature ^= (uint64_t)layout->last_mismatching_expected_size
      + UINT64_C(0x9e3779b97f4a7c15) + (signature << 6) + (signature >> 2);
  signature ^= layout->current_tag_offset
      + UINT64_C(0x9e3779b97f4a7c15) + (signature << 6) + (signature >> 2);
  signature ^= layout->current_tag_back_pointer_offset
      + UINT64_C(0x9e3779b97f4a7c15) + (signature << 6) + (signature >> 2);
  signature ^= (uint64_t)layout->current_tag_expected_size
      + UINT64_C(0x9e3779b97f4a7c15) + (signature << 6) + (signature >> 2);
  signature ^= (uint64_t)layout->current_tag_shape_valid
      + UINT64_C(0x9e3779b97f4a7c15) + (signature << 6) + (signature >> 2);
  signature ^= layout->parsed_extent
      + UINT64_C(0x9e3779b97f4a7c15) + (signature << 6) + (signature >> 2);
  return signature ? signature : 1;
}

static inline void flv_content_histogram_add(
    FlvContentHistogram *histogram, const uint8_t *data, uint64_t length) {
  if (!histogram || !data) {
    return;
  }
  for (uint64_t position = 0; position < length; position++) {
    histogram->bins[data[position] >> 3]++;
  }
  histogram->samples += length;
}

static inline uint64_t flv_content_histogram_cost(
    const FlvContentHistogram *left, const FlvContentHistogram *right) {
  if (!left || !right || left->samples == 0 || right->samples == 0) {
    return UINT64_MAX;
  }
  uint64_t cost = 0;

  for (uint32_t bin = 0; bin < FLV_CONTENT_HISTOGRAM_BINS; bin++) {
    uint64_t left_scaled = left->bins[bin] * UINT64_C(65536)
        / left->samples;
    uint64_t right_scaled = right->bins[bin] * UINT64_C(65536)
        / right->samples;

    cost += left_scaled > right_scaled
        ? left_scaled - right_scaled : right_scaled - left_scaled;
  }
  return cost;
}

static inline bool flv_candidate_context_histogram(
    const CarveInfo *candidate, uint64_t target_slot,
    FlvContentHistogram *histogram) {
  if (!candidate || !candidate->b || !histogram || target_slot == 0
      || scalpel_state.blocksize == 0) {
    return false;
  }
  memset(histogram, 0, sizeof(*histogram));
  const uint8_t *data = (const uint8_t *)blockvector_get_data_pointer(
      candidate->b);
  uint64_t length = blockvector_get_data_length(candidate->b);
  uint64_t first_slot = target_slot > FLV_REPAIR_CONTEXT_BLOCKS
      ? target_slot - FLV_REPAIR_CONTEXT_BLOCKS : 0;

  for (uint64_t slot = first_slot; slot < target_slot; slot++) {
    uint64_t offset = slot * (uint64_t)scalpel_state.blocksize;

    if (!data || offset >= length) {
      continue;
    }
    uint64_t available = length - offset;

    if (available > scalpel_state.blocksize) {
      available = scalpel_state.blocksize;
    }
    flv_content_histogram_add(histogram, data + offset, available);
  }
  return histogram->samples > 0;
}

static inline bool flv_source_histogram(int64_t actual_start,
                                        FlvContentHistogram *histogram) {
  if (actual_start < 0 || !histogram) {
    return false;
  }
  memset(histogram, 0, sizeof(*histogram));
  for (uint64_t block = 0; block < FLV_REPAIR_CONTEXT_BLOCKS; block++) {
    if ((uint64_t)actual_start + block > (uint64_t)INT64_MAX) {
      return false;
    }
    uint64_t available = 0;
    const uint8_t *data = (const uint8_t *)
        filemirror_actual_block_data_pointer(
            scalpel_state.filemirror, actual_start + (int64_t)block,
            &available);

    if (!data || available == 0) {
      return false;
    }
    flv_content_histogram_add(histogram, data, available);
  }
  return histogram->samples > 0;
}

static inline bool flv_candidate_block_histogram(
    const CarveInfo *candidate, uint64_t slot,
    FlvContentHistogram *histogram) {
  if (!candidate || !candidate->b || !histogram
      || scalpel_state.blocksize == 0
      || slot >= blockvector_get_num_blocks(candidate->b)) {
    return false;
  }
  const uint8_t *data = (const uint8_t *)blockvector_get_data_pointer(
      candidate->b);
  uint64_t length = blockvector_get_data_length(candidate->b);

  if (!data || slot > UINT64_MAX / scalpel_state.blocksize) {
    return false;
  }
  uint64_t offset = slot * (uint64_t)scalpel_state.blocksize;

  if (offset >= length) {
    return false;
  }
  uint64_t available = length - offset;

  if (available > scalpel_state.blocksize) {
    available = scalpel_state.blocksize;
  }
  memset(histogram, 0, sizeof(*histogram));
  flv_content_histogram_add(histogram, data + offset, available);
  return histogram->samples > 0;
}

static inline bool flv_actual_block_histogram(
    int64_t actual, FlvContentHistogram *histogram) {
  if (actual < 0 || !histogram) {
    return false;
  }
  uint64_t available = 0;
  const uint8_t *data = (const uint8_t *)
      filemirror_actual_block_data_pointer(
          scalpel_state.filemirror, actual, &available);

  if (!data || available == 0) {
    return false;
  }
  memset(histogram, 0, sizeof(*histogram));
  flv_content_histogram_add(histogram, data, available);
  return histogram->samples > 0;
}

static inline bool flv_read_actual_run(int64_t actual_start,
                                       uint64_t offset, uint8_t *output,
                                       uint64_t length) {
  if (actual_start < 0 || (!output && length > 0)
      || scalpel_state.blocksize == 0) {
    return false;
  }
  while (length > 0) {
    uint64_t block_delta = offset / scalpel_state.blocksize;
    uint64_t block_offset = offset % scalpel_state.blocksize;

    if ((uint64_t)actual_start + block_delta > (uint64_t)INT64_MAX) {
      return false;
    }
    int64_t actual = actual_start + (int64_t)block_delta;
    uint64_t available = 0;
    const uint8_t *data = (const uint8_t *)
        filemirror_actual_block_data_pointer(scalpel_state.filemirror,
                                             actual, &available);

    if (!data || block_offset >= available) {
      return false;
    }
    uint64_t count = available - block_offset;

    if (count > length) {
      count = length;
    }
    memcpy(output, data + block_offset, (size_t)count);
    output += count;
    offset += count;
    length -= count;
  }
  return true;
}

static inline bool flv_read_actual_pair(int64_t first_actual,
                                        uint64_t first_bytes,
                                        int64_t second_actual,
                                        uint64_t offset, uint8_t *output,
                                        uint64_t length) {
  if (first_actual < 0 || second_actual < 0
      || (!output && length > 0)) {
    return false;
  }
  while (length > 0) {
    int64_t actual = first_actual;
    uint64_t source_offset = offset;
    uint64_t available = length;

    if (offset >= first_bytes) {
      actual = second_actual;
      source_offset = offset - first_bytes;
    }
    else if (available > first_bytes - offset) {
      available = first_bytes - offset;
    }
    if (!flv_read_actual_run(actual, source_offset, output, available)) {
      return false;
    }
    output += available;
    offset += available;
    length -= available;
  }
  return true;
}

static inline bool flv_actual_in_prefix(const CarveInfo *candidate,
                                        uint64_t target_slot,
                                        int64_t actual) {
  if (!candidate || !candidate->b || actual < 0) {
    return true;
  }
  uint64_t limit = blockvector_get_num_blocks(candidate->b);

  if (limit > target_slot) {
    limit = target_slot;
  }
  for (uint64_t slot = 0; slot < limit; slot++) {
    if (blockvector_get_actual_blocknumber(candidate->b, slot) == actual) {
      return true;
    }
  }
  return false;
}

static inline bool flv_source_range_available(const CarveInfo *candidate,
                                              uint64_t target_slot,
                                              int64_t actual_start,
                                              uint64_t source_bytes) {
  if (!candidate || !candidate->b || actual_start < 0 || source_bytes == 0
      || scalpel_state.blocksize == 0) {
    return false;
  }
  uint64_t blocks = CEILDIV(source_bytes, scalpel_state.blocksize);
  uint64_t image_blocks = CEILDIV(
      filemirror_filesize(scalpel_state.filemirror), scalpel_state.blocksize);

  if ((uint64_t)actual_start >= image_blocks
      || blocks > image_blocks - (uint64_t)actual_start) {
    return false;
  }
  for (uint64_t block = 0; block < blocks; block++) {
    int64_t actual = actual_start + (int64_t)block;

    if (filemirror_apparent_blocknumber(scalpel_state.filemirror, actual) < 0
        || filemirror_actual_block_covered(scalpel_state.filemirror, actual)
        || flv_actual_in_prefix(candidate, target_slot, actual)) {
      return false;
    }
  }
  return true;
}

static inline bool flv_repair_anchor_valid(const CarveInfo *candidate,
                                           uint64_t target_slot,
                                           uint64_t context_slot,
                                           int64_t actual_start,
                                           uint64_t back_pointer_offset,
                                           uint32_t expected_size,
                                           FlvRepairAnchor *anchor) {
  if (!candidate || !candidate->b || !anchor || actual_start < 0
      || scalpel_state.blocksize == 0
      || target_slot > UINT64_MAX / scalpel_state.blocksize) {
    return false;
  }
  uint64_t target_offset = target_slot * (uint64_t)scalpel_state.blocksize;

  if (back_pointer_offset < target_offset) {
    return false;
  }
  if (target_slot < blockvector_get_num_blocks(candidate->b)
      && blockvector_get_actual_blocknumber(candidate->b, target_slot)
          == actual_start) {
    return false;
  }
  uint64_t position = back_pointer_offset - target_offset;
  uint8_t encoded[FLV_TAG_HEADER_SIZE];

  if (expected_size != FLV_REPAIR_ANY_PREVIOUS_SIZE) {
    if (!flv_read_actual_run(actual_start, position, encoded, 4)
        || flv_read_be32(encoded) != expected_size) {
      return false;
    }
    position += FLV_PREVIOUS_TAG_SIZE;
  }
  for (uint32_t tag = 0; tag < FLV_REPAIR_ANCHOR_TAGS; tag++) {
    if (!flv_read_actual_run(actual_start, position, encoded,
                             FLV_TAG_HEADER_SIZE)) {
      return false;
    }
    uint8_t flags_and_type = encoded[0];
    uint8_t type = flags_and_type & UINT8_C(0x1f);
    uint64_t payload_length = flv_read_be24(encoded + 1);

    if ((flags_and_type & UINT8_C(0xc0)) != 0
        || !flv_tag_type_valid(type) || flv_read_be24(encoded + 8) != 0
        || payload_length > UINT64_MAX - position - FLV_TAG_HEADER_SIZE
            - FLV_PREVIOUS_TAG_SIZE) {
      return false;
    }
    if (payload_length > 0) {
      uint8_t payload_header;

      if (!flv_read_actual_run(actual_start,
                               position + FLV_TAG_HEADER_SIZE,
                               &payload_header, 1)
          || !flv_tag_payload_header_valid(type, &payload_header, 1)) {
        return false;
      }
    }
    position += FLV_TAG_HEADER_SIZE + payload_length;
    if (!flv_read_actual_run(actual_start, position, encoded, 4)
        || flv_read_be32(encoded) != FLV_TAG_HEADER_SIZE + payload_length) {
      return false;
    }
    position += FLV_PREVIOUS_TAG_SIZE;
  }
  if (!flv_source_range_available(candidate, target_slot, actual_start,
                                  position)) {
    return false;
  }

  FlvContentHistogram context;
  FlvContentHistogram source;

  anchor->target_slot = target_slot;
  anchor->actual_start = actual_start;
  anchor->source_bytes = position;
  anchor->content_cost = UINT64_MAX;
  anchor->confidence = 0;
  anchor->reservations = 0;
  if (flv_candidate_context_histogram(candidate, context_slot, &context)
      && flv_source_histogram(actual_start, &source)) {
    anchor->content_cost = flv_content_histogram_cost(&context, &source);
  }
  uint64_t confidence_blocks = CEILDIV(position, scalpel_state.blocksize);

  if (confidence_blocks > FLV_REPAIR_CONTEXT_BLOCKS * 4U) {
    confidence_blocks = FLV_REPAIR_CONTEXT_BLOCKS * 4U;
  }
  for (uint64_t block = 0; block < confidence_blocks; block++) {
    int64_t actual = actual_start + (int64_t)block;

    anchor->confidence += (uint64_t)filemirror_get_blocktype(
        scalpel_state.filemirror, actual, candidate->needleidx);
    if (scalpel_state.reservations) {
      int64_t reserved = filemirror_actual_block_reserved(
          scalpel_state.filemirror, actual);

      if (reserved > 0 && anchor->reservations <= INT64_MAX - reserved) {
        anchor->reservations += reserved;
      }
      else if (reserved > 0) {
        anchor->reservations = INT64_MAX;
      }
    }
  }
  return true;
}

static inline bool flv_repair_anchor_better(const FlvRepairAnchor *trial,
                                            const FlvRepairAnchor *best) {
  if (!trial || !best) {
    return false;
  }
  if (best->actual_start < 0) {
    return true;
  }
  if (trial->target_slot != best->target_slot) {
    if (trial->content_cost != UINT64_MAX
        && best->content_cost != UINT64_MAX) {
      if (trial->content_cost <= UINT64_MAX
              - FLV_REPAIR_CONTENT_TARGET_TOLERANCE
          && trial->content_cost + FLV_REPAIR_CONTENT_TARGET_TOLERANCE
              < best->content_cost) {
        return true;
      }
      if (best->content_cost <= UINT64_MAX
              - FLV_REPAIR_CONTENT_TARGET_TOLERANCE
          && best->content_cost + FLV_REPAIR_CONTENT_TARGET_TOLERANCE
              < trial->content_cost) {
        return false;
      }
    }
    return trial->target_slot > best->target_slot;
  }
  if (trial->content_cost != best->content_cost) {
    if (trial->content_cost == UINT64_MAX) {
      return false;
    }
    if (best->content_cost == UINT64_MAX) {
      return true;
    }
    return trial->content_cost < best->content_cost;
  }
  if (trial->confidence != best->confidence) {
    return trial->confidence > best->confidence;
  }
  if (trial->reservations != best->reservations) {
    return trial->reservations < best->reservations;
  }
  return trial->actual_start < best->actual_start;
}

static inline bool flv_repair_partial_anchor_valid(
    const CarveInfo *candidate, uint64_t target_slot, int64_t actual_start,
    uint64_t back_pointer_offset, uint32_t expected_size,
    uint64_t *minimum_first_blocks, uint64_t *maximum_first_blocks) {
  if (!candidate || !candidate->b || actual_start < 0
      || !minimum_first_blocks || !maximum_first_blocks
      || expected_size == FLV_REPAIR_ANY_PREVIOUS_SIZE
      || scalpel_state.blocksize == 0
      || target_slot > UINT64_MAX / scalpel_state.blocksize) {
    return false;
  }
  uint64_t target_offset = target_slot * (uint64_t)scalpel_state.blocksize;

  if (back_pointer_offset < target_offset) {
    return false;
  }
  if (target_slot < blockvector_get_num_blocks(candidate->b)
      && blockvector_get_actual_blocknumber(candidate->b, target_slot)
          == actual_start) {
    return false;
  }
  uint64_t position = back_pointer_offset - target_offset;
  uint8_t encoded[FLV_TAG_HEADER_SIZE];

  if (!flv_read_actual_run(actual_start, position, encoded, 4)
      || flv_read_be32(encoded) != expected_size) {
    return false;
  }
  position += FLV_PREVIOUS_TAG_SIZE;
  uint64_t minimum_bytes = position;
  uint64_t failure_position = UINT64_MAX;
  bool first_header_valid = false;

  for (uint32_t tag = 0; tag < FLV_REPAIR_ANCHOR_TAGS; tag++) {
    if (!flv_read_actual_run(actual_start, position, encoded,
                             FLV_TAG_HEADER_SIZE)) {
      failure_position = position;
      break;
    }
    uint8_t flags_and_type = encoded[0];
    uint8_t type = flags_and_type & UINT8_C(0x1f);
    uint64_t payload_length = flv_read_be24(encoded + 1);

    if ((flags_and_type & UINT8_C(0xc0)) != 0
        || !flv_tag_type_valid(type) || flv_read_be24(encoded + 8) != 0
        || payload_length > UINT64_MAX - position - FLV_TAG_HEADER_SIZE
            - FLV_PREVIOUS_TAG_SIZE) {
      failure_position = position;
      break;
    }
    uint64_t payload_offset = position + FLV_TAG_HEADER_SIZE;

    if (payload_length > 0) {
      uint8_t payload_header;

      if (!flv_read_actual_run(actual_start, payload_offset,
                               &payload_header, 1)
          || !flv_tag_payload_header_valid(type, &payload_header, 1)) {
        failure_position = payload_offset;
        break;
      }
      if (tag == 0) {
        minimum_bytes = payload_offset + 1;
      }
    }
    else if (tag == 0) {
      minimum_bytes = payload_offset;
    }
    if (tag == 0) {
      first_header_valid = true;
    }
    uint64_t pointer_offset = payload_offset + payload_length;

    if (!flv_read_actual_run(actual_start, pointer_offset, encoded, 4)
        || flv_read_be32(encoded) != FLV_TAG_HEADER_SIZE + payload_length) {
      failure_position = pointer_offset;
      break;
    }
    position = pointer_offset + FLV_PREVIOUS_TAG_SIZE;
  }
  if (!first_header_valid || failure_position == UINT64_MAX) {
    return false;
  }
  uint64_t minimum_blocks = CEILDIV(minimum_bytes,
                                    scalpel_state.blocksize);
  uint64_t maximum_blocks = failure_position / scalpel_state.blocksize;

  if (minimum_blocks == 0 || maximum_blocks < minimum_blocks
      || minimum_blocks > UINT64_MAX / scalpel_state.blocksize
      || !flv_source_range_available(
          candidate, target_slot, actual_start,
          minimum_blocks * (uint64_t)scalpel_state.blocksize)) {
    return false;
  }
  *minimum_first_blocks = minimum_blocks;
  *maximum_first_blocks = maximum_blocks;
  return true;
}

static inline bool flv_repair_pair_anchor_valid(
    const CarveInfo *candidate, uint64_t target_slot,
    int64_t first_actual, uint64_t first_blocks, int64_t second_actual,
    uint64_t back_pointer_offset, uint32_t expected_size,
    FlvPairAnchor *anchor) {
  if (!candidate || !candidate->b || !anchor || first_actual < 0
      || second_actual < 0 || first_blocks == 0
      || expected_size == FLV_REPAIR_ANY_PREVIOUS_SIZE
      || scalpel_state.blocksize == 0
      || target_slot > UINT64_MAX / scalpel_state.blocksize
      || first_blocks > UINT64_MAX / scalpel_state.blocksize
      || first_blocks > UINT64_MAX - target_slot) {
    return false;
  }
  uint64_t target_offset = target_slot * (uint64_t)scalpel_state.blocksize;
  uint64_t first_bytes = first_blocks
      * (uint64_t)scalpel_state.blocksize;

  if (back_pointer_offset < target_offset) {
    return false;
  }
  uint64_t position = back_pointer_offset - target_offset;
  uint8_t encoded[FLV_TAG_HEADER_SIZE];

  if (!flv_read_actual_pair(first_actual, first_bytes, second_actual,
                            position, encoded, 4)
      || flv_read_be32(encoded) != expected_size) {
    return false;
  }
  position += FLV_PREVIOUS_TAG_SIZE;
  for (uint32_t tag = 0; tag < FLV_REPAIR_ANCHOR_TAGS; tag++) {
    if (!flv_read_actual_pair(first_actual, first_bytes, second_actual,
                              position, encoded, FLV_TAG_HEADER_SIZE)) {
      return false;
    }
    uint8_t flags_and_type = encoded[0];
    uint8_t type = flags_and_type & UINT8_C(0x1f);
    uint64_t payload_length = flv_read_be24(encoded + 1);

    if ((flags_and_type & UINT8_C(0xc0)) != 0
        || !flv_tag_type_valid(type) || flv_read_be24(encoded + 8) != 0
        || payload_length > UINT64_MAX - position - FLV_TAG_HEADER_SIZE
            - FLV_PREVIOUS_TAG_SIZE) {
      return false;
    }
    if (payload_length > 0) {
      uint8_t payload_header;

      if (!flv_read_actual_pair(
              first_actual, first_bytes, second_actual,
              position + FLV_TAG_HEADER_SIZE, &payload_header, 1)
          || !flv_tag_payload_header_valid(type, &payload_header, 1)) {
        return false;
      }
    }
    position += FLV_TAG_HEADER_SIZE + payload_length;
    if (!flv_read_actual_pair(first_actual, first_bytes, second_actual,
                              position, encoded, 4)
        || flv_read_be32(encoded) != FLV_TAG_HEADER_SIZE + payload_length) {
      return false;
    }
    position += FLV_PREVIOUS_TAG_SIZE;
  }
  if (position <= first_bytes
      || !flv_source_range_available(candidate, target_slot, first_actual,
                                     first_bytes)
      || !flv_source_range_available(
          candidate, target_slot + first_blocks, second_actual,
          position - first_bytes)) {
    return false;
  }
  uint64_t second_blocks = CEILDIV(position - first_bytes,
                                   scalpel_state.blocksize);
  uint64_t first_end = (uint64_t)first_actual + first_blocks;
  uint64_t second_end = (uint64_t)second_actual + second_blocks;

  if ((uint64_t)first_actual < second_end
      && (uint64_t)second_actual < first_end) {
    return false;
  }
  anchor->target_slot = target_slot;
  anchor->first_blocks = first_blocks;
  anchor->source_bytes = position;
  anchor->first_actual = first_actual;
  anchor->second_actual = second_actual;
  return true;
}

static inline void flv_repair_refine_pair_anchor(
    const CarveInfo *candidate, uint64_t back_pointer_offset,
    uint32_t expected_size, FlvPairAnchor *anchor) {
  if (!candidate || !candidate->b || !anchor
      || anchor->first_actual < 0 || anchor->second_actual < 0
      || anchor->first_blocks < 2 || scalpel_state.blocksize == 0
      || anchor->first_blocks > UINT64_MAX - FLV_REPAIR_CONTEXT_BLOCKS) {
    return;
  }
  FlvContentHistogram context;

  if (!flv_candidate_context_histogram(
          candidate, anchor->target_slot, &context)) {
    return;
  }
  uint64_t first_blocks = anchor->first_blocks;
  uint64_t window = first_blocks + FLV_REPAIR_CONTEXT_BLOCKS;

  if (window > SIZE_MAX / sizeof(uint64_t) - 1) {
    return;
  }
  uint64_t *baseline_prefix = (uint64_t *)calloc(
      (size_t)window + 1, sizeof(*baseline_prefix));
  uint64_t *first_prefix = (uint64_t *)calloc(
      (size_t)window + 1, sizeof(*first_prefix));
  uint64_t *second_prefix = (uint64_t *)calloc(
      (size_t)window + 1, sizeof(*second_prefix));

  check_memory_allocation(baseline_prefix, __LINE__, __FILE__,
                          "FLV baseline content costs");
  check_memory_allocation(first_prefix, __LINE__, __FILE__,
                          "FLV first-run content costs");
  check_memory_allocation(second_prefix, __LINE__, __FILE__,
                          "FLV second-run content costs");

  bool usable = true;
  for (uint64_t block = 0; block < first_blocks; block++) {
    FlvContentHistogram baseline;
    FlvContentHistogram first;

    if (anchor->target_slot > UINT64_MAX - block
        || (uint64_t)anchor->first_actual + block
            > (uint64_t)INT64_MAX
        || !flv_candidate_block_histogram(
            candidate, anchor->target_slot + block, &baseline)
        || !flv_actual_block_histogram(
            anchor->first_actual + (int64_t)block, &first)) {
      usable = false;
      break;
    }
    uint64_t baseline_cost = flv_content_histogram_cost(
        &context, &baseline);
    uint64_t first_cost = flv_content_histogram_cost(&context, &first);

    if (baseline_cost == UINT64_MAX || first_cost == UINT64_MAX
        || baseline_prefix[block] > UINT64_MAX - baseline_cost
        || first_prefix[block] > UINT64_MAX - first_cost) {
      usable = false;
      break;
    }
    baseline_prefix[block + 1] = baseline_prefix[block] + baseline_cost;
    first_prefix[block + 1] = first_prefix[block] + first_cost;
  }
  for (uint64_t block = 0; usable && block < window; block++) {
    FlvContentHistogram second;

    if ((uint64_t)anchor->second_actual + block > (uint64_t)INT64_MAX
        || !flv_actual_block_histogram(
            anchor->second_actual + (int64_t)block, &second)) {
      usable = false;
      break;
    }
    uint64_t second_cost = flv_content_histogram_cost(&context, &second);

    if (second_cost == UINT64_MAX
        || second_prefix[block] > UINT64_MAX - second_cost) {
      usable = false;
      break;
    }
    second_prefix[block + 1] = second_prefix[block] + second_cost;
  }
  if (!usable) {
    free(baseline_prefix);
    free(first_prefix);
    free(second_prefix);
    return;
  }

  typedef struct FlvBoundaryCandidate {
    uint64_t lead;
    uint64_t split;
    uint64_t cost;
  } FlvBoundaryCandidate;

  FlvBoundaryCandidate choices[FLV_REPAIR_BOUNDARY_CANDIDATES];
  for (uint32_t choice = 0;
       choice < FLV_REPAIR_BOUNDARY_CANDIDATES; choice++) {
    choices[choice].lead = 0;
    choices[choice].split = first_blocks;
    choices[choice].cost = UINT64_MAX;
  }

  int64_t best_difference = 0;
  uint64_t best_lead = 0;
  for (uint64_t split = 1; split <= first_blocks; split++) {
    uint64_t lead = split - 1;
    int64_t difference;

    if (baseline_prefix[lead] >= first_prefix[lead]) {
      uint64_t delta = baseline_prefix[lead] - first_prefix[lead];
      difference = delta > (uint64_t)INT64_MAX
          ? INT64_MAX : (int64_t)delta;
    }
    else {
      uint64_t delta = first_prefix[lead] - baseline_prefix[lead];
      difference = delta > (uint64_t)INT64_MAX
          ? INT64_MIN : -(int64_t)delta;
    }
    if (lead == 0 || difference < best_difference) {
      best_difference = difference;
      best_lead = lead;
    }

    uint64_t base_cost = first_prefix[split]
        + second_prefix[window - split];
    uint64_t score;

    if (best_difference < 0) {
      uint64_t reduction = (uint64_t)(-(best_difference + 1)) + 1;
      score = reduction > base_cost ? 0 : base_cost - reduction;
    }
    else if (base_cost > UINT64_MAX - (uint64_t)best_difference) {
      score = UINT64_MAX;
    }
    else {
      score = base_cost + (uint64_t)best_difference;
    }

    uint32_t insertion = FLV_REPAIR_BOUNDARY_CANDIDATES;
    for (uint32_t choice = 0;
         choice < FLV_REPAIR_BOUNDARY_CANDIDATES; choice++) {
      if (score < choices[choice].cost) {
        insertion = choice;
        break;
      }
    }
    if (insertion < FLV_REPAIR_BOUNDARY_CANDIDATES) {
      for (uint32_t choice = FLV_REPAIR_BOUNDARY_CANDIDATES - 1;
           choice > insertion; choice--) {
        choices[choice] = choices[choice - 1];
      }
      choices[insertion].lead = best_lead;
      choices[insertion].split = split;
      choices[insertion].cost = score;
    }
  }

  uint64_t original_cost = first_prefix[first_blocks]
      + second_prefix[FLV_REPAIR_CONTEXT_BLOCKS];
  uint64_t selected_cost = original_cost;
  FlvPairAnchor selected = *anchor;

  for (uint32_t choice = 0;
       choice < FLV_REPAIR_BOUNDARY_CANDIDATES
           && choices[choice].cost != UINT64_MAX;
       choice++) {
    uint64_t lead_first = choices[choice].lead > 2
        ? choices[choice].lead - 2 : 0;
    uint64_t lead_last = choices[choice].lead + 2;

    if (lead_last >= first_blocks) {
      lead_last = first_blocks - 1;
    }
    uint64_t split_first = choices[choice].split > 2
        ? choices[choice].split - 2 : 1;
    uint64_t split_last = choices[choice].split + 2;

    if (split_last > first_blocks) {
      split_last = first_blocks;
    }
    for (uint64_t lead = lead_first; lead <= lead_last; lead++) {
      for (uint64_t split = split_first; split <= split_last; split++) {
        if (split <= lead
            || anchor->target_slot > UINT64_MAX - lead
            || (uint64_t)anchor->first_actual + lead
                > (uint64_t)INT64_MAX) {
          continue;
        }
        uint64_t score = baseline_prefix[lead]
            + (first_prefix[split] - first_prefix[lead])
            + second_prefix[window - split];

        if (selected_cost != UINT64_MAX
            && (score > UINT64_MAX
                    - FLV_REPAIR_CONTENT_DECISIVE_MARGIN
                || score + FLV_REPAIR_CONTENT_DECISIVE_MARGIN
                    >= selected_cost)) {
          continue;
        }
        FlvPairAnchor trial;

        if (flv_repair_pair_anchor_valid(
                candidate, anchor->target_slot + lead,
                anchor->first_actual + (int64_t)lead,
                split - lead, anchor->second_actual,
                back_pointer_offset, expected_size, &trial)) {
          selected = trial;
          selected_cost = score;
        }
      }
    }
  }

  *anchor = selected;
  free(baseline_prefix);
  free(first_prefix);
  free(second_prefix);
}

static inline FlvRepairResult flv_reassembly_find_anchor(
    ThreadWork *work, CarveInfo **candidate, const FlvLayout *layout,
    FlvCarveState *state, FlvRepairAnchor *anchor,
    uuid_string_t uuidp, uuid_string_t uuidc) {
  if (!work || !candidate || !*candidate || !(*candidate)->b || !layout
      || !flv_carve_state_valid(state) || !anchor
      || scalpel_state.blocksize == 0) {
    return FLV_REPAIR_NO_MATCH;
  }
  uint64_t back_pointer_offset = UINT64_MAX;
  uint32_t expected_size = FLV_REPAIR_ANY_PREVIOUS_SIZE;
  uint64_t first_target = UINT64_MAX;
  uint64_t last_target = UINT64_MAX;
  uint64_t total_blocks = blockvector_get_num_blocks((*candidate)->b);

  if (layout->current_tag_shape_valid
      && layout->current_tag_offset != UINT64_MAX
      && layout->current_tag_back_pointer_offset
          != UINT64_MAX) {
    back_pointer_offset = layout->current_tag_back_pointer_offset;
    expected_size = layout->current_tag_expected_size;
    first_target = CEILDIV(layout->current_tag_offset,
                           scalpel_state.blocksize);
    last_target = back_pointer_offset / scalpel_state.blocksize;
  }
  else if (layout->last_mismatching_back_pointer_offset != UINT64_MAX
           && layout->last_mismatching_tag_offset != UINT64_MAX
           && layout->last_mismatching_back_pointer_offset
                   + FLV_PREVIOUS_TAG_SIZE == layout->parsed_extent) {
    back_pointer_offset = layout->last_mismatching_back_pointer_offset;
    expected_size = layout->last_mismatching_expected_size;
    first_target = layout->last_mismatching_tag_offset
        / scalpel_state.blocksize + 1;
    last_target = back_pointer_offset / scalpel_state.blocksize;
  }
  else if (layout->current_tag_offset != UINT64_MAX
           && layout->current_tag_offset == layout->parsed_extent
           && (layout->current_tag_offset % scalpel_state.blocksize) == 0) {
    back_pointer_offset = layout->current_tag_offset;
    first_target = layout->current_tag_offset / scalpel_state.blocksize;
    last_target = first_target;
  }
  else if (layout->parsed_extent > 0
           && layout->parsed_extent == blockvector_get_data_length(
               (*candidate)->b)
           && (layout->parsed_extent % scalpel_state.blocksize) == 0) {
    back_pointer_offset = layout->parsed_extent;
    first_target = layout->parsed_extent / scalpel_state.blocksize;
    last_target = first_target;
  }

  if (first_target == UINT64_MAX || first_target > last_target
      || first_target > total_blocks) {
    return FLV_REPAIR_NO_MATCH;
  }
  if (last_target > total_blocks) {
    last_target = total_blocks;
  }
  uint64_t signature = flv_repair_signature(
      layout, blockvector_get_data_length((*candidate)->b));

  if (state->stage != FLV_REPAIR_STAGE_SCAN
      || state->signature != signature) {
    state->stage = FLV_REPAIR_STAGE_SCAN;
    state->signature = signature;
    state->next_actual = 0;
    state->best_target_slot = UINT64_MAX;
    state->best_actual = -1;
    state->best_content_cost = UINT64_MAX;
    state->best_confidence = 0;
    state->best_reservations = INT64_MAX;
    state->extension_terminal_only = 0;
    state->extension_mapped = 0;
    state->extension_signature = 0;
    flv_repair_ambiguity_prepare(
        *candidate, first_target, last_target,
        &state->pending_ambiguity);
  }
  FlvRepairAnchor best = {
      .target_slot = state->best_target_slot,
      .actual_start = state->best_actual,
      .source_bytes = 0,
      .content_cost = state->best_content_cost,
      .confidence = state->best_confidence,
      .reservations = state->best_reservations
  };
  uint64_t image_blocks = CEILDIV(
      filemirror_filesize(scalpel_state.filemirror), scalpel_state.blocksize);

  for (uint64_t actual_index = state->next_actual;
       actual_index < image_blocks && actual_index <= (uint64_t)INT64_MAX;
       actual_index++) {
    int64_t actual = (int64_t)actual_index;

    state->next_actual = actual_index + 1;
    if (filemirror_apparent_blocknumber(scalpel_state.filemirror, actual) >= 0
        && !filemirror_actual_block_covered(scalpel_state.filemirror,
                                            actual)) {
      for (uint64_t target = first_target; target <= last_target; target++) {
        FlvRepairAnchor trial;
        bool valid = flv_repair_anchor_valid(
            *candidate, target, first_target, actual,
            back_pointer_offset, expected_size, &trial);

        if (valid) {
          flv_repair_ambiguity_retain(
              &state->pending_ambiguity, &trial);
        }
        if (valid && flv_repair_anchor_better(&trial, &best)) {
          best = trial;
          state->best_target_slot = trial.target_slot;
          state->best_actual = trial.actual_start;
          state->best_content_cost = trial.content_cost;
          state->best_confidence = trial.confidence;
          state->best_reservations = trial.reservations;
        }
      }
    }
    if ((actual_index % FLV_REPAIR_SCAN_QUANTUM) == 0) {
      if (reassembly_check_kill_queue(work, candidate, uuidp, uuidc)) {
        return FLV_REPAIR_STOPPED;
      }
      if (atomic_load_explicit(&REASS_RETURN_TO_IDLE,
                               memory_order_acquire)) {
        carve_put_state((*candidate)->carvehashkey, state);
        if (reassembly_time_to_checkpoint(work->id, *candidate, uuidp,
                                          uuidc)) {
          return FLV_REPAIR_STOPPED;
        }
      }
    }
  }
  if (best.actual_start < 0
      || !flv_repair_anchor_valid(
          *candidate, best.target_slot, first_target, best.actual_start,
          back_pointer_offset, expected_size, anchor)) {
    state->stage = FLV_REPAIR_STAGE_NONE;
    state->signature = 0;
    state->next_actual = 0;
    state->best_actual = -1;
    state->extension_terminal_only = 0;
    flv_repair_ambiguity_reset(&state->pending_ambiguity);
    return FLV_REPAIR_NO_MATCH;
  }
  state->stage = FLV_REPAIR_STAGE_EXTEND;
  state->extension_terminal_only = 0;
  state->best_target_slot = anchor->target_slot;
  state->best_actual = anchor->actual_start;
  state->best_content_cost = anchor->content_cost;
  state->best_confidence = anchor->confidence;
  state->best_reservations = anchor->reservations;
  carve_put_state((*candidate)->carvehashkey, state);
  return FLV_REPAIR_READY;
}

static inline FlvRepairResult flv_reassembly_find_pair_anchor(
    ThreadWork *work, CarveInfo **candidate, const FlvLayout *layout,
    FlvCarveState *state, FlvPairAnchor *anchor,
    uuid_string_t uuidp, uuid_string_t uuidc) {
  if (!work || !candidate || !*candidate || !(*candidate)->b || !layout
      || !flv_carve_state_valid(state) || !anchor
      || scalpel_state.blocksize == 0) {
    return FLV_REPAIR_NO_MATCH;
  }
  uint64_t back_pointer_offset = UINT64_MAX;
  uint32_t expected_size = FLV_REPAIR_ANY_PREVIOUS_SIZE;
  uint64_t target_slot = UINT64_MAX;

  if (layout->current_tag_shape_valid
      && layout->current_tag_offset != UINT64_MAX
      && layout->current_tag_back_pointer_offset != UINT64_MAX) {
    back_pointer_offset = layout->current_tag_back_pointer_offset;
    expected_size = layout->current_tag_expected_size;
    target_slot = CEILDIV(layout->current_tag_offset,
                          scalpel_state.blocksize);
  }
  else if (layout->last_mismatching_back_pointer_offset != UINT64_MAX
           && layout->last_mismatching_tag_offset != UINT64_MAX
           && layout->last_mismatching_back_pointer_offset
                   + FLV_PREVIOUS_TAG_SIZE == layout->parsed_extent) {
    back_pointer_offset = layout->last_mismatching_back_pointer_offset;
    expected_size = layout->last_mismatching_expected_size;
    target_slot = layout->last_mismatching_tag_offset
        / scalpel_state.blocksize + 1;
  }
  if (target_slot == UINT64_MAX
      || target_slot > blockvector_get_num_blocks((*candidate)->b)
      || expected_size == FLV_REPAIR_ANY_PREVIOUS_SIZE) {
    return FLV_REPAIR_NO_MATCH;
  }
  uint64_t signature = flv_repair_signature(
      layout, blockvector_get_data_length((*candidate)->b));

  if ((state->stage != FLV_REPAIR_STAGE_PAIR_FIRST_SCAN
       && state->stage != FLV_REPAIR_STAGE_PAIR_SECOND_SCAN)
      || state->signature != signature
      || state->pair_target_slot != target_slot) {
    state->stage = FLV_REPAIR_STAGE_PAIR_FIRST_SCAN;
    state->signature = signature;
    state->next_actual = 0;
    state->pair_target_slot = target_slot;
    state->pair_first_blocks = 0;
    state->pair_minimum_first_blocks = 0;
    state->pair_maximum_first_blocks = 0;
    state->pair_next_second_actual = 0;
    state->pair_source_bytes = 0;
    state->pair_first_actual = -1;
    state->pair_second_actual = -1;
  }
  uint64_t image_blocks = CEILDIV(
      filemirror_filesize(scalpel_state.filemirror), scalpel_state.blocksize);

  while (true) {
    if (state->stage == FLV_REPAIR_STAGE_PAIR_FIRST_SCAN) {
      bool found_first = false;

      for (uint64_t actual_index = state->next_actual;
           actual_index < image_blocks
               && actual_index <= (uint64_t)INT64_MAX;
           actual_index++) {
        int64_t actual = (int64_t)actual_index;

        state->next_actual = actual_index + 1;
        if (filemirror_apparent_blocknumber(
                scalpel_state.filemirror, actual) >= 0
            && !filemirror_actual_block_covered(
                scalpel_state.filemirror, actual)) {
          uint64_t minimum_first_blocks;
          uint64_t maximum_first_blocks;

          if (flv_repair_partial_anchor_valid(
                  *candidate, target_slot, actual,
                  back_pointer_offset, expected_size,
                  &minimum_first_blocks, &maximum_first_blocks)) {
            state->pair_first_actual = actual;
            state->pair_first_blocks = maximum_first_blocks;
            state->pair_minimum_first_blocks = minimum_first_blocks;
            state->pair_maximum_first_blocks = maximum_first_blocks;
            state->pair_next_second_actual = 0;
            state->stage = FLV_REPAIR_STAGE_PAIR_SECOND_SCAN;
            found_first = true;
            break;
          }
        }
        if ((actual_index % FLV_REPAIR_SCAN_QUANTUM) == 0) {
          if (reassembly_check_kill_queue(
                  work, candidate, uuidp, uuidc)) {
            return FLV_REPAIR_STOPPED;
          }
          if (atomic_load_explicit(&REASS_RETURN_TO_IDLE,
                                   memory_order_acquire)) {
            carve_put_state((*candidate)->carvehashkey, state);
            if (reassembly_time_to_checkpoint(
                    work->id, *candidate, uuidp, uuidc)) {
              return FLV_REPAIR_STOPPED;
            }
          }
        }
      }
      if (!found_first) {
        state->stage = FLV_REPAIR_STAGE_NONE;
        state->signature = 0;
        state->pair_first_actual = -1;
        carve_put_state((*candidate)->carvehashkey, state);
        return FLV_REPAIR_NO_MATCH;
      }
    }

    while (state->stage == FLV_REPAIR_STAGE_PAIR_SECOND_SCAN) {
      for (uint64_t actual_index = state->pair_next_second_actual;
           actual_index < image_blocks
               && actual_index <= (uint64_t)INT64_MAX;
           actual_index++) {
        int64_t actual = (int64_t)actual_index;

        state->pair_next_second_actual = actual_index + 1;
        if (filemirror_apparent_blocknumber(
                scalpel_state.filemirror, actual) >= 0
            && !filemirror_actual_block_covered(
                scalpel_state.filemirror, actual)
            && flv_repair_pair_anchor_valid(
                *candidate, target_slot, state->pair_first_actual,
                state->pair_first_blocks, actual,
                back_pointer_offset, expected_size, anchor)) {
          flv_repair_refine_pair_anchor(
              *candidate, back_pointer_offset, expected_size, anchor);
          state->pair_target_slot = anchor->target_slot;
          state->pair_first_blocks = anchor->first_blocks;
          state->pair_first_actual = anchor->first_actual;
          state->pair_second_actual = anchor->second_actual;
          state->pair_source_bytes = anchor->source_bytes;
          state->stage = FLV_REPAIR_STAGE_PAIR_EXTEND;
          carve_put_state((*candidate)->carvehashkey, state);
          return FLV_REPAIR_READY;
        }
        if ((actual_index % FLV_REPAIR_SCAN_QUANTUM) == 0) {
          if (reassembly_check_kill_queue(
                  work, candidate, uuidp, uuidc)) {
            return FLV_REPAIR_STOPPED;
          }
          if (atomic_load_explicit(&REASS_RETURN_TO_IDLE,
                                   memory_order_acquire)) {
            carve_put_state((*candidate)->carvehashkey, state);
            if (reassembly_time_to_checkpoint(
                    work->id, *candidate, uuidp, uuidc)) {
              return FLV_REPAIR_STOPPED;
            }
          }
        }
      }
      if (state->pair_first_blocks
          > state->pair_minimum_first_blocks) {
        state->pair_first_blocks--;
        state->pair_next_second_actual = 0;
        continue;
      }
      break;
    }
    state->stage = FLV_REPAIR_STAGE_PAIR_FIRST_SCAN;
    state->pair_first_actual = -1;
    state->pair_first_blocks = 0;
    state->pair_minimum_first_blocks = 0;
    state->pair_maximum_first_blocks = 0;
  }
}

// Bind the saved extension to its unchanged rollback mapping and source run.
static inline uint64_t flv_extension_signature(
    BlockVector *original, uint64_t target, int64_t actual) {
  uint64_t signature = UINT64_C(14695981039346656037);
  uint64_t blocks = blockvector_get_num_blocks(original);
  const uint64_t fields[] = {
    scalpel_state.blocksize, target, (uint64_t)actual, blocks,
    blockvector_get_data_length(original)
  };
  for (size_t index = 0; index < sizeof(fields) / sizeof(fields[0]); index++) {
    signature = (signature ^ fields[index]) * UINT64_C(1099511628211);
  }
  for (uint64_t slot = 0; slot < blocks; slot++) {
    signature = (signature ^ (uint64_t)blockvector_get_actual_blocknumber(
        original, slot)) * UINT64_C(1099511628211);
  }
  return signature;
}

// Rebuild scratch bytes without repeating completed extension/validation batches.
// If availability changed, restart this trial against the new map instead.
static inline uint64_t flv_reassembly_restore_extension(
    CarveInfo *candidate, FlvCarveState *state, uint64_t mapped,
    uint64_t maximum_blocks, uint64_t image_blocks) {
  uint64_t target = state->best_target_slot;
  uint64_t retained = state->extension_mapped;
  uint64_t actual = (uint64_t)state->best_actual;
  if (retained <= mapped || target > maximum_blocks
      || retained > maximum_blocks - target || actual >= image_blocks
      || retained > image_blocks - actual
      || retained > (uint64_t)INT64_MAX - actual) {
    state->extension_mapped = 0;
    return mapped;
  }
  for (uint64_t block = 0; block < retained; block++) {
    int64_t source = (int64_t)(actual + block);
    if (filemirror_apparent_blocknumber(scalpel_state.filemirror, source) < 0
        || filemirror_actual_block_covered(scalpel_state.filemirror, source)
        || flv_actual_in_prefix(candidate, target, source)) {
      state->extension_mapped = 0;
      return mapped;
    }
  }
  resize_blockvector(candidate->b, target + retained);
  for (uint64_t block = mapped; block < retained; block++) {
    blockvector_set_apparent_blocknumber(candidate->b, target + block,
        filemirror_apparent_blocknumber(scalpel_state.filemirror,
                                       (int64_t)(actual + block)));
  }
  blockvector_set_data_length_to_mapped_extent(candidate->b);
  return retained;
}

static inline FlvRepairResult flv_reassembly_extend_anchor(
    ThreadWork *work, CarveInfo **candidate, FlvCarveState *state,
    uuid_string_t uuidp, uuid_string_t uuidc) {
  if (!work || !candidate || !*candidate || !(*candidate)->b
      || !flv_carve_state_valid(state)
      || state->stage != FLV_REPAIR_STAGE_EXTEND
      || state->best_actual < 0 || scalpel_state.blocksize == 0) {
    return FLV_REPAIR_NO_MATCH;
  }
  uint64_t target_slot = state->best_target_slot;
  int64_t actual_start = state->best_actual;

  inflate_blockvector((*candidate)->b);
  uint64_t total_blocks = blockvector_get_num_blocks((*candidate)->b);

  if (target_slot == 0 || target_slot > total_blocks) {
    state->stage = FLV_REPAIR_STAGE_NONE;
    flv_repair_ambiguity_reset(&state->pending_ambiguity);
    return FLV_REPAIR_NO_MATCH;
  }
  BlockVector *original = (*candidate)->b;
  BlockVector *hypothesis = NULL;

  uint64_t signature = flv_extension_signature(
      original, target_slot, actual_start);
  if (state->extension_signature != signature) {
    state->extension_mapped = 0;
    state->extension_signature = signature;
  }

  clone_blockvector(original, &hypothesis, false);
  (*candidate)->b = hypothesis;
  bool continuing = total_blocks > target_slot
      && blockvector_get_actual_blocknumber((*candidate)->b, target_slot)
          == actual_start;

  if (!continuing) {
    resize_blockvector((*candidate)->b, target_slot);
    total_blocks = target_slot;
  }
  uint64_t mapped = total_blocks - target_slot;
  uint64_t maximum_blocks = CEILDIV(FLV_MAXIMUM_SIZE,
                                    scalpel_state.blocksize);
  uint64_t image_blocks = CEILDIV(
      filemirror_filesize(scalpel_state.filemirror), scalpel_state.blocksize);

  mapped = flv_reassembly_restore_extension(
      *candidate, state, mapped, maximum_blocks, image_blocks);
  total_blocks = target_slot + mapped;

  while (total_blocks < maximum_blocks) {
    uint64_t add = FLV_REPAIR_EXTENSION_BLOCKS;

    if (add > maximum_blocks - total_blocks) {
      add = maximum_blocks - total_blocks;
    }
    uint64_t available = 0;

    while (available < add) {
      if ((uint64_t)actual_start + mapped + available >= image_blocks
          || (uint64_t)actual_start + mapped + available
              > (uint64_t)INT64_MAX) {
        break;
      }
      int64_t actual = actual_start + (int64_t)(mapped + available);

      if (filemirror_apparent_blocknumber(scalpel_state.filemirror, actual) < 0
          || filemirror_actual_block_covered(scalpel_state.filemirror, actual)
          || flv_actual_in_prefix(*candidate, target_slot, actual)) {
        break;
      }
      available++;
    }
    if (available == 0) {
      break;
    }
    resize_blockvector((*candidate)->b, total_blocks + available);
    for (uint64_t block = 0; block < available; block++) {
      int64_t actual = actual_start + (int64_t)(mapped + block);
      int64_t apparent = filemirror_apparent_blocknumber(
          scalpel_state.filemirror, actual);

      blockvector_set_apparent_blocknumber(
          (*candidate)->b, total_blocks + block, apparent);
    }
    total_blocks += available;
    mapped += available;
    blockvector_set_data_length_to_mapped_extent((*candidate)->b);
    inflate_blockvector((*candidate)->b);
    uint64_t length = blockvector_get_data_length((*candidate)->b);
    const uint8_t *data = (const uint8_t *)blockvector_get_data_pointer(
        (*candidate)->b);
    FlvLayout layout;
    FlvParseResult result = flv_parse_file(data, length, &layout);

    if (layout.parsed_extent > target_slot * (uint64_t)scalpel_state.blocksize
        && flv_layout_terminal_boundary(&layout, result, length)) {
      blockvector_set_data_length((*candidate)->b, layout.parsed_extent);
      data = (const uint8_t *)blockvector_get_data_pointer((*candidate)->b);
      FlvLayout exact_layout;
      FlvParseResult exact_result = flv_parse_file(
          data, layout.parsed_extent, &exact_layout);

      if (exact_result == FLV_PARSE_COMPLETE
          && flv_layout_terminal_likely(&exact_layout)) {
        if (state->extension_terminal_only) {
          flv_write_extent_hypothesis(*candidate, layout.parsed_extent);
          state->stage = FLV_REPAIR_STAGE_NONE;
          state->signature = 0;
          state->next_actual = 0;
          state->best_actual = -1;
          state->extension_terminal_only = 0;
          state->extension_mapped = 0;
          flv_repair_ambiguity_reset(&state->pending_ambiguity);
          (*candidate)->b = original;
          free_blockvector(&hypothesis);
          carve_put_state((*candidate)->carvehashkey, state);
          return FLV_REPAIR_NO_MATCH;
        }
        flv_repair_ambiguity_commit(
            state, target_slot, actual_start);
        flv_publish_ambiguities(*candidate, state);
        free_blockvector(&original);
        state->stage = FLV_REPAIR_STAGE_NONE;
        state->signature = 0;
        state->extension_mapped = 0;
        state->repairs++;
        carve_put_state((*candidate)->carvehashkey, state);
        if (scalpel_state.write_promising) {
          (*candidate)->flavor = PROMISING;
          write_candidate(candidate, false);
        }
        else {
          destroy_candidate(candidate);
        }
        return FLV_REPAIR_STOPPED;
      }
    }

    bool needs_more = (layout.required_extent != UINT64_MAX
                       && layout.required_extent > length)
        || (result == FLV_PARSE_COMPLETE
            && layout.parsed_extent == length)
        || layout.failure_offset == length;

    if (!needs_more) {
      uint64_t progress = layout.parsed_extent;

      if (progress <= target_slot * (uint64_t)scalpel_state.blocksize) {
        break;
      }
      if (state->extension_terminal_only) {
        if (flv_layout_structural_terminal_candidate(
                &layout, result, length)) {
          blockvector_set_data_length((*candidate)->b, progress);
          data = (const uint8_t *)blockvector_get_data_pointer(
              (*candidate)->b);
          FlvLayout exact_layout;
          FlvParseResult exact_result = flv_parse_file(
              data, progress, &exact_layout);

          if (exact_result == FLV_PARSE_COMPLETE
              && flv_layout_has_media(&exact_layout)) {
            flv_write_extent_hypothesis(*candidate, progress);
          }
        }
        break;
      }
      resize_blockvector((*candidate)->b,
                         CEILDIV(progress, scalpel_state.blocksize));
      inflate_blockvector((*candidate)->b);
      blockvector_set_data_length((*candidate)->b, progress);
      state->stage = FLV_REPAIR_STAGE_NONE;
      state->signature = 0;
      state->next_actual = 0;
      state->best_actual = -1;
      state->extension_mapped = 0;
      state->repairs++;
      flv_repair_ambiguity_commit(
          state, target_slot, actual_start);
      carve_put_state((*candidate)->carvehashkey, state);
      free_blockvector(&original);
      return FLV_REPAIR_PROGRESSED;
    }
    (*candidate)->b = original;
    bool killed = reassembly_check_kill_queue(
        work, candidate, uuidp, uuidc);

    if (killed) {
      free_blockvector(&hypothesis);
      return FLV_REPAIR_STOPPED;
    }
    (*candidate)->b = hypothesis;
    if (atomic_load_explicit(&REASS_RETURN_TO_IDLE, memory_order_acquire)) {
      (*candidate)->b = original;
      state->extension_mapped = mapped;
      carve_put_state((*candidate)->carvehashkey, state);
      bool checkpointed = reassembly_time_to_checkpoint(
          work->id, *candidate, uuidp, uuidc);

      if (checkpointed) {
        free_blockvector(&hypothesis);
        return FLV_REPAIR_STOPPED;
      }
      (*candidate)->b = hypothesis;
    }
    if (available < add) {
      break;
    }
  }

  state->stage = FLV_REPAIR_STAGE_NONE;
  state->signature = 0;
  state->extension_terminal_only = 0;
  state->extension_mapped = 0;
  flv_repair_ambiguity_reset(&state->pending_ambiguity);
  (*candidate)->b = original;
  free_blockvector(&hypothesis);
  carve_put_state((*candidate)->carvehashkey, state);
  return FLV_REPAIR_NO_MATCH;
}

static inline FlvRepairResult flv_reassembly_extend_pair(
    ThreadWork *work, CarveInfo **candidate, FlvCarveState *state,
    uuid_string_t uuidp, uuid_string_t uuidc) {
  (void)work;
  (void)uuidp;
  (void)uuidc;
  if (!candidate || !*candidate || !(*candidate)->b
      || !flv_carve_state_valid(state)
      || state->stage != FLV_REPAIR_STAGE_PAIR_EXTEND
      || state->pair_first_actual < 0 || state->pair_second_actual < 0
      || state->pair_first_blocks == 0
      || scalpel_state.blocksize == 0
      || state->pair_target_slot
          > UINT64_MAX / scalpel_state.blocksize
      || state->pair_first_blocks
          > UINT64_MAX / scalpel_state.blocksize) {
    return FLV_REPAIR_NO_MATCH;
  }
  uint64_t first_bytes = state->pair_first_blocks
      * (uint64_t)scalpel_state.blocksize;

  if (state->pair_source_bytes <= first_bytes) {
    return FLV_REPAIR_NO_MATCH;
  }
  uint64_t required_second_blocks = CEILDIV(
      state->pair_source_bytes - first_bytes, scalpel_state.blocksize);
  uint64_t desired_second_blocks = required_second_blocks;

  if (desired_second_blocks < FLV_REPAIR_EXTENSION_BLOCKS) {
    desired_second_blocks = FLV_REPAIR_EXTENSION_BLOCKS;
  }
  uint64_t image_blocks = CEILDIV(
      filemirror_filesize(scalpel_state.filemirror), scalpel_state.blocksize);
  uint64_t second_available = 0;

  while (second_available < desired_second_blocks) {
    if ((uint64_t)state->pair_second_actual + second_available
            >= image_blocks
        || (uint64_t)state->pair_second_actual + second_available
            > (uint64_t)INT64_MAX) {
      break;
    }
    int64_t actual = state->pair_second_actual
        + (int64_t)second_available;
    uint64_t first_end = (uint64_t)state->pair_first_actual
        + state->pair_first_blocks;

    if (filemirror_apparent_blocknumber(
            scalpel_state.filemirror, actual) < 0
        || filemirror_actual_block_covered(
            scalpel_state.filemirror, actual)
        || flv_actual_in_prefix(
            *candidate,
            state->pair_target_slot + state->pair_first_blocks,
            actual)
        || ((uint64_t)actual >= (uint64_t)state->pair_first_actual
            && (uint64_t)actual < first_end)) {
      break;
    }
    second_available++;
  }
  if (second_available < required_second_blocks
      || state->pair_target_slot > UINT64_MAX
          - state->pair_first_blocks - second_available) {
    state->stage = FLV_REPAIR_STAGE_NONE;
    state->signature = 0;
    carve_put_state((*candidate)->carvehashkey, state);
    return FLV_REPAIR_NO_MATCH;
  }

  BlockVector *original = (*candidate)->b;
  BlockVector *hypothesis = NULL;

  clone_blockvector(original, &hypothesis, false);
  (*candidate)->b = hypothesis;
  resize_blockvector(hypothesis, state->pair_target_slot);
  resize_blockvector(
      hypothesis, state->pair_target_slot + state->pair_first_blocks
          + second_available);

  for (uint64_t block = 0; block < state->pair_first_blocks; block++) {
    int64_t actual = state->pair_first_actual + (int64_t)block;
    int64_t apparent = filemirror_apparent_blocknumber(
        scalpel_state.filemirror, actual);

    blockvector_set_apparent_blocknumber(
        hypothesis, state->pair_target_slot + block, apparent);
  }
  for (uint64_t block = 0; block < second_available; block++) {
    int64_t actual = state->pair_second_actual + (int64_t)block;
    int64_t apparent = filemirror_apparent_blocknumber(
        scalpel_state.filemirror, actual);

    blockvector_set_apparent_blocknumber(
        hypothesis,
        state->pair_target_slot + state->pair_first_blocks + block,
        apparent);
  }
  blockvector_set_data_length_to_mapped_extent(hypothesis);
  inflate_blockvector(hypothesis);
  uint64_t length = blockvector_get_data_length(hypothesis);
  const uint8_t *data = (const uint8_t *)blockvector_get_data_pointer(
      hypothesis);
  FlvLayout layout;
  FlvParseResult result = flv_parse_file(data, length, &layout);
  uint64_t target_offset = state->pair_target_slot
      * (uint64_t)scalpel_state.blocksize;
  uint64_t confirmed_extent = target_offset + state->pair_source_bytes;

  if (result == FLV_PARSE_INVALID
      || layout.parsed_extent < confirmed_extent) {
    (*candidate)->b = original;
    free_blockvector(&hypothesis);
    state->stage = FLV_REPAIR_STAGE_NONE;
    state->signature = 0;
    carve_put_state((*candidate)->carvehashkey, state);
    return FLV_REPAIR_NO_MATCH;
  }
  if (flv_layout_terminal_boundary(&layout, result, length)) {
    blockvector_set_data_length(hypothesis, layout.parsed_extent);
    data = (const uint8_t *)blockvector_get_data_pointer(hypothesis);
    FlvLayout exact_layout;
    FlvParseResult exact_result = flv_parse_file(
        data, layout.parsed_extent, &exact_layout);

    if (exact_result == FLV_PARSE_COMPLETE
        && flv_layout_terminal_likely(&exact_layout)) {
      flv_publish_ambiguities(*candidate, state);
      free_blockvector(&original);
      state->stage = FLV_REPAIR_STAGE_NONE;
      state->signature = 0;
      state->repairs++;
      carve_put_state((*candidate)->carvehashkey, state);
      if (scalpel_state.write_promising) {
        (*candidate)->flavor = PROMISING;
        write_candidate(candidate, false);
      }
      else {
        destroy_candidate(candidate);
      }
      return FLV_REPAIR_STOPPED;
    }
  }
  uint64_t retained_extent = layout.observed_extent;

  if (retained_extent < layout.parsed_extent) {
    retained_extent = layout.parsed_extent;
  }
  if (retained_extent < confirmed_extent) {
    retained_extent = confirmed_extent;
  }
  if (retained_extent > length) {
    retained_extent = length;
  }
  resize_blockvector(hypothesis,
                     CEILDIV(retained_extent, scalpel_state.blocksize));
  blockvector_set_data_length(hypothesis, retained_extent);
  inflate_blockvector(hypothesis);
  free_blockvector(&original);
  state->stage = FLV_REPAIR_STAGE_NONE;
  state->signature = 0;
  state->next_actual = 0;
  state->pair_first_actual = -1;
  state->pair_second_actual = -1;
  state->repairs++;
  carve_put_state((*candidate)->carvehashkey, state);
  return FLV_REPAIR_PROGRESSED;
}

static inline void flv_file_validate(char *data, uint64_t length,
                                     bool *validates,
                                     uint64_t *validates_to,
                                     bool *promising, uint32_t needleidx,
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

  FlvLayout layout;
  FlvParseResult result = flv_parse_file((const uint8_t *)data, length,
                                         &layout);
  if (result == FLV_PARSE_INVALID || layout.tag_count == 0
      || !flv_layout_has_media(&layout)) {
    return;
  }
  uint64_t extent = result == FLV_PARSE_COMPLETE
      ? layout.parsed_extent : layout.observed_extent;
  if (extent == 0) {
    return;
  }
  *validates_to = extent - 1;
  *promising = true;
}

// A valid FLV tag boundary is useful evidence but cannot prove that no later
// tags belong to the file. Preserve that interpretation while reassembly
// continues looking for a fragmented continuation.
static inline bool flv_write_extent_hypothesis(CarveInfo *candidate,
                                               uint64_t extent) {
  if (!candidate || !candidate->b || extent < FLV_MINIMUM_SIZE
      || extent > blockvector_get_data_length(candidate->b)
      || scalpel_state.blocksize == 0 || !scalpel_state.write_promising) {
    return false;
  }

  BlockVector *parent = candidate->b;
  BlockVector *hypothesis = NULL;
  const CarveInfoFlavor parent_flavor = candidate->flavor;
  const bool parent_chopped = candidate->chopped;
  const uint64_t parent_validates_to = candidate->best_validates_to;

  clone_blockvector(parent, &hypothesis, false);
  candidate->b = hypothesis;
  resize_blockvector(hypothesis,
                     CEILDIV(extent, scalpel_state.blocksize));
  blockvector_set_data_length(hypothesis, extent);
  inflate_blockvector(hypothesis);
  candidate->flavor = PROMISING;
  candidate->chopped = false;
  candidate->best_validates_to = extent - 1;
  CarveInfo *preserved = candidate;
  write_candidate(&preserved, true);

  candidate->b = parent;
  candidate->flavor = parent_flavor;
  candidate->chopped = parent_chopped;
  candidate->best_validates_to = parent_validates_to;
  free_blockvector(&hypothesis);
  return true;
}

static inline void flv_reassembly(ThreadWork *work, CarveInfo **candidate,
                                  uuid_string_t uuidp,
                                  uuid_string_t uuidc) {
  if (!work || !candidate || !*candidate || !(*candidate)->b) {
    return;
  }
  FlvCarveState *state = (FlvCarveState *)carve_get_state(
      (*candidate)->carvehashkey);

  if (!flv_carve_state_valid(state)) {
    flv_free_carve_state((void **)&state);
    state = (FlvCarveState *)calloc(1, sizeof(*state));
    check_memory_allocation(state, __LINE__, __FILE__, "FlvCarveState");
    state->magic = FLV_CARVE_STATE_MAGIC;
    state->version = FLV_CARVE_STATE_VERSION;
    state->best_actual = -1;
    state->best_target_slot = UINT64_MAX;
    state->best_content_cost = UINT64_MAX;
    state->best_reservations = INT64_MAX;
    state->preserved_terminal_generation = UINT64_MAX;
  }

  while (*candidate) {
    inflate_blockvector((*candidate)->b);
    const uint8_t *data = (const uint8_t *)blockvector_get_data_pointer(
        (*candidate)->b);
    uint64_t length = blockvector_get_data_length((*candidate)->b);
    FlvLayout layout;
    FlvParseResult result = flv_parse_file(data, length, &layout);

    if (flv_layout_structural_terminal_candidate(&layout, result, length)
        && !flv_layout_terminal_likely(&layout)
        && state->preserved_terminal_generation != state->repairs
        && flv_write_extent_hypothesis(*candidate,
                                       layout.parsed_extent)) {
      state->preserved_terminal_generation = state->repairs;
      carve_put_state((*candidate)->carvehashkey, state);
    }

    if (layout.parsed_extent > 0
        && flv_layout_terminal_boundary(&layout, result, length)) {
      blockvector_set_data_length((*candidate)->b, layout.parsed_extent);
      data = (const uint8_t *)blockvector_get_data_pointer((*candidate)->b);
      FlvLayout exact_layout;
      FlvParseResult exact_result = flv_parse_file(
          data, layout.parsed_extent, &exact_layout);

      if (exact_result == FLV_PARSE_COMPLETE
          && flv_layout_terminal_likely(&exact_layout)) {
        flv_publish_ambiguities(*candidate, state);
        flv_free_carve_state((void **)&state);
        if (scalpel_state.write_promising) {
          (*candidate)->flavor = PROMISING;
          write_candidate(candidate, false);
        }
        else {
          destroy_candidate(candidate);
        }
        return;
      }
    }

    bool anchor_extension_finished = false;
    bool pair_extension_finished = false;
    bool terminal_extension_finished = false;
    if (state->stage == FLV_REPAIR_STAGE_EXTEND) {
      bool terminal_only = state->extension_terminal_only != 0;
      FlvRepairResult extension = flv_reassembly_extend_anchor(
          work, candidate, state, uuidp, uuidc);

      if (extension == FLV_REPAIR_STOPPED) {
        flv_free_carve_state((void **)&state);
        return;
      }
      if (extension == FLV_REPAIR_PROGRESSED) {
        continue;
      }
      terminal_extension_finished = terminal_only;
      anchor_extension_finished = !terminal_only;
    }
    if (state->stage == FLV_REPAIR_STAGE_PAIR_EXTEND) {
      FlvRepairResult extension = flv_reassembly_extend_pair(
          work, candidate, state, uuidp, uuidc);

      if (extension == FLV_REPAIR_STOPPED) {
        flv_free_carve_state((void **)&state);
        return;
      }
      if (extension == FLV_REPAIR_PROGRESSED) {
        continue;
      }
      pair_extension_finished = true;
    }

    bool needs_contiguous_extension =
        (layout.required_extent != UINT64_MAX
         && layout.required_extent > length)
        || layout.failure_offset == length
        || (result == FLV_PARSE_COMPLETE && layout.parsed_extent == length);

    if (needs_contiguous_extension
        && state->stage == FLV_REPAIR_STAGE_NONE
        && !terminal_extension_finished && !anchor_extension_finished
        && !pair_extension_finished) {
      uint64_t blocks = blockvector_get_num_blocks((*candidate)->b);

      if (blocks > 0) {
        int64_t last_actual = blockvector_get_actual_blocknumber(
            (*candidate)->b, blocks - 1);
        uint64_t image_blocks = CEILDIV(
            filemirror_filesize(scalpel_state.filemirror),
            scalpel_state.blocksize);

        if (last_actual >= 0 && (uint64_t)last_actual + 1 < image_blocks
            && filemirror_apparent_blocknumber(
                   scalpel_state.filemirror, last_actual + 1) >= 0
            && !filemirror_actual_block_covered(
                   scalpel_state.filemirror, last_actual + 1)) {
          state->stage = FLV_REPAIR_STAGE_EXTEND;
          state->extension_terminal_only = 1;
          state->extension_mapped = 0;
          state->extension_signature = 0;
          state->signature = 0;
          state->best_target_slot = blocks;
          state->best_actual = last_actual + 1;
          state->best_content_cost = 0;
          state->best_confidence = 0;
          state->best_reservations = 0;
          carve_put_state((*candidate)->carvehashkey, state);
          FlvRepairResult extension = flv_reassembly_extend_anchor(
              work, candidate, state, uuidp, uuidc);

          if (extension == FLV_REPAIR_STOPPED) {
            flv_free_carve_state((void **)&state);
            return;
          }
          if (extension == FLV_REPAIR_PROGRESSED) {
            continue;
          }
        }
      }
    }

    FlvRepairAnchor anchor;
    bool resuming_pair = state->stage == FLV_REPAIR_STAGE_PAIR_FIRST_SCAN
        || state->stage == FLV_REPAIR_STAGE_PAIR_SECOND_SCAN;
    FlvRepairResult search = anchor_extension_finished ? FLV_REPAIR_READY
        : ((resuming_pair || pair_extension_finished) ? FLV_REPAIR_NO_MATCH
            : flv_reassembly_find_anchor(
                work, candidate, &layout, state, &anchor, uuidp, uuidc));


    if (search == FLV_REPAIR_STOPPED) {
      flv_free_carve_state((void **)&state);
      return;
    }
    if (search == FLV_REPAIR_READY && !anchor_extension_finished) {
      FlvRepairResult extension = flv_reassembly_extend_anchor(
          work, candidate, state, uuidp, uuidc);

      if (extension == FLV_REPAIR_STOPPED) {
        flv_free_carve_state((void **)&state);
        return;
      }
      if (extension == FLV_REPAIR_PROGRESSED) {
        continue;
      }
    }

    FlvRepairResult pair_search = pair_extension_finished
        ? FLV_REPAIR_READY : FLV_REPAIR_NO_MATCH;

    if (search == FLV_REPAIR_NO_MATCH && !pair_extension_finished) {
      FlvPairAnchor pair_anchor;

      pair_search = flv_reassembly_find_pair_anchor(
          work, candidate, &layout, state, &pair_anchor, uuidp, uuidc);
      if (pair_search == FLV_REPAIR_STOPPED) {
        flv_free_carve_state((void **)&state);
        return;
      }
      if (pair_search == FLV_REPAIR_READY) {
        FlvRepairResult extension = flv_reassembly_extend_pair(
            work, candidate, state, uuidp, uuidc);

        if (extension == FLV_REPAIR_STOPPED) {
          flv_free_carve_state((void **)&state);
          return;
        }
        if (extension == FLV_REPAIR_PROGRESSED) {
          continue;
        }
      }
    }

    if (search == FLV_REPAIR_NO_MATCH
        && pair_search == FLV_REPAIR_NO_MATCH
        && flv_layout_structural_terminal_candidate(
            &layout, result, length)) {
      blockvector_set_data_length((*candidate)->b, layout.parsed_extent);
      FlvLayout exact_layout;
      FlvParseResult exact_result = flv_parse_file(
          data, layout.parsed_extent, &exact_layout);

      if (exact_result == FLV_PARSE_COMPLETE
          && flv_layout_has_media(&exact_layout)) {
        flv_publish_ambiguities(*candidate, state);
        flv_free_carve_state((void **)&state);
        if (scalpel_state.write_promising) {
          (*candidate)->flavor = PROMISING;
          write_candidate(candidate, false);
        }
        else {
          destroy_candidate(candidate);
        }
        return;
      }
    }

    state->stage = FLV_REPAIR_STAGE_NONE;
    state->signature = 0;
    flv_publish_ambiguities(*candidate, state);
    flv_free_carve_state((void **)&state);
    if (scalpel_state.write_promising) {
      (*candidate)->flavor = PROMISING;
      write_candidate(candidate, false);
    }
    else {
      destroy_candidate(candidate);
    }
    return;
  }
  flv_free_carve_state((void **)&state);
}

#endif
