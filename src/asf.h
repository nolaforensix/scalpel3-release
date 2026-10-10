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

// Advanced Systems Format validation and fragmented recovery support.
//
// ASF records an exact file extent, a persistent file identifier, packet count,
// and packet size in its File Properties Object. The Data Object repeats the
// identifier and packet count, and each media packet carries independently
// bounded payload metadata. These redundant fields provide useful evidence for
// locating fragmentation boundaries. ASF files containing Windows Media video
// codecs are written under the wmv subtype.

#ifndef SCALPEL3_ASF_H
#define SCALPEL3_ASF_H

#include "scalpel.h"

#define ASF_OBJECT_HEADER_SIZE UINT64_C(24)
#define ASF_HEADER_FIXED_SIZE UINT64_C(30)
#define ASF_FILE_PROPERTIES_SIZE UINT64_C(104)
#define ASF_STREAM_PROPERTIES_SIZE UINT64_C(78)
#define ASF_DATA_FIXED_SIZE UINT64_C(50)
#define ASF_SIMPLE_INDEX_FIXED_SIZE UINT64_C(56)
#define ASF_SIMPLE_INDEX_ENTRY_SIZE UINT64_C(6)
#define ASF_MINIMUM_SIZE \
  (ASF_HEADER_FIXED_SIZE + ASF_FILE_PROPERTIES_SIZE + ASF_DATA_FIXED_SIZE)
#define ASF_MAXIMUM_SIZE UINT64_C(1099511627776)
#define ASF_MAXIMUM_HEADER_SIZE UINT64_C(268435456)
#define ASF_MAXIMUM_PACKET_SIZE UINT32_C(67108864)
#define ASF_MAXIMUM_HEADER_OBJECTS UINT32_C(1048576)
#define ASF_PAYLOAD_CONFIDENCE_MAX 99
#define ASF_CARVE_STATE_MAGIC UINT32_C(0x41534653)
#define ASF_CARVE_STATE_VERSION 10U
#define ASF_REPAIR_ANCHOR_PACKETS 3U
#define ASF_REPAIR_POLL_INTERVAL UINT64_C(256)
#define ASF_REPAIR_PREFERRED_HYPOTHESES 8U
#define ASF_PREFERRED_ANCHOR 0U
#define ASF_PREFERRED_CONTIGUOUS_PREFIX 1U
#define ASF_PREFERRED_HOLE_SPLICE 2U

typedef enum AsfParseResult {
  ASF_PARSE_INVALID = 0,
  ASF_PARSE_PARTIAL = 1,
  ASF_PARSE_COMPLETE = 2
} AsfParseResult;

typedef struct AsfPacketSummary {
  uint32_t first_media_object[128];
  uint32_t last_media_object[128];
  uint32_t first_media_offset[128];
  uint32_t last_media_offset[128];
  uint32_t send_time;
  uint32_t duration;
  uint32_t sequence;
  uint32_t payloads;
  uint32_t media_objects;
  uint64_t stream_mask_low;
  uint64_t stream_mask_high;
  uint8_t sequence_code;
  uint8_t media_object_code;
  uint8_t media_offset_code;
  uint8_t packet_flags;
  uint8_t packet_property;
  uint8_t stream_seen[128];
} AsfPacketSummary;

typedef struct AsfLayout {
  uint64_t header_size;
  uint64_t file_size;
  uint64_t data_offset;
  uint64_t data_size;
  uint64_t packet_data_offset;
  uint64_t data_end;
  uint64_t packet_count;
  uint64_t play_duration;
  uint64_t send_duration;
  uint64_t packets_parsed;
  uint64_t parsed_extent;
  uint64_t required_extent;
  uint64_t failure_offset;
  uint64_t top_level_objects;
  uint64_t stream_mask_low;
  uint64_t stream_mask_high;
  uint32_t header_objects;
  uint32_t packet_size;
  uint32_t minimum_packet_size;
  uint32_t maximum_packet_size;
  uint32_t maximum_bitrate;
  uint32_t video_codec;
  uint32_t audio_streams;
  uint32_t video_streams;
  uint8_t file_id[16];
  bool header_valid;
  bool file_properties_valid;
  bool data_object_valid;
  bool packet_geometry_fixed;
  bool packets_valid;
  bool exact_extent_valid;
  bool saw_windows_media_video;
  bool broadcast;
} AsfLayout;

typedef enum AsfRefinePhase {
  ASF_REFINE_NONE,
  ASF_REFINE_PREFIX,
  ASF_REFINE_SCORES
} AsfRefinePhase;

typedef struct AsfRefineState {
  uint64_t view;
  uint64_t next_slot;
  uint64_t maximum_shift;
  uint64_t next_shift;
  int64_t cumulative_gain;
  int64_t best_gain;
  uint64_t best_shift;
  uint32_t phase;
} AsfRefineState;

typedef struct AsfCarveState {
  uint32_t magic;
  uint32_t version;
  uint64_t signature;
  uint64_t first_target_slot;
  uint64_t target_slot;
  uint64_t last_target_slot;
  uint64_t best_target_slot;
  uint64_t baseline_progress;
  uint64_t preferred_target_slots[ASF_REPAIR_PREFERRED_HYPOTHESES];
  uint64_t preferred_end_slots[ASF_REPAIR_PREFERRED_HYPOTHESES];
  uint64_t next_actual;
  uint64_t best_time_cost;
  uint64_t best_object_cost;
  uint64_t best_sequence_cost;
  uint64_t best_distance;
  uint64_t matches;
  uint64_t repairs;
  int64_t best_actual;
  int64_t preferred_source_actuals[ASF_REPAIR_PREFERRED_HYPOTHESES];
  int64_t preferred_suffix_actuals[ASF_REPAIR_PREFERRED_HYPOTHESES];
  int64_t best_reservations;
  uint32_t best_confidence;
  uint32_t best_anchor_packets;
  uint32_t best_object_pairs;
  uint32_t best_sequence_pairs;
  uint32_t best_time_pairs;
  uint32_t best_prefix_zeros;
  uint32_t scan_active;
  uint32_t preferred_count;
  uint32_t preferred_index;
  uint32_t preferred_modes[ASF_REPAIR_PREFERRED_HYPOTHESES];
  AsfRefineState refinement;
} AsfCarveState;

typedef struct AsfAnchorScore {
  uint64_t time_cost;
  uint64_t object_cost;
  uint64_t sequence_cost;
  uint32_t packets;
  uint32_t object_pairs;
  uint32_t sequence_pairs;
  uint32_t time_pairs;
} AsfAnchorScore;

static const uint8_t ASF_HEADER_GUID[16] = {
  0x30, 0x26, 0xb2, 0x75, 0x8e, 0x66, 0xcf, 0x11,
  0xa6, 0xd9, 0x00, 0xaa, 0x00, 0x62, 0xce, 0x6c
};

static const uint8_t ASF_FILE_PROPERTIES_GUID[16] = {
  0xa1, 0xdc, 0xab, 0x8c, 0x47, 0xa9, 0xcf, 0x11,
  0x8e, 0xe4, 0x00, 0xc0, 0x0c, 0x20, 0x53, 0x65
};

static const uint8_t ASF_STREAM_PROPERTIES_GUID[16] = {
  0x91, 0x07, 0xdc, 0xb7, 0xb7, 0xa9, 0xcf, 0x11,
  0x8e, 0xe6, 0x00, 0xc0, 0x0c, 0x20, 0x53, 0x65
};

static const uint8_t ASF_DATA_GUID[16] = {
  0x36, 0x26, 0xb2, 0x75, 0x8e, 0x66, 0xcf, 0x11,
  0xa6, 0xd9, 0x00, 0xaa, 0x00, 0x62, 0xce, 0x6c
};

static const uint8_t ASF_SIMPLE_INDEX_GUID[16] = {
  0x90, 0x08, 0x00, 0x33, 0xb1, 0xe5, 0xcf, 0x11,
  0x89, 0xf4, 0x00, 0xa0, 0xc9, 0x03, 0x49, 0xcb
};

static const uint8_t ASF_INDEX_GUID[16] = {
  0xd3, 0x29, 0xe2, 0xd6, 0xda, 0x35, 0xd1, 0x11,
  0x90, 0x34, 0x00, 0xa0, 0xc9, 0x03, 0x49, 0xbe
};

static const uint8_t ASF_AUDIO_MEDIA_GUID[16] = {
  0x40, 0x9e, 0x69, 0xf8, 0x4d, 0x5b, 0xcf, 0x11,
  0xa8, 0xfd, 0x00, 0x80, 0x5f, 0x5c, 0x44, 0x2b
};

static const uint8_t ASF_VIDEO_MEDIA_GUID[16] = {
  0xc0, 0xef, 0x19, 0xbc, 0x4d, 0x5b, 0xcf, 0x11,
  0xa8, 0xfd, 0x00, 0x80, 0x5f, 0x5c, 0x44, 0x2b
};

static inline uint16_t asf_read_le16(const uint8_t *data);
static inline uint32_t asf_read_le32(const uint8_t *data);
static inline uint64_t asf_read_le64(const uint8_t *data);
static inline bool asf_guid_equal(const uint8_t *left,
                                  const uint8_t *right);
static inline bool asf_windows_media_video_codec(uint32_t codec);
static inline bool asf_simple_index_valid(const uint8_t *object,
                                          uint64_t object_size,
                                          const AsfLayout *layout);
static inline bool asf_read_variable(const uint8_t *data, uint64_t limit,
                                     uint64_t *position, uint8_t code,
                                     uint32_t default_value,
                                     uint32_t *value);
static inline bool asf_parse_packet(const uint8_t *data, uint64_t length,
                                    uint32_t fixed_packet_size,
                                    AsfPacketSummary *summary);
static inline bool asf_parse_stream_properties(const uint8_t *object,
                                               uint64_t object_size,
                                               AsfLayout *layout);
static inline AsfParseResult asf_parse_file(const uint8_t *data,
                                            uint64_t length,
                                            AsfLayout *layout);
static inline char *asf_header_discovery(char *base, uint64_t offset,
                                         uint64_t remaining,
                                         char **matchpos,
                                         uint32_t *matchlen,
                                         uint32_t blocksize);
static inline char *asf_no_header_discovery(char *base, uint64_t offset,
                                            uint64_t remaining,
                                            char **matchpos,
                                            uint32_t *matchlen,
                                            uint32_t blocksize);
static inline uint32_t asf_block_validate(
    char *data, uint64_t length, BlockValidationDecision *decision,
    uint64_t *validates_to, uint32_t needleidx, uint32_t blocksize,
    void *blockhashkey);
static inline bool asf_carve_state_valid(const AsfCarveState *state);
static inline bool asf_serialize_carve_state(void **state, FILE *fp,
                                             StateSerialization mode);
static inline void *asf_clone_carve_state(const void *state);
static inline void asf_free_carve_state(void **state);
static inline void asf_print_carve_state(const void *state);
static inline size_t asf_sizeof_carve_state(const void *state);
static inline uint64_t asf_reassembly_signature(const AsfLayout *layout,
                                                uint64_t target_slot);
static inline void asf_reassembly_reset_search(AsfCarveState *state,
                                               uint64_t signature,
                                               uint64_t target_slot);
static inline void asf_reassembly_clear_best(AsfCarveState *state);
static inline void asf_reassembly_add_preferred(
    AsfCarveState *state, uint64_t target_slot, int64_t source_actual,
    uint32_t mode);
static inline void asf_reassembly_add_hole_splice(
    AsfCarveState *state, uint64_t target_slot, uint64_t end_slot,
    int64_t suffix_actual);
static inline bool asf_reassembly_preferred_active(
    const AsfCarveState *state);
static inline bool asf_reassembly_advance_target(
    AsfCarveState *state);
static inline int32_t asf_filetype_index(const char *filetype);
static inline BlockValidationDecision asf_reassembly_confidence(
    int64_t actual, int32_t asf_index, int32_t wmv_index);
static inline bool asf_reassembly_apparent_in_prefix(
    BlockVector *blockvector, int64_t apparent,
    uint64_t prefix_blocks);
static inline uint64_t asf_reassembly_refinement_view(
    BlockVector *blockvector, const AsfCarveState *state,
    int32_t asf_index, int32_t wmv_index, uint64_t image_blocks);
static inline bool asf_reassembly_refinement_valid(
    const AsfRefineState *refinement, uint64_t target,
    uint64_t maximum_shift);
static inline bool asf_reassembly_refine_opaque_boundary(
    ThreadWork *work, CarveInfo **candidate, AsfCarveState *state,
    int32_t asf_index, int32_t wmv_index, uint64_t image_blocks,
    uuid_string_t uuidp, uuid_string_t uuidc, BlockVector **original,
    uint64_t original_validates_to);
static inline bool asf_reassembly_copy_packet(
    CarveInfo *candidate, const uint8_t *prefix, uint64_t prefix_length,
    uint64_t target_offset, int64_t source_actual, uint64_t source_blocks,
    int64_t suffix_actual, uint64_t packet_offset, uint8_t *packet,
    uint32_t packet_size, uint64_t image_blocks);
static inline bool asf_reassembly_score_anchor(
    CarveInfo *candidate, const AsfLayout *layout, uint64_t target_slot,
    int64_t source_actual, uint64_t source_blocks, int64_t suffix_actual,
    uint64_t prefix_length, uint8_t *packet, uint64_t image_blocks,
    AsfAnchorScore *score);
static inline bool asf_reassembly_better_anchor(
    const AsfCarveState *state, const AsfAnchorScore *score,
    BlockValidationDecision confidence, int64_t reservations,
    uint64_t distance, uint32_t prefix_zeros);
static inline bool asf_reassembly_checkpoint(
    ThreadWork *work, CarveInfo **candidate, AsfCarveState *state,
    uuid_string_t uuidp, uuid_string_t uuidc);
static inline void asf_reassembly_rollback_trial(CarveInfo *candidate,
    BlockVector **original, uint64_t original_validates_to);
static inline bool asf_reassembly_checkpoint_trial(
    ThreadWork *work, CarveInfo **candidate, AsfCarveState *state,
    uuid_string_t uuidp, uuid_string_t uuidc, BlockVector **original,
    uint64_t original_validates_to);
static inline bool asf_reassembly_extend_prefix(CarveInfo *candidate,
                                                uint64_t target_slot,
                                                uint64_t image_blocks);
static inline bool asf_reassembly_apply_run(
    CarveInfo *candidate, const AsfLayout *layout, uint64_t target_slot,
    int64_t source_actual, uint64_t image_blocks, bool stop_at_zero);
static inline bool asf_reassembly_apply_splice(
    CarveInfo *candidate, const AsfLayout *layout, uint64_t target_slot,
    uint64_t end_slot, int64_t source_actual, int64_t suffix_actual,
    uint64_t image_blocks);
static inline bool asf_candidate_contiguous(const CarveInfo *candidate);
static inline void asf_assign_subtype(CarveInfo *candidate,
                                      const AsfLayout *layout);
static inline void asf_file_validate(char *data, uint64_t length,
                                     bool *validates,
                                     uint64_t *validates_to,
                                     bool *promising, uint32_t needleidx,
                                     uint32_t blocksize,
                                     void *carvehashkey);
static inline bool asf_expand_contiguous_candidate(CarveInfo *candidate,
                                                   uint64_t required_extent);
static inline void asf_candidate_validate(CarveInfo *candidate,
                                          bool *validates,
                                          uint64_t *validates_to,
                                          bool *promising);
static inline void asf_reassembly(ThreadWork *work, CarveInfo **candidate,
                                  uuid_string_t uuidp,
                                  uuid_string_t uuidc);

static inline uint16_t asf_read_le16(const uint8_t *data) {
  return (uint16_t)data[0] | (uint16_t)((uint16_t)data[1] << 8);
}

static inline uint32_t asf_read_le32(const uint8_t *data) {
  return (uint32_t)data[0]
      | ((uint32_t)data[1] << 8)
      | ((uint32_t)data[2] << 16)
      | ((uint32_t)data[3] << 24);
}

static inline uint64_t asf_read_le64(const uint8_t *data) {
  return (uint64_t)asf_read_le32(data)
      | ((uint64_t)asf_read_le32(data + 4) << 32);
}

static inline bool asf_guid_equal(const uint8_t *left,
                                  const uint8_t *right) {
  return left && right && memcmp(left, right, 16) == 0;
}

#define ASF_FOURCC(a, b, c, d) \
  ((uint32_t)(uint8_t)(a) | ((uint32_t)(uint8_t)(b) << 8) \
   | ((uint32_t)(uint8_t)(c) << 16) | ((uint32_t)(uint8_t)(d) << 24))

static inline bool asf_windows_media_video_codec(uint32_t codec) {
  switch (codec) {
  case ASF_FOURCC('W', 'M', 'V', '1'):
  case ASF_FOURCC('W', 'M', 'V', '2'):
  case ASF_FOURCC('W', 'M', 'V', '3'):
  case ASF_FOURCC('W', 'M', 'V', 'A'):
  case ASF_FOURCC('W', 'M', 'V', 'P'):
  case ASF_FOURCC('W', 'V', 'P', '2'):
  case ASF_FOURCC('W', 'V', 'C', '1'):
  case ASF_FOURCC('M', 'S', 'S', '1'):
  case ASF_FOURCC('M', 'S', 'S', '2'):
  case ASF_FOURCC('M', 'S', 'A', '1'):
  case ASF_FOURCC('M', 'T', 'S', '2'):
    return true;
  default:
    return false;
  }
}

static inline bool asf_simple_index_valid(const uint8_t *object,
                                          uint64_t object_size,
                                          const AsfLayout *layout) {
  if (!object || !layout || object_size < ASF_SIMPLE_INDEX_FIXED_SIZE
      || (!asf_guid_equal(object, ASF_SIMPLE_INDEX_GUID)
          && !asf_guid_equal(object, ASF_INDEX_GUID))) {
    return false;
  }

  static const uint8_t zero_guid[16] = {0};
  if (memcmp(object + ASF_OBJECT_HEADER_SIZE, zero_guid,
             sizeof(zero_guid)) != 0
      && memcmp(object + ASF_OBJECT_HEADER_SIZE, layout->file_id,
                sizeof(layout->file_id)) != 0) {
    return false;
  }

  uint64_t interval = asf_read_le64(object + 40);
  uint32_t maximum_packet_count = asf_read_le32(object + 48);
  uint32_t entries = asf_read_le32(object + 52);
  if (interval == 0 || maximum_packet_count == 0
      || ASF_SIMPLE_INDEX_FIXED_SIZE
             + (uint64_t)entries * ASF_SIMPLE_INDEX_ENTRY_SIZE
             != object_size) {
    return false;
  }

  for (uint32_t index = 0; index < entries; index++) {
    const uint8_t *entry = object + ASF_SIMPLE_INDEX_FIXED_SIZE
        + (uint64_t)index * ASF_SIMPLE_INDEX_ENTRY_SIZE;
    uint32_t packet = asf_read_le32(entry);
    uint16_t count = asf_read_le16(entry + 4);
    if (packet >= layout->packet_count || count == 0
        || count > maximum_packet_count
        || count > layout->packet_count - packet) {
      return false;
    }
  }
  return true;
}

static inline bool asf_read_variable(const uint8_t *data, uint64_t limit,
                                     uint64_t *position, uint8_t code,
                                     uint32_t default_value,
                                     uint32_t *value) {
  if (!data || !position || !value || *position > limit) {
    return false;
  }
  uint64_t width = code == 0 ? 0 : code == 1 ? 1 : code == 2 ? 2 : 4;
  if (width > limit - *position) {
    return false;
  }
  if (width == 0) {
    *value = default_value;
  }
  else if (width == 1) {
    *value = data[*position];
  }
  else if (width == 2) {
    *value = asf_read_le16(data + *position);
  }
  else {
    *value = asf_read_le32(data + *position);
  }
  *position += width;
  return true;
}

static inline bool asf_parse_packet(const uint8_t *data, uint64_t length,
                                    uint32_t fixed_packet_size,
                                    AsfPacketSummary *summary) {
  if (!data || !summary || fixed_packet_size == 0
      || length < fixed_packet_size) {
    return false;
  }
  memset(summary, 0, sizeof(*summary));
  uint64_t position = 0;
  uint8_t first = data[position++];
  uint8_t packet_flags;
  uint8_t packet_property;

  if ((first & 0x80U) != 0) {
    uint32_t error_correction_length = first & 0x0fU;
    if (error_correction_length < 2
        || error_correction_length > fixed_packet_size - position) {
      return false;
    }
    position += error_correction_length;
    if (position + 2 > fixed_packet_size) {
      return false;
    }
    packet_flags = data[position++];
    packet_property = data[position++];
  }
  else {
    packet_flags = first;
    if (position >= fixed_packet_size) {
      return false;
    }
    packet_property = data[position++];
  }

  uint32_t packet_length;
  uint32_t sequence;
  uint32_t padding_length;
  summary->packet_flags = packet_flags;
  summary->packet_property = packet_property;
  summary->sequence_code = (uint8_t)((packet_flags >> 1) & 3U);
  summary->media_object_code = (uint8_t)((packet_property >> 4) & 3U);
  summary->media_offset_code = (uint8_t)((packet_property >> 2) & 3U);
  if (!asf_read_variable(data, fixed_packet_size, &position,
                         (uint8_t)((packet_flags >> 5) & 3U),
                         fixed_packet_size, &packet_length)
      || !asf_read_variable(data, fixed_packet_size, &position,
                            summary->sequence_code, 0,
                            &sequence)
      || !asf_read_variable(data, fixed_packet_size, &position,
                            (uint8_t)((packet_flags >> 3) & 3U), 0,
                            &padding_length)) {
    return false;
  }
  summary->sequence = sequence;
  if (packet_length == 0 || packet_length > fixed_packet_size
      || padding_length >= packet_length
      || position > packet_length || packet_length - position < 6) {
    return false;
  }
  summary->send_time = asf_read_le32(data + position);
  summary->duration = asf_read_le16(data + position + 4);
  position += 6;

  uint32_t payload_count = 1;
  uint8_t payload_length_code = 0;
  if ((packet_flags & 1U) != 0) {
    if (position >= packet_length) {
      return false;
    }
    uint8_t payload_flags = data[position++];
    payload_count = payload_flags & 0x3fU;
    payload_length_code = (uint8_t)(payload_flags >> 6);
    if (payload_count == 0 || payload_length_code == 0) {
      return false;
    }
  }
  uint64_t payload_limit = packet_length - padding_length;
  if (position > payload_limit) {
    return false;
  }

  for (uint32_t payload = 0; payload < payload_count; payload++) {
    if (position >= payload_limit) {
      return false;
    }
    uint8_t stream_byte = data[position++];
    uint32_t stream = stream_byte & 0x7fU;
    if (stream == 0) {
      return false;
    }
    if (stream < 64) {
      summary->stream_mask_low |= UINT64_C(1) << stream;
    }
    else {
      summary->stream_mask_high |= UINT64_C(1) << (stream - 64);
    }

    uint32_t media_object_number;
    uint32_t media_object_offset;
    uint32_t replicated_length;
    uint32_t payload_length = 0;
    if (!asf_read_variable(data, payload_limit, &position,
                           (uint8_t)((packet_property >> 4) & 3U), 0,
                           &media_object_number)
        || !asf_read_variable(data, payload_limit, &position,
                              (uint8_t)((packet_property >> 2) & 3U), 0,
                              &media_object_offset)
        || !asf_read_variable(data, payload_limit, &position,
                              (uint8_t)(packet_property & 3U), 0,
                              &replicated_length)) {
      return false;
    }
    if (replicated_length > payload_limit - position) {
      return false;
    }
    if (replicated_length >= 8) {
      uint32_t media_object_size = asf_read_le32(data + position);
      if (media_object_size == 0 || media_object_size >= (1U << 29)) {
        return false;
      }
    }
    else if (replicated_length != 0 && replicated_length != 1) {
      return false;
    }
    position += replicated_length;

    if (summary->stream_seen[stream] == 0) {
      summary->first_media_object[stream] = media_object_number;
      summary->first_media_offset[stream] = media_object_offset;
      summary->stream_seen[stream] = 1;
    }
    summary->last_media_object[stream] = media_object_number;
    summary->last_media_offset[stream] = media_object_offset;

    if (payload_count > 1) {
      if (!asf_read_variable(data, payload_limit, &position,
                             payload_length_code, 0, &payload_length)
          || payload_length > payload_limit - position) {
        return false;
      }
    }
    else {
      payload_length = (uint32_t)(payload_limit - position);
    }

    if (replicated_length == 1) {
      uint64_t compressed_end = position + payload_length;
      while (position < compressed_end) {
        uint32_t compressed_length = data[position++];
        if (compressed_length == 0
            || compressed_length > compressed_end - position) {
          return false;
        }
        position += compressed_length;
        summary->media_objects++;
      }
    }
    else {
      position += payload_length;
      summary->media_objects += media_object_number != UINT32_MAX;
    }
  }
  summary->payloads = payload_count;
  return position == payload_limit;
}

static inline bool asf_parse_stream_properties(const uint8_t *object,
                                               uint64_t object_size,
                                               AsfLayout *layout) {
  if (!object || !layout || object_size < ASF_STREAM_PROPERTIES_SIZE) {
    return false;
  }
  uint32_t type_specific_size = asf_read_le32(object + 64);
  uint32_t error_correction_size = asf_read_le32(object + 68);
  uint16_t flags = asf_read_le16(object + 72);
  uint32_t stream = flags & 0x7fU;
  uint64_t payload_size = object_size - ASF_STREAM_PROPERTIES_SIZE;
  if (stream == 0 || stream >= 128
      || type_specific_size > payload_size
      || error_correction_size > payload_size - type_specific_size) {
    return false;
  }
  if (stream < 64) {
    layout->stream_mask_low |= UINT64_C(1) << stream;
  }
  else {
    layout->stream_mask_high |= UINT64_C(1) << (stream - 64);
  }

  if (asf_guid_equal(object + 24, ASF_AUDIO_MEDIA_GUID)) {
    if (type_specific_size < 16) {
      return false;
    }
    layout->audio_streams++;
  }
  else if (asf_guid_equal(object + 24, ASF_VIDEO_MEDIA_GUID)) {
    if (type_specific_size < 51) {
      return false;
    }
    const uint8_t *type_specific = object + ASF_STREAM_PROPERTIES_SIZE;
    uint32_t bitmap_size = asf_read_le32(type_specific + 11);
    uint32_t width = asf_read_le32(type_specific + 15);
    uint32_t height = asf_read_le32(type_specific + 19);
    uint16_t planes = asf_read_le16(type_specific + 23);
    uint32_t codec = asf_read_le32(type_specific + 27);
    if (bitmap_size < 40 || bitmap_size > type_specific_size - 11
        || width == 0 || height == 0 || planes == 0) {
      return false;
    }
    layout->video_streams++;
    if (layout->video_codec == 0) {
      layout->video_codec = codec;
    }
    if (asf_windows_media_video_codec(codec)) {
      layout->saw_windows_media_video = true;
    }
  }
  return true;
}

static inline AsfParseResult asf_parse_file(const uint8_t *data,
                                            uint64_t length,
                                            AsfLayout *layout) {
  if (!layout) {
    return ASF_PARSE_INVALID;
  }
  memset(layout, 0, sizeof(*layout));
  layout->failure_offset = UINT64_MAX;
  if (!data || length < 16 || !asf_guid_equal(data, ASF_HEADER_GUID)) {
    return ASF_PARSE_INVALID;
  }
  layout->header_valid = true;
  layout->parsed_extent = 16;
  layout->required_extent = ASF_HEADER_FIXED_SIZE;
  if (length < ASF_HEADER_FIXED_SIZE) {
    return ASF_PARSE_PARTIAL;
  }

  layout->header_size = asf_read_le64(data + 16);
  layout->header_objects = asf_read_le32(data + 24);
  if (layout->header_size < ASF_HEADER_FIXED_SIZE
      || layout->header_size > ASF_MAXIMUM_HEADER_SIZE
      || layout->header_objects == 0
      || layout->header_objects > ASF_MAXIMUM_HEADER_OBJECTS
      || data[28] != 1 || data[29] != 2) {
    layout->failure_offset = 16;
    return ASF_PARSE_INVALID;
  }
  layout->required_extent = layout->header_size;
  if (length < layout->header_size) {
    return ASF_PARSE_PARTIAL;
  }

  uint64_t position = ASF_HEADER_FIXED_SIZE;
  for (uint32_t index = 0; index < layout->header_objects; index++) {
    if (position > layout->header_size
        || ASF_OBJECT_HEADER_SIZE > layout->header_size - position) {
      layout->failure_offset = position;
      return ASF_PARSE_INVALID;
    }
    uint64_t object_size = asf_read_le64(data + position + 16);
    if (object_size < ASF_OBJECT_HEADER_SIZE
        || object_size > layout->header_size - position) {
      layout->failure_offset = position + 16;
      return ASF_PARSE_INVALID;
    }

    if (asf_guid_equal(data + position, ASF_FILE_PROPERTIES_GUID)) {
      if (layout->file_properties_valid
          || object_size < ASF_FILE_PROPERTIES_SIZE) {
        layout->failure_offset = position;
        return ASF_PARSE_INVALID;
      }
      memcpy(layout->file_id, data + position + 24, 16);
      layout->file_size = asf_read_le64(data + position + 40);
      layout->packet_count = asf_read_le64(data + position + 56);
      layout->play_duration = asf_read_le64(data + position + 64);
      layout->send_duration = asf_read_le64(data + position + 72);
      uint32_t flags = asf_read_le32(data + position + 88);
      layout->minimum_packet_size = asf_read_le32(data + position + 92);
      layout->maximum_packet_size = asf_read_le32(data + position + 96);
      layout->maximum_bitrate = asf_read_le32(data + position + 100);
      layout->broadcast = (flags & 1U) != 0;
      if ((flags & ~3U) != 0
          || layout->file_size < layout->header_size + ASF_DATA_FIXED_SIZE
          || layout->file_size > ASF_MAXIMUM_SIZE
          || layout->minimum_packet_size == 0
          || layout->maximum_packet_size < layout->minimum_packet_size
          || layout->maximum_packet_size > ASF_MAXIMUM_PACKET_SIZE) {
        layout->failure_offset = position + 40;
        return ASF_PARSE_INVALID;
      }
      layout->packet_geometry_fixed =
          layout->minimum_packet_size == layout->maximum_packet_size;
      layout->packet_size = layout->maximum_packet_size;
      layout->file_properties_valid = true;
      layout->exact_extent_valid = !layout->broadcast;
    }
    else if (asf_guid_equal(data + position, ASF_STREAM_PROPERTIES_GUID)
             && !asf_parse_stream_properties(data + position, object_size,
                                              layout)) {
      layout->failure_offset = position;
      return ASF_PARSE_INVALID;
    }
    position += object_size;
    layout->parsed_extent = position;
  }
  if (position != layout->header_size || !layout->file_properties_valid
      || layout->audio_streams + layout->video_streams == 0) {
    layout->failure_offset = position;
    return ASF_PARSE_INVALID;
  }

  layout->data_offset = layout->header_size;
  layout->required_extent = layout->data_offset + ASF_DATA_FIXED_SIZE;
  if (length < layout->required_extent) {
    return ASF_PARSE_PARTIAL;
  }
  if (!asf_guid_equal(data + layout->data_offset, ASF_DATA_GUID)) {
    layout->failure_offset = layout->data_offset;
    return ASF_PARSE_INVALID;
  }
  layout->data_size = asf_read_le64(data + layout->data_offset + 16);
  if (layout->data_size < ASF_DATA_FIXED_SIZE
      || layout->data_size > layout->file_size - layout->data_offset
      || memcmp(data + layout->data_offset + 24, layout->file_id, 16) != 0
      || asf_read_le64(data + layout->data_offset + 40)
             != layout->packet_count
      || data[layout->data_offset + 48] != 1
      || data[layout->data_offset + 49] != 1) {
    layout->failure_offset = layout->data_offset;
    return ASF_PARSE_INVALID;
  }
  layout->data_object_valid = true;
  layout->packet_data_offset = layout->data_offset + ASF_DATA_FIXED_SIZE;
  layout->data_end = layout->data_offset + layout->data_size;
  layout->required_extent = layout->data_end;
  layout->parsed_extent = layout->packet_data_offset;

  if (layout->packet_geometry_fixed) {
    if (layout->packet_count
            > (UINT64_MAX - ASF_DATA_FIXED_SIZE) / layout->packet_size
        || ASF_DATA_FIXED_SIZE + layout->packet_count * layout->packet_size
               != layout->data_size) {
      layout->failure_offset = layout->data_offset + 16;
      return ASF_PARSE_INVALID;
    }
    layout->packets_valid = true;
    for (uint64_t packet = 0; packet < layout->packet_count; packet++) {
      uint64_t packet_offset = layout->packet_data_offset
          + packet * layout->packet_size;
      if (packet_offset > length
          || layout->packet_size > length - packet_offset) {
        layout->required_extent = packet_offset + layout->packet_size;
        return ASF_PARSE_PARTIAL;
      }
      AsfPacketSummary summary;
      if (!asf_parse_packet(data + packet_offset,
                            length - packet_offset,
                            layout->packet_size, &summary)) {
        layout->packets_valid = false;
        layout->failure_offset = packet_offset;
        return ASF_PARSE_INVALID;
      }
      if ((summary.stream_mask_low & ~layout->stream_mask_low) != 0
          || (summary.stream_mask_high & ~layout->stream_mask_high) != 0) {
        layout->packets_valid = false;
        layout->failure_offset = packet_offset;
        return ASF_PARSE_INVALID;
      }
      layout->packets_parsed++;
      layout->parsed_extent = packet_offset + layout->packet_size;
    }
  }
  else if (length < layout->data_end) {
    return ASF_PARSE_PARTIAL;
  }

  position = layout->data_end;
  layout->parsed_extent = position;
  while (position < layout->file_size) {
    if (position > length || ASF_OBJECT_HEADER_SIZE > length - position) {
      layout->required_extent = position + ASF_OBJECT_HEADER_SIZE;
      return ASF_PARSE_PARTIAL;
    }
    uint64_t object_size = asf_read_le64(data + position + 16);
    if (object_size < ASF_OBJECT_HEADER_SIZE
        || object_size > layout->file_size - position) {
      layout->failure_offset = position;
      return ASF_PARSE_INVALID;
    }
    if (object_size > length - position) {
      layout->required_extent = position + object_size;
      return ASF_PARSE_PARTIAL;
    }
    position += object_size;
    layout->top_level_objects++;
    layout->parsed_extent = position;
  }
  if (position != layout->file_size) {
    layout->failure_offset = position;
    return ASF_PARSE_INVALID;
  }

  // Some ASF producers omit a trailing Simple Index Object from the File
  // Properties size. Include only an adjacent, internally consistent index
  // tied to this file; unrelated data after the declared extent is ignored.
  while (position <= length
         && ASF_SIMPLE_INDEX_FIXED_SIZE <= length - position
         && (asf_guid_equal(data + position, ASF_SIMPLE_INDEX_GUID)
             || asf_guid_equal(data + position, ASF_INDEX_GUID))) {
    uint64_t object_size = asf_read_le64(data + position + 16);
    if (object_size > length - position
        || !asf_simple_index_valid(data + position, object_size, layout)) {
      break;
    }
    position += object_size;
    layout->top_level_objects++;
  }

  layout->file_size = position;
  layout->parsed_extent = position;
  layout->required_extent = position;
  return ASF_PARSE_COMPLETE;
}

static inline char *asf_header_discovery(char *base, uint64_t offset,
                                         uint64_t remaining,
                                         char **matchpos,
                                         uint32_t *matchlen,
                                         uint32_t blocksize) {
  (void)blocksize;
  if (!base || !matchpos || !matchlen) {
    return NULL;
  }
  *matchpos = NULL;
  *matchlen = 0;
  if (remaining < sizeof(ASF_HEADER_GUID)) {
    return NULL;
  }
  uint8_t *search = (uint8_t *)base + offset;
  uint64_t available = remaining;
  while (available >= sizeof(ASF_HEADER_GUID)) {
    uint8_t *found = (uint8_t *)memchr(search, ASF_HEADER_GUID[0],
                                      (size_t)available);
    if (!found) {
      break;
    }
    uint64_t consumed = (uint64_t)(found - search);
    available -= consumed;
    if (available >= sizeof(ASF_HEADER_GUID)
        && asf_guid_equal(found, ASF_HEADER_GUID)) {
      uint64_t local = remaining
          - (uint64_t)(found - ((uint8_t *)base + offset));
      if (local < ASF_HEADER_FIXED_SIZE
          || (asf_read_le64(found + 16) >= ASF_HEADER_FIXED_SIZE
              && asf_read_le64(found + 16) <= ASF_MAXIMUM_HEADER_SIZE
              && asf_read_le32(found + 24) > 0
              && asf_read_le32(found + 24) <= ASF_MAXIMUM_HEADER_OBJECTS
              && found[28] == 1 && found[29] == 2)) {
        *matchpos = (char *)found;
        *matchlen = (uint32_t)sizeof(ASF_HEADER_GUID);
        return NULL;
      }
    }
    search = found + 1;
    available--;
  }
  return NULL;
}

static inline char *asf_no_header_discovery(char *base, uint64_t offset,
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

static inline uint32_t asf_block_validate(
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
  bool evidence = false;
  for (uint64_t position = 0; position + 16 <= length; position++) {
    if (asf_guid_equal(bytes + position, ASF_HEADER_GUID)
        || asf_guid_equal(bytes + position, ASF_FILE_PROPERTIES_GUID)
        || asf_guid_equal(bytes + position, ASF_STREAM_PROPERTIES_GUID)
        || asf_guid_equal(bytes + position, ASF_DATA_GUID)) {
      evidence = true;
      break;
    }
  }
  if (evidence || *decision == BLOCK_CONFIDENCE_VALID) {
    *decision = (BlockValidationDecision)ASF_PAYLOAD_CONFIDENCE_MAX;
  }
  return needleidx;
}

static inline bool asf_carve_state_valid(const AsfCarveState *state) {
  return state && state->magic == ASF_CARVE_STATE_MAGIC
      && state->version == ASF_CARVE_STATE_VERSION
      && state->refinement.phase <= ASF_REFINE_SCORES;
}

static inline bool asf_serialize_carve_state(void **state, FILE *fp,
                                             StateSerialization mode) {
  AsfCarveState **asf_state = (AsfCarveState **)state;
  if (!asf_state || !fp) {
    return false;
  }
  if (mode == DESERIALIZE) {
    *asf_state = (AsfCarveState *)calloc(1, sizeof(**asf_state));
    check_memory_allocation(*asf_state, __LINE__, __FILE__,
                            "AsfCarveState");
  }
  bool valid = false;
  if (mode == SERIALIZE) {
    valid = asf_carve_state_valid(*asf_state)
        && fwrite(*asf_state, sizeof(**asf_state), 1, fp) == 1;
  }
  else {
    const size_t prefix_size = offsetof(AsfCarveState, signature);
    valid = fread(*asf_state, prefix_size, 1, fp) == 1
        && (*asf_state)->magic == ASF_CARVE_STATE_MAGIC
        && ((*asf_state)->version == 9U
            || (*asf_state)->version == ASF_CARVE_STATE_VERSION);
    if (valid) {
      size_t record_size = (*asf_state)->version == 9U
          ? offsetof(AsfCarveState, refinement) : sizeof(**asf_state);
      valid = fread((uint8_t *)*asf_state + prefix_size,
                    record_size - prefix_size, 1, fp) == 1;
      (*asf_state)->version = ASF_CARVE_STATE_VERSION;
    }
  }
  if (!valid) {
    if (mode == DESERIALIZE) {
      free(*asf_state);
      *asf_state = NULL;
    }
    handle_error(SCALPEL_ERROR_CHECKPOINT, "ASF carve state", __LINE__,
                 __FILE__);
  }
  if (mode == DESERIALIZE && !asf_carve_state_valid(*asf_state)) {
    free(*asf_state);
    *asf_state = NULL;
    handle_error(SCALPEL_ERROR_CHECKPOINT, "invalid ASF carve state",
                 __LINE__, __FILE__);
  }
  return true;
}

static inline void *asf_clone_carve_state(const void *state) {
  const AsfCarveState *source = (const AsfCarveState *)state;
  if (!asf_carve_state_valid(source)) {
    return NULL;
  }
  AsfCarveState *copy = (AsfCarveState *)malloc(sizeof(*copy));
  check_memory_allocation(copy, __LINE__, __FILE__, "AsfCarveState");
  memcpy(copy, source, sizeof(*copy));
  return copy;
}

static inline void asf_free_carve_state(void **state) {
  if (state) {
    free(*state);
    *state = NULL;
  }
}

static inline void asf_print_carve_state(const void *state) {
  const AsfCarveState *asf_state = (const AsfCarveState *)state;
  if (!asf_carve_state_valid(asf_state)) {
    fprintf(stdout, "NULL");
    return;
  }
  fprintf(stdout,
          "first=%" PRIu64 " target=%" PRIu64 " last=%" PRIu64
          " next=%" PRIu64
          " best-target=%" PRIu64 " best=%" PRId64
          " matches=%" PRIu64 " repairs=%" PRIu64,
          asf_state->first_target_slot, asf_state->target_slot,
          asf_state->last_target_slot,
          asf_state->next_actual, asf_state->best_target_slot,
          asf_state->best_actual, asf_state->matches, asf_state->repairs);
}

static inline size_t asf_sizeof_carve_state(const void *state) {
  return asf_carve_state_valid((const AsfCarveState *)state)
      ? sizeof(AsfCarveState) : 0;
}

static inline uint64_t asf_reassembly_signature(const AsfLayout *layout,
                                                uint64_t target_slot) {
  if (!layout) {
    return 0;
  }
  uint64_t signature = UINT64_C(1469598103934665603);
  for (uint32_t index = 0; index < sizeof(layout->file_id); index++) {
    signature ^= layout->file_id[index];
    signature *= UINT64_C(1099511628211);
  }
  signature ^= layout->file_size;
  signature *= UINT64_C(1099511628211);
  signature ^= layout->packet_count;
  signature *= UINT64_C(1099511628211);
  signature ^= layout->packet_size;
  signature *= UINT64_C(1099511628211);
  signature ^= target_slot;
  signature *= UINT64_C(1099511628211);
  return signature;
}

static inline void asf_reassembly_reset_search(AsfCarveState *state,
                                               uint64_t signature,
                                               uint64_t target_slot) {
  if (!state) {
    return;
  }
  uint64_t repairs = asf_carve_state_valid(state) ? state->repairs : 0;
  memset(state, 0, sizeof(*state));
  state->magic = ASF_CARVE_STATE_MAGIC;
  state->version = ASF_CARVE_STATE_VERSION;
  state->signature = signature;
  state->first_target_slot = target_slot;
  state->target_slot = target_slot;
  state->last_target_slot = target_slot;
  for (uint32_t index = 0; index < ASF_REPAIR_PREFERRED_HYPOTHESES;
       index++) {
    state->preferred_source_actuals[index] = -1;
    state->preferred_suffix_actuals[index] = -1;
  }
  asf_reassembly_clear_best(state);
  state->best_target_slot = target_slot;
  state->repairs = repairs;
  state->scan_active = signature != 0 && target_slot != 0;
}

static inline void asf_reassembly_clear_best(AsfCarveState *state) {
  if (!state) {
    return;
  }
  state->best_time_cost = UINT64_MAX;
  state->best_object_cost = UINT64_MAX;
  state->best_sequence_cost = UINT64_MAX;
  state->best_distance = UINT64_MAX;
  state->best_actual = -1;
  state->best_reservations = INT64_MAX;
  state->best_confidence = 0;
  state->best_anchor_packets = 0;
  state->best_object_pairs = 0;
  state->best_sequence_pairs = 0;
  state->best_time_pairs = 0;
  state->best_prefix_zeros = 0;
  state->matches = 0;
  memset(&state->refinement, 0, sizeof(state->refinement));
}

static inline void asf_reassembly_add_preferred(
    AsfCarveState *state, uint64_t target_slot, int64_t source_actual,
    uint32_t mode) {
  if (!state || target_slot == 0 || source_actual < 0
      || state->preferred_count >= ASF_REPAIR_PREFERRED_HYPOTHESES) {
    return;
  }
  for (uint32_t index = 0; index < state->preferred_count; index++) {
    if (state->preferred_target_slots[index] == target_slot
        && state->preferred_source_actuals[index] == source_actual
        && state->preferred_modes[index] == mode) {
      return;
    }
  }
  uint32_t index = state->preferred_count++;
  state->preferred_target_slots[index] = target_slot;
  state->preferred_end_slots[index] = target_slot;
  state->preferred_source_actuals[index] = source_actual;
  state->preferred_suffix_actuals[index] = -1;
  state->preferred_modes[index] = mode;
}

static inline void asf_reassembly_add_hole_splice(
    AsfCarveState *state, uint64_t target_slot, uint64_t end_slot,
    int64_t suffix_actual) {
  if (!state || target_slot == 0 || end_slot <= target_slot
      || suffix_actual < 0
      || state->preferred_count >= ASF_REPAIR_PREFERRED_HYPOTHESES) {
    return;
  }
  for (uint32_t index = 0; index < state->preferred_count; index++) {
    if (state->preferred_target_slots[index] == target_slot
        && state->preferred_end_slots[index] == end_slot
        && state->preferred_suffix_actuals[index] == suffix_actual
        && state->preferred_modes[index] == ASF_PREFERRED_HOLE_SPLICE) {
      return;
    }
  }
  uint32_t index = state->preferred_count++;
  state->preferred_target_slots[index] = target_slot;
  state->preferred_end_slots[index] = end_slot;
  state->preferred_source_actuals[index] = -1;
  state->preferred_suffix_actuals[index] = suffix_actual;
  state->preferred_modes[index] = ASF_PREFERRED_HOLE_SPLICE;
}

static inline bool asf_reassembly_preferred_active(
    const AsfCarveState *state) {
  return state && state->preferred_index < state->preferred_count;
}

static inline bool asf_reassembly_advance_target(
    AsfCarveState *state) {
  if (!state) {
    return false;
  }
  if (asf_reassembly_preferred_active(state)) {
    state->preferred_index++;
    asf_reassembly_clear_best(state);
    if (asf_reassembly_preferred_active(state)) {
      state->target_slot =
          state->preferred_target_slots[state->preferred_index];
      if (state->preferred_modes[state->preferred_index]
              == ASF_PREFERRED_HOLE_SPLICE) {
        state->next_actual = 0;
      }
      else {
        state->next_actual =
            (uint64_t)state->preferred_source_actuals[state->preferred_index];
      }
      return true;
    }
    state->target_slot = state->last_target_slot;
    state->next_actual = 0;
    return state->target_slot >= state->first_target_slot;
  }
  if (state->target_slot <= state->first_target_slot) {
    return false;
  }
  state->target_slot--;
  state->next_actual = 0;
  asf_reassembly_clear_best(state);
  return true;
}

static inline int32_t asf_filetype_index(const char *filetype) {
  if (!filetype) {
    return -1;
  }
  for (uint32_t index = 0; index < scalpel_state.num_specs; index++) {
    if (strcmp(scalpel_state.search_specs[index].FILETYPE, filetype) == 0) {
      return (int32_t)index;
    }
  }
  return -1;
}

static inline BlockValidationDecision asf_reassembly_confidence(
    int64_t actual, int32_t asf_index, int32_t wmv_index) {
  BlockValidationDecision confidence = BLOCK_CONFIDENCE_INVALID;
  if (actual < 0) {
    return confidence;
  }
  if (asf_index >= 0) {
    confidence = filemirror_get_blocktype(
        scalpel_state.filemirror, actual, (uint32_t)asf_index);
  }
  if (wmv_index >= 0) {
    BlockValidationDecision wmv_confidence = filemirror_get_blocktype(
        scalpel_state.filemirror, actual, (uint32_t)wmv_index);
    if (wmv_confidence > confidence) {
      confidence = wmv_confidence;
    }
  }
  return confidence;
}

static inline bool asf_reassembly_apparent_in_prefix(
    BlockVector *blockvector, int64_t apparent,
    uint64_t prefix_blocks) {
  if (!blockvector || apparent < 0) {
    return false;
  }
  uint64_t blocks = blockvector_get_num_blocks(blockvector);
  if (prefix_blocks > blocks) {
    prefix_blocks = blocks;
  }
  for (uint64_t slot = 0; slot < prefix_blocks; slot++) {
    if (blockvector_get_apparent_blocknumber(blockvector, slot) == apparent) {
      return true;
    }
  }
  return false;
}

// Bind the saved refinement to its prefix and the evidence it actually uses.
// Apparent renumbering, reservations and unrelated image blocks do not matter.
static inline uint64_t asf_reassembly_refinement_view(
    BlockVector *blockvector, const AsfCarveState *state,
    int32_t asf_index, int32_t wmv_index, uint64_t image_blocks) {
  uint64_t view = UINT64_C(1469598103934665603);
  const uint64_t scope[] = {state->first_target_slot,
      state->best_target_slot, (uint64_t)state->best_actual, image_blocks,
      scalpel_state.blocksize, (uint64_t)asf_index, (uint64_t)wmv_index,
      state->refinement.phase};
  for (size_t index = 0; index < sizeof(scope) / sizeof(scope[0]); index++) {
    view = (view ^ scope[index]) * UINT64_C(1099511628211);
  }
  for (uint64_t slot = 0; slot < state->best_target_slot; slot++) {
    int64_t actual = blockvector_get_actual_blocknumber(blockvector, slot);
    view = (view ^ (uint64_t)actual) * UINT64_C(1099511628211);
  }
  if (state->refinement.phase == ASF_REFINE_SCORES) {
    for (uint64_t shift = 1; shift <= state->refinement.maximum_shift;
         shift++) {
      int64_t source = state->best_actual - (int64_t)shift;
      int64_t retained = blockvector_get_actual_blocknumber(
          blockvector, state->best_target_slot - shift);
      bool available = source >= 0 && (uint64_t)source < image_blocks
          && !filemirror_actual_block_covered(scalpel_state.filemirror, source)
          && filemirror_apparent_blocknumber(scalpel_state.filemirror,
                                               source) >= 0;
      uint64_t scores = (uint64_t)asf_reassembly_confidence(
          source, asf_index, wmv_index)
          | ((uint64_t)asf_reassembly_confidence(
              retained, asf_index, wmv_index) << 8)
          | ((uint64_t)available << 16);
      view = (view ^ scores) * UINT64_C(1099511628211);
    }
  }
  return view;
}

// Check saved work before using its cursors or accumulating another score.
static inline bool asf_reassembly_refinement_valid(
    const AsfRefineState *refinement, uint64_t target,
    uint64_t maximum_shift) {
  if (refinement->phase == ASF_REFINE_NONE
      || refinement->phase > ASF_REFINE_SCORES
      || refinement->maximum_shift > maximum_shift
      || refinement->maximum_shift > INT64_MAX / BLOCK_CONFIDENCE_VALID
      || refinement->next_slot > target
      || refinement->next_shift == 0
      || refinement->next_shift > refinement->maximum_shift + 1) {
    return false;
  }
  if (refinement->phase == ASF_REFINE_PREFIX) {
    return refinement->next_shift == 1
        && refinement->cumulative_gain == 0 && refinement->best_gain == 0
        && refinement->best_shift == 0;
  }
  const uint64_t processed = refinement->next_shift - 1;
  const int64_t score_bound = (int64_t)processed * BLOCK_CONFIDENCE_VALID;
  return (refinement->maximum_shift == 0 || refinement->next_slot == target)
      && refinement->best_shift <= processed
      && refinement->best_gain >= 0 && refinement->best_gain <= score_bound
      && refinement->cumulative_gain >= -score_bound
      && refinement->cumulative_gain <= refinement->best_gain
      && ((refinement->best_shift == 0) == (refinement->best_gain == 0));
}

static inline bool asf_reassembly_refine_opaque_boundary(
    ThreadWork *work, CarveInfo **candidate, AsfCarveState *state,
    int32_t asf_index, int32_t wmv_index, uint64_t image_blocks,
    uuid_string_t uuidp, uuid_string_t uuidc, BlockVector **original,
    uint64_t original_validates_to) {
  if (!work || !candidate || !*candidate || !(*candidate)->b || !state
      || state->best_actual < 0
      || (uint64_t)state->best_actual >= image_blocks
      || state->best_target_slot <= state->first_target_slot
      || wmv_index < 0) {
    return false;
  }

  uint64_t blocks = blockvector_get_num_blocks((*candidate)->b);
  if (state->best_target_slot > blocks) {
    return false;
  }

  uint64_t maximum_shift = state->best_target_slot
      - state->first_target_slot;
  if ((uint64_t)state->best_actual < maximum_shift) {
    maximum_shift = (uint64_t)state->best_actual;
  }
  if (maximum_shift > INT64_MAX / BLOCK_CONFIDENCE_VALID) {
    memset(&state->refinement, 0, sizeof(state->refinement));
    return false;
  }

  int64_t first_source = state->best_actual - (int64_t)maximum_shift;
  AsfRefineState *refinement = &state->refinement;
  if (refinement->phase != ASF_REFINE_NONE
      && (!asf_reassembly_refinement_valid(
              refinement, state->best_target_slot, maximum_shift)
          || refinement->view != asf_reassembly_refinement_view(
              (*candidate)->b, state, asf_index, wmv_index, image_blocks))) {
    memset(refinement, 0, sizeof(*refinement));
  }
  if (refinement->phase == ASF_REFINE_NONE) {
    memset(refinement, 0, sizeof(*refinement));
    refinement->phase = ASF_REFINE_PREFIX;
    refinement->maximum_shift = maximum_shift;
    refinement->next_shift = 1;
    refinement->view = asf_reassembly_refinement_view(
        (*candidate)->b, state, asf_index, wmv_index, image_blocks);
  }
  while (refinement->phase == ASF_REFINE_PREFIX
         && refinement->next_slot < state->best_target_slot
         && refinement->maximum_shift > 0) {
    uint64_t slot = refinement->next_slot;
    if (slot > 0 && slot % ASF_REPAIR_POLL_INTERVAL == 0
        && asf_reassembly_checkpoint_trial(
            work, candidate, state, uuidp, uuidc, original,
            original_validates_to)) {
      return true;
    }
    refinement->next_slot++;
    int64_t actual = blockvector_get_actual_blocknumber((*candidate)->b,
                                                        slot);
    if (actual < first_source || actual >= state->best_actual) {
      continue;
    }
    uint64_t shift = (uint64_t)(state->best_actual - actual);
    uint64_t replacement_slot = state->best_target_slot - shift;
    if (shift <= refinement->maximum_shift && slot < replacement_slot) {
      refinement->maximum_shift = shift - 1;
    }
  }
  if (refinement->phase == ASF_REFINE_PREFIX) {
    refinement->phase = ASF_REFINE_SCORES;
    refinement->view = asf_reassembly_refinement_view(
        (*candidate)->b, state, asf_index, wmv_index, image_blocks);
  }

  // Moving the target and source backward together preserves every packet byte
  // already checked by the anchor. Choose only the opaque prefix extension for
  // which classifier evidence improves on the blocks it replaces.
  while (refinement->next_shift <= refinement->maximum_shift) {
    uint64_t shift = refinement->next_shift;
    uint64_t target_slot = state->best_target_slot - shift;
    int64_t source_actual = state->best_actual - (int64_t)shift;
    int64_t retained_actual = blockvector_get_actual_blocknumber(
        (*candidate)->b, target_slot);
    if (source_actual < 0 || retained_actual < 0
        || (uint64_t)source_actual >= image_blocks
        || filemirror_actual_block_covered(scalpel_state.filemirror,
                                           source_actual)) {
      break;
    }

    int64_t source_apparent = filemirror_apparent_blocknumber(
        scalpel_state.filemirror, source_actual);
    if (source_apparent < 0) {
      break;
    }

    BlockValidationDecision source_confidence = asf_reassembly_confidence(
        source_actual, asf_index, wmv_index);
    BlockValidationDecision retained_confidence = asf_reassembly_confidence(
        retained_actual, asf_index, wmv_index);
    refinement->cumulative_gain += (int64_t)source_confidence
        - (int64_t)retained_confidence;
    if (refinement->cumulative_gain > refinement->best_gain) {
      refinement->best_gain = refinement->cumulative_gain;
      refinement->best_shift = shift;
    }
    refinement->next_shift = shift + 1;
    if (shift % ASF_REPAIR_POLL_INTERVAL == 0
        && asf_reassembly_checkpoint_trial(
            work, candidate, state, uuidp, uuidc, original,
            original_validates_to)) {
      return true;
    }
  }

  if (refinement->best_shift > 0) {
    state->best_target_slot -= refinement->best_shift;
    state->best_actual -= (int64_t)refinement->best_shift;
    state->best_confidence = (uint32_t)asf_reassembly_confidence(
        state->best_actual, asf_index, wmv_index);
  }
  memset(refinement, 0, sizeof(*refinement));
  return false;
}

static inline bool asf_reassembly_copy_packet(
    CarveInfo *candidate, const uint8_t *prefix, uint64_t prefix_length,
    uint64_t target_offset, int64_t source_actual, uint64_t source_blocks,
    int64_t suffix_actual, uint64_t packet_offset, uint8_t *packet,
    uint32_t packet_size, uint64_t image_blocks) {
  if (!candidate || !candidate->b || !prefix || !packet || packet_size == 0
      || source_actual < 0 || scalpel_state.blocksize == 0) {
    return false;
  }
  uint64_t copied = 0;
  while (copied < packet_size) {
    if (packet_offset > UINT64_MAX - copied) {
      return false;
    }
    uint64_t logical = packet_offset + copied;
    if (logical < target_offset) {
      uint64_t count = target_offset - logical;
      if (count > packet_size - copied) {
        count = packet_size - copied;
      }
      if (logical > prefix_length || count > prefix_length - logical) {
        return false;
      }
      memcpy(packet + copied, prefix + logical, (size_t)count);
      copied += count;
      continue;
    }

    uint64_t source_offset = logical - target_offset;
    int64_t run_actual = source_actual;
    if (source_blocks != UINT64_MAX) {
      if (source_blocks > UINT64_MAX / scalpel_state.blocksize) {
        return false;
      }
      uint64_t source_length = source_blocks
          * (uint64_t)scalpel_state.blocksize;
      if (source_offset >= source_length) {
        if (suffix_actual < 0) {
          return false;
        }
        source_offset -= source_length;
        run_actual = suffix_actual;
      }
    }
    uint64_t block_delta = source_offset / scalpel_state.blocksize;
    uint64_t offset_in_block = source_offset % scalpel_state.blocksize;
    if (block_delta > (uint64_t)INT64_MAX
        || run_actual > INT64_MAX - (int64_t)block_delta) {
      return false;
    }
    int64_t actual = run_actual + (int64_t)block_delta;
    if (actual < 0 || (uint64_t)actual >= image_blocks
        || filemirror_actual_block_covered(scalpel_state.filemirror, actual)) {
      return false;
    }
    int64_t apparent = filemirror_apparent_blocknumber(
        scalpel_state.filemirror, actual);
    uint64_t prefix_blocks = target_offset / scalpel_state.blocksize;
    if (apparent < 0
        || asf_reassembly_apparent_in_prefix(candidate->b, apparent,
                                             prefix_blocks)) {
      return false;
    }
    uint64_t actual_length = 0;
    const uint8_t *actual_data = (const uint8_t *)
        filemirror_actual_block_data_pointer(scalpel_state.filemirror, actual,
                                             &actual_length);
    if (!actual_data || offset_in_block >= actual_length) {
      return false;
    }
    uint64_t count = actual_length - offset_in_block;
    if (count > packet_size - copied) {
      count = packet_size - copied;
    }
    memcpy(packet + copied, actual_data + offset_in_block, (size_t)count);
    copied += count;
  }
  return true;
}

static inline bool asf_reassembly_score_anchor(
    CarveInfo *candidate, const AsfLayout *layout, uint64_t target_slot,
    int64_t source_actual, uint64_t source_blocks, int64_t suffix_actual,
    uint64_t prefix_length, uint8_t *packet, uint64_t image_blocks,
    AsfAnchorScore *score) {
  if (!candidate || !candidate->b || !layout || !packet || !score
      || !layout->packet_geometry_fixed || layout->packet_size == 0
      || layout->packets_parsed >= layout->packet_count
      || scalpel_state.blocksize == 0
      || target_slot > UINT64_MAX / scalpel_state.blocksize) {
    return false;
  }
  memset(score, 0, sizeof(*score));
  const uint8_t *prefix = (const uint8_t *)blockvector_get_data_pointer(
      candidate->b);
  uint64_t available = blockvector_get_data_length(candidate->b);
  if (prefix_length > available) {
    prefix_length = available;
  }
  uint64_t target_offset = target_slot * (uint64_t)scalpel_state.blocksize;
  uint64_t packet_offset = layout->packet_data_offset
      + layout->packets_parsed * (uint64_t)layout->packet_size;
  AsfPacketSummary previous;
  bool have_previous = false;

  if (layout->packets_parsed > 0) {
    uint64_t previous_offset = packet_offset - layout->packet_size;
    if (previous_offset <= prefix_length
        && layout->packet_size <= prefix_length - previous_offset
        && asf_parse_packet(prefix + previous_offset,
                            prefix_length - previous_offset,
                            layout->packet_size, &previous)) {
      have_previous = true;
    }
  }

  uint64_t remaining_packets = layout->packet_count - layout->packets_parsed;
  uint32_t anchors = remaining_packets < ASF_REPAIR_ANCHOR_PACKETS
      ? (uint32_t)remaining_packets : ASF_REPAIR_ANCHOR_PACKETS;
  for (uint32_t index = 0; index < anchors; index++) {
    uint64_t offset = packet_offset
        + (uint64_t)index * layout->packet_size;
    if (!asf_reassembly_copy_packet(
            candidate, prefix, prefix_length, target_offset, source_actual,
            source_blocks, suffix_actual, offset, packet,
            layout->packet_size, image_blocks)) {
      break;
    }
    AsfPacketSummary current;
    if (!asf_parse_packet(packet, layout->packet_size, layout->packet_size,
                          &current)
        || (current.stream_mask_low & ~layout->stream_mask_low) != 0
        || (current.stream_mask_high & ~layout->stream_mask_high) != 0) {
      break;
    }
    if (have_previous) {
      if (current.send_time < previous.send_time) {
        break;
      }
      uint64_t expected = (uint64_t)previous.send_time + previous.duration;
      uint64_t observed = current.send_time;
      uint64_t difference = observed > expected
          ? observed - expected : expected - observed;
      if (UINT64_MAX - score->time_cost < difference) {
        score->time_cost = UINT64_MAX;
      }
      else {
        score->time_cost += difference;
      }
      score->time_pairs++;

      if (previous.sequence_code != 0
          && previous.sequence_code == current.sequence_code) {
        uint64_t modulus = previous.sequence_code == 1
            ? UINT64_C(1) << 8
            : previous.sequence_code == 2
                ? UINT64_C(1) << 16 : UINT64_C(1) << 32;
        uint64_t sequence_difference =
            ((uint64_t)current.sequence + modulus
             - (uint64_t)previous.sequence) % modulus;
        uint64_t sequence_cost = sequence_difference > 0
            ? sequence_difference - 1 : 1;
        if (UINT64_MAX - score->sequence_cost < sequence_cost) {
          score->sequence_cost = UINT64_MAX;
        }
        else {
          score->sequence_cost += sequence_cost;
        }
        score->sequence_pairs++;
      }

      if (previous.media_object_code != 0
          && previous.media_object_code == current.media_object_code) {
        uint64_t modulus = previous.media_object_code == 1
            ? UINT64_C(1) << 8
            : previous.media_object_code == 2
                ? UINT64_C(1) << 16 : UINT64_C(1) << 32;
        for (uint32_t stream = 1; stream < 128; stream++) {
          if (previous.stream_seen[stream] == 0
              || current.stream_seen[stream] == 0) {
            continue;
          }
          uint64_t object_difference =
              ((uint64_t)current.first_media_object[stream] + modulus
               - (uint64_t)previous.last_media_object[stream]) % modulus;
          if (object_difference > modulus / 2) {
            return false;
          }
          uint64_t object_cost = object_difference > 1
              ? object_difference - 1 : 0;
          if (UINT64_MAX - score->object_cost < object_cost) {
            score->object_cost = UINT64_MAX;
          }
          else {
            score->object_cost += object_cost;
          }
          score->object_pairs++;
        }
      }
    }
    previous = current;
    have_previous = true;
    score->packets++;
  }
  return score->packets > 0;
}

static inline bool asf_reassembly_better_anchor(
    const AsfCarveState *state, const AsfAnchorScore *score,
    BlockValidationDecision confidence, int64_t reservations,
    uint64_t distance, uint32_t prefix_zeros) {
  if (!state || !score || score->packets == 0) {
    return false;
  }
  if (state->best_actual < 0 || prefix_zeros != state->best_prefix_zeros) {
    return state->best_actual < 0 || prefix_zeros < state->best_prefix_zeros;
  }
  if ((score->time_pairs > 0) != (state->best_time_pairs > 0)) {
    return score->time_pairs > 0;
  }
  if (score->time_cost != state->best_time_cost) {
    return score->time_cost < state->best_time_cost;
  }
  if ((score->object_pairs > 0) != (state->best_object_pairs > 0)) {
    return score->object_pairs > 0;
  }
  if (score->object_cost != state->best_object_cost) {
    return score->object_cost < state->best_object_cost;
  }
  if ((score->sequence_pairs > 0) != (state->best_sequence_pairs > 0)) {
    return score->sequence_pairs > 0;
  }
  if (score->sequence_cost != state->best_sequence_cost) {
    return score->sequence_cost < state->best_sequence_cost;
  }
  if (score->object_pairs != state->best_object_pairs) {
    return score->object_pairs > state->best_object_pairs;
  }
  if (score->sequence_pairs != state->best_sequence_pairs) {
    return score->sequence_pairs > state->best_sequence_pairs;
  }
  if (score->time_pairs != state->best_time_pairs) {
    return score->time_pairs > state->best_time_pairs;
  }
  if (score->packets != state->best_anchor_packets) {
    return score->packets > state->best_anchor_packets;
  }
  if ((uint32_t)confidence != state->best_confidence) {
    return (uint32_t)confidence > state->best_confidence;
  }
  if (reservations != state->best_reservations) {
    return reservations < state->best_reservations;
  }
  if (distance != state->best_distance) {
    return distance < state->best_distance;
  }
  return false;
}

static inline bool asf_reassembly_checkpoint(
    ThreadWork *work, CarveInfo **candidate, AsfCarveState *state,
    uuid_string_t uuidp, uuid_string_t uuidc) {
  if (!work || !candidate || !*candidate || !state) {
    return true;
  }
  if (reassembly_check_kill_queue(work, candidate, uuidp, uuidc)) {
    return true;
  }
  if (atomic_load_explicit(&REASS_RETURN_TO_IDLE, memory_order_acquire)) {
    carve_put_state((*candidate)->carvehashkey, state);
    if (reassembly_time_to_checkpoint(work->id, *candidate, uuidp, uuidc)) {
      return true;
    }
  }
  return false;
}

// A speculative preferred trial owns a separate vector; rejecting it must
// restore both the original mapping and its validated-prefix bookkeeping.
static inline void asf_reassembly_rollback_trial(CarveInfo *candidate,
    BlockVector **original, uint64_t original_validates_to) {
  if (candidate && original && *original) {
    free_blockvector(&candidate->b);
    candidate->b = *original;
    *original = NULL;
    candidate->best_validates_to = original_validates_to;
  }
}

// Queue the durable parent. The preferred-search descriptor recreates its
// temporary trial after restore; a declined checkpoint leaves the trial live.
static inline bool asf_reassembly_checkpoint_trial(
    ThreadWork *work, CarveInfo **candidate, AsfCarveState *state,
    uuid_string_t uuidp, uuid_string_t uuidc, BlockVector **original,
    uint64_t original_validates_to) {
  if (!original || !*original) {
    return asf_reassembly_checkpoint(work, candidate, state, uuidp, uuidc);
  }
  if (!candidate || !*candidate) {
    free_blockvector(original);
    return true;
  }
  BlockVector *trial = (*candidate)->b;
  const uint64_t trial_validates_to = (*candidate)->best_validates_to;
  (*candidate)->b = *original;
  (*candidate)->best_validates_to = original_validates_to;
  if (asf_reassembly_checkpoint(work, candidate, state, uuidp, uuidc)) {
    *original = NULL;
    free_blockvector(&trial);
    return true;
  }
  (*candidate)->b = trial;
  (*candidate)->best_validates_to = trial_validates_to;
  return false;
}

static inline bool asf_reassembly_extend_prefix(CarveInfo *candidate,
                                                uint64_t target_slot,
                                                uint64_t image_blocks) {
  if (!candidate || !candidate->b || target_slot == 0) {
    return false;
  }
  uint64_t blocks = blockvector_get_num_blocks(candidate->b);
  if (blocks == 0 || blocks > target_slot) {
    return false;
  }
  while (blocks < target_slot) {
    int64_t previous = blockvector_get_actual_blocknumber(candidate->b,
                                                          blocks - 1);
    if (previous < 0 || previous == INT64_MAX
        || (uint64_t)(previous + 1) >= image_blocks
        || filemirror_actual_block_covered(scalpel_state.filemirror,
                                           previous + 1)) {
      return false;
    }
    int64_t apparent = filemirror_apparent_blocknumber(
        scalpel_state.filemirror, previous + 1);
    if (apparent < 0
        || apparent_block_in_blockvector(candidate->b, apparent)) {
      return false;
    }
    resize_blockvector(candidate->b, blocks + 1);
    blockvector_set_apparent_blocknumber(candidate->b, blocks, apparent);
    blocks++;
  }
  blockvector_set_data_length_to_mapped_extent(candidate->b);
  inflate_blockvector(candidate->b);
  return true;
}

static inline bool asf_reassembly_apply_run(
    CarveInfo *candidate, const AsfLayout *layout, uint64_t target_slot,
    int64_t source_actual, uint64_t image_blocks, bool stop_at_zero) {
  if (!candidate || !candidate->b || !layout || scalpel_state.blocksize == 0
      || source_actual < 0 || target_slot == 0) {
    return false;
  }
  uint64_t total_blocks = CEILDIV(layout->file_size,
                                  scalpel_state.blocksize);
  if (target_slot >= total_blocks) {
    return false;
  }
  uint64_t run_blocks = 0;
  uint64_t maximum = total_blocks - target_slot;
  while (run_blocks < maximum) {
    if (run_blocks > (uint64_t)INT64_MAX
        || source_actual > INT64_MAX - (int64_t)run_blocks) {
      break;
    }
    int64_t actual = source_actual + (int64_t)run_blocks;
    if (actual < 0 || (uint64_t)actual >= image_blocks
        || filemirror_actual_block_covered(scalpel_state.filemirror, actual)) {
      break;
    }
    if (stop_at_zero
        && filemirror_actual_block_is_zero(scalpel_state.filemirror,
                                           actual)) {
      break;
    }
    int64_t apparent = filemirror_apparent_blocknumber(
        scalpel_state.filemirror, actual);
    if (apparent < 0
        || apparent_block_in_blockvector(candidate->b, apparent)) {
      break;
    }
    run_blocks++;
  }
  if (run_blocks == 0) {
    return false;
  }

  resize_blockvector(candidate->b, target_slot + run_blocks);
  for (uint64_t index = 0; index < run_blocks; index++) {
    int64_t actual = source_actual + (int64_t)index;
    int64_t apparent = filemirror_apparent_blocknumber(
        scalpel_state.filemirror, actual);
    blockvector_set_apparent_blocknumber(candidate->b, target_slot + index,
                                         apparent);
  }
  uint64_t mapped_length = (target_slot + run_blocks)
      * (uint64_t)scalpel_state.blocksize;
  blockvector_set_data_length(candidate->b,
                              mapped_length < layout->file_size
                                  ? mapped_length : layout->file_size);
  inflate_blockvector(candidate->b);
  return true;
}

static inline bool asf_reassembly_apply_splice(
    CarveInfo *candidate, const AsfLayout *layout, uint64_t target_slot,
    uint64_t end_slot, int64_t source_actual, int64_t suffix_actual,
    uint64_t image_blocks) {
  if (!candidate || !candidate->b || !layout || target_slot == 0
      || end_slot <= target_slot || source_actual < 0 || suffix_actual < 0
      || scalpel_state.blocksize == 0) {
    return false;
  }
  uint64_t total_blocks = CEILDIV(layout->file_size,
                                  scalpel_state.blocksize);
  if (end_slot > total_blocks) {
    return false;
  }
  uint64_t source_blocks = end_slot - target_slot;
  for (uint64_t index = 0; index < source_blocks; index++) {
    if (index > (uint64_t)INT64_MAX
        || source_actual > INT64_MAX - (int64_t)index) {
      return false;
    }
    int64_t actual = source_actual + (int64_t)index;
    if (actual < 0 || (uint64_t)actual >= image_blocks
        || filemirror_actual_block_covered(scalpel_state.filemirror, actual)) {
      return false;
    }
    int64_t apparent = filemirror_apparent_blocknumber(
        scalpel_state.filemirror, actual);
    if (apparent < 0
        || asf_reassembly_apparent_in_prefix(candidate->b, apparent,
                                             target_slot)) {
      return false;
    }
  }

  resize_blockvector(candidate->b, end_slot);
  for (uint64_t index = 0; index < source_blocks; index++) {
    int64_t actual = source_actual + (int64_t)index;
    int64_t apparent = filemirror_apparent_blocknumber(
        scalpel_state.filemirror, actual);
    blockvector_set_apparent_blocknumber(candidate->b, target_slot + index,
                                         apparent);
  }
  uint64_t mapped_length = end_slot * (uint64_t)scalpel_state.blocksize;
  blockvector_set_data_length(candidate->b,
                              mapped_length < layout->file_size
                                  ? mapped_length : layout->file_size);
  inflate_blockvector(candidate->b);
  if (end_slot == total_blocks) {
    return true;
  }
  return asf_reassembly_apply_run(candidate, layout, end_slot, suffix_actual,
                                  image_blocks, false);
}

static inline bool asf_candidate_contiguous(const CarveInfo *candidate) {
  if (!candidate || !candidate->b) {
    return false;
  }
  uint64_t blocks = blockvector_get_num_blocks(candidate->b);
  if (blocks == 0) {
    return false;
  }
  int64_t previous = blockvector_get_actual_blocknumber(candidate->b, 0);
  if (previous < 0) {
    return false;
  }
  for (uint64_t slot = 1; slot < blocks; slot++) {
    int64_t actual = blockvector_get_actual_blocknumber(candidate->b, slot);
    if (actual < 0 || previous == INT64_MAX || actual != previous + 1) {
      return false;
    }
    previous = actual;
  }
  return true;
}

static inline void asf_assign_subtype(CarveInfo *candidate,
                                      const AsfLayout *layout) {
  if (!candidate || !layout || !layout->saw_windows_media_video) {
    return;
  }
  int32_t index = asf_filetype_index("wmv");
  if (index >= 0) {
    candidate->needleidx = index;
    candidate->filetype = scalpel_state.search_specs[index].FILETYPE;
  }
}

static inline void asf_file_validate(char *data, uint64_t length,
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
  AsfLayout layout;
  AsfParseResult result = asf_parse_file((const uint8_t *)data, length,
                                         &layout);
  if (!layout.header_valid) {
    return;
  }
  uint64_t extent = layout.parsed_extent;
  if (layout.failure_offset != UINT64_MAX
      && layout.failure_offset > extent) {
    extent = layout.failure_offset;
  }
  if (extent == 0) {
    extent = length < 16 ? length : 16;
  }
  if (extent > length) {
    extent = length;
  }
  *validates_to = extent > 0 ? extent - 1 : 0;
  *promising = layout.file_properties_valid;
  if (result == ASF_PARSE_COMPLETE && layout.exact_extent_valid
      && layout.data_object_valid && layout.packet_geometry_fixed
      && layout.packets_valid && layout.packet_count > 0
      && layout.packets_parsed == layout.packet_count
      && layout.file_size <= length) {
    *validates = true;
    *promising = false;
    *validates_to = layout.file_size - 1;
  }
}

static inline bool asf_expand_contiguous_candidate(CarveInfo *candidate,
                                                   uint64_t required_extent) {
  if (!candidate || !candidate->b || candidate->flavor != NO_FLAVOR
      || scalpel_state.blocksize == 0 || required_extent == 0
      || required_extent > ASF_MAXIMUM_SIZE) {
    return false;
  }
  uint64_t current_blocks = blockvector_get_num_blocks(candidate->b);
  uint64_t required_blocks = CEILDIV(required_extent,
                                     scalpel_state.blocksize);
  if (current_blocks == 0 || required_blocks <= current_blocks) {
    return false;
  }
  int64_t first_apparent = blockvector_get_apparent_blocknumber(
      candidate->b, 0);
  uint64_t apparent_blocks = filemirror_apparent_blocks(
      scalpel_state.filemirror);
  if (first_apparent < 0 || (uint64_t)first_apparent >= apparent_blocks
      || required_blocks > apparent_blocks - (uint64_t)first_apparent
      || required_blocks - 1
             > (uint64_t)(INT64_MAX - first_apparent)) {
    return false;
  }
  for (uint64_t index = 0; index < current_blocks; index++) {
    if (blockvector_get_apparent_blocknumber(candidate->b, index)
        != first_apparent + (int64_t)index) {
      return false;
    }
  }
  resize_blockvector(candidate->b, required_blocks);
  for (uint64_t index = current_blocks; index < required_blocks; index++) {
    blockvector_set_apparent_blocknumber(
        candidate->b, index, first_apparent + (int64_t)index);
  }
  blockvector_set_data_length(candidate->b, required_extent);
  inflate_blockvector(candidate->b);
  return blockvector_get_data_length(candidate->b) >= required_extent;
}

static inline void asf_candidate_validate(CarveInfo *candidate,
                                          bool *validates,
                                          uint64_t *validates_to,
                                          bool *promising) {
  if (!candidate || !candidate->b || !validates || !validates_to
      || !promising || candidate->needleidx < 0
      || (uint32_t)candidate->needleidx >= scalpel_state.num_specs) {
    return;
  }
  uint64_t length = blockvector_get_non_peekahead_data_length(candidate->b);
  uint64_t available = blockvector_get_data_length(candidate->b);
  if (length == 0 || length > available) {
    length = available;
  }
  SearchSpec *spec = &scalpel_state.search_specs[candidate->needleidx];
  AsfLayout layout;
  AsfParseResult result = asf_parse_file(
      (const uint8_t *)blockvector_get_data_pointer(candidate->b), length,
      &layout);

  if (candidate->flavor == NO_FLAVOR && layout.file_properties_valid
      && layout.file_size > length
      && asf_expand_contiguous_candidate(candidate, layout.file_size)) {
    length = blockvector_get_non_peekahead_data_length(candidate->b);
    if (length == 0
        || length > blockvector_get_data_length(candidate->b)) {
      length = blockvector_get_data_length(candidate->b);
    }
    spec->FILEVALIDATOR(blockvector_get_data_pointer(candidate->b), length,
                        validates, validates_to, promising,
                        (uint32_t)candidate->needleidx,
                        scalpel_state.blocksize, candidate->carvehashkey);
    result = asf_parse_file(
        (const uint8_t *)blockvector_get_data_pointer(candidate->b), length,
        &layout);
  }

  if (result == ASF_PARSE_COMPLETE && layout.saw_windows_media_video) {
    for (uint32_t index = 0; index < scalpel_state.num_specs; index++) {
      if (strcmp(scalpel_state.search_specs[index].FILETYPE, "wmv") == 0) {
        candidate->needleidx = (int32_t)index;
        candidate->filetype = scalpel_state.search_specs[index].FILETYPE;
        break;
      }
    }
  }

  if (*validates && result == ASF_PARSE_COMPLETE) {
    uint64_t blocks = blockvector_get_num_blocks(candidate->b);
    bool contiguous = blocks > 0;
    int64_t previous = contiguous
        ? blockvector_get_actual_blocknumber(candidate->b, 0) : -1;
    if (previous < 0) {
      contiguous = false;
    }
    for (uint64_t slot = 1; contiguous && slot < blocks; slot++) {
      int64_t actual = blockvector_get_actual_blocknumber(candidate->b, slot);
      if (actual < 0 || previous == INT64_MAX || actual != previous + 1) {
        contiguous = false;
      }
      previous = actual;
    }
    if (!contiguous) {
      *validates = false;
      *promising = true;
    }
  }
}

static inline void asf_reassembly(ThreadWork *work, CarveInfo **candidate,
                                  uuid_string_t uuidp,
                                  uuid_string_t uuidc) {
  if (!work || !candidate || !*candidate || !(*candidate)->b
      || scalpel_state.blocksize == 0) {
    if (candidate && *candidate) {
      destroy_candidate(candidate);
    }
    return;
  }

  AsfCarveState *state = (AsfCarveState *)carve_get_state(
      (*candidate)->carvehashkey);
  if (!asf_carve_state_valid(state)) {
    asf_free_carve_state((void **)&state);
    state = (AsfCarveState *)calloc(1, sizeof(*state));
    check_memory_allocation(state, __LINE__, __FILE__, "AsfCarveState");
    asf_reassembly_reset_search(state, 0, 0);
  }

  int32_t asf_index = asf_filetype_index("asf");
  int32_t wmv_index = asf_filetype_index("wmv");
  uint64_t image_blocks = CEILDIV(
      filemirror_filesize(scalpel_state.filemirror), scalpel_state.blocksize);
  (*candidate)->chopped = false;

  while (*candidate) {
    BlockVector *blockvector = (*candidate)->b;
    inflate_blockvector(blockvector);
    uint64_t blocks = blockvector_get_num_blocks(blockvector);
    if (blocks == 0
        || blockvector_get_actual_blocknumber(blockvector, 0) < 0) {
      asf_free_carve_state((void **)&state);
      destroy_candidate(candidate);
      return;
    }

    for (uint64_t slot = 1; slot < blocks; slot++) {
      if (blockvector_get_actual_blocknumber(blockvector, slot) < 0) {
        resize_blockvector(blockvector, slot);
        inflate_blockvector(blockvector);
        blocks = slot;
        break;
      }
    }

    const uint8_t *data = (const uint8_t *)blockvector_get_data_pointer(
        blockvector);
    uint64_t length = blockvector_get_data_length(blockvector);
    AsfLayout layout;
    AsfParseResult result = asf_parse_file(data, length, &layout);

    if (result == ASF_PARSE_COMPLETE && layout.exact_extent_valid
        && layout.data_object_valid && layout.packet_geometry_fixed
        && layout.packets_valid && layout.packet_count > 0
        && layout.packets_parsed == layout.packet_count) {
      resize_blockvector(blockvector,
                         CEILDIV(layout.file_size, scalpel_state.blocksize));
      inflate_blockvector(blockvector);
      blockvector_set_data_length(blockvector, layout.file_size);
      asf_assign_subtype(*candidate, &layout);
      bool contiguous = asf_candidate_contiguous(*candidate);
      asf_free_carve_state((void **)&state);
      if (contiguous) {
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

    if (!layout.header_valid || !layout.file_properties_valid
        || !layout.data_object_valid || !layout.packet_geometry_fixed
        || layout.packet_size == 0 || layout.packet_count == 0
        || layout.file_size == 0) {
      break;
    }

    uint64_t total_file_blocks = CEILDIV(layout.file_size,
                                         scalpel_state.blocksize);
    if (total_file_blocks <= 1) {
      break;
    }

    if (state->scan_active == 0) {
      if (layout.packets_parsed
              > (UINT64_MAX - layout.packet_data_offset) / layout.packet_size) {
        break;
      }
      uint64_t failure_packet_offset = layout.packet_data_offset
          + layout.packets_parsed * (uint64_t)layout.packet_size;
      if (failure_packet_offset > UINT64_MAX - layout.packet_size) {
        break;
      }
      uint64_t failure_packet_end = failure_packet_offset
          + layout.packet_size;
      uint64_t first_offset = layout.packets_parsed > 0
          ? failure_packet_offset - layout.packet_size
          : layout.packet_data_offset;
      uint64_t failure_first_target = first_offset / scalpel_state.blocksize;
      uint64_t failure_last_target = CEILDIV(failure_packet_end,
                                             scalpel_state.blocksize);
      bool clean_truncation = result == ASF_PARSE_PARTIAL
          && layout.failure_offset == UINT64_MAX
          && layout.required_extent > length;

      uint64_t zero_first_target = failure_first_target;
      uint64_t zero_last_target = failure_last_target;
      uint64_t latest_zero_target = UINT64_MAX;
      int64_t latest_zero_actual = -1;
      if (zero_first_target == 0) {
        zero_first_target = 1;
      }
      if (blocks > 0 && zero_last_target >= blocks) {
        zero_last_target = blocks - 1;
      }
      if (zero_last_target >= total_file_blocks) {
        zero_last_target = total_file_blocks - 1;
      }
      if (zero_first_target <= zero_last_target) {
        for (uint64_t slot = zero_last_target;; slot--) {
          int64_t actual = blockvector_get_actual_blocknumber(blockvector,
                                                               slot);
          if (actual >= 0
              && filemirror_actual_block_is_zero(scalpel_state.filemirror,
                                                  actual)) {
            latest_zero_target = slot;
            latest_zero_actual = actual;
            break;
          }
          if (slot == zero_first_target) {
            break;
          }
        }
      }

      uint64_t first_target = clean_truncation
          ? blocks : failure_first_target;
      uint64_t last_target = clean_truncation
          ? blocks : failure_last_target;
      if (clean_truncation && latest_zero_target != UINT64_MAX
          && latest_zero_target < first_target) {
        first_target = latest_zero_target;
      }
      if (first_target == 0) {
        first_target = 1;
      }
      if (last_target > blocks) {
        last_target = blocks;
      }
      if (last_target >= total_file_blocks) {
        last_target = total_file_blocks - 1;
      }
      if (first_target > last_target) {
        first_target = last_target;
      }
      uint64_t signature = asf_reassembly_signature(&layout, first_target);
      asf_reassembly_reset_search(state, signature, first_target);
      state->last_target_slot = last_target;
      state->target_slot = last_target;
      state->baseline_progress = layout.parsed_extent;

      uint64_t hole_target = UINT64_MAX;
      uint64_t hole_end = UINT64_MAX;
      int64_t hole_suffix = -1;
      uint64_t hole_search_first = failure_first_target > 0
          ? failure_first_target : 1;
      uint64_t hole_search_last = blocks;
      if (failure_last_target < UINT64_MAX
          && hole_search_last > failure_last_target + 1) {
        hole_search_last = failure_last_target + 1;
      }
      if (hole_search_last > blocks) {
        hole_search_last = blocks;
      }
      if (hole_search_last > total_file_blocks) {
        hole_search_last = total_file_blocks;
      }
      if (hole_search_first <= hole_search_last) {
        for (uint64_t slot = hole_search_last;; slot--) {
          uint64_t run_slot = slot;
          while (run_slot > hole_search_first) {
            int64_t mapped_before = blockvector_get_actual_blocknumber(
                blockvector, run_slot - 1);
            if (mapped_before < 0
                || !filemirror_actual_block_is_zero(
                    scalpel_state.filemirror, mapped_before)) {
              break;
            }
            run_slot--;
          }
          int64_t previous_actual = blockvector_get_actual_blocknumber(
              blockvector, run_slot - 1);
          if (previous_actual >= 0 && previous_actual < INT64_MAX
              && (uint64_t)(previous_actual + 1) < image_blocks
              && filemirror_actual_block_is_zero(
                  scalpel_state.filemirror, previous_actual + 1)) {
            int64_t suffix = previous_actual + 1;
            uint64_t hole_blocks = 0;
            while ((uint64_t)suffix < image_blocks
                   && filemirror_actual_block_is_zero(
                       scalpel_state.filemirror, suffix)) {
              if (suffix == INT64_MAX || hole_blocks == UINT64_MAX) {
                break;
              }
              suffix++;
              hole_blocks++;
            }
            if (hole_blocks > 0 && (uint64_t)suffix < image_blocks
                && hole_blocks <= total_file_blocks - run_slot) {
              hole_target = run_slot;
              hole_end = run_slot + hole_blocks;
              hole_suffix = suffix;
              break;
            }
          }
          if (slot == hole_search_first) {
            break;
          }
        }
      }
      if (hole_target != UINT64_MAX && hole_suffix >= 0) {
        asf_reassembly_add_hole_splice(state, hole_target, hole_end,
                                       hole_suffix);
        asf_reassembly_add_preferred(state, hole_target, hole_suffix,
                                     ASF_PREFERRED_ANCHOR);
      }

      if (latest_zero_target != UINT64_MAX
          && latest_zero_actual >= 0 && latest_zero_actual < INT64_MAX) {
        int64_t source_actual = latest_zero_actual + 1;
        if ((uint64_t)source_actual < image_blocks) {
          asf_reassembly_add_preferred(state, latest_zero_target,
                                       source_actual,
                                       ASF_PREFERRED_ANCHOR);
          while ((uint64_t)source_actual < image_blocks
                 && filemirror_actual_block_is_zero(
                     scalpel_state.filemirror, source_actual)) {
            if (source_actual == INT64_MAX) {
              break;
            }
            source_actual++;
          }
          if ((uint64_t)source_actual < image_blocks) {
            asf_reassembly_add_preferred(state, latest_zero_target,
                                         source_actual,
                                         ASF_PREFERRED_ANCHOR);
          }
        }
      }

      bool packet_boundary_truncation = clean_truncation
          && layout.parsed_extent == length
          && (latest_zero_target == UINT64_MAX
              || latest_zero_target == blocks - 1);
      if (clean_truncation && blocks > 0) {
        int64_t previous_actual = blockvector_get_actual_blocknumber(
            blockvector, blocks - 1);
        if (previous_actual >= 0 && previous_actual < INT64_MAX
            && (uint64_t)(previous_actual + 1) < image_blocks) {
          int64_t source_actual = previous_actual + 1;
          bool source_is_zero = filemirror_actual_block_is_zero(
              scalpel_state.filemirror, source_actual);
          asf_reassembly_add_preferred(
              state, blocks, source_actual,
              packet_boundary_truncation && !source_is_zero
                  ? ASF_PREFERRED_CONTIGUOUS_PREFIX
                  : ASF_PREFERRED_ANCHOR);
          if (source_is_zero) {
            while ((uint64_t)source_actual < image_blocks
                   && filemirror_actual_block_is_zero(
                       scalpel_state.filemirror, source_actual)) {
              if (source_actual == INT64_MAX) {
                break;
              }
              source_actual++;
            }
            if ((uint64_t)source_actual < image_blocks) {
              asf_reassembly_add_preferred(state, blocks, source_actual,
                                           ASF_PREFERRED_ANCHOR);
            }
          }
        }
      }
      if (state->preferred_count > 0) {
        state->preferred_index = 0;
        state->target_slot = state->preferred_target_slots[0];
        if (state->preferred_modes[0] == ASF_PREFERRED_HOLE_SPLICE) {
          state->next_actual = 0;
        }
        else {
          state->next_actual = (uint64_t)state->preferred_source_actuals[0];
        }
      }
    }

    BlockVector *preferred_original = NULL;
    uint64_t original_validates_to = (*candidate)->best_validates_to;
    while (*candidate
           && ((asf_reassembly_preferred_active(state)
                && state->target_slot
                       == state->preferred_target_slots[
                           state->preferred_index])
               || (state->target_slot >= state->first_target_slot
                   && state->target_slot <= state->last_target_slot))) {
      uint64_t target_slot = state->target_slot;
      blockvector = (*candidate)->b;
      blocks = blockvector_get_num_blocks(blockvector);
      bool preferred_trial = asf_reassembly_preferred_active(state);
      uint32_t preferred_mode = preferred_trial
          ? state->preferred_modes[state->preferred_index]
          : ASF_PREFERRED_ANCHOR;
      bool hole_splice_scan = preferred_trial
          && preferred_mode == ASF_PREFERRED_HOLE_SPLICE;
      if (preferred_trial && !hole_splice_scan) {
        if (asf_reassembly_checkpoint(work, candidate, state, uuidp, uuidc)) {
          asf_free_carve_state((void **)&state);
          return;
        }
        BlockVector *trial = NULL;
        clone_blockvector(blockvector, &trial, true);
        preferred_original = blockvector;
        original_validates_to = (*candidate)->best_validates_to;
        (*candidate)->b = trial;
        blockvector = trial;
        blocks = blockvector_get_num_blocks(blockvector);
      }
      if (!hole_splice_scan && target_slot < blocks) {
        resize_blockvector(blockvector, target_slot);
        inflate_blockvector(blockvector);
        blocks = target_slot;
      }
      else if (!hole_splice_scan && target_slot > blocks) {
        if (!asf_reassembly_extend_prefix(*candidate, target_slot,
                                          image_blocks)) {
          asf_reassembly_rollback_trial(*candidate, &preferred_original,
                                         original_validates_to);
          if (!asf_reassembly_advance_target(state)) {
            break;
          }
          continue;
        }
        blockvector = (*candidate)->b;
        blocks = target_slot;
      }

      uint64_t prefix_length = hole_splice_scan
          ? target_slot * (uint64_t)scalpel_state.blocksize
          : blockvector_get_data_length(blockvector);
      if (prefix_length > blockvector_get_data_length(blockvector)) {
        prefix_length = blockvector_get_data_length(blockvector);
      }
      if (!hole_splice_scan) {
        (*candidate)->best_validates_to = prefix_length > 0
            ? prefix_length - 1 : 0;
      }
      AsfLayout prefix_layout;
      AsfParseResult prefix_result = asf_parse_file(
          (const uint8_t *)blockvector_get_data_pointer(blockvector),
          prefix_length, &prefix_layout);
      if (prefix_result == ASF_PARSE_INVALID
          || !prefix_layout.file_properties_valid
          || !prefix_layout.data_object_valid
          || !prefix_layout.packet_geometry_fixed
          || prefix_layout.packet_size == 0
          || prefix_layout.packets_parsed >= prefix_layout.packet_count) {
        asf_reassembly_rollback_trial(*candidate, &preferred_original,
                                       original_validates_to);
        if (!asf_reassembly_advance_target(state)) {
          break;
        }
        continue;
      }

      uint32_t prefix_zeros = 0;
      for (uint64_t slot = state->first_target_slot;
           slot < target_slot; slot++) {
        int64_t actual = blockvector_get_actual_blocknumber(blockvector, slot);
        if (actual >= 0
            && filemirror_actual_block_is_zero(scalpel_state.filemirror,
                                               actual)) {
          prefix_zeros++;
        }
      }

      uint8_t *packet = (uint8_t *)malloc(prefix_layout.packet_size);
      check_memory_allocation(packet, __LINE__, __FILE__, "ASF packet");
      int64_t previous_actual = blockvector_get_actual_blocknumber(
          blockvector, target_slot - 1);

      if (!preferred_trial
          && asf_reassembly_checkpoint(work, candidate, state, uuidp, uuidc)) {
        free(packet);
        asf_free_carve_state((void **)&state);
        return;
      }

      uint64_t scan_end = image_blocks;
      bool contiguous_prefix_scan = false;
      bool preferred_anchor_scan = false;
      if (asf_reassembly_preferred_active(state)) {
        if (hole_splice_scan) {
          scan_end = image_blocks;
        }
        else {
          int64_t preferred_source = state->preferred_source_actuals[
              state->preferred_index];
          contiguous_prefix_scan = preferred_mode
              == ASF_PREFERRED_CONTIGUOUS_PREFIX;
          preferred_anchor_scan = preferred_mode == ASF_PREFERRED_ANCHOR;
          if (preferred_source < 0
              || (uint64_t)preferred_source >= image_blocks) {
            scan_end = state->next_actual;
          }
          else {
            uint64_t source = (uint64_t)preferred_source;
            if (state->next_actual < source) {
              state->next_actual = source;
            }
            scan_end = source + 1;
          }
        }
      }
      // Checkpoint pruning can make a saved winner unusable. Its score must
      // not suppress still-available alternatives from earlier in this scan.
      if (state->best_actual >= 0) {
        int64_t best_apparent = (uint64_t)state->best_actual < image_blocks
            ? filemirror_apparent_blocknumber(
                scalpel_state.filemirror, state->best_actual) : -1;
        bool available = (uint64_t)state->best_actual < image_blocks
            && !filemirror_actual_block_covered(
                scalpel_state.filemirror, state->best_actual)
            && best_apparent >= 0
            && !(hole_splice_scan
                ? asf_reassembly_apparent_in_prefix(
                    blockvector, best_apparent, target_slot)
                : apparent_block_in_blockvector(blockvector, best_apparent));
        if (available && contiguous_prefix_scan) {
          available = !filemirror_actual_block_is_zero(
              scalpel_state.filemirror, state->best_actual);
        }
        else if (available) {
          AsfAnchorScore score;
          available = asf_reassembly_score_anchor(
              *candidate, &prefix_layout, target_slot, state->best_actual,
              hole_splice_scan
                  ? state->preferred_end_slots[state->preferred_index] - target_slot
                  : UINT64_MAX,
              hole_splice_scan
                  ? state->preferred_suffix_actuals[state->preferred_index] : -1,
              prefix_length, packet, image_blocks, &score)
              && score.packets == state->best_anchor_packets
              && score.time_cost == state->best_time_cost
              && score.object_cost == state->best_object_cost
              && score.sequence_cost == state->best_sequence_cost
              && score.object_pairs == state->best_object_pairs
              && score.sequence_pairs == state->best_sequence_pairs
              && score.time_pairs == state->best_time_pairs;
        }
        if (!available) {
          asf_reassembly_clear_best(state);
          state->next_actual = preferred_trial && !hole_splice_scan
              ? (uint64_t)state->preferred_source_actuals[state->preferred_index]
              : 0;
        }
      }
      for (uint64_t actual_index = state->next_actual;
           actual_index < scan_end && *candidate; actual_index++) {
        state->next_actual = actual_index + 1;
        if (actual_index > (uint64_t)INT64_MAX) {
          break;
        }
        int64_t actual = (int64_t)actual_index;
        if (filemirror_actual_block_covered(scalpel_state.filemirror, actual)) {
          continue;
        }
        int64_t apparent = filemirror_apparent_blocknumber(
            scalpel_state.filemirror, actual);
        bool already_retained = hole_splice_scan
            ? asf_reassembly_apparent_in_prefix(blockvector, apparent,
                                                target_slot)
            : apparent_block_in_blockvector(blockvector, apparent);
        if (apparent < 0 || already_retained) {
          continue;
        }

        AsfAnchorScore score;
        memset(&score, 0, sizeof(score));
        bool scored = false;
        if (contiguous_prefix_scan) {
          score.packets = 1;
          scored = !filemirror_actual_block_is_zero(
              scalpel_state.filemirror, actual);
        }
        else {
          uint64_t source_blocks = hole_splice_scan
              ? state->preferred_end_slots[state->preferred_index]
                    - target_slot
              : UINT64_MAX;
          int64_t suffix_actual = hole_splice_scan
              ? state->preferred_suffix_actuals[state->preferred_index]
              : -1;
          scored = asf_reassembly_score_anchor(
              *candidate, &prefix_layout, target_slot, actual, source_blocks,
              suffix_actual, prefix_length, packet, image_blocks, &score);
        }
        if (scored) {
          uint64_t remaining_packets = prefix_layout.packet_count
              - prefix_layout.packets_parsed;
          uint32_t required_anchors = remaining_packets
                  < ASF_REPAIR_ANCHOR_PACKETS
              ? (uint32_t)remaining_packets : ASF_REPAIR_ANCHOR_PACKETS;
          if (hole_splice_scan && score.packets < required_anchors) {
            continue;
          }
          if (preferred_anchor_scan
              && (score.object_cost != 0 || score.sequence_cost != 0)) {
            continue;
          }
          uint64_t projected_packets = prefix_layout.packets_parsed;
          if (UINT64_MAX - projected_packets < score.packets) {
            projected_packets = UINT64_MAX;
          }
          else {
            projected_packets += score.packets;
          }
          uint64_t projected_progress = prefix_layout.file_size;
          if (projected_packets < prefix_layout.packet_count) {
            if (projected_packets
                    > (UINT64_MAX - prefix_layout.packet_data_offset)
                        / prefix_layout.packet_size) {
              projected_progress = UINT64_MAX;
            }
            else {
              projected_progress = prefix_layout.packet_data_offset
                  + projected_packets * (uint64_t)prefix_layout.packet_size;
            }
          }
          if (!contiguous_prefix_scan
              && projected_progress <= state->baseline_progress) {
            continue;
          }
          state->matches++;
          BlockValidationDecision confidence = asf_reassembly_confidence(
              actual, asf_index, wmv_index);
          int64_t reservations = scalpel_state.reservations
              ? filemirror_actual_block_reserved(scalpel_state.filemirror,
                                                 actual) : 0;
          uint64_t distance = previous_actual >= 0
              ? (actual >= previous_actual
                     ? (uint64_t)(actual - previous_actual)
                     : (uint64_t)(previous_actual - actual))
              : UINT64_MAX;
          if (asf_reassembly_better_anchor(
                  state, &score, confidence, reservations, distance,
                  prefix_zeros)) {
            state->best_target_slot = target_slot;
            state->best_actual = actual;
            state->best_anchor_packets = score.packets;
            state->best_time_cost = score.time_cost;
            state->best_object_cost = score.object_cost;
            state->best_sequence_cost = score.sequence_cost;
            state->best_object_pairs = score.object_pairs;
            state->best_sequence_pairs = score.sequence_pairs;
            state->best_time_pairs = score.time_pairs;
            state->best_prefix_zeros = prefix_zeros;
            state->best_confidence = (uint32_t)confidence;
            state->best_reservations = reservations;
            state->best_distance = distance;
          }
        }

        if (state->next_actual % ASF_REPAIR_POLL_INTERVAL == 0
            && asf_reassembly_checkpoint_trial(
                work, candidate, state, uuidp, uuidc, &preferred_original,
                original_validates_to)) {
          free(packet);
          asf_free_carve_state((void **)&state);
          return;
        }
      }
      free(packet);
      if (state->best_actual < 0 && preferred_original) {
        asf_reassembly_rollback_trial(*candidate, &preferred_original,
                                       original_validates_to);
      }
      if (state->best_actual >= 0
          || !asf_reassembly_advance_target(state)) {
        break;
      }
    }

    bool preferred_hypothesis = asf_reassembly_preferred_active(state);
    bool hole_splice = preferred_hypothesis
        && state->preferred_modes[state->preferred_index]
               == ASF_PREFERRED_HOLE_SPLICE;
    if (!*candidate || state->best_actual < 0) {
      state->scan_active = 0;
      break;
    }

    if (!hole_splice && layout.saw_windows_media_video
        && asf_reassembly_refine_opaque_boundary(
            work, candidate, state, asf_index, wmv_index, image_blocks,
            uuidp, uuidc, &preferred_original, original_validates_to)) {
      asf_free_carve_state((void **)&state);
      return;
    }
    state->scan_active = 0;

    uint64_t target_slot = state->best_target_slot;
    blockvector = (*candidate)->b;
    blocks = blockvector_get_num_blocks(blockvector);
    if (hole_splice) {
      BlockVector *trial = NULL;
      clone_blockvector(blockvector, &trial, true);
      preferred_original = blockvector;
      original_validates_to = (*candidate)->best_validates_to;
      (*candidate)->b = trial;
      blockvector = trial;
      blocks = blockvector_get_num_blocks(blockvector);
    }
    if (!hole_splice && target_slot < blocks) {
      resize_blockvector(blockvector, target_slot);
      inflate_blockvector(blockvector);
    }
    else if (!hole_splice && target_slot > blocks
             && !asf_reassembly_extend_prefix(*candidate, target_slot,
                                              image_blocks)) {
      asf_reassembly_rollback_trial(*candidate, &preferred_original,
                                     original_validates_to);
      break;
    }

    uint64_t selected_prefix_length = hole_splice
        ? target_slot * (uint64_t)scalpel_state.blocksize
        : blockvector_get_data_length((*candidate)->b);
    if (selected_prefix_length
        > blockvector_get_data_length((*candidate)->b)) {
      selected_prefix_length = blockvector_get_data_length((*candidate)->b);
    }
    AsfLayout prefix_layout;
    AsfParseResult prefix_result = asf_parse_file(
        (const uint8_t *)blockvector_get_data_pointer((*candidate)->b),
        selected_prefix_length, &prefix_layout);
    if (prefix_result == ASF_PARSE_INVALID
        || !prefix_layout.file_properties_valid
        || !prefix_layout.data_object_valid
        || !prefix_layout.packet_geometry_fixed) {
      if (preferred_hypothesis) {
        asf_reassembly_rollback_trial(*candidate, &preferred_original,
                                       original_validates_to);
        state->scan_active = 1;
        if (asf_reassembly_advance_target(state)) {
          continue;
        }
      }
      break;
    }

    if (scalpel_state.mode_verbose) {
      lock_fprintf(stdout,
                   "ASF reassembly: start=%" PRId64 " slot=%" PRIu64
                   " source=%" PRId64
                   " anchors=%" PRIu32 " object-cost=%" PRIu64
                   " time-cost=%" PRIu64 " confidence=%" PRIu32
                   " matches=%" PRIu64 " mode=%" PRIu32 ".\n",
                   blockvector_get_actual_blocknumber(blockvector, 0),
                   target_slot, state->best_actual,
                   state->best_anchor_packets, state->best_object_cost,
                   state->best_time_cost, state->best_confidence,
                   state->matches,
                   preferred_hypothesis
                       ? state->preferred_modes[state->preferred_index]
                       : ASF_PREFERRED_ANCHOR);
    }
    uint64_t baseline_progress = state->baseline_progress;
    bool contiguous_prefix = preferred_hypothesis
        && state->preferred_modes[state->preferred_index]
               == ASF_PREFERRED_CONTIGUOUS_PREFIX;
    uint64_t prefix_length_before_apply = blockvector_get_data_length(
        (*candidate)->b);
    bool applied = hole_splice
        ? asf_reassembly_apply_splice(
              *candidate, &prefix_layout, target_slot,
              state->preferred_end_slots[state->preferred_index],
              state->best_actual,
              state->preferred_suffix_actuals[state->preferred_index],
              image_blocks)
        : asf_reassembly_apply_run(
              *candidate, &prefix_layout, target_slot, state->best_actual,
              image_blocks, contiguous_prefix);
    if (!applied) {
      if (preferred_hypothesis) {
        asf_reassembly_rollback_trial(*candidate, &preferred_original,
                                       original_validates_to);
        state->scan_active = 1;
        if (asf_reassembly_advance_target(state)) {
          continue;
        }
      }
      break;
    }

    AsfLayout repaired_layout;
    AsfParseResult repaired_result = asf_parse_file(
        (const uint8_t *)blockvector_get_data_pointer((*candidate)->b),
        blockvector_get_data_length((*candidate)->b), &repaired_layout);
    bool prefix_extended = contiguous_prefix
        && blockvector_get_data_length((*candidate)->b)
               > prefix_length_before_apply;
    if (repaired_result != ASF_PARSE_COMPLETE
        && repaired_layout.parsed_extent <= baseline_progress
        && !prefix_extended) {
      resize_blockvector((*candidate)->b, target_slot);
      inflate_blockvector((*candidate)->b);
      if (preferred_hypothesis) {
        asf_reassembly_rollback_trial(*candidate, &preferred_original,
                                       original_validates_to);
        state->scan_active = 1;
        if (asf_reassembly_advance_target(state)) {
          continue;
        }
      }
      break;
    }
    if (preferred_original) {
      free_blockvector(&preferred_original);
    }
    state->repairs++;
    state->signature = 0;
    if (state->repairs > CEILDIV(prefix_layout.file_size,
                                 scalpel_state.blocksize)) {
      break;
    }
  }

  if (*candidate) {
    inflate_blockvector((*candidate)->b);
    AsfLayout final_layout;
    asf_parse_file(
        (const uint8_t *)blockvector_get_data_pointer((*candidate)->b),
        blockvector_get_data_length((*candidate)->b), &final_layout);
    asf_assign_subtype(*candidate, &final_layout);
    asf_free_carve_state((void **)&state);
    if (scalpel_state.write_promising) {
      (*candidate)->flavor = PROMISING;
      write_candidate(candidate, false);
    }
    else {
      destroy_candidate(candidate);
    }
  }
  else {
    asf_free_carve_state((void **)&state);
  }
}

#endif
