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

// MPEG program stream, transport stream, and elementary video validation.
//
// Program streams provide the strongest recovery evidence: pack and packet
// lengths bound the byte stream, while SCR and PTS values order independently
// recognizable runs. Transport streams provide fixed packet cadence and PID
// continuity. Elementary video streams are accepted conservatively from their
// sequence, GOP, picture, slice, and end codes.

#ifndef SCALPEL3_MPEG_H
#define SCALPEL3_MPEG_H

#include "scalpel.h"
#include <mpg123.h>

#define MPEG_MINIMUM_SIZE UINT64_C(12)
#define MPEG_MAXIMUM_SIZE UINT64_C(1099511627776)
#define MPEG_PS_PREFIX UINT32_C(0x00000100)
#define MPEG_PS_PACK_ID UINT8_C(0xba)
#define MPEG_PS_SYSTEM_ID UINT8_C(0xbb)
#define MPEG_PS_END_ID UINT8_C(0xb9)
#define MPEG_PS_SEQUENCE_ID UINT8_C(0xb3)
#define MPEG_PS_SEQUENCE_END_ID UINT8_C(0xb7)
#define MPEG_PS_GOP_ID UINT8_C(0xb8)
#define MPEG_TS_SYNC UINT8_C(0x47)
#define MPEG_TS_MIN_PACKETS 5U
#define MPEG_TERMINAL_FILL_MIN UINT64_C(16)
#define MPEG_HEADER_PROBE_BYTES UINT64_C(131072)
#define MPEG_INITIAL_SCR_MAX UINT64_C(900)
#define MPEG_INTERPACK_FILL_MAX UINT64_C(16777216)
#define MPEG_PAYLOAD_CONFIDENCE_MAX 99
#define MPEG_CARVE_STATE_MAGIC UINT32_C(0x4d504753)
#define MPEG_CARVE_STATE_VERSION UINT32_C(38)
#define MPEG_REPAIR_ANCHOR_BYTES UINT32_C(512)
#define MPEG_REPAIR_TRACE_BYTES UINT64_C(262144)
#define MPEG_REPAIR_FILL_PROBE_BYTES UINT64_C(65536)
#define MPEG_REPAIR_CANDIDATES UINT32_C(64)
#define MPEG_REPAIR_REGION_CANDIDATES UINT32_C(48)
#define MPEG_REPAIR_BRANCH_DEPTH UINT32_C(32)
#define MPEG_REPAIR_BRANCH_ALTERNATIVES UINT32_C(512)
#define MPEG_TERMINAL_HYPOTHESES UINT32_C(8)
#define MPEG_TERMINAL_COST_FACTOR UINT64_C(2)
#define MPEG_REPAIR_RUN_BYTES UINT64_C(8388608)
#define MPEG_REPAIR_BRIDGE_BYTES UINT64_C(67108864)
#define MPEG_LOCAL_REPAIR_BYTES UINT64_C(1048576)
#define MPEG_REPAIR_POLL_INTERVAL UINT64_C(256)
#define MPEG_CLOCK_HISTORY UINT32_C(32)
#define MPEG_CLOCK_MASK ((UINT64_C(1) << 33) - 1)

typedef enum MpegKind {
  MPEG_KIND_UNKNOWN = 0,
  MPEG_KIND_PROGRAM = 1,
  MPEG_KIND_TRANSPORT = 2,
  MPEG_KIND_ELEMENTARY = 3
} MpegKind;

typedef enum MpegParseResult {
  MPEG_PARSE_INVALID = 0,
  MPEG_PARSE_PARTIAL = 1,
  MPEG_PARSE_COMPLETE = 2
} MpegParseResult;

typedef struct MpegClockHistory {
  uint64_t deltas[MPEG_CLOCK_HISTORY];
  uint32_t count;
} MpegClockHistory;

typedef struct MpegPesTimes {
  uint64_t presentation;
  uint64_t decoding;
  uint64_t payload_offset;
  bool present;
} MpegPesTimes;

typedef struct MpegLayout {
  MpegKind kind;
  uint64_t parsed_extent;
  uint64_t required_extent;
  uint64_t failure_offset;
  uint64_t repair_start_offset;
  uint64_t continuity_offset;
  uint64_t last_packet_offset;
  uint64_t pack_count;
  uint64_t packet_count;
  uint64_t media_packets;
  uint64_t system_headers;
  uint64_t padding_packets;
  uint64_t sequence_headers;
  uint64_t gop_headers;
  uint64_t pictures;
  uint64_t slices;
  uint64_t transport_packets;
  uint64_t transport_payload_packets;
  uint64_t first_scr;
  uint64_t previous_scr;
  uint64_t last_scr;
  uint64_t scr_step;
  uint32_t mux_rate;
  MpegClockHistory scr_history;
  uint64_t first_pts;
  uint64_t last_pts;
  uint32_t ts_stride;
  uint32_t ts_sync_offset;
  uint32_t distinct_streams;
  uint8_t stream_seen[256];
  uint8_t stream_pts_seen[256];
  uint64_t stream_last_pts[256];
  uint64_t stream_last_dts[256];
  uint64_t stream_pts_step[256];
  MpegClockHistory stream_pts_history[256];
  uint32_t video_signature;
  bool header_valid;
  bool initial_system_header;
  bool terminal_marker;
  bool terminal_fill;
  bool timestamp_valid;
  bool interrupted;
} MpegLayout;

// Each reassembly invocation owns these independent parser workspaces.
// Keeping them off the worker stack also leaves room for nested trial parsing.
typedef struct MpegReassemblyScratch {
  MpegLayout layout;
  MpegLayout trusted_layout;
  MpegLayout trial_layout;
  MpegLayout refined_layout;
  MpegLayout substitution_layout;
} MpegReassemblyScratch;

typedef struct MpegRepairCandidate {
  int64_t source_actual;
  uint64_t target_slot;
  uint64_t anchor_source_offset;
  uint64_t run_first_actual;
  uint64_t run_last_actual;
  uint64_t clock_cost;
  uint64_t trace_bytes;
  uint64_t parsed_progress;
  uint64_t bridge_progress;
  uint64_t distance;
  int64_t reservations;
  uint32_t confidence;
  uint32_t clocks;
  uint32_t stream_matches;
  uint32_t packets;
  uint32_t mux_matches;
  uint32_t mux_mismatches;
  uint32_t bridge_run_blocks;
  uint8_t profile_match;
  uint8_t profile_mismatch;
  uint8_t backward_clocks;
  uint8_t fill_continuation;
  uint8_t local_continuation;
  uint8_t nonterminal_progress;
  uint8_t payload_prefix_refined;
} MpegRepairCandidate;

typedef struct MpegRepairAlternative {
  int64_t source_actual;
  uint64_t target_slot;
  uint64_t anchor_source_offset;
  uint32_t bridge_run_blocks;
} MpegRepairAlternative;

typedef struct MpegMappingRun {
  int64_t first_actual;
  uint64_t block_count;
} MpegMappingRun;

typedef struct MpegRepairBranch {
  uint64_t baseline_progress;
  uint32_t first_alternative;
  uint32_t alternative_count;
  uint32_t next_alternative;
  uint8_t bridge;
  uint64_t prefix_blocks;
  uint64_t prefix_length;
  uint64_t prefix_run_count;
  MpegMappingRun *prefix_runs;
} MpegRepairBranch;

typedef struct MpegPrefixBlock {
  int64_t actual;
  uint64_t slot;
} MpegPrefixBlock;

typedef struct MpegCarveState {
  uint32_t magic;
  uint32_t version;
  uint64_t repairs;
  uint32_t branch_depth;
  uint32_t branch_alternative_count;
  MpegRepairBranch branches[MPEG_REPAIR_BRANCH_DEPTH];
  MpegRepairAlternative
      branch_alternatives[MPEG_REPAIR_BRANCH_ALTERNATIVES];
  uint64_t signature;
  uint64_t first_target_slot;
  uint64_t last_target_slot;
  uint64_t next_anchor_actual;
  uint64_t anchor_offset;
  uint64_t baseline_progress;
  uint64_t best_nonterminal_progress;
  uint64_t best_substitution_progress;
  uint64_t matches;
  uint32_t phase;
  uint32_t trial_index;
  uint32_t candidate_count;
  uint32_t best_nonterminal_index;
  uint32_t substitution_candidate_index;
  uint32_t substitution_next_run;
  uint32_t best_substitution_candidate_index;
  uint32_t best_substitution_run_blocks;
  uint8_t boundary_fallback_done;
  uint64_t terminal_zero_signature;
  uint64_t terminal_zero_next_slot;
  uint32_t substitution_terminal_hypotheses;
  uint32_t direct_terminal_hypotheses;
  uint8_t terminal_candidates[MPEG_REPAIR_CANDIDATES];
  uint8_t substitution_terminal_candidates[MPEG_REPAIR_CANDIDATES];
  uint8_t direct_terminal_candidates[MPEG_REPAIR_CANDIDATES];
  MpegRepairCandidate candidates[MPEG_REPAIR_CANDIDATES];
} MpegCarveState;

static inline uint16_t mpeg_read_be16(const uint8_t *data);
static inline uint32_t mpeg_read_be24(const uint8_t *data);
static inline bool mpeg_start_code_at(const uint8_t *data, uint64_t length,
                                      uint64_t offset, uint8_t *code);
static inline bool mpeg_system_stream_id(uint8_t code);
static inline bool mpeg_media_stream_id(uint8_t code);
static inline bool mpeg_parse_timestamp(const uint8_t *data,
                                        uint8_t expected_prefix,
                                        uint64_t *timestamp);
static inline bool mpeg_clock_forward(uint64_t previous, uint64_t current);
static inline void mpeg_clock_history_add(MpegClockHistory *history,
                                          uint64_t delta);
static inline uint64_t mpeg_clock_history_median(
    const MpegClockHistory *history);
static inline void mpeg_finalize_clock_steps(MpegLayout *layout);
static inline bool mpeg_pack_header(const uint8_t *data, uint64_t length,
                                    uint64_t offset, uint64_t *header_length,
                                    uint64_t *required_extent,
                                    uint64_t *scr, uint32_t *mux_rate);
static inline bool mpeg_system_header(const uint8_t *data, uint64_t length,
                                      uint64_t offset,
                                      uint64_t *packet_length,
                                      uint64_t *required_extent);
static inline bool mpeg_pes_header(const uint8_t *data, uint64_t length,
                                   uint64_t offset, uint8_t stream_id,
                                   uint64_t packet_length,
                                   MpegPesTimes *times);
static inline int mpeg_audio_continuity(const uint8_t *data, uint64_t length,
                                        uint64_t boundary, bool *interrupted);
static inline void mpeg_scan_video_codes(const uint8_t *data,
                                         uint64_t length,
                                         MpegLayout *layout);
static inline bool mpeg_program_header_valid(const uint8_t *data,
                                             uint64_t length,
                                             bool allow_partial_packet);
static inline bool mpeg_transport_header_valid(const uint8_t *data,
                                               uint64_t length,
                                               uint32_t *stride,
                                               uint32_t *sync_offset);
static inline bool mpeg_transport_packet_valid(const uint8_t *packet,
                                               uint32_t packet_length);
static inline bool mpeg_elementary_header_valid(const uint8_t *data,
                                                uint64_t length);
static inline bool mpeg_fill_to_next_pack(const uint8_t *data,
                                          uint64_t length,
                                          uint64_t offset,
                                          uint64_t *next);
static inline uint64_t mpeg_uniform_fill_extent(const uint8_t *data,
                                                uint64_t length,
                                                uint64_t offset);
static inline MpegParseResult mpeg_parse_program(const uint8_t *data,
                                                 uint64_t length,
                                                 MpegLayout *layout);
static inline MpegParseResult mpeg_parse_transport(const uint8_t *data,
                                                   uint64_t length,
                                                   MpegLayout *layout);
static inline MpegParseResult mpeg_parse_elementary(const uint8_t *data,
                                                    uint64_t length,
                                                    MpegLayout *layout);
static inline MpegParseResult mpeg_parse_file(const uint8_t *data,
                                              uint64_t length,
                                              MpegLayout *layout);
static inline bool mpeg_layout_structural(const MpegLayout *layout);
static inline bool mpeg_layout_strong(const MpegLayout *layout);
static inline bool mpeg_reassembly_partial_packet(
    const uint8_t *data, uint64_t length, const MpegLayout *layout);
static inline bool mpeg_layout_authoritative_start(const MpegLayout *layout);
static inline bool mpeg_layout_terminal(const uint8_t *data,
                                        uint64_t length,
                                        const MpegLayout *layout);
static inline char *mpeg_header_discovery(char *base, uint64_t offset,
                                          uint64_t remaining,
                                          char **matchpos,
                                          uint32_t *matchlen,
                                          uint32_t blocksize);
static inline char *mpeg_footer_discovery(char *base, uint64_t offset,
                                          uint64_t remaining,
                                          char **matchpos,
                                          uint32_t *matchlen,
                                          uint32_t blocksize);
static inline uint32_t mpeg_block_validate(
    char *data, uint64_t length, BlockValidationDecision *decision,
    uint64_t *validates_to, uint32_t needleidx, uint32_t blocksize,
    void *blockhashkey);
static inline void mpeg_file_validate(char *data, uint64_t length,
                                      bool *validates,
                                      uint64_t *validates_to,
                                      bool *promising, uint32_t needleidx,
                                      uint32_t blocksize,
                                      void *carvehashkey);
static inline bool mpeg_candidate_contiguous(const CarveInfo *candidate);
static inline void mpeg_candidate_validate(CarveInfo *candidate,
                                           bool *validates,
                                           uint64_t *validates_to,
                                           bool *promising);
static inline bool mpeg_header_at(const uint8_t *data, uint64_t length,
                                  uint64_t position);
static inline bool mpeg_position_inside_video_pes(const uint8_t *data,
                                                  uint64_t length,
                                                  uint64_t position);
static inline bool mpeg_program_contiguous_predecessor(
    const uint8_t *data, uint64_t length, uint64_t position,
    uint64_t *last_scr);
static inline bool mpeg_carve_state_valid(const MpegCarveState *state);
static inline bool mpeg_repair_prefix_valid(const MpegRepairBranch *branch);
static inline bool mpeg_reassembly_capture_prefix(
    MpegRepairBranch *branch, BlockVector *blockvector, uint64_t blocks);
static inline bool mpeg_reassembly_restore_prefix(
    CarveInfo *candidate, const MpegRepairBranch *branch, uint64_t blocks,
    uint64_t image_blocks);
static inline bool mpeg_serialize_carve_state(void **state, FILE *fp,
                                             StateSerialization mode);
static inline void *mpeg_clone_carve_state(const void *state);
static inline void mpeg_free_carve_state(void **state);
static inline size_t mpeg_sizeof_carve_state(const void *state);
static inline void mpeg_print_carve_state(const void *state);
static inline bool mpeg_reassembly_debug_candidate(
    const CarveInfo *candidate);
static inline void mpeg_reassembly_add_aligned_candidates(
    MpegCarveState *state, CarveInfo *candidate, int64_t anchor_actual,
    uint64_t anchor_offset, uint64_t first_target, uint64_t last_target,
    uint64_t image_blocks, const MpegLayout *prefix,
    const MpegPrefixBlock *prefix_index, uint64_t prefix_count,
    uint8_t *trace, uint64_t trace_capacity);
static inline MpegParseResult mpeg_reassembly_parse_trial(
    const uint8_t *data, uint64_t length, MpegLayout *layout);
static inline bool mpeg_reassembly_publish_zero_gap_hypotheses(
    ThreadWork *work, CarveInfo **candidate, MpegCarveState *state,
    uint64_t image_blocks, const MpegLayout *baseline,
    uuid_string_t uuidp, uuid_string_t uuidc);
static inline void mpeg_reassembly_search(
    ThreadWork *work, CarveInfo **candidate, uuid_string_t uuidp,
    uuid_string_t uuidc, MpegReassemblyScratch *scratch);
static inline void mpeg_reassembly(ThreadWork *work, CarveInfo **candidate,
                                   uuid_string_t uuidp,
                                   uuid_string_t uuidc);

static inline uint16_t mpeg_read_be16(const uint8_t *data) {
  return (uint16_t)((uint16_t)data[0] << 8) | (uint16_t)data[1];
}

static inline uint32_t mpeg_read_be24(const uint8_t *data) {
  return ((uint32_t)data[0] << 16) | ((uint32_t)data[1] << 8)
      | (uint32_t)data[2];
}

static inline bool mpeg_start_code_at(const uint8_t *data, uint64_t length,
                                      uint64_t offset, uint8_t *code) {
  if (!data || offset > length || UINT64_C(4) > length - offset
      || data[offset] != 0 || data[offset + 1] != 0
      || data[offset + 2] != 1) {
    return false;
  }
  if (code) {
    *code = data[offset + 3];
  }
  return true;
}

static inline bool mpeg_system_stream_id(uint8_t code) {
  return code == UINT8_C(0xbc) || code == UINT8_C(0xbd)
      || code == UINT8_C(0xbe) || code == UINT8_C(0xbf)
      || (code >= UINT8_C(0xc0) && code <= UINT8_C(0xef))
      || (code >= UINT8_C(0xf0) && code <= UINT8_C(0xf8))
      || code == UINT8_C(0xff);
}

static inline bool mpeg_media_stream_id(uint8_t code) {
  return code == UINT8_C(0xbd)
      || (code >= UINT8_C(0xc0) && code <= UINT8_C(0xef));
}

static inline bool mpeg_parse_timestamp(const uint8_t *data,
                                        uint8_t expected_prefix,
                                        uint64_t *timestamp) {
  if (!data || !timestamp || (data[0] >> 4) != expected_prefix
      || (data[0] & 1U) == 0 || (data[2] & 1U) == 0
      || (data[4] & 1U) == 0) {
    return false;
  }
  *timestamp = ((uint64_t)(data[0] & UINT8_C(0x0e)) << 29)
      | ((uint64_t)data[1] << 22)
      | ((uint64_t)(data[2] & UINT8_C(0xfe)) << 14)
      | ((uint64_t)data[3] << 7)
      | ((uint64_t)(data[4] & UINT8_C(0xfe)) >> 1);
  return true;
}

static inline bool mpeg_clock_forward(uint64_t previous, uint64_t current) {
  uint64_t delta = (current - previous) & MPEG_CLOCK_MASK;
  return delta <= (UINT64_C(1) << 32);
}

static inline void mpeg_clock_history_add(MpegClockHistory *history,
                                          uint64_t delta) {
  if (!history || delta == 0 || delta > (UINT64_C(1) << 32)) {
    return;
  }
  history->deltas[history->count % MPEG_CLOCK_HISTORY] = delta;
  if (history->count != UINT32_MAX) {
    history->count++;
  }
}

static inline uint64_t mpeg_clock_history_median(
    const MpegClockHistory *history) {
  if (!history || history->count == 0) {
    return 0;
  }
  uint32_t count = history->count < MPEG_CLOCK_HISTORY
      ? history->count : MPEG_CLOCK_HISTORY;
  uint64_t values[MPEG_CLOCK_HISTORY];
  memcpy(values, history->deltas, (size_t)count * sizeof(*values));
  for (uint32_t index = 1; index < count; index++) {
    uint64_t value = values[index];
    uint32_t position = index;
    while (position > 0 && values[position - 1] > value) {
      values[position] = values[position - 1];
      position--;
    }
    values[position] = value;
  }
  return values[count / 2];
}

static inline void mpeg_finalize_clock_steps(MpegLayout *layout) {
  if (!layout) {
    return;
  }
  layout->scr_step = mpeg_clock_history_median(&layout->scr_history);
  for (uint32_t stream = 0; stream < 256; stream++) {
    if (layout->stream_pts_seen[stream]) {
      layout->stream_pts_step[stream] = mpeg_clock_history_median(
          &layout->stream_pts_history[stream]);
    }
  }
}

static inline bool mpeg_pack_header(const uint8_t *data, uint64_t length,
                                    uint64_t offset, uint64_t *header_length,
                                    uint64_t *required_extent,
                                    uint64_t *scr, uint32_t *mux_rate) {
  uint8_t code;
  if (!data || !header_length || !required_extent || !scr || !mux_rate
      || !mpeg_start_code_at(data, length, offset, &code)
      || code != MPEG_PS_PACK_ID) {
    return false;
  }
  *required_extent = offset + 12;
  if (offset > length || UINT64_C(12) > length - offset) {
    return false;
  }

  const uint8_t *pack = data + offset;
  if ((pack[4] & UINT8_C(0xc0)) == UINT8_C(0x40)) {
    *required_extent = offset + 14;
    if (UINT64_C(14) > length - offset) {
      return false;
    }
    if ((pack[4] & UINT8_C(0xc4)) != UINT8_C(0x44)
        || (pack[6] & UINT8_C(0x04)) == 0
        || (pack[8] & UINT8_C(0x04)) == 0
        || (pack[9] & UINT8_C(0x01)) == 0
        || (pack[12] & UINT8_C(0x03)) != UINT8_C(0x03)
        || (pack[13] & UINT8_C(0xf8)) != UINT8_C(0xf8)) {
      return false;
    }
    uint64_t stuffing = pack[13] & UINT8_C(0x07);
    *required_extent = offset + 14 + stuffing;
    if (stuffing > length - offset - 14) {
      return false;
    }
    for (uint64_t index = 0; index < stuffing; index++) {
      if (pack[14 + index] != UINT8_C(0xff)) {
        return false;
      }
    }
    *header_length = 14 + stuffing;
    *scr = ((uint64_t)(pack[4] & UINT8_C(0x38)) << 27)
        | ((uint64_t)(pack[4] & UINT8_C(0x03)) << 28)
        | ((uint64_t)pack[5] << 20)
        | ((uint64_t)(pack[6] & UINT8_C(0xf8)) << 12)
        | ((uint64_t)(pack[6] & UINT8_C(0x03)) << 13)
        | ((uint64_t)pack[7] << 5)
        | ((uint64_t)(pack[8] & UINT8_C(0xf8)) >> 3);
    *mux_rate = ((uint32_t)pack[10] << 14)
        | ((uint32_t)pack[11] << 6)
        | ((uint32_t)(pack[12] & UINT8_C(0xfc)) >> 2);
    return true;
  }

  if ((pack[4] & UINT8_C(0xf1)) != UINT8_C(0x21)
      || (pack[6] & UINT8_C(0x01)) == 0
      || (pack[8] & UINT8_C(0x01)) == 0
      || (pack[9] & UINT8_C(0x80)) == 0
      || (pack[11] & UINT8_C(0x01)) == 0) {
    return false;
  }
  *header_length = 12;
  *scr = ((uint64_t)(pack[4] & UINT8_C(0x0e)) << 29)
      | ((uint64_t)pack[5] << 22)
      | ((uint64_t)(pack[6] & UINT8_C(0xfe)) << 14)
      | ((uint64_t)pack[7] << 7)
      | ((uint64_t)(pack[8] & UINT8_C(0xfe)) >> 1);
  *mux_rate = ((uint32_t)(pack[9] & UINT8_C(0x7f)) << 15)
      | ((uint32_t)pack[10] << 7)
      | ((uint32_t)pack[11] >> 1);
  return true;
}

static inline bool mpeg_system_header(const uint8_t *data, uint64_t length,
                                      uint64_t offset,
                                      uint64_t *packet_length,
                                      uint64_t *required_extent) {
  uint8_t code;
  if (!data || !packet_length || !required_extent
      || !mpeg_start_code_at(data, length, offset, &code)
      || code != MPEG_PS_SYSTEM_ID) {
    return false;
  }
  *required_extent = offset + 6;
  if (offset > length || UINT64_C(6) > length - offset) {
    return false;
  }
  uint64_t payload_length = mpeg_read_be16(data + offset + 4);
  if (payload_length < 6) {
    return false;
  }
  *packet_length = payload_length + 6;
  *required_extent = offset + *packet_length;
  if (*packet_length > length - offset) {
    return false;
  }
  const uint8_t *payload = data + offset + 6;
  if ((payload[0] & UINT8_C(0x80)) == 0
      || (payload[2] & UINT8_C(0x01)) == 0
      || (payload[4] & UINT8_C(0x20)) == 0) {
    return false;
  }
  for (uint64_t position = 6; position + 3 <= payload_length;
       position += 3) {
    if ((payload[position + 1] & UINT8_C(0xc0)) != UINT8_C(0xc0)) {
      return false;
    }
  }
  return true;
}

// Locate the payload and decode both PES timestamps. When only PTS is present
// it also specifies decoding time; explicit DTS orders reordered pictures.
static inline bool mpeg_pes_header(const uint8_t *data, uint64_t length,
                                   uint64_t offset, uint8_t stream_id,
                                   uint64_t packet_length,
                                   MpegPesTimes *times) {
  if (!data || !times || offset > length
      || packet_length > length - offset || packet_length < 6) {
    return false;
  }
  memset(times, 0, sizeof(*times));
  times->payload_offset = offset + 6;
  if (!mpeg_media_stream_id(stream_id)) {
    return true;
  }
  uint64_t payload_length = packet_length - 6;
  const uint8_t *payload = data + offset + 6;
  if (payload_length == 0) {
    return false;
  }

  if ((payload[0] & UINT8_C(0xc0)) == UINT8_C(0x80)) {
    if (payload_length < 3) {
      return false;
    }
    uint8_t flags = payload[1];
    uint64_t header_data_length = payload[2];
    if (header_data_length > payload_length - 3
        || (flags & UINT8_C(0xc0)) == UINT8_C(0x40)) {
      return false;
    }
    times->payload_offset += 3 + header_data_length;
    if ((flags & UINT8_C(0xc0)) == UINT8_C(0x80)) {
      if (header_data_length < 5
          || !mpeg_parse_timestamp(payload + 3, 2, &times->presentation)) {
        return false;
      }
      times->decoding = times->presentation;
      times->present = true;
    }
    else if ((flags & UINT8_C(0xc0)) == UINT8_C(0xc0)) {
      if (header_data_length < 10
          || !mpeg_parse_timestamp(payload + 3, 3, &times->presentation)
          || !mpeg_parse_timestamp(payload + 8, 1, &times->decoding)) {
        return false;
      }
      times->present = true;
    }
    return true;
  }

  uint64_t position = 0;
  while (position < payload_length
         && payload[position] == UINT8_C(0xff)) {
    position++;
  }
  if (position + 2 <= payload_length
      && (payload[position] & UINT8_C(0xc0)) == UINT8_C(0x40)) {
    position += 2;
  }
  if (position >= payload_length) {
    return false;
  }
  uint8_t prefix = payload[position] >> 4;
  if (prefix == 2) {
    if (position + 5 > payload_length
        || !mpeg_parse_timestamp(payload + position, 2,
                                  &times->presentation)) {
      return false;
    }
    times->decoding = times->presentation;
    times->present = true;
    times->payload_offset += position + 5;
    return true;
  }
  if (prefix == 3) {
    if (position + 10 > payload_length
        || !mpeg_parse_timestamp(payload + position, 3,
                                  &times->presentation)
        || !mpeg_parse_timestamp(payload + position + 5, 1,
                                  &times->decoding)) {
      return false;
    }
    times->present = true;
    times->payload_offset += position + 10;
    return true;
  }
  times->payload_offset += position + 1;
  return payload[position] == UINT8_C(0x0f);
}

// Decode the first MPEG audio stream across a proposed join without resync.
// Return 1 after two additional frames, -1 for lost synchronization after a
// decodable prefix, or 0 when evidence is unavailable. An interrupted check
// must be retried. This orders structural trials; it does not establish file
// identity or change validation decisions.
static inline int mpeg_audio_continuity(const uint8_t *data, uint64_t length,
                                        uint64_t boundary, bool *interrupted) {
  *interrupted = atomic_load_explicit(&REASS_RETURN_TO_IDLE,
                                       memory_order_acquire);
  if (*interrupted || !data || boundary == 0 || boundary > length
      || boundary > MPEG_REPAIR_RUN_BYTES) {
    return 0;
  }
#if MPG123_API_VERSION >= 46
  if (length - boundary > MPEG_REPAIR_TRACE_BYTES) {
    length = boundary + MPEG_REPAIR_TRACE_BYTES;
  }
  int error = 0;
  mpg123_handle *handle = mpg123_new(NULL, &error);
  if (!handle) {
    return 0;
  }
  int evidence = 0;
  if (mpg123_param(handle, MPG123_FLAGS,
                   MPG123_QUIET | MPG123_NO_RESYNC, 0.0) != MPG123_OK
      || mpg123_open_feed(handle) != MPG123_OK) {
    mpg123_delete(handle);
    return 0;
  }
  uint64_t frames = 0;
  uint64_t prefix_frames = 0;
  uint64_t position = 0;
  int stream = -1;
  bool beyond_prefix = false;
  while (position < length) {
    if (atomic_load_explicit(&REASS_RETURN_TO_IDLE, memory_order_acquire)) {
      *interrupted = true;
      break;
    }
    if (!beyond_prefix && position >= boundary) {
      if (!frames) {
        break;
      }
      prefix_frames = frames;
      beyond_prefix = true;
    }
    uint8_t code;
    if (!mpeg_start_code_at(data, length, position, &code)) {
      uint64_t next;
      if (mpeg_fill_to_next_pack(data, length, position, &next)) {
        position = next;
        continue;
      }
      break;
    }
    uint64_t packet;
    if (code == MPEG_PS_PACK_ID) {
      uint64_t required, scr;
      uint32_t mux_rate;
      if (!mpeg_pack_header(data, length, position, &packet,
                            &required, &scr, &mux_rate)) {
        break;
      }
    }
    else if (code >= MPEG_PS_SYSTEM_ID && length - position >= 6) {
      packet = 6 + (uint64_t)mpeg_read_be16(data + position + 4);
      if (packet <= 6 || packet > length - position) {
        break;
      }
    }
    else {
      break;
    }
    if (code >= 0xc0 && code <= 0xdf && (stream < 0 || code == stream)) {
      MpegPesTimes times;
      if (!mpeg_pes_header(data, length, position, code, packet, &times)) {
        break;
      }
      stream = code;
      uint64_t payload = times.payload_offset;
      const uint64_t end = position + packet;
      while (payload < end) {
        if (!beyond_prefix && payload >= boundary) {
          if (!frames) {
            goto done;
          }
          prefix_frames = frames;
          beyond_prefix = true;
        }
        // Feed the common prefix separately even inside an audio packet.
        uint64_t stop = end;
        if (!beyond_prefix && stop > boundary) {
          stop = boundary;
        }
        int result = mpg123_feed(handle, data + payload, stop - payload);
        while (result == MPG123_OK || result == MPG123_NEW_FORMAT) {
          if (atomic_load_explicit(&REASS_RETURN_TO_IDLE,
                                   memory_order_acquire)) {
            *interrupted = true;
            goto done;
          }
          unsigned char *audio = NULL;
          size_t bytes = 0;
          off_t number = 0;
          result = mpg123_decode_frame(handle, &number, &audio, &bytes);
          if (result == MPG123_OK && bytes) {
            frames++;
            // Limit evidence to two new frames, not the remaining run.
            if (beyond_prefix && frames - prefix_frames >= 2) {
              evidence = 1;
              goto done;
            }
          }
        }
        if (result != MPG123_NEED_MORE) {
          if (beyond_prefix && result == MPG123_ERR
              && mpg123_errcode(handle) == MPG123_OUT_OF_SYNC) {
            evidence = -1;
          }
          goto done;
        }
        payload = stop;
      }
    }
    position += packet;
  }
done:
  mpg123_delete(handle);
  return evidence;
#else
  // Older libraries require process-wide initialization before any thread use.
  return 0;
#endif
}

static inline void mpeg_scan_video_codes(const uint8_t *data,
                                         uint64_t length,
                                         MpegLayout *layout) {
  if (!data || !layout || length < 4) {
    return;
  }
  for (uint64_t position = 0; position + 4 <= length; position++) {
    if (data[position] != 0 || data[position + 1] != 0
        || data[position + 2] != 1) {
      continue;
    }
    uint8_t code = data[position + 3];
    if (code == MPEG_PS_SEQUENCE_ID) {
      layout->sequence_headers++;
      if (layout->video_signature == 0 && position + 8 <= length) {
        layout->video_signature = ((uint32_t)data[position + 4] << 24)
            | ((uint32_t)data[position + 5] << 16)
            | ((uint32_t)data[position + 6] << 8)
            | (uint32_t)data[position + 7];
      }
    }
    else if (code == MPEG_PS_GOP_ID) {
      layout->gop_headers++;
    }
    else if (code == 0) {
      layout->pictures++;
    }
    else if (code >= 1 && code <= UINT8_C(0xaf)) {
      layout->slices++;
    }
    position += 2;
  }
}

static inline bool mpeg_program_header_valid(const uint8_t *data,
                                             uint64_t length,
                                             bool allow_partial_packet) {
  uint64_t pack_length;
  uint64_t required;
  uint64_t scr;
  uint32_t mux_rate;
  if (!mpeg_pack_header(data, length, 0, &pack_length, &required, &scr,
                        &mux_rate)) {
    return false;
  }
  if (pack_length > length || UINT64_C(4) > length - pack_length) {
    return false;
  }
  uint8_t code;
  if (!mpeg_start_code_at(data, length, pack_length, &code)) {
    return false;
  }
  uint64_t position = pack_length;
  if (code == MPEG_PS_SYSTEM_ID) {
    uint64_t system_length;
    if (!mpeg_system_header(data, length, position, &system_length,
                            &required)) {
      return false;
    }
    position += system_length;
    if (!mpeg_start_code_at(data, length, position, &code)) {
      return false;
    }
  }
  if (code == MPEG_PS_PACK_ID) {
    return mpeg_pack_header(data, length, position, &pack_length,
                            &required, &scr, &mux_rate);
  }
  if (!mpeg_system_stream_id(code) || position > length
      || UINT64_C(6) > length - position) {
    return false;
  }
  uint64_t payload_length = mpeg_read_be16(data + position + 4);
  if (payload_length == 0) {
    return false;
  }
  uint64_t packet_length = payload_length + 6;
  if (packet_length > length - position) {
    if (!allow_partial_packet || !mpeg_media_stream_id(code)) {
      return false;
    }
    // Reassembly needs the intact PES header, not the entire first payload.
    packet_length = length - position;
  }
  MpegPesTimes times;
  return mpeg_pes_header(data, length, position, code,
                         packet_length, &times);
}

static inline bool mpeg_transport_packet_valid(const uint8_t *packet,
                                               uint32_t packet_length) {
  if (!packet || packet_length < 188 || packet[0] != MPEG_TS_SYNC
      || (packet[1] & UINT8_C(0x80)) != 0) {
    return false;
  }
  uint8_t adaptation = (packet[3] >> 4) & UINT8_C(0x03);
  if (adaptation == 0) {
    return false;
  }
  if ((adaptation & 2U) != 0) {
    uint32_t adaptation_length = packet[4];
    if (adaptation_length > 183) {
      return false;
    }
  }
  return true;
}

static inline bool mpeg_transport_header_valid(const uint8_t *data,
                                               uint64_t length,
                                               uint32_t *stride,
                                               uint32_t *sync_offset) {
  static const uint32_t strides[] = {188, 192, 204};
  static const uint32_t offsets[] = {0, 4, 0};
  if (!data) {
    return false;
  }
  for (uint32_t choice = 0; choice < 3; choice++) {
    uint32_t packet_stride = strides[choice];
    uint32_t packet_offset = offsets[choice];
    uint64_t required = packet_offset
        + (uint64_t)(MPEG_TS_MIN_PACKETS - 1) * packet_stride + 188;
    if (length < required) {
      continue;
    }
    bool valid = true;
    for (uint32_t packet = 0; packet < MPEG_TS_MIN_PACKETS; packet++) {
      uint64_t position = packet_offset + (uint64_t)packet * packet_stride;
      if (!mpeg_transport_packet_valid(data + position, 188)) {
        valid = false;
        break;
      }
    }
    if (valid) {
      if (stride) {
        *stride = packet_stride;
      }
      if (sync_offset) {
        *sync_offset = packet_offset;
      }
      return true;
    }
  }
  return false;
}

static inline bool mpeg_elementary_header_valid(const uint8_t *data,
                                                uint64_t length) {
  if (!data || length < 12 || data[0] != 0 || data[1] != 0
      || data[2] != 1 || data[3] != MPEG_PS_SEQUENCE_ID) {
    return false;
  }
  uint32_t width = ((uint32_t)data[4] << 4) | (data[5] >> 4);
  uint32_t height = ((uint32_t)(data[5] & UINT8_C(0x0f)) << 8) | data[6];
  uint8_t aspect = data[7] >> 4;
  uint8_t frame_rate = data[7] & UINT8_C(0x0f);
  return width > 0 && height > 0 && aspect >= 1 && aspect <= 14
      && frame_rate >= 1 && frame_rate <= 8
      && (data[10] & UINT8_C(0x20)) != 0;
}

static inline bool mpeg_fill_to_next_pack(const uint8_t *data,
                                          uint64_t length,
                                          uint64_t offset,
                                          uint64_t *next) {
  if (!data || !next || offset >= length) {
    return false;
  }
  uint8_t fill = data[offset];
  if (fill != 0 && fill != UINT8_C(0xff)) {
    return false;
  }
  uint64_t limit = length - offset;
  if (limit > MPEG_INTERPACK_FILL_MAX) {
    limit = MPEG_INTERPACK_FILL_MAX;
  }
  for (uint64_t delta = 1; delta + 4 <= limit; delta++) {
    if (data[offset + delta] == 0 && data[offset + delta + 1] == 0
        && data[offset + delta + 2] == 1
        && data[offset + delta + 3] == MPEG_PS_PACK_ID) {
      for (uint64_t check = 0; check < delta; check++) {
        if (data[offset + check] != fill) {
          return false;
        }
      }
      *next = offset + delta;
      return true;
    }
    if (data[offset + delta] != fill) {
      return false;
    }
  }
  return false;
}

static inline uint64_t mpeg_uniform_fill_extent(const uint8_t *data,
                                                uint64_t length,
                                                uint64_t offset) {
  if (!data || offset >= length
      || (data[offset] != 0 && data[offset] != UINT8_C(0xff))) {
    return offset;
  }
  uint8_t fill = data[offset];
  uint64_t extent = offset;
  while (extent < length && data[extent] == fill) {
    extent++;
  }
  return extent;
}

static inline MpegParseResult mpeg_parse_program(const uint8_t *data,
                                                 uint64_t length,
                                                 MpegLayout *layout) {
  if (!data || !layout || !mpeg_program_header_valid(data, length, true)) {
    return MPEG_PARSE_INVALID;
  }
  layout->kind = MPEG_KIND_PROGRAM;
  layout->header_valid = true;
  layout->timestamp_valid = true;
  uint64_t position = 0;
  uint64_t last_packet = 0;

  while (position < length) {
    uint8_t code;
    if (!mpeg_start_code_at(data, length, position, &code)) {
      uint64_t continuation;
      if (mpeg_fill_to_next_pack(data, length, position, &continuation)) {
        position = continuation;
        continue;
      }
      uint64_t fill_extent = mpeg_uniform_fill_extent(data, length, position);
      layout->failure_offset = fill_extent > position ? fill_extent : position;
      layout->repair_start_offset = last_packet;
      return MPEG_PARSE_PARTIAL;
    }

    if (code == MPEG_PS_PACK_ID) {
      uint64_t pack_length;
      uint64_t required;
      uint64_t scr;
      uint32_t mux_rate;
      if (!mpeg_pack_header(data, length, position, &pack_length,
                            &required, &scr, &mux_rate)) {
        if (required > length) {
          layout->required_extent = required;
        }
        layout->failure_offset = position;
        layout->repair_start_offset = last_packet;
        return MPEG_PARSE_PARTIAL;
      }
      if (layout->pack_count > 0
          && !mpeg_clock_forward(layout->last_scr, scr)) {
        uint64_t next_available = length - position;
        uint8_t next_code;
        uint64_t next_system_length;
        bool initial_system_header =
            mpeg_start_code_at(data + position, next_available,
                               pack_length, &next_code)
            && next_code == MPEG_PS_SYSTEM_ID
            && mpeg_system_header(data + position, next_available,
                                  pack_length, &next_system_length,
                                  &required);
        bool independent_restart =
            mpeg_program_header_valid(data + position, next_available, false)
            && (initial_system_header || scr <= MPEG_INITIAL_SCR_MAX);
        if (independent_restart) {
          layout->terminal_fill =
              mpeg_layout_terminal(data, position, layout);
          return MPEG_PARSE_COMPLETE;
        }
        layout->timestamp_valid = false;
        layout->failure_offset = position;
        layout->repair_start_offset = last_packet;
        return MPEG_PARSE_PARTIAL;
      }
      if (layout->pack_count > 0 && mux_rate != layout->mux_rate
          && layout->continuity_offset == UINT64_MAX) {
        layout->continuity_offset = position;
      }
      layout->mux_rate = mux_rate;
      if (layout->pack_count == 0) {
        layout->first_scr = scr;
      }
      else {
        uint64_t delta = (scr - layout->last_scr) & MPEG_CLOCK_MASK;
        layout->previous_scr = layout->last_scr;
        mpeg_clock_history_add(&layout->scr_history, delta);
      }
      layout->last_scr = scr;
      layout->pack_count++;
      position += pack_length;
      layout->parsed_extent = position;
      continue;
    }

    if (code == MPEG_PS_END_ID) {
      position += 4;
      layout->parsed_extent = position;
      layout->terminal_marker = true;
      return MPEG_PARSE_COMPLETE;
    }

    if (code == MPEG_PS_SYSTEM_ID) {
      uint64_t packet_length;
      uint64_t required;
      if (!mpeg_system_header(data, length, position, &packet_length,
                              &required)) {
        if (required > length) {
          layout->required_extent = required;
        }
        layout->failure_offset = position;
        layout->repair_start_offset = last_packet;
        return MPEG_PARSE_PARTIAL;
      }
      last_packet = position;
      layout->last_packet_offset = position;
      if (layout->pack_count == 1 && layout->packet_count == 0) {
        layout->initial_system_header = true;
      }
      layout->system_headers++;
      layout->packet_count++;
      position += packet_length;
      layout->parsed_extent = position;
      continue;
    }

    if (!mpeg_system_stream_id(code)) {
      layout->failure_offset = position;
      layout->repair_start_offset = last_packet;
      return MPEG_PARSE_PARTIAL;
    }
    if (UINT64_C(6) > length - position) {
      layout->required_extent = position + 6;
      layout->failure_offset = position;
      layout->repair_start_offset = last_packet;
      return MPEG_PARSE_PARTIAL;
    }
    uint64_t payload_length = mpeg_read_be16(data + position + 4);
    if (payload_length == 0) {
      layout->failure_offset = position;
      layout->repair_start_offset = last_packet;
      return MPEG_PARSE_PARTIAL;
    }
    uint64_t packet_length = payload_length + 6;
    if (packet_length > length - position) {
      layout->required_extent = position + packet_length;
      layout->failure_offset = length;
      layout->repair_start_offset = position;
      return MPEG_PARSE_PARTIAL;
    }
    MpegPesTimes times;
    if (!mpeg_pes_header(data, length, position, code, packet_length,
                         &times)) {
      layout->failure_offset = position;
      layout->repair_start_offset = last_packet;
      return MPEG_PARSE_PARTIAL;
    }
    if (times.present) {
      if (layout->first_pts == 0) {
        layout->first_pts = times.presentation;
      }
      if (layout->stream_pts_seen[code]) {
        if (mpeg_clock_forward(layout->stream_last_pts[code],
                                times.presentation)) {
          uint64_t delta = (times.presentation - layout->stream_last_pts[code])
              & MPEG_CLOCK_MASK;
          mpeg_clock_history_add(&layout->stream_pts_history[code], delta);
        }
      }
      layout->stream_pts_seen[code] = 1;
      layout->stream_last_pts[code] = times.presentation;
      layout->stream_last_dts[code] = times.decoding;
      layout->last_pts = times.presentation;
    }
    if (!layout->stream_seen[code]) {
      layout->stream_seen[code] = 1;
      layout->distinct_streams++;
    }
    if (mpeg_media_stream_id(code)) {
      layout->media_packets++;
      if (code >= UINT8_C(0xe0) && code <= UINT8_C(0xef)) {
        mpeg_scan_video_codes(data + position + 6,
                              packet_length - 6, layout);
      }
    }
    if (code == UINT8_C(0xbe)) {
      layout->padding_packets++;
    }
    last_packet = position;
    layout->last_packet_offset = position;
    layout->packet_count++;
    position += packet_length;
    layout->parsed_extent = position;
  }

  return position == length ? MPEG_PARSE_COMPLETE : MPEG_PARSE_PARTIAL;
}

static inline MpegParseResult mpeg_parse_transport(const uint8_t *data,
                                                   uint64_t length,
                                                   MpegLayout *layout) {
  uint32_t stride;
  uint32_t sync_offset;
  if (!data || !layout
      || !mpeg_transport_header_valid(data, length, &stride, &sync_offset)) {
    return MPEG_PARSE_INVALID;
  }
  layout->kind = MPEG_KIND_TRANSPORT;
  layout->header_valid = true;
  layout->timestamp_valid = true;
  layout->ts_stride = stride;
  layout->ts_sync_offset = sync_offset;
  uint64_t position = sync_offset;
  while (position + 188 <= length) {
    const uint8_t *packet = data + position;
    if (!mpeg_transport_packet_valid(packet, 188)) {
      layout->failure_offset = position;
      layout->repair_start_offset = position >= stride
          ? position - stride : 0;
      return MPEG_PARSE_PARTIAL;
    }
    uint16_t pid = (uint16_t)((packet[1] & UINT8_C(0x1f)) << 8)
        | packet[2];
    uint8_t adaptation = (packet[3] >> 4) & UINT8_C(0x03);
    layout->transport_packets++;
    if ((adaptation & 1U) != 0 && pid != UINT16_C(0x1fff)) {
      layout->transport_payload_packets++;
    }
    position += stride;
    layout->parsed_extent = position;
  }
  if (position == length || (sync_offset == 4 && position + 4 == length)) {
    layout->parsed_extent = length;
    return MPEG_PARSE_COMPLETE;
  }
  layout->required_extent = position + 188;
  layout->failure_offset = position;
  layout->repair_start_offset = position >= stride ? position - stride : 0;
  return MPEG_PARSE_PARTIAL;
}

static inline MpegParseResult mpeg_parse_elementary(const uint8_t *data,
                                                    uint64_t length,
                                                    MpegLayout *layout) {
  if (!data || !layout || !mpeg_elementary_header_valid(data, length)) {
    return MPEG_PARSE_INVALID;
  }
  layout->kind = MPEG_KIND_ELEMENTARY;
  layout->header_valid = true;
  layout->timestamp_valid = true;
  layout->sequence_headers = 1;
  uint64_t position = 4;
  uint64_t last_code = 0;
  while (position + 4 <= length) {
    if (data[position] != 0 || data[position + 1] != 0
        || data[position + 2] != 1) {
      position++;
      continue;
    }
    uint8_t code = data[position + 3];
    if (code == MPEG_PS_SEQUENCE_END_ID) {
      layout->terminal_marker = true;
      layout->parsed_extent = position + 4;
      return MPEG_PARSE_COMPLETE;
    }
    if (code == MPEG_PS_SEQUENCE_ID) {
      layout->sequence_headers++;
    }
    else if (code == MPEG_PS_GOP_ID) {
      layout->gop_headers++;
    }
    else if (code == 0) {
      layout->pictures++;
    }
    else if (code >= 1 && code <= UINT8_C(0xaf)) {
      layout->slices++;
    }
    last_code = position;
    position += 4;
  }
  layout->parsed_extent = length;
  layout->repair_start_offset = last_code;
  return MPEG_PARSE_COMPLETE;
}

static inline MpegParseResult mpeg_parse_file(const uint8_t *data,
                                              uint64_t length,
                                              MpegLayout *layout) {
  if (!layout) {
    return MPEG_PARSE_INVALID;
  }
  memset(layout, 0, sizeof(*layout));
  layout->failure_offset = UINT64_MAX;
  layout->repair_start_offset = UINT64_MAX;
  layout->continuity_offset = UINT64_MAX;
  layout->last_packet_offset = UINT64_MAX;
  if (!data || length < MPEG_MINIMUM_SIZE) {
    return MPEG_PARSE_INVALID;
  }
  if (mpeg_program_header_valid(data, length, true)) {
    MpegParseResult result = mpeg_parse_program(data, length, layout);
    mpeg_finalize_clock_steps(layout);
    return result;
  }
  if (mpeg_transport_header_valid(data, length, NULL, NULL)) {
    return mpeg_parse_transport(data, length, layout);
  }
  if (mpeg_elementary_header_valid(data, length)) {
    return mpeg_parse_elementary(data, length, layout);
  }
  return MPEG_PARSE_INVALID;
}

static inline bool mpeg_layout_structural(const MpegLayout *layout) {
  if (!layout || !layout->header_valid) {
    return false;
  }
  if (layout->kind == MPEG_KIND_PROGRAM) {
    return layout->pack_count > 0 && layout->media_packets > 0
        && layout->packet_count >= 2;
  }
  if (layout->kind == MPEG_KIND_TRANSPORT) {
    return layout->transport_packets >= MPEG_TS_MIN_PACKETS
        && layout->transport_payload_packets > 0;
  }
  if (layout->kind == MPEG_KIND_ELEMENTARY) {
    return layout->sequence_headers > 0 && layout->pictures > 0
        && layout->slices > 0;
  }
  return false;
}

static inline bool mpeg_layout_strong(const MpegLayout *layout) {
  return mpeg_layout_structural(layout)
      && (layout->kind != MPEG_KIND_PROGRAM || layout->timestamp_valid);
}

// A complete PES header can justify searching for the rest of its packet even
// before the prefix contains enough complete packets for normal validation.
static inline bool mpeg_reassembly_partial_packet(
    const uint8_t *data, uint64_t length, const MpegLayout *layout) {
  if (!data || !layout || !layout->header_valid || !layout->timestamp_valid
      || layout->kind != MPEG_KIND_PROGRAM || layout->pack_count == 0
      || layout->required_extent <= length || layout->failure_offset != length
      || layout->repair_start_offset >= length) {
    return false;
  }
  uint8_t code;
  uint64_t offset = layout->repair_start_offset;
  MpegPesTimes times;
  return mpeg_start_code_at(data, length, offset, &code)
      && mpeg_media_stream_id(code)
      && mpeg_pes_header(data, length, offset, code, length - offset,
                          &times);
}

static inline bool mpeg_layout_authoritative_start(const MpegLayout *layout) {
  return layout && layout->kind == MPEG_KIND_PROGRAM
      && layout->pack_count > 0 && layout->first_scr == 0
      && layout->initial_system_header;
}

static inline bool mpeg_layout_terminal(const uint8_t *data,
                                        uint64_t length,
                                        const MpegLayout *layout) {
  if (!data || !layout || layout->parsed_extent == 0
      || layout->parsed_extent > length) {
    return false;
  }
  if (layout->terminal_marker) {
    return true;
  }
  if (layout->kind != MPEG_KIND_PROGRAM) {
    return false;
  }
  uint64_t end = layout->parsed_extent;
  if (end < length) {
    uint64_t suffix_end = mpeg_uniform_fill_extent(data, length, end);
    if (suffix_end != length) {
      return false;
    }
  }
  uint64_t fill = 0;
  while (fill < end && data[end - fill - 1] == UINT8_C(0xff)) {
    fill++;
  }
  return fill >= MPEG_TERMINAL_FILL_MIN;
}

static inline MpegParseResult mpeg_reassembly_parse_trial(
    const uint8_t *data, uint64_t length, MpegLayout *layout) {
  if (!layout) {
    return MPEG_PARSE_INVALID;
  }
  MpegParseResult result = mpeg_parse_file(data, length, layout);
  if (result != MPEG_PARSE_PARTIAL
      || layout->kind != MPEG_KIND_PROGRAM || layout->timestamp_valid
      || layout->failure_offset == UINT64_MAX
      || layout->failure_offset == 0
      || layout->failure_offset != layout->parsed_extent
      || layout->failure_offset > length) {
    return result;
  }

  MpegLayout trusted;
  MpegParseResult trusted_result = mpeg_parse_file(
      data, layout->failure_offset, &trusted);
  if (trusted_result == MPEG_PARSE_COMPLETE
      && trusted.parsed_extent == layout->failure_offset
      && mpeg_layout_strong(&trusted) && trusted.timestamp_valid) {
    *layout = trusted;
  }
  return result;
}

static inline bool mpeg_position_inside_video_pes(const uint8_t *data,
                                                  uint64_t length,
                                                  uint64_t position) {
  if (!data || position < 7 || position > length) {
    return false;
  }
  uint64_t maximum_packet = (uint64_t)UINT16_MAX + 6;
  uint64_t begin = position > maximum_packet ? position - maximum_packet : 0;
  uint64_t scan = position - 4;
  for (;;) {
    uint8_t code;
    if (mpeg_start_code_at(data, length, scan, &code)
        && code >= UINT8_C(0xe0) && code <= UINT8_C(0xef)
        && scan + 6 <= length) {
      uint64_t packet_length = (uint64_t)mpeg_read_be16(data + scan + 4) + 6;
      uint64_t end = scan + packet_length;
      MpegPesTimes times;
      if (packet_length > 6 && end > position && end <= length
          && mpeg_pes_header(data, length, scan, code, packet_length,
                             &times)) {
        return true;
      }
    }
    if (scan == begin) {
      break;
    }
    scan--;
  }
  return false;
}

static inline bool mpeg_program_contiguous_predecessor(
    const uint8_t *data, uint64_t length, uint64_t position,
    uint64_t *last_scr) {
  if (!data || !last_scr || position < MPEG_MINIMUM_SIZE
      || position > length) {
    return false;
  }
  uint64_t begin = position > MPEG_HEADER_PROBE_BYTES
      ? position - MPEG_HEADER_PROBE_BYTES : 0;
  uint64_t scan = position - 4;
  for (;;) {
    uint8_t code;
    if (mpeg_start_code_at(data, position, scan, &code)
        && code == MPEG_PS_PACK_ID) {
      MpegLayout layout;
      memset(&layout, 0, sizeof(layout));
      layout.failure_offset = UINT64_MAX;
      layout.repair_start_offset = UINT64_MAX;
      layout.continuity_offset = UINT64_MAX;
      layout.last_packet_offset = UINT64_MAX;
      MpegParseResult result = mpeg_parse_program(
          data + scan, position - scan, &layout);
      uint64_t span = position - scan;
      bool exact_boundary = result == MPEG_PARSE_COMPLETE
          && layout.parsed_extent == span;
      if (exact_boundary && layout.pack_count > 0
          && !layout.terminal_marker) {
        *last_scr = layout.last_scr;
        return true;
      }
    }
    if (scan == begin) {
      break;
    }
    scan--;
  }
  return false;
}

static inline bool mpeg_header_at(const uint8_t *data, uint64_t length,
                                  uint64_t position) {
  if (!data || position >= length) {
    return false;
  }
  uint64_t available = length - position;
  if (mpeg_program_header_valid(data + position, available, false)) {
    uint64_t pack_length;
    uint64_t required;
    uint64_t scr;
    uint32_t mux_rate;
    if (!mpeg_pack_header(data + position, available, 0, &pack_length,
                          &required, &scr, &mux_rate)) {
      return false;
    }
    uint8_t code;
    uint64_t system_length;
    bool initial_system_header = mpeg_start_code_at(
        data + position, available, pack_length, &code)
        && code == MPEG_PS_SYSTEM_ID
        && mpeg_system_header(data + position, available, pack_length,
                              &system_length, &required);
    if (!initial_system_header && scr > MPEG_INITIAL_SCR_MAX) {
      return false;
    }
    uint64_t previous_scr;
    if (!mpeg_program_contiguous_predecessor(data, length, position,
                                             &previous_scr)) {
      return true;
    }
    return initial_system_header
        && (scr <= MPEG_INITIAL_SCR_MAX
            || !mpeg_clock_forward(previous_scr, scr));
  }

  uint32_t stride;
  uint32_t sync_offset;
  if (mpeg_transport_header_valid(data + position, available, &stride,
                                  &sync_offset)) {
    if (position >= stride
        && mpeg_transport_packet_valid(data + position - stride + sync_offset,
                                       188)) {
      return false;
    }
    return true;
  }

  return mpeg_elementary_header_valid(data + position, available)
      && !mpeg_position_inside_video_pes(data, length, position);
}

static inline bool mpeg_carve_state_valid(const MpegCarveState *state) {
  if (!state || state->magic != MPEG_CARVE_STATE_MAGIC
      || state->version != MPEG_CARVE_STATE_VERSION
      || state->branch_depth > MPEG_REPAIR_BRANCH_DEPTH
      || state->branch_alternative_count > MPEG_REPAIR_BRANCH_ALTERNATIVES
      || state->candidate_count > MPEG_REPAIR_CANDIDATES) {
    return false;
  }
  for (uint32_t depth = 0; depth < state->branch_depth; depth++) {
    const MpegRepairBranch *branch = &state->branches[depth];
    if (branch->first_alternative > state->branch_alternative_count
        || branch->alternative_count > state->branch_alternative_count
            - branch->first_alternative
        || branch->next_alternative > branch->alternative_count
        || branch->prefix_blocks == 0 || branch->prefix_run_count == 0
        || branch->prefix_run_count > branch->prefix_blocks
        || branch->prefix_run_count > SIZE_MAX / sizeof(MpegMappingRun)) {
      return false;
    }
  }
  return true;
}

// Check encoded runs independently of apparent block numbering, which can
// change at a checkpoint when other candidates cover blocks.
static inline bool mpeg_repair_prefix_valid(const MpegRepairBranch *branch) {
  if (!branch || !branch->prefix_runs || branch->prefix_run_count == 0
      || branch->prefix_run_count > branch->prefix_blocks
      || scalpel_state.blocksize == 0
      || branch->prefix_blocks > UINT64_MAX / scalpel_state.blocksize
      || branch->prefix_length
          > branch->prefix_blocks * (uint64_t)scalpel_state.blocksize) {
    return false;
  }
  uint64_t blocks = 0;
  for (uint64_t index = 0; index < branch->prefix_run_count; index++) {
    const MpegMappingRun *run = &branch->prefix_runs[index];
    if (run->first_actual < 0 || run->block_count == 0
        || run->block_count > branch->prefix_blocks - blocks
        || run->block_count - 1
            > (uint64_t)(INT64_MAX - run->first_actual)) {
      return false;
    }
    blocks += run->block_count;
  }
  return blocks == branch->prefix_blocks;
}

static inline bool mpeg_serialize_carve_state(void **state, FILE *fp,
                                             StateSerialization mode) {
  MpegCarveState **mpeg_state = (MpegCarveState **)state;
  if (!mpeg_state || !fp) {
    return false;
  }
  if (mode == DESERIALIZE) {
    *mpeg_state = (MpegCarveState *)calloc(1, sizeof(**mpeg_state));
    check_memory_allocation(*mpeg_state, __LINE__, __FILE__,
                            "MpegCarveState");
  }
  bool valid = false;
  if (mode == SERIALIZE && mpeg_carve_state_valid(*mpeg_state)) {
    MpegCarveState wire = **mpeg_state;
    for (uint32_t depth = 0; depth < MPEG_REPAIR_BRANCH_DEPTH; depth++) {
      wire.branches[depth].prefix_runs = NULL;
    }
    valid = fwrite(&wire, sizeof(wire), 1, fp) == 1;
  }
  else if (mode == DESERIALIZE) {
    valid = fread(*mpeg_state, sizeof(**mpeg_state), 1, fp) == 1;
    for (uint32_t depth = 0; depth < MPEG_REPAIR_BRANCH_DEPTH; depth++) {
      (*mpeg_state)->branches[depth].prefix_runs = NULL;
    }
    valid = valid && mpeg_carve_state_valid(*mpeg_state);
  }
  for (uint32_t depth = 0; valid && depth < (*mpeg_state)->branch_depth;
       depth++) {
    MpegRepairBranch *branch = &(*mpeg_state)->branches[depth];
    size_t bytes = (size_t)branch->prefix_run_count
        * sizeof(*branch->prefix_runs);
    if (mode == DESERIALIZE) {
      branch->prefix_runs = (MpegMappingRun *)malloc(bytes);
      check_memory_allocation(branch->prefix_runs, __LINE__, __FILE__,
                              "MPEG checkpoint prefix runs");
      valid = fread(branch->prefix_runs, bytes, 1, fp) == 1
          && mpeg_repair_prefix_valid(branch);
    }
    else {
      valid = mpeg_repair_prefix_valid(branch)
          && fwrite(branch->prefix_runs, bytes, 1, fp) == 1;
    }
  }
  if (!valid) {
    if (mode == DESERIALIZE) {
      mpeg_free_carve_state(state);
    }
    handle_error(SCALPEL_ERROR_CHECKPOINT, "invalid MPEG carve state",
                 __LINE__, __FILE__);
    return false;
  }
  return true;
}

static inline void *mpeg_clone_carve_state(const void *state) {
  const MpegCarveState *source = (const MpegCarveState *)state;
  if (!mpeg_carve_state_valid(source)) {
    return NULL;
  }
  MpegCarveState *copy = (MpegCarveState *)malloc(sizeof(*copy));
  check_memory_allocation(copy, __LINE__, __FILE__, "MpegCarveState");
  memcpy(copy, source, sizeof(*copy));
  for (uint32_t depth = 0; depth < MPEG_REPAIR_BRANCH_DEPTH; depth++) {
    copy->branches[depth].prefix_runs = NULL;
  }
  for (uint32_t depth = 0; depth < source->branch_depth; depth++) {
    const MpegRepairBranch *branch = &source->branches[depth];
    if (!mpeg_repair_prefix_valid(branch)) {
      mpeg_free_carve_state((void **)&copy);
      return NULL;
    }
    size_t bytes = (size_t)branch->prefix_run_count
        * sizeof(*branch->prefix_runs);
    copy->branches[depth].prefix_runs = (MpegMappingRun *)malloc(bytes);
    check_memory_allocation(copy->branches[depth].prefix_runs, __LINE__,
                            __FILE__, "MPEG cloned prefix runs");
    memcpy(copy->branches[depth].prefix_runs, branch->prefix_runs, bytes);
  }
  return copy;
}

static inline void mpeg_free_carve_state(void **state) {
  if (state && *state) {
    MpegCarveState *mpeg_state = (MpegCarveState *)*state;
    for (uint32_t depth = 0; depth < MPEG_REPAIR_BRANCH_DEPTH; depth++) {
      free(mpeg_state->branches[depth].prefix_runs);
    }
    free(mpeg_state);
    *state = NULL;
  }
}

static inline size_t mpeg_sizeof_carve_state(const void *state) {
  const MpegCarveState *mpeg_state = (const MpegCarveState *)state;
  if (!mpeg_carve_state_valid(mpeg_state)) {
    return 0;
  }
  size_t bytes = sizeof(*mpeg_state);
  for (uint32_t depth = 0; depth < mpeg_state->branch_depth; depth++) {
    const MpegRepairBranch *branch = &mpeg_state->branches[depth];
    if (branch->prefix_run_count
        > (SIZE_MAX - bytes) / sizeof(*branch->prefix_runs)) {
      return SIZE_MAX;
    }
    bytes += (size_t)branch->prefix_run_count * sizeof(*branch->prefix_runs);
  }
  return bytes;
}

static inline void mpeg_print_carve_state(const void *state) {
  const MpegCarveState *mpeg_state = (const MpegCarveState *)state;
  if (!mpeg_carve_state_valid(mpeg_state)) {
    fprintf(stdout, "NULL");
    return;
  }
  fprintf(stdout,
          "targets=%" PRIu64 "-%" PRIu64
          " next=%" PRIu64 " candidates=%" PRIu32
          " trial=%" PRIu32 " repairs=%" PRIu64,
          mpeg_state->first_target_slot, mpeg_state->last_target_slot,
          mpeg_state->next_anchor_actual, mpeg_state->candidate_count,
          mpeg_state->trial_index, mpeg_state->repairs);
}

static inline char *mpeg_header_discovery(char *base, uint64_t offset,
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
  if (remaining > UINT64_MAX - offset) {
    return NULL;
  }
  const uint8_t *data = (const uint8_t *)base;
  uint64_t length = offset + remaining;
  for (uint64_t position = offset;
       position + MPEG_MINIMUM_SIZE <= length;
       position++) {
    if (data[position] != 0 && data[position] != MPEG_TS_SYNC) {
      continue;
    }
    if (mpeg_header_at(data, length, position)) {
      *matchpos = (char *)data + position;
      *matchlen = data[position] == MPEG_TS_SYNC ? 1U : 4U;
      return NULL;
    }
  }
  return NULL;
}

static inline char *mpeg_footer_discovery(char *base, uint64_t offset,
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
  if (remaining > UINT64_MAX - offset) {
    return NULL;
  }
  const uint8_t *data = (const uint8_t *)base;
  uint64_t length = offset + remaining;
  for (uint64_t position = offset;
       position + MPEG_MINIMUM_SIZE <= length;
       position++) {
    if (data[position] != 0 && data[position] != MPEG_TS_SYNC) {
      continue;
    }
    if (!mpeg_header_at(data, length, position)) {
      continue;
    }
    MpegLayout layout;
    MpegParseResult result = mpeg_parse_file(data + position,
                                             length - position,
                                             &layout);
    uint64_t extent = layout.parsed_extent;
    if (result != MPEG_PARSE_COMPLETE && layout.failure_offset != UINT64_MAX
        && layout.failure_offset > extent) {
      extent = layout.failure_offset;
    }
    if (result == MPEG_PARSE_INVALID || !mpeg_layout_strong(&layout)
        || extent < MPEG_MINIMUM_SIZE || extent > length - position) {
      continue;
    }
    *matchpos = (char *)data + position + extent - 1;
    *matchlen = 1;
    return NULL;
  }
  return NULL;
}

static inline uint32_t mpeg_block_validate(
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
  uint32_t evidence = 0;
  for (uint64_t position = 0; position + 14 <= length; position++) {
    if (bytes[position] == MPEG_TS_SYNC && position + 188 * 3 < length
        && bytes[position + 188] == MPEG_TS_SYNC
        && bytes[position + 188 * 2] == MPEG_TS_SYNC
        && bytes[position + 188 * 3] == MPEG_TS_SYNC) {
      evidence += 4;
      position += 187;
      continue;
    }
    if (bytes[position] != 0 || bytes[position + 1] != 0
        || bytes[position + 2] != 1) {
      continue;
    }
    uint8_t code = bytes[position + 3];
    if (code == MPEG_PS_PACK_ID) {
      uint64_t header_length;
      uint64_t required;
      uint64_t scr;
      uint32_t mux_rate;
      if (mpeg_pack_header(bytes, length, position, &header_length,
                           &required, &scr, &mux_rate)) {
        evidence += 4;
      }
    }
    else if (code == MPEG_PS_SEQUENCE_ID
             && mpeg_elementary_header_valid(bytes + position,
                                             length - position)) {
      evidence += 3;
    }
    else if (mpeg_media_stream_id(code) && position + 9 <= length) {
      evidence++;
    }
  }
  uint32_t confidence = evidence >= 8 ? MPEG_PAYLOAD_CONFIDENCE_MAX
      : evidence >= 4 ? 90U : evidence >= 2 ? 70U : evidence > 0 ? 40U : 0U;
  if (confidence > (uint32_t)*decision) {
    *decision = (BlockValidationDecision)confidence;
  }
  return needleidx;
}

static inline void mpeg_file_validate(char *data, uint64_t length,
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
  MpegLayout layout;
  MpegParseResult result = mpeg_parse_file((const uint8_t *)data, length,
                                           &layout);
  if (!mpeg_layout_structural(&layout)) {
    return;
  }
  uint64_t extent = layout.parsed_extent;
  if (result != MPEG_PARSE_COMPLETE && layout.failure_offset != UINT64_MAX
      && layout.failure_offset > extent) {
    extent = layout.failure_offset;
  }
  if (extent == 0 || extent > length) {
    extent = length;
  }
  *validates_to = extent > 0 ? extent - 1 : 0;
  *promising = true;
  // Container structure cannot prove the provenance of compressed payload.
  // Keep structurally complete MPEG streams available for independent review.
}

static inline bool mpeg_candidate_contiguous(const CarveInfo *candidate) {
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

static inline void mpeg_candidate_validate(CarveInfo *candidate,
                                           bool *validates,
                                           uint64_t *validates_to,
                                           bool *promising) {
  if (!candidate || !candidate->b || !validates || !validates_to
      || !promising) {
    return;
  }
  uint64_t length = blockvector_get_non_peekahead_data_length(candidate->b);
  uint64_t available = blockvector_get_data_length(candidate->b);
  if (length == 0 || length > available) {
    length = available;
  }
  MpegLayout layout;
  MpegParseResult result = mpeg_parse_file(
      (const uint8_t *)blockvector_get_data_pointer(candidate->b), length,
      &layout);
  if (*validates && result == MPEG_PARSE_COMPLETE
      && (!mpeg_candidate_contiguous(candidate)
          || !mpeg_layout_authoritative_start(&layout))) {
    *validates = false;
    *promising = true;
  }
}

static inline uint64_t mpeg_reassembly_signature(
    const CarveInfo *candidate, const MpegLayout *layout,
    uint64_t anchor_offset) {
  if (!candidate || !candidate->b || !layout) {
    return 0;
  }
  uint64_t signature = UINT64_C(1469598103934665603);
  signature ^= (uint64_t)blockvector_get_actual_blocknumber(candidate->b, 0);
  signature *= UINT64_C(1099511628211);
  signature ^= blockvector_get_num_blocks(candidate->b);
  signature *= UINT64_C(1099511628211);
  signature ^= layout->parsed_extent;
  signature *= UINT64_C(1099511628211);
  signature ^= anchor_offset;
  signature *= UINT64_C(1099511628211);
  signature ^= layout->last_scr;
  signature *= UINT64_C(1099511628211);
  signature ^= layout->last_pts;
  signature *= UINT64_C(1099511628211);
  return signature;
}

static inline void mpeg_reassembly_clear_terminal_candidates(
    MpegCarveState *state) {
  if (!state) {
    return;
  }
  memset(state->terminal_candidates, 0,
         sizeof(state->terminal_candidates));
  memset(state->substitution_terminal_candidates, 0,
         sizeof(state->substitution_terminal_candidates));
  memset(state->direct_terminal_candidates, 0,
         sizeof(state->direct_terminal_candidates));
}

static inline void mpeg_reassembly_reset_state(MpegCarveState *state,
                                               uint64_t signature,
                                               uint64_t first_target,
                                               uint64_t last_target,
                                               uint64_t anchor_offset,
                                               uint64_t baseline_progress) {
  if (!state) {
    return;
  }
  memset(state->candidates, 0, sizeof(state->candidates));
  state->signature = signature;
  state->first_target_slot = first_target;
  state->last_target_slot = last_target;
  state->next_anchor_actual = 0;
  state->anchor_offset = anchor_offset;
  state->baseline_progress = baseline_progress;
  state->best_nonterminal_progress = 0;
  state->best_substitution_progress = 0;
  state->matches = 0;
  state->phase = 1;
  state->trial_index = 0;
  state->candidate_count = 0;
  state->best_nonterminal_index = UINT32_MAX;
  state->substitution_candidate_index = UINT32_MAX;
  state->substitution_next_run = 1;
  state->best_substitution_candidate_index = UINT32_MAX;
  state->best_substitution_run_blocks = 0;
  state->boundary_fallback_done = 0;
  state->substitution_terminal_hypotheses = 0;
  state->direct_terminal_hypotheses = 0;
  mpeg_reassembly_clear_terminal_candidates(state);
}

static inline uint64_t mpeg_repair_candidate_cost(
    const MpegRepairCandidate *candidate) {
  if (!candidate) {
    return UINT64_MAX;
  }
  uint64_t locality = candidate->distance / 4;
  uint64_t clock_cost = candidate->clocks > 0
      ? candidate->clock_cost / candidate->clocks : UINT64_MAX / 2;
  return clock_cost > UINT64_MAX - locality
      ? UINT64_MAX : clock_cost + locality;
}

static inline bool mpeg_repair_candidate_better(
    const MpegRepairCandidate *candidate,
    const MpegRepairCandidate *current) {
  if (!candidate || !current) {
    return candidate != NULL;
  }
  if (candidate->mux_mismatches != current->mux_mismatches) {
    return candidate->mux_mismatches < current->mux_mismatches;
  }
  if (candidate->mux_matches != current->mux_matches) {
    return candidate->mux_matches > current->mux_matches;
  }
  uint64_t local_blocks = scalpel_state.blocksize > 0
      ? CEILDIV(MPEG_LOCAL_REPAIR_BYTES, scalpel_state.blocksize) : 0;
  bool candidate_local = candidate->distance <= local_blocks;
  bool current_local = current->distance <= local_blocks;
  if (candidate->fill_continuation && current->fill_continuation
      && candidate_local != current_local) {
    return candidate_local;
  }
  if ((candidate->clocks == 0) != (current->clocks == 0)) {
    return candidate->clocks > 0;
  }
  uint64_t candidate_cost = mpeg_repair_candidate_cost(candidate);
  uint64_t current_cost = mpeg_repair_candidate_cost(current);
  if (candidate_cost != current_cost) {
    return candidate_cost < current_cost;
  }
  if (candidate->profile_match != current->profile_match) {
    return candidate->profile_match > current->profile_match;
  }
  if (candidate->backward_clocks != current->backward_clocks) {
    return candidate->backward_clocks < current->backward_clocks;
  }
  if (candidate->profile_mismatch != current->profile_mismatch) {
    return candidate->profile_mismatch < current->profile_mismatch;
  }
  if (candidate->clocks != current->clocks) {
    return candidate->clocks > current->clocks;
  }
  if (candidate->stream_matches != current->stream_matches) {
    return candidate->stream_matches > current->stream_matches;
  }
  if (candidate->packets != current->packets) {
    return candidate->packets > current->packets;
  }
  if (candidate->trace_bytes != current->trace_bytes) {
    return candidate->trace_bytes > current->trace_bytes;
  }
  if (candidate->confidence != current->confidence) {
    return candidate->confidence > current->confidence;
  }
  if (candidate->reservations != current->reservations) {
    return candidate->reservations < current->reservations;
  }
  if (candidate->distance != current->distance) {
    return candidate->distance < current->distance;
  }
  if (candidate->target_slot != current->target_slot) {
    return candidate->target_slot < current->target_slot;
  }
  return candidate->source_actual < current->source_actual;
}

static inline bool mpeg_repair_terminal_competitive(
    const MpegRepairCandidate *terminal,
    const MpegRepairCandidate *nonterminal) {
  if (!terminal) {
    return false;
  }
  if (terminal->local_continuation) {
    return true;
  }
  if (!nonterminal || !mpeg_repair_candidate_better(nonterminal, terminal)) {
    return true;
  }

  // Clock direction and stream profile are stronger than a terminal marker
  // reached through an unrelated byte run.
  if (terminal->backward_clocks != nonterminal->backward_clocks
      || terminal->profile_mismatch != nonterminal->profile_mismatch
      || terminal->profile_match != nonterminal->profile_match
      || terminal->mux_mismatches != nonterminal->mux_mismatches
      || terminal->mux_matches != nonterminal->mux_matches
      || ((terminal->clocks == 0) != (nonterminal->clocks == 0))) {
    return false;
  }

  uint64_t terminal_cost = mpeg_repair_candidate_cost(terminal);
  uint64_t nonterminal_cost = mpeg_repair_candidate_cost(nonterminal);
  if (nonterminal_cost == UINT64_MAX) {
    return true;
  }
  if (nonterminal_cost > UINT64_MAX / MPEG_TERMINAL_COST_FACTOR) {
    return true;
  }
  return terminal_cost <= nonterminal_cost * MPEG_TERMINAL_COST_FACTOR;
}

static inline bool mpeg_repair_same_alignment(
    const MpegRepairCandidate *left, const MpegRepairCandidate *right) {
  if (!left || !right) {
    return false;
  }
  if (left->target_slot == right->target_slot) {
    return left->source_actual == right->source_actual;
  }
  if (left->target_slot > right->target_slot) {
    uint64_t delta = left->target_slot - right->target_slot;
    return delta <= (uint64_t)INT64_MAX
        && right->source_actual <= INT64_MAX - (int64_t)delta
        && left->source_actual == right->source_actual + (int64_t)delta;
  }
  uint64_t delta = right->target_slot - left->target_slot;
  return delta <= (uint64_t)INT64_MAX
      && left->source_actual <= INT64_MAX - (int64_t)delta
      && right->source_actual == left->source_actual + (int64_t)delta;
}

// Save only the prefix shared by this branch's trials, coalescing consecutive
// physical blocks. No candidate bytes or reservations are held by this copy.
static inline bool mpeg_reassembly_capture_prefix(
    MpegRepairBranch *branch, BlockVector *blockvector, uint64_t blocks) {
  if (!branch || branch->prefix_runs || !blockvector || blocks == 0
      || blocks > blockvector_get_num_blocks(blockvector)
      || scalpel_state.blocksize == 0
      || blocks > UINT64_MAX / scalpel_state.blocksize) {
    return false;
  }
  uint64_t runs = 0;
  int64_t previous = -1;
  for (uint64_t slot = 0; slot < blocks; slot++) {
    int64_t actual = blockvector_get_actual_blocknumber(blockvector, slot);
    if (actual < 0) {
      return false;
    }
    if (slot == 0 || previous == INT64_MAX || actual != previous + 1) {
      runs++;
    }
    previous = actual;
  }
  if (runs > SIZE_MAX / sizeof(MpegMappingRun)) {
    return false;
  }
  MpegMappingRun *mapping = (MpegMappingRun *)calloc(
      (size_t)runs, sizeof(*mapping));
  check_memory_allocation(mapping, __LINE__, __FILE__, "MPEG prefix runs");
  uint64_t count = 0;
  previous = -1;
  for (uint64_t slot = 0; slot < blocks; slot++) {
    int64_t actual = blockvector_get_actual_blocknumber(blockvector, slot);
    if (slot == 0 || previous == INT64_MAX || actual != previous + 1) {
      mapping[count].first_actual = actual;
      count++;
    }
    mapping[count - 1].block_count++;
    previous = actual;
  }
  branch->prefix_runs = mapping;
  branch->prefix_run_count = runs;
  branch->prefix_blocks = blocks;
  uint64_t capacity = blocks * (uint64_t)scalpel_state.blocksize;
  branch->prefix_length = blockvector_get_data_length(blockvector);
  if (branch->prefix_length > capacity) {
    branch->prefix_length = capacity;
  }
  return true;
}

// Resolve physical identities against the current block map before replacing
// a trial prefix. A rejected restoration leaves the current candidate intact.
static inline bool mpeg_reassembly_restore_prefix(
    CarveInfo *candidate, const MpegRepairBranch *branch, uint64_t blocks,
    uint64_t image_blocks) {
  if (!candidate || !candidate->b || blocks == 0
      || !mpeg_repair_prefix_valid(branch) || blocks > branch->prefix_blocks) {
    return false;
  }
  uint64_t slot = 0;
  for (uint64_t index = 0; index < branch->prefix_run_count && slot < blocks;
       index++) {
    const MpegMappingRun *run = &branch->prefix_runs[index];
    uint64_t count = run->block_count;
    if (count > blocks - slot) {
      count = blocks - slot;
    }
    for (uint64_t offset = 0; offset < count; offset++) {
      int64_t actual = run->first_actual + (int64_t)offset;
      if ((uint64_t)actual >= image_blocks
          || filemirror_actual_block_covered(scalpel_state.filemirror, actual)
          || filemirror_apparent_blocknumber(scalpel_state.filemirror,
                                             actual) < 0) {
        return false;
      }
    }
    slot += count;
  }

  resize_blockvector(candidate->b, blocks);
  slot = 0;
  for (uint64_t index = 0; index < branch->prefix_run_count && slot < blocks;
       index++) {
    const MpegMappingRun *run = &branch->prefix_runs[index];
    uint64_t count = run->block_count;
    if (count > blocks - slot) {
      count = blocks - slot;
    }
    for (uint64_t offset = 0; offset < count; offset++) {
      int64_t actual = run->first_actual + (int64_t)offset;
      int64_t apparent = filemirror_apparent_blocknumber(
          scalpel_state.filemirror, actual);
      blockvector_set_apparent_blocknumber(candidate->b, slot++, apparent);
    }
  }
  uint64_t capacity = blocks * (uint64_t)scalpel_state.blocksize;
  blockvector_set_data_length(candidate->b,
      branch->prefix_length < capacity ? branch->prefix_length : capacity);
  inflate_blockvector(candidate->b);
  return true;
}

static inline uint32_t mpeg_reassembly_prepare_branch(
    MpegCarveState *state, BlockVector *blockvector) {
  if (!state || state->best_nonterminal_index >= state->candidate_count
      || scalpel_state.blocksize == 0) {
    return UINT32_MAX;
  }

  const uint32_t selected_index = state->best_nonterminal_index;
  const MpegRepairCandidate *selected = &state->candidates[selected_index];
  for (uint32_t depth = 0; depth < state->branch_depth; depth++) {
    if (state->branches[depth].bridge) {
      return selected_index;
    }
  }
  uint64_t packet_span = CEILDIV((uint64_t)UINT16_MAX,
                                 scalpel_state.blocksize) + 1;
  uint32_t alternatives[MPEG_REPAIR_CANDIDATES];
  uint32_t count = 0;
  for (uint32_t index = 0; index < state->candidate_count; index++) {
    const MpegRepairCandidate *candidate = &state->candidates[index];
    uint64_t target_delta = candidate->target_slot >= selected->target_slot
        ? candidate->target_slot - selected->target_slot
        : selected->target_slot - candidate->target_slot;
    if (candidate->nonterminal_progress
        && candidate->parsed_progress == state->best_nonterminal_progress
        && target_delta <= packet_span
        && mpeg_repair_same_alignment(candidate, selected)) {
      uint32_t position = count;
      while (position > 0) {
        const MpegRepairCandidate *previous =
            &state->candidates[alternatives[position - 1]];
        if (previous->target_slot > candidate->target_slot
            || (previous->target_slot == candidate->target_slot
                && mpeg_repair_candidate_better(previous, candidate))) {
          break;
        }
        alternatives[position] = alternatives[position - 1];
        position--;
      }
      alternatives[position] = index;
      count++;
    }
  }
  if (count < 2 || state->branch_depth >= MPEG_REPAIR_BRANCH_DEPTH
      || count > MPEG_REPAIR_BRANCH_ALTERNATIVES
          - state->branch_alternative_count) {
    return selected_index;
  }

  MpegRepairBranch *branch = &state->branches[state->branch_depth];
  if (!mpeg_reassembly_capture_prefix(branch, blockvector,
          state->candidates[alternatives[0]].target_slot)) {
    return selected_index;
  }
  state->branch_depth++;
  branch->baseline_progress = state->baseline_progress;
  branch->first_alternative = state->branch_alternative_count;
  branch->alternative_count = count;
  branch->next_alternative = 1;
  branch->bridge = 0;
  for (uint32_t position = 0; position < count; position++) {
    const MpegRepairCandidate *candidate =
        &state->candidates[alternatives[position]];
    MpegRepairAlternative *alternative =
        &state->branch_alternatives[state->branch_alternative_count++];
    alternative->source_actual = candidate->source_actual;
    alternative->target_slot = candidate->target_slot;
    alternative->anchor_source_offset = candidate->anchor_source_offset;
    alternative->bridge_run_blocks = 0;
  }
  return alternatives[0];
}

static inline uint32_t mpeg_reassembly_prepare_bridge_branch(
    MpegCarveState *state, BlockVector *blockvector, bool *primary_direct) {
  if (primary_direct) {
    *primary_direct = false;
  }
  if (!state
      || state->best_substitution_candidate_index >= state->candidate_count) {
    return UINT32_MAX;
  }

  const uint32_t selected_index =
      state->best_substitution_candidate_index;
  if (state->branch_depth != 0) {
    return selected_index;
  }
  uint32_t alternatives[MPEG_REPAIR_CANDIDATES + 1];
  uint8_t direct_alternatives[MPEG_REPAIR_CANDIDATES + 1] = {0};
  uint32_t count = 0;
  // Preserve every byte-distinct bridge so later structure can resolve
  // hypotheses that are indistinguishable at this boundary.
  for (uint32_t index = 0; index < state->candidate_count; index++) {
    const MpegRepairCandidate *candidate = &state->candidates[index];
    if (candidate->bridge_run_blocks == 0
        || candidate->bridge_progress
            != state->best_substitution_progress) {
      continue;
    }

    uint32_t duplicate = UINT32_MAX;
    for (uint32_t position = 0; position < count; position++) {
      const MpegRepairCandidate *current =
          &state->candidates[alternatives[position]];
      if (candidate->target_slot == current->target_slot
          && candidate->source_actual == current->source_actual
          && candidate->bridge_run_blocks == current->bridge_run_blocks) {
        duplicate = position;
        break;
      }
    }
    if (duplicate < count) {
      const MpegRepairCandidate *current =
          &state->candidates[alternatives[duplicate]];
      if (mpeg_repair_candidate_better(candidate, current)) {
        alternatives[duplicate] = index;
      }
      continue;
    }
    alternatives[count++] = index;
  }

  // Prefer trials that retain more of the current prefix before rewinding.
  for (uint32_t position = 1; position < count; position++) {
    uint32_t candidate_index = alternatives[position];
    uint32_t insertion = position;
    while (insertion > 0) {
      const MpegRepairCandidate *candidate =
          &state->candidates[candidate_index];
      const MpegRepairCandidate *previous =
          &state->candidates[alternatives[insertion - 1]];
      bool candidate_first = candidate->target_slot > previous->target_slot
          || (candidate->target_slot == previous->target_slot
              && mpeg_repair_candidate_better(candidate, previous));
      if (!candidate_first) {
        break;
      }
      alternatives[insertion] = alternatives[insertion - 1];
      insertion--;
    }
    alternatives[insertion] = candidate_index;
  }
  if (count == 0) {
    return selected_index;
  }
  bool preserve_direct =
      state->best_nonterminal_index < state->candidate_count;
  if (preserve_direct) {
    uint32_t direct_index = state->best_nonterminal_index;
    const MpegRepairCandidate *direct = &state->candidates[direct_index];
    uint32_t insertion = 0;
    while (insertion < count
           && state->candidates[alternatives[insertion]].target_slot
               >= direct->target_slot) {
      insertion++;
    }
    for (uint32_t position = count; position > insertion; position--) {
      alternatives[position] = alternatives[position - 1];
      direct_alternatives[position] = direct_alternatives[position - 1];
    }
    alternatives[insertion] = direct_index;
    direct_alternatives[insertion] = 1;
    count++;
  }
  if (count < 2
      || state->branch_depth >= MPEG_REPAIR_BRANCH_DEPTH
      || count > MPEG_REPAIR_BRANCH_ALTERNATIVES
          - state->branch_alternative_count) {
    return selected_index;
  }

  MpegRepairBranch *branch = &state->branches[state->branch_depth];
  if (!mpeg_reassembly_capture_prefix(branch, blockvector,
          state->candidates[alternatives[0]].target_slot)) {
    return selected_index;
  }
  state->branch_depth++;
  branch->baseline_progress = state->baseline_progress;
  branch->first_alternative = state->branch_alternative_count;
  branch->alternative_count = count;
  branch->next_alternative = 1;
  branch->bridge = 1;
  for (uint32_t position = 0; position < count; position++) {
    const MpegRepairCandidate *candidate =
        &state->candidates[alternatives[position]];
    MpegRepairAlternative *alternative =
        &state->branch_alternatives[state->branch_alternative_count++];
    alternative->source_actual = candidate->source_actual;
    alternative->target_slot = candidate->target_slot;
    alternative->anchor_source_offset = candidate->anchor_source_offset;
    alternative->bridge_run_blocks = direct_alternatives[position]
        ? 0 : candidate->bridge_run_blocks;
  }
  if (primary_direct) {
    *primary_direct = direct_alternatives[0] != 0;
  }
  return alternatives[0];
}

static inline void mpeg_reassembly_add_candidate(
    MpegCarveState *state, const MpegRepairCandidate *candidate) {
  if (!state || !candidate || candidate->source_actual < 0) {
    return;
  }
  for (uint32_t index = 0; index < state->candidate_count; index++) {
    MpegRepairCandidate *current = &state->candidates[index];
    bool same_mapping = current->source_actual == candidate->source_actual
        && current->target_slot == candidate->target_slot;
    if (same_mapping) {
      if (!mpeg_repair_candidate_better(candidate, current)) {
        return;
      }
    }
    else {
      continue;
    }
    if (same_mapping) {
      if (index + 1 < state->candidate_count) {
        memmove(current, current + 1,
                (state->candidate_count - index - 1) * sizeof(*current));
      }
      state->candidate_count--;
      break;
    }
  }

  if (!candidate->fill_continuation) {
    uint32_t region_count = 0;
    uint32_t region_worst = UINT32_MAX;
    for (uint32_t index = 0; index < state->candidate_count; index++) {
      const MpegRepairCandidate *current = &state->candidates[index];
      bool overlapping_run = !current->fill_continuation
          && candidate->run_first_actual <= current->run_last_actual
          && current->run_first_actual <= candidate->run_last_actual;
      if (overlapping_run) {
        region_count++;
        region_worst = index;
      }
    }
    if (region_count >= MPEG_REPAIR_REGION_CANDIDATES) {
      if (region_worst >= state->candidate_count
          || !mpeg_repair_candidate_better(
              candidate, &state->candidates[region_worst])) {
        return;
      }
      if (region_worst + 1 < state->candidate_count) {
        memmove(&state->candidates[region_worst],
                &state->candidates[region_worst + 1],
                (state->candidate_count - region_worst - 1)
                    * sizeof(state->candidates[0]));
      }
      state->candidate_count--;
    }
  }

  uint32_t position = state->candidate_count;
  if (position < MPEG_REPAIR_CANDIDATES) {
    state->candidate_count++;
  }
  else {
    position = MPEG_REPAIR_CANDIDATES - 1;
    if (!mpeg_repair_candidate_better(candidate,
                                      &state->candidates[position])) {
      return;
    }
  }
  while (position > 0
         && mpeg_repair_candidate_better(candidate,
                                         &state->candidates[position - 1])) {
    if (position < MPEG_REPAIR_CANDIDATES) {
      state->candidates[position] = state->candidates[position - 1];
    }
    position--;
  }
  state->candidates[position] = *candidate;
}

static inline bool mpeg_reassembly_checkpoint(
    ThreadWork *work, CarveInfo **candidate, MpegCarveState *state,
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

static inline int mpeg_prefix_block_compare(const void *left,
                                            const void *right) {
  const MpegPrefixBlock *a = (const MpegPrefixBlock *)left;
  const MpegPrefixBlock *b = (const MpegPrefixBlock *)right;
  if (a->actual != b->actual) {
    return a->actual < b->actual ? -1 : 1;
  }
  return a->slot < b->slot ? -1 : a->slot != b->slot;
}

static inline MpegPrefixBlock *mpeg_reassembly_prefix_index(
    BlockVector *blockvector, uint64_t *count) {
  if (!blockvector || !count) {
    return NULL;
  }
  *count = blockvector_get_num_blocks(blockvector);
  if (*count == 0 || *count > SIZE_MAX / sizeof(MpegPrefixBlock)) {
    return NULL;
  }
  MpegPrefixBlock *index = (MpegPrefixBlock *)malloc(
      (size_t)(*count) * sizeof(*index));
  check_memory_allocation(index, __LINE__, __FILE__,
                          "MPEG prefix block index");
  for (uint64_t slot = 0; slot < *count; slot++) {
    index[slot].actual = blockvector_get_actual_blocknumber(blockvector, slot);
    index[slot].slot = slot;
  }
  qsort(index, (size_t)*count, sizeof(*index), mpeg_prefix_block_compare);
  return index;
}

static inline bool mpeg_reassembly_actual_in_prefix(
    const MpegPrefixBlock *index, uint64_t count, int64_t actual,
    uint64_t prefix_blocks) {
  if (!index || count == 0 || actual < 0 || prefix_blocks == 0) {
    return false;
  }
  uint64_t low = 0;
  uint64_t high = count;
  while (low < high) {
    uint64_t middle = low + (high - low) / 2;
    if (index[middle].actual < actual) {
      low = middle + 1;
    }
    else {
      high = middle;
    }
  }
  for (uint64_t position = low;
       position < count && index[position].actual == actual; position++) {
    if (index[position].slot < prefix_blocks) {
      return true;
    }
  }
  return false;
}

static inline bool mpeg_reassembly_copy_physical(
    int64_t first_actual, uint64_t first_offset, uint8_t *buffer,
    uint64_t requested, uint64_t image_blocks) {
  if (first_actual < 0 || !buffer || requested == 0
      || scalpel_state.blocksize == 0
      || first_offset >= scalpel_state.blocksize) {
    return false;
  }
  uint64_t copied = 0;
  uint64_t block_delta = 0;
  while (copied < requested) {
    if (block_delta > (uint64_t)INT64_MAX
        || first_actual > INT64_MAX - (int64_t)block_delta) {
      return false;
    }
    int64_t actual = first_actual + (int64_t)block_delta;
    if (actual < 0 || (uint64_t)actual >= image_blocks
        || filemirror_actual_block_covered(scalpel_state.filemirror, actual)) {
      return false;
    }
    uint64_t available = 0;
    const uint8_t *data = (const uint8_t *)
        filemirror_actual_block_data_pointer(scalpel_state.filemirror, actual,
                                             &available);
    uint64_t offset = block_delta == 0 ? first_offset : 0;
    if (!data || offset >= available) {
      return false;
    }
    uint64_t count = available - offset;
    if (count > requested - copied) {
      count = requested - copied;
    }
    memcpy(buffer + copied, data + offset, (size_t)count);
    copied += count;
    block_delta++;
  }
  return true;
}

static inline uint64_t mpeg_reassembly_physical_bytes(
    int64_t first_actual, uint64_t first_offset, uint64_t maximum,
    uint64_t image_blocks) {
  if (first_actual < 0 || maximum == 0 || scalpel_state.blocksize == 0
      || first_offset >= scalpel_state.blocksize) {
    return 0;
  }
  uint64_t total = 0;
  uint64_t block_delta = 0;
  while (total < maximum) {
    if (block_delta > (uint64_t)INT64_MAX
        || first_actual > INT64_MAX - (int64_t)block_delta) {
      break;
    }
    int64_t actual = first_actual + (int64_t)block_delta;
    if (actual < 0 || (uint64_t)actual >= image_blocks
        || filemirror_actual_block_covered(scalpel_state.filemirror, actual)) {
      break;
    }
    uint64_t available = 0;
    const uint8_t *data = (const uint8_t *)
        filemirror_actual_block_data_pointer(scalpel_state.filemirror, actual,
                                             &available);
    uint64_t offset = block_delta == 0 ? first_offset : 0;
    if (!data || offset >= available) {
      break;
    }
    uint64_t count = available - offset;
    if (count > maximum - total) {
      count = maximum - total;
    }
    total += count;
    block_delta++;
  }
  return total;
}

static inline bool mpeg_reassembly_fill_anchor(
    const uint8_t *data, uint64_t length, uint8_t fill,
    uint64_t *anchor_offset) {
  if (!data || !anchor_offset || length < 4 || data[0] != fill
      || (fill != 0 && fill != UINT8_C(0xff))) {
    return false;
  }
  for (uint64_t position = 0; position + 4 <= length; position++) {
    if (data[position] == 0 && data[position + 1] == 0
        && data[position + 2] == 1
        && data[position + 3] == MPEG_PS_PACK_ID) {
      for (uint64_t check = 0; check < position; check++) {
        if (data[check] != fill) {
          return false;
        }
      }
      *anchor_offset = position;
      return true;
    }
    if (data[position] != fill) {
      return false;
    }
  }
  return false;
}

static inline uint32_t mpeg_reassembly_video_signature(
    const uint8_t *data, uint64_t length) {
  if (!data || length < 12) {
    return 0;
  }
  for (uint64_t position = 0; position + 12 <= length; position++) {
    if (data[position] == 0 && data[position + 1] == 0
        && data[position + 2] == 1
        && data[position + 3] == MPEG_PS_SEQUENCE_ID
        && mpeg_elementary_header_valid(data + position,
                                        length - position)) {
      return ((uint32_t)data[position + 4] << 24)
          | ((uint32_t)data[position + 5] << 16)
          | ((uint32_t)data[position + 6] << 8)
          | (uint32_t)data[position + 7];
    }
  }
  return 0;
}

static inline uint64_t mpeg_reassembly_clock_cost(
    uint64_t previous, uint64_t expected_step, uint64_t current,
    bool *backward) {
  if (!backward) {
    return UINT64_MAX;
  }
  *backward = false;
  uint64_t delta = (current - previous) & MPEG_CLOCK_MASK;
  if (delta > (UINT64_C(1) << 32)) {
    *backward = true;
    return UINT64_MAX / 4;
  }
  if (delta == 0 || expected_step == 0) {
    return delta;
  }
  uint64_t multiple = (delta + expected_step / 2) / expected_step;
  if (multiple == 0) {
    multiple = 1;
  }
  uint64_t expected = multiple > UINT64_MAX / expected_step
      ? UINT64_MAX : multiple * expected_step;
  uint64_t deviation = delta > expected ? delta - expected : expected - delta;
  return delta > UINT64_MAX - deviation ? UINT64_MAX : delta + deviation;
}

static inline bool mpeg_reassembly_trace_anchor(
    const uint8_t *data, uint64_t length, const MpegLayout *prefix,
    MpegRepairCandidate *evidence) {
  if (!data || !prefix || !evidence || length < 4) {
    return false;
  }
  memset(evidence, 0, sizeof(*evidence));
  bool compared_scr = false;
  bool compared_mux = false;
  bool compared_clock[256] = {false};
  bool matched_stream[256] = {false};
  bool have_local_scr = prefix->pack_count > 0;
  uint64_t local_scr = prefix->last_scr;
  uint8_t have_local_pts[256];
  uint64_t local_pts[256];
  uint64_t local_dts[256];
  memcpy(have_local_pts, prefix->stream_pts_seen, sizeof(have_local_pts));
  memcpy(local_pts, prefix->stream_last_pts, sizeof(local_pts));
  memcpy(local_dts, prefix->stream_last_dts, sizeof(local_dts));

  uint64_t position = 0;
  while (position + 4 <= length) {
    uint8_t code;
    if (!mpeg_start_code_at(data, length, position, &code)) {
      uint64_t continuation;
      if (mpeg_fill_to_next_pack(data, length, position, &continuation)) {
        position = continuation;
        continue;
      }
      break;
    }
    if (code == MPEG_PS_PACK_ID) {
      uint64_t packet_length;
      uint64_t required;
      uint64_t scr;
      uint32_t mux_rate;
      if (!mpeg_pack_header(data, length, position, &packet_length,
                            &required, &scr, &mux_rate)) {
        break;
      }
      if (!compared_mux && prefix->pack_count > 0) {
        if (mux_rate == prefix->mux_rate) {
          evidence->mux_matches++;
        }
        else {
          evidence->mux_mismatches++;
        }
        compared_mux = true;
      }
      if (have_local_scr && scr != local_scr) {
        bool backward;
        uint64_t cost = mpeg_reassembly_clock_cost(
            local_scr, prefix->scr_step, scr, &backward);
        if (backward) {
          evidence->backward_clocks++;
          break;
        }
        if (!compared_scr) {
          evidence->clock_cost = cost;
          evidence->clocks++;
          compared_scr = true;
        }
      }
      local_scr = scr;
      have_local_scr = true;
      position += packet_length;
      evidence->packets++;
      continue;
    }
    if (code == MPEG_PS_END_ID) {
      position += 4;
      evidence->packets++;
      break;
    }
    if (code == MPEG_PS_SYSTEM_ID) {
      uint64_t packet_length;
      uint64_t required;
      if (!mpeg_system_header(data, length, position, &packet_length,
                              &required)) {
        break;
      }
      position += packet_length;
      evidence->packets++;
      continue;
    }
    if (!mpeg_system_stream_id(code) || position + 6 > length) {
      break;
    }
    uint64_t packet_length = mpeg_read_be16(data + position + 4) + 6;
    MpegPesTimes times;
    if (packet_length == 6 || packet_length > length - position
        || !mpeg_pes_header(data, length, position, code, packet_length,
                             &times)) {
      break;
    }
    if (prefix->stream_seen[code] && !matched_stream[code]) {
      matched_stream[code] = true;
      evidence->stream_matches++;
    }
    if (times.present && have_local_pts[code]) {
      bool backward;
      uint64_t cost = mpeg_reassembly_clock_cost(
          local_pts[code], prefix->stream_pts_step[code],
          times.presentation, &backward);
      if (!mpeg_clock_forward(local_dts[code], times.decoding)) {
        evidence->backward_clocks++;
        break;
      }
      // B pictures can follow a reference picture with a later PTS. Preserve
      // presentation-distance ranking otherwise, and use DTS at that reversal.
      if (backward) {
        cost = mpeg_reassembly_clock_cost(local_dts[code], 0,
                                          times.decoding, &backward);
      }
      if (!compared_clock[code] && times.presentation != local_pts[code]) {
        evidence->clock_cost = evidence->clock_cost > UINT64_MAX - cost
            ? UINT64_MAX : evidence->clock_cost + cost;
        evidence->clocks++;
        compared_clock[code] = true;
      }
    }
    if (times.present) {
      local_pts[code] = times.presentation;
      local_dts[code] = times.decoding;
      have_local_pts[code] = 1;
    }
    position += packet_length;
    evidence->packets++;
  }

  evidence->trace_bytes = position;
  if (prefix->video_signature != 0 && position > 0) {
    uint32_t signature = mpeg_reassembly_video_signature(data, position);
    if (signature == prefix->video_signature) {
      evidence->profile_match = 1;
    }
    else if (signature != 0) {
      evidence->profile_mismatch = 1;
    }
  }
  return evidence->packets > 0 && evidence->trace_bytes > 0;
}

static inline bool mpeg_reassembly_source_available(
    CarveInfo *candidate, uint64_t target_slot, int64_t source_actual,
    uint64_t through_blocks, uint64_t image_blocks,
    const MpegPrefixBlock *prefix_index, uint64_t prefix_count) {
  if (!candidate || !candidate->b || source_actual < 0
      || through_blocks == 0) {
    return false;
  }
  for (uint64_t index = 0; index < through_blocks; index++) {
    if (index > (uint64_t)INT64_MAX
        || source_actual > INT64_MAX - (int64_t)index) {
      return false;
    }
    int64_t actual = source_actual + (int64_t)index;
    if (actual < 0 || (uint64_t)actual >= image_blocks
        || filemirror_actual_block_covered(scalpel_state.filemirror, actual)) {
      return false;
    }
    if (mpeg_reassembly_actual_in_prefix(prefix_index, prefix_count,
                                         actual, target_slot)) {
      return false;
    }
  }
  return true;
}

static inline bool mpeg_reassembly_add_mapping_candidate(
    MpegCarveState *state, const MpegRepairCandidate *evidence,
    CarveInfo *candidate, BlockVector *blockvector, uint64_t target_slot,
    int64_t source_actual, int64_t anchor_actual,
    uint64_t anchor_source_offset, uint64_t image_blocks,
    const MpegPrefixBlock *prefix_index, uint64_t prefix_count) {
  if (!state || !evidence || !candidate || !blockvector
      || target_slot == 0 || source_actual < 0 || anchor_actual < 0
      || anchor_source_offset > UINT64_MAX - 16) {
    return false;
  }
  uint64_t through_blocks = CEILDIV(anchor_source_offset + 16,
                                    scalpel_state.blocksize);
  if (!mpeg_reassembly_source_available(
          candidate, target_slot, source_actual, through_blocks,
          image_blocks, prefix_index, prefix_count)) {
    return false;
  }

  MpegRepairCandidate repair = *evidence;
  repair.source_actual = source_actual;
  repair.target_slot = target_slot;
  repair.anchor_source_offset = anchor_source_offset;
  int64_t previous_actual = blockvector_get_actual_blocknumber(
      blockvector, target_slot - 1);
  if (previous_actual >= 0 && previous_actual < INT64_MAX) {
    int64_t expected_actual = previous_actual + 1;
    repair.distance = source_actual >= expected_actual
        ? (uint64_t)(source_actual - expected_actual)
        : (uint64_t)(expected_actual - source_actual);
  }
  else {
    repair.distance = UINT64_MAX;
  }
  repair.reservations = scalpel_state.reservations
      ? filemirror_actual_block_reserved(scalpel_state.filemirror,
                                         source_actual) : 0;
  BlockValidationDecision confidence = filemirror_get_blocktype(
      scalpel_state.filemirror, source_actual,
      (uint32_t)candidate->needleidx);
  BlockValidationDecision anchor_confidence = filemirror_get_blocktype(
      scalpel_state.filemirror, anchor_actual,
      (uint32_t)candidate->needleidx);
  if (anchor_confidence > confidence) {
    confidence = anchor_confidence;
  }
  repair.confidence = (uint32_t)confidence;
  mpeg_reassembly_add_candidate(state, &repair);
  state->matches++;
  return true;
}

static inline void mpeg_reassembly_add_boundary_candidates(
    MpegCarveState *state, CarveInfo *candidate, BlockVector *blockvector,
    int64_t actual, uint64_t first_target, uint64_t last_target,
    uint64_t image_blocks, const MpegLayout *prefix,
    const MpegPrefixBlock *prefix_index, uint64_t prefix_count,
    uint8_t *trace, uint64_t trace_capacity) {
  if (!state || !candidate || !blockvector || actual < 0 || !prefix
      || !trace || trace_capacity < 7 || scalpel_state.blocksize == 0
      || filemirror_actual_block_covered(scalpel_state.filemirror, actual)
      || filemirror_apparent_blocknumber(scalpel_state.filemirror,
                                         actual) < 0
      || filemirror_get_blocktype(
             scalpel_state.filemirror, actual,
             (uint32_t)candidate->needleidx) <= BLOCK_CONFIDENCE_LOW) {
    return;
  }

  uint64_t block_length = 0;
  const uint8_t *block = (const uint8_t *)
      filemirror_actual_block_data_pointer(scalpel_state.filemirror, actual,
                                           &block_length);
  if (!block || block_length < 7) {
    return;
  }
  if (block_length > scalpel_state.blocksize) {
    block_length = scalpel_state.blocksize;
  }

  for (uint64_t offset = 0; offset + 7 <= block_length; offset++) {
    uint8_t code;
    if (!mpeg_start_code_at(block, block_length, offset, &code)
        || (code != MPEG_PS_PACK_ID && code != MPEG_PS_SYSTEM_ID
            && code != MPEG_PS_END_ID && !mpeg_system_stream_id(code))) {
      continue;
    }
    uint64_t copied = mpeg_reassembly_physical_bytes(
        actual, offset, trace_capacity, image_blocks);
    if (copied < 7
        || !mpeg_reassembly_copy_physical(actual, offset, trace, copied,
                                          image_blocks)) {
      continue;
    }
    MpegRepairCandidate evidence;
    if (!mpeg_reassembly_trace_anchor(trace, copied, prefix, &evidence)) {
      continue;
    }

    for (uint32_t preceding = 0; preceding <= 1; preceding++) {
      if ((uint64_t)actual < preceding
          || offset > UINT64_MAX
              - (uint64_t)preceding * scalpel_state.blocksize) {
        continue;
      }
      int64_t source_actual = actual - (int64_t)preceding;
      uint64_t anchor_source_offset = offset
          + (uint64_t)preceding * scalpel_state.blocksize;
      evidence.run_first_actual = (uint64_t)source_actual;
      uint64_t trace_blocks = CEILDIV(
          anchor_source_offset + evidence.trace_bytes,
          scalpel_state.blocksize);
      if (trace_blocks == 0
          || evidence.run_first_actual > UINT64_MAX - trace_blocks + 1) {
        continue;
      }
      evidence.run_last_actual = evidence.run_first_actual
          + trace_blocks - 1;

      for (uint64_t target = first_target; target <= last_target; target++) {
        mpeg_reassembly_add_mapping_candidate(
            state, &evidence, candidate, blockvector, target,
            source_actual, actual, anchor_source_offset, image_blocks,
            prefix_index, prefix_count);
        if (target == UINT64_MAX) {
          break;
        }
      }
    }
    break;
  }
}

// A packet length fixes the next header's position within a block even when
// the payload crosses a fracture. Test each possible replacement boundary.
static inline void mpeg_reassembly_add_aligned_candidates(
    MpegCarveState *state, CarveInfo *candidate, int64_t anchor_actual,
    uint64_t anchor_offset, uint64_t first_target, uint64_t last_target,
    uint64_t image_blocks, const MpegLayout *prefix,
    const MpegPrefixBlock *prefix_index, uint64_t prefix_count,
    uint8_t *trace, uint64_t trace_capacity) {
  if (!state || !candidate || !candidate->b || !prefix || !trace
      || anchor_actual < 0 || first_target == 0 || first_target > last_target
      || scalpel_state.blocksize == 0 || trace_capacity < 7) {
    return;
  }
  uint64_t offset = anchor_offset % scalpel_state.blocksize;
  uint8_t header[MPEG_REPAIR_ANCHOR_BYTES];
  uint64_t bytes = mpeg_reassembly_physical_bytes(
      anchor_actual, offset, sizeof(header), image_blocks);
  uint8_t code;
  if (bytes < 7
      || !mpeg_reassembly_copy_physical(anchor_actual, offset, header,
                                        bytes, image_blocks)
      || !mpeg_start_code_at(header, bytes, 0, &code)
      || (code != MPEG_PS_PACK_ID && code != MPEG_PS_SYSTEM_ID
          && code != MPEG_PS_END_ID && !mpeg_system_stream_id(code))) {
    return;
  }
  bytes = mpeg_reassembly_physical_bytes(
      anchor_actual, offset, trace_capacity, image_blocks);
  MpegRepairCandidate evidence;
  if (bytes < 7
      || !mpeg_reassembly_copy_physical(anchor_actual, offset, trace,
                                        bytes, image_blocks)
      || !mpeg_reassembly_trace_anchor(trace, bytes, prefix, &evidence)) {
    return;
  }
  evidence.run_first_actual = (uint64_t)anchor_actual;
  uint64_t span = CEILDIV(offset + evidence.trace_bytes,
                          scalpel_state.blocksize);
  if (span == 0 || evidence.run_first_actual > UINT64_MAX - span + 1) {
    return;
  }
  evidence.run_last_actual = evidence.run_first_actual + span - 1;
  for (uint64_t target = first_target; target <= last_target; target++) {
    if (target > anchor_offset / scalpel_state.blocksize) {
      break;
    }
    uint64_t source_offset = anchor_offset
        - target * (uint64_t)scalpel_state.blocksize;
    uint64_t delta = source_offset / scalpel_state.blocksize;
    if ((uint64_t)anchor_actual < delta) {
      continue;
    }
    int64_t source = anchor_actual - (int64_t)delta;
    mpeg_reassembly_add_mapping_candidate(
        state, &evidence, candidate, candidate->b, target, source,
        anchor_actual, source_offset, image_blocks, prefix_index, prefix_count);
    int64_t previous = blockvector_get_actual_blocknumber(candidate->b,
                                                          target - 1);
    uint64_t distance = UINT64_MAX;
    if (previous >= 0 && previous < INT64_MAX) {
      int64_t expected = previous + 1;
      distance = source >= expected ? (uint64_t)(source - expected)
          : (uint64_t)(expected - source);
    }
    if (distance > CEILDIV(MPEG_LOCAL_REPAIR_BYTES, scalpel_state.blocksize)
        && source > 0 && source_offset <= UINT64_MAX - scalpel_state.blocksize) {
      mpeg_reassembly_add_mapping_candidate(
          state, &evidence, candidate, candidate->b, target, source - 1,
          anchor_actual, source_offset + scalpel_state.blocksize,
          image_blocks, prefix_index, prefix_count);
    }
    if (target == UINT64_MAX) {
      break;
    }
  }
}

static inline BlockVector *mpeg_reassembly_build_trial(
    CarveInfo *candidate, uint64_t target_slot, int64_t source_actual,
    uint64_t minimum_blocks, uint64_t image_blocks,
    const MpegPrefixBlock *prefix_index, uint64_t prefix_count) {
  if (!candidate || !candidate->b || source_actual < 0
      || scalpel_state.blocksize == 0) {
    return NULL;
  }
  BlockVector *trial = NULL;
  clone_blockvector(candidate->b, &trial, true);
  if (!trial) {
    return NULL;
  }
  uint64_t existing = blockvector_get_num_blocks(trial);
  if (target_slot > existing) {
    free_blockvector(&trial);
    return NULL;
  }
  resize_blockvector(trial, target_slot);
  inflate_blockvector(trial);

  uint64_t maximum_blocks = CEILDIV(MPEG_REPAIR_RUN_BYTES,
                                    scalpel_state.blocksize);
  if (maximum_blocks < minimum_blocks) {
    maximum_blocks = minimum_blocks;
  }
  uint64_t run_blocks = 0;
  while (run_blocks < maximum_blocks) {
    if (run_blocks > (uint64_t)INT64_MAX
        || source_actual > INT64_MAX - (int64_t)run_blocks) {
      break;
    }
    int64_t actual = source_actual + (int64_t)run_blocks;
    if (actual < 0 || (uint64_t)actual >= image_blocks
        || filemirror_actual_block_covered(scalpel_state.filemirror, actual)) {
      break;
    }
    if (mpeg_reassembly_actual_in_prefix(prefix_index, prefix_count,
                                         actual, target_slot)) {
      break;
    }
    if (filemirror_apparent_blocknumber(scalpel_state.filemirror, actual) < 0) {
      break;
    }
    run_blocks++;
  }
  if (run_blocks < minimum_blocks) {
    free_blockvector(&trial);
    return NULL;
  }

  resize_blockvector(trial, target_slot + run_blocks);
  for (uint64_t index = 0; index < run_blocks; index++) {
    int64_t actual = source_actual + (int64_t)index;
    int64_t apparent = filemirror_apparent_blocknumber(
        scalpel_state.filemirror, actual);
    blockvector_set_apparent_blocknumber(trial, target_slot + index,
                                         apparent);
  }
  blockvector_set_data_length_to_mapped_extent(trial);
  inflate_blockvector(trial);
  return trial;
}

static inline BlockVector *mpeg_reassembly_build_bridge_trial(
    CarveInfo *candidate, uint64_t target_slot, int64_t source_actual,
    uint64_t run_blocks, uint64_t image_blocks,
    const MpegPrefixBlock *prefix_index, uint64_t prefix_count,
    uint64_t minimum_progress, MpegLayout *trial_layout,
    bool *trial_terminal) {
  if (!candidate || !candidate->b || target_slot == 0 || source_actual < 0
      || run_blocks == 0 || run_blocks > UINT64_MAX - target_slot
      || scalpel_state.blocksize == 0
      || target_slot + run_blocks
          > UINT64_MAX / (uint64_t)scalpel_state.blocksize
      || !trial_layout || !trial_terminal) {
    return NULL;
  }
  *trial_terminal = false;
  uint64_t blocks = blockvector_get_num_blocks(candidate->b);
  bool debug_candidate = mpeg_reassembly_debug_candidate(candidate);
  if (target_slot > blocks) {
    if (debug_candidate) {
      lock_fprintf(stdout,
                   "MPEG bridge: target=%" PRIu64
                   " exceeds blocks=%" PRIu64 ".\n",
                   target_slot, blocks);
    }
    return NULL;
  }
  int64_t previous_actual = blockvector_get_actual_blocknumber(
      candidate->b, target_slot - 1);
  if (previous_actual < 0 || previous_actual == INT64_MAX
      || run_blocks > (uint64_t)INT64_MAX
      || previous_actual > INT64_MAX - (int64_t)run_blocks - 1) {
    return NULL;
  }
  int64_t local_source = previous_actual + (int64_t)run_blocks + 1;
  for (uint64_t index = 0; index < run_blocks; index++) {
    if (index > (uint64_t)INT64_MAX
        || source_actual > INT64_MAX - (int64_t)index) {
      return NULL;
    }
    int64_t actual = source_actual + (int64_t)index;
    if (actual < 0 || (uint64_t)actual >= image_blocks
        || filemirror_actual_block_covered(scalpel_state.filemirror, actual)
        || filemirror_apparent_blocknumber(scalpel_state.filemirror,
                                           actual) < 0
        || mpeg_reassembly_actual_in_prefix(prefix_index, prefix_count,
                                            actual, target_slot)) {
      if (debug_candidate) {
        lock_fprintf(stdout,
                     "MPEG bridge: source=%" PRId64 " run=%" PRIu64
                     " unavailable at remote offset=%" PRIu64 ".\n",
                     source_actual, run_blocks, index);
      }
      return NULL;
    }
  }

  BlockVector *trial = NULL;
  clone_blockvector(candidate->b, &trial, true);
  if (!trial) {
    return NULL;
  }
  resize_blockvector(trial, target_slot);
  inflate_blockvector(trial);
  resize_blockvector(trial, target_slot + run_blocks);
  for (uint64_t index = 0; index < run_blocks; index++) {
    int64_t actual = source_actual + (int64_t)index;
    int64_t apparent = filemirror_apparent_blocknumber(
        scalpel_state.filemirror, actual);
    blockvector_set_apparent_blocknumber(trial, target_slot + index,
                                         apparent);
  }

  uint64_t maximum_local_blocks = CEILDIV(
      MPEG_REPAIR_BRIDGE_BYTES, scalpel_state.blocksize);
  uint64_t local_blocks = 0;
  uint64_t next_probe = CEILDIV(MPEG_REPAIR_RUN_BYTES,
                                scalpel_state.blocksize);
  if (next_probe == 0) {
    next_probe = 1;
  }
  while (local_blocks < maximum_local_blocks) {
    uint64_t target_local_blocks = next_probe;
    if (target_local_blocks > maximum_local_blocks) {
      target_local_blocks = maximum_local_blocks;
    }
    uint64_t previous_local_blocks = local_blocks;
    while (local_blocks < target_local_blocks) {
      if (local_blocks > (uint64_t)INT64_MAX
          || local_source > INT64_MAX - (int64_t)local_blocks) {
        break;
      }
      int64_t actual = local_source + (int64_t)local_blocks;
      bool overlaps_remote = actual >= source_actual
          && (uint64_t)(actual - source_actual) < run_blocks;
      if (actual < 0 || (uint64_t)actual >= image_blocks || overlaps_remote
          || filemirror_actual_block_covered(scalpel_state.filemirror, actual)
          || filemirror_apparent_blocknumber(scalpel_state.filemirror,
                                             actual) < 0
          || mpeg_reassembly_actual_in_prefix(prefix_index, prefix_count,
                                              actual, target_slot)) {
        if (debug_candidate) {
          lock_fprintf(stdout,
                       "MPEG bridge: source=%" PRId64 " run=%" PRIu64
                       " suffix stopped at actual=%" PRId64 ".\n",
                       source_actual, run_blocks, actual);
        }
        break;
      }
      local_blocks++;
    }
    if (local_blocks == previous_local_blocks) {
      break;
    }
    resize_blockvector(trial, target_slot + run_blocks + local_blocks);
    for (uint64_t index = previous_local_blocks; index < local_blocks;
         index++) {
      int64_t actual = local_source + (int64_t)index;
      int64_t apparent = filemirror_apparent_blocknumber(
          scalpel_state.filemirror, actual);
      blockvector_set_apparent_blocknumber(
          trial, target_slot + run_blocks + index, apparent);
    }

    blockvector_set_data_length_to_mapped_extent(trial);
    inflate_blockvector(trial);
    const uint8_t *data = (const uint8_t *)
        blockvector_get_data_pointer(trial);
    uint64_t length = blockvector_get_data_length(trial);
    MpegLayout layout;
    MpegParseResult result = mpeg_reassembly_parse_trial(
        data, length, &layout);
    bool terminal = mpeg_layout_terminal(data, length, &layout);
    if (!terminal && result == MPEG_PARSE_PARTIAL
        && layout.failure_offset != UINT64_MAX
        && layout.failure_offset > layout.parsed_extent
        && layout.failure_offset <= length) {
      terminal = mpeg_layout_terminal(data, layout.failure_offset, &layout);
    }
    if (debug_candidate) {
      lock_fprintf(stdout,
                   "MPEG bridge: source=%" PRId64 " run=%" PRIu64
                   " suffix=%" PRIu64 " result=%d parsed=%" PRIu64
                   " length=%" PRIu64 " failure=%" PRIu64
                   " required=%" PRIu64 " terminal=%s.\n",
                   source_actual, run_blocks, local_blocks, (int)result,
                   layout.parsed_extent, length, layout.failure_offset,
                   layout.required_extent,
                   terminal ? "true" : "false");
    }
    uint64_t reconnected_offset = (target_slot + run_blocks)
        * (uint64_t)scalpel_state.blocksize;
    if (layout.header_valid && mpeg_layout_strong(&layout)
        && layout.timestamp_valid && terminal
        && layout.parsed_extent > reconnected_offset) {
      *trial_layout = layout;
      *trial_terminal = true;
      return trial;
    }

    uint64_t final_block_start = length > scalpel_state.blocksize
        ? length - scalpel_state.blocksize : 0;
    bool reaches_edge = (result == MPEG_PARSE_COMPLETE
                         && layout.parsed_extent == length)
        || (result == MPEG_PARSE_PARTIAL
            && (layout.required_extent > length
                || layout.parsed_extent >= final_block_start
                || (layout.failure_offset != UINT64_MAX
                    && layout.failure_offset >= final_block_start)));
    uint64_t progress = layout.parsed_extent;
    if (layout.failure_offset != UINT64_MAX
        && layout.failure_offset > progress) {
      progress = layout.failure_offset;
    }
    if (result == MPEG_PARSE_PARTIAL && layout.header_valid
        && mpeg_layout_strong(&layout) && layout.timestamp_valid
        && !reaches_edge && progress > minimum_progress
        && progress > reconnected_offset) {
      *trial_layout = layout;
      return trial;
    }

    if (!layout.header_valid || !mpeg_layout_strong(&layout)
        || !layout.timestamp_valid || !reaches_edge
        || local_blocks < target_local_blocks) {
      break;
    }
    if (next_probe >= maximum_local_blocks) {
      break;
    }
    next_probe = next_probe > maximum_local_blocks / 2
        ? maximum_local_blocks : next_probe * 2;
  }

  free_blockvector(&trial);
  return NULL;
}

static inline bool mpeg_reassembly_terminal(
    const uint8_t *data, uint64_t length, const MpegLayout *layout) {
  return data && layout && mpeg_layout_strong(layout)
      && mpeg_layout_terminal(data, length, layout);
}

static inline bool mpeg_reassembly_debug_candidate(
    const CarveInfo *candidate) {
  static _Thread_local bool initialized = false;
  static _Thread_local int64_t requested_start = -1;
  if (!initialized) {
    const char *value = getenv("SCALPEL_MPEG_DEBUG_STARTBLOCK");
    if (value && *value && *value != '-') {
      char *end = NULL;
      unsigned long long requested = strtoull(value, &end, 10);
      if (end && *end == '\0'
          && requested <= (unsigned long long)INT64_MAX) {
        requested_start = (int64_t)requested;
      }
    }
    initialized = true;
  }
  if (requested_start < 0 || !candidate || !candidate->b
      || blockvector_get_num_blocks(candidate->b) == 0) {
    return false;
  }
  return blockvector_get_actual_blocknumber(candidate->b, 0)
      == requested_start;
}

static inline bool mpeg_reassembly_resume_alternative(
    CarveInfo *candidate, MpegCarveState *state, uint64_t image_blocks) {
  if (!candidate || !candidate->b || !state) {
    return false;
  }

  while (state->branch_depth > 0) {
    MpegRepairBranch *branch = &state->branches[state->branch_depth - 1];
    if (branch->next_alternative >= branch->alternative_count) {
      state->branch_alternative_count = branch->first_alternative;
      free(branch->prefix_runs);
      memset(branch, 0, sizeof(*branch));
      state->branch_depth--;
      continue;
    }

    uint32_t alternative_index = branch->first_alternative
        + branch->next_alternative++;
    if (alternative_index >= state->branch_alternative_count) {
      continue;
    }
    MpegRepairAlternative alternative =
        state->branch_alternatives[alternative_index];
    if (alternative.anchor_source_offset > UINT64_MAX - 16
        || !mpeg_reassembly_restore_prefix(candidate, branch,
              alternative.target_slot, image_blocks)) {
      continue;
    }

    uint64_t prefix_count = 0;
    MpegPrefixBlock *prefix_index = mpeg_reassembly_prefix_index(
        candidate->b, &prefix_count);
    if (!prefix_index) {
      continue;
    }
    bool bridge_alternative = alternative.bridge_run_blocks > 0;
    MpegLayout bridge_layout;
    bool bridge_terminal = false;
    BlockVector *trial;
    if (bridge_alternative) {
      trial = mpeg_reassembly_build_bridge_trial(
          candidate, alternative.target_slot, alternative.source_actual,
          alternative.bridge_run_blocks, image_blocks, prefix_index,
          prefix_count, branch->baseline_progress, &bridge_layout,
          &bridge_terminal);
    }
    else {
      uint64_t minimum_blocks = CEILDIV(
          alternative.anchor_source_offset + 16, scalpel_state.blocksize);
      trial = mpeg_reassembly_build_trial(
          candidate, alternative.target_slot, alternative.source_actual,
          minimum_blocks, image_blocks, prefix_index, prefix_count);
    }
    free(prefix_index);
    if (!trial) {
      continue;
    }

    const uint8_t *trial_data = (const uint8_t *)
        blockvector_get_data_pointer(trial);
    uint64_t trial_length = blockvector_get_data_length(trial);
    MpegLayout trial_layout;
    MpegParseResult trial_result = mpeg_reassembly_parse_trial(
        trial_data, trial_length, &trial_layout);
    bool progressed = trial_layout.header_valid
        && mpeg_layout_strong(&trial_layout)
        && trial_layout.timestamp_valid
        && trial_layout.parsed_extent > branch->baseline_progress;
    if (!progressed) {
      free_blockvector(&trial);
      continue;
    }

    bool terminal = bridge_terminal || mpeg_reassembly_terminal(
        trial_data, trial_length, &trial_layout);
    uint64_t retained = trial_layout.parsed_extent;
    if (!terminal && trial_result == MPEG_PARSE_PARTIAL
        && trial_layout.required_extent > trial_length
        && trial_layout.failure_offset != UINT64_MAX
        && trial_layout.failure_offset > retained) {
      retained = trial_layout.failure_offset;
    }
    uint64_t retained_blocks = bridge_alternative && !terminal
        ? retained / scalpel_state.blocksize
        : CEILDIV(retained, scalpel_state.blocksize);
    if (retained_blocks == 0
        || retained_blocks > blockvector_get_num_blocks(trial)) {
      free_blockvector(&trial);
      continue;
    }
    if (retained_blocks < blockvector_get_num_blocks(trial)) {
      resize_blockvector(trial, retained_blocks);
      inflate_blockvector(trial);
    }
    if (bridge_alternative && !terminal) {
      retained = retained_blocks * (uint64_t)scalpel_state.blocksize;
    }
    blockvector_set_data_length(trial, retained);
    free_blockvector(&candidate->b);
    candidate->b = trial;
    state->repairs++;
    state->signature = 0;
    state->phase = 0;
    state->trial_index = 0;
    state->candidate_count = 0;
    state->best_nonterminal_index = UINT32_MAX;
    state->substitution_candidate_index = UINT32_MAX;
    state->substitution_next_run = 1;
    state->best_nonterminal_progress = 0;
    state->best_substitution_candidate_index = UINT32_MAX;
    state->best_substitution_run_blocks = 0;
    state->best_substitution_progress = 0;
    state->substitution_terminal_hypotheses = 0;
    state->direct_terminal_hypotheses = 0;
    mpeg_reassembly_clear_terminal_candidates(state);
    carve_put_state(candidate->carvehashkey, state);
    if (scalpel_state.mode_verbose
        || mpeg_reassembly_debug_candidate(candidate)) {
      lock_fprintf(stdout,
                   "MPEG reassembly: resumed alternative slot=%" PRIu64
                   " source=%" PRId64 " bridge=%" PRIu32
                   " progress=%" PRIu64 ".\n",
                   alternative.target_slot, alternative.source_actual,
                   alternative.bridge_run_blocks,
                   trial_layout.parsed_extent);
    }
    return true;
  }
  return false;
}

static inline bool mpeg_reassembly_publish_hypothesis(
    CarveInfo *candidate, BlockVector *hypothesis,
    const MpegLayout *layout) {
  if (!candidate || !candidate->b || !hypothesis || !layout
      || !scalpel_state.write_promising || layout->parsed_extent == 0) {
    return false;
  }
  uint64_t blocks = CEILDIV(layout->parsed_extent, scalpel_state.blocksize);
  if (blocks == 0 || blocks > blockvector_get_num_blocks(hypothesis)) {
    return false;
  }

  resize_blockvector(hypothesis, blocks);
  blockvector_set_data_length(hypothesis, layout->parsed_extent);
  inflate_blockvector(hypothesis);

  BlockVector *parent_blockvector = candidate->b;
  CarveInfoFlavor parent_flavor = candidate->flavor;
  candidate->b = hypothesis;
  candidate->flavor = PROMISING;
  write_candidate(&candidate, true);
  candidate->b = parent_blockvector;
  candidate->flavor = parent_flavor;
  return true;
}

static inline bool mpeg_reassembly_publish_zero_gap_hypotheses(
    ThreadWork *work, CarveInfo **candidate, MpegCarveState *state,
    uint64_t image_blocks, const MpegLayout *baseline,
    uuid_string_t uuidp, uuid_string_t uuidc) {
  if (!work || !candidate || !*candidate || !(*candidate)->b || !state
      || !baseline || baseline->kind != MPEG_KIND_PROGRAM
      || !scalpel_state.write_promising || scalpel_state.blocksize == 0) {
    return false;
  }

  BlockVector *blockvector = (*candidate)->b;
  uint64_t blocks = blockvector_get_num_blocks(blockvector);
  if (blocks < 3) {
    return false;
  }

  uint64_t signature = mpeg_reassembly_signature(
      *candidate, baseline, baseline->parsed_extent);
  signature ^= UINT64_C(0x7a65726f67617073);
  if (state->terminal_zero_signature != signature
      || state->terminal_zero_next_slot == 0
      || state->terminal_zero_next_slot > blocks) {
    state->terminal_zero_signature = signature;
    state->terminal_zero_next_slot = 1;
  }

  while (state->terminal_zero_next_slot + 1 < blocks) {
    uint64_t zero_slot = state->terminal_zero_next_slot++;
    int64_t zero_actual = blockvector_get_actual_blocknumber(
        blockvector, zero_slot);
    if (zero_actual < 0 || !filemirror_actual_block_is_zero(
                                scalpel_state.filemirror, zero_actual)) {
      if (state->terminal_zero_next_slot % MPEG_REPAIR_POLL_INTERVAL == 0
          && mpeg_reassembly_checkpoint(work, candidate, state,
                                        uuidp, uuidc)) {
        return true;
      }
      continue;
    }

    uint64_t zero_blocks = 1;
    while (zero_slot + zero_blocks + 1 < blocks) {
      int64_t actual = blockvector_get_actual_blocknumber(
          blockvector, zero_slot + zero_blocks);
      if (actual < 0 || !filemirror_actual_block_is_zero(
                             scalpel_state.filemirror, actual)) {
        break;
      }
      zero_blocks++;
      state->terminal_zero_next_slot = zero_slot + zero_blocks;
    }

    int64_t last_actual = blockvector_get_actual_blocknumber(
        blockvector, blocks - 1);
    if (last_actual < 0 || zero_blocks > (uint64_t)INT64_MAX
        || last_actual > INT64_MAX - (int64_t)zero_blocks) {
      continue;
    }

    BlockVector *trial = NULL;
    clone_blockvector(blockvector, &trial, true);
    if (!trial) {
      continue;
    }

    bool mapping_valid = true;
    int64_t trial_last_actual = -1;
    for (uint64_t target = zero_slot; target < blocks; target++) {
      uint64_t source_slot = target + zero_blocks;
      int64_t source_actual;
      if (source_slot < blocks) {
        source_actual = blockvector_get_actual_blocknumber(
            blockvector, source_slot);
      }
      else {
        uint64_t extra = source_slot - blocks + 1;
        if (extra > (uint64_t)INT64_MAX
            || last_actual > INT64_MAX - (int64_t)extra) {
          mapping_valid = false;
          break;
        }
        source_actual = last_actual + (int64_t)extra;
      }
      if (source_actual < 0 || (uint64_t)source_actual >= image_blocks
          || filemirror_actual_block_covered(scalpel_state.filemirror,
                                             source_actual)) {
        mapping_valid = false;
        break;
      }
      int64_t apparent = filemirror_apparent_blocknumber(
          scalpel_state.filemirror, source_actual);
      if (apparent < 0) {
        mapping_valid = false;
        break;
      }
      blockvector_set_apparent_blocknumber(trial, target, apparent);
      trial_last_actual = source_actual;
    }

    if (!mapping_valid || trial_last_actual < 0) {
      free_blockvector(&trial);
      continue;
    }
    inflate_blockvector(trial);

    uint64_t last_available = 0;
    if (!filemirror_actual_block_data_pointer(
            scalpel_state.filemirror, trial_last_actual, &last_available)
        || last_available == 0 || last_available > scalpel_state.blocksize
        || blocks - 1 > (UINT64_MAX - last_available)
            / (uint64_t)scalpel_state.blocksize) {
      free_blockvector(&trial);
      continue;
    }
    uint64_t trial_length = (blocks - 1)
        * (uint64_t)scalpel_state.blocksize + last_available;
    blockvector_set_data_length(trial, trial_length);

    const uint8_t *trial_data = (const uint8_t *)
        blockvector_get_data_pointer(trial);
    MpegLayout trial_layout;
    MpegParseResult result = mpeg_reassembly_parse_trial(
        trial_data, trial_length, &trial_layout);
    bool terminal = result == MPEG_PARSE_COMPLETE
        && trial_layout.header_valid && mpeg_layout_strong(&trial_layout)
        && trial_layout.timestamp_valid
        && mpeg_reassembly_terminal(trial_data, trial_length,
                                    &trial_layout);
    if (terminal) {
      mpeg_reassembly_publish_hypothesis(*candidate, trial, &trial_layout);
      if (scalpel_state.mode_verbose
          || mpeg_reassembly_debug_candidate(*candidate)) {
        lock_fprintf(stdout,
                     "MPEG reassembly: zero-gap hypothesis slot=%" PRIu64
                     " width=%" PRIu64 " progress=%" PRIu64 ".\n",
                     zero_slot, zero_blocks, trial_layout.parsed_extent);
      }
    }
    free_blockvector(&trial);
    if (mpeg_reassembly_checkpoint(work, candidate, state, uuidp, uuidc)) {
      return true;
    }
  }
  state->terminal_zero_next_slot = blocks;
  return false;
}

static inline bool mpeg_reassembly_finish_candidate(
    CarveInfo **candidate, MpegCarveState **state,
    const MpegLayout *layout) {
  if (!candidate || !*candidate || !(*candidate)->b || !state || !layout
      || layout->parsed_extent == 0) {
    return false;
  }
  uint64_t blocks = CEILDIV(layout->parsed_extent, scalpel_state.blocksize);
  if (blocks == 0 || blocks > blockvector_get_num_blocks((*candidate)->b)) {
    return false;
  }
  resize_blockvector((*candidate)->b, blocks);
  blockvector_set_data_length((*candidate)->b, layout->parsed_extent);
  inflate_blockvector((*candidate)->b);
  mpeg_free_carve_state((void **)state);
  if (scalpel_state.write_promising) {
    (*candidate)->flavor = PROMISING;
    write_candidate(candidate, false);
  }
  else {
    destroy_candidate(candidate);
  }
  return true;
}

static inline void mpeg_reassembly_search(
    ThreadWork *work, CarveInfo **candidate, uuid_string_t uuidp,
    uuid_string_t uuidc, MpegReassemblyScratch *scratch) {
  if (!work || !candidate || !*candidate || !(*candidate)->b
      || scalpel_state.blocksize == 0) {
    if (candidate && *candidate) {
      destroy_candidate(candidate);
    }
    return;
  }

  MpegCarveState *state = (MpegCarveState *)carve_get_state(
      (*candidate)->carvehashkey);
  if (!mpeg_carve_state_valid(state)) {
    mpeg_free_carve_state((void **)&state);
    state = (MpegCarveState *)calloc(1, sizeof(*state));
    check_memory_allocation(state, __LINE__, __FILE__, "MpegCarveState");
    state->magic = MPEG_CARVE_STATE_MAGIC;
    state->version = MPEG_CARVE_STATE_VERSION;
  }

  uint64_t image_size = filemirror_filesize(scalpel_state.filemirror);
  uint64_t image_blocks = CEILDIV(image_size, scalpel_state.blocksize);
  (*candidate)->chopped = false;

mpeg_reassembly_restart:
  while (*candidate) {
    if (mpeg_reassembly_checkpoint(work, candidate, state, uuidp, uuidc)) {
      mpeg_free_carve_state((void **)&state);
      return;
    }

    BlockVector *blockvector = (*candidate)->b;
    inflate_blockvector(blockvector);
    uint64_t blocks = blockvector_get_num_blocks(blockvector);
    if (blocks == 0
        || blockvector_get_actual_blocknumber(blockvector, 0) < 0) {
      mpeg_free_carve_state((void **)&state);
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
    if (blocks == 0) {
      break;
    }

    const uint8_t *data = (const uint8_t *)
        blockvector_get_data_pointer(blockvector);
    uint64_t length = blockvector_get_data_length(blockvector);
    MpegLayout *layout = &scratch->layout;
    MpegParseResult result = mpeg_parse_file(data, length, layout);
    if (!layout->header_valid
        || (!mpeg_layout_strong(layout)
            && !mpeg_reassembly_partial_packet(data, length, layout))) {
      break;
    }
    if (mpeg_reassembly_terminal(data, length, layout)) {
      if (mpeg_reassembly_publish_zero_gap_hypotheses(
              work, candidate, state, image_blocks, layout, uuidp, uuidc)) {
        mpeg_free_carve_state((void **)&state);
        return;
      }
      if (state->branch_depth > 0) {
        BlockVector *hypothesis = NULL;
        clone_blockvector(blockvector, &hypothesis, false);
        if (hypothesis) {
          mpeg_reassembly_publish_hypothesis(*candidate, hypothesis, layout);
          free_blockvector(&hypothesis);
        }
        if (mpeg_reassembly_resume_alternative(*candidate, state,
                                               image_blocks)) {
          continue;
        }
        mpeg_free_carve_state((void **)&state);
        destroy_candidate(candidate);
        return;
      }
      if (layout->terminal_marker) {
        mpeg_reassembly_finish_candidate(candidate, &state, layout);
        return;
      }
      // Padding can occur between packets. Preserve this endpoint while
      // searching for continuation after any existing branch alternatives.
      BlockVector *hypothesis = NULL;
      clone_blockvector(blockvector, &hypothesis, false);
      if (hypothesis) {
        mpeg_reassembly_publish_hypothesis(*candidate, hypothesis, layout);
        free_blockvector(&hypothesis);
      }
      // Cloning inflates the source and may relocate its data buffer.
      data = (const uint8_t *)blockvector_get_data_pointer(blockvector);
    }
    if (layout->kind != MPEG_KIND_PROGRAM) {
      break;
    }

    uint64_t anchor_offset = length;
    bool trailing_fill = false;
    bool packet_fill = false;
    uint8_t fill_byte = 0;
    bool continuity_repair = result == MPEG_PARSE_COMPLETE
        && layout->continuity_offset != UINT64_MAX
        && layout->continuity_offset < length;
    if (result == MPEG_PARSE_PARTIAL && layout->parsed_extent < length
        && (data[layout->parsed_extent] == 0
            || data[layout->parsed_extent] == UINT8_C(0xff))
        && mpeg_uniform_fill_extent(data, length, layout->parsed_extent)
            == length) {
      trailing_fill = true;
      fill_byte = data[layout->parsed_extent];
      // Uniform disk blocks can occupy either packet payload or padding.
      // Keep the padding interpretation and also test the packet alignment.
      uint64_t block_start = layout->parsed_extent
          - layout->parsed_extent % scalpel_state.blocksize;
      packet_fill = block_start > layout->repair_start_offset
          && length - block_start >= scalpel_state.blocksize
          && mpeg_uniform_fill_extent(data, length, block_start) == length;
    }
    if (!trailing_fill && result == MPEG_PARSE_PARTIAL) {
      if (layout->required_extent > length) {
        anchor_offset = layout->required_extent;
      }
      else if (layout->failure_offset != UINT64_MAX) {
        anchor_offset = layout->failure_offset;
      }
    }
    else if (continuity_repair) {
      anchor_offset = layout->continuity_offset;
    }

    uint64_t first_target;
    uint64_t last_target;
    uint64_t trusted_extent = layout->parsed_extent;
    if (trailing_fill) {
      first_target = blocks;
      last_target = blocks;
    }
    else {
      uint64_t repair_offset = continuity_repair
          ? layout->continuity_offset : layout->repair_start_offset;
      if (!continuity_repair && repair_offset == UINT64_MAX) {
        repair_offset = layout->last_packet_offset;
      }
      if (repair_offset == UINT64_MAX || repair_offset > anchor_offset) {
        break;
      }
      trusted_extent = repair_offset;
      first_target = repair_offset / scalpel_state.blocksize;
      last_target = CEILDIV(anchor_offset, scalpel_state.blocksize);
      if (first_target == 0) {
        first_target = 1;
      }
      if (last_target > blocks) {
        last_target = blocks;
      }
      if (first_target > last_target) {
        break;
      }
    }

    MpegLayout *trusted_layout = &scratch->trusted_layout;
    const MpegLayout *ranking_layout = layout;
    if (!trailing_fill && trusted_extent > 0
        && trusted_extent <= length) {
      mpeg_parse_file(data, trusted_extent, trusted_layout);
      if (trusted_layout->header_valid
          && mpeg_layout_strong(trusted_layout)
          && trusted_layout->timestamp_valid) {
        ranking_layout = trusted_layout;
      }
    }

    uint64_t signature = mpeg_reassembly_signature(*candidate,
                                                    ranking_layout,
                                                    anchor_offset);
    if (trailing_fill) {
      signature ^= UINT64_C(0x9e3779b97f4a7c15);
    }
    if (state->signature != signature || state->phase == 0
        || state->first_target_slot != first_target
        || state->last_target_slot != last_target) {
      mpeg_reassembly_reset_state(state, signature, first_target, last_target,
                                  anchor_offset, layout->parsed_extent);
    }

    if (mpeg_reassembly_debug_candidate(*candidate)) {
      lock_fprintf(
          stdout,
          "MPEG reassembly: blocks=%" PRIu64 " length=%" PRIu64
          " result=%d parsed=%" PRIu64 " required=%" PRIu64
          " failure=%" PRIu64 " repair=%" PRIu64
          " continuity=%" PRIu64 " anchor=%" PRIu64
          " targets=%" PRIu64 "-%" PRIu64 " phase=%" PRIu32 ".\n",
          blocks, length, (int)result, layout->parsed_extent,
          layout->required_extent, layout->failure_offset,
          layout->repair_start_offset, layout->continuity_offset,
          anchor_offset, first_target, last_target, state->phase);
    }

    uint64_t prefix_count = 0;
    MpegPrefixBlock *prefix_index = mpeg_reassembly_prefix_index(
        blockvector, &prefix_count);
    if (!prefix_index) {
      break;
    }

    if (state->phase == 4) {
      uint64_t trace_capacity = MPEG_REPAIR_TRACE_BYTES;
      uint8_t *trace = (uint8_t *)malloc((size_t)trace_capacity);
      check_memory_allocation(trace, __LINE__, __FILE__,
                              "MPEG boundary fallback trace");
      for (uint64_t actual_index = state->next_anchor_actual;
           actual_index < image_blocks; actual_index++) {
        // Save the unexamined anchor before any scan branch can skip it.
        state->next_anchor_actual = actual_index;
        if (actual_index % MPEG_REPAIR_POLL_INTERVAL == 0
            && mpeg_reassembly_checkpoint(work, candidate, state,
                                          uuidp, uuidc)) {
          free(trace);
          free(prefix_index);
          mpeg_free_carve_state((void **)&state);
          return;
        }
        state->next_anchor_actual = actual_index + 1;
        if (actual_index > (uint64_t)INT64_MAX) {
          break;
        }
        mpeg_reassembly_add_boundary_candidates(
            state, *candidate, blockvector, (int64_t)actual_index,
            first_target, last_target, image_blocks, ranking_layout,
            prefix_index, prefix_count, trace, trace_capacity);
      }
      free(trace);

      // Start-code alignment can be unavailable when a fracture falls inside
      // a packet. Nearby payload starts remain useful after the full structural
      // scan has had the first opportunity to supply stronger evidence.
      if (blocks > 0) {
        int64_t previous_actual = blockvector_get_actual_blocknumber(
            blockvector, blocks - 1);
        if (previous_actual >= 0 && previous_actual < INT64_MAX) {
          int64_t expected_actual = previous_actual + 1;
          uint64_t local_blocks = CEILDIV(
              MPEG_LOCAL_REPAIR_BYTES, scalpel_state.blocksize);
          for (uint64_t distance = 0; distance <= local_blocks; distance++) {
            for (uint32_t direction = 0; direction < 2; direction++) {
              if (distance == 0 && direction != 0) {
                continue;
              }
              int64_t source_actual;
              if (direction == 0) {
                if (distance > (uint64_t)(INT64_MAX - expected_actual)) {
                  continue;
                }
                source_actual = expected_actual + (int64_t)distance;
              }
              else {
                if (distance > (uint64_t)expected_actual) {
                  continue;
                }
                source_actual = expected_actual - (int64_t)distance;
              }
              if (!mpeg_reassembly_source_available(
                      *candidate, blocks, source_actual, 1, image_blocks,
                      prefix_index, prefix_count)) {
                continue;
              }

              MpegRepairCandidate repair;
              memset(&repair, 0, sizeof(repair));
              repair.source_actual = source_actual;
              repair.target_slot = blocks;
              repair.run_first_actual = (uint64_t)source_actual;
              repair.run_last_actual = (uint64_t)source_actual;
              repair.trace_bytes = scalpel_state.blocksize;
              repair.distance = distance;
              repair.fill_continuation = trailing_fill ? 1 : 0;
              repair.local_continuation = distance == 0 ? 1 : 0;
              repair.reservations = scalpel_state.reservations
                  ? filemirror_actual_block_reserved(
                        scalpel_state.filemirror, source_actual) : 0;
              repair.confidence = (uint32_t)filemirror_get_blocktype(
                  scalpel_state.filemirror, source_actual,
                  (uint32_t)(*candidate)->needleidx);
              mpeg_reassembly_add_candidate(state, &repair);
              state->matches++;
            }
          }
        }
      }

      state->phase = 2;
      state->trial_index = 0;
    }

    if (state->phase == 1) {
      uint64_t trace_capacity = MPEG_REPAIR_TRACE_BYTES
          + MPEG_REPAIR_FILL_PROBE_BYTES;
      uint8_t *trace = (uint8_t *)malloc((size_t)trace_capacity);
      check_memory_allocation(trace, __LINE__, __FILE__,
                              "MPEG continuation trace");

      for (uint64_t actual_index = state->next_anchor_actual;
           actual_index < image_blocks; actual_index++) {
        state->next_anchor_actual = actual_index;
        if (actual_index % MPEG_REPAIR_POLL_INTERVAL == 0
            && mpeg_reassembly_checkpoint(work, candidate, state,
                                          uuidp, uuidc)) {
          free(trace);
          free(prefix_index);
          mpeg_free_carve_state((void **)&state);
          return;
        }
        state->next_anchor_actual = actual_index + 1;
        if (actual_index > (uint64_t)INT64_MAX) {
          break;
        }
        int64_t anchor_actual = (int64_t)actual_index;
        int64_t source_actual = -1;
        uint64_t anchor_source_offset = 0;
        uint64_t anchor_physical_offset = 0;
        uint64_t copied = 0;
        MpegRepairCandidate evidence;

        if (!trailing_fill || packet_fill) {
          uint64_t packet_first = packet_fill
              ? layout->repair_start_offset / scalpel_state.blocksize
              : first_target;
          if (packet_first == 0) {
            packet_first = 1;
          }
          uint64_t packet_anchor = packet_fill ? layout->parsed_extent
              : anchor_offset;
          mpeg_reassembly_add_aligned_candidates(
              state, *candidate, anchor_actual, packet_anchor, packet_first,
              last_target, image_blocks, ranking_layout,
              prefix_index, prefix_count, trace, MPEG_REPAIR_TRACE_BYTES);
          if (!trailing_fill) {
            continue;
          }
        }

        if (filemirror_actual_block_covered(scalpel_state.filemirror,
                                            anchor_actual)) {
          continue;
        }
        if (anchor_actual > 0
            && !filemirror_actual_block_covered(scalpel_state.filemirror,
                                                anchor_actual - 1)) {
          uint64_t previous_length = 0;
          const uint8_t *previous = (const uint8_t *)
              filemirror_actual_block_data_pointer(
                  scalpel_state.filemirror, anchor_actual - 1,
                  &previous_length);
          if (previous && previous_length > 0
              && previous[previous_length - 1] == fill_byte) {
            continue;
          }
        }
        copied = mpeg_reassembly_physical_bytes(
            anchor_actual, 0, trace_capacity, image_blocks);
        if (copied < 4
            || !mpeg_reassembly_copy_physical(anchor_actual, 0, trace,
                                              copied, image_blocks)) {
          continue;
        }
        uint64_t probe_length = copied;
        if (probe_length > MPEG_REPAIR_FILL_PROBE_BYTES) {
          probe_length = MPEG_REPAIR_FILL_PROBE_BYTES;
        }
        if (!mpeg_reassembly_fill_anchor(trace, probe_length, fill_byte,
                                         &anchor_source_offset)) {
          continue;
        }
        uint64_t trace_length = copied - anchor_source_offset;
        if (trace_length > MPEG_REPAIR_TRACE_BYTES) {
          trace_length = MPEG_REPAIR_TRACE_BYTES;
        }
        if (!mpeg_reassembly_trace_anchor(trace + anchor_source_offset,
                                          trace_length, ranking_layout,
                                          &evidence)) {
          continue;
        }
        source_actual = anchor_actual;
        uint64_t anchor_delta = anchor_source_offset
            / scalpel_state.blocksize;
        if (anchor_delta > (uint64_t)INT64_MAX
            || anchor_actual > INT64_MAX - (int64_t)anchor_delta) {
          continue;
        }
        anchor_actual += (int64_t)anchor_delta;
        anchor_physical_offset = anchor_source_offset
            % scalpel_state.blocksize;
        evidence.fill_continuation = 1;
        evidence.run_first_actual = (uint64_t)anchor_actual;
        uint64_t trace_span = anchor_physical_offset + evidence.trace_bytes;
        uint64_t trace_blocks = CEILDIV(trace_span,
                                        scalpel_state.blocksize);
        if (trace_blocks == 0
            || evidence.run_first_actual > UINT64_MAX - trace_blocks + 1) {
          continue;
        }
        evidence.run_last_actual = evidence.run_first_actual
            + trace_blocks - 1;

        mpeg_reassembly_add_mapping_candidate(
            state, &evidence, *candidate, blockvector, blocks,
            source_actual, anchor_actual, anchor_source_offset,
            image_blocks, prefix_index, prefix_count);
      }
      free(trace);

      // A parser failure can lag one block behind a disk gap when the skipped
      // block is inside an opaque packet payload. Rewind each plausible repair
      // slot and test the physical continuation after one intervening block.
      for (uint64_t target = first_target; target <= last_target; target++) {
        if (target == 0) {
          continue;
        }
        int64_t previous_actual = blockvector_get_actual_blocknumber(
            blockvector, target - 1);
        if (previous_actual < 0 || previous_actual > INT64_MAX - 2) {
          continue;
        }
        int64_t source_actual = previous_actual + 2;
        if (!mpeg_reassembly_source_available(
                *candidate, target, source_actual, 1, image_blocks,
                prefix_index, prefix_count)) {
          continue;
        }

        MpegRepairCandidate repair;
        memset(&repair, 0, sizeof(repair));
        repair.source_actual = source_actual;
        repair.target_slot = target;
        repair.run_first_actual = (uint64_t)source_actual;
        repair.run_last_actual = (uint64_t)source_actual;
        repair.trace_bytes = scalpel_state.blocksize;
        repair.distance = 1;
        repair.local_continuation = 1;
        repair.reservations = scalpel_state.reservations
            ? filemirror_actual_block_reserved(
                  scalpel_state.filemirror, source_actual) : 0;
        repair.confidence = (uint32_t)filemirror_get_blocktype(
            scalpel_state.filemirror, source_actual,
            (uint32_t)(*candidate)->needleidx);
        mpeg_reassembly_add_candidate(state, &repair);
        state->matches++;
        if (target == UINT64_MAX) {
          break;
        }
      }

      // Keep the exact physical continuation available even when unrelated
      // MPEG anchors fill the ranked candidate set.
      if (blocks > 0) {
        int64_t previous_actual = blockvector_get_actual_blocknumber(
            blockvector, blocks - 1);
        if (previous_actual >= 0 && previous_actual < INT64_MAX) {
          int64_t source_actual = previous_actual + 1;
          if (mpeg_reassembly_source_available(
                  *candidate, blocks, source_actual, 1, image_blocks,
                  prefix_index, prefix_count)) {
            bool found = false;
            for (uint32_t index = 0; index < state->candidate_count; index++) {
              MpegRepairCandidate *current = &state->candidates[index];
              if (current->source_actual == source_actual
                  && current->target_slot == blocks) {
                current->local_continuation = 1;
                found = true;
                break;
              }
            }
            if (!found) {
              MpegRepairCandidate repair;
              memset(&repair, 0, sizeof(repair));
              repair.source_actual = source_actual;
              repair.target_slot = blocks;
              repair.run_first_actual = (uint64_t)source_actual;
              repair.run_last_actual = (uint64_t)source_actual;
              repair.trace_bytes = scalpel_state.blocksize;
              repair.local_continuation = 1;
              repair.reservations = scalpel_state.reservations
                  ? filemirror_actual_block_reserved(
                        scalpel_state.filemirror, source_actual) : 0;
              repair.confidence = (uint32_t)filemirror_get_blocktype(
                  scalpel_state.filemirror, source_actual,
                  (uint32_t)(*candidate)->needleidx);
              if (state->candidate_count == MPEG_REPAIR_CANDIDATES) {
                state->candidate_count--;
              }
              state->candidates[state->candidate_count++] = repair;
              state->matches++;
            }
          }
        }
      }

      state->phase = 2;
      state->trial_index = 0;
      if (scalpel_state.mode_verbose
          || mpeg_reassembly_debug_candidate(*candidate)) {
        lock_fprintf(stdout,
                     "MPEG reassembly: ranked %" PRIu32
                     " physical continuation hypotheses.\n",
                     state->candidate_count);
        uint32_t shown = state->candidate_count;
        for (uint32_t index = 0; index < shown; index++) {
          const MpegRepairCandidate *ranked = &state->candidates[index];
          lock_fprintf(
              stdout,
              "  rank=%" PRIu32 " slot=%" PRIu64 " source=%" PRId64
              " clocks=%" PRIu32 " cost=%" PRIu64
              " streams=%" PRIu32 " packets=%" PRIu32
              " profile=%" PRIu8 "/%" PRIu8
              " mux=%" PRIu32 "/%" PRIu32
              " anchor-offset=%" PRIu64
              " trace=%" PRIu64 " run=%" PRIu64 "-%" PRIu64
              " distance=%" PRIu64 " confidence=%" PRIu32
              " reservations=%" PRId64 " local=%" PRIu8 "\n",
              index, ranked->target_slot, ranked->source_actual,
              ranked->clocks, ranked->clock_cost, ranked->stream_matches,
              ranked->packets, ranked->profile_match,
              ranked->profile_mismatch, ranked->mux_matches,
              ranked->mux_mismatches, ranked->anchor_source_offset,
              ranked->trace_bytes, ranked->run_first_actual,
              ranked->run_last_actual,
              ranked->distance,
              ranked->confidence, ranked->reservations,
              ranked->local_continuation);
        }
      }
    }

    bool advanced = false;
    while (state->phase == 2
           && state->trial_index < state->candidate_count && *candidate) {
      uint32_t repair_index = state->trial_index++;
      MpegRepairCandidate repair = state->candidates[repair_index];
      if (repair.anchor_source_offset > UINT64_MAX - 16) {
        continue;
      }
      uint64_t minimum_blocks = CEILDIV(repair.anchor_source_offset + 16,
                                        scalpel_state.blocksize);
      BlockVector *trial = mpeg_reassembly_build_trial(
          *candidate, repair.target_slot, repair.source_actual,
          minimum_blocks, image_blocks, prefix_index, prefix_count);
      if (!trial) {
        if (mpeg_reassembly_debug_candidate(*candidate)) {
          lock_fprintf(stdout,
                       "MPEG reassembly: rank=%" PRIu32
                       " slot=%" PRIu64 " source=%" PRId64
                       " unavailable (anchor offset=%" PRIu64
                       ", minimum blocks=%" PRIu64 ").\n",
                       repair_index, repair.target_slot,
                       repair.source_actual, repair.anchor_source_offset,
                       minimum_blocks);
        }
        continue;
      }
      const uint8_t *trial_data = (const uint8_t *)
          blockvector_get_data_pointer(trial);
      uint64_t trial_length = blockvector_get_data_length(trial);
      MpegLayout *trial_layout = &scratch->trial_layout;
      mpeg_reassembly_parse_trial(trial_data, trial_length, trial_layout);
      bool terminal = mpeg_reassembly_terminal(
          trial_data, trial_length, trial_layout);
      bool progressed = trial_layout->header_valid
          && mpeg_layout_strong(trial_layout)
          && trial_layout->timestamp_valid
          && trial_layout->parsed_extent > state->baseline_progress
          && trial_layout->parsed_extent > state->anchor_offset
          && trial_layout->packet_count > ranking_layout->packet_count;
      uint64_t local_blocks = CEILDIV(
          MPEG_LOCAL_REPAIR_BYTES, scalpel_state.blocksize);
      bool remote_candidate = repair.distance > local_blocks;
      bool strong_remote_evidence = repair.profile_match
          || (repair.mux_matches > 0
              && repair.mux_mismatches == 0);
      bool first_anchor_family = true;
      uint64_t anchor_delta = repair.anchor_source_offset
          / scalpel_state.blocksize;
      int64_t family_anchor = -1;
      if (anchor_delta <= (uint64_t)INT64_MAX
          && repair.source_actual
              <= INT64_MAX - (int64_t)anchor_delta) {
        family_anchor = repair.source_actual + (int64_t)anchor_delta;
        for (uint32_t index = 0; index < repair_index; index++) {
          const MpegRepairCandidate *earlier = &state->candidates[index];
          uint64_t earlier_delta = earlier->anchor_source_offset
              / scalpel_state.blocksize;
          if (earlier_delta <= (uint64_t)INT64_MAX
              && earlier->source_actual
                  <= INT64_MAX - (int64_t)earlier_delta
              && earlier->target_slot == repair.target_slot
              && earlier->source_actual + (int64_t)earlier_delta
                  == family_anchor) {
            first_anchor_family = false;
            break;
          }
        }
      }

      bool refined_remote = repair.payload_prefix_refined != 0;
      if (remote_candidate && progressed && strong_remote_evidence
          && first_anchor_family && family_anchor >= 0) {
        uint64_t packet_span = CEILDIV((uint64_t)UINT16_MAX,
                                       scalpel_state.blocksize) + 1;
        while (repair.source_actual > 0
               && repair.anchor_source_offset / scalpel_state.blocksize
                   < packet_span
               && repair.anchor_source_offset
                   <= UINT64_MAX - scalpel_state.blocksize
               && repair.anchor_source_offset + scalpel_state.blocksize
                   <= UINT64_MAX - 16) {
          int64_t refined_source = repair.source_actual - 1;
          uint64_t refined_anchor_offset = repair.anchor_source_offset
              + scalpel_state.blocksize;
          uint64_t refined_minimum_blocks = CEILDIV(
              refined_anchor_offset + 16, scalpel_state.blocksize);
          BlockVector *refined_trial = mpeg_reassembly_build_trial(
              *candidate, repair.target_slot, refined_source,
              refined_minimum_blocks, image_blocks, prefix_index,
              prefix_count);
          if (!refined_trial) {
            break;
          }

          const uint8_t *refined_data = (const uint8_t *)
              blockvector_get_data_pointer(refined_trial);
          uint64_t refined_length = blockvector_get_data_length(refined_trial);
          MpegLayout *refined_layout = &scratch->refined_layout;
          mpeg_reassembly_parse_trial(refined_data, refined_length,
                                      refined_layout);
          bool refinement_progressed = refined_layout->header_valid
              && mpeg_layout_strong(refined_layout)
              && refined_layout->timestamp_valid
              && refined_layout->parsed_extent > trial_layout->parsed_extent
              && refined_layout->parsed_extent > state->anchor_offset
              && refined_layout->packet_count > ranking_layout->packet_count;
          if (!refinement_progressed) {
            free_blockvector(&refined_trial);
            break;
          }

          free_blockvector(&trial);
          trial = refined_trial;
          trial_data = refined_data;
          trial_length = refined_length;
          *trial_layout = *refined_layout;
          terminal = mpeg_reassembly_terminal(
              trial_data, trial_length, trial_layout);
          progressed = true;
          repair.source_actual = refined_source;
          repair.anchor_source_offset = refined_anchor_offset;
          repair.run_first_actual = (uint64_t)refined_source;
          repair.payload_prefix_refined = 1;
          int64_t previous_actual = blockvector_get_actual_blocknumber(
              blockvector, repair.target_slot - 1);
          if (previous_actual >= 0 && previous_actual < INT64_MAX) {
            int64_t expected_actual = previous_actual + 1;
            repair.distance = refined_source >= expected_actual
                ? (uint64_t)(refined_source - expected_actual)
                : (uint64_t)(expected_actual - refined_source);
          }
          repair.reservations = scalpel_state.reservations
              ? filemirror_actual_block_reserved(
                    scalpel_state.filemirror, refined_source) : 0;
          BlockValidationDecision refined_confidence =
              filemirror_get_blocktype(
                  scalpel_state.filemirror, refined_source,
                  (uint32_t)(*candidate)->needleidx);
          if ((uint32_t)refined_confidence > repair.confidence) {
            repair.confidence = (uint32_t)refined_confidence;
          }
          state->candidates[repair_index] = repair;
          refined_remote = true;

          if (scalpel_state.mode_verbose
              || mpeg_reassembly_debug_candidate(*candidate)) {
            lock_fprintf(
                stdout,
                "MPEG reassembly: refined rank=%" PRIu32
                " slot=%" PRIu64 " source=%" PRId64
                " progress=%" PRIu64 ".\n",
                repair_index, repair.target_slot, repair.source_actual,
                trial_layout->parsed_extent);
          }
          if (atomic_load_explicit(&REASS_RETURN_TO_IDLE,
                                   memory_order_acquire)) {
            uint32_t next_trial_index = state->trial_index;
            state->trial_index = repair_index;
            if (mpeg_reassembly_checkpoint(work, candidate, state,
                                           uuidp, uuidc)) {
              free_blockvector(&trial);
              free(prefix_index);
              mpeg_free_carve_state((void **)&state);
              return;
            }
            state->trial_index = next_trial_index;
          }
        }
      }

      bool local_progress_selected = false;
      if (state->best_nonterminal_index < state->candidate_count) {
        const MpegRepairCandidate *selected = &state->candidates[
            state->best_nonterminal_index];
        local_progress_selected = selected->distance <= local_blocks;
      }
      bool resumed_substitution = state->substitution_candidate_index
          == repair_index;
      bool explore_substitution = !terminal && remote_candidate
          && (!local_progress_selected || continuity_repair
              || refined_remote || resumed_substitution)
          && (progressed || continuity_repair
              || state->boundary_fallback_done);
      if (explore_substitution
          && state->substitution_terminal_hypotheses
              < MPEG_TERMINAL_HYPOTHESES) {
        uint64_t maximum_substitution = CEILDIV(
            MPEG_REPAIR_TRACE_BYTES, scalpel_state.blocksize);
        uint64_t substitution_start = 1;
        if (state->substitution_candidate_index == repair_index
            && state->substitution_next_run > 0) {
          substitution_start = state->substitution_next_run;
        }
        for (uint64_t run_blocks = substitution_start;
             run_blocks <= maximum_substitution; run_blocks++) {
          MpegLayout *substitution_layout = &scratch->substitution_layout;
          bool substitution_terminal = false;
          BlockVector *substitution =
              mpeg_reassembly_build_bridge_trial(
                  *candidate, repair.target_slot, repair.source_actual,
                  run_blocks, image_blocks, prefix_index, prefix_count,
                  state->baseline_progress, substitution_layout,
                  &substitution_terminal);
          if (substitution) {
            bool published = false;
            bool selected = false;
            bool substitution_progressed =
                substitution_layout->parsed_extent > state->anchor_offset
                && substitution_layout->packet_count
                    > ranking_layout->packet_count;
            if (substitution_terminal && substitution_progressed) {
              published = mpeg_reassembly_publish_hypothesis(
                  *candidate, substitution, substitution_layout);
              if (!state->substitution_terminal_candidates[repair_index]) {
                bool new_alignment = true;
                for (uint32_t prior = 0; prior < state->candidate_count;
                     prior++) {
                  if (state->substitution_terminal_candidates[prior]
                      && mpeg_repair_same_alignment(
                          &state->candidates[repair_index],
                          &state->candidates[prior])) {
                    new_alignment = false;
                    break;
                  }
                }
                state->substitution_terminal_candidates[repair_index] = 1;
                if (new_alignment) {
                  state->substitution_terminal_hypotheses++;
                }
              }
            }
            else if (!substitution_terminal && substitution_progressed
                     && run_blocks <= UINT32_MAX) {
              MpegRepairCandidate *evaluated =
                  &state->candidates[repair_index];
              if (substitution_layout->parsed_extent
                      > evaluated->bridge_progress
                  || (substitution_layout->parsed_extent
                          == evaluated->bridge_progress
                      && (evaluated->bridge_run_blocks == 0
                          || run_blocks
                              < evaluated->bridge_run_blocks))) {
                evaluated->bridge_progress =
                    substitution_layout->parsed_extent;
                evaluated->bridge_run_blocks = (uint32_t)run_blocks;
              }
              selected = substitution_layout->parsed_extent
                  > state->best_substitution_progress;
              if (!selected
                  && substitution_layout->parsed_extent
                      == state->best_substitution_progress
                  && state->best_substitution_candidate_index
                      < state->candidate_count) {
                const MpegRepairCandidate *current = &state->candidates[
                    state->best_substitution_candidate_index];
                bool same_alignment = mpeg_repair_same_alignment(
                    &repair, current);
                if (same_alignment
                    && repair.target_slot != current->target_slot) {
                  selected = repair.target_slot < current->target_slot;
                }
                else if (repair.target_slot == current->target_slot
                    && repair.anchor_source_offset
                    != current->anchor_source_offset) {
                  selected = repair.anchor_source_offset
                      < current->anchor_source_offset;
                }
                else {
                  selected = mpeg_repair_candidate_better(&repair, current);
                }
              }
              if (selected) {
                state->best_substitution_progress =
                    substitution_layout->parsed_extent;
                state->best_substitution_candidate_index = repair_index;
                state->best_substitution_run_blocks = (uint32_t)run_blocks;
              }
            }
            if (scalpel_state.mode_verbose
                || mpeg_reassembly_debug_candidate(*candidate)) {
              lock_fprintf(
                  stdout,
                  "MPEG reassembly: substitution rank=%" PRIu32
                  " slot=%" PRIu64 " source=%" PRId64
                  " blocks=%" PRIu64 " progress=%" PRIu64
                  " terminal=%s published=%s%s.\n",
                  repair_index, repair.target_slot,
                  repair.source_actual, run_blocks,
                  substitution_layout->parsed_extent,
                  substitution_terminal ? "true" : "false",
                  published ? "true" : "false",
                  selected ? " selected" : "");
            }
            free_blockvector(&substitution);
          }

          if (atomic_load_explicit(&REASS_RETURN_TO_IDLE,
                                   memory_order_acquire)) {
            uint32_t next_trial_index = state->trial_index;
            state->trial_index = repair_index;
            state->substitution_candidate_index = repair_index;
            state->substitution_next_run = run_blocks < UINT32_MAX
                ? (uint32_t)(run_blocks + 1) : UINT32_MAX;
            if (mpeg_reassembly_checkpoint(work, candidate, state,
                                           uuidp, uuidc)) {
              free_blockvector(&trial);
              free(prefix_index);
              mpeg_free_carve_state((void **)&state);
              return;
            }
            state->trial_index = next_trial_index;
          }
          if (state->substitution_terminal_hypotheses
              >= MPEG_TERMINAL_HYPOTHESES) {
            break;
          }
        }
      }
      state->substitution_candidate_index = UINT32_MAX;
      state->substitution_next_run = 1;

      if (!progressed) {
        if (mpeg_reassembly_debug_candidate(*candidate)) {
          lock_fprintf(stdout,
                       "MPEG reassembly: rank=%" PRIu32
                       " slot=%" PRIu64 " source=%" PRId64
                       " rejected (parsed=%" PRIu64
                       ", anchor=%" PRIu64 ", packets=%" PRIu64
                       "/%" PRIu64 ", header=%s, strong=%s,"
                       " timestamps=%s).\n",
                       repair_index, repair.target_slot,
                       repair.source_actual, trial_layout->parsed_extent,
                       state->anchor_offset, trial_layout->packet_count,
                       ranking_layout->packet_count,
                       trial_layout->header_valid ? "true" : "false",
                       mpeg_layout_strong(trial_layout) ? "true" : "false",
                       trial_layout->timestamp_valid ? "true" : "false");
        }
        free_blockvector(&trial);
        if (mpeg_reassembly_checkpoint(work, candidate, state,
                                       uuidp, uuidc)) {
          free(prefix_index);
          mpeg_free_carve_state((void **)&state);
          return;
        }
        continue;
      }

      if (terminal) {
        state->terminal_candidates[repair_index] = 1;
        if (scalpel_state.mode_verbose
            || mpeg_reassembly_debug_candidate(*candidate)) {
          lock_fprintf(stdout,
                       "MPEG reassembly: rank=%" PRIu32
                       " slot=%" PRIu64 " source=%" PRId64
                       " progress=%" PRIu64
                       " terminal=true retained.\n",
                       repair_index, repair.target_slot,
                       repair.source_actual, trial_layout->parsed_extent);
        }
        free_blockvector(&trial);
        if (mpeg_reassembly_checkpoint(work, candidate, state,
                                       uuidp, uuidc)) {
          free(prefix_index);
          mpeg_free_carve_state((void **)&state);
          return;
        }
        continue;
      }

      state->candidates[repair_index].parsed_progress =
          trial_layout->parsed_extent;
      state->candidates[repair_index].nonterminal_progress = 1;

      bool audio_interrupted = false;
      bool select_nonterminal = state->best_nonterminal_index == UINT32_MAX;
      if (!select_nonterminal) {
        const MpegRepairCandidate *selected =
            &state->candidates[state->best_nonterminal_index];
        bool same_alignment = mpeg_repair_same_alignment(&repair, selected);
        bool same_source = repair.source_actual == selected->source_actual;
        uint64_t source_delta = repair.source_actual
                >= selected->source_actual
            ? (uint64_t)(repair.source_actual - selected->source_actual)
            : (uint64_t)(selected->source_actual - repair.source_actual);
        uint64_t local_blocks = CEILDIV(
            MPEG_LOCAL_REPAIR_BYTES, scalpel_state.blocksize);
        bool adjacent_remote = repair.target_slot == selected->target_slot
            && source_delta == 1
            && repair.distance > local_blocks
            && selected->distance > local_blocks;
        bool earlier_same_alignment = !selected->local_continuation
            && same_alignment
            && repair.target_slot < selected->target_slot;
        bool stronger_alternative = (same_source || adjacent_remote)
            && trial_layout->parsed_extent
                > state->best_nonterminal_progress;
        bool stronger_local_continuation = repair.local_continuation
            && trial_layout->parsed_extent
                > state->best_nonterminal_progress;
        bool equally_progressed_nearer = repair.target_slot
                == selected->target_slot
            && trial_layout->parsed_extent
                == state->best_nonterminal_progress
            && repair.distance < selected->distance;
        bool structurally_preferred =
            mpeg_repair_candidate_better(&repair, selected);
        uint64_t locality_tolerance = CEILDIV(
            MPEG_REPAIR_TRACE_BYTES, scalpel_state.blocksize);
        bool comparable_locality = repair.distance <= selected->distance
            || repair.distance - selected->distance <= locality_tolerance;
        bool farther_competitive = trial_layout->parsed_extent
                > state->best_nonterminal_progress
            && !same_alignment
            && (structurally_preferred || comparable_locality)
            && mpeg_repair_terminal_competitive(&repair, selected);
        // Equivalent alignments differ only in where uncertain bytes are
        // discarded. Retain the earliest structurally successful boundary.
        select_nonterminal = earlier_same_alignment || stronger_alternative
            || stronger_local_continuation || equally_progressed_nearer
            || farther_competitive;
        uint64_t common_slot = repair.target_slot < selected->target_slot
            ? repair.target_slot : selected->target_slot;
        if (common_slot <= UINT64_MAX / scalpel_state.blocksize) {
          uint64_t boundary = common_slot * scalpel_state.blocksize;
          int audio = mpeg_audio_continuity(
              trial_data, trial_layout->parsed_extent, boundary,
              &audio_interrupted);
          if (audio != 0 && (audio > 0) != select_nonterminal
              && selected->anchor_source_offset <= UINT64_MAX - 16) {
            BlockVector *prior = mpeg_reassembly_build_trial(
                *candidate, selected->target_slot, selected->source_actual,
                CEILDIV(selected->anchor_source_offset + 16,
                        scalpel_state.blocksize), image_blocks,
                prefix_index, prefix_count);
            if (prior) {
              uint64_t prior_length = blockvector_get_data_length(prior);
              if (prior_length > selected->parsed_progress) {
                prior_length = selected->parsed_progress;
              }
              int previous_audio = mpeg_audio_continuity(
                  (const uint8_t *)blockvector_get_data_pointer(prior),
                  prior_length, boundary, &audio_interrupted);
              // Neutral or equally decodable alternatives keep their
              // structural ranking. Only opposing evidence changes it.
              if (!audio_interrupted && audio * previous_audio < 0) {
                select_nonterminal = audio > previous_audio;
              }
              free_blockvector(&prior);
            }
          }
        }
      }
      if (audio_interrupted) {
        // Resume this comparison without repeating completed bridge trials.
        state->trial_index = repair_index;
        state->substitution_candidate_index = repair_index;
        state->substitution_next_run = (uint32_t)CEILDIV(
            MPEG_REPAIR_TRACE_BYTES, scalpel_state.blocksize) + 1;
        free_blockvector(&trial);
        if (mpeg_reassembly_checkpoint(work, candidate, state,
                                       uuidp, uuidc)) {
          free(prefix_index);
          mpeg_free_carve_state((void **)&state);
          return;
        }
        continue;
      }
      if (select_nonterminal) {
        state->best_nonterminal_index = repair_index;
        state->best_nonterminal_progress = trial_layout->parsed_extent;
      }
      if (scalpel_state.mode_verbose
          || mpeg_reassembly_debug_candidate(*candidate)) {
        lock_fprintf(stdout,
                     "MPEG reassembly: rank=%" PRIu32
                     " slot=%" PRIu64 " source=%" PRId64
                     " progress=%" PRIu64 " terminal=false%s.\n",
                     repair_index, repair.target_slot,
                     repair.source_actual, trial_layout->parsed_extent,
                     state->best_nonterminal_index == repair_index
                         ? " selected" : "");
      }
      free_blockvector(&trial);
      if (mpeg_reassembly_checkpoint(work, candidate, state,
                                     uuidp, uuidc)) {
        free(prefix_index);
        mpeg_free_carve_state((void **)&state);
        return;
      }
    }

    if (state->phase == 2
        && state->trial_index >= state->candidate_count) {
      const MpegRepairCandidate *nonterminal =
          state->best_nonterminal_index < state->candidate_count
              ? &state->candidates[state->best_nonterminal_index] : NULL;
      for (uint32_t index = 0; index < state->candidate_count; index++) {
        if (state->terminal_candidates[index]
            && mpeg_repair_terminal_competitive(&state->candidates[index],
                                                nonterminal)) {
          state->phase = 3;
          state->trial_index = 0;
          carve_put_state((*candidate)->carvehashkey, state);
          break;
        }
      }
    }

    while (state->phase == 3
           && state->trial_index < state->candidate_count
           && *candidate) {
      uint32_t repair_index = state->trial_index++;
      const MpegRepairCandidate *nonterminal =
          state->best_nonterminal_index < state->candidate_count
              ? &state->candidates[state->best_nonterminal_index] : NULL;
      if (!state->terminal_candidates[repair_index]
          || !mpeg_repair_terminal_competitive(
              &state->candidates[repair_index], nonterminal)) {
        continue;
      }

      MpegRepairCandidate repair = state->candidates[repair_index];
      uint64_t local_blocks = CEILDIV(
          MPEG_LOCAL_REPAIR_BYTES, scalpel_state.blocksize);
      bool local_terminal = repair.distance <= local_blocks;
      bool published_alignment = false;
      if (!local_terminal) {
        for (uint32_t prior = 0; prior < state->candidate_count; prior++) {
          if (state->direct_terminal_candidates[prior]
              && mpeg_repair_same_alignment(
                  &repair, &state->candidates[prior])) {
            published_alignment = true;
            break;
          }
        }
      }
      if (!local_terminal
          && !published_alignment
          && state->direct_terminal_hypotheses
              >= MPEG_TERMINAL_HYPOTHESES) {
        continue;
      }
      if (repair.anchor_source_offset > UINT64_MAX - 16) {
        continue;
      }
      uint64_t minimum_blocks = CEILDIV(repair.anchor_source_offset + 16,
                                        scalpel_state.blocksize);
      BlockVector *trial = mpeg_reassembly_build_trial(
          *candidate, repair.target_slot, repair.source_actual,
          minimum_blocks, image_blocks, prefix_index, prefix_count);
      if (!trial) {
        continue;
      }

      const uint8_t *trial_data = (const uint8_t *)
          blockvector_get_data_pointer(trial);
      uint64_t trial_length = blockvector_get_data_length(trial);
      MpegLayout *trial_layout = &scratch->trial_layout;
      mpeg_parse_file(trial_data, trial_length, trial_layout);
      bool terminal = mpeg_reassembly_terminal(
          trial_data, trial_length, trial_layout);
      bool progressed = trial_layout->header_valid
          && mpeg_layout_strong(trial_layout)
          && trial_layout->timestamp_valid
          && trial_layout->parsed_extent > state->baseline_progress
          && trial_layout->parsed_extent > state->anchor_offset
          && trial_layout->packet_count > ranking_layout->packet_count
          && terminal;
      bool published = progressed && mpeg_reassembly_publish_hypothesis(
          *candidate, trial, trial_layout);
      if (scalpel_state.mode_verbose
          || mpeg_reassembly_debug_candidate(*candidate)) {
        lock_fprintf(stdout,
                     "MPEG reassembly: terminal rank=%" PRIu32
                     " slot=%" PRIu64 " source=%" PRId64
                     " progress=%" PRIu64 " published=%s.\n",
                     repair_index, repair.target_slot, repair.source_actual,
                     trial_layout->parsed_extent,
                     published ? "true" : "false");
      }
      free_blockvector(&trial);
      if (progressed && !local_terminal) {
        state->direct_terminal_candidates[repair_index] = 1;
        if (!published_alignment) {
          state->direct_terminal_hypotheses++;
        }
      }
      if (mpeg_reassembly_checkpoint(work, candidate, state, uuidp, uuidc)) {
        free(prefix_index);
        mpeg_free_carve_state((void **)&state);
        return;
      }
    }

    if (state->phase == 3
        && state->trial_index >= state->candidate_count
        && (state->best_nonterminal_index < state->candidate_count
            || (state->best_substitution_candidate_index
                    < state->candidate_count
                && state->best_substitution_run_blocks > 0))) {
      state->phase = 2;
      state->trial_index = state->candidate_count;
      carve_put_state((*candidate)->carvehashkey, state);
    }

    if (state->phase == 3
        && state->trial_index >= state->candidate_count) {
      free(prefix_index);
      if (mpeg_reassembly_resume_alternative(*candidate, state,
                                             image_blocks)) {
        continue;
      }
      mpeg_free_carve_state((void **)&state);
      destroy_candidate(candidate);
      return;
    }

    bool substitution_outperformed_direct =
        state->best_nonterminal_index >= state->candidate_count
        || state->best_substitution_progress
            > state->best_nonterminal_progress;
    if (state->phase == 2
        && state->trial_index >= state->candidate_count
        && state->best_substitution_candidate_index < state->candidate_count
        && state->best_substitution_run_blocks > 0
        && state->best_substitution_progress
            > state->baseline_progress
        && substitution_outperformed_direct) {
      bool primary_direct = false;
      uint32_t repair_index = mpeg_reassembly_prepare_bridge_branch(
          state, blockvector, &primary_direct);
      if (repair_index >= state->candidate_count) {
        repair_index = state->best_substitution_candidate_index;
      }
      if (primary_direct) {
        state->best_nonterminal_index = repair_index;
      }
      else {
        state->best_substitution_candidate_index = repair_index;
        if (state->candidates[repair_index].bridge_run_blocks > 0) {
          state->best_substitution_run_blocks =
              state->candidates[repair_index].bridge_run_blocks;
        }
        MpegRepairCandidate repair = state->candidates[repair_index];
        MpegLayout *trial_layout = &scratch->trial_layout;
        bool terminal = false;
        BlockVector *trial = mpeg_reassembly_build_bridge_trial(
            *candidate, repair.target_slot, repair.source_actual,
            state->best_substitution_run_blocks, image_blocks,
            prefix_index, prefix_count, state->baseline_progress,
            trial_layout, &terminal);
        if (trial) {
          bool progressed = !terminal && trial_layout->header_valid
              && mpeg_layout_strong(trial_layout)
              && trial_layout->timestamp_valid
              && trial_layout->parsed_extent
                  >= state->best_substitution_progress
              && trial_layout->parsed_extent > state->baseline_progress
              && trial_layout->packet_count > ranking_layout->packet_count;
          uint64_t retained_blocks = progressed
              ? trial_layout->parsed_extent / scalpel_state.blocksize : 0;
          if (retained_blocks > 0
              && retained_blocks <= blockvector_get_num_blocks(trial)) {
            if (retained_blocks < blockvector_get_num_blocks(trial)) {
              resize_blockvector(trial, retained_blocks);
              inflate_blockvector(trial);
            }
            blockvector_set_data_length(
                trial, retained_blocks * (uint64_t)scalpel_state.blocksize);
            state->repairs++;
            if (scalpel_state.mode_verbose
                || mpeg_reassembly_debug_candidate(*candidate)) {
              lock_fprintf(stdout,
                           "MPEG reassembly: committed bridge rank=%" PRIu32
                           " slot=%" PRIu64 " source=%" PRId64
                           " blocks=%" PRIu32 " progress=%" PRIu64 ".\n",
                           repair_index, repair.target_slot,
                           repair.source_actual,
                           state->best_substitution_run_blocks,
                           trial_layout->parsed_extent);
            }
            free_blockvector(&(*candidate)->b);
            (*candidate)->b = trial;
            state->signature = 0;
            state->phase = 0;
            state->trial_index = 0;
            state->candidate_count = 0;
            state->best_nonterminal_index = UINT32_MAX;
            state->substitution_candidate_index = UINT32_MAX;
            state->substitution_next_run = 1;
            state->best_nonterminal_progress = 0;
            state->best_substitution_candidate_index = UINT32_MAX;
            state->best_substitution_run_blocks = 0;
            state->best_substitution_progress = 0;
            state->substitution_terminal_hypotheses = 0;
            state->direct_terminal_hypotheses = 0;
            mpeg_reassembly_clear_terminal_candidates(state);
            carve_put_state((*candidate)->carvehashkey, state);
            advanced = true;
          }
          else {
            free_blockvector(&trial);
          }
        }
      }
    }

    if (state->phase == 2
        && state->trial_index >= state->candidate_count
        && !advanced
        && state->best_nonterminal_index < state->candidate_count) {
      uint32_t branch_choice = mpeg_reassembly_prepare_branch(state, blockvector);
      if (branch_choice < state->candidate_count) {
        state->best_nonterminal_index = branch_choice;
      }
      MpegRepairCandidate repair =
          state->candidates[state->best_nonterminal_index];
      if (repair.anchor_source_offset <= UINT64_MAX - 16) {
        uint64_t minimum_blocks = CEILDIV(
            repair.anchor_source_offset + 16, scalpel_state.blocksize);
        BlockVector *trial = mpeg_reassembly_build_trial(
            *candidate, repair.target_slot, repair.source_actual,
            minimum_blocks, image_blocks, prefix_index, prefix_count);
        if (trial) {
          const uint8_t *trial_data = (const uint8_t *)
              blockvector_get_data_pointer(trial);
          uint64_t trial_length = blockvector_get_data_length(trial);
          MpegLayout *trial_layout = &scratch->trial_layout;
          MpegParseResult trial_result = mpeg_reassembly_parse_trial(
              trial_data, trial_length, trial_layout);
          bool progressed = trial_layout->header_valid
              && mpeg_layout_strong(trial_layout)
              && trial_layout->timestamp_valid
              && trial_layout->parsed_extent > state->baseline_progress
              && trial_layout->parsed_extent > state->anchor_offset
              && trial_layout->packet_count > ranking_layout->packet_count;
          if (progressed
              && !mpeg_reassembly_terminal(trial_data, trial_length,
                                            trial_layout)) {
            uint64_t retained = trial_layout->parsed_extent;
            if (trial_result == MPEG_PARSE_PARTIAL
                && trial_layout->required_extent > trial_length
                && trial_layout->failure_offset != UINT64_MAX
                && trial_layout->failure_offset > retained) {
              retained = trial_layout->failure_offset;
            }
            uint64_t retained_blocks = CEILDIV(
                retained, scalpel_state.blocksize);
            if (retained_blocks < blockvector_get_num_blocks(trial)) {
              resize_blockvector(trial, retained_blocks);
              inflate_blockvector(trial);
            }
            blockvector_set_data_length(trial, retained);
            state->repairs++;
            if (scalpel_state.mode_verbose
                || mpeg_reassembly_debug_candidate(*candidate)) {
              lock_fprintf(stdout,
                           "MPEG reassembly: committed rank=%" PRIu32
                           " slot=%" PRIu64 " source=%" PRId64
                           " progress=%" PRIu64 ".\n",
                           state->best_nonterminal_index,
                           repair.target_slot, repair.source_actual,
                           trial_layout->parsed_extent);
            }
            free_blockvector(&(*candidate)->b);
            (*candidate)->b = trial;
            state->signature = 0;
            state->phase = 0;
            state->trial_index = 0;
            state->candidate_count = 0;
            state->best_nonterminal_index = UINT32_MAX;
            state->substitution_candidate_index = UINT32_MAX;
            state->substitution_next_run = 1;
            state->best_nonterminal_progress = 0;
            state->best_substitution_candidate_index = UINT32_MAX;
            state->best_substitution_run_blocks = 0;
            state->best_substitution_progress = 0;
            state->substitution_terminal_hypotheses = 0;
            state->direct_terminal_hypotheses = 0;
            mpeg_reassembly_clear_terminal_candidates(state);
            carve_put_state((*candidate)->carvehashkey, state);
            advanced = true;
          }
          else {
            free_blockvector(&trial);
          }
        }
      }
    }
    free(prefix_index);
    if (advanced) {
      continue;
    }
    break;
  }
  if (*candidate && state->branch_depth > 0
      && mpeg_reassembly_resume_alternative(*candidate, state,
                                            image_blocks)) {
    goto mpeg_reassembly_restart;
  }
  if (*candidate && !state->boundary_fallback_done) {
    state->boundary_fallback_done = 1;
    state->next_anchor_actual = 0;
    state->phase = 4;
    state->trial_index = 0;
    state->candidate_count = 0;
    state->best_nonterminal_index = UINT32_MAX;
    state->substitution_candidate_index = UINT32_MAX;
    state->substitution_next_run = 1;
    state->best_nonterminal_progress = 0;
    state->best_substitution_candidate_index = UINT32_MAX;
    state->best_substitution_run_blocks = 0;
    state->best_substitution_progress = 0;
    state->substitution_terminal_hypotheses = 0;
    state->direct_terminal_hypotheses = 0;
    mpeg_reassembly_clear_terminal_candidates(state);
    carve_put_state((*candidate)->carvehashkey, state);
    goto mpeg_reassembly_restart;
  }
  if (*candidate) {
    mpeg_free_carve_state((void **)&state);
    if (scalpel_state.write_promising) {
      (*candidate)->flavor = PROMISING;
      write_candidate(candidate, false);
    }
    else {
      destroy_candidate(candidate);
    }
  }
  else {
    mpeg_free_carve_state((void **)&state);
  }
}

// Allocate parser scratch once, and release it on every search return,
// including checkpoint yields and completed or discarded candidates.
static inline void mpeg_reassembly(ThreadWork *work, CarveInfo **candidate,
                                   uuid_string_t uuidp,
                                   uuid_string_t uuidc) {
  MpegReassemblyScratch *scratch =
      (MpegReassemblyScratch *)malloc(sizeof(*scratch));
  check_memory_allocation(scratch, __LINE__, __FILE__,
                          "MpegReassemblyScratch");
  mpeg_reassembly_search(work, candidate, uuidp, uuidc, scratch);
  free(scratch);
}

#endif
