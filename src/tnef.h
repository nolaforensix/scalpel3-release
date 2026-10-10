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

#if !defined(SCALPEL_TNEF_H)
#define SCALPEL_TNEF_H

#include "scalpel.h"

#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <zlib.h>
#include "validator_search.h"

#define TNEF_SIGNATURE                  UINT32_C(0x223e9f78)
#define TNEF_STREAM_HEADER_SIZE         UINT64_C(6)
#define TNEF_ATTRIBUTE_HEADER_SIZE      UINT64_C(9)
#define TNEF_ATTRIBUTE_CHECKSUM_SIZE    UINT64_C(2)
#define TNEF_ATTRIBUTE_OVERHEAD         (TNEF_ATTRIBUTE_HEADER_SIZE \
                                         + TNEF_ATTRIBUTE_CHECKSUM_SIZE)
#define TNEF_MINIMUM_SIZE               UINT64_C(40)
#define TNEF_LEVEL_MESSAGE              UINT8_C(1)
#define TNEF_LEVEL_ATTACHMENT           UINT8_C(2)
#define TNEF_ATTRIBUTE_VERSION          UINT32_C(0x00089006)
#define TNEF_ATTRIBUTE_CODEPAGE         UINT32_C(0x00069007)
#define TNEF_ATTRIBUTE_ATTACHMENT_START UINT32_C(0x00069002)
#define TNEF_VERSION                    UINT32_C(0x00010000)
#define TNEF_MAXIMUM_ATTRIBUTE_TYPE     UINT16_C(8)
#define TNEF_REASSEMBLY_POLL_INTERVAL   UINT64_C(256)
#define TNEF_REASSEMBLY_SEAM_BYTES      UINT64_C(512)
#define TNEF_REASSEMBLY_SEAM_BUFFER     UINT64_C(1100)
#define TNEF_REASSEMBLY_CONTENT_SAMPLES UINT64_C(1048576)
#define TNEF_REASSEMBLY_CONTENT_MINIMUM UINT64_C(8192)

typedef enum TnefParseResult {
  TNEF_PARSE_INVALID = 0,
  TNEF_PARSE_COMPLETE,
  TNEF_PARSE_TRUNCATED,
  TNEF_PARSE_DAMAGED
} TnefParseResult;

typedef struct TnefParseSummary {
  uint64_t verified_end;
  uint64_t attribute_count;
  uint64_t attachment_count;
  uint64_t pending_attribute_start;
  uint64_t pending_payload_offset;
  uint64_t pending_payload_length;
  uint64_t pending_attribute_end;
} TnefParseSummary;

typedef enum TnefRecoveryResult {
  TNEF_RECOVERY_NO_MATCH = 0,
  TNEF_RECOVERY_MATCH,
  TNEF_RECOVERY_INTERRUPTED
} TnefRecoveryResult;

typedef struct TnefRecoveryScore {
  uint64_t verified_end;
  uint64_t attribute_count;
  uint64_t ordered_prefix;
  uint64_t discontinuity;
  uint64_t reservations;
  uint64_t seam_cost;
  uint32_t content_class;
  uint32_t perturbations;
  bool continuation;
  bool complete;
  bool found;
} TnefRecoveryScore;

typedef struct TnefBlockChecksum {
  uint16_t full_payload_sum;
  uint16_t final_payload_sum;
  uint8_t checksum_low;
  uint8_t checksum_high;
  bool readable;
} TnefBlockChecksum;

#define TNEF_SEARCH_MAGIC_V1 UINT32_C(0x544e4631)
#define TNEF_SEARCH_MAGIC UINT32_C(0x544e4632)
typedef enum {
  TNEF_SEARCH_DIRECT, TNEF_SEARCH_INDEX, TNEF_SEARCH_GAP, TNEF_SEARCH_DISPLACED
} TnefSearchPhase;

typedef struct {
  uint32_t magic;
  TnefSearchPhase phase;
  XXH128_hash_t view;
  uint64_t block_count;
  uint64_t image_blocks;
  uint64_t index_count;
  uint64_t complexity;
  uint64_t gap_length;
  uint64_t gap_slot;
  uint64_t run_slot;
  uint64_t next_apparent;
  TnefRecoveryScore best;
} TnefSearchProgress;

typedef struct {
  TnefSearchProgress progress;
  int64_t *best_actual;
  TnefBlockChecksum *index;
  TnefParseSummary pending;
  uint64_t prefix_blocks;
  XXH128_hash_t prefix;
} TnefCarveState;

static inline bool tnef_serialize_carve_state(void **state, FILE *fp, StateSerialization mode);
static inline void *tnef_clone_carve_state(const void *state);
static inline void tnef_free_carve_state(void **state);
static inline size_t tnef_sizeof_carve_state(const void *state);
static inline void tnef_print_carve_state(const void *state);
static inline XXH128_hash_t tnef_search_prefix(CarveInfo *candidate, uint64_t blocks);
static inline bool tnef_search_poll(ThreadWork *work, CarveInfo **candidate,
    uuid_string_t uuidp, uuid_string_t uuidc, TnefCarveState *state,
    const int64_t *best_mapping);

static inline uint16_t tnef_read_le16(const uint8_t *data);
static inline uint32_t tnef_read_le32(const uint8_t *data);
static inline uint16_t tnef_payload_checksum(const uint8_t *data,
                                             uint64_t length);
static inline bool tnef_attribute_header_valid(uint8_t level,
                                               uint32_t attribute);
static inline TnefParseResult tnef_parse(const uint8_t *data,
                                         uint64_t length,
                                         TnefParseSummary *summary);
static inline void tnef_file_validate(char *data, uint64_t length,
                                      bool *validates,
                                      uint64_t *validates_to,
                                      bool *promising,
                                      uint32_t needleidx,
                                      uint32_t blocksize,
                                      void *carvehashkey);
static inline void tnef_candidate_validate(CarveInfo *candidate,
                                           bool *validates,
                                           uint64_t *validates_to,
                                           bool *promising);
static inline bool tnef_candidate_is_contiguous(const CarveInfo *candidate);
static inline bool tnef_reassembly_poll(ThreadWork *work,
                                        CarveInfo **candidate,
                                        uuid_string_t uuidp,
                                        uuid_string_t uuidc);
static inline bool tnef_reassembly_mapping_valid(
    BlockVector *blockvector,
    const int64_t *mapping,
    uint64_t committed_blocks,
    uint64_t block_count);
static inline bool tnef_reassembly_copy_block(uint8_t *destination,
                                              int64_t apparent);
static inline bool tnef_reassembly_materialize(uint8_t *data,
                                               const int64_t *mapping,
                                               uint64_t block_count);
static inline uint64_t tnef_reassembly_seam_cost(
    const uint8_t *data,
    const int64_t *mapping,
    uint64_t block_count);
static inline uint32_t tnef_reassembly_content_class(
    const uint8_t *data,
    uint64_t length);
static inline bool tnef_reassembly_build_checksum_index(
    ThreadWork *work,
    CarveInfo **candidate,
    uuid_string_t uuidp,
    uuid_string_t uuidc,
    const TnefParseSummary *current_summary,
    TnefBlockChecksum *index,
    uint64_t image_blocks, TnefCarveState *state, const int64_t *best_mapping);
static inline bool tnef_reassembly_mapping_checksum_matches(
    const uint8_t *committed_data,
    const TnefParseSummary *current_summary,
    const int64_t *mapping,
    uint64_t block_count,
    uint64_t committed_blocks,
    uint16_t committed_payload_sum,
    const TnefBlockChecksum *checksum_index,
    uint64_t image_blocks);
static inline bool tnef_reassembly_score_better(
    const TnefRecoveryScore *trial,
    const TnefRecoveryScore *best);
static inline bool tnef_reassembly_score_confident(
    const TnefRecoveryScore *score,
    uint32_t minimum_content_class);
static inline void tnef_reassembly_consider_trial(
    CarveInfo *candidate,
    const uint8_t *data,
    uint64_t data_length,
    const int64_t *mapping,
    uint64_t block_count,
    uint64_t current_progress,
    uint64_t target_attribute_end,
    uint32_t perturbations,
    TnefRecoveryScore *best,
    int64_t *best_mapping);
static inline bool tnef_reassembly_fill_mapping(
    BlockVector *blockvector,
    int64_t *mapping,
    uint64_t committed_blocks,
    uint64_t block_count,
    uint64_t gap_slot,
    uint64_t gap_length);
static inline TnefRecoveryResult tnef_reassembly_try_displaced_run(
    ThreadWork *work,
    CarveInfo **candidate,
    uuid_string_t uuidp,
    uuid_string_t uuidc,
    const TnefParseSummary *current_summary,
    uint8_t *trial_data,
    uint64_t data_length,
    int64_t *mapping,
    uint64_t block_count,
    uint64_t committed_blocks,
    uint64_t attribute_blocks,
    uint64_t run_length,
    uint32_t perturbations,
    const TnefBlockChecksum *checksum_index,
    TnefRecoveryScore *best,
    int64_t *best_mapping, TnefCarveState *state);
static inline TnefRecoveryResult tnef_reassembly_repair_attribute(
    ThreadWork *work,
    CarveInfo **candidate,
    uuid_string_t uuidp,
    uuid_string_t uuidc,
    const TnefParseSummary *current_summary,
    uint64_t committed_blocks);
static inline void tnef_reassembly(ThreadWork *work,
                                   CarveInfo **candidate,
                                   uuid_string_t uuidp,
                                   uuid_string_t uuidc);

static inline uint16_t tnef_read_le16(const uint8_t *data) {

  return (uint16_t)data[0] | ((uint16_t)data[1] << 8);
}

static inline uint32_t tnef_read_le32(const uint8_t *data) {

  return (uint32_t)data[0]
         | ((uint32_t)data[1] << 8)
         | ((uint32_t)data[2] << 16)
         | ((uint32_t)data[3] << 24);
}

static inline uint16_t tnef_payload_checksum(const uint8_t *data,
                                             uint64_t length) {

  uint32_t checksum = 0;

  for (uint64_t offset = 0; offset < length; offset++) {
    checksum += data[offset];
  }
  return (uint16_t)checksum;
}

static inline bool tnef_attribute_header_valid(uint8_t level,
                                               uint32_t attribute) {

  const uint16_t attribute_type = (uint16_t)(attribute >> 16);

  return (level == TNEF_LEVEL_MESSAGE
          || level == TNEF_LEVEL_ATTACHMENT)
         && attribute_type <= TNEF_MAXIMUM_ATTRIBUTE_TYPE;
}

// Parse the sequence of checksummed TNEF attributes. A complete result ends
// at the last verified attribute; bytes after that boundary belong to the
// surrounding image rather than the TNEF stream.
//
static inline TnefParseResult tnef_parse(const uint8_t *data,
                                         uint64_t length,
                                         TnefParseSummary *summary) {

  if (!summary) {
    return TNEF_PARSE_INVALID;
  }
  memset(summary, 0, sizeof(*summary));

  if (!data || length < TNEF_MINIMUM_SIZE
      || tnef_read_le32(data) != TNEF_SIGNATURE
      || tnef_read_le16(data + 4) == 0) {
    return TNEF_PARSE_INVALID;
  }

  uint64_t offset = TNEF_STREAM_HEADER_SIZE;
  bool attachment_sequence = false;

  while (offset < length) {
    summary->pending_attribute_start = 0;
    summary->pending_payload_offset = 0;
    summary->pending_payload_length = 0;
    summary->pending_attribute_end = 0;

    if (length - offset < TNEF_ATTRIBUTE_OVERHEAD) {
      break;
    }

    const uint8_t level = data[offset];
    const uint32_t attribute = tnef_read_le32(data + offset + 1);
    const uint64_t payload_length = tnef_read_le32(data + offset + 5);

    if (!tnef_attribute_header_valid(level, attribute)
        || payload_length == 0) {
      break;
    }

    const uint64_t payload_offset = offset + TNEF_ATTRIBUTE_HEADER_SIZE;
    const uint64_t attribute_end = payload_offset + payload_length
                                   + TNEF_ATTRIBUTE_CHECKSUM_SIZE;

    summary->pending_attribute_start = offset;
    summary->pending_payload_offset = payload_offset;
    summary->pending_payload_length = payload_length;
    summary->pending_attribute_end = attribute_end;

    if (payload_length > length - payload_offset
        || TNEF_ATTRIBUTE_CHECKSUM_SIZE
               > length - payload_offset - payload_length) {
      return summary->attribute_count >= 2
                 ? TNEF_PARSE_TRUNCATED
                 : TNEF_PARSE_INVALID;
    }

    const uint8_t *payload = data + payload_offset;
    const uint16_t stored_checksum =
        tnef_read_le16(payload + payload_length);

    if (tnef_payload_checksum(payload, payload_length) != stored_checksum) {
      return summary->attribute_count >= 2
                 ? TNEF_PARSE_DAMAGED
                 : TNEF_PARSE_INVALID;
    }

    if (summary->attribute_count == 0) {
      if (level != TNEF_LEVEL_MESSAGE
          || attribute != TNEF_ATTRIBUTE_VERSION
          || payload_length != sizeof(uint32_t)
          || tnef_read_le32(payload) != TNEF_VERSION) {
        return TNEF_PARSE_INVALID;
      }
    }
    else if (summary->attribute_count == 1) {
      if (level != TNEF_LEVEL_MESSAGE
          || attribute != TNEF_ATTRIBUTE_CODEPAGE
          || payload_length != 2 * sizeof(uint32_t)) {
        return TNEF_PARSE_INVALID;
      }
    }
    else if (level == TNEF_LEVEL_ATTACHMENT) {
      if (!attachment_sequence
          && attribute != TNEF_ATTRIBUTE_ATTACHMENT_START) {
        return TNEF_PARSE_INVALID;
      }
      if (attribute == TNEF_ATTRIBUTE_ATTACHMENT_START) {
        summary->attachment_count++;
      }
      attachment_sequence = true;
    }
    else if (attachment_sequence) {
      return TNEF_PARSE_INVALID;
    }

    offset = payload_offset + payload_length
             + TNEF_ATTRIBUTE_CHECKSUM_SIZE;
    summary->verified_end = offset;
    summary->attribute_count++;
    summary->pending_attribute_start = 0;
    summary->pending_payload_offset = 0;
    summary->pending_payload_length = 0;
    summary->pending_attribute_end = 0;
  }

  if (summary->attribute_count < 2) {
    return TNEF_PARSE_INVALID;
  }
  return TNEF_PARSE_COMPLETE;
}

static inline void tnef_file_validate(char *data, uint64_t length,
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

  TnefParseSummary summary;
  const TnefParseResult result = tnef_parse((const uint8_t *)data,
                                             length, &summary);

  if (summary.verified_end > 0) {
    *validates_to = summary.verified_end - 1;
  }
  if (result == TNEF_PARSE_COMPLETE) {
    *validates = true;
  }
  else if (result == TNEF_PARSE_TRUNCATED) {
    *promising = true;
    if (length > 0) {
      *validates_to = length - 1;
    }
  }
  else if (result == TNEF_PARSE_DAMAGED) {
    *promising = true;
  }
}

// TNEF's additive attribute checksum detects damage but is not a unique
// block-level proof. Preserve noncontiguous reconstructions for examination
// without allowing a checksum collision to promote them to VALIDATED.
//
static inline void tnef_candidate_validate(CarveInfo *candidate,
                                           bool *validates,
                                           uint64_t *validates_to,
                                           bool *promising) {

  if (!candidate || !candidate->b || !validates || !validates_to || !promising) {
    return;
  }

  if (!*validates) {
    // The backend may retain only the verified prefix. Preserve the next
    // attribute's description before its header is removed by that trim.
    TnefParseSummary summary;
    const uint64_t length = blockvector_get_data_length(candidate->b);
    const uint64_t blocksize = scalpel_state.blocksize;
    if (*promising && blocksize && tnef_parse(
            (const uint8_t *)blockvector_get_data_pointer(candidate->b),
            length, &summary) != TNEF_PARSE_INVALID
        && summary.verified_end && summary.pending_attribute_end
        && summary.pending_attribute_end <= UINT64_MAX - TNEF_ATTRIBUTE_OVERHEAD) {
      const uint64_t keep = CEILDIV(summary.verified_end, blocksize);
      if (keep <= length / blocksize && keep <= blockvector_get_num_blocks(candidate->b)) {
        TnefCarveState *saved = carve_get_state(candidate->carvehashkey);
        const XXH128_hash_t prefix = tnef_search_prefix(candidate, keep);
        if (!saved || saved->prefix_blocks != keep
            || !XXH128_isEqual(saved->prefix, prefix)
            || memcmp(&saved->pending, &summary, sizeof(summary)) != 0) {
          tnef_free_carve_state((void **)&saved);
          saved = calloc(1, sizeof(*saved));
          check_memory_allocation(saved, __LINE__, __FILE__, "TNEF pending attribute");
          saved->progress.magic = TNEF_SEARCH_MAGIC;
          saved->progress.block_count = CEILDIV(
              summary.pending_attribute_end + TNEF_ATTRIBUTE_OVERHEAD, blocksize);
          saved->progress.image_blocks = filemirror_apparent_blocks(scalpel_state.filemirror);
          saved->pending = summary;
          saved->prefix_blocks = keep;
          saved->prefix = prefix;
          carve_put_state(candidate->carvehashkey, saved);
        }
        tnef_free_carve_state((void **)&saved);
        // Keep the block containing verified bytes through the backend's
        // whole-block trim. The parser's verified_end remains the byte limit.
        *validates_to = keep * blocksize - 1;
      }
    }
    return;
  }

  const uint64_t block_count = blockvector_get_num_blocks(candidate->b);

  TnefCarveState *saved = carve_get_state(candidate->carvehashkey);
  if (saved) {
    const bool pending = saved->pending.pending_attribute_end > blockvector_get_data_length(candidate->b);
    const bool same_prefix = saved->prefix_blocks == block_count
        && XXH128_isEqual(saved->prefix, tnef_search_prefix(candidate, block_count));
    const bool legacy_pending = !saved->prefix_blocks && saved->progress.block_count > block_count;
    tnef_free_carve_state((void **)&saved);
    if ((pending && same_prefix) || legacy_pending) {
      *validates = false;
      *promising = true;
      return;
    }
  }

  if (block_count < 2) {
    return;
  }

  const int64_t first_actual = blockvector_get_actual_blocknumber(
      candidate->b, 0);

  if (first_actual < 0) {
    *validates = false;
    *promising = true;
    return;
  }
  for (uint64_t slot = 1; slot < block_count; slot++) {
    if (blockvector_get_actual_blocknumber(candidate->b, slot)
        != first_actual + (int64_t)slot) {
      *validates = false;
      *promising = true;
      return;
    }
  }
}

static inline bool tnef_candidate_is_contiguous(const CarveInfo *candidate) {

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

static inline bool tnef_reassembly_poll(ThreadWork *work,
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

// Pending attribute metadata depends on the retained prefix, not on changes
// elsewhere in the image that require the source scan to be restarted.
static inline XXH128_hash_t tnef_search_prefix(CarveInfo *candidate, uint64_t blocks) {
  XXH3_state_t hash;
  XXH3_128bits_reset(&hash);
  const uint64_t length = blocks * (uint64_t)scalpel_state.blocksize;
  const uint64_t geometry[] = {blocks, length, scalpel_state.blocksize};
  XXH3_128bits_update(&hash, geometry, sizeof(geometry));
  const uint64_t image_bytes = filemirror_filesize(scalpel_state.filemirror);
  const uint64_t image_blocks = CEILDIV(image_bytes, (uint64_t)scalpel_state.blocksize);
  static const uint8_t zeros[256] = {0};
  for (uint64_t slot = 0; slot < blocks; slot++) {
    const int64_t actual = blockvector_get_actual_blocknumber(candidate->b, slot);
    XXH3_128bits_update(&hash, &actual, sizeof(actual));
    uint64_t available = 0;
    const char *data = actual >= 0 && (uint64_t)actual < image_blocks
        ? filemirror_actual_block_data_pointer(scalpel_state.filemirror, actual, &available) : NULL;
    if (!data) {
      available = 0;
    }
    if (available > scalpel_state.blocksize) {
      available = scalpel_state.blocksize;
    }
    XXH3_128bits_update(&hash, &available, sizeof(available));
    if (available) {
      XXH3_128bits_update(&hash, data, (size_t)available);
    }
    uint64_t padding = scalpel_state.blocksize - available;
    while (padding) {
      const size_t chunk = padding < sizeof(zeros) ? (size_t)padding : sizeof(zeros);
      XXH3_128bits_update(&hash, zeros, chunk);
      padding -= chunk;
    }
  }
  return XXH3_128bits_digest(&hash);
}

// Persist only when yielding. Scratch bytes can be reconstructed; ranked
// mappings, completed checksum entries and nested scan positions cannot.
static inline bool tnef_search_poll(ThreadWork *work, CarveInfo **candidate,
    uuid_string_t uuidp, uuid_string_t uuidc, TnefCarveState *state,
    const int64_t *best_mapping) {
  if (!candidate || !*candidate
      || reassembly_check_kill_queue(work, candidate, uuidp, uuidc)) {
    return true;
  }
  if (!atomic_load_explicit(&REASS_RETURN_TO_IDLE, memory_order_acquire)) {
    return false;
  }
  state->progress.view = validator_search_view(*candidate);
  if (state->progress.best.found) {
    if (!state->best_actual) {
      state->best_actual = malloc((size_t)state->progress.block_count * sizeof(*state->best_actual));
      check_memory_allocation(state->best_actual, __LINE__, __FILE__, "TNEF saved mapping");
    }
    for (uint64_t i = 0; i < state->progress.block_count; i++) {
      state->best_actual[i] = filemirror_actual_blocknumber(scalpel_state.filemirror, best_mapping[i]);
    }
  }
  carve_put_state((*candidate)->carvehashkey, state);
  return reassembly_time_to_checkpoint(work->id, *candidate, uuidp, uuidc);
}

static inline bool tnef_reassembly_mapping_valid(
    BlockVector *blockvector,
    const int64_t *mapping,
    uint64_t committed_blocks,
    uint64_t block_count) {

  if (!blockvector || !mapping || committed_blocks == 0
      || committed_blocks > block_count) {
    return false;
  }

  const int64_t image_blocks = filemirror_apparent_blocks(
      scalpel_state.filemirror);

  for (uint64_t slot = 0; slot < committed_blocks; slot++) {
    if (mapping[slot]
        != blockvector_get_apparent_blocknumber(blockvector, slot)) {
      return false;
    }
  }
  for (uint64_t slot = committed_blocks; slot < block_count; slot++) {
    const int64_t apparent = mapping[slot];

    if (apparent < 0 || apparent >= image_blocks) {
      return false;
    }

    const int64_t actual = filemirror_actual_blocknumber(
        scalpel_state.filemirror, apparent);

    if (actual < 0
        || filemirror_actual_block_covered(scalpel_state.filemirror,
                                           actual)) {
      return false;
    }
    for (uint64_t prior = 0; prior < slot; prior++) {
      if (mapping[prior] == apparent) {
        return false;
      }
    }
  }
  return true;
}

static inline bool tnef_reassembly_copy_block(uint8_t *destination,
                                              int64_t apparent) {

  if (!destination || apparent < 0
      || apparent >= (int64_t)filemirror_apparent_blocks(
          scalpel_state.filemirror)) {
    return false;
  }

  const int64_t actual = filemirror_actual_blocknumber(
      scalpel_state.filemirror, apparent);
  uint64_t available = 0;
  const char *source = filemirror_actual_block_data_pointer(
      scalpel_state.filemirror, actual, &available);

  if (!source) {
    return false;
  }

  memset(destination, 0, scalpel_state.blocksize);
  if (available > scalpel_state.blocksize) {
    available = scalpel_state.blocksize;
  }
  memcpy(destination, source, available);
  return true;
}

static inline bool tnef_reassembly_materialize(uint8_t *data,
                                               const int64_t *mapping,
                                               uint64_t block_count) {

  if (!data || !mapping) {
    return false;
  }
  for (uint64_t slot = 0; slot < block_count; slot++) {
    if (!tnef_reassembly_copy_block(
            data + slot * (uint64_t)scalpel_state.blocksize,
            mapping[slot])) {
      return false;
    }
  }
  return true;
}

// TNEF's additive checksum proves payload membership but not byte order. When
// two mappings verify equally, use compression across their discontinuities as
// a bounded continuity signal. Incompressible seams contribute no preference.
//
static inline uint64_t tnef_reassembly_seam_cost(
    const uint8_t *data,
    const int64_t *mapping,
    uint64_t block_count) {

  const uint64_t blocksize = scalpel_state.blocksize;

  if (!data || !mapping || block_count < 2
      || blocksize < TNEF_REASSEMBLY_SEAM_BYTES) {
    return UINT64_MAX;
  }

  uint8_t seam[2 * TNEF_REASSEMBLY_SEAM_BYTES];
  uint8_t compressed[TNEF_REASSEMBLY_SEAM_BUFFER];
  uint64_t compressed_total = 0;
  uint64_t useful_seams = 0;

  for (uint64_t slot = 1; slot < block_count; slot++) {
    if (mapping[slot] == mapping[slot - 1] + 1) {
      continue;
    }

    memcpy(seam,
           data + slot * blocksize - TNEF_REASSEMBLY_SEAM_BYTES,
           TNEF_REASSEMBLY_SEAM_BYTES);
    memcpy(seam + TNEF_REASSEMBLY_SEAM_BYTES,
           data + slot * blocksize,
           TNEF_REASSEMBLY_SEAM_BYTES);

    uLongf compressed_length = sizeof(compressed);
    const int result = compress2(compressed, &compressed_length, seam,
                                 sizeof(seam), Z_BEST_SPEED);

    if (result == Z_OK && compressed_length + 32 < sizeof(seam)) {
      compressed_total += compressed_length;
      useful_seams++;
    }
  }

  if (useful_seams == 0) {
    return UINT64_MAX;
  }
  return compressed_total * UINT64_C(1024) / useful_seams;
}

// Distinguish structured payloads from checksum-compatible random block
// substitutions using a bounded, evenly distributed sample. A coarse class
// avoids treating insignificant distribution noise as evidence; compressed or
// encrypted payloads naturally return no preference.
//
static inline uint32_t tnef_reassembly_content_class(
    const uint8_t *data,
    uint64_t length) {

  if (!data || length == 0) {
    return 0;
  }

  const uint64_t stride = CEILDIV(length, TNEF_REASSEMBLY_CONTENT_SAMPLES);
  uint32_t counts[256] = {0};
  uint64_t samples = 0;

  for (uint64_t offset = 0; offset < length; offset += stride) {
    counts[data[offset]]++;
    samples++;
  }

  uint64_t concentration = 0;

  for (uint32_t value = 0; value < 256; value++) {
    concentration += (uint64_t)counts[value] * counts[value];
  }
  concentration = concentration * UINT64_C(1000000)
                  / (samples * samples);

  if (concentration < TNEF_REASSEMBLY_CONTENT_MINIMUM) {
    return 0;
  }

  return (uint32_t)(concentration / UINT64_C(4096));
}

// Build the immutable byte contributions used by the additive attribute
// checksum once. Coverage and candidate membership remain live scan-time tests.
//
static inline bool tnef_reassembly_build_checksum_index(
    ThreadWork *work,
    CarveInfo **candidate,
    uuid_string_t uuidp,
    uuid_string_t uuidc,
    const TnefParseSummary *current_summary,
    TnefBlockChecksum *index,
    uint64_t image_blocks, TnefCarveState *state, const int64_t *best_mapping) {

  if (!work || !candidate || !*candidate || !current_summary || !index
      || scalpel_state.blocksize == 0
      || current_summary->pending_payload_length == 0) {
    return false;
  }

  const uint64_t blocksize = scalpel_state.blocksize;
  const uint64_t payload_end = current_summary->pending_payload_offset
                               + current_summary->pending_payload_length;
  const uint64_t final_payload_bytes =
      ((payload_end - 1) % blocksize) + 1;
  const uint64_t checksum_low_offset = payload_end % blocksize;
  const uint64_t checksum_high_offset = (payload_end + 1) % blocksize;

  for (uint64_t apparent = state->progress.index_count; apparent < image_blocks; apparent++) {
    const int64_t actual = filemirror_actual_blocknumber(
        scalpel_state.filemirror, (int64_t)apparent);

    if (actual >= 0) {
      uint64_t available = 0;
      const uint8_t *block = (const uint8_t *)
          filemirror_actual_block_data_pointer(scalpel_state.filemirror,
                                               actual, &available);

      if (block) {
        if (available > blocksize) {
          available = blocksize;
        }
        index[apparent].full_payload_sum =
            tnef_payload_checksum(block, available);
        index[apparent].final_payload_sum = tnef_payload_checksum(
            block, available < final_payload_bytes
                       ? available : final_payload_bytes);
        if (checksum_low_offset < available) {
          index[apparent].checksum_low = block[checksum_low_offset];
        }
        if (checksum_high_offset < available) {
          index[apparent].checksum_high = block[checksum_high_offset];
        }
        index[apparent].readable = true;
      }
    }

    state->progress.index_count = apparent + 1;
    if (((apparent + 1) & (TNEF_REASSEMBLY_POLL_INTERVAL - 1)) == 0
        && tnef_search_poll(work, candidate, uuidp, uuidc, state, best_mapping)) {
      return false;
    }
  }

  return *candidate != NULL;
}

// Reject mappings that cannot satisfy the current attribute checksum before
// copying their blocks or invoking the full stream parser.
//
static inline bool tnef_reassembly_mapping_checksum_matches(
    const uint8_t *committed_data,
    const TnefParseSummary *current_summary,
    const int64_t *mapping,
    uint64_t block_count,
    uint64_t committed_blocks,
    uint16_t committed_payload_sum,
    const TnefBlockChecksum *checksum_index,
    uint64_t image_blocks) {

  if (!committed_data || !current_summary || !mapping || !checksum_index
      || scalpel_state.blocksize == 0
      || current_summary->pending_payload_length == 0) {
    return false;
  }

  const uint64_t blocksize = scalpel_state.blocksize;
  const uint64_t payload_offset = current_summary->pending_payload_offset;
  const uint64_t payload_end = payload_offset
                               + current_summary->pending_payload_length;
  const uint64_t first_payload_slot = payload_offset / blocksize;
  const uint64_t final_payload_slot = (payload_end - 1) / blocksize;
  const uint64_t checksum_offset = payload_end;
  const uint64_t checksum_low_slot = checksum_offset / blocksize;
  const uint64_t checksum_high_slot = (checksum_offset + 1) / blocksize;
  uint32_t payload_sum = committed_payload_sum;

  if (final_payload_slot >= block_count
      || checksum_high_slot >= block_count) {
    return false;
  }

  const uint64_t first_mutable_slot = first_payload_slot > committed_blocks
                                          ? first_payload_slot
                                          : committed_blocks;

  for (uint64_t slot = first_mutable_slot;
       slot <= final_payload_slot; slot++) {
    const uint64_t slot_start = slot * blocksize;
    const uint64_t slot_end = slot_start + blocksize;
    const uint64_t overlap_start = payload_offset > slot_start
                                       ? payload_offset : slot_start;
    const uint64_t overlap_end = payload_end < slot_end
                                     ? payload_end : slot_end;

    const int64_t apparent = mapping[slot];

    if (apparent < 0 || (uint64_t)apparent >= image_blocks
        || !checksum_index[apparent].readable) {
      return false;
    }

    const TnefBlockChecksum *entry = &checksum_index[apparent];

    if (overlap_start == slot_start) {
      payload_sum += overlap_end == slot_end
                         ? entry->full_payload_sum
                         : entry->final_payload_sum;
    }
    else {
      const int64_t actual = filemirror_actual_blocknumber(
          scalpel_state.filemirror, apparent);
      uint64_t available = 0;
      const uint8_t *block = actual < 0 ? NULL : (const uint8_t *)
          filemirror_actual_block_data_pointer(scalpel_state.filemirror,
                                               actual, &available);

      if (!block) {
        return false;
      }
      if (available > blocksize) {
        available = blocksize;
      }
      const uint64_t relative_start = overlap_start - slot_start;
      const uint64_t relative_end = overlap_end - slot_start;

      if (relative_start < available) {
        payload_sum += tnef_payload_checksum(
            block + relative_start,
            (relative_end < available ? relative_end : available)
                - relative_start);
      }
    }
  }

  uint16_t stored_checksum = 0;

  if (checksum_low_slot < committed_blocks) {
    stored_checksum = committed_data[checksum_offset];
  }
  else {
    const int64_t apparent = mapping[checksum_low_slot];

    if (apparent < 0 || (uint64_t)apparent >= image_blocks
        || !checksum_index[apparent].readable) {
      return false;
    }
    stored_checksum = checksum_index[apparent].checksum_low;
  }

  if (checksum_high_slot < committed_blocks) {
    stored_checksum |= (uint16_t)committed_data[checksum_offset + 1] << 8;
  }
  else {
    const int64_t apparent = mapping[checksum_high_slot];

    if (apparent < 0 || (uint64_t)apparent >= image_blocks
        || !checksum_index[apparent].readable) {
      return false;
    }
    stored_checksum |= (uint16_t)checksum_index[apparent].checksum_high << 8;
  }

  return stored_checksum == (uint16_t)payload_sum;
}

static inline bool tnef_reassembly_score_better(
    const TnefRecoveryScore *trial,
    const TnefRecoveryScore *best) {

  if (!trial || !trial->found) {
    return false;
  }
  if (!best || !best->found) {
    return true;
  }
  if (trial->verified_end != best->verified_end) {
    return trial->verified_end > best->verified_end;
  }
  if (trial->attribute_count != best->attribute_count) {
    return trial->attribute_count > best->attribute_count;
  }
  if (trial->continuation != best->continuation) {
    return trial->continuation;
  }
  if (trial->complete != best->complete) {
    return trial->complete;
  }
  if (trial->perturbations != best->perturbations) {
    return trial->perturbations < best->perturbations;
  }
  if (trial->content_class != best->content_class) {
    return trial->content_class > best->content_class;
  }
  if (trial->seam_cost != best->seam_cost) {
    if (trial->seam_cost == UINT64_MAX) {
      return false;
    }
    if (best->seam_cost == UINT64_MAX) {
      return true;
    }
    return trial->seam_cost < best->seam_cost;
  }
  if (trial->ordered_prefix != best->ordered_prefix) {
    return trial->ordered_prefix > best->ordered_prefix;
  }
  if (trial->discontinuity != best->discontinuity) {
    return trial->discontinuity < best->discontinuity;
  }
  return trial->reservations < best->reservations;
}

static inline bool tnef_reassembly_score_confident(
    const TnefRecoveryScore *score,
    uint32_t minimum_content_class) {

  return score && score->found && score->continuation
         && (score->perturbations == 0
             || minimum_content_class == 0
             || score->content_class >= minimum_content_class);
}

static inline void tnef_reassembly_consider_trial(
    CarveInfo *candidate,
    const uint8_t *data,
    uint64_t data_length,
    const int64_t *mapping,
    uint64_t block_count,
    uint64_t current_progress,
    uint64_t target_attribute_end,
    uint32_t perturbations,
    TnefRecoveryScore *best,
    int64_t *best_mapping) {

  if (!candidate || !data || !mapping || !best || !best_mapping) {
    return;
  }

  TnefParseSummary summary;
  const TnefParseResult result = tnef_parse(data, data_length, &summary);

  if (result == TNEF_PARSE_INVALID
      || summary.verified_end <= current_progress) {
    return;
  }

  TnefRecoveryScore trial = {
    .verified_end = summary.verified_end,
    .attribute_count = summary.attribute_count,
    .ordered_prefix = block_count,
    .discontinuity = 0,
    .reservations = 0,
    .seam_cost = tnef_reassembly_seam_cost(data, mapping, block_count),
    .content_class = tnef_reassembly_content_class(data, data_length),
    .perturbations = perturbations,
    .continuation = summary.verified_end > target_attribute_end
                    || summary.pending_attribute_end > summary.verified_end,
    .complete = result == TNEF_PARSE_COMPLETE,
    .found = true
  };

  for (uint64_t slot = 0; slot < block_count; slot++) {
    const int64_t actual = filemirror_actual_blocknumber(
        scalpel_state.filemirror, mapping[slot]);

    if (scalpel_state.reservations && actual >= 0) {
      const int64_t reserved = filemirror_actual_block_reserved(
          scalpel_state.filemirror, actual);

      if (reserved > 0) {
        trial.reservations += (uint64_t)reserved;
      }
    }
    if (slot > 0) {
      const int64_t expected = mapping[slot - 1] + 1;
      const int64_t difference = mapping[slot] - expected;
      const uint64_t magnitude = difference < 0
                                     ? (uint64_t)(-difference)
                                     : (uint64_t)difference;

      trial.discontinuity += magnitude;
      if (magnitude > 1 && trial.ordered_prefix == block_count) {
        trial.ordered_prefix = slot;
      }
    }
  }

  if (tnef_reassembly_score_better(&trial, best)) {
    *best = trial;
    memcpy(best_mapping, mapping, block_count * sizeof(*best_mapping));
  }
}

static inline bool tnef_reassembly_fill_mapping(
    BlockVector *blockvector,
    int64_t *mapping,
    uint64_t committed_blocks,
    uint64_t block_count,
    uint64_t gap_slot,
    uint64_t gap_length) {

  if (!blockvector || !mapping || committed_blocks == 0
      || committed_blocks >= block_count) {
    return false;
  }

  for (uint64_t slot = 0; slot < committed_blocks; slot++) {
    mapping[slot] = blockvector_get_apparent_blocknumber(blockvector, slot);
  }

  const int64_t previous = mapping[committed_blocks - 1];

  for (uint64_t slot = committed_blocks; slot < block_count; slot++) {
    const uint64_t distance = slot - committed_blocks + 1;
    const uint64_t skip = gap_slot != UINT64_MAX && slot >= gap_slot
                              ? gap_length : 0;

    if (distance > (uint64_t)INT64_MAX - skip
        || previous > INT64_MAX - (int64_t)(distance + skip)) {
      return false;
    }
    mapping[slot] = previous + (int64_t)(distance + skip);
  }

  return true;
}

// Try one physically contiguous displaced run at every logical position in the
// pending attribute. The additive checksum is evaluated before materializing a
// candidate mapping, so only checksum-compatible runs reach the full parser.
//
static inline TnefRecoveryResult tnef_reassembly_try_displaced_run(
    ThreadWork *work,
    CarveInfo **candidate,
    uuid_string_t uuidp,
    uuid_string_t uuidc,
    const TnefParseSummary *current_summary,
    uint8_t *trial_data,
    uint64_t data_length,
    int64_t *mapping,
    uint64_t block_count,
    uint64_t committed_blocks,
    uint64_t attribute_blocks,
    uint64_t run_length,
    uint32_t perturbations,
    const TnefBlockChecksum *checksum_index,
    TnefRecoveryScore *best,
    int64_t *best_mapping, TnefCarveState *state) {

  if (!work || !candidate || !*candidate || !current_summary || !trial_data
      || !mapping || !checksum_index || !best || !best_mapping
      || run_length == 0
      || run_length > attribute_blocks - committed_blocks) {
    return TNEF_RECOVERY_NO_MATCH;
  }

  const uint64_t blocksize = scalpel_state.blocksize;
  const uint64_t image_blocks = filemirror_apparent_blocks(
      scalpel_state.filemirror);
  const uint64_t payload_offset = current_summary->pending_payload_offset;
  const uint64_t payload_end = payload_offset
                               + current_summary->pending_payload_length;
  const uint64_t checksum_offset = payload_end;
  const uint16_t baseline_payload_sum = tnef_payload_checksum(
      trial_data + payload_offset, current_summary->pending_payload_length);
  int64_t *baseline_run = malloc(run_length * sizeof(*baseline_run));

  check_memory_allocation(baseline_run, __LINE__, __FILE__,
                          "TNEF baseline run");

  uint64_t examined = 0;

  for (uint64_t run_slot = state->progress.run_slot ? state->progress.run_slot : committed_blocks;
       run_slot + run_length <= attribute_blocks && *candidate; run_slot++) {
    state->progress.run_slot = run_slot;
    uint32_t baseline_run_sum = 0;
    uint32_t baseline_checksum_component = 0;
    bool checksum_low_in_run = false;
    bool checksum_high_in_run = false;

    memcpy(baseline_run, mapping + run_slot,
           run_length * sizeof(*baseline_run));

    for (uint64_t j = 0; j < run_length; j++) {
      const uint64_t slot = run_slot + j;
      const uint64_t slot_start = slot * blocksize;
      const uint64_t slot_end = slot_start + blocksize;
      const uint64_t overlap_start = payload_offset > slot_start
                                         ? payload_offset : slot_start;
      const uint64_t overlap_end = payload_end < slot_end
                                       ? payload_end : slot_end;

      if (overlap_start < overlap_end) {
        baseline_run_sum += tnef_payload_checksum(
            trial_data + overlap_start, overlap_end - overlap_start);
      }
      if (checksum_offset >= slot_start && checksum_offset < slot_end) {
        checksum_low_in_run = true;
      }
      if (checksum_offset + 1 >= slot_start
          && checksum_offset + 1 < slot_end) {
        checksum_high_in_run = true;
      }
    }

    if (!checksum_low_in_run) {
      baseline_checksum_component |= trial_data[checksum_offset];
    }
    if (!checksum_high_in_run) {
      baseline_checksum_component |=
          (uint32_t)trial_data[checksum_offset + 1] << 8;
    }

    const uint16_t other_payload =
        (uint16_t)(baseline_payload_sum - baseline_run_sum);
    const uint16_t required_key =
        (uint16_t)(other_payload - baseline_checksum_component);

    for (uint64_t apparent = state->progress.next_apparent;
         apparent + run_length <= image_blocks && *candidate; apparent++) {
      bool checksum_usable = true;
      uint32_t candidate_payload_sum = 0;
      uint32_t candidate_checksum_component = 0;

      for (uint64_t j = 0; j < run_length && checksum_usable; j++) {
        const TnefBlockChecksum *entry = &checksum_index[apparent + j];

        if (!entry->readable) {
          checksum_usable = false;
          break;
        }

        const uint64_t slot = run_slot + j;
        const uint64_t slot_start = slot * blocksize;
        const uint64_t slot_end = slot_start + blocksize;
        const uint64_t overlap_start = payload_offset > slot_start
                                           ? payload_offset : slot_start;
        const uint64_t overlap_end = payload_end < slot_end
                                         ? payload_end : slot_end;

        if (overlap_start < overlap_end) {
          if (overlap_start == slot_start) {
            candidate_payload_sum += overlap_end == slot_end
                                         ? entry->full_payload_sum
                                         : entry->final_payload_sum;
          }
          else {
            const int64_t actual = filemirror_actual_blocknumber(
                scalpel_state.filemirror, (int64_t)(apparent + j));
            uint64_t available = 0;
            const uint8_t *block = actual < 0 ? NULL : (const uint8_t *)
                filemirror_actual_block_data_pointer(
                    scalpel_state.filemirror, actual, &available);

            if (!block) {
              checksum_usable = false;
              break;
            }
            if (available > blocksize) {
              available = blocksize;
            }
            for (uint64_t offset = overlap_start;
                 offset < overlap_end; offset++) {
              const uint64_t relative = offset - slot_start;

              if (relative < available) {
                candidate_payload_sum += block[relative];
              }
            }
          }
        }
        if (checksum_offset >= slot_start && checksum_offset < slot_end) {
          candidate_checksum_component |= entry->checksum_low;
        }
        if (checksum_offset + 1 >= slot_start
            && checksum_offset + 1 < slot_end) {
          candidate_checksum_component |=
              (uint32_t)entry->checksum_high << 8;
        }
      }

      if (checksum_usable
          && (uint16_t)(candidate_checksum_component
                        - candidate_payload_sum) == required_key) {
        bool usable = true;
        bool unchanged = true;

        for (uint64_t j = 0; j < run_length && usable; j++) {
          const int64_t candidate_apparent = (int64_t)(apparent + j);
          const int64_t actual = filemirror_actual_blocknumber(
              scalpel_state.filemirror, candidate_apparent);

          if (actual < 0
              || filemirror_actual_block_covered(scalpel_state.filemirror,
                                                 actual)
              || apparent_block_in_blockvector((*candidate)->b,
                                               candidate_apparent)) {
            usable = false;
            break;
          }
          if (candidate_apparent != baseline_run[j]) {
            unchanged = false;
          }
          for (uint64_t slot = 0; slot < block_count; slot++) {
            if ((slot < run_slot || slot >= run_slot + run_length)
                && mapping[slot] == candidate_apparent) {
              usable = false;
              break;
            }
          }
        }

        if (usable && !unchanged) {
          bool copied = true;

          for (uint64_t j = 0; j < run_length; j++) {
            mapping[run_slot + j] = (int64_t)(apparent + j);
            if (!tnef_reassembly_copy_block(
                    trial_data + (run_slot + j) * blocksize,
                    (int64_t)(apparent + j))) {
              copied = false;
              break;
            }
          }
          if (copied) {
            tnef_reassembly_consider_trial(
                *candidate, trial_data, data_length, mapping, block_count,
                current_summary->verified_end,
                current_summary->pending_attribute_end, perturbations,
                best, best_mapping);
          }
          for (uint64_t j = 0; j < run_length; j++) {
            mapping[run_slot + j] = baseline_run[j];
            tnef_reassembly_copy_block(
                trial_data + (run_slot + j) * blocksize, baseline_run[j]);
          }
        }
      }

      examined++;
      state->progress.next_apparent = apparent + 1;
      if ((examined & (TNEF_REASSEMBLY_POLL_INTERVAL - 1)) == 0
          && tnef_search_poll(work, candidate, uuidp, uuidc, state, best_mapping)) {
        free(baseline_run);
        return TNEF_RECOVERY_INTERRUPTED;
      }
    }
    state->progress.next_apparent = 0;
  }

  state->progress.run_slot = 0;
  free(baseline_run);
  return TNEF_RECOVERY_MATCH;
}

// Repair one checksummed attribute at a time. The physical-continuity pass
// handles ordinary extension and one inserted run. If neither verifies the
// attribute, the displaced-run pass tries one contiguous run, both with and
// without the gap. A verified mapping is committed only when it advances
// through at least one complete attribute.
//
static inline TnefRecoveryResult tnef_reassembly_repair_attribute(
    ThreadWork *work,
    CarveInfo **candidate,
    uuid_string_t uuidp,
    uuid_string_t uuidc,
    const TnefParseSummary *current_summary,
    uint64_t committed_blocks) {

  if (!work || !candidate || !*candidate || !(*candidate)->b
      || !current_summary || committed_blocks == 0
      || current_summary->pending_attribute_end == 0
      || current_summary->pending_payload_length == 0) {
    return TNEF_RECOVERY_NO_MATCH;
  }

  const uint64_t blocksize = scalpel_state.blocksize;
  const uint64_t maximum_size =
      scalpel_state.search_specs[(*candidate)->needleidx].MAXIMUMSIZE;

  if (blocksize == 0
      || current_summary->pending_attribute_end > maximum_size) {
    return TNEF_RECOVERY_NO_MATCH;
  }

  uint64_t trial_end = current_summary->pending_attribute_end;

  if (trial_end <= maximum_size - TNEF_ATTRIBUTE_OVERHEAD) {
    trial_end += TNEF_ATTRIBUTE_OVERHEAD;
  }
  else {
    trial_end = maximum_size;
  }

  const uint64_t block_count = CEILDIV(trial_end, blocksize);
  const uint64_t attribute_blocks = CEILDIV(
      current_summary->pending_attribute_end, blocksize);

  if (block_count <= committed_blocks
      || attribute_blocks <= committed_blocks
      || block_count > SIZE_MAX / sizeof(int64_t)
      || block_count > SIZE_MAX / blocksize) {
    return TNEF_RECOVERY_NO_MATCH;
  }

  const uint64_t data_length = block_count * blocksize;
  int64_t *mapping = malloc(block_count * sizeof(*mapping));
  int64_t *best_mapping = malloc(block_count * sizeof(*best_mapping));
  uint8_t *trial_data = malloc((size_t)data_length);
  TnefBlockChecksum *checksum_index = NULL;

  check_memory_allocation(mapping, __LINE__, __FILE__, "TNEF trial mapping");
  check_memory_allocation(best_mapping, __LINE__, __FILE__,
                          "TNEF best mapping");
  check_memory_allocation(trial_data, __LINE__, __FILE__, "TNEF trial data");

  const uint8_t *committed_data = (const uint8_t *)
      blockvector_get_data_pointer((*candidate)->b);

  if (!committed_data) {
    free(trial_data);
    free(best_mapping);
    free(mapping);
    return TNEF_RECOVERY_NO_MATCH;
  }

  const uint32_t minimum_content_class = tnef_reassembly_content_class(
      committed_data, committed_blocks * blocksize);
  const uint64_t payload_end = current_summary->pending_payload_offset
                               + current_summary->pending_payload_length;
  const uint64_t committed_end = committed_blocks * blocksize;
  const uint64_t committed_payload_end = payload_end < committed_end
                                             ? payload_end : committed_end;
  const uint16_t committed_payload_sum =
      current_summary->pending_payload_offset < committed_payload_end
          ? tnef_payload_checksum(
                committed_data + current_summary->pending_payload_offset,
                committed_payload_end
                    - current_summary->pending_payload_offset)
          : 0;
  const uint64_t image_blocks = filemirror_apparent_blocks(
      scalpel_state.filemirror);
  TnefCarveState *state = carve_get_state((*candidate)->carvehashkey);
  if (state && (state->progress.magic != TNEF_SEARCH_MAGIC
      || state->progress.block_count != block_count
      || state->progress.image_blocks != image_blocks
      || !XXH128_isEqual(state->progress.view, validator_search_view(*candidate)))) {
    tnef_free_carve_state((void **)&state);
  }
  if (state && state->progress.best.found) {
    const uint64_t actual_blocks = CEILDIV(filemirror_filesize(scalpel_state.filemirror), blocksize);
    for (uint64_t i = 0; i < block_count; i++) {
      if (state->best_actual[i] < 0 || (uint64_t)state->best_actual[i] >= actual_blocks
          || (best_mapping[i] = filemirror_apparent_blocknumber(
                  scalpel_state.filemirror, state->best_actual[i])) < 0) {
        tnef_free_carve_state((void **)&state);
        break;
      }
    }
  }
  if (!state) {
    state = calloc(1, sizeof(*state));
    check_memory_allocation(state, __LINE__, __FILE__, "TNEF search progress");
    state->progress.magic = TNEF_SEARCH_MAGIC;
    state->progress.block_count = block_count;
    state->progress.image_blocks = image_blocks;
  }
  state->pending = *current_summary;
  state->prefix_blocks = committed_blocks;
  state->prefix = tnef_search_prefix(*candidate, committed_blocks);
  TnefSearchProgress *progress = &state->progress;
  TnefRecoveryScore *best = &progress->best;
  const bool resume_gap = progress->phase == TNEF_SEARCH_GAP;
  const bool resume_displaced = progress->phase == TNEF_SEARCH_DISPLACED;
  TnefRecoveryResult result = TNEF_RECOVERY_NO_MATCH;
  const int64_t previous_apparent = blockvector_get_apparent_blocknumber(
      (*candidate)->b, committed_blocks - 1);
  const uint64_t extension_blocks = block_count - committed_blocks;
  uint64_t maximum_gap = 0;

  if (previous_apparent >= 0
      && (uint64_t)previous_apparent + extension_blocks < image_blocks) {
    maximum_gap = image_blocks - 1
                  - ((uint64_t)previous_apparent + extension_blocks);
  }

  // Physical continuity is both the cheapest and strongest extension.
  if (progress->phase == TNEF_SEARCH_DIRECT
      && tnef_reassembly_fill_mapping((*candidate)->b, mapping,
                                   committed_blocks, block_count,
                                   UINT64_MAX, 0)
      && tnef_reassembly_mapping_valid((*candidate)->b, mapping,
                                       committed_blocks, block_count)
      && tnef_reassembly_materialize(trial_data, mapping, block_count)) {
    tnef_reassembly_consider_trial(
        *candidate, trial_data, data_length, mapping, block_count,
        current_summary->verified_end,
        current_summary->pending_attribute_end, 0, best, best_mapping);
  }

  if (progress->phase == TNEF_SEARCH_DIRECT) {
    progress->phase = TNEF_SEARCH_INDEX;
    if (tnef_search_poll(work, candidate, uuidp, uuidc, state, best_mapping)) {
      result = TNEF_RECOVERY_INTERRUPTED;
      goto finished;
    }
  }

  if ((!tnef_reassembly_score_confident(best, minimum_content_class)
       || resume_gap || resume_displaced) && *candidate) {
    if (image_blocks > SIZE_MAX / sizeof(*checksum_index)) {
      goto finished;
    }

    state->index = realloc(state->index, (size_t)image_blocks * sizeof(*state->index));
    check_memory_allocation(state->index, __LINE__, __FILE__,
                            "TNEF block checksum index");
    checksum_index = state->index;
    memset(checksum_index + progress->index_count, 0,
           (size_t)(image_blocks - progress->index_count) * sizeof(*checksum_index));

    if (!tnef_reassembly_build_checksum_index(
            work, candidate, uuidp, uuidc, current_summary,
            checksum_index, image_blocks, state, best_mapping)) {
      result = TNEF_RECOVERY_INTERRUPTED;
      goto finished;
    }
  }
  if (progress->phase == TNEF_SEARCH_INDEX) {
    progress->phase = TNEF_SEARCH_GAP;
    progress->gap_length = 1;
    progress->gap_slot = committed_blocks;
  }

  // Search inserted runs shortest first. Once one width produces verified
  // progress, longer gaps are less plausible and need not be explored.
  for (uint64_t gap_length = progress->gap_length;
       progress->phase == TNEF_SEARCH_GAP &&
       gap_length <= maximum_gap
       && ((resume_gap && gap_length == progress->gap_length)
           || !tnef_reassembly_score_confident(best, minimum_content_class))
       && *candidate;
       gap_length++) {
    for (uint64_t gap_slot = progress->gap_slot;
         gap_slot < attribute_blocks && *candidate; gap_slot++) {
      if (tnef_reassembly_fill_mapping((*candidate)->b, mapping,
                                       committed_blocks, block_count,
                                       gap_slot, gap_length)
          && tnef_reassembly_mapping_checksum_matches(
              committed_data, current_summary, mapping, block_count,
              committed_blocks, committed_payload_sum, checksum_index,
              image_blocks)
          && tnef_reassembly_mapping_valid((*candidate)->b, mapping,
                                           committed_blocks, block_count)
          && tnef_reassembly_materialize(trial_data, mapping, block_count)) {
        tnef_reassembly_consider_trial(
            *candidate, trial_data, data_length, mapping, block_count,
            current_summary->verified_end,
            current_summary->pending_attribute_end, 1, best, best_mapping);
      }
      progress->gap_length = gap_length;
      progress->gap_slot = gap_slot + 1;
      if (tnef_search_poll(work, candidate, uuidp, uuidc, state, best_mapping)) {
        result = TNEF_RECOVERY_INTERRUPTED;
        goto finished;
      }
    }
    progress->gap_slot = committed_blocks;
  }
  if (progress->phase == TNEF_SEARCH_GAP) {
    progress->phase = TNEF_SEARCH_DISPLACED;
    progress->complexity = 1;
    progress->gap_length = 0;
    progress->gap_slot = UINT64_MAX;
  }

  // If physical runs alone cannot repair the attribute, add one displaced run.
  // Search by the total number of affected blocks so small combined
  // fragmentations are considered before a very long gap or displaced run.
  // The search remains exhaustive; checkpoints bound operational work.
  const uint64_t maximum_run = attribute_blocks - committed_blocks;
  const uint64_t maximum_complexity = maximum_gap + maximum_run;

  const uint64_t saved_complexity = progress->complexity;
  const uint64_t saved_gap = progress->gap_length;
  const uint64_t saved_slot = progress->gap_slot;
  for (uint64_t complexity = saved_complexity;
       complexity <= maximum_complexity
       && ((resume_displaced && complexity == saved_complexity)
           || !tnef_reassembly_score_confident(best, minimum_content_class))
       && *candidate;
       complexity++) {
    const uint64_t first_gap = complexity > maximum_run
                                   ? complexity - maximum_run : 0;
    const uint64_t final_gap = complexity - 1 < maximum_gap
                                   ? complexity - 1 : maximum_gap;

    for (uint64_t gap_length = resume_displaced && complexity == saved_complexity ? saved_gap : first_gap;
         gap_length <= final_gap
         && ((resume_displaced && complexity == saved_complexity && gap_length == saved_gap)
             || !tnef_reassembly_score_confident(best, minimum_content_class))
         && *candidate; gap_length++) {
      const uint64_t run_length = complexity - gap_length;
      const uint64_t first_gap_slot = gap_length == 0
                                          ? UINT64_MAX
                                          : committed_blocks;
      const uint64_t final_gap_slot = gap_length == 0
                                          ? UINT64_MAX
                                          : attribute_blocks - 1;

      for (uint64_t gap_slot = resume_displaced && complexity == saved_complexity && gap_length == saved_gap
                                  ? saved_slot : first_gap_slot;
           gap_slot <= final_gap_slot && *candidate;
           gap_slot = gap_slot == UINT64_MAX ? 0 : gap_slot + 1) {
        if (!tnef_reassembly_fill_mapping((*candidate)->b, mapping,
                                          committed_blocks, block_count,
                                          gap_slot, gap_length)
            || !tnef_reassembly_mapping_valid((*candidate)->b, mapping,
                                              committed_blocks, block_count)
            || !tnef_reassembly_materialize(trial_data, mapping,
                                             block_count)) {
          if (gap_slot == UINT64_MAX) {
            break;
          }
          continue;
        }

        progress->complexity = complexity;
        progress->gap_length = gap_length;
        progress->gap_slot = gap_slot;
        const TnefRecoveryResult run_result =
            tnef_reassembly_try_displaced_run(
                work, candidate, uuidp, uuidc, current_summary,
                trial_data, data_length, mapping, block_count,
                committed_blocks, attribute_blocks, run_length,
                gap_length == 0 ? 1 : 2, checksum_index,
                best, best_mapping, state);

        if (run_result == TNEF_RECOVERY_INTERRUPTED) {
          result = TNEF_RECOVERY_INTERRUPTED;
          goto finished;
        }
        if (gap_slot == UINT64_MAX) {
          break;
        }
      }
    }
  }

  if (!best->found || !*candidate) {
    result = *candidate ? TNEF_RECOVERY_NO_MATCH : TNEF_RECOVERY_INTERRUPTED;
    goto finished;
  }

  BlockVector *blockvector = (*candidate)->b;

  resize_blockvector(blockvector, block_count);
  for (uint64_t slot = committed_blocks; slot < block_count; slot++) {
    blockvector_set_apparent_blocknumber(blockvector, slot,
                                         best_mapping[slot]);
  }
  inflate_blockvector(blockvector);
  blockvector_set_data_length(blockvector, data_length);

  result = TNEF_RECOVERY_MATCH;
finished:
  tnef_free_carve_state((void **)&state);
  free(trial_data);
  free(best_mapping);
  free(mapping);
  return result;
}

// Extend a TNEF stream through complete checksummed attributes. A single
// attribute may span many blocks, so extension trials cover the complete
// attribute rather than requiring one block to advance the parser.
//
static inline void tnef_reassembly(ThreadWork *work,
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
  inflate_blockvector((*candidate)->b);

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

    // A chopped candidate's byte length can stop at the previous attribute.
    // Examine the rest of its placed blocks to see the pending attribute;
    // inflation deliberately does not change that meaningful byte length.
    blockvector_set_data_length(blockvector, blocks * (uint64_t)scalpel_state.blocksize);
    inflate_blockvector(blockvector);
    TnefParseSummary current_summary;
    TnefParseResult current_result = tnef_parse(
        (const uint8_t *)blockvector_get_data_pointer(blockvector),
        blockvector_get_data_length(blockvector), &current_summary);

    // Trimming to a verified boundary can remove the next attribute's header.
    // Its absence after a checkpoint is not evidence that the stream ended.
    TnefCarveState *saved = carve_get_state((*candidate)->carvehashkey);
    if (saved) {
      const bool pending = saved->pending.pending_attribute_end > current_summary.verified_end;
      if (pending && saved->prefix_blocks == blocks
          && saved->pending.verified_end == current_summary.verified_end
          && XXH128_isEqual(saved->prefix, tnef_search_prefix(*candidate, blocks))) {
        current_summary = saved->pending;
        current_result = TNEF_PARSE_TRUNCATED;
      }
      else if (current_result == TNEF_PARSE_COMPLETE
          && (pending || (!saved->prefix_blocks && saved->progress.block_count > blocks))) {
        // Older checkpoints omitted the pending header. Keep their prefix as
        // partial rather than claiming that a forgotten search was complete.
        current_result = TNEF_PARSE_TRUNCATED;
      }
      tnef_free_carve_state((void **)&saved);
    }

    if (current_result == TNEF_PARSE_COMPLETE) {
      blockvector_set_data_length(blockvector, current_summary.verified_end);
      resize_blockvector(blockvector,
                         CEILDIV(current_summary.verified_end,
                                 scalpel_state.blocksize));
      if (tnef_candidate_is_contiguous(*candidate)) {
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

    uint64_t committed_length = blocks
                                * (uint64_t)scalpel_state.blocksize;
    if (current_summary.verified_end < committed_length) {
      uint64_t keep_blocks = CEILDIV(current_summary.verified_end,
                                     scalpel_state.blocksize);

      if (keep_blocks == 0) {
        keep_blocks = 1;
      }
      if (keep_blocks < blocks) {
        resize_blockvector(blockvector, keep_blocks);
        committed_length = keep_blocks
                           * (uint64_t)scalpel_state.blocksize;
        blockvector_set_data_length(blockvector, committed_length);
        inflate_blockvector(blockvector);
        blocks = keep_blocks;
      }
    }

    if (reassembly_check_max_size(work->id, *candidate, uuidp, uuidc)) {
      break;
    }

    const TnefRecoveryResult recovery = tnef_reassembly_repair_attribute(
        work, candidate, uuidp, uuidc, &current_summary, blocks);

    if (recovery == TNEF_RECOVERY_INTERRUPTED || !*candidate) {
      return;
    }
    if (recovery != TNEF_RECOVERY_MATCH) {
      break;
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

// Arrays contain checksum summaries and physical positions, never cached image
// bytes. Counts are checked against the remaining serialized input before allocation.
static inline bool tnef_serialize_carve_state(void **state, FILE *fp, StateSerialization mode) {
  if (!state || !fp || (mode == SERIALIZE && !*state)) {
    return false;
  }
  if (mode == SERIALIZE) {
    const TnefCarveState *saved = *state;
    TnefSearchProgress header = saved->progress;
    header.magic = TNEF_SEARCH_MAGIC;
    const TnefSearchProgress *p = &header;
    return fwrite(p, sizeof(*p), 1, fp) == 1
        && (!p->best.found || fwrite(saved->best_actual, sizeof(int64_t), (size_t)p->block_count, fp) == p->block_count)
        && (!p->index_count || fwrite(saved->index, sizeof(TnefBlockChecksum), (size_t)p->index_count, fp) == p->index_count)
        && fwrite(&saved->pending, sizeof(saved->pending), 1, fp) == 1
        && fwrite(&saved->prefix_blocks, sizeof(saved->prefix_blocks), 1, fp) == 1
        && fwrite(&saved->prefix, sizeof(saved->prefix), 1, fp) == 1;
  }
  TnefSearchProgress p;
  if (fread(&p, sizeof(p), 1, fp) != 1
      || (p.magic != TNEF_SEARCH_MAGIC && p.magic != TNEF_SEARCH_MAGIC_V1)
      || p.phase > TNEF_SEARCH_DISPLACED || !p.block_count
      || p.block_count > SIZE_MAX / sizeof(int64_t)
      || p.image_blocks > SIZE_MAX / sizeof(TnefBlockChecksum)
      || p.index_count > p.image_blocks || p.next_apparent > p.image_blocks
      || p.run_slot > p.block_count
      || (p.phase >= TNEF_SEARCH_GAP && p.index_count != p.image_blocks && !p.best.found)) {
    return false;
  }
  const size_t mapping_bytes = p.best.found ? (size_t)p.block_count * sizeof(int64_t) : 0;
  const size_t index_bytes = (size_t)p.index_count * sizeof(TnefBlockChecksum);
  const off_t offset = ftello(fp);
  if (index_bytes > SIZE_MAX - mapping_bytes || offset < 0 || fseeko(fp, 0, SEEK_END) != 0) {
    return false;
  }
  const off_t end = ftello(fp);
  if (fseeko(fp, offset, SEEK_SET) != 0 || end < offset
      || (uint64_t)(end - offset) < mapping_bytes + index_bytes) {
    return false;
  }
  TnefCarveState *saved = calloc(1, sizeof(*saved));
  check_memory_allocation(saved, __LINE__, __FILE__, "TNEF restored search");
  saved->progress = p;
  if (mapping_bytes) {
    saved->best_actual = malloc(mapping_bytes);
    check_memory_allocation(saved->best_actual, __LINE__, __FILE__, "TNEF restored mapping");
    if (fread(saved->best_actual, 1, mapping_bytes, fp) != mapping_bytes) {
      tnef_free_carve_state((void **)&saved);
      return false;
    }
    for (uint64_t i = 0; i < p.block_count; i++) {
      if (saved->best_actual[i] < 0) {
        tnef_free_carve_state((void **)&saved);
        return false;
      }
    }
  }
  if (index_bytes) {
    saved->index = malloc(index_bytes);
    check_memory_allocation(saved->index, __LINE__, __FILE__, "TNEF restored checksum index");
    if (fread(saved->index, 1, index_bytes, fp) != index_bytes) {
      tnef_free_carve_state((void **)&saved);
      return false;
    }
  }
  if (p.magic == TNEF_SEARCH_MAGIC) {
    if (fread(&saved->pending, sizeof(saved->pending), 1, fp) != 1
        || fread(&saved->prefix_blocks, sizeof(saved->prefix_blocks), 1, fp) != 1
        || fread(&saved->prefix, sizeof(saved->prefix), 1, fp) != 1
        || saved->prefix_blocks > p.block_count) {
      tnef_free_carve_state((void **)&saved);
      return false;
    }
    const TnefParseSummary *pending = &saved->pending;
    const TnefParseSummary empty = {0};
    if (!saved->prefix_blocks
        && (memcmp(pending, &empty, sizeof(empty)) != 0
            || saved->prefix.low64 || saved->prefix.high64)) {
      tnef_free_carve_state((void **)&saved);
      return false;
    }
    if (saved->prefix_blocks
        && (pending->pending_attribute_start != pending->verified_end
            || pending->pending_attribute_start > UINT64_MAX - TNEF_ATTRIBUTE_OVERHEAD
            || pending->pending_payload_offset != pending->pending_attribute_start + TNEF_ATTRIBUTE_HEADER_SIZE
            || pending->pending_payload_length == 0
            || pending->pending_payload_length > UINT32_MAX
            || pending->pending_payload_length > UINT64_MAX - pending->pending_payload_offset - TNEF_ATTRIBUTE_CHECKSUM_SIZE
            || pending->pending_attribute_end != pending->pending_payload_offset
                + pending->pending_payload_length + TNEF_ATTRIBUTE_CHECKSUM_SIZE)) {
      tnef_free_carve_state((void **)&saved);
      return false;
    }
  }
  saved->progress.magic = TNEF_SEARCH_MAGIC;
  *state = saved;
  return true;
}

static inline void *tnef_clone_carve_state(const void *state) {
  if (!state) {
    return NULL;
  }
  const TnefCarveState *saved = state;
  TnefCarveState *copy = malloc(sizeof(*copy));
  check_memory_allocation(copy, __LINE__, __FILE__, "TNEF search clone");
  *copy = *saved;
  copy->best_actual = NULL;
  copy->index = NULL;
  if (saved->progress.best.found) {
    size_t bytes = (size_t)saved->progress.block_count * sizeof(int64_t);
    copy->best_actual = malloc(bytes);
    check_memory_allocation(copy->best_actual, __LINE__, __FILE__, "TNEF mapping clone");
    memcpy(copy->best_actual, saved->best_actual, bytes);
  }
  if (saved->progress.index_count) {
    size_t bytes = (size_t)saved->progress.index_count * sizeof(TnefBlockChecksum);
    copy->index = malloc(bytes);
    check_memory_allocation(copy->index, __LINE__, __FILE__, "TNEF checksum index clone");
    memcpy(copy->index, saved->index, bytes);
  }
  return copy;
}

static inline void tnef_free_carve_state(void **state) {
  if (state && *state) {
    TnefCarveState *saved = *state;
    free(saved->best_actual);
    free(saved->index);
    free(saved);
    *state = NULL;
  }
}

static inline size_t tnef_sizeof_carve_state(const void *state) {
  const TnefCarveState *saved = state;
  return saved ? sizeof(*saved) + (size_t)saved->progress.index_count * sizeof(TnefBlockChecksum)
      + (saved->progress.best.found ? (size_t)saved->progress.block_count * sizeof(int64_t) : 0) : 0;
}

static inline void tnef_print_carve_state(const void *state) {
  const TnefCarveState *saved = state;
  if (saved) {
    printf("TNEF search phase=%u checksum blocks=%" PRIu64 " complexity=%" PRIu64 "\n",
           (unsigned)saved->progress.phase, saved->progress.index_count, saved->progress.complexity);
  }
}

#endif
