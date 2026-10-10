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

#if !defined(SCALPEL_RTF_H)
#define SCALPEL_RTF_H

#include "cfbf.h"
#include "scalpel.h"
#include "zip.h"
#include "validator_search.h"

#include <ctype.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>

#define RTF_MINIMUM_SIZE 7u
#define RTF_MAXIMUM_GROUP_DEPTH UINT32_C(65536)
#define RTF_MAXIMUM_CONTROL_WORD 64u
#define RTF_REASSEMBLY_POLL_INTERVAL UINT64_C(256)
#define RTF_REASSEMBLY_LOCAL_BLOCKS INT64_C(64)
#define RTF_REASSEMBLY_SEAM_BYTES UINT64_C(256)
#define RTF_REASSEMBLY_BRIDGE_BYTES UINT64_C(512)
#define RTF_REASSEMBLY_BIGRAM_BUCKETS UINT64_C(1024)
#define RTF_REASSEMBLY_SUFFIX_FLOOR UINT64_C(256)
#define RTF_REASSEMBLY_HYPOTHESIS_LIMIT UINT64_C(256)
#define RTF_REASSEMBLY_EMBEDDED_HYPOTHESIS_LIMIT UINT64_C(512)
#define RTF_REASSEMBLY_EMBEDDED_PREFIX_LIMIT UINT64_C(32)
#define RTF_REASSEMBLY_PARTIAL_HYPOTHESIS_LIMIT UINT64_C(16)
#define RTF_REASSEMBLY_COMPOSED_HYPOTHESIS_LIMIT UINT64_C(64)
#define RTF_REASSEMBLY_PRESERVED_HYPOTHESIS_LIMIT UINT64_C(64)
#define RTF_REASSEMBLY_EMBEDDED_PRESERVED_HYPOTHESIS_LIMIT UINT64_C(80)
#define RTF_REASSEMBLY_EMBEDDED_HEX_PRIORITY_LIMIT UINT64_C(16)
#define RTF_REASSEMBLY_INITIAL_SUFFIX_BLOCKS UINT64_C(16)

typedef enum RtfReassemblyRanking {
  RTF_REASSEMBLY_RANK_LEXICAL = 0,
  RTF_REASSEMBLY_RANK_CONFIDENCE
} RtfReassemblyRanking;

typedef enum RtfEmbeddedValidation {
  RTF_EMBEDDED_INVALID = 0,
  RTF_EMBEDDED_INCOMPLETE,
  RTF_EMBEDDED_COMPLETE
} RtfEmbeddedValidation;

typedef enum RtfPictureKind {
  RTF_PICTURE_UNKNOWN = 0,
  RTF_PICTURE_PNG,
  RTF_PICTURE_JPEG,
  RTF_PICTURE_EMF,
  RTF_PICTURE_WMF
} RtfPictureKind;

typedef struct RtfReassemblyChoice {
  int64_t apparent;
  uint64_t bridge_cost;
  int64_t reserved;
  BlockValidationDecision confidence;
  bool terminal_only;
} RtfReassemblyChoice;

typedef struct RtfValidationSummary {
  bool active_deep_payload;
  uint64_t completed_deep_payloads;
  uint64_t completed_integrity_payloads;
} RtfValidationSummary;

#define RTF_SEARCH_MAGIC UINT32_C(0x52544631)
#define RTF_STATE_ENVELOPE_MAGIC UINT32_C(0x52544632)
typedef enum {
  RTF_SEARCH_NONE, RTF_SEARCH_RANK, RTF_SEARCH_TRIAL, RTF_SEARCH_PARTIAL, RTF_SEARCH_BLOCK
} RtfSearchPhase;

typedef struct {
  uint64_t counts[6];
  RtfReassemblyChoice ranks[6][RTF_REASSEMBLY_EMBEDDED_HYPOTHESIS_LIMIT];
  uint64_t choice_index;
  uint64_t written;
  uint64_t composed;
  uint64_t clean_terminal;
  uint64_t longest_complete;
  int64_t best_partial;
  uint64_t partial_blocks;
  uint64_t partial_suffix_blocks;
  bool partial_integrity;
  RtfReassemblyChoice partial_choice;
} RtfInsertionProgress;

typedef struct {
  uint32_t magic;
  RtfSearchPhase phase;
  XXH128_hash_t view;
  uint64_t gap_slot;
  uint64_t next_apparent;
  bool following_relocated_run;
  RtfReassemblyChoice best;
  int64_t forward_distance;
  bool complete;
  bool local_forward;
} RtfSearchProgress;

typedef struct {
  RtfSearchProgress progress;
  RtfInsertionProgress *insertion;
  bool block_scan_exhausted;
} RtfCarveState;

static inline bool rtf_serialize_carve_state(void **state, FILE *fp, StateSerialization mode);
static inline void *rtf_clone_carve_state(const void *state);
static inline void rtf_free_carve_state(void **state);
static inline size_t rtf_sizeof_carve_state(const void *state);
static inline void rtf_print_carve_state(const void *state);
static inline RtfCarveState *rtf_search_load(CarveInfo *candidate);
static inline void rtf_search_save(CarveInfo *candidate, RtfCarveState *state);
static inline bool rtf_reassembly_insert_search(ThreadWork *work,
    CarveInfo **candidate, uint64_t gap_slot, bool *extended,
    uuid_string_t uuidp, uuid_string_t uuidc, RtfCarveState *state);
static inline bool rtf_reassembly_write_inserted_at_stage(
    ThreadWork *work, CarveInfo **candidate, uint64_t gap_slot,
    bool *extended, bool following_relocated_run,
    uuid_string_t uuidp, uuid_string_t uuidc, bool block_scan_exhausted);

static inline bool rtf_ascii_hex(uint8_t value);
static inline bool rtf_control_name_equals(const uint8_t *name,
                                           uint64_t length,
                                           const char *expected);
static inline uint32_t rtf_read_le32(const uint8_t *data);
static inline uint16_t rtf_read_le16(const uint8_t *data);
static inline uint32_t rtf_read_be32(const uint8_t *data);
static inline bool rtf_decode_hex(const uint8_t *encoded,
                                  uint64_t encoded_length,
                                  uint8_t **decoded,
                                  uint64_t *decoded_length,
                                  uint64_t *failure_offset);
static inline uint64_t rtf_hex_encoded_offset(const uint8_t *encoded,
                                              uint64_t encoded_length,
                                              uint64_t decoded_offset);
static inline RtfEmbeddedValidation rtf_validate_emf(
    const uint8_t *data, uint64_t declared_length,
    uint64_t available_length, uint64_t *failure_offset);
static inline RtfEmbeddedValidation rtf_validate_png(
    const uint8_t *data, uint64_t length, uint64_t *failure_offset);
static inline RtfEmbeddedValidation rtf_validate_jpeg(
    const uint8_t *data, uint64_t length, uint64_t *failure_offset);
static inline RtfEmbeddedValidation rtf_validate_wmf(
    const uint8_t *data, uint64_t length, uint64_t *failure_offset);
static inline RtfEmbeddedValidation rtf_validate_ole1(
    const uint8_t *data, uint64_t length, uint64_t *failure_offset);
static inline RtfEmbeddedValidation rtf_validate_hex_picture(
    const uint8_t *encoded, uint64_t encoded_length,
    RtfPictureKind kind, uint64_t *failure_offset);
static inline RtfEmbeddedValidation rtf_validate_hex_object(
    const uint8_t *encoded, uint64_t encoded_length,
    uint64_t *failure_offset);
static inline RtfEmbeddedValidation rtf_validate_hex_zip(
    const uint8_t *encoded, uint64_t encoded_length,
    uint64_t *failure_offset);
static inline void rtf_file_validate_core(
    char *data, uint64_t length, bool *validates,
    uint64_t *validates_to, bool *promising,
    uint32_t needleidx, uint32_t blocksize,
    void *carvehashkey, RtfValidationSummary *summary);
static inline void rtf_file_validate(char *data, uint64_t length,
                                     bool *validates,
                                     uint64_t *validates_to,
                                     bool *promising,
                                     uint32_t needleidx,
                                     uint32_t blocksize,
                                     void *carvehashkey);
static inline void rtf_write_terminal_extent_alternative(
    CarveInfo **candidate, uint64_t complete_length);
static inline void rtf_candidate_validate(CarveInfo *candidate,
                                          bool *validates,
                                          uint64_t *validates_to,
                                          bool *promising);
static inline char *rtf_footer_discovery(char *base, uint64_t offset,
                                         uint64_t remaining,
                                         char **matchpos,
                                         uint32_t *matchlen,
                                         uint32_t blocksize);
static inline uint32_t rtf_block_validate(
    char *data, uint64_t length, BlockValidationDecision *decision,
    uint64_t *validates_to, uint32_t needleidx, uint32_t blocksize,
    void *blockhashkey);
static inline bool rtf_candidate_is_contiguous(const CarveInfo *candidate);
static inline uint32_t rtf_reassembly_byte_class(uint8_t value);
static inline bool rtf_reassembly_hex_window(const uint8_t *data,
                                              uint64_t length,
                                              bool trailing);
static inline bool rtf_reassembly_split_hex_escape(
    const uint8_t *left, uint64_t left_length,
    const uint8_t *right, uint64_t right_length);
static inline bool rtf_reassembly_split_repeated_control_word(
    const uint8_t *left, uint64_t left_length,
    const uint8_t *right, uint64_t right_length);
static inline uint64_t rtf_reassembly_boundary_cost(
    const uint8_t *left, uint64_t left_length,
    const uint8_t *right, uint64_t right_length);
static inline uint64_t rtf_reassembly_prefix_cost(
    const uint8_t *left, uint64_t left_length,
    const uint8_t *right, uint64_t right_length);
static inline uint64_t rtf_reassembly_seam_cost(
    BlockVector *blockvector, int64_t apparent);
static inline bool rtf_reassembly_choice_better(
    const RtfReassemblyChoice *candidate,
    const RtfReassemblyChoice *current,
    RtfReassemblyRanking ranking);
static inline void rtf_reassembly_retain_choice(
    RtfReassemblyChoice *choices, uint64_t *choice_count, uint64_t limit,
    const RtfReassemblyChoice *choice, RtfReassemblyRanking ranking);
static inline void rtf_reassembly_append_unique_choice(
    RtfReassemblyChoice *choices, uint64_t *choice_count,
    uint64_t capacity, const RtfReassemblyChoice *choice);
static inline uint64_t rtf_reassembly_bridge_cost(
    const uint8_t *left, uint64_t left_length,
    const uint8_t *middle, uint64_t middle_length,
    const uint8_t *right, uint64_t right_length);
static inline uint64_t rtf_reassembly_hex_bridge_cost(
    const uint8_t *left, uint64_t left_length,
    const uint8_t *middle, uint64_t middle_length,
    const uint8_t *right, uint64_t right_length);
static inline bool rtf_reassembly_suffix_consumes_block(
    const CarveInfo *candidate, uint64_t gap_slot,
    const int64_t *suffix, uint64_t suffix_count,
    int64_t apparent);
static inline bool rtf_reassembly_explore_partial(
    ThreadWork *work, CarveInfo **candidate,
    BlockVector *partial, uuid_string_t uuidp,
    uuid_string_t uuidc);
static inline bool rtf_reassembly_write_composed_hypothesis(
    CarveInfo **candidate, BlockVector *parent, uint64_t gap_slot,
    int64_t inserted_apparent, const int64_t *suffix,
    uint64_t suffix_count, uint64_t skipped_suffix,
    uint8_t *trial_data, uint64_t trial_length);
static inline bool rtf_reassembly_write_inserted_hypotheses(
    ThreadWork *work, CarveInfo **candidate, uint64_t gap_slot,
    bool *extended, bool following_relocated_run,
    uuid_string_t uuidp, uuid_string_t uuidc);
static inline void rtf_reassembly(ThreadWork *work,
                                  CarveInfo **candidate,
                                  uuid_string_t uuidp,
                                  uuid_string_t uuidc);

// Test one ASCII hexadecimal digit.
//
static inline bool rtf_ascii_hex(uint8_t value) {

  return (value >= '0' && value <= '9')
         || (value >= 'a' && value <= 'f')
         || (value >= 'A' && value <= 'F');
}

// Compare a parsed ASCII control-word name without allocating a temporary
// string.
//
static inline bool rtf_control_name_equals(const uint8_t *name,
                                           uint64_t length,
                                           const char *expected) {

  return name && expected && strlen(expected) == length
         && memcmp(name, expected, (size_t)length) == 0;
}

// Read a little-endian 32-bit value without alignment assumptions.
//
static inline uint32_t rtf_read_le32(const uint8_t *data) {

  return (uint32_t)data[0]
         | ((uint32_t)data[1] << 8)
         | ((uint32_t)data[2] << 16)
         | ((uint32_t)data[3] << 24);
}

static inline uint16_t rtf_read_le16(const uint8_t *data) {

  return (uint16_t)((uint16_t)data[0] | ((uint16_t)data[1] << 8));
}

static inline uint32_t rtf_read_be32(const uint8_t *data) {

  return ((uint32_t)data[0] << 24)
         | ((uint32_t)data[1] << 16)
         | ((uint32_t)data[2] << 8)
         | (uint32_t)data[3];
}

// Decode the hexadecimal representation used by RTF picture and object
// destinations. Whitespace may separate encoded bytes, but no other text is
// permitted once the payload begins.
//
static inline bool rtf_decode_hex(const uint8_t *encoded,
                                  uint64_t encoded_length,
                                  uint8_t **decoded,
                                  uint64_t *decoded_length,
                                  uint64_t *failure_offset) {

  if (!encoded || !decoded || !decoded_length || !failure_offset) {
    return false;
  }
  *decoded = NULL;
  *decoded_length = 0;
  *failure_offset = 0;

  uint64_t digits = 0;

  for (uint64_t offset = 0; offset < encoded_length; offset++) {
    const uint8_t value = encoded[offset];

    if (rtf_ascii_hex(value)) {
      digits++;
    }
    else if (value != ' ' && value != '\t'
             && value != '\r' && value != '\n') {
      *failure_offset = offset;
      return false;
    }
  }
  if (digits == 0 || (digits & 1) != 0 || digits / 2 > SIZE_MAX) {
    *failure_offset = encoded_length == 0 ? 0 : encoded_length - 1;
    return false;
  }

  const uint64_t output_length = digits / 2;
  uint8_t *output = (uint8_t *)malloc((size_t)output_length);

  check_memory_allocation(output, __LINE__, __FILE__,
                          "decoded RTF hexadecimal payload");
  uint64_t output_offset = 0;
  uint8_t high = 0;
  bool have_high = false;

  for (uint64_t offset = 0; offset < encoded_length; offset++) {
    const uint8_t value = encoded[offset];

    if (!rtf_ascii_hex(value)) {
      continue;
    }
    uint8_t nibble;

    if (value >= '0' && value <= '9') {
      nibble = (uint8_t)(value - '0');
    }
    else if (value >= 'a' && value <= 'f') {
      nibble = (uint8_t)(value - 'a' + 10);
    }
    else {
      nibble = (uint8_t)(value - 'A' + 10);
    }

    if (!have_high) {
      high = nibble;
      have_high = true;
    }
    else {
      output[output_offset++] = (uint8_t)((high << 4) | nibble);
      have_high = false;
    }
  }
  *decoded = output;
  *decoded_length = output_length;
  return true;
}

// Map a decoded-byte failure back to the first source character for that byte.
//
static inline uint64_t rtf_hex_encoded_offset(const uint8_t *encoded,
                                              uint64_t encoded_length,
                                              uint64_t decoded_offset) {

  if (!encoded || encoded_length == 0) {
    return 0;
  }
  const uint64_t target_digit = decoded_offset > UINT64_MAX / 2
      ? UINT64_MAX : decoded_offset * 2;
  uint64_t digits = 0;

  for (uint64_t offset = 0; offset < encoded_length; offset++) {
    if (!rtf_ascii_hex(encoded[offset])) {
      continue;
    }
    if (digits == target_digit) {
      return offset;
    }
    digits++;
  }
  return encoded_length - 1;
}

// Validate a complete or partial Enhanced Metafile embedded by an RTF \bin
// control word. The first invalid record offset identifies the block that must
// be reconsidered during fragmented recovery.
//
static inline RtfEmbeddedValidation rtf_validate_emf(
    const uint8_t *data, uint64_t declared_length,
    uint64_t available_length, uint64_t *failure_offset) {

  if (failure_offset) {
    *failure_offset = 0;
  }
  if (!data || !failure_offset || declared_length < 88) {
    return RTF_EMBEDDED_INVALID;
  }
  const uint64_t usable_length = available_length < declared_length
      ? available_length : declared_length;

  if (usable_length < 8) {
    return RTF_EMBEDDED_INCOMPLETE;
  }
  const uint32_t first_type = rtf_read_le32(data);
  const uint32_t header_size = rtf_read_le32(data + 4);

  if (first_type != 1 || header_size < 88 || (header_size & 3) != 0
      || header_size > declared_length) {
    return RTF_EMBEDDED_INVALID;
  }
  if (usable_length < 56) {
    return RTF_EMBEDDED_INCOMPLETE;
  }
  const uint32_t signature = rtf_read_le32(data + 40);
  const uint32_t file_size = rtf_read_le32(data + 48);

  if (signature != UINT32_C(0x464d4520)
      || file_size != declared_length) {
    return RTF_EMBEDDED_INVALID;
  }

  uint64_t offset = 0;
  uint32_t last_type = 0;

  while (offset < declared_length) {
    if (declared_length - offset < 8) {
      *failure_offset = offset;
      return RTF_EMBEDDED_INVALID;
    }
    if (offset > usable_length || usable_length - offset < 8) {
      return RTF_EMBEDDED_INCOMPLETE;
    }
    const uint32_t type = rtf_read_le32(data + offset);
    const uint32_t record_size = rtf_read_le32(data + offset + 4);

    if (record_size < 8 || (record_size & 3) != 0
        || record_size > declared_length - offset) {
      *failure_offset = offset;
      return RTF_EMBEDDED_INVALID;
    }
    if (record_size > usable_length - offset) {
      return RTF_EMBEDDED_INCOMPLETE;
    }
    last_type = type;
    offset += record_size;
  }
  if (available_length < declared_length) {
    return RTF_EMBEDDED_INCOMPLETE;
  }
  if (last_type != 14) {
    *failure_offset = offset == 0 ? 0 : offset - 1;
    return RTF_EMBEDDED_INVALID;
  }
  return RTF_EMBEDDED_COMPLETE;
}

// Validate PNG framing and every chunk CRC.
//
static inline RtfEmbeddedValidation rtf_validate_png(
    const uint8_t *data, uint64_t length, uint64_t *failure_offset) {

  static const uint8_t signature[8] = {
      0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n'
  };

  if (failure_offset) {
    *failure_offset = 0;
  }
  if (!data || !failure_offset || length < sizeof(signature)
      || memcmp(data, signature, sizeof(signature)) != 0) {
    return RTF_EMBEDDED_INVALID;
  }

  uint64_t offset = sizeof(signature);
  bool saw_ihdr = false;

  while (offset < length) {
    const uint64_t chunk_offset = offset;

    if (length - offset < 12) {
      *failure_offset = offset;
      return RTF_EMBEDDED_INVALID;
    }
    const uint32_t chunk_length = rtf_read_be32(data + offset);

    if ((uint64_t)chunk_length > length - offset - 12) {
      *failure_offset = offset;
      return RTF_EMBEDDED_INVALID;
    }
    const uint8_t *type = data + offset + 4;
    const uint8_t *payload = data + offset + 8;
    const uint32_t stored_crc = rtf_read_be32(payload + chunk_length);
    uLong calculated_crc = crc32(0L, Z_NULL, 0);

    calculated_crc = crc32(calculated_crc, type, 4);
    calculated_crc = crc32(calculated_crc, payload, chunk_length);
    if ((uint32_t)calculated_crc != stored_crc) {
      *failure_offset = chunk_offset;
      return RTF_EMBEDDED_INVALID;
    }
    if (!saw_ihdr) {
      if (chunk_length != 13 || memcmp(type, "IHDR", 4) != 0
          || rtf_read_be32(payload) == 0
          || rtf_read_be32(payload + 4) == 0) {
        *failure_offset = chunk_offset;
        return RTF_EMBEDDED_INVALID;
      }
      saw_ihdr = true;
    }
    offset += 12 + (uint64_t)chunk_length;
    if (memcmp(type, "IEND", 4) == 0) {
      if (chunk_length != 0 || offset != length) {
        *failure_offset = chunk_offset;
        return RTF_EMBEDDED_INVALID;
      }
      return RTF_EMBEDDED_COMPLETE;
    }
  }
  *failure_offset = length == 0 ? 0 : length - 1;
  return RTF_EMBEDDED_INVALID;
}

// Validate JPEG marker framing, segment extents, entropy escaping, and EOI.
//
static inline RtfEmbeddedValidation rtf_validate_jpeg(
    const uint8_t *data, uint64_t length, uint64_t *failure_offset) {

  if (failure_offset) {
    *failure_offset = 0;
  }
  if (!data || !failure_offset || length < 4
      || data[0] != 0xff || data[1] != 0xd8) {
    return RTF_EMBEDDED_INVALID;
  }

  uint64_t offset = 2;
  bool in_scan = false;

  while (offset < length) {
    if (in_scan) {
      if (data[offset++] != 0xff) {
        continue;
      }
      const uint64_t marker_offset = offset - 1;

      while (offset < length && data[offset] == 0xff) {
        offset++;
      }
      if (offset >= length) {
        *failure_offset = marker_offset;
        return RTF_EMBEDDED_INVALID;
      }
      const uint8_t marker = data[offset++];

      if (marker == 0x00 || (marker >= 0xd0 && marker <= 0xd7)) {
        continue;
      }
      if (marker == 0xd9) {
        if (offset != length) {
          *failure_offset = marker_offset;
          return RTF_EMBEDDED_INVALID;
        }
        return RTF_EMBEDDED_COMPLETE;
      }
      in_scan = false;
      offset = marker_offset;
      continue;
    }

    const uint64_t marker_offset = offset;

    if (data[offset++] != 0xff) {
      *failure_offset = marker_offset;
      return RTF_EMBEDDED_INVALID;
    }
    while (offset < length && data[offset] == 0xff) {
      offset++;
    }
    if (offset >= length) {
      *failure_offset = marker_offset;
      return RTF_EMBEDDED_INVALID;
    }
    const uint8_t marker = data[offset++];

    if (marker == 0xd9) {
      if (offset != length) {
        *failure_offset = marker_offset;
        return RTF_EMBEDDED_INVALID;
      }
      return RTF_EMBEDDED_COMPLETE;
    }
    if (marker == 0x01 || (marker >= 0xd0 && marker <= 0xd7)) {
      continue;
    }
    if (marker == 0x00 || marker == 0xd8 || length - offset < 2) {
      *failure_offset = marker_offset;
      return RTF_EMBEDDED_INVALID;
    }
    const uint16_t segment_length = (uint16_t)(
        ((uint16_t)data[offset] << 8) | data[offset + 1]);

    if (segment_length < 2 || segment_length > length - offset) {
      *failure_offset = marker_offset;
      return RTF_EMBEDDED_INVALID;
    }
    offset += segment_length;
    if (marker == 0xda) {
      in_scan = true;
    }
  }
  *failure_offset = length - 1;
  return RTF_EMBEDDED_INVALID;
}

// Validate placeable and ordinary Windows Metafile record framing.
//
static inline RtfEmbeddedValidation rtf_validate_wmf(
    const uint8_t *data, uint64_t length, uint64_t *failure_offset) {

  if (failure_offset) {
    *failure_offset = 0;
  }
  if (!data || !failure_offset) {
    return RTF_EMBEDDED_INVALID;
  }

  uint64_t base = 0;

  if (length >= 22 && rtf_read_le32(data) == UINT32_C(0x9ac6cdd7)) {
    base = 22;
  }
  if (length - base < 18) {
    return RTF_EMBEDDED_INVALID;
  }
  const uint16_t type = rtf_read_le16(data + base);
  const uint16_t header_words = rtf_read_le16(data + base + 2);
  const uint16_t version = rtf_read_le16(data + base + 4);
  const uint32_t file_words = rtf_read_le32(data + base + 6);
  const uint32_t maximum_record = rtf_read_le32(data + base + 12);
  const uint64_t file_size = (uint64_t)file_words * 2;

  if ((type != 1 && type != 2) || header_words != 9
      || (version != UINT16_C(0x0100)
          && version != UINT16_C(0x0300))
      || file_size < 18 || file_size > length - base
      || maximum_record < 3 || maximum_record > file_words) {
    *failure_offset = base;
    return RTF_EMBEDDED_INVALID;
  }

  uint64_t offset = 18;

  while (offset < file_size) {
    if (file_size - offset < 6) {
      *failure_offset = base + offset;
      return RTF_EMBEDDED_INVALID;
    }
    const uint32_t record_words = rtf_read_le32(data + base + offset);
    const uint16_t function = rtf_read_le16(data + base + offset + 4);
    const uint64_t record_size = (uint64_t)record_words * 2;

    if (record_words < 3 || record_size > file_size - offset) {
      *failure_offset = base + offset;
      return RTF_EMBEDDED_INVALID;
    }
    offset += record_size;
    if (function == 0) {
      if (record_words != 3 || offset > file_size
          || base + file_size > length
          || length - (base + offset) > 2) {
        *failure_offset = base + offset - record_size;
        return RTF_EMBEDDED_INVALID;
      }
      for (uint64_t trailing = base + offset;
           trailing < length; trailing++) {
        if (data[trailing] != 0) {
          *failure_offset = trailing;
          return RTF_EMBEDDED_INVALID;
        }
      }
      return RTF_EMBEDDED_COMPLETE;
    }
  }
  *failure_offset = base + file_size - 1;
  return RTF_EMBEDDED_INVALID;
}

// Validate the OLE1 wrapper used by RTF object data and, when present, parse
// an embedded Compound File Binary Format container using its native extent.
//
static inline RtfEmbeddedValidation rtf_validate_ole1(
    const uint8_t *data, uint64_t length, uint64_t *failure_offset) {

  if (failure_offset) {
    *failure_offset = 0;
  }
  if (!data || !failure_offset || length < 8
      || rtf_read_le32(data) != UINT32_C(0x00000501)) {
    return RTF_EMBEDDED_INVALID;
  }
  const uint32_t format = rtf_read_le32(data + 4);

  if (format != 1 && format != 2) {
    *failure_offset = 4;
    return RTF_EMBEDDED_INVALID;
  }

  uint64_t offset = 8;

  for (uint32_t string_index = 0; string_index < 3; string_index++) {
    if (length - offset < 4) {
      *failure_offset = offset;
      return RTF_EMBEDDED_INVALID;
    }
    const uint32_t string_length = rtf_read_le32(data + offset);

    offset += 4;
    if ((uint64_t)string_length > length - offset
        || (string_length != 0
            && data[offset + string_length - 1] != 0)) {
      *failure_offset = offset - 4;
      return RTF_EMBEDDED_INVALID;
    }
    offset += string_length;
    if (format == 1 && string_index == 0 && offset == length) {
      return RTF_EMBEDDED_COMPLETE;
    }
  }
  if (format == 1) {
    return RTF_EMBEDDED_COMPLETE;
  }
  if (length - offset < 4) {
    *failure_offset = offset;
    return RTF_EMBEDDED_INVALID;
  }
  const uint32_t native_length = rtf_read_le32(data + offset);

  offset += 4;
  if (native_length == 0 || (uint64_t)native_length > length - offset) {
    *failure_offset = offset - 4;
    return RTF_EMBEDDED_INVALID;
  }

  static const uint8_t cfbf_magic[CFBF_MAGIC_SIZE] = {
      0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1
  };

  if (native_length >= CFBF_MAGIC_SIZE
      && memcmp(data + offset, cfbf_magic, CFBF_MAGIC_SIZE) == 0) {
    CfbfLayout layout;
    const bool valid = cfbf_parse(data + offset, native_length, &layout);
    const uint64_t cfbf_failure = layout.failure_offset;

    if (!valid) {
      *failure_offset = offset + (cfbf_failure < native_length
                                      ? cfbf_failure : native_length - 1);
      cfbf_layout_clear(&layout);
      return RTF_EMBEDDED_INVALID;
    }
    cfbf_layout_clear(&layout);
  }
  return RTF_EMBEDDED_COMPLETE;
}

static inline RtfEmbeddedValidation rtf_validate_hex_picture(
    const uint8_t *encoded, uint64_t encoded_length,
    RtfPictureKind kind, uint64_t *failure_offset) {

  uint8_t *decoded = NULL;
  uint64_t decoded_length = 0;
  uint64_t encoded_failure = 0;

  if (!failure_offset
      || !rtf_decode_hex(encoded, encoded_length, &decoded,
                         &decoded_length, &encoded_failure)) {
    if (failure_offset) {
      *failure_offset = encoded_failure;
    }
    return RTF_EMBEDDED_INVALID;
  }

  uint64_t decoded_failure = 0;
  RtfEmbeddedValidation result = RTF_EMBEDDED_COMPLETE;

  switch (kind) {
  case RTF_PICTURE_PNG:
    result = rtf_validate_png(decoded, decoded_length, &decoded_failure);
    break;
  case RTF_PICTURE_JPEG:
    result = rtf_validate_jpeg(decoded, decoded_length, &decoded_failure);
    break;
  case RTF_PICTURE_EMF:
    result = rtf_validate_emf(decoded, decoded_length, decoded_length,
                              &decoded_failure);
    break;
  case RTF_PICTURE_WMF:
    result = rtf_validate_wmf(decoded, decoded_length, &decoded_failure);
    break;
  case RTF_PICTURE_UNKNOWN:
    break;
  }
  if (result == RTF_EMBEDDED_INVALID) {
    *failure_offset = rtf_hex_encoded_offset(
        encoded, encoded_length, decoded_failure);
  }
  free(decoded);
  return result;
}

static inline RtfEmbeddedValidation rtf_validate_hex_object(
    const uint8_t *encoded, uint64_t encoded_length,
    uint64_t *failure_offset) {

  uint8_t *decoded = NULL;
  uint64_t decoded_length = 0;
  uint64_t encoded_failure = 0;

  if (!failure_offset
      || !rtf_decode_hex(encoded, encoded_length, &decoded,
                         &decoded_length, &encoded_failure)) {
    if (failure_offset) {
      *failure_offset = encoded_failure;
    }
    return RTF_EMBEDDED_INVALID;
  }

  uint64_t decoded_failure = 0;
  const RtfEmbeddedValidation result = rtf_validate_ole1(
      decoded, decoded_length, &decoded_failure);

  if (result == RTF_EMBEDDED_INVALID) {
    *failure_offset = rtf_hex_encoded_offset(
        encoded, encoded_length, decoded_failure);
  }
  free(decoded);
  return result;
}

// Validate the package carried by an RTF theme-data destination. Older
// producers may use an unrecognized payload, but a payload beginning with a
// ZIP header must have complete, internally consistent ZIP structure and
// member data.
//
static inline RtfEmbeddedValidation rtf_validate_hex_zip(
    const uint8_t *encoded, uint64_t encoded_length,
    uint64_t *failure_offset) {

  uint8_t *decoded = NULL;
  uint64_t decoded_length = 0;
  uint64_t encoded_failure = 0;

  if (!failure_offset
      || !rtf_decode_hex(encoded, encoded_length, &decoded,
                         &decoded_length, &encoded_failure)) {
    if (failure_offset) {
      *failure_offset = encoded_failure;
    }
    return RTF_EMBEDDED_INVALID;
  }
  if (!zip_has_archive_header(decoded, decoded_length)) {
    free(decoded);
    return RTF_EMBEDDED_COMPLETE;
  }

  ZipLayout layout;
  uint64_t decoded_failure = sizeof(uint32_t);
  uint64_t failure_entry = UINT64_MAX;
  bool content_valid = false;

  memset(&layout, 0, sizeof(layout));
  const bool layout_found = zip_find_layout(
      decoded, decoded_length, 0, &layout, &decoded_failure,
      &failure_entry, &content_valid);
  (void)failure_entry;

  const bool complete = layout_found && content_valid
                        && !layout.displaced_structure
                        && !layout.encrypted
                        && layout.archive_size == decoded_length;

  if (!complete) {
    if (layout_found && decoded_failure >= decoded_length) {
      decoded_failure = decoded_length == 0 ? 0 : decoded_length - 1;
    }
    *failure_offset = rtf_hex_encoded_offset(
        encoded, encoded_length, decoded_failure);
  }
  zip_layout_clear(&layout);
  free(decoded);
  return complete ? RTF_EMBEDDED_COMPLETE : RTF_EMBEDDED_INVALID;
}

// Validate RTF group structure and return the inclusive offset of the root
// group's closing brace. Escaped delimiters and binary payloads do not affect
// group depth.
//
static inline void rtf_file_validate_core(
    char *data, uint64_t length, bool *validates,
    uint64_t *validates_to, bool *promising,
    uint32_t needleidx, uint32_t blocksize,
    void *carvehashkey, RtfValidationSummary *summary) {

  (void)needleidx;
  (void)carvehashkey;

  if (!validates || !validates_to || !promising) {
    return;
  }
  if (summary) {
    summary->active_deep_payload = false;
    summary->completed_deep_payloads = 0;
    summary->completed_integrity_payloads = 0;
  }
  *validates = false;
  *promising = false;
  *validates_to = 0;

  const uint8_t *bytes = (const uint8_t *)data;

  if (!bytes || length < RTF_MINIMUM_SIZE
      || memcmp(bytes, "{\\rtf", 5) != 0
      || (!isdigit((unsigned char)bytes[5])
          && bytes[5] != '\\' && bytes[5] != ' '
          && bytes[5] != '\r' && bytes[5] != '\n')) {
    return;
  }

  uint32_t depth = 0;
  uint32_t emf_depth = 0;
  uint32_t pict_depth = 0;
  uint32_t objdata_depth = 0;
  uint32_t themedata_depth = 0;
  uint64_t pict_data_start = UINT64_MAX;
  uint64_t objdata_data_start = UINT64_MAX;
  uint64_t themedata_data_start = UINT64_MAX;
  RtfPictureKind pict_kind = RTF_PICTURE_UNKNOWN;
  uint64_t offset = 0;

  while (offset < length) {
    const uint8_t value = bytes[offset];

    if (value == '{') {
      depth++;
      if (depth > RTF_MAXIMUM_GROUP_DEPTH) {
        return;
      }
      *validates_to = offset;
      offset++;
      continue;
    }
    if (value == '}') {
      if (depth == 0) {
        return;
      }
      RtfEmbeddedValidation embedded = RTF_EMBEDDED_COMPLETE;
      uint64_t embedded_start = UINT64_MAX;
      uint64_t embedded_failure = 0;

      if (pict_depth != 0 && depth == pict_depth) {
        if (pict_kind != RTF_PICTURE_UNKNOWN
            && pict_data_start != UINT64_MAX
            && pict_data_start < offset) {
          embedded_start = pict_data_start;
          embedded = rtf_validate_hex_picture(
              bytes + pict_data_start, offset - pict_data_start,
              pict_kind, &embedded_failure);
          if (summary && embedded == RTF_EMBEDDED_COMPLETE) {
            summary->completed_deep_payloads++;
            if (pict_kind == RTF_PICTURE_PNG) {
              summary->completed_integrity_payloads++;
            }
          }
        }
        pict_depth = 0;
        pict_data_start = UINT64_MAX;
        pict_kind = RTF_PICTURE_UNKNOWN;
        if (summary) {
          summary->active_deep_payload = objdata_depth != 0
                                         || themedata_depth != 0;
        }
      }
      if (objdata_depth != 0 && depth == objdata_depth) {
        if (objdata_data_start != UINT64_MAX
            && objdata_data_start < offset) {
          embedded_start = objdata_data_start;
          embedded = rtf_validate_hex_object(
              bytes + objdata_data_start, offset - objdata_data_start,
              &embedded_failure);
          if (summary && embedded == RTF_EMBEDDED_COMPLETE) {
            summary->completed_deep_payloads++;
          }
        }
        objdata_depth = 0;
        objdata_data_start = UINT64_MAX;
        if (summary) {
          summary->active_deep_payload = pict_depth != 0
                                         && pict_kind
                                                != RTF_PICTURE_UNKNOWN;
          summary->active_deep_payload =
              summary->active_deep_payload || themedata_depth != 0;
        }
      }
      if (themedata_depth != 0 && depth == themedata_depth) {
        if (themedata_data_start != UINT64_MAX
            && themedata_data_start < offset) {
          embedded_start = themedata_data_start;
          embedded = rtf_validate_hex_zip(
              bytes + themedata_data_start,
              offset - themedata_data_start, &embedded_failure);
          if (summary && embedded == RTF_EMBEDDED_COMPLETE) {
            summary->completed_deep_payloads++;
            summary->completed_integrity_payloads++;
          }
        }
        themedata_depth = 0;
        themedata_data_start = UINT64_MAX;
        if (summary) {
          summary->active_deep_payload = objdata_depth != 0
              || (pict_depth != 0
                  && pict_kind != RTF_PICTURE_UNKNOWN);
        }
      }
      if (embedded != RTF_EMBEDDED_COMPLETE
          && embedded_start != UINT64_MAX) {
        uint64_t failure = embedded_start + embedded_failure;

        if (blocksize != 0) {
          failure = failure / blocksize * blocksize;
        }
        *validates_to = failure == 0 ? 0 : failure - 1;
        *promising = depth != 0 && failure != 0;
        return;
      }
      depth--;
      if (emf_depth != 0 && depth < emf_depth) {
        emf_depth = 0;
      }
      *validates_to = offset;
      offset++;
      if (depth == 0) {
        while (offset < length
               && (bytes[offset] == ' ' || bytes[offset] == '\t'
                   || bytes[offset] == '\r' || bytes[offset] == '\n')) {
          offset++;
        }
        if (offset < length && bytes[offset] == 0) {
          offset++;
        }
        *validates_to = offset - 1;
        *validates = true;
        *promising = false;
        return;
      }
      continue;
    }
    if (value != '\\') {
      if (pict_depth != 0 && depth == pict_depth
          && pict_kind != RTF_PICTURE_UNKNOWN
          && pict_data_start == UINT64_MAX
          && value != ' ' && value != '\t'
          && value != '\r' && value != '\n') {
        pict_data_start = offset;
      }
      if (value == 0
          || (value < 0x20 && value != '\t'
              && value != '\r' && value != '\n')) {
        *promising = depth != 0;
        return;
      }
      *validates_to = offset;
      offset++;
      continue;
    }

    if (offset + 1 >= length) {
      *validates_to = length - 1;
      *promising = depth != 0;
      return;
    }
    const uint8_t control = bytes[offset + 1];

    if (control == '\'') {
      if (offset + 3 >= length
          || !rtf_ascii_hex(bytes[offset + 2])
          || !rtf_ascii_hex(bytes[offset + 3])) {
        if (offset + 3 >= length) {
          *validates_to = length - 1;
          *promising = depth != 0;
        }
        return;
      }
      *validates_to = offset + 3;
      offset += 4;
      continue;
    }
    if (!isalpha((unsigned char)control)) {
      *validates_to = offset + 1;
      offset += 2;
      continue;
    }

    const uint64_t name_start = offset + 1;
    uint64_t cursor = name_start;

    while (cursor < length && isalpha((unsigned char)bytes[cursor])) {
      cursor++;
      if (cursor - name_start > RTF_MAXIMUM_CONTROL_WORD) {
        return;
      }
    }
    const uint64_t name_length = cursor - name_start;
    bool negative = false;
    if (cursor < length && bytes[cursor] == '-') {
      negative = true;
      cursor++;
    }
    const uint64_t number_start = cursor;
    uint64_t number = 0;

    while (cursor < length && isdigit((unsigned char)bytes[cursor])) {
      const uint8_t digit = (uint8_t)(bytes[cursor] - '0');
      if (number > (UINT64_MAX - digit) / 10) {
        return;
      }
      number = number * 10 + digit;
      cursor++;
    }
    const bool has_number = cursor != number_start;
    if (cursor < length && bytes[cursor] == ' ') {
      cursor++;
    }

    if (rtf_control_name_equals(bytes + name_start, name_length,
                                "emfblip")) {
      emf_depth = depth;
    }
    if (rtf_control_name_equals(bytes + name_start, name_length, "pict")
        && pict_depth == 0) {
      pict_depth = depth;
      pict_data_start = UINT64_MAX;
      pict_kind = RTF_PICTURE_UNKNOWN;
    }
    if (pict_depth != 0 && depth == pict_depth) {
      if (rtf_control_name_equals(bytes + name_start, name_length,
                                  "pngblip")) {
        pict_kind = RTF_PICTURE_PNG;
        if (summary) {
          summary->active_deep_payload = true;
        }
      }
      else if (rtf_control_name_equals(bytes + name_start, name_length,
                                       "jpegblip")) {
        pict_kind = RTF_PICTURE_JPEG;
        if (summary) {
          summary->active_deep_payload = true;
        }
      }
      else if (rtf_control_name_equals(bytes + name_start, name_length,
                                       "emfblip")) {
        pict_kind = RTF_PICTURE_EMF;
        if (summary) {
          summary->active_deep_payload = true;
        }
      }
      else if (rtf_control_name_equals(bytes + name_start, name_length,
                                       "wmetafile")) {
        pict_kind = RTF_PICTURE_WMF;
        if (summary) {
          summary->active_deep_payload = true;
        }
      }
    }
    if (rtf_control_name_equals(bytes + name_start, name_length,
                                "objdata")
        && objdata_depth == 0) {
      objdata_depth = depth;
      objdata_data_start = cursor;
      if (summary) {
        summary->active_deep_payload = true;
      }
    }
    if (rtf_control_name_equals(bytes + name_start, name_length,
                                "themedata")
        && themedata_depth == 0) {
      themedata_depth = depth;
      themedata_data_start = cursor;
      if (summary) {
        summary->active_deep_payload = true;
      }
    }
    if (rtf_control_name_equals(bytes + name_start, name_length, "bin")) {
      if (!has_number || negative) {
        if (negative) {
          *validates_to = cursor == 0 ? 0 : cursor - 1;
          *promising = false;
          return;
        }
        *validates_to = cursor == 0 ? 0 : cursor - 1;
        offset = cursor;
        continue;
      }
      if (emf_depth != 0) {
        uint64_t failure_offset = 0;
        const uint64_t available = length - cursor;
        const RtfEmbeddedValidation embedded = rtf_validate_emf(
            bytes + cursor, number, available, &failure_offset);

        if (embedded == RTF_EMBEDDED_INVALID) {
          uint64_t failure = cursor + failure_offset;

          if (blocksize != 0) {
            failure = failure / blocksize * blocksize;
          }
          *validates_to = failure == 0 ? 0 : failure - 1;
          *promising = depth != 0 && failure != 0;
          return;
        }
        if (embedded == RTF_EMBEDDED_INCOMPLETE) {
          *validates_to = length - 1;
          *promising = depth != 0;
          return;
        }
      }
      if (number > length - cursor) {
        *validates_to = length - 1;
        *promising = depth != 0;
        return;
      }
      cursor += number;
    }
    *validates_to = cursor == 0 ? 0 : cursor - 1;
    offset = cursor;
  }

  *promising = depth != 0;
}

static inline void rtf_file_validate(char *data, uint64_t length,
                                     bool *validates,
                                     uint64_t *validates_to,
                                     bool *promising,
                                     uint32_t needleidx,
                                     uint32_t blocksize,
                                     void *carvehashkey) {

  rtf_file_validate_core(data, length, validates, validates_to, promising,
                         needleidx, blocksize, carvehashkey, NULL);
}

// A zero byte after the root group can be either an application terminator or
// block padding. Preserve both complete interpretations when the shorter one
// independently parses as a complete RTF.
//
static inline void rtf_write_terminal_extent_alternative(
    CarveInfo **candidate, uint64_t complete_length) {

  if (!scalpel_state.write_promising
      || !candidate || !*candidate || !(*candidate)->b
      || complete_length < 2
      || complete_length
             > blockvector_get_data_length((*candidate)->b)) {
    return;
  }
  BlockVector *blockvector = (*candidate)->b;
  const uint8_t *data = (const uint8_t *)blockvector_get_data_pointer(
      blockvector);

  if (!data || data[complete_length - 1] != 0) {
    return;
  }
  bool validates = false;
  bool promising = false;
  uint64_t validates_to = 0;

  rtf_file_validate_core((char *)data, complete_length - 1,
                         &validates, &validates_to, &promising,
                         (*candidate)->needleidx, scalpel_state.blocksize,
                         (*candidate)->carvehashkey, NULL);
  if (!validates || validates_to + 1 != complete_length - 1) {
    return;
  }

  const uint64_t saved_length = blockvector_get_data_length(blockvector);
  const uint64_t saved_validates_to = (*candidate)->best_validates_to;
  const CarveInfoFlavor saved_flavor = (*candidate)->flavor;

  blockvector_set_data_length(blockvector, complete_length - 1);
  (*candidate)->best_validates_to = complete_length - 2;
  (*candidate)->flavor = PROMISING;
  write_candidate(candidate, true);
  (*candidate)->flavor = saved_flavor;
  (*candidate)->best_validates_to = saved_validates_to;
  blockvector_set_data_length(blockvector, saved_length);
}

// A complete RTF contained in its header block can be accepted directly when
// its extent is unambiguous. Multi-block and reconstructed candidates remain
// promising because RTF has no file-wide integrity value proving block order.
//
static inline void rtf_candidate_validate(CarveInfo *candidate,
                                          bool *validates,
                                          uint64_t *validates_to,
                                          bool *promising) {

  if (!candidate || !candidate->b || !validates || !promising
      || !validates_to) {
    return;
  }

  if (*validates) {
    CarveInfo *preserved_candidate = candidate;

    rtf_write_terminal_extent_alternative(
        &preserved_candidate, *validates_to + 1);
  }

  // A bad block can complete a control sequence that began at the end of the
  // preceding block and make the whole candidate invalid. Preserve that
  // preceding block only when reparsing through its boundary proves that the
  // block-aligned prefix remains structurally promising.
  if (!*validates) {
    if (*promising || scalpel_state.blocksize == 0) {
      return;
    }
    const uint64_t data_length = blockvector_get_data_length(candidate->b);
    const uint64_t prefix_blocks = CEILDIV(*validates_to + 1,
                                           scalpel_state.blocksize);

    if (prefix_blocks == 0
        || prefix_blocks > UINT64_MAX / scalpel_state.blocksize) {
      return;
    }
    const uint64_t prefix_length = prefix_blocks * scalpel_state.blocksize;

    if (prefix_length > data_length) {
      return;
    }
    bool prefix_validates = false;
    bool prefix_promising = false;
    uint64_t prefix_validates_to = 0;

    rtf_file_validate(blockvector_get_data_pointer(candidate->b),
                      prefix_length, &prefix_validates,
                      &prefix_validates_to, &prefix_promising,
                      candidate->needleidx, scalpel_state.blocksize,
                      candidate->carvehashkey);
    if (!prefix_validates && prefix_promising
        && prefix_validates_to + 1 == prefix_length) {
      *validates_to = prefix_validates_to;
      *promising = true;
    }
    return;
  }

  const uint64_t validated_blocks = scalpel_state.blocksize == 0
      ? 0 : CEILDIV(*validates_to + 1, scalpel_state.blocksize);
  const uint8_t *data = (const uint8_t *)blockvector_get_data_pointer(
      candidate->b);
  const bool ambiguous_terminal_zero = data
      && *validates_to < blockvector_get_data_length(candidate->b)
      && data[*validates_to] == 0;

  if (candidate->flavor != NO_FLAVOR || validated_blocks != 1
      || ambiguous_terminal_zero) {
    // Accepting the NUL-terminated extent would delete the shorter alternative.
    // The backend rounds unfinished promising candidates down to a complete
    // block. Preserve an exact, structurally complete contiguous candidate
    // before retaining its block-aligned prefix for fragmented recovery.
    if (candidate->flavor == NO_FLAVOR && validated_blocks > 0
        && validated_blocks
               <= blockvector_get_num_blocks(candidate->b)
        && rtf_candidate_is_contiguous(candidate)
        && scalpel_state.write_promising) {
      BlockVector *complete = NULL;

      clone_blockvector(candidate->b, &complete, false);
      deflate_blockvector(complete);
      resize_blockvector(complete, validated_blocks);
      inflate_blockvector(complete);
      blockvector_set_data_length(complete, *validates_to + 1);

      BlockVector *saved_blockvector = candidate->b;
      const CarveInfoFlavor saved_flavor = candidate->flavor;
      CarveInfo *preserved_candidate = candidate;

      candidate->b = complete;
      candidate->flavor = PROMISING;
      write_candidate(&preserved_candidate, true);
      candidate->b = saved_blockvector;
      candidate->flavor = saved_flavor;
      free_blockvector(&complete);
    }
    *validates = false;
    *promising = true;
    return;
  }

  const uint64_t available_blocks = blockvector_get_num_blocks(candidate->b);
  if (available_blocks == 0
      || blockvector_get_actual_blocknumber(candidate->b, 0) < 0) {
    *validates = false;
    *promising = true;
  }
}

// Locate closing group delimiters. A dedicated callback is required because
// the generic two-byte prefix filter cannot represent a one-byte footer.
//
static inline char *rtf_footer_discovery(char *base, uint64_t offset,
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
  if (remaining == 0) {
    return NULL;
  }

  char *found = (char *)memchr(base + offset, '}', (size_t)remaining);

  if (found) {
    *matchpos = found;
    *matchlen = 1;
  }
  return NULL;
}

// Rank blocks for RTF reassembly without excluding binary payload blocks.
// Reassembly compares these format-specific scores directly, so they must
// remain on one consistent scale regardless of other classifiers.
//
static inline uint32_t rtf_block_validate(
    char *data, uint64_t length, BlockValidationDecision *decision,
    uint64_t *validates_to, uint32_t needleidx, uint32_t blocksize,
    void *blockhashkey) {

  (void)blocksize;
  (void)blockhashkey;

  if (!data || !decision || !validates_to || length == 0) {
    return needleidx;
  }

  const uint8_t *bytes = (const uint8_t *)data;
  uint64_t content_length = length;

  while (content_length > 0 && bytes[content_length - 1] == 0) {
    content_length--;
  }
  if (content_length == 0) {
    *decision = BLOCK_CONFIDENCE_LOW;
    *validates_to = length - 1;
    return needleidx;
  }

  uint64_t text_bytes = 0;
  uint64_t syntax_bytes = 0;
  uint64_t control_bytes = 0;

  for (uint64_t offset = 0; offset < content_length; offset++) {
    const uint8_t value = bytes[offset];

    if (value >= 0x20 || value == '\t' || value == '\r' || value == '\n') {
      text_bytes++;
    }
    else {
      control_bytes++;
    }
    if (value == '\\' || value == '{' || value == '}') {
      syntax_bytes++;
    }
  }

  BlockValidationDecision confidence = (BlockValidationDecision)10;
  const uint64_t text_percent = text_bytes * UINT64_C(100) / content_length;

  if (content_length >= 5 && memcmp(bytes, "{\\rtf", 5) == 0) {
    confidence = BLOCK_CONFIDENCE_VALID;
  }
  else if (control_bytes == 0 && text_percent >= 98 && syntax_bytes >= 2) {
    confidence = (BlockValidationDecision)85;
  }
  else if (control_bytes == 0 && text_percent >= 98) {
    confidence = (BlockValidationDecision)70;
  }
  else if (text_percent >= 90 && syntax_bytes != 0) {
    confidence = (BlockValidationDecision)55;
  }
  else if (text_percent >= 75) {
    confidence = (BlockValidationDecision)35;
  }

  *decision = confidence;
  *validates_to = length - 1;
  return needleidx;
}

static inline bool rtf_candidate_is_contiguous(const CarveInfo *candidate) {

  if (!candidate || !candidate->b) {
    return false;
  }

  const uint64_t block_count = blockvector_get_num_blocks(candidate->b);

  if (block_count < 2) {
    return true;
  }
  const int64_t first_actual = blockvector_get_actual_blocknumber(
      candidate->b, 0);

  if (first_actual < 0) {
    return false;
  }
  for (uint64_t slot = 1; slot < block_count; slot++) {
    if (blockvector_get_actual_blocknumber(candidate->b, slot)
        != first_actual + (int64_t)slot) {
      return false;
    }
  }
  return true;
}

// Group byte values into broad lexical classes for a stable boundary score.
//
static inline uint32_t rtf_reassembly_byte_class(uint8_t value) {

  if (value >= '0' && value <= '9') {
    return 0;
  }
  if ((value >= 'a' && value <= 'f')
      || (value >= 'A' && value <= 'F')) {
    return 1;
  }
  if ((value >= 'g' && value <= 'z')
      || (value >= 'G' && value <= 'Z')) {
    return 2;
  }
  if (value == '\\' || value == '{' || value == '}') {
    return 3;
  }
  if (value == ' ' || value == '\t' || value == '\r' || value == '\n') {
    return 4;
  }
  if (value >= 0x20 && value < 0x7f) {
    return 5;
  }
  if (value >= 0x80) {
    return 6;
  }
  return 7;
}

// Identify hexadecimal payload context at a block boundary. Distribution
// changes inside encoded binary data do not identify a physical gap.
//
static inline bool rtf_reassembly_hex_window(const uint8_t *data,
                                              uint64_t length,
                                              bool trailing) {

  if (!data || length == 0) {
    return false;
  }
  uint64_t sample = RTF_REASSEMBLY_BRIDGE_BYTES;

  if (sample > length) {
    sample = length;
  }
  const uint64_t start = trailing ? length - sample : 0;
  uint64_t digits = 0;

  for (uint64_t offset = 0; offset < sample; offset++) {
    const uint8_t value = data[start + offset];

    if (rtf_ascii_hex(value)) {
      digits++;
      continue;
    }
    if (value != ' ' && value != '\t' && value != '\r' && value != '\n') {
      return false;
    }
  }
  return digits * 2 >= sample;
}

// Identify an RTF hexadecimal character escape divided exactly across a block
// boundary. The introducing backslash must not itself be escaped.
//
static inline bool rtf_reassembly_split_hex_escape(
    const uint8_t *left, uint64_t left_length,
    const uint8_t *right, uint64_t right_length) {

  if (!left || left_length == 0 || !right || right_length == 0) {
    return false;
  }

  uint64_t left_token_length = 0;

  if (left[left_length - 1] == '\\'
      && right_length >= 3 && right[0] == '\''
      && rtf_ascii_hex(right[1]) && rtf_ascii_hex(right[2])) {
    left_token_length = 1;
  }
  else if (left_length >= 2 && left[left_length - 2] == '\\'
           && left[left_length - 1] == '\''
           && right_length >= 2
           && rtf_ascii_hex(right[0]) && rtf_ascii_hex(right[1])) {
    left_token_length = 2;
  }
  else if (left_length >= 3 && left[left_length - 3] == '\\'
           && left[left_length - 2] == '\''
           && rtf_ascii_hex(left[left_length - 1])
           && rtf_ascii_hex(right[0])) {
    left_token_length = 3;
  }
  if (left_token_length == 0) {
    return false;
  }

  const uint64_t token_start = left_length - left_token_length;
  uint64_t backslashes = 0;
  uint64_t offset = token_start;

  do {
    backslashes++;
    if (offset == 0 || left[offset - 1] != '\\') {
      break;
    }
    offset--;
  } while (true);

  return (backslashes & 1) != 0;
}

// Identify a control word divided across a block boundary when the completed
// word already occurs in the parsed prefix. Repeated formatting controls give
// strong ordering evidence without relying on a fixed control-word dictionary.
//
static inline bool rtf_reassembly_split_repeated_control_word(
    const uint8_t *left, uint64_t left_length,
    const uint8_t *right, uint64_t right_length) {

  if (!left || left_length == 0 || !right || right_length == 0) {
    return false;
  }

  uint64_t left_word_start = left_length;

  while (left_word_start != 0) {
    const uint8_t value = left[left_word_start - 1];

    if (!isalpha((unsigned char)value)
        && !isdigit((unsigned char)value) && value != '-') {
      break;
    }
    left_word_start--;
  }
  if (left_word_start == 0 || left_word_start == left_length
      || left[left_word_start - 1] != '\\') {
    return false;
  }

  const uint64_t slash_offset = left_word_start - 1;
  uint64_t backslashes = 1;
  uint64_t slash_scan = slash_offset;

  while (slash_scan != 0 && left[slash_scan - 1] == '\\') {
    backslashes++;
    slash_scan--;
  }
  if ((backslashes & 1) == 0) {
    return false;
  }

  uint8_t completed_word[64];
  const uint64_t left_word_length = left_length - left_word_start;

  if (left_word_length >= sizeof(completed_word)) {
    return false;
  }
  memcpy(completed_word, left + left_word_start,
         (size_t)left_word_length);

  uint64_t right_word_length = 0;

  while (right_word_length < right_length
         && left_word_length + right_word_length < sizeof(completed_word)) {
    const uint8_t value = right[right_word_length];

    if (!isalpha((unsigned char)value)
        && !isdigit((unsigned char)value) && value != '-') {
      break;
    }
    completed_word[left_word_length + right_word_length] = value;
    right_word_length++;
  }
  if (right_word_length == 0
      || (right_word_length < right_length
          && (isalpha((unsigned char)right[right_word_length])
              || isdigit((unsigned char)right[right_word_length])
              || right[right_word_length] == '-'))) {
    return false;
  }

  const uint64_t completed_length = left_word_length + right_word_length;
  uint64_t word_offset = 0;

  while (word_offset < completed_length
         && isalpha((unsigned char)completed_word[word_offset])) {
    word_offset++;
  }
  if (word_offset == 0) {
    return false;
  }
  if (word_offset < completed_length && completed_word[word_offset] == '-') {
    word_offset++;
    if (word_offset == completed_length
        || !isdigit((unsigned char)completed_word[word_offset])) {
      return false;
    }
  }
  while (word_offset < completed_length
         && isdigit((unsigned char)completed_word[word_offset])) {
    word_offset++;
  }
  if (word_offset != completed_length) {
    return false;
  }

  for (uint64_t offset = 0;
       offset + 1 + completed_length <= slash_offset; offset++) {
    if (left[offset] != '\\'
        || memcmp(left + offset + 1, completed_word,
                  (size_t)completed_length) != 0) {
      continue;
    }
    const uint8_t delimiter = left[offset + 1 + completed_length];

    if (isalpha((unsigned char)delimiter)
        || isdigit((unsigned char)delimiter) || delimiter == '-') {
      continue;
    }

    uint64_t preceding_backslashes = 1;
    uint64_t preceding_scan = offset;

    while (preceding_scan != 0 && left[preceding_scan - 1] == '\\') {
      preceding_backslashes++;
      preceding_scan--;
    }
    if ((preceding_backslashes & 1) != 0) {
      return true;
    }
  }
  return false;
}

// Compare the byte classes immediately surrounding a proposed boundary.
// Lower values indicate a more natural continuation of the current content.
//
static inline uint64_t rtf_reassembly_boundary_cost(
    const uint8_t *left, uint64_t left_length,
    const uint8_t *right, uint64_t right_length) {

  if (!left || left_length == 0 || !right || right_length == 0) {
    return UINT64_MAX;
  }

  uint64_t sample = RTF_REASSEMBLY_SEAM_BYTES;

  if (sample > left_length) {
    sample = left_length;
  }
  if (sample > right_length) {
    sample = right_length;
  }

  uint32_t left_classes[8] = {0};
  uint32_t right_classes[8] = {0};

  for (uint64_t index = 0; index < sample; index++) {
    left_classes[rtf_reassembly_byte_class(
        left[left_length - sample + index])]++;
    right_classes[rtf_reassembly_byte_class(right[index])]++;
  }

  uint64_t difference = 0;

  for (uint32_t category = 0; category < 8; category++) {
    difference += left_classes[category] > right_classes[category]
        ? left_classes[category] - right_classes[category]
        : right_classes[category] - left_classes[category];
  }
  return difference;
}

// Compare raw-byte and byte-bigram distributions across one block boundary.
// This preserves more local-order information than the coarse seam score.
//
static inline uint64_t rtf_reassembly_prefix_cost(
    const uint8_t *left, uint64_t left_length,
    const uint8_t *right, uint64_t right_length) {

  if (!left || left_length == 0 || !right || right_length == 0) {
    return UINT64_MAX;
  }

  uint64_t left_sample = RTF_REASSEMBLY_BRIDGE_BYTES;
  uint64_t right_sample = RTF_REASSEMBLY_BRIDGE_BYTES;

  if (left_sample > left_length) {
    left_sample = left_length;
  }
  if (right_sample > right_length) {
    right_sample = right_length;
  }

  uint16_t left_histogram[256] = {0};
  uint16_t right_histogram[256] = {0};
  uint16_t left_bigrams[RTF_REASSEMBLY_BIGRAM_BUCKETS] = {0};
  uint16_t right_bigrams[RTF_REASSEMBLY_BIGRAM_BUCKETS] = {0};
  const uint8_t *left_start = left + left_length - left_sample;

  for (uint64_t offset = 0; offset < left_sample; offset++) {
    left_histogram[left_start[offset]]++;
  }
  for (uint64_t offset = 0; offset < right_sample; offset++) {
    right_histogram[right[offset]]++;
  }
  for (uint64_t offset = 0; offset + 1 < left_sample; offset++) {
    const uint32_t bucket =
        ((uint32_t)left_start[offset] * UINT32_C(257)
         + left_start[offset + 1])
        % RTF_REASSEMBLY_BIGRAM_BUCKETS;

    left_bigrams[bucket]++;
  }
  for (uint64_t offset = 0; offset + 1 < right_sample; offset++) {
    const uint32_t bucket =
        ((uint32_t)right[offset] * UINT32_C(257) + right[offset + 1])
        % RTF_REASSEMBLY_BIGRAM_BUCKETS;

    right_bigrams[bucket]++;
  }

  uint64_t difference = 0;

  for (uint32_t value = 0; value < 256; value++) {
    difference += left_histogram[value] > right_histogram[value]
        ? left_histogram[value] - right_histogram[value]
        : right_histogram[value] - left_histogram[value];
  }
  for (uint32_t bucket = 0;
       bucket < RTF_REASSEMBLY_BIGRAM_BUCKETS; bucket++) {
    difference += UINT64_C(2)
        * (left_bigrams[bucket] > right_bigrams[bucket]
               ? left_bigrams[bucket] - right_bigrams[bucket]
               : right_bigrams[bucket] - left_bigrams[bucket]);
  }
  return difference;
}

// Compare bounded byte-class histograms across a proposed block boundary.
// Lower values indicate a more natural continuation of the current content.
//
static inline uint64_t rtf_reassembly_seam_cost(
    BlockVector *blockvector, int64_t apparent) {

  if (!blockvector || apparent < 0 || scalpel_state.blocksize == 0) {
    return UINT64_MAX;
  }

  const uint64_t data_length = blockvector_get_data_length(blockvector);
  const uint8_t *data = (const uint8_t *)blockvector_get_data_pointer(
      blockvector);
  const int64_t actual = filemirror_actual_blocknumber(
      scalpel_state.filemirror, apparent);
  uint64_t available = 0;
  const uint8_t *source = (const uint8_t *)
      filemirror_actual_block_data_pointer(scalpel_state.filemirror, actual,
                                           &available);

  if (!data || data_length == 0 || !source || available == 0) {
    return UINT64_MAX;
  }

  return rtf_reassembly_boundary_cost(data, data_length, source, available);
}

// Order bounded displaced-block hypotheses using independent lexical and file
// type confidence rankings. Structural parsing remains the acceptance test.
//
static inline bool rtf_reassembly_choice_better(
    const RtfReassemblyChoice *candidate,
    const RtfReassemblyChoice *current,
    RtfReassemblyRanking ranking) {

  if (!candidate || !current) {
    return false;
  }
  if (ranking == RTF_REASSEMBLY_RANK_CONFIDENCE
      && candidate->confidence != current->confidence) {
    return candidate->confidence > current->confidence;
  }
  if (candidate->bridge_cost != current->bridge_cost) {
    return candidate->bridge_cost < current->bridge_cost;
  }
  if (ranking == RTF_REASSEMBLY_RANK_LEXICAL
      && candidate->confidence != current->confidence) {
    return candidate->confidence > current->confidence;
  }
  if (candidate->reserved != current->reserved) {
    return candidate->reserved < current->reserved;
  }
  return candidate->apparent < current->apparent;
}

// Retain the best bounded set of block choices in sorted order.
//
static inline void rtf_reassembly_retain_choice(
    RtfReassemblyChoice *choices, uint64_t *choice_count, uint64_t limit,
    const RtfReassemblyChoice *choice, RtfReassemblyRanking ranking) {

  if (!choices || !choice_count || !choice || limit == 0) {
    return;
  }

  uint64_t position = 0;

  while (position < *choice_count
         && !rtf_reassembly_choice_better(choice, &choices[position],
                                          ranking)) {
    position++;
  }
  if (position >= limit) {
    return;
  }

  uint64_t new_count = *choice_count;

  if (new_count < limit) {
    new_count++;
  }
  for (uint64_t move = new_count - 1; move > position; move--) {
    choices[move] = choices[move - 1];
  }
  choices[position] = *choice;
  *choice_count = new_count;
}

// Merge independently ranked choices without repeating an equivalent trial.
// A terminal-only trial remains distinct because it omits the physical suffix.
//
static inline void rtf_reassembly_append_unique_choice(
    RtfReassemblyChoice *choices, uint64_t *choice_count,
    uint64_t capacity, const RtfReassemblyChoice *choice) {

  if (!choices || !choice_count || !choice || *choice_count >= capacity) {
    return;
  }
  for (uint64_t index = 0; index < *choice_count; index++) {
    if (choices[index].apparent == choice->apparent
        && choices[index].terminal_only == choice->terminal_only) {
      return;
    }
  }
  choices[(*choice_count)++] = *choice;
}

// Compare byte and byte-bigram distributions across both sides of an inserted
// block. Bigrams retain local order that a byte histogram alone discards.
//
static inline uint64_t rtf_reassembly_bridge_cost(
    const uint8_t *left, uint64_t left_length,
    const uint8_t *middle, uint64_t middle_length,
    const uint8_t *right, uint64_t right_length) {

  const uint64_t left_cost = rtf_reassembly_prefix_cost(
      left, left_length, middle, middle_length);
  const uint64_t right_cost = rtf_reassembly_prefix_cost(
      middle, middle_length, right, right_length);

  if (left_cost == UINT64_MAX || right_cost == UINT64_MAX) {
    return UINT64_MAX;
  }
  return left_cost + right_cost;
}

// Preserve the line cadence used by hexadecimal RTF destinations across both
// sides of an inserted block. This distinguishes blocks whose byte histograms
// are identical but whose encoded-byte alignment is not.
//
static inline uint64_t rtf_reassembly_hex_bridge_cost(
    const uint8_t *left, uint64_t left_length,
    const uint8_t *middle, uint64_t middle_length,
    const uint8_t *right, uint64_t right_length) {

  if (!left || left_length == 0 || !middle || middle_length == 0
      || !right || right_length == 0) {
    return UINT64_MAX;
  }

  uint32_t gap_counts[RTF_REASSEMBLY_BRIDGE_BYTES + 1] = {0};
  uint64_t first_middle_newline = UINT64_MAX;
  uint64_t last_middle_newline = UINT64_MAX;
  uint64_t previous_middle_newline = UINT64_MAX;
  uint64_t modal_gap = 0;
  uint32_t modal_count = 0;

  for (uint64_t offset = 0; offset < middle_length; offset++) {
    const uint8_t value = middle[offset];

    if (!rtf_ascii_hex(value) && value != ' ' && value != '\t'
        && value != '\r' && value != '\n') {
      return UINT64_MAX;
    }
    if (value != '\n') {
      continue;
    }
    if (first_middle_newline == UINT64_MAX) {
      first_middle_newline = offset;
    }
    if (previous_middle_newline != UINT64_MAX) {
      const uint64_t gap = offset - previous_middle_newline;

      if (gap <= RTF_REASSEMBLY_BRIDGE_BYTES) {
        gap_counts[gap]++;
        if (gap_counts[gap] > modal_count) {
          modal_gap = gap;
          modal_count = gap_counts[gap];
        }
      }
    }
    previous_middle_newline = offset;
    last_middle_newline = offset;
  }
  if (modal_gap == 0 || first_middle_newline == last_middle_newline) {
    return UINT64_MAX;
  }

  uint64_t last_left_newline = UINT64_MAX;

  for (uint64_t offset = left_length; offset != 0; offset--) {
    if (left[offset - 1] == '\n') {
      last_left_newline = offset - 1;
      break;
    }
  }
  uint64_t first_right_newline = UINT64_MAX;

  for (uint64_t offset = 0; offset < right_length; offset++) {
    if (right[offset] == '\n') {
      first_right_newline = offset;
      break;
    }
  }
  if (last_left_newline == UINT64_MAX
      || first_right_newline == UINT64_MAX) {
    return UINT64_MAX;
  }

  const uint64_t left_gap = left_length - last_left_newline
                            + first_middle_newline;
  const uint64_t right_gap = middle_length - last_middle_newline
                             + first_right_newline;
  uint64_t cost = left_gap > modal_gap ? left_gap - modal_gap
                                       : modal_gap - left_gap;
  const uint64_t right_cost = right_gap > modal_gap
                                  ? right_gap - modal_gap
                                  : modal_gap - right_gap;

  if (right_cost > UINT64_MAX - cost) {
    return UINT64_MAX;
  }
  cost += right_cost;

  previous_middle_newline = UINT64_MAX;
  for (uint64_t offset = first_middle_newline;
       offset <= last_middle_newline; offset++) {
    if (middle[offset] != '\n') {
      continue;
    }
    if (previous_middle_newline != UINT64_MAX) {
      const uint64_t gap = offset - previous_middle_newline;
      const uint64_t gap_cost = gap > modal_gap ? gap - modal_gap
                                                : modal_gap - gap;

      if (gap_cost > UINT64_MAX - cost) {
        return UINT64_MAX;
      }
      cost += gap_cost;
    }
    previous_middle_newline = offset;
  }
  return cost;
}

// Confirm that a statistically unusual physical block remains a valid
// continuation of the RTF prefix and suffix assembled so far.
//
static inline bool rtf_reassembly_suffix_consumes_block(
    const CarveInfo *candidate, uint64_t gap_slot,
    const int64_t *suffix, uint64_t suffix_count,
    int64_t apparent) {

  if (!candidate || !candidate->b || !suffix || apparent < 0
      || scalpel_state.blocksize == 0
      || gap_slot > UINT64_MAX / scalpel_state.blocksize
      || suffix_count > UINT64_MAX - gap_slot - 1) {
    return false;
  }
  const uint64_t trial_blocks = gap_slot + suffix_count + 1;

  if (trial_blocks > SIZE_MAX / scalpel_state.blocksize) {
    return false;
  }
  const uint64_t trial_length = trial_blocks
                                * (uint64_t)scalpel_state.blocksize;
  const uint64_t current_start = (trial_blocks - 1)
                                 * (uint64_t)scalpel_state.blocksize;
  const uint64_t prefix_length = gap_slot
                                 * (uint64_t)scalpel_state.blocksize;
  const uint8_t *parent_data = (const uint8_t *)
      blockvector_get_data_pointer(candidate->b);

  if (!parent_data
      || prefix_length > blockvector_get_data_length(candidate->b)) {
    return false;
  }
  uint8_t *trial_data = (uint8_t *)malloc((size_t)trial_length);

  check_memory_allocation(trial_data, __LINE__, __FILE__,
                          "RTF suffix continuation probe");
  memcpy(trial_data, parent_data, (size_t)prefix_length);

  for (uint64_t slot = 0; slot <= suffix_count; slot++) {
    const int64_t block_apparent = slot < suffix_count
        ? suffix[slot] : apparent;
    const int64_t actual = filemirror_actual_blocknumber(
        scalpel_state.filemirror, block_apparent);
    uint64_t source_length = 0;
    const uint8_t *source = (const uint8_t *)
        filemirror_actual_block_data_pointer(scalpel_state.filemirror,
                                             actual, &source_length);

    if (actual < 0 || !source || source_length == 0) {
      free(trial_data);
      return false;
    }
    const uint64_t copy_length = source_length < scalpel_state.blocksize
        ? source_length : scalpel_state.blocksize;
    uint8_t *destination = trial_data + prefix_length
                           + slot * (uint64_t)scalpel_state.blocksize;

    memcpy(destination, source, (size_t)copy_length);
    if (copy_length < scalpel_state.blocksize) {
      memset(destination + copy_length, 0,
             (size_t)(scalpel_state.blocksize - copy_length));
    }
  }

  bool validates = false;
  bool promising = false;
  uint64_t validates_to = 0;

  rtf_file_validate((char *)trial_data, trial_length,
                    &validates, &validates_to, &promising,
                    candidate->needleidx, scalpel_state.blocksize,
                    NULL);
  free(trial_data);
  return (validates && validates_to >= current_start)
         || (promising && validates_to + 1 == trial_length);
}

// Explore one parser proven partial without replacing the established
// candidate path. The clone passes through the same reassembly function, so
// validation, checkpointing, and output handling remain centralized.
//
static inline bool rtf_reassembly_explore_partial(
    ThreadWork *work, CarveInfo **candidate,
    BlockVector *partial, uuid_string_t uuidp,
    uuid_string_t uuidc) {

  if (!work || !candidate || !*candidate || !partial) {
    free_blockvector(&partial);
    return false;
  }

  CarveInfo *branch = (CarveInfo *)malloc(sizeof(*branch));

  check_memory_allocation(branch, __LINE__, __FILE__,
                          "RTF partial candidate");
  memcpy(branch, *candidate, sizeof(*branch));
  branch->b = partial;
  branch->best_choices = NULL;
  branch->clone = true;
  branch->cloned = true;
  branch->partial_artifact_written = false;
  branch->newblock = -1;
  branch->no_initial_block_extension = false;
  branch->inprogress_pathname[0] = 0;
  uuid_generate_random(branch->clone_binuuid);
  gen_carve_hash_key(branch->carvehashkey, branch);
  (*candidate)->cloned = true;

  uuid_string_t branch_uuidc;

  uuid_unparse_lower(branch->clone_binuuid, branch_uuidc);
  rtf_reassembly(work, &branch, uuidp, branch_uuidc);

  // A checkpoint transfers the branch to the promising queue without
  // clearing the caller's pointer. In every other path reassembly consumes it.
  if (branch
      && atomic_load_explicit(&REASS_RETURN_TO_IDLE,
                              memory_order_acquire)) {
    branch = NULL;
  }
  if (branch) {
    destroy_candidate(&branch);
  }
  if (reassembly_check_kill_queue(work, candidate, uuidp, uuidc)) {
    return true;
  }
  if (atomic_load_explicit(&REASS_RETURN_TO_IDLE, memory_order_acquire)
      && reassembly_time_to_checkpoint(work->id, *candidate,
                                       uuidp, uuidc)) {
    return true;
  }
  return false;
}

// Test one parser-located physical gap after an inserted block. A complete RTF
// proves the reconstructed bytes are structurally valid, but not that the block
// mapping is unique, so successful hypotheses remain PROMISING.
//
static inline bool rtf_reassembly_write_composed_hypothesis(
    CarveInfo **candidate, BlockVector *parent, uint64_t gap_slot,
    int64_t inserted_apparent, const int64_t *suffix,
    uint64_t suffix_count, uint64_t skipped_suffix,
    uint8_t *trial_data, uint64_t trial_length) {

  if (!candidate || !*candidate || !parent || !suffix || !trial_data
      || scalpel_state.blocksize == 0 || inserted_apparent < 0
      || skipped_suffix >= suffix_count
      || suffix_count - skipped_suffix <= 1
      || gap_slot > UINT64_MAX - skipped_suffix - 1) {
    return false;
  }
  const uint64_t blocksize = scalpel_state.blocksize;
  const uint64_t skipped_block = gap_slot + 1 + skipped_suffix;

  if (skipped_block > UINT64_MAX / blocksize) {
    return false;
  }
  const uint64_t skipped_offset = skipped_block * blocksize;

  if (skipped_offset > trial_length
      || blocksize > trial_length - skipped_offset) {
    return false;
  }
  const int64_t skipped_actual = filemirror_actual_blocknumber(
      scalpel_state.filemirror, suffix[skipped_suffix]);
  uint64_t skipped_source_length = 0;
  const uint8_t *skipped_source = (const uint8_t *)
      filemirror_actual_block_data_pointer(
          scalpel_state.filemirror, skipped_actual, &skipped_source_length);

  if (skipped_actual < 0 || !skipped_source || skipped_source_length == 0) {
    return false;
  }
  const uint64_t tail_length = trial_length - skipped_offset - blocksize;
  const uint64_t composed_length = trial_length - blocksize;

  memmove(trial_data + skipped_offset,
          trial_data + skipped_offset + blocksize,
          (size_t)tail_length);

  bool composed_validates = false;
  bool composed_promising = false;
  uint64_t composed_validates_to = 0;

  rtf_file_validate((char *)trial_data, composed_length,
                    &composed_validates, &composed_validates_to,
                    &composed_promising, (*candidate)->needleidx,
                    scalpel_state.blocksize, (*candidate)->carvehashkey);

  memmove(trial_data + skipped_offset + blocksize,
          trial_data + skipped_offset, (size_t)tail_length);
  const uint64_t restore_length = skipped_source_length < blocksize
      ? skipped_source_length : blocksize;

  memcpy(trial_data + skipped_offset, skipped_source,
         (size_t)restore_length);
  if (restore_length < blocksize) {
    memset(trial_data + skipped_offset + restore_length, 0,
           (size_t)(blocksize - restore_length));
  }

  if (!composed_validates
      || composed_validates_to + 1 <= skipped_offset) {
    return false;
  }
  const uint64_t hypothesis_blocks = CEILDIV(
      composed_validates_to + 1, blocksize);

  if (hypothesis_blocks <= gap_slot
      || hypothesis_blocks > gap_slot + suffix_count) {
    return false;
  }
  const uint64_t used_suffix_blocks = hypothesis_blocks - gap_slot - 1;

  for (uint64_t slot = 0; slot < used_suffix_blocks; slot++) {
    const uint64_t suffix_slot = slot >= skipped_suffix ? slot + 1 : slot;

    if (suffix_slot >= suffix_count
        || suffix[suffix_slot] == inserted_apparent) {
      return false;
    }
  }

  BlockVector *hypothesis = NULL;

  clone_blockvector(parent, &hypothesis, false);
  deflate_blockvector(hypothesis);
  resize_blockvector(hypothesis, hypothesis_blocks);
  for (uint64_t slot = 0; slot < gap_slot; slot++) {
    blockvector_set_apparent_blocknumber(
        hypothesis, slot,
        blockvector_get_apparent_blocknumber(parent, slot));
  }
  blockvector_set_apparent_blocknumber(
      hypothesis, gap_slot, inserted_apparent);
  for (uint64_t slot = 0; slot < used_suffix_blocks; slot++) {
    const uint64_t suffix_slot = slot >= skipped_suffix ? slot + 1 : slot;

    blockvector_set_apparent_blocknumber(
        hypothesis, gap_slot + 1 + slot, suffix[suffix_slot]);
  }
  inflate_blockvector(hypothesis);
  blockvector_set_data_length(hypothesis, composed_validates_to + 1);

  const CarveInfoFlavor saved_flavor = (*candidate)->flavor;
  const uint64_t saved_validates_to = (*candidate)->best_validates_to;

  (*candidate)->b = hypothesis;
  (*candidate)->flavor = PROMISING;
  (*candidate)->best_validates_to = composed_validates_to;
  rtf_write_terminal_extent_alternative(
      candidate, composed_validates_to + 1);
  write_candidate(candidate, true);
  (*candidate)->b = parent;
  (*candidate)->flavor = saved_flavor;
  (*candidate)->best_validates_to = saved_validates_to;
  free_blockvector(&hypothesis);
  return true;
}

// Preserve structurally complete one-block insertion hypotheses between a
// parsed prefix and a physically contiguous suffix. The search is bounded
// because RTF has no integrity value that can prove a unique displaced block.
// Returning true means the caller must stop processing the candidate.
//
static inline bool rtf_reassembly_write_inserted_hypotheses(
    ThreadWork *work, CarveInfo **candidate, uint64_t gap_slot,
    bool *extended, bool following_relocated_run,
    uuid_string_t uuidp, uuid_string_t uuidc) {

  return rtf_reassembly_write_inserted_at_stage(
      work, candidate, gap_slot, extended, following_relocated_run,
      uuidp, uuidc, false);
}

// An insertion search after block-scan exhaustion must return to that stage,
// not replay the scan and replace the pending insertion's rankings.
static inline bool rtf_reassembly_write_inserted_at_stage(
    ThreadWork *work, CarveInfo **candidate, uint64_t gap_slot,
    bool *extended, bool following_relocated_run,
    uuid_string_t uuidp, uuid_string_t uuidc, bool block_scan_exhausted) {

  if (extended) {
    *extended = false;
  }
  if (!candidate || !*candidate) {
    return false;
  }
  RtfCarveState *state = rtf_search_load(*candidate);
  // Calls preceding the interrupted search already finished on this prefix.
  if (state && (state->progress.phase == RTF_SEARCH_BLOCK
                || state->progress.gap_slot != gap_slot)) {
    rtf_free_carve_state((void **)&state);
    return false;
  }
  if (!state) {
    state = calloc(1, sizeof(*state));
    check_memory_allocation(state, __LINE__, __FILE__, "RTF search progress");
    state->progress.magic = RTF_SEARCH_MAGIC;
    state->progress.gap_slot = gap_slot;
    state->progress.following_relocated_run = following_relocated_run;
    state->block_scan_exhausted = block_scan_exhausted;
    state->insertion = calloc(1, sizeof(*state->insertion));
    check_memory_allocation(state->insertion, __LINE__, __FILE__, "RTF insertion progress");
  }
  const bool yielded = rtf_reassembly_insert_search(
      work, candidate, gap_slot, extended, uuidp, uuidc, state);
  if (!yielded && *candidate && state->progress.phase != RTF_SEARCH_NONE) {
    RtfCarveState cleared = {.progress.magic = RTF_SEARCH_MAGIC};
    carve_put_state((*candidate)->carvehashkey, &cleared);
  }
  rtf_free_carve_state((void **)&state);
  return yielded;
}

static inline bool rtf_reassembly_insert_search(ThreadWork *work,
    CarveInfo **candidate, uint64_t gap_slot, bool *extended,
    uuid_string_t uuidp, uuid_string_t uuidc, RtfCarveState *state) {

  if (extended) {
    *extended = false;
  }
  if (!work || !candidate || !*candidate || !(*candidate)->b
      || !scalpel_state.write_promising || scalpel_state.blocksize == 0
      || gap_slot == 0) {
    return false;
  }

  BlockVector *parent = (*candidate)->b;
  const uint64_t parent_blocks = blockvector_get_num_blocks(parent);
  const uint64_t parent_length = blockvector_get_data_length(parent);
  const int64_t image_blocks = filemirror_apparent_blocks(
      scalpel_state.filemirror);
  const uint64_t actual_blocks = CEILDIV(
      filemirror_filesize(scalpel_state.filemirror),
      scalpel_state.blocksize);

  if (gap_slot == 0 || gap_slot > parent_blocks || parent_length == 0
      || image_blocks <= 0
      || gap_slot > UINT64_MAX / scalpel_state.blocksize) {
    return false;
  }
  const uint64_t prefix_length = gap_slot
                                 * (uint64_t)scalpel_state.blocksize;

  if (prefix_length == 0 || prefix_length > parent_length) {
    return false;
  }
  const uint8_t *parent_data = (const uint8_t *)
      blockvector_get_data_pointer(parent);
  const int64_t left_actual = blockvector_get_actual_blocknumber(
      parent, gap_slot - 1);
  int64_t right_actual = -1;
  const bool preserve_existing_suffix = gap_slot < parent_blocks;

  if (preserve_existing_suffix) {
    right_actual = blockvector_get_actual_blocknumber(parent, gap_slot);
  }

  if (!parent_data || left_actual < 0
      || prefix_length > SIZE_MAX - scalpel_state.blocksize) {
    return false;
  }
  const uint64_t probe_length = prefix_length + scalpel_state.blocksize;
  uint8_t *probe_data = (uint8_t *)malloc((size_t)probe_length);

  check_memory_allocation(probe_data, __LINE__, __FILE__,
                          "RTF physical suffix probe");
  memcpy(probe_data, parent_data, (size_t)prefix_length);

  RtfReassemblyChoice best_right = {
      .apparent = -1,
      .bridge_cost = UINT64_MAX,
      .reserved = INT64_MAX,
      .confidence = BLOCK_CONFIDENCE_INVALID,
      .terminal_only = false
  };

  const bool repairing_internal_gap = gap_slot < parent_blocks;
  const int64_t first_right_actual = left_actual
      + (repairing_internal_gap ? 1 : 2);

  for (int64_t actual = first_right_actual;
       right_actual < 0 && actual >= 0
       && (uint64_t)actual < actual_blocks
       && actual - left_actual <= RTF_REASSEMBLY_LOCAL_BLOCKS;
       actual++) {
    const int64_t apparent = filemirror_apparent_blocknumber(
        scalpel_state.filemirror, actual);
    uint64_t source_length = 0;
    const uint8_t *source = (const uint8_t *)
        filemirror_actual_block_data_pointer(scalpel_state.filemirror,
                                             actual, &source_length);
    const BlockValidationDecision confidence = filemirror_get_blocktype(
        scalpel_state.filemirror, actual, (*candidate)->needleidx);

    if (apparent < 0 || !source || source_length == 0
        || filemirror_actual_block_covered(scalpel_state.filemirror,
                                           actual)
        || (source_length >= 5 && memcmp(source, "{\\rtf", 5) == 0)) {
      continue;
    }
    bool in_prefix = false;

    for (uint64_t slot = 0; slot < gap_slot; slot++) {
      if (blockvector_get_apparent_blocknumber(parent, slot) == apparent) {
        in_prefix = true;
        break;
      }
    }
    if (in_prefix) {
      continue;
    }

    const uint64_t copy_length = source_length < scalpel_state.blocksize
        ? source_length : scalpel_state.blocksize;

    memcpy(probe_data + prefix_length, source, (size_t)copy_length);
    if (copy_length < scalpel_state.blocksize) {
      memset(probe_data + prefix_length + copy_length, 0,
             (size_t)(scalpel_state.blocksize - copy_length));
    }

    bool probe_validates = false;
    bool probe_promising = false;
    uint64_t probe_validates_to = 0;

    rtf_file_validate((char *)probe_data, probe_length,
                      &probe_validates, &probe_validates_to,
                      &probe_promising, (*candidate)->needleidx,
                      scalpel_state.blocksize, (*candidate)->carvehashkey);
    const bool consumes_source =
        (probe_validates && probe_validates_to + 1 > prefix_length)
        || (probe_promising && probe_validates_to + 1 == probe_length);

    if (repairing_internal_gap && !consumes_source) {
      continue;
    }

    RtfReassemblyChoice choice = {
        .apparent = apparent,
        .bridge_cost = rtf_reassembly_boundary_cost(
            parent_data, prefix_length, source, source_length),
        .reserved = scalpel_state.reservations
            ? filemirror_actual_block_reserved(scalpel_state.filemirror,
                                               actual) : 0,
        .confidence = confidence,
        .terminal_only = false
    };

    if (best_right.apparent < 0
        || rtf_reassembly_choice_better(
               &choice, &best_right, RTF_REASSEMBLY_RANK_LEXICAL)) {
      best_right = choice;
    }
    // The adjacent block was already rejected before an end-gap search. Keep
    // the first physical block after that hole so abrupt binary or object data
    // is not mistaken for an unrelated run. Internal repair instead examines
    // the full local window.
    if (!repairing_internal_gap) {
      break;
    }
  }
  free(probe_data);
  if (right_actual < 0 && best_right.apparent >= 0) {
    right_actual = filemirror_actual_blocknumber(
        scalpel_state.filemirror, best_right.apparent);
  }
  if (right_actual < 0) {
    return false;
  }

  uint64_t suffix_capacity = preserve_existing_suffix
      ? parent_blocks - gap_slot : UINT64_C(64);
  uint64_t suffix_count = 0;

  if (suffix_capacity == 0) {
    return false;
  }
  int64_t *suffix = (int64_t *)malloc(
      (size_t)suffix_capacity * sizeof(*suffix));

  check_memory_allocation(suffix, __LINE__, __FILE__,
                          "RTF physical suffix");
  if (preserve_existing_suffix) {
    for (uint64_t slot = gap_slot; slot < parent_blocks; slot++) {
      const int64_t apparent = blockvector_get_apparent_blocknumber(
          parent, slot);

      if (apparent < 0) {
        break;
      }
      suffix[suffix_count++] = apparent;
    }
  }
  else {
    const uint64_t maximum_blocks = scalpel_state.search_specs[
        (*candidate)->needleidx].MAXIMUMSIZE / scalpel_state.blocksize;

    for (uint64_t actual = (uint64_t)right_actual;
         actual < actual_blocks
         && gap_slot + 1 + suffix_count < maximum_blocks;
         actual++) {
      const int64_t apparent = filemirror_apparent_blocknumber(
          scalpel_state.filemirror, (int64_t)actual);

      if (apparent < 0
          || filemirror_actual_block_covered(scalpel_state.filemirror,
                                             (int64_t)actual)) {
        break;
      }
      uint64_t source_length = 0;
      const uint8_t *source = (const uint8_t *)
          filemirror_actual_block_data_pointer(scalpel_state.filemirror,
                                               (int64_t)actual,
                                               &source_length);

      if (!source || source_length == 0
          || (suffix_count != 0 && source_length >= 5
              && memcmp(source, "{\\rtf", 5) == 0)) {
        break;
      }

      // Stop before a later physical hole so the caller can repair each
      // discontinuity independently. Hexadecimal payloads are intentionally
      // excluded because their byte distributions can change abruptly inside
      // an otherwise contiguous encoded object.
      if (suffix_count >= RTF_REASSEMBLY_SUFFIX_FLOOR
          && actual + 1 < actual_blocks) {
        uint64_t previous_length = 0;
        uint64_t lookahead_length = 0;
        const uint8_t *previous = (const uint8_t *)
            filemirror_actual_block_data_pointer(
                scalpel_state.filemirror, (int64_t)actual - 1,
                &previous_length);
        const uint8_t *lookahead = (const uint8_t *)
            filemirror_actual_block_data_pointer(
                scalpel_state.filemirror, (int64_t)actual + 1,
                &lookahead_length);
        const bool previous_to_current_hex =
            rtf_reassembly_hex_window(previous, previous_length, true)
            && rtf_reassembly_hex_window(source, source_length, false);
        const bool current_to_lookahead_hex =
            rtf_reassembly_hex_window(source, source_length, false)
            && rtf_reassembly_hex_window(lookahead, lookahead_length, false);
        const bool hexadecimal_context = previous_to_current_hex
                                         || current_to_lookahead_hex;

        if (!hexadecimal_context && previous && previous_length != 0
            && lookahead && lookahead_length != 0
            && !filemirror_actual_block_covered(
                   scalpel_state.filemirror, (int64_t)actual + 1)
            && rtf_reassembly_boundary_cost(
                   previous, previous_length, source,
                   source_length) > RTF_REASSEMBLY_SEAM_BYTES
            && rtf_reassembly_boundary_cost(
                   previous, previous_length, lookahead,
                   lookahead_length) <= RTF_REASSEMBLY_SEAM_BYTES
            && !rtf_reassembly_suffix_consumes_block(
                   *candidate, gap_slot, suffix, suffix_count, apparent)) {
          break;
        }
      }
      bool in_prefix = false;

      for (uint64_t slot = 0; slot < gap_slot; slot++) {
        if (blockvector_get_apparent_blocknumber(parent, slot) == apparent) {
          in_prefix = true;
          break;
        }
      }
      if (in_prefix) {
        break;
      }
      if (suffix_count == suffix_capacity) {
        if (suffix_capacity > SIZE_MAX / 2 / sizeof(*suffix)) {
          break;
        }
        suffix_capacity *= 2;
        suffix = (int64_t *)realloc(
            suffix, (size_t)suffix_capacity * sizeof(*suffix));
        check_memory_allocation(suffix, __LINE__, __FILE__,
                                "RTF physical suffix");
      }
      suffix[suffix_count++] = apparent;
    }
  }

  if (suffix_count == 0
      || suffix_count > (SIZE_MAX - prefix_length
                         - scalpel_state.blocksize)
                        / scalpel_state.blocksize) {
    free(suffix);
    return false;
  }
  const uint64_t suffix_length = suffix_count
                                 * (uint64_t)scalpel_state.blocksize;
  const uint64_t trial_length = prefix_length
                                + scalpel_state.blocksize + suffix_length;
  uint8_t *trial_data = (uint8_t *)malloc((size_t)trial_length);

  check_memory_allocation(trial_data, __LINE__, __FILE__,
                          "RTF insertion trial data");
  memcpy(trial_data, parent_data, (size_t)prefix_length);
  for (uint64_t slot = 0; slot < suffix_count; slot++) {
    const int64_t actual = filemirror_actual_blocknumber(
        scalpel_state.filemirror, suffix[slot]);
    uint64_t source_length = 0;
    const uint8_t *source = (const uint8_t *)
        filemirror_actual_block_data_pointer(scalpel_state.filemirror,
                                             actual, &source_length);

    if (!source || source_length == 0) {
      free(trial_data);
      free(suffix);
      return false;
    }
    const uint64_t copy_length = source_length < scalpel_state.blocksize
        ? source_length : scalpel_state.blocksize;

    memcpy(trial_data + prefix_length + scalpel_state.blocksize
               + slot * (uint64_t)scalpel_state.blocksize,
           source, (size_t)copy_length);
    if (copy_length < scalpel_state.blocksize) {
      memset(trial_data + prefix_length + scalpel_state.blocksize
                 + slot * (uint64_t)scalpel_state.blocksize + copy_length,
             0, (size_t)(scalpel_state.blocksize - copy_length));
    }
  }

  uint64_t direct_fallback_blocks = 0;
  uint64_t direct_fallback_length = 0;
  uint64_t longest_complete_blocks = 0;
  bool direct_hypothesis_written = false;

  // A complete direct suffix is definitive enough to commit immediately. An
  // incomplete direct suffix remains available as a fallback after testing
  // whether a displaced block completes the file at this discontinuity.
  if (extended && !preserve_existing_suffix) {
    const uint64_t direct_length = prefix_length + suffix_length;
    uint8_t *direct_data = (uint8_t *)malloc((size_t)direct_length);

    check_memory_allocation(direct_data, __LINE__, __FILE__,
                            "RTF direct suffix data");
    memcpy(direct_data, parent_data, (size_t)prefix_length);
    memcpy(direct_data + prefix_length,
           trial_data + prefix_length + scalpel_state.blocksize,
           (size_t)suffix_length);

    bool direct_validates = false;
    bool direct_promising = false;
    uint64_t direct_validates_to = 0;

    rtf_file_validate((char *)direct_data, direct_length,
                      &direct_validates, &direct_validates_to,
                      &direct_promising, (*candidate)->needleidx,
                      scalpel_state.blocksize, (*candidate)->carvehashkey);
    uint64_t committed_blocks = 0;
    uint64_t committed_length = 0;

    if (direct_validates) {
      committed_blocks = CEILDIV(direct_validates_to + 1,
                                 scalpel_state.blocksize);
      committed_length = direct_validates_to + 1;
    }
    else if (gap_slot == parent_blocks) {
      const uint64_t parsed_blocks = (direct_validates_to + 1)
                                     / scalpel_state.blocksize;

      if (parsed_blocks > gap_slot
          && parsed_blocks <= gap_slot + suffix_count) {
        const uint64_t parsed_length = parsed_blocks
                                       * (uint64_t)scalpel_state.blocksize;
        bool prefix_validates = false;
        bool prefix_promising = false;
        uint64_t prefix_validates_to = 0;

        rtf_file_validate((char *)direct_data, parsed_length,
                          &prefix_validates, &prefix_validates_to,
                          &prefix_promising, (*candidate)->needleidx,
                          scalpel_state.blocksize,
                          (*candidate)->carvehashkey);
        if (!prefix_validates && prefix_promising
            && prefix_validates_to + 1 == parsed_length) {
          direct_fallback_blocks = parsed_blocks;
          direct_fallback_length = parsed_length;
        }
      }
    }

    free(direct_data);
    if (committed_blocks > gap_slot
        && committed_blocks <= gap_slot + suffix_count) {
      BlockVector *direct_hypothesis = NULL;

      clone_blockvector(parent, &direct_hypothesis, false);
      parent_data = (const uint8_t *)blockvector_get_data_pointer(parent);
      if (!parent_data) {
        free_blockvector(&direct_hypothesis);
        free(trial_data);
        free(suffix);
        return false;
      }
      deflate_blockvector(direct_hypothesis);
      resize_blockvector(direct_hypothesis, committed_blocks);
      for (uint64_t slot = 0; slot < committed_blocks - gap_slot; slot++) {
        blockvector_set_apparent_blocknumber(
            direct_hypothesis, gap_slot + slot, suffix[slot]);
      }
      inflate_blockvector(direct_hypothesis);
      blockvector_set_data_length(direct_hypothesis, committed_length);

      const CarveInfoFlavor saved_flavor = (*candidate)->flavor;
      const uint64_t saved_validates_to = (*candidate)->best_validates_to;

      (*candidate)->b = direct_hypothesis;
      (*candidate)->flavor = PROMISING;
      (*candidate)->best_validates_to = committed_length - 1;
      rtf_write_terminal_extent_alternative(candidate, committed_length);
      write_candidate(candidate, true);
      (*candidate)->b = parent;
      (*candidate)->flavor = saved_flavor;
      (*candidate)->best_validates_to = saved_validates_to;
      free_blockvector(&direct_hypothesis);
      direct_hypothesis_written = true;
      longest_complete_blocks = committed_blocks;
    }
  }

  RtfValidationSummary prefix_summary = {0};
  bool prefix_validates = false;
  bool prefix_promising = false;
  uint64_t prefix_validates_to = 0;

  rtf_file_validate_core((char *)parent_data, prefix_length,
                         &prefix_validates, &prefix_validates_to,
                         &prefix_promising, (*candidate)->needleidx,
                         scalpel_state.blocksize, (*candidate)->carvehashkey,
                         &prefix_summary);

  const uint8_t *right_data = trial_data + prefix_length
                              + scalpel_state.blocksize;
  const bool embedded_hex_gap = prefix_summary.active_deep_payload
      && rtf_reassembly_hex_window(parent_data, prefix_length, true)
      && rtf_reassembly_hex_window(right_data,
                                   scalpel_state.blocksize, false);
  const uint64_t hypothesis_limit = embedded_hex_gap
      ? RTF_REASSEMBLY_EMBEDDED_HYPOTHESIS_LIMIT
      : RTF_REASSEMBLY_HYPOTHESIS_LIMIT;

  RtfReassemblyChoice
      choices[RTF_REASSEMBLY_EMBEDDED_HYPOTHESIS_LIMIT * 6];
  RtfReassemblyChoice
      hex_choices[RTF_REASSEMBLY_EMBEDDED_HYPOTHESIS_LIMIT];
  RtfReassemblyChoice
      syntax_choices[RTF_REASSEMBLY_EMBEDDED_HYPOTHESIS_LIMIT];
  RtfReassemblyChoice
      lexical_choices[RTF_REASSEMBLY_EMBEDDED_HYPOTHESIS_LIMIT];
  RtfReassemblyChoice
      confidence_choices[RTF_REASSEMBLY_EMBEDDED_HYPOTHESIS_LIMIT];
  RtfReassemblyChoice
      terminal_choices[RTF_REASSEMBLY_EMBEDDED_HYPOTHESIS_LIMIT];
  RtfReassemblyChoice
      clean_terminal_choices[RTF_REASSEMBLY_EMBEDDED_HYPOTHESIS_LIMIT];
  uint64_t choice_count = 0;
  uint64_t hex_choice_count = 0;
  uint64_t syntax_choice_count = 0;
  uint64_t lexical_choice_count = 0;
  uint64_t confidence_choice_count = 0;
  uint64_t terminal_choice_count = 0;
  uint64_t clean_terminal_choice_count = 0;
  uint64_t hypotheses_written = 0;
  uint64_t composed_hypotheses_written = 0;
  uint64_t clean_terminal_hypotheses = 0;
  uint64_t scanned = 0;
  RtfInsertionProgress *progress = state->insertion;
  if (state->progress.phase != RTF_SEARCH_NONE) {
    hex_choice_count = progress->counts[0];
    syntax_choice_count = progress->counts[1];
    lexical_choice_count = progress->counts[2];
    confidence_choice_count = progress->counts[3];
    terminal_choice_count = progress->counts[4];
    clean_terminal_choice_count = progress->counts[5];
    memcpy(hex_choices, progress->ranks[0], hex_choice_count * sizeof(*hex_choices));
    memcpy(syntax_choices, progress->ranks[1], syntax_choice_count * sizeof(*syntax_choices));
    memcpy(lexical_choices, progress->ranks[2], lexical_choice_count * sizeof(*lexical_choices));
    memcpy(confidence_choices, progress->ranks[3], confidence_choice_count * sizeof(*confidence_choices));
    memcpy(terminal_choices, progress->ranks[4], terminal_choice_count * sizeof(*terminal_choices));
    memcpy(clean_terminal_choices, progress->ranks[5], clean_terminal_choice_count * sizeof(*clean_terminal_choices));
    hypotheses_written = progress->written;
    composed_hypotheses_written = progress->composed;
    clean_terminal_hypotheses = progress->clean_terminal;
    if (progress->longest_complete > longest_complete_blocks) {
      longest_complete_blocks = progress->longest_complete;
    }
  }
  for (int64_t apparent = (int64_t)state->progress.next_apparent;
       apparent < image_blocks && state->progress.phase <= RTF_SEARCH_RANK; apparent++) {
    scanned++;
    const int64_t actual = filemirror_actual_blocknumber(
        scalpel_state.filemirror, apparent);
    bool in_mapping = false;

    for (uint64_t slot = 0; slot < gap_slot; slot++) {
      if (blockvector_get_apparent_blocknumber(parent, slot) == apparent) {
        in_mapping = true;
        break;
      }
    }
    if (actual >= 0 && !in_mapping
        && !filemirror_actual_block_covered(scalpel_state.filemirror,
                                            actual)) {
      const BlockValidationDecision confidence = filemirror_get_blocktype(
          scalpel_state.filemirror, actual, (*candidate)->needleidx);
      uint64_t source_length = 0;
      const uint8_t *source = (const uint8_t *)
          filemirror_actual_block_data_pointer(scalpel_state.filemirror,
                                               actual, &source_length);

      if (confidence != BLOCK_CONFIDENCE_INVALID && source
          && source_length == scalpel_state.blocksize
          && !(source_length >= 5
               && memcmp(source, "{\\rtf", 5) == 0)) {
        RtfReassemblyChoice choice;

        choice.apparent = apparent;
        choice.bridge_cost = rtf_reassembly_bridge_cost(
            parent_data, prefix_length, source, source_length,
            right_data, scalpel_state.blocksize);
        choice.reserved = scalpel_state.reservations
            ? filemirror_actual_block_reserved(scalpel_state.filemirror,
                                               actual) : 0;
        choice.confidence = confidence;
        choice.terminal_only = false;
        if (embedded_hex_gap) {
          RtfReassemblyChoice hex_choice = choice;
          const uint64_t cadence_cost = rtf_reassembly_hex_bridge_cost(
              parent_data, prefix_length, source, source_length,
              right_data, scalpel_state.blocksize);
          const uint64_t lexical_cost = choice.bridge_cost;
          const uint64_t lexical_scale =
              RTF_REASSEMBLY_BRIDGE_BYTES * UINT64_C(16);

          hex_choice.bridge_cost = UINT64_MAX;
          if (cadence_cost != UINT64_MAX && lexical_cost != UINT64_MAX
              && lexical_scale != 0) {
            const uint64_t bounded_lexical = lexical_cost < lexical_scale
                                                 ? lexical_cost
                                                 : lexical_scale - 1;

            if (cadence_cost
                <= (UINT64_MAX - bounded_lexical) / lexical_scale) {
              hex_choice.bridge_cost = cadence_cost * lexical_scale
                                       + bounded_lexical;
            }
          }
          if (hex_choice.bridge_cost != UINT64_MAX) {
            rtf_reassembly_retain_choice(
                hex_choices, &hex_choice_count, hypothesis_limit,
                &hex_choice, RTF_REASSEMBLY_RANK_LEXICAL);
          }
        }
        if (rtf_reassembly_split_hex_escape(
                parent_data, prefix_length, source, source_length)
            || rtf_reassembly_split_hex_escape(
                source, source_length, right_data,
                scalpel_state.blocksize)
            || rtf_reassembly_split_repeated_control_word(
                parent_data, prefix_length, source, source_length)
            || rtf_reassembly_split_repeated_control_word(
                source, source_length, right_data,
                scalpel_state.blocksize)) {
          rtf_reassembly_retain_choice(
              syntax_choices, &syntax_choice_count, hypothesis_limit,
              &choice, RTF_REASSEMBLY_RANK_LEXICAL);
        }
        rtf_reassembly_retain_choice(
            lexical_choices, &lexical_choice_count, hypothesis_limit,
            &choice, RTF_REASSEMBLY_RANK_LEXICAL);

        RtfReassemblyChoice confidence_choice = choice;

        rtf_reassembly_retain_choice(
            confidence_choices, &confidence_choice_count,
            hypothesis_limit, &confidence_choice,
            RTF_REASSEMBLY_RANK_CONFIDENCE);

        RtfReassemblyChoice terminal_choice = choice;

        terminal_choice.bridge_cost = rtf_reassembly_prefix_cost(
            parent_data, prefix_length, source, source_length);
        terminal_choice.terminal_only = true;
        rtf_reassembly_retain_choice(
            terminal_choices, &terminal_choice_count,
            hypothesis_limit, &terminal_choice,
            RTF_REASSEMBLY_RANK_LEXICAL);

        // After an earlier discontinuity has been repaired, a later displaced
        // final block can rank behind ordinary text blocks. Give terminal blocks
        // an independent ranking when the physical suffix cannot complete the
        // candidate; direct completions retain the normal bounded ordering.
        if (!direct_hypothesis_written && !embedded_hex_gap
            && !rtf_candidate_is_contiguous(*candidate)) {
          uint64_t terminal_length = source_length;

          while (terminal_length != 0) {
            const uint8_t value = source[terminal_length - 1];

            if (value != 0 && value != ' ' && value != '\t'
                && value != '\r' && value != '\n') {
              break;
            }
            terminal_length--;
          }
          if (terminal_length != 0
              && source[terminal_length - 1] == '}') {
            rtf_reassembly_retain_choice(
                clean_terminal_choices, &clean_terminal_choice_count,
                hypothesis_limit, &terminal_choice,
                RTF_REASSEMBLY_RANK_LEXICAL);
          }
        }
      }
    }

    if ((scanned % RTF_REASSEMBLY_POLL_INTERVAL) == 0) {
      if (reassembly_check_kill_queue(work, candidate, uuidp, uuidc)) {
        free(trial_data);
        free(suffix);
        return true;
      }
      if (atomic_load_explicit(&REASS_RETURN_TO_IDLE,
                               memory_order_acquire)) {
        state->progress.phase = RTF_SEARCH_RANK;
        state->progress.next_apparent = (uint64_t)apparent + 1;
        const uint64_t counts[] = {hex_choice_count, syntax_choice_count, lexical_choice_count,
            confidence_choice_count, terminal_choice_count, clean_terminal_choice_count};
        const RtfReassemblyChoice *ranks[] = {hex_choices, syntax_choices, lexical_choices,
            confidence_choices, terminal_choices, clean_terminal_choices};
        for (size_t i = 0; i < 6; i++) {
          progress->counts[i] = counts[i];
          memcpy(progress->ranks[i], ranks[i], counts[i] * sizeof(*ranks[i]));
        }
        rtf_search_save(*candidate, state);
        if (reassembly_time_to_checkpoint(work->id, *candidate, uuidp, uuidc)) {
          free(trial_data);
          free(suffix);
          return true;
        }
      }
    }
  }

  // Retain rankings for interruptions while testing their interleaved choices.
  const uint64_t counts[] = {hex_choice_count, syntax_choice_count, lexical_choice_count,
      confidence_choice_count, terminal_choice_count, clean_terminal_choice_count};
  const RtfReassemblyChoice *ranks[] = {hex_choices, syntax_choices, lexical_choices,
      confidence_choices, terminal_choices, clean_terminal_choices};
  for (size_t i = 0; i < 6; i++) {
    progress->counts[i] = counts[i];
    memcpy(progress->ranks[i], ranks[i], counts[i] * sizeof(*ranks[i]));
  }

  // Interleave independent rankings so a strong candidate in any ranking is
  // tested promptly. Left-only choices are full hypotheses inside an active
  // hexadecimal payload because the right boundary can be uninformative.
  if (scalpel_state.mode_verbose && embedded_hex_gap) {
    const uint64_t report_count = hex_choice_count < 8
                                      ? hex_choice_count : 8;

    lock_fprintf(stdout,
                 "RTF hexadecimal ranking: header=%" PRId64
                 " gap slot=%" PRIu64 " candidates=%" PRIu64 ".\n",
                 blockvector_get_actual_blocknumber(parent, 0), gap_slot,
                 hex_choice_count);
    for (uint64_t rank = 0; rank < report_count; rank++) {
      lock_fprintf(stdout,
                   "  rank=%" PRIu64 " actual=%" PRId64
                   " hexadecimal score=%" PRIu64 " confidence=%u.\n",
                   rank + 1,
                   filemirror_actual_blocknumber(
                       scalpel_state.filemirror,
                       hex_choices[rank].apparent),
                   hex_choices[rank].bridge_cost,
                   (unsigned int)hex_choices[rank].confidence);
    }
  }
  const uint64_t choice_capacity = hypothesis_limit * 6;
  const uint64_t terminal_limit = embedded_hex_gap
      && terminal_choice_count > RTF_REASSEMBLY_EMBEDDED_PREFIX_LIMIT
      ? RTF_REASSEMBLY_EMBEDDED_PREFIX_LIMIT : terminal_choice_count;
  const uint64_t preserved_hypothesis_limit = embedded_hex_gap
      ? RTF_REASSEMBLY_EMBEDDED_PRESERVED_HYPOTHESIS_LIMIT
      : RTF_REASSEMBLY_PRESERVED_HYPOTHESIS_LIMIT;
  const uint64_t prioritized_hex_count = hex_choice_count
      < RTF_REASSEMBLY_EMBEDDED_HEX_PRIORITY_LIMIT
      ? hex_choice_count : RTF_REASSEMBLY_EMBEDDED_HEX_PRIORITY_LIMIT;

  // Embedded objects can make ordinary lexical boundaries uninformative.
  // Test a small leading hexadecimal window first, then balance the remaining
  // hexadecimal candidates against every other independent ranking.
  for (uint64_t rank = 0; rank < prioritized_hex_count; rank++) {
    rtf_reassembly_append_unique_choice(
        choices, &choice_count, choice_capacity, &hex_choices[rank]);
  }

  for (uint64_t rank = 0; rank < hypothesis_limit; rank++) {
    if (rank < syntax_choice_count) {
      rtf_reassembly_append_unique_choice(
          choices, &choice_count, choice_capacity,
          &syntax_choices[rank]);
    }
    if (rank < clean_terminal_choice_count) {
      rtf_reassembly_append_unique_choice(
          choices, &choice_count, choice_capacity,
          &clean_terminal_choices[rank]);
    }
    if (rank < lexical_choice_count) {
      rtf_reassembly_append_unique_choice(
          choices, &choice_count, choice_capacity,
          &lexical_choices[rank]);
    }
    if (rank < confidence_choice_count) {
      rtf_reassembly_append_unique_choice(
          choices, &choice_count, choice_capacity,
          &confidence_choices[rank]);
    }
    if (rank < terminal_limit) {
      RtfReassemblyChoice terminal_choice = terminal_choices[rank];

      terminal_choice.terminal_only = !embedded_hex_gap;
      rtf_reassembly_append_unique_choice(
          choices, &choice_count, choice_capacity, &terminal_choice);
    }
    if (rank + prioritized_hex_count < hex_choice_count) {
      rtf_reassembly_append_unique_choice(
          choices, &choice_count, choice_capacity,
          &hex_choices[rank + prioritized_hex_count]);
    }
  }

  // Retain the strongest block-aligned partial so independently repaired
  // discontinuities can be composed without accepting the file as validated.
  int64_t best_partial_apparent = -1;
  uint64_t best_partial_blocks = 0;
  uint64_t best_partial_suffix_blocks = 0;
  bool best_partial_integrity = false;
  RtfReassemblyChoice best_partial_choice = {
      .apparent = -1,
      .bridge_cost = UINT64_MAX,
      .reserved = INT64_MAX,
      .confidence = BLOCK_CONFIDENCE_INVALID,
      .terminal_only = false
  };
  if (state->progress.phase >= RTF_SEARCH_TRIAL) {
    best_partial_apparent = progress->best_partial;
    best_partial_blocks = progress->partial_blocks;
    best_partial_suffix_blocks = progress->partial_suffix_blocks;
    best_partial_integrity = progress->partial_integrity;
    best_partial_choice = progress->partial_choice;
  }

  for (uint64_t choice_index = progress->choice_index;
       choice_index < choice_count
       && state->progress.phase != RTF_SEARCH_PARTIAL
       && hypotheses_written < preserved_hypothesis_limit;
       choice_index++) {
    const int64_t actual = filemirror_actual_blocknumber(
        scalpel_state.filemirror, choices[choice_index].apparent);
    uint64_t source_length = 0;
    const uint8_t *source = (const uint8_t *)
        filemirror_actual_block_data_pointer(scalpel_state.filemirror,
                                             actual, &source_length);

    if (!source || source_length != scalpel_state.blocksize) {
      continue;
    }
    memcpy(trial_data + prefix_length, source,
           (size_t)scalpel_state.blocksize);

    bool trial_validates = false;
    bool trial_promising = false;
    uint64_t trial_validates_to = 0;
    RtfValidationSummary trial_summary = {0};
    uint64_t choice_suffix_blocks = choices[choice_index].terminal_only
        ? 0 : suffix_count;

    if (choice_suffix_blocks > RTF_REASSEMBLY_INITIAL_SUFFIX_BLOCKS) {
      choice_suffix_blocks = RTF_REASSEMBLY_INITIAL_SUFFIX_BLOCKS;
    }
    uint64_t choice_trial_length = prefix_length
        + scalpel_state.blocksize
        + choice_suffix_blocks * (uint64_t)scalpel_state.blocksize;

    // Expand the physical suffix only while this block consumes the complete
    // trial window. This preserves unbounded file recovery without parsing a
    // long irrelevant suffix for every rejected block.
    while (true) {
      trial_validates = false;
      trial_promising = false;
      trial_validates_to = 0;
      trial_summary = (RtfValidationSummary){0};
      rtf_file_validate_core((char *)trial_data, choice_trial_length,
                             &trial_validates, &trial_validates_to,
                             &trial_promising, (*candidate)->needleidx,
                             scalpel_state.blocksize,
                             (*candidate)->carvehashkey, &trial_summary);

      const bool consumed_trial = !trial_validates && trial_promising
          && trial_validates_to + 1 == choice_trial_length;

      if (choices[choice_index].terminal_only || !consumed_trial
          || choice_suffix_blocks == suffix_count) {
        break;
      }
      if (choice_suffix_blocks > suffix_count / 2) {
        choice_suffix_blocks = suffix_count;
      }
      else {
        choice_suffix_blocks *= 2;
      }
      choice_trial_length = prefix_length + scalpel_state.blocksize
          + choice_suffix_blocks * (uint64_t)scalpel_state.blocksize;
    }

    const uint64_t parsed_length = trial_validates_to + 1;
    const uint64_t verified_length = parsed_length
        / scalpel_state.blocksize * scalpel_state.blocksize;
    bool verified_prefix_validates = false;
    bool verified_prefix_promising = false;
    uint64_t verified_prefix_validates_to = 0;

    if (extended
        && choice_index < RTF_REASSEMBLY_PARTIAL_HYPOTHESIS_LIMIT
        && !choices[choice_index].terminal_only
        && verified_length > prefix_length + scalpel_state.blocksize) {
      rtf_file_validate((char *)trial_data, verified_length,
                        &verified_prefix_validates,
                        &verified_prefix_validates_to,
                        &verified_prefix_promising,
                        (*candidate)->needleidx, scalpel_state.blocksize,
                        (*candidate)->carvehashkey);
    }
    const bool verified_partial = !verified_prefix_validates
        && verified_prefix_promising
        && verified_prefix_validates_to + 1 == verified_length;
    const bool integrity_progress = prefix_summary.active_deep_payload
        && trial_summary.completed_integrity_payloads
               > prefix_summary.completed_integrity_payloads;

    // Compose a displaced block with a later physical gap only after the parser
    // consumes the inserted block and locates the second discontinuity.
    if (!trial_validates && !choices[choice_index].terminal_only
        && parsed_length > prefix_length + scalpel_state.blocksize
        && suffix_count > 1) {
      const uint64_t failure_block = trial_validates_to
                                     / scalpel_state.blocksize;
      const uint64_t suffix_start_block = gap_slot + 1;

      if (failure_block >= suffix_start_block) {
        const uint64_t estimated_skip = failure_block - suffix_start_block;
        const int32_t adjustments[] = {0, -1, 1};

        for (uint64_t adjustment_index = 0;
             adjustment_index < sizeof(adjustments) / sizeof(adjustments[0])
             && hypotheses_written
                    < preserved_hypothesis_limit
             && composed_hypotheses_written
                    < RTF_REASSEMBLY_COMPOSED_HYPOTHESIS_LIMIT;
             adjustment_index++) {
          const int32_t adjustment = adjustments[adjustment_index];
          const int64_t signed_skip = (int64_t)estimated_skip + adjustment;

          if (signed_skip < 0 || (uint64_t)signed_skip + 1 >= suffix_count) {
            continue;
          }
          const uint64_t skipped_suffix = (uint64_t)signed_skip;
          const bool wrote_hypothesis =
              rtf_reassembly_write_composed_hypothesis(
                  candidate, parent, gap_slot,
                  choices[choice_index].apparent, suffix, suffix_count,
                  skipped_suffix, trial_data, trial_length);

          if (!wrote_hypothesis) {
            continue;
          }
          hypotheses_written++;
          composed_hypotheses_written++;
        }
      }
    }

    if (verified_partial) {
      const uint64_t partial_blocks = verified_length
                                      / scalpel_state.blocksize;
      const uint64_t used_suffix_blocks = partial_blocks - gap_slot - 1;
      bool duplicates_suffix = used_suffix_blocks > suffix_count;

      for (uint64_t slot = 0;
           !duplicates_suffix && slot < used_suffix_blocks; slot++) {
        if (suffix[slot] == choices[choice_index].apparent) {
          duplicates_suffix = true;
          break;
        }
      }
      if (!duplicates_suffix) {
        const bool better_partial = best_partial_apparent < 0
            || partial_blocks > best_partial_blocks
            || (partial_blocks == best_partial_blocks
                && integrity_progress && !best_partial_integrity)
            || (partial_blocks == best_partial_blocks
                && integrity_progress == best_partial_integrity
                && rtf_reassembly_choice_better(
                       &choices[choice_index], &best_partial_choice,
                       RTF_REASSEMBLY_RANK_LEXICAL));

        if (better_partial) {
          best_partial_apparent = choices[choice_index].apparent;
          best_partial_blocks = partial_blocks;
          best_partial_suffix_blocks = used_suffix_blocks;
          best_partial_integrity = integrity_progress;
          best_partial_choice = choices[choice_index];
        }
      }
    }

    const bool acceptable_hypothesis = choices[choice_index].terminal_only
        ? trial_validates && trial_validates_to + 1 > prefix_length
        : trial_validates
              && trial_validates_to + 1
                     > prefix_length + scalpel_state.blocksize;

    if (acceptable_hypothesis) {
      const uint64_t hypothesis_blocks = CEILDIV(
          trial_validates_to + 1, scalpel_state.blocksize);

      if (hypothesis_blocks > longest_complete_blocks) {
        longest_complete_blocks = hypothesis_blocks;
      }
      const uint64_t used_suffix_blocks = hypothesis_blocks > gap_slot + 1
          ? hypothesis_blocks - gap_slot - 1 : 0;
      bool duplicates_suffix = false;
      bool clean_terminal_padding = !choices[choice_index].terminal_only;
      uint64_t terminal_padding_end =
          (trial_validates_to / scalpel_state.blocksize + 1)
          * (uint64_t)scalpel_state.blocksize;

      if (terminal_padding_end > choice_trial_length) {
        terminal_padding_end = choice_trial_length;
      }
      for (uint64_t offset = trial_validates_to + 1;
           clean_terminal_padding && offset < terminal_padding_end;
           offset++) {
        const uint8_t value = trial_data[offset];

        clean_terminal_padding = value == 0 || value == ' '
                                 || value == '\t' || value == '\r'
                                 || value == '\n';
      }

      // The physical suffix may continue past the logical end of the RTF and
      // contain the displaced block. Exclude it only when the validated
      // hypothesis actually consumes that occurrence from the suffix.
      for (uint64_t slot = 0; slot < used_suffix_blocks; slot++) {
        if (suffix[slot] == choices[choice_index].apparent) {
          duplicates_suffix = true;
          break;
        }
      }

      if (!duplicates_suffix
          && hypothesis_blocks <= gap_slot + 1 + suffix_count) {
        BlockVector *hypothesis = NULL;

        clone_blockvector(parent, &hypothesis, false);
        deflate_blockvector(hypothesis);
        resize_blockvector(hypothesis, hypothesis_blocks);
        for (uint64_t slot = 0; slot < gap_slot; slot++) {
          blockvector_set_apparent_blocknumber(
              hypothesis, slot,
              blockvector_get_apparent_blocknumber(parent, slot));
        }
        blockvector_set_apparent_blocknumber(
            hypothesis, gap_slot, choices[choice_index].apparent);
        for (uint64_t slot = gap_slot + 1;
             slot < hypothesis_blocks; slot++) {
          blockvector_set_apparent_blocknumber(
              hypothesis, slot, suffix[slot - gap_slot - 1]);
        }
        inflate_blockvector(hypothesis);
        blockvector_set_data_length(hypothesis, trial_validates_to + 1);

        const CarveInfoFlavor saved_flavor = (*candidate)->flavor;
        const uint64_t saved_validates_to = (*candidate)->best_validates_to;

        (*candidate)->b = hypothesis;
        (*candidate)->flavor = PROMISING;
        (*candidate)->best_validates_to = trial_validates_to;
        rtf_write_terminal_extent_alternative(
            candidate, trial_validates_to + 1);
        write_candidate(candidate, true);
        (*candidate)->b = parent;
        (*candidate)->flavor = saved_flavor;
        (*candidate)->best_validates_to = saved_validates_to;
        free_blockvector(&hypothesis);
        hypotheses_written++;
        if (clean_terminal_padding) {
          clean_terminal_hypotheses++;
        }
        if (hypotheses_written >= preserved_hypothesis_limit) {
          break;
        }
      }
    }

    progress->choice_index = choice_index + 1;
    progress->written = hypotheses_written;
    progress->composed = composed_hypotheses_written;
    progress->clean_terminal = clean_terminal_hypotheses;
    progress->longest_complete = longest_complete_blocks;
    progress->best_partial = best_partial_apparent;
    progress->partial_blocks = best_partial_blocks;
    progress->partial_suffix_blocks = best_partial_suffix_blocks;
    progress->partial_integrity = best_partial_integrity;
    progress->partial_choice = best_partial_choice;
    if (((choice_index + 1) % 8) == 0) {
      if (reassembly_check_kill_queue(work, candidate, uuidp, uuidc)) {
        free(trial_data);
        free(suffix);
        return true;
      }
      if (atomic_load_explicit(&REASS_RETURN_TO_IDLE,
                               memory_order_acquire)) {
        state->progress.phase = RTF_SEARCH_TRIAL;
        rtf_search_save(*candidate, state);
        if (reassembly_time_to_checkpoint(work->id, *candidate, uuidp, uuidc)) {
          free(trial_data);
          free(suffix);
          return true;
        }
      }
    }
  }
  if (scalpel_state.mode_verbose) {
    lock_fprintf(
        stdout,
        "RTF displaced-block search: header=%" PRId64
        " gap slot=%" PRIu64 " right=%" PRId64
        " suffix blocks=%" PRIu64 " ranked=%" PRIu64
        " preserved=%" PRIu64 ".\n",
        blockvector_get_actual_blocknumber(parent, 0), gap_slot,
        right_actual, suffix_count, choice_count, hypotheses_written);
  }
  if (state->progress.phase != RTF_SEARCH_PARTIAL
      && extended && !(*candidate)->clone && best_partial_apparent >= 0
      && (best_partial_integrity
          || best_partial_blocks > longest_complete_blocks)) {
    BlockVector *partial = NULL;

    clone_blockvector(parent, &partial, false);
    deflate_blockvector(partial);
    resize_blockvector(partial, best_partial_blocks);
    blockvector_set_apparent_blocknumber(
        partial, gap_slot, best_partial_apparent);
    for (uint64_t slot = 0; slot < best_partial_suffix_blocks; slot++) {
      blockvector_set_apparent_blocknumber(partial, gap_slot + 1 + slot,
                                           suffix[slot]);
    }
    inflate_blockvector(partial);
    blockvector_set_data_length(
        partial, best_partial_blocks * (uint64_t)scalpel_state.blocksize);
    state->progress.phase = RTF_SEARCH_PARTIAL;
    // The child can checkpoint independently; do not launch it again when the
    // parent resumes. Preserve the parent's completed hypothesis accounting.
    progress->written = hypotheses_written;
    progress->composed = composed_hypotheses_written;
    progress->clean_terminal = clean_terminal_hypotheses;
    progress->longest_complete = longest_complete_blocks;
    rtf_search_save(*candidate, state);
    if (rtf_reassembly_explore_partial(
            work, candidate, partial, uuidp, uuidc)) {
      free(trial_data);
      free(suffix);
      return true;
    }
  }
  if (clean_terminal_hypotheses != 0) {
    if (!extended) {
      free(trial_data);
      free(suffix);
      return false;
    }
    free(trial_data);
    free(suffix);
    destroy_candidate(candidate);
    return true;
  }
  if (direct_hypothesis_written) {
    free(trial_data);
    free(suffix);
    destroy_candidate(candidate);
    return true;
  }
  if (extended && direct_fallback_blocks > gap_slot
      && direct_fallback_blocks <= gap_slot + suffix_count) {
    deflate_blockvector(parent);
    resize_blockvector(parent, direct_fallback_blocks);
    for (uint64_t slot = 0;
         slot < direct_fallback_blocks - gap_slot; slot++) {
      blockvector_set_apparent_blocknumber(parent, gap_slot + slot,
                                           suffix[slot]);
    }
    inflate_blockvector(parent);
    blockvector_set_data_length(parent, direct_fallback_length);
    *extended = true;
    free(trial_data);
    free(suffix);
    return false;
  }
  if (hypotheses_written != 0) {
    if (!extended) {
      free(trial_data);
      free(suffix);
      return false;
    }
    free(trial_data);
    free(suffix);
    destroy_candidate(candidate);
    return true;
  }
  free(trial_data);
  free(suffix);
  return false;
}

// Extend RTF candidates with blocks that preserve the complete parsed prefix.
// Locality, lexical continuity, classifier confidence, and reservations rank
// structurally equivalent continuations. Reconstructed files remain PROMISING
// because RTF carries no file-wide integrity value that proves block order.
//
static inline void rtf_reassembly(ThreadWork *work,
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
  bool following_relocated_run = !rtf_candidate_is_contiguous(*candidate);
  RtfCarveState *resume = rtf_search_load(*candidate);
  if (resume) {
    following_relocated_run = resume->progress.following_relocated_run;
    rtf_free_carve_state((void **)&resume);
  }

  while (*candidate) {
    BlockVector *blockvector = (*candidate)->b;
    uint64_t block_count = blockvector_get_num_blocks(blockvector);

    if (block_count == 0
        || blockvector_get_actual_blocknumber(blockvector, 0) < 0) {
      destroy_candidate(candidate);
      return;
    }
    for (uint64_t slot = 1; slot < block_count; slot++) {
      if (blockvector_get_actual_blocknumber(blockvector, slot) < 0) {
        resize_blockvector(blockvector, slot);
        blockvector_set_data_length(
            blockvector, slot * (uint64_t)scalpel_state.blocksize);
        inflate_blockvector(blockvector);
        block_count = slot;
        break;
      }
    }

    bool current_validates = false;
    bool current_promising = false;
    uint64_t current_validates_to = 0;
    RtfValidationSummary current_summary = {0};

    rtf_file_validate_core(blockvector_get_data_pointer(blockvector),
                           blockvector_get_data_length(blockvector),
                           &current_validates, &current_validates_to,
                           &current_promising, (*candidate)->needleidx,
                           scalpel_state.blocksize,
                           (*candidate)->carvehashkey, &current_summary);

    if (current_validates) {
      blockvector_set_data_length(blockvector, current_validates_to + 1);
      resize_blockvector(blockvector,
                         CEILDIV(current_validates_to + 1,
                                 scalpel_state.blocksize));
      const uint64_t completed_blocks = blockvector_get_num_blocks(
          blockvector);
      const uint8_t *completed_data = (const uint8_t *)
          blockvector_get_data_pointer(blockvector);
      bool repaired_discontinuity = false;

      for (uint64_t gap_slot = 1;
           completed_data && gap_slot + 1 < completed_blocks; gap_slot++) {
        const int64_t left_actual = blockvector_get_actual_blocknumber(
            blockvector, gap_slot - 1);
        const int64_t suspect_actual = blockvector_get_actual_blocknumber(
            blockvector, gap_slot);
        const int64_t right_actual = blockvector_get_actual_blocknumber(
            blockvector, gap_slot + 1);
        const uint64_t boundary = gap_slot
                                  * (uint64_t)scalpel_state.blocksize;
        const uint64_t lookahead = (gap_slot + 1)
                                   * (uint64_t)scalpel_state.blocksize;
        const uint64_t lookahead_length = current_validates_to + 1
                                          - lookahead;

        // Only an isolated noncontiguous block can be a stale speculative
        // choice. Preserve ordinary physical runs and relocated runs.
        if (left_actual >= 0 && suspect_actual >= 0 && right_actual >= 0
            && suspect_actual != left_actual + 1
            && right_actual != suspect_actual + 1
            && rtf_reassembly_boundary_cost(
                completed_data, boundary, completed_data + boundary,
                scalpel_state.blocksize) > RTF_REASSEMBLY_SEAM_BYTES
            && rtf_reassembly_boundary_cost(
                   completed_data, boundary, completed_data + lookahead,
                   lookahead_length) <= RTF_REASSEMBLY_SEAM_BYTES) {
          deflate_blockvector(blockvector);
          for (uint64_t slot = gap_slot;
               slot + 1 < completed_blocks; slot++) {
            blockvector_set_apparent_blocknumber(
                blockvector, slot,
                blockvector_get_apparent_blocknumber(blockvector,
                                                      slot + 1));
          }
          resize_blockvector(blockvector, completed_blocks - 1);
          inflate_blockvector(blockvector);
          blockvector_set_data_length(
              blockvector, current_validates_to + 1
                           - scalpel_state.blocksize);
          repaired_discontinuity = true;
          following_relocated_run = true;
          break;
        }
      }
      if (repaired_discontinuity) {
        continue;
      }

      if (!scalpel_state.write_promising) {
        destroy_candidate(candidate);
        return;
      }
      (*candidate)->flavor = PROMISING;
      rtf_write_terminal_extent_alternative(
          candidate, current_validates_to + 1);
      write_candidate(candidate, true);

      for (uint64_t gap_slot = 1; gap_slot < completed_blocks; gap_slot++) {
        const int64_t left_actual = blockvector_get_actual_blocknumber(
            blockvector, gap_slot - 1);
        const int64_t right_actual = blockvector_get_actual_blocknumber(
            blockvector, gap_slot);

        if (left_actual >= 0 && right_actual >= 0
            && left_actual + 1 != right_actual) {
          if (rtf_reassembly_write_inserted_hypotheses(
                  work, candidate, gap_slot, NULL, following_relocated_run, uuidp, uuidc)) {
            return;
          }
        }
      }
      destroy_candidate(candidate);
      return;
    }

    uint64_t keep_blocks = current_promising
        ? (current_validates_to + 1) / scalpel_state.blocksize
        : CEILDIV(current_validates_to + 1, scalpel_state.blocksize);

    if (keep_blocks == 0) {
      keep_blocks = 1;
    }
    if (keep_blocks < block_count) {
      following_relocated_run = false;
      resize_blockvector(blockvector, keep_blocks);
      block_count = keep_blocks;
      blockvector_set_data_length(
          blockvector, block_count * (uint64_t)scalpel_state.blocksize);
      inflate_blockvector(blockvector);

      current_summary = (RtfValidationSummary){0};
      rtf_file_validate_core(blockvector_get_data_pointer(blockvector),
                             blockvector_get_data_length(blockvector),
                             &current_validates, &current_validates_to,
                             &current_promising, (*candidate)->needleidx,
                             scalpel_state.blocksize,
                             (*candidate)->carvehashkey, &current_summary);
      if (current_validates) {
        continue;
      }
      if (!current_promising) {
        break;
      }
    }
    else if (!current_promising) {
      break;
    }

    if (reassembly_check_max_size(work->id, *candidate, uuidp, uuidc)) {
      break;
    }

    const uint64_t trial_slot = block_count;
    resume = rtf_search_load(*candidate);
    const bool resumed_internal_search = resume
        && resume->block_scan_exhausted;
    rtf_free_carve_state((void **)&resume);
    const int64_t previous_actual = blockvector_get_actual_blocknumber(
        blockvector, trial_slot - 1);
    const uint64_t actual_blocks = CEILDIV(
        filemirror_filesize(scalpel_state.filemirror),
        scalpel_state.blocksize);
    bool adjacent_rejected = false;
    bool candidate_advanced = false;

    if (!resumed_internal_search && previous_actual >= 0
        && previous_actual < INT64_MAX
        && (uint64_t)(previous_actual + 1) < actual_blocks) {
      const int64_t adjacent_actual = previous_actual + 1;
      const int64_t adjacent_apparent = filemirror_apparent_blocknumber(
          scalpel_state.filemirror, adjacent_actual);
      uint64_t adjacent_length = 0;
      const uint8_t *adjacent_data = (const uint8_t *)
          filemirror_actual_block_data_pointer(scalpel_state.filemirror,
                                               adjacent_actual,
                                               &adjacent_length);
      bool adjacent_is_gap = false;

      if (adjacent_data && adjacent_length != 0
          && adjacent_actual < INT64_MAX
          && (uint64_t)(adjacent_actual + 1) < actual_blocks) {
        const uint8_t *prefix_data = (const uint8_t *)
            blockvector_get_data_pointer(blockvector);
        const uint64_t prefix_length = blockvector_get_data_length(
            blockvector);
        const uint64_t adjacent_cost = rtf_reassembly_boundary_cost(
            prefix_data, prefix_length, adjacent_data, adjacent_length);
        const int64_t lookahead_actual = adjacent_actual + 1;
        uint64_t lookahead_length = 0;
        const uint8_t *lookahead_data = (const uint8_t *)
            filemirror_actual_block_data_pointer(
                scalpel_state.filemirror, lookahead_actual,
                &lookahead_length);
        const bool hexadecimal_context =
            rtf_reassembly_hex_window(prefix_data, prefix_length, true)
            && rtf_reassembly_hex_window(adjacent_data, adjacent_length,
                                         false)
            && rtf_reassembly_hex_window(lookahead_data, lookahead_length,
                                         false);

        if (!hexadecimal_context
            && adjacent_cost > RTF_REASSEMBLY_SEAM_BYTES
            && lookahead_data && lookahead_length != 0
            && !filemirror_actual_block_covered(
                   scalpel_state.filemirror, lookahead_actual)
            && rtf_reassembly_boundary_cost(
                   prefix_data, prefix_length, lookahead_data,
                   lookahead_length) <= RTF_REASSEMBLY_SEAM_BYTES) {
          adjacent_is_gap = true;
        }
      }

      if (adjacent_apparent >= 0 && adjacent_data && adjacent_length != 0
          && !filemirror_actual_block_covered(scalpel_state.filemirror,
                                              adjacent_actual)
          && !apparent_block_in_blockvector(blockvector,
                                            adjacent_apparent)
          && !(adjacent_length >= 5
               && memcmp(adjacent_data, "{\\rtf", 5) == 0)) {
        resize_blockvector(blockvector, trial_slot + 1);
        blockvector_set_apparent_blocknumber(blockvector, trial_slot,
                                             adjacent_apparent);
        const uint64_t old_length = inflate_blockvector_single_block(
            blockvector, trial_slot);
        bool adjacent_validates = false;
        bool adjacent_promising = false;
        uint64_t adjacent_validates_to = 0;

        rtf_file_validate(blockvector_get_data_pointer(blockvector),
                          blockvector_get_data_length(blockvector),
                          &adjacent_validates, &adjacent_validates_to,
                          &adjacent_promising, (*candidate)->needleidx,
                          scalpel_state.blocksize,
                          (*candidate)->carvehashkey);
        const bool consumes_adjacent = !adjacent_is_gap
            && (adjacent_validates
                || (adjacent_promising
                    && adjacent_validates_to + 1
                           == blockvector_get_data_length(blockvector)));

        if (consumes_adjacent) {
          if (adjacent_validates) {
            blockvector_set_data_length(blockvector,
                                        adjacent_validates_to + 1);
          }
          continue;
        }

        deflate_blockvector_single_block(blockvector, trial_slot, old_length);
        resize_blockvector(blockvector, trial_slot);
        blockvector_set_data_length(
            blockvector, trial_slot * (uint64_t)scalpel_state.blocksize);
        adjacent_rejected = true;
      }
    }

    if (!resumed_internal_search && rtf_reassembly_write_inserted_hypotheses(
            work, candidate, trial_slot, &candidate_advanced,
            following_relocated_run, uuidp, uuidc)) {
      return;
    }
    if (candidate_advanced) {
      following_relocated_run = true;
      continue;
    }

    if (!resumed_internal_search && adjacent_rejected && trial_slot > 1) {
      const uint8_t *stalled_data = (const uint8_t *)
          blockvector_get_data_pointer(blockvector);
      uint64_t repair_slot = 0;
      uint64_t repair_cost = 0;

      for (uint64_t gap_slot = 1; stalled_data && gap_slot < trial_slot;
           gap_slot++) {
        const uint64_t boundary = gap_slot
                                  * (uint64_t)scalpel_state.blocksize;
        const uint64_t cost = rtf_reassembly_boundary_cost(
            stalled_data, boundary, stalled_data + boundary,
            scalpel_state.blocksize);

        if (repair_slot == 0 || cost > repair_cost) {
          repair_slot = gap_slot;
          repair_cost = cost;
        }
      }

      if (repair_slot != 0
          && repair_cost > RTF_REASSEMBLY_SEAM_BYTES
          && rtf_reassembly_write_inserted_hypotheses(
                 work, candidate, repair_slot, &candidate_advanced,
                 following_relocated_run, uuidp, uuidc)) {
        return;
      }
      if (candidate_advanced) {
        following_relocated_run = true;
        continue;
      }
    }

    // Contiguous extension and bounded reconstruction have already been
    // attempted. Inside an unfinished encoded payload, generic block
    // selection would treat arbitrary hexadecimal data as useful progress.
    if (!resumed_internal_search && current_summary.active_deep_payload) {
      break;
    }

    const int64_t image_blocks = filemirror_apparent_blocks(
        scalpel_state.filemirror);
    int64_t best_apparent = -1;
    uint64_t best_seam_cost = UINT64_MAX;
    int64_t best_forward_distance = INT64_MAX;
    BlockValidationDecision best_confidence = BLOCK_CONFIDENCE_INVALID;
    int64_t best_reserved = INT64_MAX;
    bool best_complete = false;
    bool best_local_forward = false;
    uint64_t examined = 0;
    uint64_t next_apparent = resumed_internal_search
        ? (uint64_t)image_blocks : 0;
    resume = rtf_search_load(*candidate);
    const bool resumed_scan = resume && resume->progress.phase == RTF_SEARCH_BLOCK;
    if (resumed_scan) {
      next_apparent = resume->progress.next_apparent;
      best_apparent = resume->progress.best.apparent;
      best_seam_cost = resume->progress.best.bridge_cost;
      best_forward_distance = resume->progress.forward_distance;
      best_confidence = resume->progress.best.confidence;
      best_reserved = resume->progress.best.reserved;
      best_complete = resume->progress.complete;
      best_local_forward = resume->progress.local_forward;
    }
    rtf_free_carve_state((void **)&resume);

    resize_blockvector(blockvector, trial_slot + 1);
    blockvector_set_apparent_blocknumber(blockvector, trial_slot, -1);

    for (int64_t apparent = (int64_t)next_apparent; apparent < image_blocks; apparent++) {
      examined++;
      const int64_t actual = filemirror_actual_blocknumber(
          scalpel_state.filemirror, apparent);

      if (actual < 0
          || filemirror_actual_block_covered(scalpel_state.filemirror,
                                             actual)
          || apparent_block_in_blockvector(blockvector, apparent)) {
        goto rtf_reassembly_poll;
      }

      const BlockValidationDecision confidence = filemirror_get_blocktype(
          scalpel_state.filemirror, actual, (*candidate)->needleidx);

      if (confidence == BLOCK_CONFIDENCE_INVALID) {
        goto rtf_reassembly_poll;
      }
      uint64_t source_length = 0;
      const uint8_t *source = (const uint8_t *)
          filemirror_actual_block_data_pointer(scalpel_state.filemirror,
                                               actual, &source_length);

      if (source && source_length >= 5
          && memcmp(source, "{\\rtf", 5) == 0) {
        goto rtf_reassembly_poll;
      }

      const uint64_t seam_cost = rtf_reassembly_seam_cost(blockvector,
                                                           apparent);
      blockvector_set_apparent_blocknumber(blockvector, trial_slot,
                                            apparent);
      const uint64_t old_length = inflate_blockvector_single_block(
          blockvector, trial_slot);
      bool trial_validates = false;
      bool trial_promising = false;
      uint64_t trial_validates_to = 0;

      rtf_file_validate(blockvector_get_data_pointer(blockvector),
                        blockvector_get_data_length(blockvector),
                        &trial_validates, &trial_validates_to,
                        &trial_promising, (*candidate)->needleidx,
                        scalpel_state.blocksize, (*candidate)->carvehashkey);
      deflate_blockvector_single_block(blockvector, trial_slot, old_length);

      const bool complete = trial_validates;
      const bool consumes_block = trial_promising
          && trial_validates_to + 1
                 == (trial_slot + 1) * (uint64_t)scalpel_state.blocksize;

      if (!complete && !consumes_block) {
        goto rtf_reassembly_poll;
      }

      const int64_t forward_distance = actual > previous_actual
          ? actual - previous_actual : INT64_MAX;
      const bool local_forward = forward_distance
                                 <= RTF_REASSEMBLY_LOCAL_BLOCKS;
      const bool adjacent = forward_distance == 1;
      const int64_t reserved = scalpel_state.reservations
          ? filemirror_actual_block_reserved(scalpel_state.filemirror,
                                             actual) : 0;
      bool better;

      if (following_relocated_run && adjacent) {
        best_apparent = apparent;
        best_seam_cost = seam_cost;
        best_forward_distance = forward_distance;
        best_confidence = confidence;
        best_reserved = reserved;
        best_complete = complete;
        best_local_forward = true;
        break;
      }
      if (best_apparent < 0) {
        better = true;
      }
      else if (local_forward != best_local_forward) {
        better = local_forward;
      }
      else if (local_forward && confidence != best_confidence) {
        better = confidence > best_confidence;
      }
      else if (local_forward && forward_distance != best_forward_distance) {
        better = forward_distance < best_forward_distance;
      }
      else if (seam_cost != best_seam_cost) {
        better = seam_cost < best_seam_cost;
      }
      else if (confidence != best_confidence) {
        better = confidence > best_confidence;
      }
      else if (complete != best_complete) {
        better = complete;
      }
      else {
        better = reserved < best_reserved;
      }

      if (better) {
        best_apparent = apparent;
        best_seam_cost = seam_cost;
        best_forward_distance = forward_distance;
        best_confidence = confidence;
        best_reserved = reserved;
        best_complete = complete;
        best_local_forward = local_forward;
      }

rtf_reassembly_poll:
      if ((examined % RTF_REASSEMBLY_POLL_INTERVAL) == 0) {
        resize_blockvector(blockvector, trial_slot);
        blockvector_set_data_length(
            blockvector, trial_slot * (uint64_t)scalpel_state.blocksize);
        if (reassembly_check_kill_queue(work, candidate, uuidp, uuidc)) {
          return;
        }
        if (atomic_load_explicit(&REASS_RETURN_TO_IDLE,
                                 memory_order_acquire)) {
          RtfCarveState progress = {.progress = {
            .magic = RTF_SEARCH_MAGIC, .phase = RTF_SEARCH_BLOCK,
            .next_apparent = (uint64_t)apparent + 1,
            .following_relocated_run = following_relocated_run,
            .best = {.apparent = best_apparent, .bridge_cost = best_seam_cost,
                     .confidence = best_confidence, .reserved = best_reserved},
            .forward_distance = best_forward_distance, .complete = best_complete,
            .local_forward = best_local_forward
          }};
          rtf_search_save(*candidate, &progress);
          if (reassembly_time_to_checkpoint(work->id, *candidate, uuidp, uuidc)) {
            return;
          }
        }
        resize_blockvector(blockvector, trial_slot + 1);
        blockvector_set_apparent_blocknumber(blockvector, trial_slot, -1);
      }
    }

    if (resumed_scan) {
      RtfCarveState cleared = {.progress.magic = RTF_SEARCH_MAGIC};
      carve_put_state((*candidate)->carvehashkey, &cleared);
    }
    if (best_apparent < 0) {
      resize_blockvector(blockvector, trial_slot);
      blockvector_set_data_length(
          blockvector, trial_slot * (uint64_t)scalpel_state.blocksize);

      for (uint64_t gap_slot = 1; gap_slot < trial_slot; gap_slot++) {
        const int64_t left_actual = blockvector_get_actual_blocknumber(
            blockvector, gap_slot - 1);
        const int64_t right_actual = blockvector_get_actual_blocknumber(
            blockvector, gap_slot);

        if (left_actual >= 0 && right_actual >= 0
            && left_actual + 1 != right_actual) {
          if (rtf_reassembly_write_inserted_at_stage(
                  work, candidate, gap_slot, NULL, following_relocated_run,
                  uuidp, uuidc, true)) {
            return;
          }
        }
      }
      break;
    }

    blockvector_set_apparent_blocknumber(blockvector, trial_slot,
                                         best_apparent);
    inflate_blockvector_single_block(blockvector, trial_slot);
    blockvector_set_data_length(
        blockvector, (trial_slot + 1) * (uint64_t)scalpel_state.blocksize);
    const int64_t best_actual = filemirror_actual_blocknumber(
        scalpel_state.filemirror, best_apparent);

    if (best_actual != previous_actual + 1) {
      following_relocated_run = true;
    }
  }

  if (*candidate) {
    if (scalpel_state.write_promising) {
      (*candidate)->flavor = PROMISING;
      rtf_write_terminal_extent_alternative(
          candidate, blockvector_get_data_length((*candidate)->b));
      write_candidate(candidate, false);
    }
    else {
      destroy_candidate(candidate);
    }
  }
}

// Apparent positions are retained only with the exact candidate and map view
// that produced them. A changed view restarts ranking, not candidate recovery.
static inline RtfCarveState *rtf_search_load(CarveInfo *candidate) {
  RtfCarveState *state = carve_get_state(candidate->carvehashkey);
  if (state && (state->progress.magic != RTF_SEARCH_MAGIC
      || state->progress.phase == RTF_SEARCH_NONE
      || !XXH128_isEqual(state->progress.view, validator_search_view(candidate)))) {
    rtf_free_carve_state((void **)&state);
  }
  return state;
}

static inline void rtf_search_save(CarveInfo *candidate, RtfCarveState *state) {
  state->progress.view = validator_search_view(candidate);
  carve_put_state(candidate->carvehashkey, state);
}

static inline bool rtf_serialize_carve_state(void **state, FILE *fp, StateSerialization mode) {
  if (!state || !fp || (mode == SERIALIZE && !*state)) {
    return false;
  }
  if (mode == SERIALIZE) {
    const RtfCarveState *saved = *state;
    const bool insertion = saved->progress.phase >= RTF_SEARCH_RANK
        && saved->progress.phase <= RTF_SEARCH_PARTIAL;
    if (insertion != (saved->insertion != NULL)) {
      return false;
    }
    const uint32_t envelope[] = {
      RTF_STATE_ENVELOPE_MAGIC, saved->block_scan_exhausted ? 1 : 0
    };
    return (!saved->block_scan_exhausted || insertion)
        && fwrite(envelope, sizeof(envelope), 1, fp) == 1
        && fwrite(&saved->progress, sizeof(saved->progress), 1, fp) == 1
        && (!saved->insertion || fwrite(saved->insertion, sizeof(*saved->insertion), 1, fp) == 1);
  }
  RtfCarveState *saved = calloc(1, sizeof(*saved));
  check_memory_allocation(saved, __LINE__, __FILE__, "RTF restored search");
  RtfSearchProgress *p = &saved->progress;
  uint32_t marker = 0;
  bool read_ok = fread(&marker, sizeof(marker), 1, fp) == 1;
  if (read_ok && marker == RTF_STATE_ENVELOPE_MAGIC) {
    uint32_t exhausted = 0;
    read_ok = fread(&exhausted, sizeof(exhausted), 1, fp) == 1
        && exhausted <= 1 && fread(p, sizeof(*p), 1, fp) == 1;
    saved->block_scan_exhausted = exhausted != 0;
  }
  else if (read_ok && marker == RTF_SEARCH_MAGIC) {
    p->magic = marker;
    read_ok = fread((uint8_t *)p + sizeof(marker),
                    sizeof(*p) - sizeof(marker), 1, fp) == 1;
  }
  else {
    read_ok = false;
  }
  if (!read_ok || p->magic != RTF_SEARCH_MAGIC
      || (unsigned)p->phase > RTF_SEARCH_BLOCK || p->next_apparent > INT64_MAX
      || p->gap_slot > INT64_MAX || p->best.apparent < -1
      || (saved->block_scan_exhausted
          && (p->phase < RTF_SEARCH_RANK || p->phase > RTF_SEARCH_PARTIAL))) {
    free(saved);
    return false;
  }
  if (p->phase >= RTF_SEARCH_RANK && p->phase <= RTF_SEARCH_PARTIAL) {
    saved->insertion = malloc(sizeof(*saved->insertion));
    check_memory_allocation(saved->insertion, __LINE__, __FILE__, "RTF restored rankings");
    if (fread(saved->insertion, sizeof(*saved->insertion), 1, fp) != 1) {
      rtf_free_carve_state((void **)&saved);
      return false;
    }
    for (size_t i = 0; i < 6; i++) {
      if (saved->insertion->counts[i] > RTF_REASSEMBLY_EMBEDDED_HYPOTHESIS_LIMIT) {
        rtf_free_carve_state((void **)&saved);
        return false;
      }
      for (uint64_t j = 0; j < saved->insertion->counts[i]; j++) {
        if (saved->insertion->ranks[i][j].apparent < 0) {
          rtf_free_carve_state((void **)&saved);
          return false;
        }
      }
    }
    if (saved->insertion->choice_index > 6 * RTF_REASSEMBLY_EMBEDDED_HYPOTHESIS_LIMIT) {
      rtf_free_carve_state((void **)&saved);
      return false;
    }
  }
  *state = saved;
  return true;
}

static inline void *rtf_clone_carve_state(const void *state) {
  if (!state) {
    return NULL;
  }
  const RtfCarveState *saved = state;
  RtfCarveState *copy = malloc(sizeof(*copy));
  check_memory_allocation(copy, __LINE__, __FILE__, "RTF search clone");
  *copy = *saved;
  if (saved->insertion) {
    copy->insertion = malloc(sizeof(*copy->insertion));
    check_memory_allocation(copy->insertion, __LINE__, __FILE__, "RTF ranking clone");
    memcpy(copy->insertion, saved->insertion, sizeof(*copy->insertion));
  }
  return copy;
}

static inline void rtf_free_carve_state(void **state) {
  if (state && *state) {
    RtfCarveState *saved = *state;
    free(saved->insertion);
    free(saved);
    *state = NULL;
  }
}

static inline size_t rtf_sizeof_carve_state(const void *state) {
  const RtfCarveState *saved = state;
  return saved ? sizeof(*saved) + (saved->insertion ? sizeof(*saved->insertion) : 0) : 0;
}

static inline void rtf_print_carve_state(const void *state) {
  const RtfCarveState *saved = state;
  if (saved) {
    printf("RTF search phase=%u next=%" PRIu64 " gap=%" PRIu64 "\n",
           (unsigned)saved->progress.phase, saved->progress.next_apparent, saved->progress.gap_slot);
  }
}

#endif
