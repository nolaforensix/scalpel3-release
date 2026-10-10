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

// ISO Base Media File Format and QuickTime validation. Top-level box geometry
// gives an exact logical extent, while movie sample tables independently map
// media samples into one or more mdat boxes. The same implementation serves
// both MP4-family files and QuickTime MOV files.

#ifndef SCALPEL3_MOV_H
#define SCALPEL3_MOV_H

#include "scalpel.h"

#include <inttypes.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>

#define ISOBMFF_FOURCC(a, b, c, d)                                           \
  (((uint32_t)(uint8_t)(a) << 24) | ((uint32_t)(uint8_t)(b) << 16)           \
   | ((uint32_t)(uint8_t)(c) << 8) | (uint32_t)(uint8_t)(d))

#define ISOBMFF_MINIMUM_SIZE UINT64_C(16)
#define ISOBMFF_MAXIMUM_SIZE UINT64_C(1099511627776)
#define ISOBMFF_MAX_TRACKS 64U
#define ISOBMFF_MAX_MDAT_RANGES 256U
#define ISOBMFF_MAX_BOX_DEPTH 24U
#define ISOBMFF_MAX_TABLE_ENTRIES UINT64_C(100000000)
#define ISOBMFF_MAX_METADATA_SIZE UINT64_C(1073741824)
#define ISOBMFF_PAYLOAD_CONFIDENCE_MAX 99
#define ISOBMFF_CARVE_STATE_MAGIC UINT32_C(0x49534f42)
#define ISOBMFF_CARVE_STATE_VERSION 16U
#define ISOBMFF_REASSEMBLY_POLL_INTERVAL UINT64_C(256)
#define ISOBMFF_NO_MIDDLE_DELTA INT64_MIN
#define ISOBMFF_MAX_STORED_SOLUTIONS 32U
#define ISOBMFF_PROMISING_OUTPUT_BUDGET UINT64_C(536870912)

enum {
  ISOBMFF_STAGE_PAIR_FOOTER = 1,
  ISOBMFF_STAGE_SCORE_TWO_RUN = 2,
  ISOBMFF_STAGE_EVALUATE_TWO_RUN = 3,
  ISOBMFF_STAGE_SCORE_MIDDLE_RUN = 4,
  ISOBMFF_STAGE_EVALUATE_MIDDLE_RUN = 5,
  ISOBMFF_STAGE_FINISHED = 6,
  ISOBMFF_STAGE_FAST_SCORE_SUFFIX = 7,
  ISOBMFF_STAGE_FAST_FIND_SUFFIX = 8,
  ISOBMFF_STAGE_FAST_SCORE_SPLIT = 9,
  ISOBMFF_STAGE_FAST_EVALUATE_SPLIT = 10,
  ISOBMFF_STAGE_TGA_SCAN = 11,
  ISOBMFF_STAGE_TGA_MIDDLE_RUN = 12
};

typedef enum IsoBmffKind {
  ISOBMFF_KIND_UNKNOWN = 0,
  ISOBMFF_KIND_MOV = 1,
  ISOBMFF_KIND_MP4 = 2
} IsoBmffKind;

typedef enum IsoBmffParseResult {
  ISOBMFF_PARSE_INVALID = 0,
  ISOBMFF_PARSE_PARTIAL = 1,
  ISOBMFF_PARSE_COMPLETE = 2
} IsoBmffParseResult;

typedef struct IsoBmffBox {
  uint64_t offset;
  uint64_t size;
  uint64_t header_size;
  uint32_t type;
  bool extends_to_end;
} IsoBmffBox;

typedef struct IsoBmffRange {
  uint64_t start;
  uint64_t end;
} IsoBmffRange;

typedef struct IsoBmffStscEntry {
  uint32_t first_chunk;
  uint32_t samples_per_chunk;
  uint32_t description_index;
} IsoBmffStscEntry;

typedef struct IsoBmffAlacConfig {
  uint32_t max_samples_per_frame;
  uint8_t sample_size;
  uint8_t history_mult;
  uint8_t initial_history;
  uint8_t rice_limit;
  uint8_t channels;
  bool valid;
} IsoBmffAlacConfig;

typedef struct IsoBmffBitReader {
  const uint8_t *data;
  uint64_t length;
  uint64_t bit_position;
} IsoBmffBitReader;

typedef struct IsoBmffTrack {
  uint64_t *chunk_offsets;
  uint32_t *sample_sizes;
  IsoBmffStscEntry *sample_to_chunk;
  uint64_t chunk_count;
  uint64_t sample_count;
  uint64_t sample_to_chunk_count;
  uint64_t mapped_samples;
  uint64_t strong_samples;
  uint64_t invalid_strong_samples;
  uint32_t handler;
  uint32_t codec;
  uint32_t default_sample_size;
  uint8_t nal_length_size;
  IsoBmffAlacConfig alac;
  bool saw_track_header;
  bool saw_media_header;
  bool saw_handler;
  bool saw_sample_description;
  bool saw_time_to_sample;
} IsoBmffTrack;

typedef struct IsoBmffLayout {
  IsoBmffTrack tracks[ISOBMFF_MAX_TRACKS];
  IsoBmffRange mdat_ranges[ISOBMFF_MAX_MDAT_RANGES];
  uint64_t parsed_extent;
  uint64_t required_extent;
  uint64_t failure_offset;
  uint64_t moov_offset;
  uint64_t moov_size;
  uint64_t first_mdat_offset;
  uint64_t strong_samples;
  uint64_t invalid_strong_samples;
  uint32_t major_brand;
  uint32_t top_level_boxes;
  uint32_t track_count;
  uint32_t mdat_count;
  bool saw_ftyp;
  bool saw_moov;
  bool saw_mvhd;
  bool saw_fragment;
  bool terminal_size;
  bool metadata_valid;
} IsoBmffLayout;

typedef struct IsoBmffTgaRleState {
  uint64_t bytes_seen;
  uint64_t pixel_offset;
  uint64_t skip_remaining;
  uint64_t pixels_total;
  uint64_t pixels_decoded;
  uint64_t column;
  uint64_t payload_remaining;
  uint64_t failure_offset;
  uint32_t width;
  uint8_t pixel_bytes;
  uint8_t tail[26];
  uint8_t tail_length;
  bool initialized;
  bool invalid;
} IsoBmffTgaRleState;

typedef struct IsoBmffSolution {
  uint64_t footer_offset;
  uint64_t base_split;
  uint64_t first_split;
  uint64_t second_split;
  int64_t middle_delta;
} IsoBmffSolution;

typedef struct IsoBmffStoredSolution {
  IsoBmffSolution mapping;
  uint64_t extent;
  int64_t prefix_delta;
  int64_t suffix_delta;
} IsoBmffStoredSolution;

typedef struct IsoBmffCarveState {
  uint32_t magic;
  uint32_t version;
  uint64_t expected_moov_offset;
  uint64_t archive_extent;
  uint64_t mdat_start;
  uint64_t mdat_end;
  // Physical footer offsets remain stable when checkpoint pruning compacts the table.
  uint64_t footer_cursor;
  uint64_t active_footer;
  uint64_t preferred_footer;
  uint64_t split_cursor;
  uint64_t event_cursor;
  uint64_t current_score;
  uint64_t best_first_split;
  uint64_t best_last_split;
  uint64_t best_score;
  uint64_t base_first_split;
  uint64_t base_last_split;
  uint64_t base_split_cursor;
  uint64_t active_base_split;
  uint64_t anchor_count;
  uint64_t suffix_actual_cursor;
  uint64_t suffix_split_last;
  uint64_t solution_count_before_suffix;
  uint64_t middle_actual_cursor;
  uint64_t middle_first_cursor;
  uint64_t middle_second_cursor;
  uint64_t best_middle_score;
  IsoBmffStoredSolution solutions[ISOBMFF_MAX_STORED_SOLUTIONS];
  int64_t active_suffix_delta;
  uint64_t solution_count;
  uint64_t ambiguous_prefix_blocks;
  uint64_t repairs;
  uint64_t tga_sample_ordinal;
  uint64_t tga_sample_offset;
  uint64_t tga_sample_size;
  uint64_t tga_data_first_split;
  IsoBmffTgaRleState tga;
  uint32_t stage;
  uint32_t kind;
  uint32_t stored_solution_count;
  bool metadata_repair;
  bool metadata_payload_repair;
  bool resume_metadata_base_scan;
  bool fast_context;
  bool resume_suffix_after_tga;
  bool preferred_footer_tried;
} IsoBmffCarveState;

typedef struct IsoBmffAnchorEvent {
  uint64_t logical_block;
  uint32_t prefix_good;
  uint32_t suffix_good;
  uint32_t samples;
} IsoBmffAnchorEvent;

typedef struct IsoBmffAnchor {
  uint64_t logical_offset;
  uint64_t sample_size;
  uint32_t codec;
  uint8_t nal_length_size;
  IsoBmffAlacConfig alac;
} IsoBmffAnchor;

typedef struct IsoBmffFooterContext {
  IsoBmffLayout layout;
  IsoBmffAnchor *anchors;
  IsoBmffAnchorEvent *events;
  uint8_t *moov_data;
  uint64_t anchor_count;
  uint64_t event_count;
  uint64_t moov_actual;
  uint64_t moov_size;
  uint64_t extent;
  uint64_t logical_blocks;
  uint64_t maximum_split;
  int64_t prefix_delta;
  int64_t suffix_delta;
  bool metadata_repair;
} IsoBmffFooterContext;

static inline char *mov_header_discovery(
    char *base, uint64_t offset, uint64_t remaining, char **matchpos,
    uint32_t *matchlen, uint32_t blocksize);
static inline char *mp4_header_discovery(
    char *base, uint64_t offset, uint64_t remaining, char **matchpos,
    uint32_t *matchlen, uint32_t blocksize);
static inline char *isobmff_footer_discovery(
    char *base, uint64_t offset, uint64_t remaining, char **matchpos,
    uint32_t *matchlen, uint32_t blocksize);
static inline uint32_t isobmff_block_validate(
    char *data, uint64_t length, BlockValidationDecision *decision,
    uint64_t *validates_to, uint32_t needleidx, uint32_t blocksize,
    void *blockhashkey);
static inline void mov_file_validate(
    char *data, uint64_t length, bool *validates, uint64_t *validates_to,
    bool *promising, uint32_t needleidx, uint32_t blocksize,
    void *carvehashkey);
static inline void mp4_file_validate(
    char *data, uint64_t length, bool *validates, uint64_t *validates_to,
    bool *promising, uint32_t needleidx, uint32_t blocksize,
    void *carvehashkey);
static inline void isobmff_candidate_validate(
    CarveInfo *candidate, bool *validates, uint64_t *validates_to,
    bool *promising);
static inline bool isobmff_serialize_carve_state(
    void **state, FILE *fp, StateSerialization mode);
static inline void *isobmff_clone_carve_state(const void *srcstate);
static inline void isobmff_free_carve_state(void **state);
static inline size_t isobmff_sizeof_carve_state(const void *state);
static inline void isobmff_print_carve_state(const void *state);
static inline void isobmff_reassembly(
    ThreadWork *work, CarveInfo **candidate, uuid_string_t uuidp,
    uuid_string_t uuidc);
static inline void isobmff_finish_active_context(
    IsoBmffCarveState *state);
static inline void isobmff_finish_footer(IsoBmffCarveState *state);
static inline bool isobmff_fast_stage(uint32_t stage);
static inline uint64_t isobmff_footer_at_or_after(
    const SearchSpec *spec, uint64_t offset);
static inline uint64_t isobmff_footer_index(
    const SearchSpec *spec, uint64_t offset);
static inline uint64_t isobmff_next_footer(
    const SearchSpec *spec, IsoBmffCarveState *state);
static inline void isobmff_advance_middle_cursor(
    IsoBmffCarveState *state, uint64_t next_second);


static inline uint16_t isobmff_read_be16(const uint8_t *data) {

  return ((uint16_t)data[0] << 8) | (uint16_t)data[1];
}


static inline uint16_t isobmff_read_le16(const uint8_t *data) {

  return (uint16_t)data[0] | ((uint16_t)data[1] << 8);
}


static inline uint32_t isobmff_read_be32(const uint8_t *data) {

  return ((uint32_t)data[0] << 24) | ((uint32_t)data[1] << 16)
      | ((uint32_t)data[2] << 8) | (uint32_t)data[3];
}


static inline uint64_t isobmff_read_be64(const uint8_t *data) {

  return ((uint64_t)isobmff_read_be32(data) << 32)
      | (uint64_t)isobmff_read_be32(data + 4);
}


static inline bool isobmff_bits_read(IsoBmffBitReader *reader,
                                     uint32_t count, uint32_t *value) {

  if (!reader || !reader->data || !value || count > 32
      || reader->length > UINT64_MAX / 8) {
    return false;
  }
  uint64_t total_bits = reader->length * 8;
  if (reader->bit_position > total_bits
      || count > total_bits - reader->bit_position) {
    return false;
  }
  uint32_t result = 0;
  for (uint32_t bit = 0; bit < count; bit++) {
    uint64_t position = reader->bit_position++;
    result = (result << 1)
        | ((reader->data[position / 8] >> (7 - position % 8)) & 1U);
  }
  *value = result;
  return true;
}


static inline bool isobmff_bits_peek(const IsoBmffBitReader *reader,
                                     uint32_t count, uint32_t *value) {

  if (!reader) {
    return false;
  }
  IsoBmffBitReader copy = *reader;
  return isobmff_bits_read(&copy, count, value);
}


static inline bool isobmff_bits_skip(IsoBmffBitReader *reader,
                                     uint64_t count) {

  if (!reader || reader->length > UINT64_MAX / 8) {
    return false;
  }
  uint64_t total_bits = reader->length * 8;
  if (reader->bit_position > total_bits
      || count > total_bits - reader->bit_position) {
    return false;
  }
  reader->bit_position += count;
  return true;
}


static inline uint32_t isobmff_log2_u32(uint32_t value) {

  return value == 0 ? 0U : 31U - (uint32_t)__builtin_clz(value);
}


static inline bool isobmff_type_printable(uint32_t type) {

  for (uint32_t shift = 0; shift < 32; shift += 8) {
    uint8_t value = (uint8_t)(type >> shift);

    if (value < 0x20 || value > 0x7e) {
      return false;
    }
  }
  return true;
}


static inline bool isobmff_box_at(const uint8_t *data, uint64_t length,
                                  uint64_t offset, IsoBmffBox *box) {

  if (!data || !box || offset > length || length - offset < 8) {
    return false;
  }
  uint64_t size = isobmff_read_be32(data + offset);
  uint64_t header_size = 8;
  bool extends_to_end = false;

  if (size == 1) {
    if (length - offset < 16) {
      return false;
    }
    size = isobmff_read_be64(data + offset + 8);
    header_size = 16;
  }
  else if (size == 0) {
    size = length - offset;
    extends_to_end = true;
  }
  if (size < header_size || size > ISOBMFF_MAXIMUM_SIZE) {
    return false;
  }
  box->offset = offset;
  box->size = size;
  box->header_size = header_size;
  box->type = isobmff_read_be32(data + offset + 4);
  box->extends_to_end = extends_to_end;
  return true;
}


static inline bool isobmff_box_fits(const IsoBmffBox *box,
                                    uint64_t limit) {

  return box && box->offset <= limit && box->size <= limit - box->offset;
}


static inline bool isobmff_is_container(uint32_t type) {

  return type == ISOBMFF_FOURCC('m', 'o', 'o', 'v')
      || type == ISOBMFF_FOURCC('t', 'r', 'a', 'k')
      || type == ISOBMFF_FOURCC('m', 'd', 'i', 'a')
      || type == ISOBMFF_FOURCC('m', 'i', 'n', 'f')
      || type == ISOBMFF_FOURCC('s', 't', 'b', 'l')
      || type == ISOBMFF_FOURCC('e', 'd', 't', 's')
      || type == ISOBMFF_FOURCC('d', 'i', 'n', 'f')
      || type == ISOBMFF_FOURCC('u', 'd', 't', 'a')
      || type == ISOBMFF_FOURCC('m', 'v', 'e', 'x')
      || type == ISOBMFF_FOURCC('m', 'o', 'o', 'f')
      || type == ISOBMFF_FOURCC('t', 'r', 'a', 'f')
      || type == ISOBMFF_FOURCC('m', 'f', 'r', 'a')
      || type == ISOBMFF_FOURCC('s', 'i', 'n', 'f')
      || type == ISOBMFF_FOURCC('s', 'c', 'h', 'i')
      || type == ISOBMFF_FOURCC('w', 'a', 'v', 'e')
      || type == ISOBMFF_FOURCC('m', 'e', 't', 'a')
      || type == ISOBMFF_FOURCC('i', 'l', 's', 't');
}


static inline bool isobmff_is_known_top_level(uint32_t type) {

  return type == ISOBMFF_FOURCC('f', 't', 'y', 'p')
      || type == ISOBMFF_FOURCC('m', 'o', 'o', 'v')
      || type == ISOBMFF_FOURCC('m', 'd', 'a', 't')
      || type == ISOBMFF_FOURCC('f', 'r', 'e', 'e')
      || type == ISOBMFF_FOURCC('s', 'k', 'i', 'p')
      || type == ISOBMFF_FOURCC('w', 'i', 'd', 'e')
      || type == ISOBMFF_FOURCC('u', 'u', 'i', 'd')
      || type == ISOBMFF_FOURCC('p', 'n', 'o', 't')
      || type == ISOBMFF_FOURCC('j', 'u', 'n', 'k')
      || type == ISOBMFF_FOURCC('p', 'r', 'f', 'l')
      || type == ISOBMFF_FOURCC('m', 'o', 'o', 'f')
      || type == ISOBMFF_FOURCC('s', 't', 'y', 'p')
      || type == ISOBMFF_FOURCC('s', 'i', 'd', 'x')
      || type == ISOBMFF_FOURCC('m', 'f', 'r', 'a')
      || type == ISOBMFF_FOURCC('p', 'd', 'i', 'n')
      || type == ISOBMFF_FOURCC('m', 'e', 't', 'a');
}


static inline IsoBmffKind isobmff_brand_kind(uint32_t brand) {

  if (brand == ISOBMFF_FOURCC('q', 't', ' ', ' ')) {
    return ISOBMFF_KIND_MOV;
  }
  return isobmff_type_printable(brand)
      ? ISOBMFF_KIND_MP4 : ISOBMFF_KIND_UNKNOWN;
}


static inline void isobmff_free_track(IsoBmffTrack *track) {

  if (!track) {
    return;
  }
  free(track->chunk_offsets);
  free(track->sample_sizes);
  free(track->sample_to_chunk);
  memset(track, 0, sizeof(*track));
}


static inline void isobmff_free_layout(IsoBmffLayout *layout) {

  if (!layout) {
    return;
  }
  for (uint32_t track = 0; track < layout->track_count; track++) {
    isobmff_free_track(&layout->tracks[track]);
  }
  memset(layout, 0, sizeof(*layout));
}


static inline bool isobmff_count_fits(uint64_t count, uint64_t width,
                                      uint64_t available) {

  return count <= ISOBMFF_MAX_TABLE_ENTRIES
      && (width == 0 || count <= available / width);
}


static inline bool isobmff_parse_alac_config(
    const uint8_t *data, uint64_t length, uint64_t offset,
    IsoBmffAlacConfig *config) {

  if (!data || !config || offset > length || length - offset < 36) {
    return false;
  }
  uint64_t atom_size = isobmff_read_be32(data + offset);
  if (atom_size < 36 || atom_size > length - offset
      || isobmff_read_be32(data + offset + 4)
             != ISOBMFF_FOURCC('a', 'l', 'a', 'c')
      || isobmff_read_be32(data + offset + 8) != 0) {
    return false;
  }
  IsoBmffAlacConfig parsed = {
    .max_samples_per_frame = isobmff_read_be32(data + offset + 12),
    .sample_size = data[offset + 17],
    .history_mult = data[offset + 18],
    .initial_history = data[offset + 19],
    .rice_limit = data[offset + 20],
    .channels = data[offset + 21]
  };
  uint32_t sample_rate = isobmff_read_be32(data + offset + 32);
  if (parsed.max_samples_per_frame == 0
      || parsed.max_samples_per_frame > 4096U * 4096U
      || (parsed.sample_size != 16 && parsed.sample_size != 20
          && parsed.sample_size != 24 && parsed.sample_size != 32)
      || parsed.rice_limit == 0 || parsed.channels == 0
      || parsed.channels > 8 || sample_rate == 0) {
    return false;
  }
  parsed.valid = true;
  *config = parsed;
  return true;
}


static inline bool isobmff_parse_stsd(const uint8_t *data,
                                      const IsoBmffBox *box,
                                      IsoBmffTrack *track) {

  uint64_t payload = box->offset + box->header_size;
  uint64_t end = box->offset + box->size;

  if (end - payload < 16) {
    return false;
  }
  uint32_t entries = isobmff_read_be32(data + payload + 4);
  uint64_t position = payload + 8;

  if (entries == 0 || entries > 1024) {
    return false;
  }
  for (uint32_t entry = 0; entry < entries; entry++) {
    IsoBmffBox sample;

    if (!isobmff_box_at(data, end, position, &sample)
        || !isobmff_box_fits(&sample, end) || sample.size < 8) {
      return false;
    }
    if (entry == 0) {
      track->codec = sample.type;
      track->nal_length_size = 4;

      uint64_t scan = position + sample.header_size;
      uint64_t sample_end = position + sample.size;
      while (scan + 8 <= sample_end) {
        uint32_t child_size = isobmff_read_be32(data + scan);
        uint32_t child_type = isobmff_read_be32(data + scan + 4);

        if (sample.type == ISOBMFF_FOURCC('a', 'l', 'a', 'c')
            && child_type == ISOBMFF_FOURCC('a', 'l', 'a', 'c')
            && isobmff_parse_alac_config(
                data, sample_end, scan, &track->alac)) {
          break;
        }
        if (child_size >= 8 && child_size <= sample_end - scan
            && (child_type == ISOBMFF_FOURCC('a', 'v', 'c', 'C')
                || child_type == ISOBMFF_FOURCC('h', 'v', 'c', 'C'))) {
          if (child_type == ISOBMFF_FOURCC('a', 'v', 'c', 'C')
              && child_size >= 13) {
            track->nal_length_size = (data[scan + 12] & 3U) + 1U;
          }
          else if (child_type == ISOBMFF_FOURCC('h', 'v', 'c', 'C')
                   && child_size >= 30) {
            track->nal_length_size = (data[scan + 29] & 3U) + 1U;
          }
          break;
        }
        scan++;
      }
    }
    position += sample.size;
  }
  track->saw_sample_description = true;
  return position <= end;
}


static inline bool isobmff_parse_stsc(const uint8_t *data,
                                      const IsoBmffBox *box,
                                      IsoBmffTrack *track) {

  uint64_t payload = box->offset + box->header_size;
  uint64_t end = box->offset + box->size;

  if (end - payload < 8) {
    return false;
  }
  uint64_t count = isobmff_read_be32(data + payload + 4);
  uint64_t position = payload + 8;

  if (count == 0 || !isobmff_count_fits(count, 12, end - position)
      || count > SIZE_MAX / sizeof(*track->sample_to_chunk)) {
    return false;
  }
  IsoBmffStscEntry *entries = (IsoBmffStscEntry *)calloc(
      (size_t)count, sizeof(*entries));
  check_memory_allocation(entries, __LINE__, __FILE__, "ISO BMFF stsc");

  for (uint64_t index = 0; index < count; index++) {
    entries[index].first_chunk = isobmff_read_be32(data + position);
    entries[index].samples_per_chunk = isobmff_read_be32(data + position + 4);
    entries[index].description_index = isobmff_read_be32(
        data + position + 8);
    if (entries[index].first_chunk == 0
        || entries[index].samples_per_chunk == 0
        || entries[index].description_index == 0
        || (index == 0 && entries[index].first_chunk != 1)
        || (index > 0
            && entries[index].first_chunk
               <= entries[index - 1].first_chunk)) {
      free(entries);
      return false;
    }
    position += 12;
  }
  free(track->sample_to_chunk);
  track->sample_to_chunk = entries;
  track->sample_to_chunk_count = count;
  return true;
}


static inline bool isobmff_parse_stsz(const uint8_t *data,
                                      const IsoBmffBox *box,
                                      IsoBmffTrack *track) {

  uint64_t payload = box->offset + box->header_size;
  uint64_t end = box->offset + box->size;

  if (end - payload < 12) {
    return false;
  }
  uint32_t default_size = isobmff_read_be32(data + payload + 4);
  uint64_t count = isobmff_read_be32(data + payload + 8);
  uint64_t position = payload + 12;

  if (count == 0 || count > ISOBMFF_MAX_TABLE_ENTRIES
      || (default_size == 0
          && !isobmff_count_fits(count, 4, end - position))
      || count > SIZE_MAX / sizeof(*track->sample_sizes)) {
    return false;
  }
  uint32_t *sizes = NULL;
  if (default_size == 0) {
    sizes = (uint32_t *)malloc((size_t)count * sizeof(*sizes));
    check_memory_allocation(sizes, __LINE__, __FILE__, "ISO BMFF stsz");
    for (uint64_t index = 0; index < count; index++) {
      sizes[index] = isobmff_read_be32(data + position + index * 4);
    }
  }
  free(track->sample_sizes);
  track->sample_sizes = sizes;
  track->sample_count = count;
  track->default_sample_size = default_size;
  return true;
}


static inline bool isobmff_parse_stz2(const uint8_t *data,
                                      const IsoBmffBox *box,
                                      IsoBmffTrack *track) {

  uint64_t payload = box->offset + box->header_size;
  uint64_t end = box->offset + box->size;

  if (end - payload < 12) {
    return false;
  }
  uint8_t width = data[payload + 7];
  uint64_t count = isobmff_read_be32(data + payload + 8);
  uint64_t position = payload + 12;
  uint64_t bytes = width == 4 ? CEILDIV(count, 2)
      : width == 8 ? count : width == 16 ? count * 2 : UINT64_MAX;

  if (count == 0 || count > ISOBMFF_MAX_TABLE_ENTRIES
      || bytes == UINT64_MAX || bytes > end - position
      || count > SIZE_MAX / sizeof(*track->sample_sizes)) {
    return false;
  }
  uint32_t *sizes = (uint32_t *)malloc((size_t)count * sizeof(*sizes));
  check_memory_allocation(sizes, __LINE__, __FILE__, "ISO BMFF stz2");

  for (uint64_t index = 0; index < count; index++) {
    if (width == 4) {
      uint8_t packed = data[position + index / 2];
      sizes[index] = (index & 1U) ? packed & 0x0fU : packed >> 4;
    }
    else if (width == 8) {
      sizes[index] = data[position + index];
    }
    else {
      sizes[index] = isobmff_read_be16(data + position + index * 2);
    }
  }
  free(track->sample_sizes);
  track->sample_sizes = sizes;
  track->sample_count = count;
  track->default_sample_size = 0;
  return true;
}


static inline bool isobmff_parse_chunk_offsets(
    const uint8_t *data, const IsoBmffBox *box, IsoBmffTrack *track,
    uint64_t width) {

  uint64_t payload = box->offset + box->header_size;
  uint64_t end = box->offset + box->size;

  if (end - payload < 8) {
    return false;
  }
  uint64_t count = isobmff_read_be32(data + payload + 4);
  uint64_t position = payload + 8;

  if (count == 0 || !isobmff_count_fits(count, width, end - position)
      || count > SIZE_MAX / sizeof(*track->chunk_offsets)) {
    return false;
  }
  uint64_t *offsets = (uint64_t *)malloc(
      (size_t)count * sizeof(*offsets));
  check_memory_allocation(offsets, __LINE__, __FILE__,
                          "ISO BMFF chunk offsets");

  for (uint64_t index = 0; index < count; index++) {
    offsets[index] = width == 4
        ? isobmff_read_be32(data + position + index * width)
        : isobmff_read_be64(data + position + index * width);
    if (index > 0 && offsets[index] < offsets[index - 1]) {
      free(offsets);
      return false;
    }
  }
  free(track->chunk_offsets);
  track->chunk_offsets = offsets;
  track->chunk_count = count;
  return true;
}


static inline bool isobmff_parse_track_children(
    const uint8_t *data, uint64_t length, uint64_t start, uint64_t end,
    uint32_t depth, IsoBmffTrack *track) {

  if (!data || !track || depth > ISOBMFF_MAX_BOX_DEPTH || start > end
      || end > length) {
    return false;
  }
  uint64_t position = start;

  while (position < end) {
    IsoBmffBox box;

    if (!isobmff_box_at(data, length, position, &box)
        || !isobmff_box_fits(&box, end)) {
      return false;
    }
    uint64_t payload = position + box.header_size;
    uint64_t payload_size = box.size - box.header_size;

    if (box.type == ISOBMFF_FOURCC('t', 'k', 'h', 'd')) {
      track->saw_track_header = payload_size >= 20;
    }
    else if (box.type == ISOBMFF_FOURCC('m', 'd', 'h', 'd')) {
      track->saw_media_header = payload_size >= 20;
    }
    else if (box.type == ISOBMFF_FOURCC('h', 'd', 'l', 'r')) {
      if (payload_size < 12) {
        return false;
      }
      track->handler = isobmff_read_be32(data + payload + 8);
      track->saw_handler = isobmff_type_printable(track->handler);
    }
    else if (box.type == ISOBMFF_FOURCC('s', 't', 's', 'd')) {
      if (!isobmff_parse_stsd(data, &box, track)) {
        return false;
      }
    }
    else if (box.type == ISOBMFF_FOURCC('s', 't', 't', 's')) {
      if (payload_size < 8) {
        return false;
      }
      uint64_t count = isobmff_read_be32(data + payload + 4);
      if (!isobmff_count_fits(count, 8, payload_size - 8)) {
        return false;
      }
      track->saw_time_to_sample = true;
    }
    else if (box.type == ISOBMFF_FOURCC('s', 't', 's', 'c')) {
      if (!isobmff_parse_stsc(data, &box, track)) {
        return false;
      }
    }
    else if (box.type == ISOBMFF_FOURCC('s', 't', 's', 'z')) {
      if (!isobmff_parse_stsz(data, &box, track)) {
        return false;
      }
    }
    else if (box.type == ISOBMFF_FOURCC('s', 't', 'z', '2')) {
      if (!isobmff_parse_stz2(data, &box, track)) {
        return false;
      }
    }
    else if (box.type == ISOBMFF_FOURCC('s', 't', 'c', 'o')) {
      if (!isobmff_parse_chunk_offsets(data, &box, track, 4)) {
        return false;
      }
    }
    else if (box.type == ISOBMFF_FOURCC('c', 'o', '6', '4')) {
      if (!isobmff_parse_chunk_offsets(data, &box, track, 8)) {
        return false;
      }
    }

    if (isobmff_is_container(box.type)) {
      uint64_t child_start = payload;
      if (box.type == ISOBMFF_FOURCC('m', 'e', 't', 'a')) {
        if (payload_size < 4) {
          return false;
        }
        child_start += 4;
      }
      if (child_start < position + box.size
          && !isobmff_parse_track_children(
              data, length, child_start, position + box.size,
              depth + 1, track)) {
        return false;
      }
    }
    position += box.size;
  }
  return position == end;
}


static inline bool isobmff_track_tables_valid(IsoBmffTrack *track) {

  if (!track || !track->saw_track_header || !track->saw_media_header
      || !track->saw_handler || !track->saw_sample_description
      || !track->saw_time_to_sample || !track->chunk_offsets
      || !track->sample_to_chunk || track->chunk_count == 0
      || track->sample_count == 0) {
    return false;
  }
  uint64_t samples = 0;
  for (uint64_t entry = 0; entry < track->sample_to_chunk_count; entry++) {
    uint64_t first = track->sample_to_chunk[entry].first_chunk;
    uint64_t next = entry + 1 < track->sample_to_chunk_count
        ? track->sample_to_chunk[entry + 1].first_chunk
        : track->chunk_count + 1;

    if (first > track->chunk_count || next <= first
        || next - first > UINT64_MAX
            / track->sample_to_chunk[entry].samples_per_chunk) {
      return false;
    }
    uint64_t addition = (next - first)
        * track->sample_to_chunk[entry].samples_per_chunk;
    if (addition > UINT64_MAX - samples) {
      return false;
    }
    samples += addition;
  }
  track->mapped_samples = samples;
  return samples == track->sample_count;
}


static inline bool isobmff_parse_moov_contents(
    const uint8_t *data, uint64_t length, const IsoBmffBox *moov,
    IsoBmffLayout *layout, bool allow_compressed) {

  uint64_t position = moov->offset + moov->header_size;
  uint64_t end = moov->offset + moov->size;

  if (!isobmff_box_fits(moov, length)) {
    return false;
  }
  while (position < end) {
    IsoBmffBox child;

    if (!isobmff_box_at(data, length, position, &child)
        || !isobmff_box_fits(&child, end)) {
      return false;
    }
    if (child.type == ISOBMFF_FOURCC('m', 'v', 'h', 'd')) {
      if (child.size - child.header_size < 20) {
        return false;
      }
      layout->saw_mvhd = true;
    }
    else if (child.type == ISOBMFF_FOURCC('t', 'r', 'a', 'k')) {
      if (layout->track_count == ISOBMFF_MAX_TRACKS) {
        return false;
      }
      IsoBmffTrack *track = &layout->tracks[layout->track_count];
      if (!isobmff_parse_track_children(
              data, length, position + child.header_size,
              position + child.size, 1, track)
          || !isobmff_track_tables_valid(track)) {
        isobmff_free_track(track);
        return false;
      }
      layout->track_count++;
    }
    else if (child.type == ISOBMFF_FOURCC('m', 'v', 'e', 'x')) {
      layout->saw_fragment = true;
    }
    else if (child.type == ISOBMFF_FOURCC('c', 'm', 'o', 'v')) {
      uint64_t cmov_position = child.offset + child.header_size;
      uint64_t cmov_end = child.offset + child.size;
      uint32_t compression = 0;
      const uint8_t *compressed = NULL;
      uint64_t compressed_size = 0;
      uint64_t expanded_size = 0;
      bool saw_dcom = false;
      bool saw_cmvd = false;

      if (!allow_compressed
          || position != moov->offset + moov->header_size
          || child.size != end - position) {
        return false;
      }
      while (cmov_position < cmov_end) {
        IsoBmffBox compressed_child;

        if (!isobmff_box_at(data, length, cmov_position,
                            &compressed_child)
            || !isobmff_box_fits(&compressed_child, cmov_end)) {
          return false;
        }
        uint64_t payload = compressed_child.offset
                           + compressed_child.header_size;
        uint64_t payload_size = compressed_child.size
                                - compressed_child.header_size;

        if (compressed_child.type
            == ISOBMFF_FOURCC('d', 'c', 'o', 'm')) {
          if (saw_dcom || payload_size != 4) {
            return false;
          }
          compression = isobmff_read_be32(data + payload);
          saw_dcom = true;
        }
        else if (compressed_child.type
                 == ISOBMFF_FOURCC('c', 'm', 'v', 'd')) {
          if (saw_cmvd || payload_size <= 4) {
            return false;
          }
          expanded_size = isobmff_read_be32(data + payload);
          compressed = data + payload + 4;
          compressed_size = payload_size - 4;
          saw_cmvd = true;
        }
        else {
          return false;
        }
        cmov_position += compressed_child.size;
      }
      if (cmov_position != cmov_end || !saw_dcom || !saw_cmvd
          || compression != ISOBMFF_FOURCC('z', 'l', 'i', 'b')
          || expanded_size < ISOBMFF_MINIMUM_SIZE
          || expanded_size > ISOBMFF_MAX_METADATA_SIZE
          || expanded_size > SIZE_MAX || expanded_size > ULONG_MAX
          || compressed_size > ULONG_MAX) {
        return false;
      }

      uint8_t *expanded = (uint8_t *)malloc((size_t)expanded_size);
      if (!expanded) {
        return false;
      }
      uLongf actual_size = (uLongf)expanded_size;
      int zresult = uncompress(expanded, &actual_size, compressed,
                               (uLong)compressed_size);
      IsoBmffBox expanded_moov;
      bool valid = zresult == Z_OK && actual_size == expanded_size
          && isobmff_box_at(expanded, expanded_size, 0, &expanded_moov)
          && expanded_moov.type == ISOBMFF_FOURCC('m', 'o', 'o', 'v')
          && expanded_moov.size == expanded_size
          && isobmff_parse_moov_contents(
              expanded, expanded_size, &expanded_moov, layout, false);
      free(expanded);
      return valid;
    }
    position += child.size;
  }
  return position == end && layout->saw_mvhd
      && (layout->track_count > 0 || layout->saw_fragment);
}


static inline bool isobmff_parse_moov(const uint8_t *data,
                                      uint64_t length,
                                      const IsoBmffBox *moov,
                                      IsoBmffLayout *layout) {

  return isobmff_parse_moov_contents(
      data, length, moov, layout, true);
}


static inline bool isobmff_offset_in_mdat(const IsoBmffLayout *layout,
                                          uint64_t start,
                                          uint64_t length) {

  if (!layout || length > UINT64_MAX - start) {
    return false;
  }
  uint64_t end = start + length;
  for (uint32_t range = 0; range < layout->mdat_count; range++) {
    if (start >= layout->mdat_ranges[range].start
        && end <= layout->mdat_ranges[range].end) {
      return true;
    }
  }
  return false;
}


static inline bool isobmff_mpeg4_sample_valid(const uint8_t *data,
                                              uint64_t length) {

  if (!data || length < 4 || data[0] != 0 || data[1] != 0
      || data[2] != 1) {
    return false;
  }
  return data[3] <= 0x2f || (data[3] >= 0xb0 && data[3] <= 0xb6);
}


static inline bool isobmff_nal_sample_valid(const uint8_t *data,
                                            uint64_t length,
                                            uint8_t length_size,
                                            bool hevc) {

  if (!data || length_size < 1 || length_size > 4 || length < length_size) {
    return false;
  }
  uint64_t position = 0;
  uint64_t units = 0;

  while (position < length) {
    if (length - position < length_size) {
      return false;
    }
    uint32_t unit_length = 0;
    for (uint8_t byte = 0; byte < length_size; byte++) {
      unit_length = (unit_length << 8) | data[position + byte];
    }
    position += length_size;
    if (unit_length == 0 || unit_length > length - position) {
      return false;
    }
    uint8_t type = hevc ? (data[position] >> 1) & 0x3fU
                        : data[position] & 0x1fU;
    if ((!hevc && (type == 0 || type > 23))
        || (hevc && type > 63)) {
      return false;
    }
    position += unit_length;
    units++;
  }
  return units > 0;
}


static inline bool isobmff_tga_header_valid(
    const uint8_t *data, uint64_t length, uint64_t *pixel_offset,
    uint64_t *pixel_count, uint8_t *pixel_bytes, bool *rle) {

  if (!data || length < 18 || !pixel_offset || !pixel_count
      || !pixel_bytes || !rle || data[1] > 1) {
    return false;
  }
  uint8_t image_type = data[2];
  bool color_mapped = image_type == 1 || image_type == 9;
  bool true_color = image_type == 2 || image_type == 10;
  bool grayscale = image_type == 3 || image_type == 11;
  if (!color_mapped && !true_color && !grayscale) {
    return false;
  }
  if (color_mapped && data[1] != 1) {
    return false;
  }
  uint16_t width = isobmff_read_le16(data + 12);
  uint16_t height = isobmff_read_le16(data + 14);
  uint8_t depth = data[16];
  if (width == 0 || height == 0
      || (color_mapped && depth != 8 && depth != 16)
      || (true_color && depth != 15 && depth != 16
          && depth != 24 && depth != 32)
      || (grayscale && depth != 8 && depth != 16)) {
    return false;
  }
  uint64_t offset = 18U + data[0];
  if (data[1] == 1) {
    uint16_t entries = isobmff_read_le16(data + 5);
    uint8_t entry_depth = data[7];
    if (entries == 0 || (entry_depth != 15 && entry_depth != 16
        && entry_depth != 24 && entry_depth != 32)) {
      return false;
    }
    uint64_t map_bytes = (uint64_t)entries * ((entry_depth + 7U) / 8U);
    if (map_bytes > UINT64_MAX - offset) {
      return false;
    }
    offset += map_bytes;
  }
  if (offset > length) {
    return false;
  }
  *pixel_offset = offset;
  *pixel_count = (uint64_t)width * height;
  *pixel_bytes = (uint8_t)((depth + 7U) / 8U);
  *rle = image_type >= 9;
  return true;
}


static inline bool isobmff_tga_sample_valid(const uint8_t *data,
                                             uint64_t length) {

  uint64_t position = 0;
  uint64_t pixels = 0;
  uint8_t pixel_bytes = 0;
  bool rle = false;
  if (!isobmff_tga_header_valid(data, length, &position, &pixels,
                                &pixel_bytes, &rle)) {
    return false;
  }
  if (!rle) {
    if (pixels > UINT64_MAX / pixel_bytes) {
      return false;
    }
    uint64_t bytes = pixels * pixel_bytes;
    if (bytes > length - position) {
      return false;
    }
    position += bytes;
  }
  else {
    uint64_t decoded = 0;
    while (decoded < pixels) {
      if (position >= length) {
        return false;
      }
      uint8_t packet = data[position++];
      uint64_t count = (uint64_t)(packet & 0x7fU) + 1U;
      if (count > pixels - decoded) {
        return false;
      }
      uint64_t bytes = (packet & 0x80U) != 0
          ? pixel_bytes : count * pixel_bytes;
      if (bytes > length - position) {
        return false;
      }
      position += bytes;
      decoded += count;
    }
  }
  if (position == length) {
    return true;
  }
  static const uint8_t footer_signature[18] = "TRUEVISION-XFILE.";
  return length - position == 26
      && memcmp(data + position + 8, footer_signature,
                sizeof(footer_signature)) == 0;
}


static inline bool isobmff_tga_rle_stream_initialize(
    IsoBmffTgaRleState *state, const uint8_t *header,
    uint64_t sample_size) {

  uint64_t pixel_offset = 0;
  uint64_t pixel_count = 0;
  uint8_t pixel_bytes = 0;
  bool rle = false;

  if (!state || !header || sample_size < 18
      || !isobmff_tga_header_valid(
          header, sample_size, &pixel_offset, &pixel_count,
          &pixel_bytes, &rle)
      || !rle) {
    return false;
  }
  memset(state, 0, sizeof(*state));
  state->pixel_offset = pixel_offset;
  state->skip_remaining = pixel_offset;
  state->pixels_total = pixel_count;
  state->failure_offset = UINT64_MAX;
  state->width = isobmff_read_le16(header + 12);
  state->pixel_bytes = pixel_bytes;
  state->initialized = true;
  return true;
}


static inline bool isobmff_tga_rle_stream_feed(
    IsoBmffTgaRleState *state, const uint8_t *data, uint64_t length) {

  if (!state || !state->initialized || state->invalid
      || (!data && length > 0)) {
    return false;
  }
  while (length > 0) {
    if (state->skip_remaining > 0) {
      uint64_t count = state->skip_remaining;
      if (count > length) {
        count = length;
      }
      state->skip_remaining -= count;
      state->bytes_seen += count;
      data += count;
      length -= count;
      continue;
    }
    if (state->payload_remaining > 0) {
      uint64_t count = state->payload_remaining;
      if (count > length) {
        count = length;
      }
      state->payload_remaining -= count;
      state->bytes_seen += count;
      data += count;
      length -= count;
      continue;
    }
    if (state->pixels_decoded == state->pixels_total) {
      if (length > sizeof(state->tail) - state->tail_length) {
        state->failure_offset = state->bytes_seen;
        state->invalid = true;
        return false;
      }
      memcpy(state->tail + state->tail_length, data, (size_t)length);
      state->tail_length += (uint8_t)length;
      state->bytes_seen += length;
      return true;
    }

    uint64_t packet_offset = state->bytes_seen;
    uint8_t packet = *data++;
    length--;
    state->bytes_seen++;
    uint64_t count = (uint64_t)(packet & 0x7fU) + 1U;
    if (count > state->pixels_total - state->pixels_decoded
        || count > (uint64_t)state->width - state->column) {
      state->failure_offset = packet_offset;
      state->invalid = true;
      return false;
    }
    state->payload_remaining = (packet & 0x80U) != 0
        ? state->pixel_bytes : count * state->pixel_bytes;
    state->pixels_decoded += count;
    state->column += count;
    if (state->column == state->width) {
      state->column = 0;
    }
  }
  return true;
}


static inline bool isobmff_tga_rle_stream_complete(
    const IsoBmffTgaRleState *state) {

  static const uint8_t footer_signature[18] = "TRUEVISION-XFILE.";

  return state && state->initialized && !state->invalid
      && state->skip_remaining == 0 && state->payload_remaining == 0
      && state->pixels_decoded == state->pixels_total
      && state->column == 0
      && (state->tail_length == 0
          || (state->tail_length == sizeof(state->tail)
              && memcmp(state->tail + 8, footer_signature,
                        sizeof(footer_signature)) == 0));
}


static inline bool isobmff_h263_sample_valid(const uint8_t *data,
                                              uint64_t length) {

  return data && length >= 4 && data[0] == 0 && data[1] == 0
      && (data[2] & 0xfcU) == 0x80U;
}


static inline uint8_t isobmff_amr_nb_frame_size(uint8_t toc) {

  static const uint8_t sizes[16] = {
    13, 14, 16, 18, 20, 21, 27, 32, 6, 0, 0, 0, 0, 0, 0, 1
  };
  if ((toc & 0x83U) != 0) {
    return 0;
  }
  return sizes[(toc >> 3) & 0x0fU];
}


static inline bool isobmff_amr_nb_sample_valid(const uint8_t *data,
                                                uint64_t length) {

  return data && length > 0
      && isobmff_amr_nb_frame_size(data[0]) == length;
}


static inline uint32_t isobmff_ac3_frame_size(const uint8_t *data,
                                               uint64_t length) {

  static const uint16_t words_48khz[19] = {
    64, 80, 96, 112, 128, 160, 192, 224, 256, 320,
    384, 448, 512, 640, 768, 896, 1024, 1152, 1280
  };
  static const uint16_t words_32khz[19] = {
    96, 120, 144, 168, 192, 240, 288, 336, 384, 480,
    576, 672, 768, 960, 1152, 1344, 1536, 1728, 1920
  };
  static const uint16_t words_44khz[38] = {
    69, 70, 87, 88, 104, 105, 121, 122, 139, 140,
    174, 175, 208, 209, 243, 244, 278, 279, 348, 349,
    417, 418, 487, 488, 557, 558, 696, 697, 835, 836,
    975, 976, 1114, 1115, 1253, 1254, 1393, 1394
  };
  if (!data || length < 6 || data[0] != 0x0b || data[1] != 0x77) {
    return 0;
  }
  uint8_t fscod = data[4] >> 6;
  uint8_t frame_size_code = data[4] & 0x3fU;
  uint8_t bsid = data[5] >> 3;
  if (fscod == 3 || frame_size_code > 37 || bsid > 10) {
    return 0;
  }
  uint16_t words = fscod == 0 ? words_48khz[frame_size_code / 2]
      : fscod == 1 ? words_44khz[frame_size_code]
                   : words_32khz[frame_size_code / 2];
  return (uint32_t)words * 2U;
}


static inline bool isobmff_ac3_sample_valid(const uint8_t *data,
                                             uint64_t length) {

  return isobmff_ac3_frame_size(data, length) == length;
}


static inline bool isobmff_avs2_sample_valid(const uint8_t *data,
                                              uint64_t length) {

  if (!data || length < 6) {
    return false;
  }
  uint64_t position = 0;
  uint64_t units = 0;
  while (position < length) {
    if (length - position < 4) {
      return false;
    }
    uint32_t unit_size = isobmff_read_be32(data + position);
    position += 4;
    if (unit_size == 0 || unit_size > length - position) {
      return false;
    }
    if (units == 0) {
      if (unit_size < 2 || (data[position + 1] != 0xb0
          && data[position + 1] != 0xb2
          && data[position + 1] != 0xb3
          && data[position + 1] != 0xb6
          && data[position + 1] != 0xb7)) {
        return false;
      }
    }
    position += unit_size;
    units++;
  }
  return units > 0;
}


static inline bool isobmff_svq1_sample_valid(const uint8_t *data,
                                              uint64_t length) {

  if (!data || length < 4) {
    return false;
  }
  uint32_t header = isobmff_read_be32(data);
  uint32_t frame_code = header >> 10;
  if ((frame_code & ~0x70U) != 0 || (frame_code & 0x60U) == 0) {
    return false;
  }
  if ((header & 0x03U) == 3) {
    return false;
  }
  return frame_code == 0x20 || length >= 36;
}


static inline bool isobmff_alac_decode_scalar(
    IsoBmffBitReader *reader, uint32_t k, uint32_t bps,
    uint32_t *value) {

  if (!reader || !value || k == 0 || k > 31 || bps == 0 || bps > 32) {
    return false;
  }
  uint32_t unary = 0;
  while (unary < 9) {
    uint32_t bit = 0;
    if (!isobmff_bits_read(reader, 1, &bit)) {
      return false;
    }
    if (bit == 0) {
      break;
    }
    unary++;
  }
  if (unary > 8) {
    return isobmff_bits_read(reader, bps, value);
  }

  uint64_t decoded = unary;
  if (k != 1) {
    uint32_t extra = 0;
    if (!isobmff_bits_peek(reader, k, &extra)) {
      return false;
    }
    decoded = ((uint64_t)unary << k) - unary;
    if (extra > 1) {
      decoded += extra - 1;
      if (!isobmff_bits_skip(reader, k)) {
        return false;
      }
    }
    else if (!isobmff_bits_skip(reader, k - 1)) {
      return false;
    }
  }
  if (decoded > UINT32_MAX) {
    return false;
  }
  *value = (uint32_t)decoded;
  return true;
}


static inline bool isobmff_alac_skip_residuals(
    IsoBmffBitReader *reader, const IsoBmffAlacConfig *config,
    uint32_t samples, uint32_t bps, uint32_t history_mult) {

  if (!reader || !config || samples == 0 || bps == 0 || bps > 32) {
    return false;
  }
  uint32_t history = config->initial_history;
  uint32_t sign_modifier = 0;

  for (uint32_t sample = 0; sample < samples; sample++) {
    uint32_t k = isobmff_log2_u32((history >> 9) + 3);
    if (k > config->rice_limit) {
      k = config->rice_limit;
    }
    uint32_t value = 0;
    if (!isobmff_alac_decode_scalar(reader, k, bps, &value)
        || value > UINT32_MAX - sign_modifier) {
      return false;
    }
    value += sign_modifier;
    sign_modifier = 0;

    if (value > 0xffffU) {
      history = 0xffffU;
    }
    else {
      uint64_t scaled = (uint64_t)history * history_mult;
      uint64_t updated = (uint64_t)history
          + (uint64_t)value * history_mult - (scaled >> 9);
      history = updated > UINT32_MAX ? UINT32_MAX : (uint32_t)updated;
    }
    if (history < 128 && sample + 1 < samples) {
      uint32_t history_log = isobmff_log2_u32(history);
      k = 7U - history_log + ((history + 16U) >> 6);
      if (k > config->rice_limit) {
        k = config->rice_limit;
      }
      uint32_t zero_run = 0;
      if (!isobmff_alac_decode_scalar(reader, k, 16, &zero_run)
          || zero_run >= samples - sample) {
        return false;
      }
      sample += zero_run;
      if (zero_run <= 0xffffU) {
        sign_modifier = 1;
      }
      history = 0;
    }
  }
  return true;
}


static inline bool isobmff_alac_frame_valid(
    const uint8_t *data, uint64_t length,
    const IsoBmffAlacConfig *config) {

  if (!data || length == 0 || !config || !config->valid) {
    return false;
  }
  IsoBmffBitReader reader = {
    .data = data,
    .length = length,
    .bit_position = 0
  };
  uint32_t decoded_channels = 0;
  uint32_t frame_samples = 0;
  bool saw_end = false;

  while (reader.bit_position <= length * 8
         && length * 8 - reader.bit_position >= 3) {
    uint32_t element = 0;
    if (!isobmff_bits_read(&reader, 3, &element)) {
      return false;
    }
    if (element == 7) {
      saw_end = true;
      break;
    }
    if (element > 1 && element != 3) {
      return false;
    }
    uint32_t channels = element == 1 ? 2U : 1U;
    if (channels > config->channels - decoded_channels
        || !isobmff_bits_skip(&reader, 4)) {
      return false;
    }
    uint32_t unused = 0;
    uint32_t has_size = 0;
    uint32_t extra_code = 0;
    uint32_t uncompressed = 0;
    if (!isobmff_bits_read(&reader, 12, &unused) || unused != 0
        || !isobmff_bits_read(&reader, 1, &has_size)
        || !isobmff_bits_read(&reader, 2, &extra_code)
        || !isobmff_bits_read(&reader, 1, &uncompressed)) {
      return false;
    }
    uint32_t extra_bits = extra_code << 3;
    int32_t bps = (int32_t)config->sample_size - (int32_t)extra_bits
                  + (int32_t)channels - 1;
    if (bps < 1 || bps > 32) {
      return false;
    }
    uint32_t output_samples = config->max_samples_per_frame;
    if (has_size && !isobmff_bits_read(&reader, 32, &output_samples)) {
      return false;
    }
    if (output_samples == 0
        || output_samples > config->max_samples_per_frame
        || (frame_samples != 0 && output_samples != frame_samples)) {
      return false;
    }
    frame_samples = output_samples;

    if (!uncompressed) {
      uint32_t decorrelation_shift = 0;
      uint32_t decorrelation_weight = 0;
      uint32_t residual_mult[2] = {0, 0};
      if (!isobmff_bits_read(&reader, 8, &decorrelation_shift)
          || !isobmff_bits_read(&reader, 8, &decorrelation_weight)
          || (channels == 2 && decorrelation_weight != 0
              && decorrelation_shift > 31)) {
        return false;
      }
      for (uint32_t channel = 0; channel < channels; channel++) {
        uint32_t prediction_type = 0;
        uint32_t lpc_quant = 0;
        uint32_t residual_scale = 0;
        uint32_t lpc_order = 0;
        if (!isobmff_bits_read(&reader, 4, &prediction_type)
            || !isobmff_bits_read(&reader, 4, &lpc_quant)
            || !isobmff_bits_read(&reader, 3, &residual_scale)
            || !isobmff_bits_read(&reader, 5, &lpc_order)
            || lpc_quant == 0
            || lpc_order >= config->max_samples_per_frame
            || !isobmff_bits_skip(&reader, (uint64_t)lpc_order * 16)) {
          return false;
        }
        residual_mult[channel] = residual_scale * config->history_mult / 4;
      }
      uint64_t extra_count = (uint64_t)output_samples * channels;
      if (extra_bits != 0
          && (extra_count > UINT64_MAX / extra_bits
              || !isobmff_bits_skip(&reader, extra_count * extra_bits))) {
        return false;
      }
      for (uint32_t channel = 0; channel < channels; channel++) {
        if (!isobmff_alac_skip_residuals(
                &reader, config, output_samples, (uint32_t)bps,
                residual_mult[channel])) {
          return false;
        }
      }
    }
    else {
      uint64_t sample_bits = (uint64_t)output_samples * channels;
      if (sample_bits > UINT64_MAX / config->sample_size
          || !isobmff_bits_skip(
              &reader, sample_bits * config->sample_size)) {
        return false;
      }
    }
    decoded_channels += channels;
  }
  uint64_t total_bits = length * 8;
  return saw_end && decoded_channels == config->channels
      && frame_samples > 0 && reader.bit_position <= total_bits
      && total_bits - reader.bit_position <= 8;
}


static inline bool isobmff_alac_anchor_valid(
    const uint8_t *data, uint64_t length, uint64_t sample_size,
    const IsoBmffAlacConfig *config) {

  if (!data || length < 5 || !config || !config->valid) {
    return false;
  }
  IsoBmffBitReader reader = {
    .data = data,
    .length = length,
    .bit_position = 0
  };
  uint32_t element = 0;
  uint32_t unused = 0;
  uint32_t has_size = 0;
  uint32_t extra_code = 0;
  uint32_t uncompressed = 0;
  if (!isobmff_bits_read(&reader, 3, &element)
      || (element > 1 && element != 3)
      || !isobmff_bits_skip(&reader, 4)
      || !isobmff_bits_read(&reader, 12, &unused) || unused != 0
      || !isobmff_bits_read(&reader, 1, &has_size)
      || !isobmff_bits_read(&reader, 2, &extra_code)
      || !isobmff_bits_read(&reader, 1, &uncompressed)) {
    return false;
  }
  uint32_t channels = element == 1 ? 2U : 1U;
  uint32_t extra_bits = extra_code << 3;
  int32_t bps = (int32_t)config->sample_size - (int32_t)extra_bits
                + (int32_t)channels - 1;
  if (bps < 1 || bps > 32) {
    return false;
  }
  uint32_t output_samples = config->max_samples_per_frame;
  if (has_size && !isobmff_bits_read(&reader, 32, &output_samples)) {
    return false;
  }
  if (output_samples == 0 || output_samples > config->max_samples_per_frame) {
    return false;
  }
  if (uncompressed) {
    uint64_t required_bits = (uint64_t)output_samples * channels;
    return required_bits <= UINT64_MAX / config->sample_size
        && required_bits * config->sample_size <= sample_size * 8;
  }

  uint32_t decorrelation_shift = 0;
  uint32_t decorrelation_weight = 0;
  uint32_t prediction_type = 0;
  uint32_t lpc_quant = 0;
  uint32_t residual_scale = 0;
  uint32_t lpc_order = 0;
  return isobmff_bits_read(&reader, 8, &decorrelation_shift)
      && isobmff_bits_read(&reader, 8, &decorrelation_weight)
      && (channels != 2 || decorrelation_weight == 0
          || decorrelation_shift <= 31)
      && isobmff_bits_read(&reader, 4, &prediction_type)
      && isobmff_bits_read(&reader, 4, &lpc_quant) && lpc_quant != 0
      && isobmff_bits_read(&reader, 3, &residual_scale)
      && isobmff_bits_read(&reader, 5, &lpc_order)
      && lpc_order < config->max_samples_per_frame;
}


static inline bool isobmff_pgvv_anchor_valid(const uint8_t *data,
                                              uint64_t length,
                                              uint64_t sample_size) {

  if (!data || length < 16 || sample_size < 16) {
    return false;
  }
  uint64_t first_field_size = isobmff_read_be32(data);
  uint64_t second_field_size = isobmff_read_be32(data + 4);
  uint16_t version = (uint16_t)(((uint16_t)data[8] << 8) | data[9]);
  if (version == 0) {
    return (first_field_size > 0 || second_field_size > 0)
        && first_field_size <= sample_size
        && second_field_size <= sample_size
        && first_field_size <= sample_size - second_field_size;
  }
  if (version != 1 || length < 32 || sample_size < 32
      || first_field_size != 0) {
    return false;
  }
  first_field_size = isobmff_read_be32(data + 20);
  return first_field_size > 0 && first_field_size <= sample_size
      && second_field_size <= sample_size
      && first_field_size <= sample_size - second_field_size;
}


static inline bool isobmff_sample_strong(const IsoBmffTrack *track) {

  return track && (track->codec == ISOBMFF_FOURCC('m', 'p', '4', 'v')
      || track->codec == ISOBMFF_FOURCC('a', 'v', 'c', '1')
      || track->codec == ISOBMFF_FOURCC('a', 'v', 'c', '3')
      || track->codec == ISOBMFF_FOURCC('h', 'v', 'c', '1')
      || track->codec == ISOBMFF_FOURCC('h', 'e', 'v', '1')
      || track->codec == ISOBMFF_FOURCC('j', 'p', 'e', 'g')
      || track->codec == ISOBMFF_FOURCC('m', 'j', 'p', 'a')
      || track->codec == ISOBMFF_FOURCC('m', 'j', 'p', 'b')
      || track->codec == ISOBMFF_FOURCC('p', 'n', 'g', ' ')
      || track->codec == ISOBMFF_FOURCC('t', 'g', 'a', ' ')
      || track->codec == ISOBMFF_FOURCC('s', '2', '6', '3')
      || track->codec == ISOBMFF_FOURCC('s', 'a', 'm', 'r')
      || track->codec == ISOBMFF_FOURCC('a', 'c', '-', '3')
      || track->codec == ISOBMFF_FOURCC('a', 'v', 's', '2')
      || track->codec == ISOBMFF_FOURCC('S', 'V', 'Q', '1')
      || (track->codec == ISOBMFF_FOURCC('a', 'l', 'a', 'c')
          && track->alac.valid));
}


static inline bool isobmff_sample_anchorable(const IsoBmffTrack *track) {

  return isobmff_sample_strong(track)
      || (track && (track->codec == ISOBMFF_FOURCC('a', 'l', 'a', 'c')
                    || track->codec
                           == ISOBMFF_FOURCC('P', 'G', 'V', 'V')));
}


static inline bool isobmff_layout_samples_validated(
    const IsoBmffLayout *layout) {

  if (!layout || layout->track_count == 0
      || layout->invalid_strong_samples != 0) {
    return false;
  }
  uint64_t mapped_samples = 0;

  for (uint32_t index = 0; index < layout->track_count; index++) {
    const IsoBmffTrack *track = &layout->tracks[index];

    if (!isobmff_sample_strong(track) || track->mapped_samples == 0
        || track->mapped_samples > UINT64_MAX - mapped_samples) {
      return false;
    }
    mapped_samples += track->mapped_samples;
  }
  return mapped_samples > 0 && layout->strong_samples == mapped_samples;
}


static inline bool isobmff_sample_content_valid(
    const IsoBmffTrack *track, const uint8_t *data, uint64_t length) {

  if (track->codec == ISOBMFF_FOURCC('m', 'p', '4', 'v')) {
    return isobmff_mpeg4_sample_valid(data, length);
  }
  if (track->codec == ISOBMFF_FOURCC('a', 'v', 'c', '1')
      || track->codec == ISOBMFF_FOURCC('a', 'v', 'c', '3')) {
    return isobmff_nal_sample_valid(data, length,
                                    track->nal_length_size, false);
  }
  if (track->codec == ISOBMFF_FOURCC('h', 'v', 'c', '1')
      || track->codec == ISOBMFF_FOURCC('h', 'e', 'v', '1')) {
    return isobmff_nal_sample_valid(data, length,
                                    track->nal_length_size, true);
  }
  if (track->codec == ISOBMFF_FOURCC('j', 'p', 'e', 'g')
      || track->codec == ISOBMFF_FOURCC('m', 'j', 'p', 'a')
      || track->codec == ISOBMFF_FOURCC('m', 'j', 'p', 'b')) {
    return length >= 4 && data[0] == 0xff && data[1] == 0xd8
        && data[length - 2] == 0xff && data[length - 1] == 0xd9;
  }
  if (track->codec == ISOBMFF_FOURCC('p', 'n', 'g', ' ')) {
    static const uint8_t signature[8] = {
      0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a
    };
    return length >= sizeof(signature)
        && memcmp(data, signature, sizeof(signature)) == 0;
  }
  if (track->codec == ISOBMFF_FOURCC('t', 'g', 'a', ' ')) {
    return isobmff_tga_sample_valid(data, length);
  }
  if (track->codec == ISOBMFF_FOURCC('s', '2', '6', '3')) {
    return isobmff_h263_sample_valid(data, length);
  }
  if (track->codec == ISOBMFF_FOURCC('s', 'a', 'm', 'r')) {
    return isobmff_amr_nb_sample_valid(data, length);
  }
  if (track->codec == ISOBMFF_FOURCC('a', 'c', '-', '3')) {
    return isobmff_ac3_sample_valid(data, length);
  }
  if (track->codec == ISOBMFF_FOURCC('a', 'v', 's', '2')) {
    return isobmff_avs2_sample_valid(data, length);
  }
  if (track->codec == ISOBMFF_FOURCC('S', 'V', 'Q', '1')) {
    return isobmff_svq1_sample_valid(data, length);
  }
  if (track->codec == ISOBMFF_FOURCC('a', 'l', 'a', 'c')) {
    return isobmff_alac_frame_valid(data, length, &track->alac);
  }
  return false;
}


static inline uint32_t isobmff_samples_per_chunk(
    const IsoBmffTrack *track, uint64_t chunk_index) {

  if (!track || chunk_index >= track->chunk_count) {
    return 0;
  }
  uint64_t chunk_number = chunk_index + 1;
  for (uint64_t entry = track->sample_to_chunk_count; entry > 0; entry--) {
    if (chunk_number >= track->sample_to_chunk[entry - 1].first_chunk) {
      return track->sample_to_chunk[entry - 1].samples_per_chunk;
    }
  }
  return 0;
}


static inline uint32_t isobmff_sample_size(const IsoBmffTrack *track,
                                           uint64_t sample) {

  return track->default_sample_size != 0
      ? track->default_sample_size : track->sample_sizes[sample];
}


static inline bool isobmff_track_required_extent(
    const IsoBmffTrack *track, uint64_t *required_extent) {

  if (!track || !required_extent || track->chunk_count == 0
      || track->sample_count == 0 || !track->chunk_offsets
      || !track->sample_to_chunk) {
    return false;
  }
  uint64_t sample = 0;
  uint64_t extent = 0;

  for (uint64_t chunk = 0; chunk < track->chunk_count; chunk++) {
    uint64_t position = track->chunk_offsets[chunk];
    uint32_t samples = isobmff_samples_per_chunk(track, chunk);

    if (samples == 0) {
      return false;
    }
    for (uint32_t in_chunk = 0; in_chunk < samples; in_chunk++) {
      if (sample >= track->sample_count) {
        return false;
      }
      uint64_t sample_size = isobmff_sample_size(track, sample);
      if (sample_size > UINT64_MAX - position) {
        return false;
      }
      position += sample_size;
      if (position > extent) {
        extent = position;
      }
      sample++;
    }
  }
  if (sample != track->sample_count || extent == 0) {
    return false;
  }
  *required_extent = extent;
  return true;
}


static inline bool isobmff_layout_required_extent(
    const IsoBmffLayout *layout, uint64_t *required_extent) {

  if (!layout || !required_extent || !layout->saw_moov
      || layout->track_count == 0) {
    return false;
  }
  uint64_t extent = layout->parsed_extent;

  for (uint32_t index = 0; index < layout->track_count; index++) {
    uint64_t track_extent = 0;
    if (!isobmff_track_required_extent(&layout->tracks[index],
                                       &track_extent)) {
      return false;
    }
    if (track_extent > extent) {
      extent = track_extent;
    }
  }
  if (extent == 0 || extent > ISOBMFF_MAXIMUM_SIZE) {
    return false;
  }
  *required_extent = extent;
  return true;
}


static inline bool isobmff_record_mdat(
    IsoBmffLayout *layout, const IsoBmffBox *box) {

  if (!layout || !box
      || layout->mdat_count == ISOBMFF_MAX_MDAT_RANGES
      || box->size > UINT64_MAX - box->offset) {
    return false;
  }
  if (layout->mdat_count == 0) {
    layout->first_mdat_offset = box->offset;
  }
  layout->mdat_ranges[layout->mdat_count].start = box->offset
      + box->header_size;
  layout->mdat_ranges[layout->mdat_count].end = box->offset + box->size;
  layout->mdat_count++;
  if (box->extends_to_end) {
    layout->terminal_size = true;
  }
  return true;
}


static inline bool isobmff_validate_track_samples(
    const uint8_t *data, uint64_t length, IsoBmffLayout *layout,
    IsoBmffTrack *track) {

  uint64_t sample = 0;
  bool strong = isobmff_sample_strong(track);

  for (uint64_t chunk = 0; chunk < track->chunk_count; chunk++) {
    uint64_t position = track->chunk_offsets[chunk];
    uint32_t samples = isobmff_samples_per_chunk(track, chunk);

    if (samples == 0) {
      return false;
    }
    for (uint32_t in_chunk = 0; in_chunk < samples; in_chunk++) {
      if (sample >= track->sample_count) {
        return false;
      }
      uint64_t sample_size = isobmff_sample_size(track, sample);
      if (sample_size > UINT64_MAX - position
          || position + sample_size > length
          || !isobmff_offset_in_mdat(layout, position, sample_size)) {
        return false;
      }
      if (strong) {
        track->strong_samples++;
        layout->strong_samples++;
        if (!isobmff_sample_content_valid(track, data + position,
                                          sample_size)) {
          track->invalid_strong_samples++;
          layout->invalid_strong_samples++;
        }
      }
      position += sample_size;
      sample++;
    }
  }
  return sample == track->sample_count;
}


static inline IsoBmffParseResult isobmff_parse_file(
    const uint8_t *data, uint64_t length, IsoBmffLayout *layout) {

  if (!layout) {
    return ISOBMFF_PARSE_INVALID;
  }
  memset(layout, 0, sizeof(*layout));
  layout->required_extent = UINT64_MAX;
  layout->failure_offset = 0;

  if (!data || length < ISOBMFF_MINIMUM_SIZE) {
    return ISOBMFF_PARSE_INVALID;
  }
  uint64_t position = 0;
  bool first = true;

  while (position < length) {
    IsoBmffBox box;

    if (!isobmff_box_at(data, length, position, &box)
        || (!isobmff_is_known_top_level(box.type)
            && !isobmff_type_printable(box.type))) {
      layout->failure_offset = position;
      break;
    }
    if (first && box.type != ISOBMFF_FOURCC('f', 't', 'y', 'p')
        && box.type != ISOBMFF_FOURCC('m', 'd', 'a', 't')
        && box.type != ISOBMFF_FOURCC('m', 'o', 'o', 'v')
        && box.type != ISOBMFF_FOURCC('w', 'i', 'd', 'e')
        && box.type != ISOBMFF_FOURCC('f', 'r', 'e', 'e')) {
      return ISOBMFF_PARSE_INVALID;
    }
    if (box.size > length - position) {
      layout->required_extent = position + box.size;
      layout->failure_offset = position;
      if (box.type == ISOBMFF_FOURCC('m', 'd', 'a', 't')
          && !isobmff_record_mdat(layout, &box)) {
        return ISOBMFF_PARSE_INVALID;
      }
      if (layout->top_level_boxes > 0
          || box.type == ISOBMFF_FOURCC('f', 't', 'y', 'p')
          || box.type == ISOBMFF_FOURCC('m', 'd', 'a', 't')
          || box.type == ISOBMFF_FOURCC('m', 'o', 'o', 'v')) {
        layout->parsed_extent = position + box.header_size;
        return ISOBMFF_PARSE_PARTIAL;
      }
      return ISOBMFF_PARSE_INVALID;
    }
    if (box.type == ISOBMFF_FOURCC('f', 't', 'y', 'p')) {
      if (box.size < box.header_size + 8 || layout->saw_ftyp) {
        layout->failure_offset = position;
        break;
      }
      layout->saw_ftyp = true;
      layout->major_brand = isobmff_read_be32(data + position
                                               + box.header_size);
      if (isobmff_brand_kind(layout->major_brand)
          == ISOBMFF_KIND_UNKNOWN) {
        layout->failure_offset = position;
        break;
      }
    }
    else if (box.type == ISOBMFF_FOURCC('m', 'd', 'a', 't')) {
      if (!isobmff_record_mdat(layout, &box)) {
        layout->failure_offset = position;
        break;
      }
    }
    else if (box.type == ISOBMFF_FOURCC('m', 'o', 'o', 'v')) {
      if (layout->saw_moov
          || !isobmff_parse_moov(data, length, &box, layout)) {
        layout->failure_offset = position;
        break;
      }
      layout->saw_moov = true;
      layout->moov_offset = position;
      layout->moov_size = box.size;
    }
    else if (box.type == ISOBMFF_FOURCC('m', 'o', 'o', 'f')) {
      layout->saw_fragment = true;
    }
    position += box.size;
    layout->parsed_extent = position;
    layout->top_level_boxes++;
    first = false;
    if (box.extends_to_end) {
      break;
    }
  }

  if (layout->top_level_boxes == 0) {
    return ISOBMFF_PARSE_INVALID;
  }
  if (!layout->saw_moov && !layout->saw_fragment) {
    if (layout->mdat_count > 0 && layout->parsed_extent > 0) {
      layout->required_extent = layout->parsed_extent;
    }
    return ISOBMFF_PARSE_PARTIAL;
  }
  if (layout->mdat_count == 0) {
    return ISOBMFF_PARSE_PARTIAL;
  }

  layout->metadata_valid = true;
  for (uint32_t track = 0; track < layout->track_count; track++) {
    if (!isobmff_validate_track_samples(data, layout->parsed_extent,
                                        layout, &layout->tracks[track])) {
      layout->metadata_valid = false;
      break;
    }
  }
  if (layout->failure_offset != 0 && layout->failure_offset < length) {
    return layout->metadata_valid ? ISOBMFF_PARSE_COMPLETE
                                  : ISOBMFF_PARSE_PARTIAL;
  }
  return layout->metadata_valid ? ISOBMFF_PARSE_COMPLETE
                                : ISOBMFF_PARSE_PARTIAL;
}


static inline bool isobmff_copy_actual_bytes(uint64_t actual_offset,
                                              uint8_t *output,
                                              uint64_t length) {

  if ((!output && length > 0) || scalpel_state.blocksize == 0
      || actual_offset > filemirror_filesize(scalpel_state.filemirror)
      || length > filemirror_filesize(scalpel_state.filemirror)
                    - actual_offset) {
    return false;
  }
  while (length > 0) {
    uint64_t block = actual_offset / scalpel_state.blocksize;
    uint64_t within = actual_offset % scalpel_state.blocksize;
    uint64_t available = 0;
    const uint8_t *source = (const uint8_t *)
        filemirror_actual_block_data_pointer(
            scalpel_state.filemirror, (int64_t)block, &available);

    if (!source || within >= available) {
      return false;
    }
    uint64_t count = available - within;
    if (count > length) {
      count = length;
    }
    memcpy(output, source + within, (size_t)count);
    output += count;
    actual_offset += count;
    length -= count;
  }
  return true;
}


static inline int64_t isobmff_actual_to_apparent(int64_t actual) {

  if (actual < 0) {
    return -1;
  }
  int64_t apparent = filemirror_apparent_blocknumber(
      scalpel_state.filemirror, actual);
  if (apparent >= 0) {
    return apparent;
  }
  int64_t exemplar = filemirror_get_exemplar(
      scalpel_state.filemirror, actual);
  return exemplar >= 0
      ? filemirror_apparent_blocknumber(scalpel_state.filemirror, exemplar)
      : -1;
}


// Read only top-level headers from the physical run beginning at the file
// header. The declared mdat extent fixes the logical position at which a
// terminal moov must begin without reading or trusting the opaque payload.
static inline bool isobmff_layout_from_header(
    const CarveInfo *candidate, IsoBmffKind requested,
    uint64_t *moov_offset, uint64_t *mdat_start, uint64_t *mdat_end) {

  if (!candidate || !candidate->b || !moov_offset || !mdat_start
      || !mdat_end || scalpel_state.blocksize == 0) {
    return false;
  }
  int64_t header_block = blockvector_get_actual_blocknumber(candidate->b, 0);
  if (header_block < 0) {
    return false;
  }
  uint64_t header_within = candidate->start % scalpel_state.blocksize;
  if ((uint64_t)header_block
          > (UINT64_MAX - header_within) / scalpel_state.blocksize) {
    return false;
  }
  uint64_t header_actual = (uint64_t)header_block
                           * scalpel_state.blocksize + header_within;
  uint64_t position = 0;
  bool saw_ftyp = false;

  for (uint32_t box_index = 0; box_index < 64; box_index++) {
    uint8_t encoded[24];
    if (position > UINT64_MAX - header_actual
        || !isobmff_copy_actual_bytes(header_actual + position,
                                   encoded, sizeof(encoded))) {
      return false;
    }
    uint64_t size = isobmff_read_be32(encoded);
    uint64_t header_size = 8;
    uint32_t type = isobmff_read_be32(encoded + 4);

    if (size == 1) {
      size = isobmff_read_be64(encoded + 8);
      header_size = 16;
    }
    if (size == 0 || size < header_size
        || size > ISOBMFF_MAXIMUM_SIZE
        || size > UINT64_MAX - position) {
      return false;
    }
    if (type == ISOBMFF_FOURCC('f', 't', 'y', 'p')) {
      if (saw_ftyp || size < header_size + 8) {
        return false;
      }
      IsoBmffKind observed = isobmff_brand_kind(
          isobmff_read_be32(encoded + header_size));
      if (observed != requested) {
        return false;
      }
      saw_ftyp = true;
    }
    else if (type == ISOBMFF_FOURCC('m', 'd', 'a', 't')) {
      *mdat_start = position + header_size;
      *mdat_end = position + size;
      *moov_offset = *mdat_end;
      return true;
    }
    else if (type != ISOBMFF_FOURCC('w', 'i', 'd', 'e')
             && type != ISOBMFF_FOURCC('f', 'r', 'e', 'e')
             && type != ISOBMFF_FOURCC('s', 'k', 'i', 'p')) {
      return false;
    }
    position += size;
  }
  return false;
}


static inline bool isobmff_layout_sample_bounds(
    const IsoBmffLayout *layout, uint64_t mdat_start, uint64_t mdat_end,
    uint64_t *tail_slack, uint64_t *sample_count) {

  if (!layout || !tail_slack || !sample_count || mdat_start >= mdat_end
      || layout->track_count == 0) {
    return false;
  }
  uint64_t maximum_end = 0;
  uint64_t samples_total = 0;

  for (uint32_t track_index = 0; track_index < layout->track_count;
       track_index++) {
    const IsoBmffTrack *track = &layout->tracks[track_index];
    uint64_t sample = 0;

    for (uint64_t chunk = 0; chunk < track->chunk_count; chunk++) {
      uint64_t position = track->chunk_offsets[chunk];
      uint32_t samples = isobmff_samples_per_chunk(track, chunk);

      if (samples == 0 || position < mdat_start || position >= mdat_end) {
        return false;
      }
      for (uint32_t in_chunk = 0; in_chunk < samples; in_chunk++) {
        if (sample >= track->sample_count) {
          return false;
        }
        uint64_t size = isobmff_sample_size(track, sample);
        if (size > UINT64_MAX - position || position + size > mdat_end) {
          return false;
        }
        position += size;
        sample++;
      }
      if (position > maximum_end) {
        maximum_end = position;
      }
    }
    if (sample != track->sample_count
        || sample > UINT64_MAX - samples_total) {
      return false;
    }
    samples_total += sample;
  }
  if (maximum_end == 0 || maximum_end > mdat_end) {
    return false;
  }
  *tail_slack = mdat_end - maximum_end;
  *sample_count = samples_total;
  return true;
}


static inline bool isobmff_load_footer_layout(
    const SearchSpec *spec, uint64_t footer_index,
    uint8_t **moov_data, uint64_t *moov_actual,
    uint64_t *moov_size, IsoBmffLayout *layout) {

  if (!spec || !moov_data || !moov_actual || !moov_size || !layout
      || footer_index >= spec->offsets.numfooters
      || spec->offsets.footers[footer_index] == 0
      || spec->offsets.footerlens[footer_index] == 0) {
    return false;
  }
  uint64_t actual = spec->offsets.footers[footer_index] - 1;
  uint64_t size = (uint64_t)spec->offsets.footerlens[footer_index] + 1;
  if (size < 16 || size > ISOBMFF_MAXIMUM_SIZE
      || size > SIZE_MAX) {
    return false;
  }
  uint8_t *data = (uint8_t *)malloc((size_t)size);
  check_memory_allocation(data, __LINE__, __FILE__, "ISO BMFF moov");
  if (!isobmff_copy_actual_bytes(actual, data, size)) {
    free(data);
    return false;
  }
  IsoBmffBox moov;
  memset(layout, 0, sizeof(*layout));
  if (!isobmff_box_at(data, size, 0, &moov)
      || moov.type != ISOBMFF_FOURCC('m', 'o', 'o', 'v')
      || moov.size != size
      || !isobmff_parse_moov(data, size, &moov, layout)) {
    isobmff_free_layout(layout);
    free(data);
    return false;
  }
  *moov_data = data;
  *moov_actual = actual;
  *moov_size = size;
  return true;
}


static inline bool isobmff_anchor_bytes_valid(
    const IsoBmffAnchor *anchor, const uint8_t *data,
    uint64_t available) {

  if (!anchor || !data) {
    return false;
  }
  if (anchor->codec == ISOBMFF_FOURCC('m', 'p', '4', 'v')) {
    return available >= 4 && isobmff_mpeg4_sample_valid(data, 4);
  }
  if (anchor->codec == ISOBMFF_FOURCC('a', 'v', 'c', '1')
      || anchor->codec == ISOBMFF_FOURCC('a', 'v', 'c', '3')
      || anchor->codec == ISOBMFF_FOURCC('h', 'v', 'c', '1')
      || anchor->codec == ISOBMFF_FOURCC('h', 'e', 'v', '1')) {
    uint8_t width = anchor->nal_length_size;
    if (width < 1 || width > 4 || available < (uint64_t)width + 1) {
      return false;
    }
    uint32_t unit_length = 0;
    for (uint8_t byte = 0; byte < width; byte++) {
      unit_length = (unit_length << 8) | data[byte];
    }
    if (anchor->sample_size < width || unit_length == 0
        || (uint64_t)unit_length > anchor->sample_size - width) {
      return false;
    }
    bool hevc = anchor->codec == ISOBMFF_FOURCC('h', 'v', 'c', '1')
        || anchor->codec == ISOBMFF_FOURCC('h', 'e', 'v', '1');
    uint8_t type = hevc ? (data[width] >> 1) & 0x3fU
                        : data[width] & 0x1fU;
    return hevc ? type <= 63 : type > 0 && type <= 23;
  }
  if (anchor->codec == ISOBMFF_FOURCC('j', 'p', 'e', 'g')
      || anchor->codec == ISOBMFF_FOURCC('m', 'j', 'p', 'a')
      || anchor->codec == ISOBMFF_FOURCC('m', 'j', 'p', 'b')) {
    return available >= 2 && data[0] == 0xff && data[1] == 0xd8;
  }
  if (anchor->codec == ISOBMFF_FOURCC('p', 'n', 'g', ' ')) {
    static const uint8_t signature[8] = {
      0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a
    };
    return available >= sizeof(signature)
        && memcmp(data, signature, sizeof(signature)) == 0;
  }
  if (anchor->codec == ISOBMFF_FOURCC('t', 'g', 'a', ' ')) {
    uint64_t pixel_offset = 0;
    uint64_t pixel_count = 0;
    uint8_t pixel_bytes = 0;
    bool rle = false;
    return isobmff_tga_header_valid(
        data, available, &pixel_offset, &pixel_count, &pixel_bytes, &rle);
  }
  if (anchor->codec == ISOBMFF_FOURCC('s', '2', '6', '3')) {
    return isobmff_h263_sample_valid(data, available);
  }
  if (anchor->codec == ISOBMFF_FOURCC('s', 'a', 'm', 'r')) {
    return available > 0
        && isobmff_amr_nb_frame_size(data[0]) == anchor->sample_size;
  }
  if (anchor->codec == ISOBMFF_FOURCC('a', 'c', '-', '3')) {
    return isobmff_ac3_frame_size(data, available) == anchor->sample_size;
  }
  if (anchor->codec == ISOBMFF_FOURCC('a', 'v', 's', '2')) {
    if (available < 6) {
      return false;
    }
    uint32_t unit_size = isobmff_read_be32(data);
    return unit_size >= 2 && (uint64_t)unit_size + 4 <= anchor->sample_size
        && (data[5] == 0xb0 || data[5] == 0xb2 || data[5] == 0xb3
            || data[5] == 0xb6 || data[5] == 0xb7);
  }
  if (anchor->codec == ISOBMFF_FOURCC('S', 'V', 'Q', '1')) {
    if (available < 4) {
      return false;
    }
    uint32_t header = isobmff_read_be32(data);
    uint32_t frame_code = header >> 10;
    return (frame_code & ~0x70U) == 0 && (frame_code & 0x60U) != 0
        && (header & 0x03U) != 3
        && (frame_code == 0x20 || anchor->sample_size >= 36);
  }
  if (anchor->codec == ISOBMFF_FOURCC('a', 'l', 'a', 'c')) {
    return isobmff_alac_anchor_valid(
        data, available, anchor->sample_size, &anchor->alac);
  }
  if (anchor->codec == ISOBMFF_FOURCC('P', 'G', 'V', 'V')) {
    return isobmff_pgvv_anchor_valid(
        data, available, anchor->sample_size);
  }
  if (anchor->codec == ISOBMFF_FOURCC('m', 'd', 'a', 't')) {
    if (available < 8
        || isobmff_read_be32(data + 4)
               != ISOBMFF_FOURCC('m', 'd', 'a', 't')) {
      return false;
    }
    uint64_t size = isobmff_read_be32(data);
    uint64_t header_size = 8;
    if (size == 1) {
      if (available < 16) {
        return false;
      }
      size = isobmff_read_be64(data + 8);
      header_size = 16;
    }
    return size >= header_size && size <= ISOBMFF_MAXIMUM_SIZE;
  }
  return false;
}


static inline bool isobmff_anchor_at_delta(
    const IsoBmffAnchor *anchor, int64_t delta) {

  if (!anchor || scalpel_state.blocksize == 0) {
    return false;
  }
  uint64_t logical_block = anchor->logical_offset
                           / scalpel_state.blocksize;
  if (logical_block > (uint64_t)INT64_MAX
      || (delta < 0 && logical_block < (uint64_t)(-delta))
      || (delta > 0
          && logical_block > (uint64_t)(INT64_MAX - delta))) {
    return false;
  }
  int64_t actual_block = (int64_t)logical_block + delta;
  if (actual_block < 0
      || (uint64_t)actual_block
             > UINT64_MAX / scalpel_state.blocksize) {
    return false;
  }
  uint64_t within = anchor->logical_offset % scalpel_state.blocksize;
  uint64_t required = 8;
  if (anchor->codec == ISOBMFF_FOURCC('t', 'g', 'a', ' ')) {
    required = 18;
  }
  else if (anchor->codec == ISOBMFF_FOURCC('s', '2', '6', '3')) {
    required = 4;
  }
  else if (anchor->codec == ISOBMFF_FOURCC('s', 'a', 'm', 'r')) {
    required = 1;
  }
  else if (anchor->codec == ISOBMFF_FOURCC('a', 'c', '-', '3')) {
    required = 6;
  }
  else if (anchor->codec == ISOBMFF_FOURCC('a', 'v', 's', '2')) {
    required = 6;
  }
  else if (anchor->codec == ISOBMFF_FOURCC('S', 'V', 'Q', '1')) {
    required = 4;
  }
  else if (anchor->codec == ISOBMFF_FOURCC('a', 'l', 'a', 'c')) {
    required = 32;
  }
  else if (anchor->codec == ISOBMFF_FOURCC('P', 'G', 'V', 'V')) {
    required = 32;
  }
  else if (anchor->codec == ISOBMFF_FOURCC('m', 'd', 'a', 't')) {
    required = 16;
  }
  if (anchor->nal_length_size > 0
      && required < (uint64_t)anchor->nal_length_size + 1) {
    required = (uint64_t)anchor->nal_length_size + 1;
  }
  if (required > anchor->sample_size) {
    required = anchor->sample_size;
  }
  uint8_t encoded[32] = {0};
  uint64_t actual_offset = (uint64_t)actual_block
                           * scalpel_state.blocksize + within;
  return required > 0 && isobmff_copy_actual_bytes(
      actual_offset, encoded, required)
      && isobmff_anchor_bytes_valid(anchor, encoded, required);
}


static inline int isobmff_anchor_compare(const void *left,
                                          const void *right) {

  const IsoBmffAnchor *a = (const IsoBmffAnchor *)left;
  const IsoBmffAnchor *b = (const IsoBmffAnchor *)right;
  if (a->logical_offset < b->logical_offset) {
    return -1;
  }
  if (a->logical_offset > b->logical_offset) {
    return 1;
  }
  if (a->sample_size < b->sample_size) {
    return -1;
  }
  return a->sample_size > b->sample_size;
}


static inline bool isobmff_collect_anchors(
    const IsoBmffLayout *layout, IsoBmffAnchor **anchors,
    uint64_t *anchor_count) {

  if (!layout || !anchors || !anchor_count) {
    return false;
  }
  *anchors = NULL;
  *anchor_count = 0;
  uint64_t capacity = 0;

  for (uint32_t track_index = 0; track_index < layout->track_count;
       track_index++) {
    const IsoBmffTrack *track = &layout->tracks[track_index];
    if (!isobmff_sample_anchorable(track)) {
      continue;
    }
    if (track->sample_count > UINT64_MAX - capacity) {
      return false;
    }
    capacity += track->sample_count;
  }
  if (capacity == 0 || capacity > SIZE_MAX / sizeof(**anchors)) {
    return false;
  }
  IsoBmffAnchor *result = (IsoBmffAnchor *)calloc(
      (size_t)capacity, sizeof(*result));
  check_memory_allocation(result, __LINE__, __FILE__,
                          "ISO BMFF sample anchors");
  uint64_t count = 0;

  for (uint32_t track_index = 0; track_index < layout->track_count;
       track_index++) {
    const IsoBmffTrack *track = &layout->tracks[track_index];
    if (!isobmff_sample_anchorable(track)) {
      continue;
    }
    uint64_t sample = 0;
    for (uint64_t chunk = 0; chunk < track->chunk_count; chunk++) {
      uint64_t position = track->chunk_offsets[chunk];
      uint32_t samples = isobmff_samples_per_chunk(track, chunk);
      for (uint32_t in_chunk = 0; in_chunk < samples; in_chunk++) {
        if (sample >= track->sample_count || count >= capacity) {
          free(result);
          return false;
        }
        uint64_t size = isobmff_sample_size(track, sample);
        result[count++] = (IsoBmffAnchor){
            .logical_offset = position,
            .sample_size = size,
            .codec = track->codec,
            .nal_length_size = track->nal_length_size,
            .alac = track->alac
        };
        if (size > UINT64_MAX - position) {
          free(result);
          return false;
        }
        position += size;
        sample++;
      }
    }
  }
  if (count == 0 || scalpel_state.blocksize == 0) {
    free(result);
    return false;
  }
  qsort(result, (size_t)count, sizeof(*result), isobmff_anchor_compare);

  uint64_t compact = 0;
  for (uint64_t first = 0; first < count;) {
    uint64_t block = result[first].logical_offset / scalpel_state.blocksize;
    uint64_t last = first;
    while (last + 1 < count
           && result[last + 1].logical_offset / scalpel_state.blocksize
                  == block) {
      last++;
    }
    result[compact++] = result[first];
    if (last != first) {
      result[compact++] = result[last];
    }
    first = last + 1;
  }
  *anchors = result;
  *anchor_count = compact;
  return true;
}


static inline int isobmff_anchor_event_compare(const void *left,
                                                const void *right) {

  const IsoBmffAnchorEvent *a = (const IsoBmffAnchorEvent *)left;
  const IsoBmffAnchorEvent *b = (const IsoBmffAnchorEvent *)right;
  if (a->logical_block < b->logical_block) {
    return -1;
  }
  return a->logical_block > b->logical_block;
}


static inline bool isobmff_build_anchor_events(
    const IsoBmffAnchor *anchors, uint64_t anchor_count,
    int64_t prefix_delta, int64_t suffix_delta,
    IsoBmffAnchorEvent **events, uint64_t *event_count) {

  if (!anchors || anchor_count == 0 || !events || !event_count
      || anchor_count > SIZE_MAX / sizeof(**events)) {
    return false;
  }
  IsoBmffAnchorEvent *result = (IsoBmffAnchorEvent *)calloc(
      (size_t)anchor_count, sizeof(*result));
  check_memory_allocation(result, __LINE__, __FILE__,
                          "ISO BMFF anchor events");

  for (uint64_t index = 0; index < anchor_count; index++) {
    result[index].logical_block = anchors[index].logical_offset
                                  / scalpel_state.blocksize;
    result[index].prefix_good = isobmff_anchor_at_delta(
        &anchors[index], prefix_delta);
    result[index].suffix_good = isobmff_anchor_at_delta(
        &anchors[index], suffix_delta);
    result[index].samples = 1;
  }
  qsort(result, (size_t)anchor_count, sizeof(*result),
        isobmff_anchor_event_compare);
  uint64_t distinct = 0;
  for (uint64_t index = 0; index < anchor_count; index++) {
    if (distinct > 0
        && result[distinct - 1].logical_block
               == result[index].logical_block) {
      result[distinct - 1].prefix_good += result[index].prefix_good;
      result[distinct - 1].suffix_good += result[index].suffix_good;
      result[distinct - 1].samples += result[index].samples;
    }
    else {
      result[distinct++] = result[index];
    }
  }
  *events = result;
  *event_count = distinct;
  return true;
}


static inline bool isobmff_solution_actual_block(
    int64_t prefix_delta, int64_t suffix_delta,
    const IsoBmffSolution *solution, uint64_t slot,
    int64_t *actual_block) {

  if (!solution || !actual_block) {
    return false;
  }
  int64_t delta = slot < solution->base_split
      ? prefix_delta : suffix_delta;
  if (solution->middle_delta != ISOBMFF_NO_MIDDLE_DELTA
      && slot >= solution->first_split
      && slot < solution->second_split) {
    delta = solution->middle_delta;
  }
  if (slot > (uint64_t)INT64_MAX
      || (delta < 0 && slot < (uint64_t)(-delta))
      || (delta > 0 && slot > (uint64_t)(INT64_MAX - delta))) {
    return false;
  }
  *actual_block = (int64_t)slot + delta;
  return *actual_block >= 0;
}


static inline uint64_t isobmff_solution_first_discontinuity(
    int64_t prefix_delta, int64_t suffix_delta,
    const IsoBmffSolution *solution, uint64_t logical_blocks) {

  if (!solution || logical_blocks < 2) {
    return UINT64_MAX;
  }
  uint64_t boundaries[3] = {
    solution->base_split,
    solution->first_split,
    solution->second_split
  };
  uint64_t first = UINT64_MAX;

  for (uint32_t index = 0; index < 3; index++) {
    uint64_t boundary = boundaries[index];
    int64_t before = -1;
    int64_t after = -1;
    if (boundary == 0 || boundary >= logical_blocks
        || !isobmff_solution_actual_block(
            prefix_delta, suffix_delta, solution,
            boundary - 1, &before)
        || !isobmff_solution_actual_block(
            prefix_delta, suffix_delta, solution,
            boundary, &after)) {
      continue;
    }
    if ((before == INT64_MAX || after != before + 1)
        && boundary < first) {
      first = boundary;
    }
  }
  return first;
}


static inline bool isobmff_read_solution_bytes(
    int64_t prefix_delta, int64_t suffix_delta,
    const IsoBmffSolution *solution, uint64_t logical_offset,
    uint8_t *data, uint64_t length) {

  if (!solution || !data || scalpel_state.blocksize == 0) {
    return false;
  }
  while (length > 0) {
    uint64_t slot = logical_offset / scalpel_state.blocksize;
    uint64_t within = logical_offset % scalpel_state.blocksize;
    uint64_t count = scalpel_state.blocksize - within;
    int64_t actual_block = -1;

    if (count > length) {
      count = length;
    }
    if (!isobmff_solution_actual_block(
            prefix_delta, suffix_delta, solution, slot, &actual_block)
        || (uint64_t)actual_block
               > (UINT64_MAX - within) / scalpel_state.blocksize
        || !isobmff_copy_actual_bytes(
            (uint64_t)actual_block * scalpel_state.blocksize + within,
            data, count)) {
      return false;
    }
    logical_offset += count;
    data += count;
    length -= count;
  }
  return true;
}


static inline bool isobmff_alac_boundary_sample(
    const IsoBmffTrack *track, uint64_t boundary,
    uint64_t *sample_offset, uint64_t *sample_size) {

  if (!track || !sample_offset || !sample_size || !track->alac.valid) {
    return false;
  }
  uint64_t sample = 0;
  for (uint64_t chunk = 0; chunk < track->chunk_count; chunk++) {
    uint64_t position = track->chunk_offsets[chunk];
    uint32_t samples = isobmff_samples_per_chunk(track, chunk);
    for (uint32_t in_chunk = 0; in_chunk < samples; in_chunk++) {
      if (sample >= track->sample_count) {
        return false;
      }
      uint64_t size = isobmff_sample_size(track, sample++);
      if (size > UINT64_MAX - position) {
        return false;
      }
      uint64_t end = position + size;
      if (position < boundary && boundary < end) {
        *sample_offset = position;
        *sample_size = size;
        return true;
      }
      position = end;
    }
  }
  return false;
}


static inline bool isobmff_solution_alac_boundaries_valid(
    const IsoBmffFooterContext *context, int64_t prefix_delta,
    int64_t suffix_delta, const IsoBmffSolution *solution) {

  if (!context || !solution || scalpel_state.blocksize == 0
      || solution->first_split > UINT64_MAX / scalpel_state.blocksize
      || solution->second_split > UINT64_MAX / scalpel_state.blocksize) {
    return false;
  }
  uint64_t boundaries[2] = {
    solution->first_split * scalpel_state.blocksize,
    solution->second_split * scalpel_state.blocksize
  };
  for (uint32_t track_index = 0;
       track_index < context->layout.track_count; track_index++) {
    const IsoBmffTrack *track = &context->layout.tracks[track_index];
    if (track->codec != ISOBMFF_FOURCC('a', 'l', 'a', 'c')
        || !track->alac.valid) {
      continue;
    }
    uint64_t prior_offset = UINT64_MAX;
    for (uint32_t index = 0; index < 2; index++) {
      uint64_t offset = 0;
      uint64_t size = 0;
      if (!isobmff_alac_boundary_sample(
              track, boundaries[index], &offset, &size)
          || offset == prior_offset) {
        continue;
      }
      if (size == 0 || size > SIZE_MAX) {
        return false;
      }
      uint8_t *sample = (uint8_t *)malloc((size_t)size);
      if (!sample) {
        return false;
      }
      bool valid = isobmff_read_solution_bytes(
          prefix_delta, suffix_delta, solution, offset, sample, size)
          && isobmff_alac_frame_valid(sample, size, &track->alac);
      free(sample);
      if (!valid) {
        return false;
      }
      prior_offset = offset;
    }
  }
  return true;
}


static inline bool isobmff_tga_sample_by_ordinal(
    const IsoBmffLayout *layout, uint64_t ordinal,
    uint64_t *sample_offset, uint64_t *sample_size) {

  if (!layout || !sample_offset || !sample_size) {
    return false;
  }
  uint64_t current = 0;
  for (uint32_t track_index = 0; track_index < layout->track_count;
       track_index++) {
    const IsoBmffTrack *track = &layout->tracks[track_index];
    if (track->codec != ISOBMFF_FOURCC('t', 'g', 'a', ' ')) {
      continue;
    }
    uint64_t sample = 0;
    for (uint64_t chunk = 0; chunk < track->chunk_count; chunk++) {
      uint64_t position = track->chunk_offsets[chunk];
      uint32_t samples = isobmff_samples_per_chunk(track, chunk);
      if (samples == 0) {
        return false;
      }
      for (uint32_t in_chunk = 0; in_chunk < samples; in_chunk++) {
        if (sample >= track->sample_count) {
          return false;
        }
        uint64_t size = isobmff_sample_size(track, sample++);
        if (size > UINT64_MAX - position) {
          return false;
        }
        if (current++ == ordinal) {
          *sample_offset = position;
          *sample_size = size;
          return true;
        }
        position += size;
      }
    }
  }
  return false;
}


static inline bool isobmff_layout_has_tga(const IsoBmffLayout *layout) {

  if (!layout) {
    return false;
  }
  for (uint32_t index = 0; index < layout->track_count; index++) {
    if (layout->tracks[index].codec
        == ISOBMFF_FOURCC('t', 'g', 'a', ' ')) {
      return true;
    }
  }
  return false;
}


static inline bool isobmff_tga_feed_actual_range(
    IsoBmffTgaRleState *state, uint64_t actual_offset,
    uint64_t length) {

  if (!state || scalpel_state.blocksize == 0
      || actual_offset > filemirror_filesize(scalpel_state.filemirror)
      || length > filemirror_filesize(scalpel_state.filemirror)
                    - actual_offset) {
    return false;
  }
  while (length > 0) {
    uint64_t block = actual_offset / scalpel_state.blocksize;
    uint64_t within = actual_offset % scalpel_state.blocksize;
    uint64_t available = 0;
    const uint8_t *source = (const uint8_t *)
        filemirror_actual_block_data_pointer(
            scalpel_state.filemirror, (int64_t)block, &available);
    if (!source || within >= available) {
      return false;
    }
    uint64_t count = available - within;
    if (count > length) {
      count = length;
    }
    if (!isobmff_tga_rle_stream_feed(state, source + within, count)) {
      return false;
    }
    actual_offset += count;
    length -= count;
  }
  return true;
}


static inline bool isobmff_tga_feed_logical_range(
    IsoBmffTgaRleState *state, int64_t prefix_delta,
    int64_t suffix_delta, uint64_t base_split,
    uint64_t logical_offset, uint64_t length) {

  IsoBmffSolution baseline = {
    .footer_offset = UINT64_MAX,
    .base_split = base_split,
    .first_split = UINT64_MAX,
    .second_split = UINT64_MAX,
    .middle_delta = ISOBMFF_NO_MIDDLE_DELTA
  };

  if (!state || scalpel_state.blocksize == 0) {
    return false;
  }
  while (length > 0) {
    uint64_t slot = logical_offset / scalpel_state.blocksize;
    uint64_t within = logical_offset % scalpel_state.blocksize;
    uint64_t count = scalpel_state.blocksize - within;
    int64_t actual_block = -1;
    if (count > length) {
      count = length;
    }
    if (!isobmff_solution_actual_block(
            prefix_delta, suffix_delta, &baseline, slot, &actual_block)
        || (uint64_t)actual_block
               > (UINT64_MAX - within) / scalpel_state.blocksize
        || !isobmff_tga_feed_actual_range(
            state, (uint64_t)actual_block * scalpel_state.blocksize
                     + within,
            count)) {
      return false;
    }
    logical_offset += count;
    length -= count;
  }
  return true;
}


static inline bool isobmff_tga_configure_middle_search(
    const IsoBmffFooterContext *context, IsoBmffCarveState *state) {

  if (!context || !state || !state->tga.initialized
      || scalpel_state.blocksize == 0 || state->tga_sample_size == 0
      || state->tga_sample_offset
             > UINT64_MAX - state->tga_sample_size
      || state->tga_sample_offset
             > UINT64_MAX - state->tga.pixel_offset) {
    return false;
  }
  uint64_t blocksize = scalpel_state.blocksize;
  uint64_t sample_end = state->tga_sample_offset
                        + state->tga_sample_size;
  uint64_t data_offset = state->tga_sample_offset
                         + state->tga.pixel_offset;
  uint64_t data_first = data_offset / blocksize
                        + (data_offset % blocksize != 0);
  uint64_t second_limit = sample_end / blocksize
                          + (sample_end % blocksize != 0);
  if (second_limit > context->maximum_split) {
    second_limit = context->maximum_split;
  }
  if (data_first == 0) {
    data_first = 1;
  }
  if (second_limit <= data_first) {
    return false;
  }

  uint64_t failure = state->tga.failure_offset == UINT64_MAX
      ? state->tga_sample_size - 1 : state->tga.failure_offset;
  if (failure >= state->tga_sample_size
      || failure > UINT64_MAX - state->tga_sample_offset) {
    failure = state->tga_sample_size - 1;
  }
  uint64_t first_max = (state->tga_sample_offset + failure) / blocksize;
  if (first_max >= second_limit) {
    first_max = second_limit - 1;
  }
  if (first_max < data_first) {
    return false;
  }

  uint64_t row_bytes = (uint64_t)state->tga.width
                       * ((uint64_t)state->tga.pixel_bytes + 1U);
  uint64_t back_blocks = row_bytes / blocksize
                         + (row_bytes % blocksize != 0) + 1U;
  uint64_t first_min = first_max > back_blocks
      ? first_max - back_blocks : data_first;
  if (first_min < data_first) {
    first_min = data_first;
  }

  state->tga_data_first_split = data_first;
  state->best_first_split = first_min;
  state->best_last_split = first_max;
  state->middle_first_cursor = first_min;
  state->middle_actual_cursor = 0;
  state->middle_second_cursor = 0;
  state->stage = ISOBMFF_STAGE_TGA_MIDDLE_RUN;
  return true;
}


static inline bool isobmff_solution_nonoverlapping(
    const IsoBmffFooterContext *context, uint64_t base_split,
    uint64_t first, uint64_t second, uint64_t actual,
    uint64_t logical_blocks) {

  if (!context || context->prefix_delta < 0 || context->suffix_delta < 0
      || base_split == 0 || base_split > logical_blocks || first >= second
      || second > logical_blocks || actual > UINT64_MAX - (second - first)) {
    return false;
  }

  uint64_t middle_end = actual + (second - first);
  uint64_t logical_start[2] = {0, second};
  uint64_t logical_end[2] = {first, logical_blocks};
  for (uint32_t range = 0; range < 2; range++) {
    uint64_t prefix_end = logical_end[range] < base_split
        ? logical_end[range] : base_split;
    if (logical_start[range] < prefix_end) {
      uint64_t delta = (uint64_t)context->prefix_delta;
      if (logical_start[range] > UINT64_MAX - delta
          || prefix_end > UINT64_MAX - delta) {
        return false;
      }
      uint64_t mapped_start = logical_start[range] + delta;
      uint64_t mapped_end = prefix_end + delta;
      if (actual < mapped_end && mapped_start < middle_end) {
        return false;
      }
    }

    uint64_t suffix_start = logical_start[range] > base_split
        ? logical_start[range] : base_split;
    if (suffix_start < logical_end[range]) {
      uint64_t delta = (uint64_t)context->suffix_delta;
      if (suffix_start > UINT64_MAX - delta
          || logical_end[range] > UINT64_MAX - delta) {
        return false;
      }
      uint64_t mapped_start = suffix_start + delta;
      uint64_t mapped_end = logical_end[range] + delta;
      if (actual < mapped_end && mapped_start < middle_end) {
        return false;
      }
    }
  }
  return true;
}


static inline uint64_t isobmff_solution_extent(
    int64_t prefix_delta, int64_t suffix_delta,
    const IsoBmffSolution *solution, uint64_t base_extent) {

  uint64_t extent = base_extent;
  uint64_t image_size = filemirror_filesize(scalpel_state.filemirror);

  for (uint32_t box_index = 0; box_index < 64; box_index++) {
    uint8_t encoded[16];
    if (extent > image_size || image_size - extent < 8
        || !isobmff_read_solution_bytes(
            prefix_delta, suffix_delta, solution, extent,
            encoded, sizeof(uint64_t))) {
      break;
    }
    uint64_t size = isobmff_read_be32(encoded);
    uint64_t header_size = 8;
    uint32_t type = isobmff_read_be32(encoded + 4);

    if (!isobmff_is_known_top_level(type)) {
      break;
    }
    if (size == 1) {
      if (image_size - extent < sizeof(encoded)
          || !isobmff_read_solution_bytes(
              prefix_delta, suffix_delta, solution, extent,
              encoded, sizeof(encoded))) {
        break;
      }
      size = isobmff_read_be64(encoded + 8);
      header_size = 16;
    }
    else if (size == 0) {
      break;
    }
    if (size < header_size || size > ISOBMFF_MAXIMUM_SIZE
        || size > image_size - extent || size > SIZE_MAX - extent) {
      break;
    }
    extent += size;
  }
  return extent;
}


static inline bool isobmff_materialize_solution(
    int64_t prefix_delta, int64_t suffix_delta,
    const IsoBmffSolution *solution, uint64_t extent,
    uint8_t *data) {

  if (!solution || !data || scalpel_state.blocksize == 0) {
    return false;
  }
  uint64_t blocks = CEILDIV(extent, scalpel_state.blocksize);
  if (solution->base_split == 0 || solution->base_split > blocks
      || (solution->middle_delta != ISOBMFF_NO_MIDDLE_DELTA
          && (solution->first_split == 0
              || solution->second_split <= solution->first_split
              || solution->second_split > blocks))) {
    return false;
  }
  for (uint64_t slot = 0; slot < blocks; slot++) {
    int64_t actual_block = -1;
    if (!isobmff_solution_actual_block(
            prefix_delta, suffix_delta, solution, slot, &actual_block)
        || (uint64_t)actual_block
               > UINT64_MAX / scalpel_state.blocksize) {
      return false;
    }
    uint64_t offset = slot * (uint64_t)scalpel_state.blocksize;
    uint64_t count = extent - offset;
    if (count > scalpel_state.blocksize) {
      count = scalpel_state.blocksize;
    }
    if (!isobmff_copy_actual_bytes(
            (uint64_t)actual_block * scalpel_state.blocksize,
            data + offset, count)) {
      return false;
    }
  }
  return true;
}


static inline bool isobmff_solution_complete(
    int64_t prefix_delta, int64_t suffix_delta,
    const IsoBmffSolution *solution, uint64_t extent,
    uint8_t *data, IsoBmffLayout *layout) {

  if (!layout) {
    return false;
  }
  memset(layout, 0, sizeof(*layout));
  if (!isobmff_materialize_solution(prefix_delta, suffix_delta,
                                    solution, extent, data)) {
    return false;
  }
  IsoBmffParseResult result = isobmff_parse_file(data, extent, layout);
  return result == ISOBMFF_PARSE_COMPLETE && layout->metadata_valid
      && layout->saw_moov && layout->mdat_count > 0
      && layout->invalid_strong_samples == 0
      && layout->parsed_extent == extent && !layout->terminal_size;
}


static inline bool isobmff_commit_solution(
    CarveInfo *candidate, int64_t prefix_delta, int64_t suffix_delta,
    const IsoBmffSolution *solution, uint64_t extent) {

  if (!candidate || !candidate->b || !solution
      || scalpel_state.blocksize == 0) {
    return false;
  }
  uint64_t blocks = CEILDIV(extent, scalpel_state.blocksize);
  resize_blockvector(candidate->b, blocks);

  for (uint64_t slot = 0; slot < blocks; slot++) {
    int64_t actual_block = -1;
    if (!isobmff_solution_actual_block(
            prefix_delta, suffix_delta, solution, slot, &actual_block)) {
      return false;
    }
    int64_t apparent = isobmff_actual_to_apparent(
        actual_block);
    if (apparent < 0) {
      return false;
    }
    blockvector_set_apparent_blocknumber(candidate->b, slot, apparent);
  }
  normalize_blockvector(candidate->b);
  blockvector_set_data_length(candidate->b, extent);
  inflate_blockvector(candidate->b);
  candidate->chopped = false;
  candidate->best_validates_to = extent - 1;
  return true;
}


static inline bool isobmff_moov_prefix_valid(const uint8_t *data,
                                             uint64_t available,
                                             const IsoBmffBox *box) {

  if (!data || !box || box->type != ISOBMFF_FOURCC('m', 'o', 'o', 'v')
      || box->size < box->header_size + 8
      || available < box->header_size + 8) {
    return false;
  }
  IsoBmffBox child;
  if (!isobmff_box_at(data, available, box->header_size, &child)) {
    return false;
  }
  return child.type == ISOBMFF_FOURCC('m', 'v', 'h', 'd')
      || child.type == ISOBMFF_FOURCC('c', 'm', 'o', 'v')
      || child.type == ISOBMFF_FOURCC('t', 'r', 'a', 'k')
      || child.type == ISOBMFF_FOURCC('u', 'd', 't', 'a');
}


static inline char *isobmff_header_discovery(
    char *base, uint64_t offset, uint64_t remaining, char **matchpos,
    uint32_t *matchlen, IsoBmffKind requested) {

  if (!base || !matchpos || !matchlen) {
    return NULL;
  }
  *matchpos = NULL;
  *matchlen = 8;
  if (remaining < 16) {
    return NULL;
  }
  uint8_t *search = (uint8_t *)base + offset;
  uint64_t available = remaining;

  while (available >= 16) {
    uint8_t *found_f = (uint8_t *)memchr(search + 4, 'f',
                                        (size_t)(available - 4));
    uint8_t *found_m = requested == ISOBMFF_KIND_MOV
        ? (uint8_t *)memchr(search + 4, 'm', (size_t)(available - 4))
        : NULL;
    uint8_t *type = !found_f ? found_m : !found_m ? found_f
        : found_f < found_m ? found_f : found_m;

    if (!type || type < (uint8_t *)base + 4) {
      break;
    }
    uint8_t *start = type - 4;
    uint64_t consumed = (uint64_t)(start - search);
    if (consumed >= available) {
      break;
    }
    available -= consumed;
    IsoBmffBox box;
    uint64_t local_available = remaining
        - (uint64_t)(start - ((uint8_t *)base + offset));

    if (isobmff_box_at(start, local_available, 0, &box)) {
      if (box.type == ISOBMFF_FOURCC('f', 't', 'y', 'p')
          && local_available >= box.header_size + 8) {
        IsoBmffKind kind = isobmff_brand_kind(
            isobmff_read_be32(start + box.header_size));
        if (kind == requested) {
          *matchpos = (char *)start;
          return NULL;
        }
      }
      else if (requested == ISOBMFF_KIND_MOV
               && (box.type == ISOBMFF_FOURCC('m', 'd', 'a', 't')
                   || box.type == ISOBMFF_FOURCC('m', 'o', 'o', 'v'))
               && box.size >= box.header_size + 8
               && (box.type != ISOBMFF_FOURCC('m', 'o', 'o', 'v')
                   || isobmff_moov_prefix_valid(start,
                                                local_available, &box))) {
        *matchpos = (char *)start;
        return NULL;
      }
    }
    search = start + 1;
    available--;
  }
  return NULL;
}


static inline char *mov_header_discovery(
    char *base, uint64_t offset, uint64_t remaining, char **matchpos,
    uint32_t *matchlen, uint32_t blocksize) {

  (void)blocksize;
  return isobmff_header_discovery(base, offset, remaining, matchpos,
                                  matchlen, ISOBMFF_KIND_MOV);
}


static inline char *mp4_header_discovery(
    char *base, uint64_t offset, uint64_t remaining, char **matchpos,
    uint32_t *matchlen, uint32_t blocksize) {

  (void)blocksize;
  return isobmff_header_discovery(base, offset, remaining, matchpos,
                                  matchlen, ISOBMFF_KIND_MP4);
}


static inline char *isobmff_footer_discovery(
    char *base, uint64_t offset, uint64_t remaining, char **matchpos,
    uint32_t *matchlen, uint32_t blocksize) {

  (void)blocksize;
  if (!base || !matchpos || !matchlen) {
    return NULL;
  }
  *matchpos = NULL;
  *matchlen = 0;
  if (remaining < 16) {
    return NULL;
  }
  uint8_t *search = (uint8_t *)base + offset;
  uint64_t available = remaining;

  while (available >= 16) {
    uint8_t *type = (uint8_t *)memchr(search + 4, 'm',
                                     (size_t)(available - 4));
    if (!type || type < (uint8_t *)base + 4) {
      break;
    }
    uint8_t *start = type - 4;
    uint64_t consumed = (uint64_t)(start - search);
    available -= consumed;
    uint64_t local_available = remaining
        - (uint64_t)(start - ((uint8_t *)base + offset));
    IsoBmffBox box;

    if (isobmff_box_at(start, local_available, 0, &box)
        && box.type == ISOBMFF_FOURCC('m', 'o', 'o', 'v')
        && box.size <= UINT32_MAX
        && isobmff_moov_prefix_valid(start, local_available, &box)) {
      *matchpos = (char *)start + 1;
      *matchlen = (uint32_t)box.size - 1;
      return NULL;
    }
    search = start + 1;
    available--;
  }
  return NULL;
}


static inline uint32_t isobmff_block_validate(
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

  for (uint64_t position = 0; position + 8 <= length; position++) {
    uint32_t type = isobmff_read_be32(bytes + position + 4);

    if (type == ISOBMFF_FOURCC('f', 't', 'y', 'p')
        || type == ISOBMFF_FOURCC('m', 'o', 'o', 'v')
        || type == ISOBMFF_FOURCC('m', 'd', 'a', 't')
        || type == ISOBMFF_FOURCC('s', 't', 'c', 'o')
        || type == ISOBMFF_FOURCC('c', 'o', '6', '4')
        || type == ISOBMFF_FOURCC('s', 't', 's', 'z')
        || type == ISOBMFF_FOURCC('s', 't', 's', 'c')) {
      evidence = true;
      break;
    }
    if (position + 4 <= length
        && isobmff_mpeg4_sample_valid(bytes + position,
                                      length - position)) {
      evidence = true;
      break;
    }
  }
  if (evidence || *decision == BLOCK_CONFIDENCE_VALID) {
    *decision = (BlockValidationDecision)ISOBMFF_PAYLOAD_CONFIDENCE_MAX;
  }
  return needleidx;
}


static inline bool isobmff_state_valid(const IsoBmffCarveState *state) {

  return state && state->magic == ISOBMFF_CARVE_STATE_MAGIC
      && state->version == ISOBMFF_CARVE_STATE_VERSION
      && state->stage >= ISOBMFF_STAGE_PAIR_FOOTER
      && state->stage <= ISOBMFF_STAGE_TGA_MIDDLE_RUN
      && state->kind >= ISOBMFF_KIND_MOV
      && state->kind <= ISOBMFF_KIND_MP4
      && state->stored_solution_count <= ISOBMFF_MAX_STORED_SOLUTIONS
      && state->stored_solution_count <= state->solution_count;
}


static inline void isobmff_update_state(void *carvehashkey,
                                        const IsoBmffLayout *layout,
                                        IsoBmffKind kind) {

  if (!carvehashkey || !layout) {
    return;
  }
  IsoBmffCarveState *state = (IsoBmffCarveState *)carve_get_state(
      carvehashkey);
  if (!isobmff_state_valid(state)) {
    isobmff_free_carve_state((void **)&state);
    state = (IsoBmffCarveState *)calloc(1, sizeof(*state));
    check_memory_allocation(state, __LINE__, __FILE__,
                            "IsoBmffCarveState");
    state->magic = ISOBMFF_CARVE_STATE_MAGIC;
    state->version = ISOBMFF_CARVE_STATE_VERSION;
    state->active_footer = UINT64_MAX;
    state->preferred_footer = UINT64_MAX;
    state->active_suffix_delta = ISOBMFF_NO_MIDDLE_DELTA;
    state->stage = ISOBMFF_STAGE_PAIR_FOOTER;
    state->kind = (uint32_t)kind;
  }
  if (layout->saw_moov) {
    state->expected_moov_offset = layout->moov_offset;
    state->archive_extent = layout->parsed_extent;
  }
  else if (layout->required_extent != UINT64_MAX) {
    state->expected_moov_offset = layout->required_extent;
  }
  else if (layout->parsed_extent > 0) {
    state->expected_moov_offset = layout->parsed_extent;
  }
  carve_put_state(carvehashkey, state);
  isobmff_free_carve_state((void **)&state);
}


static inline void isobmff_file_validate_kind(
    char *data, uint64_t length, bool *validates, uint64_t *validates_to,
    bool *promising, uint32_t needleidx, uint32_t blocksize,
    void *carvehashkey, IsoBmffKind requested) {

  (void)needleidx;
  (void)blocksize;
  if (!validates || !validates_to || !promising) {
    return;
  }
  *validates = false;
  *validates_to = 0;
  *promising = false;
  IsoBmffLayout layout;
  IsoBmffParseResult result = isobmff_parse_file(
      (const uint8_t *)data, length, &layout);

  if (result == ISOBMFF_PARSE_INVALID) {
    isobmff_free_layout(&layout);
    return;
  }
  IsoBmffKind observed = layout.saw_ftyp
      ? isobmff_brand_kind(layout.major_brand) : ISOBMFF_KIND_MOV;
  if (observed != requested) {
    isobmff_free_layout(&layout);
    return;
  }
  uint64_t extent = layout.parsed_extent;
  if (layout.required_extent != UINT64_MAX
      && layout.required_extent <= length
      && layout.required_extent > extent) {
    extent = layout.required_extent;
  }
  if (extent == 0) {
    isobmff_free_layout(&layout);
    return;
  }
  *validates_to = extent - 1;
  *promising = true;
  if (result == ISOBMFF_PARSE_COMPLETE && layout.metadata_valid
      && layout.saw_moov && layout.mdat_count > 0
      && layout.invalid_strong_samples == 0
      && !layout.terminal_size
      && (scalpel_state.no_defrag
          || isobmff_layout_samples_validated(&layout))) {
    *validates = true;
    *promising = false;
    *validates_to = layout.parsed_extent - 1;
  }
  isobmff_update_state(carvehashkey, &layout, requested);
  isobmff_free_layout(&layout);
}


static inline void mov_file_validate(
    char *data, uint64_t length, bool *validates, uint64_t *validates_to,
    bool *promising, uint32_t needleidx, uint32_t blocksize,
    void *carvehashkey) {

  isobmff_file_validate_kind(data, length, validates, validates_to,
                             promising, needleidx, blocksize,
                             carvehashkey, ISOBMFF_KIND_MOV);
}


static inline void mp4_file_validate(
    char *data, uint64_t length, bool *validates, uint64_t *validates_to,
    bool *promising, uint32_t needleidx, uint32_t blocksize,
    void *carvehashkey) {

  isobmff_file_validate_kind(data, length, validates, validates_to,
                             promising, needleidx, blocksize,
                             carvehashkey, ISOBMFF_KIND_MP4);
}


static inline bool isobmff_expand_contiguous_candidate(
    CarveInfo *candidate, uint64_t required_extent) {

  if (!candidate || !candidate->b || candidate->flavor != NO_FLAVOR
      || scalpel_state.blocksize == 0 || required_extent == 0
      || required_extent > ISOBMFF_MAXIMUM_SIZE) {
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
  blockvector_set_data_length_to_mapped_extent(candidate->b);
  inflate_blockvector(candidate->b);
  uint64_t length = blockvector_get_data_length(candidate->b);
  if (getenv("SCALPEL_ISOBMFF_DEBUG")) {
    fprintf(stderr,
            "ISOBMFF expand required=%" PRIu64 " blocks=%" PRIu64
            " available=%" PRIu64 " nonpeek=%" PRIu64 "\n",
            required_extent, required_blocks, length,
            blockvector_get_non_peekahead_data_length(candidate->b));
  }
  if (length < required_extent) {
    return false;
  }
  blockvector_set_data_length(candidate->b, length);
  if (candidate->start <= UINT64_MAX - length) {
    candidate->stop = candidate->start + length - 1;
  }
  return true;
}


static inline void isobmff_candidate_validate(
    CarveInfo *candidate, bool *validates, uint64_t *validates_to,
    bool *promising) {

  if (!candidate || !candidate->b || !validates || !validates_to
      || !promising || candidate->needleidx < 0
      || (uint32_t)candidate->needleidx >= scalpel_state.num_specs) {
    return;
  }
  uint64_t available = blockvector_get_data_length(candidate->b);
  uint64_t length = blockvector_get_non_peekahead_data_length(candidate->b);
  if (length == 0 || length > available) {
    length = available;
  }
  SearchSpec *spec = &scalpel_state.search_specs[candidate->needleidx];
  spec->FILEVALIDATOR(blockvector_get_data_pointer(candidate->b), length,
                      validates, validates_to, promising,
                      (uint32_t)candidate->needleidx,
                      scalpel_state.blocksize, candidate->carvehashkey);

  for (uint32_t attempt = 0;
       attempt < 4 && candidate->flavor == NO_FLAVOR && !*validates;
       attempt++) {
    IsoBmffLayout layout;
    IsoBmffParseResult result = isobmff_parse_file(
        (const uint8_t *)blockvector_get_data_pointer(candidate->b),
        length, &layout);
    IsoBmffKind requested = strcmp(spec->FILETYPE, "mp4") == 0
        ? ISOBMFF_KIND_MP4 : ISOBMFF_KIND_MOV;
    IsoBmffKind observed = layout.saw_ftyp
        ? isobmff_brand_kind(layout.major_brand) : ISOBMFF_KIND_MOV;
    uint64_t required_extent = layout.required_extent != UINT64_MAX
        ? layout.required_extent : 0;
    uint64_t metadata_extent = 0;
    if (result != ISOBMFF_PARSE_INVALID && observed == requested
        && isobmff_layout_required_extent(&layout, &metadata_extent)
        && metadata_extent > required_extent) {
      required_extent = metadata_extent;
    }
    isobmff_free_layout(&layout);

    if (result == ISOBMFF_PARSE_INVALID || observed != requested
        || required_extent <= length
        || !isobmff_expand_contiguous_candidate(candidate,
                                                  required_extent)) {
      break;
    }
    length = blockvector_get_non_peekahead_data_length(candidate->b);
    spec->FILEVALIDATOR(blockvector_get_data_pointer(candidate->b), length,
                        validates, validates_to, promising,
                        (uint32_t)candidate->needleidx,
                        scalpel_state.blocksize, candidate->carvehashkey);
  }

  if (*validates) {
    uint64_t blocks = blockvector_get_num_blocks(candidate->b);
    bool contiguous = blocks > 0;
    int64_t previous = contiguous
        ? blockvector_get_actual_blocknumber(candidate->b, 0) : -1;

    if (previous < 0) {
      contiguous = false;
    }
    for (uint64_t slot = 1; contiguous && slot < blocks; slot++) {
      int64_t actual = blockvector_get_actual_blocknumber(
          candidate->b, slot);
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


static inline bool isobmff_serialize_carve_state(
    void **state, FILE *fp, StateSerialization mode) {

  IsoBmffCarveState **carve_state = (IsoBmffCarveState **)state;
  if (!carve_state || !fp) {
    return false;
  }
  if (mode == DESERIALIZE) {
    *carve_state = (IsoBmffCarveState *)calloc(1, sizeof(**carve_state));
    check_memory_allocation(*carve_state, __LINE__, __FILE__,
                            "IsoBmffCarveState");
  }
  if ((mode == SERIALIZE && !isobmff_state_valid(*carve_state))
      || (mode == SERIALIZE
          ? fwrite(*carve_state, sizeof(**carve_state), 1, fp)
          : fread(*carve_state, sizeof(**carve_state), 1, fp)) != 1) {
    if (mode == DESERIALIZE) {
      free(*carve_state);
      *carve_state = NULL;
    }
    handle_error(SCALPEL_ERROR_CHECKPOINT, "ISO BMFF carve state",
                 __LINE__, __FILE__);
  }
  if (mode == DESERIALIZE && (*carve_state)->version == 15U
      && (*carve_state)->magic == ISOBMFF_CARVE_STATE_MAGIC
      && (*carve_state)->stage >= ISOBMFF_STAGE_PAIR_FOOTER
      && (*carve_state)->stage <= ISOBMFF_STAGE_TGA_MIDDLE_RUN
      && (*carve_state)->kind >= ISOBMFF_KIND_MOV
      && (*carve_state)->kind <= ISOBMFF_KIND_MP4
      && (*carve_state)->stored_solution_count <= ISOBMFF_MAX_STORED_SOLUTIONS
      && (*carve_state)->stored_solution_count <= (*carve_state)->solution_count) {
    // Version 15 stored table indices. Retain completed mappings and fast-path
    // progress, but repeat the footer search whose physical frontier was not saved.
    IsoBmffCarveState *legacy = *carve_state;
    bool footer_search_started = legacy->footer_cursor != 0
        || legacy->preferred_footer_tried
        || legacy->active_footer != UINT64_MAX;
    if (legacy->stage != ISOBMFF_STAGE_FINISHED && !legacy->fast_context
        && !isobmff_fast_stage(legacy->stage)) {
      isobmff_finish_footer(legacy);
    }
    legacy->footer_cursor = 0;
    legacy->active_footer = UINT64_MAX;
    legacy->preferred_footer = UINT64_MAX;
    legacy->preferred_footer_tried = footer_search_started;
    legacy->version = ISOBMFF_CARVE_STATE_VERSION;
    for (uint32_t index = 0;
         index < legacy->stored_solution_count
         && index < ISOBMFF_MAX_STORED_SOLUTIONS; index++) {
      legacy->solutions[index].mapping.footer_offset = UINT64_MAX;
    }
  }
  if (mode == DESERIALIZE && !isobmff_state_valid(*carve_state)) {
    free(*carve_state);
    *carve_state = NULL;
    handle_error(SCALPEL_ERROR_CHECKPOINT, "invalid ISO BMFF carve state",
                 __LINE__, __FILE__);
  }
  return true;
}


static inline void *isobmff_clone_carve_state(const void *srcstate) {

  const IsoBmffCarveState *source = (const IsoBmffCarveState *)srcstate;
  if (!isobmff_state_valid(source)) {
    return NULL;
  }
  IsoBmffCarveState *copy = (IsoBmffCarveState *)malloc(sizeof(*copy));
  check_memory_allocation(copy, __LINE__, __FILE__,
                          "IsoBmffCarveState");
  memcpy(copy, source, sizeof(*copy));
  return copy;
}


static inline void isobmff_free_carve_state(void **state) {

  if (state) {
    free(*state);
    *state = NULL;
  }
}


static inline size_t isobmff_sizeof_carve_state(const void *state) {

  return isobmff_state_valid((const IsoBmffCarveState *)state)
      ? sizeof(IsoBmffCarveState) : 0;
}


static inline void isobmff_print_carve_state(const void *state) {

  const IsoBmffCarveState *carve_state =
      (const IsoBmffCarveState *)state;
  if (!isobmff_state_valid(carve_state)) {
    fprintf(stdout, "NULL");
    return;
  }
  fprintf(stdout,
          "kind=%u stage=%u moov=%" PRIu64 " extent=%" PRIu64
          " footer=%" PRIu64 " split=%" PRIu64
          " middle=%" PRIu64 " solutions=%" PRIu64
          " ambiguous-prefix=%" PRIu64 " repairs=%" PRIu64,
          carve_state->kind, carve_state->stage,
          carve_state->expected_moov_offset, carve_state->archive_extent,
          carve_state->footer_cursor, carve_state->split_cursor,
          carve_state->middle_actual_cursor, carve_state->solution_count,
          carve_state->ambiguous_prefix_blocks,
          carve_state->repairs);
}


static inline void isobmff_footer_context_clear(
    IsoBmffFooterContext *context) {

  if (!context) {
    return;
  }
  isobmff_free_layout(&context->layout);
  free(context->anchors);
  free(context->events);
  free(context->moov_data);
  memset(context, 0, sizeof(*context));
}


static inline bool isobmff_block_delta(uint64_t actual, uint64_t logical,
                                       int64_t *delta) {

  if (!delta) {
    return false;
  }
  if (actual >= logical) {
    uint64_t difference = actual - logical;
    if (difference > (uint64_t)INT64_MAX) {
      return false;
    }
    *delta = (int64_t)difference;
    return true;
  }
  uint64_t difference = logical - actual;
  if (difference > (uint64_t)INT64_MAX) {
    return false;
  }
  *delta = -(int64_t)difference;
  return true;
}


static inline uint64_t isobmff_preferred_footer(
    const CarveInfo *candidate, const SearchSpec *spec,
    uint64_t expected_moov_offset) {

  if (!candidate || !spec || expected_moov_offset == 0
      || candidate->start > UINT64_MAX - expected_moov_offset) {
    return UINT64_MAX;
  }
  uint64_t target = candidate->start + expected_moov_offset;
  uint64_t preferred = UINT64_MAX;
  uint64_t best_distance = UINT64_MAX;

  for (uint64_t index = 0; index < spec->offsets.numfooters; index++) {
    if (spec->offsets.footers[index] == 0) {
      continue;
    }
    uint64_t actual = spec->offsets.footers[index] - 1;
    uint64_t distance = actual > target ? actual - target : target - actual;
    if (preferred == UINT64_MAX || distance < best_distance) {
      preferred = spec->offsets.footers[index];
      best_distance = distance;
    }
  }
  return preferred;
}


// Header/footer discovery and pruning retain increasing physical offset order.
static inline uint64_t isobmff_footer_at_or_after(
    const SearchSpec *spec, uint64_t offset) {

  if (!spec || !spec->offsets.footers) {
    return 0;
  }
  uint64_t first = 0;
  uint64_t last = spec->offsets.numfooters;
  while (first < last) {
    uint64_t middle = first + (last - first) / 2;
    if (spec->offsets.footers[middle] < offset) {
      first = middle + 1;
    }
    else {
      last = middle;
    }
  }
  return first;
}


static inline uint64_t isobmff_footer_index(
    const SearchSpec *spec, uint64_t offset) {

  if (!spec || !spec->offsets.footers || offset == UINT64_MAX) {
    return UINT64_MAX;
  }
  uint64_t index = isobmff_footer_at_or_after(spec, offset);
  return index < spec->offsets.numfooters
      && spec->offsets.footers[index] == offset ? index : UINT64_MAX;
}


static inline uint64_t isobmff_next_footer(
    const SearchSpec *spec, IsoBmffCarveState *state) {

  if (!spec || !state || !spec->offsets.footers) {
    return UINT64_MAX;
  }
  if (!state->preferred_footer_tried) {
    state->preferred_footer_tried = true;
    uint64_t index = isobmff_footer_index(spec, state->preferred_footer);
    if (index != UINT64_MAX) {
      return index;
    }
  }
  uint64_t index = isobmff_footer_at_or_after(spec, state->footer_cursor);
  while (index < spec->offsets.numfooters) {
    uint64_t offset = spec->offsets.footers[index];
    state->footer_cursor = offset == UINT64_MAX ? offset : offset + 1;
    if (offset != 0 && offset != UINT64_MAX
        && offset != state->preferred_footer) {
      return index;
    }
    index++;
  }
  return UINT64_MAX;
}


// Decoder warm-up may revisit bytes, but must not regress the next untried split.
static inline void isobmff_advance_middle_cursor(
    IsoBmffCarveState *state, uint64_t next_second) {

  if (state->middle_second_cursor < next_second) {
    state->middle_second_cursor = next_second;
  }
}


static inline bool isobmff_prepare_footer_context(
    const CarveInfo *candidate, uint64_t footer_index,
    IsoBmffFooterContext *context) {

  if (!candidate || !candidate->b || !context
      || candidate->needleidx < 0
      || (uint32_t)candidate->needleidx >= scalpel_state.num_specs
      || scalpel_state.blocksize == 0) {
    return false;
  }
  memset(context, 0, sizeof(*context));
  SearchSpec *spec = &scalpel_state.search_specs[candidate->needleidx];
  uint64_t expected_moov = 0;
  uint64_t mdat_start = 0;
  uint64_t mdat_end = 0;
  IsoBmffKind kind = strcmp(spec->FILETYPE, "mp4") == 0
      ? ISOBMFF_KIND_MP4 : ISOBMFF_KIND_MOV;

  if (!isobmff_layout_from_header(candidate, kind, &expected_moov,
                                   &mdat_start, &mdat_end)
      || expected_moov != mdat_end || expected_moov == 0) {
    return false;
  }
  int64_t header_actual = blockvector_get_actual_blocknumber(candidate->b, 0);
  if (header_actual < 0
      || !isobmff_load_footer_layout(
          spec, footer_index, &context->moov_data,
          &context->moov_actual, &context->moov_size, &context->layout)) {
    isobmff_footer_context_clear(context);
    return false;
  }
  uint64_t sample_count = 0;
  for (uint32_t index = 0; index < context->layout.track_count; index++) {
    uint64_t track_extent = 0;
    const IsoBmffTrack *track = &context->layout.tracks[index];

    if (!isobmff_track_required_extent(track, &track_extent)
        || track->sample_count > UINT64_MAX - sample_count) {
      isobmff_footer_context_clear(context);
      return false;
    }
    sample_count += track->sample_count;
    if (track_extent > expected_moov) {
      expected_moov = track_extent;
    }
  }
  if (sample_count == 0) {
    isobmff_footer_context_clear(context);
    return false;
  }

  uint64_t blocksize = scalpel_state.blocksize;
  uint64_t moov_within = context->moov_actual % blocksize;
  uint64_t aligned_moov = expected_moov - expected_moov % blocksize;
  if (moov_within > UINT64_MAX - aligned_moov) {
    isobmff_footer_context_clear(context);
    return false;
  }
  aligned_moov += moov_within;
  if (aligned_moov < expected_moov) {
    if (aligned_moov > UINT64_MAX - blocksize) {
      isobmff_footer_context_clear(context);
      return false;
    }
    aligned_moov += blocksize;
  }
  expected_moov = aligned_moov;

  uint64_t logical_moov_block = expected_moov / blocksize;
  uint64_t actual_moov_block = context->moov_actual / blocksize;
  uint64_t image_blocks = CEILDIV(
      filemirror_filesize(scalpel_state.filemirror), blocksize);

  if (context->moov_size > UINT64_MAX - expected_moov) {
    isobmff_footer_context_clear(context);
    return false;
  }
  context->extent = expected_moov + context->moov_size;
  context->logical_blocks = CEILDIV(context->extent, blocksize);
  context->maximum_split = logical_moov_block;
  if (context->extent > spec->MAXIMUMSIZE || context->extent > SIZE_MAX
      || context->logical_blocks == 0
      || context->logical_blocks > image_blocks
      || context->maximum_split == 0
      || context->maximum_split >= context->logical_blocks
      || (uint64_t)header_actual > (uint64_t)INT64_MAX
      || !isobmff_block_delta(actual_moov_block, logical_moov_block,
                              &context->suffix_delta)) {
    isobmff_footer_context_clear(context);
    return false;
  }
  context->prefix_delta = header_actual;
  if (!isobmff_collect_anchors(&context->layout, &context->anchors,
                                  &context->anchor_count)
      || !isobmff_build_anchor_events(
          context->anchors, context->anchor_count,
          context->prefix_delta, context->suffix_delta,
          &context->events, &context->event_count)) {
    isobmff_footer_context_clear(context);
    return false;
  }
  (void)mdat_start;
  (void)mdat_end;
  return true;
}


static inline bool isobmff_prepare_fast_context(
    const CarveInfo *candidate, uint64_t known_extent,
    IsoBmffFooterContext *context) {

  if (!candidate || !candidate->b || !context || candidate->needleidx < 0
      || (uint32_t)candidate->needleidx >= scalpel_state.num_specs
      || scalpel_state.blocksize == 0) {
    return false;
  }
  memset(context, 0, sizeof(*context));
  uint64_t available = blockvector_get_data_length(candidate->b);
  uint64_t length = blockvector_get_non_peekahead_data_length(candidate->b);
  if (length == 0 || length > available) {
    length = available;
  }
  IsoBmffLayout layout;
  IsoBmffParseResult result = isobmff_parse_file(
      (const uint8_t *)blockvector_get_data_pointer(candidate->b),
      length, &layout);
  SearchSpec *spec = &scalpel_state.search_specs[candidate->needleidx];
  IsoBmffKind requested = strcmp(spec->FILETYPE, "mp4") == 0
      ? ISOBMFF_KIND_MP4 : ISOBMFF_KIND_MOV;
  IsoBmffKind observed = layout.saw_ftyp
      ? isobmff_brand_kind(layout.major_brand) : ISOBMFF_KIND_MOV;
  uint64_t extent = 0;
  int64_t header_actual = blockvector_get_actual_blocknumber(candidate->b, 0);
  bool extent_valid = isobmff_layout_required_extent(&layout, &extent);

  if (getenv("SCALPEL_ISOBMFF_DEBUG")) {
    fprintf(stderr,
            "ISOBMFF fast-context start=%" PRIu64
            " result=%u observed=%u requested=%u moov=%u mdats=%u"
            " moov-offset=%" PRIu64 " first-mdat=%" PRIu64
            " extent-valid=%u extent=%" PRIu64 " max=%" PRIu64
            " header=%" PRId64 "\n",
            candidate->start, (unsigned)result, (unsigned)observed,
            (unsigned)requested, layout.saw_moov, layout.mdat_count,
            layout.moov_offset, layout.first_mdat_offset, extent_valid,
            extent, spec->MAXIMUMSIZE, header_actual);
  }

  if (result == ISOBMFF_PARSE_INVALID || observed != requested
      || !layout.saw_moov || layout.mdat_count == 0
      || layout.moov_offset >= layout.first_mdat_offset
      || !extent_valid
      || extent == 0 || extent > spec->MAXIMUMSIZE || extent > SIZE_MAX
      || header_actual < 0 || (uint64_t)header_actual > (uint64_t)INT64_MAX) {
    isobmff_free_layout(&layout);
    return false;
  }
  if (known_extent > extent && known_extent <= spec->MAXIMUMSIZE
      && known_extent <= SIZE_MAX) {
    extent = known_extent;
  }
  uint64_t image_blocks = CEILDIV(
      filemirror_filesize(scalpel_state.filemirror), scalpel_state.blocksize);
  uint64_t logical_blocks = CEILDIV(extent, scalpel_state.blocksize);
  if (getenv("SCALPEL_ISOBMFF_DEBUG")) {
    fprintf(stderr,
            "ISOBMFF fast-context-size start=%" PRIu64
            " logical=%" PRIu64 " image=%" PRIu64
            " file-size=%" PRIu64 "\n",
            candidate->start, logical_blocks, image_blocks,
            filemirror_filesize(scalpel_state.filemirror));
  }
  if (logical_blocks < 2 || logical_blocks > image_blocks) {
    isobmff_free_layout(&layout);
    return false;
  }

  context->layout = layout;
  context->extent = extent;
  context->logical_blocks = logical_blocks;
  context->maximum_split = logical_blocks - 1;
  context->prefix_delta = header_actual;
  context->suffix_delta = ISOBMFF_NO_MIDDLE_DELTA;
  if (!isobmff_collect_anchors(&context->layout, &context->anchors,
                               &context->anchor_count)) {
    if (getenv("SCALPEL_ISOBMFF_DEBUG")) {
      fprintf(stderr,
              "ISOBMFF fast-context start=%" PRIu64
              " has no usable anchors\n",
              candidate->start);
    }
    isobmff_footer_context_clear(context);
    return false;
  }
  return true;
}


static inline bool isobmff_metadata_context_set_suffix(
    IsoBmffFooterContext *context, int64_t suffix_delta) {

  if (!context || !context->metadata_repair || !context->anchors
      || context->anchor_count != 1 || scalpel_state.blocksize == 0
      || suffix_delta == ISOBMFF_NO_MIDDLE_DELTA) {
    return false;
  }
  uint64_t logical_offset = context->anchors[0].logical_offset;
  uint64_t logical_block = logical_offset / scalpel_state.blocksize;
  uint64_t within = logical_offset % scalpel_state.blocksize;
  if ((suffix_delta < 0 && logical_block < (uint64_t)(-suffix_delta))
      || (suffix_delta > 0
          && logical_block > (uint64_t)(INT64_MAX - suffix_delta))) {
    return false;
  }
  int64_t actual_block = (int64_t)logical_block + suffix_delta;
  if (actual_block < 0
      || (uint64_t)actual_block
             > (UINT64_MAX - within) / scalpel_state.blocksize) {
    return false;
  }
  uint64_t actual_offset = (uint64_t)actual_block
                           * scalpel_state.blocksize + within;
  uint8_t encoded[16];
  if (!isobmff_copy_actual_bytes(actual_offset, encoded, sizeof(encoded))
      || isobmff_read_be32(encoded + 4)
             != ISOBMFF_FOURCC('m', 'd', 'a', 't')) {
    return false;
  }
  uint64_t size = isobmff_read_be32(encoded);
  uint64_t header_size = 8;
  if (size == 1) {
    size = isobmff_read_be64(encoded + 8);
    header_size = 16;
  }
  if (size < header_size || size > ISOBMFF_MAXIMUM_SIZE
      || size > UINT64_MAX - logical_offset
      || actual_offset > filemirror_filesize(scalpel_state.filemirror)
      || size > filemirror_filesize(scalpel_state.filemirror)
                    - actual_offset) {
    return false;
  }
  uint64_t extent = logical_offset + size;
  uint64_t logical_blocks = CEILDIV(extent, scalpel_state.blocksize);
  if (extent > SIZE_MAX || logical_blocks <= context->maximum_split) {
    return false;
  }
  context->suffix_delta = suffix_delta;
  context->extent = extent;
  context->logical_blocks = logical_blocks;
  return true;
}


static inline bool isobmff_prepare_metadata_context(
    const CarveInfo *candidate, int64_t suffix_delta,
    IsoBmffFooterContext *context) {

  if (!candidate || !candidate->b || !context || candidate->needleidx < 0
      || (uint32_t)candidate->needleidx >= scalpel_state.num_specs
      || scalpel_state.blocksize == 0) {
    return false;
  }
  memset(context, 0, sizeof(*context));
  SearchSpec *spec = &scalpel_state.search_specs[candidate->needleidx];
  IsoBmffKind requested = strcmp(spec->FILETYPE, "mp4") == 0
      ? ISOBMFF_KIND_MP4 : ISOBMFF_KIND_MOV;
  int64_t header_block = blockvector_get_actual_blocknumber(candidate->b, 0);
  uint64_t header_within = candidate->start % scalpel_state.blocksize;
  if (header_block < 0 || (uint64_t)header_block
          > (UINT64_MAX - header_within) / scalpel_state.blocksize) {
    return false;
  }
  uint64_t header_actual = (uint64_t)header_block
                           * scalpel_state.blocksize + header_within;
  uint64_t position = 0;
  bool saw_ftyp = false;

  for (uint32_t box_index = 0; box_index < 64; box_index++) {
    uint8_t encoded[32];
    if (position > UINT64_MAX - header_actual
        || !isobmff_copy_actual_bytes(header_actual + position,
                                      encoded, sizeof(encoded))) {
      return false;
    }
    IsoBmffBox box;
    if (!isobmff_box_at(encoded, sizeof(encoded), 0, &box)
        || !isobmff_is_known_top_level(box.type)
        || box.size > UINT64_MAX - position) {
      return false;
    }
    if (box.type == ISOBMFF_FOURCC('f', 't', 'y', 'p')) {
      if (saw_ftyp || box.size < box.header_size + 8
          || isobmff_brand_kind(
                 isobmff_read_be32(encoded + box.header_size))
                 != requested) {
        return false;
      }
      saw_ftyp = true;
    }
    else if (box.type == ISOBMFF_FOURCC('m', 'o', 'o', 'v')) {
      if ((requested == ISOBMFF_KIND_MP4 && !saw_ftyp)
          || !isobmff_moov_prefix_valid(encoded, sizeof(encoded), &box)) {
        return false;
      }
      uint64_t mdat_offset = position + box.size;
      uint64_t mdat_block = mdat_offset / scalpel_state.blocksize;
      if (spec->MAXIMUMSIZE < 16
          || mdat_offset > spec->MAXIMUMSIZE - 16 || mdat_block == 0
          || mdat_block > (uint64_t)INT64_MAX) {
        return false;
      }
      context->anchors = (IsoBmffAnchor *)calloc(
          1, sizeof(*context->anchors));
      check_memory_allocation(context->anchors, __LINE__, __FILE__,
                              "ISO BMFF metadata anchor");
      context->anchors[0] = (IsoBmffAnchor){
        .logical_offset = mdat_offset,
        .sample_size = 16,
        .codec = ISOBMFF_FOURCC('m', 'd', 'a', 't'),
        .nal_length_size = 0
      };
      context->anchor_count = 1;
      context->extent = mdat_offset + 16;
      context->logical_blocks = CEILDIV(
          context->extent, scalpel_state.blocksize);
      context->maximum_split = mdat_block;
      context->prefix_delta = header_block;
      context->suffix_delta = ISOBMFF_NO_MIDDLE_DELTA;
      context->metadata_repair = true;
      if (suffix_delta != ISOBMFF_NO_MIDDLE_DELTA
          && !isobmff_metadata_context_set_suffix(context,
                                                   suffix_delta)) {
        isobmff_footer_context_clear(context);
        return false;
      }
      return true;
    }
    else if (box.type != ISOBMFF_FOURCC('w', 'i', 'd', 'e')
             && box.type != ISOBMFF_FOURCC('f', 'r', 'e', 'e')
             && box.type != ISOBMFF_FOURCC('s', 'k', 'i', 'p')) {
      return false;
    }
    position += box.size;
  }
  return false;
}


static inline bool isobmff_prepare_metadata_payload_context(
    const CarveInfo *candidate, int64_t suffix_delta,
    uint64_t base_split, IsoBmffFooterContext *context) {

  IsoBmffFooterContext prepared;
  memset(&prepared, 0, sizeof(prepared));
  if (!context
      || !isobmff_prepare_metadata_context(
          candidate, suffix_delta, &prepared)
      || base_split == 0 || base_split > prepared.maximum_split) {
    isobmff_footer_context_clear(&prepared);
    return false;
  }

  IsoBmffSolution solution = {
    .footer_offset = UINT64_MAX,
    .base_split = base_split,
    .first_split = UINT64_MAX,
    .second_split = UINT64_MAX,
    .middle_delta = ISOBMFF_NO_MIDDLE_DELTA
  };
  uint64_t extent = isobmff_solution_extent(
      prepared.prefix_delta, prepared.suffix_delta,
      &solution, prepared.extent);
  if (extent == 0 || extent > SIZE_MAX) {
    isobmff_footer_context_clear(&prepared);
    return false;
  }
  uint8_t *data = (uint8_t *)malloc((size_t)extent);
  if (!data || !isobmff_materialize_solution(
          prepared.prefix_delta, prepared.suffix_delta,
          &solution, extent, data)) {
    free(data);
    isobmff_footer_context_clear(&prepared);
    return false;
  }

  IsoBmffLayout layout;
  memset(&layout, 0, sizeof(layout));
  (void)isobmff_parse_file(data, extent, &layout);
  free(data);
  IsoBmffAnchor *anchors = NULL;
  uint64_t anchor_count = 0;
  bool usable = layout.saw_moov && layout.mdat_count > 0
      && layout.track_count > 0 && layout.parsed_extent == extent
      && layout.failure_offset == 0
      && isobmff_collect_anchors(&layout, &anchors, &anchor_count)
      && anchor_count > 1;
  if (!usable) {
    free(anchors);
    isobmff_free_layout(&layout);
    isobmff_footer_context_clear(&prepared);
    return false;
  }

  free(prepared.anchors);
  prepared.anchors = anchors;
  prepared.anchor_count = anchor_count;
  prepared.layout = layout;
  prepared.extent = extent;
  prepared.logical_blocks = CEILDIV(extent, scalpel_state.blocksize);
  prepared.maximum_split = prepared.logical_blocks - 1;
  if (!isobmff_build_anchor_events(
          prepared.anchors, prepared.anchor_count,
          prepared.prefix_delta, prepared.suffix_delta,
          &prepared.events, &prepared.event_count)) {
    isobmff_footer_context_clear(&prepared);
    return false;
  }
  *context = prepared;
  return true;
}


static inline bool isobmff_fast_suffix_seed(
    const IsoBmffFooterContext *context, uint64_t *seed_index,
    uint64_t *corroborator_index) {

  if (!context || !seed_index || !corroborator_index
      || context->anchor_count == 0) {
    return false;
  }
  *seed_index = 0;
  *corroborator_index = UINT64_MAX;
  uint64_t seed_block = context->anchors[0].logical_offset
                        / scalpel_state.blocksize;

  for (uint64_t index = 1; index < context->anchor_count; index++) {
    uint64_t block = context->anchors[index].logical_offset
                     / scalpel_state.blocksize;
    if (block > seed_block) {
      *seed_index = index;
      seed_block = block;
    }
  }

  uint64_t corroborator_block = 0;
  for (uint64_t index = 0; index < context->anchor_count; index++) {
    uint64_t block = context->anchors[index].logical_offset
                     / scalpel_state.blocksize;
    if (block < seed_block
        && (*corroborator_index == UINT64_MAX
            || block > corroborator_block)) {
      *corroborator_index = index;
      corroborator_block = block;
    }
  }
  return true;
}


static inline bool isobmff_fast_suffix_delta(
    const IsoBmffFooterContext *context, uint64_t seed_index,
    uint64_t corroborator_index, uint64_t actual_block, int64_t *delta) {

  if (!context || !delta || seed_index >= context->anchor_count
      || actual_block > (uint64_t)INT64_MAX
      || isobmff_actual_to_apparent((int64_t)actual_block) < 0) {
    return false;
  }
  uint64_t logical_block = context->anchors[seed_index].logical_offset
                           / scalpel_state.blocksize;
  if (!isobmff_block_delta(actual_block, logical_block, delta)
      || *delta == context->prefix_delta
      || !isobmff_anchor_at_delta(&context->anchors[seed_index], *delta)) {
    return false;
  }
  return corroborator_index == UINT64_MAX
      || isobmff_anchor_at_delta(&context->anchors[corroborator_index],
                                 *delta);
}


static inline uint64_t isobmff_fast_suffix_score(
    const IsoBmffFooterContext *context, int64_t delta) {

  uint64_t score = 0;
  for (uint64_t index = 0; index < context->anchor_count; index++) {
    if (isobmff_anchor_at_delta(&context->anchors[index], delta)) {
      score++;
    }
  }
  return score;
}


static inline bool isobmff_fast_stage(uint32_t stage) {

  return stage >= ISOBMFF_STAGE_FAST_SCORE_SUFFIX
      && stage <= ISOBMFF_STAGE_TGA_MIDDLE_RUN;
}


static inline void isobmff_write_checkpoint_prefix(CarveInfo *candidate) {

  if (!scalpel_state.write_promising || !candidate || !candidate->b
      || scalpel_state.blocksize == 0
      || blockvector_get_num_blocks(candidate->b) <= 1) {
    return;
  }
  BlockVector *active = candidate->b;
  BlockVector *snapshot = NULL;
  uint64_t snapshot_length = blockvector_get_data_length(active);
  CarveInfoFlavor saved_flavor = candidate->flavor;
  bool saved_chopped = candidate->chopped;

  clone_blockvector(active, &snapshot, false);
  resize_blockvector(snapshot, 1);
  if (snapshot_length > scalpel_state.blocksize) {
    snapshot_length = scalpel_state.blocksize;
  }
  blockvector_set_data_length(snapshot, snapshot_length);
  candidate->b = snapshot;
  candidate->flavor = PROMISING;
  candidate->chopped = true;

  CarveInfo *preserved = candidate;
  write_candidate(&preserved, true);

  candidate->b = active;
  candidate->flavor = saved_flavor;
  candidate->chopped = saved_chopped;
  free_blockvector(&snapshot);
}


static inline bool isobmff_reassembly_stop_requested(
    ThreadWork *work, CarveInfo **candidate, IsoBmffCarveState *state,
    uuid_string_t uuidp, uuid_string_t uuidc) {

  if (reassembly_check_kill_queue(work, candidate, uuidp, uuidc)) {
    return true;
  }
  if (atomic_load_explicit(&REASS_RETURN_TO_IDLE, memory_order_acquire)
      && candidate && *candidate) {
    carve_put_state((*candidate)->carvehashkey, state);
    isobmff_write_checkpoint_prefix(*candidate);
    if (reassembly_time_to_checkpoint(work->id, *candidate, uuidp, uuidc)) {
      return true;
    }
  }
  return false;
}


static inline bool isobmff_reassembly_poll(
    ThreadWork *work, CarveInfo **candidate, IsoBmffCarveState *state,
    uuid_string_t uuidp, uuid_string_t uuidc, uint64_t *iterations) {

  (*iterations)++;
  return *iterations % ISOBMFF_REASSEMBLY_POLL_INTERVAL == 0
      && isobmff_reassembly_stop_requested(
          work, candidate, state, uuidp, uuidc);
}


static inline uint64_t isobmff_suffix_score(
    const IsoBmffFooterContext *context) {

  uint64_t score = 0;
  for (uint64_t index = 0; index < context->event_count; index++) {
    score += context->events[index].suffix_good;
  }
  return score;
}


static inline bool isobmff_equal_delta_middle_bounds(
    const IsoBmffFooterContext *context, uint64_t *first_min,
    uint64_t *first_max, uint64_t *second_min, uint64_t *second_max) {

  if (!context || !first_min || !first_max || !second_min || !second_max
      || context->prefix_delta != context->suffix_delta
      || context->event_count == 0 || context->maximum_split < 2) {
    return false;
  }

  bool saw_bad = false;
  uint64_t first_bad = 0;
  uint64_t last_bad = 0;
  for (uint64_t index = 0; index < context->event_count; index++) {
    const IsoBmffAnchorEvent *event = &context->events[index];
    if (event->prefix_good < event->samples) {
      if (!saw_bad) {
        first_bad = event->logical_block;
        saw_bad = true;
      }
      last_bad = event->logical_block;
    }
  }
  if (!saw_bad || first_bad == 0 || last_bad >= context->maximum_split) {
    return false;
  }

  uint64_t previous_good = 0;
  bool have_previous_good = false;
  uint64_t next_good = context->maximum_split;
  bool have_next_good = false;
  for (uint64_t index = 0; index < context->event_count; index++) {
    const IsoBmffAnchorEvent *event = &context->events[index];
    if (event->prefix_good != event->samples) {
      continue;
    }
    if (event->logical_block < first_bad) {
      previous_good = event->logical_block;
      have_previous_good = true;
    }
    else if (event->logical_block > last_bad) {
      next_good = event->logical_block;
      have_next_good = true;
      break;
    }
  }

  *first_min = have_previous_good ? previous_good + 1 : 1;
  *first_max = first_bad;
  *second_min = last_bad + 1;
  *second_max = have_next_good ? next_good : context->maximum_split;
  if (*second_max > context->maximum_split) {
    *second_max = context->maximum_split;
  }
  return *first_min <= *first_max && *first_max < *second_min
      && *second_min <= *second_max;
}


static inline bool isobmff_base_middle_bounds(
    const IsoBmffFooterContext *context, uint64_t base_split,
    uint64_t *first_min, uint64_t *first_max,
    uint64_t *second_min, uint64_t *second_max) {

  if (!context || !first_min || !first_max || !second_min || !second_max
      || context->event_count == 0 || base_split == 0
      || base_split > context->maximum_split) {
    return false;
  }

  bool saw_bad = false;
  uint64_t first_bad = 0;
  uint64_t last_bad = 0;
  for (uint64_t index = 0; index < context->event_count; index++) {
    const IsoBmffAnchorEvent *event = &context->events[index];
    uint32_t expected_good = event->logical_block < base_split
        ? event->prefix_good : event->suffix_good;
    if (expected_good < event->samples) {
      if (!saw_bad) {
        first_bad = event->logical_block;
        saw_bad = true;
      }
      last_bad = event->logical_block;
    }
  }
  if (!saw_bad || first_bad == 0 || last_bad >= context->maximum_split) {
    return false;
  }

  uint64_t previous_good = 0;
  bool have_previous_good = false;
  uint64_t next_good = context->maximum_split;
  bool have_next_good = false;
  for (uint64_t index = 0; index < context->event_count; index++) {
    const IsoBmffAnchorEvent *event = &context->events[index];
    uint32_t expected_good = event->logical_block < base_split
        ? event->prefix_good : event->suffix_good;
    if (expected_good != event->samples) {
      continue;
    }
    if (event->logical_block < first_bad) {
      previous_good = event->logical_block;
      have_previous_good = true;
    }
    else if (event->logical_block > last_bad) {
      next_good = event->logical_block;
      have_next_good = true;
      break;
    }
  }

  *first_min = have_previous_good ? previous_good + 1 : 1;
  *first_max = first_bad;
  *second_min = last_bad + 1;
  *second_max = have_next_good ? next_good : context->maximum_split;
  if (*second_max > context->maximum_split) {
    *second_max = context->maximum_split;
  }
  return *first_min <= *first_max && *first_max < *second_min
      && *second_min <= *second_max;
}


static inline bool isobmff_prepare_next_base_middle(
    const IsoBmffFooterContext *context, IsoBmffCarveState *state) {

  if (!context || !state || state->base_split_cursor == 0) {
    return false;
  }
  while (state->base_split_cursor <= state->base_last_split) {
    uint64_t base_split = state->base_split_cursor++;
    uint64_t first_min = 0;
    uint64_t first_max = 0;
    uint64_t second_min = 0;
    uint64_t second_max = 0;
    if (!isobmff_base_middle_bounds(
            context, base_split, &first_min, &first_max,
            &second_min, &second_max)) {
      continue;
    }
    state->active_base_split = base_split;
    state->best_first_split = first_max;
    state->best_last_split = second_min - 1;
    state->middle_actual_cursor = 0;
    state->middle_first_cursor = 0;
    state->middle_second_cursor = 0;
    state->best_middle_score = 0;
    state->stage = ISOBMFF_STAGE_SCORE_MIDDLE_RUN;
    return true;
  }
  return false;
}


static inline bool isobmff_start_base_middle(
    const IsoBmffFooterContext *context, IsoBmffCarveState *state) {

  if (!context || !state || context->prefix_delta == context->suffix_delta
      || state->best_first_split == 0
      || state->best_first_split > state->best_last_split) {
    return false;
  }
  state->base_first_split = state->best_first_split;
  state->base_last_split = state->best_last_split;
  state->base_split_cursor = state->base_first_split;
  state->active_base_split = 0;
  return isobmff_prepare_next_base_middle(context, state);
}


static inline bool isobmff_start_equal_delta_middle(
    IsoBmffFooterContext *context, IsoBmffCarveState *state) {

  uint64_t first_min = 0;
  uint64_t first_max = 0;
  uint64_t second_min = 0;
  uint64_t second_max = 0;

  if (!context || !state || state->solution_count != 0) {
    return false;
  }
  free(context->events);
  context->events = NULL;
  context->event_count = 0;
  context->suffix_delta = context->prefix_delta;
  if (!isobmff_build_anchor_events(
          context->anchors, context->anchor_count,
          context->prefix_delta, context->suffix_delta,
          &context->events, &context->event_count)
      || !isobmff_equal_delta_middle_bounds(
          context, &first_min, &first_max,
          &second_min, &second_max)) {
    free(context->events);
    context->events = NULL;
    context->event_count = 0;
    return false;
  }
  state->active_suffix_delta = context->suffix_delta;
  state->base_first_split = first_max;
  state->base_last_split = first_max;
  state->base_split_cursor = first_max + 1;
  state->active_base_split = first_max;
  state->best_first_split = first_max;
  state->best_last_split = second_min - 1;
  state->best_score = isobmff_suffix_score(context);
  state->middle_actual_cursor = 0;
  state->middle_first_cursor = 0;
  state->middle_second_cursor = 0;
  state->best_middle_score = 0;
  state->stage = ISOBMFF_STAGE_SCORE_MIDDLE_RUN;
  return true;
}


static inline void isobmff_advance_split_score(
    const IsoBmffFooterContext *context, uint64_t split,
    uint64_t *event_cursor, uint64_t *score) {

  while (*event_cursor < context->event_count
         && context->events[*event_cursor].logical_block < split) {
    const IsoBmffAnchorEvent *event = &context->events[*event_cursor];
    if (*score >= event->suffix_good) {
      *score -= event->suffix_good;
    }
    else {
      *score = 0;
    }
    *score += event->prefix_good;
    (*event_cursor)++;
  }
}


static inline bool isobmff_solution_matches_saved(
    const IsoBmffCarveState *state, const IsoBmffFooterContext *context,
    const IsoBmffSolution *solution) {

  for (uint32_t index = 0; index < state->stored_solution_count; index++) {
    const IsoBmffStoredSolution *saved = &state->solutions[index];
    // The same physical mapping is not a new solution after footer-table pruning.
    if (saved->extent == context->extent
        && saved->prefix_delta == context->prefix_delta
        && saved->suffix_delta == context->suffix_delta
        && saved->mapping.base_split == solution->base_split
        && saved->mapping.first_split == solution->first_split
        && saved->mapping.second_split == solution->second_split
        && saved->mapping.middle_delta == solution->middle_delta) {
      return true;
    }
  }
  return false;
}


static inline void isobmff_remember_solution(
    IsoBmffCarveState *state, const IsoBmffFooterContext *context,
    const IsoBmffSolution *solution) {

  if (state->stored_solution_count >= ISOBMFF_MAX_STORED_SOLUTIONS) {
    return;
  }
  IsoBmffStoredSolution *saved =
      &state->solutions[state->stored_solution_count++];
  saved->mapping = *solution;
  saved->extent = context->extent;
  saved->prefix_delta = context->prefix_delta;
  saved->suffix_delta = context->suffix_delta;
}


static inline bool isobmff_register_solution(
    IsoBmffCarveState *state,
    const IsoBmffFooterContext *context, const IsoBmffSolution *solution) {

  if (isobmff_solution_matches_saved(state, context, solution)) {
    return false;
  }
  uint64_t current_prefix = isobmff_solution_first_discontinuity(
      context->prefix_delta, context->suffix_delta, solution,
      context->logical_blocks);
  if (current_prefix != UINT64_MAX
      && (state->ambiguous_prefix_blocks == 0
          || current_prefix < state->ambiguous_prefix_blocks)) {
    state->ambiguous_prefix_blocks = current_prefix;
  }
  isobmff_remember_solution(state, context, solution);
  state->solution_count++;
  if (state->stored_solution_count >= ISOBMFF_MAX_STORED_SOLUTIONS) {
    state->stage = ISOBMFF_STAGE_FINISHED;
    return true;
  }
  return false;
}


static inline bool isobmff_middle_seed(
    const IsoBmffFooterContext *context, const IsoBmffCarveState *state,
    uint64_t *seed_index, uint64_t *corroborator_index) {

  if (!seed_index || !corroborator_index) {
    return false;
  }
  *corroborator_index = UINT64_MAX;
  for (uint64_t index = 0; index < context->anchor_count; index++) {
    uint64_t block = context->anchors[index].logical_offset
                     / scalpel_state.blocksize;
    if (block >= state->best_first_split
        && block <= state->best_last_split
        && !isobmff_anchor_at_delta(&context->anchors[index],
                                    context->prefix_delta)
        && !isobmff_anchor_at_delta(&context->anchors[index],
                                    context->suffix_delta)) {
      *seed_index = index;
      uint64_t greatest_distance = 0;
      for (uint64_t other = index + 1; other < context->anchor_count;
           other++) {
        uint64_t other_block = context->anchors[other].logical_offset
                               / scalpel_state.blocksize;
        if (other_block < state->best_first_split
            || other_block > state->best_last_split
            || isobmff_anchor_at_delta(&context->anchors[other],
                                        context->prefix_delta)
            || isobmff_anchor_at_delta(&context->anchors[other],
                                        context->suffix_delta)) {
          continue;
        }
        uint64_t distance = other_block > block
            ? other_block - block : block - other_block;
        if (*corroborator_index == UINT64_MAX
            || distance > greatest_distance) {
          *corroborator_index = other;
          greatest_distance = distance;
        }
      }
      return true;
    }
  }
  return false;
}


static inline bool isobmff_middle_delta(
    const IsoBmffFooterContext *context, uint64_t seed_index,
    uint64_t corroborator_index, uint64_t actual_block, int64_t *delta) {

  uint64_t logical_block = context->anchors[seed_index].logical_offset
                           / scalpel_state.blocksize;
  if (actual_block > (uint64_t)INT64_MAX
      || isobmff_actual_to_apparent((int64_t)actual_block) < 0
      || !isobmff_block_delta(actual_block, logical_block, delta)
      || *delta == context->prefix_delta
      || *delta == context->suffix_delta
      || !isobmff_anchor_at_delta(&context->anchors[seed_index], *delta)) {
    return false;
  }
  if (corroborator_index != UINT64_MAX
      && !isobmff_anchor_at_delta(&context->anchors[corroborator_index],
                                  *delta)) {
    return false;
  }

  return true;
}


static inline uint64_t isobmff_middle_score(
    const IsoBmffFooterContext *context, const IsoBmffCarveState *state,
    int64_t delta) {

  uint64_t score = 0;
  for (uint64_t index = 0; index < context->anchor_count; index++) {
    uint64_t block = context->anchors[index].logical_offset
                     / scalpel_state.blocksize;
    if (block >= state->best_first_split
        && block <= state->best_last_split
        && isobmff_anchor_at_delta(&context->anchors[index], delta)) {
      score++;
    }
  }
  return score;
}


static inline void isobmff_finish_footer(IsoBmffCarveState *state) {

  state->active_footer = UINT64_MAX;
  state->split_cursor = 0;
  state->event_cursor = 0;
  state->current_score = 0;
  state->best_first_split = 0;
  state->best_last_split = 0;
  state->best_score = 0;
  state->base_first_split = 0;
  state->base_last_split = 0;
  state->base_split_cursor = 0;
  state->active_base_split = 0;
  state->anchor_count = 0;
  state->suffix_actual_cursor = 0;
  state->suffix_split_last = 0;
  state->solution_count_before_suffix = 0;
  state->middle_actual_cursor = 0;
  state->middle_first_cursor = 0;
  state->middle_second_cursor = 0;
  state->best_middle_score = 0;
  state->tga_sample_ordinal = 0;
  state->tga_sample_offset = 0;
  state->tga_sample_size = 0;
  state->tga_data_first_split = 0;
  memset(&state->tga, 0, sizeof(state->tga));
  state->metadata_payload_repair = false;
  state->resume_metadata_base_scan = false;
  state->fast_context = false;
  state->resume_suffix_after_tga = false;
  state->stage = ISOBMFF_STAGE_PAIR_FOOTER;
}


static inline bool isobmff_start_tga_scan(
    const IsoBmffFooterContext *context, IsoBmffCarveState *state) {

  if (!context || !state || context->metadata_repair
      || (!state->resume_suffix_after_tga && state->solution_count != 0)
      || (state->resume_suffix_after_tga
          && state->solution_count != state->solution_count_before_suffix)
      || context->logical_blocks == 0
      || !isobmff_layout_has_tga(&context->layout)) {
    return false;
  }
  state->active_suffix_delta = context->suffix_delta
      == ISOBMFF_NO_MIDDLE_DELTA
      ? context->prefix_delta : context->suffix_delta;
  if (state->active_suffix_delta == context->prefix_delta) {
    state->base_first_split = 1;
    state->base_last_split = 1;
  }
  else {
    state->base_first_split = 1;
    state->base_last_split = context->maximum_split;
  }
  state->base_split_cursor = state->base_first_split + 1;
  state->active_base_split = state->base_first_split;
  state->tga_sample_ordinal = 0;
  state->tga_sample_offset = 0;
  state->tga_sample_size = 0;
  state->tga_data_first_split = 0;
  state->middle_actual_cursor = 0;
  state->middle_first_cursor = 0;
  state->middle_second_cursor = 0;
  memset(&state->tga, 0, sizeof(state->tga));
  state->stage = ISOBMFF_STAGE_TGA_SCAN;
  if (getenv("SCALPEL_ISOBMFF_DEBUG")) {
    fprintf(stderr,
            "ISOBMFF TGA scan prefix=%" PRId64 " suffix=%" PRId64
            " base=%" PRIu64 "-%" PRIu64 "\n",
            context->prefix_delta, state->active_suffix_delta,
            state->base_first_split, state->base_last_split);
  }
  return true;
}


static inline bool isobmff_advance_tga_base(
    const IsoBmffFooterContext *context, IsoBmffCarveState *state) {

  if (!context || !state
      || state->active_suffix_delta == context->prefix_delta
      || state->base_split_cursor == 0
      || state->base_split_cursor > state->base_last_split) {
    return false;
  }
  state->active_base_split = state->base_split_cursor++;
  state->tga_sample_ordinal = 0;
  state->tga_sample_offset = 0;
  state->tga_sample_size = 0;
  state->tga_data_first_split = 0;
  state->middle_actual_cursor = 0;
  state->middle_first_cursor = 0;
  state->middle_second_cursor = 0;
  memset(&state->tga, 0, sizeof(state->tga));
  state->stage = ISOBMFF_STAGE_TGA_SCAN;
  return true;
}


static inline void isobmff_resume_fast_suffix_scan(
    IsoBmffFooterContext *context, IsoBmffCarveState *state) {

  if (!context || !state) {
    return;
  }
  free(context->events);
  context->events = NULL;
  context->event_count = 0;
  context->suffix_delta = ISOBMFF_NO_MIDDLE_DELTA;
  state->active_suffix_delta = ISOBMFF_NO_MIDDLE_DELTA;
  state->split_cursor = 0;
  state->event_cursor = 0;
  state->current_score = 0;
  state->best_first_split = 0;
  state->best_last_split = 0;
  state->best_score = 0;
  state->base_first_split = 0;
  state->base_last_split = 0;
  state->base_split_cursor = 0;
  state->active_base_split = 0;
  state->middle_actual_cursor = 0;
  state->middle_first_cursor = 0;
  state->middle_second_cursor = 0;
  state->tga_sample_ordinal = 0;
  state->tga_sample_offset = 0;
  state->tga_sample_size = 0;
  state->tga_data_first_split = 0;
  memset(&state->tga, 0, sizeof(state->tga));
  if (state->metadata_repair) {
    state->anchor_count = 1;
    state->metadata_payload_repair = false;
    state->resume_metadata_base_scan = false;
  }
  state->resume_suffix_after_tga = false;
  state->stage = ISOBMFF_STAGE_FAST_FIND_SUFFIX;
}


static inline bool isobmff_finish_tga_attempt(
    IsoBmffFooterContext *context, IsoBmffCarveState *state) {

  if (isobmff_advance_tga_base(context, state)) {
    return true;
  }
  if (state && state->resume_suffix_after_tga) {
    isobmff_resume_fast_suffix_scan(context, state);
    return true;
  }
  isobmff_finish_active_context(state);
  return false;
}


static inline void isobmff_finish_active_context(
    IsoBmffCarveState *state) {

  if (state->fast_context) {
    state->stage = ISOBMFF_STAGE_FINISHED;
  }
  else {
    isobmff_finish_footer(state);
  }
}


static inline bool isobmff_finish_middle_attempt(
    IsoBmffFooterContext *context, IsoBmffCarveState *state) {

  if (state->fast_context
      && context->prefix_delta == context->suffix_delta
      && state->suffix_actual_cursor == UINT64_MAX) {
    if (state->solution_count != state->solution_count_before_suffix) {
      isobmff_finish_active_context(state);
      return false;
    }

    free(context->events);
    context->events = NULL;
    context->event_count = 0;
    context->suffix_delta = ISOBMFF_NO_MIDDLE_DELTA;
    state->active_suffix_delta = ISOBMFF_NO_MIDDLE_DELTA;
    state->suffix_actual_cursor = 0;
    state->middle_actual_cursor = 0;
    state->middle_first_cursor = 0;
    state->middle_second_cursor = 0;
    state->best_middle_score = 0;
    state->resume_suffix_after_tga = false;
    state->stage = ISOBMFF_STAGE_FAST_SCORE_SUFFIX;
    return true;
  }
  if (context->prefix_delta != context->suffix_delta
      && isobmff_prepare_next_base_middle(context, state)) {
    return true;
  }
  if (state->metadata_payload_repair) {
    state->metadata_payload_repair = false;
    state->resume_metadata_base_scan = true;
    state->anchor_count = 1;
    state->best_last_split = state->suffix_split_last;
    state->stage = ISOBMFF_STAGE_FAST_EVALUATE_SPLIT;
    return true;
  }
  if (state->fast_context
      && state->solution_count == state->solution_count_before_suffix
      && isobmff_start_tga_scan(context, state)) {
    return true;
  }
  if (state->fast_context && state->resume_suffix_after_tga) {
    isobmff_resume_fast_suffix_scan(context, state);
    return true;
  }
  isobmff_finish_active_context(state);
  return false;
}


static inline void isobmff_reassembly(
    ThreadWork *work, CarveInfo **candidate, uuid_string_t uuidp,
    uuid_string_t uuidc) {

  if (!work || !candidate || !*candidate || !(*candidate)->b
      || (*candidate)->needleidx < 0
      || (uint32_t)(*candidate)->needleidx >= scalpel_state.num_specs
      || scalpel_state.blocksize == 0) {
    if (candidate && *candidate) {
      destroy_candidate(candidate);
    }
    return;
  }

  normalize_blockvector((*candidate)->b);
  IsoBmffCarveState *state = (IsoBmffCarveState *)carve_get_state(
      (*candidate)->carvehashkey);
  if (!isobmff_state_valid(state)) {
    isobmff_free_carve_state((void **)&state);
    if (scalpel_state.write_promising) {
      (*candidate)->flavor = PROMISING;
      write_candidate(candidate, false);
    }
    else {
      destroy_candidate(candidate);
    }
    return;
  }

  SearchSpec *spec = &scalpel_state.search_specs[(*candidate)->needleidx];
  IsoBmffFooterContext context;
  memset(&context, 0, sizeof(context));
  bool context_ready = false;
  uint64_t iterations = 0;

  if (getenv("SCALPEL_ISOBMFF_DEBUG")) {
    fprintf(stderr,
            "ISOBMFF reassembly-entry start=%" PRIu64
            " stage=%u footer=%" PRIu64
            " extent=%" PRIu64 " expected-moov=%" PRIu64
            " length=%" PRIu64 " nonpeek=%" PRIu64 "\n",
            (*candidate)->start, state->stage, state->footer_cursor,
            state->archive_extent,
            state->expected_moov_offset,
            blockvector_get_data_length((*candidate)->b),
            blockvector_get_non_peekahead_data_length((*candidate)->b));
  }

  if (isobmff_reassembly_stop_requested(
          work, candidate, state, uuidp, uuidc)) {
    isobmff_free_carve_state((void **)&state);
    return;
  }

  while (*candidate && state->stage != ISOBMFF_STAGE_FINISHED) {
    if (state->stage == ISOBMFF_STAGE_PAIR_FOOTER
        && state->footer_cursor == 0 && !state->preferred_footer_tried
        && !context_ready) {
      bool prepared = isobmff_prepare_fast_context(
          *candidate, state->archive_extent, &context);
      if (!prepared) {
        isobmff_footer_context_clear(&context);
        prepared = isobmff_prepare_metadata_context(
            *candidate, ISOBMFF_NO_MIDDLE_DELTA, &context);
      }
      if (prepared) {
        context_ready = true;
        state->fast_context = true;
        state->archive_extent = context.extent;
        state->anchor_count = context.anchor_count;
        state->metadata_repair = context.metadata_repair;
        state->metadata_payload_repair = false;
        state->resume_metadata_base_scan = false;
        if (getenv("SCALPEL_ISOBMFF_DEBUG")) {
          fprintf(stderr,
                  "ISOBMFF fast-context-ready start=%" PRIu64
                  " extent=%" PRIu64 " blocks=%" PRIu64
                  " anchors=%" PRIu64 " prefix=%" PRId64
                  " metadata=%u\n",
                  (*candidate)->start, context.extent,
                  context.logical_blocks, context.anchor_count,
                  context.prefix_delta, context.metadata_repair);
        }
        state->middle_actual_cursor = 0;
        state->best_middle_score = 0;
        state->active_suffix_delta = ISOBMFF_NO_MIDDLE_DELTA;
        state->solution_count_before_suffix = state->solution_count;
        state->suffix_actual_cursor = UINT64_MAX;
        if (!isobmff_start_equal_delta_middle(&context, state)) {
          state->suffix_actual_cursor = 0;
          state->stage = ISOBMFF_STAGE_FAST_SCORE_SUFFIX;
        }
      }
    }
    bool resumes_fast_context = isobmff_fast_stage(state->stage)
        || (state->fast_context
            && (state->stage == ISOBMFF_STAGE_SCORE_MIDDLE_RUN
                || state->stage == ISOBMFF_STAGE_EVALUATE_MIDDLE_RUN
                || state->stage == ISOBMFF_STAGE_TGA_SCAN
                || state->stage == ISOBMFF_STAGE_TGA_MIDDLE_RUN));
    if (resumes_fast_context && !context_ready) {
      bool prepared = state->metadata_payload_repair
          ? isobmff_prepare_metadata_payload_context(
              *candidate, state->active_suffix_delta,
              state->active_base_split, &context)
          : (state->metadata_repair
              ? isobmff_prepare_metadata_context(
                  *candidate, state->active_suffix_delta, &context)
              : isobmff_prepare_fast_context(
                  *candidate, state->archive_extent, &context));
      bool extent_matches = context.extent == state->archive_extent
          || (state->metadata_repair
              && state->active_suffix_delta == ISOBMFF_NO_MIDDLE_DELTA);
      if (!prepared || context.anchor_count != state->anchor_count
          || !extent_matches) {
        isobmff_footer_context_clear(&context);
        state->stage = ISOBMFF_STAGE_FINISHED;
        break;
      }
      context_ready = true;
      if (state->stage == ISOBMFF_STAGE_FAST_SCORE_SPLIT
          || state->stage == ISOBMFF_STAGE_FAST_EVALUATE_SPLIT
          || state->stage == ISOBMFF_STAGE_SCORE_MIDDLE_RUN
          || state->stage == ISOBMFF_STAGE_EVALUATE_MIDDLE_RUN
          || state->stage == ISOBMFF_STAGE_TGA_SCAN
          || state->stage == ISOBMFF_STAGE_TGA_MIDDLE_RUN) {
        context.suffix_delta = state->active_suffix_delta;
        if (!context.events
            && !isobmff_build_anchor_events(
                context.anchors, context.anchor_count,
                context.prefix_delta, context.suffix_delta,
                &context.events, &context.event_count)) {
          isobmff_footer_context_clear(&context);
          state->stage = ISOBMFF_STAGE_FINISHED;
          break;
        }
      }
    }

    if (state->stage == ISOBMFF_STAGE_PAIR_FOOTER) {
      isobmff_footer_context_clear(&context);
      context_ready = false;
      state->metadata_repair = false;
      state->metadata_payload_repair = false;
      state->resume_metadata_base_scan = false;
      state->fast_context = false;

      if (state->preferred_footer == UINT64_MAX
          && !state->preferred_footer_tried) {
        state->preferred_footer = isobmff_preferred_footer(
            *candidate, spec, state->expected_moov_offset);
        if (state->preferred_footer == UINT64_MAX) {
          state->preferred_footer_tried = true;
        }
      }
      while (true) {
        uint64_t footer = isobmff_next_footer(spec, state);
        if (footer == UINT64_MAX) {
          break;
        }
        if (isobmff_prepare_footer_context(*candidate, footer, &context)) {
          if (getenv("SCALPEL_ISOBMFF_DEBUG")) {
            fprintf(stderr,
                    "ISOBMFF context start=%" PRIu64
                    " footer=%" PRIu64 " extent=%" PRIu64
                    " prefix=%" PRId64 " suffix=%" PRId64
                    " anchors=%" PRIu64 "\n",
                    (*candidate)->start, footer, context.extent,
                    context.prefix_delta, context.suffix_delta,
                    context.anchor_count);
          }
          context_ready = true;
          state->active_footer = spec->offsets.footers[footer];
          state->expected_moov_offset = context.maximum_split
                                        * scalpel_state.blocksize
                                        + context.moov_actual
                                          % scalpel_state.blocksize;
          state->archive_extent = context.extent;
          state->anchor_count = context.anchor_count;
          state->split_cursor = 0;
          state->event_cursor = 0;
          state->current_score = 0;
          state->best_first_split = 0;
          state->best_last_split = 0;
          state->best_score = 0;
          state->base_first_split = 0;
          state->base_last_split = 0;
          state->base_split_cursor = 0;
          state->active_base_split = 0;
          state->middle_actual_cursor = 0;
          state->middle_first_cursor = 0;
          state->middle_second_cursor = 0;
          state->best_middle_score = 0;
          state->stage = ISOBMFF_STAGE_SCORE_TWO_RUN;
          break;
        }
        if (isobmff_reassembly_poll(
                work, candidate, state, uuidp, uuidc, &iterations)) {
          isobmff_footer_context_clear(&context);
          isobmff_free_carve_state((void **)&state);
          return;
        }
      }
      if (!context_ready) {
        state->stage = ISOBMFF_STAGE_FINISHED;
        break;
      }
    }
    else if (!context_ready) {
      if (state->active_footer == UINT64_MAX
          || !isobmff_prepare_footer_context(
              *candidate, isobmff_footer_index(spec, state->active_footer),
              &context)
          || context.anchor_count != state->anchor_count
          || context.extent != state->archive_extent) {
        isobmff_footer_context_clear(&context);
        isobmff_finish_footer(state);
        continue;
      }
      context_ready = true;
    }

    if (state->stage == ISOBMFF_STAGE_FAST_SCORE_SUFFIX) {
      uint64_t seed_index = 0;
      uint64_t corroborator_index = UINT64_MAX;
      uint64_t image_blocks = CEILDIV(
          filemirror_filesize(scalpel_state.filemirror),
          scalpel_state.blocksize);

      context.suffix_delta = ISOBMFF_NO_MIDDLE_DELTA;

      if (!isobmff_fast_suffix_seed(
              &context, &seed_index, &corroborator_index)) {
        state->resume_suffix_after_tga = false;
        state->solution_count_before_suffix = state->solution_count;
        if (!isobmff_start_equal_delta_middle(&context, state)
            && !isobmff_start_tga_scan(&context, state)) {
          state->stage = ISOBMFF_STAGE_FINISHED;
        }
        continue;
      }
      while (state->middle_actual_cursor < image_blocks) {
        uint64_t actual = state->middle_actual_cursor++;
        int64_t delta = 0;

        if (isobmff_fast_suffix_delta(
                &context, seed_index, corroborator_index, actual, &delta)) {
          uint64_t score = isobmff_fast_suffix_score(&context, delta);
          if (score > state->best_middle_score) {
            state->best_middle_score = score;
            if (getenv("SCALPEL_ISOBMFF_DEBUG")) {
              fprintf(stderr,
                      "ISOBMFF fast-suffix start=%" PRIu64
                      " actual=%" PRIu64 " delta=%" PRId64
                      " score=%" PRIu64 "\n",
                      (*candidate)->start, actual, delta, score);
            }
          }
        }
        if (isobmff_reassembly_poll(
                work, candidate, state, uuidp, uuidc, &iterations)) {
          isobmff_footer_context_clear(&context);
          isobmff_free_carve_state((void **)&state);
          return;
        }
      }
      if (state->best_middle_score == 0) {
        if (isobmff_start_equal_delta_middle(&context, state)) {
          if (getenv("SCALPEL_ISOBMFF_DEBUG")) {
            fprintf(stderr,
                    "ISOBMFF fast-middle start=%" PRIu64
                    " first=%" PRIu64 " second=%" PRIu64 "\n",
                    (*candidate)->start, state->best_first_split,
                    state->best_last_split + 1);
          }
        }
        else {
          if (getenv("SCALPEL_ISOBMFF_DEBUG")) {
            fprintf(stderr,
                    "ISOBMFF fast-suffix start=%" PRIu64
                    " found no matching suffix or middle run\n",
                    (*candidate)->start);
          }
          if (!isobmff_start_tga_scan(&context, state)) {
            state->stage = ISOBMFF_STAGE_FINISHED;
          }
        }
      }
      else {
        state->suffix_actual_cursor = 0;
        state->stage = ISOBMFF_STAGE_FAST_FIND_SUFFIX;
      }
      continue;
    }

    if (state->stage == ISOBMFF_STAGE_FAST_FIND_SUFFIX) {
      uint64_t seed_index = 0;
      uint64_t corroborator_index = UINT64_MAX;
      uint64_t image_blocks = CEILDIV(
          filemirror_filesize(scalpel_state.filemirror),
          scalpel_state.blocksize);

      if (state->metadata_repair && !state->metadata_payload_repair
          && context.anchor_count != state->anchor_count) {
        isobmff_footer_context_clear(&context);
        if (!isobmff_prepare_metadata_context(
                *candidate, ISOBMFF_NO_MIDDLE_DELTA, &context)) {
          state->stage = ISOBMFF_STAGE_FINISHED;
          continue;
        }
        context_ready = true;
      }

      if (!isobmff_fast_suffix_seed(
              &context, &seed_index, &corroborator_index)) {
        state->resume_suffix_after_tga = false;
        state->solution_count_before_suffix = state->solution_count;
        if (state->solution_count != 0) {
          state->stage = ISOBMFF_STAGE_FINISHED;
        }
        else if (!isobmff_start_tga_scan(&context, state)) {
          state->stage = ISOBMFF_STAGE_FINISHED;
        }
        continue;
      }
      while (state->suffix_actual_cursor < image_blocks) {
        uint64_t actual = state->suffix_actual_cursor++;
        int64_t delta = 0;

        if (isobmff_fast_suffix_delta(
                &context, seed_index, corroborator_index, actual, &delta)
            && isobmff_fast_suffix_score(&context, delta)
                   == state->best_middle_score) {
          bool suffix_ready = true;
          if (context.metadata_repair) {
            suffix_ready = isobmff_metadata_context_set_suffix(
                &context, delta);
          }
          else {
            context.suffix_delta = delta;
          }
          if (suffix_ready && isobmff_build_anchor_events(
                  context.anchors, context.anchor_count,
                  context.prefix_delta, context.suffix_delta,
                  &context.events, &context.event_count)) {
            state->active_suffix_delta = delta;
            state->solution_count_before_suffix = state->solution_count;
            state->resume_suffix_after_tga = true;
            state->archive_extent = context.extent;
            state->split_cursor = 0;
            state->event_cursor = 0;
            state->current_score = 0;
            state->best_first_split = 0;
            state->best_last_split = 0;
            state->best_score = 0;
            state->base_first_split = 0;
            state->base_last_split = 0;
            state->base_split_cursor = 0;
            state->active_base_split = 0;
            state->stage = ISOBMFF_STAGE_FAST_SCORE_SPLIT;
            break;
          }
        }
        if (isobmff_reassembly_poll(
                work, candidate, state, uuidp, uuidc, &iterations)) {
          isobmff_footer_context_clear(&context);
          isobmff_free_carve_state((void **)&state);
          return;
        }
      }
      if (state->stage == ISOBMFF_STAGE_FAST_FIND_SUFFIX) {
        state->resume_suffix_after_tga = false;
        state->solution_count_before_suffix = state->solution_count;
        if (state->solution_count != 0) {
          state->stage = ISOBMFF_STAGE_FINISHED;
        }
        else if (!isobmff_start_equal_delta_middle(&context, state)
                 && !isobmff_start_tga_scan(&context, state)) {
          state->stage = ISOBMFF_STAGE_FINISHED;
        }
      }
      continue;
    }

    if (state->stage == ISOBMFF_STAGE_FAST_SCORE_SPLIT) {
      if (state->split_cursor == 0) {
        state->split_cursor = 1;
        state->event_cursor = 0;
        state->current_score = isobmff_suffix_score(&context);
      }
      while (state->split_cursor <= context.maximum_split) {
        uint64_t split = state->split_cursor;
        isobmff_advance_split_score(
            &context, split, &state->event_cursor, &state->current_score);
        if (state->best_first_split == 0
            || state->current_score > state->best_score) {
          state->best_score = state->current_score;
          state->best_first_split = split;
          state->best_last_split = split;
        }
        else if (state->current_score == state->best_score) {
          state->best_last_split = split;
        }
        state->split_cursor = split + 1;
        if (isobmff_reassembly_poll(
                work, candidate, state, uuidp, uuidc, &iterations)) {
          isobmff_footer_context_clear(&context);
          isobmff_free_carve_state((void **)&state);
          return;
        }
      }
      state->suffix_split_last = state->best_last_split;
      if (state->best_score == context.anchor_count) {
        state->split_cursor = state->best_first_split;
        state->event_cursor = 0;
        state->current_score = isobmff_suffix_score(&context);
        isobmff_advance_split_score(
            &context, state->split_cursor,
            &state->event_cursor, &state->current_score);
        state->stage = ISOBMFF_STAGE_FAST_EVALUATE_SPLIT;
      }
      else {
        if (!isobmff_start_base_middle(&context, state)
            && !isobmff_start_tga_scan(&context, state)) {
          state->stage = ISOBMFF_STAGE_FINISHED;
        }
      }
      continue;
    }

    if (state->stage == ISOBMFF_STAGE_FAST_EVALUATE_SPLIT) {
      if (state->resume_metadata_base_scan) {
        isobmff_footer_context_clear(&context);
        if (!isobmff_prepare_metadata_context(
                *candidate, state->active_suffix_delta, &context)
            || !isobmff_build_anchor_events(
                context.anchors, context.anchor_count,
                context.prefix_delta, context.suffix_delta,
                &context.events, &context.event_count)) {
          isobmff_footer_context_clear(&context);
          state->stage = ISOBMFF_STAGE_FINISHED;
          continue;
        }
        context_ready = true;
        state->resume_metadata_base_scan = false;
      }
      uint8_t *trial = (uint8_t *)malloc((size_t)context.extent);
      uint64_t trial_capacity = context.extent;
      bool started_payload_middle = false;
      if (trial) {
        while (state->split_cursor <= state->best_last_split) {
          uint64_t split = state->split_cursor;
          isobmff_advance_split_score(
              &context, split, &state->event_cursor, &state->current_score);
          state->split_cursor = split + 1;

          if (state->current_score == state->best_score) {
            IsoBmffSolution solution = {
              .footer_offset = UINT64_MAX,
              .base_split = split,
              .first_split = split,
              .second_split = split,
              .middle_delta = ISOBMFF_NO_MIDDLE_DELTA
            };
            uint64_t solution_extent = isobmff_solution_extent(
                context.prefix_delta, context.suffix_delta,
                &solution, context.extent);
            bool can_evaluate = true;
            if (solution_extent > trial_capacity) {
              uint8_t *grown = (uint8_t *)realloc(
                  trial, (size_t)solution_extent);
              if (!grown) {
                can_evaluate = false;
              }
              else {
                trial = grown;
                trial_capacity = solution_extent;
              }
            }
            if (can_evaluate) {
              IsoBmffLayout layout;
              bool complete = isobmff_solution_complete(
                  context.prefix_delta, context.suffix_delta,
                  &solution, solution_extent, trial, &layout);
              if (complete) {
                IsoBmffFooterContext solution_context = context;
                solution_context.extent = solution_extent;
                solution_context.logical_blocks = CEILDIV(
                    solution_extent, scalpel_state.blocksize);
                if (isobmff_register_solution(
                        state, &solution_context, &solution)) {
                  isobmff_free_layout(&layout);
                  break;
                }
              }
              isobmff_free_layout(&layout);
              if (!complete && context.metadata_repair) {
                IsoBmffFooterContext payload_context;
                memset(&payload_context, 0, sizeof(payload_context));
                if (isobmff_prepare_metadata_payload_context(
                        *candidate, context.suffix_delta, split,
                        &payload_context)) {
                  state->base_first_split = split;
                  state->base_last_split = split;
                  state->base_split_cursor = split;
                  if (isobmff_prepare_next_base_middle(
                          &payload_context, state)) {
                    isobmff_footer_context_clear(&context);
                    context = payload_context;
                    context_ready = true;
                    state->archive_extent = context.extent;
                    state->anchor_count = context.anchor_count;
                    state->metadata_payload_repair = true;
                    started_payload_middle = true;
                  }
                  else {
                    isobmff_footer_context_clear(&payload_context);
                  }
                }
              }
            }
          }
          if (started_payload_middle) {
            break;
          }
          if (isobmff_reassembly_poll(
                  work, candidate, state, uuidp, uuidc, &iterations)) {
            free(trial);
            isobmff_footer_context_clear(&context);
            isobmff_free_carve_state((void **)&state);
            return;
          }
        }
        free(trial);
      }
      if (started_payload_middle) {
        continue;
      }
      if (state->solution_count == state->solution_count_before_suffix
          && isobmff_start_tga_scan(&context, state)) {
        continue;
      }
      isobmff_resume_fast_suffix_scan(&context, state);
      continue;
    }

    if (state->stage == ISOBMFF_STAGE_TGA_SCAN) {
      context.suffix_delta = state->active_suffix_delta;
      if (state->tga_sample_size == 0) {
        uint64_t sample_offset = 0;
        uint64_t sample_size = 0;
        if (!isobmff_tga_sample_by_ordinal(
                &context.layout, state->tga_sample_ordinal,
                &sample_offset, &sample_size)) {
          isobmff_finish_tga_attempt(&context, state);
          continue;
        }
        state->tga_sample_offset = sample_offset;
        state->tga_sample_size = sample_size;
        memset(&state->tga, 0, sizeof(state->tga));

        uint8_t header[18];
        IsoBmffSolution baseline = {
          .footer_offset = UINT64_MAX,
          .base_split = state->active_base_split,
          .first_split = UINT64_MAX,
          .second_split = UINT64_MAX,
          .middle_delta = ISOBMFF_NO_MIDDLE_DELTA
        };
        if (!isobmff_read_solution_bytes(
                context.prefix_delta, state->active_suffix_delta,
                &baseline, sample_offset, header, sizeof(header))
            || !isobmff_tga_rle_stream_initialize(
                &state->tga, header, sample_size)) {
          state->tga_sample_ordinal++;
          state->tga_sample_offset = 0;
          state->tga_sample_size = 0;
          memset(&state->tga, 0, sizeof(state->tga));
          continue;
        }
      }

      while (state->tga.bytes_seen < state->tga_sample_size
             && !state->tga.invalid) {
        uint64_t logical_offset = state->tga_sample_offset
                                  + state->tga.bytes_seen;
        uint64_t count = scalpel_state.blocksize
                         - logical_offset % scalpel_state.blocksize;
        uint64_t remaining = state->tga_sample_size
                             - state->tga.bytes_seen;
        if (count > remaining) {
          count = remaining;
        }
        if (!isobmff_tga_feed_logical_range(
                &state->tga, context.prefix_delta,
                state->active_suffix_delta, state->active_base_split,
                logical_offset, count)) {
          break;
        }
        if (isobmff_reassembly_poll(
                work, candidate, state, uuidp, uuidc, &iterations)) {
          isobmff_footer_context_clear(&context);
          isobmff_free_carve_state((void **)&state);
          return;
        }
      }

      if (state->tga.invalid
          || (state->tga.bytes_seen == state->tga_sample_size
              && !isobmff_tga_rle_stream_complete(&state->tga))) {
        if (isobmff_tga_configure_middle_search(&context, state)) {
          if (getenv("SCALPEL_ISOBMFF_DEBUG")) {
            fprintf(stderr,
                    "ISOBMFF TGA middle start=%" PRIu64
                    " sample=%" PRIu64 " first=%" PRIu64
                    "-%" PRIu64 " failure=%" PRIu64 "\n",
                    (*candidate)->start, state->tga_sample_ordinal,
                    state->best_first_split, state->best_last_split,
                    state->tga.failure_offset);
          }
        }
        else {
          isobmff_finish_tga_attempt(&context, state);
        }
        continue;
      }
      if (state->tga.bytes_seen == state->tga_sample_size) {
        state->tga_sample_ordinal++;
        state->tga_sample_offset = 0;
        state->tga_sample_size = 0;
        memset(&state->tga, 0, sizeof(state->tga));
      }
      continue;
    }

    if (state->stage == ISOBMFF_STAGE_TGA_MIDDLE_RUN) {
      context.suffix_delta = state->active_suffix_delta;
      uint64_t image_blocks = CEILDIV(
          filemirror_filesize(scalpel_state.filemirror),
          scalpel_state.blocksize);
      uint64_t sample_end = state->tga_sample_offset
                            + state->tga_sample_size;
      uint64_t second_limit = sample_end / scalpel_state.blocksize
                              + (sample_end % scalpel_state.blocksize != 0);
      if (second_limit > context.maximum_split) {
        second_limit = context.maximum_split;
      }
      uint8_t *trial = (uint8_t *)malloc((size_t)context.extent);
      uint64_t trial_capacity = context.extent;
      if (!trial) {
        isobmff_finish_active_context(state);
        continue;
      }

      uint64_t first = state->middle_first_cursor != 0
          ? state->middle_first_cursor : state->best_first_split;
      while (first <= state->best_last_split && first < second_limit) {
        uint8_t header[18];
        IsoBmffTgaRleState prefix;
        IsoBmffSolution baseline = {
          .footer_offset = UINT64_MAX,
          .base_split = state->active_base_split,
          .first_split = UINT64_MAX,
          .second_split = UINT64_MAX,
          .middle_delta = ISOBMFF_NO_MIDDLE_DELTA
        };
        uint64_t prefix_end = first * (uint64_t)scalpel_state.blocksize;
        bool prefix_valid = prefix_end > state->tga_sample_offset
            && prefix_end <= sample_end
            && isobmff_read_solution_bytes(
                context.prefix_delta, state->active_suffix_delta,
                &baseline, state->tga_sample_offset,
                header, sizeof(header))
            && isobmff_tga_rle_stream_initialize(
                &prefix, header, state->tga_sample_size)
            && isobmff_tga_feed_logical_range(
                &prefix, context.prefix_delta,
                state->active_suffix_delta, state->active_base_split,
                state->tga_sample_offset,
                prefix_end - state->tga_sample_offset);

        if (prefix_valid) {
          uint64_t actual = state->middle_actual_cursor;
          while (actual < image_blocks) {
            IsoBmffTgaRleState middle = prefix;
            uint64_t resume_second = state->middle_second_cursor != 0
                ? state->middle_second_cursor : first + 1;
            uint64_t second = first + 1;

            while (second <= second_limit) {
              uint64_t source_block = actual + (second - first - 1);
              uint64_t destination = (second - 1)
                                     * (uint64_t)scalpel_state.blocksize;
              uint64_t count = scalpel_state.blocksize;
              if (source_block < actual || source_block >= image_blocks
                  || destination >= sample_end
                  || isobmff_actual_to_apparent(
                         (int64_t)source_block) < 0) {
                break;
              }
              if (count > sample_end - destination) {
                count = sample_end - destination;
              }
              if (!isobmff_tga_feed_actual_range(
                      &middle,
                      source_block * (uint64_t)scalpel_state.blocksize,
                      count)) {
                break;
              }

              if (second >= resume_second
                  && isobmff_solution_nonoverlapping(
                      &context, state->active_base_split,
                      first, second, actual, context.logical_blocks)) {
                IsoBmffTgaRleState complete = middle;
                uint64_t suffix_start = second
                                        * (uint64_t)scalpel_state.blocksize;
                if (suffix_start > sample_end) {
                  suffix_start = sample_end;
                }
                if (isobmff_tga_feed_logical_range(
                        &complete, context.prefix_delta,
                        state->active_suffix_delta,
                        state->active_base_split,
                        suffix_start, sample_end - suffix_start)
                    && isobmff_tga_rle_stream_complete(&complete)) {
                  int64_t middle_delta = 0;
                  IsoBmffSolution solution = {
                    .footer_offset = UINT64_MAX,
                    .base_split = state->active_base_split,
                    .first_split = first,
                    .second_split = second,
                    .middle_delta = ISOBMFF_NO_MIDDLE_DELTA
                  };
                  IsoBmffLayout layout;
                  memset(&layout, 0, sizeof(layout));
                  if (isobmff_block_delta(
                          actual, first, &middle_delta)) {
                    solution.middle_delta = middle_delta;
                    uint64_t solution_extent = isobmff_solution_extent(
                        context.prefix_delta, state->active_suffix_delta,
                        &solution, context.extent);
                    uint64_t solution_blocks = CEILDIV(
                        solution_extent, scalpel_state.blocksize);
                    bool can_evaluate = isobmff_solution_nonoverlapping(
                        &context, state->active_base_split,
                        first, second, actual, solution_blocks);
                    if (can_evaluate && solution_extent > trial_capacity) {
                      uint8_t *grown = (uint8_t *)realloc(
                          trial, (size_t)solution_extent);
                      if (!grown) {
                        can_evaluate = false;
                      }
                      else {
                        trial = grown;
                        trial_capacity = solution_extent;
                      }
                    }
                    if (can_evaluate && isobmff_solution_complete(
                            context.prefix_delta, state->active_suffix_delta,
                            &solution, solution_extent, trial, &layout)) {
                      IsoBmffFooterContext solution_context = context;
                      solution_context.suffix_delta =
                          state->active_suffix_delta;
                      solution_context.extent = solution_extent;
                      solution_context.logical_blocks = solution_blocks;
                      bool stop_search = isobmff_register_solution(
                          state, &solution_context, &solution);
                      state->repairs++;
                      if (getenv("SCALPEL_ISOBMFF_DEBUG")) {
                        fprintf(stderr,
                                "ISOBMFF TGA solution start=%" PRIu64
                                " first=%" PRIu64 " second=%" PRIu64
                                " actual=%" PRIu64 "\n",
                                (*candidate)->start, first, second, actual);
                      }
                      if (stop_search) {
                        isobmff_free_layout(&layout);
                        break;
                      }
                    }
                    isobmff_free_layout(&layout);
                  }
                }
              }

              state->middle_first_cursor = first;
              state->middle_actual_cursor = actual;
              isobmff_advance_middle_cursor(state, second + 1);
              if (isobmff_reassembly_poll(
                      work, candidate, state, uuidp, uuidc, &iterations)) {
                free(trial);
                isobmff_footer_context_clear(&context);
                isobmff_free_carve_state((void **)&state);
                return;
              }
              second++;
            }
            if (state->stage == ISOBMFF_STAGE_FINISHED) {
              break;
            }
            state->middle_actual_cursor = ++actual;
            state->middle_second_cursor = 0;
            if (isobmff_reassembly_poll(
                    work, candidate, state, uuidp, uuidc, &iterations)) {
              free(trial);
              isobmff_footer_context_clear(&context);
              isobmff_free_carve_state((void **)&state);
              return;
            }
          }
        }

        state->middle_first_cursor = ++first;
        state->middle_actual_cursor = 0;
        state->middle_second_cursor = 0;
        if (state->stage == ISOBMFF_STAGE_FINISHED) {
          break;
        }
      }
      free(trial);

      if (state->stage == ISOBMFF_STAGE_FINISHED) {
        continue;
      }

      if (state->solution_count == 0
          && state->best_first_split > state->tga_data_first_split) {
        state->best_last_split = state->best_first_split - 1;
        state->best_first_split = state->tga_data_first_split;
        state->middle_first_cursor = state->best_first_split;
        state->middle_actual_cursor = 0;
        state->middle_second_cursor = 0;
        if (getenv("SCALPEL_ISOBMFF_DEBUG")) {
          fprintf(stderr,
                  "ISOBMFF TGA widening start=%" PRIu64
                  " first=%" PRIu64 "-%" PRIu64 "\n",
                  (*candidate)->start, state->best_first_split,
                  state->best_last_split);
        }
      }
      else {
        isobmff_finish_tga_attempt(&context, state);
      }
      continue;
    }

    if (state->stage == ISOBMFF_STAGE_SCORE_TWO_RUN) {
      if (context.prefix_delta == context.suffix_delta) {
        uint64_t first_min = 0;
        uint64_t first_max = 0;
        uint64_t second_min = 0;
        uint64_t second_max = 0;
        state->best_score = isobmff_suffix_score(&context);
        if (state->best_score == context.anchor_count) {
          state->best_first_split = context.maximum_split;
          state->best_last_split = context.maximum_split;
          state->split_cursor = context.maximum_split;
          state->event_cursor = 0;
          state->current_score = state->best_score;
          state->stage = ISOBMFF_STAGE_EVALUATE_TWO_RUN;
        }
        else if (isobmff_equal_delta_middle_bounds(
                     &context, &first_min, &first_max,
                     &second_min, &second_max)) {
          state->base_first_split = first_max;
          state->base_last_split = first_max;
          state->base_split_cursor = first_max + 1;
          state->active_base_split = first_max;
          state->best_first_split = first_max;
          state->best_last_split = second_min - 1;
          state->middle_actual_cursor = 0;
          state->best_middle_score = 0;
          state->stage = ISOBMFF_STAGE_SCORE_MIDDLE_RUN;
          if (getenv("SCALPEL_ISOBMFF_DEBUG")) {
            fprintf(stderr,
                    "ISOBMFF middle start=%" PRIu64
                    " first=%" PRIu64 "-%" PRIu64
                    " second=%" PRIu64 "-%" PRIu64 "\n",
                    (*candidate)->start, first_min, first_max,
                    second_min, second_max);
          }
        }
        else {
          isobmff_footer_context_clear(&context);
          context_ready = false;
          isobmff_finish_footer(state);
        }
        continue;
      }
      if (state->split_cursor == 0) {
        state->split_cursor = 1;
        state->event_cursor = 0;
        state->current_score = isobmff_suffix_score(&context);
      }
      while (state->split_cursor <= context.maximum_split) {
        uint64_t split = state->split_cursor;
        isobmff_advance_split_score(
            &context, split, &state->event_cursor, &state->current_score);
        if (state->best_first_split == 0
            || state->current_score > state->best_score) {
          state->best_score = state->current_score;
          state->best_first_split = split;
          state->best_last_split = split;
        }
        else if (state->current_score == state->best_score) {
          state->best_last_split = split;
        }
        state->split_cursor = split + 1;
        if (isobmff_reassembly_poll(
                work, candidate, state, uuidp, uuidc, &iterations)) {
          isobmff_footer_context_clear(&context);
          isobmff_free_carve_state((void **)&state);
          return;
        }
      }

      if (state->best_score == context.anchor_count) {
        if (getenv("SCALPEL_ISOBMFF_DEBUG")) {
          fprintf(stderr,
                  "ISOBMFF score start=%" PRIu64
                  " footer=%" PRIu64 " best=%" PRIu64
                  " anchors=%" PRIu64 " splits=%" PRIu64 "-%" PRIu64
                  "\n",
                  (*candidate)->start, state->active_footer,
                  state->best_score, context.anchor_count,
                  state->best_first_split, state->best_last_split);
        }
        state->stage = ISOBMFF_STAGE_EVALUATE_TWO_RUN;
        state->split_cursor = state->best_first_split;
        state->event_cursor = 0;
        state->current_score = isobmff_suffix_score(&context);
        isobmff_advance_split_score(
            &context, state->split_cursor,
            &state->event_cursor, &state->current_score);
      }
      else {
        if (!isobmff_start_base_middle(&context, state)) {
          isobmff_footer_context_clear(&context);
          context_ready = false;
          isobmff_finish_footer(state);
        }
      }
      continue;
    }

    if (state->stage == ISOBMFF_STAGE_EVALUATE_TWO_RUN) {
      uint8_t *trial = (uint8_t *)malloc((size_t)context.extent);
      if (!trial) {
        isobmff_finish_footer(state);
        continue;
      }
      while (state->split_cursor <= state->best_last_split) {
        uint64_t split = state->split_cursor;
        isobmff_advance_split_score(
            &context, split, &state->event_cursor, &state->current_score);
        state->split_cursor = split + 1;

        if (state->current_score == state->best_score) {
          IsoBmffSolution solution = {
            .footer_offset = state->active_footer,
            .base_split = split,
            .first_split = split,
            .second_split = split,
            .middle_delta = ISOBMFF_NO_MIDDLE_DELTA
          };
          IsoBmffLayout layout;
          if (isobmff_solution_alac_boundaries_valid(
                  &context, context.prefix_delta, context.suffix_delta,
                  &solution)
              && isobmff_solution_complete(
                  context.prefix_delta, context.suffix_delta,
                  &solution, context.extent, trial, &layout)) {
            if (isobmff_register_solution(
                    state, &context, &solution)) {
              isobmff_free_layout(&layout);
              break;
            }
          }
          isobmff_free_layout(&layout);
        }
        if (isobmff_reassembly_poll(
                work, candidate, state, uuidp, uuidc, &iterations)) {
          free(trial);
          isobmff_footer_context_clear(&context);
          isobmff_free_carve_state((void **)&state);
          return;
        }
      }
      free(trial);
      isobmff_footer_context_clear(&context);
      context_ready = false;
      if (state->stage != ISOBMFF_STAGE_FINISHED) {
        isobmff_finish_footer(state);
      }
      continue;
    }

    if (state->stage == ISOBMFF_STAGE_SCORE_MIDDLE_RUN) {
      uint64_t seed_index = 0;
      uint64_t corroborator_index = UINT64_MAX;
      if (!isobmff_middle_seed(
              &context, state, &seed_index, &corroborator_index)) {
        if (!isobmff_finish_middle_attempt(&context, state)) {
          isobmff_footer_context_clear(&context);
          context_ready = false;
        }
        continue;
      }
      uint64_t image_blocks = CEILDIV(
          filemirror_filesize(scalpel_state.filemirror),
          scalpel_state.blocksize);
      while (state->middle_actual_cursor < image_blocks) {
        uint64_t actual = state->middle_actual_cursor++;
        int64_t delta = 0;
        if (isobmff_middle_delta(
                &context, seed_index, corroborator_index,
                actual, &delta)) {
          uint64_t score = isobmff_middle_score(&context, state, delta);
          if (score > state->best_middle_score) {
            state->best_middle_score = score;
          }
        }
        if (isobmff_reassembly_poll(
                work, candidate, state, uuidp, uuidc, &iterations)) {
          isobmff_footer_context_clear(&context);
          isobmff_free_carve_state((void **)&state);
          return;
        }
      }
      if (state->best_middle_score == 0) {
        if (!isobmff_finish_middle_attempt(&context, state)) {
          isobmff_footer_context_clear(&context);
          context_ready = false;
        }
      }
      else {
        state->stage = ISOBMFF_STAGE_EVALUATE_MIDDLE_RUN;
        state->middle_actual_cursor = 0;
        state->middle_first_cursor = 0;
        state->middle_second_cursor = 0;
      }
      continue;
    }

    if (state->stage == ISOBMFF_STAGE_EVALUATE_MIDDLE_RUN) {
      uint64_t seed_index = 0;
      uint64_t corroborator_index = UINT64_MAX;
      uint64_t image_blocks = CEILDIV(
          filemirror_filesize(scalpel_state.filemirror),
          scalpel_state.blocksize);
      uint64_t first_begin = state->best_first_split;
      uint64_t first_limit = state->best_last_split;
      uint64_t second_begin = 0;
      uint64_t second_limit = state->best_last_split < UINT64_MAX
          ? state->best_last_split + 1 : state->best_last_split;
      bool bounds_ready = context.prefix_delta == context.suffix_delta
          ? isobmff_equal_delta_middle_bounds(
              &context, &first_begin, &first_limit,
              &second_begin, &second_limit)
          : isobmff_base_middle_bounds(
              &context, state->active_base_split,
              &first_begin, &first_limit,
              &second_begin, &second_limit);
      if (!bounds_ready) {
        if (!isobmff_finish_middle_attempt(&context, state)) {
          isobmff_footer_context_clear(&context);
          context_ready = false;
        }
        continue;
      }
      if (second_limit > context.maximum_split) {
        second_limit = context.maximum_split;
      }
      if (!isobmff_middle_seed(
              &context, state, &seed_index, &corroborator_index)
          || first_begin > first_limit || first_begin >= second_limit) {
        if (!isobmff_finish_middle_attempt(&context, state)) {
          isobmff_footer_context_clear(&context);
          context_ready = false;
        }
        continue;
      }
      uint8_t *trial = (uint8_t *)malloc((size_t)context.extent);
      uint64_t trial_capacity = context.extent;
      if (!trial) {
        isobmff_finish_active_context(state);
        continue;
      }

      while (state->middle_actual_cursor < image_blocks) {
        uint64_t actual = state->middle_actual_cursor;
        int64_t delta = 0;
        bool eligible = isobmff_middle_delta(
            &context, seed_index, corroborator_index, actual, &delta)
            && isobmff_middle_score(&context, state, delta)
                   == state->best_middle_score;

        if (eligible) {
          uint64_t first = state->middle_first_cursor != 0
              ? state->middle_first_cursor : first_begin;
          while (first <= first_limit && first < second_limit) {
            uint64_t default_second = second_begin > first
                ? second_begin : first + 1;
            uint64_t second = state->middle_second_cursor != 0
                ? state->middle_second_cursor : default_second;
            while (second <= second_limit) {
              state->middle_first_cursor = first;
              state->middle_second_cursor = second + 1;
              IsoBmffSolution solution = {
                .footer_offset = state->active_footer,
                .base_split = state->active_base_split,
                .first_split = first,
                .second_split = second,
                .middle_delta = delta
              };
              uint64_t solution_extent = isobmff_solution_extent(
                  context.prefix_delta, context.suffix_delta,
                  &solution, context.extent);
              bool can_evaluate = isobmff_solution_nonoverlapping(
                  &context, state->active_base_split,
                  first, second, actual,
                  CEILDIV(solution_extent, scalpel_state.blocksize));
              if (solution_extent > trial_capacity) {
                uint8_t *grown = (uint8_t *)realloc(
                    trial, (size_t)solution_extent);
                if (!grown) {
                  can_evaluate = false;
                }
                else {
                  trial = grown;
                  trial_capacity = solution_extent;
                }
              }
              if (can_evaluate
                  && isobmff_solution_alac_boundaries_valid(
                      &context, context.prefix_delta,
                      context.suffix_delta, &solution)) {
                IsoBmffLayout layout;
                if (isobmff_solution_complete(
                        context.prefix_delta, context.suffix_delta,
                        &solution, solution_extent, trial, &layout)) {
                  IsoBmffFooterContext solution_context = context;
                  solution_context.extent = solution_extent;
                  solution_context.logical_blocks = CEILDIV(
                      solution_extent, scalpel_state.blocksize);
                  bool complete = isobmff_register_solution(
                      state, &solution_context, &solution);
                  state->repairs++;
                  if (complete) {
                    isobmff_free_layout(&layout);
                    break;
                  }
                }
                isobmff_free_layout(&layout);
              }
              if (isobmff_reassembly_poll(
                      work, candidate, state, uuidp, uuidc, &iterations)) {
                free(trial);
                isobmff_footer_context_clear(&context);
                isobmff_free_carve_state((void **)&state);
                return;
              }
              second++;
            }
            if (state->stage == ISOBMFF_STAGE_FINISHED) {
              break;
            }
            state->middle_second_cursor = 0;
            state->middle_first_cursor = ++first;
          }
        }
        if (state->stage == ISOBMFF_STAGE_FINISHED) {
          break;
        }
        state->middle_actual_cursor = actual + 1;
        state->middle_first_cursor = 0;
        state->middle_second_cursor = 0;
        if (isobmff_reassembly_poll(
                work, candidate, state, uuidp, uuidc, &iterations)) {
          free(trial);
          isobmff_footer_context_clear(&context);
          isobmff_free_carve_state((void **)&state);
          return;
        }
      }
      free(trial);
      if (state->stage == ISOBMFF_STAGE_FINISHED) {
        isobmff_footer_context_clear(&context);
        context_ready = false;
        continue;
      }
      if (!isobmff_finish_middle_attempt(&context, state)) {
        isobmff_footer_context_clear(&context);
        context_ready = false;
      }
      continue;
    }

    isobmff_finish_footer(state);
  }

  isobmff_footer_context_clear(&context);
  if (!*candidate) {
    isobmff_free_carve_state((void **)&state);
    return;
  }

  if (getenv("SCALPEL_ISOBMFF_DEBUG")) {
    fprintf(stderr,
            "ISOBMFF start=%" PRIu64 " type=%s footers=%" PRIu64
            " solutions=%" PRIu64 " repairs=%" PRIu64 "\n",
            (*candidate)->start, (*candidate)->filetype,
            state->footer_cursor, state->solution_count, state->repairs);
  }

  if (state->stored_solution_count > 0) {
    uint64_t published_bytes = 0;

    /* Complete codec parses are strong evidence, but compressed payloads do
       not necessarily carry an integrity check over their original bytes.
       Publish a bounded set of full hypotheses and one artifact ending before
       the first block whose placement was inferred. */
    for (uint32_t index = 0; index < state->stored_solution_count; index++) {
      const IsoBmffStoredSolution *saved = &state->solutions[index];
      if (published_bytes > 0
          && (published_bytes >= ISOBMFF_PROMISING_OUTPUT_BUDGET
              || saved->extent
                     > ISOBMFF_PROMISING_OUTPUT_BUDGET - published_bytes)) {
        break;
      }
      if (!isobmff_commit_solution(
              *candidate, saved->prefix_delta, saved->suffix_delta,
              &saved->mapping, saved->extent)) {
        continue;
      }
      uint64_t validates_to = 0;
      if (reassembly_check_validation(
              work->id, *candidate, &validates_to, uuidp, uuidc)) {
        isobmff_free_carve_state((void **)&state);
        write_candidate(candidate, false);
        return;
      }
      if (scalpel_state.write_promising) {
        (*candidate)->flavor = PROMISING;
        write_candidate(candidate, true);
      }
      published_bytes += saved->extent;
    }
    if (!scalpel_state.write_promising) {
      isobmff_free_carve_state((void **)&state);
      destroy_candidate(candidate);
      return;
    }

    const IsoBmffStoredSolution *first = &state->solutions[0];
    (void)isobmff_commit_solution(
        *candidate, first->prefix_delta, first->suffix_delta,
        &first->mapping, first->extent);
    uint64_t current_blocks = blockvector_get_num_blocks((*candidate)->b);
    uint64_t safe_blocks = state->ambiguous_prefix_blocks;
    if (safe_blocks == 0 || safe_blocks == UINT64_MAX
        || safe_blocks > current_blocks) {
      safe_blocks = 1;
    }
    isobmff_free_carve_state((void **)&state);
    if (scalpel_state.blocksize > 0 && safe_blocks < current_blocks) {
      uint64_t safe_length = safe_blocks * scalpel_state.blocksize;
      resize_blockvector((*candidate)->b, safe_blocks);
      blockvector_set_data_length((*candidate)->b, safe_length);
      (*candidate)->chopped = true;
    }
    (*candidate)->flavor = PROMISING;
    write_candidate(candidate, false);
    return;
  }

  isobmff_free_carve_state((void **)&state);
  if (scalpel_state.write_promising) {
    (*candidate)->flavor = PROMISING;
    write_candidate(candidate, false);
  }
  else {
    destroy_candidate(candidate);
  }
}

#endif
