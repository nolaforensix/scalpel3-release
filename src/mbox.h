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

// RFC message and Unix mbox recovery.
//
// Mail messages combine a strongly structured header with bodies whose bytes
// may be opaque after transfer encoding. Multipart boundary closure provides a
// reliable terminal extent for an individual message. Traditional mbox files
// additionally provide envelope separators between messages, but no mandatory
// container footer, so terminal mbox extents without a closed multipart body
// remain promising rather than validated.

#ifndef SCALPEL3_MBOX_H
#define SCALPEL3_MBOX_H

#include "scalpel.h"

#include <ctype.h>
#include <stdint.h>
#include <string.h>

#define MBOX_MINIMUM_SIZE UINT64_C(96)
#define MBOX_MAXIMUM_SIZE UINT64_C(4294967295)
#define MBOX_BOUNDARY_MAX 200U
#define MBOX_MULTIPART_DEPTH_MAX 16U
#define MBOX_CONTENT_TYPE_MAX 1024U
// RFC 2045 recommends 76 characters. Some deployed encoders use 80-character
// lines, so allow modest variance while rejecting implausible physical joins.
#define MBOX_BASE64_LINE_MAX UINT64_C(96)
#define MBOX_BASE64_WRAP_STABILITY 4U
#define MBOX_HEADER_FIELDS_MIN 4U
#define MBOX_RECOGNIZED_FIELDS_MIN 3U
#define MBOX_REASSEMBLY_TRIAL_BLOCKS UINT64_C(256)
#define MBOX_TRIAL_BUFFER_BYTES (UINT64_C(16) * 1024 * 1024)
#define MBOX_REASSEMBLY_ADJACENT_BLOCKS UINT64_C(1024)
#define MBOX_REASSEMBLY_COMMIT_BLOCKS UINT64_C(1024)
#define MBOX_REASSEMBLY_FRONTIER_BLOCKS UINT64_C(2)
#define MBOX_REASSEMBLY_LOCAL_BLOCKS UINT64_C(8192)
#define MBOX_REASSEMBLY_SEARCH_BAND UINT64_C(256)
#define MBOX_PRETERMINAL_LOCAL_BLOCKS UINT64_C(256)
#define MBOX_TERMINAL_BACKTRACK_BLOCKS UINT64_C(512)
#define MBOX_STATE_MAGIC UINT64_C(0x4d424f5853434133)

typedef enum MboxParseResult {
  MBOX_PARSE_INVALID = 0,
  MBOX_PARSE_PARTIAL,
  MBOX_PARSE_COMPLETE
} MboxParseResult;

typedef enum MboxTransferEncoding {
  MBOX_TRANSFER_UNSPECIFIED = 0,
  MBOX_TRANSFER_7BIT,
  MBOX_TRANSFER_8BIT,
  MBOX_TRANSFER_BINARY,
  MBOX_TRANSFER_BASE64,
  MBOX_TRANSFER_QUOTED_PRINTABLE,
  MBOX_TRANSFER_UNKNOWN
} MboxTransferEncoding;

typedef enum MboxHeaderKind {
  MBOX_HEADER_OTHER = 0,
  MBOX_HEADER_RECOGNIZED,
  MBOX_HEADER_ADDRESS,
  MBOX_HEADER_ROUTING_OR_DATE,
  MBOX_HEADER_SUBJECT,
  MBOX_HEADER_CONTENT_TYPE,
  MBOX_HEADER_TRANSFER_ENCODING
} MboxHeaderKind;

typedef struct MboxLine {
  uint64_t start;
  uint64_t content_end;
  uint64_t end;
  bool terminated;
} MboxLine;

typedef struct MboxMessageHeader {
  uint64_t body_offset;
  uint32_t fields;
  uint32_t recognized_fields;
  bool envelope;
  bool has_address;
  bool has_routing_or_date;
  bool has_subject_or_content;
  bool multipart;
  bool utf8_text;
  MboxTransferEncoding transfer_encoding;
  char boundary[MBOX_BOUNDARY_MAX + 1];
} MboxMessageHeader;

typedef struct MboxPartHeader {
  uint64_t body_offset;
  uint32_t fields;
  bool multipart;
  bool utf8_text;
  MboxTransferEncoding transfer_encoding;
  char boundary[MBOX_BOUNDARY_MAX + 1];
} MboxPartHeader;

typedef struct MboxParseSummary {
  uint64_t parsed_extent;
  uint64_t complete_extent;
  uint64_t failure_offset;
  uint32_t messages;
  uint32_t multipart_messages;
  uint32_t closed_multipart_messages;
  uint32_t mime_parts;
  uint64_t encoded_lines;
  uint32_t base64_wrap_transitions;
  bool envelope_stream;
  bool terminal_observed;
} MboxParseSummary;

// A body-line boundary whose preceding decisions use only the fixed prefix.
// This is temporary parser state, not part of the serialized search cursor.
typedef struct MboxParseCursor {
  MboxParseSummary summary;
  MboxMessageHeader header;
  uint64_t message_offset;
  uint64_t cursor;
  uint64_t message_extent;
  uint64_t terminal_extent;
  MboxTransferEncoding transfer_encoding;
  char epilogue_boundary[MBOX_BOUNDARY_MAX + 1];
  char multipart_boundaries[MBOX_MULTIPART_DEPTH_MAX][MBOX_BOUNDARY_MAX + 1];
  uint32_t multipart_depth;
  uint64_t base64_line_width;
  uint64_t base64_wrap_mismatch_offset;
  uint64_t base64_transition_width;
  uint32_t base64_line_width_run;
  uint32_t base64_transition_run;
  bool saw_boundary;
  bool closed_boundary;
  bool utf8_text;
  bool base64_wrap_mismatch;
  bool valid;
} MboxParseCursor;

// Disposable bytes for trials sharing one unchanged prefix, never serialized.
typedef struct MboxTrialBuffer {
  const BlockVector *owner;
  uint8_t *data;
  uint64_t blocks;
  uint64_t capacity;
} MboxTrialBuffer;

typedef enum MboxRunSearchResult {
  MBOX_RUN_SEARCH_NONE = 0,
  MBOX_RUN_SEARCH_READY,
  MBOX_RUN_SEARCH_STOPPED
} MboxRunSearchResult;

typedef enum MboxTerminalContext {
  MBOX_TERMINAL_PREFIX = 0,
  MBOX_TERMINAL_ADJACENT,
  MBOX_TERMINAL_PRELIMINARY,
  MBOX_TERMINAL_CONTEXTS
} MboxTerminalContext;

// The three terminal searches use different temporary prefixes. Keep their
// cursors and best trials separately so revisiting one does not erase another.
typedef struct MboxTerminalSearch {
  XXH128_hash_t prefix_hash;
  uint64_t next_actual;
  uint64_t backtrack;
  uint32_t bridge_mode;
  int64_t marker_actual;
  int64_t bridge_actual;
  int64_t best_actual;
  uint64_t best_blocks;
  uint64_t best_extent;
  uint64_t best_bridge_blocks;
  uint32_t best_wrap_transitions;
  bool initialized;
  bool in_marker;
  bool done;
} MboxTerminalSearch;

typedef struct MboxContinuationSearch {
  XXH128_hash_t prefix_hash;
  uint64_t band;
  uint64_t distance;
  uint32_t direction;
  uint64_t next_actual;
  int64_t best_actual;
  uint64_t best_blocks;
  uint64_t best_extent;
  bool best_complete;
  bool initialized;
  bool fallback;
  bool done;
} MboxContinuationSearch;

typedef enum MboxLocalContext {
  MBOX_LOCAL_PREFIX = 0,
  MBOX_LOCAL_ADJACENT,
  MBOX_LOCAL_CONTEXTS
} MboxLocalContext;

typedef struct MboxLocalSearch {
  XXH128_hash_t prefix_hash;
  uint64_t distance;
  uint32_t direction;
  int64_t excluded_actual;
  uint64_t excluded_blocks;
  int64_t best_actual;
  uint64_t best_blocks;
  uint64_t best_extent;
  bool best_complete;
  bool initialized;
  bool done;
} MboxLocalSearch;

typedef struct MboxBridgeSearch {
  XXH128_hash_t prefix_hash;
  int64_t continuation_actual;
  uint64_t continuation_blocks;
  uint64_t next_blocks;
  uint64_t best_bridge_blocks;
  uint64_t best_accepted;
  bool initialized;
  bool done;
} MboxBridgeSearch;

typedef struct MboxCarveState {
  uint64_t magic;
  XXH128_hash_t view_hash;
  bool alternate_hypothesis_written;
  MboxTerminalSearch terminal[MBOX_TERMINAL_CONTEXTS];
  MboxContinuationSearch continuation;
  MboxLocalSearch local[MBOX_LOCAL_CONTEXTS];
  MboxBridgeSearch bridge;
} MboxCarveState;

static inline bool mbox_ascii_case_equal(const uint8_t *data,
                                         uint64_t length,
                                         const char *literal);
static inline bool mbox_ascii_contains_case(const char *text,
                                            const char *needle);
static inline bool mbox_line_at(const uint8_t *data, uint64_t length,
                                uint64_t offset, MboxLine *line);
static inline bool mbox_line_is_blank(const uint8_t *data,
                                      const MboxLine *line);
static inline bool mbox_line_starts_with(const uint8_t *data,
                                         const MboxLine *line,
                                         const char *literal);
static inline bool mbox_header_name(const uint8_t *data,
                                    const MboxLine *line,
                                    uint64_t *name_length);
static inline MboxHeaderKind mbox_header_kind(const uint8_t *data,
                                              uint64_t name_length);
static inline bool mbox_header_is(const uint8_t *data,
                                  uint64_t name_length,
                                  const char *name);
static inline void mbox_append_unfolded(char *destination,
                                        uint64_t destination_size,
                                        const uint8_t *data,
                                        const MboxLine *line,
                                        uint64_t value_offset);
static inline bool mbox_extract_boundary(const char *content_type,
                                         char *boundary,
                                         uint64_t boundary_size);
static inline bool mbox_content_type_is_utf8_text(
    const char *content_type);
static inline MboxTransferEncoding mbox_transfer_encoding(
    const char *value);
static inline bool mbox_parse_message_header(const uint8_t *data,
                                             uint64_t length,
                                             uint64_t offset,
                                             MboxMessageHeader *header);
static inline bool mbox_message_header_prefix(const uint8_t *data,
                                              uint64_t length,
                                              uint64_t offset);
static inline bool mbox_parse_part_header(const uint8_t *data,
                                          uint64_t length,
                                          uint64_t offset,
                                          MboxPartHeader *header);
static inline bool mbox_boundary_line(const uint8_t *data,
                                      const MboxLine *line,
                                      const char *boundary,
                                      bool *closing);
static inline bool mbox_generic_boundary_line(const uint8_t *data,
                                              const MboxLine *line,
                                              char *boundary,
                                              uint64_t boundary_size,
                                              bool *closing);
static inline bool mbox_line_bytes_valid(const uint8_t *data,
                                         const MboxLine *line);
static inline bool mbox_8bit_line_valid(const uint8_t *data,
                                        const MboxLine *line);
static inline bool mbox_utf8_line_valid(const uint8_t *data,
                                        const MboxLine *line);
static inline bool mbox_transfer_line_valid(
    const uint8_t *data, const MboxLine *line,
    MboxTransferEncoding encoding, uint64_t *encoded_symbols);
static inline uint64_t mbox_consume_blank_lines(const uint8_t *data,
                                                uint64_t length,
                                                uint64_t offset);
static inline MboxParseResult mbox_parse(const uint8_t *data,
                                         uint64_t length,
                                         MboxParseSummary *summary);
static inline __attribute__((always_inline)) MboxParseResult
mbox_parse_resumable(
    const uint8_t *data, uint64_t length, MboxParseSummary *summary,
    const MboxParseCursor *resume, MboxParseCursor *save);
static inline void mbox_prepare_trial_prefix(
    CarveInfo *candidate, MboxParseCursor *prefix);
static inline void mbox_trial_buffer_init(
    MboxTrialBuffer *trial, const CarveInfo *candidate,
    uint64_t maximum_blocks);
static inline bool mbox_trial_buffer_append(
    MboxTrialBuffer *trial, const CarveInfo *candidate,
    int64_t first_actual, uint64_t run_blocks);
static inline uint64_t mbox_trial_run_buffered(
    CarveInfo *candidate, int64_t first_actual, uint64_t maximum_blocks,
    bool *complete, uint64_t *accepted_extent,
    uint32_t *base64_wrap_transitions, const MboxParseCursor *prefix,
    MboxTrialBuffer *trial);
static inline uint64_t mbox_trial_run_scored(
    CarveInfo *candidate, int64_t first_actual, uint64_t maximum_blocks,
    bool *complete, uint64_t *accepted_extent,
    uint32_t *base64_wrap_transitions, const MboxParseCursor *prefix);
static inline char *mbox_header_discovery(char *base, uint64_t offset,
                                          uint64_t remaining,
                                          char **matchpos,
                                          uint32_t *matchlen,
                                          uint32_t blocksize);
static inline char *mbox_footer_discovery(char *base, uint64_t offset,
                                          uint64_t remaining,
                                          char **matchpos,
                                          uint32_t *matchlen,
                                          uint32_t blocksize);
static inline uint32_t mbox_block_validate(
    char *data, uint64_t length, BlockValidationDecision *decision,
    uint64_t *validates_to, uint32_t needleidx, uint32_t blocksize,
    void *blockhashkey);
static inline void mbox_file_validate(char *data, uint64_t length,
                                      bool *validates,
                                      uint64_t *validates_to,
                                      bool *promising,
                                      uint32_t needleidx,
                                      uint32_t blocksize,
                                      void *carvehashkey);
static inline void mbox_candidate_validate(CarveInfo *candidate,
                                           bool *validates,
                                           uint64_t *validates_to,
                                           bool *promising);
static inline bool mbox_checkpoint_probe(ThreadWork *work,
                                          CarveInfo *candidate,
                                          uint64_t checkpoint_blocks,
                                          uint64_t checkpoint_length,
                                          uuid_string_t uuidp,
                                          uuid_string_t uuidc);
static inline MboxRunSearchResult mbox_find_terminal_run(
    ThreadWork *work, CarveInfo **candidate,
    MboxCarveState *search, MboxTerminalContext context,
    uint64_t checkpoint_blocks, uint64_t checkpoint_length,
    int64_t *selected_bridge_actual, uint64_t *selected_bridge_blocks,
    int64_t *selected_actual, uint64_t *selected_blocks,
    uint64_t *selected_extent, uint32_t *selected_wrap_transitions,
    uuid_string_t uuidp, uuid_string_t uuidc);
static inline bool mbox_write_extent_hypothesis(CarveInfo *candidate,
                                                uint64_t extent);
static inline int64_t mbox_apparent_at_or_after(uint64_t next_actual);
static inline MboxRunSearchResult mbox_find_continuation_run(
    ThreadWork *work, CarveInfo **candidate, MboxCarveState *search,
    uuid_string_t uuidp, uuid_string_t uuidc);
static inline MboxRunSearchResult mbox_find_local_run(
    ThreadWork *work, CarveInfo **candidate, MboxCarveState *search,
    MboxLocalContext context, uint64_t checkpoint_blocks,
    uint64_t checkpoint_length, int64_t excluded_actual,
    uint64_t excluded_blocks, uint64_t adjacent_blocks,
    uuid_string_t uuidp, uuid_string_t uuidc);
static inline void mbox_reassembly(ThreadWork *work,
                                   CarveInfo **candidate,
                                   uuid_string_t uuidp,
                                   uuid_string_t uuidc);
static inline XXH128_hash_t mbox_search_view_hash(
    CarveInfo *candidate, uint64_t blocks, uint64_t length, bool coverage);
static inline bool mbox_checkpoint_search(
    ThreadWork *work, CarveInfo *candidate, MboxCarveState *search,
    uint64_t blocks, uint64_t length,
    uuid_string_t uuidp, uuid_string_t uuidc);
static inline bool mbox_serialize_carve_state(void **state, FILE *fp,
                                              StateSerialization mode);
static inline void *mbox_clone_carve_state(const void *state);
static inline void mbox_free_carve_state(void **state);
static inline size_t mbox_sizeof_carve_state(const void *state);
static inline void mbox_print_carve_state(const void *state);

static inline bool mbox_ascii_case_equal(const uint8_t *data,
                                         uint64_t length,
                                         const char *literal) {
  if (!data || !literal || strlen(literal) != length) {
    return false;
  }
  for (uint64_t i = 0; i < length; i++) {
    if (tolower((unsigned char)data[i])
        != tolower((unsigned char)literal[i])) {
      return false;
    }
  }
  return true;
}

static inline bool mbox_ascii_contains_case(const char *text,
                                            const char *needle) {
  if (!text || !needle || !*needle) {
    return false;
  }
  uint64_t text_length = strlen(text);
  uint64_t needle_length = strlen(needle);

  if (needle_length > text_length) {
    return false;
  }
  for (uint64_t i = 0; i + needle_length <= text_length; i++) {
    if (strncasecmp(text + i, needle, needle_length) == 0) {
      return true;
    }
  }
  return false;
}

static inline bool mbox_line_at(const uint8_t *data, uint64_t length,
                                uint64_t offset, MboxLine *line) {
  if (!data || !line || offset >= length) {
    return false;
  }
  uint64_t cursor = offset;

  // Skip eight nonterminating bytes at a time. memcpy permits unaligned input;
  // finish bytewise when either CR or LF is present, independent of byte order.
  while (length - cursor >= sizeof(uint64_t)) {
    uint64_t word;
    memcpy(&word, data + cursor, sizeof(word));
    uint64_t cr = word ^ UINT64_C(0x0d0d0d0d0d0d0d0d);
    uint64_t lf = word ^ UINT64_C(0x0a0a0a0a0a0a0a0a);
    const uint64_t low = UINT64_C(0x0101010101010101);
    const uint64_t high = UINT64_C(0x8080808080808080);
    if ((((cr - low) & ~cr) | ((lf - low) & ~lf)) & high) {
      break;
    }
    cursor += sizeof(word);
  }
  while (cursor < length && data[cursor] != '\n' && data[cursor] != '\r') {
    cursor++;
  }
  line->start = offset;
  line->content_end = cursor;
  line->terminated = cursor < length;
  if (cursor < length && data[cursor] == '\r') {
    cursor++;
    if (cursor < length && data[cursor] == '\n') {
      cursor++;
    }
  }
  else if (cursor < length) {
    cursor++;
  }
  line->end = cursor;
  return true;
}

static inline bool mbox_line_is_blank(const uint8_t *data,
                                      const MboxLine *line) {
  if (!data || !line) {
    return false;
  }
  for (uint64_t i = line->start; i < line->content_end; i++) {
    if (data[i] != ' ' && data[i] != '\t') {
      return false;
    }
  }
  return true;
}

static inline bool mbox_line_starts_with(const uint8_t *data,
                                         const MboxLine *line,
                                         const char *literal) {
  if (!data || !line || !literal) {
    return false;
  }
  uint64_t literal_length = strlen(literal);

  return line->content_end - line->start >= literal_length
      && memcmp(data + line->start, literal, literal_length) == 0;
}

static inline bool mbox_header_name(const uint8_t *data,
                                    const MboxLine *line,
                                    uint64_t *name_length) {
  if (!data || !line || !name_length || line->start >= line->content_end
      || data[line->start] == ' ' || data[line->start] == '\t') {
    return false;
  }
  uint64_t cursor = line->start;

  while (cursor < line->content_end && data[cursor] != ':') {
    uint8_t value = data[cursor];
    if (value < 0x21 || value > 0x7e) {
      return false;
    }
    cursor++;
  }
  if (cursor == line->start || cursor >= line->content_end
      || cursor - line->start > 78) {
    return false;
  }
  *name_length = cursor - line->start;
  return true;
}

static inline bool mbox_header_is(const uint8_t *data,
                                  uint64_t name_length,
                                  const char *name) {
  return mbox_ascii_case_equal(data, name_length, name);
}

// Classify a header once; trial parsing revisits these names frequently.
// Length dispatch avoids comparing unrelated names without changing case rules.
static inline MboxHeaderKind mbox_header_kind(const uint8_t *data,
                                              uint64_t name_length) {
  switch (name_length) {
    case 2:
      if (mbox_header_is(data, name_length, "to")
          || mbox_header_is(data, name_length, "cc")) {
        return MBOX_HEADER_RECOGNIZED;
      }
      break;
    case 3:
      if (mbox_header_is(data, name_length, "bcc")) {
        return MBOX_HEADER_RECOGNIZED;
      }
      break;
    case 4:
      if (mbox_header_is(data, name_length, "from")) {
        return MBOX_HEADER_ADDRESS;
      }
      if (mbox_header_is(data, name_length, "date")) {
        return MBOX_HEADER_ROUTING_OR_DATE;
      }
      break;
    case 6:
      if (mbox_header_is(data, name_length, "sender")) {
        return MBOX_HEADER_ADDRESS;
      }
      if (mbox_header_is(data, name_length, "status")) {
        return MBOX_HEADER_RECOGNIZED;
      }
      break;
    case 7:
      if (mbox_header_is(data, name_length, "subject")) {
        return MBOX_HEADER_SUBJECT;
      }
      break;
    case 8:
      if (mbox_header_is(data, name_length, "received")) {
        return MBOX_HEADER_ROUTING_OR_DATE;
      }
      if (mbox_header_is(data, name_length, "reply-to")
          || mbox_header_is(data, name_length, "x-mailer")) {
        return MBOX_HEADER_RECOGNIZED;
      }
      break;
    case 10:
      if (mbox_header_is(data, name_length, "message-id")
          || mbox_header_is(data, name_length, "references")) {
        return MBOX_HEADER_RECOGNIZED;
      }
      break;
    case 11:
      if (mbox_header_is(data, name_length, "return-path")) {
        return MBOX_HEADER_ADDRESS;
      }
      if (mbox_header_is(data, name_length, "in-reply-to")) {
        return MBOX_HEADER_RECOGNIZED;
      }
      break;
    case 12:
      if (mbox_header_is(data, name_length, "content-type")) {
        return MBOX_HEADER_CONTENT_TYPE;
      }
      if (mbox_header_is(data, name_length, "delivered-to")
          || mbox_header_is(data, name_length, "mime-version")) {
        return MBOX_HEADER_RECOGNIZED;
      }
      break;
    case 25:
      if (mbox_header_is(data, name_length, "content-transfer-encoding")) {
        return MBOX_HEADER_TRANSFER_ENCODING;
      }
      break;
    default:
      break;
  }
  return MBOX_HEADER_OTHER;
}

static inline void mbox_append_unfolded(char *destination,
                                        uint64_t destination_size,
                                        const uint8_t *data,
                                        const MboxLine *line,
                                        uint64_t value_offset) {
  if (!destination || destination_size == 0 || !data || !line
      || value_offset > line->content_end) {
    return;
  }
  uint64_t used = strlen(destination);
  if (used != 0 && used + 1 < destination_size) {
    destination[used++] = ' ';
    destination[used] = 0;
  }
  while (value_offset < line->content_end
         && (data[value_offset] == ' ' || data[value_offset] == '\t')) {
    value_offset++;
  }
  while (value_offset < line->content_end && used + 1 < destination_size) {
    uint8_t value = data[value_offset++];
    if (value < 0x20 || value == 0x7f) {
      continue;
    }
    destination[used++] = (char)value;
  }
  destination[used] = 0;
}

static inline bool mbox_extract_boundary(const char *content_type,
                                         char *boundary,
                                         uint64_t boundary_size) {
  if (!content_type || !boundary || boundary_size < 2) {
    return false;
  }
  boundary[0] = 0;
  uint64_t length = strlen(content_type);

  for (uint64_t i = 0; i + 8 <= length; i++) {
    if (strncasecmp(content_type + i, "boundary", 8) != 0) {
      continue;
    }
    uint64_t cursor = i + 8;
    while (cursor < length && isspace((unsigned char)content_type[cursor])) {
      cursor++;
    }
    if (cursor >= length || content_type[cursor] != '=') {
      continue;
    }
    cursor++;
    while (cursor < length && isspace((unsigned char)content_type[cursor])) {
      cursor++;
    }
    bool quoted = cursor < length && content_type[cursor] == '"';
    if (quoted) {
      cursor++;
    }
    uint64_t output = 0;
    while (cursor < length && output + 1 < boundary_size) {
      unsigned char value = (unsigned char)content_type[cursor];
      if ((quoted && value == '"')
          || (!quoted && (isspace(value) || value == ';'))) {
        break;
      }
      if (value < 0x21 || value > 0x7e) {
        return false;
      }
      boundary[output++] = (char)value;
      cursor++;
    }
    boundary[output] = 0;
    return output != 0;
  }
  return false;
}

static inline bool mbox_content_type_is_utf8_text(
    const char *content_type) {
  if (!content_type) {
    return false;
  }
  while (*content_type && isspace((unsigned char)*content_type)) {
    content_type++;
  }
  if (strncasecmp(content_type, "text/", 5) != 0) {
    return false;
  }
  uint64_t length = strlen(content_type);

  for (uint64_t i = 5; i + 7 <= length; i++) {
    if (strncasecmp(content_type + i, "charset", 7) != 0) {
      continue;
    }
    uint64_t cursor = i + 7;
    while (cursor < length
           && isspace((unsigned char)content_type[cursor])) {
      cursor++;
    }
    if (cursor >= length || content_type[cursor] != '=') {
      continue;
    }
    cursor++;
    while (cursor < length
           && isspace((unsigned char)content_type[cursor])) {
      cursor++;
    }
    bool quoted = cursor < length && content_type[cursor] == '"';
    if (quoted) {
      cursor++;
    }
    uint64_t start = cursor;
    while (cursor < length) {
      unsigned char value = (unsigned char)content_type[cursor];
      if ((quoted && value == '"')
          || (!quoted && (isspace(value) || value == ';'))) {
        break;
      }
      cursor++;
    }
    uint64_t value_length = cursor - start;
    return (value_length == 5
            && strncasecmp(content_type + start, "utf-8", 5) == 0)
           || (value_length == 4
               && strncasecmp(content_type + start, "utf8", 4) == 0);
  }
  return false;
}

static inline MboxTransferEncoding mbox_transfer_encoding(
    const char *value) {
  if (!value || !*value) {
    return MBOX_TRANSFER_UNSPECIFIED;
  }
  while (*value && isspace((unsigned char)*value)) {
    value++;
  }
  if (strncasecmp(value, "base64", 6) == 0) {
    return MBOX_TRANSFER_BASE64;
  }
  if (strncasecmp(value, "quoted-printable", 16) == 0) {
    return MBOX_TRANSFER_QUOTED_PRINTABLE;
  }
  if (strncasecmp(value, "7bit", 4) == 0) {
    return MBOX_TRANSFER_7BIT;
  }
  if (strncasecmp(value, "8bit", 4) == 0) {
    return MBOX_TRANSFER_8BIT;
  }
  if (strncasecmp(value, "binary", 6) == 0) {
    return MBOX_TRANSFER_BINARY;
  }
  return MBOX_TRANSFER_UNKNOWN;
}

static inline bool mbox_parse_message_header(const uint8_t *data,
                                             uint64_t length,
                                             uint64_t offset,
                                             MboxMessageHeader *header) {
  if (!data || !header || offset >= length) {
    return false;
  }
  memset(header, 0, sizeof(*header));
  MboxLine line;

  if (!mbox_line_at(data, length, offset, &line)) {
    return false;
  }
  if (mbox_line_starts_with(data, &line, "From ")) {
    if (!line.terminated || line.content_end - line.start < 12) {
      return false;
    }
    header->envelope = true;
    offset = line.end;
  }

  char content_type[MBOX_CONTENT_TYPE_MAX] = {0};
  char transfer_encoding[64] = {0};
  bool collecting_content_type = false;
  bool collecting_transfer_encoding = false;
  bool saw_blank = false;

  while (offset < length) {
    if (!mbox_line_at(data, length, offset, &line)) {
      break;
    }
    if (!mbox_line_bytes_valid(data, &line)) {
      return false;
    }
    if (mbox_line_is_blank(data, &line)) {
      header->body_offset = line.end;
      saw_blank = true;
      break;
    }
    if (data[line.start] == ' ' || data[line.start] == '\t') {
      if (header->fields == 0) {
        return false;
      }
      if (collecting_content_type) {
        mbox_append_unfolded(content_type, sizeof(content_type), data,
                             &line, line.start);
      }
      else if (collecting_transfer_encoding) {
        mbox_append_unfolded(transfer_encoding,
                             sizeof(transfer_encoding), data,
                             &line, line.start);
      }
      offset = line.end;
      continue;
    }

    uint64_t name_length = 0;
    if (!mbox_header_name(data, &line, &name_length)) {
      return false;
    }
    header->fields++;
    MboxHeaderKind kind = mbox_header_kind(data + line.start, name_length);
    if (kind != MBOX_HEADER_OTHER) {
      header->recognized_fields++;
    }
    if (kind == MBOX_HEADER_ADDRESS) {
      header->has_address = true;
    }
    if (kind == MBOX_HEADER_ROUTING_OR_DATE) {
      header->has_routing_or_date = true;
    }
    if (kind == MBOX_HEADER_SUBJECT || kind == MBOX_HEADER_CONTENT_TYPE) {
      header->has_subject_or_content = true;
    }
    collecting_content_type = kind == MBOX_HEADER_CONTENT_TYPE;
    collecting_transfer_encoding = kind == MBOX_HEADER_TRANSFER_ENCODING;
    if (collecting_content_type) {
      mbox_append_unfolded(content_type, sizeof(content_type), data, &line,
                           line.start + name_length + 1);
    }
    else if (collecting_transfer_encoding) {
      mbox_append_unfolded(transfer_encoding,
                           sizeof(transfer_encoding), data, &line,
                           line.start + name_length + 1);
    }
    offset = line.end;
  }

  if (!saw_blank || header->fields < MBOX_HEADER_FIELDS_MIN
      || header->recognized_fields < MBOX_RECOGNIZED_FIELDS_MIN
      || !header->has_address || !header->has_routing_or_date
      || (!header->envelope && !header->has_subject_or_content)) {
    return false;
  }
  header->multipart = mbox_ascii_contains_case(content_type, "multipart/");
  header->utf8_text = mbox_content_type_is_utf8_text(content_type);
  header->transfer_encoding = mbox_transfer_encoding(transfer_encoding);
  if (header->multipart
      && !mbox_extract_boundary(content_type, header->boundary,
                                sizeof(header->boundary))) {
    return false;
  }
  return true;
}

static inline bool mbox_message_header_prefix(const uint8_t *data,
                                              uint64_t length,
                                              uint64_t offset) {
  if (!data || offset >= length) {
    return false;
  }

  MboxLine line;

  if (!mbox_line_at(data, length, offset, &line)) {
    return false;
  }
  if (mbox_line_starts_with(data, &line, "From ")) {
    if (!line.terminated || line.content_end - line.start < 12) {
      return false;
    }
    offset = line.end;
  }
  else if (!mbox_line_starts_with(data, &line, "Return-Path:")) {
    return false;
  }

  uint32_t fields = 0;
  uint32_t recognized = 0;
  bool has_address = false;
  bool has_routing_or_date = false;

  while (offset < length && mbox_line_at(data, length, offset, &line)) {
    if (!mbox_line_bytes_valid(data, &line)) {
      break;
    }
    if (mbox_line_is_blank(data, &line)) {
      break;
    }
    if (data[line.start] == ' ' || data[line.start] == '\t') {
      if (fields == 0) {
        return false;
      }
      offset = line.end;
      continue;
    }

    uint64_t name_length = 0;

    if (!mbox_header_name(data, &line, &name_length)) {
      break;
    }
    fields++;
    MboxHeaderKind kind = mbox_header_kind(data + line.start, name_length);
    if (kind != MBOX_HEADER_OTHER) {
      recognized++;
    }
    if (kind == MBOX_HEADER_ADDRESS) {
      has_address = true;
    }
    if (kind == MBOX_HEADER_ROUTING_OR_DATE) {
      has_routing_or_date = true;
    }
    offset = line.end;
  }

  // Three recognized routing fields are sufficient to reject an embedded
  // truncated message header even when the next physical block is absent.
  return fields >= MBOX_RECOGNIZED_FIELDS_MIN
         && recognized >= MBOX_RECOGNIZED_FIELDS_MIN
         && has_address && has_routing_or_date;
}

static inline bool mbox_parse_part_header(const uint8_t *data,
                                          uint64_t length,
                                          uint64_t offset,
                                          MboxPartHeader *header) {
  if (!data || !header || offset >= length) {
    return false;
  }
  memset(header, 0, sizeof(*header));
  char content_type[MBOX_CONTENT_TYPE_MAX] = {0};
  char transfer_encoding[64] = {0};
  bool collecting_content_type = false;
  bool collecting_transfer_encoding = false;
  MboxLine line;

  while (offset < length && mbox_line_at(data, length, offset, &line)) {
    if (!mbox_line_bytes_valid(data, &line)) {
      return false;
    }
    if (mbox_line_is_blank(data, &line)) {
      header->body_offset = line.end;
      header->multipart = mbox_ascii_contains_case(content_type,
                                                    "multipart/");
      header->utf8_text = mbox_content_type_is_utf8_text(content_type);
      header->transfer_encoding = mbox_transfer_encoding(
          transfer_encoding);
      if (header->multipart
          && !mbox_extract_boundary(content_type, header->boundary,
                                    sizeof(header->boundary))) {
        return false;
      }
      return header->fields != 0;
    }
    if (data[line.start] == ' ' || data[line.start] == '\t') {
      if (header->fields == 0) {
        return false;
      }
      if (collecting_content_type) {
        mbox_append_unfolded(content_type, sizeof(content_type), data,
                             &line, line.start);
      }
      else if (collecting_transfer_encoding) {
        mbox_append_unfolded(transfer_encoding,
                             sizeof(transfer_encoding), data,
                             &line, line.start);
      }
      offset = line.end;
      continue;
    }

    uint64_t name_length = 0;
    if (!mbox_header_name(data, &line, &name_length)) {
      return false;
    }
    header->fields++;
    collecting_content_type = mbox_header_is(
        data + line.start, name_length, "content-type");
    collecting_transfer_encoding = mbox_header_is(
        data + line.start, name_length, "content-transfer-encoding");
    if (collecting_content_type) {
      mbox_append_unfolded(content_type, sizeof(content_type), data,
                           &line, line.start + name_length + 1);
    }
    else if (collecting_transfer_encoding) {
      mbox_append_unfolded(transfer_encoding,
                           sizeof(transfer_encoding), data, &line,
                           line.start + name_length + 1);
    }
    offset = line.end;
  }
  return false;
}

static inline bool mbox_boundary_line(const uint8_t *data,
                                      const MboxLine *line,
                                      const char *boundary,
                                      bool *closing) {
  if (!data || !line || !boundary || !closing) {
    return false;
  }
  uint64_t boundary_length = strlen(boundary);
  uint64_t line_length = line->content_end - line->start;

  if (boundary_length == 0 || line_length < boundary_length + 2
      || data[line->start] != '-' || data[line->start + 1] != '-'
      || memcmp(data + line->start + 2, boundary, boundary_length) != 0) {
    return false;
  }
  uint64_t cursor = line->start + 2 + boundary_length;
  *closing = false;
  if (cursor + 2 <= line->content_end
      && data[cursor] == '-' && data[cursor + 1] == '-') {
    *closing = true;
    cursor += 2;
  }
  while (cursor < line->content_end
         && (data[cursor] == ' ' || data[cursor] == '\t')) {
    cursor++;
  }
  return cursor == line->content_end;
}

static inline bool mbox_generic_boundary_line(const uint8_t *data,
                                              const MboxLine *line,
                                              char *boundary,
                                              uint64_t boundary_size,
                                              bool *closing) {
  if (!data || !line || !boundary || boundary_size < 2 || !closing
      || line->content_end - line->start < 3
      || data[line->start] != '-' || data[line->start + 1] != '-') {
    return false;
  }
  uint64_t cursor = line->start + 2;
  uint64_t output = 0;

  while (cursor < line->content_end && output + 1 < boundary_size) {
    uint8_t value = data[cursor];

    if (value == ' ' || value == '\t') {
      break;
    }
    if (value < 0x21 || value > 0x7e) {
      return false;
    }
    boundary[output++] = (char)value;
    cursor++;
  }
  while (cursor < line->content_end
         && (data[cursor] == ' ' || data[cursor] == '\t')) {
    cursor++;
  }
  if (cursor != line->content_end || output == 0) {
    return false;
  }
  *closing = output >= 2 && boundary[output - 2] == '-'
             && boundary[output - 1] == '-';
  if (*closing) {
    output -= 2;
  }
  if (output == 0) {
    return false;
  }
  boundary[output] = 0;
  return true;
}

static inline bool mbox_line_bytes_valid(const uint8_t *data,
                                         const MboxLine *line) {
  if (!data || !line) {
    return false;
  }
  for (uint64_t i = line->start; i < line->content_end; i++) {
    uint8_t value = data[i];
    if (value == 0
        || (value < 0x20 && value != '\t' && value != 0x1b)
        || value == 0x7f) {
      return false;
    }
  }
  return true;
}

static inline bool mbox_8bit_line_valid(const uint8_t *data,
                                        const MboxLine *line) {
  if (!data || !line) {
    return false;
  }
  for (uint64_t i = line->start; i < line->content_end; i++) {
    if (data[i] == 0) {
      return false;
    }
  }
  return true;
}

static inline bool mbox_utf8_line_valid(const uint8_t *data,
                                        const MboxLine *line) {
  if (!data || !line) {
    return false;
  }
  uint64_t cursor = line->start;
  uint32_t control_bytes = 0;

  while (cursor < line->content_end) {
    uint8_t first = data[cursor++];
    if (first < 0x80) {
      if (first == 0 || first == 0x7f) {
        return false;
      }
      if (first < 0x20 && first != '\t' && first != 0x1b
          && ++control_bytes > 1) {
        return false;
      }
      continue;
    }

    uint32_t continuation = 0;
    uint8_t second_minimum = 0x80;
    uint8_t second_maximum = 0xbf;

    if (first >= 0xc2 && first <= 0xdf) {
      continuation = 1;
    }
    else if (first >= 0xe0 && first <= 0xef) {
      continuation = 2;
      if (first == 0xe0) {
        second_minimum = 0xa0;
      }
      else if (first == 0xed) {
        second_maximum = 0x9f;
      }
    }
    else if (first >= 0xf0 && first <= 0xf4) {
      continuation = 3;
      if (first == 0xf0) {
        second_minimum = 0x90;
      }
      else if (first == 0xf4) {
        second_maximum = 0x8f;
      }
    }
    else {
      return false;
    }

    if (line->content_end - cursor < continuation) {
      return !line->terminated;
    }
    uint8_t second = data[cursor++];
    if (second < second_minimum || second > second_maximum) {
      return false;
    }
    for (uint32_t i = 1; i < continuation; i++) {
      uint8_t value = data[cursor++];
      if (value < 0x80 || value > 0xbf) {
        return false;
      }
    }
  }
  return true;
}

static inline bool mbox_transfer_line_valid(
    const uint8_t *data, const MboxLine *line,
    MboxTransferEncoding encoding, uint64_t *encoded_symbols) {
  if (encoded_symbols) {
    *encoded_symbols = 0;
  }
  if (!data || !line) {
    return false;
  }
  if (encoding == MBOX_TRANSFER_BASE64) {
    uint32_t padding_count = 0;
    uint64_t symbols = 0;

    for (uint64_t i = line->start; i < line->content_end; i++) {
      uint8_t value = data[i];

      if (value == ' ' || value == '\t') {
        continue;
      }
      symbols++;
      if (symbols > MBOX_BASE64_LINE_MAX) {
        return false;
      }
      if (value == '=') {
        padding_count++;
        // Broken senders sometimes concatenate separately padded base64
        // payloads on one MIME line. The alphabet remains useful evidence,
        // but padding is not required to appear only at the line's end.
        if (padding_count > 4) {
          return false;
        }
      }
      else if (!(isalnum((unsigned char)value)
                 || value == '+' || value == '/')) {
        return false;
      }
    }
    if (encoded_symbols) {
      *encoded_symbols = symbols;
    }
    // Base64 is a stream encoding; MIME line breaks are ignorable and do not
    // necessarily align with four-symbol quanta in deployed messages.
    return true;
  }
  if (encoding == MBOX_TRANSFER_QUOTED_PRINTABLE) {
    for (uint64_t i = line->start; i < line->content_end; i++) {
      if (data[i] != '=') {
        continue;
      }
      if (i + 1 == line->content_end) {
        return true;
      }
      if (i + 2 < line->content_end
          && isxdigit((unsigned char)data[i + 1])
          && isxdigit((unsigned char)data[i + 2])) {
        i += 2;
        continue;
      }
      if (i >= line->start + 3 && data[i - 3] == '='
          && isxdigit((unsigned char)data[i - 2])
          && isxdigit((unsigned char)data[i - 1])) {
        return false;
      }
      // Deployed mail generators sometimes leave literal '=' characters in
      // quoted-printable text. MIME structure remains the stronger evidence.
    }
  }
  return true;
}

static inline uint64_t mbox_consume_blank_lines(const uint8_t *data,
                                                uint64_t length,
                                                uint64_t offset) {
  MboxLine line;

  while (offset < length && mbox_line_at(data, length, offset, &line)
         && mbox_line_is_blank(data, &line) && line.terminated) {
    offset = line.end;
  }
  return offset;
}

// resume requires the same prefix bytes used to build it. save records a point
// before any lookahead whose result could change when more bytes are appended.
// Inlining lets callers discard the unused save or resume path.
static inline __attribute__((always_inline)) MboxParseResult
mbox_parse_resumable(
    const uint8_t *data, uint64_t length, MboxParseSummary *summary,
    const MboxParseCursor *resume, MboxParseCursor *save) {
  MboxParseSummary local = {0};

  if (!summary) {
    summary = &local;
  }
  memset(summary, 0, sizeof(*summary));
  if (save) {
    memset(save, 0, sizeof(*save));
  }
  if (!data || length < MBOX_MINIMUM_SIZE) {
    return MBOX_PARSE_INVALID;
  }

  bool resuming = resume && resume->valid && resume->cursor < length;
  uint64_t message_offset = resuming ? resume->message_offset : 0;
  bool first_message = !resuming;
  if (resuming) {
    *summary = resume->summary;
  }

  while (message_offset < length) {
    MboxMessageHeader header;

    if (resuming) {
      header = resume->header;
    }
    else {
      if (!mbox_parse_message_header(data, length, message_offset, &header)) {
        summary->failure_offset = message_offset;
        return summary->messages == 0 ? MBOX_PARSE_INVALID
                                      : MBOX_PARSE_PARTIAL;
      }
      if (first_message) {
        summary->envelope_stream = header.envelope;
        first_message = false;
      }
      else if (!header.envelope) {
        summary->failure_offset = message_offset;
        return MBOX_PARSE_PARTIAL;
      }
      summary->messages++;
      if (header.multipart) {
        summary->multipart_messages++;
      }
    }

    uint64_t cursor = header.body_offset;
    uint64_t message_extent = cursor;
    uint64_t terminal_extent = 0;
    bool saw_boundary = false;
    bool closed_boundary = false;
    bool next_message = false;
    MboxTransferEncoding transfer_encoding = header.transfer_encoding;
    bool utf8_text = header.utf8_text;
    char epilogue_boundary[MBOX_BOUNDARY_MAX + 1] = {0};
    char multipart_boundaries[MBOX_MULTIPART_DEPTH_MAX]
                             [MBOX_BOUNDARY_MAX + 1] = {{0}};
    uint32_t multipart_depth = 0;
    uint64_t base64_line_width = 0;
    uint64_t base64_wrap_mismatch_offset = 0;
    uint64_t base64_transition_width = 0;
    uint32_t base64_line_width_run = 0;
    uint32_t base64_transition_run = 0;
    bool base64_wrap_mismatch = false;

    if (header.multipart) {
      memcpy(multipart_boundaries[0], header.boundary,
             sizeof(multipart_boundaries[0]));
      multipart_depth = 1;
    }

    if (resuming) {
      cursor = resume->cursor;
      message_extent = resume->message_extent;
      terminal_extent = resume->terminal_extent;
      transfer_encoding = resume->transfer_encoding;
      memcpy(epilogue_boundary, resume->epilogue_boundary,
             sizeof(epilogue_boundary));
      memcpy(multipart_boundaries, resume->multipart_boundaries,
             sizeof(multipart_boundaries));
      multipart_depth = resume->multipart_depth;
      base64_line_width = resume->base64_line_width;
      base64_wrap_mismatch_offset = resume->base64_wrap_mismatch_offset;
      base64_transition_width = resume->base64_transition_width;
      base64_line_width_run = resume->base64_line_width_run;
      base64_transition_run = resume->base64_transition_run;
      saw_boundary = resume->saw_boundary;
      closed_boundary = resume->closed_boundary;
      utf8_text = resume->utf8_text;
      base64_wrap_mismatch = resume->base64_wrap_mismatch;
      resuming = false;
    }

    while (cursor < length) {
      if (save) {
        *save = (MboxParseCursor){
            .summary = *summary, .header = header,
            .message_offset = message_offset, .cursor = cursor,
            .message_extent = message_extent, .terminal_extent = terminal_extent,
            .transfer_encoding = transfer_encoding,
            .multipart_depth = multipart_depth,
            .base64_line_width = base64_line_width,
            .base64_wrap_mismatch_offset = base64_wrap_mismatch_offset,
            .base64_transition_width = base64_transition_width,
            .base64_line_width_run = base64_line_width_run,
            .base64_transition_run = base64_transition_run,
            .saw_boundary = saw_boundary, .closed_boundary = closed_boundary,
            .utf8_text = utf8_text, .base64_wrap_mismatch = base64_wrap_mismatch,
            .valid = true};
        memcpy(save->epilogue_boundary, epilogue_boundary,
               sizeof(epilogue_boundary));
        memcpy(save->multipart_boundaries, multipart_boundaries,
               sizeof(multipart_boundaries));
      }
      MboxLine line;

      if (!mbox_line_at(data, length, cursor, &line)) {
        break;
      }
      if (!line.terminated || line.end == length) {
        save = NULL;
      }

      if (summary->envelope_stream
          && mbox_line_starts_with(data, &line, "From ")) {
        MboxMessageHeader next_header;
        bool complete_header = mbox_parse_message_header(
            data, length, line.start, &next_header);
        if (!complete_header) {
          save = NULL;
        }

        if (complete_header
            || mbox_message_header_prefix(data, length, line.start)) {
          if (!complete_header && header.multipart && !closed_boundary) {
            summary->parsed_extent = message_extent;
            summary->failure_offset = line.start;
            return MBOX_PARSE_PARTIAL;
          }
          message_extent = line.start;
          message_offset = line.start;
          next_message = true;
          break;
        }
      }
      else if (!summary->envelope_stream
               && mbox_line_starts_with(data, &line, "Return-Path:")) {
        MboxMessageHeader embedded_header;
        save = NULL;

        if (mbox_parse_message_header(data, length, line.start,
                                      &embedded_header)
            || mbox_message_header_prefix(data, length, line.start)) {
          summary->parsed_extent = message_extent;
          summary->failure_offset = line.start;
          return MBOX_PARSE_PARTIAL;
        }
      }

      uint64_t embedded_header = 0;

      for (uint64_t position = line.start + 1;
           !summary->envelope_stream && position + 12 <= line.content_end;
           position++) {
        // Most body bytes cannot start this ASCII header; avoid case folding
        // the whole literal at each byte of long encoded lines.
        bool possible_header =
            (data[position] == 'R' || data[position] == 'r')
            && mbox_ascii_case_equal(data + position, 12,
                                     "Return-Path:");
        if (possible_header) {
          save = NULL;
        }

        if (possible_header
            && mbox_message_header_prefix(data, length, position)) {
          embedded_header = position;
          break;
        }
      }
      if (embedded_header != 0) {
        summary->parsed_extent = message_extent;
        summary->failure_offset = embedded_header;
        return MBOX_PARSE_PARTIAL;
      }

      bool structural_line = false;

      if (multipart_depth > 0) {
        bool closing = false;
        const char *active_boundary =
            multipart_boundaries[multipart_depth - 1];

        if (mbox_boundary_line(data, &line, active_boundary, &closing)) {
          structural_line = true;
          base64_line_width = 0;
          base64_line_width_run = 0;
          base64_wrap_mismatch = false;
          base64_wrap_mismatch_offset = 0;
          base64_transition_width = 0;
          base64_transition_run = 0;
          if (multipart_depth == 1) {
            saw_boundary = true;
          }
          if (closing) {
            multipart_depth--;
            transfer_encoding = MBOX_TRANSFER_UNSPECIFIED;
            utf8_text = false;
            if (multipart_depth == 0) {
              if (!closed_boundary) {
                summary->closed_multipart_messages++;
              }
              closed_boundary = true;
              terminal_extent = mbox_consume_blank_lines(
                  data, length, line.end);
              MboxLine after;
              if (!mbox_line_at(data, length, terminal_extent, &after)
                  || mbox_line_is_blank(data, &after)) {
                save = NULL;
              }
              summary->terminal_observed = true;
              summary->complete_extent = terminal_extent;
              epilogue_boundary[0] = 0;
            }
          }
          else {
            MboxPartHeader part;

            if (!mbox_parse_part_header(data, length, line.end, &part)) {
              summary->parsed_extent = line.end;
              summary->failure_offset = line.end;
              return MBOX_PARSE_PARTIAL;
            }
            summary->mime_parts++;
            transfer_encoding = part.transfer_encoding;
            utf8_text = part.utf8_text;
            if (part.multipart) {
              if (multipart_depth >= MBOX_MULTIPART_DEPTH_MAX) {
                summary->parsed_extent = line.end;
                summary->failure_offset = line.end;
                return MBOX_PARSE_PARTIAL;
              }
              memcpy(multipart_boundaries[multipart_depth],
                     part.boundary,
                     sizeof(multipart_boundaries[multipart_depth]));
              multipart_depth++;
              transfer_encoding = MBOX_TRANSFER_UNSPECIFIED;
              utf8_text = false;
            }
            cursor = part.body_offset;
            message_extent = cursor;
            continue;
          }
        }
        else if (multipart_depth > 1) {
          for (uint32_t level = 0;
               level + 1 < multipart_depth; level++) {
            bool ancestor_closing = false;

            if (mbox_boundary_line(
                    data, &line, multipart_boundaries[level],
                    &ancestor_closing)) {
              (void)ancestor_closing;
              summary->parsed_extent = message_extent;
              summary->failure_offset = line.start;
              return MBOX_PARSE_PARTIAL;
            }
          }
        }
      }

      if (closed_boundary && !structural_line) {
        char generic_boundary[MBOX_BOUNDARY_MAX + 1];
        bool generic_closing = false;

        if (mbox_generic_boundary_line(
                data, &line, generic_boundary,
                sizeof(generic_boundary), &generic_closing)) {
          if (!generic_closing) {
            MboxPartHeader part;

            if (mbox_parse_part_header(data, length, line.end, &part)) {
              memcpy(epilogue_boundary, generic_boundary,
                     sizeof(epilogue_boundary));
              terminal_extent = 0;
              summary->mime_parts++;
              transfer_encoding = part.transfer_encoding;
              utf8_text = part.utf8_text;
              base64_line_width = 0;
              base64_line_width_run = 0;
              base64_wrap_mismatch = false;
              base64_wrap_mismatch_offset = 0;
              base64_transition_width = 0;
              base64_transition_run = 0;
              cursor = part.body_offset;
              message_extent = cursor;
              continue;
            }
            save = NULL;
          }
          else if (epilogue_boundary[0] != 0
                   && strcmp(generic_boundary, epilogue_boundary) == 0) {
            terminal_extent = mbox_consume_blank_lines(
                data, length, line.end);
            MboxLine after;
            if (!mbox_line_at(data, length, terminal_extent, &after)
                || mbox_line_is_blank(data, &after)) {
              save = NULL;
            }
            transfer_encoding = MBOX_TRANSFER_UNSPECIFIED;
            utf8_text = false;
            base64_line_width = 0;
            base64_line_width_run = 0;
            base64_wrap_mismatch = false;
            base64_wrap_mismatch_offset = 0;
            base64_transition_width = 0;
            base64_transition_run = 0;
            epilogue_boundary[0] = 0;
            structural_line = true;
          }
        }
      }

      uint64_t encoded_symbols = 0;

      if (!structural_line
          && !mbox_transfer_line_valid(data, &line, transfer_encoding,
                                       &encoded_symbols)) {
        summary->parsed_extent = message_extent;
        summary->failure_offset = line.start;
        if (closed_boundary && terminal_extent != 0
            && epilogue_boundary[0] == 0) {
          summary->terminal_observed = true;
          summary->complete_extent = terminal_extent;
          return MBOX_PARSE_COMPLETE;
        }
        return MBOX_PARSE_PARTIAL;
      }
      if (!structural_line
          && transfer_encoding != MBOX_TRANSFER_BINARY
          && (((transfer_encoding == MBOX_TRANSFER_8BIT
                    && !mbox_8bit_line_valid(data, &line))
               || (transfer_encoding != MBOX_TRANSFER_8BIT
                   && !mbox_line_bytes_valid(data, &line)))
              || (utf8_text && !mbox_utf8_line_valid(data, &line)))) {
        summary->parsed_extent = message_extent;
        summary->failure_offset = line.start;
        if (closed_boundary && terminal_extent != 0
            && epilogue_boundary[0] == 0) {
          summary->terminal_observed = true;
          summary->complete_extent = terminal_extent;
          return MBOX_PARSE_COMPLETE;
        }
        return MBOX_PARSE_PARTIAL;
      }
      if (!structural_line
          && transfer_encoding == MBOX_TRANSFER_BASE64
          && encoded_symbols != 0) {
        // Once a producer's wrapping width is established, a short or long
        // line is only valid as the final line before a MIME boundary.
        if (base64_wrap_mismatch) {
          if (encoded_symbols == base64_line_width) {
            summary->parsed_extent = base64_wrap_mismatch_offset;
            summary->failure_offset = base64_wrap_mismatch_offset;
            return MBOX_PARSE_PARTIAL;
          }
          if (encoded_symbols == base64_transition_width) {
            base64_transition_run++;
          }
          else {
            base64_transition_width = encoded_symbols;
            base64_transition_run = 1;
          }
          // Mailing-list software sometimes appends a separately encoded
          // footer using a different wrap width without a MIME boundary.
          if (base64_transition_run >= 2) {
            base64_line_width = base64_transition_width;
            base64_line_width_run = base64_transition_run;
            if (summary->base64_wrap_transitions < UINT32_MAX) {
              summary->base64_wrap_transitions++;
            }
            base64_wrap_mismatch = false;
            base64_wrap_mismatch_offset = 0;
            base64_transition_width = 0;
            base64_transition_run = 0;
          }
        }
        else if (base64_line_width_run >= MBOX_BASE64_WRAP_STABILITY) {
          if (encoded_symbols != base64_line_width) {
            base64_wrap_mismatch = true;
            base64_wrap_mismatch_offset = line.start;
            base64_transition_width = 0;
            base64_transition_run = 0;
          }
          else if (base64_line_width_run < UINT32_MAX) {
            base64_line_width_run++;
          }
        }
        else if (encoded_symbols == base64_line_width) {
          base64_line_width_run++;
        }
        else {
          base64_line_width = encoded_symbols;
          base64_line_width_run = 1;
        }
      }
      if (transfer_encoding == MBOX_TRANSFER_BASE64
          || transfer_encoding == MBOX_TRANSFER_QUOTED_PRINTABLE) {
        summary->encoded_lines++;
      }

      message_extent = line.end;
      cursor = line.end;
      if (!line.terminated) {
        break;
      }
    }

    summary->parsed_extent = message_extent;
    if (next_message) {
      continue;
    }
    if (header.multipart && (!saw_boundary || !closed_boundary)) {
      summary->failure_offset = message_extent;
      return MBOX_PARSE_PARTIAL;
    }
    if (closed_boundary && terminal_extent != 0
        && epilogue_boundary[0] == 0) {
      summary->terminal_observed = true;
      summary->complete_extent = terminal_extent;
      return MBOX_PARSE_COMPLETE;
    }
    return MBOX_PARSE_PARTIAL;
  }

  return summary->messages == 0 ? MBOX_PARSE_INVALID : MBOX_PARSE_PARTIAL;
}

static inline MboxParseResult mbox_parse(const uint8_t *data,
                                         uint64_t length,
                                         MboxParseSummary *summary) {
  return mbox_parse_resumable(data, length, summary, NULL, NULL);
}

// The caller keeps this prefix unchanged while trying alternative continuations.
// Rebuild it on each search entry, including after checkpoint restoration.
static inline void mbox_prepare_trial_prefix(
    CarveInfo *candidate, MboxParseCursor *prefix) {
  mbox_parse_resumable(
      (const uint8_t *)blockvector_get_data_pointer(candidate->b),
      blockvector_get_data_length(candidate->b), NULL, NULL, prefix);
}

static inline char *mbox_header_discovery(char *base, uint64_t offset,
                                          uint64_t remaining,
                                          char **matchpos,
                                          uint32_t *matchlen,
                                          uint32_t blocksize) {
  if (!base || !matchpos || !matchlen || blocksize == 0) {
    return NULL;
  }
  *matchpos = NULL;
  *matchlen = 0;
  uint64_t end = offset + remaining;
  uint64_t position = offset == 0 ? 0 : CEILDIV(offset, blocksize) * blocksize;

  for (; position < end && end - position >= MBOX_MINIMUM_SIZE;
       position += blocksize) {
    MboxMessageHeader header;
    if (mbox_parse_message_header((const uint8_t *)base, end, position,
                                  &header)) {
      *matchpos = base + position;
      *matchlen = header.envelope ? 5U : 12U;
      return NULL;
    }
  }
  return NULL;
}

static inline char *mbox_footer_discovery(char *base, uint64_t offset,
                                          uint64_t remaining,
                                          char **matchpos,
                                          uint32_t *matchlen,
                                          uint32_t blocksize) {
  if (!base || !matchpos || !matchlen || blocksize == 0) {
    return NULL;
  }
  *matchpos = NULL;
  *matchlen = 0;
  uint64_t end = offset + remaining;
  uint64_t position = offset == 0 ? 0 : CEILDIV(offset, blocksize) * blocksize;

  for (; position < end && end - position >= MBOX_MINIMUM_SIZE;
       position += blocksize) {
    MboxMessageHeader header;
    if (!mbox_parse_message_header((const uint8_t *)base, end, position,
                                   &header)) {
      continue;
    }
    MboxParseSummary summary;
    MboxParseResult result = mbox_parse((const uint8_t *)base + position,
                                       end - position, &summary);
    uint64_t extent = result == MBOX_PARSE_COMPLETE
        ? summary.complete_extent : summary.parsed_extent;
    if (extent >= MBOX_MINIMUM_SIZE && extent - 1 <= UINT32_MAX) {
      *matchpos = base + position + 1;
      *matchlen = (uint32_t)(extent - 1);
      return NULL;
    }
  }
  return NULL;
}

static inline uint32_t mbox_block_validate(
    char *data, uint64_t length, BlockValidationDecision *decision,
    uint64_t *validates_to, uint32_t needleidx, uint32_t blocksize,
    void *blockhashkey) {
  (void)blocksize;
  (void)blockhashkey;
  if (!decision || !validates_to || !data || length == 0) {
    return needleidx;
  }
  uint64_t text_bytes = 0;
  uint64_t line_breaks = 0;
  uint64_t controls = 0;
  uint64_t high_bytes = 0;

  for (uint64_t i = 0; i < length; i++) {
    uint8_t value = (uint8_t)data[i];
    if (value == '\n') {
      line_breaks++;
      text_bytes++;
    }
    else if (value == '\r' || value == '\t'
             || (value >= 0x20 && value < 0x7f)) {
      text_bytes++;
    }
    else if (value >= 0x80) {
      high_bytes++;
      text_bytes++;
    }
    else {
      controls++;
    }
  }
  if (controls > length / 32 + 1 || text_bytes * 100 < length * 94) {
    *decision = BLOCK_CONFIDENCE_INVALID;
    *validates_to = 0;
    return needleidx;
  }

  BlockValidationDecision confidence = (BlockValidationDecision)35;
  if (line_breaks >= 3) {
    confidence = (BlockValidationDecision)65;
  }
  if (high_bytes > length / 4) {
    confidence = (BlockValidationDecision)45;
  }
  if ((length >= 12 && memcmp(data, "Return-Path:", 12) == 0)
      || (length >= 5 && memcmp(data, "From ", 5) == 0)
      || (length >= 13 && memcmp(data, "Content-Type:", 13) == 0)
      || (length >= 4 && memcmp(data, "--", 2) == 0)) {
    confidence = BLOCK_CONFIDENCE_VALID;
  }
  if (*decision < confidence) {
    *decision = confidence;
  }
  *validates_to = length - 1;
  return needleidx;
}

static inline void mbox_file_validate(char *data, uint64_t length,
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
  *promising = false;
  *validates_to = 0;
  if (!data || length < MBOX_MINIMUM_SIZE) {
    return;
  }

  MboxParseSummary summary;
  MboxParseResult result = mbox_parse((const uint8_t *)data, length,
                                     &summary);

  if (result == MBOX_PARSE_COMPLETE && summary.complete_extent != 0) {
    *validates = true;
    *validates_to = summary.complete_extent - 1;
    return;
  }
  if (result == MBOX_PARSE_PARTIAL && summary.parsed_extent != 0) {
    *promising = true;
    *validates_to = summary.parsed_extent - 1;
  }
}

static inline void mbox_candidate_validate(CarveInfo *candidate,
                                           bool *validates,
                                           uint64_t *validates_to,
                                           bool *promising) {
  if (!validates || !validates_to || !promising) {
    return;
  }

  if (candidate && candidate->b
      && blockvector_get_data_pointer(candidate->b)
      && blockvector_get_data_length(candidate->b) >= MBOX_MINIMUM_SIZE) {
    MboxMessageHeader header;
    const uint8_t *data = (const uint8_t *)blockvector_get_data_pointer(
        candidate->b);

    if (mbox_parse_message_header(
            data, blockvector_get_data_length(candidate->b), 0, &header)) {
      if (candidate->qposition == INT64_MAX
          && *validates_to < MBOX_MAXIMUM_SIZE) {
        uint64_t proven_extent = *validates_to + 1;

        // Prefer roots supported by more contiguous structure while every
        // initial candidate still receives reassembly time.
        candidate->qposition -= (int64_t)(MBOX_MAXIMUM_SIZE
                                           - proven_extent);
      }
      if (!header.envelope && candidate->qposition > INT64_MIN) {
        // Prefer container envelope roots over message headers nested inside
        // the same mailbox while keeping standalone RFC messages eligible.
        candidate->qposition--;
      }
    }
  }

  if (!*validates) {
    return;
  }

  // MIME closure proves the active entity, but mbox itself has no mandatory
  // container footer and malformed producers can append further entities.
  *validates = false;
  *promising = true;
}

// Only reuse within one search with an unchanged prefix. This is disposable
// materialization, not search state; checkpoint reentry constructs a new buffer.
static inline void mbox_trial_buffer_init(MboxTrialBuffer *trial,
                                          const CarveInfo *candidate,
                                          uint64_t maximum_blocks) {
  memset(trial, 0, sizeof(*trial));
  const uint64_t blocksize = scalpel_state.blocksize;
  const uint64_t blocks = blockvector_get_num_blocks(candidate->b);
  const uint64_t limit = MBOX_TRIAL_BUFFER_BYTES;

  // Limit extra memory per search, not the size of recoverable mailboxes.
  // Larger prefixes use the existing materialization.
  if (blocksize == 0 || blocks > limit / blocksize
      || maximum_blocks > limit / blocksize - blocks) {
    return;
  }
  uint64_t capacity = (blocks + maximum_blocks) * blocksize;
  trial->data = malloc((size_t)capacity);
  check_memory_allocation(trial->data, __LINE__, __FILE__, "MBOX trial buffer");
  const uint64_t apparent_blocks = filemirror_apparent_blocks(
      scalpel_state.filemirror);
  for (uint64_t block = 0; block < blocks; block++) {
    int64_t apparent = blockvector_get_apparent_blocknumber(candidate->b, block);
    uint64_t length = 0;
    const char *data = NULL;
    if (apparent >= 0 && (uint64_t)apparent < apparent_blocks) {
      int64_t actual = filemirror_actual_blocknumber(scalpel_state.filemirror,
                                                     apparent);
      data = filemirror_actual_block_data_pointer(scalpel_state.filemirror,
                                                   actual, &length);
    }
    if (!data || length > blocksize) {
      free(trial->data);
      memset(trial, 0, sizeof(*trial));
      return;
    }
    memcpy(trial->data + block * blocksize, data, (size_t)length);
    if (length < blocksize) {
      memset(trial->data + block * blocksize + length, 0,
             (size_t)(blocksize - length));
    }
  }
  trial->owner = candidate->b;
  trial->blocks = blocks;
  trial->capacity = capacity;
}

// Replace only the proposed continuation; callers keep the cached prefix fixed.
static inline bool mbox_trial_buffer_append(MboxTrialBuffer *trial,
                                            const CarveInfo *candidate,
                                            int64_t first_actual,
                                            uint64_t run_blocks) {
  const uint64_t blocksize = scalpel_state.blocksize;
  if (!trial || !trial->data || trial->owner != candidate->b
      || trial->blocks != blockvector_get_num_blocks(candidate->b)
      || blocksize == 0
      || run_blocks > trial->capacity / blocksize - trial->blocks) {
    return false;
  }
  for (uint64_t block = 0; block < run_blocks; block++) {
    uint64_t length = 0;
    const char *data = filemirror_actual_block_data_pointer(
        scalpel_state.filemirror, first_actual + (int64_t)block, &length);
    if (!data || length > blocksize) {
      return false;
    }
    uint8_t *destination = trial->data + (trial->blocks + block) * blocksize;
    memcpy(destination, data, (size_t)length);
    if (length < blocksize) {
      memset(destination + length, 0, (size_t)(blocksize - length));
    }
  }
  return true;
}

static inline uint64_t mbox_available_run(const CarveInfo *candidate,
                                          int64_t first_actual,
                                          uint64_t maximum_blocks) {
  if (!candidate || !candidate->b || first_actual < 0
      || maximum_blocks == 0 || scalpel_state.blocksize == 0) {
    return 0;
  }

  uint64_t image_blocks = CEILDIV(
      filemirror_filesize(scalpel_state.filemirror),
      scalpel_state.blocksize);
  uint64_t available = 0;

  if ((uint64_t)first_actual >= image_blocks) {
    return 0;
  }
  if (filemirror_apparent_blocknumber(scalpel_state.filemirror, first_actual) < 0
      || filemirror_actual_block_covered(scalpel_state.filemirror,
                                         first_actual)) {
    return 0;
  }
  if (maximum_blocks > image_blocks - (uint64_t)first_actual) {
    maximum_blocks = image_blocks - (uint64_t)first_actual;
  }

  // Bound the run at its first reused block with one prefix scan, rather
  // than searching the whole blockvector for every block in the run.
  uint64_t apparent_blocks = filemirror_apparent_blocks(scalpel_state.filemirror);
  uint64_t committed_blocks = blockvector_get_num_blocks(candidate->b);
  for (uint64_t block = 0; block < committed_blocks; block++) {
    int64_t apparent = blockvector_get_apparent_blocknumber(candidate->b, block);

    if (apparent < 0 || (uint64_t)apparent >= apparent_blocks) {
      continue;
    }
    int64_t actual = filemirror_actual_blocknumber(scalpel_state.filemirror,
                                                  apparent);
    if (actual >= first_actual
        && (uint64_t)(actual - first_actual) < maximum_blocks) {
      maximum_blocks = (uint64_t)(actual - first_actual);
      if (maximum_blocks == 0) {
        return 0;
      }
    }
  }

  while (available < maximum_blocks) {
    int64_t actual = first_actual + (int64_t)available;
    int64_t apparent = filemirror_apparent_blocknumber(
        scalpel_state.filemirror, actual);

    if (apparent < 0
        || filemirror_actual_block_covered(scalpel_state.filemirror,
                                           actual)) {
      break;
    }
    available++;
  }
  return available;
}

// Parse a proposed physical run without repeatedly materializing its prefix.
// A missing or undersized cache uses the original blockvector trial path.
static inline uint64_t mbox_trial_run_buffered(
    CarveInfo *candidate, int64_t first_actual,
    uint64_t maximum_blocks, bool *complete,
    uint64_t *accepted_extent, uint32_t *base64_wrap_transitions,
    const MboxParseCursor *prefix, MboxTrialBuffer *trial) {
  if (complete) {
    *complete = false;
  }
  if (accepted_extent) {
    *accepted_extent = 0;
  }
  if (base64_wrap_transitions) {
    *base64_wrap_transitions = 0;
  }
  if (!candidate || !candidate->b || scalpel_state.blocksize == 0) {
    return 0;
  }

  BlockVector *blockvector = candidate->b;
  uint64_t committed_blocks = blockvector_get_num_blocks(blockvector);
  uint64_t committed_length = committed_blocks
                              * (uint64_t)scalpel_state.blocksize;
  uint64_t run_blocks = mbox_available_run(candidate, first_actual,
                                           maximum_blocks);

  if (run_blocks == 0 || committed_blocks > UINT64_MAX - run_blocks) {
    return 0;
  }

  const uint64_t trial_length = (committed_blocks + run_blocks)
                               * (uint64_t)scalpel_state.blocksize;
  const bool buffered = mbox_trial_buffer_append(trial, candidate, first_actual,
                                                 run_blocks);
  const uint8_t *data;
  if (buffered) {
    data = trial->data;
  }
  else {
    resize_blockvector(blockvector, committed_blocks + run_blocks);
    for (uint64_t block = 0; block < run_blocks; block++) {
      int64_t apparent = filemirror_apparent_blocknumber(
          scalpel_state.filemirror, first_actual + (int64_t)block);

      blockvector_set_apparent_blocknumber(
          blockvector, committed_blocks + block, apparent);
    }
    blockvector_set_data_length(blockvector, trial_length);
    inflate_blockvector(blockvector);
    data = (const uint8_t *)blockvector_get_data_pointer(blockvector);
  }

  MboxParseSummary summary;
  MboxParseResult result = mbox_parse_resumable(
      data, trial_length, &summary, prefix, NULL);
  if (base64_wrap_transitions) {
    *base64_wrap_transitions = summary.base64_wrap_transitions;
  }
  uint64_t accepted_blocks = 0;

  if (result == MBOX_PARSE_COMPLETE
      && summary.complete_extent > committed_length) {
    accepted_blocks = CEILDIV(summary.complete_extent - committed_length,
                              scalpel_state.blocksize);
    if (accepted_blocks > run_blocks) {
      accepted_blocks = run_blocks;
    }
    if (complete) {
      *complete = true;
    }
    if (accepted_extent) {
      *accepted_extent = summary.complete_extent;
    }
  }
  else {
    uint64_t proven_extent = summary.parsed_extent;

    if (summary.complete_extent > proven_extent) {
      proven_extent = summary.complete_extent;
    }
    if (summary.failure_offset > proven_extent
        && summary.failure_offset <= trial_length) {
      proven_extent = summary.failure_offset;
    }
    if (proven_extent > committed_length) {
      accepted_blocks = CEILDIV(proven_extent - committed_length,
                                scalpel_state.blocksize);
      if (accepted_blocks > run_blocks) {
        accepted_blocks = run_blocks;
      }
      if (accepted_extent) {
        *accepted_extent = proven_extent;
      }
    }
  }

  if (!buffered) {
    resize_blockvector(blockvector, committed_blocks);
  }
  blockvector_set_data_length(blockvector, committed_length);
  if (!buffered) {
    inflate_blockvector(blockvector);
  }
  return accepted_blocks;
}

static inline uint64_t mbox_trial_run_scored(
    CarveInfo *candidate, int64_t first_actual, uint64_t maximum_blocks,
    bool *complete, uint64_t *accepted_extent,
    uint32_t *base64_wrap_transitions, const MboxParseCursor *prefix) {
  return mbox_trial_run_buffered(candidate, first_actual, maximum_blocks,
                                 complete, accepted_extent,
                                 base64_wrap_transitions, prefix, NULL);
}

static inline uint64_t mbox_trial_run(CarveInfo *candidate,
                                      int64_t first_actual,
                                      uint64_t maximum_blocks,
                                      bool *complete,
                                      uint64_t *accepted_extent) {
  return mbox_trial_run_scored(candidate, first_actual, maximum_blocks,
                               complete, accepted_extent, NULL, NULL);
}

static inline bool mbox_commit_run(CarveInfo *candidate,
                                   int64_t first_actual,
                                   uint64_t blocks) {
  if (!candidate || !candidate->b || first_actual < 0 || blocks == 0
      || scalpel_state.blocksize == 0) {
    return false;
  }

  BlockVector *blockvector = candidate->b;
  uint64_t old_blocks = blockvector_get_num_blocks(blockvector);

  if (old_blocks > UINT64_MAX - blocks) {
    return false;
  }
  resize_blockvector(blockvector, old_blocks + blocks);
  for (uint64_t block = 0; block < blocks; block++) {
    int64_t apparent = filemirror_apparent_blocknumber(
        scalpel_state.filemirror, first_actual + (int64_t)block);

    if (apparent < 0) {
      resize_blockvector(blockvector, old_blocks);
      inflate_blockvector(blockvector);
      return false;
    }
    blockvector_set_apparent_blocknumber(blockvector,
                                         old_blocks + block, apparent);
  }
  blockvector_set_data_length(
      blockvector, (old_blocks + blocks)
                       * (uint64_t)scalpel_state.blocksize);
  inflate_blockvector(blockvector);
  return true;
}

static inline bool mbox_block_contains_marker(int64_t actual,
                                              const uint8_t *marker,
                                              uint64_t marker_length) {
  if (actual < 0 || !marker || marker_length == 0) {
    return false;
  }

  uint64_t first_length = 0;
  const uint8_t *first = (const uint8_t *)
      filemirror_actual_block_data_pointer(scalpel_state.filemirror,
                                           actual, &first_length);

  if (!first || first_length == 0) {
    return false;
  }
  const uint8_t *second = NULL;
  uint64_t second_length = 0;

  if (marker_length > 1) {
    second = (const uint8_t *)filemirror_actual_block_data_pointer(
        scalpel_state.filemirror, actual + 1, &second_length);
  }

  for (uint64_t offset = 0; offset < first_length; offset++) {
    if (first[offset] != marker[0]) {
      continue;
    }
    bool matches = true;

    for (uint64_t index = 1; index < marker_length; index++) {
      uint64_t position = offset + index;
      uint8_t value = 0;

      if (position < first_length) {
        value = first[position];
      }
      else {
        position -= first_length;
        if (!second || position >= second_length) {
          matches = false;
          break;
        }
        value = second[position];
      }
      if (value != marker[index]) {
        matches = false;
        break;
      }
    }
    if (matches) {
      return true;
    }
  }
  return false;
}

// Checkpoint the committed prefix, not a temporary continuation probe. If the
// request is withdrawn, restore the probe's mapping and exact byte length so
// its search can continue. Only block numbers need temporary storage.
//
static inline bool mbox_checkpoint_probe(ThreadWork *work,
                                          CarveInfo *candidate,
                                          uint64_t checkpoint_blocks,
                                          uint64_t checkpoint_length,
                                          uuid_string_t uuidp,
                                          uuid_string_t uuidc) {
  BlockVector *blockvector = candidate->b;
  const uint64_t probe_blocks = blockvector_get_num_blocks(blockvector);
  const uint64_t probe_length = blockvector_get_data_length(blockvector);

  if (checkpoint_blocks > probe_blocks || checkpoint_length > probe_length
      || probe_blocks - checkpoint_blocks > SIZE_MAX / sizeof(int64_t)) {
    handle_error(SCALPEL_GENERAL_ABORT, "Invalid MBOX probe checkpoint extent",
                 __LINE__, __FILE__);
  }
  const uint64_t tail_blocks = probe_blocks - checkpoint_blocks;
  int64_t *tail = NULL;

  if (tail_blocks != 0) {
    tail = (int64_t *)malloc((size_t)tail_blocks * sizeof(*tail));
    check_memory_allocation(tail, __LINE__, __FILE__,
                            "MBOX temporary continuation mapping");
    for (uint64_t slot = 0; slot < tail_blocks; slot++) {
      tail[slot] = blockvector_get_apparent_blocknumber(
          blockvector, checkpoint_blocks + slot);
    }
  }
  resize_blockvector(blockvector, checkpoint_blocks);
  blockvector_set_data_length(blockvector, checkpoint_length);
  const bool stopped = reassembly_time_to_checkpoint(
      work->id, candidate, uuidp, uuidc);

  if (!stopped) {
    resize_blockvector(blockvector, probe_blocks);
    for (uint64_t slot = 0; slot < tail_blocks; slot++) {
      blockvector_set_apparent_blocknumber(
          blockvector, checkpoint_blocks + slot, tail[slot]);
    }
    blockvector_set_data_length(blockvector, probe_length);
    inflate_blockvector(blockvector);
  }
  free(tail);
  return stopped;
}

// Hash the physical prefix rather than its apparent numbering. Coverage is
// included only for checkpoint save/restore, where it can change run choices.
static inline XXH128_hash_t mbox_search_view_hash(
    CarveInfo *candidate, uint64_t blocks, uint64_t length, bool coverage) {
  XXH3_state_t hash;
  XXH3_128bits_reset(&hash);
  const uint64_t metadata[] = {blocks, length,
      filemirror_filesize(scalpel_state.filemirror), scalpel_state.blocksize};
  XXH3_128bits_update(&hash, metadata, sizeof(metadata));
  int64_t mapping[256];
  for (uint64_t first = 0; first < blocks;) {
    uint64_t count = blocks - first;
    if (count > sizeof(mapping) / sizeof(mapping[0])) {
      count = sizeof(mapping) / sizeof(mapping[0]);
    }
    for (uint64_t i = 0; i < count; i++) {
      mapping[i] = blockvector_get_actual_blocknumber(candidate->b, first + i);
    }
    XXH3_128bits_update(&hash, mapping, (size_t)count * sizeof(mapping[0]));
    first += count;
  }
  if (coverage) {
    const uint64_t image_blocks = CEILDIV(metadata[2], metadata[3]);
    uint8_t covered[256];
    for (uint64_t first = 0; first < image_blocks;) {
      uint64_t count = image_blocks - first;
      if (count > sizeof(covered)) {
        count = sizeof(covered);
      }
      for (uint64_t i = 0; i < count; i++) {
        covered[i] = filemirror_actual_block_covered(
            scalpel_state.filemirror, (int64_t)(first + i)) ? 1 : 0;
      }
      XXH3_128bits_update(&hash, covered, (size_t)count);
      first += count;
    }
  }
  return XXH3_128bits_digest(&hash);
}

// Save search metadata before transferring ownership. The probe helper exposes
// only the committed prefix to the checkpoint and restores a cancelled probe.
static inline bool mbox_checkpoint_search(
    ThreadWork *work, CarveInfo *candidate, MboxCarveState *search,
    uint64_t blocks, uint64_t length,
    uuid_string_t uuidp, uuid_string_t uuidc) {
  if (!atomic_load_explicit(&REASS_RETURN_TO_IDLE, memory_order_acquire)) {
    return false;
  }
  search->view_hash = mbox_search_view_hash(candidate, blocks, length, true);
  carve_put_state(candidate->carvehashkey, search);
  return mbox_checkpoint_probe(work, candidate, blocks, length, uuidp, uuidc);
}

// Find the first surviving apparent entry at a physical cursor. The mapping
// remains physically ordered even when a checkpoint removes covered blocks.
static inline int64_t mbox_apparent_at_or_after(uint64_t next_actual) {
  int64_t low = 0;
  int64_t high = filemirror_apparent_blocks(scalpel_state.filemirror);
  while (low < high) {
    int64_t middle = low + (high - low) / 2;
    int64_t actual = filemirror_actual_blocknumber(
        scalpel_state.filemirror, middle);
    if (actual < 0 || (uint64_t)actual < next_actual) {
      low = middle + 1;
    }
    else {
      high = middle;
    }
  }
  return low;
}

static inline MboxRunSearchResult mbox_find_terminal_run(
    ThreadWork *work, CarveInfo **candidate,
    MboxCarveState *search, MboxTerminalContext context,
    uint64_t checkpoint_blocks, uint64_t checkpoint_length,
    int64_t *selected_bridge_actual, uint64_t *selected_bridge_blocks,
    int64_t *selected_actual, uint64_t *selected_blocks,
    uint64_t *selected_extent, uint32_t *selected_wrap_transitions,
    uuid_string_t uuidp, uuid_string_t uuidc) {
  if (!work || !candidate || !*candidate || !(*candidate)->b
      || !search || context >= MBOX_TERMINAL_CONTEXTS
      || !selected_bridge_actual || !selected_bridge_blocks
      || !selected_actual || !selected_blocks || !selected_extent) {
    return MBOX_RUN_SEARCH_NONE;
  }

  *selected_bridge_actual = -1;
  *selected_bridge_blocks = 0;
  if (selected_wrap_transitions) {
    *selected_wrap_transitions = UINT32_MAX;
  }

  const uint8_t *data = (const uint8_t *)blockvector_get_data_pointer(
      (*candidate)->b);
  uint64_t length = blockvector_get_data_length((*candidate)->b);
  MboxMessageHeader header;

  if (!mbox_parse_message_header(data, length, 0, &header)
      || !header.multipart || header.boundary[0] == 0) {
    return MBOX_RUN_SEARCH_NONE;
  }

  uint8_t marker[MBOX_BOUNDARY_MAX + 5];
  int marker_length = snprintf((char *)marker, sizeof(marker),
                               "--%s--", header.boundary);

  if (marker_length <= 0 || (uint64_t)marker_length >= sizeof(marker)) {
    return MBOX_RUN_SEARCH_NONE;
  }

  int64_t apparent_blocks = filemirror_apparent_blocks(
      scalpel_state.filemirror);
  uint64_t examined = 0;
  BlockVector *blockvector = (*candidate)->b;
  uint64_t base_blocks = blockvector_get_num_blocks(blockvector);
  uint64_t base_length = blockvector_get_data_length(blockvector);
  MboxTerminalSearch *state = &search->terminal[context];
  const XXH128_hash_t prefix_hash = mbox_search_view_hash(
      *candidate, base_blocks, base_length, false);
  bool best_available = state->best_blocks == 0
      || mbox_available_run(*candidate, state->best_actual,
                             state->best_blocks) == state->best_blocks;
  bool bridge_available = state->best_bridge_blocks == 0
      || mbox_available_run(*candidate, state->bridge_actual,
                             state->best_bridge_blocks)
             == state->best_bridge_blocks;
  if (!state->initialized || !XXH128_isEqual(prefix_hash, state->prefix_hash)
      || !best_available || !bridge_available) {
    memset(state, 0, sizeof(*state));
    state->initialized = true;
    state->prefix_hash = prefix_hash;
    state->bridge_actual = -1;
    state->best_actual = -1;
    state->best_wrap_transitions = UINT32_MAX;
  }

  if (base_blocks > 0 && state->bridge_actual < 0) {
    int64_t last_actual = blockvector_get_actual_blocknumber(
        blockvector, base_blocks - 1);

    if (last_actual >= 0 && last_actual < INT64_MAX
        && mbox_available_run(*candidate, last_actual + 1, 1) == 1) {
      state->bridge_actual = last_actual + 1;
    }
  }

  int64_t apparent = mbox_apparent_at_or_after(state->next_actual);

  MboxParseCursor prefix = {0};
  if (!state->done) {
    mbox_prepare_trial_prefix(*candidate, &prefix);
  }
  while (!state->done) {
    if (!state->in_marker) {
      if (apparent >= apparent_blocks) {
        state->done = true;
        break;
      }
      int64_t actual = filemirror_actual_blocknumber(
          scalpel_state.filemirror, apparent++);
      if (actual < 0) {
        continue;
      }
      state->next_actual = (uint64_t)actual + 1;
      bool matches = !filemirror_actual_block_covered(
                         scalpel_state.filemirror, actual)
          && !apparent_block_in_blockvector(
                 (*candidate)->b, apparent - 1)
          && mbox_block_contains_marker(actual, marker, (uint64_t)marker_length);
      if (matches) {
        state->in_marker = true;
        state->marker_actual = actual;
        state->backtrack = 0;
        state->bridge_mode = 0;
        state->best_actual = -1;
        state->best_blocks = 0;
        state->best_extent = 0;
        state->best_bridge_blocks = 0;
        state->best_wrap_transitions = UINT32_MAX;
      }
      examined++;
      if ((examined & UINT64_C(0xff)) == 0) {
        if (reassembly_check_kill_queue(work, candidate, uuidp, uuidc)
            || mbox_checkpoint_search(work, *candidate, search,
                                       checkpoint_blocks, checkpoint_length,
                                       uuidp, uuidc)) {
          return MBOX_RUN_SEARCH_STOPPED;
        }
      }
      if (!matches) {
        continue;
      }
    }

    uint64_t maximum_backtrack = (uint64_t)state->marker_actual;

    if (maximum_backtrack > MBOX_TERMINAL_BACKTRACK_BLOCKS) {
      maximum_backtrack = MBOX_TERMINAL_BACKTRACK_BLOCKS;
    }
    uint32_t bridge_modes = state->bridge_actual >= 0 ? 2U : 1U;
    while (state->backtrack <= maximum_backtrack) {
      while (state->bridge_mode < bridge_modes) {
        uint32_t bridge_mode = state->bridge_mode++;
        bool bridge_committed = bridge_mode == 1
            && mbox_commit_run(*candidate, state->bridge_actual, 1);

        if (bridge_mode == 1 && !bridge_committed) {
          continue;
        }
        int64_t first_actual = state->marker_actual - (int64_t)state->backtrack;
        bool complete = false;
        uint64_t complete_extent = 0;
        uint32_t wrap_transitions = 0;
        uint64_t accepted = mbox_trial_run_scored(
            *candidate, first_actual, state->backtrack + 2,
            &complete, &complete_extent, &wrap_transitions, &prefix);

        if (bridge_committed) {
          resize_blockvector(blockvector, base_blocks);
          blockvector_set_data_length(blockvector, base_length);
          inflate_blockvector(blockvector);
        }
        uint64_t bridge_blocks = bridge_committed ? 1 : 0;

        if (complete
            && (state->best_actual < 0
                || wrap_transitions < state->best_wrap_transitions
                || (wrap_transitions == state->best_wrap_transitions
                    && (complete_extent > state->best_extent
                        || (complete_extent == state->best_extent
                            && accepted + bridge_blocks
                                   > state->best_blocks
                                         + state->best_bridge_blocks))))) {
          state->best_actual = first_actual;
          state->best_blocks = accepted;
          state->best_extent = complete_extent;
          state->best_bridge_blocks = bridge_blocks;
          state->best_wrap_transitions = wrap_transitions;
        }

        examined++;
        if ((examined & UINT64_C(0xff)) == 0
            && reassembly_check_kill_queue(work, candidate,
                                           uuidp, uuidc)) {
          return MBOX_RUN_SEARCH_STOPPED;
        }
        if ((examined & UINT64_C(0x1f)) == 0
            && mbox_checkpoint_search(work, *candidate, search,
                                       checkpoint_blocks, checkpoint_length,
                                       uuidp, uuidc)) {
          return MBOX_RUN_SEARCH_STOPPED;
        }
      }
      state->bridge_mode = 0;
      state->backtrack++;
    }
    state->in_marker = false;
    if (state->best_actual >= 0) {
      state->done = true;
    }
  }
  if (state->best_actual >= 0) {
    if (state->best_bridge_blocks != 0) {
      *selected_bridge_actual = state->bridge_actual;
      *selected_bridge_blocks = state->best_bridge_blocks;
    }
    *selected_actual = state->best_actual;
    *selected_blocks = state->best_blocks;
    *selected_extent = state->best_extent;
    if (selected_wrap_transitions) {
      *selected_wrap_transitions = state->best_wrap_transitions;
    }
    return MBOX_RUN_SEARCH_READY;
  }
  return MBOX_RUN_SEARCH_NONE;
}

// Compare nearby choices one band at a time, then search the remaining image.
// Retain the current band's best result and the next physical fallback choice
// without exposing a speculative mapping to a checkpoint.
static inline MboxRunSearchResult mbox_find_continuation_run(
    ThreadWork *work, CarveInfo **candidate, MboxCarveState *search,
    uuid_string_t uuidp, uuid_string_t uuidc) {
  if (!work || !candidate || !*candidate || !(*candidate)->b || !search) {
    return MBOX_RUN_SEARCH_NONE;
  }
  BlockVector *blockvector = (*candidate)->b;
  const uint64_t blocks = blockvector_get_num_blocks(blockvector);
  const uint64_t length = blockvector_get_data_length(blockvector);
  if (blocks == 0) {
    return MBOX_RUN_SEARCH_NONE;
  }
  const int64_t previous = blockvector_get_actual_blocknumber(blockvector, blocks - 1);
  const uint64_t image_blocks = CEILDIV(
      filemirror_filesize(scalpel_state.filemirror), scalpel_state.blocksize);
  MboxContinuationSearch *state = &search->continuation;
  const XXH128_hash_t prefix_hash = mbox_search_view_hash(
      *candidate, blocks, length, false);
  if (!state->initialized || !XXH128_isEqual(state->prefix_hash, prefix_hash)
      || (state->best_blocks != 0
          && mbox_available_run(*candidate, state->best_actual, state->best_blocks)
                 != state->best_blocks)) {
    memset(state, 0, sizeof(*state));
    state->initialized = true;
    state->prefix_hash = prefix_hash;
    state->band = 1;
    state->distance = 1;
    state->best_actual = -1;
  }
  int64_t apparent = mbox_apparent_at_or_after(state->next_actual);
  const int64_t apparent_blocks = filemirror_apparent_blocks(scalpel_state.filemirror);
  uint64_t examined = 0;
  MboxParseCursor prefix = {0};
  MboxTrialBuffer trial = {0};
  if (!state->done) {
    mbox_prepare_trial_prefix(*candidate, &prefix);
    mbox_trial_buffer_init(&trial, *candidate, MBOX_REASSEMBLY_TRIAL_BLOCKS);
  }

  while (!state->done) {
    int64_t actual = -1;
    if (!state->fallback) {
      uint64_t band_end = state->band + MBOX_REASSEMBLY_SEARCH_BAND - 1;
      if (band_end > MBOX_REASSEMBLY_LOCAL_BLOCKS) {
        band_end = MBOX_REASSEMBLY_LOCAL_BLOCKS;
      }
      if (state->distance > band_end) {
        if (state->best_actual >= 0 && state->best_blocks > 0) {
          state->done = true;
          break;
        }
        state->band += MBOX_REASSEMBLY_SEARCH_BAND;
        state->distance = state->band;
        state->best_actual = -1;
        state->best_blocks = 0;
        state->best_extent = 0;
        state->best_complete = false;
        if (state->band > MBOX_REASSEMBLY_LOCAL_BLOCKS) {
          state->fallback = true;
        }
        continue;
      }
      if (previous >= 0) {
        if (state->direction == 0
            && (uint64_t)previous + state->distance < image_blocks
            && (uint64_t)previous + state->distance <= INT64_MAX) {
          actual = previous + (int64_t)state->distance;
        }
        else if (state->direction == 1
                 && (uint64_t)previous >= state->distance) {
          actual = previous - (int64_t)state->distance;
        }
      }
      state->direction++;
      if (state->direction == 2) {
        state->direction = 0;
        state->distance++;
      }
    }
    else {
      if (apparent >= apparent_blocks) {
        state->done = true;
        break;
      }
      actual = filemirror_actual_blocknumber(scalpel_state.filemirror, apparent++);
      if (actual >= 0) {
        state->next_actual = (uint64_t)actual + 1;
        if (previous >= 0
            && llabs(actual - previous) <= (int64_t)MBOX_REASSEMBLY_LOCAL_BLOCKS) {
          actual = -1;
        }
      }
    }
    if (actual >= 0
        && filemirror_get_blocktype(scalpel_state.filemirror, actual,
                                    (*candidate)->needleidx)
               != BLOCK_CONFIDENCE_INVALID) {
      bool complete = false;
      uint64_t extent = 0;
      const uint64_t accepted = mbox_trial_run_buffered(
          *candidate, actual, MBOX_REASSEMBLY_TRIAL_BLOCKS, &complete, &extent,
          NULL, &prefix, &trial);
      if ((complete && !state->best_complete)
          || (complete == state->best_complete && accepted > state->best_blocks)) {
        state->best_actual = actual;
        state->best_blocks = accepted;
        state->best_extent = extent;
        state->best_complete = complete;
      }
      if (state->fallback
          && (state->best_complete
              || state->best_blocks + 1 >= MBOX_REASSEMBLY_TRIAL_BLOCKS)) {
        state->done = true;
      }
    }
    examined++;
    if ((examined & UINT64_C(0xff)) == 0
        && reassembly_check_kill_queue(work, candidate, uuidp, uuidc)) {
      free(trial.data);
      return MBOX_RUN_SEARCH_STOPPED;
    }
    if ((examined & UINT64_C(0x1f)) == 0
        && mbox_checkpoint_search(work, *candidate, search, blocks, length,
                                   uuidp, uuidc)) {
      free(trial.data);
      return MBOX_RUN_SEARCH_STOPPED;
    }
  }
  free(trial.data);
  return state->best_actual >= 0 && state->best_blocks > 0
      ? MBOX_RUN_SEARCH_READY : MBOX_RUN_SEARCH_NONE;
}

// Search forward and backward around either the committed prefix or a
// temporary adjacent extension. Each context retains its best choice and the
// next direction to examine; only the committed mapping enters a checkpoint.
static inline MboxRunSearchResult mbox_find_local_run(
    ThreadWork *work, CarveInfo **candidate, MboxCarveState *search,
    MboxLocalContext context, uint64_t checkpoint_blocks,
    uint64_t checkpoint_length, int64_t excluded_actual,
    uint64_t excluded_blocks, uint64_t adjacent_blocks,
    uuid_string_t uuidp, uuid_string_t uuidc) {
  if (!work || !candidate || !*candidate || !(*candidate)->b || !search
      || context >= MBOX_LOCAL_CONTEXTS || scalpel_state.blocksize == 0) {
    return MBOX_RUN_SEARCH_NONE;
  }
  BlockVector *blockvector = (*candidate)->b;
  const uint64_t blocks = blockvector_get_num_blocks(blockvector);
  const uint64_t length = blockvector_get_data_length(blockvector);
  if (blocks == 0) {
    return MBOX_RUN_SEARCH_NONE;
  }
  const int64_t previous = blockvector_get_actual_blocknumber(blockvector, blocks - 1);
  if (previous < 0) {
    return MBOX_RUN_SEARCH_NONE;
  }
  const uint64_t image_blocks = CEILDIV(
      filemirror_filesize(scalpel_state.filemirror), scalpel_state.blocksize);
  MboxLocalSearch *state = &search->local[context];
  const XXH128_hash_t prefix_hash = mbox_search_view_hash(
      *candidate, blocks, length, false);
  if (!state->initialized || !XXH128_isEqual(state->prefix_hash, prefix_hash)
      || state->excluded_actual != excluded_actual
      || state->excluded_blocks != excluded_blocks
      || (state->best_blocks != 0
          && mbox_available_run(*candidate, state->best_actual, state->best_blocks)
                 != state->best_blocks)) {
    memset(state, 0, sizeof(*state));
    state->initialized = true;
    state->prefix_hash = prefix_hash;
    state->excluded_actual = excluded_actual;
    state->excluded_blocks = excluded_blocks;
    state->distance = 1;
    state->best_actual = -1;
    if (adjacent_blocks > 0 && previous < INT64_MAX) {
      state->best_actual = previous + 1;
      state->best_blocks = adjacent_blocks;
    }
  }
  uint64_t examined = 0;
  MboxParseCursor prefix = {0};
  MboxTrialBuffer trial = {0};
  if (!state->done) {
    mbox_prepare_trial_prefix(*candidate, &prefix);
    mbox_trial_buffer_init(&trial, *candidate, MBOX_REASSEMBLY_TRIAL_BLOCKS);
  }
  while (!state->done) {
    if (state->distance > MBOX_PRETERMINAL_LOCAL_BLOCKS
        || (state->direction == 0
            && (state->best_blocks >= MBOX_REASSEMBLY_TRIAL_BLOCKS
                || (context == MBOX_LOCAL_ADJACENT && state->best_complete)))) {
      state->done = true;
      break;
    }
    int64_t actual = -1;
    if (state->direction == 0
        && (uint64_t)previous + state->distance < image_blocks
        && (uint64_t)previous + state->distance <= INT64_MAX) {
      actual = previous + (int64_t)state->distance;
    }
    else if (state->direction == 1 && (uint64_t)previous >= state->distance) {
      actual = previous - (int64_t)state->distance;
    }
    state->direction++;
    if (state->direction == 2) {
      state->direction = 0;
      state->distance++;
    }
    const bool excluded = actual >= excluded_actual
        && excluded_actual >= 0
        && (uint64_t)(actual - excluded_actual) < excluded_blocks;
    if (actual >= 0 && !excluded
        && filemirror_get_blocktype(scalpel_state.filemirror, actual,
                                    (*candidate)->needleidx)
               != BLOCK_CONFIDENCE_INVALID) {
      bool complete = false;
      uint64_t extent = 0;
      const uint64_t accepted = mbox_trial_run_buffered(
          *candidate, actual, MBOX_REASSEMBLY_TRIAL_BLOCKS, &complete, &extent,
          NULL, &prefix, &trial);
      if (accepted > 0
          && ((complete && !state->best_complete)
              || (complete == state->best_complete && accepted > state->best_blocks))) {
        state->best_actual = actual;
        state->best_blocks = accepted;
        state->best_complete = complete;
        state->best_extent = extent;
      }
    }
    examined++;
    if ((examined & UINT64_C(0xff)) == 0
        && reassembly_check_kill_queue(work, candidate, uuidp, uuidc)) {
      free(trial.data);
      return MBOX_RUN_SEARCH_STOPPED;
    }
    if ((examined & UINT64_C(0x1f)) == 0
        && mbox_checkpoint_search(work, *candidate, search, checkpoint_blocks,
                                   checkpoint_length, uuidp, uuidc)) {
      free(trial.data);
      return MBOX_RUN_SEARCH_STOPPED;
    }
  }
  free(trial.data);
  return state->best_actual >= 0 && state->best_blocks > 0
      ? MBOX_RUN_SEARCH_READY : MBOX_RUN_SEARCH_NONE;
}

// A complete MIME entity can be the end of the mailbox or the end of one
// message within it. Preserve that interpretation while looking for another
// structurally valid message.
static inline bool mbox_write_extent_hypothesis(CarveInfo *candidate,
                                                uint64_t extent) {
  if (!candidate || !candidate->b || extent < MBOX_MINIMUM_SIZE
      || extent > blockvector_get_data_length(candidate->b)
      || scalpel_state.blocksize == 0 || !scalpel_state.write_promising) {
    return false;
  }

  BlockVector *parent = candidate->b;
  BlockVector *hypothesis = NULL;
  CarveInfoFlavor parent_flavor = candidate->flavor;
  bool parent_chopped = candidate->chopped;
  uint64_t parent_validates_to = candidate->best_validates_to;

  clone_blockvector(parent, &hypothesis, false);
  candidate->b = hypothesis;
  resize_blockvector(hypothesis, CEILDIV(extent, scalpel_state.blocksize));
  inflate_blockvector(hypothesis);
  blockvector_set_data_length(hypothesis, extent);
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

static inline void mbox_publish_candidate(CarveInfo **candidate,
                                          uint64_t extent) {
  if (!candidate || !*candidate || !(*candidate)->b || extent == 0) {
    if (candidate && *candidate) {
      destroy_candidate(candidate);
    }
    return;
  }

  uint64_t blocks = CEILDIV(extent, scalpel_state.blocksize);

  resize_blockvector((*candidate)->b, blocks);
  inflate_blockvector((*candidate)->b);
  blockvector_set_data_length((*candidate)->b, extent);
  if (scalpel_state.write_promising) {
    (*candidate)->flavor = PROMISING;
    write_candidate(candidate, false);
  }
  else {
    destroy_candidate(candidate);
  }
}

// Mail bodies can be large and line oriented, so reassembly tests runs rather
// than walking the image once for every logical block. Nearby runs are tried
// first, while a complete fallback scan preserves support for wider gaps.
// Noncontiguous results remain PROMISING because valid text and MIME syntax do
// not prove the physical provenance of every selected block.
static inline void mbox_reassembly(ThreadWork *work,
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
  MboxCarveState search = {.magic = MBOX_STATE_MAGIC};
  MboxCarveState *saved = (MboxCarveState *)carve_get_state(
      (*candidate)->carvehashkey);
  if (saved && saved->magic == MBOX_STATE_MAGIC) {
    search.alternate_hypothesis_written = saved->alternate_hypothesis_written;
    const XXH128_hash_t view = mbox_search_view_hash(
        *candidate, blockvector_get_num_blocks((*candidate)->b),
        blockvector_get_data_length((*candidate)->b), true);
    if (XXH128_isEqual(view, saved->view_hash)) {
      search = *saved;
    }
  }
  mbox_free_carve_state((void **)&saved);

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

    uint64_t committed_length = blocks
                                * (uint64_t)scalpel_state.blocksize;
    blockvector_set_data_length(blockvector, committed_length);
    inflate_blockvector(blockvector);
    MboxParseSummary current_summary;
    MboxParseResult current_result = mbox_parse(
        (const uint8_t *)blockvector_get_data_pointer(blockvector),
        committed_length, &current_summary);

    if (current_result == MBOX_PARSE_INVALID
        || current_summary.parsed_extent == 0) {
      destroy_candidate(candidate);
      return;
    }

    uint64_t current_extent = current_summary.parsed_extent;

    if (current_result == MBOX_PARSE_COMPLETE
        && current_summary.complete_extent > current_extent) {
      current_extent = current_summary.complete_extent;
    }
    uint64_t minimum_blocks = CEILDIV(current_extent,
                                      scalpel_state.blocksize);

    if (minimum_blocks == 0) {
      minimum_blocks = 1;
    }
    if (minimum_blocks < blocks) {
      resize_blockvector(blockvector, minimum_blocks);
      blocks = minimum_blocks;
      committed_length = blocks
                         * (uint64_t)scalpel_state.blocksize;
      blockvector_set_data_length(blockvector, committed_length);
      inflate_blockvector(blockvector);
    }

    if (reassembly_check_max_size(work->id, *candidate, uuidp, uuidc)) {
      break;
    }
    if (reassembly_check_kill_queue(work, candidate, uuidp, uuidc)) {
      return;
    }
    if (mbox_checkpoint_search(work, *candidate, &search,
                               blocks, committed_length, uuidp, uuidc)) {
      return;
    }

    int64_t previous_actual = blockvector_get_actual_blocknumber(
        blockvector, blocks - 1);
    uint64_t image_blocks = CEILDIV(
        filemirror_filesize(scalpel_state.filemirror),
        scalpel_state.blocksize);
    int64_t selected_actual = -1;
    uint64_t selected_blocks = 0;
    int64_t selected_bridge_actual = -1;
    uint64_t selected_bridge_blocks = 0;
    bool selected_complete = false;
    uint64_t selected_extent = 0;
    uint64_t adjacent_blocks = 0;
    uint64_t examined = 0;
    int64_t preliminary_actual = -1;
    uint64_t preliminary_blocks = 0;
    int64_t preliminary_bridge_actual = -1;
    uint64_t preliminary_bridge_blocks = 0;
    bool preliminary_complete = false;
    uint64_t preliminary_extent = 0;
    int64_t terminal_actual = -1;
    uint64_t terminal_blocks = 0;
    int64_t terminal_bridge_actual = -1;
    uint64_t terminal_bridge_blocks = 0;
    uint64_t terminal_extent = 0;
    uint32_t terminal_wrap_transitions = UINT32_MAX;
    bool terminal_ready = false;

    if (previous_actual >= 0
        && (uint64_t)previous_actual + 1 < image_blocks) {
      bool adjacent_complete = false;
      uint64_t adjacent_extent = 0;
      adjacent_blocks = mbox_trial_run(
          *candidate, previous_actual + 1,
          MBOX_REASSEMBLY_ADJACENT_BLOCKS, &adjacent_complete,
          &adjacent_extent);

      if (!search.alternate_hypothesis_written && !adjacent_complete
          && adjacent_blocks > 0
          && adjacent_blocks
                 < MBOX_REASSEMBLY_ADJACENT_BLOCKS
                       - MBOX_REASSEMBLY_FRONTIER_BLOCKS
          && adjacent_extent > committed_length
          && adjacent_extent <= committed_length
                                    + adjacent_blocks
                                          * (uint64_t)scalpel_state.blocksize
          && adjacent_extent % scalpel_state.blocksize != 0) {
        uint64_t base_blocks = blockvector_get_num_blocks(blockvector);
        uint64_t base_length = blockvector_get_data_length(blockvector);
        bool adjacent_committed = mbox_commit_run(
            *candidate, previous_actual + 1, adjacent_blocks);

        if (adjacent_committed) {
          search.alternate_hypothesis_written = mbox_write_extent_hypothesis(
              *candidate, adjacent_extent);
        }
        resize_blockvector(blockvector, base_blocks);
        blockvector_set_data_length(blockvector, base_length);
        inflate_blockvector(blockvector);
      }

      if (adjacent_complete
          || adjacent_blocks
                 >= MBOX_REASSEMBLY_ADJACENT_BLOCKS
                        - MBOX_REASSEMBLY_FRONTIER_BLOCKS) {
        selected_actual = previous_actual + 1;
        selected_blocks = adjacent_blocks;
        selected_complete = adjacent_complete;
        selected_extent = adjacent_extent;
      }
      else if (adjacent_blocks > 0) {
        preliminary_actual = previous_actual + 1;
        preliminary_blocks = adjacent_blocks;
      }
    }

    if (selected_actual < 0) {
      MboxRunSearchResult terminal_search = mbox_find_terminal_run(
          work, candidate, &search, MBOX_TERMINAL_PREFIX,
          blocks, committed_length, &terminal_bridge_actual,
          &terminal_bridge_blocks, &terminal_actual, &terminal_blocks,
          &terminal_extent, &terminal_wrap_transitions, uuidp, uuidc);

      if (terminal_search == MBOX_RUN_SEARCH_STOPPED) {
        return;
      }
      terminal_ready = terminal_search == MBOX_RUN_SEARCH_READY;
    }

    if (selected_actual < 0 && terminal_ready && adjacent_blocks > 0
        && previous_actual < INT64_MAX) {
      uint64_t base_blocks = blockvector_get_num_blocks(blockvector);
      uint64_t base_length = blockvector_get_data_length(blockvector);
      bool adjacent_committed = mbox_commit_run(
          *candidate, previous_actual + 1, adjacent_blocks);
      MboxRunSearchResult corroborated_search = MBOX_RUN_SEARCH_NONE;
      int64_t corroborated_bridge_actual = -1;
      uint64_t corroborated_bridge_blocks = 0;
      int64_t corroborated_actual = -1;
      uint64_t corroborated_blocks = 0;
      uint64_t corroborated_extent = 0;
      uint32_t corroborated_wrap_transitions = UINT32_MAX;

      if (adjacent_committed) {
        corroborated_search = mbox_find_terminal_run(
            work, candidate, &search, MBOX_TERMINAL_ADJACENT,
            base_blocks, base_length,
            &corroborated_bridge_actual,
            &corroborated_bridge_blocks, &corroborated_actual,
            &corroborated_blocks, &corroborated_extent,
            &corroborated_wrap_transitions, uuidp, uuidc);
      }
      if (corroborated_search == MBOX_RUN_SEARCH_STOPPED) {
        return;
      }
      resize_blockvector(blockvector, base_blocks);
      blockvector_set_data_length(blockvector, base_length);
      inflate_blockvector(blockvector);
      if (corroborated_search == MBOX_RUN_SEARCH_READY) {
        selected_actual = previous_actual + 1;
        selected_blocks = adjacent_blocks;
        selected_extent = corroborated_extent;
      }
    }

    if (selected_actual < 0 && previous_actual >= 0) {
      MboxRunSearchResult local_search = mbox_find_local_run(
          work, candidate, &search, MBOX_LOCAL_PREFIX,
          blocks, committed_length, terminal_ready ? terminal_actual : -1,
          terminal_ready ? terminal_blocks : 0, adjacent_blocks, uuidp, uuidc);
      if (local_search == MBOX_RUN_SEARCH_STOPPED) {
        return;
      }
      preliminary_actual = search.local[MBOX_LOCAL_PREFIX].best_actual;
      preliminary_blocks = search.local[MBOX_LOCAL_PREFIX].best_blocks;
      preliminary_complete = search.local[MBOX_LOCAL_PREFIX].best_complete;
      preliminary_extent = search.local[MBOX_LOCAL_PREFIX].best_extent;

      if (selected_actual < 0 && adjacent_blocks > 0
          && previous_actual >= 0 && previous_actual < INT64_MAX
          && adjacent_blocks <= (uint64_t)(INT64_MAX - previous_actual)) {
        int64_t bridged_actual = -1;
        uint64_t bridged_blocks = 0;
        bool bridged_complete = false;
        uint64_t bridged_extent = 0;
        const uint64_t base_blocks = blockvector_get_num_blocks(blockvector);
        const uint64_t base_length = blockvector_get_data_length(blockvector);
        const bool bridge_committed = mbox_commit_run(
            *candidate, previous_actual + 1, adjacent_blocks);
        if (bridge_committed) {
          MboxRunSearchResult bridged_search = mbox_find_local_run(
              work, candidate, &search, MBOX_LOCAL_ADJACENT,
              blocks, committed_length, previous_actual + 1,
              adjacent_blocks, 0, uuidp, uuidc);
          if (bridged_search == MBOX_RUN_SEARCH_STOPPED) {
            return;
          }
          bridged_actual = search.local[MBOX_LOCAL_ADJACENT].best_actual;
          bridged_blocks = search.local[MBOX_LOCAL_ADJACENT].best_blocks;
          bridged_complete = search.local[MBOX_LOCAL_ADJACENT].best_complete;
          bridged_extent = search.local[MBOX_LOCAL_ADJACENT].best_extent;
        }
        resize_blockvector(blockvector, base_blocks);
        blockvector_set_data_length(blockvector, base_length);
        inflate_blockvector(blockvector);

        bool bridged_ready = bridged_complete
            || bridged_blocks
                   >= MBOX_REASSEMBLY_TRIAL_BLOCKS
                          - MBOX_REASSEMBLY_FRONTIER_BLOCKS;
        bool bridged_preferred = bridged_ready
            && ((bridged_complete && !preliminary_complete)
                || (bridged_complete == preliminary_complete
                    && (bridged_extent > preliminary_extent
                        || (bridged_extent == preliminary_extent
                            && bridged_blocks + adjacent_blocks
                                   > preliminary_blocks
                                         + preliminary_bridge_blocks))));

        if (bridged_preferred) {
          selected_bridge_actual = previous_actual + 1;
          selected_bridge_blocks = adjacent_blocks;
          selected_actual = bridged_actual;
          selected_blocks = bridged_blocks;
          selected_complete = bridged_complete;
          selected_extent = bridged_extent;
        }
      }

      if (selected_actual < 0 && previous_actual < INT64_MAX
          && preliminary_actual > previous_actual + 1
          && adjacent_blocks > 0
          && !preliminary_complete
          && preliminary_blocks
                 >= MBOX_REASSEMBLY_TRIAL_BLOCKS
                        - MBOX_REASSEMBLY_FRONTIER_BLOCKS) {
        uint64_t bridge_limit = (uint64_t)(
            preliminary_actual - (previous_actual + 1));

        if (bridge_limit > adjacent_blocks) {
          bridge_limit = adjacent_blocks;
        }
        uint64_t available_bridge = mbox_available_run(
            *candidate, previous_actual + 1, bridge_limit);
        if (bridge_limit > available_bridge) {
          bridge_limit = available_bridge;
        }
        MboxBridgeSearch *bridge = &search.bridge;
        const XXH128_hash_t prefix_hash = mbox_search_view_hash(
            *candidate, blocks, committed_length, false);
        if (!bridge->initialized
            || !XXH128_isEqual(bridge->prefix_hash, prefix_hash)
            || bridge->continuation_actual != preliminary_actual
            || bridge->continuation_blocks != preliminary_blocks) {
          memset(bridge, 0, sizeof(*bridge));
          bridge->initialized = true;
          bridge->prefix_hash = prefix_hash;
          bridge->continuation_actual = preliminary_actual;
          bridge->continuation_blocks = preliminary_blocks;
          bridge->next_blocks = bridge_limit;
        }

        // Preserve the longest adjacent prefix that remains structurally
        // valid when joined to the selected continuation.
        MboxParseCursor prefix = {0};
        if (!bridge->done && bridge->next_blocks > 0) {
          mbox_prepare_trial_prefix(*candidate, &prefix);
        }
        while (!bridge->done && bridge->next_blocks > 0) {
          const uint64_t bridge_blocks = bridge->next_blocks--;
          uint64_t base_blocks = blockvector_get_num_blocks(blockvector);
          uint64_t base_length = blockvector_get_data_length(blockvector);
          bool bridge_committed = mbox_commit_run(
              *candidate, previous_actual + 1, bridge_blocks);
          bool bridge_complete = false;
          uint64_t bridge_extent = 0;
          uint64_t bridge_accepted = 0;

          if (bridge_committed) {
            bridge_accepted = mbox_trial_run_scored(
                *candidate, preliminary_actual,
                MBOX_REASSEMBLY_TRIAL_BLOCKS, &bridge_complete,
                &bridge_extent, NULL, &prefix);
            resize_blockvector(blockvector, base_blocks);
            blockvector_set_data_length(blockvector, base_length);
            inflate_blockvector(blockvector);
          }

          examined++;
          if (bridge_complete
              || bridge_accepted
                     >= MBOX_REASSEMBLY_TRIAL_BLOCKS
                            - MBOX_REASSEMBLY_FRONTIER_BLOCKS) {
            bridge->best_bridge_blocks = bridge_blocks;
            bridge->best_accepted = bridge_accepted;
            bridge->done = true;
            break;
          }
          if ((examined & UINT64_C(0xff)) == 0
              && reassembly_check_kill_queue(work, candidate,
                                             uuidp, uuidc)) {
            return;
          }
          if ((examined & UINT64_C(0x1f)) == 0
              && atomic_load_explicit(&REASS_RETURN_TO_IDLE,
                                      memory_order_acquire)
              && mbox_checkpoint_search(work, *candidate, &search,
                                         blocks, committed_length,
                                         uuidp, uuidc)) {
            return;
          }
        }
        bridge->done = true;
        if (bridge->best_bridge_blocks > 0) {
          preliminary_bridge_actual = previous_actual + 1;
          preliminary_bridge_blocks = bridge->best_bridge_blocks;
          preliminary_blocks = bridge->best_accepted;
        }
      }

      if (selected_actual < 0 && preliminary_actual >= 0
          && preliminary_blocks > 0) {
        uint64_t base_blocks = blockvector_get_num_blocks(blockvector);
        uint64_t base_length = blockvector_get_data_length(blockvector);
        bool preliminary_bridge_committed =
            preliminary_bridge_blocks == 0
            || mbox_commit_run(*candidate, preliminary_bridge_actual,
                               preliminary_bridge_blocks);
        bool preliminary_committed = preliminary_bridge_committed
            && mbox_commit_run(*candidate, preliminary_actual,
                               preliminary_blocks);
        MboxRunSearchResult corroborated_search = MBOX_RUN_SEARCH_NONE;
        int64_t corroborated_bridge_actual = -1;
        uint64_t corroborated_bridge_blocks = 0;
        int64_t corroborated_actual = -1;
        uint64_t corroborated_blocks = 0;
        uint64_t corroborated_extent = 0;
        uint32_t corroborated_wrap_transitions = UINT32_MAX;

        if (preliminary_committed) {
          corroborated_search = mbox_find_terminal_run(
              work, candidate, &search, MBOX_TERMINAL_PRELIMINARY,
              base_blocks, base_length,
              &corroborated_bridge_actual,
              &corroborated_bridge_blocks, &corroborated_actual,
              &corroborated_blocks, &corroborated_extent,
              &corroborated_wrap_transitions, uuidp, uuidc);
        }
        if (corroborated_search == MBOX_RUN_SEARCH_STOPPED) {
          return;
        }
        resize_blockvector(blockvector, base_blocks);
        blockvector_set_data_length(blockvector, base_length);
        inflate_blockvector(blockvector);
        if (corroborated_search == MBOX_RUN_SEARCH_READY
            && (!terminal_ready
                || corroborated_wrap_transitions
                       < terminal_wrap_transitions
                || (corroborated_wrap_transitions
                        == terminal_wrap_transitions
                    && corroborated_extent > terminal_extent))) {
          selected_bridge_actual = preliminary_bridge_actual;
          selected_bridge_blocks = preliminary_bridge_blocks;
          selected_actual = preliminary_actual;
          selected_blocks = preliminary_blocks;
          selected_extent = corroborated_extent;
        }
      }

    }

    if (selected_actual < 0 && terminal_ready) {
      selected_bridge_actual = terminal_bridge_actual;
      selected_bridge_blocks = terminal_bridge_blocks;
      selected_actual = terminal_actual;
      selected_blocks = terminal_blocks;
      selected_extent = terminal_extent;
      selected_complete = true;
    }

    if (selected_actual < 0 && preliminary_actual >= 0
        && preliminary_blocks > 0) {
      selected_bridge_actual = preliminary_bridge_actual;
      selected_bridge_blocks = preliminary_bridge_blocks;
      selected_actual = preliminary_actual;
      selected_blocks = preliminary_blocks;
      selected_complete = preliminary_complete;
      selected_extent = preliminary_extent;
    }

    if (selected_actual < 0 && current_result == MBOX_PARSE_COMPLETE) {
      break;
    }

    if (selected_actual < 0) {
      MboxRunSearchResult continuation = mbox_find_continuation_run(
          work, candidate, &search, uuidp, uuidc);
      if (continuation == MBOX_RUN_SEARCH_STOPPED) {
        return;
      }
      if (continuation == MBOX_RUN_SEARCH_READY) {
        selected_actual = search.continuation.best_actual;
        selected_blocks = search.continuation.best_blocks;
        selected_complete = search.continuation.best_complete;
        selected_extent = search.continuation.best_extent;
      }
    }

    bool extension_committed = false;

    if (selected_actual >= 0 && selected_blocks > 0) {
      uint64_t old_blocks = blockvector_get_num_blocks(blockvector);
      uint64_t old_length = blockvector_get_data_length(blockvector);
      uint64_t commit_blocks = selected_blocks;

      if (commit_blocks > MBOX_REASSEMBLY_COMMIT_BLOCKS) {
        commit_blocks = MBOX_REASSEMBLY_COMMIT_BLOCKS;
      }
      bool bridge_committed = selected_bridge_blocks == 0
          || mbox_commit_run(*candidate, selected_bridge_actual,
                             selected_bridge_blocks);

      if (bridge_committed) {
        extension_committed = mbox_commit_run(
            *candidate, selected_actual, commit_blocks);
      }
      if (!extension_committed) {
        resize_blockvector(blockvector, old_blocks);
        blockvector_set_data_length(blockvector, old_length);
        inflate_blockvector(blockvector);
      }
      else if (!search.alternate_hypothesis_written) {
        MboxParseSummary extended_summary;

        mbox_parse(
            (const uint8_t *)blockvector_get_data_pointer(blockvector),
            blockvector_get_data_length(blockvector), &extended_summary);
        if (extended_summary.complete_extent > old_length
            && extended_summary.complete_extent
                   <= blockvector_get_data_length(blockvector)) {
          search.alternate_hypothesis_written = mbox_write_extent_hypothesis(
              *candidate, extended_summary.complete_extent);
        }
      }
    }

    if (!extension_committed) {
      break;
    }
    memset(search.terminal, 0, sizeof(search.terminal));
    memset(&search.continuation, 0, sizeof(search.continuation));
    memset(search.local, 0, sizeof(search.local));
    memset(&search.bridge, 0, sizeof(search.bridge));
    (void)selected_complete;
    (void)selected_extent;
  }

  if (*candidate) {
    inflate_blockvector((*candidate)->b);
    MboxParseSummary summary;
    MboxParseResult result = mbox_parse(
        (const uint8_t *)blockvector_get_data_pointer((*candidate)->b),
        blockvector_get_data_length((*candidate)->b), &summary);
    uint64_t extent = result == MBOX_PARSE_COMPLETE
        ? summary.complete_extent : summary.parsed_extent;

    mbox_publish_candidate(candidate, extent);
  }
}

// Search state contains physical positions and scores, not image bytes.
static inline bool mbox_serialize_carve_state(void **state, FILE *fp,
                                              StateSerialization mode) {
  if (!state || !fp || (mode == SERIALIZE && !*state)) {
    return false;
  }
  if (mode == DESERIALIZE) {
    MboxCarveState *restored = (MboxCarveState *)malloc(sizeof(*restored));
    check_memory_allocation(restored, __LINE__, __FILE__, "MBOX search state");
    if (fread(restored, sizeof(*restored), 1, fp) != 1
        || restored->magic != MBOX_STATE_MAGIC
        || restored->continuation.direction > 1
        || restored->continuation.band > MBOX_REASSEMBLY_LOCAL_BLOCKS + 1
        || restored->continuation.distance > MBOX_REASSEMBLY_LOCAL_BLOCKS + 1
        || restored->bridge.next_blocks > MBOX_REASSEMBLY_ADJACENT_BLOCKS
        || restored->bridge.best_bridge_blocks > MBOX_REASSEMBLY_ADJACENT_BLOCKS) {
      free(restored);
      return false;
    }
    for (uint32_t i = 0; i < MBOX_TERMINAL_CONTEXTS; i++) {
      if (restored->terminal[i].bridge_mode > 2
          || restored->terminal[i].backtrack
                 > MBOX_TERMINAL_BACKTRACK_BLOCKS + 1) {
        free(restored);
        return false;
      }
    }
    for (uint32_t i = 0; i < MBOX_LOCAL_CONTEXTS; i++) {
      if (restored->local[i].direction > 1
          || restored->local[i].distance > MBOX_PRETERMINAL_LOCAL_BLOCKS + 1) {
        free(restored);
        return false;
      }
    }
    *state = restored;
    return true;
  }
  return fwrite(*state, sizeof(MboxCarveState), 1, fp) == 1;
}

static inline void *mbox_clone_carve_state(const void *state) {
  if (!state) {
    return NULL;
  }
  MboxCarveState *clone = (MboxCarveState *)malloc(sizeof(*clone));
  check_memory_allocation(clone, __LINE__, __FILE__, "MBOX search state clone");
  memcpy(clone, state, sizeof(*clone));
  return clone;
}

static inline void mbox_free_carve_state(void **state) {
  if (state && *state) {
    free(*state);
    *state = NULL;
  }
}

static inline size_t mbox_sizeof_carve_state(const void *state) {
  (void)state;
  return sizeof(MboxCarveState);
}

static inline void mbox_print_carve_state(const void *state) {
  const MboxCarveState *typed = (const MboxCarveState *)state;
  if (!typed) {
    printf("NULL\n");
    return;
  }
  for (uint32_t i = 0; i < MBOX_TERMINAL_CONTEXTS; i++) {
    const MboxTerminalSearch *search = &typed->terminal[i];
    printf("MBOX terminal context %u, next actual block %" PRIu64
           ", backtrack %" PRIu64 ", bridge %u, done %d\n",
           i, search->next_actual, search->backtrack,
           search->bridge_mode, search->done);
  }
  printf("MBOX continuation band %" PRIu64 ", distance %" PRIu64
         ", next actual block %" PRIu64 ", fallback %d, done %d\n",
         typed->continuation.band, typed->continuation.distance,
         typed->continuation.next_actual, typed->continuation.fallback,
         typed->continuation.done);
  for (uint32_t i = 0; i < MBOX_LOCAL_CONTEXTS; i++) {
    printf("MBOX local context %u, distance %" PRIu64
           ", direction %u, best actual block %" PRId64 ", done %d\n",
           i, typed->local[i].distance, typed->local[i].direction,
           typed->local[i].best_actual, typed->local[i].done);
  }
  printf("MBOX bridge next length %" PRIu64 ", best length %" PRIu64
         ", done %d\n", typed->bridge.next_blocks,
         typed->bridge.best_bridge_blocks, typed->bridge.done);
}

#endif
