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

// Plain text has no universal magic value or intrinsic end marker. Recovery is
// therefore limited to strongly textual, block-aligned runs bounded by data
// that is not plausible text. Sustained line and character evidence identifies
// plausible runs, but cannot prove that they are independent files, so results
// remain PROMISING and never cover blocks.

#ifndef SCALPEL3_TEXT_H
#define SCALPEL3_TEXT_H

#include "html.h"
#include "scalpel.h"

#include <ctype.h>
#include <stdint.h>
#include <string.h>

#define TEXT_MINIMUM_SIZE UINT64_C(1024)
#define TEXT_MAXIMUM_SIZE UINT64_C(67108864)
#define TEXT_MINIMUM_LETTERS_PER_BLOCK 24U
#define TEXT_MINIMUM_LINES_PER_BLOCK 2U
#define TEXT_MINIMUM_COMPLETE_LINES 6U

typedef struct TextBlockEvidence {
  uint64_t valid_prefix;
  uint64_t letters;
  uint64_t digits;
  uint64_t spaces;
  uint64_t punctuation;
  uint64_t high_characters;
  uint64_t invalid_bytes;
  uint32_t lines;
  uint32_t html_tags;
  bool document_prefix;
} TextBlockEvidence;

typedef struct TextRunSummary {
  uint64_t extent;
  uint64_t alternate_extent;
  uint64_t failure_offset;
  uint64_t alphanumeric;
  uint64_t characters;
  uint32_t lines;
  uint32_t blocks;
  bool terminal_boundary;
} TextRunSummary;

static inline uint32_t text_utf8_sequence_length(const uint8_t *data,
                                                 uint64_t length);
static inline TextBlockEvidence text_block_evidence(const uint8_t *data,
                                                    uint64_t length);
static inline bool text_block_strong(const uint8_t *data, uint64_t length);
static inline bool text_block_continuation(const uint8_t *data,
                                           uint64_t length);
static inline bool text_parse_run(const uint8_t *data, uint64_t length,
                                  uint32_t blocksize,
                                  TextRunSummary *summary);
static inline char *text_header_discovery(char *base, uint64_t offset,
                                          uint64_t remaining,
                                          char **matchpos,
                                          uint32_t *matchlen,
                                          uint32_t blocksize);
static inline uint32_t text_block_validate(
    char *data, uint64_t length, BlockValidationDecision *decision,
    uint64_t *validates_to, uint32_t needleidx, uint32_t blocksize,
    void *blockhashkey);
static inline void text_file_validate(char *data, uint64_t length,
                                      bool *validates,
                                      uint64_t *validates_to,
                                      bool *promising,
                                      uint32_t needleidx,
                                      uint32_t blocksize,
                                      void *carvehashkey);
static inline bool text_write_extent_hypothesis(CarveInfo *candidate,
                                                uint64_t extent);
static inline void text_reassembly(ThreadWork *work,
                                   CarveInfo **candidate,
                                   uuid_string_t uuidp,
                                   uuid_string_t uuidc);

static inline uint32_t text_utf8_sequence_length(const uint8_t *data,
                                                 uint64_t length) {
  if (!data || length == 0) {
    return 0;
  }
  const uint8_t first = data[0];
  uint32_t count;
  uint32_t minimum_second = 0x80;
  uint32_t maximum_second = 0xbf;

  if (first >= 0xc2 && first <= 0xdf) {
    count = 2;
  }
  else if (first >= 0xe0 && first <= 0xef) {
    count = 3;
    if (first == 0xe0) {
      minimum_second = 0xa0;
    }
    else if (first == 0xed) {
      maximum_second = 0x9f;
    }
  }
  else if (first >= 0xf0 && first <= 0xf4) {
    count = 4;
    if (first == 0xf0) {
      minimum_second = 0x90;
    }
    else if (first == 0xf4) {
      maximum_second = 0x8f;
    }
  }
  else {
    return 0;
  }

  if (length < count || data[1] < minimum_second
      || data[1] > maximum_second) {
    return 0;
  }
  for (uint32_t i = 2; i < count; i++) {
    if (data[i] < 0x80 || data[i] > 0xbf) {
      return 0;
    }
  }
  return count;
}

static inline TextBlockEvidence text_block_evidence(const uint8_t *data,
                                                    uint64_t length) {
  TextBlockEvidence evidence = {0};
  HtmlBlockEvidence html = html_block_evidence(data, length);

  evidence.document_prefix = html.document_prefix;
  evidence.html_tags = html.recognized_tags;
  if (!data || length == 0) {
    return evidence;
  }

  uint64_t offset = 0;
  while (offset < length) {
    const uint8_t c = data[offset];
    if (c == '\r') {
      evidence.lines++;
      evidence.spaces++;
      if (offset + 1 < length && data[offset + 1] == '\n') {
        offset++;
        evidence.spaces++;
      }
    }
    else if (c == '\n') {
      evidence.lines++;
      evidence.spaces++;
    }
    else if (c == '\t' || c == '\f' || c == ' ') {
      evidence.spaces++;
    }
    else if (c >= 0x20 && c <= 0x7e) {
      if (isalpha((unsigned char)c)) {
        evidence.letters++;
      }
      else if (isdigit((unsigned char)c)) {
        evidence.digits++;
      }
      else {
        evidence.punctuation++;
      }
    }
    else if (c >= 0xa0) {
      const uint32_t utf8_length = text_utf8_sequence_length(
          data + offset, length - offset);
      if (utf8_length > 1) {
        evidence.high_characters += utf8_length;
        offset += utf8_length - 1;
      }
      else {
        uint32_t expected = 0;
        if (c >= 0xc2 && c <= 0xdf) {
          expected = 2;
        }
        else if (c >= 0xe0 && c <= 0xef) {
          expected = 3;
        }
        else if (c >= 0xf0 && c <= 0xf4) {
          expected = 4;
        }

        const uint64_t remaining = length - offset;
        bool truncated_utf8 = expected > remaining;
        for (uint64_t i = 1; truncated_utf8 && i < remaining; i++) {
          if (data[offset + i] < 0x80 || data[offset + i] > 0xbf) {
            truncated_utf8 = false;
          }
        }
        if (truncated_utf8) {
          evidence.high_characters += remaining;
          offset = length - 1;
        }
        else {
          evidence.high_characters++;
        }
      }
    }
    else if (c >= 0x80) {
      const bool split_utf8_continuation = offset < 3 && c <= 0xbf;
      const bool cp1252_printable = c == 0x80
          || (c >= 0x82 && c <= 0x8c) || c == 0x8e
          || (c >= 0x91 && c <= 0x9c) || c == 0x9e || c == 0x9f;
      if (split_utf8_continuation || cp1252_printable) {
        evidence.high_characters++;
      }
      else {
        evidence.invalid_bytes++;
        break;
      }
    }
    else {
      evidence.invalid_bytes++;
      break;
    }
    offset++;
  }
  evidence.valid_prefix = offset;
  return evidence;
}

static inline bool text_block_strong(const uint8_t *data, uint64_t length) {
  const TextBlockEvidence evidence = text_block_evidence(data, length);
  const uint64_t alphanumeric = evidence.letters + evidence.digits;

  if (evidence.valid_prefix != length || evidence.document_prefix
      || evidence.html_tags >= 2
      || alphanumeric < TEXT_MINIMUM_LETTERS_PER_BLOCK
      || evidence.lines < TEXT_MINIMUM_LINES_PER_BLOCK) {
    return false;
  }
  const uint64_t evidence_bytes = evidence.letters + evidence.digits
                                  + evidence.spaces + evidence.punctuation
                                  + evidence.high_characters;
  return evidence_bytes * 100 >= length * 95
      && alphanumeric * 10 >= length;
}

static inline bool text_block_continuation(const uint8_t *data,
                                           uint64_t length) {
  const TextBlockEvidence evidence = text_block_evidence(data, length);
  const uint64_t alphanumeric = evidence.letters + evidence.digits;

  if (evidence.valid_prefix != length || evidence.document_prefix
      || evidence.html_tags >= 4) {
    return false;
  }
  return alphanumeric >= 8
      && (evidence.letters + evidence.digits + evidence.spaces
          + evidence.punctuation + evidence.high_characters) * 100
             >= length * 90;
}

static inline bool text_parse_run(const uint8_t *data, uint64_t length,
                                  uint32_t blocksize,
                                  TextRunSummary *summary) {
  if (!summary) {
    return false;
  }
  memset(summary, 0, sizeof(*summary));
  if (!data || blocksize == 0 || length < TEXT_MINIMUM_SIZE
      || !text_block_strong(data, length < blocksize ? length : blocksize)) {
    return false;
  }

  uint64_t offset = 0;
  while (offset < length) {
    const uint64_t block_length = length - offset < blocksize
                                      ? length - offset : blocksize;
    const TextBlockEvidence evidence = text_block_evidence(data + offset,
                                                           block_length);
    const bool full = evidence.valid_prefix == block_length;

    if (full && (offset == 0
                 ? text_block_strong(data + offset, block_length)
                 : text_block_continuation(data + offset, block_length))) {
      summary->alphanumeric += evidence.letters + evidence.digits;
      summary->characters += block_length;
      summary->lines += evidence.lines;
      summary->blocks++;
      offset += block_length;
      continue;
    }

    // A binary boundary cannot authenticate a trailing partial line.
    uint64_t terminal = evidence.valid_prefix;
    bool complete_line_ending = false;
    for (uint64_t cursor = evidence.valid_prefix; cursor > 0; cursor--) {
      const uint8_t c = data[offset + cursor - 1];
      if (c == '\r' || c == '\n') {
        terminal = cursor;
        complete_line_ending = true;
        break;
      }
    }
    if (complete_line_ending) {
      uint64_t line_start = terminal - 1;
      if (data[offset + line_start] == '\n' && line_start > 0
          && data[offset + line_start - 1] == '\r') {
        line_start--;
      }
      if (line_start > 0
          && (data[offset + line_start - 1] == '\r'
              || data[offset + line_start - 1] == '\n')) {
        summary->alternate_extent = offset + line_start;
      }
    }
    if ((evidence.valid_prefix >= 16
         || (offset > 0 && complete_line_ending))
        && !evidence.document_prefix && evidence.html_tags < 2) {
      if (terminal > 0) {
        TextBlockEvidence terminal_evidence = evidence;
        if (terminal != evidence.valid_prefix) {
          terminal_evidence = text_block_evidence(data + offset, terminal);
        }
        summary->alphanumeric += terminal_evidence.letters
                                 + terminal_evidence.digits;
        summary->characters += terminal;
        summary->lines += terminal_evidence.lines;
        summary->blocks++;
        summary->extent = offset + terminal;
        summary->failure_offset = offset + evidence.valid_prefix;
        summary->terminal_boundary = true;
        break;
      }
    }

    summary->extent = offset;
    summary->failure_offset = offset;
    summary->terminal_boundary = offset > 0;
    break;
  }

  if (offset == length) {
    summary->extent = length;
    summary->failure_offset = length;
    summary->terminal_boundary = false;
  }
  return summary->extent >= TEXT_MINIMUM_SIZE
      && summary->blocks >= 2
      && summary->lines >= TEXT_MINIMUM_COMPLETE_LINES
      && summary->alphanumeric * 12 >= summary->characters;
}

static inline char *text_header_discovery(char *base, uint64_t offset,
                                          uint64_t remaining,
                                          char **matchpos,
                                          uint32_t *matchlen,
                                          uint32_t blocksize) {
  if (!base || !matchpos || !matchlen || blocksize == 0) {
    return NULL;
  }
  *matchpos = NULL;
  *matchlen = 1;

  const uint64_t end = offset + remaining;
  uint64_t position = CEILDIV(offset, blocksize) * blocksize;
  while (position < end) {
    const uint64_t current_length = end - position < blocksize
                                        ? end - position : blocksize;
    const bool current = text_block_strong(
        (const uint8_t *)base + position, current_length);
    bool previous = false;
    bool next = true;

    if (position >= blocksize) {
      previous = text_block_strong((const uint8_t *)base + position
                                       - blocksize,
                                   blocksize);
    }
    if (position + blocksize < end) {
      const uint64_t next_length = end - position - blocksize < blocksize
                                       ? end - position - blocksize
                                       : blocksize;
      next = text_block_continuation((const uint8_t *)base + position
                                         + blocksize,
                                     next_length);
    }
    if (current && !previous && next) {
      *matchpos = base + position;
      return NULL;
    }
    if (position > UINT64_MAX - blocksize) {
      break;
    }
    position += blocksize;
  }
  return NULL;
}

static inline uint32_t text_block_validate(
    char *data, uint64_t length, BlockValidationDecision *decision,
    uint64_t *validates_to, uint32_t needleidx, uint32_t blocksize,
    void *blockhashkey) {
  (void)blocksize;
  (void)blockhashkey;
  if (!decision || !validates_to || !data || length == 0) {
    if (decision) {
      *decision = BLOCK_CONFIDENCE_INVALID;
    }
    if (validates_to) {
      *validates_to = 0;
    }
    return needleidx;
  }

  const TextBlockEvidence evidence = text_block_evidence(
      (const uint8_t *)data, length);
  if (evidence.valid_prefix != length || evidence.document_prefix
      || evidence.html_tags >= 4) {
    *decision = BLOCK_CONFIDENCE_INVALID;
    *validates_to = 0;
    return needleidx;
  }
  *validates_to = length - 1;
  uint32_t confidence = (uint32_t)*decision;
  if (text_block_strong((const uint8_t *)data, length)) {
    confidence = BLOCK_CONFIDENCE_VALID;
  }
  else if (text_block_continuation((const uint8_t *)data, length)
           && confidence < 70) {
    confidence = 70;
  }
  else if (confidence == BLOCK_CONFIDENCE_INVALID) {
    confidence = BLOCK_CONFIDENCE_LOW;
  }
  *decision = (BlockValidationDecision)confidence;
  return needleidx;
}

static inline void text_file_validate(char *data, uint64_t length,
                                      bool *validates,
                                      uint64_t *validates_to,
                                      bool *promising,
                                      uint32_t needleidx,
                                      uint32_t blocksize,
                                      void *carvehashkey) {
  (void)needleidx;
  (void)carvehashkey;
  if (!validates || !validates_to || !promising) {
    return;
  }
  *validates = false;
  *validates_to = 0;
  *promising = false;

  TextRunSummary summary;
  if (!text_parse_run((const uint8_t *)data, length, blocksize, &summary)
      || summary.extent == 0) {
    return;
  }
  *validates_to = summary.extent - 1;
  *promising = true;
}

// Preserve the shorter complete-line interpretation when binary padding can
// also be read as one final empty line.
static inline bool text_write_extent_hypothesis(CarveInfo *candidate,
                                                uint64_t extent) {
  if (!candidate || !candidate->b || extent < TEXT_MINIMUM_SIZE
      || extent >= blockvector_get_data_length(candidate->b)
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

static inline void text_reassembly(ThreadWork *work,
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

  (*candidate)->chopped = true;
  inflate_blockvector((*candidate)->b);

  while (*candidate) {
    BlockVector *blockvector = (*candidate)->b;
    const uint64_t blocks = blockvector_get_num_blocks(blockvector);
    const uint64_t current_length = blockvector_get_data_length(blockvector);
    if (blocks == 0 || current_length == 0) {
      break;
    }

    TextRunSummary summary;
    if (text_parse_run(
            (const uint8_t *)blockvector_get_data_pointer(blockvector),
            current_length, scalpel_state.blocksize, &summary)
        && summary.terminal_boundary && summary.extent > 0) {
      text_write_extent_hypothesis(*candidate, summary.alternate_extent);
      resize_blockvector(blockvector,
                         CEILDIV(summary.extent, scalpel_state.blocksize));
      inflate_blockvector(blockvector);
      blockvector_set_data_length(blockvector, summary.extent);
      (*candidate)->flavor = PROMISING;
      (*candidate)->chopped = false;
      (*candidate)->best_validates_to = summary.extent - 1;
      if (scalpel_state.write_promising) {
        write_candidate(candidate, false);
      }
      else {
        destroy_candidate(candidate);
      }
      return;
    }

    if (reassembly_check_max_size(work->id, *candidate, uuidp, uuidc)) {
      break;
    }
    if (reassembly_check_kill_queue(work, candidate, uuidp, uuidc)) {
      return;
    }
    if (atomic_load_explicit(&REASS_RETURN_TO_IDLE, memory_order_acquire)
        && reassembly_time_to_checkpoint(work->id, *candidate,
                                         uuidp, uuidc)) {
      return;
    }

    const int64_t last_actual = blockvector_get_actual_blocknumber(
        blockvector, blocks - 1);
    if (last_actual < 0 || last_actual == INT64_MAX) {
      break;
    }
    const int64_t next_actual = last_actual + 1;
    if (filemirror_actual_block_covered(scalpel_state.filemirror,
                                        next_actual)) {
      break;
    }
    const int64_t next_apparent = filemirror_apparent_blocknumber(
        scalpel_state.filemirror, next_actual);
    if (next_apparent < 0
        || apparent_block_in_blockvector(blockvector, next_apparent)) {
      break;
    }

    resize_blockvector(blockvector, blocks + 1);
    blockvector_set_apparent_blocknumber(blockvector, blocks, next_apparent);
    blockvector_set_data_length_to_mapped_extent(blockvector);
    inflate_blockvector(blockvector);

    const uint64_t extended_length = blockvector_get_data_length(blockvector);
    if (!text_parse_run(
            (const uint8_t *)blockvector_get_data_pointer(blockvector),
            extended_length, scalpel_state.blocksize, &summary)
        || summary.extent <= current_length) {
      resize_blockvector(blockvector, blocks);
      inflate_blockvector(blockvector);
      blockvector_set_data_length(blockvector, current_length);
      break;
    }

    if (summary.terminal_boundary) {
      text_write_extent_hypothesis(*candidate, summary.alternate_extent);
      resize_blockvector(blockvector,
                         CEILDIV(summary.extent, scalpel_state.blocksize));
      inflate_blockvector(blockvector);
      blockvector_set_data_length(blockvector, summary.extent);
      (*candidate)->flavor = PROMISING;
      (*candidate)->chopped = false;
      (*candidate)->best_validates_to = summary.extent - 1;
      if (scalpel_state.write_promising) {
        write_candidate(candidate, false);
      }
      else {
        destroy_candidate(candidate);
      }
      return;
    }

    (*candidate)->best_validates_to = extended_length - 1;
  }

  if (*candidate) {
    destroy_candidate(candidate);
  }
}

#endif
