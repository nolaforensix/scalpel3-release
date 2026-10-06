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

// HTML recovery. Complete documents are bounded by a document prologue and a
// closing html element. The parser deliberately accepts legacy HTML while
// rejecting binary insertions, nested document starts, and abrupt physical
// joins between uniformly different line-ending conventions.

#ifndef SCALPEL3_HTML_H
#define SCALPEL3_HTML_H

#include "scalpel.h"

#include <ctype.h>
#include <stdint.h>
#include <string.h>

#define HTML_MINIMUM_SIZE UINT64_C(32)
#define HTML_MAXIMUM_SIZE UINT64_C(1073741824)
#define HTML_PREFIX_WINDOW UINT64_C(1024)
#define HTML_TAG_NAME_MAX 32U
#define HTML_TAGLESS_TEXT_CONFIDENCE 20U
#define HTML_SUSPICIOUS_TAGLESS_BLOCKS UINT64_C(8)
#define HTML_TRIAL_WINDOW_BYTES UINT64_C(16777216)
#define HTML_STATE_MAGIC UINT64_C(0x48544d4c53434131)

typedef enum HtmlParseResult {
  HTML_PARSE_INVALID = 0,
  HTML_PARSE_PARTIAL,
  HTML_PARSE_COMPLETE
} HtmlParseResult;

typedef enum HtmlLineStyle {
  HTML_LINE_UNKNOWN = 0,
  HTML_LINE_LF,
  HTML_LINE_CRLF,
  HTML_LINE_CR
} HtmlLineStyle;

typedef struct HtmlParseSummary {
  uint64_t parsed_extent;
  uint64_t terminal_extent;
  uint64_t failure_offset;
  uint32_t tags;
  uint32_t opening_tags;
  uint32_t closing_tags;
  uint32_t comments;
  uint32_t declarations;
  uint32_t text_bytes;
  uint32_t recognized_tags;
  HtmlLineStyle line_style;
  bool saw_html_open;
  bool saw_head;
  bool saw_body;
  bool saw_title;
  bool saw_terminal;
  bool needs_more_data;
} HtmlParseSummary;

typedef struct HtmlBlockEvidence {
  uint64_t text_bytes;
  uint64_t whitespace_bytes;
  uint64_t high_bytes;
  uint64_t invalid_controls;
  uint32_t tags;
  uint32_t recognized_tags;
  bool document_prefix;
} HtmlBlockEvidence;

typedef struct HtmlRunEvaluation {
  bool found;
  bool complete;
  uint64_t prefix_blocks;
  int64_t first_actual;
  uint64_t run_blocks;
  uint64_t extent;
  uint64_t total_blocks;
  uint64_t longest_tagless_run;
  uint64_t distance;
} HtmlRunEvaluation;

// Only search descriptors are retained. The candidate owns the committed
// blockvector; temporary alternate prefixes are recreated on entry.
typedef struct HtmlCarveState {
  uint64_t magic;
  XXH128_hash_t view_hash;
  uint64_t prefixes[2];
  uint64_t next_actual;
  uint32_t prefix_count;
  uint32_t option;
  bool initialized;
  bool prepared;
  bool displaced_done;
  bool changed;
  HtmlRunEvaluation option_best[2];
  HtmlRunEvaluation current_best;
  HtmlRunEvaluation local_continuation;
  HtmlRunEvaluation physical_suffix;
  HtmlRunEvaluation skipped_complete;
} HtmlCarveState;

static inline bool html_ascii_equal_ci(const uint8_t *data, uint64_t length,
                                       const char *literal);
static inline bool html_ascii_starts_ci(const uint8_t *data, uint64_t length,
                                        const char *literal);
static inline bool html_name_is(const char *name, uint32_t length,
                                const char *literal);
static inline bool html_invalid_control(uint8_t value);
static inline bool html_recognized_tag(const char *name, uint32_t length);
static inline bool html_document_prefix(const uint8_t *data, uint64_t length,
                                        uint64_t *marker_offset);
static inline HtmlLineStyle html_initial_line_style(const uint8_t *data,
                                                    uint64_t length,
                                                    uint32_t blocksize);
static inline bool html_block_line_style_conflicts(
    const uint8_t *data, uint64_t length, HtmlLineStyle preferred);
static inline uint64_t html_trailing_linebreak_extent(const uint8_t *data,
                                                      uint64_t length,
                                                      uint64_t offset,
                                                      HtmlLineStyle preferred);
static inline bool html_find_terminal(const uint8_t *data, uint64_t length,
                                      uint64_t start, uint64_t *marker,
                                      uint64_t *extent);
static inline HtmlParseResult html_parse(const uint8_t *data, uint64_t length,
                                         uint32_t blocksize,
                                         HtmlParseSummary *summary);
static inline HtmlBlockEvidence html_block_evidence(const uint8_t *data,
                                                    uint64_t length);
static inline char *html_header_discovery(char *base, uint64_t offset,
                                          uint64_t remaining,
                                          char **matchpos,
                                          uint32_t *matchlen,
                                          uint32_t blocksize);
static inline char *html_footer_discovery(char *base, uint64_t offset,
                                          uint64_t remaining,
                                          char **matchpos,
                                          uint32_t *matchlen,
                                          uint32_t blocksize);
static inline uint32_t html_block_validate(
    char *data, uint64_t length, BlockValidationDecision *decision,
    uint64_t *validates_to, uint32_t needleidx, uint32_t blocksize,
    void *blockhashkey);
static inline void html_file_validate(char *data, uint64_t length,
                                      bool *validates,
                                      uint64_t *validates_to,
                                      bool *promising,
                                      uint32_t needleidx,
                                      uint32_t blocksize,
                                      void *carvehashkey);
static inline void html_candidate_validate(CarveInfo *candidate,
                                           bool *validates,
                                           uint64_t *validates_to,
                                           bool *promising);
static inline void html_reassembly(ThreadWork *work,
                                   CarveInfo **candidate,
                                   uuid_string_t uuidp,
                                   uuid_string_t uuidc);
static inline XXH128_hash_t html_search_view_hash(CarveInfo *candidate);
static inline bool html_search_choices_available(const HtmlCarveState *state);
static inline bool html_checkpoint_search(ThreadWork *work,
                                          CarveInfo *candidate,
                                          HtmlCarveState *state,
                                          uuid_string_t uuidp,
                                          uuid_string_t uuidc);
static inline bool html_serialize_carve_state(void **state, FILE *fp,
                                              StateSerialization mode);
static inline void *html_clone_carve_state(const void *state);
static inline void html_free_carve_state(void **state);
static inline size_t html_sizeof_carve_state(const void *state);
static inline void html_print_carve_state(const void *state);

static inline bool html_ascii_equal_ci(const uint8_t *data, uint64_t length,
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

static inline bool html_ascii_starts_ci(const uint8_t *data, uint64_t length,
                                        const char *literal) {
  const uint64_t literal_length = literal ? strlen(literal) : 0;

  return literal_length <= length
      && html_ascii_equal_ci(data, literal_length, literal);
}

static inline bool html_name_is(const char *name, uint32_t length,
                                const char *literal) {
  return name && html_ascii_equal_ci((const uint8_t *)name, length, literal);
}

static inline bool html_invalid_control(uint8_t value) {
  return value == 0 || value == 0x7f
      || (value < 0x20 && value != '\t' && value != '\r'
          && value != '\n' && value != '\f');
}

static inline bool html_recognized_tag(const char *name, uint32_t length) {
  static const char *const names[] = {
      "a", "abbr", "address", "area", "article", "aside", "audio",
      "b", "base", "bdi", "bdo", "blockquote", "body", "br",
      "button", "canvas", "caption", "center", "cite", "code", "col",
      "colgroup", "data", "datalist", "dd", "del", "details", "dfn",
      "dialog", "dir", "div", "dl", "dt", "em", "embed", "fieldset",
      "figcaption", "figure", "font", "footer", "form", "frame",
      "frameset", "h1", "h2", "h3", "h4", "h5", "h6", "head", "header",
      "hgroup", "hr", "html", "i", "iframe", "img", "input", "ins",
      "kbd", "label", "legend", "li", "link", "main", "map", "mark",
      "marquee", "menu", "meta", "meter", "nav", "nobr", "noframes",
      "noscript", "object", "ol", "optgroup", "option", "output", "p",
      "param", "picture", "plaintext", "pre", "progress", "q", "rp",
      "rt", "ruby", "s", "samp", "script", "search", "section", "select",
      "slot", "small", "source", "span", "strike", "strong", "style",
      "sub", "summary", "sup", "table", "tbody", "td", "template",
      "textarea", "tfoot", "th", "thead", "time", "title", "tr", "track",
      "tt", "u", "ul", "var", "video", "wbr", "xmp"};

  for (uint64_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
    if (html_name_is(name, length, names[i])) {
      return true;
    }
  }
  return false;
}

static inline bool html_document_prefix(const uint8_t *data, uint64_t length,
                                        uint64_t *marker_offset) {
  uint64_t offset = 0;
  const uint64_t limit = length < HTML_PREFIX_WINDOW
                             ? length : HTML_PREFIX_WINDOW;

  if (marker_offset) {
    *marker_offset = 0;
  }
  if (!data || length == 0) {
    return false;
  }
  if (limit >= 3 && data[0] == 0xef && data[1] == 0xbb
      && data[2] == 0xbf) {
    offset = 3;
  }
  while (offset < limit && isspace((unsigned char)data[offset])) {
    offset++;
  }

  if (html_ascii_starts_ci(data + offset, limit - offset, "<?xml")) {
    const uint8_t *end = (const uint8_t *)memchr(data + offset, '>',
                                                 (size_t)(limit - offset));
    if (!end) {
      return false;
    }
    offset = (uint64_t)(end - data) + 1;
    while (offset < limit && isspace((unsigned char)data[offset])) {
      offset++;
    }
  }

  if (html_ascii_starts_ci(data + offset, limit - offset, "<!doctype")
      || html_ascii_starts_ci(data + offset, limit - offset, "<html")) {
    if (marker_offset) {
      *marker_offset = offset;
    }
    return true;
  }
  return false;
}

static inline HtmlLineStyle html_initial_line_style(const uint8_t *data,
                                                    uint64_t length,
                                                    uint32_t blocksize) {
  uint64_t counts[4] = {0};
  const uint64_t sample = length < (uint64_t)blocksize * 2
                              ? length : (uint64_t)blocksize * 2;

  for (uint64_t i = 0; i < sample; i++) {
    if (data[i] == '\r') {
      if (i + 1 < sample && data[i + 1] == '\n') {
        counts[HTML_LINE_CRLF]++;
        i++;
      }
      else {
        counts[HTML_LINE_CR]++;
      }
    }
    else if (data[i] == '\n') {
      counts[HTML_LINE_LF]++;
    }
  }

  uint64_t total = counts[HTML_LINE_LF] + counts[HTML_LINE_CRLF]
                   + counts[HTML_LINE_CR];
  if (total < 4) {
    return HTML_LINE_UNKNOWN;
  }
  for (uint32_t style = HTML_LINE_LF; style <= HTML_LINE_CR; style++) {
    if (counts[style] * 10 >= total * 9) {
      return (HtmlLineStyle)style;
    }
  }
  return HTML_LINE_UNKNOWN;
}

static inline bool html_block_line_style_conflicts(
    const uint8_t *data, uint64_t length, HtmlLineStyle preferred) {
  uint64_t counts[4] = {0};

  if (preferred == HTML_LINE_UNKNOWN) {
    return false;
  }
  for (uint64_t i = 0; i < length; i++) {
    if (data[i] == '\r') {
      if (i + 1 < length && data[i + 1] == '\n') {
        counts[HTML_LINE_CRLF]++;
        i++;
      }
      else {
        counts[HTML_LINE_CR]++;
      }
    }
    else if (data[i] == '\n') {
      counts[HTML_LINE_LF]++;
    }
  }

  const uint64_t total = counts[HTML_LINE_LF] + counts[HTML_LINE_CRLF]
                         + counts[HTML_LINE_CR];
  return total >= 4 && counts[preferred] == 0;
}

static inline uint64_t html_trailing_linebreak_extent(const uint8_t *data,
                                                      uint64_t length,
                                                      uint64_t offset,
                                                      HtmlLineStyle preferred) {
  while (offset < length) {
    if (preferred == HTML_LINE_CRLF) {
      if (offset + 1 >= length || data[offset] != '\r'
          || data[offset + 1] != '\n') {
        break;
      }
      offset += 2;
    }
    else if (preferred == HTML_LINE_CR) {
      if (data[offset] != '\r') {
        break;
      }
      offset++;
    }
    else if (preferred == HTML_LINE_LF) {
      if (data[offset] != '\n') {
        break;
      }
      offset++;
    }
    else if (data[offset] == '\n') {
      offset++;
    }
    else if (offset + 1 < length && data[offset] == '\r'
             && data[offset + 1] == '\n') {
      offset += 2;
    }
    else {
      break;
    }
  }
  return offset;
}

static inline bool html_find_terminal(const uint8_t *data, uint64_t length,
                                      uint64_t start, uint64_t *marker,
                                      uint64_t *extent) {
  if (!data || start > length) {
    return false;
  }

  for (uint64_t position = start; position + 7 <= length; position++) {
    if (!html_ascii_starts_ci(data + position, length - position,
                              "</html")) {
      continue;
    }
    uint64_t cursor = position + 6;
    while (cursor < length && isspace((unsigned char)data[cursor])) {
      cursor++;
    }
    if (cursor >= length || data[cursor] != '>') {
      continue;
    }
    if (marker) {
      *marker = position;
    }
    if (extent) {
      *extent = html_trailing_linebreak_extent(
          data, length, cursor + 1, HTML_LINE_UNKNOWN);
    }
    return true;
  }
  return false;
}

static inline HtmlParseResult html_parse(const uint8_t *data, uint64_t length,
                                         uint32_t blocksize,
                                         HtmlParseSummary *summary) {
  char raw_element[HTML_TAG_NAME_MAX] = {0};
  uint32_t raw_length = 0;
  uint64_t marker_offset = 0;
  uint64_t offset = 0;

  if (!summary) {
    return HTML_PARSE_INVALID;
  }
  memset(summary, 0, sizeof(*summary));
  if (!html_document_prefix(data, length, &marker_offset)) {
    return HTML_PARSE_INVALID;
  }
  summary->line_style = html_initial_line_style(data, length, blocksize);

  while (offset < length) {
    if (blocksize > 0 && offset >= (uint64_t)blocksize * 2
        && offset % blocksize == 0
        && html_block_line_style_conflicts(
               data + offset,
               length - offset < blocksize ? length - offset : blocksize,
               summary->line_style)) {
      summary->failure_offset = offset;
      summary->parsed_extent = offset;
      return HTML_PARSE_PARTIAL;
    }

    const uint8_t c = data[offset];
    if (html_invalid_control(c)) {
      summary->failure_offset = offset;
      summary->parsed_extent = offset;
      return HTML_PARSE_PARTIAL;
    }
    if (c != '<') {
      summary->text_bytes++;
      offset++;
      continue;
    }

    if (raw_length > 0) {
      if (offset + raw_length + 3 <= length && data[offset + 1] == '/'
          && html_ascii_equal_ci(data + offset + 2, raw_length,
                                 raw_element)) {
        uint64_t cursor = offset + 2 + raw_length;
        while (cursor < length && isspace((unsigned char)data[cursor])) {
          cursor++;
        }
        if (cursor < length && data[cursor] == '>') {
          raw_length = 0;
        }
      }
      if (raw_length > 0) {
        summary->text_bytes++;
        offset++;
        continue;
      }
    }

    if (offset + 4 <= length
        && memcmp(data + offset, "<!--", 4) == 0) {
      uint64_t cursor = offset + 4;
      while (cursor + 3 <= length
             && memcmp(data + cursor, "-->", 3) != 0) {
        if (html_invalid_control(data[cursor])) {
          summary->failure_offset = cursor;
          summary->parsed_extent = cursor;
          return HTML_PARSE_PARTIAL;
        }
        cursor++;
      }
      if (cursor + 3 > length) {
        summary->failure_offset = offset;
        summary->parsed_extent = offset;
        summary->needs_more_data = true;
        return HTML_PARSE_PARTIAL;
      }
      summary->comments++;
      summary->tags++;
      offset = cursor + 3;
      continue;
    }

    if (offset + 2 <= length && (data[offset + 1] == '!'
                                  || data[offset + 1] == '?')) {
      const bool doctype = html_ascii_starts_ci(data + offset,
                                                length - offset,
                                                "<!doctype");
      if (doctype && summary->declarations > 0) {
        summary->failure_offset = offset;
        summary->parsed_extent = offset;
        return HTML_PARSE_PARTIAL;
      }
      uint8_t quote = 0;
      uint64_t cursor = offset + 2;
      for (; cursor < length; cursor++) {
        if (html_invalid_control(data[cursor])) {
          summary->failure_offset = cursor;
          summary->parsed_extent = cursor;
          return HTML_PARSE_PARTIAL;
        }
        if (quote != 0) {
          if (data[cursor] == quote) {
            quote = 0;
          }
        }
        else if (data[cursor] == '\'' || data[cursor] == '"') {
          quote = data[cursor];
        }
        else if (data[cursor] == '>') {
          break;
        }
      }
      if (cursor >= length) {
        summary->failure_offset = offset;
        summary->parsed_extent = offset;
        summary->needs_more_data = true;
        return HTML_PARSE_PARTIAL;
      }
      summary->declarations++;
      summary->tags++;
      offset = cursor + 1;
      continue;
    }

    uint64_t cursor = offset + 1;
    bool closing = false;
    if (cursor < length && data[cursor] == '/') {
      closing = true;
      cursor++;
    }
    while (cursor < length && isspace((unsigned char)data[cursor])) {
      cursor++;
    }
    const uint64_t name_start = cursor;
    while (cursor < length
           && (isalnum((unsigned char)data[cursor]) || data[cursor] == ':'
               || data[cursor] == '-' || data[cursor] == '_')) {
      cursor++;
    }
    const uint64_t name_length64 = cursor - name_start;
    if (name_length64 == 0 || name_length64 >= HTML_TAG_NAME_MAX) {
      summary->text_bytes++;
      offset++;
      continue;
    }

    uint8_t quote = 0;
    bool self_closing = false;
    uint64_t tag_end = cursor;
    for (; tag_end < length; tag_end++) {
      if (html_invalid_control(data[tag_end])) {
        summary->failure_offset = tag_end;
        summary->parsed_extent = tag_end;
        return HTML_PARSE_PARTIAL;
      }
      if (quote != 0) {
        if (data[tag_end] == quote) {
          quote = 0;
        }
      }
      else if (data[tag_end] == '\'' || data[tag_end] == '"') {
        quote = data[tag_end];
      }
      else if (data[tag_end] == '>') {
        uint64_t back = tag_end;
        while (back > cursor && isspace((unsigned char)data[back - 1])) {
          back--;
        }
        self_closing = back > cursor && data[back - 1] == '/';
        break;
      }
    }
    if (tag_end >= length) {
      summary->failure_offset = offset;
      summary->parsed_extent = offset;
      summary->needs_more_data = true;
      return HTML_PARSE_PARTIAL;
    }

    const uint32_t name_length = (uint32_t)name_length64;
    char name[HTML_TAG_NAME_MAX];
    for (uint32_t i = 0; i < name_length; i++) {
      name[i] = (char)tolower((unsigned char)data[name_start + i]);
    }
    name[name_length] = '\0';

    if (!closing && html_name_is(name, name_length, "html")) {
      if (summary->saw_html_open) {
        summary->failure_offset = offset;
        summary->parsed_extent = offset;
        return HTML_PARSE_PARTIAL;
      }
      summary->saw_html_open = true;
    }
    if (html_name_is(name, name_length, "head")) {
      summary->saw_head = true;
    }
    else if (html_name_is(name, name_length, "body")) {
      summary->saw_body = true;
    }
    else if (html_name_is(name, name_length, "title")) {
      summary->saw_title = true;
    }

    summary->tags++;
    if (closing) {
      summary->closing_tags++;
    }
    else {
      summary->opening_tags++;
    }
    if (html_recognized_tag(name, name_length)) {
      summary->recognized_tags++;
    }

    offset = tag_end + 1;
    if (closing && html_name_is(name, name_length, "html")) {
      summary->saw_terminal = true;
      summary->terminal_extent = html_trailing_linebreak_extent(
          data, length, offset, summary->line_style);
      summary->parsed_extent = summary->terminal_extent;
      summary->failure_offset = summary->terminal_extent;
      if (summary->tags >= 3 && summary->recognized_tags >= 2
          && (summary->saw_head || summary->saw_body
              || summary->saw_title)) {
        return HTML_PARSE_COMPLETE;
      }
      return HTML_PARSE_INVALID;
    }

    if (!closing && !self_closing
        && (html_name_is(name, name_length, "script")
            || html_name_is(name, name_length, "style")
            || html_name_is(name, name_length, "textarea")
            || html_name_is(name, name_length, "xmp"))) {
      memcpy(raw_element, name, name_length + 1);
      raw_length = name_length;
    }
  }

  summary->parsed_extent = length;
  summary->failure_offset = length;
  return summary->tags >= 2 && summary->recognized_tags >= 1
             ? HTML_PARSE_PARTIAL : HTML_PARSE_INVALID;
}

static inline HtmlBlockEvidence html_block_evidence(const uint8_t *data,
                                                    uint64_t length) {
  HtmlBlockEvidence evidence = {0};

  if (!data || length == 0) {
    return evidence;
  }
  evidence.document_prefix = html_document_prefix(data, length, NULL);
  for (uint64_t i = 0; i < length; i++) {
    const uint8_t c = data[i];
    if (html_invalid_control(c)) {
      evidence.invalid_controls++;
    }
    else if (isspace((unsigned char)c)) {
      evidence.whitespace_bytes++;
    }
    else {
      evidence.text_bytes++;
      if (c >= 0x80) {
        evidence.high_bytes++;
      }
    }

    if (c == '<' && i + 2 < length) {
      uint64_t cursor = i + 1;
      if (data[cursor] == '/') {
        cursor++;
      }
      while (cursor < length && isspace((unsigned char)data[cursor])) {
        cursor++;
      }
      const uint64_t start = cursor;
      while (cursor < length
             && (isalnum((unsigned char)data[cursor])
                 || data[cursor] == ':' || data[cursor] == '-')) {
        cursor++;
      }
      if (cursor > start && cursor - start < HTML_TAG_NAME_MAX) {
        evidence.tags++;
        if (html_recognized_tag((const char *)data + start,
                                (uint32_t)(cursor - start))) {
          evidence.recognized_tags++;
        }
      }
    }
  }
  return evidence;
}

static inline char *html_header_discovery(char *base, uint64_t offset,
                                          uint64_t remaining,
                                          char **matchpos,
                                          uint32_t *matchlen,
                                          uint32_t blocksize) {
  if (!base || !matchpos || !matchlen || blocksize == 0) {
    return NULL;
  }
  *matchpos = NULL;
  *matchlen = 1;

  uint64_t position = CEILDIV(offset, blocksize) * blocksize;
  const uint64_t end = offset + remaining;
  while (position < end) {
    const uint64_t available = end - position;
    if (html_document_prefix((const uint8_t *)base + position,
                             available, NULL)) {
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

static inline char *html_footer_discovery(char *base, uint64_t offset,
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

  const uint8_t *data = (const uint8_t *)base;
  const uint64_t end = offset + remaining;
  uint64_t position = 0;
  uint64_t terminal_extent = 0;
  if (html_find_terminal(data, end, offset, &position, &terminal_extent)) {
    if (terminal_extent - position <= UINT32_MAX) {
      *matchpos = base + position;
      *matchlen = (uint32_t)(terminal_extent - position);
    }
  }
  return NULL;
}

static inline uint32_t html_block_validate(
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

  uint64_t evidence_length = length;
  uint64_t terminal_extent = 0;
  if (html_find_terminal((const uint8_t *)data, length, 0, NULL,
                         &terminal_extent)) {
    evidence_length = terminal_extent;
  }
  const HtmlBlockEvidence evidence = html_block_evidence(
      (const uint8_t *)data, evidence_length);
  *validates_to = evidence_length - 1;
  if (evidence.invalid_controls > 0
      && evidence.invalid_controls * 256 > evidence_length) {
    *decision = BLOCK_CONFIDENCE_INVALID;
    *validates_to = 0;
    return needleidx;
  }

  uint32_t confidence = (uint32_t)*decision;
  if (evidence.document_prefix || evidence.recognized_tags >= 3) {
    confidence = BLOCK_CONFIDENCE_VALID;
  }
  else if (evidence.recognized_tags > 0) {
    if (confidence < 85) {
      confidence = 85;
    }
  }
  else if (evidence.text_bytes >= evidence_length / 2
           && evidence.invalid_controls == 0) {
    if (confidence < HTML_TAGLESS_TEXT_CONFIDENCE) {
      confidence = HTML_TAGLESS_TEXT_CONFIDENCE;
    }
  }
  else if (confidence == BLOCK_CONFIDENCE_INVALID) {
    confidence = BLOCK_CONFIDENCE_LOW;
  }
  *decision = (BlockValidationDecision)confidence;
  return needleidx;
}

static inline void html_file_validate(char *data, uint64_t length,
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
  if (!data || length < HTML_MINIMUM_SIZE) {
    return;
  }

  HtmlParseSummary summary;
  const HtmlParseResult result = html_parse((const uint8_t *)data, length,
                                            blocksize, &summary);
  if (result == HTML_PARSE_COMPLETE
      && summary.terminal_extent >= HTML_MINIMUM_SIZE) {
    *validates = true;
    *validates_to = summary.terminal_extent - 1;
    return;
  }
  if (result == HTML_PARSE_INVALID || summary.parsed_extent == 0) {
    return;
  }

  uint64_t extent = summary.parsed_extent;
  if (summary.failure_offset < length && blocksize > 0) {
    extent = (summary.failure_offset / blocksize) * blocksize;
  }
  if (extent == 0) {
    return;
  }
  *validates_to = extent - 1;
  *promising = summary.tags >= 2 && summary.recognized_tags >= 1;
}

static inline void html_candidate_validate(CarveInfo *candidate,
                                           bool *validates,
                                           uint64_t *validates_to,
                                           bool *promising) {
  (void)validates_to;
  if (!candidate || !candidate->b || !validates || !promising
      || !*validates) {
    return;
  }

  // A complete HTML document can be an embedded MIME or container payload.
  // Syntax establishes useful content and extent, but not standalone origin.
  *validates = false;
  *promising = true;
}

static inline bool html_actual_block_is_tagless_text(int64_t actual) {
  if (actual < 0) {
    return false;
  }

  uint64_t length = 0;
  const uint8_t *data = (const uint8_t *)
      filemirror_actual_block_data_pointer(scalpel_state.filemirror,
                                           actual, &length);
  if (!data || length == 0) {
    return false;
  }

  const HtmlBlockEvidence evidence = html_block_evidence(data, length);
  return !evidence.document_prefix && evidence.invalid_controls == 0
      && evidence.recognized_tags == 0
      && (evidence.text_bytes + evidence.whitespace_bytes) * 10
             >= length * 9;
}

static inline uint64_t html_longest_tagless_run(const BlockVector *blockvector,
                                                uint64_t blocks) {
  uint64_t longest = 0;
  uint64_t current = 0;

  if (!blockvector) {
    return 0;
  }
  for (uint64_t slot = 0; slot < blocks; slot++) {
    const int64_t actual = blockvector_get_actual_blocknumber(
        (BlockVector *)blockvector, slot);
    if (html_actual_block_is_tagless_text(actual)) {
      current++;
      if (current > longest) {
        longest = current;
      }
    }
    else {
      current = 0;
    }
  }
  return longest;
}

static inline uint64_t html_suspicious_prefix_cut(
    const BlockVector *blockvector, uint64_t blocks, uint32_t needleidx) {
  uint64_t segment_start = blocks;
  uint64_t run_length = 0;
  uint64_t low_confidence_start = blocks;
  uint64_t low_confidence_length = 0;

  if (!blockvector || blocks <= HTML_SUSPICIOUS_TAGLESS_BLOCKS + 2) {
    return blocks;
  }
  int64_t previous = blockvector_get_actual_blocknumber(
      (BlockVector *)blockvector, 0);
  for (uint64_t slot = 1; slot < blocks; slot++) {
    const int64_t actual = blockvector_get_actual_blocknumber(
        (BlockVector *)blockvector, slot);
    const bool tagless = html_actual_block_is_tagless_text(actual);
    if (previous < 0 || actual != previous + 1) {
      segment_start = slot;
      run_length = 0;
    }
    previous = actual;
    if (segment_start == blocks || slot < 2) {
      run_length = 0;
    }
    else if (tagless) {
      run_length++;
      if (run_length >= HTML_SUSPICIOUS_TAGLESS_BLOCKS) {
        return segment_start;
      }
    }
    else {
      run_length = 0;
    }

    const uint32_t confidence = actual >= 0
        ? filemirror_get_blocktype(scalpel_state.filemirror, actual,
                                   needleidx)
        : BLOCK_CONFIDENCE_INVALID;
    if (slot >= 2 && confidence <= HTML_TAGLESS_TEXT_CONFIDENCE
        && tagless) {
      if (low_confidence_length == 0) {
        low_confidence_start = slot;
      }
      low_confidence_length++;
    }
    else {
      low_confidence_start = blocks;
      low_confidence_length = 0;
    }
  }
  if (low_confidence_length >= HTML_SUSPICIOUS_TAGLESS_BLOCKS) {
    return low_confidence_start;
  }
  return blocks;
}

static inline bool html_restore_prefix(CarveInfo *candidate,
                                       uint64_t blocks) {
  if (!candidate || !candidate->b || blocks == 0
      || scalpel_state.blocksize == 0) {
    return false;
  }
  resize_blockvector(candidate->b, blocks);
  blockvector_set_data_length(candidate->b,
                              blocks * (uint64_t)scalpel_state.blocksize);
  inflate_blockvector(candidate->b);
  return true;
}

static inline bool html_actual_block_available(const CarveInfo *candidate,
                                               int64_t actual) {
  if (!candidate || !candidate->b || actual < 0
      || filemirror_actual_block_covered(scalpel_state.filemirror, actual)) {
    return false;
  }

  const int64_t apparent = filemirror_apparent_blocknumber(
      scalpel_state.filemirror, actual);
  return apparent >= 0
      && !apparent_block_in_blockvector(candidate->b, apparent)
      && filemirror_get_blocktype(scalpel_state.filemirror, actual,
                                  candidate->needleidx)
             != BLOCK_CONFIDENCE_INVALID;
}

static inline bool html_actual_block_line_conflicts(int64_t actual,
                                                    HtmlLineStyle preferred) {
  if (actual < 0 || preferred == HTML_LINE_UNKNOWN) {
    return false;
  }

  uint64_t length = 0;
  const uint8_t *data = (const uint8_t *)
      filemirror_actual_block_data_pointer(scalpel_state.filemirror,
                                           actual, &length);
  return data && length > 0
      && html_block_line_style_conflicts(data, length, preferred);
}

static inline bool html_run_start(const CarveInfo *candidate,
                                  int64_t actual, int64_t previous_selected,
                                  HtmlLineStyle preferred) {
  if (!html_actual_block_available(candidate, actual)) {
    return false;
  }

  uint64_t length = 0;
  const uint8_t *data = (const uint8_t *)
      filemirror_actual_block_data_pointer(scalpel_state.filemirror,
                                           actual, &length);
  if (!data || length == 0 || html_document_prefix(data, length, NULL)
      || html_actual_block_line_conflicts(actual, preferred)) {
    return false;
  }
  if (previous_selected >= 0 && actual == previous_selected + 1) {
    return true;
  }
  if (actual == 0 || !html_actual_block_available(candidate, actual - 1)) {
    return true;
  }
  uint64_t previous_length = 0;
  const uint8_t *previous_data = (const uint8_t *)
      filemirror_actual_block_data_pointer(scalpel_state.filemirror,
                                           actual - 1,
                                           &previous_length);
  if (previous_data && previous_length > 0
      && html_find_terminal(previous_data, previous_length, 0,
                            NULL, NULL)) {
    return true;
  }
  return html_actual_block_line_conflicts(actual - 1, preferred);
}

static inline uint64_t html_available_run(const CarveInfo *candidate,
                                          int64_t first_actual,
                                          HtmlLineStyle preferred) {
  if (!candidate || !candidate->b || first_actual < 0
      || scalpel_state.blocksize == 0) {
    return 0;
  }

  const uint64_t prefix_length = blockvector_get_data_length(candidate->b);
  const uint64_t maximum_size = scalpel_state.search_specs[
      candidate->needleidx].MAXIMUMSIZE;
  if (prefix_length >= maximum_size) {
    return 0;
  }

  uint64_t maximum_blocks = (maximum_size - prefix_length)
                            / scalpel_state.blocksize;
  uint64_t window_blocks = HTML_TRIAL_WINDOW_BYTES / scalpel_state.blocksize;
  if (window_blocks == 0) {
    window_blocks = 1;
  }
  if (maximum_blocks > window_blocks) {
    maximum_blocks = window_blocks;
  }

  const uint64_t image_blocks = CEILDIV(
      filemirror_filesize(scalpel_state.filemirror), scalpel_state.blocksize);
  uint64_t blocks = 0;
  while (blocks < maximum_blocks
         && (uint64_t)first_actual + blocks < image_blocks) {
    const int64_t actual = first_actual + (int64_t)blocks;
    if (!html_actual_block_available(candidate, actual)
        || html_actual_block_line_conflicts(actual, preferred)) {
      break;
    }

    uint64_t length = 0;
    const uint8_t *data = (const uint8_t *)
        filemirror_actual_block_data_pointer(scalpel_state.filemirror,
                                             actual, &length);
    if (!data || length == 0
        || (blocks > 0 && html_document_prefix(data, length, NULL))) {
      break;
    }
    blocks++;
  }
  return blocks;
}

static inline bool html_trial_run(CarveInfo *candidate,
                                  uint64_t prefix_blocks,
                                  int64_t first_actual,
                                  HtmlLineStyle preferred,
                                  HtmlRunEvaluation *evaluation) {
  if (!candidate || !candidate->b || !evaluation
      || !html_restore_prefix(candidate, prefix_blocks)) {
    return false;
  }
  memset(evaluation, 0, sizeof(*evaluation));

  const uint64_t run_blocks = html_available_run(candidate, first_actual,
                                                 preferred);
  if (run_blocks == 0 || prefix_blocks > UINT64_MAX - run_blocks) {
    return false;
  }

  resize_blockvector(candidate->b, prefix_blocks + run_blocks);
  for (uint64_t block = 0; block < run_blocks; block++) {
    const int64_t apparent = filemirror_apparent_blocknumber(
        scalpel_state.filemirror, first_actual + (int64_t)block);
    if (apparent < 0) {
      html_restore_prefix(candidate, prefix_blocks);
      return false;
    }
    blockvector_set_apparent_blocknumber(candidate->b,
                                         prefix_blocks + block,
                                         apparent);
  }
  blockvector_set_data_length(
      candidate->b, (prefix_blocks + run_blocks)
                        * (uint64_t)scalpel_state.blocksize);
  inflate_blockvector(candidate->b);

  HtmlParseSummary summary;
  const HtmlParseResult result = html_parse(
      (const uint8_t *)blockvector_get_data_pointer(candidate->b),
      blockvector_get_data_length(candidate->b), scalpel_state.blocksize,
      &summary);
  uint64_t total_blocks = prefix_blocks;
  uint64_t extent = prefix_blocks * (uint64_t)scalpel_state.blocksize;
  bool complete = false;

  if (result == HTML_PARSE_COMPLETE
      && summary.terminal_extent > extent) {
    total_blocks = CEILDIV(summary.terminal_extent,
                           scalpel_state.blocksize);
    extent = summary.terminal_extent;
    complete = true;
  }
  else if (result == HTML_PARSE_PARTIAL && summary.needs_more_data) {
    total_blocks = prefix_blocks + run_blocks;
    extent = total_blocks * (uint64_t)scalpel_state.blocksize;
  }
  else if (summary.parsed_extent > extent) {
    total_blocks = summary.parsed_extent / scalpel_state.blocksize;
    extent = total_blocks * (uint64_t)scalpel_state.blocksize;
  }

  if (total_blocks <= prefix_blocks
      || total_blocks > prefix_blocks + run_blocks) {
    html_restore_prefix(candidate, prefix_blocks);
    return false;
  }

  resize_blockvector(candidate->b, total_blocks);
  blockvector_set_data_length(candidate->b, extent);
  inflate_blockvector(candidate->b);

  const int64_t previous = blockvector_get_actual_blocknumber(
      candidate->b, prefix_blocks - 1);
  const uint64_t distance = previous >= 0
      ? ((uint64_t)first_actual > (uint64_t)previous
             ? (uint64_t)first_actual - (uint64_t)previous
             : (uint64_t)previous - (uint64_t)first_actual)
      : UINT64_MAX;

  evaluation->found = true;
  evaluation->complete = complete;
  evaluation->prefix_blocks = prefix_blocks;
  evaluation->first_actual = first_actual;
  evaluation->run_blocks = total_blocks - prefix_blocks;
  evaluation->extent = extent;
  evaluation->total_blocks = total_blocks;
  evaluation->longest_tagless_run = html_longest_tagless_run(
      candidate->b, total_blocks);
  evaluation->distance = distance;

  html_restore_prefix(candidate, prefix_blocks);
  return true;
}

static inline bool html_evaluation_is_better(
    const HtmlRunEvaluation *candidate,
    const HtmlRunEvaluation *best) {
  if (!candidate || !candidate->found) {
    return false;
  }
  if (!best || !best->found) {
    return true;
  }
  if (candidate->complete != best->complete) {
    return candidate->complete;
  }
  if (candidate->complete) {
    if (candidate->distance != best->distance) {
      return candidate->distance < best->distance;
    }
    if (candidate->longest_tagless_run != best->longest_tagless_run) {
      return candidate->longest_tagless_run < best->longest_tagless_run;
    }
    if (candidate->total_blocks != best->total_blocks) {
      return candidate->total_blocks > best->total_blocks;
    }
  }
  else {
    if (candidate->distance != best->distance) {
      return candidate->distance < best->distance;
    }
    if (candidate->total_blocks != best->total_blocks) {
      return candidate->total_blocks > best->total_blocks;
    }
  }
  if (candidate->distance != best->distance) {
    return candidate->distance < best->distance;
  }
  return candidate->first_actual < best->first_actual;
}

static inline bool html_commit_evaluation(
    CarveInfo *candidate, const HtmlRunEvaluation *evaluation) {
  if (!candidate || !candidate->b || !evaluation || !evaluation->found
      || !html_restore_prefix(candidate, evaluation->prefix_blocks)) {
    return false;
  }
  resize_blockvector(candidate->b, evaluation->total_blocks);
  if (evaluation->run_blocks > 0) {
    for (uint64_t block = 0; block < evaluation->run_blocks; block++) {
      const int64_t apparent = filemirror_apparent_blocknumber(
          scalpel_state.filemirror,
          evaluation->first_actual + (int64_t)block);
      if (apparent < 0) {
        html_restore_prefix(candidate, evaluation->prefix_blocks);
        return false;
      }
      blockvector_set_apparent_blocknumber(
          candidate->b, evaluation->prefix_blocks + block, apparent);
    }
  }
  inflate_blockvector(candidate->b);
  blockvector_set_data_length(candidate->b, evaluation->extent);
  return true;
}

static inline bool html_evaluations_match(const HtmlRunEvaluation *left,
                                          const HtmlRunEvaluation *right) {
  return left && right && left->found && right->found
      && left->prefix_blocks == right->prefix_blocks
      && left->first_actual == right->first_actual
      && left->run_blocks == right->run_blocks
      && left->extent == right->extent;
}

// HTML cannot establish the provenance of arbitrary prose. When a long
// tagless run creates two complete structural interpretations, preserve the
// alternate as PROMISING rather than discarding either defensible mapping.
static inline bool html_write_evaluation_hypothesis(
    CarveInfo *candidate, const HtmlRunEvaluation *evaluation) {
  if (!candidate || !candidate->b || !evaluation || !evaluation->complete
      || !scalpel_state.write_promising) {
    return false;
  }

  BlockVector *parent = candidate->b;
  BlockVector *hypothesis = NULL;
  const CarveInfoFlavor parent_flavor = candidate->flavor;
  const bool parent_chopped = candidate->chopped;
  const uint64_t parent_validates_to = candidate->best_validates_to;

  clone_blockvector(parent, &hypothesis, false);
  candidate->b = hypothesis;
  const bool committed = html_commit_evaluation(candidate, evaluation);
  if (committed) {
    candidate->flavor = PROMISING;
    candidate->chopped = false;
    candidate->best_validates_to = evaluation->extent - 1;
    CarveInfo *preserved = candidate;
    write_candidate(&preserved, true);
  }

  candidate->b = parent;
  candidate->flavor = parent_flavor;
  candidate->chopped = parent_chopped;
  candidate->best_validates_to = parent_validates_to;
  free_blockvector(&hypothesis);
  return committed;
}

// Test a displaced run in the physical hole immediately before a suffix.
// Neither run needs to parse independently: the combined document supplies
// the structural evidence. Preserve each complete reconstruction as PROMISING
// because HTML syntax cannot establish which same-type run occupied the hole.
static inline bool html_write_displaced_hypothesis(
    CarveInfo *candidate, const HtmlRunEvaluation *displaced,
    const HtmlRunEvaluation *suffix) {
  if (!candidate || !candidate->b || !displaced || !suffix
      || !displaced->found || !suffix->found
      || displaced->prefix_blocks != suffix->prefix_blocks
      || displaced->run_blocks == 0 || suffix->run_blocks == 0
      || displaced->first_actual < 0 || suffix->first_actual < 0
      || !scalpel_state.write_promising || scalpel_state.blocksize == 0) {
    return false;
  }

  const uint64_t prefix_blocks = suffix->prefix_blocks;
  const int64_t previous = blockvector_get_actual_blocknumber(
      candidate->b, prefix_blocks - 1);
  if (previous < 0 || suffix->first_actual <= previous + 1) {
    return false;
  }
  const uint64_t hole_blocks = (uint64_t)(suffix->first_actual - previous - 1);
  if (displaced->run_blocks != hole_blocks
      || (displaced->first_actual < suffix->first_actual +
              (int64_t)suffix->run_blocks
          && displaced->first_actual + (int64_t)displaced->run_blocks
                 > suffix->first_actual)
      || prefix_blocks > UINT64_MAX - displaced->run_blocks
      || prefix_blocks + displaced->run_blocks
             > UINT64_MAX - suffix->run_blocks) {
    return false;
  }

  const uint64_t total_blocks = prefix_blocks + displaced->run_blocks
                                + suffix->run_blocks;
  if (total_blocks > UINT64_MAX / scalpel_state.blocksize
      || total_blocks * (uint64_t)scalpel_state.blocksize
             > scalpel_state.search_specs[candidate->needleidx].MAXIMUMSIZE) {
    return false;
  }

  BlockVector *parent = candidate->b;
  BlockVector *hypothesis = NULL;
  const CarveInfoFlavor parent_flavor = candidate->flavor;
  const bool parent_chopped = candidate->chopped;
  const uint64_t parent_validates_to = candidate->best_validates_to;

  clone_blockvector(parent, &hypothesis, false);
  candidate->b = hypothesis;
  bool assembled = html_restore_prefix(candidate, prefix_blocks);
  if (assembled) {
    resize_blockvector(hypothesis, total_blocks);
    for (uint64_t block = 0; block < displaced->run_blocks; block++) {
      const int64_t apparent = filemirror_apparent_blocknumber(
          scalpel_state.filemirror,
          displaced->first_actual + (int64_t)block);
      if (apparent < 0) {
        assembled = false;
        break;
      }
      blockvector_set_apparent_blocknumber(
          hypothesis, prefix_blocks + block, apparent);
    }
  }
  if (assembled) {
    for (uint64_t block = 0; block < suffix->run_blocks; block++) {
      const int64_t apparent = filemirror_apparent_blocknumber(
          scalpel_state.filemirror, suffix->first_actual + (int64_t)block);
      if (apparent < 0) {
        assembled = false;
        break;
      }
      blockvector_set_apparent_blocknumber(
          hypothesis, prefix_blocks + displaced->run_blocks + block,
          apparent);
    }
  }

  bool written = false;
  if (assembled) {
    blockvector_set_data_length(
        hypothesis, total_blocks * (uint64_t)scalpel_state.blocksize);
    inflate_blockvector(hypothesis);

    HtmlParseSummary summary;
    const HtmlParseResult result = html_parse(
        (const uint8_t *)blockvector_get_data_pointer(hypothesis),
        blockvector_get_data_length(hypothesis), scalpel_state.blocksize,
        &summary);
    const uint64_t displaced_end = (prefix_blocks + displaced->run_blocks)
                                   * (uint64_t)scalpel_state.blocksize;
    if (result == HTML_PARSE_COMPLETE
        && summary.terminal_extent > displaced_end
        && summary.terminal_extent
               <= total_blocks * (uint64_t)scalpel_state.blocksize) {
      resize_blockvector(hypothesis,
                         CEILDIV(summary.terminal_extent,
                                 scalpel_state.blocksize));
      inflate_blockvector(hypothesis);
      blockvector_set_data_length(hypothesis, summary.terminal_extent);
      candidate->flavor = PROMISING;
      candidate->chopped = false;
      candidate->best_validates_to = summary.terminal_extent - 1;
      CarveInfo *preserved = candidate;
      write_candidate(&preserved, true);
      written = true;
    }
  }

  candidate->b = parent;
  candidate->flavor = parent_flavor;
  candidate->chopped = parent_chopped;
  candidate->best_validates_to = parent_validates_to;
  free_blockvector(&hypothesis);
  return written;
}

static inline void html_publish_promising(CarveInfo **candidate,
                                          bool complete) {
  if (!candidate || !*candidate) {
    return;
  }
  (*candidate)->flavor = PROMISING;
  (*candidate)->chopped = !complete;
  if (scalpel_state.write_promising) {
    write_candidate(candidate, false);
  }
  else {
    destroy_candidate(candidate);
  }
}

// Identify the committed prefix and available block set without reading image
// bytes. A changed view needs a new search because it can expose new run starts.
// This work is only needed when saving or restoring an interrupted search.
static inline XXH128_hash_t html_search_view_hash(CarveInfo *candidate) {
  XXH3_state_t hash;
  XXH3_128bits_reset(&hash);
  const uint64_t metadata[] = {
      blockvector_get_num_blocks(candidate->b),
      blockvector_get_data_length(candidate->b),
      filemirror_filesize(scalpel_state.filemirror),
      scalpel_state.blocksize};
  XXH3_128bits_update(&hash, metadata, sizeof(metadata));
  int64_t blocks[256];
  for (uint64_t first = 0; first < metadata[0];) {
    uint64_t count = metadata[0] - first;
    if (count > sizeof(blocks) / sizeof(blocks[0])) {
      count = sizeof(blocks) / sizeof(blocks[0]);
    }
    for (uint64_t i = 0; i < count; i++) {
      blocks[i] = blockvector_get_actual_blocknumber(candidate->b, first + i);
    }
    XXH3_128bits_update(&hash, blocks, (size_t)count * sizeof(blocks[0]));
    first += count;
  }
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
  return XXH3_128bits_digest(&hash);
}

// Shadow coverage can change between evaluating a run and saving a checkpoint.
// Do not reuse a retained choice whose blocks have since been claimed.
static inline bool html_search_choices_available(const HtmlCarveState *state) {
  const HtmlRunEvaluation *choices[] = {
      &state->option_best[0], &state->option_best[1], &state->current_best,
      &state->local_continuation, &state->physical_suffix,
      &state->skipped_complete};
  const uint64_t image_blocks = CEILDIV(
      filemirror_filesize(scalpel_state.filemirror), scalpel_state.blocksize);
  for (uint32_t i = 0; i < sizeof(choices) / sizeof(choices[0]); i++) {
    const HtmlRunEvaluation *choice = choices[i];
    if (!choice->found || choice->run_blocks == 0) {
      continue;
    }
    if (choice->first_actual < 0
        || (uint64_t)choice->first_actual >= image_blocks
        || choice->run_blocks > image_blocks - (uint64_t)choice->first_actual) {
      return false;
    }
    for (uint64_t block = 0; block < choice->run_blocks; block++) {
      if (filemirror_actual_block_covered(scalpel_state.filemirror,
                                          choice->first_actual + (int64_t)block)) {
        return false;
      }
    }
  }
  return true;
}

// The caller installs the committed blockvector before transferring ownership
// to the checkpoint helper. A declined request leaves both search and mapping live.
static inline bool html_checkpoint_search(ThreadWork *work,
                                          CarveInfo *candidate,
                                          HtmlCarveState *state,
                                          uuid_string_t uuidp,
                                          uuid_string_t uuidc) {
  if (!atomic_load_explicit(&REASS_RETURN_TO_IDLE, memory_order_acquire)) {
    return false;
  }
  state->view_hash = html_search_view_hash(candidate);
  carve_put_state(candidate->carvehashkey, state);
  return reassembly_time_to_checkpoint(work->id, candidate, uuidp, uuidc);
}

// HTML reassembly preserves physical runs instead of selecting isolated blocks.
// Complete noncontiguous documents remain PROMISING because HTML syntax alone
// cannot authenticate the provenance of arbitrary body text.
static inline void html_reassembly(ThreadWork *work,
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
  HtmlCarveState state = {.magic = HTML_STATE_MAGIC};
  HtmlCarveState *saved = (HtmlCarveState *)carve_get_state(
      (*candidate)->carvehashkey);
  if (saved && saved->magic == HTML_STATE_MAGIC) {
    state.changed = saved->changed;
    const XXH128_hash_t view = html_search_view_hash(*candidate);
    if (XXH128_isEqual(view, saved->view_hash)
        && html_search_choices_available(saved)) {
      state = *saved;
    }
  }
  html_free_carve_state((void **)&saved);

  while (*candidate) {
    BlockVector *blockvector = (*candidate)->b;
    uint64_t base_blocks = blockvector_get_num_blocks(blockvector);
    if (base_blocks == 0) {
      destroy_candidate(candidate);
      return;
    }
    for (uint64_t slot = 0; slot < base_blocks; slot++) {
      if (blockvector_get_actual_blocknumber(blockvector, slot) < 0) {
        base_blocks = slot;
        break;
      }
    }
    if (base_blocks == 0 || !html_restore_prefix(*candidate, base_blocks)) {
      destroy_candidate(candidate);
      return;
    }

    if (reassembly_check_max_size(work->id, *candidate, uuidp, uuidc)) {
      break;
    }
    if (reassembly_check_kill_queue(work, candidate, uuidp, uuidc)) {
      return;
    }
    if (html_checkpoint_search(work, *candidate, &state, uuidp, uuidc)) {
      return;
    }

    if (!state.initialized) {
      state.prefixes[0] = base_blocks;
      state.prefix_count = 1;
      const uint64_t cut = html_suspicious_prefix_cut(
          blockvector, base_blocks, (*candidate)->needleidx);
      if (cut >= 2 && cut < base_blocks) {
        state.prefixes[state.prefix_count++] = cut;
      }
      state.initialized = true;
    }

    HtmlRunEvaluation best = {0};
    const uint64_t image_blocks = CEILDIV(
        filemirror_filesize(scalpel_state.filemirror),
        scalpel_state.blocksize);

    for (; state.option < state.prefix_count; state.option++) {
      const uint64_t prefix_blocks = state.prefixes[state.option];
      BlockVector *option_blockvector = NULL;

      // Alternate-prefix evaluation must not truncate the live candidate.
      // resize_blockvector() deliberately discards mappings beyond a shorter
      // prefix, so perform that speculative work on an isolated clone.
      if (prefix_blocks < base_blocks) {
        clone_blockvector(blockvector, &option_blockvector, false);
        (*candidate)->b = option_blockvector;
      }
      if (!html_restore_prefix(*candidate, prefix_blocks)) {
        if (option_blockvector) {
          (*candidate)->b = blockvector;
          free_blockvector(&option_blockvector);
        }
        continue;
      }

      HtmlParseSummary prefix_summary;
      const HtmlParseResult prefix_result = html_parse(
          (const uint8_t *)blockvector_get_data_pointer((*candidate)->b),
          blockvector_get_data_length((*candidate)->b),
          scalpel_state.blocksize, &prefix_summary);
      if (prefix_result == HTML_PARSE_INVALID) {
        if (option_blockvector) {
          (*candidate)->b = blockvector;
          free_blockvector(&option_blockvector);
        }
        continue;
      }

      if (!state.prepared && prefix_result == HTML_PARSE_COMPLETE) {
        HtmlRunEvaluation existing = {
            .found = true,
            .complete = true,
            .prefix_blocks = prefix_blocks,
            .first_actual = -1,
            .run_blocks = 0,
            .extent = prefix_summary.terminal_extent,
            .total_blocks = CEILDIV(prefix_summary.terminal_extent,
                                    scalpel_state.blocksize),
            .longest_tagless_run = html_longest_tagless_run(
                (*candidate)->b, prefix_blocks),
            .distance = 0};
        if (html_evaluation_is_better(&existing, &state.current_best)) {
          state.current_best = existing;
        }
      }

      const HtmlLineStyle preferred = prefix_summary.line_style;
      const int64_t previous_selected = blockvector_get_actual_blocknumber(
          (*candidate)->b, prefix_blocks - 1);
      if (!state.prepared && previous_selected >= 0
          && (uint64_t)previous_selected + 1 < image_blocks) {
        int64_t local_actual = previous_selected + 1;
        while ((uint64_t)local_actual < image_blocks
               && !html_actual_block_available(*candidate, local_actual)) {
          local_actual++;
        }
        if (local_actual > previous_selected + 1
            && (uint64_t)local_actual < image_blocks
            && html_run_start(*candidate, local_actual, previous_selected,
                              preferred)) {
          const uint64_t local_run_blocks = html_available_run(
              *candidate, local_actual, preferred);
          if (local_run_blocks > 0
              && prefix_blocks <= UINT64_MAX - local_run_blocks) {
            state.physical_suffix.found = true;
            state.physical_suffix.prefix_blocks = prefix_blocks;
            state.physical_suffix.first_actual = local_actual;
            state.physical_suffix.run_blocks = local_run_blocks;
            state.physical_suffix.extent =
                (prefix_blocks + local_run_blocks)
                * (uint64_t)scalpel_state.blocksize;
            state.physical_suffix.total_blocks = prefix_blocks + local_run_blocks;
            state.physical_suffix.distance = (uint64_t)(
                local_actual - previous_selected);
          }
          HtmlRunEvaluation local_trial;
          const bool local_found = html_trial_run(
              *candidate, prefix_blocks, local_actual, preferred,
              &local_trial);
          if (local_found) {
            state.local_continuation = local_trial;
          }
        }
      }
      state.prepared = true;

      for (uint64_t actual_u = state.next_actual;
           actual_u < image_blocks; actual_u++) {
        const int64_t actual = (int64_t)actual_u;
        if (html_run_start(*candidate, actual, previous_selected,
                           preferred)) {
          const uint64_t available_blocks = html_available_run(
              *candidate, actual, preferred);
          if (!state.displaced_done && state.physical_suffix.found
              && actual != state.physical_suffix.first_actual) {
            const uint64_t hole_blocks = (uint64_t)(
                state.physical_suffix.first_actual - previous_selected - 1);
            if (hole_blocks > 0 && available_blocks >= hole_blocks
                && prefix_blocks <= UINT64_MAX - hole_blocks) {
              HtmlRunEvaluation displaced = {
                  .found = true,
                  .complete = false,
                  .prefix_blocks = prefix_blocks,
                  .first_actual = actual,
                  .run_blocks = hole_blocks,
                  .extent = (prefix_blocks + hole_blocks)
                            * (uint64_t)scalpel_state.blocksize,
                  .total_blocks = prefix_blocks + hole_blocks,
                  .longest_tagless_run = 0,
                  .distance = actual > previous_selected
                      ? (uint64_t)(actual - previous_selected)
                      : (uint64_t)(previous_selected - actual)};
              const bool wrote_hypothesis =
                  html_write_displaced_hypothesis(
                      *candidate, &displaced, &state.physical_suffix);
              state.displaced_done = true;
              if (wrote_hypothesis
                  && atomic_load_explicit(&REASS_RETURN_TO_IDLE,
                                          memory_order_acquire)) {
                BlockVector *active_blockvector = (*candidate)->b;
                (*candidate)->b = blockvector;
                if (html_checkpoint_search(work, *candidate, &state,
                                            uuidp, uuidc)) {
                  if (option_blockvector) {
                    free_blockvector(&option_blockvector);
                  }
                  return;
                }
                (*candidate)->b = active_blockvector;
              }
            }
          }
          HtmlRunEvaluation trial;
          if (html_trial_run(*candidate, prefix_blocks, actual,
                             preferred, &trial)) {
            const bool skips_local_continuation = trial.complete
                && state.local_continuation.found
                && !html_evaluations_match(&trial, &state.local_continuation);
            if (skips_local_continuation
                && html_evaluation_is_better(&trial, &state.skipped_complete)) {
              state.skipped_complete = trial;
            }
            else if (!skips_local_continuation
                     && html_evaluation_is_better(&trial, &state.current_best)) {
              state.current_best = trial;
            }
          }
        }

        state.next_actual = actual_u + 1;
        state.displaced_done = false;
        if ((state.next_actual & UINT64_C(0xff)) == 0) {
          BlockVector *active_blockvector = (*candidate)->b;
          (*candidate)->b = blockvector;
          if (reassembly_check_kill_queue(work, candidate,
                                          uuidp, uuidc)) {
            if (option_blockvector) {
              free_blockvector(&option_blockvector);
            }
            return;
          }
          if (html_checkpoint_search(work, *candidate, &state, uuidp, uuidc)) {
            if (option_blockvector) {
              free_blockvector(&option_blockvector);
            }
            return;
          }
          (*candidate)->b = active_blockvector;
          html_restore_prefix(*candidate, prefix_blocks);
        }
      }
      if (state.skipped_complete.found) {
        html_write_evaluation_hypothesis(*candidate, &state.skipped_complete);
      }
      state.option_best[state.option] = state.current_best;
      state.current_best = (HtmlRunEvaluation){0};
      state.local_continuation = (HtmlRunEvaluation){0};
      state.physical_suffix = (HtmlRunEvaluation){0};
      state.skipped_complete = (HtmlRunEvaluation){0};
      state.prepared = false;
      state.next_actual = 0;
      if (option_blockvector) {
        (*candidate)->b = blockvector;
        free_blockvector(&option_blockvector);
      }
      else {
        html_restore_prefix(*candidate, base_blocks);
      }
    }

    const bool base_advances = state.option_best[0].found
        && (state.option_best[0].complete
            || state.option_best[0].total_blocks > base_blocks);
    if (base_advances) {
      best = state.option_best[0];
    }
    else {
      for (uint32_t option = 0; option < state.prefix_count; option++) {
        if (html_evaluation_is_better(&state.option_best[option], &best)) {
          best = state.option_best[option];
        }
      }
    }

    for (uint32_t option = 0; option < state.prefix_count; option++) {
      if (state.option_best[option].complete
          && !html_evaluations_match(&state.option_best[option], &best)) {
        html_write_evaluation_hypothesis(*candidate,
                                         &state.option_best[option]);
      }
    }

    if (!best.found
        || (!best.complete && best.total_blocks <= base_blocks)
        || !html_commit_evaluation(*candidate, &best)) {
      break;
    }
    const bool changed = state.changed || best.prefix_blocks != base_blocks
                         || best.run_blocks != 0;
    state = (HtmlCarveState){.magic = HTML_STATE_MAGIC, .changed = changed};
    if (best.complete) {
      html_publish_promising(candidate, true);
      return;
    }
  }

  if (*candidate && state.changed) {
    html_publish_promising(candidate, false);
  }
  else if (*candidate) {
    destroy_candidate(candidate);
  }
}

// Fixed-size search state uses the normal validator checkpoint callbacks.
static inline bool html_serialize_carve_state(void **state, FILE *fp,
                                              StateSerialization mode) {
  if (!state || !fp || (mode == SERIALIZE && !*state)) {
    return false;
  }
  if (mode == DESERIALIZE) {
    HtmlCarveState *restored = (HtmlCarveState *)malloc(sizeof(*restored));
    check_memory_allocation(restored, __LINE__, __FILE__, "HTML search state");
    if (fread(restored, sizeof(*restored), 1, fp) != 1
        || restored->magic != HTML_STATE_MAGIC
        || restored->prefix_count > 2
        || restored->option > restored->prefix_count) {
      free(restored);
      return false;
    }
    *state = restored;
    return true;
  }
  return fwrite(*state, sizeof(HtmlCarveState), 1, fp) == 1;
}

static inline void *html_clone_carve_state(const void *state) {
  if (!state) {
    return NULL;
  }
  HtmlCarveState *clone = (HtmlCarveState *)malloc(sizeof(*clone));
  check_memory_allocation(clone, __LINE__, __FILE__, "HTML search state clone");
  memcpy(clone, state, sizeof(*clone));
  return clone;
}

static inline void html_free_carve_state(void **state) {
  if (state && *state) {
    free(*state);
    *state = NULL;
  }
}

static inline size_t html_sizeof_carve_state(const void *state) {
  (void)state;
  return sizeof(HtmlCarveState);
}

static inline void html_print_carve_state(const void *state) {
  const HtmlCarveState *typed = (const HtmlCarveState *)state;
  if (!typed) {
    printf("NULL\n");
    return;
  }
  printf("HTML prefix option %u/%u, next actual block %" PRIu64 "\n",
         typed->option, typed->prefix_count, typed->next_actual);
}

#endif
