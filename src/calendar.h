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

#if !defined(SCALPEL_CALENDAR_H)
#define SCALPEL_CALENDAR_H

#include "scalpel.h"
#include "validator_search.h"

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#define CALENDAR_UTF8_BOM_SIZE       UINT64_C(3)
#define CALENDAR_MAXIMUM_DEPTH       64u
#define CALENDAR_MAXIMUM_NAME_LENGTH 64u
#define CALENDAR_MINIMUM_ICS_SIZE    UINT64_C(41)
#define CALENDAR_MINIMUM_VCF_SIZE    UINT64_C(37)
#define CALENDAR_LOCAL_FORWARD_BLOCKS INT64_C(64)

typedef enum CalendarProfile {
  CALENDAR_PROFILE_ICS = 0,
  CALENDAR_PROFILE_VCF
} CalendarProfile;

typedef enum CalendarParseResult {
  CALENDAR_PARSE_INVALID = 0,
  CALENDAR_PARSE_COMPLETE,
  CALENDAR_PARSE_TRUNCATED,
  CALENDAR_PARSE_DAMAGED
} CalendarParseResult;

typedef struct CalendarComponent {
  uint64_t name_offset;
  uint32_t name_length;
} CalendarComponent;

typedef struct CalendarParseSummary {
  uint64_t validated_end;
  uint64_t property_count;
  uint64_t weak_property_count;
  uint64_t root_count;
} CalendarParseSummary;

#define CALENDAR_SEARCH_STATE_MAGIC UINT32_C(0x43414c31)
typedef struct {
  uint32_t magic;
  XXH128_hash_t view;
  uint64_t next_actual;
  int64_t best_actual;
  uint64_t progress;
  uint64_t properties;
  uint64_t weak_properties;
  BlockValidationDecision confidence;
  int64_t reserved;
  int64_t forward_distance;
  bool adjacent;
  bool local_forward;
  bool complete;
} CalendarSearchState;

static inline bool calendar_serialize_carve_state(void **state, FILE *fp, StateSerialization mode);
static inline void *calendar_clone_carve_state(const void *state);
static inline void calendar_free_carve_state(void **state);
static inline size_t calendar_sizeof_carve_state(const void *state);
static inline void calendar_print_carve_state(const void *state);

static inline uint8_t calendar_ascii_upper(uint8_t value);
static inline bool calendar_ascii_span_equal(const uint8_t *left,
                                             const uint8_t *right,
                                             uint64_t length);
static inline bool calendar_ascii_equal(const uint8_t *data, uint64_t length,
                                        const char *expected);
static inline bool calendar_line_starts(const uint8_t *line,
                                        uint64_t length,
                                        const char *prefix);
static inline bool calendar_property_name_valid(const uint8_t *line,
                                                uint64_t length,
                                                bool allow_extension_slash);
static inline bool calendar_ical_property_name_known(const uint8_t *name,
                                                     uint64_t length);
static inline bool calendar_uri_value_familiar(const uint8_t *value,
                                               uint64_t length);
static inline const uint8_t *calendar_content_value_separator(
    const uint8_t *line, uint64_t length);
static inline bool calendar_decimal_span(const uint8_t *data,
                                         uint64_t length);
static inline bool calendar_ical_date_value_valid(const uint8_t *value,
                                                  uint64_t length);
static inline bool calendar_ical_duration_value_valid(const uint8_t *value,
                                                      uint64_t length);
static inline bool calendar_ical_period_value_valid(const uint8_t *value,
                                                    uint64_t length);
static inline bool calendar_ical_temporal_property_valid(
    const uint8_t *name, uint64_t name_length, const uint8_t *value,
    uint64_t value_length);
static inline CalendarParseResult calendar_parse(
    const uint8_t *data, uint64_t length, CalendarProfile profile,
    CalendarParseSummary *summary);
static inline char *calendar_find_footer(char *base, uint64_t offset,
                                         uint64_t remaining,
                                         char **matchpos,
                                         uint32_t *matchlen,
                                         const char *footer);
static inline char *ics_footer_discovery(char *base, uint64_t offset,
                                         uint64_t remaining,
                                         char **matchpos,
                                         uint32_t *matchlen,
                                         uint32_t blocksize);
static inline char *vcf_footer_discovery(char *base, uint64_t offset,
                                         uint64_t remaining,
                                         char **matchpos,
                                         uint32_t *matchlen,
                                         uint32_t blocksize);
static inline uint32_t calendar_block_validate(
    char *data, uint64_t length, BlockValidationDecision *decision,
    uint64_t *validates_to, uint32_t needleidx, uint32_t blocksize,
    void *blockhashkey);
static inline void calendar_file_validate(
    char *data, uint64_t length, bool *validates, uint64_t *validates_to,
    bool *promising, uint32_t needleidx, uint32_t blocksize,
    void *carvehashkey, CalendarProfile profile);
static inline void ics_file_validate(char *data, uint64_t length,
                                     bool *validates,
                                     uint64_t *validates_to,
                                     bool *promising,
                                     uint32_t needleidx,
                                     uint32_t blocksize,
                                     void *carvehashkey);
static inline void vcf_file_validate(char *data, uint64_t length,
                                     bool *validates,
                                     uint64_t *validates_to,
                                     bool *promising,
                                     uint32_t needleidx,
                                     uint32_t blocksize,
                                     void *carvehashkey);
static inline void calendar_candidate_validate(CarveInfo *candidate,
                                               bool *validates,
                                               uint64_t *validates_to,
                                               bool *promising);
static inline bool calendar_candidate_is_contiguous(
    const CarveInfo *candidate);
static inline void calendar_reassembly(ThreadWork *work,
                                       CarveInfo **candidate,
                                       uuid_string_t uuidp,
                                       uuid_string_t uuidc);

static inline uint8_t calendar_ascii_upper(uint8_t value) {

  if (value >= 'a' && value <= 'z') {
    return (uint8_t)(value - ('a' - 'A'));
  }
  return value;
}

static inline bool calendar_ascii_span_equal(const uint8_t *left,
                                             const uint8_t *right,
                                             uint64_t length) {

  if (!left || !right) {
    return false;
  }
  for (uint64_t offset = 0; offset < length; offset++) {
    if (calendar_ascii_upper(left[offset])
        != calendar_ascii_upper(right[offset])) {
      return false;
    }
  }
  return true;
}

static inline bool calendar_ascii_equal(const uint8_t *data, uint64_t length,
                                        const char *expected) {

  if (!data || !expected || strlen(expected) != length) {
    return false;
  }
  return calendar_ascii_span_equal(data, (const uint8_t *)expected, length);
}

static inline bool calendar_line_starts(const uint8_t *line,
                                        uint64_t length,
                                        const char *prefix) {

  const size_t prefix_length = strlen(prefix);

  if (!line || length < prefix_length) {
    return false;
  }
  return calendar_ascii_equal(line, prefix_length, prefix);
}

static inline bool calendar_property_name_valid(const uint8_t *line,
                                                uint64_t length,
                                                bool allow_extension_slash) {

  if (!line || length == 0) {
    return false;
  }
  const bool extension_name = allow_extension_slash && length > 2
      && calendar_ascii_upper(line[0]) == 'X' && line[1] == '-';

  for (uint64_t offset = 0; offset < length; offset++) {
    const uint8_t value = line[offset];

    if ((value >= 'A' && value <= 'Z')
        || (value >= 'a' && value <= 'z')
        || (value >= '0' && value <= '9')
        || value == '-' || value == '.'
        || (extension_name && value == '/')) {
      continue;
    }
    return false;
  }
  return true;
}

static inline bool calendar_ical_property_name_known(const uint8_t *name,
                                                     uint64_t length) {

  static const char *const known[] = {
    "ACKNOWLEDGED", "ACTION", "ATTACH", "ATTENDEE", "CALSCALE",
    "CATEGORIES", "CLASS", "COLOR", "COMMENT", "COMPLETED",
    "CONFERENCE", "CONTACT", "CREATED", "DESCRIPTION", "DTEND",
    "DTSTAMP", "DTSTART", "DUE", "DURATION", "EXDATE", "FREEBUSY",
    "GEO", "IMAGE", "LAST-MODIFIED", "LOCATION", "LOCATION-TYPE",
    "METHOD", "NAME", "ORGANIZER", "PERCENT-COMPLETE", "PRIORITY",
    "PRODID", "PROXIMITY", "RDATE", "RECURRENCE-ID", "REFRESH-INTERVAL",
    "RELATED-TO", "REPEAT", "REQUEST-STATUS", "RESOURCES", "RRULE",
    "SEQUENCE", "SOURCE", "STATUS", "STRUCTURED-DATA", "STYLED-DESCRIPTION",
    "SUMMARY", "TRANSP", "TRIGGER", "TZID", "TZNAME", "TZOFFSETFROM",
    "TZOFFSETTO", "TZURL", "UID", "URL", "VERSION"
  };

  if (!name || length == 0) {
    return false;
  }
  if (length > 2 && calendar_ascii_upper(name[0]) == 'X'
      && name[1] == '-') {
    return true;
  }
  for (uint64_t index = 0; index < sizeof(known) / sizeof(known[0]);
       index++) {
    if (calendar_ascii_equal(name, length, known[index])) {
      return true;
    }
  }
  return false;
}

static inline bool calendar_uri_value_familiar(const uint8_t *value,
                                               uint64_t length) {

  static const char *const prefixes[] = {
    "cid:", "file:", "ftp://", "http://", "https://", "mailto:",
    "mid:", "urn:", "webcal:"
  };

  if (!value || length == 0) {
    return false;
  }
  for (uint64_t index = 0; index < sizeof(prefixes) / sizeof(prefixes[0]);
       index++) {
    const uint64_t prefix_length = strlen(prefixes[index]);

    if (length >= prefix_length
        && calendar_ascii_span_equal(value,
                                     (const uint8_t *)prefixes[index],
                                     prefix_length)) {
      return true;
    }
  }
  return false;
}

static inline const uint8_t *calendar_content_value_separator(
    const uint8_t *line, uint64_t length) {

  if (!line) {
    return NULL;
  }

  bool quoted = false;
  const uint8_t *quoted_colon = NULL;

  for (uint64_t offset = 0; offset < length; offset++) {
    if (line[offset] == '\\' && quoted && offset + 1 < length) {
      offset++;
      continue;
    }
    if (line[offset] == '"') {
      quoted = !quoted;
      continue;
    }
    if (line[offset] == ':') {
      if (!quoted) {
        return line + offset;
      }
      if (!quoted_colon) {
        quoted_colon = line + offset;
      }
    }
  }
  // A quoted parameter can continue on a folded physical line. In that case,
  // preserve the property as structurally plausible until the continuation is
  // available to the parser.
  return quoted_colon;
}

static inline bool calendar_decimal_span(const uint8_t *data,
                                         uint64_t length) {

  if (!data || length == 0) {
    return false;
  }
  for (uint64_t offset = 0; offset < length; offset++) {
    if (data[offset] < '0' || data[offset] > '9') {
      return false;
    }
  }
  return true;
}

static inline bool calendar_ical_date_value_valid(const uint8_t *value,
                                                  uint64_t length) {

  if (!value || (length != 8 && length != 15 && length != 16)) {
    return false;
  }
  if (!calendar_decimal_span(value, 8)) {
    return false;
  }

  const uint32_t year = (uint32_t)(value[0] - '0') * 1000u
                        + (uint32_t)(value[1] - '0') * 100u
                        + (uint32_t)(value[2] - '0') * 10u
                        + (uint32_t)(value[3] - '0');
  const uint32_t month = (uint32_t)(value[4] - '0') * 10u
                         + (uint32_t)(value[5] - '0');
  const uint32_t day = (uint32_t)(value[6] - '0') * 10u
                       + (uint32_t)(value[7] - '0');
  uint32_t maximum_day = 31;

  if (year == 0 || month == 0 || month > 12) {
    return false;
  }
  if (month == 4 || month == 6 || month == 9 || month == 11) {
    maximum_day = 30;
  }
  else if (month == 2) {
    const bool leap = (year % 4u == 0 && year % 100u != 0)
                      || year % 400u == 0;

    maximum_day = leap ? 29 : 28;
  }
  if (day == 0 || day > maximum_day) {
    return false;
  }
  if (length == 8) {
    return true;
  }
  if (value[8] != 'T' || !calendar_decimal_span(value + 9, 6)) {
    return false;
  }

  const uint32_t hour = (uint32_t)(value[9] - '0') * 10u
                        + (uint32_t)(value[10] - '0');
  const uint32_t minute = (uint32_t)(value[11] - '0') * 10u
                          + (uint32_t)(value[12] - '0');
  const uint32_t second = (uint32_t)(value[13] - '0') * 10u
                          + (uint32_t)(value[14] - '0');

  if (hour > 23 || minute > 59 || second > 60) {
    return false;
  }
  return length == 15 || value[15] == 'Z' || value[15] == 'z';
}

static inline bool calendar_ical_duration_value_valid(const uint8_t *value,
                                                      uint64_t length) {

  if (!value || length < 3) {
    return false;
  }

  uint64_t offset = 0;

  if (value[offset] == '+' || value[offset] == '-') {
    offset++;
  }
  if (offset >= length || value[offset] != 'P') {
    return false;
  }
  offset++;

  bool in_time = false;
  bool saw_value = false;
  bool saw_time_value = false;
  uint32_t last_order = 0;

  while (offset < length) {
    if (value[offset] == 'T') {
      if (in_time) {
        return false;
      }
      in_time = true;
      last_order = 0;
      offset++;
      continue;
    }

    const uint64_t number_start = offset;

    while (offset < length && value[offset] >= '0'
           && value[offset] <= '9') {
      offset++;
    }
    if (offset == number_start || offset >= length) {
      return false;
    }

    uint32_t order = 0;
    const uint8_t designator = value[offset++];

    if (!in_time && designator == 'W') {
      order = 1;
    }
    else if (!in_time && designator == 'D') {
      order = 2;
    }
    else if (in_time && designator == 'H') {
      order = 1;
    }
    else if (in_time && designator == 'M') {
      order = 2;
    }
    else if (in_time && designator == 'S') {
      order = 3;
    }
    else {
      return false;
    }
    if (order <= last_order) {
      return false;
    }
    last_order = order;
    saw_value = true;
    if (in_time) {
      saw_time_value = true;
    }
  }
  return saw_value && (!in_time || saw_time_value);
}

static inline bool calendar_ical_period_value_valid(const uint8_t *value,
                                                    uint64_t length) {

  if (!value) {
    return false;
  }

  const uint8_t *slash = memchr(value, '/', (size_t)length);

  if (!slash) {
    return false;
  }

  const uint64_t left_length = (uint64_t)(slash - value);
  const uint64_t right_length = length - left_length - 1;

  if (left_length < 15
      || !calendar_ical_date_value_valid(value, left_length)) {
    return false;
  }
  return calendar_ical_date_value_valid(slash + 1, right_length)
         || calendar_ical_duration_value_valid(slash + 1, right_length);
}

static inline bool calendar_ical_temporal_property_valid(
    const uint8_t *name, uint64_t name_length, const uint8_t *value,
    uint64_t value_length) {

  if (!name || !value) {
    return false;
  }

  const bool rdate = calendar_ascii_equal(name, name_length, "RDATE");
  const bool exdate = calendar_ascii_equal(name, name_length, "EXDATE");
  const bool freebusy = calendar_ascii_equal(name, name_length, "FREEBUSY");
  const bool duration = calendar_ascii_equal(name, name_length, "DURATION")
      || calendar_ascii_equal(name, name_length, "REFRESH-INTERVAL");
  const bool trigger = calendar_ascii_equal(name, name_length, "TRIGGER");
  const bool temporal = rdate || exdate || freebusy
      || duration || trigger
      || calendar_ascii_equal(name, name_length, "DTSTART")
      || calendar_ascii_equal(name, name_length, "DTEND")
      || calendar_ascii_equal(name, name_length, "DUE")
      || calendar_ascii_equal(name, name_length, "COMPLETED")
      || calendar_ascii_equal(name, name_length, "CREATED")
      || calendar_ascii_equal(name, name_length, "LAST-MODIFIED")
      || calendar_ascii_equal(name, name_length, "DTSTAMP")
      || calendar_ascii_equal(name, name_length, "RECURRENCE-ID");

  if (!temporal) {
    return true;
  }
  if (duration) {
    return calendar_ical_duration_value_valid(value, value_length);
  }
  if (trigger) {
    return calendar_ical_duration_value_valid(value, value_length)
           || calendar_ical_date_value_valid(value, value_length);
  }
  if (!rdate && !exdate && !freebusy) {
    return calendar_ical_date_value_valid(value, value_length);
  }

  uint64_t offset = 0;

  while (offset < value_length) {
    const uint8_t *comma = memchr(value + offset, ',',
                                  (size_t)(value_length - offset));
    const uint64_t item_length = comma
        ? (uint64_t)(comma - (value + offset)) : value_length - offset;
    bool valid = false;

    if (freebusy) {
      valid = calendar_ical_period_value_valid(value + offset, item_length);
    }
    else {
      valid = calendar_ical_date_value_valid(value + offset, item_length);
      if (rdate && !valid) {
        valid = calendar_ical_period_value_valid(value + offset,
                                                 item_length);
      }
    }
    if (!valid) {
      return false;
    }
    offset += item_length + (comma ? 1 : 0);
  }
  return value_length > 0;
}

static inline CalendarParseResult calendar_parse(
    const uint8_t *data, uint64_t length, CalendarProfile profile,
    CalendarParseSummary *summary) {

  if (!summary) {
    return CALENDAR_PARSE_INVALID;
  }
  memset(summary, 0, sizeof(*summary));

  if (!data || length == 0) {
    return CALENDAR_PARSE_INVALID;
  }

  uint64_t offset = 0;

  if (length >= CALENDAR_UTF8_BOM_SIZE
      && data[0] == UINT8_C(0xef)
      && data[1] == UINT8_C(0xbb)
      && data[2] == UINT8_C(0xbf)) {
    offset = CALENDAR_UTF8_BOM_SIZE;
  }

  CalendarComponent stack[CALENDAR_MAXIMUM_DEPTH];
  uint32_t depth = 0;
  bool saw_version = false;
  bool previous_property = false;
  bool pending_property_separator = false;
  bool pending_version = false;
  const char *root_name = profile == CALENDAR_PROFILE_ICS
                              ? "VCALENDAR" : "VCARD";

  while (offset < length) {
    const uint64_t line_start = offset;
    const uint8_t *newline = memchr(data + offset, '\n',
                                    (size_t)(length - offset));
    uint64_t line_end = newline ? (uint64_t)(newline - data) : length;
    const uint64_t next_offset = newline ? line_end + 1 : line_end;

    if (line_end > line_start && data[line_end - 1] == '\r') {
      line_end--;
    }
    const uint64_t line_length = line_end - line_start;
    const uint8_t *line = data + line_start;
    const bool next_line_folded = newline && next_offset < length
        && (data[next_offset] == ' ' || data[next_offset] == '\t');

    if (memchr(line, '\0', (size_t)line_length)) {
      if (depth == 0 && summary->root_count > 0) {
        return CALENDAR_PARSE_COMPLETE;
      }
      return summary->root_count > 0 || depth > 0
                 ? CALENDAR_PARSE_DAMAGED : CALENDAR_PARSE_INVALID;
    }
    if (line_length == 0) {
      if (depth == 0 && summary->root_count > 0) {
        summary->validated_end = next_offset;
        offset = next_offset;
        continue;
      }
      // vCard 2.1 producers commonly terminate a folded BASE64 property with
      // an empty physical line before the next property.
      if (profile == CALENDAR_PROFILE_VCF && depth > 0
          && previous_property) {
        previous_property = false;
        pending_property_separator = false;
        pending_version = false;
        summary->validated_end = next_offset;
        offset = next_offset;
        continue;
      }
      return summary->root_count > 0 || depth > 0
                 ? CALENDAR_PARSE_DAMAGED : CALENDAR_PARSE_INVALID;
    }

    if (!newline && depth > 0) {
      bool complete_root_end = false;

      if (depth == 1
          && calendar_line_starts(line, line_length, "END:")) {
        const uint64_t name_length = line_length - strlen("END:");

        complete_root_end = name_length == stack[0].name_length
            && calendar_ascii_span_equal(data + stack[0].name_offset,
                                         line + strlen("END:"),
                                         name_length);
      }
      if (!complete_root_end) {
        return CALENDAR_PARSE_TRUNCATED;
      }
    }

    bool horizontal_whitespace = true;

    for (uint64_t index = 0; index < line_length; index++) {
      if (line[index] != ' ' && line[index] != '\t') {
        horizontal_whitespace = false;
        break;
      }
    }
    if (depth == 0 && summary->root_count > 0
        && horizontal_whitespace) {
      summary->validated_end = next_offset;
      offset = next_offset;
      continue;
    }

    if (line[0] == ' ' || line[0] == '\t') {
      if (!previous_property || depth == 0) {
        return summary->root_count > 0 || depth > 0
                   ? CALENDAR_PARSE_DAMAGED : CALENDAR_PARSE_INVALID;
      }
      const uint8_t *continuation = line + 1;
      const uint64_t continuation_length = line_length - 1;
      const uint8_t *colon = calendar_content_value_separator(
          continuation, continuation_length);

      if (pending_property_separator) {
        if (!colon) {
          if (!next_line_folded) {
            return CALENDAR_PARSE_DAMAGED;
          }
        }
        else {
          pending_property_separator = false;
        }
      }
      if (pending_version && colon) {
        const uint8_t *value = colon + 1;
        const uint64_t value_length = continuation_length
            - (uint64_t)(value - continuation);

        if ((profile == CALENDAR_PROFILE_ICS
             && calendar_ascii_equal(value, value_length, "2.0"))
            || (profile == CALENDAR_PROFILE_VCF
                && (calendar_ascii_equal(value, value_length, "2.1")
                    || calendar_ascii_equal(value, value_length, "3.0")
                    || calendar_ascii_equal(value, value_length, "4.0")
                    || calendar_ascii_equal(value, value_length, "4")))) {
          saw_version = true;
          pending_version = false;
        }
        else {
          return CALENDAR_PARSE_INVALID;
        }
      }
      summary->validated_end = next_offset;
      offset = next_offset;
      continue;
    }

    previous_property = false;
    pending_property_separator = false;
    pending_version = false;
    if (calendar_line_starts(line, line_length, "BEGIN:")) {
      const uint64_t name_length = line_length - strlen("BEGIN:");
      const uint64_t name_offset = line_start + strlen("BEGIN:");

      if (name_length == 0 || name_length > CALENDAR_MAXIMUM_NAME_LENGTH
          || depth >= CALENDAR_MAXIMUM_DEPTH
          || !calendar_property_name_valid(data + name_offset,
                                           name_length, false)) {
        return summary->root_count > 0 || depth > 0
                   ? CALENDAR_PARSE_DAMAGED : CALENDAR_PARSE_INVALID;
      }
      if (depth == 0) {
        if (!calendar_ascii_equal(data + name_offset, name_length,
                                  root_name)) {
          return summary->root_count > 0 ? CALENDAR_PARSE_COMPLETE
                                         : CALENDAR_PARSE_INVALID;
        }
        saw_version = false;
      }
      stack[depth].name_offset = name_offset;
      stack[depth].name_length = (uint32_t)name_length;
      depth++;
    }
    else if (calendar_line_starts(line, line_length, "END:")) {
      const uint64_t name_length = line_length - strlen("END:");
      const uint8_t *name = line + strlen("END:");

      if (depth == 0 || name_length != stack[depth - 1].name_length
          || !calendar_ascii_span_equal(
                 data + stack[depth - 1].name_offset, name, name_length)) {
        return summary->root_count > 0 || depth > 0
                   ? CALENDAR_PARSE_DAMAGED : CALENDAR_PARSE_INVALID;
      }
      depth--;
      if (depth == 0) {
        if (!saw_version) {
          return CALENDAR_PARSE_INVALID;
        }
        summary->root_count++;
      }
    }
    else {
      if (depth == 0) {
        return summary->root_count > 0 ? CALENDAR_PARSE_COMPLETE
                                       : CALENDAR_PARSE_INVALID;
      }

      const uint8_t *colon = calendar_content_value_separator(
          line, line_length);

      if (colon == line) {
        return CALENDAR_PARSE_DAMAGED;
      }
      const uint8_t *semicolon = memchr(
          line, ';', colon ? (size_t)(colon - line) : (size_t)line_length);
      const uint64_t property_length = semicolon
                                           ? (uint64_t)(semicolon - line)
                                           : colon
                                                 ? (uint64_t)(colon - line)
                                                 : line_length;

      if (!calendar_property_name_valid(
              line, property_length, profile == CALENDAR_PROFILE_VCF)) {
        return CALENDAR_PARSE_DAMAGED;
      }

      if (profile == CALENDAR_PROFILE_ICS
          && !calendar_ical_property_name_known(line, property_length)) {
        summary->weak_property_count++;
      }
      if (!colon) {
        if (!next_line_folded) {
          return CALENDAR_PARSE_DAMAGED;
        }
        pending_version = depth == 1
            && calendar_ascii_equal(line, property_length, "VERSION");
        pending_property_separator = true;
        summary->property_count++;
        previous_property = true;
        summary->validated_end = next_offset;
        offset = next_offset;
        continue;
      }
      if (profile == CALENDAR_PROFILE_ICS && newline
          && (calendar_ascii_equal(line, property_length, "URL")
              || calendar_ascii_equal(line, property_length, "TZURL")
              || calendar_ascii_equal(line, property_length, "SOURCE"))
          && !calendar_uri_value_familiar(
                 colon + 1,
                 line_length - (uint64_t)(colon + 1 - line))) {
        summary->weak_property_count++;
      }
      if (profile == CALENDAR_PROFILE_ICS && newline
          && calendar_ascii_equal(line, property_length, "TZNAME")
          && calendar_ical_date_value_valid(
                 colon + 1,
                 line_length - (uint64_t)(colon + 1 - line))) {
        summary->weak_property_count++;
      }
      if (profile == CALENDAR_PROFILE_ICS && newline && !next_line_folded
          && !calendar_ical_temporal_property_valid(
                 line, property_length, colon + 1,
                 line_length - (uint64_t)(colon + 1 - line))) {
        return CALENDAR_PARSE_DAMAGED;
      }
      if (depth == 1
          && calendar_ascii_equal(line, property_length, "VERSION")) {
        const uint8_t *value = colon + 1;
        const uint64_t value_length = line_length
                                      - (uint64_t)(value - line);

        if ((profile == CALENDAR_PROFILE_ICS
             && calendar_ascii_equal(value, value_length, "2.0"))
            || (profile == CALENDAR_PROFILE_VCF
                && (calendar_ascii_equal(value, value_length, "2.1")
                    || calendar_ascii_equal(value, value_length, "3.0")
                    || calendar_ascii_equal(value, value_length, "4.0")
                    || calendar_ascii_equal(value, value_length, "4")))) {
          saw_version = true;
        }
        else {
          return CALENDAR_PARSE_INVALID;
        }
      }
      summary->property_count++;
      previous_property = true;
    }

    if (!newline && depth > 0) {
      return CALENDAR_PARSE_TRUNCATED;
    }

    summary->validated_end = next_offset;
    offset = next_offset;
  }

  if (depth == 0 && summary->root_count > 0) {
    return CALENDAR_PARSE_COMPLETE;
  }
  return summary->root_count > 0 || depth > 0
             ? CALENDAR_PARSE_TRUNCATED : CALENDAR_PARSE_INVALID;
}

static inline char *calendar_find_footer(char *base, uint64_t offset,
                                         uint64_t remaining,
                                         char **matchpos,
                                         uint32_t *matchlen,
                                         const char *footer) {

  *matchpos = NULL;
  *matchlen = 0;

  if (!base || !footer) {
    return NULL;
  }
  const size_t footer_length = strlen(footer);
  const uint8_t *search = (const uint8_t *)base + offset;
  uint64_t available = remaining;

  while (available >= footer_length) {
    const uint8_t *found = search;

    while (available >= footer_length
           && calendar_ascii_upper(found[0]) != 'E') {
      found++;
      available--;
    }
    if (available < footer_length) {
      break;
    }
    if (available >= footer_length
        && calendar_ascii_equal(found, footer_length, footer)) {
      uint32_t total_length = (uint32_t)footer_length;

      if (available > footer_length
          && found[footer_length] == '\r'
          && available > footer_length + 1
          && found[footer_length + 1] == '\n') {
        total_length += 2;
      }
      else if (available > footer_length
               && found[footer_length] == '\n') {
        total_length++;
      }
      *matchpos = (char *)found;
      *matchlen = total_length;
      return NULL;
    }
    search = found + 1;
    available--;
  }
  return NULL;
}

static inline char *ics_footer_discovery(char *base, uint64_t offset,
                                         uint64_t remaining,
                                         char **matchpos,
                                         uint32_t *matchlen,
                                         uint32_t blocksize) {

  (void)blocksize;
  return calendar_find_footer(base, offset, remaining, matchpos, matchlen,
                              "END:VCALENDAR");
}

static inline char *vcf_footer_discovery(char *base, uint64_t offset,
                                         uint64_t remaining,
                                         char **matchpos,
                                         uint32_t *matchlen,
                                         uint32_t blocksize) {

  (void)blocksize;
  return calendar_find_footer(base, offset, remaining, matchpos, matchlen,
                              "END:VCARD");
}

// Rank text blocks that can participate in an iCalendar or vCard stream.
// File validation remains authoritative; these scores only avoid spending
// reassembly time on binary and padding blocks.
//
static inline uint32_t calendar_block_validate(
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
    *decision = BLOCK_CONFIDENCE_INVALID;
    *validates_to = 0;
    return needleidx;
  }

  uint64_t line_count = 0;
  uint64_t structured_lines = 0;
  bool marker = false;
  uint64_t line_start = 0;

  for (uint64_t offset = 0; offset < content_length; offset++) {
    const uint8_t value = bytes[offset];

    if (value == 0 || value == 0x7f
        || (value < 0x20 && value != '\t' && value != '\r'
            && value != '\n')) {
      *decision = BLOCK_CONFIDENCE_INVALID;
      *validates_to = 0;
      return needleidx;
    }
    if (value != '\n' && offset + 1 != content_length) {
      continue;
    }

    uint64_t line_end = value == '\n' ? offset : offset + 1;
    if (line_end > line_start && bytes[line_end - 1] == '\r') {
      line_end--;
    }
    const uint64_t line_length = line_end - line_start;

    line_count++;
    if (line_length > 0
        && (bytes[line_start] == ' ' || bytes[line_start] == '\t')) {
      structured_lines++;
    }
    else if (line_length > 0) {
      const uint8_t *colon = calendar_content_value_separator(
          bytes + line_start, line_length);
      const uint8_t *semicolon = memchr(bytes + line_start, ';',
                                        (size_t)line_length);
      const uint8_t *name_end = colon;

      if (semicolon && (!name_end || semicolon < name_end)) {
        name_end = semicolon;
      }
      if (colon && name_end && name_end > bytes + line_start
          && calendar_property_name_valid(
                 bytes + line_start,
                 (uint64_t)(name_end - (bytes + line_start)), true)) {
        structured_lines++;
      }
      if (calendar_line_starts(bytes + line_start, line_length, "BEGIN:")
          || calendar_line_starts(bytes + line_start, line_length, "END:")
          || calendar_line_starts(bytes + line_start, line_length,
                                  "VERSION:")) {
        marker = true;
      }
    }
    line_start = offset + 1;
  }

  BlockValidationDecision confidence = (BlockValidationDecision)45;

  if (line_count >= 2 && structured_lines + 1 >= line_count) {
    confidence = (BlockValidationDecision)80;
  }
  if (marker) {
    confidence = (BlockValidationDecision)95;
  }
  if (*decision > confidence) {
    confidence = *decision;
  }
  *decision = confidence;
  *validates_to = content_length - 1;
  return needleidx;
}

static inline void calendar_file_validate(
    char *data, uint64_t length, bool *validates, uint64_t *validates_to,
    bool *promising, uint32_t needleidx, uint32_t blocksize,
    void *carvehashkey, CalendarProfile profile) {

  (void)needleidx;
  (void)blocksize;
  (void)carvehashkey;

  if (!validates || !validates_to || !promising) {
    return;
  }
  *validates = false;
  *validates_to = 0;
  *promising = false;

  CalendarParseSummary summary;
  const CalendarParseResult result = calendar_parse(
      (const uint8_t *)data, length, profile, &summary);

  if (summary.validated_end > 0) {
    *validates_to = summary.validated_end - 1;
  }
  if (result == CALENDAR_PARSE_COMPLETE) {
    *validates = true;
  }
  else if (result == CALENDAR_PARSE_TRUNCATED) {
    *promising = true;
    if (length > 0) {
      *validates_to = length - 1;
    }
  }
  else if (result == CALENDAR_PARSE_DAMAGED) {
    *promising = summary.validated_end > 0;
  }
}

static inline void ics_file_validate(char *data, uint64_t length,
                                     bool *validates,
                                     uint64_t *validates_to,
                                     bool *promising,
                                     uint32_t needleidx,
                                     uint32_t blocksize,
                                     void *carvehashkey) {

  calendar_file_validate(data, length, validates, validates_to, promising,
                         needleidx, blocksize, carvehashkey,
                         CALENDAR_PROFILE_ICS);
}

static inline void vcf_file_validate(char *data, uint64_t length,
                                     bool *validates,
                                     uint64_t *validates_to,
                                     bool *promising,
                                     uint32_t needleidx,
                                     uint32_t blocksize,
                                     void *carvehashkey) {

  calendar_file_validate(data, length, validates, validates_to, promising,
                         needleidx, blocksize, carvehashkey,
                         CALENDAR_PROFILE_VCF);
}

// Calendar grammar proves a byte stream is well formed but cannot prove that
// independently valid text blocks came from the same physical record.
// Preserve noncontiguous reconstructions for examination without presenting
// them as exact validated files.
//
static inline void calendar_candidate_validate(CarveInfo *candidate,
                                               bool *validates,
                                               uint64_t *validates_to,
                                               bool *promising) {

  (void)validates_to;

  if (!candidate || !candidate->b || !validates || !promising
      || !*validates) {
    return;
  }

  const uint64_t block_count = blockvector_get_num_blocks(candidate->b);

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

static inline bool calendar_candidate_is_contiguous(
    const CarveInfo *candidate) {

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

// Extend a Calendar candidate one block at a time. A structurally valid
// adjacent continuation is accepted immediately. Otherwise, candidate blocks
// are ordered using structural progress, weak-property evidence, nearby
// forward position, type confidence, and reservation pressure. Complete
// fragmented streams remain PROMISING because text grammar cannot establish
// the physical provenance of each independently valid block.
//
static inline void calendar_reassembly(ThreadWork *work,
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

  CalendarProfile profile = strcmp((*candidate)->filetype, "vcf") == 0
                                ? CALENDAR_PROFILE_VCF
                                : CALENDAR_PROFILE_ICS;

  (*candidate)->chopped = false;
  inflate_blockvector((*candidate)->b);

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

    CalendarParseSummary current_summary;
    CalendarParseResult current_result = calendar_parse(
        (const uint8_t *)blockvector_get_data_pointer(blockvector),
        blockvector_get_data_length(blockvector), profile, &current_summary);

    if (current_result == CALENDAR_PARSE_COMPLETE) {
      blockvector_set_data_length(blockvector,
                                  current_summary.validated_end);
      resize_blockvector(blockvector,
                         CEILDIV(current_summary.validated_end,
                                 scalpel_state.blocksize));
      if (calendar_candidate_is_contiguous(*candidate)) {
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

    uint64_t committed_length = block_count
                                * (uint64_t)scalpel_state.blocksize;
    if (current_summary.validated_end < committed_length) {
      uint64_t keep_blocks = CEILDIV(current_summary.validated_end,
                                     scalpel_state.blocksize);

      if (keep_blocks == 0) {
        keep_blocks = 1;
      }
      if (keep_blocks < block_count) {
        resize_blockvector(blockvector, keep_blocks);
        committed_length = keep_blocks
                           * (uint64_t)scalpel_state.blocksize;
        blockvector_set_data_length(blockvector, committed_length);
        inflate_blockvector(blockvector);
        block_count = keep_blocks;
      }
    }

    if (reassembly_check_max_size(work->id, *candidate, uuidp, uuidc)) {
      break;
    }

    const uint64_t trial_slot = block_count;
    const int64_t previous_apparent = blockvector_get_apparent_blocknumber(
        blockvector, trial_slot - 1);
    const int64_t image_blocks = filemirror_apparent_blocks(
        scalpel_state.filemirror);
    int64_t best_apparent = -1;
    uint64_t best_progress = current_summary.validated_end;
    uint64_t best_properties = current_summary.property_count;
    uint64_t best_weak_properties = current_summary.weak_property_count;
    BlockValidationDecision best_confidence = BLOCK_CONFIDENCE_INVALID;
    int64_t best_reserved = INT64_MAX;
    int64_t best_forward_distance = INT64_MAX;
    bool best_adjacent = false;
    bool best_local_forward = false;
    bool best_complete = false;
    uint64_t examined = 0;
    uint64_t next_actual = 0;
    CalendarSearchState *saved = carve_get_state((*candidate)->carvehashkey);
    if (saved && XXH128_isEqual(saved->view, validator_search_view(*candidate))) {
      const uint64_t image_actual_blocks = CEILDIV(filemirror_filesize(scalpel_state.filemirror),
                                                   scalpel_state.blocksize);
      if (saved->next_actual <= image_actual_blocks && saved->best_actual >= -1
          && (saved->best_actual < 0 || (uint64_t)saved->best_actual < image_actual_blocks)) {
        next_actual = saved->next_actual;
        best_apparent = saved->best_actual < 0 ? -1
            : filemirror_apparent_blocknumber(scalpel_state.filemirror, saved->best_actual);
        best_progress = saved->progress;
        best_properties = saved->properties;
        best_weak_properties = saved->weak_properties;
        best_confidence = saved->confidence;
        best_reserved = saved->reserved;
        best_forward_distance = saved->forward_distance;
        best_adjacent = saved->adjacent;
        best_local_forward = saved->local_forward;
        best_complete = saved->complete;
      }
    }
    calendar_free_carve_state((void **)&saved);

    resize_blockvector(blockvector, trial_slot + 1);
    blockvector_set_apparent_blocknumber(blockvector, trial_slot, -1);
    for (int64_t apparent = 0; apparent < image_blocks; apparent++) {
      const int64_t actual = filemirror_actual_blocknumber(
          scalpel_state.filemirror, apparent);

      if (actual >= 0 && (uint64_t)actual < next_actual) {
        continue;
      }
      examined++;
      const bool kill_poll = (examined & UINT64_C(0xff)) == 0;
      const bool checkpoint_poll = (examined & UINT64_C(0x1f)) == 0
          && atomic_load_explicit(&REASS_RETURN_TO_IDLE, memory_order_acquire);
      if (kill_poll || checkpoint_poll) {
        resize_blockvector(blockvector, trial_slot);
        blockvector_set_data_length(blockvector, committed_length);
        if (kill_poll && reassembly_check_kill_queue(work, candidate, uuidp, uuidc)) {
          return;
        }
        if (checkpoint_poll) {
          CalendarSearchState progress = {
            .magic = CALENDAR_SEARCH_STATE_MAGIC, .view = validator_search_view(*candidate),
            .next_actual = (uint64_t)actual,
            .best_actual = best_apparent < 0 ? -1
                : filemirror_actual_blocknumber(scalpel_state.filemirror, best_apparent),
            .progress = best_progress, .properties = best_properties,
            .weak_properties = best_weak_properties, .confidence = best_confidence,
            .reserved = best_reserved, .forward_distance = best_forward_distance,
            .adjacent = best_adjacent, .local_forward = best_local_forward, .complete = best_complete
          };
          carve_put_state((*candidate)->carvehashkey, &progress);
          if (reassembly_time_to_checkpoint(work->id, *candidate, uuidp, uuidc)) {
            return;
          }
        }
        resize_blockvector(blockvector, trial_slot + 1);
      }

      if (actual < 0
          || filemirror_actual_block_covered(scalpel_state.filemirror,
                                             actual)
          || apparent_block_in_blockvector(blockvector, apparent)) {
        continue;
      }

      const BlockValidationDecision confidence = filemirror_get_blocktype(
          scalpel_state.filemirror, actual, (*candidate)->needleidx);

      if (confidence == BLOCK_CONFIDENCE_INVALID) {
        continue;
      }

      blockvector_set_apparent_blocknumber(blockvector, trial_slot,
                                            apparent);
      const uint64_t old_length = inflate_blockvector_single_block(
          blockvector, trial_slot);
      CalendarParseSummary trial_summary;
      const CalendarParseResult trial_result = calendar_parse(
          (const uint8_t *)blockvector_get_data_pointer(blockvector),
          blockvector_get_data_length(blockvector), profile, &trial_summary);
      deflate_blockvector_single_block(blockvector, trial_slot, old_length);

      const int64_t reserved = scalpel_state.reservations
          ? filemirror_actual_block_reserved(scalpel_state.filemirror,
                                             actual) : 0;
      const bool adjacent = apparent == previous_apparent + 1;
      const bool complete = trial_result == CALENDAR_PARSE_COMPLETE;
      const int64_t forward_distance = apparent > previous_apparent
          ? apparent - previous_apparent : INT64_MAX;
      const bool local_forward = forward_distance
          <= CALENDAR_LOCAL_FORWARD_BLOCKS;

      if (adjacent && trial_summary.validated_end
                          > current_summary.validated_end
          && (trial_result == CALENDAR_PARSE_COMPLETE
              || trial_result == CALENDAR_PARSE_TRUNCATED)) {
        best_apparent = apparent;
        best_progress = trial_summary.validated_end;
        best_properties = trial_summary.property_count;
        best_weak_properties = trial_summary.weak_property_count;
        best_confidence = confidence;
        best_reserved = reserved;
        best_forward_distance = forward_distance;
        best_adjacent = true;
        best_local_forward = true;
        best_complete = complete;
        break;
      }

      bool better = false;

      if ((trial_result == CALENDAR_PARSE_COMPLETE
           || trial_result == CALENDAR_PARSE_TRUNCATED)
          && trial_summary.validated_end > current_summary.validated_end) {
        if (best_apparent < 0) {
          better = true;
        }
        // A vCard stream may contain sequential VCARD roots, so completing
        // the active root takes priority. An iCalendar stream has one
        // encompassing root, so additional validated content takes priority.
        else if (profile == CALENDAR_PROFILE_VCF
                 && complete != best_complete) {
          better = complete;
        }
        else if (trial_summary.weak_property_count
                 != best_weak_properties) {
          better = trial_summary.weak_property_count
                   < best_weak_properties;
        }
        else if (local_forward != best_local_forward) {
          better = local_forward;
        }
        else if (local_forward
                 && forward_distance != best_forward_distance) {
          better = forward_distance < best_forward_distance;
        }
        else if (trial_summary.property_count != best_properties) {
          better = trial_summary.property_count > best_properties;
        }
        else if (trial_summary.validated_end != best_progress) {
          better = trial_summary.validated_end > best_progress;
        }
        else if (complete != best_complete) {
          better = complete;
        }
        else if (confidence != best_confidence) {
          better = confidence > best_confidence;
        }
        else if (adjacent != best_adjacent) {
          better = adjacent;
        }
        else {
          better = reserved < best_reserved;
        }
      }

      if (better) {
        best_apparent = apparent;
        best_progress = trial_summary.validated_end;
        best_properties = trial_summary.property_count;
        best_weak_properties = trial_summary.weak_property_count;
        best_confidence = confidence;
        best_reserved = reserved;
        best_forward_distance = forward_distance;
        best_adjacent = adjacent;
        best_local_forward = local_forward;
        best_complete = complete;
      }

    }

    if (best_apparent < 0 || best_progress <= current_summary.validated_end) {
      resize_blockvector(blockvector, trial_slot);
      blockvector_set_data_length(blockvector, committed_length);
      break;
    }

    blockvector_set_apparent_blocknumber(blockvector, trial_slot,
                                         best_apparent);
    inflate_blockvector_single_block(blockvector, trial_slot);
    blockvector_set_data_length(
        blockvector, (trial_slot + 1) * (uint64_t)scalpel_state.blocksize);
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

// The ranking contains no pointers or image data; physical positions survive map compaction.
static inline bool calendar_serialize_carve_state(void **state, FILE *fp, StateSerialization mode) {
  if (!state || !fp || (mode == SERIALIZE && !*state)) {
    return false;
  }
  if (mode == SERIALIZE) {
    return fwrite(*state, sizeof(CalendarSearchState), 1, fp) == 1;
  }
  CalendarSearchState saved;
  if (fread(&saved, sizeof(saved), 1, fp) != 1 || saved.magic != CALENDAR_SEARCH_STATE_MAGIC
      || saved.best_actual < -1) {
    return false;
  }
  *state = calendar_clone_carve_state(&saved);
  return true;
}

static inline void *calendar_clone_carve_state(const void *state) {
  if (!state) {
    return NULL;
  }
  CalendarSearchState *copy = malloc(sizeof(*copy));
  check_memory_allocation(copy, __LINE__, __FILE__, "calendar saved search");
  memcpy(copy, state, sizeof(*copy));
  return copy;
}

static inline void calendar_free_carve_state(void **state) {
  if (state) {
    free(*state);
    *state = NULL;
  }
}

static inline size_t calendar_sizeof_carve_state(const void *state) {
  return state ? sizeof(CalendarSearchState) : 0;
}

static inline void calendar_print_carve_state(const void *state) {
  const CalendarSearchState *saved = state;
  if (saved) {
    printf("Calendar search: next physical block=%" PRIu64 " best=%" PRId64 "\n",
           saved->next_actual, saved->best_actual);
  }
}

#endif
