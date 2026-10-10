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

// CSV has no reliable magic value or intrinsic end marker. The validator therefore accepts only
// blocks containing repeated records with a consistent dialect and field count. A block can begin
// or end in a partial record, but complete records in its interior must agree.

#include "scalpel.h"

#define CSV_SUBTYPE_NAME_SIZE 32
#define CSV_MIN_STRONG_RECORDS 4
#define CSV_MIN_MODICO_RECORDS 2
#define CSV_MODICO_STRONG_CONFIDENCE 90

typedef struct CsvParseEvidence {
  bool valid;
  char delimiter;
  uint32_t columns;
  uint32_t records;
  uint32_t quoted_fields;
  uint32_t ambiguous_syntax_records;
  uint32_t trailing_empty_records;
} CsvParseEvidence;

// function prototypes for private CSV functions
static uint64_t csv_significant_length(const unsigned char *data,
                                       uint64_t length,
                                       uint32_t blocksize,
                                       bool *bounded);
static bool csv_is_html_entity_terminator(const unsigned char *data,
                                          uint64_t position);
static CsvParseEvidence csv_parse_dialect(const unsigned char *data,
                                          uint64_t length,
                                          char delimiter,
                                          bool initial_in_quotes,
                                          bool skip_first_record,
                                          bool include_final_record);
static bool csv_evidence_is_better(const CsvParseEvidence *candidate,
                                   const CsvParseEvidence *current);
static bool csv_evidence_is_sufficient(const CsvParseEvidence *evidence,
                                       BlockValidationDecision prior,
                                       bool bounded);
static inline uint32_t csv_master_block_validate(
    char *data,
    uint64_t length,
    BlockValidationDecision *decision,
    uint64_t *validates_to,
    uint32_t needleidx,
    uint32_t blocksize,
    void *blockhashkey);

// Return the text-bearing prefix of a block. Embedded control bytes reject the entire block;
// trailing zero fill is treated as a known content boundary. Bytes with the high bit set are
// retained so UTF-8 and legacy 8-bit CSV data are not rejected solely because of encoding.
//
static uint64_t csv_significant_length(const unsigned char *data,
                                       uint64_t length,
                                       uint32_t blocksize,
                                       bool *bounded) {

  bool has_nonwhitespace = false;
  uint64_t i;

  *bounded = length < blocksize;
  for (i = 0; i < length; i++) {
    unsigned char c = data[i];

    if (c == 0 || (c < 0x20 && c != '\t' && c != '\r' && c != '\n')
        || c == 0x7f) {
      bool zero_fill = c == 0;

      for (uint64_t j = i; zero_fill && j < length; j++) {
        if (data[j] != 0) {
          zero_fill = false;
        }
      }
      if (! zero_fill) {
        return 0;
      }
      *bounded = true;
      return has_nonwhitespace ? i : 0;
    }

    if (c > 0x20) {
      has_nonwhitespace = true;
    }
  }

  return has_nonwhitespace ? length : 0;
}

// A semicolon that terminates an HTML character reference is content, not a
// field boundary. Recognizing the bounded entity grammar prevents wrapped
// markup text from resembling a semicolon-delimited table while preserving
// genuine separators elsewhere in the same record.
//
static bool csv_is_html_entity_terminator(const unsigned char *data,
                                          uint64_t position) {

  static const uint64_t maximum_entity_length = 32;
  uint64_t start = position;

  while (start > 0 && position - start < maximum_entity_length) {
    unsigned char c = data[start - 1];

    if (c == '&') {
      start--;
      break;
    }
    if (! isalnum(c) && c != '#') {
      return false;
    }
    start--;
  }

  if (start >= position || data[start] != '&') {
    return false;
  }

  uint64_t cursor = start + 1;

  if (data[cursor] == '#') {
    cursor++;
    if (cursor >= position) {
      return false;
    }

    bool hexadecimal = data[cursor] == 'x' || data[cursor] == 'X';

    if (hexadecimal) {
      cursor++;
    }
    if (cursor >= position) {
      return false;
    }
    for (; cursor < position; cursor++) {
      if ((hexadecimal && ! isxdigit(data[cursor]))
          || (! hexadecimal && ! isdigit(data[cursor]))) {
        return false;
      }
    }
    return true;
  }

  if (! isalpha(data[cursor])) {
    return false;
  }
  for (cursor++; cursor < position; cursor++) {
    if (! isalnum(data[cursor])) {
      return false;
    }
  }
  return true;
}

// Parse one delimiter and one possible block-boundary state. Quoted fields follow the usual CSV
// rules: doubled quotes are escapes, delimiters and line endings are data inside quotes, and only
// horizontal whitespace may follow a closing quote before the delimiter or record ending.
//
static CsvParseEvidence csv_parse_dialect(const unsigned char *data,
                                          uint64_t length,
                                          char delimiter,
                                          bool initial_in_quotes,
                                          bool skip_first_record,
                                          bool include_final_record) {

  CsvParseEvidence evidence = {0};
  bool after_quote = false;
  bool field_has_content = false;
  bool field_has_nonwhitespace = false;
  bool in_quotes = initial_in_quotes;
  bool row_has_nonwhitespace = initial_in_quotes;
  bool row_invalid = false;
  bool row_ambiguous_syntax = false;
  bool row_delimiter_outside_parentheses = false;
  bool row_ends_in_close_parenthesis = false;
  bool row_function_like = false;
  bool row_has_parenthesis = false;
  bool row_identifier_prefix = true;
  bool row_identifier_started = false;
  bool row_trailing_backslash = false;
  bool row_started = initial_in_quotes;
  uint32_t completed_records = 0;
  uint32_t expected_columns = 0;
  uint32_t fields = 1;
  uint32_t row_parenthesis_depth = 0;
  uint32_t quoted_fields = 0;
  uint64_t i;

  evidence.delimiter = delimiter;

  for (i = 0; i < length; i++) {
    unsigned char c = data[i];
    bool finish_record = false;

    if (in_quotes) {
      row_started = true;
      if (c == '"') {
        if (i + 1 < length && data[i + 1] == '"') {
          field_has_content = true;
          row_has_nonwhitespace = true;
          i++;
        }
        else {
          in_quotes = false;
          after_quote = true;
        }
      }
      else if (c > 0x20) {
        row_has_nonwhitespace = true;
      }
      continue;
    }

    if (c == '\r' || c == '\n') {
      finish_record = true;
      if (c == '\r' && i + 1 < length && data[i + 1] == '\n') {
        i++;
      }
    }
    else if (after_quote) {
      row_started = true;
      if (c == (unsigned char)delimiter) {
        fields++;
        after_quote = false;
        field_has_content = false;
        field_has_nonwhitespace = false;
        row_delimiter_outside_parentheses = true;
        row_ends_in_close_parenthesis = false;
        row_trailing_backslash = false;
      }
      else if (c != ' ' && c != '\t') {
        row_invalid = true;
      }
    }
    else if (c == (unsigned char)delimiter
             && ! (delimiter == ';'
                   && csv_is_html_entity_terminator(data, i))) {
      row_started = true;
      fields++;
      field_has_content = false;
      field_has_nonwhitespace = false;
      if (! row_function_like || row_parenthesis_depth == 0) {
        row_delimiter_outside_parentheses = true;
      }
      row_ends_in_close_parenthesis = false;
      row_trailing_backslash = false;
    }
    else if (c == '"') {
      row_started = true;
      if (field_has_nonwhitespace) {
        row_invalid = true;
      }
      else {
        in_quotes = true;
        field_has_content = true;
        quoted_fields++;
        row_identifier_prefix = false;
        row_ends_in_close_parenthesis = false;
        row_trailing_backslash = false;
      }
    }
    else {
      row_started = true;
      if (c == '(' || c == ')') {
        row_has_parenthesis = true;
      }
      if (row_identifier_prefix) {
        if (! row_identifier_started && (c == ' ' || c == '\t')) {
          // Leading horizontal whitespace does not end an identifier prefix.
        }
        else if (! row_identifier_started
                 && (isalpha(c) || c == '_')) {
          row_identifier_started = true;
        }
        else if (row_identifier_started
                 && (isalnum(c) || c == '_')) {
          // Continue the leading identifier.
        }
        else if (row_identifier_started && c == '(') {
          row_function_like = true;
          row_identifier_prefix = false;
          row_parenthesis_depth = 1;
        }
        else {
          row_identifier_prefix = false;
        }
      }
      else if (row_function_like) {
        if (c == '(') {
          row_parenthesis_depth++;
        }
        else if (c == ')' && row_parenthesis_depth > 0) {
          row_parenthesis_depth--;
        }
      }
      if (c != ' ' && c != '\t') {
        field_has_content = true;
        field_has_nonwhitespace = true;
        row_has_nonwhitespace = true;
        row_ends_in_close_parenthesis = c == ')';
        row_trailing_backslash = c == '\\';
      }
      if (c == '{' || c == '}' || c == '[' || c == ']') {
        row_ambiguous_syntax = true;
      }
    }

    if (finish_record) {
      bool ignore_record = skip_first_record && completed_records == 0;

      completed_records++;
      if (! ignore_record) {
        if (row_invalid || ! row_has_nonwhitespace || fields < 2) {
          return evidence;
        }
        if (expected_columns == 0) {
          expected_columns = fields;
        }
        else if (fields != expected_columns) {
          return evidence;
        }
        evidence.records++;
        evidence.quoted_fields += quoted_fields;
        if (row_ambiguous_syntax
            || (row_trailing_backslash && row_has_parenthesis)
            || (row_function_like && row_parenthesis_depth == 0
                && row_ends_in_close_parenthesis
                && ! row_delimiter_outside_parentheses)) {
          evidence.ambiguous_syntax_records++;
        }
        if (! field_has_content) {
          evidence.trailing_empty_records++;
        }
      }

      after_quote = false;
      field_has_content = false;
      field_has_nonwhitespace = false;
      row_has_nonwhitespace = false;
      row_invalid = false;
      row_ambiguous_syntax = false;
      row_delimiter_outside_parentheses = false;
      row_ends_in_close_parenthesis = false;
      row_function_like = false;
      row_has_parenthesis = false;
      row_identifier_prefix = true;
      row_identifier_started = false;
      row_trailing_backslash = false;
      row_parenthesis_depth = 0;
      row_started = false;
      fields = 1;
      quoted_fields = 0;
    }
  }

  if (include_final_record && row_started) {
    bool ignore_record = skip_first_record && completed_records == 0;

    if (in_quotes || row_invalid) {
      return evidence;
    }
    if (! ignore_record) {
      if (! row_has_nonwhitespace || fields < 2) {
        return evidence;
      }
      if (expected_columns == 0) {
        expected_columns = fields;
      }
      else if (fields != expected_columns) {
        return evidence;
      }
      evidence.records++;
      evidence.quoted_fields += quoted_fields;
      if (row_ambiguous_syntax
          || (row_trailing_backslash && row_has_parenthesis)
          || (row_function_like && row_parenthesis_depth == 0
              && row_ends_in_close_parenthesis
              && ! row_delimiter_outside_parentheses)) {
        evidence.ambiguous_syntax_records++;
      }
      if (! field_has_content) {
        evidence.trailing_empty_records++;
      }
    }
  }
  else if (! include_final_record && row_started) {
    // An edge record may be incomplete, but it cannot already contain more fields than the
    // established dialect permits or violate quote syntax before the block boundary.
    if (row_invalid || (expected_columns > 0 && fields > expected_columns)) {
      return evidence;
    }
  }

  evidence.columns = expected_columns;
  evidence.valid = evidence.records > 0 && evidence.columns >= 2;
  return evidence;
}

// Prefer the parse supported by the most complete records, then the greatest amount of delimiter
// and quoting evidence. This resolves blocks that contain multiple punctuation characters without
// selecting a dialect based on the first punctuation byte encountered.
//
static bool csv_evidence_is_better(const CsvParseEvidence *candidate,
                                   const CsvParseEvidence *current) {

  uint64_t candidate_delimiters;
  uint64_t current_delimiters;

  if (! candidate->valid) {
    return false;
  }
  if (! current->valid || candidate->records != current->records) {
    return ! current->valid || candidate->records > current->records;
  }

  candidate_delimiters =
      (uint64_t)candidate->records * (candidate->columns - 1);
  current_delimiters =
      (uint64_t)current->records * (current->columns - 1);
  if (candidate_delimiters != current_delimiters) {
    return candidate_delimiters > current_delimiters;
  }
  if (candidate->quoted_fields != current->quoted_fields) {
    return candidate->quoted_fields > current->quoted_fields;
  }

  // Comma is the conventional CSV delimiter and wins an otherwise exact tie.
  return candidate->delimiter == ',' && current->delimiter != ',';
}

// Decide whether the repeated-record evidence is strong enough to publish the block. MoDiCo can
// reduce the requirement from four records to two, but it cannot make a syntactically inconsistent
// block valid.
//
static bool csv_evidence_is_sufficient(const CsvParseEvidence *evidence,
                                       BlockValidationDecision prior,
                                       bool bounded) {

  if (! evidence->valid) {
    return false;
  }

  // Markup, source initializers, and serialized arrays can mimic delimited
  // records. Their rows do not supply independent CSV evidence, even when a
  // classifier prior is present.
  const uint32_t unambiguous_records =
      evidence->records - evidence->ambiguous_syntax_records;

  if (evidence->trailing_empty_records == evidence->records
      && prior < CSV_MODICO_STRONG_CONFIDENCE) {
    return false;
  }
  if (unambiguous_records >= CSV_MIN_STRONG_RECORDS) {
    return true;
  }
  if (bounded
      && unambiguous_records + 1 == CSV_MIN_STRONG_RECORDS) {
    return true;
  }

  return prior >= CSV_MODICO_STRONG_CONFIDENCE
         && unambiguous_records >= CSV_MIN_MODICO_RECORDS;
}

// Classify one block as CSV data. The incoming decision may contain a MoDiCo confidence prior;
// structural parsing remains authoritative because every nonzero decision for a block-only file
// type is immediately published as validated output.
//
static inline uint32_t csv_master_block_validate(
    char *data,
    uint64_t length,
    BlockValidationDecision *decision,
    uint64_t *validates_to,
    uint32_t needleidx,
    uint32_t blocksize,
    void *blockhashkey) {

  static const char delimiters[] = {',', ';', '|'};
  CsvParseEvidence best = {0};
  BlockValidationDecision prior = *decision;
  bool bounded = false;
  char filetype[CSV_SUBTYPE_NAME_SIZE];
  uint64_t significant_length;

  (void)blockhashkey;
  *decision = BLOCK_CONFIDENCE_INVALID;
  *validates_to = 0;

  significant_length = csv_significant_length(
      (const unsigned char *)data, length, blocksize, &bounded);
  if (significant_length == 0) {
    return needleidx;
  }

  for (uint32_t d = 0; d < sizeof(delimiters); d++) {
    CsvParseEvidence candidate;

    // A bounded one-block file can use its first record as evidence. The second parse handles a
    // final fragment whose first row began in the preceding block.
    candidate = csv_parse_dialect((const unsigned char *)data,
                                  significant_length, delimiters[d], false,
                                  false, bounded);
    if (csv_evidence_is_sufficient(&candidate, prior, bounded)
        && csv_evidence_is_better(&candidate, &best)) {
      best = candidate;
    }

    candidate = csv_parse_dialect((const unsigned char *)data,
                                  significant_length, delimiters[d], false,
                                  true, bounded);
    if (csv_evidence_is_sufficient(&candidate, prior, bounded)
        && csv_evidence_is_better(&candidate, &best)) {
      best = candidate;
    }

    // The block can begin inside a quoted multiline field. Starting in the quoted state and
    // discarding the first completed record recovers synchronization without carrying state
    // between independently classified blocks.
    candidate = csv_parse_dialect((const unsigned char *)data,
                                  significant_length, delimiters[d], true,
                                  true, bounded);
    if (csv_evidence_is_sufficient(&candidate, prior, bounded)
        && csv_evidence_is_better(&candidate, &best)) {
      best = candidate;
    }
  }

  if (! best.valid) {
    return needleidx;
  }

  *decision = BLOCK_CONFIDENCE_VALID;
  *validates_to = significant_length - 1;
#ifndef CSV_TEST
  snprintf(filetype, sizeof(filetype), "%" PRIu32 "-col.csv", best.columns);
  needleidx = add_file_subtype(needleidx, filetype);
#else
  (void)filetype;
#endif

  return needleidx;
}
