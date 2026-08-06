//
// Scalpel3 is Copyright(C) 2021 - 2026 by Golden G. Richard III and contributors.
//
// This program is free software : you can redistribute it and / or modify it under the terms of the
// GNU General Public License as published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
// even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
// General Public License for more details.
//
// You should have received a copy of the GNU General Public License along with this program. If
// not, see <https://www.gnu.org/licenses/>.
//
// ----------------------------
// Additional Integration Terms
// ----------------------------
//
// Linking or embedding Scalpel3 (statically or dynamically) into another program such that the
// resulting executable or library forms a single combined work constitutes creation of a derivative
// work under the GPL. Any party distributing such a combined work must make the entire source code
// available under the terms of the GPL as well.
//
// Commercial entities wishing to use Scalpel3 in a closed-source or proprietary product or
// requiring support must obtain a separate commercial license.
//
// For commercial licensing or questions about integration, contact: Golden G. Richard III
// (golden@cct.lsu.edu).
//
// Please see LICENSE.md and README.md for further information.
//
//

/*
 * @author Jacob Tucker
 */

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"

#include "scalpel.h"
#include <stdint.h>
#include <stdio.h>

#define SUBFILE_NAMESIZE 32

/**
* @param               data: pointer to the data block to be checked
* @param               length: the length of the data block;
* @param               decision: pointer to the decision;
                       this gets populated with either VALID or INVALID
* @param               validates_to: pointer to last valid location
* @param               needleidx: index into array of file types
* @param               blocksize: the size of each block in the image
*
* @return              needleidx
* @side-effects        modifies 'decision' and 'validates_to' pointers
*                      based on validation results
**/
static inline uint32_t csv_master_block_validate(char *data,
                                                 uint64_t length,
                                                 BlockValidationDecision *decision,
                                                 uint64_t *validates_to,
                                                 uint32_t needleidx,
                                                 uint32_t blocksize,
                                                 void *blockhashkey);

uint8_t is_delimiter(const char c);
uint64_t calc_significant_length(const char *data, const uint64_t length);

static inline uint32_t csv_master_block_validate(char *data,
                                                 uint64_t length,
                                                 BlockValidationDecision *decision,
                                                 uint64_t *validates_to,
                                                 uint32_t needleidx,
                                                 uint32_t blocksize,
                                                 void *blockhashkey) {
  (void)blocksize;
  *validates_to = 0;
  *decision = BLOCK_CONFIDENCE_VALID;
  uint8_t in_quotes = 0, is_last_char = 0, delimiter_set = 0;
  size_t delimiters_in_line = 0, expected_delim_per_line = 0;
  uint64_t prev_record_idx = 0, curr_record_idx = 0, significant_length = 0;
  char prev_char = '\0', curr_char = '\0', delimiter = ',';
  char filetype[SUBFILE_NAMESIZE] = {'\0'};

  significant_length = calc_significant_length(data, length);

  if (significant_length == 0) {
    *decision = BLOCK_CONFIDENCE_INVALID;
    *validates_to = 0;
    return needleidx;
  }

  for (uint64_t i = 0; i != significant_length; ++i) {
    prev_char = curr_char;
    curr_char = data[i];
    is_last_char = (i + 1 == significant_length);

    if (curr_char == '"') {
      in_quotes = ! in_quotes;
      // if the quote is the last char in the block to check,
      // we need to do the end of record processing rather than
      // continuing to the next character
      if (! is_last_char) {
        continue;
      }
    }

    // handle mismatched quotes
    if (is_last_char && in_quotes) {
      *decision = BLOCK_CONFIDENCE_INVALID;
      // no delimiters were encountered before the quote
      // or is a single row
      if (expected_delim_per_line == 0 || prev_record_idx == 0) {
        *validates_to = 0;
      }
      // otherwise the last record was valid
      else {
        *validates_to = curr_record_idx - 1;
      }
      return needleidx;
    }

    if (! in_quotes) {
      // invalid if starting record with delimiter
      if ((prev_char == '\n' || i == 0) && curr_char == delimiter) {
        *decision = BLOCK_CONFIDENCE_INVALID;
        *validates_to = (curr_record_idx == 0) ? 0 : i - 1;
        return needleidx;
      }

      // set specific delimiter being used
      if ((! delimiter_set) && is_delimiter(curr_char)) {
        delimiter = curr_char;
        delimiter_set = 1;
      }

      // back-to-back delimiters aren't allowed
      // but don't handle end of record state yet
      if (prev_char == delimiter && curr_char == delimiter && ! is_last_char) {
        *decision = BLOCK_CONFIDENCE_INVALID;
        *validates_to = i - 1;
        return needleidx;
      }

      if (curr_char == delimiter) {
        delimiters_in_line++;
      }

      // invalid space or tab
      if ((curr_char == ' ' && prev_char != delimiter) || curr_char == '\t') {
        *decision = BLOCK_CONFIDENCE_INVALID;
        *validates_to = i - 1;
        return needleidx;
      }

      // reached end of record
      if (curr_char == '\n' || is_last_char) {
        // invalid if only 1 or 2 records
        if (is_last_char && prev_record_idx == 0) {
          *decision = BLOCK_CONFIDENCE_INVALID;
          *validates_to = 0;
          return needleidx;
        }

        // invalid if ending record on delimiter
        // when its not the end of the block (accounts for cut off)
        // unless it is the 2nd record (previous check covers this)
        if (prev_char == delimiter && ! is_last_char) {
          delimiters_in_line--;
          *decision = BLOCK_CONFIDENCE_INVALID;
          *validates_to = (is_last_char) ? i - 1 : i - 2;
          return needleidx;
        }

        // use 2nd record as reference for correct delimiter count;
        // not using 1st record accounts for the potential of a block
        // beginning in the middle of the record
        if (curr_record_idx != 0 && prev_record_idx == 0) {
          expected_delim_per_line = delimiters_in_line;
        }

        // invalid if only 1 field - could steal blocks from other validators
        if (
            (delimiters_in_line == 0 && curr_record_idx != 0 && ! is_last_char) ||
            (expected_delim_per_line == 0 && curr_record_idx != 0)) {
          *decision = BLOCK_CONFIDENCE_INVALID;
          *validates_to = (curr_record_idx > 1) ? curr_record_idx - 1 : 0;
          return needleidx;
        }

        // record had incorrect number of delimiters;
        // exceptions are if it is not done checking the 2nd record
        // (no reference for comparison yet) and if it is the last record
        // (to account for the block ending in the middle of a record)
        if (
            (delimiters_in_line != expected_delim_per_line) &&
            (curr_record_idx != 0) &&
            (! is_last_char)) {
          *decision = BLOCK_CONFIDENCE_INVALID;
          *validates_to = curr_record_idx - 1;
          return needleidx;
        }

        // prepare for next record if this isn't the last record
        if (! is_last_char) {
          delimiters_in_line = 0;
          prev_record_idx = curr_record_idx;
          curr_record_idx = i + 1;
        }
      }
    }
  }

  if (*decision == BLOCK_CONFIDENCE_VALID) {
    *validates_to = significant_length - 1;
#ifndef CSV_TEST
    size_t columns = expected_delim_per_line + 1;
    snprintf(filetype, SUBFILE_NAMESIZE, "%lu-col.csv", columns);
    needleidx = add_file_subtype(needleidx, filetype);
#endif
  }

  return needleidx;
}

uint8_t is_delimiter(const char c) {
  return (
      c == ',' ||
      c == ';' ||
      c == '|');
}

uint64_t calc_significant_length(const char *data, const uint64_t length) {
  uint64_t significant_length = 0;
  uint8_t all_whitespace = 1, all_zeroes = 1;

  // catch 0 length blocks
  if (length == 0) {
    return significant_length;
  }

  // don't feed binary data to block validator
  while (significant_length < length &&
         (isprint(data[significant_length]) ||
          isspace(data[significant_length]))) {
    // don't feed blocks that are all whitespace or zero to the block validator
    if (all_whitespace && data[significant_length] > ' ') {
      all_whitespace = 0;
    }
    if (all_zeroes && data[significant_length] != 0) {
      all_zeroes = 0;
    }
    significant_length++;
  }

  if (all_whitespace || all_zeroes) {
    significant_length = 0;
  }

  return significant_length;
}

#pragma GCC diagnostic pop
