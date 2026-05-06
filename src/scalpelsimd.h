//
// Scalpel3 is Copyright(C) 2021 - 2026 by Golden G.Richard III and contributors.
//
// This program is free software : you can redistribute it and / or modify it under the terms of the
// GNU General Public License as published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
// even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
// General Public License for more details.
//
// You should have received a copy of the GNU General Public License along with this program.  If
// not, see <https://www.gnu.org/licenses/>.
//
//-----------------------------
// Additional Integration Terms
// ----------------------------
//
// Linking or embedding Scalpel3 (statically or dynamically) into another program such that the
// resulting executable or library forms a single combined work constitutes creation of a derivative
// work under the GPL.  Any party distributing such a combined work must make the entire source code
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
// Scalpel3 SIMD isolation header
//

#ifndef SCALPELSIMD_H
#define SCALPELSIMD_H

#define _GNU_SOURCE 1
#include <inttypes.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#define SCALPEL3_USE_SIMD 1
#define SCALPEL3_SIMD_THRESHOLD 24

typedef struct FirstByteSet {
  uint64_t bitmap[4];
} FirstByteSet;


static inline bool fbs_contains(const FirstByteSet *fbs, unsigned char byte) {
  return (fbs->bitmap[byte >> 6] >> (byte & 0x3F)) & 1;
}


static inline void fbs_add(FirstByteSet *fbs, unsigned char byte) {
  fbs->bitmap[byte >> 6] |= (1ULL << (byte & 0x3F));
}


static inline void fbs_clear(FirstByteSet *fbs) {
  fbs->bitmap[0] = fbs->bitmap[1] = fbs->bitmap[2] = fbs->bitmap[3] = 0;
}


// pattern entry with wildcard support
typedef struct PatternEntry {
  const char *pattern;
  size_t length;
  uint32_t spec_idx;
  bool is_header;

  bool has_wildcards;
  bool *wildcard_mask;  // true = wildcard, false = exact byte

  uint64_t first8;
  uint32_t first4;
  uint16_t next2;
  bool has_first8;
} PatternEntry;


// pattern list with indexing
typedef struct PatternList {
  PatternEntry *patterns;
  uint32_t num_patterns;
  FirstByteSet first_bytes;
  FirstByteSet valid_second_bytes[256];

  // O(1) lookup by first byte
  PatternEntry **pattern_index[256];
  uint16_t pattern_counts[256];

  unsigned char target_array[256];
  int num_targets;

  void *simd_target_vectors;
  size_t simd_vector_size;
} PatternList;


// function prototypes for public scalpelsimd.c functions
void print_simd_banner(void);
void simd_get_match_mask_64(const unsigned char *chunk_64_bytes,
                              PatternList *pl,
                              uint64_t *out_mask);
int64_t contains_int64_t(const int64_t *array, uint64_t count, int64_t target);
void *memset_int64_t(int64_t *arr, int64_t val, uint64_t len);
void *memset_uint64_t(uint64_t *arr, uint64_t val, uint64_t len);
char *s3_exact_simd_or_scalar(char *needle, size_t m, char *hay, size_t n, size_t start_pos);
void simd_build_target_vectors(PatternList *pl);
void simd_free_target_vectors(void *vectors);

// PNG SIMD row processing
// filttype: 0=None, 1=Sub, 2=Up, 3=Average, 4=Paeth
// Returns the MAD (Mean Absolute Difference) between the reconstructed cur_row and prev_row.
double simd_png_reconstruct_row(int filttype, uint32_t bpp, uint32_t row_bytes,
                                const uint8_t *filtered_row,
                                uint8_t *cur_row, const uint8_t *prev_row);

#endif // SCALPELSIMD_H
