//
// Scalpel3 is Copyright(C) 2021 - 2026 by Golden G. Richard III and contributors.
//
// This program is free software : you can redistribute it and / or modify it under the terms of the GNU General Public
// License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later
// version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied
// warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along with this program. If not, see
// <https://www.gnu.org/licenses/>.
//
//-----------------------------
// Additional Integration Terms
// ----------------------------
//
// Linking or embedding Scalpel3 (statically or dynamically) into another program such that the resulting executable or
// library forms a single combined work constitutes creation of a derivative work under the GPL. Any party distributing
// such a combined work must make the entire source code available under the terms of the GPL as well.
//
// Commercial entities wishing to use Scalpel3 in a closed-source or proprietary product or requiring support must
// obtain a separate commercial license.
//
// For commercial licensing or questions about integration, contact: Golden G. Richard III (golden@cct.lsu.edu).
//
// Please see LICENSE.md and README.md for further information.
//
//

#include "dedup.h"

//
// Support functions for block dedup

// hash functions to support 256-bit sha256 hashes
uint64_t oa_sha_hash(const void *s) {

  return XXH3_64bits(s, 32);
}


void *oa_sha_cp(const void *s) {

  const unsigned char *input = (const unsigned char *)s;
  unsigned char *result;

  result = calloc(32, 1);

  if (! result) {
    fprintf(stderr, "malloc() failed in file %s at line # %d.", __FILE__, __LINE__);
    exit(EXIT_FAILURE);
  }

  memcpy(result, input, 32);

  return result;
}


bool oa_sha_eq(const void *s1, const void *s2) {

  return memcmp((void *)s1, (void *)s2, 32) ? false : true;
}


// returns size of hash
size_t oa_sha_sizeof(const void *s) {
  (void)s;
  return 32;
}


void oa_sha_free(void **s) {

  free(*s);
  *s = NULL;
}


// returns size of uint64_t
size_t oa_uint64_t_sizeof(const void *s) {
  (void)s;
  return sizeof(uint64_t);
}


void *oa_uint64_t_cp(const void *s) {

  uint64_t *input = (uint64_t *)s;
  uint64_t *result;

  result = calloc(1, sizeof(uint64_t));

  if (! result) {
    fprintf(stderr, "malloc() failed in file %s at line # %d.", __FILE__, __LINE__);
    exit(EXIT_FAILURE);
  }

  *result = *input;
  return result;
}


// hash operations for sha256 hash table
oa_key_ops oa_key_ops_sha = { .hash = oa_sha_hash,
                              .cp = oa_sha_cp,
                              .free = oa_sha_free,
                              .eq = oa_sha_eq,
                              .serialize = NULL,
                              .size_of = oa_sha_sizeof };

oa_val_ops oa_val_ops_sha = { .cp = oa_uint64_t_cp,
                              .free = oa_sha_free,
                              .serialize = NULL,
                              .size_of = oa_uint64_t_sizeof };

