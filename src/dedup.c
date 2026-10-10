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

