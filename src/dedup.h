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

#include <stdint.h>
#include <stdbool.h>
#include <stdint.h>
#include <inttypes.h>
#include "hashv4.h"
#define XXH_INLINE_ALL
#include "xxhash.h"

// prototypes for shahash.c functions
uint64_t oa_sha_hash(const void *s);
void *oa_sha_cp(const void *s);
bool oa_sha_eq(const void *s1, const void *s2);
void oa_sha_free(void **s);
size_t oa_sha_sizeof(const void *s);
void *oa_uint64_t_cp(const void *s);
size_t oa_uint64_t_sizeof(const void *s);

extern oa_key_ops oa_key_ops_sha;
extern oa_val_ops oa_val_ops_sha;
