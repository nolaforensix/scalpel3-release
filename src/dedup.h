//
// Scalpel3 is Copyright(C) 2021 - 2026 by Golden G.Richard III and contributors.
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
//-----------------------------
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
