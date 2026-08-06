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
// Uncompressed set of longs data structure, written by Golden G. Richard III (@nolaforensix), 2024.
//

#if ! defined(SETOFLONGS_H)
#define SETOFLONGS_H

#include "colors.h"
#include <ctype.h>
#include <inttypes.h>
#include <limits.h>
#include <math.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// type for set of int64_ts
typedef struct LongsSet {
  int64_t *set;
  int64_t len;
} LongsSet;


// function prototypes for public functions
int compare_longs(const void *a, const void *b);
void create_LongsSet(LongsSet **set);
void display_LongsSet(const LongsSet *set);
LongsSet *union_longsSets(const LongsSet *set1, const LongsSet *set2);
bool any_intersection_LongsSets(const LongsSet *set1, const LongsSet *set2,
                                int64_t *common);
void add_to_LongsSet(LongsSet *set, int64_t start, int64_t end);
void destroy_LongsSet(LongsSet **set);
bool binary_in_LongsSet(const LongsSet *set, int64_t target);
bool linear_in_LongsSet(const LongsSet *set, int64_t target);

#endif

