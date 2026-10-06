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

