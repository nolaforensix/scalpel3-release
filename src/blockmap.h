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
// Blockmap design and implementation Copyright (c) 2021-2026 by Golden G. Richard III and 2024-2026
// by Karley Waguespack. Blockmaps handle block coverage, deduplication, and block reservations in
// scalpel3.
//
// IMPORTANT: synchronization and thread-safety in blockmap.c functions are optimized for maximum
// performance in scalpel3 and may not be appropriate in other multithreaded contexts. For example,
// blockmap cloning is always done in a single-threaded context in scalpel3, therefore locks are not
// needed.
//

#if ! defined(BLOCKMAP_H)
#define BLOCKMAP_H

// New blockmap format for scalpel3, which supports deduplication:
//                                C                   D                    E                   Z                     R                        T
// [blocksize] [# blocks]  [coverage bitmap]  [  dedup bitmap ]   [ exemplar bitmap ]     [zero bitmap]      [ dedup refcounts ]     [reservation count]
//   uint32_t   uint64_t   one bit per block  one bit per block    one bit per block    one bit per block     int64_t per block       int64_t per block
//
// Given C / D / E bits for block j:
//
// 0 / 0 / 0:  UNCOVERED block that is either not a duplicate of any
//             other block or dedup is off. R[j] is 1.
//
// 0 / 1 / 0:  UNCOVERED dedup non-exemplar block with associated
//             reference count in R[R[j]].  Non-exemplar duplicates
//             are seen only by contiguous recovery phases in
//             scalpel3, not reassembly threads.
//
// 0 / 1 / 1:  UNCOVERED dedup exemplar block with associated reference
//             count of uncovered duplicates in R[j].  If R[j] is 0,
//             this block and all duplicates are covered.  If this
//             block is not covered, it is seen by both contiguous and
//             reassembly threads.
//
// 1 / 0 / 0:  COVERED block that is either not a duplicate of any
//             other block or dedup is off. R[j] is 0.
//
// 1 / 1 / 0:  COVERED dedup non-exemplar block with associated
//             reference count in R[R[j]].
//
// 1 / 1 / 1:  COVERED dedup exemplar block with associated reference
//             count of uncovered duplicates in R[j].
//
// All other combinations for C / D / E are reserved.
//
// Z bits indicate whether the associated blocks contains only binary zeros.
//
// T counts indicate how many times a block has been reserved (that is, the
// number times the block appears in a blockvector in any position).
//

#include "colors.h"
#include "dedup.h"
#include <inttypes.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

// main blockmap type
typedef struct Blockmap {
  // public, read-only

  uint32_t blocksize;          // blocksize for image file
  uint64_t numblocks;          // number of blocks in image file and length of R, T
  uint64_t start_block;        // blocks outside the window start_block...end_block
  uint64_t end_block;          // are not deduped and considered covered by
                               // is_block_covered() regardless of the value of their
                               // C bit.

  // PRIVATE, except for crblockmap.c and modblockmap

  uint64_t bitmap_length;      // length of C, D, E, Z in bytes
                               // operations on single unsigned chars are guaranteed to be atomic
                               // on modern Intel/AMD/Apple Silicon processors
  atomic_uchar *coveragemap;   // C
  atomic_uchar *dedupmap;      // D
  atomic_uchar *exemplarmap;   // E
  atomic_uchar *zeromap;       // Z
  atomic_llong *refcounts;     // R
  atomic_llong *reservations;  // T
} Blockmap;

// prototypes for visible blockmap.c functions
void cover_block(Blockmap *blockmap, int64_t j);
void uncover_block(Blockmap *blockmap, int64_t j);
void reserve_block(Blockmap *blockmap, int64_t j);
void unreserve_block(Blockmap *blockmap, int64_t j);
void display_blockmap_entry(Blockmap *blockmap, int64_t j);
void display_blockmap(Blockmap *blockmap);
void diff_blockmaps(Blockmap *blockmap1, Blockmap *blockmap2);
bool allocate_blockmap(Blockmap **blockmap, uint32_t blocksize, uint64_t numblocks);
void free_blockmap(Blockmap **blockmap);
void set_blockmap_window(Blockmap *blockmap, uint64_t start_block, uint64_t end_block);
bool dedup_blockmap(Blockmap *blockmap, FILE *imgfile, uint64_t *deduped, uint64_t *zeroblocks, bool progress);
bool clone_blockmap(Blockmap *src, Blockmap **dest);
bool write_blockmap(Blockmap *blockmap, FILE *blockmapfile);
bool read_blockmap(Blockmap **blockmap, FILE *blockmapfile);
bool write_blockmap_h(Blockmap *blockmap, int handle);
bool read_blockmap_h(Blockmap **blockmap, int handle);
bool is_zero_block(Blockmap *blockmap, int64_t j);
bool is_exemplar_block(Blockmap *blockmap, int64_t j);
bool is_block_covered(Blockmap *blockmap, int64_t j);
bool is_block_selectable(Blockmap *blockmap, int64_t j);
int64_t is_block_reserved(Blockmap *blockmap, int64_t j);
int64_t get_exemplar(Blockmap *blockmap, int64_t j);
uint64_t get_reference_count(Blockmap *blockmap, int64_t j);
void set_bit(atomic_uchar *bitmap, uint64_t j);
void clear_bit(atomic_uchar *bitmap, uint64_t j);
bool is_bit_set(atomic_uchar *bitmap, uint64_t j);

#endif /* BLOCKMAP_H */

