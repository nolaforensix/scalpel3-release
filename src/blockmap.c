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

// Blockmap design and implementation Copyright (c) 2021-2026 by Golden G. Richard III and 2024-2026 by Karley Waguespack.
// Blockmaps handle block coverage, deduplication, and block reservations in scalpel3.
//

#include "blockmap.h"
#include "dedup.h"
#include "scalpel.h"


// set C / D / E / R to cover block 'j'
void cover_block(Blockmap *blockmap, int64_t j) {

  //
  // bitmap and refcount transitions for block coverage:
  //
  // input C / D / E for block j    output C / D / E / R
  // -----------------------        ---------------------
  //
  //    0 / 0 / 0                   1 / 0 / 0 for block j
  //                                R[j] = 0
  //
  //    0 / 1 / 0                   1 / 1 / 0 for block j
  //                                R[R[j]]--
  //                                if [R[R[j]] == 0 then 1 / 1 / 1 for block R[j]
  //
  //    0 / 1 / 1                   R[j]--
  //                                if R[j] == 0 then 1 / 1 / 1 for block j
  //
  //
  //    1 / 0 / 0                   no changes (j is already covered)
  //
  //    1 / 1 / 0                   no changes (j is already covered)
  //
  //    1 / 1 / 1                   no changes (j is already covered)
  //

  if (! is_bit_set(blockmap->dedupmap, j) &&                 //  0 / 0 / 0
      ! is_bit_set(blockmap->exemplarmap, j)) {
    set_bit(blockmap->coveragemap, j);
    atomic_store_explicit(&blockmap->refcounts[j], 0, memory_order_release);

  }
  else if (! is_bit_set(blockmap->coveragemap, j) &&        //   0 / 1 / 0
           is_bit_set(blockmap->dedupmap, j) &&
           ! is_bit_set(blockmap->exemplarmap, j)) {
    set_bit(blockmap->coveragemap, j);
    if (atomic_fetch_add_explicit(&(blockmap->refcounts[blockmap->refcounts[j]]),
                                  -1, memory_order_acq_rel) == 1) {
      // exemplar is now covered, which means none of the associated
      // duplicate blocks remains uncovered.  The other associated
      // duplicate blocks will be lazily covered if their coverage
      // status is checked via is_block_covered().
      set_bit(blockmap->coveragemap, blockmap->refcounts[j]);
    }
  }
  else if (! is_bit_set(blockmap->coveragemap, j) &&        //   0 / 1 / 1
           is_bit_set(blockmap->dedupmap, j) &&
           is_bit_set(blockmap->exemplarmap, j)) {
    if (atomic_fetch_add_explicit(&(blockmap->refcounts[j]),
                                  -1, memory_order_acq_rel) == 1) {
      // exemplar is now covered, which means none of these duplicate
      // blocks remains uncovered.  Those duplicates will be lazily
      // covered if their coverage is checked via is_block_covered().
      set_bit(blockmap->coveragemap, j);
    }
  }
}


// set C / D / E / R to uncover block 'j'
void uncover_block(Blockmap *blockmap, int64_t j) {
  //
  // bitmap and refcount transitions for block uncoverage:
  //
  // input C / D /E for block j     output C / D / E / R
  // -----------------------        ---------------------
  //
  //    0 / 0 / 0                   no changes (block is already uncovered)
  //
  //    0 / 1 / 0                   no changes (block is already uncovered)
  //
  //    0 / 1 / 1                   no changes (block is already uncovered)
  //
  //    1 / 0 / 0                   0 / 0 / 0 for block j
  //                                R[j] = 1
  //
  //    1 / 1 / 0                   0 / 1 / 0 for block j
  //                                R[R[j]]++
  //                                0 / 1 / 1 for block R[j]
  //
  //    1 / 1 / 1                   0 / 1 / 1 for block j
  //                                R[j]++
  //

  if (is_bit_set(blockmap->coveragemap, j) &&       //       1 / 0 / 0
      ! is_bit_set(blockmap->dedupmap, j) &&
      ! is_bit_set(blockmap->exemplarmap, j)) {
    clear_bit(blockmap->coveragemap, j);
    atomic_store_explicit(&blockmap->refcounts[j], 1, memory_order_release);
  }
  else if (is_bit_set(blockmap->coveragemap, j) &&  //       1 / 1 / 0
           is_bit_set(blockmap->dedupmap, j) &&
           ! is_bit_set(blockmap->exemplarmap, j)) {
    clear_bit(blockmap->coveragemap, j);
    atomic_fetch_add_explicit(&(blockmap->refcounts[blockmap->refcounts[j]]),
                              1, memory_order_acq_rel);
    // exemplar block is uncovered because reference count > 0
    clear_bit(blockmap->coveragemap, blockmap->refcounts[j]);
  }
  else if (is_bit_set(blockmap->coveragemap, j) &&  //       1 / 1 / 1
           is_bit_set(blockmap->dedupmap, j) &&
           is_bit_set(blockmap->exemplarmap, j)) {
    clear_bit(blockmap->coveragemap, j);
    atomic_fetch_add_explicit(&(blockmap->refcounts[j]),
                              1, memory_order_acq_rel);
  }
}


// add one reservation for the exemplar of block 'j'
void reserve_block(Blockmap *blockmap, int64_t j) {

  if (j >= 0) {
    atomic_fetch_add_explicit(&(blockmap->reservations[get_exemplar(blockmap, j)]), 1, memory_order_acq_rel);
  }
}


// remove one reservation for the exemplar of block 'j'
void unreserve_block(Blockmap *blockmap, int64_t j) {

  if (j >= 0) {
    atomic_fetch_add_explicit(&(blockmap->reservations[get_exemplar(blockmap, j)]), -1, memory_order_acq_rel);
  }
}


// if a block is deduplicated, returns the actual blocknumber of the exemplar for block 'j', otherwise returns 'j'
int64_t get_exemplar(Blockmap *blockmap, int64_t j) {

  if (is_bit_set(blockmap->dedupmap, j) && ! is_bit_set(blockmap->exemplarmap, j)) {
    return atomic_load_explicit(&blockmap->refcounts[j], memory_order_acquire);
  }
  else {
    return j;
  }
}


// return reference count for the exemplar of actual blocknumber 'j'
uint64_t get_reference_count(Blockmap *blockmap, int64_t j) {

  return atomic_load_explicit(&(blockmap->refcounts[get_exemplar(blockmap, j)]), memory_order_acquire);
}


// determine if a block 'j' is covered. A block is covered if its C bit is set or if the block number lies outside of
// the window start_block...end_block
bool is_block_covered(Blockmap *blockmap, int64_t j) {

  bool covered = is_bit_set(blockmap->coveragemap, j);
  bool dedup;
  bool exemplar;

  if (covered || (uint64_t)j < blockmap->start_block || (uint64_t)j > blockmap->end_block) {
    return true;
  }
  else {
    dedup = is_bit_set(blockmap->dedupmap, j);
    exemplar = is_bit_set(blockmap->exemplarmap, j);
    if (! dedup || exemplar) {
      return covered;
    }
    else {
      // slightly more expensive case--duplicate and not exemplar. Lazily cover non-exemplar deduplicated block when the
      // reference count for the exemplar has reached zero (all blocks of this type are now covered).
      if (atomic_load_explicit(&(blockmap->refcounts[blockmap->refcounts[j]]), memory_order_acquire) == 0) {
        set_bit(blockmap->coveragemap, j);
        return true;
      }
      else {
        return false;
      }
    }
  }
}


// determine if a block 'j' is an exemplar block
bool is_exemplar_block(Blockmap *blockmap, int64_t j) {

  return is_bit_set(blockmap->exemplarmap, j);
}


// determine if a block 'j' contains all zeros
bool is_zero_block(Blockmap *blockmap, int64_t j) {

  return is_bit_set(blockmap->zeromap, j);
}


// return the number of active reservations for a block's exemplar
int64_t is_block_reserved(Blockmap *blockmap, int64_t j) {

  return atomic_load_explicit(&(blockmap->reservations[get_exemplar(blockmap, j)]), memory_order_acquire);
}


// determine if a block 'j' can be selected for a reassembly effort--this is different than
// coverage, because deduplication has an impact on block selectability. Non-deduped, uncovered
// blocks (0 / 0 / 0) are always selectable, but for deduped blocks, only uncovered exemplar blocks
// (0 / 1 / 1) are selectable.  For a block to be selectable, it must also be in the current carve
// window.
bool is_block_selectable(Blockmap *blockmap, int64_t j) {

  return (uint64_t)j >= blockmap->start_block &&
	 (uint64_t)j <= blockmap->end_block &&
	 ! is_bit_set(blockmap->coveragemap, j) &&
         is_bit_set(blockmap->dedupmap, j) == is_bit_set(blockmap->exemplarmap, j);
}


// display the coveragemap, dedup map, exemplar map, zero map and reference count for a specific block 'j' without a
// trailing newline
//
// THIS FUNCTION IS NOT THREAD-SAFE.
void display_blockmap_entry(Blockmap *blockmap, int64_t j) {

  fprintf(stdout, "%c", is_bit_set(blockmap->coveragemap, j) ? '1' : '0');
  fprintf(stdout, " / ");
  fprintf(stdout, "%c", is_bit_set(blockmap->dedupmap, j) ? '1' : '0');
  fprintf(stdout, " / ");
  fprintf(stdout, "%c", is_bit_set(blockmap->exemplarmap, j) ? '1' : '0');
  fprintf(stdout, " / ");
  fprintf(stdout, "%c", is_bit_set(blockmap->zeromap, j) ? '1' : '0');
  fprintf(stdout, " / ");
  fprintf(stdout, "%8" PRId64 "",
          (int64_t)atomic_load_explicit(&(blockmap->reservations[get_exemplar(blockmap, j)]), memory_order_acquire));
  fprintf(stdout, " / ");
  fprintf(stdout, "%8" PRId64 "%s", (int64_t)atomic_load_explicit(&(blockmap->refcounts[j]), memory_order_acquire),
          (is_bit_set(blockmap->dedupmap, j) && ! is_bit_set(blockmap->exemplarmap, j)) ? " [index of exemplar]" : "");
}


// changes the active window in the blockmap. Blocks outside the window are implicitly considered covered, regardless of
// the value of the their C bit. dedup_blockmap() MUST be called after the window is changed, to recalculate dedup
// information.
//
// THIS FUNCTION IS NOT THREAD-SAFE.
void set_blockmap_window(Blockmap *blockmap, uint64_t start_block, uint64_t end_block) {

  if (start_block == blockmap->start_block && end_block == blockmap->end_block) {
    return;
  }

  if (blockmap->numblocks == 0) {
    blockmap->start_block = 0;
    blockmap->end_block = 0;
    return;
  }

  if (start_block >= blockmap->numblocks) {
    fprintf(stderr, "%s", BLUE);
    fprintf(stderr,
            "\n\nWARNING: start block %" PRIu64 " for active carve window adjusted to max block number %" PRIu64
            ".\n\n",
            start_block, blockmap->numblocks - 1);
    fprintf(stderr, "%s", BLACK);
    start_block = blockmap->numblocks - 1;
  }

  if (end_block >= blockmap->numblocks) {
    fprintf(stderr, "%s", BLUE);
    fprintf(stderr,
            "\n\nWARNING: end block %" PRIu64 " for active carve window adjusted to max block number %" PRIu64 ".\n\n",
            end_block, blockmap->numblocks - 1);
    fprintf(stderr, "%s", BLACK);
    end_block = blockmap->numblocks - 1;
  }

  blockmap->start_block = start_block;
  blockmap->end_block = end_block;
}


// wipe all dedup and reservation data for the blockmap and recalculate dedup information for blocks
// between blockmap->start_block and blockmap->end_block for the image file 'imagefile'. Sets
// 'deduped' and 'zero' to the number of deduped and zero blocks in the blockmap window,
// respectively.  A progress message is written to stdout if 'progress' is true.
//
// THIS FUNCTION IS NOT THREAD-SAFE.
bool dedup_blockmap(Blockmap *blockmap, FILE *imgfile, uint64_t *deduped, uint64_t *zeroblocks, bool progress) {

  unsigned char *block = NULL;
  unsigned char *block2 = NULL;
  unsigned char *ZEROBLOCK = NULL;
  unsigned char sha256zero[32];
  unsigned char sha256[32];
  oa_hash *sha256ht = NULL;
  int64_t *key;
  uint64_t i;
  int64_t j;
  int perc1, perc2;

  *deduped = 0;
  *zeroblocks = 0;

  if (! (block = malloc(blockmap->blocksize))) {
    fprintf(stderr, "%s", RED);
    fprintf(stderr, "Memory exhausted while allocating block.\n");
    fprintf(stderr, "%s", BLACK);
    goto die;
  }

  if (! (block2 = malloc(blockmap->blocksize))) {
    fprintf(stderr, "%s", RED);
    fprintf(stderr, "Memory exhausted while allocating block.\n");
    fprintf(stderr, "%s", BLACK);
    goto die;
  }

  if (! (ZEROBLOCK = calloc(blockmap->blocksize, 1))) {
    fprintf(stderr, "%s", RED);
    fprintf(stderr, "Memory exhausted while allocating zero block.\n");
    fprintf(stderr, "%s", BLACK);
    goto die;
  }

  SHA256((unsigned char *)ZEROBLOCK, blockmap->blocksize, sha256zero);

  // clear all current dedup info

  for (i = 0; i < blockmap->bitmap_length; i++) {
    atomic_store_explicit(&blockmap->dedupmap[i], 0, memory_order_release);
    atomic_store_explicit(&blockmap->exemplarmap[i], 0, memory_order_release);
    atomic_store_explicit(&blockmap->zeromap[i], 0, memory_order_release);
  }

  for (i = 0; i < blockmap->numblocks; i++) {
    atomic_store_explicit(&blockmap->refcounts[i], 0, memory_order_release);
  }

  // find and record duplicate and zero blocks in window

  // initialize hash table for dedup detection
  sha256ht = oa_hash_new(oa_key_ops_sha, oa_val_ops_sha);

  if (progress) {
    // populate coveragemap, dedupmap, exemplarmap, zeromap, and refcounts
    fprintf(stdout, "Finding duplicate and zero blocks for window %" PRIu64 " - %" PRIu64 ", please be patient...    ",
            blockmap->start_block, blockmap->end_block);
    fflush(stdout);
  }

  perc1 = 0;
  perc2 = 0;
  for (i = blockmap->start_block; i <= blockmap->end_block; i++) {
    if (progress) {
      perc2 = (int)((double)(i - blockmap->start_block) / (double)(blockmap->end_block - blockmap->start_block + 1) * (double)100);
      if (perc1 != perc2 && isatty(1)) {
        perc1 = perc2;
        fprintf(stderr, "\b\b\b\b%3d%%", perc1);
      }
    }

    // read block
    bzero(block, blockmap->blocksize);
    fseek(imgfile, i * blockmap->blocksize, SEEK_SET);
    // allow short reads, which may happen for last block
    if (fread(block, 1, blockmap->blocksize, imgfile) < 1 && ferror(imgfile)) {
      fprintf(stderr, "%s", RED);
      fprintf(stderr, "\nCouldn't read block %" PRIu64 " from image file.\n", i);
      fprintf(stderr, "%s", BLACK);
      goto die;
    }

    SHA256((unsigned char *)block, blockmap->blocksize, sha256);

    // insert sha256 hash into hash table for dedup lookup, unless it's already there
    if (! oa_hash_get(sha256ht, sha256)) {
      oa_hash_put(sha256ht, sha256, &i);
    }

    // see if it's a zero block
    if (! memcmp(sha256, sha256zero, 32)) {
      set_bit(blockmap->zeromap, i);
      (*zeroblocks)++;
    }

    // see if it's a duplicate block
    if (i > 0) {
      key = (int64_t *)oa_hash_get(sha256ht, sha256);
      j = key ? (*key < (int64_t)i ? *key : -1) : -1;

      if (j >= 0) {
        // potential duplicate--verify that there's no SHA256 hash collision by comparing block data directly

        bzero(block2, blockmap->blocksize);
        fseek(imgfile, j * blockmap->blocksize, SEEK_SET);
        if (fread(block2, 1, blockmap->blocksize, imgfile) < 1) {
          fprintf(stderr, "%s", RED);
          fprintf(stderr, "\nCouldn't read block %" PRIu64 " from image file.\n", i);
          fprintf(stderr, "%s", BLACK);
          goto die;
        }

        if (! memcmp(block, block2, blockmap->blocksize)) {
          // true duplicate
          (*deduped)++;

          // duplicate--mark earlier block as exemplar by setting dedup bit and exemplar bit
          set_bit(blockmap->dedupmap, j);
          set_bit(blockmap->exemplarmap, j);

          // increment reference count for exemplar
          if (blockmap->refcounts[j] > 0) {
            // already at least one other duplicate
            blockmap->refcounts[j]++;
          }
          else {
            // exemplar + first duplicate
            blockmap->refcounts[j] = 2;
          }

          // mark current block as uncovered, deduplicated, non-exemplar
          set_bit(blockmap->dedupmap, i);

          // reference count of current block becomes index of of exemplar
          blockmap->refcounts[i] = j;
        }
      }
    }
  }

  // now set refcount to 1 for all non-duplicated blocks
  for (i = 0; i < blockmap->numblocks; i++) {
    if (! is_bit_set(blockmap->dedupmap, i) &&
	! is_bit_set(blockmap->exemplarmap, i)) {
      blockmap->refcounts[i] = 1;
    }
  }

  if (progress) {
    if (isatty(1)) {
      fprintf(stderr, "\b\b\b\b%3d%%", 100);
    }
    fprintf(stdout, "\nFound %" PRIu64 " duplicate blocks, %" PRIu64 " zero blocks in image file.\n", *deduped,
            *zeroblocks);
  }

  free(block);
  free(block2);
  free(ZEROBLOCK);
  oa_hash_free(&sha256ht);
  return true;

 die:
  free(block);
  free(block2);
  free(ZEROBLOCK);
  oa_hash_free(&sha256ht);
  return false;
}


// display coveragemap, dedup map, and reference counts to indicate various flavors of uncovered and covered blocks
//
// THIS FUNCTION IS NOT THREAD-SAFE.
void display_blockmap(Blockmap *blockmap) {

  uint64_t zero = 0, duplicate = 0, covered = 0;

  fprintf(stdout, "Blockmap contents:\n"
                  "blocknum   C / D / E / Z /     T    / refcount\n"
                  "--------   - / - / - / - / -------- / --------\n");

  for (uint64_t i = 0; i < blockmap->numblocks; i++) {
    fprintf(stdout, "%8" PRIu64 ":  ", i);
    display_blockmap_entry(blockmap, i);

    covered += is_bit_set(blockmap->coveragemap, i) ? 1 : 0;
    duplicate += is_bit_set(blockmap->dedupmap, i) ? 1 : 0;
    zero += is_bit_set(blockmap->zeromap, i) ? 1 : 0;
    putchar('\n');
  }

  fprintf(stdout, "\n"
                  "Block Key:\n"
                  "C = covered, D = Duplicate, E = Exemplar, Z = Zero, T = # Block Reservations\n");

  fprintf(stdout, "\nBlockmap dedup / active carve window: blocks %" PRIu64 " to %" PRIu64 ".\n", blockmap->start_block,
          blockmap->end_block);

  fprintf(stdout,
          "\nStatistics: \n"
          "\t%" PRIu64 " total blocks\n"
          "\t%" PRIu64 " covered blocks\n"
          "\t%" PRIu64 " implicitly covered blocks in dedup window\n"
          "\t%" PRIu64 " duplicates in dedup window\n"
          "\t%" PRIu64 " zero blocks in dedup window\n",
          blockmap->numblocks, covered, blockmap->numblocks - (blockmap->end_block - blockmap->start_block + 1),
          duplicate, zero);
}


// display differences between two blockmaps of equal size.
//
// THIS FUNCTION IS NOT THREAD-SAFE.
void diff_blockmaps(Blockmap *blockmap1, Blockmap *blockmap2) {

  bool diffs = false;

  fprintf(stdout, "Only differences are displayed.\n\n");
  fprintf(stdout, "Blockmap # 1 contents:"
                  "\t\t\t\t\t"
                  "Blockmap # 2 contents:"
                  "\n"
                  "blocknum   C / D / E / Z / refcount"
                  "\t\t\t"
                  "blocknum   C / D / E / Z / refcount"
                  "\n"
                  "--------   - / - / - / - / --------"
                  "\t\t\t"
                  "--------   - / - / - / - / --------"
                  "\n");

  for (uint64_t i = 0; i < blockmap1->numblocks; i++) {
    if (is_bit_set(blockmap1->coveragemap, i) != is_bit_set(blockmap2->coveragemap, i) ||
        is_bit_set(blockmap1->dedupmap, i) != is_bit_set(blockmap2->dedupmap, i) ||
        is_bit_set(blockmap1->exemplarmap, i) != is_bit_set(blockmap2->exemplarmap, i) ||
        is_bit_set(blockmap1->zeromap, i) != is_bit_set(blockmap2->zeromap, i) ||
        blockmap1->reservations[i] != blockmap2->reservations[i] ||
        blockmap1->refcounts[i] != blockmap2->refcounts[i]) {
      fprintf(stdout, "%8" PRIu64 ":  ", i);
      display_blockmap_entry(blockmap1, i);
      fprintf(stdout, "\t\t\t");
      fprintf(stdout, "%8" PRIu64 ":  ", i);
      display_blockmap_entry(blockmap2, i);
      putchar('\n');
      diffs = true;
    }
  }
  putchar('\n');

  if (blockmap1->start_block != blockmap2->start_block || blockmap1->end_block != blockmap2->end_block) {
    fprintf(stdout, "Active carve windows are different.  %" PRIu64 " - %" PRIu64 " != %" PRIu64 " - %" PRIu64 ".\n",
            blockmap1->start_block, blockmap1->end_block, blockmap2->start_block, blockmap2->end_block);
    diffs = true;
  }

  if (! diffs) {
    fprintf(stdout, "\nNo differences.\n");
  }
}


// write contents of blockmap to open file descriptor 'blockmapfile'
//
// THIS FUNCTION IS NOT THREAD-SAFE.
bool write_blockmap(Blockmap *blockmap, FILE *blockmapfile) {

  bool ret = true;

  fseek(blockmapfile, 0, SEEK_SET);

  // write blocksize to blockmap
  if (fwrite(&blockmap->blocksize, sizeof(uint32_t), 1, blockmapfile) != 1) {
    fprintf(stderr, "%s", RED);
    fprintf(stderr, "Failed to write blocksize to blockmap file.\n");
    fprintf(stderr, "%s", BLACK);
    ret = false;
    goto done;
  }

  // write # blocks in image file to blockmap
  if (fwrite(&blockmap->numblocks, sizeof(int64_t), 1, blockmapfile) != 1) {
    fprintf(stderr, "%s", RED);
    fprintf(stderr, "Failed to write number of blocks to blockmap file.\n");
    fprintf(stderr, "%s", BLACK);
    ret = false;
    goto done;
  }

  // write window start block
  if (fwrite(&blockmap->start_block, sizeof(uint64_t), 1, blockmapfile) != 1) {
    fprintf(stderr, "%s", RED);
    fprintf(stderr, "Failed to write start block to blockmap file.\n");
    fprintf(stderr, "%s", BLACK);
    ret = false;
    goto done;
  }

  // write window end block
  if (fwrite(&blockmap->end_block, sizeof(uint64_t), 1, blockmapfile) != 1) {
    fprintf(stderr, "%s", RED);
    fprintf(stderr, "Failed to write end block to blockmap file.\n");
    fprintf(stderr, "%s", BLACK);
    ret = false;
    goto done;
  }

  // write coveragemap, dedup map, exemplarmap, zeromap, and reference counts
  if (fwrite(blockmap->coveragemap, sizeof(atomic_uchar), blockmap->bitmap_length, blockmapfile) !=
      (size_t)blockmap->bitmap_length) {
    fprintf(stderr, "%s", RED);
    fprintf(stderr, "Failed to write coverage map to blockmap file.\n");
    fprintf(stderr, "%s", BLACK);
    ret = false;
    goto done;
  }

  if (fwrite(blockmap->dedupmap, sizeof(atomic_uchar), blockmap->bitmap_length, blockmapfile) !=
      (size_t)blockmap->bitmap_length) {
    fprintf(stderr, "%s", RED);
    fprintf(stderr, "Failed to write dedup map to blockmap file.\n");
    fprintf(stderr, "%s", BLACK);
    ret = false;
    goto done;
  }

  if (fwrite(blockmap->exemplarmap, sizeof(atomic_uchar), blockmap->bitmap_length, blockmapfile) !=
      (size_t)blockmap->bitmap_length) {
    fprintf(stderr, "%s", RED);
    fprintf(stderr, "Failed to write exemplar map to blockmap file.\n");
    fprintf(stderr, "%s", BLACK);
    ret = false;
    goto done;
  }

  if (fwrite(blockmap->zeromap, sizeof(atomic_uchar), blockmap->bitmap_length, blockmapfile) !=
      (size_t)blockmap->bitmap_length) {
    fprintf(stderr, "%s", RED);
    fprintf(stderr, "Failed to write zero map to blockmap file.\n");
    fprintf(stderr, "%s", BLACK);
    ret = false;
    goto done;
  }

  if (fwrite(blockmap->reservations, sizeof(int64_t), blockmap->numblocks, blockmapfile) !=
      (size_t)blockmap->numblocks) {
    fprintf(stderr, "%s", RED);
    fprintf(stderr, "Failed to write reservations map to blockmap file.\n");
    fprintf(stderr, "%s", BLACK);
    ret = false;
    goto done;
  }

  if (fwrite(blockmap->refcounts, sizeof(int64_t), blockmap->numblocks, blockmapfile) != (size_t)blockmap->numblocks) {
    fprintf(stderr, "%s", RED);
    fprintf(stderr, "Failed to write refcounts map to blockmap file.\n");
    fprintf(stderr, "%s", BLACK);
    ret = false;
    goto done;
  }

  if (fflush(blockmapfile) != 0) {
    fprintf(stderr, "%s", RED);
    fprintf(stderr, "Failed to flush blockmap file.\n");
    fprintf(stderr, "%s", BLACK);
    ret = false;
  }

done:
  return ret;
}


// write blockmap to an open low-level file handle 'handle'. Returns either true for success or false for failure.
// THIS FUNCTION IS NOT THREAD-SAFE.
  bool write_blockmap_h(Blockmap *blockmap, int handle) {

    FILE *fp = NULL;
    int h = -1;
    bool ret = false;

    // use a duplicate so fclose(fp) does not close the caller's handle
    h = dup(handle);
    if (h < 0) {
      goto done;
    }

    fp = fdopen(h, "wb");
    if (! fp) {
      close(h);
      goto done;
    }

    ret = write_blockmap(blockmap, fp);

    // always close stream to flush stdio state and avoid descriptor leaks
    if (fclose(fp) != 0) {
      ret = false;
    }
    fp = NULL;

  done:
    return ret;
  }


  // allocate a new blockmap and read blockmap data from an open low-level file handle 'handle'. Returns either true for
  // success or false for failure.
  //
  // THIS FUNCTION IS NOT THREAD-SAFE.
  bool read_blockmap_h(Blockmap **blockmap, int handle) {

    FILE *fp = NULL;
    int h = -1;
    bool ret = false;

    if (! blockmap) {
      return false;
    }

    *blockmap = NULL;

    // use a duplicate so fclose(fp) does not close the caller's handle
    h = dup(handle);
    if (h < 0) {
      goto done;
    }

    fp = fdopen(h, "rb");
    if (! fp) {
      close(h);
      goto done;
    }

    ret = read_blockmap(blockmap, fp);

    // always close stream to release stdio buffers/descriptors
    if (fclose(fp) != 0) {
      free_blockmap(blockmap);
      ret = false;
    }
    fp = NULL;

  done:
    return ret;
  }


static bool checked_add_u64(uint64_t left, uint64_t right, uint64_t *result) {

  if (left > UINT64_MAX - right) {
    return false;
  }

  *result = left + right;
  return true;
}


static bool checked_multiply_u64(uint64_t left, uint64_t right, uint64_t *result) {

  if (left && right > UINT64_MAX / left) {
    return false;
  }

  *result = left * right;
  return true;
}


static bool calculate_blockmap_layout(uint64_t numblocks, uint64_t *bitmap_length, uint64_t *serialized_size) {

  uint64_t component_size;
  uint64_t size = sizeof(uint32_t) + 3 * sizeof(uint64_t);

  if (! numblocks) {
    return false;
  }

  *bitmap_length = numblocks / 8 + (numblocks % 8 != 0);

  // reject dimensions that cannot be represented by the allocation or serialization APIs
  if (numblocks > SIZE_MAX / sizeof(atomic_llong) ||
      *bitmap_length > SIZE_MAX / sizeof(atomic_uchar)) {
    return false;
  }

  if (! checked_multiply_u64(*bitmap_length, 4 * sizeof(atomic_uchar), &component_size) ||
      ! checked_add_u64(size, component_size, &size) ||
      ! checked_multiply_u64(numblocks, sizeof(int64_t), &component_size) ||
      ! checked_add_u64(size, component_size, &size) ||
      ! checked_add_u64(size, component_size, &size)) {
    return false;
  }

  *serialized_size = size;
  return true;
}


static bool validate_blockmap_contents(Blockmap *blockmap) {

  int64_t reference;

  for (uint64_t i = 0; i < blockmap->numblocks; i++) {
    bool deduplicated = is_bit_set(blockmap->dedupmap, i);
    bool exemplar = is_bit_set(blockmap->exemplarmap, i);
    int64_t reservation = atomic_load_explicit(&blockmap->reservations[i], memory_order_acquire);

    if (exemplar && ! deduplicated) {
      fprintf(stderr, "%s", RED);
      fprintf(stderr,
              "Invalid deduplication state for block %" PRIu64
              " in blockmap file--an exemplar must also be marked deduplicated.\n",
              i);
      fprintf(stderr, "%s", BLACK);
      return false;
    }

    if (reservation < 0) {
      fprintf(stderr, "%s", RED);
      fprintf(stderr, "Invalid negative reservation count for block %" PRIu64 " in blockmap file.\n", i);
      fprintf(stderr, "%s", BLACK);
      return false;
    }

    if (! deduplicated) {
      continue;
    }

    reference = atomic_load_explicit(&blockmap->refcounts[i], memory_order_acquire);

    if (exemplar) {
      if (reference < 0 || (uint64_t)reference > blockmap->numblocks) {
        fprintf(stderr, "%s", RED);
        fprintf(stderr, "Invalid reference count for exemplar block %" PRIu64 " in blockmap file.\n", i);
        fprintf(stderr, "%s", BLACK);
        return false;
      }
    }
    else {
      if (reference < 0 || (uint64_t)reference >= blockmap->numblocks) {
        fprintf(stderr, "%s", RED);
        fprintf(stderr, "Invalid exemplar reference for block %" PRIu64 " in blockmap file.\n", i);
        fprintf(stderr, "%s", BLACK);
        return false;
      }

      if (! is_bit_set(blockmap->dedupmap, (uint64_t)reference) ||
          ! is_bit_set(blockmap->exemplarmap, (uint64_t)reference)) {
        fprintf(stderr, "%s", RED);
        fprintf(stderr,
                "Invalid exemplar reference for block %" PRIu64
                " in blockmap file--block %" PRId64 " is not an exemplar.\n",
                i, reference);
        fprintf(stderr, "%s", BLACK);
        return false;
      }
    }
  }

  return true;
}


// allocate a new blockmap and read blockmap data from 'blockmapfile'. Exact serialized size is enforced for regular files;
// streams receive the same header and content validation without a file-size check.
//
// THIS FUNCTION IS NOT THREAD-SAFE.
bool read_blockmap(Blockmap **blockmap, FILE *blockmapfile) {

  uint64_t numblocks;
  uint64_t start_block;
  uint64_t end_block;
  uint64_t bitmap_length;
  uint64_t serialized_size;
  uint32_t blocksize;
  struct stat s;
  bool regular_file;
  bool ret = false;

  if (! blockmap || ! blockmapfile) {
    fprintf(stderr, "%s", RED);
    fprintf(stderr, "Invalid blockmap input.\n");
    fprintf(stderr, "%s", BLACK);
    return false;
  }

  *blockmap = NULL;

  if (fstat(fileno(blockmapfile), &s)) {
    fprintf(stderr, "%s", RED);
    fprintf(stderr, "Failed to fstat() on blockmap input.\n");
    fprintf(stderr, "%s", BLACK);
    goto done;
  }

  regular_file = S_ISREG(s.st_mode);
  if (regular_file && fseek(blockmapfile, 0, SEEK_SET)) {
    fprintf(stderr, "%s", RED);
    fprintf(stderr, "Failed to seek to the beginning of blockmap file.\n");
    fprintf(stderr, "%s", BLACK);
    goto done;
  }

  // get blocksize from blockmap file
  if (fread(&blocksize, sizeof(uint32_t), 1, blockmapfile) != 1) {
    fprintf(stderr, "%s", RED);
    fprintf(stderr, "Failed to read blocksize from blockmap file.\n");
    fprintf(stderr, "%s", BLACK);
    ret = false;
    goto done;
  }

  if (blocksize < 512 || blocksize % 512) {
    fprintf(stderr, "%s", RED);
    fprintf(stderr, "Invalid blocksize in blockmap file--it must be at least 512 and a multiple of 512.\n");
    fprintf(stderr, "%s", BLACK);
    goto done;
  }

  // get numblocks
  if (fread(&numblocks, sizeof(uint64_t), 1, blockmapfile) != 1) {
    fprintf(stderr, "%s", RED);
    fprintf(stderr, "Failed to read numblocks from blockmap file.\n");
    fprintf(stderr, "%s", BLACK);
    goto done;
  }

  // get window start block
  if (fread(&start_block, sizeof(uint64_t), 1, blockmapfile) != 1) {
    fprintf(stderr, "%s", RED);
    fprintf(stderr, "Failed to read start block from blockmap file.\n");
    fprintf(stderr, "%s", BLACK);
    goto done;
  }

  // get window end block
  if (fread(&end_block, sizeof(uint64_t), 1, blockmapfile) != 1) {
    fprintf(stderr, "%s", RED);
    fprintf(stderr, "Failed to read end block from blockmap file.\n");
    fprintf(stderr, "%s", BLACK);
    goto done;
  }

  if (! numblocks) {
    fprintf(stderr, "%s", RED);
    fprintf(stderr, "Invalid number of blocks in blockmap file--it must be greater than zero.\n");
    fprintf(stderr, "%s", BLACK);
    goto done;
  }

  if (! calculate_blockmap_layout(numblocks, &bitmap_length, &serialized_size)) {
    fprintf(stderr, "%s", RED);
    fprintf(stderr, "Blockmap dimensions are too large to represent safely.\n");
    fprintf(stderr, "%s", BLACK);
    goto done;
  }

  if (start_block > end_block || end_block >= numblocks) {
    fprintf(stderr, "%s", RED);
    fprintf(stderr,
            "Invalid active carve window %" PRIu64 "-%" PRIu64 " for a blockmap containing %" PRIu64 " blocks.\n",
            start_block, end_block, numblocks);
    fprintf(stderr, "%s", BLACK);
    goto done;
  }

  // compare the complete serialized length before allocating any blockmap arrays
  if (regular_file && (s.st_size < 0 || (uintmax_t)s.st_size != serialized_size)) {
    fprintf(stderr, "%s", RED);
    fprintf(stderr,
            "Something is wrong with the blockmap file! File size should be %" PRIu64 ", not %" PRIdMAX ".\n",
            serialized_size, (intmax_t)s.st_size);
    fprintf(stderr, "%s", BLACK);
    goto done;
  }

  // allocate new blockmap only after its complete layout has been validated
  if (! allocate_blockmap(blockmap, blocksize, numblocks)) {
    fprintf(stderr, "%s", RED);
    fprintf(stderr, "Memory exhausted while allocating blockmap.\n");
    fprintf(stderr, "%s", BLACK);
    goto done;
  }

  (*blockmap)->start_block = start_block;
  (*blockmap)->end_block = end_block;

  // get coveragemap, dedup map, exemplarmap, zeromap, and reference counts
  if (fread((*blockmap)->coveragemap, sizeof(atomic_uchar), (*blockmap)->bitmap_length, blockmapfile) !=
      (size_t)(*blockmap)->bitmap_length) {
    fprintf(stderr, "%s", RED);
    fprintf(stderr, "Failed to read coverage map from blockmap file.\n");
    fprintf(stderr, "%s", BLACK);
    goto done;
  }

  if (fread((*blockmap)->dedupmap, sizeof(atomic_uchar), (*blockmap)->bitmap_length, blockmapfile) !=
      (size_t)(*blockmap)->bitmap_length) {
    fprintf(stderr, "%s", RED);
    fprintf(stderr, "Failed to read dedup map from blockmap file.\n");
    fprintf(stderr, "%s", BLACK);
    goto done;
  }

  if (fread((*blockmap)->exemplarmap, sizeof(atomic_uchar), (*blockmap)->bitmap_length, blockmapfile) !=
      (size_t)(*blockmap)->bitmap_length) {
    fprintf(stderr, "%s", RED);
    fprintf(stderr, "Failed to read exemplar map from blockmap file.\n");
    fprintf(stderr, "%s", BLACK);
    goto done;
  }

  if (fread((*blockmap)->zeromap, sizeof(atomic_uchar), (*blockmap)->bitmap_length, blockmapfile) !=
      (size_t)(*blockmap)->bitmap_length) {
    fprintf(stderr, "%s", RED);
    fprintf(stderr, "Failed to read zero map from blockmap file.\n");
    fprintf(stderr, "%s", BLACK);
    goto done;
  }

  if (fread((*blockmap)->reservations, sizeof(int64_t), (*blockmap)->numblocks, blockmapfile) !=
      (size_t)(*blockmap)->numblocks) {
    fprintf(stderr, "%s", RED);
    fprintf(stderr, "Failed to read reservations map from blockmap file.\n");
    fprintf(stderr, "%s", BLACK);
    goto done;
  }

  if (fread((*blockmap)->refcounts, sizeof(int64_t), (*blockmap)->numblocks, blockmapfile) !=
      (size_t)(*blockmap)->numblocks) {
    fprintf(stderr, "%s", RED);
    fprintf(stderr, "Failed to read refcounts map from blockmap file.\n");
    fprintf(stderr, "%s", BLACK);
    goto done;
  }

  if (! validate_blockmap_contents(*blockmap)) {
    goto done;
  }

  ret = true;

done:
  if (! ret) {
    free_blockmap(blockmap);
  }
  return ret;
}


// allocate an empty blockmap covering 'numblocks' blocks
//
// THIS FUNCTION IS NOT THREAD-SAFE.
bool allocate_blockmap(Blockmap **blockmap, uint32_t blocksize, uint64_t numblocks) {

  uint64_t i;
  uint64_t bitmap_length;
  uint64_t serialized_size;

  if (! blockmap) {
    return false;
  }

  *blockmap = NULL;

  if (blocksize < 512 || blocksize % 512 ||
      ! calculate_blockmap_layout(numblocks, &bitmap_length, &serialized_size)) {
    return false;
  }

  *blockmap = calloc(1, sizeof(Blockmap));

  if (! *blockmap) {
    return false;
  }

  (*blockmap)->numblocks = numblocks;
  (*blockmap)->blocksize = blocksize;
  (*blockmap)->bitmap_length = bitmap_length;
  (*blockmap)->start_block = 0;
  (*blockmap)->end_block = numblocks - 1;

  // allocate bitmaps
  if (! ((*blockmap)->coveragemap = calloc((*blockmap)->bitmap_length, sizeof(atomic_uchar)))) {
    goto die;
  }

  if (! ((*blockmap)->dedupmap = calloc((*blockmap)->bitmap_length, sizeof(atomic_uchar)))) {
    goto die;
  }

  if (! ((*blockmap)->exemplarmap = calloc((*blockmap)->bitmap_length, sizeof(atomic_uchar)))) {
    goto die;
  }

  if (! ((*blockmap)->zeromap = calloc((*blockmap)->bitmap_length, sizeof(atomic_uchar)))) {
    goto die;
  }

  // allocate reservation counts
  if (! ((*blockmap)->reservations = (atomic_llong *)calloc((*blockmap)->numblocks, sizeof(atomic_llong)))) {
    goto die;
  }

  // allocate reference counts for deduplication
  if (! ((*blockmap)->refcounts = (atomic_llong *)calloc((*blockmap)->numblocks, sizeof(atomic_llong)))) {
    goto die;
  }

  // C standard requires explicit atomic initialization

  for (i = 0; i < (*blockmap)->bitmap_length; i++) {
    atomic_init(&((*blockmap)->coveragemap[i]), 0);
    atomic_init(&((*blockmap)->dedupmap[i]), 0);
    atomic_init(&((*blockmap)->exemplarmap[i]), 0);
    atomic_init(&((*blockmap)->zeromap[i]), 0);
  }

  for (i = 0; i < (*blockmap)->numblocks; i++) {
    atomic_init(&((*blockmap)->reservations[i]), 0);
    atomic_init(&((*blockmap)->refcounts[i]), 1);
  }

  return true;

 die:
  free_blockmap(blockmap);
  return false;
}


// free all resources associated with a blockmap
//
// THIS FUNCTION IS NOT THREAD-SAFE.
void free_blockmap(Blockmap **blockmap) {

  if (*blockmap) {
    free((*blockmap)->coveragemap);
    free((*blockmap)->dedupmap);
    free((*blockmap)->exemplarmap);
    free((*blockmap)->zeromap);
    free((*blockmap)->reservations);
    free((*blockmap)->refcounts);
    free(*blockmap);
    *blockmap = NULL;
  }
}


// perform a deep copy of blockmap 'src' into 'dest'. If *dest is NULL, then the destination blockmap is allocated
// before the copy operations. If *dest is not NULL, then reservations in *dest are preserved. If *dest is not NULL,
// then the sizes of the two blockmaps must match.
//
// THIS FUNCTION IS NOT THREAD-SAFE.
bool clone_blockmap(Blockmap *src, Blockmap **dest) {

  bool ret = true;
  bool keep_dest_reservations = true;
  Blockmap *d;

  if (! (*dest)) {
    keep_dest_reservations = false;
    if (! allocate_blockmap(&d, src->blocksize, src->numblocks)) {
      ret = false;
      goto done;
    }
  }
  else {
    if (src->numblocks != (*dest)->numblocks) {
      ret = false;
      goto done;
    }
    d = *dest;
  }

  d->start_block = src->start_block;
  d->end_block = src->end_block;
  memcpy(d->coveragemap, src->coveragemap, src->bitmap_length * sizeof(atomic_uchar));
  memcpy(d->dedupmap, src->dedupmap, src->bitmap_length * sizeof(atomic_uchar));
  memcpy(d->exemplarmap, src->exemplarmap, src->bitmap_length * sizeof(atomic_uchar));
  memcpy(d->zeromap, src->zeromap, src->bitmap_length * sizeof(atomic_uchar));
  if (! keep_dest_reservations) {
    memcpy(d->reservations, src->reservations, src->numblocks * sizeof(atomic_llong));
  }
  memcpy(d->refcounts, src->refcounts, src->numblocks * sizeof(atomic_llong));

  // publish the fully-populated blockmap only after every field is copied, so a
  // lock-free reader of a shadow blockmap never observes a half-initialized map
  atomic_thread_fence(memory_order_release);
  *dest = d;

done:
  return ret;
}


// set jth bit in a bitmap composed of 8-bit integers
void set_bit(atomic_uchar *bitmap, uint64_t j) {

  atomic_fetch_or_explicit(&bitmap[j / 8], (unsigned char)(1 << (j % 8)), memory_order_acq_rel);
}


// clear jth bit in a bitmap composed of 8-bit integers
void clear_bit(atomic_uchar *bitmap, uint64_t j) {

  atomic_fetch_and_explicit(&bitmap[j / 8], (unsigned char)~(1 << (j % 8)), memory_order_acq_rel);
}


// returns true if jth bit is set in a bitmap of 8-bit integers, otherwise false
bool is_bit_set(atomic_uchar *bitmap, uint64_t j) {

  unsigned char v = atomic_load_explicit(&bitmap[j / 8], memory_order_acquire);

  return (v & (unsigned char)(1 << (j % 8))) != 0;
}

