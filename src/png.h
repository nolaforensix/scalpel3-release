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

// PNG validators for scalpel3 (c) 2021-2026 by Golden G. Richard III.
//
// PNG file validation code based primarily on a massive hack of pngcheck
// (see copyright info below) to eliminate the use of global variables
// (to ensure thread safety), read from an in-memory buffer, and
// actively monitor error points. If a new version of pngcheck is
// integrated, in addition to these changes, global variables have to
// be eliminated and encapsulated in the PNGMemIO structure.
//
// GGRIII: This code is not yet optimized.
//

/*============================================================================
 *
 *   Copyright 1995-2021 by Alexander Lehmann <lehmann@usa.net>,
 *                          Andreas Dilger <adilger@enel.ucalgary.ca>,
 *                          Glenn Randers-Pehrson <randeg@alum.rpi.edu>,
 *                          Greg Roelofs <newt@pobox.com>,
 *                          John Bowler <jbowler@acm.org>,
 *                          Tom Lane <tgl@sss.pgh.pa.us>
 *
 *   Permission to use, copy, modify, and distribute this software and its
 *   documentation for any purpose and without fee is hereby granted, provided
 *   that the above copyright notice appear in all copies and that both that
 *   copyright notice and this permission notice appear in supporting
 *   documentation.  This software is provided "as is" without express or
 *   implied warranty.
 *
 *===========================================================================*/
// Based on PNGCHECK VERSION 3.0.3 (patches manually applied to
// modified 3.0.2 by GGRIII)
//


#if !defined(SCALPEL_PNG_H)
#define SCALPEL_PNG_H
// uncomment to enable main() function for standalone testing,
// otherwise disable
//#define PNG_TEST


// if > 0, attempt to reuse zlib streams to increase performance

#include "scalpel.h"
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <zlib.h>
#include <math.h>  /* sqrt() for B8 adaptive variance threshold */

// Filetype-specific validation functions for filetype "png".

static inline char *png_header_discovery(char *base,
					 uint64_t offset,
					 uint64_t remaining,
					 char **matchpos,
					 uint32_t *matchlen,
					 uint32_t blocksize);

static inline char *png_footer_discovery(char *base,
					 uint64_t offset,
					 uint64_t remaining,
					 char **matchpos,
					 uint32_t *matchlen,
					 uint32_t blocksize);

static inline uint32_t png_block_validate(char *data,
					  uint64_t length,
					  BlockValidationDecision *decision,
					  uint64_t *validates_to,
					  uint32_t needleidx,
					  uint32_t blocksize,
					  void *blockhashkey);

static inline void png_file_validate(char *data,
				     uint64_t length,
				     bool *validates,
				     uint64_t *validates_to,
				     bool *promising,
				     uint32_t needleidx,
				     uint32_t blocksize,
				     void *carvehashkey);

static inline bool png_try_complete_contiguous(char *data,
					       uint64_t length,
					       uint64_t *validates_to);

// Core validation logic — called directly by png_reassembly with local state
// to avoid the expensive carve_get_state/carve_put_state hash table dance.
// When direct_state is non-NULL, reads/writes state fields directly.
// When direct_state is NULL, uses carvehashkey to access the hash table.
struct PNGCarveState;  // forward declaration for the prototype below
static inline void png_validate_core(char *data,
				     uint64_t length,
				     bool *validates,
				     uint64_t *validates_to,
				     bool *promising,
				     uint32_t needleidx,
				     uint32_t blocksize,
				     void *carvehashkey,
				     struct PNGCarveState *direct_state);

static inline bool png_no_carve(char *data,
				uint64_t length,
				char *sha256);

// a "no carve" function decides, based on file data, length, or SHA256 hash,
// whether a carving operation that has verified a file should write the file,
// or not.  A true return means "don't write the file" and a false return means
// "write the file".
static inline bool png_no_carve(char *data,
				uint64_t length,
				char *sha256) {
  (void)data;
  (void)length;
  (void)sha256;
  return false;
}

//
// a block validator function decides, based on whatever criteria are available
// (entropy, block hash dictionaries, the presence of keywords or binary
// strings, etc.) whether a block might be part of a file of the associated
// type.  A confidence interval from BLOCK_CONFIDENCE_INVALID (absolutely not a
// block of the associated file type) to BLOCK_CONFIDENCE_VALID (100% certainty)
// is used.
//

//
// BLOCK VALIDATION FUNCTIONS MUST BE THREAD-SAFE--THIS MEANS NO
// WRITEABLE GLOBAL VARIABLES, NO WRITEABLE STATIC VARIABLES, AND NO
// USE OF THREAD-UNSAFE HELPER FUNCTIONS.
//

// ============================================================================
// PNG Block State: IDAT boundary index
// ============================================================================
//
// During block validation (runs once per block at startup), scan each
// block for PNG chunk type markers ("IDAT", "IEND").  Store the byte
// offset where the marker appears.  During reassembly, query this to
// find blocks that have an IDAT boundary at the expected position —
// reducing search from O(total_blocks) to O(handful).

#define PNG_BLOCK_MAX_MARKERS 128 // max chunk boundaries per block
                                    // (at bs=65536 with 512-byte IDATs = 128 boundaries)

typedef struct PNGBlockState {
  uint8_t  num_idat_markers;   // count of "IDAT" markers found
  uint32_t idat_offsets[PNG_BLOCK_MAX_MARKERS]; // byte offsets within block
  bool     has_iend;           // block contains "IEND" marker
  uint32_t iend_offset;        // byte offset of "IEND" within block
  uint32_t block_crc;          // CRC32 of raw block data (for crc32_combine)
} PNGBlockState;

// ---- Global CRC hash table for IDAT algebraic solver ----
// Maps CRC32 to lists of actual block numbers.  Built lazily under a mutex and
// treated as read-only after publication.  Coverage is monotonic, so the table
// is keyed by immutable actual block numbers and covered entries are filtered
// at use time instead of rebuilding after every blockmap swap.
// Maximum IDAT body length accepted in CRC solver structural checks.
// PNG spec allows arbitrarily large IDATs.  128MB covers all practical encoders.
#define PNG_MAX_IDAT_BODY_LEN 134217728U

#define PNG_CRC_HASH_BUCKETS 65536
#define PNG_GAP_WINDOW_BUCKETS 262144
#define PNG_GAP_INDEX_MAX_M 8
#define PNG_MARKER_BUCKETS 65536

typedef struct PNGGapWindowEntry {
  uint32_t crc;
  int64_t start_actual;
  struct PNGGapWindowEntry *next;
} PNGGapWindowEntry;

typedef struct PNGGapWindowTable {
  PNGGapWindowEntry **buckets;
  PNGGapWindowEntry *pool;
  uint32_t count;
  uint32_t M;
} PNGGapWindowTable;

typedef struct PNGCrcEntry {
  uint32_t crc;
  int64_t actual_block;
  /* Cached structural data from PNGBlockState — populated at table build
   * time so the solver never needs block_get_state() or disk reads. */
  uint8_t  num_idat_markers;
  uint32_t idat_offsets[PNG_BLOCK_MAX_MARKERS];
  bool     has_iend;
  uint32_t iend_offset;
  struct PNGCrcEntry *next;
} PNGCrcEntry;

typedef struct PNGMarkerEntry {
  uint32_t offset;
  PNGCrcEntry *entry;
  struct PNGMarkerEntry *next;
} PNGMarkerEntry;

typedef struct PNGCrcHashTable {
  PNGCrcEntry *buckets[PNG_CRC_HASH_BUCKETS];
  int64_t total_entries;
  uint32_t block_forward[32];
  uint32_t *actual_crc;
  unsigned char *actual_valid;
  int64_t actual_count;
  int64_t apparent_count;
  PNGGapWindowTable *gap_windows[PNG_GAP_INDEX_MAX_M + 1];
  PNGMarkerEntry **marker_buckets;
  PNGMarkerEntry *marker_pool;
  uint64_t marker_count;
} PNGCrcHashTable;

static inline bool png_crc_inverse_for_len(z_off_t len, uint32_t inv[32]);
static inline void png_crc_forward_for_len(z_off_t len,
                                            uint32_t forward[32]);
static inline uint32_t png_crc_apply_forward(const uint32_t forward[32],
                                              uint32_t value);
static inline uint32_t png_crc_apply_inverse(const uint32_t inv[32],
                                              uint32_t value);
static inline int png_compare_int64(const void *left, const void *right);

static inline int png_compare_int64(const void *left, const void *right) {
  int64_t a = *(const int64_t *)left;
  int64_t b = *(const int64_t *)right;
  return (a > b) - (a < b);
}

static inline bool png_crc_actual_valid(PNGCrcHashTable *ht,
                                        int64_t actual) {
  return ht && scalpel_state.filemirror
      && actual >= 0 && actual < ht->actual_count
      && ht->actual_valid && ht->actual_valid[actual]
      && !filemirror_actual_block_covered(scalpel_state.filemirror, actual);
}

static inline int64_t png_crc_actual_to_apparent(PNGCrcHashTable *ht,
                                                 int64_t actual) {
  if (!ht || !scalpel_state.filemirror || actual < 0
      || scalpel_state.blocksize == 0) {
    return -1;
  }
  if (!png_crc_actual_valid(ht, actual)) {
    return -1;
  }
  int64_t ap = filemirror_apparent_blocknumber(scalpel_state.filemirror,
      actual);
  return ap;
}

static inline bool png_crc_apparent_crc(PNGCrcHashTable *ht,
                                        int64_t apparent,
                                        uint32_t *out_crc,
                                        int64_t *out_actual) {
  if (!ht || !scalpel_state.filemirror || apparent < 0) {
    return false;
  }
  int64_t actual = filemirror_actual_blocknumber(scalpel_state.filemirror,
      apparent);
  if (!png_crc_actual_valid(ht, actual)) {
    return false;
  }
  if (out_crc) {
    *out_crc = ht->actual_crc[actual];
  }
  if (out_actual) {
    *out_actual = actual;
  }
  return true;
}

static inline bool png_crc_actual_pair_crc(PNGCrcHashTable *ht,
                                           int64_t actual_start,
                                           uint32_t *out_crc,
                                           int64_t *out_ap0,
                                           int64_t *out_ap1) {
  if (!ht || !out_crc || !out_ap0 || !out_ap1) {
    return false;
  }
  int64_t ap0 = png_crc_actual_to_apparent(ht, actual_start);
  int64_t ap1 = png_crc_actual_to_apparent(ht, actual_start + 1);
  if (ap0 < 0 || ap1 < 0 || ap0 == ap1) {
    return false;
  }
  *out_crc = png_crc_apply_forward(ht->block_forward,
      ht->actual_crc[actual_start]) ^ ht->actual_crc[actual_start + 1];
  *out_ap0 = ap0;
  *out_ap1 = ap1;
  return true;
}

/* BBK fill-block geometry for algebraic CRC solver. */
typedef struct BBKFillInfo {
  uint64_t ov_start, ov_end;  /* byte range overlapping the IDAT CRC region */
  z_off_t trail;              /* bytes from end of overlap to end of CRC region */
  bool full;                  /* true if entire block is within IDAT CRC region */
} BBKFillInfo;

static PNGCrcHashTable *png_global_crc_table = NULL;
static uint32_t png_crc_table_needleidx = UINT32_MAX;
static atomic_ullong png_crc_table_epoch;
static pthread_mutex_t png_crc_table_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t png_gap_window_lock = PTHREAD_MUTEX_INITIALIZER;
static atomic_int png_debug_trace_events;

/* Forward declarations for PNG carve state and solver cache ownership. */
typedef struct PNGCarveState PNGCarveState;
typedef struct PNGSolverContext PNGSolverContext;
static inline void png_solver_ctx_free(PNGSolverContext **ctx);
static inline PNGSolverContext *png_solver_ctx_clone(const PNGSolverContext *ctx);
// P1 forward: needed by png_bbk_single_swap_solve for algebraic pre-filter.
static inline uint32_t png_get_block_crc(int64_t apparent_block,
                                          uint32_t needleidx,
                                          bool *ok);

static inline void png_crc_table_insert(PNGCrcHashTable *ht,
                                         uint32_t crc, int64_t actual,
                                         const PNGBlockState *bs) {
  uint32_t idx = crc % PNG_CRC_HASH_BUCKETS;
  PNGCrcEntry *e = (PNGCrcEntry *)malloc(sizeof(PNGCrcEntry));
  if (!e) return;
  e->crc = crc;
  e->actual_block = actual;
  if (bs) {
    e->num_idat_markers = bs->num_idat_markers;
    memcpy(e->idat_offsets, bs->idat_offsets,
           bs->num_idat_markers * sizeof(uint32_t));
    e->has_iend = bs->has_iend;
    e->iend_offset = bs->iend_offset;
  }
  else {
    e->num_idat_markers = 0;
    e->has_iend = false;
    e->iend_offset = 0;
  }
  e->next = ht->buckets[idx];
  ht->buckets[idx] = e;
  ht->total_entries++;
}

static inline void png_gap_window_table_free(PNGGapWindowTable *gt) {
  if (!gt) {
    return;
  }
  free(gt->buckets);
  free(gt->pool);
  free(gt);
}

static inline void png_crc_marker_index_free(PNGCrcHashTable *ht) {
  if (!ht) {
    return;
  }
  free(ht->marker_buckets);
  free(ht->marker_pool);
  ht->marker_buckets = NULL;
  ht->marker_pool = NULL;
  ht->marker_count = 0;
}

static inline void png_crc_table_free(PNGCrcHashTable *ht) {
  if (!ht) return;
  for (uint32_t i = 0; i < PNG_CRC_HASH_BUCKETS; i++) {
    PNGCrcEntry *e = ht->buckets[i];
    while (e) {
      PNGCrcEntry *next = e->next;
      free(e);
      e = next;
    }
  }
  for (uint32_t m = 0; m <= PNG_GAP_INDEX_MAX_M; m++) {
    png_gap_window_table_free(ht->gap_windows[m]);
  }
  png_crc_marker_index_free(ht);
  free(ht->actual_crc);
  free(ht->actual_valid);
  free(ht);
}

// Find all actual block numbers with the given CRC.
// Caller iterates: for (PNGCrcEntry *e = png_crc_table_find(...); e; e = png_crc_table_next(e, crc))
static inline PNGCrcEntry *png_crc_table_find(PNGCrcHashTable *ht, uint32_t crc) {
  uint32_t idx = crc % PNG_CRC_HASH_BUCKETS;
  PNGCrcEntry *e = ht->buckets[idx];
  while (e && e->crc != crc) e = e->next;
  return e;
}

static inline PNGCrcEntry *png_crc_table_next(PNGCrcEntry *prev, uint32_t crc) {
  PNGCrcEntry *e = prev->next;
  while (e && e->crc != crc) e = e->next;
  return e;
}

static inline PNGMarkerEntry *png_crc_marker_find(PNGCrcHashTable *ht,
                                                   uint32_t offset) {
  if (!ht || !ht->marker_buckets) {
    return NULL;
  }
  PNGMarkerEntry *m = ht->marker_buckets[offset % PNG_MARKER_BUCKETS];
  while (m && m->offset != offset) {
    m = m->next;
  }
  return m;
}

static inline PNGMarkerEntry *png_crc_marker_next(PNGMarkerEntry *prev,
                                                   uint32_t offset) {
  if (!prev) {
    return NULL;
  }
  PNGMarkerEntry *m = prev->next;
  while (m && m->offset != offset) {
    m = m->next;
  }
  return m;
}

static inline void png_crc_marker_index_build(PNGCrcHashTable *ht) {
  uint64_t count = 0;

  if (!ht) {
    return;
  }

  png_crc_marker_index_free(ht);

  for (uint32_t b = 0; b < PNG_CRC_HASH_BUCKETS; b++) {
    for (PNGCrcEntry *e = ht->buckets[b]; e; e = e->next) {
      count += e->num_idat_markers;
      if (e->has_iend) {
        count++;
      }
    }
  }
  if (count == 0) {
    return;
  }

  ht->marker_buckets = (PNGMarkerEntry **)calloc(PNG_MARKER_BUCKETS,
      sizeof(PNGMarkerEntry *));
  ht->marker_pool = (PNGMarkerEntry *)malloc(
      (size_t)count * sizeof(PNGMarkerEntry));
  if (!ht->marker_buckets || !ht->marker_pool) {
    png_crc_marker_index_free(ht);
    return;
  }

  uint64_t out = 0;
  for (uint32_t b = 0; b < PNG_CRC_HASH_BUCKETS; b++) {
    for (PNGCrcEntry *e = ht->buckets[b]; e; e = e->next) {
      for (uint8_t mi = 0; mi < e->num_idat_markers && out < count; mi++) {
        PNGMarkerEntry *m = &ht->marker_pool[out++];
        m->offset = e->idat_offsets[mi];
        m->entry = e;
        uint32_t idx = m->offset % PNG_MARKER_BUCKETS;
        m->next = ht->marker_buckets[idx];
        ht->marker_buckets[idx] = m;
      }
      if (e->has_iend && out < count) {
        PNGMarkerEntry *m = &ht->marker_pool[out++];
        m->offset = e->iend_offset;
        m->entry = e;
        uint32_t idx = m->offset % PNG_MARKER_BUCKETS;
        m->next = ht->marker_buckets[idx];
        ht->marker_buckets[idx] = m;
      }
    }
  }
  ht->marker_count = out;
}

#define PNG_BBK_EXACT_ITER_CAP 50000000ULL
/* BBK exact search is exponential in active fill positions.  Keep the search
 * space bounded with the filtered flat[] size and only enter exact search when
 * the total projected tree is tractable.  The iteration cap below is now a
 * checkpoint polling point, not a local scheduler yield. */
#define PNG_BBK_EXACT_FEASIBLE_CAP 8000000ULL
/* Single-swap has a cheap algebraic scan for full-middle blocks.  Boundary
 * blocks cannot use that prefilter and fall back to physical inflate+CRC per
 * candidate; only allow that path after the residual table is small. */
#define PNG_BBK_SINGLE_PHYSICAL_MAX_N 8192U
// PNG_BBK_EXACT_MAX_FILL is the static bound on fixed-size tree-state arrays
// inside png_bbk_exact_solve and the matching resume-state arrays inside
// PNGCarveState.  It used to be 32 — if n_fill exceeded 32, exact_solve
// returned 0 and silently skipped the candidate.  That violates the
// exhaust-all-orderings rule: we cannot abandon the search just because
// n_fill happens to exceed a stack-convenient bound.  Raised to 256 —
// covers PNGs up to ~4 MiB at the common 16 KiB blocksize, which is the
// size regime our current test corpora actually exercise.
// TODO: heap-allocate these arrays so the cap disappears entirely.  The
// struct overhead is currently 256 * 3 * 8 B = 6 KiB per PNGCarveState,
// which is acceptable but scales linearly with the bound.
#define PNG_BBK_EXACT_MAX_FILL 256U
// PNG_BBK_SUFFIX_TRY_LIMIT was 8 — if more than 8 distinct suffix
// candidates (per their stored IDAT CRC) existed in the hash table, only
// the first 8 were tried and the rest were silently dropped.  Same rule:
// we must try every stored-CRC candidate that could complete the chunk
// before giving up.  Raised to 256 for the same reason.
#define PNG_BBK_SUFFIX_TRY_LIMIT 256U
// A complete M=4 meet-in-the-middle search stores every ordered left pair.
// Bound per-worker storage rather than using an arbitrary candidate count;
// larger searches continue to use the structured run and anchor solvers.
#define PNG_M4_PAIR_MEMORY_LIMIT (32ULL * 1024ULL * 1024ULL)

/* M=3 Phase C is also quadratic: it fixes one middle block, then scans a
 * second block and hash-solves the third.  Keep it for small residual
 * searches only; at full corpus scale this was the tail stall. */
#define PNG_M3_PHASE_C_PAIR_CAP 8000000ULL

// Try physically-near anchored pairs before broad M=2 search.  This handles
// small local filler gaps without turning every candidate into a full-disk
// pair search.
#define PNG_M2_ANCHOR_SCAN_MAX 64U

// For post-CRC gallop, keep local prefix progress only while the remaining
// CRC span is still too wide for the strongest small-boundary solvers.
#define PNG_POSTCRC_SMALL_SOLVER_FILL_MAX 4U

// This is intentionally checkpoint-only.  PNG solvers may save progress when
// REASS_RETURN_TO_IDLE is set, but they must not return to the promising queue
// for local fairness or time-slice reasons.
static inline bool png_reassembly_yield_requested(CarveInfo *candidate) {
  (void)candidate;
  return atomic_load_explicit(&REASS_RETURN_TO_IDLE, memory_order_acquire);
}

static inline uint32_t png_bbk_copy_fill_positions_excluding(
    uint32_t *dst,
    const uint32_t *src,
    uint32_t n_fill,
    bool exclude_active,
    uint32_t exclude_pos) {
  if (!dst || !src) {
    return 0;
  }
  uint32_t out = 0;
  for (uint32_t i = 0; i < n_fill; i++) {
    if (exclude_active && src[i] == exclude_pos) {
      continue;
    }
    dst[out++] = src[i];
  }
  return out;
}

static inline void png_solver_resize_trial(CarveInfo *candidate,
                                            uint64_t num_blocks);

static inline bool png_bbk_append_suffix_trial(
    int64_t *trial_ab,
    uint32_t *trial_crc,
    bool *trial_fixed,
    uint32_t *trial_count,
    int64_t apparent_block,
    uint32_t stored_crc,
    bool fixed_suffix) {
  if (!trial_ab || !trial_crc || !trial_fixed || !trial_count) {
    return false;
  }
  for (uint32_t i = 0; i < *trial_count; i++) {
    if (trial_ab[i] == apparent_block) {
      return false;
    }
  }
  if (*trial_count >= PNG_BBK_SUFFIX_TRY_LIMIT) {
    return false;
  }
  trial_ab[*trial_count] = apparent_block;
  trial_crc[*trial_count] = stored_crc;
  trial_fixed[*trial_count] = fixed_suffix;
  (*trial_count)++;
  return true;
}

static inline bool png_bbk_entry_allowed_with_path(
    const PNGCrcEntry *e,
    PNGCrcEntry *const *chosen_entries,
    uint32_t depth,
    int64_t *apparent_block_out) {
  if (filemirror_actual_block_covered(
          scalpel_state.filemirror, e->actual_block)) {
    return false;
  }
  for (uint32_t i = 0; i < depth; i++) {
    if (chosen_entries[i]
        && chosen_entries[i]->actual_block == e->actual_block) {
      return false;
    }
  }
  int64_t ab = filemirror_apparent_blocknumber(
      scalpel_state.filemirror, e->actual_block);
  if (ab < 0) {
    return false;
  }
  *apparent_block_out = ab;
  return true;
}

static inline void png_bbk_restore_contiguous_window(CarveInfo *candidate,
                                                      uint64_t suffix_start_nb,
                                                      uint32_t fill_needed,
                                                      int64_t last_block) {
  for (uint32_t f = 0; f < fill_needed; f++) {
    blockvector_set_apparent_blocknumber(candidate->b,
        suffix_start_nb + f, last_block + 1 + (int64_t)f);
    inflate_blockvector_single_block(candidate->b,
        suffix_start_nb + f);
  }
}

static inline void png_bbk_restore_fill_positions(CarveInfo *candidate,
                                                   uint64_t suffix_start_nb,
                                                   const uint32_t *fill_pos,
                                                   uint32_t n_fill,
                                                   int64_t last_block) {
  for (uint32_t i = 0; i < n_fill; i++) {
    uint32_t fpos = fill_pos[i];
    blockvector_set_apparent_blocknumber(candidate->b,
        suffix_start_nb + fpos, last_block + 1 + (int64_t)fpos);
    inflate_blockvector_single_block(candidate->b,
        suffix_start_nb + fpos);
  }
}

static inline void png_bbk_resume_reset(PNGCarveState *local);
static inline int64_t png_bbk_resume_chosen_actual_get(
    const PNGCarveState *local, uint32_t i);
static inline bool png_bbk_resume_matches(PNGCarveState *local,
                                           bool retry_mode,
                                           uint64_t suffix_start_nb,
                                           uint64_t idat_start,
                                           uint64_t bbk_crc_len,
                                           uint32_t bbk_stored_crc,
                                           const uint32_t *fill_pos,
                                           uint32_t n_fill);
static inline bool png_bbk_resume_load(PNGCarveState *local,
                                        uint32_t *depth,
                                        bool *at_leaf,
                                        uint32_t *leaf_need_crc,
                                        int64_t *leaf_last_actual,
                                        uint64_t *iter_count,
                                        int64_t *next_flat,
                                        int64_t *chosen_flat);
static inline void png_bbk_resume_save(PNGCarveState *local,
                                        bool retry_mode,
                                        uint64_t suffix_start_nb,
                                        uint64_t idat_start,
                                        uint64_t bbk_crc_len,
                                        uint32_t bbk_stored_crc,
                                        const uint32_t *fill_pos,
                                        uint32_t n_fill,
                                        uint32_t depth,
                                        bool at_leaf,
                                        uint32_t leaf_need_crc,
                                        int64_t leaf_last_actual,
                                        uint64_t iter_count,
                                        const int64_t *next_flat,
                                        const int64_t *chosen_flat,
                                        const int64_t *chosen_blocks);
static inline PNGGapWindowTable *png_gap_window_table_get(
    PNGCrcHashTable *ht, uint32_t M);

static inline bool png_bbk_verify_crc(CarveInfo *candidate,
                                       uint64_t idat_start,
                                       uint64_t bbk_crc_len,
                                       uint32_t bbk_stored_crc) {
  const char *vd = blockvector_get_data_pointer(candidate->b);
  uint64_t vdl = blockvector_get_data_length(candidate->b);
  if (!vd || idat_start + bbk_crc_len > vdl) {
    return false;
  }
  uint32_t vc = crc32(0, NULL, 0);
  vc = crc32(vc, (const unsigned char *)(vd + idat_start),
      (uInt)bbk_crc_len);
  return vc == bbk_stored_crc;
}

static inline bool png_bbk_apparent_in_prefix(CarveInfo *candidate,
                                               uint64_t suffix_start_nb,
                                               int64_t apparent_block) {
  if (!candidate || !candidate->b || apparent_block < 0) {
    return false;
  }

  for (uint64_t i = 0; i < suffix_start_nb; i++) {
    if (blockvector_get_apparent_blocknumber(candidate->b, i)
        == apparent_block) {
      return true;
    }
  }
  return false;
}

static inline BBKFillInfo *png_bbk_build_fill_info(uint64_t suffix_start_nb,
                                                    const uint32_t *fill_pos,
                                                    uint32_t n_fill,
                                                    uint64_t idat_start,
                                                    uint64_t idat_end,
                                                    bool *all_full_out) {
  *all_full_out = true;
  BBKFillInfo *finfo = (BBKFillInfo *)malloc(
      n_fill * sizeof(BBKFillInfo));
  if (!finfo) {
    return NULL;
  }
  uint32_t bs = scalpel_state.blocksize;
  for (uint32_t i = 0; i < n_fill; i++) {
    uint64_t bstart = (suffix_start_nb + fill_pos[i]) * (uint64_t)bs;
    uint64_t bend = bstart + bs;
    finfo[i].ov_start = bstart > idat_start ? bstart : idat_start;
    finfo[i].ov_end = bend < idat_end ? bend : idat_end;
    finfo[i].trail = (z_off_t)(idat_end - finfo[i].ov_end);
    finfo[i].full = (bstart >= idat_start && bend <= idat_end);
    if (!finfo[i].full) {
      *all_full_out = false;
    }
  }
  return finfo;
}

static inline bool png_bbk_compute_unknown_target(CarveInfo *candidate,
                                                   uint64_t idat_start,
                                                   uint64_t idat_end,
                                                   const BBKFillInfo *finfo,
                                                   uint32_t n_fill,
                                                   uint32_t bbk_stored_crc,
                                                   uint32_t *unknown_target) {
  const char *bd = blockvector_get_data_pointer(candidate->b);
  uint64_t bdl = blockvector_get_data_length(candidate->b);
  if (!bd || idat_end > bdl) {
    return false;
  }

  uint32_t known_contrib = 0;
  uint64_t scan = idat_start;
  for (uint32_t i = 0; i < n_fill; i++) {
    uint64_t ov_start = finfo[i].ov_start;
    uint64_t ov_end = finfo[i].ov_end;
    if (ov_start < idat_start) {
      ov_start = idat_start;
    }
    if (ov_end > idat_end) {
      ov_end = idat_end;
    }
    if (ov_end <= ov_start || ov_end <= scan) {
      continue;
    }
    if (scan < ov_start) {
      uint64_t slen = ov_start - scan;
      uint32_t scrc = crc32(0, NULL, 0);
      scrc = crc32(scrc, (const unsigned char *)(bd + scan), (uInt)slen);
      known_contrib ^= (uint32_t)crc32_combine(
          (uLong)scrc, 0UL,
          (z_off_t)(idat_end - (scan + slen)));
    }
    scan = ov_end;
  }
  if (scan < idat_end) {
    uint64_t slen = idat_end - scan;
    uint32_t scrc = crc32(0, NULL, 0);
    scrc = crc32(scrc, (const unsigned char *)(bd + scan), (uInt)slen);
    known_contrib ^= scrc;
  }

  *unknown_target = bbk_stored_crc ^ known_contrib;
  return true;
}

static inline int png_bbk_contiguous_run_solve(CarveInfo *candidate,
                                                PNGCrcHashTable *ht,
                                                uint64_t suffix_start_nb,
                                                const uint32_t *fill_pos,
                                                uint32_t n_fill,
                                                int64_t last_block,
                                                uint64_t idat_start,
                                                uint64_t bbk_crc_len,
                                                uint32_t bbk_stored_crc,
                                                uint32_t unknown_target,
                                                const BBKFillInfo *finfo) {
  if (!candidate || !ht || !fill_pos || !finfo || n_fill == 0
      || n_fill > PNG_GAP_INDEX_MAX_M) {
    return 0;
  }

  for (uint32_t i = 1; i < n_fill; i++) {
    if (fill_pos[i] != fill_pos[i - 1] + 1) {
      return 0;
    }
  }
  for (uint32_t i = 0; i < n_fill; i++) {
    if (!finfo[i].full) {
      return 0;
    }
  }

  uint32_t inv[32];
  if (!png_crc_inverse_for_len(finfo[n_fill - 1].trail, inv)) {
    return 0;
  }

  uint32_t needed_run_crc = png_crc_apply_inverse(inv, unknown_target);
  PNGGapWindowTable *runs = png_gap_window_table_get(ht, n_fill);
  if (!runs) {
    return 0;
  }

  int64_t apparent[PNG_GAP_INDEX_MAX_M];
  uint32_t bucket = needed_run_crc % PNG_GAP_WINDOW_BUCKETS;
  for (PNGGapWindowEntry *we = runs->buckets[bucket]; we; we = we->next) {
    if (we->crc != needed_run_crc) {
      continue;
    }

    bool ok = true;
    for (uint32_t i = 0; i < n_fill; i++) {
      int64_t ap = png_crc_actual_to_apparent(ht, we->start_actual + i);
      if (ap < 0 || png_bbk_apparent_in_prefix(candidate, suffix_start_nb, ap)) {
        ok = false;
        break;
      }
      apparent[i] = ap;
    }
    if (!ok) {
      continue;
    }

    for (uint32_t i = 0; i < n_fill; i++) {
      blockvector_set_apparent_blocknumber(candidate->b,
          suffix_start_nb + fill_pos[i], apparent[i]);
      inflate_blockvector_single_block(candidate->b,
          suffix_start_nb + fill_pos[i]);
    }

    if (png_bbk_verify_crc(candidate, idat_start,
            bbk_crc_len, bbk_stored_crc)) {
      if (scalpel_state.mode_verbose) {
        lock_fprintf(stdout,
            "%sPNG BBK RUN: n_fill=%u start_actual=%" PRId64 "%s\n",
            GREEN, n_fill, we->start_actual, BLACK);
      }
      return 1;
    }

    png_bbk_restore_fill_positions(candidate, suffix_start_nb, fill_pos,
        n_fill, last_block);
  }

  return 0;
}

static inline bool png_bbk_actual_run_contribution(PNGCrcHashTable *ht,
                                                    int64_t start_actual,
                                                    uint64_t suffix_start_nb,
                                                    const uint32_t *fill_pos,
                                                    uint32_t n_fill,
                                                    uint64_t idat_end,
                                                    const BBKFillInfo *finfo,
                                                    const uint32_t tail_forward[32],
                                                    uint32_t *out) {
  if (!ht || !fill_pos || !finfo || !tail_forward || !out || n_fill == 0) {
    return false;
  }

  uint32_t bs = scalpel_state.blocksize;
  uint32_t crc = crc32(0, NULL, 0);
  uint64_t last_ov_end = 0;
  bool have_bytes = false;
  for (uint32_t i = 0; i < n_fill; i++) {
    int64_t actual = start_actual + (int64_t)i;
    if (!png_crc_actual_valid(ht, actual)) {
      return false;
    }
    if (finfo[i].ov_end <= finfo[i].ov_start) {
      continue;
    }
    if (have_bytes && finfo[i].ov_start != last_ov_end) {
      return false;
    }

    uint64_t block_start = (suffix_start_nb + fill_pos[i]) * (uint64_t)bs;
    uint64_t off = finfo[i].ov_start - block_start;
    uint64_t len = finfo[i].ov_end - finfo[i].ov_start;
    uint64_t actual_len = 0;
    char *p = filemirror_actual_block_data_pointer(
        scalpel_state.filemirror, actual, &actual_len);
    if (!p || off + len > actual_len) {
      return false;
    }

    crc = crc32(crc, (const unsigned char *)(p + off), (uInt)len);
    last_ov_end = finfo[i].ov_end;
    have_bytes = true;
  }

  if (!have_bytes || last_ov_end > idat_end) {
    return false;
  }
  *out = png_crc_apply_forward(tail_forward, crc);
  return true;
}

static inline int png_bbk_contiguous_run_scan_solve(CarveInfo *candidate,
                                                     PNGCrcHashTable *ht,
                                                     uint64_t suffix_start_nb,
                                                     const uint32_t *fill_pos,
                                                     uint32_t n_fill,
                                                     int64_t last_block,
                                                     uint64_t idat_start,
                                                     uint64_t idat_end,
                                                     uint64_t bbk_crc_len,
                                                     uint32_t bbk_stored_crc,
                                                     uint32_t unknown_target,
                                                     const BBKFillInfo *finfo) {
  (void)idat_start;

  if (!candidate || !ht || !fill_pos || !finfo || n_fill == 0
      || n_fill > PNG_GAP_INDEX_MAX_M) {
    return 0;
  }

  for (uint32_t i = 1; i < n_fill; i++) {
    if (fill_pos[i] != fill_pos[i - 1] + 1) {
      return 0;
    }
  }

  PNGGapWindowTable *runs = png_gap_window_table_get(ht, n_fill);
  if (!runs) {
    return 0;
  }

  uint64_t last_overlap_end = 0;
  for (uint32_t i = 0; i < n_fill; i++) {
    if (finfo[i].ov_end > finfo[i].ov_start) {
      last_overlap_end = finfo[i].ov_end;
    }
  }
  if (last_overlap_end == 0 || last_overlap_end > idat_end) {
    return 0;
  }
  uint32_t tail_forward[32];
  png_crc_forward_for_len((z_off_t)(idat_end - last_overlap_end),
                          tail_forward);

  uint64_t checked = 0;
  int64_t apparent[PNG_GAP_INDEX_MAX_M];
  for (uint32_t bucket = 0; bucket < PNG_GAP_WINDOW_BUCKETS; bucket++) {
    for (PNGGapWindowEntry *we = runs->buckets[bucket]; we; we = we->next) {
      if ((checked++ & 0x3FFULL) == 0ULL
          && png_reassembly_yield_requested(candidate)) {
        png_bbk_restore_fill_positions(candidate, suffix_start_nb,
            fill_pos, n_fill, last_block);
        return -1;
      }

      bool ok = true;
      for (uint32_t i = 0; i < n_fill; i++) {
        int64_t ap = png_crc_actual_to_apparent(ht, we->start_actual + i);
        if (ap < 0
            || png_bbk_apparent_in_prefix(candidate, suffix_start_nb, ap)) {
          ok = false;
          break;
        }
        apparent[i] = ap;
      }
      if (!ok) {
        continue;
      }

      uint32_t contrib = 0;
      if (!png_bbk_actual_run_contribution(ht, we->start_actual,
              suffix_start_nb, fill_pos, n_fill, idat_end,
              finfo, tail_forward, &contrib)
          || contrib != unknown_target) {
        continue;
      }

      for (uint32_t i = 0; i < n_fill; i++) {
        blockvector_set_apparent_blocknumber(candidate->b,
            suffix_start_nb + fill_pos[i], apparent[i]);
        inflate_blockvector_single_block(candidate->b,
            suffix_start_nb + fill_pos[i]);
      }

      if (png_bbk_verify_crc(candidate, idat_start,
              bbk_crc_len, bbk_stored_crc)) {
        if (scalpel_state.mode_verbose) {
          lock_fprintf(stdout,
              "%sPNG BBK RUNSCAN: n_fill=%u start_actual=%" PRId64 "%s\n",
              GREEN, n_fill, we->start_actual, BLACK);
        }
        return 1;
      }

      png_bbk_restore_fill_positions(candidate, suffix_start_nb,
          fill_pos, n_fill, last_block);
    }
  }

  return 0;
}

static inline int png_bbk_contiguous_subrun_solve(CarveInfo *candidate,
                                                   PNGCrcHashTable *ht,
                                                   uint64_t suffix_start_nb,
                                                   uint32_t fill_needed,
                                                   uint32_t skip_pos,
                                                   bool have_skip_pos,
                                                   int64_t last_block,
                                                   uint64_t idat_start,
                                                   uint64_t idat_end,
                                                   uint64_t bbk_crc_len,
                                                   uint32_t bbk_stored_crc) {
  if (!candidate || !ht || fill_needed == 0) {
    return 0;
  }

  uint32_t max_width = fill_needed;
  if (max_width > PNG_GAP_INDEX_MAX_M) {
    max_width = PNG_GAP_INDEX_MAX_M;
  }

  uint32_t fill_pos[PNG_GAP_INDEX_MAX_M];
  for (uint32_t width = max_width; width > 0; width--) {
    for (uint32_t start = 0; start + width <= fill_needed; start++) {
      if (have_skip_pos && skip_pos >= start && skip_pos < start + width) {
        continue;
      }
      for (uint32_t i = 0; i < width; i++) {
        fill_pos[i] = start + i;
      }

      bool all_full = false;
      BBKFillInfo *finfo = png_bbk_build_fill_info(
          suffix_start_nb, fill_pos, width, idat_start, idat_end,
          &all_full);
      uint32_t unknown_target = 0;
      bool geom_ok = finfo
          && png_bbk_compute_unknown_target(candidate,
              idat_start, idat_end, finfo, width,
              bbk_stored_crc, &unknown_target);
      if (geom_ok && all_full) {
        int rc = png_bbk_contiguous_run_solve(candidate, ht,
            suffix_start_nb, fill_pos, width, last_block,
            idat_start, bbk_crc_len, bbk_stored_crc,
            unknown_target, finfo);
        if (rc > 0) {
          free(finfo);
          return 1;
        }
      }
      if (geom_ok && !all_full) {
        int rc = png_bbk_contiguous_run_scan_solve(candidate, ht,
            suffix_start_nb, fill_pos, width, last_block,
            idat_start, idat_end, bbk_crc_len, bbk_stored_crc,
            unknown_target, finfo);
        if (rc != 0) {
          free(finfo);
          return rc;
        }
      }
      free(finfo);
    }
  }

  return 0;
}

static inline int png_bbk_current_idat_subrun_solve(CarveInfo *candidate,
                                                     PNGCrcHashTable *ht,
                                                     uint64_t suffix_start_nb,
                                                     uint32_t fill_needed,
                                                     int64_t last_block,
                                                     uint64_t crc_pos,
                                                     long idat_sz) {
  if (!candidate || !candidate->b || !ht || fill_needed == 0
      || idat_sz <= 0) {
    return 0;
  }

  uint64_t idat_start = crc_pos + 4;
  uint64_t bbk_crc_len = 4 + (uint64_t)idat_sz;
  uint64_t idat_end = idat_start + bbk_crc_len;
  uint64_t crc_field = idat_end;

  png_solver_resize_trial(candidate, suffix_start_nb + fill_needed);
  png_bbk_restore_contiguous_window(candidate, suffix_start_nb,
      fill_needed, last_block);

  const char *bd = blockvector_get_data_pointer(candidate->b);
  uint64_t bdl = blockvector_get_data_length(candidate->b);
  if (!bd || crc_field + 4 > bdl) {
    resize_blockvector(candidate->b, suffix_start_nb);
    return 0;
  }

  const unsigned char *ep = (const unsigned char *)(bd + crc_field);
  uint32_t stored_crc = ((uint32_t)ep[0] << 24)
      | ((uint32_t)ep[1] << 16)
      | ((uint32_t)ep[2] << 8)
      | (uint32_t)ep[3];

  bool have_skip_pos = false;
  uint32_t skip_pos = 0;
  uint64_t bs = (uint64_t)scalpel_state.blocksize;
  if (bs > 0) {
    uint64_t crc_block = crc_field / bs;
    if (crc_block >= suffix_start_nb
        && crc_block < suffix_start_nb + fill_needed) {
      skip_pos = (uint32_t)(crc_block - suffix_start_nb);
      have_skip_pos = true;
    }
  }

  int rc = png_bbk_contiguous_subrun_solve(candidate, ht, suffix_start_nb,
      fill_needed, skip_pos, have_skip_pos, last_block, idat_start,
      idat_end, bbk_crc_len, stored_crc);
  if (rc <= 0) {
    resize_blockvector(candidate->b, suffix_start_nb);
  }
  return rc;
}

static inline int png_bbk_exact_solve(CarveInfo *candidate,
                                       PNGCarveState *local,
                                       PNGCrcHashTable *ht,
                                       uint64_t suffix_start_nb,
                                       const uint32_t *fill_pos,
                                       uint32_t n_fill,
                                       int64_t last_block,
                                       uint64_t idat_start,
                                       uint64_t bbk_crc_len,
                                       uint32_t bbk_stored_crc,
                                       bool retry_mode,
                                       uint32_t unknown_target,
                                       const BBKFillInfo *finfo) {
  if (!candidate || !ht || !fill_pos || !finfo || n_fill == 0) {
    return 0;
  }
  if (n_fill > PNG_BBK_EXACT_MAX_FILL) {
    return 0;
  }

  uint32_t last_minv[32];
  if (!png_crc_inverse_for_len(finfo[n_fill - 1].trail, last_minv)) {
    png_bbk_resume_reset(local);
    return 0;
  }
  uint32_t trail_forward[PNG_BBK_EXACT_MAX_FILL][32];
  for (uint32_t i = 0; i + 1 < n_fill; i++) {
    png_crc_forward_for_len(finfo[i].trail, trail_forward[i]);
  }

  uint32_t flat_count = (uint32_t)ht->total_entries;
  if (flat_count == 0) {
    png_bbk_resume_reset(local);
    return 0;
  }
  // Build flat[] by enumerating the hash table.  Previously this kept
  // every entry — including blocks already covered by another validated
  // file and entries whose apparent-block mapping is absent — then
  // relied on per-iteration `png_bbk_entry_allowed_with_path` checks to
  // skip them.  That kept the outer loops running at full N every depth.
  // Filtering at build time shrinks the effective N before the tree
  // search starts, which multiplies into every depth of the search.
  // Also stash the apparent blocknumber we will actually place, so we
  // don't have to re-query filemirror at every visit.
  PNGCrcEntry **flat = (PNGCrcEntry **)malloc(
      (size_t)flat_count * sizeof(PNGCrcEntry *));
  int64_t *flat_ab = (int64_t *)malloc(
      (size_t)flat_count * sizeof(int64_t));
  if (!flat || !flat_ab) {
    free(flat);
    free(flat_ab);
    return 0;
  }
  uint32_t flat_i = 0;
  for (uint32_t bk = 0; bk < PNG_CRC_HASH_BUCKETS; bk++) {
    for (PNGCrcEntry *e = ht->buckets[bk]; e; e = e->next) {
      if (filemirror_actual_block_covered(
              scalpel_state.filemirror, e->actual_block)) {
        continue;
      }
      int64_t ab = filemirror_apparent_blocknumber(
          scalpel_state.filemirror, e->actual_block);
      if (ab < 0) {
        continue;
      }
      flat[flat_i] = e;
      flat_ab[flat_i] = ab;
      flat_i++;
    }
  }
  flat_count = flat_i;
  if (flat_count == 0) {
    free(flat);
    free(flat_ab);
    png_bbk_resume_reset(local);
    return 0;
  }

  uint64_t projected = 1;
  bool overflow = false;
  for (uint32_t i = 0; i + 1 < n_fill; i++) {
    if (flat_count == 0) { projected = 0; break; }
    if (projected > PNG_BBK_EXACT_FEASIBLE_CAP / (uint64_t)flat_count) {
      overflow = true;
      break;
    }
    projected *= (uint64_t)flat_count;
  }
  if (overflow || projected > PNG_BBK_EXACT_FEASIBLE_CAP) {
    if (scalpel_state.mode_verbose) {
      lock_fprintf(stdout,
          "PNG BBK ALG: skipped exact search n_fill=%u N=%u "
          "(projected > %" PRIu64 ")\n",
          n_fill, flat_count, (uint64_t)PNG_BBK_EXACT_FEASIBLE_CAP);
    }
    free(flat);
    free(flat_ab);
    png_bbk_resume_reset(local);
    return 0;
  }

  // Heap-allocate tree-search state sized to n_fill, not to the static
  // PNG_BBK_EXACT_MAX_FILL cap.  Per the exhaust-all-orderings rule, a
  // static bound that silently refuses n_fill > cap is not acceptable.
  // Sizes are O(n_fill * 8 B), negligible vs the work done inside.
  PNGCrcEntry **chosen_entries = (PNGCrcEntry **)calloc(
      n_fill, sizeof(PNGCrcEntry *));
  int64_t *chosen_blocks = (int64_t *)malloc(n_fill * sizeof(int64_t));
  int64_t *chosen_flat   = (int64_t *)malloc(n_fill * sizeof(int64_t));
  int64_t *next_flat     = (int64_t *)calloc(n_fill, sizeof(int64_t));
  if (!chosen_entries || !chosen_blocks || !chosen_flat || !next_flat) {
    free(flat); free(flat_ab);
    free(chosen_entries); free(chosen_blocks);
    free(chosen_flat);    free(next_flat);
    return 0;
  }
  for (uint32_t i = 0; i < n_fill; i++) {
    chosen_blocks[i] = -1;
    chosen_flat[i]   = -1;
  }

  uint32_t depth = 0;
  bool at_leaf = false;
  uint32_t leaf_need_crc = 0;
  int64_t leaf_last_actual = -1;
  uint64_t iter_count = 0;

  bool resumed = png_bbk_resume_matches(local, retry_mode,
      suffix_start_nb, idat_start, bbk_crc_len,
      bbk_stored_crc, fill_pos, n_fill);
  if (resumed) {
    resumed = png_bbk_resume_load(local, &depth, &at_leaf,
        &leaf_need_crc, &leaf_last_actual, &iter_count,
        next_flat, chosen_flat);
  }

  if (resumed) {
    uint32_t path_len = depth;
    if (path_len > n_fill - 1) {
      path_len = n_fill - 1;
    }
    for (uint32_t i = 0; i < path_len; i++) {
      int64_t saved_ab = png_bbk_resume_chosen_actual_get(local, i);
      if (saved_ab < 0) {
        resumed = false;
        break;
      }
      /* flat[] is rebuilt with current coverage.  Saved flat index
       * from a prior call may now point to a different entry (review
       * finding #4).  Re-map by the saved apparent block number. */
      int64_t mapped = -1;
      int64_t hint = chosen_flat[i];
      if (hint >= 0 && (uint32_t)hint < flat_count
          && flat_ab[hint] == saved_ab) {
        mapped = hint;
      } else {
        for (uint32_t j = 0; j < flat_count; j++) {
          if (flat_ab[j] == saved_ab) { mapped = j; break; }
        }
      }
      if (mapped < 0) {
        /* Saved block no longer in flat[] (covered by another file,
         * or lost its apparent mapping).  Resume fails safe. */
        resumed = false;
        break;
      }
      chosen_flat[i] = mapped;
      chosen_entries[i] = flat[mapped];
      chosen_blocks[i] = flat_ab[mapped];
    }
  }

  if (!resumed) {
    png_bbk_resume_reset(local);
    depth = 0;
    at_leaf = false;
    leaf_need_crc = 0;
    leaf_last_actual = -1;
    iter_count = 0;
    for (uint32_t i = 0; i < n_fill; i++) {
      chosen_entries[i] = NULL;
      chosen_blocks[i] = -1;
      chosen_flat[i] = -1;
      next_flat[i] = 0;
    }
  }

  while (true) {
    if (depth == n_fill - 1) {
      if (!at_leaf) {
        uint32_t shifted_xor = 0;
        for (uint32_t i = 0; i + 1 < n_fill; i++) {
          PNGCrcEntry *e = chosen_entries[i];
          if (!e) {
            free(flat); free(flat_ab);
            free(chosen_entries); free(chosen_blocks);
            free(chosen_flat);    free(next_flat);
            png_bbk_resume_reset(local);
            return 0;
          }
          shifted_xor ^= png_crc_apply_forward(trail_forward[i], e->crc);
        }
        leaf_need_crc = png_crc_apply_inverse(
            last_minv, unknown_target ^ shifted_xor);
        leaf_last_actual = -1;
        at_leaf = true;
      }

      PNGCrcEntry *leaf = png_crc_table_find(ht, leaf_need_crc);
      if (leaf_last_actual >= 0) {
        while (leaf && leaf->actual_block != leaf_last_actual) {
          leaf = png_crc_table_next(leaf, leaf_need_crc);
        }
        if (leaf) {
          leaf = png_crc_table_next(leaf, leaf_need_crc);
        }
      }

      for (; leaf; leaf = png_crc_table_next(leaf, leaf_need_crc)) {
        if ((iter_count & 0x3FFULL) == 0ULL
            && png_reassembly_yield_requested(candidate)) {
          png_bbk_resume_save(local, retry_mode, suffix_start_nb,
              idat_start, bbk_crc_len, bbk_stored_crc, fill_pos, n_fill,
              depth, true, leaf_need_crc, leaf_last_actual, iter_count,
              next_flat, chosen_flat, chosen_blocks);
          free(flat); free(flat_ab);
          free(chosen_entries); free(chosen_blocks);
          free(chosen_flat);    free(next_flat);
          return -1;
        }
        int64_t leaf_ab = -1;
        if (!png_bbk_entry_allowed_with_path(leaf, chosen_entries,
                n_fill - 1, &leaf_ab)) {
          continue;
        }
        if (++iter_count > PNG_BBK_EXACT_ITER_CAP) {
          if (png_reassembly_yield_requested(candidate)) {
            png_bbk_resume_save(local, retry_mode, suffix_start_nb,
                idat_start, bbk_crc_len, bbk_stored_crc, fill_pos, n_fill,
                depth, true, leaf_need_crc, leaf_last_actual, 0,
                next_flat, chosen_flat, chosen_blocks);
            free(flat); free(flat_ab);
            free(chosen_entries); free(chosen_blocks);
            free(chosen_flat);    free(next_flat);
            return -1;
          }
          iter_count = 0;
        }

        for (uint32_t i = 0; i + 1 < n_fill; i++) {
          blockvector_set_apparent_blocknumber(candidate->b,
              suffix_start_nb + fill_pos[i], chosen_blocks[i]);
          inflate_blockvector_single_block(candidate->b,
              suffix_start_nb + fill_pos[i]);
        }
        blockvector_set_apparent_blocknumber(candidate->b,
            suffix_start_nb + fill_pos[n_fill - 1], leaf_ab);
        inflate_blockvector_single_block(candidate->b,
            suffix_start_nb + fill_pos[n_fill - 1]);
        if (png_bbk_verify_crc(candidate, idat_start,
                bbk_crc_len, bbk_stored_crc)) {
          free(flat); free(flat_ab);
          free(chosen_entries); free(chosen_blocks);
          free(chosen_flat);    free(next_flat);
          png_bbk_resume_reset(local);
          if (scalpel_state.mode_verbose) {
            lock_fprintf(stdout, "%sPNG BBK ALG: n_fill=%u SOLVED%s\n",
                GREEN, n_fill, BLACK);
          }
          return 1;
        }
        png_bbk_restore_fill_positions(candidate, suffix_start_nb,
            fill_pos, n_fill, last_block);
        leaf_last_actual = leaf->actual_block;
      }

      at_leaf = false;
      leaf_need_crc = 0;
      leaf_last_actual = -1;
      if (depth == 0) {
        free(flat); free(flat_ab);
        free(chosen_entries); free(chosen_blocks);
        free(chosen_flat);    free(next_flat);
        png_bbk_resume_reset(local);
        return 0;
      }
      depth--;
      continue;
    }

    bool advanced = false;
    for (int64_t idx = next_flat[depth]; idx < (int64_t)flat_count; idx++) {
      if ((iter_count & 0x3FFULL) == 0ULL
          && png_reassembly_yield_requested(candidate)) {
        png_bbk_resume_save(local, retry_mode, suffix_start_nb,
            idat_start, bbk_crc_len, bbk_stored_crc, fill_pos, n_fill,
            depth, false, 0, -1, iter_count, next_flat, chosen_flat,
            chosen_blocks);
        free(flat); free(flat_ab);
        free(chosen_entries); free(chosen_blocks);
        free(chosen_flat);    free(next_flat);
        return -1;
      }
      PNGCrcEntry *e = flat[idx];
      // Path-conflict check only — covered/unmapped already filtered out
      // during flat[] build above, so flat_ab[idx] is the valid apparent
      // blocknumber we'll place at this depth.
      int64_t ab = flat_ab[idx];
      bool conflict = false;
      for (uint32_t i = 0; i < depth; i++) {
        if (chosen_entries[i]
            && chosen_entries[i]->actual_block == e->actual_block) {
          conflict = true;
          break;
        }
      }
      if (conflict) {
        continue;
      }
      if (++iter_count > PNG_BBK_EXACT_ITER_CAP) {
        if (png_reassembly_yield_requested(candidate)) {
          png_bbk_resume_save(local, retry_mode, suffix_start_nb,
              idat_start, bbk_crc_len, bbk_stored_crc, fill_pos, n_fill,
              depth, false, 0, -1, 0, next_flat, chosen_flat,
              chosen_blocks);
          free(flat); free(flat_ab);
          free(chosen_entries); free(chosen_blocks);
          free(chosen_flat);    free(next_flat);
          return -1;
        }
        iter_count = 0;
      }
      chosen_entries[depth] = e;
      chosen_blocks[depth] = ab;
      chosen_flat[depth] = idx;
      next_flat[depth] = idx + 1;
      depth++;
      if (depth < PNG_BBK_EXACT_MAX_FILL) {
        chosen_entries[depth] = NULL;
        chosen_blocks[depth] = -1;
        chosen_flat[depth] = -1;
        next_flat[depth] = 0;
      }
      at_leaf = false;
      leaf_need_crc = 0;
      leaf_last_actual = -1;
      advanced = true;
      break;
    }

    if (advanced) {
      continue;
    }

    chosen_entries[depth] = NULL;
    chosen_blocks[depth] = -1;
    chosen_flat[depth] = -1;
    next_flat[depth] = 0;
    if (depth == 0) {
      free(flat); free(flat_ab);
      free(chosen_entries); free(chosen_blocks);
      free(chosen_flat);    free(next_flat);
      png_bbk_resume_reset(local);
      return 0;
    }
    depth--;
  }
}

static inline int png_bbk_single_swap_solve(CarveInfo *candidate,
                                             PNGCrcHashTable *ht,
                                             uint64_t suffix_start_nb,
                                             const uint32_t *fill_pos,
                                             uint32_t n_fill,
                                             int64_t last_block,
                                             uint64_t idat_start,
                                             uint64_t bbk_crc_len,
                                             uint32_t bbk_stored_crc) {
  // P1 (algebraic pre-filter): compute the current IDAT CRC once so we
  // can use CRC32 linearity to reject candidates that cannot possibly
  // produce the target stored CRC.  For a position p fully inside the
  // CRC region, swapping the block there changes the IDAT CRC by
  //    delta = shift(CRC(new), tail_p) XOR shift(CRC(old), tail_p)
  // where shift(c, L) = crc32_combine(c, 0, L).  A candidate e is a
  // possible match iff shift(e->crc, tail_p) equals the target
  // contribution: shift(CRC(old), tail_p) XOR (current_crc XOR
  // bbk_stored_crc).  This replaces a physical inflate+crc verify with
  // an inverse shift and exact CRC-table lookup.  The retry path then
  // physically verifies only exact CRC matches instead of scanning every
  // table entry.  This is the path that large-corpus OUTOFORDER candidates
  // reach when is_fill classifies nothing as fill.
  uint32_t current_crc = 0;
  bool have_cur_crc = false;
  {
    const char *vd = blockvector_get_data_pointer(candidate->b);
    uint64_t vdl = blockvector_get_data_length(candidate->b);
    if (vd && idat_start + bbk_crc_len <= vdl) {
      current_crc = crc32(crc32(0, NULL, 0),
          (const unsigned char *)(vd + idat_start), (uInt)bbk_crc_len);
      have_cur_crc = true;
    }
  }
  uint32_t needed_delta = have_cur_crc ? (current_crc ^ bbk_stored_crc) : 0;
  uint64_t idat_end = idat_start + bbk_crc_len;
  uint64_t bs_u = (uint64_t)scalpel_state.blocksize;

  for (uint32_t fi = 0; fi < n_fill; fi++) {
    uint32_t fpos = fill_pos[fi];
    int64_t orig_ab = blockvector_get_apparent_blocknumber(
        candidate->b, suffix_start_nb + fpos);

    // Per-position algebraic state.  pos_alg_ok=true means we can reject
    // candidates without inflating.  false means fall back to full
    // physical verify for every candidate (e.g. boundary-overlap blocks
    // where linearity doesn't hold over just the block's CRC).
    bool pos_alg_ok = false;
    uint32_t pos_current_crc = 0;
    uint32_t pos_required_crc = 0;
    uint64_t pos_tail = 0;
    {
      uint64_t pbs = (suffix_start_nb + fpos) * bs_u;
      uint64_t pbe = pbs + bs_u;
      bool pos_full_middle = (pbs >= idat_start && pbe <= idat_end);
      if (have_cur_crc && pos_full_middle && bs_u > 0) {
        pos_tail = idat_end - pbe;
        bool ok = false;
        uint32_t cur_bcrc = png_get_block_crc(orig_ab,
            candidate->needleidx, &ok);
        if (ok) {
          pos_current_crc = cur_bcrc;
          pos_alg_ok = true;
        }
      }
    }

    if (pos_alg_ok) {
      if (pos_tail == 0) {
        pos_required_crc = pos_current_crc ^ needed_delta;
      } else {
        uint32_t pos_inv[32];
        if (png_crc_inverse_for_len((z_off_t)pos_tail, pos_inv)) {
          pos_required_crc = pos_current_crc
              ^ png_crc_apply_inverse(pos_inv, needed_delta);
        } else {
          pos_alg_ok = false;
        }
      }
    }

    if (!pos_alg_ok
        && ht->total_entries > PNG_BBK_SINGLE_PHYSICAL_MAX_N) {
      continue;
    }

    uint32_t bk = 0;
    uint64_t scan_count = 0;
    PNGCrcEntry *scan_entry = NULL;
    PNGCrcEntry *direct_entry = pos_alg_ok
        ? png_crc_table_find(ht, pos_required_crc) : NULL;
    while (true) {
      PNGCrcEntry *e = NULL;
      if (pos_alg_ok) {
        if (!direct_entry) {
          break;
        }
        e = direct_entry;
        direct_entry = png_crc_table_next(direct_entry, pos_required_crc);
      } else {
        while (!scan_entry && bk < PNG_CRC_HASH_BUCKETS) {
          if ((bk & 0xFFU) == 0U
              && png_reassembly_yield_requested(candidate)) {
            return -1;
          }
          scan_entry = ht->buckets[bk++];
        }
        if (!scan_entry) {
          break;
        }
        e = scan_entry;
        scan_entry = scan_entry->next;
      }

      if ((scan_count++ & 0xFFULL) == 0ULL
          && png_reassembly_yield_requested(candidate)) {
        return -1;
      }
      if (filemirror_actual_block_covered(
              scalpel_state.filemirror, e->actual_block)) {
        continue;
      }
      int64_t trial_ab = filemirror_apparent_blocknumber(
          scalpel_state.filemirror, e->actual_block);
      if (trial_ab < 0 || trial_ab == orig_ab) {
        continue;
      }

      blockvector_set_apparent_blocknumber(candidate->b,
          suffix_start_nb + fpos, trial_ab);
      inflate_blockvector_single_block(candidate->b,
          suffix_start_nb + fpos);
      if (png_bbk_verify_crc(candidate, idat_start,
              bbk_crc_len, bbk_stored_crc)) {
        return 1;
      }
      blockvector_set_apparent_blocknumber(candidate->b,
          suffix_start_nb + fpos, orig_ab);
      inflate_blockvector_single_block(candidate->b,
          suffix_start_nb + fpos);
    }
  }
  png_bbk_restore_fill_positions(candidate, suffix_start_nb, fill_pos,
      n_fill, last_block);
  return 0;
}

static inline int png_bbk_run_solve(CarveInfo *candidate,
                                     PNGCarveState *local,
                                     PNGCrcHashTable *bbk_ht,
                                     uint64_t suffix_start_nb,
                                     const uint32_t *fill_pos,
                                     uint32_t n_fill,
                                     int64_t last_block,
                                     uint64_t idat_start,
                                     uint64_t idat_end,
                                     uint64_t bbk_crc_len,
                                     uint32_t bbk_stored_crc,
                                     bool retry_mode) {
  if (!candidate) {
    return 0;
  }
  if (n_fill == 0) {
    return png_bbk_verify_crc(candidate, idat_start,
        bbk_crc_len, bbk_stored_crc) ? 1 : 0;
  }

  uint32_t *active_fill_pos = (uint32_t *)malloc(
      (size_t)n_fill * sizeof(uint32_t));
  if (!active_fill_pos) {
    return 0;
  }
  uint32_t active_n_fill = 0;
  uint64_t bs = (uint64_t)scalpel_state.blocksize;
  for (uint32_t i = 0; i < n_fill; i++) {
    uint64_t bstart = (suffix_start_nb + fill_pos[i]) * bs;
    uint64_t bend = bstart + bs;
    if (bstart < idat_end && bend > idat_start) {
      active_fill_pos[active_n_fill++] = fill_pos[i];
    }
  }
  if (active_n_fill == 0) {
    free(active_fill_pos);
    return png_bbk_verify_crc(candidate, idat_start,
        bbk_crc_len, bbk_stored_crc) ? 1 : 0;
  }

  bool all_full = false;
  BBKFillInfo *finfo = png_bbk_build_fill_info(
      suffix_start_nb, active_fill_pos, active_n_fill,
      idat_start, idat_end, &all_full);
  uint32_t unknown_target = 0;
  bool bbk_geom_ok = finfo
      && png_bbk_compute_unknown_target(candidate,
          idat_start, idat_end, finfo, active_n_fill,
          bbk_stored_crc, &unknown_target);
  bool solved = false;

  if (bbk_geom_ok && all_full) {
    int run_rc = png_bbk_contiguous_run_solve(candidate, bbk_ht,
        suffix_start_nb, active_fill_pos, active_n_fill, last_block,
        idat_start, bbk_crc_len, bbk_stored_crc, unknown_target, finfo);
    if (run_rc > 0) {
      solved = true;
    }
  }

  if (!solved && bbk_geom_ok && all_full) {
    int exact_rc = png_bbk_exact_solve(candidate, local, bbk_ht,
        suffix_start_nb, active_fill_pos, active_n_fill, last_block,
        idat_start, bbk_crc_len, bbk_stored_crc, retry_mode,
        unknown_target, finfo);
    if (exact_rc < 0) {
      free(finfo);
      free(active_fill_pos);
      return -1;
    }
    solved = exact_rc > 0;
  }

  if (!solved && bbk_geom_ok) {
    int single_rc = png_bbk_single_swap_solve(candidate,
        bbk_ht, suffix_start_nb, active_fill_pos, active_n_fill,
        last_block, idat_start, bbk_crc_len,
        bbk_stored_crc);
    if (single_rc < 0) {
      free(finfo);
      free(active_fill_pos);
      return -1;
    }
    solved = single_rc > 0;
  }

  free(finfo);
  free(active_fill_pos);
  return solved ? 1 : 0;
}


// png_build_crc_table and png_ensure_crc_table are defined after
// png_get_block_crc (which they depend on).

static inline bool png_serialize_block_state(void **state, FILE *fp,
    StateSerialization mode) {
  size_t (*fb)(void *, size_t, size_t, FILE *) =
      mode == SERIALIZE
      ? (size_t (*)(void *, size_t, size_t, FILE *))fwrite
      : (size_t (*)(void *, size_t, size_t, FILE *))fread;
  if (mode == DESERIALIZE) {
    *state = malloc(sizeof(PNGBlockState));
    check_memory_allocation(*state, __LINE__, __FILE__, "state");
  }
  if (fb(*state, sizeof(PNGBlockState), 1, fp) != 1) {
    perror("png block state");
    handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
  }
  return true;
}

static inline void *png_clone_block_state(const void *srcstate) {
  PNGBlockState *d = (PNGBlockState *)malloc(sizeof(PNGBlockState));
  check_memory_allocation(d, __LINE__, __FILE__, "d");
  memcpy(d, srcstate, sizeof(PNGBlockState));
  return d;
}

static inline void png_free_block_state(void **state) {
  PNGBlockState **s = (PNGBlockState **)state;
  free(*s);
  *s = NULL;
}

static inline void png_print_block_state(const void *state) {
  const PNGBlockState *s = (const PNGBlockState *)state;
  if (!s) {
    fprintf(stdout, "NULL");
    return;
  }
  fprintf(stdout, "idat=%d", s->num_idat_markers);
  for (int i = 0; i < s->num_idat_markers; i++) {
    fprintf(stdout, " @%u", s->idat_offsets[i]);
  }
  if (s->has_iend) {
    fprintf(stdout, " IEND@%u", s->iend_offset);
  }
}

static inline size_t png_sizeof_block_state(const void *state) {
  (void)state;
  return sizeof(PNGBlockState);
}

static inline uint32_t png_block_validate(char *data,
					  uint64_t length,
					  BlockValidationDecision *decision,
					  uint64_t *validates_to,
					  uint32_t needleidx,
					  uint32_t blocksize,
					  void *blockhashkey) {
  (void)blocksize;

  if (*decision == BLOCK_CONFIDENCE_INVALID) {
    *decision = BLOCK_CONFIDENCE_VALID;
  }
  *validates_to = length > 0 ? length - 1 : 0;

  if (scalpel_state.no_defrag) {
    return needleidx;
  }

  // Scan for PNG chunk type markers within this block.
  // Chunk boundaries have the pattern: [4-byte length][4-byte type]
  // We look for "IDAT" and "IEND" type strings.
  PNGBlockState bs;
  memset(&bs, 0, sizeof(bs));

  const uint8_t *udata = (const uint8_t *)data;
  if (length >= 8) {
    for (uint64_t i = 0; i <= length - 4; i++) {
      if (udata[i] == 'I' && udata[i + 1] == 'D'
          && udata[i + 2] == 'A' && udata[i + 3] == 'T') {
        // Verify this looks like a real chunk: the 4 bytes before
        // should be a plausible length (preceded by type field).
        // At minimum, offset must be >= 4 (room for length field).
        if (i >= 4 && bs.num_idat_markers < PNG_BLOCK_MAX_MARKERS) {
          bs.idat_offsets[bs.num_idat_markers] = (uint32_t)i;
          bs.num_idat_markers++;
        }
      }
      if (udata[i] == 'I' && udata[i + 1] == 'E'
          && udata[i + 2] == 'N' && udata[i + 3] == 'D') {
        if (i >= 4) {
          bs.has_iend = true;
          bs.iend_offset = (uint32_t)i;
        }
      }
    }
  }

  // Pre-compute CRC32 of raw block data for crc32_combine in reassembly.
  bs.block_crc = crc32(crc32(0, NULL, 0), (const uint8_t *)data, length);

  if (blockhashkey) {
    block_put_state(blockhashkey, &bs);
  }

  return needleidx;
}


#define BS 8192 /* size of read block for CRC calculation (and zlib) */

/* outbuf is BS bytes for inflate output, plus padding so that
 * filter reconstruction overreads past eod stay within the
 * allocation instead of spilling into adjacent struct members.
 * 65536 handles images up to ~16K pixels wide (RGBA 8-bit). */
#define OUTBUF_PAD 65536

/* D4: Incremental state caching across validator calls.
 * When enabled, saves/restores full validator state (zlib stream, H6 pixel
 * buffers, B8 ratios, IDAT loop vars) at IDAT CRC boundaries so repeated
 * calls skip re-inflating the unchanged prefix.  Disable for benchmarking. */
#define PNG_D4_STATE_CACHE 1
#define PNG_B8F_DEBUG 0       /* diagnostic output for B8f sub-block ratio check */
#define PNG_B11_DEBUG 0       /* diagnostic output for B11 window-distance auto-correlation */
#define PNG_B12_DEBUG 0       /* diagnostic output for B12 MAD spike detection */

typedef unsigned char  uch;
typedef unsigned short ush;
typedef unsigned long  ulg;
typedef signed char    sch;
typedef signed short   ssh;
typedef signed long    slg;

/* IDAT CRC ring buffer: track the last 4 verified IDAT CRC positions.
 * Self-consistent wrong IDATs (from another PNG) can pass CRC and pollute
 * last_idat_crc_pos AND the previous entry.  A ring of 4 lets us go back
 * exactly 3 IDATs, skipping past up to 2 self-consistent wrong IDATs.
 *
 * idat_crc_ring_back3() returns the entry 3 positions before the most
 * recent push.  Returns 0 if fewer than 4 entries have been pushed
 * (not enough history to go back 3). */
#define IDAT_CRC_RING_SZ 4

/* fill_needed is computed from the actual idat_sz parsed from the IDAT
 * chunk header — no artificial cap on IDAT size. */
static inline uint64_t idat_crc_ring_back3(const uint64_t ring[IDAT_CRC_RING_SZ],
                                           int count) {
  if (count < IDAT_CRC_RING_SZ) return 0;  /* not enough history */
  /* Most recent push was at index (count-1) % 4.
   * 3 positions back is at index (count-4) % 4. */
  return ring[(count - IDAT_CRC_RING_SZ) % IDAT_CRC_RING_SZ];
}

/*
 * PNG-only validator (MNG/JNG support removed).
 *
 * Currently supported chunks, in order of appearance in pngcheck() function:
 *
 *   IHDR                         // PNG header chunk
 *
 *   PLTE IDAT IEND               // critical PNG chunks
 *
 *   bKGD cHRM eXIf gAMA gIFg gIFt gIFx      // ancillary PNG chunks
 *   hIST iCCP iTXt oFFs pCAL pHYs sBIT sCAL
 *   sPLT sRGB sTER tEXt zTXt tIME tRNS
 *
 *   cmOD cmPP cpIp mkBF mkBS mkBT mkTS pcLb  // known private PNG chunks
 *   prVW spAL
 *
 *   acTL fcTL fdAT                          // APNG chunks
 *
 *   cICP mDCV cLLI caBX                     // PNG 3rd/4th edition chunks
 *
 *   iDOT                                    // Apple chunks
 *
 * Known unregistered, "public" chunks (invalid and flagged as such):
 *
 *   pRVW nULL tXMP
 */

/* Mark's macros to extract big-endian short and long ints: */
#define SH(p) ((ush)(uch)((p)[1]) | ((ush)(uch)((p)[0]) << 8))
#define LG(p) ((ulg)(SH((p)+2)) | ((ulg)(SH(p)) << 16))
#define SSH(p) ((ssh)(uch)((p)[1]) | ((ssh)(sch)((p)[0]) << 8))
#define SLG(p) ((slg)(SH((p)+2)) | ((slg)(SSH(p)) << 16))

/* for check_magic(): PNG only */
#define DO_PNG  0

#define isASCIIalpha(x)     (ascii_alpha_table[x] & 0x1)

#define ANCILLARY(chunkID)  ((chunkID)[0] & 0x20)
#define PRIVATE(chunkID)    ((chunkID)[1] & 0x20)
#define RESERVED(chunkID)   ((chunkID)[2] & 0x20)
#define SAFECOPY(chunkID)   ((chunkID)[3] & 0x20)
#define CRITICAL(chunkID)   (!ANCILLARY(chunkID))
#define PUBLIC(chunkID)     (!PRIVATE(chunkID))

#define is_err(x, mem)   (mem->global_error >= (x))
#define no_err(x, mem)   (mem->global_error < (x))


enum {
  kOK = 0,
  kWarning,           /* could be an error in some circumstances but not all */
  kCommandLineError,  /* pilot error */
  kMinorError,        /* minor spec errors (e.g., out-of-range values) */
  kMajorError,        /* file corruption, invalid chunk length/layout, etc. */
  kCriticalError      /* unexpected EOF or other file(system) error */
};


/* what the PNG magic numbers should be */
static const uch good_PNG_magic[8] = {137, 80, 78, 71, 13, 10, 26, 10};

/* EBCDIC-safe isalpha() table */
static const uch ascii_alpha_table[256] = {
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  0,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,0,0,0,0,0,
  0,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,0,0,0,0,0,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
};

/* Forbidden characters in keywords */
static const uch latin1_keyword_forbidden[256] = {
  1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,
  1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
  1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
};

/* Discouraged (control) characters in tEXt/zTXt text */
static const uch latin1_text_discouraged[256] = {
  1,1,1,1,1,1,1,1,1,1,0,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,
  1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
};


/* PNG stuff */

static const char *png_type[] = {		/* IHDR, tRNS */
  "grayscale",
  "INVALID",
  "RGB",
  "palette",   /* was "colormap" */
  "grayscale+alpha",
  "INVALID",
  "RGB+alpha"
};


static const int eqn_params[] = { 2, 3, 3, 4 };		/* pCAL */


// Thread-local zlib storage used during one pngcheck execution.  The validator
// tears this stream down at the end of each call to png_validate_core(), so it
// is not persisted across independent validation calls.
_Thread_local static z_stream zstrm;
_Thread_local static bool zstrm_initialized = false;

/* Forward declarations needed by checkpoint structs */
typedef struct printbuf_state {
  int cr;
  int lf;
  int nul;
  int control;
  int esc;
} printbuf_state;

struct PNGBlockCRC {
  uint64_t pos;
  ulg      crc;
};

// D4: PNG checkpoint state structures for incremental state caching
typedef struct PNGCheckpointLocals {
    long w, h;
    int bitdepth, sampledepth, ityp, lace, nplte;
    ulg crc, filecrc;
    long sz;
    int toread;
    ulg zhead;
    long num_chunks;
    int have_IHDR, have_IEND, have_PLTE, have_IDAT, last_is_IDAT;
    int have_bKGD, have_cHRM, have_eXIf, have_gAMA, have_hIST;
    int have_iCCP, have_oFFs, have_pCAL, have_pHYs, have_sBIT;
    int have_sCAL, have_sRGB, have_sTER, have_tIME, have_tRNS;
    int have_acTL, have_fcTL, have_iDOT, have_cICP, have_mDCV, have_cLLI, have_caBX;
    int just_seen_fcTL;
    ulg num_frames, num_plays, num_fcTL, next_sequence_number, sequence_number;
    ulg frame_width, frame_height, x_offset, y_offset;
    ush delay_num, delay_den;
    uch dispose_op, blend_op;
    printbuf_state prbuf_state;
} PNGCheckpointLocals;

typedef struct PNGM2ResumeState {
    bool active;
    bool best_found;
    bool best_validated;
    uint8_t pad;
    uint32_t fill_needed;
    uint32_t bucket;
    uint64_t suffix_nb;
    uint64_t crc_pos;
    int64_t suffix_actual;
    int64_t next_actual;
    uint64_t best_validates_to;
    uint64_t best_advance_to;
    uint32_t best_locality;
    uint32_t best_pad;
    int64_t best_left_actual;
    int64_t best_right_actual;
    int64_t best_suffix_actual;
} PNGM2ResumeState;

static inline void png_m2_resume_reset(PNGM2ResumeState *state) {
    memset(state, 0, sizeof(*state));
    state->suffix_actual = -1;
    state->next_actual = -1;
    state->best_left_actual = -1;
    state->best_right_actual = -1;
    state->best_suffix_actual = -1;
}

typedef struct PNGCarveState {
    bool valid;
    uint64_t prefix_hash;         /* XXH3 of data[0..checkpoint_curpos) */
    uint64_t checkpoint_curpos;   /* mem->curpos at save time */
    uint64_t data_length;         /* mem->length at save time */

    /* Snapshot of PNGMemIO fields (NOT data/length/carvehashkey) */
    int global_error;
    int64_t errpos;
    uint64_t curpos;
    uint64_t last_good_pos;
    int first_idat;
    int zlib_error;
    int check_zlib;
    unsigned zlib_windowbits;
    int zlib_started;
    int zlib_stopped;
    int check_windowbits;
    uint64_t last_good_filter_pos;
    uint64_t inflate_consumed_pos;
    bool errpos_is_precise;
    uint64_t last_filter_blk;
    uint64_t last_filter_blk_boundary;
    uint64_t last_idat_crc_pos;
    uint64_t last_chunk_crc_pos;   /* curpos after last successful CRC of ANY chunk type */
    uint64_t prev_idat_crc_pos;
    uint64_t idat_crc_ring[IDAT_CRC_RING_SZ];
    int      idat_crc_ring_count;
    bool have_iend;
    uint32_t blocksize;
    long img_width;
    long img_height;
    int img_bitdepth;

    /* CRC checkpoint array */
    struct PNGBlockCRC *crc_ckpts;
    int n_crc_ckpts;
    int max_crc_ckpts;
    ulg idat_stored_crc;
    uint64_t idat_data_start;
    long idat_data_sz;
    bool mid_idat;

    /* H6 pixel gradient gate */
    uint8_t *prev_row_pixels;
    uint8_t *cur_row_pixels;
    uint32_t pixel_row_bytes;
    uint8_t bpp_bytes;
    double running_mad_sum;
    uint64_t mad_count;
    uint32_t consecutive_good_rows;
    double   post_crc_mad_sum;
    uint32_t post_crc_mad_count;

    /* H7 Paeth fraction */
    double   running_corr_sum;
    uint64_t corr_count;
    double   post_crc_corr_sum;
    uint32_t post_crc_corr_count;

    /* B8 inflate rate */
    uint64_t b8_block_in_start;
    uint64_t b8_block_out_start;
    double b8_running_ratio;
    double b8_running_ratio_sq;
    uint64_t b8_ratio_count;
    uint64_t b8_last_block;
    uint64_t b8_total_out;
    uint64_t b8_anomaly_pos;

    /* Z9: post-Z_STREAM_END IDAT data tracking */

    /* B9: Filter type distribution anomaly detection */
    uint32_t b9_block_filt[5];
    uint32_t b9_block_rows;
    double   b9_running_frac[5];
    double   b9_running_l1;
    double   b9_running_l1_sq;
    uint64_t b9_block_count;
    uint64_t b9_anomaly_pos;

    /* B10: Per-block MAD average anomaly detection */
    double   b10_block_mad_sum;
    uint32_t b10_block_mad_count;
    double   b10_running_mad_avg;
    double   b10_running_mad_avg_sq;
    uint64_t b10_block_count;
    uint64_t b10_anomaly_pos;
    double   b10_last_mad;
    double   b10_max_post_crc_mad;

    /* B8f: Fine-grained sub-block compression ratio */
    uint64_t b8f_sub_blocksize;
    uint64_t b8f_block_in_start;
    uint64_t b8f_block_out_start;
    double   b8f_running_ratio;
    double   b8f_running_ratio_sq;
    uint64_t b8f_ratio_count;
    uint64_t b8f_last_sub_blk;
    uint64_t b8f_anomaly_pos;

    /* B11: Auto-correlation at zlib window distance.
     * Ring buffer of per-row pixel checksums.  Compare current row
     * to the row from ~32KB of decompressed output ago. */
    uint8_t  b11_byte_ring[65536]; /* 64KB ring of raw decompressed bytes */
    uint64_t b11_byte_wpos;        /* total bytes written to ring */
    uint32_t b11_hash_ring[128];   /* hash of each 256-byte-spaced 64-byte sample */
    uint32_t b11_hash_wpos;        /* write position in hash ring */
    uint32_t b11_byte_match_run;   /* consecutive hash-matched samples */
    uint64_t b11_byte_last_check;  /* decompressed pos of last similarity check */
    uint64_t b11_anomaly_pos;      /* file pos of echo anomaly; 0 = none */
    uint64_t b12_spike_pos;        /* B12: block boundary with MAD spike */
    double   b12_spike_mad;
    double   b12_spike_ratio;
    uint64_t b12_rows_into_block;
    /* Combined suspicion */
    double   b8_suspicion;
    double   b8_max_suspicion_since_crc;
    double   b9_suspicion;
    double   b10_suspicion;
    double   combined_max_sum;
    uint64_t combined_anomaly_pos;
    uint64_t post_zend_idat_bytes;  /* IDAT body bytes encountered after Z_STREAM_END */

    /* IDAT loop state */
    long cur_y;
    int cur_pass;
    long cur_xoff, cur_yoff;
    long cur_xskip, cur_yskip;
    long cur_width;
    long cur_linebytes;
    long numfilt;
    long numfilt_this_block;
    long numfilt_total;
    long numfilt_pass[7];

    /* inflate output pointer offset (relative to outbuf start).
     * pngcheck's outbuf wrapping trick leaves inflate_out_ptr at
     * outbuf + delta, where delta > 0 means a partial row was already
     * "consumed" by reading past eod.  On restore we must skip those
     * delta bytes so row boundaries stay aligned. */
    ptrdiff_t inflate_out_ptr_offset;

    /* zlib stream snapshot (heap-allocated to avoid aliased internals on memcpy) */
    z_stream *zstrm_copy;
    bool has_zstrm;

    /* Unconsumed inflate input at save time.  The drain loop overwrites
     * mem->buffer after the inflate loop exits, so zstrm.next_in becomes
     * stale.  We save the leftover bytes here and replay them on restore. */
    uint8_t *zstrm_leftover;
    unsigned zstrm_leftover_count;

    /* CRC solver resume state — preserved across progress checkpoints so
     * the solver doesn't restart from scratch after yield/reassign.
     * Zero-initialized means "start from the beginning."
     * Reset when solver_suffix_nb changes (new suffix position). */
    int64_t  solver_suffix_idx;     /* suffix candidate index (si) to resume at */
    int64_t  solver_right_idx;      /* er1 flat index to resume at */
    int64_t  solver_right_idx2;     /* er2 flat index to resume at */
    uint64_t solver_suffix_nb;      /* suffix_start_nb these fields apply to */
    uint8_t  solver_phase;          /* 0 none, 1 M3-B, 2 M3-C, 3 M4,
                                     * 4 M3 split-run, 5 suffix-run */
    uint8_t  solver_pair_idx;       /* M3 split-run pair index */
    uint16_t solver_phase_pad;
    uint64_t solver_m4_universe_hash;
    uint64_t solver_table_epoch;    /* apparent-block mapping epoch */
    PNGM2ResumeState m2_resume;

    /* Heap-backed solver table cache.  It is cloned for in-process queue
     * handoff, but is intentionally dropped from disk checkpoints; scalar
     * resume fields below are the durable progress record. */
    PNGSolverContext *solver_ctx;

    /* GAP fast path resume state — direct field so it survives
     * solver_ctx free/rebuild and disk checkpoints.
     * Checkpoints can fire at any time and yielding without saving state
     * causes the 1M-apparent-block sliding scan to restart from 0 every
     * call — never completing.  Keyed by (suffix_nb, crc_pos, M).
     * gap_fast_exhausted=true when the scan finished without finding;
     * subsequent calls for the same key skip GAP entirely so MitM gets
     * its turn.  A confirmed exhausted scan stores gap_fast_si=-1; older
     * checkpoints without that sentinel are rescanned once so pre-batching
     * false exhaustion does not permanently poison the candidate. */
    bool     gap_fast_resume_valid;
    bool     gap_fast_exhausted;
    uint32_t gap_fast_M;
    int64_t  gap_fast_si;
    int64_t  gap_fast_start;
    uint64_t gap_fast_suffix_nb;
    uint64_t gap_fast_crc_pos;

    /* D=1 algebraic search resume (for the M<1 fallback branch).
     * Keyed by (suffix_nb, crc_pos, fill_needed) so that re-entry after
     * trim/backtrack to the same crc_pos but different geometry
     * invalidates stale fpos/bk (review finding #5). */
    bool     d1_resume_valid;
    uint32_t d1_resume_fpos;
    uint32_t d1_resume_bk;
    uint64_t d1_resume_crc_pos;
    uint64_t d1_resume_suffix_nb;
    uint32_t d1_resume_fill_needed;

    /* BBK exact-solver resume state — preserved across progress checkpoints.
     * Unlike the older CRC solver, BBK exact search now walks a generic DFS
     * frontier.  Persist the frontier so yields do not restart the search. */
    bool     bbk_resume_active;
    bool     bbk_resume_retry;
    bool     bbk_resume_at_leaf;
    uint8_t  bbk_resume_depth;
    uint32_t bbk_resume_n_fill;
    uint64_t bbk_resume_suffix_nb;
    uint64_t bbk_resume_idat_start;
    uint64_t bbk_resume_crc_len;
    uint32_t bbk_resume_stored_crc;
    uint32_t bbk_resume_leaf_need_crc;
    int64_t  bbk_resume_leaf_last_actual;
    uint64_t bbk_resume_iter_count;
    uint32_t bbk_resume_fill_pos[PNG_BBK_EXACT_MAX_FILL];
    int64_t  bbk_resume_next_flat[PNG_BBK_EXACT_MAX_FILL];
    int64_t  bbk_resume_chosen_flat[PNG_BBK_EXACT_MAX_FILL];
    /* Actual block numbers corresponding to chosen_flat[] at save time.
     * flat[] is rebuilt each call by filtering current coverage, so the
     * same flat index can point to a different entry after coverage
     * changes.  On resume we re-map saved actuals back to current flat[]
     * indices; if a saved actual is no longer in flat[], resume fails
     * safe (review finding #4). */
    int64_t  bbk_resume_chosen_actual[PNG_BBK_EXACT_MAX_FILL];

    /* Exhaustion deferral.  Under parallel reassembly, other PNGs may have
     * validated into the shadow blockmap while this candidate was searching.
     * Do not cement a partial until the primary blockmap has had a checkpoint
     * swap chance to include that work. */
    bool     exhausted_waiting_for_checkpoint;
    uint64_t exhausted_wait_suffix_nb;
    uint64_t exhausted_wait_crc_pos;
    uint64_t exhausted_wait_validated_files;
    time_t   exhausted_wait_checkpoint_sec;
    long     exhausted_wait_checkpoint_nsec;

    uint64_t safe_partial_blocks;
    uint64_t safe_partial_length;

    /* pngcheck locals */
    PNGCheckpointLocals loc;
} PNGCarveState;

typedef struct PNGReassemblyPrivateState {
  int64_t  solver_suffix_idx;
  int64_t  solver_right_idx;
  int64_t  solver_right_idx2;
  uint64_t solver_suffix_nb;
  uint8_t  solver_phase;
  uint8_t  solver_pair_idx;
  uint16_t solver_phase_pad;
  uint64_t solver_m4_universe_hash;
  uint64_t solver_table_epoch;
  PNGM2ResumeState m2_resume;
  PNGSolverContext *solver_ctx;
  bool     gap_fast_resume_valid;
  bool     gap_fast_exhausted;
  uint32_t gap_fast_M;
  int64_t  gap_fast_si;
  int64_t  gap_fast_start;
  uint64_t gap_fast_suffix_nb;
  uint64_t gap_fast_crc_pos;
  bool     d1_resume_valid;
  uint32_t d1_resume_fpos;
  uint32_t d1_resume_bk;
  uint64_t d1_resume_crc_pos;
  uint64_t d1_resume_suffix_nb;
  uint32_t d1_resume_fill_needed;
  bool     bbk_resume_active;
  bool     bbk_resume_retry;
  bool     bbk_resume_at_leaf;
  uint8_t  bbk_resume_depth;
  uint32_t bbk_resume_n_fill;
  uint64_t bbk_resume_suffix_nb;
  uint64_t bbk_resume_idat_start;
  uint64_t bbk_resume_crc_len;
  uint32_t bbk_resume_stored_crc;
  uint32_t bbk_resume_leaf_need_crc;
  int64_t  bbk_resume_leaf_last_actual;
  uint64_t bbk_resume_iter_count;
  uint32_t bbk_resume_fill_pos[PNG_BBK_EXACT_MAX_FILL];
  int64_t  bbk_resume_next_flat[PNG_BBK_EXACT_MAX_FILL];
  int64_t  bbk_resume_chosen_flat[PNG_BBK_EXACT_MAX_FILL];
  int64_t  bbk_resume_chosen_actual[PNG_BBK_EXACT_MAX_FILL];
  bool     exhausted_waiting_for_checkpoint;
  uint64_t exhausted_wait_suffix_nb;
  uint64_t exhausted_wait_crc_pos;
  uint64_t exhausted_wait_validated_files;
  time_t   exhausted_wait_checkpoint_sec;
  long     exhausted_wait_checkpoint_nsec;
  uint64_t safe_partial_blocks;
  uint64_t safe_partial_length;
} PNGReassemblyPrivateState;

static inline void png_solver_resume_reset(PNGCarveState *local) {
  if (!local) {
    return;
  }
  local->solver_suffix_idx = 0;
  local->solver_right_idx = 0;
  local->solver_right_idx2 = 0;
  local->solver_suffix_nb = 0;
  local->solver_phase = 0;
  local->solver_pair_idx = 0;
  local->solver_phase_pad = 0;
  local->solver_m4_universe_hash = 0;
  png_m2_resume_reset(&local->m2_resume);
}

static inline void png_bbk_resume_reset(PNGCarveState *local) {
  if (!local) {
    return;
  }
  local->bbk_resume_active = false;
  local->bbk_resume_retry = false;
  local->bbk_resume_at_leaf = false;
  local->bbk_resume_depth = 0;
  local->bbk_resume_n_fill = 0;
  local->bbk_resume_suffix_nb = 0;
  local->bbk_resume_idat_start = 0;
  local->bbk_resume_crc_len = 0;
  local->bbk_resume_stored_crc = 0;
  local->bbk_resume_leaf_need_crc = 0;
  local->bbk_resume_leaf_last_actual = -1;
  local->bbk_resume_iter_count = 0;
  for (uint32_t i = 0; i < PNG_BBK_EXACT_MAX_FILL; i++) {
    local->bbk_resume_fill_pos[i] = 0;
    local->bbk_resume_next_flat[i] = 0;
    local->bbk_resume_chosen_flat[i] = -1;
    local->bbk_resume_chosen_actual[i] = -1;
  }
}

static inline int64_t png_bbk_resume_chosen_actual_get(
    const PNGCarveState *local, uint32_t i) {
  if (!local || i >= PNG_BBK_EXACT_MAX_FILL) { return -1; }
  return local->bbk_resume_chosen_actual[i];
}

static inline bool png_bbk_resume_matches(PNGCarveState *local,
                                           bool retry_mode,
                                           uint64_t suffix_start_nb,
                                           uint64_t idat_start,
                                           uint64_t bbk_crc_len,
                                           uint32_t bbk_stored_crc,
                                           const uint32_t *fill_pos,
                                           uint32_t n_fill) {
  if (!local || !local->bbk_resume_active) {
    return false;
  }
  if (local->bbk_resume_retry != retry_mode
      || local->bbk_resume_suffix_nb != suffix_start_nb
      || local->bbk_resume_idat_start != idat_start
      || local->bbk_resume_crc_len != bbk_crc_len
      || local->bbk_resume_stored_crc != bbk_stored_crc
      || local->bbk_resume_n_fill != n_fill) {
    return false;
  }
  return memcmp(local->bbk_resume_fill_pos, fill_pos,
      n_fill * sizeof(uint32_t)) == 0;
}

static inline bool png_bbk_resume_load(PNGCarveState *local,
                                        uint32_t *depth,
                                        bool *at_leaf,
                                        uint32_t *leaf_need_crc,
                                        int64_t *leaf_last_actual,
                                        uint64_t *iter_count,
                                        int64_t *next_flat,
                                        int64_t *chosen_flat) {
  if (!local || !local->bbk_resume_active) {
    return false;
  }
  *depth = local->bbk_resume_depth;
  *at_leaf = local->bbk_resume_at_leaf;
  *leaf_need_crc = local->bbk_resume_leaf_need_crc;
  *leaf_last_actual = local->bbk_resume_leaf_last_actual;
  *iter_count = local->bbk_resume_iter_count;
  // Copy only n_fill entries.  The caller's next_flat/chosen_flat are
  // heap-allocated to n_fill × sizeof(int64_t) (see the exact_solve
  // heap-alloc conversion in the prior session); the struct-side
  // bbk_resume_next_flat/bbk_resume_chosen_flat are still MAX_FILL-sized,
  // but only the first n_fill entries are meaningful.  Copying the full
  // MAX_FILL overwrites 2 KiB of heap past the caller's buffer.
  uint32_t nf = local->bbk_resume_n_fill;
  if (nf > PNG_BBK_EXACT_MAX_FILL) { nf = PNG_BBK_EXACT_MAX_FILL; }
  memcpy(next_flat, local->bbk_resume_next_flat,
      nf * sizeof(int64_t));
  memcpy(chosen_flat, local->bbk_resume_chosen_flat,
      nf * sizeof(int64_t));
  return true;
}

static inline void png_bbk_resume_init(PNGCarveState *local,
                                        bool retry_mode,
                                        uint64_t suffix_start_nb,
                                        uint64_t idat_start,
                                        uint64_t bbk_crc_len,
                                        uint32_t bbk_stored_crc,
                                        const uint32_t *fill_pos,
                                        uint32_t n_fill) {
  if (!local) {
    return;
  }
  png_bbk_resume_reset(local);
  local->bbk_resume_active = true;
  local->bbk_resume_retry = retry_mode;
  local->bbk_resume_suffix_nb = suffix_start_nb;
  local->bbk_resume_idat_start = idat_start;
  local->bbk_resume_crc_len = bbk_crc_len;
  local->bbk_resume_stored_crc = bbk_stored_crc;
  local->bbk_resume_n_fill = n_fill;
  memcpy(local->bbk_resume_fill_pos, fill_pos,
      n_fill * sizeof(uint32_t));
}

static inline void png_bbk_resume_save(PNGCarveState *local,
                                        bool retry_mode,
                                        uint64_t suffix_start_nb,
                                        uint64_t idat_start,
                                        uint64_t bbk_crc_len,
                                        uint32_t bbk_stored_crc,
                                        const uint32_t *fill_pos,
                                        uint32_t n_fill,
                                        uint32_t depth,
                                        bool at_leaf,
                                        uint32_t leaf_need_crc,
                                        int64_t leaf_last_actual,
                                        uint64_t iter_count,
                                        const int64_t *next_flat,
                                        const int64_t *chosen_flat,
                                        const int64_t *chosen_blocks) {
  if (!local) {
    return;
  }
  png_bbk_resume_init(local, retry_mode, suffix_start_nb, idat_start,
      bbk_crc_len, bbk_stored_crc, fill_pos, n_fill);
  local->bbk_resume_depth = depth;
  local->bbk_resume_at_leaf = at_leaf;
  local->bbk_resume_leaf_need_crc = leaf_need_crc;
  local->bbk_resume_leaf_last_actual = leaf_last_actual;
  local->bbk_resume_iter_count = iter_count;
  // Copy only n_fill entries — caller's next_flat/chosen_flat are
  // heap-allocated to exactly n_fill × sizeof(int64_t).  See matching
  // comment in png_bbk_resume_load.
  uint32_t nf = n_fill;
  if (nf > PNG_BBK_EXACT_MAX_FILL) { nf = PNG_BBK_EXACT_MAX_FILL; }
  memcpy(local->bbk_resume_next_flat, next_flat,
      nf * sizeof(int64_t));
  memcpy(local->bbk_resume_chosen_flat, chosen_flat,
      nf * sizeof(int64_t));
  /* Also save the apparent block numbers (review finding #4): on
   * resume we must verify flat[] still maps the saved flat index to
   * the same block — coverage changes rebuild flat[] with shifted
   * indices.  Any mismatch forces a safe resume-fail (full restart). */
  memcpy(local->bbk_resume_chosen_actual, chosen_blocks,
      nf * sizeof(int64_t));
}

static inline void png_gap_resume_reset(PNGCarveState *local) {
  if (!local) {
    return;
  }
  local->gap_fast_resume_valid = false;
  local->gap_fast_exhausted = false;
  local->gap_fast_M = 0;
  local->gap_fast_si = 0;
  local->gap_fast_start = 0;
  local->gap_fast_suffix_nb = 0;
  local->gap_fast_crc_pos = 0;
}

static inline void png_d1_resume_reset(PNGCarveState *local) {
  if (!local) {
    return;
  }
  local->d1_resume_valid = false;
  local->d1_resume_fpos = 0;
  local->d1_resume_bk = 0;
  local->d1_resume_crc_pos = 0;
  local->d1_resume_suffix_nb = 0;
  local->d1_resume_fill_needed = 0;
}

static inline void png_reassembly_search_resume_reset(PNGCarveState *local) {
  if (!local) {
    return;
  }
  png_solver_resume_reset(local);
  png_gap_resume_reset(local);
  png_d1_resume_reset(local);
  png_bbk_resume_reset(local);
  png_solver_ctx_free(&local->solver_ctx);
}

static inline void png_reassembly_private_save(
    PNGReassemblyPrivateState *dst, const PNGCarveState *src) {
  memset(dst, 0, sizeof(*dst));
  if (!src) {
    return;
  }
  dst->solver_suffix_idx = src->solver_suffix_idx;
  dst->solver_right_idx = src->solver_right_idx;
  dst->solver_right_idx2 = src->solver_right_idx2;
  dst->solver_suffix_nb = src->solver_suffix_nb;
  dst->solver_phase = src->solver_phase;
  dst->solver_pair_idx = src->solver_pair_idx;
  dst->solver_phase_pad = src->solver_phase_pad;
  dst->solver_m4_universe_hash = src->solver_m4_universe_hash;
  dst->solver_table_epoch = src->solver_table_epoch;
  dst->m2_resume = src->m2_resume;
  dst->solver_ctx = src->solver_ctx;
  dst->gap_fast_resume_valid = src->gap_fast_resume_valid;
  dst->gap_fast_exhausted = src->gap_fast_exhausted;
  dst->gap_fast_M = src->gap_fast_M;
  dst->gap_fast_si = src->gap_fast_si;
  dst->gap_fast_start = src->gap_fast_start;
  dst->gap_fast_suffix_nb = src->gap_fast_suffix_nb;
  dst->gap_fast_crc_pos = src->gap_fast_crc_pos;
  dst->d1_resume_valid = src->d1_resume_valid;
  dst->d1_resume_fpos = src->d1_resume_fpos;
  dst->d1_resume_bk = src->d1_resume_bk;
  dst->d1_resume_crc_pos = src->d1_resume_crc_pos;
  dst->d1_resume_suffix_nb = src->d1_resume_suffix_nb;
  dst->d1_resume_fill_needed = src->d1_resume_fill_needed;
  dst->bbk_resume_active = src->bbk_resume_active;
  dst->bbk_resume_retry = src->bbk_resume_retry;
  dst->bbk_resume_at_leaf = src->bbk_resume_at_leaf;
  dst->bbk_resume_depth = src->bbk_resume_depth;
  dst->bbk_resume_n_fill = src->bbk_resume_n_fill;
  dst->bbk_resume_suffix_nb = src->bbk_resume_suffix_nb;
  dst->bbk_resume_idat_start = src->bbk_resume_idat_start;
  dst->bbk_resume_crc_len = src->bbk_resume_crc_len;
  dst->bbk_resume_stored_crc = src->bbk_resume_stored_crc;
  dst->bbk_resume_leaf_need_crc = src->bbk_resume_leaf_need_crc;
  dst->bbk_resume_leaf_last_actual = src->bbk_resume_leaf_last_actual;
  dst->bbk_resume_iter_count = src->bbk_resume_iter_count;
  memcpy(dst->bbk_resume_fill_pos, src->bbk_resume_fill_pos,
         sizeof(dst->bbk_resume_fill_pos));
  memcpy(dst->bbk_resume_next_flat, src->bbk_resume_next_flat,
         sizeof(dst->bbk_resume_next_flat));
  memcpy(dst->bbk_resume_chosen_flat, src->bbk_resume_chosen_flat,
         sizeof(dst->bbk_resume_chosen_flat));
  memcpy(dst->bbk_resume_chosen_actual, src->bbk_resume_chosen_actual,
         sizeof(dst->bbk_resume_chosen_actual));
  dst->exhausted_waiting_for_checkpoint =
      src->exhausted_waiting_for_checkpoint;
  dst->exhausted_wait_suffix_nb = src->exhausted_wait_suffix_nb;
  dst->exhausted_wait_crc_pos = src->exhausted_wait_crc_pos;
  dst->exhausted_wait_validated_files =
      src->exhausted_wait_validated_files;
  dst->exhausted_wait_checkpoint_sec =
      src->exhausted_wait_checkpoint_sec;
  dst->exhausted_wait_checkpoint_nsec =
      src->exhausted_wait_checkpoint_nsec;
  dst->safe_partial_blocks = src->safe_partial_blocks;
  dst->safe_partial_length = src->safe_partial_length;
}

static inline void png_reassembly_private_restore(
    PNGCarveState *dst, const PNGReassemblyPrivateState *src) {
  if (!dst || !src) {
    return;
  }
  dst->solver_suffix_idx = src->solver_suffix_idx;
  dst->solver_right_idx = src->solver_right_idx;
  dst->solver_right_idx2 = src->solver_right_idx2;
  dst->solver_suffix_nb = src->solver_suffix_nb;
  dst->solver_phase = src->solver_phase;
  dst->solver_pair_idx = src->solver_pair_idx;
  dst->solver_phase_pad = src->solver_phase_pad;
  dst->solver_m4_universe_hash = src->solver_m4_universe_hash;
  dst->solver_table_epoch = src->solver_table_epoch;
  dst->m2_resume = src->m2_resume;
  dst->solver_ctx = src->solver_ctx;
  dst->gap_fast_resume_valid = src->gap_fast_resume_valid;
  dst->gap_fast_exhausted = src->gap_fast_exhausted;
  dst->gap_fast_M = src->gap_fast_M;
  dst->gap_fast_si = src->gap_fast_si;
  dst->gap_fast_start = src->gap_fast_start;
  dst->gap_fast_suffix_nb = src->gap_fast_suffix_nb;
  dst->gap_fast_crc_pos = src->gap_fast_crc_pos;
  dst->d1_resume_valid = src->d1_resume_valid;
  dst->d1_resume_fpos = src->d1_resume_fpos;
  dst->d1_resume_bk = src->d1_resume_bk;
  dst->d1_resume_crc_pos = src->d1_resume_crc_pos;
  dst->d1_resume_suffix_nb = src->d1_resume_suffix_nb;
  dst->d1_resume_fill_needed = src->d1_resume_fill_needed;
  dst->bbk_resume_active = src->bbk_resume_active;
  dst->bbk_resume_retry = src->bbk_resume_retry;
  dst->bbk_resume_at_leaf = src->bbk_resume_at_leaf;
  dst->bbk_resume_depth = src->bbk_resume_depth;
  dst->bbk_resume_n_fill = src->bbk_resume_n_fill;
  dst->bbk_resume_suffix_nb = src->bbk_resume_suffix_nb;
  dst->bbk_resume_idat_start = src->bbk_resume_idat_start;
  dst->bbk_resume_crc_len = src->bbk_resume_crc_len;
  dst->bbk_resume_stored_crc = src->bbk_resume_stored_crc;
  dst->bbk_resume_leaf_need_crc = src->bbk_resume_leaf_need_crc;
  dst->bbk_resume_leaf_last_actual = src->bbk_resume_leaf_last_actual;
  dst->bbk_resume_iter_count = src->bbk_resume_iter_count;
  memcpy(dst->bbk_resume_fill_pos, src->bbk_resume_fill_pos,
         sizeof(dst->bbk_resume_fill_pos));
  memcpy(dst->bbk_resume_next_flat, src->bbk_resume_next_flat,
         sizeof(dst->bbk_resume_next_flat));
  memcpy(dst->bbk_resume_chosen_flat, src->bbk_resume_chosen_flat,
         sizeof(dst->bbk_resume_chosen_flat));
  memcpy(dst->bbk_resume_chosen_actual, src->bbk_resume_chosen_actual,
         sizeof(dst->bbk_resume_chosen_actual));
  dst->exhausted_waiting_for_checkpoint =
      src->exhausted_waiting_for_checkpoint;
  dst->exhausted_wait_suffix_nb = src->exhausted_wait_suffix_nb;
  dst->exhausted_wait_crc_pos = src->exhausted_wait_crc_pos;
  dst->exhausted_wait_validated_files =
      src->exhausted_wait_validated_files;
  dst->exhausted_wait_checkpoint_sec =
      src->exhausted_wait_checkpoint_sec;
  dst->exhausted_wait_checkpoint_nsec =
      src->exhausted_wait_checkpoint_nsec;
  dst->safe_partial_blocks = src->safe_partial_blocks;
  dst->safe_partial_length = src->safe_partial_length;
}

// the following structure and functions are used to replace fgetc(),
// ungetc(), and fread() calls in the pngcheck source and to localize
// global variables in the original source code for pngcheck, to
// ensure thread safety
typedef struct PNGMemIO {
  unsigned char *data;     // data provided for validation
  uint64_t length;         // length of data provided for validation
  uint64_t curpos;         // current position in 'data'
  int64_t errpos;          // first error position in 'data'
  uint64_t last_good_pos;  // curpos at start of last chunk iteration

  // buf was previously global
  unsigned char buffer[BS];

  // global_error was previously global
  int global_error;

  // zlib stuff was previously global (USE_ZLIB is always 1)
  int first_idat;             /* flag:  is this the first IDAT chunk? */
  int zlib_error;             /* reset in IHDR section; used for IDAT */
  int check_zlib;             /* validate zlib stream (just IDATs for now) */
  unsigned zlib_windowbits;
  uch outbuf[BS + OUTBUF_PAD];
  int zlib_started;
  int zlib_stopped;
  int check_windowbits;           /* more stringent zlib stream-checking */
  uint64_t last_good_filter_pos;  /* input pos after last good filter row */
  uint64_t inflate_consumed_pos;  /* curpos when inflate avail_in last hit 0
                                   * (before next refill).  Used by gap check to
                                   * exclude never-inflated EOF bytes from gap. */
  bool errpos_is_precise;         /* errpos set by IDAT zlib/filter path (trustworthy);
                                     false means errpos set by set_err() at arbitrary curpos */

  /* Block-boundary tracking during IDAT filter validation.
   * When blocksize > 0, we record the last block boundary crossed by
   * the zlib input stream.  If wrong data happens to decompress into rows
   * with valid filter types, last_good_filter_pos advances past the
   * corruption.  last_filter_blk_boundary gives us a safe snap-back
   * point that is aligned to the carver's block grid. */
  uint64_t last_filter_blk;         /* block index of last-seen boundary */
  uint64_t last_filter_blk_boundary; /* file pos of that boundary */

  /* Post-IDAT tracking for CRC validation */
  uint64_t last_idat_crc_pos;   /* curpos after last successful IDAT CRC */
  uint64_t last_chunk_crc_pos;  /* curpos after last successful CRC of ANY chunk */
  uint64_t prev_idat_crc_pos;  /* last_idat_crc_pos value BEFORE the most
                                 * recent update.  One IDAT further back. */
  uint64_t idat_crc_ring[IDAT_CRC_RING_SZ]; /* Ring buffer of last 4 verified
                                 * IDAT CRC positions.  Used as a final backstop
                                 * in VT computation to catch cases where 2+
                                 * self-consistent wrong IDATs pollute both
                                 * last_idat_crc_pos and prev_idat_crc_pos. */
  int      idat_crc_ring_count; /* total IDATs pushed into ring */
  uint64_t d4_restore_crc_pos;  /* last_idat_crc_pos at D4 restore time.
                                 * After D4 restore, a self-consistent wrong IDAT
                                 * can pass CRC and pollute last_idat_crc_pos.
                                 * This field preserves the checkpoint's value so
                                 * the CRC failure handler can cap errpos correctly. */
  bool     have_iend;           /* true if IEND was seen during parsing */

  /* Block boundary analysis state.
   * Only populated when blocksize > 0. */
  uint32_t blocksize;             /* carver block size; 0 = unknown */
  long     img_width;             /* image width from IHDR */
  long     img_height;            /* image height from IHDR */
  int      img_bitdepth;          /* total bit depth (channels * sampledepth) */

  /* Per-block CRC checkpoints within the current IDAT chunk */
  struct PNGBlockCRC *crc_ckpts;  /* malloc'd array; NULL if blocksize==0 */
  int           n_crc_ckpts;
  int           max_crc_ckpts;
  ulg           idat_stored_crc;  /* stored CRC read from file (for crc32_combine) */
  uint64_t      idat_data_start;  /* file pos of start of current IDAT body */
  long          idat_data_sz;     /* byte length of current IDAT body */
  bool          mid_idat;         /* inside IDAT body without CRC verification */

  /* H6: Pixel gradient gate state for enhanced IDAT validation.
   * Reconstructs pixels from filtered rows and validates using MAD (Mean Absolute Difference)
   * threshold. Detects when wrong IDAT data produces unrealistic pixel gradients. */
  uint8_t  *prev_row_pixels;      /* malloc'd: previous row's reconstructed pixels */
  uint8_t  *cur_row_pixels;       /* malloc'd: current row being reconstructed */
  uint32_t  pixel_row_bytes;      /* width * bpp_bytes (pixel data, no filter byte) */
  uint8_t   bpp_bytes;            /* bytes per complete pixel (from IHDR) */
  double    running_mad_sum;      /* cumulative MAD sum for running average */
  uint64_t  mad_count;            /* number of MAD samples taken */
  uint32_t  consecutive_good_rows; /* consecutive rows passing BOTH filter + MAD checks (gate=3) */
  double    post_crc_mad_sum;     /* H6c: MAD sum for rows processed after last CRC boundary */
  uint32_t  post_crc_mad_count;   /* H6c: count of rows processed after last CRC boundary */

  /* H7: Filter type distribution (Paeth fraction).
   * Track the fraction of rows using filter type 4 (Paeth).  Photographic
   * PNGs are ~90-97% Paeth.  Wrong data from wrong zlib dictionary context
   * produces filter type 0 (None) predominantly.  Field names retain "corr"
   * for code continuity with save/restore/clone infrastructure. */
  double    running_corr_sum;     /* cumulative Paeth indicator sum (1.0 per Paeth row) */
  uint64_t  corr_count;           /* number of rows sampled for Paeth tracking */
  double    post_crc_corr_sum;    /* H7: Paeth indicator sum after last CRC boundary */
  uint32_t  post_crc_corr_count;  /* H7: row count after last CRC boundary */

  /* B8: Inflate rate discontinuity detection.
   * Track compressed-to-decompressed byte ratio per block.  A sudden change
   * at a block boundary suggests foreign data.
   * REVERT: remove these 6 fields and all code marked "B8:" to disable. */
  uint64_t  b8_block_in_start;    /* compressed bytes consumed at block start */
  uint64_t  b8_block_out_start;   /* decompressed bytes produced at block start */
  double    b8_running_ratio;     /* running sum of compression ratios */
  double    b8_running_ratio_sq;  /* running sum of squared ratios (for variance) */
  uint64_t  b8_ratio_count;       /* number of ratio samples */
  uint64_t  b8_last_block;        /* last block index seen for B8 */
  uint64_t  b8_total_out;         /* cumulative decompressed output bytes */
  uint64_t  b8_anomaly_pos;      /* file pos of block boundary where ratio anomaly
                                   * was detected.  Set by B8 EOF check; used by VT
                                   * computation to cap validates_to.  0 = no anomaly. */

  /* Z9: post-Z_STREAM_END IDAT data tracking.  After inflate returns
   * Z_STREAM_END, any remaining IDAT data is NOT validated by inflate
   * or the filter check.  For correct PNGs, this is at most a few bytes.
   * A full IDAT body (65536 bytes) after Z_STREAM_END is impossible in
   * a well-formed file -- it can only be wrong data from another file. */

  /* B9: Filter type distribution anomaly detection.
   * Track per-block filter type histogram (5 bins for types 0-4).
   * At block boundaries, compute L1 distance between current block's
   * normalized distribution and the running average.  Echo blocks tend
   * to shift toward filter type 0 (None) because the zlib sliding
   * window contains filter residuals near 0.
   * REVERT: remove these fields and all code marked "B9:" to disable. */
  uint32_t  b9_block_filt[5];     /* per-block filter type counts (types 0-4) */
  uint32_t  b9_block_rows;        /* total rows counted in current block */
  double    b9_running_frac[5];   /* running sum of per-block fractions for each type */
  double    b9_running_l1;        /* running sum of L1 distances across blocks */
  double    b9_running_l1_sq;     /* running sum of squared L1 (for variance) */
  uint64_t  b9_block_count;       /* number of completed blocks with filter data */
  uint64_t  b9_anomaly_pos;       /* file pos of filter distrib anomaly; 0 = none */

  /* B10: Per-block MAD average anomaly detection.
   * Track average MAD (mean absolute difference between consecutive
   * unfiltered rows) per block.  Echo blocks gradually degrade as the
   * zlib sliding window fills with wrong data, elevating MAD over the
   * block.  The per-block average captures this drift even when
   * individual rows pass the H6 per-row check.
   * Orthogonal to B8 (pixel-domain vs compressed-domain).
   * REVERT: remove these fields and all code marked "B10:" to disable. */
  double    b10_block_mad_sum;    /* sum of MAD values in current block */
  uint32_t  b10_block_mad_count;  /* rows with MAD in current block */
  double    b10_running_mad_avg;  /* running sum of per-block MAD averages */
  double    b10_running_mad_avg_sq; /* running sum of squared averages (variance) */
  uint64_t  b10_block_count;      /* completed blocks with MAD data */
  uint64_t  b10_anomaly_pos;      /* file pos of MAD anomaly; 0 = none */
  double    b10_last_mad;         /* H9: most recently computed row MAD */
  double    b10_max_post_crc_mad; /* H9: max MAD since last IDAT CRC boundary */
  double    h9_cand_mad_sum;      /* H9: MAD sum for candidate-region rows only */
  uint32_t  h9_cand_mad_count;    /* H9: count of candidate-region rows */
  uint32_t  h9_mad_count_since_d4; /* diagnostic: MAD computations since D4 restore */


  /* B8f: Fine-grained sub-block compression ratio.
   * Same adaptive threshold as B8 but computed at sub-block boundaries
   * (blocksize/4, min 2048).  More frequent sampling gives tighter
   * variance estimates and catches ratio shifts that B8 averages away.
   * Sub-block size adapts to blocksize parameter.
   * REVERT: remove these fields and all code marked "B8f:" to disable. */
  uint64_t  b8f_sub_blocksize;    /* sub-block size: max(blocksize/4, 2048) */
  uint64_t  b8f_block_in_start;   /* compressed bytes at sub-block start */
  uint64_t  b8f_block_out_start;  /* decompressed bytes at sub-block start */
  double    b8f_running_ratio;    /* running sum of sub-block ratios */
  double    b8f_running_ratio_sq; /* running sum of squared sub-block ratios */
  uint64_t  b8f_ratio_count;      /* number of sub-block ratio samples */
  uint64_t  b8f_last_sub_blk;     /* last sub-block index seen */
  uint64_t  b8f_anomaly_pos;      /* file pos of sub-block ratio anomaly; 0 = none */

  /* B11: Auto-correlation at zlib window distance.
   * The echo effect produces decompressed bytes nearly identical to bytes
   * from ~32KB back (the zlib sliding window size).  This detector keeps
   * a ring buffer of per-row pixel checksums and compares each new row to
   * the row from ~32KB of decompressed data ago.
   * Correct image data shows natural progression (low lag-32K similarity).
   * Echo data shows high lag-32K similarity (replay from window).
   * This signal CORRELATES with B8 since both are caused by echo.
   * REVERT: remove these fields and all code marked "B11:" to disable. */
  uint8_t   b11_byte_ring[65536]; /* 64KB ring of raw decompressed bytes */
  uint64_t  b11_byte_wpos;        /* total bytes written to ring */
  uint32_t  b11_hash_ring[128];   /* hash per 256-byte-spaced 64-byte sample */
  uint32_t  b11_hash_wpos;        /* write position in hash ring */
  uint32_t  b11_byte_match_run;   /* consecutive hash-matched samples */
  uint64_t  b11_byte_last_check;  /* decompressed pos of last similarity check */
  uint64_t  b11_anomaly_pos;      /* file pos of window-correlation anomaly; 0 = none */

  /* B12: Single-row MAD spike detection at block boundaries.
   * When echo starts, the first decoded row has pixels from a different
   * image region — producing a massive MAD spike vs the previous row.
   * H6c averages MAD over all post-CRC rows and misses this because
   * subsequent echo rows have similar-to-normal MAD.  B12 catches the
   * ONE transition row that your eye sees as a visible seam.
   *
   * Track the block boundary and row number where MAD crosses last;
   * at the first row of each new block after CRC, if MAD > spike_thresh
   * × running_avg, record the block boundary position. */
  uint64_t  b12_spike_pos;        /* file pos of block boundary with MAD spike; 0 = none */
  double    b12_spike_mad;        /* MAD value at the spike row */
  double    b12_spike_ratio;      /* mad/avg ratio at the spike — keep highest */
  uint64_t  b12_rows_into_block;  /* rows decoded since last block boundary */

  // Historical note: B13/B14/B15 were experimental echo detectors.
  // B13 tracked a sliding MAD window; B14 tried to freeze progress after
  // sustained MAD depression; B15 tried to freeze progress after a run of
  // non-Paeth filters.  B14/B15 freeze positions were never consumed by
  // scoring, so the hot-loop work did not affect recovery.  They are
  // intentionally absent unless a future corpus shows a measured need for
  // a new, wired-in ranking signal.

  /* Combined suspicion: latest normalized dev/thresh from each detector.
   * Updated at block boundary, EOF, and post-inflate check sites.
   * Value of 1.0 = exactly at individual threshold; >1.0 = would fire alone.
   * Used for combined weak-signal fusion: sum of suspicions across detectors
   * can catch wrong blocks that no single detector catches alone. */
  double    b8_suspicion;         /* latest B8 dev/thresh (0 if no data) */
  double    b8_max_suspicion_since_crc; /* max B8 suspicion since last IDAT CRC */
  double    b9_suspicion;         /* latest B9 dev/thresh (0 if no data) */
  double    b10_suspicion;        /* latest B10 dev/thresh (0 if no data) */
  double    combined_max_sum;     /* max combined suspicion sum seen so far */
  uint64_t  combined_anomaly_pos; /* file pos where max sum occurred; 0 = none */
  uint64_t  post_zend_idat_bytes;  /* IDAT body bytes accumulated after Z_STREAM_END */

  /* IDAT inflate loop state (was _Thread_local static) */
  uch      *inflate_out_ptr;    /* output pointer into outbuf (was 'p') */
  int       cur_y;              /* current row in current interlace pass */
  int       cur_pass;           /* current interlace pass (0 for non-interlaced) */
  int       cur_xoff, cur_yoff; /* interlace offsets */
  int       cur_xskip, cur_yskip; /* interlace step sizes */
  long      cur_width;          /* width of current interlace pass */
  long      cur_linebytes;      /* bytes per row in current pass (incl filter byte) */
  long      numfilt;            /* filter rows in current block */
  long      numfilt_this_block; /* filter rows in this block segment */
  long      numfilt_total;      /* total filter rows across all blocks */
  long      numfilt_pass[7];    /* filter rows per interlace pass */

  /* D4: Carve state caching */
  void      *carvehashkey;      /* key for carve_get/put_state calls */

  /* D4: Unconsumed inflate input stashed after the inflate loop exits.
   * The body-drain loop overwrites mem->buffer, making zstrm.next_in
   * stale.  We save the leftover bytes here so the checkpoint can
   * preserve them and the restore path can replay them. */
  uint8_t   *zstrm_leftover;
  unsigned  zstrm_leftover_count;

  /* When non-NULL, the validator reads/writes this state directly
   * instead of going through carve_get_state/carve_put_state.
   * Set by png_validate_core when called from png_reassembly. */
  PNGCarveState *direct_state;

  bool complete_contiguous_probe;
} PNGMemIO;


// GGRIII: the set_err() function had to be converted to a function to
// discover the first place an error occurs in the memory buffer
static inline void set_err(int x, PNGMemIO *mem) {

  mem->global_error = ((mem->global_error < (x))? (x) : mem->global_error);

  // Remember the *first* place we saw a meaningful error.
  // GGRIII fix: Only latch errpos for errors >= kMinorError.
  // Warnings (kWarning) are often pedantic and fire early (e.g.,
  // unknown ancillary chunk), which poisons errpos long before
  // actual corruption.  This caused validates_to to overshoot
  // backward into valid data or forward via the curpos-1 fallback.

  if (mem->errpos < 0 && x >= kMinorError) {
    mem->errpos = mem->curpos;
  }
}

// GGRIII: this version doesn't set errpos.
static inline void set_err_no_errpos(int x, PNGMemIO *mem) {

  mem->global_error = ((mem->global_error < (x))? (x) : mem->global_error);

}


static inline void init_printbuf_state(printbuf_state *prbuf)
{
  prbuf->cr = 0;
  prbuf->lf = 0;
  prbuf->nul = 0;
  prbuf->control = 0;
  prbuf->esc = 0;
}

/* Scan buffer for control characters (no output; just sets state flags) */
static inline void print_buffer(printbuf_state *prbuf, uch *buf, int size, int indent)
{
  (void)indent;
  while (size-- > 0) {
    uch c = *buf++;
    if (c < 32 || (c >= 127 && c < 160)) {
      if (c == '\n')
        prbuf->lf = 1;
      else if (c == '\r')
        prbuf->cr = 1;
      else if (c == '\0')
        prbuf->nul = 1;
      else
        prbuf->control = 1;
      if (c == 27)
        prbuf->esc = 1;
    }
  }
}

/* Report text chunk validation errors based on printbuf state */
static inline void report_printbuf(PNGMemIO *mem, printbuf_state *prbuf, char *chunkid)
{
  (void)chunkid;
  if (prbuf->cr) {
    set_err(kMinorError, mem);
  }
  if (prbuf->nul) {
    set_err(kMinorError, mem);
  }
  if (prbuf->control) {
    set_err(kMinorError, mem);
  }
}


static inline ulg  getlong (PNGMemIO *mem, char *where);
static inline int  keywordlen (uch *buffer, int maxsize);
static inline int  pngcheck (PNGMemIO *mem);
static inline int  check_magic (PNGMemIO *mem, uch *magic, int which);
static inline int  check_chunk_name (PNGMemIO *mem, char *chunk_name);
static inline int  check_keyword (PNGMemIO *mem, uch *buffer, int maxsize, int *pKeylen,
                    char *keyword_name, char *chunkid);
static inline int  check_text (PNGMemIO *mem, uch *buffer, int maxsize, char *chunkid);
static inline int  check_ascii_float (PNGMemIO *mem, uch *buffer, int len, char *chunkid);
static inline void init_PNGMemIO(PNGMemIO *m, char *data, uint64_t length,
                                 bool complete_contiguous_probe);


// initialize all important fields in a PNGMemIO structure
static inline void init_PNGMemIO(PNGMemIO *m, char *data, uint64_t length,
                                 bool complete_contiguous_probe) {

  zstrm_initialized = false;

  m->data = (unsigned char *)data;
  m->length = length;
  m->complete_contiguous_probe = complete_contiguous_probe;
  m->curpos = 0;
  m->errpos = -1;
  m->errpos_is_precise = false;
  m->last_good_pos = 0;
  m->global_error = kOK;

  /* zlib stuff (USE_ZLIB is always 1) */
  m->first_idat = 1;
  m->zlib_error = 0;
  m->check_zlib = 1;
  m->zlib_windowbits = 15;
  m->zlib_started=false;
  m->zlib_stopped=false;
  m->check_windowbits = 1;

  /* IDAT loop state */
  m->inflate_out_ptr = NULL;
  m->cur_y = 0;
  m->cur_pass = 0;
  m->cur_xoff = 0;
  m->cur_yoff = 0;
  m->cur_xskip = 1;
  m->cur_yskip = 1;
  m->cur_width = 0;
  m->cur_linebytes = 0;
  m->numfilt = 0;
  m->numfilt_this_block = 0;
  m->numfilt_total = 0;
  memset(m->numfilt_pass, 0, sizeof(m->numfilt_pass));
  m->last_good_filter_pos = 0;
  m->inflate_consumed_pos = 0;
  m->last_filter_blk = 0;
  m->last_filter_blk_boundary = 0;
  m->last_idat_crc_pos = 0;
  m->last_chunk_crc_pos = 0;
  m->prev_idat_crc_pos = 0;
  memset(m->idat_crc_ring, 0, sizeof(m->idat_crc_ring));
  m->idat_crc_ring_count = 0;
  m->d4_restore_crc_pos = 0;
  m->have_iend = false;

  /* block boundary analysis */
  m->blocksize       = 0;
  m->img_width       = 0;
  m->img_height      = 0;
  m->img_bitdepth    = 0;
  m->crc_ckpts       = NULL;
  m->n_crc_ckpts     = 0;
  m->max_crc_ckpts   = 0;
  m->idat_stored_crc = 0;
  m->idat_data_start = 0;
  m->idat_data_sz    = 0;
  m->mid_idat        = false;

  /* H6: Initialize pixel reconstruction state */
  m->prev_row_pixels = NULL;
  m->cur_row_pixels = NULL;
  m->pixel_row_bytes = 0;
  m->bpp_bytes = 1;
  m->running_mad_sum = 0.0;
  m->mad_count = 0;
  m->consecutive_good_rows = 0;
  m->post_crc_mad_sum = 0.0;
  m->post_crc_mad_count = 0;

  /* H7: correlation */
  m->running_corr_sum = 0.0;
  m->corr_count = 0;
  m->post_crc_corr_sum = 0.0;
  m->post_crc_corr_count = 0;

  /* B8: inflate rate discontinuity */
  m->b8_block_in_start = 0;
  m->b8_block_out_start = 0;
  m->b8_running_ratio = 0.0;
  m->b8_running_ratio_sq = 0.0;
  m->b8_ratio_count = 0;
  m->b8_last_block = 0;
  m->b8_total_out = 0;
  m->b8_anomaly_pos = 0;

  /* Z9: post-Z_STREAM_END tracking */

  /* B9: Filter distribution */
  memset(m->b9_block_filt, 0, sizeof(m->b9_block_filt));
  m->b9_block_rows = 0;
  memset(m->b9_running_frac, 0, sizeof(m->b9_running_frac));
  m->b9_running_l1 = 0.0;
  m->b9_running_l1_sq = 0.0;
  m->b9_block_count = 0;
  m->b9_anomaly_pos = 0;

  /* B10: Per-block MAD average */
  m->b10_block_mad_sum = 0.0;
  m->b10_block_mad_count = 0;
  m->b10_running_mad_avg = 0.0;
  m->b10_running_mad_avg_sq = 0.0;
  m->b10_block_count = 0;
  m->b10_anomaly_pos = 0;
  m->b10_last_mad = 0.0;
  m->b10_max_post_crc_mad = 0.0;
  m->h9_cand_mad_sum = 0.0;
  m->h9_cand_mad_count = 0;
  m->h9_mad_count_since_d4 = 0;


  /* B8f: Fine-grained sub-block ratio */
  m->b8f_sub_blocksize = 0;  /* set when blocksize is known */
  m->b8f_block_in_start = 0;
  m->b8f_block_out_start = 0;
  m->b8f_running_ratio = 0.0;
  m->b8f_running_ratio_sq = 0.0;
  m->b8f_ratio_count = 0;
  m->b8f_last_sub_blk = 0;
  m->b8f_anomaly_pos = 0;

  /* B11: Auto-correlation */
  if (!complete_contiguous_probe) {
    memset(m->b11_byte_ring, 0, sizeof(m->b11_byte_ring));
    memset(m->b11_hash_ring, 0, sizeof(m->b11_hash_ring));
  }
  m->b11_byte_wpos = 0;
  m->b11_hash_wpos = 0;
  m->b11_byte_match_run = 0;
  m->b11_byte_last_check = 0;
  m->b11_anomaly_pos = 0;
  m->b12_spike_pos = 0;
  m->b12_spike_mad = 0.0;
  m->b12_spike_ratio = 0.0;
  m->b12_rows_into_block = 0;
  /* Combined suspicion */
  m->b8_suspicion = 0.0;
  m->b8_max_suspicion_since_crc = 0.0;
  m->b9_suspicion = 0.0;
  m->b10_suspicion = 0.0;
  m->combined_max_sum = 0.0;
  m->combined_anomaly_pos = 0;
  m->post_zend_idat_bytes = 0;

  /* D4: Carve state caching */
  m->carvehashkey = NULL;
  m->zstrm_leftover = NULL;
  m->zstrm_leftover_count = 0;
  m->direct_state = NULL;
}


/* D4: PNG carve state management functions */

static inline void *png_clone_carve_state(const void *srcstate) {
    const PNGCarveState *s = (const PNGCarveState *)srcstate;
    if (!s) return NULL;

    PNGCarveState *d = malloc(sizeof(PNGCarveState));
    if (!d) return NULL;
    memcpy(d, s, sizeof(PNGCarveState));

    /* Deep copy H6 pixel buffers */
    if (s->prev_row_pixels && s->pixel_row_bytes > 0) {
        d->prev_row_pixels = malloc(s->pixel_row_bytes);
        if (!d->prev_row_pixels) {
            free(d);
            return NULL;
        }
        memcpy(d->prev_row_pixels, s->prev_row_pixels, s->pixel_row_bytes);
    } else {
        d->prev_row_pixels = NULL;
    }

    if (s->cur_row_pixels && s->pixel_row_bytes > 0) {
        d->cur_row_pixels = malloc(s->pixel_row_bytes);
        if (!d->cur_row_pixels) {
            free(d->prev_row_pixels);
            free(d);
            return NULL;
        }
        memcpy(d->cur_row_pixels, s->cur_row_pixels, s->pixel_row_bytes);
    } else {
        d->cur_row_pixels = NULL;
    }

    /* Deep copy CRC checkpoints */
    if (s->crc_ckpts && s->n_crc_ckpts > 0) {
        d->crc_ckpts = malloc(s->max_crc_ckpts * sizeof(struct PNGBlockCRC));
        if (!d->crc_ckpts) {
            free(d->cur_row_pixels);
            free(d->prev_row_pixels);
            free(d);
            return NULL;
        }
        memcpy(d->crc_ckpts, s->crc_ckpts, s->n_crc_ckpts * sizeof(struct PNGBlockCRC));
    } else {
        d->crc_ckpts = NULL;
    }

    /* Deep copy zlib stream.  zstrm_copy is a pointer, so memcpy above
     * only copied the pointer value (shared ownership, no aliased zlib
     * internals).  We allocate a fresh z_stream and inflateCopy into it. */
    d->zstrm_copy = NULL;
    if (s->has_zstrm && s->zstrm_copy) {
        d->zstrm_copy = calloc(1, sizeof(z_stream));
        if (!d->zstrm_copy ||
            inflateCopy(d->zstrm_copy, s->zstrm_copy) != Z_OK) {
            free(d->zstrm_copy);
            d->zstrm_copy = NULL;
            d->has_zstrm = false;
        }
    } else {
        d->has_zstrm = false;
    }

    /* Deep copy leftover inflate input */
    d->zstrm_leftover = NULL;
    if (s->zstrm_leftover && s->zstrm_leftover_count > 0) {
        d->zstrm_leftover = malloc(s->zstrm_leftover_count);
        if (d->zstrm_leftover) {
            memcpy(d->zstrm_leftover, s->zstrm_leftover,
                   s->zstrm_leftover_count);
        } else {
            d->zstrm_leftover_count = 0;
        }
    }

    /* Clone the in-process solver cache so a checkpoint/requeue handoff
     * does not discard table-building work.  Disk serialization still drops
     * it intentionally; scalar resume fields remain the durable state. */
    d->solver_ctx = png_solver_ctx_clone(s->solver_ctx);

    return d;
}

static inline void png_free_carve_state(void **state) {
    PNGCarveState **sp = (PNGCarveState **)state;
    if (!sp || !*sp) return;

    PNGCarveState *s = *sp;
    free(s->prev_row_pixels);
    free(s->cur_row_pixels);
    free(s->crc_ckpts);
    if (s->has_zstrm && s->zstrm_copy) {
        inflateEnd(s->zstrm_copy);
        free(s->zstrm_copy);
    }
    free(s->zstrm_leftover);
    png_solver_ctx_free(&s->solver_ctx);
    free(s);
    *sp = NULL;
}

static inline bool png_serialize_carve_state(void **state, FILE *fp, StateSerialization mode) {
    PNGCarveState **sp = (PNGCarveState **)state;

    size_t (*fb)(void *ptr, size_t size, size_t nitems, FILE *stream) =
        mode == SERIALIZE ?
        (size_t (*)(void *, size_t, size_t, FILE *))fwrite :
        (size_t (*)(void *, size_t, size_t, FILE *))fread;

    if (mode == DESERIALIZE) {
        *sp = (PNGCarveState *)calloc(1, sizeof(PNGCarveState));
        check_memory_allocation(*sp, __LINE__, __FILE__, "PNGCarveState");
    }

    /* Serialize a scrubbed carve state so scalar CRC/reassembly progress
     * and BBK resume state survive checkpoints.  Heap-backed D4/zlib
     * state and solver table caches are intentionally rebuilt after
     * restart. */
    if (mode == SERIALIZE) {
        PNGCarveState tmp;
        if (*sp) {
            tmp = **sp;
        } else {
            memset(&tmp, 0, sizeof(tmp));
        }
        tmp.valid = false;          /* force fresh D4 parse after checkpoint */
        tmp.prev_row_pixels = NULL;
        tmp.cur_row_pixels = NULL;
        tmp.crc_ckpts = NULL;
        tmp.n_crc_ckpts = 0;
        tmp.max_crc_ckpts = 0;
        tmp.zstrm_copy = NULL;
        tmp.has_zstrm = false;
        tmp.zstrm_leftover = NULL;
        tmp.zstrm_leftover_count = 0;
        tmp.solver_ctx = NULL;
        if (fb(&tmp, sizeof(tmp), 1, fp) != 1) {
            perror("png carve state serialization");
            return false;
        }
    } else {
        if (fb(*sp, sizeof(PNGCarveState), 1, fp) != 1) {
            perror("png carve state deserialization");
            free(*sp);
            *sp = NULL;
            return false;
        }
        (*sp)->prev_row_pixels = NULL;
        (*sp)->cur_row_pixels = NULL;
        (*sp)->crc_ckpts = NULL;
        (*sp)->zstrm_copy = NULL;
        (*sp)->zstrm_leftover = NULL;
        (*sp)->solver_ctx = NULL;
    }

    return true;
}

static inline void png_print_carve_state(const void *state) {
    const PNGCarveState *s = (const PNGCarveState *)state;
    if (!s) {
        fprintf(stdout, "NULL\n");
        return;
    }
    fprintf(stdout, "D4: valid=%d curpos=%llu hash=%llx\n",
            s->valid, (unsigned long long)s->checkpoint_curpos,
            (unsigned long long)s->prefix_hash);
}

// memory-oriented fgetc() clone
static inline int mem_fgetc(PNGMemIO *m) {
  int c=EOF;

  if (m->curpos < m->length) {
    c = *(m->data + m->curpos++);
  }
  return c;
}

// memory-oriented ungetc() clone
static inline void mem_ungetc(int c, PNGMemIO *m) {
  (void)c;

  // this only supports putting the last character read back, but
  // that's sufficient for pngcheck.  c is ignored.

  if (m->curpos > 0) {
    m->curpos--;
  }
}

// memory-oriented fread clone
static inline size_t mem_fread(void *buf, size_t size, size_t num_items, PNGMemIO *m) {
  size_t ret = 0;
  size_t nbytes = 0;

  if (!buf || !m || size == 0 || num_items == 0) {
    return 0;
  }

  if (num_items > SIZE_MAX / size) {
    nbytes = SIZE_MAX;
  }
  else {
    nbytes = size * num_items;
  }

  if (m->curpos >= m->length) {
    nbytes = 0;
  }
  else {
    uint64_t remaining = m->length - m->curpos;
    if ((uint64_t)nbytes > remaining) {
      nbytes = (size_t)remaining;
    }
  }

  if (nbytes > 0) {
    ret = nbytes / size;
    memcpy(buf, m->data + m->curpos, nbytes);
    m->curpos += nbytes;
  }

  return ret;
}


/* USE_ZLIB is always 1: CRC uses zlib's crc32() directly */
#define CRCCOMPL(c) c
#define CRCINIT (0)
#define update_crc crc32


ulg getlong(PNGMemIO *mem, char *where)
{
  ulg res = 0;
  int j;
  (void)where;

  for (j = 0; j < 4; ++j) {
    int c;

    if ((c = mem_fgetc(mem)) == EOF) {
      // EOF: ran out of data, probably because the file is currently
      // missing some blocks at the end.  For incremental validation
      // (direct_state), use kMajorError so the VT path can still
      // accept files with IEND.  For from-scratch validation, keep
      // kCriticalError so genuinely truncated files are rejected.
      if (mem->direct_state) {
        set_err_no_errpos(kMajorError, mem);
      }
      else {
        set_err_no_errpos(kCriticalError, mem);
      }
      return 0;
    }
    res <<= 8;
    res |= c & 0xff;
  }

  return res;
}


int keywordlen(uch *buf, int maxsize)
{
  int j = 0;

  while (j < maxsize && buf[j])
    ++j;

  return j;
}


/* Known PNG/JNG/MNG chunk names used by #2 spurious-header check.
 * Matching only against this set reduces false positive probability from
 * ~0.16% per boundary (any 4 letters) to ~0 (specific known names). */
static const char *const png_known_chunk_names[] = {
  /* Critical PNG */
  "IHDR", "PLTE", "IDAT", "IEND",
  /* Ancillary PNG */
  "bKGD", "cHRM", "eXIf", "fRAc", "gAMA", "gIFg", "gIFt", "gIFx",
  "hIST", "iCCP", "iTXt", "oFFs", "pCAL", "pHYs", "sBIT", "sCAL",
  "sPLT", "sRGB", "sTER", "tEXt", "zTXt", "tIME", "tRNS",
  /* PNG 3rd/4th edition */
  "cICP", "mDCV", "cLLI", "caBX",
  /* APNG */
  "acTL", "fcTL", "fdAT",
  /* Apple */
  "iDOT",
  /* Known private */
  "cmOD", "cmPP", "cpIp", "mkBF", "mkBS", "mkBT", "mkTS", "pcLb",
  "prVW", "spAL",
  /* JNG */
  "JHDR", "JDAT", "JSEP",
  /* MNG */
  "MHDR", "MEND", "DHDR", "FRAM", "SAVE", "SEEK", "nEED", "DEFI",
  "BACK", "MOVE", "CLON", "SHOW", "CLIP", "LOOP", "ENDL", "PROM",
  "fPRI", "eXPI", "BASI", "IPNG", "PPLT", "PAST", "TERM", "DISC",
  "pHYg", "DROP", "DBYK", "ORDR", "MAGN",
  /* Known invalid public */
  "pRVW", "nULL", "tXMP",
  NULL
};

static inline int png_is_known_chunk(const unsigned char *type4)
{
  char name[5];
  name[0] = (char)type4[0]; name[1] = (char)type4[1];
  name[2] = (char)type4[2]; name[3] = (char)type4[3]; name[4] = '\0';
  for (int i = 0; png_known_chunk_names[i]; ++i)
    if (strcmp(name, png_known_chunk_names[i]) == 0)
      return 1;
  return 0;
}

/* #9: Palette-index validation for color type 3 (indexed-color) images.
 * Every decoded pixel index must be < nplte.  This is a deterministic,
 * spec-level constraint: wrong IDAT data decompressed through a stale zlib
 * context will almost certainly produce out-of-range indices when the
 * palette is smaller than the full bit-depth range.  Zero false-positive
 * risk on correct data.
 *
 * Only checked on filter type 0 (none) rows, where p+1 contains raw
 * palette indices.  For filter types 1-4 the bytes are prediction
 * residuals, not raw indices, so the check does not apply.
 *
 * For bit depths < 8, only the first 'width' samples are validated;
 * unused low bits in the final byte are ignored. */
static inline int png_palette_row_indices_ok(const uch *row,
                                             long width,
                                             int bitdepth,
                                             int nplte)
{
  if (width <= 0 || nplte <= 0)
    return 1;

  if (bitdepth <= 0 || bitdepth > 8)
    return 1; /* unexpected bit depth; do not reject */

  /* If palette has at least the full symbol range for the bit depth,
   * every possible sample is valid — skip the check. */
  if (nplte >= (1 << bitdepth))
    return 1;

  if (bitdepth == 8) {
    for (long x = 0; x < width; ++x)
      if (row[x] >= (uch)nplte)
        return 0;
    return 1;
  }
  else if (bitdepth == 4) {
    long x = 0;
    long nbytes = (width + 1) / 2;
    for (long i = 0; i < nbytes; ++i) {
      uch b = row[i];
      uch hi = (uch)(b >> 4);
      uch lo = (uch)(b & 0x0F);
      if (x < width && hi >= (uch)nplte) return 0;
      ++x;
      if (x < width && lo >= (uch)nplte) return 0;
      ++x;
    }
    return 1;
  }
  else if (bitdepth == 2) {
    long x = 0;
    long nbytes = (width + 3) / 4;
    for (long i = 0; i < nbytes; ++i) {
      uch b = row[i];
      for (int shift = 6; shift >= 0 && x < width; shift -= 2, ++x) {
        uch v = (uch)((b >> shift) & 0x03);
        if (v >= (uch)nplte) return 0;
      }
    }
    return 1;
  }
  else /* bitdepth == 1 */ {
    long x = 0;
    long nbytes = (width + 7) / 8;
    for (long i = 0; i < nbytes; ++i) {
      uch b = row[i];
      for (int shift = 7; shift >= 0 && x < width; --shift, ++x) {
        uch v = (uch)((b >> shift) & 0x01);
        if (v >= (uch)nplte) return 0;
      }
    }
    return 1;
  }
}

/* -----------------------------------------------------------------------
 * Block-boundary CRC checkpoint helpers (#5)
 *
 * png_ckpt_maybe_record() is called after every mem_fread() + update_crc()
 * pair in the IDAT body-drain path.  For each block boundary that falls
 * within the just-read buffer [prev_pos, cur_pos), it records the CRC of
 * all IDAT bytes up to EXACTLY that boundary position, computed by
 * crc32(crc_before_buf, buf, boundary_offset_in_buf).
 *
 * After a CRC failure, png_file_validate() iterates the checkpoints
 * left-to-right.  For each checkpoint k it computes the suffix CRC of
 * data[bdy_k .. idat_end) from the raw data buffer, then tests
 * crc32_combine(prefix_crc_k, suffix_crc_k, suffix_len_k) == filecrc.
 * The rightmost checkpoint where this holds is the last good block.
 * ----------------------------------------------------------------------- */

/* H6: Paeth predictor function for filter type 4 (Paeth) inverse filtering.
 * Used during pixel reconstruction to validate IDAT row data. */
static inline uint8_t paeth_predictor(uint8_t a, uint8_t b, uint8_t c) {
    int p = (int)a + (int)b - (int)c;
    int pa = abs(p - (int)a);
    int pb = abs(p - (int)b);
    int pc = abs(p - (int)c);
    if (pa <= pb && pa <= pc) return a;
    if (pb <= pc) return b;
    return c;
}

static inline void png_ckpt_maybe_record(PNGMemIO *mem,
                                          ulg crc_before,    /* CRC before this buffer */
                                          const uch *buf,    /* the just-read buffer */
                                          uint64_t prev_pos, /* file pos at buf start */
                                          uint64_t cur_pos)  /* file pos at buf end */
{
  uint32_t bs = mem->blocksize;
  if (!bs) return;

  uint64_t first_bdy = (prev_pos / bs + 1) * bs;
  if (first_bdy >= cur_pos) return;

  for (uint64_t bdy = first_bdy; bdy < cur_pos; bdy += bs) {
    if (mem->n_crc_ckpts >= mem->max_crc_ckpts) {
      int newmax = mem->max_crc_ckpts ? mem->max_crc_ckpts * 2 : 64;
      struct PNGBlockCRC *p = (struct PNGBlockCRC *)realloc(
          mem->crc_ckpts, newmax * sizeof(*mem->crc_ckpts));
      if (!p) return;  /* OOM: skip checkpointing */
      mem->crc_ckpts     = p;
      mem->max_crc_ckpts = newmax;
    }
    /* Compute CRC of prefix ending exactly at bdy:
     *   crc32(crc_before_buf, buf[0 .. bdy-prev_pos)) */
    uInt prefix_bytes = (uInt)(bdy - prev_pos);
    if (prefix_bytes > (cur_pos - prev_pos)) return;  /* sanity guard */
    ulg crc_at_bdy = crc32(crc_before, buf, prefix_bytes);

    mem->crc_ckpts[mem->n_crc_ckpts].pos = bdy;
    mem->crc_ckpts[mem->n_crc_ckpts].crc = crc_at_bdy;
    ++mem->n_crc_ckpts;
  }
}

/* Release CRC checkpoint array */
static inline void png_ckpt_free(PNGMemIO *mem)
{
  free(mem->crc_ckpts);
  mem->crc_ckpts      = NULL;
  mem->n_crc_ckpts    = 0;
  mem->max_crc_ckpts  = 0;
}

int pngcheck(PNGMemIO *mem) {
  int i;
  long sz;
  uch magic[8];
  char chunkid[5] = {'\0', '\0', '\0', '\0', '\0'};
  int toread;
  int c;
  int have_IHDR = 0, have_IEND = 0;
  int have_PLTE = 0;
  int have_IDAT = 0, last_is_IDAT = 0;
  int have_bKGD = 0, have_cHRM = 0, have_eXIf = 0, have_gAMA = 0, have_hIST = 0;
  int have_iCCP = 0, have_oFFs = 0, have_pCAL = 0, have_pHYs = 0, have_sBIT = 0;
  int have_sCAL = 0, have_sRGB = 0, have_sTER = 0, have_tIME = 0, have_tRNS = 0;
  /* PNG 3rd/4th edition and APNG */
  int have_acTL = 0, have_fcTL = 0, have_iDOT = 0;
  int have_cICP = 0, have_mDCV = 0, have_cLLI = 0, have_caBX = 0;
  int just_seen_fcTL = 0;
  ulg num_frames = 0L, num_plays = 0L, num_fcTL = 0L;
  ulg next_sequence_number = 0L;
  ulg sequence_number = 0L;
  ulg frame_width = 0L, frame_height = 0L, x_offset = 0L, y_offset = 0L;
  ush delay_num = 0, delay_den = 0;
  uch dispose_op = 0, blend_op = 0;
  ulg zhead = 1;   /* 0x10000 indicates both zlib header bytes read */
  ulg crc, filecrc = 0;
  long num_chunks = 0L;
  long w = 0L, h = 0L;
  int bitdepth = 0, sampledepth = 0, ityp = 1, lace = 0, nplte = 0;
  printbuf_state prbuf_state;

  mem->global_error = kOK;

#if PNG_D4_STATE_CACHE
  /* D4: Check for valid checkpoint to resume from.
   * When mem->direct_state is provided (called from png_reassembly),
   * use it directly — no hash table clone.  The caller owns the state. */
  {
    bool _d4_owns_saved = false;  // true when we cloned and must free
    PNGCarveState *saved = NULL;
    if (mem->complete_contiguous_probe) {
      saved = NULL;
    }
    else if (mem->direct_state) {
      saved = mem->direct_state;
    }
    else if (mem->carvehashkey) {
      saved = (PNGCarveState *)carve_get_state(mem->carvehashkey);
      _d4_owns_saved = true;
    }
    if (saved && saved->valid
        && saved->checkpoint_curpos <= mem->length) {
      /* Verify prefix integrity */
      uint64_t hash = XXH3_64bits(mem->data, saved->checkpoint_curpos);
      if (hash == saved->prefix_hash) {
        /* Restore pngcheck locals */
        w = saved->loc.w; h = saved->loc.h;
        bitdepth = saved->loc.bitdepth; sampledepth = saved->loc.sampledepth;
        ityp = saved->loc.ityp; lace = saved->loc.lace; nplte = saved->loc.nplte;
        crc = saved->loc.crc; filecrc = saved->loc.filecrc;
        sz = saved->loc.sz; toread = saved->loc.toread;
        zhead = saved->loc.zhead; num_chunks = saved->loc.num_chunks;
        have_IHDR = saved->loc.have_IHDR; have_IEND = saved->loc.have_IEND;
        have_PLTE = saved->loc.have_PLTE; have_IDAT = saved->loc.have_IDAT;
        last_is_IDAT = saved->loc.last_is_IDAT;
        have_bKGD = saved->loc.have_bKGD; have_cHRM = saved->loc.have_cHRM;
        have_eXIf = saved->loc.have_eXIf; have_gAMA = saved->loc.have_gAMA;
        have_hIST = saved->loc.have_hIST; have_iCCP = saved->loc.have_iCCP;
        have_oFFs = saved->loc.have_oFFs; have_pCAL = saved->loc.have_pCAL;
        have_pHYs = saved->loc.have_pHYs; have_sBIT = saved->loc.have_sBIT;
        have_sCAL = saved->loc.have_sCAL; have_sRGB = saved->loc.have_sRGB;
        have_sTER = saved->loc.have_sTER; have_tIME = saved->loc.have_tIME;
        have_tRNS = saved->loc.have_tRNS;
        have_acTL = saved->loc.have_acTL; have_fcTL = saved->loc.have_fcTL;
        have_iDOT = saved->loc.have_iDOT; have_cICP = saved->loc.have_cICP;
        have_mDCV = saved->loc.have_mDCV; have_cLLI = saved->loc.have_cLLI;
        have_caBX = saved->loc.have_caBX;
        just_seen_fcTL = saved->loc.just_seen_fcTL;
        num_frames = saved->loc.num_frames; num_plays = saved->loc.num_plays;
        num_fcTL = saved->loc.num_fcTL;
        next_sequence_number = saved->loc.next_sequence_number;
        sequence_number = saved->loc.sequence_number;
        frame_width = saved->loc.frame_width; frame_height = saved->loc.frame_height;
        x_offset = saved->loc.x_offset; y_offset = saved->loc.y_offset;
        delay_num = saved->loc.delay_num; delay_den = saved->loc.delay_den;
        dispose_op = saved->loc.dispose_op; blend_op = saved->loc.blend_op;
        prbuf_state = saved->loc.prbuf_state;

        /* Restore PNGMemIO fields (preserve data, length, carvehashkey) */
        mem->global_error = saved->global_error;
        mem->errpos = saved->errpos;
        mem->curpos = saved->curpos;
        mem->last_good_pos = saved->last_good_pos;
        mem->first_idat = saved->first_idat;
        mem->zlib_error = saved->zlib_error;
        mem->check_zlib = saved->check_zlib;
        mem->zlib_windowbits = saved->zlib_windowbits;
        mem->zlib_started = saved->zlib_started;
        mem->zlib_stopped = saved->zlib_stopped;
        mem->check_windowbits = saved->check_windowbits;
        mem->last_good_filter_pos = saved->last_good_filter_pos;
        mem->inflate_consumed_pos = saved->inflate_consumed_pos;
        mem->errpos_is_precise = saved->errpos_is_precise;
        mem->last_filter_blk = saved->last_filter_blk;
        mem->last_filter_blk_boundary = saved->last_filter_blk_boundary;
        mem->last_idat_crc_pos = saved->last_idat_crc_pos;
        mem->last_chunk_crc_pos = saved->last_chunk_crc_pos;
        mem->prev_idat_crc_pos = saved->prev_idat_crc_pos;
        memcpy(mem->idat_crc_ring, saved->idat_crc_ring, sizeof(mem->idat_crc_ring));
        mem->idat_crc_ring_count = saved->idat_crc_ring_count;
        mem->d4_restore_crc_pos = saved->last_idat_crc_pos;
        mem->have_iend = saved->have_iend;
        mem->img_width = saved->img_width;
        mem->img_height = saved->img_height;
        mem->img_bitdepth = saved->img_bitdepth;

        /* CRC checkpoints: deep copy into mem.
         * CRITICAL: keep crc_ckpts, n_crc_ckpts, and max_crc_ckpts
         * consistent.  If crc_ckpts is NULL, max_crc_ckpts MUST be 0
         * so png_ckpt_maybe_record triggers realloc instead of writing
         * through a NULL pointer. */
        if (mem->crc_ckpts) { free(mem->crc_ckpts); mem->crc_ckpts = NULL; }
        mem->n_crc_ckpts = 0;
        mem->max_crc_ckpts = 0;
        if (saved->crc_ckpts && saved->n_crc_ckpts > 0) {
          mem->crc_ckpts = malloc(saved->max_crc_ckpts * sizeof(struct PNGBlockCRC));
          if (! mem->crc_ckpts) { mem->max_crc_ckpts = 0; mem->n_crc_ckpts = 0; }
          if (mem->crc_ckpts) {
            memcpy(mem->crc_ckpts, saved->crc_ckpts, saved->n_crc_ckpts * sizeof(struct PNGBlockCRC));
            mem->n_crc_ckpts = saved->n_crc_ckpts;
            mem->max_crc_ckpts = saved->max_crc_ckpts;
          }
        }
        mem->idat_stored_crc = saved->idat_stored_crc;
        mem->idat_data_start = saved->idat_data_start;
        mem->idat_data_sz = saved->idat_data_sz;
        mem->mid_idat = saved->mid_idat;

        /* H6: deep copy pixel buffers */
        if (saved->prev_row_pixels && saved->pixel_row_bytes > 0) {
          if (!mem->prev_row_pixels || mem->pixel_row_bytes != saved->pixel_row_bytes) {
            free(mem->prev_row_pixels);
            mem->prev_row_pixels = malloc(saved->pixel_row_bytes);
            if (! mem->prev_row_pixels) { mem->pixel_row_bytes = 0; }
          }
          if (mem->prev_row_pixels) {
            memcpy(mem->prev_row_pixels, saved->prev_row_pixels, saved->pixel_row_bytes);
          }
        }
        if (saved->cur_row_pixels && saved->pixel_row_bytes > 0) {
          if (!mem->cur_row_pixels || mem->pixel_row_bytes != saved->pixel_row_bytes) {
            free(mem->cur_row_pixels);
            mem->cur_row_pixels = malloc(saved->pixel_row_bytes);
            if (! mem->cur_row_pixels) { mem->pixel_row_bytes = 0; }
          }
          if (mem->cur_row_pixels) {
            memcpy(mem->cur_row_pixels, saved->cur_row_pixels, saved->pixel_row_bytes);
          }
        }
        mem->pixel_row_bytes = saved->pixel_row_bytes;
        mem->bpp_bytes = saved->bpp_bytes;
        mem->running_mad_sum = saved->running_mad_sum;
        mem->mad_count = saved->mad_count;
        mem->consecutive_good_rows = saved->consecutive_good_rows;
        mem->post_crc_mad_sum = saved->post_crc_mad_sum;
        mem->post_crc_mad_count = saved->post_crc_mad_count;

        /* H7 Paeth fraction */
        mem->running_corr_sum = saved->running_corr_sum;
        mem->corr_count = saved->corr_count;
        mem->post_crc_corr_sum = saved->post_crc_corr_sum;
        mem->post_crc_corr_count = saved->post_crc_corr_count;

        /* B8 */
        mem->b8_block_in_start = saved->b8_block_in_start;
        mem->b8_block_out_start = saved->b8_block_out_start;
        mem->b8_running_ratio = saved->b8_running_ratio;
        mem->b8_running_ratio_sq = saved->b8_running_ratio_sq;
        mem->b8_ratio_count = saved->b8_ratio_count;
        mem->b8_last_block = saved->b8_last_block;
        mem->b8_total_out = saved->b8_total_out;
        mem->b8_anomaly_pos = saved->b8_anomaly_pos;

        /* B9: Filter distribution */
        memcpy(mem->b9_block_filt, saved->b9_block_filt, sizeof(mem->b9_block_filt));
        mem->b9_block_rows = saved->b9_block_rows;
        memcpy(mem->b9_running_frac, saved->b9_running_frac, sizeof(mem->b9_running_frac));
        mem->b9_running_l1 = saved->b9_running_l1;
        mem->b9_running_l1_sq = saved->b9_running_l1_sq;
        mem->b9_block_count = saved->b9_block_count;
        mem->b9_anomaly_pos = saved->b9_anomaly_pos;

        /* B10: Per-block MAD average */
        mem->b10_block_mad_sum = saved->b10_block_mad_sum;
        mem->b10_block_mad_count = saved->b10_block_mad_count;
        mem->b10_running_mad_avg = saved->b10_running_mad_avg;
        mem->b10_running_mad_avg_sq = saved->b10_running_mad_avg_sq;
        mem->b10_block_count = saved->b10_block_count;
        mem->b10_anomaly_pos = saved->b10_anomaly_pos;
        mem->b10_last_mad = saved->b10_last_mad;
        mem->b10_max_post_crc_mad = 0.0;  /* reset: track max from this restore */
        mem->h9_cand_mad_sum = 0.0;     /* H9: reset candidate-region accumulators */
        mem->h9_cand_mad_count = 0;
        mem->h9_mad_count_since_d4 = 0;  /* reset: count MADs from this restore */


        /* B8f: Fine-grained sub-block ratio */
        mem->b8f_sub_blocksize = saved->b8f_sub_blocksize;
        mem->b8f_block_in_start = saved->b8f_block_in_start;
        mem->b8f_block_out_start = saved->b8f_block_out_start;
        mem->b8f_running_ratio = saved->b8f_running_ratio;
        mem->b8f_running_ratio_sq = saved->b8f_running_ratio_sq;
        mem->b8f_ratio_count = saved->b8f_ratio_count;
        mem->b8f_last_sub_blk = saved->b8f_last_sub_blk;
        mem->b8f_anomaly_pos = saved->b8f_anomaly_pos;

        /* B11: Auto-correlation */
        memcpy(mem->b11_byte_ring, saved->b11_byte_ring, sizeof(mem->b11_byte_ring));
        mem->b11_byte_wpos = saved->b11_byte_wpos;
        memcpy(mem->b11_hash_ring, saved->b11_hash_ring, sizeof(mem->b11_hash_ring));
        mem->b11_hash_wpos = saved->b11_hash_wpos;
        mem->b11_byte_match_run = saved->b11_byte_match_run;
        mem->b11_byte_last_check = saved->b11_byte_last_check;
        mem->b11_anomaly_pos = saved->b11_anomaly_pos;
        mem->b12_spike_pos = saved->b12_spike_pos;
        mem->b12_spike_mad = saved->b12_spike_mad;
        mem->b12_spike_ratio = saved->b12_spike_ratio;
        mem->b12_rows_into_block = saved->b12_rows_into_block;
        /* Combined suspicion */
        mem->b8_suspicion = saved->b8_suspicion;
        mem->b8_max_suspicion_since_crc = saved->b8_max_suspicion_since_crc;
        mem->b9_suspicion = saved->b9_suspicion;
        mem->b10_suspicion = saved->b10_suspicion;
        mem->combined_max_sum = saved->combined_max_sum;
        mem->combined_anomaly_pos = saved->combined_anomaly_pos;
        mem->post_zend_idat_bytes = saved->post_zend_idat_bytes;

        /* IDAT loop state */
        mem->cur_y = saved->cur_y;
        mem->cur_pass = saved->cur_pass;
        mem->cur_xoff = saved->cur_xoff;
        mem->cur_yoff = saved->cur_yoff;
        mem->cur_xskip = saved->cur_xskip;
        mem->cur_yskip = saved->cur_yskip;
        mem->cur_width = saved->cur_width;
        mem->cur_linebytes = saved->cur_linebytes;
        mem->numfilt = saved->numfilt;
        mem->numfilt_this_block = saved->numfilt_this_block;
        mem->numfilt_total = saved->numfilt_total;
        memcpy(mem->numfilt_pass, saved->numfilt_pass, sizeof(mem->numfilt_pass));
        /* Restore inflate output pointer offset.  pngcheck's wrapping
         * trick leaves inflate_out_ptr at outbuf + delta after each
         * refill.  delta > 0 means a partial row was already consumed
         * past eod; the first delta bytes of the next inflate fill are
         * continuation data that the row processor must skip. */
        mem->inflate_out_ptr = mem->outbuf + saved->inflate_out_ptr_offset;

        /* Restore zlib stream */
        if (saved->has_zstrm) {
          if (zstrm_initialized) {
            inflateEnd(&zstrm);
          }
          if (saved->zstrm_copy &&
              inflateCopy(&zstrm, saved->zstrm_copy) == Z_OK) {
            zstrm_initialized = true;
            /* The wrap reset next_out to outbuf and avail_out to BS
             * at save time; restore those same values so inflate fills
             * from the start of outbuf (p at outbuf + offset skips the
             * partial-row continuation bytes). */
            zstrm.next_out = mem->outbuf;
            zstrm.avail_out = BS;

            /* Replay unconsumed inflate input.  At save time, these bytes
             * were in mem->buffer but the body-drain loop overwrote them.
             * Copy them back into mem->buffer so zstrm.next_in is valid. */
            if (saved->zstrm_leftover_count > 0 && saved->zstrm_leftover) {
              memcpy(mem->buffer, saved->zstrm_leftover,
                     saved->zstrm_leftover_count);
              zstrm.next_in = mem->buffer;
              zstrm.avail_in = saved->zstrm_leftover_count;
            } else {
              zstrm.next_in = Z_NULL;
              zstrm.avail_in = 0;
            }
          }
        }

        if (_d4_owns_saved) {
          png_free_carve_state((void **)&saved);
        }
        goto d4_resume_main_loop;
      }
    }
    if (_d4_owns_saved) {
      png_free_carve_state((void **)&saved);
    }
    /* D4 restore failed (invalid or hash mismatch).  Reset curpos to 0
     * so the validator re-parses from the PNG signature.  Without this,
     * curpos remains at the stale D4 checkpoint position and the
     * validator reads garbage instead of the PNG magic bytes. */
    mem->curpos = 0;
  }
#endif /* PNG_D4_STATE_CACHE */

  if (mem_fread(magic, 1, 8, mem)!=8) {
    set_err(kCriticalError, mem);
    return mem->global_error;
  }

  {
    int check = check_magic(mem, magic, DO_PNG);
    if (check == 1) {
      /* bytes 2-4 say "PNG" but other magic bytes are wrong */
      set_err(kCriticalError, mem);
    } else if (check == 2) {
      /* not a PNG file */
      set_err(kCriticalError, mem);
    }
  }

  if (is_err(kMinorError, mem))
      return mem->global_error;

  /*-------------------- BEGINNING OF IMMENSE WHILE-LOOP --------------------*/

#if PNG_D4_STATE_CACHE
  d4_resume_main_loop:
#endif

  while ((c = mem_fgetc(mem)) != EOF) {
    mem_ungetc(c, mem);
    mem->last_good_pos = mem->curpos;

    // Yield to checkpoint if signaled.  Return current error state
    // so the caller sees partial progress rather than waiting.
    if (mem->direct_state
        && atomic_load_explicit(&REASS_RETURN_TO_IDLE,
                                memory_order_acquire)) {
      return mem->global_error;
    }

    if (have_IEND) {
      // Additional data past IEND isn't an error — just stop processing.
      // Record the file end position (curpos is at byte after IEND CRC).
      mem->last_good_pos = mem->curpos;
      mem->global_error=kOK;
      return mem->global_error;
    }

    sz = getlong(mem, "chunk length");

    if (is_err(kMajorError, mem))
      return mem->global_error;

    if (sz < 0 || sz > 0x7fffffff) {
      set_err(kMajorError, mem);
      return mem->global_error;
    }

    if (mem_fread(chunkid, 1, 4, mem) != 4) {
      if (mem->direct_state) {
        set_err_no_errpos(kMajorError, mem);
      }
      else {
        set_err_no_errpos(kCriticalError, mem);
      }
      return mem->global_error;
    }

    chunkid[4] = '\0';
    ++num_chunks;

    if (check_chunk_name(mem, chunkid) != 0) {
      set_err(kMajorError, mem);
      return mem->global_error;
    }

    if (is_err(kMajorError, mem))
      return mem->global_error;

    crc = update_crc(CRCINIT, (uch *)chunkid, 4);

    if (!have_IHDR && strcmp(chunkid,"IHDR")!=0)
    {
      set_err(kMinorError, mem);
      return mem->global_error;
    }

    toread = (sz > BS)? BS:sz;

    if (mem_fread(mem->buffer, 1, (size_t)toread, mem) != (size_t)toread) {
      /* EOF: missing blocks at the end — not a validation error */
      set_err_no_errpos(kCriticalError, mem);
      return mem->global_error;
    }

    {
      /* CRC before body data = CRC of chunk type alone */
      ulg first_crc_before = crc32(CRCINIT, (uch *)chunkid, 4);
      crc = update_crc(crc, (uch *)mem->buffer, toread);

      /* #5: CRC checkpoint for block boundaries within first toread of IDAT */
      if (strcmp(chunkid, "IDAT") == 0 && mem->blocksize) {
        uint64_t prev_pos = mem->curpos - toread;
        png_ckpt_maybe_record(mem, first_crc_before, (const uch *)mem->buffer,
                              prev_pos, mem->curpos);
      }

      /* #2: spurious chunk-header check for block boundaries in first toread
       * of any non-IDAT chunk.  Same logic as in the body-drain loop. */
      if (mem->blocksize && strcmp(chunkid, "IDAT") != 0) {
        uint64_t bs = mem->blocksize;
        uint64_t prev_pos = mem->curpos - toread;
        uint64_t first_bdy = (prev_pos / bs + 1) * bs;
        for (uint64_t bdy = first_bdy; bdy < mem->curpos; bdy += bs) {
          if (bdy + 8 <= mem->length) {
            const unsigned char *bp = (const unsigned char *)mem->data + bdy;
            unsigned long probe_len = ((ulg)bp[0]<<24)|((ulg)bp[1]<<16)|
                                      ((ulg)bp[2]<<8)|(ulg)bp[3];
            /* Match only known chunk names — arbitrary 4-letter sequences
             * appear too often in compressed data to be reliable. */
            int looks_like_header =
              (probe_len <= 0x7fffffffUL) &&
              png_is_known_chunk(bp + 4);
            if (looks_like_header) {
                mem->errpos = (bdy > 1) ? (int64_t)(bdy - 2) : 0;
              set_err_no_errpos(kMajorError, mem);
              return mem->global_error;
            }
          }
        }
      }
    }

    /*================================*
     * PNG *
     *================================*/

    /*------*
     | IHDR |
     *------*/
    if (strcmp(chunkid, "IHDR") == 0) {
      if (have_IHDR) {
        set_err(kMinorError, mem);
      } else if (sz != 13) {
        set_err(kMajorError, mem);
      }
      if (no_err(kMinorError, mem)) {
        int compr, filt;

        w = LG(mem->buffer);
        h = LG(mem->buffer+4);
        if (w <= 0 || h <= 0 || w > 2147483647 || h > 2147483647) {
          set_err(kMinorError, mem);
        }
        bitdepth = sampledepth = (uch)mem->buffer[8];
        ityp = (uch)mem->buffer[9];
        if (ityp == 1 || ityp == 5 || ityp > (int)(sizeof(png_type)/sizeof(char*))) {
          ityp = 1; /* avoid out of range array index */
          set_err(kMinorError, mem);
        }
        switch (sampledepth) {
          case 1:
          case 2:
          case 4:
            if (ityp == 2 || ityp == 4 || ityp == 6) { /* RGB or GA or RGBA */
              set_err(kMinorError, mem);
            }
            break;
          case 8:
            break;
          case 16:
            if (ityp == 3) { /* palette */
              set_err(kMinorError, mem);
            }
            break;
          default:
            set_err(kMinorError, mem);
            break;
        }
        compr = (uch)mem->buffer[10];
        if (compr > 127) {
          set_err(kWarning, mem);
        } else if (compr > 0) {
          set_err(kMinorError, mem);
        }
        filt = (uch)mem->buffer[11];
        if (filt > 127) {
          set_err(kWarning, mem);
        } else if (filt > 0)
        {
          set_err(kMinorError, mem);
        }
        lace = (uch)mem->buffer[12];
        if (lace > 127) {
          set_err(kWarning, mem);
        } else if (lace > 1) {
          set_err(kMinorError, mem);
        }
        switch (ityp) {
          case 2:
            bitdepth = sampledepth * 3;   /* RGB */
            break;
          case 4:
            bitdepth = sampledepth * 2;   /* gray+alpha */
            break;
          case 6:
            bitdepth = sampledepth * 4;   /* RGBA */
            break;
        }
      }
      have_IHDR = 1;
      last_is_IDAT = 0;
      /* Snapshot dimensions for block-boundary analysis */
      mem->img_width    = w;
      mem->img_height   = h;
      mem->img_bitdepth = bitdepth;

      /* H6: Allocate pixel reconstruction buffers for gradient gate validation.
       * Compute bytes per pixel from color type and sample depth. */
      {
        int channels;
        switch (ityp) {
          case 0: channels = 1; break;  /* grayscale */
          case 2: channels = 3; break;  /* RGB */
          case 3: channels = 1; break;  /* palette (1 index byte per pixel) */
          case 4: channels = 2; break;  /* grayscale + alpha */
          case 6: channels = 4; break;  /* RGBA */
          default: channels = 1; break;
        }
        mem->bpp_bytes = (channels * sampledepth + 7) / 8;
        if (mem->bpp_bytes < 1) mem->bpp_bytes = 1;
        mem->pixel_row_bytes = (uint32_t)((w * channels * sampledepth + 7) / 8);

        /* Allocate buffers for previous and current row pixel data reconstruction */
        if (!mem->complete_contiguous_probe && mem->pixel_row_bytes > 0) {
          mem->prev_row_pixels = (uint8_t *)calloc(mem->pixel_row_bytes, 1);
          mem->cur_row_pixels = (uint8_t *)calloc(mem->pixel_row_bytes, 1);
        }

        /* Initialize H6 gate state */
        mem->running_mad_sum = 0.0;
        mem->mad_count = 0;
        mem->consecutive_good_rows = 0;
        mem->post_crc_mad_sum = 0.0;
        mem->post_crc_mad_count = 0;
        /* H7 Paeth fraction */
        mem->running_corr_sum = 0.0;
        mem->corr_count = 0;
        mem->post_crc_corr_sum = 0.0;
        mem->post_crc_corr_count = 0;
      }
      mem->first_idat = 1;  /* flag:  next IDAT will be the first in this subimage */
      mem->zlib_error = 0;  /* flag:  no zlib errors yet in this file */
    /*================================================*
     * PNG chunks (with the exception of IHDR, above) *
     *================================================*/

    /*------*
     | PLTE |
     *------*/
    } else if (strcmp(chunkid, "PLTE") == 0) {
      if (have_PLTE) {
        set_err(kMinorError, mem);
      } else if (ityp != 3 && ityp != 2 && ityp != 6) {
        set_err(kMinorError, mem);
      } else if (have_IDAT) {
        set_err(kMinorError, mem);
      } else if (have_bKGD) {
        set_err(kMinorError, mem);
      } else if (sz < 3 || sz > 768 || sz % 3 != 0) {
        set_err(kMinorError, mem);
      } else {
        nplte = sz / 3;
        if ((bitdepth == 1 && nplte > 2) ||
            (bitdepth == 2 && nplte > 4) || (bitdepth == 4 && nplte > 16))
        {
          set_err(kMinorError, mem);
        }
      }

      if (no_err(kMinorError, mem)) {
        if (ityp == 1)   /* for tRNS */
          ityp = 3;
      }
      have_PLTE = 1;
      last_is_IDAT = 0;

    /*------*
     | IDAT |
     *------*/
    } else if (strcmp(chunkid, "IDAT") == 0) {
      /* Record IDAT body range for block-boundary CRC analysis (#5) */
      if (mem->blocksize) {
        mem->idat_data_start = mem->curpos - toread;
        mem->idat_data_sz    = sz;
        mem->n_crc_ckpts     = 0;  /* reset from any previous chunk */
        mem->mid_idat        = true;  /* inside IDAT body, CRC not yet verified */
      }
      if (have_IDAT && !last_is_IDAT) {
        set_err(kMajorError, mem);
      } else if (ityp == 3 && !have_PLTE) {
        set_err(kMajorError, mem);
      }

      if (!no_err(kMinorError, mem))
        return mem->global_error;

      /* We just want to check that we have read at least the minimum (10)
       * IDAT bytes possible, but avoid any overflow for short ints.  We
       * must also take into account that 0-length IDAT chunks are legal.
       */
      if (have_IDAT <= 0)
        have_IDAT = (sz > 0)? sz : -1;  /* -1 as marker for IDAT(s), no data */
      else if (have_IDAT < 10)
        have_IDAT += (sz > 10)? 10 : sz;

      /* Dump the zlib header from the first two bytes. */
      if (zhead < 0x10000 && sz > 0) {
        zhead = (zhead << 8) + mem->buffer[0];
        if (sz > 1 && zhead < 0x10000)
          zhead = (zhead << 8) + mem->buffer[1];
        if (zhead >= 0x10000) {
          /* See the code in zlib deflate.c that writes out the header when
             s->status is INIT_STATE.  In fact this code is based on the zlib
             specification in RFC 1950 (ftp://ds.internic.net/rfc/rfc1950.txt),
             with the implicit assumption that the zlib header *is* written (it
             always should be inside a valid PNG file).  The variable names are
             taken, verbatim, from the RFC. */
          unsigned int CINFO = (zhead & 0xf000) >> 12;

          if (mem->check_windowbits)   /* check for libpng 1.2.6 windowBits bug */
            mem->zlib_windowbits = CINFO + 8;
	  unsigned int CM = (zhead & 0xf00) >> 8;

	  if ((zhead & 0xffff) % 31) {
	    set_err(kMajorError, mem);
	  } else if (CM != 8) {
	    set_err(kMajorError, mem);
	  }
	}
      }

      /* Z9: Detect unvalidated IDAT data after Z_STREAM_END.
       *
       * When zlib_error == -1, inflate returned Z_STREAM_END on a previous
       * IDAT — the entire compressed image stream has been decompressed.
       * Any subsequent IDAT body data is NOT validated by inflate or the
       * filter check (the inflate block below is skipped entirely).
       *
       * After Z_STREAM_END the remaining IDAT data is unvalidated by zlib.
       * A correct PNG may still have one or more complete IDAT chunks whose
       * CRCs pass — e.g. the encoder wrote fixed-size IDATs and the zlib
       * stream ended partway through one, leaving a full ~65 KB chunk of
       * legitimate trailing data.
       *
       * Threshold: 8× blocksize.  This tolerates several IDAT chunks of
       * legitimate post-zend data while still catching gross wrong-block
       * splicing (each wrong block contributes ~blocksize bytes; 8+ wrong
       * blocks after Z_STREAM_END would trigger this, and by then the
       * pixel-level heuristics H6c/H7 should already be capping VT).
       *
       * This is the "discriminating signal" that the disabled #6 tail cap
       * (line ~4010) could not find: correct blocks after Z_STREAM_END
       * produce negligible extra data, while wrong blocks produce a full
       * IDAT body worth of unvalidated data. */
      if (mem->zlib_error == -1 && mem->blocksize > 0 && sz > 0) {
        mem->post_zend_idat_bytes += (uint64_t)sz;
        if (mem->post_zend_idat_bytes > (uint64_t)mem->blocksize * 8) {
          /* Flag the error.  Use last_idat_crc_pos as the anchor: that's
           * where the last verified IDAT CRC was, and all data after it
           * is unvalidated.  Set errpos_is_precise so VT branch 1 fires
           * directly (no ambiguity about the error location).
           * Note: last_idat_crc_pos may be polluted by self-consistent
           * wrong IDATs; the ring buffer backstop in VT computation
           * catches that case. */
          if (!mem->errpos_is_precise) {
            mem->errpos = (mem->last_idat_crc_pos > 1)
                          ? (int64_t)(mem->last_idat_crc_pos - 2) : 0;
            mem->errpos_is_precise = true;
          }
          set_err_no_errpos(kMajorError, mem);
        }
      }

      if (mem->check_zlib && !mem->zlib_error) {
        /* IDAT loop state in PNGMemIO; use local aliases for readability */
        #define cur_y        mem->cur_y
        #define cur_pass     mem->cur_pass
        #define cur_xoff     mem->cur_xoff
        #define cur_yoff     mem->cur_yoff
        #define cur_xskip    mem->cur_xskip
        #define cur_yskip    mem->cur_yskip
        #define cur_width    mem->cur_width
        #define cur_linebytes mem->cur_linebytes
        #define numfilt      mem->numfilt
        #define numfilt_this_block mem->numfilt_this_block
        #define numfilt_total mem->numfilt_total
        #define numfilt_pass mem->numfilt_pass
        uch *p = mem->inflate_out_ptr;  /* local working pointer */
        uch *eod;
        int err=Z_OK;

        zstrm.next_in = mem->buffer;
        zstrm.avail_in = toread;

        /* initialize zlib and bit/byte/line variables if not already done */
        if (mem->first_idat) {
	  if (! zstrm_initialized) {
	    zstrm.next_out = p = mem->outbuf;
            zstrm.avail_out = BS;
            zstrm.zalloc = (alloc_func)Z_NULL;
            zstrm.zfree = (free_func)Z_NULL;
            zstrm.opaque = (voidpf)Z_NULL;

            if ((err = inflateInit2(&zstrm, mem->zlib_windowbits)) != Z_OK) {
              mem->zlib_error = 1;
              set_err_no_errpos(kCriticalError, mem);
              lock_fprintf(stderr, "COULD NOT INITIALIZE zlib STREAM: %d.\n", err);
              zstrm.next_in = Z_NULL;
              zstrm.avail_in = 0;
              err = Z_STREAM_END;
	    }
	    else {
	      zstrm_initialized = true;
	    }
	  }
	  else {
	    if ((err = inflateReset(&zstrm)) != Z_OK) {
              mem->zlib_error = 1;
              set_err_no_errpos(kCriticalError, mem);
	      lock_fprintf(stderr, "COULD NOT RESET zlib STREAM: %d.\n", err);
              inflateEnd(&zstrm);
              zstrm_initialized = false;
              zstrm.next_in = Z_NULL;
              zstrm.avail_in = 0;
              err = Z_STREAM_END;
	    }
	  }
          if (!mem->zlib_error) {
	    mem->zlib_started=true;
            cur_y = 0;
            cur_pass = 1;     /* interlace pass:  1 through 7 */
            cur_xoff = cur_yoff = 0;
            cur_xskip = cur_yskip = lace? 8 : 1;
            cur_width = (w - cur_xoff + cur_xskip - 1) / cur_xskip; /* round up */
            cur_linebytes = ((cur_width*bitdepth + 7) >> 3) + 1; /* round, fltr */
            numfilt = 0L;
            mem->last_good_filter_pos = mem->curpos - toread;  /* start of IDAT compressed data */
            mem->consecutive_good_rows = 0;  /* #4: reset at each new IDAT sequence */
            mem->post_crc_mad_sum = 0.0;
            mem->post_crc_mad_count = 0;
            mem->post_crc_corr_sum = 0.0;
            mem->post_crc_corr_count = 0;

            /* B8: initialize rate tracking at start of IDAT decompression */
            mem->b8_block_in_start = mem->curpos - toread;

            /* B8f: compute adaptive sub-block size */
            if (mem->blocksize > 0 && mem->b8f_sub_blocksize == 0) {
              mem->b8f_sub_blocksize = mem->blocksize / 4;
              if (mem->b8f_sub_blocksize < 2048)
                mem->b8f_sub_blocksize = 2048;
              mem->b8f_block_in_start = mem->curpos - toread;
              mem->b8f_block_out_start = 0;
              mem->b8f_last_sub_blk = (mem->curpos - toread) / mem->b8f_sub_blocksize;
            }
            mem->b8_block_out_start = 0;
            mem->b8_last_block = (mem->curpos - toread) / (mem->blocksize ? mem->blocksize : 1);
            mem->first_idat = 0;
            if (lace) {   /* loop through passes to calculate total filters */
            int passm1, yskip=0, yoff=0, xoff=0;

            for (passm1 = 0;  passm1 < 7;  ++passm1) {
              switch (passm1) {  /* (see table below for full summary) */
                case 0:  yskip = 8; yoff = 0; xoff = 0; break;
                case 1:  yskip = 8; yoff = 0; xoff = 4; break;
                case 2:  yskip = 8; yoff = 4; xoff = 0; break;
                case 3:  yskip = 4; yoff = 0; xoff = 2; break;
                case 4:  yskip = 4; yoff = 2; xoff = 0; break;
                case 5:  yskip = 2; yoff = 0; xoff = 1; break;
                case 6:  yskip = 2; yoff = 1; xoff = 0; break;
              }
              /* effective height is reduced if odd pass:  subtract yoff (but
               * if effective width of pass is 0 => no rows and no filters) */
              numfilt_pass[passm1] =
                (w <= xoff)? 0 : (h - yoff + yskip - 1) / yskip;

              if (passm1 > 0)  /* now make it cumulative */
                numfilt_pass[passm1] += numfilt_pass[passm1 - 1];
            }
          } else {
            numfilt_pass[0] = h;   /* if non-interlaced */
            numfilt_pass[1] = numfilt_pass[2] = numfilt_pass[3] = h;
            numfilt_pass[4] = numfilt_pass[5] = numfilt_pass[6] = h;
          }
            numfilt_total = numfilt_pass[6];
          }
        }

        numfilt_this_block = 0L;

        while (err != Z_STREAM_END && zstrm.avail_in > 0) {
          /* know zstrm.avail_out > 0:  get some image/filter data */
          err = inflate(&zstrm, Z_SYNC_FLUSH);
          if (err != Z_OK && err != Z_STREAM_END) {
            mem->zlib_error = 1;		/* fatal error only for this PNG */
            break;			/* kill zlib loop */
          }


          if (!mem->complete_contiguous_probe) {
            /* B8: track cumulative decompressed output */
            mem->b8_total_out = zstrm.total_out;

            /* B11 byte-level echo detection: record raw decompressed bytes
             * into a 64KB ring buffer and periodically compare current output
             * to output from ~window-distance back.  Echo (LZ77 replaying from
             * zlib window) produces byte sequences copied from various distances
             * within the window.  We check 3 distances: 16KB, 24KB, 32KB.
             *
             * Every 256 bytes of new output, compare a 64-byte sample.  Count
             * matching bytes: >=48/64 (75%) = high similarity.  8+ consecutive
             * high-similarity samples (2KB of sustained echo) = anomaly. */
            {
            uint64_t new_total = zstrm.total_out;
            uint64_t old_total = mem->b11_byte_wpos;
            if (new_total > old_total) {
              /* Copy newly decompressed bytes into ring.
               * inflate() wrote to outbuf; the new bytes end at
               * (outbuf + BS - avail_out) and there are (new_total - old_total)
               * of them at the tail of the filled region. */
              uint64_t produced = new_total - old_total;
              uch *fill_end = mem->outbuf + BS - zstrm.avail_out;
              uch *fill_start = fill_end - produced;
              if (fill_start < mem->outbuf) fill_start = mem->outbuf;
              uint64_t nbytes = (uint64_t)(fill_end - fill_start);

              for (uint64_t bi = 0; bi < nbytes; bi++) {
                mem->b11_byte_ring[(old_total + bi) & 0xFFFF] = fill_start[bi];
              }
              mem->b11_byte_wpos = new_total;

              /* Multi-distance contiguous-run echo detection: every 256 bytes,
               * compare a 64-byte sample against the same position minus D
               * for D = 4K,8K,12K,16K,20K,24K,28K,32K.  For each distance,
               * find the longest contiguous run of matching bytes.  Take the
               * MAX contiguous run across all distances.  If max_contig >= 12
               * for 8+ consecutive windows, flag echo anomaly.
               *
               * Key insight: natural image correlation produces scattered
               * matching bytes (sim=40-50 but short contiguous runs of 1-3).
               * Echo LZ77 copies produce long contiguous runs (10-30+ bytes).
               * Contiguous run length discriminates far better than total sim.
               *
               * Flat-region filter: FNV-1a hash of current sample must
               * differ from previous sample's hash (local diversity). */
              while (mem->b11_byte_last_check + 256 <= new_total
                     && new_total >= 32768) {  /* need 32KB of byte history */
                mem->b11_byte_last_check += 256;
                uint64_t pos = mem->b11_byte_last_check;

                /* Compute FNV-1a hash of 64 bytes ending at pos for diversity */
                uint32_t cur_hash = 2166136261u;
                for (uint32_t hi = 0; hi < 64; hi++) {
                  cur_hash ^= (uint32_t)mem->b11_byte_ring[(pos - 64 + hi) & 0xFFFF];
                  cur_hash *= 16777619u;
                }

                /* Local diversity: skip if hash == previous hash (flat region) */
                uint32_t prev_hash_idx = (mem->b11_hash_wpos + 127) & 127;
                int locally_diverse = (cur_hash != mem->b11_hash_ring[prev_hash_idx]);
                if (cur_hash == 0) locally_diverse = 0;

                /* Compare 64-byte sample at 5 distances (16K-32K), find max
                 * contiguous run.  Skip 4K-12K: too much natural image
                 * correlation at short distances causes false positives. */
                uint32_t max_contig = 0;
                uint32_t best_dist = 0;
                uint32_t best_sim = 0;
                if (locally_diverse && pos >= 32768 + 64) {
                  for (uint32_t di = 4; di <= 8; di++) {
                    uint32_t dist = di * 4096;  /* 16K, 20K, 24K, 28K, 32K */
                    uint32_t sim = 0;
                    uint32_t contig = 0;
                    uint32_t max_c = 0;
                    for (uint32_t bi = 0; bi < 64; bi++) {
                      uint8_t a = mem->b11_byte_ring[(pos - 64 + bi) & 0xFFFF];
                      uint8_t b = mem->b11_byte_ring[(pos - 64 + bi - dist) & 0xFFFF];
                      if (a == b) {
                        sim++;
                        contig++;
                        if (contig > max_c) max_c = contig;
                      } else {
                        contig = 0;
                      }
                    }
                    if (max_c > max_contig) {
                      max_contig = max_c;
                      best_dist = dist;
                      best_sim = sim;
                    }
                  }
                }
                (void)best_dist;
                (void)best_sim;

                /* Threshold: 16+ contiguous matching bytes = likely LZ77 copy.
                 * Natural image correlation at 16K+ rarely produces runs this
                 * long; LZ77 copies are typically 3-258 bytes. */
                if (max_contig >= 16) {
                  mem->b11_byte_match_run++;
                } else {
                  mem->b11_byte_match_run = 0;
                }

#if PNG_B11_DEBUG
                if (mem->b11_byte_match_run > 2
                    || (max_contig >= 12 && locally_diverse)
                    || (pos / 256) % 500 == 0) {
                  uint64_t ip = mem->curpos - zstrm.avail_in;
                  fprintf(stderr, "B11C: ipos=%"PRIu64" decomp=%"PRIu64
                          " contig=%u sim=%u dist=%u div=%d run=%u\n",
                          ip, pos, max_contig, best_sim, best_dist,
                          locally_diverse, mem->b11_byte_match_run);
                }
#endif

                /* 8+ consecutive windows with max_contig >= 16 = 2KB of
                 * sustained echo with LZ77-copy-length contiguous matches */
                if (mem->b11_byte_match_run >= 8 && mem->b11_anomaly_pos == 0) {
                  uint64_t ip = mem->curpos - zstrm.avail_in;
                  mem->b11_anomaly_pos = ip;
#if PNG_B11_DEBUG
                  fprintf(stderr, "B11C: ANOMALY at %"PRIu64" run=%u\n",
                          ip, mem->b11_byte_match_run);
#endif
                }

                /* Store hash in ring for next diversity check */
                mem->b11_hash_ring[mem->b11_hash_wpos & 127] = cur_hash;
                mem->b11_hash_wpos++;
              }
            }
            }
          }

          /* now have uncompressed, filtered image data in outbuf */
          eod = mem->outbuf + BS - zstrm.avail_out;
          while (p < eod) {

	    /* Protect against run-on data past image dimensions */
	    if ((lace && cur_pass > 7) || (!lace && cur_y > h)) {
	      mem->zlib_error = 2;           /* fatal: run-on past image dims (ze=2) */
	      err = Z_STREAM_END;       /* kill middle loop */
	      break;                    /* kill "innermost" loop */
	    }


            if (cur_linebytes) {
              int filttype = p[0];
              if (filttype > 127) {
                if (lace > 1)
                  break;  /* assume it's due to unknown interlace method */
                mem->consecutive_good_rows = 0;  /* #4 */
                mem->post_crc_mad_sum = 0.0;
                mem->post_crc_mad_count = 0;
                mem->post_crc_corr_sum = 0.0;
                mem->post_crc_corr_count = 0;
                // Break out of all loops so avail_in correction sets errpos precisely
                mem->zlib_error = 2;  /* filter-type failure (ze=2 distinguishes from inflate Z_DATA_ERROR ze=1) */
                err = Z_STREAM_END;
                break;
              } else if (filttype > 4) {
                if (lace <= 1) {
                  mem->consecutive_good_rows = 0;  /* #4 */
                  mem->post_crc_mad_sum = 0.0;
                  mem->post_crc_mad_count = 0;
                  mem->post_crc_corr_sum = 0.0;
                  mem->post_crc_corr_count = 0;
                  // Break out of all loops so avail_in correction sets errpos precisely
                  mem->zlib_error = 2;  /* filter-type failure (ze=2 distinguishes from inflate Z_DATA_ERROR ze=1) */
                  err = Z_STREAM_END;
                  break;
                } /* else assume it's due to unknown interlace method */
                break;
              }

              {
                ++numfilt;
                ++numfilt_this_block;

                /* B9: accumulate per-block filter type histogram */
                if (filttype <= 4) {
                  mem->b9_block_filt[filttype]++;
                  mem->b9_block_rows++;
                }
                /* H6: Pixel gradient gate with MAD validation.
                 *
                 * Apply inverse filter to reconstruct pixel values from filtered row data,
                 * then compute Mean Absolute Difference (MAD) between consecutive rows.
                 * Correct PNG data produces small MAD values (avg 5-30). Wrong IDAT data
                 * decompressed with wrong zlib context produces random pixel values with
                 * MAD ~127 (half of 256). Gate requires 2 consecutive valid rows to
                 * advance last_good_filter_pos. */
                {
                  uint32_t row_num = (uint32_t)cur_y;  /* monotonic row counter */

                  if (mem->cur_row_pixels && mem->pixel_row_bytes > 0) {
                   if ((p + 1 + mem->pixel_row_bytes) <= (mem->outbuf + BS + OUTBUF_PAD)) {
                    /* Row pixel data fits within outbuf allocation.
                     * Note: may extend past eod (inflate output end) into
                     * padding — this is the original pngcheck behavior where
                     * rows straddling buffer boundaries read stale/zero data
                     * for the tail portion.  MAD is slightly diluted but
                     * sufficient for validation. */
                    /* Reconstruct pixels — switch OUTSIDE the loop so the
                     * compiler can auto-vectorize each filter type's loop. */
                    uint8_t *filtered = (uint8_t *)(p + 1);  /* skip filter byte */
                    uint32_t prb = mem->pixel_row_bytes;
                    uint8_t bpp = mem->bpp_bytes;
                    uint8_t *cur = mem->cur_row_pixels;
                    uint8_t *prv = mem->prev_row_pixels;
                    switch (filttype) {
                      case 0:  /* None */
                        memcpy(cur, filtered, prb);
                        break;
                      case 1:  /* Sub */
                        for (uint32_t i = 0; i < bpp && i < prb; i++) {
                          cur[i] = filtered[i];
                        }
                        for (uint32_t i = bpp; i < prb; i++) {
                          cur[i] = filtered[i] + cur[i - bpp];
                        }
                        break;
                      case 2:  /* Up — vectorizable */
                        for (uint32_t i = 0; i < prb; i++) {
                          cur[i] = filtered[i] + prv[i];
                        }
                        break;
                      case 3:  /* Average */
                        for (uint32_t i = 0; i < bpp && i < prb; i++) {
                          cur[i] = filtered[i] + (prv[i] / 2);
                        }
                        for (uint32_t i = bpp; i < prb; i++) {
                          cur[i] = filtered[i] + ((cur[i - bpp] + prv[i]) / 2);
                        }
                        break;
                      case 4:  /* Paeth */
                        for (uint32_t i = 0; i < bpp && i < prb; i++) {
                          cur[i] = filtered[i] + paeth_predictor(0, prv[i], 0);
                        }
                        for (uint32_t i = bpp; i < prb; i++) {
                          cur[i] = filtered[i] + paeth_predictor(
                              cur[i - bpp], prv[i], prv[i - bpp]);
                        }
                        break;
                      default:  /* Unknown filter — treat as None */
                        memcpy(cur, filtered, prb);
                        break;
                    }

                    /* Compute MAD if this is not the first row */
                    bool row_ok = true;
                    if (row_num > 0) {
                      uint64_t diff_sum = 0;
                      for (uint32_t i = 0; i < mem->pixel_row_bytes; ++i) {
                        diff_sum += abs((int)mem->cur_row_pixels[i] - (int)mem->prev_row_pixels[i]);
                      }
                      double mad = (double)diff_sum / mem->pixel_row_bytes;

                      /* B10: accumulate per-block MAD */
                      mem->b10_block_mad_sum += mad;
                      mem->b10_block_mad_count++;
                      mem->b10_last_mad = mad;  /* H9: always track most recent row MAD */
                      /* H9: track max MAD since last IDAT CRC for blind-spot detection */
                      {
                        uint64_t ipos_mad = mem->curpos - zstrm.avail_in;
                        if (mem->last_idat_crc_pos > 0
                            && ipos_mad > mem->last_idat_crc_pos) {
                          if (mad > mem->b10_max_post_crc_mad)
                            mem->b10_max_post_crc_mad = mad;
                          /* H9: candidate-region accumulator — skip first block
                           * after CRC (committed data), start at candidate block */
                          if (mem->blocksize > 0
                              && ipos_mad > mem->last_idat_crc_pos + mem->blocksize) {
                            mem->h9_cand_mad_sum += mad;
                            mem->h9_cand_mad_count++;
                          }
                        }
                      }
                      mem->h9_mad_count_since_d4++;  /* diagnostic */

                      /* B12: Single-row MAD spike detection at block boundaries.
                       *
                       * Check the first 2 rows of each new block after the last
                       * CRC boundary.  When echo starts, the transition row has
                       * pixels from a completely different image region, producing
                       * a MAD spike visible to the naked eye.
                       *
                       * LATEST WINS: always overwrite with the most recent spike.
                       * Reasoning: correct→correct boundaries occasionally spike
                       * from texture changes, but after the echo transition the
                       * echo region is smooth (copies from sliding window), so
                       * the echo transition is the LAST significant spike.
                       *
                       * Threshold: 5× running average (minimum to identify a
                       * real discontinuity vs. normal row-to-row variation). */
                      if (mem->blocksize > 0 && mem->b12_rows_into_block < 2
                          && mem->mad_count >= 8
                          && mem->last_idat_crc_pos > 0) {
                        uint64_t ipos = mem->curpos - zstrm.avail_in;
                        if (ipos > mem->last_idat_crc_pos) {
                          double ravg = mem->running_mad_sum / mem->mad_count;
                          double ratio = (ravg > 0.0) ? mad / ravg : 0.0;
                          if (ravg > 10.0 && ratio > 5.0) {
                            /* Latest spike — always overwrite previous */
                            mem->b12_spike_pos = mem->last_filter_blk_boundary;
                            mem->b12_spike_mad = mad;
                            mem->b12_spike_ratio = ratio;
#if PNG_B12_DEBUG
                            fprintf(stderr, "B12-SPIKE: mad=%.1f avg=%.1f ratio=%.1f"
                                    " blk_pos=%"PRIu64" ipos=%"PRIu64
                                    " crc_pos=%"PRIu64" rows_in=%"PRIu64"\n",
                                    mad, ravg, ratio,
                                    mem->b12_spike_pos, ipos,
                                    mem->last_idat_crc_pos,
                                    mem->b12_rows_into_block);
#endif
                          }
                        }
                      }
                      mem->b12_rows_into_block++;

                      /* B11 row-based logic removed — replaced by byte-level
                       * comparison in the inflate output path above. */

                      /* H7: Filter type distribution (Paeth fraction).
                       *
                       * For photographic PNG data, encoders overwhelmingly
                       * choose filter type 4 (Paeth) — typically 90-97% of
                       * rows.  When wrong compressed data from another image
                       * is decompressed with the wrong zlib dictionary, the
                       * output bytes are biased toward 0 (because the sliding
                       * window contains filter residuals near 0).  So wrong
                       * data produces filter type 0 (None) much more often
                       * than Paeth.
                       *
                       * Track a running Paeth fraction and a post-CRC Paeth
                       * fraction.  A sustained drop in Paeth fraction after
                       * a CRC boundary indicates foreign data.
                       *
                       * This signal is orthogonal to MAD: it depends on the
                       * deflate decoding context, not pixel value statistics.
                       * Similar images have similar MAD but the filter type
                       * depends on which bytes the deflate decoder produces
                       * as the first byte of each row. */
                      double is_paeth = (filttype == 4) ? 1.0 : 0.0;

                      /* Gate decision: MAD must be < max(running_avg * 3, 30) */
                      if (mem->mad_count > 0) {
                        double running_avg = mem->running_mad_sum / mem->mad_count;
                        double threshold = running_avg * 3.0;
                        if (threshold < 30.0) threshold = 30.0;
                        if (mad > threshold) row_ok = false;
                        /* H6b: Lower-bound MAD check during cgr recovery.
                         *
                         * Dictionary laundering produces rows that are
                         * near-identical copies from the sliding window:
                         * MAD collapses to 0-12 against a running avg of
                         * ~37.  These rows pass the upper-bound check but
                         * are anomalously smooth — real image rows in the
                         * recovery window should have MAD in the normal
                         * range, not drastically below it.
                         *
                         * Only apply during cgr recovery (cgr < gate) so
                         * that normal processing of legitimately smooth
                         * image regions (where cgr is already high) is
                         * not affected.
                         *
                         * Guard: only apply when running_avg > 15
                         * so that genuinely smooth images (low MAD
                         * overall) are not affected.  The corruption
                         * signal we target has running_avg typically
                         * 30+, so 15 gives wide safety margin. */
                        if (row_ok && mem->consecutive_good_rows < 3
                            && running_avg > 15.0
                            && mad < running_avg / 3.0) {
                          row_ok = false;
                        }
                        /* H6c: Post-CRC MAD accumulator.
                         *
                         * Type 2 dictionary laundering: corrupted data
                         * produces rows with MAD at roughly half the
                         * running average (e.g., MAD ~21 vs avg ~44).
                         * These pass both upper and lower bounds, so
                         * cgr never resets and H6b never activates.
                         *
                         * Per-row detection fails because individual
                         * rows at 0.5× average are normal in photos.
                         * Instead, accumulate a separate MAD average
                         * for rows processed after the last CRC
                         * boundary.  At VT time, compare post-CRC
                         * average to pre-CRC running average to detect
                         * the sustained drop that indicates corruption.
                         *
                         * We track the input position and compare it
                         * to last_idat_crc_pos to know when we've
                         * crossed the CRC boundary. */
                        /* H6c + H7: Post-CRC accumulators for MAD and Paeth fraction */
                        {
                          uint64_t ipos_now = mem->curpos - zstrm.avail_in;
                          if (mem->last_idat_crc_pos > 0
                              && ipos_now > mem->last_idat_crc_pos) {
                            mem->post_crc_mad_sum += mad;
                            mem->post_crc_mad_count++;
                            mem->post_crc_corr_sum += is_paeth;
                            mem->post_crc_corr_count++;
                          }
                        }
                      }

                      if (row_ok) {
                        mem->running_mad_sum += mad;
                        mem->mad_count++;
                        mem->running_corr_sum += is_paeth;
                        mem->corr_count++;
                        mem->consecutive_good_rows++;
                      } else {
                        mem->consecutive_good_rows = 0;
                      }
                    }

                    /* Swap row pointers for next iteration */
                    uint8_t *tmp = mem->prev_row_pixels;
                    mem->prev_row_pixels = mem->cur_row_pixels;
                    mem->cur_row_pixels = tmp;
                   }
                   /* Row wider than allocation: full-row reconstruction
                    * can't fit, but we can still reconstruct the portion
                    * of the row that inflate actually produced (up to eod).
                    * This gives us a partial-row MAD for H9 tiebreaking
                    * on ultra-wide images where pixel_row_bytes > 73728.
                    * prev_row_pixels/cur_row_pixels buffers are allocated
                    * at full pixel_row_bytes and D4-restored. */
                  } else {
                    uint32_t partial_bytes = 0;
                    if (eod > p + 1) {
                      partial_bytes = (uint32_t)(eod - p - 1);
                      if (partial_bytes > mem->pixel_row_bytes)
                        partial_bytes = mem->pixel_row_bytes;
                    }
                    if (partial_bytes > 256
                        && mem->cur_row_pixels && mem->prev_row_pixels) {
                      /* Partial pixel reconstruction — switch outside loop */
                      uint8_t *filtered = (uint8_t *)(p + 1);
                      uint8_t bpp = mem->bpp_bytes;
                      uint8_t *cur = mem->cur_row_pixels;
                      uint8_t *prv = mem->prev_row_pixels;
                      switch (filttype) {
                        case 0:  /* None */
                          memcpy(cur, filtered, partial_bytes);
                          break;
                        case 1:  /* Sub */
                          for (uint32_t i = 0; i < bpp && i < partial_bytes; i++) {
                            cur[i] = filtered[i];
                          }
                          for (uint32_t i = bpp; i < partial_bytes; i++) {
                            cur[i] = filtered[i] + cur[i - bpp];
                          }
                          break;
                        case 2:  /* Up — vectorizable */
                          for (uint32_t i = 0; i < partial_bytes; i++) {
                            cur[i] = filtered[i] + prv[i];
                          }
                          break;
                        case 3:  /* Average */
                          for (uint32_t i = 0; i < bpp && i < partial_bytes; i++) {
                            cur[i] = filtered[i] + (prv[i] / 2);
                          }
                          for (uint32_t i = bpp; i < partial_bytes; i++) {
                            cur[i] = filtered[i] + ((cur[i - bpp] + prv[i]) / 2);
                          }
                          break;
                        case 4:  /* Paeth */
                          for (uint32_t i = 0; i < bpp && i < partial_bytes; i++) {
                            cur[i] = filtered[i] + paeth_predictor(0, prv[i], 0);
                          }
                          for (uint32_t i = bpp; i < partial_bytes; i++) {
                            cur[i] = filtered[i] + paeth_predictor(
                                cur[i - bpp], prv[i], prv[i - bpp]);
                          }
                          break;
                        default:
                          memcpy(cur, filtered, partial_bytes);
                          break;
                      }

                      /* Compute partial-row MAD (skip first row: no prev data) */
                      uint32_t row_num = (uint32_t)cur_y;
                      if (row_num > 0) {
                        uint64_t diff_sum = 0;
                        for (uint32_t i = 0; i < partial_bytes; ++i) {
                          diff_sum += abs((int)mem->cur_row_pixels[i] - (int)mem->prev_row_pixels[i]);
                        }
                        double partial_mad = (double)diff_sum / partial_bytes;
                        mem->b10_last_mad = partial_mad;
                        /* H9: track max MAD since last IDAT CRC */
                        {
                          uint64_t ipos_pr = mem->curpos - zstrm.avail_in;
                          if (mem->last_idat_crc_pos > 0
                              && ipos_pr > mem->last_idat_crc_pos
                              && partial_mad > mem->b10_max_post_crc_mad) {
                            mem->b10_max_post_crc_mad = partial_mad;
                          }
                        }
                        mem->b10_block_mad_sum += partial_mad;
                        mem->b10_block_mad_count++;
                        mem->h9_mad_count_since_d4++;  /* diagnostic */

                        /* Track Paeth fraction for H7 partial-row support */
                        int is_paeth = (filttype == 4) ? 1 : 0;
                        mem->running_mad_sum += partial_mad;
                        mem->mad_count++;
                        mem->running_corr_sum += is_paeth;
                        mem->corr_count++;

                        /* H6c + H7: Post-CRC accumulators for partial rows */
                        {
                          uint64_t ipos_now = mem->curpos - zstrm.avail_in;
                          if (mem->last_idat_crc_pos > 0
                              && ipos_now > mem->last_idat_crc_pos) {
                            mem->post_crc_mad_sum += partial_mad;
                            mem->post_crc_mad_count++;
                            mem->post_crc_corr_sum += is_paeth;
                            mem->post_crc_corr_count++;
                          }
                        }
                      }

                      /* Swap row pointers so next row uses this partial as prev */
                      uint8_t *tmp = mem->prev_row_pixels;
                      mem->prev_row_pixels = mem->cur_row_pixels;
                      mem->cur_row_pixels = tmp;
                    }
                    mem->consecutive_good_rows++;
                  }
                }

                p += cur_linebytes;

                /* Track block boundaries (no counter reset) */
                if (mem->blocksize > 0) {
                  uint64_t input_pos = mem->curpos - zstrm.avail_in;
                  uint64_t cur_blk = input_pos / mem->blocksize;
                  if (cur_blk != mem->last_filter_blk) {
                    mem->last_filter_blk_boundary = cur_blk * mem->blocksize;
                    mem->last_filter_blk = cur_blk;
                    mem->b12_rows_into_block = 0;  /* B12: reset row counter at block boundary */
                    /* no reset — counter carries across boundaries */

                    /* B8: Check inflate rate discontinuity at block boundary.
                     * Compare this block's compression ratio against running avg.
                     * REVERT: remove this entire B8 block to disable. */
                    {
                      uint64_t blk_in = input_pos - mem->b8_block_in_start;
                      uint64_t blk_out = mem->b8_total_out - mem->b8_block_out_start;
                      if (blk_in > 0 && blk_out > 0) {
                        double ratio = (double)blk_out / (double)blk_in;
                        if (mem->b8_ratio_count >= 2) {
                          double avg = mem->b8_running_ratio / mem->b8_ratio_count;
                          double dev = ratio - avg;
                          if (dev < 0) dev = -dev;
                          /* Adaptive threshold: max(3σ, 0.75*avg).
                           *   - 0.75*avg is the floor (≈ 1.75x fixed threshold).
                           *   - 3σ adapts to the file's natural ratio variance.
                           * For low-variance files (uniform content), the floor
                           * dominates — same behavior as the 1.75x fixed threshold
                           * that catches same-resolution echo.
                           * For high-variance files (diverse content), 3σ dominates —
                           * looser threshold avoids false positives on correct blocks
                           * whose ratios naturally vary across the image.
                           * Net effect: can only be same or better than fixed 1.75x. */
                          double b8_thresh = avg * 0.75;  /* floor */
                          if (mem->b8_ratio_count >= 4) {
                            double var = (mem->b8_running_ratio_sq / mem->b8_ratio_count)
                                         - avg * avg;
                            if (var < 0.0) var = 0.0;
                            double sd = sqrt(var);
                            double sigma_thresh = sd * 3.0;
                            if (sigma_thresh > b8_thresh)
                              b8_thresh = sigma_thresh;
                          }
                          /* Store normalized suspicion for combined diagnostic */
                          if (avg > 0.0 && b8_thresh > 0.0) {
                            mem->b8_suspicion = dev / b8_thresh;
                            if (mem->b8_suspicion > mem->b8_max_suspicion_since_crc)
                              mem->b8_max_suspicion_since_crc = mem->b8_suspicion;
                          }
                          /* Reset consecutive_good_rows at wider threshold */
                          if (avg > 0.0 && dev > b8_thresh * 1.5) {
                            mem->consecutive_good_rows = 0;
                          }
                          /* B8 boundary: set b8_anomaly_pos.  Only record
                           * the FIRST anomaly (earliest wrong block). */
                          if (avg > 0.0 && dev > b8_thresh) {
                            if (mem->b8_anomaly_pos == 0)
                              mem->b8_anomaly_pos = mem->b8_block_in_start;
                          }
                        }
                        mem->b8_running_ratio += ratio;
                        mem->b8_running_ratio_sq += ratio * ratio;
                        mem->b8_ratio_count++;
                      }
                      mem->b8_block_in_start = input_pos;
                      mem->b8_block_out_start = mem->b8_total_out;
                    }

                    /* B9: Check filter type distribution discontinuity at block boundary.
                     * Compare this block's filter histogram to running average using
                     * L1 distance.  Orthogonal to B8 (decompressed-side signal).
                     * REVERT: remove this entire B9 block to disable. */
                    if (mem->b9_block_rows >= 4) {
                      /* Compute current block's normalized distribution */
                      double cur_frac[5];
                      int fi;
                      for (fi = 0; fi < 5; fi++)
                        cur_frac[fi] = (double)mem->b9_block_filt[fi] / mem->b9_block_rows;

                      if (mem->b9_block_count >= 2) {
                        /* Compute L1 distance to running average distribution */
                        double l1 = 0.0;
                        for (fi = 0; fi < 5; fi++) {
                          double avg_fi = mem->b9_running_frac[fi] / mem->b9_block_count;
                          double d = cur_frac[fi] - avg_fi;
                          if (d < 0) d = -d;
                          l1 += d;
                        }

                        double b9_thresh = 1.5;  /* floor: L1=1.5 means 75% of distribution mass shifted */
                        if (mem->b9_block_count >= 4) {
                          double l1_avg = mem->b9_running_l1 / (mem->b9_block_count - 1);
                          double l1_var = (mem->b9_running_l1_sq / (mem->b9_block_count - 1))
                                          - l1_avg * l1_avg;
                          if (l1_var < 0.0) l1_var = 0.0;
                          double sigma_thresh = sqrt(l1_var) * 3.0;
                          if (sigma_thresh > b9_thresh)
                            b9_thresh = sigma_thresh;
                        }
                        /* Store normalized suspicion for combined diagnostic */
                        if (b9_thresh > 0.0)
                          mem->b9_suspicion = l1 / b9_thresh;


                        /* B9 boundary: flag anomaly (first only) */
                        if (l1 > b9_thresh) {
                          if (mem->b9_anomaly_pos == 0)
                            mem->b9_anomaly_pos = mem->b8_block_in_start;
                        }

                        /* Track L1 variance */
                        mem->b9_running_l1 += l1;
                        mem->b9_running_l1_sq += l1 * l1;
                      }

                      /* Accumulate running distribution and reset block counters */
                      for (fi = 0; fi < 5; fi++) {
                        mem->b9_running_frac[fi] += cur_frac[fi];
                        mem->b9_block_filt[fi] = 0;
                      }
                      mem->b9_block_count++;
                      mem->b9_block_rows = 0;
                    }

                    /* B10: Check per-block MAD average discontinuity.
                     * Compare this block's average MAD to running avg across blocks.
                     * REVERT: remove this entire B10 block to disable. */
                    if (mem->b10_block_mad_count >= 1) {
                      double blk_avg = mem->b10_block_mad_sum / mem->b10_block_mad_count;
                      if (mem->b10_block_count >= 2) {
                        double run_avg = mem->b10_running_mad_avg / mem->b10_block_count;
                        double dev = blk_avg - run_avg;
                        if (dev < 0) dev = -dev;
                        double b10_thresh = run_avg * 1.5;
                        if (mem->b10_block_count >= 4) {
                          double var = (mem->b10_running_mad_avg_sq / mem->b10_block_count)
                                       - run_avg * run_avg;
                          if (var < 0.0) var = 0.0;
                          double sigma_thresh = sqrt(var) * 3.0;
                          if (sigma_thresh > b10_thresh)
                            b10_thresh = sigma_thresh;
                        }
                        /* Store normalized suspicion for combined diagnostic */
                        if (run_avg > 0.0 && b10_thresh > 0.0)
                          mem->b10_suspicion = dev / b10_thresh;
                        if (run_avg > 0.0 && dev > b10_thresh) {
                          if (mem->b10_anomaly_pos == 0)
                            mem->b10_anomaly_pos = mem->b8_block_in_start;
                        }
                      }
                      mem->b10_running_mad_avg += blk_avg;
                      mem->b10_running_mad_avg_sq += blk_avg * blk_avg;
                      mem->b10_block_count++;
                      mem->b10_block_mad_sum = 0.0;
                      mem->b10_block_mad_count = 0;
                    }

                    /* Combined suspicion diagnostic at block boundary.
                     * Print all three normalized suspicion values on one line
                     * when any exceeds 0.3 (30% of its individual threshold). */
                    { double csum = mem->b8_suspicion + mem->b9_suspicion + mem->b10_suspicion;
                      /* Track the maximum combined suspicion sum and its position */
                      if (csum > mem->combined_max_sum) {
                        mem->combined_max_sum = csum;
                        mem->combined_anomaly_pos = mem->b8_block_in_start;
                      }
                    }

                    /* B8f: Fine-grained sub-block compression ratio check.
                     * Same as B8 but fires at sub_blocksize boundaries
                     * (blocksize/4, min 2048) for higher sensitivity.
                     * REVERT: remove this entire B8f block to disable. */
                    if (mem->b8f_sub_blocksize > 0) {
                      uint64_t cur_sub = input_pos / mem->b8f_sub_blocksize;
                      if (cur_sub != mem->b8f_last_sub_blk) {
                        mem->b8f_last_sub_blk = cur_sub;
                        uint64_t sub_in = input_pos - mem->b8f_block_in_start;
                        uint64_t sub_out = mem->b8_total_out - mem->b8f_block_out_start;
                        if (sub_in > 0 && sub_out > 0) {
                          double ratio = (double)sub_out / (double)sub_in;
                          if (mem->b8f_ratio_count >= 32) {
                            double avg = mem->b8f_running_ratio / mem->b8f_ratio_count;
                            double dev = ratio - avg;
                            if (dev < 0) dev = -dev;
                            double b8f_thresh = avg * 0.75;  /* same floor as B8 */
                            if (1) { /* sigma always available at cnt>=32 */
                              double var = (mem->b8f_running_ratio_sq / mem->b8f_ratio_count)
                                           - avg * avg;
                              if (var < 0.0) var = 0.0;
                              double sigma_thresh = sqrt(var) * 3.0;
                              if (sigma_thresh > b8f_thresh)
                                b8f_thresh = sigma_thresh;
                            }
#if PNG_B8F_DEBUG
                            fprintf(stderr, "B8F-SUB: sub=%"PRIu64
                                    " in=%"PRIu64" out=%"PRIu64
                                    " ratio=%.3f avg=%.3f dev=%.3f thresh=%.3f"
                                    " cnt=%"PRIu64"\n",
                                    cur_sub, sub_in, sub_out,
                                    ratio, avg, dev, b8f_thresh,
                                    mem->b8f_ratio_count);
#endif
                            if (avg > 0.0 && dev > b8f_thresh) {
                              if (mem->b8f_anomaly_pos == 0)
                                mem->b8f_anomaly_pos = mem->b8f_block_in_start;
#if PNG_B8F_DEBUG
                              fprintf(stderr, "B8F-SUB: ANOMALY at %"PRIu64"\n",
                                      mem->b8f_anomaly_pos);
#endif
                            }
                          }
                          mem->b8f_running_ratio += ratio;
                          mem->b8f_running_ratio_sq += ratio * ratio;
                          mem->b8f_ratio_count++;
                        }
                        mem->b8f_block_in_start = input_pos;
                        mem->b8f_block_out_start = mem->b8_total_out;
                      }
                    }
                  }
                }

                /* H6 gate = 3. With MAD validation, correct data passes on
                 * virtually every row, so gate=3 is easily reachable. Wrong
                 * data typically fails MAD quickly, preventing validated
                 * progress from advancing through it. */
                {
                  uint64_t input_pos_gate = mem->curpos - zstrm.avail_in;
                  uint32_t h6_gate = 3;
                  if (mem->consecutive_good_rows >= h6_gate)
                    mem->last_good_filter_pos = input_pos_gate;
                }
              }


            }
            cur_y += cur_yskip;

            if (lace) {
              while (cur_y >= h) {	/* may loop if very short image */
                /*
                    pass  xskip yskip  xoff yoff
                      1     8     8      0    0
                      2     8     8      4    0
                      3     4     8      0    4
                      4     4     4      2    0
                      5     2     4      0    2
                      6     2     2      1    0
                      7     1     2      0    1
                 */
                if (cur_pass >= 7) {
                  mem->zlib_stopped = true;
                  mem->zlib_error = -1;
                  err = Z_STREAM_END;
                  break;
                }
                ++cur_pass;
                if (cur_pass & 1) {	/* beginning an odd pass */
                  cur_yoff = cur_xoff;
                  cur_xoff = 0;
                  cur_xskip >>= 1;
                } else {		/* beginning an even pass */
                  if (cur_pass == 2)
                    cur_xoff = 4;
                  else {
                    cur_xoff = cur_yoff >> 1;
                    cur_yskip >>= 1;
                  }
                  cur_yoff = 0;
                }
                cur_y = cur_yoff;


		if (cur_xskip == 0) {
		  mem->zlib_error = 1;       /* fatal error only for this PNG */
		  break;
		}


                /* effective width is reduced if even pass: subtract cur_xoff */
                cur_width = (w - cur_xoff + cur_xskip - 1) / cur_xskip;
                cur_linebytes = ((cur_width*bitdepth + 7) >> 3) + 1;
                if (cur_linebytes == 1)	/* just the filter byte?  no can do */
                    cur_linebytes = 0;

                /* H6: Reset pixel gradient gate for new interlace pass */
                if (mem->prev_row_pixels) {
                  memset(mem->prev_row_pixels, 0, mem->pixel_row_bytes);
                }
                mem->consecutive_good_rows = 0;
                mem->mad_count = 0;
                mem->running_mad_sum = 0.0;
              }


	      if (mem->zlib_error) {
					   err = Z_STREAM_END;     /* kill middle loop */
		break;                  /* kill "innermost" loop */
	      }


            } else if (cur_y >= h) {
	      mem->zlib_stopped = true;
              mem->zlib_error = -1;		/* kill outermost loop (over chunks) */
              err = Z_STREAM_END;	/* kill middle loop */
              break;			/* kill innermost loop */
            }
          }


	  if (! mem->zlib_error && no_err(kMinorError, mem)) {


          p -= (eod - mem->outbuf);		/* wrap p back into outbuf region */
          zstrm.next_out = mem->outbuf;
          zstrm.avail_out = BS;

          /* get more input (waiting until buffer empties is not necessary best
           * zlib strategy, but simpler than shifting leftover data around) */
          if (zstrm.avail_in == 0 && sz > toread) {
            int data_read;

            /* Record that inflate consumed all input up to curpos.
             * This is the true "inflate frontier" — everything before
             * this point was actually decompressed.  The upcoming
             * mem_fread may read bytes that are NEVER inflated (if EOF
             * interrupts), so curpos after the read would overstate
             * how far inflate got.  The gap check in png_file_validate
             * uses this to avoid false positives on valid truncated data. */
            mem->inflate_consumed_pos = mem->curpos;

            sz -= toread;
            toread = (sz > BS)? BS:sz;
            if ((data_read = mem_fread(mem->buffer, 1, toread, mem)) != toread) {
	      /* EOF: missing blocks at the end — not a validation error.
	       *
	       * B8 EOF: evaluate the FINAL block's compression ratio.
	       * The normal B8 check at block boundaries (line ~1904) only
	       * evaluates the PREVIOUS block — the current (last) block is
	       * never evaluated because there's no next boundary to trigger
	       * B8.  This is why B8 shows 0 rejections: the wrong block is
	       * always at the END of the candidate data.
	       *
	       * Here we compute the ratio for the final partial block.
	       * If it deviates significantly from the running average
	       * (using adaptive variance-based threshold), the block
	       * likely contains foreign data.
	       *
	       * Safety: b8_ratio_count >= 4 ensures we have a meaningful
	       * variance.  b8_anomaly_pos is only used to CAP validates_to
	       * (gated on err > kWarning), so it never fires on complete
	       * valid files. */
	      if (mem->blocksize > 0 && mem->b8_ratio_count >= 2) {
	        uint64_t blk_in  = mem->inflate_consumed_pos - mem->b8_block_in_start;
	        uint64_t blk_out = mem->b8_total_out - mem->b8_block_out_start;
	        if (blk_in > 0 && blk_out > 0) {
	          double ratio = (double)blk_out / (double)blk_in;
	          double avg   = mem->b8_running_ratio / mem->b8_ratio_count;
	          double dev   = ratio - avg;
	          if (dev < 0) dev = -dev;
	          double sd    = 0.0;
	          double b8_thresh = avg * 0.75;  /* floor */
	          if (mem->b8_ratio_count >= 4) {
	            double var = (mem->b8_running_ratio_sq / mem->b8_ratio_count)
	                         - avg * avg;
	            if (var < 0.0) var = 0.0;
	            sd = sqrt(var);
	            double sigma_thresh = sd * 3.0;
	            if (sigma_thresh > b8_thresh)
	              b8_thresh = sigma_thresh;
	          }
	          /* Store normalized suspicion for combined diagnostic */
	          if (avg > 0.0 && b8_thresh > 0.0) {
	            mem->b8_suspicion = dev / b8_thresh;
	            if (mem->b8_suspicion > mem->b8_max_suspicion_since_crc)
	              mem->b8_max_suspicion_since_crc = mem->b8_suspicion;
	          }
	          if (avg > 0.0 && dev > b8_thresh) {
	            mem->b8_anomaly_pos = mem->b8_block_in_start;
	          }
	        }
	      }


	      /* B8f EOF: evaluate final sub-block's compression ratio. */
	      if (mem->b8f_sub_blocksize > 0 && mem->b8f_ratio_count >= 4) {
	        uint64_t sub_in  = mem->inflate_consumed_pos - mem->b8f_block_in_start;
	        uint64_t sub_out = mem->b8_total_out - mem->b8f_block_out_start;
	        if (sub_in > 0 && sub_out > 0) {
	          double ratio = (double)sub_out / (double)sub_in;
	          double avg   = mem->b8f_running_ratio / mem->b8f_ratio_count;
	          double dev   = ratio - avg;
	          if (dev < 0) dev = -dev;
	          double b8f_thresh = avg * 0.75;
	          if (mem->b8f_ratio_count >= 8) {
	            double var = (mem->b8f_running_ratio_sq / mem->b8f_ratio_count)
	                         - avg * avg;
	            if (var < 0.0) var = 0.0;
	            double sigma_thresh = sqrt(var) * 3.0;
	            if (sigma_thresh > b8f_thresh)
	              b8f_thresh = sigma_thresh;
	          }
#if PNG_B8F_DEBUG
	          fprintf(stderr, "B8F-EOF: sub_in=%"PRIu64" sub_out=%"PRIu64
	                  " ratio=%.3f avg=%.3f dev=%.3f thresh=%.3f cnt=%"PRIu64"\n",
	                  sub_in, sub_out, ratio, avg, dev, b8f_thresh,
	                  mem->b8f_ratio_count);
#endif
	          if (avg > 0.0 && dev > b8f_thresh) {
	            if (mem->b8f_anomaly_pos == 0)
	              mem->b8f_anomaly_pos = mem->b8f_block_in_start;
	          }
	        }
	      }

	      /* B9 EOF: evaluate final block's filter distribution.
	       * Same logic as B9 block boundary but for the last block. */
	      if (mem->blocksize > 0 && mem->b9_block_rows >= 4
	          && mem->b9_block_count >= 2) {
	        double cur_frac[5];
	        int fi;
	        for (fi = 0; fi < 5; fi++)
	          cur_frac[fi] = (double)mem->b9_block_filt[fi] / mem->b9_block_rows;
	        double l1 = 0.0;
	        for (fi = 0; fi < 5; fi++) {
	          double avg_fi = mem->b9_running_frac[fi] / mem->b9_block_count;
	          double d = cur_frac[fi] - avg_fi;
	          if (d < 0) d = -d;
	          l1 += d;
	        }
	        double b9_thresh = 1.5;
	        if (mem->b9_block_count >= 4) {
	          double l1_avg = mem->b9_running_l1 / (mem->b9_block_count - 1);
	          double l1_var = (mem->b9_running_l1_sq / (mem->b9_block_count - 1))
	                          - l1_avg * l1_avg;
	          if (l1_var < 0.0) l1_var = 0.0;
	          double sigma_thresh = sqrt(l1_var) * 3.0;
	          if (sigma_thresh > b9_thresh)
	            b9_thresh = sigma_thresh;
	        }
	        if (b9_thresh > 0.0)
	          mem->b9_suspicion = l1 / b9_thresh;
	        if (l1 > b9_thresh) {
	          mem->b9_anomaly_pos = mem->b8_block_in_start;
	        }
	      }

	      /* B10 EOF: evaluate final block's MAD average. */
	      if (mem->blocksize > 0 && mem->b10_block_mad_count >= 2
	          && mem->b10_block_count >= 2) {
	        double blk_avg = mem->b10_block_mad_sum / mem->b10_block_mad_count;
	        double run_avg = mem->b10_running_mad_avg / mem->b10_block_count;
	        double dev = blk_avg - run_avg;
	        if (dev < 0) dev = -dev;
	        double b10_thresh = run_avg * 1.5;
	        if (mem->b10_block_count >= 4) {
	          double var = (mem->b10_running_mad_avg_sq / mem->b10_block_count)
	                       - run_avg * run_avg;
	          if (var < 0.0) var = 0.0;
	          double sigma_thresh = sqrt(var) * 3.0;
	          if (sigma_thresh > b10_thresh)
	            b10_thresh = sigma_thresh;
	        }
	        if (run_avg > 0.0 && b10_thresh > 0.0)
	          mem->b10_suspicion = dev / b10_thresh;
	        if (run_avg > 0.0 && dev > b10_thresh) {
	          mem->b10_anomaly_pos = mem->b8_block_in_start;
	        }
	      }


	      if (data_read == 0) {
	        /* True EOF: no data at all.  Nothing to inflate. */
	        set_err_no_errpos(kCriticalError, mem);
	        return mem->global_error;
	      }
	      /* Partial read: inflate available data for better signal.
	       * For wrong blocks, inflate detects filter/deflate errors
	       * within the partial data.  For correct blocks, lgfp
	       * advances further, improving VT.
	       * Set sz=0 so the inflate loop exits after this buffer. */
	      toread = data_read;
	      sz = 0;
	      /* Fall through to CRC update and inflate processing */
            }
	    { ulg crc_before_refill = crc;
	      crc = update_crc(crc, mem->buffer, toread);
	      /* #5: record CRC checkpoints at block boundaries within this
	       * refill buffer, just like the initial-read and body-drain paths.
	       * Without this, multi-block IDATs have no checkpoints for the
	       * inflate-processed portion, and the #5 CRC-combine search in
	       * png_file_validate() can't locate the bad block. */
	      if (strcmp(chunkid, "IDAT") == 0 && mem->blocksize) {
	        uint64_t prev_pos = mem->curpos - toread;
	        png_ckpt_maybe_record(mem, crc_before_refill,
	                              (const uch *)mem->buffer,
	                              prev_pos, mem->curpos);
	      }
	    }
            zstrm.next_in = mem->buffer;
            zstrm.avail_in = toread;
          }
	  } else {
	    // Guard blocked buffer management (zlib_error or global_error).
	    // Force the decompression loop to exit: without resetting
	    // avail_out and next_out, continuing would spin forever
	    // (inflate returns Z_OK with avail_out==0, never consuming
	    // input, never reaching Z_STREAM_END).
	    if (! mem->zlib_error)
	      mem->zlib_error = 1;
	    err = Z_STREAM_END;
	  }
	}

        /* Update inflate_consumed_pos to reflect where inflate actually
         * stopped.  The refill-path update (avail_in==0 && sz>toread)
         * only fires on successful refills.  If inflate exits due to
         * filter error, Z_STREAM_END, or EOF on the last buffer, it
         * may not have been updated.  curpos - avail_in is the true
         * position of the last byte inflate consumed. */
        mem->inflate_consumed_pos = mem->curpos - zstrm.avail_in;

        /* B8: Evaluate the FINAL inflate block's compression ratio.
         *
         * The B8 check at block boundaries (line ~1918) only evaluates
         * COMPLETED blocks — the current (last) block is never evaluated
         * because there's no next boundary to trigger it.  This is why
         * the wrong block (always at the END of the candidate data)
         * was never caught by B8.
         *
         * This check runs at the INFLATE LOOP EXIT — the point where
         * inflate has consumed all available data (or errored out).
         * It catches:
         *   - Wrong blocks processed via echo (inflate didn't error)
         *   - Wrong blocks that triggered Z_DATA_ERROR
         *   - Normal EOF where the last block was wrong
         *
         * The b8_anomaly_pos flag is used by the VT computation to
         * cap validates_to, preventing overshoot.
         *
         * Only evaluate if we have a meaningful average (>= 2 samples)
         * and blocksize is known. */
        if (mem->blocksize > 0 && mem->b8_ratio_count >= 2) {
          uint64_t blk_in  = mem->inflate_consumed_pos - mem->b8_block_in_start;
          uint64_t blk_out = mem->b8_total_out - mem->b8_block_out_start;
          if (blk_in > 0 && blk_out > 0) {
            double ratio = (double)blk_out / (double)blk_in;
            double avg   = mem->b8_running_ratio / mem->b8_ratio_count;
            double dev   = ratio - avg;
            if (dev < 0) dev = -dev;
            double b8_thresh = avg * 0.75;  /* floor */
            if (mem->b8_ratio_count >= 4) {
              double var = (mem->b8_running_ratio_sq / mem->b8_ratio_count)
                           - avg * avg;
              if (var < 0.0) var = 0.0;
              double sigma_thresh = sqrt(var) * 3.0;
              if (sigma_thresh > b8_thresh)
                b8_thresh = sigma_thresh;
            }
            /* Store normalized suspicion for combined diagnostic */
            if (avg > 0.0 && b8_thresh > 0.0) {
              mem->b8_suspicion = dev / b8_thresh;
              if (mem->b8_suspicion > mem->b8_max_suspicion_since_crc)
                mem->b8_max_suspicion_since_crc = mem->b8_suspicion;
            }
            if (avg > 0.0 && dev > b8_thresh) {
              if (mem->b8_anomaly_pos == 0)
                mem->b8_anomaly_pos = mem->b8_block_in_start;
            }
          }
        }


        /* B8f: post-inflate sub-block ratio check. */
        if (mem->b8f_sub_blocksize > 0 && mem->b8f_ratio_count >= 4) {
          uint64_t sub_in  = mem->inflate_consumed_pos - mem->b8f_block_in_start;
          uint64_t sub_out = mem->b8_total_out - mem->b8f_block_out_start;
          if (sub_in > 0 && sub_out > 0) {
            double ratio = (double)sub_out / (double)sub_in;
            double avg   = mem->b8f_running_ratio / mem->b8f_ratio_count;
            double dev   = ratio - avg;
            if (dev < 0) dev = -dev;
            double b8f_thresh = avg * 0.75;
            if (mem->b8f_ratio_count >= 8) {
              double var = (mem->b8f_running_ratio_sq / mem->b8f_ratio_count)
                           - avg * avg;
              if (var < 0.0) var = 0.0;
              double sigma_thresh = sqrt(var) * 3.0;
              if (sigma_thresh > b8f_thresh)
                b8f_thresh = sigma_thresh;
            }
            if (avg > 0.0 && dev > b8f_thresh) {
              if (mem->b8f_anomaly_pos == 0)
                mem->b8f_anomaly_pos = mem->b8f_block_in_start;
            }
          }
        }

        /* B9: post-inflate filter distribution check (same as B9 EOF). */
        if (mem->blocksize > 0 && mem->b9_block_rows >= 4
            && mem->b9_block_count >= 2) {
          double cur_frac[5];
          int fi;
          for (fi = 0; fi < 5; fi++)
            cur_frac[fi] = (double)mem->b9_block_filt[fi] / mem->b9_block_rows;
          double l1 = 0.0;
          for (fi = 0; fi < 5; fi++) {
            double avg_fi = mem->b9_running_frac[fi] / mem->b9_block_count;
            double d = cur_frac[fi] - avg_fi;
            if (d < 0) d = -d;
            l1 += d;
          }
          double b9_thresh = 1.0;
          if (mem->b9_block_count >= 4) {
            double l1_avg = mem->b9_running_l1 / (mem->b9_block_count - 1);
            double l1_var = (mem->b9_running_l1_sq / (mem->b9_block_count - 1))
                            - l1_avg * l1_avg;
            if (l1_var < 0.0) l1_var = 0.0;
            double sigma_thresh = sqrt(l1_var) * 3.0;
            if (sigma_thresh > b9_thresh)
              b9_thresh = sigma_thresh;
          }
          if (b9_thresh > 0.0)
            mem->b9_suspicion = l1 / b9_thresh;
          if (l1 > b9_thresh) {
            if (mem->b9_anomaly_pos == 0)
              mem->b9_anomaly_pos = mem->b8_block_in_start;
          }
        }

        /* B10: post-inflate per-block MAD check. */
        if (mem->blocksize > 0 && mem->b10_block_mad_count >= 2
            && mem->b10_block_count >= 2) {
          double blk_avg = mem->b10_block_mad_sum / mem->b10_block_mad_count;
          double run_avg = mem->b10_running_mad_avg / mem->b10_block_count;
          double dev = blk_avg - run_avg;
          if (dev < 0) dev = -dev;
          double b10_thresh = run_avg * 1.5;
          if (mem->b10_block_count >= 4) {
            double var = (mem->b10_running_mad_avg_sq / mem->b10_block_count)
                         - run_avg * run_avg;
            if (var < 0.0) var = 0.0;
            double sigma_thresh = sqrt(var) * 3.0;
            if (sigma_thresh > b10_thresh)
              b10_thresh = sigma_thresh;
          }
          if (run_avg > 0.0 && b10_thresh > 0.0)
            mem->b10_suspicion = dev / b10_thresh;
          if (run_avg > 0.0 && dev > b10_thresh) {
            if (mem->b10_anomaly_pos == 0)
              mem->b10_anomaly_pos = mem->b8_block_in_start;
          }
        }


        /* Save local pointer back to struct */
        mem->inflate_out_ptr = p;

        /* D4: Stash unconsumed inflate input before the body-drain loop
         * overwrites mem->buffer.  zstrm.next_in points into mem->buffer
         * at the unconsumed bytes; avail_in tells us how many. */
        if (zstrm.avail_in > 0 && zstrm.next_in) {
          if (!mem->zstrm_leftover || mem->zstrm_leftover_count < zstrm.avail_in) {
            free(mem->zstrm_leftover);
            mem->zstrm_leftover = malloc(zstrm.avail_in);
          if (! mem->zstrm_leftover) { mem->zstrm_leftover_count = 0; }
          }
          if (mem->zstrm_leftover) {
            memcpy(mem->zstrm_leftover, zstrm.next_in, zstrm.avail_in);
            mem->zstrm_leftover_count = zstrm.avail_in;
          } else {
            mem->zstrm_leftover_count = 0;
          }
        } else {
          mem->zstrm_leftover_count = 0;
        }

        #undef cur_y
        #undef cur_pass
        #undef cur_xoff
        #undef cur_yoff
        #undef cur_xskip
        #undef cur_yskip
        #undef cur_width
        #undef cur_linebytes
        #undef numfilt
        #undef numfilt_this_block
        #undef numfilt_total
        #undef numfilt_pass
      }
      if (mem->zlib_error > 0) {  /* our flag, not zlib's (-1 means normal exit) */
        // Three error boundaries are available:
        //   last_good_filter_pos: input position after the last decompressed
        //     row that passed the filter-type check.  Protected by the
        //     dynamic consecutive-valid-rows gate (#4) computed so that
        //     N rows at fixed-Huffman rate exceed one blocksize of input.
        //     P(N consecutive valid by chance) = (5/256)^N, negligible.
        //   error block start: derived from zlib's actual input position at
        //     error time (curpos - avail_in).  Gives the start of the block
        //     containing the error.  This is a defensive cap: if filter_pos
        //     somehow overshot past the error block, we clamp to block start.
        //   last_good_pos: input position at the start of the current IDAT
        //     chunk.  Always safe (set before any chunk data is consumed),
        //     but coarser (~1 IDAT chunk = ~4 blocks for 64K IDAT chunks).
        //
        // Strategy: use last_good_filter_pos directly -- the dynamic
        // N-row gate makes it reliable.  Cap with the error block start as a defensive
        // bound (catches the extremely rare overshoot case).  Only fall back
        // to last_good_pos when no block-level info is available.
        //
        // NOTE: we no longer cap with last_filter_blk_boundary because it
        // lags by one block when RANDOM data causes immediate Z_DATA_ERROR
        // (inflate fails before producing output, so the boundary tracking
        // in the filter loop never advances to the error block).  This
        // caused errpos to be one block too conservative, trimming a correct
        // block and forcing the reassembly engine to re-find it (often
        // picking a wrong block).
        uint64_t safe_pos = mem->last_good_filter_pos;
        if (mem->blocksize > 0) {
          uint64_t error_input_pos = mem->curpos - zstrm.avail_in;
          uint64_t error_blk_start =
            (error_input_pos / mem->blocksize) * mem->blocksize;
          /* The error_blk_start cap already prevents overshoot past the
           * error block.  For the zlib_error path, inflate detected an
           * actual error (bad filter type, bad deflate code), so the
           * error position is precise.  We do NOT snap last_good_filter_pos
           * to its block boundary here because that causes regression when
           * inflate errors immediately on wrong data (lgfp is genuinely in
           * the last correct block, snap-back loses it).  The gap check
           * and CRC-failure paths apply snap-back because they lack the
           * precise error_blk_start signal. */
          if (error_blk_start > 0 && error_blk_start < safe_pos)
            safe_pos = error_blk_start;

          /* CRC-verified cap: zlib's sliding window echo can push BOTH
           * lgfp and error_blk_start well past the actual wrong block —
           * up to one full IDAT chunk (~4 blocks for 64KB IDATs).  The
           * echo copies valid pixels from the window, passing filter and
           * MAD checks, so lgfp advances freely through wrong data.
           *
           * A self-consistent wrong IDAT can pass CRC in a prior loop
           * iteration, polluting last_idat_crc_pos.  When that happens,
           * the inflate error fires in the NEXT IDAT (just past the wrong
           * IDAT's CRC), so error_blk_start ≤ last_idat_crc_pos.
           *
           * When error_blk_start > last_idat_crc_pos, the error is well
           * past the last verified CRC — no self-consistent wrong IDAT
           * could have polluted last.  Use last directly (preserves more
           * correct data, critical for gap-bridging in reassembly).
           *
           * When error_blk_start ≤ last_idat_crc_pos, a prior wrong IDAT
           * may have updated last.  Fall back to min(prev, d4c) to stay
           * behind the pollution. */
          {
            uint64_t crc_cap = 0;
            if (error_blk_start > mem->last_idat_crc_pos) {
              /* Error is past the last CRC — last is not polluted. */
              crc_cap = mem->last_idat_crc_pos;
            } else {
              /* Error is near/before last CRC — possible pollution. */
              crc_cap = mem->last_idat_crc_pos;
              if (mem->prev_idat_crc_pos > 0 &&
                  (crc_cap == 0 || mem->prev_idat_crc_pos < crc_cap))
                crc_cap = mem->prev_idat_crc_pos;
              if (mem->d4_restore_crc_pos > 0 &&
                  (crc_cap == 0 || mem->d4_restore_crc_pos < crc_cap))
                crc_cap = mem->d4_restore_crc_pos;
            }
            if (crc_cap > 0 && safe_pos > crc_cap)
              safe_pos = crc_cap;
          }
        }
        if (mem->last_good_pos > 0 && mem->last_good_pos < safe_pos
            && !(mem->blocksize > 0 && mem->last_filter_blk_boundary > 0))
          safe_pos = mem->last_good_pos;
        /* Use -2 (not -1) to match the convention used by every other error
         * path (IDAT CRC failure, spurious-header detection, EOF fallback,
         * CRC-checkpoint fallback).  When safe_pos bottoms out at
         * last_good_pos, -1 would produce validates_to == best_validates_to
         * + 1, making a wrong block appear to "improve" validation by 1 byte
         * and beating the previous N-block configuration.  -2 guarantees the
         * wrong block ties (at most) with the prior configuration. */
        /* Guard: only set errpos on the FIRST inflate error.
         * Without this guard, the ZLERR handler fires on EVERY
         * subsequent IDAT (zlib_error stays 1, inflate block is
         * skipped).  After later IDATs pass CRC and advance
         * last_idat_crc_pos, the CRC cap no longer fires, and
         * errpos is overwritten with lgfp-2 — which includes
         * echo-advanced data past the wrong block.  The CRCFAIL
         * handler has this same guard (errpos_is_precise). */
        if (!mem->errpos_is_precise) {
          mem->errpos = (safe_pos > 1) ? (int64_t)(safe_pos - 2) : 0;
          mem->errpos_is_precise = true;  /* sub-chunk boundary from zlib/filter path */
        }
        set_err_no_errpos(kMajorError, mem);
      }
      last_is_IDAT = 1;
      just_seen_fcTL = 0;

    /*------*
     | IEND |
     *------*/
    } else if (strcmp(chunkid, "IEND") == 0) {
      if (have_IEND) {
        set_err(kMinorError, mem);
      } else if (sz != 0) {
        set_err(kMinorError, mem);
      } else if (have_IDAT <= 0) {
        set_err(kMajorError, mem);
      } else if (have_IDAT < 10) {
        set_err(kWarning, mem);
      }
      have_IEND = 1;
      mem->have_iend = true;
      last_is_IDAT = 0;

    /*------*
     | bKGD |
     *------*/
    } else if (strcmp(chunkid, "bKGD") == 0) {
      if (have_bKGD) {
        set_err(kMinorError, mem);
      } else if (have_IDAT) {
        set_err(kMinorError, mem);
      }
      switch (ityp) {
        case 0:
        case 4:
          if (sz != 2) {
            set_err(kMajorError, mem);
          }
          break;
        case 1: /* fallthrough: treat as 16-bit RGBA */
        case 2:
        case 6:
          if (sz != 6) {
            set_err(kMajorError, mem);
          }
          break;
        case 3:
          if (sz != 1) {
            set_err(kMajorError, mem);
          } else if (mem->buffer[0] >= nplte) {
            set_err(kMajorError, mem);
          }
          break;
      }
      have_bKGD = 1;
      last_is_IDAT = 0;

    /*------*
     | cHRM |
     *------*/
    } else if (strcmp(chunkid, "cHRM") == 0) {
      if (have_cHRM) {
        set_err(kMinorError, mem);
      } else if (have_PLTE) {
        set_err(kMinorError, mem);
      } else if (have_IDAT) {
        set_err(kMinorError, mem);
      } else if (sz != 32) {
        set_err(kMajorError, mem);
      }
      if (no_err(kMinorError, mem)) {
        double wx, wy, rx, ry, gx, gy, bx, by;

        wx = (double)SLG(mem->buffer)/100000;
        wy = (double)SLG(mem->buffer+4)/100000;
        rx = (double)SLG(mem->buffer+8)/100000;
        ry = (double)SLG(mem->buffer+12)/100000;
        gx = (double)SLG(mem->buffer+16)/100000;
        gy = (double)SLG(mem->buffer+20)/100000;
        bx = (double)SLG(mem->buffer+24)/100000;
        by = (double)SLG(mem->buffer+28)/100000;

        if (wx < 0 || wx > 0.8 || wy < 0 || wy > 0.8 || wx + wy > 1.0) {
          set_err(kMinorError, mem);
        } else if (rx < 0 || rx > 0.8 || ry < 0 || ry > 0.8 || rx + ry > 1.0) {
          set_err(kMinorError, mem);
        } else if (gx < 0 || gx > 0.8 || gy < 0 || gy > 0.8 || gx + gy > 1.0) {
          set_err(kMinorError, mem);
        } else if (bx < 0 || bx > 0.8 || by < 0 || by > 0.8 || bx + by > 1.0) {
          set_err(kMinorError, mem);
        }
      }
      have_cHRM = 1;
      last_is_IDAT = 0;

    /*------*
     | eXIf |
     *------*/
    } else if (strcmp(chunkid, "eXIf") == 0) {
      if (have_eXIf) {
        set_err(kMinorError, mem);
      } else if (have_IDAT) {
        set_err(kMinorError, mem);
      }
      have_eXIf = 1;
      last_is_IDAT = 0;

    /*------*
     | fRAc |
     *------*/
    } else if (strcmp(chunkid, "fRAc") == 0) {

    /*------*
     | gAMA |
     *------*/
    } else if (strcmp(chunkid, "gAMA") == 0) {
      if (have_gAMA) {
        set_err(kMinorError, mem);
      } else if (have_IDAT) {
        set_err(kMinorError, mem);
      } else if (have_PLTE) {
        set_err(kMinorError, mem);
      } else if (sz != 4) {
        set_err(kMajorError, mem);
      } else if (LG(mem->buffer) == 0) {
        set_err(kMinorError, mem);
      }
      have_gAMA = 1;
      last_is_IDAT = 0;

    /*------*
     | gIFg |
     *------*/
    } else if (strcmp(chunkid, "gIFg") == 0) {
      if (sz != 4) {
        set_err(kMajorError, mem);
      }
      last_is_IDAT = 0;

    /*------*
     | gIFt |
     *------*/
    } else if (strcmp(chunkid, "gIFt") == 0) {
      set_err(kMinorError, mem);
      if (sz < 24) {
        set_err(kMajorError, mem);
      }
      last_is_IDAT = 0;

    /*------*
     | gIFx |
     *------*/
    } else if (strcmp(chunkid, "gIFx") == 0) {
      if (sz < 11) {
        set_err(kMajorError, mem);
      }
      last_is_IDAT = 0;

    /*------*
     | hIST |
     *------*/
    } else if (strcmp(chunkid, "hIST") == 0) {
      if (sz > BS) {
        set_err(kMinorError, mem);
      }
      have_hIST = 1;
      last_is_IDAT = 0;

    /*------*
     | iCCP |
     *------*/
    } else if (strcmp(chunkid, "iCCP") == 0) {
      int name_len;

      if (have_iCCP) {
        set_err(kMinorError, mem);
      } else if (have_sRGB) {
        set_err(kMinorError, mem);
      } else if (have_PLTE) {
        set_err(kMinorError, mem);
      } else if (have_IDAT) {
        set_err(kMinorError, mem);
      } else if (check_keyword(mem, mem->buffer, toread, &name_len, "profile name",
                               chunkid)) {
        set_err(kMinorError, mem);
      } else {
        int remainder = toread - name_len - 3;
        uch compr = mem->buffer[name_len+1];

        if (remainder < 0) {
          set_err(kMajorError, mem);
        } else if (mem->buffer[name_len] != 0) {
          set_err(kMajorError, mem);
        } else if (compr > 0 && compr < 128) {
          set_err(kMinorError, mem);
        } else if (compr >= 128) {
          set_err(kWarning, mem);
        }
        if (no_err(kMinorError, mem)) {
          init_printbuf_state(&prbuf_state);
          print_buffer(&prbuf_state, mem->buffer, name_len, 0);
          report_printbuf(mem, &prbuf_state, chunkid);
        }
      }
      have_iCCP = 1;
      last_is_IDAT = 0;

    /*------*
     | iTXt |
     *------*/
    } else if (strcmp(chunkid, "iTXt") == 0) {
      int keylen;

      if (check_keyword(mem, mem->buffer, toread, &keylen, "keyword", chunkid))
        set_err(kMinorError, mem);
      else {
        int compressed = 0, compr = 0;

        init_printbuf_state(&prbuf_state);

        compressed = mem->buffer[keylen+1];
        if (compressed < 0 || compressed > 1) {
          set_err(kMinorError, mem);
        } else if ((compr = (uch)mem->buffer[keylen+2]) > 127) {
          set_err(kWarning, mem);
        } else if (compr > 0) {
          set_err(kMinorError, mem);
        }
        if (no_err(kMinorError, mem)) {
          (void)keywordlen((mem->buffer)+keylen+3, toread-keylen-3);
        }
        report_printbuf(mem, &prbuf_state, chunkid);   /* print CR/LF & NULLs info */
      }
      last_is_IDAT = 0;

    /*------*
     | oFFs |
     *------*/
    } else if (strcmp(chunkid, "oFFs") == 0) {
      if (have_oFFs) {
        set_err(kMinorError, mem);
      } else if (have_IDAT) {
        set_err(kMinorError, mem);
      } else if (sz != 9) {
        set_err(kMinorError, mem);
      } else if (mem->buffer[8] > 1) {
        set_err(kMinorError, mem);
      }
      have_oFFs = 1;
      last_is_IDAT = 0;

    /*------*
     | pCAL |
     *------*/
    } else if (strcmp(chunkid, "pCAL") == 0) {
      if (no_err(kMinorError, mem)) {
        int name_len;

        if (check_keyword(mem, mem->buffer, toread, &name_len, "calibration name",
                          chunkid))
          set_err(kMinorError, mem);
        else if (sz < name_len + 15) {
          set_err(kMajorError, mem);
        } else {
          int eqn_num = mem->buffer[name_len+9];
          int num_params = mem->buffer[name_len+10];

          if (eqn_num < 0 || eqn_num > 3) {
            set_err(kMinorError, mem);
          } else if (num_params != eqn_params[eqn_num]) {
            set_err(kMinorError, mem);
          } else {
            int remainder = 0;
            uch *pbuf;

            init_printbuf_state(&prbuf_state);
            print_buffer(&prbuf_state, mem->buffer, name_len, 0);
            report_printbuf(mem, &prbuf_state, chunkid);
            if (toread == sz)
              remainder = toread - name_len - 11;
            pbuf = mem->buffer + name_len + 11;
            if (*pbuf != 0) {
              int unit_len = keywordlen(pbuf, remainder);

              init_printbuf_state(&prbuf_state);
              print_buffer(&prbuf_state, pbuf, unit_len, 0);
              report_printbuf(mem, &prbuf_state, chunkid);
              pbuf += unit_len;
              remainder -= unit_len;
            }
            for (i = 0;  i < num_params;  ++i) {
              int len;

              if (remainder < 2) {
                set_err(kMajorError, mem);
                break;
              }
              if (*pbuf != 0) {
                set_err(kMinorError, mem);
                break;
              }
              ++pbuf;
              --remainder;
              len = keywordlen(pbuf, remainder);
              init_printbuf_state(&prbuf_state);
              print_buffer(&prbuf_state, pbuf, len, 0);
              report_printbuf(mem, &prbuf_state, chunkid);
              pbuf += len;
              remainder -= len;
            }
          }
        }
      }
      have_pCAL = 1;
      last_is_IDAT = 0;

    /*------*
     | pHYs |
     *------*/
    } else if (strcmp(chunkid, "pHYs") == 0) {
      if (have_pHYs) {
        set_err(kMinorError, mem);
      } else if (have_IDAT) {
        set_err(kMinorError, mem);
      } else if (sz != 9) {
        set_err(kMajorError, mem);
      } else if (mem->buffer[8] > 1) {
        set_err(kMinorError, mem);
      }
      have_pHYs = 1;
      last_is_IDAT = 0;

    /*------*
     | sBIT |
     *------*/
    } else if (strcmp(chunkid, "sBIT") == 0) {
      int maxbits = (ityp == 3)? 8 : sampledepth;

      switch (ityp) {
        case 0:
          if (sz != 1) {
            set_err(kMajorError, mem);
          } else if (mem->buffer[0] == 0 || mem->buffer[0] > maxbits) {
            set_err(kMinorError, mem);
          }
          break;
        case 2:
        case 3:
          if (sz != 3) {
            set_err(kMajorError, mem);
          } else if (mem->buffer[0] == 0 || mem->buffer[0] > maxbits) {
            set_err(kMinorError, mem);
          } else if (mem->buffer[1] == 0 || mem->buffer[1] > maxbits) {
            set_err(kMinorError, mem);
          } else if (mem->buffer[2] == 0 || mem->buffer[2] > maxbits) {
            set_err(kMinorError, mem);
          }
          break;
        case 4:
          if (sz != 2) {
            set_err(kMajorError, mem);
          } else if (mem->buffer[0] == 0 || mem->buffer[0] > maxbits) {
            set_err(kMajorError, mem);
          } else if (mem->buffer[1] == 0 || mem->buffer[1] > maxbits) {
            set_err(kMajorError, mem);
          }
          break;
        case 6:
          if (sz != 4) {
            set_err(kMajorError, mem);
          } else if (mem->buffer[0] == 0 || mem->buffer[0] > maxbits) {
            set_err(kMinorError, mem);
          } else if (mem->buffer[1] == 0 || mem->buffer[1] > maxbits) {
            set_err(kMinorError, mem);
          } else if (mem->buffer[2] == 0 || mem->buffer[2] > maxbits) {
            set_err(kMinorError, mem);
          } else if (mem->buffer[3] == 0 || mem->buffer[3] > maxbits) {
            set_err(kMinorError, mem);
          }
          break;
      }
      have_sBIT = 1;
      last_is_IDAT = 0;

    /*------*
     | sCAL |
     *------*/
    } else if (strcmp(chunkid, "sCAL") == 0) {
      int unittype = mem->buffer[0];
      uch *pPixwidth = mem->buffer+1, *pPixheight=NULL;

      if (have_sCAL) {
        set_err(kMinorError, mem);
      } else if (have_IDAT) {
        set_err(kMinorError, mem);
      } else if (sz < 4) {
        set_err(kMinorError, mem);
      } else if (sz > BS) {
        set_err(kMinorError, mem);
      } else if (unittype < 1 || unittype > 2) {
        set_err(kMinorError, mem);
      } else {
        uch *qq;
        for (qq = pPixwidth;  qq < mem->buffer+sz;  ++qq) {
          if (*qq == 0)
            break;
        }
        if (qq == mem->buffer+sz) {
          set_err(kMinorError, mem);
        } else {
          pPixheight = qq + 1;
          if (pPixheight == mem->buffer+sz || *pPixheight == 0) {
            set_err(kMinorError, mem);
          }
        }
        if (no_err(kMinorError, mem)) {
          if (pPixheight == NULL) {
            /* missing pixel height, but -f was given */
            pPixheight = mem->buffer+sz;
	  }
          for (qq = pPixheight;  qq < mem->buffer+sz;  ++qq) {
            if (*qq == 0)
              break;
          }
          if (qq != mem->buffer+sz) {
            set_err(kWarning, mem);
          }
          if (*pPixwidth == '-' ||
	      (pPixheight != mem->buffer+sz && *pPixheight == '-')) {
            set_err(kMinorError, mem);
          } else if (check_ascii_float(mem, pPixwidth, pPixheight-pPixwidth-1,
                                       chunkid) ||
                     check_ascii_float(mem, pPixheight, mem->buffer+sz-pPixheight,
                                       chunkid))
          {
            set_err(kMinorError, mem);
          }
        }
      }
      have_sCAL = 1;
      last_is_IDAT = 0;

    /*------*
     | sPLT |
     *------*/
    } else if (strcmp(chunkid, "sPLT") == 0) {
      int name_len;

      if (have_IDAT) {
        set_err(kMinorError, mem);
      } else if (check_keyword(mem, mem->buffer, toread, &name_len, "palette name",
                               chunkid)) {
        set_err(kMinorError, mem);
      } else {
        uch bps = (unsigned char)mem->buffer[name_len+1];
        int remainder = toread - name_len - 2;
        int bytes = (bps >> 3);
        int entry_sz = 4*bytes + 2;

        if (remainder < 0) {
          set_err(kMajorError, mem);
        } else if (mem->buffer[name_len] != 0) {
          set_err(kMinorError, mem);
        } else if (bps != 8 && bps != 16) {
          set_err(kMinorError, mem);
        } else if (remainder % entry_sz != 0) {
          set_err(kMajorError, mem);
        }
      }
      last_is_IDAT = 0;

    /*------*
     | sRGB |
     *------*/
    } else if (strcmp(chunkid, "sRGB") == 0) {
      if (have_sRGB) {
        set_err(kMinorError, mem);
      } else if (have_iCCP) {
        set_err(kMinorError, mem);
      } else if (have_PLTE) {
        set_err(kMinorError, mem);
      } else if (have_IDAT) {
        set_err(kMinorError, mem);
      } else if (sz != 1) {
        set_err(kMinorError, mem);
      } else if (mem->buffer[0] > 3) {
        set_err(kMinorError, mem);
      }
      have_sRGB = 1;
      last_is_IDAT = 0;

    /*------*
     | sTER |
     *------*/
    } else if (strcmp(chunkid, "sTER") == 0) {
      if (have_sTER) {
        set_err(kMinorError, mem);
      } else if (have_IDAT) {
        set_err(kMinorError, mem);
      } else if (sz != 1) {
        set_err(kMinorError, mem);
      } else if (mem->buffer[0] > 1) {
        set_err(kMinorError, mem);
      }
      have_sTER = 1;
      last_is_IDAT = 0;

    /*------*  *------*
     | tEXt |  | zTXt |
     *------*  *------*/
    } else if (strcmp(chunkid, "tEXt") == 0 || strcmp(chunkid, "zTXt") == 0) {
      int ztxt = (chunkid[0] == 'z');
      int keylen;

      if (check_keyword(mem, mem->buffer, toread, &keylen, "keyword", chunkid))
        set_err(kMinorError, mem);
      else if (ztxt) {
        int compr = (uch)mem->buffer[keylen+1];
        if (compr > 127) {
          set_err(kWarning, mem);
        } else if (compr > 0) {
          set_err(kMinorError, mem);
        }
      }
      else if (check_text(mem, mem->buffer + keylen + 1, toread - keylen - 1, chunkid)) {
        set_err(kMinorError, mem);
      }
      last_is_IDAT = 0;

    /*------*
     | tIME |
     *------*/
    } else if (strcmp(chunkid, "tIME") == 0) {
      if (have_tIME) {
        set_err(kMinorError, mem);
      } else if (sz != 7) {
        set_err(kMinorError, mem);
      } else {
        int yr = SH(mem->buffer);
        int mo = mem->buffer[2];
        int dy = mem->buffer[3];
        int hh = mem->buffer[4];
        int mm = mem->buffer[5];
        int ss = mem->buffer[6];

        /* zero-based; tIME month is 1-based */
        int daysInMonth[12] = {31,28,31,30,31,30,31,31,30,31,30,31};

        /* leap year check */
        if (mo == 2) {
          if (yr % 400 == 0)
            daysInMonth[1] = 29;
          else if (yr % 100 != 0 && yr % 4 == 0)
            daysInMonth[1] = 29;
        }

        if (yr < 1995) {
          /* conversion to PNG format counts as modification... */
          set_err(kMinorError, mem);
        } else if (mo < 1 || mo > 12) {
          set_err(kMinorError, mem);
        } else if (dy < 1 || dy > daysInMonth[mo - 1]) {
          set_err(kMinorError, mem);
        } else if (hh < 0 || hh > 23) {
          set_err(kMinorError, mem);
        } else if (mm < 0 || mm > 59) {
          set_err(kMinorError, mem);
        } else if (ss < 0 || ss > 60) {
          set_err(kMinorError, mem);
        }
      }
      have_tIME = 1;
      last_is_IDAT = 0;

    /*------*
     | tRNS |
     *------*/
    } else if (strcmp(chunkid, "tRNS") == 0) {
      if (no_err(kMinorError, mem)) {
        switch (ityp) {
          case 0:
            if (sz != 2) {
              set_err(kMajorError, mem);
            }
            break;
          case 2:
            if (sz != 6) {
              set_err(kMajorError, mem);
            }
            break;
          case 3:
            if (sz > nplte) {
              set_err(kMajorError, mem);
            }
            break;
          default:
            set_err(kMinorError, mem);
            break;
        }
      }
      have_tRNS = 1;
      last_is_IDAT = 0;

    /*===========================================*/
    /* APNG chunks (PNG Extensions)             */

    /*------*
     | acTL |
     *------*/
    } else if (strcmp(chunkid, "acTL") == 0) {
      if (have_IDAT) {
        set_err(kMinorError, mem);
      } else if (have_acTL) {
        set_err(kMinorError, mem);
      } else if (sz != 8) {
        set_err(kMinorError, mem);
      }
      if (no_err(kMinorError, mem)) {
        num_frames = LG(mem->buffer);
        num_plays  = LG(mem->buffer+4);
        if (num_frames == 0) {
          set_err(kMinorError, mem);
        }
      }
      have_acTL = 1;
      last_is_IDAT = 0;

    /*------*
     | fcTL |
     *------*/
    } else if (strcmp(chunkid, "fcTL") == 0) {
      if (sz != 26) {
        set_err(kMinorError, mem);
      }
      if (no_err(kMinorError, mem)) {
        sequence_number = LG(mem->buffer);
        frame_width     = LG(mem->buffer+4);
        frame_height    = LG(mem->buffer+8);
        x_offset        = LG(mem->buffer+12);
        y_offset        = LG(mem->buffer+16);
        delay_num       = SH(mem->buffer+20);
        delay_den       = SH(mem->buffer+22);
        dispose_op      = mem->buffer[24];
        blend_op        = mem->buffer[25];
      }
      /* first frame is IDAT checks */
      if (!have_fcTL && !have_IDAT) {
        if (x_offset > 0 || y_offset > 0) {
          set_err(kMinorError, mem);
        }
        if (frame_height != (ulg)h || frame_width != (ulg)w) {
          set_err(kMinorError, mem);
        }
      }
      /* missing fdAT check */
      if (just_seen_fcTL) {
        set_err(kMinorError, mem);
      }
      /* sequence numbers */
      if (!have_fcTL && sequence_number != 0) {
        set_err(kMinorError, mem);
      } else if (have_fcTL && sequence_number != next_sequence_number) {
        set_err(kMinorError, mem);
      } else {
        next_sequence_number++;
      }
      if (frame_width == 0 || frame_height == 0) {
        set_err(kMinorError, mem);
      }
      if (frame_width + x_offset > (ulg)w || frame_height + y_offset > (ulg)h) {
        set_err(kMinorError, mem);
      }
      if (delay_den == 0) delay_den = 100;
      if (dispose_op > 2) {
        set_err(kMinorError, mem);
      }
      if (blend_op > 1) {
        set_err(kMinorError, mem);
      }
      have_fcTL = 1;
      just_seen_fcTL = 1;
      num_fcTL++;
      last_is_IDAT = 0;

    /*------*
     | fdAT |
     *------*/
    } else if (strcmp(chunkid, "fdAT") == 0) {
      if (sz < 4) {
        set_err(kMinorError, mem);
      }
      if (no_err(kMinorError, mem)) {
        sequence_number = LG(mem->buffer);
        if (sequence_number != next_sequence_number) {
          set_err(kMinorError, mem);
        } else {
          next_sequence_number++;
        }
      }
      just_seen_fcTL = 0;
      last_is_IDAT = 0;

    /*------*
     | iDOT |
     *------*/
    } else if (strcmp(chunkid, "iDOT") == 0) {
      if (have_iDOT) {
        set_err(kMinorError, mem);
      } else if (have_IDAT) {
        set_err(kMinorError, mem);
      } else if (sz < 16) {
        set_err(kMinorError, mem);
      } else {
        long segments = LG(mem->buffer);
        if ((ulg)sz != (ulg)(4 + segments * 12)) {
          set_err(kMinorError, mem);
        }
      }
      have_iDOT = 1;
      last_is_IDAT = 0;

    /*===========================================*/
    /* PNG Third Edition new chunks              */

    /*------*
     | cICP |
     *------*/
    } else if (strcmp(chunkid, "cICP") == 0) {
      if (have_cICP) {
        set_err(kMinorError, mem);
      } else if (have_PLTE) {
        set_err(kMinorError, mem);
      } else if (have_IDAT) {
        set_err(kMinorError, mem);
      } else if (sz != 4) {
        set_err(kMajorError, mem);
      }
      if (no_err(kMinorError, mem)) {
        /* buffer[2] = matrix coefficients, must be 0 for RGB */
        uch fullrange = mem->buffer[3];
        if (mem->buffer[2] > 0) {
          set_err(kMinorError, mem);
        } else if (fullrange > 1) {
          set_err(kMinorError, mem);
          /* print human-readable color space name */
        }
      }
      have_cICP = 1;
      last_is_IDAT = 0;

    /*------*
     | mDCV |
     *------*/
    } else if (strcmp(chunkid, "mDCV") == 0) {
      if (have_mDCV) {
        set_err(kMinorError, mem);
      } else if (have_PLTE) {
        set_err(kMinorError, mem);
      } else if (have_IDAT) {
        set_err(kMinorError, mem);
      } else if (sz != 24) {
        set_err(kMajorError, mem);
      }
      if (no_err(kMinorError, mem)) {
        double rx = (double)SH(mem->buffer)/50000;
        double ry = (double)SH(mem->buffer+2)/50000;
        double gx = (double)SH(mem->buffer+4)/50000;
        double gy = (double)SH(mem->buffer+6)/50000;
        double bx = (double)SH(mem->buffer+8)/50000;
        double by = (double)SH(mem->buffer+10)/50000;
        double wx = (double)SH(mem->buffer+12)/50000;
        double wy = (double)SH(mem->buffer+14)/50000;
        double maxlum = (double)LG(mem->buffer+16)/10000;
        double minlum = (double)LG(mem->buffer+20)/10000;
        if (wx < 0 || wx > 0.8 || wy < 0 || wy > 0.8 || wx + wy > 1.0) {
          set_err(kMinorError, mem);
        } else if (rx < 0 || rx > 0.8 || ry < 0 || ry > 0.8 || rx + ry > 1.0) {
          set_err(kMinorError, mem);
        } else if (gx < 0 || gx > 0.8 || gy < 0 || gy > 0.8 || gx + gy > 1.0) {
          set_err(kMinorError, mem);
        } else if (bx < 0 || bx > 0.8 || by < 0 || by > 0.8 || bx + by > 1.0) {
          set_err(kMinorError, mem);
        } else if (maxlum > 10000) {
          set_err(kMinorError, mem);
        } else if (minlum > 10) {
          set_err(kMinorError, mem);
        }
      }
      have_mDCV = 1;
      last_is_IDAT = 0;

    /*------*
     | cLLI |
     *------*/
    } else if (strcmp(chunkid, "cLLI") == 0) {
      if (have_cLLI) {
        set_err(kMinorError, mem);
      } else if (have_PLTE) {
        set_err(kMinorError, mem);
      } else if (have_IDAT) {
        set_err(kMinorError, mem);
      } else if (sz != 8) {
        set_err(kMajorError, mem);
      }
      if (no_err(kMinorError, mem)) {
        ulg cll  = LG(mem->buffer);
        double maxCLL  = (double)cll/10000;
        if (maxCLL > 10000) {
          set_err(kMinorError, mem);
        }
      }
      have_cLLI = 1;
      last_is_IDAT = 0;

    /*------*
     | caBX |
     *------*/
    } else if (strcmp(chunkid, "caBX") == 0) {
      if (have_IDAT) {
        set_err(kMinorError, mem);
      }
      have_caBX = 1;
      last_is_IDAT = 0;

    /*------*
     | cLLi |  (old lowercase spelling — rejected)
     *------*/
    } else if (strcmp(chunkid, "cLLi") == 0) {
      last_is_IDAT = 0;

    /*------*
     | mDCv |  (old lowercase spelling — rejected)
     *------*/
    } else if (strcmp(chunkid, "mDCv") == 0) {
      last_is_IDAT = 0;

    /*===========================================*/
    /* identifiable private chunks; guts unknown */

    /*------*
     | cmOD |
     *------*/
    } else if (strcmp(chunkid, "cmOD") == 0) {

    /*------*
     | cmPP |   (guessing MS)
     *------*/
    } else if (strcmp(chunkid, "cmPP") == 0) {

    /*------*
     | cpIp |
     *------*/
    } else if (strcmp(chunkid, "cpIp") == 0) {

    /*------*
     | mkBF |
     *------*/
    } else if (strcmp(chunkid, "mkBF") == 0) {

    /*------*
     | mkBS |
     *------*/
    } else if (strcmp(chunkid, "mkBS") == 0) {

    /*------*
     | mkBT |
     *------*/
    } else if (strcmp(chunkid, "mkBT") == 0) {

    /*------*
     | mkTS |
     *------*/
    } else if (strcmp(chunkid, "mkTS") == 0) {

    /* msOG - Microsoft?  Macromedia? */

    /*------*
     | pcLb |
     *------*/
    } else if (strcmp(chunkid, "pcLb") == 0) {

    /*------*
     | prVW |
     *------*/
    } else if (strcmp(chunkid, "prVW") == 0) {

    /*------*
     | spAL |  intermediate sPLT test version (still had gamma field)
     *------*/
    } else if (strcmp(chunkid, "spAL") == 0) {
      /* png-group/documents/history/png-proposed-sPLT-19961015.html */

    /*===============*
     * unknown chunk *
     *===============*/

    } else {
      if (CRITICAL(chunkid) && SAFECOPY(chunkid)) {
        /* a critical, safe-to-copy chunk is an error */
        set_err(kMajorError, mem);
      } else if (RESERVED(chunkid)) {
        /* a chunk with the reserved bit set is an error (or spec updated) */
        set_err(kMajorError, mem);
      } else if (PUBLIC(chunkid)) {
        /* All registered public PNG chunks are known; unknown public = invalid */
        set_err(kMajorError, mem);
      } else if (CRITICAL(chunkid)) {
        /* Private critical chunks: warning per PNG spec */
        set_err(kWarning, mem);
      }
      last_is_IDAT = 0;
    }

    /*=======================================================================*/

    if (no_err(kMinorError, mem)) {
      while (sz > toread) {
        int data_read;
        sz -= toread;
        toread = (sz > BS)? BS:sz;

        data_read = mem_fread(mem->buffer, 1, toread, mem);

        if (data_read != toread) {
	  /* EOF: missing blocks at the end — not a validation error */
	  set_err_no_errpos(kCriticalError, mem);
          return mem->global_error;
        }
        { ulg crc_before = crc;
          crc = update_crc(crc, (uch *)mem->buffer, toread);
          /* #5: checkpoint running CRC at block boundaries within IDAT.
           * Pass crc_before so the function can compute the exact boundary CRC. */
          if (strcmp(chunkid, "IDAT") == 0 && mem->blocksize) {
            uint64_t prev_pos = mem->curpos - toread;
            png_ckpt_maybe_record(mem, crc_before, (const uch *)mem->buffer,
                                  prev_pos, mem->curpos);
          }
        }

        /* #2: At each block boundary inside a chunk body, verify the bytes
         * at that position don't look like a spurious PNG chunk header.
         * If they do, a wrong block almost certainly starts here. */
        if (mem->blocksize && strcmp(chunkid, "IDAT") != 0) {
          uint64_t bs = mem->blocksize;
          uint64_t prev_pos = mem->curpos - toread;
          uint64_t first_bdy = (prev_pos / bs + 1) * bs;
          for (uint64_t bdy = first_bdy; bdy < mem->curpos; bdy += bs) {
            /* We need 8 bytes: 4-byte length + 4-byte type.
             * Only check if we have data at this position. */
            if (bdy + 8 <= mem->length) {
              const unsigned char *bp = (const unsigned char *)mem->data + bdy;
              unsigned long probe_len = ((ulg)bp[0]<<24)|((ulg)bp[1]<<16)|
                                        ((ulg)bp[2]<<8)|(ulg)bp[3];
              /* Valid chunk type: all 4 bytes are printable ASCII letters [A-Za-z] */
              /* Match only known chunk names — arbitrary 4-letter sequences
               * appear too often in compressed data to be reliable. */
              int looks_like_header =
                (probe_len <= 0x7fffffffUL) &&
                png_is_known_chunk(bp + 4);
              /* We are inside a chunk body, NOT at a chunk boundary.
               * Spurious chunk header = structural corruption starts here. */
              if (looks_like_header) {
                if (!mem->errpos_is_precise) {
                  mem->errpos = (bdy > 1) ? (int64_t)(bdy - 2) : 0;
                }
                set_err_no_errpos(kMajorError, mem);
                return mem->global_error;
              }
            }
          }
        }
      }

      filecrc = getlong(mem, "CRC value");

      if (is_err(kMajorError, mem))
        return mem->global_error;

      /* #5: save the stored CRC before the check so png_file_validate()
       * can use crc32_combine() on the checkpoints to locate the bad block */
      if (strcmp(chunkid, "IDAT") == 0 && mem->blocksize)
        mem->idat_stored_crc = filecrc;

      if (filecrc != CRCCOMPL(crc)) {
        if (strcmp(chunkid, "IDAT") == 0 && mem->last_good_pos > 1) {
          // IDAT CRC failure: need to set errpos as precisely as possible.
          //
          // If the zlib/filter path already set a precise errpos
          // (errpos_is_precise == true), keep it -- that path has
          // sub-chunk block-level precision.
          //
          // Otherwise, try to use last_good_filter_pos for sub-chunk
          // precision.  This is critical for IDAT-boundary corruption:
          // when a RANDOM block falls at the boundary between two IDATs,
          // only a few bytes of the IDAT body are corrupted (the tail
          // end).  Those few RANDOM bytes are often too short to trigger
          // Z_DATA_ERROR in inflate, so the zlib_error path never fires.
          // The CRC catches the corruption, but falling back to
          // last_good_pos - 2 (start of the IDAT chunk) loses ALL blocks
          // within the IDAT (~4 blocks for 64KB IDATs).  Using
          // last_good_filter_pos instead preserves the blocks that were
          // fully validated by inflate + filter checking.
          //
          // Cap with the block containing the failed CRC: the CRC bytes
          // (and the last few body bytes in the same block) are known-bad.
          // This prevents overshoot when wrong data from another PNG
          // decompresses to valid-looking filter rows, pushing
          // last_good_filter_pos past the actual corruption boundary.
          //
          // Fallback: last_good_pos - 2 when inflate wasn't active
          // (no last_good_filter_pos data available).
          if (!mem->errpos_is_precise) {
            /* Use prev_idat_crc_pos: the IDAT CRC position TWO IDATs back.
             *
             * A self-consistent wrong IDAT (another PNG's body+CRC) passes
             * CRC, polluting last_idat_crc_pos with the wrong IDAT's
             * position.  prev_idat_crc_pos is one IDAT further back.
             * d4_restore_crc_pos provides additional fallback.
             *
             * Ring buffer backstop for echo cases (zlib_error == 0):
             * When inflate didn't error, wrong data decompressed via
             * echo (LZ77 backreferences into the sliding window).
             * Echo implies 2+ wrong IDATs passed CRC, polluting BOTH
             * last and prev.  ring_back3 goes 3 IDATs back — past the
             * pollution.  When inflate DID error (zlib_error > 0), the
             * error happened in the first wrong IDAT, so at most 1
             * wrong IDAT passed CRC and prev is still clean. */
            /* Use last_idat_crc_pos as the primary safe position.
             *
             * Rationale: this handler fires when a CRC check FAILS.
             * At this point, the current IDAT's CRC has NOT passed,
             * so last_idat_crc_pos still points to the CRC of the
             * PRECEDING IDAT — before the corruption.  Using last
             * preserves the maximum amount of validated data.
             *
             * The original min(d4c, prev) approach was designed to
             * handle self-consistent wrong IDATs (from the same PNG)
             * that pass CRC and pollute last.  However:
             *   - When zlib_error > 0 (inflate errored): the inflate
             *     error handler already set errpos_is_precise, so this
             *     code is SKIPPED (line 3631 guard).
             *   - When zlib_error == -1 (Z_STREAM_END): last is from
             *     a correct IDAT (no inflate to detect wrong blocks,
             *     but CRC is the only validation available).
             *   - When zlib_error == 0 (echo): both last and prev may
             *     be polluted (echo implies 2+ wrong IDATs).  Neither
             *     is reliable; the ring backstop was designed for this
             *     but is disabled.  Using last loses at most 1 wrong
             *     block (same as prev in practice) while preserving
             *     correct data critical for gap-bridging.
             *
             * Do NOT cap with d4_restore_crc_pos here.  During D4
             * incremental validation (reassembly), d4c is the CRC
             * position at the checkpoint — typically several IDATs
             * back.  The IDATs between d4c and last are from kept
             * blocks (correct data).  If the trial block is also
             * correct, the CRC right after last passes, advancing
             * last_idat_crc_pos.  Capping at d4c would erase that
             * advancement, making the correct block indistinguishable
             * from wrong blocks (all give VT = d4c - 2).
             *
             * The d4c cap was intended for self-consistent wrong
             * IDATs that pass CRC and pollute last.  But:
             *   1. The failing CRC that triggered this handler has
             *      NOT updated last (it failed), so last points to
             *      a CRC that genuinely passed.
             *   2. During D4 reassembly, kept blocks between d4c
             *      and the trial block are correct — no wrong IDAT
             *      can pollute last in that range.
             *   3. A self-consistent wrong trial block could pass
             *      one CRC and pollute last, but its VT would be
             *      at that wrong position, which is generally lower
             *      than the correct block's VT. */
            uint64_t safe_crc = 0;
            if (mem->last_idat_crc_pos > 1)
              safe_crc = mem->last_idat_crc_pos;

            /* F8: Echo-safe lgfp handling.
             *
             * This code ONLY runs when zlib_error == 0 AND filter
             * checks didn't fire (errpos_is_precise is false) — i.e.
             * the same-resolution echo case where LZ77 back-refs
             * copy valid-looking pixel data through wrong blocks.
             *
             * Diverse-resolution files always have ze > 0 or filter
             * failure (errpos_is_precise already true), so this
             * block is SKIPPED for them.  No diverse-resolution
             * precision is lost.
             *
             * When safe_crc > 0 (a verified IDAT CRC exists), do
             * NOT extend safe_crc with lgfp.  Echo can push lgfp
             * through entire wrong blocks — not just a few bytes
             * past a boundary — making any lgfp-based extension
             * unreliable.  The verified CRC is the only safe anchor.
             *
             * When safe_crc == 0 (first IDAT, no CRC verified yet),
             * use lgfp for initial progress with block-boundary
             * clipping for small overshoots. */
            if (mem->zlib_error == 0 &&
                mem->last_good_filter_pos > safe_crc) {
              int f8_ext = (safe_crc == 0);
              if (f8_ext) {
                /* First IDAT: no verified CRC anchor.  Use lgfp
                 * with block-boundary clipping for echo overshoot. */
                uint64_t lgfp_safe = mem->last_good_filter_pos;
                if (mem->blocksize > 0) {
                  uint64_t bb = (lgfp_safe / mem->blocksize)
                                * mem->blocksize;
                  uint64_t overshoot = lgfp_safe - bb;
                  if (bb > 0 && overshoot < mem->blocksize / 4)
                    lgfp_safe = bb;
                }
                safe_crc = lgfp_safe;
              }
              /* else: safe_crc > 0 — verified CRC anchor exists.
               * Do NOT extend with lgfp (echo-unreliable). */
            }

            if (safe_crc > 1) {
              mem->errpos = (int64_t)(safe_crc - 2);
              mem->errpos_is_precise = true;
            } else {
              mem->errpos = mem->last_good_pos - 2;
            }
          }
          set_err_no_errpos(kMajorError, mem);
        } else {
          // Non-IDAT CRC failure.  Use kMajorError so that the validates_to
          // computation in png_file_validate triggers rollback to
          // last_good_pos rather than falling through to curpos - 1.
          set_err(kMajorError, mem);
        }
      }
    }

    /* Clear mid_idat when CRC was reached (pass or fail) before early exit */
    if (strcmp(chunkid, "IDAT") == 0)
      mem->mid_idat = false;

    if (mem->global_error > kWarning)
      return mem->global_error;

    // IEND is only authoritative after the IDAT zlib stream has produced
    // the complete image.  A wrong tail can contain self-consistent IDAT
    // chunk CRCs plus IEND, but still leave inflate short of the required
    // rows.  Treat that as structural failure before recording IEND as a
    // verified frontier.
    if (strcmp(chunkid, "IEND") == 0
        && mem->check_zlib
        && mem->zlib_started
        && !mem->zlib_stopped) {
      uint64_t safe_crc = idat_crc_ring_back3(mem->idat_crc_ring,
                                              mem->idat_crc_ring_count);
      if (safe_crc == 0 && mem->d4_restore_crc_pos > 0) {
        safe_crc = mem->d4_restore_crc_pos;
      }
      if (safe_crc == 0 && mem->prev_idat_crc_pos > 0) {
        safe_crc = mem->prev_idat_crc_pos;
      }
      if (safe_crc > 1) {
        mem->errpos = (int64_t)(safe_crc - 2);
        mem->errpos_is_precise = true;
      }
      set_err_no_errpos(kMajorError, mem);
      return mem->global_error;
    }

    /* CRC passed for this chunk — record position for any-chunk CRC tracking. */
    mem->last_chunk_crc_pos = mem->curpos;

    /* IEND CRC passed: update last_good_pos to include the full IEND chunk.
     * Without this, last_good_pos stays at the START of IEND (set at the top
     * of the loop), and if the file ends right after IEND (EOF on next
     * fgetc), the 12-byte IEND chunk gets trimmed off. */
    if (have_IEND) {
      mem->last_good_pos = mem->curpos;
    }

    /* If it was IDAT, we're no longer mid-IDAT.
     * Also record this as the last verified IDAT position. */
    if (strcmp(chunkid, "IDAT") == 0) {
      mem->mid_idat = false;
      mem->prev_idat_crc_pos = mem->last_idat_crc_pos;
      mem->idat_crc_ring[mem->idat_crc_ring_count % IDAT_CRC_RING_SZ] = mem->curpos;
      mem->idat_crc_ring_count++;
      mem->last_idat_crc_pos = mem->curpos;
      /* CRC verified: reset B8 suspicion accumulator — all blocks
       * up to this point are cryptographically confirmed correct. */
      mem->b8_max_suspicion_since_crc = 0.0;
      mem->b10_max_post_crc_mad = 0.0;  /* H9: reset max for new blind spot */
      /* H6c: Reset post-CRC MAD accumulator.  Each time an IDAT CRC
       * is verified, we start fresh so the accumulator only captures
       * rows processed after THIS CRC boundary.  Without this reset,
       * rows from between the previous CRC and this CRC (which are
       * correct) would dilute the average after a D4 restore. */
      mem->post_crc_mad_sum = 0.0;
      mem->post_crc_mad_count = 0;
      mem->post_crc_corr_sum = 0.0;
      mem->post_crc_corr_count = 0;

#if PNG_D4_STATE_CACHE
      /* D4: Save checkpoint after verified IDAT CRC */
      if (mem->carvehashkey) {
        PNGCarveState ckpt = {0};
        ckpt.valid = true;
        ckpt.checkpoint_curpos = mem->curpos;
        ckpt.data_length = mem->length;
        ckpt.prefix_hash = XXH3_64bits(mem->data, mem->curpos);

        /* Save PNGMemIO fields */
        ckpt.global_error = mem->global_error;
        ckpt.errpos = mem->errpos;
        ckpt.curpos = mem->curpos;
        ckpt.last_good_pos = mem->last_good_pos;
        ckpt.first_idat = mem->first_idat;
        ckpt.zlib_error = mem->zlib_error;
        ckpt.check_zlib = mem->check_zlib;
        ckpt.zlib_windowbits = mem->zlib_windowbits;
        ckpt.zlib_started = mem->zlib_started;
        ckpt.zlib_stopped = mem->zlib_stopped;
        ckpt.check_windowbits = mem->check_windowbits;
        ckpt.last_good_filter_pos = mem->last_good_filter_pos;
        ckpt.inflate_consumed_pos = mem->inflate_consumed_pos;
        ckpt.errpos_is_precise = mem->errpos_is_precise;
        ckpt.last_filter_blk = mem->last_filter_blk;
        ckpt.last_filter_blk_boundary = mem->last_filter_blk_boundary;
        ckpt.last_idat_crc_pos = mem->last_idat_crc_pos;
        ckpt.last_chunk_crc_pos = mem->last_chunk_crc_pos;
        ckpt.prev_idat_crc_pos = mem->prev_idat_crc_pos;
        memcpy(ckpt.idat_crc_ring, mem->idat_crc_ring, sizeof(ckpt.idat_crc_ring));
        ckpt.idat_crc_ring_count = mem->idat_crc_ring_count;
        ckpt.have_iend = mem->have_iend;
        ckpt.blocksize = mem->blocksize;
        ckpt.img_width = mem->img_width;
        ckpt.img_height = mem->img_height;
        ckpt.img_bitdepth = mem->img_bitdepth;

        /* CRC checkpoints */
        if (mem->crc_ckpts && mem->n_crc_ckpts > 0) {
          ckpt.crc_ckpts = malloc(mem->max_crc_ckpts * sizeof(struct PNGBlockCRC));
          if (! ckpt.crc_ckpts) { ckpt.max_crc_ckpts = 0; ckpt.n_crc_ckpts = 0; }
          if (ckpt.crc_ckpts) {
            memcpy(ckpt.crc_ckpts, mem->crc_ckpts, mem->n_crc_ckpts * sizeof(struct PNGBlockCRC));
          }
        }
        ckpt.n_crc_ckpts = mem->n_crc_ckpts;
        ckpt.max_crc_ckpts = mem->max_crc_ckpts;
        ckpt.idat_stored_crc = mem->idat_stored_crc;
        ckpt.idat_data_start = mem->idat_data_start;
        ckpt.idat_data_sz = mem->idat_data_sz;
        ckpt.mid_idat = mem->mid_idat;

        /* H6: pixel buffers */
        if (mem->prev_row_pixels && mem->pixel_row_bytes > 0) {
          ckpt.prev_row_pixels = malloc(mem->pixel_row_bytes);
          if (! ckpt.prev_row_pixels) { ckpt.pixel_row_bytes = 0; }
          if (ckpt.prev_row_pixels) {
            memcpy(ckpt.prev_row_pixels, mem->prev_row_pixels, mem->pixel_row_bytes);
          }
        }
        if (mem->cur_row_pixels && mem->pixel_row_bytes > 0) {
          ckpt.cur_row_pixels = malloc(mem->pixel_row_bytes);
          if (! ckpt.cur_row_pixels) { ckpt.pixel_row_bytes = 0; }
          if (ckpt.cur_row_pixels) {
            memcpy(ckpt.cur_row_pixels, mem->cur_row_pixels, mem->pixel_row_bytes);
          }
        }
        ckpt.pixel_row_bytes = mem->pixel_row_bytes;
        ckpt.bpp_bytes = mem->bpp_bytes;
        ckpt.running_mad_sum = mem->running_mad_sum;
        ckpt.mad_count = mem->mad_count;
        ckpt.consecutive_good_rows = mem->consecutive_good_rows;
        ckpt.post_crc_mad_sum = mem->post_crc_mad_sum;
        ckpt.post_crc_mad_count = mem->post_crc_mad_count;
        /* H7 Paeth fraction */
        ckpt.running_corr_sum = mem->running_corr_sum;
        ckpt.corr_count = mem->corr_count;
        ckpt.post_crc_corr_sum = mem->post_crc_corr_sum;
        ckpt.post_crc_corr_count = mem->post_crc_corr_count;

        /* B8: inflate rate */
        ckpt.b8_block_in_start = mem->b8_block_in_start;
        ckpt.b8_block_out_start = mem->b8_block_out_start;
        ckpt.b8_running_ratio = mem->b8_running_ratio;
        ckpt.b8_running_ratio_sq = mem->b8_running_ratio_sq;
        ckpt.b8_ratio_count = mem->b8_ratio_count;
        ckpt.b8_last_block = mem->b8_last_block;
        ckpt.b8_total_out = mem->b8_total_out;
        ckpt.b8_anomaly_pos = mem->b8_anomaly_pos;

        /* B9: Filter distribution */
        memcpy(ckpt.b9_block_filt, mem->b9_block_filt, sizeof(ckpt.b9_block_filt));
        ckpt.b9_block_rows = mem->b9_block_rows;
        memcpy(ckpt.b9_running_frac, mem->b9_running_frac, sizeof(ckpt.b9_running_frac));
        ckpt.b9_running_l1 = mem->b9_running_l1;
        ckpt.b9_running_l1_sq = mem->b9_running_l1_sq;
        ckpt.b9_block_count = mem->b9_block_count;
        ckpt.b9_anomaly_pos = mem->b9_anomaly_pos;

        /* B10: Per-block MAD average */
        ckpt.b10_block_mad_sum = mem->b10_block_mad_sum;
        ckpt.b10_block_mad_count = mem->b10_block_mad_count;
        ckpt.b10_running_mad_avg = mem->b10_running_mad_avg;
        ckpt.b10_running_mad_avg_sq = mem->b10_running_mad_avg_sq;
        ckpt.b10_block_count = mem->b10_block_count;
        ckpt.b10_anomaly_pos = mem->b10_anomaly_pos;
        ckpt.b10_last_mad = mem->b10_last_mad;
        ckpt.b10_max_post_crc_mad = mem->b10_max_post_crc_mad;


        /* B8f: Fine-grained sub-block ratio */
        ckpt.b8f_sub_blocksize = mem->b8f_sub_blocksize;
        ckpt.b8f_block_in_start = mem->b8f_block_in_start;
        ckpt.b8f_block_out_start = mem->b8f_block_out_start;
        ckpt.b8f_running_ratio = mem->b8f_running_ratio;
        ckpt.b8f_running_ratio_sq = mem->b8f_running_ratio_sq;
        ckpt.b8f_ratio_count = mem->b8f_ratio_count;
        ckpt.b8f_last_sub_blk = mem->b8f_last_sub_blk;
        ckpt.b8f_anomaly_pos = mem->b8f_anomaly_pos;

        /* B11: Auto-correlation */
        memcpy(ckpt.b11_byte_ring, mem->b11_byte_ring, sizeof(ckpt.b11_byte_ring));
        ckpt.b11_byte_wpos = mem->b11_byte_wpos;
        memcpy(ckpt.b11_hash_ring, mem->b11_hash_ring, sizeof(ckpt.b11_hash_ring));
        ckpt.b11_hash_wpos = mem->b11_hash_wpos;
        ckpt.b11_byte_match_run = mem->b11_byte_match_run;
        ckpt.b11_byte_last_check = mem->b11_byte_last_check;
        ckpt.b11_anomaly_pos = mem->b11_anomaly_pos;
        ckpt.b12_spike_pos = mem->b12_spike_pos;
        ckpt.b12_spike_mad = mem->b12_spike_mad;
        ckpt.b12_spike_ratio = mem->b12_spike_ratio;
        ckpt.b12_rows_into_block = mem->b12_rows_into_block;
        /* Combined suspicion */
        ckpt.b8_suspicion = mem->b8_suspicion;
        ckpt.b8_max_suspicion_since_crc = mem->b8_max_suspicion_since_crc;
        ckpt.b9_suspicion = mem->b9_suspicion;
        ckpt.b10_suspicion = mem->b10_suspicion;
        ckpt.combined_max_sum = mem->combined_max_sum;
        ckpt.combined_anomaly_pos = mem->combined_anomaly_pos;
        ckpt.post_zend_idat_bytes = mem->post_zend_idat_bytes;

        /* IDAT loop state */
        ckpt.cur_y = mem->cur_y;
        ckpt.cur_pass = mem->cur_pass;
        ckpt.cur_xoff = mem->cur_xoff;
        ckpt.cur_yoff = mem->cur_yoff;
        ckpt.cur_xskip = mem->cur_xskip;
        ckpt.cur_yskip = mem->cur_yskip;
        ckpt.cur_width = mem->cur_width;
        ckpt.cur_linebytes = mem->cur_linebytes;
        ckpt.numfilt = mem->numfilt;
        ckpt.numfilt_this_block = mem->numfilt_this_block;
        ckpt.numfilt_total = mem->numfilt_total;
        memcpy(ckpt.numfilt_pass, mem->numfilt_pass, sizeof(ckpt.numfilt_pass));

        /* inflate output pointer offset.  pngcheck's wrapping trick
         * leaves inflate_out_ptr at outbuf + delta after the last refill.
         * delta > 0 means a partial row was already consumed past eod;
         * the first delta bytes of the NEXT inflate fill are continuation
         * data that should be skipped by the row processor. */
        ckpt.inflate_out_ptr_offset = mem->inflate_out_ptr - (uch *)mem->outbuf;


        /* zlib stream — heap-allocate so memcpy of ckpt never aliases internals */
        ckpt.zstrm_copy = NULL;
        ckpt.has_zstrm = false;
        if (zstrm_initialized) {
          ckpt.zstrm_copy = calloc(1, sizeof(z_stream));
          if (! ckpt.zstrm_copy) { ckpt.has_zstrm = false; }
          if (ckpt.zstrm_copy &&
              inflateCopy(ckpt.zstrm_copy, &zstrm) == Z_OK) {
            ckpt.has_zstrm = true;
          } else {
            free(ckpt.zstrm_copy);
            ckpt.zstrm_copy = NULL;
          }
        }

        /* D4: Save unconsumed inflate input.  In normal flow, avail_in
         * should be 0 at this point: the inflate loop exits when
         * avail_in==0 and no more refills are available, and we only
         * reach the save point without errors.  The leftover mechanism
         * is defensive against future changes to the inflate loop. */
        ckpt.zstrm_leftover = NULL;
        ckpt.zstrm_leftover_count = 0;
        if (mem->zstrm_leftover_count > 0 && mem->zstrm_leftover) {
          ckpt.zstrm_leftover = malloc(mem->zstrm_leftover_count);
          if (! ckpt.zstrm_leftover) { ckpt.zstrm_leftover_count = 0; }
          if (ckpt.zstrm_leftover) {
            memcpy(ckpt.zstrm_leftover, mem->zstrm_leftover,
                   mem->zstrm_leftover_count);
            ckpt.zstrm_leftover_count = mem->zstrm_leftover_count;
          }
        }

        /* pngcheck locals */
        ckpt.loc.w = w; ckpt.loc.h = h;
        ckpt.loc.bitdepth = bitdepth; ckpt.loc.sampledepth = sampledepth;
        ckpt.loc.ityp = ityp; ckpt.loc.lace = lace; ckpt.loc.nplte = nplte;
        ckpt.loc.crc = crc; ckpt.loc.filecrc = filecrc;
        ckpt.loc.sz = sz; ckpt.loc.toread = toread;
        ckpt.loc.zhead = zhead; ckpt.loc.num_chunks = num_chunks;
        ckpt.loc.have_IHDR = have_IHDR; ckpt.loc.have_IEND = have_IEND;
        ckpt.loc.have_PLTE = have_PLTE; ckpt.loc.have_IDAT = have_IDAT;
        ckpt.loc.last_is_IDAT = last_is_IDAT;
        ckpt.loc.have_bKGD = have_bKGD; ckpt.loc.have_cHRM = have_cHRM;
        ckpt.loc.have_eXIf = have_eXIf; ckpt.loc.have_gAMA = have_gAMA;
        ckpt.loc.have_hIST = have_hIST; ckpt.loc.have_iCCP = have_iCCP;
        ckpt.loc.have_oFFs = have_oFFs; ckpt.loc.have_pCAL = have_pCAL;
        ckpt.loc.have_pHYs = have_pHYs; ckpt.loc.have_sBIT = have_sBIT;
        ckpt.loc.have_sCAL = have_sCAL; ckpt.loc.have_sRGB = have_sRGB;
        ckpt.loc.have_sTER = have_sTER; ckpt.loc.have_tIME = have_tIME;
        ckpt.loc.have_tRNS = have_tRNS;
        ckpt.loc.have_acTL = have_acTL; ckpt.loc.have_fcTL = have_fcTL;
        ckpt.loc.have_iDOT = have_iDOT; ckpt.loc.have_cICP = have_cICP;
        ckpt.loc.have_mDCV = have_mDCV; ckpt.loc.have_cLLI = have_cLLI;
        ckpt.loc.have_caBX = have_caBX;
        ckpt.loc.just_seen_fcTL = just_seen_fcTL;
        ckpt.loc.num_frames = num_frames; ckpt.loc.num_plays = num_plays;
        ckpt.loc.num_fcTL = num_fcTL;
        ckpt.loc.next_sequence_number = next_sequence_number;
        ckpt.loc.sequence_number = sequence_number;
        ckpt.loc.frame_width = frame_width; ckpt.loc.frame_height = frame_height;
        ckpt.loc.x_offset = x_offset; ckpt.loc.y_offset = y_offset;
        ckpt.loc.delay_num = delay_num; ckpt.loc.delay_den = delay_den;
        ckpt.loc.dispose_op = dispose_op; ckpt.loc.blend_op = blend_op;
        ckpt.loc.prbuf_state = prbuf_state;

        if (mem->direct_state) {
          /* Direct mode: move ckpt into caller's state.  Free old
           * sub-fields, then transfer ownership of ckpt's sub-fields
           * (no clone needed). */
          PNGCarveState *ds = mem->direct_state;
          free(ds->prev_row_pixels);
          free(ds->cur_row_pixels);
          free(ds->crc_ckpts);
          if (ds->has_zstrm && ds->zstrm_copy) {
            inflateEnd(ds->zstrm_copy);
            free(ds->zstrm_copy);
          }
          free(ds->zstrm_leftover);
          /* D4 checkpoints replace validator-owned state.  Preserve the
           * reassembly-private search frontier around the struct copy. */
          PNGReassemblyPrivateState saved_reass;
          png_reassembly_private_save(&saved_reass, ds);
          memcpy(ds, &ckpt, sizeof(PNGCarveState));
          png_reassembly_private_restore(ds, &saved_reass);
          /* ckpt's sub-fields are now owned by ds — don't free them */
        }
        else {
          carve_put_state(mem->carvehashkey, &ckpt);
          /* Free local allocations -- carve_put_state cloned them */
          free(ckpt.prev_row_pixels);
          free(ckpt.cur_row_pixels);
          free(ckpt.crc_ckpts);
          if (ckpt.has_zstrm && ckpt.zstrm_copy) {
            inflateEnd(ckpt.zstrm_copy);
            free(ckpt.zstrm_copy);
          }
          free(ckpt.zstrm_leftover);
        }
      }
#endif /* PNG_D4_STATE_CACHE */
    }
  }

  /*----------------------- END OF IMMENSE WHILE-LOOP -----------------------*/

  if (no_err(kMinorError, mem)) {
    if (!have_IEND) {
      set_err(kMinorError, mem);
    } else {
      /* APNG: check fcTL frame count and trailing fdAT */
      if (have_acTL && (num_frames != num_fcTL)) {
        set_err(kMinorError, mem);
      }
      if (have_acTL && just_seen_fcTL) {
        set_err(kMinorError, mem);
      }
      /* mDCV requires cICP */
      if (have_mDCV && !have_cICP) {
        set_err(kMinorError, mem);
      }
    }
  }


  if (mem->global_error > kWarning)
    return mem->global_error;

  return mem->global_error;

} /* end function pngcheck() */


/* check_magic()
 *
 * Check the PNG magic numbers in 8-byte buffer at the beginning of a file.
 * Returns 0 if valid PNG, 1 if bytes 2-4 match but others don't, 2 if no match.
 *
 * by Alexander Lehmann, Glenn Randers-Pehrson and Greg Roelofs
 */
int check_magic(PNGMemIO *mem, uch *magic, int which)
{
  int i;
  const uch *good_magic = good_PNG_magic;
  (void)mem;
  (void)which;  /* PNG-only: which parameter retained for call-site compatibility */

  for (i = 1; i <= 3; ++i) {
    if (magic[i] != good_magic[i]) {
      return 2;
    }
  }

  if (magic[0] != good_magic[0] ||
      magic[4] != good_magic[4] || magic[5] != good_magic[5] ||
      magic[6] != good_magic[6] || magic[7] != good_magic[7]) {
    /* CORRUPTED by text conversion — diagnostic details stripped */
    return 1;
  }

  return 0;
}


int check_chunk_name(PNGMemIO *mem, char *chunk_name)
{
  if (isASCIIalpha((int)(uch)chunk_name[0]) &&
      isASCIIalpha((int)(uch)chunk_name[1]) &&
      isASCIIalpha((int)(uch)chunk_name[2]) &&
      isASCIIalpha((int)(uch)chunk_name[3]))
    return 0;

  set_err(kMajorError, mem);  /* usually means we've "jumped the tracks": bail! */
  return 1;
}


/* caller must do set_err(kMinorError) based on return value (0 == OK) */
int check_keyword(PNGMemIO *mem, uch *buffer, int maxsize, int *pKeylen,
                  char *keyword_name, char *chunkid)
{
  int j, prev_space = 0;
  int keylen = keywordlen(buffer, maxsize);
  (void)mem;
  (void)keyword_name;
  (void)chunkid;

  if (pKeylen)
    *pKeylen = keylen;

  if (keylen == 0) {
    return 1;
  }

  if (keylen > 79) {
    return 2;
  }

  if (buffer[0] == ' ') {
    return 3;
  }

  if (buffer[keylen - 1] == ' ') {
    return 4;
  }

  for (j = 0; j < keylen; ++j) {
    if (buffer[j] == ' ') {
      if (prev_space) {
        return 5;
      }
      prev_space = 1;
    } else {
      prev_space = 0;
    }
  }

  for (j = 0; j < keylen; ++j) {
    if (latin1_keyword_forbidden[buffer[j]]) {   /* [0,31] || [127,160] */
      return 6;
    }
  }

  return 0;
}


/* caller must do set_err(kMinorError) based on return value (0 == OK) */
int check_text(PNGMemIO *mem, uch *buffer, int maxsize, char *chunkid)
{
  int j;
  (void)mem;
  (void)chunkid;

  for (j = 0; j < maxsize; ++j) {
    if (buffer[j] == 0) {
      return 1;
    }
  }

  return 0;
}


/* caller must do set_err(kMinorError) based on return value (0 == OK) */
int check_ascii_float(PNGMemIO *mem, uch *buffer, int len, char *chunkid)
{
  uch *qq = buffer, *bufEnd = buffer + len;
  int have_integer = 0, have_dot = 0, have_fraction = 0;
  int have_E = 0, have_Esign = 0, have_exponent = 0, in_digits = 0;
  int have_nonzero = 0;
  int rc = 0;
  (void)mem;
  (void)chunkid;

  for (qq = buffer;  qq < bufEnd && !rc;  ++qq) {
    switch (*qq) {
      case '+':
      case '-':
        if (qq == buffer) {
          in_digits = 0;
        } else if (have_E && !have_Esign) {
          have_Esign = 1;
          in_digits = 0;
        } else {
          rc = 1;
        }
        break;

      case '.':
        if (!have_dot && !have_E) {
          have_dot = 1;
          in_digits = 0;
        } else {
          rc = 2;
        }
        break;

      case 'e':
      case 'E':
        if (have_integer || have_fraction) {
          have_E = 1;
          in_digits = 0;
        } else {
          rc = 3;
        }
        break;

      default:
        if (*qq < '0' || *qq > '9') {
          rc = 4;
        } else if (in_digits) {
          /* still in digits:  do nothing except check for non-zero digits */
          if (!have_exponent && *qq != '0')
            have_nonzero = 1;
        } else if (!have_integer && !have_dot) {
          have_integer = 1;
          in_digits = 1;
          if (*qq != '0')
            have_nonzero = 1;
        } else if (have_dot && !have_fraction) {
          have_fraction = 1;
          in_digits = 1;
          if (*qq != '0')
            have_nonzero = 1;
        } else if (have_E && !have_exponent) {
          have_exponent = 1;
          in_digits = 1;
        } else {
          /* is this case possible? */
          rc = 5;
        }
        break;
    }
  }

  /* must have either integer part or fractional part; all else is optional */
  if (rc == 0 && !have_integer && !have_fraction) {
    rc = 6;
  }

  /* non-exponent part must be non-zero (=> must have seen a non-zero digit) */
  if (rc == 0 && !have_nonzero) {
    rc = 7;
  }

  return rc;
}

// a file validator function determines the position in 'data' at
// which validation (possibly) fails for this file type. While exact
// determination is often difficult, effort should be expended to make
// this determination as accurate as possible, otherwise reassembly of
// some fragmented files may fail.  If the file fully validates,
// 'validates' should be set to true and 'promising' to false. If the
// file partially validates, 'validates' should be set to false and
// 'promising' to true. 'data' may be truncated at position
// 'validates_to' by calling code, again, accurate determine is
// essential.
//
// FILE VALIDATION FUNCTIONS MUST BE THREAD-SAFE--THIS MEANS NO
// WRITEABLE GLOBAL VARIABLES, NO WRITEABLE STATIC VARIABLES, AND NO
// USE OF THREAD-UNSAFE HELPER FUNCTIONS.
//
// png_validate_core — core validation logic.  When direct_state is
// non-NULL, reads/writes state fields directly (no hash table clones).
// When direct_state is NULL, accesses state via carvehashkey through
// the carve state hash table (the FILEVALIDATOR path).
//
static inline void png_validate_core(char *data,
				     uint64_t length,
				     bool *validates,
				     uint64_t *validates_to,
				     bool *promising,
				     uint32_t needleidx,
				     uint32_t blocksize,
				     void *carvehashkey,
				     PNGCarveState *direct_state) {

  int err = kOK;
  PNGMemIO mem;
  (void)needleidx;
  *validates = false;
  *validates_to = 0;
  *promising=false;

  if (scalpel_state.mode_verbose) {
    lock_fprintf(stdout, "png_file_validate() called on %p.\n", data);
  }

#if MAC_MEMORY_PROFILING > 0
  memory_footprint("png start");
#endif

  init_PNGMemIO(&mem, data, length, false);
  mem.blocksize = blocksize;  /* enable block-boundary analysis */
  mem.carvehashkey = carvehashkey;  /* D4: enable state caching */
  mem.direct_state = direct_state;  /* direct state: bypass hash table */

  err = pngcheck(&mem);

  // Tear down the thread-local zlib stream after each validator call.
  if (zstrm_initialized) {
    inflateEnd(&zstrm);
    zstrm_initialized = false;
  }

  /* -----------------------------------------------------------------------
   * Block-boundary post-processing (#3, #5)
   * These run only when blocksize was provided and an error was detected.
   * ----------------------------------------------------------------------- */
  if (mem.blocksize > 0 && err > kWarning) {


  }

  /* Free CRC checkpoint array now that we're done with it */
  if (mem.crc_ckpts) png_ckpt_free(&mem);

  /* H6: Free pixel reconstruction buffers */
  if (mem.prev_row_pixels) { free(mem.prev_row_pixels); mem.prev_row_pixels = NULL; }
  if (mem.cur_row_pixels) { free(mem.cur_row_pixels); mem.cur_row_pixels = NULL; }

  /* D4: Free leftover inflate input buffer */
  if (mem.zstrm_leftover) { free(mem.zstrm_leftover); mem.zstrm_leftover = NULL; }

  int vt_branch = 0;  /* diagnostic: which VT path was taken */

  /* Compute a safe cap for last_good_pos-based branches.
   * A self-consistent wrong IDAT passing CRC also updates last_good_pos
   * (successful chunk processing), so lgp is polluted alongside
   * last_idat_crc_pos.  prev_idat_crc_pos / d4_restore_crc_pos predate
   * any possible wrong-IDAT pollution. */
  uint64_t safe_lgp = mem.last_good_pos;
  if (mem.blocksize > 0 && err > kWarning) {
    uint64_t crc_cap = 0;
    if (mem.prev_idat_crc_pos > 0)
      crc_cap = mem.prev_idat_crc_pos;
    if (mem.d4_restore_crc_pos > 0 &&
        (crc_cap == 0 || mem.d4_restore_crc_pos < crc_cap))
      crc_cap = mem.d4_restore_crc_pos;
    if (crc_cap > 0 && safe_lgp > crc_cap)
      safe_lgp = crc_cap;
  }

  // When an error occurred and we have a CRC-verified IDAT position,
  // trim to the last verified IDAT CRC boundary.  This gives reassembly
  // a clean BV with only proven-correct data — no partial or wrong IDATs.
  // Only gate on last_idat_crc_pos (not last_chunk_crc_pos) because
  // pre-IDAT CRC positions (IHDR, iCCP, etc.) are too early — trimming
  // there loses header blocks that reassembly needs for IDAT info.
  if (err > kWarning && mem.last_idat_crc_pos > 0) {
    *validates_to = mem.last_idat_crc_pos - 1;
    vt_branch = 10;
  }
  else if (mem.errpos >= 0 && mem.errpos != (int64_t)mem.curpos)  {
    // errpos was set and differs from curpos.  This covers:
    //   - IDAT decompression/filter errors (errpos_is_precise == true): trust directly.
    //   - IDAT CRC errors (errpos = last_good_pos - 2): also precise.
    //   - Any set_err() call that locked errpos at an arbitrary curpos
    //     (errpos_is_precise == false): errpos may be inside a wrong block;
    //     roll back to last known-good chunk boundary if a real error followed.
    if (mem.errpos_is_precise) {
      *validates_to = mem.errpos;
      vt_branch = 1;
    }
    else if (err > kWarning && safe_lgp > 1) {
      *validates_to = safe_lgp - 2;
      // Floor: never snap below blocksize-1 when no IDAT CRC verified.
      // safe_lgp can be the IDAT chunk start (byte 337), producing
      // validates_to=335 which trims the candidate below MINIMUMSIZE
      // and prevents it from reaching png_reassembly.
      if (mem.last_idat_crc_pos == 0 && mem.blocksize > 0
          && *validates_to < (uint64_t)(mem.blocksize - 1)) {
        *validates_to = mem.blocksize - 1;
      }
      vt_branch = 2;
    }
    else {
      *validates_to = mem.errpos;
      vt_branch = 3;
    }
  }
  else if (mem.errpos >= 0 && mem.errpos == (int64_t)mem.curpos
           && err > kMinorError && safe_lgp > 1) {
    *validates_to = safe_lgp - 2;
    if (mem.last_idat_crc_pos == 0 && mem.blocksize > 0
        && *validates_to < (uint64_t)(mem.blocksize - 1)) {
      *validates_to = mem.blocksize - 1;
    }
    vt_branch = 4;
  }
  else {
    // Fallback: errpos was never set (no error detected by pngcheck) or
    // conditions above didn't match.  curpos is wherever parsing stopped.
    //
    // GGRIII fix: When blocksize is available and a real error (above
    // warning level) occurred, do not let validates_to extend to curpos-1
    // (which may be near the end of the buffer).  That causes enormous
    // overshoot into wrong data.  Snap back to last_good_pos instead.
    // Gate on err > kWarning (not > kOK) so that warning-only files
    // (which are basically valid) still get full validates_to = curpos-1.
    //
    // Additional gate on errpos >= 0: when errpos was never latched by
    // set_err(), the ONLY errors that fired were EOF handlers (which use
    // set_err_no_errpos).  Every non-EOF error path either calls set_err()
    // or explicitly sets errpos before set_err_no_errpos().  Therefore
    // errpos < 0 guarantees the data was correct up to the EOF point --
    // zlib verified it, CRCs passed for every complete chunk -- and
    // curpos-1 is an accurate validates_to.  Snapping back to
    // last_good_pos-2 in the EOF-only case loses up to one full IDAT
    // chunk of precision (~16 KB), which can prevent the reassembly
    // engine from ever seeing the candidate block at the next position.
    uint64_t vt = mem.curpos > 0 ? mem.curpos - 1 : 0;

    /* F9: REVERTED — fastpath suppression for mid-IDAT endings.
     *
     * Suppressing fastpath (vt = curpos-2 instead of curpos-1) was
     * counterproductive: went from 4 CAT 5 to 6 CAT 5 on test2.frg.
     *
     * Root cause: without gallop, the engine plods one block at a time
     * through the CRC blind spot, trying ALL candidates at each position.
     * For same-resolution echo, all candidates tie (identical VT), so
     * wrong blocks are still committed — just slower.  Meanwhile,
     * gallop + F8 is FASTER at reaching the CRC boundary and detecting
     * the error.  Suppressing gallop delays error detection.
     *
     * The additional 2 new failures (01a249386ca6971c.png,
     * 051ea30a7abae758.png) likely result from the engine's tie-breaking
     * and backtrack queue behavior changing when fastpath is disabled.
     *
     * The fundamental problem remains: between IDAT CRC boundaries
     * (~4 blocks), same-resolution blocks are indistinguishable by
     * inflate, filter checks, gap check, B8, H6c, or H7.  The ONLY
     * discriminator is the IDAT CRC itself. */

    if (mem.blocksize > 0 && err > kWarning && safe_lgp > 1
        && mem.errpos >= 0) {
      vt = safe_lgp - 2;
      if (mem.last_idat_crc_pos == 0
          && vt < (uint64_t)(mem.blocksize - 1)) {
        vt = mem.blocksize - 1;
      }
      vt_branch = 50;
    }
    // When we hit EOF mid-IDAT without any explicit error (errpos < 0),
    // the code above gives vt = curpos-1 (fastpath).  That's correct for
    // valid truncated data.  BUT inflate can consume a wrong block of
    // data without erroring (it interprets bytes as deflate codes and
    // may produce output that passes the filter-type check via sliding-
    // window back-references copying valid earlier data).
    //
    // The filter-type check (dynamic N-consecutive-valid-rows gate) stops
    // last_good_filter_pos from advancing once garbage rows appear.
    // If the gap between curpos and last_good_filter_pos exceeds a
    // threshold, the last block(s) almost certainly contained wrong data.
    //
    // KEY INSIGHT: the reassembly engine tries ~200K candidate blocks
    // and picks the one with the highest validates_to.  The gap check
    // fires when inflate_consumed_pos - last_good_filter_pos > max_gap.
    // The dynamic N-consecutive-rows gate ensures N rows at fixed
    // Huffman rate exceed one blocksize of input, so wrong data can
    // NEVER advance last_good_filter_pos within one appended block.
    // The gap stays large and the check fires reliably.
    //
    // Threshold: 1.25 * raw_row_bytes.  For valid truncated data,
    // the gap is at most one compressed row (≤ raw_row_bytes + 5).
    // 1.25x gives safe margin.  This threshold is now secondary —
    // the dynamic gate is the primary defense.
    //
    // CRITICAL: use inflate_consumed_pos (not curpos) as the reference.
    // When EOF interrupts a refill, data_read bytes are read into the
    // buffer but NEVER inflated.  curpos includes those bytes, making
    // the gap artificially large (up to +8192).  inflate_consumed_pos
    // tracks where inflate actually consumed all input (avail_in == 0),
    // giving the true gap from inflate's perspective.
    //
    // For valid COMPLETE data (zlib_error=-1, Z_STREAM_END), the body
    // drain legitimately reads remaining IDAT bytes without updating
    // last_good_filter_pos, so the gap can be large — skip this check.
    {
      uint64_t raw_row = 0;
      if (mem.img_width > 0 && mem.img_bitdepth > 0)
        raw_row = (uint64_t)((mem.img_width * mem.img_bitdepth + 7) / 8) + 1;
      /* Threshold = raw_row + 25% margin.  For valid data the gap is
       * at most one compressed row ≤ raw_row + 5.  1.25× is safe.
       *
       * The primary defense is the 5-consecutive-rows gate: wrong
       * data can't produce 5 valid rows in one 16384-byte block
       * (each row consumes ~raw_row×9/8 input bytes; 5 rows need
       * ~5.6×raw_row > blocksize for typical images).  So
       * last_good_filter_pos never advances past the wrong block
       * and the gap stays large enough to always fire. */
      uint64_t max_gap = (raw_row > 0 && raw_row < (uint64_t)mem.blocksize)
                         ? raw_row + (raw_row >> 2) : (uint64_t)mem.blocksize;
      if (mem.mid_idat && mem.blocksize > 0 && mem.zlib_started
          && mem.zlib_error >= 0
          && mem.inflate_consumed_pos > 0
          && mem.last_good_filter_pos > 0
          && mem.inflate_consumed_pos > mem.last_good_filter_pos + max_gap) {
        uint64_t filter_vt = (mem.last_good_filter_pos > 1)
            ? mem.last_good_filter_pos - 2 : 0;
        /* CRC cap: the echo effect (zlib sliding-window back-references
         * copying valid earlier data) can advance lgfp well past the last
         * verified CRC without any zlib error.  Without this cap, echo
         * blocks at positions between CRC boundaries get inflated VT values
         * (e.g. lgfp-2 inside the wrong block) that beat the CRC-capped VT
         * of blocks that DO trigger errors.  This causes the reassembly
         * engine to commit an echo block as an "improvement" — blocking
         * the correct OOO block from ever being placed.
         *
         * Apply the same CRC backstop used by the ZLERR handler: cap
         * filter_vt at last_idat_crc_pos - 2.  For correct blocks, the
         * gap check doesn't fire (no gap), so this cap never affects them.
         * For echo blocks, it pulls VT back to the CRC boundary, making
         * them tie with (not beat) the CRC-capped ze>0 blocks. */
        {
          uint64_t crc_cap = mem.last_idat_crc_pos;
          if (mem.prev_idat_crc_pos > 0 && mem.prev_idat_crc_pos < crc_cap)
            crc_cap = mem.prev_idat_crc_pos;
          if (mem.d4_restore_crc_pos > 0 && mem.d4_restore_crc_pos < crc_cap)
            crc_cap = mem.d4_restore_crc_pos;
          if (crc_cap > 0 && filter_vt > crc_cap - 2)
            filter_vt = (crc_cap > 1) ? crc_cap - 2 : 0;
        }
        if (filter_vt < vt) {
          vt = filter_vt;
          vt_branch = 51;  /* gap check */
        }
      }
    }


    /* B8 anomaly cap: if the B8 EOF check detected a compression ratio
     * anomaly in the final block, cap vt at the start of that block.
     * This is the discriminating signal the #6 tail cap couldn't find:
     * correct blocks maintain a consistent ratio with the file's own
     * Huffman table, while foreign blocks (from another PNG) decode
     * with a mismatched table, producing a very different ratio.
     *
     * Unlike the #6 cap (which fires for both wrong AND correct blocks
     * in truncated IDAT tails), B8 anomaly ONLY fires when the final
     * block's ratio deviates significantly from the running average.
     * Correct blocks keep the same table and ratio, so this is a true
     * discriminator.
     *
     * GUARD: only apply when err > kWarning.  For files that validate
     * completely (contiguous carving: IEND reached, err <= kWarning),
     * the B8 ratio variation is just natural PNG compression variation
     * (smooth vs detailed regions).  The B8 cap is designed for the
     * case where wrong data is appended and hits EOF mid-IDAT, which
     * always sets err = kCriticalError via set_err_no_errpos().
     *
     * The -2 offset mirrors the CRCFAIL and gap-check conventions:
     * it avoids landing exactly on a block boundary (which would
     * produce a tie with best_validates_to and force exhaustive search). */
    if (err > kWarning && mem.b8_anomaly_pos > 0 && mem.b8_anomaly_pos < vt) {
      uint64_t b8_vt = (mem.b8_anomaly_pos > 1)
                        ? mem.b8_anomaly_pos - 2 : 0;
      if (b8_vt < vt) {
        vt = b8_vt;
        vt_branch = 52;  /* B8 anomaly cap */
      }


    }  /* end B8 anomaly cap */


    /* H6c: Post-CRC MAD comparison.
     *
     * Type 2 dictionary laundering produces corrupted rows with MAD
     * at ~0.5× the running average — too subtle for per-row detection
     * (individual rows at 0.5× avg are normal in photos) but clearly
     * anomalous when aggregated over ALL post-CRC rows.
     *
     * Compare the average MAD of rows processed after the last IDAT
     * CRC boundary to the overall running average.  If the post-CRC
     * average is significantly lower, the post-CRC data is likely
     * corrupted.  Cap VT at the CRC position.
     *
     * Conditions:
     *   - mid_idat: we're in a truncated IDAT (not a complete file)
     *   - post_crc_mad_count >= 2: enough rows to be meaningful
     *   - running_avg > 20: skip for smooth images (low MAD overall)
     *   - post_crc_avg < running_avg * 0.65: sustained MAD drop
     *
     * The 0.65 threshold catches corruption at 0.49× (observed) with
     * margin, while allowing normal fluctuation.  For correct data,
     * the post-CRC average matches the overall average closely. */
    if (mem.mid_idat && mem.blocksize > 0
        && mem.post_crc_mad_count >= 16
        && mem.mad_count > 0
        && mem.last_idat_crc_pos > 0) {
      double running_avg = mem.running_mad_sum / mem.mad_count;
      double post_crc_avg = mem.post_crc_mad_sum / mem.post_crc_mad_count;
      if (running_avg > 20.0
          && post_crc_avg < running_avg * 0.65) {
        /* Use min(prev, d4c) for cap position.  ring_back3 removed:
         * it regresses 3 IDATs back (~196K), which causes catastrophic
         * VT regression when H6c false-positives on correct blocks
         * with naturally smooth post-CRC regions.  Without rb3, the
         * cap at prev/d4c is ~65K back — still effective for catching
         * echo blocks but not so aggressive as to be unrecoverable
         * when it's wrong. */
        uint64_t safe_crc = mem.prev_idat_crc_pos;
        if (safe_crc == 0) safe_crc = mem.d4_restore_crc_pos;
        if (safe_crc == 0) safe_crc = mem.last_idat_crc_pos;
        uint64_t crc_vt = (safe_crc > 1) ? safe_crc - 2 : 0;
        if (crc_vt < vt) {
          vt = crc_vt;
          vt_branch = 53;  /* H6c post-CRC MAD cap */
        }
      }
    }

    /* H7: Post-CRC Paeth fraction comparison.
     *
     * PNG encoders choose filter type 4 (Paeth) for ~90-97% of rows
     * in photographic images.  When wrong compressed data from another
     * image is decompressed with the wrong zlib dictionary, the output
     * bytes are biased toward 0 (the sliding window contains filter
     * residuals near 0, and LZ77 backreferences copy those).  So wrong
     * data overwhelmingly produces filter type 0 (None) instead of
     * Paeth.
     *
     * This signal is orthogonal to MAD: similar images have similar MAD
     * but the filter type byte depends on what the deflate decoder
     * produces as the first byte of each decompressed row, which is
     * fundamentally different for correct vs wrong dictionary context.
     *
     * Compare the Paeth fraction of rows processed after the last IDAT
     * CRC boundary to the overall running Paeth fraction.  A sustained
     * drop indicates foreign data.
     *
     * Conditions:
     *   - mid_idat: we're in a truncated IDAT (not a complete file)
     *   - post_crc_corr_count >= 5: enough rows to be meaningful
     *   - corr_count > 10: enough baseline samples
     *   - running Paeth fraction > 0.70: image uses mostly Paeth
     *   - post_crc Paeth fraction < running * 0.50: sustained drop
     *
     * Note: field names still say "corr" for code continuity with the
     * state infrastructure, but they now store Paeth fractions. */
    if (mem.mid_idat && mem.blocksize > 0
        && mem.post_crc_corr_count >= 5
        && mem.corr_count > 10
        && mem.last_idat_crc_pos > 0) {
      double running_paeth = mem.running_corr_sum / mem.corr_count;
      double post_crc_paeth = mem.post_crc_corr_sum / mem.post_crc_corr_count;
      if (running_paeth > 0.70
          && post_crc_paeth < 0.25) {
        /* H7 confirmed corruption: use min(prev, d4c) for cap.
         * ring_back3 removed for same reason as H6c: 3-IDAT regression
         * is catastrophically aggressive on false positives.  Consistent
         * with H6c to avoid cap asymmetry. */
        uint64_t safe_crc = mem.prev_idat_crc_pos;
        if (safe_crc == 0) safe_crc = mem.d4_restore_crc_pos;
        if (safe_crc == 0) safe_crc = mem.last_idat_crc_pos;
        uint64_t crc_vt = (safe_crc > 1) ? safe_crc - 2 : 0;
        if (crc_vt < vt) {
          vt = crc_vt;
          vt_branch = 54;  /* H7 post-CRC Paeth fraction cap */
        }
      }
	    }

    /* Ring buffer backstop: catch cases where 2+ self-consistent wrong
     * IDATs polluted both last_idat_crc_pos AND prev_idat_crc_pos,
     * causing the error handlers to set VT too high.
     *
     * ring_back3 goes 3 IDATs back — guaranteed clean for up to 2
     * wrong IDATs.  Only applies when:
     *   1) We have enough ring history (>= 4 IDATs verified)
     *   2) The computed VT exceeds prev_idat_crc_pos (evidence that
     *      the error handlers couldn't snap back far enough)
     *   3) ring_back3 - 2 is lower than the computed VT
     *
     * Condition (2) is key: for 0-1 wrong IDATs, the error handlers
     * already set VT <= prev_idat_crc_pos (using the clean prev).
     * VT > prev only happens when prev itself is polluted. */
    *validates_to = vt;

    // Historical note: two non-kOK blind-spot tiebreakers were removed
    // from this fallback path.  H8 was a candidate-block Paeth-fraction
    // tiebreaker; H9 was a candidate-block MAD tiebreaker.  They were
    // intended to reduce VT by one byte for echo-like candidate blocks
    // when no deterministic CRC/error signal distinguished candidates.
    // In the old code they were unreachable because they tested
    // vt_branch == 5 before vt_branch was assigned 5 below.  Enabling
    // them did not improve the measured GAP, OOO, or GAP+OOO PNG
    // corpora, so they are intentionally not parked here as inactive
    // code.  The live H9 block below is a different kOK demotion path.
    if (!vt_branch) vt_branch = 5;  /* plain fallback */
  }


  /* H9: Blind spot MAD tiebreaker — kOK path.
   *
   * Blind-spot echo blocks validate fully (err == kOK) because the zlib
   * stream decompresses without error and no CRC boundary falls within
   * the candidate block.  H6c/H7 run only in the error path and never
   * see these blocks.  The old H8 fallback tiebreaker was also an
   * error-path idea and is intentionally not present.
   *
   * B10 suspicion IS available because the block boundary code computed
   * it before resetting per-block counters.  For echo blocks, the
   * candidate's per-block MAD is anomalously high (random pixels from
   * dictionary laundering), giving suspicion >> 1.5.  For correct
   * blocks, suspicion is typically 0.0-1.3.
   *
   * When H9 fires, demote from full validation (kOK, validates=true)
   * to partial (validates_to = len-2, promising=true).  The correct
   * candidate retains its full validation at len-1 and wins. */
  int h9_demoted = 0;
  if (err == kOK && mem.blocksize > 0
      && !mem.have_iend  // NEVER demote complete files with IEND
      && mem.b10_block_count >= 4
      && mem.h9_cand_mad_count >= 3   // P4: 2 → 3 to cut false fires on short candidates
      && mem.last_idat_crc_pos > 0) {
    double run_avg = mem.b10_running_mad_avg / mem.b10_block_count;
    double cand_avg = mem.h9_cand_mad_sum / mem.h9_cand_mad_count;
    // P4: tighten from (run>5.0 && cand>run*3.0) to (run>7.0 && cand>run*4.0).
    // H9 was demoting legitimate high-variance images (photographs,
    // dithered palettes) on incomplete candidates.  The tighter gate
    // still catches echo-block pollution (cand_avg usually 10-50x run_avg)
    // without clipping real textured content.
    // Additionally require b10_anomaly_pos > 0 as a co-fire signal — the
    // demotion is only meaningful when a block-boundary anomaly was also
    // observed, which is the actual echo-block signature.
    if (run_avg > 7.0
        && cand_avg > run_avg * 4.0
        && mem.b10_anomaly_pos > 0) {
      *validates_to = (mem.length > 1) ? mem.length - 2 : 0;
      h9_demoted = 1;
    }
  }

  // Only validate fully when IEND is present and pngcheck passed.
  // Without IEND the file is incomplete — mark promising so it enters
  // reassembly instead of being written as junk to VALIDATED.
  if (err == kOK && !h9_demoted) {
    if (mem.have_iend) {
      *validates = true;
      if (mem.last_good_pos > 0) {
        *validates_to = mem.last_good_pos - 1;
      } else {
        *validates_to = mem.length > 0 ? mem.length - 1 : 0;
      }
    } else {
      // No IEND: trim to last verified IDAT CRC, mark promising.
      *validates = false;
      *promising = true;
      if (mem.last_idat_crc_pos > 0) {
        *validates_to = mem.last_idat_crc_pos - 1;
      } else if (mem.last_chunk_crc_pos > 0) {
        // Keep all verified pre-IDAT chunks + next chunk header
        // (8 bytes: length + type) so reassembly knows the IDAT size.
        *validates_to = mem.last_chunk_crc_pos + 7;
      } else if (mem.last_good_pos > 0) {
        // Without a CRC anchor, fall back to the parser's last good byte
        // rather than speculatively crediting the whole candidate.
        *validates_to = mem.last_good_pos - 1;
      } else {
        *validates_to = 0;
      }
    }
  }
  else if (*validates_to > 0) {
    *promising = true;
  }


  // Final floor: never let validates_to drop below blocksize-1 for
  // non-validated candidates. Prevents trimming to 0 blocks.
  // Must also set promising=true — otherwise carve.c discards on
  // !promising && !validates, defeating the floor.
  if (! *validates && mem.blocksize > 0 && length >= mem.blocksize
      && *validates_to < mem.blocksize - 1) {
    *validates_to = mem.blocksize - 1;
    *promising = true;
  }

  if (scalpel_state.mode_verbose) {
    lock_fprintf(stdout, "png_file_validate() on %p: length = %"PRIu64", validates = %1d, "
		 "validates_to = %"PRIu64", promising = %1d, err=%d, vt_branch=%u, "
		 "last_idat_crc_pos=%"PRIu64", last_chunk_crc_pos=%"PRIu64", "
		 "last_good_pos=%"PRIu64", errpos=%"PRId64", have_iend=%d.\n",
		 data, length, *validates, *validates_to, *promising, err, vt_branch,
		 mem.last_idat_crc_pos, mem.last_chunk_crc_pos,
		 mem.last_good_pos, mem.errpos, (int)mem.have_iend);
  }

  /* Propagate CRC state from validator back to state.
   *
   * CRITICAL: only propagate when CRC state ADVANCED.  When the
   * validator runs on corrupt data (covered blocks from work sharing),
   * it may produce last_chunk_crc_pos = 0.  Allowing that to overwrite
   * a previously verified CRC position would destroy proven progress. */
  if (direct_state) {
    /* Direct mode: update caller's state in-place — no hash table. */
    if (mem.last_chunk_crc_pos > direct_state->last_chunk_crc_pos) {
      if (scalpel_state.mode_verbose) {
        lock_fprintf(stdout,
                     "PNG CRC-PROP(direct): %" PRIu64 " -> %" PRIu64
                     " (idat_sz=%ld)\n",
                     direct_state->last_chunk_crc_pos, mem.last_chunk_crc_pos,
                     mem.idat_data_sz);
      }
      direct_state->last_chunk_crc_pos = mem.last_chunk_crc_pos;
      direct_state->last_idat_crc_pos = mem.last_idat_crc_pos;
      direct_state->prev_idat_crc_pos = mem.prev_idat_crc_pos;
      memcpy(direct_state->idat_crc_ring, mem.idat_crc_ring,
             sizeof(direct_state->idat_crc_ring));
      direct_state->idat_crc_ring_count = mem.idat_crc_ring_count;
      if (mem.idat_data_sz > 0) {
        direct_state->idat_data_start = mem.idat_data_start;
        direct_state->idat_data_sz = mem.idat_data_sz;
        direct_state->idat_stored_crc = mem.idat_stored_crc;
      }
    }
    if (mem.idat_data_sz > 0
        && mem.idat_data_start == direct_state->last_chunk_crc_pos + 8) {
      direct_state->idat_data_start = mem.idat_data_start;
      direct_state->idat_data_sz = mem.idat_data_sz;
      direct_state->idat_stored_crc = mem.idat_stored_crc;
    }
  }
  else if (carvehashkey) {
    PNGCarveState *rs = (PNGCarveState *)carve_get_state(carvehashkey);
    if (rs && mem.last_chunk_crc_pos > rs->last_chunk_crc_pos) {
      if (scalpel_state.mode_verbose) {
        lock_fprintf(stdout,
                     "PNG CRC-PROP: %" PRIu64 " -> %" PRIu64
                     " (idat_sz=%ld)\n",
                     rs->last_chunk_crc_pos, mem.last_chunk_crc_pos,
                     mem.idat_data_sz);
      }
      rs->last_chunk_crc_pos = mem.last_chunk_crc_pos;
      rs->last_idat_crc_pos = mem.last_idat_crc_pos;
      rs->prev_idat_crc_pos = mem.prev_idat_crc_pos;
      memcpy(rs->idat_crc_ring, mem.idat_crc_ring,
             sizeof(rs->idat_crc_ring));
      rs->idat_crc_ring_count = mem.idat_crc_ring_count;
      if (mem.idat_data_sz > 0) {
        rs->idat_data_start = mem.idat_data_start;
        rs->idat_data_sz = mem.idat_data_sz;
        rs->idat_stored_crc = mem.idat_stored_crc;
      }
      carve_put_state(carvehashkey, rs);
    }
    if (rs && mem.idat_data_sz > 0
        && mem.idat_data_start == rs->last_chunk_crc_pos + 8) {
      rs->idat_data_start = mem.idat_data_start;
      rs->idat_data_sz = mem.idat_data_sz;
      rs->idat_stored_crc = mem.idat_stored_crc;
      carve_put_state(carvehashkey, rs);
    }
    png_free_carve_state((void **)&rs);
  }

#if MAC_MEMORY_PROFILING > 0
  memory_footprint("png exit");
#endif
}


// png_try_complete_contiguous — stateless complete-PNG probe.  This answers
// only "is the current buffer already a complete PNG?" and never reads or
// writes recovery/checkpoint state.
static inline bool png_try_complete_contiguous(char *data,
					       uint64_t length,
					       uint64_t *validates_to) {
  int err;
  PNGMemIO mem;

  if (validates_to) {
    *validates_to = 0;
  }

  init_PNGMemIO(&mem, data, length, true);
  err = pngcheck(&mem);

  if (zstrm_initialized) {
    inflateEnd(&zstrm);
    zstrm_initialized = false;
  }

  if (mem.crc_ckpts) png_ckpt_free(&mem);
  if (mem.prev_row_pixels) { free(mem.prev_row_pixels); mem.prev_row_pixels = NULL; }
  if (mem.cur_row_pixels) { free(mem.cur_row_pixels); mem.cur_row_pixels = NULL; }
  if (mem.zstrm_leftover) { free(mem.zstrm_leftover); mem.zstrm_leftover = NULL; }

  if (err == kOK && mem.have_iend) {
    if (validates_to) {
      *validates_to = mem.last_good_pos > 0
                      ? mem.last_good_pos - 1
                      : (length > 0 ? length - 1 : 0);
    }
    return true;
  }

  if (scalpel_state.mode_verbose) {
    lock_fprintf(stdout,
		 "png_try_complete_contiguous() on %p: length = %"PRIu64
		 ", validates = 0, validates_to = %"PRIu64
		 ", err=%d, have_iend=%d.\n",
		 data, length, validates_to ? *validates_to : 0, err,
		 (int)mem.have_iend);
  }

  return false;
}


// png_file_validate — FILEVALIDATOR-compliant wrapper.  Used by the system
// for contiguous validation.  A stateless complete-PNG probe runs first; if
// that fails, no-defrag mode stops and fragmented mode enters recovery logic.
static inline void png_file_validate(char *data,
				     uint64_t length,
				     bool *validates,
				     uint64_t *validates_to,
				     bool *promising,
				     uint32_t needleidx,
				     uint32_t blocksize,
				     void *carvehashkey) {
  *validates = false;
  *validates_to = 0;
  *promising = false;

  if (png_try_complete_contiguous(data, length, validates_to)) {
    *validates = true;
    return;
  }

  if (scalpel_state.no_defrag) {
    return;
  }

  png_validate_core(data, length, validates, validates_to, promising,
                    needleidx, blocksize, carvehashkey, NULL);
}


// header validation functions can be used as an alternative to fixed binary strings or regular
// expressions to identify file headers.  Non-MASTER header functions should always return NULL.
// MASTER header functions should return NULL if no header is discovered or a dynamically allocated
// character string identifying the file subtype for the discovered header.  'data' is the *base* of
// the buffer. The search must start at data + offset.  'length' is the usable portion of the buffer
// beyond offset.
//
static inline char *png_header_discovery(char *base,
					 uint64_t offset,
					 uint64_t remaining,
					 char **matchpos,
					 uint32_t *matchlen,
					 uint32_t blocksize) {

  size_t table[UCHAR_MAX + 1];
  char *HEADER="\x89\x50\x4e\x47\x0d\x0a\x1a\x0a";
  (void)blocksize;

  base += offset;
  *matchlen = 8;
  init_bm_table(HEADER, table, *matchlen, true);
  *matchpos = find_binary_string(HEADER,
				 *matchlen,
				 base,
				 remaining,
				 table,
				 true);

  return NULL;
}


// footer validation functions can be used as an alternative to fixed binary strings or regular
// expressions to identify file footers. Footer functions should always return NULL.  'data' is the
// *base* of the buffer. The search must start at data + offset.  'length' is the usable portion of
// the buffer beyond offset.
//
static inline char *png_footer_discovery(char *base,
					 uint64_t offset,
					 uint64_t remaining,
					 char **matchpos,
					 uint32_t *matchlen,
					 uint32_t blocksize) {

  char *FOOTER="/IEND..../";
  char end[MAX_STRING_LENGTH];
  char errmsg[MAX_STRING_LENGTH];
  int len;
  pcre2_code  *re;
  pcre2_match_data *match_data;
  int err;                   // tracks regex compilation success
  PCRE2_SIZE erroffset;      // offset of error in regular expression compilation
  (void)blocksize;

  base += offset;
  *matchpos=NULL;
  *matchlen=0;
  len = translate(FOOTER, "png", true);
  memcpy(end, FOOTER+1, len);

  re = pcre2_compile((PCRE2_SPTR8)end, len,
		     PCRE2_CASELESS * 0,
		     &err,
		     &erroffset,
		     NULL);

  if (! re) {
    // fatal
    handle_error(SCALPEL_ERROR_BAD_REGEX, errmsg,
		 __LINE__, __FILE__);
  }

  match_data = find_regular_expression(re, base, remaining);
  if (match_data) {
    PCRE2_SIZE *ovector;
    ovector = pcre2_get_ovector_pointer(match_data);
    *matchpos = base + ovector[0];
    *matchlen = ovector[1] - ovector[0];
    pcre2_match_data_free(match_data);
  }
  pcre2_code_free(re);

  return NULL;
}

// ============================================================================
// PNG custom reassembly — CRC-verified, no backtracking
// ============================================================================

// prototypes
static inline void png_reassembly_init_candidate(CarveInfo *candidate,
                                                  PNGCarveState *local);
static inline void png_reassembly(ThreadWork *work, CarveInfo **c,
                                   uuid_string_t uuidp, uuid_string_t uuidc);
static inline bool png_direct_validate(int id, CarveInfo *candidate,
    uint64_t *validates_to, PNGCarveState *local,
    uuid_string_t uuidp, uuid_string_t uuidc);

// Check if an apparent block has an IDAT marker at the expected byte
// offset within the block.  Uses the precomputed block state from
// png_block_validate.  Returns true if the block has IDAT at the
// expected offset (±0 tolerance — must be exact).
static inline bool png_block_has_idat_at(int64_t apparent_block,
                                          uint32_t expected_offset,
                                          uint32_t needleidx) {
  int64_t actual = filemirror_actual_blocknumber(
      scalpel_state.filemirror, apparent_block);
  if (actual < 0) {
    return false;
  }
  char hashkey[BLOCK_HASH_KEY_SIZE];
  if (!gen_block_hash_key(hashkey, needleidx, actual)) {
    return false;
  }
  PNGBlockState *bs = (PNGBlockState *)block_get_state(hashkey);
  if (!bs) {
    return false;  // no block state = no IDAT marker info
  }
  bool found = false;
  // Check IDAT markers at expected offset
  for (int i = 0; i < bs->num_idat_markers; i++) {
    if (bs->idat_offsets[i] == expected_offset) {
      found = true;
      break;
    }
  }
  // Also accept IEND at the expected offset — the filter assumes
  // the next chunk is always IDAT, but after the last IDAT the
  // next chunk is IEND.  (Ancillary chunks between last IDAT and
  // IEND are spec-legal but not observed in real datasets.)
  if (!found && bs->has_iend && bs->iend_offset == expected_offset) {
    found = true;
  }
  free(bs);
  return found;
}

// ============================================================================
// Parse first IDAT chunk from BV data (pre-CRC mode helper)
// ============================================================================
//
// In pre-CRC mode, the carve state doesn't have idat_data_sz because no
// IDAT CRC has been verified yet.  But the IDAT chunk HEADER (including
// the body length) is already in the BV prefix data.  Parse it to get
// the IDAT body size and the byte position of the CRC.
//
// Returns true if an IDAT chunk was found.  Fills out idat_body_start,
// idat_body_size, and idat_crc_pos (byte position of the 4-byte CRC in
// the data stream, right after the IDAT body).

static inline bool png_parse_first_idat(CarveInfo *candidate,
                                         uint64_t *idat_body_start,
                                         uint32_t *idat_body_size,
                                         uint64_t *idat_crc_pos) {
  uint8_t *data = (uint8_t *)blockvector_get_data_pointer(candidate->b);
  uint64_t dl = blockvector_get_data_length(candidate->b);
  if (!data || dl < 20) {
    return false;
  }

  // Walk PNG chunks: skip 8-byte signature, then chunk chain
  uint64_t pos = 8;
  while (pos + 12 <= dl) {
    uint32_t chunk_len = ((uint32_t)data[pos] << 24)
        | ((uint32_t)data[pos + 1] << 16)
        | ((uint32_t)data[pos + 2] << 8)
        | (uint32_t)data[pos + 3];
    if (data[pos + 4] == 'I' && data[pos + 5] == 'D'
        && data[pos + 6] == 'A' && data[pos + 7] == 'T') {
      if (chunk_len > PNG_MAX_IDAT_BODY_LEN) {
        return false;
      }
      *idat_body_start = pos + 8;
      *idat_body_size = chunk_len;
      *idat_crc_pos = pos + 8 + chunk_len;
      return true;
    }
    // Bound non-IDAT chunks before skipping them.  IDAT is handled above
    // even when only its header is present, because fragmented reassembly
    // needs the length to solve forward to the CRC boundary.
    if ((uint64_t)chunk_len + 12 > dl - pos) {
      return false;
    }
    // Skip: length(4) + type(4) + body(chunk_len) + crc(4)
    pos += 12 + (uint64_t)chunk_len;
  }
  return false;
}

// ============================================================================
// Solver table types — file-scope so PNGSolverContext can persist them
// across in-process requeue handoffs without rebuild.
// ============================================================================
#define MITM_BUCKETS2  65536
#define PNG_M3_BUCKETS 65536

typedef struct Er2Entry {
  uint32_t shifted_crc;
  int64_t actual_block;
  struct Er2Entry *next;
} Er2Entry;

typedef struct MitmEntry2 {
  uint32_t crc;
  int64_t actual;
  struct MitmEntry2 *next;
} MitmEntry2;

typedef struct {
  int64_t actual_block;
  int64_t apparent_block;
  uint32_t stored_crc;
  uint32_t partial_crc;  /* CRC of body portion within this block */
  bool valid;
} PNGSuffixCand;

static inline bool png_suffix_candidate_from_entry(PNGSuffixCand *sc,
                                                    PNGCrcEntry *e,
                                                    CarveInfo *candidate,
                                                    bool marker_required,
                                                    uint32_t type_pos,
                                                    bool crc_in_suffix,
                                                    uint64_t crc_off_in_blk,
                                                    bool body_in_suffix,
                                                    uint64_t body_off,
                                                    uint64_t suffix_partial_len,
                                                    uint64_t crc_field_pos) {
  if (!sc || !e) {
    return false;
  }

  sc->actual_block = e->actual_block;
  sc->apparent_block = filemirror_apparent_blocknumber(
      scalpel_state.filemirror, e->actual_block);
  sc->valid = false;
  if (sc->apparent_block < 0) {
    return false;
  }
  if (filemirror_actual_block_covered(scalpel_state.filemirror,
          e->actual_block)) {
    return false;
  }

  if (marker_required) {
    bool has_marker = false;
    for (uint8_t mi = 0; mi < e->num_idat_markers; mi++) {
      if (e->idat_offsets[mi] == type_pos) {
        has_marker = true;
        break;
      }
    }
    if (!has_marker && e->has_iend && e->iend_offset == type_pos) {
      has_marker = true;
    }
    if (!has_marker) {
      return false;
    }
  }

  if (crc_in_suffix) {
    unsigned char crc_buf[4];
    if (! get_apparent_block_bytes(scalpel_state.filemirror,
            sc->apparent_block, crc_off_in_blk, 4, crc_buf)) {
      return false;
    }
    sc->stored_crc = ((uint32_t)crc_buf[0] << 24)
        | ((uint32_t)crc_buf[1] << 16)
        | ((uint32_t)crc_buf[2] << 8) | (uint32_t)crc_buf[3];
  }
  else {
    sc->stored_crc = 0;
    if (candidate && candidate->b
        && crc_field_pos + 4 <= blockvector_get_data_length(candidate->b)) {
      const unsigned char *sep = (const unsigned char *)(
          blockvector_get_data_pointer(candidate->b) + crc_field_pos);
      sc->stored_crc = ((uint32_t)sep[0] << 24)
          | ((uint32_t)sep[1] << 16)
          | ((uint32_t)sep[2] << 8) | (uint32_t)sep[3];
    }
  }

  if (body_in_suffix && suffix_partial_len > 0) {
    unsigned char pbuf[16384];
    uint32_t plen = (suffix_partial_len > sizeof(pbuf))
        ? (uint32_t)sizeof(pbuf) : (uint32_t)suffix_partial_len;
    if (! get_apparent_block_bytes(scalpel_state.filemirror,
            sc->apparent_block, body_off, plen, pbuf)) {
      return false;
    }
    sc->partial_crc = crc32(0, pbuf, (uInt)plen);
  }
  else {
    sc->partial_crc = crc32(0, NULL, 0);
  }

  sc->valid = true;
  return true;
}

typedef struct PNGSolverContext {
    MitmEntry2 *left_pool;
    MitmEntry2 **left_table;
    PNGCrcEntry **ht_flat;
    uint32_t ht_flat_count;
    PNGSuffixCand *suffix_cands;
    uint32_t nsuffix;
    uint64_t built_for_suffix_nb;
    uint64_t built_for_crc_pos;
    bool valid;
    /* M=3 shifted-CRC lookup tables — in-process cache only. */
    Er2Entry *m3_pool[3];
    Er2Entry **m3_htab[3];
    uint32_t m3_count[3];
    int m3_alias[3];
    bool m3_tables_valid;
} PNGSolverContext;

static inline void png_solver_ctx_free(PNGSolverContext **ctx) {
    if (!ctx || !*ctx) return;
    PNGSolverContext *c = *ctx;
    free(c->left_pool); free(c->left_table);
    free(c->ht_flat);
    free(c->suffix_cands);
    for (int mi = 0; mi < 3; mi++) {
        if (c->m3_alias[mi] < 0) {
            free(c->m3_htab[mi]); free(c->m3_pool[mi]);
        }
    }
    free(c);
    *ctx = NULL;
}

static inline uint32_t png_solver_ctx_count_mitm2(MitmEntry2 **tab,
                                                  uint32_t buckets) {
  uint32_t count = 0;
  if (!tab) {
    return 0;
  }
  for (uint32_t b = 0; b < buckets; b++) {
    for (MitmEntry2 *e = tab[b]; e; e = e->next) {
      count++;
    }
  }
  return count;
}

static inline uint32_t png_solver_ctx_count_er2(Er2Entry **tab,
                                                uint32_t buckets) {
  uint32_t count = 0;
  if (!tab) {
    return 0;
  }
  for (uint32_t b = 0; b < buckets; b++) {
    for (Er2Entry *e = tab[b]; e; e = e->next) {
      count++;
    }
  }
  return count;
}

static inline PNGSolverContext *png_solver_ctx_clone(
    const PNGSolverContext *src) {
  if (!src) {
    return NULL;
  }

  PNGSolverContext *dst = (PNGSolverContext *)calloc(1, sizeof(*dst));
  if (!dst) {
    return NULL;
  }
  *dst = *src;
  dst->left_pool = NULL;
  dst->left_table = NULL;
  dst->ht_flat = NULL;
  dst->suffix_cands = NULL;
  for (int mi = 0; mi < 3; mi++) {
    dst->m3_pool[mi] = NULL;
    dst->m3_htab[mi] = NULL;
  }

  if (src->left_table) {
    uint32_t left_count =
        png_solver_ctx_count_mitm2(src->left_table, MITM_BUCKETS2);
    if (left_count > 0) {
      dst->left_pool = (MitmEntry2 *)malloc(
          (size_t)left_count * sizeof(MitmEntry2));
      dst->left_table = (MitmEntry2 **)calloc(
          MITM_BUCKETS2, sizeof(MitmEntry2 *));
      if (!dst->left_pool || !dst->left_table) goto fail;
      uint32_t out = 0;
      for (uint32_t b = 0; b < MITM_BUCKETS2; b++) {
        for (MitmEntry2 *e = src->left_table[b]; e; e = e->next) {
          MitmEntry2 *copy = &dst->left_pool[out++];
          *copy = *e;
          uint32_t idx = copy->crc % MITM_BUCKETS2;
          copy->next = dst->left_table[idx];
          dst->left_table[idx] = copy;
        }
      }
    }
  }

  if (src->ht_flat && src->ht_flat_count > 0) {
    dst->ht_flat = (PNGCrcEntry **)malloc(
        (size_t)src->ht_flat_count * sizeof(PNGCrcEntry *));
    if (!dst->ht_flat) goto fail;
    memcpy(dst->ht_flat, src->ht_flat,
        (size_t)src->ht_flat_count * sizeof(PNGCrcEntry *));
  }

  if (src->suffix_cands && src->nsuffix > 0) {
    dst->suffix_cands = (PNGSuffixCand *)malloc(
        (size_t)src->nsuffix * sizeof(PNGSuffixCand));
    if (!dst->suffix_cands) goto fail;
    memcpy(dst->suffix_cands, src->suffix_cands,
        (size_t)src->nsuffix * sizeof(PNGSuffixCand));
  }

  for (int mi = 0; mi < 3; mi++) {
    if (src->m3_alias[mi] >= 0 || !src->m3_htab[mi]) {
      continue;
    }
    uint32_t count =
        png_solver_ctx_count_er2(src->m3_htab[mi], PNG_M3_BUCKETS);
    if (count == 0) {
      dst->m3_count[mi] = 0;
      continue;
    }
    dst->m3_pool[mi] = (Er2Entry *)malloc(
        (size_t)count * sizeof(Er2Entry));
    dst->m3_htab[mi] = (Er2Entry **)calloc(
        PNG_M3_BUCKETS, sizeof(Er2Entry *));
    if (!dst->m3_pool[mi] || !dst->m3_htab[mi]) goto fail;
    uint32_t out = 0;
    for (uint32_t b = 0; b < PNG_M3_BUCKETS; b++) {
      for (Er2Entry *e = src->m3_htab[mi][b]; e; e = e->next) {
        Er2Entry *copy = &dst->m3_pool[mi][out++];
        *copy = *e;
        uint32_t idx = copy->shifted_crc % PNG_M3_BUCKETS;
        copy->next = dst->m3_htab[mi][idx];
        dst->m3_htab[mi][idx] = copy;
      }
    }
  }

  return dst;

fail:
  png_solver_ctx_free(&dst);
  return NULL;
}

// png_get_block_crc — look up pre-computed CRC32 of a block's raw data.
// Returns 0 if lookup fails (no block state, non-viable block, etc.)
// and sets *ok = false.  On success sets *ok = true.
static inline uint32_t png_get_block_crc(int64_t apparent_block,
                                          uint32_t needleidx,
                                          bool *ok) {
  *ok = false;
  int64_t actual = filemirror_actual_blocknumber(
      scalpel_state.filemirror, apparent_block);
  if (actual < 0) {
    return 0;
  }
  char hashkey[BLOCK_HASH_KEY_SIZE];
  if (!gen_block_hash_key(hashkey, needleidx, actual)) {
    return 0;
  }
  PNGBlockState *bs = (PNGBlockState *)block_get_state(hashkey);
  if (!bs) {
    return 0;
  }
  uint32_t crc = bs->block_crc;
  png_free_block_state((void **)&bs);
  *ok = true;
  return crc;
}

static inline bool png_chunk_type_is_ascii(const uint8_t *type) {
  return type
      && isASCIIalpha((int)type[0])
      && isASCIIalpha((int)type[1])
      && isASCIIalpha((int)type[2])
      && isASCIIalpha((int)type[3]);
}

static inline void png_crc_forward_for_len(z_off_t len,
                                            uint32_t forward[32]) {
  uLong op = crc32_combine_gen(len);
  for (int i = 0; i < 32; i++) {
    forward[i] = (uint32_t)crc32_combine_op(
        (uLong)(1U << i), 0UL, op);
  }
}

static inline uint32_t png_crc_apply_forward(const uint32_t forward[32],
                                              uint32_t value) {
  uint32_t out = 0;
  for (int bit = 0; bit < 32; bit++) {
    if (value & (1U << bit)) {
      out ^= forward[bit];
    }
  }
  return out;
}

static inline bool png_crc_inverse_for_len(z_off_t len, uint32_t inv[32]) {
  uint32_t aug[32];
  png_crc_forward_for_len(len, aug);
  for (int i = 0; i < 32; i++) {
    inv[i] = 1U << i;
  }

  for (int col = 0; col < 32; col++) {
    int pivot = -1;
    for (int row = col; row < 32; row++) {
      if (aug[row] & (1U << col)) {
        pivot = row;
        break;
      }
    }
    if (pivot < 0) {
      return false;
    }
    if (pivot != col) {
      uint32_t t = aug[col];
      aug[col] = aug[pivot];
      aug[pivot] = t;
      t = inv[col];
      inv[col] = inv[pivot];
      inv[pivot] = t;
    }
    for (int row = 0; row < 32; row++) {
      if (row != col && (aug[row] & (1U << col))) {
        aug[row] ^= aug[col];
        inv[row] ^= inv[col];
      }
    }
  }
  return true;
}

static inline uint32_t png_crc_apply_inverse(const uint32_t inv[32],
                                             uint32_t value) {
  uint32_t out = 0;
  for (int bit = 0; bit < 32; bit++) {
    if (value & (1U << bit)) {
      out ^= inv[bit];
    }
  }
  return out;
}

static inline PNGGapWindowTable *png_gap_window_table_get(
    PNGCrcHashTable *ht, uint32_t M) {
  if (!ht || M == 0 || M > PNG_GAP_INDEX_MAX_M
      || !ht->actual_crc || !ht->actual_valid
      || ht->actual_count <= 0
      || (int64_t)M > ht->actual_count) {
    return NULL;
  }

  PNGGapWindowTable *cached = ht->gap_windows[M];
  if (cached) {
    return cached;
  }

  pthread_mutex_lock(&png_gap_window_lock);
  cached = ht->gap_windows[M];
  if (cached) {
    pthread_mutex_unlock(&png_gap_window_lock);
    return cached;
  }

  int64_t max_windows64 = ht->actual_count - (int64_t)M + 1;
  if (max_windows64 <= 0 || max_windows64 > UINT32_MAX) {
    pthread_mutex_unlock(&png_gap_window_lock);
    return NULL;
  }

  PNGGapWindowTable *gt = (PNGGapWindowTable *)calloc(1, sizeof(*gt));
  if (!gt) {
    pthread_mutex_unlock(&png_gap_window_lock);
    return NULL;
  }
  gt->buckets = (PNGGapWindowEntry **)calloc(PNG_GAP_WINDOW_BUCKETS,
      sizeof(PNGGapWindowEntry *));
  gt->pool = (PNGGapWindowEntry *)malloc(
      (size_t)max_windows64 * sizeof(PNGGapWindowEntry));
  gt->M = M;
  if (!gt->buckets || !gt->pool) {
    png_gap_window_table_free(gt);
    pthread_mutex_unlock(&png_gap_window_lock);
    return NULL;
  }

  uint32_t bs = scalpel_state.blocksize;
  uint32_t block_forward[32];
  png_crc_forward_for_len((z_off_t)bs, block_forward);
  for (int64_t start = 0; start < max_windows64; start++) {
    bool ok_window = true;
    uint32_t run_crc = crc32(0, NULL, 0);
    for (uint32_t f = 0; f < M; f++) {
      int64_t actual = start + (int64_t)f;
      if (!png_crc_actual_valid(ht, actual)) {
        ok_window = false;
        break;
      }
      run_crc = png_crc_apply_forward(block_forward, run_crc)
          ^ ht->actual_crc[actual];
    }
    if (!ok_window) {
      continue;
    }
    PNGGapWindowEntry *we = &gt->pool[gt->count++];
    we->crc = run_crc;
    we->start_actual = start;
    uint32_t idx = run_crc % PNG_GAP_WINDOW_BUCKETS;
    we->next = gt->buckets[idx];
    gt->buckets[idx] = we;
  }

  if (gt->count == 0) {
    png_gap_window_table_free(gt);
    pthread_mutex_unlock(&png_gap_window_lock);
    return NULL;
  }

  ht->gap_windows[M] = gt;
  pthread_mutex_unlock(&png_gap_window_lock);
  return gt;
}

// ---- CRC hash table construction (uses png_get_block_crc above) ----

static inline PNGCrcHashTable *png_build_crc_table(uint32_t png_needleidx) {
  PNGCrcHashTable *ht = (PNGCrcHashTable *)calloc(1, sizeof(PNGCrcHashTable));
  if (!ht) return NULL;
  png_crc_forward_for_len((z_off_t)scalpel_state.blocksize,
                          ht->block_forward);
  int64_t total = (int64_t)CEILDIV(filemirror_filesize(
      scalpel_state.filemirror), (uint64_t)scalpel_state.blocksize);
  if (total > 0) {
    ht->actual_count = total;
    ht->apparent_count = (int64_t)filemirror_apparent_blocks(
        scalpel_state.filemirror);
    ht->actual_crc = (uint32_t *)calloc((size_t)total,
        sizeof(uint32_t));
    ht->actual_valid = (unsigned char *)calloc((size_t)total,
        sizeof(unsigned char));
  }
  int64_t skipped_covered = 0;
  for (int64_t actual = 0; actual < total; actual++) {
    // Skip blocks already covered by validated files.  Coverage is monotonic,
    // so omitting these entries is safe; entries that become covered later are
    // filtered at use time rather than forcing a full table rebuild.
    if (filemirror_actual_block_covered(scalpel_state.filemirror, actual)) {
      skipped_covered++;
      continue;
    }
    // Get full PNGBlockState — contains CRC + structural markers.
    char hashkey[BLOCK_HASH_KEY_SIZE];
    if (!gen_block_hash_key(hashkey, png_needleidx, actual)) {
      continue;
    }
    PNGBlockState *bs = (PNGBlockState *)block_get_state(hashkey);
    if (!bs) {
      continue;
    }
    uint32_t crc = bs->block_crc;
    if (ht->actual_crc && ht->actual_valid) {
      ht->actual_crc[actual] = crc;
      ht->actual_valid[actual] = 1;
    }
    // Check if this actual block is already in the table
    // (dedup: multiple apparent blocks can map to same actual)
    bool dup = false;
    PNGCrcEntry *e = png_crc_table_find(ht, crc);
    while (e) {
      if (e->actual_block == actual) { dup = true; break; }
      e = png_crc_table_next(e, crc);
    }
    if (!dup) {
      png_crc_table_insert(ht, crc, actual, bs);
    }
    png_free_block_state((void **)&bs);
  }
  if (skipped_covered > 0) {
    lock_fprintf(stdout, "PNG CRC table: skipped %" PRId64 " covered blocks\n",
                 skipped_covered);
  }
  png_crc_marker_index_build(ht);
  return ht;
}

static inline PNGCrcHashTable *png_ensure_crc_table(uint32_t png_needleidx) {
  pthread_mutex_lock(&png_crc_table_lock);
  int64_t current_actual = scalpel_state.filemirror
      ? (int64_t)CEILDIV(filemirror_filesize(scalpel_state.filemirror),
                         (uint64_t)scalpel_state.blocksize) : 0;
  int64_t current_apparent = scalpel_state.filemirror
      ? (int64_t)filemirror_apparent_blocks(scalpel_state.filemirror) : 0;
  if (!png_global_crc_table || png_crc_table_needleidx != png_needleidx
      || png_global_crc_table->actual_count != current_actual) {
    if (png_global_crc_table) {
      png_crc_table_free(png_global_crc_table);
    }
    png_global_crc_table = png_build_crc_table(png_needleidx);
    png_crc_table_needleidx = png_needleidx;
    atomic_fetch_add_explicit(&png_crc_table_epoch, 1,
                              memory_order_acq_rel);
    if (png_global_crc_table) {
      lock_fprintf(stdout, "PNG CRC hash table built: %" PRId64 " entries\n",
                   png_global_crc_table->total_entries);
    }
  }
  else if (png_global_crc_table->apparent_count != current_apparent) {
    png_global_crc_table->apparent_count = current_apparent;
    atomic_fetch_add_explicit(&png_crc_table_epoch, 1,
                              memory_order_acq_rel);
  }
  pthread_mutex_unlock(&png_crc_table_lock);
  return png_global_crc_table;
}

// ---- Solver state snapshot / in-solver validation ----
//
// png_direct_validate() incrementally mutates CRC-tracking fields on
// PNGCarveState.  When the solver hits a spurious GF(2) CRC collision
// and the validator rejects the placement, we must roll those fields
// back or the caller's `last_chunk_crc_pos > first_idat_crc_pos` check
// wrongly fires and galloping starts on wrong data.  At 150+ file
// hash-table scale the spurious-match rate is ~1 per candidate, so a
// failure to roll back means the whole corpus gets stuck at Cat-4.
//
typedef struct PNGSolverStateSnapshot {
  uint64_t last_chunk_crc_pos;
  uint64_t last_idat_crc_pos;
  uint64_t prev_idat_crc_pos;
  uint64_t idat_crc_ring[IDAT_CRC_RING_SZ];
  int      idat_crc_ring_count;
  ulg      idat_stored_crc;
  uint64_t idat_data_start;
  long     idat_data_sz;
  bool     valid;
  bool     have_iend;
  /* Echo-fingerprint fields are restored on reject so a failed trial does
   * not poison the next solver placement attempt. */
  double   post_crc_corr_sum;
  uint32_t post_crc_corr_count;
  double   running_corr_sum;
  uint64_t corr_count;
  double   post_crc_mad_sum;
  uint32_t post_crc_mad_count;
  double   running_mad_sum;
  uint64_t mad_count;
  uint32_t consecutive_good_rows;
  /* Reassembly-private resume fields (review finding #5): the validator
   * call inside a trial can mutate these (D4 save path preserves them
   * now, but partial scan progress can still be written during the
   * call); on trial rejection, roll them back so next attempt sees the
   * pre-trial resume position, not a half-updated one from the rolled-
   * back trial.  solver_ctx is a heap pointer — not snapshotted. */
  int64_t  solver_suffix_idx;
  int64_t  solver_right_idx;
  int64_t  solver_right_idx2;
  uint64_t solver_suffix_nb;
  uint8_t  solver_phase;
  uint8_t  solver_pair_idx;
  uint16_t solver_phase_pad;
  uint64_t solver_m4_universe_hash;
  uint64_t solver_table_epoch;
  PNGM2ResumeState m2_resume;
  bool     gap_fast_resume_valid;
  bool     gap_fast_exhausted;
  uint32_t gap_fast_M;
  int64_t  gap_fast_si;
  int64_t  gap_fast_start;
  uint64_t gap_fast_suffix_nb;
  uint64_t gap_fast_crc_pos;
  bool     d1_resume_valid;
  uint32_t d1_resume_fpos;
  uint32_t d1_resume_bk;
  uint64_t d1_resume_crc_pos;
  uint64_t d1_resume_suffix_nb;
  uint32_t d1_resume_fill_needed;
} PNGSolverStateSnapshot;

static inline void png_solver_snapshot(PNGSolverStateSnapshot *snap,
                                        const PNGCarveState *local) {
  snap->last_chunk_crc_pos = local->last_chunk_crc_pos;
  snap->last_idat_crc_pos  = local->last_idat_crc_pos;
  snap->prev_idat_crc_pos  = local->prev_idat_crc_pos;
  memcpy(snap->idat_crc_ring, local->idat_crc_ring,
         sizeof(snap->idat_crc_ring));
  snap->idat_crc_ring_count  = local->idat_crc_ring_count;
  snap->idat_stored_crc      = local->idat_stored_crc;
  snap->idat_data_start      = local->idat_data_start;
  snap->idat_data_sz         = local->idat_data_sz;
  snap->valid                = local->valid;
  snap->have_iend            = local->have_iend;
  snap->post_crc_corr_sum    = local->post_crc_corr_sum;
  snap->post_crc_corr_count  = local->post_crc_corr_count;
  snap->running_corr_sum     = local->running_corr_sum;
  snap->corr_count           = local->corr_count;
  snap->post_crc_mad_sum     = local->post_crc_mad_sum;
  snap->post_crc_mad_count   = local->post_crc_mad_count;
  snap->running_mad_sum      = local->running_mad_sum;
  snap->mad_count            = local->mad_count;
  snap->consecutive_good_rows = local->consecutive_good_rows;
  snap->solver_suffix_idx    = local->solver_suffix_idx;
  snap->solver_right_idx     = local->solver_right_idx;
  snap->solver_right_idx2    = local->solver_right_idx2;
  snap->solver_suffix_nb     = local->solver_suffix_nb;
  snap->solver_phase         = local->solver_phase;
  snap->solver_pair_idx      = local->solver_pair_idx;
  snap->solver_phase_pad     = local->solver_phase_pad;
  snap->solver_m4_universe_hash = local->solver_m4_universe_hash;
  snap->solver_table_epoch   = local->solver_table_epoch;
  snap->m2_resume            = local->m2_resume;
  snap->gap_fast_resume_valid = local->gap_fast_resume_valid;
  snap->gap_fast_exhausted   = local->gap_fast_exhausted;
  snap->gap_fast_M           = local->gap_fast_M;
  snap->gap_fast_si          = local->gap_fast_si;
  snap->gap_fast_start       = local->gap_fast_start;
  snap->gap_fast_suffix_nb   = local->gap_fast_suffix_nb;
  snap->gap_fast_crc_pos     = local->gap_fast_crc_pos;
  snap->d1_resume_valid      = local->d1_resume_valid;
  snap->d1_resume_fpos       = local->d1_resume_fpos;
  snap->d1_resume_bk         = local->d1_resume_bk;
  snap->d1_resume_crc_pos    = local->d1_resume_crc_pos;
  snap->d1_resume_suffix_nb  = local->d1_resume_suffix_nb;
  snap->d1_resume_fill_needed = local->d1_resume_fill_needed;
}

static inline void png_solver_restore(PNGCarveState *local,
                                       const PNGSolverStateSnapshot *snap) {
  local->last_chunk_crc_pos = snap->last_chunk_crc_pos;
  local->last_idat_crc_pos  = snap->last_idat_crc_pos;
  local->prev_idat_crc_pos  = snap->prev_idat_crc_pos;
  memcpy(local->idat_crc_ring, snap->idat_crc_ring,
         sizeof(local->idat_crc_ring));
  local->idat_crc_ring_count  = snap->idat_crc_ring_count;
  local->idat_stored_crc      = snap->idat_stored_crc;
  local->idat_data_start      = snap->idat_data_start;
  local->idat_data_sz         = snap->idat_data_sz;
  local->valid                = snap->valid;
  local->have_iend            = snap->have_iend;
  local->post_crc_corr_sum    = snap->post_crc_corr_sum;
  local->post_crc_corr_count  = snap->post_crc_corr_count;
  local->running_corr_sum     = snap->running_corr_sum;
  local->corr_count           = snap->corr_count;
  local->post_crc_mad_sum     = snap->post_crc_mad_sum;
  local->post_crc_mad_count   = snap->post_crc_mad_count;
  local->running_mad_sum      = snap->running_mad_sum;
  local->mad_count            = snap->mad_count;
  local->consecutive_good_rows = snap->consecutive_good_rows;
  local->solver_suffix_idx    = snap->solver_suffix_idx;
  local->solver_right_idx     = snap->solver_right_idx;
  local->solver_right_idx2    = snap->solver_right_idx2;
  local->solver_suffix_nb     = snap->solver_suffix_nb;
  local->solver_phase         = snap->solver_phase;
  local->solver_pair_idx      = snap->solver_pair_idx;
  local->solver_phase_pad     = snap->solver_phase_pad;
  local->solver_m4_universe_hash = snap->solver_m4_universe_hash;
  local->solver_table_epoch   = snap->solver_table_epoch;
  local->m2_resume            = snap->m2_resume;
  local->gap_fast_resume_valid = snap->gap_fast_resume_valid;
  local->gap_fast_exhausted   = snap->gap_fast_exhausted;
  local->gap_fast_M           = snap->gap_fast_M;
  local->gap_fast_si          = snap->gap_fast_si;
  local->gap_fast_start       = snap->gap_fast_start;
  local->gap_fast_suffix_nb   = snap->gap_fast_suffix_nb;
  local->gap_fast_crc_pos     = snap->gap_fast_crc_pos;
  local->d1_resume_valid      = snap->d1_resume_valid;
  local->d1_resume_fpos       = snap->d1_resume_fpos;
  local->d1_resume_bk         = snap->d1_resume_bk;
  local->d1_resume_crc_pos    = snap->d1_resume_crc_pos;
  local->d1_resume_suffix_nb  = snap->d1_resume_suffix_nb;
  local->d1_resume_fill_needed = snap->d1_resume_fill_needed;
}

// png_solver_confirm_match — validate a solver placement and roll back
// on rejection.  Accept criteria: validator approves the whole file OR
// the validator's CRC scan walked past the END of the IDAT we just
// solved (crc_pos + 12 + idat_sz).  The "past this specific IDAT" check
// is stricter than the older "> pre-validation _cp" pattern — a spurious
// CRC collision that advances _last_chunk_crc_pos_ before _crc_pos_
// (e.g., an earlier chunk that happens to parse) would slip past the
// looser check but fails this one.
//
// On accept: state stays committed, return true.
// On reject: state restored to pre-validate snapshot, return false.
// The caller is responsible for any BV rollback.
//
// Strict mode: require full validation (_sv == true).  Use for the
// GAP fast path which at scale produces 200+ "echo" spurious matches
// (LZ77 back-refs satisfying filter/Paeth gates) per stuck-N file,
// each passing CRC.  Lenient mode accepts when CRC advances past this
// IDAT; sufficient for strictly-algebraic solvers (M=3/M=4 MitM)
// whose combinatorics already limit false-positive rate.
static inline bool png_solver_confirm_match_strict(
    CarveInfo *candidate, PNGCarveState *local,
    ThreadWork *work, uuid_string_t uuidp, uuid_string_t uuidc) {
  PNGSolverStateSnapshot snap;
  png_solver_snapshot(&snap, local);

  uint64_t vt;
  bool validated = png_direct_validate(work->id, candidate, &vt,
      local, uuidp, uuidc);
  if (validated) {
    return true;
  }
  png_solver_restore(local, &snap);
  return false;
}

static inline bool png_solver_confirm_match(
    CarveInfo *candidate, PNGCarveState *local,
    ThreadWork *work, uuid_string_t uuidp, uuid_string_t uuidc,
    uint64_t crc_pos, long idat_sz) {
  PNGSolverStateSnapshot snap;
  png_solver_snapshot(&snap, local);

  uint64_t vt;
  bool validated = png_direct_validate(work->id, candidate, &vt,
      local, uuidp, uuidc);
  if (validated) {
    return true;
  }

  uint64_t target = crc_pos + 12 + (uint64_t)idat_sz;
  if (idat_sz > 0 && local->last_chunk_crc_pos >= target) {
    // Full validation rejected.  That's normal for multi-IDAT files where
    // later IDATs still have wrong blocks at this solve iteration.  Accept
    // only if the validator actually walked past the IDAT solved here.
    return true;
  }

  png_solver_restore(local, &snap);
  return false;
}

static inline bool png_solver_crc_marker_matches(
    CarveInfo *candidate, uint64_t type_start, uint64_t crc_region_len,
    uint64_t crc_field_pos, uint32_t stored_crc) {
  const char *vd = blockvector_get_data_pointer(candidate->b);
  uint64_t vdl = blockvector_get_data_length(candidate->b);
  if (!vd || crc_field_pos + 12 > vdl) {
    return false;
  }

  uint32_t vcrc = crc32(0, NULL, 0);
  vcrc = crc32(vcrc, (const unsigned char *)(vd + type_start),
      (uInt)crc_region_len);
  if (vcrc != stored_crc) {
    return false;
  }

  uint64_t next_type_pos = crc_field_pos + 8;
  if (next_type_pos + 4 > vdl) {
    return false;
  }
  const unsigned char *tp =
      (const unsigned char *)(vd + next_type_pos);
  const unsigned char *lp =
      (const unsigned char *)(vd + crc_field_pos + 4);
  uint32_t next_len = ((uint32_t)lp[0] << 24)
      | ((uint32_t)lp[1] << 16)
      | ((uint32_t)lp[2] << 8) | (uint32_t)lp[3];

  if (tp[0] == 'I' && tp[1] == 'D' && tp[2] == 'A' && tp[3] == 'T') {
    return next_len <= PNG_MAX_IDAT_BODY_LEN;
  }
  if (tp[0] == 'I' && tp[1] == 'E' && tp[2] == 'N' && tp[3] == 'D'
      && next_len == 0) {
    if (next_type_pos + 8 <= vdl) {
      const unsigned char *ic =
          (const unsigned char *)(vd + next_type_pos + 4);
      uint32_t icrc = ((uint32_t)ic[0] << 24)
          | ((uint32_t)ic[1] << 16)
          | ((uint32_t)ic[2] << 8) | (uint32_t)ic[3];
      return icrc == 0xAE426082U;
    }
    return true;
  }
  return false;
}

static inline uint32_t png_gap_locality_score(CarveInfo *candidate,
                                               uint64_t suffix_start_nb,
                                               uint32_t first_full,
                                               const int64_t *window_ap,
                                               uint32_t M) {
  if (!candidate || !candidate->b || !window_ap || suffix_start_nb == 0) {
    return 0;
  }

  int64_t prefix_actual = blockvector_get_actual_blocknumber(candidate->b,
      suffix_start_nb - 1);
  if (prefix_actual < 0) {
    return 0;
  }

  uint32_t score = 0;
  for (uint32_t f = 0; f < M; f++) {
    int64_t actual = filemirror_actual_blocknumber(scalpel_state.filemirror,
        window_ap[f]);
    int64_t expected = prefix_actual + 1 + (int64_t)first_full + (int64_t)f;
    if (actual == expected) {
      score++;
    }
  }
  return score;
}

static inline uint32_t png_gap_contiguous_locality_score(
    CarveInfo *candidate, uint64_t suffix_start_nb, uint32_t first_full,
    int64_t window_start_ap, uint32_t M) {
  if (!candidate || !candidate->b || suffix_start_nb == 0
      || window_start_ap < 0) {
    return 0;
  }

  int64_t prefix_actual = blockvector_get_actual_blocknumber(candidate->b,
      suffix_start_nb - 1);
  if (prefix_actual < 0) {
    return 0;
  }

  uint32_t score = 0;
  for (uint32_t f = 0; f < M; f++) {
    int64_t actual = filemirror_actual_blocknumber(scalpel_state.filemirror,
        window_start_ap + (int64_t)f);
    int64_t expected = prefix_actual + 1 + (int64_t)first_full + (int64_t)f;
    if (actual == expected) {
      score++;
    }
  }
  return score;
}

static inline bool png_gap_match_better(bool validated, uint64_t validates_to,
                                         uint64_t advance_to,
                                         uint32_t locality,
                                         bool best_found,
                                         bool best_validated,
                                         uint64_t best_validates_to,
                                         uint64_t best_advance_to,
                                         uint32_t best_locality) {
  if (!best_found) {
    return true;
  }
  if (validated != best_validated) {
    return validated;
  }
  if (validates_to != best_validates_to) {
    return validates_to > best_validates_to;
  }
  if (advance_to != best_advance_to) {
    return advance_to > best_advance_to;
  }
  return locality > best_locality;
}

static inline void png_solver_resize_trial(CarveInfo *candidate,
                                            uint64_t num_blocks) {
  resize_blockvector(candidate->b, num_blocks);
  blockvector_set_data_length(candidate->b,
      num_blocks * (uint64_t)scalpel_state.blocksize);
}

// ---- IDAT CRC solver ----
// Given the IDAT boundary info and a set of K block positions to fill,
// use the CRC hash table to find displaced blocks algebraically.
//
// For F=1 (one missing middle block): compute required CRC, hash lookup.
// For F=2: iterate one, compute required CRC for other, hash lookup.
//
// png_crc_solve_idat — algebraic IDAT solver using CRC hash table.
//
// Given an IDAT chunk at crc_pos with body size idat_sz:
// 1. Classify fill blocks as prefix-boundary, full-middle, suffix-boundary
// 2. Compute prefix CRC from verified BV data
// 3. Precompute suffix candidates (inflate, read stored CRC, partial CRC)
// 4. MitM on full middle blocks with GF(2) inverse
// 5. For each MitM match + suffix candidate: full CRC verify
//
// Returns true if solved (blocks placed in BV).
// Returns: 0 = not found, 1 = contiguous fast path (definitive),
//          2 = algebraic MitM match (needs validation).
static inline int png_crc_solve_idat(
    CarveInfo *candidate, PNGCarveState *local,
    uint64_t suffix_start_nb, uint32_t fill_needed,
    int64_t last_block, int64_t total_apparent,
    uint64_t crc_pos, long idat_sz,
    ThreadWork *work, uuid_string_t uuidp, uuid_string_t uuidc) {
  static int64_t png_trace_start_block = -2;
  if (png_trace_start_block == -2) {
    const char *trace_env = getenv("SCALPEL_PNG_TRACE_STARTBLOCK");
    png_trace_start_block = trace_env ? strtoll(trace_env, NULL, 10) : -1;
  }
  static int64_t png_trace_actual_block = -2;
  if (png_trace_actual_block == -2) {
    const char *trace_actual_env = getenv("SCALPEL_PNG_TRACE_ACTUAL");
    png_trace_actual_block = trace_actual_env
        ? strtoll(trace_actual_env, NULL, 10) : -1;
  }
  bool png_trace_this = false;
  if (png_trace_start_block >= 0 && candidate && candidate->b
      && blockvector_get_num_blocks(candidate->b) > 0) {
    png_trace_this = blockvector_get_actual_blocknumber(candidate->b, 0)
        == png_trace_start_block;
  }

  if (fill_needed == 0 || idat_sz <= 0) {
    return 0;
  }
  uint32_t bs = scalpel_state.blocksize;
  if (bs == 0) {
    return 0;
  }
  if (total_apparent <= 0 || last_block < -1
      || (uint64_t)fill_needed > (uint64_t)total_apparent
      || last_block >= total_apparent - (int64_t)fill_needed) {
    return 0;
  }

  /* Build "block X is already in BV prefix" lookup so MitM/GAP don't
   * place a block that duplicates one already in the candidate's prefix.
   * Fixed-size stack array (cheapest — no heap, no free path) sized for
   * typical PNG prefix lengths; truncate and skip lookup for unusually
   * large prefixes. */
  #define PNG_SOLVER_PREFIX_MAX 4096
  int64_t _prefix_ab[PNG_SOLVER_PREFIX_MAX];
  uint64_t _prefix_ab_count = 0;
  bool _prefix_ab_usable = false;
  if (suffix_start_nb > 0 && suffix_start_nb <= PNG_SOLVER_PREFIX_MAX
      && candidate && candidate->b) {
    for (uint64_t _i = 0; _i < suffix_start_nb; _i++) {
      int64_t _ab = blockvector_get_apparent_blocknumber(
          candidate->b, _i);
      if (_ab >= 0) {
        _prefix_ab[_prefix_ab_count++] = _ab;
      }
    }
    /* insertion-sort ascending for binary search */
    for (uint64_t _i = 1; _i < _prefix_ab_count; _i++) {
      int64_t _v = _prefix_ab[_i];
      uint64_t _j = _i;
      while (_j > 0 && _prefix_ab[_j - 1] > _v) {
        _prefix_ab[_j] = _prefix_ab[_j - 1]; _j--;
      }
      _prefix_ab[_j] = _v;
    }
    _prefix_ab_usable = true;
  }
  #define _AB_IN_BV_PREFIX(_ab) ({ \
    bool _hit = false; \
    if (_prefix_ab_usable && _prefix_ab_count > 0) { \
      uint64_t _lo = 0, _hi = _prefix_ab_count; \
      while (_lo < _hi) { \
        uint64_t _mi = (_lo + _hi) / 2; \
        if (_prefix_ab[_mi] == (int64_t)(_ab)) { _hit = true; break; } \
        if (_prefix_ab[_mi] < (int64_t)(_ab)) _lo = _mi + 1; \
        else _hi = _mi; \
      } \
    } \
    _hit; })

  PNGCrcHashTable *ht = png_ensure_crc_table(candidate->needleidx);
  if (!ht || ht->total_entries == 0) {
    return 0;
  }
  uint64_t table_epoch = atomic_load_explicit(&png_crc_table_epoch,
                                              memory_order_acquire);
  if (local->solver_table_epoch != table_epoch) {
    png_reassembly_search_resume_reset(local);
    local->solver_table_epoch = table_epoch;
  }

  if (scalpel_state.mode_verbose) {
    lock_fprintf(stdout,
        "PNG_SOLVE_ENTRY snb=%" PRIu64 " crc_pos=%" PRIu64
        " idat_sz=%ld fn=%u total_ap=%" PRId64 " ht=%" PRId64
        " gap_exhausted=%d d1_valid=%d\n",
        suffix_start_nb, crc_pos, idat_sz, fill_needed,
        (int64_t)filemirror_apparent_blocks(scalpel_state.filemirror),
        ht->total_entries,
        local->gap_fast_exhausted ? 1 : 0,
        local->d1_resume_valid ? 1 : 0);
  }

  // CRC region geometry.
  // PNG CRC covers: type (4 bytes "IDAT") + body (idat_sz bytes).
  // crc_pos = start of chunk (length field).
  uint64_t type_start = crc_pos + 4;
  uint64_t crc_region_len = 4 + (uint64_t)idat_sz;
  uint64_t crc_region_end = type_start + crc_region_len;
  uint64_t crc_field_pos = crc_region_end;  // stored CRC starts here

  // Step 1: Classify fill blocks.
  // Identify full middle blocks (entirely within CRC region)
  // and boundary blocks (partial overlap).
  uint32_t first_full = fill_needed;   // index of first full middle block
  uint32_t last_full_plus1 = 0;        // index past last full middle block
  for (uint32_t f = 0; f < fill_needed; f++) {
    uint64_t fb_start = (suffix_start_nb + f) * (uint64_t)bs;
    uint64_t fb_end = fb_start + bs;
    if (fb_start >= type_start && fb_end <= crc_region_end) {
      if (f < first_full) {
        first_full = f;
      }
      last_full_plus1 = f + 1;
    }
  }
  uint32_t M = (last_full_plus1 > first_full)
      ? (last_full_plus1 - first_full) : 0;

  if (png_trace_this) {
    lock_fprintf(stdout,
        "PNG_TRACE start=%" PRId64 " snb=%" PRIu64 " fill=%u"
        " last=%" PRId64 " crc_pos=%" PRIu64 " idat=%ld"
        " first_full=%u last_full_plus1=%u M=%u\n",
        png_trace_start_block, suffix_start_nb, fill_needed, last_block,
        crc_pos, idat_sz, first_full, last_full_plus1, M);
  }

  if (M < 1) {
    // No full middle blocks — can't use algebraic hash table approach.
    // Fall back to direct CRC search for small IDATs.
    // Place contiguous fill and check CRC
    png_solver_resize_trial(candidate, suffix_start_nb + fill_needed);
    for (uint32_t f = 0; f < fill_needed; f++) {
      int64_t ab = last_block + 1 + (int64_t)f;
      blockvector_set_apparent_blocknumber(candidate->b,
          suffix_start_nb + f, ab);
      inflate_blockvector_single_block(candidate->b, suffix_start_nb + f);
    }
    // Contiguous CRC check
    {
      const char *d0 = blockvector_get_data_pointer(candidate->b);
      uint64_t dl0 = blockvector_get_data_length(candidate->b);
      if (crc_field_pos + 4 <= dl0) {
        uint32_t c0 = crc32(0, NULL, 0);
        c0 = crc32(c0, (const unsigned char *)(d0 + type_start),
                   (uInt)crc_region_len);
        const unsigned char *e0p = (const unsigned char *)(d0 + crc_field_pos);
	        uint32_t s0 = ((uint32_t)e0p[0] << 24) | ((uint32_t)e0p[1] << 16)
	                     | ((uint32_t)e0p[2] << 8) | (uint32_t)e0p[3];
	        if (c0 == s0
	            && png_solver_crc_marker_matches(candidate, type_start,
	                crc_region_len, crc_field_pos, s0)
	            && png_solver_confirm_match(candidate, local, work,
	                uuidp, uuidc, crc_pos, idat_sz)) {
	          return 1;  /* contiguous fast path */
	        }
	      }
    }
    // D=1 algebraic search: for each fill position, compute the needed
    // partial CRC via GF(2) algebra, scan candidates using mmap partial
    // reads.  For positions containing the stored CRC bytes, read both
    // the partial data AND the stored CRC from each candidate.
    // O(N × partial_len) mmap reads instead of O(N × bs) inflates.
    {
      const char *_d0 = blockvector_get_data_pointer(candidate->b);
      uint64_t _dl0 = blockvector_get_data_length(candidate->b);
      uint32_t _cont = crc32(0, NULL, 0);
      if (type_start + crc_region_len <= _dl0) {
        _cont = crc32(_cont, (const unsigned char *)(_d0 + type_start),
                       (uInt)crc_region_len);
      }
      const unsigned char *_sep = (const unsigned char *)(_d0 + crc_field_pos);
      uint32_t _sto = ((uint32_t)_sep[0] << 24) | ((uint32_t)_sep[1] << 16)
          | ((uint32_t)_sep[2] << 8) | (uint32_t)_sep[3];
      uint32_t _diff = _sto ^ _cont;

      // Resume D=1 from saved position (direct PNGCarveState fields so
      // the solver_ctx free/rebuild doesn't wipe our progress).
      uint32_t d1_start_fpos = 0;
      uint32_t d1_start_bk = 0;
      if (local->d1_resume_valid
          && local->d1_resume_crc_pos == crc_pos
          && local->d1_resume_suffix_nb == suffix_start_nb
          && local->d1_resume_fill_needed == fill_needed) {
        d1_start_fpos = local->d1_resume_fpos;
        d1_start_bk = local->d1_resume_bk;
      } else {
        local->d1_resume_valid = false;
      }

      for (uint32_t fpos = d1_start_fpos; fpos < fill_needed && _diff != 0; fpos++) {
        uint64_t _bs_s = (suffix_start_nb + fpos) * (uint64_t)bs;
        uint64_t _be = _bs_s + (uint64_t)bs;
        uint64_t _cs = (_bs_s > type_start) ? _bs_s : type_start;
        uint64_t _ce = (_be < crc_region_end) ? _be : crc_region_end;
        uint64_t _cl = (_cs < _ce) ? _ce - _cs : 0;
        uint64_t _al = (_ce < crc_region_end) ? crc_region_end - _ce : 0;
        uint64_t _lo = _cs - _bs_s;
        if (_cl == 0) { continue; }

        // Does this position contain the stored CRC bytes?
        bool has_crc_field = (crc_field_pos >= _bs_s && crc_field_pos < _be);
        uint64_t crc_off_in_blk = crc_field_pos - _bs_s;

        uint32_t _wr = crc32(0, NULL, 0);
        _wr = crc32(_wr, (const unsigned char *)(_d0 + _cs), (uInt)_cl);

        uint32_t _Minv[32];
        if (!png_crc_inverse_for_len((z_off_t)_al, _Minv)) {
          continue;
        }

        uint32_t _delta = png_crc_apply_inverse(_Minv, _diff);
        uint32_t _needed = _wr ^ _delta;

        int64_t _sab = blockvector_get_apparent_blocknumber(
            candidate->b, suffix_start_nb + fpos);
        // Read buffer: partial data + optional CRC + structural bytes
        uint32_t read_len = (uint32_t)_cl;
        if (has_crc_field && crc_off_in_blk + 12 <= (uint64_t)bs) {
          // Also read stored CRC (4) + next chunk len (4) + type (4) = 12 bytes
          uint32_t end_needed = (uint32_t)(crc_off_in_blk + 12);
          if (end_needed > read_len + (uint32_t)_lo) { read_len = end_needed - (uint32_t)_lo; }
        }
        unsigned char *_pb = (unsigned char *)malloc((size_t)(read_len > _cl ? read_len : _cl));
        if (! _pb) { continue; }

        // Full-block-aligned fast path: when the fill position covers an
        // entire block within the CRC region (_cl == bs && _lo == 0), the
        // partial CRC equals the pre-computed full-block CRC in e->crc.
        // Skip all disk reads and compare directly.
        bool full_block_aligned = (_cl == (uint64_t)bs && _lo == 0);

        uint32_t bk_init = (fpos == d1_start_fpos) ? d1_start_bk : 0;
        for (uint32_t bk = bk_init; bk < PNG_CRC_HASH_BUCKETS; bk++) {
          if ((bk & 0xFF) == 0
              && png_reassembly_yield_requested(candidate)) {
            // Save D=1 resume state in PNGCarveState direct fields.
            local->d1_resume_valid = true;
            local->d1_resume_fpos = fpos;
            local->d1_resume_bk = bk;
            local->d1_resume_crc_pos = crc_pos;
            local->d1_resume_suffix_nb = suffix_start_nb;
            local->d1_resume_fill_needed = fill_needed;
            free(_pb);
            resize_blockvector(candidate->b, suffix_start_nb);
            return -1;
          }
          for (PNGCrcEntry *e = ht->buckets[bk]; e; e = e->next) {
            if (filemirror_actual_block_covered(scalpel_state.filemirror,
                    e->actual_block)) { continue; }
            int64_t ab = filemirror_apparent_blocknumber(
                scalpel_state.filemirror, e->actual_block);
            if (ab < 0 || ab == _sab) { continue; }

            // Structural pre-filter for CRC-field positions: the block must
            // have IDAT or IEND at the expected structural offset. Use cached
            // markers — zero disk reads.
            if (has_crc_field) {
              uint32_t type_pos = (uint32_t)(crc_off_in_blk + 8);
              bool has_marker = false;
              for (uint8_t mi = 0; mi < e->num_idat_markers; mi++) {
                if (e->idat_offsets[mi] == type_pos) {
                  has_marker = true;
                  break;
                }
              }
              if (!has_marker && e->has_iend && e->iend_offset == type_pos) {
                has_marker = true;
              }
              if (!has_marker) { continue; }
            }

            uint32_t pc;
            if (full_block_aligned && !has_crc_field) {
              // Zero-I/O fast path: use pre-computed block CRC.
              pc = e->crc;
              if (pc != _needed) { continue; }
            }
            else {
              if (! get_apparent_block_bytes(scalpel_state.filemirror,
                      ab, _lo, (uint32_t)_cl, _pb)) { continue; }
              pc = crc32(0, NULL, 0);
              pc = crc32(pc, _pb, (uInt)_cl);

              if (has_crc_field) {
                // For CRC-field positions: the stored CRC comes from THIS
                // candidate. Read it and compute what the full CRC would be.
                unsigned char crc_bytes[4];
                if (! get_apparent_block_bytes(scalpel_state.filemirror,
                        ab, crc_off_in_blk, 4, crc_bytes)) { continue; }
                uint32_t cand_stored = ((uint32_t)crc_bytes[0] << 24)
                    | ((uint32_t)crc_bytes[1] << 16)
                    | ((uint32_t)crc_bytes[2] << 8) | (uint32_t)crc_bytes[3];
                uint32_t cand_diff = cand_stored ^ _cont;
                uint32_t cand_delta = 0;
                for (int b2 = 0; b2 < 32; b2++) {
                  if (cand_diff & (1U << b2)) { cand_delta ^= _Minv[b2]; }
                }
                if (pc != (_wr ^ cand_delta)) { continue; }
              }
              else {
                if (pc != _needed) { continue; }
              }
            }

            // Algebraic match — inflate and full verify
            blockvector_set_apparent_blocknumber(candidate->b,
                suffix_start_nb + fpos, ab);
            inflate_blockvector_single_block(candidate->b,
                suffix_start_nb + fpos);
            const char *vd = blockvector_get_data_pointer(candidate->b);
            uint64_t vdl = blockvector_get_data_length(candidate->b);
            if (crc_field_pos + 4 <= vdl) {
              uint32_t vc = crc32(0, NULL, 0);
              vc = crc32(vc, (const unsigned char *)(vd + type_start),
                         (uInt)crc_region_len);
              const unsigned char *ep =
                  (const unsigned char *)(vd + crc_field_pos);
              uint32_t vs = ((uint32_t)ep[0] << 24) | ((uint32_t)ep[1] << 16)
                  | ((uint32_t)ep[2] << 8) | (uint32_t)ep[3];
              if (vc == vs) {
                bool sok = false;
                uint64_t nxt = crc_field_pos + 8;
                if (nxt + 4 <= vdl) {
                  const unsigned char *tp = (const unsigned char *)(vd + nxt);
                  const unsigned char *lp = (const unsigned char *)(vd + crc_field_pos + 4);
                  uint32_t nl = ((uint32_t)lp[0] << 24) | ((uint32_t)lp[1] << 16)
                      | ((uint32_t)lp[2] << 8) | (uint32_t)lp[3];
                  if (tp[0]=='I' && tp[1]=='D' && tp[2]=='A' && tp[3]=='T'
                      && nl <= PNG_MAX_IDAT_BODY_LEN) { sok = true; }
                  else if (tp[0]=='I' && tp[1]=='E' && tp[2]=='N'
                           && tp[3]=='D' && nl == 0 && nxt + 8 <= vdl) {
                    const unsigned char *ic = (const unsigned char *)(vd + nxt + 4);
                    uint32_t icrc = ((uint32_t)ic[0] << 24) | ((uint32_t)ic[1] << 16)
                        | ((uint32_t)ic[2] << 8) | (uint32_t)ic[3];
                    if (icrc == 0xAE426082U) { sok = true; }
                  }
                }
                if (sok) {
                  // Validate before committing — structural-check + CRC
                  // alone is not enough at scale.  See
                  // png_solver_confirm_match rationale.
                  if (png_solver_confirm_match(candidate, local, work,
                          uuidp, uuidc, crc_pos, idat_sz)) {
                    free(_pb);
                    return 2;
                  }
                  // Rejected — fall through to restore and keep scanning.
                }
              }
            }
            blockvector_set_apparent_blocknumber(candidate->b,
                suffix_start_nb + fpos, _sab);
            inflate_blockvector_single_block(candidate->b,
                suffix_start_nb + fpos);
          }
        }
        free(_pb);
      }
      // D=1 scan completed (either solved above or exhausted).  Clear
      // resume state so stale fpos/bk don't get re-applied to a later
      // IDAT's solve.
      local->d1_resume_valid = false;
    }
    resize_blockvector(candidate->b, suffix_start_nb);
    return 0;
  }

  // Step 2: Place contiguous blocks and inflate (need BV data for boundaries).
  png_solver_resize_trial(candidate, suffix_start_nb + fill_needed);
  for (uint32_t f = 0; f < fill_needed; f++) {
    int64_t ab = last_block + 1 + (int64_t)f;
    blockvector_set_apparent_blocknumber(candidate->b, suffix_start_nb + f, ab);
    inflate_blockvector_single_block(candidate->b, suffix_start_nb + f);
  }

  const char *data = blockvector_get_data_pointer(candidate->b);
  uint64_t dl = blockvector_get_data_length(candidate->b);

  // Check contiguous fill first.  Save CRC values for algebraic solver.
  uint32_t contig_crc = 0;
  uint32_t bv_stored_crc = 0;
  if (crc_field_pos + 4 <= dl) {
    contig_crc = crc32(0, NULL, 0);
    contig_crc = crc32(contig_crc, (const unsigned char *)(data + type_start),
                  (uInt)crc_region_len);
    const unsigned char *ep = (const unsigned char *)(data + crc_field_pos);
	    bv_stored_crc = ((uint32_t)ep[0] << 24) | ((uint32_t)ep[1] << 16)
	                   | ((uint32_t)ep[2] << 8) | (uint32_t)ep[3];
	    if (contig_crc == bv_stored_crc
	        && png_solver_crc_marker_matches(candidate, type_start,
	            crc_region_len, crc_field_pos, bv_stored_crc)
	        && png_solver_confirm_match_strict(candidate, local, work,
	            uuidp, uuidc)) {
	      return 1;  /* contiguous fast path */
	    }
	  }

  // Compute prefix CRC: data from type_start to start of first full middle block.
  uint64_t first_full_byte = (suffix_start_nb + first_full) * (uint64_t)bs;
  uint64_t prefix_partial_len = first_full_byte - type_start;
  uint32_t crc_prefix = crc32(0, NULL, 0);
  if (prefix_partial_len > 0 && type_start + prefix_partial_len <= dl) {
    crc_prefix = crc32(crc_prefix,
        (const unsigned char *)(data + type_start),
        (uInt)prefix_partial_len);
  }

  // Suffix geometry: bytes from end of last full middle block to end of CRC region.
  uint64_t last_full_end = (suffix_start_nb + last_full_plus1) * (uint64_t)bs;
  uint64_t suffix_partial_len = (crc_region_end > last_full_end)
      ? (crc_region_end - last_full_end) : 0;

  // The suffix block (fill position last_full_plus1 or later) contains both
  // the end of the IDAT body AND the stored CRC bytes.
  // We need to iterate suffix candidates, inflate each to get:
  //   (a) the stored CRC bytes
  //   (b) the partial body data CRC contribution
  // Determine which fill position contains the stored CRC.
  uint32_t suffix_fill_pos = fill_needed - 1;  // last fill block
  uint64_t suffix_block_start = (suffix_start_nb + suffix_fill_pos) * (uint64_t)bs;

  // Offsets within the suffix block for the data we need:
  // - CRC field: crc_field_pos - suffix_block_start
  // - Structural check: 8 bytes after CRC field (next chunk len+type)
  // - Partial body: from (last_full_end - suffix_block_start) for suffix_partial_len bytes
  bool crc_in_suffix = (crc_field_pos >= suffix_block_start
      && crc_field_pos + 4 <= suffix_block_start + bs);
  uint64_t crc_off_in_blk = crc_in_suffix ? (crc_field_pos - suffix_block_start) : 0;
  uint64_t struct_off = crc_in_suffix ? (crc_field_pos + 4 - suffix_block_start) : 0;
  bool body_in_suffix = (suffix_partial_len > 0
      && last_full_end >= suffix_block_start
      && last_full_end + suffix_partial_len <= suffix_block_start + bs);
  uint64_t body_off = body_in_suffix ? (last_full_end - suffix_block_start) : 0;
  uint32_t suffix_type_pos = crc_in_suffix ? (uint32_t)(struct_off + 4) : 0;

  // Precompute suffix candidate data.  When the suffix block contains the
  // stored CRC, it must also contain an IDAT/IEND marker at suffix_type_pos;
  // use the global marker-offset index instead of scanning every CRC entry.
  int64_t suffix_cand_count = 0;
  bool use_marker_index = crc_in_suffix && ht->marker_buckets;
  if (use_marker_index) {
    for (PNGMarkerEntry *m = png_crc_marker_find(ht, suffix_type_pos);
         m; m = png_crc_marker_next(m, suffix_type_pos)) {
      suffix_cand_count++;
    }
  }
  else {
    for (uint32_t b = 0; b < PNG_CRC_HASH_BUCKETS; b++) {
      for (PNGCrcEntry *e = ht->buckets[b]; e; e = e->next) {
        suffix_cand_count++;
      }
    }
  }
  if (suffix_cand_count == 0) {
    resize_blockvector(candidate->b, suffix_start_nb);
    return 0;
  }

  PNGSuffixCand *suffix_cands = (PNGSuffixCand *)calloc(
      (size_t)suffix_cand_count, sizeof(PNGSuffixCand));
  if (!suffix_cands) {
    resize_blockvector(candidate->b, suffix_start_nb);
    return 0;
  }

  int64_t sc_idx = 0;
  if (use_marker_index) {
    for (PNGMarkerEntry *m = png_crc_marker_find(ht, suffix_type_pos);
         m && sc_idx < suffix_cand_count;
         m = png_crc_marker_next(m, suffix_type_pos)) {
      PNGSuffixCand sc;
      if (png_suffix_candidate_from_entry(&sc, m->entry, candidate,
              false, suffix_type_pos, crc_in_suffix, crc_off_in_blk,
              body_in_suffix, body_off, suffix_partial_len, crc_field_pos)) {
        suffix_cands[sc_idx++] = sc;
      }
    }
  }
  else {
    for (uint32_t b = 0; b < PNG_CRC_HASH_BUCKETS; b++) {
      for (PNGCrcEntry *e = ht->buckets[b]; e; e = e->next) {
        PNGSuffixCand sc;
        if (png_suffix_candidate_from_entry(&sc, e, candidate,
                crc_in_suffix, suffix_type_pos, crc_in_suffix,
                crc_off_in_blk, body_in_suffix, body_off,
                suffix_partial_len, crc_field_pos)) {
          suffix_cands[sc_idx++] = sc;
        }
      }
    }
  }
  suffix_cand_count = sc_idx;

  // Keep only viable structural suffix candidates.  The initial allocation is
  // sized to the full CRC table for simple traversal, but leaving invalid
  // entries in the active count makes every solver phase scan hundreds of
  // thousands of non-suffix blocks before reaching the few real candidates.
  int64_t suffix_valid_count = 0;
  for (int64_t i = 0; i < suffix_cand_count; i++) {
    PNGSuffixCand *sc = &suffix_cands[i];
    if (!sc->valid || sc->apparent_block < 0
        || filemirror_actual_block_covered(scalpel_state.filemirror,
            sc->actual_block)
        || _AB_IN_BV_PREFIX(sc->apparent_block)) {
      continue;
    }
    if (suffix_valid_count != i) {
      suffix_cands[suffix_valid_count] = *sc;
    }
    suffix_valid_count++;
  }
  suffix_cand_count = suffix_valid_count;
  if (png_trace_this) {
    lock_fprintf(stdout,
        "PNG_TRACE_SOLVER_CANDS snb=%" PRIu64 " crc=%" PRIu64
        " suffix_cands=%" PRId64 " crc_in_suffix=%d"
        " suffix_type_pos=%u suffix_partial=%" PRIu64
        " trace_actual=%" PRId64 "\n",
        suffix_start_nb, crc_pos, suffix_cand_count,
        crc_in_suffix ? 1 : 0, suffix_type_pos,
        suffix_partial_len, png_trace_actual_block);
    if (png_trace_actual_block >= 0) {
      for (int64_t i = 0; i < suffix_cand_count; i++) {
        PNGSuffixCand *sc = &suffix_cands[i];
        if (sc->valid && sc->actual_block == png_trace_actual_block) {
          lock_fprintf(stdout,
              "PNG_TRACE_SOLVER_CAND_MATCH idx=%" PRId64
              " actual=%" PRId64 " apparent=%" PRId64
              " stored=%08" PRIx32 " partial=%08" PRIx32 "\n",
              i, sc->actual_block, sc->apparent_block,
              sc->stored_crc, sc->partial_crc);
          break;
        }
      }
    }
  }
  if (suffix_cand_count == 0) {
    free(suffix_cands);
    resize_blockvector(candidate->b, suffix_start_nb);
    return 0;
  }

  // ---- GAP Fast Path (any M) ----
  // Test if the M missing middle blocks form a contiguous run somewhere
  // on disk.  This is the common case for GAP fragmentation: blocks are
  // removed from one location and the gap is filled, but the displaced
  // blocks land contiguously elsewhere.  The indexed path below builds a
  // reusable CRC table for M-block apparent runs and does target lookups
  // per suffix candidate; the older sliding scan remains as allocation/
  // large-M fallback.
  //
  // Build a direct-indexed array: apparent_block → block_crc for O(1) lookup.
  bool solved = false;
  if (M > 0) {
    // Fast M=2 local-pair split:
    //   known local pair + displaced suffix block.
    // This is the small version of the anchored M=3 path below.  It handles
    // GAP+OOO cases where the full IDAT middle blocks are still immediately
    // after the trusted prefix, but the suffix/next-chunk block moved.
    if (M == 2 && suffix_fill_pos == first_full + 2
        && ht->actual_crc && ht->actual_valid && ht->actual_count > 0) {
      int64_t prefix_last_actual = (suffix_start_nb > 0)
          ? blockvector_get_actual_blocknumber(candidate->b,
              suffix_start_nb - 1)
          : -1;
      if (prefix_last_actual >= 0) {
        uint64_t target = crc_pos + 12 + (uint64_t)idat_sz;
        bool best_found = false;
        bool best_validated = false;
        uint64_t best_validates_to = 0;
        uint64_t best_advance_to = 0;
        uint32_t best_locality = 0;
        int64_t best_local_ap0 = -1;
        int64_t best_local_ap1 = -1;
        int64_t best_suffix_ap = -1;
        uint64_t best_data_length = 0;
        uint64_t best_num_blocks = 0;
        PNGSolverStateSnapshot best_snap = {0};

        for (uint32_t delta = 0;
             delta <= PNG_M2_ANCHOR_SCAN_MAX && !solved; delta++) {
          uint32_t local_pair_crc = 0;
          int64_t local_ap0 = -1;
          int64_t local_ap1 = -1;
          int64_t local_full_start_actual = prefix_last_actual + 1
              + (int64_t)first_full + (int64_t)delta;
          bool local_pair_ok = png_crc_actual_pair_crc(ht,
                  local_full_start_actual, &local_pair_crc,
                  &local_ap0, &local_ap1)
              && !_AB_IN_BV_PREFIX(local_ap0)
              && !_AB_IN_BV_PREFIX(local_ap1);
          if (png_trace_this && (local_pair_ok || delta == 0)) {
            lock_fprintf(stdout,
                "PNG_TRACE_M2_ANCHOR prefix_actual=%" PRId64
                " delta=%u local_start=%" PRId64
                " local_pair_ok=%d local_ap=[%" PRId64 ",%" PRId64 "]"
                " local_pair_crc=%08" PRIx32 "\n",
                prefix_last_actual, delta, local_full_start_actual,
                local_pair_ok ? 1 : 0, local_ap0, local_ap1,
                local_pair_crc);
          }
          if (!local_pair_ok) {
            continue;
          }

          for (int64_t si = 0; si < suffix_cand_count && !solved; si++) {
            PNGSuffixCand *sc = &suffix_cands[si];
            if (!sc->valid || sc->apparent_block < 0
                || sc->apparent_block == local_ap0
                || sc->apparent_block == local_ap1
                || _AB_IN_BV_PREFIX(sc->apparent_block)
                || filemirror_actual_block_covered(scalpel_state.filemirror,
                    sc->actual_block)) {
              continue;
            }

            png_solver_resize_trial(candidate, suffix_start_nb + fill_needed);
            blockvector_set_apparent_blocknumber(candidate->b,
                suffix_start_nb + first_full, local_ap0);
            blockvector_set_apparent_blocknumber(candidate->b,
                suffix_start_nb + first_full + 1, local_ap1);
            blockvector_set_apparent_blocknumber(candidate->b,
                suffix_start_nb + suffix_fill_pos, sc->apparent_block);
            for (uint32_t f = 0; f < fill_needed; f++) {
              inflate_blockvector_single_block(candidate->b,
                  suffix_start_nb + f);
            }

            PNGSolverStateSnapshot pre_snap;
            png_solver_snapshot(&pre_snap, local);
            uint64_t vt = 0;
            bool validated = false;
            uint64_t advance_to = local->last_chunk_crc_pos;
            bool marker_ok = png_solver_crc_marker_matches(candidate,
                type_start, crc_region_len, crc_field_pos, sc->stored_crc);
            bool plausible = false;
            if (marker_ok) {
              validated = png_direct_validate(work->id, candidate, &vt,
                  local, uuidp, uuidc);
              advance_to = local->last_chunk_crc_pos;
              plausible = validated || advance_to >= target;
            }
            uint32_t locality = PNG_M2_ANCHOR_SCAN_MAX - delta + 1;
            if (png_trace_this) {
              lock_fprintf(stdout,
                  "PNG_TRACE_M2_ANCHOR_TRY si=%" PRId64
                  " delta=%u sc_actual=%" PRId64
                  " sc_ap=%" PRId64 " marker=%d validated=%d"
                  " vt=%" PRIu64 " advance=%" PRIu64
                  " target=%" PRIu64 " plausible=%d\n",
                  si, delta, sc->actual_block, sc->apparent_block,
                  marker_ok ? 1 : 0, validated ? 1 : 0, vt,
                  advance_to, target, plausible ? 1 : 0);
            }
            if (plausible && png_gap_match_better(validated, vt, advance_to,
                locality, best_found, best_validated, best_validates_to,
                best_advance_to, best_locality)) {
              best_found = true;
              best_validated = validated;
              best_validates_to = vt;
              best_advance_to = advance_to;
              best_locality = locality;
              best_local_ap0 = local_ap0;
              best_local_ap1 = local_ap1;
              best_suffix_ap = sc->apparent_block;
              best_data_length = blockvector_get_data_length(candidate->b);
              best_num_blocks = blockvector_get_num_blocks(candidate->b);
              png_solver_snapshot(&best_snap, local);
              if (validated) {
                solved = true;
              }
            }

            png_solver_restore(local, &pre_snap);
            png_solver_resize_trial(candidate, suffix_start_nb + fill_needed);
            for (uint32_t f = 0; f < fill_needed; f++) {
              int64_t orig = last_block + 1 + (int64_t)f;
              blockvector_set_apparent_blocknumber(candidate->b,
                  suffix_start_nb + f, orig);
              inflate_blockvector_single_block(candidate->b,
                  suffix_start_nb + f);
            }
          }
        }

        if (best_found) {
          png_solver_resize_trial(candidate, suffix_start_nb + fill_needed);
          blockvector_set_apparent_blocknumber(candidate->b,
              suffix_start_nb + first_full, best_local_ap0);
          blockvector_set_apparent_blocknumber(candidate->b,
              suffix_start_nb + first_full + 1, best_local_ap1);
          blockvector_set_apparent_blocknumber(candidate->b,
              suffix_start_nb + suffix_fill_pos, best_suffix_ap);
          for (uint32_t f = 0; f < fill_needed; f++) {
            inflate_blockvector_single_block(candidate->b,
                suffix_start_nb + f);
          }
          if (best_data_length > 0) {
            blockvector_set_data_length(candidate->b, best_data_length);
          }
          if (best_num_blocks > 0) {
            resize_blockvector(candidate->b, best_num_blocks);
          }
          png_solver_restore(local, &best_snap);
          if (scalpel_state.mode_verbose) {
            lock_fprintf(stdout,
                "%sPNG CRC SOLVER: M=2 anchored local pair "
                "[%" PRId64 ",%" PRId64 "] suffix %" PRId64 "%s\n",
                GREEN, best_local_ap0, best_local_ap1,
                best_suffix_ap, BLACK);
          }
          solved = true;
        }
      }

      if (solved) {
        free(suffix_cands);
        return 2;
      }
    }

    // Fast M=3 anchored split:
    //   known local pair + contiguous displaced tail pair.
    // This handles the common case where two full middle blocks follow
    // the validated prefix locally, while the final middle block and the
    // suffix block moved together.  It is intentionally tried before the
    // broad GAP scan so large corpora do not spend an entire time slice
    // walking tens of thousands of structurally-plausible suffix blocks.
    if (M == 3 && suffix_fill_pos == first_full + 3
        && ht->actual_crc && ht->actual_valid && ht->actual_count > 0) {
      data = blockvector_get_data_pointer(candidate->b);
      dl = blockvector_get_data_length(candidate->b);

      uint32_t quick_mid_crc[3];
      bool quick_mid_ok = true;
      for (int mi = 0; mi < 3; mi++) {
        uint32_t fidx = first_full + (uint32_t)mi;
        uint64_t blk_byte = (suffix_start_nb + fidx) * (uint64_t)bs;
        if (data && blk_byte + bs <= dl) {
          quick_mid_crc[mi] = crc32(crc32(0, NULL, 0),
              (const unsigned char *)(data + blk_byte), (uInt)bs);
        } else {
          quick_mid_ok = false;
        }
      }

      if (quick_mid_ok) {
        z_off_t after[3];
        uint32_t after_forward[3][32];
        uint32_t shifted_contig[3];
        for (int mi = 0; mi < 3; mi++) {
          uint64_t blk_end = (suffix_start_nb + first_full + (uint32_t)mi)
              * (uint64_t)bs + (uint64_t)bs;
          after[mi] = (z_off_t)(crc_region_end > blk_end
              ? crc_region_end - blk_end : 0);
          png_crc_forward_for_len(after[mi], after_forward[mi]);
          shifted_contig[mi] = png_crc_apply_forward(
              after_forward[mi], quick_mid_crc[mi]);
        }

        uint32_t block_forward[32];
        uint32_t suffix_forward[32];
        png_crc_forward_for_len((z_off_t)bs, block_forward);
        png_crc_forward_for_len((z_off_t)suffix_partial_len, suffix_forward);
        uint32_t quick_crc_up_to_suffix = crc_prefix;
        for (int mi = 0; mi < 3; mi++) {
          quick_crc_up_to_suffix = png_crc_apply_forward(block_forward,
              quick_crc_up_to_suffix) ^ quick_mid_crc[mi];
        }

        int64_t prefix_last_actual = (suffix_start_nb > 0)
            ? blockvector_get_actual_blocknumber(candidate->b,
                suffix_start_nb - 1)
            : -1;
        uint32_t local_pair_crc = 0;
        int64_t local_ap0 = -1;
        int64_t local_ap1 = -1;
        int64_t local_full_start_actual = prefix_last_actual + 1
            + (int64_t)first_full;
        bool local_pair_ok = prefix_last_actual >= 0
            && png_crc_actual_pair_crc(ht, local_full_start_actual,
                &local_pair_crc, &local_ap0, &local_ap1)
            && !_AB_IN_BV_PREFIX(local_ap0)
            && !_AB_IN_BV_PREFIX(local_ap1);
        if (png_trace_this) {
          lock_fprintf(stdout,
              "PNG_TRACE_M3_ANCHOR prefix_actual=%" PRId64
              " local_start=%" PRId64 " local_pair_ok=%d"
              " local_ap=[%" PRId64 ",%" PRId64 "]"
              " local_pair_crc=%08" PRIx32 "\n",
              prefix_last_actual, local_full_start_actual,
              local_pair_ok ? 1 : 0, local_ap0, local_ap1,
              local_pair_crc);
        }

        if (local_pair_ok) {
          uint32_t shifted_local_pair = png_crc_apply_forward(
              after_forward[1], local_pair_crc);

          for (int64_t si = 0; si < suffix_cand_count && !solved; si++) {
            PNGSuffixCand *sc = &suffix_cands[si];
            if (!sc->valid || sc->apparent_block < 0
                || _AB_IN_BV_PREFIX(sc->apparent_block)
                || filemirror_actual_block_covered(scalpel_state.filemirror,
                    sc->actual_block)) {
              continue;
            }

            int64_t tail_actual = sc->actual_block - 1;
            int64_t tail_ap = png_crc_actual_to_apparent(ht, tail_actual);
            bool trace_anchor_sc = png_trace_this
                && (png_trace_actual_block < 0
                    || sc->actual_block == png_trace_actual_block);
            if (tail_ap < 0 || tail_ap == local_ap0
                || tail_ap == local_ap1 || tail_ap == sc->apparent_block
                || _AB_IN_BV_PREFIX(tail_ap)) {
              if (trace_anchor_sc) {
                lock_fprintf(stdout,
                    "PNG_TRACE_M3_ANCHOR_SKIP si=%" PRId64
                    " sc_actual=%" PRId64 " sc_ap=%" PRId64
                    " tail_actual=%" PRId64 " tail_ap=%" PRId64 "\n",
                    si, sc->actual_block, sc->apparent_block,
                    tail_actual, tail_ap);
              }
              continue;
            }

            uint32_t crc_with_sc = png_crc_apply_forward(suffix_forward,
                quick_crc_up_to_suffix) ^ sc->partial_crc;
            uint32_t diff = sc->stored_crc ^ crc_with_sc;
            if (diff == 0) {
              continue;
            }

            uint32_t target_all = diff ^ shifted_contig[0]
                ^ shifted_contig[1] ^ shifted_contig[2];
            uint32_t shifted_tail = png_crc_apply_forward(after_forward[2],
                ht->actual_crc[tail_actual]);
            if (trace_anchor_sc) {
              lock_fprintf(stdout,
                  "PNG_TRACE_M3_ANCHOR_CHECK si=%" PRId64
                  " sc_actual=%" PRId64 " sc_ap=%" PRId64
                  " tail_actual=%" PRId64 " tail_ap=%" PRId64
                  " target=%08" PRIx32 " local=%08" PRIx32
                  " tail=%08" PRIx32 " lhs=%08" PRIx32 "\n",
                  si, sc->actual_block, sc->apparent_block,
                  tail_actual, tail_ap, target_all,
                  shifted_local_pair, shifted_tail,
                  target_all ^ shifted_tail);
            }
            if ((target_all ^ shifted_tail) != shifted_local_pair) {
              continue;
            }

            png_solver_resize_trial(candidate, suffix_start_nb + fill_needed);
            blockvector_set_apparent_blocknumber(candidate->b,
                suffix_start_nb + first_full + 0, local_ap0);
            blockvector_set_apparent_blocknumber(candidate->b,
                suffix_start_nb + first_full + 1, local_ap1);
            blockvector_set_apparent_blocknumber(candidate->b,
                suffix_start_nb + first_full + 2, tail_ap);
            blockvector_set_apparent_blocknumber(candidate->b,
                suffix_start_nb + suffix_fill_pos, sc->apparent_block);
            for (uint32_t f = 0; f < fill_needed; f++) {
              inflate_blockvector_single_block(candidate->b,
                  suffix_start_nb + f);
            }

            bool trace_marker_ok = png_solver_crc_marker_matches(
                candidate, type_start, crc_region_len, crc_field_pos,
                sc->stored_crc);
            bool trace_confirm_ok = false;
            if (trace_marker_ok) {
              trace_confirm_ok = png_solver_confirm_match(candidate, local,
                  work, uuidp, uuidc, crc_pos, idat_sz);
            }
            if (trace_anchor_sc) {
              lock_fprintf(stdout,
                  "PNG_TRACE_M3_ANCHOR_TRY si=%" PRId64
                  " marker=%d confirm=%d last_crc=%" PRIu64
                  " target=%" PRIu64 "\n",
                  si, trace_marker_ok ? 1 : 0,
                  trace_confirm_ok ? 1 : 0,
                  local->last_chunk_crc_pos,
                  crc_pos + 12 + (uint64_t)idat_sz);
            }
            if (trace_marker_ok && trace_confirm_ok) {
              if (scalpel_state.mode_verbose) {
                lock_fprintf(stdout,
                    "%sPNG CRC SOLVER: M=3 anchored 2+2 blocks "
                    "[%" PRId64 ",%" PRId64 ",%" PRId64
                    "] suffix %" PRId64 "%s\n",
                    GREEN, local_ap0, local_ap1, tail_ap,
                    sc->apparent_block, BLACK);
              }
              solved = true;
              break;
            }

            for (uint32_t f = 0; f < fill_needed; f++) {
              int64_t orig = last_block + 1 + (int64_t)f;
              blockvector_set_apparent_blocknumber(candidate->b,
                  suffix_start_nb + f, orig);
              inflate_blockvector_single_block(candidate->b,
                  suffix_start_nb + f);
            }
          }
        }

        if (!solved && prefix_last_actual >= 0) {
          int64_t local_head_actual = local_full_start_actual;
          int64_t local_head_ap = png_crc_actual_to_apparent(ht,
              local_head_actual);
          if (local_head_ap >= 0 && !_AB_IN_BV_PREFIX(local_head_ap)) {
            uint32_t shifted_local_head = png_crc_apply_forward(
                after_forward[0], ht->actual_crc[local_head_actual]);

            for (int64_t si = 0; si < suffix_cand_count && !solved; si++) {
              PNGSuffixCand *sc = &suffix_cands[si];
              if (!sc->valid || sc->apparent_block < 0
                  || _AB_IN_BV_PREFIX(sc->apparent_block)
                  || filemirror_actual_block_covered(scalpel_state.filemirror,
                      sc->actual_block)) {
                continue;
              }

              int64_t tail1_actual = sc->actual_block - 2;
              int64_t tail2_actual = sc->actual_block - 1;
              int64_t tail1_ap = png_crc_actual_to_apparent(ht,
                  tail1_actual);
              int64_t tail2_ap = png_crc_actual_to_apparent(ht,
                  tail2_actual);
              if (tail1_ap < 0 || tail2_ap < 0
                  || tail1_ap == tail2_ap
                  || tail1_ap == local_head_ap
                  || tail2_ap == local_head_ap
                  || tail1_ap == sc->apparent_block
                  || tail2_ap == sc->apparent_block
                  || _AB_IN_BV_PREFIX(tail1_ap)
                  || _AB_IN_BV_PREFIX(tail2_ap)) {
                continue;
              }

              uint32_t crc_with_sc = png_crc_apply_forward(suffix_forward,
                  quick_crc_up_to_suffix) ^ sc->partial_crc;
              uint32_t diff = sc->stored_crc ^ crc_with_sc;
              if (diff == 0) {
                continue;
              }

              uint32_t target_all = diff ^ shifted_contig[0]
                  ^ shifted_contig[1] ^ shifted_contig[2];
              uint32_t shifted_tail1 = png_crc_apply_forward(
                  after_forward[1], ht->actual_crc[tail1_actual]);
              uint32_t shifted_tail2 = png_crc_apply_forward(
                  after_forward[2], ht->actual_crc[tail2_actual]);
              bool trace_anchor_sc = png_trace_this
                  && (png_trace_actual_block < 0
                      || sc->actual_block == png_trace_actual_block);
              if (trace_anchor_sc) {
                lock_fprintf(stdout,
                    "PNG_TRACE_M3_ANCHOR_1P3_CHECK si=%" PRId64
                    " sc_actual=%" PRId64 " sc_ap=%" PRId64
                    " head_actual=%" PRId64 " head_ap=%" PRId64
                    " tail1_actual=%" PRId64 " tail1_ap=%" PRId64
                    " tail2_actual=%" PRId64 " tail2_ap=%" PRId64
                    " target=%08" PRIx32 " head=%08" PRIx32
                    " tail1=%08" PRIx32 " tail2=%08" PRIx32
                    " rhs=%08" PRIx32 "\n",
                    si, sc->actual_block, sc->apparent_block,
                    local_head_actual, local_head_ap, tail1_actual, tail1_ap,
                    tail2_actual, tail2_ap, target_all, shifted_local_head,
                    shifted_tail1, shifted_tail2,
                    shifted_local_head ^ shifted_tail1 ^ shifted_tail2);
              }
              if (target_all != (shifted_local_head
                    ^ shifted_tail1 ^ shifted_tail2)) {
                continue;
              }

              png_solver_resize_trial(candidate, suffix_start_nb + fill_needed);
              blockvector_set_apparent_blocknumber(candidate->b,
                  suffix_start_nb + first_full + 0, local_head_ap);
              blockvector_set_apparent_blocknumber(candidate->b,
                  suffix_start_nb + first_full + 1, tail1_ap);
              blockvector_set_apparent_blocknumber(candidate->b,
                  suffix_start_nb + first_full + 2, tail2_ap);
              blockvector_set_apparent_blocknumber(candidate->b,
                  suffix_start_nb + suffix_fill_pos, sc->apparent_block);
              for (uint32_t f = 0; f < fill_needed; f++) {
                inflate_blockvector_single_block(candidate->b,
                    suffix_start_nb + f);
              }

              bool trace_marker_ok = png_solver_crc_marker_matches(
                  candidate, type_start, crc_region_len, crc_field_pos,
                  sc->stored_crc);
              bool trace_confirm_ok = false;
              if (trace_marker_ok) {
                trace_confirm_ok = png_solver_confirm_match(candidate, local,
                    work, uuidp, uuidc, crc_pos, idat_sz);
              }
              if (trace_anchor_sc) {
                lock_fprintf(stdout,
                    "PNG_TRACE_M3_ANCHOR_1P3_TRY si=%" PRId64
                    " marker=%d confirm=%d last_crc=%" PRIu64
                    " target=%" PRIu64 "\n",
                    si, trace_marker_ok ? 1 : 0,
                    trace_confirm_ok ? 1 : 0,
                    local->last_chunk_crc_pos,
                    crc_pos + 12 + (uint64_t)idat_sz);
              }
              if (trace_marker_ok && trace_confirm_ok) {
                if (scalpel_state.mode_verbose) {
                  lock_fprintf(stdout,
                      "%sPNG CRC SOLVER: M=3 anchored 1+3 blocks "
                      "[%" PRId64 ",%" PRId64 ",%" PRId64
                      "] suffix %" PRId64 "%s\n",
                      GREEN, local_head_ap, tail1_ap, tail2_ap,
                      sc->apparent_block, BLACK);
                }
                solved = true;
                break;
              }

              for (uint32_t f = 0; f < fill_needed; f++) {
                int64_t orig = last_block + 1 + (int64_t)f;
                blockvector_set_apparent_blocknumber(candidate->b,
                    suffix_start_nb + f, orig);
                inflate_blockvector_single_block(candidate->b,
                    suffix_start_nb + f);
              }
            }
          }
        }
      }

      if (solved) {
        free(suffix_cands);
        return 2;
      }
    }

    PNGGapWindowTable *gap_index = png_gap_window_table_get(ht, M);
    uint32_t gap_suffix_inv[32];
    if (gap_index
        && png_crc_inverse_for_len((z_off_t)suffix_partial_len,
                                   gap_suffix_inv)) {
      bool gap_geom_match = (local->gap_fast_suffix_nb == suffix_start_nb
                             && local->gap_fast_crc_pos == crc_pos
                             && local->gap_fast_M == M);
      if (gap_geom_match && local->gap_fast_exhausted
          && local->gap_fast_si == -1) {
        goto gap_fast_path_done;
      }

      int64_t resume_si = 0;
      if (gap_geom_match && local->gap_fast_resume_valid) {
        resume_si = local->gap_fast_si;
        if (resume_si < 0) {
          resume_si = 0;
        }
      } else {
        local->gap_fast_resume_valid = false;
        local->gap_fast_exhausted = false;
        local->gap_fast_suffix_nb = suffix_start_nb;
        local->gap_fast_crc_pos = crc_pos;
        local->gap_fast_M = M;
      }

	      z_off_t middle_len = (z_off_t)((uint64_t)M * (uint64_t)bs);
	      uint32_t shifted_prefix = (uint32_t)crc32_combine(
	          (uLong)crc_prefix, 0UL, middle_len);
	      int64_t current_total_ap = (int64_t)filemirror_apparent_blocks(
	          scalpel_state.filemirror);
	      uint64_t target = crc_pos + 12 + (uint64_t)idat_sz;
	      bool best_found = false;
	      bool best_validated = false;
	      uint64_t best_validates_to = 0;
	      uint64_t best_advance_to = 0;
	      uint32_t best_locality = 0;
	      int64_t best_window_ap[PNG_GAP_INDEX_MAX_M];
	      int64_t best_suffix_ap = -1;
	      uint64_t best_data_length = 0;
	      uint64_t best_num_blocks = 0;
	      PNGSolverStateSnapshot best_snap = {0};
	      bool stop_gap_scan = false;

	      for (int64_t si = resume_si;
	           si < suffix_cand_count && !stop_gap_scan; si++) {
	        if ((si & 0x3FF) == 0
	            && png_reassembly_yield_requested(candidate)) {
          local->gap_fast_resume_valid = true;
          local->gap_fast_exhausted = false;
          local->gap_fast_si = si;
          local->gap_fast_start = 0;
          local->gap_fast_M = M;
          local->gap_fast_suffix_nb = suffix_start_nb;
          local->gap_fast_crc_pos = crc_pos;
          local->solver_suffix_nb = suffix_start_nb;
          free(suffix_cands);
          resize_blockvector(candidate->b, suffix_start_nb);
          return -1;
        }

        PNGSuffixCand *sc = &suffix_cands[si];
        if (!sc->valid) {
          continue;
        }
        if (sc->apparent_block < 0
            || sc->apparent_block >= current_total_ap) {
          continue;
        }
        if (filemirror_actual_block_covered(scalpel_state.filemirror,
                sc->actual_block)) {
          continue;
        }
        if (_AB_IN_BV_PREFIX(sc->apparent_block)) {
          continue;
        }

        uint32_t f_right = sc->partial_crc;
        uint32_t req_left = png_crc_apply_inverse(gap_suffix_inv,
            sc->stored_crc ^ f_right);
        uint32_t req_run = req_left ^ shifted_prefix;
        uint32_t bucket = req_run % PNG_GAP_WINDOW_BUCKETS;

	        for (PNGGapWindowEntry *we = gap_index->buckets[bucket];
	             we && !stop_gap_scan; we = we->next) {
          if (we->crc != req_run) {
            continue;
          }
          if (we->start_actual < 0
              || we->start_actual + (int64_t)M > ht->actual_count) {
            continue;
          }

          bool window_ok = true;
          int64_t window_ap[PNG_GAP_INDEX_MAX_M];
          for (uint32_t f = 0; f < M; f++) {
            int64_t actual = we->start_actual + (int64_t)f;
            int64_t ab = png_crc_actual_to_apparent(ht, actual);
            if (ab < 0 || ab >= current_total_ap
                || actual == sc->actual_block
                || _AB_IN_BV_PREFIX(ab)) {
              window_ok = false;
              break;
            }
            window_ap[f] = ab;
          }
          if (!window_ok) {
            continue;
          }
          for (uint32_t f = 0; f < M; f++) {
            if (sc->apparent_block == window_ap[f]) {
              window_ok = false;
              break;
            }
          }
          if (!window_ok) {
            continue;
          }

          png_solver_resize_trial(candidate, suffix_start_nb + fill_needed);
          for (uint32_t f = 0; f < M; f++) {
            blockvector_set_apparent_blocknumber(candidate->b,
                suffix_start_nb + first_full + f, window_ap[f]);
          }
          blockvector_set_apparent_blocknumber(candidate->b,
              suffix_start_nb + suffix_fill_pos, sc->apparent_block);
          for (uint32_t f = 0; f < fill_needed; f++) {
            inflate_blockvector_single_block(candidate->b,
                suffix_start_nb + f);
          }

          PNGSolverStateSnapshot pre_snap;
          png_solver_snapshot(&pre_snap, local);
          uint64_t vt;
          bool validated = png_direct_validate(work->id, candidate, &vt,
              local, uuidp, uuidc);
          uint64_t advance_to = local->last_chunk_crc_pos;
          uint32_t locality = png_gap_locality_score(candidate,
              suffix_start_nb, first_full, window_ap, M);
          // CRC algebra plus the next PNG marker identifies the seam.  If every
          // filled block is also the physical local continuation, accept the
          // match even when the streaming validator does not advance state.
          bool plausible = validated || advance_to >= target
              || locality == M;
          if (png_trace_this) {
            lock_fprintf(stdout,
                "PNG_TRACE_GAP_INDEX_TRY si=%" PRId64
                " sc_actual=%" PRId64 " sc_ap=%" PRId64
                " start_actual=%" PRId64 " aps0=%" PRId64
                " M=%u validated=%d vt=%" PRIu64
                " advance=%" PRIu64 " target=%" PRIu64
                " locality=%u plausible=%d\n",
                si, sc->actual_block, sc->apparent_block,
                we->start_actual, window_ap[0], M,
                validated ? 1 : 0, vt, advance_to, target,
                locality, plausible ? 1 : 0);
          }
          if (plausible && png_gap_match_better(validated, vt, advance_to,
              locality, best_found, best_validated, best_validates_to,
              best_advance_to, best_locality)) {
            best_found = true;
            best_validated = validated;
            best_validates_to = vt;
            best_advance_to = advance_to;
            best_locality = locality;
            memcpy(best_window_ap, window_ap,
                M * sizeof(best_window_ap[0]));
            best_suffix_ap = sc->apparent_block;
            best_data_length = blockvector_get_data_length(candidate->b);
            best_num_blocks = blockvector_get_num_blocks(candidate->b);
            png_solver_snapshot(&best_snap, local);
            if (validated || locality == M) {
              stop_gap_scan = true;
            }
          }

          png_solver_restore(local, &pre_snap);
          png_solver_resize_trial(candidate, suffix_start_nb + fill_needed);
          blockvector_set_data_length(candidate->b,
              (suffix_start_nb + fill_needed) * (uint64_t)bs);
          for (uint32_t f = 0; f < fill_needed; f++) {
            int64_t orig = last_block + 1 + (int64_t)f;
            blockvector_set_apparent_blocknumber(candidate->b,
                suffix_start_nb + f, orig);
            inflate_blockvector_single_block(candidate->b,
                suffix_start_nb + f);
          }
        }
      }

	      if (best_found) {
	        png_solver_resize_trial(candidate, suffix_start_nb + fill_needed);
	        for (uint32_t f = 0; f < M; f++) {
	          blockvector_set_apparent_blocknumber(candidate->b,
	              suffix_start_nb + first_full + f, best_window_ap[f]);
	        }
	        blockvector_set_apparent_blocknumber(candidate->b,
	            suffix_start_nb + suffix_fill_pos, best_suffix_ap);
	        for (uint32_t f = 0; f < fill_needed; f++) {
	          inflate_blockvector_single_block(candidate->b,
	              suffix_start_nb + f);
	        }
	        if (best_data_length > 0) {
	          blockvector_set_data_length(candidate->b, best_data_length);
	        }
	        if (best_num_blocks > 0) {
	          resize_blockvector(candidate->b, best_num_blocks);
	        }
	        png_solver_restore(local, &best_snap);
	        solved = true;
	      }

	      local->gap_fast_resume_valid = false;
      if (!solved) {
        local->gap_fast_exhausted = true;
        local->gap_fast_suffix_nb = suffix_start_nb;
        local->gap_fast_crc_pos = crc_pos;
        local->gap_fast_M = M;
        local->gap_fast_si = -1;
        local->gap_fast_start = 0;
        local->solver_suffix_nb = suffix_start_nb;
      } else {
        local->gap_fast_exhausted = false;
      }

      if (solved) {
        free(suffix_cands);
        return 2;
      }

      goto gap_fast_path_done;
    }

    int64_t total_ap = (int64_t)filemirror_apparent_blocks(
        scalpel_state.filemirror);
    uint32_t *ab_crc = (uint32_t *)calloc((size_t)total_ap, sizeof(uint32_t));
    bool *ab_valid = (bool *)calloc((size_t)total_ap, sizeof(bool));
    if (ab_crc && ab_valid) {
      // Populate from hash table — O(N).
      for (uint32_t b = 0; b < PNG_CRC_HASH_BUCKETS; b++) {
        for (PNGCrcEntry *e = ht->buckets[b]; e; e = e->next) {
          int64_t ab = filemirror_apparent_blocknumber(
              scalpel_state.filemirror, e->actual_block);
          if (ab >= 0 && ab < total_ap) {
            ab_crc[ab] = e->crc;
            ab_valid[ab] = true;
          }
        }
      }

      // For each suffix candidate, slide an M-block window across all
      // apparent blocks and check if the combined CRC matches.
      //
      // Resume across yields: without this, the scan restarts from
      // start=0 on every (very frequent at big-test scale) yield, so
      // it never reaches the end.  Resume state lives in PNGCarveState
      // (direct fields, not solver_ctx) so it survives the solver_ctx
      // free/rebuild that M=2/M=3 MitM performs.
      //
      // If the scan already finished for this (suffix_nb, crc_pos, M)
      // without finding a match, skip GAP entirely so later strategies
      // get their turn instead of re-scanning 1M windows.
      bool gap_geom_match = (local->gap_fast_suffix_nb == suffix_start_nb
                             && local->gap_fast_crc_pos == crc_pos
                             && local->gap_fast_M == M);
      if (gap_geom_match && local->gap_fast_exhausted
          && local->gap_fast_si == -1) {
        // Skip GAP fast path entirely.
        free(ab_crc);
        free(ab_valid);
        goto gap_fast_path_done;
      }
      int64_t resume_si = 0;
      int64_t resume_start = 0;
      if (gap_geom_match && local->gap_fast_resume_valid) {
        resume_si = local->gap_fast_si;
        resume_start = local->gap_fast_start;
      } else {
        // Geometry changed — invalidate any stale state.
        local->gap_fast_resume_valid = false;
        local->gap_fast_exhausted = false;
        local->gap_fast_suffix_nb = suffix_start_nb;
        local->gap_fast_crc_pos = crc_pos;
        local->gap_fast_M = M;
      }
      // ---- Phase 1: collect CRC matches (up to cap) without committing ----
      // CRC32 collides at ~2^-32 per comparison; across ~N*total_apparent
      // windows at 20k-entry hash table scale we see ~4-8 matches per call
      // per the stuck-N diagnosis.  Committing the FIRST match (which is
      // what the pre-multi-match code did) almost guarantees picking a
      // spurious one: the validator's full-chain check is the reliable
      // arbiter but only one placement can be committed per solver call.
      // Collect up to PNG_GAP_MAX_MATCHES, then Phase 2 validates each and
      // commits the one whose validator walks farthest.
      #define PNG_GAP_MAX_MATCHES 32
      int64_t gap_match_start[PNG_GAP_MAX_MATCHES];
      int64_t gap_match_sc_idx[PNG_GAP_MAX_MATCHES];
      uint32_t gap_match_count = 0;
      bool gap_yielded = false;
      bool gap_match_cap_reached = false;
      int64_t gap_cap_resume_si = 0;
      int64_t gap_cap_resume_start = 0;
      uint32_t gap_block_forward[32];
      uint32_t gap_suffix_forward[32];
      png_crc_forward_for_len((z_off_t)bs, gap_block_forward);
      png_crc_forward_for_len((z_off_t)suffix_partial_len,
                              gap_suffix_forward);

      for (int64_t si = resume_si;
           si < suffix_cand_count
               && gap_match_count < PNG_GAP_MAX_MATCHES
               && !gap_yielded;
           si++) {
        PNGSuffixCand *sc = &suffix_cands[si];
        if (!sc->valid) { continue; }

        int64_t start_init = (si == resume_si) ? resume_start : 0;
        for (int64_t start = start_init;
             start + (int64_t)M <= total_ap
                 && gap_match_count < PNG_GAP_MAX_MATCHES
                 && !gap_yielded;
             start++) {
          if ((start & 0xFF) == 0
              && png_reassembly_yield_requested(candidate)) {
            // GAP fast path yield — save progress directly in PNGCarveState
            // so the next call can resume rather than rescan from 0.
            local->gap_fast_resume_valid = true;
            local->gap_fast_exhausted = false;
            local->gap_fast_si = si;
            local->gap_fast_start = start;
            local->gap_fast_M = M;
            local->gap_fast_suffix_nb = suffix_start_nb;
            local->gap_fast_crc_pos = crc_pos;
            local->solver_suffix_nb = suffix_start_nb;
            gap_yielded = true;
            break;
          }
          // Skip if any block in the window is invalid or covered.
          bool window_ok = true;
          uint32_t window_crc = crc_prefix;
          for (uint32_t f = 0; f < M; f++) {
            int64_t ab = start + (int64_t)f;
            if (!ab_valid[ab]) { window_ok = false; break; }
            if (filemirror_actual_block_covered(scalpel_state.filemirror,
                    filemirror_actual_blocknumber(
                        scalpel_state.filemirror, ab))) {
              window_ok = false; break;
            }
            window_crc = png_crc_apply_forward(gap_block_forward,
                window_crc) ^ ab_crc[ab];
          }
          if (!window_ok) { continue; }

          // Combine with suffix partial and check against stored CRC.
          uint32_t full_crc = png_crc_apply_forward(gap_suffix_forward,
              window_crc) ^ sc->partial_crc;
          if (full_crc != sc->stored_crc) { continue; }

          // CRC match — record it, keep scanning.
          gap_match_start[gap_match_count] = start;
          gap_match_sc_idx[gap_match_count] = si;
          gap_match_count++;
          if (gap_match_count >= PNG_GAP_MAX_MATCHES) {
            gap_match_cap_reached = true;
            if (start + 1 + (int64_t)M <= total_ap) {
              gap_cap_resume_si = si;
              gap_cap_resume_start = start + 1;
            } else {
              gap_cap_resume_si = si + 1;
              gap_cap_resume_start = 0;
            }
            break;
          }
        }
        if (gap_match_cap_reached) {
          break;
        }
      }

      if (gap_yielded) {
        // Partial scan — honor the yield now, even if we have matches.
        // Next call's resume will continue the scan from where we left off
        // and collect any matches we missed here.
        free(ab_crc); free(ab_valid);
        free(suffix_cands);
        resize_blockvector(candidate->b, suffix_start_nb);
        return -1;
      }


	      // ---- Phase 2: try each collected match.  First one whose validator
	      // walks farthest commits; others are rolled back.  CRC equality
	      // proves the current chunk bytes, but at corpus scale multiple
	      // placements can satisfy that equality.  Ranking by downstream
	      // validation avoids committing the first same-offset echo match.
	      uint64_t target = crc_pos + 12 + (uint64_t)idat_sz;
	      bool best_found = false;
	      bool best_validated = false;
	      uint64_t best_validates_to = 0;
	      uint64_t best_advance_to = 0;
	      uint32_t best_locality = 0;
	      int64_t best_start = -1;
	      int64_t best_sc_idx = -1;
	      uint64_t best_data_length = 0;
	      uint64_t best_num_blocks = 0;
	      PNGSolverStateSnapshot best_snap = {0};
	      for (uint32_t mi = 0; mi < gap_match_count && !solved; mi++) {
	        int64_t m_start = gap_match_start[mi];
	        int64_t m_si = gap_match_sc_idx[mi];
        PNGSuffixCand *m_sc = &suffix_cands[m_si];
        // Place blocks.
        png_solver_resize_trial(candidate, suffix_start_nb + fill_needed);
        for (uint32_t f = 0; f < M; f++) {
          blockvector_set_apparent_blocknumber(candidate->b,
              suffix_start_nb + first_full + f, m_start + (int64_t)f);
        }
        blockvector_set_apparent_blocknumber(candidate->b,
            suffix_start_nb + suffix_fill_pos, m_sc->apparent_block);
        for (uint32_t f = 0; f < fill_needed; f++) {
          inflate_blockvector_single_block(candidate->b,
              suffix_start_nb + f);
        }
        // Snapshot + validate.  On reject, roll state back to pre-match
        // so the next match attempt sees a clean slate.
        PNGSolverStateSnapshot pre_snap;
        png_solver_snapshot(&pre_snap, local);
        uint64_t vt;
        bool validated = png_direct_validate(work->id, candidate, &vt,
            local, uuidp, uuidc);
        uint64_t advance_to = local->last_chunk_crc_pos;
        uint32_t locality = png_gap_contiguous_locality_score(candidate,
            suffix_start_nb, first_full, m_start, M);
        bool accept = validated || (advance_to >= target)
            || locality == M;
        if (png_trace_this) {
          lock_fprintf(stdout,
              "PNG_TRACE_GAP_SCAN_TRY mi=%u si=%" PRId64
              " sc_actual=%" PRId64 " sc_ap=%" PRId64
              " start=%" PRId64 " M=%u validated=%d"
              " vt=%" PRIu64 " advance=%" PRIu64
              " target=%" PRIu64 " locality=%u plausible=%d\n",
              mi, m_si, m_sc->actual_block, m_sc->apparent_block,
              m_start, M, validated ? 1 : 0, vt, advance_to,
              target, locality, accept ? 1 : 0);
        }
        if (accept) {
          if (png_gap_match_better(validated, vt, advance_to, locality,
              best_found, best_validated, best_validates_to,
              best_advance_to, best_locality)) {
            best_found = true;
            best_validated = validated;
            best_validates_to = vt;
            best_advance_to = advance_to;
            best_locality = locality;
            best_start = m_start;
            best_sc_idx = m_si;
            best_data_length = blockvector_get_data_length(candidate->b);
            best_num_blocks = blockvector_get_num_blocks(candidate->b);
            png_solver_snapshot(&best_snap, local);
          }
          if (validated || locality == M) {
            solved = true;
          }
        }
        // Restore state and BV for next match.  Accepted candidates are
        // committed after ranking, not inside this loop.
        png_solver_restore(local, &pre_snap);
        png_solver_resize_trial(candidate, suffix_start_nb + fill_needed);
        blockvector_set_data_length(candidate->b,
            (suffix_start_nb + fill_needed) * (uint64_t)bs);
        for (uint32_t f = 0; f < fill_needed; f++) {
          int64_t orig = last_block + 1 + (int64_t)f;
          blockvector_set_apparent_blocknumber(candidate->b,
              suffix_start_nb + f, orig);
          inflate_blockvector_single_block(candidate->b,
              suffix_start_nb + f);
        }
      }
	      if (best_found && best_sc_idx >= 0) {
	        PNGSuffixCand *best_sc = &suffix_cands[best_sc_idx];
	        png_solver_resize_trial(candidate, suffix_start_nb + fill_needed);
	        for (uint32_t f = 0; f < M; f++) {
	          blockvector_set_apparent_blocknumber(candidate->b,
	              suffix_start_nb + first_full + f, best_start + (int64_t)f);
	        }
	        blockvector_set_apparent_blocknumber(candidate->b,
	            suffix_start_nb + suffix_fill_pos, best_sc->apparent_block);
	        for (uint32_t f = 0; f < fill_needed; f++) {
	          inflate_blockvector_single_block(candidate->b,
	              suffix_start_nb + f);
	        }
	        if (best_data_length > 0) {
	          blockvector_set_data_length(candidate->b, best_data_length);
	        }
	        if (best_num_blocks > 0) {
	          resize_blockvector(candidate->b, best_num_blocks);
	        }
	        png_solver_restore(local, &best_snap);
	        solved = true;
	      }
	      if (!solved && gap_match_count > 0) {
	        // All matches rejected.  Leave state clean.
	        resize_blockvector(candidate->b, suffix_start_nb);
      }
      if (!solved && gap_match_cap_reached
          && gap_cap_resume_si < suffix_cand_count) {
        local->gap_fast_resume_valid = true;
        local->gap_fast_exhausted = false;
        local->gap_fast_si = gap_cap_resume_si;
        local->gap_fast_start = gap_cap_resume_start;
        local->gap_fast_M = M;
        local->gap_fast_suffix_nb = suffix_start_nb;
        local->gap_fast_crc_pos = crc_pos;
        local->solver_suffix_nb = suffix_start_nb;
        free(ab_crc);
        free(ab_valid);
        free(suffix_cands);
        resize_blockvector(candidate->b, suffix_start_nb);
        return -1;
      }
      #undef PNG_GAP_MAX_MATCHES
    }
    free(ab_crc);
    free(ab_valid);

    // GAP fast path finished for this (suffix_nb, crc_pos, M) without
    // yielding.  If solved, clear state (caller returns 2).  If not,
    // mark exhausted so the next call skips GAP and gives MitM a turn.
    local->gap_fast_resume_valid = false;
    if (!solved) {
      local->gap_fast_exhausted = true;
      local->gap_fast_suffix_nb = suffix_start_nb;
      local->gap_fast_crc_pos = crc_pos;
      local->gap_fast_M = M;
      local->gap_fast_si = -1;
      local->gap_fast_start = 0;
      local->solver_suffix_nb = suffix_start_nb;
    } else {
      local->gap_fast_exhausted = false;
    }

    gap_fast_path_done:;
    if (solved) {
      free(suffix_cands);
      return 2;
    }
  }

  /* Fast M=3 suffix-anchored solver.
   *
   * The large PNG corpus commonly fragments one IDAT window as:
   *   position 0 singleton + positions 1,2,suffix as a contiguous run
   * or the adjacent 2+2 variant.  The generic M=3 solver below builds
   * per-candidate shifted-CRC tables over the whole active blockmap; at
   * 600k+ available blocks and many concurrent reassembly threads that is
   * both slow and memory-heavy.  For these suffix-anchored shapes, invert
   * the CRC shift and use the existing raw block CRC hash table directly.
   */
  if (!solved && M == 3 && suffix_fill_pos == first_full + 3
      && ht->actual_crc && ht->actual_valid
      && ht->actual_count > 0) {
    data = blockvector_get_data_pointer(candidate->b);
    dl = blockvector_get_data_length(candidate->b);

    uint32_t mid_crc[3];
    bool mid_crc_ok = true;
    for (int mi = 0; mi < 3; mi++) {
      uint32_t fidx = first_full + (uint32_t)mi;
      uint64_t blk_byte = (suffix_start_nb + fidx) * (uint64_t)bs;
      if (data && blk_byte + bs <= dl) {
        mid_crc[mi] = crc32(crc32(0, NULL, 0),
            (const unsigned char *)(data + blk_byte), (uInt)bs);
      } else {
        mid_crc_ok = false;
      }
    }

    if (mid_crc_ok) {
      z_off_t after[3];
      uint32_t after_forward[3][32];
      uint32_t shifted_contig[3];
      for (int mi = 0; mi < 3; mi++) {
        uint64_t blk_end = (suffix_start_nb + first_full + (uint32_t)mi)
            * (uint64_t)bs + (uint64_t)bs;
        after[mi] = (z_off_t)(crc_region_end > blk_end
            ? crc_region_end - blk_end : 0);
        png_crc_forward_for_len(after[mi], after_forward[mi]);
        shifted_contig[mi] = png_crc_apply_forward(
            after_forward[mi], mid_crc[mi]);
      }

      uint32_t block_forward[32];
      uint32_t suffix_forward[32];
      png_crc_forward_for_len((z_off_t)bs, block_forward);
      png_crc_forward_for_len((z_off_t)suffix_partial_len, suffix_forward);
      uint32_t mid_crc_up_to_suffix = crc_prefix;
      for (int mi = 0; mi < 3; mi++) {
        mid_crc_up_to_suffix = png_crc_apply_forward(block_forward,
            mid_crc_up_to_suffix) ^ mid_crc[mi];
      }

      uint32_t inv_after0[32];
      bool inv_after0_ok = png_crc_inverse_for_len(after[0], inv_after0);
      PNGGapWindowTable *pair_index = png_gap_window_table_get(ht, 2);
      uint32_t pair_after_inv[32];
      bool pair_after_inv_ok = png_crc_inverse_for_len(after[1],
          pair_after_inv);
      uint32_t pair_after2_inv[32];
      bool pair_after2_inv_ok = png_crc_inverse_for_len(after[2],
          pair_after2_inv);
      int64_t total_ap = (int64_t)filemirror_apparent_blocks(
          scalpel_state.filemirror);

      #define PNG_M3_FAST_AP_VALID(_ap) \
        ((_ap) >= 0 && (_ap) < total_ap \
         && png_crc_apparent_crc(ht, (_ap), NULL, NULL))
      #define PNG_M3_FAST_AP_FROM_ACT(_act) \
        png_crc_actual_to_apparent(ht, (_act))
      #define PNG_M3_FAST_SHIFT_AP(_ap, _pos) \
        ({ uint32_t _ap_crc = 0; \
           (void)png_crc_apparent_crc(ht, (_ap), &_ap_crc, NULL); \
           png_crc_apply_forward(after_forward[(_pos)], _ap_crc); })
      #define PNG_M3_FAST_RESTORE_CONTIG() do { \
        for (uint32_t _rf = 0; _rf < fill_needed; _rf++) { \
          int64_t _orig = last_block + 1 + (int64_t)_rf; \
          blockvector_set_apparent_blocknumber(candidate->b, \
              suffix_start_nb + _rf, _orig); \
          inflate_blockvector_single_block(candidate->b, \
              suffix_start_nb + _rf); \
        } \
      } while (0)
      #define PNG_M3_FAST_TRY(_ab0, _ab1, _ab2, _sap, _scptr, _kind) do { \
        int64_t _pa0 = (_ab0); \
        int64_t _pa1 = (_ab1); \
        int64_t _pa2 = (_ab2); \
        int64_t _ps = (_sap); \
        PNGSuffixCand *_sc = (_scptr); \
        if (!solved \
            && PNG_M3_FAST_AP_VALID(_pa0) \
            && PNG_M3_FAST_AP_VALID(_pa1) \
            && PNG_M3_FAST_AP_VALID(_pa2) \
            && PNG_M3_FAST_AP_VALID(_ps) \
            && !_AB_IN_BV_PREFIX(_pa0) \
            && !_AB_IN_BV_PREFIX(_pa1) \
            && !_AB_IN_BV_PREFIX(_pa2) \
            && !_AB_IN_BV_PREFIX(_ps) \
            && _pa0 != _pa1 && _pa0 != _pa2 && _pa1 != _pa2 \
            && _pa0 != _ps && _pa1 != _ps && _pa2 != _ps) { \
          int64_t _aa0 = filemirror_actual_blocknumber( \
              scalpel_state.filemirror, _pa0); \
          int64_t _aa1 = filemirror_actual_blocknumber( \
              scalpel_state.filemirror, _pa1); \
          int64_t _aa2 = filemirror_actual_blocknumber( \
              scalpel_state.filemirror, _pa2); \
          if (_aa0 >= 0 && _aa1 >= 0 && _aa2 >= 0 \
              && _aa0 != _aa1 && _aa0 != _aa2 && _aa1 != _aa2 \
              && _aa0 != _sc->actual_block \
              && _aa1 != _sc->actual_block \
              && _aa2 != _sc->actual_block \
              && !filemirror_actual_block_covered( \
                  scalpel_state.filemirror, _aa0) \
              && !filemirror_actual_block_covered( \
                  scalpel_state.filemirror, _aa1) \
              && !filemirror_actual_block_covered( \
                  scalpel_state.filemirror, _aa2)) { \
            resize_blockvector(candidate->b, \
                suffix_start_nb + fill_needed); \
            blockvector_set_apparent_blocknumber(candidate->b, \
                suffix_start_nb + first_full + 0, _pa0); \
            blockvector_set_apparent_blocknumber(candidate->b, \
                suffix_start_nb + first_full + 1, _pa1); \
            blockvector_set_apparent_blocknumber(candidate->b, \
                suffix_start_nb + first_full + 2, _pa2); \
            blockvector_set_apparent_blocknumber(candidate->b, \
                suffix_start_nb + suffix_fill_pos, _ps); \
            for (uint32_t _if = 0; _if < fill_needed; _if++) { \
              inflate_blockvector_single_block(candidate->b, \
                  suffix_start_nb + _if); \
            } \
            bool _trace_try = png_trace_this \
                && (png_trace_actual_block < 0 \
                    || _sc->actual_block == png_trace_actual_block); \
            bool _marker_ok = png_solver_crc_marker_matches(candidate, \
                type_start, crc_region_len, crc_field_pos, _sc->stored_crc); \
            bool _confirm_ok = false; \
            if (_marker_ok) { \
              _confirm_ok = png_solver_confirm_match(candidate, local, work, \
                  uuidp, uuidc, crc_pos, idat_sz); \
            } \
            if (_trace_try) { \
              lock_fprintf(stdout, \
                  "PNG_TRACE_M3_FAST_TRY kind=%s sc_actual=%" PRId64 \
                  " sc_ap=%" PRId64 " aps=[%" PRId64 ",%" PRId64 \
                  ",%" PRId64 "] marker=%d confirm=%d last_crc=%" PRIu64 \
                  " target=%" PRIu64 "\n", \
                  (_kind), _sc->actual_block, _ps, _pa0, _pa1, _pa2, \
                  _marker_ok ? 1 : 0, _confirm_ok ? 1 : 0, \
                  local->last_chunk_crc_pos, \
                  crc_pos + 12 + (uint64_t)idat_sz); \
            } \
            if (_marker_ok && _confirm_ok) { \
              if (scalpel_state.mode_verbose) { \
                lock_fprintf(stdout, \
                    "%sPNG CRC SOLVER: M=3 fast suffix %s blocks " \
                    "[%" PRId64 ",%" PRId64 ",%" PRId64 \
                    "] suffix %" PRId64 "%s\n", \
                    GREEN, (_kind), _pa0, _pa1, _pa2, _ps, BLACK); \
              } \
              solved = true; \
            } \
            if (!solved) { PNG_M3_FAST_RESTORE_CONTIG(); } \
          } \
        } \
      } while (0)

      for (int64_t si = 0; si < suffix_cand_count && !solved; si++) {
        PNGSuffixCand *sc = &suffix_cands[si];
        if (!sc->valid || sc->apparent_block < 0
            || sc->apparent_block >= total_ap
            || _AB_IN_BV_PREFIX(sc->apparent_block)
            || filemirror_actual_block_covered(scalpel_state.filemirror,
                sc->actual_block)) {
          continue;
        }

        uint32_t crc_with_sc = png_crc_apply_forward(suffix_forward,
            mid_crc_up_to_suffix) ^ sc->partial_crc;
        uint32_t diff = sc->stored_crc ^ crc_with_sc;
        if (diff == 0) {
          continue;
        }

        uint32_t target_all = diff ^ shifted_contig[0]
            ^ shifted_contig[1] ^ shifted_contig[2];
        int64_t sap = sc->apparent_block;
        int64_t prefix_last_actual = (suffix_start_nb > 0)
            ? blockvector_get_actual_blocknumber(candidate->b,
                suffix_start_nb - 1)
            : -1;

        /* All four fill blocks are contiguous elsewhere. */
        int64_t r0 = PNG_M3_FAST_AP_FROM_ACT(sc->actual_block - 3);
        int64_t r1 = PNG_M3_FAST_AP_FROM_ACT(sc->actual_block - 2);
        int64_t r2 = PNG_M3_FAST_AP_FROM_ACT(sc->actual_block - 1);
        if (PNG_M3_FAST_AP_VALID(r0) && PNG_M3_FAST_AP_VALID(r1)
            && PNG_M3_FAST_AP_VALID(r2)) {
          uint32_t run_shift = PNG_M3_FAST_SHIFT_AP(r0, 0)
              ^ PNG_M3_FAST_SHIFT_AP(r1, 1)
              ^ PNG_M3_FAST_SHIFT_AP(r2, 2);
          if (run_shift == target_all) {
            PNG_M3_FAST_TRY(r0, r1, r2, sap, sc, "4-run");
          }
        }

        /* Position 0 singleton + positions 1,2,suffix contiguous. */
        if (!solved && inv_after0_ok) {
          int64_t r1b = PNG_M3_FAST_AP_FROM_ACT(sc->actual_block - 2);
          int64_t r2b = PNG_M3_FAST_AP_FROM_ACT(sc->actual_block - 1);
          if (PNG_M3_FAST_AP_VALID(r1b) && PNG_M3_FAST_AP_VALID(r2b)) {
            uint32_t needed_shift0 = target_all
                ^ PNG_M3_FAST_SHIFT_AP(r1b, 1)
                ^ PNG_M3_FAST_SHIFT_AP(r2b, 2);
            uint32_t needed_raw0 = png_crc_apply_inverse(inv_after0,
                needed_shift0);
            for (PNGCrcEntry *me = png_crc_table_find(ht, needed_raw0);
                 me && !solved;
                 me = png_crc_table_next(me, needed_raw0)) {
              if (filemirror_actual_block_covered(
                      scalpel_state.filemirror, me->actual_block)) {
                continue;
              }
              int64_t ab0 = filemirror_apparent_blocknumber(
                  scalpel_state.filemirror, me->actual_block);
              if (ab0 < 0 || ab0 == r1b || ab0 == r2b || ab0 == sap) {
                continue;
              }
              PNG_M3_FAST_TRY(ab0, r1b, r2b, sap, sc, "1+3-run");
            }
          }
        }

        /* Positions 0,1 contiguous + positions 2,suffix contiguous. */
        if (!solved && pair_after_inv_ok) {
          int64_t r2c = PNG_M3_FAST_AP_FROM_ACT(sc->actual_block - 1);
          if (PNG_M3_FAST_AP_VALID(r2c)) {
            uint32_t target_pair = target_all
                ^ PNG_M3_FAST_SHIFT_AP(r2c, 2);
            uint32_t req_pair = png_crc_apply_inverse(pair_after_inv,
                target_pair);
            if (prefix_last_actual >= 0) {
              uint32_t pair_crc = 0;
              int64_t p0 = -1, p1 = -1;
              if (png_crc_actual_pair_crc(ht,
                      prefix_last_actual + 1 + (int64_t)first_full,
                      &pair_crc, &p0, &p1)
                  && pair_crc == req_pair) {
                PNG_M3_FAST_TRY(p0, p1, r2c, sap, sc,
                    "2+2-run-actual");
              }
            }
            if (!solved && pair_index) {
              uint32_t bucket = req_pair % PNG_GAP_WINDOW_BUCKETS;
              for (PNGGapWindowEntry *we = pair_index->buckets[bucket];
                   we && !solved; we = we->next) {
                if (we->crc != req_pair) {
                  continue;
                }
                uint32_t pair_crc = 0;
                int64_t p0 = -1, p1 = -1;
                if (!png_crc_actual_pair_crc(ht, we->start_actual,
                        &pair_crc, &p0, &p1)
                    || pair_crc != req_pair
                    || p0 == r2c || p1 == r2c
                    || p0 == sap || p1 == sap
                    || _AB_IN_BV_PREFIX(p0)
                    || _AB_IN_BV_PREFIX(p1)) {
                  continue;
                }
                PNG_M3_FAST_TRY(p0, p1, r2c, sap, sc,
                    "2+2-run");
              }
            }
          }
        }

        /* Position 0 singleton + positions 1,2 contiguous + suffix
         * singleton.  This is the dominant residual shape in the large PNG
         * test: a tiny displaced 2-block island between otherwise contiguous
         * filesystem runs.
         */
        if (!solved && pair_after2_inv_ok) {
          int64_t ab0 = (prefix_last_actual >= 0)
              ? PNG_M3_FAST_AP_FROM_ACT(prefix_last_actual + 1
                    + (int64_t)first_full)
              : -1;
          if (PNG_M3_FAST_AP_VALID(ab0)
              && !_AB_IN_BV_PREFIX(ab0)) {
            uint32_t target_pair = target_all
                ^ PNG_M3_FAST_SHIFT_AP(ab0, 0);
            uint32_t req_pair = png_crc_apply_inverse(pair_after2_inv,
                target_pair);
            if (pair_index) {
              uint32_t bucket = req_pair % PNG_GAP_WINDOW_BUCKETS;
              for (PNGGapWindowEntry *we = pair_index->buckets[bucket];
                   we && !solved; we = we->next) {
                if (we->crc != req_pair) {
                  continue;
                }
                uint32_t pair_crc = 0;
                int64_t p0 = -1, p1 = -1;
                if (!png_crc_actual_pair_crc(ht, we->start_actual,
                        &pair_crc, &p0, &p1)
                    || pair_crc != req_pair
                    || p0 == ab0 || p1 == ab0
                    || p0 == sap || p1 == sap
                    || _AB_IN_BV_PREFIX(p0)
                    || _AB_IN_BV_PREFIX(p1)) {
                  continue;
                }
                PNG_M3_FAST_TRY(ab0, p0, p1, sap, sc,
                    "1+2+1-run");
              }
            }
            int64_t scan_start = sc->actual_block > 64
                ? sc->actual_block - 64 : 0;
            for (int64_t actual_start = scan_start;
                 actual_start < sc->actual_block && !solved;
                 actual_start++) {
              uint32_t pair_crc = 0;
              int64_t p0 = -1, p1 = -1;
              if (!png_crc_actual_pair_crc(ht, actual_start,
                      &pair_crc, &p0, &p1)
                  || pair_crc != req_pair
                  || p0 == ab0 || p1 == ab0
                  || p0 == sap || p1 == sap
                  || _AB_IN_BV_PREFIX(p0)
                  || _AB_IN_BV_PREFIX(p1)) {
                continue;
              }
              PNG_M3_FAST_TRY(ab0, p0, p1, sap, sc,
                  "1+2+1-run-actual");
            }
          }
        }
      }

      #undef PNG_M3_FAST_TRY
      #undef PNG_M3_FAST_RESTORE_CONTIG
      #undef PNG_M3_FAST_SHIFT_AP
      #undef PNG_M3_FAST_AP_FROM_ACT
      #undef PNG_M3_FAST_AP_VALID

      if (solved) {
        free(suffix_cands);
        return 2;
      }
    }
  }

  // MitM: split M middle blocks into left half and right half.
  // Split middle blocks: left gets more to keep right scan cheap.
  // Right scan includes the suffix block (iterated separately), so
  // right_count should be small.  For M=2: left=1, right=1.
  // For M=3: left=2, right=1.  For M=4: left=2, right=2.
  // M≤3: left=1 (O(N) table), right=M-1 (O(N) er2 table + O(N²) scan).
  // Each M=3 scan iteration: 1 XOR + 1 hash probe, O(N) memory.
  // M≥4: left=ceil(M/2), right=M-left.
  uint32_t left_count = (M <= 3) ? 1 : (M + 1) / 2;
  uint32_t right_count = M - left_count;
  int64_t resume_si = 0;
  int64_t resume_er1 = 0;
  int64_t resume_er2 = 0;
  uint8_t resume_phase = 0;
  uint8_t resume_pair = 0;

  z_off_t right_total_len = (z_off_t)right_count * (z_off_t)bs
      + (z_off_t)suffix_partial_len;

  uint32_t Minv[32];
  if (!png_crc_inverse_for_len(right_total_len, Minv)) {
    free(suffix_cands);
    resize_blockvector(candidate->b, suffix_start_nb);
    return 0;
  }

  // Resume from the saved frontier when the IDAT geometry still matches.
  if (local->solver_suffix_nb == suffix_start_nb
      && local->solver_phase != 0) {
    resume_si = local->solver_suffix_idx;
    resume_er1 = local->solver_right_idx;
    resume_er2 = local->solver_right_idx2;
    resume_phase = local->solver_phase;
    resume_pair = local->solver_pair_idx;
  }

  // Build left table: all combinations of left_count middle blocks.
  // left_crc = crc32_combine chain from crc_prefix through left blocks.
  // For left_count=1: O(N) entries.  For left_count=2: O(N²) entries.

  if (left_count == 1) {
    // Check/build solver_ctx — cloned across in-process queue handoffs.
    PNGSolverContext *sctx = local->solver_ctx;
    bool need_build = (!sctx || !sctx->valid
        || sctx->built_for_suffix_nb != suffix_start_nb
        || sctx->built_for_crc_pos != crc_pos);
    if (need_build) {
      png_solver_ctx_free(&local->solver_ctx);
      sctx = (PNGSolverContext *)calloc(1, sizeof(PNGSolverContext));
      if (!sctx) {
        free(suffix_cands);
        resize_blockvector(candidate->b, suffix_start_nb);
        return 0;
      }
      local->solver_ctx = sctx;

      // Left table: for each b_left, left_crc = crc32_combine(crc_prefix, b_left_crc, bs)
      sctx->left_table = (MitmEntry2 **)calloc(MITM_BUCKETS2, sizeof(MitmEntry2 *));
      sctx->left_pool = (MitmEntry2 *)malloc(
          (size_t)ht->total_entries * sizeof(MitmEntry2));
      if (! sctx->left_table || ! sctx->left_pool) {
        png_solver_ctx_free(&local->solver_ctx);
        free(suffix_cands);
        resize_blockvector(candidate->b, suffix_start_nb);
        return 0;
      }

      // Pre-compute the shifted prefix: crc32_combine(crc_prefix, 0, bs).
      uint32_t shifted_prefix = (uint32_t)crc32_combine(
          (uLong)crc_prefix, 0UL, (z_off_t)bs);
      uint32_t _lt_count = 0;
      for (uint32_t b = 0; b < PNG_CRC_HASH_BUCKETS; b++) {
        for (PNGCrcEntry *e = ht->buckets[b]; e; e = e->next) {
          uint32_t lcrc = shifted_prefix ^ e->crc;
          MitmEntry2 *me = &sctx->left_pool[_lt_count++];
          me->crc = lcrc;
          me->actual = e->actual_block;
          uint32_t idx = lcrc % MITM_BUCKETS2;
          me->next = sctx->left_table[idx];
          sctx->left_table[idx] = me;
        }
      }

      // Flatten hash table into array for indexed resume after checkpoint.
      sctx->ht_flat_count = 0;
      for (uint32_t b = 0; b < PNG_CRC_HASH_BUCKETS; b++) {
        for (PNGCrcEntry *e = ht->buckets[b]; e; e = e->next) {
          sctx->ht_flat_count++;
        }
      }
      sctx->ht_flat = (PNGCrcEntry **)malloc(
          (size_t)sctx->ht_flat_count * sizeof(PNGCrcEntry *));
      if (sctx->ht_flat) {
        /* Filter out already-covered and unmapped entries at build time.
         * At 3000-file scale after most validate, most hash entries are
         * covered; scanning them per-call wastes enormous time.  This is
         * the same optimization BBK does in its flat[] build. */
        uint32_t fi = 0;
        for (uint32_t b = 0; b < PNG_CRC_HASH_BUCKETS; b++) {
          for (PNGCrcEntry *e = ht->buckets[b]; e; e = e->next) {
            if (filemirror_actual_block_covered(
                    scalpel_state.filemirror, e->actual_block)) {
              continue;
            }
            if (filemirror_apparent_blocknumber(
                    scalpel_state.filemirror, e->actual_block) < 0) {
              continue;
            }
            sctx->ht_flat[fi++] = e;
          }
        }
        sctx->ht_flat_count = fi;
      }

      // Copy suffix_cands into solver_ctx for persistence.
      sctx->suffix_cands = suffix_cands;
      sctx->nsuffix = (uint32_t)suffix_cand_count;

      sctx->built_for_suffix_nb = suffix_start_nb;
      sctx->built_for_crc_pos = crc_pos;
      sctx->valid = true;
      // Caller's suffix_cands is now owned by sctx — NULL to prevent double-free.
      suffix_cands = NULL;
    } else {
      // Reuse existing context — also reuse its suffix_cands.
      // Free the freshly-allocated suffix_cands (duplicate).
      free(suffix_cands);
      suffix_cands = NULL;
      suffix_cand_count = sctx->nsuffix;
    }

    // Aliases for readability
    MitmEntry2 **left_table = sctx->left_table;
    MitmEntry2 *left_pool = sctx->left_pool;
    PNGSuffixCand *sc_arr = sctx->suffix_cands;
    (void)left_pool; /* suppress unused warning — used via left_table chains */

    bool m2_best_found = false;
    bool m2_best_validated = false;
    uint64_t m2_best_validates_to = 0;
    uint64_t m2_best_advance_to = 0;
    uint32_t m2_best_locality = 0;
    int64_t m2_best_left_actual = -1;
    int64_t m2_best_right_actual = -1;
    int64_t m2_best_suffix_actual = -1;
    bool stop_m2_scan = false;
    int64_t m2_start_si = 0;
    uint64_t m2_poll_count = 0;

    if (right_count == 1) {
      bool resume_matches = local->m2_resume.active
          && local->m2_resume.suffix_nb == suffix_start_nb
          && local->m2_resume.crc_pos == crc_pos
          && local->m2_resume.fill_needed == fill_needed;
      if (!resume_matches) {
        png_m2_resume_reset(&local->m2_resume);
        local->m2_resume.active = true;
        local->m2_resume.suffix_nb = suffix_start_nb;
        local->m2_resume.crc_pos = crc_pos;
        local->m2_resume.fill_needed = fill_needed;
      } else {
        m2_best_found = local->m2_resume.best_found;
        m2_best_validated = local->m2_resume.best_validated;
        m2_best_validates_to = local->m2_resume.best_validates_to;
        m2_best_advance_to = local->m2_resume.best_advance_to;
        m2_best_locality = local->m2_resume.best_locality;
        m2_best_left_actual = local->m2_resume.best_left_actual;
        m2_best_right_actual = local->m2_resume.best_right_actual;
        m2_best_suffix_actual = local->m2_resume.best_suffix_actual;

        if (m2_best_found) {
          int64_t best_left = png_crc_actual_to_apparent(
              ht, m2_best_left_actual);
          int64_t best_right = png_crc_actual_to_apparent(
              ht, m2_best_right_actual);
          int64_t best_suffix = png_crc_actual_to_apparent(
              ht, m2_best_suffix_actual);
          if (best_left < 0 || best_right < 0 || best_suffix < 0
              || best_left == best_right || best_left == best_suffix
              || best_right == best_suffix
              || _AB_IN_BV_PREFIX(best_left)
              || _AB_IN_BV_PREFIX(best_right)
              || _AB_IN_BV_PREFIX(best_suffix)) {
            m2_best_found = false;
            local->m2_resume.best_found = false;
          }
        }

        if (local->m2_resume.suffix_actual >= 0) {
          bool found_suffix = false;
          for (int64_t si = 0; si < suffix_cand_count; si++) {
            if (sc_arr[si].actual_block
                == local->m2_resume.suffix_actual) {
              m2_start_si = si;
              found_suffix = true;
              break;
            }
          }
          if (!found_suffix) {
            local->m2_resume.bucket = 0;
            local->m2_resume.next_actual = -1;
            local->m2_resume.suffix_actual = -1;
          }
        }
      }
    } else {
      png_m2_resume_reset(&local->m2_resume);
    }

    uint32_t m2_suffix_forward[32];
    if (right_count == 1) {
      png_crc_forward_for_len((z_off_t)suffix_partial_len,
                              m2_suffix_forward);
    }

    // Suffix candidate loop — M=2 (right_count == 1) uses sc->stored_crc.
    for (int64_t si = m2_start_si; si < suffix_cand_count && !stop_m2_scan;
         si++) {
      PNGSuffixCand *sc = &sc_arr[si];
      if (!sc->valid || right_count != 1) {
        continue;
      }

      uint32_t br_start = 0;
      bool use_resume_cursor =
          local->m2_resume.suffix_actual == sc->actual_block;
      if (use_resume_cursor) {
        br_start = local->m2_resume.bucket;
        if (br_start >= PNG_CRC_HASH_BUCKETS) {
          br_start = 0;
          use_resume_cursor = false;
        }
      }

      // M=2: left=1, right=1. For each right middle block:
      for (uint32_t br = br_start; br < PNG_CRC_HASH_BUCKETS && !stop_m2_scan;
           br++) {
        PNGCrcEntry *er_start = ht->buckets[br];
        if (use_resume_cursor && br == br_start &&
            local->m2_resume.next_actual >= 0) {
          PNGCrcEntry *saved = er_start;
          while (saved && saved->actual_block != local->m2_resume.next_actual) {
            saved = saved->next;
          }
          if (saved) {
            er_start = saved;
          }
        }
        use_resume_cursor = false;

        for (PNGCrcEntry *er = er_start; er && !stop_m2_scan; er = er->next) {
          if ((m2_poll_count++ & 0xFFULL) == 0ULL &&
              png_reassembly_yield_requested(candidate)) {
            local->m2_resume.active = true;
            local->m2_resume.suffix_nb = suffix_start_nb;
            local->m2_resume.crc_pos = crc_pos;
            local->m2_resume.fill_needed = fill_needed;
            local->m2_resume.suffix_actual = sc->actual_block;
            local->m2_resume.bucket = br;
            local->m2_resume.next_actual = er->actual_block;
            resize_blockvector(candidate->b, suffix_start_nb);
            return -1;
          }
          /* Skip covered or unmapped right-candidates at loop time —
           * they can't be placed, so the expensive algebra below is
           * wasted on them.  Also skip blocks already in BV prefix. */
          if (filemirror_actual_block_covered(scalpel_state.filemirror,
                                              er->actual_block)) {
            continue;
          }
          int64_t _er_ap = filemirror_apparent_blocknumber(
              scalpel_state.filemirror, er->actual_block);
          if (_er_ap < 0) {
            continue;
          }
          if (_AB_IN_BV_PREFIX(_er_ap)) {
            continue;
          }
          // right_crc = combine(b_right, suffix_partial)
          uint32_t rcrc = png_crc_apply_forward(m2_suffix_forward,
              er->crc) ^ sc->partial_crc;
          uint32_t f_right = rcrc;
          uint32_t xored = sc->stored_crc ^ f_right;
          uint32_t req_left = 0;
          for (int bit = 0; bit < 32; bit++) {
            if (xored & (1U << bit)) {
              req_left ^= Minv[bit];
            }
          }
          // Lookup in left table
          uint32_t lidx = req_left % MITM_BUCKETS2;
          for (MitmEntry2 *me = left_table[lidx]; me && !solved;
               me = me->next) {
            if (me->crc != req_left) {
              continue;
            }
            // Match: me->actual = left middle, er->actual_block = right middle,
            // sc = suffix
            if (me->actual == er->actual_block ||
                me->actual == sc->actual_block ||
                er->actual_block == sc->actual_block) {
              continue;
            }
            /* Skip if left is covered (right already filtered above). */
            if (filemirror_actual_block_covered(scalpel_state.filemirror,
                                                me->actual)) {
              continue;
            }
            // Place all blocks and full verify
            int64_t ab_l = filemirror_apparent_blocknumber(
                scalpel_state.filemirror, me->actual);
            int64_t ab_r = filemirror_apparent_blocknumber(
                scalpel_state.filemirror, er->actual_block);
            if (ab_l < 0 || ab_r < 0) {
              continue;
            }
            /* Skip if left would duplicate a block already in the
             * BV prefix (right was filtered above, suffix_ab too).
             * Suffix candidate's apparent block also not in prefix. */
            if (_AB_IN_BV_PREFIX(ab_l)) {
              continue;
            }
            if (_AB_IN_BV_PREFIX(sc->apparent_block)) {
              continue;
            }
            blockvector_set_apparent_blocknumber(
                candidate->b, suffix_start_nb + first_full, ab_l);
            blockvector_set_apparent_blocknumber(
                candidate->b, suffix_start_nb + first_full + 1, ab_r);
            blockvector_set_apparent_blocknumber(
                candidate->b, suffix_start_nb + suffix_fill_pos,
                sc->apparent_block);
            for (uint32_t f = 0; f < fill_needed; f++) {
              inflate_blockvector_single_block(candidate->b,
                                               suffix_start_nb + f);
            }
            const char *vd = blockvector_get_data_pointer(candidate->b);
            uint64_t vdl = blockvector_get_data_length(candidate->b);
            if (crc_field_pos + 4 <= vdl) {
              uint32_t vcrc = crc32(0, NULL, 0);
              vcrc = crc32(vcrc, (const unsigned char *)(vd + type_start),
                           (uInt)crc_region_len);
              // Compare against sc->stored_crc (from mmap), NOT BV data.
              // BV-read stored CRC is tautological — placed blocks may be
              // from a different IDAT with internally consistent CRC.
              if (vcrc == sc->stored_crc) {
                bool _sok = false;
                uint64_t _nxt = crc_field_pos + 8;
                if (_nxt + 4 <= vdl) {
                  const unsigned char *_tp = (const unsigned char *)(vd + _nxt);
                  const unsigned char *_lp =
                      (const unsigned char *)(vd + crc_field_pos + 4);
                  uint32_t _nl = ((uint32_t)_lp[0] << 24) |
                                 ((uint32_t)_lp[1] << 16) |
                                 ((uint32_t)_lp[2] << 8) | (uint32_t)_lp[3];
                  if (_tp[0] == 'I' && _tp[1] == 'D' && _tp[2] == 'A' &&
                      _tp[3] == 'T' && _nl <= PNG_MAX_IDAT_BODY_LEN) {
                    _sok = true;
                  } else if (_tp[0] == 'I' && _tp[1] == 'E' && _tp[2] == 'N' &&
                             _tp[3] == 'D' && _nl == 0 && _nxt + 8 <= vdl) {
                    const unsigned char *_ic =
                        (const unsigned char *)(vd + _nxt + 4);
                    uint32_t _icrc = ((uint32_t)_ic[0] << 24) |
                                     ((uint32_t)_ic[1] << 16) |
                                     ((uint32_t)_ic[2] << 8) | (uint32_t)_ic[3];
                    if (_icrc == 0xAE426082U) {
                      _sok = true;
                    }
                  }
                }
                if (_sok) {
                  PNGSolverStateSnapshot _pre_snap;
                  png_solver_snapshot(&_pre_snap, local);
                  uint64_t _crc_pre = local->last_chunk_crc_pos;
                  bool _sv2;
                  uint64_t _svt2;
                  _sv2 = png_direct_validate(work->id, candidate, &_svt2, local,
                                             uuidp, uuidc);
                  uint64_t _advance = local->last_chunk_crc_pos;
                  bool _plausible = _sv2 || _advance > _crc_pre;
                  int64_t _window_ap[PNG_GAP_INDEX_MAX_M];
                  _window_ap[0] = ab_l;
                  _window_ap[1] = ab_r;
                  uint32_t _locality = png_gap_locality_score(
                      candidate, suffix_start_nb, first_full, _window_ap, M);
                  if (png_trace_this) {
                    lock_fprintf(stdout,
                                 "PNG_TRACE_M2_TRY si=%" PRId64 " left=%" PRId64
                                 " right=%" PRId64 " suffix=%" PRId64
                                 " suffix_actual=%" PRId64
                                 " validated=%d vt=%" PRIu64 " advance=%" PRIu64
                                 " pre=%" PRIu64 " locality=%u plausible=%d\n",
                                 si, ab_l, ab_r, sc->apparent_block,
                                 sc->actual_block, _sv2 ? 1 : 0, _svt2,
                                 _advance, _crc_pre, _locality,
                                 _plausible ? 1 : 0);
                  }
                  bool _new_best =
                      _plausible &&
                      png_gap_match_better(
                          _sv2, _svt2, _advance, _locality, m2_best_found,
                          m2_best_validated, m2_best_validates_to,
                          m2_best_advance_to, m2_best_locality);
                  if (_new_best) {
                    m2_best_found = true;
                    m2_best_validated = _sv2;
                    m2_best_validates_to = _svt2;
                    m2_best_advance_to = _advance;
                    m2_best_locality = _locality;
                    m2_best_left_actual = me->actual;
                    m2_best_right_actual = er->actual_block;
                    m2_best_suffix_actual = sc->actual_block;
                    if (_sv2 || _locality == M) {
                      stop_m2_scan = true;
                    }
                  }
                  png_solver_restore(local, &_pre_snap);
                  if (_new_best) {
                    local->m2_resume.best_found = true;
                    local->m2_resume.best_validated = m2_best_validated;
                    local->m2_resume.best_validates_to = m2_best_validates_to;
                    local->m2_resume.best_advance_to = m2_best_advance_to;
                    local->m2_resume.best_locality = m2_best_locality;
                    local->m2_resume.best_left_actual = m2_best_left_actual;
                    local->m2_resume.best_right_actual = m2_best_right_actual;
                    local->m2_resume.best_suffix_actual = m2_best_suffix_actual;
                  }
                }
              }
            }
            // Undo — restore contiguous before trying the next match.
            for (uint32_t f = 0; f < fill_needed; f++) {
              int64_t orig = last_block + 1 + (int64_t)f;
              blockvector_set_apparent_blocknumber(candidate->b,
                                                   suffix_start_nb + f, orig);
              inflate_blockvector_single_block(candidate->b,
                                               suffix_start_nb + f);
            }
          }
        }
      }
    } // end suffix candidate loop (M=2)

    png_m2_resume_reset(&local->m2_resume);
    if (m2_best_found) {
      int64_t m2_best_left =
          png_crc_actual_to_apparent(ht, m2_best_left_actual);
      int64_t m2_best_right =
          png_crc_actual_to_apparent(ht, m2_best_right_actual);
      int64_t m2_best_suffix =
          png_crc_actual_to_apparent(ht, m2_best_suffix_actual);
      bool best_placeable =
          m2_best_left >= 0 && m2_best_right >= 0 && m2_best_suffix >= 0 &&
          m2_best_left != m2_best_right && m2_best_left != m2_best_suffix &&
          m2_best_right != m2_best_suffix && !_AB_IN_BV_PREFIX(m2_best_left) &&
          !_AB_IN_BV_PREFIX(m2_best_right) && !_AB_IN_BV_PREFIX(m2_best_suffix);
      if (best_placeable) {
        png_solver_resize_trial(candidate, suffix_start_nb + fill_needed);
        blockvector_set_apparent_blocknumber(
            candidate->b, suffix_start_nb + first_full, m2_best_left);
        blockvector_set_apparent_blocknumber(
            candidate->b, suffix_start_nb + first_full + 1, m2_best_right);
        blockvector_set_apparent_blocknumber(
            candidate->b, suffix_start_nb + suffix_fill_pos, m2_best_suffix);
        for (uint32_t f = 0; f < fill_needed; f++) {
          inflate_blockvector_single_block(candidate->b, suffix_start_nb + f);
        }

        PNGSolverStateSnapshot final_pre_snap;
        png_solver_snapshot(&final_pre_snap, local);
        uint64_t final_crc_pre = local->last_chunk_crc_pos;
        uint64_t final_vt = 0;
        bool final_validated = png_direct_validate(
            work->id, candidate, &final_vt, local, uuidp, uuidc);
        bool final_plausible =
            final_validated || local->last_chunk_crc_pos > final_crc_pre;
        if (final_plausible) {
          if (scalpel_state.mode_verbose) {
            lock_fprintf(stdout,
                         "%sPNG CRC SOLVER: M=2 selected blocks [%" PRId64
                         ",%" PRId64 "] suffix %" PRId64 "%s\n",
                         GREEN, m2_best_left, m2_best_right, m2_best_suffix,
                         BLACK);
          }
          solved = true;
        } else {
          png_solver_restore(local, &final_pre_snap);
        }
      }
    }

    // ================================================================
    // M=3 algebraic solver: O(S × N) where S ~ 1-5 suffix candidates.
    //
    // Geometry-dependent tables (shifted-CRC) built ONCE outside the loop.
    // Phase A/B run per suffix candidate using sc->stored_crc for correct
    // diff when the suffix block is also displaced.
    // ================================================================
    if (right_count == 2 && !solved) {
      // Get contiguous block CRCs for the 3 middle positions.
      // Compute mid_crc directly from BV data — always correct after
      // inflate, works for ANY block type (zero fill, random fill, etc.).
      // The old approach used png_get_block_crc which fails for fill
      // blocks without PNGBlockState, disabling the entire M=3 solver.
      uint32_t mid_crc[3];
      bool mid_crc_ok = true;
      for (int mi = 0; mi < 3; mi++) {
        uint32_t fidx = first_full + mi;
        uint64_t blk_byte = (suffix_start_nb + fidx) * (uint64_t)bs;
        if (blk_byte + bs <= dl) {
          mid_crc[mi] = crc32(crc32(0, NULL, 0),
              (const unsigned char *)(data + blk_byte), (uInt)bs);
        }
        else {
          mid_crc_ok = false;
        }
      }

      if (mid_crc_ok) {
        // Compute bytes_after for each of the 3 middle positions.
        z_off_t after[3];
        uint32_t after_forward[3][32];
        for (int mi = 0; mi < 3; mi++) {
          uint64_t blk_end = (suffix_start_nb + first_full + mi)
              * (uint64_t)bs + bs;
          after[mi] = (z_off_t)(crc_region_end > blk_end
              ? crc_region_end - blk_end : 0);
          png_crc_forward_for_len(after[mi], after_forward[mi]);
        }

        // Shifted contiguous CRCs (constant per position).
        uint32_t shifted_contig[3];
        for (int mi = 0; mi < 3; mi++) {
          shifted_contig[mi] = png_crc_apply_forward(
              after_forward[mi], mid_crc[mi]);
        }

        uint32_t block_forward[32];
        uint32_t suffix_forward[32];
        png_crc_forward_for_len((z_off_t)bs, block_forward);
        png_crc_forward_for_len((z_off_t)suffix_partial_len, suffix_forward);
        uint32_t mid_crc_up_to_suffix = crc_prefix;
        for (int mi = 0; mi < 3; mi++) {
          mid_crc_up_to_suffix = png_crc_apply_forward(block_forward,
              mid_crc_up_to_suffix) ^ mid_crc[mi];
        }

        // Build shifted-CRC lookup tables ONCE (geometry-only, O(N)).
        // Persist in solver_ctx so repeated solver calls reuse the tables.
        #define M3_TAB(k) (sctx->m3_alias[(int)(k)] >= 0 \
            ? sctx->m3_alias[(int)(k)] : (int)(k))

        if (!sctx->m3_tables_valid) {
          for (int mi = 0; mi < 3; mi++) {
            sctx->m3_htab[mi] = NULL;
            sctx->m3_pool[mi] = NULL;
            sctx->m3_count[mi] = 0;
            sctx->m3_alias[mi] = -1;
          }
          for (int mi = 0; mi < 3; mi++) {
            bool shared = false;
            for (int prev = 0; prev < mi; prev++) {
              if (after[mi] == after[prev]) {
                sctx->m3_alias[mi] = prev;
                shared = true;
                break;
              }
            }
            if (shared) { continue; }
            sctx->m3_htab[mi] = (Er2Entry **)calloc(
                PNG_M3_BUCKETS, sizeof(Er2Entry *));
            sctx->m3_pool[mi] = (Er2Entry *)malloc(
                (size_t)ht->total_entries * sizeof(Er2Entry));
            if (!sctx->m3_htab[mi] || !sctx->m3_pool[mi]) {
              free(sctx->m3_htab[mi]); free(sctx->m3_pool[mi]);
              sctx->m3_htab[mi] = NULL; sctx->m3_pool[mi] = NULL;
              continue;
            }
            uint32_t cnt = 0;
            for (uint32_t b2 = 0; b2 < PNG_CRC_HASH_BUCKETS; b2++) {
              for (PNGCrcEntry *e = ht->buckets[b2]; e; e = e->next) {
                /* Filter at build time — same rationale as ht_flat. */
                if (filemirror_actual_block_covered(
                        scalpel_state.filemirror, e->actual_block)) {
                  continue;
                }
                if (filemirror_apparent_blocknumber(
                        scalpel_state.filemirror, e->actual_block) < 0) {
                  continue;
                }
                uint32_t sc2 = png_crc_apply_forward(
                    after_forward[mi], e->crc);
                Er2Entry *ent = &sctx->m3_pool[mi][cnt++];
                ent->shifted_crc = sc2;
                ent->actual_block = e->actual_block;
                uint32_t idx = sc2 % PNG_M3_BUCKETS;
                ent->next = sctx->m3_htab[mi][idx];
                sctx->m3_htab[mi][idx] = ent;
              }
            }
            sctx->m3_count[mi] = cnt;
          }
          sctx->m3_tables_valid = true;
        }

        // Iterate suffix candidates — S is ~1-5 after structural pre-filter.
        // Aliases for readability.
        Er2Entry **m3_htab[3] = {sctx->m3_htab[0], sctx->m3_htab[1], sctx->m3_htab[2]};
        int64_t m3_total_ap = (int64_t)filemirror_apparent_blocks(
            scalpel_state.filemirror);
        uint32_t *m3_ab_crc = NULL;
        bool *m3_ab_valid = NULL;
        if (m3_total_ap > 0) {
          m3_ab_crc = (uint32_t *)calloc((size_t)m3_total_ap,
                                         sizeof(uint32_t));
          m3_ab_valid = (bool *)calloc((size_t)m3_total_ap,
                                       sizeof(bool));
          if (m3_ab_crc && m3_ab_valid) {
            for (uint32_t b2 = 0; b2 < PNG_CRC_HASH_BUCKETS; b2++) {
              for (PNGCrcEntry *e = ht->buckets[b2]; e; e = e->next) {
                if (filemirror_actual_block_covered(
                        scalpel_state.filemirror, e->actual_block)) {
                  continue;
                }
                int64_t ab = filemirror_apparent_blocknumber(
                    scalpel_state.filemirror, e->actual_block);
                if (ab >= 0 && ab < m3_total_ap) {
                  m3_ab_crc[ab] = e->crc;
                  m3_ab_valid[ab] = true;
                }
              }
            }
          }
        }

        for (int64_t si = resume_si; si < suffix_cand_count && !solved; si++) {
          PNGSuffixCand *sc = &sc_arr[si];
          if (!sc->valid) { continue; }

          // Compute diff using THIS suffix candidate's stored CRC.
          // CRC of prefix + 3 contiguous middle blocks + suffix partial:
          uint32_t crc_with_sc = png_crc_apply_forward(suffix_forward,
              mid_crc_up_to_suffix) ^ sc->partial_crc;
          uint32_t diff = sc->stored_crc ^ crc_with_sc;
          if (diff == 0) { continue; }  // contiguous already matches this suffix

          // ---- Suffix-anchored split-run fast path ----
          // The large corpus most often leaves the suffix block contiguous
          // with one or more preceding middle blocks:
          //   positions 0,1 + positions 2,suffix
          //   position  0   + positions 1,2,suffix
          // The generic split-run path below treats the suffix as independent,
          // so it misses that structure and wastes work.  Anchor on the
          // structurally-filtered suffix candidate and solve the remaining
          // middle positions algebraically.
          if (!solved && m3_ab_crc && m3_ab_valid
              && suffix_fill_pos == first_full + 3
              && (resume_phase == 0 || resume_phase == 5
                  || si > resume_si)) {
            int64_t sap = sc->apparent_block;
            bool sc_place_ok = (sap >= 0 && sap < m3_total_ap
                && !_AB_IN_BV_PREFIX(sap)
                && !filemirror_actual_block_covered(
                    scalpel_state.filemirror, sc->actual_block));

            #define PNG_M3_AP_VALID(_ap) \
              ((_ap) >= 0 && (_ap) < m3_total_ap && m3_ab_valid[(_ap)])
            #define PNG_M3_AP_FROM_ACT(_act) \
              png_crc_actual_to_apparent(ht, (_act))
            #define PNG_M3_SHIFT_AP(_ap, _pos) \
              png_crc_apply_forward(after_forward[(_pos)], \
                                    m3_ab_crc[(_ap)])
            #define PNG_M3_RESTORE_CONTIG() do { \
              for (uint32_t _rf = 0; _rf < fill_needed; _rf++) { \
                int64_t _orig = last_block + 1 + (int64_t)_rf; \
                blockvector_set_apparent_blocknumber(candidate->b, \
                    suffix_start_nb + _rf, _orig); \
                inflate_blockvector_single_block(candidate->b, \
                    suffix_start_nb + _rf); \
              } \
            } while (0)
            #define PNG_M3_TRY_SUFFIX_PLACEMENT(_ab0, _ab1, _ab2, _kind) do { \
              int64_t _pa0 = (_ab0); \
              int64_t _pa1 = (_ab1); \
              int64_t _pa2 = (_ab2); \
              if (!solved && sc_place_ok \
                  && PNG_M3_AP_VALID(_pa0) && PNG_M3_AP_VALID(_pa1) \
                  && PNG_M3_AP_VALID(_pa2) \
                  && !_AB_IN_BV_PREFIX(_pa0) \
                  && !_AB_IN_BV_PREFIX(_pa1) \
                  && !_AB_IN_BV_PREFIX(_pa2) \
                  && _pa0 != _pa1 && _pa0 != _pa2 && _pa1 != _pa2 \
                  && _pa0 != sap && _pa1 != sap && _pa2 != sap) { \
                int64_t _aa0 = filemirror_actual_blocknumber( \
                    scalpel_state.filemirror, _pa0); \
                int64_t _aa1 = filemirror_actual_blocknumber( \
                    scalpel_state.filemirror, _pa1); \
                int64_t _aa2 = filemirror_actual_blocknumber( \
                    scalpel_state.filemirror, _pa2); \
                if (_aa0 >= 0 && _aa1 >= 0 && _aa2 >= 0 \
                    && _aa0 != _aa1 && _aa0 != _aa2 && _aa1 != _aa2 \
                    && _aa0 != sc->actual_block \
                    && _aa1 != sc->actual_block \
                    && _aa2 != sc->actual_block \
                    && !filemirror_actual_block_covered( \
                        scalpel_state.filemirror, _aa0) \
                    && !filemirror_actual_block_covered( \
                        scalpel_state.filemirror, _aa1) \
                    && !filemirror_actual_block_covered( \
                        scalpel_state.filemirror, _aa2)) { \
                  resize_blockvector(candidate->b, \
                      suffix_start_nb + fill_needed); \
                  blockvector_set_apparent_blocknumber(candidate->b, \
                      suffix_start_nb + first_full + 0, _pa0); \
                  blockvector_set_apparent_blocknumber(candidate->b, \
                      suffix_start_nb + first_full + 1, _pa1); \
                  blockvector_set_apparent_blocknumber(candidate->b, \
                      suffix_start_nb + first_full + 2, _pa2); \
                  blockvector_set_apparent_blocknumber(candidate->b, \
                      suffix_start_nb + suffix_fill_pos, sap); \
                  for (uint32_t _if = 0; _if < fill_needed; _if++) { \
                    inflate_blockvector_single_block(candidate->b, \
                        suffix_start_nb + _if); \
                  } \
                  if (png_solver_crc_marker_matches(candidate, type_start, \
                          crc_region_len, crc_field_pos, sc->stored_crc) \
                      && png_solver_confirm_match(candidate, local, work, \
                          uuidp, uuidc, crc_pos, idat_sz)) { \
                    if (scalpel_state.mode_verbose) { \
                      lock_fprintf(stdout, \
                          "%sPNG CRC SOLVER: M=3 suffix-run %s blocks " \
                          "[%" PRId64 ",%" PRId64 ",%" PRId64 \
                          "] suffix %" PRId64 "%s\n", \
                          GREEN, (_kind), _pa0, _pa1, _pa2, sap, BLACK); \
                    } \
                    solved = true; \
                  } \
                  if (!solved) { PNG_M3_RESTORE_CONTIG(); } \
                } \
              } \
            } while (0)

            uint32_t target_all = diff ^ shifted_contig[0]
                ^ shifted_contig[1] ^ shifted_contig[2];
            PNGGapWindowTable *pair_index = png_gap_window_table_get(ht, 2);
            uint32_t pair_after_inv[32];
            bool pair_after_inv_ok = png_crc_inverse_for_len(after[1],
                pair_after_inv);
            uint32_t pair_after2_inv[32];
            bool pair_after2_inv_ok = png_crc_inverse_for_len(after[2],
                pair_after2_inv);

            if (sc_place_ok) {
              int64_t prefix_last_actual = (suffix_start_nb > 0)
                  ? blockvector_get_actual_blocknumber(candidate->b,
                      suffix_start_nb - 1)
                  : -1;
              // All four fill blocks are one displaced contiguous run.
              int64_t r0 = PNG_M3_AP_FROM_ACT(sc->actual_block - 3);
              int64_t r1 = PNG_M3_AP_FROM_ACT(sc->actual_block - 2);
              int64_t r2 = PNG_M3_AP_FROM_ACT(sc->actual_block - 1);
              if (PNG_M3_AP_VALID(r0) && PNG_M3_AP_VALID(r1)
                  && PNG_M3_AP_VALID(r2)) {
                uint32_t run_shift = PNG_M3_SHIFT_AP(r0, 0)
                    ^ PNG_M3_SHIFT_AP(r1, 1)
                    ^ PNG_M3_SHIFT_AP(r2, 2);
                if (run_shift == target_all) {
                  PNG_M3_TRY_SUFFIX_PLACEMENT(r0, r1, r2, "4-run");
                }
              }

              // Position 0 singleton + positions 1,2,suffix contiguous.
              if (!solved) {
                int64_t r1b = PNG_M3_AP_FROM_ACT(sc->actual_block - 2);
                int64_t r2b = PNG_M3_AP_FROM_ACT(sc->actual_block - 1);
                int ti_0 = M3_TAB(0);
                if (PNG_M3_AP_VALID(r1b) && PNG_M3_AP_VALID(r2b)
                    && m3_htab[ti_0]) {
                  uint32_t needed_0 = target_all
                      ^ PNG_M3_SHIFT_AP(r1b, 1)
                      ^ PNG_M3_SHIFT_AP(r2b, 2);
                  uint32_t bidx = needed_0 % PNG_M3_BUCKETS;
                  for (Er2Entry *me = m3_htab[ti_0][bidx];
                       me && !solved; me = me->next) {
                    if (me->shifted_crc != needed_0) { continue; }
                    if (filemirror_actual_block_covered(
                            scalpel_state.filemirror, me->actual_block)) {
                      continue;
                    }
                    int64_t ab0 = filemirror_apparent_blocknumber(
                        scalpel_state.filemirror, me->actual_block);
                    if (ab0 < 0 || ab0 == r1b || ab0 == r2b
                        || ab0 == sap) {
                      continue;
                    }
                    PNG_M3_TRY_SUFFIX_PLACEMENT(ab0, r1b, r2b,
                        "1+3-run");
                  }
                }
              }

              // Positions 0,1 contiguous + positions 2,suffix contiguous.
              if (!solved && pair_after_inv_ok) {
                int64_t r2c = PNG_M3_AP_FROM_ACT(sc->actual_block - 1);
                if (PNG_M3_AP_VALID(r2c)) {
                  uint32_t target_pair = target_all
                      ^ PNG_M3_SHIFT_AP(r2c, 2);
                  uint32_t req_pair = png_crc_apply_inverse(pair_after_inv,
                      target_pair);
                  if (prefix_last_actual >= 0) {
                    uint32_t pair_crc = 0;
                    int64_t p0 = -1, p1 = -1;
                  if (png_crc_actual_pair_crc(ht,
                          prefix_last_actual + 1 + (int64_t)first_full,
                          &pair_crc, &p0, &p1)
                      && pair_crc == req_pair) {
                      PNG_M3_TRY_SUFFIX_PLACEMENT(p0, p1, r2c,
                        "2+2-run-actual");
                    }
                  }
                  if (!solved && pair_index) {
                    uint32_t bucket = req_pair % PNG_GAP_WINDOW_BUCKETS;
                    for (PNGGapWindowEntry *we = pair_index->buckets[bucket];
                         we && !solved; we = we->next) {
                      if (we->crc != req_pair) {
                        continue;
                      }
                      uint32_t pair_crc = 0;
                      int64_t p0 = -1, p1 = -1;
                      if (!png_crc_actual_pair_crc(ht, we->start_actual,
                              &pair_crc, &p0, &p1)
                          || pair_crc != req_pair
                          || p0 == r2c || p1 == r2c
                          || p0 == sap || p1 == sap
                          || _AB_IN_BV_PREFIX(p0)
                          || _AB_IN_BV_PREFIX(p1)) {
                        continue;
                      }
                      PNG_M3_TRY_SUFFIX_PLACEMENT(p0, p1, r2c,
                        "2+2-run");
                    }
                  }
                }
              }

              // Position 0 singleton + positions 1,2 contiguous + suffix
              // singleton.  This catches a 2-block displaced island inside
              // the IDAT fill window, with the blocks immediately before and
              // after the island still on the original contiguous run.
              if (!solved && pair_after2_inv_ok) {
                int ti_0 = M3_TAB(0);
                int64_t ab0 = (prefix_last_actual >= 0)
                    ? PNG_M3_AP_FROM_ACT(prefix_last_actual + 1
                          + (int64_t)first_full)
                    : -1;
                if (PNG_M3_AP_VALID(ab0)
                    && !_AB_IN_BV_PREFIX(ab0) && m3_htab[ti_0]) {
                  uint32_t target_pair = target_all
                      ^ PNG_M3_SHIFT_AP(ab0, 0);
                  uint32_t req_pair = png_crc_apply_inverse(
                      pair_after2_inv, target_pair);
                  if (pair_index) {
                    uint32_t bucket = req_pair % PNG_GAP_WINDOW_BUCKETS;
                    for (PNGGapWindowEntry *we = pair_index->buckets[bucket];
                         we && !solved; we = we->next) {
                      if (we->crc != req_pair) {
                        continue;
                      }
                      uint32_t pair_crc = 0;
                      int64_t p0 = -1, p1 = -1;
                      if (!png_crc_actual_pair_crc(ht, we->start_actual,
                              &pair_crc, &p0, &p1)
                          || pair_crc != req_pair
                          || p0 == ab0 || p1 == ab0
                          || p0 == sap || p1 == sap
                          || _AB_IN_BV_PREFIX(p0)
                          || _AB_IN_BV_PREFIX(p1)) {
                        continue;
                      }
                      PNG_M3_TRY_SUFFIX_PLACEMENT(ab0, p0, p1,
                          "1+2+1-run");
                    }
                  }
                  int64_t scan_start = sc->actual_block > 64
                      ? sc->actual_block - 64 : 0;
                  for (int64_t actual_start = scan_start;
                       actual_start < sc->actual_block && !solved;
                       actual_start++) {
                    uint32_t pair_crc = 0;
                    int64_t p0 = -1, p1 = -1;
                    if (!png_crc_actual_pair_crc(ht, actual_start,
                            &pair_crc, &p0, &p1)
                        || pair_crc != req_pair
                        || p0 == ab0 || p1 == ab0
                        || p0 == sap || p1 == sap
                        || _AB_IN_BV_PREFIX(p0)
                        || _AB_IN_BV_PREFIX(p1)) {
                      continue;
                    }
                    PNG_M3_TRY_SUFFIX_PLACEMENT(ab0, p0, p1,
                        "1+2+1-run-actual");
                  }
                }
              }
            }

            #undef PNG_M3_TRY_SUFFIX_PLACEMENT
            #undef PNG_M3_RESTORE_CONTIG
            #undef PNG_M3_SHIFT_AP
            #undef PNG_M3_AP_FROM_ACT
            #undef PNG_M3_AP_VALID
          }

          // ---- Split-run fast path: one singleton + one contiguous pair ----
          // The full corpus commonly fragments PNGs by moving a short run out
          // of the middle while leaving the immediately following run intact.
          // GAP only handles all M middle blocks being contiguous; generic
          // Phase C below is effectively O(N^2).  For M=3, try the two
          // order-preserving split shapes in O(N):
          //   positions (0,1) contiguous + position 2 singleton
          //   position 0 singleton + positions (1,2) contiguous
          if (!solved && m3_ab_crc && m3_ab_valid
              && (resume_phase == 0 || resume_phase == 4
                  || si > resume_si)) {
            uint32_t target_all = diff ^ shifted_contig[0]
                ^ shifted_contig[1] ^ shifted_contig[2];
            const uint8_t split_pairs[2][3] = {{0, 1, 2}, {1, 2, 0}};
            uint32_t split_pair_start = (si == resume_si
                && resume_phase == 4) ? (uint32_t)resume_pair : 0;
            for (uint32_t spi = split_pair_start;
                 spi < 2 && !solved; spi++) {
              uint32_t pa = split_pairs[spi][0];
              uint32_t pb = split_pairs[spi][1];
              uint32_t ps = split_pairs[spi][2];
              int ti_s = (int)M3_TAB(ps);
              if (!m3_htab[ti_s]) { continue; }
              int64_t start_init = (si == resume_si
                  && resume_phase == 4
                  && spi == split_pair_start
                  && resume_er1 > 0) ? resume_er1 : 0;
              for (int64_t start = start_init;
                   start + 1 < m3_total_ap && !solved; start++) {
                if ((start & 0xFFF) == 0
                    && png_reassembly_yield_requested(candidate)) {
                  local->solver_phase = 4;
                  local->solver_pair_idx = (uint8_t)spi;
                  local->solver_suffix_idx = si;
                  local->solver_right_idx = start;
                  local->solver_right_idx2 = 0;
                  local->solver_suffix_nb = suffix_start_nb;
                  resize_blockvector(candidate->b, suffix_start_nb);
                  free(m3_ab_crc);
                  free(m3_ab_valid);
                  return -1;
                }
                if (!m3_ab_valid[start] || !m3_ab_valid[start + 1]) {
                  continue;
                }
                if (_AB_IN_BV_PREFIX(start)
                    || _AB_IN_BV_PREFIX(start + 1)
                    || start == sc->apparent_block
                    || start + 1 == sc->apparent_block) {
                  continue;
                }
                int64_t actual_a = filemirror_actual_blocknumber(
                    scalpel_state.filemirror, start);
                int64_t actual_b = filemirror_actual_blocknumber(
                    scalpel_state.filemirror, start + 1);
                if (actual_a < 0 || actual_b < 0
                    || filemirror_actual_block_covered(
                        scalpel_state.filemirror, actual_a)
                    || filemirror_actual_block_covered(
                        scalpel_state.filemirror, actual_b)
                    || actual_a == sc->actual_block
                    || actual_b == sc->actual_block) {
                  continue;
                }

                uint32_t pair_shift = png_crc_apply_forward(
                    after_forward[pa], m3_ab_crc[start])
                    ^ png_crc_apply_forward(
                        after_forward[pb], m3_ab_crc[start + 1]);
                uint32_t needed_single = target_all ^ pair_shift;
                uint32_t bidx = needed_single % PNG_M3_BUCKETS;
                for (Er2Entry *me = m3_htab[ti_s][bidx];
                     me && !solved; me = me->next) {
                  if (me->shifted_crc != needed_single) { continue; }
                  if (me->actual_block == actual_a
                      || me->actual_block == actual_b
                      || me->actual_block == sc->actual_block) {
                    continue;
                  }
                  if (filemirror_actual_block_covered(
                          scalpel_state.filemirror, me->actual_block)) {
                    continue;
                  }
                  int64_t ab_s = filemirror_apparent_blocknumber(
                      scalpel_state.filemirror, me->actual_block);
                  if (ab_s < 0 || _AB_IN_BV_PREFIX(ab_s)
                      || ab_s == start || ab_s == start + 1
                      || ab_s == sc->apparent_block) {
                    continue;
                  }

                  blockvector_set_apparent_blocknumber(candidate->b,
                      suffix_start_nb + first_full + pa, start);
                  blockvector_set_apparent_blocknumber(candidate->b,
                      suffix_start_nb + first_full + pb, start + 1);
                  blockvector_set_apparent_blocknumber(candidate->b,
                      suffix_start_nb + first_full + ps, ab_s);
                  blockvector_set_apparent_blocknumber(candidate->b,
                      suffix_start_nb + suffix_fill_pos,
                      sc->apparent_block);
                  for (uint32_t f = 0; f < fill_needed; f++) {
                    inflate_blockvector_single_block(candidate->b,
                        suffix_start_nb + f);
                  }

                  const char *vds = blockvector_get_data_pointer(
                      candidate->b);
                  uint64_t vdls = blockvector_get_data_length(candidate->b);
                  if (vds && crc_field_pos + 4 <= vdls) {
                    uint32_t vcs = crc32(0, NULL, 0);
                    vcs = crc32(vcs,
                        (const unsigned char *)(vds + type_start),
                        (uInt)crc_region_len);
                    if (vcs == sc->stored_crc) {
                      bool sok = false;
                      uint64_t nxt = crc_field_pos + 8;
                      if (nxt + 4 <= vdls) {
                        const unsigned char *tp =
                            (const unsigned char *)(vds + nxt);
                        const unsigned char *lp =
                            (const unsigned char *)(
                                vds + crc_field_pos + 4);
                        uint32_t nl = ((uint32_t)lp[0] << 24)
                            | ((uint32_t)lp[1] << 16)
                            | ((uint32_t)lp[2] << 8) | (uint32_t)lp[3];
                        if (tp[0]=='I' && tp[1]=='D' && tp[2]=='A'
                            && tp[3]=='T'
                            && nl > 0 && nl <= PNG_MAX_IDAT_BODY_LEN) {
                          sok = true;
                        }
                        else if (tp[0]=='I' && tp[1]=='E'
                            && tp[2]=='N' && tp[3]=='D'
                            && nl == 0) {
                          sok = true;
                        }
                      }
                      if (sok && png_solver_confirm_match(candidate, local,
                              work, uuidp, uuidc, crc_pos, idat_sz)) {
                        if (scalpel_state.mode_verbose) {
                          lock_fprintf(stdout,
                              "%sPNG CRC SOLVER: M=3 split-run pair=(%u,%u) "
                              "single=%u blocks [%" PRId64 ",%" PRId64
                              ",%" PRId64 "] suffix %" PRId64 "%s\n",
                              GREEN, pa, pb, ps, start, start + 1,
                              ab_s, sc->apparent_block, BLACK);
                        }
                        solved = true;
                      }
                    }
                  }
                  if (!solved) {
                    for (uint32_t f = 0; f < fill_needed; f++) {
                      int64_t orig = last_block + 1 + (int64_t)f;
                      blockvector_set_apparent_blocknumber(candidate->b,
                          suffix_start_nb + f, orig);
                      inflate_blockvector_single_block(candidate->b,
                          suffix_start_nb + f);
                    }
                  }
                }
              }
            }
          }

          // ---- Phase A: single-block replacement, O(1) per position ----
          for (int fixed = 0; fixed < 3 && !solved; fixed++) {
            int ti = M3_TAB(fixed);
            if (!m3_htab[ti]) { continue; }
            uint32_t target_a = diff ^ shifted_contig[fixed];
            uint32_t bidx = target_a % PNG_M3_BUCKETS;
            for (Er2Entry *me = m3_htab[ti][bidx];
                 me && !solved; me = me->next) {
              if (me->shifted_crc != target_a) { continue; }
              if (filemirror_actual_block_covered(
                      scalpel_state.filemirror, me->actual_block)) {
                continue;
              }
              int64_t trial_ab = filemirror_apparent_blocknumber(
                  scalpel_state.filemirror, me->actual_block);
              if (trial_ab < 0) { continue; }
              /* Skip if the candidate block is already in BV prefix —
               * placing it would duplicate an existing entry and the
               * validator would reject. */
              if (_AB_IN_BV_PREFIX(trial_ab)) { continue; }
              if (_AB_IN_BV_PREFIX(sc->apparent_block)) { continue; }

              // Place middle block + suffix candidate, inflate, verify.
              uint32_t fpos_abs = first_full + fixed;
              blockvector_set_apparent_blocknumber(candidate->b,
                  suffix_start_nb + fpos_abs, trial_ab);
              blockvector_set_apparent_blocknumber(candidate->b,
                  suffix_start_nb + suffix_fill_pos, sc->apparent_block);
              for (uint32_t f = 0; f < fill_needed; f++) {
                inflate_blockvector_single_block(candidate->b,
                    suffix_start_nb + f);
              }
              const char *vd = blockvector_get_data_pointer(candidate->b);
              uint64_t vdl = blockvector_get_data_length(candidate->b);
              if (vd && crc_field_pos + 4 <= vdl) {
                uint32_t vcrc = crc32(0, NULL, 0);
                vcrc = crc32(vcrc,
                    (const unsigned char *)(vd + type_start),
                    (uInt)crc_region_len);
                const unsigned char *vep =
                    (const unsigned char *)(vd + crc_field_pos);
                uint32_t vstored = ((uint32_t)vep[0] << 24)
                    | ((uint32_t)vep[1] << 16)
                    | ((uint32_t)vep[2] << 8) | (uint32_t)vep[3];
                if (vcrc == vstored) {
                  bool _sok = false;
                  uint64_t _nxt = crc_field_pos + 8;
                  if (_nxt + 4 <= vdl) {
                    const unsigned char *_tp =
                        (const unsigned char *)(vd + _nxt);
                    const unsigned char *_lp =
                        (const unsigned char *)(vd + crc_field_pos + 4);
                    uint32_t _nl = ((uint32_t)_lp[0] << 24)
                        | ((uint32_t)_lp[1] << 16)
                        | ((uint32_t)_lp[2] << 8) | (uint32_t)_lp[3];
                    if (_tp[0]=='I' && _tp[1]=='D' && _tp[2]=='A'
                        && _tp[3]=='T'
                        && _nl <= PNG_MAX_IDAT_BODY_LEN) { _sok = true; }
                    else if (_tp[0]=='I' && _tp[1]=='E' && _tp[2]=='N'
                        && _tp[3]=='D' && _nl == 0) { _sok = true; }
                  }
                  if (_sok) {
                    uint64_t _cp = local->last_chunk_crc_pos;
                    bool _sv2; uint64_t _svt2;
                    _sv2 = png_direct_validate(work->id, candidate,
                        &_svt2, local, uuidp, uuidc);
                    if (_sv2 || local->last_chunk_crc_pos > _cp) {
                      if (scalpel_state.mode_verbose) {
                        lock_fprintf(stdout,
                            "%sPNG CRC SOLVER: M=3 alg (1-of-3) pos=%d "
                            "block %" PRId64 " suffix %" PRId64 "%s\n",
                            GREEN, fixed, trial_ab,
                            sc->apparent_block, BLACK);
                      }
                      solved = true;
                    }
                    else { local->last_chunk_crc_pos = _cp; }
                  }
                }
              }
              if (!solved) {
                // Restore all contiguous.
                for (uint32_t f = 0; f < fill_needed; f++) {
                  int64_t orig = last_block + 1 + (int64_t)f;
                  blockvector_set_apparent_blocknumber(candidate->b,
                      suffix_start_nb + f, orig);
                  inflate_blockvector_single_block(candidate->b,
                      suffix_start_nb + f);
                }
              }
            }
          }

          // ---- Phase B: two-block replacement, O(N) per pair ----
          if (!solved) {
            int pairs[3][3] = {{0,1,2}, {0,2,1}, {1,2,0}};
            uint32_t pi_start = (si == resume_si && resume_phase == 1)
                ? (uint32_t)resume_pair : 0;
            for (uint32_t pi = pi_start; pi < 3 && !solved; pi++) {
              int pa = pairs[pi][0], pb = pairs[pi][1];
              int ti_a = M3_TAB(pa), ti_b = M3_TAB(pb);
              if (!m3_htab[ti_a] || !m3_htab[ti_b]) { continue; }
              uint32_t target_pair = diff
                  ^ shifted_contig[pa] ^ shifted_contig[pb];
              uint32_t ei_start = (si == resume_si
                  && resume_phase == 1
                  && pi == pi_start
                  && resume_er1 > 0)
                  ? (uint32_t)resume_er1 : 0;

              // Iterate pre-computed pool instead of hash table +
              // redundant crc32_combine.  Pool already has shifted_crc.
              uint32_t ti_a_count = sctx->m3_count[ti_a];
              for (uint32_t ei = ei_start;
                   ei < ti_a_count && !solved; ei++) {
                if ((ei & 0xFF) == 0
                    && png_reassembly_yield_requested(candidate)) {
                  local->solver_phase = 1;
                  local->solver_pair_idx = (uint8_t)pi;
                  local->solver_suffix_idx = si;
                  local->solver_right_idx = ei;
                  local->solver_right_idx2 = 0;
                  local->solver_suffix_nb = suffix_start_nb;
                  // BV has contiguous fill — trim to clean state.
                  resize_blockvector(candidate->b, suffix_start_nb);
                  free(m3_ab_crc);
                  free(m3_ab_valid);
                  return -1;
                }
                Er2Entry *cea = &sctx->m3_pool[ti_a][ei];
                if (filemirror_actual_block_covered(
                        scalpel_state.filemirror, cea->actual_block)) {
                  continue;
                }
                {
                  int64_t _cea_ap = filemirror_apparent_blocknumber(
                      scalpel_state.filemirror, cea->actual_block);
                  if (_cea_ap < 0) { continue; }
                  if (_AB_IN_BV_PREFIX(_cea_ap)) { continue; }
                  if (_AB_IN_BV_PREFIX(sc->apparent_block)) { continue; }
                }
                  uint32_t shifted_a = cea->shifted_crc;
                  uint32_t needed_b = target_pair ^ shifted_a;
                  uint32_t bidx = needed_b % PNG_M3_BUCKETS;
                  for (Er2Entry *me = m3_htab[ti_b][bidx];
                       me && !solved; me = me->next) {
                    if (me->shifted_crc != needed_b) { continue; }
                    if (me->actual_block == cea->actual_block) { continue; }
                    if (filemirror_actual_block_covered(
                            scalpel_state.filemirror, me->actual_block)) {
                      continue;
                    }
                    int64_t ab_a = filemirror_apparent_blocknumber(
                        scalpel_state.filemirror, cea->actual_block);
                    int64_t ab_b = filemirror_apparent_blocknumber(
                        scalpel_state.filemirror, me->actual_block);
                    if (ab_a < 0 || ab_b < 0) { continue; }
                    if (_AB_IN_BV_PREFIX(ab_b)) { continue; }

                    // Place middle blocks + suffix, inflate, verify.
                    uint32_t fa = first_full + pa;
                    uint32_t fb = first_full + pb;
                    blockvector_set_apparent_blocknumber(candidate->b,
                        suffix_start_nb + fa, ab_a);
                    blockvector_set_apparent_blocknumber(candidate->b,
                        suffix_start_nb + fb, ab_b);
                    blockvector_set_apparent_blocknumber(candidate->b,
                        suffix_start_nb + suffix_fill_pos,
                        sc->apparent_block);
                    for (uint32_t f = 0; f < fill_needed; f++) {
                      inflate_blockvector_single_block(candidate->b,
                          suffix_start_nb + f);
                    }
                    const char *vd2 = blockvector_get_data_pointer(
                        candidate->b);
                    uint64_t vdl2 = blockvector_get_data_length(
                        candidate->b);
                    if (vd2 && crc_field_pos + 4 <= vdl2) {
                      uint32_t vc2 = crc32(0, NULL, 0);
                      vc2 = crc32(vc2,
                          (const unsigned char *)(vd2 + type_start),
                          (uInt)crc_region_len);
                      if (vc2 == sc->stored_crc) {
                        bool _sok = false;
                        uint64_t _nxt = crc_field_pos + 8;
                        if (_nxt + 4 <= vdl2) {
                          const unsigned char *_tp =
                              (const unsigned char *)(vd2 + _nxt);
                          const unsigned char *_lp =
                              (const unsigned char *)(
                                  vd2 + crc_field_pos + 4);
                          uint32_t _nl = ((uint32_t)_lp[0] << 24)
                              | ((uint32_t)_lp[1] << 16)
                              | ((uint32_t)_lp[2] << 8) | (uint32_t)_lp[3];
                          if (_tp[0]=='I' && _tp[1]=='D'
                              && _tp[2]=='A' && _tp[3]=='T'
                              && _nl <= PNG_MAX_IDAT_BODY_LEN) { _sok = true; }
                          else if (_tp[0]=='I' && _tp[1]=='E'
                              && _tp[2]=='N' && _tp[3]=='D'
                              && _nl == 0) { _sok = true; }
                        }
                        if (_sok) {
                          uint64_t _cp = local->last_chunk_crc_pos;
                          bool _sv; uint64_t _svt;
                          _sv = png_direct_validate(work->id, candidate,
                              &_svt, local, uuidp, uuidc);
                          if (_sv || local->last_chunk_crc_pos > _cp) {
                            if (scalpel_state.mode_verbose) {
                              lock_fprintf(stdout,
                                  "%sPNG CRC SOLVER: M=3 alg (2-of-3) "
                                  "pair=(%d,%d) blocks "
                                  "[%" PRId64 ",%" PRId64 "] suffix %"
                                  PRId64 "%s\n",
                                  GREEN, pa, pb, ab_a, ab_b,
                                  sc->apparent_block, BLACK);
                            }
                            solved = true;
                          }
                          else { local->last_chunk_crc_pos = _cp; }
                        }
                      }
                    }
                    if (!solved) {
                      // Restore all contiguous.
                      for (uint32_t f = 0; f < fill_needed; f++) {
                        int64_t orig = last_block + 1 + (int64_t)f;
                        blockvector_set_apparent_blocknumber(candidate->b,
                            suffix_start_nb + f, orig);
                        inflate_blockvector_single_block(candidate->b,
                            suffix_start_nb + f);
                      }
                    }
                  }
                }

              // Yield check per pair.
              if (!solved && png_reassembly_yield_requested(candidate)) {
                local->solver_phase = 1;
                local->solver_pair_idx = (uint8_t)pi;
                local->solver_suffix_idx = si;
                local->solver_right_idx = 0;
                local->solver_right_idx2 = 0;
                local->solver_suffix_nb = suffix_start_nb;
                // Tables persist in sctx — do NOT free.
                resize_blockvector(candidate->b, suffix_start_nb);
                free(m3_ab_crc);
                free(m3_ab_valid);
                return -1;
              }
            }
          }

          // ---- Phase C: three-block replacement, O(N^2) ----
          // When all 3 middle blocks are wrong (Phase A and B failed),
          // iterate blocks at position 0, and for each, solve the
          // remaining pair (positions 1,2) as an M=2 MitM problem
          // using the existing m3_htab tables.
          if (!solved) {
            // For each candidate at position 0 (first_full):
            uint32_t ei_start = (si == resume_si
                && resume_phase == 2
                && resume_er1 > 0)
                ? (uint32_t)resume_er1 : 0;
            uint32_t ti_0 = M3_TAB(0);
            int ti_1 = M3_TAB(1), ti_2 = M3_TAB(2);
            uint32_t ti_0_count = sctx->m3_count[ti_0];
            uint32_t ti_1_count = sctx->m3_count[ti_1];
            uint64_t phase_c_pairs =
                (uint64_t)ti_0_count * (uint64_t)ti_1_count;
            bool phase_c_feasible = sctx->m3_pool[ti_0]
                && m3_htab[ti_1] && m3_htab[ti_2]
                && phase_c_pairs <= PNG_M3_PHASE_C_PAIR_CAP;
            if (!phase_c_feasible) {
              if (scalpel_state.mode_verbose
                  && phase_c_pairs > PNG_M3_PHASE_C_PAIR_CAP) {
                lock_fprintf(stdout,
                    "PNG SOLVER: M=3 skipped Phase C all-block search "
                    "(pairs=%" PRIu64 " > %" PRIu64 ")\n",
                    phase_c_pairs, (uint64_t)PNG_M3_PHASE_C_PAIR_CAP);
              }
            }
            for (uint32_t ei = phase_c_feasible ? ei_start : ti_0_count;
                 ei < ti_0_count && !solved; ei++) {

              // Yield check every 16 iterations for responsiveness.
              if (!solved && (ei & 0xF) == 0
                  && png_reassembly_yield_requested(candidate)) {
                local->solver_phase = 2;
                local->solver_pair_idx = 0;
                local->solver_suffix_idx = si;
                local->solver_right_idx = ei;
                local->solver_right_idx2 = 0;
                local->solver_suffix_nb = suffix_start_nb;
                resize_blockvector(candidate->b, suffix_start_nb);
                free(m3_ab_crc);
                free(m3_ab_valid);
                return -1;
              }

              Er2Entry *c0 = &sctx->m3_pool[ti_0][ei];
              if (filemirror_actual_block_covered(
                      scalpel_state.filemirror, c0->actual_block)) {
                continue;
              }
              // With candidate c0 at position 0:
              // need: shift(c0, after[0]) ^ shift(c1, after[1]) ^ shift(c2, after[2])
              //     = diff ^ shifted_contig[0] ^ shifted_contig[1] ^ shifted_contig[2]
              //     = TARGET_ALL
              // So: shift(c1, after[1]) ^ shift(c2, after[2])
              //     = TARGET_ALL ^ shift(c0, after[0])
              //     = target_pair_12
              uint32_t target_all = diff ^ shifted_contig[0]
                  ^ shifted_contig[1] ^ shifted_contig[2];
              uint32_t target_pair_12 = target_all ^ c0->shifted_crc;

              // M=2 lookup: iterate table for position 1, look up position 2.
              uint32_t e1_start = (si == resume_si
                  && resume_phase == 2
                  && ei == ei_start
                  && resume_er2 > 0)
                  ? (uint32_t)resume_er2 : 0;
              for (uint32_t e1 = e1_start;
                   e1 < ti_1_count && !solved; e1++) {
                if ((e1 & 0xFF) == 0
                    && png_reassembly_yield_requested(candidate)) {
                  local->solver_phase = 2;
                  local->solver_pair_idx = 0;
                  local->solver_suffix_idx = si;
                  local->solver_right_idx = ei;
                  local->solver_right_idx2 = e1;
                  local->solver_suffix_nb = suffix_start_nb;
                  resize_blockvector(candidate->b, suffix_start_nb);
                  free(m3_ab_crc);
                  free(m3_ab_valid);
                  return -1;
                }
                Er2Entry *c1 = &sctx->m3_pool[ti_1][e1];
                if (c1->actual_block == c0->actual_block) { continue; }
                if (filemirror_actual_block_covered(
                        scalpel_state.filemirror, c1->actual_block)) {
                  continue;
                }
                uint32_t needed_2 = target_pair_12 ^ c1->shifted_crc;
                uint32_t bidx = needed_2 % PNG_M3_BUCKETS;
                for (Er2Entry *c2 = m3_htab[ti_2][bidx];
                     c2 && !solved; c2 = c2->next) {
                  if (c2->shifted_crc != needed_2) { continue; }
                  if (c2->actual_block == c0->actual_block
                      || c2->actual_block == c1->actual_block) { continue; }
                  if (filemirror_actual_block_covered(
                          scalpel_state.filemirror, c2->actual_block)) {
                    continue;
                  }
                  // Triple match. Place all 3 + suffix, inflate, verify.
                  int64_t ab0 = filemirror_apparent_blocknumber(
                      scalpel_state.filemirror, c0->actual_block);
                  int64_t ab1 = filemirror_apparent_blocknumber(
                      scalpel_state.filemirror, c1->actual_block);
                  int64_t ab2 = filemirror_apparent_blocknumber(
                      scalpel_state.filemirror, c2->actual_block);
                  if (ab0 < 0 || ab1 < 0 || ab2 < 0) { continue; }

                  blockvector_set_apparent_blocknumber(candidate->b,
                      suffix_start_nb + first_full + 0, ab0);
                  blockvector_set_apparent_blocknumber(candidate->b,
                      suffix_start_nb + first_full + 1, ab1);
                  blockvector_set_apparent_blocknumber(candidate->b,
                      suffix_start_nb + first_full + 2, ab2);
                  blockvector_set_apparent_blocknumber(candidate->b,
                      suffix_start_nb + suffix_fill_pos,
                      sc->apparent_block);
                  for (uint32_t f = 0; f < fill_needed; f++) {
                    inflate_blockvector_single_block(candidate->b,
                        suffix_start_nb + f);
                  }
                  const char *vd3 = blockvector_get_data_pointer(
                      candidate->b);
                  uint64_t vdl3 = blockvector_get_data_length(
                      candidate->b);
                  if (vd3 && crc_field_pos + 4 <= vdl3) {
                    uint32_t vc3 = crc32(0, NULL, 0);
                    vc3 = crc32(vc3,
                        (const unsigned char *)(vd3 + type_start),
                        (uInt)crc_region_len);
                    if (vc3 == sc->stored_crc) {
                      bool _sok = false;
                      uint64_t _nxt = crc_field_pos + 8;
                      if (_nxt + 4 <= vdl3) {
                        const unsigned char *_tp =
                            (const unsigned char *)(vd3 + _nxt);
                        const unsigned char *_lp =
                            (const unsigned char *)(
                                vd3 + crc_field_pos + 4);
                        uint32_t _nl = ((uint32_t)_lp[0] << 24)
                            | ((uint32_t)_lp[1] << 16)
                            | ((uint32_t)_lp[2] << 8) | (uint32_t)_lp[3];
                        if (_tp[0]=='I' && _tp[1]=='D'
                            && _tp[2]=='A' && _tp[3]=='T'
                            && _nl > 0 && _nl <= PNG_MAX_IDAT_BODY_LEN) {
                          _sok = true;
                        }
                        else if (_tp[0]=='I' && _tp[1]=='E'
                            && _tp[2]=='N' && _tp[3]=='D'
                            && _nl == 0) { _sok = true; }
                      }
                      if (_sok) {
                        uint64_t _cp = local->last_chunk_crc_pos;
                        bool _sv; uint64_t _svt;
                        _sv = png_direct_validate(work->id, candidate,
                            &_svt, local, uuidp, uuidc);
                        if (_sv || local->last_chunk_crc_pos > _cp) {
                          if (scalpel_state.mode_verbose) {
                            lock_fprintf(stdout,
                                "%sPNG CRC SOLVER: M=3 alg (3-of-3) "
                                "blocks [%" PRId64 ",%" PRId64
                                ",%" PRId64 "] suffix %" PRId64 "%s\n",
                                GREEN, ab0, ab1, ab2,
                                sc->apparent_block, BLACK);
                          }
                          solved = true;
                        }
                        else { local->last_chunk_crc_pos = _cp; }
                      }
                    }
                  }
                  if (!solved) {
                    for (uint32_t f = 0; f < fill_needed; f++) {
                      int64_t orig = last_block + 1 + (int64_t)f;
                      blockvector_set_apparent_blocknumber(candidate->b,
                          suffix_start_nb + f, orig);
                      inflate_blockvector_single_block(candidate->b,
                          suffix_start_nb + f);
                    }
                  }
                }
              }
            }
          }
        } // end suffix candidate loop (M=3)

        free(m3_ab_crc);
        free(m3_ab_valid);
        png_solver_resume_reset(local);

        // Tables persist in sctx — freed by png_solver_ctx_free.
        #undef M3_TAB
      }

      if (!solved) {
        // Restore all contiguous blocks.
        for (uint32_t f = 0; f < fill_needed; f++) {
          int64_t orig = last_block + 1 + (int64_t)f;
          blockvector_set_apparent_blocknumber(candidate->b,
              suffix_start_nb + f, orig);
          inflate_blockvector_single_block(candidate->b, suffix_start_nb + f);
        }
      }
    } // end M=3 solver

    // Tables persist in solver_ctx — do NOT free here.
  } // end left_count == 1
  /* OLD M=3 O(N²) code removed — replaced with O(N) decomposition above. */
  else if (left_count == 2) {
    // M=4: complete 2+2 meet-in-the-middle search.  Earlier structured
    // solvers handle large candidate universes; this exact fallback runs
    // only when every ordered left pair fits inside the per-worker budget.
    typedef struct PNGM4PairEntry {
      uint32_t crc;
      uint32_t first;
      uint32_t second;
      uint32_t next;
    } PNGM4PairEntry;

    PNGCrcEntry **flat = NULL;
    uint32_t *shifted = NULL;
    PNGM4PairEntry *pair_pool = NULL;
    uint32_t *pair_buckets = NULL;
    uint32_t fi = 0;
    uint32_t pair_bucket_count = 0;
    uint64_t pair_count = 0;
    bool m4_yielded = false;

    uint64_t viable_count = 0;
    for (uint32_t b = 0; b < PNG_CRC_HASH_BUCKETS; b++) {
      for (PNGCrcEntry *e = ht->buckets[b]; e; e = e->next) {
        if (filemirror_actual_block_covered(scalpel_state.filemirror,
                                            e->actual_block)) {
          continue;
        }
        int64_t apparent = filemirror_apparent_blocknumber(
            scalpel_state.filemirror, e->actual_block);
        if (apparent < 0 || _AB_IN_BV_PREFIX(apparent)) {
          continue;
        }
        viable_count++;
      }
    }

    if (viable_count < 4 || viable_count > UINT32_MAX) {
      goto m4_done;
    }
    pair_count = viable_count * (viable_count - 1);
    if (pair_count > PNG_M4_PAIR_MEMORY_LIMIT / sizeof(PNGM4PairEntry)) {
      if (scalpel_state.mode_verbose || png_trace_this) {
        lock_fprintf(stdout,
            "PNG SOLVER: M=4 exact search skipped: %" PRIu64
            " viable blocks require %" PRIu64
            " pair bytes (budget=%" PRIu64 ")\n",
            viable_count,
            pair_count * (uint64_t)sizeof(PNGM4PairEntry),
            (uint64_t)PNG_M4_PAIR_MEMORY_LIMIT);
      }
      goto m4_done;
    }

    flat = (PNGCrcEntry **)malloc(
        (size_t)viable_count * sizeof(PNGCrcEntry *));
    if (!flat) {
      goto m4_done;
    }
    for (uint32_t b = 0; b < PNG_CRC_HASH_BUCKETS; b++) {
      for (PNGCrcEntry *e = ht->buckets[b]; e; e = e->next) {
        if (filemirror_actual_block_covered(scalpel_state.filemirror,
                                            e->actual_block)) {
          continue;
        }
        int64_t apparent = filemirror_apparent_blocknumber(
            scalpel_state.filemirror, e->actual_block);
        if (apparent < 0 || _AB_IN_BV_PREFIX(apparent)) {
          continue;
        }
        if (fi < viable_count) {
          flat[fi++] = e;
        }
      }
    }
    if (fi < 4) {
      goto m4_done;
    }

    // Resume indices are meaningful only while the ordered viable-block and
    // suffix-candidate universes are unchanged.  Coverage can change across a
    // progress checkpoint, so fingerprint both lists and the IDAT geometry.
    XXH3_state_t m4_hash_state;
    if (XXH3_64bits_reset(&m4_hash_state) != XXH_OK
        || XXH3_64bits_update(&m4_hash_state, &suffix_start_nb,
                              sizeof(suffix_start_nb)) != XXH_OK
        || XXH3_64bits_update(&m4_hash_state, &crc_pos,
                              sizeof(crc_pos)) != XXH_OK
        || XXH3_64bits_update(&m4_hash_state, &idat_sz,
                              sizeof(idat_sz)) != XXH_OK
        || XXH3_64bits_update(&m4_hash_state, &fill_needed,
                              sizeof(fill_needed)) != XXH_OK
        || XXH3_64bits_update(&m4_hash_state, &first_full,
                              sizeof(first_full)) != XXH_OK
        || XXH3_64bits_update(&m4_hash_state, &suffix_fill_pos,
                              sizeof(suffix_fill_pos)) != XXH_OK
        || XXH3_64bits_update(&m4_hash_state, &fi, sizeof(fi)) != XXH_OK) {
      goto m4_done;
    }
    for (uint32_t i = 0; i < fi; i++) {
      int64_t actual = flat[i]->actual_block;
      if (XXH3_64bits_update(&m4_hash_state, &actual, sizeof(actual))
          != XXH_OK) {
        goto m4_done;
      }
    }
    if (XXH3_64bits_update(&m4_hash_state, &suffix_cand_count,
                           sizeof(suffix_cand_count)) != XXH_OK) {
      goto m4_done;
    }
    for (int64_t i = 0; i < suffix_cand_count; i++) {
      int64_t actual = suffix_cands[i].actual_block;
      if (XXH3_64bits_update(&m4_hash_state, &actual, sizeof(actual))
          != XXH_OK) {
        goto m4_done;
      }
    }
    uint64_t m4_universe_hash = XXH3_64bits_digest(&m4_hash_state);
    if (m4_universe_hash == 0) {
      m4_universe_hash = UINT64_MAX;
    }
    if (resume_phase == 3
        && local->solver_m4_universe_hash != m4_universe_hash) {
      if (scalpel_state.mode_verbose || png_trace_this) {
        lock_fprintf(stdout,
            "PNG SOLVER: M=4 viable universe changed; restarting scan\n");
      }
      resume_si = 0;
      resume_er1 = 0;
      resume_er2 = 0;
      resume_phase = 0;
      local->solver_suffix_idx = 0;
      local->solver_right_idx = 0;
      local->solver_right_idx2 = 0;
      local->solver_phase = 0;
      local->solver_m4_universe_hash = 0;
    }

    pair_count = (uint64_t)fi * (uint64_t)(fi - 1);
    pair_bucket_count = 1024;
    while ((uint64_t)pair_bucket_count < (pair_count + 1) / 2) {
      pair_bucket_count <<= 1;
    }
    uint64_t m4_bytes = pair_count * sizeof(PNGM4PairEntry)
        + (uint64_t)pair_bucket_count * sizeof(uint32_t)
        + (uint64_t)fi * (sizeof(PNGCrcEntry *) + sizeof(uint32_t));
    if (m4_bytes > PNG_M4_PAIR_MEMORY_LIMIT) {
      if (scalpel_state.mode_verbose || png_trace_this) {
        lock_fprintf(stdout,
            "PNG SOLVER: M=4 exact search skipped: %u viable blocks"
            " require %" PRIu64 " bytes (budget=%" PRIu64 ")\n",
            fi, m4_bytes, (uint64_t)PNG_M4_PAIR_MEMORY_LIMIT);
      }
      goto m4_done;
    }

    shifted = (uint32_t *)malloc((size_t)fi * sizeof(uint32_t));
    pair_pool = (PNGM4PairEntry *)malloc(
        (size_t)pair_count * sizeof(PNGM4PairEntry));
    pair_buckets = (uint32_t *)malloc(
        (size_t)pair_bucket_count * sizeof(uint32_t));
    if (!shifted || !pair_pool || !pair_buckets) {
      goto m4_done;
    }
    memset(pair_buckets, 0xff,
           (size_t)pair_bucket_count * sizeof(uint32_t));

    uint32_t block_forward[32];
    uint32_t prefix_forward[32];
    uint32_t suffix_forward[32];
    png_crc_forward_for_len((z_off_t)bs, block_forward);
    png_crc_forward_for_len((z_off_t)bs * 2, prefix_forward);
    png_crc_forward_for_len((z_off_t)suffix_partial_len,
                            suffix_forward);
    uint32_t shifted_prefix = png_crc_apply_forward(prefix_forward,
                                                     crc_prefix);
    for (uint32_t i = 0; i < fi; i++) {
      shifted[i] = png_crc_apply_forward(block_forward, flat[i]->crc);
    }

    uint64_t pidx = 0;
    for (uint32_t i = 0; i < fi && !m4_yielded; i++) {
      for (uint32_t j = 0; j < fi; j++) {
        if (i == j) {
          continue;
        }
        if ((pidx & 0xFFFFULL) == 0ULL
            && png_reassembly_yield_requested(candidate)) {
          local->solver_phase = 3;
          local->solver_suffix_idx = 0;
          local->solver_right_idx = 0;
          local->solver_right_idx2 = 0;
          local->solver_suffix_nb = suffix_start_nb;
          local->solver_m4_universe_hash = m4_universe_hash;
          m4_yielded = true;
          break;
        }
        uint32_t left_crc = shifted_prefix ^ shifted[i] ^ flat[j]->crc;
        uint32_t bucket = left_crc & (pair_bucket_count - 1);
        PNGM4PairEntry *entry = &pair_pool[pidx];
        entry->crc = left_crc;
        entry->first = i;
        entry->second = j;
        entry->next = pair_buckets[bucket];
        pair_buckets[bucket] = (uint32_t)pidx;
        pidx++;
      }
    }
    if (m4_yielded) {
      goto m4_done;
    }

    int64_t si_start = resume_phase == 3 ? resume_si : 0;
    uint64_t m4_poll_count = 0;
    for (int64_t si = si_start; si < suffix_cand_count && !solved; si++) {
      PNGSuffixCand *sc = &suffix_cands[si];
      if (!sc->valid || sc->apparent_block < 0
          || _AB_IN_BV_PREFIX(sc->apparent_block)
          || filemirror_actual_block_covered(scalpel_state.filemirror,
                                             sc->actual_block)) {
        continue;
      }

      uint32_t r0_start = (resume_phase == 3 && si == si_start
                           && resume_er1 >= 0)
          ? (uint32_t)resume_er1 : 0;
      for (uint32_t r0 = r0_start; r0 < fi && !solved; r0++) {
        uint32_t r1_start = (resume_phase == 3 && si == si_start
                             && r0 == r0_start && resume_er2 >= 0)
            ? (uint32_t)resume_er2 : 0;
        for (uint32_t r1 = r1_start; r1 < fi && !solved; r1++) {
          if (r0 == r1
              || flat[r0]->actual_block == sc->actual_block
              || flat[r1]->actual_block == sc->actual_block) {
            continue;
          }
          if ((m4_poll_count++ & 0xFFULL) == 0ULL
              && png_reassembly_yield_requested(candidate)) {
            local->solver_phase = 3;
            local->solver_suffix_idx = si;
            local->solver_right_idx = r0;
            local->solver_right_idx2 = r1;
            local->solver_suffix_nb = suffix_start_nb;
            local->solver_m4_universe_hash = m4_universe_hash;
            m4_yielded = true;
            break;
          }

          uint32_t right_pair_crc = shifted[r0] ^ flat[r1]->crc;
          uint32_t right_crc = png_crc_apply_forward(suffix_forward,
              right_pair_crc) ^ sc->partial_crc;
          uint32_t required_left = png_crc_apply_inverse(Minv,
              sc->stored_crc ^ right_crc);
          uint32_t entry_index = pair_buckets[
              required_left & (pair_bucket_count - 1)];

          while (entry_index != UINT32_MAX && !solved) {
            PNGM4PairEntry *entry = &pair_pool[entry_index];
            if (entry->crc == required_left) {
              PNGCrcEntry *left0 = flat[entry->first];
              PNGCrcEntry *left1 = flat[entry->second];
              if (left0->actual_block != flat[r0]->actual_block
                  && left0->actual_block != flat[r1]->actual_block
                  && left1->actual_block != flat[r0]->actual_block
                  && left1->actual_block != flat[r1]->actual_block
                  && left0->actual_block != sc->actual_block
                  && left1->actual_block != sc->actual_block) {
                int64_t ab0 = filemirror_apparent_blocknumber(
                    scalpel_state.filemirror, left0->actual_block);
                int64_t ab1 = filemirror_apparent_blocknumber(
                    scalpel_state.filemirror, left1->actual_block);
                int64_t ab2 = filemirror_apparent_blocknumber(
                    scalpel_state.filemirror, flat[r0]->actual_block);
                int64_t ab3 = filemirror_apparent_blocknumber(
                    scalpel_state.filemirror, flat[r1]->actual_block);
                if (ab0 >= 0 && ab1 >= 0 && ab2 >= 0 && ab3 >= 0) {
                  PNGSolverStateSnapshot pre_snap;
                  png_solver_snapshot(&pre_snap, local);
                  png_solver_resize_trial(candidate,
                                          suffix_start_nb + fill_needed);
                  blockvector_set_apparent_blocknumber(candidate->b,
                      suffix_start_nb + first_full, ab0);
                  blockvector_set_apparent_blocknumber(candidate->b,
                      suffix_start_nb + first_full + 1, ab1);
                  blockvector_set_apparent_blocknumber(candidate->b,
                      suffix_start_nb + first_full + 2, ab2);
                  blockvector_set_apparent_blocknumber(candidate->b,
                      suffix_start_nb + first_full + 3, ab3);
                  blockvector_set_apparent_blocknumber(candidate->b,
                      suffix_start_nb + suffix_fill_pos,
                      sc->apparent_block);
                  for (uint32_t f = 0; f < fill_needed; f++) {
                    inflate_blockvector_single_block(candidate->b,
                                                     suffix_start_nb + f);
                  }

                  const char *trial_data =
                      blockvector_get_data_pointer(candidate->b);
                  uint64_t trial_length =
                      blockvector_get_data_length(candidate->b);
                  bool crc_matches = false;
                  if (trial_data && type_start + crc_region_len
                      <= trial_length) {
                    uint32_t trial_crc = crc32(0, NULL, 0);
                    trial_crc = crc32(trial_crc,
                        (const unsigned char *)(trial_data + type_start),
                        (uInt)crc_region_len);
                    crc_matches = trial_crc == sc->stored_crc;
                  }
                  if (crc_matches
                      && png_solver_crc_marker_matches(candidate,
                          type_start, crc_region_len, crc_field_pos,
                          sc->stored_crc)
                      && png_solver_confirm_match(candidate, local, work,
                          uuidp, uuidc, crc_pos, idat_sz)) {
                    solved = true;
                    if (scalpel_state.mode_verbose || png_trace_this) {
                      lock_fprintf(stdout,
                          "PNG CRC SOLVER: M=4 selected blocks ["
                          "%" PRId64 ",%" PRId64 ",%" PRId64
                          ",%" PRId64 "] suffix %" PRId64 "\n",
                          ab0, ab1, ab2, ab3, sc->apparent_block);
                    }
                  }
                  if (!solved) {
                    png_solver_restore(local, &pre_snap);
                    for (uint32_t f = 0; f < fill_needed; f++) {
                      int64_t original = last_block + 1 + (int64_t)f;
                      blockvector_set_apparent_blocknumber(candidate->b,
                          suffix_start_nb + f, original);
                      inflate_blockvector_single_block(candidate->b,
                                                       suffix_start_nb + f);
                    }
                  }
                }
              }
            }
            entry_index = entry->next;
          }
        }
        if (m4_yielded) {
          break;
        }
      }
      resume_phase = 0;
    }

m4_done:
    free(pair_buckets);
    free(pair_pool);
    free(shifted);
    free(flat);
    if (m4_yielded) {
      resize_blockvector(candidate->b, suffix_start_nb);
      return -1;
    }

    png_solver_resume_reset(local);
    if (!solved) {
      for (uint32_t f = 0; f < fill_needed; f++) {
        int64_t original = last_block + 1 + (int64_t)f;
        blockvector_set_apparent_blocknumber(candidate->b,
            suffix_start_nb + f, original);
        inflate_blockvector_single_block(candidate->b,
                                         suffix_start_nb + f);
      }
    }
  }
  else if (left_count > 2) {
    // M>=5: not yet implemented — would require O(N^3) or higher.
    if (scalpel_state.mode_verbose) {
      lock_fprintf(stdout,
          "PNG SOLVER: M=%u (left_count=%u) — skipping (too complex)\n",
          M, left_count);
    }
  }

  free(suffix_cands);

  if (solved) {
    return 2;
  }

  resize_blockvector(candidate->b, suffix_start_nb);
  return 0;
}

// Initialize (or re-initialize after checkpoint) a PNG reassembly candidate.
// Handles covered blocks that appeared during checkpoint: truncates BV at
// first hole and resets stale CRC carve state.  Mirrors the role of
// LR_reassembly_init_candidate() — see reassembly.c:95-101 comments.
//
// CRC-tracking state in PNGCarveState is preserved from file validation
// when no holes are found.  File validation ran on the full contiguous BV
// (which may contain wrong blocks past the fragmentation point), but CRC-32
// catches wrong blocks: last_chunk_crc_pos / last_idat_crc_pos reflect the
// last CRC verified from the CORRECT prefix.  Resetting without cause would
// destroy D4 checkpoint CRC data and force re-discovery from scratch.
//
// When a hole IS found (covered block reclaimed at checkpoint), the CRC
// chain is broken at that point.  The one-way CRC propagation gate in
// png_file_validate (only propagates increases) prevents the validator from
// correcting stale (too-high) positions.  We must reset here.
static inline void png_reassembly_init_candidate(CarveInfo *candidate,
                                                  PNGCarveState *local) {

  candidate->chopped = false;
  inflate_blockvector(candidate->b);

  // Scan BV for holes from covered blocks reclaimed at checkpoint.
  // After inflate_blockvector → normalize_blockvector, blocks whose
  // apparent-to-actual mapping became invalid (covered block) have
  // actual_blocknumber set to -1 and valid set to false — but the
  // apparent number is preserved (still non-negative).  Check both
  // apparent AND actual to catch all invalidated blocks.
  // PNG wants LR-style truncation: CRC chain breaks at the hole, so
  // nothing past it is trustworthy.
  uint64_t nb = blockvector_get_num_blocks(candidate->b);
  for (uint64_t hi = 0; hi < nb; hi++) {  // Start at 0: corrupt block 0 causes Cat5
    int64_t ab = blockvector_get_apparent_blocknumber(candidate->b, hi);
    int64_t act = blockvector_get_actual_blocknumber(candidate->b, hi);
    if (ab < 0 || act < 0) {
      if (scalpel_state.mode_verbose) {
        lock_fprintf(stdout,
            "PNG init_candidate: hole at index %" PRIu64
            " (ab=%" PRId64 "), trimming BV from %" PRIu64
            " to %" PRIu64 "\n",
            hi, ab, nb, hi);
      }
      resize_blockvector(candidate->b, hi);
      inflate_blockvector(candidate->b);

      // Cap CRC carve state to the LAST VERIFIED IDAT CRC boundary
      // that still fits in the trimmed BV.  Wiping to zero (previous
      // behavior) was the root cause of the 131→132-file livelock; the
      // solver would lose all verified progress on every
      // checkpoint-induced hole, restart scans from zero, yield on
      // reassembly_time_to_checkpoint, re-enter, wipe again.
      //
      // Capping to trimmed_dl directly is wrong: trimmed_dl is a block
      // boundary, almost certainly mid-IDAT.  The solver treats lcp as
      // "the next chunk header starts here" and would read garbage.
      //
      // The right cap target is the largest known IDAT CRC boundary
      // that is <= trimmed_dl.  That position IS a chunk boundary and
      // the validator confirmed it CRC-correct.  Sources: the ring
      // entries and last/prev_idat_crc_pos.  If nothing in state is
      // usable (all positions are past the trim), fall back to wipe:
      // the chunk walk below will re-derive from the PNG signature.
      {
        uint64_t trimmed_dl = blockvector_get_data_length(candidate->b);
        if (local->last_chunk_crc_pos > trimmed_dl) {
          uint64_t cap_target = 0;
          if (local->last_idat_crc_pos <= trimmed_dl
              && local->last_idat_crc_pos > cap_target) {
            cap_target = local->last_idat_crc_pos;
          }
          if (local->prev_idat_crc_pos <= trimmed_dl
              && local->prev_idat_crc_pos > cap_target) {
            cap_target = local->prev_idat_crc_pos;
          }
          for (int _ri = 0; _ri < IDAT_CRC_RING_SZ; _ri++) {
            uint64_t r = local->idat_crc_ring[_ri];
            if (r <= trimmed_dl && r > cap_target) {
              cap_target = r;
            }
          }
          if (cap_target > 0) {
            // Cap to a known CRC boundary.  Preserve the verified prefix.
            local->last_chunk_crc_pos = cap_target;
            if (local->last_idat_crc_pos > cap_target) {
              local->last_idat_crc_pos = cap_target;
            }
            if (local->prev_idat_crc_pos > cap_target) {
              local->prev_idat_crc_pos = cap_target;
            }
            for (int _ri = 0; _ri < IDAT_CRC_RING_SZ; _ri++) {
              if (local->idat_crc_ring[_ri] > cap_target) {
                local->idat_crc_ring[_ri] = 0;
              }
            }
            // Next IDAT's size is unknown past the cap; let validator
            // re-read the length prefix.
            local->idat_data_sz = 0;
            local->valid = false;
            png_solver_resume_reset(local);
            if (scalpel_state.mode_verbose) {
              lock_fprintf(stdout,
                  "PNG init_candidate: hole-trim capped to CRC "
                  "boundary %" PRIu64 " (trimmed_dl=%" PRIu64 ")\n",
                  cap_target, trimmed_dl);
            }
          } else {
            // No verified CRC boundary survives the trim.  Full wipe.
            if (scalpel_state.mode_verbose) {
              lock_fprintf(stdout,
                  "PNG init_candidate: hole-trim no valid CRC boundary "
                  "<= %" PRIu64 ", wiping\n", trimmed_dl);
            }
            local->last_chunk_crc_pos = 0;
            local->last_idat_crc_pos = 0;
            local->prev_idat_crc_pos = 0;
            memset(local->idat_crc_ring, 0, sizeof(local->idat_crc_ring));
            local->idat_crc_ring_count = 0;
            local->idat_data_sz = 0;
            local->valid = false;
            png_solver_resume_reset(local);
          }
        }
      }
      break;
    }
  }

  // CRC-verify inherited data.  Contiguous carving places blocks
  // contiguously — including ZERO fill at GAP/OOO positions.  These
  // are WRONG blocks.  Walk the PNG chunk chain and verify CRC32 for
  // each chunk.  Trim at the first CRC failure.
  nb = blockvector_get_num_blocks(candidate->b);
  if (nb > 2) {
    uint8_t *data = (uint8_t *)blockvector_get_data_pointer(
        candidate->b);
    uint64_t dl = blockvector_get_data_length(candidate->b);
    if (data && dl > 20) {
      uint64_t pos = 8;  // skip PNG signature
      while (pos + 12 <= dl) {
        uint32_t chunk_len = ((uint32_t)data[pos] << 24)
            | ((uint32_t)data[pos + 1] << 16)
            | ((uint32_t)data[pos + 2] << 8)
            | (uint32_t)data[pos + 3];
        const uint8_t *type = data + pos + 4;
        if (!png_chunk_type_is_ascii(type)
            || chunk_len > PNG_MAX_IDAT_BODY_LEN) {
          break;
        }
        uint64_t crc_at = pos + 8 + (uint64_t)chunk_len;
        if (crc_at + 4 > dl) {
          // Chunk extends past BV data.  Temporarily extend
          // the BV with contiguous blocks to cover it, then
          // verify CRC.  If CRC fails, trim.  If passes, keep.
          uint64_t needed_bytes = crc_at + 4;
          uint64_t needed_blocks = (needed_bytes
              + (uint64_t)scalpel_state.blocksize - 1)
              / (uint64_t)scalpel_state.blocksize;
          uint64_t cur_nb = blockvector_get_num_blocks(
              candidate->b);
          int64_t last_ab = blockvector_get_apparent_blocknumber(
              candidate->b, cur_nb - 1);
          int64_t total_ap = (int64_t)filemirror_apparent_blocks(
              scalpel_state.filemirror);
          if (last_ab >= 0
              && last_ab + (int64_t)(needed_blocks - cur_nb)
                 < total_ap
              && needed_blocks > cur_nb) {
            resize_blockvector(candidate->b, needed_blocks);
            for (uint64_t ei = cur_nb; ei < needed_blocks; ei++) {
              blockvector_set_apparent_blocknumber(candidate->b,
                  ei, last_ab + 1 + (int64_t)(ei - cur_nb));
              inflate_blockvector_single_block(candidate->b, ei);
            }
            data = (uint8_t *)blockvector_get_data_pointer(
                candidate->b);
            dl = blockvector_get_data_length(candidate->b);
            // Now fall through to verify CRC below
          } else {
            break;  // can't extend
          }
        }
        uint32_t computed = crc32(0, NULL, 0);
        computed = crc32(computed, data + pos + 4,
            4 + chunk_len);
        uint32_t stored = ((uint32_t)data[crc_at] << 24)
            | ((uint32_t)data[crc_at + 1] << 16)
            | ((uint32_t)data[crc_at + 2] << 8)
            | (uint32_t)data[crc_at + 3];
        if (computed != stored) {
          // CRC failure on THIS chunk at byte `pos`.  The chunks BEFORE
          // pos already passed CRC in this walk (or earlier in state),
          // so their verification is preserved below.
          //
          // Trim to include up to `pos` (end of last passed chunk + start
          // of failed chunk).  Use CEILDIV so the partial last block
          // covering byte `pos` stays in BV — this lets state fields
          // referencing byte `pos` (e.g. last_chunk_crc_pos) remain
          // consistent with BV length.  Rounding DOWN to a block boundary
          // below `pos` would leave state referencing bytes past BV end
          // and force a defensive CRC-state wipe on every re-entry, which
          // was the root cause of the "sharp cliff at N=132" livelock:
          // state got reset -> reassembly restarted from scratch ->
          // solver yielded on same spot -> next checkpoint fired same
          // reset -> livelock.
          uint64_t keep_blocks = (pos + (uint64_t)scalpel_state.blocksize - 1)
              / (uint64_t)scalpel_state.blocksize;
          if (keep_blocks < 1) { keep_blocks = 1; }
          uint64_t cur_total = blockvector_get_num_blocks(candidate->b);
          if (keep_blocks < cur_total) {
            if (scalpel_state.mode_verbose) {
              lock_fprintf(stdout,
                  "PNG init_candidate: CRC failure at byte %"
                  PRIu64 ", trimming BV from %" PRIu64
                  " to %" PRIu64 " blocks (data_length=%" PRIu64 ")\n",
                  pos, nb, keep_blocks, pos);
            }
            resize_blockvector(candidate->b, keep_blocks);
            blockvector_set_data_length(candidate->b, pos);
            inflate_blockvector(candidate->b);
            // Cap state to trimmed position, but PRESERVE prior verified
            // progress (do NOT zero everything like the previous code did).
            if (local->last_chunk_crc_pos > pos) {
              local->last_chunk_crc_pos = pos;
            }
            if (local->last_idat_crc_pos > pos) {
              local->last_idat_crc_pos = pos;
            }
            if (local->prev_idat_crc_pos > pos) {
              local->prev_idat_crc_pos = pos;
            }
            // idat_crc_ring entries past pos are now invalid; cap them.
            for (int _ri = 0; _ri < IDAT_CRC_RING_SZ; _ri++) {
              if (local->idat_crc_ring[_ri] > pos) {
                local->idat_crc_ring[_ri] = 0;
              }
            }
            // Preserve solver frontier when this routine is merely
            // re-establishing the same CRC-failing suffix after a
            // checkpoint.  Resetting unconditionally here made long
            // suffix-anchored scans restart from zero forever.
            if (local->solver_suffix_nb != keep_blocks) {
              png_solver_resume_reset(local);
            }
          }
          break;
        }
        // Stop at IEND
        if (data[pos + 4] == 'I' && data[pos + 5] == 'E'
            && data[pos + 6] == 'N' && data[pos + 7] == 'D') {
          break;
        }
        pos = crc_at + 4;
      }
    }
  }
}

// png_direct_validate — call png_validate_core directly with local state,
// bypassing the carve state hash table.  Replicates the bookkeeping that
// reassembly_check_validation() does (set flavor, resize BV on success).
static inline bool png_direct_validate(int id, CarveInfo *candidate,
    uint64_t *validates_to, PNGCarveState *local,
    uuid_string_t uuidp, uuid_string_t uuidc) {
  (void)id; (void)uuidp; (void)uuidc;
  bool validates = false;
  bool promising = false;

#if VALIDATOR_PERFORMANCE_STATS > 0
  struct timespec FV_starttime, FV_endtime;
  clock_gettime(CLOCK_MONOTONIC, &FV_starttime);
#endif

  png_validate_core(blockvector_get_data_pointer(candidate->b),
                    blockvector_get_data_length(candidate->b),
                    &validates, validates_to, &promising,
                    candidate->needleidx, scalpel_state.blocksize,
                    candidate->carvehashkey, local);

#if VALIDATOR_PERFORMANCE_STATS > 0
  clock_gettime(CLOCK_MONOTONIC, &FV_endtime);
  uint64_t FV_elapsed = (FV_endtime.tv_sec - FV_starttime.tv_sec) * NANOSECONDS_PER_SECOND
                       + (FV_endtime.tv_nsec - FV_starttime.tv_nsec);
  atomic_fetch_add_explicit(&scalpel_state.search_specs[candidate->needleidx].FV_calls,
                            1, memory_order_acq_rel);
  atomic_max_u64_pub(&scalpel_state.search_specs[candidate->needleidx].FV_longest,
                     FV_elapsed);
  atomic_fetch_add_explicit(&scalpel_state.search_specs[candidate->needleidx].FV_total,
                            FV_elapsed, memory_order_acq_rel);
#endif

  if (validates) {
    candidate->flavor = VALIDATED;
    blockvector_set_data_length(candidate->b, *validates_to + 1);
    resize_blockvector(candidate->b,
        CEILDIV(blockvector_get_data_length(candidate->b),
                scalpel_state.blocksize));
  }

  return validates;
}

static inline bool png_cap_crc_state_to_length(PNGCarveState *local,
                                               uint64_t bv_end) {
  if (!local) {
    return false;
  }

  bool inconsistent = local->last_chunk_crc_pos > bv_end
      || local->last_idat_crc_pos > bv_end
      || local->prev_idat_crc_pos > bv_end
      || (local->valid && local->checkpoint_curpos > bv_end);
  for (int i = 0; i < IDAT_CRC_RING_SZ && !inconsistent; i++) {
    inconsistent = local->idat_crc_ring[i] > bv_end;
  }
  if (!inconsistent) {
    return false;
  }

  uint64_t cap_target = 0;
  if (local->last_chunk_crc_pos <= bv_end
      && local->last_chunk_crc_pos > cap_target) {
    cap_target = local->last_chunk_crc_pos;
  }
  if (local->last_idat_crc_pos <= bv_end
      && local->last_idat_crc_pos > cap_target) {
    cap_target = local->last_idat_crc_pos;
  }
  if (local->prev_idat_crc_pos <= bv_end
      && local->prev_idat_crc_pos > cap_target) {
    cap_target = local->prev_idat_crc_pos;
  }
  for (int i = 0; i < IDAT_CRC_RING_SZ; i++) {
    uint64_t r = local->idat_crc_ring[i];
    if (r <= bv_end && r > cap_target) {
      cap_target = r;
    }
  }

  if (cap_target > 0) {
    if (local->last_chunk_crc_pos > cap_target) {
      local->last_chunk_crc_pos = cap_target;
    }
    if (local->last_idat_crc_pos > cap_target) {
      local->last_idat_crc_pos = cap_target;
    }
    if (local->prev_idat_crc_pos > cap_target) {
      local->prev_idat_crc_pos = cap_target;
    }
    for (int i = 0; i < IDAT_CRC_RING_SZ; i++) {
      if (local->idat_crc_ring[i] > cap_target) {
        local->idat_crc_ring[i] = 0;
      }
    }
  } else {
    local->last_chunk_crc_pos = 0;
    local->last_idat_crc_pos = 0;
    local->prev_idat_crc_pos = 0;
    memset(local->idat_crc_ring, 0, sizeof(local->idat_crc_ring));
    local->idat_crc_ring_count = 0;
  }

  local->idat_data_sz = 0;
  local->valid = false;
  png_reassembly_search_resume_reset(local);
  return true;
}

static atomic_bool png_reassembly_base_validated_set;
static atomic_ulong png_reassembly_base_validated;

static inline uint64_t png_reassembly_validated_delta(void) {
  uint64_t current = atomic_load_explicit(&scalpel_state.validated_files,
                                          memory_order_acquire);
  bool expected = false;
  if (atomic_compare_exchange_strong_explicit(
          &png_reassembly_base_validated_set, &expected, true,
          memory_order_acq_rel, memory_order_acquire)) {
    atomic_store_explicit(&png_reassembly_base_validated, current,
                          memory_order_release);
    return 0;
  }
  uint64_t base = atomic_load_explicit(&png_reassembly_base_validated,
                                       memory_order_acquire);
  return current > base ? current - base : 0;
}

static inline void png_publish_reassembly_state(void *carvehashkey,
                                                PNGCarveState *local,
                                                CarveInfo *candidate) {
  if (!local) {
    return;
  }
  if (candidate && candidate->b) {
    png_cap_crc_state_to_length(local,
        blockvector_get_data_length(candidate->b));
  }
  carve_put_state(carvehashkey, local);
}

static inline bool png_preserve_crc_frontier_in_candidate(
    PNGCarveState *local, CarveInfo *candidate) {
  if (!local || !candidate || !candidate->b
      || local->last_chunk_crc_pos == 0
      || scalpel_state.blocksize <= 0) {
    return false;
  }

  uint64_t crc_blocks = CEILDIV(local->last_chunk_crc_pos,
                                (uint64_t)scalpel_state.blocksize);
  uint64_t cur_blocks = blockvector_get_num_blocks(candidate->b);
  if (crc_blocks == 0 || crc_blocks > cur_blocks) {
    return false;
  }

  resize_blockvector(candidate->b, crc_blocks);

  /* Keep the whole filesystem block containing the verified CRC boundary.
   * The tail of that block often contains the next chunk header; trimming to
   * the exact CRC byte forces the next pass to rediscover data it already has.
   */
  blockvector_set_data_length(candidate->b,
      crc_blocks * (uint64_t)scalpel_state.blocksize);
  return true;
}

static inline bool png_trim_output_blind_idat_tail(
    PNGCarveState *local, CarveInfo *candidate) {
  if (!local || !candidate || !candidate->b
      || candidate->flavor == VALIDATED
      || local->have_iend) {
    return false;
  }

  const uint8_t *data = (const uint8_t *)blockvector_get_data_pointer(
      candidate->b);
  uint64_t dl = blockvector_get_data_length(candidate->b);

  if (!data || dl < 20 || scalpel_state.blocksize <= 0) {
    return false;
  }

  uint64_t pos = 8;
  uint64_t prev_idat_end = 0;
  uint64_t last_idat_end = 0;
  uint64_t idat_end_ring[IDAT_CRC_RING_SZ] = {0};
  uint32_t idat_end_count = 0;
  uint64_t keep_pos = 0;
  while (pos + 8 <= dl) {
    uint32_t chunk_len = ((uint32_t)data[pos] << 24)
        | ((uint32_t)data[pos + 1] << 16)
        | ((uint32_t)data[pos + 2] << 8)
        | (uint32_t)data[pos + 3];
    const uint8_t *type = data + pos + 4;
    if (!png_chunk_type_is_ascii(type)
        || chunk_len > PNG_MAX_IDAT_BODY_LEN) {
      break;
    }

    uint64_t crc_at = pos + 8 + (uint64_t)chunk_len;
    if (crc_at + 4 > dl) {
      if (type[0] == 'I' && type[1] == 'D'
          && type[2] == 'A' && type[3] == 'T'
          && prev_idat_end > 0) {
        keep_pos = prev_idat_end;
      }
      break;
    }

    uint32_t computed = crc32(0, NULL, 0);
    computed = crc32(computed, data + pos + 4,
        (uInt)(4 + chunk_len));
    uint32_t stored = ((uint32_t)data[crc_at] << 24)
        | ((uint32_t)data[crc_at + 1] << 16)
        | ((uint32_t)data[crc_at + 2] << 8)
        | (uint32_t)data[crc_at + 3];
    if (computed != stored) {
      break;
    }

    uint64_t chunk_end = crc_at + 4;
    if (type[0] == 'I' && type[1] == 'D'
        && type[2] == 'A' && type[3] == 'T') {
      prev_idat_end = last_idat_end;
      last_idat_end = chunk_end;
      idat_end_ring[idat_end_count % IDAT_CRC_RING_SZ] = chunk_end;
      idat_end_count++;
    }
    else if (type[0] == 'I' && type[1] == 'E'
             && type[2] == 'N' && type[3] == 'D') {
      // Non-VALIDATED output with IEND means the chunk envelope closed
      // but full validation rejected it.  Roll back before the terminal
      // IDATs rather than writing a structurally neat but wrong tail.
      if (idat_end_count >= 3) {
        keep_pos = idat_end_ring[(idat_end_count - 3)
                                 % IDAT_CRC_RING_SZ];
      }
      else if (idat_end_count >= 2) {
        keep_pos = idat_end_ring[(idat_end_count - 2)
                                 % IDAT_CRC_RING_SZ];
      }
      break;
    }
    pos = chunk_end;
  }

  if (keep_pos == 0) {
    return false;
  }

  uint64_t keep_blocks = CEILDIV(keep_pos,
      (uint64_t)scalpel_state.blocksize);
  if (keep_blocks == 0
      || keep_blocks >= blockvector_get_num_blocks(candidate->b)) {
    return false;
  }

  resize_blockvector(candidate->b, keep_blocks);
  blockvector_set_data_length(candidate->b,
      keep_blocks * (uint64_t)scalpel_state.blocksize);
  local->last_chunk_crc_pos = keep_pos;
  local->last_idat_crc_pos = keep_pos;
  return true;
}

static inline void png_trim_checkpoint_candidate(
    PNGCarveState *local, CarveInfo *candidate) {
  if (!local || !candidate || !candidate->b
      || candidate->flavor == VALIDATED) {
    return;
  }

  uint64_t cur_blocks = blockvector_get_num_blocks(candidate->b);
  uint64_t keep_blocks = cur_blocks;

  if (local->solver_phase != 0
      && local->solver_suffix_nb > 0
      && local->solver_suffix_nb < keep_blocks) {
    keep_blocks = local->solver_suffix_nb;
  }
  if (local->m2_resume.active
      && local->m2_resume.suffix_nb > 0
      && local->m2_resume.suffix_nb < keep_blocks) {
    keep_blocks = local->m2_resume.suffix_nb;
  }
  if (local->bbk_resume_active
      && local->bbk_resume_suffix_nb > 0
      && local->bbk_resume_suffix_nb < keep_blocks) {
    keep_blocks = local->bbk_resume_suffix_nb;
  }
  if (local->d1_resume_valid
      && local->d1_resume_suffix_nb > 0
      && local->d1_resume_suffix_nb < keep_blocks) {
    keep_blocks = local->d1_resume_suffix_nb;
  }
  if (local->gap_fast_resume_valid
      && !local->gap_fast_exhausted
      && local->gap_fast_suffix_nb > 0
      && local->gap_fast_suffix_nb < keep_blocks) {
    keep_blocks = local->gap_fast_suffix_nb;
  }
  if (local->safe_partial_blocks > 0
      && local->safe_partial_blocks < keep_blocks) {
    keep_blocks = local->safe_partial_blocks;
  }

  if (keep_blocks < cur_blocks) {
    resize_blockvector(candidate->b, keep_blocks);
    if (local->safe_partial_blocks == keep_blocks
        && local->safe_partial_length > 0) {
      blockvector_set_data_length(candidate->b,
          local->safe_partial_length);
    }
    else {
      blockvector_set_data_length(candidate->b,
          keep_blocks * (uint64_t)scalpel_state.blocksize);
    }
  }

  png_preserve_crc_frontier_in_candidate(local, candidate);
}

static inline bool png_should_defer_exhausted_partial(
    PNGCarveState *local, uint64_t suffix_start_nb, uint64_t crc_pos) {
  if (!local || scalpel_state.max_reassembly_threads <= 1) {
    return false;
  }

  uint64_t queued = nolock_queue_length(&promising_queue);
  uint32_t idle = atomic_load_explicit(&num_idle_reassembly_threads,
                                       memory_order_acquire);
  uint32_t max_threads = (uint32_t)scalpel_state.max_reassembly_threads;
  uint32_t active = max_threads > idle ? max_threads - idle : 0;
  uint64_t validated_delta = png_reassembly_validated_delta();
  if ((queued == 0 && active <= 1)
      || validated_delta == 0
      || (queued == 0 && validated_delta < 2)) {
    local->exhausted_waiting_for_checkpoint = false;
    return false;
  }

  struct timespec cp = last_checkpoint;
  uint64_t validated = atomic_load_explicit(&scalpel_state.validated_files,
                                            memory_order_acquire);
  bool same_key = local->exhausted_waiting_for_checkpoint
      && local->exhausted_wait_suffix_nb == suffix_start_nb
      && local->exhausted_wait_crc_pos == crc_pos;

  /* `last_checkpoint` is initialized at process start and is not advanced by
   * the checkpoint loop, so it cannot be used as the primary liveness signal
   * here.  Defer an exhausted partial only while other files are still being
   * validated.  If this same suffix/CRC key re-enters and validated_files did
   * not advance, write the partial instead of requeueing forever. */
  if (same_key && validated <= local->exhausted_wait_validated_files) {
    local->exhausted_waiting_for_checkpoint = false;
    return false;
  }

  local->exhausted_waiting_for_checkpoint = true;
  local->exhausted_wait_suffix_nb = suffix_start_nb;
  local->exhausted_wait_crc_pos = crc_pos;
  local->exhausted_wait_validated_files = validated;
  local->exhausted_wait_checkpoint_sec = cp.tv_sec;
  local->exhausted_wait_checkpoint_nsec = cp.tv_nsec;
  return true;
}

static inline bool png_reassembly_checkpoint_candidate(
    int id, void *carvehashkey, PNGCarveState *local, CarveInfo *candidate,
    uuid_string_t uuidp, uuid_string_t uuidc) {

  png_trim_checkpoint_candidate(local, candidate);
  png_publish_reassembly_state(carvehashkey, local, candidate);
  return reassembly_time_to_checkpoint(id, candidate, uuidp, uuidc);
}

static inline void png_reassembly(ThreadWork *work, CarveInfo **c,
                                   uuid_string_t uuidp, uuid_string_t uuidc) {
  bool validates;
  uint64_t validates_to;
  CarveInfo *candidate = *c;
  bool trimmed_stale_blocks = false;  // true after we've trimmed at current suffix
  uint64_t trimmed_at_suffix_nb = 0;  // suffix_start_nb where last trim happened
  bool complete_probe_validated = false;
  bool solver_advanced_last_pass = false;  // true if solver placed blocks past CRC
  bool state_published = false;
  uint64_t safe_partial_blocks = 0;
  uint64_t safe_partial_length = 0;

  // Local carve state — ONE get from hash table.  All reads/writes go
  // through this pointer; hash table is only synced at checkpoints + end.
  // Save the hash key now — candidate may be freed by kill queue later.
  char local_carvehashkey[CARVE_HASH_KEY_SIZE];
  memcpy(local_carvehashkey, candidate->carvehashkey, CARVE_HASH_KEY_SIZE);
  PNGCarveState *local = (PNGCarveState *)carve_get_state(
      local_carvehashkey);
  if (!local) {
    local = (PNGCarveState *)calloc(1, sizeof(PNGCarveState));
    check_memory_allocation(local, __LINE__, __FILE__, "local");
  }

  png_reassembly_init_candidate(candidate, local);
  uint64_t entry_last_chunk_crc_pos = local->last_chunk_crc_pos;

  if (png_try_complete_contiguous(blockvector_get_data_pointer(candidate->b),
                                  blockvector_get_data_length(candidate->b),
                                  &validates_to)) {
    candidate->flavor = VALIDATED;
    blockvector_set_data_length(candidate->b, validates_to + 1);
    resize_blockvector(candidate->b,
        CEILDIV(blockvector_get_data_length(candidate->b),
                scalpel_state.blocksize));
    complete_probe_validated = true;
    goto done_write_candidate;
  }

  if (scalpel_state.mode_verbose) {
    uint64_t nb_after_sanity = blockvector_get_num_blocks(candidate->b);
    int64_t first_ab = nb_after_sanity > 0 ?
        blockvector_get_apparent_blocknumber(candidate->b, 0) : -1;
    int64_t last_ab = nb_after_sanity > 0 ?
        blockvector_get_apparent_blocknumber(candidate->b, nb_after_sanity - 1) : -1;
    lock_fprintf(stdout,
                 "\nPNG reassembly thread # %1d: processing candidate %p UUIDs\n%s / %s.\n"
                 "  After sanity check: %" PRIu64 " blocks, apparent range [%" PRId64 "..%" PRId64 "]\n",
                 work->id, candidate->b, uuidp, uuidc,
                 nb_after_sanity, first_ab, last_ab);
  }

png_reassembly_restart:
  while (1) {
    if (atomic_load_explicit(&REASS_RETURN_TO_IDLE,
                             memory_order_acquire)) {
      state_published = true;
      if (png_reassembly_checkpoint_candidate(work->id, local_carvehashkey,
              local, candidate, uuidp, uuidc)) {
        goto done_do_not_write_candidate;
      }
      state_published = false;
    }
    if (reassembly_check_kill_queue(work, &candidate, uuidp, uuidc)) {
      goto done_do_not_write_candidate;
    }
    if (reassembly_check_max_size(work->id, candidate, uuidp, uuidc)) {
      goto done_write_candidate;
    }

    if (blockvector_get_num_blocks(candidate->b) == 0) {
      if (scalpel_state.mode_verbose) {
        lock_fprintf(stdout,
            "PNG reassembly: 0-block BV, destroying candidate\n");
      }
      destroy_candidate(&candidate);
      goto done_do_not_write_candidate;
    }


    // =====================================================================
    // SUFFIX BUILDING: extend the BV by one suffix (contiguous block run).
    //
    // Suffix length depends on CRC state:
    //   - Known IDAT size (post-CRC): fill_needed = (idat_sz+12)/blocksize
    //   - Unknown (pre-CRC or no IDAT info): fill_needed = 1 (greedy)
    //
    // Acceptance:
    //   - CRC advance: definitive, always accept (any phase)
    //   - Best validates_to: tentative, accept when no CRC info yet
    //
    // Tiers (applied in order until suffix completes):
    //   1. Contiguous fill with friend rotation
    //   2. Split-fill (2-segment, fill_needed > 1 only)
    //   3. Block-by-block greedy (BBK)
    // =====================================================================
    {
      uint64_t crc_pos = local->last_chunk_crc_pos;
      // Get the next PNG chunk's body length.  Most of the machinery below
      // was built for IDAT CRC solving, but PNG CRC geometry is identical
      // for ancillary chunks.  That matters when fragmentation occurs in
      // metadata before the first IDAT: the next proof point is the current
      // ancillary chunk's CRC, not an image-data CRC.
      long idat_sz = 0;
      if (local->idat_data_sz > 0
          && local->idat_data_start == crc_pos + 8) {
        idat_sz = local->idat_data_sz;
      }
      // Read actual chunk size from BV data.  crc_pos = curpos AFTER the
      // last verified CRC = start of next chunk.  For IDAT this also fixes
      // stale idat_data_sz when the last IDAT is shorter than preceding ones.
      if (crc_pos > 0) {
        const uint8_t *bvd =
            (const uint8_t *)blockvector_get_data_pointer(candidate->b);
        uint64_t bvdl = blockvector_get_data_length(candidate->b);
        // Verify crc_pos points to a valid chunk boundary.
        // The validator's last_chunk_crc_pos can drift when ancillary chunks
        // (iCCP, sRGB, etc.) shift byte positions between IHDR and IDAT.
        // If misaligned, walk the chunk chain to find the correct position.
        if (bvd && crc_pos + 8 <= bvdl
            && !png_chunk_type_is_ascii(bvd + crc_pos + 4)) {
          // crc_pos is misaligned. Walk chunk chain from byte 8 but
          // ONLY through the verified prefix (up to crc_pos).  Don't
          // walk into unverified fill data -- random bytes could produce
          // fake chunk lengths and markers at large N.
          uint64_t walk_limit = crc_pos + 128;
          if (walk_limit > bvdl) { walk_limit = bvdl; }
          uint64_t p = 8;
          while (p + 12 <= walk_limit) {
            uint32_t cl = ((uint32_t)bvd[p] << 24)
                | ((uint32_t)bvd[p + 1] << 16)
                | ((uint32_t)bvd[p + 2] << 8)
                | (uint32_t)bvd[p + 3];
            if (cl > PNG_MAX_IDAT_BODY_LEN) { break; }
            uint64_t nxt = p + 12 + (uint64_t)cl;
            if (nxt > walk_limit) { break; }
            if (nxt > crc_pos
                && nxt + 8 <= bvdl
                && png_chunk_type_is_ascii(bvd + nxt + 4)) {
              crc_pos = nxt;
              local->last_chunk_crc_pos = nxt;
              break;
            }
            p = nxt;
          }
        }
        if (bvd && crc_pos + 8 <= bvdl
            && png_chunk_type_is_ascii(bvd + crc_pos + 4)
            && !(bvd[crc_pos + 4] == 'I' && bvd[crc_pos + 5] == 'E'
                 && bvd[crc_pos + 6] == 'N' && bvd[crc_pos + 7] == 'D')) {
          long actual_sz = (long)(((uint32_t)bvd[crc_pos] << 24)
                                | ((uint32_t)bvd[crc_pos + 1] << 16)
                                | ((uint32_t)bvd[crc_pos + 2] << 8)
                                | (uint32_t)bvd[crc_pos + 3]);
          if (actual_sz > 0
              && (uint64_t)actual_sz <= PNG_MAX_IDAT_BODY_LEN) {
            idat_sz = actual_sz;
          }
        }
      }

      // Trim BV to the last verified CRC boundary block.
      // SKIP when the solver placed blocks past the CRC boundary on the
      // previous pass — those blocks are correct but not yet CRC-verified.
      // Trimming them forces the solver to re-solve, causing infinite stalls.
      if (crc_pos > 0 && !solver_advanced_last_pass) {
        uint64_t crc_blk = (crc_pos + (uint64_t)scalpel_state.blocksize - 1)
                           / (uint64_t)scalpel_state.blocksize;
        uint64_t cur_nb = blockvector_get_num_blocks(candidate->b);
        if (crc_blk < cur_nb) {
          if (scalpel_state.mode_verbose) {
            lock_fprintf(stdout,
                "PNG TRIM: trimming BV from %" PRIu64 " to %" PRIu64
                " blocks (crc_pos=%" PRIu64 ")\n",
                cur_nb, crc_blk, crc_pos);
          }
          resize_blockvector(candidate->b, crc_blk);
          // Reset solver state — the trim changed the BV.
          // Do NOT reset trimmed_stale_blocks: that flag prevents an
          // infinite loop where CRC trim and stale-block trim keep
          // resetting each other's guards.
          png_solver_resume_reset(local);
          /* Do not clear idat_data_sz merely because the IDAT extends past
           * the trimmed BV.  That is the normal fragmented case: the solver
           * needs the already-parsed next-IDAT length to know the CRC target.
           * Stale sizes are rejected above unless idat_data_start matches
           * this exact chunk boundary. */
        }
      }

      uint64_t suffix_start_nb = blockvector_get_num_blocks(candidate->b);
      uint64_t suffix_start_dl = blockvector_get_data_length(candidate->b);
      safe_partial_blocks = suffix_start_nb;
      safe_partial_length = suffix_start_dl;
      local->safe_partial_blocks = suffix_start_nb;
      local->safe_partial_length = suffix_start_dl;
      bool png_trace_suffix = false;
      int png_trace_event = -1;
      const char *png_trace_suffix_env = getenv("SCALPEL_PNG_TRACE_SUFFIX_NB");
      if (png_trace_suffix_env) {
        int64_t png_trace_nb = strtoll(png_trace_suffix_env, NULL, 10);
        png_trace_suffix = png_trace_nb < 0
            || suffix_start_nb == (uint64_t)png_trace_nb;
        if (png_trace_suffix) {
          const char *png_trace_limit_env = getenv("SCALPEL_PNG_TRACE_LIMIT");
          int png_trace_limit = png_trace_limit_env
              ? atoi(png_trace_limit_env) : 200;
          png_trace_event = atomic_fetch_add_explicit(
              &png_debug_trace_events, 1, memory_order_acq_rel);
          if (png_trace_event >= png_trace_limit) {
            png_trace_suffix = false;
          }
        }
      }

      uint32_t fill_needed;
      bool accept_on_validates_to;
      bool accept_on_idat_milestone = false;

      // Byte position and size of the first IDAT chunk, parsed from
      // BV data.  Used to compute fill_needed in pre-CRC mode and
      // for cheap CRC32 verification in Tier 1C.
      uint64_t first_idat_body_start = 0;
      uint32_t first_idat_body_size = 0;
      uint64_t first_idat_crc_pos = 0;
      bool have_first_idat = png_parse_first_idat(candidate,
          &first_idat_body_start, &first_idat_body_size,
          &first_idat_crc_pos);
      if (png_trace_suffix) {
        int64_t png_first_ab = suffix_start_nb > 0
            ? blockvector_get_apparent_blocknumber(candidate->b, 0) : -1;
        int64_t png_last_ab = suffix_start_nb > 0
            ? blockvector_get_apparent_blocknumber(candidate->b,
                suffix_start_nb - 1) : -1;
        lock_fprintf(stdout,
            "PNG_TRACE_SUFFIX event=%d snb=%" PRIu64 " dl=%" PRIu64
            " first=%" PRId64 " last=%" PRId64 " crc=%" PRIu64
            " idat_sz=%ld have_first=%d first_body=%" PRIu64
            " first_size=%u first_crc=%" PRIu64 "\n",
            png_trace_event, suffix_start_nb, suffix_start_dl,
            png_first_ab, png_last_ab, crc_pos, idat_sz,
            have_first_idat ? 1 : 0, first_idat_body_start,
            first_idat_body_size, first_idat_crc_pos);
      }

      if (idat_sz <= 0 && crc_pos > 0) {
        uint64_t inferred_idat_sz = 0;
        if (have_first_idat && first_idat_body_size > 0
            && crc_pos == first_idat_crc_pos + 4) {
          inferred_idat_sz = first_idat_body_size;
        } else if (local->last_idat_crc_pos == crc_pos
            && local->prev_idat_crc_pos > 0
            && crc_pos > local->prev_idat_crc_pos + 12) {
          inferred_idat_sz = crc_pos - local->prev_idat_crc_pos - 12;
        }
        if (inferred_idat_sz > 0
            && inferred_idat_sz <= (uint64_t)PNG_MAX_IDAT_BODY_LEN) {
          /* The next header is often just beyond the trimmed CRC frontier.
           * Use the previous verified IDAT size as a solver target only;
           * candidates still must pass CRC and next-chunk marker checks. */
          idat_sz = (long)inferred_idat_sz;
        }
      }

      if (crc_pos > 0 && idat_sz > 0) {
        // Post-CRC with known IDAT: exact chunk fill.
        // Must use byte positions to account for chunk start
        // not aligning with a block boundary.
        uint64_t next_crc = crc_pos + (uint64_t)idat_sz + 12;
        uint64_t end_blk = (next_crc + (uint64_t)scalpel_state.blocksize - 1)
                           / (uint64_t)scalpel_state.blocksize;
        fill_needed = (uint32_t)(end_blk > suffix_start_nb
                                 ? end_blk - suffix_start_nb : 1);
        if (fill_needed < 2) { fill_needed = 2; }
        { uint32_t _fn_cap = (uint32_t)(scalpel_state.largest_maxfilesize
              / (uint64_t)scalpel_state.blocksize + 2);
          if (fill_needed > _fn_cap) { fill_needed = _fn_cap; }
        }
        accept_on_validates_to = false;
      } else if (have_first_idat && first_idat_crc_pos + 4 > suffix_start_dl) {
        // Pre-CRC but IDAT chunk header is in the prefix.  Compute the
        // fill needed to reach the first CRC boundary.  If that span is
        // large, first let zlib/filter validation advance through any
        // contiguous local prefix; otherwise the CRC solver sees a huge
        // artificial M and wastes time solving blocks that are already local.
        uint64_t target = first_idat_crc_pos + 4;  // include CRC itself
        uint64_t end_blk = (target + (uint64_t)scalpel_state.blocksize - 1)
                           / (uint64_t)scalpel_state.blocksize;
        fill_needed = (uint32_t)(end_blk > suffix_start_nb
                                 ? end_blk - suffix_start_nb : 1);
        if (fill_needed < 2) { fill_needed = 2; }
        { uint32_t _fn_cap = (uint32_t)(scalpel_state.largest_maxfilesize
              / (uint64_t)scalpel_state.blocksize + 2);
          if (fill_needed > _fn_cap) { fill_needed = _fn_cap; }
        }
        accept_on_validates_to = (fill_needed > PNG_GAP_INDEX_MAX_M);
      } else {
        // No IDAT info at all: bootstrap just far enough to expose the
        // first IDAT header, then switch to CRC-driven logic.  Do not
        // keep candidates alive on validates_to alone here; that causes
        // large runs to stall on structurally plausible junk suffixes.
        fill_needed = 4;
        { uint32_t _fn_cap = (uint32_t)(scalpel_state.largest_maxfilesize
              / (uint64_t)scalpel_state.blocksize + 2);
          if (fill_needed > _fn_cap) { fill_needed = _fn_cap; }
        }
        if (fill_needed < 1) { fill_needed = 1; }
        accept_on_validates_to = false;
        accept_on_idat_milestone = true;
      }

      if (scalpel_state.mode_verbose) {
        lock_fprintf(stdout,
                     "PNG SUFFIX: crc_pos=%" PRIu64 " idat_sz=%ld"
                     " fill_needed=%" PRIu32 " accept_vt=%d\n",
                     crc_pos, idat_sz, fill_needed,
                     accept_on_validates_to);
      }
      int64_t total_apparent = (int64_t)filemirror_apparent_blocks(
          scalpel_state.filemirror);
      int64_t last_block = blockvector_get_apparent_blocknumber(candidate->b,
          suffix_start_nb - 1);
      // OOO fixup: if the solver placed a far-away OOO block at the last
      // BV position, last_block points to a distant disk location.  Detect
      // by comparing to the expected contiguous block from position 0.
      // Only correct when the gap is large (clearly OOO, not a normal gap).
      {
        int64_t base = blockvector_get_apparent_blocknumber(candidate->b, 0);
        int64_t expected = base + (int64_t)(suffix_start_nb - 1);
        int64_t gap = last_block - expected;
        if (gap < 0) { gap = -gap; }
        if (gap > (int64_t)fill_needed + 4 && expected >= 0
            && expected < total_apparent) {
          last_block = expected;
        }
      }

      bool baseline_available = total_apparent > 0 && last_block >= -1
          && (uint64_t)fill_needed <= (uint64_t)total_apparent
          && last_block < total_apparent - (int64_t)fill_needed;

      // A header or repaired fragment can lie near the end of apparent
      // address space.  The contiguous trial is only a baseline for the CRC
      // solver, so select another unused window rather than indexing past the
      // blockmap.
      if (!baseline_available) {
        int64_t trial_start = -1;
        bool first_window_available = fill_needed <= total_apparent;
        for (uint32_t f = 0; first_window_available && f < fill_needed; f++) {
          int64_t actual = filemirror_actual_blocknumber(
              scalpel_state.filemirror, (int64_t)f);
          if (actual < 0
              || filemirror_actual_block_covered(
                  scalpel_state.filemirror, actual)
              || apparent_block_in_blockvector(candidate->b, (int64_t)f)) {
            first_window_available = false;
          }
        }
        if (first_window_available) {
          trial_start = 0;
        }
        else {
          uint64_t used_count = blockvector_get_num_blocks(candidate->b);
          int64_t *used = NULL;
          if (used_count <= SIZE_MAX / sizeof(int64_t)) {
            used = (int64_t *)malloc((size_t)used_count * sizeof(int64_t));
          }
          if (used) {
            for (uint64_t i = 0; i < used_count; i++) {
              used[i] = blockvector_get_apparent_blocknumber(candidate->b, i);
            }
            qsort(used, (size_t)used_count, sizeof(int64_t),
                  png_compare_int64);

            uint64_t used_index = 0;
            uint32_t available_run = 0;
            for (int64_t apparent = 0;
                 apparent < total_apparent && trial_start < 0;
                 apparent++) {
              while (used_index < used_count
                     && used[used_index] < apparent) {
                used_index++;
              }
              bool in_candidate = used_index < used_count
                  && used[used_index] == apparent;
              if (in_candidate) {
                while (used_index < used_count
                       && used[used_index] == apparent) {
                  used_index++;
                }
              }
              int64_t actual = filemirror_actual_blocknumber(
                  scalpel_state.filemirror, apparent);
              if (in_candidate || actual < 0
                  || filemirror_actual_block_covered(
                      scalpel_state.filemirror, actual)) {
                available_run = 0;
              }
              else if (++available_run == fill_needed) {
                trial_start = apparent + 1 - (int64_t)fill_needed;
              }
            }
            free(used);
          }
          else {
            // Preserve recovery under allocation pressure using the original
            // bounded-memory scan.
            for (int64_t start = 0;
                 start + (int64_t)fill_needed <= total_apparent;
                 start++) {
              bool available = true;
              for (uint32_t f = 0; f < fill_needed; f++) {
                int64_t apparent = start + (int64_t)f;
                int64_t actual = filemirror_actual_blocknumber(
                    scalpel_state.filemirror, apparent);
                if (actual < 0
                    || filemirror_actual_block_covered(
                        scalpel_state.filemirror, actual)
                    || apparent_block_in_blockvector(candidate->b,
                                                     apparent)) {
                  available = false;
                  break;
                }
              }
              if (available) {
                trial_start = start;
                break;
              }
            }
          }
        }
        if (trial_start >= 0) {
          last_block = trial_start - 1;
          baseline_available = true;
        }
      }

      bool suffix_found = false;
      // solver_advanced_last_pass persists across iterations — only reset
      // when the CRC trim at line 9807 actually fires (meaning the solver's
      // blocks were superseded).  Resetting here caused the CRC trim to
      // erase solver progress on the very next iteration.
      // IDAT marker filter: precompute which trial block must have an
      // IDAT marker and at what offset.  Used by ALL search tiers to
      // skip blocks that can't possibly contain the CRC boundary.
      // The next "IDAT" type field is 8 bytes after the CRC position:
      //   [4-byte CRC][4-byte length][4-byte type "IDAT"]
      // For pre-CRC: use first_idat_crc_pos.
      // For post-CRC: use the computed next CRC position.
      int64_t idat_filter_block = -1;  // which trial block (relative to suffix_start)
      uint32_t idat_filter_offset = 0; // byte offset within that block
      bool idat_filter_active = false;
      {
        uint64_t crc_check_pos = 0;
        if (crc_pos > 0 && idat_sz > 0) {
          crc_check_pos = crc_pos + 8 + (uint64_t)idat_sz;
        } else if (have_first_idat) {
          crc_check_pos = first_idat_crc_pos;
        }
        if (crc_check_pos > 0) {
          // The next IDAT type is at crc_check_pos + 8
          uint64_t next_idat_type = crc_check_pos + 8;
          int64_t marker_block = (int64_t)(next_idat_type
              / (uint64_t)scalpel_state.blocksize);
          idat_filter_block = marker_block - (int64_t)suffix_start_nb;
          idat_filter_offset = (uint32_t)(next_idat_type
              % (uint64_t)scalpel_state.blocksize);
          idat_filter_active = (idat_filter_block >= 0
              && idat_filter_block < (int64_t)fill_needed);
        }
      }

      // Inline check: does a candidate fill starting at apparent block
      // 'start' have IDAT at the expected position?
      #define IDAT_FILTER_CHECK(start) \
        (idat_filter_active \
         ? png_block_has_idat_at((start) + idat_filter_block, \
               idat_filter_offset, candidate->needleidx) \
         : true)

      // -------------------------------------------------------------------
      // Two-mode dispatch:
      //   Pre-CRC (crc_pos == 0): contiguous fill with structural validation
      //   Post-CRC (crc_pos > 0): CRC solver is the primary strategy
      // -------------------------------------------------------------------

      // If the validator already found IEND, the file is complete.
      // Don't try to extend further — just write what we have.
      if (local->have_iend) {
        candidate->flavor = VALIDATED;
        goto done_write_candidate;
      }

      // Reset frontier when the target IDAT changes (crc_pos advanced
      // or suffix_start_nb changed).  The frontier indices are only valid
      // for the same (suffix_start_nb, crc_pos) they were saved at.
      // Use solver_suffix_nb to detect changes — it tracks the
      // suffix_start_nb the frontier was saved for.
      if (local->solver_suffix_nb != suffix_start_nb) {
        bool preserve_gap_resume =
            (local->gap_fast_suffix_nb == suffix_start_nb
             && local->gap_fast_crc_pos == crc_pos
             && (local->gap_fast_resume_valid
                 || local->gap_fast_exhausted));
        if (!preserve_gap_resume) {
          png_solver_resume_reset(local);
        }
        local->solver_suffix_nb = suffix_start_nb;
      }

      if (crc_pos > 0 && idat_sz > 0) {
        // POST-CRC: GALLOP FIRST, then solver at boundaries.
        //
        // Step 1: Try contiguous extension (cheap).  If the fragmentation
        // boundary is behind us, the next blocks are contiguous and
        // pngcheck can verify them without the solver.
        {
          int64_t gal_ab = last_block + 1;
          int64_t max_ab = (int64_t)filemirror_apparent_blocks(
              scalpel_state.filemirror);
          uint64_t gal_nb = suffix_start_nb;
	          uint64_t gal_cap = (idat_sz > 0)
	              ? (uint64_t)((idat_sz + 12) / scalpel_state.blocksize + 1)
	              : scalpel_state.gallop_factor;
	          if (gal_cap < scalpel_state.gallop_factor)
	            gal_cap = scalpel_state.gallop_factor;
	          if (gal_cap > scalpel_state.gallop_limit)
	            gal_cap = scalpel_state.gallop_limit;
	          if (gal_cap > fill_needed) {
	            gal_cap = fill_needed;
	          }
	          if (fill_needed > PNG_GAP_INDEX_MAX_M && gal_cap > 4) {
	            gal_cap = 4;
	          } else if (fill_needed > 3 && gal_cap > 1) {
	            gal_cap = 1;
	          }
          while (gal_ab < max_ab && gal_nb < suffix_start_nb + gal_cap
                 && !filemirror_actual_block_covered(
                     scalpel_state.filemirror,
                     filemirror_actual_blocknumber(
                         scalpel_state.filemirror, gal_ab))) {
            resize_blockvector(candidate->b, gal_nb + 1);
            blockvector_set_apparent_blocknumber(candidate->b, gal_nb, gal_ab);
            inflate_blockvector_single_block(candidate->b, gal_nb);
            gal_nb++;
            gal_ab++;
          }
	          if (gal_nb > suffix_start_nb) {
	            uint64_t crc_before_gallop = local->last_chunk_crc_pos;
	            bool gsv; uint64_t gsvt;
	            gsv = png_direct_validate(work->id, candidate,
	                &gsvt, local, uuidp, uuidc);
	            {
	              static int64_t png_post_trace_start_block = -2;
	              if (png_post_trace_start_block == -2) {
	                const char *trace_env =
	                    getenv("SCALPEL_PNG_TRACE_STARTBLOCK");
	                png_post_trace_start_block = trace_env
	                    ? strtoll(trace_env, NULL, 10) : -1;
	              }
	              if (png_post_trace_start_block >= 0
	                  && blockvector_get_num_blocks(candidate->b) > 0
	                  && blockvector_get_actual_blocknumber(candidate->b, 0)
	                      == png_post_trace_start_block) {
	                lock_fprintf(stdout,
	                    "PNG_TRACE_POSTCRC_GALLOP start=%" PRId64
	                    " snb=%" PRIu64 " fill=%u gal_nb=%" PRIu64
	                    " gsv=%d gsvt=%" PRIu64 " suffix_dl=%" PRIu64
	                    " crc_before=%" PRIu64 " crc_after=%" PRIu64
	                    " idat_crc=%" PRIu64 "\n",
	                    png_post_trace_start_block, suffix_start_nb,
	                    fill_needed, gal_nb, gsv ? 1 : 0, gsvt,
	                    suffix_start_dl, crc_before_gallop,
	                    local->last_chunk_crc_pos,
	                    crc_pos + 8 + (uint64_t)idat_sz);
	              }
	            }
	            if (gsv) {
	              goto done_write_candidate;
	            }
	            if (local->last_chunk_crc_pos > crc_before_gallop) {
	              // CRC advanced! Contiguous blocks worked. Trim to verified.
	              if (local->last_idat_crc_pos > 0) {
	                uint64_t trim_blk = (local->last_idat_crc_pos
	                    + (uint64_t)scalpel_state.blocksize - 1)
                    / (uint64_t)scalpel_state.blocksize;
                if (trim_blk < blockvector_get_num_blocks(candidate->b)) {
                  resize_blockvector(candidate->b, trim_blk);
                }
              }
	              suffix_found = true;
	              continue;  // gallop again from new position
	            }
	            if (fill_needed > PNG_POSTCRC_SMALL_SOLVER_FILL_MAX
	                && gsvt >= suffix_start_dl + scalpel_state.blocksize - 1) {
	              uint64_t idat_crc_field_pos =
	                  crc_pos + 8 + (uint64_t)idat_sz;
	              if (gsvt < idat_crc_field_pos) {
	                // Keep the structurally proven local prefix so the next
	                // pass solves only the actual seam near the CRC.
	                uint64_t proven_blk =
	                    (gsvt + 1 + (uint64_t)scalpel_state.blocksize - 1)
	                    / (uint64_t)scalpel_state.blocksize;
	                if (proven_blk > suffix_start_nb) {
	                  if (proven_blk < blockvector_get_num_blocks(candidate->b)) {
	                    resize_blockvector(candidate->b, proven_blk);
	                  }
	                  suffix_found = true;
	                  solver_advanced_last_pass = true;
	                  continue;
	                }
	              }
	            }
	            // Gallop didn't advance CRC — trim back to suffix start.
	            resize_blockvector(candidate->b, suffix_start_nb);
	          }
	        }

        if (!suffix_found && baseline_available
            && local && local->gap_fast_exhausted
            && fill_needed >= PNG_GAP_INDEX_MAX_M
            && crc_pos > 0 && idat_sz > 0) {
          PNGCrcHashTable *pre_bbk_ht =
              png_ensure_crc_table(candidate->needleidx);
          int pre_bbk_rc = png_bbk_current_idat_subrun_solve(candidate,
              pre_bbk_ht, suffix_start_nb, fill_needed, last_block,
              crc_pos, idat_sz);
          if (pre_bbk_rc < 0) {
            continue;
          }
          if (pre_bbk_rc > 0) {
            local->last_chunk_crc_pos =
                crc_pos + 8 + (uint64_t)idat_sz + 4;
            suffix_found = true;
            solver_advanced_last_pass = true;
            continue;
          }
        }

        // Step 2: Gallop failed — fragmentation boundary is HERE.
        // Invoke the CRC solver for the NEXT SINGLE IDAT.
        int solver_result = png_crc_solve_idat(candidate, local,
            suffix_start_nb, fill_needed, last_block, total_apparent,
            crc_pos, idat_sz, work, uuidp, uuidc);
        if (solver_result == -1) {
          state_published = true;
          if (png_reassembly_checkpoint_candidate(work->id,
                  local_carvehashkey, local, candidate, uuidp, uuidc)) {
            goto done_do_not_write_candidate;
          }
          state_published = false;
          goto png_reassembly_restart;
        }
        suffix_found = (solver_result > 0);
        if (suffix_found) {
          solver_advanced_last_pass = true;
          // Solver succeeded.  Force CRC advance for this IDAT
          // (solver verified algebraically; validator's D4 state
          // may be stale from wrong blocks earlier in BV).
          if (local->last_chunk_crc_pos <= crc_pos) {
            local->last_chunk_crc_pos = crc_pos + 8 + (uint64_t)idat_sz + 4;
          }

          // GALLOP: extend BV with capped contiguous blocks from the
          // solver's last placement, then run pngcheck once.  This
          // verifies every IDAT in the contiguous stretch without
          // the solver.  The solver only fires at gap boundaries.
          {
            uint64_t cur_nb = blockvector_get_num_blocks(candidate->b);
            int64_t last_ab = blockvector_get_apparent_blocknumber(
                candidate->b, cur_nb - 1);
            int64_t max_ab = (int64_t)filemirror_apparent_blocks(
                scalpel_state.filemirror);
            // Extend with contiguous blocks (capped)
            uint64_t ext_cap = (idat_sz > 0)
                ? (uint64_t)((idat_sz + 12) / scalpel_state.blocksize + 1)
                : scalpel_state.gallop_factor;
            if (ext_cap < scalpel_state.gallop_factor)
              ext_cap = scalpel_state.gallop_factor;
            if (ext_cap > scalpel_state.gallop_limit)
              ext_cap = scalpel_state.gallop_limit;
            uint64_t ext_start_nb = cur_nb;
            int64_t ext_ab = last_ab + 1;
            while (ext_ab < max_ab
                   && cur_nb < ext_start_nb + ext_cap
                   && ! filemirror_actual_block_covered(
                       scalpel_state.filemirror,
                       filemirror_actual_blocknumber(
                           scalpel_state.filemirror, ext_ab))) {
              resize_blockvector(candidate->b, cur_nb + 1);
              blockvector_set_apparent_blocknumber(candidate->b,
                  cur_nb, ext_ab);
              inflate_blockvector_single_block(candidate->b, cur_nb);
              cur_nb++;
              ext_ab++;
            }
            // Run pngcheck on the extended BV — verifies all
            // contiguous IDATs in one pass.
            bool _gsv; uint64_t _gsvt;
            _gsv = png_direct_validate(work->id, candidate,
                &_gsvt, local, uuidp, uuidc);
            if (_gsv) {
              goto done_write_candidate;
            }
            // pngcheck advanced last_chunk_crc_pos through verified
            // IDATs.  Solver's blocks are now CRC-proven.
            solver_advanced_last_pass = false;
            if (local->last_idat_crc_pos > 0) {
              uint64_t trim_blk = (local->last_idat_crc_pos
                  + (uint64_t)scalpel_state.blocksize - 1)
                  / (uint64_t)scalpel_state.blocksize;
              if (trim_blk < blockvector_get_num_blocks(candidate->b)) {
                resize_blockvector(candidate->b, trim_blk);
              }
            }
          }
          // Continue loop — gallop extends contiguous, solver
          // fires only at next gap.
          continue;
        }
        // ---- BBK fallback: block-by-block with CRC verification ----
        // The algebraic solver failed (M>3 or no match found).
        // Identify which fill positions have fill data (not in the CRC
        // hash table) and try candidates ONLY at those positions.
        // Correct contiguous blocks are kept, reducing the problem to
        // the actual displaced count (typically 1-3 even when fill_needed=12).
        if (!suffix_found && crc_pos > 0 && idat_sz > 0) {
          PNGCrcHashTable *bbk_ht = png_ensure_crc_table(candidate->needleidx);
          if (bbk_ht && bbk_ht->total_entries > 0
              && baseline_available) {
            // Place contiguous fill first (baseline).
            png_solver_resize_trial(candidate, suffix_start_nb + fill_needed);
            for (uint32_t f = 0; f < fill_needed; f++) {
              int64_t ab = last_block + 1 + (int64_t)f;
              blockvector_set_apparent_blocknumber(candidate->b,
                  suffix_start_nb + f, ab);
              inflate_blockvector_single_block(candidate->b,
                  suffix_start_nb + f);
            }

            // Identify fill positions: blocks that need replacement.
            // A position is fill if the block is:
            //   (a) not in the CRC hash table (zero/random fill), OR
            //   (b) covered by another validated file (wrong PNG block).
            uint32_t *fill_pos = (uint32_t *)malloc(
                fill_needed * sizeof(uint32_t));
            uint32_t n_fill = 0;
            for (uint32_t f = 0; fill_pos && f < fill_needed; f++) {
              int64_t ab = last_block + 1 + (int64_t)f;
              int64_t act = filemirror_actual_blocknumber(
                  scalpel_state.filemirror, ab);
              bool is_fill = false;
              if (act < 0) {
                is_fill = true;
              } else if (filemirror_actual_block_is_zero(
                             scalpel_state.filemirror, act)) {
                /*
                 * Fragmentator commonly fills missing PNG positions with zero
                 * blocks.  Those blocks are valid image blocks, uncovered, and
                 * present in the CRC table, so the old classifier silently
                 * treated them as ordinary data and missed the real fill slots.
                 * A literal zero block inside compressed IDAT data is an
                 * extraordinarily strong wrong-block signal, so treat it as
                 * fill here.
                 */
                is_fill = true;
              } else if (filemirror_actual_block_covered(
                             scalpel_state.filemirror, act)) {
                // Block belongs to another validated file — wrong data
                is_fill = true;
              } else {
                // Check if this actual block is in the CRC hash table
                bool ok;
                uint32_t bcrc = png_get_block_crc(ab, candidate->needleidx, &ok);
                bool in_table = false;
                if (ok) {
                  PNGCrcEntry *e = png_crc_table_find(bbk_ht, bcrc);
                  while (e) {
                    if (e->actual_block == act) { in_table = true; break; }
                    e = png_crc_table_next(e, bcrc);
                  }
                }
                if (!in_table) { is_fill = true; }
              }
              if (is_fill) {
                fill_pos[n_fill++] = f;
              }
            }
            if (scalpel_state.mode_verbose) {
              lock_fprintf(stdout, "PNG BBK: fill_needed=%u fill_positions=%u\n",
                  fill_needed, n_fill);
            }

            // CRC geometry for this IDAT.
            uint64_t bbk_type_start = crc_pos + 4;
            uint64_t bbk_crc_len = 4 + (uint64_t)idat_sz;
            uint64_t bbk_crc_field = bbk_type_start + bbk_crc_len;

            // Read stored CRC from the suffix candidate (independent source).
            // Find the suffix block — it's the fill block containing bbk_crc_field.
            uint32_t suffix_pos = fill_needed - 1;
            uint64_t suffix_blk_start = (suffix_start_nb + suffix_pos)
                * (uint64_t)scalpel_state.blocksize;
            bool bbk_have_stored = false;
            int64_t suffix_trial_ab[PNG_BBK_SUFFIX_TRY_LIMIT];
            uint32_t suffix_trial_crc[PNG_BBK_SUFFIX_TRY_LIMIT];
            bool suffix_trial_fixed[PNG_BBK_SUFFIX_TRY_LIMIT];
            uint32_t suffix_trial_count = 0;
            for (uint32_t sti = 0; sti < PNG_BBK_SUFFIX_TRY_LIMIT; sti++) {
              suffix_trial_ab[sti] = -1;
              suffix_trial_crc[sti] = 0;
              suffix_trial_fixed[sti] = false;
            }
            if (bbk_crc_field >= suffix_blk_start
                && bbk_crc_field + 4 <= suffix_blk_start
                    + scalpel_state.blocksize) {
              // CRC field is in the suffix block. Need to read from
              // candidate blocks, not contiguous fill. Use suffix precomp
              // approach: find blocks with IDAT/IEND at the right offset.
              uint64_t crc_off = bbk_crc_field - suffix_blk_start;
              uint64_t struct_off = crc_off + 4;
              uint32_t marker_off = (uint32_t)(struct_off + 4);
              int64_t cur_suffix_ab = blockvector_get_apparent_blocknumber(
                  candidate->b, suffix_start_nb + suffix_pos);
              int64_t cur_suffix_actual = filemirror_actual_blocknumber(
                  scalpel_state.filemirror, cur_suffix_ab);
              if (cur_suffix_ab >= 0
                  && cur_suffix_actual >= 0
                  && !filemirror_actual_block_covered(
                         scalpel_state.filemirror, cur_suffix_actual)
                  && png_block_has_idat_at(cur_suffix_ab,
                         marker_off, candidate->needleidx)) {
                unsigned char crc_buf[4];
                if (get_apparent_block_bytes(scalpel_state.filemirror,
                        cur_suffix_ab, crc_off, 4, crc_buf)) {
                  uint32_t cur_stored_crc = ((uint32_t)crc_buf[0] << 24)
                      | ((uint32_t)crc_buf[1] << 16)
                      | ((uint32_t)crc_buf[2] << 8)
                      | (uint32_t)crc_buf[3];
                  png_bbk_append_suffix_trial(
                      suffix_trial_ab, suffix_trial_crc,
                      suffix_trial_fixed, &suffix_trial_count,
                      cur_suffix_ab, cur_stored_crc, true);
                }
              }
              for (uint32_t bk = 0; bk < PNG_CRC_HASH_BUCKETS; bk++) {
                for (PNGCrcEntry *e = bbk_ht->buckets[bk]; e; e = e->next) {
                  if (suffix_trial_count >= PNG_BBK_SUFFIX_TRY_LIMIT) {
                    break;
                  }
                  if (filemirror_actual_block_covered(
                          scalpel_state.filemirror, e->actual_block)) {
                    continue;
                  }
                  // Check structural marker at expected position.
                  bool has_marker = false;
                  for (uint8_t mi = 0; mi < e->num_idat_markers; mi++) {
                    if (e->idat_offsets[mi] == marker_off) {
                      has_marker = true; break;
                    }
                  }
                  if (!has_marker && e->has_iend
                      && e->iend_offset == marker_off) {
                    has_marker = true;
                  }
                  if (!has_marker) { continue; }

                  // Read stored CRC from this candidate via mmap.
                  int64_t sc_ab = filemirror_apparent_blocknumber(
                      scalpel_state.filemirror, e->actual_block);
                  if (sc_ab < 0) { continue; }
                  unsigned char crc_buf[4];
                  if (get_apparent_block_bytes(scalpel_state.filemirror,
                          sc_ab, crc_off, 4, crc_buf)) {
                    uint32_t trial_crc = ((uint32_t)crc_buf[0] << 24)
                        | ((uint32_t)crc_buf[1] << 16)
                        | ((uint32_t)crc_buf[2] << 8)
                        | (uint32_t)crc_buf[3];
                    png_bbk_append_suffix_trial(
                        suffix_trial_ab, suffix_trial_crc,
                        suffix_trial_fixed, &suffix_trial_count,
                        sc_ab, trial_crc, true);
                  }
                }
                if (suffix_trial_count >= PNG_BBK_SUFFIX_TRY_LIMIT) {
                  break;
                }
              }
            }
            else {
              // CRC field should be in the prefix (already in BV).
              // But verify it's not in a fill block (unverified data).
              bool crc_in_fill = false;
              uint64_t bs_sz = (uint64_t)scalpel_state.blocksize;
              for (uint32_t fi = 0; fi < n_fill && !crc_in_fill; fi++) {
                uint64_t fb_start = (suffix_start_nb + fill_pos[fi]) * bs_sz;
                if (bbk_crc_field >= fb_start
                    && bbk_crc_field < fb_start + bs_sz) {
                  crc_in_fill = true;
                }
              }
              if (!crc_in_fill) {
                const char *bd = blockvector_get_data_pointer(candidate->b);
                uint64_t bdl = blockvector_get_data_length(candidate->b);
                if (bd && bbk_crc_field + 4 <= bdl) {
                  const unsigned char *ep =
                      (const unsigned char *)(bd + bbk_crc_field);
                  uint32_t bbk_stored_crc = ((uint32_t)ep[0] << 24)
                      | ((uint32_t)ep[1] << 16)
                      | ((uint32_t)ep[2] << 8) | (uint32_t)ep[3];
                  int64_t cur_suffix_ab = blockvector_get_apparent_blocknumber(
                      candidate->b, suffix_start_nb + suffix_pos);
                  png_bbk_append_suffix_trial(
                      suffix_trial_ab, suffix_trial_crc,
                      suffix_trial_fixed, &suffix_trial_count,
                      cur_suffix_ab, bbk_stored_crc, false);
                }
              }
            }
            bbk_have_stored = suffix_trial_count > 0;

            if (bbk_have_stored) {
              uint64_t idat_start = bbk_type_start;
              uint64_t idat_end = bbk_type_start + bbk_crc_len;
              uint32_t *retry_fill_pos = NULL;
              if (n_fill < fill_needed) {
                retry_fill_pos = (uint32_t *)malloc(
                    fill_needed * sizeof(uint32_t));
              }
              for (uint32_t sti = 0;
                   sti < suffix_trial_count && !suffix_found;
                   sti++) {
                uint32_t bbk_stored_crc = suffix_trial_crc[sti];
                bool bbk_suffix_fixed = suffix_trial_fixed[sti];
                int64_t bbk_suffix_ab = suffix_trial_ab[sti];
                png_bbk_restore_contiguous_window(candidate,
                    suffix_start_nb, fill_needed, last_block);
                if (bbk_suffix_fixed && bbk_suffix_ab >= 0) {
                  blockvector_set_apparent_blocknumber(candidate->b,
                      suffix_start_nb + suffix_pos, bbk_suffix_ab);
                  inflate_blockvector_single_block(candidate->b,
                      suffix_start_nb + suffix_pos);
                }
                if (scalpel_state.mode_verbose && suffix_trial_count > 1
                    && bbk_suffix_fixed) {
                  lock_fprintf(stdout,
                      "PNG BBK: trying suffix trial %u/%u ab=%" PRId64 "\n",
                      sti + 1, suffix_trial_count, bbk_suffix_ab);
                }

                uint32_t *solve_fill_pos = fill_pos;
                uint32_t solve_n_fill = n_fill;
                uint32_t *solve_fill_tmp = NULL;
                if (bbk_suffix_fixed && n_fill > 0) {
                  solve_fill_tmp = (uint32_t *)malloc(
                      n_fill * sizeof(uint32_t));
                  if (solve_fill_tmp) {
                    solve_n_fill = png_bbk_copy_fill_positions_excluding(
                        solve_fill_tmp, fill_pos, n_fill, true, suffix_pos);
                    solve_fill_pos = solve_fill_tmp;
                  }
                }

                int solve_rc = png_bbk_run_solve(candidate, local, bbk_ht,
                    suffix_start_nb, solve_fill_pos, solve_n_fill, last_block,
                    idat_start, idat_end, bbk_crc_len, bbk_stored_crc, false);
                if (solve_rc < 0) {
                  png_bbk_restore_contiguous_window(candidate,
                      suffix_start_nb, fill_needed, last_block);
                  resize_blockvector(candidate->b, suffix_start_nb);
                  free(solve_fill_tmp);
                  free(retry_fill_pos);
                  free(fill_pos);
                  state_published = true;
                  if (png_reassembly_checkpoint_candidate(work->id,
                          local_carvehashkey, local, candidate,
                          uuidp, uuidc)) {
                    goto done_do_not_write_candidate;
                  }
                  state_published = false;
                  goto png_reassembly_restart;
                }
                if (solve_rc > 0) {
                  if (scalpel_state.mode_verbose) {
                    lock_fprintf(stdout,
                        "%sPNG BBK: IDAT solved! crc_pos=%" PRIu64
                        " fill=%u n_fill=%u%s\n",
                        GREEN, crc_pos, fill_needed, solve_n_fill, BLACK);
                  }
                  local->last_chunk_crc_pos =
                      crc_pos + 8 + (uint64_t)idat_sz + 4;
                  suffix_found = true;
                  solver_advanced_last_pass = true;
                  free(solve_fill_tmp);
                  break;
                }
                free(solve_fill_tmp);

                if (!suffix_found && retry_fill_pos && n_fill < fill_needed) {
                  int subrun_rc = png_bbk_contiguous_subrun_solve(candidate,
                      bbk_ht, suffix_start_nb, fill_needed, suffix_pos,
                      bbk_suffix_fixed, last_block, idat_start, idat_end,
                      bbk_crc_len, bbk_stored_crc);
                  if (subrun_rc < 0) {
                    png_bbk_restore_contiguous_window(candidate,
                        suffix_start_nb, fill_needed, last_block);
                    resize_blockvector(candidate->b, suffix_start_nb);
                    free(retry_fill_pos);
                    free(fill_pos);
                    state_published = true;
                    if (png_reassembly_checkpoint_candidate(work->id,
                            local_carvehashkey, local, candidate,
                            uuidp, uuidc)) {
                      goto done_do_not_write_candidate;
                    }
                    state_published = false;
                    goto png_reassembly_restart;
                  }
                  if (subrun_rc > 0) {
                    local->last_chunk_crc_pos =
                        crc_pos + 8 + (uint64_t)idat_sz + 4;
                    suffix_found = true;
                    solver_advanced_last_pass = true;
                    if (scalpel_state.mode_verbose) {
                      lock_fprintf(stdout,
                          "%sPNG BBK SUBRUN: SOLVED fill=%u%s\n",
                          GREEN, fill_needed, BLACK);
                    }
                  }
                }

                if (!suffix_found && retry_fill_pos && n_fill < fill_needed) {
                  uint32_t retry_n_fill = 0;
                  png_bbk_restore_contiguous_window(candidate,
                      suffix_start_nb, fill_needed, last_block);
                  for (uint32_t f = 0; f < fill_needed; f++) {
                    if (bbk_suffix_fixed && f == suffix_pos) {
                      continue;
                    }
                    retry_fill_pos[retry_n_fill++] = f;
                  }
                  if (bbk_suffix_fixed && bbk_suffix_ab >= 0) {
                    blockvector_set_apparent_blocknumber(candidate->b,
                        suffix_start_nb + suffix_pos, bbk_suffix_ab);
                    inflate_blockvector_single_block(candidate->b,
                        suffix_start_nb + suffix_pos);
                  }
                  if (scalpel_state.mode_verbose) {
                    lock_fprintf(stdout,
                        "PNG BBK: retry with ALL %u positions as fill\n",
                        retry_n_fill);
                  }
                  int retry_rc = png_bbk_run_solve(candidate, local, bbk_ht,
                      suffix_start_nb, retry_fill_pos, retry_n_fill,
                      last_block, idat_start, idat_end, bbk_crc_len,
                      bbk_stored_crc, true);
                  if (retry_rc < 0) {
                    png_bbk_restore_contiguous_window(candidate,
                        suffix_start_nb, fill_needed, last_block);
                    resize_blockvector(candidate->b, suffix_start_nb);
                    free(retry_fill_pos);
                    free(fill_pos);
                    state_published = true;
                    if (png_reassembly_checkpoint_candidate(work->id,
                            local_carvehashkey, local, candidate,
                            uuidp, uuidc)) {
                      goto done_do_not_write_candidate;
                    }
                    state_published = false;
                    goto png_reassembly_restart;
                  }
                  if (retry_rc > 0) {
                    local->last_chunk_crc_pos =
                        crc_pos + 8 + (uint64_t)idat_sz + 4;
                    suffix_found = true;
                    solver_advanced_last_pass = true;
                    if (scalpel_state.mode_verbose) {
                      lock_fprintf(stdout,
                          "%sPNG BBK RETRY: SOLVED fill=%u%s\n",
                          GREEN, fill_needed, BLACK);
                    }
                  }
                }
              }
              free(retry_fill_pos);
            }

            // Same-range pair-swap repair was removed: fragmentator
            // OUTOFORDER displaces blocks rather than swapping in place.

            if (!suffix_found) {
              // BBK failed — restore all contiguous.
              for (uint32_t f = 0; f < fill_needed; f++) {
                int64_t ab = last_block + 1 + (int64_t)f;
                blockvector_set_apparent_blocknumber(candidate->b,
                    suffix_start_nb + f, ab);
                inflate_blockvector_single_block(candidate->b,
                    suffix_start_nb + f);
              }
              resize_blockvector(candidate->b, suffix_start_nb);
            }
            free(fill_pos);
          }
        }

        if (suffix_found) { continue; }

        // Solver failed — try contiguous fill past the stuck IDAT, but
        // ONLY accept if the stuck IDAT's CRC actually passes.  The
        // previous logic accepted ANY CRC advance (which could be from
        // a later chunk), producing Category 5 files at large N.
        {
          int64_t skip_ab = last_block + 1 + (int64_t)fill_needed;
          int64_t max_ab = (int64_t)filemirror_apparent_blocks(
              scalpel_state.filemirror);
          if (skip_ab < max_ab && skip_ab > 0) {
            uint64_t skip_nb = suffix_start_nb;
            for (int64_t ab = last_block + 1; ab < skip_ab && ab < max_ab; ab++) {
              resize_blockvector(candidate->b, skip_nb + 1);
              blockvector_set_apparent_blocknumber(candidate->b, skip_nb, ab);
              inflate_blockvector_single_block(candidate->b, skip_nb);
              skip_nb++;
            }
            uint64_t skip_cap = (idat_sz > 0)
                ? (uint64_t)((idat_sz + 12) / scalpel_state.blocksize + 1)
                : scalpel_state.gallop_factor;
            if (skip_cap < scalpel_state.gallop_factor)
              skip_cap = scalpel_state.gallop_factor;
            if (skip_cap > scalpel_state.gallop_limit)
              skip_cap = scalpel_state.gallop_limit;
            while (skip_ab < max_ab && skip_nb < suffix_start_nb + skip_cap
                   && !filemirror_actual_block_covered(
                       scalpel_state.filemirror,
                       filemirror_actual_blocknumber(
                           scalpel_state.filemirror, skip_ab))) {
              resize_blockvector(candidate->b, skip_nb + 1);
              blockvector_set_apparent_blocknumber(candidate->b, skip_nb, skip_ab);
              inflate_blockvector_single_block(candidate->b, skip_nb);
              skip_nb++;
              skip_ab++;
            }
            if (skip_nb > suffix_start_nb) {
              // Verify: the stuck IDAT's CRC must PASS.  Don't accept
              // based on any-CRC-advance — that lets wrong blocks through.
              // CRC region: type(4) at crc_pos+4, body(idat_sz), stored CRC(4).
              const char *sd = blockvector_get_data_pointer(candidate->b);
              uint64_t sdl = blockvector_get_data_length(candidate->b);
              bool skip_crc_ok = false;
              uint64_t sk_type = crc_pos + 4;
              uint64_t sk_crc_len = 4 + (uint64_t)idat_sz;
              uint64_t sk_crc_field = sk_type + sk_crc_len;
              if (sd && idat_sz > 0 && sk_crc_field + 4 <= sdl) {
                uint32_t sc_crc = crc32(0, NULL, 0);
                sc_crc = crc32(sc_crc,
                    (const unsigned char *)(sd + sk_type),
                    (uInt)sk_crc_len);
                const unsigned char *sc_ep =
                    (const unsigned char *)(sd + sk_crc_field);
                uint32_t sc_stored = ((uint32_t)sc_ep[0] << 24)
                    | ((uint32_t)sc_ep[1] << 16)
                    | ((uint32_t)sc_ep[2] << 8) | (uint32_t)sc_ep[3];
                skip_crc_ok = (sc_crc == sc_stored);
              }
              if (skip_crc_ok) {
                bool ssv; uint64_t ssvt;
                ssv = png_direct_validate(work->id, candidate,
                    &ssvt, local, uuidp, uuidc);
                if (ssv) {
                  goto done_write_candidate;
                }
                if (local->last_idat_crc_pos > 0) {
                  uint64_t trim_blk = (local->last_idat_crc_pos
                      + (uint64_t)scalpel_state.blocksize - 1)
                      / (uint64_t)scalpel_state.blocksize;
                  if (trim_blk < blockvector_get_num_blocks(candidate->b)) {
                    resize_blockvector(candidate->b, trim_blk);
                  }
                }
                suffix_found = true;
                continue;
              }
              // CRC didn't pass — trim back, don't keep wrong blocks.
              resize_blockvector(candidate->b, suffix_start_nb);
            }
          }
        }
      }
      else {
        // PRE-CRC: contiguous fill with structural validation.
        // Try blocks sequentially from last_block+1.  The embedded
        // pngcheck validator catches bad blocks (wrong filter bytes,
        // inflate errors, chunk boundary violations).  Accept on
        // CRC advance or validates_to progress.
        if (baseline_available) {
          png_solver_resize_trial(candidate, suffix_start_nb + fill_needed);
          for (uint32_t f = 0; f < fill_needed; f++) {
            int64_t ab = last_block + 1 + (int64_t)f;
            if (!IDAT_FILTER_CHECK(last_block + 1)) {
              break;
            }
            blockvector_set_apparent_blocknumber(candidate->b,
                suffix_start_nb + f, ab);
            inflate_blockvector_single_block(candidate->b,
                suffix_start_nb + f);
          }
          uint64_t crc_before = local->last_chunk_crc_pos;
          bool sv;
          uint64_t svt;
          sv = png_direct_validate(work->id, candidate,
              &svt, local, uuidp, uuidc);
          uint64_t crc_after = local->last_chunk_crc_pos;
          if (png_trace_suffix) {
            lock_fprintf(stdout,
                "PNG_TRACE_PRECRC event=%d snb=%" PRIu64
                " fill=%u accept_vt=%d sv=%d svt=%" PRIu64
                " suffix_dl=%" PRIu64 " first_crc=%" PRIu64
                " crc_before=%" PRIu64 " crc_after=%" PRIu64 "\n",
                png_trace_event, suffix_start_nb, fill_needed,
                accept_on_validates_to ? 1 : 0, sv ? 1 : 0, svt,
                suffix_start_dl, first_idat_crc_pos, crc_before,
                crc_after);
          }
          if (sv) {
            goto done_write_candidate;
          }
          if (crc_after > crc_before) {
            // CRC advanced — contiguous fill is working
            suffix_found = true;
            continue;
          }
          if (accept_on_validates_to
              && svt >= suffix_start_dl + scalpel_state.blocksize - 1
              && svt < first_idat_crc_pos) {
            // Pre-CRC structural validation proved up to svt.
            // Trim BV to only the PROVEN portion — don't keep trailing
            // unproven blocks (they may be fill data that generates Cat6).
            {
              uint64_t proven_blk = (svt + 1 + (uint64_t)scalpel_state.blocksize - 1)
                  / (uint64_t)scalpel_state.blocksize;
              if (proven_blk < blockvector_get_num_blocks(candidate->b)) {
                resize_blockvector(candidate->b, proven_blk);
              }
            }
            suffix_found = true;
            continue;
          }
          if (accept_on_idat_milestone) {
            uint64_t trial_body_start = 0;
            uint32_t trial_body_size = 0;
            uint64_t trial_crc_pos = 0;
            if (png_parse_first_idat(candidate, &trial_body_start,
                    &trial_body_size, &trial_crc_pos)
                && (trial_body_start > suffix_start_dl
                    || trial_crc_pos > suffix_start_dl)) {
              uint64_t milestone_blk = (trial_body_start
                  + (uint64_t)scalpel_state.blocksize - 1)
                  / (uint64_t)scalpel_state.blocksize;
              if (milestone_blk < 1) { milestone_blk = 1; }
              if (png_trace_suffix) {
                lock_fprintf(stdout,
                    "PNG_TRACE_MILESTONE event=%d snb=%" PRIu64
                    " old_dl=%" PRIu64 " trial_body=%" PRIu64
                    " trial_size=%u trial_crc=%" PRIu64
                    " milestone=%" PRIu64 " cur_nb=%" PRIu64 "\n",
                    png_trace_event, suffix_start_nb, suffix_start_dl,
                    trial_body_start, trial_body_size, trial_crc_pos,
                    milestone_blk, blockvector_get_num_blocks(candidate->b));
              }
              if (milestone_blk < blockvector_get_num_blocks(candidate->b)) {
                resize_blockvector(candidate->b, milestone_blk);
              }
              suffix_found = true;
              continue;
            }
          }
          // Contiguous fill didn't work — trim back
          resize_blockvector(candidate->b, suffix_start_nb);
        }

        // Contiguous fill failed.  If we have first IDAT info and the
        // CRC boundary is in the suffix, invoke the CRC solver.
        if (! suffix_found && have_first_idat
            && first_idat_crc_pos + 4 > suffix_start_dl
            && first_idat_body_size > 0
            && first_idat_body_start >= 8) {
          uint64_t fi_chunk_start = first_idat_body_start - 8;
          int solver_result = png_crc_solve_idat(candidate, local,
              suffix_start_nb, fill_needed, last_block, total_apparent,
              fi_chunk_start, (long)first_idat_body_size,
              work, uuidp, uuidc);
          if (solver_result == -1) {
            state_published = true;
            if (png_reassembly_checkpoint_candidate(work->id,
                    local_carvehashkey, local, candidate, uuidp, uuidc)) {
              goto done_do_not_write_candidate;
            }
            state_published = false;
            goto png_reassembly_restart;
          }
          if (solver_result > 0) {
            bool sv2; uint64_t svt2;
            sv2 = png_direct_validate(work->id, candidate,
                &svt2, local, uuidp, uuidc);
            if (sv2) {
              goto done_write_candidate;
            }
            if (local->last_chunk_crc_pos > first_idat_crc_pos) {
              suffix_found = true;
              // After first IDAT bootstrap succeeds, gallop with
              // contiguous blocks to cover subsequent IDATs cheaply.
              {
                uint64_t cur_nb = blockvector_get_num_blocks(candidate->b);
                int64_t gal_ab = blockvector_get_apparent_blocknumber(
                    candidate->b, cur_nb - 1) + 1;
                int64_t max_ab = (int64_t)filemirror_apparent_blocks(
                    scalpel_state.filemirror);
                uint64_t fi_gal_cap = (first_idat_body_size > 0)
                    ? (uint64_t)((first_idat_body_size + 12)
                        / scalpel_state.blocksize + 1)
                    : scalpel_state.gallop_factor;
                if (fi_gal_cap < scalpel_state.gallop_factor)
                  fi_gal_cap = scalpel_state.gallop_factor;
                if (fi_gal_cap > scalpel_state.gallop_limit)
                  fi_gal_cap = scalpel_state.gallop_limit;
                uint64_t fi_gal_start_nb = cur_nb;
                while (gal_ab < max_ab
                    && cur_nb < fi_gal_start_nb + fi_gal_cap
                    && !filemirror_actual_block_covered(
                        scalpel_state.filemirror,
                        filemirror_actual_blocknumber(
                            scalpel_state.filemirror, gal_ab))) {
                  resize_blockvector(candidate->b, cur_nb + 1);
                  blockvector_set_apparent_blocknumber(candidate->b,
                      cur_nb, gal_ab);
                  inflate_blockvector_single_block(candidate->b, cur_nb);
                  cur_nb++;
                  gal_ab++;
                }
                bool _gsv2; uint64_t _gsvt2;
                _gsv2 = png_direct_validate(work->id, candidate,
                    &_gsvt2, local, uuidp, uuidc);
                if (_gsv2) {
                  goto done_write_candidate;
                }
                if (local->last_idat_crc_pos > 0) {
                  uint64_t trim_blk = (local->last_idat_crc_pos
                      + (uint64_t)scalpel_state.blocksize - 1)
                      / (uint64_t)scalpel_state.blocksize;
                  if (trim_blk < blockvector_get_num_blocks(candidate->b)) {
                    resize_blockvector(candidate->b, trim_blk);
                  }
                }
              }
              continue;
            }
            // CRC didn't advance (D4 state mismatch) — update manually.
            // Safe: the solver already proved this IDAT correct via
            // algebraic CRC verification (solver_result > 0).
            local->last_chunk_crc_pos = first_idat_crc_pos + 4;
            suffix_found = true;
            continue;
          }

          // Same-range pair-swap repair was removed for the same reason as
          // the post-CRC path: the active solver handles displaced blocks.

          if (suffix_found) { continue; }
          // Solver failed — restore BV.
          resize_blockvector(candidate->b, suffix_start_nb);
        }
      }

      // -------------------------------------------------------------------
      // All suffix strategies exhausted for this pass.
      // Trim stale blocks once, then write what we have.
      // on the retry pass.
      // -------------------------------------------------------------------
      if (!trimmed_stale_blocks || trimmed_at_suffix_nb != suffix_start_nb) {
        trimmed_stale_blocks = true;
        trimmed_at_suffix_nb = suffix_start_nb;
        resize_blockvector(candidate->b, suffix_start_nb);
        uint64_t trim_nb = suffix_start_nb;

        if (trim_nb > 1) {
          validates = png_direct_validate(work->id, candidate,
              &validates_to, local, uuidp, uuidc);
          uint64_t dl = blockvector_get_data_length(candidate->b);

          if (!validates &&
              validates_to + (uint64_t)scalpel_state.blocksize < dl) {
            uint64_t valid_blocks =
                (validates_to + 1) / scalpel_state.blocksize;
            if (valid_blocks < 1) valid_blocks = 1;

            /* Never trim below the CRC-verified prefix.  Covered blocks
             * from work sharing can corrupt re-inflation data, giving a
             * misleadingly low validates_to.  CRC-verified blocks are
             * proven correct (1-in-4.3-billion) and must be preserved. */
            uint64_t crc_floor_blocks = 0;
            if (local->last_chunk_crc_pos > 0) {
              crc_floor_blocks =
                  local->last_chunk_crc_pos / scalpel_state.blocksize;
              if (crc_floor_blocks < 1) {
                crc_floor_blocks = 1;
              }
            }

            if (valid_blocks < crc_floor_blocks) {
              valid_blocks = crc_floor_blocks;
            }

            if (valid_blocks < trim_nb) {
              if (scalpel_state.mode_verbose) {
                lock_fprintf(stdout,
                             "PNG SUFFIX: trimming stale blocks %" PRIu64
                             " -> %" PRIu64
                             " (validates_to=%" PRIu64
                             " data_length=%" PRIu64
                             " crc_floor=%" PRIu64 ")\n",
                             trim_nb, valid_blocks, validates_to, dl,
                             crc_floor_blocks);
              }
              resize_blockvector(candidate->b, valid_blocks);
              inflate_blockvector(candidate->b);
              /* Only reset CRC state if we trimmed below ALL CRC data.
               * If crc_floor_blocks > 0 and we kept that many blocks,
               * the CRC state is still valid — do NOT reset it. */
              if (valid_blocks < crc_floor_blocks || crc_floor_blocks == 0) {
                local->last_chunk_crc_pos = 0;
                local->last_idat_crc_pos = 0;
                local->prev_idat_crc_pos = 0;
                memset(local->idat_crc_ring, 0, sizeof(local->idat_crc_ring));
                local->idat_crc_ring_count = 0;
                local->idat_data_sz = 0;
                local->n_crc_ckpts = 0;
              }
              continue;  // retry with trimmed BV
            }
          }
        }
      }

      /* A validation call during this pass can discover the next IDAT
       * length after we already computed idat_sz == 0 above.  Do not
       * cement a partial at the CRC boundary in that case; restart the
       * suffix pass so the CRC solver gets the now-known target geometry. */
      if (crc_pos > 0 && idat_sz <= 0
          && local->last_chunk_crc_pos == crc_pos
          && local->idat_data_sz > 0
          && local->idat_data_start == crc_pos + 8) {
        continue;
      }

      if (local->last_chunk_crc_pos > entry_last_chunk_crc_pos) {
        if (scalpel_state.mode_verbose) {
          lock_fprintf(stdout,
                       "PNG SUFFIX: CRC frontier advanced %" PRIu64
                       " -> %" PRIu64
                       "; continuing from improved prefix\n",
                       entry_last_chunk_crc_pos,
                       local->last_chunk_crc_pos);
        }
        if (!png_preserve_crc_frontier_in_candidate(local, candidate)) {
          resize_blockvector(candidate->b, suffix_start_nb);
          blockvector_set_data_length(candidate->b, suffix_start_dl);
        }
        entry_last_chunk_crc_pos = local->last_chunk_crc_pos;
        continue;
      }

      if (local->last_chunk_crc_pos > 0) {
        if (scalpel_state.mode_verbose) {
          lock_fprintf(stdout,
                       "PNG SUFFIX: exhausted at %" PRIu64
                       " blocks CRC=%" PRIu64 " — writing partial\n",
                       suffix_start_nb, local->last_chunk_crc_pos);
        }
        if (!png_preserve_crc_frontier_in_candidate(local, candidate)) {
          resize_blockvector(candidate->b, suffix_start_nb);
          blockvector_set_data_length(candidate->b, suffix_start_dl);
        }
        goto done_write_candidate;
      }

      // No CRC progress at all — write the prefix and finish.
      resize_blockvector(candidate->b, suffix_start_nb);
      blockvector_set_data_length(candidate->b, suffix_start_dl);

      if (scalpel_state.mode_verbose) {
        lock_fprintf(stdout,
                     "PNG SUFFIX: all strategies exhausted at %" PRIu64
                     " blocks, writing prefix\n",
                     suffix_start_nb);
      }

      goto done_write_candidate;
    }
  }

done_write_candidate:
  ;
  bool wrote_crc_frontier = false;
  if (candidate->flavor != VALIDATED && local) {
    wrote_crc_frontier = png_preserve_crc_frontier_in_candidate(
        local, candidate);
    png_trim_output_blind_idat_tail(local, candidate);
  }

  if (!wrote_crc_frontier
      && candidate->flavor != VALIDATED
      && local
      && local->safe_partial_blocks > 0
      && local->safe_partial_blocks < blockvector_get_num_blocks(candidate->b)) {
    resize_blockvector(candidate->b, local->safe_partial_blocks);
    blockvector_set_data_length(candidate->b, local->safe_partial_length);
  }
  else if (candidate->flavor != VALIDATED
      && safe_partial_blocks > 0
      && safe_partial_blocks < blockvector_get_num_blocks(candidate->b)) {
    resize_blockvector(candidate->b, safe_partial_blocks);
    blockvector_set_data_length(candidate->b, safe_partial_length);
  }

  // Final IEND trim: for VALIDATED files, run a fresh validation to get
  // the exact file length.  Skip if already trimmed (data length is not
  // a multiple of blocksize, meaning it was already trimmed by have_iend).
  if (!complete_probe_validated
      && candidate->flavor == VALIDATED
      && blockvector_get_data_length(candidate->b) % scalpel_state.blocksize == 0) {
    bool _fv = false; uint64_t _fvt = 0; bool _fp = false;
    if (png_try_complete_contiguous(blockvector_get_data_pointer(candidate->b),
                                    blockvector_get_data_length(candidate->b),
                                    &_fvt)) {
      _fv = true;
    } else {
      png_validate_core(blockvector_get_data_pointer(candidate->b),
                        blockvector_get_data_length(candidate->b),
                        &_fv, &_fvt, &_fp,
                        candidate->needleidx, scalpel_state.blocksize,
                        candidate->carvehashkey, NULL);
    }
    if (_fv && _fvt + 1 < blockvector_get_data_length(candidate->b)) {
      blockvector_set_data_length(candidate->b, _fvt + 1);
      resize_blockvector(candidate->b,
          CEILDIV(_fvt + 1, scalpel_state.blocksize));
    }
  }

  if (scalpel_state.mode_verbose) {
    lock_fprintf(stdout,
                 "\nPNG reassembly thread # %1d: DWC exit (%s) UUIDs\n%s / %s.\n",
                 work->id,
                 candidate->flavor == PROMISING  ? "PROMISING" :
                 candidate->flavor == VALIDATED ? "VALIDATED" : "INPROGRESS",
                 uuidp, uuidc);
  }
  // Don't modify the global CRC hash table — solver threads iterate
  // it concurrently.  Covered blocks are skipped via
  // filemirror_actual_block_covered() checks in the solver.
  if (local && !state_published) {
    png_publish_reassembly_state(local_carvehashkey, local, candidate);
    state_published = true;
  }
  write_candidate(c, false);
  candidate = *c;
  goto done;

done_do_not_write_candidate:
  if (scalpel_state.mode_verbose) {
    lock_fprintf(stdout,
                 "\nPNG reassembly thread # %1d: DDNWC exit UUIDs\n%s / %s.\n",
                 work->id, uuidp, uuidc);
  }

done:
  if (local) {
    if (!state_published) {
      png_publish_reassembly_state(local_carvehashkey, local, candidate);
    }
    png_free_carve_state((void **)&local);
  }
}

#endif
