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

// gif validators for scalpel3 (c) 2021-2026 by Golden G. Richard III.
//
// These are based in part on giffix, which is a part of giflib v5.
//
// Validation combines GIF structure, LZW decoding, sub-block alignment,
// frame and row checkpoints, pixel differences, and compressed-data
// consumption. Reassembly uses this evidence to rank candidate blocks and
// confirm displaced runs before committing them.
//
#if ! defined(SCALPEL_GIF_H)
#define SCALPEL_GIF_H
#include "scalpel.h"
#include <fcntl.h>
#include <math.h>
#include <stdlib.h>


#define GIFV_LOG(fmt, ...)
#define GIF_REASSEMBLY_VALIDATE_SLACK 16
#define GIF_REASSEMBLY_WEAK_VALIDATION_BYTES 4
#define GIF_REASSEMBLY_STRONG_WIN_BYTES 1024
#define GIF_REASSEMBLY_LOCAL_DISTANCE_MAX 16
#define GIF_REASSEMBLY_PRESTART_DISTANCE_MAX GIF_REASSEMBLY_LOCAL_DISTANCE_MAX
#define GIF_REASSEMBLY_GAP_SCAN_WINDOW GIF_REASSEMBLY_LOCAL_DISTANCE_MAX
#define GIF_REASSEMBLY_RETURN_SCAN_WINDOW 64
#define GIF_REASSEMBLY_RETURN_CONFIRM_BLOCKS 8
#define GIF_REASSEMBLY_DEEP_RETURN_CONFIRM_BLOCKS 512
#define GIF_REASSEMBLY_RETURN_REGRESSION_PROBE_BLOCKS \
  GIF_REASSEMBLY_RETURN_CONFIRM_BLOCKS
#define GIF_REASSEMBLY_RETURN_PROOF_SHIFT 16
#define GIF_REASSEMBLY_RETURN_PROOF_MASK UINT32_C(0xffff)
#define GIF_REASSEMBLY_LOOKAHEAD_LIMIT 64
#define GIF_REASSEMBLY_NONLOCAL_CHAIN_PROBE_BLOCKS 8
#define GIF_REASSEMBLY_PHASE_ANCHOR_BACKFILL \
  (GIF_REASSEMBLY_NONLOCAL_CHAIN_PROBE_BLOCKS - 1)
#define GIF_REASSEMBLY_VALID_ANCHOR_BACKFILL 2
#define GIF_REASSEMBLY_PREFIX_ANCHORS_BEFORE_BACKSCAN 512
#define GIF_REASSEMBLY_ACTUAL_BACKSCAN_WINDOW 1048576
#define GIF_REASSEMBLY_ACTUAL_BACKSCAN_ANCHOR_YIELD_DISTANCE 4096
#define GIF_REASSEMBLY_ACTUAL_BACKSCAN_ANCHOR_YIELD_MIN_BLOCKS 96
#define GIF_REASSEMBLY_ACTUAL_RUN_RESCUE_SCAN_LIMIT 128
#define GIF_REASSEMBLY_PHASE_MIN_MAX_SUBBLOCK 240
#define GIF_REASSEMBLY_PHASE_THRESHOLD_SLACK 4
#define GIF_REASSEMBLY_PHASE_MIN_HEADERS 8
#define GIF_REASSEMBLY_PHASE_MIN_PRIOR_GAPS 2
#define GIF_REASSEMBLY_PHASE_PROBE_SCAN_LIMIT 1024
#define GIF_REASSEMBLY_PHASE_PROBE_MIN_BLOCKS 2
#define GIF_REASSEMBLY_PHASE_PROBE_MIN_HEADERS 2
#define GIF_REASSEMBLY_COMPLETION_PROBE_SCAN_LIMIT 2048

static inline int64_t gif_reassembly_anchor_apparent_block(
    const CarveInfo *candidate);
static inline uint64_t gif_reassembly_anchor_block(
    const CarveInfo *candidate);

static inline int64_t gif_reassembly_anchor_apparent_block(
    const CarveInfo *candidate) {
  int64_t apparentblocknumber = -1;

  if (!candidate) {
    return -1;
  }

  if (candidate->b && blockvector_get_num_blocks(candidate->b) > 0) {
    apparentblocknumber =
        blockvector_get_apparent_blocknumber(candidate->b, 0);
    if (apparentblocknumber >= 0) {
      return apparentblocknumber;
    }
  }

  if (scalpel_state.blocksize == 0) {
    return -1;
  }

  return (int64_t)(candidate->start / scalpel_state.blocksize);
}

static inline uint64_t gif_reassembly_anchor_block(const CarveInfo *candidate) {
  int64_t apparentblocknumber = gif_reassembly_anchor_apparent_block(candidate);

  return apparentblocknumber >= 0 ? (uint64_t)apparentblocknumber : 0;
}

// filetype-specific validation functions for filetype "gif"
static inline uint32_t gif_block_validate(char *data, uint64_t length, BlockValidationDecision *decision, uint64_t *validates_to,
                                          uint32_t needleidx, uint32_t blocksize, void *blockhashkey);

static inline void gif_file_validate(char *data, uint64_t length, bool *validates, uint64_t *validates_to, bool *promising,
                                     uint32_t needleidx, uint32_t blocksize, void *carvehashkey);
static inline void gif_reassembly(ThreadWork *work, CarveInfo **c,
                                  uuid_string_t uuidp, uuid_string_t uuidc);

// serialize or deserialize carve state to a file
static inline bool gif_serialize_carve_state(void **state, FILE *fp, StateSerialization mode);

// clone gif carve state
static inline void *gif_clone_carve_state(const void *srcstate);

// free gif carve state
static inline void gif_free_carve_state(void **state);

// display a representation of gif carve state
static inline void gif_print_carve_state(const void *state);

// LZW decoder state for intra-frame checkpointing (~12KB).
// Defined here (before GIFCarveState) so it can be embedded inline.
#define GIF_LZW_MAX_CODES 4096
#define GIF_LZW_MAX_BITS  12

typedef struct GIFLZWState {
  // Code table
  uint16_t prefix[GIF_LZW_MAX_CODES];
  uint8_t  suffix[GIF_LZW_MAX_CODES];
  // Cache each code's first character for constant-time KwKwK decoding.
  // Entries are maintained incrementally as the code table grows.
  uint8_t  first_char[GIF_LZW_MAX_CODES];
  uint16_t next_code;           // next available table entry
  uint8_t  code_size;           // current bits per code (min+1 to 12)
  uint8_t  min_code_size;       // from GIF stream (LZW minimum code size byte)
  uint16_t clear_code;          // 2^min_code_size
  uint16_t eoi_code;            // clear_code + 1
  uint16_t prev_code;           // previous code (UINT16_MAX = none)

  // Bitstream state — sub-block buffer for bursty consumption.
  // When a new sub-block is needed, mem->curpos advances past the entire
  // sub-block at once (matching libgif's GIFMemRead chunk pattern).
  // Subsequent byte reads come from this buffer without advancing curpos.
  uint32_t bit_buf;             // accumulated bits (up to 24 bits buffered)
  uint8_t  bits_in_buf;         // number of valid bits in bit_buf
  uint8_t  sb_buf[256];         // buffered sub-block data (max 255 bytes)
  uint8_t  sb_buf_len;          // total bytes in buffer
  uint8_t  sb_buf_pos;          // next byte to read from buffer
  bool     sb_truncated;        // candidate ended inside this sub-block

  // Output stack for decoding multi-pixel codes
  uint8_t  out_stack[GIF_LZW_MAX_CODES];
  uint16_t out_stack_top;       // number of pixels in out_stack

  // Pixel output state for row-at-a-time decoding
  bool     eof_reached;         // true after stream stop
  bool     saw_eoi;             // true only after a real EOI code
} GIFLZWState;

// Bound on the previous-scanline pixels stored inside a resume snapshot so the
// carve state stays fixed-size. MAD-active snapshots after the first row are
// retained only when the preceding row fits in this buffer.
#define GIF_SNAP_PREV_ROW_MAX 4096

// Ring of pending resume snapshots collected during one validation call, one
// per block boundary crossed by the row decoder. Captured BEFORE a row
// decodes, so each entry is exactly resumable at its row. done: persists the
// newest entry at or below the block-aligned checkpoint position.
#define GIF_SNAP_RING 4
typedef struct GIFSnapPending {
  bool     valid;
  bool     mad_active;
  bool     prev_row_present;
  uint32_t next_row;
  uint32_t frame_index;
  uint64_t pos;
  uint64_t record_pos;
  uint64_t last_good_mad_pos;
  uint64_t last_normal_pos;
  double   running_mad_sum;
  uint32_t mad_count;
  int32_t  bad_mad_streak;
  double   running_bpr_sum;
  double   running_bpr_sq;
  uint32_t bpr_count;
  uint32_t prev_row_len;
  GIFLZWState lzw;
  uint8_t  prev_row[GIF_SNAP_PREV_ROW_MAX];
} GIFSnapPending;

// Carve state for GIF validation checkpointing. This struct is fixed-size with no pointers,
// so memcpy() suffices for cloning. On each validator call, the saved prefix is verified via
// XXH3 hash. Live replay logic uses that to skip completed frames and to fast-replay trusted
// rows inside the current frame up to checkpoint_curpos before detector-heavy validation resumes.

typedef struct GIFCarveState {
  bool valid;                       // state has been populated
  uint64_t prefix_hash;            // XXH3 of data[0..checkpoint_curpos)
  uint64_t checkpoint_curpos;      // decoder position at save time
  uint64_t data_length;            // data length at save time
  // outer-scope detection anchors
  uint64_t last_good_row_pos;      // last confirmed-good decoder position
  uint64_t pre_boundary_pos;       // position before most recent block-boundary crossing
  uint64_t last_boundary_check;    // last position checked for boundary crossing
  uint64_t sb_limit;               // sub-block structure inconsistency position
  uint64_t last_normal_pos;        // last position with normal LZW consumption
  // Layer A: RGB MAD tracking
  double running_mad_sum;
  uint32_t mad_count;
  uint32_t consecutive_good_rows;
  uint32_t bad_row_streak;
  uint64_t gate_block;
  // Layer B: LZW consumption rate tracking
  double running_bpr_sum;
  double running_bpr_sq;
  uint32_t bpr_count;
  // frame tracking
  uint32_t completed_frames;       // number of fully-processed frames before checkpoint
  uint64_t first_frame_end;        // byte position where first frame ended (for sub-block alignment)
  // Probe-local semantic progress for custom reassembly. These fields track
  // the furthest trustworthy progress seen in the current validation call,
  // even when no new checkpoint-safe replay boundary was crossed.
  bool probe_score_valid;
  uint32_t probe_completed_frames;
  uint64_t probe_checkpoint_curpos;
  uint64_t probe_last_good_row_pos;
  uint64_t probe_last_normal_pos;
  // cross-frame detection state
  int bad_mad_streak;              // consecutive bad MAD rows (carries across frames)
  // palette-index fallback state
  int low_similarity_count;
  int first_low_row;
  // LZW decoder state for intra-frame checkpointing. A later validation
  // call restores the decoder at snap_pos inside the frame whose image
  // descriptor record starts at snap_record_pos, instead of re-decoding the
  // frame's LZW stream from its first byte. Validity is guarded by an XXH3
  // hash over data[0..snap_pos), independently of the frame-skip replay gate,
  // so a snapshot survives even when later prefix bytes changed. All fields
  // are fixed-size: the struct stays memcpy-clonable and raw-serializable.
  bool     snap_valid;
  bool     snap_mad_active;       // snapshot requires previous-row MAD state
  bool     snap_prev_row_present;  // prev_row holds the row before snap_next_row
  uint32_t snap_next_row;          // row index the resumed decode starts at
  uint32_t snap_frame_index;       // ImageNum on entry to the snapshot frame
  uint64_t snap_pos;               // decoder position (start of snap_next_row)
  uint64_t snap_record_pos;        // position of the frame's 0x2C record byte
  uint64_t snap_prefix_hash;       // XXH3 of data[0..snap_pos)
  uint64_t snap_last_good_mad_pos; // per-frame detector anchors at snap_pos
  uint64_t snap_last_normal_pos;
  double   snap_running_mad_sum;
  uint32_t snap_mad_count;
  int32_t  snap_bad_mad_streak;
  double   snap_running_bpr_sum;
  double   snap_running_bpr_sq;
  uint32_t snap_bpr_count;
  uint32_t snap_prev_row_len;
  GIFLZWState snap_lzw;
  uint8_t  snap_prev_row[GIF_SNAP_PREV_ROW_MAX];
  bool reassembly_return_pending;
  int64_t reassembly_return_start;
  bool reassembly_return_actual_valid;
  int64_t reassembly_return_actual;
  bool reassembly_return_deferred;
  uint32_t reassembly_prefix_anchor_trials;
  bool reassembly_actual_backscan_active;
  // The low and high 16-bit halves hold the remaining proven displaced-run
  // and return-path block counts in existing checkpoint-layout padding.
  uint32_t reassembly_return_chain_blocks;
  int64_t reassembly_actual_backscan_anchor;
  int64_t reassembly_actual_backscan_next;
  bool reassembly_actual_run_rescue_pending;
  int64_t reassembly_actual_run_rescue_anchor;
  int64_t reassembly_actual_run_rescue_start;
  int64_t reassembly_actual_run_rescue_next;
  bool reassembly_phase_hint_checked;
  bool reassembly_phase_hint_valid;
  uint64_t reassembly_phase_hint_length;
  uint32_t reassembly_phase_hint_offset;
  uint8_t reassembly_phase_hint_threshold;
  bool reassembly_phase_scan_exhausted;
  uint64_t reassembly_phase_scan_exhausted_length;
  bool reassembly_completion_probe_exhausted;
  uint64_t reassembly_completion_probe_exhausted_length;
  bool reassembly_prestart_exhausted;
  uint32_t reassembly_trusted_plateau_blocks;
  uint32_t reassembly_checkpoint_plateau_blocks;
  bool reassembly_scan_cursor_valid;
  int64_t reassembly_scan_cursor;
  bool reassembly_scan_cursor_actual_valid;
  int64_t reassembly_scan_cursor_actual;
  uint64_t reassembly_scan_cursor_length;
  bool reassembly_seed_scan_started;
  bool reassembly_preserved_frontier;
} GIFCarveState;

static inline void gif_validate_core(char *data, uint64_t length,
                                     bool *validates,
                                     uint64_t *validates_to,
                                     bool *promising,
                                     uint32_t needleidx,
                                     uint32_t blocksize,
                                     void *carvehashkey,
                                     GIFCarveState *direct_state);

// the following structure is used to support reading GIF data for gif_lib from a memory buffer.
typedef struct GIFMemIO {
  unsigned char *data;  // data provided for validation
  uint64_t length;      // length of data provided for validation
  uint64_t curpos;      // current position in 'data'
  int64_t errpos;       // first error position
} GIFMemIO;

// =========================================================================
// GIF LZW decoder functions.
// =========================================================================

// Initialize the LZW decoder.  mem->curpos should point to the LZW
// minimum code size byte at the start of the image data.  After init,
// mem->curpos is advanced past the min code size byte.
// Returns false if min_code_size is invalid (corrupt data).
static inline bool gif_lzw_init(GIFLZWState *s, GIFMemIO *mem) {
  memset(s, 0, sizeof(*s));
  if (mem->curpos >= mem->length) {
    s->eof_reached = true;
    return false;
  }
  s->min_code_size = mem->data[mem->curpos];
  // Accept 1-bit streams for valid monochrome GIFs, plus the same extended
  // 9-11 range already tolerated for real-world encoders. Reject 12 because
  // clear_code would equal GIF_LZW_MAX_CODES (4096), leaving no room for
  // EOI/new entries.
  if (s->min_code_size < 1 || s->min_code_size > GIF_LZW_MAX_BITS - 1) {
    s->eof_reached = true;
    mem->curpos++;
    return false;
  }
  s->clear_code = 1 << s->min_code_size;
  s->eoi_code = s->clear_code + 1;
  s->code_size = s->min_code_size + 1;
  s->next_code = s->eoi_code + 1;
  s->prev_code = UINT16_MAX;
  mem->curpos++;  // skip the min code size byte
  s->sb_buf_len = 0;
  s->sb_buf_pos = 0;
  s->bit_buf = 0;
  s->bits_in_buf = 0;
  s->out_stack_top = 0;
  s->eof_reached = false;
  s->saw_eoi = false;

  // Initialize literal entries in code table
  for (uint16_t i = 0; i < s->clear_code; i++) {
    s->prefix[i] = UINT16_MAX;  // no prefix (literal)
    s->suffix[i] = (uint8_t)i;
    s->first_char[i] = (uint8_t)i;
  }
  return true;
}

static inline void gif_reassembly_reset_candidate_state(CarveInfo *candidate) {
  if (candidate->best_choices) {
    destroy_queue(candidate->best_choices);
    init_queue(candidate->best_choices, sizeof(int64_t), true, NULL, true);
  }

  if (carve_hash_key_valid(candidate->carvehashkey)) {
    GIFCarveState cleared = {0};
    carve_put_state(candidate->carvehashkey, &cleared);
  }

  candidate->newblock = -1;
  candidate->fastpath = false;
  candidate->no_initial_block_extension = false;
  candidate->block_choice_start = 0;
  candidate->best_validates_to = 0;
}

static inline void gif_reassembly_refresh_candidate_state(
    CarveInfo *candidate);
static inline void gif_reassembly_copy_runtime_fields(
    GIFCarveState *dst, const GIFCarveState *src);
static inline uint32_t gif_reassembly_effective_plateau_blocks(
    const GIFCarveState *state);
static inline uint32_t gif_reassembly_proven_chain_blocks(
    const GIFCarveState *state);
static inline uint32_t gif_reassembly_proven_return_blocks(
    const GIFCarveState *state);
static inline void gif_reassembly_set_return_proof(
    GIFCarveState *state, uint32_t chain_blocks, uint32_t return_blocks);
static inline bool gif_reassembly_subblock_phase_from_data(
    const unsigned char *data, uint64_t length, uint32_t *offset_out,
    uint8_t *threshold_out);
static inline bool gif_reassembly_get_phase_hint(
    CarveInfo *candidate, GIFCarveState *state, uint32_t *offset_out,
    uint8_t *threshold_out);
static inline bool gif_reassembly_block_matches_phase_transition(
    int64_t apparentblocknumber, uint32_t offset);
static inline bool gif_reassembly_block_phase_continuation(
    int64_t apparentblocknumber, uint32_t offset, uint8_t threshold,
    uint32_t minimum_headers, uint32_t *next_offset_out);
static inline bool gif_reassembly_block_matches_phase_hint(
    int64_t apparentblocknumber, uint32_t offset, uint8_t threshold);
static inline bool gif_reassembly_block_matches_phase_probe_hint(
    int64_t apparentblocknumber, uint32_t offset, uint8_t threshold);
static inline int64_t gif_reassembly_phase_choice(
    CarveInfo *candidate, uint64_t slot, int64_t scan_start,
    int64_t scan_count, int64_t previous_apparentblocknumber,
    GIFCarveState *state, int64_t *resume_after_out);
static inline int64_t gif_reassembly_phase_probe_choice(
    CarveInfo *candidate, uint64_t slot, int64_t scan_start,
    int64_t scan_count, int64_t previous_apparentblocknumber,
    GIFCarveState *state, int64_t *resume_after_out,
    bool include_local_forward);
static inline int64_t gif_reassembly_completion_probe_choice(
    CarveInfo *candidate, uint64_t slot, int64_t scan_start,
    int64_t scan_count, int64_t previous_apparentblocknumber,
    GIFCarveState *state, int64_t *resume_after_out);
static inline uint32_t gif_reassembly_probe_adjacent_completion(
    CarveInfo *candidate, const GIFCarveState *base_state,
    int64_t first_apparentblocknumber);

static inline bool gif_reassembly_normalize_candidate(int id,
    CarveInfo *candidate, uuid_string_t uuidp, uuid_string_t uuidc,
    bool *validated_out) {
  uint64_t nb;
  uint64_t i;
  uint64_t validates_to = 0;
  bool validates = false;
  bool cold_validates = false;
  bool cold_promising = false;
  uint64_t cold_validates_to = 0;
  uint64_t cur_len;
  uint64_t keep_len;
  uint64_t keep_blocks;
  uint64_t bs = (uint64_t)scalpel_state.blocksize;
  uint64_t resumed_plateau_allowance = 0;
  uint32_t resumed_plateau_blocks = 0;
  bool preserve_resumed_plateau = false;
  GIFCarveState cold_state = {0};
  GIFCarveState resumed_state = {0};

  *validated_out = false;

  candidate->chopped = false;
  inflate_blockvector(candidate->b);

  if (candidate->newblock < 0 && candidate->block_choice_start < 0) {
    candidate->block_choice_start = 0;
    candidate->fastpath = false;
  }

  if (candidate->no_initial_block_extension
      && carve_hash_key_valid(candidate->carvehashkey)) {
    void *saved = carve_get_state(candidate->carvehashkey);

    if (saved) {
      memcpy(&resumed_state, saved, sizeof(resumed_state));
      gif_free_carve_state(&saved);
    }

    resumed_plateau_blocks = resumed_state.reassembly_trusted_plateau_blocks;
    if (resumed_state.reassembly_checkpoint_plateau_blocks
        > resumed_plateau_blocks) {
      resumed_plateau_blocks = resumed_state.reassembly_checkpoint_plateau_blocks;
    }
    if (bs > 0 && resumed_plateau_blocks > 0) {
      resumed_plateau_allowance =
          ((uint64_t)resumed_plateau_blocks + 1) * bs
          + GIF_REASSEMBLY_VALIDATE_SLACK;
      if (resumed_state.data_length > 0
          && resumed_state.data_length < blockvector_get_data_length(candidate->b)
          && resumed_state.data_length + resumed_plateau_allowance
                 >= blockvector_get_data_length(candidate->b) - 1) {
        preserve_resumed_plateau = true;
      }
    }

    if (resumed_state.valid
        && resumed_state.data_length > 0
        && resumed_state.data_length < blockvector_get_data_length(candidate->b)
        && !preserve_resumed_plateau) {
      blockvector_set_data_length(candidate->b, resumed_state.data_length);
    }
  }

  nb = blockvector_get_num_blocks(candidate->b);
  for (i = 0; i < nb; i++) {
    int64_t ab = blockvector_get_apparent_blocknumber(candidate->b, i);
    int64_t act = blockvector_get_actual_blocknumber(candidate->b, i);
    if (ab < 0 || act < 0) {
      // A restored scan keeps its exclusions in an empty slot after the
      // committed prefix. It is search state, not a hole in the file data.
      if (candidate->no_initial_block_extension && bs > 0
          && ab < 0 && act < 0 && i + 1 == nb
          && blockvector_get_data_length(candidate->b) > 0
          && i == CEILDIV(blockvector_get_data_length(candidate->b), bs)) {
        break;
      }
      if (i == 0) {
        return false;
      }
      resize_blockvector(candidate->b, i);
      inflate_blockvector(candidate->b);
      gif_reassembly_reset_candidate_state(candidate);
      gif_reassembly_refresh_candidate_state(candidate);
      break;
    }
  }

  if (blockvector_get_num_blocks(candidate->b) == 0) {
    return false;
  }

  validates = reassembly_check_validation(id, candidate, &validates_to,
                                          uuidp, uuidc);
  if (candidate->no_initial_block_extension) {
    gif_validate_core(blockvector_get_data_pointer(candidate->b),
                      blockvector_get_data_length(candidate->b),
                      &cold_validates, &cold_validates_to, &cold_promising,
                      candidate->needleidx, scalpel_state.blocksize, NULL,
                      &cold_state);

    validates = cold_validates;
    validates_to = cold_validates_to;
    if (!preserve_resumed_plateau
        && !validates
        && resumed_plateau_allowance > 0
        && cold_promising
        && validates_to + resumed_plateau_allowance
               >= blockvector_get_data_length(candidate->b) - 1) {
      preserve_resumed_plateau = true;
    }
    if (carve_hash_key_valid(candidate->carvehashkey)) {
      gif_reassembly_copy_runtime_fields(&cold_state, &resumed_state);
      carve_put_state(candidate->carvehashkey, &cold_state);
    }
    (void)cold_promising;
  }
  if (validates) {
    *validated_out = true;
    return true;
  }

  cur_len = blockvector_get_data_length(candidate->b);
  if (cur_len == 0) {
    return false;
  }

  if (candidate->no_initial_block_extension
      && candidate->newblock < 0
      && bs > 0
      && blockvector_get_num_blocks(candidate->b) == CEILDIV(cur_len, bs)
      && validates_to + 1 >= cur_len) {
    candidate->no_initial_block_extension = false;
    if (candidate->block_choice_start < 0) {
      candidate->block_choice_start = 0;
    }
    candidate->fastpath = false;
  }

  keep_len = validates_to + 1;
  if (bs > 0 && keep_len < bs) {
    keep_len = bs;
  }
  if (preserve_resumed_plateau
      && candidate->no_initial_block_extension
      && !validates
      && cold_promising
      && keep_len < cur_len
      && keep_len + resumed_plateau_allowance >= cur_len - 1) {
    keep_len = cur_len;
  }
  if (keep_len > cur_len) {
    keep_len = cur_len;
  }

  if (keep_len < cur_len) {
    keep_blocks = CEILDIV(keep_len, bs);
    if (keep_blocks == 0) {
      keep_blocks = 1;
    }
    blockvector_set_data_length(candidate->b, keep_len);
    resize_blockvector(candidate->b, keep_blocks);
    inflate_blockvector(candidate->b);
    gif_reassembly_reset_candidate_state(candidate);
    gif_reassembly_refresh_candidate_state(candidate);
  }

  return true;
}

typedef struct GIFReassemblyScore {
  uint32_t completed_frames;
  uint64_t checkpoint_curpos;
  uint64_t last_good_row_pos;
  uint64_t last_normal_pos;
} GIFReassemblyScore;

typedef struct GIFValidationSummary {
  bool validates;
  bool promising;
  uint64_t validates_to;
  GIFReassemblyScore score;
} GIFValidationSummary;

typedef struct GIFReassemblyFollowCache {
  GIFValidationSummary summary;
  int64_t newblock;
  bool valid;
  bool has_followon;
} GIFReassemblyFollowCache;

static inline void gif_reassembly_capture_score(CarveInfo *candidate,
                                                GIFReassemblyScore *score);
static inline void gif_reassembly_capture_score_from_state(
    const GIFCarveState *gif_state, GIFReassemblyScore *score);
static inline int gif_reassembly_compare_score(const GIFReassemblyScore *lhs,
                                               const GIFReassemblyScore *rhs);
static inline int gif_reassembly_compare_probe_summary(
    const GIFValidationSummary *lhs, const GIFValidationSummary *rhs);
static inline bool gif_reassembly_ambiguous_probe_tie(
    const GIFValidationSummary *lhs, const GIFValidationSummary *rhs);
static inline uint64_t gif_reassembly_score_covered_length(
    const GIFReassemblyScore *score);
static inline void gif_reassembly_clamp_nonvalidated_summary(
    uint64_t oldlength, GIFValidationSummary *summary);
static inline void gif_reassembly_load_state_raw(CarveInfo *candidate,
                                                 GIFCarveState *state);
static inline void gif_reassembly_load_state(CarveInfo *candidate,
                                             GIFCarveState *state);
static inline void gif_reassembly_clamp_state_to_length(
    GIFCarveState *state, uint64_t data_length);
static inline void gif_reassembly_store_state_impl(
    CarveInfo *candidate, const GIFCarveState *state, int caller_line);
#define gif_reassembly_store_state(candidate, state) \
  gif_reassembly_store_state_impl((candidate), (state), __LINE__)
static inline void gif_reassembly_validate_local(
    CarveInfo *candidate, GIFCarveState *state,
    GIFValidationSummary *summary);
static inline bool gif_reassembly_promote_current_validation(
    CarveInfo *candidate, bool *validated_out);
static inline bool gif_reassembly_promote_current_blocks(
    CarveInfo *candidate, bool *validated_out);

static inline bool gif_reassembly_score_advanced(
    const GIFReassemblyScore *current, const GIFReassemblyScore *base) {
  return gif_reassembly_compare_score(current, base) > 0;
}

static inline bool gif_reassembly_score_not_regressed(
    const GIFReassemblyScore *current, const GIFReassemblyScore *base) {
  return gif_reassembly_compare_score(current, base) >= 0;
}

static inline bool gif_reassembly_strong_winner(
    uint64_t oldlength, int64_t current_apparentblocknumber,
    int64_t previous_apparentblocknumber,
    const GIFValidationSummary *summary,
    const GIFCarveState *base_state) {
  GIFReassemblyScore base_score = {0};
  uint64_t advanced_bytes = summary->validates_to + 1 > oldlength
                                ? summary->validates_to + 1 - oldlength
                                : 0;
  uint64_t strong_bytes = GIF_REASSEMBLY_STRONG_WIN_BYTES;
  (void)current_apparentblocknumber;
  (void)previous_apparentblocknumber;

  if ((uint64_t)scalpel_state.blocksize / 4 > strong_bytes) {
    strong_bytes = (uint64_t)scalpel_state.blocksize / 4;
  }

  gif_reassembly_capture_score_from_state(base_state, &base_score);
  return gif_reassembly_score_advanced(&summary->score, &base_score)
         || advanced_bytes >= strong_bytes;
}

static inline void gif_reassembly_maybe_arm_fastpath(
    CarveInfo *candidate, uint64_t oldlength,
    int64_t current_apparentblocknumber,
    int64_t previous_apparentblocknumber,
    const GIFValidationSummary *summary,
    const GIFCarveState *base_state) {
  if (!candidate || !summary || previous_apparentblocknumber < 0) {
    return;
  }

  if (base_state && base_state->reassembly_return_pending) {
    return;
  }

  if (current_apparentblocknumber == previous_apparentblocknumber + 1
      && summary->validates_to
             == blockvector_get_data_length(candidate->b) - 1
      && gif_reassembly_strong_winner(oldlength,
                                      current_apparentblocknumber,
                                      previous_apparentblocknumber,
                                      summary, base_state)) {
    candidate->fastpath = true;
  }
}

static inline bool gif_reassembly_weak_validation_summary(
    uint64_t oldlength, const GIFValidationSummary *summary,
    const GIFReassemblyScore *base_score) {
  uint64_t advanced_bytes = summary->validates_to + 1 > oldlength
                                ? summary->validates_to + 1 - oldlength
                                : 0;

  if (advanced_bytes > GIF_REASSEMBLY_WEAK_VALIDATION_BYTES) {
    return false;
  }

  return !gif_reassembly_score_advanced(&summary->score, base_score);
}

static inline bool gif_reassembly_local_forward_choice(
    int64_t previous_apparentblocknumber, int64_t current_apparentblocknumber) {
  if (previous_apparentblocknumber < 0
      || current_apparentblocknumber <= previous_apparentblocknumber) {
    return false;
  }

  return (uint64_t)(current_apparentblocknumber
                    - previous_apparentblocknumber)
         <= GIF_REASSEMBLY_LOCAL_DISTANCE_MAX;
}

static inline bool gif_reassembly_local_seed_choice(
    int64_t start_apparentblocknumber, int64_t current_apparentblocknumber) {
  if (start_apparentblocknumber < 0
      || current_apparentblocknumber <= start_apparentblocknumber) {
    return false;
  }

  return (uint64_t)(current_apparentblocknumber - start_apparentblocknumber)
         <= GIF_REASSEMBLY_LOCAL_DISTANCE_MAX;
}

static inline bool gif_reassembly_apparent_in_forward_window(
    int64_t start_apparentblocknumber, int64_t current_apparentblocknumber,
    uint64_t window) {
  int64_t apparent_blocks;
  int64_t delta;

  if (start_apparentblocknumber < 0
      || current_apparentblocknumber < 0
      || window == 0) {
    return false;
  }

  apparent_blocks =
      (int64_t)filemirror_apparent_blocks(scalpel_state.filemirror);
  if (apparent_blocks <= 0) {
    return current_apparentblocknumber >= start_apparentblocknumber
           && (uint64_t)(current_apparentblocknumber
                         - start_apparentblocknumber) < window;
  }

  start_apparentblocknumber %= apparent_blocks;
  if (start_apparentblocknumber < 0) {
    start_apparentblocknumber += apparent_blocks;
  }
  current_apparentblocknumber %= apparent_blocks;
  if (current_apparentblocknumber < 0) {
    current_apparentblocknumber += apparent_blocks;
  }

  delta = current_apparentblocknumber - start_apparentblocknumber;
  if (delta < 0) {
    delta += apparent_blocks;
  }

  return (uint64_t)delta < window;
}

static inline bool gif_reassembly_apparent_in_return_window(
    const GIFCarveState *state, int64_t current_apparentblocknumber) {
  return state
         && state->reassembly_return_pending
         && gif_reassembly_apparent_in_forward_window(
                state->reassembly_return_start, current_apparentblocknumber,
                GIF_REASSEMBLY_RETURN_SCAN_WINDOW);
}

static inline bool gif_reassembly_choice_in_return_window(
    const GIFCarveState *state, int64_t current_apparentblocknumber) {
  int64_t apparent_blocks;
  int64_t current_actualblocknumber;

  if (!state
      || !state->reassembly_return_pending
      || current_apparentblocknumber < 0) {
    return false;
  }

  apparent_blocks =
      (int64_t)filemirror_apparent_blocks(scalpel_state.filemirror);
  if (apparent_blocks <= 0) {
    return false;
  }
  current_apparentblocknumber %= apparent_blocks;
  if (current_apparentblocknumber < 0) {
    current_apparentblocknumber += apparent_blocks;
  }

  if (state->reassembly_return_actual_valid
      && state->reassembly_return_actual >= 0) {
    current_actualblocknumber =
        filemirror_actual_blocknumber(scalpel_state.filemirror,
                                      current_apparentblocknumber);
    return current_actualblocknumber >= state->reassembly_return_actual
           && (uint64_t)(current_actualblocknumber
                         - state->reassembly_return_actual)
                  < GIF_REASSEMBLY_RETURN_SCAN_WINDOW;
  }

  return gif_reassembly_apparent_in_return_window(
      state, current_apparentblocknumber);
}

static inline bool gif_reassembly_tail_block_in_prestart_window(
    CarveInfo *candidate) {
  uint64_t nb;
  int64_t tail_apparentblocknumber;
  int64_t start_apparentblocknumber;

  if (scalpel_state.blocksize == 0) {
    return false;
  }

  nb = blockvector_get_num_blocks(candidate->b);
  if (nb == 0) {
    return false;
  }

  tail_apparentblocknumber =
      blockvector_get_apparent_blocknumber(candidate->b, nb - 1);
  start_apparentblocknumber = gif_reassembly_anchor_apparent_block(candidate);

  if (tail_apparentblocknumber < 0
      || start_apparentblocknumber <= 0
      || tail_apparentblocknumber >= start_apparentblocknumber) {
    return false;
  }

  return (uint64_t)(start_apparentblocknumber - tail_apparentblocknumber)
         <= GIF_REASSEMBLY_PRESTART_DISTANCE_MAX;
}

static inline bool gif_reassembly_can_commit_prestart_plateau(
    CarveInfo *candidate, uint64_t saved_length,
    const GIFValidationSummary *summary,
    const GIFReassemblyScore *base_score) {
  if (saved_length == 0 || scalpel_state.blocksize == 0 || !summary->promising
      || !gif_reassembly_tail_block_in_prestart_window(candidate)
      || gif_reassembly_compare_score(&summary->score, base_score) < 0) {
    return false;
  }

  return summary->validates_to
             + (uint64_t)scalpel_state.blocksize
             + GIF_REASSEMBLY_VALIDATE_SLACK
         >= saved_length - 1;
}

static inline bool gif_reassembly_tail_block_in_local_forward_window(
    CarveInfo *candidate) {
  uint64_t nb;
  int64_t previous_apparentblocknumber;
  int64_t tail_apparentblocknumber;

  if (!candidate || scalpel_state.blocksize == 0) {
    return false;
  }

  nb = blockvector_get_num_blocks(candidate->b);
  if (nb < 2) {
    return false;
  }

  previous_apparentblocknumber =
      blockvector_get_apparent_blocknumber(candidate->b, nb - 2);
  tail_apparentblocknumber =
      blockvector_get_apparent_blocknumber(candidate->b, nb - 1);

  return gif_reassembly_local_forward_choice(previous_apparentblocknumber,
                                             tail_apparentblocknumber);
}

static inline bool gif_reassembly_can_commit_local_plateau(
    CarveInfo *candidate, uint64_t saved_length,
    const GIFValidationSummary *summary,
    const GIFReassemblyScore *base_score) {
  if (saved_length == 0 || scalpel_state.blocksize == 0 || !summary->promising
      || !gif_reassembly_tail_block_in_local_forward_window(candidate)
      || summary->score.completed_frames < base_score->completed_frames
      || summary->score.checkpoint_curpos
             + (uint64_t)scalpel_state.blocksize
             + GIF_REASSEMBLY_VALIDATE_SLACK
             < base_score->checkpoint_curpos
      || summary->score.last_good_row_pos
             + (uint64_t)scalpel_state.blocksize
             + GIF_REASSEMBLY_VALIDATE_SLACK
             < base_score->last_good_row_pos
      || summary->score.last_normal_pos
             + (uint64_t)scalpel_state.blocksize
             + GIF_REASSEMBLY_VALIDATE_SLACK
             < base_score->last_normal_pos) {
    return false;
  }

  return summary->validates_to
             + (uint64_t)scalpel_state.blocksize
             + GIF_REASSEMBLY_VALIDATE_SLACK
         >= saved_length - 1;
}

static inline uint64_t gif_reassembly_preserve_committed_best(
    CarveInfo *candidate, uint64_t validates_to) {
  uint64_t committed_length = blockvector_get_data_length(candidate->b);

  if (committed_length == 0) {
    return validates_to;
  }

  if (validates_to + 1 < committed_length) {
    return committed_length - 1;
  }

  return validates_to;
}

static inline uint64_t gif_reassembly_committed_prestart_tail_blocks(
    CarveInfo *candidate, uint64_t committed_length) {
  uint64_t bs = (uint64_t)scalpel_state.blocksize;
  uint64_t committed_blocks;
  uint64_t count = 0;
  int64_t start_apparentblocknumber;
  int64_t previous_apparentblocknumber = -1;

  if (bs == 0 || committed_length == 0) {
    return 0;
  }

  committed_blocks = CEILDIV(committed_length, bs);
  if (committed_blocks == 0
      || committed_blocks > blockvector_get_num_blocks(candidate->b)) {
    return 0;
  }

  start_apparentblocknumber = gif_reassembly_anchor_apparent_block(candidate);
  if (start_apparentblocknumber <= 0) {
    return 0;
  }

  for (uint64_t idx = committed_blocks; idx > 0; idx--) {
    int64_t apparentblocknumber =
        blockvector_get_apparent_blocknumber(candidate->b, idx - 1);

    if (apparentblocknumber < 0
        || apparentblocknumber >= start_apparentblocknumber
        || (uint64_t)(start_apparentblocknumber - apparentblocknumber)
               > GIF_REASSEMBLY_PRESTART_DISTANCE_MAX) {
      break;
    }

    if (count > 0
        && previous_apparentblocknumber - apparentblocknumber != 1) {
      break;
    }

    count++;
    previous_apparentblocknumber = apparentblocknumber;
  }

  return count;
}

static inline void gif_reassembly_copy_runtime_fields(
    GIFCarveState *dst, const GIFCarveState *src) {
  if (!dst || !src) {
    return;
  }

  dst->reassembly_return_pending = src->reassembly_return_pending;
  dst->reassembly_return_start = src->reassembly_return_start;
  dst->reassembly_return_actual_valid =
      src->reassembly_return_actual_valid;
  dst->reassembly_return_actual = src->reassembly_return_actual;
  dst->reassembly_return_deferred = src->reassembly_return_deferred;
  dst->reassembly_return_chain_blocks =
      src->reassembly_return_chain_blocks;
  dst->reassembly_prefix_anchor_trials =
      src->reassembly_prefix_anchor_trials;
  dst->reassembly_actual_backscan_active =
      src->reassembly_actual_backscan_active;
  dst->reassembly_actual_backscan_anchor =
      src->reassembly_actual_backscan_anchor;
  dst->reassembly_actual_backscan_next =
      src->reassembly_actual_backscan_next;
  dst->reassembly_actual_run_rescue_pending =
      src->reassembly_actual_run_rescue_pending;
  dst->reassembly_actual_run_rescue_anchor =
      src->reassembly_actual_run_rescue_anchor;
  dst->reassembly_actual_run_rescue_start =
      src->reassembly_actual_run_rescue_start;
  dst->reassembly_actual_run_rescue_next =
      src->reassembly_actual_run_rescue_next;
  dst->reassembly_phase_hint_checked = src->reassembly_phase_hint_checked;
  dst->reassembly_phase_hint_valid = src->reassembly_phase_hint_valid;
  dst->reassembly_phase_hint_length = src->reassembly_phase_hint_length;
  dst->reassembly_phase_hint_offset = src->reassembly_phase_hint_offset;
  dst->reassembly_phase_hint_threshold = src->reassembly_phase_hint_threshold;
  dst->reassembly_phase_scan_exhausted = src->reassembly_phase_scan_exhausted;
  dst->reassembly_phase_scan_exhausted_length =
      src->reassembly_phase_scan_exhausted_length;
  dst->reassembly_completion_probe_exhausted =
      src->reassembly_completion_probe_exhausted;
  dst->reassembly_completion_probe_exhausted_length =
      src->reassembly_completion_probe_exhausted_length;
  dst->reassembly_prestart_exhausted = src->reassembly_prestart_exhausted;
  dst->reassembly_trusted_plateau_blocks =
      src->reassembly_trusted_plateau_blocks;
  dst->reassembly_checkpoint_plateau_blocks =
      src->reassembly_checkpoint_plateau_blocks;
  dst->reassembly_scan_cursor_valid = src->reassembly_scan_cursor_valid;
  dst->reassembly_scan_cursor = src->reassembly_scan_cursor;
  dst->reassembly_scan_cursor_actual_valid =
      src->reassembly_scan_cursor_actual_valid;
  dst->reassembly_scan_cursor_actual = src->reassembly_scan_cursor_actual;
  dst->reassembly_scan_cursor_length =
      src->reassembly_scan_cursor_length;
  dst->reassembly_seed_scan_started = src->reassembly_seed_scan_started;
}

static inline bool gif_reassembly_current_apparent_block_valid(
    int64_t apparentblocknumber) {
  uint64_t apparent_blocks = 0;

  if (apparentblocknumber < 0 || !scalpel_state.filemirror) {
    return false;
  }

  apparent_blocks = filemirror_apparent_blocks(scalpel_state.filemirror);
  return (uint64_t)apparentblocknumber < apparent_blocks;
}

static inline uint32_t gif_reassembly_proven_chain_blocks(
    const GIFCarveState *state) {
  if (!state || !state->reassembly_return_pending) {
    return 0;
  }

  return state->reassembly_return_chain_blocks
         & GIF_REASSEMBLY_RETURN_PROOF_MASK;
}

static inline uint32_t gif_reassembly_proven_return_blocks(
    const GIFCarveState *state) {
  if (!state || !state->reassembly_return_pending) {
    return 0;
  }

  return state->reassembly_return_chain_blocks
         >> GIF_REASSEMBLY_RETURN_PROOF_SHIFT;
}

static inline void gif_reassembly_set_return_proof(
    GIFCarveState *state, uint32_t chain_blocks, uint32_t return_blocks) {
  if (!state) {
    return;
  }

  if (chain_blocks > GIF_REASSEMBLY_RETURN_PROOF_MASK) {
    chain_blocks = GIF_REASSEMBLY_RETURN_PROOF_MASK;
  }
  if (return_blocks > GIF_REASSEMBLY_RETURN_PROOF_MASK) {
    return_blocks = GIF_REASSEMBLY_RETURN_PROOF_MASK;
  }

  state->reassembly_return_chain_blocks =
      (return_blocks << GIF_REASSEMBLY_RETURN_PROOF_SHIFT) | chain_blocks;
}

static inline void gif_reassembly_set_return_start(
    GIFCarveState *state, int64_t apparentblocknumber, bool deferred) {
  int64_t actualblocknumber = -1;

  if (!state) {
    return;
  }

  if (!gif_reassembly_current_apparent_block_valid(apparentblocknumber)) {
    state->reassembly_return_pending = false;
    state->reassembly_return_deferred = false;
    state->reassembly_return_chain_blocks = 0;
    state->reassembly_return_start = -1;
    state->reassembly_return_actual_valid = false;
    state->reassembly_return_actual = -1;
    return;
  }

  state->reassembly_return_pending = true;
  state->reassembly_return_start = apparentblocknumber;
  state->reassembly_return_deferred = deferred;
  state->reassembly_return_chain_blocks = 0;
  state->reassembly_return_actual_valid = false;
  state->reassembly_return_actual = -1;

  actualblocknumber =
      filemirror_actual_blocknumber(scalpel_state.filemirror,
                                    apparentblocknumber);
  if (actualblocknumber >= 0) {
    state->reassembly_return_actual_valid = true;
    state->reassembly_return_actual = actualblocknumber;
  }
}

static inline void gif_reassembly_clear_return_start(GIFCarveState *state) {
  if (!state) {
    return;
  }

  state->reassembly_return_pending = false;
  state->reassembly_return_deferred = false;
  state->reassembly_return_chain_blocks = 0;
  state->reassembly_return_start = -1;
  state->reassembly_return_actual_valid = false;
  state->reassembly_return_actual = -1;
}

static inline void gif_reassembly_clear_scan_cursor(GIFCarveState *state) {
  if (!state) {
    return;
  }

  state->reassembly_scan_cursor_valid = false;
  state->reassembly_scan_cursor = -1;
  state->reassembly_scan_cursor_actual_valid = false;
  state->reassembly_scan_cursor_actual = -1;
  state->reassembly_scan_cursor_length = 0;
}

static inline void gif_reassembly_normalize_return_start(
    GIFCarveState *state) {
  int64_t apparentblocknumber = -1;
  int64_t actualblocknumber = -1;

  if (!state || !state->reassembly_return_pending) {
    if (state) {
      state->reassembly_return_actual_valid = false;
      state->reassembly_return_actual = -1;
    }
    return;
  }

  if (state->reassembly_return_actual_valid
      && state->reassembly_return_actual >= 0) {
    apparentblocknumber =
        filemirror_apparent_blocknumber(scalpel_state.filemirror,
                                        state->reassembly_return_actual);
    if (gif_reassembly_current_apparent_block_valid(apparentblocknumber)) {
      state->reassembly_return_start = apparentblocknumber;
      return;
    }
  }

  if (gif_reassembly_current_apparent_block_valid(
          state->reassembly_return_start)) {
    actualblocknumber =
        filemirror_actual_blocknumber(scalpel_state.filemirror,
                                      state->reassembly_return_start);
    if (actualblocknumber >= 0) {
      state->reassembly_return_actual_valid = true;
      state->reassembly_return_actual = actualblocknumber;
      return;
    }
  }

  gif_reassembly_clear_return_start(state);
}

static inline void gif_reassembly_normalize_scan_cursor(
    GIFCarveState *state) {
  int64_t apparentblocknumber = -1;
  int64_t actualblocknumber = -1;

  if (!state) {
    return;
  }

  if (!state->reassembly_scan_cursor_valid) {
    state->reassembly_scan_cursor_actual_valid = false;
    state->reassembly_scan_cursor_actual = -1;
    return;
  }

  if (state->reassembly_scan_cursor_actual_valid
      && state->reassembly_scan_cursor_actual >= 0) {
    apparentblocknumber =
        filemirror_apparent_blocknumber(scalpel_state.filemirror,
                                        state->reassembly_scan_cursor_actual);
    if (gif_reassembly_current_apparent_block_valid(apparentblocknumber)) {
      state->reassembly_scan_cursor = apparentblocknumber;
      return;
    }
  }

  if (gif_reassembly_current_apparent_block_valid(
          state->reassembly_scan_cursor)) {
    actualblocknumber =
        filemirror_actual_blocknumber(scalpel_state.filemirror,
                                      state->reassembly_scan_cursor);
    if (actualblocknumber >= 0) {
      state->reassembly_scan_cursor_actual_valid = true;
      state->reassembly_scan_cursor_actual = actualblocknumber;
      return;
    }
  }

  gif_reassembly_clear_scan_cursor(state);
}

static inline void gif_reassembly_set_scan_cursor(
    GIFCarveState *state, int64_t apparentblocknumber, uint64_t data_length) {
  int64_t actualblocknumber = -1;

  if (!state) {
    return;
  }

  if (!gif_reassembly_current_apparent_block_valid(apparentblocknumber)) {
    gif_reassembly_clear_scan_cursor(state);
    return;
  }

  state->reassembly_scan_cursor_valid = true;
  state->reassembly_scan_cursor = apparentblocknumber;
  state->reassembly_scan_cursor_actual_valid = false;
  state->reassembly_scan_cursor_actual = -1;
  state->reassembly_scan_cursor_length = data_length;

  actualblocknumber =
      filemirror_actual_blocknumber(scalpel_state.filemirror,
                                    apparentblocknumber);
  if (actualblocknumber >= 0) {
    state->reassembly_scan_cursor_actual_valid = true;
    state->reassembly_scan_cursor_actual = actualblocknumber;
  }
}

static inline uint32_t gif_reassembly_effective_plateau_blocks(
    const GIFCarveState *state) {
  uint32_t plateau_blocks = 0;

  if (!state) {
    return 0;
  }

  plateau_blocks = state->reassembly_trusted_plateau_blocks;
  if (state->reassembly_checkpoint_plateau_blocks > plateau_blocks) {
    plateau_blocks = state->reassembly_checkpoint_plateau_blocks;
  }

  return plateau_blocks;
}

static inline void gif_reassembly_capture_score_from_state(
    const GIFCarveState *gif_state, GIFReassemblyScore *score) {
  memset(score, 0, sizeof(*score));

  if (!gif_state) {
    return;
  }

  if (gif_state->probe_score_valid) {
    score->completed_frames = gif_state->probe_completed_frames;
    score->checkpoint_curpos = gif_state->probe_checkpoint_curpos;
    score->last_good_row_pos = gif_state->probe_last_good_row_pos;
    score->last_normal_pos = gif_state->probe_last_normal_pos;
    return;
  }

  if (!gif_state->valid) {
    return;
  }

  score->completed_frames = gif_state->completed_frames;
  score->checkpoint_curpos = gif_state->checkpoint_curpos;
  score->last_good_row_pos = gif_state->last_good_row_pos;
  score->last_normal_pos = gif_state->last_normal_pos;
}

static inline void gif_reassembly_capture_score(CarveInfo *candidate,
                                                GIFReassemblyScore *score) {
  void *state = NULL;

  if (! carve_hash_key_valid(candidate->carvehashkey)) {
    memset(score, 0, sizeof(*score));
    return;
  }

  state = carve_get_state(candidate->carvehashkey);
  if (! state) {
    memset(score, 0, sizeof(*score));
    return;
  }

  gif_reassembly_capture_score_from_state((GIFCarveState *)state, score);
  gif_free_carve_state(&state);
}

static inline void gif_reassembly_load_state(CarveInfo *candidate,
                                             GIFCarveState *state) {
  uint64_t data_length;

  memset(state, 0, sizeof(*state));

  if (! carve_hash_key_valid(candidate->carvehashkey)) {
    return;
  }

  gif_reassembly_load_state_raw(candidate, state);

  data_length = blockvector_get_data_length(candidate->b);
  if (state->data_length > data_length
      || state->checkpoint_curpos > data_length
      || state->last_good_row_pos > data_length
      || state->pre_boundary_pos > data_length
      || state->last_boundary_check > data_length
      || state->sb_limit > data_length
      || state->last_normal_pos > data_length
      || state->first_frame_end > data_length) {
    gif_reassembly_clamp_state_to_length(state, data_length);
  }

}

static inline void gif_reassembly_load_state_raw(CarveInfo *candidate,
                                                 GIFCarveState *state) {
  void *saved = NULL;

  memset(state, 0, sizeof(*state));

  if (! carve_hash_key_valid(candidate->carvehashkey)) {
    return;
  }

  saved = carve_get_state(candidate->carvehashkey);
  if (!saved) {
    return;
  }

  memcpy(state, saved, sizeof(*state));
  gif_free_carve_state(&saved);
  gif_reassembly_normalize_return_start(state);
  gif_reassembly_normalize_scan_cursor(state);
}

static inline void gif_reassembly_clamp_state_to_length(
    GIFCarveState *state, uint64_t data_length) {
  if (!state) {
    return;
  }

  state->data_length = data_length;

  if (state->checkpoint_curpos > data_length) {
    state->checkpoint_curpos = data_length;
    state->valid = false;
  }
  if (state->last_good_row_pos > data_length) {
    state->last_good_row_pos = data_length;
  }
  if (state->pre_boundary_pos > data_length) {
    state->pre_boundary_pos = data_length;
  }
  if (state->last_boundary_check > data_length) {
    state->last_boundary_check = data_length;
  }
  if (state->sb_limit > data_length) {
    state->sb_limit = data_length;
  }
  if (state->last_normal_pos > data_length) {
    state->last_normal_pos = data_length;
  }
  if (state->first_frame_end > data_length) {
    state->first_frame_end = data_length;
  }

  if (state->probe_checkpoint_curpos > data_length) {
    state->probe_checkpoint_curpos = data_length;
    state->probe_score_valid = false;
  }
  if (state->probe_last_good_row_pos > data_length) {
    state->probe_last_good_row_pos = data_length;
  }
  if (state->probe_last_normal_pos > data_length) {
    state->probe_last_normal_pos = data_length;
  }

  if (state->last_good_row_pos < state->checkpoint_curpos) {
    state->last_good_row_pos = state->checkpoint_curpos;
  }
  if (state->last_normal_pos < state->checkpoint_curpos) {
    state->last_normal_pos = state->checkpoint_curpos;
  }
  if (state->probe_last_good_row_pos < state->probe_checkpoint_curpos) {
    state->probe_last_good_row_pos = state->probe_checkpoint_curpos;
  }
  if (state->probe_last_normal_pos < state->probe_checkpoint_curpos) {
    state->probe_last_normal_pos = state->probe_checkpoint_curpos;
  }
}

static inline void gif_reassembly_store_state_impl(
    CarveInfo *candidate, const GIFCarveState *state, int caller_line) {
  GIFCarveState cleared = {0};
  const GIFCarveState *stored = state ? state : &cleared;
  (void)caller_line;

  if (! carve_hash_key_valid(candidate->carvehashkey)) {
    return;
  }

  carve_put_state(candidate->carvehashkey, (void *)stored);
}

static inline bool gif_reassembly_checkpoint_requested(void) {
  return atomic_load_explicit(&REASS_RETURN_TO_IDLE, memory_order_acquire);
}

static inline bool gif_reassembly_exceeded_max_size(
    int id, CarveInfo *candidate, uuid_string_t uuidp, uuid_string_t uuidc) {
  uint64_t maximum_size;

  if (!candidate || !candidate->b) {
    return false;
  }

  maximum_size = scalpel_state.search_specs[candidate->needleidx].MAXIMUMSIZE;
  if (blockvector_get_data_length(candidate->b) <= maximum_size) {
    return false;
  }

  lock_fprintf(stdout,
               "Reassembly thread # %1d abandoning GIF branch with blockvector %p "
               "and UUIDs\n%s / %s\nbecause size %" PRIu64
               " exceeds maximum for file type %" PRIu64 ".\n",
               id, candidate->b, uuidp, uuidc,
               blockvector_get_data_length(candidate->b), maximum_size);
  return true;
}

static inline void gif_reassembly_interrupt_scan(
    bool *stop_scanning_out, bool *checkpoint_interrupted_out) {
  if (stop_scanning_out) {
    *stop_scanning_out = true;
  }
  if (checkpoint_interrupted_out) {
    *checkpoint_interrupted_out = true;
  }
}

static inline bool gif_reassembly_debug_candidate(CarveInfo *candidate) {
  static bool initialized = false;
  static int64_t debug_startblock = -1;
  int64_t actual0 = -1;

  if (!initialized) {
    const char *env = getenv("SCALPEL_GIF_DEBUG_STARTBLOCK");
    if (env && *env) {
      char *end = NULL;
      long long want = strtoll(env, &end, 10);
      if (end && *end == '\0' && want >= 0) {
        debug_startblock = (int64_t)want;
      }
    }
    initialized = true;
  }

  if (debug_startblock < 0 || !candidate || !candidate->b
      || blockvector_get_num_blocks(candidate->b) == 0) {
    return false;
  }

  actual0 = blockvector_get_actual_blocknumber(candidate->b, 0);
  return actual0 == debug_startblock;
}

static inline void gif_reassembly_validate_local_impl(
    CarveInfo *candidate, GIFCarveState *state,
    GIFValidationSummary *summary) {
  GIFCarveState preserved = {0};
  char *data = blockvector_get_data_pointer(candidate->b);
  uint64_t data_length = blockvector_get_data_length(candidate->b);
  bool snapshot_changed = false;

  memset(summary, 0, sizeof(*summary));
  if (state) {
    preserved = *state;
  }

  gif_validate_core(data, data_length,
                    &summary->validates, &summary->validates_to,
                    &summary->promising, candidate->needleidx,
                    scalpel_state.blocksize, NULL, state);
  if (state) {
    gif_reassembly_copy_runtime_fields(state, &preserved);
  }
  gif_reassembly_capture_score_from_state(state, &summary->score);

  // Persist decoder snapshots independently of a trial's validation result.
  // Only snapshot fields are merged:
  //  - Checkpoint fields must NOT be persisted from failed trials. A trial
  //    can advance reliable_pos into its own (wrong) trial block, and a
  //    persisted checkpoint there lets the frame-skip replay structurally
  //    skip re-validating that content on a later call, a false accept.
  //    Checkpoints continue to persist only through the post-validate store.
  //  - Snapshot reuse requires an exact prefix-hash match and complete
  //    detector context. Every byte past snap_pos is still decoded and
  //    detector-checked.
  //  - Runtime scan/exhaustion bookkeeping is never touched here: overwriting
  //    it with a trial's stale copy would re-open completed scans.
  snapshot_changed = state && state->snap_valid
      && (! preserved.snap_valid
          || state->snap_pos != preserved.snap_pos
          || state->snap_prefix_hash != preserved.snap_prefix_hash);
  if (snapshot_changed) {
    GIFCarveState *stored =
        (GIFCarveState *)carve_get_state(candidate->carvehashkey);
    GIFCarveState merged;
    bool incoming_matches = false;
    bool stored_matches = false;
    bool put_needed = false;

    if (stored) {
      merged = *stored;
    }
    else {
      memset(&merged, 0, sizeof(merged));
    }
    incoming_matches = state->snap_pos > 0
        && state->snap_pos <= data_length
        && XXH3_64bits(data, state->snap_pos) == state->snap_prefix_hash;
    stored_matches = merged.snap_valid
        && merged.snap_pos > 0
        && merged.snap_pos <= data_length
        && XXH3_64bits(data, merged.snap_pos) == merged.snap_prefix_hash;

    // Prefer the furthest snapshot on the current branch. A farther snapshot
    // from a different trial is not useful here, so replace it when its hash
    // does not match this candidate even if the replacement is earlier.
    if (incoming_matches
        && (! stored_matches || state->snap_pos > merged.snap_pos)) {
      merged.valid = true;
      merged.snap_valid = true;
      merged.snap_mad_active = state->snap_mad_active;
      merged.snap_prev_row_present = state->snap_prev_row_present;
      merged.snap_next_row = state->snap_next_row;
      merged.snap_frame_index = state->snap_frame_index;
      merged.snap_pos = state->snap_pos;
      merged.snap_record_pos = state->snap_record_pos;
      merged.snap_prefix_hash = state->snap_prefix_hash;
      merged.snap_last_good_mad_pos = state->snap_last_good_mad_pos;
      merged.snap_last_normal_pos = state->snap_last_normal_pos;
      merged.snap_running_mad_sum = state->snap_running_mad_sum;
      merged.snap_mad_count = state->snap_mad_count;
      merged.snap_bad_mad_streak = state->snap_bad_mad_streak;
      merged.snap_running_bpr_sum = state->snap_running_bpr_sum;
      merged.snap_running_bpr_sq = state->snap_running_bpr_sq;
      merged.snap_bpr_count = state->snap_bpr_count;
      merged.snap_prev_row_len = state->snap_prev_row_len;
      merged.snap_lzw = state->snap_lzw;
      memcpy(merged.snap_prev_row, state->snap_prev_row,
             sizeof(merged.snap_prev_row));
      put_needed = true;
    }
    if (put_needed) {
      carve_put_state(candidate->carvehashkey, &merged);
    }
    gif_free_carve_state((void **)&stored);
  }
}

static inline void gif_reassembly_validate_local(
    CarveInfo *candidate, GIFCarveState *state,
    GIFValidationSummary *summary) {
  gif_reassembly_validate_local_impl(candidate, state, summary);
}

static inline void gif_reassembly_validate_local_probe(
    CarveInfo *candidate, GIFCarveState *state,
    GIFValidationSummary *summary) {
  gif_reassembly_validate_local_impl(candidate, state, summary);
}

static inline uint32_t gif_reassembly_probe_adjacent_completion(
    CarveInfo *candidate, const GIFCarveState *base_state,
    int64_t first_apparentblocknumber) {
  uint64_t old_blocks;
  uint64_t apparent_blocks;
  uint64_t oldlengths[GIF_REASSEMBLY_DEEP_RETURN_CONFIRM_BLOCKS] = {0};
  uint32_t appended_blocks = 0;
  uint32_t last_probed_blocks = 0;
  uint32_t proven_blocks = 0;
  GIFCarveState trial_state = {0};
  GIFValidationSummary trial_summary = {0};

  if (!candidate || !candidate->b || !base_state
      || first_apparentblocknumber < 0) {
    return 0;
  }

  old_blocks = blockvector_get_num_blocks(candidate->b);
  apparent_blocks =
      filemirror_apparent_blocks(scalpel_state.filemirror);
  if ((uint64_t)first_apparentblocknumber >= apparent_blocks) {
    return 0;
  }

  while (appended_blocks < GIF_REASSEMBLY_DEEP_RETURN_CONFIRM_BLOCKS) {
    uint64_t apparent_index;
    int64_t apparentblocknumber;
    int64_t actualblocknumber;
    uint64_t slot;

    apparent_index =
        (uint64_t)first_apparentblocknumber + appended_blocks;
    if (apparent_index > (uint64_t)INT64_MAX
        || apparent_index >= apparent_blocks
        || apparent_block_in_blockvector(candidate->b,
                                         (int64_t)apparent_index)
        || gif_reassembly_checkpoint_requested()) {
      break;
    }
    apparentblocknumber = (int64_t)apparent_index;

    actualblocknumber = filemirror_actual_blocknumber(
        scalpel_state.filemirror, apparentblocknumber);
    if (actualblocknumber < 0
        || filemirror_get_blocktype(scalpel_state.filemirror,
                                    actualblocknumber,
                                    candidate->needleidx)
               == BLOCK_CONFIDENCE_INVALID
        || filemirror_actual_block_covered(scalpel_state.filemirror,
                                           actualblocknumber)) {
      break;
    }

    slot = old_blocks + appended_blocks;
    resize_blockvector(candidate->b, slot + 1);
    blockvector_set_apparent_blocknumber(candidate->b, slot,
                                         apparentblocknumber);
    oldlengths[appended_blocks] =
        inflate_blockvector_single_block(candidate->b, slot);
    appended_blocks++;

    // Probe powers of two so long compressed-data plateaus require only
    // logarithmically many full validator calls.
    if ((appended_blocks & (appended_blocks - 1)) != 0
        && appended_blocks < GIF_REASSEMBLY_DEEP_RETURN_CONFIRM_BLOCKS) {
      continue;
    }

    trial_state = *base_state;
    gif_reassembly_validate_local_probe(candidate, &trial_state,
                                        &trial_summary);
    last_probed_blocks = appended_blocks;
    if (trial_summary.validates) {
      proven_blocks = appended_blocks;
      break;
    }
  }

  if (proven_blocks == 0 && appended_blocks > last_probed_blocks) {
    trial_state = *base_state;
    gif_reassembly_validate_local_probe(candidate, &trial_state,
                                        &trial_summary);
    if (trial_summary.validates) {
      proven_blocks = appended_blocks;
    }
  }

  while (appended_blocks > 0) {
    uint64_t slot = old_blocks + appended_blocks - 1;

    deflate_blockvector_single_block(candidate->b, slot,
                                     oldlengths[appended_blocks - 1]);
    resize_blockvector(candidate->b, slot);
    appended_blocks--;
  }

  return proven_blocks;
}

static inline void gif_reassembly_refresh_candidate_state(
    CarveInfo *candidate) {
  GIFCarveState refreshed = {0};
  GIFCarveState preserved = {0};
  GIFValidationSummary summary = {0};
  void *saved = NULL;

  if (! carve_hash_key_valid(candidate->carvehashkey)
      || blockvector_get_num_blocks(candidate->b) == 0
      || blockvector_get_data_length(candidate->b) == 0) {
    return;
  }

  saved = carve_get_state(candidate->carvehashkey);
  if (saved) {
    preserved = *(GIFCarveState *)saved;
    gif_free_carve_state(&saved);
  }

  gif_reassembly_validate_local(candidate, &refreshed, &summary);
  gif_reassembly_copy_runtime_fields(&refreshed, &preserved);

  carve_put_state(candidate->carvehashkey, &refreshed);
  candidate->best_validates_to = summary.validates_to;
}

static inline bool gif_reassembly_promote_current_validation(
    CarveInfo *candidate, bool *validated_out) {
  GIFCarveState trial_state = {0};
  GIFCarveState preserved_runtime = {0};
  GIFValidationSummary summary = {0};
  GIFReassemblyScore base_score = {0};
  bool tried_cold = false;
  uint64_t oldlength = 0;
  uint64_t saved_length = blockvector_get_data_length(candidate->b);

  *validated_out = false;
  inflate_blockvector(candidate->b);
  if (blockvector_get_num_blocks(candidate->b) > 0) {
    oldlength = (blockvector_get_num_blocks(candidate->b) - 1)
                * (uint64_t)scalpel_state.blocksize;
  }

  while (1) {
    if (! tried_cold) {
      gif_reassembly_load_state(candidate, &trial_state);
    }
    else {
      gif_reassembly_load_state(candidate, &preserved_runtime);
      memset(&trial_state, 0, sizeof(trial_state));
    }
    gif_reassembly_capture_score_from_state(&trial_state, &base_score);
    gif_reassembly_validate_local(candidate, &trial_state, &summary);
    if (tried_cold) {
      gif_reassembly_copy_runtime_fields(&trial_state, &preserved_runtime);
    }
    gif_reassembly_clamp_nonvalidated_summary(oldlength, &summary);
    if (summary.validates
        && gif_reassembly_weak_validation_summary(oldlength, &summary,
                                                  &base_score)) {
      summary.validates = false;
    }
    if (summary.validates || tried_cold) {
      break;
    }
    tried_cold = true;
  }

  if (! summary.validates) {
    blockvector_set_data_length(candidate->b, saved_length);
    return false;
  }

  gif_reassembly_store_state(candidate, &trial_state);
  candidate->best_validates_to = summary.validates_to;
  candidate->flavor = VALIDATED;
  blockvector_set_data_length(candidate->b, summary.validates_to + 1);
  resize_blockvector(candidate->b,
                     CEILDIV(blockvector_get_data_length(candidate->b),
                             scalpel_state.blocksize));
  *validated_out = true;
  return true;
}

static inline bool gif_reassembly_promote_current_blocks(
    CarveInfo *candidate, bool *validated_out) {
  uint64_t nb = blockvector_get_num_blocks(candidate->b);
  uint64_t saved_length = blockvector_get_data_length(candidate->b);
  uint64_t full_length;
  int64_t last_actual;
  uint64_t last_start;
  uint64_t last_len;
  GIFCarveState trial_state = {0};
  GIFCarveState cold_state = {0};
  GIFCarveState preserved_runtime = {0};
  GIFValidationSummary summary = {0};
  GIFValidationSummary cold_summary = {0};
  GIFReassemblyScore base_score = {0};
  GIFReassemblyScore cold_base_score = {0};

  *validated_out = false;

  if (nb == 0 || scalpel_state.blocksize == 0) {
    return false;
  }

  last_actual = blockvector_get_actual_blocknumber(candidate->b, nb - 1);
  if (last_actual < 0) {
    return false;
  }

  last_start = (uint64_t)last_actual * (uint64_t)scalpel_state.blocksize;
  last_len = (uint64_t)scalpel_state.blocksize;
  if (last_start + last_len > filemirror_filesize(scalpel_state.filemirror)) {
    last_len = filemirror_filesize(scalpel_state.filemirror) - last_start;
  }

  full_length = (nb - 1) * (uint64_t)scalpel_state.blocksize + last_len;
  if (full_length <= saved_length) {
    return false;
  }

  blockvector_set_data_length(candidate->b, full_length);
  gif_reassembly_load_state(candidate, &trial_state);
  gif_reassembly_capture_score_from_state(&trial_state, &base_score);
  gif_reassembly_validate_local(candidate, &trial_state, &summary);
  gif_reassembly_clamp_nonvalidated_summary(saved_length, &summary);
  if (summary.validates
      && gif_reassembly_weak_validation_summary(saved_length, &summary,
                                                &base_score)) {
    summary.validates = false;
  }

  if (summary.validates) {
    gif_reassembly_store_state(candidate, &trial_state);
    candidate->best_validates_to = summary.validates_to;
    candidate->flavor = VALIDATED;
    blockvector_set_data_length(candidate->b, summary.validates_to + 1);
    resize_blockvector(candidate->b,
                       CEILDIV(blockvector_get_data_length(candidate->b),
                               scalpel_state.blocksize));
    *validated_out = true;
    return true;
  }

  if (summary.validates_to > saved_length - 1) {
    gif_reassembly_load_state(candidate, &preserved_runtime);
    cold_base_score = base_score;
    gif_reassembly_validate_local(candidate, &cold_state, &cold_summary);
    gif_reassembly_copy_runtime_fields(&cold_state, &preserved_runtime);
    gif_reassembly_clamp_nonvalidated_summary(saved_length, &cold_summary);
    if (cold_summary.validates
        && gif_reassembly_weak_validation_summary(saved_length, &cold_summary,
                                                  &cold_base_score)) {
      cold_summary.validates = false;
    }

    if (cold_summary.validates) {
      gif_reassembly_store_state(candidate, &cold_state);
      candidate->best_validates_to = cold_summary.validates_to;
      candidate->flavor = VALIDATED;
      blockvector_set_data_length(candidate->b, cold_summary.validates_to + 1);
      resize_blockvector(candidate->b,
                         CEILDIV(blockvector_get_data_length(candidate->b),
                                 scalpel_state.blocksize));
      *validated_out = true;
      return true;
    }

    if (cold_summary.validates_to > saved_length - 1) {
      gif_reassembly_store_state(candidate, &cold_state);
      candidate->best_validates_to = cold_summary.validates_to;
      blockvector_set_data_length(candidate->b, cold_summary.validates_to + 1);
      resize_blockvector(candidate->b,
                         CEILDIV(blockvector_get_data_length(candidate->b),
                                 scalpel_state.blocksize));
      return true;
    }
  }

  if (gif_reassembly_can_commit_prestart_plateau(candidate, saved_length,
                                                 &summary, &base_score)
      || gif_reassembly_can_commit_local_plateau(candidate, saved_length,
                                                 &summary, &base_score)) {
    gif_reassembly_store_state(candidate, &trial_state);
    candidate->best_validates_to = full_length - 1;
    blockvector_set_data_length(candidate->b, full_length);
    resize_blockvector(candidate->b,
                       CEILDIV(blockvector_get_data_length(candidate->b),
                               scalpel_state.blocksize));
    return true;
  }

  blockvector_set_data_length(candidate->b, saved_length);
  return false;
}

static inline int gif_reassembly_compare_score(const GIFReassemblyScore *lhs,
                                               const GIFReassemblyScore *rhs) {
  if (lhs->completed_frames != rhs->completed_frames) {
    return lhs->completed_frames > rhs->completed_frames ? 1 : -1;
  }

  if (lhs->checkpoint_curpos != rhs->checkpoint_curpos) {
    return lhs->checkpoint_curpos > rhs->checkpoint_curpos ? 1 : -1;
  }

  if (lhs->last_good_row_pos != rhs->last_good_row_pos) {
    return lhs->last_good_row_pos > rhs->last_good_row_pos ? 1 : -1;
  }

  if (lhs->last_normal_pos != rhs->last_normal_pos) {
    return lhs->last_normal_pos > rhs->last_normal_pos ? 1 : -1;
  }

  return 0;
}

static inline int gif_reassembly_compare_probe_summary(
    const GIFValidationSummary *lhs, const GIFValidationSummary *rhs) {
  if (lhs->validates != rhs->validates) {
    return lhs->validates ? 1 : -1;
  }

  if (lhs->validates && lhs->validates_to != rhs->validates_to) {
    return lhs->validates_to > rhs->validates_to ? 1 : -1;
  }

  if (!lhs->validates
      && lhs->score.completed_frames == rhs->score.completed_frames
      && lhs->score.checkpoint_curpos == rhs->score.checkpoint_curpos
      && scalpel_state.blocksize > 0) {
    uint64_t lhs_row_delta =
        lhs->score.last_good_row_pos > lhs->score.checkpoint_curpos
            ? lhs->score.last_good_row_pos - lhs->score.checkpoint_curpos
            : 0;
    uint64_t rhs_row_delta =
        rhs->score.last_good_row_pos > rhs->score.checkpoint_curpos
            ? rhs->score.last_good_row_pos - rhs->score.checkpoint_curpos
            : 0;
    uint64_t lhs_normal_delta =
        lhs->score.last_normal_pos > lhs->score.checkpoint_curpos
            ? lhs->score.last_normal_pos - lhs->score.checkpoint_curpos
            : 0;
    uint64_t rhs_normal_delta =
        rhs->score.last_normal_pos > rhs->score.checkpoint_curpos
            ? rhs->score.last_normal_pos - rhs->score.checkpoint_curpos
            : 0;
    uint64_t lhs_row_blocks = lhs_row_delta / scalpel_state.blocksize;
    uint64_t rhs_row_blocks = rhs_row_delta / scalpel_state.blocksize;
    uint64_t lhs_normal_blocks = lhs_normal_delta / scalpel_state.blocksize;
    uint64_t rhs_normal_blocks = rhs_normal_delta / scalpel_state.blocksize;
    uint64_t row_gap = lhs_row_delta > rhs_row_delta
                           ? lhs_row_delta - rhs_row_delta
                           : rhs_row_delta - lhs_row_delta;
    uint64_t normal_gap = lhs_normal_delta > rhs_normal_delta
                              ? lhs_normal_delta - rhs_normal_delta
                              : rhs_normal_delta - lhs_normal_delta;

    if (lhs_row_blocks != rhs_row_blocks) {
      return lhs_row_blocks > rhs_row_blocks ? 1 : -1;
    }

    if (lhs_normal_blocks != rhs_normal_blocks) {
      return lhs_normal_blocks > rhs_normal_blocks ? 1 : -1;
    }

    if (row_gap > GIF_REASSEMBLY_VALIDATE_SLACK) {
      return lhs_row_delta > rhs_row_delta ? 1 : -1;
    }

    if (normal_gap > GIF_REASSEMBLY_VALIDATE_SLACK) {
      return lhs_normal_delta > rhs_normal_delta ? 1 : -1;
    }
  }

  {
    int semantic_cmp = gif_reassembly_compare_score(&lhs->score, &rhs->score);
    if (semantic_cmp != 0) {
      return semantic_cmp;
    }
  }

  if (lhs->validates_to != rhs->validates_to) {
    return lhs->validates_to > rhs->validates_to ? 1 : -1;
  }

  return 0;
}

static inline bool gif_reassembly_ambiguous_probe_tie(
    const GIFValidationSummary *lhs, const GIFValidationSummary *rhs) {
  if (lhs->validates || rhs->validates
      || lhs->validates_to != rhs->validates_to
      || lhs->score.completed_frames != rhs->score.completed_frames
      || lhs->score.checkpoint_curpos != rhs->score.checkpoint_curpos
      || scalpel_state.blocksize == 0) {
    return false;
  }

  return gif_reassembly_compare_probe_summary(lhs, rhs) == 0;
}

static inline int gif_reassembly_compare_forward_distance(
    int64_t previous_apparentblocknumber, int64_t lhs_apparentblocknumber,
    int64_t rhs_apparentblocknumber) {
  uint64_t total_apparent_blocks;
  uint64_t lhs_distance;
  uint64_t rhs_distance;

  if (previous_apparentblocknumber < 0
      || lhs_apparentblocknumber < 0
      || rhs_apparentblocknumber < 0) {
    return 0;
  }

  total_apparent_blocks = filemirror_apparent_blocks(scalpel_state.filemirror);
  if (total_apparent_blocks == 0) {
    return 0;
  }

  lhs_distance =
      (uint64_t)(lhs_apparentblocknumber - previous_apparentblocknumber
                 + (int64_t)total_apparent_blocks) % total_apparent_blocks;
  rhs_distance =
      (uint64_t)(rhs_apparentblocknumber - previous_apparentblocknumber
                 + (int64_t)total_apparent_blocks) % total_apparent_blocks;

  if (lhs_distance == rhs_distance) {
    return 0;
  }

  return lhs_distance < rhs_distance ? 1 : -1;
}

static inline int gif_reassembly_compare_locality(
    int64_t previous_apparentblocknumber, int64_t lhs_apparentblocknumber,
    int64_t rhs_apparentblocknumber) {
  uint64_t total_apparent_blocks;
  uint64_t lhs_distance;
  uint64_t rhs_distance;
  bool lhs_local;
  bool rhs_local;

  if (previous_apparentblocknumber < 0
      || lhs_apparentblocknumber < 0
      || rhs_apparentblocknumber < 0) {
    return 0;
  }

  total_apparent_blocks = filemirror_apparent_blocks(scalpel_state.filemirror);
  if (total_apparent_blocks == 0) {
    return 0;
  }

  lhs_distance =
      (uint64_t)(lhs_apparentblocknumber - previous_apparentblocknumber
                 + (int64_t)total_apparent_blocks) % total_apparent_blocks;
  rhs_distance =
      (uint64_t)(rhs_apparentblocknumber - previous_apparentblocknumber
                 + (int64_t)total_apparent_blocks) % total_apparent_blocks;
  lhs_local = lhs_distance <= GIF_REASSEMBLY_LOCAL_DISTANCE_MAX;
  rhs_local = rhs_distance <= GIF_REASSEMBLY_LOCAL_DISTANCE_MAX;

  if (lhs_local == rhs_local) {
    return 0;
  }

  return lhs_local ? 1 : -1;
}

static inline bool gif_reassembly_defer_distance_tiebreak(
    int64_t previous_apparentblocknumber, int64_t lhs_apparentblocknumber,
    int64_t rhs_apparentblocknumber) {
  uint64_t total_apparent_blocks;
  uint64_t lhs_distance;
  uint64_t rhs_distance;

  if (previous_apparentblocknumber < 0
      || lhs_apparentblocknumber < 0
      || rhs_apparentblocknumber < 0) {
    return false;
  }

  total_apparent_blocks = filemirror_apparent_blocks(scalpel_state.filemirror);
  if (total_apparent_blocks == 0) {
    return false;
  }

  lhs_distance =
      (uint64_t)(lhs_apparentblocknumber - previous_apparentblocknumber
                 + (int64_t)total_apparent_blocks) % total_apparent_blocks;
  rhs_distance =
      (uint64_t)(rhs_apparentblocknumber - previous_apparentblocknumber
                 + (int64_t)total_apparent_blocks) % total_apparent_blocks;

  return lhs_distance > GIF_REASSEMBLY_LOCAL_DISTANCE_MAX
         && rhs_distance > GIF_REASSEMBLY_LOCAL_DISTANCE_MAX;
}

static inline bool gif_reassembly_preserve_local_frontier(
    int64_t previous_apparentblocknumber, int64_t current_apparentblocknumber,
    int64_t best_apparentblocknumber, const GIFValidationSummary *trial_summary,
    const GIFValidationSummary *best_probe) {
  int locality_cmp;

  if (previous_apparentblocknumber < 0) {
    return false;
  }

  locality_cmp = gif_reassembly_compare_locality(
      previous_apparentblocknumber, current_apparentblocknumber,
      best_apparentblocknumber);
  if (locality_cmp >= 0) {
    return false;
  }

  if (trial_summary->validates || best_probe->validates) {
    return false;
  }

  if (trial_summary->score.completed_frames != best_probe->score.completed_frames) {
    return false;
  }

  if (trial_summary->validates_to
      > best_probe->validates_to + GIF_REASSEMBLY_STRONG_WIN_BYTES) {
    return false;
  }

  if (trial_summary->score.checkpoint_curpos
      > best_probe->score.checkpoint_curpos + GIF_REASSEMBLY_STRONG_WIN_BYTES) {
    return false;
  }

  if (trial_summary->score.last_good_row_pos
      > best_probe->score.last_good_row_pos + GIF_REASSEMBLY_STRONG_WIN_BYTES) {
    return false;
  }

  if (trial_summary->score.last_normal_pos
      > best_probe->score.last_normal_pos + GIF_REASSEMBLY_STRONG_WIN_BYTES) {
    return false;
  }

  return true;
}

static inline int64_t gif_reassembly_effective_locality_anchor(
    CarveInfo *candidate, int64_t previous_apparentblocknumber) {
  GIFCarveState gif_state = {0};
  uint64_t apparent_blocks;
  int64_t next_apparent;

  if (previous_apparentblocknumber < 0) {
    return previous_apparentblocknumber;
  }

  apparent_blocks = filemirror_apparent_blocks(scalpel_state.filemirror);
  if (apparent_blocks == 0) {
    return previous_apparentblocknumber;
  }

  gif_reassembly_load_state_raw(candidate, &gif_state);
  if (!gif_state.reassembly_return_pending
      || gif_state.reassembly_return_start < 0) {
    return previous_apparentblocknumber;
  }

  next_apparent = (previous_apparentblocknumber + 1) % (int64_t)apparent_blocks;
  if (next_apparent < 0) {
    next_apparent += (int64_t)apparent_blocks;
  }

  if (!apparent_block_in_blockvector(candidate->b, next_apparent)
      && next_apparent != gif_state.reassembly_return_start) {
    return previous_apparentblocknumber;
  }

  return (gif_state.reassembly_return_start + (int64_t)apparent_blocks - 1)
         % (int64_t)apparent_blocks;
}

static inline int64_t gif_reassembly_recent_forward_gap_start(
    CarveInfo *candidate) {
  uint64_t blocks = blockvector_get_num_blocks(candidate->b);
  uint64_t committed_blocks = blocks;
  uint64_t data_length = blockvector_get_data_length(candidate->b);
  int64_t previous_apparentblocknumber;
  int64_t current_apparentblocknumber;
  int64_t gap;

  if (scalpel_state.blocksize > 0 && data_length > 0) {
    committed_blocks = CEILDIV(data_length,
                               (uint64_t)scalpel_state.blocksize);
    if (committed_blocks == 0 || committed_blocks > blocks) {
      committed_blocks = blocks;
    }
  }

  if (committed_blocks < 2) {
    return -1;
  }

  previous_apparentblocknumber = blockvector_get_apparent_blocknumber(
      candidate->b, committed_blocks - 2);
  current_apparentblocknumber = blockvector_get_apparent_blocknumber(
      candidate->b, committed_blocks - 1);

  if (previous_apparentblocknumber < 0 || current_apparentblocknumber < 0) {
    return -1;
  }

  gap = current_apparentblocknumber - previous_apparentblocknumber;
  if (gap <= 1 || gap > GIF_REASSEMBLY_LOCAL_DISTANCE_MAX) {
    return -1;
  }

  return previous_apparentblocknumber + 1;
}

static inline int64_t gif_reassembly_prestart_gap_start(
    CarveInfo *candidate) {
  uint64_t blocks = blockvector_get_num_blocks(candidate->b);
  uint64_t start_apparent;
  uint64_t current_length = blockvector_get_data_length(candidate->b);
  uint64_t committed_length = candidate->best_validates_to + 1;
  uint64_t min_allowed_apparent = 0;
  int64_t min_apparent = INT64_MAX;
  uint64_t max_apparent = 0;
  bool have_apparent = false;
  GIFCarveState gif_state = {0};

  if (blocks < 2 || scalpel_state.blocksize == 0) {
    return -1;
  }

  if (current_length > committed_length
      && current_length - committed_length
             > (uint64_t)scalpel_state.blocksize
                   + GIF_REASSEMBLY_VALIDATE_SLACK) {
    return -1;
  }

  gif_reassembly_load_state(candidate, &gif_state);
  if (gif_state.reassembly_prestart_exhausted) {
    return -1;
  }

  start_apparent = gif_reassembly_anchor_block(candidate);
  if (start_apparent == 0) {
    return -1;
  }
  if (start_apparent > (uint64_t)GIF_REASSEMBLY_PRESTART_DISTANCE_MAX) {
    min_allowed_apparent =
        start_apparent - (uint64_t)GIF_REASSEMBLY_PRESTART_DISTANCE_MAX;
  }

  for (uint64_t i = 0; i < blocks; i++) {
    int64_t apparent =
        blockvector_get_apparent_blocknumber(candidate->b, i);
    if (apparent < 0) {
      continue;
    }
    have_apparent = true;
    if (apparent < min_apparent) {
      min_apparent = apparent;
    }
    if ((uint64_t)apparent > max_apparent) {
      max_apparent = (uint64_t)apparent;
    }
  }

  if (!have_apparent
      || min_apparent < 0
      || (uint64_t)min_apparent < min_allowed_apparent) {
    return -1;
  }

  if (start_apparent <= (uint64_t)GIF_REASSEMBLY_PRESTART_DISTANCE_MAX) {
    return 0;
  }

  return (int64_t)(start_apparent - GIF_REASSEMBLY_PRESTART_DISTANCE_MAX);
}

static inline int64_t gif_reassembly_resume_choice_start(
    CarveInfo *candidate, int64_t fallback_start) {
  int64_t restart_start;
  uint64_t blocks;
  uint64_t apparent_blocks;
  int64_t tail_apparent;
  GIFCarveState gif_state = {0};

  gif_reassembly_load_state_raw(candidate, &gif_state);
  if (gif_state.reassembly_return_pending
      && gif_state.reassembly_return_start >= 0
      && !gif_state.reassembly_return_deferred) {
    return gif_state.reassembly_return_start;
  }

  restart_start = gif_reassembly_recent_forward_gap_start(candidate);
  if (restart_start >= 0) {
    return restart_start;
  }

  restart_start = gif_reassembly_prestart_gap_start(candidate);
  if (restart_start >= 0) {
    return restart_start;
  }

  blocks = candidate ? blockvector_get_num_blocks(candidate->b) : 0;
  apparent_blocks = filemirror_apparent_blocks(scalpel_state.filemirror);
  if (blocks == 0 || apparent_blocks == 0) {
    return fallback_start;
  }

  tail_apparent =
      blockvector_get_apparent_blocknumber(candidate->b, blocks - 1);
  if (tail_apparent < 0) {
    return fallback_start;
  }

  if (gif_state.reassembly_return_pending
      && gif_state.reassembly_return_start >= 0
      && (!gif_state.reassembly_return_deferred
          || (fallback_start >= 0
              && fallback_start
                     >= tail_apparent + 1
                            + GIF_REASSEMBLY_GAP_SCAN_WINDOW))) {
    return gif_state.reassembly_return_start;
  }

  restart_start = (tail_apparent + 1) % (int64_t)apparent_blocks;
  if (restart_start < 0) {
    restart_start += (int64_t)apparent_blocks;
  }
  return restart_start;
}

static inline bool gif_reassembly_choice_in_prestart_gap(
    int64_t prestart_gap_start, int64_t start_apparentblocknumber,
    int64_t apparentblocknumber) {
  return prestart_gap_start >= 0
         && start_apparentblocknumber > prestart_gap_start
         && apparentblocknumber >= prestart_gap_start
         && apparentblocknumber < start_apparentblocknumber;
}

static inline int64_t gif_reassembly_next_return_gap_choice(
    CarveInfo *candidate, int64_t current_apparentblocknumber,
    int64_t floor_apparentblocknumber) {
  int64_t apparentblocknumber;
  int64_t actualblocknumber;

  if (!candidate || current_apparentblocknumber <= 0) {
    return -1;
  }

  if (floor_apparentblocknumber < 0) {
    floor_apparentblocknumber = 0;
  }

  for (apparentblocknumber = current_apparentblocknumber - 1;
       apparentblocknumber >= floor_apparentblocknumber;
       apparentblocknumber--) {
    if (apparent_block_in_blockvector(candidate->b, apparentblocknumber)) {
      continue;
    }

    actualblocknumber =
        filemirror_actual_blocknumber(scalpel_state.filemirror,
                                      apparentblocknumber);
    if (actualblocknumber < 0
        || filemirror_get_blocktype(scalpel_state.filemirror,
                                    actualblocknumber,
                                    candidate->needleidx)
               == BLOCK_CONFIDENCE_INVALID
        || filemirror_actual_block_covered(scalpel_state.filemirror,
                                           actualblocknumber)) {
      continue;
    }

    return apparentblocknumber;
  }

  return -1;
}

static inline bool gif_reassembly_slot_allows_choice(
    CarveInfo *candidate, uint64_t slot, int64_t apparentblocknumber) {
  uint64_t evaluated = 0;

  if (!candidate || apparentblocknumber < 0) {
    return false;
  }

  return blockvector_get_choice(candidate->b, slot, apparentblocknumber, 1,
                                &evaluated) == apparentblocknumber;
}

static inline bool gif_reassembly_actual_block_is_giflike(
    CarveInfo *candidate, int64_t actualblocknumber) {
  int64_t actual_blocks;

  if (!candidate || actualblocknumber < 0
      || scalpel_state.blocksize == 0
      || filemirror_actual_block_covered(scalpel_state.filemirror,
                                         actualblocknumber)) {
    return false;
  }

  actual_blocks = (int64_t)CEILDIV(filemirror_filesize(scalpel_state.filemirror),
                                   (uint64_t)scalpel_state.blocksize);
  if (actualblocknumber >= actual_blocks) {
    return false;
  }

  return filemirror_get_blocktype(scalpel_state.filemirror,
                                  actualblocknumber,
                                  candidate->needleidx)
         != BLOCK_CONFIDENCE_INVALID;
}

static inline bool gif_reassembly_actual_block_starts_giflike_run(
    CarveInfo *candidate, int64_t actualblocknumber) {
  if (!gif_reassembly_actual_block_is_giflike(candidate, actualblocknumber)) {
    return false;
  }

  if (actualblocknumber == 0) {
    return true;
  }

  return !gif_reassembly_actual_block_is_giflike(candidate,
                                                 actualblocknumber - 1);
}

static inline int64_t gif_reassembly_first_giflike_run_after_actual(
    CarveInfo *candidate, int64_t previous_actualblocknumber,
    int64_t scan_limit) {
  int64_t actual_blocks;
  int64_t scan_end;

  if (!candidate
      || previous_actualblocknumber < 0
      || scan_limit <= 0
      || scalpel_state.blocksize == 0) {
    return -1;
  }

  actual_blocks = (int64_t)CEILDIV(filemirror_filesize(scalpel_state.filemirror),
                                   (uint64_t)scalpel_state.blocksize);
  if (actual_blocks <= 0
      || previous_actualblocknumber + 1 >= actual_blocks) {
    return -1;
  }

  scan_end = previous_actualblocknumber + 1 + scan_limit;
  if (scan_end > actual_blocks) {
    scan_end = actual_blocks;
  }

  for (int64_t actualblocknumber = previous_actualblocknumber + 1;
       actualblocknumber < scan_end;
       actualblocknumber++) {
    int64_t apparentblocknumber;

    if (!gif_reassembly_actual_block_starts_giflike_run(candidate,
                                                        actualblocknumber)) {
      continue;
    }

    apparentblocknumber =
        filemirror_apparent_blocknumber(scalpel_state.filemirror,
                                        actualblocknumber);
    if (apparentblocknumber >= 0
        && !apparent_block_in_blockvector(candidate->b,
                                          apparentblocknumber)) {
      return apparentblocknumber;
    }
  }

  return -1;
}

static inline void gif_reassembly_set_return_start_near_actual(
    CarveInfo *candidate, GIFCarveState *state, int64_t fallback_apparent,
    int64_t previous_actualblocknumber, bool deferred) {
  int64_t return_apparent =
      gif_reassembly_first_giflike_run_after_actual(
          candidate, previous_actualblocknumber,
          GIF_REASSEMBLY_RETURN_SCAN_WINDOW);

  if (return_apparent < 0) {
    return_apparent = fallback_apparent;
  }

  gif_reassembly_set_return_start(state, return_apparent, deferred);
}

static inline int64_t gif_reassembly_giflike_run_start_choice(
    CarveInfo *candidate, uint64_t slot, int64_t scan_start,
    int64_t scan_count, int64_t previous_apparentblocknumber,
    int64_t *resume_after_out) {
  int64_t apparent_blocks;
  int64_t toconsider;
  int64_t original_scan_start;
  int64_t local_forward_cutoff = -1;

  if (resume_after_out) {
    *resume_after_out = -1;
  }

  if (!candidate) {
    return -1;
  }

  apparent_blocks =
      (int64_t)filemirror_apparent_blocks(scalpel_state.filemirror);
  if (apparent_blocks <= 0) {
    return -1;
  }

  if (scan_start < 0) {
    scan_start = 0;
  }
  scan_start %= apparent_blocks;
  if (scan_start < 0) {
    scan_start += apparent_blocks;
  }
  original_scan_start = scan_start;
  toconsider = scan_count > 0 ? scan_count : apparent_blocks;
  if (toconsider > apparent_blocks) {
    toconsider = apparent_blocks;
  }

  if (previous_apparentblocknumber >= 0) {
    local_forward_cutoff =
        previous_apparentblocknumber + GIF_REASSEMBLY_GAP_SCAN_WINDOW;
  }

  for (int64_t j = 0; j < toconsider; ++j) {
    int64_t apparentblocknumber = (original_scan_start + j) % apparent_blocks;
    int64_t actualblocknumber;

    if (gif_reassembly_checkpoint_requested()) {
      return -1;
    }

    if (previous_apparentblocknumber >= 0
        && apparentblocknumber > previous_apparentblocknumber
        && apparentblocknumber <= local_forward_cutoff) {
      continue;
    }

    if (!gif_reassembly_slot_allows_choice(candidate, slot,
                                           apparentblocknumber)) {
      continue;
    }

    actualblocknumber =
        filemirror_actual_blocknumber(scalpel_state.filemirror,
                                      apparentblocknumber);
    if (!gif_reassembly_actual_block_starts_giflike_run(candidate,
                                                        actualblocknumber)) {
      continue;
    }

    if (resume_after_out) {
      *resume_after_out = (apparentblocknumber + 1) % apparent_blocks;
    }
    if (gif_reassembly_debug_candidate(candidate)) {
      fprintf(stderr,
              "[gifdbg] run-start start=%" PRId64
              " prev=%" PRId64 " choice=%" PRId64
              " actual=%" PRId64 "\n",
              blockvector_get_actual_blocknumber(candidate->b, 0),
              previous_apparentblocknumber, apparentblocknumber,
              actualblocknumber);
    }
    return apparentblocknumber;
  }

  return -1;
}

static inline int64_t gif_reassembly_valid_anchor_choice(
    CarveInfo *candidate, uint64_t slot, int64_t scan_start, int64_t scan_count,
    int64_t previous_apparentblocknumber, int64_t *resume_after_out) {
  int64_t apparent_blocks;
  int64_t toconsider;
  int64_t j;
  int64_t original_scan_start;
  int64_t anchor_apparent = -1;
  int64_t local_forward_cutoff = -1;
  bool wrap_prefix_first = false;

  if (resume_after_out) {
    *resume_after_out = -1;
  }

  if (!candidate) {
    return -1;
  }

  apparent_blocks =
      (int64_t)filemirror_apparent_blocks(scalpel_state.filemirror);
  if (apparent_blocks <= 0) {
    return -1;
  }

  if (scan_start < 0) {
    scan_start = 0;
  }
  scan_start %= apparent_blocks;
  if (scan_start < 0) {
    scan_start += apparent_blocks;
  }
  original_scan_start = scan_start;

  toconsider = scan_count > 0 ? scan_count : apparent_blocks;
  if (toconsider > apparent_blocks) {
    toconsider = apparent_blocks;
  }

  if (previous_apparentblocknumber >= 0) {
    local_forward_cutoff =
        previous_apparentblocknumber + GIF_REASSEMBLY_GAP_SCAN_WINDOW;
    wrap_prefix_first =
        local_forward_cutoff < apparent_blocks
        && scan_start > local_forward_cutoff;
  }

  for (int pass = 0; pass < (wrap_prefix_first ? 2 : 1); ++pass) {
    int64_t pass_start = scan_start;
    int64_t pass_count = toconsider;
    bool wrap_prefix_pass = false;

    if (wrap_prefix_first) {
      if (pass == 0) {
        pass_start = 0;
        pass_count = previous_apparentblocknumber + 1;
        if (pass_count > apparent_blocks) {
          pass_count = apparent_blocks;
        }
        wrap_prefix_pass = true;
      }
      else {
        pass_start = scan_start;
        pass_count = apparent_blocks - scan_start;
      }
    }

    for (j = 0; j < pass_count; ++j) {
      int64_t apparentblocknumber = (pass_start + j) % apparent_blocks;
      int64_t actualblocknumber;

      if (gif_reassembly_checkpoint_requested()) {
        return -1;
      }

      if (previous_apparentblocknumber >= 0
          && apparentblocknumber > previous_apparentblocknumber
          && apparentblocknumber <= local_forward_cutoff) {
        continue;
      }

      if (!gif_reassembly_slot_allows_choice(candidate, slot,
                                             apparentblocknumber)) {
        continue;
      }

      if (apparent_block_in_blockvector(candidate->b, apparentblocknumber)) {
        continue;
      }

      actualblocknumber =
          filemirror_actual_blocknumber(scalpel_state.filemirror,
                                        apparentblocknumber);
      if (actualblocknumber < 0
          || filemirror_get_blocktype(scalpel_state.filemirror,
                                      actualblocknumber,
                                      candidate->needleidx)
                 != BLOCK_CONFIDENCE_VALID) {
        continue;
      }

      anchor_apparent = apparentblocknumber;

      for (int backfill = GIF_REASSEMBLY_VALID_ANCHOR_BACKFILL;
           backfill >= 0; --backfill) {
        int64_t candidate_apparent = anchor_apparent - backfill;
        int64_t candidate_actual;

        if (candidate_apparent < 0) {
          continue;
        }

        if (previous_apparentblocknumber >= 0
            && candidate_apparent > previous_apparentblocknumber
            && candidate_apparent <= local_forward_cutoff) {
          continue;
        }

        if (!gif_reassembly_slot_allows_choice(candidate, slot,
                                               candidate_apparent)) {
          continue;
        }

        if (apparent_block_in_blockvector(candidate->b, candidate_apparent)) {
          continue;
        }

        candidate_actual =
            filemirror_actual_blocknumber(scalpel_state.filemirror,
                                          candidate_apparent);
        if (candidate_actual < 0
            || filemirror_get_blocktype(scalpel_state.filemirror,
                                        candidate_actual,
                                        candidate->needleidx)
                   == BLOCK_CONFIDENCE_INVALID) {
          continue;
        }

        if (resume_after_out) {
          *resume_after_out =
              wrap_prefix_pass ? original_scan_start
                               : (candidate_apparent + 1) % apparent_blocks;
        }
        if (gif_reassembly_debug_candidate(candidate)) {
          fprintf(stderr,
                  "[gifdbg] valid-anchor start=%" PRId64
                  " prev=%" PRId64 " anchor=%" PRId64
                  " choice=%" PRId64 " actual=%" PRId64 "\n",
                  blockvector_get_actual_blocknumber(candidate->b, 0),
                  previous_apparentblocknumber, anchor_apparent,
                  candidate_apparent, candidate_actual);
        }
        return candidate_apparent;
      }
    }
  }

  return -1;
}

static inline void gif_reassembly_clear_actual_run_rescue(
    GIFCarveState *state) {
  if (!state) {
    return;
  }

  state->reassembly_actual_run_rescue_pending = false;
  state->reassembly_actual_run_rescue_anchor = -1;
  state->reassembly_actual_run_rescue_start = -1;
  state->reassembly_actual_run_rescue_next = -1;
}

static inline void gif_reassembly_schedule_actual_run_rescue(
    CarveInfo *candidate, GIFCarveState *state, int64_t previous_actualblocknumber,
    int64_t rejected_actualblocknumber) {
  int64_t actual_blocks;
  int64_t scan_limit;
  int64_t actualblocknumber;

  if (!candidate
      || !state
      || previous_actualblocknumber <= rejected_actualblocknumber
      || rejected_actualblocknumber < 0
      || scalpel_state.blocksize == 0
      || !state->reassembly_actual_backscan_active
      || state->reassembly_actual_backscan_anchor != previous_actualblocknumber
      || state->reassembly_actual_backscan_next >= rejected_actualblocknumber
      || !gif_reassembly_actual_block_starts_giflike_run(
             candidate, rejected_actualblocknumber)) {
    return;
  }

  actual_blocks = (int64_t)CEILDIV(filemirror_filesize(scalpel_state.filemirror),
                                   (uint64_t)scalpel_state.blocksize);
  if (actual_blocks <= 0) {
    return;
  }

  scan_limit = rejected_actualblocknumber
               + GIF_REASSEMBLY_ACTUAL_RUN_RESCUE_SCAN_LIMIT;
  if (scan_limit > previous_actualblocknumber) {
    scan_limit = previous_actualblocknumber;
  }
  if (scan_limit > actual_blocks) {
    scan_limit = actual_blocks;
  }

  for (actualblocknumber = rejected_actualblocknumber + 1;
       actualblocknumber < scan_limit;
       actualblocknumber++) {
    int64_t candidate_actual;

    if (!gif_reassembly_actual_block_is_giflike(candidate, actualblocknumber)) {
      break;
    }

    if (filemirror_get_blocktype(scalpel_state.filemirror,
                                 actualblocknumber,
                                 candidate->needleidx)
            != BLOCK_CONFIDENCE_VALID) {
      continue;
    }

    if (actualblocknumber - rejected_actualblocknumber
        <= GIF_REASSEMBLY_LOCAL_DISTANCE_MAX) {
      return;
    }

    candidate_actual = actualblocknumber - 1;
    if (candidate_actual <= rejected_actualblocknumber
        || !gif_reassembly_actual_block_is_giflike(candidate,
                                                   candidate_actual)) {
      return;
    }

    state->reassembly_actual_run_rescue_pending = true;
    state->reassembly_actual_run_rescue_anchor = previous_actualblocknumber;
    state->reassembly_actual_run_rescue_start = rejected_actualblocknumber;
    state->reassembly_actual_run_rescue_next = candidate_actual;
    gif_reassembly_store_state(candidate, state);
    if (gif_reassembly_debug_candidate(candidate)) {
      fprintf(stderr,
              "[gifdbg] actual-run-rescue-scheduled start=%" PRId64
              " anchor_actual=%" PRId64 " run_start=%" PRId64
              " valid_anchor=%" PRId64 " rescue_actual=%" PRId64 "\n",
              blockvector_get_actual_blocknumber(candidate->b, 0),
              previous_actualblocknumber, rejected_actualblocknumber,
              actualblocknumber, candidate_actual);
    }
    return;
  }
}

static inline int64_t gif_reassembly_actual_run_rescue_choice(
    CarveInfo *candidate, uint64_t slot, int64_t previous_actualblocknumber,
    GIFCarveState *state) {
  int64_t candidate_actual;
  int64_t candidate_apparent;
  int64_t run_start_actual;

  if (!candidate
      || !state
      || !state->reassembly_actual_run_rescue_pending
      || state->reassembly_actual_run_rescue_start < 0
      || state->reassembly_actual_run_rescue_next < 0) {
    return -1;
  }

  if (state->reassembly_actual_run_rescue_anchor != previous_actualblocknumber
      || scalpel_state.blocksize == 0) {
    gif_reassembly_clear_actual_run_rescue(state);
    gif_reassembly_store_state(candidate, state);
    return -1;
  }

  if (gif_reassembly_checkpoint_requested()) {
    gif_reassembly_store_state(candidate, state);
    return -1;
  }

  candidate_actual = state->reassembly_actual_run_rescue_next;
  run_start_actual = state->reassembly_actual_run_rescue_start;
  candidate_apparent =
      filemirror_apparent_blocknumber(scalpel_state.filemirror,
                                      candidate_actual);
  gif_reassembly_clear_actual_run_rescue(state);
  gif_reassembly_store_state(candidate, state);

  if (candidate_apparent < 0
      || apparent_block_in_blockvector(candidate->b, candidate_apparent)
      || !gif_reassembly_actual_block_is_giflike(candidate, candidate_actual)
      || !gif_reassembly_slot_allows_choice(candidate, slot,
                                            candidate_apparent)) {
    return -1;
  }

  if (gif_reassembly_debug_candidate(candidate)) {
    fprintf(stderr,
            "[gifdbg] actual-run-rescue start=%" PRId64
            " anchor_actual=%" PRId64 " run_start=%" PRId64
            " choice=%" PRId64 " actual=%" PRId64 "\n",
            blockvector_get_actual_blocknumber(candidate->b, 0),
            previous_actualblocknumber,
            run_start_actual,
            candidate_apparent, candidate_actual);
  }
  return candidate_apparent;
}

static inline bool gif_reassembly_finalize_phase_hint(
    uint64_t offset, uint8_t max_subblock_len, uint32_t headers_seen,
    uint32_t *offset_out, uint8_t *threshold_out) {
  uint64_t required_span;

  if (!offset_out || !threshold_out
      || scalpel_state.blocksize == 0
      || offset >= scalpel_state.blocksize
      || headers_seen < 2
      || max_subblock_len < GIF_REASSEMBLY_PHASE_MIN_MAX_SUBBLOCK) {
    return false;
  }

  *threshold_out =
      max_subblock_len > GIF_REASSEMBLY_PHASE_THRESHOLD_SLACK
          ? (uint8_t)(max_subblock_len - GIF_REASSEMBLY_PHASE_THRESHOLD_SLACK)
          : max_subblock_len;
  if (*threshold_out == 0) {
    return false;
  }

  required_span =
      (uint64_t)(*threshold_out + 1) * GIF_REASSEMBLY_PHASE_MIN_HEADERS;
  if (offset > (uint64_t)scalpel_state.blocksize
      || required_span > (uint64_t)scalpel_state.blocksize - offset) {
    return false;
  }

  *offset_out = (uint32_t)offset;
  return true;
}

static inline bool gif_reassembly_scan_subblocks_for_phase(
    const unsigned char *data, uint64_t length, uint64_t *pos,
    uint8_t *max_subblock_len, uint32_t *headers_seen,
    uint32_t *offset_out, uint8_t *threshold_out) {

  if (!data || !pos || !max_subblock_len || !headers_seen
      || !offset_out || !threshold_out) {
    return false;
  }

  while (*pos < length) {
    uint8_t subblock_len = data[*pos];
    uint64_t payload_end;

    if (subblock_len == 0) {
      (*pos)++;
      return false;
    }

    if (subblock_len > *max_subblock_len) {
      *max_subblock_len = subblock_len;
    }
    if (*headers_seen < UINT32_MAX) {
      (*headers_seen)++;
    }

    if (*pos > UINT64_MAX - 1U - (uint64_t)subblock_len) {
      return false;
    }
    payload_end = *pos + 1U + (uint64_t)subblock_len;

    if (payload_end >= length) {
      return gif_reassembly_finalize_phase_hint(
          payload_end - length, *max_subblock_len, *headers_seen,
          offset_out, threshold_out);
    }

    *pos = payload_end;
  }

  return gif_reassembly_finalize_phase_hint(
      0, *max_subblock_len, *headers_seen, offset_out, threshold_out);
}

static inline bool gif_reassembly_subblock_phase_from_data(
    const unsigned char *data, uint64_t length, uint32_t *offset_out,
    uint8_t *threshold_out) {
  uint64_t pos = 13;
  uint64_t table_size;
  uint8_t image_max_subblock_len = 0;
  uint32_t image_headers_seen = 0;

  if (!data || !offset_out || !threshold_out || length < 13
      || data[0] != 'G' || data[1] != 'I' || data[2] != 'F') {
    return false;
  }

  if (data[10] & 0x80) {
    table_size = 3U * (1ULL << ((data[10] & 0x07) + 1));
    if (pos > UINT64_MAX - table_size) {
      return false;
    }
    pos += table_size;
  }

  while (pos < length) {
    uint8_t marker = data[pos];

    if (marker == 0x3B) {
      return false;
    }

    if (marker == 0x21) {
      uint8_t extension_max_subblock_len = 0;
      uint32_t extension_headers_seen = 0;

      if (pos > UINT64_MAX - 2U || pos + 2U > length) {
        return false;
      }
      pos += 2U;
      if (gif_reassembly_scan_subblocks_for_phase(
              data, length, &pos, &extension_max_subblock_len,
              &extension_headers_seen, offset_out, threshold_out)) {
        return true;
      }
      continue;
    }

    if (marker == 0x2C) {
      uint8_t packed;

      if (pos > UINT64_MAX - 10U || pos + 10U > length) {
        return false;
      }
      packed = data[pos + 9U];
      pos += 10U;
      if (packed & 0x80) {
        table_size = 3U * (1ULL << ((packed & 0x07) + 1));
        if (pos > UINT64_MAX - table_size || pos + table_size > length) {
          if (pos > UINT64_MAX - table_size - 1U) {
            return false;
          }
          return gif_reassembly_finalize_phase_hint(
              pos + table_size + 1U - length,
              image_max_subblock_len, image_headers_seen,
              offset_out, threshold_out);
        }
        pos += table_size;
      }

      if (pos >= length) {
        return gif_reassembly_finalize_phase_hint(
            pos + 1U - length, image_max_subblock_len,
            image_headers_seen, offset_out, threshold_out);
      }
      pos++;
      if (gif_reassembly_scan_subblocks_for_phase(
              data, length, &pos, &image_max_subblock_len,
              &image_headers_seen, offset_out, threshold_out)) {
        return true;
      }
      continue;
    }

    return false;
  }

  return false;
}

static inline bool gif_reassembly_get_phase_hint(
    CarveInfo *candidate, GIFCarveState *state, uint32_t *offset_out,
    uint8_t *threshold_out) {
  uint64_t data_length;
  GIFCarveState cold_state = {0};
  GIFCarveState runtime_state = {0};
  GIFValidationSummary cold_summary = {0};

  if (!candidate || !state || !offset_out || !threshold_out) {
    return false;
  }

  data_length = blockvector_get_data_length(candidate->b);
  if (state->reassembly_phase_hint_checked
      && state->reassembly_phase_hint_length == data_length) {
    if (!state->reassembly_phase_hint_valid) {
      return false;
    }
    *offset_out = state->reassembly_phase_hint_offset;
    *threshold_out = state->reassembly_phase_hint_threshold;
    return true;
  }

  // A speculative plateau can move the committed prefix beyond the saved
  // decoder snapshot. Refresh once for this prefix length before evaluating
  // displaced blocks, then retain all reassembly bookkeeping.
  runtime_state = *state;
  gif_reassembly_validate_local_probe(candidate, &cold_state, &cold_summary);
  if (gif_reassembly_debug_candidate(candidate)) {
    lock_fprintf(stderr,
            "[gifdbg] phase-state-refresh start=%" PRId64
            " length=%" PRIu64 " validates=%d validates_to=%" PRIu64
            " state_valid=%d checkpoint=%" PRIu64
            " snap_valid=%d snap_pos=%" PRIu64 " hash=%" PRIu64 "\n",
            blockvector_get_actual_blocknumber(candidate->b, 0),
            data_length, cold_summary.validates ? 1 : 0,
            cold_summary.validates_to, cold_state.valid ? 1 : 0,
            cold_state.checkpoint_curpos, cold_state.snap_valid ? 1 : 0,
            cold_state.snap_pos,
            XXH3_64bits(blockvector_get_data_pointer(candidate->b),
                        data_length));
  }
  gif_reassembly_copy_runtime_fields(&cold_state, &runtime_state);
  *state = cold_state;

  state->reassembly_phase_hint_checked = true;
  state->reassembly_phase_hint_valid = false;
  state->reassembly_phase_hint_length = data_length;
  state->reassembly_phase_hint_offset = 0;
  state->reassembly_phase_hint_threshold = 0;
  state->reassembly_phase_scan_exhausted = false;
  state->reassembly_phase_scan_exhausted_length = 0;

  if (gif_reassembly_subblock_phase_from_data(
          (const unsigned char *)blockvector_get_data_pointer(candidate->b),
          data_length, offset_out, threshold_out)) {
    state->reassembly_phase_hint_valid = true;
    state->reassembly_phase_hint_offset = *offset_out;
    state->reassembly_phase_hint_threshold = *threshold_out;
    gif_reassembly_store_state(candidate, state);
    return true;
  }

  gif_reassembly_store_state(candidate, state);
  return false;
}

static inline bool gif_reassembly_block_matches_phase_hint(
    int64_t apparentblocknumber, uint32_t offset, uint8_t threshold) {
  uint64_t pos = offset;

  if (apparentblocknumber < 0
      || threshold == 0
      || scalpel_state.blocksize == 0
      || offset >= scalpel_state.blocksize) {
    return false;
  }

  if (gif_reassembly_block_matches_phase_transition(apparentblocknumber,
                                                    offset)) {
    return true;
  }

  for (uint32_t hits = 0; hits < GIF_REASSEMBLY_PHASE_MIN_HEADERS; hits++) {
    unsigned char subblock_len = 0;

    if (pos >= scalpel_state.blocksize
        || !get_apparent_block_bytes(scalpel_state.filemirror,
                                     apparentblocknumber, pos, 1,
                                     &subblock_len)
        || subblock_len < threshold) {
      return false;
    }

    pos += 1U + (uint64_t)subblock_len;
  }

  return true;
}

static inline bool gif_reassembly_block_phase_continuation(
    int64_t apparentblocknumber, uint32_t offset, uint8_t threshold,
    uint32_t minimum_headers, uint32_t *next_offset_out) {
  uint64_t pos = offset;
  uint32_t headers = 0;

  if (apparentblocknumber < 0
      || threshold == 0
      || minimum_headers == 0
      || !next_offset_out
      || scalpel_state.blocksize == 0
      || offset >= scalpel_state.blocksize) {
    return false;
  }

  while (pos < scalpel_state.blocksize) {
    unsigned char subblock_len = 0;

    if (!get_apparent_block_bytes(scalpel_state.filemirror,
                                  apparentblocknumber, pos, 1,
                                  &subblock_len)
        || subblock_len < threshold
        || pos > UINT64_MAX - 1U - (uint64_t)subblock_len) {
      return false;
    }

    pos += 1U + (uint64_t)subblock_len;
    headers++;
  }

  if (headers < minimum_headers
      || pos - (uint64_t)scalpel_state.blocksize
             >= (uint64_t)scalpel_state.blocksize) {
    return false;
  }

  *next_offset_out =
      (uint32_t)(pos - (uint64_t)scalpel_state.blocksize);
  return true;
}

static inline bool gif_reassembly_block_matches_phase_transition(
    int64_t apparentblocknumber, uint32_t offset) {
  uint64_t pos = offset;

  if (apparentblocknumber < 0
      || scalpel_state.blocksize == 0
      || offset >= scalpel_state.blocksize) {
    return false;
  }

  for (uint32_t headers = 0;
       headers < GIF_REASSEMBLY_PHASE_MIN_HEADERS; headers++) {
    unsigned char subblock_len = 0;

    if (pos >= scalpel_state.blocksize
        || !get_apparent_block_bytes(scalpel_state.filemirror,
                                     apparentblocknumber, pos, 1,
                                     &subblock_len)) {
      return false;
    }

    if (subblock_len == 0) {
      unsigned char record[10] = {0};

      pos++;
      if (pos >= scalpel_state.blocksize
          || !get_apparent_block_bytes(scalpel_state.filemirror,
                                       apparentblocknumber, pos, 1,
                                       record)) {
        return false;
      }

      if (record[0] == 0x3B) {
        return true;
      }
      if (record[0] == 0x21) {
        if (pos + 2U > scalpel_state.blocksize
            || !get_apparent_block_bytes(scalpel_state.filemirror,
                                         apparentblocknumber, pos, 2,
                                         record)) {
          return false;
        }
        return record[1] == 0x01 || record[1] == 0xF9
               || record[1] == 0xFE || record[1] == 0xFF;
      }
      if (record[0] == 0x2C) {
        if (pos + sizeof(record) > scalpel_state.blocksize
            || !get_apparent_block_bytes(scalpel_state.filemirror,
                                         apparentblocknumber, pos,
                                         sizeof(record), record)) {
          return false;
        }
        return (record[5] != 0 || record[6] != 0)
               && (record[7] != 0 || record[8] != 0);
      }
      return false;
    }

    if (pos > UINT64_MAX - 1U - (uint64_t)subblock_len) {
      return false;
    }
    pos += 1U + (uint64_t)subblock_len;
  }

  return false;
}

static inline bool gif_reassembly_block_matches_phase_probe_hint(
    int64_t apparentblocknumber, uint32_t offset, uint8_t threshold) {
  uint64_t pos = offset;

  if (apparentblocknumber < 0
      || threshold == 0
      || scalpel_state.blocksize == 0
      || offset >= scalpel_state.blocksize) {
    return false;
  }

  if (gif_reassembly_block_matches_phase_transition(apparentblocknumber,
                                                    offset)) {
    return true;
  }

  for (uint32_t hits = 0; hits < GIF_REASSEMBLY_PHASE_PROBE_MIN_HEADERS;
       hits++) {
    unsigned char subblock_len = 0;

    if (pos >= scalpel_state.blocksize
        || !get_apparent_block_bytes(scalpel_state.filemirror,
                                     apparentblocknumber, pos, 1,
                                     &subblock_len)
        || subblock_len < threshold) {
      return false;
    }

    pos += 1U + (uint64_t)subblock_len;
  }

  return true;
}

static inline uint32_t gif_reassembly_committed_actual_gap_count(
    CarveInfo *candidate, uint64_t data_length) {
  uint64_t committed_blocks;
  uint64_t num_blocks;
  uint32_t gaps = 0;
  int64_t previous_actual = -1;

  if (!candidate || scalpel_state.blocksize == 0 || data_length == 0) {
    return 0;
  }

  committed_blocks = CEILDIV(data_length, scalpel_state.blocksize);
  num_blocks = blockvector_get_num_blocks(candidate->b);
  if (committed_blocks > num_blocks) {
    committed_blocks = num_blocks;
  }

  for (uint64_t i = 0; i < committed_blocks; i++) {
    int64_t actualblocknumber =
        blockvector_get_actual_blocknumber(candidate->b, i);

    if (actualblocknumber < 0) {
      continue;
    }

    if (previous_actual >= 0 && actualblocknumber != previous_actual + 1) {
      if (gaps < UINT32_MAX) {
        gaps++;
      }
    }
    previous_actual = actualblocknumber;
  }

  return gaps;
}

static inline int64_t gif_reassembly_phase_choice(
    CarveInfo *candidate, uint64_t slot, int64_t scan_start,
    int64_t scan_count, int64_t previous_apparentblocknumber,
    GIFCarveState *state, int64_t *resume_after_out) {
  int64_t apparent_blocks;
  int64_t toconsider;
  int64_t local_forward_cutoff = -1;
  uint32_t phase_offset = 0;
  uint8_t phase_threshold = 0;
  bool wrap_prefix_first = false;

  if (resume_after_out) {
    *resume_after_out = -1;
  }

  if (!candidate || !state
      || gif_reassembly_committed_actual_gap_count(
             candidate, blockvector_get_data_length(candidate->b))
             < GIF_REASSEMBLY_PHASE_MIN_PRIOR_GAPS
      || !gif_reassembly_get_phase_hint(
             candidate, state, &phase_offset, &phase_threshold)) {
    return -1;
  }

  if (state->reassembly_phase_scan_exhausted
      && state->reassembly_phase_scan_exhausted_length
             == blockvector_get_data_length(candidate->b)) {
    return -1;
  }

  apparent_blocks =
      (int64_t)filemirror_apparent_blocks(scalpel_state.filemirror);
  if (apparent_blocks <= 0) {
    return -1;
  }

  if (scan_start < 0) {
    scan_start = 0;
  }
  scan_start %= apparent_blocks;
  if (scan_start < 0) {
    scan_start += apparent_blocks;
  }
  toconsider = scan_count > 0 ? scan_count : apparent_blocks;
  if (toconsider > apparent_blocks) {
    toconsider = apparent_blocks;
  }

  if (previous_apparentblocknumber >= 0) {
    local_forward_cutoff =
        previous_apparentblocknumber + GIF_REASSEMBLY_GAP_SCAN_WINDOW;
    wrap_prefix_first =
        local_forward_cutoff < apparent_blocks
        && scan_start > local_forward_cutoff;
  }

  for (int pass = 0; pass < (wrap_prefix_first ? 2 : 1); pass++) {
    int64_t pass_start = scan_start;
    int64_t pass_count = toconsider;

    if (wrap_prefix_first) {
      if (pass == 0) {
        pass_start = 0;
        pass_count = previous_apparentblocknumber + 1;
        if (pass_count > apparent_blocks) {
          pass_count = apparent_blocks;
        }
      }
      else {
        pass_start = scan_start;
        pass_count = apparent_blocks - scan_start;
      }
    }

    for (int64_t j = 0; j < pass_count; j++) {
      int64_t apparentblocknumber = (pass_start + j) % apparent_blocks;
      int64_t actualblocknumber;

      if (gif_reassembly_checkpoint_requested()) {
        gif_reassembly_store_state(candidate, state);
        return -1;
      }

      if (previous_apparentblocknumber >= 0
          && apparentblocknumber > previous_apparentblocknumber
          && apparentblocknumber <= local_forward_cutoff) {
        continue;
      }

      if (!gif_reassembly_slot_allows_choice(candidate, slot,
                                             apparentblocknumber)
          || apparent_block_in_blockvector(candidate->b, apparentblocknumber)
          || !gif_reassembly_block_matches_phase_hint(
                 apparentblocknumber, phase_offset, phase_threshold)) {
        continue;
      }

      actualblocknumber =
          filemirror_actual_blocknumber(scalpel_state.filemirror,
                                        apparentblocknumber);
      if (!gif_reassembly_actual_block_is_giflike(candidate,
                                                  actualblocknumber)) {
        continue;
      }

      if (resume_after_out) {
        *resume_after_out = (apparentblocknumber + 1) % apparent_blocks;
      }
      state->reassembly_phase_scan_exhausted = false;
      state->reassembly_phase_scan_exhausted_length = 0;
      gif_reassembly_store_state(candidate, state);

      if (gif_reassembly_debug_candidate(candidate)) {
        fprintf(stderr,
                "[gifdbg] phase-choice start=%" PRId64
                " prev=%" PRId64 " choice=%" PRId64
                " actual=%" PRId64 " offset=%u threshold=%u\n",
                blockvector_get_actual_blocknumber(candidate->b, 0),
                previous_apparentblocknumber, apparentblocknumber,
                actualblocknumber, phase_offset, phase_threshold);
      }
      return apparentblocknumber;
    }
  }

  state->reassembly_phase_scan_exhausted = true;
  state->reassembly_phase_scan_exhausted_length =
      blockvector_get_data_length(candidate->b);
  gif_reassembly_store_state(candidate, state);
  return -1;
}

static inline int64_t gif_reassembly_actual_backscan_choice(
    CarveInfo *candidate, uint64_t slot, int64_t previous_actualblocknumber,
    GIFCarveState *state) {
  int64_t actual_blocks;
  int64_t floor_actual;
  int64_t actualblocknumber;

  if (!candidate || !state || previous_actualblocknumber <= 0
      || scalpel_state.blocksize == 0) {
    return -1;
  }

  actual_blocks = (int64_t)CEILDIV(filemirror_filesize(scalpel_state.filemirror),
                                   (uint64_t)scalpel_state.blocksize);
  if (actual_blocks <= 0) {
    return -1;
  }

  if (previous_actualblocknumber >= actual_blocks) {
    previous_actualblocknumber = actual_blocks - 1;
  }

  floor_actual =
      previous_actualblocknumber > GIF_REASSEMBLY_ACTUAL_BACKSCAN_WINDOW
          ? previous_actualblocknumber - GIF_REASSEMBLY_ACTUAL_BACKSCAN_WINDOW
          : 0;

  if (!state->reassembly_actual_backscan_active
      || state->reassembly_actual_backscan_anchor != previous_actualblocknumber
      || state->reassembly_actual_backscan_next < floor_actual
      || state->reassembly_actual_backscan_next >= previous_actualblocknumber) {
    state->reassembly_actual_backscan_active = true;
    state->reassembly_actual_backscan_anchor = previous_actualblocknumber;
    state->reassembly_actual_backscan_next = previous_actualblocknumber - 1;
  }

  for (actualblocknumber = state->reassembly_actual_backscan_next;
       actualblocknumber >= floor_actual; --actualblocknumber) {
    int64_t apparentblocknumber;

    state->reassembly_actual_backscan_next = actualblocknumber - 1;

    if (gif_reassembly_checkpoint_requested()) {
      gif_reassembly_store_state(candidate, state);
      return -1;
    }

    if (!gif_reassembly_actual_block_starts_giflike_run(candidate,
                                                        actualblocknumber)) {
      continue;
    }

    apparentblocknumber =
        filemirror_apparent_blocknumber(scalpel_state.filemirror,
                                        actualblocknumber);
    if (apparentblocknumber < 0
        || apparent_block_in_blockvector(candidate->b, apparentblocknumber)
        || !gif_reassembly_slot_allows_choice(candidate, slot,
                                              apparentblocknumber)) {
      continue;
    }

    gif_reassembly_store_state(candidate, state);
    if (gif_reassembly_debug_candidate(candidate)) {
      fprintf(stderr,
              "[gifdbg] actual-backscan start=%" PRId64
              " anchor_actual=%" PRId64 " choice=%" PRId64
              " actual=%" PRId64 " next_actual=%" PRId64 "\n",
              blockvector_get_actual_blocknumber(candidate->b, 0),
              previous_actualblocknumber, apparentblocknumber,
              filemirror_actual_blocknumber(scalpel_state.filemirror,
                                            apparentblocknumber),
              state->reassembly_actual_backscan_next);
    }
    return apparentblocknumber;
  }

  state->reassembly_actual_backscan_active = false;
  state->reassembly_actual_backscan_anchor = -1;
  state->reassembly_actual_backscan_next = -1;
  gif_reassembly_store_state(candidate, state);
  return -1;
}

static inline bool gif_reassembly_should_try_actual_backscan(
    const GIFCarveState *state, int64_t previous_apparentblocknumber,
    int64_t previous_actualblocknumber, int64_t local_gap_start,
    bool prestart_scan_active, int64_t block_choice_start) {
  if (!state
      || previous_apparentblocknumber < 0
      || previous_actualblocknumber < 0
      || local_gap_start >= 0
      || prestart_scan_active
      || block_choice_start < previous_apparentblocknumber + 1
                                + GIF_REASSEMBLY_GAP_SCAN_WINDOW) {
    return false;
  }

  if (state->reassembly_actual_backscan_active
      || state->reassembly_prefix_anchor_trials
             >= GIF_REASSEMBLY_PREFIX_ANCHORS_BEFORE_BACKSCAN) {
    return true;
  }

  return state->reassembly_return_pending
         || gif_reassembly_effective_plateau_blocks(state) > 0;
}

static inline bool gif_reassembly_actual_backscan_should_yield_to_anchor(
    CarveInfo *candidate, const GIFCarveState *state,
    int64_t previous_actualblocknumber) {
  if (!candidate
      || !candidate->b
      || blockvector_get_num_blocks(candidate->b)
             < GIF_REASSEMBLY_ACTUAL_BACKSCAN_ANCHOR_YIELD_MIN_BLOCKS
      || !state
      || !state->reassembly_actual_backscan_active
      || state->reassembly_actual_backscan_anchor != previous_actualblocknumber
      || state->reassembly_actual_backscan_next < 0
      || previous_actualblocknumber < state->reassembly_actual_backscan_next) {
    return false;
  }

  return previous_actualblocknumber - state->reassembly_actual_backscan_next
         >= GIF_REASSEMBLY_ACTUAL_BACKSCAN_ANCHOR_YIELD_DISTANCE;
}

static inline void gif_reassembly_arm_actual_backscan(CarveInfo *candidate) {
  GIFCarveState gif_state = {0};

  if (!candidate) {
    return;
  }

  gif_reassembly_load_state_raw(candidate, &gif_state);
  if (gif_state.reassembly_prefix_anchor_trials
      < GIF_REASSEMBLY_PREFIX_ANCHORS_BEFORE_BACKSCAN) {
    gif_state.reassembly_prefix_anchor_trials =
        GIF_REASSEMBLY_PREFIX_ANCHORS_BEFORE_BACKSCAN;
    gif_reassembly_store_state(candidate, &gif_state);
  }
}

static inline uint64_t gif_reassembly_score_covered_length(
    const GIFReassemblyScore *score) {
  uint64_t covered = 0;

  if (!score) {
    return 0;
  }

  covered = score->checkpoint_curpos + 1;
  if (score->last_good_row_pos + 1 > covered) {
    covered = score->last_good_row_pos + 1;
  }
  if (score->last_normal_pos + 1 > covered) {
    covered = score->last_normal_pos + 1;
  }

  return covered;
}

static inline void gif_reassembly_clamp_nonvalidated_summary(
    uint64_t oldlength, GIFValidationSummary *summary) {
  uint64_t covered;
  uint64_t slack = 0;
  uint64_t limit;

  if (!summary || summary->validates) {
    return;
  }

  // Reassembly trials always extend a prefix that is already committed in the
  // candidate. A failed extension must not score below that trusted prefix or
  // the chooser/backtracker will under-value correct branches and compare
  // remote follow-on probes against a regressed baseline.
  if (oldlength > 0 && summary->validates_to + 1 < oldlength) {
    summary->validates_to = oldlength - 1;
    return;
  }

  if (summary->validates_to + 1 == oldlength) {
    return;
  }

  covered = gif_reassembly_score_covered_length(&summary->score);
  if (covered < oldlength) {
    covered = oldlength;
  }

  if (scalpel_state.blocksize > 0) {
    slack = (uint64_t)scalpel_state.blocksize;
  }

  limit = covered;
  if (UINT64_MAX - limit < slack) {
    limit = UINT64_MAX;
  }
  else {
    limit += slack;
  }

  if (summary->validates_to + 1 > limit) {
    summary->validates_to = limit > 0 ? limit - 1 : 0;
  }
}

static inline void gif_reassembly_probe_score(
    int id, CarveInfo *candidate, uint64_t oldlength,
    const GIFCarveState *base_state, int64_t actualblocknumber,
    GIFValidationSummary *summary_out) {
  uint64_t slot = blockvector_get_num_blocks(candidate->b) - 1;
  int64_t saved_apparent =
      blockvector_get_apparent_blocknumber(candidate->b, slot);
  int64_t probe_apparent =
      filemirror_apparent_blocknumber(scalpel_state.filemirror,
                                      actualblocknumber);
  GIFCarveState trial_state = {0};

  deflate_blockvector_single_block(candidate->b, slot, oldlength);
  blockvector_set_apparent_blocknumber(candidate->b, slot, probe_apparent);
  inflate_blockvector_single_block(candidate->b, slot);

  if (base_state) {
    trial_state = *base_state;
  }
  gif_reassembly_validate_local_probe(candidate, &trial_state, summary_out);

  (void)id;

  deflate_blockvector_single_block(candidate->b, slot, oldlength);
  blockvector_set_apparent_blocknumber(candidate->b, slot, saved_apparent);
  if (saved_apparent >= 0) {
    inflate_blockvector_single_block(candidate->b, slot);
  }
}

static inline bool gif_reassembly_probe_followon(
    int id, CarveInfo *candidate, uint64_t oldlength,
    const GIFCarveState *base_state, int64_t actualblocknumber,
    GIFValidationSummary *summary_out) {
  uint64_t slot = blockvector_get_num_blocks(candidate->b) - 1;
  uint64_t old_blocks = blockvector_get_num_blocks(candidate->b);
  int64_t saved_apparent =
      blockvector_get_apparent_blocknumber(candidate->b, slot);
  int64_t probe_apparent =
      filemirror_apparent_blocknumber(scalpel_state.filemirror,
                                      actualblocknumber);
  int64_t follow_apparent = probe_apparent + 1;
  int64_t follow_actual;
  uint64_t apparent_blocks =
      filemirror_apparent_blocks(scalpel_state.filemirror);
  uint64_t first_oldlength;
  uint64_t second_oldlength;
  GIFCarveState trial_state = {0};
  bool ok = false;

  memset(summary_out, 0, sizeof(*summary_out));

  if (follow_apparent < 0
      || (uint64_t)follow_apparent >= apparent_blocks
      || apparent_block_in_blockvector(candidate->b, follow_apparent)) {
    return false;
  }

  follow_actual =
      filemirror_actual_blocknumber(scalpel_state.filemirror, follow_apparent);
  if (follow_actual < 0
      || filemirror_get_blocktype(scalpel_state.filemirror, follow_actual,
                                  candidate->needleidx) == BLOCK_CONFIDENCE_INVALID
      || filemirror_actual_block_covered(scalpel_state.filemirror,
                                         follow_actual)) {
    return false;
  }

  if (gif_reassembly_checkpoint_requested()) {
    return false;
  }

  deflate_blockvector_single_block(candidate->b, slot, oldlength);
  blockvector_set_apparent_blocknumber(candidate->b, slot, probe_apparent);
  first_oldlength = inflate_blockvector_single_block(candidate->b, slot);

  resize_blockvector(candidate->b, old_blocks + 1);
  blockvector_set_apparent_blocknumber(candidate->b, old_blocks, follow_apparent);
  second_oldlength = inflate_blockvector_single_block(candidate->b, old_blocks);

  if (base_state) {
    trial_state = *base_state;
  }
  gif_reassembly_validate_local_probe(candidate, &trial_state, summary_out);

  (void)id;
  ok = true;

  deflate_blockvector_single_block(candidate->b, old_blocks, second_oldlength);
  resize_blockvector(candidate->b, old_blocks);
  deflate_blockvector_single_block(candidate->b, slot, first_oldlength);
  blockvector_set_apparent_blocknumber(candidate->b, slot, saved_apparent);
  if (saved_apparent >= 0) {
    inflate_blockvector_single_block(candidate->b, slot);
  }
  return ok;
}

static inline bool gif_reassembly_probe_nonlocal_return(
    int id, CarveInfo *candidate, uint64_t oldlength,
    const GIFCarveState *base_state, int64_t actualblocknumber,
    int64_t previous_apparentblocknumber, int64_t return_scan_window,
    bool matching_gap_only, bool allow_return_regression,
    uint32_t return_confirm_blocks,
    GIFValidationSummary *summary_out, uint32_t *chain_blocks_out,
    uint32_t *return_blocks_out, int64_t *return_start_out) {
  uint64_t slot = blockvector_get_num_blocks(candidate->b) - 1;
  uint64_t old_blocks = blockvector_get_num_blocks(candidate->b);
  uint64_t apparent_blocks =
      filemirror_apparent_blocks(scalpel_state.filemirror);
  int64_t saved_apparent =
      blockvector_get_apparent_blocknumber(candidate->b, slot);
  int64_t first_apparent =
      filemirror_apparent_blocknumber(scalpel_state.filemirror,
                                      actualblocknumber);
  int64_t return_start = -1;
  uint64_t first_oldlength = 0;
  uint64_t chain_oldlengths[GIF_REASSEMBLY_NONLOCAL_CHAIN_PROBE_BLOCKS - 1] = {0};
  uint32_t chain_blocks = 1;
  uint32_t best_chain_blocks = 1;
  uint32_t best_return_blocks = 0;
  int64_t best_return_start = -1;
  uint32_t chain_phase_offset = 0;
  bool chain_phase_valid = false;
  GIFCarveState chain_state = {0};
  GIFCarveState trial_state = {0};
  GIFValidationSummary chain_summary = {0};
  GIFValidationSummary best_summary = {0};
  GIFValidationSummary trial_summary = {0};
  bool ok = false;
  bool classified_chain_start = false;
  bool strict_return_proof =
      allow_return_regression
      || (base_state && base_state->reassembly_return_pending);

  memset(summary_out, 0, sizeof(*summary_out));
  if (chain_blocks_out) {
    *chain_blocks_out = 0;
  }
  if (return_blocks_out) {
    *return_blocks_out = 0;
  }
  if (return_start_out) {
    *return_start_out = -1;
  }
  (void)id;

  if (!candidate || previous_apparentblocknumber < 0
      || first_apparent < 0 || apparent_blocks == 0
      || return_scan_window <= 0 || return_confirm_blocks == 0
      || return_confirm_blocks
             > GIF_REASSEMBLY_DEEP_RETURN_CONFIRM_BLOCKS) {
    return false;
  }

  if ((uint64_t)return_scan_window > apparent_blocks) {
    return_scan_window = (int64_t)apparent_blocks;
  }

  if (base_state && base_state->reassembly_return_pending
      && base_state->reassembly_return_start >= 0) {
    return_start = base_state->reassembly_return_start;
  }
  else {
    return_start = previous_apparentblocknumber + 1;
  }

  if (return_start < 0) {
    return false;
  }
  if ((uint64_t)return_start >= apparent_blocks) {
    return_start %= (int64_t)apparent_blocks;
    if (return_start < 0) {
      return_start += (int64_t)apparent_blocks;
    }
  }

  if (gif_reassembly_checkpoint_requested()) {
    return false;
  }

  classified_chain_start =
      filemirror_get_blocktype(scalpel_state.filemirror, actualblocknumber,
                               candidate->needleidx)
      == BLOCK_CONFIDENCE_VALID;

  deflate_blockvector_single_block(candidate->b, slot, oldlength);
  blockvector_set_apparent_blocknumber(candidate->b, slot, first_apparent);
  first_oldlength = inflate_blockvector_single_block(candidate->b, slot);

  if (base_state) {
    chain_state = *base_state;
  }
  gif_reassembly_validate_local_probe(candidate, &chain_state, &chain_summary);
  best_summary = chain_summary;
  if (base_state
      && base_state->reassembly_phase_hint_valid
      && base_state->reassembly_phase_hint_length == oldlength) {
    chain_phase_valid = gif_reassembly_block_phase_continuation(
        first_apparent, base_state->reassembly_phase_hint_offset,
        base_state->reassembly_phase_hint_threshold,
        GIF_REASSEMBLY_PHASE_PROBE_MIN_HEADERS, &chain_phase_offset);
  }
  ok = true;

  for (;;) {
    int64_t first_return_offset =
        matching_gap_only ? (int64_t)chain_blocks : 0;
    int64_t last_return_offset =
        matching_gap_only ? first_return_offset + 1 : return_scan_window;

    if (first_return_offset >= return_scan_window) {
      break;
    }

    for (int64_t j = first_return_offset;
         j < last_return_offset;
         ++j) {
      int64_t return_apparent =
          (return_start + j) % (int64_t)apparent_blocks;
      int64_t return_actual;
      uint64_t return_slot = old_blocks + (uint64_t)chain_blocks - 1;
      uint64_t return_oldlengths[
          GIF_REASSEMBLY_DEEP_RETURN_CONFIRM_BLOCKS] = {0};
      uint32_t return_blocks = 0;
      uint32_t last_probed_blocks = 0;
      GIFValidationSummary return_summary = {0};
      bool select_return = false;
      bool return_collides_with_chain = false;
      bool return_regressed = false;
      int summary_cmp;

      if (apparent_block_in_blockvector(candidate->b, return_apparent)) {
        continue;
      }

      return_actual =
          filemirror_actual_blocknumber(scalpel_state.filemirror,
                                        return_apparent);
      if (return_actual < 0
          || filemirror_get_blocktype(scalpel_state.filemirror, return_actual,
                                      candidate->needleidx)
                 == BLOCK_CONFIDENCE_INVALID
          || filemirror_actual_block_covered(scalpel_state.filemirror,
                                             return_actual)) {
        continue;
      }

      if (gif_reassembly_checkpoint_requested()) {
        break;
      }

      resize_blockvector(candidate->b, return_slot + 1);
      blockvector_set_apparent_blocknumber(candidate->b, return_slot,
                                           return_apparent);
      return_oldlengths[0] =
          inflate_blockvector_single_block(candidate->b, return_slot);
      trial_state = chain_state;
      gif_reassembly_validate_local_probe(candidate, &trial_state,
                                          &trial_summary);
      // A valid return can cross an LZW boundary that temporarily lowers the
      // parser score, so probe a short contiguous prefix before rejecting it.
      return_summary = trial_summary;
      return_blocks = 1;
      last_probed_blocks = 1;
      return_regressed =
          gif_reassembly_compare_probe_summary(&trial_summary,
                                               &chain_summary) < 0;
      if (return_regressed && !strict_return_proof) {
        deflate_blockvector_single_block(candidate->b, return_slot,
                                         return_oldlengths[0]);
        resize_blockvector(candidate->b, return_slot);
        continue;
      }
      while (!return_summary.validates
             && return_blocks < return_confirm_blocks) {
        int64_t next_return_apparent =
            (return_apparent + (int64_t)return_blocks)
            % (int64_t)apparent_blocks;
        int64_t next_return_actual;
        uint64_t next_return_slot = return_slot + return_blocks;

        if (apparent_block_in_blockvector(candidate->b,
                                          next_return_apparent)) {
          if (next_return_apparent >= first_apparent
              && (uint64_t)(next_return_apparent - first_apparent)
                     < chain_blocks) {
            return_collides_with_chain = true;
          }
          break;
        }

        next_return_actual = filemirror_actual_blocknumber(
            scalpel_state.filemirror, next_return_apparent);
        if (next_return_actual < 0
            || filemirror_get_blocktype(scalpel_state.filemirror,
                                        next_return_actual,
                                        candidate->needleidx)
                   == BLOCK_CONFIDENCE_INVALID
            || filemirror_actual_block_covered(scalpel_state.filemirror,
                                               next_return_actual)
            || gif_reassembly_checkpoint_requested()) {
          break;
        }

        resize_blockvector(candidate->b, next_return_slot + 1);
        blockvector_set_apparent_blocknumber(candidate->b, next_return_slot,
                                             next_return_apparent);
        return_oldlengths[return_blocks] =
            inflate_blockvector_single_block(candidate->b, next_return_slot);
        return_blocks++;

        // Validation cost grows with the return prefix. Probe powers of two
        // so long semantic plateaus require logarithmically many decoder
        // calls while still finding a short confirmation quickly.
        if ((return_blocks & (return_blocks - 1)) != 0
            && return_blocks < return_confirm_blocks) {
          continue;
        }

        trial_state = chain_state;
        gif_reassembly_validate_local_probe(candidate, &trial_state,
                                            &trial_summary);
        last_probed_blocks = return_blocks;
        return_summary = trial_summary;
        return_regressed =
            gif_reassembly_compare_probe_summary(&trial_summary,
                                                 &chain_summary) < 0;
        if (return_regressed
            && (!strict_return_proof
                || return_blocks
                       >= GIF_REASSEMBLY_RETURN_REGRESSION_PROBE_BLOCKS)) {
          break;
        }
      }

      if (!return_regressed && last_probed_blocks < return_blocks) {
        trial_state = chain_state;
        gif_reassembly_validate_local_probe(candidate, &trial_state,
                                            &trial_summary);
        last_probed_blocks = return_blocks;
        if (gif_reassembly_compare_probe_summary(&trial_summary,
                                                 &chain_summary) < 0) {
          return_regressed = true;
        }
        else {
          return_summary = trial_summary;
        }
      }

      // A return path that reaches its displaced chain would have to reuse
      // physical blocks, so it cannot represent a complete file.
      // GIF parsing can remain on a semantic plateau for several correct
      // blocks. Keep the bounded return trial only when the complete probe
      // eventually produces stronger evidence than the displaced chain.
      if ((strict_return_proof && return_collides_with_chain
           && !return_summary.validates)
          || return_regressed
          || (!return_summary.validates
              && gif_reassembly_compare_probe_summary(&return_summary,
                                                      &chain_summary) <= 0)) {
        while (return_blocks > 0) {
          uint64_t return_index = return_slot + return_blocks - 1;
          deflate_blockvector_single_block(
              candidate->b, return_index,
              return_oldlengths[return_blocks - 1]);
          resize_blockvector(candidate->b, return_index);
          return_blocks--;
        }
        continue;
      }

      summary_cmp = gif_reassembly_compare_probe_summary(
          &return_summary, &best_summary);

      if (return_summary.validates != best_summary.validates) {
        select_return = return_summary.validates;
      }
      else if ((return_blocks > 0) != (best_return_blocks > 0)) {
        select_return = return_blocks > 0;
      }
      else if (summary_cmp != 0) {
        select_return = summary_cmp > 0;
      }
      else if (return_blocks != best_return_blocks) {
        select_return = return_blocks > best_return_blocks;
      }
      else if (return_blocks > 0 && chain_blocks != best_chain_blocks) {
        select_return = chain_blocks < best_chain_blocks;
      }

      if (select_return) {
        best_summary = return_summary;
        best_chain_blocks = chain_blocks;
        best_return_blocks = return_blocks;
        best_return_start = return_apparent;
      }

      while (return_blocks > 0) {
        uint64_t return_index = return_slot + return_blocks - 1;
        deflate_blockvector_single_block(
            candidate->b, return_index,
            return_oldlengths[return_blocks - 1]);
        resize_blockvector(candidate->b, return_index);
        return_blocks--;
      }

      if (best_return_blocks == return_confirm_blocks
          && best_chain_blocks == chain_blocks) {
        break;
      }
    }

    if (best_summary.validates
        || chain_blocks >= GIF_REASSEMBLY_NONLOCAL_CHAIN_PROBE_BLOCKS) {
      break;
    }

    {
      int64_t next_apparent = first_apparent + (int64_t)chain_blocks;
      int64_t next_actual;
      uint64_t chain_slot = old_blocks + (uint64_t)chain_blocks - 1;
      uint64_t chain_oldlength;
      uint32_t next_chain_phase_offset = 0;
      bool next_chain_phase_valid = false;
      GIFCarveState prior_chain_state = chain_state;

      if ((uint64_t)next_apparent >= apparent_blocks
          || apparent_block_in_blockvector(candidate->b, next_apparent)) {
        break;
      }

      next_actual = filemirror_actual_blocknumber(scalpel_state.filemirror,
                                                  next_apparent);
      if (next_actual < 0
          || filemirror_get_blocktype(scalpel_state.filemirror, next_actual,
                                      candidate->needleidx)
                 == BLOCK_CONFIDENCE_INVALID
          || filemirror_actual_block_covered(scalpel_state.filemirror,
                                             next_actual)
          || gif_reassembly_checkpoint_requested()) {
        break;
      }

      resize_blockvector(candidate->b, chain_slot + 1);
      blockvector_set_apparent_blocknumber(candidate->b, chain_slot,
                                           next_apparent);
      chain_oldlength =
          inflate_blockvector_single_block(candidate->b, chain_slot);
      if (chain_phase_valid) {
        next_chain_phase_valid = gif_reassembly_block_phase_continuation(
            next_apparent, chain_phase_offset,
            base_state->reassembly_phase_hint_threshold,
            GIF_REASSEMBLY_PHASE_PROBE_MIN_HEADERS,
            &next_chain_phase_offset);
      }
      gif_reassembly_validate_local_probe(candidate, &chain_state,
                                          &trial_summary);
      int chain_cmp =
          gif_reassembly_compare_probe_summary(&trial_summary,
                                               &chain_summary);
      uint64_t required_chain_progress =
          scalpel_state.blocksize > GIF_REASSEMBLY_VALIDATE_SLACK
              ? (uint64_t)scalpel_state.blocksize
                    - GIF_REASSEMBLY_VALIDATE_SLACK
              : 1;
      bool chain_has_full_block_evidence =
          chain_summary.validates
          || (chain_summary.validates_to >= oldlength
              && chain_summary.validates_to - oldlength
                     >= required_chain_progress - 1);
      bool preserve_phase_plateau =
          chain_cmp == 0
          && (next_chain_phase_valid || chain_has_full_block_evidence
              || classified_chain_start);
      if (gif_reassembly_debug_candidate(candidate)) {
        lock_fprintf(stderr,
                "[gifdbg] phase-probe-chain start=%" PRId64
                " first=%" PRId64 " next=%" PRId64
                " blocks=%u cmp=%d phase=%d full=%d"
                " vt=%" PRIu64 " frames=%u checkpoint=%" PRIu64
                " good=%" PRIu64 " normal=%" PRIu64 "\n",
                blockvector_get_actual_blocknumber(candidate->b, 0),
                first_apparent, next_apparent, chain_blocks + 1,
                chain_cmp, next_chain_phase_valid ? 1 : 0,
                chain_has_full_block_evidence ? 1 : 0,
                trial_summary.validates_to,
                trial_summary.score.completed_frames,
                trial_summary.score.checkpoint_curpos,
                trial_summary.score.last_good_row_pos,
                trial_summary.score.last_normal_pos);
      }
      if (chain_cmp < 0 || (chain_cmp == 0 && !preserve_phase_plateau)) {
        chain_state = prior_chain_state;
        deflate_blockvector_single_block(candidate->b, chain_slot,
                                         chain_oldlength);
        resize_blockvector(candidate->b, chain_slot);
        break;
      }

      chain_oldlengths[chain_blocks - 1] = chain_oldlength;
      chain_summary = trial_summary;
      chain_phase_valid = next_chain_phase_valid;
      chain_phase_offset = next_chain_phase_offset;
      chain_blocks++;
      if (best_return_blocks == 0) {
        int best_cmp = gif_reassembly_compare_probe_summary(
            &chain_summary, &best_summary);

        // A phase-consistent chain remains useful structural evidence while
        // the decoder is between semantic checkpoints.
        if (best_cmp > 0
            || (best_cmp == 0
                && chain_phase_valid
                && chain_blocks > best_chain_blocks)) {
          best_summary = chain_summary;
          best_chain_blocks = chain_blocks;
        }
      }
    }
  }

  if (chain_blocks_out) {
    *chain_blocks_out = best_chain_blocks;
  }
  if (return_blocks_out) {
    *return_blocks_out = best_return_blocks;
  }
  if (return_start_out) {
    *return_start_out = best_return_start;
  }

  while (chain_blocks > 1) {
    uint64_t chain_slot = old_blocks + (uint64_t)chain_blocks - 2;
    deflate_blockvector_single_block(candidate->b, chain_slot,
                                     chain_oldlengths[chain_blocks - 2]);
    resize_blockvector(candidate->b, chain_slot);
    chain_blocks--;
  }

  deflate_blockvector_single_block(candidate->b, slot, first_oldlength);
  blockvector_set_apparent_blocknumber(candidate->b, slot, saved_apparent);
  if (saved_apparent >= 0) {
    inflate_blockvector_single_block(candidate->b, slot);
  }

  if (ok) {
    *summary_out = best_summary;
  }
  return ok;
}

static inline bool gif_reassembly_probe_nonlocal_potential(
    int id, CarveInfo *candidate, uint64_t oldlength,
    const GIFCarveState *base_state, int64_t actualblocknumber,
    int64_t previous_apparentblocknumber,
    GIFValidationSummary *summary_out) {
  GIFValidationSummary best_summary = {0};
  GIFValidationSummary trial_summary = {0};
  bool allow_return_regression = false;
  bool ok = false;

  memset(summary_out, 0, sizeof(*summary_out));
  allow_return_regression =
      gif_reassembly_committed_actual_gap_count(candidate, oldlength) > 0
      && filemirror_get_blocktype(scalpel_state.filemirror,
                                  actualblocknumber,
                                  candidate->needleidx)
             == BLOCK_CONFIDENCE_VALID;

  ok = gif_reassembly_probe_followon(id, candidate, oldlength, base_state,
                                     actualblocknumber, &best_summary);
  if (gif_reassembly_probe_nonlocal_return(id, candidate, oldlength,
                                           base_state, actualblocknumber,
                                           previous_apparentblocknumber,
                                           GIF_REASSEMBLY_RETURN_SCAN_WINDOW,
                                           false, allow_return_regression,
                                           GIF_REASSEMBLY_RETURN_CONFIRM_BLOCKS,
                                           &trial_summary, NULL, NULL, NULL)
      && (!ok
          || gif_reassembly_compare_probe_summary(&trial_summary,
                                                  &best_summary) > 0)) {
    best_summary = trial_summary;
    ok = true;
  }

  if (ok) {
    *summary_out = best_summary;
  }
  return ok;
}

static inline int64_t gif_reassembly_phase_probe_choice(
    CarveInfo *candidate, uint64_t slot, int64_t scan_start,
    int64_t scan_count, int64_t previous_apparentblocknumber,
    GIFCarveState *state, int64_t *resume_after_out,
    bool include_local_forward) {
  int64_t apparent_blocks;
  int64_t toconsider;
  int64_t local_forward_cutoff = -1;
  int64_t best_choice = -1;
  int64_t best_reserved = INT64_MAX;
  BlockValidationDecision best_confidence = BLOCK_CONFIDENCE_INVALID;
  uint32_t phase_offset = 0;
  uint8_t phase_threshold = 0;
  uint64_t oldlength;
  uint64_t required_validates_to;
  uint64_t minimum_probe_validates_to;
  uint32_t probes = 0;
  uint32_t probe_limit = GIF_REASSEMBLY_PHASE_PROBE_SCAN_LIMIT;
  bool wrap_prefix_first = false;
  bool backfill_mode = false;
  bool deep_return_mode = false;
  bool classified_anchor_pass = false;
  uint32_t best_chain_blocks = UINT32_MAX;
  uint32_t best_return_blocks = 0;
  int64_t best_return_start = -1;
  bool best_local_chain_proven = false;
  bool best_local_chain_progress = false;
  bool best_overlaps_return_window = false;
  bool strict_phase_proof =
      include_local_forward
      || (state && state->reassembly_return_pending);
  GIFValidationSummary best_probe_summary = {0};

  if (resume_after_out) {
    *resume_after_out = -1;
  }

  if (!candidate || !state || scalpel_state.blocksize <= 0) {
    return -1;
  }

  oldlength = blockvector_get_data_length(candidate->b);
  classified_anchor_pass = include_local_forward;
  if (state->reassembly_phase_scan_exhausted
      && state->reassembly_phase_scan_exhausted_length == oldlength) {
    if (gif_reassembly_debug_candidate(candidate)) {
      fprintf(stderr,
              "[gifdbg] phase-probe-skip-exhausted start=%" PRId64
              " prev=%" PRId64 " scan_start=%" PRId64
              " oldlength=%" PRIu64 "\n",
              blockvector_get_actual_blocknumber(candidate->b, 0),
              previous_apparentblocknumber, scan_start, oldlength);
    }
    return -1;
  }

  if (!gif_reassembly_get_phase_hint(
             candidate, state, &phase_offset, &phase_threshold)) {
    state->reassembly_phase_scan_exhausted = true;
    state->reassembly_phase_scan_exhausted_length = oldlength;
    gif_reassembly_store_state(candidate, state);
    if (gif_reassembly_debug_candidate(candidate)) {
      fprintf(stderr,
              "[gifdbg] phase-probe-no-hint start=%" PRId64
              " prev=%" PRId64 " scan_start=%" PRId64
              " oldlength=%" PRIu64 "\n",
              blockvector_get_actual_blocknumber(candidate->b, 0),
              previous_apparentblocknumber, scan_start, oldlength);
    }
    return -1;
  }

  if (UINT64_MAX - oldlength
      < (uint64_t)scalpel_state.blocksize
             * GIF_REASSEMBLY_PHASE_PROBE_MIN_BLOCKS) {
    return -1;
  }
  required_validates_to =
      oldlength
      + (uint64_t)scalpel_state.blocksize
            * GIF_REASSEMBLY_PHASE_PROBE_MIN_BLOCKS
      - 1;
  minimum_probe_validates_to =
      oldlength + (uint64_t)scalpel_state.blocksize - 1;
  if (minimum_probe_validates_to >= GIF_REASSEMBLY_VALIDATE_SLACK) {
    minimum_probe_validates_to -= GIF_REASSEMBLY_VALIDATE_SLACK;
  }

  apparent_blocks =
      (int64_t)filemirror_apparent_blocks(scalpel_state.filemirror);
  if (apparent_blocks <= 0) {
    return -1;
  }

  if (scan_start < 0) {
    scan_start = 0;
  }
  scan_start %= apparent_blocks;
  if (scan_start < 0) {
    scan_start += apparent_blocks;
  }
  toconsider = scan_count > 0 ? scan_count : apparent_blocks;
  if (toconsider > apparent_blocks) {
    toconsider = apparent_blocks;
  }

  if (previous_apparentblocknumber >= 0) {
    local_forward_cutoff =
        previous_apparentblocknumber + GIF_REASSEMBLY_GAP_SCAN_WINDOW;
    wrap_prefix_first =
        !include_local_forward
        && local_forward_cutoff < apparent_blocks
        && scan_start > local_forward_cutoff;
  }

phase_probe_restart:
  probes = 0;
  probe_limit = backfill_mode || classified_anchor_pass
                    ? GIF_REASSEMBLY_PHASE_PROBE_SCAN_LIMIT
                          * GIF_REASSEMBLY_PHASE_ANCHOR_BACKFILL
                    : GIF_REASSEMBLY_PHASE_PROBE_SCAN_LIMIT;

  for (int pass = 0; pass < (wrap_prefix_first ? 2 : 1); pass++) {
    int64_t pass_start = scan_start;
    int64_t pass_count = toconsider;

    if (wrap_prefix_first) {
      if (pass == 0) {
        pass_start = 0;
        pass_count = previous_apparentblocknumber + 1;
        if (pass_count > apparent_blocks) {
          pass_count = apparent_blocks;
        }
      }
      else {
        pass_start = scan_start;
        pass_count = apparent_blocks - scan_start;
      }
    }

    for (int64_t j = 0; j < pass_count; j++) {
      int64_t apparentblocknumber = (pass_start + j) % apparent_blocks;
      int64_t anchor_actualblocknumber;
      BlockValidationDecision anchor_confidence;
      bool retry_local_forward =
          include_local_forward
          && previous_apparentblocknumber >= 0
          && apparentblocknumber == previous_apparentblocknumber + 1;

      if (gif_reassembly_checkpoint_requested()) {
        gif_reassembly_set_scan_cursor(state, apparentblocknumber, oldlength);
        gif_reassembly_store_state(candidate, state);
        return -1;
      }

      if (probes >= probe_limit) {
        if (gif_reassembly_debug_candidate(candidate)) {
          fprintf(stderr,
                  "[gifdbg] phase-probe-limit start=%" PRId64
                  " prev=%" PRId64 " scan_start=%" PRId64
                  " apparent=%" PRId64 " probes=%u"
                  " offset=%u threshold=%u oldlength=%" PRIu64 "\n",
                  blockvector_get_actual_blocknumber(candidate->b, 0),
                  previous_apparentblocknumber, scan_start,
                  apparentblocknumber, probes, phase_offset,
                  phase_threshold, oldlength);
        }
        goto phase_probe_complete;
      }

      if ((!retry_local_forward
           && !gif_reassembly_slot_allows_choice(candidate, slot,
                                                 apparentblocknumber))
          || apparent_block_in_blockvector(candidate->b,
                                           apparentblocknumber)) {
        continue;
      }

      anchor_actualblocknumber =
          filemirror_actual_blocknumber(scalpel_state.filemirror,
                                        apparentblocknumber);
      if (!gif_reassembly_actual_block_is_giflike(candidate,
                                                  anchor_actualblocknumber)) {
        continue;
      }
      anchor_confidence = filemirror_get_blocktype(
          scalpel_state.filemirror, anchor_actualblocknumber,
          candidate->needleidx);
      if ((classified_anchor_pass
           && anchor_confidence != BLOCK_CONFIDENCE_VALID)
          || (!retry_local_forward
              && !gif_reassembly_block_matches_phase_probe_hint(
                     apparentblocknumber, phase_offset, phase_threshold))) {
        continue;
      }

      for (int backfill = backfill_mode ? 1 : 0;
           backfill <= (backfill_mode || classified_anchor_pass
                            ? GIF_REASSEMBLY_PHASE_ANCHOR_BACKFILL
                            : 0);
           backfill++) {
        int64_t probe_actualblocknumber =
            anchor_actualblocknumber - (int64_t)backfill;
        int64_t probe_apparentblocknumber;
        GIFValidationSummary probe_summary = {0};
        GIFValidationSummary deep_summary = {0};
        uint32_t probe_chain_blocks = 0;
        uint32_t probe_return_blocks = 0;
        int64_t probe_return_start = -1;
        bool deep_probe_ok;
        bool local_chain_proven;
        bool local_chain_progress;
        bool overlaps_return_window = false;
        bool probe_is_local_retry = false;
        bool return_path_proven = false;

        if (probe_actualblocknumber < 0) {
          continue;
        }

        probe_apparentblocknumber = filemirror_apparent_blocknumber(
            scalpel_state.filemirror, probe_actualblocknumber);
        probe_is_local_retry =
            retry_local_forward
            && probe_apparentblocknumber == apparentblocknumber;
        if (probe_apparentblocknumber < 0
            || (!probe_is_local_retry
                && !gif_reassembly_slot_allows_choice(
                       candidate, slot, probe_apparentblocknumber))
            || apparent_block_in_blockvector(candidate->b,
                                             probe_apparentblocknumber)
            || !gif_reassembly_actual_block_is_giflike(
                   candidate, probe_actualblocknumber)) {
          continue;
        }

        if (gif_reassembly_checkpoint_requested()) {
          gif_reassembly_set_scan_cursor(state, probe_apparentblocknumber,
                                         oldlength);
          gif_reassembly_store_state(candidate, state);
          return -1;
        }

        if (probes >= probe_limit) {
          goto phase_probe_complete;
        }
        probes++;

        gif_reassembly_probe_score(0, candidate, oldlength, state,
                                   probe_actualblocknumber, &probe_summary);

        if (gif_reassembly_debug_candidate(candidate)) {
          fprintf(stderr,
                  "[gifdbg] phase-probe-trial start=%" PRId64
                  " prev=%" PRId64 " choice=%" PRId64
                  " actual=%" PRId64 " backfill=%d probe_vt=%" PRIu64
                  " required=%" PRIu64 " probes=%u"
                  " score=(frames=%u,checkpoint=%" PRIu64
                  ",good=%" PRIu64 ",normal=%" PRIu64 ")\n",
                  blockvector_get_actual_blocknumber(candidate->b, 0),
                  previous_apparentblocknumber, probe_apparentblocknumber,
                  probe_actualblocknumber, backfill,
                  probe_summary.validates_to, required_validates_to, probes,
                  probe_summary.score.completed_frames,
                  probe_summary.score.checkpoint_curpos,
                  probe_summary.score.last_good_row_pos,
                  probe_summary.score.last_normal_pos);
        }

        // A conservative boundary cap can hide all progress in the first
        // displaced block, so confirm every phase-matched candidate against
        // the nearby return path before rejecting it.
        deep_probe_ok = gif_reassembly_probe_nonlocal_return(
            0, candidate, oldlength, state, probe_actualblocknumber,
            previous_apparentblocknumber,
            GIF_REASSEMBLY_GAP_SCAN_WINDOW, true, strict_phase_proof,
            deep_return_mode
                ? GIF_REASSEMBLY_DEEP_RETURN_CONFIRM_BLOCKS
                : GIF_REASSEMBLY_RETURN_CONFIRM_BLOCKS,
            &deep_summary,
            &probe_chain_blocks, &probe_return_blocks,
            &probe_return_start);
        if (deep_probe_ok && probe_return_blocks > 0
            && (uint64_t)probe_chain_blocks
                   <= (UINT64_MAX - oldlength)
                          / (uint64_t)scalpel_state.blocksize) {
          uint64_t return_progress_floor =
              oldlength
              + (uint64_t)probe_chain_blocks
                    * (uint64_t)scalpel_state.blocksize;

          return_path_proven =
              deep_summary.validates_to >= return_progress_floor;
        }
        if (gif_reassembly_debug_candidate(candidate)) {
          lock_fprintf(stderr,
                       "[gifdbg] phase-probe-return start=%" PRId64
                       " choice=%" PRId64 " ok=%d chain=%u return=%u"
                       " return_start=%" PRId64 " progress=%d vt=%" PRIu64
                       " score=(frames=%u,checkpoint=%" PRIu64
                       ",good=%" PRIu64 ",normal=%" PRIu64 ")\n",
                       blockvector_get_actual_blocknumber(candidate->b, 0),
                       probe_apparentblocknumber, deep_probe_ok ? 1 : 0,
                       probe_chain_blocks, probe_return_blocks,
                       probe_return_start, return_path_proven ? 1 : 0,
                       deep_summary.validates_to,
                       deep_summary.score.completed_frames,
                       deep_summary.score.checkpoint_curpos,
                       deep_summary.score.last_good_row_pos,
                       deep_summary.score.last_normal_pos);
        }
        if (deep_probe_ok
            && gif_reassembly_compare_probe_summary(&deep_summary,
                                                    &probe_summary) > 0) {
          probe_summary = deep_summary;
        }
        if (!return_path_proven) {
          probe_return_blocks = 0;
          probe_return_start = -1;
        }
        else if (strict_phase_proof
                 && probe_apparentblocknumber >= probe_return_start
                 && (uint64_t)(probe_apparentblocknumber
                               - probe_return_start)
                        < GIF_REASSEMBLY_DEEP_RETURN_CONFIRM_BLOCKS) {
          overlaps_return_window = true;
        }

        local_chain_progress =
            probe_summary.validates_to >= minimum_probe_validates_to
            || probe_summary.score.checkpoint_curpos
                   > minimum_probe_validates_to
            || probe_summary.score.last_good_row_pos
                   > minimum_probe_validates_to
            || probe_summary.score.last_normal_pos
                   > minimum_probe_validates_to;
        local_chain_proven =
            probe_return_blocks == 0
            && probe_chain_blocks
                   == GIF_REASSEMBLY_NONLOCAL_CHAIN_PROBE_BLOCKS
            && probe_apparentblocknumber > previous_apparentblocknumber
            && probe_apparentblocknumber <= local_forward_cutoff;

        // A phase-matched block that parses through its full extent is strong
        // evidence by itself. A complete local phase chain is equivalent
        // evidence when the decoder remains on a long semantic plateau.
        if (probe_summary.validates
            || probe_summary.validates_to >= minimum_probe_validates_to
            || local_chain_proven) {
          BlockValidationDecision confidence =
              filemirror_get_blocktype(scalpel_state.filemirror,
                                       probe_actualblocknumber,
                                       candidate->needleidx);
          int64_t reserved = scalpel_state.reservations
                                 ? filemirror_actual_block_reserved(
                                       scalpel_state.filemirror,
                                       probe_actualblocknumber)
                                 : 0;
          bool proven_return = probe_return_blocks > 0;
          bool best_proven_return = best_return_blocks > 0;
          bool probe_return_dominated = false;
          bool best_return_dominated = false;
          int cmp;
          bool select_probe = false;

          if (proven_return && best_local_chain_proven
              && best_local_chain_progress
              && best_choice >= 0 && probe_return_start >= 0) {
            uint64_t local_blocks_to_return =
                probe_return_start >= best_choice
                    ? (uint64_t)(probe_return_start - best_choice)
                    : (uint64_t)apparent_blocks
                          - (uint64_t)best_choice
                          + (uint64_t)probe_return_start;

            probe_return_dominated =
                local_blocks_to_return < best_chain_blocks
                && probe_chain_blocks > local_blocks_to_return
                && !probe_summary.validates
                && probe_summary.score.completed_frames
                       <= best_probe_summary.score.completed_frames;
          }
          if (best_proven_return && local_chain_proven
              && local_chain_progress
              && best_return_start >= 0) {
            uint64_t local_blocks_to_return =
                best_return_start >= probe_apparentblocknumber
                    ? (uint64_t)(best_return_start
                                 - probe_apparentblocknumber)
                    : (uint64_t)apparent_blocks
                          - (uint64_t)probe_apparentblocknumber
                          + (uint64_t)best_return_start;

            best_return_dominated =
                local_blocks_to_return < probe_chain_blocks
                && best_chain_blocks > local_blocks_to_return
                && !best_probe_summary.validates
                && best_probe_summary.score.completed_frames
                       <= probe_summary.score.completed_frames;
          }

          cmp = best_choice < 0
                    ? 1
                    : gif_reassembly_compare_probe_summary(
                          &probe_summary, &best_probe_summary);

          // Progress after the displaced chain establishes both that run and
          // the point where the original stream resumes. Without that proof,
          // a complete local phase chain has stronger provenance than a
          // distant path that can parse as an unrelated GIF. When both paths
          // prove a return, prefer the shorter excursion before comparing
          // decoded frame progress.
          if (best_choice < 0) {
            select_probe = true;
          }
          else if (probe_return_dominated) {
            select_probe = false;
          }
          else if (best_return_dominated) {
            select_probe = true;
          }
          else if (proven_return != best_proven_return) {
            select_probe = proven_return;
          }
          else if (proven_return
                   && probe_summary.validates
                          != best_probe_summary.validates) {
            select_probe = probe_summary.validates;
          }
          else if (strict_phase_proof
                   && proven_return
                   && overlaps_return_window
                          != best_overlaps_return_window) {
            // Equivalent displaced runs should not consume blocks that their
            // predicted forward return path may need later.
            select_probe = !overlaps_return_window;
          }
          else if (local_chain_proven != best_local_chain_proven) {
            select_probe = local_chain_proven;
          }
          else if (proven_return
                   && probe_chain_blocks != best_chain_blocks) {
            select_probe = probe_chain_blocks < best_chain_blocks;
          }
          else if (probe_summary.score.completed_frames
                   != best_probe_summary.score.completed_frames) {
            select_probe = probe_summary.score.completed_frames
                           > best_probe_summary.score.completed_frames;
          }
          else if (probe_summary.validates != best_probe_summary.validates) {
            select_probe = probe_summary.validates;
          }
          else if (probe_return_blocks != best_return_blocks) {
            select_probe = probe_return_blocks > best_return_blocks;
          }
          else if (cmp != 0) {
            select_probe = cmp > 0;
          }
          else if (confidence != best_confidence) {
            select_probe = confidence > best_confidence;
          }
          else if (reserved != best_reserved) {
            select_probe = reserved < best_reserved;
          }

          if (select_probe) {
            best_choice = probe_apparentblocknumber;
            best_reserved = reserved;
            best_confidence = confidence;
            best_chain_blocks = probe_chain_blocks;
            best_return_blocks = probe_return_blocks;
            best_return_start = probe_return_start;
            best_local_chain_proven = local_chain_proven;
            best_local_chain_progress = local_chain_progress;
            best_overlaps_return_window = overlaps_return_window;
            best_probe_summary = probe_summary;
            if (probe_is_local_retry
                && (proven_return || local_chain_proven)) {
              goto phase_probe_complete;
            }
          }
        }
      }
    }
  }

phase_probe_complete:
  if (best_choice >= 0) {
    if (!best_probe_summary.validates
        && (best_chain_blocks > 1
            || best_return_blocks
                   == GIF_REASSEMBLY_RETURN_CONFIRM_BLOCKS)) {
      int64_t best_actualblocknumber = filemirror_actual_blocknumber(
          scalpel_state.filemirror, best_choice);
      GIFValidationSummary extended_summary = {0};
      uint32_t extended_chain_blocks = 0;
      uint32_t extended_return_blocks = 0;
      int64_t extended_return_start = -1;

      // Only the selected candidate receives a deeper return-path probe, and
      // it is retained only when it produces additional structural evidence.
      // This avoids making every candidate pay the larger validation cost.
      if (best_actualblocknumber >= 0
          && gif_reassembly_probe_nonlocal_return(
                 0, candidate, oldlength, state, best_actualblocknumber,
                 previous_apparentblocknumber,
                 GIF_REASSEMBLY_GAP_SCAN_WINDOW, true,
                 strict_phase_proof,
                 GIF_REASSEMBLY_DEEP_RETURN_CONFIRM_BLOCKS,
                 &extended_summary, &extended_chain_blocks,
                 &extended_return_blocks, &extended_return_start)
          && gif_reassembly_compare_probe_summary(&extended_summary,
                                                  &best_probe_summary) > 0
          && extended_return_blocks > best_return_blocks) {
        best_probe_summary = extended_summary;
        best_chain_blocks = extended_chain_blocks;
        best_return_blocks = extended_return_blocks;
        best_return_start = extended_return_start;
      }
    }

    if (best_return_blocks > 0 && best_return_start >= 0) {
      uint32_t committed_return_blocks = best_return_blocks;
      bool defer_return = best_chain_blocks > 1;

      // Deep lookahead can establish that a return path is promising without
      // proving every intervening block. Re-evaluate long paths in bounded
      // segments unless the probe validated the complete GIF.
      if (!best_probe_summary.validates
          && committed_return_blocks > GIF_REASSEMBLY_RETURN_CONFIRM_BLOCKS) {
        committed_return_blocks = GIF_REASSEMBLY_RETURN_CONFIRM_BLOCKS;
      }
      gif_reassembly_set_return_start(state, best_return_start,
                                      defer_return);
      gif_reassembly_set_return_proof(state, best_chain_blocks,
                                      committed_return_blocks);
      gif_reassembly_store_state(candidate, state);
    }
    else if (best_chain_blocks > 1 && apparent_blocks > 0) {
      int64_t after_chain =
          (best_choice + (int64_t)best_chain_blocks) % apparent_blocks;

      // The phase probe validated this contiguous chain as a unit. Preserve
      // that exact proof so semantic plateaus can be committed one block at a
      // time, then resume ordinary selection immediately after the chain.
      gif_reassembly_set_return_start(state, after_chain, true);
      gif_reassembly_set_return_proof(state, best_chain_blocks, 0);
      gif_reassembly_store_state(candidate, state);
    }
    if (resume_after_out) {
      *resume_after_out = (best_choice + 1) % apparent_blocks;
    }
    if (gif_reassembly_debug_candidate(candidate)) {
      fprintf(stderr,
              "[gifdbg] phase-probe-choice start=%" PRId64
              " prev=%" PRId64 " choice=%" PRId64
              " actual=%" PRId64 " offset=%u threshold=%u"
              " probe_vt=%" PRIu64 " oldlength=%" PRIu64
              " probes=%u chain_blocks=%u return_blocks=%u"
              " return_start=%" PRId64 "\n",
              blockvector_get_actual_blocknumber(candidate->b, 0),
              previous_apparentblocknumber, best_choice,
              filemirror_actual_blocknumber(scalpel_state.filemirror,
                                            best_choice),
              phase_offset, phase_threshold,
              best_probe_summary.validates_to, oldlength, probes,
              (unsigned)best_chain_blocks, (unsigned)best_return_blocks,
              best_return_start);
    }
    return best_choice;
  }

  if (classified_anchor_pass) {
    classified_anchor_pass = false;
    goto phase_probe_restart;
  }

  if (!deep_return_mode) {
    deep_return_mode = true;
    goto phase_probe_restart;
  }

  if (!backfill_mode) {
    backfill_mode = true;
    deep_return_mode = false;
    goto phase_probe_restart;
  }

  state->reassembly_phase_scan_exhausted = true;
  state->reassembly_phase_scan_exhausted_length = oldlength;
  gif_reassembly_store_state(candidate, state);
  if (gif_reassembly_debug_candidate(candidate)) {
    fprintf(stderr,
            "[gifdbg] phase-probe-exhausted start=%" PRId64
            " prev=%" PRId64 " scan_start=%" PRId64
            " probes=%u offset=%u threshold=%u oldlength=%" PRIu64 "\n",
            blockvector_get_actual_blocknumber(candidate->b, 0),
            previous_apparentblocknumber, scan_start, probes,
            phase_offset, phase_threshold, oldlength);
  }
  return -1;
}

static inline int64_t gif_reassembly_completion_probe_choice(
    CarveInfo *candidate, uint64_t slot, int64_t scan_start,
    int64_t scan_count, int64_t previous_apparentblocknumber,
    GIFCarveState *state, int64_t *resume_after_out) {
  int64_t apparent_blocks;
  int64_t toconsider;
  int64_t local_forward_cutoff = -1;
  uint64_t oldlength;
  uint32_t probes = 0;
  bool wrap_prefix_first = false;

  if (resume_after_out) {
    *resume_after_out = -1;
  }

  if (!candidate || !state || previous_apparentblocknumber < 0
      || scalpel_state.blocksize <= 0) {
    return -1;
  }

  oldlength = blockvector_get_data_length(candidate->b);
  if (gif_reassembly_committed_actual_gap_count(candidate, oldlength)
      < GIF_REASSEMBLY_PHASE_MIN_PRIOR_GAPS) {
    return -1;
  }

  if (state->reassembly_completion_probe_exhausted
      && state->reassembly_completion_probe_exhausted_length == oldlength) {
    return -1;
  }

  apparent_blocks =
      (int64_t)filemirror_apparent_blocks(scalpel_state.filemirror);
  if (apparent_blocks <= 0) {
    return -1;
  }

  if (scan_start < 0) {
    scan_start = 0;
  }
  scan_start %= apparent_blocks;
  if (scan_start < 0) {
    scan_start += apparent_blocks;
  }
  toconsider = scan_count > 0 ? scan_count : apparent_blocks;
  if (toconsider > apparent_blocks) {
    toconsider = apparent_blocks;
  }

  local_forward_cutoff =
      previous_apparentblocknumber + GIF_REASSEMBLY_GAP_SCAN_WINDOW;
  wrap_prefix_first =
      local_forward_cutoff < apparent_blocks
      && scan_start > local_forward_cutoff;

  for (int pass = 0; pass < (wrap_prefix_first ? 2 : 1); pass++) {
    int64_t pass_start = scan_start;
    int64_t pass_count = toconsider;

    if (wrap_prefix_first) {
      if (pass == 0) {
        pass_start = 0;
        pass_count = previous_apparentblocknumber + 1;
        if (pass_count > apparent_blocks) {
          pass_count = apparent_blocks;
        }
      }
      else {
        pass_start = scan_start;
        pass_count = apparent_blocks - scan_start;
      }
    }

    for (int64_t j = 0; j < pass_count; j++) {
      int64_t apparentblocknumber = (pass_start + j) % apparent_blocks;
      int64_t actualblocknumber;
      GIFValidationSummary probe_summary = {0};

      if (gif_reassembly_checkpoint_requested()) {
        gif_reassembly_store_state(candidate, state);
        return -1;
      }

      if (probes >= GIF_REASSEMBLY_COMPLETION_PROBE_SCAN_LIMIT) {
        state->reassembly_completion_probe_exhausted = true;
        state->reassembly_completion_probe_exhausted_length = oldlength;
        gif_reassembly_store_state(candidate, state);
        if (gif_reassembly_debug_candidate(candidate)) {
          fprintf(stderr,
                  "[gifdbg] completion-probe-limit start=%" PRId64
                  " prev=%" PRId64 " scan_start=%" PRId64
                  " probes=%u oldlength=%" PRIu64 "\n",
                  blockvector_get_actual_blocknumber(candidate->b, 0),
                  previous_apparentblocknumber, scan_start,
                  probes, oldlength);
        }
        return -1;
      }

      if (previous_apparentblocknumber >= 0
          && apparentblocknumber > previous_apparentblocknumber
          && apparentblocknumber <= local_forward_cutoff) {
        continue;
      }

      if (!gif_reassembly_slot_allows_choice(candidate, slot,
                                             apparentblocknumber)
          || apparent_block_in_blockvector(candidate->b,
                                           apparentblocknumber)) {
        continue;
      }

      actualblocknumber =
          filemirror_actual_blocknumber(scalpel_state.filemirror,
                                        apparentblocknumber);
      if (!gif_reassembly_actual_block_is_giflike(candidate,
                                                  actualblocknumber)) {
        continue;
      }

      probes++;
      if (!gif_reassembly_probe_nonlocal_potential(
              0, candidate, oldlength, state, actualblocknumber,
              previous_apparentblocknumber, &probe_summary)) {
        continue;
      }

      if (probe_summary.validates) {
        if (resume_after_out) {
          *resume_after_out = (apparentblocknumber + 1) % apparent_blocks;
        }
        state->reassembly_completion_probe_exhausted = false;
        state->reassembly_completion_probe_exhausted_length = 0;
        gif_reassembly_store_state(candidate, state);
        if (gif_reassembly_debug_candidate(candidate)) {
          fprintf(stderr,
                  "[gifdbg] completion-probe-choice start=%" PRId64
                  " prev=%" PRId64 " choice=%" PRId64
                  " actual=%" PRId64 " probe_vt=%" PRIu64
                  " oldlength=%" PRIu64 " probes=%u\n",
                  blockvector_get_actual_blocknumber(candidate->b, 0),
                  previous_apparentblocknumber, apparentblocknumber,
                  actualblocknumber, probe_summary.validates_to,
                  oldlength, probes);
        }
        return apparentblocknumber;
      }
    }
  }

  state->reassembly_completion_probe_exhausted = true;
  state->reassembly_completion_probe_exhausted_length = oldlength;
  gif_reassembly_store_state(candidate, state);
  if (gif_reassembly_debug_candidate(candidate)) {
    fprintf(stderr,
            "[gifdbg] completion-probe-exhausted start=%" PRId64
            " prev=%" PRId64 " scan_start=%" PRId64
            " probes=%u oldlength=%" PRIu64 "\n",
            blockvector_get_actual_blocknumber(candidate->b, 0),
            previous_apparentblocknumber, scan_start, probes, oldlength);
  }
  return -1;
}

static inline bool gif_reassembly_probe_lookahead(
    CarveInfo *candidate, uint64_t oldlength, int64_t first_actualblocknumber,
    const GIFCarveState *first_state,
    const GIFValidationSummary *first_summary,
    GIFValidationSummary *summary_out) {
  uint64_t slot = blockvector_get_num_blocks(candidate->b) - 1;
  uint64_t old_blocks = blockvector_get_num_blocks(candidate->b);
  int64_t saved_apparent =
      blockvector_get_apparent_blocknumber(candidate->b, slot);
  int64_t first_apparent =
      filemirror_apparent_blocknumber(scalpel_state.filemirror,
                                      first_actualblocknumber);
  uint64_t first_length;
  uint64_t second_oldlength;
  bool improved = false;
  GIFValidationSummary trial_summary = {0};
  GIFCarveState trial_state = {0};
  int64_t apparent_blocks =
      filemirror_apparent_blocks(scalpel_state.filemirror);

  *summary_out = *first_summary;

  if (first_apparent < 0 || apparent_blocks <= 0) {
    return false;
  }

  if (gif_reassembly_checkpoint_requested()) {
    return false;
  }

  deflate_blockvector_single_block(candidate->b, slot, oldlength);
  blockvector_set_apparent_blocknumber(candidate->b, slot, first_apparent);
  first_length = inflate_blockvector_single_block(candidate->b, slot);

  resize_blockvector(candidate->b, old_blocks + 1);

  int64_t lookahead_start = first_apparent - GIF_REASSEMBLY_LOOKAHEAD_LIMIT;
  int64_t lookahead_end = first_apparent + GIF_REASSEMBLY_LOOKAHEAD_LIMIT;
  if (lookahead_start < 0) {
    lookahead_start = 0;
  }
  if (lookahead_end > apparent_blocks) {
    lookahead_end = apparent_blocks;
  }

  for (int64_t second_apparent = lookahead_start;
       second_apparent < lookahead_end;
       second_apparent++) {
    int64_t second_actual =
        filemirror_actual_blocknumber(scalpel_state.filemirror,
                                      second_apparent);

    if (gif_reassembly_checkpoint_requested()) {
      break;
    }

    if (second_actual < 0
        || apparent_block_in_blockvector(candidate->b, second_apparent)
        || filemirror_get_blocktype(scalpel_state.filemirror, second_actual,
                                    candidate->needleidx)
               == BLOCK_CONFIDENCE_INVALID
        || filemirror_actual_block_covered(scalpel_state.filemirror,
                                           second_actual)) {
      continue;
    }

    blockvector_set_apparent_blocknumber(candidate->b, old_blocks,
                                         second_apparent);
    second_oldlength = inflate_blockvector_single_block(candidate->b,
                                                        old_blocks);
    trial_state = *first_state;
    gif_reassembly_validate_local_probe(candidate, &trial_state,
                                        &trial_summary);
    if (gif_reassembly_compare_probe_summary(&trial_summary, summary_out) > 0) {
      *summary_out = trial_summary;
      improved = true;
    }
    deflate_blockvector_single_block(candidate->b, old_blocks, second_oldlength);
  }

  resize_blockvector(candidate->b, old_blocks);
  deflate_blockvector_single_block(candidate->b, slot, first_length);
  blockvector_set_apparent_blocknumber(candidate->b, slot, saved_apparent);
  if (saved_apparent >= 0) {
    inflate_blockvector_single_block(candidate->b, slot);
  }
  return improved;
}

static inline void gif_reassembly_prepare_for_extension(CarveInfo *candidate) {
  bool resume_current_slot = candidate->no_initial_block_extension;
  bool resume_preserved_frontier = false;
  GIFCarveState gif_state = {0};
  int64_t local_gap_start = -1;
  int64_t prestart_gap_start = -1;
  int64_t start_apparentblocknumber = -1;
  int64_t committed_tail_apparent = -1;
  uint32_t resume_plateau_blocks = 0;
  bool plateau_wrap_resume = false;
  bool preserved_frontier_resume = false;
  bool active_scan_slot = false;
  bool deferred_scan_cursor = false;
  bool scan_cursor_stale = false;
  candidate->fastpath = false;

  gif_reassembly_load_state(candidate, &gif_state);
  preserved_frontier_resume = gif_state.reassembly_preserved_frontier;
  if (gif_state.reassembly_preserved_frontier) {
    gif_state.reassembly_preserved_frontier = false;
    gif_reassembly_store_state(candidate, &gif_state);
  }
  if (scalpel_state.blocksize > 0) {
    start_apparentblocknumber =
        gif_reassembly_anchor_apparent_block(candidate);
    if (blockvector_get_data_length(candidate->b) > 0) {
      uint64_t committed_blocks =
          CEILDIV(blockvector_get_data_length(candidate->b),
                  (uint64_t)scalpel_state.blocksize);
      active_scan_slot =
          blockvector_get_num_blocks(candidate->b) > committed_blocks;
    }
  }
  if (resume_current_slot
      && !active_scan_slot
      && candidate->best_validates_to + 1
             >= blockvector_get_data_length(candidate->b)) {
    resume_current_slot = false;
    candidate->no_initial_block_extension = false;
  }
  if (gif_state.reassembly_scan_cursor_valid
      && gif_state.reassembly_scan_cursor >= 0) {
    if (gif_state.reassembly_scan_cursor_length
        == blockvector_get_data_length(candidate->b)) {
      if (resume_current_slot) {
        candidate->block_choice_start = gif_state.reassembly_scan_cursor;
      }
      else {
        deferred_scan_cursor = true;
      }
    }
    else if (gif_state.reassembly_scan_cursor_length
             < blockvector_get_data_length(candidate->b)) {
      gif_reassembly_clear_scan_cursor(&gif_state);
      scan_cursor_stale = true;
    }
  }
  resume_plateau_blocks = gif_reassembly_effective_plateau_blocks(&gif_state);
  if (resume_current_slot
      && candidate->newblock < 0
      && blockvector_get_num_blocks(candidate->b) > 0) {
    uint64_t tail_slot = blockvector_get_num_blocks(candidate->b) - 1;
    bool checkpointed_plateau_return =
        resume_plateau_blocks > 0
        && gif_state.reassembly_return_pending
        && gif_state.reassembly_return_start >= 0
        && candidate->best_validates_to + 1
               < blockvector_get_data_length(candidate->b);

    if (checkpointed_plateau_return) {
      /* A checkpointed plateau-backed return slot may come back with the tail
         slot's exclusion set already exhausted. Reset only that speculative
         slot so the deferred return window can be re-probed after restore. */
      blockvector_free_choices(candidate->b, tail_slot);
    }
  }
  if (resume_current_slot
      && filemirror_apparent_blocks(scalpel_state.filemirror) > 0
      && resume_plateau_blocks > 0
      && gif_state.reassembly_return_start >= 0
      && candidate->block_choice_start
             >= (int64_t)filemirror_apparent_blocks(
                    scalpel_state.filemirror)) {
    candidate->block_choice_start = gif_state.reassembly_return_start;
  }

  if (!resume_current_slot) {
    if (preserved_frontier_resume
        && candidate->newblock >= 0
        && blockvector_get_data_length(candidate->b) > 0
        && candidate->best_validates_to + 1
               >= blockvector_get_data_length(candidate->b)) {
      int64_t resumed_best_apparent =
          filemirror_apparent_blocknumber(scalpel_state.filemirror,
                                          candidate->newblock);
      if (resumed_best_apparent >= 0) {
        resume_preserved_frontier = true;
      }
      else {
        candidate->newblock = -1;
      }
    }
    local_gap_start = gif_reassembly_recent_forward_gap_start(candidate);
    prestart_gap_start = gif_reassembly_prestart_gap_start(candidate);
    resize_blockvector(candidate->b, blockvector_get_num_blocks(candidate->b) + 1);
    if (!resume_preserved_frontier) {
      candidate->newblock = -1;
      candidate->best_validates_to =
          blockvector_get_data_length(candidate->b) - 1;
    }
  }
  else {
    candidate->no_initial_block_extension = false;
    local_gap_start = gif_reassembly_recent_forward_gap_start(candidate);
    prestart_gap_start = gif_reassembly_prestart_gap_start(candidate);
    if (candidate->newblock >= 0
        && candidate->best_validates_to + 1
               >= blockvector_get_data_length(candidate->b)) {
      int64_t best_apparentblocknumber =
          filemirror_apparent_blocknumber(scalpel_state.filemirror,
                                          candidate->newblock);
      bool reset_stale_best = false;

      if (local_gap_start >= 0
          && candidate->block_choice_start == local_gap_start
          && (best_apparentblocknumber < local_gap_start
              || best_apparentblocknumber
                     >= local_gap_start + GIF_REASSEMBLY_GAP_SCAN_WINDOW)) {
        reset_stale_best = true;
      }

      if (!reset_stale_best
          && prestart_gap_start >= 0
          && start_apparentblocknumber > prestart_gap_start
          && candidate->block_choice_start == prestart_gap_start
          && !(best_apparentblocknumber >= prestart_gap_start
               && best_apparentblocknumber < start_apparentblocknumber)) {
        reset_stale_best = true;
      }

      if (reset_stale_best) {
        candidate->newblock = -1;
        candidate->best_validates_to =
            blockvector_get_data_length(candidate->b) - 1;
      }
    }
  }

  if (!resume_current_slot && !resume_preserved_frontier) {
    int64_t last_apparent =
        blockvector_get_apparent_blocknumber(
            candidate->b, blockvector_get_num_blocks(candidate->b) - 2);
    int64_t next_apparent = last_apparent + 1;
    candidate->block_choice_start = -1;

    plateau_wrap_resume =
        filemirror_apparent_blocks(scalpel_state.filemirror) > 0
        && !gif_state.reassembly_return_pending
        && resume_plateau_blocks > 0
        && gif_state.reassembly_return_start >= 0
        && next_apparent
               >= (int64_t)filemirror_apparent_blocks(
                      scalpel_state.filemirror);

    if (plateau_wrap_resume) {
      /* Once a plateau-backed chain wraps past the apparent block ceiling,
         resume from the recorded return window before revisiting older
         local/pre-start gaps. Otherwise the low-block gap logic can steal
         the slot immediately after a correct wrap frontier. */
      candidate->block_choice_start = gif_state.reassembly_return_start;
    }
    else if (gif_state.reassembly_return_pending
             && !gif_state.reassembly_return_deferred
             && gif_state.reassembly_return_start >= 0) {
      candidate->block_choice_start = gif_state.reassembly_return_start;
    }
    else if (next_apparent >= 0
             && next_apparent
                    < (int64_t)filemirror_apparent_blocks(
                           scalpel_state.filemirror)
             && !apparent_block_in_blockvector(candidate->b,
                                                next_apparent)) {
      // Continue from an accepted gap jump before reconsidering the skipped
      // physical window. A separately proven return path takes precedence.
      candidate->block_choice_start = next_apparent;
    }
    else if (local_gap_start >= 0
             && !apparent_block_in_blockvector(candidate->b,
                                                local_gap_start)) {
      candidate->block_choice_start = local_gap_start;
    }
    else if (filemirror_apparent_blocks(scalpel_state.filemirror) > 0
             && resume_plateau_blocks > 0
             && gif_state.reassembly_return_start >= 0
             && next_apparent
                    >= (int64_t)filemirror_apparent_blocks(
                           scalpel_state.filemirror)) {
      uint64_t apparent_blocks =
          filemirror_apparent_blocks(scalpel_state.filemirror);
      int64_t wrapped_next = next_apparent % (int64_t)apparent_blocks;
      if (wrapped_next < 0) {
        wrapped_next += (int64_t)apparent_blocks;
      }

      if (plateau_wrap_resume) {
        candidate->block_choice_start = gif_state.reassembly_return_start;
      }
      else if (wrapped_next == gif_state.reassembly_return_start
          || apparent_block_in_blockvector(candidate->b, wrapped_next)) {
        candidate->block_choice_start = gif_state.reassembly_return_start;
      }
      else {
        candidate->block_choice_start = wrapped_next;
      }
    }
    else {
      candidate->block_choice_start = next_apparent;
    }

    if (candidate->block_choice_start == next_apparent
        && prestart_gap_start >= 0
        && next_apparent >= 0
        && next_apparent
               < (int64_t)filemirror_apparent_blocks(
                      scalpel_state.filemirror)
        && apparent_block_in_blockvector(candidate->b, next_apparent)
        && !apparent_block_in_blockvector(candidate->b, prestart_gap_start)) {
      candidate->block_choice_start = prestart_gap_start;
    }
  }
  else if (resume_preserved_frontier
           && candidate->block_choice_start < 0) {
    candidate->block_choice_start =
        gif_reassembly_resume_choice_start(candidate, 0);
  }

  if (deferred_scan_cursor
      && !gif_state.reassembly_return_pending) {
    candidate->block_choice_start = gif_state.reassembly_scan_cursor;
  }

  if (blockvector_get_num_blocks(candidate->b)
      > (resume_current_slot ? 0 : 1)) {
    uint64_t committed_tail_index =
        blockvector_get_num_blocks(candidate->b) - (resume_current_slot ? 1 : 2);
    committed_tail_apparent =
        blockvector_get_apparent_blocknumber(candidate->b, committed_tail_index);
  }

  if (resume_plateau_blocks > 0
      && gif_state.reassembly_return_start > 0
      && !gif_state.reassembly_return_deferred
      && committed_tail_apparent >= gif_state.reassembly_return_start
      && candidate->block_choice_start >= 0
      && candidate->block_choice_start < gif_state.reassembly_return_start) {
    candidate->block_choice_start = gif_state.reassembly_return_start;
  }

  // Once a displaced chain has been confirmed, its return window takes
  // precedence over a scan cursor left by the active speculative slot.
  if (gif_state.reassembly_return_pending
      && !gif_state.reassembly_return_deferred
      && gif_state.reassembly_return_start >= 0
      && !gif_reassembly_choice_in_return_window(
             &gif_state, candidate->block_choice_start)) {
    candidate->block_choice_start = gif_state.reassembly_return_start;
  }

  if (scan_cursor_stale) {
    gif_reassembly_store_state(candidate, &gif_state);
  }
}

static inline int64_t gif_reassembly_get_block_choice(
    CarveInfo *candidate, GIFCarveState *runtime_state) {
  int64_t reserved;
  int64_t block_choice = -1;
  int64_t actualblocknumber;
  int64_t count;
  int64_t full_scan_count;
  int64_t local_gap_start = -1;
  int64_t prestart_gap_start = -1;
  int64_t start_apparentblocknumber = -1;
  int64_t previous_apparentblocknumber = -1;
  int64_t previous_previous_apparentblocknumber = -1;
  int64_t previous_actualblocknumber = -1;
  int64_t immediate_next = -1;
  int64_t local_forward_end = -1;
  int64_t anchor_resume_start = -1;
  int64_t prestart_end = -1;
  int64_t scan_best_choice = -1;
  int64_t scan_contiguous_choice = -1;
  int64_t scan_best_reserved = INT64_MAX;
  int64_t scan_contiguous_reserved = INT64_MAX;
  uint32_t phase_offset = 0;
  uint8_t phase_threshold = 0;
  uint64_t committed_blocks = 0;
  uint64_t slot = 0;
  uint64_t evaluated;
  uint64_t immediate_evaluated = 0;
  bool viable = false;
  bool scan_consecutive = false;
  bool have_committed_local_gap = false;
  bool local_forward_phase = false;
  bool local_gap_phase = false;
  bool prestart_phase = false;
  bool prestart_scan_active = false;
  bool return_window_phase = false;
  bool choice_removed = false;
  bool anchor_yield_tried = false;
  bool immediate_path_is_known_gap = false;
  BlockValidationDecision scan_blocktype = BLOCK_CONFIDENCE_INVALID;
  BlockValidationDecision scan_best_confidence = BLOCK_CONFIDENCE_INVALID;
  BlockValidationDecision scan_contiguous_confidence = BLOCK_CONFIDENCE_INVALID;
  GIFCarveState gif_state = {0};

#if BLOCK_SELECTION_PERFORMANCE_STATS > 0
  struct timespec BLK_starttime;
  struct timespec BLK_endtime;
  uint64_t BLK_examined = 0;

  clock_gettime(CLOCK_MONOTONIC, &BLK_starttime);
#endif

  count = filemirror_apparent_blocks(scalpel_state.filemirror);
  if (scalpel_state.blocksize > 0) {
    committed_blocks =
        CEILDIV(blockvector_get_data_length(candidate->b),
                (uint64_t)scalpel_state.blocksize);
  }
  local_gap_start = gif_reassembly_recent_forward_gap_start(candidate);
  prestart_gap_start = gif_reassembly_prestart_gap_start(candidate);
  start_apparentblocknumber = gif_reassembly_anchor_apparent_block(candidate);
  slot = blockvector_get_num_blocks(candidate->b) - 1;
  gif_reassembly_load_state_raw(candidate, &gif_state);
  if (gif_reassembly_debug_candidate(candidate)) {
    int64_t dbg0 = blockvector_get_num_blocks(candidate->b) > 0
                       ? blockvector_get_actual_blocknumber(candidate->b, 0)
                       : -1;
    int64_t dbg1 = blockvector_get_num_blocks(candidate->b) > 1
                       ? blockvector_get_actual_blocknumber(candidate->b, 1)
                       : -1;
    int64_t dbg2 = blockvector_get_num_blocks(candidate->b) > 2
                       ? blockvector_get_actual_blocknumber(candidate->b, 2)
                       : -1;
    fprintf(stderr,
            "[gifdbg] choice-state start=%" PRId64
            " blocks=%" PRIu64 " len=%" PRIu64
            " a0=%" PRId64 " a1=%" PRId64 " a2=%" PRId64
            " bcstart=%" PRId64 " newblock=%" PRId64
            " return_pending=%d return_deferred=%d"
            " return_start=%" PRId64 " return_actual=%" PRId64 "\n",
            dbg0, blockvector_get_num_blocks(candidate->b),
            blockvector_get_data_length(candidate->b),
            dbg0, dbg1, dbg2, candidate->block_choice_start,
            candidate->newblock,
            gif_state.reassembly_return_pending ? 1 : 0,
            gif_state.reassembly_return_deferred ? 1 : 0,
            gif_state.reassembly_return_start,
            gif_state.reassembly_return_actual_valid
                ? gif_state.reassembly_return_actual
                : -1);
  }
  if (gif_state.reassembly_return_pending) {
    /* A deferred return means we are walking a displaced island and must
       either continue that island locally or go back to the recorded return
       window. Older pre-start/local-gap heuristics must not steal this slot
       and restart a whole-image scan. */
    local_gap_start = -1;
    prestart_gap_start = -1;
  }
  if (blockvector_get_num_blocks(candidate->b) >= 2) {
    previous_apparentblocknumber =
        blockvector_get_apparent_blocknumber(candidate->b, slot - 1);
    previous_actualblocknumber =
        blockvector_get_actual_blocknumber(candidate->b, slot - 1);
  }
  if (blockvector_get_num_blocks(candidate->b) >= 3) {
    previous_previous_apparentblocknumber =
        blockvector_get_apparent_blocknumber(candidate->b, slot - 2);
  }
  if (previous_apparentblocknumber >= 0 && count > 0) {
    immediate_next = previous_apparentblocknumber + 1;
    if (previous_previous_apparentblocknumber >= 0) {
      have_committed_local_gap =
          previous_apparentblocknumber > previous_previous_apparentblocknumber + 1
          && previous_apparentblocknumber - previous_previous_apparentblocknumber
                 <= GIF_REASSEMBLY_LOCAL_DISTANCE_MAX;
    }
  }
  else if (start_apparentblocknumber >= 0 && count > 0) {
    immediate_next = start_apparentblocknumber + 1;
  }

  if (immediate_next >= 0 && immediate_next < count) {
    actualblocknumber = filemirror_actual_blocknumber(
        scalpel_state.filemirror, immediate_next);
    // Covered and zero blocks cannot continue the candidate. A jump in
    // actual positions means the blockmap removed covered blocks between
    // these apparent neighbors.
    immediate_path_is_known_gap =
        actualblocknumber >= 0
        && (filemirror_actual_block_covered(scalpel_state.filemirror,
                                            actualblocknumber)
            || filemirror_actual_block_is_zero(scalpel_state.filemirror,
                                               actualblocknumber)
            || (previous_actualblocknumber >= 0
                && actualblocknumber != previous_actualblocknumber + 1));
    if (gif_reassembly_debug_candidate(candidate)) {
      fprintf(stderr,
              "[gifdbg] immediate-path start=%" PRId64
              " prev_apparent=%" PRId64 " prev_actual=%" PRId64
              " next_apparent=%" PRId64 " next_actual=%" PRId64
              " known_gap=%d committed_gaps=%u\n",
              blockvector_get_actual_blocknumber(candidate->b, 0),
              previous_apparentblocknumber, previous_actualblocknumber,
              immediate_next, actualblocknumber,
              immediate_path_is_known_gap ? 1 : 0,
              gif_reassembly_committed_actual_gap_count(
                  candidate, blockvector_get_data_length(candidate->b)));
    }
  }

  if (gif_state.reassembly_return_pending
      && gif_state.reassembly_return_deferred
      && gif_state.reassembly_return_start >= 0
      && immediate_next >= 0
      && (immediate_next >= count
          || apparent_block_in_blockvector(candidate->b, immediate_next))) {
    gif_state.reassembly_return_deferred = false;
    gif_state.reassembly_return_chain_blocks = 0;
    gif_reassembly_store_state(candidate, &gif_state);
    candidate->block_choice_start = gif_state.reassembly_return_start;
  }

  if (local_gap_start < 0
      && prestart_gap_start < 0
      && (!gif_state.reassembly_return_pending
          || gif_state.reassembly_return_deferred)
      && committed_blocks <= 2
      && immediate_next >= 0
      && immediate_next < count) {
    /* Early GIF candidates often consist of only the first header block, or
       just the two header blocks. Search a bounded local window before
       falling back to a whole-image scan. */
    local_gap_start = immediate_next;
  }

  if (immediate_next >= 0
      && committed_blocks == 1
      && start_apparentblocknumber >= 0
      && count > 0) {
    int64_t scan_end = immediate_next + GIF_REASSEMBLY_GAP_SCAN_WINDOW;
    int64_t seed_scan_start = immediate_next;

    if (scan_end > count) {
      scan_end = count;
    }

    if (gif_state.reassembly_seed_scan_started
        && candidate->block_choice_start >= immediate_next) {
      if (candidate->block_choice_start < scan_end) {
        seed_scan_start = candidate->block_choice_start;
      }
      else {
        seed_scan_start = scan_end;
      }
    }
    else {
      gif_state.reassembly_seed_scan_started = true;
      gif_reassembly_store_state(candidate, &gif_state);
    }

    for (block_choice = seed_scan_start;
         block_choice < scan_end;
         ++block_choice) {
      if (apparent_block_in_blockvector(candidate->b, block_choice)) {
        continue;
      }

      actualblocknumber =
          filemirror_actual_blocknumber(scalpel_state.filemirror, block_choice);
      viable =
          actualblocknumber >= 0
          && filemirror_get_blocktype(scalpel_state.filemirror, actualblocknumber,
                                      candidate->needleidx)
                 != BLOCK_CONFIDENCE_INVALID;
      if (gif_reassembly_debug_candidate(candidate)) {
        fprintf(stderr,
                "[gifdbg] seed-scan start=%" PRId64
                " anchor=%" PRId64 " choice=%" PRId64 " actual=%" PRId64
                " viable=%d\n",
                blockvector_get_actual_blocknumber(candidate->b, 0),
                start_apparentblocknumber, block_choice, actualblocknumber,
                viable ? 1 : 0);
      }
      if (!viable) {
        continue;
      }

      candidate->block_choice_start =
          (block_choice + 1) % filemirror_apparent_blocks(scalpel_state.filemirror);
      blockvector_remove_choice(candidate->b, slot, block_choice);
      return block_choice;
    }
  }

  if (block_choice < 0
      && committed_blocks > 1
      && (local_gap_start >= 0 || immediate_path_is_known_gap)
      && previous_apparentblocknumber >= 0
      && !gif_state.reassembly_return_pending
      && gif_reassembly_committed_actual_gap_count(
             candidate, blockvector_get_data_length(candidate->b))
             >= GIF_REASSEMBLY_PHASE_MIN_PRIOR_GAPS) {
    // After several discontinuities, a nearby block can preserve an LZW
    // plateau while hiding a displaced continuation. Prefer a classified
    // anchor only when a bounded phase probe also proves its return path.
    anchor_resume_start = -1;
    block_choice = gif_reassembly_phase_probe_choice(
        candidate, slot, immediate_next, count,
        previous_apparentblocknumber, &gif_state, &anchor_resume_start, true);
    if (block_choice >= 0) {
      if (anchor_resume_start >= 0) {
        candidate->block_choice_start = anchor_resume_start;
      }
      blockvector_remove_choice(candidate->b, slot, block_choice);
      choice_removed = true;
      goto done;
    }
    block_choice = -1;
  }

  if (immediate_next >= 0
      && immediate_next < count
      && !have_committed_local_gap
      && local_gap_start < 0
      && prestart_gap_start < 0
      && (!gif_state.reassembly_return_pending
          || gif_state.reassembly_return_deferred)
      && !apparent_block_in_blockvector(candidate->b, immediate_next)) {
    block_choice =
        blockvector_get_choice(candidate->b, slot, immediate_next, 1,
                               &immediate_evaluated);
#if BLOCK_SELECTION_PERFORMANCE_STATS > 0
    BLK_examined += immediate_evaluated;
#endif
    if (block_choice == immediate_next) {
      actualblocknumber =
          filemirror_actual_blocknumber(scalpel_state.filemirror, block_choice);
      viable =
          filemirror_get_blocktype(scalpel_state.filemirror, actualblocknumber,
                                   candidate->needleidx)
              != BLOCK_CONFIDENCE_INVALID
          && !apparent_block_in_blockvector(candidate->b, block_choice);
      reserved = scalpel_state.reservations
                     ? filemirror_actual_block_reserved(scalpel_state.filemirror,
                                                        actualblocknumber)
                     : 0;
      if (gif_reassembly_debug_candidate(candidate)) {
        fprintf(stderr,
                "[gifdbg] immediate start=%" PRId64
                " prev=%" PRId64 " choice=%" PRId64 " actual=%" PRId64
                " viable=%d reserved=%" PRId64 "\n",
                blockvector_get_actual_blocknumber(candidate->b, 0),
                previous_apparentblocknumber, block_choice, actualblocknumber,
                viable ? 1 : 0, reserved);
      }
      if (viable) {
        candidate->block_choice_start =
            (block_choice + 1) % filemirror_apparent_blocks(scalpel_state.filemirror);
        blockvector_remove_choice(candidate->b, slot, block_choice);
        return block_choice;
      }

      blockvector_remove_choice(candidate->b, slot, block_choice);
      block_choice = -1;
    }
  }

  if (block_choice < 0
      && immediate_next >= 0
      && immediate_next < count
      && committed_blocks > 1
      && !gif_state.reassembly_return_pending
      && !immediate_path_is_known_gap
      && !apparent_block_in_blockvector(candidate->b, immediate_next)
      && gif_reassembly_get_phase_hint(candidate, &gif_state,
                                       &phase_offset, &phase_threshold)
      && (candidate->block_choice_start != immediate_next
          || !gif_reassembly_block_matches_phase_probe_hint(
                 immediate_next, phase_offset, phase_threshold))) {
    // Resolve an unexplained discontinuity before a plausible local path can
    // hide it, including when an earlier gap has already been committed.
    anchor_resume_start = -1;
    block_choice = gif_reassembly_phase_probe_choice(
        candidate, slot, immediate_next, count,
        previous_apparentblocknumber, &gif_state, &anchor_resume_start, true);
    if (block_choice >= 0) {
      if (anchor_resume_start >= 0) {
        candidate->block_choice_start = anchor_resume_start;
      }
      blockvector_remove_choice(candidate->b, slot, block_choice);
      choice_removed = true;
      goto done;
    }
    block_choice = -1;
  }

  full_scan_count = count;
  prestart_scan_active =
      prestart_gap_start >= 0
      && start_apparentblocknumber > prestart_gap_start
      && candidate->block_choice_start == prestart_gap_start;

  if (previous_apparentblocknumber >= 0
      && gif_state.reassembly_return_pending
      && gif_state.reassembly_return_deferred
      && gif_state.reassembly_return_start >= 0
      && local_gap_start < 0
      && !prestart_scan_active
      && candidate->block_choice_start
             >= previous_apparentblocknumber + 1
                  + GIF_REASSEMBLY_GAP_SCAN_WINDOW) {
    gif_state.reassembly_return_deferred = false;
    gif_state.reassembly_return_chain_blocks = 0;
    gif_reassembly_store_state(candidate, &gif_state);
    candidate->block_choice_start = gif_state.reassembly_return_start;
  }

  if (previous_apparentblocknumber >= 0
      && local_gap_start < 0
      && !prestart_scan_active
      && prestart_gap_start >= 0
      && start_apparentblocknumber > prestart_gap_start
      && (!gif_state.reassembly_return_pending
          || gif_state.reassembly_return_deferred)
      && candidate->block_choice_start
             >= previous_apparentblocknumber + 1
                  + GIF_REASSEMBLY_GAP_SCAN_WINDOW
      && !apparent_block_in_blockvector(candidate->b, prestart_gap_start)) {
    if (gif_reassembly_debug_candidate(candidate)) {
      fprintf(stderr,
              "[gifdbg] prestart-retry start=%" PRId64
              " prev=%" PRId64 " retry_start=%" PRId64
              " bcstart=%" PRId64 "\n",
              blockvector_get_actual_blocknumber(candidate->b, 0),
              previous_apparentblocknumber, prestart_gap_start,
              candidate->block_choice_start);
    }
    candidate->block_choice_start = prestart_gap_start;
    prestart_scan_active = true;
  }

  if (previous_apparentblocknumber >= 0
      && local_gap_start < 0
      && !prestart_scan_active
      && (!gif_state.reassembly_return_pending
          || gif_state.reassembly_return_deferred)
      && candidate->block_choice_start
             >= previous_apparentblocknumber + 1
                  + GIF_REASSEMBLY_GAP_SCAN_WINDOW) {
    block_choice = gif_reassembly_actual_run_rescue_choice(
        candidate, slot, previous_actualblocknumber, &gif_state);
    if (block_choice >= 0) {
      blockvector_remove_choice(candidate->b, slot, block_choice);
      choice_removed = true;
      goto done;
    }

    anchor_resume_start = -1;
    block_choice = gif_reassembly_phase_choice(
        candidate, slot, candidate->block_choice_start, full_scan_count,
        previous_apparentblocknumber, &gif_state, &anchor_resume_start);
    if (block_choice >= 0) {
      if (anchor_resume_start >= 0) {
        candidate->block_choice_start = anchor_resume_start;
      }
      blockvector_remove_choice(candidate->b, slot, block_choice);
      choice_removed = true;
      goto done;
    }

    if (block_choice < 0) {
      anchor_resume_start = -1;
      block_choice = gif_reassembly_phase_probe_choice(
          candidate, slot, candidate->block_choice_start, full_scan_count,
          previous_apparentblocknumber, &gif_state, &anchor_resume_start,
          false);
      if (block_choice >= 0) {
        if (anchor_resume_start >= 0) {
          candidate->block_choice_start = anchor_resume_start;
        }
        blockvector_remove_choice(candidate->b, slot, block_choice);
        choice_removed = true;
        goto done;
      }
    }

    if (block_choice < 0) {
      anchor_resume_start = -1;
      block_choice = gif_reassembly_completion_probe_choice(
          candidate, slot, candidate->block_choice_start, full_scan_count,
          previous_apparentblocknumber, &gif_state, &anchor_resume_start);
      if (block_choice >= 0) {
        if (anchor_resume_start >= 0) {
          candidate->block_choice_start = anchor_resume_start;
        }
        blockvector_remove_choice(candidate->b, slot, block_choice);
        choice_removed = true;
        goto done;
      }
    }

    if (gif_reassembly_actual_backscan_should_yield_to_anchor(
            candidate, &gif_state, previous_actualblocknumber)) {
      anchor_yield_tried = true;
      block_choice = gif_reassembly_valid_anchor_choice(
          candidate, slot, candidate->block_choice_start, full_scan_count,
          previous_apparentblocknumber, &anchor_resume_start);
    }

    if (block_choice < 0
        && gif_reassembly_should_try_actual_backscan(
            &gif_state, previous_apparentblocknumber,
            previous_actualblocknumber, local_gap_start,
            prestart_scan_active, candidate->block_choice_start)) {
      block_choice = gif_reassembly_actual_backscan_choice(
          candidate, slot, previous_actualblocknumber, &gif_state);
      if (block_choice >= 0) {
        blockvector_remove_choice(candidate->b, slot, block_choice);
        choice_removed = true;
        goto done;
      }
    }

    block_choice = gif_reassembly_giflike_run_start_choice(
        candidate, slot, candidate->block_choice_start, full_scan_count,
        previous_apparentblocknumber, &anchor_resume_start);
    if (block_choice < 0 && !anchor_yield_tried) {
      block_choice = gif_reassembly_valid_anchor_choice(
          candidate, slot, candidate->block_choice_start, full_scan_count,
          previous_apparentblocknumber, &anchor_resume_start);
    }
    if (block_choice >= 0) {
      if (anchor_resume_start >= 0) {
        candidate->block_choice_start = anchor_resume_start;
      }
      if (block_choice <= previous_apparentblocknumber
          && gif_state.reassembly_prefix_anchor_trials < UINT32_MAX) {
        gif_state.reassembly_prefix_anchor_trials++;
        gif_reassembly_store_state(candidate, &gif_state);
      }
      blockvector_remove_choice(candidate->b, slot, block_choice);
      choice_removed = true;
      goto done;
    }
  }

  if (previous_apparentblocknumber >= 0
      && local_gap_start < 0
      && !prestart_scan_active
      && (!gif_state.reassembly_return_pending
          || gif_state.reassembly_return_deferred)
      && candidate->block_choice_start >= previous_apparentblocknumber + 1
      && candidate->block_choice_start
             < previous_apparentblocknumber + 1
                   + GIF_REASSEMBLY_GAP_SCAN_WINDOW) {
    local_forward_end =
        previous_apparentblocknumber + 1 + GIF_REASSEMBLY_GAP_SCAN_WINDOW;
    if (local_forward_end > count) {
      local_forward_end = count;
    }
    count = local_forward_end - candidate->block_choice_start;
    local_forward_phase = true;
  }
  else if (local_gap_start >= 0
      && gif_reassembly_apparent_in_forward_window(
             local_gap_start, candidate->block_choice_start,
             GIF_REASSEMBLY_GAP_SCAN_WINDOW)) {
    int64_t offset = candidate->block_choice_start - local_gap_start;
    if (offset < 0) {
      offset += full_scan_count;
    }
    count = GIF_REASSEMBLY_GAP_SCAN_WINDOW - offset;
    if (count > full_scan_count) {
      count = full_scan_count;
    }
    local_gap_phase = true;
  }
  else if (prestart_gap_start >= 0
           && start_apparentblocknumber > prestart_gap_start
           && candidate->block_choice_start >= prestart_gap_start
           && candidate->block_choice_start < start_apparentblocknumber) {
    prestart_end = start_apparentblocknumber;
    if (prestart_end > candidate->block_choice_start) {
      count = prestart_end - candidate->block_choice_start;
      prestart_phase = true;
    }
  }
  else if (gif_state.reassembly_return_pending
           && gif_state.reassembly_return_start >= 0
           && gif_reassembly_choice_in_return_window(
                  &gif_state, candidate->block_choice_start)) {
    int64_t offset;

    if (gif_state.reassembly_return_actual_valid) {
      int64_t current_actual;
      int64_t normalized_start =
          candidate->block_choice_start % full_scan_count;
      if (normalized_start < 0) {
        normalized_start += full_scan_count;
      }
      current_actual = filemirror_actual_blocknumber(
          scalpel_state.filemirror, normalized_start);
      offset = current_actual - gif_state.reassembly_return_actual;
    }
    else {
      offset = candidate->block_choice_start
               - gif_state.reassembly_return_start;
      if (offset < 0) {
        offset += full_scan_count;
      }
    }

    count = GIF_REASSEMBLY_RETURN_SCAN_WINDOW - offset;
    if (count > full_scan_count) {
      count = full_scan_count;
    }
    return_window_phase = true;
  }

  if (previous_apparentblocknumber >= 0
      && local_gap_start < 0
      && !prestart_scan_active
      && !local_forward_phase
      && !prestart_phase
      && !return_window_phase
      && (!gif_state.reassembly_return_pending
          || gif_state.reassembly_return_deferred)
      && candidate->block_choice_start >= 0
      && candidate->block_choice_start <= previous_apparentblocknumber) {
    anchor_resume_start = -1;
    block_choice = gif_reassembly_phase_probe_choice(
        candidate, slot, candidate->block_choice_start, full_scan_count,
        previous_apparentblocknumber, &gif_state, &anchor_resume_start, false);
    if (block_choice >= 0) {
      if (anchor_resume_start >= 0) {
        candidate->block_choice_start = anchor_resume_start;
      }
      blockvector_remove_choice(candidate->b, slot, block_choice);
      choice_removed = true;
      goto done;
    }
  }

restart_scan:
  scan_best_choice = -1;
  scan_contiguous_choice = -1;
  scan_best_reserved = INT64_MAX;
  scan_contiguous_reserved = INT64_MAX;
  scan_best_confidence = BLOCK_CONFIDENCE_INVALID;
  scan_contiguous_confidence = BLOCK_CONFIDENCE_INVALID;

  while (count > 0) {
    block_choice = blockvector_get_choice(
        candidate->b, blockvector_get_num_blocks(candidate->b) - 1,
        candidate->block_choice_start, count, &evaluated);

#if BLOCK_SELECTION_PERFORMANCE_STATS > 0
    BLK_examined += evaluated;
#endif

    if (block_choice == -1) {
      break;
    }

    scan_consecutive = immediate_next >= 0 && block_choice == immediate_next;

    candidate->block_choice_start =
        (block_choice + 1) % filemirror_apparent_blocks(scalpel_state.filemirror);

    count -= evaluated;
    actualblocknumber =
        filemirror_actual_blocknumber(scalpel_state.filemirror, block_choice);

    scan_blocktype =
        filemirror_get_blocktype(scalpel_state.filemirror, actualblocknumber,
                                 candidate->needleidx);

    viable =
        scan_blocktype != BLOCK_CONFIDENCE_INVALID
        && ! apparent_block_in_blockvector(candidate->b, block_choice);

    reserved = scalpel_state.reservations
                   ? filemirror_actual_block_reserved(scalpel_state.filemirror,
                                                      actualblocknumber)
                   : 0;

    if (gif_reassembly_debug_candidate(candidate)
        && previous_apparentblocknumber >= 0
        && block_choice >= previous_apparentblocknumber
        && block_choice <= previous_apparentblocknumber + 16) {
      fprintf(stderr,
              "[gifdbg] scan start=%" PRId64 " prev=%" PRId64
              " choice=%" PRId64 " actual=%" PRId64 " viable=%d confidence=%u"
              " reserved=%" PRId64 " count_left=%" PRId64 "\n",
              blockvector_get_actual_blocknumber(candidate->b, 0),
              previous_apparentblocknumber, block_choice, actualblocknumber,
              viable ? 1 : 0, (unsigned)scan_blocktype, reserved, count);
    }

    if (viable) {
      // A bounded forward window represents a physical locality hypothesis.
      // Test it in disk order; confidence ranks the wider fallback scan.
      if (local_forward_phase || local_gap_phase || return_window_phase) {
        goto done;
      }

      if (scan_consecutive
          && scan_blocktype == BLOCK_CONFIDENCE_VALID
          && reserved == 0) {
        goto done;
      }

      if (scan_consecutive && scan_contiguous_choice == -1) {
        scan_contiguous_choice = block_choice;
        scan_contiguous_confidence = scan_blocktype;
        scan_contiguous_reserved = reserved;
      }

      if (scan_best_choice == -1
          || scan_blocktype > scan_best_confidence
          || (scan_blocktype == scan_best_confidence
              && reserved < scan_best_reserved)) {
        scan_best_choice = block_choice;
        scan_best_confidence = scan_blocktype;
        scan_best_reserved = reserved;
      }
      block_choice = -1;
      continue;
    }

    if (! viable) {
      blockvector_remove_choice(candidate->b,
                                blockvector_get_num_blocks(candidate->b) - 1,
                                block_choice);
      block_choice = -1;
    }
  }

  if (scan_contiguous_choice != -1
      && scan_best_choice != -1
      && scan_best_choice != scan_contiguous_choice) {
    int best_conf = (int)scan_best_confidence;
    int contiguous_conf = (int)scan_contiguous_confidence;
    if (best_conf < contiguous_conf + 20
        && !(scan_best_confidence == BLOCK_CONFIDENCE_VALID
             && scan_contiguous_confidence < 80)) {
      scan_best_choice = scan_contiguous_choice;
      scan_best_confidence = scan_contiguous_confidence;
      scan_best_reserved = scan_contiguous_reserved;
    }
  }
  else if (scan_contiguous_choice != -1 && scan_best_choice == -1) {
    scan_best_choice = scan_contiguous_choice;
    scan_best_confidence = scan_contiguous_confidence;
    scan_best_reserved = scan_contiguous_reserved;
  }

  if (scan_best_choice != -1) {
    block_choice = scan_best_choice;
    goto done;
  }

  if (block_choice == -1
      && prestart_phase) {
    gif_state.reassembly_prestart_exhausted = true;
    gif_reassembly_store_state(candidate, &gif_state);
    if (gif_reassembly_debug_candidate(candidate)) {
      fprintf(stderr,
              "[gifdbg] prestart-exhausted start=%" PRId64
              " prev=%" PRId64 " next_start=%" PRId64
              " full_count=%" PRId64 "\n",
              blockvector_get_actual_blocknumber(candidate->b, 0),
              previous_apparentblocknumber,
              immediate_next >= 0 ? immediate_next : start_apparentblocknumber + 1,
              full_scan_count);
    }
    prestart_phase = false;
    if (immediate_next >= 0 && immediate_next < full_scan_count) {
      candidate->block_choice_start = immediate_next;
    }
    else if (start_apparentblocknumber >= 0 && start_apparentblocknumber + 1 < full_scan_count) {
      candidate->block_choice_start = start_apparentblocknumber + 1;
    }
    count = full_scan_count;
    goto restart_scan;
  }

  if (block_choice == -1
      && local_forward_phase
      && previous_apparentblocknumber >= 0) {
    if (gif_state.reassembly_return_pending
        && gif_state.reassembly_return_deferred
        && gif_state.reassembly_return_start >= 0) {
      gif_state.reassembly_return_deferred = false;
      gif_state.reassembly_return_chain_blocks = 0;
      gif_reassembly_store_state(candidate, &gif_state);
      candidate->block_choice_start = gif_state.reassembly_return_start;
      local_forward_phase = false;
      count = GIF_REASSEMBLY_RETURN_SCAN_WINDOW;
      if (count > full_scan_count) {
        count = full_scan_count;
      }
      return_window_phase = true;
      goto restart_scan;
    }

    anchor_yield_tried = false;
    block_choice = gif_reassembly_actual_run_rescue_choice(
        candidate, slot, previous_actualblocknumber, &gif_state);
    if (block_choice >= 0) {
      blockvector_remove_choice(candidate->b, slot, block_choice);
      choice_removed = true;
      goto done;
    }

    anchor_resume_start = -1;
    block_choice = gif_reassembly_phase_choice(
        candidate, slot, local_forward_end, full_scan_count,
        previous_apparentblocknumber, &gif_state, &anchor_resume_start);
    if (block_choice >= 0) {
      if (anchor_resume_start >= 0) {
        candidate->block_choice_start = anchor_resume_start;
      }
      blockvector_remove_choice(candidate->b, slot, block_choice);
      choice_removed = true;
      goto done;
    }

    if (block_choice < 0) {
      anchor_resume_start = -1;
      block_choice = gif_reassembly_phase_probe_choice(
          candidate, slot, local_forward_end, full_scan_count,
          previous_apparentblocknumber, &gif_state, &anchor_resume_start,
          false);
    }

    if (block_choice < 0) {
      anchor_resume_start = -1;
      block_choice = gif_reassembly_completion_probe_choice(
          candidate, slot, local_forward_end, full_scan_count,
          previous_apparentblocknumber, &gif_state, &anchor_resume_start);
    }

    if (gif_reassembly_actual_backscan_should_yield_to_anchor(
            candidate, &gif_state, previous_actualblocknumber)) {
      anchor_yield_tried = true;
      block_choice = gif_reassembly_valid_anchor_choice(
          candidate, slot, local_forward_end, full_scan_count,
          previous_apparentblocknumber, &anchor_resume_start);
    }

    if (block_choice < 0
        && gif_reassembly_should_try_actual_backscan(
            &gif_state, previous_apparentblocknumber,
            previous_actualblocknumber, local_gap_start,
            prestart_scan_active, candidate->block_choice_start)) {
      block_choice = gif_reassembly_actual_backscan_choice(
          candidate, slot, previous_actualblocknumber, &gif_state);
    }

    if (block_choice < 0) {
      block_choice = gif_reassembly_giflike_run_start_choice(
          candidate, slot, local_forward_end, full_scan_count,
          previous_apparentblocknumber, &anchor_resume_start);
    }
    if (block_choice < 0 && !anchor_yield_tried) {
      block_choice = gif_reassembly_valid_anchor_choice(
          candidate, slot, local_forward_end, full_scan_count,
          previous_apparentblocknumber, &anchor_resume_start);
    }
    if (block_choice >= 0) {
      if (anchor_resume_start >= 0) {
        candidate->block_choice_start = anchor_resume_start;
      }
      if (block_choice <= previous_apparentblocknumber
          && gif_state.reassembly_prefix_anchor_trials < UINT32_MAX) {
        gif_state.reassembly_prefix_anchor_trials++;
        gif_reassembly_store_state(candidate, &gif_state);
      }
      blockvector_remove_choice(candidate->b, slot, block_choice);
      choice_removed = true;
      goto done;
    }

    if (gif_reassembly_debug_candidate(candidate)) {
      fprintf(stderr,
              "[gifdbg] local-forward-exhausted start=%" PRId64
              " prev=%" PRId64 " restart_start=%" PRId64
              " full_count=%" PRId64 "\n",
              blockvector_get_actual_blocknumber(candidate->b, 0),
              previous_apparentblocknumber, local_forward_end,
              full_scan_count);
    }
    local_forward_phase = false;
    count = full_scan_count;
    goto restart_scan;
  }

  if (block_choice == -1 && return_window_phase) {
    goto done;
  }

done:
  if (runtime_state) {
    gif_reassembly_copy_runtime_fields(runtime_state, &gif_state);
  }
  if (block_choice == -1 && gif_reassembly_debug_candidate(candidate)) {
    fprintf(stderr,
            "[gifdbg] no-choice start=%" PRId64
            " prev=%" PRId64 " bcstart=%" PRId64
            " local_gap=%" PRId64 " prestart=%" PRId64
            " return_pending=%d return_start=%" PRId64 "\n",
            blockvector_get_actual_blocknumber(candidate->b, 0),
            previous_apparentblocknumber, candidate->block_choice_start,
            local_gap_start, prestart_gap_start,
            gif_state.reassembly_return_pending ? 1 : 0,
            gif_state.reassembly_return_start);
  }
  if (block_choice != -1 && !choice_removed) {
    blockvector_remove_choice(candidate->b,
                              blockvector_get_num_blocks(candidate->b) - 1,
                              block_choice);
  }

#if BLOCK_SELECTION_PERFORMANCE_STATS > 0
  clock_gettime(CLOCK_MONOTONIC, &BLK_endtime);
  uint64_t BLK_elapsed =
      (BLK_endtime.tv_sec - BLK_starttime.tv_sec) * NANOSECONDS_PER_SECOND
      + (BLK_endtime.tv_nsec - BLK_starttime.tv_nsec);

  atomic_fetch_add_explicit(
      &scalpel_state.search_specs[candidate->needleidx].BLK_calls, 1,
      memory_order_acq_rel);
  atomic_max_u64_pub(
      &scalpel_state.search_specs[candidate->needleidx].BLK_longest,
      BLK_elapsed);
  atomic_fetch_add_explicit(
      &scalpel_state.search_specs[candidate->needleidx].BLK_total,
      BLK_elapsed, memory_order_acq_rel);
  atomic_max_u64_pub(
      &scalpel_state.search_specs[candidate->needleidx].BLK_most_blocks,
      BLK_examined);
#endif

  return block_choice;
}

static inline void gif_reassembly_extension_successful(CarveInfo *candidate) {
  GIFCarveState gif_state = {0};

  if (! candidate->fastpath) {
    blockvector_set_apparent_blocknumber(
        candidate->b, blockvector_get_num_blocks(candidate->b) - 1,
        filemirror_apparent_blocknumber(scalpel_state.filemirror,
                                        candidate->newblock));
    inflate_blockvector_single_block(candidate->b,
                                     blockvector_get_num_blocks(candidate->b) - 1);
    blockvector_set_data_length(candidate->b, candidate->best_validates_to + 1);
  }

  if (blockvector_get_num_blocks(candidate->b) > 1
      && filemirror_apparent_blocks(scalpel_state.filemirror) > 0) {
    int64_t current_apparent =
        blockvector_get_apparent_blocknumber(
            candidate->b, blockvector_get_num_blocks(candidate->b) - 1);
    int64_t previous_apparent =
        blockvector_get_apparent_blocknumber(
            candidate->b, blockvector_get_num_blocks(candidate->b) - 2);
    int64_t previous_actual =
        blockvector_get_actual_blocknumber(
            candidate->b, blockvector_get_num_blocks(candidate->b) - 2);
    uint64_t apparent_blocks =
        filemirror_apparent_blocks(scalpel_state.filemirror);
    int64_t start_apparentblocknumber = -1;
    uint64_t trusted_plateau_blocks = 0;
    int64_t saved_return_start = -1;
    uint32_t remaining_chain_blocks = 0;
    uint32_t remaining_return_blocks = 0;
    bool advanced_confirmed_chain = false;
    bool completed_confirmed_chain = false;
    bool advanced_confirmed_return = false;
    bool returned_to_displacement_source = false;

    gif_reassembly_load_state(candidate, &gif_state);
    remaining_chain_blocks =
        gif_reassembly_proven_chain_blocks(&gif_state);
    remaining_return_blocks =
        gif_reassembly_proven_return_blocks(&gif_state);
    if (gif_state.reassembly_return_pending
        && remaining_chain_blocks > 0
        && current_apparent != gif_state.reassembly_return_start) {
      remaining_chain_blocks--;
      advanced_confirmed_chain = true;
      if (remaining_chain_blocks == 0) {
        gif_state.reassembly_return_deferred = false;
        completed_confirmed_chain = true;
        candidate->block_choice_start = gif_state.reassembly_return_start;
        if (remaining_return_blocks == 0) {
          gif_reassembly_clear_return_start(&gif_state);
        }
      }
      else {
        gif_state.reassembly_return_deferred = true;
        candidate->block_choice_start = current_apparent + 1;
      }
      gif_reassembly_set_return_proof(&gif_state,
                                      remaining_chain_blocks,
                                      remaining_return_blocks);
    }
    if (gif_state.reassembly_return_pending
        && !advanced_confirmed_chain
        && !gif_state.reassembly_return_deferred
        && remaining_chain_blocks == 0
        && remaining_return_blocks > 0
        && current_apparent == gif_state.reassembly_return_start) {
      remaining_return_blocks--;

      if (remaining_return_blocks > 0) {
        gif_reassembly_set_return_start(&gif_state,
                                        current_apparent + 1, false);
        gif_reassembly_set_return_proof(&gif_state, 0,
                                        remaining_return_blocks);
        candidate->block_choice_start = gif_state.reassembly_return_start;
      }
      else {
        gif_reassembly_clear_return_start(&gif_state);
      }
      advanced_confirmed_return = true;
    }
    saved_return_start = gif_state.reassembly_return_start;
    if (scalpel_state.blocksize > 0) {
      start_apparentblocknumber =
          gif_reassembly_anchor_apparent_block(candidate);
      trusted_plateau_blocks =
          gif_reassembly_committed_prestart_tail_blocks(
              candidate, blockvector_get_data_length(candidate->b));
    }

    // A validated jump back to the source position after a contiguous
    // displaced run is a return, not the beginning of another gap.
    if (!gif_state.reassembly_return_pending
        && current_apparent > previous_apparent + GIF_REASSEMBLY_LOCAL_DISTANCE_MAX) {
      uint64_t committed_blocks = blockvector_get_num_blocks(candidate->b);

      if (committed_blocks >= 3) {
        uint64_t displaced_end = committed_blocks - 2;
        uint64_t displaced_start = displaced_end;

        while (displaced_start > 0) {
          int64_t run_current = blockvector_get_apparent_blocknumber(
              candidate->b, displaced_start);
          int64_t run_previous = blockvector_get_apparent_blocknumber(
              candidate->b, displaced_start - 1);

          if (run_current < 0 || run_previous < 0
              || run_current != run_previous + 1) {
            break;
          }
          displaced_start--;
        }

        if (displaced_start > 0) {
          int64_t displaced_first = blockvector_get_apparent_blocknumber(
              candidate->b, displaced_start);
          int64_t source_anchor = blockvector_get_apparent_blocknumber(
              candidate->b, displaced_start - 1);
          uint64_t displaced_blocks =
              displaced_end - displaced_start + 1;

          if (displaced_first >= 0 && source_anchor >= 0
              && displaced_first < source_anchor
              && displaced_blocks < (uint64_t)INT64_MAX
              && (uint64_t)source_anchor
                     <= (uint64_t)INT64_MAX - displaced_blocks - 1
              && current_apparent
                     == source_anchor + (int64_t)displaced_blocks + 1) {
            uint32_t completion_blocks = 0;

            returned_to_displacement_source = true;
            if (current_apparent < INT64_MAX
                && (uint64_t)current_apparent + 1 < apparent_blocks) {
              // A source rejoin can land inside compressed image data where
              // individual blocks expose no new structural checkpoint. Prove
              // a bounded adjacent completion before carrying that plateau.
              completion_blocks = gif_reassembly_probe_adjacent_completion(
                  candidate, &gif_state, current_apparent + 1);
              gif_reassembly_set_return_start(&gif_state,
                                              current_apparent + 1, false);
              gif_reassembly_set_return_proof(
                  &gif_state, 0,
                  completion_blocks > 0
                      ? completion_blocks
                      : GIF_REASSEMBLY_RETURN_CONFIRM_BLOCKS);
              candidate->block_choice_start = current_apparent + 1;
            }
          }
        }
      }
    }

    if (!advanced_confirmed_return
        && !gif_state.reassembly_return_pending
        && !returned_to_displacement_source
        && previous_apparent >= 0
        && current_apparent > previous_apparent + GIF_REASSEMBLY_LOCAL_DISTANCE_MAX
        && previous_apparent + 1 < (int64_t)apparent_blocks) {
      gif_reassembly_set_return_start(&gif_state, previous_apparent + 1,
                                      true);
      saved_return_start = gif_state.reassembly_return_start;
    }

    if (trusted_plateau_blocks > UINT32_MAX) {
      trusted_plateau_blocks = UINT32_MAX;
    }
    if (trusted_plateau_blocks > 0) {
      gif_state.reassembly_trusted_plateau_blocks =
          (uint32_t)trusted_plateau_blocks;
      if (gif_state.reassembly_checkpoint_plateau_blocks
          < gif_state.reassembly_trusted_plateau_blocks) {
        gif_state.reassembly_checkpoint_plateau_blocks =
            gif_state.reassembly_trusted_plateau_blocks;
      }
    }
    else if (gif_state.reassembly_trusted_plateau_blocks > 0
             && start_apparentblocknumber >= 0
             && previous_apparent >= 0
             && current_apparent > previous_apparent
             && current_apparent >= start_apparentblocknumber) {
      if (gif_state.reassembly_trusted_plateau_blocks < UINT32_MAX) {
        gif_state.reassembly_trusted_plateau_blocks++;
      }
      if (gif_state.reassembly_checkpoint_plateau_blocks
          < gif_state.reassembly_trusted_plateau_blocks) {
        gif_state.reassembly_checkpoint_plateau_blocks =
            gif_state.reassembly_trusted_plateau_blocks;
      }
    }
    else if (gif_state.reassembly_trusted_plateau_blocks > 0
             && start_apparentblocknumber >= 0
             && (current_apparent >= start_apparentblocknumber
                 || gif_reassembly_tail_block_in_prestart_window(candidate))) {
      /* Once the candidate has rejoined the main forward chain, a later
         nonlocal accept in the same forward/pre-start window should not
         erase the checkpoint allowance that the earlier plateau earned. */
    }
    else if (gif_state.reassembly_trusted_plateau_blocks > 0) {
      gif_state.reassembly_trusted_plateau_blocks = 0;
    }

    if (advanced_confirmed_return) {
      // The exact return sequence and its length were established by the
      // bounded phase probe; its cursor was advanced above.
    }
    else if (gif_state.reassembly_trusted_plateau_blocks > 0
        && saved_return_start >= 0
        && previous_apparent >= saved_return_start
        && current_apparent >= saved_return_start
        && current_apparent < previous_apparent
        && !gif_reassembly_choice_in_return_window(&gif_state,
                                                   current_apparent)) {
      int64_t next_return_gap =
          gif_reassembly_next_return_gap_choice(
              candidate, current_apparent,
              saved_return_start - GIF_REASSEMBLY_GAP_SCAN_WINDOW);

      if (next_return_gap >= 0) {
        gif_reassembly_set_return_start(&gif_state, next_return_gap,
                                        false);
      }
      else {
        gif_reassembly_set_return_start(
            &gif_state,
            (previous_apparent + 2) % (int64_t)apparent_blocks,
            false);
      }
    }
    else if (gif_state.reassembly_return_pending
        && !gif_state.reassembly_return_deferred
        && current_apparent >= 0
        && gif_reassembly_choice_in_return_window(&gif_state,
                                                  current_apparent)) {
      int64_t next_return_gap = -1;

      if (gif_state.reassembly_trusted_plateau_blocks > 0
          && saved_return_start >= 0
          && previous_apparent >= saved_return_start
          && current_apparent > previous_apparent) {
        next_return_gap =
            gif_reassembly_next_return_gap_choice(
                candidate, current_apparent,
                saved_return_start - GIF_REASSEMBLY_GAP_SCAN_WINDOW);
      }

      if (next_return_gap >= 0) {
        gif_reassembly_set_return_start(&gif_state, next_return_gap,
                                        false);
      }
      else {
        gif_reassembly_clear_return_start(&gif_state);
      }
    }
    else if (!gif_state.reassembly_return_pending
        && current_apparent >= 0
        && previous_apparent >= 0
        && current_apparent < previous_apparent) {
      gif_reassembly_set_return_start_near_actual(
          candidate, &gif_state,
          (previous_apparent + 2) % (int64_t)apparent_blocks,
          previous_actual, true);
    }
    else if (gif_state.reassembly_return_pending
             && !completed_confirmed_chain
             && !returned_to_displacement_source
             && current_apparent >= 0
             && previous_apparent >= 0
             && current_apparent > previous_apparent
             && !gif_state.reassembly_return_deferred
             && current_apparent < gif_state.reassembly_return_start) {
      gif_reassembly_set_return_start(
          &gif_state,
          (gif_state.reassembly_return_start + 1)
              % (int64_t)apparent_blocks,
          false);
      gif_state.reassembly_return_deferred = false;
      gif_state.reassembly_return_chain_blocks = 0;
    }

    gif_state.reassembly_prefix_anchor_trials = 0;
    gif_state.reassembly_actual_backscan_active = false;
    gif_state.reassembly_actual_backscan_anchor = -1;
    gif_state.reassembly_actual_backscan_next = -1;
    if (!gif_state.reassembly_scan_cursor_valid
        || gif_state.reassembly_scan_cursor_length
               < blockvector_get_data_length(candidate->b)) {
      gif_reassembly_clear_scan_cursor(&gif_state);
    }
    gif_state.reassembly_completion_probe_exhausted = false;
    gif_state.reassembly_completion_probe_exhausted_length = 0;
    gif_reassembly_clear_actual_run_rescue(&gif_state);

    if (gif_reassembly_debug_candidate(candidate)) {
      fprintf(stderr,
              "[gifdbg] extension-success start=%" PRId64
              " prev_app=%" PRId64 " cur_app=%" PRId64
              " prev_actual=%" PRId64
              " return_pending=%d return_deferred=%d"
              " return_start=%" PRId64 " return_actual=%" PRId64
              " source_return=%d\n",
              blockvector_get_actual_blocknumber(candidate->b, 0),
              previous_apparent, current_apparent, previous_actual,
              gif_state.reassembly_return_pending ? 1 : 0,
              gif_state.reassembly_return_deferred ? 1 : 0,
              gif_state.reassembly_return_start,
              gif_state.reassembly_return_actual_valid
                  ? gif_state.reassembly_return_actual
                  : -1,
              returned_to_displacement_source ? 1 : 0);
    }

    gif_reassembly_store_state(candidate, &gif_state);
  }
}

static inline void gif_reassembly_checkpoint_flush(CarveInfo *candidate) {
  uint64_t bs = (uint64_t)scalpel_state.blocksize;
  uint64_t original_length = blockvector_get_data_length(candidate->b);
  uint64_t original_blocks = blockvector_get_num_blocks(candidate->b);
  uint64_t original_committed_blocks =
      bs > 0 ? CEILDIV(original_length, bs) : original_blocks;
  int64_t saved_block_choice_start = candidate->block_choice_start;
  int64_t saved_newblock = candidate->newblock;
  uint64_t saved_best_validates_to = candidate->best_validates_to;
  uint64_t data_length;
  uint64_t keep_len;
  uint64_t keep_blocks;
  bool cold_validates = false;
  bool cold_promising = false;
  uint64_t cold_validates_to = 0;
  bool active_scan_slot =
      bs > 0
      && original_length > 0
      && original_blocks == original_committed_blocks + 1
      && saved_block_choice_start >= 0;
  bool saved_best_reaches_materialized =
      original_length > 0 && saved_best_validates_to >= original_length - 1;
  bool speculative_best_beyond_materialized =
      active_scan_slot
      && saved_newblock >= 0
      && saved_best_validates_to >= original_length;
  bool speculative_best_fills_slot =
      speculative_best_beyond_materialized
      && saved_best_validates_to < UINT64_MAX
      && bs > 0
      && saved_best_validates_to - original_length + 1 >= bs;
  bool materialized_speculative_frontier = false;
  bool preserve_frontier =
      candidate->newblock >= 0 && !speculative_best_beyond_materialized;
  bool frontier_metadata_only =
      preserve_frontier
      && active_scan_slot
      && saved_best_reaches_materialized;
  bool preserve_scan_slot =
      active_scan_slot
      && saved_best_reaches_materialized
      && (!preserve_frontier || speculative_best_beyond_materialized);
  bool keep_prestart_plateau = false;
  bool saved_scan_cursor_for_original = false;
  uint64_t saved_trusted_plateau_allowance = 0;
  uint32_t saved_checkpoint_plateau_blocks = 0;
  GIFCarveState cold_state = {0};
  GIFCarveState saved_state = {0};

  gif_reassembly_load_state(candidate, &saved_state);
  saved_scan_cursor_for_original =
      saved_state.reassembly_scan_cursor_valid
      && saved_state.reassembly_scan_cursor >= 0
      && saved_state.reassembly_scan_cursor_length == original_length;
  if (gif_reassembly_debug_candidate(candidate)) {
    fprintf(stderr,
            "[gifdbg] ckpt-enter start=%" PRId64
            " data_length=%" PRIu64 " blocks=%" PRIu64
            " best=%" PRIu64 " newblock=%" PRId64 "\n",
            blockvector_get_num_blocks(candidate->b) > 0
                ? blockvector_get_actual_blocknumber(candidate->b, 0)
                : -1,
            original_length, original_blocks, saved_best_validates_to,
            saved_newblock);
  }
  saved_checkpoint_plateau_blocks =
      saved_state.reassembly_checkpoint_plateau_blocks;
  if (saved_checkpoint_plateau_blocks
      < saved_state.reassembly_trusted_plateau_blocks) {
    saved_checkpoint_plateau_blocks =
        saved_state.reassembly_trusted_plateau_blocks;
  }
  if (bs > 0 && saved_checkpoint_plateau_blocks > 0) {
    saved_trusted_plateau_allowance =
        ((uint64_t)saved_checkpoint_plateau_blocks + 1) * bs
        + GIF_REASSEMBLY_VALIDATE_SLACK;
  }

  // Checkpointing should preserve a speculative terminal scan when the
  // committed prefix survives cold validation unchanged. Active GIF
  // candidates often carry one extra speculative terminal slot beyond the
  // committed byte length. A best block found inside that scan is not a
  // committed frontier until the scan finishes, so checkpoint it as a cursor
  // and slot to resume from, not as `newblock` to promote after restart.
  candidate->fastpath = false;
  data_length = blockvector_get_data_length(candidate->b);
  if (!preserve_scan_slot && data_length > 0 && bs > 0) {
    keep_blocks = CEILDIV(data_length, bs);
    if (keep_blocks == 0) {
      keep_blocks = 1;
    }
    if (blockvector_get_num_blocks(candidate->b) > keep_blocks) {
      resize_blockvector(candidate->b, keep_blocks);
      inflate_blockvector(candidate->b);
    }
  }

  data_length = blockvector_get_data_length(candidate->b);
  if (data_length == 0) {
    candidate->best_validates_to = 0;
    gif_reassembly_store_state(candidate, NULL);
    return;
  }

  gif_validate_core(blockvector_get_data_pointer(candidate->b), data_length,
                    &cold_validates, &cold_validates_to, &cold_promising,
                    candidate->needleidx, scalpel_state.blocksize, NULL,
                    &cold_state);
  if (gif_reassembly_debug_candidate(candidate)) {
    fprintf(stderr,
            "[gifdbg] ckpt-cold start=%" PRId64
            " validates=%d promising=%d validates_to=%" PRIu64
            " data_length=%" PRIu64 "\n",
            blockvector_get_num_blocks(candidate->b) > 0
                ? blockvector_get_actual_blocknumber(candidate->b, 0)
                : -1,
            cold_validates ? 1 : 0, cold_promising ? 1 : 0,
            cold_validates_to, data_length);
  }

  if (speculative_best_fills_slot
      && (cold_validates || cold_validates_to + 1 >= data_length)) {
    int64_t saved_apparent =
        filemirror_apparent_blocknumber(scalpel_state.filemirror,
                                        saved_newblock);

    if (saved_apparent >= 0 && original_committed_blocks > 0) {
      uint64_t frontier_slot = original_committed_blocks;

      if (blockvector_get_num_blocks(candidate->b) < frontier_slot + 1) {
        resize_blockvector(candidate->b, frontier_slot + 1);
      }
      else if (blockvector_get_num_blocks(candidate->b) > frontier_slot + 1) {
        resize_blockvector(candidate->b, frontier_slot + 1);
      }
      blockvector_set_data_length(candidate->b, original_length);
      blockvector_set_apparent_blocknumber(candidate->b, frontier_slot,
                                           saved_apparent);
      inflate_blockvector_single_block(candidate->b, frontier_slot);
      blockvector_set_data_length(candidate->b, saved_best_validates_to + 1);

      memset(&cold_state, 0, sizeof(cold_state));
      data_length = blockvector_get_data_length(candidate->b);
      gif_validate_core(blockvector_get_data_pointer(candidate->b), data_length,
                        &cold_validates, &cold_validates_to, &cold_promising,
                        candidate->needleidx, scalpel_state.blocksize, NULL,
                        &cold_state);
      preserve_frontier = false;
      preserve_scan_slot = false;
      frontier_metadata_only = false;
      materialized_speculative_frontier = true;
    }
  }

  if (!cold_validates && cold_validates_to + 1 < data_length) {
    keep_prestart_plateau =
        cold_promising
        && saved_best_validates_to + 1 == data_length
        && (gif_reassembly_tail_block_in_prestart_window(candidate)
            || (saved_trusted_plateau_allowance > 0
                && cold_validates_to + saved_trusted_plateau_allowance
                       >= data_length - 1));

    if (!keep_prestart_plateau) {
      keep_len = cold_validates_to + 1;
      if (bs > 0 && keep_len < bs) {
        keep_len = bs;
      }
      if (keep_len < data_length) {
        blockvector_set_data_length(candidate->b, keep_len);
        if (bs > 0) {
          keep_blocks = CEILDIV(keep_len, bs);
          if (keep_blocks == 0) {
            keep_blocks = 1;
          }
          resize_blockvector(candidate->b, keep_blocks);
          inflate_blockvector(candidate->b);
        }

        memset(&cold_state, 0, sizeof(cold_state));
        gif_validate_core(blockvector_get_data_pointer(candidate->b),
                          blockvector_get_data_length(candidate->b),
                          &cold_validates, &cold_validates_to, &cold_promising,
                          candidate->needleidx, scalpel_state.blocksize, NULL,
                          &cold_state);
        preserve_frontier = false;
        preserve_scan_slot = false;
      }
    }
  }

  if (keep_prestart_plateau
      && !cold_validates
      && cold_validates_to + 1 < blockvector_get_data_length(candidate->b)) {
    /* The speculative tail bytes may be worth keeping across a checkpoint,
       but the frontier metadata is not checkpoint-safe once cold validation
       falls short of the materialized bytes. Force the saved checkpoint state
       back to the cold-safe prefix so restore starts from a real frontier. */
    preserve_frontier = false;
  }

  if (blockvector_get_data_length(candidate->b) != original_length
      || blockvector_get_num_blocks(candidate->b) != original_blocks) {
    bool dropped_speculative_slot_only =
        frontier_metadata_only
        && blockvector_get_data_length(candidate->b) == original_length
        && blockvector_get_num_blocks(candidate->b) == original_committed_blocks;

    if (!dropped_speculative_slot_only && !materialized_speculative_frontier) {
      preserve_frontier = false;
    }
    if (!keep_prestart_plateau
        || blockvector_get_data_length(candidate->b) != original_length) {
      saved_state.reassembly_trusted_plateau_blocks = 0;
      saved_state.reassembly_checkpoint_plateau_blocks = 0;
    }
    preserve_scan_slot = false;
  }

  if (preserve_scan_slot
      && saved_block_choice_start >= 0
      && blockvector_get_data_length(candidate->b) == original_length) {
    if (!saved_scan_cursor_for_original) {
      gif_reassembly_set_scan_cursor(&saved_state, saved_block_choice_start,
                                     original_length);
    }
  }
  else if (!saved_scan_cursor_for_original) {
    gif_reassembly_clear_scan_cursor(&saved_state);
  }

  if (blockvector_get_data_length(candidate->b) == original_length) {
    gif_reassembly_copy_runtime_fields(&cold_state, &saved_state);
  }
  else if (saved_state.reassembly_scan_cursor_valid
           && saved_state.reassembly_scan_cursor_length
                  > blockvector_get_data_length(candidate->b)) {
    // A cold-safe prefix must rebuild length-dependent return and probe
    // state. The deferred cursor remains valid for the later scan position
    // because it is also tied to the original candidate length.
    cold_state.reassembly_scan_cursor_valid = true;
    cold_state.reassembly_scan_cursor = saved_state.reassembly_scan_cursor;
    cold_state.reassembly_scan_cursor_actual_valid =
        saved_state.reassembly_scan_cursor_actual_valid;
    cold_state.reassembly_scan_cursor_actual =
        saved_state.reassembly_scan_cursor_actual;
    cold_state.reassembly_scan_cursor_length =
        saved_state.reassembly_scan_cursor_length;
  }
  cold_state.reassembly_preserved_frontier = preserve_frontier;
  gif_reassembly_store_state(candidate, &cold_state);

  if (preserve_frontier) {
    candidate->newblock = saved_newblock;
    candidate->best_validates_to = saved_best_validates_to;
    if (candidate->best_validates_to + 1 < blockvector_get_data_length(candidate->b)) {
      candidate->best_validates_to = blockvector_get_data_length(candidate->b) - 1;
    }
    candidate->block_choice_start = saved_block_choice_start;
  }
  else if (preserve_scan_slot) {
    candidate->newblock = -1;
    if (blockvector_get_data_length(candidate->b) > 0) {
      candidate->best_validates_to =
          blockvector_get_data_length(candidate->b) - 1;
    }
    else {
      candidate->best_validates_to = cold_validates_to;
    }
    candidate->block_choice_start = saved_block_choice_start;
    candidate->no_initial_block_extension = true;
  }
  else {
    candidate->newblock = -1;
    if (keep_prestart_plateau) {
      int64_t restart_start =
          gif_reassembly_resume_choice_start(candidate,
                                             saved_block_choice_start);
      candidate->best_validates_to = cold_validates_to;
      candidate->block_choice_start =
          restart_start >= 0 ? restart_start : saved_block_choice_start;
    }
    else if (blockvector_get_data_length(candidate->b) > 0) {
      candidate->best_validates_to = blockvector_get_data_length(candidate->b) - 1;
    }
    else {
      candidate->best_validates_to = 0;
    }
    if (!keep_prestart_plateau && candidate->best_choices) {
      destroy_queue(candidate->best_choices);
      init_queue(candidate->best_choices, sizeof(int64_t), true, NULL, true);
    }
    if (!keep_prestart_plateau
        && blockvector_get_num_blocks(candidate->b) == original_blocks
        && blockvector_get_num_blocks(candidate->b) > 0) {
      blockvector_free_choices(candidate->b,
                               blockvector_get_num_blocks(candidate->b) - 1);
    }
    if (!keep_prestart_plateau) {
      candidate->block_choice_start =
          gif_reassembly_resume_choice_start(candidate,
                                             saved_block_choice_start);
    }
  }

  if (gif_reassembly_debug_candidate(candidate)) {
    fprintf(stderr,
            "[gifdbg] ckpt-exit start=%" PRId64
            " data_length=%" PRIu64 " blocks=%" PRIu64
            " best=%" PRIu64 " newblock=%" PRId64
            " preserve=%d preserve_scan=%d keep_prestart=%d noinit=%d\n",
            blockvector_get_num_blocks(candidate->b) > 0
                ? blockvector_get_actual_blocknumber(candidate->b, 0)
                : -1,
            blockvector_get_data_length(candidate->b),
            blockvector_get_num_blocks(candidate->b),
            candidate->best_validates_to, candidate->newblock,
            preserve_frontier ? 1 : 0, preserve_scan_slot ? 1 : 0,
            keep_prestart_plateau ? 1 : 0,
            candidate->no_initial_block_extension ? 1 : 0);
  }
}

static inline void gif_reassembly_did_not_validate(
    int id, CarveInfo *candidate, int64_t block_choice, uint64_t oldlength,
    const GIFCarveState *base_state, const GIFValidationSummary *trial_summary,
    const GIFCarveState *trial_state, GIFValidationSummary *best_summary,
    GIFCarveState *best_state, bool *best_state_valid,
    GIFReassemblyFollowCache *best_follow_cache,
    bool *stop_scanning_out, bool *checkpoint_interrupted_out) {
  int64_t actualblocknumber;
  bool better = false;
  int64_t current_actualblocknumber =
      filemirror_actual_blocknumber(scalpel_state.filemirror, block_choice);
  int64_t current_apparentblocknumber = block_choice;
  int64_t previous_apparentblocknumber = -1;
  int64_t previous_actualblocknumber = -1;
  int64_t local_gap_start = -1;
  int64_t prestart_gap_start = -1;
  int64_t start_apparentblocknumber = -1;
  int64_t locality_anchor = -1;
  bool no_best_yet = candidate->newblock < 0;
  bool current_is_seed_forward = false;
  bool current_is_local_gap = false;
  bool current_is_prestart_gap = false;
  bool current_is_local_forward = false;
  bool current_is_phase_aligned_adjacent = false;
  bool current_is_confirmed_path = false;
  bool has_committed_actual_gap = false;
  bool trial_preserves_length = false;
  uint64_t committed_prestart_tail_blocks = 0;
  uint64_t committed_blocks = 0;
  uint64_t trusted_plateau_blocks = 0;
  uint32_t proven_chain_blocks = 0;
  uint32_t proven_return_blocks = 0;
  uint64_t prestart_accept_allowance =
      (uint64_t)scalpel_state.blocksize + GIF_REASSEMBLY_VALIDATE_SLACK;
  GIFCarveState gif_state = {0};
  GIFReassemblyScore base_score = {0};

  if (blockvector_get_num_blocks(candidate->b) >= 2) {
    previous_apparentblocknumber = blockvector_get_apparent_blocknumber(
        candidate->b, blockvector_get_num_blocks(candidate->b) - 2);
    previous_actualblocknumber = blockvector_get_actual_blocknumber(
        candidate->b, blockvector_get_num_blocks(candidate->b) - 2);
  }
  local_gap_start = gif_reassembly_recent_forward_gap_start(candidate);
  prestart_gap_start = gif_reassembly_prestart_gap_start(candidate);
  if (scalpel_state.blocksize > 0) {
    committed_blocks =
        CEILDIV(oldlength, (uint64_t)scalpel_state.blocksize);
    start_apparentblocknumber =
        gif_reassembly_anchor_apparent_block(candidate);
    committed_prestart_tail_blocks =
        gif_reassembly_committed_prestart_tail_blocks(candidate, oldlength);
  }
  gif_reassembly_load_state(candidate, &gif_state);
  has_committed_actual_gap =
      gif_reassembly_committed_actual_gap_count(candidate, oldlength) > 0;
  proven_chain_blocks = gif_reassembly_proven_chain_blocks(&gif_state);
  proven_return_blocks = gif_reassembly_proven_return_blocks(&gif_state);
  gif_reassembly_capture_score_from_state(base_state, &base_score);
  trusted_plateau_blocks = committed_prestart_tail_blocks;
  if (gif_state.reassembly_trusted_plateau_blocks > trusted_plateau_blocks) {
    trusted_plateau_blocks = gif_state.reassembly_trusted_plateau_blocks;
  }
  current_is_seed_forward =
      committed_blocks == 1
      && gif_reassembly_local_seed_choice(start_apparentblocknumber,
                                          current_apparentblocknumber);
  current_is_local_gap =
      local_gap_start >= 0
      && current_apparentblocknumber >= local_gap_start
      && current_apparentblocknumber
             < local_gap_start + GIF_REASSEMBLY_GAP_SCAN_WINDOW;
  current_is_prestart_gap =
      gif_reassembly_choice_in_prestart_gap(prestart_gap_start,
                                            start_apparentblocknumber,
                                            current_apparentblocknumber);
  current_is_local_forward =
      previous_apparentblocknumber >= 0
      && gif_reassembly_local_forward_choice(previous_apparentblocknumber,
                                             current_apparentblocknumber);
  current_is_phase_aligned_adjacent =
      previous_apparentblocknumber >= 0
      && current_apparentblocknumber == previous_apparentblocknumber + 1
      && gif_state.reassembly_phase_hint_valid
      && gif_state.reassembly_phase_hint_length == oldlength
      && gif_reassembly_block_matches_phase_probe_hint(
             current_apparentblocknumber,
             gif_state.reassembly_phase_hint_offset,
             gif_state.reassembly_phase_hint_threshold);
  if (gif_state.reassembly_return_pending
      && (proven_chain_blocks > 0 || proven_return_blocks > 0)) {
    int64_t next_choice = current_apparentblocknumber + 1;
    int64_t apparent_blocks =
        (int64_t)filemirror_apparent_blocks(scalpel_state.filemirror);

    if (apparent_blocks > 0 && next_choice >= apparent_blocks) {
      next_choice %= apparent_blocks;
    }
    if (proven_chain_blocks > 0) {
      current_is_confirmed_path =
          current_apparentblocknumber != gif_state.reassembly_return_start
          && candidate->block_choice_start == next_choice;
    }
    else if (!gif_state.reassembly_return_deferred
             && proven_return_blocks > 0) {
      current_is_confirmed_path =
          current_apparentblocknumber == gif_state.reassembly_return_start;
    }
  }
  prestart_accept_allowance +=
      trusted_plateau_blocks * (uint64_t)scalpel_state.blocksize;
  locality_anchor = gif_reassembly_effective_locality_anchor(
      candidate, previous_apparentblocknumber);

  if (gif_reassembly_debug_candidate(candidate)) {
    int64_t dbg0 = blockvector_get_num_blocks(candidate->b) > 0
                       ? blockvector_get_actual_blocknumber(candidate->b, 0)
                       : -1;
    int64_t dbg1 = blockvector_get_num_blocks(candidate->b) > 1
                       ? blockvector_get_actual_blocknumber(candidate->b, 1)
                       : -1;
    int64_t dbg2 = blockvector_get_num_blocks(candidate->b) > 2
                       ? blockvector_get_actual_blocknumber(candidate->b, 2)
                       : -1;
    fprintf(stderr,
            "[gifdbg] did-not-validate start=%" PRId64
            " blocks=%" PRIu64 " len=%" PRIu64
            " a0=%" PRId64 " a1=%" PRId64 " a2=%" PRId64
            " choice=%" PRId64 " oldlen=%" PRIu64
            " vt=%" PRIu64 " newblock=%" PRId64 " bestvt=%" PRIu64 "\n",
            dbg0, blockvector_get_num_blocks(candidate->b),
            blockvector_get_data_length(candidate->b),
            dbg0, dbg1, dbg2, block_choice, oldlength,
            trial_summary->validates_to, candidate->newblock,
            candidate->best_validates_to);
  }

  if (gif_reassembly_checkpoint_requested()) {
    gif_reassembly_interrupt_scan(stop_scanning_out,
                                  checkpoint_interrupted_out);
    return;
  }

  // A trial must either extend byte validation or improve the structural
  // score before it can be committed by a local shortcut.
  bool trial_advanced_bytes = trial_summary->validates_to >= oldlength;
  trial_preserves_length = trial_summary->validates_to + 1 >= oldlength;
  bool trial_supported_by_progress =
      !base_state
      || trial_advanced_bytes
      || gif_reassembly_score_advanced(&trial_summary->score, &base_score);

  if (current_is_confirmed_path) {
    // The bounded phase probe has already validated this displaced block and
    // its return sequence together. Commit each proven block only while the
    // standalone trial remains promising and structurally nonregressing.
    if (no_best_yet
        && trial_summary->promising
        && trial_preserves_length
        && gif_reassembly_score_not_regressed(&trial_summary->score,
                                              &base_score)) {
      candidate->best_validates_to =
          gif_reassembly_preserve_committed_best(candidate,
                                                 trial_summary->validates_to);
      candidate->newblock = current_actualblocknumber;
      *best_summary = *trial_summary;
      if (trial_state) {
        *best_state = *trial_state;
        *best_state_valid = true;
      }
      *stop_scanning_out = true;
      return;
    }

    gif_reassembly_clear_return_start(&gif_state);
    gif_reassembly_store_state(candidate, &gif_state);
  }

  if (current_is_local_forward
      && gif_state.reassembly_return_pending
      && gif_state.reassembly_return_deferred
      && gif_state.reassembly_return_start >= 0
      && !trial_advanced_bytes) {
    // A deep probe has already confirmed this displaced run and its return.
    // Preserve the expected adjacent chain block when it introduces no
    // structural regression, even if it ends inside a semantic plateau.
    if (no_best_yet
        && proven_chain_blocks > 0
        && trial_preserves_length
        && gif_reassembly_score_not_regressed(&trial_summary->score,
                                              &base_score)) {
      candidate->best_validates_to =
          gif_reassembly_preserve_committed_best(candidate,
                                                 trial_summary->validates_to);
      candidate->newblock = current_actualblocknumber;
      *best_summary = *trial_summary;
      if (trial_state) {
        *best_state = *trial_state;
        *best_state_valid = true;
      }
      *stop_scanning_out = true;
      return;
    }

    gif_state.reassembly_return_deferred = false;
    gif_state.reassembly_return_chain_blocks = 0;
    gif_reassembly_store_state(candidate, &gif_state);
    candidate->block_choice_start = gif_state.reassembly_return_start;
    return;
  }
  if (no_best_yet
      && current_is_seed_forward
      && trial_preserves_length
      && trial_summary->validates_to
             + (uint64_t)scalpel_state.blocksize
             + GIF_REASSEMBLY_VALIDATE_SLACK
             >= oldlength - 1
      && (!base_state
          || trial_advanced_bytes
          || gif_reassembly_score_advanced(&trial_summary->score,
                                           &base_score))) {
    if (gif_reassembly_debug_candidate(candidate)) {
      fprintf(stderr,
              "[gifdbg] accept-seed-forward start=%" PRId64
              " current=%" PRId64 " actual=%" PRId64
              " validates_to=%" PRIu64 " oldlength=%" PRIu64 "\n",
              blockvector_get_actual_blocknumber(candidate->b, 0),
              current_apparentblocknumber, current_actualblocknumber,
              trial_summary->validates_to, oldlength);
    }
    candidate->best_validates_to =
        gif_reassembly_preserve_committed_best(candidate,
                                               trial_summary->validates_to);
    candidate->newblock = current_actualblocknumber;
    *best_summary = *trial_summary;
    if (trial_state) {
      *best_state = *trial_state;
      *best_state_valid = true;
    }
    gif_reassembly_maybe_arm_fastpath(candidate, oldlength,
                                      current_apparentblocknumber,
                                      previous_apparentblocknumber,
                                      trial_summary, base_state);
    *stop_scanning_out = true;
    return;
  }

  if (no_best_yet
      && current_is_seed_forward
      && trial_state
      && base_state
      && trial_preserves_length
      && !trial_advanced_bytes
      && gif_reassembly_score_not_regressed(&trial_summary->score,
                                            &base_score)) {
    GIFValidationSummary seed_path_summary = {0};
    uint32_t seed_chain_blocks = 0;
    uint32_t seed_return_blocks = 0;
    int64_t seed_return_start = -1;
    bool seed_path_proven = gif_reassembly_probe_nonlocal_return(
        id, candidate, oldlength, base_state, current_actualblocknumber,
        previous_apparentblocknumber, GIF_REASSEMBLY_GAP_SCAN_WINDOW,
        false, false, GIF_REASSEMBLY_RETURN_CONFIRM_BLOCKS,
        &seed_path_summary,
        &seed_chain_blocks, &seed_return_blocks, &seed_return_start);

    if (gif_reassembly_checkpoint_requested()) {
      gif_reassembly_interrupt_scan(stop_scanning_out,
                                    checkpoint_interrupted_out);
      return;
    }

    // A seed block may end inside a long compressed-data plateau. Commit it
    // only when a bounded scan also proves the later return path and advances
    // structural evidence beyond the one-block trial.
    if (seed_path_proven
        && seed_return_start >= 0
        && seed_return_blocks > 0
        && (seed_path_summary.validates
            || seed_return_blocks == GIF_REASSEMBLY_RETURN_CONFIRM_BLOCKS)
        && gif_reassembly_compare_probe_summary(&seed_path_summary,
                                                trial_summary) > 0
        && gif_reassembly_score_advanced(&seed_path_summary.score,
                                         &base_score)) {
      candidate->best_validates_to =
          gif_reassembly_preserve_committed_best(candidate,
                                                 trial_summary->validates_to);
      candidate->newblock = current_actualblocknumber;
      *best_summary = *trial_summary;
      *best_state = *trial_state;
      gif_reassembly_set_return_start(best_state, seed_return_start,
                                      seed_chain_blocks > 1);
      gif_reassembly_set_return_proof(best_state, seed_chain_blocks,
                                      seed_return_blocks);
      *best_state_valid = true;
      *stop_scanning_out = true;
      return;
    }
  }

  if (no_best_yet
      && current_is_local_gap
      && trial_preserves_length
      && trial_summary->validates_to
             + (uint64_t)scalpel_state.blocksize
             + GIF_REASSEMBLY_VALIDATE_SLACK
             >= oldlength - 1
      && (!base_state
          || trial_advanced_bytes
          || gif_reassembly_score_advanced(&trial_summary->score,
                                           &base_score))) {
    if (gif_reassembly_debug_candidate(candidate)) {
      fprintf(stderr,
              "[gifdbg] accept-local-gap start=%" PRId64
              " current=%" PRId64 " actual=%" PRId64
              " validates_to=%" PRIu64 " oldlength=%" PRIu64 "\n",
              blockvector_get_actual_blocknumber(candidate->b, 0),
              current_apparentblocknumber, current_actualblocknumber,
              trial_summary->validates_to, oldlength);
    }
    candidate->best_validates_to =
        gif_reassembly_preserve_committed_best(candidate,
                                               trial_summary->validates_to);
    candidate->newblock = current_actualblocknumber;
    *best_summary = *trial_summary;
    if (trial_state) {
      *best_state = *trial_state;
      *best_state_valid = true;
    }
    *stop_scanning_out = true;
    return;
  }

  if (no_best_yet
      && current_is_prestart_gap
      && trial_summary->validates_to + prestart_accept_allowance
             >= oldlength - 1
      && trial_supported_by_progress) {
    candidate->best_validates_to =
        gif_reassembly_preserve_committed_best(candidate,
                                               trial_summary->validates_to);
    candidate->newblock = current_actualblocknumber;
    *best_summary = *trial_summary;
    if (trial_state) {
      *best_state = *trial_state;
      *best_state_valid = true;
    }
    *stop_scanning_out = true;
    return;
  }

  if (no_best_yet
      && trusted_plateau_blocks > 0
      && gif_state.reassembly_return_start >= 0
      && previous_apparentblocknumber >= gif_state.reassembly_return_start
      && current_apparentblocknumber >= gif_state.reassembly_return_start
      && current_apparentblocknumber
             < gif_state.reassembly_return_start
                   + GIF_REASSEMBLY_GAP_SCAN_WINDOW
      && trial_preserves_length
      && trial_summary->validates_to + prestart_accept_allowance
             >= oldlength - 1
      && trial_supported_by_progress) {
    candidate->best_validates_to =
        gif_reassembly_preserve_committed_best(candidate,
                                               trial_summary->validates_to);
    candidate->newblock = current_actualblocknumber;
    *best_summary = *trial_summary;
    if (trial_state) {
      *best_state = *trial_state;
      *best_state_valid = true;
    }
    *stop_scanning_out = true;
    return;
  }

  if (no_best_yet
      && trusted_plateau_blocks > 0
      && previous_apparentblocknumber >= 0
      && current_apparentblocknumber > previous_apparentblocknumber
      && trial_preserves_length
      && trial_summary->validates_to + prestart_accept_allowance
             >= oldlength - 1
      && trial_supported_by_progress) {
    candidate->best_validates_to =
        gif_reassembly_preserve_committed_best(candidate,
                                               trial_summary->validates_to);
    candidate->newblock = current_actualblocknumber;
    *best_summary = *trial_summary;
    if (trial_state) {
      *best_state = *trial_state;
      *best_state_valid = true;
    }
    *stop_scanning_out = true;
    return;
  }

  if (no_best_yet
      && trusted_plateau_blocks > 0
      && gif_state.reassembly_return_start > 0
      && previous_apparentblocknumber >= gif_state.reassembly_return_start
      && current_apparentblocknumber >= 0
      && current_apparentblocknumber < gif_state.reassembly_return_start
      && !gif_reassembly_score_advanced(&trial_summary->score, &base_score)) {
    return;
  }

  if (no_best_yet
      && prestart_gap_start >= 0
      && start_apparentblocknumber > prestart_gap_start
      && current_apparentblocknumber == start_apparentblocknumber - 1) {
    gif_state.reassembly_prestart_exhausted = true;
    gif_reassembly_store_state(candidate, &gif_state);
  }

  // Keep phase-aligned blocks serialized until a physical gap establishes a
  // fragmented path. After that gap, accept byte-level progress here, but let
  // the block selector compare semantic plateaus with displaced alternatives.
  if (no_best_yet
      && current_is_phase_aligned_adjacent
      && trial_preserves_length
      && (trial_advanced_bytes || !has_committed_actual_gap)
      && !gif_state.reassembly_return_pending
      && gif_reassembly_score_not_regressed(&trial_summary->score,
                                            &base_score)) {
    candidate->best_validates_to =
        gif_reassembly_preserve_committed_best(candidate,
                                               trial_summary->validates_to);
    candidate->newblock = current_actualblocknumber;
    *best_summary = *trial_summary;
    if (trial_state) {
      *best_state = *trial_state;
      *best_state_valid = true;
    }
    *stop_scanning_out = true;
    return;
  }

  if (no_best_yet
      && current_is_local_forward
      && trial_preserves_length
      && trial_summary->validates_to
             + (uint64_t)scalpel_state.blocksize
             + GIF_REASSEMBLY_VALIDATE_SLACK
             >= oldlength - 1
      && (!base_state
          || trial_advanced_bytes
          || gif_reassembly_score_advanced(&trial_summary->score,
                                           &base_score))) {
    if (gif_reassembly_debug_candidate(candidate)) {
      fprintf(stderr,
              "[gifdbg] accept-local-forward start=%" PRId64
              " prev=%" PRId64 " current=%" PRId64 " actual=%" PRId64
              " validates_to=%" PRIu64 " oldlength=%" PRIu64 "\n",
              blockvector_get_actual_blocknumber(candidate->b, 0),
              previous_apparentblocknumber, current_apparentblocknumber,
              current_actualblocknumber, trial_summary->validates_to,
              oldlength);
    }
    candidate->best_validates_to =
        gif_reassembly_preserve_committed_best(candidate,
                                               trial_summary->validates_to);
    candidate->newblock = current_actualblocknumber;
    *best_summary = *trial_summary;
    if (trial_state) {
      *best_state = *trial_state;
      *best_state_valid = true;
    }
    gif_reassembly_maybe_arm_fastpath(candidate, oldlength,
                                      current_apparentblocknumber,
                                      previous_apparentblocknumber,
                                      trial_summary, base_state);
    *stop_scanning_out = true;
    return;
  }

  if (no_best_yet
      && current_is_local_forward
      && gif_reassembly_debug_candidate(candidate)) {
    bool near_oldlength =
        trial_summary->validates_to
            + (uint64_t)scalpel_state.blocksize
            + GIF_REASSEMBLY_VALIDATE_SLACK
        >= oldlength - 1;
    bool non_regressed =
        !base_state
        || gif_reassembly_score_not_regressed(&trial_summary->score,
                                              &base_score);
    fprintf(stderr,
            "[gifdbg] local-forward-eval start=%" PRId64
            " prev=%" PRId64 " current=%" PRId64
            " near_old=%d non_regressed=%d"
            " validates_to=%" PRIu64 " oldlength=%" PRIu64
            " base(cp=%" PRIu64 ",good=%" PRIu64 ",norm=%" PRIu64 ",frames=%u)"
            " trial(cp=%" PRIu64 ",good=%" PRIu64 ",norm=%" PRIu64 ",frames=%u)\n",
            blockvector_get_actual_blocknumber(candidate->b, 0),
            previous_apparentblocknumber, current_apparentblocknumber,
            near_oldlength ? 1 : 0,
            non_regressed ? 1 : 0, trial_summary->validates_to, oldlength,
            base_score.checkpoint_curpos, base_score.last_good_row_pos,
            base_score.last_normal_pos, base_score.completed_frames,
            trial_summary->score.checkpoint_curpos,
            trial_summary->score.last_good_row_pos,
            trial_summary->score.last_normal_pos,
            trial_summary->score.completed_frames);
  }

  if (no_best_yet
      && current_is_local_forward
      && trial_preserves_length
      && base_state
      && !trial_advanced_bytes
      && trial_summary->validates_to
             + (uint64_t)scalpel_state.blocksize
             + GIF_REASSEMBLY_VALIDATE_SLACK
             >= oldlength - 1
      && !gif_reassembly_score_advanced(&trial_summary->score, &base_score)
      && gif_reassembly_score_not_regressed(&trial_summary->score,
                                            &base_score)) {
    gif_reassembly_arm_actual_backscan(candidate);
  }

  if (no_best_yet
      && previous_apparentblocknumber >= 0
      && !current_is_local_gap
      && !current_is_prestart_gap
      && !current_is_local_forward
      && trial_summary->validates_to <= oldlength + GIF_REASSEMBLY_VALIDATE_SLACK) {
    GIFValidationSummary nonlocal_follow = {0};
    bool has_nonlocal_followon =
        gif_reassembly_probe_nonlocal_potential(
            id, candidate, oldlength, base_state, current_actualblocknumber,
            previous_apparentblocknumber, &nonlocal_follow);
    int follow_cmp =
        has_nonlocal_followon
            ? gif_reassembly_compare_probe_summary(&nonlocal_follow,
                                                   trial_summary)
            : -1;

    if (gif_reassembly_checkpoint_requested()) {
      gif_reassembly_interrupt_scan(stop_scanning_out,
                                    checkpoint_interrupted_out);
      return;
    }

    if (!has_nonlocal_followon || follow_cmp <= 0) {
      gif_reassembly_schedule_actual_run_rescue(
          candidate, &gif_state, previous_actualblocknumber,
          current_actualblocknumber);
      if (gif_reassembly_debug_candidate(candidate)) {
        fprintf(stderr,
                "[gifdbg] reject-nonlocal-unproven start=%" PRId64
                " prev=%" PRId64 " current=%" PRId64 " actual=%" PRId64
                " validates_to=%" PRIu64 " oldlength=%" PRIu64
                " has_follow=%d follow_vt=%" PRIu64 "\n",
                blockvector_get_actual_blocknumber(candidate->b, 0),
                previous_apparentblocknumber, current_apparentblocknumber,
                current_actualblocknumber, trial_summary->validates_to,
                oldlength, has_nonlocal_followon ? 1 : 0,
                nonlocal_follow.validates_to);
      }
      return;
    }

  }

  if (candidate->newblock >= 0) {
    int64_t best_apparentblocknumber =
        filemirror_apparent_blocknumber(scalpel_state.filemirror,
                                        candidate->newblock);
    bool current_is_prestart_gap = gif_reassembly_choice_in_prestart_gap(
        prestart_gap_start, start_apparentblocknumber,
        current_apparentblocknumber);
    bool best_is_prestart_gap = gif_reassembly_choice_in_prestart_gap(
        prestart_gap_start, start_apparentblocknumber,
        best_apparentblocknumber);

    if (current_is_prestart_gap != best_is_prestart_gap
        && trial_summary->validates_to
               + (uint64_t)scalpel_state.blocksize
               + GIF_REASSEMBLY_VALIDATE_SLACK
               >= candidate->best_validates_to
        && candidate->best_validates_to
               + (uint64_t)scalpel_state.blocksize
               + GIF_REASSEMBLY_VALIDATE_SLACK
               >= trial_summary->validates_to) {
      GIFValidationSummary current_follow = {0};
      GIFValidationSummary best_follow = {0};
      bool current_has_followon =
          gif_reassembly_probe_nonlocal_potential(
              id, candidate, oldlength, base_state,
              current_actualblocknumber, previous_apparentblocknumber,
              &current_follow);
      bool best_has_followon;
      if (best_follow_cache
          && best_follow_cache->valid
          && best_follow_cache->newblock == candidate->newblock) {
        best_follow = best_follow_cache->summary;
        best_has_followon = best_follow_cache->has_followon;
      }
      else {
        best_has_followon =
            gif_reassembly_probe_nonlocal_potential(
                id, candidate, oldlength, base_state, candidate->newblock,
                previous_apparentblocknumber, &best_follow);
        if (best_follow_cache) {
          best_follow_cache->summary = best_follow;
          best_follow_cache->has_followon = best_has_followon;
          best_follow_cache->newblock = candidate->newblock;
          best_follow_cache->valid = true;
        }
      }
      int follow_cmp = 0;

      if (gif_reassembly_checkpoint_requested()) {
        gif_reassembly_interrupt_scan(stop_scanning_out,
                                      checkpoint_interrupted_out);
        return;
      }

      if (current_has_followon && best_has_followon) {
        follow_cmp =
            gif_reassembly_compare_probe_summary(&current_follow, &best_follow);
      }

      if (current_is_prestart_gap
          && current_has_followon
          && (!best_has_followon || follow_cmp > 0)) {
        candidate->best_validates_to =
            gif_reassembly_preserve_committed_best(candidate,
                                                   trial_summary->validates_to);
        candidate->newblock = current_actualblocknumber;
        *best_summary = *trial_summary;
        if (trial_state) {
          *best_state = *trial_state;
          *best_state_valid = true;
        }
        return;
      }

      if (best_is_prestart_gap
          && best_has_followon
          && (!current_has_followon || follow_cmp < 0)) {
        return;
      }
    }
  }

  if (trial_summary->validates_to > candidate->best_validates_to) {
    bool replace = true;
    uint64_t advanced_bytes =
        trial_summary->validates_to + 1 > oldlength
            ? trial_summary->validates_to + 1 - oldlength
            : 0;
    uint64_t required_prestart_win = GIF_REASSEMBLY_STRONG_WIN_BYTES;

    if ((uint64_t)scalpel_state.blocksize / 4 > required_prestart_win) {
      required_prestart_win = (uint64_t)scalpel_state.blocksize / 4;
    }

    if (no_best_yet
        && previous_apparentblocknumber >= 0
        && prestart_gap_start >= 0
        && start_apparentblocknumber > prestart_gap_start
        && current_apparentblocknumber > previous_apparentblocknumber + 1
        && !gif_reassembly_choice_in_prestart_gap(prestart_gap_start,
                                                  start_apparentblocknumber,
                                                  current_apparentblocknumber)
        && advanced_bytes < required_prestart_win) {
      replace = false;
    }

    if (candidate->newblock >= 0
        && trial_summary->validates_to - candidate->best_validates_to
               <= GIF_REASSEMBLY_VALIDATE_SLACK) {
      GIFValidationSummary best_probe = {0};
      GIFValidationSummary current_follow = {0};
      GIFValidationSummary best_follow = {0};
      int cmp;
      int semantic_cmp;
      int64_t best_apparentblocknumber =
          filemirror_apparent_blocknumber(scalpel_state.filemirror,
                                          candidate->newblock);
      bool defer_distance = gif_reassembly_defer_distance_tiebreak(
          locality_anchor, current_apparentblocknumber,
          best_apparentblocknumber);

      if (gif_reassembly_checkpoint_requested()) {
        gif_reassembly_interrupt_scan(stop_scanning_out,
                                      checkpoint_interrupted_out);
        return;
      }

      if (*best_state_valid) {
        best_probe = *best_summary;
      }
      else {
        gif_reassembly_probe_score(id, candidate, oldlength, base_state,
                                   candidate->newblock, &best_probe);
      }

      if (gif_reassembly_preserve_local_frontier(
              previous_apparentblocknumber, current_apparentblocknumber,
              best_apparentblocknumber, trial_summary, &best_probe)) {
        replace = false;
      }

      cmp = gif_reassembly_compare_probe_summary(trial_summary, &best_probe);
      semantic_cmp = gif_reassembly_compare_score(&trial_summary->score,
                                                  &best_probe.score);

      if (trial_summary->validates_to
              <= best_probe.validates_to + GIF_REASSEMBLY_VALIDATE_SLACK
          && semantic_cmp == 0
          && previous_apparentblocknumber >= 0) {
        int locality_cmp = gif_reassembly_compare_locality(
            locality_anchor, current_apparentblocknumber,
            best_apparentblocknumber);
        if (locality_cmp < 0) {
          replace = false;
        }
        else if (locality_cmp > 0) {
          cmp = locality_cmp;
        }
      }

      if (trial_summary->validates_to
              <= best_probe.validates_to
                     + (uint64_t)scalpel_state.blocksize
                     + GIF_REASSEMBLY_VALIDATE_SLACK
          && semantic_cmp == 0
          && previous_apparentblocknumber >= 0) {
        int locality_cmp = gif_reassembly_compare_locality(
            locality_anchor, current_apparentblocknumber,
            best_apparentblocknumber);
        if (locality_cmp < 0) {
          cmp = 0;
          defer_distance = true;
        }
        else if (locality_cmp > 0) {
          cmp = locality_cmp;
        }
      }

      if (defer_distance
          && cmp > 0
          && trial_summary->validates_to
                 <= best_probe.validates_to + GIF_REASSEMBLY_VALIDATE_SLACK
          && semantic_cmp == 0) {
        cmp = 0;
      }

      if (best_probe.validates_to
          > trial_summary->validates_to + GIF_REASSEMBLY_VALIDATE_SLACK) {
        replace = false;
      }
      else if (cmp < 0) {
        replace = false;
      }
      else if (cmp == 0 && ! defer_distance
               && previous_apparentblocknumber >= 0) {
        int distance_cmp = gif_reassembly_compare_forward_distance(
            locality_anchor, current_apparentblocknumber,
            best_apparentblocknumber);
        if (distance_cmp < 0) {
          replace = false;
        }
        else if (distance_cmp > 0) {
          cmp = distance_cmp;
        }
      }
      if (replace && cmp == 0
               && defer_distance
               && gif_reassembly_ambiguous_probe_tie(trial_summary,
                                                     &best_probe)
               && *best_state_valid) {
        GIFValidationSummary current_lookahead = *trial_summary;
        GIFValidationSummary best_lookahead = best_probe;
        int look_cmp;

        if (gif_reassembly_checkpoint_requested()) {
          gif_reassembly_interrupt_scan(stop_scanning_out,
                                        checkpoint_interrupted_out);
          return;
        }

        gif_reassembly_probe_lookahead(candidate, oldlength,
                                       current_actualblocknumber,
                                       trial_state, trial_summary,
                                       &current_lookahead);
        gif_reassembly_probe_lookahead(candidate, oldlength,
                                       candidate->newblock,
                                       best_state, &best_probe,
                                       &best_lookahead);
        look_cmp = gif_reassembly_compare_probe_summary(&current_lookahead,
                                                        &best_lookahead);
        if (look_cmp < 0) {
          replace = false;
        }
        else if (look_cmp > 0) {
          cmp = look_cmp;
        }
      }
      if (replace && cmp == 0 && defer_distance) {
        bool current_has_followon =
            gif_reassembly_probe_nonlocal_potential(
                id, candidate, oldlength, base_state,
                current_actualblocknumber, previous_apparentblocknumber,
                &current_follow);
        bool best_has_followon;
        if (best_follow_cache
            && best_follow_cache->valid
            && best_follow_cache->newblock == candidate->newblock) {
          best_follow = best_follow_cache->summary;
          best_has_followon = best_follow_cache->has_followon;
        }
        else {
          best_has_followon =
              gif_reassembly_probe_nonlocal_potential(
                  id, candidate, oldlength, base_state, candidate->newblock,
                  previous_apparentblocknumber, &best_follow);
          if (best_follow_cache) {
            best_follow_cache->summary = best_follow;
            best_follow_cache->has_followon = best_has_followon;
            best_follow_cache->newblock = candidate->newblock;
            best_follow_cache->valid = true;
          }
        }
        int follow_cmp =
            gif_reassembly_compare_probe_summary(&current_follow,
                                                 &best_follow);

        if (gif_reassembly_checkpoint_requested()) {
          gif_reassembly_interrupt_scan(stop_scanning_out,
                                        checkpoint_interrupted_out);
          return;
        }

        if (best_has_followon
            && best_follow.validates_to
                   > current_follow.validates_to + GIF_REASSEMBLY_VALIDATE_SLACK) {
          replace = false;
        }
        else if (follow_cmp < 0) {
          replace = false;
        }
        else if (follow_cmp > 0) {
          cmp = follow_cmp;
        }
        else if (follow_cmp == 0 && best_has_followon && ! current_has_followon) {
          replace = false;
        }
      }
      if (replace && cmp == 0 && previous_apparentblocknumber >= 0) {
        int distance_cmp = gif_reassembly_compare_forward_distance(
            previous_apparentblocknumber, current_apparentblocknumber,
            best_apparentblocknumber);
        if (distance_cmp < 0) {
          replace = false;
        }
        else if (distance_cmp > 0) {
          cmp = distance_cmp;
        }
      }
      if (replace && cmp == 0
               && best_apparentblocknumber >= 0
               && current_apparentblocknumber >= best_apparentblocknumber) {
        replace = false;
      }
    }

    if (replace) {
      bool weak_consecutive_first_winner =
          no_best_yet
          && !trial_summary->validates
          && previous_apparentblocknumber >= 0
          && current_apparentblocknumber == previous_apparentblocknumber + 1
          && trial_summary->validates_to
                 <= oldlength + GIF_REASSEMBLY_VALIDATE_SLACK
          && !gif_reassembly_strong_winner(oldlength,
                                           current_apparentblocknumber,
                                           previous_apparentblocknumber,
                                           trial_summary, base_state);

      if (candidate->newblock >= 0) {
        destroy_queue(candidate->best_choices);
      }

      candidate->best_validates_to =
          gif_reassembly_preserve_committed_best(candidate,
                                                 trial_summary->validates_to);
      candidate->newblock = current_actualblocknumber;
      *best_summary = *trial_summary;
      *best_state = *trial_state;
      *best_state_valid = true;
      if (weak_consecutive_first_winner) {
        if (gif_reassembly_debug_candidate(candidate)) {
          fprintf(stderr,
                  "[gifdbg] weak-first-winner start=%" PRId64
                  " current=%" PRId64 " actual=%" PRId64
                  " validates_to=%" PRIu64 " oldlength=%" PRIu64 "\n",
                  blockvector_get_actual_blocknumber(candidate->b, 0),
                  current_apparentblocknumber, current_actualblocknumber,
                  trial_summary->validates_to, oldlength);
        }
        candidate->block_choice_start = 0;
      }
      if (no_best_yet
          && previous_apparentblocknumber >= 0
          && !current_is_local_gap
          && !current_is_prestart_gap
          && !current_is_local_forward
          && advanced_bytes > GIF_REASSEMBLY_VALIDATE_SLACK) {
        GIFValidationSummary follow_summary = {0};
        bool has_followon =
            gif_reassembly_probe_nonlocal_potential(
                id, candidate, oldlength, base_state,
                current_actualblocknumber, previous_apparentblocknumber,
                &follow_summary);

        if (has_followon
            && follow_summary.validates_to
                   > trial_summary->validates_to
                         + GIF_REASSEMBLY_VALIDATE_SLACK) {
          if (gif_reassembly_debug_candidate(candidate)) {
            fprintf(stderr,
                    "[gifdbg] accept-nonlocal-followon start=%" PRId64
                    " prev=%" PRId64 " current=%" PRId64
                    " actual=%" PRId64 " validates_to=%" PRIu64
                    " follow_vt=%" PRIu64 " oldlength=%" PRIu64
                    " advanced=%" PRIu64 "\n",
                    blockvector_get_actual_blocknumber(candidate->b, 0),
                    previous_apparentblocknumber, current_apparentblocknumber,
                    current_actualblocknumber, trial_summary->validates_to,
                    follow_summary.validates_to, oldlength, advanced_bytes);
          }
          *stop_scanning_out = true;
          return;
        }
      }
      better = true;
    }
  }
  else if (candidate->newblock >= 0
           && trial_summary->validates_to + GIF_REASSEMBLY_VALIDATE_SLACK
                  >= candidate->best_validates_to) {
    GIFValidationSummary best_probe = {0};
    GIFValidationSummary current_follow = {0};
    GIFValidationSummary best_follow = {0};
    int cmp;
    int semantic_cmp;
    int64_t best_apparentblocknumber =
        filemirror_apparent_blocknumber(scalpel_state.filemirror,
                                        candidate->newblock);
    bool defer_distance = gif_reassembly_defer_distance_tiebreak(
        locality_anchor, current_apparentblocknumber,
        best_apparentblocknumber);
    bool near_tie =
        trial_summary->validates_to < candidate->best_validates_to;
    bool small_gap_semantic_tie = false;
    bool best_is_strong = false;
    bool preserve_local_tie = false;
    bool prefer_local_current_tie = false;
    bool compare_full_block_followon = false;
    int locality_cmp = 0;

    if (gif_reassembly_checkpoint_requested()) {
      gif_reassembly_interrupt_scan(stop_scanning_out,
                                    checkpoint_interrupted_out);
      return;
    }

    if (*best_state_valid) {
      best_probe = *best_summary;
    }
    else {
      gif_reassembly_probe_score(id, candidate, oldlength, base_state,
                                 candidate->newblock, &best_probe);
    }

    if (gif_reassembly_preserve_local_frontier(
            locality_anchor, current_apparentblocknumber,
            best_apparentblocknumber, trial_summary, &best_probe)) {
      cmp = -1;
    }
    else {
      cmp = gif_reassembly_compare_probe_summary(trial_summary, &best_probe);
    }
    semantic_cmp = gif_reassembly_compare_score(&trial_summary->score,
                                                &best_probe.score);

    // When nonlocal choices consume the same full block, compare their
    // bounded continuations before trusting shallow semantic differences.
    compare_full_block_followon =
        !near_tie
        && defer_distance
        && !trial_summary->validates
        && !best_probe.validates
        && trial_summary->validates_to == best_probe.validates_to
        && trial_summary->validates_to >= oldlength
        && trial_summary->validates_to - oldlength + 1
               + GIF_REASSEMBLY_VALIDATE_SLACK
               >= (uint64_t)scalpel_state.blocksize;

    if (previous_apparentblocknumber >= 0) {
      locality_cmp = gif_reassembly_compare_locality(
          locality_anchor, current_apparentblocknumber,
          best_apparentblocknumber);
    }
    preserve_local_tie =
        !near_tie
        && locality_cmp < 0
        && !trial_summary->validates
        && !best_probe.validates
        && semantic_cmp > 0
        && trial_summary->validates_to
               <= best_probe.validates_to + GIF_REASSEMBLY_VALIDATE_SLACK
        && best_probe.validates_to
               <= trial_summary->validates_to + GIF_REASSEMBLY_VALIDATE_SLACK;
    prefer_local_current_tie =
        !near_tie
        && locality_cmp > 0
        && !trial_summary->validates
        && !best_probe.validates
        && trial_summary->score.completed_frames
               == best_probe.score.completed_frames
        && trial_summary->validates_to
               <= best_probe.validates_to + GIF_REASSEMBLY_VALIDATE_SLACK
        && best_probe.validates_to
               <= trial_summary->validates_to + GIF_REASSEMBLY_VALIDATE_SLACK
        && best_probe.score.checkpoint_curpos
               <= trial_summary->score.checkpoint_curpos
                      + GIF_REASSEMBLY_STRONG_WIN_BYTES
        && best_probe.score.last_good_row_pos
               <= trial_summary->score.last_good_row_pos
                      + GIF_REASSEMBLY_STRONG_WIN_BYTES
        && best_probe.score.last_normal_pos
               <= trial_summary->score.last_normal_pos
                      + GIF_REASSEMBLY_STRONG_WIN_BYTES;
    small_gap_semantic_tie =
        near_tie
        && locality_cmp < 0
        && !trial_summary->validates
        && !best_probe.validates
        && semantic_cmp == 0
        && trial_summary->validates_to
               <= best_probe.validates_to + GIF_REASSEMBLY_VALIDATE_SLACK
        && best_probe.validates_to
               <= trial_summary->validates_to + GIF_REASSEMBLY_VALIDATE_SLACK;
    best_is_strong = gif_reassembly_strong_winner(
        oldlength, best_apparentblocknumber, previous_apparentblocknumber,
        &best_probe, base_state);

    if (near_tie && best_is_strong) {
      cmp = -1;
    }
    else if (near_tie && small_gap_semantic_tie) {
      cmp = 0;
    }
    else if (prefer_local_current_tie && cmp < 0) {
      cmp = 0;
    }

    if (cmp == 0 && small_gap_semantic_tie && *best_state_valid) {
      GIFValidationSummary current_lookahead = *trial_summary;
      GIFValidationSummary best_lookahead = best_probe;

      if (gif_reassembly_checkpoint_requested()) {
        gif_reassembly_interrupt_scan(stop_scanning_out,
                                      checkpoint_interrupted_out);
        return;
      }

      gif_reassembly_probe_lookahead(candidate, oldlength,
                                     current_actualblocknumber,
                                     trial_state, trial_summary,
                                     &current_lookahead);
      gif_reassembly_probe_lookahead(candidate, oldlength,
                                     candidate->newblock,
                                     best_state, &best_probe,
                                     &best_lookahead);
      cmp = gif_reassembly_compare_probe_summary(&current_lookahead,
                                                 &best_lookahead);
    }

    if (cmp == 0 && ! defer_distance && ! small_gap_semantic_tie
        && ! preserve_local_tie
        && previous_apparentblocknumber >= 0) {
      cmp = gif_reassembly_compare_forward_distance(
          locality_anchor, current_apparentblocknumber,
          best_apparentblocknumber);
    }

    if (cmp == 0 && defer_distance && ! small_gap_semantic_tie
        && ! preserve_local_tie
        && gif_reassembly_ambiguous_probe_tie(trial_summary, &best_probe)
        && *best_state_valid) {
      GIFValidationSummary current_lookahead = *trial_summary;
      GIFValidationSummary best_lookahead = best_probe;

      if (gif_reassembly_checkpoint_requested()) {
        gif_reassembly_interrupt_scan(stop_scanning_out,
                                      checkpoint_interrupted_out);
        return;
      }

      gif_reassembly_probe_lookahead(candidate, oldlength,
                                     current_actualblocknumber,
                                     trial_state, trial_summary,
                                     &current_lookahead);
      gif_reassembly_probe_lookahead(candidate, oldlength,
                                     candidate->newblock,
                                     best_state, &best_probe,
                                     &best_lookahead);
      cmp = gif_reassembly_compare_probe_summary(&current_lookahead,
                                                 &best_lookahead);
    }
    if ((cmp == 0 || compare_full_block_followon)
        && defer_distance && ! small_gap_semantic_tie
        && ! preserve_local_tie) {
      bool current_has_followon =
          gif_reassembly_probe_nonlocal_potential(
              id, candidate, oldlength, base_state,
              current_actualblocknumber, previous_apparentblocknumber,
              &current_follow);
      bool best_has_followon;
      if (best_follow_cache
          && best_follow_cache->valid
          && best_follow_cache->newblock == candidate->newblock) {
        best_follow = best_follow_cache->summary;
        best_has_followon = best_follow_cache->has_followon;
      }
      else {
        best_has_followon =
            gif_reassembly_probe_nonlocal_potential(
                id, candidate, oldlength, base_state, candidate->newblock,
                previous_apparentblocknumber, &best_follow);
        if (best_follow_cache) {
          best_follow_cache->summary = best_follow;
          best_follow_cache->has_followon = best_has_followon;
          best_follow_cache->newblock = candidate->newblock;
          best_follow_cache->valid = true;
        }
      }
      int follow_cmp =
          gif_reassembly_compare_probe_summary(&current_follow,
                                               &best_follow);

      if (gif_reassembly_checkpoint_requested()) {
        gif_reassembly_interrupt_scan(stop_scanning_out,
                                      checkpoint_interrupted_out);
        return;
      }

      if (best_has_followon
          && best_follow.validates_to
                 > current_follow.validates_to + GIF_REASSEMBLY_VALIDATE_SLACK) {
        cmp = -1;
      }
      else if (follow_cmp != 0) {
        cmp = follow_cmp;
      }
      else if (best_has_followon && ! current_has_followon) {
        cmp = -1;
      }
    }

    if (cmp == 0 && previous_apparentblocknumber >= 0
        && ! preserve_local_tie) {
      cmp = gif_reassembly_compare_forward_distance(
          locality_anchor, current_apparentblocknumber,
          best_apparentblocknumber);
    }

    if (preserve_local_tie) {
      actualblocknumber = current_actualblocknumber;
      add_to_queue(candidate->best_choices, &actualblocknumber, 0);
      better = true;
    }
    else if (cmp > 0) {
      destroy_queue(candidate->best_choices);
      candidate->newblock = current_actualblocknumber;
      *best_summary = *trial_summary;
      *best_state = *trial_state;
      *best_state_valid = true;
      better = true;
    }
    else if (! near_tie && cmp == 0
             && current_apparentblocknumber < best_apparentblocknumber) {
      destroy_queue(candidate->best_choices);
      candidate->newblock = current_actualblocknumber;
      *best_summary = *trial_summary;
      *best_state = *trial_state;
      *best_state_valid = true;
      better = true;
    }
    else if (! near_tie && cmp == 0) {
      actualblocknumber = current_actualblocknumber;
      add_to_queue(candidate->best_choices, &actualblocknumber, 0);
      better = true;
    }
  }

  if (better
      && previous_apparentblocknumber >= 0
      && current_apparentblocknumber == previous_apparentblocknumber + 1
      && trial_summary->validates_to
             == blockvector_get_data_length(candidate->b) - 1
      && (!base_state || !base_state->reassembly_return_pending)
      && gif_reassembly_strong_winner(oldlength,
                                      current_apparentblocknumber,
                                      previous_apparentblocknumber,
                                      trial_summary, base_state)) {
    candidate->fastpath = true;
  }

}

static inline int64_t gif_reassembly_backtrack(
    CarveInfo *candidate, uuid_string_t uuidp, uuid_string_t uuidc) {
  int64_t block_choice = -1;
  int64_t rejected_apparent = -1;
  GIFCarveState gif_state = {0};
  uint32_t trusted_plateau_blocks = 0;
  int64_t apparent_blocks = 0;

  if (scalpel_state.write_promising) {
    write_candidate(&candidate, true);
  }

  atomic_fetch_add_explicit(
      &scalpel_state.search_specs[candidate->needleidx].backtracked, 1,
      memory_order_acq_rel);

  rejected_apparent =
      blockvector_get_apparent_blocknumber(
          candidate->b, blockvector_get_num_blocks(candidate->b) - 1);
  if (rejected_apparent >= 0) {
    blockvector_remove_choice(candidate->b,
                              blockvector_get_num_blocks(candidate->b) - 1,
                              rejected_apparent);
  }

  gif_reassembly_load_state(candidate, &gif_state);
  trusted_plateau_blocks = gif_state.reassembly_trusted_plateau_blocks;
  if (gif_state.reassembly_checkpoint_plateau_blocks > trusted_plateau_blocks) {
    trusted_plateau_blocks = gif_state.reassembly_checkpoint_plateau_blocks;
  }
  apparent_blocks =
      (int64_t)filemirror_apparent_blocks(scalpel_state.filemirror);

  while (blockvector_get_num_blocks(candidate->b) > 1 && block_choice == -1) {
    int64_t tail_apparent =
        blockvector_get_apparent_blocknumber(
            candidate->b, blockvector_get_num_blocks(candidate->b) - 1);
    bool plateau_wrap_backtrack =
        trusted_plateau_blocks > 0
        && apparent_blocks > 0
        && gif_state.reassembly_return_start >= 0
        && tail_apparent >= gif_state.reassembly_return_start;

    if (tail_apparent < 0) {
      resize_blockvector(candidate->b,
                         blockvector_get_num_blocks(candidate->b) - 1);
      continue;
    }

    candidate->block_choice_start = tail_apparent + 1;
    if (plateau_wrap_backtrack
        && candidate->block_choice_start >= apparent_blocks) {
      candidate->block_choice_start = gif_state.reassembly_return_start;
    }
    block_choice = gif_reassembly_get_block_choice(candidate, &gif_state);
    if (plateau_wrap_backtrack
        && block_choice >= 0
        && block_choice < gif_state.reassembly_return_start) {
      block_choice = -1;
    }

    if (block_choice == -1) {
      resize_blockvector(candidate->b, blockvector_get_num_blocks(candidate->b) - 1);
    }
  }

  (void)uuidp;
  (void)uuidc;

  return block_choice;
}

static inline void gif_reassembly_gallop(
    int id, CarveInfo *candidate, uint64_t *validates_to, bool *validates,
    uint64_t *gallop, bool *checkpoint_interrupted_out, uuid_string_t uuidp,
    uuid_string_t uuidc) {
  int64_t pregallop_newblock;
  uint64_t pregallop_num_blocks;
  uint64_t pregallop_length;
  uint64_t gallop_count;
  int64_t last_block;
  int64_t next;
  int64_t pregallop_tail_apparent = -1;
  uint64_t idx;
  GIFCarveState gallop_state = {0};
  GIFValidationSummary gallop_summary = {0};
  GIFReassemblyScore gallop_base_score = {0};

  if (*gallop == 0) {
    *gallop = scalpel_state.gallop_factor;
  }
  else {
    *gallop *= scalpel_state.gallop_factor;
    if (*gallop > scalpel_state.gallop_limit) {
      *gallop = scalpel_state.gallop_limit;
    }
  }

  gallop_count = 0;
  pregallop_newblock = candidate->newblock;
  pregallop_num_blocks = blockvector_get_num_blocks(candidate->b);
  pregallop_length = blockvector_get_data_length(candidate->b);
  if (pregallop_num_blocks > 0) {
    pregallop_tail_apparent =
        blockvector_get_apparent_blocknumber(candidate->b,
                                             pregallop_num_blocks - 1);
  }
  gif_reassembly_load_state(candidate, &gallop_state);
  if (gallop_state.reassembly_return_pending) {
    *validates = false;
    *validates_to = candidate->best_validates_to;
    *gallop = 0;
    candidate->fastpath = false;
    return;
  }

  last_block = filemirror_apparent_blocks(scalpel_state.filemirror);
  next = blockvector_get_apparent_blocknumber(
             candidate->b, blockvector_get_num_blocks(candidate->b) - 1)
         + 1;

  while (gallop_count < *gallop && next < last_block
         && next == blockvector_get_apparent_blocknumber(
                        candidate->b, blockvector_get_num_blocks(candidate->b) - 1)
                        + 1
         && filemirror_get_blocktype(
                scalpel_state.filemirror,
                filemirror_actual_blocknumber(scalpel_state.filemirror, next),
                candidate->needleidx) != BLOCK_CONFIDENCE_INVALID
         && ! filemirror_actual_block_covered(
                scalpel_state.filemirror,
                filemirror_actual_blocknumber(scalpel_state.filemirror, next))
         && ! apparent_block_in_blockvector(candidate->b, next)) {
    if (gif_reassembly_checkpoint_requested()) {
      candidate->newblock = pregallop_newblock;
      blockvector_set_data_length(candidate->b, pregallop_length);
      resize_blockvector(candidate->b, pregallop_num_blocks);
      candidate->fastpath = false;
      candidate->block_choice_start =
          pregallop_tail_apparent >= 0 ? pregallop_tail_apparent + 1 : 0;
      *gallop = 0;
      if (checkpoint_interrupted_out) {
        *checkpoint_interrupted_out = true;
      }
      return;
    }

    resize_blockvector(candidate->b, blockvector_get_num_blocks(candidate->b) + 1);
    blockvector_set_apparent_blocknumber(candidate->b,
                                         blockvector_get_num_blocks(candidate->b) - 1,
                                         next);
    next = next + 1;
    inflate_blockvector_single_block(candidate->b,
                                     blockvector_get_num_blocks(candidate->b) - 1);
    gallop_count++;
  }

  if (gif_reassembly_debug_candidate(candidate)) {
    fprintf(stderr,
            "[gifdbg] gallop start=%" PRId64
            " count=%" PRIu64 " target=%" PRIu64
            " pregallop_blocks=%" PRIu64 " pregallop_length=%" PRIu64 "\n",
            blockvector_get_num_blocks(candidate->b) > 0
                ? blockvector_get_actual_blocknumber(candidate->b, 0)
                : -1,
            gallop_count, *gallop, pregallop_num_blocks, pregallop_length);
  }

  if (! gallop_count) {
    candidate->block_choice_start =
        pregallop_tail_apparent >= 0 ? pregallop_tail_apparent + 1 : 0;
  }
  else {
    if (gif_reassembly_checkpoint_requested()) {
      candidate->newblock = pregallop_newblock;
      blockvector_set_data_length(candidate->b, pregallop_length);
      resize_blockvector(candidate->b, pregallop_num_blocks);
      candidate->fastpath = false;
      candidate->block_choice_start =
          pregallop_tail_apparent >= 0 ? pregallop_tail_apparent + 1 : 0;
      *gallop = 0;
      if (checkpoint_interrupted_out) {
        *checkpoint_interrupted_out = true;
      }
      return;
    }

    gif_reassembly_load_state(candidate, &gallop_state);
    gif_reassembly_capture_score_from_state(&gallop_state, &gallop_base_score);
    gif_reassembly_validate_local(candidate, &gallop_state, &gallop_summary);
    gif_reassembly_clamp_nonvalidated_summary(pregallop_length,
                                              &gallop_summary);
    *validates = gallop_summary.validates;
    *validates_to = gallop_summary.validates_to;

    if (*validates
        && gif_reassembly_weak_validation_summary(pregallop_length,
                                                  &gallop_summary,
                                                  &gallop_base_score)) {
      *validates = false;
    }

    if (*validates) {
      gif_reassembly_store_state(candidate, &gallop_state);
      blockvector_set_data_length(candidate->b, *validates_to + 1);
      resize_blockvector(
          candidate->b,
          CEILDIV(blockvector_get_data_length(candidate->b),
                  scalpel_state.blocksize));
    }
    else if (*validates_to > candidate->best_validates_to) {
      blockvector_set_data_length(candidate->b, *validates_to + 1);
      resize_blockvector(candidate->b,
                         CEILDIV(blockvector_get_data_length(candidate->b),
                                 scalpel_state.blocksize));

      for (idx = pregallop_num_blocks - 1;
           idx < blockvector_get_num_blocks(candidate->b);
           idx++) {
        blockvector_remove_choice(candidate->b, idx,
                                  blockvector_get_apparent_blocknumber(
                                      candidate->b, idx));
      }

      candidate->best_validates_to = blockvector_get_data_length(candidate->b) - 1;
      candidate->newblock =
          filemirror_actual_blocknumber(
              scalpel_state.filemirror,
              blockvector_get_apparent_blocknumber(
                  candidate->b, blockvector_get_num_blocks(candidate->b) - 1));
      candidate->fastpath = false;

      gallop_state.data_length = blockvector_get_data_length(candidate->b);
      if (gallop_state.probe_checkpoint_curpos > gallop_state.data_length) {
        gallop_state.probe_checkpoint_curpos = gallop_state.data_length;
      }
      if (gallop_state.probe_last_good_row_pos > gallop_state.data_length) {
        gallop_state.probe_last_good_row_pos = gallop_state.data_length;
      }
      if (gallop_state.probe_last_normal_pos > gallop_state.data_length) {
        gallop_state.probe_last_normal_pos = gallop_state.data_length;
      }
      if (gallop_state.valid && gallop_state.checkpoint_curpos > gallop_state.data_length) {
        gallop_state.valid = false;
      }
      gif_reassembly_store_state(candidate, &gallop_state);

      if (blockvector_get_data_length(candidate->b) % scalpel_state.blocksize) {
        *gallop = 0;
        candidate->block_choice_start =
            blockvector_get_apparent_blocknumber(
                candidate->b, blockvector_get_num_blocks(candidate->b) - 1)
            + 1;
      }

      destroy_queue(candidate->best_choices);
    }
    else {
      candidate->newblock = pregallop_newblock;
      resize_blockvector(candidate->b, pregallop_num_blocks);
      candidate->fastpath = false;
      candidate->block_choice_start =
          pregallop_tail_apparent >= 0 ? pregallop_tail_apparent + 1 : 0;
    }
  }

  (void)id;
  (void)uuidp;
  (void)uuidc;
}

static inline void gif_reassembly(ThreadWork *work, CarveInfo **c,
                                  uuid_string_t uuidp, uuid_string_t uuidc) {
  CarveInfo *candidate = *c;
  bool validated = false;
  bool validates = false;
  uint64_t validates_to = 0;
  int64_t block_choice;
  uint64_t tick = 0;
  uint64_t oldlength;
  uint64_t gallop = 0;
  GIFReassemblyScore base_score = {0};
  GIFCarveState base_state = {0};
  GIFCarveState trial_state = {0};
  GIFCarveState best_state = {0};
  GIFValidationSummary trial_summary = {0};
  GIFValidationSummary best_summary = {0};
  GIFReassemblyFollowCache best_follow_cache = {0};
  bool best_state_valid = false;
  bool stop_scanning = false;
  bool checkpoint_interrupted = false;
  int64_t saved_trial_slot_apparent = -1;
  uint64_t trial_slot_start = 0;
  uint32_t return_gap_descents = 0;

  if (!gif_reassembly_normalize_candidate(work->id, candidate, uuidp, uuidc,
                                          &validated)) {
    destroy_candidate(&candidate);
    *c = candidate;
    return;
  }

  if (validated) {
    write_candidate(c, false);
    return;
  }

  while (1) {
    if (atomic_load_explicit(&REASS_RETURN_TO_IDLE, memory_order_acquire)) {
      gif_reassembly_checkpoint_flush(candidate);
      if (reassembly_time_to_checkpoint(work->id, candidate, uuidp, uuidc)) {
        goto done_do_not_write_candidate;
      }
    }

    if (gif_reassembly_exceeded_max_size(work->id, candidate, uuidp, uuidc)) {
      destroy_candidate(&candidate);
      goto done_do_not_write_candidate;
    }

    if (blockvector_get_num_blocks(candidate->b) == 0) {
      destroy_candidate(&candidate);
      goto done_do_not_write_candidate;
    }

    gif_reassembly_prepare_for_extension(candidate);
    saved_trial_slot_apparent =
        blockvector_get_apparent_blocknumber(
            candidate->b, blockvector_get_num_blocks(candidate->b) - 1);
    trial_slot_start =
        (blockvector_get_num_blocks(candidate->b) - 1)
        * (uint64_t)scalpel_state.blocksize;
    gif_reassembly_capture_score(candidate, &base_score);
    gif_reassembly_load_state(candidate, &base_state);
    memset(&best_state, 0, sizeof(best_state));
    memset(&best_summary, 0, sizeof(best_summary));
    memset(&best_follow_cache, 0, sizeof(best_follow_cache));
    best_follow_cache.newblock = -1;
    best_state_valid = false;
    stop_scanning = false;
    checkpoint_interrupted = false;

    while (! candidate->fastpath
           && (block_choice = gif_reassembly_get_block_choice(
                   candidate, &base_state)) >= 0) {
      if (reassembly_check_kill_queue(work, &candidate, uuidp, uuidc)) {
        goto done_do_not_write_candidate;
      }

      if (gif_reassembly_checkpoint_requested()) {
        checkpoint_interrupted = true;
        break;
      }

      if (tick++ % 100000 == 0 && ! scalpel_state.mode_verbose) {
        lock_fprintf(stdout, "%s.%s", BLUE, BLACK);
        fflush(stdout);
      }

      blockvector_set_apparent_blocknumber(
          candidate->b, blockvector_get_num_blocks(candidate->b) - 1,
          block_choice);
      oldlength = inflate_blockvector_single_block(
          candidate->b, blockvector_get_num_blocks(candidate->b) - 1);

      trial_state = base_state;
      gif_reassembly_validate_local(candidate, &trial_state, &trial_summary);
      gif_reassembly_clamp_nonvalidated_summary(oldlength, &trial_summary);
      validates = trial_summary.validates;
      validates_to = trial_summary.validates_to;

      if (validates) {
        bool weak_validation =
            gif_reassembly_weak_validation_summary(oldlength,
                                                   &trial_summary,
                                                   &base_score);
        int64_t previous_apparentblocknumber = -1;
        bool acceptable_validation_choice = false;

        if (blockvector_get_num_blocks(candidate->b) >= 2) {
          previous_apparentblocknumber =
              blockvector_get_apparent_blocknumber(
                  candidate->b, blockvector_get_num_blocks(candidate->b) - 2);
        }
        acceptable_validation_choice =
            gif_reassembly_local_forward_choice(previous_apparentblocknumber,
                                                block_choice)
            || gif_reassembly_choice_in_return_window(&base_state,
                                                      block_choice);

        // Weak validation must improve structural evidence and use either a
        // physically local continuation or a confirmed return window. This
        // prevents coincidental trailers in unrelated data from advancing the
        // committed frontier.
        if (! weak_validation
            && (! gif_reassembly_score_advanced(&trial_summary.score,
                                                &base_score)
                || ! acceptable_validation_choice)) {
          weak_validation = true;
        }

        if (! weak_validation) {
          gif_reassembly_store_state(candidate, &trial_state);
          candidate->flavor = VALIDATED;
          blockvector_set_data_length(candidate->b, validates_to + 1);
          resize_blockvector(candidate->b,
                             CEILDIV(blockvector_get_data_length(candidate->b),
                                     scalpel_state.blocksize));
          goto done_write_candidate;
        }
        validates = false;
      }

      gif_reassembly_did_not_validate(work->id, candidate, block_choice,
                                      oldlength, &base_state, &trial_summary,
                                      &trial_state, &best_summary,
                                      &best_state, &best_state_valid,
                                      &best_follow_cache,
                                      &stop_scanning,
                                      &checkpoint_interrupted);

      if (! candidate->fastpath) {
        deflate_blockvector_single_block(
            candidate->b, blockvector_get_num_blocks(candidate->b) - 1,
            oldlength);
        blockvector_set_apparent_blocknumber(
            candidate->b, blockvector_get_num_blocks(candidate->b) - 1,
            saved_trial_slot_apparent);
        if (saved_trial_slot_apparent >= 0
            && oldlength > trial_slot_start) {
          blockvector_set_apparent_blocknumber(
              candidate->b, blockvector_get_num_blocks(candidate->b) - 1,
              saved_trial_slot_apparent);
          inflate_blockvector_single_block(
              candidate->b, blockvector_get_num_blocks(candidate->b) - 1);
        }
      }

      if (atomic_load_explicit(&REASS_RETURN_TO_IDLE, memory_order_acquire)) {
        gif_reassembly_checkpoint_flush(candidate);
        if (reassembly_time_to_checkpoint(work->id, candidate, uuidp, uuidc)) {
          goto done_do_not_write_candidate;
        }
      }

      if (stop_scanning) {
        break;
      }
    }

    if (checkpoint_interrupted) {
      continue;
    }

    if (candidate->fastpath) {
      if (best_state_valid) {
        gif_reassembly_store_state(candidate, &best_state);
      }
      gif_reassembly_gallop(work->id, candidate, &validates_to, &validates,
                            &gallop, &checkpoint_interrupted, uuidp, uuidc);
    }
    else {
      gallop = 0;
    }

    if (validates) {
      candidate->best_validates_to = validates_to;
      candidate->flavor = VALIDATED;
      goto done_write_candidate;
    }

    rewind_queue(candidate->best_choices);
    while (! empty_queue(candidate->best_choices)) {
      remove_from_front(candidate->best_choices, &block_choice);
      blockvector_add_choice(
          candidate->b, blockvector_get_num_blocks(candidate->b) - 1,
          filemirror_apparent_blocknumber(scalpel_state.filemirror,
                                          block_choice));
    }

    if (candidate->newblock >= 0) {
      bool promoted_current = false;

      if (best_state_valid
          && candidate->best_validates_to <= best_summary.validates_to) {
        gif_reassembly_store_state(candidate, &best_state);
      }
      gif_reassembly_extension_successful(candidate);
      return_gap_descents = 0;
      promoted_current =
          gif_reassembly_promote_current_blocks(candidate, &validates);
      if (promoted_current && validates) {
        goto done_write_candidate;
      }
      if (promoted_current) {
        continue;
      }
    }
    else {
      GIFCarveState committed_state = {0};
      GIFValidationSummary committed_summary = {0};
      bool promoted_current = false;

      gif_reassembly_load_state_raw(candidate, &committed_state);
      if (committed_state.reassembly_return_pending
          && committed_state.reassembly_trusted_plateau_blocks > 0
          && committed_state.reassembly_return_start > 0) {
        int64_t next_return_gap =
            gif_reassembly_next_return_gap_choice(
                candidate, committed_state.reassembly_return_start,
                committed_state.reassembly_return_start
                    - GIF_REASSEMBLY_GAP_SCAN_WINDOW);

        if (next_return_gap >= 0
            && next_return_gap < committed_state.reassembly_return_start
            && return_gap_descents < 3) {
          gif_reassembly_set_return_start(&committed_state,
                                          next_return_gap, false);
          gif_reassembly_store_state(candidate, &committed_state);
          candidate->block_choice_start = next_return_gap;
          candidate->no_initial_block_extension = true;
          return_gap_descents++;
          continue;
        }
      }
      resize_blockvector(candidate->b,
                         blockvector_get_num_blocks(candidate->b) - 1);
      if (committed_state.reassembly_trusted_plateau_blocks > 0
          || committed_state.reassembly_checkpoint_plateau_blocks > 0) {
        gif_reassembly_clamp_state_to_length(
            &committed_state, blockvector_get_data_length(candidate->b));
        gif_reassembly_store_state(candidate, &committed_state);
      }
      if (gif_reassembly_checkpoint_requested()) {
        checkpoint_interrupted = true;
        continue;
      }
      if (gif_reassembly_promote_current_validation(candidate, &validates)
          && validates) {
        goto done_write_candidate;
      }

      if (gif_reassembly_checkpoint_requested()) {
        checkpoint_interrupted = true;
        continue;
      }
      promoted_current =
          gif_reassembly_promote_current_blocks(candidate, &validates);
      if (promoted_current && validates) {
        goto done_write_candidate;
      }
      if (promoted_current) {
        continue;
      }

      if (candidate->best_validates_to + 1
              == blockvector_get_data_length(candidate->b)) {
        uint64_t plateau_allowance = 0;
        uint64_t plateau_blocks = 0;
        uint64_t data_length = blockvector_get_data_length(candidate->b);

        gif_reassembly_load_state(candidate, &committed_state);
        if (gif_reassembly_checkpoint_requested()) {
          checkpoint_interrupted = true;
          continue;
        }
        gif_reassembly_validate_local(candidate, &committed_state,
                                      &committed_summary);
        plateau_blocks = committed_state.reassembly_trusted_plateau_blocks;
        if (plateau_blocks > 0) {
          plateau_allowance =
              (plateau_blocks + 1) * (uint64_t)scalpel_state.blocksize
              + GIF_REASSEMBLY_VALIDATE_SLACK;
        }

        if (committed_summary.validates) {
          gif_reassembly_store_state(candidate, &committed_state);
          candidate->best_validates_to = committed_summary.validates_to;
          candidate->flavor = VALIDATED;
          goto done_write_candidate;
        }

        if (committed_summary.promising
            && committed_summary.validates_to + 1
                   == blockvector_get_data_length(candidate->b)) {
          uint64_t keep_blocks =
              CEILDIV(blockvector_get_data_length(candidate->b),
                      scalpel_state.blocksize);

          if (keep_blocks == 0) {
            keep_blocks = 1;
          }
          if (blockvector_get_num_blocks(candidate->b) > keep_blocks) {
            resize_blockvector(candidate->b, keep_blocks);
          }
          gif_reassembly_store_state(candidate, &committed_state);
          candidate->best_validates_to = committed_summary.validates_to;
          if (atomic_load_explicit(&REASS_RETURN_TO_IDLE,
                                   memory_order_acquire)) {
            gif_reassembly_checkpoint_flush(candidate);
            if (reassembly_time_to_checkpoint(work->id, candidate,
                    uuidp, uuidc)) {
              goto done_do_not_write_candidate;
            }
          }
        }

        if (plateau_allowance > 0
            && committed_summary.promising
            && committed_summary.validates_to + plateau_allowance
                   >= data_length - 1) {
          gif_reassembly_store_state(candidate, &committed_state);
        }
      }

      if (! scalpel_state.backtrack
          || blockvector_get_num_blocks(candidate->b) == 1) {
        if (! scalpel_state.write_promising) {
          destroy_candidate(&candidate);
          goto done_do_not_write_candidate;
        }
        goto done_write_candidate;
      }

      block_choice = gif_reassembly_backtrack(candidate, uuidp, uuidc);
      if (block_choice != -1 && blockvector_get_num_blocks(candidate->b) > 1) {
        uint64_t committed_length = candidate->best_validates_to + 1;
        GIFCarveState backtrack_state = {0};

        blockvector_set_apparent_blocknumber(
            candidate->b, blockvector_get_num_blocks(candidate->b) - 1,
            block_choice);
        blockvector_set_data_length_to_mapped_extent(candidate->b);
        inflate_blockvector(candidate->b);
        if (committed_length < blockvector_get_data_length(candidate->b)) {
          gif_reassembly_load_state_raw(candidate, &backtrack_state);
          blockvector_set_data_length(candidate->b, committed_length);
          if (backtrack_state.reassembly_trusted_plateau_blocks > 0
              || backtrack_state.reassembly_checkpoint_plateau_blocks > 0) {
            gif_reassembly_clamp_state_to_length(&backtrack_state,
                                                 committed_length);
            gif_reassembly_store_state(candidate, &backtrack_state);
          }
        }
      }
      else {
        destroy_candidate(&candidate);
        goto done_do_not_write_candidate;
      }
    }
  }

done_write_candidate:
  *c = candidate;
  write_candidate(c, false);
  return;

done_do_not_write_candidate:
  // Ownership has either moved to the promising queue or the candidate was
  // destroyed. Do not hand a queue-owned pointer back to the caller.
  *c = NULL;
}

// Reset the code table (after a clear code).
static inline void gif_lzw_clear(GIFLZWState *s) {
  s->code_size = s->min_code_size + 1;
  s->next_code = s->eoi_code + 1;
  s->prev_code = UINT16_MAX;
}

// Read the next LZW code from the sub-block bitstream.
// Uses a sub-block buffer so mem->curpos advances in chunks (matching
// libgif's GIFMemRead pattern). This produces bursty bytes_consumed
// values that the detection heuristics were calibrated for.
// Returns the code, or -1 on EOF/error.
static inline int32_t gif_lzw_read_code(GIFLZWState *s,
                                        GIFMemIO *mem) {
  const uint8_t *data = mem->data;
  uint64_t length = mem->length;

  // Fill the bit buffer until we have enough bits
  while (s->bits_in_buf < s->code_size) {
    // If the sub-block buffer is exhausted, load the next sub-block
    if (s->sb_buf_pos >= s->sb_buf_len) {
      // Read next sub-block length byte
      if (mem->curpos >= length) {
        return -1;
      }
      uint8_t sb_len = data[mem->curpos++];
      if (sb_len == 0) {
        return -1;  // block terminator
      }
      s->sb_truncated = false;
      // Buffer the entire sub-block and advance curpos past it
      // (this is the bursty advance that matches libgif's pattern)
      if (mem->curpos + sb_len > length) {
        s->sb_truncated = true;
        sb_len = (uint8_t)(length - mem->curpos);
      }
      memcpy(s->sb_buf, data + mem->curpos, sb_len);
      mem->curpos += sb_len;
      s->sb_buf_len = sb_len;
      s->sb_buf_pos = 0;
    }
    // Read one byte from the buffer (no curpos advance)
    s->bit_buf |= (uint32_t)s->sb_buf[s->sb_buf_pos++] << s->bits_in_buf;
    s->bits_in_buf += 8;
  }

  int32_t code = s->bit_buf & ((1 << s->code_size) - 1);
  s->bit_buf >>= s->code_size;
  s->bits_in_buf -= s->code_size;
  return code;
}

// Decode pixels from an LZW code into the output stack.
// Returns the number of pixels produced, or -1 on error.
static inline int gif_lzw_decode_code(GIFLZWState *s, uint16_t code) {
  s->out_stack_top = 0;

  if (code > s->next_code && code != s->clear_code
      && code != s->eoi_code) {
    // Code beyond next_code — corrupt data
    return -1;
  }
  if (code == s->next_code && code != s->clear_code
      && code != s->eoi_code) {
    // Special case: code not yet in table.
    // The string is prev_code's string + prev_code's first character.
    if (s->prev_code == UINT16_MAX || s->prev_code >= GIF_LZW_MAX_CODES) {
      return -1;
    }
    s->out_stack[s->out_stack_top++] = s->first_char[s->prev_code];
    // Then push prev_code's full string
    code = s->prev_code;
  }

  // Unwind the code into the output stack (reversed)
  while (code != UINT16_MAX && code < GIF_LZW_MAX_CODES
         && s->out_stack_top < GIF_LZW_MAX_CODES) {
    s->out_stack[s->out_stack_top++] = s->suffix[code];
    code = s->prefix[code];
  }

  return (int)s->out_stack_top;
}

// Decode one scanline (img_width pixels) into the output buffer.
// Reads through mem->curpos for compatible bytes_consumed tracking.
// Returns the number of bytes consumed, or -1 on error.
// Excess pixels from a code that spans a row boundary are saved in the
// output stack and emitted at the start of the next row call.
static inline int64_t gif_lzw_decode_row(GIFLZWState *s,
                                         GIFMemIO *mem,
                                         uint8_t *outbuf,
                                         int img_width) {
  uint64_t start_pos = mem->curpos;
  int pixels_out = 0;

  // Emit any leftover pixels from the previous row's last code
  while (s->out_stack_top > 0 && pixels_out < img_width) {
    s->out_stack_top--;
    outbuf[pixels_out++] = s->out_stack[s->out_stack_top];
  }

  // Limit iterations to prevent infinite loops on corrupt data.
  int max_iterations = img_width * 2 + 100;
  int iterations = 0;

  while (pixels_out < img_width && !s->eof_reached) {
    if (++iterations > max_iterations) {
      s->eof_reached = true;
      break;
    }

    int32_t code = gif_lzw_read_code(s, mem);
    if (code < 0) {
      s->eof_reached = true;
      break;
    }

    if ((uint16_t)code == s->clear_code) {
      gif_lzw_clear(s);
      continue;
    }
    if ((uint16_t)code == s->eoi_code) {
      s->eof_reached = true;
      s->saw_eoi = true;
      break;
    }

    int npix = gif_lzw_decode_code(s, (uint16_t)code);
    if (npix < 0) {
      return -1;
    }

    // Add new entry to code table.  The new entry's suffix is the
    // first character of the current code's string, which is the last
    // element pushed onto the output stack (the stack is built in
    // reverse order).
    if (s->prev_code != UINT16_MAX && s->next_code < GIF_LZW_MAX_CODES
        && npix > 0) {
      s->prefix[s->next_code] = s->prev_code;
      s->suffix[s->next_code] = s->out_stack[npix - 1];
      s->first_char[s->next_code] = s->first_char[s->prev_code];
      s->next_code++;

      // Increase code size when table grows past current capacity
      if (s->next_code >= (1u << s->code_size)
          && s->code_size < GIF_LZW_MAX_BITS) {
        s->code_size++;
      }
    }
    s->prev_code = (uint16_t)code;

    // Output pixels (stack is reversed — emit from top down).
    // If we fill the row before exhausting the stack, the remaining
    // pixels stay in out_stack (with out_stack_top tracking how many
    // are left) for the next row call.
    // Clear the stack before emitting. If the row fills mid-code, preserve the
    // remaining pixels for the next row.
    s->out_stack_top = 0;
    for (int i = npix - 1; i >= 0; i--) {
      if (pixels_out < img_width) {
        outbuf[pixels_out++] = s->out_stack[i];
      } else {
        // Row full mid-code: save remaining pixels for next row's drain loop.
        s->out_stack_top = (uint16_t)(i + 1);
        break;
      }
    }
    if (pixels_out >= img_width) {
      break;
    }
  }

  return (int64_t)(mem->curpos - start_pos);
}

static inline void gif_finish_tail_probe(GIFLZWState *orig,
                                         GIFMemIO *orig_mem,
                                         uint64_t *tail_bytes_out,
                                         uint32_t *tail_nonclear_out,
                                         bool *saw_eoi_out) {
  GIFLZWState s = *orig;
  GIFMemIO mem = *orig_mem;
  uint64_t tail_start = mem.curpos;
  uint32_t nonclear_codes = 0;
  bool saw_eoi = s.saw_eoi;
  bool reached_subblock_terminator = false;
  uint32_t guard = 0;

  if (s.out_stack_top > 0) {
    nonclear_codes++;
    s.out_stack_top = 0;
  }

  while (!saw_eoi && mem.curpos < mem.length) {
    uint64_t read_start = mem.curpos;
    int32_t code = gif_lzw_read_code(&s, &mem);
    if (code < 0) {
      // A zero-length sub-block ends the compressed stream. The code reader
      // consumes that byte, so no further sub-block walk is necessary.
      reached_subblock_terminator =
          mem.curpos == read_start + 1 && mem.data[read_start] == 0;
      break;
    }
    if ((uint16_t)code == s.clear_code) {
      gif_lzw_clear(&s);
    }
    else if ((uint16_t)code == s.eoi_code) {
      saw_eoi = true;
      s.eof_reached = true;
      s.saw_eoi = true;
      break;
    }
    else {
      int npix = gif_lzw_decode_code(&s, (uint16_t)code);
      if (npix < 0) {
        break;
      }
      if (s.prev_code != UINT16_MAX && s.next_code < GIF_LZW_MAX_CODES
          && npix > 0) {
        s.prefix[s.next_code] = s.prev_code;
        s.suffix[s.next_code] = s.out_stack[npix - 1];
        s.first_char[s.next_code] = s.first_char[s.prev_code];
        s.next_code++;
        if (s.next_code >= (1u << s.code_size)
            && s.code_size < GIF_LZW_MAX_BITS) {
          s.code_size++;
        }
      }
      s.prev_code = (uint16_t)code;
      s.out_stack_top = 0;
      nonclear_codes++;
    }
    // Permit clear codes interleaved with legitimate tail data while bounding
    // work on corrupt input.
    if (++guard > GIF_LZW_MAX_CODES * 8) {
      break;
    }
  }

  s.sb_buf_pos = s.sb_buf_len;
  if (!reached_subblock_terminator) {
    while (mem.curpos < mem.length) {
      uint8_t sb = mem.data[mem.curpos++];
      if (sb == 0) {
        break;
      }
      if (mem.curpos + sb > mem.length) {
        mem.curpos = mem.length;
        break;
      }
      mem.curpos += sb;
    }
  }

  if (tail_bytes_out) {
    *tail_bytes_out = mem.curpos - tail_start;
  }
  if (tail_nonclear_out) {
    *tail_nonclear_out = nonclear_codes;
  }
  if (saw_eoi_out) {
    *saw_eoi_out = saw_eoi;
  }
}


// =========================================================================
// GIF binary parser — replaces libgif dependency entirely.
// =========================================================================
typedef struct GIFColor { uint8_t Red, Green, Blue; } GIFColor;
typedef struct GIFHeader {
  uint16_t screen_width, screen_height;
  uint8_t background;
  GIFColor *global_cmap;
  int global_cmap_count;
} GIFHeader;

static inline uint16_t gif_read_u16(const uint8_t *d) {
  return (uint16_t)d[0] | ((uint16_t)d[1] << 8);
}

static inline bool gif_has_header_anchor(const uint8_t *data,
                                         uint64_t length) {
  uint8_t packed;
  bool has_gct;
  uint64_t gct_bytes = 0;

  if (length < 13) {
    return false;
  }
  if (data[0] != 'G' || data[1] != 'I' || data[2] != 'F') {
    return false;
  }
  if (data[3] != '8' || (data[4] != '7' && data[4] != '9')
      || data[5] != 'a') {
    return false;
  }

  packed = data[10];
  has_gct = ((packed >> 7) & 1) != 0;
  if (has_gct) {
    uint64_t gct_count = (uint64_t)1 << ((packed & 7) + 1);
    gct_bytes = gct_count * 3;
  }

  return 13 + gct_bytes <= length;
}

static inline bool gif_reserve_u8_buffer(uint8_t **buffer,
                                         size_t *capacity,
                                         size_t needed) {
  uint8_t *grown;

  if (*capacity >= needed) {
    return true;
  }

  grown = (uint8_t *)realloc(*buffer, needed);
  if (!grown) {
    return false;
  }

  *buffer = grown;
  *capacity = needed;
  return true;
}

static inline uint64_t gif_parse_header(const uint8_t *data, uint64_t length, GIFHeader *hdr) {
  memset(hdr, 0, sizeof(*hdr));
  if (length < 13) { return 0; }
  if (data[0]!='G'||data[1]!='I'||data[2]!='F') { return 0; }
  if (data[3] != '8' || (data[4] != '7' && data[4] != '9') || data[5] != 'a') {
    return 0;
  }
  hdr->screen_width = gif_read_u16(data+6);
  hdr->screen_height = gif_read_u16(data+8);
  hdr->background = data[11];
  uint8_t packed = data[10];
  bool has_gct = (packed>>7)&1;
  int gct_count = has_gct ? (1<<((packed&7)+1)) : 0;
  uint64_t pos = 13;
  if (has_gct) {
    uint64_t gct_bytes = (uint64_t)gct_count*3;
    if (pos+gct_bytes > length) { return 0; }
    hdr->global_cmap = (GIFColor*)malloc(gct_count*sizeof(GIFColor));
    if (!hdr->global_cmap) { return 0; }
    for (int i=0; i<gct_count; i++) {
      hdr->global_cmap[i].Red   = data[pos+i*3+0];
      hdr->global_cmap[i].Green = data[pos+i*3+1];
      hdr->global_cmap[i].Blue  = data[pos+i*3+2];
    }
    hdr->global_cmap_count = gct_count;
    pos += gct_bytes;
  }
  return pos;
}

static inline uint64_t gif_skip_ext(const uint8_t *data, uint64_t length, uint64_t pos) {
  if (pos >= length) { return 0; }
  uint8_t label = data[pos++];
  if (label == 0xF9) {
    if (pos + 6 > length) { return 0; }
    if (data[pos] != 4) { return 0; }
    if (data[pos + 5] != 0) { return 0; }
    return pos + 6;
  }
  if (label != 0xFF && label != 0xFE && label != 0x01) {
    return 0;
  }
  while (pos < length) {
    uint8_t sb = data[pos++];
    if (sb == 0) { return pos; }
    if (pos + sb > length) { return 0; }
    pos += sb;
  }
  return 0;
}

static inline uint64_t gif_parse_image_desc(const uint8_t *data, uint64_t length, uint64_t pos,
    uint16_t *il, uint16_t *it, uint16_t *iw, uint16_t *ih, bool *interlaced,
    GIFColor **lcmap, int *lcmap_count) {
  if (pos+9 > length) { return 0; }
  *il = gif_read_u16(data+pos); *it = gif_read_u16(data+pos+2);
  *iw = gif_read_u16(data+pos+4); *ih = gif_read_u16(data+pos+6);
  uint8_t packed = data[pos+8];
  *interlaced = (packed>>6)&1;
  bool has_lct = (packed>>7)&1;
  int lct_count = has_lct ? (1<<((packed&7)+1)) : 0;
  pos += 9;
  *lcmap = NULL; *lcmap_count = 0;
  if (has_lct) {
    uint64_t lct_bytes = (uint64_t)lct_count*3;
    if (pos+lct_bytes > length) { return 0; }
    *lcmap = (GIFColor*)malloc(lct_count*sizeof(GIFColor));
    if (!*lcmap) { return 0; }
    for (int i=0; i<lct_count; i++) {
      (*lcmap)[i].Red   = data[pos+i*3+0];
      (*lcmap)[i].Green = data[pos+i*3+1];
      (*lcmap)[i].Blue  = data[pos+i*3+2];
    }
    *lcmap_count = lct_count;
    pos += lct_bytes;
  }
  return pos; // position of LZW min code size byte
}

// other function prototypes
static inline void init_GIFMemIO(GIFMemIO *m, char *data, uint64_t length);

///////////////////////////
// carve state functions //
///////////////////////////

// Serialize or deserialize carve state. GIFCarveState is fixed-size with no
// pointers, so checkpoint I/O can treat it as a single blob even though
// SIZEOFCARVESTATEFUNC intentionally remains NULL.
static inline bool gif_serialize_carve_state(void **state, FILE *fp, StateSerialization mode) {
  size_t (*fb)(void *ptr, size_t size, size_t nitems,
               FILE *stream) = mode == SERIALIZE ? (size_t (*)(void *ptr, size_t size, size_t nitems, FILE *stream))fwrite
                                                 : (size_t (*)(void *ptr, size_t size, size_t nitems, FILE *stream))fread;

  if (mode == DESERIALIZE) {
    *state = malloc(sizeof(GIFCarveState));
    check_memory_allocation(*state, __LINE__, __FILE__, "state");
  }

  if (fb(*state, sizeof(GIFCarveState), 1, fp) != 1) {
    perror("gif carve state");
    handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
  }

  return true;
}


// clone gif carve state. Fixed-size struct, memcpy suffices.
static inline void *gif_clone_carve_state(const void *srcstate) {
  GIFCarveState *d = malloc(sizeof(GIFCarveState));
  check_memory_allocation(d, __LINE__, __FILE__, "d");
  memcpy(d, srcstate, sizeof(GIFCarveState));
  return d;
}


// free gif carve state. No internal pointers to free.
static inline void gif_free_carve_state(void **state) {
  GIFCarveState **s = (GIFCarveState **)state;
  free(*s);
  *s = NULL;
}


// display a representation of gif carve state.
//
// IMPORTANT: lock_fprintf() MUST NOT BE USED BY PRINTCARVESTATEFUNC functions, as this will result
// in deadlock. Use fprintf(stdout, ...) instead.
//
static inline void gif_print_carve_state(const void *state) {
  GIFCarveState *s = (GIFCarveState *)state;

  if (! s) {
    fprintf(stdout, "NULL\n");
  }
  else {
    fprintf(stdout, "valid=%d ckpt=%" PRIu64 " lgp=%" PRIu64 " frames=%u"
            " snap=%d snap_pos=%" PRIu64 " snap_row=%u",
            s->valid, s->checkpoint_curpos, s->last_good_row_pos, s->completed_frames,
            s->snap_valid, s->snap_pos, s->snap_next_row);
  }
}

//
// a block validator function decides, based on whatever criteria are available (entropy, block hash
// dictionaries, the presence of keywords or binary strings, etc.) whether a block might be part of
// a file of the associated type. A confidence interval from BLOCK_CONFIDENCE_INVALID (absolutely
// not a block of the associated file type) to BLOCK_CONFIDENCE_VALID (100% certainty) is used.
//
// BLOCK VALIDATION FUNCTIONS MUST BE THREAD-SAFE--THIS MEANS NO WRITEABLE GLOBAL VARIABLES, NO
// WRITEABLE STATIC VARIABLES, AND NO USE OF THREAD-UNSAFE HELPER FUNCTIONS.
//
static inline uint32_t gif_block_validate(char *data, uint64_t length, BlockValidationDecision *decision, uint64_t *validates_to,
                                          uint32_t needleidx, uint32_t blocksize, void *blockhashkey) {
  bool header_anchor = false;
  bool all_zero = false;
  BlockValidationDecision structural_decision = BLOCK_CONFIDENCE_VALID;

  (void)needleidx;
  (void)blocksize;
  (void)blockhashkey;

  *validates_to = length > 0 ? length - 1 : 0;

  if (scalpel_state.no_defrag) {
    if (*decision == BLOCK_CONFIDENCE_INVALID) {
      *decision = BLOCK_CONFIDENCE_VALID;
    }
    return needleidx;
  }

  // Header blocks are reliable anchors. If the block begins with a
  // syntactically valid GIF header, keep it fully valid and skip the
  // interior sub-block heuristic below.
  if (gif_has_header_anchor((const uint8_t *)data, length)) {
    header_anchor = true;
  }

  // Zero-block check: reject truly all-zero blocks. Some valid interior GIF
  // blocks begin with long zero runs, so a leading 0x00 by itself is not a
  // reliable rejection signal.
  if (! header_anchor && structural_decision == BLOCK_CONFIDENCE_VALID) {
    if (length >= 1024) {
      uint64_t zero_total = 0;
      uint64_t lane_zero[4] = {0, 0, 0, 0};
      uint64_t printable = 0;
      uint64_t hi_bytes = 0;
      uint64_t freq[256] = {0};
      uint64_t lane_freq[4][256] = {{0}};
      uint64_t lane_len = 0;
      uint64_t max_lane_zero = 0;
      uint64_t top8_total = 0;
      uint64_t lane_max = 0;
      uint64_t i;
      uint64_t b;

      all_zero = ((uint8_t)data[0] == 0x00);
      for (i = 0; i < length; i++) {
        uint8_t c = (uint8_t)data[i];

        freq[c]++;
        lane_freq[i & 3][c]++;
        if (c == 0x00) {
          zero_total++;
          lane_zero[i & 3]++;
        }
        else {
          all_zero = false;
        }
        if ((c >= 32 && c < 127) || c == '\t' || c == '\n' || c == '\r') {
          printable++;
        }
        if (c >= 250) {
          hi_bytes++;
        }
      }

      if (all_zero) {
        structural_decision = BLOCK_CONFIDENCE_INVALID;
      }

      if (structural_decision == BLOCK_CONFIDENCE_VALID) {
        lane_len = length / 4;
        for (i = 0; i < 4; i++) {
          if (lane_zero[i] > max_lane_zero) {
            max_lane_zero = lane_zero[i];
          }
        }

        // Reject strongly structured non-header blocks that look like
        // fixed-width numeric/text tables rather than GIF image data.
        if (lane_len > 0
            && zero_total >= length / 8
            && max_lane_zero >= (lane_len * 19) / 20
            && max_lane_zero >= (zero_total * 19) / 20) {
          structural_decision = BLOCK_CONFIDENCE_INVALID;
        }
      }

      if (structural_decision == BLOCK_CONFIDENCE_VALID
          && printable >= (length * 7) / 8
          && hi_bytes <= length / 4096) {
        // Reject plain-text lookup/name tables. Compressed GIF image data
        // contains plenty of non-printable and high-value bytes.
        structural_decision = BLOCK_CONFIDENCE_INVALID;
      }

      if (structural_decision == BLOCK_CONFIDENCE_VALID) {
        for (i = 0; i < 8; i++) {
          uint64_t best_count = 0;
          uint32_t best_byte = 0;

          for (b = 0; b < 256; b++) {
            if (freq[b] > best_count) {
              best_count = freq[b];
              best_byte = (uint32_t)b;
            }
          }
          if (best_count == 0) {
            break;
          }
          top8_total += best_count;
          freq[best_byte] = 0;
        }

        lane_len = (length + 3) / 4;
        if (lane_len > 0) {
          for (i = 0; i < 4; i++) {
            for (b = 0; b < 256; b++) {
              if (lane_freq[i][b] > lane_max) {
                lane_max = lane_freq[i][b];
              }
            }
          }
        }

        // Reject structured symbol/record tables that mix mostly-printable
        // bytes with repeated fixed-lane punctuation patterns.
        if (printable >= (length * 3) / 5
            && top8_total >= (length * 3) / 20
            && lane_max >= lane_len / 20) {
          structural_decision = BLOCK_CONFIDENCE_INVALID;
        }
      }
    }
    else if (length >= 16 && (uint8_t)data[0] == 0x00) {
      all_zero = true;
      for (uint64_t z = 0; z < length; z++) {
        if ((uint8_t)data[z] != 0x00) {
          all_zero = false;
          break;
        }
      }
      if (all_zero) {
        structural_decision = BLOCK_CONFIDENCE_INVALID;
      }
    }
  }

  // Sub-block structure check: GIF image data uses sub-blocks with a 1-byte length prefix.
  // Correct encoders use 255-byte sub-blocks (0xFF header + 255 data = 256 stride).
  // Check several expected header positions for 0xFF. Random non-GIF data has only ~1/256
  // chance of matching at each position.
  //
  // This check is conservative: it only rejects blocks that clearly lack GIF sub-block structure.
  // It does not attempt to identify which GIF file a block belongs to (same-phase blocks from
  // different GIF files will both pass).
  if (! header_anchor && structural_decision == BLOCK_CONFIDENCE_VALID && length >= 512) {
    // Derive the full sub-block threshold from the encoder's observed maximum.
    // GIF permits lengths from 1 through 255, so a fixed threshold would reject
    // valid encoders that consistently use smaller sub-blocks. A tolerance of
    // four bytes permits legal variation while retaining a useful stride test.
    uint64_t sb_base = UINT64_MAX;
    uint64_t sp = 0;
    uint8_t max_sb_len = 0;
    uint64_t walk_end = sp;
    while (walk_end < length) {
      uint8_t sb_len = (uint8_t)data[walk_end];
      if (sb_len == 0) {
        break;
      }
      if (sb_len > max_sb_len) {
        max_sb_len = sb_len;
      }
      if (walk_end + 1 + sb_len > length) { break; }
      walk_end += 1 + sb_len;
    }
    // Need enough signal: at least 64-byte sub-blocks seen somewhere.
    uint8_t full_threshold = (max_sb_len >= 64) ? (uint8_t)(max_sb_len - 4) : 0;

    if (full_threshold > 0) {
      // Find the first sub-block that meets the threshold to anchor stride.
      sp = 0;
      while (sp < length) {
        uint8_t sb_len = (uint8_t)data[sp];
        if (sb_len == 0) {
          break;
        }
        if (sb_len >= full_threshold) {
          sb_base = sp;
          break;
        }
        if (sp + 1 + sb_len > length) { break; }
        sp += 1 + sb_len;
      }
    }

    if (sb_base < UINT64_MAX) {
      uint64_t stride = 1 + (uint8_t)data[sb_base];
      int checks = 0;
      int bad = 0;
      for (int h = 1; h <= 4; h++) {
        uint64_t hpos = sb_base + (uint64_t)h * stride;
        if (hpos < length) {
          checks++;
          if ((uint8_t)data[hpos] < full_threshold) {
            bad++;
          }
        }
      }
      // If we had enough positions to check and most failed, reject
      if (checks >= 3 && bad >= 3) {
        structural_decision = BLOCK_CONFIDENCE_LOW;
      }
    }
    else if (max_sb_len > 0 && max_sb_len < 64) {
      // Very small sub-blocks only — could be a very short/low-resolution
      // GIF frame or non-GIF data. Downgrade but don't reject.
      structural_decision = BLOCK_CONFIDENCE_LOW;
    }
    else {
      // No parseable sub-block chain from offset 0. Downgrade (full
      // validator still gets a say).
      structural_decision = BLOCK_CONFIDENCE_LOW;
    }
  }

  if (structural_decision == BLOCK_CONFIDENCE_INVALID) {
    *decision = BLOCK_CONFIDENCE_INVALID;
  }
  else if (*decision == BLOCK_CONFIDENCE_INVALID) {
    *decision = structural_decision;
  }

  if (scalpel_state.mode_verbose) {
    lock_fprintf(stdout, "gif_block_validate() called on %p.\n", data);
  }

  return needleidx;
}

static inline void init_GIFMemIO(GIFMemIO *m, char *data, uint64_t length) {
  m->data = (unsigned char *)data;
  m->length = length;
  m->curpos = 0;
  m->errpos = -1;
}


// GIFMemRead removed — no longer needed (libgif dependency eliminated)


// Skip GIF sub-blocks starting at data[pos] (first byte is a sub-block length prefix).
// Returns position after the sub-block terminator (0x00 length byte).
static inline uint64_t gif_skip_subblocks(const char *data, uint64_t length, uint64_t pos) {
  while (pos < length) {
    uint8_t sb_len = (uint8_t)data[pos];
    pos++;
    if (sb_len == 0) {
      break;
    }
    if (pos + sb_len > length) {
      return length;  // truncated sub-block — treat as end of data
    }
    pos += sb_len;
  }
  return pos;
}


// Skip a GIF image record. pos should point to the first byte AFTER the 0x2C image introducer.
// Reads the image descriptor (9 bytes), optional local color table, LZW minimum code size byte,
// then skips all image data sub-blocks. Returns position after the sub-block terminator.
static inline uint64_t gif_skip_image_record(const char *data, uint64_t length, uint64_t pos) {
  if (pos + 9 > length) {
    return length;
  }
  uint8_t packed = (uint8_t)data[pos + 8];
  pos += 9;
  // skip local color table if present
  if (packed & 0x80) {
    int ct_size = 3 * (1 << ((packed & 0x07) + 1));
    pos += ct_size;
  }
  if (pos >= length) {
    return length;
  }
  pos++;  // skip LZW minimum code size byte
  return gif_skip_subblocks(data, length, pos);
}

// a file validator function determines the position in 'data' at which validation (possibly) fails
// for this file type. While exact determination is often difficult, effort should be expended to
// make this determination as accurate as possible, otherwise reassembly of fragmented files may
// fail. If the file fully validates, 'validates' should be set to true and 'promising' to false. If
// the file partially validates, 'validates' should be set to false and 'promising' to true. 'data'
// will be truncated at position 'validates_to' by calling code, so accurate determination is
// essential.
//
// FILE VALIDATION FUNCTIONS MUST BE THREAD-SAFE--THIS MEANS NO WRITEABLE GLOBAL VARIABLES, NO
// WRITEABLE STATIC VARIABLES, AND NO USE OF THREAD-UNSAFE HELPER FUNCTIONS.
//
static inline void gif_validate_core(char *data, uint64_t length,
                                     bool *validates,
                                     uint64_t *validates_to,
                                     bool *promising,
                                     uint32_t needleidx,
                                     uint32_t blocksize,
                                     void *carvehashkey,
                                     GIFCarveState *direct_state) {
  GIFHeader gif_hdr;
  memset(&gif_hdr, 0, sizeof(gif_hdr));
  GIFColor *frame_lcmap = NULL;
  int frame_lcmap_count = 0;
  int ImageNum = 0;
  uint32_t bs = 0;
  GIFMemIO mem;

  //
  // From gif_lib.h:
  //
  // typedef struct GifFileType { GifWord SWidth, SHeight; /* Size of virtual canvas */ GifWord
  // SColorResolution; /* How many colors can we generate? */ GifWord SBackGroundColor; /*
  // Background color for virtual canvas */ uint8_t AspectByte; /* Used to compute pixel aspect
  // ratio */ ColorMapObject *SColorMap; /* Global colormap, NULL if nonexistent. */ int ImageCount;
  // /* Number of current image (both APIs) */ GifImageDesc Image; /* Current image (low-level API)
  // */ SavedImage *SavedImages; /* Image sequence (high-level API) */ int ExtensionBlockCount; /*
  // Count extensions past last image */ ExtensionBlock *ExtensionBlocks; /* Extensions past last
  // image */ int Error; /* Last error condition reported */ void *UserData; /* hook to attach user
  // data (TVT) */ void *Private; /* Don't mess with this! */ } GifFileType;
  //
  // typedef int (*InputFunc) (GifFileType *, uint8_t *, int);
  //
  // GifFileType *DGifOpen(void *userPtr, InputFunc readFunc, int *ErrorCode)
  //

  if (scalpel_state.mode_verbose) {
    lock_fprintf(stdout, "gif_file_validate() called on %p.\n", data);
  }

  // Frame-local buffers — declared at function scope for centralized
  // cleanup in done: label.  Must be before first goto done.
  uint8_t *scanline = NULL;
  size_t scanline_capacity = 0;
  uint8_t *prev_scanline = NULL;
  size_t prev_scanline_capacity = 0;
  GIFLZWState *_frame_lzw = NULL;
  // Ring of pending resume snapshots for this call. Allocation is lazy; a
  // failed allocation leaves validation correct but disables snapshot reuse.
  GIFSnapPending *snap_ring = NULL;
  uint32_t snap_ring_head = 0;
  uint64_t snap_ring_last_block = UINT64_MAX;

  // Checkpoint restore: check for saved state from a previous validation call on the same
  // candidate. If the prefix of data matches (verified by XXH3 hash), skip already-validated
  // frames and restore detection state, so only new data is fully processed.
  bool in_replay = false;
  bool restored_from_frame_checkpoint = false;
  uint32_t frames_to_skip = 0;
  uint64_t replay_checkpoint_curpos = 0;
  GIFCarveState replay_state_storage = {0};
  GIFCarveState *replay_state = NULL;
  bool resume_snap = false;
  bool snap_src_set = false;
  GIFCarveState snap_src;

  (void)needleidx;
  (void)blocksize;

  if (direct_state) {
    if (direct_state->valid) {
      snap_src = *direct_state;
      snap_src_set = true;
    }
    if (direct_state->valid && direct_state->checkpoint_curpos > 0
        && direct_state->checkpoint_curpos <= length) {
      uint64_t hash = XXH3_64bits(data, direct_state->checkpoint_curpos);
      if (hash == direct_state->prefix_hash) {
        in_replay = true;
        replay_state = &replay_state_storage;
        memcpy(replay_state, direct_state, sizeof(*replay_state));
        frames_to_skip = (direct_state->completed_frames > 1)
            ? (direct_state->completed_frames - 2) : 0;
        replay_checkpoint_curpos = direct_state->checkpoint_curpos;
      }
    }
  }
  else if (carvehashkey) {
    GIFCarveState *saved = (GIFCarveState *)carve_get_state(carvehashkey);
    if (saved && saved->valid) {
      snap_src = *saved;
      snap_src_set = true;
    }
    if (saved && saved->valid && saved->checkpoint_curpos > 0
        && saved->checkpoint_curpos <= length) {
      uint64_t hash = XXH3_64bits(data, saved->checkpoint_curpos);
      if (hash == saved->prefix_hash) {
        in_replay = true;
        replay_state = &replay_state_storage;
        memcpy(replay_state, saved, sizeof(*replay_state));
        frames_to_skip = (saved->completed_frames > 1)
            ? (saved->completed_frames - 2) : 0;
        replay_checkpoint_curpos = saved->checkpoint_curpos;
      }
    }
    gif_free_carve_state((void **)&saved);
  }

  // Qualify the intra-frame LZW resume snapshot on its own prefix hash,
  // independently of the frame-skip gate above. Trials share the candidate's
  // committed prefix and differ in the tail, so a snapshot below the changed
  // bytes stays usable even when the frame-skip gate's longer hash fails.
  if (snap_src_set && snap_src.snap_valid
      && snap_src.snap_pos > 0 && snap_src.snap_pos <= length
      && snap_src.snap_record_pos < snap_src.snap_pos
      && !snap_src.snap_lzw.sb_truncated
      && !(snap_src.snap_frame_index > 0 && snap_src.snap_next_row == 0)
      && (! snap_src.snap_mad_active
          || snap_src.snap_next_row == 0
          || (snap_src.snap_prev_row_present
              && snap_src.snap_prev_row_len <= GIF_SNAP_PREV_ROW_MAX))
      && XXH3_64bits(data, snap_src.snap_pos) == snap_src.snap_prefix_hash) {
    resume_snap = true;
  }

  *validates = false;
  *validates_to = 0;
  *promising = false;


  init_GIFMemIO(&mem, data, length);
  GIFV_LOG("begin");

  // State API: track completed frames for checkpoint/restore.
  uint32_t frames_at_lgp_boundary = 0;
  uint64_t lgp_boundary_block = 0;
  // Outer-scope anchors: reliable_pos tracks position where data still
  // looked normal (used for checkpoint placement and validates_to capping).
  uint64_t reliable_pos = 0;
  // Outer-scope MAD anchor: last position where RGB MAD confirmed good data.
  // Updated at end of each frame from frame-local last_good_mad_pos.
  uint64_t outer_last_good_mad_pos = 0;
  // Sub-block alignment state (outer scope for done: capping)
  uint64_t outer_sb_base = UINT64_MAX;
  // First frame's sub-block base (never overwritten, used in done: check)
  uint64_t first_sb_base = UINT64_MAX;
  uint64_t first_frame_end = 0;
  // Cross-frame MAD: save last row's RGB values from each frame so we can
  // compare with the first row of the next frame.  Detects wrong blocks
  // from DIFFERENT GIF files (different palettes produce huge MAD).
  uint8_t *prev_frame_last_rgb = NULL;     // RGB triplets of last row
  int prev_frame_rgb_count = 0;            // number of RGB triplets saved
  uint64_t prev_frame_end_pos = 0;         // byte position where prev frame ended
  bool prev_frame_had_lcmap = false;       // previous frame used a local color table
  // (bad_mad_streak, running_mad_sum, mad_count are per-frame — declared
  //  inside the frame block.  Cross-frame accumulation was tested and
  //  causes false positives on legitimate high-contrast animation frames.)

  bs = scalpel_state.blocksize;

  // One-time pre-decode scan: traverse GIF structure in raw data to find
  // the first block boundary with broken sub-block alignment. Done once
  // per validator call, before any LZW decoding.
  uint64_t first_bad_sb_boundary = UINT64_MAX;
  if (bs > 0 && length > 13) {
    // Parse GIF header to find first image data
    uint64_t sp = 6;  // skip signature
    // Logical screen descriptor: 4 bytes (w,h) + 1 flags + 1 bgcolor + 1 aspect = 7 bytes
    if (sp + 7 <= length) {
      uint8_t lsd_flags = (uint8_t)data[sp + 4];
      sp += 7;
      // Global color table
      if (lsd_flags & 0x80) {
        uint32_t gct_entries = 1u << ((lsd_flags & 0x07) + 1);
        sp += gct_entries * 3;
      }
    }
    // Now sp is at the first record. Find all frames' sub-block regions
    // and check alignment at each block boundary.
    uint64_t scan_sb_base = UINT64_MAX;
    uint64_t scan_sb_stride = 256;
    bool scan_done = false;

    while (!scan_done && sp < length) {
      uint8_t marker = (uint8_t)data[sp];
      if (marker == 0x2C) {
        // Image descriptor: 1 marker + 4 uint16 + 1 flags = 10 bytes
        if (sp + 10 > length) { break; }
        uint8_t img_flags = (uint8_t)data[sp + 9];
        sp += 10;
        if (img_flags & 0x80) {
          uint32_t lct_entries = 1u << ((img_flags & 0x07) + 1);
          sp += lct_entries * 3;
        }
        if (sp >= length) { break; }
        sp++;  // skip LZW minimum code size byte
        // Derive this frame's full sub-block threshold from its observed
        // maximum length.
        uint8_t frame_max_sb = 0;
        {
          uint64_t probe = sp;
          int peek = 0;
          while (probe < length && peek < 64) {
            uint8_t sb_len = (uint8_t)data[probe];
            if (sb_len == 0) { break; }
            if (sb_len > frame_max_sb) { frame_max_sb = sb_len; }
            if (probe + 1 + sb_len > length) { break; }
            probe += 1 + sb_len;
            peek++;
          }
        }
        uint8_t frame_full_threshold = (frame_max_sb >= 64) ? (uint8_t)(frame_max_sb - 4) : 0;

        // Find first full-size sub-block for this frame
        scan_sb_base = UINT64_MAX;
        if (frame_full_threshold > 0) {
          uint64_t search = sp;
          while (search < length) {
            uint8_t sb_len = (uint8_t)data[search];
            if (sb_len == 0) { break; }
            if (sb_len >= frame_full_threshold) {
              scan_sb_base = search;
              scan_sb_stride = 1 + sb_len;
              break;
            }
            search += 1 + sb_len;
          }
        }
        // Walk sub-blocks to find where full-size sub-blocks end
        uint64_t frame_sb_end = length;
        bool natural_frame_end = false;
        bool walk_hit_eof = false;
        if (scan_sb_base < UINT64_MAX) {
          uint64_t walk = scan_sb_base;
          while (walk < length) {
            uint8_t sb_len = (uint8_t)data[walk];
            if (sb_len == 0) {
              frame_sb_end = walk;
              // Verify the byte after terminator is a valid GIF marker
              if (walk + 1 < length) {
                uint8_t next = (uint8_t)data[walk + 1];
                if (next == 0x2C || next == 0x21 || next == 0x3B) {
                  natural_frame_end = true;
                }
              }
              break;
            }
            if (frame_full_threshold > 0 && sb_len < frame_full_threshold) {
              frame_sb_end = walk;
              // Check if this is a natural short sub-block ending
              // (followed by valid sub-blocks and a 0x00 terminator)
              // vs wrong data that happened to be below the encoder's
              // observed full-size threshold.
              uint64_t check = walk;
              while (check < length) {
                uint8_t cl = (uint8_t)data[check];
                if (cl == 0) {
                  // Verify the byte after terminator is a valid GIF marker
                  if (check + 1 < length) {
                    uint8_t next = (uint8_t)data[check + 1];
                    if (next == 0x2C || next == 0x21 || next == 0x3B) {
                      natural_frame_end = true;
                    }
                  }
                  else {
                    // Terminator at EOF — can't confirm next marker.
                    // Treat as truncation, not wrong data.
                    walk_hit_eof = true;
                  }
                  break;
                }
                if (check + 1 + cl > length) {
                  // Sub-block walk ran past available data — truncation,
                  // not wrong alignment.  Don't let probes fire past here.
                  walk_hit_eof = true;
                  break;
                }
                check += 1 + cl;
              }
              if (check >= length) { walk_hit_eof = true; }
              break;
            }
            walk += 1 + sb_len;
          }
          // A walk that reaches a natural terminator or short final sub-block
          // has followed the actual length fields to a recognized frame end.
          // Do not apply a fixed-stride probe in that case because legal,
          // nonuniform sub-block sizes cause predicted positions to drift.
          bool walk_succeeded = natural_frame_end;
          // Check block boundaries within this frame's full-size region.
          // Use 8 probes at consecutive stride positions after each boundary.
          // For correct data: all probes see sub-block headers (>= 254).
          // For wrong data: probes hit non-header bytes (< 254).
          // When wrong data at a boundary terminates the walk early
          // (frame_sb_end near boundary), allow probes past frame_sb_end
          // to read into wrong data. But for NATURAL frame endings
          // (correct data transitions to next frame), limit probes to
          // frame_sb_end to avoid false positives from next frame's
          // different alignment.
          uint64_t start_blk = scan_sb_base / bs + 1;
          uint64_t max_blk = length / bs;
          for (uint64_t bk = start_blk; bk <= max_blk && !walk_succeeded; bk++) {
            uint64_t boundary = bk * bs;
            if (boundary < scan_sb_base || boundary >= frame_sb_end) {
              if (boundary >= frame_sb_end) { break; }
              continue;
            }
            uint64_t boff = boundary - scan_sb_base;
            uint64_t strides_in = boff / scan_sb_stride;
            uint64_t nearest = scan_sb_base + (strides_in + 1) * scan_sb_stride;
            int bad_h = 0;
            int valid_h = 0;
            for (int h = 0; h < 8; h++) {
              uint64_t hpos = nearest + (uint64_t)h * scan_sb_stride;
              if (hpos >= length) {
                break;
              }
              // Limit probes to frame_sb_end when:
              //  - natural frame end (correct data → next frame has different alignment)
              //  - truncation (walk hit EOF → missing data, not wrong alignment)
              // Only allow probes past frame_sb_end when the walk ended on
              // genuinely suspicious data (not EOF, not natural terminator).
              if ((natural_frame_end || walk_hit_eof) && hpos >= frame_sb_end) {
                break;
              }
              valid_h++;
              if ((uint8_t)data[hpos] < frame_full_threshold) {
                bad_h++;
              }
            }
            if (valid_h >= 3 && bad_h >= (valid_h - 1)) {
              // Phase-shift check: before declaring this boundary bad,
              // see if the block starting here has valid internal
              // sub-block structure at a DIFFERENT phase. Fragmented
              // reassembly produces phase discontinuities at block
              // boundaries — correct blocks from different disk offsets
              // have sub-block headers at different positions.
              bool has_internal_sb = false;
              {
                uint64_t isp = boundary;
                while (isp < length && isp < boundary + 512) {
                  uint8_t isb_len = (uint8_t)data[isp];
                  if (isb_len == 0) {
                    break;
                  }
                  if (isb_len >= frame_full_threshold) {
                    // Found a full-size sub-block. Verify stride.
                    uint64_t istride = 1 + isb_len;
                    int icheck = 0;
                    int igood = 0;
                    for (int ih = 1; ih <= 3; ih++) {
                      uint64_t ihpos = isp + (uint64_t)ih * istride;
                      if (ihpos >= length) {
                        break;
                      }
                      icheck++;
                      if ((uint8_t)data[ihpos] >= frame_full_threshold) {
                        igood++;
                      }
                    }
                    if (icheck >= 2 && igood >= 2) {
                      has_internal_sb = true;
                    }
                    break;
                  }
                  if (isp + 1 + isb_len > length) {
                    break;
                  }
                  isp += 1 + isb_len;
                }
              }
              if (!has_internal_sb) {
                first_bad_sb_boundary = boundary;
                scan_done = true;
                break;
              }
              // else: phase shift from fragmented reassembly — continue
              // scanning with the original stride. The LZW decoder will
              // determine whether this block is correct or wrong.
            }
          }
          // (Edge case handling removed — was causing state API interaction issues)
        }
        // Skip remaining sub-blocks to reach the terminator
        while (sp < length) {
          uint8_t sb_len = (uint8_t)data[sp];
          if (sb_len == 0) { sp++; break; }
          if (sp + 1 + sb_len > length) { sp = length; break; }
          sp += 1 + sb_len;
        }
      } else if (marker == 0x21) {
        // Extension: marker + type + sub-blocks
        if (sp + 2 > length) { break; }
        sp += 2;
        while (sp < length) {
          uint8_t sb_len = (uint8_t)data[sp];
          if (sb_len == 0) { sp++; break; }
          if (sp + 1 + sb_len > length) { sp = length; break; }
          sp += 1 + sb_len;
        }
      } else {
        // Trailer (0x3B) or unknown — stop
        break;
      }
    }
  }

  {
    uint64_t hdr_end = gif_parse_header((const uint8_t *)data, length, &gif_hdr);
    if (hdr_end == 0) { mem.errpos = 0; goto done; }
    mem.curpos = hdr_end;
  }

  // Intra-frame resume takes priority over frame-skip replay. It jumps
  // straight to the snapshot frame's image descriptor (skipping all earlier
  // frames without touching them), and the descriptor branch below then
  // restores the LZW decoder mid-frame. The frame-skip path remains the
  // fallback when no snapshot qualifies.
  if (resume_snap) {
    mem.curpos = snap_src.snap_record_pos;
    ImageNum = (int)snap_src.snap_frame_index;
    frames_at_lgp_boundary = (uint32_t)ImageNum;
    lgp_boundary_block = (bs > 0) ? snap_src.snap_record_pos / bs : 0;
    reliable_pos = snap_src.snap_record_pos;
    if (snap_src.snap_last_good_mad_pos > outer_last_good_mad_pos) {
      outer_last_good_mad_pos = snap_src.snap_last_good_mad_pos;
    }
    first_frame_end = snap_src.first_frame_end;
    in_replay = false;
    frames_to_skip = 0;
  }
  // Checkpoint frame-skip: if restoring from saved state, skip completed frames by walking
  // sub-blocks directly (no LZW decompression). This advances mem.curpos past all already-
  // validated frames.
  else if (in_replay && frames_to_skip > 0) {
    uint64_t skip_pos = mem.curpos;
    uint32_t skipped = 0;
    while (skipped < frames_to_skip && skip_pos < length) {
      uint8_t rec = (uint8_t)data[skip_pos];
      skip_pos++;
      if (rec == 0x2C) {
        skip_pos = gif_skip_image_record(data, length, skip_pos);
        skipped++;
      } else if (rec == 0x21) {
        skip_pos = gif_skip_ext((const uint8_t *)data, length, skip_pos);
      } else if (rec == 0x3B) {
        break;
      } else {
        in_replay = false;
        break;
      }
    }
    if (in_replay && skipped == frames_to_skip) {
      mem.curpos = skip_pos;
      ImageNum = skipped;
      frames_at_lgp_boundary = skipped;
      lgp_boundary_block = (bs > 0) ? skip_pos / bs : 0;
      // Re-anchor at the replay entry point so the last previously-completed
      // frame is decoded again and can rebuild trustworthy anchors.
      reliable_pos = skip_pos;
      outer_last_good_mad_pos = skip_pos;
      // Restore cross-frame detection state from checkpoint
      first_frame_end = replay_state->first_frame_end;
      // bad_mad_streak, running_mad_sum, mad_count, BPR are per-frame (not restored)
      restored_from_frame_checkpoint = true;
    } else {
      in_replay = false;
      frames_to_skip = 0;
      replay_checkpoint_curpos = 0;
    }
  }

  // scan data until there's an error — our own record parser

  uint8_t record_type = 0;
  int stray_00_count = 0;
  do {
    uint64_t pre_record_pos = mem.curpos;
    if (mem.curpos >= length) { mem.errpos = mem.curpos; goto done; }
    record_type = (uint8_t)data[mem.curpos++];
    if (record_type != 0x00) { stray_00_count = 0; }

    if (record_type == 0x2C) {
      // IMAGE DESCRIPTOR
      GIFV_LOG("enter image desc");
      uint64_t pre_imgdesc_pos = mem.curpos;
      uint16_t img_left, img_top, img_w, img_h;
      bool img_interlaced;
      if (frame_lcmap) { free(frame_lcmap); frame_lcmap = NULL; frame_lcmap_count = 0; }
      uint64_t img_data_pos = gif_parse_image_desc((const uint8_t *)data, length, mem.curpos,
          &img_left, &img_top, &img_w, &img_h, &img_interlaced,
          &frame_lcmap, &frame_lcmap_count);
      if (img_data_pos == 0) { mem.errpos = pre_imgdesc_pos; goto done; }
      mem.curpos = img_data_pos;

      // Record position before image data for byte offset calculation
      uint64_t image_data_start = mem.curpos;

      // Sub-block alignment detection: GIF image data uses sub-blocks with
      // 1-byte length prefix. Correct encoders use 255-byte sub-blocks, so
      // headers (0xFF) appear at predictable positions: base, base+256, etc.
      // Walk sub-blocks to find: (1) where full-size sub-blocks start (sb_base),
      // and (2) where full-size sub-blocks END (sb_limit) — after this point,
      // sub-blocks shrink and alignment checks are unreliable.
      {
        uint64_t sp = image_data_start + 1;  // skip LZW minimum code size byte
        outer_sb_base = UINT64_MAX;
        // Derive the full-size threshold from the encoder's observed maximum.
        uint8_t outer_max_sb = 0;
        {
          uint64_t probe = sp;
          int peek = 0;
          while (probe < length && peek < 64) {
            uint8_t sb_len = (uint8_t)data[probe];
            if (sb_len == 0) { break; }
            if (sb_len > outer_max_sb) { outer_max_sb = sb_len; }
            if (probe + 1 + sb_len > length) { break; }
            probe += 1 + sb_len;
            peek++;
          }
        }
        uint8_t outer_full_threshold = (outer_max_sb >= 64) ? (uint8_t)(outer_max_sb - 4) : 0;
        // Phase 1: find first full-size sub-block
        if (outer_full_threshold > 0) {
          while (sp < length) {
            uint8_t sb_len = (uint8_t)data[sp];
            if (sb_len == 0) {
              break;
            }
            if (sb_len >= outer_full_threshold) {
              outer_sb_base = sp;
              break;
            }
            if (sp + 1 + sb_len > length) { break; }
            sp += 1 + sb_len;
          }
        }
        // Phase 2: DON'T walk forward to find sub-block end — walking
        // into wrong blocks (OUTOFORDER) would falsely set sb_limit early.
        // Instead, sb_limit stays UINT64_MAX (unknown end). The boundary
        // check in done: will verify alignment at each boundary; wrong
        // blocks will fail the check regardless of where sub-blocks end.
      }
      // Save first frame's alignment (never overwritten)
      if (first_sb_base == UINT64_MAX && outer_sb_base < UINT64_MAX) {
        first_sb_base = outer_sb_base;
      }
      int img_width = (int)img_w;
      int img_height = (int)img_h;

      // SAFETY: reject insane dimensions
      if (img_width <= 0 || img_height <= 0 || img_width > 65535 || img_height > 65535) {
        mem.errpos = mem.curpos;
        goto done;
      }
      // Many valid GIFs place frame rectangles partially outside the logical
      // screen and rely on viewer clipping. Treat those as valid here rather
      // than hard-rejecting a new frame at its image descriptor.

      if (!gif_reserve_u8_buffer(&scanline, &scanline_capacity,
                                 (size_t)img_width)) {
        mem.errpos = mem.curpos;
        goto done;
      }

      // SAFETY: Cap at 65535 rows to prevent infinite loops on corrupt dimension data
      int max_rows = img_height;
      if (max_rows > 65535) {
        max_rows = 65535;
      }

      // wrong-block detection state
      uint64_t last_normal_pos = mem.curpos;
      uint64_t max_row_bytes = (uint64_t)img_width * 3;

      // Layer B: Statistical LZW consumption (per-frame — frame-local
      // compression ratio establishes the baseline; cross-frame accumulation
      // was tested and HURTS detection because different frames have
      // legitimately different compression ratios).
      double running_bpr_sum = 0.0;
      double running_bpr_sq = 0.0;
      uint32_t bpr_count = 0;
      if (max_row_bytes < 2048) {
        max_row_bytes = 2048;
      }

      // DETECTION 5: RGB MAD (Mean Absolute Difference) between consecutive rows.
      // When wrong data enters the LZW decoder, decoded pixels become random,
      // producing very high MAD values between adjacent rows. Ultra-conservative
      // thresholds ensure no false positives on correct data.
      //
      // Parameters: use a high adaptive multiplier and require a long streak
      // before triggering. Legitimate high-motion GIFs can sustain elevated
      // inter-row MAD for multiple rows; tail/overflow checks carry more of
      // the graft-detection load now.
      bool is_interlaced = img_interlaced;
      GIFColor *ActiveColorMap = frame_lcmap ? frame_lcmap : gif_hdr.global_cmap;
      int color_count = frame_lcmap ? frame_lcmap_count : gif_hdr.global_cmap_count;
      int rgb_sample_count = (img_width > 16) ? img_width / 4 : img_width;
      int bad_mad_streak = 0;
      double running_mad_sum = 0.0;
      int mad_count = 0;
      // Initialize from outer anchor — prevents starting in wrong data
      // when a new frame begins past wrong-block boundary.
      // For first frame (outer is 0), use mem.curpos (start of image data).
      uint64_t last_good_mad_pos = (outer_last_good_mad_pos > 0)
                                   ? outer_last_good_mad_pos : mem.curpos;
      bool mad_active = false;
      // True once prev_scanline holds the row before the one about to be
      // compared. Normally set at the end of every row; a snapshot resume
      // without a stored previous row leaves it false for one row, skipping
      // a MAD comparison over bytes the earlier call already validated.
      bool mad_prev_seeded = false;
      // The tail probe sets this after confirming EOI termination. For frames
      // without MAD evidence, this is the required integrity signal for
      // advancing reliable_pos past the frame.
      bool frame_saw_eoi = false;
      if (!is_interlaced && ActiveColorMap && color_count > 0
          && img_width >= 8) {
        if (gif_reserve_u8_buffer(&prev_scanline, &prev_scanline_capacity,
                                  (size_t)img_width)) {
          mad_active = true;
        }
      }

      // Initialize our LZW decoder for this frame (heap-allocated —
      // GIFLZWState is ~16KB, too large for stack with 96+ threads)
      if (!_frame_lzw) {
        _frame_lzw = (GIFLZWState *)malloc(sizeof(GIFLZWState));
        if (!_frame_lzw) {
          mem.errpos = mem.curpos;
          goto done;
        }
      }
      if (!gif_lzw_init(_frame_lzw, &mem)) {
        mem.errpos = mem.curpos;
        goto done;
      }

      // Restore the LZW decoder mid-frame from the qualified snapshot.
      // The descriptor, colormap, buffers, and alignment probe above were
      // rebuilt by the normal parse; only the decode position, decoder state,
      // and per-frame detector context come from the snapshot.
      int resume_row_start = 0;
      if (resume_snap && pre_record_pos == snap_src.snap_record_pos) {
        *_frame_lzw = snap_src.snap_lzw;
        mem.curpos = snap_src.snap_pos;
        resume_row_start = (int)snap_src.snap_next_row;
        if (resume_row_start > max_rows) {
          resume_row_start = max_rows;
        }
        last_normal_pos = snap_src.snap_last_normal_pos;
        last_good_mad_pos = snap_src.snap_last_good_mad_pos;
        bad_mad_streak = (int)snap_src.snap_bad_mad_streak;
        running_mad_sum = snap_src.snap_running_mad_sum;
        mad_count = (int)snap_src.snap_mad_count;
        running_bpr_sum = snap_src.snap_running_bpr_sum;
        running_bpr_sq = snap_src.snap_running_bpr_sq;
        bpr_count = snap_src.snap_bpr_count;
        if (mad_active && snap_src.snap_prev_row_present
            && snap_src.snap_prev_row_len == (uint32_t)img_width) {
          memcpy(prev_scanline, snap_src.snap_prev_row, (size_t)img_width);
          mad_prev_seeded = true;
        }
        if (scalpel_state.mode_verbose) {
          lock_fprintf(stdout,
              "GIF LZW resume: frame %u row %d pos %" PRIu64 " (seeded=%d)\n",
              snap_src.snap_frame_index, resume_row_start,
              snap_src.snap_pos, mad_prev_seeded ? 1 : 0);
        }
        resume_snap = false;
      }

      for (int row = resume_row_start; row < max_rows; row++) {
        uint64_t pos_before = mem.curpos;

        // Capture a pending resume snapshot at the first row that starts
        // in a new block. The decoder state is copied before the row decodes,
        // so the entry is exactly resumable at this row. done: persists the
        // newest entry whose position lies at or below the checkpoint.
        if (bs > 0 && pos_before / bs != snap_ring_last_block
            && !_frame_lzw->sb_truncated
            && (ImageNum == 0 || row > 0)
            && (! mad_active
                || row == 0
                || (mad_prev_seeded
                    && img_width <= GIF_SNAP_PREV_ROW_MAX))) {
          if (!snap_ring) {
            snap_ring = (GIFSnapPending *)calloc(GIF_SNAP_RING,
                                                 sizeof(GIFSnapPending));
          }
          if (snap_ring) {
            GIFSnapPending *pend = &snap_ring[snap_ring_head];
            pend->valid = true;
            pend->mad_active = mad_active;
            pend->next_row = (uint32_t)row;
            pend->frame_index = (uint32_t)ImageNum;
            pend->pos = pos_before;
            pend->record_pos = pre_record_pos;
            pend->last_good_mad_pos = last_good_mad_pos;
            pend->last_normal_pos = last_normal_pos;
            pend->running_mad_sum = running_mad_sum;
            pend->mad_count = (uint32_t)mad_count;
            pend->bad_mad_streak = (int32_t)bad_mad_streak;
            pend->running_bpr_sum = running_bpr_sum;
            pend->running_bpr_sq = running_bpr_sq;
            pend->bpr_count = bpr_count;
            pend->lzw = *_frame_lzw;
            pend->prev_row_present = false;
            pend->prev_row_len = 0;
            if (mad_active && mad_prev_seeded
                && img_width <= GIF_SNAP_PREV_ROW_MAX) {
              memcpy(pend->prev_row, prev_scanline, (size_t)img_width);
              pend->prev_row_len = (uint32_t)img_width;
              pend->prev_row_present = true;
            }
            snap_ring_head = (snap_ring_head + 1) % GIF_SNAP_RING;
            snap_ring_last_block = pos_before / bs;
          }
        }

        int64_t _lzw_rc = gif_lzw_decode_row(_frame_lzw, &mem,
            scanline, img_width);

        // After the LAST row: skip remaining sub-blocks through curpos
        // (matching libgif's behavior where DGifGetLine's last call
        // includes the sub-block skip, so bytes_consumed for the last
        // row includes these extra bytes).
        if (_lzw_rc >= 0 && !_frame_lzw->eof_reached
            && row == max_rows - 1) {
          uint64_t finish_tail_bytes = 0;
          uint32_t finish_nonclear_codes = 0;
          bool finish_saw_eoi = false;
          gif_finish_tail_probe(_frame_lzw, &mem,
                                &finish_tail_bytes,
                                &finish_nonclear_codes,
                                &finish_saw_eoi);
          if (finish_saw_eoi) {
            frame_saw_eoi = true;
          }
          // No-EOI tails should be tiny and inert. Once compressed data keeps
          // going without ever reaching EOI, we are almost certainly decoding
          // through grafted data from a later file.
          //
          // Some valid streams reach the sub-block terminator without an
          // explicit EOI and leave inert padding. Reject only when a large tail
          // also contains non-clear codes, or when either signal is extreme.
          if (!finish_saw_eoi &&
              ((finish_tail_bytes >= 2048 && finish_nonclear_codes > 0)
               || finish_tail_bytes >= 8192
               || finish_nonclear_codes >= 32)) {
            mem.errpos = mad_active ? last_good_mad_pos : last_normal_pos;
            goto done;
          }
          // Even when an eventual EOI exists, a nontrivial post-row tail is a
          // strong sign that we jumped into later compressed data. In sampled
          // ground-truth GIFs this tail stays tiny. Large tails are grafts.
          //
          // After EOI, require a large tail and additional codes together, or
          // an extreme value for either signal alone.
          if (finish_saw_eoi &&
              ((finish_tail_bytes >= 1024 && finish_nonclear_codes >= 4)
               || finish_tail_bytes >= 4096
               || finish_nonclear_codes >= 64)) {
            mem.errpos = mad_active ? last_good_mad_pos : last_normal_pos;
            goto done;
          }
          // Keep the broad absolute cap as a second line of defense for
          // obviously bad same-file grafts with very long tails.
          if (finish_tail_bytes >= 4096 ||
              (!finish_saw_eoi &&
               finish_tail_bytes >= 2048 &&
               finish_nonclear_codes >= 512) ||
              (finish_tail_bytes >= 1024 &&
               finish_nonclear_codes >= 768)) {
            mem.errpos = mad_active ? last_good_mad_pos : last_normal_pos;
            goto done;
          }
          // Discard buffered data
          _frame_lzw->sb_buf_pos = _frame_lzw->sb_buf_len;
          // Walk remaining sub-blocks
          while (mem.curpos < length) {
            uint8_t sb = (uint8_t)data[mem.curpos++];
            if (sb == 0) { break; }
            if (mem.curpos + sb > length) { mem.curpos = length; break; }
            mem.curpos += sb;
          }
        }

        if (_lzw_rc < 0 || _frame_lzw->eof_reached) {
          if (mem.curpos >= mem.length) {
            mem.errpos = mem.curpos;       // clean truncation
            if (mad_active && last_good_mad_pos > reliable_pos) {
              reliable_pos = last_good_mad_pos;
              if (last_good_mad_pos > outer_last_good_mad_pos) {
                outer_last_good_mad_pos = last_good_mad_pos;
              }
            }
            else if (!mad_active && last_normal_pos > reliable_pos) {
              reliable_pos = last_normal_pos;
            }
          } else {
            mem.errpos = pos_before;       // LZW corruption -- use pre-decode position
          }
          goto done;
        }

        uint64_t bytes_consumed = mem.curpos - pos_before;
        if (in_replay && replay_checkpoint_curpos > 0
            && mem.curpos >= replay_checkpoint_curpos) {
          in_replay = false;
        }

        // DETECTION 6: Cross-frame check at row 0 of each new frame,
        // BUT ONLY when this frame starts in a different block than the
        // previous frame ended (indicating a new block's data).
        // Two sub-checks:
        //   a) Dimension change: if the frame width changed across a block
        //      boundary, it's very likely cross-file data (same-file animations
        //      maintain consistent logical screen dimensions).
        //   b) RGB MAD: if dimensions match, check pixel content.
        if (row == 0 && bs > 0
            && prev_frame_end_pos > 0
            && (pos_before / bs) > (prev_frame_end_pos / bs)) {
          // Sub-check (a): dimension overflow — DISABLED.
          // GIF spec allows frame offset+dimension to exceed the logical
          // screen (viewers clip to screen bounds).  Many legitimate GIFs
          // use this for animation effects.
          // Sub-check (b): RGB MAD for same-width frames
          if (prev_frame_last_rgb && prev_frame_rgb_count > 0
              && ActiveColorMap && color_count > 0) {
            double xf_mad_sum = 0.0;
            int xf_samples = 0;
            int si = 0;
            for (int px = 0; px < img_width && si < prev_frame_rgb_count; px += 4) {
              uint8_t idx = scanline[px];
              if (idx < color_count) {
                int dr = abs((int)ActiveColorMap[idx].Red
                             - (int)prev_frame_last_rgb[si * 3 + 0]);
                int dg = abs((int)ActiveColorMap[idx].Green
                             - (int)prev_frame_last_rgb[si * 3 + 1]);
                int db = abs((int)ActiveColorMap[idx].Blue
                             - (int)prev_frame_last_rgb[si * 3 + 2]);
                xf_mad_sum += (double)(dr + dg + db);
                xf_samples++;
              }
              si++;
            }
            if (xf_samples > 4) {
              double xf_mad = xf_mad_sum / (double)xf_samples;
              // Local color tables can legitimately change the palette between
              // frames, so use a relaxed cross-frame threshold when either
              // frame has one.
              double xf_threshold =
                  (frame_lcmap || prev_frame_had_lcmap) ? 2000.0 : 700.0;
              if (xf_mad > xf_threshold) {
                mem.errpos = prev_frame_end_pos;
                goto done;
              }
            }
          }
        }

        // DETECTION 1: Statistical LZW consumption anomaly
        if (row > 10 && bpr_count >= 10) {
          double avg_bpr = running_bpr_sum / (double)bpr_count;
          double var = (running_bpr_sq / (double)bpr_count) - (avg_bpr * avg_bpr);
          double stddev = (var > 0.0) ? sqrt(var) : 0.0;
          double stat_threshold = avg_bpr + 4.0 * stddev;
          if (stat_threshold < (double)max_row_bytes) {
            stat_threshold = (double)max_row_bytes;
          }
          if ((double)bytes_consumed > stat_threshold) {
            if (mad_active) {
              mem.errpos = last_good_mad_pos;
            } else {
              mem.errpos = last_normal_pos;
            }
            goto done;
          }
        }
        else if (bytes_consumed > max_row_bytes
                 && row > 10) {
          uint64_t processed = last_normal_pos - image_data_start;
          uint64_t safety_margin = processed / 20;
          if (safety_margin < 1024) {
            safety_margin = 1024;
          }
          if (safety_margin > processed) {
            safety_margin = processed / 2;
          }
          mem.errpos = last_normal_pos - safety_margin;
          goto done;
        }

        // DETECTION 4: Enforce pre-decoded sub-block boundary cap.
        // If we've reached a boundary where sub-block alignment is broken,
        // the current block is wrong data — stop immediately.
        if (first_bad_sb_boundary < UINT64_MAX
            && mem.curpos >= first_bad_sb_boundary) {
          mem.errpos = first_bad_sb_boundary;
          goto done;
        }

        // DETECTION 5: RGB MAD gate. Compare decoded pixel RGB values between
        // consecutive rows. Wrong LZW data produces random palette indices that
        // map to random RGB values, creating very high inter-row MAD.
        if (mad_active && row > 0 && mad_prev_seeded) {
          double mad_sum = 0.0;
          int samples = 0;
          for (int px = 0; px < img_width && samples < rgb_sample_count; px += 4) {
            uint8_t idx_cur = scanline[px];
            uint8_t idx_prev = prev_scanline[px];
            if (idx_cur < color_count && idx_prev < color_count) {
              GIFColor *c1 = &ActiveColorMap[idx_cur];
              GIFColor *c2 = &ActiveColorMap[idx_prev];
              int dr = abs((int)c1->Red - (int)c2->Red);
              int dg = abs((int)c1->Green - (int)c2->Green);
              int db = abs((int)c1->Blue - (int)c2->Blue);
              mad_sum += (double)(dr + dg + db);
              samples++;
            }
          }
          if (samples > 0) {
            double row_mad = mad_sum / (double)samples;
            running_mad_sum += row_mad;
            mad_count++;

            // Adaptive threshold: use the running average as a baseline, with a
            // high floor to avoid false positives on high-contrast correct data.
            //
            // Use a generous adaptive threshold and require a sustained streak
            // so scene changes and short high-contrast bursts do not look like
            // wrong-block reassembly.
            double avg_mad = (mad_count > 0) ? running_mad_sum / (double)mad_count : 0.0;
            double threshold = avg_mad * 5.0;
            if (threshold < 300.0) {
              threshold = 300.0;
            }

            if (row_mad > threshold && row > 10) {
              bad_mad_streak++;
              if (bad_mad_streak >= 16
                  && row < max_rows - 8) {
                mem.errpos = last_good_mad_pos;
                goto done;
              }
            }
            else {
              if (bad_mad_streak > 0) {
                bad_mad_streak = 0;
              }
              // Only advance the anchor after several good rows in succession
              // (row > 0 check prevents advancing at the very start).
              if (row > 5) {
                last_good_mad_pos = pos_before;
                // Update outer anchor per-row so it's available in done:
                // even if the current frame never completes (e.g., first
                // frame spans many blocks but candidate is truncated).
                if (pos_before > outer_last_good_mad_pos) {
                  outer_last_good_mad_pos = pos_before;
                }
              }
            }
          }
        }

        // Save current scanline for next row's MAD comparison
        if (mad_active) {
          memcpy(prev_scanline, scanline, img_width * sizeof(uint8_t));
          mad_prev_seeded = true;
        }

        // Accumulate bytes-per-row statistics for Layer B.
        // Skip row 0 (no baseline yet) and the last row of each frame
        // (sub-block skip inflates bytes_consumed, skewing the stats).
        if (row > 0 && row < max_rows - 1) {
          running_bpr_sum += (double)bytes_consumed;
          running_bpr_sq += (double)bytes_consumed * (double)bytes_consumed;
          bpr_count++;
        }

        // Advance last_normal_pos using statistical threshold after warm-up
        if (bpr_count >= 10) {
          double avg_bpr = running_bpr_sum / (double)bpr_count;
          if ((double)bytes_consumed < avg_bpr * 2.0) {
            last_normal_pos = mem.curpos;
          }
        }
        else if (bytes_consumed < max_row_bytes / 2) {
          last_normal_pos = mem.curpos;
        }

      }

      // Save last row's RGB values for cross-frame MAD check.
      // When a wrong block from a DIFFERENT GIF file is appended, the next
      // frame will have a completely different palette, producing huge MAD
      // between the last row of this frame and the first row of the next.
      if (mad_active && ActiveColorMap && color_count > 0 && scanline) {
        int save_count = 0;
        for (int px = 0; px < img_width && save_count < rgb_sample_count; px += 4) {
          save_count++;
        }
        if (save_count > 0) {
          if (!prev_frame_last_rgb || save_count > prev_frame_rgb_count) {
            if (prev_frame_last_rgb) { free(prev_frame_last_rgb); }
            prev_frame_last_rgb = (uint8_t *)malloc(save_count * 3);
          }
          if (prev_frame_last_rgb) {
            int si = 0;
            for (int px = 0; px < img_width && si < save_count; px += 4) {
              uint8_t idx = scanline[px];
              if (idx < color_count) {
                prev_frame_last_rgb[si * 3 + 0] = ActiveColorMap[idx].Red;
                prev_frame_last_rgb[si * 3 + 1] = ActiveColorMap[idx].Green;
                prev_frame_last_rgb[si * 3 + 2] = ActiveColorMap[idx].Blue;
              }
              else {
                prev_frame_last_rgb[si * 3 + 0] = 0;
                prev_frame_last_rgb[si * 3 + 1] = 0;
                prev_frame_last_rgb[si * 3 + 2] = 0;
              }
              si++;
            }
            prev_frame_rgb_count = save_count;
          }
        }
      }
      // Always update frame tracking for DET6 — even when MAD is not
      // active (interlaced/small frames), DET6 needs the correct
      // predecessor frame for boundary and overflow checks.
      prev_frame_end_pos = mem.curpos;
      prev_frame_had_lcmap = (frame_lcmap != NULL);

      // Sub-block skip is now handled inside the row loop (after the
      // last row), matching libgif's DGifGetLine behavior.

      GIFV_LOG("image read ok");
      // Frame completed — use MAD-confirmed position as reliable anchor.
      // If MAD detection was active, use last_good_mad_pos which only
      // advances when rows pass RGB MAD check. This prevents reliable_pos
      // from advancing past undetected wrong data that the LZW decoder
      // tolerated.
      //
      // For frames without MAD evidence, advance reliable_pos only after a
      // clean EOI. Plausible consumption alone is not enough to establish that
      // the compressed stream terminated legitimately.
      if (mad_active && last_good_mad_pos > reliable_pos) {
        reliable_pos = last_good_mad_pos;
        outer_last_good_mad_pos = last_good_mad_pos;
      }
      else if (!mad_active
               && frame_saw_eoi
               && last_normal_pos > reliable_pos) {
        // Clean EOI + statistically normal consumption — advance.
        reliable_pos = last_normal_pos;
      }
      // else: no MAD AND no clean EOI — reliable_pos stays where it was
      // (conservative: the frame's bytes remain un-anchored for checkpoint
      // purposes). The candidate can still validate if a later frame
      // produces a proper anchor; but we refuse to pre-commit this one.
      if (first_frame_end == 0) {
        first_frame_end = mem.curpos;
      }
      ImageNum++;
      // State API: track which block the decoder reached when this frame completed.
      if (bs > 0 && reliable_pos > 0) {
        uint64_t cur_block = reliable_pos / bs;
        if (cur_block > lgp_boundary_block) {
          lgp_boundary_block = cur_block;
          frames_at_lgp_boundary = ImageNum;
        }
      }

    } else if (record_type == 0x21) {
      // EXTENSION
      uint64_t pre_ext_pos = mem.curpos;
      uint64_t ext_end = gif_skip_ext((const uint8_t *)data, length, mem.curpos);
      if (ext_end == 0) { mem.errpos = pre_ext_pos; goto done; }
      mem.curpos = ext_end;
      if (ext_end > reliable_pos) {
        reliable_pos = ext_end;
      }

    } else if (record_type == 0x3B) {
      // TRAILER
      GIFV_LOG("terminate");
      *validates = true;

    } else if (record_type == 0x00) {
      stray_00_count++;
      if (stray_00_count > 2) {
        mem.errpos = pre_record_pos;
        goto done;
      }
      continue; // stray terminator

    } else {
      mem.errpos = pre_record_pos;
      goto done;
    }
  } while (record_type != 0x3B);

done:
  if (prev_frame_last_rgb) { free(prev_frame_last_rgb); prev_frame_last_rgb = NULL; }
  // Centralized cleanup for scanline/LZW scratch buffers. These pointers may
  // already have been freed during frame processing and nulled out there.
  free(scanline);    scanline = NULL;
  free(prev_scanline); prev_scanline = NULL;
  free(_frame_lzw);  _frame_lzw = NULL;
  // snap_ring is freed after the state save below consumes it

  bs = scalpel_state.blocksize;

  // Save checkpoint state for state API using the last proven block-aligned
  // anchor.  Fragmented GIF candidates often fail mid-frame after decoding a
  // long correct prefix.  If the trusted prefix ends strictly before errpos,
  // preserve it so later validator calls can replay from that boundary
  // instead of re-decoding the entire prefix from scratch.
  if (direct_state || carvehashkey) {
    GIFCarveState existing = {0};
    uint64_t existing_ckpt = 0;

    if (direct_state) {
      existing = *direct_state;
    }
    else if (carvehashkey) {
      GIFCarveState *saved = (GIFCarveState *)carve_get_state(carvehashkey);
      if (saved) {
        existing = *saved;
        gif_free_carve_state((void **)&saved);
      }
    }

    if (existing.valid) {
      existing_ckpt = existing.checkpoint_curpos;
    }

    // Persist probe fields only after forward progress so a failed trial cannot
    // replace stronger evidence. The canonical state save below has its own
    // checkpoint-safety gate.
    if (reliable_pos > existing.probe_checkpoint_curpos
        || (ImageNum >= 0
            && (uint32_t)ImageNum > existing.probe_completed_frames)
        || outer_last_good_mad_pos > existing.probe_last_good_row_pos) {
      existing.probe_score_valid = true;
      existing.probe_completed_frames = ImageNum;
      existing.probe_checkpoint_curpos = reliable_pos;
      existing.probe_last_good_row_pos = outer_last_good_mad_pos;
      existing.probe_last_normal_pos = reliable_pos;
      if (existing.probe_last_good_row_pos < existing.probe_checkpoint_curpos) {
        existing.probe_last_good_row_pos = existing.probe_checkpoint_curpos;
      }
      if (existing.probe_last_normal_pos < existing.probe_checkpoint_curpos) {
        existing.probe_last_normal_pos = existing.probe_checkpoint_curpos;
      }
    }

    if (reliable_pos > 0 && bs > 0) {
      uint64_t ckpt_pos = (reliable_pos / bs) * bs;
      bool ckpt_safe = false;
      if (ckpt_pos >= bs && ckpt_pos > existing_ckpt) {
        if (mem.errpos <= 0 || mem.errpos >= (int64_t)length) {
          ckpt_safe = true;
        }
        else if ((uint64_t)mem.errpos > ckpt_pos) {
          ckpt_safe = true;
        }
      }
      if (ckpt_safe) {
        existing.valid = true;
        existing.checkpoint_curpos = ckpt_pos;
        // A valid replay state always carries the hash for its checkpoint
        // position.
        existing.prefix_hash = XXH3_64bits(data, ckpt_pos);
        existing.data_length = length;
        existing.completed_frames = frames_at_lgp_boundary;
        existing.first_frame_end = first_frame_end;
        existing.last_good_row_pos = outer_last_good_mad_pos;
        existing.last_normal_pos = reliable_pos;

        // Persist the newest pending resume snapshot at or below the
        // checkpoint position. When none qualifies, any stored
        // snapshot is kept; its own prefix hash still guards it.
        if (snap_ring) {
          GIFSnapPending *best = NULL;
          for (uint32_t si = 0; si < GIF_SNAP_RING; si++) {
            GIFSnapPending *pend = &snap_ring[si];
            if (pend->valid && pend->pos <= ckpt_pos
                && (!best || pend->pos > best->pos)) {
              best = pend;
            }
          }
          if (best) {
            existing.snap_valid = true;
            existing.snap_mad_active = best->mad_active;
            existing.snap_prev_row_present = best->prev_row_present;
            existing.snap_next_row = best->next_row;
            existing.snap_frame_index = best->frame_index;
            existing.snap_pos = best->pos;
            existing.snap_record_pos = best->record_pos;
            existing.snap_prefix_hash = XXH3_64bits(data, best->pos);
            existing.snap_last_good_mad_pos = best->last_good_mad_pos;
            existing.snap_last_normal_pos = best->last_normal_pos;
            existing.snap_running_mad_sum = best->running_mad_sum;
            existing.snap_mad_count = best->mad_count;
            existing.snap_bad_mad_streak = best->bad_mad_streak;
            existing.snap_running_bpr_sum = best->running_bpr_sum;
            existing.snap_running_bpr_sq = best->running_bpr_sq;
            existing.snap_bpr_count = best->bpr_count;
            existing.snap_prev_row_len = best->prev_row_len;
            existing.snap_lzw = best->lzw;
            memcpy(existing.snap_prev_row, best->prev_row,
                   sizeof(existing.snap_prev_row));
          }
        }
      }
    }

    if (direct_state) {
      *direct_state = existing;
    }
    else {
      carve_put_state(carvehashkey, &existing);
    }
  }
  free(snap_ring);
  snap_ring = NULL;

  if (*validates) {
    // File validated completely (found terminator) — curpos is trustworthy
    // UNLESS the pre-decode scan found wrong sub-block alignment, which means
    // a wrong block produced a coincidental GIF terminator.
    if (*validates_to == 0) {
      *validates_to = mem.curpos - 1;
      if (*validates_to > length - 1) {
        *validates_to = length - 1;
      }
    }
    while (*validates_to + 1 < length) {
      uint8_t t = (uint8_t)data[*validates_to + 1];
      if (t == '\r' || t == '\n') {
        (*validates_to)++;
      }
      else {
        break;
      }
    }
    // Apply fb cap even for "complete" validation — wrong blocks can produce
    // valid GIF terminators (0x3B) by coincidence.
    if (first_bad_sb_boundary < UINT64_MAX && *validates_to >= first_bad_sb_boundary) {
      uint64_t before = *validates_to;
      *validates_to = (first_bad_sb_boundary > 0) ? first_bad_sb_boundary - 1 : 0;
      *validates = false;
      (void)before;
    }
    // Also check MAD anchor gap — if curpos is more than a blocksize past the
    // last MAD-confirmed position, the data likely contains wrong blocks that
    // the LZW decoder tolerated (same-file blocks with identical alignment).
    if (*validates && bs > 0) {
      uint64_t v_anchor = 0;
      if (reliable_pos > 0) {
        v_anchor = reliable_pos;
      }
      else if (outer_last_good_mad_pos > 0) {
        v_anchor = outer_last_good_mad_pos;
      }
      if (v_anchor > 0 && *validates_to >= v_anchor + (uint64_t)bs * 4) {
        // Large gap between reliable anchor and trailer — trailer
        // might be coincidental in wrong data.  But use a generous
        // threshold (4 blocks) since legitimate multi-frame GIFs can
        // have frames where MAD is inactive (interlaced, no colormap).
        uint64_t before = *validates_to;
        uint64_t v_anchor_blk_end = ((v_anchor / bs) + 1) * bs - 1;
        *validates_to = (v_anchor_blk_end < *validates_to)
            ? v_anchor_blk_end : *validates_to;
        *validates = false;
        (void)before;
      }
    }
  }

  if (mem.errpos == (int64_t)length) {
      // Clean truncation — the decoder consumed all data without error.
      // Use the ROW-LEVEL reliable position (which advances per-row
      // when MAD confirms) rather than frame-level reliable_pos. This
      // prevents under-valuing correct truncated data when frames span
      // multiple blocks without completing. The frame-level reliable_pos
      // is still used for validates=true gap check (more suspicious case).
      uint64_t best_anchor = 0;
      if (reliable_pos > 0) {
        best_anchor = reliable_pos;
      }
      else if (outer_last_good_mad_pos > 0) {
        best_anchor = outer_last_good_mad_pos;
      }
      if (best_anchor > 0 && bs > 0 && mem.curpos >= best_anchor + (bs * 2)) {
        // Large gap — snap to end of block containing anchor.
        uint64_t best_anchor_blk_end = ((best_anchor / bs) + 1) * bs - 1;
        uint64_t cur_limit = mem.curpos > 0 ? mem.curpos - 1 : 0;
        *validates_to = (best_anchor_blk_end < cur_limit)
            ? best_anchor_blk_end : cur_limit;
      }
      else {
        *validates_to = mem.curpos > 0 ? mem.curpos - 1 : 0;
      }
  }
  else if (mem.errpos > 0) {
      // Mid-data error — errpos marks where the error was detected.
      // Block-boundary gap check: if the error is in a different block
      // than the MAD anchor, the block containing the error is suspect
      // (wrong block from another GIF file that the LZW decoder
      // partially tolerated before erroring). Cap at the anchor.
      uint64_t err_anchor = 0;
      if (reliable_pos > 0) {
        err_anchor = reliable_pos;
      }
      else if (outer_last_good_mad_pos > 0) {
        err_anchor = outer_last_good_mad_pos;
      }
      if (err_anchor > 0 && bs > 0) {
        uint64_t anchor_blk = err_anchor / bs;
        uint64_t err_blk = (uint64_t)mem.errpos / bs;
        if (err_blk > anchor_blk) {
          // Error is in a later block than anchor — snap to end of
          // anchor's block (the whole anchor block is valid).
          *validates_to = (anchor_blk + 1) * bs - 1;
        }
        else {
          *validates_to = mem.errpos - 1;
        }
      }
      else {
        *validates_to = mem.errpos - 1;
      }
  }

  // Pre-decode scan structural cap: two-level check.
  // Level 1: cap at fb (wrong data starts at or after this boundary).
  // Level 2: cap one block before fb if the block before fb has wrong data
  //          (same-file blocks pass alignment at their start but fail at the
  //          next boundary, so fb lands one block too late).
  if (first_bad_sb_boundary < UINT64_MAX) {
    // Level 1: direct cap at fb
    if (*validates_to >= first_bad_sb_boundary) {
      uint64_t before = *validates_to;
      *validates_to = (first_bad_sb_boundary > 0) ? first_bad_sb_boundary - 1 : 0;
      *validates = false;
      (void)before;
    }
    // Level 2: cap one block before fb — applies when MAD anchor is at or
    // before the start of the suspect block (same-file wrong-position blocks
    // pass alignment at their start but fail at the next boundary).
    if (bs > 0 && first_bad_sb_boundary >= bs) {
      uint64_t prev_block_start = first_bad_sb_boundary - bs;
      if (*validates_to >= prev_block_start &&
          reliable_pos > 0 && reliable_pos <= prev_block_start) {
        uint64_t before = *validates_to;
        *validates_to = (prev_block_start > 0) ? prev_block_start - 1 : 0;
        *validates = false;
        (void)before;
      }
    }
  }

  // Preserve the first filesystem block of an incomplete candidate so its
  // header prefix remains available for fragmented reassembly.
  if (! *validates && bs > 0 && length >= (uint64_t)bs
      && *validates_to < (uint64_t)bs - 1) {
    *validates_to = (uint64_t)bs - 1;
  }
  *promising = !*validates && *validates_to > 0;

  if (scalpel_state.mode_verbose) {
    lock_fprintf(stdout, "gif_file_validate() on %p: validates = %1d, validates_to = %" PRIu64 ", promising = %1d.\n", data,
                 (int)*validates, *validates_to, (int)*promising);
  }

  // A candidate restored through the committed frame checkpoint that cannot
  // advance beyond the already-proven replay prefix is a dead branch. An
  // intra-frame snapshot is only a decoder optimization and must not change
  // whether the same bytes remain promising.
  if (!*validates && *promising && restored_from_frame_checkpoint
      && replay_checkpoint_curpos > 0
      && *validates_to + 1 <= replay_checkpoint_curpos) {
    *promising = false;
  }

  // Likewise, once a resumed branch has crossed the saved replay checkpoint,
  // it should not lag more than one full block behind the current frontier.
  // Requiring proof in the newest appended block immediately is too strict:
  // some valid fragmented branches need one extension to cross the replay
  // checkpoint and a later extension to accumulate proof in the next block.
  // But letting them trail by multiple blocks causes stale branches to clone.
  if (!*validates && *promising && restored_from_frame_checkpoint
      && bs > 0 && length >= (uint64_t)bs * 2
      && *validates_to + 1 <= length - (uint64_t)bs * 2) {
    *promising = false;
  }

  if (gif_hdr.global_cmap) {
    free(gif_hdr.global_cmap);
  }
  if (frame_lcmap) {
    free(frame_lcmap);
  }
}

static inline void gif_file_validate(char *data, uint64_t length,
                                     bool *validates,
                                     uint64_t *validates_to,
                                     bool *promising,
                                     uint32_t needleidx,
                                     uint32_t blocksize,
                                     void *carvehashkey) {
  gif_validate_core(data, length, validates, validates_to, promising,
                    needleidx, blocksize, carvehashkey, NULL);
}


#endif
