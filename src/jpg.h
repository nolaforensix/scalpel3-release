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

// Forensic-grade JPEG validator for scalpel3 (c) 2021-2026 by Golden G. Richard III.
//
// GGRIII: This code is not yet optimized.
//
// OPUS47 fix set applied (2026-04-16):
//   J1  DC continuity check: removed dead if/else branch and the fallback
//       end-of-MCU current_block advance; dc_diff is now computed for all
//       dc_sym values so boundary crossings with dc_sym==0 don't silently
//       skip threshold enforcement.
//   J2  Adaptive DC threshold is now also applied mid-pass in
//       jpg_huffman_validate after a calibration window (first 128 MCUs),
//       so the full-validation path benefits too, not only the resume path.
//   J3  jpg_huffman_clean_validates_to signature cleaned: unused arguments
//       removed. Behavior (credit length-1 when Huffman is clean) unchanged.
//   J4  (REVERSED by J5 fix) The custom jpg_reassembly call graph is kept
//       and made live again. The original report called it dead because
//       scalpelconf.c had REASSEMBLYFUNC = NULL — but flipping that switch
//       is the correct architectural fix for J5, not deleting the code.
//   J5  JPG-specific logic that had been bolted into reassembly.c
//       (jpg_lr_try_sorted_suffix_full_validation, jpg_lr_clamp_cold_frontier,
//       cold-state-probe-on-tie inside LR_reassembly_did_not_validate) is
//       migrated into this file as jpg_reassembly_try_sorted_suffix_full_
//       validation, jpg_reassembly_clamp_cold_frontier, and the
//       cold-state-probe block inside jpg_reassembly_did_not_validate. A
//       custom REASSEMBLYFUNC is wired up via scalpelconf.c.opus47. The
//       JPG hooks still present in reassembly.c are guarded by
//       jpg_lr_candidate() and now never fire for JPG (they're dormant
//       until a core-engine cleanup removes them).
//   J6  MPF "all-padding" and "non-padding tail" cases both set validates=
//       true now, fixing the swap that left complete MPFs in the promising
//       queue indefinitely.
//   J8  Full-validation path prescreen: a cheap 64KB SOS sniff enables the
//       entropy-specific invalid-byte-stuffing rule that previously never
//       fired on first-pass data.
//   J9  local_state is stack-allocated instead of calloc'd per call.
//
// ARCHITECTURAL: JPG now uses its own custom reassembly function
// (scalpelconf.c.opus47 sets .REASSEMBLYFUNC = jpg_reassembly). The hooks
// in reassembly.c (jpg_lr_candidate, jpg_lr_try_sorted_suffix_full_validation,
// jpg_lr_clamp_cold_frontier, and the jpg-specific probe in
// LR_reassembly_did_not_validate) along with candidate_disable_reservations
// in carve.c:110 are no longer exercised for JPG candidates. They can be
// removed in a follow-up core-engine cleanup, but leaving them in place
// is harmless: jpg_lr_candidate() returns false for a JPG candidate that
// entered its own custom path, and reservations for JPG are now controlled
// by the custom function itself.
//

#if ! defined(SCALPEL_JPG_H)
#define SCALPEL_JPG_H
#include "scalpel.h"
#include <float.h>
#include <fcntl.h>
#include <jpeglib.h>
#include <jerror.h>
#include <setjmp.h>
#include <unistd.h>

// uncomment to enable main() function for standalone testing #define JPEG_TEST #define
// JPEG_TEST_BLOCKSIZE 512

// ============================================================================
// JPEG Marker Definitions
// ============================================================================

#define M_SOI 0xD8
#define M_EOI 0xD9
#define M_SOF0 0xC0
#define M_SOF1 0xC1
#define M_SOF2 0xC2
#define M_SOF3 0xC3
#define M_SOF5 0xC5
#define M_SOF6 0xC6
#define M_SOF7 0xC7
#define M_SOF9 0xC9
#define M_SOF10 0xCA
#define M_SOF11 0xCB
#define M_SOF13 0xCD
#define M_SOF14 0xCE
#define M_SOF15 0xCF
#define M_DHT 0xC4
#define M_DAC 0xCC
#define M_DRI 0xDD
#define M_RST0 0xD0
#define M_RST7 0xD7
#define M_DQT 0xDB
#define M_SOS 0xDA
#define M_DNL 0xDC
#define M_DHP 0xDE
#define M_EXP 0xDF
#define M_APP0 0xE0
#define M_APP1 0xE1
#define M_APP2 0xE2
#define M_APP14 0xEE
#define M_COM 0xFE
#define M_TEM 0x01

// ============================================================================
// Validation State and Configuration
// ============================================================================

#define JPG_MAX_COMPONENTS 4
#define JPG_MAX_HUFFMAN_TABLES 4
#define JPG_MAX_QUANT_TABLES 4
// note: JPEG SOF stores dimensions as 16-bit, so max is inherently 65535 These constants exist for
// documentation; the uint16_t type enforces the limit
#define JPG_MAX_SAMPLING 4
#define JPG_MAX_CODE_LENGTH 16
#define JPG_MAX_HUFFMAN_CODES 256
#define JPG_HUFFMAN_PROFILE_CHECKPOINT_QUANTUM 16u

typedef enum {
  JPG_VAL_OK = 0,
  JPG_VAL_TRUNCATED,
  JPG_VAL_INVALID_MARKER,
  JPG_VAL_INVALID_LENGTH,
  JPG_VAL_INVALID_HUFFMAN,
  JPG_VAL_INVALID_QUANT,
  JPG_VAL_INVALID_SOF,
  JPG_VAL_INVALID_SOS,
  JPG_VAL_INVALID_ENTROPY,
  JPG_VAL_INVALID_STRUCTURE,
  JPG_VAL_CORRUPT_DATA
} JpgValidationResult;

typedef struct {
  bool defined;
  uint8_t bits[17];
  uint8_t huffval[256];
  uint32_t total_codes;
  int32_t maxcode[17];
  int32_t valptr[17];
  uint16_t code[256];
  uint8_t size[256];
} JpgHuffmanTable;

typedef struct {
  uint8_t id;
  uint8_t h_samp;
  uint8_t v_samp;
  uint8_t quant_tbl;
} JpgComponent;

typedef struct {
  uint8_t comp_idx;
  uint8_t dc_tbl;
  uint8_t ac_tbl;
} JpgScanComponent;

typedef struct {
  const uint8_t *data;
  uint64_t length;
  uint64_t pos;
  uint64_t last_good_pos;
  uint64_t error_pos;
  JpgValidationResult result;
  bool have_sof;
  uint8_t precision;
  uint16_t height;
  uint16_t width;
  uint8_t num_components;
  JpgComponent components[JPG_MAX_COMPONENTS];
  uint8_t max_h_samp;
  uint8_t max_v_samp;
  JpgHuffmanTable dc_tables[JPG_MAX_HUFFMAN_TABLES];
  JpgHuffmanTable ac_tables[JPG_MAX_HUFFMAN_TABLES];
  bool quant_defined[JPG_MAX_QUANT_TABLES];
  uint16_t quant_tables[JPG_MAX_QUANT_TABLES][64];
  uint8_t quant_precision[JPG_MAX_QUANT_TABLES];
  uint16_t restart_interval;
  bool in_scan;
  uint8_t scan_components;
  JpgScanComponent scan_comp[JPG_MAX_COMPONENTS];
  uint8_t ss, se;
  uint8_t ah, al;
  uint64_t entropy_bytes;
  uint32_t restart_count;
  bool rst_seq_broken;
  uint64_t rst_seq_error_pos;
  bool is_progressive;
  uint8_t scan_count;
  bool had_scan;
  uint64_t entropy_start;
  uint64_t scan_start;
  uint64_t scan_entropy_start;
  bool has_mpf;
  uint64_t mpf_primary_size;
  uint64_t mpf_compound_end;
} JpgValidationContext;

// ============================================================================
// Carve State: Huffman Bitstream Checkpoint
// ============================================================================

typedef struct JPGHuffmanCheckpoint {
  bool valid;
  uint64_t byte_pos;
  uint8_t bit_pos;
  uint8_t current_byte;
  uint32_t mcu_count;
  uint32_t mcus_since_restart;
  uint8_t expected_rst;
  int32_t dc_predictors[JPG_MAX_COMPONENTS];
  uint64_t current_block;
  uint64_t dc_abs_sum;
  uint64_t dc_samples;
  uint64_t ac_abs_sum;
  uint64_t ac_samples;
} JPGHuffmanCheckpoint;

typedef struct JPGHuffmanBlockProfile {
  uint32_t *mcu_at_boundary;
  uint64_t boundary_count;
} JPGHuffmanBlockProfile;

enum {
  JPG_RUN_ORDER_GROUP_BATCH = 64,
  JPG_RUN_ORDER_PRIMARY_GROUPS = 16,
  JPG_RUN_ORDER_PHASE_SCAN = 1,
  JPG_RUN_ORDER_PHASE_EXTERNAL_INSERT = 2,
  JPG_RUN_ORDER_PHASE_INTERNAL_TRANSPOSE = 3,
  JPG_RUN_ORDER_PHASE_EXHAUSTED = 4,
  JPG_RUN_ORDER_KIND_NONE = 0,
  JPG_RUN_ORDER_KIND_EXTERNAL_INSERT = 1,
  JPG_RUN_ORDER_KIND_INTERNAL_TRANSPOSE = 2
};

enum {
  JPG_HIDDEN_BOUNDARY_CHOICES = 32,
  JPG_HIDDEN_BOUNDARY_SCAN_BATCH = 256,
  JPG_FOOTER_TAIL_LOCAL_STARTS = 32
};

#define JPG_RUN_ORDER_STRONG_JOIN_SCORE 4.0
#define JPG_RUN_ORDER_HIDDEN_BOUNDARY_SCORE 2.0
#define JPG_FOREIGN_TAIL_RATE_WINDOW_BYTES 8192
#define JPG_FOREIGN_TAIL_MIN_RATE_RATIO 1.25
#define JPG_FOREIGN_TAIL_MIN_SEAM_SCORE 1.10

typedef struct JPGRunOrderBoundary {
  uint64_t first_block;
  uint64_t last_block;
  uint32_t boundary_row;
  double seam_mad;
  double baseline_mad;
  double normalized;
} JPGRunOrderBoundary;

typedef struct JPGRunOrderProgress {
  bool active;
  bool page_after_valid;
  bool scan_group_active;
  bool transpose_trial_initialized;
  bool fallback_rollback_valid;
  uint8_t phase;
  uint64_t signature;
  uint64_t source_length;
  uint64_t source_blocks;
  int64_t first_apparent;
  int64_t last_apparent;
  double page_after_normalized;
  uint64_t page_after_first_block;
  uint64_t scan_next_block;
  JPGRunOrderBoundary scan_group;
  uint32_t group_count;
  JPGRunOrderBoundary groups[JPG_RUN_ORDER_GROUP_BATCH];
  uint32_t external_group;
  uint64_t external_cut_next;
  uint64_t external_blocks_next;
  uint32_t transpose_i;
  uint32_t transpose_j;
  uint32_t transpose_k;
  bool transpose_probe_mode;
  bool transpose_refine_mode;
  uint64_t transpose_cut_a;
  uint64_t transpose_cut_b;
  uint64_t transpose_cut_c;
  uint64_t fallback_rollback_block;
  double fallback_rollback_rate_ratio;
  bool best_valid;
  uint8_t best_kind;
  uint32_t complete_hypotheses;
  double best_max_join_score;
  double best_total_join_score;
  uint64_t best_cut_a;
  uint64_t best_cut_b;
  uint64_t best_cut_c;
  uint64_t best_external_blocks;
  uint32_t best_group_i;
  uint32_t best_group_j;
  uint32_t best_group_k;
} JPGRunOrderProgress;

typedef struct JPGHiddenBoundaryChoice {
  int64_t actual_block;
  double score;
} JPGHiddenBoundaryChoice;

typedef struct JPGHiddenBoundaryProgress {
  bool active;
  bool baseline_scan_initialized;
  bool scan_complete;
  bool scan_wrapped;
  bool choices_ready;
  bool previous_compatible;
  bool rejected_successor_checked;
  bool natural_scan_active;
  bool natural_scan_complete;
  bool natural_tail_search_initialized;
  bool natural_probe_complete;
  uint64_t origin_blocks;
  uint64_t origin_length;
  uint64_t trials;
  uint32_t scan_batch_positions;
  // Physical positions survive changes to the apparent view at checkpoints.
  int64_t next_actual;
  int64_t scan_wrap_actual;
  int64_t natural_start_actual;
  int64_t natural_limit_actual;
  int64_t natural_next_actual;
  uint64_t natural_available;
  uint64_t natural_trial_next;
  uint32_t choice_count;
  uint32_t next_choice;
  JPGHiddenBoundaryChoice choices[JPG_HIDDEN_BOUNDARY_CHOICES];
} JPGHiddenBoundaryProgress;

// Tail trials belong to a particular prefix. Physical positions remain stable
// when recovered blocks are removed from the apparent address space.
typedef struct JPGFooterTailProgress {
  bool active;
  bool complete;
  bool interval_active;
  bool local_complete;
  uint64_t source_blocks;
  uint64_t source_length;
  uint64_t source_signature;
  int64_t floor_actual;
  int64_t footer_actual;
  int64_t reverse_next_actual;
  int64_t local_next_actual;
  int64_t local_limit_actual;
  uint64_t probes;
  uint64_t full_trials;
} JPGFooterTailProgress;

typedef struct {
  bool valid;
  JDIMENSION boundary_row;
  double seam_mad;
  double baseline_mad;
  double normalized;
} JpgBoundaryScore;

// Search decisions persist independently of the decoder cache. Once a saved
// choice is selected, decoding can resume from the original prefix checkpoint.
typedef struct JPGForwardScanChoice {
  bool found;
  bool validates;
  bool has_followon_support;
  bool restart_not_due;
  bool have_boundary;
  bool reaches_trial_end;
  bool near_trial_end;
  bool is_immediate;
  int64_t actual;
  uint64_t commit_validates_to;
  uint64_t direct_validates_to;
  uint64_t score_validates_to;
  JpgBoundaryScore boundary;
} JPGForwardScanChoice;

typedef struct JPGForwardScanProgress {
  bool active;
  bool pass_complete;
  bool baseline_seed_prepared;
  bool progressive_seed_prepared;
  bool baseline_seed_needs_search;
  bool contiguous_tail_probed;
  bool backward_choice_found;
  uint32_t scan_mode;
  uint32_t scan_pass;
  uint64_t source_blocks;
  uint64_t source_length;
  uint64_t source_signature;
  uint64_t view_blocks;
  uint64_t view_signature;
  int64_t next_actual;
  int64_t natural_tail_actual;
  JPGForwardScanChoice best;
  JPGForwardScanChoice before_backward;
} JPGForwardScanProgress;

static inline int64_t jpg_reassembly_apparent_lower_bound(int64_t actual);
static inline uint64_t jpg_forward_source_signature(CarveInfo *candidate,
                                                     uint64_t blocks);
static inline uint64_t jpg_forward_view_signature(void);
static inline bool jpg_forward_source_matches(
    CarveInfo *candidate, const JPGForwardScanProgress *progress,
    uint64_t blocks, uint64_t length);
static inline bool jpg_forward_progress_matches(
    CarveInfo *candidate, const JPGForwardScanProgress *progress,
    uint64_t blocks, uint64_t length, uint32_t scan_mode);

// ============================================================================
// Carve State: Full State for Checkpoint/Restore
// ============================================================================

typedef struct JPGCarveState {
  bool valid;
  uint64_t prefix_hash;           // XXH3 of data[0..checkpoint_pos)
  uint64_t checkpoint_pos;        // block-aligned position where we checkpointed
  uint64_t prev_validates_to;     // validates_to at checkpoint time
  uint64_t prev_length;           // data length at checkpoint time
  bool prev_validates;            // whether it fully validated at checkpoint time
  int32_t max_observed_dc_diff;   // cumulative max |dc_diff| from trusted prefix
  uint32_t fixed_prefix_blocks;   // initial promising prefix that reassembly must not rewrite
  bool reassembly_seed_checked;
  bool reassembly_seed_needs_search;
  bool hidden_boundary_recovery;
  uint32_t hidden_boundary_runs_committed;
  bool hidden_rejected_range_valid;
  int64_t hidden_rejected_first_actual;
  int64_t hidden_rejected_last_actual;

  // Cached header parse results (skip structural validation on restore)
  bool have_sof;
  bool is_progressive;
  uint8_t precision;
  uint16_t height;
  uint16_t width;
  uint8_t num_components;
  JpgComponent components[JPG_MAX_COMPONENTS];
  uint8_t max_h_samp;
  uint8_t max_v_samp;
  JpgHuffmanTable dc_tables[JPG_MAX_HUFFMAN_TABLES];
  JpgHuffmanTable ac_tables[JPG_MAX_HUFFMAN_TABLES];
  bool quant_defined[JPG_MAX_QUANT_TABLES];
  uint16_t restart_interval;
  uint64_t entropy_start;
  uint8_t scan_components;
  JpgScanComponent scan_comp[JPG_MAX_COMPONENTS];
  uint8_t ss;
  uint8_t se;
  uint8_t ah;
  uint8_t al;
  bool had_scan;
  uint8_t scan_count;

  // Huffman bitstream checkpoint at last block boundary
  JPGHuffmanCheckpoint huff_checkpoint;

  // Resumable search for complete EOI-bearing candidates whose physical run
  // order does not decode. Visual seams rank hypotheses; full validation is
  // still required before any mapping is accepted.
  JPGRunOrderProgress run_order_progress;

  // A hidden corruption boundary can leave a long, clean JPEG prefix whose
  // next fragment begins anywhere in the image. Preserve the bounded search
  // cursor and its strongest alternatives so checkpoints do not restart it.
  JPGHiddenBoundaryProgress hidden_boundary_progress;

  JPGFooterTailProgress footer_tail_progress;
  JPGForwardScanProgress forward_scan_progress;

} JPGCarveState;

typedef struct JpgSavedRetrySearch JpgSavedRetrySearch;
typedef struct JpgReassemblyRetrySearch JpgReassemblyRetrySearch;
typedef struct JpgSavedRetryFrame JpgSavedRetryFrame;
typedef struct JpgOOOBridgeChoice JpgOOOBridgeChoice;

// Decoder snapshots stay cheap to copy; the stored state owns retry history.
typedef struct {
  JPGCarveState decoder;
  JpgSavedRetrySearch *retry;
} JPGStoredCarveState;

static _Thread_local JpgReassemblyRetrySearch *jpg_active_retry_search;
static _Thread_local void *jpg_active_retry_key;

static inline bool jpg_serialize_carve_state(void **state, FILE *fp,
                                             StateSerialization mode);
static inline void *jpg_clone_carve_state(const void *state);
static inline void jpg_free_carve_state(void **state);
static inline size_t jpg_sizeof_carve_state(const void *state);
static inline void jpg_retry_storage_free(JpgSavedRetrySearch **storage);
static inline JpgSavedRetrySearch *
jpg_retry_storage_clone(const JpgSavedRetrySearch *source);
static inline bool jpg_retry_actual_available(int64_t actual);
static inline bool jpg_retry_range_signature(int64_t start, uint64_t count,
                                             uint64_t *signature);
static inline bool jpg_retry_save_choice(JpgOOOBridgeChoice *choice,
                                         uint64_t signature[2]);
static inline bool jpg_retry_load_choice(JpgOOOBridgeChoice *choice,
                                         const uint64_t signature[2]);
static inline JpgSavedRetrySearch *
jpg_retry_store(const JpgReassemblyRetrySearch *search);
static inline void jpg_retry_load(const JpgSavedRetrySearch *saved,
                                  JpgReassemblyRetrySearch *search);
static inline bool jpg_retry_transfer(FILE *fp, void *value, size_t size,
                                      StateSerialization mode);
static inline bool jpg_retry_frame_valid(const JpgSavedRetryFrame *saved);
static inline JPGCarveState *jpg_get_decoder_state(void *key);
static inline void jpg_put_decoder_state(void *key,
                                         const JPGCarveState *decoder);
static inline void jpg_save_retry_checkpoint(CarveInfo *candidate);
static inline void jpg_load_retry_checkpoint(CarveInfo *candidate,
                                             JpgReassemblyRetrySearch *search);

static inline void jpg_reassembly_finish_mapped_tail(CarveInfo *candidate,
                                                     bool *validates,
                                                     uint64_t *validates_to);
static inline void jpg_reassembly_publish_exit_prefix(
    CarveInfo *candidate, uint64_t validates_to);

static inline bool jpg_tail_is_padding_only(const char *data,
                                            uint64_t start,
                                            uint64_t length) {
  for (uint64_t pos = start; pos < length; pos++) {
    uint8_t b = (uint8_t)data[pos];
    if (b != 0x00 && b != 0xFF) {
      return false;
    }
  }
  return true;
}

static inline bool jpg_validates_to_real_eoi(const char *data,
                                             uint64_t length,
                                             uint64_t validates_to) {
  if (length < 2 || validates_to >= length) {
    return false;
  }
  if (validates_to > 0
      && (uint8_t)data[validates_to - 1] == 0xFF
      && (uint8_t)data[validates_to] == M_EOI) {
    return true;
  }
  if (validates_to + 1 < length
      && (uint8_t)data[validates_to] == 0xFF
      && (uint8_t)data[validates_to + 1] == M_EOI) {
    return true;
  }
  return false;
}

static inline bool jpg_range_may_contain_eoi(const char *data,
                                             uint64_t start,
                                             uint64_t length) {
  if (!data || length < 2 || start >= length) {
    return false;
  }
  if (start > 0) {
    start--;
  }
  for (uint64_t pos = start; pos + 1 < length; pos++) {
    if ((uint8_t)data[pos] == 0xFF
        && (uint8_t)data[pos + 1] == M_EOI) {
      return true;
    }
  }
  return false;
}

static inline uint64_t jpg_find_first_nonpadding(const char *data,
                                                 uint64_t start,
                                                 uint64_t length) {
  for (uint64_t pos = start; pos < length; pos++) {
    uint8_t b = (uint8_t)data[pos];
    if (b != 0x00 && b != 0xFF) {
      return pos;
    }
  }
  return length;
}

// ============================================================================
// Carve State API Functions
// ============================================================================

// Decoder trials stay pointer-free; retry ownership belongs to the stored state.
static inline JPGCarveState *jpg_get_decoder_state(void *key) {
  void *stored = carve_get_state(key);
  if (!stored) {
    return NULL;
  }
  JPGStoredCarveState *value = stored;
  jpg_retry_storage_free(&value->retry);
  // The first member has the allocation's address and is freed by the caller.
  return &value->decoder;
}

// Preserve saved alternatives unless the active search already owns them.
static inline void jpg_put_decoder_state(void *key, const JPGCarveState *decoder) {
  JPGStoredCarveState value = {.decoder = *decoder};
  void *saved = NULL;
  if (key != jpg_active_retry_key || !jpg_active_retry_search) {
    saved = carve_get_state(key);
    if (saved) {
      value.retry = ((JPGStoredCarveState *)saved)->retry;
    }
  }
  carve_put_state(key, &value);
  jpg_free_carve_state(&saved);
}

// jpg_print_carve_state — display state for debugging.
static inline void jpg_print_carve_state(const void *state) {
  const JPGCarveState *s = (const JPGCarveState *)state;
  if (!s) {
    fprintf(stdout, "NULL\n");
  }
  else {
    fprintf(stdout, "valid=%d ckpt=%" PRIu64 " vt=%" PRIu64 " len=%" PRIu64 " huff_mcu=%u",
            s->valid, s->checkpoint_pos, s->prev_validates_to, s->prev_length,
            s->huff_checkpoint.valid ? s->huff_checkpoint.mcu_count : 0);
    fprintf(stdout, " dc_max=%" PRId32 " prefix_blocks=%" PRIu32,
            s->max_observed_dc_diff, s->fixed_prefix_blocks);
  }
}

static inline bool jpg_reassembly_debug_candidate(CarveInfo *candidate) {
  static int initialized = 0;
  static int64_t debug_startblock = -1;
  char *env;

  if (!initialized) {
    env = getenv("SCALPEL_JPG_DEBUG_STARTBLOCK");
    if (env && *env) {
      debug_startblock = strtoll(env, NULL, 10);
    }
    initialized = 1;
  }

  if (!candidate || debug_startblock < 0 || !candidate->b
      || blockvector_get_num_blocks(candidate->b) == 0) {
    return false;
  }

  return blockvector_get_actual_blocknumber(candidate->b, 0) == debug_startblock;
}

static inline void jpg_reassembly_debug_dump(const char *tag,
                                             CarveInfo *candidate,
                                             int64_t block_choice,
                                             uint64_t validates_to) {
  if (!jpg_reassembly_debug_candidate(candidate)) {
    return;
  }

  lock_fprintf(stderr,
               "[jpgdbg] %s blocks=%" PRIu64 " data=%" PRIu64
               " new=%" PRId64 " best=%" PRIu64 " start=%" PRId64
               " choice=%" PRId64 " vt=%" PRIu64 " pairs=",
               tag,
               blockvector_get_num_blocks(candidate->b),
               blockvector_get_data_length(candidate->b),
               candidate->newblock,
               candidate->best_validates_to,
               candidate->block_choice_start,
               block_choice,
               validates_to);

  for (uint64_t i = 0; i < blockvector_get_num_blocks(candidate->b); i++) {
    lock_fprintf(stderr, "%" PRId64 "->%" PRId64 "%s",
                 blockvector_get_apparent_blocknumber(candidate->b, i),
                 blockvector_get_actual_blocknumber(candidate->b, i),
                 i + 1 == blockvector_get_num_blocks(candidate->b) ? "" : ",");
  }
  lock_fprintf(stderr, "\n");
}

static inline bool jpg_validate_debug_enabled(void) {
  static int initialized = 0;
  static int enabled = 0;
  char *env;

  if (!initialized) {
    env = getenv("SCALPEL_JPG_VALIDATE_DEBUG");
    enabled = (env && *env && strcmp(env, "0") != 0);
    initialized = 1;
  }

  return enabled;
}

static inline uint32_t jpg_reassembly_scan_mode(void) {
  static int initialized = 0;
  static uint32_t mode = 0;
  char *env;

  if (!initialized) {
    env = getenv("SCALPEL_JPG_REASSEMBLY_SCAN");
    if (env && strcmp(env, "bounded") == 0) {
      mode = 0;
    } else if (env && strcmp(env, "wide") == 0) {
      mode = 1;
    } else if (env && strcmp(env, "confidence") == 0) {
      mode = 2;
    } else if (env && strcmp(env, "anchor") == 0) {
      mode = 3;
    } else {
      env = getenv("SCALPEL_JPG_CONFIDENCE_ORDER");
      mode = (!env || !*env || strcmp(env, "0") != 0) ? 2 : 0;
    }
    initialized = 1;
  }

  return mode;
}

// ============================================================================
// Utility Functions
// ============================================================================

static inline uint16_t jpg_read_u16(const uint8_t *p) { return ((uint16_t)p[0] << 8) | p[1]; }

static inline bool jpg_has_bytes(JpgValidationContext *ctx, uint64_t n) { return (ctx->pos + n <= ctx->length); }

static inline uint8_t jpg_read_byte(JpgValidationContext *ctx) { return ctx->data[ctx->pos++]; }

static inline bool jpg_is_valid_marker(uint8_t marker) {
  if (marker == 0x00 || marker == 0xFF) {
    return false;
  }
  return true;
}


static inline bool jpg_is_sof_marker(uint8_t marker) {
  return (marker >= M_SOF0 && marker <= M_SOF3) || (marker >= M_SOF5 && marker <= M_SOF7) || (marker >= M_SOF9 && marker <= M_SOF11)
         || (marker >= M_SOF13 && marker <= M_SOF15);
}


static inline bool jpg_is_standalone_marker(uint8_t marker) {
  return marker == M_SOI || marker == M_EOI || marker == M_TEM || (marker >= M_RST0 && marker <= M_RST7);
}


// ============================================================================
// Parsing Helpers
// ============================================================================

static inline bool jpg_validate_huffman_table(JpgHuffmanTable *table) {
  uint32_t code = 0;
  uint32_t total_symbols = 0;
  int si = 0;

  for (int length = 1; length <= 16; length++) {
    uint8_t count = table->bits[length];
    total_symbols += count;
    for (int i = 0; i < count; i++) {
      if (code >= (1u << length)) {
        return false;
      }
      if (si < 256) {
        table->code[si] = (uint16_t)code;
        table->size[si] = (uint8_t)length;
        si++;
      }
      code++;
    }
    if (length < 16) {
      code <<= 1;
    }
  }
  if (code > (1u << 16)) {
    return false;
  }
  if (total_symbols == 0 || total_symbols > 256) {
    return false;
  }
  table->total_codes = total_symbols;

  si = 0;
  for (int length = 1; length <= 16; length++) {
    if (table->bits[length] == 0) {
      table->maxcode[length] = -1;
    }
    else {
      table->valptr[length] = si;
      si += table->bits[length];
      table->maxcode[length] = table->code[si - 1];
    }
  }
  return true;
}


static inline JpgValidationResult jpg_parse_dht(JpgValidationContext *ctx, uint16_t length) {
  uint64_t end_pos = ctx->pos + length - 2;
  while (ctx->pos < end_pos) {
    if (! jpg_has_bytes(ctx, 17)) {
      return JPG_VAL_TRUNCATED;
    }
    uint8_t info = jpg_read_byte(ctx);
    uint8_t tc = (info >> 4) & 0x0F;
    uint8_t th = info & 0x0F;
    if (tc > 1 || th >= JPG_MAX_HUFFMAN_TABLES) {
      ctx->error_pos = ctx->pos - 1;
      return JPG_VAL_INVALID_HUFFMAN;
    }
    JpgHuffmanTable *table = (tc == 0) ? &ctx->dc_tables[th] : &ctx->ac_tables[th];
    table->bits[0] = 0;
    uint32_t total = 0;
    for (int i = 1; i <= 16; i++) {
      table->bits[i] = jpg_read_byte(ctx);
      total += table->bits[i];
    }
    if (total > 256 || total == 0) {
      ctx->error_pos = ctx->pos;
      return JPG_VAL_INVALID_HUFFMAN;
    }
    if (! jpg_has_bytes(ctx, total)) {
      return JPG_VAL_TRUNCATED;
    }
    if (ctx->pos + total > end_pos) {
      ctx->error_pos = ctx->pos;
      return JPG_VAL_INVALID_LENGTH;
    }
    for (uint32_t i = 0; i < total; i++) {
      table->huffval[i] = jpg_read_byte(ctx);
    }
    if (! jpg_validate_huffman_table(table)) {
      ctx->error_pos = ctx->pos;
      return JPG_VAL_INVALID_HUFFMAN;
    }
    table->defined = true;
  }
  return JPG_VAL_OK;
}


static inline JpgValidationResult jpg_parse_dqt(JpgValidationContext *ctx, uint16_t length) {

  uint64_t end_pos = ctx->pos + length - 2;
  while (ctx->pos < end_pos) {
    if (! jpg_has_bytes(ctx, 1)) {
      return JPG_VAL_TRUNCATED;
    }
    uint8_t info = jpg_read_byte(ctx);
    uint8_t pq = (info >> 4) & 0x0F;
    uint8_t tq = info & 0x0F;
    if (pq > 1 || tq >= JPG_MAX_QUANT_TABLES) {
      ctx->error_pos = ctx->pos - 1;
      return JPG_VAL_INVALID_QUANT;
    }
    uint32_t table_size = (pq == 0) ? 64 : 128;
    if (! jpg_has_bytes(ctx, table_size)) {
      return JPG_VAL_TRUNCATED;
    }
    if (ctx->pos + table_size > end_pos) {
      ctx->error_pos = ctx->pos;
      return JPG_VAL_INVALID_LENGTH;
    }
    ctx->quant_precision[tq] = pq;
    for (int i = 0; i < 64; i++) {
      uint16_t val;
      if (pq == 0) {
        val = jpg_read_byte(ctx);
      }
      else {
        val = jpg_read_u16(ctx->data + ctx->pos);
        ctx->pos += 2;
      }
      ctx->quant_tables[tq][i] = val;
      if (val == 0) {
        ctx->error_pos = ctx->pos;
        return JPG_VAL_INVALID_QUANT;
      }
    }
    ctx->quant_defined[tq] = true;
  }
  return JPG_VAL_OK;
}


static inline JpgValidationResult jpg_parse_sof(JpgValidationContext *ctx, uint8_t marker, uint16_t length) {

  if (ctx->have_sof) {
    ctx->error_pos = ctx->pos - 4;
    return JPG_VAL_INVALID_STRUCTURE;
  }
  if (length < 8 || ! jpg_has_bytes(ctx, length - 2)) {
    return JPG_VAL_TRUNCATED;
  }

  ctx->precision = jpg_read_byte(ctx);
  ctx->height = jpg_read_u16(ctx->data + ctx->pos);
  ctx->pos += 2;
  ctx->width = jpg_read_u16(ctx->data + ctx->pos);
  ctx->pos += 2;
  ctx->num_components = jpg_read_byte(ctx);

  if (ctx->precision != 8 && ctx->precision != 12) {
    if (! jpg_is_sof_marker(marker) || (marker != M_SOF3 && marker != M_SOF7 && marker != M_SOF11 && marker != M_SOF15)) {
      if (ctx->precision < 2 || ctx->precision > 16) {
        ctx->error_pos = ctx->pos - 6;
        return JPG_VAL_INVALID_SOF;
      }
    }
  }
  if (ctx->width == 0) {
    ctx->error_pos = ctx->pos - 3;
    return JPG_VAL_INVALID_SOF;
  }
  // note: height==0 is valid in JPEG (means DNL marker will define it later)
  if (ctx->num_components == 0 || ctx->num_components > JPG_MAX_COMPONENTS) {
    ctx->error_pos = ctx->pos - 1;
    return JPG_VAL_INVALID_SOF;
  }
  if (length != 8 + 3 * ctx->num_components) {
    ctx->error_pos = ctx->pos;
    return JPG_VAL_INVALID_LENGTH;
  }

  ctx->max_h_samp = 0;
  ctx->max_v_samp = 0;
  for (int i = 0; i < ctx->num_components; i++) {
    if (! jpg_has_bytes(ctx, 3)) {
      return JPG_VAL_TRUNCATED;
    }
    ctx->components[i].id = jpg_read_byte(ctx);
    uint8_t sampling = jpg_read_byte(ctx);
    ctx->components[i].h_samp = (sampling >> 4) & 0x0F;
    ctx->components[i].v_samp = sampling & 0x0F;
    ctx->components[i].quant_tbl = jpg_read_byte(ctx);

    if (ctx->components[i].h_samp == 0 || ctx->components[i].h_samp > JPG_MAX_SAMPLING || ctx->components[i].v_samp == 0
        || ctx->components[i].v_samp > JPG_MAX_SAMPLING) {
      ctx->error_pos = ctx->pos - 2;
      return JPG_VAL_INVALID_SOF;
    }
    if (ctx->components[i].h_samp > ctx->max_h_samp) {
      ctx->max_h_samp = ctx->components[i].h_samp;
    }
    if (ctx->components[i].v_samp > ctx->max_v_samp) {
      ctx->max_v_samp = ctx->components[i].v_samp;
    }
    if (ctx->components[i].quant_tbl >= JPG_MAX_QUANT_TABLES) {
      ctx->error_pos = ctx->pos - 1;
      return JPG_VAL_INVALID_SOF;
    }
  }
  ctx->have_sof = true;
  ctx->is_progressive = (marker == M_SOF2 || marker == M_SOF6 || marker == M_SOF10 || marker == M_SOF14);
  return JPG_VAL_OK;
}


static inline JpgValidationResult jpg_parse_sos(JpgValidationContext *ctx, uint16_t length) {
  if (! ctx->have_sof) {
    ctx->error_pos = ctx->pos - 4;
    return JPG_VAL_INVALID_STRUCTURE;
  }
  if (! jpg_has_bytes(ctx, 1)) {
    return JPG_VAL_TRUNCATED;
  }
  ctx->scan_components = jpg_read_byte(ctx);
  if (ctx->scan_components == 0 || ctx->scan_components > ctx->num_components || ctx->scan_components > JPG_MAX_COMPONENTS) {
    ctx->error_pos = ctx->pos - 1;
    return JPG_VAL_INVALID_SOS;
  }
  if (length != 6 + 2 * ctx->scan_components) {
    ctx->error_pos = ctx->pos;
    return JPG_VAL_INVALID_LENGTH;
  }
  for (int i = 0; i < ctx->scan_components; i++) {
    if (! jpg_has_bytes(ctx, 2)) {
      return JPG_VAL_TRUNCATED;
    }
    uint8_t cs = jpg_read_byte(ctx);
    uint8_t td_ta = jpg_read_byte(ctx);
    int comp_idx = -1;
    for (int j = 0; j < ctx->num_components; j++) {
      if (ctx->components[j].id == cs) {
        comp_idx = j;
        break;
      }
    }
    if (comp_idx < 0) {
      ctx->error_pos = ctx->pos - 2;
      return JPG_VAL_INVALID_SOS;
    }
    ctx->scan_comp[i].comp_idx = comp_idx;
    ctx->scan_comp[i].dc_tbl = (td_ta >> 4) & 0x0F;
    ctx->scan_comp[i].ac_tbl = td_ta & 0x0F;
    if (ctx->scan_comp[i].dc_tbl >= JPG_MAX_HUFFMAN_TABLES || ctx->scan_comp[i].ac_tbl >= JPG_MAX_HUFFMAN_TABLES) {
      ctx->error_pos = ctx->pos - 1;
      return JPG_VAL_INVALID_SOS;
    }
  }
  if (! jpg_has_bytes(ctx, 3)) {
    return JPG_VAL_TRUNCATED;
  }
  ctx->ss = jpg_read_byte(ctx);
  ctx->se = jpg_read_byte(ctx);
  uint8_t a = jpg_read_byte(ctx);
  ctx->ah = (a >> 4) & 0x0F;
  ctx->al = a & 0x0F;
  if (ctx->is_progressive) {
    if (ctx->ss > 63 || ctx->se > 63 || ctx->se < ctx->ss) {
      ctx->error_pos = ctx->pos - 3;
      return JPG_VAL_INVALID_SOS;
    }
  }
  else {
    if (ctx->ss != 0 || ctx->se != 63) {
      ctx->error_pos = ctx->pos - 3;
      return JPG_VAL_INVALID_SOS;
    }
  }
  if (ctx->ah > 13 || ctx->al > 13) {
    ctx->error_pos = ctx->pos - 1;
    return JPG_VAL_INVALID_SOS;
  }
  ctx->in_scan = true;
  ctx->had_scan = true;
  ctx->scan_count++;
  return JPG_VAL_OK;
}

static inline uint16_t jpg_read_endian_u16(const uint8_t *data, bool little_endian) {
  if (little_endian) {
    return (uint16_t)data[0] | ((uint16_t)data[1] << 8);
  }
  return ((uint16_t)data[0] << 8) | (uint16_t)data[1];
}

static inline uint32_t jpg_read_endian_u32(const uint8_t *data, bool little_endian) {
  if (little_endian) {
    return (uint32_t)data[0]
           | ((uint32_t)data[1] << 8)
           | ((uint32_t)data[2] << 16)
           | ((uint32_t)data[3] << 24);
  }
  return ((uint32_t)data[0] << 24)
         | ((uint32_t)data[1] << 16)
         | ((uint32_t)data[2] << 8)
         | (uint32_t)data[3];
}

static inline void jpg_parse_mpf_segment(JpgValidationContext *ctx,
                                         uint16_t seg_length) {
  const uint8_t *seg;
  const uint8_t *tiff;
  bool little_endian;
  uint32_t ifd0_off;
  uint64_t ifd_pos;
  uint16_t entry_count;
  uint32_t num_images = 0;
  uint32_t mpentry_count = 0;
  uint32_t mpentry_offset = 0;
  uint64_t mpf_base;
  uint64_t compound_end = 0;
  uint64_t primary_size = 0;

  if (seg_length < 2 + 4 + 8) {
    return;
  }

  seg = ctx->data + ctx->pos;
  if (memcmp(seg, "MPF\0", 4) != 0) {
    return;
  }

  tiff = seg + 4;
  if ((seg_length - 2) < 12) {
    return;
  }

  if (memcmp(tiff, "II", 2) == 0) {
    little_endian = true;
  }
  else if (memcmp(tiff, "MM", 2) == 0) {
    little_endian = false;
  }
  else {
    return;
  }

  if (jpg_read_endian_u16(tiff + 2, little_endian) != 42) {
    return;
  }

  ifd0_off = jpg_read_endian_u32(tiff + 4, little_endian);
  if (ifd0_off + 2 > (uint32_t)(seg_length - 2 - 4)) {
    return;
  }

  ifd_pos = ctx->pos + 4 + ifd0_off;
  if (ifd_pos + 2 > ctx->length) {
    return;
  }

  entry_count = jpg_read_endian_u16(ctx->data + ifd_pos, little_endian);
  if (ifd_pos + 2 + (uint64_t)entry_count * 12 > ctx->length) {
    return;
  }

  for (uint16_t i = 0; i < entry_count; i++) {
    const uint8_t *entry = ctx->data + ifd_pos + 2 + (uint64_t)i * 12;
    uint16_t tag = jpg_read_endian_u16(entry, little_endian);
    uint16_t type = jpg_read_endian_u16(entry + 2, little_endian);
    uint32_t count = jpg_read_endian_u32(entry + 4, little_endian);
    uint32_t value = jpg_read_endian_u32(entry + 8, little_endian);

    if (tag == 0xB001 && type == 4 && count == 1) {
      num_images = value;
    }
    else if (tag == 0xB002 && type == 7 && count >= 16) {
      mpentry_count = count;
      mpentry_offset = value;
    }
  }

  if (num_images == 0 || mpentry_count < 16 || mpentry_offset == 0) {
    return;
  }

  mpf_base = (uint64_t)ctx->pos + 4;
  for (uint32_t i = 0; i < num_images; i++) {
    uint64_t entry_pos = mpf_base + mpentry_offset + (uint64_t)i * 16;
    uint32_t image_size;
    uint32_t image_offset;
    uint64_t image_start;
    uint64_t image_end;

    if (entry_pos + 16 > ctx->length) {
      break;
    }

    image_size = jpg_read_endian_u32(ctx->data + entry_pos + 4, little_endian);
    image_offset = jpg_read_endian_u32(ctx->data + entry_pos + 8, little_endian);
    image_start = (i == 0) ? 0 : (mpf_base + image_offset);
    image_end = image_start + image_size;

    if (i == 0) {
      primary_size = image_size;
    }
    if (image_end > compound_end) {
      compound_end = image_end;
    }
  }

  if (primary_size == 0 || compound_end <= primary_size) {
    return;
  }

  ctx->has_mpf = true;
  ctx->mpf_primary_size = primary_size;
  ctx->mpf_compound_end = compound_end;
}


// ============================================================================
// Entropy Stream Validation
// ============================================================================

static inline JpgValidationResult jpg_scan_entropy_data(JpgValidationContext *ctx) {
  uint32_t restart_count = 0;
  uint8_t expected_rst = 0;
  (void)restart_count;
  bool prev_ff = false;

  while (ctx->pos < ctx->length) {
    uint8_t b = jpg_read_byte(ctx);

    if (prev_ff) {
      prev_ff = false;
      if (b == 0x00) {
        continue;
      }
      if (b == 0xFF) {
        prev_ff = true;
        continue;
      }

      if (b >= M_RST0 && b <= M_RST7) {
        uint8_t rst_num = b - M_RST0;
        if (ctx->restart_interval > 0) {
          if (rst_num != expected_rst) {
            if (! ctx->rst_seq_broken) {
              ctx->rst_seq_broken = true;
              ctx->rst_seq_error_pos = ctx->pos - 2;
            }
            expected_rst = rst_num;
          }
          expected_rst = (expected_rst + 1) & 0x07;
        }
        restart_count++;
        ctx->entropy_bytes = ctx->pos;
        ctx->last_good_pos = ctx->pos;
        continue;
      }

      ctx->pos -= 2;
      ctx->entropy_bytes = ctx->pos;
      ctx->restart_count = restart_count;
      ctx->last_good_pos = ctx->pos;
      return JPG_VAL_OK;
    }

    if (b == 0xFF) {
      prev_ff = true;
    }
  }

  ctx->entropy_bytes = ctx->pos;
  ctx->restart_count = restart_count;
  // CRITICAL FIX: Ensure last_good_pos reflects the valid entropy we just scanned
  ctx->last_good_pos = ctx->pos;
  return JPG_VAL_TRUNCATED;
}

static inline JpgValidationResult jpg_validate_structure(JpgValidationContext *ctx) {
  if (! jpg_has_bytes(ctx, 2)) {
    return JPG_VAL_TRUNCATED;
  }
  if (jpg_read_byte(ctx) != 0xFF || jpg_read_byte(ctx) != M_SOI) {
    ctx->error_pos = 0;
    return JPG_VAL_INVALID_MARKER;
  }
  ctx->last_good_pos = ctx->pos;

  while (ctx->pos < ctx->length) {
    if (! jpg_has_bytes(ctx, 2)) {
      return JPG_VAL_TRUNCATED;
    }
    uint8_t b1 = jpg_read_byte(ctx);
    if (b1 != 0xFF) {
      ctx->error_pos = ctx->pos - 1;
      return JPG_VAL_INVALID_STRUCTURE;
    }
    uint8_t marker;
    do {
      if (! jpg_has_bytes(ctx, 1)) {
        return JPG_VAL_TRUNCATED;
      }
      marker = jpg_read_byte(ctx);
    } while (marker == 0xFF);
    if (marker == 0x00) {
      ctx->error_pos = ctx->pos - 1;
      return JPG_VAL_INVALID_STRUCTURE;
    }

    if (marker == M_EOI) {
      ctx->last_good_pos = ctx->pos;
      return JPG_VAL_OK;
    }
    if (marker == M_SOS) {
      ctx->scan_start = ctx->pos - 2;
      if (! jpg_has_bytes(ctx, 2)) {
        return JPG_VAL_TRUNCATED;
      }
      uint16_t length = jpg_read_u16(ctx->data + ctx->pos);
      ctx->pos += 2;
      JpgValidationResult result = jpg_parse_sos(ctx, length);
      if (result != JPG_VAL_OK) {
        return result;
      }
      ctx->last_good_pos = ctx->pos;
      ctx->scan_entropy_start = ctx->pos;
      if (ctx->entropy_start == 0) { ctx->entropy_start = ctx->pos; }
      result = jpg_scan_entropy_data(ctx);
      if (result != JPG_VAL_OK && result != JPG_VAL_TRUNCATED) {
        return result;
      }
      if (result == JPG_VAL_TRUNCATED) {
        return JPG_VAL_TRUNCATED;
      }
      ctx->in_scan = false;
      continue;
    }
    if (jpg_is_standalone_marker(marker)) {
      ctx->last_good_pos = ctx->pos;
      continue;
    }

    if (! jpg_has_bytes(ctx, 2)) {
      return JPG_VAL_TRUNCATED;
    }
    uint16_t length = jpg_read_u16(ctx->data + ctx->pos);
    ctx->pos += 2;
    if (length < 2) {
      ctx->error_pos = ctx->pos - 2;
      return JPG_VAL_INVALID_LENGTH;
    }
    if (! jpg_has_bytes(ctx, length - 2)) {
      return JPG_VAL_TRUNCATED;
    }

    JpgValidationResult result = JPG_VAL_OK;
    if (marker == M_DHT) {
      result = jpg_parse_dht(ctx, length);
    }
    else if (marker == M_DQT) {
      result = jpg_parse_dqt(ctx, length);
    }
    else if (jpg_is_sof_marker(marker)) {
      result = jpg_parse_sof(ctx, marker, length);
    }
    else if (marker == M_DRI) {
      if (length != 4) {
        ctx->error_pos = ctx->pos;
        result = JPG_VAL_INVALID_LENGTH;
      }
      else {
        ctx->restart_interval = jpg_read_u16(ctx->data + ctx->pos);
        ctx->pos += 2;
      }
    }
    else {
      if (marker == M_APP2) {
        jpg_parse_mpf_segment(ctx, length);
      }
      if (marker >= 0x02 && marker <= 0xBF && ctx->had_scan) {
        ctx->error_pos = ctx->pos - 4;
        return JPG_VAL_CORRUPT_DATA;
      }
      ctx->pos += length - 2;
    }

    if (result != JPG_VAL_OK) {
      return result;
    }
    ctx->last_good_pos = ctx->pos;
  }
  return JPG_VAL_TRUNCATED;
}


// ============================================================================
// Libjpeg Integration
// ============================================================================

struct jpg_error_mgr {
  struct jpeg_error_mgr pub;
  jmp_buf setjmp_buffer;
};
typedef struct jpg_error_mgr *jpg_error_mgr_ptr;

typedef struct jpg_mem_source {
  unsigned char *data;
  unsigned long length;
  unsigned long curpos;
  long errpos;
  long first_errpos;      // first error or warning during image decoding
  uint32_t swallowed_error_count;  // total number of swallowed errors during partial decode
  unsigned char EOI[32];
  unsigned int jpeg_error;
} jpg_mem_source;

_Thread_local static struct jpeg_decompress_struct jpg_cinfo;
_Thread_local static struct jpg_mem_source jpg_cd;
_Thread_local static struct jpg_error_mgr jpg_jerr;
_Thread_local static unsigned long jpg_last_good_pos;
_Thread_local static uint32_t jpg_current_blocksize;
_Thread_local static int32_t jpg_dc_threshold = 2000;   // adaptive DC continuity threshold
_Thread_local static int32_t jpg_max_observed_dc_diff;  // max |dc_diff| seen in last validation
_Thread_local static int jpg_allow_partial_decode = 0;


static inline unsigned long jpg_bytes_consumed(j_decompress_ptr cinfo, jpg_mem_source *cd) {
  const struct jpeg_source_mgr *src = cinfo->src;
  if (! src) {
    return cd->curpos;
  }
  if (src->next_input_byte == &cd->EOI[0]) {
    return (cd->curpos >= 2 ? cd->curpos - 2 : 0);
  }
  return cd->curpos - (unsigned long)src->bytes_in_buffer;
}


static inline void jpg_term_source(j_decompress_ptr cinfo) { (void)cinfo; }

static inline void jpg_init_source(j_decompress_ptr cinfo) { (void)cinfo; }

static inline void jpg_skip_input_data(j_decompress_ptr cinfo, long num_bytes) {
  struct jpeg_source_mgr *src = cinfo->src;
  if (num_bytes > 0) {
    while (num_bytes > (long)src->bytes_in_buffer) {
      num_bytes -= (long)src->bytes_in_buffer;
      (cinfo->src->fill_input_buffer)(cinfo);
    }
    src->next_input_byte += (size_t)num_bytes;
    src->bytes_in_buffer -= (size_t)num_bytes;
  }
}


static inline int jpg_fill_input_buffer(j_decompress_ptr cinfo) {
  unsigned long nbytes;
  jpg_mem_source *cd = (jpg_mem_source *)(cinfo->client_data);
#if defined(JPEG_TEST)
  nbytes = JPEG_TEST_BLOCKSIZE;
#else
  nbytes = scalpel_state.blocksize;
#endif
  if (cd->length == 0 || cd->curpos >= cd->length - 1) {
    nbytes = 0;
  }
  else if (cd->curpos + nbytes >= cd->length - 1) {
    nbytes = cd->length - cd->curpos;
  }

  if (nbytes <= 0) {
    cd->jpeg_error = JERR_INPUT_EOF;
    if (cd->errpos < 0) {
      cd->errpos = cd->curpos;
    }
    cinfo->src->next_input_byte = cd->EOI;
    cinfo->src->bytes_in_buffer = 2;
  }
  else {
    cinfo->src->next_input_byte = cd->data + cd->curpos;
    cinfo->src->bytes_in_buffer = nbytes;
    cd->curpos += nbytes;
  }
  return true;
}


static inline void jpg_handle_error(j_common_ptr cinfo) {
  jpg_error_mgr_ptr myerr = (jpg_error_mgr_ptr)cinfo->err;
  jpg_mem_source *cd = (jpg_mem_source *)(cinfo->client_data);
  cd->errpos = (long)jpg_bytes_consumed((j_decompress_ptr)cinfo, cd);
  cd->jpeg_error = cinfo->err->msg_code;
  if (jpg_allow_partial_decode) {
    int code = cinfo->err->msg_code;
    if (code == 93 || code == 92 || (code >= 61 && code <= 70)) {
      // Track first swallowed error position — only errors swallowed during
      // jpeg_read_coefficients, never header-phase warnings
      cd->swallowed_error_count++;
      if (cd->first_errpos < 0) {
        cd->first_errpos = cd->errpos;
      }
      return;
    }
  }
  longjmp(myerr->setjmp_buffer, 1);
}


static inline void jpg_output_message(j_common_ptr cinfo) {
  jpg_mem_source *cd = (jpg_mem_source *)(cinfo->client_data);
  cd->jpeg_error = cinfo->err->msg_code;
  cd->errpos = (long)jpg_bytes_consumed((j_decompress_ptr)cinfo, cd);
  if (jpg_allow_partial_decode && cd->first_errpos < 0) {
    cd->first_errpos = cd->errpos;
  }
}


// ============================================================================
// Wrong Block & MCU Detection
// ============================================================================

typedef struct {
  bool detected;
  uint32_t corruption_row;
  uint64_t estimated_byte;
  const char *method;
  double confidence;
} JpgWrongBlockResult;

_Thread_local static JpgWrongBlockResult jpg_wrongblock_result;

typedef struct {
  bool valid;
  uint32_t mcu_count;
  uint32_t expected_mcus;
  uint32_t mcus_since_restart;
  uint8_t expected_rst;
  bool restart_due;
  uint64_t final_byte_pos;
  uint64_t entropy_start;
  double bytes_per_mcu;
  double expected_bytes_per_mcu;
  double mcu_deviation;
  double max_mcu_deviation;
  double max_dc_discontinuity;
  uint64_t dc_discontinuity_pos;
  uint64_t dc_abs_sum;
  uint64_t dc_samples;
  uint64_t ac_abs_sum;
  uint64_t ac_samples;
} JpgMcuValidationResult;

_Thread_local static JpgMcuValidationResult jpg_mcu_result;

typedef struct {
  const uint8_t *data;
  uint64_t length;
  uint64_t byte_pos;
  uint8_t bit_pos;
  uint8_t current_byte;
  bool hit_marker;
  uint64_t marker_pos;
  bool at_restart;
  bool has_restart;
} JpgBitstream;

static inline void jpg_bs_init(JpgBitstream *bs, const uint8_t *data, uint64_t length, uint64_t start_pos, bool has_restart) {
  bs->data = data;
  bs->length = length;
  bs->byte_pos = start_pos;
  bs->bit_pos = 0;
  bs->current_byte = 0;
  bs->hit_marker = false;
  bs->marker_pos = 0;
  bs->at_restart = false;
  bs->has_restart = has_restart;
}


static inline bool jpg_bs_next_byte(JpgBitstream *bs) {
  if (bs->byte_pos >= bs->length) {
    return false;
  }
  bs->current_byte = bs->data[bs->byte_pos++];
  if (bs->current_byte == 0xFF) {
    if (bs->byte_pos >= bs->length) {
      return false;
    }
    uint8_t next = bs->data[bs->byte_pos];
    if (next == 0x00) {
      bs->byte_pos++;
    }
    else if (next >= M_RST0 && next <= M_RST7 && bs->has_restart) {
      bs->byte_pos--;
      bs->at_restart = true;
      return false;
    }
    else {
      bs->hit_marker = true;
      bs->marker_pos = bs->byte_pos - 1;
      return false;
    }
  }
  bs->bit_pos = 8;
  return true;
}


static inline int32_t jpg_bs_get_bits(JpgBitstream *bs, int n) {
  if (n <= 0) {
    return 0;
  }
  if (n > 16) {
    return -1;
  }
  int32_t result = 0;
  while (n > 0) {
    if (bs->bit_pos == 0) {
      if (! jpg_bs_next_byte(bs)) {
        return -1;
      }
    }
    int take = (n < bs->bit_pos) ? n : bs->bit_pos;
    int shift = bs->bit_pos - take;
    int mask = (1 << take) - 1;
    result = (result << take) | ((bs->current_byte >> shift) & mask);
    bs->bit_pos -= take;
    n -= take;
  }
  return result;
}


static inline int jpg_bs_decode_huffman(JpgBitstream *bs, JpgHuffmanTable *table) {
  if (! table->defined) {
    return -1;
  }
  int32_t code = 0;
  for (int length = 1; length <= 16; length++) {
    int32_t bit = jpg_bs_get_bits(bs, 1);
    if (bit < 0) {
      return -1;
    }
    code = (code << 1) | bit;
    if (table->maxcode[length] >= 0 && code <= table->maxcode[length]) {
      int idx = table->valptr[length] + (code - (table->maxcode[length] - table->bits[length] + 1));
      if (idx >= 0 && idx < (int)table->total_codes) {
        return table->huffval[idx];
      }
      return -1;
    }
  }
  return -1;
}


// Version that also returns the code length (for bit alignment checking)
static inline int jpg_bs_decode_huffman_len(JpgBitstream *bs, JpgHuffmanTable *table, int *out_length) {
  *out_length = 0;
  if (! table->defined) {
    return -1;
  }
  int32_t code = 0;
  for (int length = 1; length <= 16; length++) {
    int32_t bit = jpg_bs_get_bits(bs, 1);
    if (bit < 0) {
      return -1;
    }
    code = (code << 1) | bit;
    if (table->maxcode[length] >= 0 && code <= table->maxcode[length]) {
      int idx = table->valptr[length] + (code - (table->maxcode[length] - table->bits[length] + 1));
      if (idx >= 0 && idx < (int)table->total_codes) {
        *out_length = length;
        return table->huffval[idx];
      }
      return -1;
    }
  }
  return -1;
}

typedef struct {
  bool supported;
  bool valid;
  bool complete;
  uint64_t units;
  uint64_t expected_units;
  uint64_t entropy_bytes;
} JpgProgressiveEntropyEvidence;

static inline uint64_t jpg_progressive_component_blocks(
    const JpgValidationContext *ctx,
    const JpgComponent *component) {
  uint64_t width_denominator;
  uint64_t height_denominator;
  uint64_t width_blocks;
  uint64_t height_blocks;

  if (!ctx || !component || ctx->max_h_samp == 0 || ctx->max_v_samp == 0) {
    return 0;
  }
  width_denominator = (uint64_t)ctx->max_h_samp * 8;
  height_denominator = (uint64_t)ctx->max_v_samp * 8;
  width_blocks = CEILDIV((uint64_t)ctx->width * component->h_samp,
                         width_denominator);
  height_blocks = CEILDIV((uint64_t)ctx->height * component->v_samp,
                          height_denominator);
  return width_blocks * height_blocks;
}

static inline uint64_t *jpg_progressive_prior_nonzero_map(
    const JpgValidationContext *ctx,
    int component_index,
    uint64_t expected_blocks) {
  static const uint8_t natural_order[64] = {
      0,  1,  8, 16,  9,  2,  3, 10,
     17, 24, 32, 25, 18, 11,  4,  5,
     12, 19, 26, 33, 40, 48, 41, 34,
     27, 20, 13,  6,  7, 14, 21, 28,
     35, 42, 49, 56, 57, 50, 43, 36,
     29, 22, 15, 23, 30, 37, 44, 51,
     58, 59, 52, 45, 38, 31, 39, 46,
     53, 60, 61, 54, 47, 55, 62, 63
  };
  struct jpeg_decompress_struct cinfo;
  struct jpg_error_mgr jerr;
  jpg_mem_source cd;
  uint64_t * volatile nonzero = NULL;
  volatile bool complete = false;

  if (!ctx || !ctx->data || ctx->length < 2 || component_index < 0
      || component_index >= ctx->num_components || expected_blocks == 0
      || expected_blocks > SIZE_MAX / sizeof(uint64_t)) {
    return NULL;
  }

  memset(&cd, 0, sizeof(cd));
  cd.data = (unsigned char *)ctx->data;
  cd.length = (unsigned long)ctx->length;
  cd.errpos = -1;
  cd.first_errpos = -1;
  cd.EOI[0] = 0xFF;
  cd.EOI[1] = JPEG_EOI;

  jpeg_create_decompress(&cinfo);
  cinfo.client_data = &cd;
  cinfo.err = jpeg_std_error(&jerr.pub);
  jerr.pub.error_exit = jpg_handle_error;
  jerr.pub.output_message = jpg_output_message;
  jerr.pub.trace_level = 0;
  cinfo.src = (struct jpeg_source_mgr *)(cinfo.mem->alloc_small)(
      (j_common_ptr)&cinfo, JPOOL_PERMANENT,
      sizeof(struct jpeg_source_mgr));
  cinfo.src->init_source = jpg_init_source;
  cinfo.src->fill_input_buffer = jpg_fill_input_buffer;
  cinfo.src->skip_input_data = jpg_skip_input_data;
  cinfo.src->resync_to_restart = jpeg_resync_to_restart;
  cinfo.src->term_source = jpg_term_source;
  cinfo.src->bytes_in_buffer = 0;
  cinfo.src->next_input_byte = ctx->data;

  jpg_allow_partial_decode = 1;
  if (setjmp(jerr.setjmp_buffer)) {
    goto prior_map_done;
  }
  if (jpeg_read_header(&cinfo, TRUE) != JPEG_HEADER_OK) {
    goto prior_map_done;
  }
  {
    jvirt_barray_ptr *coef_arrays = jpeg_read_coefficients(&cinfo);
    jpeg_component_info *component;
    uint64_t blocks;

    if (!coef_arrays || component_index >= cinfo.num_components) {
      goto prior_map_done;
    }
    component = &cinfo.comp_info[component_index];
    blocks = (uint64_t)component->width_in_blocks
             * component->height_in_blocks;
    if (blocks != expected_blocks) {
      goto prior_map_done;
    }
    nonzero = calloc((size_t)blocks, sizeof(uint64_t));
    check_memory_allocation((void *)nonzero, __LINE__, __FILE__,
                            "jpg progressive coefficient map");
    for (JDIMENSION row = 0; row < component->height_in_blocks; row++) {
      JBLOCKARRAY buffer = (cinfo.mem->access_virt_barray)(
          (j_common_ptr)&cinfo, coef_arrays[component_index], row, 1, FALSE);

      for (JDIMENSION column = 0;
           column < component->width_in_blocks; column++) {
        uint64_t block = (uint64_t)row * component->width_in_blocks + column;

        for (uint32_t coefficient = 1; coefficient < 64; coefficient++) {
          JCOEF value = buffer[0][column][natural_order[coefficient]];
          JCOEF current_bit = (JCOEF)(1U << ctx->al);

          if (value > current_bit || value < -current_bit) {
            ((uint64_t *)nonzero)[block] |= UINT64_C(1) << coefficient;
          }
        }
      }
    }
    complete = true;
  }

prior_map_done:
  jpg_allow_partial_decode = 0;
  jpeg_destroy_decompress(&cinfo);
  if (!complete) {
    free((void *)nonzero);
    return NULL;
  }
  return (uint64_t *)nonzero;
}

_Thread_local static uint32_t jpg_progressive_refinement_failure;
_Thread_local static uint64_t jpg_progressive_refinement_failure_byte;

static inline bool jpg_progressive_decode_ac_refinement_unit(
    JpgBitstream *bs,
    JpgHuffmanTable *table,
    uint8_t ss,
    uint8_t se,
    uint64_t *nonzero,
    uint32_t *eob_run) {
  uint32_t coefficient = ss;

#define JPG_REFINEMENT_FAIL(code) do {                                      \
    jpg_progressive_refinement_failure = (code);                            \
    jpg_progressive_refinement_failure_byte = bs ? bs->byte_pos : 0;        \
    return false;                                                           \
  } while (0)

  if (!bs || !table || !nonzero || !eob_run) {
    JPG_REFINEMENT_FAIL(1);
  }
  if (*eob_run == 0) {
    while (coefficient <= se) {
      uint32_t run;
      uint32_t size;
      bool introduce_coefficient;
      int symbol;

      symbol = jpg_bs_decode_huffman(bs, table);
      if (symbol < 0) {
        JPG_REFINEMENT_FAIL(3);
      }
      run = ((uint32_t)symbol >> 4) & 0x0f;
      size = (uint32_t)symbol & 0x0f;
      if (size > 1) {
        JPG_REFINEMENT_FAIL(4);
      }
      introduce_coefficient = size == 1;
      if (introduce_coefficient) {
        if (jpg_bs_get_bits(bs, 1) < 0) {
          JPG_REFINEMENT_FAIL(5);
        }
      }
      else if (run != 15) {
        int32_t extra = run > 0 ? jpg_bs_get_bits(bs, (int)run) : 0;

        if (extra < 0) {
          JPG_REFINEMENT_FAIL(6);
        }
        *eob_run = (1U << run) + (uint32_t)extra;
        break;
      }

      while (coefficient <= se) {
        if ((*nonzero & (UINT64_C(1) << coefficient)) != 0) {
          if (jpg_bs_get_bits(bs, 1) < 0) {
            JPG_REFINEMENT_FAIL(7);
          }
          coefficient++;
        }
        else {
          if (run == 0) {
            break;
          }
          run--;
          coefficient++;
        }
      }
      if (introduce_coefficient) {
        if (coefficient <= se) {
          *nonzero |= UINT64_C(1) << coefficient;
        }
      }
      coefficient++;
    }
  }

  if (*eob_run > 0) {
    while (coefficient <= se) {
      if ((*nonzero & (UINT64_C(1) << coefficient)) != 0
          && jpg_bs_get_bits(bs, 1) < 0) {
        JPG_REFINEMENT_FAIL(11);
      }
      coefficient++;
    }
    (*eob_run)--;
  }
#undef JPG_REFINEMENT_FAIL
  return true;
}

static inline bool jpg_progressive_entropy_scan_evidence(
    const JpgValidationContext *ctx,
    uint64_t entropy_end,
    JpgProgressiveEntropyEvidence *evidence) {
  JpgBitstream bs;
  uint64_t expected_units;
  uint64_t unit = 0;
  uint32_t eob_run = 0;
  bool interleaved;
  uint64_t *prior_nonzero = NULL;

  if (!evidence) {
    return false;
  }
  memset(evidence, 0, sizeof(*evidence));
  jpg_progressive_refinement_failure = 0;
  jpg_progressive_refinement_failure_byte = 0;
  evidence->valid = true;
  if (!ctx || !ctx->is_progressive || !ctx->had_scan
      || ctx->scan_entropy_start == 0
      || entropy_end < ctx->scan_entropy_start
      || ctx->restart_interval != 0) {
    return true;
  }

  interleaved = ctx->scan_components > 1;
  if (interleaved) {
    uint64_t mcu_width = CEILDIV(ctx->width,
                                 (uint64_t)ctx->max_h_samp * 8);
    uint64_t mcu_height = CEILDIV(ctx->height,
                                  (uint64_t)ctx->max_v_samp * 8);

    if (ctx->ss != 0 || mcu_width == 0 || mcu_height == 0) {
      return true;
    }
    expected_units = mcu_width * mcu_height;
  }
  else {
    int component_index;

    if (ctx->scan_components != 1) {
      return true;
    }
    component_index = ctx->scan_comp[0].comp_idx;
    if (component_index < 0 || component_index >= ctx->num_components) {
      return true;
    }
    expected_units = jpg_progressive_component_blocks(
        ctx, &ctx->components[component_index]);
  }
  if (expected_units == 0) {
    return true;
  }
  if (ctx->ss > 0 && ctx->ah > 0) {
    int component_index;

    if (interleaved || ctx->scan_components != 1) {
      return true;
    }
    component_index = ctx->scan_comp[0].comp_idx;
    prior_nonzero = jpg_progressive_prior_nonzero_map(
        ctx, component_index, expected_units);
    if (!prior_nonzero) {
      return true;
    }
  }

  evidence->supported = true;
  evidence->expected_units = expected_units;
  evidence->entropy_bytes = entropy_end - ctx->scan_entropy_start;
  jpg_bs_init(&bs, ctx->data, entropy_end, ctx->scan_entropy_start, false);

  for (unit = 0; unit < expected_units; unit++) {
    if (ctx->ss > 0 && ctx->ah > 0) {
      JpgHuffmanTable *table =
          (JpgHuffmanTable *)&ctx->ac_tables[ctx->scan_comp[0].ac_tbl];

      if (!jpg_progressive_decode_ac_refinement_unit(
              &bs, table, ctx->ss, ctx->se,
              &prior_nonzero[unit], &eob_run)) {
        goto progressive_truncated_or_invalid;
      }
    }
    else if (ctx->ss == 0) {
      for (int scan_component = 0;
           scan_component < ctx->scan_components;
           scan_component++) {
        const JpgScanComponent *scan = &ctx->scan_comp[scan_component];
        const JpgComponent *component = &ctx->components[scan->comp_idx];
        uint32_t blocks = interleaved
                              ? component->h_samp * component->v_samp
                              : 1;

        for (uint32_t block = 0; block < blocks; block++) {
          if (ctx->ah == 0) {
            JpgHuffmanTable *table =
                (JpgHuffmanTable *)&ctx->dc_tables[scan->dc_tbl];
            int symbol = jpg_bs_decode_huffman(&bs, table);

            if (symbol < 0) {
              goto progressive_truncated_or_invalid;
            }
            if (symbol > 16 || jpg_bs_get_bits(&bs, symbol) < 0) {
              goto progressive_truncated_or_invalid;
            }
          }
          else if (jpg_bs_get_bits(&bs, 1) < 0) {
            goto progressive_truncated_or_invalid;
          }
        }
      }
    }
    else {
      const JpgScanComponent *scan = &ctx->scan_comp[0];
      JpgHuffmanTable *table =
          (JpgHuffmanTable *)&ctx->ac_tables[scan->ac_tbl];
      uint32_t coefficient = ctx->ss;

      if (eob_run > 0) {
        eob_run--;
        continue;
      }
      while (coefficient <= ctx->se) {
        int symbol = jpg_bs_decode_huffman(&bs, table);
        uint32_t run;
        uint32_t size;

        if (symbol < 0) {
          goto progressive_truncated_or_invalid;
        }
        run = ((uint32_t)symbol >> 4) & 0x0f;
        size = (uint32_t)symbol & 0x0f;
        if (size > 0) {
          coefficient += run;
          if (coefficient > ctx->se || size > 16
              || jpg_bs_get_bits(&bs, (int)size) < 0) {
            if (coefficient > ctx->se || size > 16) {
              goto progressive_invalid;
            }
            goto progressive_truncated_or_invalid;
          }
          coefficient++;
        }
        else if (run == 15) {
          coefficient += 16;
          if (coefficient > (uint32_t)ctx->se + 1) {
            goto progressive_invalid;
          }
        }
        else {
          int32_t extra = run > 0 ? jpg_bs_get_bits(&bs, (int)run) : 0;

          if (extra < 0) {
            goto progressive_truncated_or_invalid;
          }
          eob_run = (1U << run) + (uint32_t)extra - 1;
          break;
        }
      }
    }
  }

  evidence->units = expected_units;
  evidence->complete = true;
  if (bs.byte_pos < entropy_end) {
    jpg_progressive_refinement_failure = 20;
    jpg_progressive_refinement_failure_byte = bs.byte_pos;
    goto progressive_invalid;
  }
  free(prior_nonzero);
  return true;

progressive_truncated_or_invalid:
  if (bs.byte_pos < entropy_end || bs.hit_marker) {
    goto progressive_invalid;
  }
  evidence->units = unit;
  free(prior_nonzero);
  return true;

progressive_invalid:
  evidence->valid = false;
  evidence->units = unit;
  free(prior_nonzero);
  return false;
}

static inline uint64_t jpg_progressive_next_entropy_marker(
    const uint8_t *data,
    uint64_t start,
    uint64_t length) {
  uint64_t pos = start;

  while (data && pos + 1 < length) {
    if (data[pos] != 0xff) {
      pos++;
      continue;
    }
    uint64_t marker_start = pos;
    do {
      pos++;
    } while (pos < length && data[pos] == 0xff);
    if (pos >= length) {
      return length;
    }
    if (data[pos] == 0x00
        || (data[pos] >= M_RST0 && data[pos] <= M_RST7)) {
      pos++;
      continue;
    }
    return marker_start;
  }
  return length;
}


typedef enum {
  JPG_HUFFMAN_FAILURE_NONE = 0,
  JPG_HUFFMAN_FAILURE_ENTROPY_CODE,
  JPG_HUFFMAN_FAILURE_DC_CONTINUITY,
  JPG_HUFFMAN_FAILURE_AC_RUN,
  JPG_HUFFMAN_FAILURE_AC_MAGNITUDE,
  JPG_HUFFMAN_FAILURE_RESTART_SEQUENCE,
  JPG_HUFFMAN_FAILURE_TRAILING_DATA,
  JPG_HUFFMAN_FAILURE_UNEXPECTED_MARKER
} JpgHuffmanFailure;

static inline bool jpg_huffman_failure_is_hard(JpgHuffmanFailure failure) {
  return failure == JPG_HUFFMAN_FAILURE_ENTROPY_CODE
         || failure == JPG_HUFFMAN_FAILURE_AC_RUN
         || failure == JPG_HUFFMAN_FAILURE_RESTART_SEQUENCE;
}

static inline const char *jpg_huffman_failure_method(JpgHuffmanFailure failure) {
  switch (failure) {
    case JPG_HUFFMAN_FAILURE_ENTROPY_CODE:
    case JPG_HUFFMAN_FAILURE_AC_RUN:
      return "huffman_invalid";
    case JPG_HUFFMAN_FAILURE_DC_CONTINUITY:
      return "dc_discontinuity";
    case JPG_HUFFMAN_FAILURE_AC_MAGNITUDE:
      return "ac_magnitude";
    case JPG_HUFFMAN_FAILURE_RESTART_SEQUENCE:
      return "rst_sequence";
    case JPG_HUFFMAN_FAILURE_TRAILING_DATA:
      return "huffman_trailing_data";
    case JPG_HUFFMAN_FAILURE_UNEXPECTED_MARKER:
      return "huffman_unexpected_marker";
    case JPG_HUFFMAN_FAILURE_NONE:
    default:
      return "none";
  }
}

// jpg_huffman_validate — walk the MCU entropy stream, detecting wrong blocks.
//
// Parameters:
//   ctx         — parsed JPEG structure (header tables, scan info, data pointer)
//   restore     — if non-NULL and valid, resume Huffman decoding from this checkpoint
//   save_to     — if non-NULL, save checkpoint state at the last good block boundary
//   failure     — if non-NULL, identify the entropy failure class
//   profile     — if non-NULL, record cumulative MCU counts at block boundaries
//
// Returns: 0 if no error found, or the byte position of the first detected error.
static inline uint64_t jpg_huffman_validate(JpgValidationContext *ctx,
                                            JPGHuffmanCheckpoint *restore,
                                            JPGHuffmanCheckpoint *save_to,
                                            JpgHuffmanFailure *failure,
                                            JPGHuffmanBlockProfile *profile) {
  if (failure) {
    *failure = JPG_HUFFMAN_FAILURE_NONE;
  }
  if (save_to) {
    memset(save_to, 0, sizeof(*save_to));
  }
  memset(&jpg_mcu_result, 0, sizeof(jpg_mcu_result));
  if (!ctx->have_sof || !ctx->had_scan || ctx->is_progressive) {
    return 0;
  }

  uint64_t entropy_start = ctx->entropy_start;
  if (entropy_start == 0) {
    // Fallback: raw scan (should not normally be needed when ctx is
    // populated from structured parse or restore).
    for (uint64_t i = 0; i + 3 < ctx->length; i++) {
      if (ctx->data[i] == 0xFF && ctx->data[i + 1] == 0xDA) {
        uint16_t sos_len = (ctx->data[i + 2] << 8) | ctx->data[i + 3];
        entropy_start = i + 2 + sos_len;
        break;
      }
    }
  }
  if (entropy_start == 0 || entropy_start >= ctx->length) {
    memset(&jpg_mcu_result, 0, sizeof(jpg_mcu_result));
    return 0;
  }

  JpgBitstream bs;
  bool has_restart = (ctx->restart_interval > 0);
  jpg_bs_init(&bs, ctx->data, ctx->length, entropy_start, has_restart);

  uint32_t h_samp = ctx->max_h_samp > 0 ? ctx->max_h_samp : 1;
  uint32_t v_samp = ctx->max_v_samp > 0 ? ctx->max_v_samp : 1;
  uint32_t mcu_width = (ctx->width + h_samp * 8 - 1) / (h_samp * 8);
  uint32_t mcu_height = (ctx->height + v_samp * 8 - 1) / (v_samp * 8);
  if (mcu_width == 0 || mcu_height == 0) {
    return 0;
  }

  uint32_t total_mcus = mcu_width * mcu_height;
  memset(&jpg_mcu_result, 0, sizeof(jpg_mcu_result));
  jpg_mcu_result.entropy_start = entropy_start;
  jpg_mcu_result.expected_mcus = total_mcus;
  jpg_mcu_result.valid = true;

  uint32_t restart_interval = ctx->restart_interval;
  uint32_t mcus_since_restart = 0;
  uint8_t expected_rst = 0;
  uint64_t last_mcu_start_pos = entropy_start;
  int32_t comp_dc_predictor[JPG_MAX_COMPONENTS] = {0};

  // Track two different notions of "current block":
  // 1. checkpoint_block advances only when an MCU starts in a new filesystem
  //    block, so we can save a resumable Huffman checkpoint at that boundary.
  // 2. current_block tracks the last block observed by the DC continuity logic.
  uint64_t checkpoint_block = (jpg_current_blocksize > 0) ? (entropy_start / jpg_current_blocksize) : 0;
  uint64_t current_block = checkpoint_block;
  uint32_t start_mcu = 0;
  int32_t max_observed_dc_diff = 0;  // track for adaptive threshold

  // OPUS47/J2: After a calibration period, tighten the DC threshold based
  // on observed DC range. Previously only the fast/restore path did this;
  // the full-validation path always used the permissive 2000 default. The
  // calibration runs inside this pass so the full path benefits too.
  int32_t local_dc_threshold = jpg_dc_threshold;
  static const uint32_t JPG_DC_CALIBRATION_MCUS = 128;
  bool dc_calibrated = false;

  // Restore from Huffman checkpoint if available
  if (restore && restore->valid && restore->byte_pos >= entropy_start
      && restore->byte_pos <= ctx->length) {
    bs.byte_pos = restore->byte_pos;
    bs.bit_pos = restore->bit_pos;
    bs.current_byte = restore->current_byte;
    start_mcu = restore->mcu_count;
    mcus_since_restart = restore->mcus_since_restart;
    expected_rst = restore->expected_rst;
    memcpy(comp_dc_predictor, restore->dc_predictors, sizeof(comp_dc_predictor));
    checkpoint_block = restore->current_block;
    current_block = restore->current_block;
    jpg_mcu_result.dc_abs_sum = restore->dc_abs_sum;
    jpg_mcu_result.dc_samples = restore->dc_samples;
    jpg_mcu_result.ac_abs_sum = restore->ac_abs_sum;
    jpg_mcu_result.ac_samples = restore->ac_samples;
  }
  if (profile && profile->mcu_at_boundary
      && checkpoint_block < profile->boundary_count) {
    profile->mcu_at_boundary[checkpoint_block] = start_mcu;
  }

  for (uint32_t mcu = start_mcu; mcu < total_mcus; mcu++) {
    if (profile && mcu % JPG_HUFFMAN_PROFILE_CHECKPOINT_QUANTUM == 0
        && atomic_load_explicit(&REASS_RETURN_TO_IDLE,
                                memory_order_acquire)) {
      return 0;
    }
    last_mcu_start_pos = bs.byte_pos;
    jpg_mcu_result.mcu_count = mcu;
    jpg_mcu_result.mcus_since_restart = mcus_since_restart;
    jpg_mcu_result.expected_rst = expected_rst;
    jpg_mcu_result.restart_due = false;
    jpg_mcu_result.final_byte_pos = bs.byte_pos;

    // OPUS47/J2+J16: tighten the DC threshold once calibration MCUs have
    // run. The tightening catches wrong-block extensions whose entropy
    // decodes to dc_diff well above the file's observed range, but the
    // original J2 (3x observed, floor 200) was too aggressive — real
    // photos with large DC swings in the header region triggered false
    // positives that made jpg_huffman_validate claim an error at the
    // first block boundary even on fully valid files. That broke
    // fragmented reassembly signal: every extension looked identical
    // because the walker bailed out before even reaching the extension.
    //
    // J16: loosen to 10x observed with a 1000 floor. Real photos rarely
    // have 10x swings block-to-block but wrong reassemblies routinely
    // produce dc_diffs of several thousand.
    if (!dc_calibrated && mcu >= start_mcu + JPG_DC_CALIBRATION_MCUS) {
      int32_t adaptive = max_observed_dc_diff * 10;
      if (adaptive < 1000) {
        adaptive = 1000;
      }
      if (adaptive < local_dc_threshold) {
        local_dc_threshold = adaptive;
      }
      dc_calibrated = true;
    }

    // Check if we crossed a block boundary since last MCU
    if (jpg_current_blocksize > 0) {
      uint64_t mcu_block = bs.byte_pos / jpg_current_blocksize;
      if (mcu_block > checkpoint_block) {
        if (profile && profile->mcu_at_boundary
            && profile->boundary_count > 0) {
          uint64_t last_boundary = mcu_block;

          if (last_boundary >= profile->boundary_count) {
            last_boundary = profile->boundary_count - 1;
          }
          for (uint64_t boundary = checkpoint_block + 1;
               boundary <= last_boundary; boundary++) {
            profile->mcu_at_boundary[boundary] = mcu;
          }
        }
        checkpoint_block = mcu_block;

        // Save checkpoint at each block boundary crossing (last save wins)
        if (save_to) {
          save_to->valid = true;
          save_to->byte_pos = bs.byte_pos;
          save_to->bit_pos = bs.bit_pos;
          save_to->current_byte = bs.current_byte;
          save_to->mcu_count = mcu;
          save_to->mcus_since_restart = mcus_since_restart;
          save_to->expected_rst = expected_rst;
          memcpy(save_to->dc_predictors, comp_dc_predictor, sizeof(comp_dc_predictor));
          save_to->current_block = checkpoint_block;
          save_to->dc_abs_sum = jpg_mcu_result.dc_abs_sum;
          save_to->dc_samples = jpg_mcu_result.dc_samples;
          save_to->ac_abs_sum = jpg_mcu_result.ac_abs_sum;
          save_to->ac_samples = jpg_mcu_result.ac_samples;
        }
      }
    }
    for (int ci = 0; ci < ctx->scan_components; ci++) {
      JpgScanComponent *sc = &ctx->scan_comp[ci];
      JpgComponent *comp = &ctx->components[sc->comp_idx];
      JpgHuffmanTable *dc_tbl = &ctx->dc_tables[sc->dc_tbl];
      JpgHuffmanTable *ac_tbl = &ctx->ac_tables[sc->ac_tbl];

      if (!dc_tbl->defined || !ac_tbl->defined) {
        return 0;
      }
      int blocks = comp->h_samp * comp->v_samp;

      for (int b = 0; b < blocks; b++) {
        // check decoded DC coefficient changes at block boundaries; code
        // lengths vary by Huffman table, while unusually large decoded
        // changes provide useful evidence of a bad continuation.
        int dc_sym = jpg_bs_decode_huffman(&bs, dc_tbl);
        if (dc_sym < 0) {
          if (bs.at_restart) {
            goto handle_restart;
          }
          if (bs.byte_pos >= ctx->length) {
            return 0;    // Clean truncation
          }
          if (failure) {
            *failure = JPG_HUFFMAN_FAILURE_ENTROPY_CODE;
          }
          return last_mcu_start_pos > 0 ? last_mcu_start_pos : bs.byte_pos;
        }

        int32_t dc_diff = 0;
        if (dc_sym > 0) {
          int32_t dc_extra = jpg_bs_get_bits(&bs, dc_sym);
          if (dc_extra < 0) {
            if (bs.at_restart) {
              goto handle_restart;
            }
            if (bs.byte_pos >= ctx->length) {
              return 0;  // Clean truncation
            }
            if (failure) {
              *failure = JPG_HUFFMAN_FAILURE_ENTROPY_CODE;
            }
            return last_mcu_start_pos > 0 ? last_mcu_start_pos : bs.byte_pos;
          }
          dc_diff = (dc_extra < (1 << (dc_sym - 1))) ? dc_extra - (1 << dc_sym) + 1 : dc_extra;
          comp_dc_predictor[sc->comp_idx] += dc_diff;
        }

        int32_t abs_dc_diff = (dc_diff < 0) ? -dc_diff : dc_diff;

        jpg_mcu_result.dc_abs_sum += (uint64_t)abs_dc_diff;
        jpg_mcu_result.dc_samples++;

        // advance at every boundary, including zero-difference symbols, so
        // the next MCU cannot repeat the same boundary check.
        if (jpg_current_blocksize > 0) {
          uint64_t dc_block = bs.byte_pos / jpg_current_blocksize;
          if (dc_block > current_block) {
            if ((double)abs_dc_diff
                > jpg_mcu_result.max_dc_discontinuity) {
              jpg_mcu_result.max_dc_discontinuity = (double)abs_dc_diff;
              jpg_mcu_result.dc_discontinuity_pos =
                  dc_block * jpg_current_blocksize;
            }
            if (abs_dc_diff > max_observed_dc_diff) {
              max_observed_dc_diff = abs_dc_diff;
            }
            if (abs_dc_diff > local_dc_threshold) {
              if (failure) {
                *failure = JPG_HUFFMAN_FAILURE_DC_CONTINUITY;
              }
              return dc_block * jpg_current_blocksize;
            }
            current_block = dc_block;
          }
        }

        int ac_count = 0;
        int32_t ac_block_sum = 0;

        while (ac_count < 63) {
          int ac_sym = jpg_bs_decode_huffman(&bs, ac_tbl);
          if (ac_sym < 0) {
            if (bs.at_restart) {
              goto handle_restart;
            }
            if (bs.byte_pos >= ctx->length) {
              return 0;    // Clean truncation
            }
            if (failure) {
              *failure = JPG_HUFFMAN_FAILURE_ENTROPY_CODE;
            }
            return last_mcu_start_pos > 0 ? last_mcu_start_pos : bs.byte_pos;
          }
          if (ac_sym == 0) {
            break;
          }
          int run = (ac_sym >> 4) & 0x0F;
          int size = ac_sym & 0x0F;
          ac_count += run + 1;
          if (ac_count > 63) {
            if (failure) {
              *failure = JPG_HUFFMAN_FAILURE_AC_RUN;
            }
            return last_mcu_start_pos > 0 ? last_mcu_start_pos : bs.byte_pos;
          }
          if (size > 0) {
            int32_t ac_extra = jpg_bs_get_bits(&bs, size);
            if (ac_extra < 0) {
              if (bs.at_restart) {
                goto handle_restart;
              }
              if (bs.byte_pos >= ctx->length) {
                return 0;  // Clean truncation
              }
              if (failure) {
                *failure = JPG_HUFFMAN_FAILURE_ENTROPY_CODE;
              }
              return last_mcu_start_pos > 0 ? last_mcu_start_pos : bs.byte_pos;
            }
            int32_t mag = (ac_extra < (1 << (size - 1))) ? ac_extra - (1 << size) + 1 : ac_extra;
            ac_block_sum += abs(mag);
          }
        }

        // Threshold 8000 - catches garbage data that decodes to large AC values
        if (ac_block_sum > 8000) {
          if (failure) {
            *failure = JPG_HUFFMAN_FAILURE_AC_MAGNITUDE;
          }
          return last_mcu_start_pos > 0 ? last_mcu_start_pos : bs.byte_pos;
        }
        jpg_mcu_result.ac_abs_sum += (uint64_t)ac_block_sum;
        jpg_mcu_result.ac_samples++;

      }
    }
    // OPUS47/J1: removed the blind end-of-MCU advance of current_block.
    // The inner DC boundary check now handles all boundary crossings,
    // including the dc_sym==0 case. Advancing unconditionally here would
    // blow past boundaries for which the DC check never got a chance.
    // Note: if AC reading crosses a boundary, the NEXT MCU's DC read will
    // see dc_block > current_block and fire the check then — correct.
    mcus_since_restart++;
    jpg_mcu_result.mcus_since_restart = mcus_since_restart;

  handle_restart:
    // Restart markers separate intervals and are not required after the final MCU.
    if (bs.at_restart
        || (restart_interval > 0
            && mcus_since_restart >= restart_interval
            && mcu + 1 < total_mcus)) {
      uint64_t rst_pos;
      uint64_t marker_code_pos;

      // Reset predictors on restart
      for (int k = 0; k < JPG_MAX_COMPONENTS; k++) {
        comp_dc_predictor[k] = 0;
      }

      bs.bit_pos = 0;
      bs.at_restart = false;

      // a restart marker is required immediately after the interval. Scanning
      // ahead through entropy bytes hides missing fragments and can make an
      // unrelated later RST marker look like a valid continuation.
      rst_pos = bs.byte_pos;
      marker_code_pos = rst_pos;
      while (marker_code_pos < bs.length
             && bs.data[marker_code_pos] == 0xFF) {
        marker_code_pos++;
      }
      if (marker_code_pos >= bs.length) {
        jpg_mcu_result.mcu_count = mcu + 1;
        jpg_mcu_result.mcus_since_restart = mcus_since_restart;
        jpg_mcu_result.expected_rst = expected_rst;
        jpg_mcu_result.restart_due = true;
        jpg_mcu_result.final_byte_pos = bs.length;
        return 0;
      }
      if (rst_pos == marker_code_pos
          || bs.data[marker_code_pos] < M_RST0
          || bs.data[marker_code_pos] > M_RST7
          || (uint8_t)(bs.data[marker_code_pos] - M_RST0) != expected_rst) {
        if (failure) {
          *failure = JPG_HUFFMAN_FAILURE_RESTART_SEQUENCE;
        }
        if (jpg_current_blocksize > 0) {
          return (rst_pos / jpg_current_blocksize) * jpg_current_blocksize;
        }
        return rst_pos;
      }
      bs.byte_pos = marker_code_pos + 1;
      expected_rst = (expected_rst + 1) & 0x07;
      mcus_since_restart = 0;
      jpg_mcu_result.mcus_since_restart = 0;
      jpg_mcu_result.expected_rst = expected_rst;
    }
  }

  jpg_mcu_result.mcu_count = total_mcus;
  jpg_mcu_result.final_byte_pos = bs.byte_pos;

  // Export max observed DC diff for adaptive threshold computation
  jpg_max_observed_dc_diff = max_observed_dc_diff;

  // Trailing garbage check: if Huffman parsing finished cleanly but there's significant remaining
  // data that wasn't consumed, that indicates wrong block(s) at the end.
  // Threshold: one blocksize accounts for normal block-alignment padding after EOI.
  uint64_t remaining = (bs.byte_pos < bs.length) ? (bs.length - bs.byte_pos) : 0;
  uint64_t trailing_threshold = (jpg_current_blocksize > 0) ? jpg_current_blocksize : 100;
  if (remaining > trailing_threshold && last_mcu_start_pos > 0) {
    if (failure) {
      *failure = JPG_HUFFMAN_FAILURE_TRAILING_DATA;
    }
    return last_mcu_start_pos;
  }

  if (bs.hit_marker) {
    if (failure) {
      *failure = JPG_HUFFMAN_FAILURE_UNEXPECTED_MARKER;
    }
    return bs.marker_pos;
  }

  return 0;
}


typedef struct {
  bool found;
  bool hard_failure;
  uint64_t validates_to;
  uint64_t thumbnail_offset;
  uint64_t available_length;
  uint64_t declared_length;
  JpgHuffmanFailure huffman_failure;
} JpgEmbeddedJpegEvidence;


static inline bool jpg_range_is_available(uint64_t offset,
                                          uint64_t size,
                                          uint64_t limit) {
  return offset <= limit && size <= limit - offset;
}


static inline uint16_t jpg_tiff_u16(const uint8_t *data, bool little_endian) {
  if (little_endian) {
    return (uint16_t)data[0] | ((uint16_t)data[1] << 8);
  }
  return ((uint16_t)data[0] << 8) | (uint16_t)data[1];
}


static inline uint32_t jpg_tiff_u32(const uint8_t *data, bool little_endian) {
  if (little_endian) {
    return (uint32_t)data[0]
           | ((uint32_t)data[1] << 8)
           | ((uint32_t)data[2] << 16)
           | ((uint32_t)data[3] << 24);
  }
  return ((uint32_t)data[0] << 24)
         | ((uint32_t)data[1] << 16)
         | ((uint32_t)data[2] << 8)
         | (uint32_t)data[3];
}


static inline bool jpg_tiff_scalar(const uint8_t *entry,
                                   bool little_endian,
                                   uint32_t *value) {
  uint16_t type = jpg_tiff_u16(entry + 2, little_endian);
  uint32_t count = jpg_tiff_u32(entry + 4, little_endian);

  if (!value || count != 1) {
    return false;
  }
  if (type == 3) {
    *value = jpg_tiff_u16(entry + 8, little_endian);
    return true;
  }
  if (type == 4) {
    *value = jpg_tiff_u32(entry + 8, little_endian);
    return true;
  }
  return false;
}


static inline bool jpg_find_exif_thumbnail(const uint8_t *data,
                                           uint64_t length,
                                           uint64_t *thumbnail_offset,
                                           uint64_t *thumbnail_length,
                                           uint64_t *container_end) {
  uint64_t pos = 2;

  if (!data || length < 4 || data[0] != 0xff || data[1] != M_SOI
      || !thumbnail_offset || !thumbnail_length || !container_end) {
    return false;
  }

  while (pos + 1 < length) {
    uint8_t marker;
    uint16_t segment_length;
    uint64_t segment_end;
    uint64_t payload_start;
    uint64_t parse_limit;

    if (data[pos] != 0xff) {
      return false;
    }
    while (pos < length && data[pos] == 0xff) {
      pos++;
    }
    if (pos >= length) {
      return false;
    }
    marker = data[pos++];
    if (marker == M_SOS || marker == M_EOI) {
      return false;
    }
    if (marker == 0x00 || marker == M_SOI
        || (marker >= M_RST0 && marker <= M_RST7)) {
      continue;
    }
    if (!jpg_range_is_available(pos, 2, length)) {
      return false;
    }
    segment_length = jpg_read_u16(data + pos);
    if (segment_length < 2) {
      return false;
    }
    segment_end = pos + segment_length;
    payload_start = pos + 2;
    parse_limit = segment_end < length ? segment_end : length;

    if (marker == M_APP1
        && jpg_range_is_available(payload_start, 14, parse_limit)
        && memcmp(data + payload_start, "Exif\0\0", 6) == 0) {
      uint64_t tiff_start = payload_start + 6;
      bool little_endian;
      uint32_t ifd0_relative;
      uint64_t ifd0;
      uint16_t ifd0_entries;
      uint64_t ifd0_table_size;
      uint64_t next_ifd_pos;
      uint32_t ifd1_relative;
      uint64_t ifd1;
      uint16_t ifd1_entries;
      uint64_t ifd1_table_size;
      uint32_t relative_offset = 0;
      uint32_t declared_length = 0;
      bool have_offset = false;
      bool have_length = false;

      if (data[tiff_start] == 'I' && data[tiff_start + 1] == 'I') {
        little_endian = true;
      }
      else if (data[tiff_start] == 'M' && data[tiff_start + 1] == 'M') {
        little_endian = false;
      }
      else {
        goto next_segment;
      }
      if (jpg_tiff_u16(data + tiff_start + 2, little_endian) != 42) {
        goto next_segment;
      }
      ifd0_relative = jpg_tiff_u32(data + tiff_start + 4, little_endian);
      ifd0 = tiff_start + ifd0_relative;
      if (!jpg_range_is_available(ifd0, 2, parse_limit)) {
        goto next_segment;
      }
      ifd0_entries = jpg_tiff_u16(data + ifd0, little_endian);
      ifd0_table_size = (uint64_t)ifd0_entries * 12;
      if (!jpg_range_is_available(ifd0 + 2, ifd0_table_size + 4,
                                  parse_limit)) {
        goto next_segment;
      }
      next_ifd_pos = ifd0 + 2 + ifd0_table_size;
      ifd1_relative = jpg_tiff_u32(data + next_ifd_pos, little_endian);
      if (ifd1_relative == 0) {
        goto next_segment;
      }
      ifd1 = tiff_start + ifd1_relative;
      if (!jpg_range_is_available(ifd1, 2, parse_limit)) {
        goto next_segment;
      }
      ifd1_entries = jpg_tiff_u16(data + ifd1, little_endian);
      ifd1_table_size = (uint64_t)ifd1_entries * 12;
      if (!jpg_range_is_available(ifd1 + 2, ifd1_table_size, parse_limit)) {
        goto next_segment;
      }

      for (uint16_t entry_index = 0;
           entry_index < ifd1_entries;
           entry_index++) {
        const uint8_t *entry = data + ifd1 + 2
                               + (uint64_t)entry_index * 12;
        uint16_t tag = jpg_tiff_u16(entry, little_endian);
        uint32_t value;

        if (tag == 0x0201
            && jpg_tiff_scalar(entry, little_endian, &value)) {
          relative_offset = value;
          have_offset = true;
        }
        else if (tag == 0x0202
                 && jpg_tiff_scalar(entry, little_endian, &value)) {
          declared_length = value;
          have_length = true;
        }
      }
      if (have_offset && have_length && declared_length >= 2
          && relative_offset <= UINT64_MAX - tiff_start) {
        uint64_t absolute_offset = tiff_start + relative_offset;

        if (absolute_offset >= payload_start
            && absolute_offset < segment_end
            && declared_length <= segment_end - absolute_offset
            && jpg_range_is_available(absolute_offset, 2, length)
            && data[absolute_offset] == 0xff
            && data[absolute_offset + 1] == M_SOI) {
          *thumbnail_offset = absolute_offset;
          *thumbnail_length = declared_length;
          *container_end = segment_end;
          return true;
        }
      }
    }

  next_segment:
    if (segment_end > length) {
      return false;
    }
    pos = segment_end;
  }
  return false;
}


static inline JpgEmbeddedJpegEvidence jpg_embedded_exif_evidence(
    const uint8_t *data,
    uint64_t length) {
  JpgEmbeddedJpegEvidence evidence;
  uint64_t container_end = 0;

  memset(&evidence, 0, sizeof(evidence));
  if (!jpg_find_exif_thumbnail(data, length, &evidence.thumbnail_offset,
                               &evidence.declared_length, &container_end)) {
    return evidence;
  }
  evidence.found = true;
  evidence.available_length = length - evidence.thumbnail_offset;
  if (evidence.available_length > evidence.declared_length) {
    evidence.available_length = evidence.declared_length;
  }

  if (evidence.available_length < 4) {
    return evidence;
  }

  JpgValidationContext embedded_context;
  JpgValidationResult structural_result;
  JPGHuffmanCheckpoint embedded_checkpoint;
  JpgHuffmanFailure huffman_failure = JPG_HUFFMAN_FAILURE_NONE;
  JpgMcuValidationResult saved_mcu_result = jpg_mcu_result;
  int32_t saved_max_observed_dc_diff = jpg_max_observed_dc_diff;
  int32_t saved_dc_threshold = jpg_dc_threshold;
  uint32_t saved_blocksize = jpg_current_blocksize;
  uint64_t huffman_error;
  uint64_t nested_error = 0;

  memset(&embedded_context, 0, sizeof(embedded_context));
  embedded_context.data = data + evidence.thumbnail_offset;
  embedded_context.length = evidence.available_length;
  structural_result = jpg_validate_structure(&embedded_context);

  // disable filesystem-boundary heuristics for the unaligned nested stream;
  // impossible codes and restart sequencing remain authoritative.
  jpg_current_blocksize = 0;
  jpg_dc_threshold = INT32_MAX;
  huffman_error = jpg_huffman_validate(&embedded_context, NULL,
                                       &embedded_checkpoint,
                                       &huffman_failure, NULL);
  JpgMcuValidationResult embedded_mcu_result = jpg_mcu_result;
  jpg_mcu_result = saved_mcu_result;
  jpg_max_observed_dc_diff = saved_max_observed_dc_diff;
  jpg_dc_threshold = saved_dc_threshold;
  jpg_current_blocksize = saved_blocksize;

  if (huffman_error > 0 && jpg_huffman_failure_is_hard(huffman_failure)) {
    nested_error = huffman_error;
    if (huffman_failure == JPG_HUFFMAN_FAILURE_RESTART_SEQUENCE
        && embedded_mcu_result.final_byte_pos > embedded_context.entropy_start
        && embedded_mcu_result.final_byte_pos < nested_error) {
      nested_error = embedded_mcu_result.final_byte_pos;
    }
    evidence.huffman_failure = huffman_failure;
  }
  else if (embedded_context.rst_seq_broken
           && embedded_context.rst_seq_error_pos > 0) {
    nested_error = embedded_context.rst_seq_error_pos;
    evidence.huffman_failure = JPG_HUFFMAN_FAILURE_RESTART_SEQUENCE;
  }

  if (nested_error > 0
      && nested_error <= UINT64_MAX - evidence.thumbnail_offset) {
    uint64_t outer_error = evidence.thumbnail_offset + nested_error;

    evidence.hard_failure = true;
    evidence.validates_to = outer_error > 0 ? outer_error - 1 : 0;
  }
  if (jpg_validate_debug_enabled()) {
    lock_fprintf(stderr,
                 "[jpgvdbg] embedded-exif len=%" PRIu64
                 " off=%" PRIu64 " avail=%" PRIu64 " declared=%" PRIu64
                 " structural=%d sof=%d scan=%d rst=%d huff_err=%" PRIu64
                 " failure=%d hard=%d vt=%" PRIu64 "\n",
                 length, evidence.thumbnail_offset, evidence.available_length,
                 evidence.declared_length, structural_result,
                 embedded_context.have_sof ? 1 : 0,
                 embedded_context.had_scan ? 1 : 0,
                 embedded_context.rst_seq_broken ? 1 : 0,
                 huffman_error, huffman_failure,
                 evidence.hard_failure ? 1 : 0, evidence.validates_to);
  }
  return evidence;
}


static inline void jpg_libjpeg_validate(char *data, uint64_t length, bool *validates, uint64_t *validates_to, bool *promising,
                                        uint32_t needleidx, uint32_t blocksize, void *blockhashkey) {
  (void)needleidx;
  (void)blocksize;
  (void)blockhashkey;
  jpg_last_good_pos = 0;
  *validates = false;
  *promising = false;
  *validates_to = 0;

  memset(&jpg_cd, 0, sizeof(jpg_cd));
  jpg_cd.data = (unsigned char *)data;
  jpg_cd.length = (unsigned long)length;
  jpg_cd.curpos = 0;
  jpg_cd.errpos = -1;
  jpg_cd.first_errpos = -1;
  jpg_cd.jpeg_error = 0;
  jpg_cd.EOI[0] = 0xFF;
  jpg_cd.EOI[1] = JPEG_EOI;

  jpeg_create_decompress(&jpg_cinfo);
  jpg_cinfo.client_data = &jpg_cd;
  jpg_cinfo.err = jpeg_std_error(&jpg_jerr.pub);
  jpg_jerr.pub.error_exit = jpg_handle_error;
  jpg_jerr.pub.output_message = jpg_output_message;
  jpg_jerr.pub.trace_level = 0;
  jpg_cinfo.src = (struct jpeg_source_mgr *)(jpg_cinfo.mem->alloc_small)((j_common_ptr)&jpg_cinfo, JPOOL_PERMANENT,
                                                                         sizeof(struct jpeg_source_mgr));
  jpg_cinfo.src->init_source = jpg_init_source;
  jpg_cinfo.src->fill_input_buffer = jpg_fill_input_buffer;
  jpg_cinfo.src->skip_input_data = jpg_skip_input_data;
  jpg_cinfo.src->resync_to_restart = jpeg_resync_to_restart;
  jpg_cinfo.src->term_source = jpg_term_source;
  jpg_cinfo.src->bytes_in_buffer = 0;
  jpg_cinfo.src->next_input_byte = (unsigned char *)data;

  if (setjmp(jpg_jerr.setjmp_buffer)) {
    goto compute_result;
  }
  if (jpeg_read_header(&jpg_cinfo, TRUE) != JPEG_HEADER_OK) {
    goto cleanup;
  }

  jpg_last_good_pos = jpg_bytes_consumed(&jpg_cinfo, &jpg_cd);
  jpg_allow_partial_decode = 1;
  jvirt_barray_ptr *coef_arrays = jpeg_read_coefficients(&jpg_cinfo);
  jpg_allow_partial_decode = 0;
  if (! coef_arrays) {
    goto compute_result;
  }
  jpg_last_good_pos = jpg_bytes_consumed(&jpg_cinfo, &jpg_cd);

  // note: jpg_wrongblock_result is now reset at start of jpg_file_validate

  for (int ci = 0; ci < jpg_cinfo.num_components; ci++) {
    jpeg_component_info *comp_info = &jpg_cinfo.comp_info[ci];
    for (JDIMENSION row = 0; row < comp_info->height_in_blocks; row++) {
      JBLOCKARRAY buffer = (jpg_cinfo.mem->access_virt_barray)((j_common_ptr)&jpg_cinfo, coef_arrays[ci], row, 1, FALSE);
      (void)buffer;
    }
    jpg_last_good_pos = jpg_bytes_consumed(&jpg_cinfo, &jpg_cd);
  }
  (void)jpeg_finish_decompress(&jpg_cinfo);

compute_result:;
  jpg_allow_partial_decode = 0;
  const unsigned long consumed = jpg_bytes_consumed(&jpg_cinfo, &jpg_cd);
  const bool ok = (jpg_cd.jpeg_error == 0 && jpg_cd.errpos < 0);
  *validates = ok;
  if (ok) {
    *validates_to = (consumed > 0) ? (uint64_t)(consumed - 1) : 0;
    if (jpg_wrongblock_result.detected) {
      *validates = false;
      if (jpg_wrongblock_result.estimated_byte > 0 && jpg_wrongblock_result.estimated_byte < *validates_to) {
        *validates_to = jpg_wrongblock_result.estimated_byte - 1;
      }
    }
  }
  else if (jpg_cd.errpos == (long)length || jpg_cd.jpeg_error == JERR_INPUT_EOF) {
    *validates_to = (consumed > 0) ? (uint64_t)(consumed - 1) : 0;
  }
  else if (jpg_cd.jpeg_error == JWRN_HIT_MARKER) {
    *validates_to = (jpg_cd.errpos > 0) ? (uint64_t)(jpg_cd.errpos - 1) : ((consumed > 0) ? consumed - 1 : 0);
  }
  else if (jpg_cd.errpos >= 0) {
    *validates_to = (uint64_t)(jpg_cd.errpos > 0 ? (jpg_cd.errpos - 1) : 0);
  }
  else {
    *validates_to = (jpg_last_good_pos > 0) ? (uint64_t)(jpg_last_good_pos - 1) : 0;
  }
  // Preserve the first decoder failure even when later input exhaustion
  // replaces the current error. Header warnings do not define this frontier.
  if (! ok && jpg_cd.first_errpos > 0 && (uint64_t)jpg_cd.first_errpos < *validates_to) {
    *validates_to = (uint64_t)(jpg_cd.first_errpos - 1);
  }
  if (length == 0) {
    *validates_to = 0;
  }
  else if (*validates_to >= length) {
    *validates_to = length - 1;
  }
  // Floor: never let validates_to drop below blocksize-1.
  // A tiny validates_to trims the candidate to 0 blocks, and
  // init_candidate destroys it before reassembly gets a chance.
  if (! *validates && blocksize > 0 && length >= blocksize
      && *validates_to < blocksize - 1) {
    *validates_to = blocksize - 1;
  }
  *promising = (! *validates) && (*validates_to > 0);

  if (jpg_validate_debug_enabled()) {
    lock_fprintf(stderr,
                 "[jpgvdbg] lib len=%" PRIu64 " ok=%d prom=%d vt=%" PRIu64
                 " consumed=%lu errpos=%ld jpeg_error=%u first_err=%ld swallowed=%u\n",
                 length,
                 *validates ? 1 : 0,
                 *promising ? 1 : 0,
                 *validates_to,
                 consumed,
                 jpg_cd.errpos,
                 jpg_cd.jpeg_error,
                 jpg_cd.first_errpos,
                 jpg_cd.swallowed_error_count);
  }

cleanup:
  jpg_allow_partial_decode = 0;
  jpeg_destroy_decompress(&jpg_cinfo);
}


// ============================================================================
// Pixel-Level MAD (Mean Absolute Difference) Discriminator
// ============================================================================

// jpg_get_scanline — decode and return a SPECIFIC scanline's pixel data.
// Caller must free the returned buffer. Returns NULL on failure.
static inline uint8_t *jpg_get_scanline(char *data, uint64_t length,
                                         JDIMENSION target_row, JDIMENSION *out_stride) {
  *out_stride = 0;
  struct jpeg_decompress_struct cinfo;
  struct jpg_error_mgr jerr;
  jpg_mem_source cd;
  uint8_t * volatile result = NULL;  // 'pointer to volatile' pattern for longjmp safety

  memset(&cd, 0, sizeof(cd));
  cd.data = (unsigned char *)data;
  cd.length = (unsigned long)length;
  cd.EOI[0] = 0xFF;
  cd.EOI[1] = JPEG_EOI;

  jpeg_create_decompress(&cinfo);
  cinfo.client_data = &cd;
  cinfo.err = jpeg_std_error(&jerr.pub);
  jerr.pub.error_exit = jpg_handle_error;
  jerr.pub.output_message = jpg_output_message;
  jerr.pub.trace_level = 0;
  cinfo.src = (struct jpeg_source_mgr *)(cinfo.mem->alloc_small)((j_common_ptr)&cinfo, JPOOL_PERMANENT,
                                                                   sizeof(struct jpeg_source_mgr));
  cinfo.src->init_source = jpg_init_source;
  cinfo.src->fill_input_buffer = jpg_fill_input_buffer;
  cinfo.src->skip_input_data = jpg_skip_input_data;
  cinfo.src->resync_to_restart = jpeg_resync_to_restart;
  cinfo.src->term_source = jpg_term_source;
  cinfo.src->bytes_in_buffer = 0;
  cinfo.src->next_input_byte = (unsigned char *)data;

  jpg_allow_partial_decode = 1;
  if (setjmp(jerr.setjmp_buffer)) {
    goto gs_done;
  }
  if (jpeg_read_header(&cinfo, TRUE) != JPEG_HEADER_OK) {
    goto gs_done;
  }
  cinfo.out_color_space = JCS_RGB;
  jpeg_start_decompress(&cinfo);
  {
    JDIMENSION stride = cinfo.output_width * cinfo.output_components;
    uint8_t *skip = (uint8_t *)malloc(stride);
    *out_stride = stride;
    result = (uint8_t *)malloc(stride);
    check_memory_allocation(skip, __LINE__, __FILE__, "scanline_skip");
    check_memory_allocation(result, __LINE__, __FILE__, "scanline");
    JSAMPROW rp[1];
    JSAMPROW sp[1];
    rp[0] = result;
    sp[0] = skip;
    while (cinfo.output_scanline < cinfo.output_height) {
      if (cinfo.output_scanline == target_row) {
        jpeg_read_scanlines(&cinfo, rp, 1);
        break;
      }
      // Skip this row
      if (jpeg_read_scanlines(&cinfo, sp, 1) == 0) {
        free(result);
        free(skip);
        result = NULL;
        break;
      }
    }
    free(skip);
  }
  jpeg_abort_decompress(&cinfo);
gs_done:
  jpg_allow_partial_decode = 0;
  jpeg_destroy_decompress(&cinfo);
  return result;
}

static inline double jpg_row_mad(const uint8_t *a, const uint8_t *b, JDIMENSION stride) {
  uint64_t sum = 0;
  for (JDIMENSION i = 0; i < stride; i++) {
    int diff = (int)a[i] - (int)b[i];
    if (diff < 0) {
      diff = -diff;
    }
    sum += (uint64_t)diff;
  }
  return stride > 0 ? (double)sum / (double)stride : 0.0;
}

typedef struct {
  const char *data;
  uint8_t *pixels;
  uint64_t prefix_length;
  unsigned int scale_denom;
  JDIMENSION stride;
  JDIMENSION rows;
} JpgBoundaryPreviewCache;

static _Thread_local JpgBoundaryPreviewCache *jpg_boundary_preview_cache;

static inline bool jpg_reassembly_checkpoint_requested(void) {
  return atomic_load_explicit(&REASS_RETURN_TO_IDLE, memory_order_acquire);
}

static inline void jpg_boundary_preview_cache_invalidate(void) {
  if (!jpg_boundary_preview_cache) {
    return;
  }
  free(jpg_boundary_preview_cache->pixels);
  memset(jpg_boundary_preview_cache, 0,
         sizeof(*jpg_boundary_preview_cache));
}

static inline uint8_t *jpg_decode_preview_scaled(char *data, uint64_t length,
                                                 unsigned int scale_denom,
                                                 bool checkpoint_sensitive,
                                                 JDIMENSION *stride_out,
                                                 JDIMENSION *rows_out) {
  struct jpeg_decompress_struct cinfo;
  struct jpg_error_mgr jerr;
  jpg_mem_source cd;
  uint8_t * volatile pixels = NULL;

  *stride_out = 0;
  *rows_out = 0;
  memset(&cd, 0, sizeof(cd));
  cd.data = (unsigned char *)data;
  cd.length = (unsigned long)length;
  cd.errpos = -1;
  cd.first_errpos = -1;
  cd.EOI[0] = 0xFF;
  cd.EOI[1] = JPEG_EOI;

  jpeg_create_decompress(&cinfo);
  cinfo.client_data = &cd;
  cinfo.err = jpeg_std_error(&jerr.pub);
  jerr.pub.error_exit = jpg_handle_error;
  jerr.pub.output_message = jpg_output_message;
  jerr.pub.trace_level = 0;
  cinfo.src = (struct jpeg_source_mgr *)(cinfo.mem->alloc_small)(
      (j_common_ptr)&cinfo, JPOOL_PERMANENT, sizeof(struct jpeg_source_mgr));
  cinfo.src->init_source = jpg_init_source;
  cinfo.src->fill_input_buffer = jpg_fill_input_buffer;
  cinfo.src->skip_input_data = jpg_skip_input_data;
  cinfo.src->resync_to_restart = jpeg_resync_to_restart;
  cinfo.src->term_source = jpg_term_source;
  cinfo.src->bytes_in_buffer = 0;
  cinfo.src->next_input_byte = (unsigned char *)data;

  jpg_allow_partial_decode = 1;
  if (setjmp(jerr.setjmp_buffer)) {
    goto preview_done;
  }
  if (jpeg_read_header(&cinfo, TRUE) != JPEG_HEADER_OK) {
    goto preview_done;
  }
  cinfo.scale_num = 1;
  cinfo.scale_denom = scale_denom;
  cinfo.out_color_space = JCS_RGB;
  cinfo.do_fancy_upsampling = FALSE;
  cinfo.dct_method = JDCT_IFAST;
  jpeg_start_decompress(&cinfo);

  {
    JDIMENSION stride = cinfo.output_width * cinfo.output_components;
    uint64_t allocation = (uint64_t)stride * cinfo.output_height;
    JDIMENSION rows = 0;

    if (allocation == 0 || allocation > 64ULL * 1024 * 1024) {
      goto preview_done;
    }
    pixels = (uint8_t *)malloc((size_t)allocation);
    check_memory_allocation((void *)pixels, __LINE__, __FILE__, "jpg_preview");
    while (cinfo.output_scanline < cinfo.output_height) {
      JSAMPROW row = (uint8_t *)pixels + (uint64_t)cinfo.output_scanline * stride;

      if (checkpoint_sensitive
          && (cinfo.output_scanline & 31u) == 0
          && jpg_reassembly_checkpoint_requested()) {
        free((void *)pixels);
        pixels = NULL;
        goto preview_done;
      }
      if (jpeg_read_scanlines(&cinfo, &row, 1) != 1) {
        break;
      }
      rows++;
    }
    *stride_out = stride;
    *rows_out = rows;
  }
  jpeg_abort_decompress(&cinfo);

preview_done:
  jpg_allow_partial_decode = 0;
  jpeg_destroy_decompress(&cinfo);
  return (uint8_t *)pixels;
}

static inline JpgBoundaryScore jpg_decode_boundary_scaled(
    char *data,
    uint64_t length,
    unsigned int scale_denom,
    bool checkpoint_sensitive,
    const uint8_t *prefix,
    JDIMENSION prefix_stride,
    JDIMENSION prefix_rows) {
  struct jpeg_decompress_struct cinfo;
  struct jpg_error_mgr jerr;
  jpg_mem_source cd;
  volatile JpgBoundaryScore result;
  uint8_t * volatile row_storage = NULL;
  double recent_mad[8] = {0.0};
  volatile uint32_t recent_count = 0;
  volatile uint32_t recent_next = 0;
  JDIMENSION decoded_rows = 0;
  volatile bool boundary_found = false;

  memset((void *)&result, 0, sizeof(result));
  if (!data || !prefix || prefix_stride == 0 || prefix_rows < 3) {
    JpgBoundaryScore empty = {0};

    return empty;
  }

  memset(&cd, 0, sizeof(cd));
  cd.data = (unsigned char *)data;
  cd.length = (unsigned long)length;
  cd.errpos = -1;
  cd.first_errpos = -1;
  cd.EOI[0] = 0xFF;
  cd.EOI[1] = JPEG_EOI;

  jpeg_create_decompress(&cinfo);
  cinfo.client_data = &cd;
  cinfo.err = jpeg_std_error(&jerr.pub);
  jerr.pub.error_exit = jpg_handle_error;
  jerr.pub.output_message = jpg_output_message;
  jerr.pub.trace_level = 0;
  cinfo.src = (struct jpeg_source_mgr *)(cinfo.mem->alloc_small)(
      (j_common_ptr)&cinfo, JPOOL_PERMANENT, sizeof(struct jpeg_source_mgr));
  cinfo.src->init_source = jpg_init_source;
  cinfo.src->fill_input_buffer = jpg_fill_input_buffer;
  cinfo.src->skip_input_data = jpg_skip_input_data;
  cinfo.src->resync_to_restart = jpeg_resync_to_restart;
  cinfo.src->term_source = jpg_term_source;
  cinfo.src->bytes_in_buffer = 0;
  cinfo.src->next_input_byte = (unsigned char *)data;

  jpg_allow_partial_decode = 1;
  if (setjmp(jerr.setjmp_buffer)) {
    result.valid = false;
    goto boundary_decode_done;
  }
  if (jpeg_read_header(&cinfo, TRUE) != JPEG_HEADER_OK) {
    goto boundary_decode_done;
  }
  cinfo.scale_num = 1;
  cinfo.scale_denom = scale_denom;
  cinfo.out_color_space = JCS_RGB;
  cinfo.do_fancy_upsampling = FALSE;
  cinfo.dct_method = JDCT_IFAST;
  jpeg_start_decompress(&cinfo);

  {
    JDIMENSION stride = cinfo.output_width * cinfo.output_components;
    uint64_t allocation = (uint64_t)stride * cinfo.output_height;
    uint8_t *previous;
    uint8_t *current;

    if (allocation == 0 || allocation > 64ULL * 1024 * 1024
        || stride != prefix_stride
        || (uint64_t)stride * 2 > SIZE_MAX) {
      goto boundary_decode_done;
    }
    row_storage = (uint8_t *)malloc((size_t)stride * 2);
    check_memory_allocation((void *)row_storage, __LINE__, __FILE__,
                            "jpg_boundary_rows");
    previous = (uint8_t *)row_storage;
    current = previous + stride;
    if (checkpoint_sensitive && jpg_reassembly_checkpoint_requested()) {
      goto boundary_decode_done;
    }
    {
      JSAMPROW row = previous;

      if (jpeg_read_scanlines(&cinfo, &row, 1) != 1) {
        goto boundary_decode_done;
      }
      decoded_rows = 1;
    }

    while (cinfo.output_scanline < cinfo.output_height
           && decoded_rows < prefix_rows) {
      JSAMPROW row = current;
      double pair_mad;

      if (checkpoint_sensitive
          && (cinfo.output_scanline & 31u) == 0
          && jpg_reassembly_checkpoint_requested()) {
        goto boundary_decode_done;
      }
      if (jpeg_read_scanlines(&cinfo, &row, 1) != 1) {
        break;
      }
      pair_mad = jpg_row_mad(previous, current, stride);
      if (!boundary_found
          && jpg_row_mad(prefix + (uint64_t)decoded_rows * prefix_stride,
                         current, stride)
                 >= 0.5) {
        double baseline = 0.0;

        result.boundary_row = decoded_rows;
        result.seam_mad = pair_mad;
        for (uint32_t sample = 0; sample < recent_count; sample++) {
          baseline += recent_mad[sample];
        }
        if (recent_count > 0) {
          baseline /= recent_count;
        }
        result.baseline_mad = baseline;
        result.normalized =
            pair_mad / (baseline > 1.0 ? baseline : 1.0);
        boundary_found = true;
      }
      else if (!boundary_found) {
        recent_mad[recent_next] = pair_mad;
        recent_next = (recent_next + 1) % 8;
        if (recent_count < 8) {
          recent_count++;
        }
      }
      decoded_rows++;
      {
        uint8_t *swap = previous;

        previous = current;
        current = swap;
      }
    }
    while (cinfo.output_scanline < cinfo.output_height) {
      JSAMPROW row = current;

      if (checkpoint_sensitive
          && (cinfo.output_scanline & 31u) == 0
          && jpg_reassembly_checkpoint_requested()) {
        goto boundary_decode_done;
      }
      if (jpeg_read_scanlines(&cinfo, &row, 1) != 1) {
        break;
      }
    }
    result.valid = boundary_found && decoded_rows >= 3;
  }
  jpeg_abort_decompress(&cinfo);

boundary_decode_done:
  jpg_allow_partial_decode = 0;
  free((void *)row_storage);
  jpeg_destroy_decompress(&cinfo);
  {
    JpgBoundaryScore output;

    output.valid = result.valid;
    output.boundary_row = result.boundary_row;
    output.seam_mad = result.seam_mad;
    output.baseline_mad = result.baseline_mad;
    output.normalized = result.normalized;
    return output;
  }
}

static inline JpgBoundaryScore jpg_boundary_score_scaled(
    char *data,
    uint64_t prefix_length,
    uint64_t full_length,
    unsigned int scale_denom,
    bool checkpoint_sensitive) {
  JpgBoundaryScore result;
  JDIMENSION prefix_stride = 0;
  JDIMENSION prefix_rows = 0;
  uint8_t *prefix = NULL;
  bool cached_prefix = false;

  memset(&result, 0, sizeof(result));
  if (checkpoint_sensitive && jpg_reassembly_checkpoint_requested()) {
    return result;
  }
  if (jpg_boundary_preview_cache
      && jpg_boundary_preview_cache->data == data
      && jpg_boundary_preview_cache->pixels
      && jpg_boundary_preview_cache->prefix_length == prefix_length
      && jpg_boundary_preview_cache->scale_denom == scale_denom) {
    prefix = jpg_boundary_preview_cache->pixels;
    prefix_stride = jpg_boundary_preview_cache->stride;
    prefix_rows = jpg_boundary_preview_cache->rows;
    cached_prefix = true;
  }
  else {
    prefix = jpg_decode_preview_scaled(data, prefix_length, scale_denom,
                                       checkpoint_sensitive,
                                       &prefix_stride, &prefix_rows);
    if (jpg_boundary_preview_cache && prefix) {
      jpg_boundary_preview_cache_invalidate();
      jpg_boundary_preview_cache->data = data;
      jpg_boundary_preview_cache->pixels = prefix;
      jpg_boundary_preview_cache->prefix_length = prefix_length;
      jpg_boundary_preview_cache->scale_denom = scale_denom;
      jpg_boundary_preview_cache->stride = prefix_stride;
      jpg_boundary_preview_cache->rows = prefix_rows;
      cached_prefix = true;
    }
  }
  if (!prefix || prefix_stride == 0 || prefix_rows < 3) {
    goto boundary_done;
  }
  if (checkpoint_sensitive && jpg_reassembly_checkpoint_requested()) {
    goto boundary_done;
  }
  result = jpg_decode_boundary_scaled(data, full_length, scale_denom,
                                      checkpoint_sensitive,
                                      prefix, prefix_stride, prefix_rows);

boundary_done:
  if (!cached_prefix) {
    free(prefix);
  }
  return result;
}

static inline JpgBoundaryScore jpg_boundary_score(char *data,
                                                  uint64_t prefix_length,
                                                  uint64_t full_length) {
  return jpg_boundary_score_scaled(data, prefix_length, full_length, 8,
                                   false);
}

static inline uint64_t jpg_huffman_trusted_validates_to(
    const JPGHuffmanCheckpoint *save,
    uint64_t previous_validates_to,
    uint64_t previous_checkpoint_pos) {
  if (!save || !save->valid || save->byte_pos == 0) {
    return previous_validates_to;
  }

  if (save->byte_pos <= previous_checkpoint_pos) {
    return previous_validates_to;
  }

  return save->byte_pos - 1;
}

// a full zero block is unavailable to reassembly because the blockmap covers it.
static const uint64_t jpg_zero_run_min_blocks = 1;

static inline bool jpg_block_is_all_zero(const char *data,
                                         uint64_t block_start,
                                         uint32_t blocksize,
                                         uint64_t length) {
  if (!data || blocksize == 0 || block_start + blocksize > length) {
    return false;
  }

  for (uint32_t i = 0; i < blocksize; i++) {
    if ((uint8_t)data[block_start + i] != 0) {
      return false;
    }
  }

  return true;
}

static inline uint64_t jpg_relocate_error_over_zero_run(const char *data,
                                                        uint64_t length,
                                                        uint32_t blocksize,
                                                        uint64_t entropy_start,
                                                        uint64_t error_pos) {
  uint64_t error_block;
  uint64_t entropy_block;
  uint64_t first_zero_block = UINT64_MAX;
  uint64_t zero_blocks = 0;

  if (!data || blocksize == 0 || error_pos == 0 || error_pos >= length) {
    return error_pos;
  }

  error_block = error_pos / blocksize;
  entropy_block = entropy_start / blocksize;
  if (error_block == 0 || error_block <= entropy_block) {
    return error_pos;
  }

  for (uint64_t blk = error_block; blk > entropy_block; ) {
    uint64_t candidate_block = blk - 1;
    uint64_t block_start = candidate_block * blocksize;

    if (!jpg_block_is_all_zero(data, block_start, blocksize, length)) {
      break;
    }

    first_zero_block = candidate_block;
    zero_blocks++;
    blk = candidate_block;
  }

  if (zero_blocks < jpg_zero_run_min_blocks
      || first_zero_block == UINT64_MAX) {
    return error_pos;
  }

  return first_zero_block * blocksize;
}

static inline uint64_t jpg_find_interior_zero_run_after_prefix(const char *data,
                                                               uint64_t length,
                                                               uint32_t blocksize,
                                                               uint64_t prefix_validates_to,
                                                               uint64_t limit_pos) {
  uint64_t start_block;
  uint64_t limit_block;
  uint64_t run_start = UINT64_MAX;
  uint64_t run_len = 0;

  if (!data || blocksize == 0 || length < (uint64_t)blocksize * 2) {
    return 0;
  }

  if (limit_pos == 0 || limit_pos >= length) {
    limit_pos = length - 1;
  }

  start_block = CEILDIV(prefix_validates_to + 1, blocksize);
  limit_block = limit_pos / blocksize;
  if (start_block > limit_block) {
    return 0;
  }

  // include the block containing limit_pos because a decoder error can land inside the zero run.
  for (uint64_t blk = start_block; blk <= limit_block; blk++) {
    uint64_t block_start = blk * blocksize;
    if (jpg_block_is_all_zero(data, block_start, blocksize, length)) {
      if (run_start == UINT64_MAX) {
        run_start = blk;
        run_len = 1;
      }
      else {
        run_len++;
      }
    }
    else {
      if (run_len >= jpg_zero_run_min_blocks) {
        return run_start * blocksize;
      }
      run_start = UINT64_MAX;
      run_len = 0;
    }
  }

  if (run_len >= jpg_zero_run_min_blocks) {
    return run_start * blocksize;
  }

  return 0;
}

static inline uint64_t jpg_find_trailing_zero_run_start(const char *data,
                                                        uint64_t length,
                                                        uint32_t blocksize,
                                                        uint64_t entropy_start) {
  uint64_t run_start = 0;
  uint64_t full_blocks;

  if (!data || blocksize == 0 || length < (uint64_t)blocksize) {
    return 0;
  }

  full_blocks = length / blocksize;
  while (full_blocks > 0) {
    uint64_t blk = full_blocks - 1;
    uint64_t block_start = blk * (uint64_t)blocksize;

    if (block_start < entropy_start) {
      break;
    }
    if (!jpg_block_is_all_zero(data, block_start, blocksize, length)) {
      break;
    }

    run_start = block_start;
    full_blocks = blk;
  }

  return run_start;
}

static inline bool jpg_zero_run_meets_min_blocks(const char *data,
                                                 uint64_t length,
                                                 uint32_t blocksize,
                                                 uint64_t run_start_pos,
                                                 uint64_t min_blocks) {
  if (!data || blocksize == 0 || run_start_pos >= length || min_blocks == 0) {
    return false;
  }

  for (uint64_t i = 0; i < min_blocks; i++) {
    uint64_t block_start = run_start_pos + i * (uint64_t)blocksize;
    if (!jpg_block_is_all_zero(data, block_start, blocksize, length)) {
      return false;
    }
  }

  return true;
}

// OPUS47/J3: signature cleaned up — previously took trusted_validates_to
// and lib_validates_to but ignored both. The over-credit to (length-1)
// when Huffman is clean but libjpeg fails is intentional; reducing it
// caused a 3→29 Cat6 regression per project_cat6_validator_bugs. Keep
// the behavior but don't lie about the inputs.
static inline uint64_t jpg_huffman_clean_validates_to(uint64_t length) {
  return length > 0 ? length - 1 : 0;
}

static inline uint64_t jpg_promising_committed_length(uint64_t validates_to,
                                                      uint32_t blocksize) {
  if (blocksize == 0) {
    return validates_to + 1;
  }
  if (validates_to + 1 < blocksize) {
    return blocksize;
  }
  return ((validates_to + 1) / blocksize) * blocksize;
}

static inline uint32_t jpg_structural_prefix_blocks(uint64_t entropy_start,
                                                    uint32_t blocksize) {
  uint32_t blocks;

  if (blocksize == 0 || entropy_start == 0) {
    return 1;
  }

  blocks = (uint32_t)CEILDIV(entropy_start, blocksize);
  return blocks > 0 ? blocks : 1;
}

static inline uint32_t jpg_saved_fixed_prefix_blocks(const JPGCarveState *local_state,
                                                     uint32_t default_blocks,
                                                     uint32_t blocksize) {
  if (blocksize == 0) {
    return 1;
  }

  if (local_state && local_state->fixed_prefix_blocks > 0) {
    return local_state->fixed_prefix_blocks;
  }

  return default_blocks > 0 ? default_blocks : 1;
}

static inline uint32_t jpg_committed_prefix_blocks(uint64_t committed_length,
                                                   uint32_t blocksize) {
  if (blocksize == 0 || committed_length == 0) {
    return 1;
  }

  return (uint32_t)CEILDIV(committed_length, blocksize);
}

static inline void jpg_sanitize_resume_state(JPGCarveState *state,
                                             uint64_t length,
                                             uint32_t blocksize,
                                             bool allow_speculative_huff) {
  uint32_t max_hashed_blocks;

  if (!state || !state->valid) {
    return;
  }

  if (length > 0 && state->prev_length > length) {
    state->prev_length = length;
  }

  if (blocksize == 0) {
    if (length > 0 && state->prev_validates_to >= length) {
      state->prev_validates_to = length - 1;
    }
    return;
  }

  max_hashed_blocks = (uint32_t)CEILDIV(state->checkpoint_pos, blocksize);
  if (max_hashed_blocks == 0 && length >= blocksize) {
    max_hashed_blocks = 1;
  }
  if (state->fixed_prefix_blocks > max_hashed_blocks) {
    state->fixed_prefix_blocks = max_hashed_blocks;
  }

  if (state->huff_checkpoint.valid
      && (state->huff_checkpoint.byte_pos > length
          || (!allow_speculative_huff
              && state->huff_checkpoint.byte_pos > state->checkpoint_pos)
          || (allow_speculative_huff
              && state->huff_checkpoint.byte_pos > state->prev_length))) {
    memset(&state->huff_checkpoint, 0, sizeof(JPGHuffmanCheckpoint));
  }

  if (!state->huff_checkpoint.valid && state->checkpoint_pos > 0
      && state->prev_validates_to >= state->checkpoint_pos) {
    state->prev_validates_to = state->checkpoint_pos - 1;
  }

  if (length > 0 && state->prev_validates_to >= length) {
    state->prev_validates_to = length - 1;
  }
}

static inline uint32_t jpg_initial_prefix_blocks(const JPGCarveState *local_state,
                                                 uint64_t length,
                                                 uint32_t blocksize) {
  if (local_state && local_state->fixed_prefix_blocks > 0) {
    return local_state->fixed_prefix_blocks;
  }
  if (local_state && local_state->had_scan && local_state->entropy_start > 0) {
    return jpg_structural_prefix_blocks(local_state->entropy_start, blocksize);
  }
  // A one-block committed prefix is too weak for JPEG reassembly. Once the
  // generic promising trim in carve.c collapses a fresh candidate to a single
  // block, resumed validation loses crucial header/table context and starts
  // exploring detached suffixes. When at least two full blocks are present,
  // preserve a two-block seed by default.
  if (blocksize > 0 && length >= (uint64_t)blocksize * 2) {
    return 2;
  }
  return 1;
}

// jpg_ff_prescreen — check blocks for non-JPEG data via 0xFF analysis.
// Returns truncated length (blocks after bad data removed), or original length if clean.
// start_blk allows skipping already-validated prefix blocks.
// had_scan: true if a SOS marker has been found in the validated prefix.
// Entropy-specific rules (invalid byte stuffing) are only applied when
// had_scan is true, preventing false truncation of metadata-heavy files
// where APP1/ICC/etc. spans many blocks before entropy data begins.
// Scan forward for either EOI or an 0xFF followed by a byte in [0x02, 0xBF].
// The latter is invalid inside entropy data. Returns the file byte offset of
// the first event, or 0 if neither event occurs in [start, end).
static inline uint64_t jpg_ff_find_invalid_marker(const uint8_t *data,
                                                  uint64_t start,
                                                  uint64_t end,
                                                  bool *saw_eoi) {
  *saw_eoi = false;
  if (end < 2 || start + 1 >= end) {
    return 0;
  }
  for (uint64_t i = start; i + 1 < end; i++) {
    if (data[i] == 0xFF) {
      uint8_t next = data[i + 1];
      if (next == M_EOI) {
        *saw_eoi = true;
        return i;
      }
      if (next >= 0x02 && next <= 0xBF) {
        return i;
      }
    }
  }
  return 0;
}

// OPUS47/J11: rewritten prescreen. The previous implementation treated
// EVERY block as entropy once `had_scan` was set anywhere in the file,
// producing false positives on legitimate 0xFF<data> sequences in DQT,
// DHT and APP-segment data that appear *before* SOS. The fix: only treat
// bytes at file positions >= entropy_start as entropy. Blocks entirely
// before entropy_start (header/segment data) are skipped; the block
// straddling SOS only has its entropy suffix scanned. If the caller
// could not locate SOS and passes entropy_start_byte == 0, we skip the
// entropy rule entirely (safer than false positives).
static inline uint64_t jpg_ff_prescreen(const char *data, uint64_t length, uint32_t blocksize,
                                        uint64_t start_blk, uint64_t entropy_start_byte) {
  uint64_t event_pos = 0;
  uint64_t scan_limit = length;
  bool saw_eoi = false;

  if (blocksize == 0 || length <= blocksize) {
    return length;
  }

  uint64_t num_blocks = length / blocksize;
  if (entropy_start_byte > 0 && length > entropy_start_byte) {
    uint64_t scan_start = start_blk * (uint64_t)blocksize;

    if (scan_start < entropy_start_byte) {
      scan_start = entropy_start_byte;
    }
    event_pos = jpg_ff_find_invalid_marker((const uint8_t *)data,
                                           scan_start, length, &saw_eoi);
    if (event_pos > 0) {
      scan_limit = event_pos;
    }
  }

  for (uint64_t blk = start_blk; blk < num_blocks; blk++) {
    uint64_t block_start = blk * (uint64_t)blocksize;
    uint64_t block_end = block_start + blocksize;

    if (block_start >= scan_limit) {
      break;
    }
    if (block_end > length) {
      block_end = length;
    }
    const uint8_t *block_data = (const uint8_t *)data + block_start;

    // A block-aligned SOI after the outer scan begins marks the start of a
    // different JPEG. SOI signatures before SOS may belong to thumbnails
    // embedded in APP metadata and must not split the enclosing image.
    if (blk > 0 && entropy_start_byte > 0
        && block_start >= entropy_start_byte
        && block_end >= block_start + 2
        && block_data[0] == 0xFF && block_data[1] == 0xD8) {
      return block_start;
    }
  }

  if (saw_eoi) {
    return length;
  }
  if (event_pos > 0) {
    // Truncate at the block containing the invalid marker so downstream keeps
    // the prior validated prefix.
    return (event_pos / blocksize) * blocksize;
  }
  return length;
}

// jpg_save_header_to_state — copy parsed header info from JpgValidationContext into JPGCarveState.
static inline void jpg_save_header_to_state(JPGCarveState *state, JpgValidationContext *ctx) {
  state->have_sof = ctx->have_sof;
  state->is_progressive = ctx->is_progressive;
  state->precision = ctx->precision;
  state->height = ctx->height;
  state->width = ctx->width;
  state->num_components = ctx->num_components;
  memcpy(state->components, ctx->components, sizeof(ctx->components));
  state->max_h_samp = ctx->max_h_samp;
  state->max_v_samp = ctx->max_v_samp;
  memcpy(state->dc_tables, ctx->dc_tables, sizeof(ctx->dc_tables));
  memcpy(state->ac_tables, ctx->ac_tables, sizeof(ctx->ac_tables));
  memcpy(state->quant_defined, ctx->quant_defined, sizeof(ctx->quant_defined));
  state->restart_interval = ctx->restart_interval;
  state->scan_components = ctx->scan_components;
  memcpy(state->scan_comp, ctx->scan_comp, sizeof(ctx->scan_comp));
  state->ss = ctx->ss;
  state->se = ctx->se;
  state->ah = ctx->ah;
  state->al = ctx->al;
  state->had_scan = ctx->had_scan;
  state->scan_count = ctx->scan_count;
  // Use parser-tracked entropy start if available; avoid raw scan.
  state->entropy_start = ctx->entropy_start;
}

// jpg_restore_header_from_state — populate JpgValidationContext from cached JPGCarveState.
static inline void jpg_restore_header_from_state(JpgValidationContext *ctx, const JPGCarveState *state) {
  ctx->have_sof = state->have_sof;
  ctx->is_progressive = state->is_progressive;
  ctx->precision = state->precision;
  ctx->height = state->height;
  ctx->width = state->width;
  ctx->num_components = state->num_components;
  memcpy(ctx->components, state->components, sizeof(state->components));
  ctx->max_h_samp = state->max_h_samp;
  ctx->max_v_samp = state->max_v_samp;
  memcpy(ctx->dc_tables, state->dc_tables, sizeof(state->dc_tables));
  memcpy(ctx->ac_tables, state->ac_tables, sizeof(state->ac_tables));
  memcpy(ctx->quant_defined, state->quant_defined, sizeof(state->quant_defined));
  ctx->restart_interval = state->restart_interval;
  ctx->scan_components = state->scan_components;
  memcpy(ctx->scan_comp, state->scan_comp, sizeof(state->scan_comp));
  ctx->ss = state->ss;
  ctx->se = state->se;
  ctx->ah = state->ah;
  ctx->al = state->al;
  ctx->had_scan = state->had_scan;
  ctx->scan_count = state->scan_count;
  ctx->entropy_start = state->entropy_start;
}


static inline void jpg_validate_core(char *data, uint64_t length, bool *validates, uint64_t *validates_to, bool *promising,
                                     uint32_t needleidx, uint32_t blocksize, void *carvehashkey,
                                     JPGCarveState *direct_state) {
  (void)needleidx;
  *validates = false;
  *validates_to = 0;
  *promising = false;

  // Reset per-call state that persists in thread-local storage.
  // Without this, one file's observed DC range or threshold can
  // contaminate validation of subsequent files on the same thread.
  jpg_dc_threshold = 2000;
  jpg_max_observed_dc_diff = 0;
  memset(&jpg_mcu_result, 0, sizeof(jpg_mcu_result));
  memset(&jpg_wrongblock_result, 0, sizeof(jpg_wrongblock_result));
  if (length < 4) {
    return;
  }

  // ---- Carve state restore: check for saved state from previous validation call ----
  // Keep each trial's decoder state on the stack to avoid per-call allocation.
  bool restored = false;
  JPGCarveState local_state_storage;
  memset(&local_state_storage, 0, sizeof(local_state_storage));
  JPGCarveState *local_state = &local_state_storage;

  if (direct_state) {
    // Direct state path: read from direct_state, no hash table access
    if (direct_state->valid && direct_state->checkpoint_pos > 0) {
      if (direct_state->checkpoint_pos > 0 && direct_state->checkpoint_pos <= length) {
        uint64_t hash = XXH3_64bits(data, direct_state->checkpoint_pos);
        if (hash == direct_state->prefix_hash) {
          memcpy(local_state, direct_state, sizeof(JPGCarveState));
          jpg_sanitize_resume_state(local_state, length, blocksize, true);
          restored = true;
        }
      }
      else if (length < direct_state->prev_length && blocksize > 0) {
        uint64_t trim_ckpt = (length / blocksize) * blocksize;
        if (trim_ckpt >= blocksize && trim_ckpt <= direct_state->checkpoint_pos) {
          uint64_t hash = XXH3_64bits(data, trim_ckpt);
          memcpy(local_state, direct_state, sizeof(JPGCarveState));
          local_state->checkpoint_pos = trim_ckpt;
          local_state->prefix_hash = hash;
          local_state->prev_validates_to = trim_ckpt > 0 ? trim_ckpt - 1 : 0;
          local_state->prev_length = length;
          memset(&local_state->huff_checkpoint, 0, sizeof(JPGHuffmanCheckpoint));
          jpg_sanitize_resume_state(local_state, length, blocksize, false);
          restored = true;
          // Write trimmed state back directly
          memcpy(direct_state, local_state, sizeof(JPGCarveState));
        }
      }
    }
  }
  else if (carvehashkey) {
    JPGCarveState *saved = (JPGCarveState *)jpg_get_decoder_state(carvehashkey);
    if (saved && saved->valid && saved->checkpoint_pos > 0) {
      if (saved->checkpoint_pos <= length) {
        // Normal case: checkpoint is within current data
        uint64_t hash = XXH3_64bits(data, saved->checkpoint_pos);
        if (hash == saved->prefix_hash) {
          memcpy(local_state, saved, sizeof(JPGCarveState));
          jpg_sanitize_resume_state(local_state, length, blocksize, false);
          restored = true;
        }
      }
      else if (length < saved->prev_length && blocksize > 0) {
        // Trim case: blockvector was shortened. Try to restore at a smaller
        // checkpoint aligned to block boundary within current data.
        uint64_t trim_ckpt = (length / blocksize) * blocksize;
        if (trim_ckpt >= blocksize && trim_ckpt <= saved->checkpoint_pos) {
          uint64_t hash = XXH3_64bits(data, trim_ckpt);
          // Recompute hash — we can only restore if the prefix up to trim_ckpt
          // is still valid. Save header but invalidate Huffman checkpoint
          // (bitstream state beyond trim_ckpt is unknown).
          memcpy(local_state, saved, sizeof(JPGCarveState));
          local_state->checkpoint_pos = trim_ckpt;
          local_state->prefix_hash = hash;
          local_state->prev_validates_to = trim_ckpt > 0 ? trim_ckpt - 1 : 0;
          local_state->prev_length = length;
          memset(&local_state->huff_checkpoint, 0, sizeof(JPGHuffmanCheckpoint));
          jpg_sanitize_resume_state(local_state, length, blocksize, false);
          restored = true;
          // Save the trimmed state back so future calls see the trimmed checkpoint
          jpg_put_decoder_state(carvehashkey, local_state);
        }
      }
    }
    free(saved);
  }

  if (restored) {
    jpg_max_observed_dc_diff = local_state->max_observed_dc_diff;
    if (jpg_validate_debug_enabled()) {
      lock_fprintf(stderr,
                   "[jpgvdbg] restore len=%" PRIu64 " ckpt=%" PRIu64
                   " prev=%" PRIu64 " prevlen=%" PRIu64
                   " huff_valid=%d huff_byte=%" PRIu64
                   " fixed=%" PRIu32 " direct=%d\n",
                   length,
                   local_state->checkpoint_pos,
                   local_state->prev_validates_to,
                   local_state->prev_length,
                   local_state->huff_checkpoint.valid ? 1 : 0,
                   local_state->huff_checkpoint.byte_pos,
                   local_state->fixed_prefix_blocks,
                   direct_state ? 1 : 0);
    }
  }

  // ---- 0xFF pre-screening: skip prefix blocks if restored ----
  uint64_t prescreen_start = (restored && blocksize > 0) ? (local_state->checkpoint_pos / blocksize) : 0;
  // OPUS47/J11: compute entropy_start_byte (byte offset where entropy data
  // begins, i.e. just past the SOS segment). Pass that to the prescreen so
  // it only flags invalid 0xFF<data> sequences in the entropy stream, not
  // in header segments (DQT/DHT/APP) where 0xFF followed by data bytes is
  // legitimate payload. Previous `had_scan` bool mis-classified header
  // blocks as entropy when SOS existed anywhere in the file.
  uint64_t prescreen_entropy_start = 0;
  if (restored && local_state->entropy_start > 0) {
    prescreen_entropy_start = local_state->entropy_start;
  }
  else if (length >= 4 && (uint8_t)data[0] == 0xFF && (uint8_t)data[1] == M_SOI) {
    // OPUS47/J13: walk markers properly from SOI instead of a naive byte
    // scan for 0xFF 0xDA. The byte scan hit false matches inside APP
    // segment data (EXIF/ICC/XMP often contains 0xFF 0xDA as literal
    // bytes), producing a bogus entropy_start that made the prescreen
    // truncate valid progressive JPEGs at block 1. Proper marker walk
    // skips each segment's length correctly and identifies the real SOS.
    uint64_t pos = 2;
    uint64_t scan_limit = length < 65536 ? length : 65536;
    while (pos + 3 < scan_limit) {
      // Skip fill bytes; a marker is introduced by one or more 0xFFs.
      if ((uint8_t)data[pos] != 0xFF) { break; }
      while (pos < scan_limit && (uint8_t)data[pos] == 0xFF) { pos++; }
      if (pos >= scan_limit) { break; }
      uint8_t marker = (uint8_t)data[pos++];
      // Standalone markers (no length field).
      if (marker == 0x00 || marker == M_SOI || marker == M_EOI
          || (marker >= 0xD0 && marker <= 0xD7)) {
        continue;
      }
      if (pos + 1 >= scan_limit) { break; }
      uint16_t seg_len = ((uint16_t)(uint8_t)data[pos] << 8)
                        | (uint16_t)(uint8_t)data[pos + 1];
      if (seg_len < 2) { break; }  // malformed
      if (marker == M_SOS) {
        if (pos + seg_len <= length) {
          prescreen_entropy_start = pos + seg_len;
        }
        break;
      }
      pos += seg_len;
    }
  }
  uint64_t original_length = length;  // save for floor before early return
  length = jpg_ff_prescreen(data, length, blocksize, prescreen_start, prescreen_entropy_start);
  if (length < 4) {
    // Apply floor: never discard a candidate that has at least one block.
    // Without this, the floor at end-of-function is bypassed entirely.
    if (blocksize > 0 && original_length >= (uint64_t)blocksize) {
      *validates_to = blocksize - 1;
      *promising = true;
    }
    return;
  }

  // ---- Fast path: restored state + Huffman-only validation ----
  // When the prefix is unchanged, skip structural validation and libjpeg.
  // Use Huffman validation resumed from checkpoint to validate new blocks.
  if (restored && local_state->have_sof && local_state->had_scan
      && !local_state->is_progressive) {
    jpg_current_blocksize = blocksize;
    uint64_t trusted_validates_to = local_state->prev_validates_to;
    uint32_t initial_prefix_blocks =
        jpg_initial_prefix_blocks(local_state, length, blocksize);
    uint64_t initial_prefix_validates_to = 0;
    uint64_t structural_validates_to = 0;
    uint64_t zero_run_prefix_validates_to = 0;

    if (blocksize > 0 && initial_prefix_blocks > 0) {
      initial_prefix_validates_to =
          (uint64_t)initial_prefix_blocks * blocksize - 1;
      if (length > 0 && initial_prefix_validates_to >= length) {
        initial_prefix_validates_to = length - 1;
      }
    }
    if (blocksize > 0 && local_state->entropy_start > 0) {
      structural_validates_to =
          (uint64_t)jpg_structural_prefix_blocks(local_state->entropy_start,
                                                 blocksize) * blocksize - 1;
      if (length > 0 && structural_validates_to >= length) {
        structural_validates_to = length - 1;
      }
    }
    // Whole zero blocks are legal inside marker metadata. Treat them as gap
    // evidence only after the complete structural prefix containing SOS.
    zero_run_prefix_validates_to =
        initial_prefix_validates_to > structural_validates_to
            ? initial_prefix_validates_to
            : structural_validates_to;
    if (local_state->prev_validates_to > zero_run_prefix_validates_to) {
      zero_run_prefix_validates_to = local_state->prev_validates_to;
    }

    // Tighten the DC continuity check based on the trusted prefix. The
    // observed range is persisted in carve state so resumed validations use
    // the same prefix-derived threshold instead of the permissive default.
    if (local_state->max_observed_dc_diff > 0) {
      int32_t adaptive = local_state->max_observed_dc_diff * 3;
      if (adaptive < 200) adaptive = 200;
      jpg_dc_threshold = adaptive;
    }
    else {
      jpg_dc_threshold = 2000;
    }

    // Restore header into validation context
    JpgValidationContext ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.data = (const uint8_t *)data;
    ctx.length = length;
    jpg_restore_header_from_state(&ctx, local_state);

    // Resume Huffman from checkpoint
    JPGHuffmanCheckpoint huff_save;
    JPGHuffmanCheckpoint *huff_restore = local_state->huff_checkpoint.valid
                                         ? &local_state->huff_checkpoint : NULL;
    JpgHuffmanFailure huffman_failure;
    uint64_t huffman_error_pos =
        jpg_huffman_validate(&ctx, huff_restore, &huff_save,
                             &huffman_failure, NULL);
    trusted_validates_to = jpg_huffman_trusted_validates_to(
        &huff_save, trusted_validates_to, local_state->checkpoint_pos);


    if (huffman_error_pos > 0) {
      huffman_error_pos = jpg_relocate_error_over_zero_run(data, length,
                                                           blocksize,
                                                           local_state->entropy_start,
                                                           huffman_error_pos);
      {
        uint64_t zero_run_pos =
            jpg_find_interior_zero_run_after_prefix(data, length, blocksize,
                                                    zero_run_prefix_validates_to,
                                                    huffman_error_pos);
        if (zero_run_pos > 0 && zero_run_pos < huffman_error_pos) {
          huffman_error_pos = zero_run_pos;
        }
      }
      if (!jpg_wrongblock_result.detected
          || huffman_error_pos < jpg_wrongblock_result.estimated_byte) {
        jpg_wrongblock_result.detected = true;
        jpg_wrongblock_result.estimated_byte = huffman_error_pos;
        jpg_wrongblock_result.confidence =
            jpg_huffman_failure_is_hard(huffman_failure) ? 100.0 : 75.0;
        jpg_wrongblock_result.method =
            jpg_huffman_failure_method(huffman_failure);
      }
      *validates = false;
      *validates_to = huffman_error_pos - 1;
      *promising = true;
    }
    else {
      bool lib_validates = false;
      bool lib_promising = false;
      uint64_t lib_validates_to = 0;
      uint64_t validated_zero_run_pos = 0;

      // libjpeg is authoritative for final validation, but a candidate with no
      // EOI after the trusted prefix cannot be final.
      if (jpg_range_may_contain_eoi(data, local_state->checkpoint_pos,
                                    length)) {
        jpg_libjpeg_validate(data, length, &lib_validates,
                             &lib_validates_to, &lib_promising,
                             needleidx, blocksize, carvehashkey);
      }
      if (lib_validates) {
        validated_zero_run_pos =
            jpg_find_interior_zero_run_after_prefix(
                data, length, blocksize, zero_run_prefix_validates_to,
                lib_validates_to);
      }
      if (validated_zero_run_pos > 0) {
        // a zero filesystem block cannot be part of a recoverable entropy
        // stream because the blockmap makes it unavailable to reassembly.
        *validates = false;
        *validates_to = validated_zero_run_pos - 1;
        *promising = true;
      }
      else if (lib_validates
               && jpg_validates_to_real_eoi(data, length,
                                            lib_validates_to)) {
        *validates = true;
        *validates_to = lib_validates_to;
        *promising = false;
      }
      else {
        uint64_t zero_run_pos =
            jpg_find_interior_zero_run_after_prefix(
                data, length, blocksize,
                zero_run_prefix_validates_to,
                length - 1);
        uint64_t trailing_zero_pos =
            jpg_find_trailing_zero_run_start(data, length, blocksize,
                                             local_state->entropy_start);
        *validates = false;
        *promising = true;
        if (zero_run_pos > 0) {
          *validates_to = zero_run_pos - 1;
        }
        else if (trailing_zero_pos > 0) {
          *validates_to = trailing_zero_pos - 1;
        }
        else {
          *validates_to = jpg_huffman_clean_validates_to(length);
        }
      }
    }

    // Save updated validator checkpoint state. If Huffman resume did not
    // advance, preserve the previously restored checkpoint fields.
    if ((direct_state || carvehashkey) && blocksize > 0 && *validates_to > 0) {
      uint64_t ckpt_pos = ((*validates_to + 1) / blocksize) * blocksize;
      int32_t cumulative_dc_max = local_state->max_observed_dc_diff;
      uint32_t fixed_prefix_blocks = jpg_initial_prefix_blocks(local_state, length, blocksize);
      uint32_t structural_prefix_blocks =
          jpg_structural_prefix_blocks(ctx.entropy_start, blocksize);
      bool canonical_promising_state =
          (!direct_state && !*validates
           && (*promising || *validates_to + 1 < length));
      uint64_t save_length = ckpt_pos;
      uint64_t save_prev_validates_to = *validates_to;
      uint32_t save_fixed_prefix_blocks = fixed_prefix_blocks;
      const JPGHuffmanCheckpoint *save_huff_checkpoint = NULL;

      if (fixed_prefix_blocks < structural_prefix_blocks) {
        fixed_prefix_blocks = structural_prefix_blocks;
      }
      save_fixed_prefix_blocks = fixed_prefix_blocks;

      if (jpg_max_observed_dc_diff > cumulative_dc_max) {
        cumulative_dc_max = jpg_max_observed_dc_diff;
      }
      if (canonical_promising_state) {
        save_length = jpg_promising_committed_length(*validates_to, blocksize);
        if (save_length > length) {
          save_length = length;
        }
        save_prev_validates_to = save_length > 0 ? save_length - 1 : 0;
        save_fixed_prefix_blocks =
            jpg_saved_fixed_prefix_blocks(local_state, fixed_prefix_blocks, blocksize);
        if (jpg_committed_prefix_blocks(save_length, blocksize) > save_fixed_prefix_blocks) {
          save_fixed_prefix_blocks = jpg_committed_prefix_blocks(save_length, blocksize);
        }
        if (huff_save.valid && huff_save.byte_pos <= save_length) {
          save_huff_checkpoint = &huff_save;
        }
        else if (local_state->huff_checkpoint.valid
                 && local_state->huff_checkpoint.byte_pos <= save_length) {
          save_huff_checkpoint = &local_state->huff_checkpoint;
        }
      }
      else {
        save_length = ckpt_pos;
        save_prev_validates_to = *validates_to;
        save_fixed_prefix_blocks = fixed_prefix_blocks;
        if (huff_save.valid) {
          save_huff_checkpoint = &huff_save;
        }
        else if (local_state->huff_checkpoint.valid) {
          save_huff_checkpoint = &local_state->huff_checkpoint;
        }
      }
      if ((direct_state && *validates_to + 1 >= blocksize)
          || (save_length >= blocksize
              && (save_length > local_state->checkpoint_pos
                  || (!local_state->huff_checkpoint.valid
                      && save_huff_checkpoint)))) {
        if (direct_state) {
          uint64_t direct_save_length = *validates_to + 1;

          if (direct_save_length > length) {
            direct_save_length = length;
          }
          if (direct_save_length == 0) {
            direct_save_length = save_length;
          }
          // Direct state path: write fields directly.
          direct_state->valid = true;
          direct_state->checkpoint_pos = direct_save_length;
          direct_state->prefix_hash = XXH3_64bits(data, direct_save_length);
          direct_state->prev_validates_to = *validates_to;
          direct_state->prev_length = length;
          direct_state->prev_validates = *validates;
          direct_state->max_observed_dc_diff = cumulative_dc_max;
          direct_state->fixed_prefix_blocks = fixed_prefix_blocks;
          direct_state->reassembly_seed_checked =
              local_state->reassembly_seed_checked;
          direct_state->reassembly_seed_needs_search =
              local_state->reassembly_seed_needs_search;
          memcpy(&direct_state->run_order_progress,
                 &local_state->run_order_progress,
                 sizeof(direct_state->run_order_progress));
          direct_state->footer_tail_progress = local_state->footer_tail_progress;
          direct_state->forward_scan_progress = local_state->forward_scan_progress;
          jpg_save_header_to_state(direct_state, &ctx);
          if (huff_save.valid && huff_save.byte_pos <= length) {
            memcpy(&direct_state->huff_checkpoint, &huff_save,
                   sizeof(JPGHuffmanCheckpoint));
          }
          else if (local_state->huff_checkpoint.valid
                   && local_state->huff_checkpoint.byte_pos <= length) {
            memcpy(&direct_state->huff_checkpoint, &local_state->huff_checkpoint,
                   sizeof(JPGHuffmanCheckpoint));
          }
          else {
            memset(&direct_state->huff_checkpoint, 0, sizeof(JPGHuffmanCheckpoint));
          }
        }
        else {
          JPGCarveState *save_state = (JPGCarveState *)calloc(1, sizeof(JPGCarveState));
          check_memory_allocation(save_state, __LINE__, __FILE__, "save_state");
          save_state->valid = true;
          save_state->checkpoint_pos = save_length;
          save_state->prefix_hash = XXH3_64bits(data, save_length);
          save_state->prev_validates_to = save_prev_validates_to;
          save_state->prev_length = canonical_promising_state ? save_length : length;
          save_state->prev_validates = *validates;
          save_state->max_observed_dc_diff = cumulative_dc_max;
          save_state->fixed_prefix_blocks = save_fixed_prefix_blocks;
          save_state->reassembly_seed_checked =
              local_state->reassembly_seed_checked;
          save_state->reassembly_seed_needs_search =
              local_state->reassembly_seed_needs_search;
          memcpy(&save_state->run_order_progress,
                 &local_state->run_order_progress,
                 sizeof(save_state->run_order_progress));
          save_state->footer_tail_progress = local_state->footer_tail_progress;
          save_state->forward_scan_progress = local_state->forward_scan_progress;
          jpg_save_header_to_state(save_state, &ctx);
          if (save_huff_checkpoint) {
            memcpy(&save_state->huff_checkpoint, save_huff_checkpoint,
                   sizeof(JPGHuffmanCheckpoint));
          }
          if (jpg_validate_debug_enabled()) {
            lock_fprintf(stderr,
                         "[jpgvdbg] save-fast len=%" PRIu64 " vt=%" PRIu64
                         " save_len=%" PRIu64 " prev=%" PRIu64
                         " prevlen=%" PRIu64 " huff_valid=%d huff_byte=%" PRIu64
                         " fixed=%" PRIu32 " canonical=%d\n",
                         length,
                         *validates_to,
                         save_state->checkpoint_pos,
                         save_state->prev_validates_to,
                         save_state->prev_length,
                         save_state->huff_checkpoint.valid ? 1 : 0,
                         save_state->huff_checkpoint.byte_pos,
                         save_state->fixed_prefix_blocks,
                         canonical_promising_state ? 1 : 0);
          }
          jpg_put_decoder_state(carvehashkey, save_state);
          free(save_state);
        }
      }
    }

    if (length > 0 && *validates_to >= length) {
      *validates_to = length - 1;
    }
    // Floor: fast path must also prevent validates_to from dropping below
    // blocksize-1, otherwise the BV shrinks to 0 blocks in LR_reassembly.
    if (! *validates && blocksize > 0 && original_length >= (uint64_t)blocksize
        && *validates_to < (uint64_t)blocksize - 1) {
      *validates_to = blocksize - 1;
      *promising = true;
    }

    return;
  }

  // ---- Full validation path (no usable carve state) ----
  JpgValidationContext ctx;
  memset(&ctx, 0, sizeof(ctx));
  ctx.data = (const uint8_t *)data;
  ctx.length = length;

  JpgValidationResult result = jpg_validate_structure(&ctx);
  if (result == JPG_VAL_OK || result == JPG_VAL_TRUNCATED) {
    bool lib_validates, lib_promising;
    uint64_t lib_validates_to;
    uint64_t trusted_validates_to = 0;
    uint64_t structural_validates_to = 0;
    uint32_t initial_prefix_blocks =
        jpg_initial_prefix_blocks(NULL, length, blocksize);
    uint64_t initial_prefix_validates_to = 0;
    uint64_t zero_run_prefix_validates_to = 0;
    uint64_t validated_zero_run_pos = 0;
    JpgEmbeddedJpegEvidence embedded_evidence;
    jpg_current_blocksize = blocksize;
    jpg_libjpeg_validate(data, length, &lib_validates, &lib_validates_to, &lib_promising, needleidx, blocksize, carvehashkey);

    JPGHuffmanCheckpoint huff_save;
    JpgHuffmanFailure huffman_failure;
    uint64_t huffman_error_pos =
        jpg_huffman_validate(&ctx, NULL, &huff_save,
                             &huffman_failure, NULL);
    embedded_evidence = jpg_embedded_exif_evidence(
        (const uint8_t *)data, length);
    trusted_validates_to =
        jpg_huffman_trusted_validates_to(&huff_save, 0, 0);
    if (blocksize > 0 && ctx.entropy_start > 0) {
      structural_validates_to =
          (uint64_t)jpg_structural_prefix_blocks(ctx.entropy_start, blocksize) * blocksize - 1;
      if (length > 0 && structural_validates_to >= length) {
        structural_validates_to = length - 1;
      }
    }
    if (blocksize > 0 && initial_prefix_blocks > 0) {
      initial_prefix_validates_to =
          (uint64_t)initial_prefix_blocks * blocksize - 1;
      if (length > 0 && initial_prefix_validates_to >= length) {
        initial_prefix_validates_to = length - 1;
      }
    }
    zero_run_prefix_validates_to =
        initial_prefix_validates_to > structural_validates_to
            ? initial_prefix_validates_to
            : structural_validates_to;
    if (lib_validates) {
      validated_zero_run_pos =
          jpg_find_interior_zero_run_after_prefix(
              data, length, blocksize, zero_run_prefix_validates_to,
              lib_validates_to);
    }

    // Record wrongblock info for diagnostic purposes
    if (huffman_error_pos > 0 && !lib_validates) {
      huffman_error_pos = jpg_relocate_error_over_zero_run(data, length,
                                                           blocksize,
                                                           ctx.entropy_start,
                                                           huffman_error_pos);
      {
        uint64_t zero_run_pos =
            jpg_find_interior_zero_run_after_prefix(data, length, blocksize,
                                                    zero_run_prefix_validates_to,
                                                    huffman_error_pos);
        if (zero_run_pos > 0 && zero_run_pos < huffman_error_pos) {
          huffman_error_pos = zero_run_pos;
        }
      }
      if (!jpg_wrongblock_result.detected || huffman_error_pos < jpg_wrongblock_result.estimated_byte) {
        jpg_wrongblock_result.detected = true;
        jpg_wrongblock_result.estimated_byte = huffman_error_pos;
        jpg_wrongblock_result.confidence =
            jpg_huffman_failure_is_hard(huffman_failure) ? 100.0 : 75.0;
        jpg_wrongblock_result.method =
            jpg_huffman_failure_method(huffman_failure);
      }
    }
    if (ctx.rst_seq_broken && ctx.rst_seq_error_pos > 0) {
      if (!jpg_wrongblock_result.detected || ctx.rst_seq_error_pos < jpg_wrongblock_result.estimated_byte) {
        jpg_wrongblock_result.detected = true;
        jpg_wrongblock_result.estimated_byte = ctx.rst_seq_error_pos;
        jpg_wrongblock_result.confidence = 100.0;
        jpg_wrongblock_result.method = "rst_sequence";
      }
    }
    if (embedded_evidence.hard_failure) {
      uint64_t embedded_error_pos = embedded_evidence.validates_to + 1;

      if (!jpg_wrongblock_result.detected
          || embedded_error_pos < jpg_wrongblock_result.estimated_byte) {
        jpg_wrongblock_result.detected = true;
        jpg_wrongblock_result.estimated_byte = embedded_error_pos;
        jpg_wrongblock_result.confidence = 100.0;
        jpg_wrongblock_result.method =
            embedded_evidence.huffman_failure
                    == JPG_HUFFMAN_FAILURE_RESTART_SEQUENCE
                ? "embedded_rst_sequence"
                : "embedded_huffman_invalid";
      }
    }

    // a hard failure in a declared embedded JPEG exposes corruption that the
    // outer marker parser cannot inspect while it is still inside APP data.
    if (embedded_evidence.hard_failure
        && (!ctx.rst_seq_broken
            || embedded_evidence.validates_to + 1
                   <= ctx.rst_seq_error_pos)) {
      *validates = false;
      *validates_to = embedded_evidence.validates_to;
      *promising = true;
      goto save_state;
    }

    // RST SEQUENCE CHECK: If RST markers are out of order, that PROVES wrong block
    if (ctx.rst_seq_broken && ctx.rst_seq_error_pos > 0) {
      *validates = false;
      *validates_to = ctx.rst_seq_error_pos > 0 ? ctx.rst_seq_error_pos - 1 : 0;
      *promising = true;
      if (jpg_validate_debug_enabled()) {
        lock_fprintf(stderr,
                     "[jpgvdbg] full len=%" PRIu64 " result=%d rst_broken=1 vt=%" PRIu64
                     " libv=%d libp=%d libvt=%" PRIu64 " huff_err=%" PRIu64
                     " trusted=%" PRIu64 " structural=%" PRIu64 " prefix=%" PRIu64
                     " mcu=%u/%u final=%" PRIu64 "\n",
                     length, result, *validates_to,
                     lib_validates ? 1 : 0, lib_promising ? 1 : 0, lib_validates_to,
                     huffman_error_pos, trusted_validates_to,
                     structural_validates_to, initial_prefix_validates_to,
                     jpg_mcu_result.mcu_count, jpg_mcu_result.expected_mcus,
                     jpg_mcu_result.final_byte_pos);
      }
      goto save_state;
    }

    // Scoring: use continuous ranking, not wrongblock position
    if (validated_zero_run_pos > 0) {
      // a zero filesystem block may decode as flat image data, but it must
      // be replaced before this candidate can be considered complete.
      *validates = false;
      *validates_to = validated_zero_run_pos - 1;
      *promising = true;
    }
    else if (lib_validates
        && !jpg_validates_to_real_eoi(data, length, lib_validates_to)) {
      // libjpeg injects an EOI for truncated input; that is useful progress
      // evidence, but it cannot establish that the carved file is complete.
      *validates = false;
      *validates_to = lib_validates_to;
      *promising = true;
    }
    else if (lib_validates) {
      if (ctx.has_mpf
          && ctx.mpf_primary_size > 0
          && ctx.mpf_compound_end > ctx.mpf_primary_size
          && lib_validates_to + 1 <= ctx.mpf_primary_size) {
        if (length < ctx.mpf_compound_end) {
          /*
           * MPF is advisory metadata. Editors sometimes leave stale MPF
           * offsets after rewriting the primary JPEG; a clean primary EOI
           * is stronger evidence than missing secondary MPF bytes.
           */
          if (jpg_validates_to_real_eoi(data, length, lib_validates_to)
              && jpg_tail_is_padding_only(data, lib_validates_to + 1, length)) {
            *validates = true;
            *validates_to = lib_validates_to;
            *promising = false;
          }
          else {
            *validates = false;
            *validates_to = length > 0 ? length - 1 : 0;
            *promising = true;
          }
        }
        else {
          /*
           * MPF gives the logical end of the compound object.
           * Trim at that boundary even when the remaining bytes are block
           * padding; otherwise validated block-aligned carves become
           * length-mismatch recoveries.
           */
          *validates = true;
          *promising = false;
          *validates_to =
              ctx.mpf_compound_end > 0 ? ctx.mpf_compound_end - 1 : 0;
        }
      }
      // A real EOI ends the JPEG even when its final disk block contains
      // unrelated bytes. Only contradictory entropy evidence may override
      // libjpeg's complete decode; continuity and magnitude checks are
      // ranking heuristics and cannot establish corruption on their own.
      else if (huffman_error_pos > 0
               && jpg_huffman_failure_is_hard(huffman_failure)
               && lib_validates_to + 1 < length
               && !jpg_tail_is_padding_only(data, lib_validates_to + 1, length)
               && lib_validates_to > huffman_error_pos + blocksize) {
        *validates = false;
        *validates_to = huffman_error_pos - 1;
        *promising = true;
      }
      else {
        *validates = true;
        *validates_to = lib_validates_to;
        *promising = false;
      }
    }
    else {
      *validates = false;
      *promising = lib_promising;
      if (huffman_error_pos > 0) {
        huffman_error_pos = jpg_relocate_error_over_zero_run(data, length,
                                                             blocksize,
                                                             ctx.entropy_start,
                                                             huffman_error_pos);
        {
          uint64_t zero_run_pos =
              jpg_find_interior_zero_run_after_prefix(data, length, blocksize,
                                                      zero_run_prefix_validates_to,
                                                      huffman_error_pos);
          if (zero_run_pos > 0 && zero_run_pos < huffman_error_pos) {
            huffman_error_pos = zero_run_pos;
          }
        }
        // During reassembly, libjpeg's farther decode remains useful as a
        // tentative search frontier when the strict entropy decoder loses
        // alignment. An explicit restart sequence violation remains
        // authoritative. Final validation still requires a complete decode
        // through a real EOI.
        //
        // Safety: if a large zero/padding run appears before lib_vt,
        // clamp to the start of that run. libjpeg accepts zero runs as
        // AC=0 coefficients and can be tricked into "validating" a
        // zero-filled gap that's actually reassembly garbage.
        uint64_t frontier = huffman_error_pos > 0 ? huffman_error_pos - 1 : 0;
        if ((!jpg_huffman_failure_is_hard(huffman_failure)
             || (direct_state
                 && huffman_failure != JPG_HUFFMAN_FAILURE_RESTART_SEQUENCE))
            && lib_validates_to > frontier) {
          uint64_t zero_run_in_disputed = jpg_find_interior_zero_run_after_prefix(
              data, length, blocksize, frontier, lib_validates_to);
          uint64_t trailing_zero =
              jpg_find_trailing_zero_run_start(data, length, blocksize, ctx.entropy_start);
          uint64_t effective = lib_validates_to;
          if (zero_run_in_disputed > 0 && zero_run_in_disputed <= lib_validates_to) {
            effective = zero_run_in_disputed > 0 ? zero_run_in_disputed - 1 : frontier;
          }
          if (trailing_zero > 0 && trailing_zero <= lib_validates_to
              && (effective > trailing_zero - 1 ? trailing_zero - 1 : effective) > frontier) {
            effective = trailing_zero - 1;
          }
          if (effective > frontier) {
            frontier = effective;
          }
        }
        *validates_to = frontier;
        *promising = true;
      }
      else {
        uint64_t zero_run_pos =
            jpg_find_interior_zero_run_after_prefix(data, length, blocksize,
                                                    zero_run_prefix_validates_to,
                                                    length - 1);
        uint64_t trailing_zero_pos =
            jpg_find_trailing_zero_run_start(data, length, blocksize,
                                             ctx.entropy_start);
        if (zero_run_pos > 0) {
          *validates_to = zero_run_pos - 1;
        }
        else if (trailing_zero_pos > 0) {
          *validates_to = trailing_zero_pos - 1;
        }
        else {
          *validates_to = length > 0 ? length - 1 : 0;
        }
        *promising = true;
      }
    }

    if (jpg_validate_debug_enabled()) {
      lock_fprintf(stderr,
                   "[jpgvdbg] full len=%" PRIu64 " result=%d validates=%d promising=%d vt=%" PRIu64
                   " libv=%d libp=%d libvt=%" PRIu64 " huff_err=%" PRIu64
                   " trusted=%" PRIu64 " structural=%" PRIu64 " prefix=%" PRIu64
                   " mcu=%u/%u final=%" PRIu64 " wrong=%d method=%s\n",
                   length, result,
                   *validates ? 1 : 0, *promising ? 1 : 0, *validates_to,
                   lib_validates ? 1 : 0, lib_promising ? 1 : 0, lib_validates_to,
                   huffman_error_pos, trusted_validates_to,
                   structural_validates_to, initial_prefix_validates_to,
                   jpg_mcu_result.mcu_count, jpg_mcu_result.expected_mcus,
                   jpg_mcu_result.final_byte_pos,
                   jpg_wrongblock_result.detected ? 1 : 0,
                   jpg_wrongblock_result.detected && jpg_wrongblock_result.method
                       ? jpg_wrongblock_result.method : "none");
    }

    // Save carve state with Huffman checkpoint
    goto save_state;
  save_state:
    if ((direct_state || carvehashkey) && blocksize > 0 && *validates_to > 0
        && !ctx.has_mpf) {
      uint64_t ckpt_pos = ((*validates_to + 1) / blocksize) * blocksize;
      int32_t cumulative_dc_max = jpg_max_observed_dc_diff;
      uint32_t fixed_prefix_blocks = jpg_initial_prefix_blocks(local_state, length, blocksize);
      uint32_t structural_prefix_blocks =
          jpg_structural_prefix_blocks(ctx.entropy_start, blocksize);
      bool canonical_promising_state =
          (!direct_state && !*validates
           && (*promising || *validates_to + 1 < length));
      uint64_t save_length = ckpt_pos;
      uint64_t save_prev_validates_to = *validates_to;
      uint32_t save_fixed_prefix_blocks = fixed_prefix_blocks;
      const JPGHuffmanCheckpoint *save_huff_checkpoint = NULL;

      if (fixed_prefix_blocks < structural_prefix_blocks) {
        fixed_prefix_blocks = structural_prefix_blocks;
      }
      save_fixed_prefix_blocks = fixed_prefix_blocks;

      if (canonical_promising_state) {
        save_length = jpg_promising_committed_length(*validates_to, blocksize);
        if (save_length > length) {
          save_length = length;
        }
        save_prev_validates_to = save_length > 0 ? save_length - 1 : 0;
        save_fixed_prefix_blocks =
            jpg_saved_fixed_prefix_blocks(local_state, fixed_prefix_blocks, blocksize);
        if (jpg_committed_prefix_blocks(save_length, blocksize) > save_fixed_prefix_blocks) {
          save_fixed_prefix_blocks = jpg_committed_prefix_blocks(save_length, blocksize);
        }
        if (huff_save.valid && huff_save.byte_pos <= save_length) {
          save_huff_checkpoint = &huff_save;
        }
      }
      else if (huff_save.valid) {
        save_huff_checkpoint = &huff_save;
      }

      if (save_length >= blocksize) {
        if (direct_state) {
          uint64_t direct_save_length = *validates_to + 1;

          if (direct_save_length > length) {
            direct_save_length = length;
          }
          if (direct_save_length == 0) {
            direct_save_length = save_length;
          }
          // Direct state path: write fields directly.
          direct_state->valid = true;
          direct_state->checkpoint_pos = direct_save_length;
          direct_state->prefix_hash = XXH3_64bits(data, direct_save_length);
          direct_state->prev_validates_to = *validates_to;
          direct_state->prev_length = length;
          direct_state->prev_validates = *validates;
          direct_state->max_observed_dc_diff = cumulative_dc_max;
          direct_state->fixed_prefix_blocks = fixed_prefix_blocks;
          direct_state->reassembly_seed_checked =
              local_state->reassembly_seed_checked;
          direct_state->reassembly_seed_needs_search =
              local_state->reassembly_seed_needs_search;
          memcpy(&direct_state->run_order_progress,
                 &local_state->run_order_progress,
                 sizeof(direct_state->run_order_progress));
          direct_state->footer_tail_progress = local_state->footer_tail_progress;
          direct_state->forward_scan_progress = local_state->forward_scan_progress;
          jpg_save_header_to_state(direct_state, &ctx);
          if (huff_save.valid && huff_save.byte_pos <= length) {
            memcpy(&direct_state->huff_checkpoint, &huff_save,
                   sizeof(JPGHuffmanCheckpoint));
          }
          else {
            // Clear stale checkpoint — matches the calloc behavior
            // of the hash table path where save_state starts zeroed.
            memset(&direct_state->huff_checkpoint, 0, sizeof(JPGHuffmanCheckpoint));
          }
        }
        else {
          JPGCarveState *save = (JPGCarveState *)calloc(1, sizeof(JPGCarveState));
          check_memory_allocation(save, __LINE__, __FILE__, "save");
          save->valid = true;
          save->checkpoint_pos = save_length;
          save->prefix_hash = XXH3_64bits(data, save_length);
          save->prev_validates_to = save_prev_validates_to;
          save->prev_length = canonical_promising_state ? save_length : length;
          save->prev_validates = *validates;
          save->max_observed_dc_diff = cumulative_dc_max;
          save->fixed_prefix_blocks = save_fixed_prefix_blocks;
          save->reassembly_seed_checked =
              local_state->reassembly_seed_checked;
          save->reassembly_seed_needs_search =
              local_state->reassembly_seed_needs_search;
          memcpy(&save->run_order_progress,
                 &local_state->run_order_progress,
                 sizeof(save->run_order_progress));
          save->footer_tail_progress = local_state->footer_tail_progress;
          save->forward_scan_progress = local_state->forward_scan_progress;
          jpg_save_header_to_state(save, &ctx);
          if (save_huff_checkpoint) {
            memcpy(&save->huff_checkpoint, save_huff_checkpoint,
                   sizeof(JPGHuffmanCheckpoint));
          }
          if (jpg_validate_debug_enabled()) {
            lock_fprintf(stderr,
                         "[jpgvdbg] save-full len=%" PRIu64 " vt=%" PRIu64
                         " save_len=%" PRIu64 " prev=%" PRIu64
                         " prevlen=%" PRIu64 " huff_valid=%d huff_byte=%" PRIu64
                         " fixed=%" PRIu32 " canonical=%d\n",
                         length,
                         *validates_to,
                         save->checkpoint_pos,
                         save->prev_validates_to,
                         save->prev_length,
                         save->huff_checkpoint.valid ? 1 : 0,
                         save->huff_checkpoint.byte_pos,
                         save->fixed_prefix_blocks,
                         canonical_promising_state ? 1 : 0);
          }
          jpg_put_decoder_state(carvehashkey, save);
          free(save);
        }
      }
    }
  }
  else {
    // Structural validation failed — use libjpeg for discrimination
    bool lib_validates, lib_promising;
    uint64_t lib_validates_to;
    uint64_t structural_validates_to = 0;
    jpg_current_blocksize = blocksize;
    jpg_libjpeg_validate(data, length, &lib_validates, &lib_validates_to, &lib_promising, needleidx, blocksize, carvehashkey);

    if (ctx.last_good_pos > 0) {
      structural_validates_to = ctx.last_good_pos - 1;
    }
    else if (ctx.error_pos > 0) {
      structural_validates_to = ctx.error_pos - 1;
    }

    if (lib_validates) {
      // A clean libjpeg decode is not enough to override an explicit
      // structural parser failure. Preserve only the structure-confirmed
      // prefix so LR does not cement a wrong interior block.
      *validates = false;
      *validates_to = structural_validates_to;
      *promising = true;
    }
    else {
      *validates = false;
      *validates_to = structural_validates_to;
      *promising = lib_promising;
    }
  }
  if (length > 0 && *validates_to >= length) {
    *validates_to = length - 1;
  }
  // Floor: never let validates_to drop below blocksize-1 for non-validated
  // candidates. Prevents candidates from being trimmed to 0 blocks.
  // Must also set promising=true — otherwise carve.c discards on
  // !promising && !validates, defeating the floor.
  if (! *validates && blocksize > 0 && length >= blocksize
      && *validates_to < blocksize - 1) {
    *validates_to = blocksize - 1;
    *promising = true;
  }
}


// jpg_file_validate — FILEVALIDATOR-compliant wrapper.  Used by the system
// for contiguous validation.  Delegates to jpg_validate_core with hash table
// access (direct_state = NULL).
static inline void jpg_file_validate(char *data, uint64_t length, bool *validates, uint64_t *validates_to, bool *promising,
                                     uint32_t needleidx, uint32_t blocksize, void *carvehashkey) {
  jpg_validate_core(data, length, validates, validates_to, promising,
                    needleidx, blocksize, carvehashkey, NULL);
}


// ============================================================================
// Custom JPG Reassembly Function
// ============================================================================

static inline uint32_t jpg_reassembly_get_fixed_prefix_blocks(CarveInfo *candidate) {
  void *state = jpg_get_decoder_state(candidate->carvehashkey);
  uint32_t fixed_prefix_blocks = 1;
  if (state) {
    JPGCarveState *jpg_state = (JPGCarveState *)state;
    if (jpg_state->fixed_prefix_blocks > 0) {
      fixed_prefix_blocks = jpg_state->fixed_prefix_blocks;
    }
    free(state);
  }
  if (fixed_prefix_blocks > blockvector_get_num_blocks(candidate->b)) {
    fixed_prefix_blocks = blockvector_get_num_blocks(candidate->b);
  }
  if (fixed_prefix_blocks == 0) {
    fixed_prefix_blocks = 1;
  }
  return fixed_prefix_blocks;
}

static inline bool jpg_reassembly_shallow_phase(CarveInfo *candidate,
                                                uint32_t fixed_prefix_blocks) {
  uint64_t num_blocks = blockvector_get_num_blocks(candidate->b);
  return num_blocks <= fixed_prefix_blocks + 2;
}

static inline bool jpg_reassembly_has_gap_upto(CarveInfo *candidate,
                                               uint32_t fixed_prefix_blocks,
                                               uint64_t num_blocks) {
  uint64_t start_idx = fixed_prefix_blocks > 0 ? fixed_prefix_blocks - 1 : 0;

  if (num_blocks < 2 || start_idx + 1 >= num_blocks) {
    return false;
  }

  for (uint64_t idx = start_idx + 1; idx < num_blocks; idx++) {
    int64_t prev_apparent = blockvector_get_apparent_blocknumber(candidate->b, idx - 1);
    int64_t cur_apparent = blockvector_get_apparent_blocknumber(candidate->b, idx);

    if (prev_apparent >= 0 && cur_apparent >= 0
        && cur_apparent != prev_apparent + 1) {
      return true;
    }
  }

  return false;
}

static inline bool jpg_reassembly_has_gap(CarveInfo *candidate,
                                          uint32_t fixed_prefix_blocks) {
  return jpg_reassembly_has_gap_upto(candidate, fixed_prefix_blocks,
                                     blockvector_get_num_blocks(candidate->b));
}

static inline bool jpg_reassembly_has_physical_gap(CarveInfo *candidate) {
  uint64_t num_blocks = blockvector_get_num_blocks(candidate->b);

  if (num_blocks < 2) {
    return false;
  }
  for (uint64_t idx = 1; idx < num_blocks; idx++) {
    int64_t previous =
        blockvector_get_actual_blocknumber(candidate->b, idx - 1);
    int64_t current = blockvector_get_actual_blocknumber(candidate->b, idx);

    if (previous >= 0 && current >= 0 && current != previous + 1) {
      return true;
    }
  }
  return false;
}

static inline bool jpg_reassembly_apparent_in_blockvector_strict(
    BlockVector *b,
    int64_t apparentblocknumber) {
  if (apparentblocknumber < 0) {
    return false;
  }

  for (uint64_t i = 0; i < blockvector_get_num_blocks(b); i++) {
    if (blockvector_get_apparent_blocknumber(b, i) == apparentblocknumber) {
      return true;
    }
  }

  return false;
}

// OPUS47: custom jpg_reassembly restored and extended. Paired with
// scalpelconf.c.opus47 setting .REASSEMBLYFUNC = jpg_reassembly. The
// JPG-specific logic that had been bolted into reassembly.c
// (jpg_lr_try_sorted_suffix_full_validation, jpg_lr_clamp_cold_frontier,
// and the cold-state probe-on-tie block inside LR_reassembly_did_not_validate)
// is migrated into this file as proper jpg_reassembly_* helpers. Once JPG
// runs on the custom REASSEMBLYFUNC, the hooks in reassembly.c guarded by
// jpg_lr_candidate() never fire for JPG candidates and may be removed in
// a follow-up core-engine cleanup.

// Forward declaration: custom did_not_validate and init_candidate call
// these helpers which are defined further down the file.
static inline bool jpg_reassembly_try_sorted_suffix_full_validation(
    CarveInfo *candidate, uint64_t *validates_to);
static inline void jpg_reassembly_clamp_cold_frontier(CarveInfo *candidate,
                                                      const char *tag);

typedef enum JPGReassemblyTrialResult {
  JPG_REASS_TRIAL_WORSE = 0,
  JPG_REASS_TRIAL_EQUIV = 1,
  JPG_REASS_TRIAL_BETTER = 2,
  JPG_REASS_TRIAL_STRONG_BETTER = 3,
} JPGReassemblyTrialResult;

typedef struct JPGReassemblyMaterializationCache {
  char *data;
  int64_t *actual_blocks;
  uint64_t capacity_blocks;
  uint64_t active_blocks;
} JPGReassemblyMaterializationCache;

static _Thread_local JPGReassemblyMaterializationCache
    *jpg_reassembly_materialization_cache;

static const int64_t JPG_REASS_BLOCK_CHOICE_CHECKPOINT = INT64_MIN;

static inline void jpg_reassembly_init_candidate(int id, CarveInfo *candidate,
                                                 uuid_string_t uuidp,
                                                 uuid_string_t uuidc) {
  if (scalpel_state.mode_verbose) {
    lock_fprintf(stdout,
                 "\nReassembly thread # %1d waking up to process JPG candidate "
                 "with blockvector %p and UUIDs\n%s / %s.\n",
                 id, candidate->b, uuidp, uuidc);
  }
  candidate->chopped = false;
  inflate_blockvector(candidate->b);

  // OPUS47: cold-frontier clamp migrated from reassembly.c. When a
  // candidate returns from the promising queue its saved best_validates_to
  // can occasionally over-credit a polluted tail; this forces an
  // independent cold revalidation before LR-style extension resumes.
  jpg_reassembly_clamp_cold_frontier(candidate, "cold_init_clamp");
}

static inline void jpg_reassembly_prepare_for_extension(CarveInfo *candidate) {
  uint64_t slot;
  candidate->fastpath = false;

  if (! candidate->no_initial_block_extension) {
    resize_blockvector(candidate->b, blockvector_get_num_blocks(candidate->b) + 1);
    candidate->newblock = -1;
    candidate->best_validates_to = blockvector_get_data_length(candidate->b) - 1;
  }
  else {
    candidate->no_initial_block_extension = false;
  }

  slot = blockvector_get_num_blocks(candidate->b) - 1;
  blockvector_set_apparent_blocknumber(candidate->b, slot, -1);

  // JPG block viability is strongly prefix-dependent. Reusing the LR slot-level
  // exclusion bitmap across backtracks can permanently blacklist a correct
  // block after it was tried against a different prefix state.
  blockvector_free_choices(candidate->b, slot);

  // leave the one-shot random-start sentinel in place for a clone's first extension
  if (! candidate->clone || candidate->block_choice_start != -1) {
    // after a clone's initial divergence, JPG candidates must always try the immediate next
    // apparent block first. The LR-style "+2" sentinel skips the true next block for fresh
    // extensions, which is catastrophic when headerblocks=2.
    candidate->block_choice_start =
        blockvector_get_apparent_blocknumber(candidate->b,
                                             blockvector_get_num_blocks(candidate->b) - 2)
        + 1;
  }

  jpg_reassembly_debug_dump("prepare", candidate, -1, 0);
}

static inline bool jpg_reassembly_load_saved_state(CarveInfo *candidate,
                                                   JPGCarveState *state) {
  void *saved;

  memset(state, 0, sizeof(*state));
  saved = jpg_get_decoder_state(candidate->carvehashkey);
  if (!saved) {
    return false;
  }

  memcpy(state, saved, sizeof(*state));
  free(saved);
  return state->valid;
}

// materialize 'candidate' in the reusable cache installed by jpg_reassembly()
// and store its logical length in 'length_out'. The returned buffer is borrowed:
// it must not be freed or retained across another materialization call on this
// thread or beyond the active jpg_reassembly() call.
//
static inline char *jpg_reassembly_materialize_candidate(CarveInfo *candidate,
                                                         uint64_t *length_out) {
  JPGReassemblyMaterializationCache *cache =
      jpg_reassembly_materialization_cache;
  uint64_t num_blocks = blockvector_get_num_blocks(candidate->b);
  uint64_t blocksize = scalpel_state.blocksize;

  if (!cache || blocksize == 0) {
    handle_error(SCALPEL_GENERAL_ABORT,
                 "JPG materialization cache is unavailable",
                 __LINE__, __FILE__);
  }

  if (num_blocks > cache->capacity_blocks) {
    uint64_t old_capacity = cache->capacity_blocks;
    uint64_t new_capacity = old_capacity > 0 ? old_capacity : 8;

    while (new_capacity < num_blocks) {
      if (new_capacity > UINT64_MAX / 2) {
        handle_error(SCALPEL_GENERAL_ABORT,
                     "JPG materialization cache capacity overflow",
                     __LINE__, __FILE__);
      }
      new_capacity *= 2;
    }
    if (new_capacity > SIZE_MAX / blocksize
        || new_capacity > SIZE_MAX / sizeof(*cache->actual_blocks)) {
      handle_error(SCALPEL_GENERAL_ABORT,
                   "JPG materialization cache size overflow",
                   __LINE__, __FILE__);
    }

    jpg_boundary_preview_cache_invalidate();
    cache->data = (char *)realloc(cache->data,
                                  (size_t)(new_capacity * blocksize));
    check_memory_allocation(cache->data, __LINE__, __FILE__,
                            "jpg reassembly materialization data");
    cache->actual_blocks = (int64_t *)realloc(
        cache->actual_blocks,
        (size_t)(new_capacity * sizeof(*cache->actual_blocks)));
    check_memory_allocation(cache->actual_blocks, __LINE__, __FILE__,
                            "jpg reassembly materialization block map");

    memset(cache->data + old_capacity * blocksize, 0,
           (size_t)((new_capacity - old_capacity) * blocksize));
    for (uint64_t i = old_capacity; i < new_capacity; i++) {
      cache->actual_blocks[i] = -1;
    }
    cache->capacity_blocks = new_capacity;
  }

  for (uint64_t i = num_blocks; i < cache->active_blocks; i++) {
    if (jpg_boundary_preview_cache
        && jpg_boundary_preview_cache->data == cache->data
        && i * blocksize < jpg_boundary_preview_cache->prefix_length) {
      jpg_boundary_preview_cache_invalidate();
    }
    cache->actual_blocks[i] = -1;
  }

  for (uint64_t i = 0; i < num_blocks; i++) {
    int64_t apparent = blockvector_get_apparent_blocknumber(candidate->b, i);
    int64_t actual = -1;
    char *slot = cache->data + i * blocksize;

    if (apparent < 0) {
      if (cache->actual_blocks[i] != -1
          && jpg_boundary_preview_cache
          && jpg_boundary_preview_cache->data == cache->data
          && i * blocksize < jpg_boundary_preview_cache->prefix_length) {
        jpg_boundary_preview_cache_invalidate();
      }
      memset(slot, 0, (size_t)blocksize);
      cache->actual_blocks[i] = -1;
      continue;
    }

    actual = filemirror_actual_blocknumber(scalpel_state.filemirror, apparent);
    if (cache->actual_blocks[i] != actual || i + 1 == num_blocks) {
      uint64_t block_length = 0;
      char *block_data = filemirror_actual_block_data_pointer(
          scalpel_state.filemirror, actual, &block_length);

      if (cache->actual_blocks[i] != actual
          && jpg_boundary_preview_cache
          && jpg_boundary_preview_cache->data == cache->data
          && i * blocksize < jpg_boundary_preview_cache->prefix_length) {
        jpg_boundary_preview_cache_invalidate();
      }
      memset(slot, 0, (size_t)blocksize);
      if (block_data) {
        if (block_length > blocksize) {
          block_length = blocksize;
        }
        memcpy(slot, block_data, (size_t)block_length);
      }
      cache->actual_blocks[i] = actual;
    }
  }

  cache->active_blocks = num_blocks;
  *length_out = blockvector_get_data_length(candidate->b);
  return cache->data;
}

#define JPG_REASS_FINAL_JOIN_SCORE_LIMIT 4.0

enum {
  JPG_REASS_FINAL_NONCONTIGUOUS_JOIN_MINIMUM = 2,
  JPG_REASS_FINAL_SUSPICIOUS_JOIN_MINIMUM = 1
};

typedef struct JPGReassemblyPhysicalRun {
  uint64_t source_slot;
  uint64_t length;
  int64_t first_actual;
  int64_t last_actual;
} JPGReassemblyPhysicalRun;

static inline int jpg_reassembly_compare_physical_runs(const void *left,
                                                       const void *right) {
  const JPGReassemblyPhysicalRun *left_run =
      (const JPGReassemblyPhysicalRun *)left;
  const JPGReassemblyPhysicalRun *right_run =
      (const JPGReassemblyPhysicalRun *)right;

  if (left_run->first_actual < right_run->first_actual) {
    return -1;
  }
  if (left_run->first_actual > right_run->first_actual) {
    return 1;
  }
  return 0;
}

static inline bool jpg_reassembly_validate_direct(
    CarveInfo *candidate, JPGCarveState *state, uint64_t *validates_to,
    uint32_t fixed_prefix_blocks);
static inline bool jpg_reassembly_requires_cold_validation(
    CarveInfo *candidate, uint32_t fixed_prefix_blocks);

// Early trials across a gap must be checked from the beginning of the file.
static inline bool jpg_reassembly_requires_cold_validation(
    CarveInfo *candidate, uint32_t fixed_prefix_blocks) {
  return jpg_reassembly_has_gap(candidate, fixed_prefix_blocks)
         && blockvector_get_num_blocks(candidate->b)
                <= (uint64_t)fixed_prefix_blocks + 3;
}

// A complete libjpeg decode establishes syntactic validity but cannot prove
// the order of independently relocated entropy runs. Preserve distinct valid
// run orders as promising hypotheses. Without a second valid order, require
// independent evidence of a suspicious join before treating a decoded
// multi-run candidate as ambiguous. Requiring more than one relocated join
// keeps an ordinary single-gap reconstruction conclusive.
static inline bool jpg_reassembly_has_ambiguous_join_order(
    CarveInfo *candidate) {
  uint64_t num_blocks;
  uint64_t noncontiguous_joins = 0;
  uint64_t length = 0;
  char *data;
  uint32_t suspicious_joins = 0;

  if (!candidate || !candidate->b || scalpel_state.blocksize == 0) {
    return false;
  }

  num_blocks = blockvector_get_num_blocks(candidate->b);
  for (uint64_t slot = 1; slot < num_blocks; slot++) {
    const int64_t previous =
        blockvector_get_actual_blocknumber(candidate->b, slot - 1);
    const int64_t current =
        blockvector_get_actual_blocknumber(candidate->b, slot);

    if (previous < 0 || current != previous + 1) {
      noncontiguous_joins++;
    }
  }
  if (noncontiguous_joins
      < JPG_REASS_FINAL_NONCONTIGUOUS_JOIN_MINIMUM) {
    return false;
  }

  // A valid entropy stream can occasionally survive a permutation of whole
  // physical runs. If physically ordering the same tail runs also produces a
  // complete JPEG with fewer joins, retain that simpler reconstruction but do
  // not claim that the format proves which of the two valid orders is correct.
  if (noncontiguous_joins < SIZE_MAX / sizeof(JPGReassemblyPhysicalRun)) {
    const uint64_t run_count = noncontiguous_joins + 1;
    JPGReassemblyPhysicalRun *runs =
        (JPGReassemblyPhysicalRun *)malloc(
            (size_t)run_count * sizeof(*runs));
    uint64_t run_index = 0;
    uint64_t sorted_joins = 0;
    uint64_t destination_slot = 0;
    BlockVector *ordered = NULL;
    bool usable = true;

    check_memory_allocation(runs, __LINE__, __FILE__,
                            "JPG physical run ordering");
    memset(runs, 0, (size_t)run_count * sizeof(*runs));
    runs[0].source_slot = 0;
    runs[0].first_actual =
        blockvector_get_actual_blocknumber(candidate->b, 0);
    if (runs[0].first_actual < 0) {
      usable = false;
    }

    for (uint64_t slot = 1; usable && slot < num_blocks; slot++) {
      const int64_t previous =
          blockvector_get_actual_blocknumber(candidate->b, slot - 1);
      const int64_t current =
          blockvector_get_actual_blocknumber(candidate->b, slot);

      if (previous < 0 || current < 0) {
        usable = false;
        break;
      }
      if (current != previous + 1) {
        runs[run_index].length =
            slot - runs[run_index].source_slot;
        runs[run_index].last_actual = previous;
        run_index++;
        runs[run_index].source_slot = slot;
        runs[run_index].first_actual = current;
      }
    }
    if (usable) {
      runs[run_index].length =
          num_blocks - runs[run_index].source_slot;
      runs[run_index].last_actual =
          blockvector_get_actual_blocknumber(candidate->b, num_blocks - 1);
      usable = run_index + 1 == run_count;
    }

    if (usable) {
      qsort(runs + 1, (size_t)(run_count - 1), sizeof(*runs),
            jpg_reassembly_compare_physical_runs);
      for (uint64_t index = 1; index < run_count; index++) {
        if (runs[index].first_actual
            != runs[index - 1].last_actual + 1) {
          sorted_joins++;
        }
      }
      usable = sorted_joins < noncontiguous_joins;
    }

    if (usable) {
      CarveInfo ordered_candidate = *candidate;
      JPGCarveState ordered_state;
      uint64_t ordered_validates_to = 0;
      const uint64_t original_length =
          blockvector_get_data_length(candidate->b);
      bool ordered_validates;

      clone_blockvector(candidate->b, &ordered, false);
      for (uint64_t index = 0; index < run_count; index++) {
        for (uint64_t offset = 0; offset < runs[index].length; offset++) {
          const int64_t apparent = blockvector_get_apparent_blocknumber(
              candidate->b, runs[index].source_slot + offset);

          blockvector_set_apparent_blocknumber(
              ordered, destination_slot++, apparent);
        }
      }
      deflate_blockvector(ordered);
      blockvector_set_data_length(ordered, original_length);
      inflate_blockvector(ordered);
      ordered_candidate.b = ordered;
      memset(&ordered_state, 0, sizeof(ordered_state));
      ordered_validates = jpg_reassembly_validate_direct(
          &ordered_candidate, &ordered_state, &ordered_validates_to,
          jpg_reassembly_get_fixed_prefix_blocks(candidate));

      if (ordered_validates && original_length > 0
          && ordered_validates_to == original_length - 1) {
        if (scalpel_state.write_promising) {
          BlockVector *original = candidate->b;
          const CarveInfoFlavor original_flavor = candidate->flavor;
          const uint64_t original_validates_to =
              candidate->best_validates_to;
          CarveInfo *preserved_candidate = candidate;

          candidate->b = ordered;
          candidate->flavor = PROMISING;
          candidate->best_validates_to = ordered_validates_to;
          write_candidate(&preserved_candidate, true);
          candidate->b = original;
          candidate->flavor = original_flavor;
          candidate->best_validates_to = original_validates_to;
        }
        if (jpg_reassembly_debug_candidate(candidate)) {
          lock_fprintf(stderr,
                       "[jpgdbg] final_join alternate physical runs=%" PRIu64
                       " joins=%" PRIu64 "->%" PRIu64
                       " preserved=%d\n",
                       run_count, noncontiguous_joins, sorted_joins,
                       scalpel_state.write_promising ? 1 : 0);
        }
        free_blockvector(&ordered);
        free(runs);
        return true;
      }
    }
    if (ordered) {
      free_blockvector(&ordered);
    }
    free(runs);
  }

  data = jpg_reassembly_materialize_candidate(candidate, &length);
  if (!data || length == 0) {
    return false;
  }

  for (uint64_t slot = 1; slot < num_blocks; slot++) {
    const int64_t previous =
        blockvector_get_actual_blocknumber(candidate->b, slot - 1);
    const int64_t current =
        blockvector_get_actual_blocknumber(candidate->b, slot);
    uint64_t prefix_length;
    JpgBoundaryScore boundary;

    if (previous >= 0 && current == previous + 1) {
      continue;
    }
    if (slot > UINT64_MAX / scalpel_state.blocksize) {
      break;
    }
    prefix_length = slot * scalpel_state.blocksize;
    if (prefix_length >= length) {
      break;
    }

    boundary = jpg_boundary_score_scaled(data, prefix_length, length, 1,
                                         false);
    if (jpg_reassembly_debug_candidate(candidate)) {
      lock_fprintf(stderr,
                   "[jpgdbg] final_join slot=%" PRIu64
                   " previous=%" PRId64 " current=%" PRId64
                   " valid=%d normalized=%.3f\n",
                   slot, previous, current, boundary.valid ? 1 : 0,
                   boundary.normalized);
    }
    if (boundary.valid
        && boundary.normalized >= JPG_REASS_FINAL_JOIN_SCORE_LIMIT) {
      suspicious_joins++;
      if (suspicious_joins
          >= JPG_REASS_FINAL_SUSPICIOUS_JOIN_MINIMUM) {
        return true;
      }
    }
  }

  return false;
}

static inline bool jpg_reassembly_validate_direct(CarveInfo *candidate,
                                                  JPGCarveState *state,
                                                  uint64_t *validates_to,
                                                  uint32_t fixed_prefix_blocks) {
  bool validates = false;
  bool promising = false;
  uint64_t materialized_length = 0;
  char *materialized = jpg_reassembly_materialize_candidate(candidate,
                                                            &materialized_length);
  bool use_full_validation =
      jpg_reassembly_requires_cold_validation(candidate, fixed_prefix_blocks);

  if (use_full_validation) {
    memset(state, 0, sizeof(*state));
  }

  if (jpg_reassembly_debug_candidate(candidate)
      && blockvector_get_num_blocks(candidate->b) <= 4) {
    lock_fprintf(stderr,
                 "[jpgdbg] direct_state valid=%d ckpt=%" PRIu64 " prev=%" PRIu64
                 " fixed=%" PRIu32 " huff_valid=%d huff_byte=%" PRIu64
                 " full=%d\n",
                 state->valid ? 1 : 0,
                 state->checkpoint_pos,
                 state->prev_validates_to,
                 state->fixed_prefix_blocks,
                 state->huff_checkpoint.valid ? 1 : 0,
                 state->huff_checkpoint.byte_pos,
                 use_full_validation ? 1 : 0);
    for (uint64_t i = 0; i < blockvector_get_num_blocks(candidate->b); i++) {
      lock_fprintf(stderr,
                   "[jpgdbg] seg%llu act=%" PRId64 " ap=%" PRId64 " hash=%" PRIu64 "\n",
                   (unsigned long long)i,
                   blockvector_get_actual_blocknumber(candidate->b, i),
                   blockvector_get_apparent_blocknumber(candidate->b, i),
                   (uint64_t)XXH3_64bits(materialized + i * scalpel_state.blocksize,
                                         scalpel_state.blocksize));
    }
  }

  jpg_validate_core(materialized,
                    materialized_length,
                    &validates, validates_to, &promising,
                    candidate->needleidx, scalpel_state.blocksize,
                    NULL, state);
  return validates;
}

// Check the remaining bytes of an already mapped final block before searching
// for another block. A rejected or interrupted trial preserves the exact prefix.
// Validator state remains untouched; normal reassembly resumes it on acceptance.
static inline void jpg_reassembly_finish_mapped_tail(
    CarveInfo *candidate, bool *validates, uint64_t *validates_to) {
  if (!candidate || !candidate->b || !validates || !validates_to
      || *validates || scalpel_state.blocksize == 0
      || jpg_reassembly_checkpoint_requested()) {
    return;
  }
  uint64_t length = blockvector_get_data_length(candidate->b);
  uint64_t count = blockvector_get_num_blocks(candidate->b);
  uint64_t blocksize = scalpel_state.blocksize;
  if (length == 0 || length % blocksize == 0
      || count > UINT64_MAX / blocksize
      || count != length / blocksize + 1) {
    return;
  }
  int64_t apparent = blockvector_get_apparent_blocknumber(candidate->b, count - 1);
  if (apparent < 0
      || (uint64_t)apparent >= filemirror_apparent_blocks(scalpel_state.filemirror)) {
    return;
  }
  int64_t actual = filemirror_actual_blocknumber(scalpel_state.filemirror, apparent);
  uint64_t available = 0;
  if (actual < 0 || filemirror_actual_block_covered(scalpel_state.filemirror, actual)
      || !filemirror_actual_block_data_pointer(scalpel_state.filemirror, actual,
                                               &available)) {
    return;
  }
  if (available > blocksize) {
    available = blocksize;
  }
  uint64_t trial_length = (count - 1) * blocksize + available;
  if (trial_length <= length) {
    return;
  }

  JpgWrongBlockResult previous_wrongblock = jpg_wrongblock_result;
  JPGCarveState trial_state = {0};
  uint64_t trial_validates_to = 0;
  blockvector_set_data_length(candidate->b, trial_length);
  bool trial_validates = jpg_reassembly_validate_direct(
      candidate, &trial_state, &trial_validates_to,
      jpg_reassembly_get_fixed_prefix_blocks(candidate));
  if (!jpg_reassembly_checkpoint_requested()
      && trial_validates_to < trial_length
      && (trial_validates
          || (!jpg_wrongblock_result.detected
              && trial_validates_to + 1 > length))) {
    blockvector_set_data_length(candidate->b, trial_validates_to + 1);
    inflate_blockvector(candidate->b);
    *validates = trial_validates;
    *validates_to = trial_validates_to;
    return;
  }
  blockvector_set_data_length(candidate->b, length);
  jpg_wrongblock_result = previous_wrongblock;
}

static inline bool jpg_reassembly_cold_validation_is_better(
    bool cold_validates,
    uint64_t cold_validates_to,
    const JpgWrongBlockResult *cold_wrongblock,
    uint64_t current_validates_to,
    const JpgWrongBlockResult *current_wrongblock) {
  if (cold_validates) {
    return true;
  }
  if (cold_validates_to <= current_validates_to) {
    return false;
  }
  if (!current_wrongblock || !current_wrongblock->detected) {
    return true;
  }

  // A structural frontier beyond a known entropy failure is weaker evidence.
  // Replace it only when the cold pass independently moves that failure.
  return cold_wrongblock && cold_wrongblock->detected
         && cold_wrongblock->estimated_byte
                > current_wrongblock->estimated_byte;
}

static inline bool jpg_reassembly_candidate_is_progressive(
    CarveInfo *candidate,
    uint32_t *structural_prefix_blocks,
    bool *format_known) {
  uint64_t length = 0;
  char *data;
  JpgValidationContext context;

  if (structural_prefix_blocks) {
    *structural_prefix_blocks = 1;
  }
  if (format_known) {
    *format_known = false;
  }
  if (!candidate || !candidate->b) {
    return false;
  }
  data = jpg_reassembly_materialize_candidate(candidate, &length);
  memset(&context, 0, sizeof(context));
  context.data = (const uint8_t *)data;
  context.length = length;
  (void)jpg_validate_structure(&context);
  if (structural_prefix_blocks && context.entropy_start > 0) {
    *structural_prefix_blocks = jpg_structural_prefix_blocks(
        context.entropy_start, scalpel_state.blocksize);
  }
  if (structural_prefix_blocks && scalpel_state.blocksize > 0
      && length >= (uint64_t)scalpel_state.blocksize * 2
      && *structural_prefix_blocks < 2) {
    *structural_prefix_blocks = 2;
  }
  if (format_known) {
    *format_known = context.have_sof && context.entropy_start > 0;
  }
  return context.have_sof && context.entropy_start > 0
         && context.is_progressive;
}
// OPUS47: migrated from reassembly.c (was jpg_lr_try_sorted_suffix_full_validation).
// When a candidate's natural-order validation fails, try small permutations of
// the suffix — both reordering and one-element-drop trials — to see if an
// alternative ordering validates. This fixes cases where the correct blocks
// are in the candidate but arrived in the wrong order (typical after LR
// galloping over a transposed run).
static inline bool jpg_reassembly_try_sorted_suffix_full_validation(
    CarveInfo *candidate, uint64_t *validates_to) {
  enum {
    JPG_REASS_SORTED_SUFFIX_MIN = 3,
    JPG_REASS_SORTED_SUFFIX_MAX = 8
  };
  uint32_t fixed_prefix_blocks;
  uint64_t num_blocks;
  uint64_t original_length;
  uint64_t max_suffix;
  uint64_t suffix_len = 0;
  int64_t suffix[JPG_REASS_SORTED_SUFFIX_MAX];
  int64_t trial[JPG_REASS_SORTED_SUFFIX_MAX];
  int64_t sorted[JPG_REASS_SORTED_SUFFIX_MAX];

  if (!candidate || !candidate->b || !validates_to) {
    return false;
  }

  fixed_prefix_blocks = jpg_reassembly_get_fixed_prefix_blocks(candidate);
  num_blocks = blockvector_get_num_blocks(candidate->b);
  original_length = blockvector_get_data_length(candidate->b);
  if (num_blocks <= fixed_prefix_blocks + JPG_REASS_SORTED_SUFFIX_MIN) {
    return false;
  }

  max_suffix = num_blocks - fixed_prefix_blocks;
  if (max_suffix > JPG_REASS_SORTED_SUFFIX_MAX) {
    max_suffix = JPG_REASS_SORTED_SUFFIX_MAX;
  }

  for (suffix_len = max_suffix; suffix_len >= JPG_REASS_SORTED_SUFFIX_MIN; suffix_len--) {
    uint64_t start_idx = num_blocks - suffix_len;

    for (uint64_t i = 0; i < suffix_len; i++) {
      suffix[i] = blockvector_get_apparent_blocknumber(candidate->b, start_idx + i);
    }

    for (int64_t drop_index = -1; drop_index < (int64_t)suffix_len - 1; drop_index++) {
      uint64_t trial_len = suffix_len - (drop_index >= 0 ? 1 : 0);
      uint64_t trial_idx = 0;
      int64_t min_apparent;
      int64_t max_apparent;
      bool duplicate = false;
      bool already_sorted = true;
      JPGCarveState trial_state;
      bool validates;

      if (trial_len < JPG_REASS_SORTED_SUFFIX_MIN) {
        continue;
      }

      for (uint64_t i = 0; i < suffix_len; i++) {
        if ((int64_t)i == drop_index) {
          continue;
        }
        trial[trial_idx] = suffix[i];
        sorted[trial_idx] = suffix[i];
        trial_idx++;
      }

      min_apparent = trial[0];
      max_apparent = trial[0];
      for (uint64_t i = 0; i < trial_len; i++) {
        if (trial[i] < 0) {
          duplicate = true;
          break;
        }
        if (trial[i] < min_apparent) {
          min_apparent = trial[i];
        }
        if (trial[i] > max_apparent) {
          max_apparent = trial[i];
        }
        if (i > 0) {
          if (trial[i] <= trial[i - 1]) {
            already_sorted = false;
          }
          for (uint64_t j = 0; j < i; j++) {
            if (trial[i] == trial[j]) {
              duplicate = true;
              break;
            }
          }
        }
        if (duplicate) {
          break;
        }
      }

      if (duplicate || max_apparent != trial[trial_len - 1]
          || max_apparent - min_apparent + 1 != (int64_t)trial_len
          || (drop_index < 0 && already_sorted)) {
        continue;
      }

      for (uint64_t i = 1; i < trial_len; i++) {
        int64_t value = sorted[i];
        uint64_t j = i;
        while (j > 0 && sorted[j - 1] > value) {
          sorted[j] = sorted[j - 1];
          j--;
        }
        sorted[j] = value;
      }

      resize_blockvector(candidate->b, num_blocks - (drop_index >= 0 ? 1 : 0));
      for (uint64_t i = 0; i < trial_len; i++) {
        blockvector_set_apparent_blocknumber(candidate->b, start_idx + i, sorted[i]);
      }
      blockvector_set_data_length_to_mapped_extent(candidate->b);
      deflate_blockvector(candidate->b);
      inflate_blockvector(candidate->b);

      memset(&trial_state, 0, sizeof(trial_state));
      validates = jpg_reassembly_validate_direct(candidate, &trial_state, validates_to,
                                                 fixed_prefix_blocks);
      if (validates) {
        jpg_reassembly_debug_dump(drop_index >= 0
                                      ? "sorted_suffix_drop_validate"
                                      : "sorted_suffix_validate",
                                  candidate, -1, *validates_to);
        return true;
      }

      // Restore original ordering before trying next permutation
      resize_blockvector(candidate->b, num_blocks);
      for (uint64_t i = 0; i < suffix_len; i++) {
        blockvector_set_apparent_blocknumber(candidate->b, start_idx + i, suffix[i]);
      }
      blockvector_set_data_length(candidate->b, original_length);
      deflate_blockvector(candidate->b);
      inflate_blockvector(candidate->b);
    }
  }

  return false;
}

// OPUS47: migrated from reassembly.c (was jpg_lr_clamp_cold_frontier).
// Called at init time (from the promising queue). Runs an independent
// cold validation of the candidate. If the result undershoots the saved
// best_validates_to, clamp back to the cold frontier — this catches
// tail-overcredit from a previous promising-state commit.
static inline void jpg_reassembly_clamp_cold_frontier(CarveInfo *candidate,
                                                      const char *tag) {
  JPGCarveState trial_state;
  uint32_t fixed_prefix_blocks;
  uint64_t current_length;
  uint64_t current_end;
  uint64_t cold_validates_to = 0;
  uint64_t clamp_validates_to;
  uint64_t min_validates_to;
  bool cold_validates;

  if (!candidate || !candidate->b
      || blockvector_get_num_blocks(candidate->b) < 2) {
    return;
  }

  current_length = blockvector_get_data_length(candidate->b);
  if (current_length == 0) {
    return;
  }

  fixed_prefix_blocks = jpg_reassembly_get_fixed_prefix_blocks(candidate);
  memset(&trial_state, 0, sizeof(trial_state));
  cold_validates = jpg_reassembly_validate_direct(candidate, &trial_state,
                                                  &cold_validates_to,
                                                  fixed_prefix_blocks);
  current_end = current_length - 1;

  if (cold_validates) {
    if (cold_validates_to > candidate->best_validates_to) {
      candidate->best_validates_to = cold_validates_to;
    }
    return;
  }

  clamp_validates_to = cold_validates_to;
  if (trial_state.valid && trial_state.huff_checkpoint.valid
      && trial_state.huff_checkpoint.byte_pos > 0) {
    uint64_t checkpoint_validates_to = trial_state.huff_checkpoint.byte_pos - 1;
    if (checkpoint_validates_to < clamp_validates_to) {
      clamp_validates_to = checkpoint_validates_to;
    }
  }

  if (scalpel_state.blocksize > 0) {
    uint64_t full_blocks = (clamp_validates_to + 1) / scalpel_state.blocksize;
    if (full_blocks > 0) {
      clamp_validates_to = full_blocks * scalpel_state.blocksize - 1;
    }
  }

  min_validates_to = fixed_prefix_blocks > 0
                     ? (uint64_t)fixed_prefix_blocks * scalpel_state.blocksize - 1
                     : 0;
  if (clamp_validates_to < min_validates_to) {
    clamp_validates_to = min_validates_to;
  }

  if (clamp_validates_to >= current_end
      && clamp_validates_to >= candidate->best_validates_to) {
    return;
  }

  candidate->best_validates_to = clamp_validates_to;
  candidate->newblock = -1;
  candidate->fastpath = false;
  if (candidate->best_choices) {
    destroy_queue(candidate->best_choices);
  }

  blockvector_set_data_length(candidate->b, candidate->best_validates_to + 1);
  resize_blockvector(candidate->b,
                     CEILDIV(candidate->best_validates_to + 1,
                             scalpel_state.blocksize));

  jpg_reassembly_debug_dump(tag, candidate, -1, clamp_validates_to);
}

enum {
  JPG_REASSEMBLY_PROBE_MAX_CHAIN = 8
};

static inline uint64_t jpg_reassembly_probe_followon(CarveInfo *candidate,
                                                     const JPGCarveState *trial_state,
                                                     uint64_t validates_to) {
  static const uint64_t JPG_REASSEMBLY_PROBE_WINDOW = 32;
  uint64_t best_validates_to = validates_to;
  uint64_t saved_length = blockvector_get_data_length(candidate->b);
  uint64_t committed_length = validates_to + 1;
  uint64_t num_blocks = blockvector_get_num_blocks(candidate->b);
  int64_t current_apparentblocknumber =
      blockvector_get_apparent_blocknumber(candidate->b, num_blocks - 1);
  int64_t last_apparentblocknumber =
      filemirror_apparent_blocks(scalpel_state.filemirror);

  if (committed_length == 0 || current_apparentblocknumber < 0) {
    return best_validates_to;
  }

  blockvector_set_data_length(candidate->b, committed_length);
  resize_blockvector(candidate->b, num_blocks + 1);

  for (uint64_t offset = 1; offset <= JPG_REASSEMBLY_PROBE_WINDOW; offset++) {
    int64_t probe_choice = current_apparentblocknumber + (int64_t)offset;
    int64_t actualblocknumber;
    JPGCarveState probe_state;
    bool stop_offset = false;

    if (probe_choice >= last_apparentblocknumber) {
      break;
    }

    if (jpg_reassembly_checkpoint_requested()) {
      break;
    }

    actualblocknumber =
        filemirror_actual_blocknumber(scalpel_state.filemirror, probe_choice);
    if (filemirror_get_blocktype(scalpel_state.filemirror,
                                 actualblocknumber,
                                 candidate->needleidx) == BLOCK_CONFIDENCE_INVALID
        || jpg_reassembly_apparent_in_blockvector_strict(candidate->b, probe_choice)) {
      continue;
    }

    memcpy(&probe_state, trial_state, sizeof(probe_state));
    resize_blockvector(candidate->b, num_blocks);
    blockvector_set_data_length(candidate->b, committed_length);

    for (uint64_t chain = 0; chain < JPG_REASSEMBLY_PROBE_MAX_CHAIN; chain++) {
      int64_t chain_choice = probe_choice + (int64_t)chain;
      int64_t chain_actualblocknumber;
      uint64_t probe_validates_to = 0;
      bool probe_validates;

      if (chain_choice >= last_apparentblocknumber) {
        break;
      }
      if (jpg_reassembly_checkpoint_requested()) {
        stop_offset = true;
        break;
      }

      chain_actualblocknumber =
          filemirror_actual_blocknumber(scalpel_state.filemirror, chain_choice);
      if (filemirror_get_blocktype(scalpel_state.filemirror,
                                   chain_actualblocknumber,
                                   candidate->needleidx) == BLOCK_CONFIDENCE_INVALID
          || jpg_reassembly_apparent_in_blockvector_strict(candidate->b, chain_choice)) {
        break;
      }

      resize_blockvector(candidate->b, blockvector_get_num_blocks(candidate->b) + 1);
      blockvector_set_apparent_blocknumber(candidate->b,
                                           blockvector_get_num_blocks(candidate->b) - 1,
                                           chain_choice);
      inflate_blockvector_single_block(candidate->b,
                                       blockvector_get_num_blocks(candidate->b) - 1);

      probe_validates =
          jpg_reassembly_validate_direct(candidate, &probe_state,
                                         &probe_validates_to,
                                         jpg_reassembly_get_fixed_prefix_blocks(candidate));

      if (jpg_reassembly_debug_candidate(candidate)) {
        lock_fprintf(stderr,
                     "[jpgdbg] probe base=%" PRId64 " chain=%" PRIu64
                     " vt=%" PRIu64 " valid=%d blocks=%" PRIu64 "\n",
                     probe_choice,
                     chain + 1,
                     probe_validates_to,
                     probe_validates ? 1 : 0,
                     blockvector_get_num_blocks(candidate->b));
      }

      if (probe_validates) {
        best_validates_to = blockvector_get_data_length(candidate->b) - 1;
        stop_offset = true;
        break;
      }

      if (probe_validates_to > best_validates_to) {
        best_validates_to = probe_validates_to;
      }
    }

    resize_blockvector(candidate->b, num_blocks);
    blockvector_set_data_length(candidate->b, committed_length);
    if (stop_offset) {
      break;
    }
  }

  resize_blockvector(candidate->b, num_blocks);
  blockvector_set_data_length(candidate->b, saved_length);

  return best_validates_to;
}

static inline uint64_t jpg_reassembly_probe_contiguous_followon(
    CarveInfo *candidate,
    const JPGCarveState *trial_state,
    uint64_t validates_to,
    bool *restart_not_due) {
  uint64_t best_validates_to = validates_to;
  uint64_t saved_length = blockvector_get_data_length(candidate->b);
  uint64_t num_blocks = blockvector_get_num_blocks(candidate->b);
  uint64_t committed_length = validates_to + 1;
  int64_t current_apparentblocknumber =
      blockvector_get_apparent_blocknumber(candidate->b, num_blocks - 1);
  int64_t last_apparentblocknumber =
      filemirror_apparent_blocks(scalpel_state.filemirror);
  JPGCarveState probe_state;

  if (restart_not_due) {
    *restart_not_due = false;
  }

  if (committed_length == 0 || current_apparentblocknumber < 0) {
    return best_validates_to;
  }

  memcpy(&probe_state, trial_state, sizeof(probe_state));
  blockvector_set_data_length(candidate->b, committed_length);

  for (uint64_t chain = 1; chain <= JPG_REASSEMBLY_PROBE_MAX_CHAIN; chain++) {
    int64_t chain_choice = current_apparentblocknumber + (int64_t)chain;
    int64_t chain_actualblocknumber;
    uint64_t probe_validates_to = 0;
    bool probe_validates;

    if (chain_choice >= last_apparentblocknumber
        || jpg_reassembly_checkpoint_requested()) {
      break;
    }

    chain_actualblocknumber =
        filemirror_actual_blocknumber(scalpel_state.filemirror, chain_choice);
    if (chain_actualblocknumber < 0
        || filemirror_actual_block_covered(scalpel_state.filemirror,
                                           chain_actualblocknumber)
        || filemirror_get_blocktype(scalpel_state.filemirror,
                                    chain_actualblocknumber,
                                    candidate->needleidx) == BLOCK_CONFIDENCE_INVALID
        || jpg_reassembly_apparent_in_blockvector_strict(candidate->b,
                                                         chain_choice)) {
      break;
    }

    resize_blockvector(candidate->b, blockvector_get_num_blocks(candidate->b) + 1);
    blockvector_set_apparent_blocknumber(candidate->b,
                                         blockvector_get_num_blocks(candidate->b) - 1,
                                         chain_choice);
    inflate_blockvector_single_block(candidate->b,
                                     blockvector_get_num_blocks(candidate->b) - 1);

    probe_validates =
        jpg_reassembly_validate_direct(candidate, &probe_state,
                                       &probe_validates_to,
                                       jpg_reassembly_get_fixed_prefix_blocks(candidate));

    if (jpg_reassembly_debug_candidate(candidate)) {
      lock_fprintf(stderr,
                   "[jpgdbg] contiguous_probe chain=%" PRIu64
                   " choice=%" PRId64 " vt=%" PRIu64
                   " valid=%d blocks=%" PRIu64 "\n",
                   chain,
                   chain_choice,
                   probe_validates_to,
                   probe_validates ? 1 : 0,
                   blockvector_get_num_blocks(candidate->b));
    }

    if (probe_validates) {
      best_validates_to = blockvector_get_data_length(candidate->b) - 1;
      break;
    }

    if (probe_validates_to > best_validates_to) {
      best_validates_to = probe_validates_to;
      if (restart_not_due) {
        *restart_not_due =
            probe_state.restart_interval > 0
            && jpg_mcu_result.valid
            && !jpg_mcu_result.restart_due
            && jpg_mcu_result.mcus_since_restart
                   < probe_state.restart_interval;
      }
    }
  }

  resize_blockvector(candidate->b, num_blocks);
  blockvector_set_data_length(candidate->b, saved_length);

  return best_validates_to;
}

static inline bool jpg_reassembly_try_fast_contiguous_commit(
    CarveInfo *candidate,
    const JPGCarveState *prefix_state,
    JPGCarveState *best_state,
    bool *have_best_state,
    uint32_t fixed_prefix_blocks,
    bool *validates,
    uint64_t *validates_to) {
  static const uint64_t JPG_REASSEMBLY_CONTIG_SLACK = 256;
  uint64_t oldlength;
  uint64_t target_length;
  uint64_t required_length;
  uint64_t required_checkpoint;
  int64_t next_apparentblocknumber;
  int64_t actualblocknumber;
  JPGCarveState trial_state;

  if (candidate->clone || candidate->newblock >= 0
      || jpg_reassembly_has_gap(candidate, fixed_prefix_blocks)
      || blockvector_get_num_blocks(candidate->b) < 2) {
    return false;
  }

  next_apparentblocknumber =
      blockvector_get_apparent_blocknumber(candidate->b,
                                           blockvector_get_num_blocks(candidate->b) - 2) + 1;
  if (next_apparentblocknumber < 0
      || (uint64_t)next_apparentblocknumber
             >= filemirror_apparent_blocks(scalpel_state.filemirror)) {
    return false;
  }

  actualblocknumber =
      filemirror_actual_blocknumber(scalpel_state.filemirror, next_apparentblocknumber);
  if (filemirror_get_blocktype(scalpel_state.filemirror,
                               actualblocknumber,
                               candidate->needleidx) == BLOCK_CONFIDENCE_INVALID
      || filemirror_actual_block_is_zero(scalpel_state.filemirror, actualblocknumber)
      || jpg_reassembly_apparent_in_blockvector_strict(candidate->b, next_apparentblocknumber)) {
    return false;
  }

  oldlength = blockvector_get_data_length(candidate->b);
  target_length = oldlength + scalpel_state.blocksize;
  required_length = target_length > JPG_REASSEMBLY_CONTIG_SLACK
                    ? target_length - JPG_REASSEMBLY_CONTIG_SLACK
                    : target_length;
  required_checkpoint = required_length;

  blockvector_set_apparent_blocknumber(candidate->b,
                                       blockvector_get_num_blocks(candidate->b) - 1,
                                       next_apparentblocknumber);
  inflate_blockvector_single_block(candidate->b,
                                   blockvector_get_num_blocks(candidate->b) - 1);

  memcpy(&trial_state, prefix_state, sizeof(trial_state));
  *validates = jpg_reassembly_validate_direct(candidate, &trial_state,
                                              validates_to, fixed_prefix_blocks);

  if (*validates) {
    if (have_best_state) {
      memcpy(best_state, &trial_state, sizeof(*best_state));
      *have_best_state = true;
    }
    jpg_reassembly_debug_dump("fast_contig_validated", candidate,
                              next_apparentblocknumber, *validates_to);
    return true;
  }

  if (*validates_to + 1 >= required_length
      && trial_state.valid
      && trial_state.checkpoint_pos >= required_checkpoint) {
    candidate->best_validates_to = *validates_to;
    candidate->newblock = actualblocknumber;
    if (have_best_state) {
      memcpy(best_state, &trial_state, sizeof(*best_state));
      *have_best_state = true;
    }
    jpg_reassembly_debug_dump("fast_contig_accept", candidate,
                              next_apparentblocknumber, *validates_to);
    return true;
  }

  deflate_blockvector_single_block(candidate->b,
                                   blockvector_get_num_blocks(candidate->b) - 1,
                                   oldlength);
  blockvector_set_apparent_blocknumber(candidate->b,
                                       blockvector_get_num_blocks(candidate->b) - 1,
                                       -1);
  return false;
}

static inline bool jpg_reassembly_try_fast_forward_tail_commit(
    CarveInfo *candidate,
    const JPGCarveState *prefix_state,
    JPGCarveState *best_state,
    bool *have_best_state,
    uint32_t fixed_prefix_blocks,
    bool *validates,
    uint64_t *validates_to) {
  uint64_t oldlength;
  int64_t next_apparentblocknumber;
  int64_t actualblocknumber;
  JPGCarveState trial_state;
  uint64_t frontier_validates_to;

  if (candidate->clone || candidate->newblock >= 0
      || !jpg_reassembly_has_gap(candidate, fixed_prefix_blocks)
      || !prefix_state->valid
      || !prefix_state->huff_checkpoint.valid
      || blockvector_get_num_blocks(candidate->b) < 2) {
    return false;
  }

  next_apparentblocknumber =
      blockvector_get_apparent_blocknumber(candidate->b,
                                           blockvector_get_num_blocks(candidate->b) - 2) + 1;
  if (next_apparentblocknumber < 0
      || next_apparentblocknumber
             >= (int64_t)filemirror_apparent_blocks(scalpel_state.filemirror)) {
    return false;
  }

  actualblocknumber =
      filemirror_actual_blocknumber(scalpel_state.filemirror, next_apparentblocknumber);
  if (filemirror_get_blocktype(scalpel_state.filemirror,
                               actualblocknumber,
                               candidate->needleidx) == BLOCK_CONFIDENCE_INVALID
      || filemirror_actual_block_is_zero(scalpel_state.filemirror, actualblocknumber)
      || jpg_reassembly_apparent_in_blockvector_strict(candidate->b, next_apparentblocknumber)) {
    return false;
  }

  oldlength = blockvector_get_data_length(candidate->b);
  blockvector_set_apparent_blocknumber(candidate->b,
                                       blockvector_get_num_blocks(candidate->b) - 1,
                                       next_apparentblocknumber);
  inflate_blockvector_single_block(candidate->b,
                                   blockvector_get_num_blocks(candidate->b) - 1);

  memcpy(&trial_state, prefix_state, sizeof(trial_state));
  *validates = jpg_reassembly_validate_direct(candidate, &trial_state,
                                              validates_to, fixed_prefix_blocks);

  if (*validates) {
    if (have_best_state) {
      memcpy(best_state, &trial_state, sizeof(*best_state));
      *have_best_state = true;
    }
    jpg_reassembly_debug_dump("fast_tail_validated", candidate,
                              next_apparentblocknumber, *validates_to);
    return true;
  }

  if (trial_state.valid
      && trial_state.huff_checkpoint.valid
      && trial_state.huff_checkpoint.byte_pos > prefix_state->huff_checkpoint.byte_pos) {
    frontier_validates_to = trial_state.huff_checkpoint.byte_pos - 1;
    if (*validates_to > frontier_validates_to) {
      frontier_validates_to = *validates_to;
    }
    candidate->best_validates_to = frontier_validates_to;
    candidate->newblock = actualblocknumber;
    if (have_best_state) {
      memcpy(best_state, &trial_state, sizeof(*best_state));
      *have_best_state = true;
    }
    jpg_reassembly_debug_dump("fast_tail_accept", candidate,
                              next_apparentblocknumber, frontier_validates_to);
    return true;
  }

  deflate_blockvector_single_block(candidate->b,
                                   blockvector_get_num_blocks(candidate->b) - 1,
                                   oldlength);
  blockvector_set_apparent_blocknumber(candidate->b,
                                       blockvector_get_num_blocks(candidate->b) - 1,
                                       -1);
  return false;
}

static inline bool jpg_reassembly_try_local_bridge_commit(
    CarveInfo *candidate,
    const JPGCarveState *prefix_state,
    JPGCarveState *best_state,
    bool *have_best_state,
    bool *validates,
    uint64_t *validates_to,
    uint64_t oldlength,
    int64_t bridge_start_apparent,
    int64_t bridge_end_apparent) {
  static const uint64_t JPG_REASS_LOCAL_BRIDGE_SLACK = 2;
  uint64_t saved_num_blocks;
  int64_t saved_last_apparent;
  uint64_t bridge_blocks;
  uint64_t required_validates_to;
  uint64_t frontier_validates_to;
  uint64_t extra_blocks = 0;
  JPGCarveState trial_state;

  if (bridge_start_apparent < 0 || bridge_end_apparent < bridge_start_apparent
      || !prefix_state->valid) {
    return false;
  }

  bridge_blocks = (uint64_t)(bridge_end_apparent - bridge_start_apparent + 1);
  if (bridge_blocks < 2) {
    return false;
  }

  saved_num_blocks = blockvector_get_num_blocks(candidate->b);
  saved_last_apparent =
      blockvector_get_apparent_blocknumber(candidate->b, saved_num_blocks - 1);

  deflate_blockvector_single_block(candidate->b, saved_num_blocks - 1, oldlength);
  blockvector_set_apparent_blocknumber(candidate->b, saved_num_blocks - 1,
                                       bridge_start_apparent);
  inflate_blockvector_single_block(candidate->b, saved_num_blocks - 1);

  for (int64_t apparent = bridge_start_apparent + 1;
       apparent <= bridge_end_apparent;
       apparent++) {
    int64_t actualblocknumber;

    if (jpg_reassembly_checkpoint_requested()) {
      goto restore_single_trial;
    }

    actualblocknumber =
        filemirror_actual_blocknumber(scalpel_state.filemirror, apparent);
    if (filemirror_get_blocktype(scalpel_state.filemirror,
                                 actualblocknumber,
                                 candidate->needleidx) == BLOCK_CONFIDENCE_INVALID
        || jpg_reassembly_apparent_in_blockvector_strict(candidate->b, apparent)) {
      goto restore_single_trial;
    }

    resize_blockvector(candidate->b, blockvector_get_num_blocks(candidate->b) + 1);
    blockvector_set_apparent_blocknumber(candidate->b,
                                         blockvector_get_num_blocks(candidate->b) - 1,
                                         apparent);
    inflate_blockvector_single_block(candidate->b,
                                     blockvector_get_num_blocks(candidate->b) - 1);
  }

  while (1) {
    memcpy(&trial_state, prefix_state, sizeof(trial_state));
    *validates =
        jpg_reassembly_validate_direct(candidate, &trial_state, validates_to,
                                       jpg_reassembly_get_fixed_prefix_blocks(candidate));

    frontier_validates_to = *validates_to;
    if (trial_state.huff_checkpoint.valid
        && trial_state.huff_checkpoint.byte_pos > frontier_validates_to + 1) {
      frontier_validates_to = trial_state.huff_checkpoint.byte_pos - 1;
    }

    required_validates_to =
        oldlength + (bridge_blocks + extra_blocks) * scalpel_state.blocksize - 1;
    if (*validates || frontier_validates_to >= required_validates_to) {
      if (! *validates && frontier_validates_to > *validates_to) {
        *validates_to = frontier_validates_to;
      }
      candidate->best_validates_to = *validates_to;
      candidate->newblock = -1;
      if (have_best_state) {
        memcpy(best_state, &trial_state, sizeof(*best_state));
        *have_best_state = true;
      }
      jpg_reassembly_debug_dump("bridge_accept", candidate,
                                bridge_end_apparent + (int64_t)extra_blocks,
                                *validates_to);
      return true;
    }

    if (extra_blocks >= JPG_REASS_LOCAL_BRIDGE_SLACK
        || jpg_reassembly_checkpoint_requested()) {
      break;
    }

    bridge_end_apparent++;
    if (bridge_end_apparent < 0
        || (uint64_t)bridge_end_apparent
               >= filemirror_apparent_blocks(scalpel_state.filemirror)) {
      break;
    }

    int64_t actualblocknumber =
        filemirror_actual_blocknumber(scalpel_state.filemirror, bridge_end_apparent);
    if (filemirror_get_blocktype(scalpel_state.filemirror,
                                 actualblocknumber,
                                 candidate->needleidx) == BLOCK_CONFIDENCE_INVALID
        || jpg_reassembly_apparent_in_blockvector_strict(candidate->b, bridge_end_apparent)) {
      break;
    }

    resize_blockvector(candidate->b, blockvector_get_num_blocks(candidate->b) + 1);
    blockvector_set_apparent_blocknumber(candidate->b,
                                         blockvector_get_num_blocks(candidate->b) - 1,
                                         bridge_end_apparent);
    inflate_blockvector_single_block(candidate->b,
                                     blockvector_get_num_blocks(candidate->b) - 1);
    extra_blocks++;
  }

restore_single_trial:
  resize_blockvector(candidate->b, saved_num_blocks);
  blockvector_set_apparent_blocknumber(candidate->b, saved_num_blocks - 1,
                                       saved_last_apparent);
  inflate_blockvector_single_block(candidate->b, saved_num_blocks - 1);
  return false;
}

static inline bool jpg_reassembly_try_local_tail_backfill(
    CarveInfo *candidate,
    JPGCarveState *best_state,
    bool *have_best_state,
    bool *validates,
    uint64_t *validates_to,
    uint32_t fixed_prefix_blocks) {
  static const uint64_t JPG_REASS_LOCAL_BACKFILL_WINDOW = 32;
  static const uint64_t JPG_REASS_LOCAL_BACKFILL_TAIL_CAP =
      JPG_REASS_LOCAL_BACKFILL_WINDOW;
  uint64_t saved_num_blocks = blockvector_get_num_blocks(candidate->b);
  uint64_t saved_length = blockvector_get_data_length(candidate->b);
  int64_t *saved_apparents = NULL;
  uint64_t baseline_frontier = candidate->best_validates_to;
  uint64_t prefix_num_blocks;
  uint64_t tail_blocks;
  int64_t prefix_tail_apparent;
  int64_t tail_start_apparent;
  int64_t tail_end_apparent;
  int64_t accepted_start_apparent;
  uint64_t tail_start_idx;
  JPGCarveState prefix_state;
  JPGCarveState accepted_state;
  uint64_t prefix_validates_to = 0;
  uint64_t accepted_validates_to = 0;
  bool accepted = false;
  bool accepted_validates = false;
  bool prefix_validates;

  if (candidate->clone || candidate->newblock < 0
      || !jpg_reassembly_has_gap(candidate, fixed_prefix_blocks)
      || saved_num_blocks <= fixed_prefix_blocks + 1) {
    return false;
  }

  tail_start_idx = saved_num_blocks - 1;
  while (tail_start_idx > fixed_prefix_blocks
         && blockvector_get_apparent_blocknumber(candidate->b, tail_start_idx)
                == blockvector_get_apparent_blocknumber(candidate->b, tail_start_idx - 1) + 1) {
    tail_start_idx--;
  }
  if (tail_start_idx == 0 || tail_start_idx <= fixed_prefix_blocks) {
    return false;
  }
  prefix_num_blocks = tail_start_idx;
  tail_blocks = saved_num_blocks - tail_start_idx;
  if (tail_blocks < 2 || tail_blocks > JPG_REASS_LOCAL_BACKFILL_TAIL_CAP) {
    return false;
  }

  tail_start_apparent = blockvector_get_apparent_blocknumber(candidate->b, tail_start_idx);
  tail_end_apparent =
      blockvector_get_apparent_blocknumber(candidate->b, saved_num_blocks - 1);
  if (tail_start_apparent < 0
      || tail_end_apparent != tail_start_apparent + (int64_t)tail_blocks - 1) {
    return false;
  }

  prefix_tail_apparent =
      blockvector_get_apparent_blocknumber(candidate->b, prefix_num_blocks - 1);
  if (prefix_tail_apparent < 0 || tail_start_apparent <= prefix_tail_apparent + 1
      || (uint64_t)(tail_start_apparent - (prefix_tail_apparent + 1))
             > JPG_REASS_LOCAL_BACKFILL_WINDOW) {
    return false;
  }
  accepted_start_apparent = tail_start_apparent;
  accepted_validates_to = *validates_to;
  accepted_validates = *validates;

  saved_apparents = (int64_t *)calloc(saved_num_blocks, sizeof(*saved_apparents));
  check_memory_allocation(saved_apparents, __LINE__, __FILE__, "saved_apparents");
  for (uint64_t i = 0; i < saved_num_blocks; i++) {
    saved_apparents[i] = blockvector_get_apparent_blocknumber(candidate->b, i);
  }

  resize_blockvector(candidate->b, prefix_num_blocks);
  blockvector_set_data_length(candidate->b, prefix_num_blocks * scalpel_state.blocksize);

  memset(&prefix_state, 0, sizeof(prefix_state));
  prefix_validates =
      jpg_reassembly_validate_direct(candidate, &prefix_state,
                                     &prefix_validates_to,
                                     fixed_prefix_blocks);
  if (jpg_reassembly_checkpoint_requested()) {
    goto restore_original_tail;
  }
  if (!prefix_validates && !prefix_state.valid
      && prefix_validates_to + 1 < blockvector_get_data_length(candidate->b)) {
    goto restore_original_tail;
  }

  for (int64_t prepend_apparent = tail_start_apparent - 1;
       prepend_apparent > prefix_tail_apparent;
       prepend_apparent--) {
    JPGCarveState trial_state;
    uint64_t frontier_validates_to;
    bool trial_validates;

    resize_blockvector(candidate->b, prefix_num_blocks);
    blockvector_set_data_length(candidate->b, prefix_num_blocks * scalpel_state.blocksize);

    for (int64_t apparent = prepend_apparent; apparent <= tail_end_apparent; apparent++) {
      int64_t actualblocknumber =
          filemirror_actual_blocknumber(scalpel_state.filemirror, apparent);

      if (jpg_reassembly_checkpoint_requested()) {
        goto restore_original_tail;
      }
      if (filemirror_get_blocktype(scalpel_state.filemirror,
                                   actualblocknumber,
                                   candidate->needleidx) == BLOCK_CONFIDENCE_INVALID
          || jpg_reassembly_apparent_in_blockvector_strict(candidate->b, apparent)) {
        goto restore_original_tail;
      }

      resize_blockvector(candidate->b, blockvector_get_num_blocks(candidate->b) + 1);
      blockvector_set_apparent_blocknumber(candidate->b,
                                           blockvector_get_num_blocks(candidate->b) - 1,
                                           apparent);
      inflate_blockvector_single_block(candidate->b,
                                       blockvector_get_num_blocks(candidate->b) - 1);
    }

    memcpy(&trial_state, &prefix_state, sizeof(trial_state));
    trial_validates =
        jpg_reassembly_validate_direct(candidate, &trial_state, validates_to,
                                       fixed_prefix_blocks);
    frontier_validates_to = *validates_to;
    if (trial_state.huff_checkpoint.valid
        && trial_state.huff_checkpoint.byte_pos > frontier_validates_to + 1) {
      frontier_validates_to = trial_state.huff_checkpoint.byte_pos - 1;
    }

    if (trial_validates
        || (trial_state.valid && trial_state.huff_checkpoint.valid
            && frontier_validates_to >= baseline_frontier)) {
      accepted = true;
      accepted_start_apparent = prepend_apparent;
      accepted_validates = trial_validates;
      accepted_validates_to = *validates_to;
      if (!trial_validates && frontier_validates_to > accepted_validates_to) {
        accepted_validates_to = frontier_validates_to;
      }
      memcpy(&accepted_state, &trial_state, sizeof(accepted_state));
      baseline_frontier = accepted_validates_to;
      jpg_reassembly_debug_dump("backfill_accept", candidate,
                                prepend_apparent, accepted_validates_to);
      continue;
    }
  }

  if (accepted) {
    resize_blockvector(candidate->b, prefix_num_blocks);
    blockvector_set_data_length(candidate->b, prefix_num_blocks * scalpel_state.blocksize);
    for (int64_t apparent = accepted_start_apparent; apparent <= tail_end_apparent; apparent++) {
      resize_blockvector(candidate->b, blockvector_get_num_blocks(candidate->b) + 1);
      blockvector_set_apparent_blocknumber(candidate->b,
                                           blockvector_get_num_blocks(candidate->b) - 1,
                                           apparent);
      inflate_blockvector_single_block(candidate->b,
                                       blockvector_get_num_blocks(candidate->b) - 1);
    }
    *validates = accepted_validates;
    *validates_to = accepted_validates_to;
    candidate->best_validates_to = accepted_validates_to;
    candidate->newblock = filemirror_actual_blocknumber(scalpel_state.filemirror,
                                                        tail_end_apparent);
    if (have_best_state) {
      memcpy(best_state, &accepted_state, sizeof(*best_state));
      *have_best_state = true;
    }
    free(saved_apparents);
    return true;
  }

restore_original_tail:
  resize_blockvector(candidate->b, saved_num_blocks);
  for (uint64_t i = 0; i < saved_num_blocks; i++) {
    blockvector_set_apparent_blocknumber(candidate->b, i, saved_apparents[i]);
    inflate_blockvector_single_block(candidate->b, i);
  }
  blockvector_set_data_length(candidate->b, saved_length);
  free(saved_apparents);
  return false;
}

static inline bool jpg_reassembly_try_local_support_tail_commit(
    CarveInfo *candidate,
    const JPGCarveState *prefix_state,
    JPGCarveState *best_state,
    bool *have_best_state,
    bool *validates,
    uint64_t *validates_to,
    uint64_t oldlength,
    int64_t support_start_apparent,
    int64_t tail_apparent,
    uint64_t baseline_validates_to) {
  static const uint64_t JPG_REASS_LOCAL_SUPPORT_TAIL_MAX_GAP = 8;
  static const uint64_t JPG_REASS_LOCAL_SUPPORT_TAIL_MAX_BLOCKS = 4;
  uint64_t saved_num_blocks;
  int64_t saved_last_apparent;
  int64_t max_support_end_apparent;
  JPGCarveState trial_state;

  if (support_start_apparent < 0 || tail_apparent <= support_start_apparent
      || (uint64_t)(tail_apparent - support_start_apparent)
             > JPG_REASS_LOCAL_SUPPORT_TAIL_MAX_GAP
      || !prefix_state->valid) {
    return false;
  }

  saved_num_blocks = blockvector_get_num_blocks(candidate->b);
  saved_last_apparent =
      blockvector_get_apparent_blocknumber(candidate->b, saved_num_blocks - 1);
  max_support_end_apparent =
      support_start_apparent + (int64_t)JPG_REASS_LOCAL_SUPPORT_TAIL_MAX_BLOCKS - 1;
  if (max_support_end_apparent >= tail_apparent) {
    max_support_end_apparent = tail_apparent - 1;
  }

  for (int64_t support_end_apparent = support_start_apparent;
       support_end_apparent <= max_support_end_apparent;
       support_end_apparent++) {
    uint64_t frontier_validates_to;

    resize_blockvector(candidate->b, saved_num_blocks);
    blockvector_set_apparent_blocknumber(candidate->b, saved_num_blocks - 1,
                                         support_start_apparent);
    inflate_blockvector_single_block(candidate->b, saved_num_blocks - 1);

    for (int64_t apparent = support_start_apparent + 1;
         apparent <= support_end_apparent;
         apparent++) {
      int64_t actualblocknumber;

      if (jpg_reassembly_checkpoint_requested()) {
        goto restore_single_trial;
      }

      actualblocknumber =
          filemirror_actual_blocknumber(scalpel_state.filemirror, apparent);
      if (filemirror_get_blocktype(scalpel_state.filemirror,
                                   actualblocknumber,
                                   candidate->needleidx) == BLOCK_CONFIDENCE_INVALID
          || jpg_reassembly_apparent_in_blockvector_strict(candidate->b, apparent)) {
        goto restore_single_trial;
      }

      resize_blockvector(candidate->b, blockvector_get_num_blocks(candidate->b) + 1);
      blockvector_set_apparent_blocknumber(candidate->b,
                                           blockvector_get_num_blocks(candidate->b) - 1,
                                           apparent);
      inflate_blockvector_single_block(candidate->b,
                                       blockvector_get_num_blocks(candidate->b) - 1);
    }

    resize_blockvector(candidate->b, blockvector_get_num_blocks(candidate->b) + 1);
    blockvector_set_apparent_blocknumber(candidate->b,
                                         blockvector_get_num_blocks(candidate->b) - 1,
                                         tail_apparent);
    inflate_blockvector_single_block(candidate->b,
                                     blockvector_get_num_blocks(candidate->b) - 1);

    memcpy(&trial_state, prefix_state, sizeof(trial_state));
    *validates =
        jpg_reassembly_validate_direct(candidate, &trial_state, validates_to,
                                       jpg_reassembly_get_fixed_prefix_blocks(candidate));

    frontier_validates_to = *validates_to;
    if (trial_state.huff_checkpoint.valid
        && trial_state.huff_checkpoint.byte_pos > frontier_validates_to + 1) {
      frontier_validates_to = trial_state.huff_checkpoint.byte_pos - 1;
    }

    if (*validates
        || (trial_state.valid && trial_state.huff_checkpoint.valid
            && frontier_validates_to >= baseline_validates_to)) {
      if (!*validates && frontier_validates_to > *validates_to) {
        *validates_to = frontier_validates_to;
      }
      candidate->best_validates_to = *validates_to;
      candidate->newblock = filemirror_actual_blocknumber(scalpel_state.filemirror,
                                                          tail_apparent);
      if (have_best_state) {
        memcpy(best_state, &trial_state, sizeof(*best_state));
        *have_best_state = true;
      }
      jpg_reassembly_debug_dump("support_tail_accept", candidate,
                                support_end_apparent, *validates_to);
      return true;
    }
  }

restore_single_trial:
  resize_blockvector(candidate->b, saved_num_blocks);
  blockvector_set_apparent_blocknumber(candidate->b, saved_num_blocks - 1,
                                       saved_last_apparent);
  inflate_blockvector_single_block(candidate->b, saved_num_blocks - 1);
  blockvector_set_data_length(candidate->b, oldlength + scalpel_state.blocksize);
  return false;
}

static inline int64_t jpg_reassembly_get_block_choice(CarveInfo *candidate) {
  int64_t block_choice = -1;
  int64_t best_choice = -1;
  int64_t adjacent_choice = -1;
  int64_t actualblocknumber;
  int64_t first_apparentblocknumber;
  int64_t reserved;
  int64_t count;
  uint64_t slot;
  uint64_t evaluated;
  bool viable;
  bool adjacent;
  bool in_vector;
  bool checkpoint_choice = false;
  bool terminal_choice = false;
  BlockValidationDecision blocktype = BLOCK_CONFIDENCE_INVALID;
  BlockValidationDecision best_blocktype = BLOCK_CONFIDENCE_INVALID;
  BlockValidationDecision adjacent_blocktype = BLOCK_CONFIDENCE_INVALID;
  int64_t best_reserved = INT64_MAX;
  int64_t adjacent_reserved = INT64_MAX;

#if BLOCK_SELECTION_PERFORMANCE_STATS > 0
  struct timespec BLK_starttime;
  struct timespec BLK_endtime;
  uint64_t BLK_examined = 0;

  clock_gettime(CLOCK_MONOTONIC, &BLK_starttime);
#endif

  count = filemirror_apparent_blocks(scalpel_state.filemirror);
  slot = blockvector_get_num_blocks(candidate->b) - 1;
  first_apparentblocknumber =
      blockvector_get_num_blocks(candidate->b) > 0
      ? blockvector_get_apparent_blocknumber(candidate->b, 0)
      : -1;
  if (slot > 0) {
    int64_t previous = blockvector_get_apparent_blocknumber(candidate->b, slot - 1);
    if (previous >= 0 && previous + 1 < count) {
      adjacent_choice = previous + 1;
    }
  }

  while (count > 0) {
    if (jpg_reassembly_checkpoint_requested()) {
      block_choice = JPG_REASS_BLOCK_CHOICE_CHECKPOINT;
      checkpoint_choice = true;
      goto done;
    }

    block_choice = blockvector_get_choice(candidate->b, slot,
                                          candidate->block_choice_start,
                                          count, &evaluated);

#if BLOCK_SELECTION_PERFORMANCE_STATS > 0
    BLK_examined += evaluated;
#endif

    if (block_choice == -1) {
      goto done;
    }

    adjacent = block_choice == adjacent_choice;

    if (jpg_reassembly_debug_candidate(candidate)) {
      lock_fprintf(stderr, "[jpgdbg] pick slot=%" PRIu64 " ap=%" PRId64 " act=%" PRId64 " adjacent=%d\n",
                   blockvector_get_num_blocks(candidate->b) - 1,
                   block_choice,
                   filemirror_actual_blocknumber(scalpel_state.filemirror, block_choice),
                   adjacent ? 1 : 0);
    }

    candidate->block_choice_start =
        (block_choice + 1) % filemirror_apparent_blocks(scalpel_state.filemirror);
    count -= evaluated;

    actualblocknumber =
        filemirror_actual_blocknumber(scalpel_state.filemirror, block_choice);

    blocktype = filemirror_get_blocktype(scalpel_state.filemirror,
                                         actualblocknumber,
                                         candidate->needleidx);
    in_vector = jpg_reassembly_apparent_in_blockvector_strict(candidate->b, block_choice);
    viable = blocktype != BLOCK_CONFIDENCE_INVALID
             && !in_vector
             && (first_apparentblocknumber < 0
                 || block_choice >= first_apparentblocknumber);
    reserved = scalpel_state.reservations
                   ? filemirror_actual_block_reserved(scalpel_state.filemirror,
                                                      actualblocknumber)
                   : 0;

    if (jpg_reassembly_debug_candidate(candidate)) {
      lock_fprintf(stderr,
                   "[jpgdbg] viable ap=%" PRId64 " act=%" PRId64
                   " blocktype=%u invec=%d zero=%d viable=%d reserved=%" PRId64 "\n",
                   block_choice,
                   actualblocknumber,
                   (unsigned)blocktype,
                   in_vector ? 1 : 0,
                   filemirror_actual_block_is_zero(scalpel_state.filemirror,
                                                   actualblocknumber) ? 1 : 0,
                   viable ? 1 : 0,
                   reserved);
    }

    if (! viable) {
      blockvector_remove_choice(candidate->b,
                                slot,
                                block_choice);
      block_choice = -1;
    }
    else {
      if (blocktype == BLOCK_CONFIDENCE_VALID && reserved == 0) {
        best_choice = block_choice;
        best_blocktype = blocktype;
        best_reserved = reserved;
        terminal_choice = true;
        goto done;
      }

      if (adjacent) {
        adjacent_blocktype = blocktype;
        adjacent_reserved = reserved;
      }

      if (best_choice == -1
          || blocktype > best_blocktype
          || (blocktype == best_blocktype && reserved < best_reserved)) {
        best_choice = block_choice;
        best_blocktype = blocktype;
        best_reserved = reserved;
      }
    }
  }

done:
  if (checkpoint_choice) {
    goto report_choice;
  }

  if (!terminal_choice && adjacent_blocktype != BLOCK_CONFIDENCE_INVALID
      && best_choice != -1 && best_choice != adjacent_choice) {
    int best_conf = (int)best_blocktype;
    int adjacent_conf = (int)adjacent_blocktype;
    if (best_conf <= adjacent_conf + 1 && adjacent_reserved <= best_reserved) {
      best_choice = adjacent_choice;
      best_blocktype = adjacent_blocktype;
      best_reserved = adjacent_reserved;
    }
  }

  block_choice = best_choice;

  if (block_choice >= 0) {
    blockvector_remove_choice(candidate->b, slot, block_choice);
  }

report_choice:
  jpg_reassembly_debug_dump("choice_done", candidate, block_choice, 0);

#if BLOCK_SELECTION_PERFORMANCE_STATS > 0
  clock_gettime(CLOCK_MONOTONIC, &BLK_endtime);
  uint64_t BLK_elapsed =
      (BLK_endtime.tv_sec - BLK_starttime.tv_sec) * NANOSECONDS_PER_SECOND
      + (BLK_endtime.tv_nsec - BLK_starttime.tv_nsec);

  atomic_fetch_add_explicit(&scalpel_state.search_specs[candidate->needleidx].BLK_calls,
                            1, memory_order_acq_rel);
  atomic_max_u64_pub(&scalpel_state.search_specs[candidate->needleidx].BLK_longest,
                     BLK_elapsed);
  atomic_fetch_add_explicit(&scalpel_state.search_specs[candidate->needleidx].BLK_total,
                            BLK_elapsed, memory_order_acq_rel);
  atomic_max_u64_pub(&scalpel_state.search_specs[candidate->needleidx].BLK_most_blocks,
                     BLK_examined);
#endif

  return block_choice;
}

static inline void jpg_reassembly_extension_successful(
    CarveInfo *candidate,
    const JPGCarveState *best_state) {
  uint64_t committed_length;

  if (! candidate->fastpath) {
    blockvector_set_apparent_blocknumber(candidate->b,
                                         blockvector_get_num_blocks(candidate->b) - 1,
                                         filemirror_apparent_blocknumber(
                                             scalpel_state.filemirror,
                                             candidate->newblock));
    inflate_blockvector_single_block(candidate->b,
                                     blockvector_get_num_blocks(candidate->b) - 1);
    committed_length = candidate->best_validates_to + 1;
    if (best_state && best_state->valid
        && best_state->prev_length > committed_length
        && best_state->prev_length <= blockvector_get_data_length(candidate->b)) {
      committed_length = best_state->prev_length;
    }
    blockvector_set_data_length(candidate->b, committed_length);
    resize_blockvector(candidate->b,
                       CEILDIV(blockvector_get_data_length(candidate->b),
                               scalpel_state.blocksize));
  }
}

static inline bool jpg_reassembly_has_closer_viable_forward_block(
    CarveInfo *candidate,
    int64_t expected_next_apparentblocknumber,
    int64_t current_apparentblocknumber) {
  static const int64_t JPG_REASSEMBLY_PREJUMP_WINDOW = 32;
  int64_t first_apparentblocknumber;
  int64_t last_apparentblocknumber;

  if (expected_next_apparentblocknumber < 0
      || current_apparentblocknumber <= expected_next_apparentblocknumber
      || blockvector_get_num_blocks(candidate->b) == 0) {
    return false;
  }

  first_apparentblocknumber =
      blockvector_get_apparent_blocknumber(candidate->b, 0);
  if (first_apparentblocknumber >= 0
      && current_apparentblocknumber < first_apparentblocknumber) {
    return false;
  }

  last_apparentblocknumber = current_apparentblocknumber - 1;
  if (last_apparentblocknumber - expected_next_apparentblocknumber
      >= JPG_REASSEMBLY_PREJUMP_WINDOW) {
    last_apparentblocknumber =
        expected_next_apparentblocknumber + JPG_REASSEMBLY_PREJUMP_WINDOW - 1;
  }

  for (int64_t apparentblocknumber = expected_next_apparentblocknumber;
       apparentblocknumber <= last_apparentblocknumber;
       apparentblocknumber++) {
    int64_t actualblocknumber;

    if (first_apparentblocknumber >= 0
        && apparentblocknumber < first_apparentblocknumber) {
      continue;
    }
    if (jpg_reassembly_apparent_in_blockvector_strict(candidate->b, apparentblocknumber)) {
      continue;
    }

    actualblocknumber =
        filemirror_actual_blocknumber(scalpel_state.filemirror,
                                      apparentblocknumber);
    if (filemirror_actual_block_is_zero(scalpel_state.filemirror,
                                        actualblocknumber)) {
      continue;
    }
    if (filemirror_get_blocktype(scalpel_state.filemirror,
                                 actualblocknumber,
                                 candidate->needleidx) != BLOCK_CONFIDENCE_INVALID) {
      return true;
    }
  }

  return false;
}

static inline bool jpg_reassembly_has_nearby_viable_forward_block(
    CarveInfo *candidate,
    int64_t start_apparentblocknumber,
    uint64_t window) {
  int64_t first_apparentblocknumber;
  int64_t last_apparentblocknumber;

  if (!candidate || window == 0 || blockvector_get_num_blocks(candidate->b) == 0) {
    return false;
  }

  first_apparentblocknumber =
      blockvector_get_apparent_blocknumber(candidate->b, 0);
  last_apparentblocknumber =
      filemirror_apparent_blocks(scalpel_state.filemirror);
  if (start_apparentblocknumber < 0 || start_apparentblocknumber >= last_apparentblocknumber) {
    return false;
  }

  for (uint64_t offset = 0; offset < window; offset++) {
    int64_t apparentblocknumber = start_apparentblocknumber + (int64_t)offset;
    int64_t actualblocknumber;

    if (apparentblocknumber >= last_apparentblocknumber) {
      break;
    }
    if (first_apparentblocknumber >= 0
        && apparentblocknumber < first_apparentblocknumber) {
      continue;
    }
    if (jpg_reassembly_apparent_in_blockvector_strict(candidate->b, apparentblocknumber)) {
      continue;
    }

    actualblocknumber =
        filemirror_actual_blocknumber(scalpel_state.filemirror,
                                      apparentblocknumber);
    if (filemirror_actual_block_is_zero(scalpel_state.filemirror,
                                        actualblocknumber)) {
      continue;
    }
    if (filemirror_get_blocktype(scalpel_state.filemirror,
                                 actualblocknumber,
                                 candidate->needleidx) != BLOCK_CONFIDENCE_INVALID) {
      return true;
    }
  }

  return false;
}

static inline JPGReassemblyTrialResult jpg_reassembly_did_not_validate(CarveInfo *candidate,
                                                                       uint64_t validates_to,
                                                                       int64_t block_choice,
                                                                       const JPGCarveState *trial_state,
                                                                       uint64_t *best_rank_score,
                                                                       uint32_t fixed_prefix_blocks) {
  static const uint64_t JPG_REASSEMBLY_NEAR_BEST_DELTA = 64;
  static const uint64_t JPG_REASSEMBLY_LOCAL_COMMIT_WINDOW = 32;
  static const uint64_t JPG_REASSEMBLY_FIRST_GAP_LOCAL_SUPPORT_BONUS = 1024;
  static const uint64_t JPG_REASSEMBLY_FIRST_GAP_ZERO_PENALTY = 1024;
  static const uint64_t JPG_REASSEMBLY_SHALLOW_WRONGBLOCK_PENALTY = 4096;
  uint64_t baseline_validates_to = candidate->best_validates_to;
  uint64_t rank_score = validates_to;
  uint64_t current_best_rank = *best_rank_score;
  uint64_t committed_num_blocks =
      blockvector_get_num_blocks(candidate->b) > 0
      ? blockvector_get_num_blocks(candidate->b) - 1
      : 0;

  int64_t current_actualblocknumber =
      filemirror_actual_blocknumber(scalpel_state.filemirror, block_choice);
  int64_t current_apparentblocknumber = block_choice;
  int64_t anchor_apparentblocknumber =
      blockvector_get_apparent_blocknumber(candidate->b,
                                           blockvector_get_num_blocks(candidate->b) - 2);
  int64_t expected_next_apparentblocknumber = anchor_apparentblocknumber + 1;
  int64_t best_apparentblocknumber =
      candidate->newblock >= 0
      ? filemirror_apparent_blocknumber(scalpel_state.filemirror, candidate->newblock)
      : INT64_MAX;
  bool current_forward = current_apparentblocknumber >= expected_next_apparentblocknumber;
  bool best_forward = best_apparentblocknumber >= expected_next_apparentblocknumber;
  uint64_t current_distance =
      current_forward
      ? (uint64_t)(current_apparentblocknumber - expected_next_apparentblocknumber)
      : UINT64_MAX;
  uint64_t best_distance =
      best_forward
      ? (uint64_t)(best_apparentblocknumber - expected_next_apparentblocknumber)
      : UINT64_MAX;
  bool candidate_has_gap =
      jpg_reassembly_has_gap_upto(candidate, fixed_prefix_blocks,
                                  committed_num_blocks);
  bool first_gap_phase = !candidate_has_gap;
  bool current_zero =
      filemirror_actual_block_is_zero(scalpel_state.filemirror, current_actualblocknumber);
  bool best_zero =
      candidate->newblock >= 0
      ? filemirror_actual_block_is_zero(scalpel_state.filemirror, candidate->newblock)
      : false;
  bool closer_local_support_exists =
      !candidate_has_gap
      && current_forward
      && current_distance > 0
      && jpg_reassembly_has_closer_viable_forward_block(candidate,
                                                        expected_next_apparentblocknumber,
                                                        current_apparentblocknumber);
  bool nearby_nonzero_forward_exists =
      first_gap_phase
      && current_forward
      && current_zero
      && jpg_reassembly_has_nearby_viable_forward_block(candidate,
                                                        current_apparentblocknumber + 1,
                                                        JPG_REASSEMBLY_LOCAL_COMMIT_WINDOW);
  bool better = false;
  bool equivalent = false;
  bool keep_existing_local = false;
  bool strong_local_commit = false;
  bool direct_progress = validates_to > baseline_validates_to;
  bool first_post_prefix_extension =
      committed_num_blocks == fixed_prefix_blocks;
  bool shallow_gap_phase =
      candidate_has_gap
      && current_forward
      && blockvector_get_num_blocks(candidate->b) <= (uint64_t)fixed_prefix_blocks + 3;
  bool validator_wrongblock =
      jpg_wrongblock_result.detected
      && jpg_wrongblock_result.method
      && (!strcmp(jpg_wrongblock_result.method, "huffman_invalid")
          || !strcmp(jpg_wrongblock_result.method, "rst_sequence"));

  if (first_gap_phase && current_forward && current_distance == 0) {
    if (current_zero) {
      rank_score =
          rank_score > JPG_REASSEMBLY_FIRST_GAP_ZERO_PENALTY
          ? rank_score - JPG_REASSEMBLY_FIRST_GAP_ZERO_PENALTY
          : 0;
    }
    else {
      rank_score += JPG_REASSEMBLY_FIRST_GAP_LOCAL_SUPPORT_BONUS;
    }
  }

  if (first_post_prefix_extension
      && current_forward
      && current_distance == 0
      && !current_zero
      && validates_to >= baseline_validates_to) {
    better = true;
    strong_local_commit = true;
  }

  if (jpg_reassembly_shallow_phase(candidate, fixed_prefix_blocks)
      && current_forward
      && validates_to >= baseline_validates_to) {
    rank_score = jpg_reassembly_probe_followon(candidate, trial_state, validates_to);
    if (first_gap_phase && current_distance == 0) {
      if (current_zero) {
        rank_score =
            rank_score > JPG_REASSEMBLY_FIRST_GAP_ZERO_PENALTY
            ? rank_score - JPG_REASSEMBLY_FIRST_GAP_ZERO_PENALTY
            : 0;
      }
      else {
        rank_score += JPG_REASSEMBLY_FIRST_GAP_LOCAL_SUPPORT_BONUS;
      }
    }
  }

  if (shallow_gap_phase) {
    if (validator_wrongblock) {
      rank_score =
          rank_score > JPG_REASSEMBLY_SHALLOW_WRONGBLOCK_PENALTY
          ? rank_score - JPG_REASSEMBLY_SHALLOW_WRONGBLOCK_PENALTY
          : 0;
    }
  }

  if (first_gap_phase
      && current_forward
      && current_distance == 0
      && current_zero
      && (!direct_progress || nearby_nonzero_forward_exists)) {
    keep_existing_local = true;
  }

  if (candidate_has_gap
      && current_forward
      && current_distance == 0
      && validates_to >= baseline_validates_to) {
    if (current_zero && validates_to == baseline_validates_to) {
      keep_existing_local = true;
    }
    else if (candidate->newblock < 0 || !best_forward || best_distance != 0) {
      better = true;
    }
    else if (rank_score > current_best_rank) {
      better = true;
    }
  }
  else if (candidate_has_gap
           && candidate->newblock >= 0
           && best_forward
           && best_distance == 0
           && current_forward
           && current_distance > 0
           && validates_to >= baseline_validates_to) {
    keep_existing_local = true;
  }

  if (!better && !keep_existing_local && closer_local_support_exists) {
    keep_existing_local = true;
  }

  if (!better && !keep_existing_local && candidate->newblock < 0) {
    better = rank_score > current_best_rank;
  }
  else if (!better && !keep_existing_local) {
    if (rank_score > current_best_rank + JPG_REASSEMBLY_NEAR_BEST_DELTA) {
      better = true;
    }
    else if (current_best_rank > rank_score + JPG_REASSEMBLY_NEAR_BEST_DELTA) {
      better = false;
    }
    else {
      if (current_forward && ! best_forward) {
        better = true;
      }
      else if (first_gap_phase && current_distance == 0 && !current_zero && best_zero) {
        better = true;
      }
      else if (first_gap_phase && current_zero && best_distance == 0 && !best_zero) {
        better = false;
      }
      else if (current_forward == best_forward
               && current_distance < best_distance) {
        better = true;
      }
      else if (current_forward == best_forward
               && current_distance == best_distance
               && rank_score > current_best_rank) {
        better = true;
      }
      else {
        equivalent = true;
      }
    }
  }

  // OPUS47: cold-state-probe-on-tie migrated from reassembly.c
  // (LR_reassembly_did_not_validate). When the trial exactly matches
  // baseline_validates_to and we have no best yet, and we're trying to
  // bridge a gap with a nearby forward choice, re-run validation from a
  // fresh cold state. If the cold validator's Huffman checkpoint advances
  // further than validates_to, use that as the frontier — this rescues
  // bridge trials that the incremental validator under-credited because
  // stale trial_state had an outdated huff checkpoint.
  if (!better && !equivalent
      && candidate->newblock < 0
      && validates_to == baseline_validates_to
      && candidate_has_gap
      && current_forward
      && current_distance < JPG_REASSEMBLY_LOCAL_COMMIT_WINDOW
      && blockvector_get_num_blocks(candidate->b) >= 2) {
    JPGCarveState cold_state;
    uint64_t cold_validates_to = 0;
    uint64_t cold_frontier;
    bool cold_validates;

    memset(&cold_state, 0, sizeof(cold_state));
    cold_validates = jpg_reassembly_validate_direct(candidate, &cold_state,
                                                    &cold_validates_to,
                                                    fixed_prefix_blocks);
    cold_frontier = cold_validates_to;
    if (!cold_validates
        && cold_state.valid
        && cold_state.huff_checkpoint.valid
        && cold_state.huff_checkpoint.byte_pos > cold_frontier + 1) {
      cold_frontier = cold_state.huff_checkpoint.byte_pos - 1;
    }

    if (cold_frontier > candidate->best_validates_to) {
      rank_score = cold_frontier;
      validates_to = cold_frontier;
      better = true;
    }
  }

  if (better) {
    if (candidate->newblock >= 0) {
      destroy_queue(candidate->best_choices);
    }
    *best_rank_score = rank_score;
    candidate->best_validates_to = validates_to;
    candidate->newblock = current_actualblocknumber;
    if (!candidate_has_gap
        && current_forward
        && current_distance < JPG_REASSEMBLY_LOCAL_COMMIT_WINDOW
        && direct_progress
        && rank_score > validates_to) {
      strong_local_commit = true;
    }
  }
  else if (candidate->newblock >= 0 && equivalent
           && current_actualblocknumber != candidate->newblock) {
    add_to_queue(candidate->best_choices, &current_actualblocknumber, 0);
  }

  jpg_reassembly_debug_dump(strong_local_commit ? "did_not_validate_strong_better"
                                   : (better ? "did_not_validate_better"
                                   : (equivalent ? "did_not_validate_equiv"
                                                 : "did_not_validate_worse")),
                            candidate, block_choice, validates_to);
  if (strong_local_commit) {
    return JPG_REASS_TRIAL_STRONG_BETTER;
  }
  if (better) {
    return JPG_REASS_TRIAL_BETTER;
  }
  if (equivalent) {
    return JPG_REASS_TRIAL_EQUIV;
  }
  return JPG_REASS_TRIAL_WORSE;
}

static inline int64_t jpg_reassembly_backtrack(CarveInfo *candidate,
                                               uuid_string_t uuidp,
                                               uuid_string_t uuidc,
                                               uint32_t fixed_prefix_blocks) {
  int64_t block_choice = -1;
  int64_t tail_apparentblocknumber;

  if (scalpel_state.mode_verbose) {
    display_blockvector(candidate->b, "JPG BACKTRACKING");
  }

  atomic_fetch_add_explicit(&scalpel_state.search_specs[candidate->needleidx].backtracked,
                            1, memory_order_acq_rel);

  if (scalpel_state.write_promising) {
    if (scalpel_state.mode_verbose) {
      lock_fprintf(stdout,
                   "\nJPG candidate with blockvector %p and UUIDs"
                   "\n%s / %s\ndidn't validate, writing current version and "
                   "backtracking.\n",
                   candidate->b, uuidp, uuidc);
    }
    write_candidate(&candidate, true);
  }

  while (blockvector_get_num_blocks(candidate->b) > fixed_prefix_blocks
         && blockvector_get_apparent_blocknumber(candidate->b,
                                                 blockvector_get_num_blocks(candidate->b) - 1) < 0) {
    resize_blockvector(candidate->b, blockvector_get_num_blocks(candidate->b) - 1);
  }
  if (blockvector_get_num_blocks(candidate->b) <= fixed_prefix_blocks) {
    return -1;
  }

  tail_apparentblocknumber =
      blockvector_get_apparent_blocknumber(candidate->b,
                                           blockvector_get_num_blocks(candidate->b) - 1);
  if (tail_apparentblocknumber >= 0) {
    blockvector_remove_choice(candidate->b,
                              blockvector_get_num_blocks(candidate->b) - 1,
                              tail_apparentblocknumber);
  }

  while (blockvector_get_num_blocks(candidate->b) > fixed_prefix_blocks
         && block_choice == -1) {
    if (jpg_reassembly_checkpoint_requested()) {
      return JPG_REASS_BLOCK_CHOICE_CHECKPOINT;
    }

    candidate->block_choice_start =
        blockvector_get_apparent_blocknumber(candidate->b,
                                             blockvector_get_num_blocks(candidate->b) - 1) + 1;
    block_choice = jpg_reassembly_get_block_choice(candidate);

    if (block_choice == JPG_REASS_BLOCK_CHOICE_CHECKPOINT) {
      return JPG_REASS_BLOCK_CHOICE_CHECKPOINT;
    }

    if (block_choice == -1) {
      resize_blockvector(candidate->b, blockvector_get_num_blocks(candidate->b) - 1);
    }
  }

  if (scalpel_state.mode_verbose) {
    display_blockvector(candidate->b, "AFTER JPG BACKTRACKING");
  }

  jpg_reassembly_debug_dump("backtrack_done", candidate, block_choice, 0);

  return block_choice;
}

static inline bool jpg_reassembly_gallop(CarveInfo *candidate,
                                         uint64_t *validates_to,
                                         bool *validates,
                                         uint64_t *gallop,
                                         uuid_string_t uuidp,
                                         uuid_string_t uuidc) {
  static const uint64_t boundary_slack = 4;
  int64_t pregallop_newblock;
  uint64_t pregallop_num_blocks;
  uint64_t pregallop_length;
  uint64_t gallop_count;
  int64_t last_block;
  int64_t next;
  uint64_t idx;

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

  last_block = filemirror_apparent_blocks(scalpel_state.filemirror);
  next = blockvector_get_apparent_blocknumber(candidate->b,
                                              blockvector_get_num_blocks(candidate->b) - 1) + 1;

  while (gallop_count < *gallop && next < last_block
         && next == blockvector_get_apparent_blocknumber(candidate->b,
                                                         blockvector_get_num_blocks(candidate->b) - 1) + 1
         && filemirror_get_blocktype(scalpel_state.filemirror,
                                     filemirror_actual_blocknumber(scalpel_state.filemirror, next),
                                     candidate->needleidx) != BLOCK_CONFIDENCE_INVALID
         && ! filemirror_actual_block_covered(scalpel_state.filemirror,
                                              filemirror_actual_blocknumber(scalpel_state.filemirror, next))
         && ! jpg_reassembly_apparent_in_blockvector_strict(candidate->b, next)) {
    if (jpg_reassembly_checkpoint_requested()) {
      candidate->newblock = pregallop_newblock;
      resize_blockvector(candidate->b, pregallop_num_blocks);
      blockvector_set_data_length(candidate->b, pregallop_length);
      candidate->fastpath = false;
      candidate->block_choice_start = -2;
      return true;
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

  if (! gallop_count) {
    candidate->block_choice_start = -2;
  }
  else {
    *validates = reassembly_check_validation(0, candidate, validates_to, uuidp, uuidc);
    if (!*validates && *validates_to <= candidate->best_validates_to) {
      JPGCarveState cold_state;
      uint64_t cold_validates_to = 0;
      bool cold_validates;

      memset(&cold_state, 0, sizeof(cold_state));
      cold_validates =
          jpg_reassembly_validate_direct(candidate, &cold_state,
                                         &cold_validates_to,
                                         jpg_reassembly_get_fixed_prefix_blocks(candidate));
      if (cold_validates || cold_validates_to > *validates_to) {
        *validates = cold_validates;
        *validates_to = cold_validates_to;
        if (cold_state.valid) {
          jpg_put_decoder_state(candidate->carvehashkey, &cold_state);
        }
      }
    }

    if (*validates) {
      blockvector_set_data_length(candidate->b, *validates_to + 1);
      resize_blockvector(candidate->b,
                         CEILDIV(blockvector_get_data_length(candidate->b),
                                 scalpel_state.blocksize));
    }
    else if (*validates_to > candidate->best_validates_to
             && (*validates_to >= blockvector_get_data_length(candidate->b) - 1
                 || blockvector_get_data_length(candidate->b) - 1 - *validates_to
                        <= boundary_slack)) {
      blockvector_set_data_length(candidate->b, *validates_to + 1);
      resize_blockvector(candidate->b,
                         CEILDIV(blockvector_get_data_length(candidate->b),
                                 scalpel_state.blocksize));

      for (idx = pregallop_num_blocks - 1;
           idx < blockvector_get_num_blocks(candidate->b);
           idx++) {
        blockvector_remove_choice(candidate->b, idx,
                                 blockvector_get_apparent_blocknumber(candidate->b, idx));
      }

      candidate->best_validates_to = blockvector_get_data_length(candidate->b) - 1;
      candidate->newblock = filemirror_actual_blocknumber(
          scalpel_state.filemirror,
          blockvector_get_apparent_blocknumber(candidate->b,
                                               blockvector_get_num_blocks(candidate->b) - 1));

      if (blockvector_get_data_length(candidate->b) % scalpel_state.blocksize) {
        *gallop = 0;
        candidate->block_choice_start =
            blockvector_get_apparent_blocknumber(candidate->b,
                                                 blockvector_get_num_blocks(candidate->b) - 1) + 1;
      }

      destroy_queue(candidate->best_choices);
    }
    else {
      candidate->newblock = pregallop_newblock;
      resize_blockvector(candidate->b, pregallop_num_blocks);
      blockvector_set_data_length(candidate->b, pregallop_length);
      candidate->fastpath = false;
      candidate->block_choice_start = -2;
    }
  }

  return false;
}

typedef struct JPGReassemblyForwardChoice {
  bool found;
  bool validates;
  bool has_followon_support;
  bool restart_not_due;
  bool have_state;
  bool have_boundary;
  bool reaches_trial_end;
  bool near_trial_end;
  bool is_immediate;
  int64_t apparent;
  int64_t actual;
  uint64_t commit_validates_to;
  uint64_t direct_validates_to;
  uint64_t score_validates_to;
  JpgBoundaryScore boundary;
  JPGCarveState state;
} JPGReassemblyForwardChoice;

static inline void jpg_forward_save_choice(
    JPGForwardScanChoice *saved, const JPGReassemblyForwardChoice *choice);
static inline bool jpg_forward_restore_choice(
    JPGReassemblyForwardChoice *choice, const JPGForwardScanChoice *saved);
static inline void jpg_forward_save_progress(
    JPGForwardScanProgress *progress, uint32_t scan_pass, int64_t next_actual,
    int64_t natural_tail_start, bool contiguous_tail_probed,
    bool backward_choice_found, const JPGReassemblyForwardChoice *best,
    const JPGReassemblyForwardChoice *before_backward);

// Identify the source mapping without including a speculative final slot.
static inline uint64_t jpg_forward_source_signature(CarveInfo *candidate,
                                                     uint64_t blocks) {
  uint64_t signature = 0;
  for (uint64_t i = 0; i < blocks; i++) {
    int64_t actual = blockvector_get_actual_blocknumber(candidate->b, i);
    signature = XXH3_64bits_withSeed(&actual, sizeof(actual), signature);
  }
  return signature;
}

// Fingerprint the apparent view only when saving or restoring an interrupted
// scan. A changed view can change adjacency and the evidence behind a score.
static inline uint64_t jpg_forward_view_signature(void) {
  int64_t actuals[256];
  uint64_t blocks = filemirror_apparent_blocks(scalpel_state.filemirror);
  uint64_t signature = 0;
  for (uint64_t first = 0; first < blocks;) {
    uint64_t count = blocks - first;
    if (count > 256) {
      count = 256;
    }
    for (uint64_t i = 0; i < count; i++) {
      actuals[i] = filemirror_actual_blocknumber(scalpel_state.filemirror,
                                                (int64_t)(first + i));
    }
    signature = XXH3_64bits_withSeed(actuals, count * sizeof(actuals[0]),
                                    signature);
    first += count;
  }
  return signature;
}

// Prefix preparation does not depend on whether a decoder cache was produced.
static inline bool jpg_forward_source_matches(
    CarveInfo *candidate, const JPGForwardScanProgress *progress,
    uint64_t blocks, uint64_t length) {
  return progress->active && blocks > 0 && length > 0
         && progress->source_blocks == blocks
         && progress->source_length == length
         && progress->source_signature
                == jpg_forward_source_signature(candidate, blocks);
}

// Reuse search decisions only for the same bytes, block choices, and ordering.
static inline bool jpg_forward_progress_matches(
    CarveInfo *candidate, const JPGForwardScanProgress *progress,
    uint64_t blocks, uint64_t length, uint32_t scan_mode) {
  return jpg_forward_source_matches(candidate, progress, blocks, length)
         && progress->scan_mode == scan_mode
         && progress->scan_pass <= 7
         && progress->view_blocks
                == filemirror_apparent_blocks(scalpel_state.filemirror)
         && progress->view_signature == jpg_forward_view_signature();
}

// Keep ranking evidence, but not a duplicate decoder cache for each choice.
static inline void jpg_forward_save_choice(
    JPGForwardScanChoice *saved, const JPGReassemblyForwardChoice *choice) {
  saved->found = choice->found;
  saved->validates = choice->validates;
  saved->has_followon_support = choice->has_followon_support;
  saved->restart_not_due = choice->restart_not_due;
  saved->have_boundary = choice->have_boundary;
  saved->reaches_trial_end = choice->reaches_trial_end;
  saved->near_trial_end = choice->near_trial_end;
  saved->is_immediate = choice->is_immediate;
  saved->actual = choice->actual;
  saved->commit_validates_to = choice->commit_validates_to;
  saved->direct_validates_to = choice->direct_validates_to;
  saved->score_validates_to = choice->score_validates_to;
  saved->boundary = choice->boundary;
}

// The stored prefix decoder state remains usable when this block is selected.
// If the competing choice is no longer available, repeat the scan rather than
// accepting a weaker alternative from only the unvisited part of the image.
static inline bool jpg_forward_restore_choice(
    JPGReassemblyForwardChoice *choice, const JPGForwardScanChoice *saved) {
  memset(choice, 0, sizeof(*choice));
  choice->apparent = -1;
  choice->actual = -1;
  if (!saved->found) {
    return true;
  }
  uint64_t image_blocks = CEILDIV(
      filemirror_filesize(scalpel_state.filemirror), scalpel_state.blocksize);
  if (saved->actual < 0 || (uint64_t)saved->actual >= image_blocks) {
    return false;
  }
  int64_t apparent = filemirror_apparent_blocknumber(scalpel_state.filemirror,
                                                    saved->actual);
  if (apparent < 0
      || filemirror_actual_block_covered(scalpel_state.filemirror,
                                         saved->actual)) {
    return false;
  }
  choice->found = saved->found;
  choice->validates = saved->validates;
  choice->has_followon_support = saved->has_followon_support;
  choice->restart_not_due = saved->restart_not_due;
  choice->have_boundary = saved->have_boundary;
  choice->reaches_trial_end = saved->reaches_trial_end;
  choice->near_trial_end = saved->near_trial_end;
  choice->is_immediate = saved->is_immediate;
  choice->apparent = apparent;
  choice->actual = saved->actual;
  choice->commit_validates_to = saved->commit_validates_to;
  choice->direct_validates_to = saved->direct_validates_to;
  choice->score_validates_to = saved->score_validates_to;
  choice->boundary = saved->boundary;
  return true;
}

// Record the start of a trial. An interruption inside one of its probes must
// repeat that trial, not skip work whose result is not yet known.
static inline void jpg_forward_save_progress(
    JPGForwardScanProgress *progress, uint32_t scan_pass, int64_t next_actual,
    int64_t natural_tail_start, bool contiguous_tail_probed,
    bool backward_choice_found, const JPGReassemblyForwardChoice *best,
    const JPGReassemblyForwardChoice *before_backward) {
  progress->active = true;
  progress->pass_complete = false;
  progress->scan_pass = scan_pass;
  progress->next_actual = next_actual;
  progress->natural_tail_actual = natural_tail_start >= 0
      ? filemirror_actual_blocknumber(scalpel_state.filemirror, natural_tail_start)
      : -1;
  progress->contiguous_tail_probed = contiguous_tail_probed;
  progress->backward_choice_found = backward_choice_found;
  jpg_forward_save_choice(&progress->best, best);
  jpg_forward_save_choice(&progress->before_backward, before_backward);
}

typedef struct {
  bool pending;
  uint64_t num_blocks;
  uint64_t length;
  uint64_t best_validates_to;
  int64_t newblock;
  int64_t block_choice_start;
  bool chopped;
  bool fastpath;
  bool have_prefix_state;
  int64_t *apparent_blocks;
  JPGCarveState prefix_state;
  JPGReassemblyForwardChoice choice;
} JPGReassemblyFallback;

static inline void jpg_reassembly_clear_fallback(
    JPGReassemblyFallback *fallback) {
  if (!fallback) {
    return;
  }

  free(fallback->apparent_blocks);
  memset(fallback, 0, sizeof(*fallback));
}

static inline void jpg_reassembly_save_fallback(
    CarveInfo *candidate,
    const JPGCarveState *prefix_state,
    bool have_prefix_state,
    const JPGReassemblyForwardChoice *choice,
    JPGReassemblyFallback *fallback) {
  if (!candidate || !candidate->b || !choice || !choice->found || !fallback
      || fallback->pending) {
    return;
  }

  fallback->num_blocks = blockvector_get_num_blocks(candidate->b);
  fallback->length = blockvector_get_data_length(candidate->b);
  fallback->best_validates_to = candidate->best_validates_to;
  fallback->newblock = candidate->newblock;
  fallback->block_choice_start = candidate->block_choice_start;
  fallback->chopped = candidate->chopped;
  fallback->fastpath = candidate->fastpath;
  fallback->have_prefix_state = have_prefix_state;
  fallback->choice = *choice;
  if (have_prefix_state) {
    fallback->prefix_state = *prefix_state;
  }

  fallback->apparent_blocks =
      malloc(fallback->num_blocks * sizeof(*fallback->apparent_blocks));
  check_memory_allocation(fallback->apparent_blocks, __LINE__, __FILE__,
                          "jpg fallback apparent blocks");
  for (uint64_t i = 0; i < fallback->num_blocks; i++) {
    fallback->apparent_blocks[i] =
        blockvector_get_apparent_blocknumber(candidate->b, i);
  }
  fallback->pending = true;
}

static inline bool jpg_reassembly_restore_fallback(
    CarveInfo *candidate,
    JPGReassemblyFallback *fallback,
    bool *validates,
    uint64_t *validates_to) {
  JPGReassemblyForwardChoice choice;

  if (!candidate || !candidate->b || !fallback || !fallback->pending
      || !validates || !validates_to) {
    return false;
  }

  choice = fallback->choice;
  resize_blockvector(candidate->b, fallback->num_blocks);
  for (uint64_t i = 0; i < fallback->num_blocks; i++) {
    blockvector_set_apparent_blocknumber(candidate->b, i,
                                         fallback->apparent_blocks[i]);
  }
  blockvector_set_data_length(candidate->b, fallback->length);
  inflate_blockvector(candidate->b);

  candidate->best_validates_to = fallback->best_validates_to;
  candidate->newblock = fallback->newblock;
  candidate->block_choice_start = fallback->block_choice_start;
  candidate->chopped = fallback->chopped;
  candidate->fastpath = fallback->fastpath;
  if (fallback->have_prefix_state) {
    jpg_put_decoder_state(candidate->carvehashkey, &fallback->prefix_state);
  }

  resize_blockvector(candidate->b, fallback->num_blocks + 1);
  blockvector_set_apparent_blocknumber(candidate->b, fallback->num_blocks,
                                       choice.apparent);
  (void)inflate_blockvector_single_block(candidate->b,
                                         fallback->num_blocks);
  *validates = choice.validates;
  *validates_to = choice.commit_validates_to;
  if (choice.have_state) {
    jpg_put_decoder_state(candidate->carvehashkey, &choice.state);
  }
  candidate->best_validates_to = *validates_to;
  candidate->newblock = choice.actual;
  candidate->fastpath = false;
  blockvector_set_data_length(candidate->b, *validates_to + 1);
  resize_blockvector(candidate->b,
                     CEILDIV(blockvector_get_data_length(candidate->b),
                             scalpel_state.blocksize));
  jpg_reassembly_debug_dump("forward_fallback_accept", candidate,
                            choice.apparent, choice.score_validates_to);
  jpg_reassembly_clear_fallback(fallback);
  return true;
}

// Publish the checked part of the current mapping on checkpoint-and-exit.
// Ordinary checkpoints only save search state; they do not create partial files.
static inline void jpg_reassembly_publish_exit_prefix(
    CarveInfo *candidate, uint64_t validates_to) {
  if (!candidate || !candidate->b || candidate->flavor == VALIDATED
      || !scalpel_state.write_promising || scalpel_state.blocksize == 0
      || !atomic_load_explicit(&REASS_RETURN_TO_IDLE, memory_order_acquire)
      || !atomic_load_explicit(&TAKE_CHECKPOINT_AND_EXIT, memory_order_acquire)
      || validates_to == UINT64_MAX) {
    return;
  }
  uint64_t length = blockvector_get_data_length(candidate->b);
  if (validates_to == 0 || validates_to >= length) {
    return;
  }
  uint64_t retained = validates_to + 1;
  uint64_t count = 1 + (retained - 1) / scalpel_state.blocksize;
  if (count > blockvector_get_num_blocks(candidate->b)) {
    return;
  }

  BlockVector *partial = NULL;
  clone_blockvector(candidate->b, &partial, false);
  resize_blockvector(partial, count);
  blockvector_set_data_length(partial, retained);
  inflate_blockvector(partial);
  BlockVector *original = candidate->b;
  CarveInfoFlavor flavor = candidate->flavor;
  candidate->b = partial;
  candidate->flavor = PROMISING;
  write_candidate(&candidate, true);
  candidate->b = original;
  candidate->flavor = flavor;
  free_blockvector(&partial);
}

static inline bool jpg_reassembly_time_to_checkpoint(
    int id,
    CarveInfo *candidate,
    uuid_string_t uuidp,
    uuid_string_t uuidc,
    JPGReassemblyFallback *fallback,
    bool *validates,
    uint64_t *validates_to,
    const JPGForwardScanProgress *forward_progress) {
  if (!jpg_reassembly_checkpoint_requested()) {
    jpg_reassembly_publish_exit_prefix(candidate, *validates_to);
    return false;
  }
  if (fallback && fallback->pending) {
    (void)jpg_reassembly_restore_fallback(candidate, fallback, validates,
                                          validates_to);
  }
  if (jpg_forward_source_matches(
             candidate, forward_progress, blockvector_get_num_blocks(candidate->b),
             blockvector_get_data_length(candidate->b))) {
    JPGCarveState state;
    (void)jpg_reassembly_load_saved_state(candidate, &state);
    state.forward_scan_progress = *forward_progress;
    state.forward_scan_progress.view_blocks =
        filemirror_apparent_blocks(scalpel_state.filemirror);
    state.forward_scan_progress.view_signature = jpg_forward_view_signature();
    jpg_put_decoder_state(candidate->carvehashkey, &state);
    *validates_to = forward_progress->source_length - 1;
  }
  jpg_reassembly_publish_exit_prefix(candidate, *validates_to);
  jpg_save_retry_checkpoint(candidate);
  return reassembly_time_to_checkpoint(id, candidate, uuidp, uuidc);
}

enum {
  JPG_REASS_OOO_MIN_RUN = 1,
  JPG_REASS_OOO_MAX_RUN = 8,
  JPG_REASS_OOO_SUFFIX_PROBE = 128,
  JPG_REASS_OOO_MIN_SUFFIX_PROBE = 2,
  JPG_REASS_OOO_GLOBAL_MIN_SUFFIX_PROBE = 3,
  JPG_REASS_BASELINE_STRONG_SUFFIX_PROBE = 4,
  /* full-image probing is expensive and riskier, so use it only for
     short first-seam repairs or after a non-clean suffix trial. */
  JPG_REASS_OOO_FIRST_GLOBAL_MAX_RUN = 3,
  JPG_REASS_OOO_BOUNDARY_SLACK = 4,
  JPG_REASS_OOO_ANCHOR_BACKSCAN_BLOCKS = 12,
  JPG_REASS_OOO_STRICT_ANCHOR_BACKSCAN_BLOCKS = 40,
  JPG_REASS_OOO_PRIORITY_BACKSCAN_BLOCKS = 2048,
  JPG_REASS_OOO_LOCAL_BACKSCAN_BLOCKS = 8192,
  JPG_REASS_OOO_RAW_ANCHOR_SCAN_MAX = 32768,
  JPG_REASS_OOO_MAX_TRIALS = 32768,
  JPG_REASS_BASELINE_SEED_PROBE_BYTES = 16 * 1024,
  JPG_REASS_SMALL_BLOCK_BRIDGE_BYTES = 8 * 1024,
  JPG_REASS_BASELINE_SCATTER_PROBE_BYTES = 32 * 1024
};

#define JPG_REASS_PROGRESSIVE_RATE_LIMIT 0.08
#define JPG_REASS_PROGRESSIVE_BOUNDARY_RATIO 1.25
#define JPG_REASS_PROGRESSIVE_CONTINUATION_BOUNDARY_LIMIT 1.00
#define JPG_REASS_SCATTER_ENTRY_RATIO 0.75
#define JPG_REASS_BASELINE_RATE_LIMIT 0.04
#define JPG_REASS_BASELINE_STRONG_RATE_LIMIT 0.02
#define JPG_REASS_BASELINE_LOCAL_RATE_LIMIT 0.08
#define JPG_REASS_ICC_CURVE_SCORE_LIMIT 1.00
#define JPG_REASS_ICC_CURVE_SCORE_RATIO 4.00
#define JPG_REASS_BASELINE_BRIDGE_SCORE_LIMIT 2.00
#define JPG_REASS_BASELINE_SUFFIX_BOUNDARY_LIMIT 1.00
#define JPG_REASS_BASELINE_CONTIGUOUS_BOUNDARY_RATIO 1.10
#define JPG_REASS_BASELINE_FORWARD_BRIDGE_RATIO 0.85
#define JPG_REASS_SCATTER_LOOKAHEAD_RATIO 1.10
#define JPG_REASS_SCATTER_LOOKAHEAD_SLACK 0.10
#define JPG_REASS_BASELINE_DC_DISCONTINUITY_RATIO 1.50
#define JPG_REASS_BASELINE_UNSUPPORTED_SCORE_LIMIT \
  (JPG_REASS_BASELINE_BRIDGE_SCORE_LIMIT * 4.0)

typedef struct JpgOOOBridgeChoice {
  bool found;
  bool full_validates;
  bool direct_validates;
  bool huffman_available;
  bool huffman_support;
  bool progressive_entropy_supported;
  bool progressive_entropy_complete;
  bool progressive_entropy_contiguous;
  bool baseline_rate_supported;
  bool dc_discontinuity_supported;
  bool entropy_profile_supported;
  bool hidden_boundary_candidate;
  uint32_t hidden_boundary_rank;
  bool apparent_continuation;
  int64_t moved_start;
  uint64_t run_len;
  int64_t suffix_start;
  uint64_t suffix_len;
  double progressive_entropy_score;
  double baseline_rate_deviation;
  double entropy_profile_deviation;
  double hidden_boundary_score;
  double max_dc_discontinuity;
  JpgBoundaryScore boundary;
  JpgBoundaryScore suffix_boundary;
} JpgOOOBridgeChoice;

enum {
  JPG_REASS_BRIDGE_SHORTLIST_SIZE = JPG_HIDDEN_BOUNDARY_CHOICES,
  JPG_REASS_DEFAULT_SHORTLIST_SIZE = 8,
  JPG_REASS_SCATTER_LOOKAHEAD_CHOICES = 3,
  JPG_REASS_RETRY_CHOICES = JPG_REASS_BRIDGE_SHORTLIST_SIZE * 2 + 1,
  JPG_REASS_RETRY_FRAMES = 16,
  JPG_REASS_RETRY_LIMIT = 32
};

typedef struct {
  uint32_t count;
  JpgOOOBridgeChoice choices[JPG_REASS_BRIDGE_SHORTLIST_SIZE];
  uint32_t entry_only_count;
  JpgOOOBridgeChoice entry_only_choices[JPG_REASS_BRIDGE_SHORTLIST_SIZE];
} JpgOOOBridgeShortlist;

static _Thread_local JpgOOOBridgeShortlist *jpg_reassembly_bridge_shortlist;

typedef struct {
  uint64_t num_blocks;
  uint64_t length;
  uint64_t best_validates_to;
  int64_t newblock;
  int64_t block_choice_start;
  bool chopped;
  bool fastpath;
  bool have_prefix_state;
  int64_t *apparent_blocks;
  JPGCarveState prefix_state;
  bool have_selected_choice;
  bool defer_initial_retry;
  JpgOOOBridgeChoice selected_choice;
  double retry_priority;
  uint32_t next_choice;
  uint32_t choice_count;
  JpgOOOBridgeChoice choices[JPG_REASS_RETRY_CHOICES];
} JpgReassemblyRetryFrame;

typedef struct JpgReassemblyRetrySearch {
  bool replay_started;
  uint32_t attempts;
  uint32_t frame_count;
  JpgReassemblyRetryFrame frames[JPG_REASS_RETRY_FRAMES];
} JpgReassemblyRetrySearch;

typedef struct {
  int64_t first;
  uint64_t count;
} JpgRetryRun;

struct JpgSavedRetryFrame {
  JpgReassemblyRetryFrame frame;
  uint64_t run_count;
  JpgRetryRun *runs;
  uint64_t selected_signature[2];
  uint64_t signatures[JPG_REASS_RETRY_CHOICES][2];
};

struct JpgSavedRetrySearch {
  bool replay_started;
  uint32_t attempts;
  uint32_t frame_count;
  JpgSavedRetryFrame frames[JPG_REASS_RETRY_FRAMES];
};

// Release every saved prefix and its search state.
static inline void jpg_retry_storage_free(JpgSavedRetrySearch **storage) {
  if (!storage || !*storage) {
    return;
  }
  for (uint32_t i = 0; i < (*storage)->frame_count; i++) {
    free((*storage)->frames[i].runs);
  }
  free(*storage);
  *storage = NULL;
}

// Give each stored state its own compact prefix runs.
static inline JpgSavedRetrySearch *
jpg_retry_storage_clone(const JpgSavedRetrySearch *source) {
  if (!source) {
    return NULL;
  }
  JpgSavedRetrySearch *copy = malloc(sizeof(*copy));
  check_memory_allocation(copy, __LINE__, __FILE__, "jpg saved retries");
  *copy = *source;
  for (uint32_t i = 0; i < copy->frame_count; i++) {
    const uint64_t count = copy->frames[i].run_count;
    copy->frames[i].runs = malloc(count * sizeof(JpgRetryRun));
    check_memory_allocation(copy->frames[i].runs, __LINE__, __FILE__,
                            "jpg saved prefix");
    memcpy(copy->frames[i].runs, source->frames[i].runs,
           count * sizeof(JpgRetryRun));
  }
  return copy;
}

// Check bounds before accessing the actual block map.
static inline bool jpg_retry_actual_available(int64_t actual) {
  if (actual < 0 || !scalpel_state.blocksize) {
    return false;
  }
  const uint64_t bytes = filemirror_filesize(scalpel_state.filemirror);
  const uint64_t blocks =
      bytes / scalpel_state.blocksize + (bytes % scalpel_state.blocksize != 0);
  return (uint64_t)actual < blocks &&
         !filemirror_actual_block_covered(scalpel_state.filemirror, actual);
}

// A saved range must describe the same physical blocks after remapping.
static inline bool jpg_retry_range_signature(int64_t start, uint64_t count,
                                             uint64_t *signature) {
  const uint64_t available =
      filemirror_apparent_blocks(scalpel_state.filemirror);
  if (!count || start < 0 || (uint64_t)start > available ||
      count > available - (uint64_t)start) {
    return false;
  }
  uint64_t hash = UINT64_C(1469598103934665603);
  for (uint64_t i = 0; i < count; i++) {
    const int64_t actual = filemirror_actual_blocknumber(
        scalpel_state.filemirror, start + (int64_t)i);
    if (!jpg_retry_actual_available(actual)) {
      return false;
    }
    hash = (hash ^ (uint64_t)actual) * UINT64_C(1099511628211);
  }
  *signature = hash;
  return true;
}

// Store physical starts and signatures for the moved run and optional suffix.
static inline bool jpg_retry_save_choice(JpgOOOBridgeChoice *choice,
                                         uint64_t signature[2]) {
  if (!choice->found) {
    return true;
  }
  if (!jpg_retry_range_signature(choice->moved_start, choice->run_len,
                                 &signature[0]) ||
      (choice->suffix_len &&
       !jpg_retry_range_signature(choice->suffix_start, choice->suffix_len,
                                  &signature[1]))) {
    return false;
  }
  choice->moved_start = filemirror_actual_blocknumber(scalpel_state.filemirror,
                                                      choice->moved_start);
  if (choice->suffix_len) {
    choice->suffix_start = filemirror_actual_blocknumber(
        scalpel_state.filemirror, choice->suffix_start);
  }
  return true;
}

// Remap a choice only if coverage has left both source ranges intact.
static inline bool jpg_retry_load_choice(JpgOOOBridgeChoice *choice,
                                         const uint64_t signature[2]) {
  if (!choice->found) {
    return true;
  }
  uint64_t observed;
  if (!jpg_retry_actual_available(choice->moved_start) ||
      (choice->suffix_len &&
       !jpg_retry_actual_available(choice->suffix_start))) {
    return false;
  }
  choice->moved_start = filemirror_apparent_blocknumber(
      scalpel_state.filemirror, choice->moved_start);
  if (!jpg_retry_range_signature(choice->moved_start, choice->run_len,
                                 &observed) ||
      observed != signature[0]) {
    return false;
  }
  if (choice->suffix_len) {
    choice->suffix_start = filemirror_apparent_blocknumber(
        scalpel_state.filemirror, choice->suffix_start);
    if (!jpg_retry_range_signature(choice->suffix_start, choice->suffix_len,
                                   &observed) ||
        observed != signature[1]) {
      return false;
    }
  }
  return true;
}

// Prefixes are compact physical runs; no trial bytes are retained or written.
static inline JpgSavedRetrySearch *
jpg_retry_store(const JpgReassemblyRetrySearch *search) {
  if (!search || (!search->frame_count && !search->attempts)) {
    return NULL;
  }
  JpgSavedRetrySearch *saved = calloc(1, sizeof(*saved));
  check_memory_allocation(saved, __LINE__, __FILE__, "jpg retry checkpoint");
  saved->replay_started = search->replay_started;
  saved->attempts = search->attempts;
  const uint64_t available =
      filemirror_apparent_blocks(scalpel_state.filemirror);
  for (uint32_t i = 0; i < search->frame_count; i++) {
    const JpgReassemblyRetryFrame *frame = &search->frames[i];
    JpgSavedRetryFrame *entry = &saved->frames[saved->frame_count];
    entry->frame = *frame;
    entry->frame.apparent_blocks = NULL;
    entry->run_count = 0;
    entry->runs = malloc(frame->num_blocks * sizeof(*entry->runs));
    check_memory_allocation(entry->runs, __LINE__, __FILE__,
                            "jpg retry physical runs");
    for (uint64_t slot = 0; slot < frame->num_blocks; slot++) {
      const int64_t apparent = frame->apparent_blocks[slot];
      if (apparent < 0 || (uint64_t)apparent >= available) {
        handle_error(SCALPEL_GENERAL_ABORT, "Invalid JPEG retry prefix",
                     __LINE__, __FILE__);
      }
      const int64_t actual =
          filemirror_actual_blocknumber(scalpel_state.filemirror, apparent);
      if (entry->run_count &&
          entry->runs[entry->run_count - 1].first +
                  (int64_t)entry->runs[entry->run_count - 1].count ==
              actual) {
        entry->runs[entry->run_count - 1].count++;
      }
      else {
        entry->runs[entry->run_count++] = (JpgRetryRun){actual, 1};
      }
    }
    entry->runs = realloc(entry->runs, entry->run_count * sizeof(*entry->runs));
    check_memory_allocation(entry->runs, __LINE__, __FILE__,
                            "jpg compact retry prefix");
    if (entry->frame.block_choice_start >= 0 &&
        (uint64_t)entry->frame.block_choice_start < available) {
      entry->frame.block_choice_start = filemirror_actual_blocknumber(
          scalpel_state.filemirror, entry->frame.block_choice_start);
    }
    else if (entry->frame.block_choice_start >= 0) {
      entry->frame.block_choice_start = INT64_MAX;
    }
    if (entry->frame.have_selected_choice &&
        !jpg_retry_save_choice(&entry->frame.selected_choice,
                               entry->selected_signature)) {
      entry->frame.have_selected_choice = false;
    }
    for (uint32_t j = 0; j < frame->choice_count; j++) {
      if (!jpg_retry_save_choice(&entry->frame.choices[j],
                                 entry->signatures[j])) {
        entry->frame.choices[j].found = false;
      }
    }
    saved->frame_count++;
  }
  return saved;
}

// Restore surviving frames without resetting completed choices or attempts.
static inline void jpg_retry_load(const JpgSavedRetrySearch *saved,
                                  JpgReassemblyRetrySearch *search) {
  if (!saved) {
    return;
  }
  search->replay_started = saved->replay_started;
  search->attempts = saved->attempts;
  const uint64_t available =
      filemirror_apparent_blocks(scalpel_state.filemirror);
  for (uint32_t i = 0; i < saved->frame_count; i++) {
    const JpgSavedRetryFrame *entry = &saved->frames[i];
    const JpgReassemblyRetryFrame *source = &entry->frame;
    if (source->num_blocks > available ||
        source->num_blocks > SIZE_MAX / sizeof(int64_t)) {
      continue;
    }
    JpgReassemblyRetryFrame *frame = &search->frames[search->frame_count];
    *frame = *source;
    frame->apparent_blocks =
        malloc(frame->num_blocks * sizeof(*frame->apparent_blocks));
    check_memory_allocation(frame->apparent_blocks, __LINE__, __FILE__,
                            "jpg resumed retry prefix");
    uint64_t slot = 0;
    bool valid = true;
    for (uint64_t j = 0; j < entry->run_count && valid; j++) {
      for (uint64_t k = 0; k < entry->runs[j].count; k++) {
        const int64_t actual = entry->runs[j].first + (int64_t)k;
        if (!jpg_retry_actual_available(actual)) {
          valid = false;
          break;
        }
        const int64_t apparent =
            filemirror_apparent_blocknumber(scalpel_state.filemirror, actual);
        if (apparent < 0) {
          valid = false;
          break;
        }
        frame->apparent_blocks[slot++] = apparent;
      }
    }
    if (!valid) {
      free(frame->apparent_blocks);
      memset(frame, 0, sizeof(*frame));
      continue;
    }
    if (frame->block_choice_start == INT64_MAX) {
      frame->block_choice_start = (int64_t)available;
    }
    else if (frame->block_choice_start >= 0) {
      frame->block_choice_start =
          jpg_reassembly_apparent_lower_bound(frame->block_choice_start);
    }
    if (frame->have_selected_choice &&
        !jpg_retry_load_choice(&frame->selected_choice,
                               entry->selected_signature)) {
      frame->have_selected_choice = false;
    }
    frame->choice_count = 0;
    frame->next_choice = 0;
    for (uint32_t j = 0; j < source->choice_count; j++) {
      JpgOOOBridgeChoice choice = source->choices[j];
      if (choice.found &&
          jpg_retry_load_choice(&choice, entry->signatures[j])) {
        frame->choices[frame->choice_count++] = choice;
        if (j < source->next_choice) {
          frame->next_choice++;
        }
      }
    }
    search->frame_count++;
  }
}

// Deep copy stored state, including its owned retry prefixes.
static inline void *jpg_clone_carve_state(const void *state) {
  const JPGStoredCarveState *source = state;
  JPGStoredCarveState *copy = malloc(sizeof(*copy));
  check_memory_allocation(copy, __LINE__, __FILE__, "jpg stored state");
  *copy = *source;
  copy->retry = jpg_retry_storage_clone(source->retry);
  return copy;
}

// Release stored state and clear the caller's pointer.
static inline void jpg_free_carve_state(void **state) {
  if (state && *state) {
    JPGStoredCarveState *value = *state;
    jpg_retry_storage_free(&value->retry);
    free(value);
    *state = NULL;
  }
}

// Owned pointers require the clone callback rather than a shallow memcpy.
static inline size_t jpg_sizeof_carve_state(const void *state) {
  (void)state;
  return 0;
}

// Transfer one checkpoint field in the requested direction.
static inline bool jpg_retry_transfer(FILE *fp, void *value, size_t size,
                                      StateSerialization mode) {
  return mode == SERIALIZE ? fwrite(value, size, 1, fp) == 1
                           : fread(value, size, 1, fp) == 1;
}

// Check prefix geometry and count bounds before a frame can be restored.
static inline bool jpg_retry_frame_valid(const JpgSavedRetryFrame *saved) {
  const JpgReassemblyRetryFrame *frame = &saved->frame;
  if (!frame->num_blocks || frame->num_blocks > INT64_MAX || !frame->length ||
      !scalpel_state.blocksize ||
      frame->num_blocks < 1 + (frame->length - 1) / scalpel_state.blocksize ||
      frame->choice_count > JPG_REASS_RETRY_CHOICES ||
      frame->next_choice > frame->choice_count || !saved->run_count ||
      saved->run_count > frame->num_blocks) {
    return false;
  }
  uint64_t total = 0;
  for (uint64_t i = 0; i < saved->run_count; i++) {
    const JpgRetryRun *run = &saved->runs[i];
    if (run->first < 0 || !run->count ||
        run->count > (uint64_t)INT64_MAX - (uint64_t)run->first ||
        run->count > frame->num_blocks - total) {
      return false;
    }
    total += run->count;
  }
  return total == frame->num_blocks;
}

// Checkpoint decoder state and compact retry history without serializing
// ownership.
static inline bool jpg_serialize_carve_state(void **state, FILE *fp,
                                             StateSerialization mode) {
  uint64_t magic = UINT64_C(0x4a50474657524434);
  JPGStoredCarveState *value = mode == SERIALIZE ? *state : NULL;
  bool okay = jpg_retry_transfer(fp, &magic, sizeof(magic), mode) &&
              magic == UINT64_C(0x4a50474657524434);
  if (mode == DESERIALIZE && okay) {
    value = calloc(1, sizeof(*value));
    check_memory_allocation(value, __LINE__, __FILE__, "jpg restored state");
  }
  uint32_t present = value && value->retry ? 1 : 0;
  okay =
      okay &&
      jpg_retry_transfer(fp, &value->decoder, sizeof(value->decoder), mode) &&
      jpg_retry_transfer(fp, &present, sizeof(present), mode) && present <= 1;
  if (okay && present) {
    if (mode == DESERIALIZE) {
      value->retry = calloc(1, sizeof(*value->retry));
      check_memory_allocation(value->retry, __LINE__, __FILE__,
                              "jpg restored retries");
    }
    JpgSavedRetrySearch *saved = value->retry;
    okay = jpg_retry_transfer(fp, &saved->replay_started,
                              sizeof(saved->replay_started), mode) &&
           jpg_retry_transfer(fp, &saved->attempts, sizeof(saved->attempts),
                              mode) &&
           saved->attempts <= JPG_REASS_RETRY_LIMIT &&
           jpg_retry_transfer(fp, &saved->frame_count,
                              sizeof(saved->frame_count), mode) &&
           saved->frame_count <= JPG_REASS_RETRY_FRAMES;
    if (!okay) {
      saved->frame_count = 0;
    }
    for (uint32_t i = 0; okay && i < saved->frame_count; i++) {
      JpgSavedRetryFrame *entry = &saved->frames[i];
      okay =
          jpg_retry_transfer(fp, &entry->frame, sizeof(entry->frame), mode) &&
          entry->frame.apparent_blocks == NULL &&
          jpg_retry_transfer(fp, &entry->run_count, sizeof(entry->run_count),
                             mode) &&
          entry->run_count > 0 &&
          entry->run_count <= SIZE_MAX / sizeof(JpgRetryRun) &&
          entry->run_count <= entry->frame.num_blocks;
      if (okay && mode == DESERIALIZE) {
        const off_t position = ftello(fp);
        struct stat status;
        okay = position >= 0 && fstat(fileno(fp), &status) == 0 &&
               status.st_size >= position &&
               entry->run_count <=
                   (uint64_t)(status.st_size - position) / sizeof(JpgRetryRun);
        if (okay) {
          entry->runs = malloc(entry->run_count * sizeof(JpgRetryRun));
          check_memory_allocation(entry->runs, __LINE__, __FILE__,
                                  "jpg restored prefix runs");
        }
      }
      okay = okay &&
             jpg_retry_transfer(fp, entry->runs,
                                entry->run_count * sizeof(JpgRetryRun), mode) &&
             jpg_retry_frame_valid(entry) &&
             jpg_retry_transfer(fp, entry->selected_signature,
                                sizeof(entry->selected_signature), mode) &&
             jpg_retry_transfer(fp, entry->signatures,
                                sizeof(entry->signatures), mode);
    }
  }
  if (!okay) {
    if (mode == DESERIALIZE) {
      jpg_free_carve_state((void **)&value);
    }
    handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
    return false;
  }
  if (mode == DESERIALIZE) {
    *state = value;
  }
  return true;
}

// Snapshot the active search before returning its candidate for checkpointing.
static inline void jpg_save_retry_checkpoint(CarveInfo *candidate) {
  if (!candidate || candidate->carvehashkey != jpg_active_retry_key ||
      !jpg_active_retry_search) {
    return;
  }
  void *stored = carve_get_state(candidate->carvehashkey);
  JPGStoredCarveState value = {0};
  if (stored) {
    value.decoder = ((JPGStoredCarveState *)stored)->decoder;
  }
  value.retry = jpg_retry_store(jpg_active_retry_search);
  carve_put_state(candidate->carvehashkey, &value);
  jpg_retry_storage_free(&value.retry);
  jpg_free_carve_state(&stored);
}

// Transfer saved alternatives into the invocation's mutable search state.
static inline void jpg_load_retry_checkpoint(CarveInfo *candidate,
                                             JpgReassemblyRetrySearch *search) {
  void *stored = carve_get_state(candidate->carvehashkey);
  if (!stored) {
    return;
  }
  JPGStoredCarveState *value = stored;
  jpg_retry_load(value->retry, search);
  jpg_retry_storage_free(&value->retry);
  carve_put_state(candidate->carvehashkey, value);
  jpg_free_carve_state(&stored);
}

static inline bool jpg_reassembly_baseline_bridge_beats_forward(
    const JpgOOOBridgeChoice *bridge,
    const JPGReassemblyForwardChoice *forward);

static inline void
jpg_reassembly_clear_retry_frame(JpgReassemblyRetryFrame *frame) {
  if (!frame) {
    return;
  }
  free(frame->apparent_blocks);
  memset(frame, 0, sizeof(*frame));
}

static inline void jpg_reassembly_clear_retry_search(
    JpgReassemblyRetrySearch *search) {
  if (!search) {
    return;
  }
  for (uint32_t i = 0; i < search->frame_count; i++) {
    free(search->frames[i].apparent_blocks);
  }
  memset(search, 0, sizeof(*search));
}

static inline bool jpg_reassembly_same_bridge_choice(
    const JpgOOOBridgeChoice *left,
    const JpgOOOBridgeChoice *right) {
  return left && right
         && left->moved_start == right->moved_start
         && left->run_len == right->run_len
         && left->suffix_len == right->suffix_len
         && (left->suffix_len == 0
             || left->suffix_start == right->suffix_start);
}

static inline void jpg_reassembly_add_retry_choice(
    JpgReassemblyRetryFrame *frame,
    const JpgOOOBridgeChoice *choice,
    const JpgOOOBridgeChoice *chosen,
    const JPGReassemblyForwardChoice *forward) {
  if (!frame || !choice || !choice->found
      || frame->choice_count >= JPG_REASS_RETRY_CHOICES
      || jpg_reassembly_same_bridge_choice(choice, chosen)
      || (forward && forward->found && choice->run_len == 1
          && choice->suffix_len == 0
          && choice->moved_start == forward->apparent)) {
    return;
  }
  for (uint32_t i = 0; i < frame->choice_count; i++) {
    if (jpg_reassembly_same_bridge_choice(&frame->choices[i], choice)) {
      return;
    }
  }
  frame->choices[frame->choice_count++] = *choice;
}

static inline double jpg_reassembly_retry_choice_score(
    const JpgOOOBridgeChoice *choice) {
  double score = choice && choice->boundary.valid
                     ? choice->boundary.normalized
                     : JPG_REASS_BASELINE_BRIDGE_SCORE_LIMIT;

  if (!choice) {
    return HUGE_VAL;
  }
  if (choice->hidden_boundary_candidate) {
    return (double)choice->hidden_boundary_rank;
  }
  if (choice->baseline_rate_supported) {
    score += 2.5 * choice->baseline_rate_deviation;
  }
  if (choice->dc_discontinuity_supported) {
    score += fmin(0.005 * choice->max_dc_discontinuity, 1.0);
  }
  if (choice->suffix_len > 0) {
    score -= 0.25;
  }
  if (choice->apparent_continuation) {
    score -= 0.5;
  }
  return score;
}

static inline bool jpg_reassembly_retry_choice_better(
    const JpgOOOBridgeChoice *trial,
    const JpgOOOBridgeChoice *best) {
  double trial_score;
  double best_score;

  if (!trial || !trial->found) {
    return false;
  }
  if (!best || !best->found) {
    return true;
  }
  if (trial->direct_validates != best->direct_validates) {
    return trial->direct_validates;
  }
  if (trial->full_validates != best->full_validates) {
    return trial->full_validates;
  }
  if (trial->huffman_support != best->huffman_support) {
    return trial->huffman_support;
  }
  if (trial->progressive_entropy_complete
      != best->progressive_entropy_complete) {
    return trial->progressive_entropy_complete;
  }
  trial_score = jpg_reassembly_retry_choice_score(trial);
  best_score = jpg_reassembly_retry_choice_score(best);
  return trial_score < best_score
         || (trial_score == best_score
             && (trial->run_len > best->run_len
                 || (trial->run_len == best->run_len
                     && trial->moved_start < best->moved_start)));
}

static inline void jpg_reassembly_sort_retry_choices(
    JpgReassemblyRetryFrame *frame) {
  if (!frame) {
    return;
  }
  for (uint32_t i = 1; i < frame->choice_count; i++) {
    JpgOOOBridgeChoice choice = frame->choices[i];
    uint32_t position = i;

    while (position > 0
           && jpg_reassembly_retry_choice_better(
                  &choice, &frame->choices[position - 1])) {
      frame->choices[position] = frame->choices[position - 1];
      position--;
    }
    frame->choices[position] = choice;
  }
}

static inline void jpg_reassembly_save_retry_frame(
    CarveInfo *candidate,
    const JPGCarveState *prefix_state,
    bool have_prefix_state,
    const JPGReassemblyForwardChoice *forward,
    const JpgOOOBridgeChoice *best_bridge,
    const JpgOOOBridgeChoice *chosen,
    const JpgOOOBridgeShortlist *shortlist,
    JpgReassemblyRetrySearch *search) {
  JpgReassemblyRetryFrame frame;
  bool strong_entry_alternative = false;

  if (!candidate || !candidate->b || !prefix_state || !have_prefix_state
      || !best_bridge || !best_bridge->found || !shortlist || !search
      || search->attempts >= JPG_REASS_RETRY_LIMIT
      || search->frame_count >= JPG_REASS_RETRY_FRAMES) {
    return;
  }
  if ((chosen && chosen->apparent_continuation)
      || (!chosen && forward && forward->found && forward->is_immediate
          && forward->has_followon_support)) {
    return;
  }
  // a later syntactic validation alone cannot justify a weaker two-seam
  // bridge; retain a strongly supported entry when its exit is uncertain.
  if (!prefix_state->is_progressive && !chosen && forward && forward->found
      && forward->have_boundary
      && !jpg_reassembly_baseline_bridge_beats_forward(best_bridge,
                                                       forward)) {
    if (shortlist->entry_only_count > 0) {
      const JpgOOOBridgeChoice *entry = &shortlist->entry_only_choices[0];
      double entry_score = entry->boundary.normalized;

      if (entry->baseline_rate_supported) {
        entry_score += entry->baseline_rate_deviation;
      }
      strong_entry_alternative =
          !jpg_reassembly_has_physical_gap(candidate)
          && entry->huffman_support && entry->boundary.valid
          && entry_score
                 < forward->boundary.normalized
                       * JPG_REASS_SCATTER_ENTRY_RATIO;
    }
    if (!strong_entry_alternative) {
      return;
    }
  }
  memset(&frame, 0, sizeof(frame));
  if (!jpg_reassembly_same_bridge_choice(best_bridge, chosen)) {
    jpg_reassembly_add_retry_choice(&frame, best_bridge, chosen, forward);
  }
  for (uint32_t i = 0; i < shortlist->entry_only_count; i++) {
    JpgOOOBridgeChoice entry = shortlist->entry_only_choices[i];

    // Entry-ranked retries establish only the transition into a displaced
    // run. Normal forward selection then determines how far that run extends.
    entry.full_validates = entry.direct_validates;
    entry.suffix_start = -1;
    entry.suffix_len = 0;
    memset(&entry.suffix_boundary, 0, sizeof(entry.suffix_boundary));
    jpg_reassembly_add_retry_choice(
        &frame, &entry, chosen, forward);
  }
  for (uint32_t i = 0; i < shortlist->count; i++) {
    jpg_reassembly_add_retry_choice(&frame, &shortlist->choices[i], chosen,
                                    forward);
  }
  if (frame.choice_count == 0) {
    return;
  }
  jpg_reassembly_sort_retry_choices(&frame);
  if (chosen && chosen->found) {
    frame.have_selected_choice = true;
    frame.defer_initial_retry =
        !chosen->full_validates && chosen->suffix_len == 0
        && best_bridge->suffix_len > 0
        && chosen->moved_start == best_bridge->moved_start
        && chosen->run_len == best_bridge->run_len;
    frame.selected_choice = *chosen;
    frame.retry_priority =
        jpg_reassembly_retry_choice_score(&frame.choices[0])
        - jpg_reassembly_retry_choice_score(chosen);
  }
  else if (forward && forward->found && forward->have_boundary) {
    frame.retry_priority =
        jpg_reassembly_retry_choice_score(&frame.choices[0])
        - forward->boundary.normalized;
  }
  else {
    frame.retry_priority =
        jpg_reassembly_retry_choice_score(&frame.choices[0]);
  }

  frame.num_blocks = blockvector_get_num_blocks(candidate->b);
  frame.length = blockvector_get_data_length(candidate->b);
  frame.best_validates_to = candidate->best_validates_to;
  frame.newblock = candidate->newblock;
  frame.block_choice_start = candidate->block_choice_start;
  frame.chopped = candidate->chopped;
  frame.fastpath = candidate->fastpath;
  frame.have_prefix_state = true;
  frame.prefix_state = *prefix_state;
  frame.apparent_blocks =
      malloc(frame.num_blocks * sizeof(*frame.apparent_blocks));
  check_memory_allocation(frame.apparent_blocks, __LINE__, __FILE__,
                          "jpg retry apparent blocks");
  for (uint64_t i = 0; i < frame.num_blocks; i++) {
    frame.apparent_blocks[i] =
        blockvector_get_apparent_blocknumber(candidate->b, i);
  }

  search->frames[search->frame_count++] = frame;
  if (jpg_reassembly_debug_candidate(candidate)) {
    lock_fprintf(stderr,
                 "[jpgdbg] retry_save frames=%" PRIu32
                 " blocks=%" PRIu64 " choices=%" PRIu32
                 " chosen=%" PRId64 "+%" PRIu64
                 " priority=%.3f\n",
                 search->frame_count, frame.num_blocks, frame.choice_count,
                 chosen ? chosen->moved_start : -1,
                 chosen ? chosen->run_len : 0, frame.retry_priority);
  }
}

static inline bool jpg_reassembly_retry_alternative_preferred(
    const JpgReassemblyRetrySearch *search) {
  const JpgReassemblyRetryFrame *frame;
  const JpgOOOBridgeChoice *alternative;

  if (!search || search->frame_count == 0) {
    return false;
  }
  frame = &search->frames[search->frame_count - 1];
  if (frame->next_choice >= frame->choice_count) {
    return false;
  }
  alternative = &frame->choices[frame->next_choice];
  if (!search->replay_started && frame->have_selected_choice
      && frame->selected_choice.boundary.valid
      && alternative->boundary.valid
      && frame->selected_choice.boundary.normalized
             < alternative->boundary.normalized
                   * JPG_REASS_SCATTER_ENTRY_RATIO) {
    return false;
  }
  return frame->have_selected_choice
         && !frame->defer_initial_retry
         && !frame->selected_choice.apparent_continuation
         && (search->replay_started || frame->retry_priority < 0.0)
         && jpg_reassembly_retry_choice_better(
                alternative, &frame->selected_choice);
}

typedef struct {
  bool supported;
  bool clean;
  bool reaches_probe_end;
  uint64_t frontier;
  JpgHuffmanFailure failure;
  JpgMcuValidationResult mcu;
} JpgReassemblyEntropyProbe;

static inline bool jpg_reassembly_ooo_range_available(
    CarveInfo *candidate,
    int64_t start_apparent,
    uint64_t blocks,
    int64_t exclude_start,
    uint64_t exclude_blocks);
static inline void jpg_reassembly_ooo_restore_candidate(
    CarveInfo *candidate,
    uint64_t saved_num_blocks,
    uint64_t saved_length);
static inline void jpg_reassembly_ooo_append_range(
    CarveInfo *candidate,
    int64_t start_apparent,
    uint64_t blocks);

static inline bool jpg_reassembly_mcu_reaches_probe(
    const JpgMcuValidationResult *result,
    uint64_t probe_length) {
  uint64_t tolerance = scalpel_state.blocksize / 64;

  if (tolerance < 256) {
    tolerance = 256;
  }
  return result && result->valid && result->expected_mcus > 0
         && result->final_byte_pos > 0
         && result->final_byte_pos + tolerance >= probe_length;
}

// screen a baseline candidate by resuming only the entropy decoder. Full
// libjpeg validation remains the authority for every candidate that survives.
static inline bool jpg_reassembly_probe_baseline_entropy(
    CarveInfo *candidate,
    const JPGCarveState *prefix_state,
    uint64_t saved_num_blocks,
    uint64_t saved_length,
    int64_t run_start,
    uint64_t run_len,
    int64_t suffix_start,
    uint64_t suffix_len,
    JpgReassemblyEntropyProbe *probe) {
  JPGHuffmanCheckpoint huff_save;
  JPGHuffmanCheckpoint huff_restore;
  JpgValidationContext ctx;
  JpgHuffmanFailure failure = JPG_HUFFMAN_FAILURE_NONE;
  JpgMcuValidationResult saved_mcu_result;
  uint64_t materialized_length = 0;
  uint64_t huffman_error_pos;
  char *materialized;
  uint32_t saved_blocksize = jpg_current_blocksize;
  int32_t saved_dc_threshold = jpg_dc_threshold;
  int32_t saved_max_observed_dc_diff = jpg_max_observed_dc_diff;

  if (probe) {
    memset(probe, 0, sizeof(*probe));
  }
  if (!candidate || !candidate->b || !prefix_state || !probe
      || !prefix_state->valid || prefix_state->is_progressive
      || !prefix_state->have_sof || !prefix_state->had_scan
      || !prefix_state->huff_checkpoint.valid || run_len == 0
      || !jpg_reassembly_ooo_range_available(candidate, run_start, run_len,
                                             suffix_start, suffix_len)
      || (suffix_len > 0
          && !jpg_reassembly_ooo_range_available(candidate, suffix_start,
                                                 suffix_len, run_start,
                                                 run_len))) {
    return false;
  }

  jpg_reassembly_ooo_restore_candidate(candidate, saved_num_blocks,
                                       saved_length);
  jpg_reassembly_ooo_append_range(candidate, run_start, run_len);
  if (suffix_len > 0) {
    jpg_reassembly_ooo_append_range(candidate, suffix_start, suffix_len);
  }

  materialized = jpg_reassembly_materialize_candidate(candidate,
                                                       &materialized_length);
  memset(&ctx, 0, sizeof(ctx));
  ctx.data = (const uint8_t *)materialized;
  ctx.length = materialized_length;
  jpg_restore_header_from_state(&ctx, prefix_state);
  jpg_current_blocksize = scalpel_state.blocksize;
  if (prefix_state->max_observed_dc_diff > 0) {
    int32_t adaptive = prefix_state->max_observed_dc_diff * 3;

    if (adaptive < 200) {
      adaptive = 200;
    }
    jpg_dc_threshold = adaptive;
  }
  else {
    jpg_dc_threshold = 2000;
  }

  memset(&huff_save, 0, sizeof(huff_save));
  memcpy(&huff_restore, &prefix_state->huff_checkpoint,
         sizeof(huff_restore));
  huffman_error_pos = jpg_huffman_validate(
      &ctx, &huff_restore, &huff_save, &failure, NULL);
  memcpy(&saved_mcu_result, &jpg_mcu_result, sizeof(saved_mcu_result));

  probe->supported = true;
  probe->clean = huffman_error_pos == 0;
  probe->failure = failure;
  probe->frontier = prefix_state->prev_validates_to;
  if (huff_save.valid && huff_save.byte_pos > probe->frontier + 1) {
    probe->frontier = huff_save.byte_pos - 1;
  }
  if (saved_mcu_result.final_byte_pos > probe->frontier + 1) {
    probe->frontier = saved_mcu_result.final_byte_pos - 1;
  }
  if (huffman_error_pos > 0 && huffman_error_pos - 1 > probe->frontier) {
    probe->frontier = huffman_error_pos - 1;
  }
  probe->reaches_probe_end =
      probe->clean
      && jpg_reassembly_mcu_reaches_probe(&saved_mcu_result,
                                          materialized_length);
  memcpy(&probe->mcu, &saved_mcu_result, sizeof(probe->mcu));

  jpg_reassembly_ooo_restore_candidate(candidate, saved_num_blocks,
                                       saved_length);
  jpg_current_blocksize = saved_blocksize;
  jpg_dc_threshold = saved_dc_threshold;
  jpg_max_observed_dc_diff = saved_max_observed_dc_diff;
  return true;
}

static inline bool jpg_reassembly_baseline_local_rate_consistent(
    CarveInfo *candidate,
    const JPGCarveState *prefix_state,
    uint64_t saved_num_blocks,
    uint64_t saved_length,
    int64_t run_start,
    uint64_t run_len,
    bool *rate_available,
    double *rate_deviation) {
  JpgReassemblyEntropyProbe probe;
  double prefix_rate;
  double extension_rate;

  if (rate_available) {
    *rate_available = false;
  }
  if (rate_deviation) {
    *rate_deviation = DBL_MAX;
  }
  if (!candidate || !prefix_state || !rate_available || !rate_deviation
      || run_len == 0) {
    return false;
  }

  memset(&probe, 0, sizeof(probe));
  if (!jpg_reassembly_probe_baseline_entropy(
          candidate, prefix_state, saved_num_blocks, saved_length,
          run_start, run_len, -1, 0, &probe)
      || !probe.supported || !probe.clean || !probe.reaches_probe_end
      || !prefix_state->huff_checkpoint.valid
      || prefix_state->huff_checkpoint.mcu_count == 0
      || prefix_state->huff_checkpoint.byte_pos
             <= prefix_state->entropy_start
      || probe.mcu.mcu_count <= prefix_state->huff_checkpoint.mcu_count
      || probe.mcu.final_byte_pos
             <= prefix_state->huff_checkpoint.byte_pos) {
    return false;
  }

  prefix_rate =
      (double)(prefix_state->huff_checkpoint.byte_pos
               - prefix_state->entropy_start)
      / prefix_state->huff_checkpoint.mcu_count;
  extension_rate =
      (double)(probe.mcu.final_byte_pos
               - prefix_state->huff_checkpoint.byte_pos)
      / (probe.mcu.mcu_count - prefix_state->huff_checkpoint.mcu_count);
  if (prefix_rate <= 0.0) {
    return false;
  }

  *rate_deviation = fabs(extension_rate - prefix_rate) / prefix_rate;
  *rate_available = true;
  return *rate_deviation < JPG_REASS_BASELINE_LOCAL_RATE_LIMIT;
}

static pthread_mutex_t jpg_reassembly_raw_header_lock =
    PTHREAD_MUTEX_INITIALIZER;
static unsigned char *jpg_reassembly_raw_header_cache = NULL;
static uint64_t jpg_reassembly_raw_header_cache_blocks = 0;
static int jpg_reassembly_raw_header_fd = -1;
static bool jpg_reassembly_raw_header_unavailable = false;
static bool jpg_reassembly_raw_header_cleanup_registered = false;

static inline void jpg_reassembly_raw_header_cache_cleanup(void) {
  if (jpg_reassembly_raw_header_fd >= 0) {
    close(jpg_reassembly_raw_header_fd);
    jpg_reassembly_raw_header_fd = -1;
  }
  free(jpg_reassembly_raw_header_cache);
  jpg_reassembly_raw_header_cache = NULL;
  jpg_reassembly_raw_header_cache_blocks = 0;
}

static inline bool jpg_reassembly_raw_header_cache_init(void) {
  uint64_t blocks;

  if (jpg_reassembly_raw_header_cache
      || jpg_reassembly_raw_header_unavailable) {
    return jpg_reassembly_raw_header_cache != NULL;
  }

  if (scalpel_state.blocksize == 0 || !scalpel_state.image_pathname[0]) {
    jpg_reassembly_raw_header_unavailable = true;
    return false;
  }

  blocks = CEILDIV(filemirror_filesize(scalpel_state.filemirror),
                   scalpel_state.blocksize);
  if (blocks == 0) {
    jpg_reassembly_raw_header_unavailable = true;
    return false;
  }

  jpg_reassembly_raw_header_cache = calloc(blocks, sizeof(unsigned char));
  if (!jpg_reassembly_raw_header_cache) {
    jpg_reassembly_raw_header_unavailable = true;
    return false;
  }

  jpg_reassembly_raw_header_fd = open(scalpel_state.image_pathname, O_RDONLY);
  if (jpg_reassembly_raw_header_fd < 0) {
    free(jpg_reassembly_raw_header_cache);
    jpg_reassembly_raw_header_cache = NULL;
    jpg_reassembly_raw_header_unavailable = true;
    return false;
  }

  jpg_reassembly_raw_header_cache_blocks = blocks;
  if (!jpg_reassembly_raw_header_cleanup_registered) {
    atexit(jpg_reassembly_raw_header_cache_cleanup);
    jpg_reassembly_raw_header_cleanup_registered = true;
  }
  return true;
}

static inline bool jpg_reassembly_raw_block_starts_with_header(
    int64_t actual_block) {
  unsigned char cached;
  unsigned char buf[4];
  off_t offset;
  bool ret = false;

  if (actual_block < 0) {
    return false;
  }

  MUTEX_ERROR_CHECK(pthread_mutex_lock(&jpg_reassembly_raw_header_lock),
                    __LINE__, __FILE__);
  if (!jpg_reassembly_raw_header_cache_init()
      || (uint64_t)actual_block >= jpg_reassembly_raw_header_cache_blocks) {
    MUTEX_ERROR_CHECK(pthread_mutex_unlock(&jpg_reassembly_raw_header_lock),
                      __LINE__, __FILE__);
    return false;
  }

  cached = jpg_reassembly_raw_header_cache[actual_block];
  if (cached != 0) {
    ret = cached == 2;
    MUTEX_ERROR_CHECK(pthread_mutex_unlock(&jpg_reassembly_raw_header_lock),
                      __LINE__, __FILE__);
    return ret;
  }

  offset = (off_t)((uint64_t)actual_block * scalpel_state.blocksize);
  if (pread(jpg_reassembly_raw_header_fd, buf, sizeof(buf), offset)
      == (ssize_t)sizeof(buf)) {
    ret = buf[0] == 0xff && buf[1] == 0xd8 && buf[2] == 0xff
          && buf[3] != 0x00 && buf[3] != 0xff;
  }
  jpg_reassembly_raw_header_cache[actual_block] = ret ? 2 : 1;

  MUTEX_ERROR_CHECK(pthread_mutex_unlock(&jpg_reassembly_raw_header_lock),
                    __LINE__, __FILE__);
  return ret;
}

static inline bool jpg_reassembly_ooo_followed_by_raw_header(
    int64_t run_start,
    uint64_t run_len) {
  int64_t last_actual;

  if (run_len == 0) {
    return false;
  }

  last_actual =
      filemirror_actual_blocknumber(scalpel_state.filemirror,
                                    run_start + (int64_t)run_len - 1);
  if (last_actual < 0 || last_actual == INT64_MAX) {
    return false;
  }

  return jpg_reassembly_raw_block_starts_with_header(last_actual + 1);
}

static inline uint64_t jpg_reassembly_raw_anchor_distance(
    int64_t run_start,
    uint64_t run_len,
    uint64_t max_distance) {
  int64_t last_actual;
  uint64_t image_blocks;

  if (run_len == 0 || max_distance == 0) {
    return 0;
  }
  last_actual = filemirror_actual_blocknumber(
      scalpel_state.filemirror, run_start + (int64_t)run_len - 1);
  if (last_actual < 0) {
    return 0;
  }
  image_blocks = CEILDIV(filemirror_filesize(scalpel_state.filemirror),
                         scalpel_state.blocksize);
  for (uint64_t distance = 1; distance <= max_distance; distance++) {
    uint64_t next_actual = (uint64_t)last_actual + distance;

    if (next_actual == image_blocks
        || (next_actual < image_blocks
            && jpg_reassembly_raw_block_starts_with_header(
                   (int64_t)next_actual))) {
      return distance;
    }
  }
  return 0;
}

static inline bool jpg_reassembly_ooo_apparent_available(
    CarveInfo *candidate,
    int64_t apparent) {
  int64_t actual;

  if (!candidate || !candidate->b || apparent < 0
      || apparent >= (int64_t)filemirror_apparent_blocks(scalpel_state.filemirror)
      || jpg_reassembly_apparent_in_blockvector_strict(candidate->b, apparent)) {
    return false;
  }

  actual = filemirror_actual_blocknumber(scalpel_state.filemirror, apparent);
  if (actual < 0
      || filemirror_actual_block_covered(scalpel_state.filemirror, actual)) {
    return false;
  }
  if (filemirror_get_blocktype(scalpel_state.filemirror, actual,
                               candidate->needleidx)
      == BLOCK_CONFIDENCE_INVALID) {
    return false;
  }

  return true;
}

static inline bool jpg_reassembly_ooo_range_available(
    CarveInfo *candidate,
    int64_t start_apparent,
    uint64_t blocks,
    int64_t exclude_start,
    uint64_t exclude_blocks) {
  int64_t exclude_end =
      exclude_blocks > 0 ? exclude_start + (int64_t)exclude_blocks - 1 : -1;

  if (blocks == 0 || start_apparent < 0
      || start_apparent + (int64_t)blocks
             > (int64_t)filemirror_apparent_blocks(scalpel_state.filemirror)) {
    return false;
  }

  for (uint64_t i = 0; i < blocks; i++) {
    int64_t apparent = start_apparent + (int64_t)i;

    if (exclude_blocks > 0 && apparent >= exclude_start && apparent <= exclude_end) {
      return false;
    }
    if (!jpg_reassembly_ooo_apparent_available(candidate, apparent)) {
      return false;
    }
  }

  return true;
}

static inline bool jpg_reassembly_ooo_range_has_zero(
    int64_t start_apparent,
    uint64_t blocks) {
  if (blocks == 0 || start_apparent < 0
      || start_apparent + (int64_t)blocks
             > (int64_t)filemirror_apparent_blocks(scalpel_state.filemirror)) {
    return true;
  }

  for (uint64_t i = 0; i < blocks; i++) {
    int64_t actual =
        filemirror_actual_blocknumber(scalpel_state.filemirror,
                                      start_apparent + (int64_t)i);

    if (actual < 0
        || filemirror_actual_block_is_zero(scalpel_state.filemirror, actual)) {
      return true;
    }
  }

  return false;
}


static inline bool jpg_reassembly_ooo_range_has_eoi(
    int64_t start_apparent,
    uint64_t blocks) {
  unsigned char previous = 0;
  bool have_previous = false;

  if (blocks == 0 || start_apparent < 0) {
    return false;
  }

  for (uint64_t i = 0; i < blocks; i++) {
    int64_t actual = filemirror_actual_blocknumber(
        scalpel_state.filemirror, start_apparent + (int64_t)i);
    uint64_t length = 0;
    const unsigned char *data =
        (const unsigned char *)filemirror_actual_block_data_pointer(
            scalpel_state.filemirror, actual, &length);

    if (!data) {
      return false;
    }
    for (uint64_t pos = 0; pos < length; pos++) {
      if (have_previous && previous == 0xff && data[pos] == 0xd9) {
        return true;
      }
      previous = data[pos];
      have_previous = true;
    }
  }
  return false;
}

static inline bool jpg_reassembly_header_anchor_apparent(
    CarveInfo *candidate,
    uint64_t header_index,
    int64_t *header_apparent) {
  SearchSpec *spec;
  int64_t header_actual_block;

  if (!candidate || !header_apparent) {
    return false;
  }

  spec = &scalpel_state.search_specs[candidate->needleidx];
  if (header_index >= spec->offsets.numheaders || scalpel_state.blocksize == 0) {
    return false;
  }

  header_actual_block =
      (int64_t)(spec->offsets.headers[header_index] / scalpel_state.blocksize);
  if (header_actual_block < 0) {
    return false;
  }

  *header_apparent =
      filemirror_apparent_blocknumber(scalpel_state.filemirror,
                                      header_actual_block);
  return *header_apparent >= 0;
}

static inline bool jpg_reassembly_next_header_apparent(
    CarveInfo *candidate,
    int64_t min_apparent,
    int64_t *next_header_apparent) {
  SearchSpec *spec;
  bool found = false;
  int64_t best = 0;

  if (!candidate || !next_header_apparent || scalpel_state.blocksize == 0) {
    return false;
  }

  spec = &scalpel_state.search_specs[candidate->needleidx];
  for (uint64_t header_index = 0;
       header_index < spec->offsets.numheaders;
       header_index++) {
    int64_t header_actual_block =
        (int64_t)(spec->offsets.headers[header_index]
                  / scalpel_state.blocksize);
    int64_t header_apparent_block;

    if (header_actual_block < 0) {
      continue;
    }
    header_apparent_block =
        filemirror_apparent_blocknumber(scalpel_state.filemirror,
                                        header_actual_block);
    if (header_apparent_block >= min_apparent
        && (!found || header_apparent_block < best)) {
      best = header_apparent_block;
      found = true;
    }
  }

  if (found) {
    *next_header_apparent = best;
  }
  return found;
}

static inline bool jpg_reassembly_next_footer_apparent(
    CarveInfo *candidate,
    int64_t min_apparent,
    int64_t max_apparent,
    int64_t *next_footer_apparent) {
  SearchSpec *spec;
  bool found = false;
  int64_t best = 0;

  if (!candidate || !next_footer_apparent || scalpel_state.blocksize == 0
      || min_apparent < 0 || max_apparent <= min_apparent) {
    return false;
  }

  spec = &scalpel_state.search_specs[candidate->needleidx];
  for (uint64_t footer_index = 0;
       footer_index < spec->offsets.numfooters;
       footer_index++) {
    int64_t footer_actual_block =
        (int64_t)(spec->offsets.footers[footer_index]
                  / scalpel_state.blocksize);
    int64_t footer_apparent_block;

    if (footer_actual_block < 0) {
      continue;
    }
    footer_apparent_block =
        filemirror_apparent_blocknumber(scalpel_state.filemirror,
                                        footer_actual_block);
    if (footer_apparent_block >= min_apparent
        && footer_apparent_block < max_apparent
        && (!found || footer_apparent_block < best)) {
      best = footer_apparent_block;
      found = true;
    }
  }

  if (found) {
    *next_footer_apparent = best;
  }
  return found;
}

static inline bool jpg_reassembly_entropy_block_plausible(
    int64_t actual,
    bool is_progressive) {
  uint64_t length = 0;
  const unsigned char *data;

  if (actual < 0) {
    return false;
  }
  data = (const unsigned char *)filemirror_actual_block_data_pointer(
      scalpel_state.filemirror, actual, &length);
  if (!data || length == 0) {
    return false;
  }

  for (uint64_t i = 0; i + 1 < length; i++) {
    unsigned char marker;

    if (data[i] != 0xff) {
      continue;
    }
    marker = data[++i];
    while (marker == 0xff && i + 1 < length) {
      marker = data[++i];
    }
    if (marker != 0x00 && marker != 0xd9
        && (marker < 0xd0 || marker > 0xd7)
        && !(is_progressive
             && (marker == 0xc4 || marker == 0xcc || marker == 0xda
                 || marker == 0xdb || marker == 0xdc || marker == 0xdd
                 || marker == 0xfe || (marker >= 0xe0 && marker <= 0xef)))) {
      return false;
    }
  }
  return true;
}

static inline bool jpg_reassembly_apparent_range_has_restart_marker(
    int64_t start_apparent,
    uint64_t blocks,
    uint8_t expected_rst) {
  for (uint64_t block = 0; block < blocks; block++) {
    int64_t actual = filemirror_actual_blocknumber(
        scalpel_state.filemirror, start_apparent + (int64_t)block);
    uint64_t length = 0;
    const unsigned char *data;

    if (actual < 0) {
      return false;
    }
    data = (const unsigned char *)filemirror_actual_block_data_pointer(
        scalpel_state.filemirror, actual, &length);
    if (!data) {
      return false;
    }
    for (uint64_t i = 0; i + 1 < length; i++) {
      if (data[i] == 0xff
          && data[i + 1] == (unsigned char)(M_RST0 + expected_rst)) {
        return true;
      }
    }
  }
  return false;
}

static inline bool jpg_reassembly_expected_restart_marker(
    const CarveInfo *candidate,
    const JPGCarveState *prefix_state,
    uint8_t *expected_rst) {
  const unsigned char *data;
  uint64_t length;
  uint8_t expected = 0;

  if (!candidate || !candidate->b || !prefix_state || !expected_rst
      || prefix_state->restart_interval == 0) {
    return false;
  }
  if (prefix_state->huff_checkpoint.valid) {
    *expected_rst = prefix_state->huff_checkpoint.expected_rst;
    return true;
  }

  data = (const unsigned char *)blockvector_get_data_pointer(candidate->b);
  length = blockvector_get_data_length(candidate->b);
  if (!data || prefix_state->entropy_start >= length) {
    return false;
  }
  for (uint64_t pos = prefix_state->entropy_start; pos + 1 < length; pos++) {
    if (data[pos] != 0xff) {
      continue;
    }
    while (pos + 1 < length && data[pos + 1] == 0xff) {
      pos++;
    }
    if (pos + 1 >= length) {
      break;
    }
    if (data[pos + 1] == 0x00) {
      pos++;
      continue;
    }
    if (data[pos + 1] >= M_RST0 && data[pos + 1] <= M_RST7) {
      expected = (uint8_t)(data[pos + 1] - M_RST0 + 1) & 0x07;
      pos++;
    }
  }
  *expected_rst = expected;
  return true;
}

static inline bool jpg_reassembly_bridge_candidate_plausible(
    int64_t moved_start,
    bool is_progressive) {
  int64_t moved_actual = filemirror_actual_blocknumber(
      scalpel_state.filemirror, moved_start);

  return moved_actual >= 0
         && !jpg_reassembly_raw_block_starts_with_header(moved_actual)
         && jpg_reassembly_entropy_block_plausible(moved_actual,
                                                   is_progressive);
}

static inline void jpg_reassembly_ooo_restore_candidate(CarveInfo *candidate,
                                                        uint64_t saved_num_blocks,
                                                        uint64_t saved_length) {
  resize_blockvector(candidate->b, saved_num_blocks);
  blockvector_set_data_length(candidate->b, saved_length);
}

static inline void jpg_reassembly_ooo_append_range(CarveInfo *candidate,
                                                   int64_t start_apparent,
                                                   uint64_t blocks) {
  for (uint64_t i = 0; i < blocks; i++) {
    resize_blockvector(candidate->b, blockvector_get_num_blocks(candidate->b) + 1);
    blockvector_set_apparent_blocknumber(candidate->b,
                                         blockvector_get_num_blocks(candidate->b) - 1,
                                         start_apparent + (int64_t)i);
    inflate_blockvector_single_block(candidate->b,
                                     blockvector_get_num_blocks(candidate->b) - 1);
  }
}

static inline bool jpg_reassembly_icc_curve_score_data(
    const uint8_t *data,
    uint64_t length,
    uint64_t bridge_start,
    uint64_t bridge_end,
    double *score) {
  uint64_t scan_limit;

  if (!data || !score || bridge_start >= bridge_end
      || bridge_end + 2 > length) {
    return false;
  }
  scan_limit = bridge_start < length ? bridge_start : length;
  for (uint64_t marker = 0; marker + 18 <= scan_limit; marker++) {
    uint16_t segment_length;
    uint64_t segment_end;
    uint64_t profile_start;
    uint64_t profile_size;
    uint64_t tag_table;
    uint32_t tag_count;

    if (data[marker] != 0xff || data[marker + 1] != 0xe2) {
      continue;
    }
    segment_length = jpg_read_u16(data + marker + 2);
    segment_end = marker + 2 + segment_length;
    profile_start = marker + 18;
    if (segment_length < 16 || profile_start + 132 > length
        || segment_end < profile_start + 132
        || memcmp(data + marker + 4, "ICC_PROFILE\0", 12) != 0
        || data[marker + 16] != 1 || data[marker + 17] != 1) {
      continue;
    }
    profile_size = jpg_read_endian_u32(data + profile_start, false);
    if (profile_size < 132 || profile_size > segment_end - profile_start
        || memcmp(data + profile_start + 36, "acsp", 4) != 0) {
      continue;
    }
    tag_count = jpg_read_endian_u32(data + profile_start + 128, false);
    tag_table = profile_start + 132;
    if (tag_count > (length - tag_table) / 12) {
      continue;
    }

    for (uint32_t tag = 0; tag < tag_count; tag++) {
      const uint8_t *entry = data + tag_table + (uint64_t)tag * 12;
      uint64_t tag_offset = jpg_read_endian_u32(entry + 4, false);
      uint64_t tag_size = jpg_read_endian_u32(entry + 8, false);
      uint64_t tag_start;
      uint64_t curve_start;
      uint64_t curve_end;
      uint64_t check_start;
      uint64_t check_end;
      uint32_t curve_count;
      uint64_t before_start;
      uint64_t after_end;
      bool have_entry_seam;
      bool have_exit_seam;
      double entry_total = 0.0;
      double exit_total = 0.0;
      uint32_t entry_count = 0;
      uint32_t exit_count = 0;
      double total_score = 0.0;

      if (tag_offset > profile_size || tag_size > profile_size - tag_offset) {
        continue;
      }
      tag_start = profile_start + tag_offset;
      if (tag_size < 14 || tag_start + 12 > length
          || memcmp(data + tag_start, "curv", 4) != 0) {
        continue;
      }
      curve_count = jpg_read_endian_u32(data + tag_start + 8, false);
      curve_start = tag_start + 12;
      if (curve_count < 2
          || (uint64_t)curve_count > (tag_size - 12) / 2) {
        continue;
      }
      curve_end = curve_start + (uint64_t)curve_count * 2;
      if (bridge_end <= curve_start || bridge_start >= curve_end) {
        continue;
      }
      have_entry_seam =
          bridge_start >= curve_start + 2 && bridge_start < curve_end
          && (bridge_start - curve_start) % 2 == 0;
      have_exit_seam =
          bridge_end >= curve_start + 2 && bridge_end < curve_end
          && (bridge_end - curve_start) % 2 == 0;
      if (!have_entry_seam && !have_exit_seam) {
        continue;
      }

      check_start = bridge_start > curve_start + 2
                        ? bridge_start : curve_start + 2;
      if ((check_start - curve_start) % 2 != 0) {
        check_start++;
      }
      check_end = bridge_end < curve_end - 2
                      ? bridge_end : curve_end - 2;
      if ((check_end - curve_start) % 2 != 0) {
        check_end--;
      }
      for (uint64_t pos = check_start; pos <= check_end; pos += 2) {
        if (jpg_read_u16(data + pos)
            < jpg_read_u16(data + pos - 2)) {
          goto next_icc_tag;
        }
      }

      if (have_entry_seam) {
        before_start = bridge_start > curve_start + 64
                           ? bridge_start - 64 : curve_start;
        for (uint64_t pos = before_start + 2;
             pos < bridge_start; pos += 2) {
          entry_total += (double)(jpg_read_u16(data + pos)
                                  - jpg_read_u16(data + pos - 2));
          entry_count++;
        }
        for (uint64_t pos = bridge_start + 2;
             pos < bridge_end && pos < curve_end
               && pos <= bridge_start + 64;
             pos += 2) {
          entry_total += (double)(jpg_read_u16(data + pos)
                                  - jpg_read_u16(data + pos - 2));
          entry_count++;
        }
        if (entry_count == 0) {
          continue;
        }
        {
          int64_t entry_gap =
              (int64_t)jpg_read_u16(data + bridge_start)
              - jpg_read_u16(data + bridge_start - 2);
          double entry_reference = entry_total / entry_count;

          total_score += fabs((double)entry_gap - entry_reference)
                         / (entry_reference + 1.0);
        }
      }

      if (have_exit_seam) {
        before_start = bridge_end > curve_start + 64
                           ? bridge_end - 64 : curve_start;
        for (uint64_t pos = before_start + 2;
             pos < bridge_end; pos += 2) {
          exit_total += (double)(jpg_read_u16(data + pos)
                                 - jpg_read_u16(data + pos - 2));
          exit_count++;
        }
        after_end = bridge_end + 64 < curve_end
                        ? bridge_end + 64 : curve_end;
        if (after_end > length) {
          after_end = length - ((length - curve_start) % 2);
        }
        for (uint64_t pos = bridge_end + 2;
             pos < after_end; pos += 2) {
          exit_total += (double)(jpg_read_u16(data + pos)
                                 - jpg_read_u16(data + pos - 2));
          exit_count++;
        }
        if (exit_count == 0) {
          continue;
        }
        {
          int64_t exit_gap =
              (int64_t)jpg_read_u16(data + bridge_end)
              - jpg_read_u16(data + bridge_end - 2);
          double exit_reference = exit_total / exit_count;

          total_score += fabs((double)exit_gap - exit_reference)
                         / (exit_reference + 1.0);
        }
      }

      *score = total_score;
      return true;

next_icc_tag:
      continue;
    }
  }
  return false;
}

static inline bool jpg_reassembly_icc_curve_bridge_score(
    CarveInfo *candidate,
    uint64_t saved_num_blocks,
    uint64_t saved_length,
    int64_t moved_start,
    uint64_t run_len,
    int64_t suffix_start,
    uint64_t suffix_len,
    double *score) {
  uint64_t materialized_length = 0;
  char *materialized;
  bool supported;

  if (!candidate || !candidate->b || !score || run_len == 0
      || suffix_len == 0
      || !jpg_reassembly_ooo_range_available(candidate, moved_start, run_len,
                                              suffix_start, suffix_len)
      || !jpg_reassembly_ooo_range_available(candidate, suffix_start,
                                              suffix_len,
                                              moved_start, run_len)
      || jpg_reassembly_ooo_range_has_zero(moved_start, run_len)) {
    return false;
  }
  jpg_reassembly_ooo_restore_candidate(candidate, saved_num_blocks,
                                       saved_length);
  jpg_reassembly_ooo_append_range(candidate, moved_start, run_len);
  jpg_reassembly_ooo_append_range(candidate, suffix_start, suffix_len);
  materialized = jpg_reassembly_materialize_candidate(candidate,
                                                       &materialized_length);
  supported = jpg_reassembly_icc_curve_score_data(
      (const uint8_t *)materialized, materialized_length,
      saved_length,
      saved_length + run_len * (uint64_t)scalpel_state.blocksize,
      score);
  jpg_reassembly_ooo_restore_candidate(candidate, saved_num_blocks,
                                       saved_length);
  return supported;
}

static inline bool jpg_reassembly_try_contiguous_tail_validation(
    CarveInfo *candidate,
    bool *validates,
    uint64_t *validates_to,
    uint32_t fixed_prefix_blocks,
    uint64_t saved_num_blocks,
    uint64_t saved_length,
    int64_t tail_start) {
  SearchSpec *spec;
  JPGCarveState trial_state;
  int64_t tail_limit;
  int64_t next_header = -1;
  int64_t next_footer = -1;
  uint64_t max_tail_blocks;
  uint64_t tail_blocks;
  uint64_t trial_validates_to = 0;
  bool trial_validates;

  if (!candidate || !candidate->b || !validates || !validates_to
      || scalpel_state.blocksize == 0 || tail_start < 0) {
    return false;
  }

  spec = &scalpel_state.search_specs[candidate->needleidx];
  if (saved_length >= spec->MAXIMUMSIZE) {
    return false;
  }
  max_tail_blocks =
      CEILDIV(spec->MAXIMUMSIZE - saved_length, scalpel_state.blocksize);
  tail_limit = (int64_t)filemirror_apparent_blocks(scalpel_state.filemirror);
  if (max_tail_blocks < (uint64_t)(tail_limit - tail_start)) {
    tail_limit = tail_start + (int64_t)max_tail_blocks;
  }
  if (jpg_reassembly_next_header_apparent(candidate, tail_start + 1,
                                          &next_header)
      && next_header < tail_limit) {
    tail_limit = next_header;
  }
  if (!jpg_reassembly_next_footer_apparent(candidate, tail_start, tail_limit,
                                           &next_footer)) {
    return false;
  }

  tail_blocks = (uint64_t)(next_footer - tail_start + 1);
  jpg_reassembly_ooo_restore_candidate(candidate, saved_num_blocks,
                                       saved_length);
  if (!jpg_reassembly_ooo_range_available(candidate, tail_start, tail_blocks,
                                          -1, 0)) {
    return false;
  }
  jpg_reassembly_ooo_append_range(candidate, tail_start, tail_blocks);

  memset(&trial_state, 0, sizeof(trial_state));
  trial_validates =
      jpg_reassembly_validate_direct(candidate, &trial_state,
                                     &trial_validates_to,
                                     fixed_prefix_blocks);
  if (!trial_validates) {
    if (jpg_reassembly_debug_candidate(candidate)) {
      lock_fprintf(stderr,
                   "[jpgdbg] contiguous_tail_failed start=%" PRId64
                   " blocks=%" PRIu64 " vt=%" PRIu64
                   " wrong=%d method=%s\n",
                   tail_start, tail_blocks, trial_validates_to,
                   jpg_wrongblock_result.detected ? 1 : 0,
                   jpg_wrongblock_result.detected
                       && jpg_wrongblock_result.method
                       ? jpg_wrongblock_result.method : "none");
    }
    jpg_reassembly_ooo_restore_candidate(candidate, saved_num_blocks,
                                         saved_length);
    return false;
  }

  *validates = true;
  *validates_to = trial_validates_to;
  blockvector_set_data_length(candidate->b, trial_validates_to + 1);
  resize_blockvector(candidate->b,
                     CEILDIV(blockvector_get_data_length(candidate->b),
                             scalpel_state.blocksize));
  candidate->best_validates_to = trial_validates_to;
  if (blockvector_get_num_blocks(candidate->b) > 0) {
    int64_t last_apparent = blockvector_get_apparent_blocknumber(
        candidate->b, blockvector_get_num_blocks(candidate->b) - 1);
    candidate->newblock =
        filemirror_actual_blocknumber(scalpel_state.filemirror, last_apparent);
  }
  if (trial_state.valid) {
    jpg_put_decoder_state(candidate->carvehashkey, &trial_state);
  }
  jpg_reassembly_debug_dump("contiguous_tail_validated", candidate,
                            tail_start, trial_validates_to);
  return true;
}

// A permissive entropy decoder can consume blocks from another JPEG before a
// later hard failure exposes the substitution. Rebuild a hypothesis on a
// clone, progressively removing that speculative suffix, and retain it only
// when the complete JPEG validator proves the replacement tail.
static inline bool jpg_reassembly_try_suffix_rollback_tail_validation(
    CarveInfo *candidate,
    bool *validates,
    uint64_t *validates_to,
    uint32_t minimum_prefix_blocks,
    uint64_t saved_num_blocks,
    uint64_t saved_length,
    int64_t tail_start) {
  BlockVector *original;
  BlockVector *hypothesis = NULL;
  uint64_t maximum_rollback;

  if (!candidate || !candidate->b || !validates || !validates_to
      || scalpel_state.blocksize == 0 || tail_start < 0
      || saved_num_blocks < 2) {
    return false;
  }
  if (minimum_prefix_blocks == 0) {
    minimum_prefix_blocks = 1;
  }
  if (minimum_prefix_blocks >= saved_num_blocks) {
    return false;
  }

  original = candidate->b;
  maximum_rollback = saved_num_blocks - minimum_prefix_blocks;
  clone_blockvector(original, &hypothesis, false);
  candidate->b = hypothesis;

  for (uint64_t rollback = 1; rollback <= maximum_rollback; rollback++) {
    uint64_t trial_blocks = saved_num_blocks - rollback;
    uint64_t trial_length = trial_blocks * (uint64_t)scalpel_state.blocksize;

    if (jpg_reassembly_checkpoint_requested()) {
      break;
    }
    if (trial_length > saved_length) {
      trial_length = saved_length;
    }
    if (jpg_reassembly_try_contiguous_tail_validation(
            candidate, validates, validates_to, minimum_prefix_blocks,
            trial_blocks, trial_length, tail_start)) {
      free_blockvector(&original);
      return true;
    }
  }

  candidate->b = original;
  free_blockvector(&hypothesis);
  return false;
}

static inline bool jpg_run_order_boundary_better(
    const JPGRunOrderBoundary *left,
    const JPGRunOrderBoundary *right) {
  if (left->normalized != right->normalized) {
    return left->normalized > right->normalized;
  }
  return left->first_block < right->first_block;
}

static inline bool jpg_run_order_boundary_after_page(
    const JPGRunOrderProgress *progress,
    const JPGRunOrderBoundary *boundary) {
  if (!progress->page_after_valid) {
    return true;
  }
  if (boundary->normalized < progress->page_after_normalized) {
    return true;
  }
  return boundary->normalized == progress->page_after_normalized
         && boundary->first_block > progress->page_after_first_block;
}

static inline void jpg_run_order_insert_boundary(
    JPGRunOrderProgress *progress,
    const JPGRunOrderBoundary *boundary) {
  uint32_t index;

  if (!isfinite(boundary->normalized) || boundary->normalized <= 0.0
      || !jpg_run_order_boundary_after_page(progress, boundary)) {
    return;
  }

  if (progress->group_count < JPG_RUN_ORDER_GROUP_BATCH) {
    index = progress->group_count++;
    progress->groups[index] = *boundary;
  }
  else {
    index = JPG_RUN_ORDER_GROUP_BATCH - 1;
    if (!jpg_run_order_boundary_better(boundary,
                                       &progress->groups[index])) {
      return;
    }
    progress->groups[index] = *boundary;
  }

  while (index > 0
         && jpg_run_order_boundary_better(&progress->groups[index],
                                          &progress->groups[index - 1])) {
    JPGRunOrderBoundary swap = progress->groups[index - 1];

    progress->groups[index - 1] = progress->groups[index];
    progress->groups[index] = swap;
    index--;
  }
}

static inline void jpg_run_order_finish_scan_group(
    JPGRunOrderProgress *progress) {
  if (!progress->scan_group_active) {
    return;
  }
  jpg_run_order_insert_boundary(progress, &progress->scan_group);
  memset(&progress->scan_group, 0, sizeof(progress->scan_group));
  progress->scan_group_active = false;
}

static inline bool jpg_run_order_same_scan_group(
    const JPGRunOrderBoundary *group,
    const JpgBoundaryScore *score) {
  return group->boundary_row == score->boundary_row
         && group->seam_mad == score->seam_mad
         && group->baseline_mad == score->baseline_mad
         && group->normalized == score->normalized;
}

static inline bool jpg_reassembly_physically_contiguous(
    const CarveInfo *candidate,
    uint64_t blocks) {
  if (!candidate || !candidate->b || blocks == 0
      || blocks > blockvector_get_num_blocks(candidate->b)) {
    return false;
  }

  for (uint64_t slot = 1; slot < blocks; slot++) {
    int64_t previous_actual =
        blockvector_get_actual_blocknumber(candidate->b, slot - 1);
    int64_t current_actual =
        blockvector_get_actual_blocknumber(candidate->b, slot);
    int64_t previous_apparent =
        blockvector_get_apparent_blocknumber(candidate->b, slot - 1);
    int64_t current_apparent =
        blockvector_get_apparent_blocknumber(candidate->b, slot);

    if (previous_actual < 0 || current_actual != previous_actual + 1
        || previous_apparent < 0
        || current_apparent != previous_apparent + 1) {
      return false;
    }
  }
  return true;
}

static inline uint64_t jpg_reassembly_last_eoi_length(
    const char *data,
    uint64_t length) {
  if (!data || length < 2) {
    return 0;
  }
  for (uint64_t pos = length - 1; pos > 0; pos--) {
    if ((uint8_t)data[pos - 1] == 0xff
        && (uint8_t)data[pos] == M_EOI) {
      return pos + 1;
    }
  }
  return 0;
}

static inline void jpg_run_order_boundary_range(
    const JPGRunOrderBoundary *boundary,
    uint64_t source_blocks,
    uint64_t *minimum,
    uint64_t *maximum) {
  *minimum = boundary->first_block > 2
             ? boundary->first_block - 2 : 1;
  *maximum = boundary->last_block + 2;
  if (*maximum >= source_blocks) {
    *maximum = source_blocks - 1;
  }
}

static inline void jpg_reassembly_commit_run_order_hypothesis(
    CarveInfo *candidate,
    BlockVector *original,
    const JPGCarveState *trial_state,
    uint64_t validates_to) {
  free_blockvector(&original);
  candidate->best_validates_to = validates_to;
  candidate->newblock = blockvector_get_actual_blocknumber(
      candidate->b, blockvector_get_num_blocks(candidate->b) - 1);
  if (trial_state->valid) {
    jpg_put_decoder_state(candidate->carvehashkey, (void *)trial_state);
  }
}

static inline bool jpg_reassembly_run_order_join_score(
    CarveInfo *candidate,
    double *maximum_score,
    double *total_score) {
  uint64_t length = 0;
  uint64_t num_blocks;
  char *data;
  uint32_t joins = 0;

  if (!maximum_score || !total_score) {
    return false;
  }
  *maximum_score = DBL_MAX;
  *total_score = DBL_MAX;
  if (!candidate || !candidate->b || scalpel_state.blocksize == 0) {
    return false;
  }
  num_blocks = blockvector_get_num_blocks(candidate->b);
  data = jpg_reassembly_materialize_candidate(candidate, &length);
  if (!data || length == 0) {
    return false;
  }

  *maximum_score = 0.0;
  *total_score = 0.0;

  for (uint64_t slot = 1; slot < num_blocks; slot++) {
    const int64_t previous =
        blockvector_get_actual_blocknumber(candidate->b, slot - 1);
    const int64_t current =
        blockvector_get_actual_blocknumber(candidate->b, slot);
    uint64_t prefix_length;
    JpgBoundaryScore boundary;

    if (previous >= 0 && current == previous + 1) {
      continue;
    }
    if (slot > UINT64_MAX / scalpel_state.blocksize) {
      return false;
    }
    prefix_length = slot * (uint64_t)scalpel_state.blocksize;
    if (prefix_length >= length) {
      return false;
    }
    // Materialization reuses one thread-local buffer across hypotheses, so a
    // pointer alone cannot identify cached decoded pixels from its old bytes.
    jpg_boundary_preview_cache_invalidate();
    boundary = jpg_boundary_score_scaled(data, prefix_length, length, 1,
                                         true);
    if (jpg_reassembly_checkpoint_requested()) {
      return false;
    }
    if (!boundary.valid || !isfinite(boundary.normalized)) {
      return false;
    }
    if (jpg_reassembly_debug_candidate(candidate)) {
      lock_fprintf(stderr,
                   "[jpgdbg] run_order_join slot=%" PRIu64
                   " previous=%" PRId64 " current=%" PRId64
                   " normalized=%.6f\n",
                   slot, previous, current, boundary.normalized);
    }
    if (boundary.normalized > *maximum_score) {
      *maximum_score = boundary.normalized;
    }
    *total_score += boundary.normalized;
    joins++;
  }
  return joins > 0;
}

static inline bool jpg_reassembly_try_external_run_insertion(
    CarveInfo *candidate,
    uint64_t source_blocks,
    uint64_t source_length,
    uint64_t cut,
    int64_t external_start,
    uint64_t external_blocks,
    uint32_t fixed_prefix_blocks,
    bool *validates,
    uint64_t *validates_to,
    bool commit,
    double *maximum_join_score,
    double *total_join_score) {
  BlockVector *original;
  BlockVector *hypothesis = NULL;
  JPGCarveState trial_state;
  uint64_t destination = 0;
  uint64_t trial_length;
  uint64_t trial_validates_to = 0;
  bool trial_validates;

  if (!candidate || !candidate->b || !validates || !validates_to
      || !maximum_join_score || !total_join_score
      || source_blocks < 2 || cut == 0 || cut >= source_blocks
      || external_start < 0 || external_blocks == 0
      || external_blocks > UINT64_MAX - source_blocks
      || external_blocks > (UINT64_MAX - source_length)
                               / scalpel_state.blocksize) {
    return false;
  }
  if (!jpg_reassembly_ooo_range_available(candidate, external_start,
                                          external_blocks, -1, 0)
      || jpg_reassembly_ooo_range_has_zero(external_start,
                                          external_blocks)) {
    return false;
  }

  trial_length = source_length
                 + external_blocks * (uint64_t)scalpel_state.blocksize;
  original = candidate->b;
  init_blockvector(scalpel_state.filemirror, &hypothesis,
                   source_blocks + external_blocks, false);

  for (uint64_t source = 0; source < cut; source++) {
    blockvector_set_apparent_blocknumber(
        hypothesis, destination++,
        blockvector_get_apparent_blocknumber(original, source));
  }
  for (uint64_t offset = 0; offset < external_blocks; offset++) {
    blockvector_set_apparent_blocknumber(
        hypothesis, destination++, external_start + (int64_t)offset);
  }
  for (uint64_t source = cut; source < source_blocks; source++) {
    blockvector_set_apparent_blocknumber(
        hypothesis, destination++,
        blockvector_get_apparent_blocknumber(original, source));
  }
  blockvector_set_data_length(hypothesis, trial_length);
  inflate_blockvector(hypothesis);
  candidate->b = hypothesis;

  if (!jpg_reassembly_run_order_join_score(
          candidate, maximum_join_score, total_join_score)
      || *maximum_join_score >= JPG_RUN_ORDER_STRONG_JOIN_SCORE) {
    candidate->b = original;
    free_blockvector(&hypothesis);
    return false;
  }
  memset(&trial_state, 0, sizeof(trial_state));
  trial_validates = jpg_reassembly_validate_direct(
      candidate, &trial_state, &trial_validates_to, fixed_prefix_blocks);
  if (!trial_validates || trial_validates_to + 1 != trial_length) {
    candidate->b = original;
    free_blockvector(&hypothesis);
    return false;
  }

  if (!commit) {
    candidate->b = original;
    free_blockvector(&hypothesis);
    return true;
  }

  *validates = true;
  *validates_to = trial_validates_to;
  jpg_reassembly_commit_run_order_hypothesis(
      candidate, original, &trial_state, trial_validates_to);
  return true;
}

static inline bool jpg_reassembly_try_internal_run_transpose(
    CarveInfo *candidate,
    uint64_t source_blocks,
    uint64_t source_length,
    uint64_t cut_a,
    uint64_t cut_b,
    uint64_t cut_c,
    uint32_t fixed_prefix_blocks,
    bool *validates,
    uint64_t *validates_to,
    bool commit,
    double *maximum_join_score,
    double *total_join_score) {
  BlockVector *original;
  BlockVector *hypothesis = NULL;
  JPGCarveState trial_state;
  uint64_t destination = 0;
  uint64_t trial_validates_to = 0;
  bool trial_validates;

  if (!candidate || !candidate->b || !validates || !validates_to
      || !maximum_join_score || !total_join_score
      || cut_a == 0 || cut_a >= cut_b || cut_b >= cut_c
      || cut_c >= source_blocks) {
    return false;
  }

  original = candidate->b;
  init_blockvector(scalpel_state.filemirror, &hypothesis,
                   source_blocks, false);
  for (uint64_t source = 0; source < cut_a; source++) {
    blockvector_set_apparent_blocknumber(
        hypothesis, destination++,
        blockvector_get_apparent_blocknumber(original, source));
  }
  for (uint64_t source = cut_b; source < cut_c; source++) {
    blockvector_set_apparent_blocknumber(
        hypothesis, destination++,
        blockvector_get_apparent_blocknumber(original, source));
  }
  for (uint64_t source = cut_a; source < cut_b; source++) {
    blockvector_set_apparent_blocknumber(
        hypothesis, destination++,
        blockvector_get_apparent_blocknumber(original, source));
  }
  for (uint64_t source = cut_c; source < source_blocks; source++) {
    blockvector_set_apparent_blocknumber(
        hypothesis, destination++,
        blockvector_get_apparent_blocknumber(original, source));
  }
  blockvector_set_data_length(hypothesis, source_length);
  inflate_blockvector(hypothesis);
  candidate->b = hypothesis;

  if (!jpg_reassembly_run_order_join_score(
          candidate, maximum_join_score, total_join_score)
      || *maximum_join_score >= JPG_RUN_ORDER_STRONG_JOIN_SCORE) {
    candidate->b = original;
    free_blockvector(&hypothesis);
    return false;
  }
  memset(&trial_state, 0, sizeof(trial_state));
  trial_validates = jpg_reassembly_validate_direct(
      candidate, &trial_state, &trial_validates_to, fixed_prefix_blocks);
  if (!trial_validates || trial_validates_to + 1 != source_length) {
    candidate->b = original;
    free_blockvector(&hypothesis);
    return false;
  }

  if (!commit) {
    candidate->b = original;
    free_blockvector(&hypothesis);
    return true;
  }

  *validates = true;
  *validates_to = trial_validates_to;
  jpg_reassembly_commit_run_order_hypothesis(
      candidate, original, &trial_state, trial_validates_to);
  return true;
}

static inline bool jpg_run_order_hypothesis_better(
    const JPGRunOrderProgress *progress,
    double maximum_join_score,
    double total_join_score) {
  if (!progress->best_valid) {
    return true;
  }
  if (maximum_join_score != progress->best_max_join_score) {
    return maximum_join_score < progress->best_max_join_score;
  }
  return total_join_score < progress->best_total_join_score;
}

static inline void jpg_run_order_note_hypothesis(
    JPGRunOrderProgress *progress,
    uint8_t kind,
    uint64_t cut_a,
    uint64_t cut_b,
    uint64_t cut_c,
    uint64_t external_blocks,
    uint32_t group_i,
    uint32_t group_j,
    uint32_t group_k,
    double maximum_join_score,
    double total_join_score) {
  if (progress->complete_hypotheses < UINT32_MAX) {
    progress->complete_hypotheses++;
  }
  if (!jpg_run_order_hypothesis_better(
          progress, maximum_join_score, total_join_score)) {
    return;
  }
  progress->best_valid = true;
  progress->best_kind = kind;
  progress->best_max_join_score = maximum_join_score;
  progress->best_total_join_score = total_join_score;
  progress->best_cut_a = cut_a;
  progress->best_cut_b = cut_b;
  progress->best_cut_c = cut_c;
  progress->best_external_blocks = external_blocks;
  progress->best_group_i = group_i;
  progress->best_group_j = group_j;
  progress->best_group_k = group_k;
}

static inline bool jpg_reassembly_apply_best_run_order_hypothesis(
    CarveInfo *candidate,
    JPGRunOrderProgress *progress,
    uint64_t source_blocks,
    uint64_t source_length,
    uint32_t fixed_prefix_blocks,
    bool *validates,
    uint64_t *validates_to) {
  double maximum_join_score = DBL_MAX;
  double total_join_score = DBL_MAX;

  if (!progress->best_valid) {
    return false;
  }
  if (progress->best_kind == JPG_RUN_ORDER_KIND_EXTERNAL_INSERT) {
    return jpg_reassembly_try_external_run_insertion(
        candidate, source_blocks, source_length,
        progress->best_cut_a, progress->last_apparent + 1,
        progress->best_external_blocks, fixed_prefix_blocks,
        validates, validates_to, true,
        &maximum_join_score, &total_join_score);
  }
  if (progress->best_kind == JPG_RUN_ORDER_KIND_INTERNAL_TRANSPOSE) {
    return jpg_reassembly_try_internal_run_transpose(
        candidate, source_blocks, source_length,
        progress->best_cut_a, progress->best_cut_b, progress->best_cut_c,
        fixed_prefix_blocks, validates, validates_to, true,
        &maximum_join_score, &total_join_score);
  }
  return false;
}

static inline bool jpg_reassembly_attach_contiguous_eoi(
    CarveInfo *candidate,
    uint64_t *source_length) {
  uint64_t saved_blocks;
  uint64_t saved_length;
  int64_t tail_apparent;
  int64_t limit;
  int64_t next_header = -1;
  int64_t next_footer = -1;
  uint64_t append_blocks;
  uint64_t materialized_length = 0;
  char *materialized;

  if (!candidate || !candidate->b || !source_length
      || blockvector_get_num_blocks(candidate->b) == 0) {
    return false;
  }

  saved_blocks = blockvector_get_num_blocks(candidate->b);
  saved_length = blockvector_get_data_length(candidate->b);
  tail_apparent = blockvector_get_apparent_blocknumber(
      candidate->b, saved_blocks - 1);
  limit = (int64_t)filemirror_apparent_blocks(scalpel_state.filemirror);
  if (tail_apparent < 0 || tail_apparent + 1 >= limit) {
    return false;
  }
  if (jpg_reassembly_next_header_apparent(candidate, tail_apparent + 1,
                                          &next_header)
      && next_header < limit) {
    limit = next_header;
  }
  if (!jpg_reassembly_next_footer_apparent(candidate, tail_apparent + 1,
                                           limit, &next_footer)) {
    return false;
  }

  append_blocks = (uint64_t)(next_footer - tail_apparent);
  if (!jpg_reassembly_ooo_range_available(candidate, tail_apparent + 1,
                                          append_blocks, -1, 0)) {
    return false;
  }
  jpg_reassembly_ooo_append_range(candidate, tail_apparent + 1,
                                  append_blocks);
  materialized = jpg_reassembly_materialize_candidate(candidate,
                                                       &materialized_length);
  *source_length = jpg_reassembly_last_eoi_length(materialized,
                                                  materialized_length);
  if (*source_length <= saved_length
      || materialized_length - *source_length
             >= scalpel_state.blocksize) {
    jpg_reassembly_ooo_restore_candidate(candidate, saved_blocks,
                                         saved_length);
    *source_length = 0;
    return false;
  }

  blockvector_set_data_length(candidate->b, *source_length);
  candidate->newblock = blockvector_get_actual_blocknumber(
      candidate->b, blockvector_get_num_blocks(candidate->b) - 1);
  return true;
}

static inline void jpg_run_order_advance_transpose_combination(
    JPGRunOrderProgress *progress) {
  progress->transpose_trial_initialized = false;
  progress->transpose_k++;
  if (progress->transpose_k < progress->group_count) {
    return;
  }
  progress->transpose_j++;
  if (progress->transpose_j + 1 < progress->group_count) {
    progress->transpose_k = progress->transpose_j + 1;
    return;
  }
  progress->transpose_i++;
  if (progress->transpose_i + 2 < progress->group_count) {
    progress->transpose_j = progress->transpose_i + 1;
    progress->transpose_k = progress->transpose_j + 1;
  }
}

static inline bool jpg_reassembly_find_foreign_tail_cut(
    CarveInfo *candidate,
    JpgValidationContext *context,
    uint64_t source_blocks,
    uint64_t *cut_out,
    double *rate_ratio_out) {
  JPGHuffmanBlockProfile profile;
  JpgHuffmanFailure failure = JPG_HUFFMAN_FAILURE_NONE;
  JpgMcuValidationResult saved_mcu_result;
  uint32_t *mcu_at_boundary;
  uint32_t saved_blocksize = jpg_current_blocksize;
  int32_t saved_dc_threshold = jpg_dc_threshold;
  int32_t saved_max_observed_dc_diff = jpg_max_observed_dc_diff;
  size_t profile_entries;
  uint64_t rate_window;
  uint64_t best_cut = 0;
  double best_ratio = 0.0;
  JpgBoundaryScore boundary;

  if (!candidate || !context || !cut_out || !rate_ratio_out
      || !context->have_sof || !context->had_scan || context->is_progressive
      || context->entropy_start == 0 || scalpel_state.blocksize == 0
      || source_blocks < 3
      || source_blocks > SIZE_MAX / sizeof(*mcu_at_boundary) - 1) {
    return false;
  }

  profile_entries = (size_t)(source_blocks + 1);
  mcu_at_boundary = malloc(profile_entries * sizeof(*mcu_at_boundary));
  check_memory_allocation(mcu_at_boundary, __LINE__, __FILE__,
                          "jpg foreign-tail MCU profile");
  memset(mcu_at_boundary, 0xff,
         profile_entries * sizeof(*mcu_at_boundary));
  profile.mcu_at_boundary = mcu_at_boundary;
  profile.boundary_count = source_blocks + 1;

  memcpy(&saved_mcu_result, &jpg_mcu_result, sizeof(saved_mcu_result));
  jpg_current_blocksize = scalpel_state.blocksize;
  (void)jpg_huffman_validate(context, NULL, NULL, &failure, &profile);
  memcpy(&jpg_mcu_result, &saved_mcu_result, sizeof(jpg_mcu_result));
  jpg_current_blocksize = saved_blocksize;
  jpg_dc_threshold = saved_dc_threshold;
  jpg_max_observed_dc_diff = saved_max_observed_dc_diff;
  if (jpg_reassembly_checkpoint_requested()) {
    free(mcu_at_boundary);
    return false;
  }

  rate_window = CEILDIV(JPG_FOREIGN_TAIL_RATE_WINDOW_BYTES,
                        scalpel_state.blocksize);
  if (rate_window == 0) {
    rate_window = 1;
  }

  for (uint64_t cut = rate_window;
       cut + rate_window < source_blocks; cut++) {
    uint32_t left_start = mcu_at_boundary[cut - rate_window];
    uint32_t center = mcu_at_boundary[cut];
    uint32_t right_end = mcu_at_boundary[cut + rate_window];
    uint64_t left_mcus;
    uint64_t right_mcus;
    double ratio;

    if (left_start == UINT32_MAX || center == UINT32_MAX
        || right_end == UINT32_MAX || center <= left_start
        || right_end <= center) {
      continue;
    }
    left_mcus = (uint64_t)center - left_start;
    right_mcus = (uint64_t)right_end - center;
    ratio = left_mcus > right_mcus
              ? (double)left_mcus / (double)right_mcus
              : (double)right_mcus / (double)left_mcus;
    if (ratio < JPG_FOREIGN_TAIL_MIN_RATE_RATIO) {
      continue;
    }
    if (ratio > best_ratio
        || (ratio == best_ratio && (best_cut == 0 || cut < best_cut))) {
      best_cut = cut;
      best_ratio = ratio;
    }
  }

  free(mcu_at_boundary);
  if (best_cut == 0) {
    return false;
  }
  jpg_boundary_preview_cache_invalidate();
  boundary = jpg_boundary_score_scaled(
      (char *)context->data,
      best_cut * (uint64_t)scalpel_state.blocksize,
      context->length, 8, true);
  if (jpg_reassembly_checkpoint_requested()
      || !boundary.valid || boundary.boundary_row <= 1
      || boundary.baseline_mad <= 0.0
      || !isfinite(boundary.normalized)
      || boundary.normalized < JPG_FOREIGN_TAIL_MIN_SEAM_SCORE) {
    return false;
  }
  *cut_out = best_cut;
  *rate_ratio_out = best_ratio;
  if (jpg_reassembly_debug_candidate(candidate)) {
    lock_fprintf(stderr,
                 "[jpgdbg] foreign_tail_cut block=%" PRIu64
                 " rate_ratio=%.6f seam=%.6f\n",
                 best_cut, best_ratio, boundary.normalized);
  }
  return true;
}

static inline bool jpg_reassembly_rollback_hidden_boundary(
    CarveInfo *candidate,
    uint64_t rollback_block,
    bool *validates,
    uint64_t *validates_to,
    double rate_ratio) {
  BlockVector *original;
  BlockVector *prefix = NULL;
  JPGCarveState prefix_state;
  uint64_t original_blocks;
  uint64_t prefix_length;
  uint64_t prefix_validates_to = 0;
  uint32_t prefix_fixed_blocks;
  int64_t rejected_first;
  int64_t rejected_last;
  bool prefix_validates;

  if (!candidate || !candidate->b || !validates || !validates_to
      || scalpel_state.blocksize == 0 || rollback_block == 0
      || rollback_block >= blockvector_get_num_blocks(candidate->b)
      || rollback_block > UINT64_MAX / scalpel_state.blocksize) {
    return false;
  }

  original = candidate->b;
  original_blocks = blockvector_get_num_blocks(original);
  rejected_first = blockvector_get_actual_blocknumber(
      original, rollback_block);
  rejected_last = rejected_first;
  int64_t previous_apparent = blockvector_get_apparent_blocknumber(
      original, rollback_block);
  for (uint64_t slot = rollback_block + 1;
       rejected_first >= 0 && slot < original_blocks; slot++) {
    int64_t apparent;

    if ((slot & 255u) == 0
        && jpg_reassembly_checkpoint_requested()) {
      return false;
    }
    apparent = blockvector_get_apparent_blocknumber(original, slot);
    if (apparent != previous_apparent + 1) {
      break;
    }
    previous_apparent = apparent;
    rejected_last = blockvector_get_actual_blocknumber(original, slot);
  }
  prefix_length = rollback_block * (uint64_t)scalpel_state.blocksize;
  prefix_fixed_blocks = rollback_block > UINT32_MAX
                          ? UINT32_MAX : (uint32_t)rollback_block;
  clone_blockvector(original, &prefix, false);
  candidate->b = prefix;
  resize_blockvector(prefix, rollback_block);
  blockvector_set_data_length(prefix, prefix_length);
  inflate_blockvector(prefix);
  memset(&prefix_state, 0, sizeof(prefix_state));
  prefix_validates = jpg_reassembly_validate_direct(
      candidate, &prefix_state, &prefix_validates_to,
      prefix_fixed_blocks);
  if (!prefix_validates && prefix_state.valid
      && !jpg_wrongblock_result.detected
      && prefix_validates_to + 1 >= prefix_length) {
    prefix_state.reassembly_seed_checked = true;
    prefix_state.reassembly_seed_needs_search = true;
    prefix_state.hidden_boundary_recovery = true;
    prefix_state.hidden_boundary_runs_committed = 0;
    prefix_state.hidden_rejected_range_valid = rejected_first >= 0;
    prefix_state.hidden_rejected_first_actual = rejected_first;
    prefix_state.hidden_rejected_last_actual = rejected_last;
    free_blockvector(&original);
    *validates = false;
    *validates_to = prefix_length - 1;
    candidate->best_validates_to = *validates_to;
    candidate->newblock = blockvector_get_actual_blocknumber(
        candidate->b, rollback_block - 1);
    jpg_put_decoder_state(candidate->carvehashkey, &prefix_state);
    if (jpg_reassembly_debug_candidate(candidate)) {
      lock_fprintf(stderr,
                   "[jpgdbg] hidden_boundary_rollback block=%" PRIu64
                   " length=%" PRIu64 " rate_ratio=%.6f\n",
                   rollback_block, prefix_length, rate_ratio);
    }
    return true;
  }

  candidate->b = original;
  free_blockvector(&prefix);
  return false;
}

// A foreign tail can be followed physically by the displaced JPEG suffix.
// Test that one local replacement without disturbing the complete run-order
// search needed when the missing run must instead be inserted internally.
static inline bool jpg_reassembly_try_foreign_tail_successor(
    CarveInfo *candidate,
    const JPGCarveState *prefix_state,
    uint64_t rollback_block,
    int64_t source_last_apparent,
    bool require_entropy_probe,
    bool *validates,
    uint64_t *validates_to) {
  BlockVector *original;
  BlockVector *hypothesis = NULL;
  JpgReassemblyEntropyProbe probe;
  uint64_t prefix_length;
  uint32_t prefix_fixed_blocks;
  int64_t tail_start;
  bool trial_validates = false;
  uint64_t trial_validates_to = 0;
  uint64_t restored_length = 0;

  if (!candidate || !candidate->b || !prefix_state
      || !validates || !validates_to
      || scalpel_state.blocksize == 0 || rollback_block == 0
      || rollback_block >= blockvector_get_num_blocks(candidate->b)
      || rollback_block > UINT64_MAX / scalpel_state.blocksize
      || source_last_apparent < 0 || source_last_apparent == INT64_MAX) {
    return false;
  }

  tail_start = source_last_apparent + 1;
  prefix_length = rollback_block * (uint64_t)scalpel_state.blocksize;
  prefix_fixed_blocks = rollback_block > UINT32_MAX
                          ? UINT32_MAX : (uint32_t)rollback_block;
  original = candidate->b;
  clone_blockvector(original, &hypothesis, false);
  candidate->b = hypothesis;

  if (require_entropy_probe) {
    memset(&probe, 0, sizeof(probe));
    if (!jpg_reassembly_probe_baseline_entropy(
            candidate, prefix_state, rollback_block, prefix_length,
            tail_start, 1, -1, 0, &probe)
        || !probe.supported || !probe.clean || !probe.reaches_probe_end) {
      candidate->b = original;
      free_blockvector(&hypothesis);
      (void)jpg_reassembly_materialize_candidate(candidate, &restored_length);
      return false;
    }
  }

  if (!jpg_reassembly_try_contiguous_tail_validation(
          candidate, &trial_validates, &trial_validates_to,
          prefix_fixed_blocks, rollback_block, prefix_length, tail_start)
      || !trial_validates) {
    candidate->b = original;
    free_blockvector(&hypothesis);
    (void)jpg_reassembly_materialize_candidate(candidate, &restored_length);
    return false;
  }

  free_blockvector(&original);
  *validates = true;
  *validates_to = trial_validates_to;
  return true;
}

static inline bool jpg_reassembly_try_terminal_run_order_repair(
    CarveInfo *candidate,
    bool *validates,
    uint64_t *validates_to,
    uint32_t fixed_prefix_blocks,
    bool allow_hidden_boundary_search,
    bool *candidate_changed,
    bool *checkpoint_hit) {
  JPGCarveState state;
  JPGRunOrderProgress *progress;
  JpgValidationContext context;
  uint64_t materialized_length = 0;
  uint64_t source_length;
  uint64_t source_blocks;
  uint64_t signature;
  uint64_t hidden_entropy_limit = 0;
  bool hidden_boundary_search = false;
  bool incomplete_mcu_tail_search = false;
  char *materialized;

  if (candidate_changed) {
    *candidate_changed = false;
  }
  if (checkpoint_hit) {
    *checkpoint_hit = false;
  }
  if (!candidate || !candidate->b || !validates || !validates_to
      || scalpel_state.blocksize == 0
      || blockvector_get_num_blocks(candidate->b) < 4) {
    return false;
  }

  materialized = jpg_reassembly_materialize_candidate(candidate,
                                                       &materialized_length);
  source_length = jpg_reassembly_last_eoi_length(materialized,
                                                 materialized_length);
  if ((source_length == 0
       || source_length + scalpel_state.blocksize < materialized_length)
      && jpg_reassembly_attach_contiguous_eoi(candidate, &source_length)) {
    materialized = jpg_reassembly_materialize_candidate(
        candidate, &materialized_length);
  }
  if (jpg_reassembly_debug_candidate(candidate)) {
    lock_fprintf(stderr,
                 "[jpgdbg] run_order_gate materialized=%" PRIu64
                 " eoi=%" PRIu64 " vt=%" PRIu64 " blocks=%" PRIu64
                 "\n",
                 materialized_length, source_length, *validates_to,
                 blockvector_get_num_blocks(candidate->b));
  }
  if (source_length == 0) {
    if (jpg_reassembly_debug_candidate(candidate)) {
      lock_fprintf(stderr, "[jpgdbg] run_order_skip no_eoi\n");
    }
    return false;
  }
  incomplete_mcu_tail_search =
      *validates_to + 1 <= source_length
      && source_length - (*validates_to + 1)
             <= (uint64_t)scalpel_state.blocksize
                  + JPG_REASS_OOO_BOUNDARY_SLACK
      && jpg_mcu_result.valid
      && jpg_mcu_result.expected_mcus > 0
      && jpg_mcu_result.mcu_count > 0
      && jpg_mcu_result.mcu_count < jpg_mcu_result.expected_mcus
      && jpg_mcu_result.final_byte_pos > jpg_mcu_result.entropy_start
      && jpg_mcu_result.final_byte_pos <= source_length
      && source_length - jpg_mcu_result.final_byte_pos
             <= (uint64_t)scalpel_state.blocksize
                  + JPG_REASS_OOO_BOUNDARY_SLACK;
  hidden_boundary_search =
      *validates_to + 1 < source_length
      && source_length - (*validates_to + 1)
             > (uint64_t)scalpel_state.blocksize
                 + JPG_REASS_OOO_BOUNDARY_SLACK
      && jpg_wrongblock_result.detected
      && jpg_wrongblock_result.method
      && strcmp(jpg_wrongblock_result.method,
                "huffman_trailing_data") == 0
      && jpg_mcu_result.valid
      && jpg_mcu_result.expected_mcus > 0
      && jpg_mcu_result.mcu_count == jpg_mcu_result.expected_mcus
      && jpg_mcu_result.final_byte_pos > 0
      && jpg_mcu_result.final_byte_pos < source_length;
  if (hidden_boundary_search) {
    hidden_entropy_limit = jpg_mcu_result.final_byte_pos;
    if (!allow_hidden_boundary_search) {
      return false;
    }
  }
  if (*validates_to + 1 < source_length
      && source_length - (*validates_to + 1)
             > (uint64_t)scalpel_state.blocksize
                 + JPG_REASS_OOO_BOUNDARY_SLACK
      && !hidden_boundary_search && !incomplete_mcu_tail_search) {
    if (jpg_reassembly_debug_candidate(candidate)) {
      lock_fprintf(stderr,
                   "[jpgdbg] run_order_skip unsupported_shortfall"
                   " source=%" PRIu64 " vt=%" PRIu64 "\n",
                   source_length, *validates_to);
    }
    return false;
  }
  source_blocks = CEILDIV(source_length, scalpel_state.blocksize);
  if (source_blocks != blockvector_get_num_blocks(candidate->b)
      || !jpg_reassembly_physically_contiguous(candidate, source_blocks)) {
    if (jpg_reassembly_debug_candidate(candidate)) {
      lock_fprintf(stderr,
                   "[jpgdbg] run_order_skip layout source_blocks=%" PRIu64
                   " vector_blocks=%" PRIu64 " contiguous=%d\n",
                   source_blocks, blockvector_get_num_blocks(candidate->b),
                   jpg_reassembly_physically_contiguous(candidate,
                                                        source_blocks)
                       ? 1 : 0);
    }
    return false;
  }

  memset(&context, 0, sizeof(context));
  context.data = (const uint8_t *)materialized;
  context.length = source_length;
  (void)jpg_validate_structure(&context);
  if (!context.have_sof || context.entropy_start == 0
      || context.is_progressive) {
    if (jpg_reassembly_debug_candidate(candidate)) {
      lock_fprintf(stderr,
                   "[jpgdbg] run_order_skip structure sof=%d entropy=%" PRIu64
                   " progressive=%d\n",
                   context.have_sof ? 1 : 0, context.entropy_start,
                   context.is_progressive ? 1 : 0);
    }
    return false;
  }

  memset(&state, 0, sizeof(state));
  if (!jpg_reassembly_load_saved_state(candidate, &state)) {
    uint64_t rebuilt_validates_to = 0;

    memset(&state, 0, sizeof(state));
    (void)jpg_reassembly_validate_direct(candidate, &state,
                                         &rebuilt_validates_to,
                                         fixed_prefix_blocks);
  }
  if (!state.valid) {
    if (jpg_reassembly_debug_candidate(candidate)) {
      lock_fprintf(stderr, "[jpgdbg] run_order_skip no_state\n");
    }
    return false;
  }

  signature = XXH3_64bits(materialized, source_length);
  signature ^= source_blocks * UINT64_C(0x9e3779b97f4a7c15);
  progress = &state.run_order_progress;
  if (!progress->active || progress->signature != signature
      || progress->source_length != source_length
      || progress->source_blocks != source_blocks) {
    int64_t first_apparent = blockvector_get_apparent_blocknumber(
        candidate->b, 0);
    int64_t last_apparent = blockvector_get_apparent_blocknumber(
        candidate->b, source_blocks - 1);

    memset(progress, 0, sizeof(*progress));
    progress->active = true;
    progress->phase = JPG_RUN_ORDER_PHASE_SCAN;
    progress->signature = signature;
    progress->source_length = source_length;
    progress->source_blocks = source_blocks;
    progress->first_apparent = first_apparent;
    progress->last_apparent = last_apparent;
    progress->scan_next_block =
        CEILDIV(context.entropy_start, scalpel_state.blocksize);
    if (progress->scan_next_block < 1) {
      progress->scan_next_block = 1;
    }
  }

  if (incomplete_mcu_tail_search) {
    uint64_t rollback_block = 0;
    uint64_t trusted_prefix_length = *validates_to + 1;
    uint64_t trusted_prefix_blocks = 0;
    double rate_ratio = 0.0;

    if (trusted_prefix_length % scalpel_state.blocksize == 0) {
      trusted_prefix_blocks =
          trusted_prefix_length / scalpel_state.blocksize;
    }

    if (progress->fallback_rollback_valid) {
      rollback_block = progress->fallback_rollback_block;
      rate_ratio = progress->fallback_rollback_rate_ratio;
    }
    else if (jpg_reassembly_find_foreign_tail_cut(
                 candidate, &context, source_blocks,
                 &rollback_block, &rate_ratio)) {
      if (jpg_reassembly_try_foreign_tail_successor(
              candidate, &state, rollback_block, progress->last_apparent,
              false,
              validates, validates_to)) {
        return true;
      }
      progress->fallback_rollback_valid = true;
      progress->fallback_rollback_block = rollback_block;
      progress->fallback_rollback_rate_ratio = rate_ratio;
    }
    if (rollback_block != 0) {
      if (jpg_reassembly_checkpoint_requested()) {
        jpg_put_decoder_state(candidate->carvehashkey, &state);
        if (checkpoint_hit) {
          *checkpoint_hit = true;
        }
        return false;
      }
      // A terminal fragment can contain an incidental EOI immediately after a
      // fully validated block boundary. If the rate-derived cut does not prove
      // a complete replacement, test that local alternative before rollback.
      if (trusted_prefix_blocks > 0
          && trusted_prefix_blocks < source_blocks
          && trusted_prefix_blocks != rollback_block
          && jpg_reassembly_try_foreign_tail_successor(
                 candidate, &state, trusted_prefix_blocks,
                 progress->last_apparent, true,
                 validates, validates_to)) {
        return true;
      }
      if (jpg_reassembly_checkpoint_requested()) {
        jpg_put_decoder_state(candidate->carvehashkey, &state);
        if (checkpoint_hit) {
          *checkpoint_hit = true;
        }
        return false;
      }
      if (jpg_reassembly_rollback_hidden_boundary(
              candidate, rollback_block, validates, validates_to,
              rate_ratio)) {
        if (candidate_changed) {
          *candidate_changed = true;
        }
        return false;
      }
      if (!jpg_reassembly_checkpoint_requested()) {
        progress->fallback_rollback_valid = false;
        progress->fallback_rollback_block = 0;
        progress->fallback_rollback_rate_ratio = 0.0;
      }
    }
    else if (trusted_prefix_blocks > 0
             && trusted_prefix_blocks < source_blocks
             && jpg_reassembly_try_foreign_tail_successor(
                    candidate, &state, trusted_prefix_blocks,
                    progress->last_apparent, true,
                    validates, validates_to)) {
      return true;
    }
    if (jpg_reassembly_checkpoint_requested()) {
      jpg_put_decoder_state(candidate->carvehashkey, &state);
      if (checkpoint_hit) {
        *checkpoint_hit = true;
      }
      return false;
    }
  }

  while (progress->phase != JPG_RUN_ORDER_PHASE_EXHAUSTED) {
    if (progress->phase == JPG_RUN_ORDER_PHASE_SCAN) {
      materialized = jpg_reassembly_materialize_candidate(
          candidate, &materialized_length);
      while (progress->scan_next_block < source_blocks) {
        uint64_t block = progress->scan_next_block;
        JpgBoundaryScore score;

        if (jpg_reassembly_checkpoint_requested()) {
          jpg_put_decoder_state(candidate->carvehashkey, &state);
          if (checkpoint_hit) {
            *checkpoint_hit = true;
          }
          return false;
        }
        score = jpg_boundary_score_scaled(
            materialized, block * (uint64_t)scalpel_state.blocksize,
            source_length, 8, true);
        if (jpg_reassembly_checkpoint_requested()) {
          jpg_put_decoder_state(candidate->carvehashkey, &state);
          if (checkpoint_hit) {
            *checkpoint_hit = true;
          }
          return false;
        }
        progress->scan_next_block++;

        if (!score.valid) {
          jpg_run_order_finish_scan_group(progress);
          continue;
        }
        if (progress->scan_group_active
            && jpg_run_order_same_scan_group(&progress->scan_group,
                                             &score)) {
          progress->scan_group.last_block = block;
          continue;
        }

        jpg_run_order_finish_scan_group(progress);
        progress->scan_group_active = true;
        progress->scan_group.first_block = block;
        progress->scan_group.last_block = block;
        progress->scan_group.boundary_row = score.boundary_row;
        progress->scan_group.seam_mad = score.seam_mad;
        progress->scan_group.baseline_mad = score.baseline_mad;
        progress->scan_group.normalized = score.normalized;
      }
      jpg_run_order_finish_scan_group(progress);
      if (jpg_reassembly_debug_candidate(candidate)) {
        lock_fprintf(stderr,
                     "[jpgdbg] run_order_scan_complete groups=%u"
                     " hidden=%d incomplete=%d\n",
                     progress->group_count,
                     hidden_boundary_search ? 1 : 0,
                     incomplete_mcu_tail_search ? 1 : 0);
      }
      if (progress->group_count == 0) {
        progress->phase = JPG_RUN_ORDER_PHASE_EXHAUSTED;
        break;
      }
      if (hidden_boundary_search) {
        for (uint32_t index = 0; index < progress->group_count; index++) {
          const JPGRunOrderBoundary *group = &progress->groups[index];
          const uint64_t boundary_byte =
              group->first_block * (uint64_t)scalpel_state.blocksize;

          if (group->boundary_row <= 1 || group->baseline_mad <= 0.0
              || group->normalized < JPG_RUN_ORDER_HIDDEN_BOUNDARY_SCORE
              || boundary_byte >= hidden_entropy_limit) {
            continue;
          }
          if (jpg_reassembly_debug_candidate(candidate)) {
            lock_fprintf(stderr,
                         "[jpgdbg] hidden_boundary_group first=%" PRIu64
                         " last=%" PRIu64 " row=%u score=%.6f\n",
                         group->first_block, group->last_block,
                         group->boundary_row, group->normalized);
          }
          if (jpg_reassembly_rollback_hidden_boundary(
                  candidate, group->first_block, validates,
                  validates_to, 0.0)) {
            if (candidate_changed) {
              *candidate_changed = true;
            }
            return false;
          }
          if (jpg_reassembly_checkpoint_requested()) {
            jpg_put_decoder_state(candidate->carvehashkey, &state);
            if (checkpoint_hit) {
              *checkpoint_hit = true;
            }
            return false;
          }
        }
        progress->phase = JPG_RUN_ORDER_PHASE_EXHAUSTED;
        break;
      }
      progress->phase = JPG_RUN_ORDER_PHASE_EXTERNAL_INSERT;
      progress->external_group = 0;
      progress->external_cut_next = 0;
      progress->external_blocks_next = 0;
    }

    if (progress->phase == JPG_RUN_ORDER_PHASE_EXTERNAL_INSERT) {
      int64_t external_start = progress->last_apparent + 1;
      int64_t next_header = -1;
      uint64_t external_blocks = 0;

      if (external_start >= 0
          && jpg_reassembly_next_header_apparent(candidate, external_start,
                                                 &next_header)
          && next_header > external_start) {
        external_blocks = (uint64_t)(next_header - external_start);
      }
      if (jpg_reassembly_debug_candidate(candidate)) {
        lock_fprintf(stderr,
                     "[jpgdbg] run_order_external start=%" PRId64
                     " next_header=%" PRId64 " blocks=%" PRIu64
                     " groups=%u\n",
                     external_start, next_header, external_blocks,
                     progress->group_count);
      }

      while (external_blocks > 0
             && progress->external_group < progress->group_count) {
        JPGRunOrderBoundary *group =
            &progress->groups[progress->external_group];
        uint64_t minimum;
        uint64_t maximum;

        jpg_run_order_boundary_range(group, source_blocks,
                                     &minimum, &maximum);
        if (progress->external_cut_next < minimum) {
          progress->external_cut_next = minimum;
          progress->external_blocks_next = external_blocks;
        }
        while (progress->external_cut_next <= maximum) {
          uint64_t cut = progress->external_cut_next;
          uint64_t trial_external_blocks = progress->external_blocks_next;

          if (trial_external_blocks == 0
              || trial_external_blocks > external_blocks) {
            trial_external_blocks = external_blocks;
            progress->external_blocks_next = trial_external_blocks;
          }

          if (jpg_reassembly_checkpoint_requested()) {
            jpg_put_decoder_state(candidate->carvehashkey, &state);
            if (checkpoint_hit) {
              *checkpoint_hit = true;
            }
            return false;
          }
          {
            double maximum_join_score = DBL_MAX;
            double total_join_score = DBL_MAX;
            bool complete_hypothesis;

            complete_hypothesis = jpg_reassembly_try_external_run_insertion(
                candidate, source_blocks, source_length, cut,
                external_start, trial_external_blocks,
                fixed_prefix_blocks, validates, validates_to, false,
                &maximum_join_score, &total_join_score);
            if (jpg_reassembly_checkpoint_requested()) {
              jpg_put_decoder_state(candidate->carvehashkey, &state);
              if (checkpoint_hit) {
                *checkpoint_hit = true;
              }
              return false;
            }
            if (complete_hypothesis) {
              jpg_run_order_note_hypothesis(
                  progress, JPG_RUN_ORDER_KIND_EXTERNAL_INSERT,
                  cut, 0, 0, trial_external_blocks,
                  0, 0, 0,
                  maximum_join_score, total_join_score);
              if (jpg_reassembly_debug_candidate(candidate)) {
                lock_fprintf(stderr,
                             "[jpgdbg] run_order_complete external"
                             " cut=%" PRIu64 " blocks=%" PRIu64
                             " max=%.6f total=%.6f best=%.6f\n",
                             cut, trial_external_blocks,
                             maximum_join_score, total_join_score,
                             progress->best_max_join_score);
              }
            }
          }
          progress->external_blocks_next--;
          if (progress->external_blocks_next == 0) {
            progress->external_cut_next++;
            progress->external_blocks_next = external_blocks;
          }
        }
        if (progress->best_valid
            && progress->best_kind == JPG_RUN_ORDER_KIND_EXTERNAL_INSERT
            && jpg_reassembly_apply_best_run_order_hypothesis(
                   candidate, progress, source_blocks, source_length,
                   fixed_prefix_blocks, validates, validates_to)) {
          return true;
        }
        progress->external_group++;
        progress->external_cut_next = 0;
        progress->external_blocks_next = 0;
      }

      progress->phase = JPG_RUN_ORDER_PHASE_INTERNAL_TRANSPOSE;
      progress->transpose_i = 0;
      progress->transpose_j = 1;
      progress->transpose_k = 2;
      progress->transpose_probe_mode = true;
      progress->transpose_refine_mode = false;
      progress->transpose_trial_initialized = false;
    }

    if (progress->phase == JPG_RUN_ORDER_PHASE_INTERNAL_TRANSPOSE) {
      while (progress->group_count >= 3
             && progress->transpose_i + 2 < progress->group_count) {
        const JPGRunOrderBoundary *ordered[3] = {
          &progress->groups[progress->transpose_i],
          &progress->groups[progress->transpose_j],
          &progress->groups[progress->transpose_k]
        };
        uint64_t minimum[3];
        uint64_t maximum[3];

        for (uint32_t left = 0; left < 2; left++) {
          for (uint32_t right = left + 1; right < 3; right++) {
            if (ordered[right]->first_block < ordered[left]->first_block) {
              const JPGRunOrderBoundary *swap = ordered[left];

              ordered[left] = ordered[right];
              ordered[right] = swap;
            }
          }
        }
        for (uint32_t index = 0; index < 3; index++) {
          jpg_run_order_boundary_range(ordered[index], source_blocks,
                                       &minimum[index], &maximum[index]);
          if (progress->transpose_probe_mode) {
            minimum[index] = ordered[index]->first_block;
            maximum[index] = minimum[index] + 3;
            if (maximum[index] >= source_blocks) {
              maximum[index] = source_blocks - 1;
            }
          }
        }
        if (!progress->transpose_trial_initialized) {
          progress->transpose_cut_a = minimum[0];
          progress->transpose_cut_b = minimum[1];
          progress->transpose_cut_c = minimum[2];
          progress->transpose_trial_initialized = true;
        }

        while (progress->transpose_cut_a <= maximum[0]) {
          uint64_t cut_a = progress->transpose_cut_a;
          uint64_t cut_b = progress->transpose_cut_b;
          uint64_t cut_c = progress->transpose_cut_c;

          progress->transpose_cut_c++;
          if (progress->transpose_cut_c > maximum[2]) {
            progress->transpose_cut_c = minimum[2];
            progress->transpose_cut_b++;
            if (progress->transpose_cut_b > maximum[1]) {
              progress->transpose_cut_b = minimum[1];
              progress->transpose_cut_a++;
            }
          }

          if (cut_a >= cut_b || cut_b >= cut_c) {
            continue;
          }
          if (jpg_reassembly_checkpoint_requested()) {
            progress->transpose_cut_a = cut_a;
            progress->transpose_cut_b = cut_b;
            progress->transpose_cut_c = cut_c;
            jpg_put_decoder_state(candidate->carvehashkey, &state);
            if (checkpoint_hit) {
              *checkpoint_hit = true;
            }
            return false;
          }
          {
            double maximum_join_score = DBL_MAX;
            double total_join_score = DBL_MAX;
            bool complete_hypothesis;

            complete_hypothesis = jpg_reassembly_try_internal_run_transpose(
                candidate, source_blocks, source_length,
                cut_a, cut_b, cut_c, fixed_prefix_blocks,
                validates, validates_to, false,
                &maximum_join_score, &total_join_score);
            if (jpg_reassembly_checkpoint_requested()) {
              progress->transpose_cut_a = cut_a;
              progress->transpose_cut_b = cut_b;
              progress->transpose_cut_c = cut_c;
              jpg_put_decoder_state(candidate->carvehashkey, &state);
              if (checkpoint_hit) {
                *checkpoint_hit = true;
              }
              return false;
            }
            if (complete_hypothesis) {
              jpg_run_order_note_hypothesis(
                  progress, JPG_RUN_ORDER_KIND_INTERNAL_TRANSPOSE,
                  cut_a, cut_b, cut_c, 0,
                  progress->transpose_i, progress->transpose_j,
                  progress->transpose_k,
                  maximum_join_score, total_join_score);
              if (jpg_reassembly_debug_candidate(candidate)) {
                lock_fprintf(stderr,
                             "[jpgdbg] run_order_complete transpose"
                             " cuts=%" PRIu64 ",%" PRIu64 ",%" PRIu64
                             " max=%.6f total=%.6f best=%.6f\n",
                             cut_a, cut_b, cut_c,
                             maximum_join_score, total_join_score,
                             progress->best_max_join_score);
              }
            }
          }
        }
        {
          uint32_t primary_groups = progress->group_count;
          bool probe_complete;
          bool refinement_complete = progress->transpose_refine_mode;

          if (primary_groups > JPG_RUN_ORDER_PRIMARY_GROUPS) {
            primary_groups = JPG_RUN_ORDER_PRIMARY_GROUPS;
          }
          probe_complete = progress->transpose_probe_mode
              && progress->transpose_i == 0
              && progress->transpose_j == 1
              && progress->transpose_k + 1 >= primary_groups;
          jpg_run_order_advance_transpose_combination(progress);
          if (refinement_complete) {
            if (jpg_reassembly_apply_best_run_order_hypothesis(
                    candidate, progress, source_blocks, source_length,
                    fixed_prefix_blocks, validates, validates_to)) {
              return true;
            }
            progress->transpose_refine_mode = false;
          }
          if (probe_complete) {
            progress->transpose_probe_mode = false;
            progress->transpose_trial_initialized = false;
            if (progress->best_valid
                && progress->best_kind
                       == JPG_RUN_ORDER_KIND_INTERNAL_TRANSPOSE) {
              progress->transpose_refine_mode = true;
              progress->transpose_i = progress->best_group_i;
              progress->transpose_j = progress->best_group_j;
              progress->transpose_k = progress->best_group_k;
            }
            else {
              progress->transpose_i = 0;
              progress->transpose_j = 1;
              progress->transpose_k = 2;
            }
          }
        }
      }

      if (progress->group_count < JPG_RUN_ORDER_GROUP_BATCH) {
        progress->phase = JPG_RUN_ORDER_PHASE_EXHAUSTED;
        break;
      }
      progress->page_after_valid = true;
      progress->page_after_normalized =
          progress->groups[progress->group_count - 1].normalized;
      progress->page_after_first_block =
          progress->groups[progress->group_count - 1].first_block;
      progress->phase = JPG_RUN_ORDER_PHASE_SCAN;
      progress->scan_next_block =
          CEILDIV(context.entropy_start, scalpel_state.blocksize);
      if (progress->scan_next_block < 1) {
        progress->scan_next_block = 1;
      }
      progress->scan_group_active = false;
      progress->group_count = 0;
      progress->transpose_trial_initialized = false;
    }
  }

  if (jpg_reassembly_apply_best_run_order_hypothesis(
          candidate, progress, source_blocks, source_length,
          fixed_prefix_blocks, validates, validates_to)) {
    return true;
  }
  jpg_put_decoder_state(candidate->carvehashkey, &state);
  return false;
}

static inline bool jpg_reassembly_try_pending_hidden_rollback(
    CarveInfo *candidate,
    bool *validates,
    uint64_t *validates_to) {
  JPGCarveState state;
  JPGRunOrderProgress *progress;
  uint64_t materialized_length = 0;
  uint64_t signature;
  uint64_t rollback_block;
  double rate_ratio;
  char *materialized;

  if (!candidate || !candidate->b || !validates || !validates_to) {
    return false;
  }
  memset(&state, 0, sizeof(state));
  if (!jpg_reassembly_load_saved_state(candidate, &state)) {
    return false;
  }
  progress = &state.run_order_progress;
  if (!progress->active || !progress->fallback_rollback_valid
      || progress->source_blocks
             != blockvector_get_num_blocks(candidate->b)
      || progress->source_length == 0) {
    return false;
  }

  materialized = jpg_reassembly_materialize_candidate(
      candidate, &materialized_length);
  if (!materialized || materialized_length < progress->source_length) {
    progress->fallback_rollback_valid = false;
    jpg_put_decoder_state(candidate->carvehashkey, &state);
    return false;
  }
  signature = XXH3_64bits(materialized, progress->source_length);
  signature ^= progress->source_blocks
               * UINT64_C(0x9e3779b97f4a7c15);
  if (signature != progress->signature) {
    progress->fallback_rollback_valid = false;
    jpg_put_decoder_state(candidate->carvehashkey, &state);
    return false;
  }

  rollback_block = progress->fallback_rollback_block;
  rate_ratio = progress->fallback_rollback_rate_ratio;
  if (jpg_reassembly_rollback_hidden_boundary(
          candidate, rollback_block, validates, validates_to, rate_ratio)) {
    return true;
  }
  if (jpg_reassembly_checkpoint_requested()) {
    jpg_put_decoder_state(candidate->carvehashkey, &state);
    return false;
  }
  progress->fallback_rollback_valid = false;
  progress->fallback_rollback_block = 0;
  progress->fallback_rollback_rate_ratio = 0.0;
  jpg_put_decoder_state(candidate->carvehashkey, &state);
  return false;
}

// A terminal fragment can precede its JPEG header physically. Probe possible
// starts of each such EOI-anchored run from the saved baseline entropy state;
// only a run that resumes cleanly and completes through the real EOI is kept.
static inline bool jpg_reassembly_try_preheader_tail_validation(
    CarveInfo *candidate,
    const JPGCarveState *prefix_state,
    bool *validates,
    uint64_t *validates_to,
    uint32_t fixed_prefix_blocks,
    uint64_t saved_num_blocks,
    uint64_t saved_length,
    uint64_t maximum_start_trials) {
  uint64_t start_trials = 0;

  if (!candidate || !candidate->b || !prefix_state || !validates
      || !validates_to || !prefix_state->valid
      || prefix_state->is_progressive
      || !prefix_state->huff_checkpoint.valid
      || saved_num_blocks == 0 || scalpel_state.blocksize == 0) {
    return false;
  }

  const int64_t first_apparent = blockvector_get_apparent_blocknumber(
      candidate->b, 0);
  const int64_t apparent_blocks = (int64_t)filemirror_apparent_blocks(
      scalpel_state.filemirror);
  SearchSpec *spec = &scalpel_state.search_specs[candidate->needleidx];

  if (jpg_reassembly_debug_candidate(candidate)) {
    lock_fprintf(stderr,
                 "[jpgdbg] preheader_tail begin blocks=%" PRIu64
                 " length=%" PRIu64 " first=%" PRId64
                 " footers=%" PRIu64 " huffman=%d\n",
                 saved_num_blocks, saved_length, first_apparent,
                 spec->offsets.numfooters,
                 prefix_state->huff_checkpoint.valid ? 1 : 0);
  }

  if (first_apparent <= 0 || apparent_blocks <= 0
      || saved_length >= spec->MAXIMUMSIZE) {
    return false;
  }

  uint64_t maximum_tail_blocks = CEILDIV(
      spec->MAXIMUMSIZE - saved_length, scalpel_state.blocksize);

  for (uint64_t footer_cursor = spec->offsets.numfooters;
       footer_cursor > 0; footer_cursor--) {
    const uint64_t footer_index = footer_cursor - 1;
    const int64_t footer_actual = (int64_t)(
        spec->offsets.footers[footer_index] / scalpel_state.blocksize);
    const int64_t footer_apparent = filemirror_apparent_blocknumber(
        scalpel_state.filemirror, footer_actual);

    if (footer_actual < 0 || footer_apparent < 0
        || footer_apparent >= first_apparent
        || jpg_reassembly_apparent_in_blockvector_strict(
               candidate->b, footer_apparent)) {
      continue;
    }

    int64_t first_start = footer_apparent
                          - (int64_t)maximum_tail_blocks + 1;

    if (first_start < 0) {
      first_start = 0;
    }
    for (uint64_t header_index = 0;
         header_index < spec->offsets.numheaders; header_index++) {
      int64_t header_apparent = -1;

      if (jpg_reassembly_header_anchor_apparent(
              candidate, header_index, &header_apparent)
          && header_apparent >= first_start
          && header_apparent < footer_apparent) {
        first_start = header_apparent + 1;
      }
    }

    for (int64_t tail_start = footer_apparent;
         tail_start >= first_start; tail_start--) {
      if (maximum_start_trials > 0
          && start_trials >= maximum_start_trials) {
        jpg_reassembly_ooo_restore_candidate(candidate, saved_num_blocks,
                                             saved_length);
        return false;
      }
      start_trials++;
      if (jpg_reassembly_checkpoint_requested()) {
        jpg_reassembly_ooo_restore_candidate(candidate, saved_num_blocks,
                                             saved_length);
        return false;
      }

      uint64_t probe_blocks = (uint64_t)(footer_apparent - tail_start + 1);

      if (probe_blocks > JPG_REASSEMBLY_PROBE_MAX_CHAIN) {
        probe_blocks = JPG_REASSEMBLY_PROBE_MAX_CHAIN;
      }
      if (!jpg_reassembly_ooo_range_available(
              candidate, tail_start, probe_blocks, -1, 0)
          || jpg_reassembly_ooo_range_has_zero(tail_start, probe_blocks)) {
        continue;
      }

      JpgReassemblyEntropyProbe probe;

      memset(&probe, 0, sizeof(probe));
      const bool probed = jpg_reassembly_probe_baseline_entropy(
          candidate, prefix_state, saved_num_blocks, saved_length,
          tail_start, probe_blocks, -1, 0, &probe);

      if (jpg_reassembly_debug_candidate(candidate)
          && (tail_start == first_start
              || (probed && probe.supported && probe.clean))) {
        lock_fprintf(stderr,
                     "[jpgdbg] preheader_tail probe start=%" PRId64
                     " footer=%" PRId64 " blocks=%" PRIu64
                     " probed=%d supported=%d clean=%d reaches=%d"
                     " frontier=%" PRIu64 " failure=%d\n",
                     tail_start, footer_apparent, probe_blocks,
                     probed ? 1 : 0, probe.supported ? 1 : 0,
                     probe.clean ? 1 : 0,
                     probe.reaches_probe_end ? 1 : 0,
                     probe.frontier, probe.failure);
      }
      if (!probed || !probe.supported || !probe.clean
          || !probe.reaches_probe_end) {
        continue;
      }

      if (jpg_reassembly_try_contiguous_tail_validation(
              candidate, validates, validates_to, fixed_prefix_blocks,
              saved_num_blocks, saved_length, tail_start)
          && *validates && !jpg_wrongblock_result.detected) {
        return true;
      }
      jpg_reassembly_ooo_restore_candidate(candidate, saved_num_blocks,
                                           saved_length);
      *validates = false;
    }
  }

  return false;
}

static inline bool jpg_reassembly_try_bridge_tail_validation(
    CarveInfo *candidate,
    const JPGCarveState *prefix_state,
    bool have_prefix_state,
    bool *validates,
    uint64_t *validates_to,
    uint32_t fixed_prefix_blocks,
    uint64_t saved_num_blocks,
    uint64_t saved_length,
    int64_t moved_start,
    uint64_t run_len,
    int64_t suffix_start,
    bool commit,
    JpgBoundaryScore *boundary_out) {
  SearchSpec *spec;
  JPGCarveState trial_state;
  int64_t suffix_limit;
  int64_t next_header = -1;
  int64_t next_footer = -1;
  uint64_t max_tail_blocks;
  uint64_t suffix_blocks;
  uint64_t trial_validates_to = 0;
  uint64_t materialized_length = 0;
  char *materialized;
  JpgValidationContext structural_ctx;
  JpgReassemblyEntropyProbe entropy_probe;
  bool trial_validates;

  if (!candidate || !candidate->b || !validates || !validates_to
      || scalpel_state.blocksize == 0 || moved_start < 0
      || run_len == 0 || suffix_start < 0) {
    return false;
  }

  spec = &scalpel_state.search_specs[candidate->needleidx];
  if (saved_length >= spec->MAXIMUMSIZE
      || run_len > CEILDIV(spec->MAXIMUMSIZE - saved_length,
                           scalpel_state.blocksize)) {
    return false;
  }
  max_tail_blocks =
      CEILDIV(spec->MAXIMUMSIZE - saved_length, scalpel_state.blocksize)
      - run_len;
  suffix_limit =
      (int64_t)filemirror_apparent_blocks(scalpel_state.filemirror);
  if (max_tail_blocks < (uint64_t)(suffix_limit - suffix_start)) {
    suffix_limit = suffix_start + (int64_t)max_tail_blocks;
  }
  if (jpg_reassembly_next_header_apparent(candidate, suffix_start + 1,
                                          &next_header)
      && next_header < suffix_limit) {
    suffix_limit = next_header;
  }
  if (!jpg_reassembly_next_footer_apparent(candidate, suffix_start,
                                           suffix_limit, &next_footer)) {
    return false;
  }

  suffix_blocks = (uint64_t)(next_footer - suffix_start + 1);
  jpg_reassembly_ooo_restore_candidate(candidate, saved_num_blocks,
                                       saved_length);
  if (!jpg_reassembly_ooo_range_available(candidate, moved_start, run_len,
                                          suffix_start, suffix_blocks)
      || !jpg_reassembly_ooo_range_available(candidate, suffix_start,
                                             suffix_blocks,
                                             moved_start, run_len)
      || jpg_reassembly_ooo_range_has_zero(moved_start, run_len)) {
    return false;
  }
  memset(&entropy_probe, 0, sizeof(entropy_probe));
  if (have_prefix_state
      && jpg_reassembly_probe_baseline_entropy(
             candidate, prefix_state, saved_num_blocks, saved_length,
             moved_start, run_len, suffix_start, suffix_blocks,
             &entropy_probe)
      && entropy_probe.supported && !entropy_probe.clean
      && jpg_huffman_failure_is_hard(entropy_probe.failure)) {
    if (jpg_reassembly_debug_candidate(candidate)) {
      lock_fprintf(stderr,
                   "[jpgdbg] entropy_tail run=%" PRId64 "+%" PRIu64
                   " suffix=%" PRId64 "+%" PRIu64
                   " clean=0 failure=%d frontier=%" PRIu64
                   " mcu=%u/%u final=%" PRIu64 " reject=1\n",
                   moved_start, run_len, suffix_start, suffix_blocks,
                   entropy_probe.failure, entropy_probe.frontier,
                   entropy_probe.mcu.mcu_count,
                   entropy_probe.mcu.expected_mcus,
                   entropy_probe.mcu.final_byte_pos);
    }
    return false;
  }
  if (entropy_probe.supported
      && jpg_reassembly_debug_candidate(candidate)) {
    lock_fprintf(stderr,
                 "[jpgdbg] entropy_tail run=%" PRId64 "+%" PRIu64
                 " suffix=%" PRId64 "+%" PRIu64
                 " clean=%d failure=%d frontier=%" PRIu64
                 " mcu=%u/%u final=%" PRIu64 " reject=0\n",
                 moved_start, run_len, suffix_start, suffix_blocks,
                 entropy_probe.clean ? 1 : 0, entropy_probe.failure,
                 entropy_probe.frontier, entropy_probe.mcu.mcu_count,
                 entropy_probe.mcu.expected_mcus,
                 entropy_probe.mcu.final_byte_pos);
  }
  jpg_reassembly_ooo_append_range(candidate, moved_start, run_len);
  jpg_reassembly_ooo_append_range(candidate, suffix_start, suffix_blocks);

  materialized = jpg_reassembly_materialize_candidate(candidate,
                                                       &materialized_length);
  memset(&structural_ctx, 0, sizeof(structural_ctx));
  structural_ctx.data = (const uint8_t *)materialized;
  structural_ctx.length = materialized_length;
  if (jpg_validate_structure(&structural_ctx) != JPG_VAL_OK) {
    jpg_reassembly_ooo_restore_candidate(candidate, saved_num_blocks,
                                         saved_length);
    return false;
  }

  memset(&trial_state, 0, sizeof(trial_state));
  trial_validates = jpg_reassembly_validate_direct(
      candidate, &trial_state, &trial_validates_to, fixed_prefix_blocks);
  if (!trial_validates) {
    jpg_reassembly_ooo_restore_candidate(candidate, saved_num_blocks,
                                         saved_length);
    return false;
  }

  if (boundary_out) {
    *boundary_out = jpg_boundary_score(materialized, saved_length,
                                       trial_validates_to + 1);
  }

  if (!commit) {
    jpg_reassembly_ooo_restore_candidate(candidate, saved_num_blocks,
                                         saved_length);
    return true;
  }

  *validates = true;
  *validates_to = trial_validates_to;
  blockvector_set_data_length(candidate->b, trial_validates_to + 1);
  resize_blockvector(candidate->b,
                     CEILDIV(blockvector_get_data_length(candidate->b),
                             scalpel_state.blocksize));
  candidate->best_validates_to = trial_validates_to;
  if (blockvector_get_num_blocks(candidate->b) > 0) {
    int64_t last_apparent = blockvector_get_apparent_blocknumber(
        candidate->b, blockvector_get_num_blocks(candidate->b) - 1);
    candidate->newblock =
        filemirror_actual_blocknumber(scalpel_state.filemirror, last_apparent);
  }
  if (trial_state.valid) {
    jpg_put_decoder_state(candidate->carvehashkey, &trial_state);
  }
  jpg_reassembly_debug_dump("bridge_tail_validated", candidate,
                            moved_start, trial_validates_to);
  return true;
}

static inline bool jpg_reassembly_try_ooo_candidate_run(
    CarveInfo *candidate,
    const JPGCarveState *prefix_state,
    bool have_prefix_state,
    bool *validates,
    uint64_t *validates_to,
    uint32_t fixed_prefix_blocks,
    uint64_t saved_num_blocks,
    uint64_t saved_length,
    int64_t run_start,
    uint64_t run_len,
    int64_t suffix_start,
    uint64_t suffix_len,
    bool require_full_validate,
    bool reject_zero_run,
    bool commit,
    JpgBoundaryScore *boundary_out) {
  JPGCarveState trial_state;
  uint64_t trial_validates_to = 0;
  uint64_t trial_frontier;
  uint64_t trial_end;
  uint64_t commit_validates_to = 0;
  bool trial_validates;
  bool reaches_probe_end;
  bool reaches_probe_commit = false;

  if (!jpg_reassembly_ooo_range_available(candidate, run_start, run_len,
                                          suffix_start, suffix_len)) {
    return false;
  }
  if (suffix_len > 0
      && !jpg_reassembly_ooo_range_available(candidate, suffix_start, suffix_len,
                                             run_start, run_len)) {
    return false;
  }
  if (reject_zero_run
      && (jpg_reassembly_ooo_range_has_zero(run_start, run_len)
          || (suffix_len > 0
              && jpg_reassembly_ooo_range_has_zero(suffix_start,
                                                   suffix_len)))) {
    return false;
  }

  jpg_reassembly_ooo_restore_candidate(candidate, saved_num_blocks,
                                       saved_length);
  jpg_reassembly_ooo_append_range(candidate, run_start, run_len);
  if (suffix_len > 0) {
    jpg_reassembly_ooo_append_range(candidate, suffix_start, suffix_len);
  }

  if (have_prefix_state) {
    memcpy(&trial_state, prefix_state, sizeof(trial_state));
  }
  else {
    memset(&trial_state, 0, sizeof(trial_state));
  }

  trial_validates =
      jpg_reassembly_validate_direct(candidate, &trial_state,
                                     &trial_validates_to,
                                     fixed_prefix_blocks);
  trial_frontier = trial_validates_to;
  if (trial_state.valid && trial_state.huff_checkpoint.valid
      && trial_state.huff_checkpoint.byte_pos > trial_frontier + 1) {
    trial_frontier = trial_state.huff_checkpoint.byte_pos - 1;
  }

  if (require_full_validate && !trial_validates) {
    JPGCarveState cold_state;
    uint64_t cold_validates_to = 0;
    bool cold_validates;

    memset(&cold_state, 0, sizeof(cold_state));
    cold_validates =
        jpg_reassembly_validate_direct(candidate, &cold_state,
                                       &cold_validates_to,
                                       fixed_prefix_blocks);
    if (!cold_validates) {
      jpg_reassembly_ooo_restore_candidate(candidate, saved_num_blocks,
                                           saved_length);
      return false;
    }
    memcpy(&trial_state, &cold_state, sizeof(trial_state));
    trial_validates = true;
    trial_validates_to = cold_validates_to;
    trial_frontier = trial_validates_to;
  }

  trial_end = blockvector_get_data_length(candidate->b) - 1;
  reaches_probe_end =
      trial_frontier >= trial_end
      || (trial_end > trial_frontier
          && trial_end - trial_frontier <= JPG_REASS_OOO_BOUNDARY_SLACK
          && !jpg_wrongblock_result.detected);
  if ((reaches_probe_end || trial_validates)
      && (boundary_out || jpg_reassembly_debug_candidate(candidate))) {
    uint64_t boundary_length =
        trial_validates ? trial_validates_to + 1
                        : blockvector_get_data_length(candidate->b);
    JpgBoundaryScore boundary = jpg_boundary_score(
        blockvector_get_data_pointer(candidate->b), saved_length,
        boundary_length);

    if (boundary_out) {
      memcpy(boundary_out, &boundary, sizeof(*boundary_out));
    }
    if (jpg_reassembly_debug_candidate(candidate)) {
      lock_fprintf(stderr,
                   "[jpgdbg] ooo_boundary run=%" PRId64 "+%" PRIu64
                   " suffix=%" PRId64 "+%" PRIu64 " valid=%d row=%u"
                   " seam=%.3f base=%.3f norm=%.3f\n",
                   run_start, run_len, suffix_start, suffix_len,
                   boundary.valid ? 1 : 0, boundary.boundary_row,
                   boundary.seam_mad, boundary.baseline_mad,
                   boundary.normalized);
    }
  }
  if (jpg_reassembly_debug_candidate(candidate)) {
      lock_fprintf(stderr,
                   "[jpgdbg] ooo_run_trial run=%" PRId64 "+%" PRIu64
                   " suffix=%" PRId64 "+%" PRIu64 " valid=%d vt=%" PRIu64
                   " frontier=%" PRIu64 " end=%" PRIu64 " reaches=%d"
                   " prefix_mcu=%u@%" PRIu64 " trial_mcu=%u@%" PRIu64 "\n",
                   run_start, run_len, suffix_start, suffix_len,
                   trial_validates ? 1 : 0, trial_validates_to,
                   trial_frontier, trial_end, reaches_probe_end ? 1 : 0,
                   prefix_state && prefix_state->huff_checkpoint.valid
                       ? prefix_state->huff_checkpoint.mcu_count : 0,
                   prefix_state && prefix_state->huff_checkpoint.valid
                       ? prefix_state->huff_checkpoint.byte_pos : 0,
                   trial_state.huff_checkpoint.valid
                       ? trial_state.huff_checkpoint.mcu_count : 0,
                   trial_state.huff_checkpoint.valid
                       ? trial_state.huff_checkpoint.byte_pos : 0);
      lock_fprintf(stderr,
                   "[jpgdbg] ooo_mcu run=%" PRId64 "+%" PRIu64
                   " suffix=%" PRId64 "+%" PRIu64 " count=%u/%u final=%" PRIu64
                   " valid=%d dc=%.0f@%" PRIu64 "\n",
                   run_start, run_len, suffix_start, suffix_len,
                   jpg_mcu_result.mcu_count, jpg_mcu_result.expected_mcus,
                   jpg_mcu_result.final_byte_pos,
                   jpg_mcu_result.valid ? 1 : 0,
                   jpg_mcu_result.max_dc_discontinuity,
                   jpg_mcu_result.dc_discontinuity_pos);
  }
  if (!require_full_validate
      && !trial_validates && scalpel_state.blocksize > 0
      && !reaches_probe_end
      && trial_frontier + 1 > saved_length + run_len * scalpel_state.blocksize) {
    uint64_t committed_len =
        CEILDIV(trial_frontier + 1, scalpel_state.blocksize)
        * scalpel_state.blocksize;
    uint64_t min_committed_len =
        saved_length
        + (run_len + JPG_REASS_OOO_MIN_SUFFIX_PROBE)
              * scalpel_state.blocksize;

    if (committed_len >= min_committed_len
        && committed_len < blockvector_get_data_length(candidate->b)) {
      commit_validates_to = committed_len - 1;
      reaches_probe_commit = true;
    }
  }

  if (!commit
      && (trial_validates || reaches_probe_end || reaches_probe_commit)) {
    *validates = trial_validates;
    if (trial_validates) {
      *validates_to = trial_validates_to;
    }
    else if (reaches_probe_end) {
      *validates_to = trial_end;
    }
    else {
      *validates_to = commit_validates_to - 1;
    }
    jpg_reassembly_ooo_restore_candidate(candidate, saved_num_blocks,
                                         saved_length);
    return trial_validates || !boundary_out || boundary_out->valid;
  }

  if (trial_validates || reaches_probe_end || reaches_probe_commit) {
    uint64_t committed_blocks;

    if (reaches_probe_end && !trial_validates) {
      trial_validates_to = trial_end;
    }
    else if (reaches_probe_commit) {
      JPGCarveState confirm_state;
      uint64_t confirm_validates_to = 0;
      bool confirm_validates;

      trial_validates_to = commit_validates_to;
      blockvector_set_data_length(candidate->b, trial_validates_to + 1);
      resize_blockvector(candidate->b,
                         CEILDIV(blockvector_get_data_length(candidate->b),
                                 scalpel_state.blocksize));
      if (have_prefix_state) {
        memcpy(&confirm_state, prefix_state, sizeof(confirm_state));
      }
      else {
        memset(&confirm_state, 0, sizeof(confirm_state));
      }
      confirm_validates =
          jpg_reassembly_validate_direct(candidate, &confirm_state,
                                         &confirm_validates_to,
                                         fixed_prefix_blocks);
      if (!confirm_validates) {
        jpg_reassembly_ooo_restore_candidate(candidate, saved_num_blocks,
                                             saved_length);
        return false;
      }
      memcpy(&trial_state, &confirm_state, sizeof(trial_state));
      trial_validates = true;
      trial_validates_to = confirm_validates_to;
    }
    *validates = trial_validates;
    *validates_to = trial_validates_to;
    candidate->best_validates_to = trial_validates_to;
    if (trial_state.valid) {
      if (trial_validates && prefix_state
          && prefix_state->hidden_boundary_recovery) {
        trial_state.hidden_boundary_recovery = false;
        memset(&trial_state.hidden_boundary_progress, 0,
               sizeof(trial_state.hidden_boundary_progress));
      }
      jpg_put_decoder_state(candidate->carvehashkey, &trial_state);
    }
    blockvector_set_data_length(candidate->b, trial_validates_to + 1);
    resize_blockvector(candidate->b,
                       CEILDIV(blockvector_get_data_length(candidate->b),
                               scalpel_state.blocksize));
    committed_blocks = blockvector_get_num_blocks(candidate->b);
    if (committed_blocks > 0) {
      int64_t last_apparent =
          blockvector_get_apparent_blocknumber(candidate->b,
                                               committed_blocks - 1);
      if (last_apparent >= 0) {
        candidate->newblock =
            filemirror_actual_blocknumber(scalpel_state.filemirror,
                                          last_apparent);
      }
    }
    jpg_reassembly_debug_dump("ooo_run_accept", candidate,
                              run_start, trial_validates_to);
    return true;
  }

  jpg_reassembly_ooo_restore_candidate(candidate, saved_num_blocks,
                                       saved_length);
  return false;
}

// Recover two logical runs that both precede the current header run in the
// image. Entropy decoding only rejects implausible first runs; a hypothesis is
// committed only when adding the EOI-bearing second run validates the JPEG.
static inline bool jpg_reassembly_try_preheader_two_run_validation(
    CarveInfo *candidate,
    const JPGCarveState *prefix_state,
    bool *validates,
    uint64_t *validates_to,
    uint32_t fixed_prefix_blocks,
    uint64_t saved_num_blocks,
    uint64_t saved_length,
    int64_t selected_moved_start) {
  int64_t first_apparent;
  int64_t search_start;
  int64_t search_floor;

  if (!candidate || !candidate->b || !prefix_state || !validates
      || !validates_to || !prefix_state->valid
      || prefix_state->is_progressive
      || !prefix_state->huff_checkpoint.valid
      || saved_num_blocks == 0 || scalpel_state.blocksize == 0) {
    return false;
  }

  first_apparent = blockvector_get_apparent_blocknumber(candidate->b, 0);
  if (first_apparent <= 0) {
    return false;
  }
  if (selected_moved_start >= 0) {
    if (selected_moved_start >= first_apparent) {
      return false;
    }
    search_start = selected_moved_start;
    search_floor = selected_moved_start;
  }
  else {
    search_start = first_apparent - 1;
    search_floor =
        first_apparent - JPG_REASS_OOO_PRIORITY_BACKSCAN_BLOCKS;
    if (search_floor < 0) {
      search_floor = 0;
    }
  }

  for (int64_t moved_start = search_start;
       moved_start >= search_floor; moved_start--) {
    uint64_t max_run_len = JPG_REASS_OOO_MAX_RUN;

    if (jpg_reassembly_checkpoint_requested()) {
      jpg_reassembly_ooo_restore_candidate(candidate, saved_num_blocks,
                                           saved_length);
      return false;
    }
    if (!jpg_reassembly_bridge_candidate_plausible(moved_start, false)) {
      continue;
    }
    if ((uint64_t)(first_apparent - moved_start) < max_run_len) {
      max_run_len = (uint64_t)(first_apparent - moved_start);
    }

    for (uint64_t run_len = max_run_len; run_len > 0; run_len--) {
      JpgReassemblyEntropyProbe probe;
      JPGCarveState trial_state;
      uint64_t trial_validates_to = 0;
      uint64_t trial_num_blocks;
      uint64_t trial_length;
      bool trial_validates;

      if (jpg_reassembly_checkpoint_requested()) {
        jpg_reassembly_ooo_restore_candidate(candidate, saved_num_blocks,
                                             saved_length);
        return false;
      }
      if (!jpg_reassembly_ooo_range_available(candidate, moved_start,
                                              run_len, -1, 0)
          || jpg_reassembly_ooo_range_has_zero(moved_start, run_len)) {
        continue;
      }
      memset(&probe, 0, sizeof(probe));
      if (!jpg_reassembly_probe_baseline_entropy(
              candidate, prefix_state, saved_num_blocks, saved_length,
              moved_start, run_len, -1, 0, &probe)
          || !probe.supported || !probe.clean
          || !probe.reaches_probe_end) {
        continue;
      }

      jpg_reassembly_ooo_restore_candidate(candidate, saved_num_blocks,
                                           saved_length);
      jpg_reassembly_ooo_append_range(candidate, moved_start, run_len);
      trial_num_blocks = blockvector_get_num_blocks(candidate->b);
      trial_length = blockvector_get_data_length(candidate->b);
      memcpy(&trial_state, prefix_state, sizeof(trial_state));
      trial_validates = jpg_reassembly_validate_direct(
          candidate, &trial_state, &trial_validates_to,
          fixed_prefix_blocks);
      if (trial_validates) {
        *validates = true;
        *validates_to = trial_validates_to;
        blockvector_set_data_length(candidate->b, trial_validates_to + 1);
        resize_blockvector(candidate->b,
                           CEILDIV(trial_validates_to + 1,
                                   scalpel_state.blocksize));
        candidate->best_validates_to = trial_validates_to;
        jpg_put_decoder_state(candidate->carvehashkey, &trial_state);
        return true;
      }
      if (trial_state.valid && trial_state.huff_checkpoint.valid
          && jpg_reassembly_try_preheader_tail_validation(
                 candidate, &trial_state, validates, validates_to,
                 fixed_prefix_blocks, trial_num_blocks, trial_length,
                 JPG_REASS_OOO_SUFFIX_PROBE)) {
        return true;
      }
      jpg_reassembly_ooo_restore_candidate(candidate, saved_num_blocks,
                                           saved_length);
      if (jpg_reassembly_checkpoint_requested()) {
        return false;
      }
    }
  }

  jpg_reassembly_ooo_restore_candidate(candidate, saved_num_blocks,
                                       saved_length);
  return false;
}

static inline bool jpg_reassembly_try_hidden_rejected_successor(
    CarveInfo *candidate,
    JPGCarveState *prefix_state,
    bool *validates,
    uint64_t *validates_to,
    uint32_t fixed_prefix_blocks,
    uint64_t saved_num_blocks,
    uint64_t saved_length) {
  JPGHiddenBoundaryProgress *progress;
  int64_t successor;
  bool advanced;

  if (!candidate || !candidate->b || !prefix_state || !validates
      || !validates_to || !prefix_state->valid
      || !prefix_state->hidden_boundary_recovery
      || !prefix_state->hidden_rejected_range_valid
      || prefix_state->hidden_rejected_last_actual == INT64_MAX) {
    return false;
  }

  progress = &prefix_state->hidden_boundary_progress;
  if (!progress->active) {
    memset(progress, 0, sizeof(*progress));
    progress->active = true;
    progress->origin_blocks = saved_num_blocks;
    progress->origin_length = saved_length;
  }
  if (progress->rejected_successor_checked
      || progress->origin_blocks != saved_num_blocks
      || progress->origin_length != saved_length) {
    return false;
  }

  successor = jpg_reassembly_apparent_lower_bound(
      prefix_state->hidden_rejected_last_actual + 1);
  if (!jpg_reassembly_ooo_apparent_available(candidate, successor)
      || !jpg_reassembly_bridge_candidate_plausible(successor, false)
      || jpg_reassembly_ooo_range_has_zero(successor, 1)) {
    progress->rejected_successor_checked = true;
    jpg_put_decoder_state(candidate->carvehashkey, prefix_state);
    return false;
  }

  advanced = jpg_reassembly_try_ooo_candidate_run(
      candidate, prefix_state, true, validates, validates_to,
      fixed_prefix_blocks, saved_num_blocks, saved_length,
      successor, 1, -1, 0, false, true, true, NULL);
  if (jpg_reassembly_checkpoint_requested()) {
    if (!advanced) {
      jpg_put_decoder_state(candidate->carvehashkey, prefix_state);
    }
    return advanced;
  }
  if (!advanced) {
    progress->rejected_successor_checked = true;
    jpg_put_decoder_state(candidate->carvehashkey, prefix_state);
  }
  return advanced;
}

static inline bool jpg_reassembly_try_hidden_natural_run(
    CarveInfo *candidate,
    JPGCarveState *prefix_state,
    bool *validates,
    uint64_t *validates_to,
    uint32_t fixed_prefix_blocks,
    uint64_t saved_num_blocks,
    uint64_t saved_length) {
  JPGHiddenBoundaryProgress *progress;
  JpgReassemblyEntropyProbe probe;
  JPGCarveState commit_state;
  int64_t tail_apparent;
  int64_t natural_start;
  int64_t rejected_start = -1;
  int64_t next_header = -1;
  uint64_t rejected_blocks = 0;
  bool probed;

  if (!candidate || !candidate->b || !prefix_state || !validates
      || !validates_to || !prefix_state->valid
      || !prefix_state->hidden_boundary_recovery) {
    return false;
  }
  progress = &prefix_state->hidden_boundary_progress;
  if (!progress->active || progress->natural_probe_complete
      || saved_num_blocks != progress->origin_blocks + 1
      || saved_length <= progress->origin_length) {
    return false;
  }
  tail_apparent = blockvector_get_apparent_blocknumber(
      candidate->b, saved_num_blocks - 1);
  if (tail_apparent < 0) {
    return false;
  }

  if (!progress->natural_scan_active) {
    natural_start = tail_apparent + 1;
    if (!jpg_reassembly_next_header_apparent(
            candidate, natural_start, &next_header)
        || next_header <= natural_start) {
      progress->natural_probe_complete = true;
      jpg_put_decoder_state(candidate->carvehashkey, prefix_state);
      return false;
    }
    progress->natural_scan_active = true;
    progress->natural_start_actual = filemirror_actual_blocknumber(
        scalpel_state.filemirror, natural_start);
    progress->natural_limit_actual = filemirror_actual_blocknumber(
        scalpel_state.filemirror, next_header);
    progress->natural_next_actual = progress->natural_start_actual;
    progress->natural_available = 0;
  }

  int64_t apparent = jpg_reassembly_apparent_lower_bound(
      progress->natural_next_actual);
  while (!progress->natural_scan_complete
         && progress->natural_next_actual < progress->natural_limit_actual) {
    if (apparent <= 0
        || (uint64_t)apparent
               >= filemirror_apparent_blocks(scalpel_state.filemirror)) {
      progress->natural_scan_complete = true;
      break;
    }
    int64_t actual = filemirror_actual_blocknumber(
        scalpel_state.filemirror, apparent);
    int64_t previous_actual = filemirror_actual_blocknumber(
        scalpel_state.filemirror, apparent - 1);

    if (jpg_reassembly_checkpoint_requested()) {
      jpg_put_decoder_state(candidate->carvehashkey, prefix_state);
      return false;
    }
    if (actual != progress->natural_next_actual || previous_actual < 0
        || actual != previous_actual + 1
        || !jpg_reassembly_ooo_apparent_available(candidate, apparent)) {
      progress->natural_scan_complete = true;
      break;
    }
    progress->natural_available++;
    progress->natural_next_actual = actual + 1;
    apparent++;
  }
  if (progress->natural_next_actual >= progress->natural_limit_actual) {
    progress->natural_scan_complete = true;
  }
  if (!progress->natural_scan_complete) {
    jpg_put_decoder_state(candidate->carvehashkey, prefix_state);
    return false;
  }
  natural_start = jpg_reassembly_apparent_lower_bound(
      progress->natural_start_actual);
  int64_t natural_end = jpg_reassembly_apparent_lower_bound(
      progress->natural_limit_actual);
  // A saved physical run must still be present in full before it is probed.
  if (progress->natural_next_actual != progress->natural_limit_actual
      || natural_start >= natural_end
      || filemirror_actual_blocknumber(scalpel_state.filemirror, natural_start)
             != progress->natural_start_actual
      || (uint64_t)(natural_end - natural_start) != progress->natural_available
      || progress->natural_available == 0) {
    progress->natural_probe_complete = true;
    jpg_put_decoder_state(candidate->carvehashkey, prefix_state);
    return false;
  }

  if (prefix_state->hidden_rejected_range_valid
      && prefix_state->hidden_rejected_first_actual >= 0
      && prefix_state->hidden_rejected_last_actual
             >= prefix_state->hidden_rejected_first_actual
      && prefix_state->hidden_rejected_last_actual < INT64_MAX) {
    rejected_start = jpg_reassembly_apparent_lower_bound(
        prefix_state->hidden_rejected_first_actual);
    int64_t rejected_end = jpg_reassembly_apparent_lower_bound(
        prefix_state->hidden_rejected_last_actual + 1);
    rejected_blocks = (uint64_t)(rejected_end - rejected_start);
  }
  if (rejected_blocks > 0) {
    if (!progress->natural_tail_search_initialized) {
      progress->natural_tail_search_initialized = true;
      progress->natural_trial_next = progress->natural_available;
      jpg_put_decoder_state(candidate->carvehashkey, prefix_state);
    }
    while (progress->natural_trial_next > 0) {
      uint64_t run_len = progress->natural_trial_next;

      if (jpg_reassembly_checkpoint_requested()) {
        jpg_put_decoder_state(candidate->carvehashkey, prefix_state);
        return false;
      }
      if (jpg_reassembly_debug_candidate(candidate)
          && (run_len == progress->natural_available
              || (run_len & 63u) == 0)) {
        lock_fprintf(stderr,
                     "[jpgdbg] hidden_tail_trial start=%" PRId64
                     " blocks=%" PRIu64 " suffix=%" PRId64 "+%" PRIu64
                     "\n",
                     natural_start, run_len,
                     rejected_start,
                     rejected_blocks);
      }
      if (jpg_reassembly_try_ooo_candidate_run(
              candidate, prefix_state, true, validates, validates_to,
              fixed_prefix_blocks, saved_num_blocks, saved_length,
              natural_start, run_len,
              rejected_start,
              rejected_blocks, true, false, true, NULL)) {
        return true;
      }
      if (jpg_reassembly_checkpoint_requested()) {
        jpg_put_decoder_state(candidate->carvehashkey, prefix_state);
        return false;
      }
      progress->natural_trial_next--;
      jpg_put_decoder_state(candidate->carvehashkey, prefix_state);
    }
  }

  memset(&probe, 0, sizeof(probe));
  probed = jpg_reassembly_probe_baseline_entropy(
      candidate, prefix_state, saved_num_blocks, saved_length,
      natural_start, progress->natural_available,
      -1, 0, &probe);
  if (jpg_reassembly_checkpoint_requested()) {
    jpg_put_decoder_state(candidate->carvehashkey, prefix_state);
    return false;
  }
  if (!probed || !probe.supported || !probe.clean
      || !probe.reaches_probe_end) {
    progress->natural_probe_complete = true;
    jpg_put_decoder_state(candidate->carvehashkey, prefix_state);
    return false;
  }

  if (jpg_reassembly_debug_candidate(candidate)) {
    lock_fprintf(stderr,
                 "[jpgdbg] hidden_natural_run start=%" PRId64
                 " blocks=%" PRIu64 " frontier=%" PRIu64 "\n",
                 natural_start, progress->natural_available,
                 probe.frontier);
  }
  memcpy(&commit_state, prefix_state, sizeof(commit_state));
  memset(&commit_state.hidden_boundary_progress, 0,
         sizeof(commit_state.hidden_boundary_progress));
  if (commit_state.hidden_boundary_runs_committed < UINT32_MAX) {
    commit_state.hidden_boundary_runs_committed++;
  }
  progress->natural_probe_complete = true;
  jpg_put_decoder_state(candidate->carvehashkey, prefix_state);
  return jpg_reassembly_try_ooo_candidate_run(
      candidate, &commit_state, true, validates, validates_to,
      fixed_prefix_blocks, saved_num_blocks, saved_length,
      natural_start, progress->natural_available,
      -1, 0, false, true, true, NULL);
}

// Return the first apparent position whose physical block is at least actual.
// This also gives a usable continuation when the saved physical block is covered.
static inline int64_t jpg_reassembly_apparent_lower_bound(int64_t actual) {
  int64_t low = 0;
  int64_t high = (int64_t)filemirror_apparent_blocks(scalpel_state.filemirror);

  while (low < high) {
    int64_t middle = low + (high - low) / 2;
    int64_t mapped = filemirror_actual_blocknumber(
        scalpel_state.filemirror, middle);

    if (mapped < actual) {
      low = middle + 1;
    }
    else {
      high = middle;
    }
  }
  return low;
}

static inline bool jpg_reassembly_begin_footer_interval(
    CarveInfo *candidate,
    JPGFooterTailProgress *progress,
    int64_t search_floor_actual,
    int64_t apparent_blocks,
    uint64_t maximum_tail_blocks) {
  SearchSpec *spec;
  int64_t next_footer = -1;
  int64_t floor;

  if (!candidate || !progress || search_floor_actual < 0
      || maximum_tail_blocks == 0) {
    return false;
  }
  floor = jpg_reassembly_apparent_lower_bound(search_floor_actual);
  if (floor >= apparent_blocks
      || !jpg_reassembly_next_footer_apparent(
             candidate, floor, apparent_blocks, &next_footer)) {
    return false;
  }

  if (maximum_tail_blocks < (uint64_t)(next_footer - floor + 1)) {
    floor = next_footer - (int64_t)maximum_tail_blocks + 1;
  }
  spec = &scalpel_state.search_specs[candidate->needleidx];
  for (uint64_t index = 0; index < spec->offsets.numheaders; index++) {
    int64_t actual = (int64_t)(spec->offsets.headers[index]
                               / scalpel_state.blocksize);
    int64_t apparent = filemirror_apparent_blocknumber(
        scalpel_state.filemirror, actual);

    if (apparent >= floor && apparent < next_footer) {
      floor = apparent + 1;
    }
  }
  for (uint64_t index = 0; index < spec->offsets.numfooters; index++) {
    int64_t actual = (int64_t)(spec->offsets.footers[index]
                               / scalpel_state.blocksize);
    int64_t apparent = filemirror_apparent_blocknumber(
        scalpel_state.filemirror, actual);

    if (apparent >= floor && apparent < next_footer) {
      floor = apparent + 1;
    }
  }

  int64_t local_limit = floor;
  if (next_footer - floor >= JPG_FOOTER_TAIL_LOCAL_STARTS) {
    local_limit += JPG_FOOTER_TAIL_LOCAL_STARTS - 1;
  }
  else {
    local_limit = next_footer;
  }
  progress->interval_active = true;
  progress->floor_actual = filemirror_actual_blocknumber(
      scalpel_state.filemirror, floor);
  progress->footer_actual = filemirror_actual_blocknumber(
      scalpel_state.filemirror, next_footer);
  progress->reverse_next_actual = progress->footer_actual;
  progress->local_complete = false;
  progress->local_next_actual = progress->floor_actual;
  progress->local_limit_actual = filemirror_actual_blocknumber(
      scalpel_state.filemirror, local_limit);
  return true;
}

// Try EOI-anchored continuations for the current prefix. Nearby starts precede
// a reverse sweep. Physical cursors survive changes to apparent block positions;
// entropy checks reject mismatches, and complete validation decides acceptance.
static inline bool jpg_reassembly_try_footer_tail(
    CarveInfo *candidate,
    JPGCarveState *prefix_state,
    bool *validates,
    uint64_t *validates_to,
    uint32_t fixed_prefix_blocks,
    uint64_t saved_num_blocks,
    uint64_t saved_length) {
  JPGFooterTailProgress *progress;
  int64_t apparent_blocks;
  int64_t tail_actual;
  uint64_t maximum_tail_blocks;
  uint64_t signature;

  if (!candidate || !candidate->b || !prefix_state || !validates
      || !validates_to || !prefix_state->valid
      || prefix_state->is_progressive
      || !prefix_state->huff_checkpoint.valid
      || scalpel_state.blocksize == 0 || saved_num_blocks == 0
      || saved_num_blocks > blockvector_get_num_blocks(candidate->b)
      || saved_num_blocks > SIZE_MAX / sizeof(int64_t)) {
    return false;
  }

  // A selected first block may still have a physically contiguous fragment
  // to extend. Finish that bounded extension before searching for a tail.
  if (prefix_state->hidden_boundary_recovery
      && prefix_state->hidden_boundary_progress.active
      && !prefix_state->hidden_boundary_progress.natural_probe_complete
      && saved_num_blocks - 1
             == prefix_state->hidden_boundary_progress.origin_blocks
      && saved_length
             > prefix_state->hidden_boundary_progress.origin_length) {
    return false;
  }

  signature = 0;
  for (uint64_t index = 0; index < saved_num_blocks; index++) {
    int64_t actual = blockvector_get_actual_blocknumber(candidate->b, index);

    signature = XXH3_64bits_withSeed(&actual, sizeof(actual), signature);
  }
  progress = &prefix_state->footer_tail_progress;
  if (!progress->active
      || progress->source_blocks != saved_num_blocks
      || progress->source_length != saved_length
      || progress->source_signature != signature) {
    memset(progress, 0, sizeof(*progress));
    progress->active = true;
    progress->source_blocks = saved_num_blocks;
    progress->source_length = saved_length;
    progress->source_signature = signature;
  }
  if (progress->complete) {
    return false;
  }

  tail_actual = blockvector_get_actual_blocknumber(
      candidate->b, saved_num_blocks - 1);
  apparent_blocks = (int64_t)filemirror_apparent_blocks(
      scalpel_state.filemirror);
  SearchSpec *spec = &scalpel_state.search_specs[candidate->needleidx];
  if (tail_actual < 0 || tail_actual == INT64_MAX
      || saved_length >= spec->MAXIMUMSIZE) {
    progress->complete = true;
    jpg_put_decoder_state(candidate->carvehashkey, prefix_state);
    return false;
  }
  maximum_tail_blocks = CEILDIV(
      spec->MAXIMUMSIZE - saved_length, scalpel_state.blocksize);
  if (!progress->interval_active
      && !jpg_reassembly_begin_footer_interval(
             candidate, progress, tail_actual + 1,
             apparent_blocks, maximum_tail_blocks)) {
    progress->complete = true;
    jpg_put_decoder_state(candidate->carvehashkey, prefix_state);
    return false;
  }

  while (!progress->complete) {
    JpgReassemblyEntropyProbe probe;
    int64_t tail_start = -1;
    int64_t trial_actual = -1;
    int64_t footer_apparent = jpg_reassembly_apparent_lower_bound(
        progress->footer_actual);
    uint64_t probe_blocks;
    bool probed;
    bool local_trial = false;

    if (jpg_reassembly_checkpoint_requested()) {
      jpg_put_decoder_state(candidate->carvehashkey, prefix_state);
      return false;
    }
    if (footer_apparent >= apparent_blocks
        || filemirror_actual_blocknumber(scalpel_state.filemirror,
                                          footer_apparent)
               != progress->footer_actual) {
      progress->local_complete = true;
      progress->reverse_next_actual = -1;
    }
    if (!progress->local_complete) {
      tail_start = jpg_reassembly_apparent_lower_bound(
          progress->local_next_actual);
      if (tail_start < apparent_blocks) {
        trial_actual = filemirror_actual_blocknumber(
            scalpel_state.filemirror, tail_start);
      }
      if (trial_actual >= 0 && trial_actual <= progress->local_limit_actual) {
        progress->local_next_actual = trial_actual + 1;
        local_trial = true;
      }
      else {
        progress->local_complete = true;
      }
    }
    if (!local_trial) {
      tail_start = jpg_reassembly_apparent_lower_bound(
          progress->reverse_next_actual);
      if (tail_start == apparent_blocks
          || filemirror_actual_blocknumber(scalpel_state.filemirror,
                                            tail_start)
                 > progress->reverse_next_actual) {
        tail_start--;
      }
      trial_actual = tail_start >= 0
                         ? filemirror_actual_blocknumber(
                               scalpel_state.filemirror, tail_start) : -1;
      if (trial_actual < progress->floor_actual) {
        if (progress->footer_actual < INT64_MAX
            && jpg_reassembly_begin_footer_interval(
                   candidate, progress, progress->footer_actual + 1,
                   apparent_blocks, maximum_tail_blocks)) {
          continue;
        }
        progress->complete = true;
        break;
      }
      progress->reverse_next_actual = trial_actual - 1;
      if (trial_actual <= progress->local_limit_actual) {
        continue;
      }
    }

    if (!jpg_reassembly_ooo_apparent_available(candidate, tail_start)
        || !jpg_reassembly_bridge_candidate_plausible(tail_start, false)
        || jpg_reassembly_ooo_range_has_zero(tail_start, 1)) {
      continue;
    }
    probe_blocks = (uint64_t)(footer_apparent - tail_start + 1);
    if (probe_blocks > JPG_REASSEMBLY_PROBE_MAX_CHAIN) {
      probe_blocks = JPG_REASSEMBLY_PROBE_MAX_CHAIN;
    }
    if (!jpg_reassembly_ooo_range_available(candidate, tail_start,
                                             probe_blocks, -1, 0)
        || jpg_reassembly_ooo_range_has_zero(tail_start, probe_blocks)) {
      continue;
    }

    memset(&probe, 0, sizeof(probe));
    progress->probes++;
    probed = jpg_reassembly_probe_baseline_entropy(
        candidate, prefix_state, saved_num_blocks, saved_length,
        tail_start, probe_blocks, -1, 0, &probe);
    if (!jpg_reassembly_checkpoint_requested()
        && probed && probe.supported && probe.clean
        && probe.reaches_probe_end) {
      progress->full_trials++;
      if (jpg_reassembly_debug_candidate(candidate)) {
        lock_fprintf(stderr,
                     "[jpgdbg] footer_tail actual=%" PRId64
                     " footer_actual=%" PRId64 " full_trial=%" PRIu64 "\n",
                     trial_actual, progress->footer_actual,
                     progress->full_trials);
      }
      if (jpg_reassembly_try_contiguous_tail_validation(
              candidate, validates, validates_to, fixed_prefix_blocks,
              saved_num_blocks, saved_length, tail_start)
          && *validates && !jpg_wrongblock_result.detected) {
        return true;
      }
      jpg_reassembly_ooo_restore_candidate(candidate, saved_num_blocks,
                                           saved_length);
      *validates = false;
    }
    if (jpg_reassembly_checkpoint_requested()) {
      if (local_trial) {
        progress->local_next_actual = trial_actual;
      }
      else {
        progress->reverse_next_actual = trial_actual;
      }
      jpg_put_decoder_state(candidate->carvehashkey, prefix_state);
      return false;
    }
  }

  progress->complete = true;
  jpg_put_decoder_state(candidate->carvehashkey, prefix_state);
  return false;
}

static inline void jpg_reassembly_restore_retry_frame(
    CarveInfo *candidate,
    JpgReassemblyRetryFrame *frame) {
  if (!candidate || !candidate->b || !frame || !frame->apparent_blocks) {
    return;
  }

  resize_blockvector(candidate->b, frame->num_blocks);
  for (uint64_t i = 0; i < frame->num_blocks; i++) {
    blockvector_set_apparent_blocknumber(candidate->b, i,
                                         frame->apparent_blocks[i]);
  }
  blockvector_set_data_length(candidate->b, frame->length);
  inflate_blockvector(candidate->b);
  candidate->best_validates_to = frame->best_validates_to;
  candidate->newblock = frame->newblock;
  candidate->block_choice_start = frame->block_choice_start;
  candidate->chopped = frame->chopped;
  candidate->fastpath = frame->fastpath;
  if (frame->have_prefix_state) {
    jpg_put_decoder_state(candidate->carvehashkey, &frame->prefix_state);
  }
}

static inline bool jpg_reassembly_apply_retry_choice(
    CarveInfo *candidate,
    const JpgReassemblyRetryFrame *frame,
    const JpgOOOBridgeChoice *choice,
    bool *validates,
    uint64_t *validates_to) {
  uint32_t fixed_prefix_blocks;

  if (!candidate || !frame || !choice || !choice->found || !validates
      || !validates_to) {
    return false;
  }
  fixed_prefix_blocks = jpg_reassembly_get_fixed_prefix_blocks(candidate);
  if (choice->full_validates && choice->direct_validates) {
    return jpg_reassembly_try_ooo_candidate_run(
        candidate, &frame->prefix_state, frame->have_prefix_state,
        validates, validates_to, fixed_prefix_blocks,
        frame->num_blocks, frame->length,
        choice->moved_start, choice->run_len, 0, 0,
        true, true, true, NULL);
  }
  if (choice->full_validates) {
    return jpg_reassembly_try_bridge_tail_validation(
        candidate, &frame->prefix_state, frame->have_prefix_state,
        validates, validates_to, fixed_prefix_blocks,
        frame->num_blocks, frame->length,
        choice->moved_start, choice->run_len,
        choice->suffix_start, true, NULL);
  }
  return jpg_reassembly_try_ooo_candidate_run(
      candidate, &frame->prefix_state, frame->have_prefix_state,
      validates, validates_to, fixed_prefix_blocks,
      frame->num_blocks, frame->length,
      choice->moved_start, choice->run_len,
      choice->suffix_start, choice->suffix_len,
      false, true, true, NULL);
}

static inline bool jpg_reassembly_restore_retry(
    CarveInfo *candidate,
    JpgReassemblyRetrySearch *search,
    bool *validates,
    uint64_t *validates_to,
    bool latest_frame_only) {
  if (!candidate || !search || !validates || !validates_to) {
    return false;
  }

  while (search->frame_count > 0
         && search->attempts < JPG_REASS_RETRY_LIMIT) {
    JpgReassemblyRetryFrame *frame;

    if (jpg_reassembly_checkpoint_requested()) {
      return false;
    }

    if (!search->replay_started) {
      uint32_t selected = UINT32_MAX;

      if (latest_frame_only) {
        selected = search->frame_count - 1;
        if (search->frames[selected].next_choice
                >= search->frames[selected].choice_count) {
          selected = UINT32_MAX;
        }
      }
      else {
        for (uint32_t i = 0; i < search->frame_count; i++) {
          if (search->frames[i].next_choice
                  >= search->frames[i].choice_count) {
            continue;
          }
          if (search->frames[i].retry_priority < 0.0) {
            selected = i;
            break;
          }
          if (selected == UINT32_MAX
              || search->frames[i].retry_priority
                     < search->frames[selected].retry_priority) {
            selected = i;
          }
        }
      }
      if (selected == UINT32_MAX) {
        break;
      }
      for (uint32_t i = selected + 1; i < search->frame_count; i++) {
        jpg_reassembly_clear_retry_frame(&search->frames[i]);
      }
      search->frame_count = selected + 1;
    }
    frame = &search->frames[search->frame_count - 1];

    while (frame->next_choice < frame->choice_count
           && search->attempts < JPG_REASS_RETRY_LIMIT) {
      if (jpg_reassembly_checkpoint_requested()) {
        return false;
      }
      JpgOOOBridgeChoice choice = frame->choices[frame->next_choice];

      if (jpg_reassembly_debug_candidate(candidate)) {
        lock_fprintf(stderr,
                     "[jpgdbg] retry_try attempt=%" PRIu32
                     " frame=%" PRIu32 " choice=%" PRIu32 "/%" PRIu32
                     " blocks=%" PRIu64 " moved=%" PRId64 "+%" PRIu64
                     " suffix=%" PRId64 "+%" PRIu64
                     " score=%.3f dc=%.0f\n",
                     search->attempts + 1, search->frame_count,
                     frame->next_choice + 1, frame->choice_count,
                     frame->num_blocks, choice.moved_start, choice.run_len,
                     choice.suffix_start, choice.suffix_len,
                     jpg_reassembly_retry_choice_score(&choice),
                     choice.max_dc_discontinuity);
      }
      jpg_reassembly_restore_retry_frame(candidate, frame);
      const bool accepted = jpg_reassembly_apply_retry_choice(
          candidate, frame, &choice, validates, validates_to);
      if (!accepted && jpg_reassembly_checkpoint_requested()) {
        return false;
      }
      frame->next_choice++;
      search->attempts++;
      if (accepted) {
        search->replay_started = true;
        jpg_reassembly_debug_dump("bridge_retry_accept", candidate,
                                  choice.moved_start, *validates_to);
        return true;
      }
    }

    jpg_reassembly_clear_retry_frame(frame);
    search->frame_count--;
    if (latest_frame_only) {
      return false;
    }
  }
  return false;
}

static inline bool jpg_reassembly_progressive_entropy_score(
    CarveInfo *candidate,
    uint64_t saved_num_blocks,
    uint64_t saved_length,
    int64_t moved_start,
    uint64_t run_len,
    int64_t suffix_start,
    uint64_t suffix_len,
    bool *supported,
    bool *completed_scan,
    double *score) {
  char *prefix_data;
  char *trial_data;
  uint64_t prefix_length = 0;
  uint64_t trial_length = 0;
  JpgValidationContext prefix_context;
  JpgValidationContext trial_context;
  JpgProgressiveEntropyEvidence prefix_evidence;
  JpgProgressiveEntropyEvidence trial_evidence;
  JpgValidationResult prefix_result;
  JpgValidationResult trial_result;
  bool valid = true;

  if (supported) {
    *supported = false;
  }
  if (completed_scan) {
    *completed_scan = false;
  }
  if (score) {
    *score = 1.0e9;
  }
  if (!candidate || !candidate->b || !supported || !completed_scan || !score
      || moved_start < 0 || run_len == 0) {
    return false;
  }

  jpg_reassembly_ooo_restore_candidate(candidate, saved_num_blocks,
                                       saved_length);
  prefix_data = jpg_reassembly_materialize_candidate(candidate,
                                                      &prefix_length);
  memset(&prefix_context, 0, sizeof(prefix_context));
  prefix_context.data = (const uint8_t *)prefix_data;
  prefix_context.length = prefix_length;
  prefix_result = jpg_validate_structure(&prefix_context);
  if (jpg_reassembly_debug_candidate(candidate)) {
    lock_fprintf(stderr,
                 "[jpgdbg] progressive_entropy_prefix result=%d"
                 " scans=%u scan=%" PRIu64 "/%" PRIu64
                 " entropy=%" PRIu64 " ss=%u se=%u ah=%u al=%u\n",
                 prefix_result, prefix_context.scan_count,
                 prefix_context.scan_start,
                 prefix_context.scan_entropy_start,
                 prefix_context.entropy_bytes,
                 prefix_context.ss, prefix_context.se,
                 prefix_context.ah, prefix_context.al);
  }
  if (prefix_result != JPG_VAL_TRUNCATED || !prefix_context.is_progressive
      || prefix_context.scan_entropy_start == 0) {
    goto progressive_score_done;
  }
  {
    bool prefix_entropy_valid = jpg_progressive_entropy_scan_evidence(
        &prefix_context, prefix_context.entropy_bytes, &prefix_evidence);

    if (!prefix_evidence.supported) {
      goto progressive_score_done;
    }
    *supported = true;
    if (!prefix_entropy_valid || !prefix_evidence.valid) {
      valid = false;
    }
  }
  if (!valid) {
    if (jpg_reassembly_debug_candidate(candidate)) {
      lock_fprintf(stderr,
                   "[jpgdbg] progressive_entropy_prefix_evidence"
                   " supported=%d valid=%d complete=%d units=%" PRIu64
                   "/%" PRIu64 " bytes=%" PRIu64
                   " refine_failure=%u@%" PRIu64 "\n",
                   prefix_evidence.supported ? 1 : 0,
                   prefix_evidence.valid ? 1 : 0,
                   prefix_evidence.complete ? 1 : 0,
                   prefix_evidence.units, prefix_evidence.expected_units,
                   prefix_evidence.entropy_bytes,
                   jpg_progressive_refinement_failure,
                   jpg_progressive_refinement_failure_byte);
    }
    goto progressive_score_done;
  }

  jpg_reassembly_ooo_append_range(candidate, moved_start, run_len);
  if (suffix_len > 0) {
    jpg_reassembly_ooo_append_range(candidate, suffix_start, suffix_len);
  }
  trial_data = jpg_reassembly_materialize_candidate(candidate, &trial_length);
  memset(&trial_context, 0, sizeof(trial_context));
  trial_context.data = (const uint8_t *)trial_data;
  trial_context.length = trial_length;
  trial_result = jpg_validate_structure(&trial_context);
  if (jpg_reassembly_debug_candidate(candidate)) {
    lock_fprintf(stderr,
                 "[jpgdbg] progressive_entropy_trial result=%d"
                 " scans=%u scan=%" PRIu64 "/%" PRIu64
                 " entropy=%" PRIu64 " ss=%u se=%u ah=%u al=%u\n",
                 trial_result, trial_context.scan_count,
                 trial_context.scan_start,
                 trial_context.scan_entropy_start,
                 trial_context.entropy_bytes,
                 trial_context.ss, trial_context.se,
                 trial_context.ah, trial_context.al);
  }
  if (trial_result != JPG_VAL_TRUNCATED && trial_result != JPG_VAL_OK) {
    *supported = true;
    valid = false;
    goto progressive_score_done;
  }

  if (trial_context.scan_count == prefix_context.scan_count
      && trial_context.scan_entropy_start
             == prefix_context.scan_entropy_start
      && trial_context.ss == prefix_context.ss
      && trial_context.se == prefix_context.se
      && trial_context.ah == prefix_context.ah
      && trial_context.al == prefix_context.al) {
    double prior_bytes_per_unit;
    double extension_bytes_per_unit;
    uint64_t added_bytes;
    uint64_t added_units;

    bool trial_entropy_valid = jpg_progressive_entropy_scan_evidence(
        &trial_context, trial_context.entropy_bytes, &trial_evidence);

    if (jpg_reassembly_debug_candidate(candidate)) {
      lock_fprintf(stderr,
                   "[jpgdbg] progressive_entropy_trial_evidence"
                   " supported=%d valid=%d complete=%d units=%" PRIu64
                   "/%" PRIu64 " bytes=%" PRIu64
                   " refine_failure=%u@%" PRIu64 "\n",
                   trial_evidence.supported ? 1 : 0,
                   trial_evidence.valid ? 1 : 0,
                   trial_evidence.complete ? 1 : 0,
                   trial_evidence.units, trial_evidence.expected_units,
                   trial_evidence.entropy_bytes,
                   jpg_progressive_refinement_failure,
                   jpg_progressive_refinement_failure_byte);
    }

    if (!trial_evidence.supported) {
      goto progressive_score_done;
    }
    *supported = true;
    if (!trial_entropy_valid || !trial_evidence.valid
        || trial_evidence.units < prefix_evidence.units
        || trial_evidence.entropy_bytes < prefix_evidence.entropy_bytes) {
      valid = false;
      goto progressive_score_done;
    }
    added_units = trial_evidence.units - prefix_evidence.units;
    added_bytes = trial_evidence.entropy_bytes
                  - prefix_evidence.entropy_bytes;
    if (prefix_evidence.units == 0 || added_units == 0 || added_bytes == 0) {
      goto progressive_score_done;
    }
    prior_bytes_per_unit =
        (double)prefix_evidence.entropy_bytes / prefix_evidence.units;
    extension_bytes_per_unit = (double)added_bytes / added_units;
    *score = fabs(extension_bytes_per_unit - prior_bytes_per_unit)
             / (prior_bytes_per_unit > 0.0 ? prior_bytes_per_unit : 1.0);
    *completed_scan = trial_evidence.complete;
  }
  else if (trial_context.scan_count > prefix_context.scan_count) {
    JpgValidationContext completed_context = prefix_context;
    JpgProgressiveEntropyEvidence completed_evidence;
    bool completed_entropy_valid;
    uint64_t marker = jpg_progressive_next_entropy_marker(
        (const uint8_t *)trial_data, prefix_context.scan_entropy_start,
        trial_length);

    completed_context.data = (const uint8_t *)trial_data;
    completed_context.length = marker;
    if (marker >= trial_length) {
      goto progressive_score_done;
    }
    completed_entropy_valid = jpg_progressive_entropy_scan_evidence(
        &completed_context, marker, &completed_evidence);
    if (!completed_evidence.supported) {
      goto progressive_score_done;
    }
    *supported = true;
    if (!completed_entropy_valid || !completed_evidence.valid
        || !completed_evidence.complete) {
      valid = false;
      goto progressive_score_done;
    }
    *completed_scan = true;
    *score = 0.0;
  }

progressive_score_done:
  jpg_reassembly_ooo_restore_candidate(candidate, saved_num_blocks,
                                       saved_length);
  return valid;
}

static inline bool jpg_reassembly_progressive_clean_probe_end(
    uint64_t probe_length) {
  bool exact_position = jpg_cd.errpos == (long)probe_length;
  bool synthetic_eoi_position =
      jpg_cd.jpeg_error == JWRN_HIT_MARKER
      && jpg_cd.errpos >= 0
      && (uint64_t)jpg_cd.errpos + 2 == probe_length;

  return (jpg_cd.jpeg_error == JERR_INPUT_EOF
          || jpg_cd.jpeg_error == JWRN_JPEG_EOF
          || jpg_cd.jpeg_error == JWRN_HIT_MARKER)
         && (exact_position || synthetic_eoi_position)
         && jpg_cd.swallowed_error_count == 0;
}

static inline bool jpg_reassembly_evaluate_progressive_bridge(
    CarveInfo *candidate,
    const JPGCarveState *prefix_state,
    bool have_prefix_state,
    uint32_t fixed_prefix_blocks,
    uint64_t saved_num_blocks,
    uint64_t saved_length,
    int64_t moved_start,
    uint64_t run_len,
    int64_t suffix_start,
    uint64_t suffix_len,
    bool tail_has_zero_before_footer,
    JpgOOOBridgeChoice *choice) {
  int64_t moved_actual;
  bool probe_validates = false;
  uint64_t probe_validates_to = 0;
  uint64_t selected_suffix_len = suffix_len;
  bool direct_validates = false;
  bool full_validates;
  bool entropy_supported = false;
  bool entropy_completed_scan = false;
  bool entropy_valid;
  bool moved_has_eoi;
  bool clean_probe_end = false;
  int64_t saved_prefix_tail = -1;
  double entropy_score = 1.0e9;
  JpgBoundaryScore boundary;
  JpgBoundaryScore suffix_boundary;

  if (!candidate || !prefix_state || !have_prefix_state || !choice
      || run_len == 0) {
    return false;
  }
  if (saved_num_blocks > 0) {
    saved_prefix_tail = blockvector_get_apparent_blocknumber(
        candidate->b, saved_num_blocks - 1);
  }
  moved_actual = filemirror_actual_blocknumber(scalpel_state.filemirror,
                                               moved_start);
  if (!jpg_reassembly_bridge_candidate_plausible(moved_start, true)) {
    return false;
  }

  memset(&boundary, 0, sizeof(boundary));
  memset(&suffix_boundary, 0, sizeof(suffix_boundary));
  moved_has_eoi = jpg_reassembly_ooo_range_has_eoi(moved_start, run_len);
  if (moved_has_eoi
      && jpg_reassembly_try_ooo_candidate_run(
             candidate, prefix_state, have_prefix_state,
             &probe_validates, &probe_validates_to, fixed_prefix_blocks,
             saved_num_blocks, saved_length, moved_start, run_len, 0, 0,
             true, true, false, &boundary)) {
    direct_validates = probe_validates;
  }
  if (moved_has_eoi && !direct_validates) {
    return false;
  }
  full_validates = direct_validates;
  if (!full_validates && suffix_len > 0
      && !tail_has_zero_before_footer) {
    full_validates = jpg_reassembly_try_bridge_tail_validation(
        candidate, prefix_state, have_prefix_state,
        &probe_validates, &probe_validates_to,
        fixed_prefix_blocks, saved_num_blocks, saved_length,
        moved_start, run_len, suffix_start, false, &boundary);
  }
  if (!full_validates) {
    uint64_t probe_length =
        saved_length + (run_len + suffix_len) * scalpel_state.blocksize;

    if (suffix_len > 0
        && jpg_reassembly_try_ooo_candidate_run(
               candidate, prefix_state, have_prefix_state,
               &probe_validates, &probe_validates_to, fixed_prefix_blocks,
               saved_num_blocks, saved_length, moved_start, run_len,
               suffix_start, suffix_len, false, true, false, NULL)) {
      clean_probe_end = jpg_reassembly_progressive_clean_probe_end(
          probe_length);
    }
    if (suffix_len == 0 || !clean_probe_end) {
      selected_suffix_len = 0;
      probe_length = saved_length + run_len * scalpel_state.blocksize;
      if (!jpg_reassembly_try_ooo_candidate_run(
              candidate, prefix_state, have_prefix_state,
              &probe_validates, &probe_validates_to, fixed_prefix_blocks,
              saved_num_blocks, saved_length, moved_start, run_len,
              0, 0, false, true, false, NULL)) {
        return false;
      }
      clean_probe_end = jpg_reassembly_progressive_clean_probe_end(
          probe_length);
    }
    if (!clean_probe_end) {
      // coefficient extraction is expensive, so use it for an ambiguous probe
      // only when testing the physical continuation of the current fragment.
      if (jpg_reassembly_debug_candidate(candidate)) {
        lock_fprintf(stderr,
                     "[jpgdbg] progressive_ambiguous moved=%" PRId64
                     " prefix_tail=%" PRId64 " blocks=%" PRIu64 "\n",
                     moved_start, saved_prefix_tail, saved_num_blocks);
      }
      if (saved_prefix_tail < 0 || moved_start != saved_prefix_tail + 1) {
        return false;
      }
    }
  }
  entropy_valid = jpg_reassembly_progressive_entropy_score(
      candidate, saved_num_blocks, saved_length,
      moved_start, run_len,
      selected_suffix_len > 0 ? suffix_start : 0,
      selected_suffix_len, &entropy_supported,
      &entropy_completed_scan, &entropy_score);
  if ((!entropy_valid && entropy_supported)
      || (!entropy_valid && !direct_validates && !full_validates)) {
    return false;
  }
  if (!direct_validates && !full_validates && !clean_probe_end
      && !entropy_supported) {
    return false;
  }
  if (!full_validates
      && !jpg_reassembly_try_ooo_candidate_run(
             candidate, prefix_state, have_prefix_state,
             &probe_validates, &probe_validates_to, fixed_prefix_blocks,
             saved_num_blocks, saved_length, moved_start, run_len,
             selected_suffix_len > 0 ? suffix_start : 0,
             selected_suffix_len, false, true, false, &boundary)
      && (saved_prefix_tail < 0 || moved_start != saved_prefix_tail + 1)) {
    return false;
  }

  if (selected_suffix_len > 0) {
    uint64_t materialized_length = 0;
    uint64_t bridge_end =
        saved_length + run_len * scalpel_state.blocksize;
    char *materialized;

    jpg_reassembly_ooo_restore_candidate(candidate, saved_num_blocks,
                                         saved_length);
    jpg_reassembly_ooo_append_range(candidate, moved_start, run_len);
    jpg_reassembly_ooo_append_range(candidate, suffix_start,
                                    selected_suffix_len);
    materialized = jpg_reassembly_materialize_candidate(
        candidate, &materialized_length);
    if (bridge_end < materialized_length) {
      suffix_boundary = jpg_boundary_score(
          materialized, bridge_end, materialized_length);
    }
    jpg_reassembly_ooo_restore_candidate(candidate, saved_num_blocks,
                                         saved_length);
  }

  memset(choice, 0, sizeof(*choice));
  choice->found = true;
  choice->full_validates = full_validates;
  choice->direct_validates = direct_validates;
  choice->progressive_entropy_supported = entropy_supported;
  choice->progressive_entropy_complete = entropy_completed_scan;
  choice->progressive_entropy_contiguous =
      entropy_supported && saved_prefix_tail >= 0
      && moved_start == saved_prefix_tail + 1
      && entropy_score < 1.0e9;
  choice->moved_start = moved_start;
  choice->run_len = run_len;
  choice->suffix_start = suffix_start;
  choice->suffix_len = full_validates ? 0 : selected_suffix_len;
  choice->progressive_entropy_score = entropy_score;
  choice->boundary = boundary;
  choice->suffix_boundary = suffix_boundary;
  if (jpg_reassembly_debug_candidate(candidate)) {
    lock_fprintf(stderr,
                 "[jpgdbg] progressive_bridge run=%" PRId64 "+%" PRIu64
                 " actual=%" PRId64 " full=%d direct=%d entropy=%d/%d"
                 " rate=%.6f norm=%.3f\n",
                 moved_start, run_len, moved_actual,
                 full_validates ? 1 : 0, direct_validates ? 1 : 0,
                 entropy_supported ? 1 : 0,
                 entropy_completed_scan ? 1 : 0, entropy_score,
                 boundary.normalized);
    if (choice->suffix_boundary.valid) {
      lock_fprintf(stderr,
                   "[jpgdbg] progressive_bridge_exit run=%" PRId64 "+%" PRIu64
                   " suffix=%" PRId64 "+%" PRIu64 " row=%u"
                   " seam=%.3f base=%.3f norm=%.3f\n",
                   moved_start, run_len, suffix_start,
                   selected_suffix_len,
                   choice->suffix_boundary.boundary_row,
                   choice->suffix_boundary.seam_mad,
                   choice->suffix_boundary.baseline_mad,
                   choice->suffix_boundary.normalized);
    }
  }
  return true;
}

static inline bool jpg_reassembly_evaluate_baseline_bridge(
    CarveInfo *candidate,
    const JPGCarveState *prefix_state,
    bool have_prefix_state,
    uint32_t fixed_prefix_blocks,
    uint64_t saved_num_blocks,
    uint64_t saved_length,
    int64_t moved_start,
    uint64_t run_len,
    int64_t suffix_start,
    uint64_t suffix_len,
    JpgOOOBridgeChoice *choice) {
  int64_t moved_actual;
  bool probe_validates = false;
  bool tail_validates = false;
  bool direct_validates;
  bool full_validates;
  bool huffman_available;
  bool huffman_support;
  bool suffix_huffman_support;
  bool baseline_rate_supported = false;
  uint64_t probe_validates_to = 0;
  uint64_t tail_validates_to = 0;
  uint64_t supported_suffix_len = 0;
  double baseline_rate_deviation = 0.0;
  JpgBoundaryScore boundary;
  JpgBoundaryScore suffix_boundary;
  JpgMcuValidationResult mcu_evidence;
  JpgReassemblyEntropyProbe entropy_probe;
  int64_t saved_prefix_tail = -1;

  if (!candidate || !prefix_state || !choice || run_len == 0
      || (have_prefix_state && prefix_state->is_progressive)) {
    return false;
  }
  if (saved_num_blocks > 0) {
    saved_prefix_tail = blockvector_get_apparent_blocknumber(
        candidate->b, saved_num_blocks - 1);
  }
  moved_actual = filemirror_actual_blocknumber(scalpel_state.filemirror,
                                               moved_start);
  if (!jpg_reassembly_bridge_candidate_plausible(moved_start, false)) {
    return false;
  }

  memset(&boundary, 0, sizeof(boundary));
  memset(&suffix_boundary, 0, sizeof(suffix_boundary));
  memset(&mcu_evidence, 0, sizeof(mcu_evidence));
  memset(&entropy_probe, 0, sizeof(entropy_probe));
  if (jpg_reassembly_probe_baseline_entropy(
          candidate, prefix_state, saved_num_blocks, saved_length,
          moved_start, run_len, 0, 0, &entropy_probe)
      && entropy_probe.supported) {
    if (jpg_reassembly_debug_candidate(candidate)) {
      lock_fprintf(stderr,
                   "[jpgdbg] baseline_entropy run=%" PRId64 "+%" PRIu64
                   " clean=%d reaches=%d failure=%d frontier=%" PRIu64
                   " mcu=%u/%u final=%" PRIu64 " dc=%.0f@%" PRIu64 "\n",
                   moved_start, run_len, entropy_probe.clean ? 1 : 0,
                   entropy_probe.reaches_probe_end ? 1 : 0,
                   entropy_probe.failure, entropy_probe.frontier,
                   entropy_probe.mcu.mcu_count,
                   entropy_probe.mcu.expected_mcus,
                   entropy_probe.mcu.final_byte_pos,
                   entropy_probe.mcu.max_dc_discontinuity,
                   entropy_probe.mcu.dc_discontinuity_pos);
    }
    if ((!entropy_probe.clean || !entropy_probe.reaches_probe_end)
        && jpg_huffman_failure_is_hard(entropy_probe.failure)) {
      return false;
    }
    if (entropy_probe.clean && entropy_probe.reaches_probe_end
        && prefix_state->huff_checkpoint.valid
        && prefix_state->huff_checkpoint.mcu_count > 0
        && prefix_state->huff_checkpoint.byte_pos
               > prefix_state->entropy_start
        && entropy_probe.mcu.mcu_count
               > prefix_state->huff_checkpoint.mcu_count
        && entropy_probe.mcu.final_byte_pos
               > prefix_state->huff_checkpoint.byte_pos) {
      double prefix_rate =
          (double)(prefix_state->huff_checkpoint.byte_pos
                   - prefix_state->entropy_start)
          / prefix_state->huff_checkpoint.mcu_count;
      double extension_rate =
          (double)(entropy_probe.mcu.final_byte_pos
                   - prefix_state->huff_checkpoint.byte_pos)
          / (entropy_probe.mcu.mcu_count
             - prefix_state->huff_checkpoint.mcu_count);

      if (prefix_rate > 0.0) {
        baseline_rate_supported = true;
        baseline_rate_deviation =
            fabs(extension_rate - prefix_rate) / prefix_rate;
      }
    }
  }
  if (!jpg_reassembly_try_ooo_candidate_run(
          candidate, prefix_state, have_prefix_state,
          &probe_validates, &probe_validates_to, fixed_prefix_blocks,
          saved_num_blocks, saved_length, moved_start, run_len, 0, 0,
          false, true, false, &boundary)
      && !(entropy_probe.supported && entropy_probe.clean
           && entropy_probe.reaches_probe_end)) {
    return false;
  }
  memcpy(&mcu_evidence, &jpg_mcu_result, sizeof(mcu_evidence));
  direct_validates = probe_validates;
  if (jpg_reassembly_ooo_range_has_eoi(moved_start, run_len)
      && !direct_validates) {
    return false;
  }

  full_validates = direct_validates;
  if (!full_validates) {
    full_validates = jpg_reassembly_try_bridge_tail_validation(
        candidate, prefix_state, have_prefix_state,
        &tail_validates, &tail_validates_to, fixed_prefix_blocks,
        saved_num_blocks, saved_length, moved_start, run_len,
        suffix_start, false, NULL);
  }
  if (!direct_validates) {
    for (uint64_t probe_suffix_len = 1;
         probe_suffix_len <= suffix_len;
         probe_suffix_len++) {
      probe_validates = false;
      probe_validates_to = 0;
      if (!jpg_reassembly_try_ooo_candidate_run(
              candidate, prefix_state, have_prefix_state,
              &probe_validates, &probe_validates_to, fixed_prefix_blocks,
              saved_num_blocks, saved_length, moved_start, run_len,
              suffix_start, probe_suffix_len, false, true, false, NULL)) {
        break;
      }
      if (probe_validates_to + 1
          <= saved_length + run_len * scalpel_state.blocksize) {
        break;
      }
      supported_suffix_len =
          (probe_validates_to + 1 - saved_length
           - run_len * scalpel_state.blocksize)
          / scalpel_state.blocksize;
      if (supported_suffix_len > probe_suffix_len) {
        supported_suffix_len = probe_suffix_len;
      }
      memcpy(&mcu_evidence, &jpg_mcu_result, sizeof(mcu_evidence));
      if (probe_validates || supported_suffix_len < probe_suffix_len) {
        break;
      }
    }
  }

  suffix_huffman_support = jpg_reassembly_mcu_reaches_probe(
      &mcu_evidence,
      probe_validates
          ? probe_validates_to + 1
          : saved_length
                + (run_len + supported_suffix_len)
                      * scalpel_state.blocksize);
  huffman_available = entropy_probe.supported
                      || mcu_evidence.expected_mcus > 0;
  huffman_support = entropy_probe.supported
                        ? entropy_probe.clean
                              && entropy_probe.reaches_probe_end
                        : suffix_huffman_support;
  if (!baseline_rate_supported && suffix_huffman_support
      && supported_suffix_len >= JPG_REASS_OOO_MIN_SUFFIX_PROBE
      && prefix_state->huff_checkpoint.valid
      && prefix_state->huff_checkpoint.mcu_count > 0
      && prefix_state->huff_checkpoint.byte_pos > prefix_state->entropy_start
      && mcu_evidence.mcu_count
             > prefix_state->huff_checkpoint.mcu_count
      && mcu_evidence.final_byte_pos
             > prefix_state->huff_checkpoint.byte_pos) {
    double prefix_rate =
        (double)(prefix_state->huff_checkpoint.byte_pos
                 - prefix_state->entropy_start)
        / prefix_state->huff_checkpoint.mcu_count;
    double extension_rate =
        (double)(mcu_evidence.final_byte_pos
                 - prefix_state->huff_checkpoint.byte_pos)
        / (mcu_evidence.mcu_count
           - prefix_state->huff_checkpoint.mcu_count);

    if (prefix_rate > 0.0) {
      baseline_rate_supported = true;
      baseline_rate_deviation =
          fabs(extension_rate - prefix_rate) / prefix_rate;
    }
  }

  if (supported_suffix_len > 0) {
    uint64_t materialized_length = 0;
    uint64_t bridge_end =
        saved_length + run_len * scalpel_state.blocksize;
    char *materialized;

    jpg_reassembly_ooo_restore_candidate(candidate, saved_num_blocks,
                                         saved_length);
    jpg_reassembly_ooo_append_range(candidate, moved_start, run_len);
    jpg_reassembly_ooo_append_range(candidate, suffix_start,
                                    supported_suffix_len);
    materialized = jpg_reassembly_materialize_candidate(
        candidate, &materialized_length);
    if (scalpel_state.blocksize < JPG_REASS_BASELINE_SEED_PROBE_BYTES
        && saved_length < materialized_length) {
      boundary = jpg_boundary_score(materialized, saved_length,
                                    materialized_length);
    }
    if (bridge_end < materialized_length) {
      suffix_boundary = jpg_boundary_score(
          materialized, bridge_end, materialized_length);
    }
    jpg_reassembly_ooo_restore_candidate(candidate, saved_num_blocks,
                                         saved_length);
  }

  memset(choice, 0, sizeof(*choice));
  choice->found = true;
  choice->full_validates = full_validates;
  choice->direct_validates = direct_validates;
  choice->huffman_available = huffman_available;
  choice->huffman_support = huffman_support;
  choice->baseline_rate_supported = baseline_rate_supported;
  choice->dc_discontinuity_supported = entropy_probe.supported;
  choice->apparent_continuation =
      saved_prefix_tail >= 0 && moved_start == saved_prefix_tail + 1;
  choice->moved_start = moved_start;
  choice->run_len = run_len;
  choice->suffix_start = suffix_start;
  choice->suffix_len = supported_suffix_len;
  choice->baseline_rate_deviation = baseline_rate_deviation;
  choice->max_dc_discontinuity =
      entropy_probe.mcu.max_dc_discontinuity;
  choice->boundary = boundary;
  choice->suffix_boundary = suffix_boundary;
  if (jpg_reassembly_debug_candidate(candidate)) {
    lock_fprintf(stderr,
                 "[jpgdbg] baseline_bridge run=%" PRId64 "+%" PRIu64
                 " actual=%" PRId64 " full=%d direct=%d huffman=%d/%d"
                 " suffix=%" PRIu64 " rate=%d/%.6f norm=%.3f\n",
                 moved_start, run_len, moved_actual,
                 full_validates ? 1 : 0, direct_validates ? 1 : 0,
                 huffman_available ? 1 : 0, huffman_support ? 1 : 0,
                 supported_suffix_len, baseline_rate_supported ? 1 : 0,
                 baseline_rate_deviation, boundary.normalized);
    if (choice->suffix_boundary.valid) {
      lock_fprintf(stderr,
                   "[jpgdbg] baseline_bridge_exit run=%" PRId64 "+%" PRIu64
                   " suffix=%" PRId64 "+%" PRIu64 " row=%u"
                   " seam=%.3f base=%.3f norm=%.3f\n",
                   moved_start, run_len, suffix_start,
                   supported_suffix_len,
                   choice->suffix_boundary.boundary_row,
                   choice->suffix_boundary.seam_mad,
                   choice->suffix_boundary.baseline_mad,
                   choice->suffix_boundary.normalized);
    }
  }
  return true;
}

static inline bool jpg_reassembly_evaluate_baseline_scatter_block(
    CarveInfo *candidate,
    const JPGCarveState *prefix_state,
    uint32_t fixed_prefix_blocks,
    uint64_t saved_num_blocks,
    uint64_t saved_length,
    int64_t moved_start,
    bool measure_boundary,
    JpgOOOBridgeChoice *choice) {
  JpgReassemblyEntropyProbe entropy_probe;
  JpgBoundaryScore boundary;
  uint64_t materialized_length = 0;
  uint64_t probe_blocks;
  char *materialized;
  bool baseline_rate_supported = false;
  bool entropy_available;
  double baseline_rate_deviation = 0.0;
  double entropy_profile_deviation = 0.0;

  if (!candidate || !prefix_state || !prefix_state->valid || !choice
      || prefix_state->is_progressive || scalpel_state.blocksize == 0
      || !jpg_reassembly_bridge_candidate_plausible(moved_start, false)
      || jpg_reassembly_ooo_range_has_zero(moved_start, 1)) {
    return false;
  }

  // an EOI-bearing block still requires the full validation path.
  if (jpg_reassembly_ooo_range_has_eoi(moved_start, 1)) {
    return jpg_reassembly_evaluate_baseline_bridge(
        candidate, prefix_state, true, fixed_prefix_blocks,
        saved_num_blocks, saved_length, moved_start, 1, -1, 0, choice);
  }

  probe_blocks = CEILDIV(JPG_REASS_BASELINE_SCATTER_PROBE_BYTES,
                         scalpel_state.blocksize);
  if (probe_blocks == 0) {
    probe_blocks = 1;
  }
  while (probe_blocks > 1
         && (!jpg_reassembly_ooo_range_available(
                  candidate, moved_start, probe_blocks, -1, 0)
             || jpg_reassembly_ooo_range_has_zero(
                    moved_start, probe_blocks))) {
    probe_blocks--;
  }

  memset(&entropy_probe, 0, sizeof(entropy_probe));
  entropy_available = jpg_reassembly_probe_baseline_entropy(
      candidate, prefix_state, saved_num_blocks, saved_length,
      moved_start, probe_blocks, -1, 0, &entropy_probe);
  if (!entropy_available || !entropy_probe.supported || !entropy_probe.clean
      || !entropy_probe.reaches_probe_end) {
    if (jpg_reassembly_debug_candidate(candidate)) {
      lock_fprintf(stderr,
                   "[jpgdbg] baseline_scatter_reject run=%" PRId64
                   "+1 available=%d supported=%d clean=%d reaches=%d"
                   " failure=%d frontier=%" PRIu64 " final=%" PRIu64 "\n",
                   moved_start, entropy_available ? 1 : 0,
                   entropy_probe.supported ? 1 : 0,
                   entropy_probe.clean ? 1 : 0,
                   entropy_probe.reaches_probe_end ? 1 : 0,
                   entropy_probe.failure, entropy_probe.frontier,
                   entropy_probe.mcu.final_byte_pos);
    }
    return false;
  }

  if (prefix_state->huff_checkpoint.valid
      && prefix_state->huff_checkpoint.mcu_count > 0
      && prefix_state->huff_checkpoint.byte_pos > prefix_state->entropy_start
      && entropy_probe.mcu.mcu_count
             > prefix_state->huff_checkpoint.mcu_count
      && entropy_probe.mcu.final_byte_pos
             > prefix_state->huff_checkpoint.byte_pos) {
    double prefix_rate =
        (double)(prefix_state->huff_checkpoint.byte_pos
                 - prefix_state->entropy_start)
        / prefix_state->huff_checkpoint.mcu_count;
    double extension_rate =
        (double)(entropy_probe.mcu.final_byte_pos
                 - prefix_state->huff_checkpoint.byte_pos)
        / (entropy_probe.mcu.mcu_count
           - prefix_state->huff_checkpoint.mcu_count);

    if (prefix_rate > 0.0) {
      baseline_rate_supported = true;
      baseline_rate_deviation =
          fabs(extension_rate - prefix_rate) / prefix_rate;
      entropy_profile_deviation = baseline_rate_deviation;

      if (prefix_state->huff_checkpoint.dc_samples > 0
          && entropy_probe.mcu.dc_samples
                 > prefix_state->huff_checkpoint.dc_samples
          && entropy_probe.mcu.dc_abs_sum
                 >= prefix_state->huff_checkpoint.dc_abs_sum) {
        double prefix_dc_mean =
            (double)prefix_state->huff_checkpoint.dc_abs_sum
            / prefix_state->huff_checkpoint.dc_samples;
        double extension_dc_mean =
            (double)(entropy_probe.mcu.dc_abs_sum
                     - prefix_state->huff_checkpoint.dc_abs_sum)
            / (entropy_probe.mcu.dc_samples
               - prefix_state->huff_checkpoint.dc_samples);

        if (prefix_dc_mean > 0.0) {
          entropy_profile_deviation +=
              fabs(extension_dc_mean - prefix_dc_mean) / prefix_dc_mean;
        }
      }
      if (prefix_state->huff_checkpoint.ac_samples > 0
          && entropy_probe.mcu.ac_samples
                 > prefix_state->huff_checkpoint.ac_samples
          && entropy_probe.mcu.ac_abs_sum
                 >= prefix_state->huff_checkpoint.ac_abs_sum) {
        double prefix_ac_mean =
            (double)prefix_state->huff_checkpoint.ac_abs_sum
            / prefix_state->huff_checkpoint.ac_samples;
        double extension_ac_mean =
            (double)(entropy_probe.mcu.ac_abs_sum
                     - prefix_state->huff_checkpoint.ac_abs_sum)
            / (entropy_probe.mcu.ac_samples
               - prefix_state->huff_checkpoint.ac_samples);

        if (prefix_ac_mean > 0.0) {
          entropy_profile_deviation +=
              fabs(extension_ac_mean - prefix_ac_mean) / prefix_ac_mean;
        }
      }
    }
  }

  memset(&boundary, 0, sizeof(boundary));
  if (measure_boundary) {
    jpg_reassembly_ooo_restore_candidate(candidate, saved_num_blocks,
                                         saved_length);
    jpg_reassembly_ooo_append_range(candidate, moved_start, 1);
    materialized = jpg_reassembly_materialize_candidate(candidate,
                                                         &materialized_length);
    boundary = jpg_boundary_score(materialized, saved_length,
                                  materialized_length);
    jpg_reassembly_ooo_restore_candidate(candidate, saved_num_blocks,
                                         saved_length);
    if (!boundary.valid) {
      return false;
    }
  }

  memset(choice, 0, sizeof(*choice));
  choice->found = true;
  choice->huffman_available = true;
  choice->huffman_support = true;
  choice->baseline_rate_supported = baseline_rate_supported;
  choice->dc_discontinuity_supported = entropy_probe.supported;
  choice->entropy_profile_supported = baseline_rate_supported;
  choice->moved_start = moved_start;
  choice->run_len = 1;
  choice->suffix_start = -1;
  choice->baseline_rate_deviation = baseline_rate_deviation;
  choice->entropy_profile_deviation = entropy_profile_deviation;
  choice->max_dc_discontinuity =
      entropy_probe.mcu.max_dc_discontinuity;
  choice->boundary = boundary;
  if (jpg_reassembly_debug_candidate(candidate)) {
    lock_fprintf(stderr,
                 "[jpgdbg] baseline_scatter run=%" PRId64
                 "+1 rate=%d/%.6f profile=%.6f norm=%.3f\n",
                 moved_start, baseline_rate_supported ? 1 : 0,
                 baseline_rate_deviation, entropy_profile_deviation,
                 boundary.normalized);
  }
  return true;
}

static inline bool jpg_reassembly_measure_baseline_scatter_boundary(
    CarveInfo *candidate,
    uint64_t saved_num_blocks,
    uint64_t saved_length,
    JpgOOOBridgeChoice *choice) {
  uint64_t materialized_length = 0;
  char *materialized;

  if (!candidate || !candidate->b || !choice || !choice->found
      || choice->moved_start < 0 || choice->run_len != 1) {
    return false;
  }
  jpg_reassembly_ooo_restore_candidate(candidate, saved_num_blocks,
                                       saved_length);
  jpg_reassembly_ooo_append_range(candidate, choice->moved_start, 1);
  materialized = jpg_reassembly_materialize_candidate(candidate,
                                                       &materialized_length);
  choice->boundary = jpg_boundary_score_scaled(
      materialized, saved_length, materialized_length, 8, true);
  jpg_reassembly_ooo_restore_candidate(candidate, saved_num_blocks,
                                       saved_length);
  return choice->boundary.valid;
}

static inline bool jpg_reassembly_baseline_bridge_score_better(
    const JpgOOOBridgeChoice *trial,
    const JpgOOOBridgeChoice *best) {
  double trial_score;
  double best_score;
  double trial_worst_join;
  double best_worst_join;

  if (!trial || !best || !trial->boundary.valid || !best->boundary.valid) {
    return false;
  }
  trial_worst_join = trial->boundary.normalized;
  best_worst_join = best->boundary.normalized;
  if (trial->suffix_boundary.valid && best->suffix_boundary.valid) {
    trial_worst_join =
        fmax(trial_worst_join, trial->suffix_boundary.normalized);
    best_worst_join =
        fmax(best_worst_join, best->suffix_boundary.normalized);
  }
  if (trial_worst_join != best_worst_join) {
    return trial_worst_join < best_worst_join;
  }
  trial_score =
      trial->boundary.normalized
      + (trial->suffix_boundary.valid && best->suffix_boundary.valid
             ? fmin(trial->suffix_boundary.normalized,
                    JPG_REASS_BASELINE_BRIDGE_SCORE_LIMIT) : 0.0)
      + (trial->baseline_rate_supported && best->baseline_rate_supported
             ? trial->baseline_rate_deviation : 0.0);
  best_score =
      best->boundary.normalized
      + (trial->suffix_boundary.valid && best->suffix_boundary.valid
             ? fmin(best->suffix_boundary.normalized,
                    JPG_REASS_BASELINE_BRIDGE_SCORE_LIMIT) : 0.0)
      + (trial->baseline_rate_supported && best->baseline_rate_supported
             ? best->baseline_rate_deviation : 0.0);
  return trial_score < best_score
         || (trial_score == best_score
             && (trial->boundary.seam_mad < best->boundary.seam_mad
                 || (trial->boundary.seam_mad == best->boundary.seam_mad
                     && trial->suffix_len > best->suffix_len)));
}

static inline bool jpg_reassembly_baseline_bridge_better(
    const JpgOOOBridgeChoice *trial,
    const JpgOOOBridgeChoice *best) {
  if (!trial || !trial->found) {
    return false;
  }
  if (!best || !best->found) {
    return true;
  }
  if (trial->direct_validates != best->direct_validates) {
    return trial->direct_validates;
  }
  if (trial->full_validates != best->full_validates) {
    return trial->full_validates;
  }
  if (trial->huffman_support != best->huffman_support) {
    return trial->huffman_support;
  }
  if (!trial->full_validates && trial->huffman_support
      && (trial->suffix_len > 0) != (best->suffix_len > 0)) {
    return trial->suffix_len > 0;
  }
  if (!trial->full_validates && trial->huffman_support
      && trial->suffix_len != best->suffix_len) {
    return trial->suffix_len > best->suffix_len;
  }
  if (trial->boundary.valid != best->boundary.valid) {
    return trial->boundary.valid;
  }
  if (trial->suffix_len > 0 && best->suffix_len > 0
      && trial->suffix_boundary.valid != best->suffix_boundary.valid) {
    return trial->suffix_boundary.valid;
  }
  if (!trial->full_validates && trial->huffman_support
      && trial->boundary.valid
      && trial->apparent_continuation != best->apparent_continuation) {
    const JpgOOOBridgeChoice *continuation =
        trial->apparent_continuation ? trial : best;
    const JpgOOOBridgeChoice *remote =
        trial->apparent_continuation ? best : trial;

    if (continuation->boundary.normalized
        <= remote->boundary.normalized
               * JPG_REASS_BASELINE_CONTIGUOUS_BOUNDARY_RATIO) {
      return trial->apparent_continuation;
    }
  }
  return trial->boundary.valid
         && jpg_reassembly_baseline_bridge_score_better(trial, best);
}

static inline bool jpg_reassembly_baseline_scatter_better(
    const JpgOOOBridgeChoice *trial,
    const JpgOOOBridgeChoice *best) {
  bool trial_rate_consistent;
  bool best_rate_consistent;

  if (!trial || !trial->found) {
    return false;
  }
  if (!best || !best->found) {
    return true;
  }
  if (trial->direct_validates != best->direct_validates) {
    return trial->direct_validates;
  }
  if (trial->full_validates != best->full_validates) {
    return trial->full_validates;
  }
  if (trial->huffman_support != best->huffman_support) {
    return trial->huffman_support;
  }
  trial_rate_consistent =
      trial->baseline_rate_supported
      && trial->baseline_rate_deviation < JPG_REASS_BASELINE_RATE_LIMIT;
  best_rate_consistent =
      best->baseline_rate_supported
      && best->baseline_rate_deviation < JPG_REASS_BASELINE_RATE_LIMIT;
  if (trial_rate_consistent != best_rate_consistent) {
    return trial_rate_consistent;
  }
  if (trial->dc_discontinuity_supported
      && best->dc_discontinuity_supported) {
    if (trial->max_dc_discontinuity
            * JPG_REASS_BASELINE_DC_DISCONTINUITY_RATIO
        < best->max_dc_discontinuity) {
      return true;
    }
    if (best->max_dc_discontinuity
            * JPG_REASS_BASELINE_DC_DISCONTINUITY_RATIO
        < trial->max_dc_discontinuity) {
      return false;
    }
  }
  return jpg_reassembly_baseline_bridge_better(trial, best);
}

static inline bool jpg_reassembly_baseline_scatter_rate_consistent(
    const JpgOOOBridgeChoice *choice) {
  return choice && choice->baseline_rate_supported
         && choice->baseline_rate_deviation
                < JPG_REASS_BASELINE_RATE_LIMIT;
}

static inline bool jpg_reassembly_restart_entry_better(
    const JpgOOOBridgeChoice *trial,
    const JpgOOOBridgeChoice *best) {
  if (!trial || !trial->found || !trial->huffman_support
      || trial->suffix_len == 0 || !trial->boundary.valid) {
    return false;
  }
  if (!best || !best->found) {
    return true;
  }
  if (trial->direct_validates != best->direct_validates) {
    return trial->direct_validates;
  }
  if (trial->full_validates != best->full_validates) {
    return trial->full_validates;
  }
  if (trial->boundary.normalized != best->boundary.normalized) {
    return trial->boundary.normalized < best->boundary.normalized;
  }
  if (trial->boundary.seam_mad != best->boundary.seam_mad) {
    return trial->boundary.seam_mad < best->boundary.seam_mad;
  }
  if (trial->baseline_rate_supported && best->baseline_rate_supported
      && trial->baseline_rate_deviation != best->baseline_rate_deviation) {
    return trial->baseline_rate_deviation < best->baseline_rate_deviation;
  }
  return trial->moved_start < best->moved_start;
}

static inline bool jpg_reassembly_refine_baseline_bridge_run_length(
    CarveInfo *candidate,
    const JPGCarveState *prefix_state,
    bool have_prefix_state,
    uint32_t fixed_prefix_blocks,
    uint64_t saved_num_blocks,
    uint64_t saved_length,
    int64_t suffix_start,
    uint64_t suffix_len,
    JpgOOOBridgeChoice *best) {
  JpgOOOBridgeChoice refined_best;
  JpgOOOBridgeChoice ranking_best;
  int64_t moved_start;
  uint32_t refined_choices = 0;

  if (!candidate || !prefix_state || !best || !best->found
      || best->direct_validates || !best->huffman_support
      || best->suffix_len == 0
      || suffix_start < 0 || suffix_len == 0) {
    return false;
  }

  moved_start = best->moved_start;
  memset(&refined_best, 0, sizeof(refined_best));
  memset(&ranking_best, 0, sizeof(ranking_best));
  for (uint64_t run_len = JPG_REASS_OOO_MIN_RUN;
       run_len <= JPG_REASS_OOO_MAX_RUN;
       run_len++) {
    JpgOOOBridgeChoice ranking_trial;
    JpgOOOBridgeChoice trial;
    uint64_t bridge_end;
    uint64_t materialized_length = 0;
    char *materialized;

    memset(&trial, 0, sizeof(trial));
    if (!jpg_reassembly_evaluate_baseline_bridge(
            candidate, prefix_state, have_prefix_state,
            fixed_prefix_blocks, saved_num_blocks, saved_length,
            moved_start, run_len, suffix_start, suffix_len, &trial)
        || !trial.huffman_support || trial.suffix_len == 0) {
      continue;
    }

    jpg_reassembly_ooo_restore_candidate(candidate, saved_num_blocks,
                                         saved_length);
    jpg_reassembly_ooo_append_range(candidate, moved_start, run_len);
    jpg_reassembly_ooo_append_range(candidate, suffix_start,
                                    trial.suffix_len);
    materialized = jpg_reassembly_materialize_candidate(
        candidate, &materialized_length);
    bridge_end = saved_length + run_len * scalpel_state.blocksize;
    ranking_trial = trial;
    ranking_trial.boundary = jpg_boundary_score_scaled(
        materialized, saved_length, materialized_length, 2, false);
    if (bridge_end < materialized_length) {
      ranking_trial.suffix_boundary = jpg_boundary_score_scaled(
          materialized, bridge_end, materialized_length, 2, false);
    }
    jpg_reassembly_ooo_restore_candidate(candidate, saved_num_blocks,
                                         saved_length);

    if (!trial.boundary.valid || !trial.suffix_boundary.valid
        || !ranking_trial.boundary.valid
        || !ranking_trial.suffix_boundary.valid) {
      continue;
    }
    refined_choices++;
    if (jpg_reassembly_baseline_bridge_better(&ranking_trial,
                                              &ranking_best)) {
      ranking_best = ranking_trial;
      refined_best = trial;
    }
  }

  if (refined_choices < 2 || !refined_best.found) {
    return false;
  }
  if (jpg_reassembly_debug_candidate(candidate)) {
    lock_fprintf(stderr,
                 "[jpgdbg] bridge_refined moved=%" PRId64
                 " run=%" PRIu64 " suffix=%" PRId64 "+%" PRIu64
                 " entry=%.3f exit=%.3f choices=%" PRIu32 "\n",
                 refined_best.moved_start, refined_best.run_len,
                 refined_best.suffix_start, refined_best.suffix_len,
                 refined_best.boundary.normalized,
                 refined_best.suffix_boundary.normalized,
                 refined_choices);
  }
  *best = refined_best;
  return true;
}

static inline bool jpg_reassembly_baseline_entry_only_better(
    const JpgOOOBridgeChoice *trial,
    const JpgOOOBridgeChoice *best) {
  double trial_score;
  double best_score;

  if (!trial || !trial->found) {
    return false;
  }
  if (!best || !best->found) {
    return true;
  }
  if (trial->direct_validates != best->direct_validates) {
    return trial->direct_validates;
  }
  if (trial->full_validates != best->full_validates) {
    return trial->full_validates;
  }
  if (trial->huffman_support != best->huffman_support) {
    return trial->huffman_support;
  }
  if (trial->boundary.valid != best->boundary.valid) {
    return trial->boundary.valid;
  }
  if (!trial->boundary.valid) {
    return false;
  }
  trial_score = trial->boundary.normalized
                + (trial->baseline_rate_supported
                       ? trial->baseline_rate_deviation : 0.0);
  best_score = best->boundary.normalized
               + (best->baseline_rate_supported
                      ? best->baseline_rate_deviation : 0.0);
  return trial_score < best_score
         || (trial_score == best_score
             && (trial->boundary.seam_mad < best->boundary.seam_mad
                 || (trial->boundary.seam_mad == best->boundary.seam_mad
                     && (trial->suffix_len > best->suffix_len
                         || (trial->suffix_len == best->suffix_len
                             && trial->run_len > best->run_len)))));
}

static inline void jpg_reassembly_shortlist_baseline_entry_only(
    const JpgOOOBridgeChoice *trial) {
  JpgOOOBridgeShortlist *shortlist = jpg_reassembly_bridge_shortlist;
  uint32_t position;

  // entry-ranked retries retain the return suffix but do not use its seam to
  // rank the prefix-to-fragment transition.
  if (!shortlist || !trial || !trial->found) {
    return;
  }
  for (position = 0; position < shortlist->entry_only_count; position++) {
    JpgOOOBridgeChoice *existing =
        &shortlist->entry_only_choices[position];

    if (existing->moved_start == trial->moved_start
        && existing->run_len == trial->run_len) {
      if (!jpg_reassembly_baseline_entry_only_better(trial, existing)) {
        return;
      }
      memmove(existing, existing + 1,
              (shortlist->entry_only_count - position - 1)
                  * sizeof(*existing));
      shortlist->entry_only_count--;
      break;
    }
  }
  for (position = 0; position < shortlist->entry_only_count; position++) {
    if (jpg_reassembly_baseline_entry_only_better(
            trial, &shortlist->entry_only_choices[position])) {
      break;
    }
  }
  if (position >= JPG_REASS_DEFAULT_SHORTLIST_SIZE) {
    return;
  }
  if (shortlist->entry_only_count < JPG_REASS_DEFAULT_SHORTLIST_SIZE) {
    shortlist->entry_only_count++;
  }
  memmove(&shortlist->entry_only_choices[position + 1],
          &shortlist->entry_only_choices[position],
          (shortlist->entry_only_count - position - 1)
              * sizeof(shortlist->entry_only_choices[0]));
  shortlist->entry_only_choices[position] = *trial;
}

static inline void jpg_reassembly_shortlist_baseline_bridge(
    const JpgOOOBridgeChoice *trial) {
  JpgOOOBridgeShortlist *shortlist = jpg_reassembly_bridge_shortlist;
  uint32_t position;

  if (!shortlist || !trial || !trial->found) {
    return;
  }
  jpg_reassembly_shortlist_baseline_entry_only(trial);
  for (position = 0; position < shortlist->count; position++) {
    JpgOOOBridgeChoice *existing = &shortlist->choices[position];

    if (existing->moved_start == trial->moved_start
        && existing->run_len == trial->run_len
        && existing->suffix_start == trial->suffix_start
        && existing->suffix_len == trial->suffix_len) {
      if (!jpg_reassembly_baseline_bridge_better(trial, existing)) {
        return;
      }
      memmove(existing, existing + 1,
              (shortlist->count - position - 1) * sizeof(*existing));
      shortlist->count--;
      break;
    }
  }
  for (position = 0; position < shortlist->count; position++) {
    if (jpg_reassembly_baseline_bridge_better(
            trial, &shortlist->choices[position])) {
      break;
    }
  }
  if (position >= JPG_REASS_DEFAULT_SHORTLIST_SIZE) {
    return;
  }
  if (shortlist->count < JPG_REASS_DEFAULT_SHORTLIST_SIZE) {
    shortlist->count++;
  }
  memmove(&shortlist->choices[position + 1],
          &shortlist->choices[position],
          (shortlist->count - position - 1)
              * sizeof(shortlist->choices[0]));
  shortlist->choices[position] = *trial;
}

static inline bool jpg_reassembly_baseline_bridge_beats_forward(
    const JpgOOOBridgeChoice *bridge,
    const JPGReassemblyForwardChoice *forward) {
  double bridge_score;

  if (!bridge || !forward || !bridge->boundary.valid
      || !forward->have_boundary) {
    return false;
  }
  bridge_score = bridge->boundary.normalized;
  if (bridge->suffix_len >= JPG_REASS_OOO_MIN_SUFFIX_PROBE
      && bridge->suffix_boundary.valid) {
    bridge_score = fmax(bridge_score,
                        bridge->suffix_boundary.normalized);
  }
  return bridge_score
         < forward->boundary.normalized
               * JPG_REASS_BASELINE_FORWARD_BRIDGE_RATIO;
}

static inline void jpg_reassembly_rank_baseline_bridge(
    JpgOOOBridgeChoice *best,
    const JpgOOOBridgeChoice *trial) {
  if (!best || !trial || !trial->found) {
    return;
  }
  jpg_reassembly_shortlist_baseline_bridge(trial);
  if (jpg_reassembly_baseline_bridge_better(trial, best)) {
    *best = *trial;
  }
}

static inline bool jpg_reassembly_baseline_bridge_conclusive(
    const JpgOOOBridgeChoice *bridge) {
  return bridge && bridge->found
         && (bridge->direct_validates || bridge->full_validates);
}

static inline double jpg_reassembly_baseline_entry_score(
    const JpgOOOBridgeChoice *choice) {
  if (!choice || !choice->found || !choice->boundary.valid) {
    return DBL_MAX;
  }
  return choice->boundary.normalized
         + (choice->baseline_rate_supported
                ? choice->baseline_rate_deviation : 0.0);
}

static inline void jpg_reassembly_rank_baseline_entry(
    JpgOOOBridgeChoice *best,
    const JpgOOOBridgeChoice *trial) {
  bool replace = false;

  if (!best || !trial || !trial->found || trial->run_len != 1) {
    return;
  }
  if (!best->found) {
    replace = true;
  }
  else if (trial->direct_validates != best->direct_validates) {
    replace = trial->direct_validates;
  }
  else if (trial->huffman_support != best->huffman_support) {
    replace = trial->huffman_support;
  }
  else if (trial->boundary.valid != best->boundary.valid) {
    replace = trial->boundary.valid;
  }
  else if (jpg_reassembly_baseline_entry_score(trial)
           < jpg_reassembly_baseline_entry_score(best)) {
    replace = true;
  }

  if (replace) {
    *best = *trial;
    best->full_validates = best->direct_validates;
    best->suffix_start = -1;
    best->suffix_len = 0;
    memset(&best->suffix_boundary, 0, sizeof(best->suffix_boundary));
  }
}

static inline void jpg_reassembly_insert_hidden_boundary_choice(
    JPGHiddenBoundaryProgress *progress,
    int64_t actual_block,
    double score) {
  uint32_t position;

  if (!progress || actual_block < 0 || !isfinite(score)) {
    return;
  }
  for (position = 0; position < progress->choice_count; position++) {
    if (progress->choices[position].actual_block == actual_block) {
      if (progress->choices[position].score <= score) {
        return;
      }
      memmove(&progress->choices[position],
              &progress->choices[position + 1],
              (progress->choice_count - position - 1)
                  * sizeof(progress->choices[0]));
      progress->choice_count--;
      break;
    }
  }
  for (position = 0; position < progress->choice_count; position++) {
    if (score < progress->choices[position].score
        || (score == progress->choices[position].score
            && actual_block
                   < progress->choices[position].actual_block)) {
      break;
    }
  }
  if (position >= JPG_HIDDEN_BOUNDARY_CHOICES) {
    return;
  }
  if (progress->choice_count < JPG_HIDDEN_BOUNDARY_CHOICES) {
    progress->choice_count++;
  }
  memmove(&progress->choices[position + 1],
          &progress->choices[position],
          (progress->choice_count - position - 1)
              * sizeof(progress->choices[0]));
  progress->choices[position].actual_block = actual_block;
  progress->choices[position].score = score;
}

static inline void jpg_reassembly_group_hidden_boundary_choices(
    CarveInfo *candidate,
    JPGHiddenBoundaryProgress *progress) {
  int64_t group_ends[JPG_HIDDEN_BOUNDARY_CHOICES];
  double group_scores[JPG_HIDDEN_BOUNDARY_CHOICES];

  if (!candidate || !progress || progress->choice_count < 2) {
    return;
  }
  for (uint32_t index = 0; index < progress->choice_count; index++) {
    int64_t next_header = -1;
    int64_t apparent = filemirror_apparent_blocknumber(
        scalpel_state.filemirror, progress->choices[index].actual_block);

    if (apparent >= 0 && jpg_reassembly_next_header_apparent(
            candidate, apparent + 1,
            &next_header)) {
      group_ends[index] = filemirror_actual_blocknumber(
          scalpel_state.filemirror, next_header);
    }
    else {
      group_ends[index] = progress->choices[index].actual_block;
    }
    group_scores[index] = progress->choices[index].score;
  }
  for (uint32_t left = 0; left < progress->choice_count; left++) {
    for (uint32_t right = 0; right < progress->choice_count; right++) {
      if (group_ends[left] == group_ends[right]
          && progress->choices[right].score < group_scores[left]) {
        group_scores[left] = progress->choices[right].score;
      }
    }
  }
  for (uint32_t index = 1; index < progress->choice_count; index++) {
    JPGHiddenBoundaryChoice choice = progress->choices[index];
    int64_t group_end = group_ends[index];
    double group_score = group_scores[index];
    uint32_t position = index;

    while (position > 0
           && (group_score < group_scores[position - 1]
               || (group_score == group_scores[position - 1]
                   && group_end == group_ends[position - 1]
                   && choice.actual_block
                          < progress->choices[position - 1].actual_block))) {
      progress->choices[position] = progress->choices[position - 1];
      group_ends[position] = group_ends[position - 1];
      group_scores[position] = group_scores[position - 1];
      position--;
    }
    progress->choices[position] = choice;
    group_ends[position] = group_end;
    group_scores[position] = group_score;
  }
}

static inline bool jpg_reassembly_rank_global_baseline_block(
    CarveInfo *candidate,
    JPGCarveState *prefix_state,
    uint32_t fixed_prefix_blocks,
    uint64_t saved_num_blocks,
    uint64_t saved_length,
    int64_t last_apparent,
    bool prefer_apparent_continuation,
    JpgOOOBridgeChoice *best) {
  uint64_t trials = 0;
  bool hidden_boundary_search;

  if (!candidate || !prefix_state || !prefix_state->valid || !best) {
    return true;
  }
  hidden_boundary_search =
      !prefer_apparent_continuation
      && prefix_state->hidden_boundary_recovery;

  if (hidden_boundary_search) {
    JPGHiddenBoundaryProgress *progress =
        &prefix_state->hidden_boundary_progress;

    if (!progress->active
        || progress->origin_blocks != saved_num_blocks
        || progress->origin_length != saved_length) {
      memset(progress, 0, sizeof(*progress));
      progress->active = true;
      progress->origin_blocks = saved_num_blocks;
      progress->origin_length = saved_length;
    }
    if (!progress->baseline_scan_initialized) {
      int64_t tail_apparent = -1;
      int64_t scan_start = -1;

      progress->baseline_scan_initialized = true;
      if (saved_num_blocks > 0) {
        tail_apparent = blockvector_get_apparent_blocknumber(
            candidate->b, saved_num_blocks - 1);
      }
      if (tail_apparent >= 0 && tail_apparent < INT64_MAX) {
        scan_start = tail_apparent + 1;
      }
      if (prefix_state->hidden_rejected_range_valid
          && prefix_state->hidden_rejected_last_actual < INT64_MAX) {
        int64_t successor = jpg_reassembly_apparent_lower_bound(
            prefix_state->hidden_rejected_last_actual + 1);
        if (successor > scan_start) {
          scan_start = successor;
        }
      }
      if (scan_start >= 0 && scan_start < last_apparent) {
        progress->next_actual = filemirror_actual_blocknumber(
            scalpel_state.filemirror, scan_start);
        progress->scan_wrap_actual = progress->next_actual;
      }
      else {
        progress->scan_wrapped = true;
        progress->next_actual = 0;
        progress->scan_wrap_actual = last_apparent > 0
            ? filemirror_actual_blocknumber(scalpel_state.filemirror,
                                             last_apparent - 1) + 1 : 0;
      }
    }

    if (progress->choices_ready
        && progress->next_choice >= progress->choice_count) {
      progress->choices_ready = false;
      progress->choice_count = 0;
      progress->next_choice = 0;
      memset(progress->choices, 0, sizeof(progress->choices));
    }

    if (!progress->scan_complete) {
      int64_t scan_limit = progress->scan_wrapped
          ? jpg_reassembly_apparent_lower_bound(progress->scan_wrap_actual)
          : last_apparent;
      int64_t apparent = jpg_reassembly_apparent_lower_bound(
          progress->next_actual);
      while (!progress->scan_complete) {
        int64_t actual;
        JpgOOOBridgeChoice trial;
        bool evaluated;

        if (apparent >= scan_limit) {
          if (!progress->scan_wrapped && progress->scan_wrap_actual > 0) {
            progress->scan_wrapped = true;
            progress->next_actual = 0;
            apparent = 0;
            scan_limit = jpg_reassembly_apparent_lower_bound(
                progress->scan_wrap_actual);
            progress->previous_compatible = false;
            continue;
          }
          progress->scan_complete = true;
          break;
        }
        if (jpg_reassembly_checkpoint_requested()) {
          jpg_put_decoder_state(candidate->carvehashkey, prefix_state);
          return false;
        }
        actual = filemirror_actual_blocknumber(scalpel_state.filemirror,
                                               apparent);
        if (actual != progress->next_actual) {
          progress->previous_compatible = false;
        }
        progress->next_actual = actual;
        progress->scan_batch_positions++;
        if (!jpg_reassembly_ooo_apparent_available(candidate, apparent)) {
          evaluated = false;
        }
        else if (prefix_state->hidden_rejected_range_valid
                 && actual >= prefix_state->hidden_rejected_first_actual
                 && actual <= prefix_state->hidden_rejected_last_actual) {
          evaluated = false;
        }
        else if (jpg_reassembly_ooo_range_has_eoi(apparent, 1)) {
          evaluated = false;
        }
        else {
          double profile;

          progress->trials++;
          memset(&trial, 0, sizeof(trial));
          evaluated = jpg_reassembly_evaluate_baseline_scatter_block(
              candidate, prefix_state, fixed_prefix_blocks,
              saved_num_blocks, saved_length, apparent, false, &trial);
          if (evaluated) {
            profile = trial.entropy_profile_supported
                        ? trial.entropy_profile_deviation
                        : DBL_MAX;
            if (!progress->previous_compatible) {
              jpg_reassembly_insert_hidden_boundary_choice(
                  progress, actual, profile);
            }
            progress->previous_compatible = true;
          }
        }
        if (!evaluated) {
          progress->previous_compatible = false;
        }
        if (jpg_reassembly_checkpoint_requested()) {
          jpg_put_decoder_state(candidate->carvehashkey, prefix_state);
          return false;
        }
        progress->next_actual = actual + 1;
        apparent++;
        if (progress->scan_batch_positions
              >= JPG_HIDDEN_BOUNDARY_SCAN_BATCH) {
          progress->scan_batch_positions = 0;
        }
      }
      if (progress->scan_complete && progress->choice_count > 0) {
        jpg_reassembly_group_hidden_boundary_choices(candidate, progress);
        progress->choices_ready = true;
      }
      jpg_put_decoder_state(candidate->carvehashkey, prefix_state);
    }

    if (progress->choices_ready) {
      JpgOOOBridgeShortlist *shortlist = jpg_reassembly_bridge_shortlist;

      if (shortlist) {
        memset(shortlist, 0, sizeof(*shortlist));
      }
      memset(best, 0, sizeof(*best));
      for (uint32_t index = progress->next_choice;
           index < progress->choice_count; index++) {
        JpgOOOBridgeChoice trial;
        int64_t apparent = filemirror_apparent_blocknumber(
            scalpel_state.filemirror, progress->choices[index].actual_block);

        if (jpg_reassembly_checkpoint_requested()) {
          jpg_put_decoder_state(candidate->carvehashkey, prefix_state);
          return false;
        }
        if (apparent < 0
            || !jpg_reassembly_ooo_apparent_available(candidate, apparent)) {
          continue;
        }
        memset(&trial, 0, sizeof(trial));
        if (!jpg_reassembly_evaluate_baseline_scatter_block(
                candidate, prefix_state, fixed_prefix_blocks,
                saved_num_blocks, saved_length,
                apparent, true, &trial)) {
          continue;
        }
        trial.hidden_boundary_candidate = true;
        trial.hidden_boundary_rank = index;
        trial.hidden_boundary_score = progress->choices[index].score;
        if (!best->found) {
          *best = trial;
        }
        if (shortlist
            && shortlist->count < JPG_REASS_BRIDGE_SHORTLIST_SIZE) {
          shortlist->choices[shortlist->count++] = trial;
          shortlist->entry_only_choices[
              shortlist->entry_only_count++] = trial;
        }
      }
      if (!best->found) {
        progress->next_choice = progress->choice_count;
        jpg_put_decoder_state(candidate->carvehashkey, prefix_state);
      }
    }
    return true;
  }

  int64_t tail_apparent = saved_num_blocks > 0
                              ? blockvector_get_apparent_blocknumber(
                                    candidate->b, saved_num_blocks - 1)
                              : -1;
  int64_t local_first = tail_apparent - JPG_REASS_OOO_LOCAL_BACKSCAN_BLOCKS;
  bool conclusive = false;

  if (local_first < 0) {
    local_first = 0;
  }

  // Try nearby preceding blocks first. A displaced run commonly sits close to
  // the current physical run, while the global pass preserves broad coverage.
  for (uint32_t phase = 0;
       phase < 2 && !conclusive && !jpg_reassembly_checkpoint_requested();
       phase++) {
    int64_t apparent = phase == 0 ? tail_apparent - 1 : 0;
    uint64_t trial_limit = phase == 0
                               ? JPG_REASS_OOO_LOCAL_BACKSCAN_BLOCKS
                               : JPG_REASS_OOO_MAX_TRIALS;

    trials = 0;
    while (trials < trial_limit
           && (phase == 0 ? apparent >= local_first
                          : apparent < last_apparent)) {
      JpgOOOBridgeChoice trial;
      int64_t trial_apparent = apparent;

      if (phase == 0) {
        apparent--;
      }
      else {
        apparent++;
      }

      if (jpg_reassembly_checkpoint_requested()) {
        break;
      }
      if (phase == 1 && trial_apparent >= local_first
          && trial_apparent < tail_apparent) {
        continue;
      }
      if (!jpg_reassembly_ooo_apparent_available(candidate,
                                                  trial_apparent)) {
        continue;
      }
      trials++;
      memset(&trial, 0, sizeof(trial));
      bool evaluated = prefer_apparent_continuation
          ? jpg_reassembly_evaluate_baseline_bridge(
                candidate, prefix_state, true, fixed_prefix_blocks,
                saved_num_blocks, saved_length, trial_apparent, 1, -1, 0,
                &trial)
          : jpg_reassembly_evaluate_baseline_scatter_block(
                candidate, prefix_state, fixed_prefix_blocks,
                saved_num_blocks, saved_length, trial_apparent, true, &trial);

      if (evaluated && !trial.full_validates && !trial.direct_validates
          && trial.huffman_support && scalpel_state.blocksize > 0
          && scalpel_state.blocksize <= JPG_REASS_SMALL_BLOCK_BRIDGE_BYTES) {
        uint64_t exact_run_len =
            CEILDIV(JPG_REASS_SMALL_BLOCK_BRIDGE_BYTES,
                    scalpel_state.blocksize);

        if (exact_run_len > JPG_REASS_OOO_MAX_RUN) {
          exact_run_len = JPG_REASS_OOO_MAX_RUN;
        }
        if (exact_run_len > 0
            && exact_run_len
                   < (uint64_t)(last_apparent - trial_apparent)) {
          JpgOOOBridgeChoice exact_trial;
          int64_t suffix_start =
              trial_apparent + (int64_t)exact_run_len;

          memset(&exact_trial, 0, sizeof(exact_trial));
          if (jpg_reassembly_evaluate_baseline_bridge(
                  candidate, prefix_state, true, fixed_prefix_blocks,
                  saved_num_blocks, saved_length, trial_apparent,
                  exact_run_len, suffix_start, 0, &exact_trial)
              && exact_trial.full_validates) {
            trial = exact_trial;
          }
        }
      }

      if (evaluated) {
        if (!prefer_apparent_continuation) {
          trial.apparent_continuation = false;
        }
        jpg_reassembly_shortlist_baseline_bridge(&trial);
        if (prefer_apparent_continuation
            ? jpg_reassembly_baseline_bridge_better(&trial, best)
            : jpg_reassembly_baseline_scatter_better(&trial, best)) {
          *best = trial;
        }
        if (jpg_reassembly_baseline_bridge_conclusive(best)) {
          conclusive = true;
          break;
        }
      }
    }
  }
  return !jpg_reassembly_checkpoint_requested();
}

static inline void jpg_reassembly_rank_nearby_baseline_bridge(
    CarveInfo *candidate,
    const JPGCarveState *prefix_state,
    uint32_t fixed_prefix_blocks,
    uint64_t saved_num_blocks,
    uint64_t saved_length,
    int64_t tail_apparent,
    int64_t suffix_start,
    uint64_t suffix_len,
    JpgOOOBridgeChoice *best,
    JpgOOOBridgeChoice *runner_up) {
  int64_t first_apparent;
  int64_t last_apparent;
  int64_t apparent_blocks;

  if (!candidate || !prefix_state || !prefix_state->valid
      || suffix_start < 0 || suffix_len == 0 || !best || !runner_up) {
    return;
  }
  apparent_blocks = (int64_t)filemirror_apparent_blocks(
      scalpel_state.filemirror);
  first_apparent = tail_apparent
                   - JPG_REASS_OOO_STRICT_ANCHOR_BACKSCAN_BLOCKS;
  if (first_apparent < 0) {
    first_apparent = 0;
  }
  last_apparent = tail_apparent
                  + JPG_REASS_OOO_STRICT_ANCHOR_BACKSCAN_BLOCKS;
  if (last_apparent >= apparent_blocks) {
    last_apparent = apparent_blocks - 1;
  }

  for (int64_t apparent = first_apparent;
       apparent <= last_apparent; apparent++) {
    JpgOOOBridgeChoice trial;

    if ((apparent >= suffix_start
         && apparent < suffix_start + (int64_t)suffix_len)
        || !jpg_reassembly_ooo_apparent_available(candidate, apparent)) {
      continue;
    }
    memset(&trial, 0, sizeof(trial));
    if (!jpg_reassembly_evaluate_baseline_bridge(
            candidate, prefix_state, true, fixed_prefix_blocks,
            saved_num_blocks, saved_length, apparent, 1,
            suffix_start, suffix_len, &trial)
        || !trial.huffman_support || trial.suffix_len != suffix_len) {
      continue;
    }
    if (jpg_reassembly_baseline_bridge_better(&trial, best)) {
      *runner_up = *best;
      *best = trial;
    }
    else if (jpg_reassembly_baseline_bridge_better(&trial, runner_up)) {
      *runner_up = trial;
    }
  }
}

static inline bool jpg_reassembly_refine_baseline_scatter_lookahead(
    CarveInfo *candidate,
    const JPGCarveState *prefix_state,
    uint32_t fixed_prefix_blocks,
    uint64_t saved_num_blocks,
    uint64_t saved_length,
    int64_t last_apparent,
    JpgOOOBridgeChoice *best) {
  JpgOOOBridgeShortlist *shortlist = jpg_reassembly_bridge_shortlist;
  JpgOOOBridgeChoice choices[JPG_REASS_SCATTER_LOOKAHEAD_CHOICES];
  uint32_t choice_count = 0;
  uint32_t selected = 0;
  uint32_t evaluated = 0;
  bool selected_validates = false;
  bool selected_next_conclusive = false;
  double selected_score = HUGE_VAL;
  double cutoff;

  if (!candidate || !prefix_state || !prefix_state->valid || !shortlist
      || !best || !best->found || best->run_len != 1
      || best->suffix_len != 0) {
    return false;
  }

  choices[choice_count++] = *best;
  cutoff = jpg_reassembly_retry_choice_score(best)
           * JPG_REASS_SCATTER_LOOKAHEAD_RATIO
           + JPG_REASS_SCATTER_LOOKAHEAD_SLACK;
  for (uint32_t rank = 0;
       rank < shortlist->count
         && choice_count < JPG_REASS_SCATTER_LOOKAHEAD_CHOICES;
       rank++) {
    const JpgOOOBridgeChoice *choice = &shortlist->choices[rank];

    if (choice->run_len != 1 || choice->suffix_len != 0
        || jpg_reassembly_same_bridge_choice(choice, best)
        || jpg_reassembly_baseline_scatter_rate_consistent(choice)
               != jpg_reassembly_baseline_scatter_rate_consistent(best)
        || jpg_reassembly_retry_choice_score(choice) > cutoff) {
      continue;
    }
    choices[choice_count++] = *choice;
  }
  if (choice_count < 2) {
    return false;
  }

  for (uint32_t index = 0; index < choice_count; index++) {
    JpgOOOBridgeShortlist lookahead_shortlist;
    JpgOOOBridgeShortlist *saved_shortlist =
        jpg_reassembly_bridge_shortlist;
    JPGCarveState trial_state = *prefix_state;
    JpgOOOBridgeChoice next;
    uint64_t trial_validates_to = 0;
    uint64_t trial_num_blocks;
    uint64_t trial_length;
    bool trial_validates;
    bool next_conclusive = false;
    double score;

    if (jpg_reassembly_checkpoint_requested()) {
      break;
    }
    jpg_reassembly_ooo_restore_candidate(candidate, saved_num_blocks,
                                         saved_length);
    jpg_reassembly_ooo_append_range(candidate, choices[index].moved_start, 1);
    trial_num_blocks = blockvector_get_num_blocks(candidate->b);
    trial_length = blockvector_get_data_length(candidate->b);
    trial_validates = jpg_reassembly_validate_direct(
        candidate, &trial_state, &trial_validates_to, fixed_prefix_blocks);
    memset(&next, 0, sizeof(next));
    if (!trial_validates && trial_state.valid) {
      memset(&lookahead_shortlist, 0, sizeof(lookahead_shortlist));
      jpg_reassembly_bridge_shortlist = &lookahead_shortlist;
      jpg_reassembly_rank_global_baseline_block(
          candidate, &trial_state, fixed_prefix_blocks,
          trial_num_blocks, trial_length, last_apparent, false, &next);
      jpg_reassembly_bridge_shortlist = saved_shortlist;
      next_conclusive = jpg_reassembly_baseline_bridge_conclusive(&next);
    }
    score = jpg_reassembly_retry_choice_score(&choices[index]);
    if (!trial_validates) {
      score += next.found ? jpg_reassembly_retry_choice_score(&next)
                          : HUGE_VAL;
    }
    if (jpg_reassembly_debug_candidate(candidate)) {
      lock_fprintf(stderr,
                   "[jpgdbg] scatter_lookahead moved=%" PRId64
                   " next=%" PRId64 " valid=%d conclusive=%d score=%.3f\n",
                   choices[index].moved_start,
                   next.found ? next.moved_start : -1,
                   trial_validates ? 1 : 0,
                   next_conclusive ? 1 : 0, score);
    }
    evaluated++;
    if (evaluated == 1
        || (trial_validates && !selected_validates)
        || (trial_validates == selected_validates
            && next_conclusive && !selected_next_conclusive)
        || (trial_validates == selected_validates
            && next_conclusive == selected_next_conclusive
            && score < selected_score)) {
      selected = index;
      selected_validates = trial_validates;
      selected_next_conclusive = next_conclusive;
      selected_score = score;
    }
  }

  jpg_reassembly_bridge_shortlist = shortlist;
  jpg_reassembly_ooo_restore_candidate(candidate, saved_num_blocks,
                                       saved_length);
  if (evaluated < 2) {
    return false;
  }
  *best = choices[selected];
  return true;
}

static inline bool jpg_reassembly_progressive_bridge_better(
    const JpgOOOBridgeChoice *trial,
    const JpgOOOBridgeChoice *best) {
  if (!trial || !trial->found) {
    return false;
  }
  if (!best || !best->found) {
    return true;
  }
  if (trial->direct_validates != best->direct_validates) {
    return trial->direct_validates;
  }
  if (trial->full_validates != best->full_validates) {
    return trial->full_validates;
  }
  if (trial->progressive_entropy_complete
      != best->progressive_entropy_complete) {
    return trial->progressive_entropy_complete;
  }
  if (trial->progressive_entropy_supported
      != best->progressive_entropy_supported) {
    return trial->progressive_entropy_supported;
  }
  if (trial->boundary.valid != best->boundary.valid) {
    return trial->boundary.valid;
  }
  if (trial->boundary.valid
      && trial->boundary.normalized != best->boundary.normalized) {
    return trial->boundary.normalized < best->boundary.normalized;
  }
  if (trial->boundary.valid
      && trial->boundary.seam_mad != best->boundary.seam_mad) {
    return trial->boundary.seam_mad < best->boundary.seam_mad;
  }
  if (trial->moved_start == best->moved_start
      && trial->run_len != best->run_len) {
    return trial->run_len > best->run_len;
  }
  return trial->progressive_entropy_supported
         && trial->progressive_entropy_score
                != best->progressive_entropy_score
         && trial->progressive_entropy_score
                < best->progressive_entropy_score;
}

static inline void jpg_reassembly_shortlist_progressive_bridge(
    const JpgOOOBridgeChoice *trial) {
  JpgOOOBridgeShortlist *shortlist = jpg_reassembly_bridge_shortlist;
  uint32_t position;

  if (!shortlist || !trial || !trial->found) {
    return;
  }
  for (position = 0; position < shortlist->count; position++) {
    JpgOOOBridgeChoice *existing = &shortlist->choices[position];

    if (existing->moved_start == trial->moved_start
        && existing->run_len == trial->run_len
        && existing->suffix_start == trial->suffix_start
        && existing->suffix_len == trial->suffix_len) {
      if (!jpg_reassembly_progressive_bridge_better(trial, existing)) {
        return;
      }
      memmove(existing, existing + 1,
              (shortlist->count - position - 1) * sizeof(*existing));
      shortlist->count--;
      break;
    }
  }
  for (position = 0; position < shortlist->count; position++) {
    if (jpg_reassembly_progressive_bridge_better(
            trial, &shortlist->choices[position])) {
      break;
    }
  }
  if (position >= JPG_REASS_DEFAULT_SHORTLIST_SIZE) {
    return;
  }
  if (shortlist->count < JPG_REASS_DEFAULT_SHORTLIST_SIZE) {
    shortlist->count++;
  }
  memmove(&shortlist->choices[position + 1],
          &shortlist->choices[position],
          (shortlist->count - position - 1)
              * sizeof(shortlist->choices[0]));
  shortlist->choices[position] = *trial;
}

static inline void jpg_reassembly_rank_progressive_bridge(
    JpgOOOBridgeChoice *best,
    const JpgOOOBridgeChoice *trial) {
  if (!best || !trial || !trial->found) {
    return;
  }
  jpg_reassembly_shortlist_progressive_bridge(trial);
  if (jpg_reassembly_progressive_bridge_better(trial, best)) {
    *best = *trial;
  }
}

static inline bool jpg_reassembly_progressive_bridge_conclusive(
    const JpgOOOBridgeChoice *bridge) {
  return bridge && bridge->found
         && (bridge->direct_validates || bridge->full_validates
             || bridge->progressive_entropy_complete);
}

static inline bool jpg_reassembly_progressive_choice_supported(
    const JpgOOOBridgeChoice *choice) {
  return choice && choice->found
         && (choice->direct_validates || choice->full_validates
             || choice->progressive_entropy_complete
             || choice->progressive_entropy_contiguous
             || (choice->progressive_entropy_supported
                 && choice->progressive_entropy_score
                        < JPG_REASS_PROGRESSIVE_RATE_LIMIT));
}

static inline bool jpg_reassembly_progressive_bridge_preferred(
    const JpgOOOBridgeChoice *bridge,
    const JPGReassemblyForwardChoice *forward) {
  if (!bridge || !bridge->found) {
    return false;
  }
  if (jpg_reassembly_progressive_bridge_conclusive(bridge)) {
    if (bridge->direct_validates && forward && forward->found
        && bridge->moved_start != forward->apparent
        && (forward->validates
            || forward->score_validates_to
                   > forward->commit_validates_to)
        && !bridge->progressive_entropy_complete
        && !(bridge->progressive_entropy_supported
             && bridge->progressive_entropy_score
                    < JPG_REASS_PROGRESSIVE_RATE_LIMIT)) {
      return false;
    }
    return true;
  }
  if (forward && forward->found && forward->is_immediate) {
    return false;
  }
  if (bridge->progressive_entropy_supported
      && bridge->progressive_entropy_score
             < JPG_REASS_PROGRESSIVE_RATE_LIMIT
      && (!forward || !forward->have_boundary || !bridge->boundary.valid
          || bridge->boundary.normalized
                 <= forward->boundary.normalized
                    * JPG_REASS_PROGRESSIVE_BOUNDARY_RATIO)) {
    return true;
  }
  return bridge->boundary.valid
         && (!forward || !forward->have_boundary
             || bridge->boundary.normalized
                    < forward->boundary.normalized);
}

static inline bool jpg_reassembly_has_noncontiguous_tail_join(
    const CarveInfo *candidate,
    uint32_t fixed_prefix_blocks) {
  uint64_t num_blocks;
  int64_t previous;
  int64_t current;

  if (!candidate || !candidate->b || fixed_prefix_blocks == 0) {
    return false;
  }
  num_blocks = blockvector_get_num_blocks(candidate->b);
  if (num_blocks <= fixed_prefix_blocks) {
    return false;
  }
  previous = blockvector_get_apparent_blocknumber(
      candidate->b, num_blocks - 2);
  current = blockvector_get_apparent_blocknumber(candidate->b,
                                                  num_blocks - 1);
  return previous >= 0 && current >= 0 && current != previous + 1;
}

static inline bool jpg_reassembly_baseline_scatter_active(
    const CarveInfo *candidate,
    uint32_t fixed_prefix_blocks) {
  uint64_t num_blocks;
  uint32_t contiguous_run = 0;
  uint32_t noncontiguous_run = 0;
  bool active = false;

  if (!candidate || !candidate->b || fixed_prefix_blocks == 0) {
    return false;
  }
  num_blocks = blockvector_get_num_blocks(candidate->b);
  for (uint64_t block = fixed_prefix_blocks;
       block < num_blocks; block++) {
    int64_t previous = blockvector_get_apparent_blocknumber(
        candidate->b, block - 1);
    int64_t current = blockvector_get_apparent_blocknumber(
        candidate->b, block);

    if (previous < 0 || current < 0) {
      contiguous_run = 0;
      noncontiguous_run = 0;
      continue;
    }
    if (current == previous + 1) {
      contiguous_run++;
      noncontiguous_run = 0;
      if (active && contiguous_run >= 1) {
        active = false;
      }
    }
    else {
      noncontiguous_run++;
      contiguous_run = 0;
      if (!active && noncontiguous_run >= 2) {
        active = true;
      }
    }
  }
  return active;
}

static inline void jpg_reassembly_rank_global_progressive_fragment(
    CarveInfo *candidate,
    const JPGCarveState *prefix_state,
    uint32_t fixed_prefix_blocks,
    uint64_t saved_num_blocks,
    uint64_t saved_length,
    int64_t last_apparent,
    JpgOOOBridgeChoice *best) {
  uint64_t trials = 0;

  if (!candidate || !prefix_state || !prefix_state->valid || !best) {
    return;
  }
  for (int64_t apparent = 0;
       apparent < last_apparent && trials < JPG_REASS_OOO_MAX_TRIALS;
       apparent++) {
    JpgOOOBridgeChoice trial;
    bool evaluated;

    if (jpg_reassembly_checkpoint_requested()) {
      break;
    }
    if (!jpg_reassembly_ooo_apparent_available(candidate, apparent)) {
      continue;
    }
    trials++;
    memset(&trial, 0, sizeof(trial));
    evaluated = jpg_reassembly_evaluate_progressive_bridge(
        candidate, prefix_state, true, fixed_prefix_blocks,
        saved_num_blocks, saved_length, apparent, 1, 0, 0, false,
        &trial);
    if (evaluated && jpg_reassembly_progressive_choice_supported(&trial)) {
      jpg_reassembly_rank_progressive_bridge(best, &trial);
    }
    if (evaluated && trial.progressive_entropy_supported
        && !trial.progressive_entropy_complete
        && !trial.direct_validates && !trial.full_validates) {
      for (uint64_t run_len = 2;
           run_len <= JPG_REASS_OOO_MAX_RUN
             && trials < JPG_REASS_OOO_MAX_TRIALS;
           run_len++) {
        if (!jpg_reassembly_ooo_range_available(candidate, apparent,
                                                run_len, -1, 0)) {
          break;
        }
        trials++;
        memset(&trial, 0, sizeof(trial));
        if (!jpg_reassembly_evaluate_progressive_bridge(
                candidate, prefix_state, true, fixed_prefix_blocks,
                saved_num_blocks, saved_length, apparent, run_len,
                0, 0, false, &trial)) {
          break;
        }
        if (jpg_reassembly_progressive_choice_supported(&trial)) {
          jpg_reassembly_rank_progressive_bridge(best, &trial);
        }
        if (jpg_reassembly_progressive_bridge_conclusive(&trial)) {
          break;
        }
      }
    }
    if (best->direct_validates || best->full_validates) {
      break;
    }
  }
}

static inline bool jpg_reassembly_score_ooo_bridge_at(
    CarveInfo *candidate,
    const JPGCarveState *prefix_state,
    bool have_prefix_state,
    bool *validates,
    uint64_t *validates_to,
    uint32_t fixed_prefix_blocks,
    int64_t moved_start,
    JpgOOOBridgeChoice *best) {
  static const uint64_t suffix_probe_blocks = 8;
  uint64_t saved_num_blocks;
  uint64_t saved_length;
  int64_t tail_apparent;
  int64_t last_apparent;

  if (!candidate || !candidate->b || !validates || !validates_to || !best
      || blockvector_get_num_blocks(candidate->b) == 0) {
    return false;
  }

  saved_num_blocks = blockvector_get_num_blocks(candidate->b);
  saved_length = blockvector_get_data_length(candidate->b);
  tail_apparent =
      blockvector_get_apparent_blocknumber(candidate->b, saved_num_blocks - 1);
  last_apparent =
      (int64_t)filemirror_apparent_blocks(scalpel_state.filemirror);

  if (tail_apparent < 0 || moved_start <= tail_apparent + 1) {
    return false;
  }

  for (uint64_t run_len = JPG_REASS_OOO_MIN_RUN;
       run_len <= JPG_REASS_OOO_MAX_RUN;
       run_len++) {
    int64_t suffix_candidates[2] = {
        tail_apparent + 1,
        tail_apparent + (int64_t)run_len + 1
    };

    for (size_t suffix_idx = 0; suffix_idx < 2; suffix_idx++) {
      int64_t suffix_start = suffix_candidates[suffix_idx];
      int64_t suffix_stop =
          moved_start < last_apparent ? moved_start : last_apparent;
      int64_t next_header_apparent = -1;
      uint64_t suffix_len = 0;

      if (suffix_idx > 0 && suffix_start == suffix_candidates[0]) {
        continue;
      }
      if (jpg_reassembly_checkpoint_requested()) {
        goto no_bridge;
      }
      if (suffix_start < 0 || suffix_start >= suffix_stop) {
        continue;
      }
      if (jpg_reassembly_next_header_apparent(candidate, suffix_start,
                                              &next_header_apparent)
          && next_header_apparent > suffix_start
          && next_header_apparent < suffix_stop) {
        suffix_stop = next_header_apparent;
      }
      while (suffix_len < suffix_probe_blocks
             && suffix_start + (int64_t)suffix_len < suffix_stop
             && jpg_reassembly_ooo_apparent_available(
                    candidate, suffix_start + (int64_t)suffix_len)) {
        suffix_len++;
      }
      if (suffix_len < JPG_REASS_OOO_MIN_SUFFIX_PROBE) {
        continue;
      }
      JpgBoundaryScore boundary;

      memset(&boundary, 0, sizeof(boundary));
      if (jpg_reassembly_try_ooo_candidate_run(
              candidate, prefix_state, have_prefix_state,
              validates, validates_to, fixed_prefix_blocks,
              saved_num_blocks, saved_length,
              moved_start, run_len, suffix_start, suffix_len,
              false, true, false, &boundary)) {
        if (!best->found
            || boundary.normalized < best->boundary.normalized
            || (boundary.normalized == best->boundary.normalized
                && boundary.seam_mad < best->boundary.seam_mad)) {
          best->found = true;
          best->moved_start = moved_start;
          best->run_len = run_len;
          best->suffix_start = suffix_start;
          best->suffix_len = suffix_len;
          memcpy(&best->boundary, &boundary, sizeof(best->boundary));
        }
      }
    }
  }

no_bridge:
  jpg_reassembly_ooo_restore_candidate(candidate, saved_num_blocks,
                                       saved_length);
  return best->found;
}

static inline bool jpg_reassembly_score_inferred_bridge_at(
    CarveInfo *candidate,
    const JPGCarveState *prefix_state,
    bool have_prefix_state,
    uint32_t fixed_prefix_blocks,
    uint64_t saved_num_blocks,
    uint64_t saved_length,
    int64_t moved_start,
    uint64_t run_len,
    int64_t suffix_start,
    uint64_t suffix_len,
    JpgOOOBridgeChoice *best) {
  JpgBoundaryScore boundary;
  uint64_t trial_validates_to = 0;
  bool trial_validates = false;

  if (!best || run_len == 0) {
    return false;
  }

  memset(&boundary, 0, sizeof(boundary));
  if (!jpg_reassembly_try_ooo_candidate_run(
          candidate, prefix_state, have_prefix_state,
          &trial_validates, &trial_validates_to, fixed_prefix_blocks,
          saved_num_blocks, saved_length,
          moved_start, run_len, suffix_start, suffix_len,
          false, true, false, &boundary)) {
    return false;
  }

  if (!best->found
      || boundary.normalized < best->boundary.normalized
      || (boundary.normalized == best->boundary.normalized
          && boundary.seam_mad < best->boundary.seam_mad)) {
    best->found = true;
    best->moved_start = moved_start;
    best->run_len = run_len;
    best->suffix_start = suffix_start;
    best->suffix_len = suffix_len;
    memcpy(&best->boundary, &boundary, sizeof(best->boundary));
  }
  return true;
}

static inline bool jpg_reassembly_try_confidence_anchor_bridge(
    CarveInfo *candidate,
    const JPGCarveState *prefix_state,
    bool have_prefix_state,
    bool *validates,
    uint64_t *validates_to,
    uint32_t fixed_prefix_blocks,
    uint64_t saved_num_blocks,
    uint64_t saved_length,
    int64_t bridge_start,
    uint64_t bridge_len) {
  JPGCarveState trial_state;
  uint64_t trial_validates_to = 0;
  uint64_t trial_frontier;
  uint64_t trial_end;
  uint64_t committed_blocks;
  bool trial_validates;

  if (bridge_len == 0
      || !jpg_reassembly_ooo_range_available(candidate, bridge_start,
                                             bridge_len, 0, 0)
      || jpg_reassembly_ooo_range_has_zero(bridge_start, bridge_len)) {
    return false;
  }

  jpg_reassembly_ooo_restore_candidate(candidate, saved_num_blocks,
                                       saved_length);
  jpg_reassembly_ooo_append_range(candidate, bridge_start, bridge_len);

  if (have_prefix_state) {
    memcpy(&trial_state, prefix_state, sizeof(trial_state));
  }
  else {
    memset(&trial_state, 0, sizeof(trial_state));
  }

  trial_validates =
      jpg_reassembly_validate_direct(candidate, &trial_state,
                                     &trial_validates_to,
                                     fixed_prefix_blocks);
  trial_frontier = trial_validates_to;
  if (trial_state.valid && trial_state.huff_checkpoint.valid
      && trial_state.huff_checkpoint.byte_pos > trial_frontier + 1) {
    trial_frontier = trial_state.huff_checkpoint.byte_pos - 1;
  }

  trial_end = blockvector_get_data_length(candidate->b) - 1;
  if (!trial_validates && trial_frontier < trial_end) {
    if (jpg_reassembly_debug_candidate(candidate)) {
      lock_fprintf(stderr,
                   "[jpgdbg] anchor_bridge_reject start=%" PRId64
                   " len=%" PRIu64 " valid=%d frontier=%" PRIu64
                   " end=%" PRIu64 " state=%d huff=%d huff_byte=%" PRIu64 "\n",
                   bridge_start,
                   bridge_len,
                   trial_validates ? 1 : 0,
                   trial_frontier,
                   trial_end,
                   trial_state.valid ? 1 : 0,
                   trial_state.huff_checkpoint.valid ? 1 : 0,
                   trial_state.huff_checkpoint.byte_pos);
    }
    jpg_reassembly_ooo_restore_candidate(candidate, saved_num_blocks,
                                         saved_length);
    return false;
  }

  if (!trial_validates) {
    trial_validates_to = trial_end;
  }
  *validates = trial_validates;
  *validates_to = trial_validates_to;
  candidate->best_validates_to = trial_validates_to;
  if (trial_state.valid) {
    jpg_put_decoder_state(candidate->carvehashkey, &trial_state);
  }
  blockvector_set_data_length(candidate->b, trial_validates_to + 1);
  resize_blockvector(candidate->b,
                     CEILDIV(blockvector_get_data_length(candidate->b),
                             scalpel_state.blocksize));
  committed_blocks = blockvector_get_num_blocks(candidate->b);
  if (committed_blocks > 0) {
    int64_t last_apparent =
        blockvector_get_apparent_blocknumber(candidate->b,
                                             committed_blocks - 1);
    if (last_apparent >= 0) {
      candidate->newblock =
          filemirror_actual_blocknumber(scalpel_state.filemirror,
                                        last_apparent);
    }
  }
  jpg_reassembly_debug_dump("anchor_bridge_accept", candidate,
                            bridge_start, trial_validates_to);
  return true;
}

static inline bool jpg_reassembly_try_confidence_anchor_scan(
    CarveInfo *candidate,
    const JPGCarveState *prefix_state,
    bool have_prefix_state,
    bool *validates,
    uint64_t *validates_to,
    uint32_t fixed_prefix_blocks,
    uint64_t saved_num_blocks,
    uint64_t saved_length,
    int64_t tail_apparent,
    int64_t first_apparent,
    int64_t last_apparent,
    bool *checkpoint_hit) {
  static const uint64_t bridge_lengths[] = {4, 8, 16, 32, 64};
  static const uint64_t max_anchors_per_prefix = 64;
  uint64_t min_prefix_blocks = scalpel_state.blocksize > 0
                               && saved_length >= (uint64_t)scalpel_state.blocksize * 2
                               ? 2 : 1;
  int64_t *saved_apparents = NULL;

  if (checkpoint_hit) {
    *checkpoint_hit = false;
  }
  if (!candidate || !candidate->b || !validates || !validates_to
      || saved_num_blocks == 0 || saved_num_blocks < min_prefix_blocks
      || tail_apparent < 0 || last_apparent <= tail_apparent + 1) {
    return false;
  }

  saved_apparents = (int64_t *)calloc(saved_num_blocks, sizeof(*saved_apparents));
  check_memory_allocation(saved_apparents, __LINE__, __FILE__, "saved_apparents");
  for (uint64_t i = 0; i < saved_num_blocks; i++) {
    saved_apparents[i] =
        blockvector_get_apparent_blocknumber(candidate->b, i);
  }

  for (uint64_t prefix_blocks = min_prefix_blocks;
       prefix_blocks <= saved_num_blocks;
       prefix_blocks++) {
    JPGCarveState anchor_prefix_state;
    uint64_t prefix_length = prefix_blocks * scalpel_state.blocksize;
    uint64_t prefix_validates_to = 0;
    uint32_t trial_fixed_prefix_blocks = fixed_prefix_blocks;
    int64_t prefix_tail_apparent;
    uint64_t anchors_considered = 0;
    bool prefix_validates;

    if (prefix_length > saved_length) {
      prefix_length = saved_length;
    }
    if (jpg_reassembly_checkpoint_requested()) {
      resize_blockvector(candidate->b, saved_num_blocks);
      for (uint64_t i = 0; i < saved_num_blocks; i++) {
        blockvector_set_apparent_blocknumber(candidate->b, i,
                                             saved_apparents[i]);
        inflate_blockvector_single_block(candidate->b, i);
      }
      blockvector_set_data_length(candidate->b, saved_length);
      free(saved_apparents);
      if (checkpoint_hit) {
        *checkpoint_hit = true;
      }
      return false;
    }

    resize_blockvector(candidate->b, prefix_blocks);
    for (uint64_t i = 0; i < prefix_blocks; i++) {
      blockvector_set_apparent_blocknumber(candidate->b, i,
                                           saved_apparents[i]);
      inflate_blockvector_single_block(candidate->b, i);
    }
    blockvector_set_data_length(candidate->b, prefix_length);
    if (trial_fixed_prefix_blocks > prefix_blocks) {
      trial_fixed_prefix_blocks = (uint32_t)prefix_blocks;
    }
    if (trial_fixed_prefix_blocks == 0) {
      trial_fixed_prefix_blocks = 1;
    }

    prefix_tail_apparent =
        blockvector_get_apparent_blocknumber(candidate->b,
                                             prefix_blocks - 1);
    if (prefix_tail_apparent < 0) {
      continue;
    }

    memset(&anchor_prefix_state, 0, sizeof(anchor_prefix_state));
    if (have_prefix_state && prefix_blocks == saved_num_blocks) {
      memcpy(&anchor_prefix_state, prefix_state, sizeof(anchor_prefix_state));
    }
    prefix_validates =
        jpg_reassembly_validate_direct(candidate, &anchor_prefix_state,
                                       &prefix_validates_to,
                                       trial_fixed_prefix_blocks);
    if (jpg_reassembly_debug_candidate(candidate)) {
      lock_fprintf(stderr,
                   "[jpgdbg] anchor_prefix blocks=%" PRIu64
                   " len=%" PRIu64 " tail=%" PRId64
                   " fixed=%" PRIu32 " valid=%d vt=%" PRIu64
                   " state=%d huff=%d huff_byte=%" PRIu64 "\n",
                   prefix_blocks,
                   prefix_length,
                   prefix_tail_apparent,
                   trial_fixed_prefix_blocks,
                   prefix_validates ? 1 : 0,
                   prefix_validates_to,
                   anchor_prefix_state.valid ? 1 : 0,
                   anchor_prefix_state.huff_checkpoint.valid ? 1 : 0,
                   anchor_prefix_state.huff_checkpoint.byte_pos);
    }
    if (!prefix_validates && !anchor_prefix_state.valid
        && prefix_validates_to + 1 < blockvector_get_data_length(candidate->b)) {
      continue;
    }

    for (int64_t anchor = prefix_tail_apparent + 1;
         anchor < last_apparent;
         anchor++) {
      int64_t actual;
      BlockValidationDecision blocktype;

      if (jpg_reassembly_checkpoint_requested()) {
        resize_blockvector(candidate->b, saved_num_blocks);
        for (uint64_t i = 0; i < saved_num_blocks; i++) {
          blockvector_set_apparent_blocknumber(candidate->b, i,
                                               saved_apparents[i]);
          inflate_blockvector_single_block(candidate->b, i);
        }
        blockvector_set_data_length(candidate->b, saved_length);
        free(saved_apparents);
        if (checkpoint_hit) {
          *checkpoint_hit = true;
        }
        return false;
      }
      if (first_apparent >= 0 && anchor < first_apparent) {
        continue;
      }
      if (jpg_reassembly_apparent_in_blockvector_strict(candidate->b, anchor)) {
        continue;
      }
      actual = filemirror_actual_blocknumber(scalpel_state.filemirror, anchor);
      if (actual < 0
          || filemirror_actual_block_covered(scalpel_state.filemirror, actual)) {
        continue;
      }
      blocktype = filemirror_get_blocktype(scalpel_state.filemirror,
                                           actual,
                                           candidate->needleidx);
      if (blocktype != BLOCK_CONFIDENCE_VALID) {
        continue;
      }
      if (anchors_considered++ >= max_anchors_per_prefix) {
        if (jpg_reassembly_debug_candidate(candidate)) {
          lock_fprintf(stderr,
                       "[jpgdbg] anchor_prefix_limit blocks=%" PRIu64
                       " limit=%" PRIu64 " next_anchor=%" PRId64 "\n",
                       prefix_blocks,
                       max_anchors_per_prefix,
                       anchor);
        }
        break;
      }

      for (size_t i = 0;
           i < sizeof(bridge_lengths) / sizeof(bridge_lengths[0]);
           i++) {
        uint64_t bridge_len = bridge_lengths[i];
        int64_t bridge_start = anchor - (int64_t)bridge_len + 1;

        if (bridge_start <= prefix_tail_apparent) {
          continue;
        }
        if (jpg_reassembly_try_confidence_anchor_bridge(
                candidate, &anchor_prefix_state, anchor_prefix_state.valid,
                validates, validates_to, trial_fixed_prefix_blocks,
                prefix_blocks, prefix_length, bridge_start,
                bridge_len)) {
          free(saved_apparents);
          return true;
        }
      }
    }
  }

  resize_blockvector(candidate->b, saved_num_blocks);
  for (uint64_t i = 0; i < saved_num_blocks; i++) {
    blockvector_set_apparent_blocknumber(candidate->b, i,
                                         saved_apparents[i]);
    inflate_blockvector_single_block(candidate->b, i);
  }
  blockvector_set_data_length(candidate->b, saved_length);
  free(saved_apparents);
  return false;
}

static inline bool jpg_reassembly_try_ooo_run_repair(
    CarveInfo *candidate,
    const JPGCarveState *prefix_state,
    bool have_prefix_state,
    bool *validates,
    uint64_t *validates_to,
    uint32_t fixed_prefix_blocks,
    uint64_t min_run_len,
    uint64_t max_run_len,
    bool allow_global_scan,
    bool require_full_validate,
    bool reject_zero_run,
    uint64_t anchor_backscan_blocks,
    bool *checkpoint_hit) {
  uint64_t saved_num_blocks;
  uint64_t saved_length;
  int64_t tail_apparent;
  int64_t last_apparent;
  uint64_t trials = 0;
  bool exact_run;
  SearchSpec *spec;

  if (checkpoint_hit) {
    *checkpoint_hit = false;
  }

  if (!candidate || !candidate->b || !validates || !validates_to
      || blockvector_get_num_blocks(candidate->b) == 0
      || blockvector_get_num_blocks(candidate->b) < fixed_prefix_blocks) {
    return false;
  }

  if (min_run_len == 0 || min_run_len < JPG_REASS_OOO_MIN_RUN) {
    min_run_len = JPG_REASS_OOO_MIN_RUN;
  }
  if (max_run_len == 0 || max_run_len > JPG_REASS_OOO_MAX_RUN) {
    max_run_len = JPG_REASS_OOO_MAX_RUN;
  }
  if (min_run_len > max_run_len) {
    return false;
  }
  if (anchor_backscan_blocks == 0) {
    anchor_backscan_blocks = JPG_REASS_OOO_ANCHOR_BACKSCAN_BLOCKS;
  }
  exact_run = min_run_len == max_run_len;

  saved_num_blocks = blockvector_get_num_blocks(candidate->b);
  saved_length = blockvector_get_data_length(candidate->b);
  tail_apparent =
      blockvector_get_apparent_blocknumber(candidate->b, saved_num_blocks - 1);
  last_apparent = (int64_t)filemirror_apparent_blocks(scalpel_state.filemirror);
  if (tail_apparent < 0 || last_apparent <= 0) {
    return false;
  }

  spec = &scalpel_state.search_specs[candidate->needleidx];
  for (uint64_t run_len = min_run_len; run_len <= max_run_len; run_len++) {
    int64_t suffix_start = tail_apparent + (int64_t)run_len + 1;
    int64_t suffix_stop = last_apparent;
    int64_t next_header_apparent = -1;
    uint64_t suffix_len = 0;

    if (suffix_start < 0) {
      continue;
    }
    if (jpg_reassembly_next_header_apparent(candidate, suffix_start,
                                            &next_header_apparent)
        && next_header_apparent > suffix_start
        && next_header_apparent < suffix_stop) {
      suffix_stop = next_header_apparent;
    }
    while (suffix_len < JPG_REASS_OOO_SUFFIX_PROBE
           && suffix_start + (int64_t)suffix_len < suffix_stop
           && jpg_reassembly_ooo_apparent_available(candidate,
                                                    suffix_start + (int64_t)suffix_len)) {
      suffix_len++;
    }
    if (suffix_len == 0) {
      continue;
    }
    if (require_full_validate && reject_zero_run
        && last_apparent >= (int64_t)run_len) {
      int64_t scan_stop = last_apparent - (int64_t)run_len;
      uint64_t raw_scanned = 0;

      for (int64_t run_start = 0;
           run_start <= scan_stop
           && raw_scanned < JPG_REASS_OOO_RAW_ANCHOR_SCAN_MAX;
           run_start++, raw_scanned++) {
        if (jpg_reassembly_checkpoint_requested()) {
          jpg_reassembly_ooo_restore_candidate(candidate,
                                               saved_num_blocks,
                                               saved_length);
          if (checkpoint_hit) {
            *checkpoint_hit = true;
          }
          return false;
        }
        if (!jpg_reassembly_ooo_followed_by_raw_header(run_start, run_len)) {
          continue;
        }
        if (trials++ >= JPG_REASS_OOO_MAX_TRIALS) {
          jpg_reassembly_ooo_restore_candidate(candidate, saved_num_blocks,
                                               saved_length);
          return false;
        }
        if (jpg_reassembly_try_ooo_candidate_run(candidate, prefix_state,
                                                 have_prefix_state,
                                                 validates, validates_to,
                                                 fixed_prefix_blocks,
                                                 saved_num_blocks,
                                                 saved_length,
                                                 run_start, run_len,
                                                 suffix_start, suffix_len,
                                                 require_full_validate,
                                                 reject_zero_run, true, NULL)) {
          return true;
        }
      }
    }
    for (uint64_t backscan = run_len;
         backscan <= anchor_backscan_blocks;
         backscan += run_len) {
      for (uint64_t header_index = 0;
           header_index < spec->offsets.numheaders;
           header_index++) {
        int64_t header_apparent;
        int64_t run_start;

        if (jpg_reassembly_checkpoint_requested()) {
          jpg_reassembly_ooo_restore_candidate(candidate,
                                               saved_num_blocks,
                                               saved_length);
          if (checkpoint_hit) {
            *checkpoint_hit = true;
          }
          return false;
        }

        if (!jpg_reassembly_header_anchor_apparent(candidate, header_index,
                                                   &header_apparent)
            || header_apparent < (int64_t)backscan) {
          continue;
        }
        run_start = header_apparent - (int64_t)backscan;
        if (trials++ >= JPG_REASS_OOO_MAX_TRIALS) {
          jpg_reassembly_ooo_restore_candidate(candidate, saved_num_blocks,
                                               saved_length);
          return false;
        }
        if (jpg_reassembly_try_ooo_candidate_run(candidate, prefix_state,
                                                 have_prefix_state,
                                                 validates, validates_to,
                                                 fixed_prefix_blocks,
                                                 saved_num_blocks,
                                                 saved_length,
                                                 run_start, run_len,
                                                 suffix_start, suffix_len,
                                                 require_full_validate,
                                                 reject_zero_run, true, NULL)) {
          return true;
        }
      }
    }

    if (last_apparent >= (int64_t)run_len) {
      if (jpg_reassembly_checkpoint_requested()) {
        jpg_reassembly_ooo_restore_candidate(candidate,
                                             saved_num_blocks,
                                             saved_length);
        if (checkpoint_hit) {
          *checkpoint_hit = true;
        }
        return false;
      }
      for (uint64_t backscan = run_len;
           backscan <= anchor_backscan_blocks
           && last_apparent >= (int64_t)backscan;
           backscan += run_len) {
        int64_t eof_run_start = last_apparent - (int64_t)backscan;

        if (trials++ >= JPG_REASS_OOO_MAX_TRIALS) {
          jpg_reassembly_ooo_restore_candidate(candidate, saved_num_blocks,
                                               saved_length);
          return false;
        }
        if (jpg_reassembly_try_ooo_candidate_run(candidate, prefix_state,
                                                 have_prefix_state,
                                                 validates, validates_to,
                                                 fixed_prefix_blocks,
                                                 saved_num_blocks,
                                                 saved_length,
                                                 eof_run_start, run_len,
                                                 suffix_start, suffix_len,
                                                 require_full_validate,
                                                 reject_zero_run, true, NULL)) {
          return true;
        }
      }
    }

    if (!(require_full_validate && reject_zero_run)
        && last_apparent >= (int64_t)run_len) {
      int64_t scan_stop = last_apparent - (int64_t)run_len;
      uint64_t raw_scanned = 0;

      for (int64_t run_start = 0;
           run_start <= scan_stop
           && raw_scanned < JPG_REASS_OOO_RAW_ANCHOR_SCAN_MAX;
           run_start++, raw_scanned++) {
        if (jpg_reassembly_checkpoint_requested()) {
          jpg_reassembly_ooo_restore_candidate(candidate,
                                               saved_num_blocks,
                                               saved_length);
          if (checkpoint_hit) {
            *checkpoint_hit = true;
          }
          return false;
        }
        if (!jpg_reassembly_ooo_followed_by_raw_header(run_start, run_len)) {
          continue;
        }
        if (trials++ >= JPG_REASS_OOO_MAX_TRIALS) {
          jpg_reassembly_ooo_restore_candidate(candidate, saved_num_blocks,
                                               saved_length);
          return false;
        }
        if (jpg_reassembly_try_ooo_candidate_run(candidate, prefix_state,
                                                 have_prefix_state,
                                                 validates, validates_to,
                                                 fixed_prefix_blocks,
                                                 saved_num_blocks,
                                                 saved_length,
                                                 run_start, run_len,
                                                 suffix_start, suffix_len,
                                                 require_full_validate,
                                                 reject_zero_run, true, NULL)) {
          return true;
        }
      }
    }

    if (allow_global_scan
        && (suffix_len >= JPG_REASS_OOO_GLOBAL_MIN_SUFFIX_PROBE
            || exact_run)
        && last_apparent >= (int64_t)run_len) {
      int64_t scan_stop = last_apparent - (int64_t)run_len;

      for (int64_t run_start = 0; run_start <= scan_stop; run_start++) {
        if (jpg_reassembly_checkpoint_requested()) {
          jpg_reassembly_ooo_restore_candidate(candidate,
                                               saved_num_blocks,
                                               saved_length);
          if (checkpoint_hit) {
            *checkpoint_hit = true;
          }
          return false;
        }

        if (trials++ >= JPG_REASS_OOO_MAX_TRIALS) {
          jpg_reassembly_ooo_restore_candidate(candidate, saved_num_blocks,
                                               saved_length);
          return false;
        }
        if (jpg_reassembly_try_ooo_candidate_run(candidate, prefix_state,
                                                 have_prefix_state,
                                                 validates, validates_to,
                                                 fixed_prefix_blocks,
                                                 saved_num_blocks,
                                                 saved_length,
                                                 run_start, run_len,
                                                 suffix_start, suffix_len,
                                                 require_full_validate,
                                                 reject_zero_run, true, NULL)) {
          return true;
        }
      }
    }
  }

  jpg_reassembly_ooo_restore_candidate(candidate, saved_num_blocks,
                                       saved_length);
  return false;
}

static inline void jpg_reassembly(ThreadWork *work, CarveInfo **c,
                                  uuid_string_t uuidp,
                                  uuid_string_t uuidc) {
  static const int64_t JPG_REASSEMBLY_FORWARD_SCAN_WINDOW = 128;
  static const int64_t JPG_REASSEMBLY_NEARBY_SCAN_WINDOW = 4096;
  static const uint64_t JPG_REASSEMBLY_BOUNDARY_SLACK = 4;
  bool validates = false;
  uint64_t validates_to = 0;
  uint64_t tick = 0;
  uint64_t gallop = 0;
  CarveInfo *candidate = *c;
  JPGReassemblyMaterializationCache materialization_cache;
  JPGReassemblyMaterializationCache *previous_materialization_cache =
      jpg_reassembly_materialization_cache;
  JpgBoundaryPreviewCache boundary_preview_cache;
  JpgBoundaryPreviewCache *previous_boundary_preview_cache =
      jpg_boundary_preview_cache;
  JpgOOOBridgeShortlist bridge_shortlist;
  JpgOOOBridgeShortlist *previous_bridge_shortlist =
      jpg_reassembly_bridge_shortlist;
  JPGReassemblyFallback fallback;
  JpgReassemblyRetrySearch *retry_search;
  JpgReassemblyRetrySearch *previous_retry_search = jpg_active_retry_search;
  void *previous_retry_key = jpg_active_retry_key;
  bool progressive_scatter_followup = false;
  bool progressive_format = false;
  bool format_known = false;
  uint32_t structural_prefix_blocks = 1;
  bool progressive_seed_prepared = false;
  bool baseline_seed_prepared = false;
  bool baseline_seed_needs_search = false;
  JPGForwardScanProgress forward_progress;

  {
    JPGCarveState saved;
    (void)jpg_reassembly_load_saved_state(candidate, &saved);
    forward_progress = saved.forward_scan_progress;
  }

  memset(&materialization_cache, 0, sizeof(materialization_cache));
  memset(&boundary_preview_cache, 0, sizeof(boundary_preview_cache));
  memset(&bridge_shortlist, 0, sizeof(bridge_shortlist));
  memset(&fallback, 0, sizeof(fallback));
  // Each retry frame includes decoder state; keep the history off the worker stack.
  retry_search = calloc(1, sizeof(*retry_search));
  check_memory_allocation(retry_search, __LINE__, __FILE__,
                          "jpg reassembly retry search");
  jpg_load_retry_checkpoint(candidate, retry_search);
  jpg_active_retry_search = retry_search;
  jpg_active_retry_key = candidate->carvehashkey;
  jpg_reassembly_materialization_cache = &materialization_cache;
  jpg_boundary_preview_cache = &boundary_preview_cache;
  jpg_reassembly_bridge_shortlist = &bridge_shortlist;

  if (scalpel_state.mode_verbose) {
    lock_fprintf(stdout,
                 "\nReassembly thread # %1d waking up to process JPG candidate "
                 "with blockvector %p and UUIDs\n%s / %s.\n",
                 work->id, candidate->b, uuidp, uuidc);
  }

  candidate->chopped = false;
  candidate->fastpath = false;
  candidate->newblock = -1;
  inflate_blockvector(candidate->b);

  while (1) {
    uint64_t num_blocks;
    uint64_t oldlength;
    uint64_t accept_threshold;
    int64_t tail_apparent;
    int64_t tail_actual;
    int64_t first_apparent;
    int64_t last_apparent;
    int64_t natural_tail_start = -1;
    JPGCarveState prefix_state;
    bool have_prefix_state;
    JPGReassemblyForwardChoice best_choice;
    JpgOOOBridgeChoice best_bridge;
    JpgOOOBridgeChoice bridge_to_commit;
    JpgOOOBridgeChoice best_baseline_entry;
    bool advanced = false;
    bool backward_choice_found = false;
    bool global_baseline_search = false;
    bool global_progressive_search = false;
    bool baseline_scatter_active = false;
    bool baseline_scatter_ambiguous = false;
    bool baseline_bridge_ambiguous = false;
    bool strong_baseline_entry = false;
    bool progressive_global_ambiguous = false;
    bool baseline_entry_verify = false;
    bool progressive_entry_verify = progressive_scatter_followup;
    bool prefer_bridge = false;
    bool strong_forward_continuation = false;
    bool raw_jump_requires_bridge = false;
    bool nearby_baseline_bridge_selected = false;
    bool small_gap_rate_available = false;
    bool small_gap_rate_consistent = false;
    bool small_gap_rate_strong = false;
    bool small_gap_forward_supported = false;
    bool small_gap_boundary_unsupported = false;
    bool shallow_baseline_gap_ambiguous = false;
    double small_gap_rate_deviation = DBL_MAX;
    bool have_expected_restart = false;
    uint8_t expected_restart = 0;
    uint32_t scan_mode = jpg_reassembly_scan_mode();
    bool wide_scan = scan_mode == 1 || scan_mode == 2;
    bool confidence_order = scan_mode == 2;
    bool anchor_scan = scan_mode == 3;

    if (reassembly_check_max_size(work->id, candidate, uuidp, uuidc)) {
      if (jpg_reassembly_restore_retry(candidate, retry_search, &validates,
                                       &validates_to, false)) {
        gallop = 0;
        progressive_scatter_followup = false;
        if (validates) {
          candidate->flavor = VALIDATED;
          goto done_write_candidate;
        }
        continue;
      }
      if (jpg_reassembly_restore_fallback(candidate, &fallback, &validates,
                                          &validates_to)) {
        gallop = 0;
        if (validates) {
          candidate->flavor = VALIDATED;
          goto done_write_candidate;
        }
        continue;
      }
      if (jpg_reassembly_try_pending_hidden_rollback(
              candidate, &validates, &validates_to)) {
        gallop = 0;
        progressive_scatter_followup = false;
        continue;
      }
      if (!scalpel_state.write_promising) {
        destroy_candidate(&candidate);
        goto done_do_not_write_candidate;
      }
      goto done_write_candidate;
    }

    if (reassembly_check_kill_queue(work, &candidate, uuidp, uuidc)) {
      goto done_do_not_write_candidate;
    }

    if (blockvector_get_num_blocks(candidate->b) == 0) {
      destroy_candidate(&candidate);
      goto done_do_not_write_candidate;
    }

    validates = reassembly_check_validation(work->id, candidate,
                                            &validates_to, uuidp, uuidc);
    jpg_reassembly_debug_dump(validates ? "forward_current_valid"
                                        : "forward_current",
                              candidate, -1, validates_to);
    if (!validates
        && validates_to + 1 < blockvector_get_data_length(candidate->b)) {
      JPGCarveState cold_state;
      JpgWrongBlockResult current_wrongblock = jpg_wrongblock_result;
      JpgWrongBlockResult cold_wrongblock;
      uint64_t cold_validates_to = 0;
      bool cold_validates;

      memset(&cold_state, 0, sizeof(cold_state));
      cold_validates =
          jpg_reassembly_validate_direct(candidate, &cold_state,
                                         &cold_validates_to,
                                         jpg_reassembly_get_fixed_prefix_blocks(candidate));
      cold_wrongblock = jpg_wrongblock_result;
      if (jpg_reassembly_cold_validation_is_better(
              cold_validates, cold_validates_to, &cold_wrongblock,
              validates_to, &current_wrongblock)) {
        validates = cold_validates;
        validates_to = cold_validates_to;
        jpg_wrongblock_result = cold_wrongblock;
        if (cold_state.valid) {
          jpg_put_decoder_state(candidate->carvehashkey, &cold_state);
        }
        jpg_reassembly_debug_dump(cold_validates ? "forward_current_cold_valid"
                                                 : "forward_current_cold",
                                  candidate, -1, validates_to);
      }
      else {
        jpg_wrongblock_result = current_wrongblock;
      }
    }
    if (validates) {
      candidate->flavor = VALIDATED;
      blockvector_set_data_length(candidate->b, validates_to + 1);
      resize_blockvector(candidate->b,
                         CEILDIV(blockvector_get_data_length(candidate->b),
                                 scalpel_state.blocksize));
      goto done_write_candidate;
    }

    {
      bool run_order_changed = false;
      bool run_order_checkpoint = false;

      if (jpg_reassembly_try_terminal_run_order_repair(
              candidate, &validates, &validates_to,
              jpg_reassembly_get_fixed_prefix_blocks(candidate),
              true,
              &run_order_changed,
              &run_order_checkpoint)) {
        candidate->flavor = PROMISING;
        if (!scalpel_state.write_promising) {
          destroy_candidate(&candidate);
          goto done_do_not_write_candidate;
        }
        goto done_write_candidate;
      }
      if (run_order_changed) {
        gallop = 0;
        progressive_scatter_followup = false;
        continue;
      }
      if (run_order_checkpoint
          && jpg_reassembly_time_to_checkpoint(
                 work->id, candidate, uuidp, uuidc, &fallback,
                 &validates, &validates_to,
                 &forward_progress)) {
        goto done_do_not_write_candidate;
      }
    }

    {
      uint64_t current_length = blockvector_get_data_length(candidate->b);
      uint64_t validated_length = validates_to + 1;

      if (validated_length < current_length) {
        uint64_t shortfall = current_length - validated_length;

        if (current_length % scalpel_state.blocksize == 0
            && shortfall <= JPG_REASSEMBLY_BOUNDARY_SLACK
            && !jpg_wrongblock_result.detected) {
          validates_to = current_length - 1;
          validated_length = current_length;
        } else {
          uint64_t keep_blocks = CEILDIV(validated_length, scalpel_state.blocksize);
          if (keep_blocks == 0) {
            keep_blocks = 1;
          }
          blockvector_set_data_length(candidate->b, validated_length);
          resize_blockvector(candidate->b, keep_blocks);
        }
      }
    }
    jpg_reassembly_finish_mapped_tail(candidate, &validates, &validates_to);
    if (validates) {
      candidate->flavor = VALIDATED;
      resize_blockvector(candidate->b,
                         CEILDIV(blockvector_get_data_length(candidate->b),
                                 scalpel_state.blocksize));
      goto done_write_candidate;
    }
    if (validates_to > candidate->best_validates_to) {
      candidate->best_validates_to = validates_to;
    }

    if (jpg_reassembly_time_to_checkpoint(work->id, candidate, uuidp, uuidc,
                                          &fallback, &validates,
                                          &validates_to,
                                          &forward_progress)) {
      goto done_do_not_write_candidate;
    }

    num_blocks = blockvector_get_num_blocks(candidate->b);
    oldlength = blockvector_get_data_length(candidate->b);
    tail_apparent =
        blockvector_get_apparent_blocknumber(candidate->b, num_blocks - 1);
    tail_actual =
        blockvector_get_actual_blocknumber(candidate->b, num_blocks - 1);
    first_apparent =
        blockvector_get_apparent_blocknumber(candidate->b, 0);
    last_apparent = (int64_t)filemirror_apparent_blocks(scalpel_state.filemirror);
    if (tail_apparent < 0) {
      break;
    }

    memset(&prefix_state, 0, sizeof(prefix_state));
    have_prefix_state =
        jpg_reassembly_load_saved_state(candidate, &prefix_state);
    if (!format_known) {
      bool detected_format = false;

      progressive_format =
          jpg_reassembly_candidate_is_progressive(
              candidate, &structural_prefix_blocks, &detected_format);
      format_known = detected_format;
    }
    if (format_known && have_prefix_state) {
      prefix_state.is_progressive = progressive_format;
      if (prefix_state.reassembly_seed_checked) {
        progressive_seed_prepared = true;
        baseline_seed_prepared = true;
        baseline_seed_needs_search =
            prefix_state.reassembly_seed_needs_search;
        prefix_state.reassembly_seed_needs_search = false;
      }
    }
    else {
      uint64_t rebuilt_validates_to = 0;

      memset(&prefix_state, 0, sizeof(prefix_state));
      (void)jpg_reassembly_validate_direct(
          candidate, &prefix_state, &rebuilt_validates_to,
          jpg_reassembly_get_fixed_prefix_blocks(candidate));
      have_prefix_state = prefix_state.valid;
      if (have_prefix_state) {
        if (format_known) {
          prefix_state.is_progressive = progressive_format;
        }
        jpg_put_decoder_state(candidate->carvehashkey, &prefix_state);
      }
    }
    if (jpg_forward_source_matches(candidate, &forward_progress,
                                    num_blocks, oldlength)) {
      baseline_seed_prepared = forward_progress.baseline_seed_prepared;
      progressive_seed_prepared = forward_progress.progressive_seed_prepared;
      baseline_seed_needs_search = forward_progress.baseline_seed_needs_search;
    }
    if (format_known && progressive_format && !progressive_seed_prepared) {
      uint64_t seed_blocks = structural_prefix_blocks;
      uint64_t seed_length;
      uint64_t rebuilt_validates_to = 0;
      bool trimmed = false;

      if (seed_blocks > num_blocks) {
        seed_blocks = num_blocks;
      }
      seed_length = seed_blocks * (uint64_t)scalpel_state.blocksize;
      if (seed_length > oldlength) {
        seed_length = oldlength;
      }
      if (num_blocks > seed_blocks) {
        resize_blockvector(candidate->b, seed_blocks);
        blockvector_set_data_length(candidate->b, seed_length);
        candidate->best_validates_to = seed_length > 0 ? seed_length - 1 : 0;
        candidate->newblock = blockvector_get_actual_blocknumber(
            candidate->b, seed_blocks - 1);
        memset(&prefix_state, 0, sizeof(prefix_state));
        (void)jpg_reassembly_validate_direct(
            candidate, &prefix_state, &rebuilt_validates_to,
            (uint32_t)seed_blocks);
        have_prefix_state = prefix_state.valid;
        trimmed = true;
      }
      if (have_prefix_state) {
        prefix_state.is_progressive = true;
        prefix_state.reassembly_seed_checked = true;
        prefix_state.reassembly_seed_needs_search = false;
        jpg_put_decoder_state(candidate->carvehashkey, &prefix_state);
      }
      progressive_seed_prepared = true;
      if (trimmed) {
        continue;
      }
    }
    if (format_known && !progressive_format && !baseline_seed_prepared) {
      bool inspected = false;
      bool seed_needs_search = false;

      if (scalpel_state.blocksize >= JPG_REASS_BASELINE_SEED_PROBE_BYTES
          && have_prefix_state && structural_prefix_blocks > 0
          && num_blocks == (uint64_t)structural_prefix_blocks + 1) {
        int64_t body_apparent = blockvector_get_apparent_blocknumber(
            candidate->b, structural_prefix_blocks);
        uint64_t seed_length =
            (uint64_t)structural_prefix_blocks * scalpel_state.blocksize;
        uint64_t rebuilt_validates_to = 0;
        JpgReassemblyEntropyProbe seed_probe;
        bool probe_available;
        bool discard_body = false;

        resize_blockvector(candidate->b, structural_prefix_blocks);
        blockvector_set_data_length(candidate->b, seed_length);
        memset(&prefix_state, 0, sizeof(prefix_state));
        (void)jpg_reassembly_validate_direct(
            candidate, &prefix_state, &rebuilt_validates_to,
            structural_prefix_blocks);
        have_prefix_state = prefix_state.valid;
        memset(&seed_probe, 0, sizeof(seed_probe));
        probe_available =
            have_prefix_state
            && jpg_reassembly_probe_baseline_entropy(
                   candidate, &prefix_state, structural_prefix_blocks,
                   seed_length, body_apparent, 1, -1, 0, &seed_probe);
        if (probe_available && seed_probe.supported
            && (!seed_probe.clean || !seed_probe.reaches_probe_end)
            && jpg_huffman_failure_is_hard(seed_probe.failure)) {
          discard_body = true;
        }
        if (!discard_body) {
          jpg_reassembly_ooo_append_range(candidate, body_apparent, 1);
          blockvector_set_data_length(candidate->b, oldlength);
          memset(&prefix_state, 0, sizeof(prefix_state));
          (void)jpg_reassembly_validate_direct(
              candidate, &prefix_state, &rebuilt_validates_to,
              structural_prefix_blocks);
          have_prefix_state = prefix_state.valid;
        }
        candidate->best_validates_to =
            blockvector_get_data_length(candidate->b) - 1;
        candidate->newblock = blockvector_get_actual_blocknumber(
            candidate->b, blockvector_get_num_blocks(candidate->b) - 1);
        seed_needs_search = discard_body;
        inspected = true;
      }
      else if (scalpel_state.blocksize < JPG_REASS_BASELINE_SEED_PROBE_BYTES
               && structural_prefix_blocks > 0
               && num_blocks > (uint64_t)structural_prefix_blocks) {
        int64_t body_apparent = blockvector_get_apparent_blocknumber(
            candidate->b, structural_prefix_blocks);
        uint64_t original_body_blocks =
            num_blocks - (uint64_t)structural_prefix_blocks;
        uint64_t retained_body_blocks = 0;
        uint64_t probe_blocks;
        uint64_t seed_length =
            (uint64_t)structural_prefix_blocks * scalpel_state.blocksize;
        uint64_t rebuilt_validates_to = 0;
        JpgReassemblyEntropyProbe seed_probe;
        JpgBoundaryScore seed_boundary;
        bool probe_available;

        while (retained_body_blocks < original_body_blocks) {
          uint64_t slot = (uint64_t)structural_prefix_blocks
                          + retained_body_blocks;
          int64_t apparent = blockvector_get_apparent_blocknumber(
              candidate->b, slot);
          int64_t actual = blockvector_get_actual_blocknumber(
              candidate->b, slot);

          if (apparent != body_apparent + (int64_t)retained_body_blocks
              || actual < 0
              || filemirror_actual_block_is_zero(scalpel_state.filemirror,
                                                  actual)) {
            break;
          }
          retained_body_blocks++;
        }
        seed_needs_search = retained_body_blocks < original_body_blocks;

        memset(&seed_boundary, 0, sizeof(seed_boundary));
        if (retained_body_blocks > 0) {
          uint64_t seed_materialized_length = 0;
          char *seed_materialized = jpg_reassembly_materialize_candidate(
              candidate, &seed_materialized_length);

          seed_boundary = jpg_boundary_score(seed_materialized, seed_length,
                                             seed_materialized_length);
        }

        resize_blockvector(candidate->b, structural_prefix_blocks);
        blockvector_set_data_length(candidate->b, seed_length);
        memset(&prefix_state, 0, sizeof(prefix_state));
        (void)jpg_reassembly_validate_direct(
            candidate, &prefix_state, &rebuilt_validates_to,
            structural_prefix_blocks);
        have_prefix_state = prefix_state.valid;
        memset(&seed_probe, 0, sizeof(seed_probe));
        if (!have_prefix_state) {
          retained_body_blocks = 0;
          seed_needs_search = true;
        }
        probe_blocks = retained_body_blocks;
        if (probe_blocks > 0
            && jpg_reassembly_ooo_apparent_available(
                   candidate, body_apparent + (int64_t)probe_blocks)
            && !jpg_reassembly_ooo_range_has_zero(
                   body_apparent + (int64_t)probe_blocks, 1)) {
          probe_blocks++;
        }
        probe_available =
            have_prefix_state && probe_blocks > 0
            && jpg_reassembly_probe_baseline_entropy(
                   candidate, &prefix_state, structural_prefix_blocks,
                   seed_length, body_apparent, probe_blocks, -1, 0,
                   &seed_probe);
        if (probe_available && seed_probe.supported
            && (!seed_probe.clean || !seed_probe.reaches_probe_end)
            && jpg_huffman_failure_is_hard(seed_probe.failure)) {
          uint64_t supported_body_blocks = 0;

          // Retain every complete body block supported by the entropy probe.
          // The boundary score can reject the body only when the probe cannot
          // establish any progress beyond the structural prefix.
          if (seed_probe.frontier + 1 > seed_length) {
            supported_body_blocks =
                (seed_probe.frontier + 1 - seed_length)
                / scalpel_state.blocksize;
            if (supported_body_blocks < retained_body_blocks) {
              retained_body_blocks = supported_body_blocks;
            }
          }
          else if (seed_boundary.valid
                   && seed_boundary.normalized
                          > JPG_REASS_BASELINE_BRIDGE_SCORE_LIMIT) {
            retained_body_blocks = 0;
          }
          seed_needs_search = true;
        }
        if (retained_body_blocks > 0) {
          uint64_t retained_length =
              ((uint64_t)structural_prefix_blocks + retained_body_blocks)
              * scalpel_state.blocksize;

          if (retained_length > oldlength) {
            retained_length = oldlength;
          }
          jpg_reassembly_ooo_append_range(candidate, body_apparent,
                                          retained_body_blocks);
          blockvector_set_data_length(candidate->b, retained_length);
          memset(&prefix_state, 0, sizeof(prefix_state));
          (void)jpg_reassembly_validate_direct(
              candidate, &prefix_state, &rebuilt_validates_to,
              structural_prefix_blocks);
          have_prefix_state = prefix_state.valid;
        }
        candidate->best_validates_to =
            blockvector_get_data_length(candidate->b) - 1;
        candidate->newblock = blockvector_get_actual_blocknumber(
            candidate->b, blockvector_get_num_blocks(candidate->b) - 1);
        inspected = true;
      }
      if (have_prefix_state) {
        prefix_state.is_progressive = false;
        prefix_state.reassembly_seed_checked = true;
        prefix_state.reassembly_seed_needs_search = seed_needs_search;
        baseline_seed_needs_search = seed_needs_search;
        jpg_put_decoder_state(candidate->carvehashkey, &prefix_state);
      }
      baseline_seed_prepared = true;
      if (inspected) {
        continue;
      }
    }
    if (format_known && have_prefix_state) {
      if (progressive_format) {
        if (jpg_reassembly_has_noncontiguous_tail_join(
                candidate, structural_prefix_blocks)) {
          // verify the next transition after entering a remote fragment, then
          // return to the normal fast path once its blocks prove contiguous.
          progressive_entry_verify = true;
        }
      }
      else if (jpg_reassembly_has_noncontiguous_tail_join(
                   candidate, structural_prefix_blocks)) {
        // verify the transition after every baseline discontinuity, then
        // return to the fast path as soon as the apparent blocks are adjacent.
        baseline_entry_verify = true;
      }
      if (!progressive_format) {
        if (prefix_state.hidden_boundary_recovery) {
          JPGHiddenBoundaryProgress *progress =
              &prefix_state.hidden_boundary_progress;

          baseline_scatter_active =
              !progress->active
              || (num_blocks == progress->origin_blocks
                  && oldlength == progress->origin_length);
        }
        else {
          baseline_scatter_active =
              jpg_reassembly_baseline_scatter_active(
                  candidate, structural_prefix_blocks);
        }
        if (baseline_seed_needs_search
            && num_blocks == structural_prefix_blocks) {
          baseline_scatter_active = true;
        }
        baseline_entry_verify =
            baseline_entry_verify || baseline_scatter_active;
      }
    }
    if (format_known && have_prefix_state && !progressive_format) {
      have_expected_restart = jpg_reassembly_expected_restart_marker(
          candidate, &prefix_state, &expected_restart);
      if (jpg_reassembly_debug_candidate(candidate)
          && prefix_state.restart_interval > 0) {
        lock_fprintf(stderr,
                     "[jpgdbg] restart_expected available=%d rst=%u"
                     " huffman=%d\n",
                     have_expected_restart ? 1 : 0, expected_restart,
                     prefix_state.huff_checkpoint.valid ? 1 : 0);
      }
    }

    if (!advanced && format_known && have_prefix_state
        && !prefix_state.is_progressive
        && prefix_state.hidden_boundary_recovery
        && jpg_reassembly_try_hidden_rejected_successor(
               candidate, &prefix_state, &validates, &validates_to,
               jpg_reassembly_get_fixed_prefix_blocks(candidate),
               num_blocks, oldlength)) {
      if (validates) {
        candidate->flavor = VALIDATED;
        goto done_write_candidate;
      }
      advanced = true;
    }
    if (jpg_reassembly_checkpoint_requested()
        && jpg_reassembly_time_to_checkpoint(
               work->id, candidate, uuidp, uuidc, &fallback,
               &validates, &validates_to,
               &forward_progress)) {
      goto done_do_not_write_candidate;
    }
    if (advanced) {
      continue;
    }

    if (!advanced && format_known && have_prefix_state
        && !prefix_state.is_progressive
        && prefix_state.hidden_boundary_recovery
        && jpg_reassembly_try_footer_tail(
               candidate, &prefix_state, &validates, &validates_to,
               jpg_reassembly_get_fixed_prefix_blocks(candidate),
               num_blocks, oldlength)) {
      candidate->flavor = VALIDATED;
      goto done_write_candidate;
    }
    if (jpg_reassembly_checkpoint_requested()
        && jpg_reassembly_time_to_checkpoint(
               work->id, candidate, uuidp, uuidc, &fallback,
               &validates, &validates_to,
               &forward_progress)) {
      goto done_do_not_write_candidate;
    }

    if (!advanced && format_known && have_prefix_state
        && !prefix_state.is_progressive
        && prefix_state.hidden_boundary_recovery
        && jpg_reassembly_try_hidden_natural_run(
               candidate, &prefix_state, &validates, &validates_to,
               jpg_reassembly_get_fixed_prefix_blocks(candidate),
               num_blocks, oldlength)) {
      if (validates) {
        candidate->flavor = VALIDATED;
        goto done_write_candidate;
      }
      advanced = true;
    }
    if (jpg_reassembly_checkpoint_requested()
        && jpg_reassembly_time_to_checkpoint(
               work->id, candidate, uuidp, uuidc, &fallback,
               &validates, &validates_to,
               &forward_progress)) {
      goto done_do_not_write_candidate;
    }
    if (advanced) {
      continue;
    }

    accept_threshold = oldlength;
    {
      uint64_t previous_block_boundary = num_blocks * scalpel_state.blocksize;
      if (previous_block_boundary > accept_threshold) {
        accept_threshold = previous_block_boundary;
      }
    }

    memset(&best_choice, 0, sizeof(best_choice));
    best_choice.apparent = -1;
    best_choice.actual = -1;
    memset(&best_bridge, 0, sizeof(best_bridge));
    memset(&best_baseline_entry, 0, sizeof(best_baseline_entry));
    memset(&bridge_shortlist, 0, sizeof(bridge_shortlist));

    resize_blockvector(candidate->b, num_blocks + 1);
    blockvector_set_apparent_blocknumber(candidate->b, num_blocks, -1);
    blockvector_free_choices(candidate->b, num_blocks);

    {
      uint32_t scan_passes =
          have_prefix_state && prefix_state.hidden_boundary_recovery
              ? 0 : (confidence_order ? 7 : 1);
      JPGReassemblyForwardChoice choice_before_backward;
      bool stop_forward_scan = false;
      bool contiguous_tail_probed = false;
      uint32_t first_scan_pass = 0;
      int64_t resume_actual = -1;

      memset(&choice_before_backward, 0, sizeof(choice_before_backward));
      if (jpg_forward_progress_matches(candidate, &forward_progress,
                                        num_blocks, oldlength, scan_mode)
          && forward_progress.scan_pass <= scan_passes
          && (forward_progress.pass_complete || forward_progress.next_actual >= 0)
          && jpg_forward_restore_choice(&best_choice, &forward_progress.best)
          && jpg_forward_restore_choice(&choice_before_backward,
                                          &forward_progress.before_backward)) {
        first_scan_pass = forward_progress.scan_pass;
        backward_choice_found = forward_progress.backward_choice_found;
        contiguous_tail_probed = forward_progress.contiguous_tail_probed;
        natural_tail_start = forward_progress.natural_tail_actual >= 0
            ? filemirror_apparent_blocknumber(scalpel_state.filemirror,
                                               forward_progress.natural_tail_actual)
            : -1;
        if (forward_progress.pass_complete) {
          if (first_scan_pass == 1 && backward_choice_found) {
            best_choice = choice_before_backward;
            backward_choice_found = false;
          }
          if (first_scan_pass < scan_passes) {
            first_scan_pass++;
          }
        }
        else {
          resume_actual = forward_progress.next_actual;
        }
        if (jpg_reassembly_debug_candidate(candidate)) {
          lock_fprintf(stderr,
                       "[jpgdbg] forward_resume pass=%" PRIu32
                       " next_actual=%" PRId64 " best_actual=%" PRId64 "\n",
                       first_scan_pass, resume_actual,
                       best_choice.found ? best_choice.actual : -1);
        }
      }
      else {
        memset(&best_choice, 0, sizeof(best_choice));
        best_choice.apparent = best_choice.actual = -1;
        memset(&choice_before_backward, 0, sizeof(choice_before_backward));
      }
      memset(&forward_progress, 0, sizeof(forward_progress));
      forward_progress.source_blocks = num_blocks;
      forward_progress.source_length = oldlength;
      forward_progress.source_signature =
          jpg_forward_source_signature(candidate, num_blocks);
      forward_progress.scan_mode = scan_mode;
      forward_progress.baseline_seed_prepared = baseline_seed_prepared;
      forward_progress.progressive_seed_prepared = progressive_seed_prepared;
      forward_progress.baseline_seed_needs_search = baseline_seed_needs_search;

      for (uint32_t scan_pass = first_scan_pass;
           scan_pass < scan_passes && !stop_forward_scan;
           scan_pass++) {
        bool backward_scan = confidence_order && scan_pass == 1;
        int64_t scan_start = tail_apparent + 1;
        int64_t scan_step = 1;
        int64_t scan_limit = tail_apparent
                             + JPG_REASSEMBLY_FORWARD_SCAN_WINDOW;

        if (backward_scan) {
          int64_t backward_origin = first_apparent > 0
                                        ? first_apparent
                                        : tail_apparent;

          if (scan_pass != first_scan_pass || resume_actual < 0) {
            choice_before_backward = best_choice;
          }
          scan_start = backward_origin - 1;
          scan_step = -1;
          scan_limit =
              backward_origin - JPG_REASS_OOO_PRIORITY_BACKSCAN_BLOCKS;
          if (scan_limit < 0) {
            scan_limit = 0;
          }
        }
        else if (wide_scan && !confidence_order) {
          scan_limit = last_apparent - 1;
        }
        else if (confidence_order
                 && (scan_pass == 2 || scan_pass == 3)) {
          scan_limit = tail_apparent
                       + JPG_REASSEMBLY_NEARBY_SCAN_WINDOW;
        }
        else if (confidence_order && scan_pass > 3) {
          scan_limit = last_apparent - 1;
        }

        if (!backward_scan && scan_limit >= last_apparent) {
          scan_limit = last_apparent - 1;
        }

        if (scan_pass == first_scan_pass && resume_actual >= 0) {
          scan_start = jpg_reassembly_apparent_lower_bound(resume_actual);
          if (backward_scan
              && (scan_start >= last_apparent
                  || filemirror_actual_blocknumber(scalpel_state.filemirror,
                                                     scan_start) > resume_actual)) {
            scan_start--;
          }
        }

        for (int64_t apparent = scan_start;
             backward_scan ? apparent >= scan_limit : apparent <= scan_limit;
             apparent += scan_step) {
          int64_t actual;
          BlockValidationDecision blocktype;

          if (jpg_reassembly_checkpoint_requested()) {
            jpg_forward_save_progress(
                &forward_progress, scan_pass,
                filemirror_actual_blocknumber(scalpel_state.filemirror, apparent),
                natural_tail_start, contiguous_tail_probed, backward_choice_found,
                &best_choice, &choice_before_backward);
            resize_blockvector(candidate->b, num_blocks);
            blockvector_set_data_length(candidate->b, oldlength);
            if (jpg_reassembly_time_to_checkpoint(
                    work->id, candidate, uuidp, uuidc, &fallback,
                    &validates, &validates_to,
                    &forward_progress)) {
              goto done_do_not_write_candidate;
            }
            resize_blockvector(candidate->b, num_blocks + 1);
            blockvector_set_apparent_blocknumber(candidate->b, num_blocks, -1);
            blockvector_free_choices(candidate->b, num_blocks);
          }
          if (tick++ % 100000 == 0 && ! scalpel_state.mode_verbose) {
            lock_fprintf(stdout, "%s.%s", BLUE, BLACK);
            fflush(stdout);
          }

          if (!backward_scan && first_apparent >= 0
              && apparent < first_apparent
              && tail_apparent >= first_apparent) {
            continue;
          }
          if (jpg_reassembly_apparent_in_blockvector_strict(candidate->b, apparent)) {
            continue;
          }

          actual = filemirror_actual_blocknumber(scalpel_state.filemirror,
                                                 apparent);
          if (actual < 0
              || filemirror_actual_block_covered(scalpel_state.filemirror, actual)) {
            continue;
          }

          blocktype = filemirror_get_blocktype(scalpel_state.filemirror,
                                               actual,
                                               candidate->needleidx);
          // A terminal sector can contain only the end of entropy data and EOI,
          // which is not enough to classify the sector independently. Always
          // test the physically adjacent continuation; the full JPEG validator
          // still decides whether it can be committed.
          if (blocktype == BLOCK_CONFIDENCE_INVALID
              && apparent != tail_apparent + 1) {
            continue;
          }

          if (confidence_order && scan_pass > 0) {
            if ((scan_pass == 2 || scan_pass == 3)
                && apparent <= tail_apparent
                               + JPG_REASSEMBLY_FORWARD_SCAN_WINDOW) {
              continue;
            }
            if (scan_pass == 2
                && blocktype != BLOCK_CONFIDENCE_VALID) {
              continue;
            }
            if (scan_pass > 3
                && apparent <= tail_apparent
                               + JPG_REASSEMBLY_NEARBY_SCAN_WINDOW) {
              continue;
            }
            if (scan_pass == 4) {
              if (blocktype != BLOCK_CONFIDENCE_VALID) {
                continue;
              }
            }
            else if (scan_pass == 5) {
              if (blocktype < 80 || blocktype == BLOCK_CONFIDENCE_VALID) {
                continue;
              }
            }
            else if (scan_pass == 6 && blocktype >= 80) {
              continue;
            }
          }

          if (confidence_order && (backward_scan || scan_pass == 2)
              && have_prefix_state && !prefix_state.is_progressive
              && prefix_state.huff_checkpoint.valid) {
            JpgReassemblyEntropyProbe entropy_probe;
            const bool probe_available =
                jpg_reassembly_probe_baseline_entropy(
                    candidate, &prefix_state, num_blocks, oldlength,
                    apparent, 1, -1, 0, &entropy_probe);

            resize_blockvector(candidate->b, num_blocks + 1);
            blockvector_set_apparent_blocknumber(candidate->b, num_blocks,
                                                 -1);
            blockvector_free_choices(candidate->b, num_blocks);
            if (probe_available && entropy_probe.supported
                && (!entropy_probe.clean
                    || !entropy_probe.reaches_probe_end)
                && jpg_huffman_failure_is_hard(entropy_probe.failure)
                && entropy_probe.frontier < accept_threshold) {
              continue;
            }
          }

          jpg_forward_save_progress(
              &forward_progress, scan_pass, actual, natural_tail_start,
              contiguous_tail_probed, backward_choice_found,
              &best_choice, &choice_before_backward);
          blockvector_set_apparent_blocknumber(candidate->b, num_blocks,
                                               apparent);
          (void)inflate_blockvector_single_block(candidate->b, num_blocks);

          JPGCarveState trial_state;
          uint64_t trial_validates_to = 0;
          uint64_t trial_score_validates_to = 0;
          uint64_t trial_end;
          uint64_t trial_shortfall;
          bool trial_reaches_end;
          bool trial_near_end;
          bool trial_actual_is_zero;
          bool trial_effectively_reaches_end;
          bool trial_has_followon_support;
          bool trial_wrongblock;
          bool trial_restart_not_due = false;
          bool trial_have_boundary = false;
          bool trial_is_natural_tail = false;
          bool trial_is_immediate;
          bool trial_validates;
          JpgBoundaryScore trial_boundary;

          memset(&trial_boundary, 0, sizeof(trial_boundary));

          if (have_prefix_state) {
            memcpy(&trial_state, &prefix_state, sizeof(trial_state));
          } else {
            memset(&trial_state, 0, sizeof(trial_state));
          }

          const uint32_t trial_fixed_prefix =
              jpg_reassembly_get_fixed_prefix_blocks(candidate);
          const bool trial_may_resume =
              trial_state.valid && trial_state.checkpoint_pos > 0
              && !jpg_reassembly_requires_cold_validation(
                     candidate, trial_fixed_prefix);
          trial_validates =
              jpg_reassembly_validate_direct(candidate, &trial_state,
                                             &trial_validates_to,
                                             trial_fixed_prefix);
          validates = trial_validates;
          validates_to = trial_validates_to;
          jpg_reassembly_debug_dump(validates ? "forward_trial_valid"
                                              : "forward_trial",
                                    candidate, apparent, validates_to);
          // A trial already decoded from scratch has no independent cold
          // fallback to try. Retain that fallback for resumable decoder state.
          if (!validates && trial_may_resume
              && validates_to + 1 <= accept_threshold) {
            JPGCarveState cold_state;
            JpgWrongBlockResult current_wrongblock = jpg_wrongblock_result;
            JpgWrongBlockResult cold_wrongblock;
            uint64_t cold_validates_to = 0;
            bool cold_validates;

            memset(&cold_state, 0, sizeof(cold_state));
            cold_validates =
                jpg_reassembly_validate_direct(candidate, &cold_state,
                                               &cold_validates_to,
                                               jpg_reassembly_get_fixed_prefix_blocks(candidate));
            cold_wrongblock = jpg_wrongblock_result;
            if (jpg_reassembly_cold_validation_is_better(
                    cold_validates, cold_validates_to, &cold_wrongblock,
                    validates_to, &current_wrongblock)) {
              validates = cold_validates;
              validates_to = cold_validates_to;
              memcpy(&trial_state, &cold_state, sizeof(trial_state));
              jpg_wrongblock_result = cold_wrongblock;
              jpg_reassembly_debug_dump(cold_validates ? "forward_cold_valid"
                                                       : "forward_cold_accept",
                                        candidate, apparent, validates_to);
            }
            else {
              jpg_wrongblock_result = current_wrongblock;
            }
          }

          trial_end = blockvector_get_data_length(candidate->b) - 1;
          trial_reaches_end = validates_to >= trial_end;
          trial_shortfall = trial_reaches_end ? 0 : trial_end - validates_to;
          trial_near_end = trial_shortfall <= JPG_REASSEMBLY_BOUNDARY_SLACK;
          trial_wrongblock = jpg_wrongblock_result.detected;
          trial_actual_is_zero =
              filemirror_actual_block_is_zero(scalpel_state.filemirror, actual);
          trial_effectively_reaches_end =
              trial_reaches_end
              || (trial_near_end && !trial_actual_is_zero && !trial_wrongblock);
          trial_is_immediate = apparent == tail_apparent + 1;
          trial_score_validates_to = validates_to;
          if (!validates && validates_to + 1 > accept_threshold) {
            uint64_t followon_score =
                jpg_reassembly_probe_contiguous_followon(candidate, &trial_state,
                                                         validates_to,
                                                         &trial_restart_not_due);
            if (followon_score > trial_score_validates_to) {
              trial_score_validates_to = followon_score;
            }
            jpg_reassembly_debug_dump("forward_score", candidate, apparent,
                                      trial_score_validates_to);
          }
          trial_has_followon_support =
              scalpel_state.blocksize > 0
              && trial_score_validates_to >=
                     trial_end + 2 * (uint64_t)scalpel_state.blocksize;

          if (natural_tail_start < 0
              && (apparent > tail_apparent + 1
                  || actual != tail_actual + 1)
              && !trial_actual_is_zero
              && validates_to + 1 > accept_threshold) {
            natural_tail_start = apparent;
            trial_is_natural_tail = true;
          }

          if ((trial_has_followon_support
               || (trial_is_natural_tail && trial_effectively_reaches_end))
              && (apparent > tail_apparent + 1 || trial_is_natural_tail)) {
            trial_boundary = jpg_boundary_score(
                blockvector_get_data_pointer(candidate->b), oldlength,
                blockvector_get_data_length(candidate->b));
            trial_have_boundary = trial_boundary.valid;
          }
          // Try a complete decode through the next known footer for the
          // physical continuation and strongly ranked remote continuations.
          const bool try_ranked_tail =
              confidence_order && trial_has_followon_support
              && ((scan_pass == 0 && !trial_is_immediate)
                  || (scan_pass == 2
                      && blocktype == BLOCK_CONFIDENCE_VALID));
          const bool try_complete_tail =
              trial_is_natural_tail
              || try_ranked_tail;
          if (!validates && try_complete_tail
              && (!trial_is_natural_tail || !contiguous_tail_probed)
              && (try_ranked_tail || !trial_is_natural_tail
                  || !(scalpel_state.blocksize
                           <= JPG_REASS_SMALL_BLOCK_BRIDGE_BYTES
                       && actual > tail_actual + 1))) {
            bool polluted_prefix = false;

            if (trial_is_natural_tail) {
              contiguous_tail_probed = true;
            }
            deflate_blockvector_single_block(candidate->b, num_blocks, oldlength);
            blockvector_set_apparent_blocknumber(candidate->b, num_blocks, -1);
            resize_blockvector(candidate->b, num_blocks);
            blockvector_set_data_length(candidate->b, oldlength);
            if (jpg_reassembly_try_contiguous_tail_validation(
                    candidate, &validates, &validates_to,
                    jpg_reassembly_get_fixed_prefix_blocks(candidate),
                    num_blocks, oldlength, apparent)) {
              candidate->flavor = VALIDATED;
              goto done_write_candidate;
            }
            polluted_prefix =
                oldlength > 0 && validates_to < oldlength - 1
                && jpg_wrongblock_result.detected
                && jpg_wrongblock_result.method
                && strcmp(jpg_wrongblock_result.method,
                          "huffman_trailing_data") == 0;
            if (trial_is_natural_tail && polluted_prefix
                && num_blocks > structural_prefix_blocks
                && jpg_reassembly_try_suffix_rollback_tail_validation(
                       candidate, &validates, &validates_to,
                       structural_prefix_blocks, num_blocks, oldlength,
                       apparent)) {
              advanced = true;
              stop_forward_scan = true;
              break;
            }
            resize_blockvector(candidate->b, num_blocks + 1);
            blockvector_set_apparent_blocknumber(candidate->b, num_blocks,
                                                 apparent);
            (void)inflate_blockvector_single_block(candidate->b, num_blocks);
          }

          if (trial_has_followon_support
              && jpg_reassembly_debug_candidate(candidate)) {
            lock_fprintf(stderr,
                         "[jpgdbg] forward_boundary choice=%" PRId64
                         " valid=%d row=%u seam=%.3f base=%.3f norm=%.3f\n",
                         apparent, trial_boundary.valid ? 1 : 0,
                         trial_boundary.boundary_row, trial_boundary.seam_mad,
                         trial_boundary.baseline_mad,
                         trial_boundary.normalized);
          }

          if (validates
              || (trial_effectively_reaches_end
                  && (trial_is_immediate || trial_has_followon_support
                      || (trial_is_natural_tail && trial_have_boundary)))) {
            bool better_direct_progress =
                validates_to > best_choice.direct_validates_to;
            bool equal_direct_progress =
                validates_to == best_choice.direct_validates_to;
            bool comparable_continuity =
                trial_is_immediate == best_choice.is_immediate;
            bool better_continuity =
                equal_direct_progress && trial_is_immediate
                && !best_choice.is_immediate;
            bool comparable_followon =
                trial_has_followon_support
                == best_choice.has_followon_support;
            bool better_followon =
                equal_direct_progress && comparable_continuity
                && ((trial_has_followon_support
                     && !best_choice.has_followon_support)
                    || (comparable_followon
                        && trial_score_validates_to
                               > best_choice.score_validates_to));
            bool equal_followon_progress =
                comparable_followon
                && trial_score_validates_to
                       == best_choice.score_validates_to;
            bool better_boundary =
                equal_direct_progress && comparable_continuity
                && equal_followon_progress
                && trial_have_boundary
                && (!best_choice.have_boundary
                    || trial_boundary.normalized
                           < best_choice.boundary.normalized
                    || (trial_boundary.normalized
                            == best_choice.boundary.normalized
                        && trial_boundary.seam_mad
                               < best_choice.boundary.seam_mad));
            bool replace_best =
                !best_choice.found
                || validates
                || better_direct_progress
                || better_continuity
                || better_followon
                || better_boundary
                || (equal_direct_progress && comparable_continuity
                    && equal_followon_progress
                    && trial_have_boundary == best_choice.have_boundary
                    && apparent < best_choice.apparent);

            if (replace_best) {
              best_choice.found = true;
              best_choice.validates = validates;
              best_choice.has_followon_support = trial_has_followon_support;
              best_choice.restart_not_due = trial_restart_not_due;
              best_choice.reaches_trial_end = trial_effectively_reaches_end;
              best_choice.near_trial_end = trial_near_end;
              best_choice.is_immediate = trial_is_immediate;
              best_choice.apparent = apparent;
              best_choice.actual = actual;
              best_choice.commit_validates_to =
                  trial_effectively_reaches_end ? trial_end : validates_to;
              best_choice.direct_validates_to = validates_to;
              best_choice.score_validates_to = trial_score_validates_to;
              best_choice.have_boundary = trial_have_boundary;
              if (trial_have_boundary) {
                memcpy(&best_choice.boundary, &trial_boundary,
                       sizeof(best_choice.boundary));
              }
              if (trial_state.valid) {
                memcpy(&best_choice.state, &trial_state,
                       sizeof(best_choice.state));
                best_choice.have_state = true;
              } else {
                best_choice.have_state = false;
              }
              if (backward_scan && trial_has_followon_support) {
                backward_choice_found = true;
              }
              if (validates || trial_is_immediate) {
                jpg_reassembly_debug_dump("forward_best_valid", candidate,
                                          apparent, validates_to);
                stop_forward_scan = true;
                break;
              }
            }
          }

          deflate_blockvector_single_block(candidate->b, num_blocks, oldlength);
          blockvector_set_apparent_blocknumber(candidate->b, num_blocks, -1);

          if (backward_scan && trial_has_followon_support
              && format_known && have_prefix_state
              && !prefix_state.is_progressive) {
            int64_t preheader_footer = -1;
            bool range_has_eoi = jpg_reassembly_next_footer_apparent(
                candidate, apparent, first_apparent, &preheader_footer);

            resize_blockvector(candidate->b, num_blocks);
            blockvector_set_data_length(candidate->b, oldlength);
            if (range_has_eoi && first_apparent > apparent
                && jpg_reassembly_try_ooo_candidate_run(
                       candidate, &prefix_state, true,
                       &validates, &validates_to,
                       jpg_reassembly_get_fixed_prefix_blocks(candidate),
                       num_blocks, oldlength, apparent,
                       (uint64_t)(first_apparent - apparent),
                       -1, 0, true, true, true, NULL)) {
              candidate->flavor = VALIDATED;
              goto done_write_candidate;
            }
            if (!range_has_eoi
                && jpg_reassembly_try_preheader_two_run_validation(
                    candidate, &prefix_state, &validates, &validates_to,
                    jpg_reassembly_get_fixed_prefix_blocks(candidate),
                    num_blocks, oldlength, apparent)) {
              candidate->flavor = VALIDATED;
              blockvector_set_data_length(candidate->b, validates_to + 1);
              resize_blockvector(
                  candidate->b,
                  CEILDIV(blockvector_get_data_length(candidate->b),
                          scalpel_state.blocksize));
              goto done_write_candidate;
            }
            resize_blockvector(candidate->b, num_blocks + 1);
            blockvector_set_apparent_blocknumber(candidate->b, num_blocks,
                                                 -1);
            blockvector_free_choices(candidate->b, num_blocks);
          }

          if (reassembly_check_kill_queue(work, &candidate, uuidp, uuidc)) {
            goto done_do_not_write_candidate;
          }
          if (jpg_reassembly_checkpoint_requested()) {
            resize_blockvector(candidate->b, num_blocks);
            blockvector_set_data_length(candidate->b, oldlength);
            if (jpg_reassembly_time_to_checkpoint(
                    work->id, candidate, uuidp, uuidc, &fallback,
                    &validates, &validates_to,
                    &forward_progress)) {
              goto done_do_not_write_candidate;
            }
            resize_blockvector(candidate->b, num_blocks + 1);
            blockvector_set_apparent_blocknumber(candidate->b, num_blocks, -1);
            blockvector_free_choices(candidate->b, num_blocks);
          }
          if (trial_is_natural_tail && !confidence_order) {
            break;
          }
        }

        if (backward_scan && backward_choice_found) {
          best_choice = choice_before_backward;
          backward_choice_found = false;
        }
      }
      jpg_forward_save_progress(
          &forward_progress, scan_passes, -1, natural_tail_start,
          contiguous_tail_probed, backward_choice_found,
          &best_choice, &choice_before_backward);
      forward_progress.pass_complete = true;
      if (advanced) {
        forward_progress.active = false;
      }
    }

    if (!advanced && !format_known && natural_tail_start >= 0
        && (!best_choice.found
            || (best_choice.apparent == natural_tail_start
                && tail_actual >= 0
                && best_choice.actual > tail_actual + 1
                && (uint64_t)(best_choice.actual - tail_actual - 1)
                       <= JPG_REASS_OOO_MAX_RUN))) {
      uint64_t structural_suffix_len = 0;
      uint64_t structural_trials = 0;
      uint64_t structural_run_len =
          best_choice.found
              ? (uint64_t)(best_choice.actual - tail_actual - 1) : 1;
      int64_t best_structural_start = -1;
      int64_t runner_up_structural_start = -1;
      double best_structural_score = DBL_MAX;
      double runner_up_structural_score = DBL_MAX;
      double direct_structural_score = DBL_MAX;
      bool direct_structural_supported = false;

      resize_blockvector(candidate->b, num_blocks);
      blockvector_set_data_length(candidate->b, oldlength);
      while (structural_suffix_len < JPG_REASS_OOO_MAX_RUN
             && jpg_reassembly_ooo_apparent_available(
                    candidate,
                    natural_tail_start + (int64_t)structural_suffix_len)
             && !jpg_reassembly_ooo_range_has_zero(
                    natural_tail_start + (int64_t)structural_suffix_len, 1)) {
        structural_suffix_len++;
      }
      if (structural_suffix_len > 1) {
        direct_structural_supported =
            jpg_reassembly_icc_curve_bridge_score(
                candidate, num_blocks, oldlength,
                natural_tail_start, 1, natural_tail_start + 1,
                structural_suffix_len - 1, &direct_structural_score);
      }
      for (int64_t moved_start = 0;
           structural_suffix_len > 0 && moved_start < last_apparent
             && structural_trials < JPG_REASS_OOO_MAX_TRIALS;
           moved_start++) {
        double structural_score;

        if (jpg_reassembly_checkpoint_requested()) {
          break;
        }
        structural_trials++;
        if (!jpg_reassembly_icc_curve_bridge_score(
                candidate, num_blocks, oldlength,
                moved_start, structural_run_len, natural_tail_start,
                structural_suffix_len, &structural_score)) {
          continue;
        }
        if (structural_score < best_structural_score) {
          runner_up_structural_start = best_structural_start;
          runner_up_structural_score = best_structural_score;
          best_structural_start = moved_start;
          best_structural_score = structural_score;
        }
        else if (structural_score < runner_up_structural_score) {
          runner_up_structural_start = moved_start;
          runner_up_structural_score = structural_score;
        }
      }
      if (jpg_reassembly_debug_candidate(candidate)) {
        lock_fprintf(stderr,
                     "[jpgdbg] structural_bridge_rank best=%" PRId64
                     "/%.6f runner=%" PRId64 "/%.6f"
                     " direct=%d/%.6f run=%" PRIu64
                     " suffix=%" PRId64 "+%" PRIu64 "\n",
                     best_structural_start, best_structural_score,
                     runner_up_structural_start,
                     runner_up_structural_score,
                     direct_structural_supported ? 1 : 0,
                     direct_structural_score, structural_run_len,
                     natural_tail_start, structural_suffix_len);
      }
      // a sampled ICC curve distinguishes a direct continuation from a
      // displaced run before the JPEG frame reaches the normal scorer.
      if (direct_structural_supported
          && direct_structural_score <= JPG_REASS_ICC_CURVE_SCORE_LIMIT
          && (best_structural_start < 0
              || direct_structural_score * JPG_REASS_ICC_CURVE_SCORE_RATIO
                     < best_structural_score)
          && jpg_reassembly_try_ooo_candidate_run(
                 candidate, &prefix_state, have_prefix_state,
                 &validates, &validates_to,
                 jpg_reassembly_get_fixed_prefix_blocks(candidate),
                 num_blocks, oldlength, natural_tail_start, 1,
                 natural_tail_start + 1, structural_suffix_len - 1,
                 false, true, true, NULL)) {
        advanced = true;
      }
      else if (best_structural_start >= 0
          && best_structural_score <= JPG_REASS_ICC_CURVE_SCORE_LIMIT
          && (runner_up_structural_start < 0
              || best_structural_score * JPG_REASS_ICC_CURVE_SCORE_RATIO
                     < runner_up_structural_score)
          && (!direct_structural_supported
              || best_structural_score * JPG_REASS_ICC_CURVE_SCORE_RATIO
                     < direct_structural_score)
          && jpg_reassembly_try_ooo_candidate_run(
                 candidate, &prefix_state, have_prefix_state,
                 &validates, &validates_to,
                 jpg_reassembly_get_fixed_prefix_blocks(candidate),
                 num_blocks, oldlength, best_structural_start,
                 structural_run_len,
                 natural_tail_start, structural_suffix_len,
                 false, true, true, NULL)) {
        advanced = true;
      }
      if (jpg_reassembly_checkpoint_requested()
          && jpg_reassembly_time_to_checkpoint(
                 work->id, candidate, uuidp, uuidc, &fallback,
                 &validates, &validates_to,
                 &forward_progress)) {
        goto done_do_not_write_candidate;
      }
    }

    if (!advanced && format_known && have_prefix_state
        && !prefix_state.is_progressive && best_choice.found
        && best_choice.actual == tail_actual + 2
        && scalpel_state.blocksize <= JPG_REASS_SMALL_BLOCK_BRIDGE_BYTES) {
      uint64_t local_run_len = 0;

      resize_blockvector(candidate->b, num_blocks);
      blockvector_set_data_length(candidate->b, oldlength);
      while (local_run_len < JPG_REASS_OOO_MAX_RUN
             && jpg_reassembly_ooo_apparent_available(
                    candidate,
                    best_choice.apparent + (int64_t)local_run_len)
             && !jpg_reassembly_ooo_range_has_zero(
                    best_choice.apparent + (int64_t)local_run_len, 1)) {
        local_run_len++;
      }
      small_gap_rate_consistent =
          jpg_reassembly_baseline_local_rate_consistent(
              candidate, &prefix_state, num_blocks, oldlength,
              best_choice.apparent, local_run_len,
              &small_gap_rate_available, &small_gap_rate_deviation);
      small_gap_rate_strong =
          small_gap_rate_available
          && small_gap_rate_deviation
                 < JPG_REASS_BASELINE_STRONG_RATE_LIMIT;
      if (num_blocks <= (uint64_t)structural_prefix_blocks + 1) {
        JpgOOOBridgeChoice local_bridge;
        JpgOOOBridgeChoice nearby_best;
        JpgOOOBridgeChoice nearby_runner_up;

        memset(&local_bridge, 0, sizeof(local_bridge));
        memset(&nearby_best, 0, sizeof(nearby_best));
        memset(&nearby_runner_up, 0, sizeof(nearby_runner_up));
        (void)jpg_reassembly_evaluate_baseline_bridge(
            candidate, &prefix_state, true,
            jpg_reassembly_get_fixed_prefix_blocks(candidate),
            num_blocks, oldlength, best_choice.apparent, local_run_len,
            -1, 0, &local_bridge);
        small_gap_boundary_unsupported =
            local_bridge.boundary.valid
            && local_bridge.boundary.normalized
                   > JPG_REASS_BASELINE_UNSUPPORTED_SCORE_LIMIT;
        small_gap_forward_supported =
            local_run_len >= JPG_REASS_OOO_MIN_SUFFIX_PROBE
            && local_bridge.huffman_support && local_bridge.boundary.valid
            && (!small_gap_rate_available || small_gap_rate_consistent)
            && (local_bridge.boundary.normalized
                   <= JPG_REASS_BASELINE_BRIDGE_SCORE_LIMIT
                || (local_bridge.boundary.baseline_mad <= 1.0
                    && !small_gap_rate_available
                    && local_bridge.boundary.normalized
                           <= JPG_REASS_BASELINE_UNSUPPORTED_SCORE_LIMIT));
        if (!local_bridge.boundary.valid) {
          jpg_reassembly_rank_nearby_baseline_bridge(
              candidate, &prefix_state,
              jpg_reassembly_get_fixed_prefix_blocks(candidate),
              num_blocks, oldlength, tail_apparent,
              best_choice.apparent, local_run_len,
              &nearby_best, &nearby_runner_up);
          if (nearby_best.found && nearby_best.boundary.valid) {
            best_bridge = nearby_best;
            nearby_baseline_bridge_selected = true;
            jpg_reassembly_shortlist_baseline_bridge(&nearby_best);
            if (nearby_runner_up.found) {
              jpg_reassembly_shortlist_baseline_bridge(&nearby_runner_up);
            }
          }
        }
        shallow_baseline_gap_ambiguous =
            num_blocks <= (uint64_t)structural_prefix_blocks + 1
            && local_run_len < JPG_REASS_BASELINE_STRONG_SUFFIX_PROBE
            && !local_bridge.full_validates
            && !local_bridge.direct_validates
            && !local_bridge.boundary.valid
            && !nearby_baseline_bridge_selected
            && (!small_gap_rate_available || !small_gap_rate_consistent);
        if (jpg_reassembly_debug_candidate(candidate)) {
          lock_fprintf(stderr,
                       "[jpgdbg] nearby_bridge local=%.6f/%.3f/%d"
                       " best=%" PRId64
                       "/%.6f/%" PRIu64 " runner=%" PRId64
                       "/%.6f/%" PRIu64 " selected=%d\n",
                       local_bridge.baseline_rate_deviation,
                       local_bridge.boundary.normalized,
                       local_bridge.boundary.valid ? 1 : 0,
                       nearby_best.found ? nearby_best.moved_start : -1,
                       nearby_best.baseline_rate_deviation,
                       nearby_best.suffix_len,
                       nearby_runner_up.found
                           ? nearby_runner_up.moved_start : -1,
                       nearby_runner_up.baseline_rate_deviation,
                       nearby_runner_up.suffix_len,
                       nearby_baseline_bridge_selected ? 1 : 0);
        }
      }
      if (jpg_reassembly_debug_candidate(candidate)) {
        lock_fprintf(stderr,
                     "[jpgdbg] local_gap_rate run=%" PRId64 "+%" PRIu64
                     " available=%d deviation=%.6f consistent=%d\n",
                     best_choice.apparent, local_run_len,
                     small_gap_rate_available ? 1 : 0,
                     small_gap_rate_deviation,
                     small_gap_rate_consistent ? 1 : 0);
      }
    }

    // a shallow entropy prefix without consistent rate or image evidence cannot
    // safely distinguish distant fragments; retain the trusted partial candidate.
    if (shallow_baseline_gap_ambiguous) {
      resize_blockvector(candidate->b, num_blocks);
      blockvector_set_data_length(candidate->b, oldlength);
      break;
    }

    raw_jump_requires_bridge =
        nearby_baseline_bridge_selected
        || (best_choice.found
        && best_choice.actual > tail_actual + 1
        && !(small_gap_forward_supported
             || (best_choice.has_followon_support
                 && best_choice.restart_not_due))
        && ((scalpel_state.blocksize <= JPG_REASS_SMALL_BLOCK_BRIDGE_BYTES
             && !progressive_format
             && ((best_choice.have_boundary
                  && (best_choice.boundary.normalized
                            > JPG_REASS_BASELINE_UNSUPPORTED_SCORE_LIMIT
                      || (best_choice.boundary.normalized
                                > JPG_REASS_BASELINE_SUFFIX_BOUNDARY_LIMIT
                          && !small_gap_rate_strong)))
                 || (small_gap_rate_available
                     && !small_gap_rate_consistent)
                 || (!small_gap_rate_available
                     && num_blocks
                            == (uint64_t)structural_prefix_blocks + 1)))
            || scalpel_state.blocksize >= JPG_REASS_BASELINE_SEED_PROBE_BYTES
            || best_choice.actual > tail_actual + 2
            || num_blocks == structural_prefix_blocks));
    strong_forward_continuation =
        !advanced && format_known && have_prefix_state
        && !prefix_state.is_progressive && !baseline_scatter_active
        && !raw_jump_requires_bridge && best_choice.found
        && (small_gap_forward_supported
            || (best_choice.is_immediate && best_choice.reaches_trial_end
             && (best_choice.actual == tail_actual + 1
                 || prefix_state.restart_interval == 0
                 || (have_expected_restart
                     && jpg_reassembly_apparent_range_has_restart_marker(
                            best_choice.apparent, 2,
                            expected_restart))))
            || (best_choice.has_followon_support
                && natural_tail_start >= 0
                && best_choice.apparent == natural_tail_start
                && (best_choice.restart_not_due
                    || prefix_state.restart_interval == 0
                    || (have_expected_restart
                        && jpg_reassembly_apparent_range_has_restart_marker(
                               best_choice.apparent, 2,
                               expected_restart)))));

    if (!strong_forward_continuation && !advanced && format_known
        && have_prefix_state && prefix_state.is_progressive
        && !progressive_entry_verify && !raw_jump_requires_bridge
        && natural_tail_start >= 0 && best_choice.found
        && best_choice.apparent == natural_tail_start
        && best_choice.has_followon_support && best_choice.have_boundary
        && best_choice.boundary.normalized
               <= JPG_REASS_PROGRESSIVE_CONTINUATION_BOUNDARY_LIMIT
        && best_choice.score_validates_to >= best_choice.commit_validates_to
        && best_choice.score_validates_to - best_choice.commit_validates_to
               >= JPG_REASSEMBLY_PROBE_MAX_CHAIN
                    * (uint64_t)scalpel_state.blocksize) {
      JpgOOOBridgeChoice forward_probe;

      memset(&forward_probe, 0, sizeof(forward_probe));
      if (jpg_reassembly_evaluate_progressive_bridge(
              candidate, &prefix_state, true,
              jpg_reassembly_get_fixed_prefix_blocks(candidate),
              num_blocks, oldlength, best_choice.apparent, 1,
              0, 0, false, &forward_probe)
          && (forward_probe.direct_validates
              || forward_probe.full_validates
              || forward_probe.progressive_entropy_complete
              || (forward_probe.progressive_entropy_supported
                  && forward_probe.progressive_entropy_score
                         < JPG_REASS_PROGRESSIVE_RATE_LIMIT))) {
        // a locally normal seam plus a full follow-on probe makes the nearby
        // progressive continuation conclusive without a full-image search.
        strong_forward_continuation = true;
      }
    }

    // less than one block of trusted entropy cannot distinguish another
    // distant fragment after the baseline candidate is already fragmented.
    if (!advanced && !strong_forward_continuation && format_known
        && have_prefix_state && !prefix_state.is_progressive
        && prefix_state.restart_interval == 0
        && !prefix_state.huff_checkpoint.valid
        && !nearby_baseline_bridge_selected && raw_jump_requires_bridge
        && jpg_reassembly_has_physical_gap(candidate)
        && best_choice.found && best_choice.actual > tail_actual + 1
        && prefix_state.entropy_start < oldlength
        && oldlength - prefix_state.entropy_start
               < (uint64_t)scalpel_state.blocksize) {
      resize_blockvector(candidate->b, num_blocks);
      blockvector_set_data_length(candidate->b, oldlength);
      break;
    }

    if (!advanced && !strong_forward_continuation
        && format_known && natural_tail_start >= 0
        && !progressive_entry_verify
        && !nearby_baseline_bridge_selected
        && (!baseline_scatter_active || progressive_format)) {
      uint64_t anchored_bridge_trials = 0;
      uint64_t global_bridge_trials = 0;
      uint64_t suffix_len = 0;
      int64_t bridge_footer = -1;
      JpgOOOBridgeChoice best_restart_entry;
      bool tail_has_zero_before_footer = false;
      bool anchored_bridge_complete = false;
      bool restart_anchor_required =
          have_prefix_state && !prefix_state.is_progressive
          && prefix_state.restart_interval > 0
          && have_expected_restart
          && !jpg_reassembly_apparent_range_has_restart_marker(
                 natural_tail_start, 2, expected_restart);

      memset(&best_restart_entry, 0, sizeof(best_restart_entry));
      resize_blockvector(candidate->b, num_blocks);
      blockvector_set_data_length(candidate->b, oldlength);
      while (suffix_len < 8
             && jpg_reassembly_ooo_apparent_available(
                    candidate, natural_tail_start + (int64_t)suffix_len)
             && !jpg_reassembly_ooo_range_has_zero(
                    natural_tail_start + (int64_t)suffix_len, 1)) {
        suffix_len++;
      }
      if (jpg_reassembly_next_footer_apparent(
              candidate, natural_tail_start, last_apparent,
              &bridge_footer)) {
        tail_has_zero_before_footer = jpg_reassembly_ooo_range_has_zero(
            natural_tail_start,
            (uint64_t)(bridge_footer - natural_tail_start + 1));
      }
      if (suffix_len > 0 && have_prefix_state) {
        uint32_t fixed_prefix_blocks =
            jpg_reassembly_get_fixed_prefix_blocks(candidate);
        JpgOOOBridgeChoice raw_anchor_best;
        JpgOOOBridgeChoice raw_anchor_runner_up;

        memset(&raw_anchor_best, 0, sizeof(raw_anchor_best));
        memset(&raw_anchor_runner_up, 0, sizeof(raw_anchor_runner_up));

        // a run ending at a raw JPEG header is a bounded, high-value search;
        // use it only when the best entropy-supported seam is unambiguous.
        if (prefix_state.is_progressive) {
          for (uint64_t run_len = JPG_REASS_OOO_MIN_RUN;
               run_len <= JPG_REASS_OOO_MAX_RUN;
               run_len++) {
            for (int64_t moved_start = 0;
                 moved_start + (int64_t)run_len <= last_apparent
                   && anchored_bridge_trials < JPG_REASS_OOO_MAX_TRIALS;
                 moved_start++) {
              JpgOOOBridgeChoice trial_bridge;

              if (jpg_reassembly_checkpoint_requested()) {
                break;
              }
              if (jpg_reassembly_raw_anchor_distance(
                      moved_start, run_len,
                      JPG_REASS_OOO_ANCHOR_BACKSCAN_BLOCKS)
                     != 1
                  || !jpg_reassembly_bridge_candidate_plausible(
                         moved_start, true)) {
                continue;
              }
              anchored_bridge_trials++;
              memset(&trial_bridge, 0, sizeof(trial_bridge));
              if (!jpg_reassembly_evaluate_progressive_bridge(
                      candidate, &prefix_state, have_prefix_state,
                      fixed_prefix_blocks, num_blocks, oldlength,
                      moved_start, run_len, natural_tail_start, suffix_len,
                      tail_has_zero_before_footer, &trial_bridge)) {
                continue;
              }
              jpg_reassembly_rank_progressive_bridge(&best_bridge,
                                                     &trial_bridge);
              if (jpg_reassembly_progressive_bridge_better(
                      &trial_bridge, &raw_anchor_best)) {
                raw_anchor_runner_up = raw_anchor_best;
                raw_anchor_best = trial_bridge;
              }
              else if (jpg_reassembly_progressive_bridge_better(
                           &trial_bridge, &raw_anchor_runner_up)) {
                raw_anchor_runner_up = trial_bridge;
              }
            }
          }
          // A baseline bridge that needs the known suffix can have multiple
          // complete solutions, so compare it with the unanchored candidates.
          anchored_bridge_complete =
              raw_anchor_best.found && raw_anchor_runner_up.found
              && raw_anchor_best.progressive_entropy_supported
              && raw_anchor_best.progressive_entropy_score
                     < JPG_REASS_PROGRESSIVE_RATE_LIMIT
              && raw_anchor_best.boundary.valid
              && raw_anchor_runner_up.boundary.valid
              && raw_anchor_best.boundary.normalized
                     * JPG_REASS_PROGRESSIVE_BOUNDARY_RATIO
                   < raw_anchor_runner_up.boundary.normalized
              && jpg_reassembly_progressive_bridge_preferred(
                     &raw_anchor_best, &best_choice);
          if (anchored_bridge_complete) {
            best_bridge = raw_anchor_best;
          }
        }

        for (uint64_t run_len = JPG_REASS_OOO_MIN_RUN;
             run_len <= JPG_REASS_OOO_MAX_RUN
               && !anchored_bridge_complete;
             run_len++) {
          for (int64_t moved_start = 0;
               moved_start + (int64_t)run_len <= last_apparent
                 && anchored_bridge_trials < JPG_REASS_OOO_MAX_TRIALS;
               moved_start++) {
            JpgOOOBridgeChoice trial_bridge;
            uint64_t anchor_distance;

            if (jpg_reassembly_checkpoint_requested()) {
              break;
            }
            if (restart_anchor_required
                && !jpg_reassembly_apparent_range_has_restart_marker(
                       moved_start, run_len, expected_restart)) {
              continue;
            }
            anchor_distance = jpg_reassembly_raw_anchor_distance(
                moved_start, run_len,
                JPG_REASS_OOO_ANCHOR_BACKSCAN_BLOCKS);
            if (anchor_distance == 0) {
              continue;
            }
            if (!jpg_reassembly_bridge_candidate_plausible(
                    moved_start, prefix_state.is_progressive)) {
              continue;
            }
            anchored_bridge_trials++;
            memset(&trial_bridge, 0, sizeof(trial_bridge));
            if (prefix_state.is_progressive) {
              if (jpg_reassembly_evaluate_progressive_bridge(
                      candidate, &prefix_state, have_prefix_state,
                      fixed_prefix_blocks, num_blocks, oldlength,
                      moved_start, run_len, natural_tail_start, suffix_len,
                      tail_has_zero_before_footer, &trial_bridge)) {
                jpg_reassembly_rank_progressive_bridge(&best_bridge,
                                                       &trial_bridge);
              }
            }
            else if (jpg_reassembly_evaluate_baseline_bridge(
                         candidate, &prefix_state, have_prefix_state,
                         fixed_prefix_blocks, num_blocks, oldlength,
                         moved_start, run_len, natural_tail_start, suffix_len,
                         &trial_bridge)) {
              jpg_reassembly_rank_baseline_bridge(&best_bridge,
                                                  &trial_bridge);
              jpg_reassembly_rank_baseline_entry(&best_baseline_entry,
                                                 &trial_bridge);
              if (restart_anchor_required
                  && jpg_reassembly_restart_entry_better(
                         &trial_bridge, &best_restart_entry)) {
                best_restart_entry = trial_bridge;
              }
            }
          }
          anchored_bridge_complete =
              prefix_state.is_progressive
                  ? jpg_reassembly_progressive_bridge_conclusive(
                        &best_bridge)
                  : best_bridge.direct_validates;

          if (!anchored_bridge_complete) {
            for (int64_t moved_start = 0;
                 moved_start + (int64_t)run_len <= last_apparent
                   && global_bridge_trials < JPG_REASS_OOO_MAX_TRIALS;
                 moved_start++) {
              JpgOOOBridgeChoice trial_bridge;

              if (jpg_reassembly_checkpoint_requested()) {
                break;
              }
              if (restart_anchor_required
                  && !jpg_reassembly_apparent_range_has_restart_marker(
                         moved_start, run_len, expected_restart)) {
                continue;
              }
              if (jpg_reassembly_raw_anchor_distance(
                      moved_start, run_len,
                      JPG_REASS_OOO_ANCHOR_BACKSCAN_BLOCKS)
                      != 0
                  || !jpg_reassembly_bridge_candidate_plausible(
                         moved_start, prefix_state.is_progressive)) {
                continue;
              }
              global_bridge_trials++;
              memset(&trial_bridge, 0, sizeof(trial_bridge));
              if (prefix_state.is_progressive) {
                if (jpg_reassembly_evaluate_progressive_bridge(
                        candidate, &prefix_state, have_prefix_state,
                        fixed_prefix_blocks, num_blocks, oldlength,
                        moved_start, run_len, natural_tail_start, suffix_len,
                        tail_has_zero_before_footer, &trial_bridge)) {
                  jpg_reassembly_rank_progressive_bridge(&best_bridge,
                                                         &trial_bridge);
                }
              }
              else if (jpg_reassembly_evaluate_baseline_bridge(
                           candidate, &prefix_state, have_prefix_state,
                           fixed_prefix_blocks, num_blocks, oldlength,
                           moved_start, run_len, natural_tail_start,
                           suffix_len, &trial_bridge)) {
                jpg_reassembly_rank_baseline_bridge(&best_bridge,
                                                    &trial_bridge);
                jpg_reassembly_rank_baseline_entry(&best_baseline_entry,
                                                   &trial_bridge);
                if (restart_anchor_required
                    && jpg_reassembly_restart_entry_better(
                           &trial_bridge, &best_restart_entry)) {
                  best_restart_entry = trial_bridge;
                }
              }
            }
          }

          anchored_bridge_complete =
              prefix_state.is_progressive
                  ? jpg_reassembly_progressive_bridge_conclusive(
                        &best_bridge)
                  : jpg_reassembly_baseline_bridge_conclusive(
                        &best_bridge);
        }
        if (restart_anchor_required && best_restart_entry.found) {
          best_bridge = best_restart_entry;
        }
        if (!prefix_state.is_progressive && best_bridge.found
            && scalpel_state.blocksize
                   < JPG_REASS_BASELINE_SEED_PROBE_BYTES) {
          int64_t refined_starts[JPG_REASS_BRIDGE_SHORTLIST_SIZE + 1];
          uint32_t refined_start_count = 0;
          JpgOOOBridgeChoice refined_bridge = best_bridge;

          refined_starts[refined_start_count++] =
              refined_bridge.moved_start;
          if (jpg_reassembly_refine_baseline_bridge_run_length(
                  candidate, &prefix_state, have_prefix_state,
                  fixed_prefix_blocks, num_blocks, oldlength,
                  natural_tail_start, suffix_len, &refined_bridge)
              && jpg_reassembly_baseline_bridge_better(
                     &refined_bridge, &best_bridge)) {
            best_bridge = refined_bridge;
          }
          // Refine the other strong entry seams before accepting a complete
          // suffix-dependent bridge with a shorter displaced run.
          for (uint32_t rank = 0;
               rank < bridge_shortlist.entry_only_count; rank++) {
            bool already_refined = false;

            refined_bridge = bridge_shortlist.entry_only_choices[rank];
            for (uint32_t i = 0; i < refined_start_count; i++) {
              if (refined_starts[i] == refined_bridge.moved_start) {
                already_refined = true;
                break;
              }
            }
            if (already_refined) {
              continue;
            }
            refined_starts[refined_start_count++] =
                refined_bridge.moved_start;
            if (jpg_reassembly_refine_baseline_bridge_run_length(
                    candidate, &prefix_state, have_prefix_state,
                    fixed_prefix_blocks, num_blocks, oldlength,
                    natural_tail_start, suffix_len, &refined_bridge)
                && jpg_reassembly_baseline_bridge_better(
                       &refined_bridge, &best_bridge)) {
              best_bridge = refined_bridge;
            }
          }
        }
      }
      if (jpg_reassembly_checkpoint_requested()
          && jpg_reassembly_time_to_checkpoint(
                 work->id, candidate, uuidp, uuidc, &fallback,
                 &validates, &validates_to,
                 &forward_progress)) {
        goto done_do_not_write_candidate;
      }
    }

    if (!advanced && format_known && !best_choice.found && natural_tail_start < 0
        && have_prefix_state && prefix_state.is_progressive) {
      uint64_t bridge_trials = 0;

      resize_blockvector(candidate->b, num_blocks);
      blockvector_set_data_length(candidate->b, oldlength);
      for (int64_t moved_start = 0;
           moved_start < last_apparent
             && bridge_trials < JPG_REASS_OOO_MAX_TRIALS;
           moved_start++) {
        JpgOOOBridgeChoice trial_bridge;

        if (jpg_reassembly_checkpoint_requested()) {
          break;
        }
        if (!jpg_reassembly_ooo_apparent_available(candidate, moved_start)) {
          continue;
        }
        bridge_trials++;
        memset(&trial_bridge, 0, sizeof(trial_bridge));
        if (jpg_reassembly_evaluate_progressive_bridge(
                candidate, &prefix_state, have_prefix_state,
                jpg_reassembly_get_fixed_prefix_blocks(candidate),
                num_blocks, oldlength, moved_start, 1, 0, 0, false,
                &trial_bridge)
            && (trial_bridge.direct_validates
                || trial_bridge.full_validates
                || trial_bridge.progressive_entropy_complete
                || (trial_bridge.progressive_entropy_supported
                    && trial_bridge.progressive_entropy_score
                           < JPG_REASS_PROGRESSIVE_RATE_LIMIT))) {
          jpg_reassembly_rank_progressive_bridge(&best_bridge,
                                                 &trial_bridge);
        }
      }
      if (jpg_reassembly_checkpoint_requested()
          && jpg_reassembly_time_to_checkpoint(
                 work->id, candidate, uuidp, uuidc, &fallback,
                 &validates, &validates_to,
                 &forward_progress)) {
        goto done_do_not_write_candidate;
      }
    }

    if (!advanced && progressive_format && have_prefix_state
        && num_blocks == structural_prefix_blocks) {
      JpgOOOBridgeChoice initial_probe;
      bool supported = false;

      if (jpg_reassembly_progressive_bridge_conclusive(&best_bridge)) {
        supported = true;
      }
      else if (best_bridge.found) {
        memset(&initial_probe, 0, sizeof(initial_probe));
        if (jpg_reassembly_evaluate_progressive_bridge(
                candidate, &prefix_state, true, structural_prefix_blocks,
                num_blocks, oldlength, best_bridge.moved_start,
                best_bridge.run_len, 0, 0, false, &initial_probe)
            && jpg_reassembly_progressive_choice_supported(&initial_probe)) {
          best_bridge = initial_probe;
          supported = true;
        }
      }
      if (!supported && best_choice.found) {
        memset(&initial_probe, 0, sizeof(initial_probe));
        if (jpg_reassembly_evaluate_progressive_bridge(
                candidate, &prefix_state, true, structural_prefix_blocks,
                num_blocks, oldlength, best_choice.apparent, 1,
                0, 0, false, &initial_probe)
            && jpg_reassembly_progressive_choice_supported(&initial_probe)) {
          best_bridge = initial_probe;
          supported = true;
        }
      }
      if (!supported) {
        memset(&best_bridge, 0, sizeof(best_bridge));
        global_progressive_search = true;
        jpg_reassembly_rank_global_progressive_fragment(
            candidate, &prefix_state, structural_prefix_blocks,
            num_blocks, oldlength, last_apparent, &best_bridge);
        if (jpg_reassembly_checkpoint_requested()
            && jpg_reassembly_time_to_checkpoint(
                   work->id, candidate, uuidp, uuidc, &fallback,
                   &validates, &validates_to,
                   &forward_progress)) {
          goto done_do_not_write_candidate;
        }
      }
    }

    if (!advanced && progressive_entry_verify
        && have_prefix_state && prefix_state.is_progressive) {
      JpgOOOBridgeChoice entry_probe;

      resize_blockvector(candidate->b, num_blocks);
      blockvector_set_data_length(candidate->b, oldlength);
      memset(&best_bridge, 0, sizeof(best_bridge));
      memset(&entry_probe, 0, sizeof(entry_probe));
      if (best_choice.found && best_choice.is_immediate
          && jpg_reassembly_evaluate_progressive_bridge(
                 candidate, &prefix_state, true,
                 structural_prefix_blocks, num_blocks, oldlength,
                 best_choice.apparent, 1, 0, 0, false, &entry_probe)
          && jpg_reassembly_progressive_choice_supported(&entry_probe)) {
        best_bridge = entry_probe;
        progressive_entry_verify = false;
      }
      else {
        global_progressive_search = true;
        jpg_reassembly_rank_global_progressive_fragment(
            candidate, &prefix_state,
            structural_prefix_blocks,
            num_blocks, oldlength, last_apparent, &best_bridge);
        progressive_global_ambiguous =
            best_bridge.found
            && !jpg_reassembly_progressive_bridge_conclusive(&best_bridge)
            && bridge_shortlist.count > 1
            && best_bridge.boundary.valid
            && bridge_shortlist.choices[1].boundary.valid
            && best_bridge.boundary.normalized
                   * JPG_REASS_PROGRESSIVE_BOUNDARY_RATIO
                 >= bridge_shortlist.choices[1].boundary.normalized;
      }
      if (jpg_reassembly_checkpoint_requested()
          && jpg_reassembly_time_to_checkpoint(
                 work->id, candidate, uuidp, uuidc, &fallback,
                 &validates, &validates_to,
                 &forward_progress)) {
        goto done_do_not_write_candidate;
      }
    }

    if (!advanced && !strong_forward_continuation
        && format_known && have_prefix_state
        && !prefix_state.is_progressive
        && scalpel_state.blocksize < JPG_REASS_BASELINE_SEED_PROBE_BYTES
        && best_bridge.found && !best_bridge.full_validates
        && !best_bridge.direct_validates && best_bridge.suffix_len > 0
        && best_bridge.suffix_len < JPG_REASS_OOO_MIN_SUFFIX_PROBE
        && (!best_bridge.suffix_boundary.valid
            || best_bridge.suffix_boundary.normalized
                   > JPG_REASS_BASELINE_SUFFIX_BOUNDARY_LIMIT)) {
      // re-evaluate a short return when its exit seam lacks local support.
      best_bridge.suffix_start = -1;
      best_bridge.suffix_len = 0;
      memset(&best_bridge.suffix_boundary, 0,
             sizeof(best_bridge.suffix_boundary));
    }

    strong_baseline_entry =
        !advanced && format_known && have_prefix_state
        && !prefix_state.is_progressive && best_choice.found
        && best_choice.have_boundary && tail_actual >= 0
        && tail_actual < INT64_MAX
        && best_choice.actual > tail_actual + 1
        && best_baseline_entry.found
        && best_baseline_entry.moved_start != best_choice.apparent
        && best_baseline_entry.huffman_available
        && best_baseline_entry.huffman_support
        && best_baseline_entry.baseline_rate_supported
        && best_baseline_entry.boundary.valid
        && best_baseline_entry.boundary.normalized
               < best_choice.boundary.normalized
                     * JPG_REASS_BASELINE_FORWARD_BRIDGE_RATIO;

    if (!advanced && format_known && have_prefix_state
        && !prefix_state.is_progressive
        && !baseline_scatter_active
        && (num_blocks
                <= (uint64_t)jpg_reassembly_get_fixed_prefix_blocks(candidate)
                     + 1
            || strong_baseline_entry)
        && best_baseline_entry.found
        && best_baseline_entry.huffman_support
        && (strong_baseline_entry
            || (best_baseline_entry.baseline_rate_supported
                && best_baseline_entry.baseline_rate_deviation
                       < JPG_REASS_BASELINE_RATE_LIMIT))
        && (!best_bridge.found
            || (!best_bridge.full_validates
                && !best_bridge.direct_validates
                && (best_bridge.run_len > 1
                    || best_baseline_entry.moved_start
                           != best_bridge.moved_start
                    || jpg_reassembly_baseline_entry_score(
                           &best_baseline_entry)
                           < jpg_reassembly_baseline_entry_score(&best_bridge)
                                 * JPG_REASS_SCATTER_ENTRY_RATIO
                    || (best_choice.found
                        && best_choice.have_boundary
                        && best_baseline_entry.moved_start
                               == best_bridge.moved_start
                        && !jpg_reassembly_baseline_bridge_beats_forward(
                               &best_bridge, &best_choice)
                        && best_baseline_entry.boundary.valid
                        && best_baseline_entry.boundary.normalized
                               < best_choice.boundary.normalized
                                     * JPG_REASS_BASELINE_FORWARD_BRIDGE_RATIO))))) {
      best_bridge = best_baseline_entry;
      global_baseline_search = true;
    }

    if (!advanced && !strong_forward_continuation
        && format_known && !global_baseline_search
        && have_prefix_state && !prefix_state.is_progressive
        && (!prefix_state.hidden_boundary_recovery
            || baseline_scatter_active)
        && (baseline_scatter_active
            || ((baseline_entry_verify
                 || (!best_choice.found
                     && (!best_bridge.found
                         || best_bridge.suffix_len == 0)))
                && (!best_bridge.found
                    || best_bridge.suffix_len == 0)))) {
      resize_blockvector(candidate->b, num_blocks);
      blockvector_set_data_length(candidate->b, oldlength);
      if (baseline_scatter_active) {
        memset(&best_bridge, 0, sizeof(best_bridge));
      }
      global_baseline_search = true;
      jpg_reassembly_rank_global_baseline_block(
          candidate, &prefix_state,
          jpg_reassembly_get_fixed_prefix_blocks(candidate),
          num_blocks, oldlength, last_apparent,
          !baseline_scatter_active, &best_bridge);
      if (baseline_scatter_active && best_bridge.found
          && !prefix_state.hidden_boundary_recovery) {
        (void)jpg_reassembly_refine_baseline_scatter_lookahead(
            candidate, &prefix_state,
            jpg_reassembly_get_fixed_prefix_blocks(candidate),
            num_blocks, oldlength, last_apparent, &best_bridge);
        // a rejected seed with no local image baseline must not be replaced by
        // an extreme seam that is only the least-bad unsupported guess.
        baseline_scatter_ambiguous =
            baseline_seed_needs_search
            && num_blocks == structural_prefix_blocks
            && best_bridge.boundary.valid
            && best_bridge.boundary.baseline_mad <= 1.0
            && best_bridge.boundary.normalized
                   > JPG_REASS_BASELINE_UNSUPPORTED_SCORE_LIMIT;
      }
      if (jpg_reassembly_checkpoint_requested()
          && jpg_reassembly_time_to_checkpoint(
                 work->id, candidate, uuidp, uuidc, &fallback,
                 &validates, &validates_to,
                 &forward_progress)) {
        goto done_do_not_write_candidate;
      }
    }

    // retain the strongest prefix join independently of its suffix seam for
    // retry when the complete bridge remains ambiguous.
    jpg_reassembly_shortlist_baseline_entry_only(&best_baseline_entry);

    if (jpg_reassembly_debug_candidate(candidate)) {
      int64_t trace_start = blockvector_get_num_blocks(candidate->b) > 0
                            ? blockvector_get_actual_blocknumber(candidate->b, 0)
                            : -1;
      lock_fprintf(stderr,
                   "[jpgdbg] ranked file_start=%" PRId64
                   " forward=%d choice=%" PRId64
                   " boundary=%d norm=%.3f bridge=%d full=%d moved=%" PRId64
                   "+%" PRIu64 " huffman=%d/%d suffix=%" PRId64 "+%" PRIu64
                   " norm=%.3f modes=%d/%d/%d global=%d/%d\n",
                   trace_start, best_choice.found ? 1 : 0,
                   best_choice.apparent,
                   best_choice.have_boundary ? 1 : 0,
                   best_choice.boundary.normalized,
                   best_bridge.found ? 1 : 0,
                   best_bridge.full_validates ? 1 : 0,
                   best_bridge.moved_start, best_bridge.run_len,
                   best_bridge.huffman_available ? 1 : 0,
                   best_bridge.huffman_support ? 1 : 0,
                   best_bridge.suffix_start, best_bridge.suffix_len,
                   best_bridge.boundary.normalized,
                   baseline_scatter_active ? 1 : 0,
                   baseline_entry_verify ? 1 : 0,
                   progressive_entry_verify ? 1 : 0,
                   global_baseline_search ? 1 : 0,
                   global_progressive_search ? 1 : 0);
      for (uint32_t rank = 0; rank < bridge_shortlist.count; rank++) {
          const JpgOOOBridgeChoice *choice =
              &bridge_shortlist.choices[rank];

          lock_fprintf(stderr,
                       "[jpgdbg] bridge_rank file_start=%" PRId64
                       " rank=%" PRIu32
                       " moved=%" PRId64 "+%" PRIu64
                       " suffix=%" PRId64 "+%" PRIu64
                       " full=%d direct=%d huffman=%d/%d"
                       " entropy=%d/%d rate=%.6f norm=%.3f exit=%.3f"
                       " dc=%.0f\n",
                       trace_start, rank + 1,
                       choice->moved_start, choice->run_len,
                       choice->suffix_start, choice->suffix_len,
                       choice->full_validates ? 1 : 0,
                       choice->direct_validates ? 1 : 0,
                       choice->huffman_available ? 1 : 0,
                       choice->huffman_support ? 1 : 0,
                       choice->progressive_entropy_supported ? 1 : 0,
                       choice->progressive_entropy_complete ? 1 : 0,
                       choice->progressive_entropy_supported
                           ? choice->progressive_entropy_score
                           : choice->baseline_rate_deviation,
                       choice->boundary.normalized,
                       choice->suffix_boundary.normalized,
                       choice->max_dc_discontinuity);
      }
      for (uint32_t rank = 0;
           rank < bridge_shortlist.entry_only_count; rank++) {
          const JpgOOOBridgeChoice *choice =
              &bridge_shortlist.entry_only_choices[rank];

          lock_fprintf(stderr,
                       "[jpgdbg] entry_rank file_start=%" PRId64
                       " rank=%" PRIu32 " moved=%" PRId64 "+%" PRIu64
                       " huffman=%d/%d rate=%.6f norm=%.3f\n",
                       trace_start, rank + 1,
                       choice->moved_start, choice->run_len,
                       choice->huffman_available ? 1 : 0,
                       choice->huffman_support ? 1 : 0,
                       choice->baseline_rate_deviation,
                       choice->boundary.normalized);
      }
    }

    // without a viable forward path, or with only an unsupported jump, a weak
    // non-validating bridge is not enough evidence to replace the trusted prefix.
    baseline_bridge_ambiguous =
        !advanced && format_known && have_prefix_state
        && !prefix_state.is_progressive && best_bridge.found
        && ((!best_choice.found && !best_bridge.full_validates
             && !best_bridge.direct_validates && best_bridge.boundary.valid
             && best_bridge.boundary.normalized
                    > JPG_REASS_BASELINE_UNSUPPORTED_SCORE_LIMIT)
            || (raw_jump_requires_bridge && best_choice.found
                && best_choice.have_boundary
                && num_blocks <= (uint64_t)structural_prefix_blocks + 1
                && best_choice.boundary.normalized
                       > JPG_REASS_BASELINE_BRIDGE_SCORE_LIMIT
                && !best_bridge.full_validates
                && !best_bridge.direct_validates
                && best_bridge.suffix_len
                       < JPG_REASS_BASELINE_STRONG_SUFFIX_PROBE
                && best_bridge.suffix_len
                       < CEILDIV(JPG_REASS_BASELINE_SEED_PROBE_BYTES,
                                 scalpel_state.blocksize)
                && ((best_choice.boundary.baseline_mad > 1.0
                     && !jpg_reassembly_baseline_bridge_beats_forward(
                            &best_bridge, &best_choice))
                    || (best_bridge.suffix_len > 0
                        && best_bridge.boundary.valid
                        && best_bridge.boundary.normalized
                               >= best_choice.boundary.normalized
                                    * JPG_REASS_SCATTER_ENTRY_RATIO)))
            || (raw_jump_requires_bridge && best_choice.found
                && !best_choice.have_boundary
                && num_blocks <= (uint64_t)structural_prefix_blocks + 1
                && small_gap_boundary_unsupported
                && !best_bridge.full_validates
                && !best_bridge.direct_validates
                && best_bridge.boundary.valid
                && best_bridge.boundary.normalized
                       > JPG_REASS_BASELINE_UNSUPPORTED_SCORE_LIMIT * 2.0)
            || (best_bridge.full_validates && !best_bridge.boundary.valid
                && bridge_shortlist.count > 1
                && bridge_shortlist.choices[1].full_validates
                && !bridge_shortlist.choices[1].boundary.valid));
    // a global progressive tie has no image evidence for choosing one remote
    // fragment over another, so retain the trusted prefix.
    if (baseline_scatter_ambiguous || baseline_bridge_ambiguous
        || progressive_global_ambiguous) {
      resize_blockvector(candidate->b, num_blocks);
      blockvector_set_data_length(candidate->b, oldlength);
      break;
    }

    prefer_bridge =
        !advanced && !strong_forward_continuation
        && format_known && best_bridge.found
        && ((have_prefix_state && prefix_state.is_progressive
             && (global_progressive_search
                 || jpg_reassembly_progressive_bridge_preferred(
                        &best_bridge, &best_choice)))
            || (!(have_prefix_state && prefix_state.is_progressive)
                && (!best_choice.found
                    || (!best_choice.have_boundary
                        && !(best_choice.is_immediate
                             && best_choice.has_followon_support))
                    || best_bridge.full_validates
                    || (baseline_scatter_active
                        && global_baseline_search
                        && best_bridge.huffman_support)
                    || (baseline_entry_verify
                        && !(best_choice.is_immediate
                             && best_choice.has_followon_support)
                        && best_bridge.huffman_support
                        && best_bridge.baseline_rate_supported
                        && best_bridge.baseline_rate_deviation
                               < JPG_REASS_BASELINE_RATE_LIMIT
                        && (!best_choice.have_boundary
                            || jpg_reassembly_baseline_bridge_beats_forward(
                                   &best_bridge, &best_choice)))
                    || (strong_baseline_entry && global_baseline_search
                        && best_bridge.huffman_support)
                    || ((!best_choice.has_followon_support
                         || best_bridge.huffman_support)
                        && jpg_reassembly_baseline_bridge_beats_forward(
                               &best_bridge, &best_choice)))));
    bridge_to_commit = best_bridge;
    if (bridge_to_commit.hidden_boundary_candidate
        && prefix_state.hidden_boundary_progress.active) {
      JPGHiddenBoundaryProgress *progress =
          &prefix_state.hidden_boundary_progress;

      while (progress->next_choice < progress->choice_count
             && progress->choices[progress->next_choice].actual_block
                    != filemirror_actual_blocknumber(
                        scalpel_state.filemirror, bridge_to_commit.moved_start)) {
        progress->next_choice++;
      }
      if (progress->next_choice < progress->choice_count) {
        progress->next_choice++;
      }
      jpg_put_decoder_state(candidate->carvehashkey, &prefix_state);
    }
    if (prefer_bridge && have_prefix_state && !prefix_state.is_progressive
        && !best_bridge.full_validates && !best_bridge.direct_validates
        && best_bridge.suffix_len > 0) {
      // The entry seam establishes the displaced run. Its return suffix is a
      // separate hypothesis that remains available through the retry frame.
      bridge_to_commit.full_validates = false;
      bridge_to_commit.suffix_start = -1;
      bridge_to_commit.suffix_len = 0;
      memset(&bridge_to_commit.suffix_boundary, 0,
             sizeof(bridge_to_commit.suffix_boundary));
    }
    if (!advanced && format_known && have_prefix_state && best_bridge.found
        && ((!baseline_scatter_active && !global_baseline_search
             && !global_progressive_search)
            || best_bridge.hidden_boundary_candidate)
        && (best_bridge.hidden_boundary_candidate
            || jpg_reassembly_has_physical_gap(candidate)
            || (best_choice.found
                && best_choice.actual > tail_actual + 1))) {
      resize_blockvector(candidate->b, num_blocks);
      blockvector_set_data_length(candidate->b, oldlength);
      jpg_reassembly_save_retry_frame(
          candidate, &prefix_state, have_prefix_state, &best_choice,
          &best_bridge, prefer_bridge ? &bridge_to_commit : NULL,
          &bridge_shortlist, retry_search);
    }
    if (!advanced
        && jpg_reassembly_retry_alternative_preferred(retry_search)
        && jpg_reassembly_restore_retry(candidate, retry_search,
                                        &validates, &validates_to, true)) {
      gallop = 0;
      progressive_scatter_followup = false;
      if (validates) {
        candidate->flavor = VALIDATED;
        goto done_write_candidate;
      }
      continue;
    }

    if (prefer_bridge) {
      bool saved_fallback = false;

      resize_blockvector(candidate->b, num_blocks);
      blockvector_set_data_length(candidate->b, oldlength);
      if (!fallback.pending && have_prefix_state
          && !best_bridge.full_validates
          && !(prefix_state.is_progressive
               && (best_bridge.progressive_entropy_complete
                   || (best_bridge.progressive_entropy_supported
                       && best_bridge.progressive_entropy_score
                              < JPG_REASS_PROGRESSIVE_RATE_LIMIT)))
          && best_choice.found
          && best_choice.apparent == natural_tail_start) {
        jpg_reassembly_save_fallback(candidate, &prefix_state,
                                     have_prefix_state, &best_choice,
                                     &fallback);
        saved_fallback = fallback.pending;
      }
      if ((bridge_to_commit.full_validates
           && bridge_to_commit.direct_validates
           && jpg_reassembly_try_ooo_candidate_run(
                  candidate, &prefix_state, have_prefix_state,
                  &validates, &validates_to,
                  jpg_reassembly_get_fixed_prefix_blocks(candidate),
                  num_blocks, oldlength,
                  bridge_to_commit.moved_start, bridge_to_commit.run_len, 0, 0,
                  true, true, true, NULL))
          || (bridge_to_commit.full_validates
              && !bridge_to_commit.direct_validates
           && jpg_reassembly_try_bridge_tail_validation(
                  candidate, &prefix_state, have_prefix_state,
                  &validates, &validates_to,
                  jpg_reassembly_get_fixed_prefix_blocks(candidate),
                  num_blocks, oldlength, bridge_to_commit.moved_start,
                  bridge_to_commit.run_len, bridge_to_commit.suffix_start,
                  true, NULL))
          || (!bridge_to_commit.full_validates
              && jpg_reassembly_try_ooo_candidate_run(
                  candidate, &prefix_state, have_prefix_state,
                  &validates, &validates_to,
                  jpg_reassembly_get_fixed_prefix_blocks(candidate),
                  num_blocks, oldlength,
                  bridge_to_commit.moved_start, bridge_to_commit.run_len,
                  bridge_to_commit.suffix_start, bridge_to_commit.suffix_len,
                  false, true, true, NULL))) {
        advanced = true;
      }
      if (!advanced && saved_fallback) {
        jpg_reassembly_clear_fallback(&fallback);
      }
    }

    if (advanced) {
      if (have_prefix_state && prefix_state.is_progressive) {
        bool strong_progressive_transition =
            best_bridge.progressive_entropy_complete
            || (best_bridge.boundary.valid
                && best_bridge.progressive_entropy_supported
                && best_bridge.progressive_entropy_score
                       < JPG_REASS_PROGRESSIVE_RATE_LIMIT);

        progressive_scatter_followup =
            global_progressive_search && !validates
            && !best_bridge.direct_validates && !best_bridge.full_validates
            && !strong_progressive_transition;
      }
      if (validates) {
        candidate->flavor = VALIDATED;
        blockvector_set_data_length(candidate->b, validates_to + 1);
        resize_blockvector(candidate->b,
                           CEILDIV(blockvector_get_data_length(candidate->b),
                                   scalpel_state.blocksize));
        goto done_write_candidate;
      }
      continue;
    }

    if (best_choice.found) {
      resize_blockvector(candidate->b, num_blocks + 1);
      blockvector_set_apparent_blocknumber(candidate->b, num_blocks,
                                           best_choice.apparent);
      (void)inflate_blockvector_single_block(candidate->b, num_blocks);
      validates = best_choice.validates;
      validates_to = best_choice.commit_validates_to;
      if (best_choice.have_state) {
        jpg_put_decoder_state(candidate->carvehashkey, &best_choice.state);
      }
      if (validates) {
        candidate->flavor = VALIDATED;
        blockvector_set_data_length(candidate->b, validates_to + 1);
        resize_blockvector(candidate->b,
                           CEILDIV(blockvector_get_data_length(candidate->b),
                                   scalpel_state.blocksize));
        goto done_write_candidate;
      }

      candidate->best_validates_to = validates_to;
      candidate->newblock = best_choice.actual;
      blockvector_set_data_length(candidate->b, validates_to + 1);
      resize_blockvector(candidate->b,
                         CEILDIV(blockvector_get_data_length(candidate->b),
                                 scalpel_state.blocksize));
      jpg_reassembly_debug_dump("forward_best_accept", candidate,
                                best_choice.apparent,
                                best_choice.score_validates_to);
      advanced = true;

      if (best_choice.reaches_trial_end) {
        uint64_t before_blocks = blockvector_get_num_blocks(candidate->b);
        uint64_t before_length = blockvector_get_data_length(candidate->b);
        void *saved_state = jpg_get_decoder_state(candidate->carvehashkey);
        bool gallop_checkpoint;
        bool gallop_progress;

        candidate->fastpath = true;
        gallop_checkpoint =
            jpg_reassembly_gallop(candidate, &validates_to, &validates,
                                  &gallop, uuidp, uuidc);
        gallop_progress =
            blockvector_get_num_blocks(candidate->b) != before_blocks
            || blockvector_get_data_length(candidate->b) != before_length;
        if (!gallop_progress && saved_state) {
          jpg_put_decoder_state(candidate->carvehashkey, saved_state);
        }
        if (saved_state) {
          free(saved_state);
        }
        if (gallop_checkpoint
            && jpg_reassembly_time_to_checkpoint(
                   work->id, candidate, uuidp, uuidc, &fallback,
                   &validates, &validates_to,
                   &forward_progress)) {
          goto done_do_not_write_candidate;
        }
        if (validates) {
          candidate->flavor = VALIDATED;
          blockvector_set_data_length(candidate->b, validates_to + 1);
          resize_blockvector(candidate->b,
                             CEILDIV(blockvector_get_data_length(candidate->b),
                                     scalpel_state.blocksize));
          goto done_write_candidate;
        }
        if (!gallop_progress) {
          gallop = 0;
        }
      }
    }

    if (advanced) {
      continue;
    }

    resize_blockvector(candidate->b, num_blocks);
    blockvector_set_data_length(candidate->b, oldlength);

    if (jpg_reassembly_time_to_checkpoint(work->id, candidate, uuidp, uuidc,
                                          &fallback, &validates,
                                          &validates_to,
                                          &forward_progress)) {
      goto done_do_not_write_candidate;
    }

    if (anchor_scan) {
      bool anchor_checkpoint = false;

      if (jpg_reassembly_try_confidence_anchor_scan(
              candidate, &prefix_state, have_prefix_state,
              &validates, &validates_to,
              jpg_reassembly_get_fixed_prefix_blocks(candidate),
              num_blocks, oldlength, tail_apparent, first_apparent,
              last_apparent, &anchor_checkpoint)) {
        if (validates) {
          candidate->flavor = VALIDATED;
          blockvector_set_data_length(candidate->b, validates_to + 1);
          resize_blockvector(candidate->b,
                             CEILDIV(blockvector_get_data_length(candidate->b),
                                     scalpel_state.blocksize));
          goto done_write_candidate;
        }
        {
          uint64_t anchor_gallop = 0;

          // A high-confidence bridge usually restores a contiguous tail.
          while (!validates) {
            uint64_t before_blocks = blockvector_get_num_blocks(candidate->b);
            uint64_t before_length = blockvector_get_data_length(candidate->b);
            void *saved_state = jpg_get_decoder_state(candidate->carvehashkey);
            bool gallop_checkpoint =
                jpg_reassembly_gallop(candidate, &validates_to, &validates,
                                      &anchor_gallop, uuidp, uuidc);
            bool gallop_progress =
                blockvector_get_num_blocks(candidate->b) != before_blocks
                || blockvector_get_data_length(candidate->b) != before_length;

            if (!gallop_progress && saved_state) {
              jpg_put_decoder_state(candidate->carvehashkey, saved_state);
            }
            if (saved_state) {
              free(saved_state);
            }
            if (gallop_checkpoint
                && jpg_reassembly_time_to_checkpoint(
                       work->id, candidate, uuidp, uuidc, &fallback,
                       &validates, &validates_to,
                       &forward_progress)) {
              goto done_do_not_write_candidate;
            }
            if (validates) {
              candidate->flavor = VALIDATED;
              blockvector_set_data_length(candidate->b, validates_to + 1);
              resize_blockvector(candidate->b,
                                 CEILDIV(blockvector_get_data_length(candidate->b),
                                         scalpel_state.blocksize));
              goto done_write_candidate;
            }
            if (!gallop_progress) {
              if (scalpel_state.gallop_factor > 1
                  && anchor_gallop > scalpel_state.gallop_factor) {
                uint64_t next_gallop = anchor_gallop / scalpel_state.gallop_factor;

                anchor_gallop = next_gallop >= scalpel_state.gallop_factor
                                ? next_gallop / scalpel_state.gallop_factor
                                : 0;
                continue;
              }
              break;
            }
            if (jpg_reassembly_time_to_checkpoint(
                    work->id, candidate, uuidp, uuidc, &fallback,
                    &validates, &validates_to,
                    &forward_progress)) {
              goto done_do_not_write_candidate;
            }
          }
        }
        advanced = true;
      }
      if (anchor_checkpoint
          && jpg_reassembly_time_to_checkpoint(
                 work->id, candidate, uuidp, uuidc, &fallback,
                 &validates, &validates_to,
                 &forward_progress)) {
        goto done_do_not_write_candidate;
      }
    }

    if (advanced) {
      continue;
    }

    {
      bool ooo_checkpoint = false;

      if (jpg_reassembly_try_ooo_run_repair(candidate, &prefix_state,
                                            have_prefix_state,
                                            &validates, &validates_to,
                                            jpg_reassembly_get_fixed_prefix_blocks(candidate),
                                            0, 0,
                                            false,
                                            false, false,
                                            JPG_REASS_OOO_ANCHOR_BACKSCAN_BLOCKS,
                                            &ooo_checkpoint)) {
        if (validates) {
          candidate->flavor = VALIDATED;
          blockvector_set_data_length(candidate->b, validates_to + 1);
          resize_blockvector(candidate->b,
                             CEILDIV(blockvector_get_data_length(candidate->b),
                                     scalpel_state.blocksize));
          goto done_write_candidate;
        }
        advanced = true;
      }
      if (ooo_checkpoint
          && jpg_reassembly_time_to_checkpoint(
                 work->id, candidate, uuidp, uuidc, &fallback,
                 &validates, &validates_to,
                 &forward_progress)) {
        goto done_do_not_write_candidate;
      }
    }

    if (advanced) {
      continue;
    }

    if (jpg_reassembly_restore_retry(candidate, retry_search, &validates,
                                     &validates_to, false)) {
      gallop = 0;
      progressive_scatter_followup = false;
      if (validates) {
        candidate->flavor = VALIDATED;
        goto done_write_candidate;
      }
      continue;
    }

    if (jpg_reassembly_restore_fallback(candidate, &fallback, &validates,
                                        &validates_to)) {
      gallop = 0;
      if (validates) {
        candidate->flavor = VALIDATED;
        goto done_write_candidate;
      }
      continue;
    }

    {
      bool run_order_changed = false;
      bool run_order_checkpoint = false;

      if (jpg_reassembly_try_terminal_run_order_repair(
              candidate, &validates, &validates_to,
              jpg_reassembly_get_fixed_prefix_blocks(candidate),
              true, &run_order_changed, &run_order_checkpoint)) {
        candidate->flavor = PROMISING;
        if (!scalpel_state.write_promising) {
          destroy_candidate(&candidate);
          goto done_do_not_write_candidate;
        }
        goto done_write_candidate;
      }
      if (run_order_changed) {
        gallop = 0;
        progressive_scatter_followup = false;
        continue;
      }
      if (run_order_checkpoint
          && jpg_reassembly_time_to_checkpoint(
                 work->id, candidate, uuidp, uuidc, &fallback,
                 &validates, &validates_to,
                 &forward_progress)) {
        goto done_do_not_write_candidate;
      }
    }

    if (format_known && have_prefix_state
        && !prefix_state.is_progressive
        && jpg_reassembly_try_preheader_tail_validation(
               candidate, &prefix_state, &validates, &validates_to,
               jpg_reassembly_get_fixed_prefix_blocks(candidate),
               num_blocks, oldlength, 0)) {
      candidate->flavor = VALIDATED;
      blockvector_set_data_length(candidate->b, validates_to + 1);
      resize_blockvector(candidate->b,
                         CEILDIV(blockvector_get_data_length(candidate->b),
                                 scalpel_state.blocksize));
      goto done_write_candidate;
    }
    if (jpg_reassembly_checkpoint_requested()
        && jpg_reassembly_time_to_checkpoint(
               work->id, candidate, uuidp, uuidc, &fallback,
               &validates, &validates_to,
               &forward_progress)) {
      goto done_do_not_write_candidate;
    }

    if (format_known && have_prefix_state
        && !prefix_state.is_progressive
        && jpg_reassembly_try_footer_tail(
               candidate, &prefix_state, &validates, &validates_to,
               jpg_reassembly_get_fixed_prefix_blocks(candidate),
               num_blocks, oldlength)) {
      candidate->flavor = VALIDATED;
      goto done_write_candidate;
    }
    if (jpg_reassembly_checkpoint_requested()
        && jpg_reassembly_time_to_checkpoint(
               work->id, candidate, uuidp, uuidc, &fallback,
               &validates, &validates_to,
               &forward_progress)) {
      goto done_do_not_write_candidate;
    }

    if (jpg_reassembly_try_pending_hidden_rollback(
            candidate, &validates, &validates_to)) {
      gallop = 0;
      progressive_scatter_followup = false;
      continue;
    }

    jpg_reassembly_debug_dump("forward_no_progress", candidate, -1,
                              validates_to);
    break;
  }

  if (! scalpel_state.write_promising) {
    destroy_candidate(&candidate);
    goto done_do_not_write_candidate;
  }

done_write_candidate:
  if (candidate && candidate->flavor == VALIDATED
      && jpg_reassembly_has_ambiguous_join_order(candidate)) {
    candidate->flavor = PROMISING;
    if (!scalpel_state.write_promising) {
      destroy_candidate(&candidate);
      goto done_do_not_write_candidate;
    }
  }
  if (jpg_reassembly_debug_candidate(candidate)) {
    lock_fprintf(stderr,
                 "[jpgdbg] done_write local=%p caller=%p caller_blocks=%" PRIu64
                 " caller_length=%" PRIu64 "\n",
                 (void *)candidate, (void *)*c,
                 *c ? blockvector_get_num_blocks((*c)->b) : 0,
                 *c ? blockvector_get_data_length((*c)->b) : 0);
    jpg_reassembly_debug_dump("done_write", candidate, -1, validates_to);
  }
  write_candidate(c, false);
  goto done;

done_do_not_write_candidate:
done:
  jpg_reassembly_clear_fallback(&fallback);
  jpg_reassembly_clear_retry_search(retry_search);
  free(retry_search);
  jpg_active_retry_search = previous_retry_search;
  jpg_active_retry_key = previous_retry_key;
  jpg_boundary_preview_cache_invalidate();
  jpg_boundary_preview_cache = previous_boundary_preview_cache;
  jpg_reassembly_bridge_shortlist = previous_bridge_shortlist;
  free(materialization_cache.actual_blocks);
  free(materialization_cache.data);
  jpg_reassembly_materialization_cache = previous_materialization_cache;
}

#if defined(JPEG_TEST)
int main(int argc, char *argv[]) {
  struct stat file_info;
  bool validates, promising;
  uint64_t validates_to, len;
  char *buf;
  if (argc != 2) {
    printf("USAGE: %s filename.jpg\n", argv[0]);
    return 0;
  }
  if (stat(argv[1], &file_info)) {
    printf("Couldn't open JPEG file.\n");
    return 0;
  }
  len = file_info.st_size;
  buf = malloc(len + 100);
  int fd = open(argv[1], O_RDONLY);
  uint64_t i = 0;
  while (i < len) {
    int rc = read(fd, buf + i, len - i);
    if (rc <= 0) {
      break;
    }
    i += rc;
  }
  close(fd);
  JpgValidationContext ctx;
  memset(&ctx, 0, sizeof(ctx));
  ctx.data = (const uint8_t *)buf;
  ctx.length = len;
  JpgValidationResult result = jpg_validate_structure(&ctx);
  printf("Structural validation: result=%d, last_good=%lu, error=%lu\n", result, (unsigned long)ctx.last_good_pos,
         (unsigned long)ctx.error_pos);
  jpg_file_validate(buf, len, &validates, &validates_to, &promising, 0, JPEG_TEST_BLOCKSIZE, NULL);
  printf("jpg_file_validate(): validates=%d, validates_to=%lu, promising=%d\n", validates, (unsigned long)validates_to, promising);
  if (jpg_wrongblock_result.detected) {
    printf("Wrong-block detection: byte %lu via %s\n", (unsigned long)jpg_wrongblock_result.estimated_byte,
           jpg_wrongblock_result.method);
  }
  free(buf);
  return 0;
}

#endif
#endif
