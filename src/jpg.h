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
#include <fcntl.h>
#include <jerror.h>
#include <jpeglib.h>
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
} JPGHuffmanCheckpoint;

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

} JPGCarveState;

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

// jpg_serialize_carve_state — serialize/deserialize JPGCarveState for checkpointing.
// No internal pointers, so memcpy-safe via fwrite/fread.
static inline bool jpg_serialize_carve_state(void **state, FILE *fp, StateSerialization mode) {
  size_t (*fb)(void *ptr, size_t size, size_t nitems,
               FILE *stream) = mode == SERIALIZE ? (size_t (*)(void *, size_t, size_t, FILE *))fwrite
                                                 : (size_t (*)(void *, size_t, size_t, FILE *))fread;
  if (mode == DESERIALIZE) {
    *state = malloc(sizeof(JPGCarveState));
    check_memory_allocation(*state, __LINE__, __FILE__, "state");
  }
  if (fb(*state, sizeof(JPGCarveState), 1, fp) != 1) {
    perror("jpg carve state");
    handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
  }
  return true;
}

// jpg_clone_carve_state — deep copy (no pointers, memcpy is sufficient).
static inline void *jpg_clone_carve_state(const void *srcstate) {
  JPGCarveState *d = (JPGCarveState *)malloc(sizeof(JPGCarveState));
  check_memory_allocation(d, __LINE__, __FILE__, "d");
  memcpy(d, srcstate, sizeof(JPGCarveState));
  return d;
}

// jpg_free_carve_state — free state and NULL the pointer.
static inline void jpg_free_carve_state(void **state) {
  JPGCarveState **s = (JPGCarveState **)state;
  free(*s);
  *s = NULL;
}

// jpg_sizeof_carve_state — return sizeof for memcpy-based optimization.
static inline size_t jpg_sizeof_carve_state(const void *state) {
  (void)state;
  return sizeof(JPGCarveState);
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
  long first_errpos;      // first error position during partial decode (swallowed errors only)
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
  uint64_t final_byte_pos;
  uint64_t entropy_start;
  double bytes_per_mcu;
  double expected_bytes_per_mcu;
  double mcu_deviation;
  double max_mcu_deviation;
  double max_dc_discontinuity;
  uint64_t dc_discontinuity_pos;
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


// jpg_huffman_validate — walk the MCU entropy stream, detecting wrong blocks.
//
// Parameters:
//   ctx         — parsed JPEG structure (header tables, scan info, data pointer)
//   restore     — if non-NULL and valid, resume Huffman decoding from this checkpoint
//   save_to     — if non-NULL, save checkpoint state at the last good block boundary
//
// Returns: 0 if no error found, or the byte position of the first detected error.
static inline uint64_t jpg_huffman_validate(JpgValidationContext *ctx,
                                            JPGHuffmanCheckpoint *restore,
                                            JPGHuffmanCheckpoint *save_to) {
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

  if (save_to) {
    memset(save_to, 0, sizeof(JPGHuffmanCheckpoint));
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
  }

  for (uint32_t mcu = start_mcu; mcu < total_mcus; mcu++) {
    last_mcu_start_pos = bs.byte_pos;
    jpg_mcu_result.mcu_count = mcu;
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
      if (adaptive < 1000) adaptive = 1000;
      if (adaptive < local_dc_threshold) {
        local_dc_threshold = adaptive;
      }
      dc_calibrated = true;
    }

    // Check if we crossed a block boundary since last MCU
    if (jpg_current_blocksize > 0) {
      uint64_t mcu_block = bs.byte_pos / jpg_current_blocksize;
      if (mcu_block > checkpoint_block) {
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
        // DC CONTINUITY CHECK at block boundaries. Instead of checking
        // DC code LENGTH (which varies by Huffman table and causes false
        // rejections), check the decoded DC coefficient VALUE. A correct
        // continuation has smooth DC values (small diff from predictor).
        // A wrong block produces random bit alignment → large DC diff.
        //
        // OPUS47/J1: dc_diff is computed for all dc_sym values (0 and >0)
        // and the boundary check always fires on boundary crossing. The
        // previous code only checked inside `if (dc_sym > 0)` and relied
        // on an end-of-MCU fallback to advance current_block; that left a
        // hole where dc_sym==0 at a boundary-crossing MCU silently skipped
        // the check for that entire block.
        int dc_sym = jpg_bs_decode_huffman(&bs, dc_tbl);
        if (dc_sym < 0) {
          if (bs.at_restart) {
            goto handle_restart;
          }
          if (bs.byte_pos >= ctx->length) {
            return 0;    // Clean truncation
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
            return last_mcu_start_pos > 0 ? last_mcu_start_pos : bs.byte_pos;
          }
          dc_diff = (dc_extra < (1 << (dc_sym - 1))) ? dc_extra - (1 << dc_sym) + 1 : dc_extra;
          comp_dc_predictor[sc->comp_idx] += dc_diff;
        }

        // DC CONTINUITY CHECK: runs unconditionally on boundary crossing.
        // When dc_diff==0 the threshold check trivially passes, but we
        // still advance current_block so subsequent MCUs in the new block
        // don't re-fire. This closes the dc_sym==0 boundary hole.
        if (jpg_current_blocksize > 0) {
          uint64_t dc_block = bs.byte_pos / jpg_current_blocksize;
          if (dc_block > current_block) {
            int32_t abs_dc_diff = (dc_diff < 0) ? -dc_diff : dc_diff;
            if (abs_dc_diff > max_observed_dc_diff) {
              max_observed_dc_diff = abs_dc_diff;
            }
            if (abs_dc_diff > local_dc_threshold) {
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
            return last_mcu_start_pos > 0 ? last_mcu_start_pos : bs.byte_pos;
          }
          if (ac_sym == 0) {
            break;
          }
          int run = (ac_sym >> 4) & 0x0F;
          int size = ac_sym & 0x0F;
          ac_count += run + 1;
          if (ac_count > 63) {
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
              return last_mcu_start_pos > 0 ? last_mcu_start_pos : bs.byte_pos;
            }
            int32_t mag = (ac_extra < (1 << (size - 1))) ? ac_extra - (1 << size) + 1 : ac_extra;
            ac_block_sum += abs(mag);
          }
        }

        // Threshold 8000 - catches garbage data that decodes to large AC values
        if (ac_block_sum > 8000) {
          return last_mcu_start_pos > 0 ? last_mcu_start_pos : bs.byte_pos;
        }

      }
    }
    // OPUS47/J1: removed the blind end-of-MCU advance of current_block.
    // The inner DC boundary check now handles all boundary crossings,
    // including the dc_sym==0 case. Advancing unconditionally here would
    // blow past boundaries for which the DC check never got a chance.
    // Note: if AC reading crosses a boundary, the NEXT MCU's DC read will
    // see dc_block > current_block and fire the check then — correct.
    mcus_since_restart++;

  handle_restart:
    if (bs.at_restart || (restart_interval > 0 && mcus_since_restart >= restart_interval)) {
      // Reset predictors on restart
      for (int k = 0; k < JPG_MAX_COMPONENTS; k++) {
        comp_dc_predictor[k] = 0;
      }

      bs.bit_pos = 0;
      bs.at_restart = false;
      // Find and verify the next RST marker
      while (bs.byte_pos < bs.length) {
        if (bs.data[bs.byte_pos] == 0xFF && bs.byte_pos + 1 < bs.length) {
          uint8_t next = bs.data[bs.byte_pos + 1];
          if (next >= M_RST0 && next <= M_RST7) {
            // RST sequence verification: wrong block ordering causes RST numbers
            // to be out of sequence. This is definitive proof of wrong blocks.
            uint8_t rst_num = next - M_RST0;
            if (rst_num != expected_rst) {
              uint64_t rst_pos = bs.byte_pos;
              // Return the block boundary containing this wrong RST marker
              if (jpg_current_blocksize > 0) {
                return (rst_pos / jpg_current_blocksize) * jpg_current_blocksize;
              }
              return rst_pos;
            }
            bs.byte_pos += 2;
            break;
          }
        }
        bs.byte_pos++;
      }
      expected_rst = (expected_rst + 1) & 0x07;
      mcus_since_restart = 0;
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
    return last_mcu_start_pos;
  }

  if (bs.hit_marker) {
    return bs.marker_pos;
  }

  return 0;
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

  // Note: jpg_wrongblock_result is now reset at start of jpg_file_validate

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
  // If partial decode swallowed errors, cap validates_to at the first swallowed
  // error position. This only fires for errors during jpeg_read_coefficients
  // (not header-phase warnings), so it won't affect correct files.
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

// jpg_count_scanlines — quickly count how many scanlines libjpeg can decode from this data.
static inline JDIMENSION jpg_count_scanlines(char *data, uint64_t length) {
  struct jpeg_decompress_struct cinfo;
  struct jpg_error_mgr jerr;
  jpg_mem_source cd;
  JDIMENSION count = 0;

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
    goto cs_done;
  }
  if (jpeg_read_header(&cinfo, TRUE) != JPEG_HEADER_OK) {
    goto cs_done;
  }
  cinfo.out_color_space = JCS_RGB;
  jpeg_start_decompress(&cinfo);
  {
    JDIMENSION stride = cinfo.output_width * cinfo.output_components;
    uint8_t *row = (uint8_t *)malloc(stride);
    JSAMPROW rp[1];
    rp[0] = row;
    while (cinfo.output_scanline < cinfo.output_height) {
      if (jpeg_read_scanlines(&cinfo, rp, 1) == 0) {
        break;
      }
      count++;
    }
    free(row);
  }
  jpeg_abort_decompress(&cinfo);
cs_done:
  jpg_allow_partial_decode = 0;
  jpeg_destroy_decompress(&cinfo);
  return count;
}

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

static inline bool jpg_should_run_seam_detector(uint64_t length, uint32_t blocksize) {
  if (blocksize == 0) {
    return false;
  }
  // Interior seam detection is only meaningful once the candidate has grown
  // beyond the shallow header/prefix stage. Running it on 2-3 block prefixes
  // falsely demotes both correct and incorrect partials to the first block.
  return length >= (uint64_t)blocksize * 4;
}

// Detect a strong interior seam in the decoded image. This is used only on the
// ambiguous "truncated but still decodes" path, where wrong shifted tails often
// introduce a large row-to-row discontinuity well before the bottom of the
// image, while true tail truncations tend to confine corruption near the end.
static inline bool jpg_detect_interior_seam(char *data, uint64_t length,
                                            double *early_max_out, JDIMENSION *early_row_out) {
  struct jpeg_decompress_struct cinfo;
  struct jpg_error_mgr jerr;
  jpg_mem_source cd;
  uint8_t * volatile prev = NULL;
  uint8_t * volatile cur = NULL;
  volatile double total_mad = 0.0;
  volatile uint32_t mad_count = 0;
  volatile double early_max = 0.0;
  volatile JDIMENSION early_row = 0;
  volatile bool detected = false;

  if (early_max_out) {
    *early_max_out = 0.0;
  }
  if (early_row_out) {
    *early_row_out = 0;
  }

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
    goto seam_done;
  }
  if (jpeg_read_header(&cinfo, TRUE) != JPEG_HEADER_OK) {
    goto seam_done;
  }
  cinfo.out_color_space = JCS_RGB;
  jpeg_start_decompress(&cinfo);

  if (cinfo.output_height < 64 || cinfo.output_width == 0 || cinfo.output_components == 0) {
    goto seam_done;
  }

  {
    JDIMENSION stride = cinfo.output_width * cinfo.output_components;
    JDIMENSION cutoff = (cinfo.output_height * 9) / 10;
    JSAMPROW rp[1];

    prev = (uint8_t *)malloc(stride);
    cur = (uint8_t *)malloc(stride);
    check_memory_allocation((void *)prev, __LINE__, __FILE__, "jpg_seam_prev");
    check_memory_allocation((void *)cur, __LINE__, __FILE__, "jpg_seam_cur");

    rp[0] = (JSAMPROW)prev;
    if (jpeg_read_scanlines(&cinfo, rp, 1) != 1) {
      goto seam_done;
    }

    while (cinfo.output_scanline < cinfo.output_height) {
      rp[0] = (JSAMPROW)cur;
      if (jpeg_read_scanlines(&cinfo, rp, 1) != 1) {
        break;
      }

      JDIMENSION row = cinfo.output_scanline - 1;
      double mad = jpg_row_mad((const uint8_t *)prev, (const uint8_t *)cur, stride);
      total_mad += mad;
      mad_count++;

      if (row > 32 && row < cutoff && mad > early_max) {
        early_max = mad;
        early_row = row;
      }

      uint8_t *tmp = (uint8_t *)prev;
      prev = cur;
      cur = tmp;
    }

    if (mad_count >= 32) {
      double mean_mad = total_mad / (double)mad_count;
      /*
       * A wrong inserted fragment often creates a single very strong interior
       * seam. Keep this detector conservative: it only needs to catch the
       * narrow class of candidates that otherwise validate cleanly to EOF.
       */
      if (early_row > 32
          && early_max >= 40.0
          && early_max >= mean_mad * 6.0) {
        detected = true;
      }
    }
  }

seam_done:
  jpg_allow_partial_decode = 0;
  if (early_max_out) {
    *early_max_out = early_max;
  }
  if (early_row_out) {
    *early_row_out = early_row;
  }
  free((void *)prev);
  free((void *)cur);
  jpeg_destroy_decompress(&cinfo);
  return detected;
}

static inline bool jpg_apply_libvalidate_seam_guard(char *data,
                                                    uint64_t length,
                                                    uint32_t blocksize,
                                                    const JPGCarveState *local_state,
                                                    bool *validates,
                                                    uint64_t *validates_to,
                                                    bool *promising) {
  double seam_mad = 0.0;
  JDIMENSION seam_row = 0;
  uint64_t fallback;

  if (!validates || !validates_to || !promising || !*validates
      || !jpg_should_run_seam_detector(length, blocksize)) {
    return false;
  }

  if (!jpg_detect_interior_seam(data, length, &seam_mad, &seam_row)) {
    return false;
  }

  fallback = (length > blocksize) ? (length - blocksize - 1) : 0;
  if (local_state && local_state->prev_validates_to + 1 < length) {
    fallback = local_state->prev_validates_to;
  }
  if (length > 0 && fallback >= length) {
    fallback = length - 1;
  }

  *validates = false;
  *promising = true;
  *validates_to = fallback;

  if (!jpg_wrongblock_result.detected
      || fallback + 1 < jpg_wrongblock_result.estimated_byte) {
    jpg_wrongblock_result.detected = true;
    jpg_wrongblock_result.estimated_byte = fallback + 1;
    jpg_wrongblock_result.confidence = seam_mad;
    jpg_wrongblock_result.method = "row_mad_seam";
  }

  if (jpg_validate_debug_enabled()) {
    lock_fprintf(stderr,
                 "[jpgvdbg] seam len=%" PRIu64 " row=%u mad=%.3f fallback=%" PRIu64 "\n",
                 length, seam_row, seam_mad, fallback);
  }

  return true;
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
  static const uint64_t JPG_ZERO_RUN_RELOCATE_MIN_BLOCKS = 2;
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

  if (zero_blocks < JPG_ZERO_RUN_RELOCATE_MIN_BLOCKS
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
  static const uint64_t JPG_ZERO_RUN_RELOCATE_MIN_BLOCKS = 2;
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
  if (start_block >= limit_block) {
    return 0;
  }

  for (uint64_t blk = start_block; blk < limit_block; blk++) {
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
      if (run_len >= JPG_ZERO_RUN_RELOCATE_MIN_BLOCKS) {
        return run_start * blocksize;
      }
      run_start = UINT64_MAX;
      run_len = 0;
    }
  }

  if (run_len >= JPG_ZERO_RUN_RELOCATE_MIN_BLOCKS) {
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
// Scan forward for an 0xFF that is followed by a byte in [0x02, 0xBF] — the
// invalid-marker-in-entropy signature. Returns the file byte offset of the
// offending 0xFF, or 0 if none found in [start, end).
static inline uint64_t jpg_ff_find_invalid_marker(const uint8_t *data,
                                                  uint64_t start,
                                                  uint64_t end) {
  if (end < 2 || start + 1 >= end) {
    return 0;
  }
  for (uint64_t i = start; i + 1 < end; i++) {
    if (data[i] == 0xFF) {
      uint8_t next = data[i + 1];
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
  if (blocksize == 0 || length <= blocksize) {
    return length;
  }
  uint64_t num_blocks = length / blocksize;
  for (uint64_t blk = start_blk; blk < num_blocks; blk++) {
    uint64_t block_start = blk * (uint64_t)blocksize;
    uint64_t block_end = block_start + blocksize;
    if (block_end > length) block_end = length;
    const uint8_t *block_data = (const uint8_t *)data + block_start;

    // Second-header check — runs on every block past the first, regardless
    // of entropy state: a spurious SOI inside a candidate means a different
    // file starts at this block.
    if (blk > 0 && block_end >= block_start + 2
        && block_data[0] == 0xFF && block_data[1] == 0xD8) {
      return block_start;
    }

    // Entropy scan only where we know we're past SOS.
    if (entropy_start_byte > 0 && block_end > entropy_start_byte) {
      uint64_t scan_start = block_start > entropy_start_byte
                                ? block_start
                                : entropy_start_byte;
      uint64_t inv_pos = jpg_ff_find_invalid_marker(
          (const uint8_t *)data, scan_start, block_end);
      if (inv_pos > 0) {
        // Truncate at the block containing the invalid marker so downstream
        // keeps the prior validated prefix.
        return block_start;
      }
    }
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
  // OPUS47/J9: stack-allocate instead of calloc — JPGCarveState is ~1.4KB,
  // well within thread stack, and saves ~N million allocator calls per run.
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
    JPGCarveState *saved = (JPGCarveState *)carve_get_state(carvehashkey);
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
          carve_put_state(carvehashkey, local_state);
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
    uint64_t huffman_error_pos = jpg_huffman_validate(&ctx, huff_restore, &huff_save);
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
                                                    local_state->prev_validates_to,
                                                    huffman_error_pos);
        if (zero_run_pos > 0 && zero_run_pos < huffman_error_pos) {
          huffman_error_pos = zero_run_pos;
        }
      }
      *validates = false;
      *validates_to = huffman_error_pos - 1;
      *promising = true;
    }
    else {
      // Huffman clean — run libjpeg for final validation.
      // libjpeg is authoritative for setting validates=true.
      bool lib_validates, lib_promising;
      uint64_t lib_validates_to;
      jpg_libjpeg_validate(data, length, &lib_validates, &lib_validates_to, &lib_promising,
                           needleidx, blocksize, carvehashkey);
      if (lib_validates) {
        *validates = true;
        *validates_to = lib_validates_to;
        *promising = false;
      }
      else {
        uint64_t zero_run_prefix_validates_to =
            local_state->prev_validates_to > initial_prefix_validates_to
                ? local_state->prev_validates_to
                : initial_prefix_validates_to;
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
          || (save_length > local_state->checkpoint_pos && save_length >= blocksize)) {
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
          carve_put_state(carvehashkey, save_state);
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
    jpg_current_blocksize = blocksize;
    jpg_libjpeg_validate(data, length, &lib_validates, &lib_validates_to, &lib_promising, needleidx, blocksize, carvehashkey);

    JPGHuffmanCheckpoint huff_save;
    uint64_t huffman_error_pos = jpg_huffman_validate(&ctx, NULL, &huff_save);
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

    // Record wrongblock info for diagnostic purposes
    if (huffman_error_pos > 0 && !lib_validates) {
      huffman_error_pos = jpg_relocate_error_over_zero_run(data, length,
                                                           blocksize,
                                                           ctx.entropy_start,
                                                           huffman_error_pos);
      {
        uint64_t zero_run_pos =
            jpg_find_interior_zero_run_after_prefix(data, length, blocksize,
                                                    initial_prefix_validates_to,
                                                    huffman_error_pos);
        if (zero_run_pos > 0 && zero_run_pos < huffman_error_pos) {
          huffman_error_pos = zero_run_pos;
        }
      }
      if (!jpg_wrongblock_result.detected || huffman_error_pos < jpg_wrongblock_result.estimated_byte) {
        jpg_wrongblock_result.detected = true;
        jpg_wrongblock_result.estimated_byte = huffman_error_pos;
        jpg_wrongblock_result.confidence = 100.0;
        jpg_wrongblock_result.method = "huffman_invalid";
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
    if (lib_validates) {
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
      // OPUS47/J12: only override libjpeg's positive validation with a
      // Huffman error when libjpeg did NOT validate all the way to the
      // end of the data AND the remaining data is NOT trailing padding.
      // When libjpeg stops at a valid EOI and the rest of the buffer is
      // zero/0xFF padding (common when scalpel3 carves block-aligned
      // regions that extend past the file's actual end), we want to
      // accept the file and commit at libjpeg's last good byte. A
      // Huffman "error" at an early block boundary in a libjpeg-valid
      // file is a false positive (e.g. aggressive DC continuity check
      // firing on a legitimate large DC swing). For true reassembly
      // candidates with wrong tail blocks, libjpeg typically stops well
      // before the end and the trailing bytes contain JPEG-ish garbage
      // (non-padding), so this check still rejects those.
      else if (huffman_error_pos > 0
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
                                                      initial_prefix_validates_to,
                                                      huffman_error_pos);
          if (zero_run_pos > 0 && zero_run_pos < huffman_error_pos) {
            huffman_error_pos = zero_run_pos;
          }
        }
        // OPUS47/J15: when libjpeg successfully decodes past the Huffman
        // walker's error position, prefer libjpeg's value as the validated
        // frontier. The Huffman walker has a DC continuity check that
        // produces false positives on valid photos with large DC swings,
        // which previously clamped validates_to to the early error
        // position even when libjpeg confirmed the intervening bytes
        // decoded cleanly. Without this, fragmented-JPG reassembly can't
        // distinguish extensions that grow the valid frontier from ones
        // that don't — every extension reports the same validates_to and
        // LR has no progress signal.
        //
        // Safety: if a large zero/padding run appears before lib_vt,
        // clamp to the start of that run. libjpeg accepts zero runs as
        // AC=0 coefficients and can be tricked into "validating" a
        // zero-filled gap that's actually reassembly garbage.
        uint64_t frontier = huffman_error_pos > 0 ? huffman_error_pos - 1 : 0;
        if (lib_validates_to > frontier) {
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
                                                    initial_prefix_validates_to,
                                                    length - 1);
        uint64_t trailing_zero_pos =
            jpg_find_trailing_zero_run_start(data, length, blocksize,
                                             ctx.entropy_start);
        if (trailing_zero_pos > 0) {
          *validates_to = trailing_zero_pos - 1;
        }
        else if (zero_run_pos > 0) {
          *validates_to = zero_run_pos - 1;
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
          carve_put_state(carvehashkey, save);
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
  void *state = carve_get_state(candidate->carvehashkey);
  uint32_t fixed_prefix_blocks = 1;
  if (state) {
    JPGCarveState *jpg_state = (JPGCarveState *)state;
    if (jpg_state->fixed_prefix_blocks > 0) {
      fixed_prefix_blocks = jpg_state->fixed_prefix_blocks;
    }
    scalpel_state.search_specs[candidate->needleidx].FREECARVESTATEFUNC(&state);
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

static const int64_t JPG_REASS_BLOCK_CHOICE_CHECKPOINT = INT64_MIN;

static inline bool jpg_reassembly_checkpoint_requested(void) {
  return atomic_load_explicit(&REASS_RETURN_TO_IDLE, memory_order_acquire);
}

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

  if (! candidate->clone) {
    // JPG candidates must always try the immediate next apparent block first.
    // The LR-style "+2" sentinel skips the true next block for fresh
    // extensions, which is catastrophic when headerblocks=2.
    candidate->block_choice_start =
        blockvector_get_apparent_blocknumber(candidate->b,
                                             blockvector_get_num_blocks(candidate->b) - 2)
        + 1;
  }
  else {
    candidate->block_choice_start = -1;
  }

  jpg_reassembly_debug_dump("prepare", candidate, -1, 0);
}

static inline bool jpg_reassembly_load_saved_state(CarveInfo *candidate,
                                                   JPGCarveState *state) {
  void *saved;

  memset(state, 0, sizeof(*state));
  saved = carve_get_state(candidate->carvehashkey);
  if (!saved) {
    return false;
  }

  memcpy(state, saved, sizeof(*state));
  scalpel_state.search_specs[candidate->needleidx].FREECARVESTATEFUNC(&saved);
  return state->valid;
}

static inline char *jpg_reassembly_materialize_candidate(CarveInfo *candidate,
                                                         uint64_t *length_out) {
  uint64_t num_blocks = blockvector_get_num_blocks(candidate->b);
  uint64_t alloc_len = num_blocks * scalpel_state.blocksize;
  char *buf = (char *)calloc(1, alloc_len);

  check_memory_allocation(buf, __LINE__, __FILE__, "jpg_reassembly_materialize_candidate");

  for (uint64_t i = 0; i < num_blocks; i++) {
    int64_t apparent = blockvector_get_apparent_blocknumber(candidate->b, i);
    unsigned char *block_data;

    if (apparent < 0) {
      continue;
    }

    block_data = get_apparent_block_data(scalpel_state.filemirror, apparent);
    memcpy(buf + i * scalpel_state.blocksize,
           block_data,
           scalpel_state.blocksize);
    free(block_data);
  }

  *length_out = blockvector_get_data_length(candidate->b);
  return buf;
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
      jpg_reassembly_has_gap(candidate, fixed_prefix_blocks)
      && blockvector_get_num_blocks(candidate->b) <= (uint64_t)fixed_prefix_blocks + 3;

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
                    NULL, use_full_validation ? NULL : state);
  free(materialized);
  return validates;
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

static inline double jpg_reassembly_measure_seam(CarveInfo *candidate) {
  uint64_t materialized_length = 0;
  char *materialized = jpg_reassembly_materialize_candidate(candidate,
                                                            &materialized_length);
  double seam_mad = 0.0;
  JDIMENSION seam_row = 0;

  if (jpg_should_run_seam_detector(materialized_length, scalpel_state.blocksize)) {
    (void)jpg_detect_interior_seam(materialized, materialized_length,
                                   &seam_mad, &seam_row);
  }

  free(materialized);
  return seam_mad;
}

static inline uint64_t jpg_reassembly_probe_followon(CarveInfo *candidate,
                                                     const JPGCarveState *trial_state,
                                                     uint64_t validates_to) {
  static const uint64_t JPG_REASSEMBLY_PROBE_WINDOW = 32;
  static const uint64_t JPG_REASSEMBLY_PROBE_MAX_CHAIN = 8;
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
    uint64_t validates_to) {
  static const uint64_t JPG_REASSEMBLY_PROBE_MAX_CHAIN = 8;
  uint64_t best_validates_to = validates_to;
  uint64_t saved_length = blockvector_get_data_length(candidate->b);
  uint64_t num_blocks = blockvector_get_num_blocks(candidate->b);
  uint64_t committed_length = validates_to + 1;
  int64_t current_apparentblocknumber =
      blockvector_get_apparent_blocknumber(candidate->b, num_blocks - 1);
  int64_t last_apparentblocknumber =
      filemirror_apparent_blocks(scalpel_state.filemirror);
  JPGCarveState probe_state;

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
  int64_t actualblocknumber;
  int64_t first_apparentblocknumber;
  int64_t count;
  uint64_t evaluated;
  bool viable = false;
  bool consecutive = false;
  bool in_vector = false;
  BlockValidationDecision blocktype = BLOCK_CONFIDENCE_INVALID;

#if BLOCK_SELECTION_PERFORMANCE_STATS > 0
  struct timespec BLK_starttime;
  struct timespec BLK_endtime;
  uint64_t BLK_examined = 0;

  clock_gettime(CLOCK_MONOTONIC, &BLK_starttime);
#endif

  count = filemirror_apparent_blocks(scalpel_state.filemirror);
  first_apparentblocknumber =
      blockvector_get_num_blocks(candidate->b) > 0
      ? blockvector_get_apparent_blocknumber(candidate->b, 0)
      : -1;

  while (count > 0) {
    if (jpg_reassembly_checkpoint_requested()) {
      block_choice = JPG_REASS_BLOCK_CHOICE_CHECKPOINT;
      goto done;
    }

    block_choice = blockvector_get_choice(candidate->b,
                                          blockvector_get_num_blocks(candidate->b) - 1,
                                          candidate->block_choice_start,
                                          count, &evaluated);

#if BLOCK_SELECTION_PERFORMANCE_STATS > 0
    BLK_examined += evaluated;
#endif

    if (block_choice == -1) {
      goto done;
    }

    consecutive = candidate->block_choice_start >= 0
                  && block_choice == candidate->block_choice_start;

    if (jpg_reassembly_debug_candidate(candidate)) {
      lock_fprintf(stderr, "[jpgdbg] pick slot=%" PRIu64 " ap=%" PRId64 " act=%" PRId64 " consecutive=%d\n",
                   blockvector_get_num_blocks(candidate->b) - 1,
                   block_choice,
                   filemirror_actual_blocknumber(scalpel_state.filemirror, block_choice),
                   consecutive ? 1 : 0);
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

    if (jpg_reassembly_debug_candidate(candidate)) {
      lock_fprintf(stderr,
                   "[jpgdbg] viable ap=%" PRId64 " act=%" PRId64
                   " blocktype=%u invec=%d zero=%d viable=%d\n",
                   block_choice,
                   actualblocknumber,
                   (unsigned)blocktype,
                   in_vector ? 1 : 0,
                   filemirror_actual_block_is_zero(scalpel_state.filemirror,
                                                   actualblocknumber) ? 1 : 0,
                   viable ? 1 : 0);
    }

    if (viable) {
      goto done;
    }

    if (! viable) {
      blockvector_remove_choice(candidate->b,
                                blockvector_get_num_blocks(candidate->b) - 1,
                                block_choice);
      block_choice = -1;
    }
  }

done:
  if (block_choice >= 0) {
    blockvector_remove_choice(candidate->b,
                              blockvector_get_num_blocks(candidate->b) - 1,
                              block_choice);
  }

  jpg_reassembly_debug_dump("choice_done", candidate, block_choice, 0);

#if BLOCK_SELECTION_PERFORMANCE_STATS > 0
  clock_gettime(CLOCK_MONOTONIC, &BLK_endtime);
  uint64_t BLK_elapsed =
      (BLK_endtime.tv_sec - BLK_starttime.tv_sec) * 1e9
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
  int64_t pregallop_newblock;
  uint64_t pregallop_num_blocks;
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

    if (*validates) {
      blockvector_set_data_length(candidate->b, *validates_to + 1);
      resize_blockvector(candidate->b,
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
      candidate->fastpath = false;
      candidate->block_choice_start = -2;
    }
  }

  return false;
}

typedef struct JPGReassemblyForwardChoice {
  bool found;
  bool validates;
  bool have_state;
  bool reaches_trial_end;
  bool near_trial_end;
  bool is_immediate;
  int64_t apparent;
  int64_t actual;
  uint64_t commit_validates_to;
  uint64_t score_validates_to;
  JPGCarveState state;
} JPGReassemblyForwardChoice;

enum {
  JPG_REASS_OOO_MIN_RUN = 2,
  JPG_REASS_OOO_MAX_RUN = 8,
  JPG_REASS_OOO_SUFFIX_PROBE = 128,
  JPG_REASS_OOO_MIN_SUFFIX_PROBE = 2,
  JPG_REASS_OOO_GLOBAL_MIN_SUFFIX_PROBE = 3,
  /* Full-image probing is expensive and riskier, so use it only for
     short first-seam repairs or after a non-clean suffix trial. */
  JPG_REASS_OOO_FIRST_GLOBAL_MAX_RUN = 3,
  JPG_REASS_OOO_BOUNDARY_SLACK = 4,
  JPG_REASS_OOO_ANCHOR_BACKSCAN_BLOCKS = 12,
  JPG_REASS_OOO_STRICT_ANCHOR_BACKSCAN_BLOCKS = 40,
  JPG_REASS_OOO_RAW_ANCHOR_SCAN_MAX = 32768,
  JPG_REASS_OOO_MAX_TRIALS = 32768
};

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
    bool reject_zero_run) {
  JPGCarveState trial_state;
  uint64_t trial_validates_to = 0;
  uint64_t trial_frontier;
  uint64_t trial_end;
  uint64_t commit_validates_to = 0;
  bool trial_validates;
  bool reaches_probe_commit = false;

  if (!jpg_reassembly_ooo_range_available(candidate, run_start, run_len,
                                          suffix_start, suffix_len)) {
    return false;
  }
  if (reject_zero_run
      && jpg_reassembly_ooo_range_has_zero(run_start, run_len)) {
    return false;
  }

  jpg_reassembly_ooo_restore_candidate(candidate, saved_num_blocks,
                                       saved_length);
  jpg_reassembly_ooo_append_range(candidate, run_start, run_len);
  jpg_reassembly_ooo_append_range(candidate, suffix_start, suffix_len);

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
  if (!require_full_validate
      && !trial_validates && scalpel_state.blocksize > 0
      && !(trial_frontier >= trial_end
           || (trial_end > trial_frontier
               && trial_end - trial_frontier <= JPG_REASS_OOO_BOUNDARY_SLACK))
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

  if (trial_validates || reaches_probe_commit) {
    uint64_t committed_blocks;

    if (reaches_probe_commit) {
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
      carve_put_state(candidate->carvehashkey, &trial_state);
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
                                                 reject_zero_run)) {
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
                                                 reject_zero_run)) {
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
                                                 reject_zero_run)) {
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
                                                 reject_zero_run)) {
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
                                                 reject_zero_run)) {
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
  static const uint64_t JPG_REASSEMBLY_BOUNDARY_SLACK = 4;
  bool validates = false;
  uint64_t validates_to = 0;
  uint64_t tick = 0;
  CarveInfo *candidate = *c;

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
    int64_t first_apparent;
    int64_t last_apparent;
    JPGCarveState prefix_state;
    bool have_prefix_state;
    JPGReassemblyForwardChoice best_choice;
    bool advanced = false;

    if (reassembly_check_max_size(work->id, candidate, uuidp, uuidc)) {
      if (!scalpel_state.write_promising) {
        destroy_candidate(&candidate);
        goto done_do_not_write_candidate;
      }
      goto done_write_candidate;
    }

    if (reassembly_check_kill_queue(work->id, &candidate, uuidp, uuidc)) {
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
      uint64_t cold_validates_to = 0;
      bool cold_validates;

      memset(&cold_state, 0, sizeof(cold_state));
      cold_validates =
          jpg_reassembly_validate_direct(candidate, &cold_state,
                                         &cold_validates_to,
                                         jpg_reassembly_get_fixed_prefix_blocks(candidate));
      if (cold_validates || cold_validates_to > validates_to) {
        validates = cold_validates;
        validates_to = cold_validates_to;
        if (cold_state.valid) {
          carve_put_state(candidate->carvehashkey, &cold_state);
        }
        jpg_reassembly_debug_dump(cold_validates ? "forward_current_cold_valid"
                                                 : "forward_current_cold",
                                  candidate, -1, validates_to);
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
      uint64_t current_length = blockvector_get_data_length(candidate->b);
      uint64_t validated_length = validates_to + 1;

      if (validated_length < current_length) {
        uint64_t shortfall = current_length - validated_length;

        if (current_length % scalpel_state.blocksize == 0
            && shortfall <= JPG_REASSEMBLY_BOUNDARY_SLACK) {
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
    if (validates_to > candidate->best_validates_to) {
      candidate->best_validates_to = validates_to;
    }

    if (reassembly_time_to_checkpoint(work->id, candidate, uuidp, uuidc)) {
      goto done_do_not_write_candidate;
    }

    num_blocks = blockvector_get_num_blocks(candidate->b);
    oldlength = blockvector_get_data_length(candidate->b);
    tail_apparent =
        blockvector_get_apparent_blocknumber(candidate->b, num_blocks - 1);
    first_apparent =
        blockvector_get_apparent_blocknumber(candidate->b, 0);
    last_apparent = (int64_t)filemirror_apparent_blocks(scalpel_state.filemirror);
    if (tail_apparent < 0 || tail_apparent + 1 >= last_apparent) {
      break;
    }

    memset(&prefix_state, 0, sizeof(prefix_state));
    have_prefix_state =
        jpg_reassembly_load_saved_state(candidate, &prefix_state);

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

    resize_blockvector(candidate->b, num_blocks + 1);
    blockvector_set_apparent_blocknumber(candidate->b, num_blocks, -1);
    blockvector_free_choices(candidate->b, num_blocks);

    for (int64_t apparent = tail_apparent + 1;
         apparent < last_apparent
         && apparent <= tail_apparent + JPG_REASSEMBLY_FORWARD_SCAN_WINDOW;
         apparent++) {
      int64_t actual;
      BlockValidationDecision blocktype;

      if (jpg_reassembly_checkpoint_requested()) {
        resize_blockvector(candidate->b, num_blocks);
        blockvector_set_data_length(candidate->b, oldlength);
        if (reassembly_time_to_checkpoint(work->id, candidate, uuidp, uuidc)) {
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

      if (first_apparent >= 0 && apparent < first_apparent) {
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
      if (blocktype == BLOCK_CONFIDENCE_INVALID) {
        continue;
      }

      blockvector_set_apparent_blocknumber(candidate->b, num_blocks, apparent);
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
      bool trial_is_immediate;
      bool trial_validates;

      if (have_prefix_state) {
        memcpy(&trial_state, &prefix_state, sizeof(trial_state));
      } else {
        memset(&trial_state, 0, sizeof(trial_state));
      }

      trial_validates =
          jpg_reassembly_validate_direct(candidate, &trial_state,
                                         &trial_validates_to,
                                         jpg_reassembly_get_fixed_prefix_blocks(candidate));
      validates = trial_validates;
      validates_to = trial_validates_to;
      jpg_reassembly_debug_dump(validates ? "forward_trial_valid"
                                          : "forward_trial",
                                candidate, apparent, validates_to);
      if (!validates && validates_to + 1 <= accept_threshold) {
        JPGCarveState cold_state;
        uint64_t cold_validates_to = 0;
        bool cold_validates;

        memset(&cold_state, 0, sizeof(cold_state));
        cold_validates =
            jpg_reassembly_validate_direct(candidate, &cold_state,
                                           &cold_validates_to,
                                           jpg_reassembly_get_fixed_prefix_blocks(candidate));
        if (cold_validates || cold_validates_to > validates_to) {
          validates = cold_validates;
          validates_to = cold_validates_to;
          memcpy(&trial_state, &cold_state, sizeof(trial_state));
          jpg_reassembly_debug_dump(cold_validates ? "forward_cold_valid"
                                                   : "forward_cold_accept",
                                    candidate, apparent, validates_to);
        }
      }

      trial_end = blockvector_get_data_length(candidate->b) - 1;
      trial_reaches_end = validates_to >= trial_end;
      trial_shortfall = trial_reaches_end ? 0 : trial_end - validates_to;
      trial_near_end = trial_shortfall <= JPG_REASSEMBLY_BOUNDARY_SLACK;
      trial_actual_is_zero =
          filemirror_actual_block_is_zero(scalpel_state.filemirror, actual);
      trial_effectively_reaches_end =
          trial_reaches_end || (trial_near_end && !trial_actual_is_zero);
      trial_is_immediate = apparent == tail_apparent + 1;
      trial_score_validates_to = validates_to;
      if (!validates && validates_to + 1 > accept_threshold) {
        uint64_t followon_score =
            jpg_reassembly_probe_contiguous_followon(candidate, &trial_state,
                                                     validates_to);
        if (followon_score > trial_score_validates_to) {
          trial_score_validates_to = followon_score;
        }
        jpg_reassembly_debug_dump("forward_score", candidate, apparent,
                                  trial_score_validates_to);
      }

      if (!validates
          && validates_to + 1 > accept_threshold
          && apparent > tail_apparent + 1) {
        uint64_t skipped_blocks = (uint64_t)(apparent - tail_apparent - 1);
        bool prior_gap =
            jpg_reassembly_has_gap(
                candidate,
                jpg_reassembly_get_fixed_prefix_blocks(candidate));
        bool allow_anchor_ooo = !trial_effectively_reaches_end || prior_gap;
        bool allow_global_ooo =
            !trial_effectively_reaches_end
            || skipped_blocks <= JPG_REASS_OOO_FIRST_GLOBAL_MAX_RUN;
        bool ooo_checkpoint = false;

        deflate_blockvector_single_block(candidate->b, num_blocks, oldlength);
        blockvector_set_apparent_blocknumber(candidate->b, num_blocks, -1);
        resize_blockvector(candidate->b, num_blocks);
        blockvector_set_data_length(candidate->b, oldlength);
        if (skipped_blocks >= JPG_REASS_OOO_MIN_RUN
            && skipped_blocks <= JPG_REASS_OOO_MAX_RUN
            && jpg_reassembly_try_ooo_run_repair(candidate, &prefix_state,
                                                 have_prefix_state,
                                                 &validates, &validates_to,
                                                 jpg_reassembly_get_fixed_prefix_blocks(candidate),
                                                 skipped_blocks, skipped_blocks,
                                                 false,
                                                 true, true,
                                                 JPG_REASS_OOO_STRICT_ANCHOR_BACKSCAN_BLOCKS,
                                                 &ooo_checkpoint)) {
          advanced = true;
          break;
        }
        if (ooo_checkpoint
            && reassembly_time_to_checkpoint(work->id, candidate, uuidp, uuidc)) {
          goto done_do_not_write_candidate;
        }
        if (allow_anchor_ooo
            && jpg_reassembly_try_ooo_run_repair(candidate, &prefix_state,
                                                 have_prefix_state,
                                                 &validates, &validates_to,
                                                 jpg_reassembly_get_fixed_prefix_blocks(candidate),
                                                 0, skipped_blocks,
                                                 false,
                                                 false, false,
                                                 JPG_REASS_OOO_ANCHOR_BACKSCAN_BLOCKS,
                                                 &ooo_checkpoint)) {
          advanced = true;
          break;
        }
        if (ooo_checkpoint
            && reassembly_time_to_checkpoint(work->id, candidate, uuidp, uuidc)) {
          goto done_do_not_write_candidate;
        }
        if (skipped_blocks >= JPG_REASS_OOO_MIN_RUN
            && skipped_blocks <= JPG_REASS_OOO_MAX_RUN
            && allow_global_ooo
            && jpg_reassembly_try_ooo_run_repair(candidate, &prefix_state,
                                                 have_prefix_state,
                                                 &validates, &validates_to,
                                                 jpg_reassembly_get_fixed_prefix_blocks(candidate),
                                                 skipped_blocks, skipped_blocks,
                                                 true,
                                                 false, false,
                                                 JPG_REASS_OOO_ANCHOR_BACKSCAN_BLOCKS,
                                                 &ooo_checkpoint)) {
          advanced = true;
          break;
        }
        if (ooo_checkpoint
            && reassembly_time_to_checkpoint(work->id, candidate, uuidp, uuidc)) {
          goto done_do_not_write_candidate;
        }
        resize_blockvector(candidate->b, num_blocks + 1);
        blockvector_set_apparent_blocknumber(candidate->b, num_blocks, apparent);
        (void)inflate_blockvector_single_block(candidate->b, num_blocks);
      }

      if (validates || validates_to + 1 > accept_threshold) {
        bool defer_immediate =
            trial_is_immediate && !trial_effectively_reaches_end && !validates;
        bool have_deferred_immediate =
            best_choice.found
            && best_choice.is_immediate
            && !best_choice.reaches_trial_end
            && !best_choice.validates;
        bool replace_deferred =
            have_deferred_immediate
            && (validates
                || (trial_effectively_reaches_end
                    && trial_score_validates_to
                           > best_choice.score_validates_to
                                 + JPG_REASSEMBLY_BOUNDARY_SLACK));

        if (!best_choice.found || replace_deferred) {
          best_choice.found = true;
          best_choice.validates = validates;
          best_choice.reaches_trial_end = trial_effectively_reaches_end;
          best_choice.near_trial_end = trial_near_end;
          best_choice.is_immediate = trial_is_immediate;
          best_choice.apparent = apparent;
          best_choice.actual = actual;
          best_choice.commit_validates_to = validates_to;
          best_choice.score_validates_to = trial_score_validates_to;
          if (trial_state.valid) {
            memcpy(&best_choice.state, &trial_state,
                   sizeof(best_choice.state));
            best_choice.have_state = true;
          } else {
            best_choice.have_state = false;
          }
          if (validates) {
            jpg_reassembly_debug_dump("forward_best_valid", candidate,
                                      apparent, validates_to);
            break;
          }
        }
        if (replace_deferred || (!defer_immediate && !have_deferred_immediate)) {
          break;
        }
      }

      deflate_blockvector_single_block(candidate->b, num_blocks, oldlength);
      blockvector_set_apparent_blocknumber(candidate->b, num_blocks, -1);

      if (reassembly_check_kill_queue(work->id, &candidate, uuidp, uuidc)) {
        goto done_do_not_write_candidate;
      }
      if (jpg_reassembly_checkpoint_requested()) {
        resize_blockvector(candidate->b, num_blocks);
        blockvector_set_data_length(candidate->b, oldlength);
        if (reassembly_time_to_checkpoint(work->id, candidate, uuidp, uuidc)) {
          goto done_do_not_write_candidate;
        }
        resize_blockvector(candidate->b, num_blocks + 1);
        blockvector_set_apparent_blocknumber(candidate->b, num_blocks, -1);
        blockvector_free_choices(candidate->b, num_blocks);
      }
    }

    if (advanced) {
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
      blockvector_set_apparent_blocknumber(candidate->b, num_blocks,
                                           best_choice.apparent);
      (void)inflate_blockvector_single_block(candidate->b, num_blocks);
      validates = best_choice.validates;
      validates_to = best_choice.commit_validates_to;
      if (best_choice.have_state) {
        carve_put_state(candidate->carvehashkey, &best_choice.state);
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
    }

    if (advanced) {
      continue;
    }

    resize_blockvector(candidate->b, num_blocks);
    blockvector_set_data_length(candidate->b, oldlength);

    if (reassembly_time_to_checkpoint(work->id, candidate, uuidp, uuidc)) {
      goto done_do_not_write_candidate;
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
          && reassembly_time_to_checkpoint(work->id, candidate, uuidp, uuidc)) {
        goto done_do_not_write_candidate;
      }
    }

    if (advanced) {
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
  write_candidate(c, false);
  goto done;

done_do_not_write_candidate:
done:;
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
