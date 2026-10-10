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

// Original version of 123.h by Karley Waguespack.
//
// 123: a synthetic file format used as a teaching example for adding new
// file types to scalpel3. Three things are demonstrated:
//
//   1. a block validator + file validator pair
//   2. per-block and per-candidate state via scalpel3's state API
//   3. a custom reassembly function that uses file metadata to direct
//      placement instead of left-to-right extension
//
// 123 file format. A 123 file is a sequence of fixed-size blocks:
//
//   [HEADER]    "#HEADER#"    + 8-char file ID + '-' padding
//   [SECT 0]    '0' * blocksize    (one or more 0-blocks)
//   [SECT 1]    '1' * blocksize    (one or more 1-blocks)
//     ...
//   [SECT 9]    '9' * blocksize    (one or more 9-blocks)
//   [METADATA]  "#METADATA#"  + same 8-char file ID + 10 records + '-' padding
//   [FOOTER]    "#FOOTER#"    + '-' padding
//
// Each metadata record is 17 bytes: 1 char section type + 8-char ASCII offset + 8-char ASCII
// size. The metadata block defines per-section sizes, so without it the layout is unknown. The
// 8-char file ID in the header must match the one in the metadata; this pairs each metadata block
// with its own header when multiple 123 files coexist in an image.
//
// Sample files and the fragmentator configs that produce fragmented copies live under
// SCALPEL3_DATA/123-tests/. TESTS/cmdline.test exercises 123 reassembly end-to-end as a regression.
//
// State API quick reference. Block state is per-block and immutable once the block validator sets
// it. Candidate (carve) state is per-candidate and mutable throughout reassembly.
//
//   block_put_state(blockhashkey, &state)  -- stores a deep copy via CLONE
//   block_get_state(blockhashkey)          -- returns a deep copy you must free
//   carve_put_state(carvehashkey, state)   -- same copy semantics
//   carve_get_state(carvehashkey)
//
// Important: during reassembly the block hash key is not available directly; recompute it with
// gen_block_hash_key(). That function returns the exemplar block's hash key, so duplicates resolve
// to the canonical state. The carve hash key is always available as candidate->carvehashkey.  See
// scalpel.h.
//
// You must register CLONE / FREE / SERIALIZE hooks (and optionally SIZEOF / PRINT hooks) in
// scalpelconf.c for every state type you store. See the 123 entry in scalpelconf.c and the
// state-API functions below.
//
// Important: scalpel3's general guidance is that block validators should err on the side of
// inclusiveness -- a single missed block can destroy a reassembly attempt. The validators below are
// strict only because 123 blocks are structurally unambiguous (a magic check or digit-uniformity
// check suffices). For ambiguous formats (e.g., the compressed body of a JPEG), prefer permissive
// block validation and let the file validator disambiguate. abc.h shows an
// exhaustive-file-validator variant of that pattern.


#include "scalpel.h"

#define HEADER_SIGNATURE_123 "#HEADER#"
#define FOOTER_SIGNATURE_123 "#FOOTER#"
#define METADATA_SIGNATURE_123 "#METADATA#"

#define HEADER_SIZE_123 8
#define FOOTER_SIZE_123 8
#define METADATA_SIZE_123 10
#define FILE_ID_SIZE_123 8


// ============================================================================
// State structures
// ============================================================================

// per-block state for 123 files. We use a single character to tag each
// block's type:
//   '0'..'9' -- digit blocks (the n-th section's filler)
//   'h'      -- header
//   'f'      -- footer
//   'm'      -- metadata
//
// The tag set is a 123-specific convention; other file types invent their
// own. gif.h is a richer example using a struct with dynamic data.
typedef struct {
  char value;
} File123BlockState;


// per-candidate state for 123 reassembly. Tracks placement progress so the
// custom reassembly thread can decide what block type belongs in each
// remaining slot.
//
// Only used during custom reassembly; contiguous recovery never touches it.
#define FILE123_STATE_MAGIC UINT32_C(0x31323353)
#define FILE123_STATE_VERSION UINT32_C(1)
#define FILE123_SCAN_YIELDED INT64_C(-2)
#define FILE123_SCAN_INTERVAL UINT64_C(128)

typedef enum File123ScanKind {
  FILE123_SCAN_NONE,
  FILE123_SCAN_METADATA,
  FILE123_SCAN_TYPE
} File123ScanKind;

typedef struct File123Scan {
  XXH128_hash_t query;
  uint64_t next_actual;
  uint64_t remaining;
  uint64_t image_blocks;
  uint32_t kind;
} File123Scan;

// Exact layout of the original unversioned checkpoint record.
typedef struct {
  bool header_placed;
  bool metadata_placed;
  bool footer_placed;
  uint8_t expected_blocks[10];
  uint8_t recovered_blocks[10];
  bool skeleton_initialized;
} File123LegacyState;

typedef struct {
  bool header_placed;
  bool metadata_placed;
  bool footer_placed;

  // expected_blocks[i] holds the total block count for section i (0..9),
  // parsed from the metadata block.
  uint8_t expected_blocks[10];

  // recovered_blocks[i] holds the number of section-i blocks placed so far.
  // When recovered_blocks[i] == expected_blocks[i] for all i, the file is
  // complete (modulo header / metadata / footer flags above).
  uint8_t recovered_blocks[10];

  // set true once expected_blocks[] has been populated from a metadata block.
  bool skeleton_initialized;

  File123Scan scan;
} File123ReassemblyState;

_Static_assert(offsetof(File123ReassemblyState, scan) == sizeof(File123LegacyState),
               "123 legacy checkpoint prefix layout");


// ============================================================================
// Function prototypes
// ============================================================================

// block validator and file validator
static inline uint32_t file_123_block_validate(char *data,
                                        uint64_t length,
                                        BlockValidationDecision *decision,
                                        uint64_t *validates_to,
                                        uint32_t needleidx,
                                        uint32_t blocksize,
                                        void *blockhashkey);


// file validator (registered) and an internal wrapper that takes a CarveInfo
// and flattens it for the registered validator
static inline void file_123_file_validate(char *data,
                                    uint64_t length,
                                    bool *validates,
                                    uint64_t *validates_to,
                                    bool *promising,
                                    uint32_t needleidx,
                                    uint32_t blocksize,
                                    void *carvehashkey);
static bool file_123_validate_candidate(CarveInfo *cand,
                                        uint64_t *validates_to);

// block state API hooks (see scalpelconf.c for what each hook must do)
static inline bool file_123_serialize_block_state(void **state, FILE *fp,
                                              StateSerialization mode);
static inline void *file_123_clone_block_state(const void *srcstate);
static inline void file_123_free_block_state(void **state);
static inline size_t file_123_sizeof_block_state(const void *state);
static inline void file_123_print_block_state(const void *state);

// candidate (carve) state API hooks
static inline bool file_123_serialize_carve_state(void **state, FILE *fp,
                                                 StateSerialization mode);
static inline void *file_123_clone_carve_state(const void *srcstate);
static inline void file_123_free_carve_state(void **state);
static inline size_t file_123_sizeof_carve_state(const void *state);
static inline void file_123_print_carve_state(const void *state);

// custom reassembly thread and its helpers
static bool file_123_reassembly_init_candidate(ThreadWork *work,
                                              CarveInfo **candidate,
                                              uuid_string_t uuidp,
                                              uuid_string_t uuidc);
static bool file_123_reassembly_prepare_for_extension(CarveInfo *cand,
                                              int64_t *hole_idx,
                                              int64_t *start_ap);
static int64_t file_123_reassembly_get_block_choice(
    ThreadWork *work, CarveInfo **candidate, int64_t *block_choice_start,
    int64_t logical_slot_index, char target_type,
    uuid_string_t uuidp, uuid_string_t uuidc);
static int64_t file_123_find_reusable_section_block(CarveInfo *candidate,
                                                   char target_type);
static void file_123_reassembly_extension_successful(int id,
                                                    CarveInfo *candidate,
                                                    int64_t logical_slot_index);
static void file_123_reassembly_gallop(int id,
                                      CarveInfo *candidate,
                                      int64_t start_index,
                                      int64_t end_index,
                                      uint32_t *gallop,
                                      uint64_t *validates_to,
                                      bool *validates);
static void file_123_reassembly(ThreadWork *work, CarveInfo **c,
                        uuid_string_t uuidp, uuid_string_t uuidc);

// lower-level reassembly helpers
static void file_123_resize_blockvector_to_expected(CarveInfo *cand);
static int file_123_slot_to_section(const File123ReassemblyState *st,
                           uint64_t num_blocks,
                           int64_t slot);
static uint64_t file_123_calculate_file_size_from_metadata(CarveInfo *candidate);
static void file_123_place_metadata_block(CarveInfo *candidate,
                          int64_t apparent_blocknum);
static uint8_t *file_123_get_metadata_block_data(int64_t actual_blocknum);
static bool file_123_validate_metadata_block(CarveInfo *candidate,
                             int64_t metadata_block);
static int64_t file_123_find_valid_metadata_block(
    ThreadWork *work, CarveInfo **candidate, File123ReassemblyState *state,
    uuid_string_t uuidp, uuid_string_t uuidc);
static inline bool file_123_carve_state_valid(const File123ReassemblyState *state);
static inline XXH128_hash_t file_123_scan_query(CarveInfo *candidate,
                                               uint64_t slot, char target_type);
static inline void file_123_scan_begin(CarveInfo *candidate,
    File123ReassemblyState *state, File123ScanKind kind, uint64_t slot,
    int64_t start_apparent, char target_type);
static int64_t file_123_scan_blocks(ThreadWork *work, CarveInfo **candidate,
    File123ReassemblyState *state, uint64_t slot, char target_type,
    uuid_string_t uuidp, uuid_string_t uuidc, uint64_t *examined);
static int64_t file_123_find_hole_end(CarveInfo *cand,
                             uint64_t start);
static char file_123_block_type_for_slot(CarveInfo *cand,
                                uint64_t slot);
static char *file_123_blockvector_to_buffer_range(BlockVector *bv,
                                  int64_t start_idx,
                                  int64_t end_idx);

// Sentinel value for block_state.value meaning "not yet classified". We
// only persist block state when the value has moved off this sentinel,
// i.e., when one of the four pattern checks below has classified the block.
#define FILE_123_BLOCK_TYPE_UNKNOWN '?'


// block validator. Called by scalpel3 once per uncovered block during
// initialization, before any recovery phase begins. Reads `length` bytes
// at `data`, writes a confidence to *decision, and optionally attaches
// per-block metadata via block_put_state(). Returns the file type index
// (needleidx) the block belongs to; returning a different needleidx
// claims the block on behalf of a different file type (used by master /
// inheritance setups in scalpelconf.c -- this example simply returns its
// own).
//
// The confidence values available are BLOCK_CONFIDENCE_INVALID (0),
// BLOCK_CONFIDENCE_LOW (1, "ambiguous; file validator decides"), and
// BLOCK_CONFIDENCE_VALID (100). Intermediate values are permitted (e.g.,
// ML-derived scores). 123 blocks are structurally unambiguous, so this
// validator uses only the endpoints.
//
// important: validates_to is for formats where individual blocks can be
// partially valid. 123 blocks are atomic: a block either matches a
// pattern entirely or it doesn't. We set validates_to to length-1
// unconditionally.
//
// important: the state struct passed to block_put_state() is deep-copied
// by scalpel3 via your CLONE hook. The local on the stack does not need
// to outlive the call.

static inline uint32_t file_123_block_validate(char *data,
                                               uint64_t length,
                                               BlockValidationDecision *decision,
                                               uint64_t *validates_to,
                                               uint32_t needleidx,
                                               uint32_t blocksize,
                                               void *blockhashkey) {
  (void)blocksize;


  // assume VALID and disqualify on any mismatch. Every branch below uses
  // the same pattern: detect a candidate type, set *decision = INVALID on
  // failure, and let control fall through to the state-persisting block at
  // the bottom of the function.
  *decision = BLOCK_CONFIDENCE_VALID;
  *validates_to = length - 1;

  char state = FILE_123_BLOCK_TYPE_UNKNOWN;

  // header block: "#HEADER#" + 8-char file ID + '-' padding.
  if (memcmp(HEADER_SIGNATURE_123, data, HEADER_SIZE_123) == 0) {
    for (uint64_t i = HEADER_SIZE_123 + FILE_ID_SIZE_123; i < length; i++) {
      if (data[i] != '-') {
        *decision = BLOCK_CONFIDENCE_INVALID;
        break;
      }
    }
    state = 'h';
  }
  // footer block: "#FOOTER#" + '-' padding.
  else if (memcmp(FOOTER_SIGNATURE_123, data, FOOTER_SIZE_123) == 0) {
    for (uint64_t i = FOOTER_SIZE_123; i < length; i++) {
      if (data[i] != '-') {
        *decision = BLOCK_CONFIDENCE_INVALID;
        break;
      }
    }
    state = 'f';
  }
  // digit (n-)block: every byte equals the same digit '0'..'9'.
  else if (isdigit(data[0])) {
    char expected_digit = data[0];
    for (uint64_t i = 1; i < length; i++) {
      if (data[i] != expected_digit) {
        *decision = BLOCK_CONFIDENCE_INVALID;
        break;
      }
    }
    state = expected_digit;
  }
  // metadata block: "#METADATA#" + 8-char file ID + 10 records (17 bytes
  // each: 1-char section type + 8-char ASCII offset + 8-char ASCII size) +
  // '-' padding. Total structured bytes = 10 + 8 + (10 * 17) = 188.
  else if (memcmp(METADATA_SIGNATURE_123, data, METADATA_SIZE_123) == 0) {
    const uint64_t total_metadata_bytes =
        METADATA_SIZE_123 + FILE_ID_SIZE_123 + (10 * 17);
    bool ok = (length >= total_metadata_bytes);

    // each record's first byte must be a section type in '0'..'9'.
    uint64_t position = METADATA_SIZE_123 + FILE_ID_SIZE_123;
    for (uint64_t rec = 0; ok && rec < 10; rec++) {
      char section_type = data[position];
      if (section_type < '0' || section_type > '9') {
        ok = false;
      }
      position += 17;
    }

    // remainder of the block must be '-' padding.
    for (uint64_t i = total_metadata_bytes; ok && i < length; i++) {
      if (data[i] != '-') {
        ok = false;
      }
    }

    if (ok) {
      state = 'm';
    } else {
      *decision = BLOCK_CONFIDENCE_INVALID;
    }
  }
  // no recognized pattern.
  else {
    *decision = BLOCK_CONFIDENCE_INVALID;
  }

  // persist block state for valid blocks so the reassembly thread can
  // identify block types later. We only store state for classified blocks;
  // anything still tagged UNKNOWN is by definition not a valid 123 block.
  if (*decision == BLOCK_CONFIDENCE_VALID &&
      state != FILE_123_BLOCK_TYPE_UNKNOWN) {

    if (blockhashkey == NULL) {
      lock_fprintf(stderr, "[debug] VALID 123 block seen but blockhashkey is NULL\n");
    } else {
      // the local is deep-copied by scalpel3 via CLONEBLOCKSTATEFUNC; it
      // is safe to pass &blk_state and discard the local on return.
      File123BlockState blk_state = { .value = state };
      block_put_state(blockhashkey, &blk_state);

    }
  }

  return needleidx;
}




// file validator. Called by contiguous recovery (each candidate is run
// through this once) and by the custom reassembly thread (after each
// block placement). Reads a flat buffer `data` of `length` bytes -- the
// concatenated contents of the blocks currently in the candidate's
// blockvector -- and reports:
//
//   *validates    -- true if a complete, valid file is present
//   *validates_to -- last byte offset that conformed to the format
//   *promising    -- true if data is a partially-valid fragment worth
//                    keeping in the promising queue
//
// important: because the block validator above already classified every
// block by content, this validator only needs to check the first byte of
// each block to confirm arrangement -- it does not re-verify the
// per-block invariants. This turns an O(bytes) re-check into an O(blocks)
// scan and is the main reason 123 splits work between the two validators.

static inline void file_123_file_validate(char *data,
                                          uint64_t length,
                                          bool *validates,
                                          uint64_t *validates_to,
                                          bool *promising,
                                          uint32_t needleidx,
                                          uint32_t blocksize,
                                          void *carvehashkey) {
  (void)needleidx;
  (void)carvehashkey;

  // --------------------------------------------------------------------------
  // 1. header block.
  // --------------------------------------------------------------------------
  // must start with the header signature followed by an 8-character file ID.
  if (length < HEADER_SIZE_123 + FILE_ID_SIZE_123 ||
      memcmp(HEADER_SIGNATURE_123, data, HEADER_SIZE_123) != 0) {
    *validates = false;
    *promising = false;
    *validates_to = 0;
    return;
  }

  // stash the header's file ID so we can match it against the metadata
  // block's file ID later. This pairing is what lets us validate the right
  // metadata with the right header when multiple 123 files coexist in an
  // image -- see the FILE-ID MATCHING sub-section below.
  char header_file_id[FILE_ID_SIZE_123];
  memcpy(header_file_id, &data[HEADER_SIZE_123], FILE_ID_SIZE_123);

  // --------------------------------------------------------------------------
  // 2. digit-section walk.
  // --------------------------------------------------------------------------
  // step through the candidate one block at a time, inspecting only the
  // first byte. The sequence must run '0' -> '1' -> ... -> '9' strictly,
  // possibly with multiple blocks per digit.
  char current_digit = '0';
  uint64_t curr_offset = blocksize;

  if (curr_offset >= length) {
    *validates = false;
    *promising = true;
    *validates_to = length - 1;
    return;
  }

  // the first n-block must be a 0-block.
  if (data[curr_offset] != '0') {
    *validates = false;
    *promising = true;
    *validates_to = curr_offset - 1;
    return;
  }

  while (curr_offset < length) {
    char c = data[curr_offset];

    if (c == current_digit) {
      // still inside the current digit's section
      curr_offset += blocksize;
    } else if (c == current_digit + 1 && current_digit < '9') {
      // moved to the next digit's section
      current_digit++;
      curr_offset += blocksize;
    } else {
      // section sequence broken -- exit the loop for further analysis
      break;
    }
  }

  // the walk above guarantees all sections 0..9 are present iff we ended
  // having seen a 9-block (combined with the 0-start check above and the
  // strict-increment rule).
  if (current_digit != '9') {
    *validates = false;
    *promising = true;
    *validates_to = curr_offset - 1;
    return;
  }

  // bounds check: the strict-increment branch may have advanced
  // curr_offset past length.
  if (curr_offset >= length) {
    *validates = false;
    *promising = true;
    *validates_to = length - 1;
    return;
  }

  // --------------------------------------------------------------------------
  // 3. metadata block + file-ID matching.
  // --------------------------------------------------------------------------
  // we should now be sitting at the metadata block. It must (a) carry the
  // metadata signature and (b) carry the SAME 8-char file ID as the header.
  // The second check is what disambiguates metadata blocks across multiple
  // 123 files in the same image.
  if (curr_offset + METADATA_SIZE_123 + FILE_ID_SIZE_123 > length ||
      memcmp(METADATA_SIGNATURE_123, &data[curr_offset], METADATA_SIZE_123) != 0) {
    *validates = false;
    *promising = true;
    *validates_to = curr_offset - 1;
    return;
  }
  if (memcmp(header_file_id, &data[curr_offset + METADATA_SIZE_123], FILE_ID_SIZE_123) != 0) {
    *validates = false;
    *promising = true;
    *validates_to = curr_offset - 1;
    return;
  }

  // --------------------------------------------------------------------------
  // 4. cross-check section contents against metadata records.
  // --------------------------------------------------------------------------
  // for each of the 10 records, parse the ASCII offset and size, then
  // verify every byte in [offset, offset+size) matches the section's
  // digit. This is more thorough than the digit-walk above and would catch
  // any block-arrangement errors the walk missed.
  const uint64_t record_size = 17;
  const uint64_t num_records = 10;
  uint64_t meta_start = curr_offset + METADATA_SIZE_123 + FILE_ID_SIZE_123;
  uint64_t meta_end = meta_start + (record_size * num_records);

  if (meta_end > length) {
    *validates = false;
    *promising = true;
    *validates_to = curr_offset - 1;
    return;
  }

  for (uint64_t i = 0; i < num_records; i++) {
    uint64_t record_offset = meta_start + i * record_size;
    char section_type = data[record_offset];
    if (section_type < '0' || section_type > '9') {
      *validates = false;
      *promising = true;
      *validates_to = record_offset - 1;
      return;
    }

    // 8-char ASCII offset + 8-char ASCII size, both null-terminated for strtoull.
    char offset_buf[9] = {0};
    char size_buf[9] = {0};
    memcpy(offset_buf, &data[record_offset + 1], 8);
    memcpy(size_buf,   &data[record_offset + 9], 8);
    uint64_t section_offset = strtoull(offset_buf, NULL, 10);
    uint64_t section_size   = strtoull(size_buf, NULL, 10);

    if (section_offset + section_size > length) {
      *validates = false;
      *promising = true;
      *validates_to = length - 1;
      return;
    }
    for (uint64_t j = 0; j < section_size; j++) {
      if (data[section_offset + j] != section_type) {
        *validates = false;
        *promising = true;
        *validates_to = section_offset + j - 1;
        return;
      }
    }
  }

  // --------------------------------------------------------------------------
  // 5. footer block.
  // --------------------------------------------------------------------------
  curr_offset += blocksize;
  if (curr_offset + FOOTER_SIZE_123 > length ||
      memcmp(FOOTER_SIGNATURE_123, &data[curr_offset], FOOTER_SIZE_123) != 0) {
    *validates = false;
    *promising = true;
    *validates_to = curr_offset - 1;
    return;
  }
  curr_offset += blocksize;

  // full file present.
  *validates = true;
  *promising = false;
  *validates_to = curr_offset - 1;
}


// ============================================================================
// Block state API functions
// ============================================================================
//
// Each hook is documented in scalpelconf.c. gif.h contains a more elaborate
// example using dynamic-length data; here, block state is a single char, so
// the implementations are simple.




// Tell scalpel how to serialize and deserialize the block state
static inline bool file_123_serialize_block_state(void **state, FILE *fp,
                                            StateSerialization mode) {
  // cast state to correct structure
  File123BlockState **s = (File123BlockState **)state;


  // this defines a function pointer fb, which points to read or write depending on the mode
  size_t (*fb)(void *ptr, size_t size, size_t nitems, FILE *stream) =
    mode == SERIALIZE ?
    (size_t (*)(void *, size_t, size_t, FILE *))fwrite :
    (size_t (*)(void *, size_t, size_t, FILE *))fread;


  // if mode is deserialize, then we need to allocate a buffer for the state
  if (mode == DESERIALIZE) {
    *s = (File123BlockState *)malloc(sizeof(File123BlockState));
    check_memory_allocation(*s, __LINE__, __FILE__, "File123BlockState");
  }


  // perform the actual serialization or deserialization. Since our struct
  // consists of static values, the code is short and simple. See gif.h
  // for a more complex example.
  if (fb(&((*s)->value), sizeof(char), 1, fp) != 1) {
    perror("file_123_serialize_block_state: value");
    handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
  }


  return true;
}




// Tell scalpel how to clone the block state
static inline void *file_123_clone_block_state(const void *srcstate) {
  File123BlockState *s = (File123BlockState *)srcstate;
  File123BlockState *d = (File123BlockState*) malloc(sizeof(File123BlockState));
  check_memory_allocation(d, __LINE__, __FILE__, "File123BlockState clone");
  d->value = s->value;
  return d;
}




//Tell scalpel how to free the block state
static inline void file_123_free_block_state(void **state) {
  File123BlockState **s = ((File123BlockState **)state);
  if (*s) {
    //simply free the struct
    free(*s);
    *s = NULL;
  }
}




// SIZEOFBLOCKSTATEFUNC: File123BlockState is plain-old-data with no internal
// pointers, so memcpy produces a correct deep clone.  Defining this
// function lets scalpel3 use a fast memcpy path instead of calling
// file_123_clone_block_state.
static inline size_t file_123_sizeof_block_state(const void *state) {
  (void)state;
  return sizeof(File123BlockState);
}




//Tell scalpel how to print the block state
static inline void file_123_print_block_state(const void *state) {
  const File123BlockState *s = (const File123BlockState *)state;
  if (!s) {
    fprintf(stdout, "NULL");
  } else {
    fprintf(stdout, "'%c'", s->value);
  }
}






// ============================================================================
// Candidate (carve) state API functions
// ============================================================================
//
// Each hook is documented in scalpelconf.c. gif.h shows a richer example with
// dynamic data; the File123ReassemblyState struct here is fixed-size POD, so
// the hooks reduce to memcpy / malloc / free.


// Validate fixed-size state before using restored fields.
//
static inline bool file_123_carve_state_valid(const File123ReassemblyState *state) {
  if (!state) {
    return false;
  }
  const uint8_t *bytes = (const uint8_t *)state;
  const size_t flags[] = {
    offsetof(File123ReassemblyState, header_placed),
    offsetof(File123ReassemblyState, metadata_placed),
    offsetof(File123ReassemblyState, footer_placed),
    offsetof(File123ReassemblyState, skeleton_initialized)
  };
  for (uint32_t i = 0; i < sizeof(flags) / sizeof(flags[0]); i++) {
    if (bytes[flags[i]] > 1) {
      return false;
    }
  }
  return state->scan.kind <= FILE123_SCAN_TYPE
      && (state->scan.kind == FILE123_SCAN_NONE
          || (state->scan.image_blocks > 0
              && state->scan.image_blocks <= INT64_MAX
              && state->scan.remaining <= state->scan.image_blocks
              && state->scan.next_actual < state->scan.image_blocks));
}

// The original unversioned record is still readable; it had no scan frontier.
//
static inline bool file_123_serialize_carve_state(void **state, FILE *fp,
                                                StateSerialization mode) {
  if (!state || !fp) {
    return false;
  }
  File123ReassemblyState **typed = (File123ReassemblyState **)state;
  if (mode == SERIALIZE) {
    const uint32_t header[] = {FILE123_STATE_MAGIC, FILE123_STATE_VERSION};
    if (!file_123_carve_state_valid(*typed)) {
      return false;
    }
    if (fwrite(header, sizeof(header), 1, fp) != 1
        || fwrite(*typed, sizeof(**typed), 1, fp) != 1) {
      handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
    }
    return true;
  }

  uint32_t marker = 0;
  if (fread(&marker, sizeof(marker), 1, fp) != 1) {
    handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
  }
  *typed = (File123ReassemblyState *)calloc(1, sizeof(**typed));
  check_memory_allocation(*typed, __LINE__, __FILE__, "123 restored state");
  if (marker == FILE123_STATE_MAGIC) {
    uint32_t version = 0;
    if (fread(&version, sizeof(version), 1, fp) != 1) {
      handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
    }
    if (version != FILE123_STATE_VERSION) {
      file_123_free_carve_state(state);
      return false;
    }
    if (fread(*typed, sizeof(**typed), 1, fp) != 1) {
      handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
    }
  }
  else {
    uint8_t legacy[sizeof(File123LegacyState)];
    memcpy(legacy, &marker, sizeof(marker));
    if (fread(legacy + sizeof(marker), sizeof(legacy) - sizeof(marker), 1, fp) != 1) {
      handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
    }
    memcpy(*typed, legacy, sizeof(legacy));
  }
  if (!file_123_carve_state_valid(*typed)) {
    file_123_free_carve_state(state);
    return false;
  }
  return true;
}




// Tell Scalpel how to clone carve state
static inline void *file_123_clone_carve_state(const void *srcstate) {
  const File123ReassemblyState *s =
                  (const File123ReassemblyState *)srcstate;
  File123ReassemblyState *d = (File123ReassemblyState *)
                  malloc(sizeof(File123ReassemblyState));


  check_memory_allocation(d, __LINE__, __FILE__, "file_123_clone_carve_state");


  // safe to use memcpy for the deep clone since everything in the
  // struct is plain-old-data
  memcpy(d, s, sizeof(File123ReassemblyState));
  // once again, if you have pointers or dynamic data in your
  // state, you'll need more complicated logic
  // for performing the deep clone
  return d;
}




// Tell scalpel how to free the carve state
static inline void file_123_free_carve_state(void **state) {
  File123ReassemblyState **s = (File123ReassemblyState **)state;
  //This is straightforward since no dynamic data
  free(*s);
  *s = NULL;
}




// SIZEOFCARVESTATEFUNC: File123ReassemblyState is plain-old-data with no
// internal pointers, so memcpy produces a correct deep clone.  Defining
// this function lets scalpel3 use a fast memcpy path instead of calling
// file_123_clone_carve_state.
static inline size_t file_123_sizeof_carve_state(const void *state) {
  (void)state;
  return sizeof(File123ReassemblyState);
}




// Tell scalpel how to print the carve state for debugging purposes
static inline void file_123_print_carve_state(const void *state) {
  const File123ReassemblyState *s =
                  (const File123ReassemblyState *)state;


  if (!s) {
    printf("NULL\n");
    return;
  }


  //Produce a report of the values that are in the state
  printf("H:%d M:%d F:%d SKEL:%d\n", s->header_placed,
                                      s->metadata_placed,
                                      s->footer_placed,
                                      s->skeleton_initialized);
  printf("Expected blocks: ");
  for (int i = 0; i < 10; i++) {
    printf("%d ", s->expected_blocks[i]);
  }
  printf("\nRecovered blocks: ");
  for (int i = 0; i < 10; i++) {
    printf("%d ", s->recovered_blocks[i]);
  }
  printf("\n");
}






// ============================================================================
// Custom reassembly logic
// ============================================================================
//
// When and why a format wants a custom reassembly thread.
//
// scalpel3 requires every file type to register a block validator and a
// file validator. The file validator is used during contiguous recovery
// (phase C) and -- by default -- during fragmented reassembly (phases
// F1/F2) via the LR (left-to-right) strategy in reassembly.c.
//
// If LR is a poor fit, you can register your own .REASSEMBLYFUNC. Two
// flavors are typical:
//
//   Option 1: reuse the file validator inside a custom reassembly thread.
//             Good when the format is rigid, blocks have well-defined
//             positions, and section boundaries align with block
//             boundaries, so validating in sequence remains sensible.
//
//   Option 2: write fully custom validation logic in the reassembly
//             thread. Necessary when section boundaries can fall inside
//             blocks, when blocks must be partially accepted/rejected,
//             when byte-level offset tracking is required, or when
//             best-effort / probabilistic matching is involved.
//
// In both flavors the registered file validator is still used during the
// contiguous recovery phase; you only override behaviour for fragmented
// recovery.
//
// 123 uses Option 1. Its layout is dictated by the metadata block: each
// block has a well-defined section, sections align on block boundaries,
// digit blocks of the same section are byte-identical, and the file is
// validated end-to-end by file_123_file_validate(). As a result we do not
// need the LR-style backtracking machinery -- no best-choices queue, no
// tail-shrinking. Real-world formats almost always do.
//
// The functions below mix two layers:
//   - Higher-level helpers specific to 123 reassembly (init candidate,
//     prepare for extension, get block choice, ...).
//   - Lower-level helpers that compute section boundaries, validate
//     metadata, manipulate the blockvector, etc.
//
// Some general utilities live in reassembly.c and are reused via
// scalpel.h (e.g., reassembly_time_to_checkpoint,
// reassembly_check_max_size).


// ----------------------------------------------------------------------------
// Higher-level reassembly helpers
// ----------------------------------------------------------------------------


// prepare a candidate pulled off the promising queue for processing.
//
// Candidates arrive in one of three states:
//   1. Header-only          -- just found during header discovery
//   2. Header + contiguous  -- partial run produced by contiguous recovery
//   3. Partially reassembled -- returned from a previous checkpoint
//
// For (1) and (2) we allocate fresh reassembly state, locate a metadata
// block (preferring one already present in the candidate; otherwise
// searching the image), place it, resize the blockvector to the full file
// length implied by the metadata, and re-inflate any blocks that were
// already placed before resizing.
//
// For (3) the state already exists with metadata_placed and
// skeleton_initialized set. We inflate the blockvector and reconcile the
// recovered_blocks[] counts against the current BV contents -- the
// backend may have trimmed covered blocks between checkpoints, making the
// saved counts stale.
static bool file_123_reassembly_init_candidate(ThreadWork *work,
                                   CarveInfo **c_ptr,
                                   uuid_string_t uuidp,
                                   uuid_string_t uuidc){

  CarveInfo *candidate = *c_ptr;
  const int id = work->id;

  if (scalpel_state.mode_verbose) {
    lock_fprintf(stdout,
        "\nReassembly thread #%d processing candidate %p  UUIDs %s / %s\n",
        id, candidate->b, uuidp, uuidc);
  }


  //Fetch or create per file state
  File123ReassemblyState *state =
      (File123ReassemblyState *)carve_get_state(candidate->carvehashkey);


  // initialize state
  if (!state) {
    state = (File123ReassemblyState *)calloc(1, sizeof *state);
    check_memory_allocation(state, __LINE__, __FILE__, "File123ReassemblyState");
    state->header_placed        = true;
    state->metadata_placed      = false;
    state->footer_placed        = false;
    state->skeleton_initialized = false;
    carve_put_state(candidate->carvehashkey, state);

  }


  // initialize bv and inflate the header
  inflate_blockvector(candidate->b);
  // inflate_blockvector_single_block(candidate->b, 0);


  //Case 3: candidate already initialized; inflate and return
  if (blockvector_get_num_blocks(candidate->b) > 1 && state->metadata_placed &&
      state->skeleton_initialized){



    // inflate the block vector
    inflate_blockvector(candidate->b);

    // reconcile recovered_blocks[] with what is actually still in the
    // blockvector.  The backend may have trimmed covered blocks since
    // the last time this candidate was processed, making the saved
    // counts stale.
    uint64_t num_blks = blockvector_get_num_blocks(candidate->b);
    memset(state->recovered_blocks, 0, sizeof(state->recovered_blocks));
    state->header_placed  = false;
    state->footer_placed  = false;
    state->metadata_placed = false;

    for (uint64_t i = 0; i < num_blks; i++) {
      if (blockvector_get_apparent_blocknumber(candidate->b, i) == -1) {
        continue;
      }
      int sec = file_123_slot_to_section(state, num_blks, (int64_t)i);
      if (sec >= 0 && sec < 10) {
        state->recovered_blocks[sec]++;
      } else if (i == 0) {
        state->header_placed = true;
      } else if (i == num_blks - 1) {
        state->footer_placed = true;
      } else {
        state->metadata_placed = true;
      }
    }
    // skeleton_initialized remains true — the layout from metadata
    // (expected_blocks[]) is still valid even after trimming.

    carve_put_state(candidate->carvehashkey, state);
    file_123_free_carve_state((void **)&state);
    return false;
  }


  // candidate needs to be initialized; ensure a metadata block is parsed
  // and the skeleton is set up.


  // calculate how many blocks were already placed in this candidate
  uint64_t placed_blocks = 0;
  for (uint64_t i = 0; i < blockvector_get_num_blocks(candidate->b); i++) {
    if (blockvector_get_apparent_blocknumber(candidate->b, i) != -1) {
      placed_blocks++;
    }
  }



  // was a metadata block already present in the contiguous fragment?
  int64_t m_apparent = -1;
  for (uint64_t i = 0; i < placed_blocks; ++i) {


    int64_t blk_ap = blockvector_get_apparent_blocknumber(candidate->b, i);
    // reached the end of contiguous data; break
    if (blk_ap == -1){
      break;
    }


    // get state
    int64_t blk_act = filemirror_actual_blocknumber(
      scalpel_state.filemirror, blk_ap);
    char hashkey[BLOCK_HASH_KEY_SIZE];
    gen_block_hash_key(hashkey, candidate->needleidx, blk_act);
    File123BlockState *blk_state = (File123BlockState *)block_get_state(hashkey);


    // metadata is already present in the fragment
    if (blk_state && blk_state->value == 'm') {
      m_apparent = blk_ap;
      file_123_free_block_state((void **)&blk_state);
      break;
    }
    file_123_free_block_state((void **)&blk_state);
  }


  // log metadata search results


  if (m_apparent != -1) {
    // metadata is already present
    file_123_place_metadata_block(candidate, m_apparent);
  } else {
    // no metadata block already in candidate; search for one
    int64_t meta_block = file_123_find_valid_metadata_block(
        work, c_ptr, state, uuidp, uuidc);
    if (meta_block == FILE123_SCAN_YIELDED) {
      file_123_free_carve_state((void **)&state);
      return true;
    }
    if (meta_block < 0) {
      if (scalpel_state.mode_verbose){
        lock_fprintf(stdout,
          "\n[init] No matching metadata block for UUID %s - abandoning\n",
          uuidc);
      }
      file_123_free_carve_state((void **)&state);
      destroy_candidate(c_ptr);
      return false;
    }
    //metadata block found
    file_123_place_metadata_block(candidate, meta_block);
  }


  // metadata is in place; calculate the full file size, build the
  // full-size skeleton, and re-inflate existing blocks.


  uint64_t total_blocks = file_123_calculate_file_size_from_metadata(candidate);
  if (total_blocks == 0) {
    // shouldn’t happen; but for safety:
    file_123_free_carve_state((void **)&state);
    destroy_candidate(c_ptr);
    return false;
  }


  // initializes empty slots to have actual/apparent blknum -1
  resize_blockvector(candidate->b, total_blocks);


  // inflate the good blocks after the header. This function populates
  // the data buffer, but it also updates the BV length
  // so even though we're not accessing data, calls to this are needed any
  // time blocks are committed, to ensure bv length is set correctly
  for (uint64_t i = 1; i < placed_blocks; ++i) {
    if (blockvector_get_apparent_blocknumber(candidate->b, i) != -1) {
      inflate_blockvector_single_block(candidate->b, i);
    }
  }


  // retrieve state
  File123ReassemblyState *st =
        (File123ReassemblyState *)carve_get_state(candidate->carvehashkey);


  // for the pre-existing blocks, we need to update recovered blocks
  for (uint64_t i = 1; i < placed_blocks; ++i) {
    if (blockvector_get_apparent_blocknumber(candidate->b, i) != -1) {
      //get actual block number
      int64_t actual_blk = filemirror_actual_blocknumber(scalpel_state.filemirror,
                                                         blockvector_get_apparent_blocknumber(candidate->b, i));
      // retrieve the state for this block
      char hashkey[BLOCK_HASH_KEY_SIZE];
      gen_block_hash_key(hashkey, candidate->needleidx, actual_blk);
      File123BlockState *blk_state =
          (File123BlockState *)block_get_state(hashkey);
      char ch = blk_state->value;
      file_123_free_block_state((void **)&blk_state);
      // update the recovered blocks approrpriately
      if (ch >= '0' && ch <= '9') {
        int sec = ch - '0';
        st->recovered_blocks[sec]++;
      }
    }
  }


  carve_put_state(candidate->carvehashkey, st);
  file_123_free_carve_state((void **)&st);
  file_123_free_carve_state((void **)&state);
  return false;
}






// decide where the reassembly thread should begin searching for the next
// block. Called each time we try to extend a candidate by one logical slot.
//
// Similar to the LR-reassembly helper but adapted for 123 files:
//
//   - 123 blockvectors are sized to the final file length up front; empty
//     slots are marked -1, so no dynamic resize is required.
//
//   - 123 reassembly never uses clones, because layout is metadata-directed
//     rather than exploratory. Each thread works on a unique candidate, so
//     we do not randomize the starting point to avoid lock-step.
//
//   - Strategy: find the first hole (-1) in the blockvector and propose a
//     preferred starting point for the search (previous_apparent + 1 if a
//     predecessor exists).
//
// Returns true if a hole was found (out-params valid), false if the
// candidate is already complete (out-params set to -1). hole_idx is the
// logical index of the first hole; start_ap is a heuristic apparent block
// to try first (>0 for prefer-continuity, -1 for no guess).
static bool file_123_reassembly_prepare_for_extension(CarveInfo *cand,
                                              int64_t *hole_idx,
                                              int64_t *start_ap){
  // Search all logical slots, including holes beyond the current byte extent.
  int64_t slots = blockvector_get_num_blocks(cand->b);


  //loop over all the slots
  for (int64_t i = 0; i < slots; ++i) {
    //find the first hole and assign to hole_idx
    if (blockvector_get_apparent_blocknumber(cand->b, i) == -1) {
      if (hole_idx){
        *hole_idx = i;
      }
      //get the next likely block (contiguous)
      if (start_ap) {
        if (i > 0 && blockvector_get_apparent_blocknumber(cand->b, i-1) != -1){
          *start_ap = blockvector_get_apparent_blocknumber(cand->b, i-1) + 1;
        }
        else{
            *start_ap = -1;
        }
      }
      //if a hole is found, then let the caller proceed
      return true;
    }
  }
  // No holes left – candidate is full
  if (hole_idx){
    *hole_idx = -1;
  }
  if (start_ap){
    *start_ap = -1;
  }
  return false;
}


// Search from the preferred physical block, wrapping once. Rejected blocks
// need not be tried again after a checkpoint; current selectability is checked
// before every trial. Repeated identical digit blocks may reuse an already
// placed block when deduplication has removed the other copies.
// Returns an apparent block number, -1 when exhausted, or -2 after yielding.
//
static int64_t file_123_reassembly_get_block_choice(
    ThreadWork *work, CarveInfo **candidate, int64_t *block_choice_start,
    int64_t logical_slot_index, char target_type,
    uuid_string_t uuidp, uuid_string_t uuidc) {
  File123ReassemblyState *state =
      (File123ReassemblyState *)carve_get_state((*candidate)->carvehashkey);
  if (!state) {
    return -1;
  }
  file_123_scan_begin(*candidate, state, FILE123_SCAN_TYPE,
      (uint64_t)logical_slot_index,
      block_choice_start ? *block_choice_start : 0, target_type);
  uint64_t examined = 0;
#if BLOCK_SELECTION_PERFORMANCE_STATS > 0
  const uint32_t needleidx = (*candidate)->needleidx;
  struct timespec started, ended;
  clock_gettime(CLOCK_MONOTONIC, &started);
#endif
  int64_t choice = file_123_scan_blocks(work, candidate, state,
      (uint64_t)logical_slot_index, target_type, uuidp, uuidc, &examined);
#if BLOCK_SELECTION_PERFORMANCE_STATS > 0
  clock_gettime(CLOCK_MONOTONIC, &ended);
  const uint64_t elapsed = (ended.tv_sec - started.tv_sec) * NANOSECONDS_PER_SECOND
                            + (ended.tv_nsec - started.tv_nsec);
  atomic_fetch_add_explicit(&scalpel_state.search_specs[needleidx].BLK_calls,
                           1, memory_order_acq_rel);
  atomic_max_u64_pub(&scalpel_state.search_specs[needleidx].BLK_longest, elapsed);
  atomic_fetch_add_explicit(&scalpel_state.search_specs[needleidx].BLK_total,
                           elapsed, memory_order_acq_rel);
  atomic_max_u64_pub(&scalpel_state.search_specs[needleidx].BLK_most_blocks, examined);
#endif
  file_123_free_carve_state((void **)&state);
  if (choice >= 0) {
    blockvector_remove_choice((*candidate)->b, (uint64_t)logical_slot_index, choice);
    if (block_choice_start) {
      *block_choice_start = choice + 1;
    }
  }
  else if (choice == -1 && target_type >= '0' && target_type <= '9') {
    choice = file_123_find_reusable_section_block(*candidate, target_type);
  }
  return choice;
}


static int64_t file_123_find_reusable_section_block(CarveInfo *candidate,
                                                   char target_type) {
  uint64_t slots = blockvector_get_num_blocks(candidate->b);

  for (uint64_t i = 0; i < slots; ++i) {
    int64_t apparent = blockvector_get_apparent_blocknumber(candidate->b, i);
    if (apparent == -1) {
      continue;
    }

    int64_t actual_blk = filemirror_actual_blocknumber(
        scalpel_state.filemirror, apparent);
    char hashkey[BLOCK_HASH_KEY_SIZE];
    gen_block_hash_key(hashkey, candidate->needleidx, actual_blk);
    File123BlockState *blk_state = (File123BlockState *)block_get_state(hashkey);
    bool match = (blk_state && blk_state->value == target_type);
    file_123_free_block_state((void **)&blk_state);

    if (match) {
      return apparent;
    }
  }

  return -1;
}






// commit a block to the blockvector by placing it into `slot` and
// inflating the BV. Similar to the LR version but doesn't commit from
// the end -- accepts an arbitrary slot index. The candidate length is
// not updated because 123 candidates are not built contiguously.
static void file_123_reassembly_extension_successful(int id,
                                      CarveInfo *candidate,
                                      int64_t logical_slot_index) {
  (void)id;


  File123ReassemblyState *st =
        (File123ReassemblyState *)carve_get_state(candidate->carvehashkey);


  // convert actual block to apparent blocknumber
  int64_t apparent = filemirror_apparent_blocknumber( scalpel_state.filemirror, candidate->newblock);


  //make sure the logical index is at least 0
  if (logical_slot_index < 0) {
    lock_fprintf(stderr, "[error] logical_slot_index is negative: %" PRId64 "\n", logical_slot_index);
    file_123_free_carve_state((void **)&st);
    exit(1);
  }
  //Also make sure the logical slot index is within bounds
  if ((uint64_t) logical_slot_index >= blockvector_get_num_blocks(candidate->b)){
    lock_fprintf(stdout, "logical_slot_index %" PRId64 " exceeds blockvector length %" PRIu64 "\n",
                logical_slot_index, blockvector_get_num_blocks(candidate->b));
    file_123_free_carve_state((void **)&st);
    exit(1);
  }
  // place the block into the specified logical slot
  blockvector_set_apparent_blocknumber(candidate->b, logical_slot_index, apparent);


  // inflate that block; we're not accessing data, but this call is needed
  // to ensure bv->length is updated appropriately
  inflate_blockvector_single_block(candidate->b, logical_slot_index);


  //update recovered blocks
  int sec = file_123_slot_to_section(st, blockvector_get_num_blocks(candidate->b), logical_slot_index);
  if (sec >= 0 && sec < 10){
    st->recovered_blocks[sec]++;
  }
  //update the footer flag if we place that block
  if (logical_slot_index == (int64_t)(blockvector_get_num_blocks(candidate->b) - 1)) {
    st->footer_placed = true;
  }
  carve_put_state(candidate->carvehashkey, st);
  file_123_free_carve_state((void **)&st);
}






// attempt to rapidly extend a candidate across a known hole by placing
// a sequence of contiguous blocks and validating the result. This is
// gallop mode -- inspired by LR reassembly's galloping strategy but
// tailored to deterministic, metadata-driven 123 files.
//
// Behavior:
//   - Starts at the beginning of a hole in the candidate's blockvector.
//   - Sequentially places the next logical (contiguous) apparent block
//     into the candidate.
//   - Skips block-selection heuristics (does not call get_block_choice())
//     to preserve the speed and intent of galloping.
//   - Stops placing if the previous block isn't present (can't derive
//     next), a block is already placed elsewhere, or a candidate block
//     is marked BLOCK_CONFIDENCE_INVALID.
//   - After attempting to gallop-fill the hole, calls the file validator
//     to assess whether the new region is valid.
//   - On failure, rolls back unvalidated blocks and resets the gallop.
//
// Differences from LR galloping: LR assumes sequential reassembly and
// may expand the entire candidate length; this version uses a
// pre-defined hole range, does not grow the blockvector, and avoids
// overwriting future valid regions.
static void file_123_reassembly_gallop(int            id,
                                       CarveInfo     *candidate,
                                       int64_t        start_index,
                                       int64_t        end_index,
                                       uint32_t      *gallop,
                                       uint64_t      *validates_to,
                                       bool          *validates){
  (void)id;


  // determine how many blocks to try in this round
  const uint32_t hole_size = (uint32_t)(end_index - start_index + 1);


  if (*gallop == 0){
    //first time
    *gallop = scalpel_state.gallop_factor;
  } else {
    //exponential growth
    *gallop *= scalpel_state.gallop_factor;
    if (*gallop > hole_size){
      *gallop = hole_size;
    }
  }


  // place sequential blocks
  int64_t  logical_index = start_index;
  uint32_t placed_count  = 0;


  while (logical_index <= end_index && placed_count < *gallop){


    if (logical_index == 0 ||
        blockvector_get_apparent_blocknumber(candidate->b, logical_index - 1) == -1){
      break;
    }


    int64_t prev_ap  = blockvector_get_apparent_blocknumber(candidate->b, logical_index - 1);
    int64_t next_ap  = prev_ap + 1;


    if (apparent_block_in_blockvector(candidate->b, next_ap)){
      break;
    }


    //make sure the block is valid for this file type
    if (filemirror_get_blocktype(scalpel_state.filemirror,
            filemirror_actual_blocknumber(scalpel_state.filemirror, next_ap),
            candidate->needleidx) == BLOCK_CONFIDENCE_INVALID){
      break;
    }


    // commit the block into the hole
    blockvector_set_apparent_blocknumber(candidate->b, logical_index, next_ap);
    // inflate_blockvector_single_block(candidate->b, logical_index);


    //update the recovered blocks in the metadata
    File123ReassemblyState *st =
    (File123ReassemblyState *)carve_get_state(candidate->carvehashkey);
    int sec = file_123_slot_to_section(st, blockvector_get_num_blocks(candidate->b), logical_index);
    if (sec >= 0 && sec < 10){
      st->recovered_blocks[sec]++;
    }
    carve_put_state(candidate->carvehashkey, st);
    file_123_free_carve_state((void **)&st);
    candidate->newblock = filemirror_actual_blocknumber(
                              scalpel_state.filemirror, next_ap);
    ++logical_index;
    ++placed_count;
  }


  // validate the contiguous portion of the file that we modified
  if (placed_count == 0) {
    *validates = false;
    *gallop    = 0;
    return;
  }


  int64_t last_modified = logical_index - 1;
  uint64_t length_bytes = (uint64_t)(last_modified + 1) *
                          scalpel_state.blocksize;


  char *data = file_123_blockvector_to_buffer_range(candidate->b,
                                            0, last_modified);


  bool promising_dummy = false;
  file_123_file_validate(data, length_bytes,
                          validates, validates_to,
                          &promising_dummy,
                          candidate->needleidx,
                          scalpel_state.blocksize,
                          candidate->carvehashkey);
  free(data);


  // if the file validates, resize the block vector to the correct size
  if (*validates) {
    uint64_t validated_blocks = ( (*validates_to + 1) + scalpel_state.blocksize - 1 )
                            / scalpel_state.blocksize;
    resize_blockvector(candidate->b, validated_blocks);
  }


  // rollback to last validates_to upon failure
  if (!*validates) {
    int64_t last_ok = (int64_t)(*validates_to / scalpel_state.blocksize);


    for (int64_t i = last_ok + 1; i <= last_modified; ++i) {
      // decrement recovered blocks (state bookkeeping)
      File123ReassemblyState *st =
      (File123ReassemblyState *)carve_get_state(candidate->carvehashkey);
      int sec = file_123_slot_to_section(st, blockvector_get_num_blocks(candidate->b), i);
      if (sec >= 0 && sec < 10 && st->recovered_blocks[sec] > 0){
        st->recovered_blocks[sec]--;
      }
      carve_put_state(candidate->carvehashkey, st);
      file_123_free_carve_state((void **)&st);
      blockvector_set_apparent_blocknumber(candidate->b, i, -1);
    }
    //reset gallop factor
    *gallop = 0;
  }
}






// validate an entire candidate by flattening its blockvector into a buffer
// and running the registered file validator over it
static bool file_123_validate_candidate(CarveInfo *cand,
                                        uint64_t  *validates_to){


  uint64_t len_bytes = blockvector_get_num_blocks(cand->b) * scalpel_state.blocksize;
  // copy the file data into a buffer (without per-slot bitmaps, etc)
  char *buf = file_123_blockvector_to_buffer_range(cand->b,
                                          0, blockvector_get_num_blocks(cand->b) - 1);


  bool ok, prom;
  // pass through the file validator
  file_123_file_validate(buf, len_bytes,
                         &ok, validates_to,
                         &prom, cand->needleidx,
                         scalpel_state.blocksize,
                         cand->carvehashkey);
  free(buf);
  return ok;
}






// locate the inclusive end of the current hole that starts at `start`
static int64_t file_123_find_hole_end(CarveInfo *cand, uint64_t start){
  uint64_t i = start;
  while (i < blockvector_get_num_blocks(cand->b) &&
         blockvector_get_apparent_blocknumber(cand->b, i) == -1){
    ++i;
  }


  return i - 1;
}






// return the required File123BlockState tag for the block that belongs
// in `slot` (e.g., 'h' for header slot, '3' for a slot inside section 3)
static char file_123_block_type_for_slot(CarveInfo *cand, uint64_t slot){
  File123ReassemblyState *st =
      (File123ReassemblyState *)carve_get_state(cand->carvehashkey);


  if (!st || !st->skeleton_initialized){
    file_123_free_carve_state((void **)&st);
    return '?';
  }


  // header 0, sections 0‑9, metadata, footer
  if (slot == 0){
    file_123_free_carve_state((void **)&st);
    return 'h';
  }
  // last slot is guaranteed to be the footer because of resizing in init_candidate
  if (slot == blockvector_get_num_blocks(cand->b) - 1){
    file_123_free_carve_state((void **)&st);
    return 'f';
  }


  // walk through section boundaries to determine what section pos falls
  uint64_t pos = 1;
  for (int sec = 0; sec < 10; ++sec) {
    uint64_t end = pos + st->expected_blocks[sec] - 1;
    if (slot >= pos && slot <= end){
      file_123_free_carve_state((void **)&st);
      return (char)('0' + sec);
    }
    pos = end + 1;
  }
  // if still not found after searching the 10 sections, then metadata
  file_123_free_carve_state((void **)&st);
  return 'm';
}






// ----------------------------------------------------------------------------
// Lower-level reassembly helpers
// ----------------------------------------------------------------------------


// resize the blockvector to the expected number of blocks given the
// state information of the candidate. Used to do a final resize before
// writing out the candidate.
static void file_123_resize_blockvector_to_expected(CarveInfo *cand) {


  File123ReassemblyState *state =
              (File123ReassemblyState *)carve_get_state(cand->carvehashkey);


  uint64_t expected_total_blocks = 0;
  if (state->header_placed){
    expected_total_blocks += 1;
  }
  if (state->metadata_placed){
    expected_total_blocks += 1;
  }
  for (int section = 0; section < 10; section++){
    expected_total_blocks += state->expected_blocks[section];
  }
  if (state->footer_placed){
    expected_total_blocks += 1;
  }
  resize_blockvector(cand->b, expected_total_blocks);
  file_123_free_carve_state((void **)&state);
}


// translate a logical slot index into a section number 0..9 using
// expected_blocks[] in the reassembly state, or -1 for header /
// metadata / footer slots.
//
// Used as a helper when updating recovered_blocks[] in the reassembly
// state -- we need a section number from a slot number. -1 is
// returned for header/metadata/footer because those have dedicated
// flags in the state struct.
static int file_123_slot_to_section(const File123ReassemblyState *st,
                           uint64_t num_blocks,
                           int64_t slot){
    //layout unknown
    if (!st || !st->skeleton_initialized){
      return -1;
    }
    //header
    if (slot == 0){
      return -1;
    }
    //footer
    if (slot == (int64_t)(num_blocks-1)){
      return -1;
    }


    int64_t pos = 1;
    for (int sec = 0; sec < 10; ++sec) {
        int64_t end = pos + st->expected_blocks[sec] - 1;
        if (slot >= pos && slot <= end){
          return sec;
        }
        pos = end + 1;
    }
    // If we haven't returned by now, then it's metadata
    return -1;
}


// convert a range of a blockvector [start_idx, end_idx] into a contiguous
// heap buffer. Each block in the range is read individually; missing
// blocks (apparent == -1) are zero-filled. The caller owns and must free
// the returned buffer.
//
// Used during file validation, especially in gallop mode, to construct a
// temporary buffer to pass to a validator.
static char *file_123_blockvector_to_buffer_range(BlockVector *bv, int64_t start_idx, int64_t end_idx) {
  int64_t num_blocks = end_idx - start_idx + 1;
  uint64_t blocksize = scalpel_state.blocksize;
  char *buffer = (char *)malloc(num_blocks * blocksize);
  check_memory_allocation(buffer, __LINE__, __FILE__, "file_123_blockvector_to_buffer_range");

  for (int64_t i = start_idx; i <= end_idx; i++) {
    char *block_dest = buffer + (i - start_idx) * blocksize;

    int64_t ap = blockvector_get_apparent_blocknumber(bv, i);
    if (ap == -1) {
      memset(block_dest, 0, blocksize);
    } else {
      unsigned char *block = get_apparent_block_data(scalpel_state.filemirror, ap);
      memcpy(block_dest, block, blocksize);
      free(block);
    }
  }
  return buffer;
}


// Bind a scan to the candidate's physical mapping, not apparent numbering.
// A changed candidate must reconsider earlier metadata compatibility decisions.
//
static inline XXH128_hash_t file_123_scan_query(CarveInfo *candidate,
                                               uint64_t slot, char target_type) {
  XXH3_state_t hash;
  XXH3_128bits_reset(&hash);
  const uint64_t geometry[] = {
    blockvector_get_num_blocks(candidate->b),
    blockvector_get_data_length(candidate->b),
    filemirror_filesize(scalpel_state.filemirror), scalpel_state.blocksize,
    slot, (uint8_t)target_type, candidate->needleidx
  };
  XXH3_128bits_update(&hash, geometry, sizeof(geometry));
  for (uint64_t i = 0; i < geometry[0]; i++) {
    const int64_t actual = blockvector_get_actual_blocknumber(candidate->b, i);
    XXH3_128bits_update(&hash, &actual, sizeof(actual));
  }
  return XXH3_128bits_digest(&hash);
}

static inline void file_123_scan_begin(CarveInfo *candidate,
    File123ReassemblyState *state, File123ScanKind kind, uint64_t slot,
    int64_t start_apparent, char target_type) {
  const XXH128_hash_t query = file_123_scan_query(candidate, slot, target_type);
  if (state->scan.kind == (uint32_t)kind
      && XXH128_isEqual(query, state->scan.query)) {
    return;
  }
  const uint64_t blocks = CEILDIV(
      filemirror_filesize(scalpel_state.filemirror), scalpel_state.blocksize);
  int64_t first = 0;
  if (start_apparent >= 0
      && (uint64_t)start_apparent < filemirror_apparent_blocks(scalpel_state.filemirror)) {
    first = filemirror_actual_blocknumber(scalpel_state.filemirror, start_apparent);
  }
  if (first < 0 || (uint64_t)first >= blocks) {
    first = 0;
  }
  state->scan = (File123Scan) {
    .query = query, .next_actual = (uint64_t)first,
    .remaining = blocks, .image_blocks = blocks, .kind = (uint32_t)kind
  };
}

// Scan physical positions once, checking current selectability at each trial.
// Return -2 only after saving progress and yielding with the committed mapping.
//
static int64_t file_123_scan_blocks(ThreadWork *work, CarveInfo **candidate,
    File123ReassemblyState *state, uint64_t slot, char target_type,
    uuid_string_t uuidp, uuid_string_t uuidc, uint64_t *examined) {
  *examined = 0;
  while (state->scan.remaining > 0) {
    (*examined)++;
    const uint64_t actual = state->scan.next_actual;
    state->scan.next_actual = actual + 1 == state->scan.image_blocks ? 0 : actual + 1;
    state->scan.remaining--;
    const int64_t apparent = filemirror_apparent_blocknumber(
        scalpel_state.filemirror, (int64_t)actual);
    uint64_t evaluated = 0;
    if (apparent >= 0
        && filemirror_actual_blocknumber(scalpel_state.filemirror, apparent) == (int64_t)actual
        && blockvector_get_choice((*candidate)->b, slot, apparent, 1, &evaluated) == apparent
        && !apparent_block_in_blockvector((*candidate)->b, apparent)
        && filemirror_get_blocktype(scalpel_state.filemirror, (int64_t)actual,
                                    (*candidate)->needleidx) != BLOCK_CONFIDENCE_INVALID) {
      char hashkey[BLOCK_HASH_KEY_SIZE];
      gen_block_hash_key(hashkey, (*candidate)->needleidx, (int64_t)actual);
      File123BlockState *block_state = (File123BlockState *)block_get_state(hashkey);
      const bool matches = block_state && block_state->value == target_type;
      file_123_free_block_state((void **)&block_state);
      if (matches && (state->scan.kind != FILE123_SCAN_METADATA
                      || file_123_validate_metadata_block(*candidate, apparent))) {
        memset(&state->scan, 0, sizeof(state->scan));
        carve_put_state((*candidate)->carvehashkey, state);
        return apparent;
      }
    }
    if (*examined % FILE123_SCAN_INTERVAL == 0) {
      if (reassembly_check_kill_queue(work, candidate, uuidp, uuidc)) {
        return FILE123_SCAN_YIELDED;
      }
      if (atomic_load_explicit(&REASS_RETURN_TO_IDLE, memory_order_acquire)) {
        carve_put_state((*candidate)->carvehashkey, state);
        if (reassembly_time_to_checkpoint(work->id, *candidate, uuidp, uuidc)) {
          return FILE123_SCAN_YIELDED;
        }
      }
    }
  }
  memset(&state->scan, 0, sizeof(state->scan));
  carve_put_state((*candidate)->carvehashkey, state);
  return -1;
}

// Find a metadata block whose identifier and section layout match the header.
// The common scan retains rejected-source progress across checkpoints.
//
static int64_t file_123_find_valid_metadata_block(
    ThreadWork *work, CarveInfo **candidate, File123ReassemblyState *state,
    uuid_string_t uuidp, uuid_string_t uuidc) {
  file_123_scan_begin(*candidate, state, FILE123_SCAN_METADATA, 0, 0, 'm');
  uint64_t examined = 0;
  return file_123_scan_blocks(work, candidate, state, 0, 'm', uuidp, uuidc, &examined);
}






// check that `metadata_block` (apparent block number) is a metadata
// block that pairs correctly with `candidate`. Two things must hold:
//
//   1. The metadata signature is present and the embedded 8-char file
//      ID matches the file ID in the candidate's header block.
//   2. The blocks already placed in the candidate are consistent with
//      the section layout described by the metadata records: each
//      placed block falls in the section its tag implies, and no
//      section has more placed blocks than the metadata expects.
//
// Returns true if both hold. Does NOT mutate carve state -- that is
// done later by file_123_place_metadata_block() once a valid metadata
// block has been chosen.
static bool file_123_validate_metadata_block(CarveInfo *candidate, int64_t metadata_block) {
  File123ReassemblyState *state =
  (File123ReassemblyState *)carve_get_state(candidate->carvehashkey);
  if (!state){
    return false;
  }

  int64_t actual_block =
  filemirror_actual_blocknumber(scalpel_state.filemirror, metadata_block);
  uint8_t *blockdata = file_123_get_metadata_block_data(actual_block);
  if (!blockdata){
    file_123_free_carve_state((void **)&state);
    return false;
  }

  if (memcmp(blockdata, "#METADATA#", METADATA_SIZE_123) != 0) {
    free(blockdata);
    file_123_free_carve_state((void **)&state);
    return false;
  }

  // compare the file ID in the metadata block against the header block's
  // file ID.  This ensures each metadata pairs only with its own header.
  int64_t hdr_ap = blockvector_get_apparent_blocknumber(candidate->b, 0);
  unsigned char *hdr_data = get_apparent_block_data(scalpel_state.filemirror, hdr_ap);
  if (!hdr_data) {
    free(blockdata);
    file_123_free_carve_state((void **)&state);
    return false;
  }
  bool id_match = (memcmp(&hdr_data[HEADER_SIZE_123],
                          &blockdata[METADATA_SIZE_123],
                          FILE_ID_SIZE_123) == 0);
  free(hdr_data);
  if (!id_match) {
    free(blockdata);
    file_123_free_carve_state((void **)&state);
    return false;
  }

  uint64_t placed_blocks = 0;
  for (uint64_t i = 0; i < blockvector_get_num_blocks(candidate->b); i++) {
    if (blockvector_get_apparent_blocknumber(candidate->b, i) != -1) {
      placed_blocks++;
    }
  }

  uint8_t expected[10] = {0};
  for (int section = 0; section < 10; section++) {
    char size_str[9] = {0};
    memcpy(size_str, &blockdata[METADATA_SIZE_123 + FILE_ID_SIZE_123 + 9 + section * 17], 8);
    uint64_t size = strtoull(size_str, NULL, 10);
    expected[section] =
    (uint8_t)((size + scalpel_state.blocksize - 1) / scalpel_state.blocksize);
  }

  int current_section = -1;
  int placed_in_section = 0;

  for (uint64_t i = 1; i < placed_blocks; i++) {
    int64_t blknum = blockvector_get_apparent_blocknumber(candidate->b, i);
    int64_t actual_blk = filemirror_actual_blocknumber(scalpel_state.filemirror, blknum);
    int64_t exemplar_blk = filemirror_get_exemplar(scalpel_state.filemirror, actual_blk);

    char hashkey[BLOCK_HASH_KEY_SIZE];
    gen_block_hash_key(hashkey, candidate->needleidx, exemplar_blk);
    File123BlockState *blk_state = (File123BlockState *)block_get_state(hashkey);

    if (!blk_state) {
      free(blockdata);
      file_123_free_carve_state((void **)&state);
      return false;
    }

    int section = blk_state->value - '0';
    file_123_free_block_state((void **)&blk_state);

    if (current_section == -1) {
      current_section = section;
      placed_in_section = 1;
    } else if (section == current_section) {
      placed_in_section++;
      if (placed_in_section > expected[section]) {
        free(blockdata);
        file_123_free_carve_state((void **)&state);
        return false;
      }
    } else if (section == current_section + 1) {
      if (placed_in_section != expected[current_section]) {
        free(blockdata);
        file_123_free_carve_state((void **)&state);
        return false;
      }
      current_section = section;
      placed_in_section = 1;
    } else {
      free(blockdata);
      file_123_free_carve_state((void **)&state);
      return false;
    }
  }
  free(blockdata);
  file_123_free_carve_state((void **)&state);
  return true;
}




// fetch a heap-allocated copy of the contents of the metadata block at
// the given actual block number. Converts to apparent first, then defers
// to get_apparent_block_data(). The caller owns and must free the
// returned buffer.
static uint8_t *file_123_get_metadata_block_data(int64_t actual_blocknum) {
  int64_t apparent = filemirror_apparent_blocknumber(scalpel_state.filemirror, actual_blocknum);
  if (apparent < 0) {
    return NULL;
  }
  return get_apparent_block_data(scalpel_state.filemirror, apparent);
}




// place the metadata block at its expected slot in the candidate's
// blockvector, parse expected_blocks[] from the record sizes, mark
// metadata_placed and skeleton_initialized in the carve state, and resize
// the BV if necessary to fit the metadata slot
static void file_123_place_metadata_block(CarveInfo *candidate, int64_t apparent_blocknum) {
  if (apparent_blocknum < 0){
    return;
  }

  int64_t actual_block =
    filemirror_actual_blocknumber(scalpel_state.filemirror, apparent_blocknum);
  uint8_t *blockdata = file_123_get_metadata_block_data(actual_block);
  if (!blockdata){
    return;
  }

  if (memcmp(blockdata, "#METADATA#", 10) != 0) {
    free(blockdata);
    return;
  }

  File123ReassemblyState *state =
      (File123ReassemblyState *)carve_get_state(candidate->carvehashkey);
  if (!state) {
    exit(1);
  }

  for (int section = 0; section < 10; section++) {
    char size_str[9] = {0};
    memcpy(size_str, &blockdata[METADATA_SIZE_123 + FILE_ID_SIZE_123 + 9 + section * 17], 8);
    uint64_t byte_size = strtoull(size_str, NULL, 10);

    uint8_t block_count =
      (uint8_t)((byte_size + scalpel_state.blocksize - 1) / scalpel_state.blocksize);
    state->expected_blocks[section] = block_count;
  }

  uint64_t metadata_position = 1;
  for (int i = 0; i < 10; i++) {
    metadata_position += state->expected_blocks[i];
  }

  uint64_t needed_size = metadata_position + 1;
  if (blockvector_get_num_blocks(candidate->b) < needed_size) {
    resize_blockvector(candidate->b, needed_size);
  }

  blockvector_set_apparent_blocknumber(candidate->b, metadata_position, apparent_blocknum);
  inflate_blockvector_single_block(candidate->b, metadata_position);

  state->metadata_placed = true;
  state->skeleton_initialized = true;

  carve_put_state(candidate->carvehashkey, state);
  file_123_free_carve_state((void **)&state);
  free(blockdata);
}




// compute the total block count of a 123 file from the reassembly state
// (1 header + sum of expected_blocks[0..9] + 1 metadata + 1 footer).
// Returns 0 if the state's skeleton has not been initialized.
static uint64_t file_123_calculate_file_size_from_metadata(CarveInfo *candidate) {
  File123ReassemblyState *state =
            (File123ReassemblyState *)carve_get_state(candidate->carvehashkey);
  if (!state || !state->skeleton_initialized) {
    // can't calculate size without metadata / skeleton
    file_123_free_carve_state((void **)&state);
    return 0;
  }


  uint64_t total_blocks = 1; // Start with header


  // add all section block counts
  for (int i = 0; i < 10; i++) {
    total_blocks += state->expected_blocks[i];
  }


  // add metadata and footer
  total_blocks += 1;
  total_blocks += 1;


  file_123_free_carve_state((void **)&state);
  return total_blocks;
}






// ============================================================================
// Main reassembly loop
// ============================================================================

// custom reassembly entry point for 123 files. Orchestrates the overall
// reassembly using the helpers above:
//
//   1. Initialize a new candidate (or resume a checkpointed one).
//   2. Locate holes in the candidate and fill them with blocks of the
//      type required by the metadata.
//   3. Validate partial fragments and entire files using the registered
//      file validator.
//   4. Write the candidate on full recovery, or abort if hopeless.




static void file_123_reassembly(ThreadWork      *work,
                        CarveInfo      **c,
                        uuid_string_t    uuidp,
                        uuid_string_t    uuidc){



  // variables initialization
  bool     validates     = false;
  uint64_t validates_to  = 0;
  uint32_t gallop_factor = 0;
  uint64_t tick          = 0;


  // print info
  if (scalpel_state.mode_verbose){
    lock_fprintf(stdout,
        "\nReassembly thread #%d starting on candidate %p  UUIDs\n%s / %s\n",
        work->id, (*c)->b, uuidp, uuidc);
  }


  // initialize candidate
  if (file_123_reassembly_init_candidate(work, c, uuidp, uuidc) || !*c) {
    return;
  }


  // main reassembly loop
  while (1){
    // progress dots for non-verbose (mimics LR)
    if (!scalpel_state.mode_verbose && (tick++ % 100000) == 0) {
      lock_fprintf(stdout, "%s.%s", BLUE, BLACK);
      fflush(stdout);
    }


    // if candidate has reached max size, break out of the loop
    if (reassembly_check_max_size(work->id, *c, uuidp, uuidc)) {
      lock_fprintf(stdout,
          "\nThread #%d reached max size on %s / %s; writing file\n",
          work->id, uuidp, uuidc);
      break;
    }



    // find the next hole
    int64_t hole_idx, start_ap;
    if (!file_123_reassembly_prepare_for_extension(*c, &hole_idx, &start_ap)) {
      // perform a final validation before breaking
      validates = file_123_validate_candidate(*c, &validates_to);
      break;
    }


    char target_type = file_123_block_type_for_slot(*c, hole_idx);


    // get a block that matches the expected type
    int64_t blk_ap = file_123_reassembly_get_block_choice(
                          work, c, &start_ap, hole_idx, target_type, uuidp, uuidc);
    if (blk_ap == FILE123_SCAN_YIELDED) {
      return;
    }



    if (blk_ap == -1) {
      destroy_candidate(c);
      return;
    }


    // place the block
    (*c)->newblock = filemirror_actual_blocknumber(
                          scalpel_state.filemirror, blk_ap);
    file_123_reassembly_extension_successful(work->id, *c, hole_idx);


    if (scalpel_state.mode_verbose){
      lock_fprintf(stdout,
        "Thread #%d placed apparent %" PRId64 " at slot %" PRId64 "\n",
        work->id, blk_ap, hole_idx);
    }



    // validate
    validates = file_123_validate_candidate(*c, &validates_to);
    if (validates){
      break;
    }



    // gallop
    int64_t hole_end = file_123_find_hole_end(*c, hole_idx);


    file_123_reassembly_gallop(work->id, *c,
                              hole_idx, hole_end,
                              &gallop_factor,
                              &validates_to, &validates);


    if (scalpel_state.mode_verbose){
      lock_fprintf(stdout,
        "Thread #%d gallop %s (factor=%u) up to byte %" PRIu64 "\n",
        work->id, validates ? "SUCCEEDED" : "failed",
        gallop_factor, validates_to);
    }


    if (validates){
      break;
    }


    // checkpointing
    if (reassembly_time_to_checkpoint(work->id, *c, uuidp, uuidc)) {
      lock_fprintf(stdout,
          "\nThread #%d checkpointing candidate %p  UUIDs\n%s / %s\n",
          work->id, (*c)->b, uuidp, uuidc);
      return;
    }
  }


  // exit paths
  if (validates) {
    (*c)->flavor = VALIDATED;
    lock_fprintf(stdout,
        "\nThread #%d VALIDATED candidate %p  UUIDs\n%s / %s\n",
        work->id, (*c)->b, uuidp, uuidc);




    uint64_t blocksize = scalpel_state.blocksize;
    uint64_t validated_blocks = (validates_to + blocksize - 1) / blocksize;
    resize_blockvector((*c)->b, validated_blocks);

    write_candidate(c, false);
  } else {
    lock_fprintf(stdout,
        "\nThread #%d abandoning candidate %p  UUIDs\n%s / %s\n",
        work->id, (*c)->b, uuidp, uuidc);
    if (scalpel_state.write_promising) {
      (*c)->flavor = PROMISING;
      file_123_resize_blockvector_to_expected(*c);
      write_candidate(c, false);
    } else {
      destroy_candidate(c);
      return;
    }
  }
}
