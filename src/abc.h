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

/**
 * @author Karley W.
 * @discussion
 *
 * This file contains functionality for various .abc file and block
 * validation. ".abc" is a simple, synthetic file type that serves to
 * illustrate how validators are constructed for scalpel3.
 *
 * ".abc" is an ASCII file type that follows this format:
 *
 * [BLOCK 1]     "[HEADER]AAAAAAAAAA..."
 * [BLOCK 2]     "BBBBBBBBBB..."
 * [BLOCK 3]     "CCCCCCCCCC..."
 * ...
 * [BLOCK 26]    "ZZZZZZZZZZ...[FOOTER]"
 *
 * where [HEADER] = "#0123456789#" and [FOOTER] = "#9876543210#"
 *
 * The file type will always be 26*blocksize long and filetypes of the
 * same block size are identical.
 *
 * Functions for the block validator and file validator are contained
 * in this file, then they are installed into scalpel3 by modifying
 * the "scalpelconf.c" file.
 *
 * Note: This file shows three ways that file/block validators can be
 * written:
 *
 *      [Example #1]: (abc_block_validate & abc_file_validate): This
 *      is the preferred method, if possible. This method uses a block
 *      validator capable of thoroughly and accurately validating
 *      blocks belonging to abc files. The block validator does the
 *      heavy lifting of ensuring the contents inside of the blocks
 *      are correct, then the file validator merely checks the
 *      arrangement of the blocks in the data. The drawback of this
 *      approach is that performing block validation can be extremely
 *      difficult or impossible for some file types.
 *
 *      [Example #2]: (abc_block_validate_alt and
 *      abc_file_validate_alt): This recipe is more appropriate when
 *      it isn't possible to accurately validate blocks of a
 *      particular file type. As a consequence, all (or most) blocks
 *      are automatically validated as potential candidates, and the
 *      file validator must exhaustively verify that the entire
 *      contents of a potential file are correct. This results in a
 *      more complex and monolithic file validator. Most of the
 *      existing validators work this way.
 *
 *      [Example #3]: (abc_block_validate [same as # 1] and
 *      abc_file_validate_mem): This example illustrates "restartable"
 *      file validation, where the validator remembers previously
 *      validated data through scalpel3's state API and tries to limit
 *      data revalidation efforts.  The key idea for restartable
 *      validation is to store enough state so that data validation
 *      can begin starting at the first new block, rather than at
 *      index 0.
 *
 *      ** Wherever possible, restartable file validators are preferred,
 *         as they can offer dramatically increased performance. **
 *
 * The scalpelconf.c entry for "abc" currently uses Example #2
 * (abc_block_validate_alt / abc_file_validate_alt).  To experiment
 * with the other examples, swap the .BLOCKVALIDATOR and
 * .FILEVALIDATOR fields in scalpelconf.c.  Example #3 also requires
 * the carve state API functions (see the comment block above
 * abc_file_validate_mem for the full list of fields to set).
 *
 **/

#include "scalpel.h"
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>

#define HEADER_SIZE 12
#define FOOTER_SIZE 12


// ====================================================================
// State structure for Example #3 (restartable file validation).
// Tracks how many complete blocks have been validated, so subsequent
// calls can skip already-checked data.
// ====================================================================
typedef struct {
    uint32_t blocks_validated;   // complete blocks validated so far (0-26)
} AbcRestartState;


// FUNCTION PROTOTYPES
static inline uint32_t abc_block_validate(char *data,
					  uint64_t length,
					  BlockValidationDecision *decision,
					  uint64_t *validates_to,
					  uint32_t needleidx,
					  uint32_t blocksize,
					  void *blockhashkey);

static inline void abc_file_validate(char *data,
				     uint64_t length,
				     bool *validates,
				     uint64_t *validates_to,
				     bool *promising,
				     uint32_t needleidx,
				     uint32_t blocksize,
				     void *carvehashkey);

static inline uint32_t abc_block_validate_alt(char *data,
					      uint64_t length,
					      BlockValidationDecision *decision,
					      uint64_t *validates_to,
					      uint32_t needleidx,
					      uint32_t blocksize,
					      void *blockhashkey);

static inline void abc_file_validate_alt(char *data,
					 uint64_t length,
					 bool *validates,
					 uint64_t *validates_to,
					 bool *promising,
					 uint32_t needleidx,
					 uint32_t blocksize,
					 void *carvehashkey);

static inline void abc_file_validate_mem(char *data,
					 uint64_t length,
					 bool *validates,
					 uint64_t *validates_to,
					 bool *promising,
					 uint32_t needleidx,
					 uint32_t blocksize,
					 void *carvehashkey);

// State API functions for Example #3 (restartable validation).
// These are required when using the carve state API; see scalpelconf.c
// for full documentation on each.
static inline bool abc_serialize_carve_state(void **state, FILE *fp,
					     StateSerialization mode);
static inline void *abc_clone_carve_state(const void *srcstate);
static inline void abc_free_carve_state(void **state);
static inline size_t abc_sizeof_carve_state(const void *state);
static inline void abc_print_carve_state(const void *state);


// FUNCTION DEFINITIONS

/**
 * @discussion          validates whether a block could belong to an abc file.
 *                      This is the thorough block validator (Example #1).
 *
 * @param data          pointer to the data block to be checked
 * @param length        length of the data block in bytes
 * @param decision      populated with BLOCK_CONFIDENCE_VALID or BLOCK_CONFIDENCE_INVALID
 * @param validates_to  set to the last valid byte offset within the block
 * @param needleidx     file type index in scalpelconf (returned unchanged)
 * @param blocksize     the block size of the image
 * @param blockhashkey  opaque key for block state API (unused in this example)
 * @return              needleidx (unchanged)
 */
static inline uint32_t abc_block_validate(char *data,
					  uint64_t length,
					  BlockValidationDecision *decision,
					  uint64_t *validates_to,
					  uint32_t needleidx,
					  uint32_t blocksize,
					  void *blockhashkey) {

  (void)blocksize;
  (void)blockhashkey;

  *decision = BLOCK_CONFIDENCE_VALID;
  *validates_to = length - 1;

  // look at the first character; is it an uppercase alphabetic char
  // (excluding A or Z)?
  if (isalpha(data[0]) && isupper(data[0]) && data[0] != 'A' && data[0] != 'Z') {
    //next check: get ascii val and see all data in block is of this
    //value
    char val = data[0];
    for (uint64_t i = 1; i < length; i++) {
      // if any entry is not of that character, block is invalid
      if (data[i] != val) {
	*decision = BLOCK_CONFIDENCE_INVALID;
	break;
      }
    }
  }
  else if (length >= HEADER_SIZE && memcmp("#0123456789#", data, HEADER_SIZE) == 0) {
    // then we have a header. Characters should be 'A'
    for (uint64_t i = HEADER_SIZE; i < length; i++) {
      if (data[i] != 'A') {
	*decision = BLOCK_CONFIDENCE_INVALID;
	break;
      }
    }
  }
  else if (length >= FOOTER_SIZE &&
	   memcmp("#9876543210#",
		  &data[length - FOOTER_SIZE], FOOTER_SIZE) == 0) {
    // this would be a footer. Characters before it should be 'Z'
    for (uint64_t i = 0; i < length - FOOTER_SIZE; i++) {
      if (data[i] != 'Z') {
	*decision = BLOCK_CONFIDENCE_INVALID;
	break;
      }
    }
  }
  else{
    // if first byte of block is not uppercase letter, header, or
    // footer, block is not valid
    *decision = BLOCK_CONFIDENCE_INVALID;
  }

  return needleidx;

}


/**
 * @discussion          validates whether data forms a valid abc file (or a
 *                      promising partial file).  This is the Example #1 file
 *                      validator, which assumes the block validator has already
 *                      eliminated invalid blocks.  As a result, this function
 *                      only checks the first byte of each block to verify
 *                      correct ordering.
 *
 * @param data          pointer to the concatenated block data
 * @param length        total length of the data in bytes
 * @param validates     set to true if a complete, valid file is present
 * @param validates_to  last byte offset that validated successfully
 * @param promising     set to true if data is a promising partial file
 * @param needleidx     file type index in scalpelconf (unused)
 * @param blocksize     the block size of the image
 * @param carvehashkey  opaque key for carve state API (unused in this example)
 */
static inline void abc_file_validate(char *data,
				     uint64_t length,
				     bool *validates,
				     uint64_t *validates_to,
				     bool *promising,
				     uint32_t needleidx,
				     uint32_t blocksize,
				     void *carvehashkey) {

  (void)needleidx;
  (void)carvehashkey;

  // The first 12 bytes should be the header
  if (length < HEADER_SIZE || memcmp("#0123456789#", data, HEADER_SIZE) != 0) {
    *validates = false;
    *promising = false;
    *validates_to = 0;
    return;
  }

  // The character in the first block after the header should be 'A'
  if (length < HEADER_SIZE + 1 || data[HEADER_SIZE] != 'A') {
    *validates = false;
    *promising = true;
    *validates_to = HEADER_SIZE - 1;
    return;
  }

  // Check that subsequent blocks contain B-Y in order (blocks 1-25).
  // Because the block validator already checked byte-level content,
  // we only need to verify the first byte of each block.
  char expected = 'B';
  uint64_t i = blocksize;
  while (i / blocksize <= 25 && i < length) {
    if (data[i] != expected) {
      *validates = false;
      *promising = true;
      *validates_to = i - 1;
      return;
    }
    i += blocksize;
    expected += 1;
  }

  if (length >= 26 * (uint64_t)blocksize) {
    // Complete file
    *validates = true;
    *promising = false;
    *validates_to = 26 * (uint64_t)blocksize - 1;
    return;
  }

  // Partial file — promising fragment.
  // i points to the start of the next block we would have checked,
  // so the last validated byte is i - 1.
  *validates = false;
  *promising = true;
  *validates_to = i - 1;
  return;
}


/**
 * @discussion          Permissive block validator (Example #2).  Marks every
 *                      block as VALID so that all blocks are candidates.  Use
 *                      this style when it is not possible to validate individual
 *                      blocks with a high degree of accuracy; the file validator
 *                      must then do all the heavy lifting.
 *
 * @param data          pointer to the data block to be checked
 * @param length        length of the data block in bytes
 * @param decision      populated with BLOCK_CONFIDENCE_VALID (always)
 * @param validates_to  set to length - 1
 * @param needleidx     file type index in scalpelconf (returned unchanged)
 * @param blocksize     the block size of the image (unused)
 * @param blockhashkey  opaque key for block state API (unused)
 * @return              needleidx (unchanged)
 */
static inline uint32_t abc_block_validate_alt(char *data,
					      uint64_t length,
					      BlockValidationDecision *decision,
					      uint64_t *validates_to,
					      uint32_t needleidx,
					      uint32_t blocksize,
					      void *blockhashkey) {

  (void)data;
  (void)blocksize;
  (void)blockhashkey;

  *decision = BLOCK_CONFIDENCE_VALID;
  *validates_to = length - 1;
  return needleidx;

}


/**
 * @discussion          Exhaustive file validator (Example #2).  Because the
 *                      block validator (abc_block_validate_alt) accepts every
 *                      block, this function must check every byte of every
 *                      block to verify a valid abc file.
 *
 * @param data          pointer to the concatenated block data
 * @param length        total length of the data in bytes
 * @param validates     set to true if a complete, valid file is present
 * @param validates_to  last byte offset that validated successfully
 * @param promising     set to true if data is a promising partial file
 * @param needleidx     file type index in scalpelconf (unused)
 * @param blocksize     the block size of the image
 * @param carvehashkey  opaque key for carve state API (unused in this example)
 */
static inline void abc_file_validate_alt(char *data,
					 uint64_t length,
					 bool *validates,
					 uint64_t *validates_to,
					 bool *promising,
					 uint32_t needleidx,
					 uint32_t blocksize,
					 void *carvehashkey) {

  (void)needleidx;
  (void)carvehashkey;

  //the first 12 bytes should be the header
  if (length < HEADER_SIZE || memcmp("#0123456789#", data, HEADER_SIZE) != 0) {
    //if failed to find, return
    *validates = false;
    *promising = false;
    *validates_to = 0;
    return;
  }
  // all other bytes in 1st block should be 'A'
  for (uint64_t k = HEADER_SIZE; k < blocksize && k < length; k++) {
    if (data[k] != 'A') {
      *validates = false;
      *promising = true;
      *validates_to = k - 1;
      return;
    }
  }

  // the next blocks should be arranged in alphabetical order
  char expected = 'B';
  // loops to start of each block B-Y
  uint64_t i = 0;
  for (i = blocksize; i/blocksize <=24 && i < length; i += blocksize) {
    // loops through contents of each block
    for (uint32_t j = i; j < i + blocksize && j < length; j++) {
      if (data[j] != expected) {
	*validates = false;
	*promising = true;
	*validates_to = j - 1;
	return;
      }
    }
    expected += 1;
  }

  // check how many blocks there are. If this file type is complete,
  // there will be 26 or more blocks
  if (length >= 26 * (uint64_t)blocksize) {
    // check for Z characters
    for (uint64_t k = 25 * (uint64_t)blocksize; k < 26 * (uint64_t)blocksize - FOOTER_SIZE; k++) {
      if (data[k] != 'Z') {
	*validates = false;
	*promising = true;
	// validates up to previous byte
	*validates_to = k - 1;
	return;
      }
    }
    // then check for footer
    if (memcmp("#9876543210#", &data[26 * (uint64_t)blocksize - FOOTER_SIZE], FOOTER_SIZE) != 0) {
      // if failed to find, return
      *validates = false;
      *promising = true;
      *validates_to = 26 * (uint64_t)blocksize - FOOTER_SIZE - 1;
      return;
    }
    else{
      // in this case, footer was found, so mark valid
      *validates = true;
      *promising = false;
      *validates_to = 26 * (uint64_t)blocksize - 1;
      return;
    }
  }
  else {
    // Partial file.  The inner loop above validated all bytes within
    // blocks 1-24 (B through Y) up to 'length'.  If the data extends
    // into block 25 (the Z section, starting at offset 25*blocksize),
    // those bytes have not been checked yet because the outer loop
    // exits at block 24.
    uint64_t z_start = 25 * (uint64_t)blocksize;
    if (length > z_start) {
      for (uint64_t k = z_start; k < length; k++) {
	if (data[k] != 'Z') {
	  *validates = false;
	  *promising = true;
	  *validates_to = k - 1;
	  return;
	}
      }
    }
    *validates = false;
    *promising = true;
    *validates_to = length - 1;
    return;
  }
}


// ====================================================================
// EXAMPLE #3: RESTARTABLE FILE VALIDATION (abc_file_validate_mem)
// ====================================================================
//
// This example uses the carve state API to remember how far validation
// has progressed across calls.  On each invocation, the validator:
//
//   1. Retrieves saved state via carve_get_state() (returns a deep copy).
//   2. Detects blockvector truncation and rolls back state if needed.
//   3. Resumes byte-level validation from where the previous call stopped.
//   4. Saves updated state via carve_put_state() (stores a deep copy).
//   5. Frees the local copy of state.
//
// For file types with expensive validation, this avoids redundant work
// during reassembly.  The block validator (abc_block_validate, Example #1)
// handles individual block checks; this validator focuses on the
// sequential arrangement of blocks within a candidate file.
//
// IMPORTANT: The blockvector can be truncated between calls, making
// previously validated regions invalid.  The validator detects this by
// comparing the current data length against the saved progress and
// adjusts state accordingly.
//
// To wire up this validator, set the following fields in scalpelconf.c:
//
//   .FILEVALIDATOR           = abc_file_validate_mem,
//   .SERIALIZECARVESTATEFUNC = abc_serialize_carve_state,
//   .CLONECARVESTATEFUNC     = abc_clone_carve_state,
//   .FREECARVESTATEFUNC      = abc_free_carve_state,
//   .SIZEOFCARVESTATEFUNC    = abc_sizeof_carve_state,
//   .PRINTCARVESTATEFUNC     = abc_print_carve_state,
//

/**
 * @discussion          Restartable file validator for abc files.
 *                      Uses the carve state API to skip previously
 *                      validated blocks.
 */
static inline void abc_file_validate_mem(char *data,
					 uint64_t length,
					 bool *validates,
					 uint64_t *validates_to,
					 bool *promising,
					 uint32_t needleidx,
					 uint32_t blocksize,
					 void *carvehashkey) {
  (void)needleidx;

  // 1. Retrieve saved state (deep copy — must be freed when done)
  AbcRestartState *state = (AbcRestartState *)carve_get_state(carvehashkey);

  // First call: no state yet — allocate and initialize
  if (!state) {
    state = (AbcRestartState *)calloc(1, sizeof(AbcRestartState));
    check_memory_allocation(state, __LINE__, __FILE__, "AbcRestartState");
    state->blocks_validated = 0;
  }

  // 2. Detect truncation: if the data is now shorter than what we
  //    previously validated, roll back to the last complete block
  //    within the current data.
  if (state->blocks_validated > 0 &&
      length < (uint64_t)state->blocks_validated * blocksize) {
    state->blocks_validated = (uint32_t)(length / blocksize);
  }

  uint32_t start_block = state->blocks_validated;

  // 3. Validate from where we left off.

  // --- Header block (block 0): #0123456789# followed by 'A' fill ---
  if (start_block == 0) {
    if (length < HEADER_SIZE ||
	memcmp("#0123456789#", data, HEADER_SIZE) != 0) {
      *validates = false;
      *promising = false;
      *validates_to = 0;
      state->blocks_validated = 0;
      carve_put_state(carvehashkey, state);
      abc_free_carve_state((void **)&state);
      return;
    }
    for (uint64_t i = HEADER_SIZE; i < blocksize && i < length; i++) {
      if (data[i] != 'A') {
	*validates = false;
	*promising = true;
	*validates_to = i - 1;
	state->blocks_validated = 0;
	carve_put_state(carvehashkey, state);
	abc_free_carve_state((void **)&state);
	return;
      }
    }
    start_block = 1;
  }

  // --- Interior blocks 1-24 (characters B-Y) ---
  char expected = (char)('A' + start_block);
  for (uint32_t blk = start_block; blk < 25 &&
	 (uint64_t)blk * blocksize < length; blk++) {
    uint64_t blk_start = (uint64_t)blk * blocksize;
    uint64_t blk_end = blk_start + blocksize;
    if (blk_end > length) {
      blk_end = length;
    }
    for (uint64_t i = blk_start; i < blk_end; i++) {
      if (data[i] != expected) {
	*validates = false;
	*promising = true;
	*validates_to = i - 1;
	state->blocks_validated = blk;
	carve_put_state(carvehashkey, state);
	abc_free_carve_state((void **)&state);
	return;
      }
    }
    expected++;
    start_block = blk + 1;
  }

  // --- Final block 25 (Z fill + footer) ---
  if (length >= 26 * (uint64_t)blocksize) {
    uint64_t z_start = 25 * (uint64_t)blocksize;
    uint64_t z_end = 26 * (uint64_t)blocksize;

    for (uint64_t i = z_start; i < z_end - FOOTER_SIZE; i++) {
      if (data[i] != 'Z') {
	*validates = false;
	*promising = true;
	*validates_to = i - 1;
	state->blocks_validated = 25;
	carve_put_state(carvehashkey, state);
	abc_free_carve_state((void **)&state);
	return;
      }
    }
    if (memcmp("#9876543210#", &data[z_end - FOOTER_SIZE], FOOTER_SIZE) != 0) {
      *validates = false;
      *promising = true;
      *validates_to = z_end - FOOTER_SIZE - 1;
      state->blocks_validated = 25;
      carve_put_state(carvehashkey, state);
      abc_free_carve_state((void **)&state);
      return;
    }

    // Full file validated
    *validates = true;
    *promising = false;
    *validates_to = 26 * (uint64_t)blocksize - 1;
    state->blocks_validated = 26;
    carve_put_state(carvehashkey, state);
    abc_free_carve_state((void **)&state);
    return;
  }

  // Partial file — promising fragment
  *validates = false;
  *promising = true;
  *validates_to = length - 1;
  state->blocks_validated = start_block;
  carve_put_state(carvehashkey, state);
  abc_free_carve_state((void **)&state);
}


// ====================================================================
// STATE API FUNCTIONS FOR EXAMPLE #3
// ====================================================================
//
// These functions tell scalpel3 how to serialize, clone, free, size,
// and display the AbcRestartState structure.  They are required
// whenever the carve state API (carve_get_state / carve_put_state)
// is used.  See scalpelconf.c for full documentation on each.
//
// Because AbcRestartState contains only fixed-size fields (no
// pointers), the implementations are straightforward.  For a more
// complex example with dynamic data, see gif.h.

static inline bool abc_serialize_carve_state(void **state, FILE *fp,
					     StateSerialization mode) {
  AbcRestartState **s = (AbcRestartState **)state;

  size_t (*fb)(void *ptr, size_t size, size_t nitems, FILE *stream) =
    mode == SERIALIZE ?
    (size_t (*)(void *, size_t, size_t, FILE *))fwrite :
    (size_t (*)(void *, size_t, size_t, FILE *))fread;

  if (mode == DESERIALIZE) {
    *s = (AbcRestartState *)malloc(sizeof(AbcRestartState));
    check_memory_allocation(*s, __LINE__, __FILE__, "AbcRestartState");
  }

  if (fb(&((*s)->blocks_validated), sizeof(uint32_t), 1, fp) != 1) {
    perror("abc_serialize_carve_state");
    handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
  }
  return true;
}

static inline void *abc_clone_carve_state(const void *srcstate) {
  const AbcRestartState *s = (const AbcRestartState *)srcstate;
  AbcRestartState *d = (AbcRestartState *)malloc(sizeof(AbcRestartState));
  check_memory_allocation(d, __LINE__, __FILE__, "AbcRestartState clone");
  memcpy(d, s, sizeof(AbcRestartState));
  return d;
}

static inline void abc_free_carve_state(void **state) {
  AbcRestartState **s = (AbcRestartState **)state;
  if (*s) {
    free(*s);
    *s = NULL;
  }
}

// SIZEOFCARVESTATEFUNC: because AbcRestartState is plain-old-data with
// no internal pointers, memcpy produces a correct deep clone.  Defining
// this function lets scalpel3 use a fast memcpy path instead of calling
// abc_clone_carve_state.
static inline size_t abc_sizeof_carve_state(const void *state) {
  (void)state;
  return sizeof(AbcRestartState);
}

static inline void abc_print_carve_state(const void *state) {
  const AbcRestartState *s = (const AbcRestartState *)state;
  if (!s) {
    printf("NULL\n");
  } else {
    printf("blocks_validated: %u\n", s->blocks_validated);
  }
}



