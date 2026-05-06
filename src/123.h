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


/*
 Author: Karley W.


 Based on the template for custom reassembly threads by
 Golden G. Richard III.


------------------------------------------------------------------------------
  INTRODUCTION:
------------------------------------------------------------------------------


 This is an example validator which illustrates how to use
 custom reassembly threads and state to handle reassembly
 of more complex file types that cannot be handled in a left-to-right
 fashion. It is inspired by the structure present in ELF file types.
 Since this is a reference implmentation, it is very heavily commented.


 The 123 file type consists of blocks of numbers. A 0-block is a block that
 contains all 0's, a 1-block is a block that contains all 1's, etc. In the
 file, these blocks appear in ascending order, and the highest numerical
 value is a 9-block. This file type has a header block (#HEADER# + 8-char file ID) and
 footer block (#FOOTER#), which are padded with dashes to the block size
 to help keep this example simple.  The 8-character hex file ID appears
 in both the header and metadata blocks, tying them together so the
 reassembler can match the correct metadata to its header when multiple
 123 files coexist in an image.


 Each of the blocks in these files types are grouped into sections according
 to what number resides in the block. For example, all 0-blocks reside in the
 0-section at the beginning of the file, and all 9-blocks reside in the
 9-section at the end of the file. Similar logic applies to the intermediate
 sections.


 There is a metadata block which appears after the 9-block section.
 This metadata describes each of the sections (0-9), their start offset
 in the file, and their size in the file. Describing size information is
 necessary because sections in this file type can have more than one block
 associated with them (their size is not simply fixed to the block size).


 To help with identifying and parsing this metadata, there is a signature
 (#METADATA#) followed by the same 8-char file ID from the header, which
 appears at the beginning of the structure. After the structure,
 this block is padded with dashes to the blocksize for simplicity in
 identifying these blocks. Since the structure appears at the end of the file,
 the footer block (#FOOTER# padded with dashes) will appear after this structure.
 More detailed info and diagrams describing this file type can be found in the docs.


 These files can be generated using the generate-123-file.py script.


 The custom reassembly thread works on fragmented files of this type. The block
 validator identifies 123 blocks and ties state to them based on the type. The reassembly
 thread then polls this information throughout reassembly to accurately place blocks.
 There is an additional mechanism for storing file state which is able to track a "skeleton"
 of the file. This is used to track what blocks have been placed so far, and once all
 components in the skeleton are placed, this triggers validation and writing of the file.


 Further comments about how this example works can be found throughout the code.


*/


/*


------------------------------------------------------------------------------
  ADDITIONAL NOTES REGARDING STATE:
------------------------------------------------------------------------------
    State API is documented in scalpelconf.c.
    These are the functions that you must write if you use state for a file type.
    They tell scalpel how to serialize, clone, free, and optionally print states.
    Additional working examples of these state functions
    can be found in gif.h. This example shows a simple case where all fields
    in the struct are static. The gif example shows how to work with dynamic
    data, where extra care must be taken when allocating, freeing, and serializing
    the fields.


    On the other hand, the functions that you use to interact with state
    (get state, put state, etc) can be found in scalpel.h.


    They include:
      void *carve_get_state(void *hashkey);
      void carve_put_state(void *hashkey, void *state);
      void *block_get_state(void *hashkey);
      void block_put_state(void *hashkey, void *state);


    When using block and file validators, you can pass the blockhashkey and
    carvehash key respectively to these functions to poll information about
    the state or change the state.


    However, note that during reassembly, the blockhashkey becomes inactive
    to conserve memory. Therefore, to poll block state during reassembly, you must
    use the function gen_block_hash_key() to calculate the blockhashkey on the fly.
    This function is defined in util.c.


    gen_block_hash_key() was modified so that it always returns the exemplar
    block number. This is important since state is not stored for duplicate
    blocks (only the exemplar).


    Meanwhile, the carve state can be accessed during reassembly using the
    carvehashkey that is present inside of the CarveInfo struct. This
    structure is readily available throughout the reassembly process
    (see example reassembly functions towards the bottom of this file).
*/




/*
------------------------------------------------------------------------------
  FILE VALIDATORS VS CUSTOM REASSEMBLY:
------------------------------------------------------------------------------
    Scalpel internals require that every file type has a block validator and
    File validator. The file validator is necessary for the contiguous recovery
    phase which will work in a left-to-right fashion. In the case that a file type
    does not use a custom reassembly thread, the file validator is also used in the
    fragmented reassembly phase using the left-to-right reassembly logic that is
    already coded in scalpel.


    When there is a custom reassembly thread, there are one of two possibilities.
        (1) the file validator can be recycled and called in the reassembly thread.
        (2) the reassembly thread can use new (custom) logic separate from the
        file validator


------------------------------------------------------------------------------
OPTION 1: Reuse the file_validate() function inside the reassembly thread
------------------------------------------------------------------------------


Use this approach when:


  - The file structure is rigid and deterministic
  - Blocks have a clear, unique location based on metadata or position
  - Section/component boundaries align cleanly with blocks
  - Full-file validation is possible by scanning the buffer sequentially
  - Partial file validation is possible by scanning the placed content from the header
  - It is safe to truncate or roll-back at an invalid byte offset (via validates_to)


------------------------------------------------------------------------------
OPTION 2: Use fully custom validation logic in your reassembly thread
------------------------------------------------------------------------------


Use this approach when:


  - Section boundaries could fall within blocks or be ambiguous
  - Blocks must be validated independently, or partially accepted/rejected,
    rather than in sequential chunks
  - Byte-level validation or offset tracking is required
  - Block placement depends on structure or content that can't be validated
    via file_validate(). For example, perhaps you need to validate or roll
    back ranges of blocks in a way that default LR file_validate doesn't support.
  - You need thresholds or best-effort matching logic to model good decisions or
    guesses.


In these more complex cases, the reassembly thread should implement its own
validation logic, since the standard file_validate() will not be expressive enough.


Note: file_validate() will still be used during the contiguous carving phase.
You only override behavior during fragmented recovery.


------------------------------------------------------------------------------
WHY THIS FILE TYPE (123) USES OPTION 1
------------------------------------------------------------------------------


The 123 file format is ideal for Option 1 because:


  - The file has strict structure: a header, 10 sequential sections, metadata,
    and a footer — each block has a well-defined location.
  - The metadata explicitly defines the size and layout of all sections.
  - Blocks do not vary in interpretation, and layout is deterministic.
  - Block formatting is consistent and not file-specific. For example, all
    1-blocks are the same, 2-blocks are the same, etc. No complex picking logic,
    choice tracking, or backtracking logic is required.
  - The file can be validated entirely by scanning its buffer from start to end
    during reassembly, since it's largely reconstructed from left-to-right,
    with some custom logic in place for initializing candidates and selecting
    metadata.
  - The `validates_to` mechanism works safely, since the reassembly process is linear.


As a result, this implementation reuses file_123_file_validate() inside the
reassembly thread during fragmented recovery. This keeps the reassembly logic
simple, fast, and easier to understand, while demonstrating how to implement
custom reassembly logic and state to more intentionally guide reassembly
efforts.


*/


#include "scalpel.h"
#include <stdint.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>


#define HEADER_SIGNATURE_123 "#HEADER#"
#define FOOTER_SIGNATURE_123 "#FOOTER#"
#define METADATA_SIGNATURE_123 "#METADATA#"


#define HEADER_SIZE_123 8
#define FOOTER_SIZE_123 8
#define METADATA_SIZE_123 10
#define FILE_ID_SIZE_123 8


// Uncomment to enable debugging of the custom reassembly functions.
// #define FILE_123_REASSEMBLY_DEBUG


/***************************************************************/
/*                   STATE STRUCTURES                          */
/***************************************************************/


/*
    Block state in this example is a single character
    identifying the block type ('0'-'9', 'h', 'f', or 'm').
*/
typedef struct {
    char value;
} CharBlockState;




/*
    Structure that serves as the carving state.
    It consists of three boolean values that indicate whether the
    metadata, header, and footer have been placed yet.


    There are also two arrays: one for tracking the expected blocks within
    sections and another for tracking recovered blocks.
    These values combined help track the reassembly progress for
    fragmented files.


    The boolean skeleton_initialized tracks whether this
    struct has been initialized with information from the 123 file metadata.


    This state is not used for contiguous recovery and only
    becomes relevant in the custom reassembly thread.
*/
typedef struct {
    bool header_placed;
    bool metadata_placed;
    bool footer_placed;


    // total expected blocks for each section (from metadata)
    uint8_t expected_blocks[10];


    // current # of blocks recovered for each section
    uint8_t recovered_blocks[10];


    // once metadata is parsed, this is set to true
    bool skeleton_initialized;


} File123ReassemblyState;


// FUNCTION PROTOTYPES

/* block validator and file validator */
static inline uint32_t file_123_block_validate(char *data,
                                        uint64_t length,
                                        BlockValidationDecision *decision,
                                        uint64_t *validates_to,
                                        uint32_t needleidx,
                                        uint32_t blocksize,
                                        void *blockhashkey);


/* file validator signature */
static inline void file_123_file_validate(char *data,
                                    uint64_t length,
                                    bool *validates,
                                    uint64_t *validates_to,
                                    bool *promising,
                                    uint32_t needleidx,
                                    uint32_t blocksize,
                                    void *carvehashkey);
static bool file_123_file_validate_full(CarveInfo *cand,
                                        uint64_t *validates_to);

/* block state API */
static inline bool char_serialize_block_state(void **state, FILE *fp,
                                              StateSerialization mode);
static inline void *char_clone_block_state(const void *srcstate);
static inline void char_free_block_state(void **state);
static inline size_t char_sizeof_block_state(const void *state);
static inline void char_print_block_state(const void *state);

/* carve state API */
static inline bool file123_serialize_carve_state(void **state, FILE *fp,
                                                 StateSerialization mode);
static inline void *file123_clone_carve_state(const void *srcstate);
static inline void file123_free_carve_state(void **state);
static inline size_t file123_sizeof_carve_state(const void *state);
static inline void file123_print_carve_state(const void *state);

/* custom reassembly */
static void File123_reassembly_init_candidate(int id,
                                              CarveInfo **candidate,
                                              uuid_string_t uuidp,
                                              uuid_string_t uuidc);
bool File123_reassembly_prepare_for_extension(CarveInfo *cand,
                                              int64_t *hole_idx,
                                              int64_t *start_ap);
static int64_t File123_reassembly_get_block_choice(CarveInfo *candidate,
                                                   int64_t *block_choice_start,
                                                   int64_t logical_slot_index,
                                                   char target_type);
static int64_t File123_find_reusable_section_block(CarveInfo *candidate,
                                                   char target_type);
static void File123_reassembly_extension_successful(int id,
                                                    CarveInfo *candidate,
                                                    int64_t logical_slot_index);
static void File123_reassembly_gallop(int id,
                                      CarveInfo *candidate,
                                      int64_t start_index,
                                      int64_t end_index,
                                      uint32_t *gallop,
                                      uint64_t *validates_to,
                                      bool *validates);
void File123_reassembly(ThreadWork *work, CarveInfo **c,
                        uuid_string_t uuidp, uuid_string_t uuidc);

/* reassembly helpers */
void file123_resize_blockvector_to_expected(CarveInfo *cand);
static int slot_to_section(const File123ReassemblyState *st,
                           uint64_t num_blocks,
                           int64_t slot);
uint64_t calculate_file_size_from_metadata(CarveInfo *candidate);
void place_metadata_block(CarveInfo *candidate,
                          int64_t apparent_blocknum);
uint8_t *get_metadata_block_data(int64_t actual_blocknum);
bool validate_metadata_block(CarveInfo *candidate,
                             int64_t metadata_block);
int64_t find_valid_metadata_block(CarveInfo *candidate);
static int64_t find_hole_end(CarveInfo *cand,
                             uint64_t start);
static char block_type_for_slot(CarveInfo *cand,
                                uint64_t slot);
char *blockvector_to_buffer_range(BlockVector *bv,
                                  int64_t start_idx,
                                  int64_t end_idx);

/***************************************************************/
/*              BLOCK VALIDATOR IMPLEMENTATION                 */
/***************************************************************/


/**
 * @discussion          validates whether a block could belong to a 123 file
 *
 * @param  data             pointer to the data block to be checked
 * @param  length           length of the data block
 * @param  decision         pointer to the decision result; either VALID or INVALID
 * @param  validates_to     used in the case that the block validates partially up to an offset
 * @param  needleidx        file type in scalpelconf
 * @param  blocksize        size of each block in the image
 * @param  blockhashkey     used to set information about state
 */
static inline uint32_t file_123_block_validate(char *data,
                                          uint64_t length,
                                          BlockValidationDecision *decision,
                                          uint64_t *validates_to,
                                          uint32_t needleidx,
                                          uint32_t blocksize,
                                          void *blockhashkey){
  (void)blocksize;




  #ifdef FILE_123_REASSEMBLY_DEBUG
    lock_fprintf(stdout, "[block-validate] Called for block of length %" PRIu64 " (needleidx=%u)\n",
             length, needleidx);
  #endif


  // initialize the decision to VALID; then disqualify if any mismatch
  *decision = BLOCK_CONFIDENCE_VALID;
  *validates_to = length - 1;


  //initial state of an unknown block
  char state = '?';


  //Check for a header block (#HEADER# + 8-char file ID + '-' padding)
  if (memcmp(HEADER_SIGNATURE_123, data, HEADER_SIZE_123) == 0){
    // Ensure bytes after signature + file ID are '-'
    for (uint64_t i = HEADER_SIZE_123 + FILE_ID_SIZE_123; i < length; i++) {
      if (data[i] != '-') {
        *decision = BLOCK_CONFIDENCE_INVALID;
        break;
      }
    }
    //state corresponding to a header block
    state = 'h';
  }
  //Check for a footer block (#FOOTER# plus '-' padding)
  else if (memcmp(FOOTER_SIGNATURE_123, data, FOOTER_SIZE_123) == 0){
    // Ensure remainder is '-'
    for (uint64_t i = FOOTER_SIZE_123; i < length; i++) {
      if (data[i] != '-') {
        *decision = BLOCK_CONFIDENCE_INVALID;
        break;
      }
    }
    //state corresponding to a footer block
    state = 'f';
  }
  // Check for an n-block (0–9)
  //    The first character indicates the digit, all block chars must match
  else if (isdigit(data[0])) {
    char expected_digit = data[0];
    for (uint64_t i = 1; i < length; i++) {
      if (data[i] != expected_digit) {
        *decision = BLOCK_CONFIDENCE_INVALID;
        break;
      }
    }
    //state corresponding to an n-block
    state = expected_digit;
  }
  //Check for a metadata block (#METADATA# + 8-char file ID + records)
  //    Then parse possible records of length 17 bytes (type=1, offset=8, size=8)
  else if (memcmp(METADATA_SIGNATURE_123, data, METADATA_SIZE_123) == 0){
    // We expect the signature, an 8-char file ID, and exactly 10 records
    // of 17 bytes each => 10 + 8 + 170 = 188 bytes of structured data.
    uint64_t position = METADATA_SIZE_123 + FILE_ID_SIZE_123;
    uint64_t record_count = 0;
    const uint64_t total_metadata_bytes = METADATA_SIZE_123 + FILE_ID_SIZE_123 + (10 * 17);


    // 1. Do we have at least enough space for 10 records
    if (length < total_metadata_bytes) {
      *decision = BLOCK_CONFIDENCE_INVALID;
      return needleidx;
    }


    // 2. For each of the 10 records
    for (record_count = 0; record_count < 10; record_count++) {
      char section_type = data[position];
      // The first char in each record must be 0–9 since it describes section type
      if (section_type < '0' || section_type > '9') {
          *decision = BLOCK_CONFIDENCE_INVALID;
          return needleidx;
      }
      // Move to the next record & perform check for all 17 records
      position += 17;
    }


    // 3. After 10 records, ensure the remaining bytes are dashes
    for (uint64_t i = total_metadata_bytes; i < length; i++) {
      if (data[i] != '-') {
          *decision = BLOCK_CONFIDENCE_INVALID;
          return needleidx;
      }
    }
    //state corresponding to metadata block
    state = 'm';
  // If all checks pass, the decision stays VALID.
  } else {
    // If it matches none of the known patterns, it's an invalid 123 block
    *decision = BLOCK_CONFIDENCE_INVALID;
  }
  // Set block state for valid blocks so the reassembly thread can
  // identify block types later.
  if (*decision == BLOCK_CONFIDENCE_VALID) {


    if (blockhashkey == NULL) {
      lock_fprintf(stderr, "[debug] VALID 123 block seen but blockhashkey is NULL\n");
    } else {


      // create the block state struct
      CharBlockState blk_state = {
        .value = state,
      };


      //only put the state if we have a valid 123 block
      if(state != '?'){
        block_put_state(blockhashkey, &blk_state);


        // print debug info
        #ifdef FILE_123_REASSEMBLY_DEBUG
        // Confirm it was actually stored
        CharBlockState *check = (CharBlockState *)block_get_state(blockhashkey);
        if (check) {
          lock_fprintf(stdout,
            "[block-validate] Stored state = '%c' retrieved successfully (needleidx=%u)\n",
            check->value, needleidx);
          char_free_block_state((void **)&check);
        } else {
          lock_fprintf(stdout,
            "[block-validate] ERROR: block state appears to be NULL after storing (needleidx=%u)\n",
            needleidx);
        }
        fflush(stdout);
        #endif
      }
    }
  }
  //block validators return the needleidx
  return needleidx;
}




/***************************************************************/
/*               FILE VALIDATOR IMPLEMENTATION                 */
/***************************************************************/


/**
 * @discussion              validates whether some data is a valid 123
 *                          file (or partially valid).
 *
 *
 * @param  data             pointer to the data (all concatenated blocks)
 * @param  length           total length of the data
 * @param  validates        describes if data is fully valid
 * @param  validates_to     describes to what offset data is valid
 * @param  promising        indicates whether data is partially valid
 * @param  needleidx        file type index in scalpelconf
 * @param  blocksize        size of each block in the image
 * @param  carvehashkey     for setting file state
 */
static inline void file_123_file_validate(char *data,
                                        uint64_t length,
                                        bool *validates,
                                        uint64_t *validates_to,
                                        bool *promising,
                                        uint32_t needleidx,
                                        uint32_t blocksize,
                                        void *carvehashkey){
  (void)needleidx;
  (void)carvehashkey;
  // Notes:
  // Since we already checked blocks in the block validation phase,
  // we do not need to exhaustively check contents for padding and
  // other information. Instead, this file validator "polls" basic
  // identifying information (signatures, etc.) about the blocks and
  // moves on if the expected data is found near the beginning of the
  // block.


  // The first 8 bytes should be the header signature, followed by an
  // 8-character file ID.
  if (length < HEADER_SIZE_123 + FILE_ID_SIZE_123 ||
      memcmp(HEADER_SIGNATURE_123, data, HEADER_SIZE_123) != 0) {
    // no header, return
    *validates = false;
    *promising = false;
    *validates_to = 0;
    return;
  }

  // Save the file ID from the header for later comparison with metadata
  char header_file_id[FILE_ID_SIZE_123];
  memcpy(header_file_id, &data[HEADER_SIZE_123], FILE_ID_SIZE_123);


  // current_digit will track which digit we are in ('0'..'9')
  char current_digit = '0';


  // Start polling blocks at multiples of blocksize,
  uint64_t curr_offset = blocksize;


  // If we don't even have a full first data block, it's a partial fragment
  if (curr_offset >= length) {
    *validates = false;
    *promising = true;
    *validates_to = length - 1;
    return;
  }


  //It is required that the first n-block be a 0-block
  if (data[curr_offset] != '0') {
    *validates = false;
    *promising = true;
    *validates_to = curr_offset - 1;
    return;
  }


  //Now check the remainder of the blocks
  while (curr_offset < length) {
    char c = data[curr_offset];


    // The below checks will keep advancing curr_offset, checking
    // for ascending n-blocks which are strictly one higher until we
    // get to an invalid sequence. Once we get an invalid sequence,
    // we will break out of this loop for further analysis


    // Same digit => we remain in the same digit section
    if (c == current_digit) {
      curr_offset += blocksize;
      continue;
    }
    // Next digit => needs to be strictly one higher, e.g. '0' -> '1', '1' -> '2'
    else if (c == current_digit + 1 && current_digit < '9') {
      current_digit++;
      curr_offset += blocksize;
      continue;
    }
    // If we reach this point we have an invalid sequence
    else {
      //break so we can perform further analysis
      break;
    }


  }


  // Ensure that the last digit seen was a 9. If not --> partial fragment.
  // This check, the check for a 0-block near the beginning, and the check
  // that next digits are strictly one higher ensures that we have all
  // sections 0-9 present if this check passes.
  if (current_digit != '9') {
    *validates = false;
    *promising = true;
    *validates_to = curr_offset - 1;
    return;
  }


  // make sure we're not out of bounds
  // this check is necessary because it's possible that a previous
  // increment in the loop caused curr_offset >= length, which is out
  // of bounds.
  if (curr_offset >= length) {
    *validates = false;
    *promising = true;
    *validates_to = length - 1;
    return;
  }


  // Once we get here, we should either be at the metadata signature or an invalid sequence
  if(curr_offset + METADATA_SIZE_123 + FILE_ID_SIZE_123 > length
    || memcmp(METADATA_SIGNATURE_123, &data[curr_offset], METADATA_SIZE_123) != 0){
      //No metadata signature found, so data is partial
      *validates = false;
      *promising = true;
      *validates_to = curr_offset - 1;
      return;
  }

  // Verify the metadata file ID matches the header file ID
  if (memcmp(header_file_id, &data[curr_offset + METADATA_SIZE_123], FILE_ID_SIZE_123) != 0) {
    *validates = false;
    *promising = true;
    *validates_to = curr_offset - 1;
    return;
  }


  // If we reach this point, metadata block is found and its file ID matches
  // the header. Validate file contents using metadata to ensure that the
  // correct number of blocks reside in each section.


  const uint64_t record_size = 17;
  const uint64_t num_records = 10;
  uint64_t meta_start = curr_offset + METADATA_SIZE_123 + FILE_ID_SIZE_123;
  uint64_t meta_end = meta_start + (record_size * num_records);


  // Ensure enough data for metadata records
  if (meta_end > length) {
    *validates = false;
    *promising = true;
    *validates_to = curr_offset - 1;
    return;
  }


  //loop through metadata records and validate file contents
  for (uint64_t i = 0; i < num_records; i++) {
    uint64_t record_offset = meta_start + i * record_size;


    char section_type = data[record_offset];
    if (section_type < '0' || section_type > '9') {
      *validates = false;
      *promising = true;
      *validates_to = record_offset - 1;
      return;
    }


    //parse the ASCII offset and size out of records
    char offset_buf[9] = {0};
    char size_buf[9] = {0};


    memcpy(offset_buf, &data[record_offset + 1], 8);
    memcpy(size_buf,   &data[record_offset + 9], 8);


    uint64_t section_offset = strtoull(offset_buf, NULL, 10);
    uint64_t section_size   = strtoull(size_buf, NULL, 10);


    // check bounds of the section
    if (section_offset + section_size > length) {
      *validates = false;
      *promising = true;
      *validates_to = length - 1;
      return;
    }


    // Validate contents: all bytes must match the section digit
    for (uint64_t j = 0; j < section_size; j++) {
      if (data[section_offset + j] != section_type) {
        *validates = false;
        *promising = true;
        *validates_to = section_offset + j - 1;
        return;
      }
    }
    //repeat for all sections
  }


  //increment to check the footer block
  curr_offset += blocksize;
  if(curr_offset + FOOTER_SIZE_123 > length
    || memcmp(FOOTER_SIGNATURE_123, &data[curr_offset], FOOTER_SIZE_123) != 0){
    //No footer signature found, so data is partial
    *validates = false;
    *promising = true;
    *validates_to = curr_offset - 1;
    return;
  }
  //increment to end of file
  curr_offset += blocksize;


  //else we have a full file present
  *validates = true;
  *promising = false;
  *validates_to = curr_offset - 1;
  return;


}


/***************************************************************/
/*              BLOCK STATE API FUNCTIONS                      */
/***************************************************************/


// THESE API FUNCTIONS ARE DOCUMENTED IN SCALPELCONF.C
// MORE WORKING EXAMPLES CAN BE FOUND IN GIF.H


// In this case, block state consists of a single static field,
// so the function implementations are fairly simple.




// Tell scalpel how to serialize and deserialize the block state
static inline bool char_serialize_block_state(void **state, FILE *fp,
                                            StateSerialization mode) {
  // cast state to correct structure
  CharBlockState **s = (CharBlockState **)state;


  // this defines a function pointer fb, which points to read or write depending on the mode
  size_t (*fb)(void *ptr, size_t size, size_t nitems, FILE *stream) =
    mode == SERIALIZE ?
    (size_t (*)(void *, size_t, size_t, FILE *))fwrite :
    (size_t (*)(void *, size_t, size_t, FILE *))fread;


  // if mode is deserialize, then we need to allocate a buffer for the state
  if (mode == DESERIALIZE) {
    *s = (CharBlockState *)malloc(sizeof(CharBlockState));
    check_memory_allocation(*s, __LINE__, __FILE__, "CharBlockState");
  }


  // Perform the actual serialization or deserialization.
  // since our struct consists of a static values, the code is short and simple.
  // See gif for a more complex example
  if (fb(&((*s)->value), sizeof(char), 1, fp) != 1) {
    perror("char_serialize_block_state: value");
    handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
  }


  return true;
}




// Tell scalpel how to clone the block state
static inline void *char_clone_block_state(const void *srcstate) {
  CharBlockState *s = (CharBlockState *)srcstate;
  CharBlockState *d = (CharBlockState*) malloc(sizeof(CharBlockState));
  check_memory_allocation(d, __LINE__, __FILE__, "CharBlockState clone");
  d->value = s->value;
  return d;
}




//Tell scalpel how to free the block state
static inline void char_free_block_state(void **state) {
  CharBlockState **s = ((CharBlockState **)state);
  if (*s) {
    //simply free the struct
    free(*s);
    *s = NULL;
  }
}




// SIZEOFBLOCKSTATEFUNC: CharBlockState is plain-old-data with no internal
// pointers, so memcpy produces a correct deep clone.  Defining this
// function lets scalpel3 use a fast memcpy path instead of calling
// char_clone_block_state.
static inline size_t char_sizeof_block_state(const void *state) {
  (void)state;
  return sizeof(CharBlockState);
}




//Tell scalpel how to print the block state
static inline void char_print_block_state(const void *state) {
  const CharBlockState *s = (const CharBlockState *)state;
  if (!s) {
    fprintf(stdout, "NULL");
  } else {
    fprintf(stdout, "'%c'", s->value);
  }
}






/***************************************************************/
/*              CARVE STATE API FUNCTIONS                      */
/***************************************************************/


// THESE API FUNCTIONS ARE DOCUMENTED IN SCALPELCONF.C
// MORE WORKING EXAMPLES CAN BE FOUND IN GIF.H


// Tell scalpel how to serialize/deserialize the carve state
static inline bool file123_serialize_carve_state(void **state, FILE *fp,
                                                StateSerialization mode) {
  File123ReassemblyState **s = (File123ReassemblyState **)state;


  size_t (*fb)(void *ptr, size_t size, size_t nitems, FILE *stream) =
      mode == SERIALIZE ?
      (size_t (*)(void *, size_t, size_t, FILE *))fwrite :
      (size_t (*)(void *, size_t, size_t, FILE *))fread;


  if (mode == DESERIALIZE) {
    *s = (File123ReassemblyState *)malloc(sizeof(File123ReassemblyState));
    check_memory_allocation(*s, __LINE__, __FILE__, "File123ReassemblyState");
  }


  // Here, I serialize/deserialize the entire struct with a single read/write
  // This doesn't cause issues since all fields in the struct are fixed-sized.
  // If pointers or dynamic data is used in state, you will need more complicated
  // code for handling this (see the handling of the msg field in gif.h for an example)


  if (fb(*s, sizeof(File123ReassemblyState), 1, fp) != 1) {
    perror("file123 carve state serialization");
    handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
  }


  return true;
}




// Tell Scalpel how to clone carve state
static inline void *file123_clone_carve_state(const void *srcstate) {
  const File123ReassemblyState *s =
                  (const File123ReassemblyState *)srcstate;
  File123ReassemblyState *d = (File123ReassemblyState *)
                  malloc(sizeof(File123ReassemblyState));


  check_memory_allocation(d, __LINE__, __FILE__, "file123_clone_carve_state");


  // It is safe to use memcopy for deep clone since everything
  // in the struct is plain old data
  memcpy(d, s, sizeof(File123ReassemblyState));
  // once again, if you have pointers or dynamic data in your
  // state, you'll need more complicated logic
  // for performing the deep clone
  return d;
}




// Tell scalpel how to free the carve state
static inline void file123_free_carve_state(void **state) {
  File123ReassemblyState **s = (File123ReassemblyState **)state;
  //This is straightforward since no dynamic data
  free(*s);
  *s = NULL;
}




// SIZEOFCARVESTATEFUNC: File123ReassemblyState is plain-old-data with no
// internal pointers, so memcpy produces a correct deep clone.  Defining
// this function lets scalpel3 use a fast memcpy path instead of calling
// file123_clone_carve_state.
static inline size_t file123_sizeof_carve_state(const void *state) {
  (void)state;
  return sizeof(File123ReassemblyState);
}




// Tell scalpel how to print the carve state for debugging purposes
static inline void file123_print_carve_state(const void *state) {
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






/***************************************************************/
/*                CUSTOM REASSEMBLY LOGIC                      */
/***************************************************************/




/*
  To see how the LR reassembly works, see the template in reassembly.c.
*/


// Side note: there are some additional functions in reassembly.c
// which are 'public' and those are re-used in this example by
// including scalpel.h. They are general enough
// that no customizations are needed.


/*
  In the case of 123 files, we do not need File123_reassembly_did_not_validate()
  and File123_reassembly_backtrack().


  This is why:


  LR‑style files have an unknown block order.  When the tail block that was
  just appended fails validation the algorithm must remember “what almost
  worked” and later roll back to an earlier tail length to try a different
  block (back‑tracking).  That is why the LR code keeps a best‑choices
  queue (`*_did_not_validate`) and a complex tail‑shrinking routine
  (`*_backtrack`).


  In 123 files the situation is different:
    • The exact layout (section boundaries, block types) is dictated by
      the metadata block.
    • We scan the candidate pool for a block of the required section type.
      If duplicate section blocks have been collapsed by the blockmap, we may
      reuse an already-placed block of that same section because those blocks
      are byte-identical by construction.


  Because there is no permutation search:
    - We never rank or cache “almost good” blocks
      (so *_did_not_validate is unnecessary), and
    - We never roll the tail back to pick a different block
      (so *_backtrack is unnecessary).


   In short, 123 reassembly is deterministic hole‑filling, not exploratory
   permutation, and the LR bookkeeping helpers add no value here. However,
   for real-world file types, these will almost always be needed.
*/
// ***********************************************************************
// ****** HIGHER-LEVEL SUPPORT FUNCTIONS SPECIFIC TO 123 REASSEMBLY ******
// ***********************************************************************


/*
  This function prepares a candidate removed from the promising
  queue for processing by a reassembly thread.


  Candidates can fall into one of three cases:


    1. Header-only block (found during header discovery)
    2. Header + contiguous fragment (found during contiguous recovery)
    3. Partially reassembled candidate (returned from checkpointing or
    another interruption)


  Cases (1) and (2) are raw candidates that have not been reassembled before.
  For these, we perform the following steps:


    1. Initialize or retrieve reassembly state:
       If no state exists, allocate a File123ReassemblyState and attach
       it using carve_put_state().
       Set initial flags:
         header_placed = true
         metadata_placed = false
         footer_placed = false
         skeleton_initialized = false


    2. Locate a metadata block:
       a. If a metadata block ('m') already exists in the candidate,
       use it.
       b. Otherwise, search the image for a valid metadata block (type 'm')
       and validate it against the candidate.


    3. Place and validate metadata:
       If a valid metadata block is found, call place_metadata_block() to store
       it in the blockvector, extract expected block layout, and set metadata_placed
       and skeleton_initialized.


    4. Resize the blockvector to the full file size as indicated by the metadata.
       Newly allocated slots are initialized to -1 to represent holes.


    5. Reinflate all valid blocks after the header that were present before resizing.


  Case (3) is detected when the state already exists and both metadata_placed and
  skeleton_initialized are true.


  In this case:
    1. Inflate the block vector
    2. Reconcile carve state (recovered_blocks[], placement flags) against
       the actual blockvector contents, since the backend may have trimmed
       covered blocks since the last time this candidate was processed.
    3. Return (the candidate is ready to resume reassembly)
*/
static void File123_reassembly_init_candidate(int id,
                                   CarveInfo **c_ptr,
                                   uuid_string_t uuidp,
                                   uuid_string_t uuidc){

  CarveInfo *candidate = *c_ptr;

  if (scalpel_state.mode_verbose) {
    lock_fprintf(stdout,
        "\nReassembly thread #%d processing candidate %p  UUIDs %s / %s\n",
        id, candidate->b, uuidp, uuidc);
  }


  //Fetch or create per file state
  File123ReassemblyState *state =
      (File123ReassemblyState *)carve_get_state(candidate->carvehashkey);


  // Initialize state
  if (!state) {
    state = (File123ReassemblyState *)calloc(1, sizeof *state);
    state->header_placed        = true;
    state->metadata_placed      = false;
    state->footer_placed        = false;
    state->skeleton_initialized = false;
    carve_put_state(candidate->carvehashkey, state);


    #ifdef FILE_123_REASSEMBLY_DEBUG
    lock_fprintf(stdout,
      "[reassembly-init] New state allocated for candidate %p\n",
      candidate->b);
    lock_fprintf(stdout, "carvehashkey = ");
    for (uint64_t i = 0; i < CARVE_HASH_KEY_SIZE; ++i) {
      lock_fprintf(stdout, "%02x", (unsigned char)(candidate->carvehashkey)[i]);
    }
    lock_fprintf(stdout, "\n");
    fflush(stdout);
    #endif
  }


  // initialize bv and inflate the header
  inflate_blockvector(candidate->b);
  // inflate_blockvector_single_block(candidate->b, 0);


  //Case 3: candidate already initialized; inflate and return
  if (blockvector_get_num_blocks(candidate->b) > 1 && state->metadata_placed &&
      state->skeleton_initialized){


    #ifdef FILE_123_REASSEMBLY_DEBUG
    lock_fprintf(stdout,
      "[reassembly-init] Resuming candidate %p with %" PRIu64 " blocks (metadata+layout already set)\n",
		 candidate->b, blockvector_get_num_blocks(candidate->b));
    fflush(stdout);
    #endif


    // inflate the block vector
    inflate_blockvector(candidate->b);

    // Reconcile recovered_blocks[] with what is actually still in the
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
      int sec = slot_to_section(state, num_blks, (int64_t)i);
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
    file123_free_carve_state((void **)&state);
    return;
  }


  /*********************************************************************/
  /*   We found a candidate that needs to be initialized.             */
  /*   Ensure a metadata block is parsed and skeleton set up          */
  /********************************************************************/


  // calculate how many blocks were already placed in this candidate
  uint64_t placed_blocks = 0;
  for (uint64_t i = 0; i < blockvector_get_num_blocks(candidate->b); i++) {
    if (blockvector_get_apparent_blocknumber(candidate->b, i) != -1) {
      placed_blocks++;
    }
  }


  #ifdef FILE_123_REASSEMBLY_DEBUG
  lock_fprintf(stdout,
  "*** [placed blocks] ******: %" PRIu64 " \n", placed_blocks);
  #endif


  // Was a metadata block already present in the contiguous fragment?
  int64_t m_apparent = -1;
  for (uint64_t i = 0; i < placed_blocks; ++i) {


    int64_t blk_ap = blockvector_get_apparent_blocknumber(candidate->b, i);
    // We've reached the end of contiguous data; break
    if (blk_ap == -1){
      break;
    }


    // Get state
    int64_t blk_act = filemirror_actual_blocknumber(
      scalpel_state.filemirror, blk_ap);
    char hashkey[BLOCK_HASH_KEY_SIZE];
    gen_block_hash_key(hashkey, candidate->needleidx, blk_act);
    CharBlockState *blk_state = (CharBlockState *)block_get_state(hashkey);


    // Metadata is already present in the fragment
    if (blk_state && blk_state->value == 'm') {
      m_apparent = blk_ap;
      char_free_block_state((void **)&blk_state);
      break;
    }
    char_free_block_state((void **)&blk_state);
  }


  // Log metadata search results
  #ifdef FILE_123_REASSEMBLY_DEBUG
  if (m_apparent != -1) {
    lock_fprintf(stdout,
      "[reassembly-init] Found embedded metadata block at apparent=%" PRId64 " in candidate %p\n",
      m_apparent, candidate->b);
  } else {
    lock_fprintf(stdout,
      "[reassembly-init] No metadata found in initial fragment of candidate %p; searching externally\n",
      candidate->b);
  }
  fflush(stdout);
  #endif


  if (m_apparent != -1) {
    // If metadata is already present
    place_metadata_block(candidate, m_apparent);
    #ifdef FILE_123_REASSEMBLY_DEBUG
    lock_fprintf(stdout,
      "[init] Placed metadata block at apparent index %" PRId64 "\n", m_apparent);
    #endif
  } else {
    // No metadata block already in candidate; we need to find one
    int64_t meta_block = find_valid_metadata_block(candidate);
    if (meta_block < 0) {
      if (scalpel_state.mode_verbose){
        lock_fprintf(stdout,
          "\n[init] No matching metadata block for UUID %s - abandoning\n",
          uuidc);
      }
      file123_free_carve_state((void **)&state);
      destroy_candidate(c_ptr);
      return;
    }
    //metadata block found
    place_metadata_block(candidate, meta_block);
    #ifdef FILE_123_REASSEMBLY_DEBUG
    lock_fprintf(stdout,
      "[init] Placed metadata block at apparent index %" PRId64 "\n", meta_block);
    #endif
  }


  /* ******************************************************************** */
  /*   Now that we have the metadata in place, we can calculate size,    */
  /*   build full‑size skeleton & re‑inflate existing blocks              */
  /* ******************************************************************** */


  uint64_t total_blocks = calculate_file_size_from_metadata(candidate);
  if (total_blocks == 0) {
    // shouldn’t happen; but for safety:
    file123_free_carve_state((void **)&state);
    destroy_candidate(c_ptr);
    return;
  }


  // This initializes empty slots to have actual/apparent blknum -1
  resize_blockvector(candidate->b, total_blocks);


  // Inflate the good blocks after the header
  // This function populates the data buffer, but it also updates bv length
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
      CharBlockState *blk_state =
          (CharBlockState *)block_get_state(hashkey);
      char ch = blk_state->value;
      char_free_block_state((void **)&blk_state);
      // update the recovered blocks approrpriately
      if (ch >= '0' && ch <= '9') {
        int sec = ch - '0';
        st->recovered_blocks[sec]++;
      }
    }
  }


  #ifdef FILE_123_REASSEMBLY_DEBUG
    lock_fprintf(stdout,"[init] after resize (%" PRIu64 " blocks)\n",
                  blockvector_get_num_blocks(candidate->b));
    display_blockvector(candidate->b, "after init");
    file123_print_carve_state(st);
  #endif

  carve_put_state(candidate->carvehashkey, st);
  file123_free_carve_state((void **)&st);
  file123_free_carve_state((void **)&state);
}






/*
  Decide where the reassembly thread should begin searching for the next block.
  Called each time we try to extend a candidate by one logical slot.


  Similar to the LR‑reassembly helper, but adapted for 123 files:


    - 123 block‑vectors are sized to the final file length up front.
      Empty slots are marked –1, so no dynamic resize is required.


    - 123 reassembly never uses “clones,” because layout is metadata‑directed
      rather than exploratory.  Each thread works on a unique candidate,
      so we do not randomize the starting point to avoid lock‑step.


    - Strategy: find the first hole (‑1) in the block‑vector and propose a
      preferred starting point for the search
      (previous_apparent + 1 if a predecessor exists).


  Return value
    true  – a hole was found; out‑params are valid
    false – no holes; candidate is already complete


  Out‑parameters
    hole_idx – logical index of the first hole, or –1 if none
    start_ap – first apparent block number to try:
                 >0 : heuristic guess (prefer continuity first)
                –1 : no good guess; caller should start at 0
 */
bool File123_reassembly_prepare_for_extension(CarveInfo *cand,
                                              int64_t *hole_idx,
                                              int64_t *start_ap){
  // We use BV capacity rather than inflated length
  // num_blocks -> full bv capacity
  // length -> inflated block vector length (how much data is there)
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


/*
   file_123_reassembly_get_block_choice()


   Purpose
     Return the next *apparent* block number that should be tried in the
     logical slot <logical_slot_index>.  The behaviour is adapted from the
     LR version but tailored to 123 files.


   Quick summary
     - Scans the candidate‑pool bitmap beginning at *block_choice_start
     - Skips duplicates already placed in the BV
     - Accepts only blocks whose CharBlockState type == <target_type>
     - Removes every block it inspects from the pool so we never revisit it
     - On success, updates *block_choice_start to “one past” the chosen block


   Default LR behaviour (for context)
     1. Start at *block_choice_start  (‑1 = random).
     2. Loop: pick a candidate, mark it visited, advance start,
        discard if wrong type or already used.
     3. Update *block_choice_start only if a valid block is found.
        If none remain, return ‑1.


   123‑specific behavior
     1. Start at *block_choice_start; if NULL use 0.
     2. Loop:
          a. blockvector_get_choice(bv, slot, start)  →  block_choice or ‑1
          b. blockvector_remove_choice(bv, slot, block_choice)
          c. start = block_choice + 1   (next physical block)
          d. if block already in BV → reject, continue
          e. look up CharBlockState; if value == target_type → accept, break
             else reject and continue
     3. If nothing usable is found before the end of the pool and the initial
        start was nonzero, wrap once to 0 and continue scanning the lower
        apparent block numbers. This keeps the search deterministic while
        supporting arbitrary block reordering.
     4. If no fresh digit-section block remains, reuse an already-placed
        block of that same section. This handles repeated identical section
        blocks when duplicates are collapsed in the blockmap.
     5. On success (block_choice != ‑1) and block_choice_start != NULL
          *block_choice_start = start   (so next call resumes here)
     6. Return value:
          ≥0  : apparent block number that passes all filters
          ‑1  : no usable block remains


   Notes
     - As in LR, *block_choice_start is NOT advanced when no valid block is
       found; caller can decide how to react (defer, abandon, etc.).
     - Caller must always check for a return value of ‑1.
 */
static int64_t File123_reassembly_get_block_choice(CarveInfo *candidate,
                                                    int64_t *block_choice_start,
                                                    int64_t logical_slot_index,
                                                    char target_type) {
  int64_t block_choice;
  int64_t start = (block_choice_start ? *block_choice_start : 0);
  int64_t initial_start;
  bool done = false;
  bool reused_existing = false;
  bool wrapped = false;
  uint64_t evaluated;


  #if BLOCK_SELECTION_PERFORMANCE_STATS > 0
  struct timespec BLK_starttime;
  struct timespec BLK_endtime;
  uint64_t BLK_examined = 0;


  clock_gettime(CLOCK_MONOTONIC, &BLK_starttime);
#endif

  if (start < 0) {
    start = 0;
  }
  initial_start = start;

  while (!done) {


#if BLOCK_SELECTION_PERFORMANCE_STATS > 0
    BLK_examined += evaluated;
#endif


    if ((block_choice =
         blockvector_get_choice(candidate->b,
                                logical_slot_index, start,  filemirror_apparent_blocks(scalpel_state.filemirror), &evaluated)) == -1) {
      if (!wrapped && initial_start > 0) {
        wrapped = true;
        start = 0;
        continue;
      }
      done = true;
    }
    else {
      // don't select the chosen block again
      blockvector_remove_choice(candidate->b,
                                logical_slot_index, block_choice);


      // advance next block choice
      start = block_choice + 1;


      // don't select duplicate blocks or blocks of the wrong type
      if (apparent_block_in_blockvector(candidate->b, block_choice) ||
      filemirror_get_blocktype(scalpel_state.filemirror,
                              filemirror_actual_blocknumber(scalpel_state.filemirror, block_choice),
                              candidate->needleidx) == BLOCK_CONFIDENCE_INVALID){
        block_choice = -1;
      } else {
        // check block type
        int64_t actual_blk = filemirror_actual_blocknumber(
          scalpel_state.filemirror, block_choice);


        char hashkey[BLOCK_HASH_KEY_SIZE];
        gen_block_hash_key(hashkey, candidate->needleidx, actual_blk);
        CharBlockState *blk_state = (CharBlockState *)block_get_state(hashkey);
        // find a block of the correct type being requested by the caller
        if(!blk_state){
          lock_fprintf(stderr, "No block state found for block %" PRId64 "\n", actual_blk);
        }
        if (blk_state && blk_state->value == target_type) {
          done = true;
        } else {
          block_choice = -1;
        }
        char_free_block_state((void **)&blk_state);
      }
    }
  }

  if (block_choice == -1 &&
      target_type >= '0' && target_type <= '9') {
    block_choice = File123_find_reusable_section_block(candidate, target_type);
    if (block_choice != -1) {
      reused_existing = true;
    }
  }


  // Only update block_choice_start if we found a valid block
  if (block_choice_start && block_choice != -1 && !reused_existing) {
    *block_choice_start = start;
  }


  #if BLOCK_SELECTION_PERFORMANCE_STATS > 0
  // update block selection performance stats
  clock_gettime(CLOCK_MONOTONIC, &BLK_endtime);
  uint64_t BLK_elapsed = (BLK_endtime.tv_sec - BLK_starttime.tv_sec) * 1e9 + (BLK_endtime.tv_nsec - BLK_starttime.tv_nsec);


  atomic_fetch_add_explicit(&scalpel_state.search_specs[candidate->needleidx].BLK_calls, 1, memory_order_acq_rel);
  atomic_max_u64_pub(&scalpel_state.search_specs[candidate->needleidx].BLK_longest, BLK_elapsed);
  atomic_fetch_add_explicit(&scalpel_state.search_specs[candidate->needleidx].BLK_total, BLK_elapsed, memory_order_acq_rel);
  atomic_max_u64_pub(&scalpel_state.search_specs[candidate->needleidx].BLK_most_blocks, BLK_examined);
#endif


  return block_choice;
}


static int64_t File123_find_reusable_section_block(CarveInfo *candidate,
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
    CharBlockState *blk_state = (CharBlockState *)block_get_state(hashkey);
    bool match = (blk_state && blk_state->value == target_type);
    char_free_block_state((void **)&blk_state);

    if (match) {
      return apparent;
    }
  }

  return -1;
}






/*
  This function commits a block to the block vector by placing it into
  the slot and inflating the blockvector.


  It is similar to the LR version of this function. However, it doesn't
  commit from the end. Instead it accepts a slot index.


  In this function, the candidate length is also not updated since the candidate
  is not built contiguously.
*/
static void File123_reassembly_extension_successful(int id,
                                      CarveInfo *candidate,
                                      int64_t logical_slot_index) {
  (void)id;


  File123ReassemblyState *st =
        (File123ReassemblyState *)carve_get_state(candidate->carvehashkey);


  // Convert actual block to apparent blocknumber
  int64_t apparent = filemirror_apparent_blocknumber( scalpel_state.filemirror, candidate->newblock);


  //make sure the logical index is at least 0
  if (logical_slot_index < 0) {
    lock_fprintf(stderr, "[error] logical_slot_index is negative: %" PRId64 "\n", logical_slot_index);
    file123_free_carve_state((void **)&st);
    exit(1);
  }
  //Also make sure the logical slot index is within bounds
  if ((uint64_t) logical_slot_index >= blockvector_get_num_blocks(candidate->b)){
    lock_fprintf(stdout, "logical_slot_index %" PRId64 " exceeds blockvector length %" PRIu64 "\n",
                logical_slot_index, blockvector_get_num_blocks(candidate->b));
    file123_free_carve_state((void **)&st);
    exit(1);
  }
  // Place the block into the specified logical slot
  blockvector_set_apparent_blocknumber(candidate->b, logical_slot_index, apparent);


  // Inflate that block; we're not accessing data, but this call is needed
  // to ensure bv->length is updated appropriately
  inflate_blockvector_single_block(candidate->b, logical_slot_index);


  //update recovered blocks
  int sec = slot_to_section(st, blockvector_get_num_blocks(candidate->b), logical_slot_index);
  if (sec >= 0 && sec < 10){
    st->recovered_blocks[sec]++;
  }
  #ifdef FILE_123_REASSEMBLY_DEBUG
  file123_print_carve_state(st);
  #endif
  //update the footer flag if we place that block
  if (logical_slot_index == (int64_t)(blockvector_get_num_blocks(candidate->b) - 1)) {
    st->footer_placed = true;
  }
  carve_put_state(candidate->carvehashkey, st);
  file123_free_carve_state((void **)&st);
}






/*
  Attempts to rapidly extend a candidate across a known hole in structured 123 files
  by placing a sequence of contiguous blocks and validating the result.


  This "galloping mode" is a performance optimization inspired by LR reassembly's
  galloping strategy, but tailored for deterministic, metadata-driven 123 files.


  Behavior:
  - Starts at the beginning of a hole in the candidate’s blockvector.
  - Sequentially places the next logical (contiguous) apparent block into the candidate.
  - Skips block selection heuristics (i.e., does not call get_block_choice()) to
    preserve the speed and intent of galloping.
  - Stops placing if:
      * The previous block isn’t present (can’t determine next),
      * A block is already placed elsewhere,
      * A candidate block is marked BLOCK_CONFIDENCE_INVALID.
  - After attempting to gallop-fill the hole, it calls the file-level validator
    to assess whether the new region is valid.
  - If validation fails, the function rolls back unvalidated blocks and resets gallop.


  Differences from LR galloping:
  - LR assumes sequential reassembly and may expand the entire candidate length.
  - This version uses a pre-defined hole range and does not grow the blockvector.
  - Instead of extending blindly through the tail, this version is aware of holes
    and avoids overwriting future valid regions.
*/
static void File123_reassembly_gallop(int            id,
                                       CarveInfo     *candidate,
                                       int64_t        start_index,
                                       int64_t        end_index,
                                       uint32_t      *gallop,
                                       uint64_t      *validates_to,
                                       bool          *validates){
  (void)id;


  // Determine how many blocks to try in this round
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


    /* Commit the block into the hole */
    blockvector_set_apparent_blocknumber(candidate->b, logical_index, next_ap);
    // inflate_blockvector_single_block(candidate->b, logical_index);


    //update the recovered blocks in the metadata
    File123ReassemblyState *st =
    (File123ReassemblyState *)carve_get_state(candidate->carvehashkey);
    int sec = slot_to_section(st, blockvector_get_num_blocks(candidate->b), logical_index);
    if (sec >= 0 && sec < 10){
      st->recovered_blocks[sec]++;
    }
    #ifdef FILE_123_REASSEMBLY_DEBUG
    file123_print_carve_state(st);
    #endif
    carve_put_state(candidate->carvehashkey, st);
    file123_free_carve_state((void **)&st);
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


  char *data = blockvector_to_buffer_range(candidate->b,
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
      int sec = slot_to_section(st, blockvector_get_num_blocks(candidate->b), i);
      if (sec >= 0 && sec < 10 && st->recovered_blocks[sec] > 0){
        st->recovered_blocks[sec]--;
      }
      carve_put_state(candidate->carvehashkey, st);
      file123_free_carve_state((void **)&st);
      blockvector_set_apparent_blocknumber(candidate->b, i, -1);
    }
    //reset gallop factor
    *gallop = 0;
  }
}






/**************************************************************/
/* validate entire candidate quickly                          */
/**************************************************************/
static bool file_123_file_validate_full(CarveInfo *cand,
                                        uint64_t  *validates_to){


  uint64_t len_bytes = blockvector_get_num_blocks(cand->b) * scalpel_state.blocksize;
  // copy the file data into a buffer (without per-slot bitmaps, etc)
  char *buf = blockvector_to_buffer_range(cand->b,
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






/**************************************************************/
/* locate end (inclusive) of current hole                     */
/**************************************************************/
static int64_t find_hole_end(CarveInfo *cand, uint64_t start){
  uint64_t i = start;
  while (i < blockvector_get_num_blocks(cand->b) &&
         blockvector_get_apparent_blocknumber(cand->b, i) == -1){
    ++i;
  }


  return i - 1;
}






/**************************************************************/
/* return required CharBlockState value for slot              */
/**************************************************************/
static char block_type_for_slot(CarveInfo *cand, uint64_t slot){
  File123ReassemblyState *st =
      (File123ReassemblyState *)carve_get_state(cand->carvehashkey);


  if (!st || !st->skeleton_initialized){
    file123_free_carve_state((void **)&st);
    return '?';
  }


  // header 0, sections 0‑9, metadata, footer
  if (slot == 0){
    file123_free_carve_state((void **)&st);
    return 'h';
  }
  // last slot is guaranteed to be the footer because of resizing in init_candidate
  if (slot == blockvector_get_num_blocks(cand->b) - 1){
    file123_free_carve_state((void **)&st);
    return 'f';
  }


  // walk through section boundaries to determine what section pos falls
  uint64_t pos = 1;
  for (int sec = 0; sec < 10; ++sec) {
    uint64_t end = pos + st->expected_blocks[sec] - 1;
    if (slot >= pos && slot <= end){
      file123_free_carve_state((void **)&st);
      return (char)('0' + sec);
    }
    pos = end + 1;
  }
  // if still not found after searching the 10 sections, then metadata
  file123_free_carve_state((void **)&st);
  return 'm';
}






// **********************************************************************
// ****** LOWER-LEVEL SUPPORT FUNCTION SPECIFIC TO 123 REASSEMBLY  ******
// **********************************************************************


/*
  Resize the block vector to the expected number of blocks
  given the state information of the candidate.


  This function is used to do a final resize before writing out the
  candiate in the reassembly function.
*/
void file123_resize_blockvector_to_expected(CarveInfo *cand) {


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
  #ifdef FILE_123_REASSEMBLY_DEBUG
  lock_fprintf(stdout,
    "[resize blockvector to expected] total blocks: %" PRIu64 " \n", expected_total_blocks);
  #endif
  resize_blockvector(cand->b, expected_total_blocks);
  file123_free_carve_state((void **)&state);
}


/*
  Translates a logical slot into a section number 0‑9,
  or –1 for header/metadata/footer, using the expected blocks
  field in the reassembly state.


  This is used as a helper function when tracking what blocks
  have been placed inside of the "skeleton" (or reassembly state).
  We need a section number from a slot number to correctly update
  the recovered_blocks field in the reassembly state.


  Note: this function returns -1 for header/metadata/footer.
  We don't need information about those blocks for
  the recovered_blocks field since the reassembly state has
  separate flags for those special blocks.
*/
static int slot_to_section(const File123ReassemblyState *st,
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


/*
  Converts a section of a BlockVector into a contiguous memory buffer.


  This function is primarily used during file validation, especially in galloping mode,
  to construct a temporary buffer from a specified range of blocks (start_idx to end_idx).


  Each block in the specified range is read individually using the blockvector API.
  If a block is missing (marked as -1), the corresponding region in the buffer is zero-filled.


  The resulting buffer can then be passed to a validator to check if a partially reassembled
  file candidate meets expected format or structural constraints.
*/
char *blockvector_to_buffer_range(BlockVector *bv, int64_t start_idx, int64_t end_idx) {
  int64_t num_blocks = end_idx - start_idx + 1;
  uint64_t blocksize = scalpel_state.blocksize;
  char *buffer = (char *)malloc(num_blocks * blocksize);
  if (!buffer) {
    lock_fprintf(stderr, "[ERROR] Failed to allocate buffer in blockvector_to_buffer_range\n");
    return NULL;
  }

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


/*
  This function is used by File123_reassembly_init_candidate() to find a suitable
  metadata block for a given candidate which is being initialized.


  First, we have to search through the candidate blocks available to us and find a block
  of the correct type by polling state information (set in the block validator). In this
  case, we're looking for a metadata block which we labeled as type 'm'.


  Once we find a metadata block, we have to check if it's an appropriate match for the candidate.
  This handled by the validate_metadata_block() function (called within this one).


  If the function finds a valid metadata block for the candidate, then the index of the block
  is returned to the caller.


  At init, it’s safe to assume that all slots have all block choices.
  So this code picks a slot after the placed blocks and uses it to search for metadata.


*/
int64_t find_valid_metadata_block(CarveInfo *candidate) {
  BlockVector *bv = candidate->b;
  uint64_t slot = 0;
  int64_t block_choice = -1;
  int64_t start = 0;

  #ifdef FILE_123_REASSEMBLY_DEBUG
  lock_fprintf(stdout,
    "[metadata-search] Starting metadata search for candidate %p (slot=%" PRIu64 ")\n",
    candidate->b, slot);
  fflush(stdout);
  #endif

  BlockVector *scan_bv = NULL;
  init_blockvector(scalpel_state.filemirror, &scan_bv, 1, false);
  inflate_blockvector(scan_bv);

  #ifdef FILE_123_REASSEMBLY_DEBUG
  BlockVector *debug_bv = NULL;
  init_blockvector(scalpel_state.filemirror, &debug_bv, 1, false);
  inflate_blockvector(debug_bv);
  uint64_t print_slot = 0;
  int64_t print_start = 0;
  int64_t print_block_choice = -1;
  uint64_t print_evaluated = 0;
  while ((print_block_choice =
    blockvector_get_choice(debug_bv, print_slot, print_start,
      filemirror_apparent_blocks(scalpel_state.filemirror), &print_evaluated)) != -1) {
    blockvector_remove_choice(debug_bv, print_slot, print_block_choice);
    int64_t act = filemirror_actual_blocknumber(scalpel_state.filemirror, print_block_choice);
    int64_t exemplar_blk = filemirror_get_exemplar(scalpel_state.filemirror, act);
    lock_fprintf(stdout,
      "[metadata-search][FULL SCAN] Block %" PRId64 " -> actual %" PRId64 " -> exemplar %" PRId64 "\n",
      print_block_choice, act, exemplar_blk);
    fflush(stdout);
    print_start = print_block_choice + 1;
  }
  free_blockvector(&debug_bv);
  #endif

  uint64_t evaluated = 0;
  while ((block_choice =
    blockvector_get_choice(scan_bv, slot, start,
      filemirror_apparent_blocks(scalpel_state.filemirror), &evaluated)) != -1) {

    blockvector_remove_choice(scan_bv, slot, block_choice);
    start = block_choice + 1;

    if (apparent_block_in_blockvector(bv, block_choice)) {
      #ifdef FILE_123_REASSEMBLY_DEBUG
      lock_fprintf(stdout,
        "[metadata-search] Skipping block_choice=%" PRId64 " - already placed in candidate\n",
        block_choice);
      #endif
      continue;
    }

    int64_t  act = filemirror_actual_blocknumber(
      scalpel_state.filemirror, block_choice);
    if (filemirror_get_blocktype(scalpel_state.filemirror,
                act, candidate->needleidx) == BLOCK_CONFIDENCE_INVALID){
      continue;
    }

    char hashkey[BLOCK_HASH_KEY_SIZE];
    gen_block_hash_key(hashkey, candidate->needleidx, act);
    CharBlockState *st = (CharBlockState *)block_get_state(hashkey);

    if (!st) {
      #ifdef FILE_123_REASSEMBLY_DEBUG
      lock_fprintf(stdout,
        "[metadata-search] Block %" PRId64 " has no state - skipping\n",
        block_choice);
      #endif
      continue;
    }

    if (st->value != 'm') {
      #ifdef FILE_123_REASSEMBLY_DEBUG
      lock_fprintf(stdout,
        "[metadata-search] Block %" PRId64 " is not metadata (value='%c') - skipping\n",
        block_choice, st->value);
      #endif
      char_free_block_state((void **)&st);
      continue;
    }

    #ifdef FILE_123_REASSEMBLY_DEBUG
    lock_fprintf(stdout,
      "[metadata-search] Found candidate metadata block %" PRId64 " - validating\n",
      block_choice);
    fflush(stdout);
    #endif

    char_free_block_state((void **)&st);
    if (validate_metadata_block(candidate, block_choice)) {
      #ifdef FILE_123_REASSEMBLY_DEBUG
      lock_fprintf(stdout,
        "[metadata-search] Metadata block %" PRId64 " validated successfully\n",
        block_choice);
      fflush(stdout);
      #endif
      free_blockvector(&scan_bv);
      return block_choice;
    }
    #ifdef FILE_123_REASSEMBLY_DEBUG
    lock_fprintf(stdout,
      "[metadata-search] Metadata block %" PRId64 " failed validation\n",
      block_choice);
    fflush(stdout);
    #endif
  }

  #ifdef FILE_123_REASSEMBLY_DEBUG
  lock_fprintf(stdout,
    "[metadata-search] No valid metadata block found for candidate %p\n",
    candidate->b);
  fflush(stdout);
  #endif

  free_blockvector(&scan_bv);
  return -1;
}






/*
  To validate a metadata block, we must inspect the block contents.
  The metadata block tells us information about the sections within
  the 123 files. There is a #METADATA# signature at the beginning of
  this block which indicates that we have a metadata block. Following
  this, there is a 17-char record for each
  section, which describes (1) the section type [1 char], (2) the offset
  the section starts in the file [8 chars], and (3) the total size of the
  section in bytes [8 chars]. All of these fields hold ascii numbers
  that can be parsed to integers.


  All together, this tells us the boundaries of each section within the 123
  file that corresponds to this metadata. Following the records, there's
  padding up to the block size using '-' chars.


  To match a metadata block with a candidate, these conditions have to be met:


    (1) Each block in the candidate must be of the correct type for the section
    it’s in (based on section boundaries defined in the metadata)


    (2) If a section has fewer blocks than expected, then there must be enough
    available slots in the blockvector (between this section’s start and the next)
    to eventually fulfill the
    required count.


  If these conditions are met, then the metadata block is an appropriate match for
  the candidate


  Here's how we can implement this checking in the code:


  In the file state structure (File123ReassemblyState), we have an array for
  storing the total. Expected number of blocks in the 123 file's sections.
  We can create a temp state, and populate the expected_blocks field based on
  the metadata block we're currently analyzing.


  Then by comparing the expected blocks with the blocks that are already in the
  candidate, we can determine


  (1) If the candidates blocks are in compliance with metadata section boundaries
  (2) If there is enough space in the candidate for future blocks if the number of
  placed blocks falls short of the expected.


*/
bool validate_metadata_block(CarveInfo *candidate, int64_t metadata_block) {
  File123ReassemblyState *state =
  (File123ReassemblyState *)carve_get_state(candidate->carvehashkey);
  if (!state){
    #ifdef FILE_123_REASSEMBLY_DEBUG
    lock_fprintf(stdout,
      "[validate metadata] No state found for candidate %p\n",
      candidate->b);
    #endif
    return false;
  }

  int64_t actual_block =
  filemirror_actual_blocknumber(scalpel_state.filemirror, metadata_block);
  uint8_t *blockdata = get_metadata_block_data(actual_block);
  if (!blockdata){
    #ifdef FILE_123_REASSEMBLY_DEBUG
    lock_fprintf(stdout,
      "[validate metadata] No block data found for actual block %" PRId64 "\n",
      actual_block);
    #endif
    file123_free_carve_state((void **)&state);
    return false;
  }

  if (memcmp(blockdata, "#METADATA#", METADATA_SIZE_123) != 0) {
    #ifdef FILE_123_REASSEMBLY_DEBUG
    lock_fprintf(stdout,
      "[validate metadata] No metadata signature found for actual block %" PRId64 "\n",
      actual_block);
    #endif
    free(blockdata);
    file123_free_carve_state((void **)&state);
    return false;
  }

  // Compare the file ID in the metadata block against the header block's
  // file ID.  This ensures each metadata pairs only with its own header.
  int64_t hdr_ap = blockvector_get_apparent_blocknumber(candidate->b, 0);
  unsigned char *hdr_data = get_apparent_block_data(scalpel_state.filemirror, hdr_ap);
  if (!hdr_data) {
    free(blockdata);
    file123_free_carve_state((void **)&state);
    return false;
  }
  bool id_match = (memcmp(&hdr_data[HEADER_SIZE_123],
                          &blockdata[METADATA_SIZE_123],
                          FILE_ID_SIZE_123) == 0);
  free(hdr_data);
  if (!id_match) {
    #ifdef FILE_123_REASSEMBLY_DEBUG
    lock_fprintf(stdout,
      "[validate metadata] File ID mismatch for metadata block %" PRId64 "\n",
      metadata_block);
    #endif
    free(blockdata);
    file123_free_carve_state((void **)&state);
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
    CharBlockState *blk_state = (CharBlockState *)block_get_state(hashkey);

    if (!blk_state) {
      #ifdef FILE_123_REASSEMBLY_DEBUG
      int64_t img_block = actual_block;
      lock_fprintf(stdout,
          "[debug] missing state  needle=%u  slot=%" PRIu64
          "  apparent=%" PRId64 "  actual=%" PRId64 "\n",
          candidate->needleidx, i, blknum, img_block);
      #endif
      free(blockdata);
      file123_free_carve_state((void **)&state);
      return false;
    }

    int section = blk_state->value - '0';
    char_free_block_state((void **)&blk_state);

    if (current_section == -1) {
      current_section = section;
      placed_in_section = 1;
      #ifdef FILE_123_REASSEMBLY_DEBUG
      lock_fprintf(stdout,
        "[validate metadata] validating section %d\n",
        current_section);
      #endif
    } else if (section == current_section) {
      placed_in_section++;
      if (placed_in_section > expected[section]) {
        #ifdef FILE_123_REASSEMBLY_DEBUG
        lock_fprintf(stdout,
          "[validate metadata] too many blocks in section %d\n",
          current_section);
        #endif
        free(blockdata);
        file123_free_carve_state((void **)&state);
        return false;
      }
    } else if (section == current_section + 1) {
      if (placed_in_section != expected[current_section]) {
        #ifdef FILE_123_REASSEMBLY_DEBUG
        lock_fprintf(stdout,
          "[validate metadata] We encountered section %d+1, but section %d has fewer blocks than required.\n",
          current_section, current_section);
        #endif
        free(blockdata);
        file123_free_carve_state((void **)&state);
        return false;
      }
      current_section = section;
      #ifdef FILE_123_REASSEMBLY_DEBUG
      lock_fprintf(stdout,
        "[validate metadata] Moved on to section %d\n",
        current_section);
      #endif
      placed_in_section = 1;
    } else {
      #ifdef FILE_123_REASSEMBLY_DEBUG
      lock_fprintf(stdout,
        "[validate metadata] Invalid section order detected");
      #endif
      free(blockdata);
      file123_free_carve_state((void **)&state);
      return false;
    }
  }
  free(blockdata);
  file123_free_carve_state((void **)&state);
  #ifdef FILE_123_REASSEMBLY_DEBUG
  lock_fprintf(stdout,
    "[validate metadata] Metadata has been successfully validated.");
  #endif
  return true;
}




/*
  Get block data for a given actual block number.

  Converts the actual block number to an apparent block number, then
  retrieves a heap-allocated copy of the block's contents via
  get_apparent_block_data().  The caller must free the returned buffer.
*/
uint8_t *get_metadata_block_data(int64_t actual_blocknum) {
  int64_t apparent = filemirror_apparent_blocknumber(scalpel_state.filemirror, actual_blocknum);
  if (apparent < 0) {
    return NULL;
  }
  return get_apparent_block_data(scalpel_state.filemirror, apparent);
}




/*
  This function places the metadata in the candidate and initializes the skeleton
*/
void place_metadata_block(CarveInfo *candidate, int64_t apparent_blocknum) {
  if (apparent_blocknum < 0){
    return;
  }

  int64_t actual_block =
    filemirror_actual_blocknumber(scalpel_state.filemirror, apparent_blocknum);
  uint8_t *blockdata = get_metadata_block_data(actual_block);
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
    #ifdef FILE_123_REASSEMBLY_DEBUG
    lock_fprintf(stdout, "[BUG] Reassembly state not initialized for place_metadata()");
    #endif
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
  file123_free_carve_state((void **)&state);
  free(blockdata);
}




/*
  This function calculates the size of a 123 file using the
  reassembly state (derived from metadata)
*/
uint64_t calculate_file_size_from_metadata(CarveInfo *candidate) {
  File123ReassemblyState *state =
            (File123ReassemblyState *)carve_get_state(candidate->carvehashkey);
  if (!state || !state->skeleton_initialized) {
    // Can't calculate size without metadata / skeleton
    file123_free_carve_state((void **)&state);
    return 0;
  }


  uint64_t total_blocks = 1; // Start with header


  // Add all section block counts
  for (int i = 0; i < 10; i++) {
    total_blocks += state->expected_blocks[i];
  }


  // Add metadata and footer
  total_blocks += 1;
  total_blocks += 1;


  file123_free_carve_state((void **)&state);
  return total_blocks;
}






/**********************************************************************/
/*  Main reassembly loop for 123 files                                */
/**********************************************************************/
/*
    This function tries to fill a candidate
    It's main purpose is to control the overall reassembly logic using the helper functions.
    It's main functions are to:
        1) Initialize new candidates or candidates being resumed after checkpointing
        2) Locate holes in the candidate and fill them accurately and efficiently
        3) Validate the candidte-- both partial fragments and entire files
        4) Write the candidate upon full recovery, or abort if hopeless
*/




void File123_reassembly(ThreadWork      *work,
                        CarveInfo      **c,
                        uuid_string_t    uuidp,
                        uuid_string_t    uuidc){


  #ifdef FILE_123_REASSEMBLY_DEBUG
  lock_fprintf(stdout,
    "\n[reassembly] Thread #%d started on candidate %p (UUIDc=%s)\n",
    work->id, *c ? (*c)->b : NULL, uuidc);
  fflush(stdout);
  #endif


  // Variables initialization
  bool     validates     = false;
  uint64_t validates_to  = 0;
  uint32_t gallop_factor = 0;
  uint64_t tick          = 0;


  // Print info
  if (scalpel_state.mode_verbose){
    lock_fprintf(stdout,
        "\nReassembly thread #%d starting on candidate %p  UUIDs\n%s / %s\n",
        work->id, (*c)->b, uuidp, uuidc);
  }


  // Initialize Candidate
  File123_reassembly_init_candidate(work->id, c, uuidp, uuidc);
  if (!*c) {
    return;
  }


  // Main reassembly loop
  while (1){
    // Progress dots for non-verbose (mimics LR)
    if (!scalpel_state.mode_verbose && (tick++ % 100000) == 0) {
      lock_fprintf(stdout, "%s.%s", BLUE, BLACK);
      fflush(stdout);
    }


    // If candidate has reached max size, break out of the loop
    if (reassembly_check_max_size(work->id, *c, uuidp, uuidc)) {
      lock_fprintf(stdout,
          "\nThread #%d reached max size on %s / %s; writing file\n",
          work->id, uuidp, uuidc);
      break;
    }


    #ifdef FILE_123_REASSEMBLY_DEBUG
    lock_fprintf(stdout,
      "Prepare for extension [start]: \n[loop] Tick=%" PRIu64 " | Candidate=%p | flavor=%d | newblock=%" PRId64 "\n",
      tick, *c, (*c)->flavor, (*c)->newblock);
    #endif


    // Find the next hole
    int64_t hole_idx, start_ap;
    if (!File123_reassembly_prepare_for_extension(*c, &hole_idx, &start_ap)) {
      #ifdef FILE_123_REASSEMBLY_DEBUG
      lock_fprintf(stdout,
          "\nThread #%d: no holes remain in candidate %p\n",
          work->id, (*c)->b);
      #endif
      // Perform a final validation before breaking
      validates = file_123_file_validate_full(*c, &validates_to);
      #ifdef FILE_123_REASSEMBLY_DEBUG
      lock_fprintf(stdout, "[final validation] %s – no holes left in candidate %p\n",
        validates ? "SUCCESS" : "FAILED", (*c)->b);
      #endif
      break;
    }


    char target_type = block_type_for_slot(*c, hole_idx);
    #ifdef FILE_123_REASSEMBLY_DEBUG
    lock_fprintf(stdout,
      "Get block choice [start] \n[loop] Tick=%" PRIu64 " | Candidate=%p | flavor=%d | newblock=%" PRId64 "\n",
      tick, *c, (*c)->flavor, (*c)->newblock);
    #endif


    // Get a block that matches the expected type
    int64_t blk_ap = File123_reassembly_get_block_choice(
                          *c, &start_ap, hole_idx, target_type);


    #ifdef FILE_123_REASSEMBLY_DEBUG
    lock_fprintf(stdout,
        "Get block choice [end] \n[loop] Tick=%" PRIu64 " | Candidate=%p | flavor=%d | newblock=%" PRId64 "\n",
        tick, *c, (*c)->flavor, (*c)->newblock);
    #endif


    if (blk_ap == -1) {
      #ifdef FILE_123_REASSEMBLY_DEBUG
      lock_fprintf(stdout,
          "\nThread #%d: no %c-type block available for slot %" PRId64
          "; abandoning candidate\n",
          work->id, target_type, hole_idx);
      #endif
      destroy_candidate(c);
      return;
    }


    // Place the block
    (*c)->newblock = filemirror_actual_blocknumber(
                          scalpel_state.filemirror, blk_ap);
    #ifdef FILE_123_REASSEMBLY_DEBUG
    lock_fprintf(stdout,
      "Extend [start]\n[loop] Tick=%" PRIu64 " | Candidate=%p | flavor=%d | newblock=%" PRId64 "\n",
      tick, *c, (*c)->flavor, (*c)->newblock);
    #endif
    File123_reassembly_extension_successful(work->id, *c, hole_idx);
    #ifdef FILE_123_REASSEMBLY_DEBUG
    lock_fprintf(stdout,
      "Extend [end]\n[loop] Tick=%" PRIu64 " | Candidate=%p | flavor=%d | newblock=%" PRId64 "\n",
      tick, *c, (*c)->flavor, (*c)->newblock);
    #endif


    if (scalpel_state.mode_verbose){
      lock_fprintf(stdout,
        "Thread #%d placed apparent %" PRId64 " at slot %" PRId64 "\n",
        work->id, blk_ap, hole_idx);
    }


    #ifdef FILE_123_REASSEMBLY_DEBUG
    lock_fprintf(stdout,
      "validate [start] \n[loop] Tick=%" PRIu64 " | Candidate=%p | flavor=%d | newblock=%" PRId64 "\n",
      tick, *c, (*c)->flavor, (*c)->newblock);
    #endif


    // Validate
    validates = file_123_file_validate_full(*c, &validates_to);
    #ifdef FILE_123_REASSEMBLY_DEBUG
    lock_fprintf(stdout, "[validate result] %s after placing block %" PRId64 "\n",
      validates ? "SUCCESS" : "FAILED", hole_idx);
    #endif
    if (validates){
      break;
    }


    #ifdef FILE_123_REASSEMBLY_DEBUG
    lock_fprintf(stdout,
      "validate [end] \n[loop] Tick=%" PRIu64 " | Candidate=%p | flavor=%d | newblock=%" PRId64 "\n",
      tick, *c, (*c)->flavor, (*c)->newblock);
    #endif


    // Gallop
    int64_t hole_end = find_hole_end(*c, hole_idx);
    #ifdef FILE_123_REASSEMBLY_DEBUG
    lock_fprintf(stdout, "Promising queue size: %" PRIu64 "\n",
                 (uint64_t)promising_queue.queuelength);
    #endif


    File123_reassembly_gallop(work->id, *c,
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


  // Exit paths
  if (validates) {
    (*c)->flavor = VALIDATED;
    lock_fprintf(stdout,
        "\nThread #%d VALIDATED candidate %p  UUIDs\n%s / %s\n",
        work->id, (*c)->b, uuidp, uuidc);




    uint64_t blocksize = scalpel_state.blocksize;
    uint64_t validated_blocks = (validates_to + blocksize - 1) / blocksize;
    resize_blockvector((*c)->b, validated_blocks);


    #ifdef FILE_123_REASSEMBLY_DEBUG
      display_blockvector((*c)->b, "final BV");
      File123ReassemblyState *dbg_st =
          (File123ReassemblyState*)carve_get_state((*c)->carvehashkey);
      file123_print_carve_state(dbg_st);
      file123_free_carve_state((void **)&dbg_st);
    #endif
    write_candidate(c, false);
  } else {
    lock_fprintf(stdout,
        "\nThread #%d abandoning candidate %p  UUIDs\n%s / %s\n",
        work->id, (*c)->b, uuidp, uuidc);
    #ifdef FILE_123_REASSEMBLY_DEBUG
      display_blockvector((*c)->b, "final BV");
      File123ReassemblyState *dbg_st2 =
          (File123ReassemblyState*)carve_get_state((*c)->carvehashkey);
      file123_print_carve_state(dbg_st2);
      file123_free_carve_state((void **)&dbg_st2);
    #endif
    if (scalpel_state.write_promising) {
      (*c)->flavor = PROMISING;
      file123_resize_blockvector_to_expected(*c);
      write_candidate(c, false);
    } else {
      destroy_candidate(c);
      return;
    }
  }
}
