//
// Scalpel3 is Copyright(C) 2021 - 2025 by Golden G.Richard III and
// contributors.
//
// This program is free software : you can redistribute it and / or modify it
// under the terms of the GNU General Public License as published by the Free
// Software Foundation, either version 3 of the License, or (at your option) any
// later version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
// FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
// details.
//
// You should have received a copy of the GNU General Public License along with
// this program.  If not, see <https://www.gnu.org/licenses/>.
//
//
//------------------------------------------------------------------------
// Additional Integration Terms
// ------------------------------------------------------------------------
// Linking or embedding Scalpel3 (statically or dynamically) into another
// program such that the resulting executable or library forms a single
// combined work constitutes creation of a derivative work under the GPL.
// Any party distributing such a combined work must make the entire source
// code available under the terms of the GPL as well.
//
// Commercial entities wishing to use Scalpel3 in a closed-source or proprietary
// product or requiring support must obtain a separate commercial license.
//
// For commercial licensing or questions about integration, contact:
// Golden G. Richard III (golden@cct.lsu.edu).
//
// Please see LICENSE.md and README.md for further information.
//
//

/**
 * @author: Samuel Goodwin
 *
 * This file is used to validate PDF files that are contiguous in memory.
 *
 * A PDF file follows the general layout shown below, with some notable omissions for simplicity sake:
 *
 * --PDF version header
 * --Object 1
 * --Object 2
 * --Object 3
 * --Object N
 * --Xref Table or Stream
 * --Startxref offset incdicator
 * --PDF Footer
 *
 * There are many exceptions to this structure, most notably the fact that multiple
 * xref tables/streams including both types may be present within the same file due to
 * incremental updates. This file aims to leverage the xref tables and streams of a given
 * file, using the documented offsets of each object within the file to ensure each object
 * is located at their expected location within the file. If successful, this provides a high
 * degree of certainty that the file is uncorrupted and complete.
 */

#include "scalpel.h"
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <stdint.h>
#include <zlib.h>


#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-variable"
#pragma GCC diagnostic ignored "-Wunused-but-set-variable"
#pragma GCC diagnostic ignored "-Wunused-function"
#pragma GCC diagnostic ignored "-Wunused-parameter"
#pragma GCC diagnostic ignored "-Wtype-limits"

//#define PDFTESTING

// Define stream conditions
#define LENGTHNOTFOUND -1
#define INBLOCK 1
#define INNEXTBLOCK 2
#define MULTIBLOCK 3

// Define block selection modes
#define NEXTOBJECT 1
#define FINDENDSTREAM 2
#define EXTENDSTREAMFROMSTART 3
#define EXTENDSTREAMFROMEND 4

// Define candidate extension modes
#define OBJECTEXTNSION 1
#define ENDSTREAMEXTENSION 2

#define NOFRAG

#define INCOMPLETESTREAMDICT 1
/**
 * Holds the data used to do prelimary analysis of
 * Xref tables. I might merge this into another struct
 * at some point in the future.
 */
typedef struct XrefObject{
    int64_t offset;
    int64_t prev_offset;
} XrefObject;

/**
 * Holds the data necessary to check whether
 * a PDF object is at its expected location in
 * the file
 */
typedef struct Object{
    int obj_num;    // The object's identifier
    uint64_t obj_offset; // The expected location of this object
} Object;

/**
 * Main struct used for validation.
 * Emulates an xref table and enables
 * complete validation of an xref as part
 * of a file
 */
typedef struct XrefTables{
    Object *entries;    // An array of Objects derived from this table
    int count;          // The # of objects in this table
} XrefTables;

/**
 * Used to store information about xrefs in
 * relation to individual blocks.
 */
typedef struct XrefParameters{
    int64_t xref_start;    // Offset of start of xref
    int64_t xref_end;      // Offset of end of xref
    int8_t conditional_flag;
    int8_t xref_type;   // 0 = table, 1 = stream
} XrefParameters;

typedef struct PDFBlockState{
    int first_obj;
    XrefParameters *xref_block_data;
    int8_t num_xrefs;
} PDFBlockState;

typedef struct PDFCarveState{
    XrefTables *xref_tables;  // Points to linked list of XrefTables
    size_t num_tables;       // Number of xref tables found
    bool incomplete_obj;
} PDFCarveState;

/**
 * Hashing struct for faster validation
 */
typedef struct ObjectHashEntry {
    int obj_num;           // PDF object number
    int entry_idx;         // Index in entries array within that table
    struct ObjectHashEntry *next;  // For chaining on collision
} ObjectHashEntry;

/**
 * Hashing struct for faster validation
 */
typedef struct ObjectHashTable {
    ObjectHashEntry **buckets;  // Array of bucket pointers
    int bucket_count;           // Size of bucket array
    int entry_count;            // Total entries stored
} ObjectHashTable;

typedef struct StreamReassembler {
    z_stream strm;           // current decompression state
    z_stream checkpoint;     // last known-good state
    size_t total_verified;   // total bytes successfully decompressed
    unsigned char *output;   // accumulated decompressed output
    size_t output_len;
    size_t output_capacity;
} StreamReassembler;

/*******************************************************/
/*                HELPER FUNCTION PROTOTYPES           */
/*******************************************************/

int extract_int(char* data, int64_t offset, int64_t length, int64_t *end_offset);

int extract_obj_num(char* data, size_t offset, uint64_t length);

int detect_xref_type(const char *data, int64_t offset, int64_t length, int64_t *out_offset);

Object* analyze_xref(char* data, int64_t offset, int64_t length, int *xref_count, uint64_t *xref_end_offset);

int extract_index_array(const char *data, int64_t offset, size_t **index_array_out, size_t *index_count_out, int64_t length);

char *decompress_with_uncompress(const char *input, size_t input_length, size_t *out_length);

char *apply_png_predictor_up(const char *input, size_t input_length, size_t columns, size_t *out_length);

char *extract_stream_data(char *data, int64_t offset, size_t *out_length, int64_t length, uint64_t *xref_end_offset);

Object* store_xref_stream(const char *decoded_data, size_t decoded_len, const size_t *index_array, size_t index_count, const int *w_array, size_t size_value, int *num_type1);

uint32_t read_be(const unsigned char *data, size_t len, size_t max_len);

int extract_w_array(const char *data, int64_t offset, int *w_out, int64_t length);

Object* store_xref_table(char *data, int64_t offset, int *num_entries, int64_t length, uint64_t *xref_end_offset);

int validate_at_offset(char *data, int64_t offset, int obj_num1, int64_t length);

int64_t find_prev_entry(char *data, int64_t length, int64_t offset, int xref_type);

int64_t find_stm_entry(char *data, int64_t length, int64_t offset, int xref_type);

int64_t find_xref_stream_start(char *data, int64_t offset);

const char *scan_buf_for_xref(char *data, uint64_t length, uint64_t search_pos, int *xref_type);

static inline const char *min_xref_start(const char *a, const char *b, const char *c, int *out_type);

static int compare_objects(const void *a, const void *b);

void sort_xref_data_by_offset(XrefTables *data);

bool add_xref_table(PDFCarveState *state, XrefTables *xref_table, int table_idx);

int check_startxref(char *data, uint64_t validation_cutoff);

int* list_candidate_objects(char *data, uint64_t length, int *obj_count);

Object* scan_blocks_for_xref(CarveInfo *candidate, BlockVector *scan_bv, int *entry_count,
                      int64_t **out_xref_blocks, int *out_xref_block_count);
Object* scan_blocks_for_xref_at_offset(CarveInfo *candidate, BlockVector *scan_bv, int *entry_count,
                      int64_t **out_xref_blocks, int *out_xref_block_count, int32_t expected_offset);

int check_last_object_length(char* data, uint64_t length, int32_t *out_startstream_local_offset, int32_t *out_endstream_local_offset, int *out_blocks_to_extend);

int stream_reassembler_init(StreamReassembler *r, const unsigned char *first_block, 
                     size_t block_size, size_t stream_offset);

int stream_reassembler_try_block(StreamReassembler *r, const unsigned char *block, size_t block_size);

void stream_reassembler_free(StreamReassembler *r);

static inline ObjectHashTable* hash_table_create(int bucket_count);

static inline void hash_table_insert(ObjectHashTable *table, int obj_num, int entry_idx);

static inline bool hash_table_lookup(ObjectHashTable *table, int obj_num, int *out_entry_idx);

static inline void hash_table_free(ObjectHashTable *table);

/*******************************************************/
/*              BLOCK STATE FUNCTION PROTOTYPES        */
/*******************************************************/

static inline bool pdf_serialize_block_state(void **state, FILE *fp,
                                             StateSerialization mode);

static inline void *pdf_clone_block_state(const void *srcstate);

static inline void pdf_free_block_state(void **state);

static inline void pdf_print_block_state(const void *state);

static inline PDFBlockState *pdf_get_blockstate_from_apparent(CarveInfo *candidate,
                                                              int64_t apparent,
                                                              int64_t *out_actual);
/*******************************************************/
/*              CARVE STATE FUNCTION PROTOTYPES        */
/*******************************************************/

static inline bool pdf_serialize_carve_state(void **state, FILE *fp,
                                             StateSerialization mode);

static inline void *pdf_clone_carve_state(const void *srcstate);

static inline void pdf_free_carve_state(void **state);

static inline void pdf_print_carve_state(const void *state);

/*******************************************************/
/*              REASSEMBLY FUNCTION PROTOTYPES         */
/*******************************************************/

static void pdf_reassembly_init_candidate(int id,
                        CarveInfo *candidate,
                        uuid_string_t uuidp,
                        uuid_string_t uuidc);

static void pdf_reassembly_prepare_for_extension(
    int id,
    CarveInfo *candidate,
    int num_blocks,
    int mode);

int64_t pdf_reassembly_get_block_choice(CarveInfo *candidate,
                                        int obj_num,
                                        int32_t endstream_local_offset,
                                        uint64_t streamstart_block_app,
                                        uint64_t endstream_block_app,
                                        int32_t stream_blocks_extended,
                                        int mode);

static void pdf_reassembly_did_not_validate(int id,
					   CarveInfo *candidate,
					   uint64_t validates_to,
					   int64_t block_choice);

static void pdf_reassembly_extension_successful(int id,
					        CarveInfo *candidate,
                            uint64_t logical_slot_index);

static int64_t pdf_reassembly_backtrack(int id,
				       CarveInfo *candidate,
				       uuid_string_t uuidp,
				       uuid_string_t uuidc);

void pdf_reassembly(ThreadWork *work,
		   CarveInfo **c,
		   uuid_string_t uuidp,
		   uuid_string_t uuidc);

/*******************************************************/
/*          VALIDATION FUNCTION PROTOTYPES             */
/*******************************************************/

static inline uint32_t pdf_block_validate(char *data,
    uint64_t length,
    BlockValidationDecision *decision,
    uint64_t *validates_to,
    uint32_t needleidx,
    uint32_t blocksize,
    void *blockhashkey);

static inline void pdf_file_validate(char *data,
    uint64_t length,
    bool *validates,
    uint64_t *validates_to,
    bool *promising,
    uint32_t needleidx,
    uint32_t blocksize,
    void *carvehashkey);

/*******************************************************/
/*              HELPER FUNCTION DEFINITIONS            */
/*******************************************************/

/**
 * @description         Extracts an integer at an offset.
 *
 * @param data          The buffer containing the candidate.
 * @param offset        The offset of the most significant digit.
 * @param length        The length of the buffer.
 *
 * @return              The extracted integer, or -1 on failure.
 */
/**
 * @description         Extracts an integer at an offset.
 *
 * @param data          The buffer containing the candidate.
 * @param offset        The offset of the most significant digit.
 * @param length        The length of the buffer.
 * @param end_offset    If non-NULL, set to the offset just past the last digit parsed.
 *
 * @return              The extracted integer, or -1 on failure.
 */
int extract_int(char* data, int64_t offset, int64_t length, int64_t *end_offset) {
    if (data == NULL) return -1;

    while (offset < length - 1 && !isdigit(data[offset])) offset++;

    int64_t start = offset;

    while (offset < length - 1 && isdigit(data[offset])) offset++;

    int64_t int_length = offset - start;
    if (int_length <= 0) return -1;

    if (end_offset) *end_offset = offset;

    char temp[int_length + 1];
    memcpy(temp, &data[start], int_length);
    temp[int_length] = '\0';

    return atoi(temp);
}

/**
 * Extracts the object number of an object by parsing
 * the format "int int obj" where the first int is the
 * object num.
 *
 * @param data          The buffer containing the candidate.
 * @param offset        The offset of the "o" in "obj".
 * @param length        The length of the candidate.
 *
 * @return              The extracted object number.
 */
int extract_obj_num(char *data, size_t offset, uint64_t length) {
    if (!data || length == 0 || offset >= length) return -1;

    // Move backward from the 'o' in "obj"
    ssize_t i = (ssize_t)offset - 1;

    // Skip whitespace before the second integer
    while (i >= 0 && isspace((unsigned char)data[i])) i--;

    // Skip the digits of the second integer
    while (i >= 0 && isdigit((unsigned char)data[i])) i--;

    // Skip whitespace between the two integers
    while (i >= 0 && isspace((unsigned char)data[i])) i--;

    // i should point to the last digit of the first integer
    ssize_t end = i;
    if (end < 0)
        return -1;

    // Walk backward to find the start of the first integer
    while (i >= 0 && isdigit((unsigned char)data[i])) i--;

    ssize_t start = i + 1;
    if (start > end || start < 0) return -1;

    size_t num_len = (size_t)(end - start + 1);
    if (num_len >= 32) return -1;

    char num_str[32];
    memcpy(num_str, data + start, num_len);
    num_str[num_len] = '\0';

    return atoi(num_str);
}

/**
 * @description         Determines the type of xref at the found offest.
 *
 * @param data          The buffer containing the candidate.
 * @param offset        The offset of the xref.
 * @param length        The length of the buffer.
 *
 * @return              1 for table, 2 for stream, 0 for none, -1 on error.
 */
int detect_xref_type(const char *data, int64_t offset, int64_t length, int64_t *out_offset) {
    if (offset >= length) {
        return -1;
    }
    if ((offset + 4 <= length && !memcmp(&data[offset], "xref", 4)) ||
        (offset + 5 <= length && !memcmp(&data[offset], "\nxref", 5)) ||
        (offset + 5 <= length && !memcmp(&data[offset], "\rxref", 5))) return 1;  // Table

    if(data[offset] == '0'){
        int64_t temp_offset = offset;
        while(temp_offset < length && data[temp_offset] == '0') temp_offset++;
        if(temp_offset + 8 <= length && !memcmp(&data[temp_offset], " 65535 f", 8)){
            while(temp_offset > 0){
                if(!memcmp(&data[temp_offset], "xref", 4)){
                    *out_offset = temp_offset;
                    return 1; // Table
                }
                temp_offset--;
            }
        }
    }

    const char *obj_pos = (const char*)memmem(&data[offset], (size_t)(length - offset), " obj", 4);
    if (obj_pos != NULL) {
        int64_t obj_offset = offset + (obj_pos - &data[offset]);
        // Isolate the object dictionary and search for xref stream indicator
        int64_t dict_end = -1;
        int nested_level = 0;
        for (int64_t i = obj_offset; i < length - 1; i++) {
            if (data[i] == '<' && data[i + 1] == '<') {
                nested_level++;
                i++;
            } else if (data[i] == '>' && data[i + 1] == '>') {
                nested_level--;
                if (nested_level == 0) {
                    dict_end = i + 2;
                    break;
                }
                i++;
            }
        }
        if (dict_end == -1) {
            return -2;  // No valid dictionary found
        }
        if (memmem(&data[obj_offset], dict_end - obj_offset, "/Type /XRef", 11) != NULL ||
            memmem(&data[obj_offset], dict_end - obj_offset, "/Type/XRef", 10) != NULL) {
            return 2;  // Stream
        }
    }
    return 0;
}

/**
 * @description         Scans backwards through the dictionary
 *                      of an xref stream the find the start of the object.
 *
 * @param data          The buffer holding the candidate.
 * @param offset        The offset of "/Type/Xref".
 *
 * @return              The relevant offset.
 */
int64_t find_xref_stream_start(char *data, int64_t offset) {
    /* Scan backwards from offset looking for " obj" */
    while (offset > 0) {
        offset--;
        if (offset >= 3 && !memcmp(&data[offset], " obj", 4)) {
            /* Found " obj", now scan backwards for the object number */
            int64_t scan = offset - 1;
            while (scan > 0 && isspace(data[scan])) scan--;

            /* scan is now at the last digit of the object number */
            while (scan > 0 && isdigit(data[scan])) scan--;

            while (scan > 0 && isspace(data[scan])) scan--;

            while (scan > 0 && isdigit(data[scan])) scan--;

            /* scan is now at a non-digit; move forward to the start of the number */
            scan++;
            return scan;  /* This is the start of the xref stream object */
        }
    }
    return -1;
}

/**
 * @description         Compares the addresses of 3 xref tables/streams
 *                      and returns the pointer to the earliest one.
 *
 * @param a             Address of next traditional xref table.
 * @param b             Address of next xref stream.
 * @param c             Address of next xref stream(different format).
 * @param out_type      The type of the earliest xref entry.
 * @return              The earliest xref.
*/
static inline const char *min_xref_start(const char *a, const char *b, const char *c, int *out_type) {
    const char *min = NULL;
    *out_type = 0;

    if (a && (!min || a < min)) { min = a; *out_type = 1; }
    if (b && (!min || b < min)) { min = b; *out_type = 2; }
    if (c && (!min || c < min)) { min = c; *out_type = 2; }

    return min;
}

/**
 * @description         Finds the /Prev entry in an xref's dictionary
 *                      to keep track of how many terminal tables
 *                      are in the validated portion of the candidtate.
 *
 * @param data          The buffer containing the candidate.
 * @param length        The length of the buffer.
 * @param offset        The offset of the xref.
 * @param xref_type     The type of xref; 1 for table; 2 for stream.
 * @return              The offset of the previous xref.
 */
int64_t find_prev_entry(char *data, int64_t length, int64_t offset, int xref_type){
    int nested_level = 1;
    int64_t prev = -1;
    if(xref_type == 1){
        while ((offset < length - 2) && memcmp(&data[offset], "<<", 2))offset++;
        if(offset < length - 2) offset += 2;
        while (offset < length - 2 && nested_level > 0){
            if ((offset < length - 2) && !memcmp(&data[offset], "<<", 2))nested_level++;
            if ((offset < length - 2) && !memcmp(&data[offset], ">>", 2))nested_level--;

            // Extract previous Xref entries if they exist
            if ((offset < length - 5) && !memcmp(&data[offset], "/Prev", 5)){
                prev = extract_int(data, offset, length, NULL);
            }
            offset++;
        }
    }

    if(xref_type == 2){
        while (offset >= 0 &&memcmp(&data[offset], "obj", 3))offset--;
        while ((offset < length - 2) && memcmp(&data[offset], "<<", 2))offset++;
        if(offset < length - 2) offset+= 2;
        while (offset < length - 2 && nested_level > 0){
            if (!memcmp(&data[offset], "<<", 2))nested_level++;
            if (!memcmp(&data[offset], ">>", 2))nested_level--;
            // Extract previous Xref entries if they exist
            if ((offset < length - 5) && !memcmp(&data[offset], "/Prev", 5)){
                prev = extract_int(data, offset, length, NULL);
            }
            offset++;
        }
    }
    return prev;
}

/**
 * @description         Finds the /XRefStm entry in an xref's dictionary.
 *                      This is another crucial part of counting the # of
 *                      terminal tables in the candidate.
 *
 * @param data          The buffer containing the candidate.
 * @param length        The length of the buffer.
 * @param offset        The offset of the xref.
 * @param xref_type     The type of xref; 1 for table; 2 for stream
 * @return              The offset of the supplimentary table.
 */
int64_t find_stm_entry(char *data, int64_t length, int64_t offset, int xref_type){
    int nested_level = 1;
    int64_t stm_offset = -1;
    if(xref_type == 1){
        while ((offset < length - 2) && memcmp(&data[offset], "<<", 2))offset++;
        if(offset < length - 2) offset += 2;
        while (offset < length - 2 && nested_level > 0){
            if ((offset < length - 2) && !memcmp(&data[offset], "<<", 2))nested_level++;
            if ((offset < length - 2) && !memcmp(&data[offset], ">>", 2))nested_level--;

            // Extract previous Xref entries if they exist
            if ((offset < length - 8) && !memcmp(&data[offset], "/XRefStm", 8)){
                stm_offset = extract_int(data, offset, length, NULL);
            }
            offset++;
        }
    }

    if(xref_type == 2){
        while (offset >= 0 && memcmp(&data[offset], "obj", 3))offset--;
        while ((offset < length - 2) && memcmp(&data[offset], "<<", 2))offset++;
        if(offset < length - 2) offset+= 2;
        while (offset < length - 2 && nested_level > 0){
            if (!memcmp(&data[offset], "<<", 2))nested_level++;
            if (!memcmp(&data[offset], ">>", 2))nested_level--;
            // Extract previous Xref entries if they exist
            if ((offset < length - 8) && !memcmp(&data[offset], "/XRefStm", 8)){
                stm_offset = extract_int(data, offset, length, NULL);
            }
            offset++;
        }
    }
    return stm_offset;
}

/**
 * @description             Extract the W array, important in decoding an xref stream.
 *                          The array contains the width values of the entry type,
 *                          second field, and third field of the entry respectively.
 * @param data              The buffer containing the candidate.
 * @param offset            The offset of the W array.
 * @param w_out             The output array to store the W values.
 * @param length            The length of the buffer.
 *
 * @return                  0 on success, negative values on failure.
 */
int extract_w_array(const char *data, int64_t offset, int *w_out, int64_t length) {
    int64_t i = offset;

    if (data[i] != '/' || data[i+1] != 'W') return -1;
    i += 2;

    // Find start of the array values
    while (i < length && isspace(data[i])) i++;
    if (data[i] != '[') return -2;
    i++;

    // Parse up to 3 integers
    for (int count = 0; count < 3; count++) {
        while (i < length && isspace(data[i])) i++;
        if (!isdigit(data[i])) return -3;

        int val = 0;
        while ( i < length && isdigit(data[i])) {
            val = val * 10 + (data[i] - '0');
            i++;
        }
        w_out[count] = val;
    }

    return 0;
}

/**
 * @description             Extracts the raw data within an xref stream for
 *                          decompression and decoding.
 *
 * @param data              The buffer containing the candidate.
 * @param offset            The offset of the stream.
 * @param out_length        The output length of the extracted stream data.
 * @param length            The length of the buffer.
 *
 * @return                  A pointer to the extracted stream data.
 */
char *extract_stream_data(char *data, int64_t offset, size_t *out_length, int64_t length, uint64_t *xref_end_offset) {

    while((offset - 6) < length && memcmp(&data[offset], "stream", 6))offset++;
    offset += 6;
    int64_t stream_start = offset;
    int64_t stream_end = stream_start;
    while(stream_end + 9 <= length && memcmp(&data[stream_end], "endstream", 9))stream_end++;
    int64_t stream_length = stream_end - stream_start;
    *xref_end_offset = stream_end;
    char* stream_data = (char*)malloc(stream_length*sizeof(char));
    if(!stream_data){
        return(NULL);
    }
    memcpy(stream_data, &data[stream_start], stream_length*sizeof(char));
    *out_length = stream_length;

    return(stream_data);

}

/**
 * @description             Parses and stores the data within a traditional xref table
 *                          into an array of Object types. Each table starts with
 *                          and likely contains multiple entries structured as:
 *                          (int) (int). The first field indicates the starting object
 *                          number, and the second field indicates how many objects follow,
 *                          incrementing the object number by +1. An object entry follows
 *                          the structure:
 *                          (int) (int) (n || f) the first field indicated the offset of
 *                          the object, the second field indicated the object generation
 *                          number and the third field indicates whether the object is
 *                          in use - f for free and n for in use. We only track and store
 *                          objects of type n because they are the only objects present in
 *                          the file and hence the only objects relevant for file validation.
 *
 * @param data              The buffer containing the candidate.
 * @param offset            The offset of the xref table.
 * @param num_entries       A pointer to an integer to store the number of entries.
 * @param length            The length of the buffer.
 * @param xref_end_offset   The offset of the end of this xref.
 *
 * @return                  A pointer to an array of Object types.
 */
Object* store_xref_table(char *data, int64_t offset, int *num_entries, int64_t length, uint64_t *xref_end_offset) {
    *num_entries = 0;

    if ((offset - 4 < length) && !memcmp(&data[offset], "xref", 4)) offset += 4;
    while (offset < length && isspace(data[offset])) offset++;

    // First pass count how many 'n' entries exist
    int count = 0;
    int64_t scan = offset;
    while ((scan - 7 < length) && memcmp(&data[scan], "trailer", 7)) {
        if (data[scan] == 'n'){
            count++;
        }
        scan++;
    }

    *num_entries = count;
    Object *entries = (Object*)malloc(sizeof(Object) * count);
    if (!entries) return NULL;
    if (count == 0) return NULL;

    // Second pass parse each section
    int entry_index = 0;

    while (offset < length - 7 && memcmp(&data[offset], "trailer", 7) && data[offset] != '\0') {
        if(entry_index == *num_entries){
            break;
        }

        while (offset < length && isspace(data[offset])) offset++;

        // Parse section header: start_obj and count
        int64_t new_offset = 0;
        int start_obj = extract_int(data, offset, length, &new_offset);
        if (start_obj == -1) break;
        offset = new_offset;
        while (offset < length && isspace(data[offset])) offset++;

        int obj_count = extract_int(data, offset, length, &new_offset);
        if (obj_count == -1) break;
        offset = new_offset;
        while (offset < length && isspace(data[offset])) offset++;

        // Parse obj_count lines of entries
        for (int i = 0; i < obj_count; i++) {
            if (offset >= length - 20) break;
            if (entry_index >= *num_entries) break;

            int byte_offset = extract_int(data, offset, length, &new_offset);
            if (byte_offset == -1) break;
            offset = new_offset;
            while (offset < length && isspace(data[offset])) offset++;

            int gen_num = extract_int(data, offset, length, &new_offset);
            if (gen_num == -1) break;
            offset = new_offset;
            while (offset < length && isspace(data[offset])) offset++;

            if (offset >= length) break;
            char type = data[offset];
            offset++;  // always advance past the type character

            // Skip to end of line
            while (offset < length && data[offset] != '\n' && data[offset] != '\r') offset++;
            while (offset < length && (data[offset] == '\n' || data[offset] == '\r')) offset++;

            if (type == 'n' && byte_offset > 0) {
                Object entry;
                entry.obj_num = start_obj + i;
                entry.obj_offset = byte_offset;
                entries[entry_index++] = entry;
            } else if (type == 'n' && byte_offset == 0) {
                (*num_entries)--;
            }
        }
    }
    *xref_end_offset = offset;
    return entries;
}

/**
 * @description             Create a new hash table with specified bucket count.
 *
 * @param bucket_count      Size of hash table.
 * @return                  Allocated and initialized hash table.
 */
static inline ObjectHashTable* hash_table_create(int bucket_count) {
    if (bucket_count <= 0) return NULL;

    ObjectHashTable *table = (ObjectHashTable*)malloc(sizeof(ObjectHashTable));
    if (!table) return NULL;

    table->buckets = (ObjectHashEntry**)calloc(bucket_count, sizeof(ObjectHashEntry*));
    if (!table->buckets) {
        free(table);
        return NULL;
    }

    table->bucket_count = bucket_count;
    table->entry_count = 0;
    return table;
}

/**
 * Hash function: maps object number to bucket index.
 * Uses modulo hashing for simplicity.
 */
static inline int hash_function(int obj_num, int bucket_count) {
    return (obj_num % bucket_count + bucket_count) % bucket_count;
}

/**
 * @description         Insert a new object mapping into the hash table.
 *
 * @param table         Hash table to insert into.
 * @param obj_num       Object number (key).
 * @param table_idx     Index in xref_tables array.
 * @param entry_idx     Index in entries array within that table.
 */
static inline void hash_table_insert(ObjectHashTable *table, int obj_num, int entry_idx) {
    if (!table) return;

    int bucket = hash_function(obj_num, table->bucket_count);
    ObjectHashEntry *entry = (ObjectHashEntry*)malloc(sizeof(ObjectHashEntry));
    if (!entry) return;

    entry->obj_num = obj_num;
    entry->entry_idx = entry_idx;
    entry->next = table->buckets[bucket];

    table->buckets[bucket] = entry;
    table->entry_count++;
}

/**
 * @description             Look up an object in the hash table.
 * @param table             Hash table to search
 * @param obj_num           Object number to find
 * @param out_entry_idx     Pointer to store entry index (output)
 * @return                  true if found, false if not found
 */
static inline bool hash_table_lookup(ObjectHashTable *table, int obj_num, int *out_entry_idx) {
    if (!table || !out_entry_idx) return false;

    int bucket = hash_function(obj_num, table->bucket_count);
    ObjectHashEntry *entry = table->buckets[bucket];

    while (entry) {
        if (entry->obj_num == obj_num) {
            *out_entry_idx = entry->entry_idx;
            return true;
        }
        entry = entry->next;
    }

    return false;
}

/**
 * @description             Free all memory associated with a hash table.
 * @param table             Hash table to free.
 */
static inline void hash_table_free(ObjectHashTable *table) {
    if (!table) return;

    if (table->buckets) {
        for (int i = 0; i < table->bucket_count; i++) {
            ObjectHashEntry *entry = table->buckets[i];
            while (entry) {
                ObjectHashEntry *temp = entry;
                entry = entry->next;
                free(temp);
            }
        }
        free(table->buckets);
    }
    free(table);
}

/**
 * @description         Compares the value of an xref entry to the value found
 *                      at its expected offset to ensure the object is in its
 *                      expected location.
 *
 * @param data          The buffer containing the candidate.
 * @param offset        The offset of the object to validate.
 * @param obj_num1      The expected object number.
 * @param length        The length of the buffer.
 *
 * @return              1 if valid, 0 if invalid, -1 on error.
 */
int validate_at_offset(char *data, int64_t offset, int obj_num1, int64_t length) {
    // No data Buffer
    if (!data) return -1;

    // Offset is out of bounds
    if (offset < 0 || offset >= length) return -2;

    while (offset < length && isspace((unsigned char)data[offset])) {
        offset++;
    }

    // Need another block to parse
    if (offset >= length || !isdigit((unsigned char)data[offset])) {
        return -3;
    }

    int obj_num2 = 0;
    int64_t start = offset;
    while (offset < length && isdigit(data[offset])) {
        offset++;
    }

    int64_t obj2_length = offset - start;
    if (obj2_length <= 0){
         return -4;
    }
    char temp[obj2_length + 1];
    memcpy(temp, &data[start], obj2_length);
    temp[obj2_length] = '\0';

    obj_num2 = atoi(temp);


    if(obj_num1 == obj_num2){
        return 1;
    }

    // Not a match

    fflush(stdout);
    return 0;
}

/** @description        Helper function for xref storage
 *                      Reads a big-endian value from a byte array.
 *
 * @param data          The buffer containing the candidate
 * @param len           The length of the buffer.
 * @param max_len       The maximum length to read.
 *
 * @return              The read value.
 */
uint32_t read_be(const unsigned char *data, size_t len, size_t max_len) {
    if (!data || len == 0 || len > 4 || len > max_len) {
        return 0;
    }
    uint32_t val = 0;
    for (size_t i = 0; i < len; i++) {
        val = (val << 8) | data[i];
    }
    return val;
}

/**
 * @description             Parses and stores the data within an xref stream
 *                          into an array of Object types. Each entry in
 *                          the stream is defined by the /W array, which
 *                          specifies the byte widths of each field in the
 *                          entry. The first field indicates the type of
 *                          entry, the second field's meaning depends on
 *                          the type, and the third field's meaning also
 *                          depends on the type. We only track and store
 *                          objects of type 1 because they are the only
 *                          objects present in the file and hence the only
 *                          objects relevant for file validation.
 *
 * @param decoded_data      The buffer containing the decoded xref stream data.
 * @param decoded_len       The length of the decoded data.
 * @param index_array       The /Index array specifying object number ranges.
 * @param index_count       The count of entries in the /Index array.
 * @param w_array           The /W array specifying field widths.
 * @param size_value        The Size value from the xref stream dictionary.
 * @param num_type1         A pointer to store the number of type 1 entries found.
 *
 * @return                  A pointer to an array of Object types.
 */
Object* store_xref_stream(const char *decoded_data, size_t decoded_len,
    const size_t *index_array, size_t index_count,
    const int *w_array, size_t size_value, int *num_type1) {
    *num_type1 = 0;
    size_t entry_len = w_array[0] + w_array[1] + w_array[2];
    const unsigned char *ptr = (const unsigned char *)decoded_data;
    Object *entries = NULL;
    size_t object_index = 0;
    int done = 0;  // flag to break out of both loops

    // If no /Index array, use fallback: Index [0 Size]
    if (!index_array || index_count == 0) {
        for (uint32_t obj_num = 0; obj_num < size_value; obj_num++, object_index++) {
            size_t offset = object_index * entry_len;
            if (offset + entry_len > decoded_len) break;

            const unsigned char *entry = ptr + offset;
            uint32_t type   = (w_array[0] > 0) ? read_be(entry, w_array[0], decoded_len - offset) : 1;
            uint32_t field2 = (w_array[1] > 0) ? read_be(entry + w_array[0], w_array[1], decoded_len - offset - w_array[0]) : 0;
            uint32_t field3 = (w_array[2] > 0) ? read_be(entry + w_array[0] + w_array[1], w_array[2], decoded_len - offset - w_array[0] - w_array[1]) : 0;

            if (type == 1 && field2 > 0) {
                Object *temp = realloc(entries, sizeof(Object) * (*num_type1 + 1));
                if (!temp){
                    free(entries);
                    return NULL;
                }
                entries = temp;
                entries[*num_type1] = (Object){
                    .obj_num = obj_num,
                    .obj_offset = field2
                };
                (*num_type1)++;
            }
        }
        return entries;
    }

    // If /Index array is provided
    for (size_t i = 0; i < index_count && !done; i += 2) {
        uint32_t start_obj = index_array[i];
        uint32_t count = index_array[i + 1];

        for (uint32_t j = 0; j < count; j++, object_index++) {
            size_t offset = object_index * entry_len;
            if (offset + entry_len > decoded_len) {
                done = 1;
                break;
            }

            const unsigned char *entry = ptr + offset;
            uint32_t type   = (w_array[0] > 0) ? read_be(entry, w_array[0], decoded_len - offset) : 1;
            uint32_t field2 = (w_array[1] > 0) ? read_be(entry + w_array[0], w_array[1], decoded_len - offset - w_array[0]) : 0;
            uint32_t field3 = (w_array[2] > 0) ? read_be(entry + w_array[0] + w_array[1], w_array[2], decoded_len - offset - w_array[0] - w_array[1]) : 0;

            if (type == 1 && field2 > 0) {
                Object *temp = realloc(entries, sizeof(Object) * (*num_type1 + 1));
                if (!temp){
                    free(entries);
                    return NULL;
                }
                entries = temp;
                entries[*num_type1] = (Object){
                    .obj_num = start_obj + j,
                    .obj_offset = field2
                };
                (*num_type1)++;
            }
        }
    }

    return entries;
}

/**
 * @description             Extracts the entries of an xref table or stream
 *                          for validation.
 *
 * @param data              The buffer containing the candidate.
 * @param offset            The offset of the xref.
 * @param length            The length of the buffer.
 * @param entry_count       The # of entries in this table (out).
 * @param xref_end_offset   The offset of the end of this table (out).
 *
 * @return                  An array of Objects.
 */
Object* analyze_xref(char* data, int64_t offset, int64_t length, int *entry_count, uint64_t *xref_end_offset){
    int nested_level = 1;
    int column_length = 0;
    size_t *index_array = NULL;
    size_t index_count = 0;
    int w_array[3] = {0, 0, 0};
    int num_references = 0;
    int num_type1 = 0;
    int num_entries = 0;
    Object *entries = NULL;
    bool predictor_present = false;
    int xref_type = detect_xref_type(data, offset, length, &offset);

    if (xref_type <= 0) {
        return NULL;
    }

    // Parse through stream dictionary for important information needed for decoding
    if (xref_type == 2) {
        // Use memmem to jump directly to << instead of scanning byte-by-byte
        char *dict_start = memmem(&data[offset], length - offset, "<<", 2);
        if (!dict_start) {
            return NULL;
        }
        offset = dict_start - data + 2;
        int64_t dict_scan_limit = offset + 10000;

        while (nested_level > 0 && offset < dict_scan_limit) {
            if (!memcmp(&data[offset], "<<", 2)) nested_level++;
            if (!memcmp(&data[offset], ">>", 2)) nested_level--;

            if ((offset < length - 2) && !memcmp(&data[offset], "/W", 2)) {
                if (extract_w_array(data, offset, w_array, length) == 0) {
                    column_length = w_array[0] + w_array[1] + w_array[2];
                } else {
                    w_array[0] = w_array[1] = w_array[2] = 0;
                }
            }

            if ((offset < length - 6) && !memcmp(&data[offset], "/Index", 6)) {
                extract_index_array(data, offset, &index_array, &index_count, length);
            }

            if ((offset < length - 5) && !memcmp(&data[offset], "/Size", 5)) {
                num_references = extract_int(data, offset + 5, length,NULL);
            }

            if ((offset < length - 10) && !memcmp(&data[offset], "/Predictor", 10)) {
                predictor_present = true;
            }

            offset++;
        }

        // Decoding stream
        size_t stream_length = 0;
        size_t decompressed_length = 0;
        size_t decoded_length = 0;

        char *stream_data = extract_stream_data(data, offset, &stream_length, length, xref_end_offset);
        if (!stream_data) {
            free(index_array);
            return NULL;
        }

        char *decompressed_data = decompress_with_uncompress(stream_data, stream_length, &decompressed_length);
        free(stream_data);

        if (!decompressed_data) {
            free(index_array);
            return NULL;
        }

        char *decoded_data = NULL;
        if (predictor_present) {
            decoded_data = apply_png_predictor_up(decompressed_data, decompressed_length, column_length, &decoded_length);
            free(decompressed_data);

            if (!decoded_data) {
                free(index_array);
                return NULL;
            }
            entries = store_xref_stream(decoded_data, decoded_length, index_array, index_count, w_array, num_references, &num_type1);
            free(decoded_data);
        } else {
            entries = store_xref_stream(decompressed_data, decompressed_length, index_array, index_count, w_array, num_references, &num_type1);
            free(decompressed_data);
        }

        free(index_array);
        *entry_count = num_type1;
    }

    if (xref_type == 1) {
        int64_t temp_offset = offset;
        nested_level = 1;

        char *dict_start = memmem(&data[temp_offset], length - temp_offset, "<<", 2);
        if (!dict_start) {
            return NULL;
        }
        temp_offset = dict_start - data + 2;
        int64_t dict_scan_limit = temp_offset + 10000;

        while (nested_level > 0 && temp_offset < dict_scan_limit) {
            if ((temp_offset < length - 2) && !memcmp(&data[temp_offset], "<<", 2)) nested_level++;
            if ((temp_offset < length - 2) && !memcmp(&data[temp_offset], ">>", 2)) nested_level--;
            temp_offset++;
        }

        entries = store_xref_table(data, offset, &num_entries, length, xref_end_offset);
        *entry_count = num_entries;
    }

    return entries;
}

/**
 * @description         Extracts the Index array of an xref stream, which
 *                      specifies the values of xref object numbers found
 *                      within stream and their location in it.
 *
 * @param data          The buffer containing the candidate.
 * @param offset        The offset of the Index array.
 * @param index_array_out   A pointer to store the extracted index array.
 * @param index_count_out   A pointer to store the count of entries in the index array
 * @param length        The length of the buffer.
 *
 * @return              0 on success, negative values on failure.
 */
int extract_index_array(const char *data, int64_t offset, size_t **index_array_out, size_t *index_count_out, int64_t length) {
    int64_t i = offset;



    if(strncmp(&data[i], "/Index", 6) != 0) return -1;

    if(i < length - 6){
        i += 6;
    }


    while (i < length && isspace(data[i])) i++;

    if (data[i] != '[') return -2;
    i++;

    size_t capacity = 8;
    size_t count = 0;
    size_t *index_array = (size_t*)malloc(capacity * sizeof(size_t));
    if (!index_array) return -3;

    while (i < length && data[i] != ']') {
        while (i < length && isspace(data[i])) i++;
        if (!isdigit(data[i])) break;

        size_t val = 0;
        while (i < length && isdigit(data[i])) {
            val = val * 10 + (data[i] - '0');
            i++;
        }

        if (count >= capacity) {
            capacity *= 2;
            size_t *tmp = (size_t*)realloc(index_array, capacity * sizeof(size_t));
            if (!tmp) {
                free(index_array);
                return -4;
            }
        index_array = tmp;
        }

        index_array[count++] = val;
        }

        if (data[i] != ']') {
            free(index_array);
            return -5;
        }

    *index_array_out = index_array;
    *index_count_out = count;
    return 0;
}

/**
 * @description         Decompresses data by reversing the zlib compression algorithm.
 *
 * @param input         The buffer containing the compressed data.
 * @param input_length  The length of the compressed data.
 * @param out_length    A pointer to store the length of the decompressed data.
 *
 * @return              A pointer to the decompressed data.
 */
char *decompress_with_uncompress(const char *input, size_t input_length, size_t *out_length) {
    while (input_length > 0 && (input[0] == '\r' || input[0] == '\n' || input[0] == ' ')) {
        input++;
        input_length--;
    }

    while (input_length > 0 &&
           (input[input_length - 1] == '\r' ||
            input[input_length - 1] == '\n' ||
            input[input_length - 1] == ' ')) {
        input_length--;
    }

    uLongf output_size = 1024 * 1024;
    char *output = (char*)malloc(output_size);
    if (!output) return NULL;

    z_stream strm = {0};
    strm.next_in = (Bytef *)input;
    strm.avail_in = input_length;
    strm.next_out = (Bytef *)output;
    strm.avail_out = output_size;

    if (inflateInit2(&strm, 15) != Z_OK) {
        free(output);
        return NULL;
    }

    int ret = inflate(&strm, Z_FINISH);
    if (ret != Z_STREAM_END) {
        inflateEnd(&strm);
        free(output);
        return NULL;
    }

    *out_length = output_size - strm.avail_out;
    inflateEnd(&strm);
    return output;
}

/**
 * @description         Applies PNG UP predictor reversal to decompressed PDF stream data.
 *
 * @param input         The buffer containing the decompressed data.
 * @param input_length  The length of the decompressed data.
 * @param columns       The number of data columns per row (from /DecodeParms /Columns).
 * @param out_length    A pointer to store the length of the decoded data.
 *
 * @return              A pointer to the decoded data (caller must free).
 */
char *apply_png_predictor_up(const char *input, size_t input_length, size_t columns, size_t *out_length) {

    if (!input || !out_length || columns == 0 || input_length == 0) {
        if (out_length) *out_length = 0;
        return NULL;
    }

    size_t row_stride = columns + 1;  // filter byte + data
    size_t row_count = input_length / row_stride;
    size_t remainder = input_length % row_stride;

    if (row_count == 0) {
        *out_length = 0;
        return NULL;
    }

    size_t alloc_size = row_count * columns;

    char *output = (char *)malloc(alloc_size);
    if (!output) {
        *out_length = 0;
        return NULL;
    }

    const unsigned char *in = (const unsigned char *)input;
    unsigned char *out = (unsigned char *)output;

    for (size_t row = 0; row < row_count; row++) {
        size_t in_offset = row * row_stride;
        unsigned char filter_byte = in[in_offset];
        const unsigned char *in_row = in + in_offset + 1;  // skip filter byte
        unsigned char *out_row = out + (row * columns);
        unsigned char *above_row = (row == 0) ? NULL : out_row - columns;

        for (size_t col = 0; col < columns; col++) {
            unsigned char above = above_row ? above_row[col] : 0;
            out_row[col] = (in_row[col] + above) & 0xFF;
        }
    }

    *out_length = row_count * columns;
    return output;
}

static int compare_objects(const void *a, const void *b) {
    const Object *obj_a = (const Object *)a;
    const Object *obj_b = (const Object *)b;
    return (obj_a->obj_offset > obj_b->obj_offset) - (obj_a->obj_offset < obj_b->obj_offset);
}

void sort_xref_data_by_offset(XrefTables *data) {
    if (!data || !data->entries || data->count == 0) return;
    
    qsort(data->entries, data->count, sizeof(Object), compare_objects);
}

bool add_xref_table(PDFCarveState *state, XrefTables *xref_table, int table_idx) {
    if (!state || !xref_table) return false;



    XrefTables *temp_tables = (XrefTables *)realloc(state->xref_tables, sizeof(XrefTables) * (state->num_tables + 1));

    if(temp_tables == NULL){
        return false;
    }
    state->xref_tables = temp_tables;
    state->xref_tables[state->num_tables] = xref_table[table_idx];
    state->num_tables++;
    return true;
}

int check_startxref(char *data, uint64_t validation_cutoff){
    char *startxref_ptr = NULL;
    uint64_t startxref_search = 0;

    while(startxref_search < validation_cutoff &&
          (startxref_ptr = memmem(&data[startxref_search],
                                   validation_cutoff - startxref_search,
                                   "startxref", 9))){
        int64_t startxref_offset = startxref_ptr - data;
        startxref_search = (uint64_t)(startxref_offset + 9);

        int64_t startxref_value = extract_int(data, startxref_offset, (int64_t)validation_cutoff, NULL);
        if(startxref_value == 0) continue;

        if((uint64_t)startxref_value > validation_cutoff) return - 1;

        if(detect_xref_type(data, startxref_value, validation_cutoff, &startxref_value) < 1){
            return 0;
        }


    }
    return 1;
}

int *list_candidate_objects(char *data, uint64_t length, int *obj_count) {
    char *obj_pos = data;
    char *end = data + length;
    int *obj_list = NULL;

    while ((obj_pos = memmem(obj_pos, end - obj_pos, "obj", 3))) {
        size_t offset = obj_pos - data;
        
        if (obj_pos >= data + 2) {
            char c1 = obj_pos[-1];
            char c2 = obj_pos[-2];
            char c3 = (obj_pos + 3 < end) ? obj_pos[3] : '\n';
            
            int valid_before = (c1 == ' ' || c1 == '\t' || c1 == '\n' || c1 == '\r') &&
                               (c2 >= '0' && c2 <= '9');
            int valid_after = (c3 == ' ' || c3 == '\t' || c3 == '\n' || c3 == '\r' ||
                               c3 == '<' || c3 == '[' || c3 == '/' || c3 == '(');
            if (valid_before && valid_after) {
                (*obj_count)++;
                int *temp = (int *)realloc(obj_list, sizeof(int) * (*obj_count));
                if (temp == NULL) {
                    free(obj_list);
                    perror("FAILED TO REALLOC OBJ_LIST\n");
                    return NULL;
                }
                obj_list = temp;
                int obj_num = extract_obj_num(data, offset, length);
                obj_list[*obj_count - 1] = obj_num;
            }
        }
        obj_pos += 3;
    }
    return obj_list;
}

int check_last_object_length(char* data, uint64_t length, int32_t *out_startstream_local_offset, int32_t *out_endstream_local_offset, int *out_blocks_to_extend) {
    int64_t object_length = 0;
    int64_t i = (int64_t)length - 8;
    for(; i > 0; i--){
        if(!memcmp(&data[i], "/Length", 7) && data[i + 7] != '1'){
            object_length = extract_int(data, i + 7, length, NULL);
            break;
        }
    }
    // No length field found
    if(object_length == 0){
        return LENGTHNOTFOUND;
    }
    // Find the stream keyword to get its file-relative offset
    uint64_t stream_file_offset = 0;
    for(; i < (int64_t)length; i++){
        if(i + 6 < (int64_t)length && !memcmp(&data[i], "stream", 6)){
            // Make sure this isn't "endstream"
            if(i >= 3 && !memcmp(&data[i-3], "end", 3)) continue;
            stream_file_offset = i + 6;
            if (data[stream_file_offset] == '\r') stream_file_offset++;
            if (data[stream_file_offset] == '\n') stream_file_offset++;
            break;
        }
    }

    // Compute endstream file-relative offset using the stream data length
    uint64_t endstream_file_offset = stream_file_offset + object_length;

    // Compute block-relative offset of endstream
    *out_endstream_local_offset = endstream_file_offset % scalpel_state.blocksize;

    // Compute block-relative offset of stream start (for reassembler init)
    *out_startstream_local_offset = stream_file_offset % scalpel_state.blocksize;

    uint32_t stream_block = stream_file_offset / scalpel_state.blocksize;
    uint32_t endstream_block = endstream_file_offset / scalpel_state.blocksize;
    *out_blocks_to_extend = endstream_block - stream_block;

    #ifdef PDFTESTING
    printf("OBJECT LENGTH: %" PRId64 "\n", object_length);
    printf("STREAM FILE OFFSET: %llu\n", (unsigned long long)stream_file_offset);
    printf("ENDSTREAM FILE OFFSET: %llu\n", (unsigned long long)endstream_file_offset);
    printf("STREAM LOCAL OFFSET: %d\n", *out_startstream_local_offset);
    printf("ENDSTREAM LOCAL OFFSET: %d\n", *out_endstream_local_offset);
    printf("BLOCKS TO EXTEND: %d\n", *out_blocks_to_extend);
    #endif
    int64_t length_in_candidate = (int64_t)length - (int64_t)stream_file_offset;
    // This stream is fully accounted for
    if(object_length < length_in_candidate) return INBLOCK;

    // This stream only extends into the next block
    else if(object_length < length_in_candidate + scalpel_state.blocksize) return INNEXTBLOCK;

    // This stream extends into the next 2 blocks at the least
    return MULTIBLOCK;
}

int stream_reassembler_init(StreamReassembler *r, const unsigned char *first_block, 
                     size_t block_size, size_t stream_offset) {
    memset(r, 0, sizeof(*r));

    r->output_capacity = 1024 * 1024;
    r->output = malloc(r->output_capacity);
    if (!r->output) return -1;

    if (inflateInit2(&r->strm, 15) != Z_OK) {
        free(r->output);
        return -1;
    }

    // Start decompression from where the actual stream data begins
    unsigned char tmp[scalpel_state.blocksize];
    r->strm.next_in  = (Bytef *)(first_block + stream_offset);
    r->strm.avail_in = block_size - stream_offset;

        do {
        r->strm.next_out  = tmp;
        r->strm.avail_out = sizeof(tmp);
        int ret = inflate(&r->strm, Z_NO_FLUSH);
        if (ret == Z_DATA_ERROR || ret == Z_MEM_ERROR) {
            inflateEnd(&r->strm);
            free(r->output);
            return -1;
        }

        size_t produced = sizeof(tmp) - r->strm.avail_out;
        if (r->output_len + produced > r->output_capacity) {
            r->output_capacity *= 2;
            unsigned char *t = realloc(r->output, r->output_capacity);
            if (!t) { inflateEnd(&r->strm); free(r->output); return -1; }
            r->output = t;
        }
        memcpy(r->output + r->output_len, tmp, produced);
        r->output_len += produced;

    } while (r->strm.avail_out == 0);

    // Snapshot this as our first checkpoint
    if (inflateCopy(&r->checkpoint, &r->strm) != Z_OK) {
        inflateEnd(&r->strm);
        free(r->output);
        return -1;
    }

    r->total_verified = r->output_len;
    return 0;
}

int stream_reassembler_try_block(StreamReassembler *r, const unsigned char *block, size_t block_size) {
    unsigned char tmp[scalpel_state.blocksize];

    // Save current output length so we can roll back
    size_t saved_output_len = r->output_len;

    // Work on the live state (which equals checkpoint at this point)
    r->strm.next_in  = (Bytef *)block;
    r->strm.avail_in = block_size;

    int stream_ended = 0;

    do {
        r->strm.next_out  = tmp;
        r->strm.avail_out = sizeof(tmp);
        int ret = inflate(&r->strm, Z_NO_FLUSH);

        if (ret == Z_DATA_ERROR) {
            // REJECT: roll back to checkpoint
            inflateEnd(&r->strm);
            inflateCopy(&r->strm, &r->checkpoint);
            r->output_len = saved_output_len;
            return 0;
        }

        if (ret == Z_MEM_ERROR) return -1;

        // Accumulate output
        size_t produced = sizeof(tmp) - r->strm.avail_out;
        if (r->output_len + produced > r->output_capacity) {
            r->output_capacity *= 2;
            unsigned char *t = realloc(r->output, r->output_capacity);
            if (!t) return -1;
            r->output = t;
        }
        memcpy(r->output + r->output_len, tmp, produced);
        r->output_len += produced;

        if (ret == Z_STREAM_END) {
            stream_ended = 1;
            break;
        }

    } while (r->strm.avail_out == 0);

    // ACCEPT: update checkpoint to include this block
    inflateEnd(&r->checkpoint);
    if (inflateCopy(&r->checkpoint, &r->strm) != Z_OK) return -1;
    r->total_verified = r->output_len;

    return stream_ended ? 2 : 1;  // 2 means stream is complete
}

void stream_reassembler_free(StreamReassembler *r) {
    inflateEnd(&r->strm);
    inflateEnd(&r->checkpoint);
    free(r->output);
}

Object* scan_blocks_for_xref_at_offset(CarveInfo *candidate,
                      BlockVector *scan_bv,
                      int *entry_count,
                      int64_t **out_xref_blocks,
                      int *out_xref_block_count,
                      int32_t expected_offset){
    init_blockvector(scalpel_state.filemirror, &scan_bv, 1, false);
    inflate_blockvector(scan_bv);

    *out_xref_blocks = NULL;
    *out_xref_block_count = 0;

    uint64_t slot = 0;
    int64_t start = 0;
    int64_t block_choice = -1;
    char *buf = NULL;
    uint64_t evaluated;
    int64_t tmp;
    Object *entries = NULL;
    uint64_t xref_end_offset;
    // DONT FORGET TO SET AN EXIT CONDITION FOR THE MAIN LOOP
    while ((block_choice = blockvector_get_choice(scan_bv, slot, start, -1, &evaluated)) != -1) {
        blockvector_remove_choice(scan_bv, slot, block_choice);
        start = block_choice + 1;

        PDFBlockState *blk_state = pdf_get_blockstate_from_apparent(candidate, block_choice, NULL);
        if(blk_state == NULL || blk_state->num_xrefs < 1){ pdf_free_block_state((void**)&blk_state); continue; }
        
        for(int i = 0; i < blk_state->num_xrefs; i++){
            // This xref is completely contained within this block
            if(blk_state->xref_block_data[i].xref_start != -1 &&
               blk_state->xref_block_data[i].xref_end != -1){
                if(blk_state->xref_block_data[i].conditional_flag == INCOMPLETESTREAMDICT){
                    if(block_choice == 0) continue;
                    buf = (char*)malloc(scalpel_state.blocksize * 2);
                    uint8_t *blk_data = get_apparent_block_data(scalpel_state.filemirror, block_choice - 1);
                    memcpy(buf, blk_data, scalpel_state.blocksize);
                    free(blk_data);
                    blk_data = get_apparent_block_data(scalpel_state.filemirror, block_choice);
                    memcpy(&buf[scalpel_state.blocksize], blk_data, scalpel_state.blocksize);
                    free(blk_data);
                    blk_state->xref_block_data[i].xref_start = find_xref_stream_start(buf,
                        scalpel_state.blocksize + blk_state->xref_block_data[i].xref_start);
                    if(expected_offset != blk_state->xref_block_data[i].xref_start){ free(buf); continue; }
                    free(buf);
                }
                uint8_t *blk_data = get_apparent_block_data(scalpel_state.filemirror, block_choice);
                if(expected_offset != blk_state->xref_block_data[i].xref_start){ free(blk_data); continue; }
                entries = analyze_xref((char*)blk_data, blk_state->xref_block_data[i].xref_start,
                scalpel_state.blocksize, entry_count, &xref_end_offset);
                free(blk_data);
                if(*entry_count > 0){
                    int start_ap = (blk_state->xref_block_data[i].conditional_flag == INCOMPLETESTREAMDICT)
                                   ? block_choice - 1 : block_choice;
                    int num_blocks = block_choice - start_ap + 1;
                    *out_xref_blocks = malloc(num_blocks * sizeof(int64_t));
                    *out_xref_block_count = num_blocks;
                    for(int b = 0; b < num_blocks; b++)
                        (*out_xref_blocks)[b] = filemirror_actual_blocknumber(scalpel_state.filemirror, start_ap + b);
                    pdf_free_block_state((void**)&blk_state);
                    return entries;
                }
            }

            // This xref starts in this block and continues in another
            // try to find the tail in the proceeding blocks
            if(blk_state->xref_block_data[i].xref_start != -1 && 
               blk_state->xref_block_data[i].xref_end == -1 &&
               blk_state->xref_block_data[i].xref_type == 1){
                if(expected_offset != blk_state->xref_block_data[i].xref_start) continue;
                int64_t tail = start;
                int64_t tail_choice = -1;

                while ((tail_choice = blockvector_get_choice(scan_bv, slot, tail, -1, &evaluated)) != -1){
                    blockvector_remove_choice(scan_bv, slot, tail_choice);
                    PDFBlockState *tail_state = pdf_get_blockstate_from_apparent(candidate, tail_choice, NULL);
                    if(tail_state == NULL){ tail = tail_choice + 1; continue; }
                    tail = tail_choice + 1;
                    // If this is true we have found a block that may
                    // hold the tail of this xref.
                    bool should_break = false;
                    if(tail_state->num_xrefs > 0 &&
                       (tail_state->xref_block_data[0].xref_end != -1 &&
                       tail_state->xref_block_data[0].xref_start == -1)){
                        // Include head block (block_choice) through tail block (tail_choice)
                        int64_t num_buf_blocks = tail - block_choice;
                        char *buf = (char*)malloc(scalpel_state.blocksize * num_buf_blocks);
                        for(int64_t k = block_choice; k < tail; k++){
                            uint8_t *blk_data = get_apparent_block_data(scalpel_state.filemirror, k);
                            memcpy(buf + (k - block_choice) * scalpel_state.blocksize,
                            blk_data, scalpel_state.blocksize);
                            free(blk_data);
                        }
                        entries = analyze_xref(buf, blk_state->xref_block_data[i].xref_start,
                        scalpel_state.blocksize * num_buf_blocks,
                        entry_count, &xref_end_offset);
                        free(buf);
                        if(*entry_count > 0){
                            *out_xref_blocks = malloc(num_buf_blocks * sizeof(int64_t));
                            *out_xref_block_count = (int)num_buf_blocks;
                            for(int64_t b = 0; b < num_buf_blocks; b++)
                                (*out_xref_blocks)[b] = filemirror_actual_blocknumber(scalpel_state.filemirror, block_choice + b);
                            pdf_free_block_state((void**)&tail_state);
                            pdf_free_block_state((void**)&blk_state);
                            return entries;
                        }
                    }
                    else if(tail_state->num_xrefs > 0 &&
                       (tail_state->xref_block_data[0].xref_end == -1)){
                        should_break = true;
                    }
                    pdf_free_block_state((void**)&tail_state);
                    if(should_break) break;
                }
            }
            // It is difficult to determine the end of an xref stream object
            // when the dictionary is not in the same block
            // take a leap of faith and see if we can find it in the next
            // apparent block.
            if(blk_state->xref_block_data[i].xref_start != -1 && 
               blk_state->xref_block_data[i].xref_end == -1 &&
               blk_state->xref_block_data[i].xref_type == 2 &&
               blk_state->xref_block_data[i].conditional_flag != INCOMPLETESTREAMDICT){
                if(expected_offset != blk_state->xref_block_data[i].xref_start) continue;
                if(block_choice + 1 >= (int64_t)filemirror_apparent_blocks(scalpel_state.filemirror)){
                    continue;
                }
                buf = (char*)malloc(scalpel_state.blocksize * 2);
                uint8_t *blk_data = get_apparent_block_data(scalpel_state.filemirror, block_choice);
                memcpy(buf, blk_data, scalpel_state.blocksize);
                free(blk_data);
                blk_data = get_apparent_block_data(scalpel_state.filemirror, block_choice + 1);
                memcpy(&buf[scalpel_state.blocksize], blk_data, scalpel_state.blocksize);
                free(blk_data);
                entries = analyze_xref(buf, blk_state->xref_block_data[i].xref_start, scalpel_state.blocksize * 2, entry_count, &xref_end_offset);
                free(buf);
                if(*entry_count > 0){
                    *out_xref_blocks = malloc(2 * sizeof(int64_t));
                    *out_xref_block_count = 2;
                    (*out_xref_blocks)[0] = filemirror_actual_blocknumber(scalpel_state.filemirror, block_choice);
                    (*out_xref_blocks)[1] = filemirror_actual_blocknumber(scalpel_state.filemirror, block_choice + 1);
                    pdf_free_block_state((void**)&blk_state);
                    return entries;
                }
            }
        }
        pdf_free_block_state((void**)&blk_state);
    }
    return entries;
}

/**
 * @description         Searches for xrefs that we probed for during block validation
 *                      best case is to find a table completely contained within a
 *                      single block. Otherwise we will need to search across multiple
 *                      blocks to reconstruct the table. Right now I don't know if
 *                      I should just send what I suspect to be an xref spread across
 *                      multiple blocks to my analysis function, or if I should
 *                      try to utilize some ML. Now that I'm typing it out I think
 *                      I should just send it for analysis.
 */
Object* scan_blocks_for_xref(CarveInfo *candidate,
                      BlockVector *scan_bv,
                      int *entry_count,
                      int64_t **out_xref_blocks,
                      int *out_xref_block_count){
    init_blockvector(scalpel_state.filemirror, &scan_bv, 1, false);
    inflate_blockvector(scan_bv);

    *out_xref_blocks = NULL;
    *out_xref_block_count = 0;

    uint64_t slot = 0;
    int64_t start = 0;
    int64_t block_choice = -1;
    char *buf = NULL;
    uint64_t evaluated;
    int64_t tmp;
    Object *entries = NULL;
    uint64_t xref_end_offset;
    // DONT FORGET TO SET AN EXIT CONDITION FOR THE MAIN LOOP
    while ((block_choice = blockvector_get_choice(scan_bv, slot, start, -1, &evaluated)) != -1) {
        blockvector_remove_choice(scan_bv, slot, block_choice);
        start = block_choice + 1;

        PDFBlockState *blk_state = pdf_get_blockstate_from_apparent(candidate, block_choice, NULL);
        if(blk_state == NULL || blk_state->num_xrefs < 1){ pdf_free_block_state((void**)&blk_state); continue; }
        
        for(int i = 0; i < blk_state->num_xrefs; i++){
            // This xref is completely contained within this block
            if(blk_state->xref_block_data[i].xref_start != -1 &&
               blk_state->xref_block_data[i].xref_end != -1){
                if(blk_state->xref_block_data[i].conditional_flag == INCOMPLETESTREAMDICT){
                    if(block_choice == 0) continue;
                    buf = (char*)malloc(scalpel_state.blocksize * 2);
                    uint8_t *blk_data = get_apparent_block_data(scalpel_state.filemirror, block_choice - 1);
                    memcpy(buf, blk_data, scalpel_state.blocksize);
                    free(blk_data);
                    blk_data = get_apparent_block_data(scalpel_state.filemirror, block_choice);
                    memcpy(&buf[scalpel_state.blocksize], blk_data, scalpel_state.blocksize);
                    free(blk_data);
                    blk_state->xref_block_data[i].xref_start = find_xref_stream_start(buf,
                        scalpel_state.blocksize + blk_state->xref_block_data[i].xref_start);
                    free(buf);
                }
                uint8_t *blk_data = get_apparent_block_data(scalpel_state.filemirror, block_choice);
                entries = analyze_xref((char*)blk_data, blk_state->xref_block_data[i].xref_start,
                scalpel_state.blocksize, entry_count, &xref_end_offset);
                free(blk_data);
                if(*entry_count > 0){
                    int start_ap = (blk_state->xref_block_data[i].conditional_flag == INCOMPLETESTREAMDICT)
                                   ? block_choice - 1 : block_choice;
                    int num_blocks = block_choice - start_ap + 1;
                    *out_xref_blocks = malloc(num_blocks * sizeof(int64_t));
                    *out_xref_block_count = num_blocks;
                    for(int b = 0; b < num_blocks; b++)
                        (*out_xref_blocks)[b] = filemirror_actual_blocknumber(scalpel_state.filemirror, start_ap + b);
                    pdf_free_block_state((void**)&blk_state);
                    return entries;
                }
            }

            // This xref starts in this block and continues in another
            // try to find the tail in the proceeding blocks
            if(blk_state->xref_block_data[i].xref_start != -1 && 
               blk_state->xref_block_data[i].xref_end == -1 &&
               blk_state->xref_block_data[i].xref_type == 1){
                int64_t tail = start;
                int64_t tail_choice = -1;

                while ((tail_choice = blockvector_get_choice(scan_bv, slot, tail, -1, &evaluated)) != -1){
                    blockvector_remove_choice(scan_bv, slot, tail_choice);
                    PDFBlockState *tail_state = pdf_get_blockstate_from_apparent(candidate, tail_choice, NULL);
                    if(tail_state == NULL){ tail = tail_choice + 1; continue; }
                    tail = tail_choice + 1;
                    // If this is true we have found a block that may
                    // hold the tail of this xref.
                    bool should_break = false;
                    if(tail_state->num_xrefs > 0 &&
                       (tail_state->xref_block_data[0].xref_end != -1 &&
                       tail_state->xref_block_data[0].xref_start == -1)){
                        // Include head block (block_choice) through tail block (tail_choice)
                        int64_t num_buf_blocks = tail - block_choice;
                        char *buf = (char*)malloc(scalpel_state.blocksize * num_buf_blocks);
                        for(int64_t k = block_choice; k < tail; k++){
                            uint8_t *blk_data = get_apparent_block_data(scalpel_state.filemirror, k);
                            memcpy(buf + (k - block_choice) * scalpel_state.blocksize,
                            blk_data, scalpel_state.blocksize);
                            free(blk_data);
                        }
                        entries = analyze_xref(buf, blk_state->xref_block_data[i].xref_start,
                        scalpel_state.blocksize * num_buf_blocks,
                        entry_count, &xref_end_offset);
                        free(buf);
                        if(*entry_count > 0){
                            *out_xref_blocks = malloc(num_buf_blocks * sizeof(int64_t));
                            *out_xref_block_count = (int)num_buf_blocks;
                            for(int64_t b = 0; b < num_buf_blocks; b++)
                                (*out_xref_blocks)[b] = filemirror_actual_blocknumber(scalpel_state.filemirror, block_choice + b);
                            pdf_free_block_state((void**)&tail_state);
                            pdf_free_block_state((void**)&blk_state);
                            return entries;
                        }
                    }
                    else if(tail_state->num_xrefs > 0 &&
                       (tail_state->xref_block_data[0].xref_end == -1)){
                        should_break = true;
                    }
                    pdf_free_block_state((void**)&tail_state);
                    if(should_break) break;
                }
            }
            // It is difficult to determine the end of an xref stream object
            // when the dictionary is not in the same block
            // take a leap of faith and see if we can find it in the next
            // apparent block.
            if(blk_state->xref_block_data[i].xref_start != -1 && 
               blk_state->xref_block_data[i].xref_end == -1 &&
               blk_state->xref_block_data[i].xref_type == 2 &&
               blk_state->xref_block_data[i].conditional_flag != INCOMPLETESTREAMDICT){
                if(block_choice + 1 >= (int64_t)filemirror_apparent_blocks(scalpel_state.filemirror)){
                    continue;
                }
                buf = (char*)malloc(scalpel_state.blocksize * 2);
                uint8_t *blk_data = get_apparent_block_data(scalpel_state.filemirror, block_choice);
                memcpy(buf, blk_data, scalpel_state.blocksize);
                free(blk_data);
                blk_data = get_apparent_block_data(scalpel_state.filemirror, block_choice + 1);
                memcpy(&buf[scalpel_state.blocksize], blk_data, scalpel_state.blocksize);
                free(blk_data);
                entries = analyze_xref(buf, blk_state->xref_block_data[i].xref_start, scalpel_state.blocksize * 2, entry_count, &xref_end_offset);
                free(buf);
                if(*entry_count > 0){
                    *out_xref_blocks = malloc(2 * sizeof(int64_t));
                    *out_xref_block_count = 2;
                    (*out_xref_blocks)[0] = filemirror_actual_blocknumber(scalpel_state.filemirror, block_choice);
                    (*out_xref_blocks)[1] = filemirror_actual_blocknumber(scalpel_state.filemirror, block_choice + 1);
                    pdf_free_block_state((void**)&blk_state);
                    return entries;
                }
            }
        }
        pdf_free_block_state((void**)&blk_state);
    }
    return entries;
}

const char *scan_buf_for_xref(char *data, uint64_t length, uint64_t search_pos, int *xref_type) {
    char *xref_table_start = NULL;
    char *xref_stream_start_nospace = memmem(&data[search_pos], length - search_pos, "/Type/XRef", 10);
    char *xref_stream_start_space   = memmem(&data[search_pos], length - search_pos, "/Type /XRef", 11);
    uint64_t temp_sp = search_pos;
    uint8_t tt_fails = 0;

    while (1) {
        xref_table_start = memmem(&data[temp_sp], length - temp_sp, "xref", 4);
        if (!xref_table_start) break;
        int64_t xref_idx = xref_table_start - data;
        bool prev_ok = (xref_idx == 0) || isspace((unsigned char)data[xref_idx - 1]);
        bool next_ok = (xref_idx + 5 >= (int64_t)length) || isspace((unsigned char)data[xref_idx + 4]);
        if (prev_ok && next_ok) break;
        xref_table_start = NULL;
        temp_sp = (uint64_t)(xref_idx + 4);
        if (++tt_fails > 4) break;
    }

    return min_xref_start(xref_table_start, xref_stream_start_nospace, xref_stream_start_space, xref_type);
}

/*******************************************************/
/*              BLOCK STATE FUNCTION DEFINITIONS       */
/*******************************************************/

static inline bool pdf_serialize_block_state(void **state, FILE *fp,
                                             StateSerialization mode){
    PDFBlockState *s;

    size_t (*fb)(void *ptr, size_t size, size_t nitems, FILE *stream) =
        mode == SERIALIZE ? (size_t (*)(void *ptr, size_t size, size_t nitems,
                                        FILE *stream))fwrite
                          : (size_t (*)(void *ptr, size_t size, size_t nitems,
                                        FILE *stream))fread;

    if (mode == DESERIALIZE) {
        *state = calloc(1, sizeof(PDFBlockState));
        check_memory_allocation(*state, __LINE__, __FILE__, "state");
    }
    s = (PDFBlockState *)*state;

    if (fb(&s->first_obj, sizeof(s->first_obj), 1, fp) != 1)
        handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
    if (fb(&s->num_xrefs, sizeof(s->num_xrefs), 1, fp) != 1)
        handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);

    if (mode == DESERIALIZE && s->num_xrefs > 0) {
        s->xref_block_data = malloc(s->num_xrefs * sizeof(XrefParameters));
        check_memory_allocation(s->xref_block_data, __LINE__, __FILE__, "xref_block_data");
    }
    if (s->num_xrefs > 0 && s->xref_block_data) {
        if (fb(s->xref_block_data, sizeof(XrefParameters), s->num_xrefs, fp) != (size_t)s->num_xrefs)
            handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
    }

    return true;
}

static inline void *pdf_clone_block_state(const void *srcstate){
    PDFBlockState *s = (PDFBlockState *)srcstate;
    PDFBlockState *d = (PDFBlockState *)malloc(sizeof(PDFBlockState));
    check_memory_allocation(d, __LINE__, __FILE__, "d");

    d->first_obj = s->first_obj;
    d->num_xrefs = s->num_xrefs;
    d->xref_block_data = NULL;
    if (s->num_xrefs > 0 && s->xref_block_data) {
        d->xref_block_data = malloc(s->num_xrefs * sizeof(XrefParameters));
        check_memory_allocation(d->xref_block_data, __LINE__, __FILE__, "xref_block_data");
        memcpy(d->xref_block_data, s->xref_block_data, s->num_xrefs * sizeof(XrefParameters));
    }
    return d;
}

static inline void pdf_free_block_state(void **state){
    PDFBlockState **s = ((PDFBlockState **)state);
    if (*s) {
        free((*s)->xref_block_data);
        free(*s);
        *s = NULL;
    }
}

static inline void pdf_print_block_state(const void *state) {
  PDFBlockState *s = (PDFBlockState *)state;

//   if (s) {
//     fprintf(stdout, "For this block, xref_start was %d, xref_end was %d and, obj was %d\n",
//             s->xref_start, s->xref_end, s->first_obj);
//   }
}

static inline PDFBlockState *pdf_get_blockstate_from_apparent(CarveInfo *candidate,
                                                              int64_t apparent,
                                                              int64_t *out_actual){
    if (!candidate || apparent < 0) return NULL;

    int64_t act = filemirror_actual_blocknumber(scalpel_state.filemirror, apparent);
    if (act < 0) return NULL;

    volatile int pdf_marker = 1;
    (void)pdf_marker;

    if (out_actual) *out_actual = act;

    if (filemirror_get_blocktype(scalpel_state.filemirror, act, candidate->needleidx)
        == BLOCK_CONFIDENCE_INVALID) {
        return NULL;
    }

    char hashkey[BLOCK_HASH_KEY_SIZE];
    gen_block_hash_key(hashkey, candidate->needleidx, act);

    return (PDFBlockState *)block_get_state(hashkey);
}

/*******************************************************/
/*            CARVE STATE FUNCTION DEFINITIONS         */
/*******************************************************/

static inline bool pdf_serialize_carve_state(void **state, FILE *fp,
                                                StateSerialization mode) {
    PDFCarveState **s = (PDFCarveState **)state;

    size_t (*fb)(void *ptr, size_t size, size_t nitems, FILE *stream) =
        mode == SERIALIZE ?
        (size_t (*)(void *, size_t, size_t, FILE *))fwrite :
        (size_t (*)(void *, size_t, size_t, FILE *))fread;

    if (mode == DESERIALIZE) {
        *s = malloc(sizeof(PDFCarveState));
        check_memory_allocation(*s, __LINE__, __FILE__, "s");
        (*s)->xref_tables = NULL;  // Initialize to NULL
        (*s)->num_tables = 0;
        (*s)->incomplete_obj = false;
    }

    // Serialize/deserialize number of xref tables
    if (fb(&(*s)->num_tables, sizeof(size_t), 1, fp) != 1) {
        handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
    }

    // Allocate array of XrefTables for DESERIALIZE mode
    if (mode == DESERIALIZE && (*s)->num_tables > 0) {
        (*s)->xref_tables = malloc((*s)->num_tables * sizeof(XrefTables));
        check_memory_allocation((*s)->xref_tables, __LINE__, __FILE__, "xref_tables array");
    }

    // For each table in the array
    for (size_t i = 0; i < (*s)->num_tables; i++) {
        XrefTables *table = &(*s)->xref_tables[i];

        // Serialize/deserialize number of entries in this table
        if (fb(&table->count, sizeof(int), 1, fp) != 1) {
            printf("pdf xref entry count");
            handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
        }

        // Allocate/read/write the entries
        if (mode == DESERIALIZE) {
            table->entries = NULL;
            if (table->count > 0) {
                table->entries = malloc(table->count * sizeof(Object));
                check_memory_allocation(table->entries, __LINE__, __FILE__, "xref entries");
            }
        }

        if (table->count > 0) {
            if (fb(table->entries, sizeof(Object), table->count, fp) != (size_t)table->count) {
                handle_error(SCALPEL_ERROR_CHECKPOINT, NULL, __LINE__, __FILE__);
            }
        }
    }

    return true;
}

static inline void *pdf_clone_carve_state(const void *srcstate) {
    const PDFCarveState *s = (const PDFCarveState *)srcstate;
    if (!s) return NULL;

    PDFCarveState *d = malloc(sizeof(PDFCarveState));
    check_memory_allocation(d, __LINE__, __FILE__, "fpdf_clone_carve_state");

    /* Copy scalar fields */
    d->num_tables = s->num_tables;
    d->incomplete_obj = s->incomplete_obj;
    d->xref_tables = NULL;

    /* Deep-copy the array of XrefTables */
    if (s->xref_tables && s->num_tables > 0) {
        d->xref_tables = malloc(s->num_tables * sizeof(XrefTables));
        check_memory_allocation(d->xref_tables, __LINE__, __FILE__, "xref_tables array");

        for (size_t i = 0; i < s->num_tables; i++) {
            d->xref_tables[i].count = s->xref_tables[i].count;
            d->xref_tables[i].entries = NULL;

            if (s->xref_tables[i].count > 0) {
                d->xref_tables[i].entries = malloc(sizeof(Object) * s->xref_tables[i].count);
                check_memory_allocation(d->xref_tables[i].entries, __LINE__, __FILE__, "xref entries");
                memcpy(d->xref_tables[i].entries, s->xref_tables[i].entries, sizeof(Object) * s->xref_tables[i].count);
            }
        }
    }

    return d;
}

static inline void pdf_free_carve_state(void **state) {
    if (!state || !*state) return;
    PDFCarveState *s = (PDFCarveState*)*state;

    if (s->xref_tables) {
        /* Free each XrefTables entry array */
        for (size_t i = 0; i < s->num_tables; i++) {
            if (s->xref_tables[i].entries) {
                free(s->xref_tables[i].entries);
                s->xref_tables[i].entries = NULL;
            }
        }
        /* Free the array itself */
        free(s->xref_tables);
        s->xref_tables = NULL;
    }

    s->num_tables = 0;
    free(s);
    *state = NULL;
}

static inline void pdf_print_carve_state(const void *state) {
  const PDFCarveState*s =
                  (const PDFCarveState *)state;

  if (!s) {
    printf("No PDF carve state available.\n");
    return;
  }

  //Produce a report of the values that are in the state
//   for(size_t i = 0; i < s->num_tables; i++){
//       printf("Xref Table %zu: %d entries\n", i, s->xref_tables[i].count);
//       for(int k = 0; k < s->xref_tables[i].count; k++){
//           printf("  Obj Num: %d, Offset: %ld\n",
//                  s->xref_tables[i].entries[k].obj_num,
//                  s->xref_tables[i].entries[k].obj_offset);
//         }
//     }
}


/*******************************************************/
/*             REASSEMBLY FUNCTION DEFINITIONS         */
/*******************************************************/

/**
 * There are a lot of things to consider when initializing a candidate
 * in order to proceed with reassembly
 * 1) Are there xref tables present in the fragment?
 *  -if so, are they complete?
 *      -if complete, we need to extract contents of each.
 *      -if not we need to try to complete them.
 *  -if there are no xref tables present in the fragment, we need
 *   to search the image to find a table that matches obj offsets
 *   in the fragment
 * 2) Do the xref tables account for every object in the fragment?
 *  -if so, maybe its a full file. Try to validate
 *  -if not, we need to attempt to find another xref table that DOES
 *   account for such objects, and eventually insert this table into
 *   the candidate through reassembly.
 *
 */
static void pdf_reassembly_init_candidate(int id,
                        CarveInfo *candidate,
                        uuid_string_t uuidp,
                        uuid_string_t uuidc){
    (void)id; (void)uuidp; (void)uuidc;

    PDFCarveState *carve_state = (PDFCarveState *)carve_get_state(candidate->carvehashkey);
    if(!carve_state){
        carve_state = (PDFCarveState *)calloc(1, sizeof *carve_state);
    }

    inflate_blockvector(candidate->b);
    char *data = blockvector_get_data_pointer(candidate->b);
    uint64_t length = blockvector_get_data_length(candidate->b);
    if(!data || length == 0){
        pdf_free_carve_state((void**)&carve_state);
        return;
    }

    XrefTables *xref_tables = NULL;
    int xref_count = 0;
    uint64_t search_pos = 0;
    uint64_t xref_end_offset = 0;

    while(search_pos < length){
        char *xref_stream_start_nospace = memmem(&data[search_pos], length - search_pos, "/Type/XRef", 10);
        char *xref_stream_start_space   = memmem(&data[search_pos], length - search_pos, "/Type /XRef", 11);

        /* Find word-bounded "xref" */
        char *xref_table_start = NULL;
        uint64_t temp_sp = search_pos;
        while(temp_sp < length){
            char *candidate_xref = memmem(&data[temp_sp], length - temp_sp, "xref", 4);
            if(!candidate_xref) break;
            int64_t xref_idx = candidate_xref - data;
            bool prev_ok = (xref_idx == 0) || isspace((unsigned char)data[xref_idx - 1]);
            bool next_ok = (xref_idx + 5 >= (int64_t)length) || isspace((unsigned char)data[xref_idx + 4]);
            if(prev_ok && next_ok){
                xref_table_start = candidate_xref;
                break;
            }
            temp_sp = (uint64_t)(xref_idx + 4);
        }

        int xref_type = 0;
        const char *first_xref = min_xref_start(xref_table_start, xref_stream_start_nospace,
                                                 xref_stream_start_space, &xref_type);
        if(!first_xref || xref_type <= 0) break;

        int64_t offset = first_xref - data;

        XrefTables *temp_tables = realloc(xref_tables, (xref_count + 1) * sizeof(XrefTables));
        if(!temp_tables){
            free(xref_tables);
            pdf_free_carve_state((void**)&carve_state);
            return;
        }
        xref_tables = temp_tables;
        xref_tables[xref_count].count = 0;
        xref_tables[xref_count].entries = NULL;
        xref_tables[xref_count].entries = analyze_xref(data, offset, length,
                                                        &xref_tables[xref_count].count, &xref_end_offset);
        if(!add_xref_table(carve_state, xref_tables, xref_count)){
            free(xref_tables[xref_count].entries);
            xref_tables[xref_count].entries = NULL;
            free(xref_tables);
            pdf_free_carve_state((void**)&carve_state);
            return;
        }
        xref_count++;
        search_pos = (uint64_t)(offset + 1);
    }

    free(xref_tables);
    carve_state->incomplete_obj = false;
    carve_put_state(candidate->carvehashkey, carve_state);
    pdf_free_carve_state((void**)&carve_state);
}

static void pdf_reassembly_prepare_for_extension(
    int id,
    CarveInfo *candidate,
    int num_blocks,
    int mode){
    (void)id;

    // fastpath is deactivated
    candidate->fastpath = false;

    // increase the size of the blockvector by one block UNLESS candidate->no_initial_block_extension
    // is true, which means that processing of the current terminal block wasn't complete when a
    // REASS_RETURN_TO_IDLE occurred and this candidate was dumped back into the promising queue. In
    // that case, starting length is already correct, so don't adjust.
    if(mode == OBJECTEXTNSION){
        resize_blockvector(candidate->b, blockvector_get_num_blocks(candidate->b) + 1);
        candidate->best_validates_to = blockvector_get_data_length(candidate->b) - 1;
    }

    else if(mode == ENDSTREAMEXTENSION){
        resize_blockvector(candidate->b, blockvector_get_num_blocks(candidate->b) + num_blocks);
        candidate->best_validates_to = blockvector_get_data_length(candidate->b) - 1;
    }
}

// merge the logic from scan for object into this function
// later will add modes for extending when we need to add a
// block primarlily containing xref info
int64_t pdf_reassembly_get_block_choice(CarveInfo *candidate,
                                        int obj_num,
                                        int32_t endstream_local_offset,
                                        uint64_t streamstart_block_app,
                                        uint64_t endstream_block_app,
                                        int32_t stream_blocks_extended,
                                        int mode){
    bool possible_match = false;
    BlockVector *scan_bv = NULL;
    uint64_t slot = 0;
    int64_t start = 0;
    uint64_t evaluated;
    int64_t block_choice;
    init_blockvector(scalpel_state.filemirror, &scan_bv, 1, false);
    inflate_blockvector(scan_bv);

    if(mode == NEXTOBJECT){
        while ((block_choice = blockvector_get_choice(scan_bv, slot, start, -1, &evaluated)) != -1) {
            blockvector_remove_choice(scan_bv, slot, block_choice);
            start = block_choice + 1;
            PDFBlockState *blk_state = pdf_get_blockstate_from_apparent(candidate, block_choice, NULL);
            if(blk_state == NULL){ continue; }
            bool match = (blk_state->first_obj == obj_num);
            pdf_free_block_state((void**)&blk_state);
            if(match) return block_choice;
        }
    }

    if(mode == FINDENDSTREAM){
        // The endstream keyword is completely contained within 1 block
        if((uint32_t)endstream_local_offset <= scalpel_state.blocksize - 9){
            while ((block_choice = blockvector_get_choice(scan_bv, slot, start, -1, &evaluated)) != -1) {
                blockvector_remove_choice(scan_bv, slot, block_choice);
                start = block_choice + 1;
                char *data = (char*)get_apparent_block_data(scalpel_state.filemirror, block_choice);
                int32_t search_offset = endstream_local_offset;
                while (search_offset < (int32_t)scalpel_state.blocksize && isspace((unsigned char)data[search_offset])) search_offset++;
                if (search_offset + 9 <= (int32_t)scalpel_state.blocksize && !memcmp(&data[search_offset], "endstream", 9)){
                    free(data);
                    return block_choice;
                }
                free(data);
            }
        }
        // The endstream keyword lies on a block boundary
        // try to extend the search to the next block and if
        // this portion is fragmented we give up on extension for now
        while ((block_choice = blockvector_get_choice(scan_bv, slot, start, -1, &evaluated)) != -1) {
            blockvector_remove_choice(scan_bv, slot, block_choice);
            start = block_choice + 1;
            char *tmp = (char*)get_apparent_block_data(scalpel_state.filemirror,block_choice);
            char *data = (char*)malloc(scalpel_state.blocksize * 2);
            memcpy(data, tmp, scalpel_state.blocksize);
            free(tmp);
            if(block_choice + 1 >= (int64_t)filemirror_apparent_blocks(scalpel_state.filemirror)){
                free(data);
                continue;
            }
            tmp = (char*)get_apparent_block_data(scalpel_state.filemirror, block_choice + 1);
            memcpy(&data[scalpel_state.blocksize], tmp, scalpel_state.blocksize);
            free(tmp);
            if(!memcmp(&data[endstream_local_offset], "endstream", 9)){
                free(data);
                return block_choice;
            }
            free(data);
        }
    }

    if(mode == EXTENDSTREAMFROMSTART){
        block_choice = blockvector_get_choice(scan_bv, slot, 
            streamstart_block_app + stream_blocks_extended, -1, &evaluated);
        if(block_choice != -1) return block_choice;
    }

    if(mode == EXTENDSTREAMFROMEND){
        block_choice = blockvector_get_choice(scan_bv, slot, 
            endstream_block_app - stream_blocks_extended, -1, &evaluated);
        if(block_choice != -1) return block_choice;
    }
    return -1;
}

static void pdf_reassembly_did_not_validate(int id,
					   CarveInfo *candidate,
					   uint64_t validates_to,
					   int64_t block_choice);

static void pdf_reassembly_extension_successful(int id, CarveInfo *candidate, uint64_t logical_slot_index) {
    (void)id;

    blockvector_set_apparent_blocknumber(candidate->b, logical_slot_index,
                                         filemirror_apparent_blocknumber(scalpel_state.filemirror, candidate->newblock));

    // inflate only the new block
    inflate_blockvector_single_block(candidate->b, logical_slot_index);

    // new length
    candidate->best_validates_to += scalpel_state.blocksize;
    blockvector_set_data_length(candidate->b, candidate->best_validates_to + 1);
}

static int64_t pdf_reassembly_backtrack(int id,
				       CarveInfo *candidate,
				       uuid_string_t uuidp,
				       uuid_string_t uuidc);

void pdf_reassembly(ThreadWork *work,
		            CarveInfo **c,
		            uuid_string_t uuidp,
		            uuid_string_t uuidc){
    CarveInfo *candidate = *c;
    XrefTables *temp_tables = NULL;
    XrefTables *test_tables = NULL;
    ObjectHashTable **xref_hashes = NULL;
    Object *entries = NULL;
    int entry_count = 0;
    int64_t *xref_blocks = NULL;
    int xref_block_count = 0;
    BlockVector *scan_bv = NULL;
    bool possible_match = false;
    bool prev_table_found = false;
    int obj_count = 0;
    int num_tables = 0;

    pdf_reassembly_init_candidate(work->id, candidate, uuidp, uuidc);
    start_reassembly:
    {
        PDFCarveState *carve_state = (PDFCarveState*)carve_get_state(candidate->carvehashkey);
        if(!carve_state) return;
        for(size_t i = 0; i < carve_state->num_tables; i++){
            sort_xref_data_by_offset(&carve_state->xref_tables[i]);
        }
        carve_put_state(candidate->carvehashkey, carve_state);
        pdf_free_carve_state((void**)&carve_state);
    }
    // write_candidate(candidate, true);
    // inflate_blockvector(candidate->b);

    int *present_objects = list_candidate_objects(blockvector_get_data_pointer(candidate->b),
       blockvector_get_data_length(candidate->b), &obj_count);
    char *data = blockvector_get_data_pointer(candidate->b);

    // The plan: exhaustively search for an xref that matches the objects
    // or at least some objects in the xref. take that as far as it can go.
    // Then repeat until we stop getting xrefs that give us literally
    // any matches. at that point we try to get the footer and finish validation.

    // We will look to validate at least one object in
    // this xref that lives at an offset > 17
    if(prev_table_found){
        possible_match = true;
        prev_table_found = false;
    } 
    else {
        while(!possible_match){
            free(entries);
            entries = NULL;
            free(xref_blocks);
            xref_blocks = NULL;
            xref_block_count = 0;
            entries = scan_blocks_for_xref(candidate, scan_bv, &entry_count, &xref_blocks, &xref_block_count);
            if(!entries || entry_count <= 0){ free(entries); entries = NULL; break; }
            int check = 0;
            for(int i = 0; i < entry_count; i++){
                check = validate_at_offset(blockvector_get_data_pointer(candidate->b),
                entries[i].obj_offset, entries[i].obj_num, blockvector_get_data_length(candidate->b));
                if(check == 1){
                    possible_match = true;
                    break;
                }
            }
        }
    }
    // At this point we either have an xref that may match our file
    // or we ran out of xrefs and none matched.

    // Case where we handle a possible match. Do a similar check
    // as in file validate.
    {
        PDFCarveState *carve_state = (PDFCarveState*)carve_get_state(candidate->carvehashkey);
        if(carve_state){
            num_tables = (int)carve_state->num_tables;
            pdf_free_carve_state((void**)&carve_state);
        }
    }
    if(possible_match){
        // Allocate hash tables for all xrefs in the candidiate plus the possiblep match
        ObjectHashTable **temp_hashes = (ObjectHashTable**)realloc(xref_hashes, (num_tables + 1) * sizeof(ObjectHashTable*));
        if (temp_hashes == NULL) {
            free(xref_hashes);
            free(entries);
            free(present_objects);
            free(xref_blocks);
            printf("FAILED TO REALLOCATE XREF_HASHES\n");
            return;
        }
        xref_hashes = temp_hashes;
        temp_tables = NULL;
        temp_tables = (XrefTables*)realloc(test_tables, (num_tables + 1) * sizeof(XrefTables));
        if (temp_tables == NULL) {
            free(xref_hashes);
            free(entries);
            free(present_objects);
            free(xref_blocks);
            printf("FAILED TO REALLOCATE XREF_HASHES\n");
            return;
        }
        test_tables = temp_tables;
        {
            PDFCarveState *carve_state = (PDFCarveState*)carve_get_state(candidate->carvehashkey);
            if(!carve_state){
                for(int i = 0; i < num_tables; i++){
                    test_tables[i].entries = NULL;
                    test_tables[i].count = 0;
                }
            } else {
                for(int i = 0; i < num_tables; i++){
                    test_tables[i].count = (int)carve_state->xref_tables[i].count;
                    if(carve_state->xref_tables[i].count > 0 && carve_state->xref_tables[i].entries){
                        test_tables[i].entries = malloc(carve_state->xref_tables[i].count * sizeof(Object));
                        if(test_tables[i].entries){
                            memcpy(test_tables[i].entries, carve_state->xref_tables[i].entries,
                                   carve_state->xref_tables[i].count * sizeof(Object));
                        } else {
                            test_tables[i].count = 0;
                        }
                    } else {
                        test_tables[i].entries = NULL;
                        test_tables[i].count = 0;
                    }
                }
                pdf_free_carve_state((void**)&carve_state);
            }
        }
        test_tables[num_tables].count = entry_count;
        test_tables[num_tables].entries = entries;

        sort_xref_data_by_offset(&test_tables[num_tables]);

        for(int i = 0; i <= num_tables; i++){


            if(test_tables[i].entries && test_tables[i].count > 0){
            // Choose bucket size based on entry count
                int bucket_count = 101;
                if(test_tables[i].count > 100) bucket_count = 509;
                if(test_tables[i].count > 500) bucket_count = 1009;
                if(test_tables[i].count > 2000) bucket_count = 2017;
                xref_hashes[i] = hash_table_create(bucket_count);
    
                if(xref_hashes[i]){
                    // Populate hash table with all entries from this xref table
                    for(int j = 0; j < test_tables[i].count; j++){
                        hash_table_insert(xref_hashes[i],
                                     test_tables[i].entries[j].obj_num,
                                     j);
                    }
                }
            }   
            else {
                // No entries or allocation failed
                xref_hashes[i] = NULL;
            }
        }
        int current_table = -1;
        int current_object = -1;
        int current_object_idx = -1;
        int check = -1;
        printf("NUM TABLES: %d", num_tables);
        for(int i = 0; i < num_tables + 1; i++){
            current_table = i;
            for(int j = 0; j < test_tables[i].count; j++){
                check = validate_at_offset(data, test_tables[i].entries[j].obj_offset, 
                    test_tables[i].entries[j].obj_num, blockvector_get_data_length(candidate->b));
                current_object = test_tables[i].entries[j].obj_num;
                current_object_idx = j;

                // Here we need to think of new conditionals for each
                // return type of validate_at_offset
                // -2 will be of particular interest as this means
                // we will need to try and extend the candidate
                // a return value of 0 could also potentially
                // lead to an extension if the value in another xref
                // returns -2

                // Need to implement a check after each validated object that searches the last
                // object in the candidate's dictionary to check for a /Length field greater than
                // blocksize (actually blocksize + the data length accounted for in the candidate already)
                if(check == 1){
                    int32_t endstream_local_offset = -1;
                    int32_t startstream_local_offset = -1;
                    uint64_t streamstart_block_app = blockvector_get_apparent_blocknumber(candidate->b, 
                        blockvector_get_num_blocks(candidate->b) - 1);
                    char *first_stream_block_data = (char*)get_apparent_block_data(scalpel_state.filemirror, streamstart_block_app);
                    data = blockvector_get_data_pointer(candidate->b);
                    uint64_t length = blockvector_get_data_length(candidate->b);
                    int blocks_to_extend = 0;
                    int stream_condition = check_last_object_length(data, length, 
                        &startstream_local_offset, &endstream_local_offset, &blocks_to_extend);
                    // Nothing happens, high degree of certainty that the next block contains a new object
                    if(stream_condition == LENGTHNOTFOUND || stream_condition == INBLOCK){
                        free(first_stream_block_data);
                        continue;
                    }

                    // Not sure what to do here since there are a couple of possibilities
                    // depending on how far the stream extends into the next block
                    if(stream_condition == INNEXTBLOCK){
                        free(first_stream_block_data);
                        continue;
                    }

                    // Here we are going to find the block containing endstream at the
                    // appropriate offset
                    // From there extend the candidate bv by the size of the stream and insert
                    // the endstream block at its position
                    if(stream_condition == MULTIBLOCK){
                        int64_t block_choice = pdf_reassembly_get_block_choice(candidate, -1, endstream_local_offset, 0, 0,-1, FINDENDSTREAM);
                        uint64_t endstream_block_apparent = (uint64_t)block_choice;
                        if(block_choice == -1){
                            return;
                        }
                        candidate->newblock = filemirror_actual_blocknumber(scalpel_state.filemirror, block_choice);
                        pdf_reassembly_prepare_for_extension(work->id, candidate, blocks_to_extend, ENDSTREAMEXTENSION);
                        pdf_reassembly_extension_successful(work->id, candidate, blockvector_get_num_blocks(candidate->b) - 1);
                        StreamReassembler r;
                        int k = 1;
                        if(stream_reassembler_init(&r, (const unsigned char *)first_stream_block_data, scalpel_state.blocksize, startstream_local_offset) == -1){
                            k = blocks_to_extend + 1; // skip the loop
                        }
                        bool extend_from_start = true;
                        const unsigned char *stream_block;
                        int stream_check;
                        while(k <= blocks_to_extend){
                            if(extend_from_start){
                                block_choice = pdf_reassembly_get_block_choice(candidate, -1, -1,
                                    streamstart_block_app, 0, k, EXTENDSTREAMFROMSTART);
                                if(block_choice == -1){ extend_from_start = false; k++; continue; }
                                stream_block = (const unsigned char*)get_apparent_block_data(scalpel_state.filemirror, block_choice);
                                stream_check = stream_reassembler_try_block(&r, stream_block, scalpel_state.blocksize);
                                free((void*)stream_block);
                                if(stream_check == 1){
                                    candidate->newblock = filemirror_actual_blocknumber(scalpel_state.filemirror, block_choice);
                                    pdf_reassembly_extension_successful(work->id, candidate,
                                        (blockvector_get_num_blocks(candidate->b) - blocks_to_extend + k - 1));
                                }
                                else if(stream_check == 0 || stream_check == -1) extend_from_start = false;
                            }
                            else{
                                block_choice = pdf_reassembly_get_block_choice(candidate, -1, -1,
                                    streamstart_block_app, endstream_block_apparent, (blocks_to_extend - k) + 1, EXTENDSTREAMFROMEND);
                                if(block_choice == -1){ k++; continue; }
                                stream_block = (const unsigned char*)get_apparent_block_data(scalpel_state.filemirror, block_choice);
                                stream_check = stream_reassembler_try_block(&r, stream_block, scalpel_state.blocksize);
                                free((void*)stream_block);
                                if(stream_check == 1){
                                    candidate->newblock = filemirror_actual_blocknumber(scalpel_state.filemirror, block_choice);
                                    pdf_reassembly_extension_successful(work->id, candidate,
                                        (blockvector_get_num_blocks(candidate->b) - blocks_to_extend + k - 2));
                                }
                            }
                            k++;
                        }
                        stream_reassembler_free(&r);
                    }
                    free(first_stream_block_data);
                    //write_candidate(&candidate, true);
                }

                // We need to try to extend the candidate by finding a block that contains the next object
                if(check == -2){
                    // Case 1: The object offset is 1 block past the current candidate length
                    if(test_tables[i].entries[j].obj_offset > 
                        blockvector_get_data_length(candidate->b)){
                        int64_t new_block = -1;

                        if((new_block = pdf_reassembly_get_block_choice(candidate, test_tables[i].entries[j].obj_num,-1, 0, 0, -1,NEXTOBJECT)) != -1){
                            char *new_block_data = (char*)get_apparent_block_data(scalpel_state.filemirror, new_block);
                            check = validate_at_offset(new_block_data,
                                test_tables[i].entries[j].obj_offset - blockvector_get_data_length(candidate->b),
                                test_tables[i].entries[j].obj_num,
                                scalpel_state.blocksize);
                            free(new_block_data);
                            if(check == 1){
                                pdf_reassembly_prepare_for_extension(work->id, candidate, 1, OBJECTEXTNSION);
                                candidate->newblock = filemirror_actual_blocknumber(
                                scalpel_state.filemirror, new_block);
                                pdf_reassembly_extension_successful(work->id, candidate, blockvector_get_num_blocks(candidate->b) - 1);
                            }
                        }
                    }
                }
                if(check != 1){
                    // Search other tables for this object using hash tables
                    for(int k = 0; k < num_tables + 1; k++){
                        if(k == current_table) continue;
        
                        // Skip if hash table doesn't exist
                        if(!xref_hashes[k]) continue;
        
                        int entry_idx;
                        if(hash_table_lookup(xref_hashes[k], current_object, &entry_idx)){
                            // Found the object in table k at position entry_idx
                            check = validate_at_offset(data, test_tables[k].entries[entry_idx].obj_offset,
                                test_tables[k].entries[entry_idx].obj_num, blockvector_get_data_length(candidate->b));
                            if(check == 1) {
                                break;  // break out of k-loop; j-loop's j++ handles increment
                            }
                        }
                    }
                // If we get here, object wasn't found in any other table
                // Handle failure case - maybe continue or break depending on your needs
                }
            }
        }
        // Set a condition to append the new xref to the candidate (hopefully)
        if(check == 1){
            PDFCarveState *carve_state = (PDFCarveState*)carve_get_state(candidate->carvehashkey);
            add_xref_table(carve_state, test_tables, num_tables);
            carve_put_state(candidate->carvehashkey, carve_state);
            pdf_free_carve_state((void**)&carve_state);
            test_tables[num_tables].entries = NULL;
            test_tables[num_tables].count = 0;
            for(int i = 0; i < xref_block_count; i++){
                uint64_t num_blocks = blockvector_get_num_blocks(candidate->b);
                uint64_t last_app = blockvector_get_apparent_blocknumber(candidate->b, num_blocks - 1);
                uint64_t new_app = filemirror_apparent_blocknumber(scalpel_state.filemirror, xref_blocks[i]);
                // printf("LAST APP: %lld\n", last_app);
                // printf("NEW APP: %lld\n", new_app);
                if(last_app == new_app) continue;

                pdf_reassembly_prepare_for_extension(work->id, candidate, 1, OBJECTEXTNSION);
                candidate->newblock = xref_blocks[i];
                pdf_reassembly_extension_successful(work->id, candidate, num_blocks);
            }
        }

    }

    if(test_tables){
        for(int i = 0; i <= num_tables; i++){
            free(test_tables[i].entries);
        }
        free(test_tables);
        test_tables = NULL;
    }
    if(xref_hashes){
        for(int i = 0; i <= num_tables; i++){
            hash_table_free(xref_hashes[i]);
        }
        free(xref_hashes);
        xref_hashes = NULL;
    }
    free(present_objects);
    free(xref_blocks);
    xref_blocks = NULL;
    int check = check_startxref(blockvector_get_data_pointer(candidate->b),
    blockvector_get_data_length(candidate->b));
    uint64_t search_pos = 0;
    int xref_type;
    const char *first_xref = scan_buf_for_xref(blockvector_get_data_pointer(candidate->b),
    blockvector_get_data_length(candidate->b), search_pos, &xref_type);
    int64_t xref_offset = first_xref - blockvector_get_data_pointer(candidate->b);
    int64_t prev_entry = find_prev_entry(blockvector_get_data_pointer(candidate->b),
    blockvector_get_data_length(candidate->b), xref_offset, xref_type);
    int prev_check = 0;
    if(prev_entry > 0){
        int64_t tmp;
        prev_check = detect_xref_type(blockvector_get_data_pointer(candidate->b),
        prev_entry, blockvector_get_data_length(candidate->b), &tmp);

    }
    // This means that the offset of an expected xref was past the bounds of the buffer
    // so we need to try to extend that buffer
    // For this particular condition that means searching for an xref that
    // exists at a specific offset within a block calculated with the value
    // of this prev entry and blocksize
    if(prev_check == -1){
        uint64_t xref_local_block_offset = prev_entry % scalpel_state.blocksize;
        int prev_entry_count = 0;
        int64_t *prev_xref_blocks = NULL;
        int prev_xref_block_count = 0;

        Object *prev_entries = scan_blocks_for_xref_at_offset(candidate, scan_bv,
            &prev_entry_count, &prev_xref_blocks, &prev_xref_block_count,
            (int32_t)xref_local_block_offset);

        if(prev_entries && prev_entry_count > 0){
            PDFCarveState *carve_state = (PDFCarveState*)carve_get_state(candidate->carvehashkey);
            // build a temporary XrefTables slot and add it
            XrefTables prev_table;
            prev_table.entries = prev_entries;
            prev_table.count = prev_entry_count;
            // reuse existing num_tables from carve_state as the slot index
            XrefTables *slot = realloc(NULL, (carve_state->num_tables + 1) * sizeof(XrefTables));
            // ... or just call add_xref_table directly if you can pass a single-element array
            add_xref_table(carve_state, &prev_table, carve_state->num_tables);
            carve_put_state(candidate->carvehashkey, carve_state);
            pdf_free_carve_state((void**)&carve_state);
            prev_table_found = true;
        }

    free(prev_entries);
    free(prev_xref_blocks);
    entries = NULL;
}

    // This means that a startxref value was past the bounds of the candidate,
    // so we are not done extending yet. Going to try a goto statement
    // to restart reassembly from this new checkpoint
    if(check == -1){
        possible_match = false;
        free(entries);
        entries = NULL;
        PDFCarveState *carve_state = (PDFCarveState*)carve_get_state(candidate->carvehashkey);
        num_tables = carve_state->num_tables;
        pdf_free_carve_state((void**)&carve_state);
        data = blockvector_get_data_pointer(candidate->b);
        goto start_reassembly;
    }
    // This means that a check failed, but was within bounds
    // I honestly have no idea how to handle this and it will be
    // painful
    //if(check == 0);

    write_candidate(&candidate, true);
    return;
}



/*******************************************************/
/*             VALIDATION FUNCTION DEFINITIONS         */
/*******************************************************/
static inline uint32_t pdf_block_validate(char *data,
    uint64_t length,
    BlockValidationDecision *decision,
    uint64_t *validates_to,
    uint32_t needleidx,
    uint32_t blocksize,
    void *blockhashkey){

    *decision = BLOCK_CONFIDENCE_VALID;
    *validates_to = length - 1;
    PDFBlockState *s = (PDFBlockState *)malloc(sizeof(PDFBlockState));
    if(!s) return needleidx;
    s->first_obj = -1;
    s->num_xrefs = 0;
    s->xref_block_data = NULL;
    char* obj_pos = NULL;

    // Check for first object in block
    if ((obj_pos = memmem(data, length, " obj", 4))){ // Extract the obj # and insert into block's data
        size_t offset = obj_pos - data;
        s->first_obj = extract_obj_num(data, offset, length);
    }

    for(uint32_t i = 0; i < blocksize; i++){
        if(i + 5 < blocksize && !memcmp(&data[i], "xref", 4)){
            bool prev_ok = (i == 0) || isspace(data[i - 1]);
            bool next_ok = (i + 5 >= length) || isspace(data[i + 4]);
            if (!prev_ok || !next_ok) {
                continue;
            }
            s->num_xrefs++;
            XrefParameters *temp_xbd = (XrefParameters*)realloc(s->xref_block_data, s->num_xrefs * sizeof(XrefParameters));
            if(temp_xbd == NULL){
                free(s->xref_block_data);
                return needleidx;
            }
            s->xref_block_data = temp_xbd;
            memset(&s->xref_block_data[s->num_xrefs - 1], 0, sizeof(XrefParameters));
            s->xref_block_data[s->num_xrefs - 1].xref_start = i;
            s->xref_block_data[s->num_xrefs - 1].xref_end = -1;
            s->xref_block_data[s->num_xrefs - 1].xref_type = 1;
            for(uint32_t j = i; j < blocksize; j++){
                if(j + 7 < blocksize && !memcmp(&data[j], "trailer", 7)){
                    s->xref_block_data[s->num_xrefs - 1].xref_end = j;
                    i = j + 1;
                    break;
                }
            }
        }

        if(i + 7 < blocksize && !memcmp(&data[i], "trailer", 7)){
            s->num_xrefs++;
            XrefParameters *temp_xbd = (XrefParameters*)realloc(s->xref_block_data, s->num_xrefs * sizeof(XrefParameters));
            if(temp_xbd == NULL){
                free(s->xref_block_data);
                return needleidx;
            }
            s->xref_block_data = temp_xbd;
            memset(&s->xref_block_data[s->num_xrefs - 1], 0, sizeof(XrefParameters));
            s->xref_block_data[s->num_xrefs - 1].xref_start = -1;
            s->xref_block_data[s->num_xrefs - 1].xref_end = i;
            s->xref_block_data[s->num_xrefs - 1].xref_type = 1;
        }

        if(i + 10 < blocksize && !memcmp(&data[i], "/Type/XRef", 10)){
            xref_stream_end_search:
            s->num_xrefs++;
            XrefParameters *temp_xbd = (XrefParameters*)realloc(s->xref_block_data, s->num_xrefs * sizeof(XrefParameters));
            if(temp_xbd == NULL){
                free(s->xref_block_data);
                return needleidx;
            }
            s->xref_block_data = temp_xbd;
            memset(&s->xref_block_data[s->num_xrefs - 1], 0, sizeof(XrefParameters));
            s->xref_block_data[s->num_xrefs - 1].xref_start = find_xref_stream_start(data, i);
            s->xref_block_data[s->num_xrefs - 1].xref_type = 2;
            s->xref_block_data[s->num_xrefs - 1].conditional_flag = 0;
            if(s->xref_block_data[s->num_xrefs - 1].xref_start == (int64_t)i){
                s->xref_block_data[s->num_xrefs - 1].conditional_flag = INCOMPLETESTREAMDICT;
            }
            s->xref_block_data[s->num_xrefs - 1].xref_end = -1;
            for(uint32_t j = i; j < blocksize; j++){
                if(j + 9 < blocksize && !(memcmp(&data[j], "endstream", 9))){
                    s->xref_block_data[s->num_xrefs - 1].xref_end = j;
                    i = j + 1;
                    break;
                }
            }
        }

        else if(i + 11 < blocksize && !memcmp(&data[i], "/Type /XRef", 11)){
            goto xref_stream_end_search;
        }

        // if(i + 9 < blocksize && !(memcmp(&data[i], "endstream", 9))){
        //     s->xref_block_data->xref_end = i;
        // }
    }
    block_put_state(blockhashkey, s);
    return needleidx;
}
/** 
 * @description         Validates a full PDF file by locating and analyzing
 *                      its xref entries and ensuring all objects are in their
 *                      expected locations.
 *
 * @param data          The buffer containing the candidate.
 * @param length        The length of the buffer.
 * @param validates     Boolean to determine whether the file validates.
 * @param validates_to  The offset to which the file validates.
 * @param promising     Boolean to determine whether the file is promising.
 * @param needleidx     The offset into the search spec array.
 * @param blocksize     The block size used for carving.
 * @param carvehashkey  The hash key for carving.
 *
 * @return              Void.
 */
static inline void pdf_file_validate(char *data,
    uint64_t length,
    bool *validates,
    uint64_t *validates_to,
    bool *promising,
    uint32_t needleidx,
    uint32_t blocksize,
    void *carvehashkey){
    *promising = true;
    *validates = false;
    *validates_to = blocksize - 1;
#ifdef NOFRAG
    XrefObject *xref_list = NULL;
    int xref_count = 0;
    int8_t check = 0;
    uint64_t validation_cutoff = blocksize - 1;
    int64_t *supp_stms = (int64_t*)malloc(sizeof(int64_t));
    int supp_count = 0;
    XrefTables* xref_tables = malloc(sizeof(XrefTables));
    ObjectHashTable **xref_hashes = NULL;
    uint64_t kg_validation_cutoff = blocksize - 1;
    int8_t validated = 0;
    uint8_t fail_count = 0;
    uint64_t xref_end_offset = 0;


    // Start at end of file and find startxref to store offset of most recent xref table
    uint64_t search_pos = 0;
    //int no_prev_count = 0;
    bool search_more = true;
    while(search_pos < length){
        int xref_type = 0;
        const char *first_xref = scan_buf_for_xref(data, length, search_pos, &xref_type);
        if(!first_xref || xref_type <= 0) break;
        //at this point we have the xref entry that comes earliest in the file
        //We will always want to check for a prev entry, and if we find more than one
        //table without it then we will cease execution of this loop and send the
        //xrefs to validation.
        //If a prev entry points to an invalid xref position we will also cease
        //execution of this loop
        int64_t offset = first_xref - data;
        int64_t prev = find_prev_entry(data, (int64_t)length, offset, xref_type);
        int64_t stm_offset = find_stm_entry(data, (int64_t)length, offset, xref_type);
        if(stm_offset != -1){
            int64_t *temp_supp = (int64_t*)realloc(supp_stms, (supp_count + 1) * sizeof(int64_t));
            if(temp_supp == NULL){
                free(supp_stms);
                free(xref_tables);
                *validates = false;
                *promising = true;
                *validates_to = blocksize - 1;
                printf("FAILED TO REALLOC SUPP_STMS\n");
                return;
            }
            supp_stms = temp_supp;
            supp_stms[supp_count] = stm_offset;
            supp_count++;
        }

        // if(prev == -1){
        //     no_prev_count++;
        // }
        for(int i = 0; i < supp_count; i++){
            for(int64_t j = offset; j > 0; j--){
                if(!memcmp(&data[j], " obj", 4)){
                    while(j > 0 && isspace(data[j])) j--;
                    while(j > 0 && isdigit(data[j])) j--;
                    while(j > 0 && isspace(data[j])) j--;
                    while(j > 0 && isdigit(data[j])) j--;
                    // j is currently on the character before the first digit of the object #
                    // /XRefStm points to the first digit of the object #
                    // Hence why we compare j + 1 and the expected offset of the supplemental stream
                    // if(j + 1 == supp_stms[i]){
                    //     no_prev_count--;
                    // }
                    break;
                }
            }
        }
        XrefObject *temp = (XrefObject*)realloc(xref_list, (xref_count + 1) * sizeof(XrefObject));
        if (temp == NULL) {
            free(temp);
            printf("FAILED TO REALLOC XREFOBJECT");
            return;
        }
        xref_list = temp;

        if(xref_type == 1){
            xref_list[xref_count].offset = offset;
        }
        if(xref_type == 2){
            xref_list[xref_count].offset = find_xref_stream_start(data, offset);
        }

        xref_list[xref_count].prev_offset = prev;
        if(xref_list[xref_count].prev_offset != -1 &&
        xref_list[xref_count].prev_offset < (int64_t)length){
            int xref_check = detect_xref_type(data, xref_list[xref_count].prev_offset, length, &xref_list[xref_count].prev_offset);
            if(xref_check < 1){ // No valid xref at this offset so we will stop searching for tables
                break;
            }
        }
        xref_count++;

        XrefTables *temp_tables = (XrefTables*)realloc(xref_tables, xref_count * sizeof(XrefTables));
        if (temp_tables == NULL) {
            free(xref_tables);
            free(xref_hashes);
            printf("FAILED TO REALLOCATE XREF_TABLES\n");
            *validates = false;
            *promising = true;
            *validates_to = blocksize -1;
            return;
        }
        xref_tables = temp_tables;

        ObjectHashTable **temp_hashes = (ObjectHashTable**)realloc(xref_hashes, xref_count * sizeof(ObjectHashTable*));
        if (temp_hashes == NULL) {
            free(xref_tables);
            free(xref_hashes);
            printf("FAILED TO REALLOCATE XREF_HASHES\n");
            *validates = false;
            *promising = true;
            *validates_to = blocksize - 1;
            return;
        }
        xref_hashes = temp_hashes;
        xref_tables[xref_count - 1].count = 0;
        xref_tables[xref_count - 1].entries = NULL;

        xref_tables[xref_count - 1].entries = analyze_xref(data, xref_list[xref_count - 1].offset,
            length, &xref_tables[xref_count - 1].count, &xref_end_offset);
        if(xref_tables[xref_count - 1].entries && xref_tables[xref_count - 1].count > 0){
        // Choose bucket size based on entry count
        int bucket_count = 101;
        if(xref_tables[xref_count - 1].count > 100) bucket_count = 509;
        if(xref_tables[xref_count - 1].count > 500) bucket_count = 1009;
        if(xref_tables[xref_count - 1].count > 2000) bucket_count = 2017;
        xref_hashes[xref_count - 1] = hash_table_create(bucket_count);

        if(xref_hashes[xref_count - 1]){
            // Populate hash table with all entries from this xref table
            for(int j = 0; j < xref_tables[xref_count - 1].count; j++){
                hash_table_insert(xref_hashes[xref_count - 1],
                             xref_tables[xref_count - 1].entries[j].obj_num,
                             j);
            }
        }
    }
    else {
        // No entries or allocation failed
        xref_hashes[xref_count - 1] = NULL;
    }
        int current_table = -1;
        int current_object = -1;
        int current_object_idx = -1;
        for(int i = 0; i < xref_count; i++){
            current_table = i;
            for(int j = 0; j < xref_tables[i].count; j++){
                check = validate_at_offset(data, xref_tables[i].entries[j].obj_offset,
                    xref_tables[i].entries[j].obj_num, length);
                current_object = xref_tables[i].entries[j].obj_num;
                current_object_idx = j;
                if(check != 1){
                    // Search other tables for this object using hash tables
                    for(int k = 0; k < xref_count; k++){
                        if(k == current_table) continue;

                        // Skip if hash table doesn't exist
                        if(!xref_hashes[k]) continue;

                        int entry_idx;
                        if(hash_table_lookup(xref_hashes[k], current_object, &entry_idx)){
                        // Found the object in table k at position entry_idx
                        check = validate_at_offset(data, xref_tables[k].entries[entry_idx].obj_offset,
                            xref_tables[k].entries[entry_idx].obj_num, length);
                            fflush(stdout);
                        if(check == 1) {
                            if(validation_cutoff < xref_tables[k].entries[entry_idx].obj_offset){
                                validation_cutoff = xref_tables[k].entries[entry_idx].obj_offset;
                            }
                            fflush(stdout);
                            break;  // break out of k-loop; j-loop's j++ handles increment
                        }
                    }
                }
                // If we get here, object wasn't found in any other table
                // Handle failure case - maybe continue or break depending on your needs
                    if(validated == 1) goto stop_validation;
                    if(check != 1){
                        fail_count++;
                        goto leave_loop;
                    }
                }
                else if(validation_cutoff < xref_tables[i].entries[j].obj_offset){
                    validation_cutoff = xref_tables[i].entries[j].obj_offset;
                }
            }
        }
        leave_loop:
        if(check == 1){
            kg_validation_cutoff = validation_cutoff;
            validated = 1;
        }
        if(validation_cutoff < xref_end_offset && check == 1
            && current_table == xref_count - 1
            && current_object_idx == xref_tables[current_table].count - 1){
            validation_cutoff = xref_end_offset;
            kg_validation_cutoff = validation_cutoff;
        }
        fflush(stdout);
        search_pos = offset + 1;
    }
    stop_validation:
    free(xref_list);
    for(int i = 0; i < xref_count; i++){
        free(xref_tables[i].entries);
        hash_table_free(xref_hashes[i]);
    }
    free(xref_tables);
    free(xref_hashes);
    free(supp_stms);
    //if(check == 1) validation_cutoff = xref_end_offset;
    if(check != 1) validation_cutoff = kg_validation_cutoff;
    char *start_xref = NULL;
    uint64_t start_xref_search = 0;
    // Find the object with the greatest offset, then parse down to find footer within 3 blocks
    if(validated == 1){ // Account for some slack in case last object is near end of file

        for(uint64_t i = validation_cutoff; i <= validation_cutoff + (blocksize * 20); i++){
            if(i + 5 <= length && (!memcmp(&data[i], "%%EOF", 5))){
                char *tail_ptr;
                validation_cutoff = i + 4;
                if(validation_cutoff + 195 < length &&
                    (tail_ptr = memmem(&data[validation_cutoff], 190, "%%EOF", 5))){
                    validation_cutoff = tail_ptr - data + 4;
                }
                if((tail_ptr = memmem(&data[9], validation_cutoff, "%PDF-1", 6)) ||
                (tail_ptr = memmem(&data[9], validation_cutoff, "%PDF-2", 6))){
                    validation_cutoff = tail_ptr - data;
                    goto search_backward;
                }
                if(validation_cutoff < length - 2 &&
                !memcmp(&data[validation_cutoff + 1], "\x0D\x0A", 2)){
                    validation_cutoff += 2;
                    if(check_startxref(data, validation_cutoff) == 0) goto startxref_fail;
                    *promising = false;
                    *validates = true;
                    *validates_to = validation_cutoff;
                    return;
                }
                else if(validation_cutoff < length - 1 &&
                (data[validation_cutoff + 1] == 0x0D ||
                data[validation_cutoff + 1] == 0x0A)){
                    validation_cutoff++;
                    if(check_startxref(data, validation_cutoff) == 0) goto startxref_fail;
                    *promising = false;
                    *validates = true;
                    *validates_to = validation_cutoff;
                    return;
                }
                else{
                    if(check_startxref(data, validation_cutoff) == 0) goto startxref_fail;
                    *promising = false;
                    *validates = true;
                    *validates_to = validation_cutoff;
                    return;
                }
                break;
            }
            else if(i == validation_cutoff + (blocksize * 20)){
                *promising = true;
                *validates = false;
                validation_cutoff = (validation_cutoff / scalpel_state.blocksize + 1) * scalpel_state.blocksize;
                *validates_to = validation_cutoff;
                return;
            }
        }
    }
    else{
        *promising = true;
        *validates = false;
        validation_cutoff = (validation_cutoff / scalpel_state.blocksize + 1) * scalpel_state.blocksize;
        *validates_to = validation_cutoff;
        return;
    }
    search_backward:
    fflush(stdout);
    for(uint64_t i = validation_cutoff; i > 9; i--){
        if(!memcmp(&data[i], "%%EOF", 5)){
            char *tail_ptr;
            validation_cutoff = i + 4;
            if((tail_ptr = memmem(&data[9], validation_cutoff - 9, "%PDF-1", 6)) ||
            (tail_ptr = memmem(&data[9], validation_cutoff - 9, "%PDF-2", 6))){
                validation_cutoff = i - 1;
                i = validation_cutoff + 1;  // Will become validation_cutoff after i--
                continue;
            }
                if(validation_cutoff < length - 2 &&
                !memcmp(&data[validation_cutoff + 1], "\x0D\x0A", 2)){
                    validation_cutoff += 2;
                    if(check_startxref(data, validation_cutoff) == 0) goto startxref_fail;
                    *promising = false;
                    *validates = true;
                    *validates_to = validation_cutoff;
                    return;
                }
                else if(validation_cutoff < length - 1 &&
                (data[validation_cutoff + 1] == 0x0D ||
                data[validation_cutoff + 1] == 0x0A)){
                    validation_cutoff++;
                    if(check_startxref(data, validation_cutoff) == 0) goto startxref_fail;
                    *promising = false;
                    *validates = true;
                    *validates_to = validation_cutoff;
                    return;
                }
                else{
                    if(check_startxref(data, validation_cutoff) == 0) goto startxref_fail;
                    *promising = false;
                    *validates = true;
                    *validates_to = validation_cutoff;
                    return;
                }
                break;
            }
        }
        startxref_fail:
        *promising = true;
        *validates = false;
        validation_cutoff = (validation_cutoff / scalpel_state.blocksize + 1) * scalpel_state.blocksize;
        *validates_to = kg_validation_cutoff;
    return;
#endif
}




#ifdef PDFTESTING

int main(int argc, char *argv[])
{

    struct stat file_info;
    BlockValidationDecision decision;
    int i, j, rc;
    uint32_t blocksize;
    uint32_t needleidx = 0;
    bool validates;
    bool promising;
    uint64_t validates_to;
    char *file_buf, *block_buf;
    uint64_t len;
    void **state;

    fflush(stdout);

    if (argc != 3)
    {
        fprintf(stderr, "USAGE: %s filename.pdf [blocksize]\n", argv[0]);
        return 0;
    }

    fflush(stdout);

    rc = stat(argv[1], &file_info);
    if (rc)
    {
        printf("Couldn't open pdf file.\n");
        return 0;
    }
    blocksize = atoi(argv[2]);
    len = file_info.st_size;
    block_buf = (char *)malloc(blocksize + 100);
    file_buf = (char *)malloc(len + 100);

    int fd = open(argv[1], O_RDONLY);
    rc = read(fd, block_buf, blocksize);
    needleidx = PDF_Block_Validate(block_buf, blocksize, &decision, &validates_to,
                     needleidx, blocksize);


    memcpy(file_buf, block_buf, blocksize);

    PDF_File_Validate(file_buf, len, &validates, &validates_to, &promising, needleidx, blocksize, state);

    return 0;
}
#endif
